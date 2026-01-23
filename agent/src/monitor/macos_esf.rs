//! macOS Endpoint Security Framework monitor - true pre-access blocking.
//!
//! This module provides native ESF integration using ES_EVENT_TYPE_AUTH_OPEN
//! events for true pre-access file blocking. Unlike eslogger, this can PREVENT
//! file reads before any data reaches process memory.
//!
//! # Requirements
//! - System Extension entitlement from Apple (requires Developer ID)
//! - Full Disk Access permission
//! - macOS 10.15+ (Catalina or later)
//! - Build with `--features esf`

use super::MonitorContext;
use crate::error::{Error, Result};
use crate::process::ProcessContext;
use endpoint_sec::sys::es_event_type_t;
use endpoint_sec::{Client, Event, Message};
use std::panic::AssertUnwindSafe;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::runtime::Handle;
use tokio::sync::oneshot;

// ============================================================================
// Testable Response Logic (no ESF dependencies)
// ============================================================================

/// Minimum time remaining before deadline to process an event.
/// If less than this, we allow immediately to avoid client termination.
const DEADLINE_THRESHOLD: Duration = Duration::from_secs(5);

/// ESF response flags
pub const ESF_ALLOW_ALL: u32 = u32::MAX;
pub const ESF_DENY_ALL: u32 = 0;

/// Information extracted from an ESF event for decision making.
#[derive(Debug, Clone)]
pub struct EventInfo {
    /// File path being accessed (None if couldn't be extracted)
    pub file_path: Option<String>,
    /// Whether this is an AUTH_OPEN event
    pub is_auth_open: bool,
    /// Whether this is any AUTH event (requires response)
    pub is_auth_event: bool,
    /// Time remaining until deadline (None if deadline passed or error)
    pub deadline_remaining: Option<Duration>,
    /// Process context for rule evaluation
    pub process_context: ProcessContext,
}

/// Decision on how to respond to an ESF event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ResponseDecision {
    /// Allow with flags, optionally cache the response.
    AllowFlags { cache: bool },
    /// Deny with flags (0), never cache.
    DenyFlags,
    /// Allow via auth result (for non-OPEN auth events).
    AllowAuth,
    /// No response needed (not an auth event).
    NoResponse,
}

/// Reason for the response decision (for logging/debugging).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ResponseReason {
    /// Event is not an AUTH event, no response required.
    NotAuthEvent,
    /// AUTH event but not AUTH_OPEN, allow via auth result.
    NotAuthOpen,
    /// AUTH_OPEN but couldn't extract file path.
    NoFilePath,
    /// File is in the exclusion list.
    Excluded,
    /// Deadline too close, allowing to avoid termination.
    DeadlineClose,
    /// Deadline already passed.
    DeadlinePassed,
    /// Access violates a protection rule.
    Violation,
    /// No violation found, access allowed.
    Allowed,
}

/// Result of analyzing an ESF event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AnalysisResult {
    /// The response decision to send to ESF.
    pub decision: ResponseDecision,
    /// The reason for this decision (for logging/debugging).
    pub reason: ResponseReason,
}

/// Analyze event info and determine response - pure function, fully testable.
///
/// This function contains the core decision logic without any ESF dependencies.
#[must_use]
pub fn determine_response(
    info: &EventInfo,
    is_excluded: bool,
    has_violation: bool,
) -> AnalysisResult {
    // Not an auth event - no response needed
    if !info.is_auth_event {
        return AnalysisResult {
            decision: ResponseDecision::NoResponse,
            reason: ResponseReason::NotAuthEvent,
        };
    }

    // Auth event but not AUTH_OPEN - allow via auth result
    if !info.is_auth_open {
        return AnalysisResult {
            decision: ResponseDecision::AllowAuth,
            reason: ResponseReason::NotAuthOpen,
        };
    }

    // AUTH_OPEN but no file path - allow (likely directory)
    if info.file_path.is_none() {
        return AnalysisResult {
            decision: ResponseDecision::AllowFlags { cache: false },
            reason: ResponseReason::NoFilePath,
        };
    }

    // File is excluded - allow and cache
    if is_excluded {
        return AnalysisResult {
            decision: ResponseDecision::AllowFlags { cache: true },
            reason: ResponseReason::Excluded,
        };
    }

    // Check deadline - allow immediately if too close or passed
    match info.deadline_remaining {
        Some(remaining) if remaining < DEADLINE_THRESHOLD => {
            return AnalysisResult {
                decision: ResponseDecision::AllowFlags { cache: false },
                reason: ResponseReason::DeadlineClose,
            };
        }
        None => {
            return AnalysisResult {
                decision: ResponseDecision::AllowFlags { cache: false },
                reason: ResponseReason::DeadlinePassed,
            };
        }
        Some(_) => {} // Deadline OK, continue
    }

    // Make decision based on violation status
    if has_violation {
        AnalysisResult {
            decision: ResponseDecision::DenyFlags,
            reason: ResponseReason::Violation,
        }
    } else {
        AnalysisResult {
            decision: ResponseDecision::AllowFlags { cache: true },
            reason: ResponseReason::Allowed,
        }
    }
}

/// Convert absolute path to ~/... format for rule matching.
#[must_use]
pub fn convert_path_to_home_relative(path: &str, euid: u32) -> String {
    if let Some(home) = crate::process::get_home_for_uid(euid) {
        let home_str = home.to_string_lossy();
        if let Some(suffix) = path.strip_prefix(home_str.as_ref()) {
            return format!("~{}", suffix);
        }
    }
    path.to_string()
}

/// Check if a path is a directory (ends with /).
#[must_use]
pub fn is_directory_path(path: &str) -> bool {
    path.ends_with('/')
}

/// Build ProcessContext from extracted process information.
///
/// Filters out empty strings for team_id/signing_id and non-positive ppid values.
#[must_use]
pub fn build_process_context_from_info(
    executable_path: PathBuf,
    pid: u32,
    euid: u32,
    ppid: i32,
    team_id: Option<String>,
    signing_id: Option<String>,
    is_platform_binary: bool,
) -> ProcessContext {
    let mut ctx = ProcessContext::new(executable_path)
        .with_pid(pid)
        .with_euid(euid)
        .with_platform_binary(is_platform_binary);

    if ppid > 0 {
        ctx = ctx.with_ppid(ppid as u32);
    }

    // Filter empty strings - ESF may return empty strings instead of None
    if let Some(tid) = team_id.filter(|s| !s.is_empty()) {
        ctx = ctx.with_team_id(tid);
    }
    if let Some(sid) = signing_id.filter(|s| !s.is_empty()) {
        ctx = ctx.with_signing_id(sid);
    }

    ctx
}

// ============================================================================
// ESF-Specific Code (thin wrappers around the testable logic)
// ============================================================================

/// ESF-based file access monitor with true pre-access blocking.
pub struct EsfMonitor {
    context: Arc<MonitorContext>,
    runtime_handle: Handle,
}

impl EsfMonitor {
    pub fn new(context: Arc<MonitorContext>) -> Self {
        Self {
            context,
            runtime_handle: Handle::current(),
        }
    }

    /// Handle incoming ESF message.
    ///
    /// CRITICAL: This runs on the ESF callback thread, not Tokio.
    /// Must respond before deadline to avoid client termination.
    fn handle_message(
        context: &Arc<MonitorContext>,
        handle: &Handle,
        client: &mut Client<'_>,
        message: Message,
    ) {
        // Extract event information from ESF message
        let info = Self::extract_event_info(&message);

        // Quick checks that don't need async
        let is_excluded = info
            .file_path
            .as_ref()
            .is_some_and(|p| context.config.is_excluded(p));

        // Check if we can respond immediately (anything except Allowed proceeds to async)
        let initial_result = determine_response(&info, is_excluded, false);
        if initial_result.reason != ResponseReason::Allowed {
            // Log deadline warnings
            if matches!(
                initial_result.reason,
                ResponseReason::DeadlineClose | ResponseReason::DeadlinePassed
            ) {
                if let Some(ref path) = info.file_path {
                    tracing::warn!("ESF {:?}, allowing: {}", initial_result.reason, path);
                }
            }
            Self::send_response(client, &message, initial_result.decision);
            return;
        }

        // Need to check rules - bridge to async MonitorContext
        // SAFETY: file_path is Some because determine_response returned Allowed,
        // which only happens when file_path is Some (NoFilePath returns early).
        let file_path = info
            .file_path
            .as_ref()
            .expect("file_path verified by determine_response");
        let violation = handle.block_on(async {
            context
                .process_access(file_path, &info.process_context)
                .await
        });

        // Make final decision with violation info
        let has_violation = violation.is_some();
        let final_result = determine_response(&info, is_excluded, has_violation);

        // Log violations
        if let Some(ref v) = violation {
            tracing::warn!(
                "ESF BLOCKED: {} -> {} (violation {})",
                info.process_context.path.display(),
                file_path,
                v.id
            );
        }

        Self::send_response(client, &message, final_result.decision);
    }

    /// Extract event information from ESF message into testable struct.
    fn extract_event_info(message: &Message) -> EventInfo {
        let event_type = message.event_type();
        let is_auth_open = event_type == es_event_type_t::ES_EVENT_TYPE_AUTH_OPEN;
        let is_auth_event =
            message.action_type() == endpoint_sec::sys::es_action_type_t::ES_ACTION_TYPE_AUTH;

        // Extract deadline
        let deadline_remaining = match message.deadline() {
            Ok(deadline) => {
                let now = std::time::Instant::now();
                deadline.checked_duration_since(now)
            }
            Err(_) => None,
        };

        // Extract file path
        let file_path = Self::extract_file_path(message);

        // Build process context
        let process_context = Self::build_process_context(message);

        EventInfo {
            file_path,
            is_auth_open,
            is_auth_event,
            deadline_remaining,
            process_context,
        }
    }

    /// Send response to ESF based on decision.
    fn send_response(client: &mut Client<'_>, message: &Message, decision: ResponseDecision) {
        let result = match decision {
            ResponseDecision::AllowFlags { cache } => {
                client.respond_flags_result(message, ESF_ALLOW_ALL, cache)
            }
            ResponseDecision::DenyFlags => {
                client.respond_flags_result(message, ESF_DENY_ALL, false)
            }
            ResponseDecision::AllowAuth => client.respond_auth_result(
                message,
                endpoint_sec::sys::es_auth_result_t::ES_AUTH_RESULT_ALLOW,
                false,
            ),
            ResponseDecision::NoResponse => return,
        };

        if let Err(e) = result {
            tracing::error!("ESF response failed ({:?}): {:?}", decision, e);
        }
    }

    /// Extract file path from AUTH_OPEN event.
    fn extract_file_path(message: &Message) -> Option<String> {
        let Event::AuthOpen(open) = message.event()? else {
            return None;
        };
        let path = open.file().path().to_string_lossy().into_owned();
        if is_directory_path(&path) {
            return None;
        }
        let euid = message.process().audit_token().euid();
        Some(convert_path_to_home_relative(&path, euid))
    }

    /// Build ProcessContext from ESF message.
    fn build_process_context(message: &Message) -> ProcessContext {
        let process = message.process();
        let path = PathBuf::from(process.executable().path());

        let audit = process.audit_token();
        let tid = process.team_id();
        let team_id = (!tid.is_empty()).then(|| tid.to_string_lossy().into_owned());
        let sid = process.signing_id();
        let signing_id = (!sid.is_empty()).then(|| sid.to_string_lossy().into_owned());

        build_process_context_from_info(
            path,
            audit.pid() as u32,
            audit.euid(),
            process.ppid(),
            team_id,
            signing_id,
            process.is_platform_binary(),
        )
    }
}

#[async_trait::async_trait]
impl super::Monitor for EsfMonitor {
    async fn start(&mut self) -> Result<()> {
        tracing::info!("Starting ESF monitor - true pre-access blocking, files denied BEFORE read");

        // Upgrade mode to "block" since ESF can truly block (not just best-effort)
        {
            let mut mode = self.context.mode.write().await;
            let current = mode.as_str();
            if current == "best-effort" {
                *mode = "block".to_string();
                tracing::info!(
                    "Mode upgraded from 'best-effort' to 'block' (ESF provides true blocking)"
                );
            } else {
                tracing::info!("Operating in '{}' mode", current);
            }
        }

        // Spawn periodic status logging
        let stats_context = self.context.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(60));
            loop {
                interval.tick().await;
                let snapshot = stats_context.stats.take();
                if snapshot.events_received > 0 || snapshot.violations > 0 {
                    tracing::info!(
                        "Status [ESF]: {} events, {} protected, {} allowed, {} blocked",
                        snapshot.events_received,
                        snapshot.protected_checks,
                        snapshot.allowed,
                        snapshot.violations
                    );
                } else {
                    tracing::debug!("Status [ESF]: idle (no events in last minute)");
                }
            }
        });

        // The ESF Client is not Send - it must be created and used on the same thread.
        // We spawn a dedicated OS thread for the ESF client lifecycle.
        let context = self.context.clone();
        let handle = self.runtime_handle.clone();

        // Channel to receive errors from the ESF thread
        let (error_tx, error_rx) = oneshot::channel::<Result<()>>();

        std::thread::Builder::new()
            .name("esf-client".to_string())
            .spawn(move || {
                tracing::debug!("ESF client thread started");

                // Create the handler closure
                let handler = move |client: &mut Client<'_>, message: Message| {
                    Self::handle_message(&context, &handle, client, message);
                };

                // Wrap in AssertUnwindSafe because endpoint-sec requires RefUnwindSafe
                let handler = AssertUnwindSafe(handler);

                // Create the ES client
                let client_result = Client::new(move |client, message| {
                    (handler)(client, message);
                });

                let mut client = match client_result {
                    Ok(c) => c,
                    Err(e) => {
                        let _ = error_tx.send(Err(Error::monitor(format!(
                            "ES client creation failed: {:?}",
                            e
                        ))));
                        return;
                    }
                };

                tracing::info!("ES client created successfully");

                // Subscribe to AUTH_OPEN events
                if let Err(e) = client.subscribe(&[es_event_type_t::ES_EVENT_TYPE_AUTH_OPEN]) {
                    let _ = error_tx.send(Err(Error::monitor(format!(
                        "Failed to subscribe to AUTH_OPEN: {:?}",
                        e
                    ))));
                    return;
                }

                tracing::info!("Subscribed to ES_EVENT_TYPE_AUTH_OPEN events");

                // Clear any stale cache
                if let Err(e) = client.clear_cache() {
                    tracing::debug!("Cache clear note: {:?}", e);
                }

                // Signal success - client is ready
                let _ = error_tx.send(Ok(()));

                tracing::info!("ESF monitor ready - unauthorized file access will be DENIED");

                // The ESF client runs its own dispatch queue internally via Grand Central Dispatch.
                // We just need to keep the client alive. This thread will block forever (or until
                // the process exits). The ESF framework handles event delivery.
                loop {
                    std::thread::sleep(Duration::from_secs(3600));
                }
            })
            .map_err(|e| Error::monitor(format!("Failed to spawn ESF thread: {}", e)))?;

        // Wait for the ESF thread to report success or failure
        match error_rx.await {
            Ok(result) => result?,
            Err(_) => {
                return Err(Error::monitor("ESF thread terminated unexpectedly"));
            }
        }

        // Keep the monitor alive - the actual work happens on the ESF thread
        loop {
            tokio::time::sleep(Duration::from_secs(3600)).await;
        }
    }

    async fn stop(&mut self) -> Result<()> {
        // The ESF thread will be terminated when the process exits
        tracing::info!("ESF monitor stopped");
        Ok(())
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    // -------------------------------------------------------------------------
    // determine_response() tests - core decision logic
    // -------------------------------------------------------------------------

    fn make_event_info(
        file_path: Option<&str>,
        is_auth_open: bool,
        is_auth_event: bool,
        deadline_remaining: Option<Duration>,
    ) -> EventInfo {
        EventInfo {
            file_path: file_path.map(|s| s.to_string()),
            is_auth_open,
            is_auth_event,
            deadline_remaining,
            process_context: ProcessContext::new(PathBuf::from("/usr/bin/test")),
        }
    }

    #[test]
    fn test_determine_response_not_auth_event() {
        let info = make_event_info(
            Some("/test/file"),
            false,
            false,
            Some(Duration::from_secs(30)),
        );
        let result = determine_response(&info, false, false);

        assert_eq!(result.decision, ResponseDecision::NoResponse);
        assert_eq!(result.reason, ResponseReason::NotAuthEvent);
    }

    #[test]
    fn test_determine_response_auth_but_not_open() {
        let info = make_event_info(
            Some("/test/file"),
            false,
            true,
            Some(Duration::from_secs(30)),
        );
        let result = determine_response(&info, false, false);

        assert_eq!(result.decision, ResponseDecision::AllowAuth);
        assert_eq!(result.reason, ResponseReason::NotAuthOpen);
    }

    #[test]
    fn test_determine_response_no_file_path() {
        let info = make_event_info(None, true, true, Some(Duration::from_secs(30)));
        let result = determine_response(&info, false, false);

        assert_eq!(
            result.decision,
            ResponseDecision::AllowFlags { cache: false }
        );
        assert_eq!(result.reason, ResponseReason::NoFilePath);
    }

    #[test]
    fn test_determine_response_excluded() {
        let info = make_event_info(
            Some("/excluded/file"),
            true,
            true,
            Some(Duration::from_secs(30)),
        );
        let result = determine_response(&info, true, false);

        assert_eq!(
            result.decision,
            ResponseDecision::AllowFlags { cache: true }
        );
        assert_eq!(result.reason, ResponseReason::Excluded);
    }

    #[test]
    fn test_determine_response_deadline_close() {
        let info = make_event_info(
            Some("/test/file"),
            true,
            true,
            Some(Duration::from_secs(3)), // Less than threshold
        );
        let result = determine_response(&info, false, false);

        assert_eq!(
            result.decision,
            ResponseDecision::AllowFlags { cache: false }
        );
        assert_eq!(result.reason, ResponseReason::DeadlineClose);
    }

    #[test]
    fn test_determine_response_deadline_passed() {
        let info = make_event_info(
            Some("/test/file"),
            true,
            true,
            None, // Deadline passed
        );
        let result = determine_response(&info, false, false);

        assert_eq!(
            result.decision,
            ResponseDecision::AllowFlags { cache: false }
        );
        assert_eq!(result.reason, ResponseReason::DeadlinePassed);
    }

    #[test]
    fn test_determine_response_violation() {
        let info = make_event_info(
            Some("~/.ssh/id_rsa"),
            true,
            true,
            Some(Duration::from_secs(30)),
        );
        let result = determine_response(&info, false, true);

        assert_eq!(result.decision, ResponseDecision::DenyFlags);
        assert_eq!(result.reason, ResponseReason::Violation);
    }

    #[test]
    fn test_determine_response_allowed() {
        let info = make_event_info(
            Some("/normal/file"),
            true,
            true,
            Some(Duration::from_secs(30)),
        );
        let result = determine_response(&info, false, false);

        assert_eq!(
            result.decision,
            ResponseDecision::AllowFlags { cache: true }
        );
        assert_eq!(result.reason, ResponseReason::Allowed);
    }

    #[test]
    fn test_determine_response_deadline_exactly_at_threshold() {
        let info = make_event_info(
            Some("/test/file"),
            true,
            true,
            Some(DEADLINE_THRESHOLD), // Exactly at threshold
        );
        let result = determine_response(&info, false, false);

        // At threshold should still be processed (not less than)
        assert_eq!(
            result.decision,
            ResponseDecision::AllowFlags { cache: true }
        );
        assert_eq!(result.reason, ResponseReason::Allowed);
    }

    #[test]
    fn test_determine_response_deadline_just_under_threshold() {
        let info = make_event_info(
            Some("/test/file"),
            true,
            true,
            Some(DEADLINE_THRESHOLD - Duration::from_millis(1)),
        );
        let result = determine_response(&info, false, false);

        assert_eq!(
            result.decision,
            ResponseDecision::AllowFlags { cache: false }
        );
        assert_eq!(result.reason, ResponseReason::DeadlineClose);
    }

    // -------------------------------------------------------------------------
    // Path conversion tests
    // -------------------------------------------------------------------------

    #[test]
    fn test_convert_path_to_home_relative_matches() {
        // Test with actual home directory lookup
        let current_uid = unsafe { libc::getuid() };
        if let Some(home) = crate::process::get_home_for_uid(current_uid) {
            let home_str = home.to_string_lossy();
            let test_path = format!("{}/.ssh/id_rsa", home_str);

            let result = convert_path_to_home_relative(&test_path, current_uid);
            assert_eq!(result, "~/.ssh/id_rsa");
        }
    }

    #[test]
    fn test_convert_path_to_home_relative_no_match() {
        let path = "/usr/bin/cat";
        let result = convert_path_to_home_relative(path, 0);

        // Should return unchanged if not under home
        // (root's home is /var/root, so /usr/bin/cat won't match)
        assert_eq!(result, "/usr/bin/cat");
    }

    #[test]
    fn test_convert_path_to_home_relative_invalid_uid() {
        let path = "/some/path";
        // Use an invalid UID that won't have a home directory
        let result = convert_path_to_home_relative(path, 99999);
        assert_eq!(result, "/some/path");
    }

    // -------------------------------------------------------------------------
    // Directory path detection tests
    // -------------------------------------------------------------------------

    #[test]
    fn test_is_directory_path_true() {
        assert!(is_directory_path("/Users/test/"));
        assert!(is_directory_path("/var/"));
        assert!(is_directory_path("/"));
        assert!(is_directory_path("./relative/dir/"));
    }

    #[test]
    fn test_is_directory_path_false() {
        assert!(!is_directory_path("/Users/test/file.txt"));
        assert!(!is_directory_path("/var/log/system.log"));
        assert!(!is_directory_path("file"));
        assert!(!is_directory_path(""));
    }

    // -------------------------------------------------------------------------
    // ProcessContext building tests
    // -------------------------------------------------------------------------

    #[test]
    fn test_build_process_context_from_info_minimal() {
        let ctx = build_process_context_from_info(
            PathBuf::from("/usr/bin/test"),
            1234,
            501,
            0, // ppid 0 - should not be set
            None,
            None,
            false,
        );

        assert_eq!(ctx.path, PathBuf::from("/usr/bin/test"));
        assert_eq!(ctx.pid, Some(1234));
        assert_eq!(ctx.euid, Some(501));
        assert_eq!(ctx.ppid, None); // ppid <= 0 not set
        assert_eq!(ctx.team_id, None);
        assert_eq!(ctx.signing_id, None);
        assert_eq!(ctx.platform_binary, Some(false));
    }

    #[test]
    fn test_build_process_context_from_info_full() {
        let ctx = build_process_context_from_info(
            PathBuf::from("/Applications/Test.app/Contents/MacOS/Test"),
            5678,
            0,
            1234,
            Some("ABCD1234".to_string()),
            Some("com.example.test".to_string()),
            true,
        );

        assert_eq!(
            ctx.path,
            PathBuf::from("/Applications/Test.app/Contents/MacOS/Test")
        );
        assert_eq!(ctx.pid, Some(5678));
        assert_eq!(ctx.euid, Some(0));
        assert_eq!(ctx.ppid, Some(1234));
        assert_eq!(ctx.team_id, Some("ABCD1234".to_string()));
        assert_eq!(ctx.signing_id, Some("com.example.test".to_string()));
        assert_eq!(ctx.platform_binary, Some(true));
    }

    #[test]
    fn test_build_process_context_from_info_empty_strings() {
        let ctx = build_process_context_from_info(
            PathBuf::from("/test"),
            1,
            1,
            2,
            Some("".to_string()), // Empty team_id
            Some("".to_string()), // Empty signing_id
            false,
        );

        // Empty strings should not be set
        assert_eq!(ctx.team_id, None);
        assert_eq!(ctx.signing_id, None);
    }

    #[test]
    fn test_build_process_context_from_info_ppid_edge_cases() {
        // ppid = 0 should not be set
        let ctx0 =
            build_process_context_from_info(PathBuf::from("/test"), 1, 1, 0, None, None, false);
        assert_eq!(ctx0.ppid, None);

        // ppid = 1 (init/launchd) should be set
        let ctx1 =
            build_process_context_from_info(PathBuf::from("/test"), 1, 1, 1, None, None, false);
        assert_eq!(ctx1.ppid, Some(1));

        // ppid = -1 should not be set
        let ctx_neg =
            build_process_context_from_info(PathBuf::from("/test"), 1, 1, -1, None, None, false);
        assert_eq!(ctx_neg.ppid, None);
    }

    // -------------------------------------------------------------------------
    // Response flag constant tests
    // -------------------------------------------------------------------------

    #[test]
    fn test_esf_flag_constants() {
        assert_eq!(ESF_ALLOW_ALL, u32::MAX);
        assert_eq!(ESF_DENY_ALL, 0);
        assert!(ESF_ALLOW_ALL > ESF_DENY_ALL);
    }

    #[test]
    fn test_deadline_threshold_reasonable() {
        // Threshold should be between 1 and 30 seconds
        assert!(DEADLINE_THRESHOLD >= Duration::from_secs(1));
        assert!(DEADLINE_THRESHOLD <= Duration::from_secs(30));
    }

    // -------------------------------------------------------------------------
    // ResponseDecision equality tests (for comprehensive coverage)
    // -------------------------------------------------------------------------

    #[test]
    fn test_response_decision_equality() {
        assert_eq!(
            ResponseDecision::AllowFlags { cache: true },
            ResponseDecision::AllowFlags { cache: true }
        );
        assert_ne!(
            ResponseDecision::AllowFlags { cache: true },
            ResponseDecision::AllowFlags { cache: false }
        );
        assert_ne!(
            ResponseDecision::AllowFlags { cache: true },
            ResponseDecision::DenyFlags
        );
        assert_ne!(ResponseDecision::DenyFlags, ResponseDecision::AllowAuth);
        assert_ne!(ResponseDecision::AllowAuth, ResponseDecision::NoResponse);
    }

    // -------------------------------------------------------------------------
    // Integration tests (require ESF entitlements)
    // -------------------------------------------------------------------------

    #[test]
    #[ignore = "requires ESF entitlement from Apple"]
    fn test_esf_client_creation() {
        // Would test: Client::new() succeeds with proper entitlements
    }

    #[test]
    #[ignore = "requires ESF entitlement from Apple"]
    fn test_esf_event_processing() {
        // Would test actual event processing with real ESF messages
    }
}
