//! Request handlers for IPC commands.

use super::protocol::{Request, Response, ViolationEvent};
use crate::rules::Exception;
use crate::storage::{Storage, Violation};
use chrono::Utc;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Maximum number of pending events to keep in memory.
const MAX_PENDING_EVENTS: usize = 1000;

/// Convert a PID from u32 to i32 safely for signal operations.
/// Returns None if the PID is too large to fit in i32.
fn pid_to_raw(pid: u32) -> Option<i32> {
    i32::try_from(pid).ok()
}

/// Shared state for request handlers.
pub struct HandlerState {
    pub storage: Arc<Storage>,
    pub mode: Arc<RwLock<String>>,
    pub degraded_mode: Arc<RwLock<bool>>,
    pub start_time: std::time::Instant,
    pub connected_clients: RwLock<usize>,
    pub pending_events: RwLock<Vec<ViolationEvent>>,
    pub config_toml: String,
}

impl HandlerState {
    pub fn new(
        storage: Arc<Storage>,
        mode: Arc<RwLock<String>>,
        degraded_mode: Arc<RwLock<bool>>,
        config_toml: String,
    ) -> Self {
        Self {
            storage,
            mode,
            degraded_mode,
            start_time: std::time::Instant::now(),
            connected_clients: RwLock::new(0),
            pending_events: RwLock::new(Vec::new()),
            config_toml,
        }
    }

    /// Handle a request and produce a response.
    pub async fn handle(&self, request: Request) -> Response {
        match request {
            Request::Ping => Response::Pong,

            Request::Status => self.handle_status().await,

            Request::GetMode => {
                let mode = self.mode.read().await;
                Response::success(mode.clone())
            }

            Request::SetMode { mode } => self.handle_set_mode(mode).await,

            Request::GetViolations { limit, since, .. } => {
                self.handle_get_violations(limit, since).await
            }

            Request::GetExceptions => self.handle_get_exceptions().await,

            Request::AddException {
                process_path,
                code_signer,
                file_pattern,
                is_glob,
                expires_at,
                comment,
            } => {
                self.handle_add_exception(
                    process_path,
                    code_signer,
                    file_pattern,
                    is_glob,
                    expires_at,
                    comment,
                )
                .await
            }

            Request::RemoveException { id } => self.handle_remove_exception(id).await,

            Request::GetConfig => Response::Config {
                toml: self.config_toml.clone(),
            },

            Request::AllowOnce { event_id } => self.handle_allow_once(&event_id).await,

            Request::AllowPermanently {
                event_id,
                expires_at,
                comment,
            } => {
                self.handle_allow_permanently(&event_id, expires_at, comment)
                    .await
            }

            Request::Kill { event_id } => self.handle_kill(&event_id).await,

            Request::Subscribe { .. } | Request::Unsubscribe => {
                // Handled at the server level, not here
                Response::success("OK")
            }
        }
    }

    async fn handle_status(&self) -> Response {
        let mode = self.mode.read().await.clone();
        let degraded_mode = *self.degraded_mode.read().await;
        let connected_clients = *self.connected_clients.read().await;
        let pending_events = self.pending_events.read().await.len();
        let uptime_secs = self.start_time.elapsed().as_secs();
        let total_violations = self.storage.count_violations().unwrap_or(0);

        Response::Status {
            mode,
            degraded_mode,
            events_pending: pending_events,
            connected_clients,
            uptime_secs,
            total_violations,
        }
    }

    async fn handle_set_mode(&self, mode: String) -> Response {
        let valid_modes = ["monitor", "block", "best-effort", "disabled"];
        if !valid_modes.contains(&mode.as_str()) {
            return Response::error(format!(
                "Invalid mode '{}'. Must be one of: {:?}",
                mode, valid_modes
            ));
        }

        *self.mode.write().await = mode.clone();

        if let Err(e) = self.storage.set_state("mode", &mode) {
            tracing::warn!("Failed to persist mode: {}", e);
        }

        Response::success(format!("Mode set to '{}'", mode))
    }

    async fn handle_get_violations(
        &self,
        limit: Option<usize>,
        since: Option<chrono::DateTime<Utc>>,
    ) -> Response {
        let limit = limit.unwrap_or(100);

        match self.storage.get_violations(limit, since) {
            Ok(violations) => {
                let events: Vec<ViolationEvent> =
                    violations.into_iter().map(violation_to_event).collect();
                Response::Violations { events }
            }
            Err(e) => Response::error(format!("Failed to get violations: {}", e)),
        }
    }

    async fn handle_get_exceptions(&self) -> Response {
        match self.storage.get_exceptions() {
            Ok(rules) => Response::Exceptions { rules },
            Err(e) => Response::error(format!("Failed to get exceptions: {}", e)),
        }
    }

    async fn handle_add_exception(
        &self,
        process_path: Option<String>,
        code_signer: Option<String>,
        file_pattern: String,
        is_glob: bool,
        expires_at: Option<chrono::DateTime<Utc>>,
        comment: Option<String>,
    ) -> Response {
        if process_path.is_none() && code_signer.is_none() {
            return Response::error("Must specify either process_path or code_signer");
        }

        let exception = Exception {
            id: 0, // Set by database
            process_path,
            code_signer,
            file_pattern,
            is_glob,
            expires_at,
            added_by: "ui".to_string(),
            comment,
            created_at: Utc::now(),
        };

        match self.storage.add_exception(&exception) {
            Ok(id) => Response::success(format!("Exception added with ID {}", id)),
            Err(e) => Response::error(format!("Failed to add exception: {}", e)),
        }
    }

    async fn handle_remove_exception(&self, id: i64) -> Response {
        match self.storage.remove_exception(id) {
            Ok(true) => Response::success(format!("Exception {} removed", id)),
            Ok(false) => Response::error(format!("Exception {} not found", id)),
            Err(e) => Response::error(format!("Failed to remove exception: {}", e)),
        }
    }

    async fn handle_allow_once(&self, event_id: &str) -> Response {
        // Find the pending event
        let mut pending = self.pending_events.write().await;
        if let Some(pos) = pending.iter().position(|e| e.id == event_id) {
            let event = pending.remove(pos);

            // Resume the process if it was suspended
            #[cfg(unix)]
            {
                use nix::sys::signal::{kill, Signal};
                use nix::unistd::Pid;

                match pid_to_raw(event.process_pid) {
                    Some(raw_pid) => {
                        let pid = Pid::from_raw(raw_pid);
                        if let Err(e) = kill(pid, Signal::SIGCONT) {
                            tracing::warn!("Failed to resume process {}: {}", event.process_pid, e);
                        }
                    }
                    None => {
                        tracing::warn!("PID {} too large for signal operation", event.process_pid);
                    }
                }
            }

            Response::success(format!("Allowed process {} once", event.process_pid))
        } else {
            Response::error(format!("Event {} not found in pending events", event_id))
        }
    }

    async fn handle_allow_permanently(
        &self,
        event_id: &str,
        expires_at: Option<chrono::DateTime<Utc>>,
        comment: Option<String>,
    ) -> Response {
        // Find the event (could be pending or in history)
        let event = {
            let pending = self.pending_events.read().await;
            pending.iter().find(|e| e.id == event_id).cloned()
        };

        let event = match event {
            Some(e) => e,
            None => {
                // Try to find in violation history
                match self.storage.get_violation(event_id) {
                    Ok(Some(v)) => violation_to_event(v),
                    _ => return Response::error(format!("Event {} not found", event_id)),
                }
            }
        };

        // Create exception
        let exception = Exception {
            id: 0,
            process_path: Some(event.process_path.clone()),
            code_signer: event.team_id.clone(),
            file_pattern: event.file_path.clone(),
            is_glob: false,
            expires_at,
            added_by: "ui".to_string(),
            comment,
            created_at: Utc::now(),
        };

        if let Err(e) = self.storage.add_exception(&exception) {
            return Response::error(format!("Failed to add exception: {}", e));
        }

        // Resume if pending
        let allow_once_response = self.handle_allow_once(event_id).await;

        match allow_once_response {
            Response::Success { .. } => {
                Response::success(format!("Exception added for {}", event.process_path))
            }
            _ => Response::success(format!("Exception added for {}", event.process_path)),
        }
    }

    async fn handle_kill(&self, event_id: &str) -> Response {
        let mut pending = self.pending_events.write().await;
        if let Some(pos) = pending.iter().position(|e| e.id == event_id) {
            let event = pending.remove(pos);

            #[cfg(unix)]
            {
                use nix::sys::signal::{kill, Signal};
                use nix::unistd::Pid;

                match pid_to_raw(event.process_pid) {
                    Some(raw_pid) => {
                        let pid = Pid::from_raw(raw_pid);
                        if let Err(e) = kill(pid, Signal::SIGKILL) {
                            return Response::error(format!(
                                "Failed to kill process {}: {}",
                                event.process_pid, e
                            ));
                        }
                    }
                    None => {
                        return Response::error(format!(
                            "PID {} too large for signal operation",
                            event.process_pid
                        ));
                    }
                }
            }

            Response::success(format!("Killed process {}", event.process_pid))
        } else {
            Response::error(format!("Event {} not found in pending events", event_id))
        }
    }

    /// Add an event to pending and return it for broadcasting.
    pub async fn add_pending_event(&self, event: ViolationEvent) -> ViolationEvent {
        let mut pending = self.pending_events.write().await;

        // Limit pending events to prevent memory issues
        if pending.len() >= MAX_PENDING_EVENTS {
            let dropped = pending.remove(0);
            tracing::warn!(
                "Pending event queue full, dropped oldest event: {}",
                dropped.id
            );
        }

        pending.push(event.clone());
        event
    }
}

fn violation_to_event(v: Violation) -> ViolationEvent {
    ViolationEvent {
        id: v.id,
        timestamp: v.timestamp,
        rule_id: v.rule_id,
        file_path: v.file_path,
        process_path: v.process_path,
        process_pid: v.process_pid,
        process_cmdline: v.process_cmdline,
        process_euid: v.process_euid,
        parent_pid: v.process_ppid,
        team_id: v.team_id,
        signing_id: v.signing_id,
        action: v.action,
        process_tree: v.process_tree,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn create_test_state() -> (HandlerState, TempDir) {
        let temp_dir = TempDir::new().unwrap();
        let db_path = temp_dir.path().join("test.db");
        let storage = Arc::new(Storage::open(&db_path).unwrap());
        let mode = Arc::new(RwLock::new("block".to_string()));
        let degraded_mode = Arc::new(RwLock::new(false));
        let state = HandlerState::new(
            storage,
            mode,
            degraded_mode,
            "[agent]\nlog_level = \"info\"".to_string(),
        );
        (state, temp_dir)
    }

    #[test]
    fn test_pid_to_raw() {
        assert_eq!(pid_to_raw(0), Some(0));
        assert_eq!(pid_to_raw(1), Some(1));
        assert_eq!(pid_to_raw(12345), Some(12345));
        assert_eq!(pid_to_raw(i32::MAX as u32), Some(i32::MAX));
        // Values larger than i32::MAX should return None
        assert_eq!(pid_to_raw(i32::MAX as u32 + 1), None);
        assert_eq!(pid_to_raw(u32::MAX), None);
    }

    #[test]
    fn test_handler_state_new() {
        let temp_dir = TempDir::new().unwrap();
        let db_path = temp_dir.path().join("test.db");
        let storage = Arc::new(Storage::open(&db_path).unwrap());
        let mode = Arc::new(RwLock::new("block".to_string()));
        let degraded_mode = Arc::new(RwLock::new(false));
        let state = HandlerState::new(storage, mode, degraded_mode, "test config".to_string());

        assert_eq!(state.config_toml, "test config");
    }

    #[tokio::test]
    async fn test_handle_ping() {
        let (state, _dir) = create_test_state();
        let response = state.handle(Request::Ping).await;
        assert!(matches!(response, Response::Pong));
    }

    #[tokio::test]
    async fn test_handle_get_mode() {
        let (state, _dir) = create_test_state();
        let response = state.handle(Request::GetMode).await;
        match response {
            Response::Success { message } => assert_eq!(message, "block"),
            _ => panic!("Expected Success response"),
        }
    }

    #[tokio::test]
    async fn test_handle_set_mode_valid() {
        let (state, _dir) = create_test_state();

        let response = state
            .handle(Request::SetMode {
                mode: "monitor".to_string(),
            })
            .await;
        match response {
            Response::Success { message } => assert!(message.contains("monitor")),
            _ => panic!("Expected Success response"),
        }

        // Verify mode was changed
        let mode = state.mode.read().await;
        assert_eq!(*mode, "monitor");
    }

    #[tokio::test]
    async fn test_handle_set_mode_invalid() {
        let (state, _dir) = create_test_state();

        let response = state
            .handle(Request::SetMode {
                mode: "invalid".to_string(),
            })
            .await;
        match response {
            Response::Error { message, .. } => assert!(message.contains("Invalid mode")),
            _ => panic!("Expected Error response"),
        }

        // Verify mode was not changed
        let mode = state.mode.read().await;
        assert_eq!(*mode, "block");
    }

    #[tokio::test]
    async fn test_handle_status() {
        let (state, _dir) = create_test_state();
        let response = state.handle(Request::Status).await;
        match response {
            Response::Status {
                mode,
                events_pending,
                ..
            } => {
                assert_eq!(mode, "block");
                assert_eq!(events_pending, 0);
            }
            _ => panic!("Expected Status response"),
        }
    }

    #[tokio::test]
    async fn test_handle_get_config() {
        let (state, _dir) = create_test_state();
        let response = state.handle(Request::GetConfig).await;
        match response {
            Response::Config { toml } => assert!(toml.contains("log_level")),
            _ => panic!("Expected Config response"),
        }
    }

    #[tokio::test]
    async fn test_handle_get_violations_empty() {
        let (state, _dir) = create_test_state();
        let response = state
            .handle(Request::GetViolations {
                limit: None,
                since: None,
                file_path: None,
            })
            .await;
        match response {
            Response::Violations { events } => assert!(events.is_empty()),
            _ => panic!("Expected Violations response"),
        }
    }

    #[tokio::test]
    async fn test_handle_get_exceptions_empty() {
        let (state, _dir) = create_test_state();
        let response = state.handle(Request::GetExceptions).await;
        match response {
            Response::Exceptions { rules } => assert!(rules.is_empty()),
            _ => panic!("Expected Exceptions response"),
        }
    }

    #[tokio::test]
    async fn test_handle_add_exception_valid() {
        let (state, _dir) = create_test_state();
        let response = state
            .handle(Request::AddException {
                process_path: Some("/usr/bin/test".to_string()),
                code_signer: None,
                file_pattern: "~/.ssh/*".to_string(),
                is_glob: true,
                expires_at: None,
                comment: Some("Test exception".to_string()),
            })
            .await;
        match response {
            Response::Success { message } => assert!(message.contains("Exception added")),
            _ => panic!("Expected Success response"),
        }

        // Verify exception was added
        let exceptions = state.storage.get_exceptions().unwrap();
        assert_eq!(exceptions.len(), 1);
    }

    #[tokio::test]
    async fn test_handle_add_exception_with_code_signer() {
        let (state, _dir) = create_test_state();
        let response = state
            .handle(Request::AddException {
                process_path: None,
                code_signer: Some("APPLE123".to_string()),
                file_pattern: "~/.ssh/*".to_string(),
                is_glob: true,
                expires_at: None,
                comment: None,
            })
            .await;
        match response {
            Response::Success { message } => assert!(message.contains("Exception added")),
            _ => panic!("Expected Success response"),
        }
    }

    #[tokio::test]
    async fn test_handle_add_exception_invalid_no_identifier() {
        let (state, _dir) = create_test_state();
        let response = state
            .handle(Request::AddException {
                process_path: None,
                code_signer: None,
                file_pattern: "~/.ssh/*".to_string(),
                is_glob: true,
                expires_at: None,
                comment: None,
            })
            .await;
        match response {
            Response::Error { message, .. } => {
                assert!(message.contains("process_path") || message.contains("code_signer"))
            }
            _ => panic!("Expected Error response"),
        }
    }

    #[tokio::test]
    async fn test_handle_remove_exception() {
        let (state, _dir) = create_test_state();

        // First add an exception
        let exception = Exception {
            id: 0,
            process_path: Some("/test".to_string()),
            code_signer: None,
            file_pattern: "~/.test".to_string(),
            is_glob: false,
            expires_at: None,
            added_by: "test".to_string(),
            comment: None,
            created_at: Utc::now(),
        };
        let id = state.storage.add_exception(&exception).unwrap();

        // Remove it
        let response = state.handle(Request::RemoveException { id }).await;
        match response {
            Response::Success { message } => assert!(message.contains("removed")),
            _ => panic!("Expected Success response"),
        }

        // Verify it's gone
        let exceptions = state.storage.get_exceptions().unwrap();
        assert!(exceptions.is_empty());
    }

    #[tokio::test]
    async fn test_handle_remove_exception_not_found() {
        let (state, _dir) = create_test_state();
        let response = state.handle(Request::RemoveException { id: 999 }).await;
        match response {
            Response::Error { message, .. } => assert!(message.contains("not found")),
            _ => panic!("Expected Error response"),
        }
    }

    #[tokio::test]
    async fn test_handle_allow_once_not_found() {
        let (state, _dir) = create_test_state();
        let response = state
            .handle(Request::AllowOnce {
                event_id: "nonexistent".to_string(),
            })
            .await;
        match response {
            Response::Error { message, .. } => assert!(message.contains("not found")),
            _ => panic!("Expected Error response"),
        }
    }

    #[tokio::test]
    async fn test_handle_kill_not_found() {
        let (state, _dir) = create_test_state();
        let response = state
            .handle(Request::Kill {
                event_id: "nonexistent".to_string(),
            })
            .await;
        match response {
            Response::Error { message, .. } => assert!(message.contains("not found")),
            _ => panic!("Expected Error response"),
        }
    }

    #[tokio::test]
    async fn test_handle_subscribe() {
        let (state, _dir) = create_test_state();
        let response = state.handle(Request::Subscribe { filter: None }).await;
        match response {
            Response::Success { message } => assert_eq!(message, "OK"),
            _ => panic!("Expected Success response"),
        }
    }

    #[tokio::test]
    async fn test_handle_unsubscribe() {
        let (state, _dir) = create_test_state();
        let response = state.handle(Request::Unsubscribe).await;
        match response {
            Response::Success { message } => assert_eq!(message, "OK"),
            _ => panic!("Expected Success response"),
        }
    }

    #[tokio::test]
    async fn test_add_pending_event() {
        let (state, _dir) = create_test_state();
        let event = ViolationEvent::new(
            "~/.ssh/id_rsa".to_string(),
            "/usr/bin/cat".to_string(),
            1234,
            "blocked".to_string(),
        );

        let returned_event = state.add_pending_event(event.clone()).await;
        assert_eq!(returned_event.id, event.id);

        let pending = state.pending_events.read().await;
        assert_eq!(pending.len(), 1);
    }

    #[tokio::test]
    async fn test_add_pending_event_overflow() {
        let (state, _dir) = create_test_state();

        // Add MAX_PENDING_EVENTS + 1 events
        for i in 0..=MAX_PENDING_EVENTS {
            let event = ViolationEvent::new(
                format!("~/.ssh/id_{}", i),
                "/usr/bin/cat".to_string(),
                i as u32,
                "blocked".to_string(),
            );
            state.add_pending_event(event).await;
        }

        let pending = state.pending_events.read().await;
        // Should be limited to MAX_PENDING_EVENTS
        assert_eq!(pending.len(), MAX_PENDING_EVENTS);
        // First event should have been dropped
        assert!(pending[0].file_path.contains("_1"));
    }

    #[tokio::test]
    async fn test_handle_allow_permanently_not_found() {
        let (state, _dir) = create_test_state();
        let response = state
            .handle(Request::AllowPermanently {
                event_id: "nonexistent".to_string(),
                expires_at: None,
                comment: None,
            })
            .await;
        match response {
            Response::Error { message, .. } => assert!(message.contains("not found")),
            _ => panic!("Expected Error response"),
        }
    }

    #[tokio::test]
    async fn test_handle_allow_once_with_pending_event() {
        let (state, _dir) = create_test_state();

        // Add a pending event with a known PID (use current process PID for testing)
        let pid = std::process::id();
        let event = ViolationEvent::new(
            "~/.ssh/id_rsa".to_string(),
            "/usr/bin/cat".to_string(),
            pid,
            "blocked".to_string(),
        );
        let event_id = event.id.clone();
        state.add_pending_event(event).await;

        // Allow it once
        let response = state.handle(Request::AllowOnce { event_id }).await;
        match response {
            Response::Success { message } => assert!(message.contains("Allowed")),
            _ => panic!("Expected Success response"),
        }

        // Verify it was removed from pending
        let pending = state.pending_events.read().await;
        assert!(pending.is_empty());
    }

    #[tokio::test]
    async fn test_violation_to_event() {
        let violation =
            Violation::new("~/.ssh/id_rsa", "/usr/bin/cat".to_string(), 1234, "blocked")
                .with_rule_id("ssh_keys")
                .with_ppid(1)
                .with_euid(501)
                .with_cmdline("cat ~/.ssh/id_rsa")
                .with_team_id("APPLE123")
                .with_signing_id("com.apple.cat");

        let event = violation_to_event(violation.clone());

        assert_eq!(event.file_path, "~/.ssh/id_rsa");
        assert_eq!(event.process_path, "/usr/bin/cat");
        assert_eq!(event.process_pid, 1234);
        assert_eq!(event.action, "blocked");
        assert_eq!(event.rule_id, Some("ssh_keys".to_string()));
        assert_eq!(event.parent_pid, Some(1));
        assert_eq!(event.process_euid, Some(501));
        assert_eq!(event.process_cmdline, Some("cat ~/.ssh/id_rsa".to_string()));
        assert_eq!(event.team_id, Some("APPLE123".to_string()));
        assert_eq!(event.signing_id, Some("com.apple.cat".to_string()));
    }
}
