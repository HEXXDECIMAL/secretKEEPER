//! Request handlers for IPC commands.

use super::protocol::{
    AddExceptionParams, Category, LearningRecommendation, Request, Response, ViolationEvent,
};
use crate::rules::{Exception, RuleEngine, SignerType};
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
    /// Pending events awaiting user action. Shared with MonitorContext.
    pub pending_events: Arc<RwLock<Vec<ViolationEvent>>>,
    pub config_toml: String,
    pub rule_engine: Arc<RwLock<RuleEngine>>,
}

impl HandlerState {
    pub fn new(
        storage: Arc<Storage>,
        mode: Arc<RwLock<String>>,
        degraded_mode: Arc<RwLock<bool>>,
        config_toml: String,
        rule_engine: Arc<RwLock<RuleEngine>>,
        pending_events: Arc<RwLock<Vec<ViolationEvent>>>,
    ) -> Self {
        Self {
            storage,
            mode,
            degraded_mode,
            start_time: std::time::Instant::now(),
            connected_clients: RwLock::new(0),
            pending_events,
            config_toml,
            rule_engine,
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

            Request::AddException(params) => self.handle_add_exception(params).await,

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

            Request::GetCategories => self.handle_get_categories().await,

            Request::SetCategoryEnabled {
                category_id,
                enabled,
            } => {
                self.handle_set_category_enabled(&category_id, enabled)
                    .await
            }

            Request::Subscribe { .. } | Request::Unsubscribe => {
                // Handled at the server level, not here
                Response::success("OK")
            }

            Request::GetAgentInfo => self.handle_get_agent_info(),

            Request::ResumeProcess { pid } => self.handle_resume_process(pid),

            // Learning mode commands
            Request::GetLearningStatus => self.handle_get_learning_status(),
            Request::GetLearningRecommendations => self.handle_get_learning_recommendations(),
            Request::ApproveLearning { id } => self.handle_approve_learning(id),
            Request::RejectLearning { id } => self.handle_reject_learning(id),
            Request::ApproveAllLearnings => self.handle_approve_all_learnings(),
            Request::RejectAllLearnings => self.handle_reject_all_learnings(),
            Request::CompleteLearningReview => self.handle_complete_learning_review(),
            Request::EndLearningEarly => self.handle_end_learning_early(),
        }
    }

    fn handle_get_agent_info(&self) -> Response {
        // Get the binary modification time
        let binary_path = std::env::current_exe().unwrap_or_default();
        let binary_mtime = std::fs::metadata(&binary_path)
            .and_then(|m| m.modified())
            .map(|t| {
                t.duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs() as i64
            })
            .unwrap_or(0);

        Response::AgentInfo {
            binary_mtime,
            version: env!("CARGO_PKG_VERSION").to_string(),
        }
    }

    fn handle_resume_process(&self, pid: u32) -> Response {
        #[cfg(unix)]
        {
            use nix::sys::signal::{kill, Signal};
            use nix::unistd::Pid;

            // Validate PID is reasonable (not 0 or 1)
            if pid <= 1 {
                return Response::error(format!("Cannot resume PID {}", pid));
            }

            match pid_to_raw(pid) {
                Some(raw_pid) => {
                    let nix_pid = Pid::from_raw(raw_pid);
                    match kill(nix_pid, Signal::SIGCONT) {
                        Ok(()) => {
                            tracing::info!("Resumed process {} via ResumeProcess command", pid);
                            Response::success(format!("Resumed process {}", pid))
                        }
                        Err(e) => {
                            tracing::warn!("Failed to resume process {}: {}", pid, e);
                            Response::error(format!("Failed to resume process {}: {}", pid, e))
                        }
                    }
                }
                None => {
                    tracing::warn!("PID {} too large for signal operation", pid);
                    Response::error(format!("PID {} too large for signal operation", pid))
                }
            }
        }

        #[cfg(not(unix))]
        {
            let _ = pid;
            Response::error("ResumeProcess not supported on this platform")
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

    async fn handle_add_exception(&self, params: AddExceptionParams) -> Response {
        // Must have at least one identifier
        let has_signer =
            params.team_id.is_some() || params.signing_id.is_some() || params.signer_type.is_some();
        if params.process_path.is_none() && !has_signer {
            return Response::error(
                "Must specify either process_path or signer (signer_type + team_id/signing_id)",
            );
        }

        // Parse signer_type if provided
        let parsed_signer_type: Option<SignerType> = match params.signer_type {
            Some(s) => match s.parse() {
                Ok(t) => Some(t),
                Err(e) => return Response::error(format!("Invalid signer_type: {}", e)),
            },
            None => {
                // Infer signer_type from team_id/signing_id if not explicitly provided
                if params.team_id.is_some() {
                    Some(SignerType::TeamId)
                } else if params.signing_id.is_some() {
                    // Default to SigningId if only signing_id is provided
                    Some(SignerType::SigningId)
                } else {
                    None
                }
            }
        };

        let exception = Exception {
            id: 0, // Set by database
            process_path: params.process_path,
            signer_type: parsed_signer_type,
            team_id: params.team_id,
            signing_id: params.signing_id,
            file_pattern: params.file_pattern,
            is_glob: params.is_glob,
            expires_at: params.expires_at,
            added_by: "ui".to_string(),
            comment: params.comment,
            created_at: Utc::now(),
            source: crate::rules::ExceptionSource::User,
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

            // Resume the process and its parent if they were suspended
            #[cfg(unix)]
            {
                use nix::sys::signal::{kill, Signal};
                use nix::unistd::Pid;

                // Resume child process
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

                // Resume parent process if it was also stopped
                if let Some(ppid) = event.parent_pid {
                    if ppid > 1 {
                        if let Some(raw_ppid) = pid_to_raw(ppid) {
                            let parent = Pid::from_raw(raw_ppid);
                            if let Err(e) = kill(parent, Signal::SIGCONT) {
                                tracing::warn!("Failed to resume parent process {}: {}", ppid, e);
                            } else {
                                tracing::info!("Resumed parent process {}", ppid);
                            }
                        }
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

        // Create exception - determine signer type from event
        let (signer_type, team_id, signing_id) = if event.team_id.is_some() {
            (
                Some(SignerType::TeamId),
                event.team_id.clone(),
                event.signing_id.clone(),
            )
        } else if event.signing_id.is_some() {
            // No team_id but has signing_id - could be platform binary or adhoc
            // Use SigningId type for platform binaries
            (Some(SignerType::SigningId), None, event.signing_id.clone())
        } else {
            // No signing info at all
            (None, None, None)
        };

        let exception = Exception {
            id: 0,
            process_path: Some(event.process_path.clone()),
            signer_type,
            team_id,
            signing_id,
            file_pattern: event.file_path.clone(),
            is_glob: false,
            expires_at,
            added_by: "ui".to_string(),
            comment,
            created_at: Utc::now(),
            source: crate::rules::ExceptionSource::User,
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

                // Kill child process
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

                // Kill parent process if it was also stopped
                if let Some(ppid) = event.parent_pid {
                    if ppid > 1 {
                        if let Some(raw_ppid) = pid_to_raw(ppid) {
                            let parent = Pid::from_raw(raw_ppid);
                            if let Err(e) = kill(parent, Signal::SIGKILL) {
                                tracing::warn!("Failed to kill parent process {}: {}", ppid, e);
                            } else {
                                tracing::info!("Killed parent process {}", ppid);
                            }
                        }
                    }
                }
            }

            Response::success(format!("Killed process {} and parent", event.process_pid))
        } else {
            Response::error(format!("Event {} not found in pending events", event_id))
        }
    }

    async fn handle_get_categories(&self) -> Response {
        let rule_engine = self.rule_engine.read().await;
        let categories: Vec<Category> = rule_engine
            .get_categories()
            .into_iter()
            .map(|(id, enabled)| {
                // Get patterns for this category from the protected files
                let patterns = rule_engine
                    .protected_files()
                    .iter()
                    .find(|pf| pf.id == id)
                    .map(|pf| pf.patterns.clone())
                    .unwrap_or_default();
                Category {
                    id,
                    enabled,
                    patterns,
                }
            })
            .collect();
        Response::Categories { categories }
    }

    async fn handle_set_category_enabled(&self, category_id: &str, enabled: bool) -> Response {
        let mut rule_engine = self.rule_engine.write().await;
        rule_engine.set_category_enabled(category_id, enabled);
        let status = if enabled { "enabled" } else { "disabled" };
        Response::success(format!("Category '{}' {}", category_id, status))
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

// =============================================================================
// Learning mode handlers
// =============================================================================

/// State key for learning mode persistence.
const LEARNING_START_KEY: &str = "learning_start_time";
const LEARNING_STATE_KEY: &str = "learning_state";
const LEARNING_DURATION_HOURS: u64 = 24;

impl HandlerState {
    fn handle_get_learning_status(&self) -> Response {
        // Get state from storage
        let state = self
            .storage
            .get_state(LEARNING_STATE_KEY)
            .ok()
            .flatten()
            .unwrap_or_else(|| "disabled".to_string());

        // Calculate hours remaining
        let hours_remaining = if state == "learning" {
            self.storage
                .get_state(LEARNING_START_KEY)
                .ok()
                .flatten()
                .and_then(|s| s.parse::<u64>().ok())
                .map(|start| {
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs();
                    let elapsed_hours = (now.saturating_sub(start)) / 3600;
                    LEARNING_DURATION_HOURS.saturating_sub(elapsed_hours) as u32
                })
                .unwrap_or(0)
        } else {
            0
        };

        // Get counts
        let stats = self.storage.count_learned_by_status().unwrap_or_default();

        Response::LearningStatus {
            state,
            hours_remaining,
            pending_count: stats.pending,
            approved_count: stats.approved,
            rejected_count: stats.rejected,
        }
    }

    fn handle_get_learning_recommendations(&self) -> Response {
        match self.storage.get_learned_exceptions("pending") {
            Ok(learnings) => {
                let recommendations: Vec<LearningRecommendation> = learnings
                    .into_iter()
                    .map(|l| LearningRecommendation {
                        id: l.id,
                        category_id: l.category_id,
                        process_path: l.process_path,
                        process_name: l.process_base,
                        team_id: l.team_id,
                        signing_id: l.signing_id,
                        is_platform_binary: l.is_platform_binary,
                        observation_count: l.observation_count,
                        status: l.status,
                    })
                    .collect();
                Response::LearningRecommendations { recommendations }
            }
            Err(e) => Response::error(format!("Failed to get recommendations: {}", e)),
        }
    }

    fn handle_approve_learning(&self, id: i64) -> Response {
        match self.storage.approve_learning(id) {
            Ok(true) => Response::success(format!("Approved recommendation {}", id)),
            Ok(false) => Response::error(format!(
                "Recommendation {} not found or already processed",
                id
            )),
            Err(e) => Response::error(format!("Failed to approve: {}", e)),
        }
    }

    fn handle_reject_learning(&self, id: i64) -> Response {
        match self.storage.reject_learning(id) {
            Ok(true) => Response::success(format!("Rejected recommendation {}", id)),
            Ok(false) => Response::error(format!(
                "Recommendation {} not found or already processed",
                id
            )),
            Err(e) => Response::error(format!("Failed to reject: {}", e)),
        }
    }

    fn handle_approve_all_learnings(&self) -> Response {
        match self.storage.approve_all_learnings() {
            Ok(count) => Response::success(format!("Approved {} recommendations", count)),
            Err(e) => Response::error(format!("Failed to approve all: {}", e)),
        }
    }

    fn handle_reject_all_learnings(&self) -> Response {
        match self.storage.reject_all_learnings() {
            Ok(count) => Response::success(format!("Rejected {} recommendations", count)),
            Err(e) => Response::error(format!("Failed to reject all: {}", e)),
        }
    }

    fn handle_complete_learning_review(&self) -> Response {
        // Check if there are pending recommendations
        if self.storage.has_pending_learnings().unwrap_or(false) {
            return Response::error(
                "Cannot complete review: there are still pending recommendations. \
                 Please approve or reject all recommendations first.",
            );
        }

        // Migrate approved learnings to exceptions
        let migrated = match self.storage.migrate_approved_to_exceptions() {
            Ok(count) => count,
            Err(e) => return Response::error(format!("Failed to migrate exceptions: {}", e)),
        };

        // Transition to complete state
        if let Err(e) = self.storage.set_state(LEARNING_STATE_KEY, "complete") {
            return Response::error(format!("Failed to update state: {}", e));
        }

        Response::success(format!(
            "Learning review complete. Created {} exceptions.",
            migrated
        ))
    }

    fn handle_end_learning_early(&self) -> Response {
        // Check current state
        let current_state = self
            .storage
            .get_state(LEARNING_STATE_KEY)
            .ok()
            .flatten()
            .unwrap_or_else(|| "disabled".to_string());

        if current_state != "learning" {
            return Response::error(format!(
                "Cannot end learning: current state is '{}', expected 'learning'",
                current_state
            ));
        }

        // Transition to pending_review
        if let Err(e) = self.storage.set_state(LEARNING_STATE_KEY, "pending_review") {
            return Response::error(format!("Failed to update state: {}", e));
        }

        Response::success("Learning period ended. Please review recommendations.")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn create_test_state() -> (HandlerState, TempDir) {
        create_test_state_with_protected_files(Vec::new())
    }

    fn create_test_state_with_protected_files(
        protected_files: Vec<crate::config::ProtectedFile>,
    ) -> (HandlerState, TempDir) {
        let temp_dir = TempDir::new().unwrap();
        let db_path = temp_dir.path().join("test.db");
        let storage = Arc::new(Storage::open(&db_path).unwrap());
        let mode = Arc::new(RwLock::new("block".to_string()));
        let degraded_mode = Arc::new(RwLock::new(false));
        let rule_engine = Arc::new(RwLock::new(RuleEngine::new(protected_files, Vec::new())));
        let pending_events = Arc::new(RwLock::new(Vec::new()));
        let state = HandlerState::new(
            storage,
            mode,
            degraded_mode,
            "[agent]\nlog_level = \"info\"".to_string(),
            rule_engine,
            pending_events,
        );
        (state, temp_dir)
    }

    fn make_test_protected_files() -> Vec<crate::config::ProtectedFile> {
        use crate::config::ProtectedFile;
        use crate::rules::AllowRule;
        vec![ProtectedFile {
            id: "ssh_keys".to_string(),
            patterns: vec!["~/.ssh/id_*".to_string()],
            allow: vec![AllowRule {
                base: Some("ssh".to_string()),
                ..Default::default()
            }],
        }]
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
        let rule_engine = Arc::new(RwLock::new(RuleEngine::new(Vec::new(), Vec::new())));
        let pending_events = Arc::new(RwLock::new(Vec::new()));
        let state = HandlerState::new(
            storage,
            mode,
            degraded_mode,
            "test config".to_string(),
            rule_engine,
            pending_events,
        );

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
            .handle(Request::AddException(AddExceptionParams {
                process_path: Some("/usr/bin/test".to_string()),
                signer_type: None,
                team_id: None,
                signing_id: None,
                file_pattern: "~/.ssh/*".to_string(),
                is_glob: true,
                expires_at: None,
                comment: Some("Test exception".to_string()),
            }))
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
            .handle(Request::AddException(AddExceptionParams {
                process_path: None,
                signer_type: Some("team_id".to_string()),
                team_id: Some("APPLE123".to_string()),
                signing_id: None,
                file_pattern: "~/.ssh/*".to_string(),
                is_glob: true,
                expires_at: None,
                comment: None,
            }))
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
            .handle(Request::AddException(AddExceptionParams {
                process_path: None,
                signer_type: None,
                team_id: None,
                signing_id: None,
                file_pattern: "~/.ssh/*".to_string(),
                is_glob: true,
                expires_at: None,
                comment: None,
            }))
            .await;
        match response {
            Response::Error { message, .. } => {
                assert!(message.contains("process_path") || message.contains("signer"))
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
            signer_type: None,
            team_id: None,
            signing_id: None,
            file_pattern: "~/.test".to_string(),
            is_glob: false,
            expires_at: None,
            added_by: "test".to_string(),
            comment: None,
            created_at: Utc::now(),
            source: crate::rules::ExceptionSource::User,
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

    #[tokio::test]
    async fn test_handle_get_categories() {
        let (state, _dir) = create_test_state_with_protected_files(make_test_protected_files());
        let response = state.handle(Request::GetCategories).await;

        match response {
            Response::Categories { categories } => {
                assert_eq!(categories.len(), 1);
                assert_eq!(categories[0].id, "ssh_keys");
                assert!(categories[0].enabled);
                assert!(!categories[0].patterns.is_empty());
            }
            _ => panic!("Expected Categories response"),
        }
    }

    #[tokio::test]
    async fn test_handle_get_categories_empty() {
        let (state, _dir) = create_test_state();
        let response = state.handle(Request::GetCategories).await;

        match response {
            Response::Categories { categories } => {
                assert!(categories.is_empty());
            }
            _ => panic!("Expected Categories response"),
        }
    }

    #[tokio::test]
    async fn test_handle_set_category_enabled_disable() {
        let (state, _dir) = create_test_state_with_protected_files(make_test_protected_files());

        // Disable the category
        let response = state
            .handle(Request::SetCategoryEnabled {
                category_id: "ssh_keys".to_string(),
                enabled: false,
            })
            .await;

        match response {
            Response::Success { message } => {
                assert!(message.contains("disabled"));
            }
            _ => panic!("Expected Success response"),
        }

        // Verify it's disabled
        let response = state.handle(Request::GetCategories).await;
        match response {
            Response::Categories { categories } => {
                assert!(!categories[0].enabled);
            }
            _ => panic!("Expected Categories response"),
        }
    }

    #[tokio::test]
    async fn test_handle_set_category_enabled_enable() {
        let (state, _dir) = create_test_state_with_protected_files(make_test_protected_files());

        // First disable
        state
            .handle(Request::SetCategoryEnabled {
                category_id: "ssh_keys".to_string(),
                enabled: false,
            })
            .await;

        // Then re-enable
        let response = state
            .handle(Request::SetCategoryEnabled {
                category_id: "ssh_keys".to_string(),
                enabled: true,
            })
            .await;

        match response {
            Response::Success { message } => {
                assert!(message.contains("enabled"));
            }
            _ => panic!("Expected Success response"),
        }

        // Verify it's enabled
        let response = state.handle(Request::GetCategories).await;
        match response {
            Response::Categories { categories } => {
                assert!(categories[0].enabled);
            }
            _ => panic!("Expected Categories response"),
        }
    }

    #[tokio::test]
    async fn test_handle_set_category_enabled_nonexistent() {
        let (state, _dir) = create_test_state_with_protected_files(make_test_protected_files());

        // Try to disable a non-existent category
        let response = state
            .handle(Request::SetCategoryEnabled {
                category_id: "nonexistent_category".to_string(),
                enabled: false,
            })
            .await;

        // Should still succeed (no-op for unknown category)
        assert!(matches!(response, Response::Success { .. }));
    }

    // Edge case tests for reliability

    #[tokio::test]
    async fn test_handle_add_exception_with_signing_id_only() {
        // Adding exception with only signing_id should infer signer_type
        let (state, _dir) = create_test_state();
        let response = state
            .handle(Request::AddException(AddExceptionParams {
                process_path: None,
                signer_type: None, // Not specified
                team_id: None,
                signing_id: Some("com.apple.bluetoothd".to_string()),
                file_pattern: "~/.ssh/*".to_string(),
                is_glob: true,
                expires_at: None,
                comment: None,
            }))
            .await;

        // Should succeed - signing_id alone is valid
        match response {
            Response::Success { message } => assert!(message.contains("Exception added")),
            _ => panic!("Expected Success response"),
        }

        // Verify the exception was stored with inferred signer_type
        let exceptions = state.storage.get_exceptions().unwrap();
        assert_eq!(exceptions.len(), 1);
        assert_eq!(
            exceptions[0].signer_type,
            Some(crate::rules::SignerType::SigningId)
        );
    }

    #[tokio::test]
    async fn test_handle_add_exception_with_team_id_only() {
        // Adding exception with only team_id should infer signer_type
        let (state, _dir) = create_test_state();
        let response = state
            .handle(Request::AddException(AddExceptionParams {
                process_path: None,
                signer_type: None, // Not specified
                team_id: Some("APPLE123".to_string()),
                signing_id: None,
                file_pattern: "~/.ssh/*".to_string(),
                is_glob: true,
                expires_at: None,
                comment: None,
            }))
            .await;

        // Should succeed
        match response {
            Response::Success { message } => assert!(message.contains("Exception added")),
            _ => panic!("Expected Success response"),
        }

        // Verify the exception was stored with inferred signer_type
        let exceptions = state.storage.get_exceptions().unwrap();
        assert_eq!(exceptions.len(), 1);
        assert_eq!(
            exceptions[0].signer_type,
            Some(crate::rules::SignerType::TeamId)
        );
    }

    #[tokio::test]
    async fn test_handle_add_exception_explicit_signer_type() {
        // Adding exception with explicit signer_type should use it
        let (state, _dir) = create_test_state();
        let response = state
            .handle(Request::AddException(AddExceptionParams {
                process_path: None,
                signer_type: Some("adhoc".to_string()),
                team_id: None,
                signing_id: Some("adhoc-app-id".to_string()),
                file_pattern: "~/.ssh/*".to_string(),
                is_glob: true,
                expires_at: None,
                comment: None,
            }))
            .await;

        match response {
            Response::Success { message } => assert!(message.contains("Exception added")),
            _ => panic!("Expected Success response"),
        }

        let exceptions = state.storage.get_exceptions().unwrap();
        assert_eq!(exceptions.len(), 1);
        assert_eq!(
            exceptions[0].signer_type,
            Some(crate::rules::SignerType::Adhoc)
        );
    }

    #[tokio::test]
    async fn test_handle_add_exception_invalid_signer_type() {
        // Invalid signer_type string should return error
        let (state, _dir) = create_test_state();
        let response = state
            .handle(Request::AddException(AddExceptionParams {
                process_path: None,
                signer_type: Some("invalid_type".to_string()),
                team_id: Some("TEAM".to_string()),
                signing_id: None,
                file_pattern: "~/.ssh/*".to_string(),
                is_glob: true,
                expires_at: None,
                comment: None,
            }))
            .await;

        match response {
            Response::Error { message, .. } => {
                assert!(
                    message.contains("Invalid signer_type")
                        || message.contains("unknown signer type")
                )
            }
            _ => panic!("Expected Error response"),
        }
    }

    #[tokio::test]
    async fn test_handle_add_exception_unsigned_type() {
        // Adding unsigned exception should work
        let (state, _dir) = create_test_state();
        let response = state
            .handle(Request::AddException(AddExceptionParams {
                process_path: Some("/usr/local/bin/unsigned-tool".to_string()),
                signer_type: Some("unsigned".to_string()),
                team_id: None,
                signing_id: None,
                file_pattern: "~/.ssh/*".to_string(),
                is_glob: true,
                expires_at: None,
                comment: None,
            }))
            .await;

        match response {
            Response::Success { message } => assert!(message.contains("Exception added")),
            _ => panic!("Expected Success response"),
        }

        let exceptions = state.storage.get_exceptions().unwrap();
        assert_eq!(exceptions.len(), 1);
        assert_eq!(
            exceptions[0].signer_type,
            Some(crate::rules::SignerType::Unsigned)
        );
    }

    #[tokio::test]
    async fn test_handle_add_exception_with_process_path_and_signer() {
        // Both process_path and signer can be specified together
        let (state, _dir) = create_test_state();
        let response = state
            .handle(Request::AddException(AddExceptionParams {
                process_path: Some("/usr/bin/ssh".to_string()),
                signer_type: Some("team_id".to_string()),
                team_id: Some("APPLE".to_string()),
                signing_id: None,
                file_pattern: "~/.ssh/*".to_string(),
                is_glob: true,
                expires_at: None,
                comment: Some("Allow Apple ssh".to_string()),
            }))
            .await;

        match response {
            Response::Success { message } => assert!(message.contains("Exception added")),
            _ => panic!("Expected Success response"),
        }

        let exceptions = state.storage.get_exceptions().unwrap();
        assert_eq!(exceptions.len(), 1);
        assert_eq!(exceptions[0].process_path, Some("/usr/bin/ssh".to_string()));
        assert_eq!(exceptions[0].team_id, Some("APPLE".to_string()));
    }

    #[tokio::test]
    async fn test_handle_add_exception_empty_file_pattern() {
        // Empty file_pattern should still be accepted (though not very useful)
        let (state, _dir) = create_test_state();
        let response = state
            .handle(Request::AddException(AddExceptionParams {
                process_path: Some("/usr/bin/test".to_string()),
                signer_type: None,
                team_id: None,
                signing_id: None,
                file_pattern: "".to_string(),
                is_glob: false,
                expires_at: None,
                comment: None,
            }))
            .await;

        // Should succeed - empty pattern won't match anything useful but is valid
        match response {
            Response::Success { message } => assert!(message.contains("Exception added")),
            _ => panic!("Expected Success response"),
        }
    }

    #[tokio::test]
    async fn test_handle_add_exception_with_expiration() {
        let (state, _dir) = create_test_state();
        let expires = Utc::now() + chrono::Duration::hours(1);

        let response = state
            .handle(Request::AddException(AddExceptionParams {
                process_path: Some("/usr/bin/test".to_string()),
                signer_type: None,
                team_id: None,
                signing_id: None,
                file_pattern: "~/.ssh/*".to_string(),
                is_glob: true,
                expires_at: Some(expires),
                comment: None,
            }))
            .await;

        match response {
            Response::Success { message } => assert!(message.contains("Exception added")),
            _ => panic!("Expected Success response"),
        }

        let exceptions = state.storage.get_exceptions().unwrap();
        assert_eq!(exceptions.len(), 1);
        assert!(exceptions[0].expires_at.is_some());
    }
}
