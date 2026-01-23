//! Learning mode support for automatic exception discovery.
//!
//! During the learning period, the agent monitors file access patterns and
//! records observations. After the period ends, users review the recommendations
//! and approve/reject them before enforcement mode can begin.
//!
//! ## State Machine
//!
//! ```text
//! [Disabled] <-- config.enabled = false
//!      |
//!      v
//! [Learning] --> timer running, recording observations
//!      |
//!      v (timer expires)
//! [PendingReview] --> waiting for user to review recommendations
//!      |
//!      v (user completes review)
//! [Complete] --> enforcement mode can begin
//! ```
//!
//! ## Review Process
//!
//! Users can:
//! - View all pending recommendations at any time during learning
//! - Approve or reject individual recommendations
//! - Approve all recommendations at once
//! - Reject (discard) all recommendations at once
//! - Enforcement is blocked until review is complete

#![allow(dead_code)]

use crate::config::LearningConfig;
use crate::process::ProcessContext;
use crate::storage::{LearnedObservation, Storage};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// State keys for learning mode persistence.
const LEARNING_START_KEY: &str = "learning_start_time";
const LEARNING_STATE_KEY: &str = "learning_state";

/// Learning mode states.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LearningState {
    /// Learning is disabled in configuration.
    #[default]
    Disabled,
    /// Actively learning - recording observations.
    Learning,
    /// Learning period complete, waiting for user review.
    PendingReview,
    /// Review complete, enforcement mode can begin.
    Complete,
}

impl std::fmt::Display for LearningState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LearningState::Disabled => write!(f, "disabled"),
            LearningState::Learning => write!(f, "learning"),
            LearningState::PendingReview => write!(f, "pending_review"),
            LearningState::Complete => write!(f, "complete"),
        }
    }
}

impl std::str::FromStr for LearningState {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "disabled" => Ok(LearningState::Disabled),
            "learning" => Ok(LearningState::Learning),
            "pending_review" => Ok(LearningState::PendingReview),
            "complete" => Ok(LearningState::Complete),
            _ => Err(format!("unknown learning state: {}", s)),
        }
    }
}

/// Learning mode controller.
pub struct LearningController {
    config: LearningConfig,
    storage: Arc<Storage>,
}

impl LearningController {
    /// Create a new learning controller.
    pub fn new(config: LearningConfig, storage: Arc<Storage>) -> Self {
        Self { config, storage }
    }

    /// Initialize learning mode. Call this on agent startup.
    /// Returns the current learning state.
    pub fn initialize(&self) -> LearningState {
        if !self.config.enabled {
            tracing::info!("Learning mode disabled in config");
            return LearningState::Disabled;
        }

        // Check persisted state first
        if let Ok(Some(state_str)) = self.storage.get_state(LEARNING_STATE_KEY) {
            if let Ok(state) = state_str.parse::<LearningState>() {
                match state {
                    LearningState::Complete => {
                        tracing::info!("Learning already complete");
                        return LearningState::Complete;
                    }
                    LearningState::PendingReview => {
                        tracing::info!("Learning complete, pending user review");
                        return LearningState::PendingReview;
                    }
                    LearningState::Disabled => {
                        // Config says enabled but state says disabled - re-evaluate
                    }
                    LearningState::Learning => {
                        // Check if timer has expired
                    }
                }
            }
        }

        // Check if we've started learning (timer)
        if let Ok(Some(start_str)) = self.storage.get_state(LEARNING_START_KEY) {
            if let Ok(start_secs) = start_str.parse::<u64>() {
                let elapsed_hours = self.elapsed_hours_since(start_secs);

                if elapsed_hours < self.config.duration_hours as u64 {
                    tracing::info!(
                        "Learning mode active, {} hours remaining",
                        self.config.duration_hours as u64 - elapsed_hours
                    );
                    let _ = self
                        .storage
                        .set_state(LEARNING_STATE_KEY, &LearningState::Learning.to_string());
                    return LearningState::Learning;
                } else {
                    // Timer expired - transition to pending review
                    tracing::info!("Learning period complete, transitioning to review");
                    let _ = self.storage.set_state(
                        LEARNING_STATE_KEY,
                        &LearningState::PendingReview.to_string(),
                    );
                    return LearningState::PendingReview;
                }
            }
        }

        // First run - start learning
        let now = self.current_timestamp();

        if self
            .storage
            .set_state(LEARNING_START_KEY, &now.to_string())
            .is_ok()
        {
            let _ = self
                .storage
                .set_state(LEARNING_STATE_KEY, &LearningState::Learning.to_string());
            tracing::info!(
                "Learning mode started for {} hours",
                self.config.duration_hours
            );
            LearningState::Learning
        } else {
            tracing::warn!("Failed to persist learning start time");
            LearningState::Disabled
        }
    }

    /// Get the current learning state.
    #[must_use]
    pub fn state(&self) -> LearningState {
        if !self.config.enabled {
            return LearningState::Disabled;
        }

        // Check persisted state
        if let Ok(Some(state_str)) = self.storage.get_state(LEARNING_STATE_KEY) {
            if let Ok(state) = state_str.parse::<LearningState>() {
                // If in learning state, check if timer has expired
                if state == LearningState::Learning {
                    if let Ok(Some(start_str)) = self.storage.get_state(LEARNING_START_KEY) {
                        if let Ok(start_secs) = start_str.parse::<u64>() {
                            let elapsed = self.elapsed_hours_since(start_secs);
                            if elapsed >= self.config.duration_hours as u64 {
                                // Auto-transition to pending review
                                let _ = self.storage.set_state(
                                    LEARNING_STATE_KEY,
                                    &LearningState::PendingReview.to_string(),
                                );
                                return LearningState::PendingReview;
                            }
                        }
                    }
                }
                return state;
            }
        }

        LearningState::Disabled
    }

    /// Check if learning mode is currently active (recording observations).
    #[must_use]
    pub fn is_learning(&self) -> bool {
        self.state() == LearningState::Learning
    }

    /// Check if enforcement should be blocked (pending review).
    #[must_use]
    pub fn is_blocking_enforcement(&self) -> bool {
        self.state() == LearningState::PendingReview
    }

    /// Check if learning is complete and enforcement can proceed.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        matches!(
            self.state(),
            LearningState::Complete | LearningState::Disabled
        )
    }

    /// Get remaining learning time in hours.
    #[must_use]
    pub fn hours_remaining(&self) -> u32 {
        if self.state() != LearningState::Learning {
            return 0;
        }

        if let Ok(Some(start_str)) = self.storage.get_state(LEARNING_START_KEY) {
            if let Ok(start_secs) = start_str.parse::<u64>() {
                let elapsed = self.elapsed_hours_since(start_secs);
                return self.config.duration_hours.saturating_sub(elapsed as u32);
            }
        }
        0
    }

    /// Check if a process should be blocked from auto-approval.
    /// Interpreters, shells, and network tools cannot be auto-approved.
    #[must_use]
    pub fn is_blocked_executable(&self, process_base: &str) -> bool {
        self.config
            .blocked_executables
            .iter()
            .any(|blocked| blocked == process_base)
    }

    /// Record an observation for learning.
    /// Returns true if the observation was recorded.
    pub fn record_observation(&self, category_id: &str, context: &ProcessContext) -> bool {
        if !self.is_learning() {
            return false;
        }

        let process_path = context.path.to_string_lossy();
        let process_base = context
            .path
            .file_name()
            .map(|s| s.to_string_lossy().to_string())
            .unwrap_or_default();

        // Don't record blocked executables
        if self.is_blocked_executable(&process_base) {
            tracing::debug!("Skipping learning for blocked executable: {}", process_base);
            return false;
        }

        // Create observation
        let mut obs = LearnedObservation::new(category_id, process_path.as_ref(), &process_base);

        if let Some(ref team_id) = context.team_id {
            obs = obs.with_team_id(team_id);
        }
        if let Some(ref signing_id) = context.signing_id {
            obs = obs.with_signing_id(signing_id);
        }
        if let Some(is_platform) = context.platform_binary {
            obs = obs.with_platform_binary(is_platform);
        }

        // Record the observation
        if let Err(e) = self.storage.record_learned_observation(&obs) {
            tracing::warn!("Failed to record learning observation: {}", e);
            return false;
        }

        tracing::debug!(
            "Recorded learning observation: {} accessing {} (team_id={:?})",
            process_base,
            category_id,
            context.team_id
        );

        true
    }

    // =========================================================================
    // Review workflow methods
    // =========================================================================

    /// Get all pending recommendations for user review.
    pub fn get_pending_recommendations(&self) -> Vec<LearnedObservation> {
        self.storage
            .get_learned_exceptions("pending")
            .unwrap_or_default()
    }

    /// Get all observations (for viewing during learning period).
    pub fn get_all_observations(&self) -> Vec<LearnedObservation> {
        self.storage
            .get_all_learned_observations()
            .unwrap_or_default()
    }

    /// Approve a single recommendation by ID.
    pub fn approve(&self, id: i64) -> bool {
        self.storage.approve_learning(id).unwrap_or(false)
    }

    /// Reject a single recommendation by ID.
    pub fn reject(&self, id: i64) -> bool {
        self.storage.reject_learning(id).unwrap_or(false)
    }

    /// Approve all pending recommendations.
    pub fn approve_all(&self) -> u32 {
        self.storage.approve_all_learnings().unwrap_or(0)
    }

    /// Reject (discard) all pending recommendations.
    pub fn reject_all(&self) -> u32 {
        self.storage.reject_all_learnings().unwrap_or(0)
    }

    /// Complete the review process.
    /// Migrates approved recommendations to exceptions and transitions to Complete state.
    /// Returns the number of exceptions created.
    pub fn complete_review(&self) -> u32 {
        // Migrate approved learnings to exceptions
        let count = self.storage.migrate_approved_to_exceptions().unwrap_or(0);

        // Transition to complete state
        let _ = self
            .storage
            .set_state(LEARNING_STATE_KEY, &LearningState::Complete.to_string());

        tracing::info!("Learning review complete: {} exceptions created", count);

        count
    }

    /// Restart learning mode from scratch.
    /// Clears all existing observations and restarts the learning timer.
    /// Can be called from any state except Disabled (config.enabled = false).
    pub fn restart_learning(&self) -> bool {
        if !self.config.enabled {
            tracing::warn!("Cannot restart learning: disabled in configuration");
            return false;
        }

        // Clear all existing observations
        if let Err(e) = self.storage.clear_learned_observations() {
            tracing::warn!("Failed to clear learned observations: {}", e);
            return false;
        }

        // Reset the start time to now
        let now = self.current_timestamp();
        if let Err(e) = self.storage.set_state(LEARNING_START_KEY, &now.to_string()) {
            tracing::warn!("Failed to set learning start time: {}", e);
            return false;
        }

        // Set state to Learning
        if let Err(e) = self
            .storage
            .set_state(LEARNING_STATE_KEY, &LearningState::Learning.to_string())
        {
            tracing::warn!("Failed to set learning state: {}", e);
            return false;
        }

        tracing::info!(
            "Learning mode restarted for {} hours",
            self.config.duration_hours
        );

        true
    }

    /// Check if there are any pending recommendations.
    pub fn has_pending(&self) -> bool {
        self.storage.has_pending_learnings().unwrap_or(false)
    }

    /// Get learning statistics.
    pub fn stats(&self) -> LearningStats {
        let db_stats = self.storage.count_learned_by_status().unwrap_or_default();
        LearningStats {
            state: self.state(),
            hours_remaining: self.hours_remaining(),
            pending: db_stats.pending,
            approved: db_stats.approved,
            rejected: db_stats.rejected,
        }
    }

    // =========================================================================
    // Helper methods
    // =========================================================================

    fn current_timestamp(&self) -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }

    fn elapsed_hours_since(&self, start_secs: u64) -> u64 {
        let now = self.current_timestamp();
        (now.saturating_sub(start_secs)) / 3600
    }
}

/// Learning mode statistics.
#[derive(Debug, Clone, Default)]
pub struct LearningStats {
    /// Current learning state.
    pub state: LearningState,
    /// Hours remaining in learning period (0 if not learning).
    pub hours_remaining: u32,
    /// Number of pending recommendations.
    pub pending: u32,
    /// Number of approved recommendations.
    pub approved: u32,
    /// Number of rejected recommendations.
    pub rejected: u32,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn test_config() -> LearningConfig {
        LearningConfig {
            enabled: true,
            duration_hours: 24,
            min_observations: 2,
            require_team_id: true,
            allow_platform_binary: true,
            blocked_executables: vec!["bash".into(), "python".into(), "node".into(), "curl".into()],
        }
    }

    #[test]
    fn test_is_blocked_executable() {
        let storage = Arc::new(Storage::in_memory().unwrap());
        let controller = LearningController::new(test_config(), storage);

        assert!(controller.is_blocked_executable("bash"));
        assert!(controller.is_blocked_executable("python"));
        assert!(controller.is_blocked_executable("node"));
        assert!(controller.is_blocked_executable("curl"));
        assert!(!controller.is_blocked_executable("ssh"));
        assert!(!controller.is_blocked_executable("git"));
    }

    #[test]
    fn test_learning_disabled() {
        let mut config = test_config();
        config.enabled = false;

        let storage = Arc::new(Storage::in_memory().unwrap());
        let controller = LearningController::new(config, storage);

        assert_eq!(controller.initialize(), LearningState::Disabled);
        assert!(!controller.is_learning());
        assert!(controller.is_complete());
    }

    #[test]
    fn test_learning_starts() {
        let storage = Arc::new(Storage::in_memory().unwrap());
        let controller = LearningController::new(test_config(), storage);

        assert_eq!(controller.initialize(), LearningState::Learning);
        assert!(controller.is_learning());
        assert!(!controller.is_complete());
        assert!(!controller.is_blocking_enforcement());
    }

    #[test]
    fn test_record_observation_blocked() {
        let storage = Arc::new(Storage::in_memory().unwrap());
        let controller = LearningController::new(test_config(), storage);
        controller.initialize();

        // Try to record a blocked executable
        let ctx = ProcessContext::new(PathBuf::from("/bin/bash"));
        assert!(!controller.record_observation("ssh_keys", &ctx));
    }

    #[test]
    fn test_record_observation_allowed() {
        let storage = Arc::new(Storage::in_memory().unwrap());
        let controller = LearningController::new(test_config(), storage);
        controller.initialize();

        // Record a legitimate process
        let ctx = ProcessContext::new(PathBuf::from("/usr/bin/git")).with_team_id("APPLE123");
        assert!(controller.record_observation("ssh_keys", &ctx));
    }

    #[test]
    fn test_stats() {
        let storage = Arc::new(Storage::in_memory().unwrap());
        let controller = LearningController::new(test_config(), storage);
        controller.initialize();

        let stats = controller.stats();
        assert_eq!(stats.state, LearningState::Learning);
        assert_eq!(stats.pending, 0);
        assert_eq!(stats.approved, 0);
    }

    #[test]
    fn test_approve_reject_workflow() {
        let storage = Arc::new(Storage::in_memory().unwrap());
        let controller = LearningController::new(test_config(), storage);
        controller.initialize();

        // Record some observations
        let ctx1 = ProcessContext::new(PathBuf::from("/usr/bin/git")).with_team_id("APPLE123");
        let ctx2 = ProcessContext::new(PathBuf::from("/usr/bin/ssh")).with_team_id("APPLE456");

        controller.record_observation("ssh_keys", &ctx1);
        controller.record_observation("ssh_keys", &ctx2);

        // Check pending
        let pending = controller.get_pending_recommendations();
        assert_eq!(pending.len(), 2);

        // Approve one
        controller.approve(pending[0].id);

        // Reject one
        controller.reject(pending[1].id);

        // Check stats
        let stats = controller.stats();
        assert_eq!(stats.pending, 0);
        assert_eq!(stats.approved, 1);
        assert_eq!(stats.rejected, 1);
    }

    #[test]
    fn test_reject_all() {
        let storage = Arc::new(Storage::in_memory().unwrap());
        let controller = LearningController::new(test_config(), storage);
        controller.initialize();

        // Record some observations
        let ctx1 = ProcessContext::new(PathBuf::from("/usr/bin/git")).with_team_id("APPLE123");
        let ctx2 = ProcessContext::new(PathBuf::from("/usr/bin/ssh")).with_team_id("APPLE456");

        controller.record_observation("ssh_keys", &ctx1);
        controller.record_observation("ssh_keys", &ctx2);

        // Reject all
        let rejected = controller.reject_all();
        assert_eq!(rejected, 2);

        // Check stats
        let stats = controller.stats();
        assert_eq!(stats.pending, 0);
        assert_eq!(stats.rejected, 2);
    }

    #[test]
    fn test_complete_review() {
        let storage = Arc::new(Storage::in_memory().unwrap());
        let controller = LearningController::new(test_config(), storage.clone());
        controller.initialize();

        // Record and approve
        let ctx = ProcessContext::new(PathBuf::from("/usr/bin/git")).with_team_id("APPLE123");
        controller.record_observation("ssh_keys", &ctx);
        controller.approve_all();

        // Complete review
        let count = controller.complete_review();
        assert_eq!(count, 1);

        // Check state
        assert_eq!(controller.state(), LearningState::Complete);
        assert!(controller.is_complete());
        assert!(!controller.is_blocking_enforcement());

        // Check that exception was created
        let exceptions = storage.get_exceptions().unwrap();
        assert_eq!(exceptions.len(), 1);
        assert_eq!(exceptions[0].source, crate::rules::ExceptionSource::Learned);
    }

    #[test]
    fn test_restart_learning() {
        let storage = Arc::new(Storage::in_memory().unwrap());
        let controller = LearningController::new(test_config(), storage.clone());
        controller.initialize();

        // Record some observations
        let ctx1 = ProcessContext::new(PathBuf::from("/usr/bin/git")).with_team_id("APPLE123");
        controller.record_observation("ssh_keys", &ctx1);

        // Verify observation exists
        let stats = controller.stats();
        assert_eq!(stats.pending, 1);

        // Complete review to move to Complete state
        controller.approve_all();
        controller.complete_review();
        assert_eq!(controller.state(), LearningState::Complete);

        // Restart learning
        assert!(controller.restart_learning());

        // Verify state is back to Learning
        assert_eq!(controller.state(), LearningState::Learning);
        assert!(controller.is_learning());

        // Verify observations were cleared
        let stats = controller.stats();
        assert_eq!(stats.pending, 0);
        assert_eq!(stats.approved, 0);
        assert_eq!(stats.rejected, 0);
    }
}
