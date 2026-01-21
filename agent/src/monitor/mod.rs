//! File access monitoring implementations.
//!
//! **Security Note on eslogger (macOS):**
//! The eslogger mechanism uses Apple's Endpoint Security framework via the
//! `eslogger` command-line tool. This provides notification events AFTER file
//! access has occurred - it cannot prevent the initial read. When in "block"
//! mode, we suspend the process via SIGSTOP after detecting the access, but
//! the file contents may have already been read into the process's memory.
//!
//! For true pre-access blocking on macOS, a direct ESF implementation would
//! be required (using ES_AUTH_OPEN events). This is a known limitation.
//!
//! On Linux, fanotify with FAN_OPEN_PERM provides true pre-access blocking.

#[cfg(target_os = "macos")]
mod macos_eslogger;

#[cfg(target_os = "linux")]
mod linux_fanotify;

#[cfg(target_os = "freebsd")]
mod freebsd_dtrace;

use crate::config::Config;
use crate::error::{Error, Result};
use crate::ipc::ViolationEvent;
use crate::process::{build_process_tree, ProcessContext};
use crate::rules::{Decision, RuleEngine};
use crate::storage::{Storage, Violation};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{broadcast, Mutex};

/// Trait for file access monitors.
#[async_trait::async_trait]
pub trait Monitor: Send + Sync {
    /// Start monitoring file access.
    async fn start(&mut self) -> Result<()>;

    /// Stop monitoring.
    async fn stop(&mut self) -> Result<()>;
}

/// Monitoring mechanism to use.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mechanism {
    Auto,
    #[cfg(target_os = "macos")]
    Eslogger,
    #[cfg(target_os = "macos")]
    Esf,
    #[cfg(target_os = "linux")]
    Fanotify,
    #[cfg(target_os = "freebsd")]
    Dtrace,
}

impl std::str::FromStr for Mechanism {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        match s.to_lowercase().as_str() {
            "auto" => Ok(Mechanism::Auto),
            #[cfg(target_os = "macos")]
            "eslogger" => Ok(Mechanism::Eslogger),
            #[cfg(target_os = "macos")]
            "esf" => Ok(Mechanism::Esf),
            #[cfg(target_os = "linux")]
            "fanotify" => Ok(Mechanism::Fanotify),
            #[cfg(target_os = "freebsd")]
            "dtrace" => Ok(Mechanism::Dtrace),
            _ => Err(Error::config(format!("Unknown mechanism: {}", s))),
        }
    }
}

impl Mechanism {
    /// Get the default mechanism for the current platform.
    pub fn default_for_platform() -> Self {
        #[cfg(target_os = "macos")]
        {
            Mechanism::Eslogger
        }

        #[cfg(target_os = "linux")]
        {
            Mechanism::Fanotify
        }

        #[cfg(target_os = "freebsd")]
        {
            Mechanism::Dtrace
        }

        #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "freebsd")))]
        {
            Mechanism::Auto
        }
    }

    /// Resolve Auto to the actual mechanism.
    pub fn resolve(self) -> Self {
        if self == Mechanism::Auto {
            Self::default_for_platform()
        } else {
            self
        }
    }
}

/// Simple rate limiter using a sliding window.
pub struct RateLimiter {
    max_per_sec: u32,
    window_start: Mutex<Instant>,
    count: AtomicU64,
}

impl RateLimiter {
    pub fn new(max_per_sec: u32) -> Self {
        Self {
            max_per_sec,
            window_start: Mutex::new(Instant::now()),
            count: AtomicU64::new(0),
        }
    }

    /// Check if an event should be allowed. Returns true if under limit.
    pub async fn check(&self) -> bool {
        if self.max_per_sec == 0 {
            return true; // No limit
        }

        let mut window_start = self.window_start.lock().await;
        let now = Instant::now();

        // Reset window if more than 1 second has passed
        if now.duration_since(*window_start) >= Duration::from_secs(1) {
            *window_start = now;
            self.count.store(1, Ordering::SeqCst);
            return true;
        }

        // Increment and check
        let count = self.count.fetch_add(1, Ordering::SeqCst) + 1;
        count <= self.max_per_sec as u64
    }

    /// Get the number of events dropped due to rate limiting.
    #[allow(dead_code)]
    pub fn dropped_count(&self) -> u64 {
        let count = self.count.load(Ordering::SeqCst);
        if count > self.max_per_sec as u64 {
            count - self.max_per_sec as u64
        } else {
            0
        }
    }
}

/// Shared context for monitors.
pub struct MonitorContext {
    pub config: Config,
    pub rule_engine: RuleEngine,
    pub storage: Arc<Storage>,
    pub event_tx: broadcast::Sender<ViolationEvent>,
    pub mode: Arc<tokio::sync::RwLock<String>>,
    pub degraded_mode: Arc<tokio::sync::RwLock<bool>>,
    rate_limiter: RateLimiter,
}

impl MonitorContext {
    /// Create a new monitor context.
    pub fn new(
        config: Config,
        rule_engine: RuleEngine,
        storage: Arc<Storage>,
        event_tx: broadcast::Sender<ViolationEvent>,
        mode: Arc<tokio::sync::RwLock<String>>,
        degraded_mode: Arc<tokio::sync::RwLock<bool>>,
    ) -> Self {
        let max_events_per_sec = config.monitoring.max_events_per_sec;
        Self {
            config,
            rule_engine,
            storage,
            event_tx,
            mode,
            degraded_mode,
            rate_limiter: RateLimiter::new(max_events_per_sec),
        }
    }

    /// Process a file access event.
    pub async fn process_access(
        &self,
        file_path: &str,
        context: &ProcessContext,
    ) -> Option<ViolationEvent> {
        // Check rate limit first
        if !self.rate_limiter.check().await {
            tracing::trace!("Rate limit exceeded, dropping event for {}", file_path);
            return None;
        }

        // Check if file is excluded
        if self.config.is_excluded(file_path) {
            tracing::trace!("File {} is excluded", file_path);
            return None;
        }

        // Evaluate rules
        let decision = self.rule_engine.evaluate(context, file_path);

        match decision {
            Decision::Allow => {
                tracing::trace!(
                    "Allowed: {} accessing {}",
                    context.path.display(),
                    file_path
                );
                None
            }
            Decision::NotProtected => {
                tracing::trace!("File {} is not protected", file_path);
                None
            }
            Decision::Deny => {
                let mode = self.mode.read().await;
                let action = match mode.as_str() {
                    "block" => "blocked",
                    "best-effort" => "stopped",
                    _ => "logged",
                };

                tracing::warn!(
                    "VIOLATION: {} accessing {} ({})",
                    context.path.display(),
                    file_path,
                    action
                );

                // Build process tree
                let tree = context.pid.map(build_process_tree).unwrap_or_default();

                // Create violation record with all context
                let violation = Violation::new(
                    file_path,
                    context.path.to_string_lossy().to_string(),
                    context.pid.unwrap_or(0),
                    action,
                )
                .with_rule_id(self.rule_engine.get_rule_id(file_path).unwrap_or("unknown"))
                .with_process_tree(tree.clone())
                .with_ppid_opt(context.ppid)
                .with_euid_opt(context.euid)
                .with_cmdline_opt(context.args.as_ref().map(|a| a.join(" ")))
                .with_team_id_opt(context.team_id.clone())
                .with_signing_id_opt(context.signing_id.clone());

                // Record to database
                if let Err(e) = self.storage.record_violation(&violation) {
                    tracing::error!("Failed to record violation: {}", e);
                }

                // Create event for broadcast
                let event = ViolationEvent {
                    id: violation.id,
                    timestamp: violation.timestamp,
                    rule_id: violation.rule_id,
                    file_path: violation.file_path,
                    process_path: violation.process_path,
                    process_pid: violation.process_pid,
                    process_cmdline: violation.process_cmdline,
                    process_euid: violation.process_euid,
                    parent_pid: violation.process_ppid,
                    team_id: violation.team_id,
                    signing_id: violation.signing_id,
                    action: violation.action,
                    process_tree: tree,
                };

                // Broadcast to connected clients
                let _ = self.event_tx.send(event.clone());

                Some(event)
            }
        }
    }

    /// Suspend a process (for blocking mode on macOS).
    #[cfg(unix)]
    pub fn suspend_process(&self, pid: u32) -> Result<()> {
        use nix::sys::signal::{kill, Signal};
        use nix::unistd::Pid;

        let pid = Pid::from_raw(pid as i32);
        kill(pid, Signal::SIGSTOP).map_err(|e| Error::monitor(format!("Failed to suspend process: {}", e)))
    }
}

/// Create a monitor based on the configuration.
pub fn create_monitor(
    mechanism: Mechanism,
    context: Arc<MonitorContext>,
) -> Result<Box<dyn Monitor>> {
    let mechanism = mechanism.resolve();

    #[cfg(target_os = "macos")]
    {
        match mechanism {
            Mechanism::Eslogger => {
                Ok(Box::new(macos_eslogger::EsloggerMonitor::new(context)))
            }
            Mechanism::Esf => {
                Err(Error::config("Direct ESF not yet implemented"))
            }
            _ => Err(Error::UnsupportedPlatform(format!("{:?}", mechanism))),
        }
    }

    #[cfg(target_os = "linux")]
    {
        match mechanism {
            Mechanism::Fanotify => {
                Ok(Box::new(linux_fanotify::FanotifyMonitor::new(context)))
            }
            _ => Err(Error::UnsupportedPlatform(format!("{:?}", mechanism))),
        }
    }

    #[cfg(target_os = "freebsd")]
    {
        match mechanism {
            Mechanism::Dtrace => {
                Ok(Box::new(freebsd_dtrace::DtraceMonitor::new(context)))
            }
            _ => Err(Error::UnsupportedPlatform(format!("{:?}", mechanism))),
        }
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "freebsd")))]
    {
        Err(Error::UnsupportedPlatform(std::env::consts::OS.to_string()))
    }
}

/// Expand ~ to home directory in a path pattern.
#[allow(dead_code)]
pub fn expand_home(pattern: &str, home: &std::path::Path) -> String {
    if let Some(suffix) = pattern.strip_prefix("~/") {
        format!("{}/{}", home.display(), suffix)
    } else if pattern == "~" {
        home.to_string_lossy().to_string()
    } else {
        pattern.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn test_expand_home_with_suffix() {
        let home = Path::new("/home/testuser");
        assert_eq!(
            expand_home("~/.ssh/id_rsa", home),
            "/home/testuser/.ssh/id_rsa"
        );
    }

    #[test]
    fn test_expand_home_just_tilde() {
        let home = Path::new("/home/testuser");
        assert_eq!(expand_home("~", home), "/home/testuser");
    }

    #[test]
    fn test_expand_home_absolute_path() {
        let home = Path::new("/home/testuser");
        assert_eq!(expand_home("/etc/passwd", home), "/etc/passwd");
    }

    #[test]
    fn test_expand_home_relative_path() {
        let home = Path::new("/home/testuser");
        assert_eq!(expand_home("foo/bar", home), "foo/bar");
    }

    #[test]
    fn test_mechanism_from_str_auto() {
        let mech: Mechanism = "auto".parse().unwrap();
        assert_eq!(mech, Mechanism::Auto);
    }

    #[test]
    fn test_mechanism_from_str_case_insensitive() {
        let mech: Mechanism = "AUTO".parse().unwrap();
        assert_eq!(mech, Mechanism::Auto);
    }

    #[test]
    fn test_mechanism_from_str_invalid() {
        let result: std::result::Result<Mechanism, _> = "invalid".parse();
        assert!(result.is_err());
    }

    #[test]
    fn test_mechanism_resolve_auto() {
        let mech = Mechanism::Auto;
        let resolved = mech.resolve();
        assert_ne!(resolved, Mechanism::Auto);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn test_mechanism_from_str_eslogger() {
        let mech: Mechanism = "eslogger".parse().unwrap();
        assert_eq!(mech, Mechanism::Eslogger);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn test_mechanism_default_macos() {
        assert_eq!(Mechanism::default_for_platform(), Mechanism::Eslogger);
    }

    #[tokio::test]
    async fn test_rate_limiter_no_limit() {
        let limiter = RateLimiter::new(0);
        // With limit 0, should always allow
        for _ in 0..100 {
            assert!(limiter.check().await);
        }
    }

    #[tokio::test]
    async fn test_rate_limiter_under_limit() {
        let limiter = RateLimiter::new(10);
        // First 10 should be allowed
        for _ in 0..10 {
            assert!(limiter.check().await);
        }
    }

    #[tokio::test]
    async fn test_rate_limiter_over_limit() {
        let limiter = RateLimiter::new(5);
        // First 5 allowed
        for _ in 0..5 {
            assert!(limiter.check().await);
        }
        // Next ones should be rejected (still in same window)
        assert!(!limiter.check().await);
        assert!(!limiter.check().await);
    }

    #[tokio::test]
    async fn test_rate_limiter_dropped_count() {
        let limiter = RateLimiter::new(3);
        // First 3 allowed
        for _ in 0..3 {
            limiter.check().await;
        }
        assert_eq!(limiter.dropped_count(), 0);

        // Next 5 are over limit
        for _ in 0..5 {
            limiter.check().await;
        }
        assert_eq!(limiter.dropped_count(), 5);
    }

    #[tokio::test]
    async fn test_monitor_context_process_access_not_protected() {
        use crate::config::Config;
        use crate::rules::RuleEngine;
        use crate::storage::Storage;
        use crate::process::ProcessContext;
        use std::path::PathBuf;
        use tempfile::TempDir;

        let temp_dir = TempDir::new().unwrap();
        let db_path = temp_dir.path().join("test.db");
        let storage = Arc::new(Storage::open(&db_path).unwrap());
        let config = Config::default();
        let rule_engine = RuleEngine::new(Vec::new(), Vec::new());
        let (event_tx, _rx) = broadcast::channel(100);
        let mode = Arc::new(tokio::sync::RwLock::new("block".to_string()));
        let degraded_mode = Arc::new(tokio::sync::RwLock::new(false));

        let ctx = MonitorContext::new(config, rule_engine, storage, event_tx, mode, degraded_mode);

        let process = ProcessContext::new(PathBuf::from("/usr/bin/cat")).with_pid(1234);
        let result = ctx.process_access("/tmp/random_file.txt", &process).await;
        assert!(result.is_none()); // Not protected
    }

    #[tokio::test]
    async fn test_monitor_context_process_access_allowed() {
        use crate::config::{Config, ProtectedFile};
        use crate::rules::{RuleEngine, AllowRule};
        use crate::storage::Storage;
        use crate::process::ProcessContext;
        use std::path::PathBuf;
        use tempfile::TempDir;

        let temp_dir = TempDir::new().unwrap();
        let db_path = temp_dir.path().join("test.db");
        let storage = Arc::new(Storage::open(&db_path).unwrap());

        let mut config = Config::default();
        let protected = ProtectedFile {
            id: "ssh_keys".to_string(),
            patterns: vec!["~/.ssh/*".to_string()],
            allow: vec![AllowRule {
                path: Some("/usr/bin/ssh".to_string()),
                ..Default::default()
            }],
        };
        config.protected_files.push(protected.clone());

        let rule_engine = RuleEngine::new(vec![protected], Vec::new());
        let (event_tx, _rx) = broadcast::channel(100);
        let mode = Arc::new(tokio::sync::RwLock::new("block".to_string()));
        let degraded_mode = Arc::new(tokio::sync::RwLock::new(false));

        let ctx = MonitorContext::new(config, rule_engine, storage, event_tx, mode, degraded_mode);

        // Allowed process
        let process = ProcessContext::new(PathBuf::from("/usr/bin/ssh")).with_pid(1234);
        let result = ctx.process_access("~/.ssh/id_rsa", &process).await;
        assert!(result.is_none()); // Allowed, no violation
    }

    #[tokio::test]
    async fn test_monitor_context_process_access_denied() {
        use crate::config::{Config, ProtectedFile};
        use crate::rules::RuleEngine;
        use crate::storage::Storage;
        use crate::process::ProcessContext;
        use std::path::PathBuf;
        use tempfile::TempDir;

        let temp_dir = TempDir::new().unwrap();
        let db_path = temp_dir.path().join("test.db");
        let storage = Arc::new(Storage::open(&db_path).unwrap());

        let mut config = Config::default();
        let protected = ProtectedFile {
            id: "ssh_keys".to_string(),
            patterns: vec!["~/.ssh/*".to_string()],
            allow: vec![], // No allow rules
        };
        config.protected_files.push(protected.clone());

        let rule_engine = RuleEngine::new(vec![protected], Vec::new());
        let (event_tx, _rx) = broadcast::channel(100);
        let mode = Arc::new(tokio::sync::RwLock::new("block".to_string()));
        let degraded_mode = Arc::new(tokio::sync::RwLock::new(false));

        let ctx = MonitorContext::new(config, rule_engine, storage, event_tx, mode, degraded_mode);

        // Denied process
        let process = ProcessContext::new(PathBuf::from("/usr/bin/cat")).with_pid(1234);
        let result = ctx.process_access("~/.ssh/id_rsa", &process).await;
        assert!(result.is_some()); // Denied, violation recorded
        let violation = result.unwrap();
        assert_eq!(violation.action, "blocked");
        assert_eq!(violation.file_path, "~/.ssh/id_rsa");
    }

    #[tokio::test]
    async fn test_monitor_context_process_access_excluded() {
        use crate::config::Config;
        use crate::rules::RuleEngine;
        use crate::storage::Storage;
        use crate::process::ProcessContext;
        use std::path::PathBuf;
        use tempfile::TempDir;

        let temp_dir = TempDir::new().unwrap();
        let db_path = temp_dir.path().join("test.db");
        let storage = Arc::new(Storage::open(&db_path).unwrap());

        let mut config = Config::default();
        config.excluded_patterns.push("/tmp/*".to_string());

        let rule_engine = RuleEngine::new(Vec::new(), Vec::new());
        let (event_tx, _rx) = broadcast::channel(100);
        let mode = Arc::new(tokio::sync::RwLock::new("block".to_string()));
        let degraded_mode = Arc::new(tokio::sync::RwLock::new(false));

        let ctx = MonitorContext::new(config, rule_engine, storage, event_tx, mode, degraded_mode);

        let process = ProcessContext::new(PathBuf::from("/usr/bin/cat")).with_pid(1234);
        let result = ctx.process_access("/tmp/excluded_file.txt", &process).await;
        assert!(result.is_none()); // Excluded
    }

    #[tokio::test]
    async fn test_monitor_context_mode_logged() {
        use crate::config::{Config, ProtectedFile};
        use crate::rules::RuleEngine;
        use crate::storage::Storage;
        use crate::process::ProcessContext;
        use std::path::PathBuf;
        use tempfile::TempDir;

        let temp_dir = TempDir::new().unwrap();
        let db_path = temp_dir.path().join("test.db");
        let storage = Arc::new(Storage::open(&db_path).unwrap());

        let mut config = Config::default();
        let protected = ProtectedFile {
            id: "ssh_keys".to_string(),
            patterns: vec!["~/.ssh/*".to_string()],
            allow: vec![],
        };
        config.protected_files.push(protected.clone());

        let rule_engine = RuleEngine::new(vec![protected], Vec::new());
        let (event_tx, _rx) = broadcast::channel(100);
        let mode = Arc::new(tokio::sync::RwLock::new("monitor".to_string())); // Not block mode
        let degraded_mode = Arc::new(tokio::sync::RwLock::new(false));

        let ctx = MonitorContext::new(config, rule_engine, storage, event_tx, mode, degraded_mode);

        let process = ProcessContext::new(PathBuf::from("/usr/bin/cat")).with_pid(1234);
        let result = ctx.process_access("~/.ssh/id_rsa", &process).await;
        assert!(result.is_some());
        let violation = result.unwrap();
        assert_eq!(violation.action, "logged"); // Should be "logged" in monitor mode
    }

    #[test]
    fn test_create_monitor_unsupported() {
        // Test the create_monitor function error path
        #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "freebsd")))]
        {
            use crate::config::Config;
            use crate::rules::RuleEngine;
            use crate::storage::Storage;
            use tempfile::TempDir;

            let temp_dir = TempDir::new().unwrap();
            let db_path = temp_dir.path().join("test.db");
            let storage = Arc::new(Storage::open(&db_path).unwrap());
            let config = Config::default();
            let rule_engine = RuleEngine::new(Vec::new(), Vec::new());
            let (event_tx, _rx) = broadcast::channel(100);
            let mode = Arc::new(tokio::sync::RwLock::new("block".to_string()));
            let degraded_mode = Arc::new(tokio::sync::RwLock::new(false));

            let ctx = Arc::new(MonitorContext::new(config, rule_engine, storage, event_tx, mode, degraded_mode));
            let result = create_monitor(Mechanism::Auto, ctx);
            assert!(result.is_err());
        }
    }
}
