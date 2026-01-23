//! File access monitoring implementations.
//!
//! # macOS Monitoring Mechanisms
//!
//! ## ESF (Endpoint Security Framework) - PRODUCTION
//!
//! The `esf` mechanism uses Apple's Endpoint Security framework directly via the
//! native API. This is the **recommended mechanism for production deployments**.
//!
//! **Requirements:**
//! - System Extension entitlement from Apple (requires Developer ID)
//! - User approval for System Extension installation
//! - Full Disk Access (FDA) permission
//!
//! **Capabilities:**
//! - True pre-access blocking via ES_AUTH_OPEN events
//! - Can prevent file access before any data is read
//! - Stable, supported API with proper error handling
//! - Survives process crashes without leaving system in bad state
//!
//! ## eslogger - DEVELOPMENT/TESTING ONLY
//!
//! The `eslogger` mechanism uses Apple's `eslogger` command-line tool, which
//! wraps the Endpoint Security framework. This is **only for development and
//! testing** when you don't have the required entitlements.
//!
//! **⚠️ WARNING: eslogger is UNSTABLE and NOT suitable for production:**
//! - Provides notification events AFTER file access has occurred
//! - Cannot prevent the initial read - data may already be exfiltrated
//! - Relies on parsing JSON output from an external process
//! - May miss events under high load or if eslogger crashes
//! - No official stability guarantees from Apple
//! - Process suspension via SIGSTOP is a best-effort mitigation
//!
//! **When to use eslogger:**
//! - Local development without Apple Developer ID
//! - Testing rule configurations before production deployment
//! - Demonstrations and proof-of-concept work
//!
//! **When NOT to use eslogger:**
//! - Production deployments
//! - Any environment where security is critical
//! - Systems where you need guaranteed blocking
//!
//! # Linux Monitoring
//!
//! On Linux, fanotify with FAN_OPEN_PERM provides true pre-access blocking,
//! similar to ESF on macOS.

#[cfg(target_os = "macos")]
mod macos_eslogger;

#[cfg(all(target_os = "macos", feature = "esf"))]
mod macos_esf;

#[cfg(target_os = "linux")]
mod linux_fanotify;

#[cfg(target_os = "freebsd")]
mod freebsd_dtrace;

#[cfg(target_os = "netbsd")]
mod netbsd_dtrace;

use crate::config::Config;
use crate::error::{Error, Result};
use crate::ipc::ViolationEvent;
use crate::process::{build_process_tree, ProcessContext, ProcessTreeEntry};
use crate::rules::{Decision, RuleEngine};
use crate::storage::{Storage, Violation};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{broadcast, Mutex};

// Package cache for Linux/FreeBSD/NetBSD package-based rule matching
#[cfg(any(target_os = "linux", target_os = "freebsd", target_os = "netbsd"))]
use crate::process::package_cache::PackageCache;

/// Trait for file access monitors.
#[async_trait::async_trait]
pub trait Monitor: Send + Sync {
    /// Start monitoring file access.
    async fn start(&mut self) -> Result<()>;

    /// Stop monitoring.
    async fn stop(&mut self) -> Result<()>;
}

/// Monitoring mechanism to use.
///
/// # macOS Mechanisms
///
/// - **`Esf`** (PRODUCTION): Direct Endpoint Security Framework integration.
///   Requires System Extension entitlement from Apple. Provides true pre-access
///   blocking and is the only mechanism suitable for production use.
///
/// - **`Eslogger`** (DEVELOPMENT ONLY): Uses Apple's eslogger CLI tool.
///   ⚠️ UNSTABLE - only for development/testing without entitlements.
///   Cannot block access, only detect it after the fact.
///
/// # Other Platforms
///
/// - **`Fanotify`** (Linux): Uses fanotify with FAN_OPEN_PERM for true blocking.
/// - **`Dtrace`** (FreeBSD/NetBSD): Uses DTrace for monitoring.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mechanism {
    Auto,
    /// ⚠️ DEVELOPMENT ONLY - unstable, cannot block access
    #[cfg(target_os = "macos")]
    Eslogger,
    /// PRODUCTION - requires System Extension entitlement
    #[cfg(target_os = "macos")]
    Esf,
    #[cfg(target_os = "linux")]
    Fanotify,
    #[cfg(target_os = "freebsd")]
    Dtrace,
    #[cfg(target_os = "netbsd")]
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
            #[cfg(target_os = "netbsd")]
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

        #[cfg(target_os = "netbsd")]
        {
            Mechanism::Dtrace
        }

        #[cfg(not(any(
            target_os = "macos",
            target_os = "linux",
            target_os = "freebsd",
            target_os = "netbsd"
        )))]
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
        count.saturating_sub(self.max_per_sec as u64)
    }
}

/// Statistics for monitoring events.
#[derive(Debug, Default)]
pub struct EventStats {
    /// Total file access events received
    pub events_received: AtomicU64,
    /// Events that were for protected files
    pub protected_checks: AtomicU64,
    /// Accesses that were allowed by rules
    pub allowed: AtomicU64,
    /// Accesses that resulted in violations
    pub violations: AtomicU64,
    /// Events dropped due to rate limiting
    pub rate_limited: AtomicU64,
}

impl EventStats {
    /// Get current stats and reset counters to zero.
    pub fn take(&self) -> EventStatsSnapshot {
        EventStatsSnapshot {
            events_received: self.events_received.swap(0, Ordering::SeqCst),
            protected_checks: self.protected_checks.swap(0, Ordering::SeqCst),
            allowed: self.allowed.swap(0, Ordering::SeqCst),
            violations: self.violations.swap(0, Ordering::SeqCst),
            rate_limited: self.rate_limited.swap(0, Ordering::SeqCst),
        }
    }
}

/// A snapshot of event statistics.
#[derive(Debug, Clone)]
pub struct EventStatsSnapshot {
    pub events_received: u64,
    pub protected_checks: u64,
    pub allowed: u64,
    pub violations: u64,
    pub rate_limited: u64,
}

/// Shared context for monitors.
pub struct MonitorContext {
    pub config: Config,
    pub rule_engine: Arc<tokio::sync::RwLock<RuleEngine>>,
    pub storage: Arc<Storage>,
    pub event_tx: broadcast::Sender<ViolationEvent>,
    pub mode: Arc<tokio::sync::RwLock<String>>,
    pub degraded_mode: Arc<tokio::sync::RwLock<bool>>,
    /// Pending events awaiting user action. Shared with IPC handlers.
    pub pending_events: Arc<tokio::sync::RwLock<Vec<ViolationEvent>>>,
    rate_limiter: RateLimiter,
    pub stats: EventStats,
    /// Package cache for Linux/FreeBSD/NetBSD package-based rule matching.
    /// Uses file metadata (inode, mtime, ctime, btime) as cache key.
    #[cfg(any(target_os = "linux", target_os = "freebsd", target_os = "netbsd"))]
    package_cache: PackageCache,
}

impl MonitorContext {
    /// Create a new monitor context.
    pub fn new(
        config: Config,
        rule_engine: Arc<tokio::sync::RwLock<RuleEngine>>,
        storage: Arc<Storage>,
        event_tx: broadcast::Sender<ViolationEvent>,
        mode: Arc<tokio::sync::RwLock<String>>,
        degraded_mode: Arc<tokio::sync::RwLock<bool>>,
        pending_events: Arc<tokio::sync::RwLock<Vec<ViolationEvent>>>,
    ) -> Self {
        let max_events_per_sec = config.monitoring.max_events_per_sec;
        Self {
            config,
            rule_engine,
            storage,
            event_tx,
            mode,
            degraded_mode,
            pending_events,
            rate_limiter: RateLimiter::new(max_events_per_sec),
            stats: EventStats::default(),
            #[cfg(any(target_os = "linux", target_os = "freebsd", target_os = "netbsd"))]
            package_cache: PackageCache::new(),
        }
    }

    /// Enrich a ProcessContext with package information (Linux/FreeBSD/NetBSD only).
    /// This looks up which system package owns the process executable and
    /// populates the `package` field for package-based rule matching.
    #[cfg(any(target_os = "linux", target_os = "freebsd", target_os = "netbsd"))]
    pub fn enrich_with_package_info(&self, context: &mut ProcessContext) {
        if let Some(pkg_info) = self.package_cache.lookup(&context.path) {
            context.package = Some(pkg_info);
        }
    }

    /// Enrich a ProcessContext with package information and verify if required.
    /// Only performs verification if rules require `package_verified = true`.
    #[cfg(any(target_os = "linux", target_os = "freebsd", target_os = "netbsd"))]
    pub fn enrich_with_verified_package_info(
        &self,
        context: &mut ProcessContext,
        require_verification: bool,
    ) {
        if let Some(pkg_info) = self
            .package_cache
            .lookup_and_verify(&context.path, require_verification)
        {
            context.package = Some(pkg_info);
        }
    }

    /// Process a file access event.
    pub async fn process_access(
        &self,
        file_path: &str,
        context: &ProcessContext,
    ) -> Option<ViolationEvent> {
        // Track that we received an event
        self.stats.events_received.fetch_add(1, Ordering::Relaxed);

        // Check if file is excluded first (fast path)
        if self.config.is_excluded(file_path) {
            tracing::trace!("File {} is excluded", file_path);
            return None;
        }

        // Quick check if this file is protected - protected files bypass rate limiting
        let rule_engine = self.rule_engine.read().await;
        let is_protected = rule_engine.is_protected(file_path);
        let is_ssh_file = file_path.contains(".ssh");
        drop(rule_engine);

        // Apply rate limiting only to non-protected files
        // Protected files (SSH keys, AWS creds, etc.) should NEVER be rate limited
        if !is_protected {
            if !self.rate_limiter.check().await {
                self.stats.rate_limited.fetch_add(1, Ordering::Relaxed);
                tracing::trace!("Rate limit exceeded, dropping event for {}", file_path);
                return None;
            }
            // Not protected, nothing more to do
            return None;
        }

        // This is a protected file - always process it
        self.stats.protected_checks.fetch_add(1, Ordering::Relaxed);

        // Evaluate rules with debug mode for SSH files
        let rule_engine = self.rule_engine.read().await;
        let decision = rule_engine.evaluate_with_debug(context, file_path, is_ssh_file);
        let rule_id = rule_engine.get_rule_id(file_path).map(|s| s.to_string());
        drop(rule_engine); // Release lock early

        match decision {
            Decision::Allow => {
                self.stats.allowed.fetch_add(1, Ordering::Relaxed);
                tracing::trace!(
                    "Allowed: {} accessing {}",
                    context.path.display(),
                    file_path
                );
                None
            }
            Decision::NotProtected => {
                // Shouldn't happen since we checked is_protected above, but handle gracefully
                tracing::trace!("File {} is not protected", file_path);
                None
            }
            Decision::Deny => {
                // Check for duplicate: if we already have a pending event for the same PID + file,
                // skip creating another event. This happens when a process reads a file multiple
                // times before we can suspend it.
                let pid = context.pid.unwrap_or(0);
                {
                    let pending = self.pending_events.read().await;
                    let is_duplicate = pending
                        .iter()
                        .any(|e| e.process_pid == pid && e.file_path == file_path);
                    if is_duplicate {
                        tracing::debug!(
                            "Skipping duplicate violation for PID {} -> {}",
                            pid,
                            file_path
                        );
                        return None;
                    }
                }

                self.stats.violations.fetch_add(1, Ordering::Relaxed);
                let mode = self.mode.read().await;
                let mode_str = mode.as_str();
                let should_stop = mode_str == "block" || mode_str == "best-effort";
                let action = match mode_str {
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

                // Stop processes FIRST so they can't exit while we build the tree
                if should_stop {
                    if let Some(pid) = context.pid {
                        if let Err(e) = self.suspend_process(pid, context.ppid) {
                            tracing::warn!("Failed to suspend process {}: {}", pid, e);
                        } else if mode_str == "best-effort" {
                            tracing::info!(
                                "Best-effort: stopped process {} and parent (file may have been accessed)",
                                pid
                            );
                        } else {
                            tracing::info!(
                                "Suspended process {} and parent pending user decision",
                                pid
                            );
                        }
                    }
                }

                // Build process tree AFTER stopping - processes are now stopped and can be queried
                let tree = build_tree_from_context(context);

                // Create violation record with all context
                let violation = Violation::new(
                    file_path,
                    context.path.to_string_lossy().to_string(),
                    context.pid.unwrap_or(0),
                    action,
                )
                .with_rule_id(rule_id.as_deref().unwrap_or("unknown"))
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

                // Add to pending events for user action (allow/deny/kill)
                {
                    let mut pending = self.pending_events.write().await;
                    // Limit pending events to prevent memory issues
                    const MAX_PENDING_EVENTS: usize = 100;
                    if pending.len() >= MAX_PENDING_EVENTS {
                        let dropped = pending.remove(0);
                        tracing::warn!(
                            "Pending event queue full, dropped oldest event: {}",
                            dropped.id
                        );
                    }
                    pending.push(event.clone());
                }

                // Broadcast to connected clients
                // Note: send() fails if no receivers, which is normal during startup
                if let Err(e) = self.event_tx.send(event.clone()) {
                    tracing::debug!("No UI clients connected to receive violation event: {}", e);
                }

                Some(event)
            }
        }
    }

    /// Suspend a process and optionally its parent (for blocking mode on macOS).
    /// Stopping both prevents the parent from spawning more malicious children.
    #[cfg(unix)]
    pub fn suspend_process(&self, pid: u32, ppid: Option<u32>) -> Result<()> {
        use nix::errno::Errno;
        use nix::sys::signal::{kill, Signal};
        use nix::unistd::Pid;

        let mut child_suspended = false;

        // Try to stop the child process
        let child_pid = Pid::from_raw(pid as i32);
        match kill(child_pid, Signal::SIGSTOP) {
            Ok(()) => {
                child_suspended = true;
            }
            Err(Errno::ESRCH) => {
                // Process already exited - that's OK, continue to try parent
                tracing::info!(
                    "Child process {} already exited, will try to suspend parent",
                    pid
                );
            }
            Err(e) => {
                return Err(Error::monitor(format!(
                    "Failed to suspend child process {}: {}",
                    pid, e
                )));
            }
        }

        // Also stop the parent if provided and it's not init/launchd
        if let Some(parent) = ppid {
            if parent > 1 {
                let parent_pid = Pid::from_raw(parent as i32);
                match kill(parent_pid, Signal::SIGSTOP) {
                    Ok(()) => {
                        if child_suspended {
                            tracing::info!(
                                "Suspended parent process {} along with child {}",
                                parent,
                                pid
                            );
                        } else {
                            tracing::info!(
                                "Suspended parent process {} (child {} already exited)",
                                parent,
                                pid
                            );
                        }
                    }
                    Err(Errno::ESRCH) => {
                        tracing::info!("Parent process {} already exited", parent);
                    }
                    Err(e) => {
                        // Log but don't fail - parent may have exited for other reasons
                        tracing::warn!("Failed to suspend parent process {}: {}", parent, e);
                    }
                }
            }
        }

        Ok(())
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
            Mechanism::Eslogger => Ok(Box::new(macos_eslogger::EsloggerMonitor::new(context))),
            #[cfg(feature = "esf")]
            Mechanism::Esf => Ok(Box::new(macos_esf::EsfMonitor::new(context))),
            #[cfg(not(feature = "esf"))]
            Mechanism::Esf => Err(Error::config(
                "ESF support not compiled in. Build with: cargo build --features esf",
            )),
            _ => Err(Error::UnsupportedPlatform(format!("{:?}", mechanism))),
        }
    }

    #[cfg(target_os = "linux")]
    {
        match mechanism {
            Mechanism::Fanotify => Ok(Box::new(linux_fanotify::FanotifyMonitor::new(context))),
            _ => Err(Error::UnsupportedPlatform(format!("{:?}", mechanism))),
        }
    }

    #[cfg(target_os = "freebsd")]
    {
        match mechanism {
            Mechanism::Dtrace => Ok(Box::new(freebsd_dtrace::DtraceMonitor::new(context))),
            _ => Err(Error::UnsupportedPlatform(format!("{:?}", mechanism))),
        }
    }

    #[cfg(target_os = "netbsd")]
    {
        match mechanism {
            Mechanism::Dtrace => Ok(Box::new(netbsd_dtrace::DtraceMonitor::new(context))),
            _ => Err(Error::UnsupportedPlatform(format!("{:?}", mechanism))),
        }
    }

    #[cfg(not(any(
        target_os = "macos",
        target_os = "linux",
        target_os = "freebsd",
        target_os = "netbsd"
    )))]
    {
        Err(Error::UnsupportedPlatform(std::env::consts::OS.to_string()))
    }
}

/// Build process tree from ProcessContext.
/// Creates the first entry from the context (since the process may have exited),
/// then builds the parent chain by querying the system.
///
/// This should be called AFTER processes have been stopped (if applicable),
/// so the is_stopped state will be accurately captured.
fn build_tree_from_context(context: &ProcessContext) -> Vec<ProcessTreeEntry> {
    use crate::process::is_process_stopped;

    let mut tree = Vec::new();
    let pid = context.pid.unwrap_or(0);

    // Create entry for the violating process from the event data we already have
    // This is important because short-lived processes (cat, grep, etc.) may exit
    // before we can query /proc or ps for their info
    let process_name = context
        .path
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_default();

    // Query actual stopped state - processes should already be stopped if applicable
    let is_stopped = if pid > 0 {
        is_process_stopped(pid)
    } else {
        false
    };

    let first_entry = ProcessTreeEntry {
        pid,
        ppid: context.ppid,
        name: process_name,
        path: context.path.to_string_lossy().to_string(),
        cwd: None, // Not available from eslogger
        cmdline: context.args.as_ref().map(|a| a.join(" ")),
        uid: context.euid, // eslogger gives us euid
        euid: context.euid,
        team_id: context.team_id.clone(),
        signing_id: context.signing_id.clone(),
        is_platform_binary: context.platform_binary.unwrap_or(false),
        is_stopped,
    };
    tree.push(first_entry);

    // Now build the rest of the tree from the parent PID
    // Parent should be stopped too if we stopped it, so it can be queried reliably
    if let Some(ppid) = context.ppid {
        if ppid > 0 {
            let parent_tree = build_process_tree(ppid);
            if parent_tree.is_empty() {
                tracing::debug!(
                    "Parent process tree empty for ppid {} (child pid {:?})",
                    ppid,
                    context.pid
                );
            } else {
                tree.extend(parent_tree);
            }
        }
    } else {
        tracing::debug!("No ppid available for process {:?}", context.pid);
    }

    tree
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
        use crate::process::ProcessContext;
        use crate::rules::RuleEngine;
        use crate::storage::Storage;
        use std::path::PathBuf;
        use tempfile::TempDir;

        let temp_dir = TempDir::new().unwrap();
        let db_path = temp_dir.path().join("test.db");
        let storage = Arc::new(Storage::open(&db_path).unwrap());
        let config = Config::default();
        let rule_engine = Arc::new(tokio::sync::RwLock::new(RuleEngine::new(
            Vec::new(),
            Vec::new(),
        )));
        let (event_tx, _rx) = broadcast::channel(100);
        let mode = Arc::new(tokio::sync::RwLock::new("block".to_string()));
        let degraded_mode = Arc::new(tokio::sync::RwLock::new(false));
        let pending_events = Arc::new(tokio::sync::RwLock::new(Vec::new()));

        let ctx = MonitorContext::new(
            config,
            rule_engine,
            storage,
            event_tx,
            mode,
            degraded_mode,
            pending_events,
        );

        let process = ProcessContext::new(PathBuf::from("/usr/bin/cat")).with_pid(1234);
        let result = ctx.process_access("/tmp/random_file.txt", &process).await;
        assert!(result.is_none()); // Not protected
    }

    #[tokio::test]
    async fn test_monitor_context_process_access_allowed() {
        use crate::config::{Config, ProtectedFile};
        use crate::process::ProcessContext;
        use crate::rules::{AllowRule, RuleEngine};
        use crate::storage::Storage;
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

        let rule_engine = Arc::new(tokio::sync::RwLock::new(RuleEngine::new(
            vec![protected],
            Vec::new(),
        )));
        let (event_tx, _rx) = broadcast::channel(100);
        let mode = Arc::new(tokio::sync::RwLock::new("block".to_string()));
        let degraded_mode = Arc::new(tokio::sync::RwLock::new(false));
        let pending_events = Arc::new(tokio::sync::RwLock::new(Vec::new()));

        let ctx = MonitorContext::new(
            config,
            rule_engine,
            storage,
            event_tx,
            mode,
            degraded_mode,
            pending_events,
        );

        // Allowed process
        let process = ProcessContext::new(PathBuf::from("/usr/bin/ssh")).with_pid(1234);
        let result = ctx.process_access("~/.ssh/id_rsa", &process).await;
        assert!(result.is_none()); // Allowed, no violation
    }

    #[tokio::test]
    async fn test_monitor_context_process_access_denied() {
        use crate::config::{Config, ProtectedFile};
        use crate::process::ProcessContext;
        use crate::rules::RuleEngine;
        use crate::storage::Storage;
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

        let rule_engine = Arc::new(tokio::sync::RwLock::new(RuleEngine::new(
            vec![protected],
            Vec::new(),
        )));
        let (event_tx, _rx) = broadcast::channel(100);
        let mode = Arc::new(tokio::sync::RwLock::new("block".to_string()));
        let degraded_mode = Arc::new(tokio::sync::RwLock::new(false));
        let pending_events = Arc::new(tokio::sync::RwLock::new(Vec::new()));

        let ctx = MonitorContext::new(
            config,
            rule_engine,
            storage,
            event_tx,
            mode,
            degraded_mode,
            pending_events,
        );

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
        use crate::process::ProcessContext;
        use crate::rules::RuleEngine;
        use crate::storage::Storage;
        use std::path::PathBuf;
        use tempfile::TempDir;

        let temp_dir = TempDir::new().unwrap();
        let db_path = temp_dir.path().join("test.db");
        let storage = Arc::new(Storage::open(&db_path).unwrap());

        let mut config = Config::default();
        config.excluded_patterns.push("/tmp/*".to_string());

        let rule_engine = Arc::new(tokio::sync::RwLock::new(RuleEngine::new(
            Vec::new(),
            Vec::new(),
        )));
        let (event_tx, _rx) = broadcast::channel(100);
        let mode = Arc::new(tokio::sync::RwLock::new("block".to_string()));
        let degraded_mode = Arc::new(tokio::sync::RwLock::new(false));
        let pending_events = Arc::new(tokio::sync::RwLock::new(Vec::new()));

        let ctx = MonitorContext::new(
            config,
            rule_engine,
            storage,
            event_tx,
            mode,
            degraded_mode,
            pending_events,
        );

        let process = ProcessContext::new(PathBuf::from("/usr/bin/cat")).with_pid(1234);
        let result = ctx.process_access("/tmp/excluded_file.txt", &process).await;
        assert!(result.is_none()); // Excluded
    }

    #[tokio::test]
    async fn test_monitor_context_mode_logged() {
        use crate::config::{Config, ProtectedFile};
        use crate::process::ProcessContext;
        use crate::rules::RuleEngine;
        use crate::storage::Storage;
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

        let rule_engine = Arc::new(tokio::sync::RwLock::new(RuleEngine::new(
            vec![protected],
            Vec::new(),
        )));
        let (event_tx, _rx) = broadcast::channel(100);
        let mode = Arc::new(tokio::sync::RwLock::new("monitor".to_string())); // Not block mode
        let degraded_mode = Arc::new(tokio::sync::RwLock::new(false));
        let pending_events = Arc::new(tokio::sync::RwLock::new(Vec::new()));

        let ctx = MonitorContext::new(
            config,
            rule_engine,
            storage,
            event_tx,
            mode,
            degraded_mode,
            pending_events,
        );

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
            let rule_engine = Arc::new(tokio::sync::RwLock::new(RuleEngine::new(
                Vec::new(),
                Vec::new(),
            )));
            let (event_tx, _rx) = broadcast::channel(100);
            let mode = Arc::new(tokio::sync::RwLock::new("block".to_string()));
            let degraded_mode = Arc::new(tokio::sync::RwLock::new(false));
            let pending_events = Arc::new(tokio::sync::RwLock::new(Vec::new()));

            let ctx = Arc::new(MonitorContext::new(
                config,
                rule_engine,
                storage,
                event_tx,
                mode,
                degraded_mode,
                pending_events,
            ));
            let result = create_monitor(Mechanism::Auto, ctx);
            assert!(result.is_err());
        }
    }
}
