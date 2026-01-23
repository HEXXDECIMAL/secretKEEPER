//! NetBSD DTrace-based file access monitor.
//!
//! # Overview
//!
//! This module uses DTrace on NetBSD to monitor file access events. DTrace probes
//! the `syscall::openat:entry` and `syscall::open:entry` syscalls to capture file
//! access attempts.
//!
//! # Limitations
//!
//! - **Cannot block access**: DTrace is an observability tool, not a security framework.
//!   File access is detected AFTER it begins, not before.
//!
//! - **Best-effort mitigation**: Like macOS eslogger and FreeBSD, we SIGSTOP violating
//!   processes after detection to prevent further exfiltration.
//!
//! - **Requires root**: DTrace requires root privileges to run.
//!
//! # Requirements
//!
//! - NetBSD 8+ with DTrace enabled (MKDTRACE=yes in build)
//! - Root privileges to run the agent
//!
//! # NetBSD-Specific Notes
//!
//! - DTrace on NetBSD supports SDT and FBT providers, with syscall provider available
//! - Process executable lookup uses /proc/<pid>/exe when procfs is mounted,
//!   falling back to sysctl kern.proc.pathname

use super::MonitorContext;
use crate::error::{Error, Result};
use crate::process::{get_home_for_uid, ProcessContext};
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::{Child, Command};
use tokio::sync::Notify;

/// Path to dtrace binary - standard location on NetBSD
const DTRACE_PATH: &str = "/usr/sbin/dtrace";

/// Alternate path if installed via pkgsrc
const DTRACE_PATH_PKGSRC: &str = "/usr/pkg/sbin/dtrace";

/// DTrace script that probes file open syscalls.
/// Output format: pid|ppid|uid|path
/// Uses | as delimiter since it's rare in paths.
/// Filters out our own PID to avoid infinite loops.
/// Note: openat has path in arg1, open has path in arg0.
/// Uses __SECRETKEEPER_PID__ as placeholder to avoid accidental substitution.
const DTRACE_SCRIPT: &str = r#"
syscall::openat:entry
/pid != __SECRETKEEPER_PID__ && arg1 != 0/
{
    printf("%d|%d|%d|%s\n", pid, ppid, uid, copyinstr(arg1));
}

syscall::open:entry
/pid != __SECRETKEEPER_PID__ && arg0 != 0/
{
    printf("%d|%d|%d|%s\n", pid, ppid, uid, copyinstr(arg0));
}
"#;

pub struct DtraceMonitor {
    context: Arc<MonitorContext>,
    child: Option<Child>,
    /// Signal to stop background tasks
    shutdown: Arc<AtomicBool>,
    /// Notify background tasks to check shutdown
    shutdown_notify: Arc<Notify>,
    /// Path to dtrace binary (detected at runtime)
    dtrace_path: String,
}

impl DtraceMonitor {
    pub fn new(context: Arc<MonitorContext>) -> Self {
        // Detect dtrace path at construction time
        let dtrace_path = Self::find_dtrace_path();
        Self {
            context,
            child: None,
            shutdown: Arc::new(AtomicBool::new(false)),
            shutdown_notify: Arc::new(Notify::new()),
            dtrace_path,
        }
    }

    /// Find the dtrace binary path.
    fn find_dtrace_path() -> String {
        // Check standard location first
        if std::path::Path::new(DTRACE_PATH).exists() {
            return DTRACE_PATH.to_string();
        }
        // Check pkgsrc location
        if std::path::Path::new(DTRACE_PATH_PKGSRC).exists() {
            return DTRACE_PATH_PKGSRC.to_string();
        }
        // Default to standard path, will fail later with clear error
        DTRACE_PATH.to_string()
    }

    /// Check if dtrace is available on the system.
    fn check_dtrace_available(&self) -> bool {
        std::process::Command::new(&self.dtrace_path)
            .arg("-V")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }

    /// Spawn the dtrace subprocess with our monitoring script.
    async fn spawn_dtrace(&self) -> Result<Child> {
        let our_pid = std::process::id();

        let script = DTRACE_SCRIPT.replace("__SECRETKEEPER_PID__", &our_pid.to_string());

        let child = Command::new(&self.dtrace_path)
            .args([
                "-q", // Quiet mode - suppress dtrace preamble
                "-n", // Inline script
                &script,
            ])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| Error::monitor(format!("Failed to spawn dtrace: {}", e)))?;

        tracing::info!("Started dtrace process with PID: {:?}", child.id());
        Ok(child)
    }

    /// Parse a line of dtrace output into file path and process context.
    /// Format: pid|ppid|uid|path
    async fn parse_dtrace_line(&self, line: &str) -> Option<(String, ProcessContext)> {
        let line = line.trim();
        if line.is_empty() {
            return None;
        }

        let parts: Vec<&str> = line.splitn(4, '|').collect();
        if parts.len() < 4 {
            tracing::debug!("Malformed dtrace output: {}", line);
            return None;
        }

        let pid: u32 = parts[0].parse().ok()?;
        let ppid: u32 = parts[1].parse().ok()?;
        let uid: u32 = parts[2].parse().ok()?;
        let path = parts[3];

        // Skip empty paths
        if path.is_empty() {
            return None;
        }

        // Skip directories (ending with /)
        if path.ends_with('/') {
            return None;
        }

        // Get process executable path (async to avoid blocking)
        let exe_path = self
            .get_process_exe(pid)
            .await
            .unwrap_or_else(|| PathBuf::from("unknown"));

        // Build process context
        let context = ProcessContext::new(exe_path)
            .with_pid(pid)
            .with_ppid(ppid)
            .with_uid(uid)
            .with_euid(uid); // On NetBSD, we get uid; euid requires more work

        // Normalize file path - expand to ~/ format for user home directories
        let normalized_path = self.normalize_path(path, uid);

        Some((normalized_path, context))
    }

    /// Get the executable path for a process.
    /// On NetBSD, try /proc/<pid>/exe first (if procfs mounted),
    /// then fall back to sysctl.
    async fn get_process_exe(&self, pid: u32) -> Option<PathBuf> {
        // Try /proc/<pid>/exe symlink first (requires procfs mounted)
        let proc_exe = PathBuf::from(format!("/proc/{}/exe", pid));
        if let Ok(exe_path) = tokio::fs::read_link(&proc_exe).await {
            return Some(exe_path);
        }

        // Fall back to sysctl kern.proc.pathname.<pid>
        // This is available without procfs
        let output = Command::new("/sbin/sysctl")
            .args(["-n", &format!("kern.proc.pathname.{}", pid)])
            .output()
            .await
            .ok()?;

        if !output.status.success() {
            return None;
        }

        let path_str = String::from_utf8_lossy(&output.stdout);
        let path = path_str.trim();
        if path.is_empty() || path == "(unknown)" {
            return None;
        }

        Some(PathBuf::from(path))
    }

    /// Normalize a file path, converting /home/user/... to ~/...
    fn normalize_path(&self, path: &str, uid: u32) -> String {
        if !path.starts_with('/') {
            // Relative path, return as-is
            return path.to_string();
        }

        if let Some(home) = get_home_for_uid(uid) {
            let home_str = home.to_string_lossy();
            if let Some(suffix) = path.strip_prefix(home_str.as_ref()) {
                if suffix.is_empty() || suffix.starts_with('/') {
                    return format!("~{}", suffix);
                }
            }
        }

        path.to_string()
    }
}

#[async_trait::async_trait]
impl super::Monitor for DtraceMonitor {
    async fn start(&mut self) -> Result<()> {
        tracing::info!("Starting DTrace monitor on NetBSD");
        tracing::info!("Using dtrace at: {}", self.dtrace_path);
        tracing::info!("Note: DTrace requires root privileges");

        // Check if dtrace is available
        if !self.check_dtrace_available() {
            return Err(Error::monitor(format!(
                "dtrace not found at {} or not executable. Ensure you're running as root on NetBSD with DTrace enabled (MKDTRACE=yes).",
                self.dtrace_path
            )));
        }

        // DTrace can only observe, not block - set mode to best-effort
        {
            let mut mode = self.context.mode.write().await;
            if mode.as_str() == "block" {
                *mode = "best-effort".to_string();
                tracing::warn!(
                    "Mode changed to 'best-effort': DTrace can observe and suspend, but cannot pre-emptively block file access"
                );
            }
        }

        // Reset shutdown state
        self.shutdown.store(false, Ordering::SeqCst);

        // Spawn dtrace with restart logic
        let mut restart_delay = Duration::from_millis(500);
        const MAX_RESTART_DELAY: Duration = Duration::from_secs(30);
        let mut consecutive_failures = 0;

        loop {
            // Spawn dtrace
            let mut child = match self.spawn_dtrace().await {
                Ok(c) => {
                    consecutive_failures = 0;
                    restart_delay = Duration::from_millis(500);
                    c
                }
                Err(e) => {
                    consecutive_failures += 1;
                    tracing::error!(
                        "Failed to spawn dtrace (attempt {}): {}",
                        consecutive_failures,
                        e
                    );

                    if consecutive_failures >= 5 {
                        return Err(Error::monitor(format!(
                            "dtrace failed to start after {} attempts: {}",
                            consecutive_failures, e
                        )));
                    }

                    tracing::info!("Retrying in {:?}...", restart_delay);
                    tokio::time::sleep(restart_delay).await;
                    restart_delay = (restart_delay * 2).min(MAX_RESTART_DELAY);
                    continue;
                }
            };

            // Take stdout
            let stdout = match child.stdout.take() {
                Some(stdout) => stdout,
                None => {
                    if let Err(e) = child.kill().await {
                        tracing::warn!("Failed to kill orphaned dtrace process: {}", e);
                    }
                    return Err(Error::monitor("Failed to capture dtrace stdout"));
                }
            };

            // Log stderr in background with shutdown support
            if let Some(stderr) = child.stderr.take() {
                let shutdown = self.shutdown.clone();
                let shutdown_notify = self.shutdown_notify.clone();
                tokio::spawn(async move {
                    let reader = BufReader::new(stderr);
                    let mut lines = reader.lines();
                    loop {
                        tokio::select! {
                            _ = shutdown_notify.notified() => {
                                if shutdown.load(Ordering::SeqCst) {
                                    tracing::debug!("Stderr logging task shutting down");
                                    break;
                                }
                            }
                            result = lines.next_line() => {
                                match result {
                                    Ok(Some(line)) => {
                                        // DTrace privilege errors
                                        if line.contains("permission denied")
                                            || line.contains("DTrace requires additional privileges")
                                        {
                                            tracing::error!("DTrace permission error: {}", line);
                                            tracing::error!("Ensure the agent is running as root");
                                        } else {
                                            tracing::warn!("dtrace stderr: {}", line);
                                        }
                                    }
                                    Ok(None) => break, // EOF
                                    Err(_) => break,
                                }
                            }
                        }
                    }
                });
            }

            self.child = Some(child);

            // Spawn periodic status logging with shutdown support
            let stats_context = self.context.clone();
            let shutdown = self.shutdown.clone();
            let shutdown_notify = self.shutdown_notify.clone();
            tokio::spawn(async move {
                let mut interval = tokio::time::interval(Duration::from_secs(60));
                loop {
                    tokio::select! {
                        _ = shutdown_notify.notified() => {
                            if shutdown.load(Ordering::SeqCst) {
                                tracing::debug!("Stats logging task shutting down");
                                break;
                            }
                        }
                        _ = interval.tick() => {
                            let snapshot = stats_context.stats.take();
                            if snapshot.events_received > 0
                                || snapshot.protected_checks > 0
                                || snapshot.violations > 0
                            {
                                tracing::info!(
                                    "Status [dtrace/netbsd]: {} events, {} protected file checks, {} allowed, {} violations, {} rate-limited",
                                    snapshot.events_received,
                                    snapshot.protected_checks,
                                    snapshot.allowed,
                                    snapshot.violations,
                                    snapshot.rate_limited
                                );
                            } else {
                                tracing::debug!(
                                    "Status [dtrace/netbsd]: idle (no file access events in last minute)"
                                );
                            }
                        }
                    }
                }
            });

            // Process events
            let reader = BufReader::new(stdout);
            let mut lines = reader.lines();

            tracing::info!("Listening for file access events...");

            let mut event_count: u64 = 0;
            while let Ok(Some(line)) = lines.next_line().await {
                // Check for shutdown
                if self.shutdown.load(Ordering::SeqCst) {
                    tracing::info!("Shutdown requested, stopping event processing");
                    break;
                }

                event_count += 1;

                // Log first few events and then periodically for debugging
                if event_count <= 5 || event_count % 1000 == 0 {
                    tracing::debug!("dtrace event #{}: {}", event_count, line);
                }

                if let Some((file_path, mut context)) = self.parse_dtrace_line(&line).await {
                    // Enrich with package information for package-based rule matching.
                    // Always verify since package rules require verification by default.
                    self.context
                        .enrich_with_verified_package_info(&mut context, true);

                    // Debug logging for SSH file access
                    if file_path.contains(".ssh") {
                        tracing::info!(
                            "SSH file access detected: path={} by process={} (uid={:?}, pid={:?})",
                            file_path,
                            context.path.display(),
                            context.uid,
                            context.pid
                        );
                    }

                    // Process the access with a timeout to avoid blocking indefinitely
                    let process_future = self.context.process_access(&file_path, &context);
                    match tokio::time::timeout(Duration::from_secs(5), process_future).await {
                        Ok(Some(violation)) => {
                            tracing::warn!(
                                "VIOLATION [{}]: {} accessed {} ({})",
                                violation.id,
                                violation.process_path,
                                violation.file_path,
                                violation.action
                            );
                        }
                        Ok(None) => {
                            // No violation, normal case
                        }
                        Err(_) => {
                            tracing::warn!(
                                "Timeout processing access to {} by pid {:?}, skipping",
                                file_path,
                                context.pid
                            );
                        }
                    }
                }
            }

            // Check if we should exit or restart
            if self.shutdown.load(Ordering::SeqCst) {
                tracing::info!("Shutdown requested, not restarting dtrace");
                // Wait for child to fully exit
                if let Some(mut child) = self.child.take() {
                    let _ = child.wait().await;
                }
                break;
            }

            // dtrace exited unexpectedly - restart
            tracing::warn!("dtrace process exited unexpectedly, will restart...");

            // Wait for child to fully exit to avoid zombies
            if let Some(mut child) = self.child.take() {
                let _ = child.wait().await;
            }

            // Wait before restart with backoff
            tokio::time::sleep(restart_delay).await;
            restart_delay = (restart_delay * 2).min(MAX_RESTART_DELAY);
        }

        Ok(())
    }

    async fn stop(&mut self) -> Result<()> {
        tracing::info!("Stopping dtrace monitor");

        // Signal shutdown to all background tasks
        self.shutdown.store(true, Ordering::SeqCst);
        self.shutdown_notify.notify_waiters();

        // Kill and wait for dtrace child process
        if let Some(mut child) = self.child.take() {
            if let Err(e) = child.kill().await {
                tracing::warn!("Failed to kill dtrace process: {}", e);
            }
            // Wait to reap the child and avoid zombie
            match tokio::time::timeout(Duration::from_secs(5), child.wait()).await {
                Ok(Ok(status)) => {
                    tracing::debug!("dtrace process exited with status: {}", status);
                }
                Ok(Err(e)) => {
                    tracing::warn!("Error waiting for dtrace process: {}", e);
                }
                Err(_) => {
                    tracing::warn!("Timeout waiting for dtrace process to exit");
                }
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::rules::RuleEngine;
    use crate::storage::Storage;
    use tokio::sync::broadcast;

    fn create_test_monitor() -> DtraceMonitor {
        let temp_dir = tempfile::TempDir::new().unwrap();
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
        let context = Arc::new(MonitorContext::new(
            config,
            rule_engine,
            storage,
            event_tx,
            mode,
            degraded_mode,
            pending_events,
        ));
        // Keep temp_dir alive
        std::mem::forget(temp_dir);
        DtraceMonitor::new(context)
    }

    #[tokio::test]
    async fn test_parse_dtrace_line_valid() {
        let monitor = create_test_monitor();

        let result = monitor.parse_dtrace_line("1234|1|0|/etc/passwd").await;
        assert!(result.is_some());

        let (path, context) = result.unwrap();
        assert_eq!(path, "/etc/passwd");
        assert_eq!(context.pid, Some(1234));
        assert_eq!(context.ppid, Some(1));
        assert_eq!(context.uid, Some(0));
    }

    #[tokio::test]
    async fn test_parse_dtrace_line_with_spaces() {
        let monitor = create_test_monitor();

        let result = monitor
            .parse_dtrace_line("5678|100|501|/home/user/my file.txt")
            .await;
        assert!(result.is_some());

        let (path, _context) = result.unwrap();
        assert_eq!(path, "/home/user/my file.txt");
    }

    #[tokio::test]
    async fn test_parse_dtrace_line_with_pipe_in_path() {
        let monitor = create_test_monitor();

        // Path contains a pipe character - should still parse correctly
        // since we use splitn(4, ...) to limit splits
        let result = monitor
            .parse_dtrace_line("1234|1|0|/tmp/file|with|pipes.txt")
            .await;
        assert!(result.is_some());

        let (path, _context) = result.unwrap();
        assert_eq!(path, "/tmp/file|with|pipes.txt");
    }

    #[tokio::test]
    async fn test_parse_dtrace_line_empty() {
        let monitor = create_test_monitor();
        assert!(monitor.parse_dtrace_line("").await.is_none());
        assert!(monitor.parse_dtrace_line("   ").await.is_none());
    }

    #[tokio::test]
    async fn test_parse_dtrace_line_malformed() {
        let monitor = create_test_monitor();

        // Missing fields
        assert!(monitor.parse_dtrace_line("1234").await.is_none());
        assert!(monitor.parse_dtrace_line("1234|1").await.is_none());
        assert!(monitor.parse_dtrace_line("1234|1|0").await.is_none());
    }

    #[tokio::test]
    async fn test_parse_dtrace_line_invalid_numbers() {
        let monitor = create_test_monitor();

        assert!(monitor
            .parse_dtrace_line("abc|1|0|/etc/passwd")
            .await
            .is_none());
        assert!(monitor
            .parse_dtrace_line("1234|xyz|0|/etc/passwd")
            .await
            .is_none());
        assert!(monitor
            .parse_dtrace_line("1234|1|bad|/etc/passwd")
            .await
            .is_none());
    }

    #[tokio::test]
    async fn test_parse_dtrace_line_directory_skipped() {
        let monitor = create_test_monitor();

        let result = monitor.parse_dtrace_line("1234|1|0|/home/user/").await;
        assert!(result.is_none()); // Directories should be skipped
    }

    #[tokio::test]
    async fn test_parse_dtrace_line_empty_path() {
        let monitor = create_test_monitor();

        let result = monitor.parse_dtrace_line("1234|1|0|").await;
        assert!(result.is_none());
    }

    #[test]
    fn test_normalize_path_absolute() {
        let monitor = create_test_monitor();

        // Non-home paths stay as-is
        let result = monitor.normalize_path("/etc/passwd", 0);
        assert_eq!(result, "/etc/passwd");
    }

    #[test]
    fn test_normalize_path_relative() {
        let monitor = create_test_monitor();

        let result = monitor.normalize_path("relative/path.txt", 501);
        assert_eq!(result, "relative/path.txt");
    }

    #[test]
    fn test_normalize_path_home_directory() {
        let monitor = create_test_monitor();

        // Get current user's home for testing
        #[cfg(unix)]
        {
            let uid = unsafe { libc::getuid() };
            if let Some(home) = get_home_for_uid(uid) {
                let home_str = home.to_string_lossy();
                let test_path = format!("{}/.ssh/id_rsa", home_str);

                let result = monitor.normalize_path(&test_path, uid);
                assert!(
                    result.starts_with("~/"),
                    "Expected ~/ prefix, got: {}",
                    result
                );
                assert!(result.ends_with(".ssh/id_rsa"));
            }
        }
    }

    #[test]
    fn test_dtrace_monitor_new() {
        let monitor = create_test_monitor();
        assert!(monitor.child.is_none());
        assert!(!monitor.shutdown.load(Ordering::SeqCst));
    }

    #[test]
    fn test_dtrace_script_substitution() {
        let our_pid = 12345u32;
        let script = DTRACE_SCRIPT.replace("__SECRETKEEPER_PID__", &our_pid.to_string());

        assert!(script.contains("pid != 12345"));
        assert!(!script.contains("__SECRETKEEPER_PID__"));
    }

    #[tokio::test]
    async fn test_parse_dtrace_line_ssh_key() {
        let monitor = create_test_monitor();

        let result = monitor
            .parse_dtrace_line("9999|1000|501|/home/user/.ssh/id_rsa")
            .await;
        assert!(result.is_some());

        let (path, context) = result.unwrap();
        assert!(path.contains(".ssh"));
        assert_eq!(context.pid, Some(9999));
    }

    #[tokio::test]
    async fn test_parse_dtrace_line_aws_credentials() {
        let monitor = create_test_monitor();

        let result = monitor
            .parse_dtrace_line("9999|1000|501|/home/user/.aws/credentials")
            .await;
        assert!(result.is_some());

        let (path, _context) = result.unwrap();
        assert!(path.contains(".aws/credentials"));
    }

    #[tokio::test]
    async fn test_parse_dtrace_line_large_pid() {
        let monitor = create_test_monitor();

        // Large but valid PIDs
        let result = monitor
            .parse_dtrace_line("4294967295|1|0|/etc/passwd")
            .await;
        assert!(result.is_some());

        let (_path, context) = result.unwrap();
        assert_eq!(context.pid, Some(4294967295));
    }

    #[tokio::test]
    async fn test_parse_dtrace_line_whitespace_handling() {
        let monitor = create_test_monitor();

        // Leading/trailing whitespace should be trimmed
        let result = monitor
            .parse_dtrace_line("  1234|1|0|/etc/passwd  \n")
            .await;
        assert!(result.is_some());

        let (path, _context) = result.unwrap();
        // Path should not have trailing whitespace
        assert!(!path.ends_with(' '));
        assert!(!path.ends_with('\n'));
    }
}
