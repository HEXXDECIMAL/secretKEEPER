//! FreeBSD DTrace-based file access monitor.
//!
//! # Overview
//!
//! This module uses DTrace on FreeBSD to monitor file access events. DTrace probes
//! the `syscall::openat:entry` and `syscall::open:entry` syscalls to capture file
//! access attempts.
//!
//! # Limitations
//!
//! - **Cannot block access**: DTrace is an observability tool, not a security framework.
//!   File access is detected AFTER it begins, not before.
//!
//! - **Best-effort mitigation**: Like macOS eslogger, we SIGSTOP violating processes
//!   after detection to prevent further exfiltration.
//!
//! - **Requires root**: DTrace requires root privileges to run.
//!
//! # Requirements
//!
//! - FreeBSD with DTrace enabled (default in FreeBSD 10+)
//! - Root privileges to run the agent

use super::MonitorContext;
use crate::error::{Error, Result};
use crate::process::{get_home_for_uid, ProcessContext};
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::{Child, Command};

/// Path to dtrace binary
const DTRACE_PATH: &str = "/usr/sbin/dtrace";

/// DTrace script that probes file open syscalls.
/// Output format: pid|ppid|uid|path
/// Uses | as delimiter since it's rare in paths.
/// Filters out our own PID to avoid infinite loops.
/// Note: openat has path in arg1, open has path in arg0.
const DTRACE_SCRIPT: &str = r#"
syscall::openat:entry
/pid != $1 && arg1 != 0/
{
    printf("%d|%d|%d|%s\n", pid, ppid, uid, copyinstr(arg1));
}

syscall::open:entry
/pid != $1 && arg0 != 0/
{
    printf("%d|%d|%d|%s\n", pid, ppid, uid, copyinstr(arg0));
}
"#;

pub struct DtraceMonitor {
    context: Arc<MonitorContext>,
    child: Option<Child>,
}

impl DtraceMonitor {
    pub fn new(context: Arc<MonitorContext>) -> Self {
        Self {
            context,
            child: None,
        }
    }

    /// Check if dtrace is available on the system.
    fn check_dtrace_available() -> bool {
        std::process::Command::new(DTRACE_PATH)
            .arg("-V")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }

    /// Spawn the dtrace subprocess with our monitoring script.
    async fn spawn_dtrace(&self) -> Result<Child> {
        let our_pid = std::process::id();

        let script = DTRACE_SCRIPT.replace("$1", &our_pid.to_string());

        let child = Command::new(DTRACE_PATH)
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
    fn parse_dtrace_line(&self, line: &str) -> Option<(String, ProcessContext)> {
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

        // Get process executable path
        let exe_path = self
            .get_process_exe(pid)
            .unwrap_or_else(|| PathBuf::from("unknown"));

        // Build process context
        let context = ProcessContext::new(exe_path)
            .with_pid(pid)
            .with_ppid(ppid)
            .with_uid(uid)
            .with_euid(uid); // On FreeBSD, we get uid; euid requires more work

        // Normalize file path - expand to ~/ format for user home directories
        let normalized_path = self.normalize_path(path, uid);

        Some((normalized_path, context))
    }

    /// Get the executable path for a process.
    fn get_process_exe(&self, pid: u32) -> Option<PathBuf> {
        // Use procstat to get the executable path
        let output = std::process::Command::new("/usr/bin/procstat")
            .args(["-b", &pid.to_string()])
            .output()
            .ok()?;

        if !output.status.success() {
            return None;
        }

        let output_str = String::from_utf8_lossy(&output.stdout);
        // Skip header line, parse second line
        let line = output_str.lines().nth(1)?;
        let parts: Vec<&str> = line.split_whitespace().collect();

        // Format: PID COMM PATH
        parts.get(2).map(|s| PathBuf::from(*s))
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
        tracing::info!("Starting DTrace monitor");
        tracing::info!("Note: DTrace requires root privileges");

        // Check if dtrace is available
        if !Self::check_dtrace_available() {
            return Err(Error::monitor(
                "dtrace not found or not executable. Ensure you're running as root on FreeBSD.",
            ));
        }

        // DTrace can only observe, not block - set mode to best-effort
        {
            let mut mode = self.context.mode.write().await;
            if mode.as_str() == "block" {
                *mode = "best-effort".to_string();
                tracing::info!(
                    "Mode: best-effort (DTrace can observe and suspend, not pre-emptively block)"
                );
            }
        }

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

            // Log stderr in background
            if let Some(stderr) = child.stderr.take() {
                tokio::spawn(async move {
                    let reader = BufReader::new(stderr);
                    let mut lines = reader.lines();
                    while let Ok(Some(line)) = lines.next_line().await {
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
                });
            }

            self.child = Some(child);

            // Spawn periodic status logging
            let stats_context = self.context.clone();
            tokio::spawn(async move {
                let mut interval = tokio::time::interval(Duration::from_secs(60));
                loop {
                    interval.tick().await;
                    let snapshot = stats_context.stats.take();
                    if snapshot.events_received > 0
                        || snapshot.protected_checks > 0
                        || snapshot.violations > 0
                    {
                        tracing::info!(
                            "Status [dtrace]: {} events, {} protected file checks, {} allowed, {} violations, {} rate-limited",
                            snapshot.events_received,
                            snapshot.protected_checks,
                            snapshot.allowed,
                            snapshot.violations,
                            snapshot.rate_limited
                        );
                    } else {
                        tracing::info!(
                            "Status [dtrace]: idle (no file access events in last minute)"
                        );
                    }
                }
            });

            // Process events
            let reader = BufReader::new(stdout);
            let mut lines = reader.lines();

            tracing::info!("Listening for file access events...");

            let mut event_count: u64 = 0;
            while let Ok(Some(line)) = lines.next_line().await {
                event_count += 1;

                // Log first few events and then periodically for debugging
                if event_count <= 5 || event_count % 1000 == 0 {
                    tracing::debug!("dtrace event #{}: {}", event_count, line);
                }

                if let Some((file_path, context)) = self.parse_dtrace_line(&line) {
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

                    // Process the access
                    if let Some(violation) = self.context.process_access(&file_path, &context).await
                    {
                        tracing::warn!(
                            "VIOLATION [{}]: {} accessed {} ({})",
                            violation.id,
                            violation.process_path,
                            violation.file_path,
                            violation.action
                        );
                    }
                }
            }

            // dtrace exited - decide whether to restart
            tracing::warn!("dtrace process exited, will restart...");

            // Wait before restart with backoff
            tokio::time::sleep(restart_delay).await;
            restart_delay = (restart_delay * 2).min(MAX_RESTART_DELAY);
        }
    }

    async fn stop(&mut self) -> Result<()> {
        if let Some(mut child) = self.child.take() {
            tracing::info!("Stopping dtrace monitor");
            if let Err(e) = child.kill().await {
                tracing::warn!("Failed to kill dtrace process: {}", e);
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

    #[test]
    fn test_parse_dtrace_line_valid() {
        let monitor = create_test_monitor();

        let result = monitor.parse_dtrace_line("1234|1|0|/etc/passwd");
        assert!(result.is_some());

        let (path, context) = result.unwrap();
        assert_eq!(path, "/etc/passwd");
        assert_eq!(context.pid, Some(1234));
        assert_eq!(context.ppid, Some(1));
        assert_eq!(context.uid, Some(0));
    }

    #[test]
    fn test_parse_dtrace_line_with_spaces() {
        let monitor = create_test_monitor();

        let result = monitor.parse_dtrace_line("5678|100|501|/home/user/my file.txt");
        assert!(result.is_some());

        let (path, _context) = result.unwrap();
        assert_eq!(path, "/home/user/my file.txt");
    }

    #[test]
    fn test_parse_dtrace_line_with_pipe_in_path() {
        let monitor = create_test_monitor();

        // Path contains a pipe character - should still parse correctly
        // since we use splitn(4, ...) to limit splits
        let result = monitor.parse_dtrace_line("1234|1|0|/tmp/file|with|pipes.txt");
        assert!(result.is_some());

        let (path, _context) = result.unwrap();
        assert_eq!(path, "/tmp/file|with|pipes.txt");
    }

    #[test]
    fn test_parse_dtrace_line_empty() {
        let monitor = create_test_monitor();
        assert!(monitor.parse_dtrace_line("").is_none());
        assert!(monitor.parse_dtrace_line("   ").is_none());
    }

    #[test]
    fn test_parse_dtrace_line_malformed() {
        let monitor = create_test_monitor();

        // Missing fields
        assert!(monitor.parse_dtrace_line("1234").is_none());
        assert!(monitor.parse_dtrace_line("1234|1").is_none());
        assert!(monitor.parse_dtrace_line("1234|1|0").is_none());
    }

    #[test]
    fn test_parse_dtrace_line_invalid_numbers() {
        let monitor = create_test_monitor();

        assert!(monitor.parse_dtrace_line("abc|1|0|/etc/passwd").is_none());
        assert!(monitor
            .parse_dtrace_line("1234|xyz|0|/etc/passwd")
            .is_none());
        assert!(monitor
            .parse_dtrace_line("1234|1|bad|/etc/passwd")
            .is_none());
    }

    #[test]
    fn test_parse_dtrace_line_directory_skipped() {
        let monitor = create_test_monitor();

        let result = monitor.parse_dtrace_line("1234|1|0|/home/user/");
        assert!(result.is_none()); // Directories should be skipped
    }

    #[test]
    fn test_parse_dtrace_line_empty_path() {
        let monitor = create_test_monitor();

        let result = monitor.parse_dtrace_line("1234|1|0|");
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
    }

    #[test]
    fn test_dtrace_script_substitution() {
        let our_pid = 12345u32;
        let script = DTRACE_SCRIPT.replace("$1", &our_pid.to_string());

        assert!(script.contains("pid != 12345"));
        assert!(!script.contains("$1"));
    }

    #[test]
    fn test_parse_dtrace_line_ssh_key() {
        let monitor = create_test_monitor();

        let result = monitor.parse_dtrace_line("9999|1000|501|/home/user/.ssh/id_rsa");
        assert!(result.is_some());

        let (path, context) = result.unwrap();
        assert!(path.contains(".ssh"));
        assert_eq!(context.pid, Some(9999));
    }

    #[test]
    fn test_parse_dtrace_line_aws_credentials() {
        let monitor = create_test_monitor();

        let result = monitor.parse_dtrace_line("9999|1000|501|/home/user/.aws/credentials");
        assert!(result.is_some());

        let (path, _context) = result.unwrap();
        assert!(path.contains(".aws/credentials"));
    }

    #[test]
    fn test_parse_dtrace_line_large_pid() {
        let monitor = create_test_monitor();

        // Large but valid PIDs
        let result = monitor.parse_dtrace_line("4294967295|1|0|/etc/passwd");
        assert!(result.is_some());

        let (_path, context) = result.unwrap();
        assert_eq!(context.pid, Some(4294967295));
    }

    #[test]
    fn test_parse_dtrace_line_whitespace_handling() {
        let monitor = create_test_monitor();

        // Leading/trailing whitespace should be trimmed
        let result = monitor.parse_dtrace_line("  1234|1|0|/etc/passwd  \n");
        assert!(result.is_some());

        let (path, _context) = result.unwrap();
        // Path should not have trailing whitespace
        assert!(!path.ends_with(' '));
        assert!(!path.ends_with('\n'));
    }
}
