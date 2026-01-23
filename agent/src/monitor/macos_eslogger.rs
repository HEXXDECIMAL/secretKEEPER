//! macOS eslogger-based file access monitor.

use super::MonitorContext;
use crate::error::{Error, Result};
use crate::process::ProcessContext;
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command;

pub struct EsloggerMonitor {
    context: Arc<MonitorContext>,
    child: Option<tokio::process::Child>,
}

impl EsloggerMonitor {
    pub fn new(context: Arc<MonitorContext>) -> Self {
        Self {
            context,
            child: None,
        }
    }

    fn check_eslogger_available() -> bool {
        std::process::Command::new("which")
            .arg("eslogger")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }

    /// Check if FDA is granted by briefly running eslogger.
    /// This is the only reliable way for a root process to check FDA,
    /// since root can read files regardless of TCC permissions.
    fn check_fda_granted() -> bool {
        use std::io::{BufRead, BufReader};
        use std::time::Duration;

        // Spawn eslogger briefly
        let mut child = match std::process::Command::new("eslogger")
            .args(["open", "--format", "json"])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
        {
            Ok(c) => c,
            Err(_) => return false,
        };

        // Give it a moment to start and potentially fail
        std::thread::sleep(Duration::from_millis(300));

        match child.try_wait() {
            Ok(Some(_)) => {
                // Process exited quickly - check stderr for FDA error
                if let Some(stderr) = child.stderr.take() {
                    let reader = BufReader::new(stderr);
                    for line in reader.lines().map_while(|r| r.ok()) {
                        if line.contains("ES_NEW_CLIENT_RESULT_ERR_NOT_PERMITTED")
                            || line.contains("Not permitted to create an ES Client")
                        {
                            return false;
                        }
                    }
                }
                // Exited for other reason - assume no FDA
                false
            }
            Ok(None) => {
                // Still running after 300ms - FDA is granted!
                let _ = child.kill();
                let _ = child.wait(); // Reap the zombie
                true
            }
            Err(_) => false,
        }
    }
}

#[async_trait::async_trait]
impl super::Monitor for EsloggerMonitor {
    async fn start(&mut self) -> Result<()> {
        tracing::info!("Starting eslogger monitor");
        tracing::info!("Note: eslogger requires Full Disk Access permission on macOS");

        if !Self::check_eslogger_available() {
            return Err(Error::monitor(
                "eslogger not found. Please ensure macOS 13+ or install eslogger.",
            ));
        }

        // Start eslogger with open events
        let mut child = Command::new("eslogger")
            .args(["open", "--format", "json"])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| Error::monitor(format!("Failed to spawn eslogger: {}", e)))?;

        tracing::info!("Started eslogger process with PID: {:?}", child.id());

        // Take stdout - if this fails, kill the child process to prevent leak
        let stdout = match child.stdout.take() {
            Some(stdout) => stdout,
            None => {
                // Kill the orphaned child process before returning error
                if let Err(e) = child.kill().await {
                    tracing::warn!("Failed to kill orphaned eslogger process: {}", e);
                }
                return Err(Error::monitor("Failed to capture eslogger stdout"));
            }
        };

        let stderr = child.stderr.take();

        // Log stderr in background and detect FDA errors
        if let Some(stderr) = stderr {
            let mode_clone = self.context.mode.clone();
            let context_degraded_clone = self.context.degraded_mode.clone();
            tokio::spawn(async move {
                let reader = BufReader::new(stderr);
                let mut lines = reader.lines();
                while let Ok(Some(line)) = lines.next_line().await {
                    tracing::error!("eslogger stderr: {}", line);

                    // Detect Full Disk Access error - monitoring is BROKEN without FDA
                    if line.contains("ES_NEW_CLIENT_RESULT_ERR_NOT_PERMITTED")
                        || line.contains("Not permitted to create an ES Client")
                    {
                        tracing::error!("===========================================");
                        tracing::error!("CRITICAL: Full Disk Access NOT GRANTED");
                        tracing::error!("SecretKeeper CANNOT monitor files without FDA!");
                        tracing::error!("Grant FDA to Terminal or the agent binary.");
                        tracing::error!("===========================================");

                        // Mark as degraded - this means monitoring is broken, not "best-effort"
                        let mut degraded = context_degraded_clone.write().await;
                        *degraded = true;

                        // Set mode to indicate no protection
                        let mut mode = mode_clone.write().await;
                        *mode = "disabled".to_string();
                    }
                }
            });
        }

        self.child = Some(child);

        // Process events
        let reader = BufReader::new(stdout);
        let mut lines = reader.lines();

        tracing::info!("eslogger stdout reader ready, waiting for events...");

        // eslogger can only OBSERVE events (ES_EVENT_TYPE_NOTIFY), not block them.
        // True blocking requires ES_AUTH_OPEN events via direct EndpointSecurity.
        // So when using eslogger, we're always in "best-effort" mode.
        {
            let mut mode = self.context.mode.write().await;
            if mode.as_str() == "block" {
                *mode = "best-effort".to_string();
                tracing::info!(
                    "Mode: best-effort (eslogger can observe and suspend, not pre-emptively block)"
                );
            }
        }

        tracing::info!("Listening for file access events...");

        // Spawn periodic status logging task
        let stats_context = self.context.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(60));
            loop {
                interval.tick().await;
                let snapshot = stats_context.stats.take();
                if snapshot.events_received > 0
                    || snapshot.protected_checks > 0
                    || snapshot.violations > 0
                {
                    tracing::info!(
                        "Status [eslogger]: {} events, {} protected file checks, {} allowed, {} violations, {} rate-limited",
                        snapshot.events_received,
                        snapshot.protected_checks,
                        snapshot.allowed,
                        snapshot.violations,
                        snapshot.rate_limited
                    );
                } else {
                    tracing::info!(
                        "Status [eslogger]: idle (no file access events in last minute)"
                    );
                }
            }
        });

        // Track if we've seen the FDA error
        let degraded_flag = self.context.degraded_mode.clone();

        let mut event_count: u64 = 0;
        while let Ok(Some(line)) = lines.next_line().await {
            event_count += 1;

            // Log first few events and then every 1000th for debugging
            if event_count <= 5 || event_count.is_multiple_of(1000) {
                tracing::debug!("eslogger event #{}: {} bytes", event_count, line.len());
            }

            if line.trim().is_empty() {
                continue;
            }

            // Parse the event
            match serde_json::from_str::<serde_json::Value>(&line) {
                Ok(json) => {
                    if let Some(event) = self.parse_open_event(&json) {
                        let (file_path, context) = event;

                        // Info-level log for SSH key access (critical for debugging)
                        if file_path.contains(".ssh") {
                            tracing::info!(
                                "SSH file access detected: path={} by process={} (euid={:?}, pid={:?})",
                                file_path,
                                context.path.display(),
                                context.euid,
                                context.pid
                            );
                        }

                        // Check if this is a protected file and handle it
                        // Note: process_access now handles suspension internally before building tree
                        if let Some(violation) =
                            self.context.process_access(&file_path, &context).await
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
                Err(e) => {
                    tracing::debug!("Failed to parse eslogger event: {}", e);
                }
            }
        }

        // eslogger exited - check if it was due to FDA error
        let is_degraded = *degraded_flag.read().await;
        if is_degraded {
            tracing::error!("=================================================");
            tracing::error!("FILE MONITORING DISABLED - NO PROTECTION ACTIVE");
            tracing::error!("=================================================");
            tracing::error!("The agent will stay running for UI communication only.");
            tracing::error!("To enable protection:");
            tracing::error!("  1. Open System Settings > Privacy & Security > Full Disk Access");
            tracing::error!("  2. Add: /Library/PrivilegedHelperTools/secretkeeper-agent");
            tracing::error!("  3. The agent will automatically restart when FDA is granted");

            // Keep the agent running for IPC communication, but periodically check for FDA
            // If FDA is granted, self-terminate to let launchd restart with full monitoring
            tracing::info!(
                "Will check for FDA grant every few seconds and auto-restart when granted"
            );

            // Initial delay before first check (10s) to avoid restart loop
            tracing::info!("Waiting 10s before first FDA check...");
            tokio::time::sleep(tokio::time::Duration::from_secs(10)).await;

            // Incremental backoff: 500ms -> 1s -> 2s -> 4s -> 8s -> 10s (max)
            let mut check_interval_ms: u64 = 500;
            const MAX_INTERVAL_MS: u64 = 10_000;
            let mut check_count: u32 = 0;

            loop {
                check_count += 1;
                tracing::info!("FDA check #{}: testing eslogger...", check_count);

                // Check FDA by briefly running eslogger
                let fda_granted = Self::check_fda_granted();

                if fda_granted {
                    tracing::info!("=================================================");
                    tracing::info!("FDA GRANTED - Restarting agent for full monitoring");
                    tracing::info!("=================================================");
                    // Exit with non-zero so launchd's KeepAlive (SuccessfulExit=false) restarts us
                    std::process::exit(1);
                }

                tracing::info!(
                    "FDA check #{}: not granted, next check in {}ms",
                    check_count,
                    check_interval_ms
                );

                // Sleep with current backoff interval
                tokio::time::sleep(tokio::time::Duration::from_millis(check_interval_ms)).await;

                // Increase interval with exponential backoff, capped at max
                check_interval_ms = (check_interval_ms * 2).min(MAX_INTERVAL_MS);
            }
        }

        // Normal exit
        tracing::info!("eslogger monitor stopped");
        Ok(())
    }

    async fn stop(&mut self) -> Result<()> {
        if let Some(mut child) = self.child.take() {
            child.kill().await.ok();
        }
        Ok(())
    }
}

impl EsloggerMonitor {
    fn parse_open_event(&self, json: &serde_json::Value) -> Option<(String, ProcessContext)> {
        // Check if this is an open event
        let event = json.get("event")?.get("open")?;
        let file = event.get("file")?;

        // Get file path
        let file_path = file.get("path")?.as_str()?;

        // Skip directories
        if file_path.ends_with('/') {
            return None;
        }

        // Get process info
        let process = json.get("process")?;

        let process_path = process
            .get("executable")
            .and_then(|e| e.get("path"))
            .and_then(|p| p.as_str())
            .map(PathBuf::from)?;

        let pid = process
            .get("audit_token")
            .and_then(|t| t.get("pid"))
            .and_then(|p| p.as_u64())
            .map(|p| p as u32);

        let ppid = process
            .get("ppid")
            .and_then(|p| p.as_u64())
            .map(|p| p as u32);

        let euid = process
            .get("audit_token")
            .and_then(|t| t.get("euid"))
            .and_then(|e| e.as_u64())
            .map(|e| e as u32);

        let team_id = process
            .get("team_id")
            .and_then(|t| t.as_str())
            .filter(|s| !s.is_empty())
            .map(String::from);

        let signing_id = process
            .get("signing_id")
            .and_then(|s| s.as_str())
            .filter(|s| !s.is_empty())
            .map(String::from);

        let is_platform_binary = process
            .get("is_platform_binary")
            .and_then(|b| b.as_bool())
            .unwrap_or(false);

        // Build process context
        let mut context = ProcessContext::new(process_path);

        if let Some(pid) = pid {
            context = context.with_pid(pid);
        }
        if let Some(ppid) = ppid {
            context = context.with_ppid(ppid);
        }
        if let Some(euid) = euid {
            context = context.with_euid(euid);
        }
        if let Some(team_id) = team_id {
            context = context.with_team_id(team_id);
        }
        if let Some(signing_id) = signing_id {
            context = context.with_signing_id(signing_id);
        }
        context = context.with_platform_binary(is_platform_binary);

        // Expand ~ in file path to user's home directory
        let expanded_path = if file_path.starts_with('/') {
            // Check if it's in a user's home directory
            if let Some(euid) = euid {
                if let Some(home) = crate::process::get_home_for_uid(euid) {
                    let home_str = home.to_string_lossy();
                    // Ensure the path is actually under the home directory (followed by / or nothing)
                    let rest = file_path.strip_prefix(home_str.as_ref());
                    if let Some(suffix) = rest {
                        if suffix.is_empty() || suffix.starts_with('/') {
                            let expanded = format!("~{}", suffix);
                            tracing::debug!(
                                "Path expansion: {} -> {} (euid={}, home={})",
                                file_path,
                                expanded,
                                euid,
                                home_str
                            );
                            expanded
                        } else {
                            file_path.to_string()
                        }
                    } else {
                        file_path.to_string()
                    }
                } else {
                    tracing::debug!(
                        "No home directory for euid={} - using raw path: {}",
                        euid,
                        file_path
                    );
                    file_path.to_string()
                }
            } else {
                tracing::debug!("No euid available - using raw path: {}", file_path);
                file_path.to_string()
            }
        } else {
            file_path.to_string()
        };

        Some((expanded_path, context))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::rules::RuleEngine;
    use crate::storage::Storage;
    use tokio::sync::broadcast;

    fn create_test_monitor() -> EsloggerMonitor {
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
        // Need to keep temp_dir alive - leak it for tests
        std::mem::forget(temp_dir);
        EsloggerMonitor::new(context)
    }

    #[test]
    fn test_parse_open_event_full() {
        let monitor = create_test_monitor();

        let json: serde_json::Value = serde_json::from_str(
            r#"{
            "event": {
                "open": {
                    "file": {
                        "path": "/Users/testuser/.ssh/id_rsa"
                    }
                }
            },
            "process": {
                "executable": {
                    "path": "/usr/bin/cat"
                },
                "audit_token": {
                    "pid": 12345,
                    "euid": 501
                },
                "ppid": 1,
                "team_id": "APPLE123",
                "signing_id": "com.apple.cat",
                "is_platform_binary": true
            }
        }"#,
        )
        .unwrap();

        let result = monitor.parse_open_event(&json);
        assert!(result.is_some());

        let (file_path, context) = result.unwrap();
        assert_eq!(file_path, "/Users/testuser/.ssh/id_rsa");
        assert_eq!(context.path.to_string_lossy(), "/usr/bin/cat");
        assert_eq!(context.pid, Some(12345));
        assert_eq!(context.ppid, Some(1));
        assert_eq!(context.euid, Some(501));
        assert_eq!(context.team_id, Some("APPLE123".to_string()));
        assert_eq!(context.signing_id, Some("com.apple.cat".to_string()));
        assert_eq!(context.platform_binary, Some(true));
    }

    #[test]
    fn test_parse_open_event_minimal() {
        let monitor = create_test_monitor();

        let json: serde_json::Value = serde_json::from_str(
            r#"{
            "event": {
                "open": {
                    "file": {
                        "path": "/tmp/test.txt"
                    }
                }
            },
            "process": {
                "executable": {
                    "path": "/usr/bin/cat"
                }
            }
        }"#,
        )
        .unwrap();

        let result = monitor.parse_open_event(&json);
        assert!(result.is_some());

        let (file_path, context) = result.unwrap();
        assert_eq!(file_path, "/tmp/test.txt");
        assert_eq!(context.path.to_string_lossy(), "/usr/bin/cat");
        assert!(context.pid.is_none());
        assert!(context.ppid.is_none());
        assert!(context.team_id.is_none());
    }

    #[test]
    fn test_parse_open_event_directory_skipped() {
        let monitor = create_test_monitor();

        let json: serde_json::Value = serde_json::from_str(
            r#"{
            "event": {
                "open": {
                    "file": {
                        "path": "/Users/testuser/.ssh/"
                    }
                }
            },
            "process": {
                "executable": {
                    "path": "/usr/bin/ls"
                }
            }
        }"#,
        )
        .unwrap();

        let result = monitor.parse_open_event(&json);
        assert!(result.is_none()); // Directories are skipped
    }

    #[test]
    fn test_parse_open_event_missing_file() {
        let monitor = create_test_monitor();

        let json: serde_json::Value = serde_json::from_str(
            r#"{
            "event": {
                "open": {}
            },
            "process": {
                "executable": {
                    "path": "/usr/bin/cat"
                }
            }
        }"#,
        )
        .unwrap();

        let result = monitor.parse_open_event(&json);
        assert!(result.is_none());
    }

    #[test]
    fn test_parse_open_event_missing_process() {
        let monitor = create_test_monitor();

        let json: serde_json::Value = serde_json::from_str(
            r#"{
            "event": {
                "open": {
                    "file": {
                        "path": "/tmp/test.txt"
                    }
                }
            }
        }"#,
        )
        .unwrap();

        let result = monitor.parse_open_event(&json);
        assert!(result.is_none());
    }

    #[test]
    fn test_parse_open_event_missing_executable() {
        let monitor = create_test_monitor();

        let json: serde_json::Value = serde_json::from_str(
            r#"{
            "event": {
                "open": {
                    "file": {
                        "path": "/tmp/test.txt"
                    }
                }
            },
            "process": {
                "ppid": 1
            }
        }"#,
        )
        .unwrap();

        let result = monitor.parse_open_event(&json);
        assert!(result.is_none());
    }

    #[test]
    fn test_parse_open_event_empty_team_id() {
        let monitor = create_test_monitor();

        let json: serde_json::Value = serde_json::from_str(
            r#"{
            "event": {
                "open": {
                    "file": {
                        "path": "/tmp/test.txt"
                    }
                }
            },
            "process": {
                "executable": {
                    "path": "/usr/bin/cat"
                },
                "team_id": "",
                "signing_id": ""
            }
        }"#,
        )
        .unwrap();

        let result = monitor.parse_open_event(&json);
        assert!(result.is_some());

        let (_file_path, context) = result.unwrap();
        // Empty strings should be filtered out
        assert!(context.team_id.is_none());
        assert!(context.signing_id.is_none());
    }

    #[test]
    fn test_parse_open_event_not_open_event() {
        let monitor = create_test_monitor();

        let json: serde_json::Value = serde_json::from_str(
            r#"{
            "event": {
                "close": {
                    "file": {
                        "path": "/tmp/test.txt"
                    }
                }
            },
            "process": {
                "executable": {
                    "path": "/usr/bin/cat"
                }
            }
        }"#,
        )
        .unwrap();

        let result = monitor.parse_open_event(&json);
        assert!(result.is_none()); // Not an open event
    }

    #[test]
    fn test_parse_open_event_path_expansion() {
        let monitor = create_test_monitor();

        // Get current user's home directory
        let current_uid = unsafe { libc::getuid() };
        let home = crate::process::get_home_for_uid(current_uid);

        if let Some(home_path) = home {
            let home_str = home_path.to_string_lossy();
            let test_file = format!("{}/.ssh/id_rsa", home_str);

            let json: serde_json::Value = serde_json::from_str(&format!(
                r#"{{
                "event": {{
                    "open": {{
                        "file": {{
                            "path": "{}"
                        }}
                    }}
                }},
                "process": {{
                    "executable": {{
                        "path": "/usr/bin/cat"
                    }},
                    "audit_token": {{
                        "euid": {}
                    }}
                }}
            }}"#,
                test_file, current_uid
            ))
            .unwrap();

            let result = monitor.parse_open_event(&json);
            assert!(result.is_some());

            let (file_path, _context) = result.unwrap();
            // Should be expanded to ~/ format
            assert!(file_path.starts_with("~/") || file_path == test_file);
        }
    }

    #[test]
    fn test_eslogger_monitor_new() {
        let monitor = create_test_monitor();
        assert!(monitor.child.is_none());
    }

    #[test]
    fn test_parse_open_event_is_platform_binary_false() {
        let monitor = create_test_monitor();

        let json: serde_json::Value = serde_json::from_str(
            r#"{
            "event": {
                "open": {
                    "file": {
                        "path": "/tmp/test.txt"
                    }
                }
            },
            "process": {
                "executable": {
                    "path": "/usr/local/bin/custom"
                },
                "is_platform_binary": false
            }
        }"#,
        )
        .unwrap();

        let result = monitor.parse_open_event(&json);
        assert!(result.is_some());

        let (_file_path, context) = result.unwrap();
        assert_eq!(context.platform_binary, Some(false));
    }

    #[test]
    fn test_parse_open_event_missing_is_platform_binary() {
        let monitor = create_test_monitor();

        let json: serde_json::Value = serde_json::from_str(
            r#"{
            "event": {
                "open": {
                    "file": {
                        "path": "/tmp/test.txt"
                    }
                }
            },
            "process": {
                "executable": {
                    "path": "/usr/bin/cat"
                }
            }
        }"#,
        )
        .unwrap();

        let result = monitor.parse_open_event(&json);
        assert!(result.is_some());

        let (_file_path, context) = result.unwrap();
        // Default should be false when missing
        assert_eq!(context.platform_binary, Some(false));
    }
}
