//! Linux fanotify-based file access monitor.
//!
//! Fanotify provides file access notifications at the kernel level.
//! For blocking mode, we use FAN_OPEN_PERM events and respond with allow/deny.

use super::MonitorContext;
use crate::error::{Error, Result};
use crate::process::{get_home_for_uid, ProcessContext};
use std::collections::HashSet;
use std::ffi::CString;
use std::os::unix::io::{AsRawFd, FromRawFd, OwnedFd};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::io::unix::AsyncFd;

// Fanotify constants (not all exposed by nix)
const FAN_CLOEXEC: libc::c_uint = 0x0000_0001;
const FAN_CLASS_CONTENT: libc::c_uint = 0x0000_0004;
const FAN_CLASS_PRE_CONTENT: libc::c_uint = 0x0000_0008;
const FAN_UNLIMITED_QUEUE: libc::c_uint = 0x0000_0010;
const FAN_UNLIMITED_MARKS: libc::c_uint = 0x0000_0020;

const FAN_MARK_ADD: libc::c_uint = 0x0000_0001;
const FAN_MARK_MOUNT: libc::c_uint = 0x0000_0010;

const FAN_OPEN: u64 = 0x0000_0020;
const FAN_OPEN_PERM: u64 = 0x0001_0000;
const FAN_ACCESS_PERM: u64 = 0x0002_0000;

const FAN_ALLOW: u32 = 0x01;
const FAN_DENY: u32 = 0x02;

const FAN_EVENT_METADATA_LEN: usize = std::mem::size_of::<FanEventMetadata>();

#[repr(C)]
struct FanEventMetadata {
    event_len: u32,
    vers: u8,
    reserved: u8,
    metadata_len: u16,
    mask: u64,
    fd: i32,
    pid: i32,
}

#[repr(C)]
struct FanResponse {
    fd: i32,
    response: u32,
}

pub struct FanotifyMonitor {
    context: Arc<MonitorContext>,
    fanotify_fd: Option<OwnedFd>,
    watched_paths: HashSet<PathBuf>,
}

impl FanotifyMonitor {
    pub fn new(context: Arc<MonitorContext>) -> Self {
        Self {
            context,
            fanotify_fd: None,
            watched_paths: HashSet::new(),
        }
    }

    fn init_fanotify(&mut self, blocking: bool) -> Result<()> {
        // Choose class based on whether we need blocking
        let class = if blocking {
            FAN_CLASS_PRE_CONTENT // Required for permission events
        } else {
            FAN_CLASS_CONTENT
        };

        let flags = FAN_CLOEXEC | class | FAN_UNLIMITED_QUEUE | FAN_UNLIMITED_MARKS;

        // Use O_NONBLOCK for async-friendly I/O
        let fd = unsafe {
            libc::fanotify_init(
                flags,
                libc::O_RDONLY as u32 | libc::O_LARGEFILE as u32 | libc::O_NONBLOCK as u32,
            )
        };

        if fd < 0 {
            let err = std::io::Error::last_os_error();
            return Err(Error::monitor(format!(
                "fanotify_init failed: {}. Ensure you have CAP_SYS_ADMIN capability.",
                err
            )));
        }

        self.fanotify_fd = Some(unsafe { OwnedFd::from_raw_fd(fd) });
        Ok(())
    }

    fn add_watch(&mut self, path: &PathBuf, blocking: bool) -> Result<()> {
        let fd = self
            .fanotify_fd
            .as_ref()
            .ok_or_else(|| Error::monitor("fanotify not initialized"))?;

        // Choose event mask based on blocking mode
        let mask = if blocking {
            FAN_OPEN_PERM | FAN_ACCESS_PERM
        } else {
            FAN_OPEN
        };

        let path_cstr = CString::new(path.to_string_lossy().as_bytes())
            .map_err(|_| Error::monitor("Invalid path"))?;

        let ret = unsafe {
            libc::fanotify_mark(
                fd.as_raw_fd(),
                FAN_MARK_ADD | FAN_MARK_MOUNT,
                mask,
                libc::AT_FDCWD,
                path_cstr.as_ptr(),
            )
        };

        if ret < 0 {
            let err = std::io::Error::last_os_error();
            tracing::warn!(
                "Failed to add fanotify watch on {}: {}",
                path.display(),
                err
            );
        } else {
            self.watched_paths.insert(path.clone());
            tracing::debug!("Added fanotify watch on {}", path.display());
        }

        Ok(())
    }

    fn setup_watches(&mut self, blocking: bool) -> Result<()> {
        // Collect unique parent directories from protected file patterns
        let mut watch_dirs: HashSet<PathBuf> = HashSet::new();

        // Always watch common directories
        watch_dirs.insert(PathBuf::from("/home"));
        watch_dirs.insert(PathBuf::from("/root"));
        watch_dirs.insert(PathBuf::from("/etc"));

        // Extract directories from protected file patterns
        for pf in &self.context.config.protected_files {
            for pattern in &pf.patterns {
                // Expand ~ to /home (we'll watch /home which covers all users)
                let path = if pattern.starts_with("~/") {
                    // Already covered by /home
                    continue;
                } else if pattern.starts_with('/') {
                    // Extract the first few path components
                    let path = PathBuf::from(pattern.split('*').next().unwrap_or(pattern));
                    // Get parent directory for file patterns
                    path.parent().map(|p| p.to_path_buf())
                } else {
                    None
                };

                if let Some(dir) = path {
                    // Only add if it's a real directory prefix (not too deep)
                    let components: Vec<_> = dir.components().collect();
                    if components.len() >= 2 && components.len() <= 4 {
                        watch_dirs.insert(dir);
                    }
                }
            }
        }

        tracing::info!(
            "Setting up fanotify watches on {} directories",
            watch_dirs.len()
        );

        for dir in watch_dirs {
            if dir.exists() {
                self.add_watch(&dir, blocking)?;
            } else {
                tracing::debug!("Watch directory does not exist: {}", dir.display());
            }
        }

        Ok(())
    }

    fn read_link_for_fd(fd: i32) -> Option<PathBuf> {
        let link_path = format!("/proc/self/fd/{}", fd);
        std::fs::read_link(&link_path).ok()
    }

    fn get_process_info(pid: i32) -> Option<ProcessContext> {
        let pid = pid as u32;
        let proc_path = format!("/proc/{}", pid);

        // Read exe path
        let exe_path = std::fs::read_link(format!("{}/exe", proc_path)).ok()?;

        // Read status for ppid and uid
        let status = std::fs::read_to_string(format!("{}/status", proc_path)).ok()?;
        let mut ppid: Option<u32> = None;
        let mut uid: Option<u32> = None;
        let mut euid: Option<u32> = None;

        for line in status.lines() {
            if let Some(val) = line.strip_prefix("PPid:") {
                ppid = val.trim().parse().ok();
            } else if let Some(val) = line.strip_prefix("Uid:") {
                let parts: Vec<&str> = val.split_whitespace().collect();
                uid = parts.first().and_then(|s| s.parse().ok());
                euid = parts.get(1).and_then(|s| s.parse().ok());
            }
        }

        // Read cmdline
        let cmdline = std::fs::read_to_string(format!("{}/cmdline", proc_path))
            .ok()
            .map(|s| {
                s.split('\0')
                    .filter(|s| !s.is_empty())
                    .map(String::from)
                    .collect::<Vec<_>>()
            });

        let mut ctx = ProcessContext::new(exe_path).with_pid(pid);

        if let Some(ppid) = ppid {
            ctx = ctx.with_ppid(ppid);
        }
        if let Some(uid) = uid {
            ctx = ctx.with_uid(uid);
        }
        if let Some(euid) = euid {
            ctx = ctx.with_euid(euid);
        }
        if let Some(args) = cmdline {
            ctx = ctx.with_args(args);
        }

        Some(ctx)
    }

    fn expand_path_to_tilde(path: &PathBuf, uid: Option<u32>) -> String {
        let path_str = path.to_string_lossy();

        if let Some(uid) = uid {
            if let Some(home) = get_home_for_uid(uid) {
                let home_str = home.to_string_lossy();
                if path_str.starts_with(home_str.as_ref()) {
                    return format!("~{}", &path_str[home_str.len()..]);
                }
            }
        }

        path_str.to_string()
    }

    /// Process a fanotify event. Returns (allow, fd) for permission events.
    /// For blocking mode, ALWAYS returns Some to ensure we send a response.
    async fn process_event(&self, event: &FanEventMetadata, blocking: bool) -> Option<(bool, i32)> {
        // Get the file path from the fd
        let file_path = match Self::read_link_for_fd(event.fd) {
            Some(p) => p,
            None => {
                // Can't resolve path - allow to avoid blocking unknown access
                return if blocking {
                    Some((true, event.fd))
                } else {
                    None
                };
            }
        };

        // Get process info - if process exited, allow access to avoid hang
        let mut context = match Self::get_process_info(event.pid) {
            Some(c) => c,
            None => {
                tracing::debug!(
                    "Process {} exited before we could inspect it, allowing access to {}",
                    event.pid,
                    file_path.display()
                );
                return if blocking {
                    Some((true, event.fd))
                } else {
                    None
                };
            }
        };

        // Enrich with package information for package-based rule matching.
        // Always verify since package rules require verification by default.
        self.context
            .enrich_with_verified_package_info(&mut context, true);

        // Convert path to ~/ format for matching
        let normalized_path = Self::expand_path_to_tilde(&file_path, context.euid);

        // Check if file is excluded
        if self.context.config.is_excluded(&normalized_path) {
            return if blocking {
                Some((true, event.fd)) // Allow
            } else {
                None
            };
        }

        // Process the access with a timeout to avoid blocking indefinitely
        let process_future = self.context.process_access(&normalized_path, &context);
        let result = tokio::time::timeout(std::time::Duration::from_secs(5), process_future).await;

        match result {
            Ok(Some(violation)) => {
                tracing::warn!(
                    "VIOLATION [{}]: {} accessed {} ({})",
                    violation.id,
                    violation.process_path,
                    violation.file_path,
                    violation.action
                );

                // In blocking mode, deny the access
                if blocking {
                    return Some((false, event.fd)); // Deny
                }
            }
            Ok(None) => {
                // No violation
            }
            Err(_) => {
                // Timeout - allow to avoid blocking the process
                tracing::warn!(
                    "Timeout processing access to {} by pid {}, allowing",
                    normalized_path,
                    event.pid
                );
            }
        }

        if blocking {
            Some((true, event.fd)) // Allow
        } else {
            None
        }
    }
}

#[async_trait::async_trait]
impl super::Monitor for FanotifyMonitor {
    async fn start(&mut self) -> Result<()> {
        tracing::info!("Starting fanotify monitor");
        tracing::info!("Note: fanotify requires CAP_SYS_ADMIN capability");

        // Check if we're in blocking mode
        let blocking = {
            let mode = self.context.mode.read().await;
            mode.as_str() == "block"
        };

        tracing::info!(
            "Mode: {} ({})",
            if blocking { "block" } else { "monitor" },
            if blocking {
                "will deny unauthorized access"
            } else {
                "will only log"
            }
        );

        // Initialize fanotify
        self.init_fanotify(blocking)?;

        // Set up watches
        self.setup_watches(blocking)?;

        let fd = self
            .fanotify_fd
            .as_ref()
            .ok_or_else(|| Error::monitor("fanotify not initialized"))?;

        tracing::info!("Listening for file access events...");

        // Event buffer
        let mut buf = vec![0u8; 4096];
        let raw_fd = fd.as_raw_fd();

        // Wrap in AsyncFd for async-friendly I/O
        let async_fd = AsyncFd::new(raw_fd)
            .map_err(|e| Error::monitor(format!("Failed to create AsyncFd for fanotify: {}", e)))?;

        loop {
            // Wait for the fd to be readable
            let mut guard = async_fd.readable().await.map_err(|e| {
                Error::monitor(format!("Failed to wait for fanotify readability: {}", e))
            })?;

            // Try to read events (non-blocking)
            let bytes_read =
                unsafe { libc::read(raw_fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };

            if bytes_read < 0 {
                let err = std::io::Error::last_os_error();
                if err.kind() == std::io::ErrorKind::WouldBlock {
                    // No data available yet, clear readiness and wait again
                    guard.clear_ready();
                    continue;
                }
                if err.kind() == std::io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(Error::Io(err));
            }

            if bytes_read == 0 {
                guard.clear_ready();
                continue;
            }

            // Process events
            let mut offset = 0;
            while offset < bytes_read as usize {
                if offset + FAN_EVENT_METADATA_LEN > bytes_read as usize {
                    break;
                }

                let event = unsafe { &*(buf.as_ptr().add(offset) as *const FanEventMetadata) };

                // Validate event
                if event.vers != 3 {
                    tracing::warn!("Unexpected fanotify version: {}", event.vers);
                    break;
                }

                if event.fd >= 0 {
                    let is_perm_event =
                        blocking && (event.mask & (FAN_OPEN_PERM | FAN_ACCESS_PERM)) != 0;

                    // Process the event
                    let (allow, fd) = match self.process_event(event, blocking).await {
                        Some((allow, fd)) => (allow, fd),
                        None => {
                            // Non-blocking mode or shouldn't happen - close fd
                            unsafe { libc::close(event.fd) };
                            offset += event.event_len as usize;
                            continue;
                        }
                    };

                    if is_perm_event {
                        // Send response for permission event - MUST succeed or process hangs
                        let response = FanResponse {
                            fd,
                            response: if allow { FAN_ALLOW } else { FAN_DENY },
                        };

                        let written = unsafe {
                            libc::write(
                                raw_fd,
                                &response as *const _ as *const libc::c_void,
                                std::mem::size_of::<FanResponse>(),
                            )
                        };

                        if written < 0 {
                            let err = std::io::Error::last_os_error();
                            tracing::error!(
                                "Failed to send fanotify response for fd {}: {}. Process may hang!",
                                fd,
                                err
                            );
                        } else if (written as usize) != std::mem::size_of::<FanResponse>() {
                            tracing::error!(
                                "Partial fanotify response write: {} of {} bytes. Process may hang!",
                                written,
                                std::mem::size_of::<FanResponse>()
                            );
                        }
                    }

                    // Close the event fd
                    unsafe { libc::close(fd) };
                }

                offset += event.event_len as usize;
            }
        }
    }

    async fn stop(&mut self) -> Result<()> {
        self.fanotify_fd = None;
        self.watched_paths.clear();
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

    fn create_test_monitor() -> FanotifyMonitor {
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
        let context = Arc::new(super::super::MonitorContext::new(
            config,
            rule_engine,
            storage,
            event_tx,
            mode,
            degraded_mode,
            pending_events,
        ));
        // Keep temp_dir alive for the duration of tests
        std::mem::forget(temp_dir);
        FanotifyMonitor::new(context)
    }

    // =========================================================================
    // Struct size tests (critical for kernel ABI compatibility)
    // =========================================================================

    #[test]
    fn test_fan_event_metadata_size() {
        // FanEventMetadata must match kernel's fanotify_event_metadata (24 bytes)
        assert_eq!(
            std::mem::size_of::<FanEventMetadata>(),
            24,
            "FanEventMetadata size must be 24 bytes for kernel ABI"
        );
    }

    #[test]
    fn test_fan_response_size() {
        // FanResponse must match kernel's fanotify_response (8 bytes)
        assert_eq!(
            std::mem::size_of::<FanResponse>(),
            8,
            "FanResponse size must be 8 bytes for kernel ABI"
        );
    }

    // =========================================================================
    // Fanotify constant tests
    // =========================================================================

    #[test]
    fn test_fanotify_constants() {
        // Verify constants match kernel values
        assert_eq!(FAN_ALLOW, 0x01);
        assert_eq!(FAN_DENY, 0x02);
        assert_eq!(FAN_CLOEXEC, 0x0000_0001);
        assert_eq!(FAN_CLASS_CONTENT, 0x0000_0004);
        assert_eq!(FAN_CLASS_PRE_CONTENT, 0x0000_0008);
        assert_eq!(FAN_OPEN_PERM, 0x0001_0000);
        assert_eq!(FAN_ACCESS_PERM, 0x0002_0000);
        assert_eq!(FAN_MARK_ADD, 0x0000_0001);
        assert_eq!(FAN_MARK_MOUNT, 0x0000_0010);
    }

    #[test]
    fn test_fan_event_metadata_len_constant() {
        assert_eq!(FAN_EVENT_METADATA_LEN, 24);
    }

    // =========================================================================
    // Monitor construction tests
    // =========================================================================

    #[test]
    fn test_fanotify_monitor_new() {
        let monitor = create_test_monitor();
        assert!(monitor.fanotify_fd.is_none());
        assert!(monitor.watched_paths.is_empty());
    }

    // =========================================================================
    // Path expansion tests
    // =========================================================================

    #[test]
    fn test_expand_path_to_tilde_matches() {
        // Get current user's home for testing
        let uid = unsafe { libc::getuid() };
        if let Some(home) = get_home_for_uid(uid) {
            let home_str = home.to_string_lossy();
            let test_path = PathBuf::from(format!("{}/.ssh/id_rsa", home_str));

            let result = FanotifyMonitor::expand_path_to_tilde(&test_path, Some(uid));
            assert!(
                result.starts_with("~/"),
                "Expected ~/ prefix, got: {}",
                result
            );
            assert!(result.ends_with(".ssh/id_rsa"));
        }
    }

    #[test]
    fn test_expand_path_to_tilde_no_match() {
        // Path not under any home directory
        let test_path = PathBuf::from("/etc/passwd");
        let result = FanotifyMonitor::expand_path_to_tilde(&test_path, Some(0));
        assert_eq!(result, "/etc/passwd");
    }

    #[test]
    fn test_expand_path_to_tilde_no_uid() {
        let test_path = PathBuf::from("/home/user/.ssh/id_rsa");
        let result = FanotifyMonitor::expand_path_to_tilde(&test_path, None);
        assert_eq!(result, "/home/user/.ssh/id_rsa");
    }

    #[test]
    fn test_expand_path_to_tilde_invalid_uid() {
        // Very high UID unlikely to exist
        let test_path = PathBuf::from("/home/user/.ssh/id_rsa");
        let result = FanotifyMonitor::expand_path_to_tilde(&test_path, Some(99999999));
        assert_eq!(result, "/home/user/.ssh/id_rsa");
    }

    // =========================================================================
    // Process info tests (only run on Linux)
    // =========================================================================

    #[test]
    #[cfg(target_os = "linux")]
    fn test_get_process_info_current() {
        let pid = std::process::id() as i32;
        let result = FanotifyMonitor::get_process_info(pid);
        assert!(result.is_some(), "Should get info for current process");

        let ctx = result.unwrap();
        assert_eq!(ctx.pid, Some(pid as u32));
        assert!(ctx.ppid.is_some());
        assert!(ctx.uid.is_some());
        assert!(ctx.euid.is_some());
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn test_get_process_info_invalid_pid() {
        // PID that almost certainly doesn't exist
        let result = FanotifyMonitor::get_process_info(999999999);
        assert!(result.is_none());
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn test_get_process_info_extracts_exe_path() {
        let pid = std::process::id() as i32;
        let result = FanotifyMonitor::get_process_info(pid);
        assert!(result.is_some());

        let ctx = result.unwrap();
        // exe_path should be the test binary
        let exe_str = ctx.exe_path.to_string_lossy();
        assert!(
            exe_str.contains("secretkeeper") || exe_str.contains("cargo"),
            "Expected test binary path, got: {}",
            exe_str
        );
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn test_get_process_info_extracts_cmdline() {
        let pid = std::process::id() as i32;
        let result = FanotifyMonitor::get_process_info(pid);
        assert!(result.is_some());

        let ctx = result.unwrap();
        // Should have args (at least the binary name)
        assert!(ctx.args.is_some(), "Should have command line args");
    }

    // =========================================================================
    // FD path resolution tests
    // =========================================================================

    #[test]
    fn test_read_link_for_fd_stdin() {
        // fd 0 (stdin) should resolve to something
        let result = FanotifyMonitor::read_link_for_fd(0);
        // May or may not succeed depending on how tests are run
        // Just verify it doesn't panic
        let _ = result;
    }

    #[test]
    fn test_read_link_for_fd_invalid() {
        // Negative fd should fail
        let result = FanotifyMonitor::read_link_for_fd(-1);
        assert!(result.is_none());
    }

    #[test]
    fn test_read_link_for_fd_nonexistent() {
        // Very high fd unlikely to be open
        let result = FanotifyMonitor::read_link_for_fd(99999);
        assert!(result.is_none());
    }

    // =========================================================================
    // Integration tests (require CAP_SYS_ADMIN, marked #[ignore])
    // =========================================================================

    #[test]
    #[ignore = "requires CAP_SYS_ADMIN capability"]
    #[cfg(target_os = "linux")]
    fn test_fanotify_init_blocking() {
        let mut monitor = create_test_monitor();
        let result = monitor.init_fanotify(true);
        assert!(
            result.is_ok(),
            "fanotify_init should succeed with CAP_SYS_ADMIN"
        );
        assert!(monitor.fanotify_fd.is_some());
    }

    #[test]
    #[ignore = "requires CAP_SYS_ADMIN capability"]
    #[cfg(target_os = "linux")]
    fn test_fanotify_init_notify() {
        let mut monitor = create_test_monitor();
        let result = monitor.init_fanotify(false);
        assert!(
            result.is_ok(),
            "fanotify_init should succeed with CAP_SYS_ADMIN"
        );
        assert!(monitor.fanotify_fd.is_some());
    }

    #[test]
    #[ignore = "requires CAP_SYS_ADMIN capability"]
    #[cfg(target_os = "linux")]
    fn test_fanotify_add_watch() {
        let mut monitor = create_test_monitor();
        monitor.init_fanotify(true).unwrap();

        let temp_dir = tempfile::TempDir::new().unwrap();
        let result = monitor.add_watch(&temp_dir.path().to_path_buf(), true);
        assert!(result.is_ok());
        assert!(monitor.watched_paths.contains(temp_dir.path()));
    }

    #[test]
    #[ignore = "requires CAP_SYS_ADMIN capability"]
    #[cfg(target_os = "linux")]
    fn test_fanotify_setup_watches() {
        let mut monitor = create_test_monitor();
        monitor.init_fanotify(true).unwrap();

        let result = monitor.setup_watches(true);
        assert!(result.is_ok());
        // Should have added watches for /home, /root, /etc (if they exist)
        assert!(!monitor.watched_paths.is_empty());
    }
}
