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

        let fd = unsafe { libc::fanotify_init(flags, libc::O_RDONLY as u32 | libc::O_LARGEFILE as u32) };

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
            tracing::warn!("Failed to add fanotify watch on {}: {}", path.display(), err);
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

        tracing::info!("Setting up fanotify watches on {} directories", watch_dirs.len());

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

    async fn process_event(
        &self,
        event: &FanEventMetadata,
        blocking: bool,
    ) -> Option<(bool, i32)> {
        // Get the file path from the fd
        let file_path = Self::read_link_for_fd(event.fd)?;

        // Get process info
        let context = Self::get_process_info(event.pid)?;

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

        // Process the access
        if let Some(violation) = self
            .context
            .process_access(&normalized_path, &context)
            .await
        {
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

        loop {
            // Read events (blocking read)
            let bytes_read = unsafe {
                libc::read(raw_fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len())
            };

            if bytes_read < 0 {
                let err = std::io::Error::last_os_error();
                if err.kind() == std::io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(Error::Io(err));
            }

            if bytes_read == 0 {
                continue;
            }

            // Process events
            let mut offset = 0;
            while offset < bytes_read as usize {
                if offset + FAN_EVENT_METADATA_LEN > bytes_read as usize {
                    break;
                }

                let event = unsafe {
                    &*(buf.as_ptr().add(offset) as *const FanEventMetadata)
                };

                // Validate event
                if event.vers != 3 {
                    tracing::warn!("Unexpected fanotify version: {}", event.vers);
                    break;
                }

                if event.fd >= 0 {
                    // Process the event
                    if let Some((allow, fd)) = self.process_event(event, blocking).await {
                        if blocking && (event.mask & (FAN_OPEN_PERM | FAN_ACCESS_PERM)) != 0 {
                            // Send response for permission event
                            let response = FanResponse {
                                fd,
                                response: if allow { FAN_ALLOW } else { FAN_DENY },
                            };

                            unsafe {
                                libc::write(
                                    raw_fd,
                                    &response as *const _ as *const libc::c_void,
                                    std::mem::size_of::<FanResponse>(),
                                );
                            }
                        }

                        // Close the event fd
                        unsafe { libc::close(fd) };
                    } else if event.fd >= 0 {
                        // Close fd for events we don't process
                        unsafe { libc::close(event.fd) };
                    }
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
