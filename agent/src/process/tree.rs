//! Process tree building for EDR-style violation display.

use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::path::PathBuf;

// Absolute paths for subprocess calls - prevents PATH manipulation attacks
#[cfg(target_os = "macos")]
mod paths {
    pub const PS: &str = "/bin/ps";
    pub const LSOF: &str = "/usr/sbin/lsof";
    pub const CODESIGN: &str = "/usr/bin/codesign";
}

#[cfg(target_os = "freebsd")]
mod paths {
    pub const PS: &str = "/bin/ps";
    pub const PROCSTAT: &str = "/usr/bin/procstat";
}

/// A single entry in a process tree, containing all information needed for
/// security investigation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessTreeEntry {
    pub pid: u32,
    pub ppid: Option<u32>,
    pub name: String,
    pub path: String,
    pub cwd: Option<String>,
    pub cmdline: Option<String>,
    pub uid: Option<u32>,
    pub euid: Option<u32>,
    pub team_id: Option<String>,
    pub signing_id: Option<String>,
    pub is_platform_binary: bool,
    /// Whether this process is currently stopped (SIGSTOP).
    #[serde(default)]
    pub is_stopped: bool,
}

/// Build complete process tree from PID up to init (PID 1).
#[must_use]
pub fn build_process_tree(pid: u32) -> Vec<ProcessTreeEntry> {
    let mut tree = Vec::new();
    let mut current_pid = pid;
    let mut visited = HashSet::new();

    while current_pid > 0 && !visited.contains(&current_pid) {
        visited.insert(current_pid);

        if let Some(entry) = get_process_info(current_pid) {
            let ppid = entry.ppid;
            tree.push(entry);

            if current_pid == 1 || ppid.is_none() || ppid == Some(0) {
                break;
            }
            current_pid = ppid.unwrap_or(0);
        } else {
            tracing::debug!(
                "Failed to get process info for PID {} - process may have exited",
                current_pid
            );
            break;
        }
    }

    tree
}

#[cfg(target_os = "macos")]
fn get_process_info(pid: u32) -> Option<ProcessTreeEntry> {
    use std::process::Command;

    // Get process info using ps
    let output = Command::new(paths::PS)
        .args(["-p", &pid.to_string(), "-o", "ppid=,uid=,comm=,args="])
        .output()
        .ok()?;

    if !output.status.success() {
        return None;
    }

    let info = String::from_utf8_lossy(&output.stdout);
    let info = info.trim();
    if info.is_empty() {
        return None;
    }

    // Parse: "ppid uid comm args..."
    let mut parts = info.split_whitespace();
    let ppid: Option<u32> = parts.next().and_then(|s| s.parse().ok());
    let uid: Option<u32> = parts.next().and_then(|s| s.parse().ok());
    let name = parts.next().unwrap_or("").to_string();
    let cmdline: Option<String> = {
        let rest: Vec<&str> = parts.collect();
        if rest.is_empty() {
            None
        } else {
            Some(rest.join(" "))
        }
    };

    // Get full path
    let path = get_process_path_macos(pid).unwrap_or_else(|| PathBuf::from(&name));

    // Derive name from full path (not truncated comm which is limited to 16 chars)
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or(name);

    // Get signing info
    let (team_id, signing_id, is_platform) = get_signing_info_macos(&path);

    // Get CWD
    let cwd = get_cwd_macos(pid);

    // Check if process is stopped
    let is_stopped = is_process_stopped(pid);

    Some(ProcessTreeEntry {
        pid,
        ppid,
        name,
        path: path.to_string_lossy().to_string(),
        cwd,
        cmdline,
        uid,
        euid: uid, // On macOS, getting EUID requires more work
        team_id,
        signing_id,
        is_platform_binary: is_platform,
        is_stopped,
    })
}

/// Check if a process is stopped (SIGSTOP) by querying its state.
#[cfg(target_os = "macos")]
pub fn is_process_stopped(pid: u32) -> bool {
    use std::process::Command;

    // Use ps to get process state
    let output = Command::new(paths::PS)
        .args(["-p", &pid.to_string(), "-o", "state="])
        .output()
        .ok();

    if let Some(output) = output {
        if output.status.success() {
            let state = String::from_utf8_lossy(&output.stdout);
            // 'T' indicates stopped process (SIGSTOP)
            return state.trim().starts_with('T');
        }
    }
    false
}

/// Check if a process is stopped (SIGSTOP) by reading /proc/PID/stat.
#[cfg(target_os = "linux")]
pub fn is_process_stopped(pid: u32) -> bool {
    std::fs::read_to_string(format!("/proc/{}/stat", pid))
        .ok()
        .map(|stat| {
            // Format: pid (comm) state ...
            // State T = stopped
            stat.split(')')
                .nth(1)
                .map(|s| s.trim().starts_with('T'))
                .unwrap_or(false)
        })
        .unwrap_or(false)
}

/// Check if a process is stopped on FreeBSD.
#[cfg(target_os = "freebsd")]
pub fn is_process_stopped(pid: u32) -> bool {
    use std::process::Command;

    Command::new(paths::PS)
        .args(["-p", &pid.to_string(), "-o", "state="])
        .output()
        .ok()
        .map(|o| {
            if o.status.success() {
                String::from_utf8_lossy(&o.stdout).trim().starts_with('T')
            } else {
                false
            }
        })
        .unwrap_or(false)
}

/// Fallback for unsupported platforms.
#[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "freebsd")))]
pub fn is_process_stopped(_pid: u32) -> bool {
    false
}

#[cfg(target_os = "macos")]
fn get_process_path_macos(pid: u32) -> Option<PathBuf> {
    use std::ffi::OsString;
    use std::os::unix::ffi::OsStringExt;

    // Use proc_pidpath
    let mut buf = vec![0u8; libc::MAXPATHLEN as usize];
    let ret = unsafe {
        libc::proc_pidpath(
            pid as i32,
            buf.as_mut_ptr() as *mut libc::c_void,
            buf.len() as u32,
        )
    };

    if ret > 0 {
        buf.truncate(ret as usize);
        Some(PathBuf::from(OsString::from_vec(buf)))
    } else {
        None
    }
}

#[cfg(target_os = "macos")]
fn get_cwd_macos(pid: u32) -> Option<String> {
    use std::process::Command;

    // Use lsof to get CWD
    let output = Command::new(paths::LSOF)
        .args(["-p", &pid.to_string(), "-d", "cwd", "-Fn"])
        .output()
        .ok()?;

    if !output.status.success() {
        return None;
    }

    let output_str = String::from_utf8_lossy(&output.stdout);
    for line in output_str.lines() {
        if let Some(path) = line.strip_prefix('n') {
            return Some(path.to_string());
        }
    }

    None
}

#[cfg(target_os = "macos")]
fn get_signing_info_macos(path: &std::path::Path) -> (Option<String>, Option<String>, bool) {
    use std::process::Command;

    let output = Command::new(paths::CODESIGN)
        .args(["-dvvv", "--", path.to_string_lossy().as_ref()])
        .output();

    let output = match output {
        Ok(o) => o,
        Err(_) => return (None, None, false),
    };

    // codesign outputs to stderr
    let info = String::from_utf8_lossy(&output.stderr);

    let mut team_id = None;
    let mut signing_id = None;
    let mut is_platform = false;

    for line in info.lines() {
        if let Some(tid) = line.strip_prefix("TeamIdentifier=") {
            let tid = tid.trim();
            if tid != "not set" {
                team_id = Some(tid.to_string());
            }
        } else if let Some(sid) = line.strip_prefix("Identifier=") {
            signing_id = Some(sid.trim().to_string());
        } else if line.contains("flags=") && line.contains("platform") {
            is_platform = true;
        }
    }

    (team_id, signing_id, is_platform)
}

#[cfg(target_os = "linux")]
fn get_process_info(pid: u32) -> Option<ProcessTreeEntry> {
    let proc_path = format!("/proc/{}", pid);

    // Read status for ppid and uid
    let status = std::fs::read_to_string(format!("{}/status", proc_path)).ok()?;

    let mut ppid: Option<u32> = None;
    let mut uid: Option<u32> = None;
    let mut euid: Option<u32> = None;

    for line in status.lines() {
        if let Some(val) = line.strip_prefix("PPid:") {
            ppid = val.trim().parse().ok();
        } else if let Some(val) = line.strip_prefix("Uid:") {
            // Format: real effective saved fs
            let parts: Vec<&str> = val.split_whitespace().collect();
            uid = parts.first().and_then(|s| s.parse().ok());
            euid = parts.get(1).and_then(|s| s.parse().ok());
        }
    }

    // Read exe symlink for path
    let path = std::fs::read_link(format!("{}/exe", proc_path))
        .ok()
        .unwrap_or_default();

    // Read comm for name
    let name = std::fs::read_to_string(format!("{}/comm", proc_path))
        .ok()
        .map(|s| s.trim().to_string())
        .unwrap_or_default();

    // Read cmdline
    let cmdline = std::fs::read_to_string(format!("{}/cmdline", proc_path))
        .ok()
        .map(|s| s.replace('\0', " ").trim().to_string())
        .filter(|s| !s.is_empty());

    // Read cwd
    let cwd = std::fs::read_link(format!("{}/cwd", proc_path))
        .ok()
        .map(|p| p.to_string_lossy().to_string());

    // Check if process is stopped by looking at /proc/{pid}/stat
    let is_stopped = std::fs::read_to_string(format!("{}/stat", proc_path))
        .ok()
        .map(|stat| {
            // Format: pid (comm) state ...
            // State T = stopped
            stat.split(')')
                .nth(1)
                .map(|s| s.trim().starts_with('T'))
                .unwrap_or(false)
        })
        .unwrap_or(false);

    Some(ProcessTreeEntry {
        pid,
        ppid,
        name,
        path: path.to_string_lossy().to_string(),
        cwd,
        cmdline,
        uid,
        euid,
        team_id: None,
        signing_id: None,
        is_platform_binary: false,
        is_stopped,
    })
}

#[cfg(target_os = "freebsd")]
fn get_process_info(pid: u32) -> Option<ProcessTreeEntry> {
    use std::process::Command;

    // Use procstat -b to get binary path (single call, reuse output)
    let procstat_b_output = Command::new(paths::PROCSTAT)
        .args(["-b", &pid.to_string()])
        .output()
        .ok()?;

    if !procstat_b_output.status.success() {
        return None;
    }

    let procstat_b_str = String::from_utf8_lossy(&procstat_b_output.stdout);
    let lines: Vec<&str> = procstat_b_str.lines().collect();

    // Skip header, parse first data line
    if lines.len() < 2 {
        return None;
    }

    // procstat -b format: "  PID  COMM             PATH"
    // The path may contain spaces, so we need to parse carefully
    let data_line = lines[1].trim();

    // Split into at most 3 parts: PID, COMM, PATH
    // PID is numeric, COMM is the next word, PATH is everything after
    let mut parts_iter = data_line.split_whitespace();
    let _pid_str = parts_iter.next()?;
    let comm = parts_iter.next()?;

    // The path is the rest of the line after COMM
    // Find where COMM ends in the original line and take everything after
    let comm_end = data_line.find(comm)? + comm.len();
    let path_str = data_line[comm_end..].trim();
    let path = if path_str.is_empty() {
        PathBuf::from(comm)
    } else {
        PathBuf::from(path_str)
    };

    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| comm.to_string());

    // Get more info from ps - use ww for wide output to get full cmdline
    let ps_output = Command::new(paths::PS)
        .args(["-ww", "-p", &pid.to_string(), "-o", "ppid=,uid=,args="])
        .output()
        .ok()?;

    let ps_info = String::from_utf8_lossy(&ps_output.stdout);
    let ps_trimmed = ps_info.trim();

    // Parse: "PPID UID ARGS..."
    // PPID and UID are numeric, ARGS is everything else (may contain spaces)
    let mut ps_parts = ps_trimmed.splitn(3, char::is_whitespace);
    let ppid: Option<u32> = ps_parts.next().and_then(|s| s.trim().parse().ok());
    let uid: Option<u32> = ps_parts.next().and_then(|s| s.trim().parse().ok());
    let cmdline: Option<String> = ps_parts
        .next()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());

    // Get CWD using procstat -f
    let cwd = Command::new(paths::PROCSTAT)
        .args(["-f", &pid.to_string()])
        .output()
        .ok()
        .and_then(|o| {
            if !o.status.success() {
                return None;
            }
            let output_str = String::from_utf8_lossy(&o.stdout);
            for line in output_str.lines() {
                // Format: "PID COMM FD T V FLAGS REF OFFSET PRO NAME"
                // cwd line has " cwd " in the FD column area
                if line.contains(" cwd ") {
                    // The path is everything after the last whitespace-separated fields
                    // Look for the path which starts with /
                    if let Some(slash_pos) = line.rfind(" /") {
                        return Some(line[slash_pos + 1..].trim().to_string());
                    }
                }
            }
            None
        });

    // Check if process is stopped using ps
    let is_stopped = Command::new(paths::PS)
        .args(["-p", &pid.to_string(), "-o", "state="])
        .output()
        .ok()
        .map(|o| {
            if o.status.success() {
                String::from_utf8_lossy(&o.stdout).trim().starts_with('T')
            } else {
                false
            }
        })
        .unwrap_or(false);

    Some(ProcessTreeEntry {
        pid,
        ppid,
        name,
        path: path.to_string_lossy().to_string(),
        cwd,
        cmdline,
        uid,
        euid: uid,
        team_id: None,
        signing_id: None,
        is_platform_binary: false,
        is_stopped,
    })
}

#[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "freebsd")))]
fn get_process_info(_pid: u32) -> Option<ProcessTreeEntry> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_process_tree_current() {
        let pid = std::process::id();
        let tree = build_process_tree(pid);

        // Should have at least our own process
        assert!(!tree.is_empty());
        assert_eq!(tree[0].pid, pid);

        // Should end at init (pid 1)
        let last = tree.last().unwrap();
        assert!(last.pid == 1 || last.ppid == Some(0) || last.ppid.is_none());
    }

    #[test]
    fn test_process_tree_entry_serialize() {
        let entry = ProcessTreeEntry {
            pid: 1234,
            ppid: Some(1),
            name: "test".to_string(),
            path: "/usr/bin/test".to_string(),
            cwd: Some("/home/user".to_string()),
            cmdline: Some("test --arg".to_string()),
            uid: Some(501),
            euid: Some(501),
            team_id: Some("TEAM123".to_string()),
            signing_id: Some("com.example.test".to_string()),
            is_platform_binary: false,
            is_stopped: true,
        };

        let json = serde_json::to_string(&entry).unwrap();
        assert!(json.contains("\"is_stopped\":true"));
        assert!(json.contains("\"pid\":1234"));
        assert!(json.contains("\"team_id\":\"TEAM123\""));
    }

    #[test]
    fn test_process_tree_entry_deserialize() {
        let json = r#"{
            "pid": 5678,
            "ppid": 1,
            "name": "cat",
            "path": "/bin/cat",
            "cwd": "/tmp",
            "cmdline": "cat file.txt",
            "uid": 0,
            "euid": 0,
            "team_id": null,
            "signing_id": "com.apple.cat",
            "is_platform_binary": true,
            "is_stopped": false
        }"#;

        let entry: ProcessTreeEntry = serde_json::from_str(json).unwrap();
        assert_eq!(entry.pid, 5678);
        assert_eq!(entry.ppid, Some(1));
        assert!(entry.is_platform_binary);
        assert!(!entry.is_stopped);
    }

    #[test]
    fn test_process_tree_entry_deserialize_defaults() {
        // Test that is_stopped defaults to false when not present
        let json = r#"{
            "pid": 999,
            "ppid": null,
            "name": "init",
            "path": "/sbin/init",
            "cwd": null,
            "cmdline": null,
            "uid": null,
            "euid": null,
            "team_id": null,
            "signing_id": null,
            "is_platform_binary": false
        }"#;

        let entry: ProcessTreeEntry = serde_json::from_str(json).unwrap();
        assert_eq!(entry.pid, 999);
        assert!(!entry.is_stopped); // defaults to false
    }

    #[test]
    fn test_current_process_not_stopped() {
        let pid = std::process::id();
        let tree = build_process_tree(pid);

        // Our own process should not be stopped
        assert!(!tree[0].is_stopped);
    }
}
