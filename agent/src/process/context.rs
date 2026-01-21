//! Process context information for system process identification.

use std::path::PathBuf;

/// Context information about a process attempting to access protected files.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessContext {
    /// Full path to the process executable.
    pub path: PathBuf,
    /// Process ID.
    pub pid: Option<u32>,
    /// Parent process ID.
    pub ppid: Option<u32>,
    /// Apple Team ID (secure, assigned by Apple).
    pub team_id: Option<String>,
    /// App ID / Bundle ID (can be set by developer, less secure).
    pub app_id: Option<String>,
    /// Signing ID (code signature identifier).
    pub signing_id: Option<String>,
    /// Command-line arguments.
    pub args: Option<Vec<String>>,
    /// User ID.
    pub uid: Option<u32>,
    /// Effective User ID.
    pub euid: Option<u32>,
    /// Whether this is an Apple platform binary.
    pub platform_binary: Option<bool>,
    /// Current working directory.
    pub cwd: Option<PathBuf>,
}

#[allow(dead_code)]
impl ProcessContext {
    /// Creates a new process context with the specified executable path.
    pub fn new(path: PathBuf) -> Self {
        Self {
            path,
            pid: None,
            ppid: None,
            team_id: None,
            app_id: None,
            signing_id: None,
            args: None,
            uid: None,
            euid: None,
            platform_binary: None,
            cwd: None,
        }
    }

    pub fn with_pid(mut self, pid: u32) -> Self {
        self.pid = Some(pid);
        self
    }

    pub fn with_ppid(mut self, ppid: u32) -> Self {
        self.ppid = Some(ppid);
        self
    }

    pub fn with_team_id(mut self, team_id: impl Into<String>) -> Self {
        self.team_id = Some(team_id.into());
        self
    }

    pub fn with_app_id(mut self, app_id: impl Into<String>) -> Self {
        self.app_id = Some(app_id.into());
        self
    }

    pub fn with_signing_id(mut self, signing_id: impl Into<String>) -> Self {
        self.signing_id = Some(signing_id.into());
        self
    }

    pub fn with_args(mut self, args: Vec<String>) -> Self {
        self.args = Some(args);
        self
    }

    pub fn with_uid(mut self, uid: u32) -> Self {
        self.uid = Some(uid);
        self
    }

    pub fn with_euid(mut self, euid: u32) -> Self {
        self.euid = Some(euid);
        self
    }

    pub fn with_platform_binary(mut self, platform_binary: bool) -> Self {
        self.platform_binary = Some(platform_binary);
        self
    }

    pub fn with_cwd(mut self, cwd: PathBuf) -> Self {
        self.cwd = Some(cwd);
        self
    }

    /// Returns the process basename.
    pub fn basename(&self) -> &str {
        self.path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("")
    }
}

/// Retrieves the home directory path for a given user ID.
pub fn get_home_for_uid(uid: u32) -> Option<PathBuf> {
    #[cfg(unix)]
    {
        use std::ffi::CStr;
        use std::os::unix::ffi::OsStringExt;

        // SAFETY: getpwuid returns a pointer to a static buffer.
        // We copy the data immediately and don't store the pointer.
        unsafe {
            let pwd = libc::getpwuid(uid);
            if pwd.is_null() {
                return None;
            }

            let home_dir = (*pwd).pw_dir;
            if home_dir.is_null() {
                return None;
            }

            let home_cstr = CStr::from_ptr(home_dir);
            let home_bytes = home_cstr.to_bytes();
            let home_osstring = std::ffi::OsString::from_vec(home_bytes.to_vec());
            Some(PathBuf::from(home_osstring))
        }
    }

    #[cfg(not(unix))]
    {
        let _ = uid;
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_process_context_builder() {
        let ctx = ProcessContext::new(PathBuf::from("/usr/bin/ssh"))
            .with_pid(1234)
            .with_ppid(1)
            .with_uid(501)
            .with_euid(501)
            .with_team_id("ABCD1234")
            .with_cwd(PathBuf::from("/home/user"));

        assert_eq!(ctx.path, PathBuf::from("/usr/bin/ssh"));
        assert_eq!(ctx.pid, Some(1234));
        assert_eq!(ctx.ppid, Some(1));
        assert_eq!(ctx.uid, Some(501));
        assert_eq!(ctx.euid, Some(501));
        assert_eq!(ctx.team_id, Some("ABCD1234".to_string()));
        assert_eq!(ctx.cwd, Some(PathBuf::from("/home/user")));
    }

    #[test]
    fn test_basename() {
        let ctx = ProcessContext::new(PathBuf::from("/usr/bin/ssh"));
        assert_eq!(ctx.basename(), "ssh");

        let ctx2 = ProcessContext::new(PathBuf::from("/Applications/Firefox.app/Contents/MacOS/firefox"));
        assert_eq!(ctx2.basename(), "firefox");
    }

    #[test]
    fn test_process_context_new_minimal() {
        let ctx = ProcessContext::new(PathBuf::from("/bin/cat"));
        assert_eq!(ctx.path, PathBuf::from("/bin/cat"));
        assert!(ctx.pid.is_none());
        assert!(ctx.ppid.is_none());
        assert!(ctx.team_id.is_none());
        assert!(ctx.app_id.is_none());
        assert!(ctx.signing_id.is_none());
        assert!(ctx.args.is_none());
        assert!(ctx.uid.is_none());
        assert!(ctx.euid.is_none());
        assert!(ctx.platform_binary.is_none());
        assert!(ctx.cwd.is_none());
    }

    #[test]
    fn test_process_context_with_app_id() {
        let ctx = ProcessContext::new(PathBuf::from("/usr/bin/ssh"))
            .with_app_id("com.apple.ssh");
        assert_eq!(ctx.app_id, Some("com.apple.ssh".to_string()));
    }

    #[test]
    fn test_process_context_with_signing_id() {
        let ctx = ProcessContext::new(PathBuf::from("/usr/bin/ssh"))
            .with_signing_id("com.apple.ssh");
        assert_eq!(ctx.signing_id, Some("com.apple.ssh".to_string()));
    }

    #[test]
    fn test_process_context_with_args() {
        let ctx = ProcessContext::new(PathBuf::from("/usr/bin/ssh"))
            .with_args(vec!["-l".to_string(), "user".to_string(), "host".to_string()]);
        assert_eq!(ctx.args, Some(vec!["-l".to_string(), "user".to_string(), "host".to_string()]));
    }

    #[test]
    fn test_process_context_with_platform_binary() {
        let ctx = ProcessContext::new(PathBuf::from("/usr/bin/ssh"))
            .with_platform_binary(true);
        assert_eq!(ctx.platform_binary, Some(true));

        let ctx2 = ProcessContext::new(PathBuf::from("/usr/local/bin/custom"))
            .with_platform_binary(false);
        assert_eq!(ctx2.platform_binary, Some(false));
    }

    #[test]
    fn test_process_context_full_builder() {
        let ctx = ProcessContext::new(PathBuf::from("/Applications/Terminal.app/Contents/MacOS/Terminal"))
            .with_pid(12345)
            .with_ppid(1)
            .with_team_id("APPLE")
            .with_app_id("com.apple.Terminal")
            .with_signing_id("com.apple.Terminal")
            .with_args(vec!["Terminal".to_string()])
            .with_uid(501)
            .with_euid(501)
            .with_platform_binary(true)
            .with_cwd(PathBuf::from("/Users/testuser"));

        assert_eq!(ctx.pid, Some(12345));
        assert_eq!(ctx.ppid, Some(1));
        assert_eq!(ctx.team_id, Some("APPLE".to_string()));
        assert_eq!(ctx.app_id, Some("com.apple.Terminal".to_string()));
        assert_eq!(ctx.signing_id, Some("com.apple.Terminal".to_string()));
        assert_eq!(ctx.args, Some(vec!["Terminal".to_string()]));
        assert_eq!(ctx.uid, Some(501));
        assert_eq!(ctx.euid, Some(501));
        assert_eq!(ctx.platform_binary, Some(true));
        assert_eq!(ctx.cwd, Some(PathBuf::from("/Users/testuser")));
        assert_eq!(ctx.basename(), "Terminal");
    }

    #[test]
    fn test_basename_empty_path() {
        let ctx = ProcessContext::new(PathBuf::from(""));
        assert_eq!(ctx.basename(), "");
    }

    #[test]
    fn test_basename_just_filename() {
        let ctx = ProcessContext::new(PathBuf::from("myprogram"));
        assert_eq!(ctx.basename(), "myprogram");
    }

    #[test]
    fn test_process_context_equality() {
        let ctx1 = ProcessContext::new(PathBuf::from("/usr/bin/ssh"))
            .with_pid(1234)
            .with_team_id("TEAM1");

        let ctx2 = ProcessContext::new(PathBuf::from("/usr/bin/ssh"))
            .with_pid(1234)
            .with_team_id("TEAM1");

        assert_eq!(ctx1, ctx2);
    }

    #[test]
    fn test_process_context_inequality() {
        let ctx1 = ProcessContext::new(PathBuf::from("/usr/bin/ssh"))
            .with_pid(1234);

        let ctx2 = ProcessContext::new(PathBuf::from("/usr/bin/ssh"))
            .with_pid(5678);

        assert_ne!(ctx1, ctx2);
    }

    #[test]
    fn test_get_home_for_uid_current_user() {
        // Get current uid
        #[cfg(unix)]
        {
            let uid = unsafe { libc::getuid() };
            let home = get_home_for_uid(uid);
            assert!(home.is_some());
            let home = home.unwrap();
            assert!(home.is_absolute());
            assert!(home.exists());
        }
    }

    #[test]
    fn test_get_home_for_uid_root() {
        #[cfg(unix)]
        {
            let home = get_home_for_uid(0);
            // Root should have a home directory (typically /root or /var/root)
            assert!(home.is_some());
        }
    }

    #[test]
    fn test_get_home_for_uid_nonexistent() {
        #[cfg(unix)]
        {
            // Very high UID that likely doesn't exist
            let home = get_home_for_uid(99999);
            // Should return None for non-existent user
            assert!(home.is_none());
        }
    }
}
