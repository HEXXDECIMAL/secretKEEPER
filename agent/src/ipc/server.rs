//! Unix socket IPC server.

use super::handlers::HandlerState;
use super::protocol::{Request, Response, ViolationEvent};
use crate::error::{Error, Result};
use crate::rules::RuleEngine;
use crate::storage::Storage;
use std::path::Path;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{broadcast, RwLock};

/// Maximum size of a single IPC request line.
const MAX_LINE_LENGTH: usize = 65536;

/// Privileged commands that require root or matching UID.
const PRIVILEGED_COMMANDS: &[&str] = &[
    "set_mode",
    "kill",
    "add_exception",
    "remove_exception",
    "allow_once",
    "allow_permanently",
];

/// Peer credentials from Unix socket.
#[derive(Debug, Clone, Copy)]
pub struct PeerCredentials {
    pub pid: u32,
    pub uid: u32,
    pub gid: u32,
}

impl PeerCredentials {
    /// Check if peer is root (uid 0).
    pub fn is_root(&self) -> bool {
        self.uid == 0
    }

    /// Check if peer is authorized for privileged operations.
    /// Authorized users: root (UID 0) or members of the admin group (GID 80 on macOS).
    /// This allows the desktop user to manage SecretKeeper from the UI.
    pub fn is_authorized(&self) -> bool {
        if self.is_root() {
            return true;
        }

        // On macOS, allow users in the admin group (gid 80)
        #[cfg(target_os = "macos")]
        {
            // Check if user is in admin group (gid 80)
            // We check supplementary groups, not just the primary gid
            if is_user_in_admin_group(self.uid) {
                return true;
            }
        }

        false
    }
}

/// Check if a user is in the admin group (gid 80) on macOS.
#[cfg(target_os = "macos")]
fn is_user_in_admin_group(uid: u32) -> bool {
    use std::ffi::CStr;

    // Get password entry for user
    let passwd = unsafe { libc::getpwuid(uid) };
    if passwd.is_null() {
        tracing::debug!("is_user_in_admin_group: getpwuid({}) returned null", uid);
        return false;
    }

    let username = unsafe { CStr::from_ptr((*passwd).pw_name) };
    let username = match username.to_str() {
        Ok(s) => s,
        Err(_) => {
            tracing::debug!("is_user_in_admin_group: invalid username for uid={}", uid);
            return false;
        }
    };

    // Check if user is in admin group (gid 80)
    const ADMIN_GID: i32 = 80;
    let mut ngroups: libc::c_int = 32;
    let mut groups: Vec<i32> = vec![0; ngroups as usize];

    let base_gid = unsafe { (*passwd).pw_gid as i32 };
    let result = unsafe {
        libc::getgrouplist(
            username.as_ptr() as *const libc::c_char,
            base_gid,
            groups.as_mut_ptr(),
            &mut ngroups,
        )
    };

    if result < 0 {
        // Buffer too small, resize and retry
        groups.resize(ngroups as usize, 0);
        unsafe {
            libc::getgrouplist(
                username.as_ptr() as *const libc::c_char,
                base_gid,
                groups.as_mut_ptr(),
                &mut ngroups,
            );
        }
    }

    let user_groups: Vec<i32> = groups.iter().take(ngroups as usize).copied().collect();
    let in_admin = user_groups.contains(&ADMIN_GID);
    tracing::info!(
        "Auth check: uid={} username={} groups={:?} in_admin={}",
        uid,
        username,
        user_groups,
        in_admin
    );

    in_admin
}

/// Get peer credentials from a Unix socket.
#[cfg(unix)]
fn get_peer_credentials(stream: &UnixStream) -> Option<PeerCredentials> {
    use std::os::unix::io::AsRawFd;

    let fd = stream.as_raw_fd();

    #[cfg(target_os = "linux")]
    {
        let mut cred: libc::ucred = unsafe { std::mem::zeroed() };
        let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;

        let ret = unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_PEERCRED,
                &mut cred as *mut _ as *mut libc::c_void,
                &mut len,
            )
        };

        if ret == 0 {
            Some(PeerCredentials {
                pid: cred.pid as u32,
                uid: cred.uid,
                gid: cred.gid,
            })
        } else {
            None
        }
    }

    #[cfg(target_os = "macos")]
    {
        let mut uid: libc::uid_t = 0;
        let mut gid: libc::gid_t = 0;

        let ret = unsafe { libc::getpeereid(fd, &mut uid, &mut gid) };

        if ret == 0 {
            // macOS doesn't provide PID via getpeereid, use 0 as placeholder
            Some(PeerCredentials { pid: 0, uid, gid })
        } else {
            None
        }
    }

    #[cfg(target_os = "freebsd")]
    {
        let mut cred: libc::xucred = unsafe { std::mem::zeroed() };
        let mut len = std::mem::size_of::<libc::xucred>() as libc::socklen_t;

        let ret = unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_LOCAL,
                libc::LOCAL_PEERCRED,
                &mut cred as *mut _ as *mut libc::c_void,
                &mut len,
            )
        };

        if ret == 0 {
            Some(PeerCredentials {
                pid: 0, // FreeBSD xucred doesn't include PID
                uid: cred.cr_uid,
                gid: cred.cr_gid,
            })
        } else {
            None
        }
    }
}

/// Check if a request requires privileged access.
fn is_privileged_request(request: &Request) -> bool {
    let action = match request {
        Request::SetMode { .. } => "set_mode",
        Request::Kill { .. } => "kill",
        Request::AddException { .. } => "add_exception",
        Request::RemoveException { .. } => "remove_exception",
        Request::AllowOnce { .. } => "allow_once",
        Request::AllowPermanently { .. } => "allow_permanently",
        _ => return false,
    };
    PRIVILEGED_COMMANDS.contains(&action)
}

/// IPC server for client communication.
pub struct IpcServer {
    listener: UnixListener,
    state: Arc<HandlerState>,
    event_tx: broadcast::Sender<ViolationEvent>,
}

impl IpcServer {
    /// Create a new IPC server at the given socket path.
    pub async fn new(
        socket_path: &Path,
        storage: Arc<Storage>,
        mode: Arc<RwLock<String>>,
        degraded_mode: Arc<RwLock<bool>>,
        config_toml: String,
        rule_engine: Arc<RwLock<RuleEngine>>,
    ) -> Result<Self> {
        // Remove existing socket if present
        if socket_path.exists() {
            std::fs::remove_file(socket_path)?;
        }

        // Ensure parent directory exists
        if let Some(parent) = socket_path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let listener = UnixListener::bind(socket_path).map_err(|e| {
            if e.kind() == std::io::ErrorKind::AddrInUse {
                Error::SocketInUse(socket_path.to_path_buf())
            } else {
                Error::Io(e)
            }
        })?;

        // Socket is world read/write (0o666) so any user can connect for status/events.
        // Privileged operations (kill, allow, set_mode, exceptions) require root or admin group,
        // enforced at the protocol level with a clear error response.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::Permissions::from_mode(0o666);
            std::fs::set_permissions(socket_path, perms)?;
        }

        let (event_tx, _) = broadcast::channel(1000);

        let state = Arc::new(HandlerState::new(
            storage,
            mode,
            degraded_mode,
            config_toml,
            rule_engine,
        ));

        tracing::info!("IPC server listening on {}", socket_path.display());

        Ok(Self {
            listener,
            state,
            event_tx,
        })
    }

    /// Get a sender for broadcasting events to subscribers.
    pub fn event_sender(&self) -> broadcast::Sender<ViolationEvent> {
        self.event_tx.clone()
    }

    /// Get shared state (for the monitor to add events).
    #[allow(dead_code)]
    pub fn state(&self) -> Arc<HandlerState> {
        self.state.clone()
    }

    /// Run the server, accepting connections.
    pub async fn run(&self) -> Result<()> {
        loop {
            match self.listener.accept().await {
                Ok((stream, _)) => {
                    // Get peer credentials before splitting the stream
                    #[cfg(unix)]
                    let peer_creds = get_peer_credentials(&stream);
                    #[cfg(not(unix))]
                    let peer_creds = None;

                    let state = self.state.clone();
                    let event_rx = self.event_tx.subscribe();

                    // Increment connected clients
                    {
                        let mut clients = state.connected_clients.write().await;
                        *clients += 1;
                    }

                    tokio::spawn(async move {
                        if let Err(e) =
                            handle_client(stream, state.clone(), event_rx, peer_creds).await
                        {
                            tracing::debug!("Client disconnected: {}", e);
                        }

                        // Decrement connected clients
                        let mut clients = state.connected_clients.write().await;
                        *clients = clients.saturating_sub(1);
                    });
                }
                Err(e) => {
                    tracing::error!("Failed to accept connection: {}", e);
                }
            }
        }
    }

    /// Broadcast a violation event to all subscribers.
    #[allow(dead_code)]
    pub async fn broadcast_event(&self, event: ViolationEvent) {
        let event = self.state.add_pending_event(event).await;
        let _ = self.event_tx.send(event);
    }
}

async fn handle_client(
    stream: UnixStream,
    state: Arc<HandlerState>,
    mut event_rx: broadcast::Receiver<ViolationEvent>,
    peer_creds: Option<PeerCredentials>,
) -> Result<()> {
    let (reader, writer) = stream.into_split();
    let mut reader = BufReader::new(reader);
    let writer = Arc::new(RwLock::new(writer));

    let mut subscribed = false;
    let mut line = String::new();

    // Log peer credentials for audit
    if let Some(creds) = &peer_creds {
        tracing::debug!(
            "Client connected: pid={}, uid={}, gid={}",
            creds.pid,
            creds.uid,
            creds.gid
        );
    }

    loop {
        line.clear();

        tokio::select! {
            // Handle incoming requests
            result = reader.read_line(&mut line) => {
                match result {
                    Ok(0) => {
                        // EOF - client disconnected
                        return Ok(());
                    }
                    Ok(n) if n > MAX_LINE_LENGTH => {
                        let response = Response::error("Request too large");
                        send_response(&writer, &response).await?;
                        continue;
                    }
                    Ok(_) => {
                        let response = match serde_json::from_str::<Request>(line.trim()) {
                            Ok(request) => {
                                // Check authorization for privileged commands
                                if is_privileged_request(&request) {
                                    match &peer_creds {
                                        Some(creds) if creds.is_authorized() => {
                                            // Authorized - proceed
                                        }
                                        Some(creds) => {
                                            tracing::error!(
                                                "PERMISSION DENIED: uid={} attempted privileged operation: {:?}",
                                                creds.uid,
                                                request
                                            );
                                            send_response(
                                                &writer,
                                                &Response::error_with_code(
                                                    "Permission denied: requires admin group membership. Run 'id' to check your groups.",
                                                    "E_PERM",
                                                ),
                                            ).await?;
                                            continue;
                                        }
                                        None => {
                                            tracing::warn!(
                                                "Could not verify credentials for privileged request"
                                            );
                                            send_response(
                                                &writer,
                                                &Response::error_with_code(
                                                    "Permission denied: could not verify credentials",
                                                    "E_CRED",
                                                ),
                                            ).await?;
                                            continue;
                                        }
                                    }
                                }

                                // Handle subscribe/unsubscribe specially
                                match &request {
                                    Request::Subscribe { .. } => {
                                        subscribed = true;
                                        Response::success("Subscribed to events")
                                    }
                                    Request::Unsubscribe => {
                                        subscribed = false;
                                        Response::success("Unsubscribed from events")
                                    }
                                    _ => state.handle(request).await,
                                }
                            }
                            Err(e) => {
                                Response::error(format!("Invalid JSON: {}", e))
                            }
                        };

                        send_response(&writer, &response).await?;
                    }
                    Err(e) => {
                        return Err(Error::Io(e));
                    }
                }
            }

            // Forward events to subscribed clients
            result = event_rx.recv(), if subscribed => {
                match result {
                    Ok(event) => {
                        let response = Response::Event(event);
                        send_response(&writer, &response).await?;
                    }
                    Err(broadcast::error::RecvError::Lagged(n)) => {
                        tracing::warn!("Client lagged, missed {} events", n);
                    }
                    Err(broadcast::error::RecvError::Closed) => {
                        return Ok(());
                    }
                }
            }
        }
    }
}

async fn send_response(
    writer: &Arc<RwLock<tokio::net::unix::OwnedWriteHalf>>,
    response: &Response,
) -> Result<()> {
    let json = serde_json::to_string(response)?;
    let mut writer = writer.write().await;
    writer.write_all(json.as_bytes()).await?;
    writer.write_all(b"\n").await?;
    writer.flush().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn create_test_rule_engine() -> Arc<RwLock<RuleEngine>> {
        Arc::new(RwLock::new(RuleEngine::new(Vec::new(), Vec::new())))
    }

    #[tokio::test]
    async fn test_server_creation() {
        let dir = tempdir().unwrap();
        let socket_path = dir.path().join("test.sock");
        let storage = Arc::new(Storage::in_memory().unwrap());
        let mode = Arc::new(RwLock::new("block".to_string()));
        let degraded_mode = Arc::new(RwLock::new(false));
        let rule_engine = create_test_rule_engine();

        let server = IpcServer::new(
            &socket_path,
            storage,
            mode,
            degraded_mode,
            String::new(),
            rule_engine,
        )
        .await;
        assert!(server.is_ok());
        assert!(socket_path.exists());
    }

    #[test]
    fn test_peer_credentials_is_root() {
        let root_creds = PeerCredentials {
            pid: 1234,
            uid: 0,
            gid: 0,
        };
        assert!(root_creds.is_root());

        let user_creds = PeerCredentials {
            pid: 1234,
            uid: 501,
            gid: 20,
        };
        assert!(!user_creds.is_root());
    }

    #[test]
    fn test_peer_credentials_is_authorized() {
        // Root is always authorized
        let root_creds = PeerCredentials {
            pid: 1,
            uid: 0,
            gid: 0,
        };
        assert!(root_creds.is_authorized());

        // Unknown UIDs (not in admin group) are not authorized
        let unknown_user_creds = PeerCredentials {
            pid: 1234,
            uid: 99999,
            gid: 99999,
        };
        assert!(!unknown_user_creds.is_authorized());

        // Note: uid 501 (typical macOS user) may be authorized if in admin group.
        // We don't test this as it depends on the system's user configuration.
    }

    #[test]
    fn test_is_privileged_request() {
        // Privileged requests
        assert!(is_privileged_request(&Request::SetMode {
            mode: "block".to_string()
        }));
        assert!(is_privileged_request(&Request::Kill {
            event_id: "test".to_string()
        }));
        assert!(is_privileged_request(&Request::AddException {
            process_path: Some("/test".to_string()),
            code_signer: None,
            file_pattern: "~/.ssh/*".to_string(),
            is_glob: true,
            expires_at: None,
            comment: None,
        }));
        assert!(is_privileged_request(&Request::RemoveException { id: 1 }));
        assert!(is_privileged_request(&Request::AllowOnce {
            event_id: "test".to_string()
        }));
        assert!(is_privileged_request(&Request::AllowPermanently {
            event_id: "test".to_string(),
            expires_at: None,
            comment: None,
        }));

        // Non-privileged requests
        assert!(!is_privileged_request(&Request::Ping));
        assert!(!is_privileged_request(&Request::Status));
        assert!(!is_privileged_request(&Request::GetMode));
        assert!(!is_privileged_request(&Request::GetViolations {
            limit: None,
            since: None,
            file_path: None,
        }));
        assert!(!is_privileged_request(&Request::GetExceptions));
        assert!(!is_privileged_request(&Request::GetConfig));
        assert!(!is_privileged_request(&Request::Subscribe { filter: None }));
        assert!(!is_privileged_request(&Request::Unsubscribe));
    }

    #[tokio::test]
    async fn test_server_event_sender() {
        let dir = tempdir().unwrap();
        let socket_path = dir.path().join("test.sock");
        let storage = Arc::new(Storage::in_memory().unwrap());
        let mode = Arc::new(RwLock::new("block".to_string()));
        let degraded_mode = Arc::new(RwLock::new(false));
        let rule_engine = create_test_rule_engine();

        let server = IpcServer::new(
            &socket_path,
            storage,
            mode,
            degraded_mode,
            "test config".to_string(),
            rule_engine,
        )
        .await
        .unwrap();

        let tx = server.event_sender();
        // Can create multiple receivers
        let _rx1 = tx.subscribe();
        let _rx2 = tx.subscribe();
    }

    #[tokio::test]
    async fn test_server_state() {
        let dir = tempdir().unwrap();
        let socket_path = dir.path().join("test.sock");
        let storage = Arc::new(Storage::in_memory().unwrap());
        let mode = Arc::new(RwLock::new("block".to_string()));
        let degraded_mode = Arc::new(RwLock::new(false));
        let rule_engine = create_test_rule_engine();

        let server = IpcServer::new(
            &socket_path,
            storage,
            mode,
            degraded_mode,
            "test config".to_string(),
            rule_engine,
        )
        .await
        .unwrap();

        let state = server.state();
        assert_eq!(state.config_toml, "test config");
    }

    #[tokio::test]
    async fn test_server_replaces_existing_socket() {
        let dir = tempdir().unwrap();
        let socket_path = dir.path().join("test.sock");

        // Create a dummy file at the socket path
        std::fs::write(&socket_path, "dummy").unwrap();
        assert!(socket_path.exists());

        let storage = Arc::new(Storage::in_memory().unwrap());
        let mode = Arc::new(RwLock::new("block".to_string()));
        let degraded_mode = Arc::new(RwLock::new(false));
        let rule_engine = create_test_rule_engine();
        let server = IpcServer::new(
            &socket_path,
            storage,
            mode,
            degraded_mode,
            String::new(),
            rule_engine,
        )
        .await;

        // Should succeed and replace the existing file
        assert!(server.is_ok());
        assert!(socket_path.exists());
    }

    #[tokio::test]
    async fn test_server_creates_parent_dirs() {
        let dir = tempdir().unwrap();
        let socket_path = dir.path().join("subdir/nested/test.sock");

        // Parent dirs don't exist
        assert!(!socket_path.parent().unwrap().exists());

        let storage = Arc::new(Storage::in_memory().unwrap());
        let mode = Arc::new(RwLock::new("block".to_string()));
        let degraded_mode = Arc::new(RwLock::new(false));
        let rule_engine = create_test_rule_engine();
        let server = IpcServer::new(
            &socket_path,
            storage,
            mode,
            degraded_mode,
            String::new(),
            rule_engine,
        )
        .await;

        // Should create parent dirs and succeed
        assert!(server.is_ok());
        assert!(socket_path.exists());
    }

    #[tokio::test]
    async fn test_max_line_length_constant() {
        // Verify the constant is reasonable
        assert!(MAX_LINE_LENGTH > 0);
        assert!(MAX_LINE_LENGTH <= 1024 * 1024); // Should be <= 1MB
    }

    #[test]
    fn test_privileged_commands_list() {
        // Verify all expected commands are in the list
        assert!(PRIVILEGED_COMMANDS.contains(&"set_mode"));
        assert!(PRIVILEGED_COMMANDS.contains(&"kill"));
        assert!(PRIVILEGED_COMMANDS.contains(&"add_exception"));
        assert!(PRIVILEGED_COMMANDS.contains(&"remove_exception"));
        assert!(PRIVILEGED_COMMANDS.contains(&"allow_once"));
        assert!(PRIVILEGED_COMMANDS.contains(&"allow_permanently"));

        // Verify some commands are NOT in the list
        assert!(!PRIVILEGED_COMMANDS.contains(&"ping"));
        assert!(!PRIVILEGED_COMMANDS.contains(&"status"));
        assert!(!PRIVILEGED_COMMANDS.contains(&"get_mode"));
    }
}
