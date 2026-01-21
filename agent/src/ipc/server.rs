//! Unix socket IPC server.

use super::handlers::HandlerState;
use super::protocol::{Request, Response, ViolationEvent};
use crate::error::{Error, Result};
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
    /// Authorized if: root, or same UID as agent (for testing).
    pub fn is_authorized(&self) -> bool {
        self.is_root() || self.uid == unsafe { libc::getuid() }
    }
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

        // Set socket permissions to allow any local user to connect
        // This is safe because the socket is only accessible locally
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::Permissions::from_mode(0o666);
            std::fs::set_permissions(socket_path, perms)?;
        }

        let (event_tx, _) = broadcast::channel(1000);

        let state = Arc::new(HandlerState::new(storage, mode, degraded_mode, config_toml));

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
                                            tracing::warn!(
                                                "Unauthorized request from uid={}: {:?}",
                                                creds.uid,
                                                request
                                            );
                                            send_response(
                                                &writer,
                                                &Response::error_with_code(
                                                    "Permission denied: privileged operation requires root",
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

    #[tokio::test]
    async fn test_server_creation() {
        let dir = tempdir().unwrap();
        let socket_path = dir.path().join("test.sock");
        let storage = Arc::new(Storage::in_memory().unwrap());
        let mode = Arc::new(RwLock::new("block".to_string()));
        let degraded_mode = Arc::new(RwLock::new(false));

        let server =
            IpcServer::new(&socket_path, storage, mode, degraded_mode, String::new()).await;
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

        // Same UID as current process is authorized
        let current_uid = unsafe { libc::getuid() };
        let same_user_creds = PeerCredentials {
            pid: 1234,
            uid: current_uid,
            gid: 20,
        };
        assert!(same_user_creds.is_authorized());

        // Different non-root UID is not authorized (unless it's current user)
        let other_user_creds = PeerCredentials {
            pid: 1234,
            uid: 99999,
            gid: 99999,
        };
        // This will be false unless running as UID 99999
        if current_uid != 99999 {
            assert!(!other_user_creds.is_authorized());
        }
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

        let server = IpcServer::new(
            &socket_path,
            storage,
            mode,
            degraded_mode,
            "test config".to_string(),
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

        let server = IpcServer::new(
            &socket_path,
            storage,
            mode,
            degraded_mode,
            "test config".to_string(),
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
        let server =
            IpcServer::new(&socket_path, storage, mode, degraded_mode, String::new()).await;

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
        let server =
            IpcServer::new(&socket_path, storage, mode, degraded_mode, String::new()).await;

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
