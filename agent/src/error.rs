//! Error types for the secretkeeper agent.

use std::path::PathBuf;
use thiserror::Error;

/// Result type for secretkeeper operations.
pub type Result<T> = std::result::Result<T, Error>;

/// Errors that can occur in the secretkeeper agent.
#[derive(Error, Debug)]
#[allow(dead_code)]
pub enum Error {
    #[error("configuration error: {0}")]
    Config(String),

    #[error("failed to parse config file {path}: {source}")]
    ConfigParse {
        path: PathBuf,
        #[source]
        source: toml::de::Error,
    },

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("database error: {0}")]
    Database(#[from] rusqlite::Error),

    #[error("IPC error: {0}")]
    Ipc(String),

    #[error("JSON serialization error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("monitor error: {0}")]
    Monitor(String),

    #[error("process not found: pid {0}")]
    ProcessNotFound(u32),

    #[error("permission denied: {0}")]
    PermissionDenied(String),

    #[error("not running as root")]
    NotRoot,

    #[error("unsupported platform: {0}")]
    UnsupportedPlatform(String),

    #[error("socket already in use: {0}")]
    SocketInUse(PathBuf),
}

#[allow(dead_code)]
impl Error {
    pub fn config(msg: impl Into<String>) -> Self {
        Self::Config(msg.into())
    }

    pub fn ipc(msg: impl Into<String>) -> Self {
        Self::Ipc(msg.into())
    }

    pub fn monitor(msg: impl Into<String>) -> Self {
        Self::Monitor(msg.into())
    }

    pub fn permission_denied(msg: impl Into<String>) -> Self {
        Self::PermissionDenied(msg.into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_config() {
        let err = Error::config("test config error");
        assert_eq!(err.to_string(), "configuration error: test config error");
    }

    #[test]
    fn test_error_ipc() {
        let err = Error::ipc("connection failed");
        assert_eq!(err.to_string(), "IPC error: connection failed");
    }

    #[test]
    fn test_error_monitor() {
        let err = Error::monitor("fanotify init failed");
        assert_eq!(err.to_string(), "monitor error: fanotify init failed");
    }

    #[test]
    fn test_error_permission_denied() {
        let err = Error::permission_denied("not root");
        assert_eq!(err.to_string(), "permission denied: not root");
    }

    #[test]
    fn test_error_not_root() {
        let err = Error::NotRoot;
        assert_eq!(err.to_string(), "not running as root");
    }

    #[test]
    fn test_error_process_not_found() {
        let err = Error::ProcessNotFound(12345);
        assert_eq!(err.to_string(), "process not found: pid 12345");
    }

    #[test]
    fn test_error_unsupported_platform() {
        let err = Error::UnsupportedPlatform("windows".to_string());
        assert_eq!(err.to_string(), "unsupported platform: windows");
    }

    #[test]
    fn test_error_socket_in_use() {
        let err = Error::SocketInUse(PathBuf::from("/var/run/test.sock"));
        assert_eq!(err.to_string(), "socket already in use: /var/run/test.sock");
    }

    #[test]
    fn test_error_from_io() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "file not found");
        let err: Error = io_err.into();
        assert!(err.to_string().contains("file not found"));
    }

    #[test]
    fn test_error_from_json() {
        let json_err = serde_json::from_str::<serde_json::Value>("invalid json").unwrap_err();
        let err: Error = json_err.into();
        assert!(err.to_string().contains("JSON serialization error"));
    }
}
