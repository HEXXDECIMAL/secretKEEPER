//! IPC protocol message types.

use crate::process::ProcessTreeEntry;
use crate::rules::Exception;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Client request to the agent.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum Request {
    /// Subscribe to real-time events.
    Subscribe {
        #[serde(default)]
        filter: Option<EventFilter>,
    },

    /// Unsubscribe from events.
    Unsubscribe,

    /// Get agent status.
    Status,

    /// Get current enforcement mode.
    GetMode,

    /// Set enforcement mode.
    SetMode { mode: String },

    /// Allow a suspended process to continue (one-time).
    AllowOnce { event_id: String },

    /// Add permanent/temporary exception for a violation.
    AllowPermanently {
        event_id: String,
        #[serde(default)]
        expires_at: Option<DateTime<Utc>>,
        #[serde(default)]
        comment: Option<String>,
    },

    /// Kill a suspended process.
    Kill { event_id: String },

    /// Get violation history.
    GetViolations {
        #[serde(default)]
        limit: Option<usize>,
        #[serde(default)]
        since: Option<DateTime<Utc>>,
        #[serde(default)]
        file_path: Option<String>,
    },

    /// Get all active exceptions.
    GetExceptions,

    /// Add a new exception.
    AddException {
        #[serde(default)]
        process_path: Option<String>,
        #[serde(default)]
        code_signer: Option<String>,
        file_pattern: String,
        #[serde(default)]
        is_glob: bool,
        #[serde(default)]
        expires_at: Option<DateTime<Utc>>,
        #[serde(default)]
        comment: Option<String>,
    },

    /// Remove an exception by ID.
    RemoveException { id: i64 },

    /// Get current configuration (as TOML).
    GetConfig,

    /// Ping for health check.
    Ping,
}

/// Filter for event subscription.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EventFilter {
    /// Only receive events for these file patterns.
    #[serde(default)]
    pub file_patterns: Vec<String>,

    /// Only receive events matching these rule IDs.
    #[serde(default)]
    pub rule_ids: Vec<String>,

    /// Only receive denied events.
    #[serde(default)]
    pub denied_only: bool,
}

/// Agent response to client.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum Response {
    /// Operation succeeded.
    Success {
        #[serde(default)]
        message: String,
    },

    /// Operation failed.
    Error {
        message: String,
        #[serde(default)]
        code: Option<String>,
    },

    /// Real-time violation event.
    Event(ViolationEvent),

    /// Agent status.
    Status {
        mode: String,
        degraded_mode: bool,
        events_pending: usize,
        connected_clients: usize,
        uptime_secs: u64,
        total_violations: u64,
    },

    /// Violation history response.
    Violations { events: Vec<ViolationEvent> },

    /// Exception list response.
    Exceptions { rules: Vec<Exception> },

    /// Configuration response.
    Config { toml: String },

    /// Pong response to ping.
    Pong,
}

#[allow(dead_code)]
impl Response {
    pub fn success(message: impl Into<String>) -> Self {
        Self::Success {
            message: message.into(),
        }
    }

    pub fn error(message: impl Into<String>) -> Self {
        Self::Error {
            message: message.into(),
            code: None,
        }
    }

    pub fn error_with_code(message: impl Into<String>, code: impl Into<String>) -> Self {
        Self::Error {
            message: message.into(),
            code: Some(code.into()),
        }
    }
}

/// A violation event for client notification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ViolationEvent {
    /// Unique event ID.
    pub id: String,

    /// When the violation occurred.
    pub timestamp: DateTime<Utc>,

    /// Which rule was triggered (if any).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rule_id: Option<String>,

    /// The protected file that was accessed.
    pub file_path: String,

    /// Path to the violating process.
    pub process_path: String,

    /// Process ID.
    pub process_pid: u32,

    /// Command line of the process.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub process_cmdline: Option<String>,

    /// Effective user ID.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub process_euid: Option<u32>,

    /// Parent process ID.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_pid: Option<u32>,

    /// Apple Team ID (if signed).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub team_id: Option<String>,

    /// Code signing ID.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signing_id: Option<String>,

    /// Action taken (blocked, logged, suspended).
    pub action: String,

    /// Full process tree from violator to init.
    pub process_tree: Vec<ProcessTreeEntry>,
}

#[allow(dead_code)]
impl ViolationEvent {
    pub fn new(
        file_path: impl Into<String>,
        process_path: impl Into<String>,
        process_pid: u32,
        action: impl Into<String>,
    ) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            timestamp: Utc::now(),
            rule_id: None,
            file_path: file_path.into(),
            process_path: process_path.into(),
            process_pid,
            process_cmdline: None,
            process_euid: None,
            parent_pid: None,
            team_id: None,
            signing_id: None,
            action: action.into(),
            process_tree: Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_request_serialize() {
        let req = Request::Subscribe { filter: None };
        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains("subscribe"));

        let req2 = Request::SetMode {
            mode: "monitor".to_string(),
        };
        let json2 = serde_json::to_string(&req2).unwrap();
        assert!(json2.contains("set_mode"));
        assert!(json2.contains("monitor"));
    }

    #[test]
    fn test_request_deserialize() {
        let json = r#"{"action": "status"}"#;
        let req: Request = serde_json::from_str(json).unwrap();
        assert!(matches!(req, Request::Status));

        let json2 = r#"{"action": "set_mode", "mode": "block"}"#;
        let req2: Request = serde_json::from_str(json2).unwrap();
        match req2 {
            Request::SetMode { mode } => assert_eq!(mode, "block"),
            _ => panic!("Wrong variant"),
        }
    }

    #[test]
    fn test_response_serialize() {
        let resp = Response::success("OK");
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("success"));

        let resp2 = Response::error("Something failed");
        let json2 = serde_json::to_string(&resp2).unwrap();
        assert!(json2.contains("error"));
    }

    #[test]
    fn test_all_request_types_deserialize() {
        // Subscribe with filter
        let json = r#"{"action": "subscribe", "filter": {"denied_only": true}}"#;
        let req: Request = serde_json::from_str(json).unwrap();
        match req {
            Request::Subscribe { filter } => {
                assert!(filter.unwrap().denied_only);
            }
            _ => panic!("Wrong variant"),
        }

        // Unsubscribe
        let json = r#"{"action": "unsubscribe"}"#;
        let req: Request = serde_json::from_str(json).unwrap();
        assert!(matches!(req, Request::Unsubscribe));

        // GetMode
        let json = r#"{"action": "get_mode"}"#;
        let req: Request = serde_json::from_str(json).unwrap();
        assert!(matches!(req, Request::GetMode));

        // AllowOnce
        let json = r#"{"action": "allow_once", "event_id": "abc123"}"#;
        let req: Request = serde_json::from_str(json).unwrap();
        match req {
            Request::AllowOnce { event_id } => assert_eq!(event_id, "abc123"),
            _ => panic!("Wrong variant"),
        }

        // AllowPermanently
        let json = r#"{"action": "allow_permanently", "event_id": "abc123", "comment": "test"}"#;
        let req: Request = serde_json::from_str(json).unwrap();
        match req {
            Request::AllowPermanently {
                event_id, comment, ..
            } => {
                assert_eq!(event_id, "abc123");
                assert_eq!(comment, Some("test".to_string()));
            }
            _ => panic!("Wrong variant"),
        }

        // Kill
        let json = r#"{"action": "kill", "event_id": "abc123"}"#;
        let req: Request = serde_json::from_str(json).unwrap();
        match req {
            Request::Kill { event_id } => assert_eq!(event_id, "abc123"),
            _ => panic!("Wrong variant"),
        }

        // GetViolations
        let json = r#"{"action": "get_violations", "limit": 100}"#;
        let req: Request = serde_json::from_str(json).unwrap();
        match req {
            Request::GetViolations { limit, .. } => assert_eq!(limit, Some(100)),
            _ => panic!("Wrong variant"),
        }

        // GetExceptions
        let json = r#"{"action": "get_exceptions"}"#;
        let req: Request = serde_json::from_str(json).unwrap();
        assert!(matches!(req, Request::GetExceptions));

        // AddException
        let json = r#"{"action": "add_exception", "file_pattern": "~/.ssh/*", "is_glob": true}"#;
        let req: Request = serde_json::from_str(json).unwrap();
        match req {
            Request::AddException {
                file_pattern,
                is_glob,
                ..
            } => {
                assert_eq!(file_pattern, "~/.ssh/*");
                assert!(is_glob);
            }
            _ => panic!("Wrong variant"),
        }

        // RemoveException
        let json = r#"{"action": "remove_exception", "id": 42}"#;
        let req: Request = serde_json::from_str(json).unwrap();
        match req {
            Request::RemoveException { id } => assert_eq!(id, 42),
            _ => panic!("Wrong variant"),
        }

        // GetConfig
        let json = r#"{"action": "get_config"}"#;
        let req: Request = serde_json::from_str(json).unwrap();
        assert!(matches!(req, Request::GetConfig));

        // Ping
        let json = r#"{"action": "ping"}"#;
        let req: Request = serde_json::from_str(json).unwrap();
        assert!(matches!(req, Request::Ping));
    }

    #[test]
    fn test_all_response_types_serialize() {
        // Status response
        let resp = Response::Status {
            mode: "block".to_string(),
            degraded_mode: false,
            events_pending: 5,
            connected_clients: 2,
            uptime_secs: 3600,
            total_violations: 100,
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("block"));
        assert!(json.contains("3600"));

        // Pong response
        let resp = Response::Pong;
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("pong"));

        // Config response
        let resp = Response::Config {
            toml: "[agent]\nlog_level = \"info\"".to_string(),
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("config"));
        assert!(json.contains("log_level"));

        // Error with code
        let resp = Response::error_with_code("Failed", "E001");
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("E001"));
    }

    #[test]
    fn test_violation_event_new() {
        let event = ViolationEvent::new("~/.ssh/id_rsa", "/usr/bin/cat", 1234, "blocked");

        assert_eq!(event.file_path, "~/.ssh/id_rsa");
        assert_eq!(event.process_path, "/usr/bin/cat");
        assert_eq!(event.process_pid, 1234);
        assert_eq!(event.action, "blocked");
        assert!(!event.id.is_empty());
        assert!(event.process_tree.is_empty());
    }

    #[test]
    fn test_violation_event_serialize() {
        let event = ViolationEvent::new("~/.ssh/id_rsa", "/usr/bin/cat", 1234, "blocked");

        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("id_rsa"));
        assert!(json.contains("1234"));
        assert!(json.contains("blocked"));

        // Optional fields should not appear when None
        assert!(!json.contains("team_id"));
        assert!(!json.contains("signing_id"));
    }

    #[test]
    fn test_event_filter_defaults() {
        let filter = EventFilter::default();
        assert!(filter.file_patterns.is_empty());
        assert!(filter.rule_ids.is_empty());
        assert!(!filter.denied_only);
    }

    #[test]
    fn test_roundtrip_serialize_deserialize() {
        // Test that serializing and deserializing produces equivalent results
        let original = Request::AddException {
            process_path: Some("/usr/bin/mytool".to_string()),
            code_signer: Some("TEAM123".to_string()),
            file_pattern: "~/.ssh/*".to_string(),
            is_glob: true,
            expires_at: None,
            comment: Some("Test exception".to_string()),
        };

        let json = serde_json::to_string(&original).unwrap();
        let restored: Request = serde_json::from_str(&json).unwrap();

        match restored {
            Request::AddException {
                process_path,
                code_signer,
                file_pattern,
                is_glob,
                comment,
                ..
            } => {
                assert_eq!(process_path, Some("/usr/bin/mytool".to_string()));
                assert_eq!(code_signer, Some("TEAM123".to_string()));
                assert_eq!(file_pattern, "~/.ssh/*");
                assert!(is_glob);
                assert_eq!(comment, Some("Test exception".to_string()));
            }
            _ => panic!("Wrong variant after roundtrip"),
        }
    }
}
