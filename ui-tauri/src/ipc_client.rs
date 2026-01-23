use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::io;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;
use tokio::time::timeout;

/// Connection timeout for initial socket connection
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// Read timeout for waiting on responses
const READ_TIMEOUT: Duration = Duration::from_secs(30);

/// Socket paths to try in order (first one that exists wins)
const SOCKET_PATHS: &[&str] = &[
    "/var/run/secretkeeper.sock",
    "/var/run/secretkeeper/secretkeeper.sock",
    "/tmp/secretkeeper.sock",
];

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ViolationEvent {
    pub id: String,
    pub timestamp: DateTime<Utc>,
    pub rule_id: Option<String>,
    pub file_path: String,
    pub process_path: String,
    pub process_pid: u32,
    pub parent_pid: Option<u32>,
    pub process_euid: Option<u32>,
    pub process_cmdline: Option<String>,
    pub team_id: Option<String>,
    pub signing_id: Option<String>,
    pub action: String,
    pub process_tree: Vec<ProcessTreeEntry>,
}

impl ViolationEvent {
    pub fn process_name(&self) -> String {
        self.process_path
            .split('/')
            .next_back()
            .unwrap_or(&self.process_path)
            .to_string()
    }

    pub fn signing_status(&self) -> &'static str {
        if self
            .process_tree
            .first()
            .map(|e| e.is_platform_binary)
            .unwrap_or(false)
        {
            "platform"
        } else if self.team_id.is_some() {
            "signed"
        } else if self.signing_id.is_some() {
            "adhoc"
        } else {
            "unsigned"
        }
    }
}

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
    #[serde(default)]
    pub is_platform_binary: bool,
    #[serde(default)]
    pub state: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentStatus {
    pub mode: String,
    #[serde(default)]
    pub degraded_mode: bool,
    #[serde(default)]
    pub events_pending: usize,
    #[serde(default)]
    pub connected_clients: usize,
    pub uptime_secs: u64,
    pub total_violations: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Exception {
    pub id: i64,
    pub process_path: Option<String>,
    pub signer_type: Option<String>,
    pub team_id: Option<String>,
    pub signing_id: Option<String>,
    pub file_pattern: String,
    #[serde(default)]
    pub is_glob: bool,
    pub expires_at: Option<DateTime<Utc>>,
    pub added_by: String,
    pub comment: Option<String>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AddExceptionParams {
    pub process_path: Option<String>,
    pub signer_type: Option<String>,
    pub team_id: Option<String>,
    pub signing_id: Option<String>,
    pub file_pattern: String,
    #[serde(default)]
    pub is_glob: bool,
    pub expires_at: Option<DateTime<Utc>>,
    pub comment: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Category {
    pub id: String,
    pub enabled: bool,
    pub patterns: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LearningStatus {
    pub state: String,
    pub hours_remaining: u32,
    pub pending_count: u32,
    pub approved_count: u32,
    pub rejected_count: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LearningRecommendation {
    pub id: i64,
    pub category_id: String,
    pub process_path: String,
    pub process_name: String,
    pub team_id: Option<String>,
    pub signing_id: Option<String>,
    pub is_platform_binary: bool,
    pub observation_count: u32,
    pub status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum Request {
    Subscribe {
        #[serde(default)]
        filter: Option<EventFilter>,
    },
    Status,
    SetMode {
        mode: String,
    },
    AllowOnce {
        event_id: String,
    },
    AllowPermanently {
        event_id: String,
        #[serde(default)]
        expires_at: Option<DateTime<Utc>>,
        #[serde(default)]
        comment: Option<String>,
    },
    Kill {
        event_id: String,
    },
    GetViolations {
        #[serde(default)]
        limit: Option<usize>,
        #[serde(default)]
        since: Option<DateTime<Utc>>,
    },
    GetExceptions,
    #[serde(rename = "add_exception")]
    AddException(AddExceptionParams),
    RemoveException {
        id: i64,
    },
    GetCategories,
    SetCategoryEnabled {
        category_id: String,
        enabled: bool,
    },
    ResumeProcess {
        pid: u32,
    },
    Ping,
    GetLearningStatus,
    GetLearningRecommendations,
    ApproveLearning {
        id: i64,
    },
    RejectLearning {
        id: i64,
    },
    ApproveAllLearnings,
    RejectAllLearnings,
    CompleteLearningReview,
    EndLearningEarly,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct EventFilter {
    #[serde(default)]
    pub file_patterns: Vec<String>,
    #[serde(default)]
    pub rule_ids: Vec<String>,
    #[serde(default)]
    pub denied_only: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum Response {
    Success {
        #[serde(default)]
        message: String,
    },
    Error {
        message: String,
    },
    #[serde(rename = "status")]
    Status {
        mode: String,
        #[serde(default)]
        degraded_mode: bool,
        #[serde(default)]
        events_pending: usize,
        #[serde(default)]
        connected_clients: usize,
        uptime_secs: u64,
        total_violations: u64,
    },
    Violations {
        events: Vec<ViolationEvent>,
    },
    Exceptions {
        rules: Vec<Exception>,
    },
    Categories {
        categories: Vec<Category>,
    },
    Event(ViolationEvent),
    Pong,
    LearningStatus {
        state: String,
        hours_remaining: u32,
        pending_count: u32,
        approved_count: u32,
        rejected_count: u32,
    },
    LearningRecommendations {
        recommendations: Vec<LearningRecommendation>,
    },
}

fn unexpected_response() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "Unexpected response")
}

pub struct IpcClient {
    stream: Option<BufReader<UnixStream>>,
    socket_path: Option<String>,
}

impl IpcClient {
    pub fn new() -> Self {
        Self {
            stream: None,
            socket_path: None,
        }
    }

    #[allow(dead_code)]
    pub fn is_connected(&self) -> bool {
        self.stream.is_some()
    }

    pub async fn connect(&mut self) -> io::Result<()> {
        // Try each socket path in order
        let mut last_err = io::Error::new(io::ErrorKind::NotFound, "No socket paths configured");

        for path in SOCKET_PATHS {
            // Check if socket exists before trying to connect
            if !std::path::Path::new(path).exists() {
                continue;
            }

            match timeout(CONNECT_TIMEOUT, UnixStream::connect(path)).await {
                Ok(Ok(stream)) => {
                    self.stream = Some(BufReader::new(stream));
                    self.socket_path = Some(path.to_string());
                    return Ok(());
                }
                Ok(Err(e)) => {
                    last_err = e;
                    continue;
                }
                Err(_) => {
                    last_err = io::Error::new(
                        io::ErrorKind::TimedOut,
                        format!("Connection to {} timed out", path),
                    );
                    continue;
                }
            }
        }

        Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!(
                "Could not connect to agent. Tried paths: {:?}. Last error: {}",
                SOCKET_PATHS, last_err
            ),
        ))
    }

    pub async fn disconnect(&mut self) {
        self.stream = None;
        self.socket_path = None;
    }

    async fn send(&mut self, request: &Request) -> io::Result<Response> {
        let stream = self
            .stream
            .as_mut()
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotConnected, "Not connected"))?;

        let json = serde_json::to_string(request)?;
        stream.get_mut().write_all(json.as_bytes()).await?;
        stream.get_mut().write_all(b"\n").await?;
        stream.get_mut().flush().await?;

        let mut line = String::new();
        match timeout(READ_TIMEOUT, stream.read_line(&mut line)).await {
            Ok(Ok(_)) => {}
            Ok(Err(e)) => return Err(e),
            Err(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "Timeout waiting for response from agent",
                ))
            }
        }

        serde_json::from_str(&line).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Parse error: {} in: {}", e, line.trim()),
            )
        })
    }

    pub async fn subscribe(&mut self, filter: Option<EventFilter>) -> io::Result<()> {
        match self.send(&Request::Subscribe { filter }).await? {
            Response::Success { .. } => Ok(()),
            Response::Error { message } => Err(io::Error::other(message)),
            _ => Err(unexpected_response()),
        }
    }

    /// Read an event with a timeout. Returns None on timeout (not an error).
    /// This allows periodic reconnection checks.
    #[allow(dead_code)]
    pub async fn read_event(&mut self) -> io::Result<Option<ViolationEvent>> {
        self.read_event_timeout(READ_TIMEOUT).await
    }

    /// Read an event with a custom timeout
    pub async fn read_event_timeout(
        &mut self,
        read_timeout: Duration,
    ) -> io::Result<Option<ViolationEvent>> {
        let stream = self
            .stream
            .as_mut()
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotConnected, "Not connected"))?;

        let mut line = String::new();
        match timeout(read_timeout, stream.read_line(&mut line)).await {
            Ok(Ok(0)) => {
                // Connection closed
                return Err(io::Error::new(
                    io::ErrorKind::ConnectionReset,
                    "Connection closed by agent",
                ));
            }
            Ok(Ok(_)) => {}
            Ok(Err(e)) => return Err(e),
            Err(_) => {
                // Timeout - not an error, just no events
                return Ok(None);
            }
        }

        let response: Response = serde_json::from_str(&line)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;

        match response {
            Response::Event(event) => Ok(Some(event)),
            _ => Ok(None),
        }
    }

    /// Send a ping to check if connection is alive
    pub async fn ping(&mut self) -> io::Result<()> {
        match self.send(&Request::Ping).await? {
            Response::Pong => Ok(()),
            Response::Error { message } => Err(io::Error::other(message)),
            _ => Err(unexpected_response()),
        }
    }

    pub async fn get_status(&mut self) -> io::Result<AgentStatus> {
        match self.send(&Request::Status).await? {
            Response::Status {
                mode,
                degraded_mode,
                events_pending,
                connected_clients,
                uptime_secs,
                total_violations,
            } => Ok(AgentStatus {
                mode,
                degraded_mode,
                events_pending,
                connected_clients,
                uptime_secs,
                total_violations,
            }),
            Response::Error { message } => Err(io::Error::other(message)),
            _ => Err(unexpected_response()),
        }
    }

    pub async fn set_mode(&mut self, mode: String) -> io::Result<()> {
        match self.send(&Request::SetMode { mode }).await? {
            Response::Success { .. } => Ok(()),
            Response::Error { message } => Err(io::Error::other(message)),
            _ => Err(unexpected_response()),
        }
    }

    pub async fn get_violations(
        &mut self,
        limit: Option<usize>,
        since: Option<DateTime<Utc>>,
    ) -> io::Result<Vec<ViolationEvent>> {
        match self.send(&Request::GetViolations { limit, since }).await? {
            Response::Violations { events } => Ok(events),
            Response::Error { message } => Err(io::Error::other(message)),
            _ => Err(unexpected_response()),
        }
    }

    pub async fn get_exceptions(&mut self) -> io::Result<Vec<Exception>> {
        match self.send(&Request::GetExceptions).await? {
            Response::Exceptions { rules } => Ok(rules),
            Response::Error { message } => Err(io::Error::other(message)),
            _ => Err(unexpected_response()),
        }
    }

    pub async fn add_exception(&mut self, params: AddExceptionParams) -> io::Result<()> {
        match self.send(&Request::AddException(params)).await? {
            Response::Success { .. } => Ok(()),
            Response::Error { message } => Err(io::Error::other(message)),
            _ => Err(unexpected_response()),
        }
    }

    pub async fn remove_exception(&mut self, id: i64) -> io::Result<()> {
        match self.send(&Request::RemoveException { id }).await? {
            Response::Success { .. } => Ok(()),
            Response::Error { message } => Err(io::Error::other(message)),
            _ => Err(unexpected_response()),
        }
    }

    pub async fn allow_once(&mut self, event_id: String) -> io::Result<()> {
        match self.send(&Request::AllowOnce { event_id }).await? {
            Response::Success { .. } => Ok(()),
            Response::Error { message } => Err(io::Error::other(message)),
            _ => Err(unexpected_response()),
        }
    }

    pub async fn allow_permanently(
        &mut self,
        event_id: String,
        expires_at: Option<DateTime<Utc>>,
        comment: Option<String>,
    ) -> io::Result<()> {
        match self
            .send(&Request::AllowPermanently {
                event_id,
                expires_at,
                comment,
            })
            .await?
        {
            Response::Success { .. } => Ok(()),
            Response::Error { message } => Err(io::Error::other(message)),
            _ => Err(unexpected_response()),
        }
    }

    pub async fn kill_process(&mut self, event_id: String) -> io::Result<()> {
        match self.send(&Request::Kill { event_id }).await? {
            Response::Success { .. } => Ok(()),
            Response::Error { message } => Err(io::Error::other(message)),
            _ => Err(unexpected_response()),
        }
    }

    pub async fn get_categories(&mut self) -> io::Result<Vec<Category>> {
        match self.send(&Request::GetCategories).await? {
            Response::Categories { categories } => Ok(categories),
            Response::Error { message } => Err(io::Error::other(message)),
            _ => Err(unexpected_response()),
        }
    }

    pub async fn set_category_enabled(
        &mut self,
        category_id: String,
        enabled: bool,
    ) -> io::Result<()> {
        match self
            .send(&Request::SetCategoryEnabled {
                category_id,
                enabled,
            })
            .await?
        {
            Response::Success { .. } => Ok(()),
            Response::Error { message } => Err(io::Error::other(message)),
            _ => Err(unexpected_response()),
        }
    }

    pub async fn resume_process(&mut self, pid: u32) -> io::Result<()> {
        match self.send(&Request::ResumeProcess { pid }).await? {
            Response::Success { .. } => Ok(()),
            Response::Error { message } => Err(io::Error::other(message)),
            _ => Err(unexpected_response()),
        }
    }

    pub async fn get_learning_status(&mut self) -> io::Result<LearningStatus> {
        match self.send(&Request::GetLearningStatus).await? {
            Response::LearningStatus {
                state,
                hours_remaining,
                pending_count,
                approved_count,
                rejected_count,
            } => Ok(LearningStatus {
                state,
                hours_remaining,
                pending_count,
                approved_count,
                rejected_count,
            }),
            Response::Error { message } => Err(io::Error::other(message)),
            _ => Err(unexpected_response()),
        }
    }

    pub async fn get_learning_recommendations(&mut self) -> io::Result<Vec<LearningRecommendation>> {
        match self.send(&Request::GetLearningRecommendations).await? {
            Response::LearningRecommendations { recommendations } => Ok(recommendations),
            Response::Error { message } => Err(io::Error::other(message)),
            _ => Err(unexpected_response()),
        }
    }

    pub async fn approve_learning(&mut self, id: i64) -> io::Result<()> {
        match self.send(&Request::ApproveLearning { id }).await? {
            Response::Success { .. } => Ok(()),
            Response::Error { message } => Err(io::Error::other(message)),
            _ => Err(unexpected_response()),
        }
    }

    pub async fn reject_learning(&mut self, id: i64) -> io::Result<()> {
        match self.send(&Request::RejectLearning { id }).await? {
            Response::Success { .. } => Ok(()),
            Response::Error { message } => Err(io::Error::other(message)),
            _ => Err(unexpected_response()),
        }
    }

    pub async fn approve_all_learnings(&mut self) -> io::Result<()> {
        match self.send(&Request::ApproveAllLearnings).await? {
            Response::Success { .. } => Ok(()),
            Response::Error { message } => Err(io::Error::other(message)),
            _ => Err(unexpected_response()),
        }
    }

    pub async fn reject_all_learnings(&mut self) -> io::Result<()> {
        match self.send(&Request::RejectAllLearnings).await? {
            Response::Success { .. } => Ok(()),
            Response::Error { message } => Err(io::Error::other(message)),
            _ => Err(unexpected_response()),
        }
    }

    pub async fn complete_learning_review(&mut self) -> io::Result<()> {
        match self.send(&Request::CompleteLearningReview).await? {
            Response::Success { .. } => Ok(()),
            Response::Error { message } => Err(io::Error::other(message)),
            _ => Err(unexpected_response()),
        }
    }

    pub async fn end_learning_early(&mut self) -> io::Result<()> {
        match self.send(&Request::EndLearningEarly).await? {
            Response::Success { .. } => Ok(()),
            Response::Error { message } => Err(io::Error::other(message)),
            _ => Err(unexpected_response()),
        }
    }
}
