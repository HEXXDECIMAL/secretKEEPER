use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::io;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;

const SOCKET_PATH: &str = "/var/run/secretkeeper.sock";

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
}

fn unexpected_response() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "Unexpected response")
}

pub struct IpcClient {
    stream: Option<BufReader<UnixStream>>,
}

impl IpcClient {
    pub fn new() -> Self {
        Self { stream: None }
    }

    pub async fn connect(&mut self) -> io::Result<()> {
        let stream = UnixStream::connect(SOCKET_PATH).await?;
        self.stream = Some(BufReader::new(stream));
        Ok(())
    }

    pub async fn disconnect(&mut self) {
        self.stream = None;
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
        stream.read_line(&mut line).await?;

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

    pub async fn read_event(&mut self) -> io::Result<Option<ViolationEvent>> {
        let stream = self
            .stream
            .as_mut()
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotConnected, "Not connected"))?;

        let mut line = String::new();
        if stream.read_line(&mut line).await? == 0 {
            return Ok(None);
        }

        let response: Response = serde_json::from_str(&line)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;

        match response {
            Response::Event(event) => Ok(Some(event)),
            _ => Ok(None),
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
}
