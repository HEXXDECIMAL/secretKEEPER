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
    pub process_name: String,
    pub process_pid: u32,
    pub parent_pid: Option<u32>,
    pub process_euid: Option<u32>,
    pub process_cmdline: Option<String>,
    pub team_id: Option<String>,
    pub signing_id: Option<String>,
    pub signing_status: String,
    pub action: String,
    pub process_tree: Vec<ProcessTreeEntry>,
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
    pub is_platform_binary: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentStatus {
    pub mode: String,
    pub uptime_secs: i64,
    pub total_violations: u64,
    pub active_exceptions: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Exception {
    pub id: i64,
    pub process_path: Option<String>,
    pub code_signer: Option<String>,
    pub file_pattern: String,
    pub is_glob: bool,
    pub expires_at: Option<DateTime<Utc>>,
    pub added_by: String,
    pub comment: Option<String>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum Request {
    Subscribe {
        filter: Option<EventFilter>,
    },
    Unsubscribe,
    Status,
    GetMode,
    SetMode {
        mode: String,
    },
    AllowOnce {
        event_id: String,
    },
    AllowPermanently {
        event_id: String,
        expires_at: Option<DateTime<Utc>>,
        comment: Option<String>,
    },
    Kill {
        event_id: String,
    },
    GetViolations {
        limit: Option<usize>,
        since: Option<DateTime<Utc>>,
    },
    GetExceptions,
    AddException {
        process_path: Option<String>,
        code_signer: Option<String>,
        file_pattern: String,
        is_glob: bool,
        expires_at: Option<DateTime<Utc>>,
        comment: Option<String>,
    },
    RemoveException {
        id: i64,
    },
    Ping,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct EventFilter {
    pub process_path: Option<String>,
    pub file_pattern: Option<String>,
    pub action: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Response {
    Ok,
    Error { message: String },
    Status { status: AgentStatus },
    Mode { mode: String },
    Violations { violations: Vec<ViolationEvent> },
    Exceptions { exceptions: Vec<Exception> },
    Event { event: Box<ViolationEvent> },
    Pong,
}

pub struct IpcClient {
    stream: Option<BufReader<UnixStream>>,
    write_half: Option<tokio::net::unix::OwnedWriteHalf>,
}

impl IpcClient {
    pub fn new() -> Self {
        Self {
            stream: None,
            write_half: None,
        }
    }

    pub async fn connect(&mut self) -> io::Result<()> {
        let stream = UnixStream::connect(SOCKET_PATH).await?;
        self.stream = Some(BufReader::new(stream));
        Ok(())
    }

    #[allow(dead_code)]
    pub fn is_connected(&self) -> bool {
        self.stream.is_some()
    }

    pub async fn disconnect(&mut self) {
        self.stream = None;
        self.write_half = None;
    }

    async fn send_request(&mut self, request: &Request) -> io::Result<Response> {
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

        serde_json::from_str(&line)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))
    }

    pub async fn subscribe(&mut self, filter: Option<EventFilter>) -> io::Result<()> {
        let response = self.send_request(&Request::Subscribe { filter }).await?;
        match response {
            Response::Ok => Ok(()),
            Response::Error { message } => Err(io::Error::other(message)),
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Unexpected response",
            )),
        }
    }

    pub async fn read_event(&mut self) -> io::Result<Option<ViolationEvent>> {
        let stream = self
            .stream
            .as_mut()
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotConnected, "Not connected"))?;

        let mut line = String::new();
        let n = stream.read_line(&mut line).await?;

        if n == 0 {
            return Ok(None);
        }

        let response: Response = serde_json::from_str(&line)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;

        match response {
            Response::Event { event } => Ok(Some(*event)),
            _ => Ok(None),
        }
    }

    pub async fn get_status(&mut self) -> io::Result<AgentStatus> {
        let response = self.send_request(&Request::Status).await?;
        match response {
            Response::Status { status } => Ok(status),
            Response::Error { message } => Err(io::Error::other(message)),
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Unexpected response",
            )),
        }
    }

    pub async fn get_mode(&mut self) -> io::Result<String> {
        let response = self.send_request(&Request::GetMode).await?;
        match response {
            Response::Mode { mode } => Ok(mode),
            Response::Error { message } => Err(io::Error::other(message)),
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Unexpected response",
            )),
        }
    }

    pub async fn set_mode(&mut self, mode: String) -> io::Result<()> {
        let response = self.send_request(&Request::SetMode { mode }).await?;
        match response {
            Response::Ok => Ok(()),
            Response::Error { message } => Err(io::Error::other(message)),
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Unexpected response",
            )),
        }
    }

    pub async fn get_violations(
        &mut self,
        limit: Option<usize>,
        since: Option<DateTime<Utc>>,
    ) -> io::Result<Vec<ViolationEvent>> {
        let response = self
            .send_request(&Request::GetViolations { limit, since })
            .await?;
        match response {
            Response::Violations { violations } => Ok(violations),
            Response::Error { message } => Err(io::Error::other(message)),
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Unexpected response",
            )),
        }
    }

    pub async fn get_exceptions(&mut self) -> io::Result<Vec<Exception>> {
        let response = self.send_request(&Request::GetExceptions).await?;
        match response {
            Response::Exceptions { exceptions } => Ok(exceptions),
            Response::Error { message } => Err(io::Error::other(message)),
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Unexpected response",
            )),
        }
    }

    pub async fn add_exception(
        &mut self,
        process_path: Option<String>,
        code_signer: Option<String>,
        file_pattern: String,
        is_glob: bool,
        expires_at: Option<DateTime<Utc>>,
        comment: Option<String>,
    ) -> io::Result<()> {
        let response = self
            .send_request(&Request::AddException {
                process_path,
                code_signer,
                file_pattern,
                is_glob,
                expires_at,
                comment,
            })
            .await?;
        match response {
            Response::Ok => Ok(()),
            Response::Error { message } => Err(io::Error::other(message)),
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Unexpected response",
            )),
        }
    }

    pub async fn remove_exception(&mut self, id: i64) -> io::Result<()> {
        let response = self.send_request(&Request::RemoveException { id }).await?;
        match response {
            Response::Ok => Ok(()),
            Response::Error { message } => Err(io::Error::other(message)),
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Unexpected response",
            )),
        }
    }

    pub async fn allow_once(&mut self, event_id: String) -> io::Result<()> {
        let response = self.send_request(&Request::AllowOnce { event_id }).await?;
        match response {
            Response::Ok => Ok(()),
            Response::Error { message } => Err(io::Error::other(message)),
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Unexpected response",
            )),
        }
    }

    pub async fn allow_permanently(
        &mut self,
        event_id: String,
        expires_at: Option<DateTime<Utc>>,
        comment: Option<String>,
    ) -> io::Result<()> {
        let response = self
            .send_request(&Request::AllowPermanently {
                event_id,
                expires_at,
                comment,
            })
            .await?;
        match response {
            Response::Ok => Ok(()),
            Response::Error { message } => Err(io::Error::other(message)),
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Unexpected response",
            )),
        }
    }

    pub async fn kill_process(&mut self, event_id: String) -> io::Result<()> {
        let response = self.send_request(&Request::Kill { event_id }).await?;
        match response {
            Response::Ok => Ok(()),
            Response::Error { message } => Err(io::Error::other(message)),
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Unexpected response",
            )),
        }
    }

    #[allow(dead_code)]
    pub async fn ping(&mut self) -> io::Result<()> {
        let response = self.send_request(&Request::Ping).await?;
        match response {
            Response::Pong => Ok(()),
            Response::Error { message } => Err(io::Error::other(message)),
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Unexpected response",
            )),
        }
    }
}
