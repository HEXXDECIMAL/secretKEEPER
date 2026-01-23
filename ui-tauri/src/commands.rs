use std::sync::Arc;
use tokio::sync::Mutex;

use crate::ipc_client::{
    AddExceptionParams, AgentStatus, Category, Exception, IpcClient, ViolationEvent,
};

type IpcState = Arc<Mutex<IpcClient>>;

/// Violation with computed fields for the frontend
#[derive(serde::Serialize)]
pub struct ViolationDisplay {
    #[serde(flatten)]
    event: ViolationEvent,
    process_name: String,
    signing_status: &'static str,
}

impl From<ViolationEvent> for ViolationDisplay {
    fn from(event: ViolationEvent) -> Self {
        let process_name = event.process_name();
        let signing_status = event.signing_status();
        Self {
            event,
            process_name,
            signing_status,
        }
    }
}

#[tauri::command]
pub async fn get_status(client: tauri::State<'_, IpcState>) -> Result<AgentStatus, String> {
    client
        .lock()
        .await
        .get_status()
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn get_mode(client: tauri::State<'_, IpcState>) -> Result<String, String> {
    client
        .lock()
        .await
        .get_status()
        .await
        .map(|s| s.mode)
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn set_mode(client: tauri::State<'_, IpcState>, mode: String) -> Result<(), String> {
    client
        .lock()
        .await
        .set_mode(mode)
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn get_violations(
    client: tauri::State<'_, IpcState>,
    limit: Option<usize>,
) -> Result<Vec<ViolationDisplay>, String> {
    client
        .lock()
        .await
        .get_violations(limit, None)
        .await
        .map(|vs| vs.into_iter().map(ViolationDisplay::from).collect())
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn get_exceptions(client: tauri::State<'_, IpcState>) -> Result<Vec<Exception>, String> {
    client
        .lock()
        .await
        .get_exceptions()
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
#[allow(clippy::too_many_arguments)]
pub async fn add_exception(
    client: tauri::State<'_, IpcState>,
    process_path: Option<String>,
    signer_type: Option<String>,
    team_id: Option<String>,
    signing_id: Option<String>,
    file_pattern: String,
    is_glob: bool,
    expires_hours: Option<i64>,
    comment: Option<String>,
) -> Result<(), String> {
    let expires_at = expires_hours.map(|h| chrono::Utc::now() + chrono::Duration::hours(h));

    client
        .lock()
        .await
        .add_exception(AddExceptionParams {
            process_path,
            signer_type,
            team_id,
            signing_id,
            file_pattern,
            is_glob,
            expires_at,
            comment,
        })
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn remove_exception(client: tauri::State<'_, IpcState>, id: i64) -> Result<(), String> {
    client
        .lock()
        .await
        .remove_exception(id)
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn allow_once(
    client: tauri::State<'_, IpcState>,
    event_id: String,
) -> Result<(), String> {
    client
        .lock()
        .await
        .allow_once(event_id)
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn allow_permanently(
    client: tauri::State<'_, IpcState>,
    event_id: String,
    expires_hours: Option<i64>,
    comment: Option<String>,
) -> Result<(), String> {
    let expires_at = expires_hours.map(|h| chrono::Utc::now() + chrono::Duration::hours(h));
    client
        .lock()
        .await
        .allow_permanently(event_id, expires_at, comment)
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn kill_process(
    client: tauri::State<'_, IpcState>,
    event_id: String,
) -> Result<(), String> {
    client
        .lock()
        .await
        .kill_process(event_id)
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn reconnect(client: tauri::State<'_, IpcState>) -> Result<(), String> {
    let mut client = client.lock().await;
    client.disconnect().await;
    client.connect().await.map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn get_categories(client: tauri::State<'_, IpcState>) -> Result<Vec<Category>, String> {
    client
        .lock()
        .await
        .get_categories()
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn set_category_enabled(
    client: tauri::State<'_, IpcState>,
    category_id: String,
    enabled: bool,
) -> Result<(), String> {
    client
        .lock()
        .await
        .set_category_enabled(category_id, enabled)
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn resume_process(client: tauri::State<'_, IpcState>, pid: u32) -> Result<(), String> {
    client
        .lock()
        .await
        .resume_process(pid)
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn export_violations(
    client: tauri::State<'_, IpcState>,
    limit: Option<usize>,
) -> Result<String, String> {
    let violations = client
        .lock()
        .await
        .get_violations(limit, None)
        .await
        .map_err(|e| e.to_string())?;

    serde_json::to_string_pretty(&violations).map_err(|e| e.to_string())
}
