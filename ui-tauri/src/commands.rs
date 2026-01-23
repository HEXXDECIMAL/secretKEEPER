use std::sync::Arc;
use tokio::sync::Mutex;

use crate::ipc_client::{AddExceptionParams, AgentStatus, Exception, IpcClient, ViolationEvent};

type IpcState = Arc<Mutex<IpcClient>>;

#[tauri::command]
pub async fn get_status(client: tauri::State<'_, IpcState>) -> Result<AgentStatus, String> {
    let mut client = client.lock().await;
    client.get_status().await.map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn get_mode(client: tauri::State<'_, IpcState>) -> Result<String, String> {
    let mut client = client.lock().await;
    client.get_mode().await.map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn set_mode(client: tauri::State<'_, IpcState>, mode: String) -> Result<(), String> {
    let mut client = client.lock().await;
    client.set_mode(mode).await.map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn get_violations(
    client: tauri::State<'_, IpcState>,
    limit: Option<usize>,
) -> Result<Vec<ViolationEvent>, String> {
    let mut client = client.lock().await;
    client
        .get_violations(limit, None)
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn get_exceptions(client: tauri::State<'_, IpcState>) -> Result<Vec<Exception>, String> {
    let mut client = client.lock().await;
    client.get_exceptions().await.map_err(|e| e.to_string())
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
    let mut client = client.lock().await;

    let expires_at = expires_hours.map(|h| chrono::Utc::now() + chrono::Duration::hours(h));

    let params = AddExceptionParams {
        process_path,
        signer_type,
        team_id,
        signing_id,
        file_pattern,
        is_glob,
        expires_at,
        comment,
    };

    client
        .add_exception(params)
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn remove_exception(client: tauri::State<'_, IpcState>, id: i64) -> Result<(), String> {
    let mut client = client.lock().await;
    client.remove_exception(id).await.map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn allow_once(
    client: tauri::State<'_, IpcState>,
    event_id: String,
) -> Result<(), String> {
    let mut client = client.lock().await;
    client.allow_once(event_id).await.map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn allow_permanently(
    client: tauri::State<'_, IpcState>,
    event_id: String,
    expires_hours: Option<i64>,
    comment: Option<String>,
) -> Result<(), String> {
    let mut client = client.lock().await;

    let expires_at = expires_hours.map(|h| chrono::Utc::now() + chrono::Duration::hours(h));

    client
        .allow_permanently(event_id, expires_at, comment)
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn kill_process(
    client: tauri::State<'_, IpcState>,
    event_id: String,
) -> Result<(), String> {
    let mut client = client.lock().await;
    client
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
