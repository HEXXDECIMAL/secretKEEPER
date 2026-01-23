#![cfg_attr(
    all(not(debug_assertions), target_os = "windows"),
    windows_subsystem = "windows"
)]

mod commands;
mod ipc_client;

use std::sync::Arc;
use tauri::{
    CustomMenuItem, Manager, SystemTray, SystemTrayEvent, SystemTrayMenu, SystemTrayMenuItem,
    WindowEvent,
};
use tokio::sync::Mutex;

use ipc_client::IpcClient;

fn update_tray_status(app_handle: &tauri::AppHandle, status: &str) {
    if let Some(tray) = app_handle.tray_handle().try_get_item("status") {
        let _ = tray.set_title(status);
    }
}

fn update_tray_for_learning(
    app_handle: &tauri::AppHandle,
    learning_status: &ipc_client::LearningStatus,
) {
    let status_text = match learning_status.state.as_str() {
        "learning" => format!(
            "🎓 Learning Mode ({} hours left)",
            learning_status.hours_remaining
        ),
        "pending_review" => format!(
            "⚠️ Review Required ({} pending)",
            learning_status.pending_count
        ),
        _ => "Status: Protected".to_string(),
    };
    update_tray_status(app_handle, &status_text);
}

fn main() {
    let tray_menu = SystemTrayMenu::new()
        .add_item(CustomMenuItem::new("status", "Status: Connecting...").disabled())
        .add_native_item(SystemTrayMenuItem::Separator)
        .add_item(CustomMenuItem::new("history", "Violation History"))
        .add_item(CustomMenuItem::new("exceptions", "Exception Manager"))
        .add_item(CustomMenuItem::new("settings", "Settings"))
        .add_native_item(SystemTrayMenuItem::Separator)
        .add_item(CustomMenuItem::new("quit", "Quit"));

    let system_tray = SystemTray::new().with_menu(tray_menu);

    tauri::Builder::default()
        .setup(|app| {
            let ipc_client = Arc::new(Mutex::new(IpcClient::new()));
            app.manage(ipc_client.clone());

            // Start IPC connection in background with reconnection support
            let app_handle = app.handle();
            tauri::async_runtime::spawn(async move {
                let client_state = app_handle.state::<Arc<Mutex<IpcClient>>>();
                let reconnect_delay = std::time::Duration::from_secs(5);
                let event_timeout = std::time::Duration::from_secs(10);

                loop {
                    // Update tray to show connecting status
                    update_tray_status(&app_handle, "Status: Connecting...");

                    // Try to connect (release lock between attempts)
                    let connected = {
                        let mut client = client_state.lock().await;
                        match client.connect().await {
                            Ok(()) => true,
                            Err(e) => {
                                eprintln!("Failed to connect to agent: {}", e);
                                false
                            }
                        }
                    };

                    if !connected {
                        update_tray_status(&app_handle, "Status: Disconnected");
                        tokio::time::sleep(reconnect_delay).await;
                        continue;
                    }

                    // Subscribe to events
                    let subscribed = {
                        let mut client = client_state.lock().await;
                        match client.subscribe(None).await {
                            Ok(()) => true,
                            Err(e) => {
                                eprintln!("Failed to subscribe: {}", e);
                                client.disconnect().await;
                                false
                            }
                        }
                    };

                    if !subscribed {
                        update_tray_status(&app_handle, "Status: Error");
                        tokio::time::sleep(reconnect_delay).await;
                        continue;
                    }

                    // Check learning status and update tray accordingly
                    {
                        let mut client = client_state.lock().await;
                        if let Ok(learning_status) = client.get_learning_status().await {
                            update_tray_for_learning(&app_handle, &learning_status);
                        } else {
                            update_tray_status(&app_handle, "Status: Connected");
                        }
                    }

                    // Event loop - release mutex between reads
                    loop {
                        let result = {
                            let mut client = client_state.lock().await;
                            client.read_event_timeout(event_timeout).await
                        };

                        match result {
                            Ok(Some(event)) => {
                                // Emit event to frontend
                                let _ = app_handle.emit_all("violation", &event);

                                // Show alert window
                                if let Some(window) = app_handle.get_window("alert") {
                                    let _ = window.emit("violation", &event);
                                    let _ = window.show();
                                    let _ = window.set_focus();
                                }
                            }
                            Ok(None) => {
                                // Timeout - no events, check connection is still alive and refresh learning status
                                let mut client = client_state.lock().await;
                                if client.ping().await.is_err() {
                                    eprintln!("Lost connection to agent (ping failed)");
                                    break;
                                }
                                // Refresh learning status in tray
                                if let Ok(learning_status) = client.get_learning_status().await {
                                    update_tray_for_learning(&app_handle, &learning_status);
                                }
                            }
                            Err(e) => {
                                eprintln!("IPC error: {}", e);
                                break;
                            }
                        }
                    }

                    // Disconnected - update status and retry
                    {
                        let mut client = client_state.lock().await;
                        client.disconnect().await;
                    }
                    update_tray_status(&app_handle, "Status: Reconnecting...");
                    tokio::time::sleep(reconnect_delay).await;
                }
            });

            Ok(())
        })
        .system_tray(system_tray)
        .on_system_tray_event(|app, event| match event {
            SystemTrayEvent::MenuItemClick { id, .. } => match id.as_str() {
                "history" => {
                    if let Some(window) = app.get_window("main") {
                        let _ = window.emit("navigate", "history");
                        let _ = window.show();
                        let _ = window.set_focus();
                    }
                }
                "exceptions" => {
                    if let Some(window) = app.get_window("main") {
                        let _ = window.emit("navigate", "exceptions");
                        let _ = window.show();
                        let _ = window.set_focus();
                    }
                }
                "settings" => {
                    if let Some(window) = app.get_window("main") {
                        let _ = window.emit("navigate", "settings");
                        let _ = window.show();
                        let _ = window.set_focus();
                    }
                }
                "quit" => {
                    std::process::exit(0);
                }
                _ => {}
            },
            SystemTrayEvent::LeftClick { .. } => {
                if let Some(window) = app.get_window("main") {
                    let _ = window.show();
                    let _ = window.set_focus();
                }
            }
            _ => {}
        })
        .on_window_event(|event| {
            if let WindowEvent::CloseRequested { api, .. } = event.event() {
                // Hide instead of close for main window
                let _ = event.window().hide();
                api.prevent_close();
            }
        })
        .invoke_handler(tauri::generate_handler![
            commands::get_status,
            commands::get_mode,
            commands::set_mode,
            commands::get_violations,
            commands::get_exceptions,
            commands::add_exception,
            commands::remove_exception,
            commands::allow_once,
            commands::allow_permanently,
            commands::kill_process,
            commands::reconnect,
            commands::get_categories,
            commands::set_category_enabled,
            commands::resume_process,
            commands::export_violations,
            commands::get_learning_status,
            commands::get_learning_recommendations,
            commands::approve_learning,
            commands::reject_learning,
            commands::approve_all_learnings,
            commands::reject_all_learnings,
            commands::complete_learning_review,
            commands::end_learning_early,
            commands::restart_learning,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
