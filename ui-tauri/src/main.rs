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

            // Start IPC connection in background
            let app_handle = app.handle();
            tauri::async_runtime::spawn(async move {
                let client = app_handle.state::<Arc<Mutex<IpcClient>>>();
                let mut client = client.lock().await;

                if let Err(e) = client.connect().await {
                    eprintln!("Failed to connect to agent: {}", e);
                    return;
                }

                // Update tray status
                if let Some(tray) = app_handle.tray_handle().try_get_item("status") {
                    let _ = tray.set_title("Status: Connected");
                }

                // Subscribe to events
                if let Err(e) = client.subscribe(None).await {
                    eprintln!("Failed to subscribe: {}", e);
                    return;
                }

                // Event loop
                loop {
                    match client.read_event().await {
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
                        Ok(None) => continue,
                        Err(e) => {
                            eprintln!("IPC error: {}", e);
                            break;
                        }
                    }
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
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
