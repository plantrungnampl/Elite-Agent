use std::sync::{Mutex, MutexGuard};

use local_agent_terminal_bootstrap::{
    Bootstrap, LocalDiagnosticDto, StartupConfig, StartupStatusDto,
};
use tauri::Manager;

struct ManagedBootstrap(Mutex<Bootstrap>);

#[tauri::command]
fn get_startup_status(state: tauri::State<'_, ManagedBootstrap>) -> StartupStatusDto {
    lock(&state).status().clone()
}

#[tauri::command]
fn retry_startup_validation(state: tauri::State<'_, ManagedBootstrap>) -> StartupStatusDto {
    lock(&state).retry_startup_validation().clone()
}

#[tauri::command]
fn get_local_diagnostics(state: tauri::State<'_, ManagedBootstrap>) -> Vec<LocalDiagnosticDto> {
    lock(&state).local_diagnostics().to_vec()
}

fn lock(state: &ManagedBootstrap) -> MutexGuard<'_, Bootstrap> {
    state.0.lock().unwrap_or_else(|error| error.into_inner())
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .setup(|app| {
            let app_data_dir = app.path().app_data_dir()?;
            app.manage(ManagedBootstrap(Mutex::new(Bootstrap::new(
                StartupConfig {
                    app_data_dir,
                    secret_values: Vec::new(),
                },
            ))));
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            get_startup_status,
            retry_startup_validation,
            get_local_diagnostics
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
