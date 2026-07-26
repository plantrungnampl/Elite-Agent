use std::path::PathBuf;
use std::sync::Mutex;

use local_agent_terminal_bootstrap::{
    Bootstrap, CommandErrorDto, ConfirmDiscardWorkspaceRequestDto, CreateTaskWorkspaceRequestDto,
    LocalDiagnosticDto, OnboardRepositoryRequestDto, ProjectSnapshot, RecoveryCandidateRequestDto,
    StartupConfig, StartupStatusDto, TaskSnapshot, WorkspaceDashboardDto,
    WorkspaceDashboardRequestDto, WorkspaceRuntime,
};
use tauri::Manager;

struct ManagedBootstrap(Mutex<Bootstrap>);

impl ManagedBootstrap {
    fn resolve_with(resolve: impl FnOnce() -> Option<PathBuf>) -> Self {
        let bootstrap = resolve()
            .map(config)
            .map(Bootstrap::new)
            .unwrap_or_else(Bootstrap::configuration_unavailable);
        Self(Mutex::new(bootstrap))
    }

    fn status(&self) -> StartupStatusDto {
        match self.0.lock() {
            Ok(bootstrap) => bootstrap.status().clone(),
            Err(_) => Bootstrap::internal_state_unavailable().status().clone(),
        }
    }

    fn retry_with(&self, resolve: impl FnOnce() -> Option<PathBuf>) -> StartupStatusDto {
        match self.0.lock() {
            Ok(mut bootstrap) => match resolve() {
                Some(app_data_dir) => bootstrap.reconfigure(config(app_data_dir)).clone(),
                None => {
                    *bootstrap = Bootstrap::configuration_unavailable();
                    bootstrap.status().clone()
                }
            },
            Err(_) => Bootstrap::internal_state_unavailable().status().clone(),
        }
    }

    fn diagnostics(&self) -> Vec<LocalDiagnosticDto> {
        match self.0.lock() {
            Ok(bootstrap) => bootstrap.local_diagnostics().to_vec(),
            Err(_) => Bootstrap::internal_state_unavailable()
                .local_diagnostics()
                .to_vec(),
        }
    }

    fn with_runtime<T>(
        &self,
        operation: impl FnOnce(&WorkspaceRuntime) -> Result<T, CommandErrorDto>,
    ) -> Result<T, CommandErrorDto> {
        let bootstrap = self
            .0
            .lock()
            .map_err(|_| CommandErrorDto::internal_state_unavailable())?;
        let runtime = bootstrap
            .workspace_runtime()
            .ok_or_else(CommandErrorDto::startup_not_ready)?;
        operation(runtime)
    }
}

#[tauri::command]
fn get_startup_status(state: tauri::State<'_, ManagedBootstrap>) -> StartupStatusDto {
    state.status()
}

#[tauri::command]
fn retry_startup_validation(
    app: tauri::AppHandle,
    state: tauri::State<'_, ManagedBootstrap>,
) -> StartupStatusDto {
    state.retry_with(|| app.path().app_data_dir().ok())
}

#[tauri::command]
fn get_local_diagnostics(state: tauri::State<'_, ManagedBootstrap>) -> Vec<LocalDiagnosticDto> {
    state.diagnostics()
}

#[tauri::command]
fn get_workspace_dashboard(
    request: WorkspaceDashboardRequestDto,
    state: tauri::State<'_, ManagedBootstrap>,
) -> Result<WorkspaceDashboardDto, CommandErrorDto> {
    state.with_runtime(|runtime| {
        runtime
            .get_workspace_dashboard(request)
            .map_err(CommandErrorDto::from)
    })
}

#[tauri::command]
fn onboard_repository(
    request: OnboardRepositoryRequestDto,
    state: tauri::State<'_, ManagedBootstrap>,
) -> Result<ProjectSnapshot, CommandErrorDto> {
    state.with_runtime(|runtime| {
        runtime
            .onboard_repository(request)
            .map_err(CommandErrorDto::from)
    })
}

#[tauri::command]
fn create_task_workspace(
    request: CreateTaskWorkspaceRequestDto,
    state: tauri::State<'_, ManagedBootstrap>,
) -> Result<TaskSnapshot, CommandErrorDto> {
    state.with_runtime(|runtime| {
        runtime
            .create_task_workspace(request)
            .map_err(CommandErrorDto::from)
    })
}

#[tauri::command]
fn reconcile_workspace(
    request: RecoveryCandidateRequestDto,
    state: tauri::State<'_, ManagedBootstrap>,
) -> Result<WorkspaceDashboardDto, CommandErrorDto> {
    state.with_runtime(|runtime| {
        runtime
            .reconcile_workspace(request)
            .map_err(CommandErrorDto::from)
    })
}

#[tauri::command]
fn preserve_workspace(
    request: RecoveryCandidateRequestDto,
    state: tauri::State<'_, ManagedBootstrap>,
) -> Result<WorkspaceDashboardDto, CommandErrorDto> {
    state.with_runtime(|runtime| {
        runtime
            .preserve_workspace(request)
            .map_err(CommandErrorDto::from)
    })
}

#[tauri::command]
fn discard_workspace(
    request: ConfirmDiscardWorkspaceRequestDto,
    state: tauri::State<'_, ManagedBootstrap>,
) -> Result<WorkspaceDashboardDto, CommandErrorDto> {
    state.with_runtime(|runtime| {
        runtime
            .discard_workspace(request)
            .map_err(CommandErrorDto::from)
    })
}

fn config(app_data_dir: PathBuf) -> StartupConfig {
    StartupConfig {
        trusted_workspace_root: app_data_dir.join("workspaces"),
        app_data_dir,
        secret_values: Vec::new(),
    }
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .setup(|app| {
            app.manage(ManagedBootstrap::resolve_with(|| {
                app.path().app_data_dir().ok()
            }));
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            get_startup_status,
            retry_startup_validation,
            get_local_diagnostics,
            get_workspace_dashboard,
            onboard_repository,
            create_task_workspace,
            reconcile_workspace,
            preserve_workspace,
            discard_workspace
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}

#[cfg(test)]
mod tests {
    use std::panic::{catch_unwind, AssertUnwindSafe};

    use local_agent_terminal_bootstrap::StartupStateDto;
    use tempfile::TempDir;

    use super::ManagedBootstrap;

    #[test]
    fn resolver_failure_is_typed_and_retry_re_resolves_before_ready() {
        let managed = ManagedBootstrap::resolve_with(|| None);

        assert_eq!(
            managed.status().issues[0].code,
            "startup.app_data_resolution_failed"
        );
        assert_ne!(managed.status().state, StartupStateDto::Ready);

        assert_ne!(managed.retry_with(|| None).state, StartupStateDto::Ready);
        let parent = TempDir::new().unwrap();
        assert_eq!(
            managed
                .retry_with(|| Some(parent.path().join("app-data")))
                .state,
            StartupStateDto::Ready
        );
    }

    #[test]
    fn poisoned_managed_state_never_serves_stale_ready() {
        let parent = TempDir::new().unwrap();
        let managed = ManagedBootstrap::resolve_with(|| Some(parent.path().join("app-data")));
        assert_eq!(managed.status().state, StartupStateDto::Ready);
        assert!(catch_unwind(AssertUnwindSafe(|| {
            let _guard = managed.0.lock().unwrap();
            panic!("poison managed bootstrap");
        }))
        .is_err());

        let status = managed.status();
        let diagnostics = managed.diagnostics();

        assert_ne!(status.state, StartupStateDto::Ready);
        assert_eq!(status.issues[0].code, "startup.internal_state_unavailable");
        assert_eq!(
            status.issues[0]
                .recovery_actions
                .iter()
                .map(|action| action.code.as_str())
                .collect::<Vec<_>>(),
            ["restart_application", "get_local_diagnostics"]
        );
        assert_eq!(diagnostics[0].code, "startup.internal_state_unavailable");
        assert_ne!(
            managed
                .retry_with(|| Some(parent.path().join("app-data")))
                .state,
            StartupStateDto::Ready
        );
    }
}
