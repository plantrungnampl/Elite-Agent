use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use local_agent_terminal_bootstrap::{
    ApprovalId, Bootstrap, CancelToolExecutionRequestDto, CommandErrorDto,
    ConfirmDiscardWorkspaceRequestDto, ContextPackageDto, CreateTaskWorkspaceRequestDto,
    DeliberationResumeActionDto, DeliberationRuntime, DeliberationWorkspaceDto,
    GetApprovalRequestDto, GetContextPackageRequestDto, GetDeliberationWorkspaceRequestDto,
    LocalDiagnosticDto, OnboardRepositoryRequestDto, PlanApprovalResolutionDto, ProjectSnapshot,
    RecoveryCandidateRequestDto, ResolveDisplayedPlanApprovalRequestDto,
    ResolveToolApprovalRequestDto, ResumeDeliberationRequestDto, Sha256Digest, StartupConfig,
    StartupStatusDto, StopAllToolsReceiptDto, TaskSnapshot, ToolActivityDto,
    ToolApprovalRequestDto, ToolApprovalResolutionDto, ToolCancellationReceiptDto, ToolRuntime,
    WorkspaceDashboardDto, WorkspaceDashboardRequestDto, WorkspaceRuntime,
};
use tauri::Manager;

struct ManagedBootstrap {
    bootstrap: Mutex<Bootstrap>,
    trusted_config: Option<StartupConfig>,
}

impl ManagedBootstrap {
    fn resolve_with(resolve: impl FnOnce() -> Option<PathBuf>) -> Self {
        let bootstrap = resolve()
            .map(config)
            .map(Bootstrap::production)
            .unwrap_or_else(Bootstrap::configuration_unavailable);
        Self {
            bootstrap: Mutex::new(bootstrap),
            trusted_config: None,
        }
    }

    fn from_config(config: StartupConfig) -> Self {
        Self {
            bootstrap: Mutex::new(Bootstrap::production(config.clone())),
            trusted_config: Some(config),
        }
    }

    fn status(&self) -> StartupStatusDto {
        match self.bootstrap.lock() {
            Ok(bootstrap) => bootstrap.status().clone(),
            Err(_) => Bootstrap::internal_state_unavailable().status().clone(),
        }
    }

    fn retry_with(&self, resolve: impl FnOnce() -> Option<PathBuf>) -> StartupStatusDto {
        let next_config = self
            .trusted_config
            .clone()
            .or_else(|| resolve().map(config));
        match self.bootstrap.lock() {
            Ok(mut bootstrap) => match next_config {
                Some(config) => bootstrap.reconfigure_production(config).clone(),
                None => {
                    *bootstrap = Bootstrap::configuration_unavailable();
                    bootstrap.status().clone()
                }
            },
            Err(_) => Bootstrap::internal_state_unavailable().status().clone(),
        }
    }

    fn diagnostics(&self) -> Vec<LocalDiagnosticDto> {
        match self.bootstrap.lock() {
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
            .bootstrap
            .lock()
            .map_err(|_| CommandErrorDto::internal_state_unavailable())?;
        let runtime = bootstrap
            .workspace_runtime()
            .ok_or_else(CommandErrorDto::startup_not_ready)?;
        operation(runtime)
    }

    fn with_tool_runtime<T>(
        &self,
        operation: impl FnOnce(Arc<ToolRuntime>) -> Result<T, CommandErrorDto>,
    ) -> Result<T, CommandErrorDto> {
        let runtime = self
            .bootstrap
            .lock()
            .map_err(|_| CommandErrorDto::internal_state_unavailable())?
            .tool_runtime_handle()
            .ok_or_else(CommandErrorDto::startup_not_ready)?;
        operation(runtime)
    }

    fn with_deliberation_runtime<T>(
        &self,
        operation: impl FnOnce(Arc<DeliberationRuntime>) -> Result<T, CommandErrorDto>,
    ) -> Result<T, CommandErrorDto> {
        let runtime = self
            .bootstrap
            .lock()
            .map_err(|_| CommandErrorDto::internal_state_unavailable())?
            .deliberation_runtime_handle()
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

#[tauri::command]
fn get_tool_activity(
    state: tauri::State<'_, ManagedBootstrap>,
) -> Result<ToolActivityDto, CommandErrorDto> {
    state.with_tool_runtime(|runtime| runtime.activity().map_err(CommandErrorDto::from))
}

#[tauri::command]
fn get_approval_request(
    request: GetApprovalRequestDto,
    state: tauri::State<'_, ManagedBootstrap>,
) -> Result<ToolApprovalRequestDto, CommandErrorDto> {
    state.with_tool_runtime(|runtime| {
        runtime
            .approval_request(
                local_agent_terminal_bootstrap::ApprovalId::new(request.approval_id)
                    .map_err(CommandErrorDto::from)?,
            )
            .map_err(CommandErrorDto::from)
    })
}

#[tauri::command]
fn resolve_tool_approval(
    request: ResolveToolApprovalRequestDto,
    state: tauri::State<'_, ManagedBootstrap>,
) -> Result<ToolApprovalResolutionDto, CommandErrorDto> {
    state.with_tool_runtime(|runtime| {
        runtime
            .resolve_approval(request)
            .map_err(CommandErrorDto::from)
    })
}

#[tauri::command]
fn cancel_tool_execution(
    request: CancelToolExecutionRequestDto,
    state: tauri::State<'_, ManagedBootstrap>,
) -> Result<ToolCancellationReceiptDto, CommandErrorDto> {
    state.with_tool_runtime(|runtime| {
        runtime
            .cancel_for_ui(request)
            .map_err(CommandErrorDto::from)
    })
}

#[tauri::command]
fn stop_all_tools(
    state: tauri::State<'_, ManagedBootstrap>,
) -> Result<StopAllToolsReceiptDto, CommandErrorDto> {
    state.with_tool_runtime(|runtime| runtime.stop_all_for_ui().map_err(CommandErrorDto::from))
}

#[tauri::command]
fn get_deliberation_workspace(
    request: GetDeliberationWorkspaceRequestDto,
    state: tauri::State<'_, ManagedBootstrap>,
) -> Result<DeliberationWorkspaceDto, CommandErrorDto> {
    get_deliberation_workspace_from_state(request, &state)
}

fn get_deliberation_workspace_from_state(
    request: GetDeliberationWorkspaceRequestDto,
    state: &ManagedBootstrap,
) -> Result<DeliberationWorkspaceDto, CommandErrorDto> {
    validate_opaque_id(&request.task_id)?;
    state.with_deliberation_runtime(|runtime| {
        runtime
            .workspace(&request.task_id)
            .map_err(CommandErrorDto::from)
    })
}

#[tauri::command]
fn resume_deliberation(
    request: ResumeDeliberationRequestDto,
    state: tauri::State<'_, ManagedBootstrap>,
) -> Result<DeliberationResumeActionDto, CommandErrorDto> {
    resume_deliberation_from_state(request, &state)
}

fn resume_deliberation_from_state(
    request: ResumeDeliberationRequestDto,
    state: &ManagedBootstrap,
) -> Result<DeliberationResumeActionDto, CommandErrorDto> {
    validate_opaque_id(&request.task_id)?;
    state.with_deliberation_runtime(|runtime| {
        runtime
            .resume_deliberation(&request.task_id)
            .map_err(CommandErrorDto::from)
    })
}

#[tauri::command]
fn get_context_package(
    request: GetContextPackageRequestDto,
    state: tauri::State<'_, ManagedBootstrap>,
) -> Result<ContextPackageDto, CommandErrorDto> {
    get_context_package_from_state(request, &state)
}

fn get_context_package_from_state(
    request: GetContextPackageRequestDto,
    state: &ManagedBootstrap,
) -> Result<ContextPackageDto, CommandErrorDto> {
    validate_opaque_id(&request.package_id)?;
    state.with_deliberation_runtime(|runtime| {
        runtime
            .context_package(&request.package_id)
            .map_err(CommandErrorDto::from)
    })
}

#[tauri::command]
fn resolve_plan_approval(
    request: ResolveDisplayedPlanApprovalRequestDto,
    state: tauri::State<'_, ManagedBootstrap>,
) -> Result<PlanApprovalResolutionDto, CommandErrorDto> {
    resolve_plan_approval_from_state(request, &state)
}

fn resolve_plan_approval_from_state(
    request: ResolveDisplayedPlanApprovalRequestDto,
    state: &ManagedBootstrap,
) -> Result<PlanApprovalResolutionDto, CommandErrorDto> {
    validate_opaque_id(&request.approval_id)?;
    let request = request.with_actor("user");
    ApprovalId::new(&request.approval_id).map_err(CommandErrorDto::from)?;
    Sha256Digest::new(&request.displayed_digest).map_err(|_| invalid_deliberation_request())?;
    if request.expected_task_version == 0 {
        return Err(invalid_deliberation_request());
    }
    state.with_deliberation_runtime(|runtime| {
        runtime
            .resolve_plan_approval(request)
            .map_err(CommandErrorDto::from)
    })
}

fn validate_opaque_id(value: &str) -> Result<(), CommandErrorDto> {
    if !value.is_empty()
        && value.len() <= 256
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
    {
        Ok(())
    } else {
        Err(invalid_deliberation_request())
    }
}

fn invalid_deliberation_request() -> CommandErrorDto {
    CommandErrorDto {
        code: "invalid_input".to_owned(),
        message: "The deliberation command request is invalid.".to_owned(),
        retryable: false,
    }
}

fn config(app_data_dir: PathBuf) -> StartupConfig {
    StartupConfig {
        trusted_workspace_root: app_data_dir.join("workspaces"),
        app_data_dir,
        secret_values: Vec::new(),
        openai: None,
        anthropic: None,
    }
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    run_with_startup_config(None);
}

pub fn run_with_config(config: StartupConfig) {
    run_with_startup_config(Some(config));
}

fn run_with_startup_config(mut trusted_config: Option<StartupConfig>) {
    tauri::Builder::default()
        .setup(move |app| {
            let managed = trusted_config.take().map_or_else(
                || ManagedBootstrap::resolve_with(|| app.path().app_data_dir().ok()),
                ManagedBootstrap::from_config,
            );
            app.manage(managed);
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
            discard_workspace,
            get_tool_activity,
            get_approval_request,
            resolve_tool_approval,
            cancel_tool_execution,
            stop_all_tools,
            get_deliberation_workspace,
            resume_deliberation,
            get_context_package,
            resolve_plan_approval
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}

#[cfg(test)]
mod tests {
    use std::panic::{catch_unwind, AssertUnwindSafe};

    use super::{
        get_context_package_from_state, get_deliberation_workspace_from_state,
        resolve_plan_approval_from_state, resume_deliberation_from_state,
        GetContextPackageRequestDto, GetDeliberationWorkspaceRequestDto, ManagedBootstrap,
        ResolveDisplayedPlanApprovalRequestDto, ResumeDeliberationRequestDto,
    };
    use local_agent_terminal_bootstrap::{
        CancelToolExecutionRequestDto, GetApprovalRequestDto, ResolveToolApprovalRequestDto,
        StartupStateDto, ToolRuntimeAvailabilityDto,
    };
    use tempfile::TempDir;

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
        let activity = managed
            .with_tool_runtime(|runtime| runtime.activity().map_err(Into::into))
            .unwrap();
        assert_eq!(activity.availability, ToolRuntimeAvailabilityDto::Ready);
    }

    #[test]
    fn poisoned_managed_state_never_serves_stale_ready() {
        let parent = TempDir::new().unwrap();
        let managed = ManagedBootstrap::resolve_with(|| Some(parent.path().join("app-data")));
        assert_eq!(managed.status().state, StartupStateDto::Ready);
        assert!(catch_unwind(AssertUnwindSafe(|| {
            let _guard = managed.bootstrap.lock().unwrap();
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

    #[test]
    fn tool_command_requests_reject_replacement_payloads_and_unknown_fields() {
        assert!(
            serde_json::from_value::<ResolveToolApprovalRequestDto>(serde_json::json!({
                "approvalId": "approval-1",
                "expectedOperationDigest": format!("sha256:{}", "a".repeat(64)),
                "decision": "approve",
                "toolArguments": ["replacement"]
            }))
            .is_err()
        );
        assert!(
            serde_json::from_value::<CancelToolExecutionRequestDto>(serde_json::json!({
                "executionId": "execution-1",
                "force": true
            }))
            .is_err()
        );
        assert!(
            serde_json::from_value::<GetApprovalRequestDto>(serde_json::json!({
                "approvalId": "approval-1",
                "operationDigest": format!("sha256:{}", "b".repeat(64))
            }))
            .is_err()
        );
    }

    #[test]
    fn production_startup_composes_the_tool_broker() {
        let parent = TempDir::new().unwrap();
        let managed = ManagedBootstrap::resolve_with(|| Some(parent.path().join("app-data")));

        let activity = managed
            .with_tool_runtime(|runtime| runtime.activity().map_err(Into::into))
            .unwrap();
        assert_eq!(activity.availability, ToolRuntimeAvailabilityDto::Ready);
        assert!(activity.entries.is_empty());
    }

    #[test]
    fn trusted_startup_config_is_retained_across_retry() {
        let parent = TempDir::new().unwrap();
        let managed =
            ManagedBootstrap::from_config(super::config(parent.path().join("configured-app-data")));

        assert_eq!(managed.status().state, StartupStateDto::Ready);
        assert_eq!(
            managed
                .retry_with(|| panic!("trusted retry must not re-resolve configuration"))
                .state,
            StartupStateDto::Ready
        );
    }

    #[test]
    fn deliberation_command_requests_reject_replacement_payloads_and_unknown_fields() {
        assert!(
            serde_json::from_value::<GetDeliberationWorkspaceRequestDto>(serde_json::json!({
                "taskId": "task-1",
                "workflow": { "phase": "Implementation" }
            }))
            .is_err()
        );
        assert!(
            serde_json::from_value::<GetContextPackageRequestDto>(serde_json::json!({
                "packageId": "context-1",
                "physicalPath": "D:\\repo\\secret.txt"
            }))
            .is_err()
        );
        assert!(
            serde_json::from_value::<ResumeDeliberationRequestDto>(serde_json::json!({
                "taskId": "task-1",
                "providerPayload": { "model": "replacement" }
            }))
            .is_err()
        );
        assert!(
            serde_json::from_value::<ResolveDisplayedPlanApprovalRequestDto>(serde_json::json!({
                "approvalId": "approval-1",
                "displayedDigest": format!("sha256:{}", "a".repeat(64)),
                "expectedTaskVersion": 9,
                "action": "approve",
                "rawPlan": { "tools": ["shell"] }
            }))
            .is_err()
        );

        for forbidden in [
            "providerPayload",
            "policy",
            "physicalPath",
            "event",
            "tool",
            "workflow",
        ] {
            let mut hostile = serde_json::json!({
                "approvalId": "approval-1",
                "displayedDigest": format!("sha256:{}", "a".repeat(64)),
                "expectedTaskVersion": 9,
                "action": "approve"
            });
            hostile
                .as_object_mut()
                .unwrap()
                .insert(forbidden.to_owned(), serde_json::json!("untrusted"));
            assert!(
                serde_json::from_value::<ResolveDisplayedPlanApprovalRequestDto>(hostile).is_err()
            );
        }

        let request =
            serde_json::from_value::<ResolveDisplayedPlanApprovalRequestDto>(serde_json::json!({
                "approvalId": "approval-1",
                "displayedDigest": format!("sha256:{}", "a".repeat(64)),
                "expectedTaskVersion": 9,
                "action": "approve"
            }))
            .unwrap()
            .with_actor("user");
        assert_eq!(request.actor_id, "user");
        assert_eq!(request.approval_id, "approval-1");
    }

    #[test]
    fn deliberation_command_handlers_are_backed_by_bootstrap_state() {
        let parent = TempDir::new().unwrap();
        let state = ManagedBootstrap::resolve_with(|| Some(parent.path().join("app-data")));

        let workspace = get_deliberation_workspace_from_state(
            GetDeliberationWorkspaceRequestDto {
                task_id: "task-missing".to_owned(),
            },
            &state,
        )
        .unwrap_err();
        assert_eq!(workspace.code, "not_found");

        let package = get_context_package_from_state(
            GetContextPackageRequestDto {
                package_id: "package-missing".to_owned(),
            },
            &state,
        )
        .unwrap_err();
        assert_eq!(package.code, "not_found");

        let resume = resume_deliberation_from_state(
            ResumeDeliberationRequestDto {
                task_id: "task-missing".to_owned(),
            },
            &state,
        )
        .unwrap_err();
        assert_eq!(resume.code, "unavailable");

        let approval = resolve_plan_approval_from_state(
            serde_json::from_value(serde_json::json!({
                "approvalId": "approval-missing",
                "displayedDigest": format!("sha256:{}", "a".repeat(64)),
                "expectedTaskVersion": 1,
                "action": "approve"
            }))
            .unwrap(),
            &state,
        )
        .unwrap_err();
        assert_eq!(approval.code, "not_found");
    }
}
