use std::fs;
use std::path::PathBuf;
use std::sync::Arc;

use local_agent_terminal_application::{
    AgentRuntime, ApprovalExpiryStore, Clock, DiagnosticSeverityDto, LocalDiagnosticDto,
    ObservationClassDto, PortError, RetainedProcessController, SafeErrorClassification,
    StartupIssueDto, StartupRecoveryActionDto, StartupStateDto, StartupStatusDto,
    ToolExecutionStore, TrustLabelDto,
};
#[cfg(windows)]
use local_agent_terminal_platform_windows::WindowsProcessLauncher;
use local_agent_terminal_repository_git::GitRepositoryGateway;
use local_agent_terminal_storage_files::{
    reconcile_artifacts, ContentAddressedArtifactStore, RecoveryLock,
};
use local_agent_terminal_storage_sqlite::{DatabaseHealth, DatabaseIssue, OpenError, SqliteStore};

use crate::agent_runtime::{
    compose_agent_runtime, AnthropicBootstrapConfig, ComposedAgentRuntime, OpenAiBootstrapConfig,
};
use crate::context_runtime::{compose_context_runtime, ContextRuntime};
use crate::deliberation_runtime::{compose_deliberation_runtime, DeliberationRuntime};
use crate::logging::LocalLog;
#[cfg(windows)]
use crate::production_tools::production_tool_broker;
use crate::tool_runtime::{
    ToolBrokerConfig, ToolControlSelfTestStatus, ToolRuntime, ToolRuntimeAvailability,
};
use crate::workspace_runtime::{
    fence_stale_leases, reconcile_workspace_after_fencing, WorkspaceRuntime,
};

#[derive(Clone)]
pub struct StartupConfig {
    pub app_data_dir: PathBuf,
    pub trusted_workspace_root: PathBuf,
    pub secret_values: Vec<String>,
    pub openai: Option<OpenAiBootstrapConfig>,
    pub anthropic: Option<AnthropicBootstrapConfig>,
}

pub struct Bootstrap {
    config: Option<StartupConfig>,
    status: StartupStatusDto,
    diagnostics: Vec<LocalDiagnosticDto>,
    runtime: Option<WorkspaceRuntime>,
    context_runtime: Option<Arc<ContextRuntime>>,
    deliberation_runtime: Option<Arc<DeliberationRuntime>>,
    agent_runtime: Option<Arc<ComposedAgentRuntime>>,
    tool_runtime: Option<Arc<ToolRuntime>>,
    tool_broker: Option<ToolBrokerConfig>,
    retained_processes: Arc<dyn RetainedProcessController>,
}

struct StartupRuntimes {
    workspace: WorkspaceRuntime,
    context: Arc<ContextRuntime>,
    deliberation: Arc<DeliberationRuntime>,
    agent_runtime: Option<Arc<ComposedAgentRuntime>>,
    tools: ToolRuntime,
}

#[cfg(windows)]
fn default_retained_process_controller() -> Arc<dyn RetainedProcessController> {
    Arc::new(WindowsProcessLauncher::fail_closed())
}

#[cfg(not(windows))]
struct UnavailableRetainedProcessController;

#[cfg(not(windows))]
impl RetainedProcessController for UnavailableRetainedProcessController {
    fn terminate_retained_process(
        &self,
        _binding: &local_agent_terminal_application::AuthoritativeProcessBinding,
    ) -> Result<local_agent_terminal_application::CancellationReceipt, PortError> {
        Err(PortError::failure(
            SafeErrorClassification::Unavailable,
            local_agent_terminal_application::Retryability::NonRetryable,
        ))
    }
}

#[cfg(not(windows))]
fn default_retained_process_controller() -> Arc<dyn RetainedProcessController> {
    Arc::new(UnavailableRetainedProcessController)
}

struct StartupFailure {
    state: StartupStateDto,
    code: &'static str,
    message: &'static str,
    category: &'static str,
    detail: String,
    recovery: RecoveryMode,
}

#[derive(Clone, Copy)]
enum RecoveryMode {
    Retry,
    Restart,
}

impl Bootstrap {
    pub fn new(config: StartupConfig) -> Self {
        Self::configured(config, None)
    }

    pub fn production(config: StartupConfig) -> Self {
        #[cfg(windows)]
        let tool_broker = Some(production_tool_broker(&config));
        #[cfg(not(windows))]
        let tool_broker = None;
        Self::configured(config, tool_broker)
    }

    pub fn with_tool_broker(config: StartupConfig, tool_broker: ToolBrokerConfig) -> Self {
        Self::configured(config, Some(tool_broker))
    }

    #[cfg(test)]
    pub(crate) fn with_agent_runtime_for_test(
        config: StartupConfig,
        agent_runtime: Arc<ComposedAgentRuntime>,
    ) -> Self {
        Self::with_runtimes_for_test(config, Some(agent_runtime), None)
    }

    #[cfg(test)]
    pub(crate) fn with_runtimes_for_test(
        config: StartupConfig,
        agent_runtime: Option<Arc<ComposedAgentRuntime>>,
        tool_runtime: Option<Arc<ToolRuntime>>,
    ) -> Self {
        Self {
            config: Some(config),
            status: StartupStatusDto {
                state: StartupStateDto::Ready,
                issues: Vec::new(),
            },
            diagnostics: Vec::new(),
            runtime: None,
            context_runtime: None,
            deliberation_runtime: None,
            agent_runtime,
            tool_runtime,
            tool_broker: None,
            retained_processes: default_retained_process_controller(),
        }
    }

    fn configured(config: StartupConfig, tool_broker: Option<ToolBrokerConfig>) -> Self {
        let mut bootstrap = Self {
            config: Some(config),
            status: StartupStatusDto {
                state: StartupStateDto::RecoverableFailure,
                issues: Vec::new(),
            },
            diagnostics: Vec::new(),
            runtime: None,
            context_runtime: None,
            deliberation_runtime: None,
            agent_runtime: None,
            tool_runtime: None,
            tool_broker,
            retained_processes: default_retained_process_controller(),
        };
        bootstrap.retry_startup_validation();
        bootstrap
    }

    pub fn configuration_unavailable() -> Self {
        Self::failed(StartupFailure {
            state: StartupStateDto::RecoverableFailure,
            code: "startup.app_data_resolution_failed",
            message: "Local application storage could not be located.",
            category: "configuration",
            detail: "The application data directory resolver did not return a usable location."
                .to_owned(),
            recovery: RecoveryMode::Retry,
        })
    }

    pub fn internal_state_unavailable() -> Self {
        Self::failed(StartupFailure {
            state: StartupStateDto::Indeterminate,
            code: "startup.internal_state_unavailable",
            message: "Startup state is unavailable and cannot be trusted.",
            category: "internal",
            detail: "Managed startup state was invalidated after an internal failure.".to_owned(),
            recovery: RecoveryMode::Restart,
        })
    }

    pub fn reconfigure(&mut self, config: StartupConfig) -> &StartupStatusDto {
        self.config = Some(config);
        self.retry_startup_validation()
    }

    pub fn reconfigure_production(&mut self, config: StartupConfig) -> &StartupStatusDto {
        #[cfg(windows)]
        {
            self.tool_broker = Some(production_tool_broker(&config));
        }
        #[cfg(not(windows))]
        {
            self.tool_broker = None;
        }
        self.reconfigure(config)
    }

    pub fn status(&self) -> &StartupStatusDto {
        &self.status
    }

    pub fn retry_startup_validation(&mut self) -> &StartupStatusDto {
        let Some(secret_values) = self
            .config
            .as_ref()
            .map(|config| config.secret_values.clone())
        else {
            return &self.status;
        };
        let mut log = LocalLog::new(secret_values);
        if let Err(failure) = self.shutdown_owned_runtimes() {
            self.record_failure(&mut log, failure);
            self.diagnostics = log.into_records();
            return &self.status;
        }
        let result = start(
            self.config
                .as_ref()
                .expect("configuration was checked before runtime shutdown"),
            &mut log,
            self.tool_broker.clone(),
            Arc::clone(&self.retained_processes),
        );
        match result {
            Ok(runtimes) => {
                self.status = StartupStatusDto {
                    state: StartupStateDto::Ready,
                    issues: Vec::new(),
                };
                self.runtime = Some(runtimes.workspace);
                self.context_runtime = Some(runtimes.context);
                self.deliberation_runtime = Some(runtimes.deliberation);
                self.agent_runtime = runtimes.agent_runtime;
                self.tool_runtime = Some(Arc::new(runtimes.tools));
                log.push(record(
                    "startup.ready",
                    "bootstrap",
                    DiagnosticSeverityDto::Info,
                    None,
                    "Startup validation completed.",
                ));
                let release = self
                    .tool_runtime
                    .as_ref()
                    .expect("successful startup always attaches the tool runtime before release");
                match release_tool_dispatch(release) {
                    Ok(true) => log.push(record(
                        "startup.tools.dispatch_released",
                        "bootstrap",
                        DiagnosticSeverityDto::Info,
                        None,
                        "Tool dispatch released after startup recovery completed.",
                    )),
                    Ok(false) => {}
                    Err(error) => match self.shutdown_owned_runtimes() {
                        Ok(()) => self.record_failure(&mut log, tool_recovery_failure(error)),
                        Err(shutdown_failure) => self.record_failure(&mut log, shutdown_failure),
                    },
                }
            }
            Err(failure) => self.record_failure(&mut log, failure),
        }
        self.diagnostics = log.into_records();
        &self.status
    }

    pub fn local_diagnostics(&self) -> &[LocalDiagnosticDto] {
        &self.diagnostics
    }

    pub fn workspace_runtime(&self) -> Option<&WorkspaceRuntime> {
        self.runtime.as_ref()
    }

    pub fn context_runtime(&self) -> Option<&ContextRuntime> {
        self.context_runtime.as_deref()
    }

    pub fn deliberation_runtime(&self) -> Option<&DeliberationRuntime> {
        self.deliberation_runtime.as_deref()
    }

    pub fn deliberation_runtime_handle(&self) -> Option<Arc<DeliberationRuntime>> {
        self.deliberation_runtime.clone()
    }

    pub fn agent_runtime(&self) -> Option<&dyn AgentRuntime> {
        self.agent_runtime
            .as_deref()
            .map(|runtime| runtime as &dyn AgentRuntime)
    }

    pub fn agent_runtime_handle(&self) -> Option<Arc<dyn AgentRuntime>> {
        self.agent_runtime
            .as_ref()
            .map(|runtime| Arc::clone(runtime) as Arc<dyn AgentRuntime>)
    }

    pub fn tool_runtime(&self) -> Option<&ToolRuntime> {
        self.tool_runtime.as_deref()
    }

    pub fn tool_runtime_handle(&self) -> Option<Arc<ToolRuntime>> {
        self.tool_runtime.clone()
    }

    fn record_failure(&mut self, log: &mut LocalLog, failure: StartupFailure) {
        log.push(record(
            failure.code,
            "bootstrap",
            DiagnosticSeverityDto::Error,
            Some(failure.category),
            &failure.detail,
        ));
        self.status = StartupStatusDto {
            state: failure.state,
            issues: vec![StartupIssueDto {
                code: failure.code.to_owned(),
                message: failure.message.to_owned(),
                recovery_actions: recovery_actions(failure.recovery),
            }],
        };
        self.runtime = None;
        self.context_runtime = None;
        self.deliberation_runtime = None;
    }

    fn shutdown_owned_runtimes(&mut self) -> Result<(), StartupFailure> {
        let agent_error = self.shutdown_agent_runtime().err();
        let tool_error = self.shutdown_tool_runtime().err();
        self.runtime = None;
        self.context_runtime = None;
        self.deliberation_runtime = None;

        if let Some(error) = agent_error {
            return Err(agent_runtime_shutdown_failure(error));
        }
        if let Some(error) = tool_error {
            return Err(tool_recovery_failure(error));
        }
        Ok(())
    }

    fn shutdown_agent_runtime(&mut self) -> Result<(), PortError> {
        let Some(runtime) = self.agent_runtime.as_ref() else {
            return Ok(());
        };
        runtime.shutdown()?;
        self.agent_runtime = None;
        Ok(())
    }

    fn shutdown_tool_runtime(&mut self) -> Result<(), PortError> {
        let Some(runtime) = self.tool_runtime.as_ref() else {
            return Ok(());
        };
        runtime.stop_all()?;
        self.tool_runtime = None;
        Ok(())
    }

    fn failed(failure: StartupFailure) -> Self {
        let mut log = LocalLog::new(Vec::new());
        log.push(record(
            failure.code,
            "bootstrap",
            DiagnosticSeverityDto::Error,
            Some(failure.category),
            &failure.detail,
        ));
        Self {
            config: None,
            status: StartupStatusDto {
                state: failure.state,
                issues: vec![StartupIssueDto {
                    code: failure.code.to_owned(),
                    message: failure.message.to_owned(),
                    recovery_actions: recovery_actions(failure.recovery),
                }],
            },
            diagnostics: log.into_records(),
            runtime: None,
            context_runtime: None,
            deliberation_runtime: None,
            agent_runtime: None,
            tool_runtime: None,
            tool_broker: None,
            retained_processes: default_retained_process_controller(),
        }
    }
}

impl Drop for Bootstrap {
    fn drop(&mut self) {
        let _ = self.shutdown_owned_runtimes();
    }
}

fn start(
    config: &StartupConfig,
    log: &mut LocalLog,
    tool_broker: Option<ToolBrokerConfig>,
    retained_processes: Arc<dyn RetainedProcessController>,
) -> Result<StartupRuntimes, StartupFailure> {
    let workspace_writes = tool_broker
        .as_ref()
        .map(ToolBrokerConfig::workspace_writes)
        .unwrap_or_else(|| {
            Arc::new(local_agent_terminal_application::WorkspaceWriteCoordinator::new())
        });
    let _recovery_lock =
        RecoveryLock::acquire(&config.app_data_dir).map_err(recovery_lock_failure)?;
    log.push(record(
        "startup.recovery_lock.acquired",
        "bootstrap",
        DiagnosticSeverityDto::Info,
        None,
        "Exclusive startup recovery lock acquired.",
    ));
    log.push(record(
        "startup.app_directories.validated",
        "bootstrap",
        DiagnosticSeverityDto::Info,
        None,
        "Required application directories are available.",
    ));

    let database = SqliteStore::open(config.app_data_dir.join("state.sqlite3"))
        .map_err(database_open_failure)?;
    match database.database_health() {
        DatabaseHealth::Healthy => {}
        DatabaseHealth::Unhealthy(issue) => return Err(database_health_failure(issue)),
    }
    log.push(record(
        "startup.database.validated",
        "storage-sqlite",
        DiagnosticSeverityDto::Info,
        None,
        "Database schema and integrity checks passed.",
    ));

    let artifacts = Arc::new(
        ContentAddressedArtifactStore::open(config.app_data_dir.join("artifacts"))
            .map_err(|error| artifact_failure("startup.artifact_storage_unavailable", error))?,
    );
    artifacts
        .validate_health()
        .map_err(|error| artifact_failure("startup.artifact_storage_unavailable", error))?;
    log.push(record(
        "startup.artifacts.validated",
        "storage-files",
        DiagnosticSeverityDto::Info,
        None,
        "Artifact storage passed capability-relative read/write validation.",
    ));

    let report = reconcile_artifacts(artifacts.as_ref(), &database, &database)
        .map_err(reconciliation_failure)?;
    log.push(record(
        "startup.artifacts.reconciled",
        "storage-files",
        DiagnosticSeverityDto::Info,
        None,
        &format!(
            "Artifact reconciliation completed: completed={}, aborted={}, quarantined={}, invalidated={}.",
            report.completed, report.aborted, report.quarantined, report.invalidated
        ),
    ));

    let fenced_leases = fence_stale_leases(&database).map_err(workspace_reconciliation_failure)?;
    log.push(record(
        "startup.leases.fenced",
        "storage-sqlite",
        DiagnosticSeverityDto::Info,
        None,
        &format!(
            "Stale executor lease fencing completed: fenced={}.",
            fenced_leases
        ),
    ));

    let tool_database = SqliteStore::open(config.app_data_dir.join("state.sqlite3"))
        .map_err(database_open_failure)?;
    let tools = match tool_broker {
        Some(tool_broker) => {
            let tool_artifacts =
                ContentAddressedArtifactStore::open(config.app_data_dir.join("artifacts"))
                    .map_err(|error| {
                        artifact_failure("startup.artifact_storage_unavailable", error)
                    })?;
            ToolRuntime::with_broker(tool_database, tool_artifacts, tool_broker)
                .map_err(tool_recovery_failure)?
        }
        None => {
            let executions: Arc<dyn ToolExecutionStore> = Arc::new(tool_database);
            ToolRuntime::recovery_only(executions, retained_processes)
        }
    };
    let survivor_report = tools.inspect_survivors().map_err(tool_recovery_failure)?;
    log.push(record(
        "startup.tools.survivors_inspected",
        "bootstrap",
        DiagnosticSeverityDto::Info,
        None,
        &format!(
            "Tool survivor inspection completed: control_self_test={}, interrupted={}, indeterminate={}, terminated_jobs={}, survivor_failures={}.",
            tool_control_self_test_name(survivor_report.control_self_test),
            survivor_report.interrupted,
            survivor_report.indeterminate,
            survivor_report.terminated_retained_jobs,
            survivor_report.survivor_inspection_failures,
        ),
    ));

    fs::create_dir_all(&config.trusted_workspace_root).map_err(|_| StartupFailure {
        state: StartupStateDto::RecoverableFailure,
        code: "startup.workspace_root_unavailable",
        message: "The managed workspace root could not be prepared.",
        category: "unavailable",
        detail: "Managed workspace directory creation failed.".to_owned(),
        recovery: RecoveryMode::Retry,
    })?;
    let artifact_root = config.app_data_dir.join("artifacts");
    let repositories = GitRepositoryGateway::open(&config.trusted_workspace_root, &[artifact_root])
        .map_err(workspace_reconciliation_failure)?;
    let workspace_report =
        reconcile_workspace_after_fencing(&database, artifacts.as_ref(), &repositories)
            .map_err(workspace_reconciliation_failure)?;
    log.push(record(
        "startup.repositories.reconciled",
        "repository-git",
        DiagnosticSeverityDto::Info,
        None,
        &format!(
            "Managed repository reconciliation completed: scanned={}.",
            workspace_report.repositories_scanned
        ),
    ));

    let file_writes = tools.recover_file_writes().map_err(tool_recovery_failure)?;
    log.push(record(
        "startup.file_writes.reconciled",
        "bootstrap",
        DiagnosticSeverityDto::Info,
        None,
        &format!(
            "Durable file-write reconciliation completed: terminalized={}.",
            file_writes.len()
        ),
    ));

    let tool_report = tools.reconcile_intents().map_err(tool_recovery_failure)?;
    let tool_availability = tools.availability().map_err(tool_recovery_failure)?;
    log.push(record(
        "startup.tools.reconciled",
        "bootstrap",
        DiagnosticSeverityDto::Info,
        None,
        &format!(
            "Tool intent reconciliation completed: recovered={}, availability={}.",
            tool_report.recovered,
            tool_availability_name(tool_availability),
        ),
    ));
    log.push(record(
        "startup.intents.reconciled",
        "bootstrap",
        DiagnosticSeverityDto::Info,
        None,
        &format!(
            "Operation intent reconciliation completed: candidates={}.",
            workspace_report.recovery_candidates.len()
        ),
    ));

    let approval_observed_at = database
        .now_utc()
        .map_err(approval_reconciliation_failure)?;
    let expired_approvals = database
        .expire_before(&approval_observed_at)
        .map_err(approval_reconciliation_failure)?;
    log.push(record(
        "startup.approvals.expired",
        "storage-sqlite",
        DiagnosticSeverityDto::Info,
        None,
        &format!(
            "Expired approval reconciliation completed: expired={}.",
            expired_approvals
        ),
    ));
    let invalidated_approvals = database
        .invalidate_unrevalidated()
        .map_err(approval_reconciliation_failure)?;
    log.push(record(
        "startup.approvals.revalidated",
        "storage-sqlite",
        DiagnosticSeverityDto::Info,
        None,
        &format!(
            "Open approval revalidation completed: invalidated={}.",
            invalidated_approvals
        ),
    ));

    let context_repositories = GitRepositoryGateway::open(
        &config.trusted_workspace_root,
        &[config.app_data_dir.join("artifacts")],
    )
    .map_err(workspace_reconciliation_failure)?;
    let context = compose_context_runtime(
        database.clone(),
        Arc::clone(&artifacts),
        context_repositories,
    )
    .map_err(context_runtime_failure)?;
    let agent_runtime = compose_agent_runtime(
        database.clone(),
        Arc::clone(&artifacts),
        Arc::clone(&context),
        config.openai.as_ref(),
        config.anthropic.as_ref(),
    )
    .map_err(agent_runtime_failure)?;
    if agent_runtime.is_some() {
        log.push(record(
            "startup.agent_runtime.composed",
            "bootstrap",
            DiagnosticSeverityDto::Info,
            None,
            "Configured trusted agent runtime was composed.",
        ));
    }
    if let Some(runtime) = agent_runtime.as_ref() {
        context
            .attach_agents(Arc::clone(runtime) as Arc<dyn AgentRuntime>)
            .map_err(context_runtime_failure)?;
    }
    let deliberation_repositories = GitRepositoryGateway::open(
        &config.trusted_workspace_root,
        &[config.app_data_dir.join("artifacts")],
    )
    .map_err(workspace_reconciliation_failure)?;
    let deliberation = compose_deliberation_runtime(
        database.clone(),
        Arc::clone(&artifacts),
        deliberation_repositories,
        context.policy_snapshot_digest().clone(),
        agent_runtime.clone(),
    );

    Ok(StartupRuntimes {
        workspace: WorkspaceRuntime::new(
            database,
            artifacts,
            repositories,
            workspace_report.recovery_candidates,
            workspace_writes,
        ),
        context,
        deliberation,
        agent_runtime,
        tools,
    })
}

fn release_tool_dispatch(tools: &ToolRuntime) -> Result<bool, PortError> {
    if matches!(
        tools.availability()?,
        ToolRuntimeAvailability::Ready | ToolRuntimeAvailability::DegradedReadOnly
    ) {
        tools.release_dispatch()?;
        return Ok(true);
    }
    Ok(false)
}

const fn tool_availability_name(availability: ToolRuntimeAvailability) -> &'static str {
    match availability {
        ToolRuntimeAvailability::Ready => "ready",
        ToolRuntimeAvailability::DegradedReadOnly => "degraded_read_only",
        ToolRuntimeAvailability::Unavailable => "unavailable",
    }
}

const fn tool_control_self_test_name(status: ToolControlSelfTestStatus) -> &'static str {
    match status {
        ToolControlSelfTestStatus::NotConfigured => "not_configured",
        ToolControlSelfTestStatus::Passed => "passed",
        ToolControlSelfTestStatus::Failed => "failed",
    }
}

fn workspace_reconciliation_failure(error: PortError) -> StartupFailure {
    StartupFailure {
        state: StartupStateDto::Indeterminate,
        code: "startup.workspace_reconciliation_failed",
        message: "Workspace recovery could not determine a safe startup state.",
        category: classification_name(error.safe_classification()),
        detail: format!(
            "Workspace reconciliation failed ({:?}, {:?}).",
            error.safe_classification(),
            error.retryability()
        ),
        recovery: RecoveryMode::Retry,
    }
}

fn tool_recovery_failure(error: PortError) -> StartupFailure {
    StartupFailure {
        state: StartupStateDto::Indeterminate,
        code: "startup.tool_recovery_failed",
        message: "Tool recovery could not determine a safe startup state.",
        category: classification_name(error.safe_classification()),
        detail: format!(
            "Tool recovery failed ({:?}, {:?}).",
            error.safe_classification(),
            error.retryability()
        ),
        recovery: RecoveryMode::Retry,
    }
}

fn agent_runtime_failure(error: PortError) -> StartupFailure {
    StartupFailure {
        state: StartupStateDto::RecoverableFailure,
        code: "startup.agent_runtime_unavailable",
        message: "The configured agent runtime could not be composed.",
        category: classification_name(error.safe_classification()),
        detail: format!(
            "Configured agent runtime composition failed ({:?}, {:?}).",
            error.safe_classification(),
            error.retryability()
        ),
        recovery: RecoveryMode::Retry,
    }
}

fn context_runtime_failure(error: PortError) -> StartupFailure {
    StartupFailure {
        state: StartupStateDto::RecoverableFailure,
        code: "startup.context_runtime_unavailable",
        message: "The context runtime could not be composed.",
        category: classification_name(error.safe_classification()),
        detail: format!(
            "Context runtime composition failed ({:?}, {:?}).",
            error.safe_classification(),
            error.retryability()
        ),
        recovery: RecoveryMode::Retry,
    }
}

fn agent_runtime_shutdown_failure(error: PortError) -> StartupFailure {
    StartupFailure {
        state: StartupStateDto::RecoverableFailure,
        code: "startup.agent_runtime_shutdown_failed",
        message: "The configured agent runtime could not be shut down safely.",
        category: classification_name(error.safe_classification()),
        detail: format!(
            "Configured agent runtime shutdown failed ({:?}, {:?}).",
            error.safe_classification(),
            error.retryability()
        ),
        recovery: RecoveryMode::Retry,
    }
}

fn approval_reconciliation_failure(error: PortError) -> StartupFailure {
    StartupFailure {
        state: StartupStateDto::Indeterminate,
        code: "startup.approval_reconciliation_failed",
        message: "Approval recovery could not determine a safe startup state.",
        category: classification_name(error.safe_classification()),
        detail: format!(
            "Approval reconciliation failed ({:?}, {:?}).",
            error.safe_classification(),
            error.retryability()
        ),
        recovery: RecoveryMode::Retry,
    }
}

fn recovery_lock_failure(error: PortError) -> StartupFailure {
    if error.safe_classification() == SafeErrorClassification::Unavailable {
        StartupFailure {
            state: StartupStateDto::RecoverableFailure,
            code: "startup.recovery_lock_unavailable",
            message: "Another application instance is validating local state.",
            category: "unavailable",
            detail: "Exclusive startup recovery lock could not be acquired.".to_owned(),
            recovery: RecoveryMode::Retry,
        }
    } else {
        artifact_failure("startup.app_directories_unavailable", error)
    }
}

fn artifact_failure(code: &'static str, error: PortError) -> StartupFailure {
    StartupFailure {
        state: StartupStateDto::RecoverableFailure,
        code,
        message: "Required local application storage could not be validated.",
        category: classification_name(error.safe_classification()),
        detail: format!(
            "Local storage validation failed ({:?}, {:?}).",
            error.safe_classification(),
            error.retryability()
        ),
        recovery: RecoveryMode::Retry,
    }
}

fn database_open_failure(error: OpenError) -> StartupFailure {
    match error {
        OpenError::ChecksumMismatch { .. } => StartupFailure {
            state: StartupStateDto::RecoverableFailure,
            code: "startup.database_schema_invalid",
            message: "The local database schema could not be validated.",
            category: "integrity_failure",
            detail: "The recorded database migration checksum did not match this application."
                .to_owned(),
            recovery: RecoveryMode::Retry,
        },
        OpenError::UnsupportedSchema { .. } => StartupFailure {
            state: StartupStateDto::RecoverableFailure,
            code: "startup.database_schema_invalid",
            message: "The local database schema could not be validated.",
            category: "integrity_failure",
            detail: "The database schema version is not supported by this application.".to_owned(),
            recovery: RecoveryMode::Retry,
        },
        OpenError::ForeignKeyViolation { .. } => StartupFailure {
            state: StartupStateDto::RecoverableFailure,
            code: "startup.database_schema_invalid",
            message: "The local database schema could not be validated.",
            category: "integrity_failure",
            detail: "The database contains rows that violate a required relationship.".to_owned(),
            recovery: RecoveryMode::Retry,
        },
        OpenError::Database(_) => StartupFailure {
            state: StartupStateDto::RecoverableFailure,
            code: "startup.database_unavailable",
            message: "The local database could not be opened.",
            category: "unavailable",
            detail: "The database adapter could not open the local store.".to_owned(),
            recovery: RecoveryMode::Retry,
        },
    }
}

fn database_health_failure(issue: DatabaseIssue) -> StartupFailure {
    let detail = match issue {
        DatabaseIssue::Unreadable => "The database could not be read for health validation.",
        DatabaseIssue::IntegrityCheckFailed(_) => {
            "The database integrity check reported a failure."
        }
        DatabaseIssue::ForeignKeyViolation => {
            "The database health check found a referential integrity violation."
        }
    };
    StartupFailure {
        state: StartupStateDto::RecoverableFailure,
        code: "startup.database_integrity_failed",
        message: "The local database failed an integrity check.",
        category: "integrity_failure",
        detail: detail.to_owned(),
        recovery: RecoveryMode::Retry,
    }
}

fn reconciliation_failure(error: PortError) -> StartupFailure {
    StartupFailure {
        state: StartupStateDto::Indeterminate,
        code: "startup.artifact_reconciliation_failed",
        message: "Artifact recovery could not determine a safe startup state.",
        category: classification_name(error.safe_classification()),
        detail: format!(
            "Artifact reconciliation failed ({:?}, {:?}).",
            error.safe_classification(),
            error.retryability()
        ),
        recovery: RecoveryMode::Retry,
    }
}

fn recovery_actions(recovery: RecoveryMode) -> Vec<StartupRecoveryActionDto> {
    vec![
        StartupRecoveryActionDto {
            code: match recovery {
                RecoveryMode::Retry => "retry_startup_validation",
                RecoveryMode::Restart => "restart_application",
            }
            .to_owned(),
            label: match recovery {
                RecoveryMode::Retry => "Retry startup validation",
                RecoveryMode::Restart => "Restart application",
            }
            .to_owned(),
        },
        StartupRecoveryActionDto {
            code: "get_local_diagnostics".to_owned(),
            label: "View local diagnostics".to_owned(),
        },
    ]
}

fn record(
    code: &str,
    component: &str,
    severity: DiagnosticSeverityDto,
    error_category: Option<&str>,
    detail: &str,
) -> LocalDiagnosticDto {
    LocalDiagnosticDto {
        code: code.to_owned(),
        component: component.to_owned(),
        severity,
        trust_label: TrustLabelDto::TrustedCore,
        observation_class: ObservationClassDto::CoreObservation,
        error_category: error_category.map(str::to_owned),
        correlation_id: None,
        detail: detail.to_owned(),
    }
}

const fn classification_name(classification: SafeErrorClassification) -> &'static str {
    match classification {
        SafeErrorClassification::Conflict => "conflict",
        SafeErrorClassification::Unavailable => "unavailable",
        SafeErrorClassification::PermissionDenied => "permission_denied",
        SafeErrorClassification::NotFound => "not_found",
        SafeErrorClassification::InvalidInput => "invalid_input",
        SafeErrorClassification::IntegrityFailure => "integrity_failure",
        SafeErrorClassification::StorageFull => "storage_full",
        SafeErrorClassification::Internal => "internal",
    }
}
