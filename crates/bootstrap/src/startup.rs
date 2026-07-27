use std::fs;
use std::path::PathBuf;

use local_agent_terminal_application::{
    DiagnosticSeverityDto, LocalDiagnosticDto, ObservationClassDto, PortError,
    SafeErrorClassification, StartupIssueDto, StartupRecoveryActionDto, StartupStateDto,
    StartupStatusDto, TrustLabelDto,
};
use local_agent_terminal_repository_git::GitRepositoryGateway;
use local_agent_terminal_storage_files::{
    reconcile_artifacts, ContentAddressedArtifactStore, RecoveryLock,
};
use local_agent_terminal_storage_sqlite::{DatabaseHealth, DatabaseIssue, OpenError, SqliteStore};

use crate::logging::LocalLog;
use crate::workspace_runtime::{reconcile_startup, WorkspaceRuntime};

pub struct StartupConfig {
    pub app_data_dir: PathBuf,
    pub trusted_workspace_root: PathBuf,
    pub secret_values: Vec<String>,
}

pub struct Bootstrap {
    config: Option<StartupConfig>,
    status: StartupStatusDto,
    diagnostics: Vec<LocalDiagnosticDto>,
    runtime: Option<WorkspaceRuntime>,
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
        let mut bootstrap = Self {
            config: Some(config),
            status: StartupStatusDto {
                state: StartupStateDto::RecoverableFailure,
                issues: Vec::new(),
            },
            diagnostics: Vec::new(),
            runtime: None,
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

    pub fn status(&self) -> &StartupStatusDto {
        &self.status
    }

    pub fn retry_startup_validation(&mut self) -> &StartupStatusDto {
        let Some(config) = self.config.as_ref() else {
            return &self.status;
        };
        self.runtime = None;
        let mut log = LocalLog::new(config.secret_values.clone());
        match start(config, &mut log) {
            Ok(runtime) => {
                log.push(record(
                    "startup.ready",
                    "bootstrap",
                    DiagnosticSeverityDto::Info,
                    None,
                    "Startup validation completed.",
                ));
                self.status = StartupStatusDto {
                    state: StartupStateDto::Ready,
                    issues: Vec::new(),
                };
                self.runtime = Some(runtime);
            }
            Err(failure) => {
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
            }
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
        }
    }
}

fn start(config: &StartupConfig, log: &mut LocalLog) -> Result<WorkspaceRuntime, StartupFailure> {
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

    let artifacts = ContentAddressedArtifactStore::open(config.app_data_dir.join("artifacts"))
        .map_err(|error| artifact_failure("startup.artifact_storage_unavailable", error))?;
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

    let report =
        reconcile_artifacts(&artifacts, &database, &database).map_err(reconciliation_failure)?;
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
    let workspace_report = reconcile_startup(&database, &artifacts, &repositories)
        .map_err(workspace_reconciliation_failure)?;
    log.push(record(
        "startup.leases.fenced",
        "storage-sqlite",
        DiagnosticSeverityDto::Info,
        None,
        &format!(
            "Stale executor lease fencing completed: fenced={}.",
            workspace_report.fenced_leases
        ),
    ));
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

    Ok(WorkspaceRuntime::new(
        database,
        artifacts,
        repositories,
        workspace_report.recovery_candidates,
    ))
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
