use std::path::PathBuf;

use local_agent_terminal_application::{
    DiagnosticSeverityDto, LocalDiagnosticDto, ObservationClassDto, PortError, RecoveryActionDto,
    SafeErrorClassification, StartupIssueDto, StartupStateDto, StartupStatusDto, TrustLabelDto,
};
use local_agent_terminal_storage_files::{
    reconcile_artifacts, ContentAddressedArtifactStore, JournaledArtifactWriter,
};
use local_agent_terminal_storage_sqlite::{DatabaseHealth, DatabaseIssue, OpenError, SqliteStore};

use crate::LocalLog;

pub struct StartupConfig {
    pub app_data_dir: PathBuf,
    pub secret_values: Vec<String>,
}

pub struct Bootstrap {
    config: StartupConfig,
    status: StartupStatusDto,
    diagnostics: Vec<LocalDiagnosticDto>,
    _runtime: Option<Runtime>,
}

struct Runtime {
    _database: SqliteStore,
    _artifacts: ContentAddressedArtifactStore,
}

struct StartupFailure {
    state: StartupStateDto,
    code: &'static str,
    message: &'static str,
    category: &'static str,
    detail: String,
}

impl Bootstrap {
    pub fn new(config: StartupConfig) -> Self {
        let mut bootstrap = Self {
            config,
            status: StartupStatusDto {
                state: StartupStateDto::RecoverableFailure,
                issues: Vec::new(),
            },
            diagnostics: Vec::new(),
            _runtime: None,
        };
        bootstrap.retry_startup_validation();
        bootstrap
    }

    pub fn status(&self) -> &StartupStatusDto {
        &self.status
    }

    pub fn retry_startup_validation(&mut self) -> &StartupStatusDto {
        let mut log = LocalLog::new(self.config.secret_values.clone());
        match start(&self.config, &mut log) {
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
                self._runtime = Some(runtime);
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
                        recovery_actions: recovery_actions(),
                    }],
                };
                self._runtime = None;
            }
        }
        self.diagnostics = log.into_records();
        &self.status
    }

    pub fn local_diagnostics(&self) -> &[LocalDiagnosticDto] {
        &self.diagnostics
    }
}

fn start(config: &StartupConfig, log: &mut LocalLog) -> Result<Runtime, StartupFailure> {
    let artifacts = ContentAddressedArtifactStore::open(config.app_data_dir.join("artifacts"))
        .map_err(|error| artifact_failure("startup.app_directories_unavailable", error))?;
    log.push(record(
        "startup.app_directories.validated",
        "bootstrap",
        DiagnosticSeverityDto::Info,
        None,
        "Required application directories are available.",
    ));

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

    let _writer = JournaledArtifactWriter::new(&artifacts, &database, &database);
    Ok(Runtime {
        _database: database,
        _artifacts: artifacts,
    })
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
    }
}

fn database_open_failure(error: OpenError) -> StartupFailure {
    match error {
        OpenError::ChecksumMismatch { .. } | OpenError::UnsupportedSchema { .. } => {
            StartupFailure {
                state: StartupStateDto::RecoverableFailure,
                code: "startup.database_schema_invalid",
                message: "The local database schema could not be validated.",
                category: "integrity_failure",
                detail: error.to_string(),
            }
        }
        OpenError::Database(_) => StartupFailure {
            state: StartupStateDto::RecoverableFailure,
            code: "startup.database_unavailable",
            message: "The local database could not be opened.",
            category: "unavailable",
            detail: error.to_string(),
        },
    }
}

fn database_health_failure(issue: DatabaseIssue) -> StartupFailure {
    StartupFailure {
        state: StartupStateDto::RecoverableFailure,
        code: "startup.database_integrity_failed",
        message: "The local database failed an integrity check.",
        category: "integrity_failure",
        detail: format!("Database health check failed: {issue:?}."),
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
    }
}

fn recovery_actions() -> Vec<RecoveryActionDto> {
    vec![
        RecoveryActionDto {
            code: "retry_startup_validation".to_owned(),
            label: "Retry startup validation".to_owned(),
        },
        RecoveryActionDto {
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
