use std::path::PathBuf;
use std::sync::Arc;

use local_agent_terminal_application::{
    ActorLocality, ApprovedProcessExecutor, ApprovedProcessRequest, AuthorizedFileRead,
    AuthorizedToolRequest, CancellationReceipt, CapabilityFilesystem, CapabilityRequest,
    CapabilityResolver, CaptureFileWritePostEvidence, CaptureFileWritePreEvidence,
    DisclosureContextProvider, DisclosureContextRequest, DisclosureOutcome, FileReadRequest,
    FileWriteEvidenceStore, FileWriteRecoveryCompletion, FileWriteRecoveryIntent, FileWriteRequest,
    GitDiffRequest, GitDiffResult, GitStatusRequest, GitStatusResult, PolicyActor,
    PolicyBoundBytes, PortError, ProcessReceipt, ResolvedCapabilityTarget, ResourceClass,
    Retryability, SafeErrorClassification, Sha256Digest, StructuredToolExecutor, TaskId, TaskQuery,
    TaskRisk, ToolAuthorityResolver, ToolAuthoritySnapshot, ToolControlSelfTest, ToolExecutionId,
    ToolExecutionResult, TrustTier, TrustedDisclosureContext, VerifiedWrite,
    WorkspaceWriteCoordinator,
};
use local_agent_terminal_platform_windows::{CapabilityRegistration, WindowsCapabilityAdapter};
use local_agent_terminal_policy_engine::VersionedPolicyEngine;
use local_agent_terminal_repository_git::{GitRepositoryGateway, GitStructuredTools};
use local_agent_terminal_storage_sqlite::{DatabaseHealth, SqliteStore};
use local_agent_terminal_tool_runtime::ToolRuntime as StructuredToolRuntime;

use crate::startup::StartupConfig;
use crate::tool_runtime::ToolBrokerConfig;

const DEFAULT_POLICY_BUNDLE: &str = r#"{"version":1,"rules":[{"id":"default-deny-process","effect":"deny","action":"process.exec"},{"id":"tool-display","effect":"allow_with_redaction","action":"tool.approval.display","redactions":["secret_scanner"]}]}"#;

#[derive(Clone)]
struct ProductionToolPaths {
    app_data_dir: PathBuf,
    trusted_workspace_root: PathBuf,
}

pub(crate) fn production_tool_broker(config: &StartupConfig) -> ToolBrokerConfig {
    let paths = ProductionToolPaths {
        app_data_dir: config.app_data_dir.clone(),
        trusted_workspace_root: config.trusted_workspace_root.clone(),
    };
    ToolBrokerConfig::new(
        DEFAULT_POLICY_BUNDLE,
        Arc::new(ProductionToolAuthority {
            paths: paths.clone(),
        }),
        Arc::new(ProductionToolExecutor {
            paths,
            writes: Arc::new(WorkspaceWriteCoordinator::new()),
        }),
    )
    .degraded_read_only()
}

struct ProductionToolAuthority {
    paths: ProductionToolPaths,
}

impl ToolAuthorityResolver for ProductionToolAuthority {
    fn resolve(
        &self,
        request: &local_agent_terminal_application::ToolRequest,
    ) -> Result<ToolAuthoritySnapshot, PortError> {
        let task_id = request.process().process().binding().task_id();
        let (database, capabilities, _, _) = task_adapters(&self.paths, task_id)?;
        let resource = request.policy().resource();
        let resolved = capabilities.resolve(CapabilityRequest {
            task_id: task_id.clone(),
            capability: resource.capability.clone(),
        })?;
        let resource_bytes = match resolved.target {
            ResolvedCapabilityTarget::Root => Vec::new(),
            ResolvedCapabilityTarget::Relative(relative_components) => {
                capabilities
                    .read(AuthorizedFileRead {
                        task_id: task_id.clone(),
                        root_identity: resolved.root_identity,
                        relative_components,
                        expected_digest: Some(resource.content_digest.clone()),
                    })?
                    .bytes
            }
        };
        let lease = if request
            .process()
            .process()
            .executor_fencing_token()
            .is_some()
        {
            database.current_lease(task_id)?
        } else {
            None
        };
        ToolAuthoritySnapshot::new(request.clone(), &resource_bytes, lease)
    }
}

struct ProductionToolExecutor {
    paths: ProductionToolPaths,
    writes: Arc<WorkspaceWriteCoordinator>,
}

impl ProductionToolExecutor {
    fn with_runtime<T>(
        &self,
        task_id: &TaskId,
        operation: impl FnOnce(&StructuredToolRuntime<'_>) -> Result<T, PortError>,
    ) -> Result<T, PortError> {
        let (database, capabilities, git, task) = task_adapters(&self.paths, task_id)?;
        let policy = VersionedPolicyEngine::from_json(DEFAULT_POLICY_BUNDLE)?;
        let context = ProductionDisclosureContext {
            task,
            policy_snapshot_digest: policy.snapshot_digest().clone(),
        };
        let process = DisabledProcessExecutor;
        let evidence = UnavailableFileWriteEvidence;
        let runtime = StructuredToolRuntime::new(
            &capabilities,
            &capabilities,
            &capabilities,
            &git,
            &database,
            &process,
            &evidence,
            &database,
            self.writes.as_ref(),
            &context,
            &policy,
            &database,
            &database,
        );
        operation(&runtime)
    }
}

impl StructuredToolExecutor for ProductionToolExecutor {
    fn execute(&self, _request: AuthorizedToolRequest) -> Result<ToolExecutionResult, PortError> {
        Err(unavailable())
    }

    fn cancel(&self, _execution_id: &ToolExecutionId) -> Result<CancellationReceipt, PortError> {
        Err(unavailable())
    }

    fn file_read(
        &self,
        request: FileReadRequest,
    ) -> Result<DisclosureOutcome<PolicyBoundBytes>, PortError> {
        let task_id = request.task_id.clone();
        self.with_runtime(&task_id, |runtime| runtime.file_read(request))
    }

    fn file_write(&self, request: FileWriteRequest) -> Result<VerifiedWrite, PortError> {
        let task_id = request.task_id.clone();
        self.with_runtime(&task_id, |runtime| runtime.file_write(request))
    }

    fn git_status(
        &self,
        request: GitStatusRequest,
    ) -> Result<DisclosureOutcome<GitStatusResult>, PortError> {
        let task_id = request.task_id.clone();
        self.with_runtime(&task_id, |runtime| runtime.git_status(request))
    }

    fn git_diff(
        &self,
        request: GitDiffRequest,
    ) -> Result<DisclosureOutcome<GitDiffResult>, PortError> {
        let task_id = request.task_id.clone();
        self.with_runtime(&task_id, |runtime| runtime.git_diff(request))
    }
}

impl ToolControlSelfTest for ProductionToolExecutor {
    fn verify_controls(&self) -> Result<(), PortError> {
        VersionedPolicyEngine::from_json(DEFAULT_POLICY_BUNDLE)?;
        let database = open_database(&self.paths)?;
        if database.database_health() != DatabaseHealth::Healthy {
            return Err(unavailable());
        }
        Ok(())
    }
}

struct DisabledProcessExecutor;

impl ApprovedProcessExecutor for DisabledProcessExecutor {
    fn execute(
        &self,
        _execution_id: ToolExecutionId,
        _request: ApprovedProcessRequest,
        _authority: Option<&local_agent_terminal_application::ToolExecutionClaimAuthority>,
    ) -> Result<ProcessReceipt, PortError> {
        Err(unavailable())
    }

    fn cancel(&self, _execution_id: &ToolExecutionId) -> Result<CancellationReceipt, PortError> {
        Err(unavailable())
    }
}

impl ToolControlSelfTest for DisabledProcessExecutor {
    fn verify_controls(&self) -> Result<(), PortError> {
        Ok(())
    }
}

struct UnavailableFileWriteEvidence;

impl FileWriteEvidenceStore for UnavailableFileWriteEvidence {
    fn capture_pre_write(
        &self,
        _request: CaptureFileWritePreEvidence,
    ) -> Result<FileWriteRecoveryIntent, PortError> {
        Err(unavailable())
    }

    fn capture_post_write(
        &self,
        _request: CaptureFileWritePostEvidence,
    ) -> Result<FileWriteRecoveryCompletion, PortError> {
        Err(unavailable())
    }
}

struct ProductionDisclosureContext {
    task: local_agent_terminal_application::TaskSnapshot,
    policy_snapshot_digest: Sha256Digest,
}

impl DisclosureContextProvider for ProductionDisclosureContext {
    fn context(
        &self,
        request: DisclosureContextRequest,
    ) -> Result<TrustedDisclosureContext, PortError> {
        if request.task_id != self.task.task_id
            || request.capability.worktree_task_id() != Some(&self.task.task_id)
        {
            return Err(unavailable());
        }
        Ok(TrustedDisclosureContext {
            actor: PolicyActor {
                connection_id: "core.local".to_owned(),
                agent_id: "core.structured-tool".to_owned(),
                trust_tier: TrustTier::CoreAdapter,
                locality: ActorLocality::Local,
            },
            resource_class: ResourceClass::InternalCode,
            task_risk: match self.task.risk_level {
                local_agent_terminal_application::RiskLevel::Low => TaskRisk::Low,
                local_agent_terminal_application::RiskLevel::Medium => TaskRisk::Medium,
                local_agent_terminal_application::RiskLevel::High => TaskRisk::High,
                local_agent_terminal_application::RiskLevel::Critical => TaskRisk::Critical,
            },
            workflow_phase: self.task.phase.as_str().to_owned(),
            purpose: "execute a structured local tool".to_owned(),
            policy_snapshot_digest: self.policy_snapshot_digest.clone(),
        })
    }
}

fn task_adapters(
    paths: &ProductionToolPaths,
    task_id: &TaskId,
) -> Result<
    (
        SqliteStore,
        WindowsCapabilityAdapter,
        GitStructuredTools,
        local_agent_terminal_application::TaskSnapshot,
    ),
    PortError,
> {
    let database = open_database(paths)?;
    let task = database.task(task_id)?;
    let worktree = task.worktree.as_ref().ok_or_else(unavailable)?;
    let gateway = GitRepositoryGateway::open(
        &paths.trusted_workspace_root,
        &[paths.app_data_dir.join("artifacts")],
    )?;
    let git =
        GitStructuredTools::from_owned_tasks(&gateway, &database, std::slice::from_ref(task_id))?;
    let root_identity = git.root_identity(task_id).ok_or_else(unavailable)?.clone();
    let capabilities = WindowsCapabilityAdapter::new(vec![CapabilityRegistration::worktree(
        root_identity,
        task_id.clone(),
        paths
            .trusted_workspace_root
            .join(worktree.worktree_id.as_str()),
    )?])?;
    Ok((database, capabilities, git, task))
}

fn open_database(paths: &ProductionToolPaths) -> Result<SqliteStore, PortError> {
    SqliteStore::open(paths.app_data_dir.join("state.sqlite3")).map_err(|_| unavailable())
}

fn unavailable() -> PortError {
    PortError::failure(
        SafeErrorClassification::Unavailable,
        Retryability::NonRetryable,
    )
}
