use std::path::{Path, PathBuf};
use std::sync::Arc;

use local_agent_terminal_application::{
    canonical_file_write_recovery_request, ActorId, ActorLocality, ApprovedProcessExecutor,
    ApprovedProcessRequest, ArtifactId, AuthorizedFileRead, AuthorizedToolRequest,
    CancellationReceipt, CanonicalJsonRequest, CapabilityFilesystem, CapabilityRequest,
    CapabilityResolver, CaptureFileWritePostEvidence, CaptureFileWritePreEvidence,
    DisclosureContextProvider, DisclosureContextRequest, DisclosureOutcome, ExpectedPresence,
    FileReadRequest, FileWriteEvidenceStore, FileWritePolicyBinding, FileWritePreImage,
    FileWriteRecoveryCompletion, FileWriteRecoveryIntent, FileWriteRecoveryRequest,
    FileWriteRecoverySnapshot, FileWriteRecoveryStore, FileWriteRequest, GitDiffRequest,
    GitDiffResult, GitStatusRequest, GitStatusResult, InspectWorktree, ManagedWorktreePath,
    PolicyAction, PolicyActor, PolicyBoundBytes, PolicyResource, PortError, ProcessReceipt,
    RepositoryGateway, ResolvedCapabilityTarget, ResourceClass, Retryability,
    SafeErrorClassification, Sha256Digest, StructuredToolExecutor, TaskId, TaskQuery, TaskRisk,
    ToolAuthorityResolver, ToolAuthoritySnapshot, ToolControlSelfTest, ToolExecutionId,
    ToolExecutionResult, ToolPolicyContext, ToolRequest, TrustTier, TrustedDisclosureContext,
    VerifiedWrite, WorkspaceFingerprint, WorkspaceRecoveryStore, WorkspaceWriteCoordinator,
    WorktreeObservation,
};
use local_agent_terminal_platform_windows::{CapabilityRegistration, WindowsCapabilityAdapter};
use local_agent_terminal_policy_engine::VersionedPolicyEngine;
use local_agent_terminal_repository_git::{GitRepositoryGateway, GitStructuredTools};
use local_agent_terminal_storage_files::ContentAddressedArtifactStore;
use local_agent_terminal_storage_sqlite::{DatabaseHealth, SqliteStore};
use local_agent_terminal_tool_runtime::ToolRuntime as StructuredToolRuntime;

use crate::startup::StartupConfig;
use crate::tool_runtime::{ToolArtifactPublisher, ToolBrokerConfig};
use crate::workspace_monitor::publish_canonical_json;

const DEFAULT_POLICY_BUNDLE: &str = r#"{"version":1,"rules":[{"id":"default-deny-process","effect":"deny","action":"process.exec"},{"id":"structured-read","effect":"allow_with_redaction","action":"context.disclose","redactions":["secret_scanner"]},{"id":"tool-display","effect":"allow_with_redaction","action":"tool.approval.display","redactions":["secret_scanner"]}]}"#;
const PRODUCTION_TOOL_PURPOSE: &str = "execute a structured local tool";

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
    let writes = Arc::new(WorkspaceWriteCoordinator::new());
    let executor = Arc::new(ProductionToolExecutor {
        paths: paths.clone(),
        writes: Arc::clone(&writes),
    });
    let recovery_executor = Arc::clone(&executor);
    ToolBrokerConfig::new(
        DEFAULT_POLICY_BUNDLE,
        Arc::new(ProductionToolAuthority {
            paths: paths.clone(),
        }),
        executor,
    )
    .without_process()
    .with_workspace_writes(writes)
    .with_file_write_recovery(Arc::new(move || recovery_executor.recover_file_writes()))
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
        let (database, capabilities, _, _, task, _) = task_adapters(&self.paths, task_id)?;
        let resource = request.policy().resource();
        let resolved = capabilities.resolve(CapabilityRequest {
            task_id: task_id.clone(),
            capability: resource.capability.clone(),
        })?;
        let authoritative_capability = resolved.capability.clone();
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
        let binding = request.process().process().binding();
        if binding.workflow_phase() != task.phase
            || binding.workspace_version() != task.workspace_version
        {
            return Err(integrity_failure());
        }
        let policy = VersionedPolicyEngine::from_json(DEFAULT_POLICY_BUNDLE)?;
        let authoritative_request = ToolRequest::new(
            request.execution_id().clone(),
            request.process().clone(),
            ToolPolicyContext::new(
                production_actor(),
                PolicyAction::new("process.exec").map_err(|_| integrity_failure())?,
                PolicyResource {
                    capability: authoritative_capability,
                    content_digest: resource.content_digest.clone(),
                    resource_class: ResourceClass::InternalCode,
                },
                production_task_risk(&task),
                PRODUCTION_TOOL_PURPOSE,
                policy.snapshot_digest().clone(),
            )?,
        )?;
        ToolAuthoritySnapshot::new(authoritative_request, &resource_bytes, lease)
    }
}

struct ProductionToolExecutor {
    paths: ProductionToolPaths,
    writes: Arc<WorkspaceWriteCoordinator>,
}

impl ProductionToolExecutor {
    fn recover_file_writes(&self) -> Result<Vec<FileWriteRecoverySnapshot>, PortError> {
        let database = open_database(&self.paths)?;
        let recoverable = database.recover()?;
        if recoverable.is_empty() {
            return Ok(Vec::new());
        }
        let mut task_ids = Vec::new();
        for snapshot in recoverable {
            if !task_ids.contains(&snapshot.request.task_id) {
                task_ids.push(snapshot.request.task_id);
            }
        }
        let tasks = task_ids
            .iter()
            .map(|task_id| database.task(task_id))
            .collect::<Result<Vec<_>, _>>()?;
        let artifacts =
            ContentAddressedArtifactStore::open(self.paths.app_data_dir.join("artifacts"))?;
        let gateway = GitRepositoryGateway::open(
            &self.paths.trusted_workspace_root,
            &[self.paths.app_data_dir.join("artifacts")],
        )?;
        let git = GitStructuredTools::from_owned_tasks(&gateway, &database, &task_ids)?;
        let registrations = tasks
            .iter()
            .map(|task| {
                let worktree = task.worktree.as_ref().ok_or_else(unavailable)?;
                CapabilityRegistration::worktree(
                    git.root_identity(&task.task_id)
                        .ok_or_else(unavailable)?
                        .clone(),
                    task.task_id.clone(),
                    self.paths
                        .trusted_workspace_root
                        .join(worktree.worktree_id.as_str()),
                )
            })
            .collect::<Result<Vec<_>, _>>()?;
        let capabilities = WindowsCapabilityAdapter::new(registrations)?;
        let policy = VersionedPolicyEngine::from_json(DEFAULT_POLICY_BUNDLE)?;
        let context = ProductionDisclosureContext {
            task: tasks.into_iter().next().ok_or_else(unavailable)?,
            policy_snapshot_digest: policy.snapshot_digest().clone(),
        };
        let disabled_process = DisabledProcessExecutor;
        let evidence = ProductionFileWriteEvidence {
            database: &database,
            artifacts: &artifacts,
            repositories: &gateway,
            task: &context.task,
            policy: None,
        };
        StructuredToolRuntime::new(
            &capabilities,
            &capabilities,
            &capabilities,
            &git,
            &database,
            &disabled_process,
            &evidence,
            &database,
            self.writes.as_ref(),
            &context,
            &policy,
            &database,
            &database,
        )
        .recover_file_writes()
    }

    fn with_runtime<T>(
        &self,
        task_id: &TaskId,
        file_write_policy: Option<FileWritePolicyBinding>,
        operation: impl FnOnce(&StructuredToolRuntime<'_>) -> Result<T, PortError>,
    ) -> Result<T, PortError> {
        let (database, capabilities, git, gateway, task, _) = task_adapters(&self.paths, task_id)?;
        let artifacts =
            ContentAddressedArtifactStore::open(self.paths.app_data_dir.join("artifacts"))?;
        let policy = VersionedPolicyEngine::from_json(DEFAULT_POLICY_BUNDLE)?;
        let context = ProductionDisclosureContext {
            task,
            policy_snapshot_digest: policy.snapshot_digest().clone(),
        };
        let disabled_process = DisabledProcessExecutor;
        let configured_evidence = ProductionFileWriteEvidence {
            database: &database,
            artifacts: &artifacts,
            repositories: &gateway,
            task: &context.task,
            policy: file_write_policy,
        };
        let runtime = StructuredToolRuntime::new(
            &capabilities,
            &capabilities,
            &capabilities,
            &git,
            &database,
            &disabled_process,
            &configured_evidence,
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
    fn execute(&self, request: AuthorizedToolRequest) -> Result<ToolExecutionResult, PortError> {
        let task_id = request
            .process_request()
            .process()
            .binding()
            .task_id()
            .clone();
        self.with_runtime(&task_id, None, |runtime| runtime.execute(request))
    }

    fn cancel(&self, execution_id: &ToolExecutionId) -> Result<CancellationReceipt, PortError> {
        DisabledProcessExecutor.cancel(execution_id)
    }

    fn terminate_retained_process(
        &self,
        binding: &local_agent_terminal_application::AuthoritativeProcessBinding,
    ) -> Result<CancellationReceipt, PortError> {
        DisabledProcessExecutor.terminate_retained_process(binding)
    }

    fn file_read(
        &self,
        request: FileReadRequest,
    ) -> Result<DisclosureOutcome<PolicyBoundBytes>, PortError> {
        let task_id = request.task_id.clone();
        self.with_runtime(&task_id, None, |runtime| runtime.file_read(request))
    }

    fn file_write(&self, request: FileWriteRequest) -> Result<VerifiedWrite, PortError> {
        let task_id = request.task_id.clone();
        let policy = request.policy.clone();
        self.with_runtime(&task_id, Some(policy), |runtime| {
            runtime.file_write(request)
        })
    }

    fn git_status(
        &self,
        request: GitStatusRequest,
    ) -> Result<DisclosureOutcome<GitStatusResult>, PortError> {
        let task_id = request.task_id.clone();
        self.with_runtime(&task_id, None, |runtime| runtime.git_status(request))
    }

    fn git_diff(
        &self,
        request: GitDiffRequest,
    ) -> Result<DisclosureOutcome<GitDiffResult>, PortError> {
        let task_id = request.task_id.clone();
        self.with_runtime(&task_id, None, |runtime| runtime.git_diff(request))
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

struct ProductionFileWriteEvidence<'a> {
    database: &'a SqliteStore,
    artifacts: &'a ContentAddressedArtifactStore,
    repositories: &'a GitRepositoryGateway,
    task: &'a local_agent_terminal_application::TaskSnapshot,
    policy: Option<FileWritePolicyBinding>,
}

impl FileWriteEvidenceStore for ProductionFileWriteEvidence<'_> {
    fn capture_pre_write(
        &self,
        capture: CaptureFileWritePreEvidence,
    ) -> Result<FileWriteRecoveryIntent, PortError> {
        let session = capture.session();
        if session.task_id() != &self.task.task_id {
            return Err(integrity_failure());
        }
        let fingerprint = observe_task_fingerprint(self.database, self.repositories, self.task)?;
        let expected_fingerprint = &self
            .task
            .worktree
            .as_ref()
            .ok_or_else(unavailable)?
            .fingerprint;
        if &fingerprint != expected_fingerprint {
            return Err(integrity_failure());
        }
        let publisher = ToolArtifactPublisher::new(self.database, self.artifacts);
        let pre_image = match capture.pre_image().present_bytes() {
            Some(observed) => FileWritePreImage::Artifact(
                publisher.publish_evidence(
                    ArtifactId::new(format!(
                        "file-write-pre-image-{}",
                        session.execution_id().as_str()
                    ))
                    .map_err(|_| invalid_input())?,
                    session.task_id(),
                    "file_write_pre_image",
                    format!(
                        "file-writes/{}/pre-image.bin",
                        session.execution_id().as_str()
                    ),
                    session.execution_id().as_str(),
                    &observed.digest,
                    &observed.bytes,
                    "application/octet-stream",
                )?,
            ),
            None => FileWritePreImage::Absent,
        };
        let pre_evidence = publish_file_write_fingerprint(
            self.database,
            self.artifacts,
            self.task,
            session.execution_id(),
            "pre",
            &fingerprint,
        )?;
        let request = FileWriteRecoveryRequest {
            execution_id: session.execution_id().clone(),
            task_id: session.task_id().clone(),
            root_identity: session.root_identity().clone(),
            relative_components: session.relative_components().clone(),
            lease_claim: session.lease_claim().clone(),
            expected_sequence: self.task.current_sequence,
            pre_image,
            expected_post_digest: capture.expected_post().digest().clone(),
            expected_post_size: capture.expected_post().size_bytes(),
            pre_fingerprint: fingerprint,
            pre_evidence,
            actor_id: ActorId::new("tool-runtime").map_err(|_| invalid_input())?,
            correlation_id: format!("file-write:{}", session.execution_id().as_str()),
            policy: self.policy.clone().ok_or_else(unavailable)?,
        };
        let canonical = canonical_file_write_recovery_request(&request)?;
        let request_artifact = publisher.publish_evidence(
            ArtifactId::new(format!(
                "file-write-request-{}",
                session.execution_id().as_str()
            ))
            .map_err(|_| invalid_input())?,
            session.task_id(),
            "file_write_request",
            format!(
                "file-writes/{}/request.json",
                session.execution_id().as_str()
            ),
            session.execution_id().as_str(),
            &canonical.operation_digest,
            &canonical.canonical_bytes,
            "application/json",
        )?;
        Ok(FileWriteRecoveryIntent {
            request,
            request_artifact,
        })
    }

    fn capture_post_write(
        &self,
        capture: CaptureFileWritePostEvidence,
    ) -> Result<FileWriteRecoveryCompletion, PortError> {
        let request = capture.recovery_request();
        let task = self.database.task(&request.task_id)?;
        let fingerprint = observe_task_fingerprint(self.database, self.repositories, &task)?;
        let post_evidence = publish_file_write_fingerprint(
            self.database,
            self.artifacts,
            &task,
            &request.execution_id,
            "post",
            &fingerprint,
        )?;
        Ok(FileWriteRecoveryCompletion {
            execution_id: request.execution_id.clone(),
            observed_post_digest: capture.observed_post().digest.clone(),
            post_fingerprint: fingerprint,
            post_evidence,
        })
    }
}

fn publish_file_write_fingerprint(
    database: &SqliteStore,
    artifacts: &ContentAddressedArtifactStore,
    task: &local_agent_terminal_application::TaskSnapshot,
    execution_id: &ToolExecutionId,
    role: &str,
    fingerprint: &WorkspaceFingerprint,
) -> Result<local_agent_terminal_application::CanonicalEvidenceRef, PortError> {
    let request = CanonicalJsonRequest::new(
        ArtifactId::new(format!(
            "file-write-{role}-fingerprint-{}",
            execution_id.as_str()
        ))
        .map_err(|_| invalid_input())?,
        task.project_id.clone(),
        Some(task.task_id.clone()),
        "workspace_fingerprint",
        format!(
            "file-writes/{}/{role}-fingerprint.json",
            execution_id.as_str()
        ),
        "tool",
        "tool-runtime",
        &serde_json::json!({
            "executionId": execution_id.as_str(),
            "fingerprint": {
                "head": fingerprint.head().as_str(),
                "indexDigest": fingerprint.index_digest(),
                "statusDigest": fingerprint.status_digest(),
            },
            "role": role,
            "sequence": task.current_sequence.get(),
            "taskId": task.task_id.as_str(),
        }),
        format!("file-write:{}:fingerprint:{role}", execution_id.as_str()),
    )?;
    publish_canonical_json(database, artifacts, request)
}

fn observe_task_fingerprint(
    database: &SqliteStore,
    repositories: &GitRepositoryGateway,
    task: &local_agent_terminal_application::TaskSnapshot,
) -> Result<WorkspaceFingerprint, PortError> {
    let worktree = task.worktree.as_ref().ok_or_else(unavailable)?;
    let project = database
        .recovery_projects()?
        .into_iter()
        .find(|project| project.project_id == task.project_id)
        .ok_or_else(unavailable)?;
    let locator = repositories.locate_persisted(Path::new(&project.repository_path))?;
    if locator.repository_id != worktree.repository_id
        || locator.stable_identity != worktree.repository_identity
    {
        return Err(integrity_failure());
    }
    match repositories.inspect_worktree(InspectWorktree {
        repository: locator,
        managed_path: ManagedWorktreePath {
            trusted_root_id: repositories.trusted_root_id().to_owned(),
            relative_leaf: PathBuf::from(worktree.worktree_id.as_str()),
            redacted_display: worktree.target_path_display.clone(),
        },
        task_id: task.task_id.clone(),
        worktree_id: worktree.worktree_id.clone(),
        branch: worktree.branch.clone(),
        base_commit: worktree.base_commit.clone(),
    })? {
        WorktreeObservation::Exact(snapshot)
            if snapshot.expected_presence == ExpectedPresence::Present =>
        {
            Ok(snapshot.fingerprint)
        }
        WorktreeObservation::Exact(_)
        | WorktreeObservation::AuthoritativelyAbsent
        | WorktreeObservation::Conflict(_) => Err(integrity_failure()),
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
            actor: production_actor(),
            resource_class: ResourceClass::InternalCode,
            task_risk: production_task_risk(&self.task),
            workflow_phase: self.task.phase.as_str().to_owned(),
            purpose: PRODUCTION_TOOL_PURPOSE.to_owned(),
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
        GitRepositoryGateway,
        local_agent_terminal_application::TaskSnapshot,
        local_agent_terminal_application::CapabilityRootIdentity,
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
        root_identity.clone(),
        task_id.clone(),
        paths
            .trusted_workspace_root
            .join(worktree.worktree_id.as_str()),
    )?])?;
    Ok((database, capabilities, git, gateway, task, root_identity))
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

fn invalid_input() -> PortError {
    PortError::failure(
        SafeErrorClassification::InvalidInput,
        Retryability::NonRetryable,
    )
}

fn integrity_failure() -> PortError {
    PortError::failure(
        SafeErrorClassification::IntegrityFailure,
        Retryability::NonRetryable,
    )
}

fn production_actor() -> PolicyActor {
    PolicyActor {
        connection_id: "core.local".to_owned(),
        agent_id: "core.structured-tool".to_owned(),
        trust_tier: TrustTier::CoreAdapter,
        locality: ActorLocality::Local,
    }
}

fn production_task_risk(task: &local_agent_terminal_application::TaskSnapshot) -> TaskRisk {
    match task.risk_level {
        local_agent_terminal_application::RiskLevel::Low => TaskRisk::Low,
        local_agent_terminal_application::RiskLevel::Medium => TaskRisk::Medium,
        local_agent_terminal_application::RiskLevel::High => TaskRisk::High,
        local_agent_terminal_application::RiskLevel::Critical => TaskRisk::Critical,
    }
}
