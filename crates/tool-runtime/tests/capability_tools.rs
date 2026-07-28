use std::sync::atomic::{AtomicBool, Ordering};

use local_agent_terminal_application::{
    AcquireLease, AuthorizedFileRead, AuthorizedFileWrite, AuthorizedGitDiff, AuthorizedGitStatus,
    CanonicalEvidenceRef, CapabilityFilesystem, CapabilityRequest, CapabilityResolver,
    CapabilityRootIdentity, ExecutorLeaseStore, FileReadRequest, FileWriteRequest, GitDiffResult,
    GitStatusResult, LeaseSnapshot, PortError, ProcessLauncher, ProcessReceipt,
    RelativePathComponents, ResolvedCapability, RevokeLease, StructuredGit, StructuredToolExecutor,
    VerifiedBytes, VerifiedWrite, WorkspaceMutationRequest, WorkspaceMutationResult,
    WorkspaceMutationStore,
};
use local_agent_terminal_domain::{
    ActorId, ArtifactId, CapabilityRef, Condition, EventId, FencingToken, GitObjectId, LeaseClaim,
    OperationState, Phase, ProjectId, RunId, Sequence, Sha256Digest, TaskId, WorkflowState,
    WorkspaceFingerprint, WorkspaceVersion,
};
use local_agent_terminal_tool_runtime::ToolRuntime;

#[test]
fn resolved_capabilities_expose_only_opaque_roots_and_normalized_components() {
    let root = CapabilityRootIdentity::new("root-1").unwrap();
    let components =
        RelativePathComponents::new(vec!["src".to_owned(), "lib.rs".to_owned()]).unwrap();

    assert_eq!(root.as_str(), "root-1");
    assert_eq!(components.as_slice(), ["src", "lib.rs"]);
    assert!(RelativePathComponents::new(vec!["..".to_owned()]).is_err());
    assert!(RelativePathComponents::new(vec!["CON.txt".to_owned()]).is_err());
    assert!(RelativePathComponents::new(vec!["name. ".to_owned()]).is_err());
}

#[test]
fn read_denial_is_non_disclosing_and_never_reaches_the_filesystem() {
    let resolver = Resolver { allowed: false };
    let filesystem = Filesystem::default();
    let mutations = mutations(&filesystem);
    let git = Git;
    let leases = Leases { current: true };
    let process = Process;
    let runtime = ToolRuntime::new(&resolver, &filesystem, &git, &leases, &process, &mutations);

    let error = runtime
        .file_read(FileReadRequest {
            task_id: task(),
            capability: capability("secret.txt"),
            expected_digest: None,
        })
        .expect_err("denied reads must fail");

    assert_eq!(
        error.safe_classification(),
        local_agent_terminal_application::SafeErrorClassification::PermissionDenied
    );
    assert!(!filesystem.read_called.load(Ordering::SeqCst));
    assert_eq!(
        error.to_string(),
        "port failure (PermissionDenied, NonRetryable)"
    );
}

#[test]
fn write_rechecks_the_lease_before_effect_then_records_the_workspace_mutation() {
    let resolver = Resolver { allowed: true };
    let filesystem = Filesystem::default();
    let mutations = mutations(&filesystem);
    let git = Git;
    let leases = Leases { current: true };
    let process = Process;
    let runtime = ToolRuntime::new(&resolver, &filesystem, &git, &leases, &process, &mutations);

    let result = runtime
        .file_write(FileWriteRequest {
            task_id: task(),
            capability: capability("result.txt"),
            expected_digest: None,
            bytes: b"replacement".to_vec(),
            fencing_token: FencingToken::new(7).unwrap(),
            lease_claim: claim(),
            workspace_mutation: mutation(),
        })
        .expect("write succeeds");

    assert_eq!(result.digest, digest(b"replacement"));
    assert!(filesystem.write_called.load(Ordering::SeqCst));
    assert!(mutations.called.load(Ordering::SeqCst));
}

#[test]
fn stale_write_has_zero_filesystem_and_mutation_effect() {
    let resolver = Resolver { allowed: true };
    let filesystem = Filesystem::default();
    let mutations = mutations(&filesystem);
    let git = Git;
    let leases = Leases { current: false };
    let process = Process;
    let runtime = ToolRuntime::new(&resolver, &filesystem, &git, &leases, &process, &mutations);

    let error = runtime
        .file_write(FileWriteRequest {
            task_id: task(),
            capability: capability("result.txt"),
            expected_digest: None,
            bytes: b"replacement".to_vec(),
            fencing_token: FencingToken::new(7).unwrap(),
            lease_claim: claim(),
            workspace_mutation: mutation(),
        })
        .expect_err("stale writes must fail");

    assert_eq!(
        error.safe_classification(),
        local_agent_terminal_application::SafeErrorClassification::Conflict
    );
    assert!(!filesystem.write_called.load(Ordering::SeqCst));
    assert!(!mutations.called.load(Ordering::SeqCst));
}

fn task() -> TaskId {
    TaskId::new("task-1").unwrap()
}
fn capability(path: &str) -> CapabilityRef {
    CapabilityRef::worktree(task(), path).unwrap()
}
fn claim() -> LeaseClaim {
    LeaseClaim::new(
        task(),
        RunId::new("run-1").unwrap(),
        FencingToken::new(7).unwrap(),
    )
}

struct Resolver {
    allowed: bool,
}

impl CapabilityResolver for Resolver {
    fn resolve(&self, request: CapabilityRequest) -> Result<ResolvedCapability, PortError> {
        if !self.allowed || request.task_id != task() {
            return Err(denied());
        }
        Ok(ResolvedCapability {
            capability: request.capability,
            content_digest: None,
            root_identity: CapabilityRootIdentity::new("root-1").unwrap(),
            relative_components: RelativePathComponents::new(vec!["workspace".to_owned()]).unwrap(),
        })
    }
}

#[derive(Default)]
struct Filesystem {
    read_called: AtomicBool,
    write_called: AtomicBool,
}

impl CapabilityFilesystem for Filesystem {
    fn read(&self, request: AuthorizedFileRead) -> Result<VerifiedBytes, PortError> {
        self.read_called.store(true, Ordering::SeqCst);
        assert_eq!(request.root_identity.as_str(), "root-1");
        Ok(VerifiedBytes {
            digest: digest(b"secret"),
            bytes: b"secret".to_vec(),
        })
    }

    fn write(&self, request: AuthorizedFileWrite) -> Result<VerifiedWrite, PortError> {
        self.write_called.store(true, Ordering::SeqCst);
        assert_eq!(request.root_identity.as_str(), "root-1");
        Ok(VerifiedWrite {
            digest: digest(&request.bytes),
        })
    }
}

struct Leases {
    current: bool,
}

impl ExecutorLeaseStore for Leases {
    fn acquire(&self, _: AcquireLease) -> Result<LeaseSnapshot, PortError> {
        unreachable!()
    }
    fn revoke(&self, _: RevokeLease) -> Result<(), PortError> {
        unreachable!()
    }
    fn fence_stale(&self) -> Result<Vec<LeaseSnapshot>, PortError> {
        unreachable!()
    }
    fn assert_current(&self, current_claim: LeaseClaim) -> Result<(), PortError> {
        if self.current && current_claim == claim() {
            Ok(())
        } else {
            Err(conflict())
        }
    }
}

struct Mutations<'a> {
    called: AtomicBool,
    filesystem: &'a Filesystem,
}

impl WorkspaceMutationStore for Mutations<'_> {
    fn record_workspace_mutation(
        &self,
        request: WorkspaceMutationRequest,
    ) -> Result<WorkspaceMutationResult, PortError> {
        assert!(self.filesystem.write_called.load(Ordering::SeqCst));
        self.called.store(true, Ordering::SeqCst);
        Ok(WorkspaceMutationResult {
            event_id: EventId::new("event-1").unwrap(),
            new_sequence: Sequence::new(request.expected_sequence.get() + 1),
            task_state: WorkflowState::new(
                Phase::WorkspaceDirty,
                Condition::Active,
                OperationState::None,
                Sequence::new(2),
                WorkspaceVersion::new(2),
                FencingToken::new(8).unwrap(),
            )
            .unwrap(),
            resume_target: None,
            invalidated_approval_ids: vec!["approval-1".to_owned()],
        })
    }

    fn record_workspace_observation_loss(
        &self,
        _: local_agent_terminal_application::WorkspaceObservationLossRequest,
    ) -> Result<(), PortError> {
        unreachable!()
    }
}

fn mutations(filesystem: &Filesystem) -> Mutations<'_> {
    Mutations {
        called: AtomicBool::new(false),
        filesystem,
    }
}

struct Git;
impl StructuredGit for Git {
    fn status(&self, _: AuthorizedGitStatus) -> Result<GitStatusResult, PortError> {
        unreachable!()
    }
    fn diff(&self, _: AuthorizedGitDiff) -> Result<GitDiffResult, PortError> {
        unreachable!()
    }
}

struct Process;
impl ProcessLauncher for Process {
    fn execute(
        &self,
        _: local_agent_terminal_application::AuthorizedProcessRequest,
    ) -> Result<ProcessReceipt, PortError> {
        unreachable!()
    }
    fn cancel(
        &self,
        _: &local_agent_terminal_application::ToolExecutionId,
    ) -> Result<local_agent_terminal_application::CancellationReceipt, PortError> {
        unreachable!()
    }
}

fn mutation() -> WorkspaceMutationRequest {
    let fingerprint = WorkspaceFingerprint::new(
        GitObjectId::new("a".repeat(40)).unwrap(),
        digest(b"index").to_string(),
        digest(b"status").to_string(),
    )
    .unwrap();
    WorkspaceMutationRequest {
        task_id: task(),
        expected_sequence: Sequence::new(1),
        claim: claim(),
        pre_fingerprint: fingerprint.clone(),
        post_fingerprint: fingerprint,
        pre_evidence: evidence("before"),
        post_evidence: evidence("after"),
        actor_id: ActorId::new("core").unwrap(),
        correlation_id: "tool-1".to_owned(),
    }
}

fn evidence(name: &str) -> CanonicalEvidenceRef {
    CanonicalEvidenceRef {
        artifact_id: ArtifactId::new(format!("artifact-{name}")).unwrap(),
        content_hash: digest(name.as_bytes()).to_string(),
        storage_key: name.to_owned(),
        size_bytes: name.len() as u64,
        project_id: ProjectId::new("project-1").unwrap(),
        task_id: Some(task()),
    }
}

fn digest(bytes: &[u8]) -> Sha256Digest {
    use sha2::{Digest, Sha256};
    Sha256Digest::new(format!("sha256:{:x}", Sha256::digest(bytes))).unwrap()
}
fn denied() -> PortError {
    PortError::failure(
        local_agent_terminal_application::SafeErrorClassification::PermissionDenied,
        local_agent_terminal_application::Retryability::NonRetryable,
    )
}
fn conflict() -> PortError {
    PortError::failure(
        local_agent_terminal_application::SafeErrorClassification::Conflict,
        local_agent_terminal_application::Retryability::NonRetryable,
    )
}
