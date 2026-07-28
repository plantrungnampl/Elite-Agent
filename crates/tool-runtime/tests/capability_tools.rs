use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Mutex;

use local_agent_terminal_application::{
    canonical_file_write_recovery_request, AcquireLease, AuthorizedFileRead, AuthorizedGitDiff,
    AuthorizedGitStatus, CapabilityFileWriteSession, CapabilityFileWriteSessionFactory,
    CapabilityFilesystem, CapabilityRequest, CapabilityResolver, CapabilityRootIdentity,
    CaptureFileWritePostEvidence, CaptureFileWritePreEvidence, ExecutorLeaseStore, FileReadRequest,
    FileWriteEvidenceStore, FileWritePolicyBinding, FileWritePostExpectation, FileWritePreImage,
    FileWriteRecoveryCompletion, FileWriteRecoveryIntent, FileWriteRecoverySnapshot,
    FileWriteRecoveryState, FileWriteRecoveryStore, FileWriteRequest, GitDiffResult,
    GitStatusResult, LeaseSnapshot, ObservedFileImage, OpenFileWriteSession, PortError,
    ProcessLauncher, ProcessReceipt, RelativePathComponents, ResolvedCapability, RevokeLease,
    StructuredGit, StructuredToolExecutor, ToolExecutionId, VerifiedBytes,
    VerifiedFileWriteCompensation, VerifiedWrite, WorkspaceWriteCoordinator,
};
use local_agent_terminal_domain::{
    ActorId, ArtifactId, CapabilityRef, FencingToken, GitObjectId, LeaseClaim, PolicyEffect,
    ProjectId, RunId, Sequence, Sha256Digest, TaskId, WorkspaceFingerprint,
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
    let harness = Harness::new(Some(b"before".to_vec()));
    harness.resolver.allowed.store(false, Ordering::SeqCst);

    let error = harness
        .runtime()
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
    assert!(!harness.reads.read_called.load(Ordering::SeqCst));
    assert_eq!(
        error.to_string(),
        "port failure (PermissionDenied, NonRetryable)"
    );
}

#[test]
fn write_holds_the_exact_durable_call_order() {
    let harness = Harness::new(Some(b"before".to_vec()));

    harness.runtime().file_write(write_request()).unwrap();

    assert_eq!(
        harness.calls(),
        [
            "resolve",
            "assert_current",
            "open_session",
            "pre_image",
            "capture_pre_write",
            "prepare",
            "start",
            "assert_current",
            "apply",
            "verify_post_image",
            "capture_post_write",
            "complete",
        ]
    );
}

#[test]
fn stale_write_has_zero_target_or_durable_effect() {
    let harness = Harness::new(Some(b"before".to_vec()));
    harness.leases.current.store(false, Ordering::SeqCst);

    let error = harness
        .runtime()
        .file_write(write_request())
        .expect_err("stale writes must fail");

    assert_eq!(
        error.safe_classification(),
        local_agent_terminal_application::SafeErrorClassification::Conflict
    );
    assert_eq!(harness.target(), Some(b"before".to_vec()));
    assert_eq!(harness.calls(), ["resolve", "assert_current"]);
    assert!(!harness.recovery.indeterminate.load(Ordering::SeqCst));
}

#[test]
fn atomic_complete_failure_restores_and_verifies_the_pre_image() {
    let harness = Harness::new(Some(b"before".to_vec()));
    harness
        .recovery
        .complete_fails
        .store(true, Ordering::SeqCst);

    assert!(harness.runtime().file_write(write_request()).is_err());

    assert_eq!(harness.target(), Some(b"before".to_vec()));
    assert!(harness
        .calls()
        .ends_with(&["complete", "restore_pre_image_and_verify"]));
    assert!(!harness.recovery.indeterminate.load(Ordering::SeqCst));
}

#[test]
fn compensation_failure_marks_the_durable_write_indeterminate() {
    let harness = Harness::new(Some(b"before".to_vec()));
    harness
        .recovery
        .complete_fails
        .store(true, Ordering::SeqCst);
    harness
        .sessions
        .compensation_fails
        .store(true, Ordering::SeqCst);

    assert!(harness.runtime().file_write(write_request()).is_err());

    assert_eq!(harness.target(), Some(b"replacement".to_vec()));
    assert!(harness.calls().ends_with(&[
        "complete",
        "restore_pre_image_and_verify",
        "mark_indeterminate"
    ]));
    assert!(harness.recovery.indeterminate.load(Ordering::SeqCst));
}

#[test]
fn successful_write_returns_the_exact_verified_digest_and_size() {
    let harness = Harness::new(None);

    let result = harness.runtime().file_write(write_request()).unwrap();

    assert_eq!(result.digest, digest(b"replacement"));
    assert_eq!(result.size_bytes, b"replacement".len() as u64);
    assert_eq!(harness.target(), Some(b"replacement".to_vec()));
}

#[test]
fn pre_write_evidence_must_echo_every_execution_binding_exactly() {
    for tamper in [
        PreEvidenceTamper::Execution,
        PreEvidenceTamper::Task,
        PreEvidenceTamper::Root,
        PreEvidenceTamper::Components,
        PreEvidenceTamper::Lease,
        PreEvidenceTamper::PreImage,
        PreEvidenceTamper::PostDigest,
        PreEvidenceTamper::PostSize,
        PreEvidenceTamper::Policy,
        PreEvidenceTamper::RequestArtifact,
    ] {
        let harness = Harness::new(Some(b"before".to_vec()));
        *harness.evidence.pre_tamper.lock().unwrap() = Some(tamper);

        let error = harness
            .runtime()
            .file_write(write_request())
            .expect_err("tampered pre-write evidence must fail closed");

        assert_eq!(
            error.safe_classification(),
            local_agent_terminal_application::SafeErrorClassification::IntegrityFailure,
            "{tamper:?}"
        );
        assert_eq!(harness.target(), Some(b"before".to_vec()), "{tamper:?}");
        assert_eq!(
            harness.calls().last(),
            Some(&"capture_pre_write"),
            "{tamper:?}"
        );
    }
}

#[test]
fn tampered_post_write_evidence_is_compensated_before_completion() {
    let harness = Harness::new(Some(b"before".to_vec()));
    harness
        .evidence
        .post_digest_tamper
        .store(true, Ordering::SeqCst);

    let error = harness
        .runtime()
        .file_write(write_request())
        .expect_err("tampered post-write evidence must fail closed");

    assert_eq!(
        error.safe_classification(),
        local_agent_terminal_application::SafeErrorClassification::IntegrityFailure
    );
    assert_eq!(harness.target(), Some(b"before".to_vec()));
    assert!(harness
        .calls()
        .ends_with(&["capture_post_write", "restore_pre_image_and_verify"]));
    assert!(!harness.calls().contains(&"complete"));
}

#[test]
fn recovery_state_echo_is_verified_before_crossing_the_effect_boundary() {
    let harness = Harness::new(Some(b"before".to_vec()));
    harness
        .recovery
        .prepare_state_tamper
        .store(true, Ordering::SeqCst);

    let error = harness
        .runtime()
        .file_write(write_request())
        .expect_err("a mismatched recovery state must fail closed");

    assert_eq!(
        error.safe_classification(),
        local_agent_terminal_application::SafeErrorClassification::IntegrityFailure
    );
    assert_eq!(harness.target(), Some(b"before".to_vec()));
    assert_eq!(harness.calls().last(), Some(&"prepare"));
    assert!(!harness.calls().contains(&"start"));
}

#[test]
fn lease_revocation_after_prepare_blocks_the_write_before_apply() {
    let harness = Harness::new(Some(b"before".to_vec()));
    harness.leases.stale_on_second.store(true, Ordering::SeqCst);

    let error = harness
        .runtime()
        .file_write(write_request())
        .expect_err("lease revocation must win the final pre-effect race");

    assert_eq!(
        error.safe_classification(),
        local_agent_terminal_application::SafeErrorClassification::Conflict
    );
    assert_eq!(harness.target(), Some(b"before".to_vec()));
    assert!(harness.calls().ends_with(&["start", "assert_current"]));
    assert!(!harness.calls().contains(&"apply"));
    assert!(!harness.recovery.indeterminate.load(Ordering::SeqCst));
}

struct Harness {
    log: RecordingLog,
    resolver: Resolver,
    reads: ReadFilesystem,
    sessions: SessionFactory,
    git: Git,
    leases: Leases,
    process: Process,
    evidence: Evidence,
    recovery: Recovery,
    writes: WorkspaceWriteCoordinator,
}

impl Harness {
    fn new(initial: Option<Vec<u8>>) -> Self {
        let log = RecordingLog::default();
        let target = Target::new(initial);
        Self {
            resolver: Resolver {
                allowed: AtomicBool::new(true),
                log: log.clone(),
            },
            reads: ReadFilesystem::default(),
            sessions: SessionFactory {
                target,
                log: log.clone(),
                compensation_fails: AtomicBool::new(false),
            },
            git: Git,
            leases: Leases {
                current: AtomicBool::new(true),
                assertions: AtomicUsize::new(0),
                stale_on_second: AtomicBool::new(false),
                log: log.clone(),
            },
            process: Process,
            evidence: Evidence {
                log: log.clone(),
                pre_tamper: Mutex::new(None),
                post_digest_tamper: AtomicBool::new(false),
            },
            recovery: Recovery {
                log: log.clone(),
                intent: Mutex::new(None),
                complete_fails: AtomicBool::new(false),
                prepare_state_tamper: AtomicBool::new(false),
                indeterminate: AtomicBool::new(false),
            },
            writes: WorkspaceWriteCoordinator::new(),
            log,
        }
    }

    fn runtime(&self) -> ToolRuntime<'_> {
        ToolRuntime::new(
            &self.resolver,
            &self.reads,
            &self.sessions,
            &self.git,
            &self.leases,
            &self.process,
            &self.evidence,
            &self.recovery,
            &self.writes,
        )
    }

    fn calls(&self) -> Vec<&'static str> {
        self.log.calls.lock().unwrap().clone()
    }

    fn target(&self) -> Option<Vec<u8>> {
        self.sessions.target.bytes.lock().unwrap().clone()
    }
}

#[derive(Clone, Default)]
struct RecordingLog {
    calls: std::sync::Arc<Mutex<Vec<&'static str>>>,
}

impl RecordingLog {
    fn push(&self, call: &'static str) {
        self.calls.lock().unwrap().push(call);
    }
}

#[derive(Clone)]
struct Target {
    bytes: std::sync::Arc<Mutex<Option<Vec<u8>>>>,
}

impl Target {
    fn new(bytes: Option<Vec<u8>>) -> Self {
        Self {
            bytes: std::sync::Arc::new(Mutex::new(bytes)),
        }
    }
}

struct Resolver {
    allowed: AtomicBool,
    log: RecordingLog,
}

impl CapabilityResolver for Resolver {
    fn resolve(&self, request: CapabilityRequest) -> Result<ResolvedCapability, PortError> {
        self.log.push("resolve");
        if !self.allowed.load(Ordering::SeqCst) || request.task_id != task() {
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
struct ReadFilesystem {
    read_called: AtomicBool,
}

impl CapabilityFilesystem for ReadFilesystem {
    fn read(&self, _: AuthorizedFileRead) -> Result<VerifiedBytes, PortError> {
        self.read_called.store(true, Ordering::SeqCst);
        Ok(VerifiedBytes {
            digest: digest(b"secret"),
            bytes: b"secret".to_vec(),
        })
    }

    fn write(
        &self,
        _: local_agent_terminal_application::AuthorizedFileWrite,
    ) -> Result<VerifiedWrite, PortError> {
        unreachable!("writes use retained sessions")
    }
}

struct SessionFactory {
    target: Target,
    log: RecordingLog,
    compensation_fails: AtomicBool,
}

impl CapabilityFileWriteSessionFactory for SessionFactory {
    fn open(
        &self,
        _: OpenFileWriteSession,
    ) -> Result<Box<dyn CapabilityFileWriteSession>, PortError> {
        self.log.push("open_session");
        let original = self.target.bytes.lock().unwrap().clone();
        let pre_image = original
            .clone()
            .map_or_else(ObservedFileImage::absent, ObservedFileImage::present);
        Ok(Box::new(Session {
            target: self.target.clone(),
            original,
            pre_image,
            log: self.log.clone(),
            compensation_fails: self.compensation_fails.load(Ordering::SeqCst),
        }))
    }
}

struct Session {
    target: Target,
    original: Option<Vec<u8>>,
    pre_image: ObservedFileImage,
    log: RecordingLog,
    compensation_fails: bool,
}

impl CapabilityFileWriteSession for Session {
    fn pre_image(&self) -> &ObservedFileImage {
        self.log.push("pre_image");
        &self.pre_image
    }

    fn apply(&mut self, bytes: &[u8]) -> Result<(), PortError> {
        self.log.push("apply");
        *self.target.bytes.lock().unwrap() = Some(bytes.to_vec());
        Ok(())
    }

    fn verify_post_image(
        &mut self,
        _: &FileWritePostExpectation,
    ) -> Result<VerifiedWrite, PortError> {
        self.log.push("verify_post_image");
        let bytes = self.target.bytes.lock().unwrap().clone().unwrap();
        Ok(VerifiedWrite {
            digest: digest(&bytes),
            size_bytes: bytes.len() as u64,
        })
    }

    fn restore_pre_image_and_verify(&mut self) -> Result<VerifiedFileWriteCompensation, PortError> {
        self.log.push("restore_pre_image_and_verify");
        if self.compensation_fails {
            return Err(conflict());
        }
        *self.target.bytes.lock().unwrap() = self.original.clone();
        Ok(self
            .original
            .as_ref()
            .map_or(VerifiedFileWriteCompensation::Absent, |bytes| {
                VerifiedFileWriteCompensation::Restored(VerifiedWrite {
                    digest: digest(bytes),
                    size_bytes: bytes.len() as u64,
                })
            }))
    }
}

#[derive(Debug, Clone, Copy)]
enum PreEvidenceTamper {
    Execution,
    Task,
    Root,
    Components,
    Lease,
    PreImage,
    PostDigest,
    PostSize,
    Policy,
    RequestArtifact,
}

struct Evidence {
    log: RecordingLog,
    pre_tamper: Mutex<Option<PreEvidenceTamper>>,
    post_digest_tamper: AtomicBool,
}

impl FileWriteEvidenceStore for Evidence {
    fn capture_pre_write(
        &self,
        capture: CaptureFileWritePreEvidence,
    ) -> Result<FileWriteRecoveryIntent, PortError> {
        self.log.push("capture_pre_write");
        let session = capture.session();
        let task_id = session.task_id().clone();
        let pre_image =
            capture
                .pre_image()
                .present_bytes()
                .map_or(FileWritePreImage::Absent, |observed| {
                    FileWritePreImage::Artifact(evidence_ref(
                        "pre-image",
                        &task_id,
                        observed.digest.as_str(),
                        observed.bytes.len() as u64,
                    ))
                });
        let mut request = local_agent_terminal_application::FileWriteRecoveryRequest {
            execution_id: session.execution_id().clone(),
            task_id: task_id.clone(),
            root_identity: session.root_identity().clone(),
            relative_components: session.relative_components().clone(),
            lease_claim: session.lease_claim().clone(),
            expected_sequence: Sequence::new(4),
            pre_image,
            expected_post_digest: capture.expected_post().digest().clone(),
            expected_post_size: capture.expected_post().size_bytes(),
            pre_fingerprint: fingerprint('a'),
            pre_evidence: evidence_ref(
                "workspace-before",
                &task_id,
                digest(b"workspace-before").as_str(),
                b"workspace-before".len() as u64,
            ),
            actor_id: ActorId::new("tool-runtime").unwrap(),
            correlation_id: format!("file-write:{}", session.execution_id().as_str()),
            policy: policy(),
        };
        let tamper = *self.pre_tamper.lock().unwrap();
        tamper_pre_evidence(&mut request, tamper);
        let canonical = canonical_file_write_recovery_request(&request)?;
        let mut intent = FileWriteRecoveryIntent {
            request,
            request_artifact: evidence_ref(
                "request",
                &task_id,
                canonical.operation_digest.as_str(),
                canonical.canonical_bytes.len() as u64,
            ),
        };
        if matches!(tamper, Some(PreEvidenceTamper::RequestArtifact)) {
            intent.request_artifact.content_hash = digest(b"wrong-request").to_string();
        }
        Ok(intent)
    }

    fn capture_post_write(
        &self,
        capture: CaptureFileWritePostEvidence,
    ) -> Result<FileWriteRecoveryCompletion, PortError> {
        self.log.push("capture_post_write");
        let observed_post_digest = if self.post_digest_tamper.load(Ordering::SeqCst) {
            digest(b"wrong-post")
        } else {
            capture.observed_post().digest.clone()
        };
        Ok(FileWriteRecoveryCompletion {
            execution_id: capture.recovery_request().execution_id.clone(),
            observed_post_digest,
            post_fingerprint: fingerprint('b'),
            post_evidence: evidence_ref(
                "workspace-after",
                &capture.recovery_request().task_id,
                digest(b"workspace-after").as_str(),
                b"workspace-after".len() as u64,
            ),
        })
    }
}

fn tamper_pre_evidence(
    request: &mut local_agent_terminal_application::FileWriteRecoveryRequest,
    tamper: Option<PreEvidenceTamper>,
) {
    match tamper {
        None | Some(PreEvidenceTamper::RequestArtifact) => {}
        Some(PreEvidenceTamper::Execution) => {
            request.execution_id = ToolExecutionId::new("other-execution").unwrap();
        }
        Some(PreEvidenceTamper::Task) => {
            let other_task = TaskId::new("task-2").unwrap();
            request.task_id = other_task.clone();
            request.lease_claim = LeaseClaim::new(
                other_task.clone(),
                request.lease_claim.holder_run_id().clone(),
                request.lease_claim.token(),
            );
            request.pre_evidence.task_id = Some(other_task.clone());
            if let FileWritePreImage::Artifact(artifact) = &mut request.pre_image {
                artifact.task_id = Some(other_task);
            }
        }
        Some(PreEvidenceTamper::Root) => {
            request.root_identity = CapabilityRootIdentity::new("root-2").unwrap();
        }
        Some(PreEvidenceTamper::Components) => {
            request.relative_components =
                RelativePathComponents::new(vec!["other.txt".to_owned()]).unwrap();
        }
        Some(PreEvidenceTamper::Lease) => {
            request.lease_claim = LeaseClaim::new(
                request.task_id.clone(),
                RunId::new("run-2").unwrap(),
                FencingToken::new(8).unwrap(),
            );
        }
        Some(PreEvidenceTamper::PreImage) => {
            if let FileWritePreImage::Artifact(artifact) = &mut request.pre_image {
                artifact.content_hash = digest(b"wrong-pre-image").to_string();
            }
        }
        Some(PreEvidenceTamper::PostDigest) => {
            request.expected_post_digest = digest(b"wrong-post");
        }
        Some(PreEvidenceTamper::PostSize) => {
            request.expected_post_size += 1;
        }
        Some(PreEvidenceTamper::Policy) => {
            request.policy.decision_id = "other-policy-decision".to_owned();
        }
    }
}

struct Recovery {
    log: RecordingLog,
    intent: Mutex<Option<FileWriteRecoveryIntent>>,
    complete_fails: AtomicBool,
    prepare_state_tamper: AtomicBool,
    indeterminate: AtomicBool,
}

impl FileWriteRecoveryStore for Recovery {
    fn prepare(
        &self,
        intent: FileWriteRecoveryIntent,
    ) -> Result<FileWriteRecoverySnapshot, PortError> {
        self.log.push("prepare");
        *self.intent.lock().unwrap() = Some(intent.clone());
        let state = if self.prepare_state_tamper.load(Ordering::SeqCst) {
            FileWriteRecoveryState::Started
        } else {
            FileWriteRecoveryState::Prepared
        };
        Ok(snapshot(intent, state))
    }

    fn start(&self, _: &ToolExecutionId) -> Result<FileWriteRecoverySnapshot, PortError> {
        self.log.push("start");
        Ok(snapshot(
            self.intent.lock().unwrap().clone().unwrap(),
            FileWriteRecoveryState::Started,
        ))
    }

    fn complete(
        &self,
        _: FileWriteRecoveryCompletion,
    ) -> Result<FileWriteRecoverySnapshot, PortError> {
        self.log.push("complete");
        if self.complete_fails.load(Ordering::SeqCst) {
            return Err(conflict());
        }
        Ok(snapshot(
            self.intent.lock().unwrap().clone().unwrap(),
            FileWriteRecoveryState::Completed,
        ))
    }

    fn mark_indeterminate(
        &self,
        _: &ToolExecutionId,
    ) -> Result<FileWriteRecoverySnapshot, PortError> {
        self.log.push("mark_indeterminate");
        self.indeterminate.store(true, Ordering::SeqCst);
        Ok(snapshot(
            self.intent.lock().unwrap().clone().unwrap(),
            FileWriteRecoveryState::Indeterminate,
        ))
    }

    fn recover(&self) -> Result<Vec<FileWriteRecoverySnapshot>, PortError> {
        Ok(Vec::new())
    }
}

fn snapshot(
    intent: FileWriteRecoveryIntent,
    state: FileWriteRecoveryState,
) -> FileWriteRecoverySnapshot {
    FileWriteRecoverySnapshot {
        request: intent.request,
        request_artifact: intent.request_artifact,
        state,
    }
}

struct Leases {
    current: AtomicBool,
    assertions: AtomicUsize,
    stale_on_second: AtomicBool,
    log: RecordingLog,
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
        self.log.push("assert_current");
        let assertion = self.assertions.fetch_add(1, Ordering::SeqCst);
        let stale_race = self.stale_on_second.load(Ordering::SeqCst) && assertion > 0;
        if self.current.load(Ordering::SeqCst) && !stale_race && current_claim == claim() {
            Ok(())
        } else {
            Err(conflict())
        }
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
        _: &ToolExecutionId,
    ) -> Result<local_agent_terminal_application::CancellationReceipt, PortError> {
        unreachable!()
    }
}

fn write_request() -> FileWriteRequest {
    FileWriteRequest {
        execution_id: ToolExecutionId::new("file-write-1").unwrap(),
        task_id: task(),
        capability: capability("result.txt"),
        expected_digest: None,
        bytes: b"replacement".to_vec(),
        lease_claim: claim(),
        policy: policy(),
    }
}

fn policy() -> FileWritePolicyBinding {
    FileWritePolicyBinding {
        decision_id: "policy-file-write-1".to_owned(),
        operation_digest: digest(b"policy-operation"),
        policy_snapshot_digest: digest(b"policy-snapshot"),
        effect: PolicyEffect::Allow,
        approval_id: None,
    }
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

fn fingerprint(head: char) -> WorkspaceFingerprint {
    WorkspaceFingerprint::new(
        GitObjectId::new(head.to_string().repeat(40)).unwrap(),
        digest(b"index").as_str(),
        digest(b"status").as_str(),
    )
    .unwrap()
}

fn evidence_ref(
    name: &str,
    task_id: &TaskId,
    content_hash: &str,
    size_bytes: u64,
) -> local_agent_terminal_application::CanonicalEvidenceRef {
    local_agent_terminal_application::CanonicalEvidenceRef {
        artifact_id: ArtifactId::new(format!("artifact-{name}")).unwrap(),
        content_hash: content_hash.to_owned(),
        storage_key: format!("objects/{name}"),
        size_bytes,
        project_id: ProjectId::new("project-1").unwrap(),
        task_id: Some(task_id.clone()),
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
