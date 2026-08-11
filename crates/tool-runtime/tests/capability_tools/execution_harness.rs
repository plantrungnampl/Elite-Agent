
#[cfg(windows)]
fn output_executable_path() -> std::path::PathBuf {
    std::path::PathBuf::from(r"\\?\C:\trusted\output-probe.exe")
}

#[cfg(not(windows))]
fn output_executable_path() -> std::path::PathBuf {
    std::path::PathBuf::from("/trusted/output-probe")
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
    disclosure_context: FixedDisclosureContext,
    disclosure_policy: VersionedPolicyEngine,
    policy_decisions: RecordingDecisionStore,
    clock: FixedClock,
}

impl Harness {
    fn new(initial: Option<Vec<u8>>) -> Self {
        let log = RecordingLog::default();
        let target = Target::new(initial);
        let disclosure_policy = VersionedPolicyEngine::from_json(
            r#"{"version":1,"rules":[{"id":"default-allow","effect":"allow","action":"context.disclose"}]}"#,
        )
        .unwrap();
        let disclosure_context = FixedDisclosureContext {
            snapshot_digest: disclosure_policy.snapshot_digest().clone(),
            resource_class: ResourceClass::InternalCode,
            locality: ActorLocality::Local,
        };
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
                fail_fails: AtomicBool::new(false),
                prepare_state_tamper: AtomicBool::new(false),
                indeterminate: AtomicBool::new(false),
                state: Mutex::new(None),
            },
            writes: WorkspaceWriteCoordinator::new(),
            disclosure_context,
            disclosure_policy,
            policy_decisions: RecordingDecisionStore::default(),
            clock: FixedClock,
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
            &self.disclosure_context,
            &self.disclosure_policy,
            &self.policy_decisions,
            &self.clock,
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

struct DisclosureResolver {
    observed_digest: Sha256Digest,
}

impl CapabilityResolver for DisclosureResolver {
    fn resolve(&self, request: CapabilityRequest) -> Result<ResolvedCapability, PortError> {
        Ok(ResolvedCapability {
            capability: request.capability,
            content_digest: Some(self.observed_digest.clone()),
            root_identity: CapabilityRootIdentity::new("disclosure-root").unwrap(),
            target: local_agent_terminal_application::ResolvedCapabilityTarget::Relative(
                RelativePathComponents::new(vec!["secret.txt".to_owned()]).unwrap(),
            ),
        })
    }
}

struct DisclosureFilesystem {
    original: Vec<u8>,
    expected_digest: Mutex<Option<Sha256Digest>>,
}

impl CapabilityFilesystem for DisclosureFilesystem {
    fn read(&self, request: AuthorizedFileRead) -> Result<VerifiedBytes, PortError> {
        *self.expected_digest.lock().unwrap() = request.expected_digest;
        Ok(VerifiedBytes {
            digest: digest(&self.original),
            bytes: self.original.clone(),
        })
    }

    fn write(
        &self,
        _: local_agent_terminal_application::AuthorizedFileWrite,
    ) -> Result<VerifiedWrite, PortError> {
        unreachable!("disclosure test does not write")
    }
}

struct FixedDisclosureContext {
    snapshot_digest: Sha256Digest,
    resource_class: ResourceClass,
    locality: ActorLocality,
}

fn disclosure_engine(effect: &str, locality: &str) -> VersionedPolicyEngine {
    VersionedPolicyEngine::from_json(&format!(
        r#"{{"version":1,"rules":[{{"id":"disclosure-rule","effect":"{effect}","locality":"{locality}","action":"context.disclose","redactions":["secret_scanner"]}}]}}"#
    ))
    .unwrap()
}

fn disclosure_context(
    engine: &VersionedPolicyEngine,
    locality: ActorLocality,
) -> FixedDisclosureContext {
    FixedDisclosureContext {
        snapshot_digest: engine.snapshot_digest().clone(),
        resource_class: ResourceClass::InternalCode,
        locality,
    }
}

impl DisclosureContextProvider for FixedDisclosureContext {
    fn context(&self, _: DisclosureContextRequest) -> Result<TrustedDisclosureContext, PortError> {
        Ok(TrustedDisclosureContext {
            actor: PolicyActor {
                connection_id: "connection-1".to_owned(),
                agent_id: "agent-1".to_owned(),
                trust_tier: TrustTier::IsolatedWorker,
                locality: self.locality,
            },
            resource_class: self.resource_class,
            task_risk: TaskRisk::Medium,
            workflow_phase: "implementation".to_owned(),
            purpose: "inspect the requested file".to_owned(),
            policy_snapshot_digest: self.snapshot_digest.clone(),
        })
    }
}

#[derive(Default)]
struct RecordingDecisionStore {
    recorded: Mutex<Vec<RecordedPolicyDecision>>,
}

impl PolicyDecisionStore for RecordingDecisionStore {
    fn record(&self, decision: RecordedPolicyDecision) -> Result<PolicyDecisionId, PortError> {
        let id = PolicyDecisionId::from_decision(&decision.decision);
        self.recorded.lock().unwrap().push(decision);
        Ok(id)
    }
}

#[derive(Debug, Clone, Copy)]
enum EvaluatorTamper {
    Request,
    Channel,
    OriginalDigest,
}

struct TamperingEvaluator {
    engine: VersionedPolicyEngine,
    tamper: EvaluatorTamper,
}

impl DisclosurePolicyEvaluator for TamperingEvaluator {
    fn disclose(
        &self,
        mut request: DisclosureRequest,
    ) -> Result<PolicyApprovedDisclosure, PortError> {
        if matches!(self.tamper, EvaluatorTamper::Request) {
            request.policy_request.purpose = "different purpose".to_owned();
        }
        let mut disclosure = DisclosurePolicyEvaluator::disclose(&self.engine, request)?;
        match self.tamper {
            EvaluatorTamper::Request => {}
            EvaluatorTamper::Channel => {
                disclosure.channel = local_agent_terminal_application::DisclosureChannel::GitDiff;
            }
            EvaluatorTamper::OriginalDigest => {
                disclosure.original_digest = digest(b"different bytes");
            }
        }
        Ok(disclosure)
    }
}

#[derive(Default)]
struct WrongIdDecisionStore {
    recorded: Mutex<Vec<RecordedPolicyDecision>>,
}

impl PolicyDecisionStore for WrongIdDecisionStore {
    fn record(&self, decision: RecordedPolicyDecision) -> Result<PolicyDecisionId, PortError> {
        self.recorded.lock().unwrap().push(decision.clone());
        let mut different = decision.decision;
        different.operation_digest = digest(b"different policy decision");
        Ok(PolicyDecisionId::from_decision(&different))
    }
}

fn run_file_disclosure(
    evaluator: &dyn DisclosurePolicyEvaluator,
    context: &dyn DisclosureContextProvider,
    decisions: &dyn PolicyDecisionStore,
) -> Result<DisclosureOutcome<local_agent_terminal_application::PolicyBoundBytes>, PortError> {
    let original = b"clean".to_vec();
    let resolver = DisclosureResolver {
        observed_digest: digest(&original),
    };
    let filesystem = DisclosureFilesystem {
        original,
        expected_digest: Mutex::new(None),
    };
    let harness = Harness::new(None);
    let runtime = ToolRuntime::new(
        &resolver,
        &filesystem,
        &harness.sessions,
        &harness.git,
        &harness.leases,
        &harness.process,
        &harness.evidence,
        &harness.recovery,
        &harness.writes,
        context,
        evaluator,
        decisions,
        &FixedClock,
    );
    runtime.file_read(FileReadRequest {
        task_id: task(),
        capability: capability("clean.txt"),
        expected_digest: None,
    })
}

struct FixedClock;

impl Clock for FixedClock {
    fn now_utc(&self) -> Result<String, PortError> {
        Ok("2026-07-28T12:00:00Z".to_owned())
    }
}

struct RootResolver;

impl CapabilityResolver for RootResolver {
    fn resolve(&self, request: CapabilityRequest) -> Result<ResolvedCapability, PortError> {
        Ok(ResolvedCapability {
            capability: request.capability,
            content_digest: None,
            root_identity: CapabilityRootIdentity::new("git-root").unwrap(),
            target: local_agent_terminal_application::ResolvedCapabilityTarget::Root,
        })
    }
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
            target: local_agent_terminal_application::ResolvedCapabilityTarget::Relative(
                RelativePathComponents::new(vec!["workspace".to_owned()]).unwrap(),
            ),
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

    fn observe_recovery_target(
        &self,
        _: &local_agent_terminal_application::FileWriteRecoveryRequest,
    ) -> Result<ObservedFileImage, PortError> {
        self.log.push("observe_recovery_target");
        Ok(self
            .target
            .bytes
            .lock()
            .unwrap()
            .clone()
            .map_or_else(ObservedFileImage::absent, ObservedFileImage::present))
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
    fail_fails: AtomicBool,
    prepare_state_tamper: AtomicBool,
    indeterminate: AtomicBool,
    state: Mutex<Option<FileWriteRecoveryState>>,
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
        *self.state.lock().unwrap() = Some(state);
        Ok(snapshot(intent, state))
    }

    fn start(&self, _: &ToolExecutionId) -> Result<FileWriteRecoverySnapshot, PortError> {
        self.log.push("start");
        *self.state.lock().unwrap() = Some(FileWriteRecoveryState::Started);
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
        *self.state.lock().unwrap() = Some(FileWriteRecoveryState::Completed);
        Ok(snapshot(
            self.intent.lock().unwrap().clone().unwrap(),
            FileWriteRecoveryState::Completed,
        ))
    }

    fn fail(
        &self,
        _: &ToolExecutionId,
        failure: FileWriteRecoveryFailure,
    ) -> Result<FileWriteRecoverySnapshot, PortError> {
        self.log.push("fail");
        if self.fail_fails.load(Ordering::SeqCst) {
            return Err(conflict());
        }
        let state = match failure {
            FileWriteRecoveryFailure::NotStarted => FileWriteRecoveryState::Failed,
            FileWriteRecoveryFailure::RecoveredNoNetEffect(_) => {
                FileWriteRecoveryState::RecoveredNoNetEffect
            }
            FileWriteRecoveryFailure::Compensated(_) => FileWriteRecoveryState::Compensated,
        };
        *self.state.lock().unwrap() = Some(state);
        Ok(snapshot(
            self.intent.lock().unwrap().clone().unwrap(),
            state,
        ))
    }

    fn mark_indeterminate(
        &self,
        _: &ToolExecutionId,
    ) -> Result<FileWriteRecoverySnapshot, PortError> {
        self.log.push("mark_indeterminate");
        self.indeterminate.store(true, Ordering::SeqCst);
        *self.state.lock().unwrap() = Some(FileWriteRecoveryState::Indeterminate);
        Ok(snapshot(
            self.intent.lock().unwrap().clone().unwrap(),
            FileWriteRecoveryState::Indeterminate,
        ))
    }

    fn recover(&self) -> Result<Vec<FileWriteRecoverySnapshot>, PortError> {
        let Some(state) = *self.state.lock().unwrap() else {
            return Ok(Vec::new());
        };
        if matches!(
            state,
            FileWriteRecoveryState::Prepared
                | FileWriteRecoveryState::Started
                | FileWriteRecoveryState::Indeterminate
        ) {
            Ok(vec![snapshot(
                self.intent.lock().unwrap().clone().unwrap(),
                state,
            )])
        } else {
            Ok(Vec::new())
        }
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
    fn status(&self, _: AuthorizedGitStatus) -> Result<RawGitStatusResult, PortError> {
        unreachable!()
    }

    fn diff(&self, _: AuthorizedGitDiff) -> Result<RawGitDiffResult, PortError> {
        unreachable!()
    }
}

struct StatusDisclosureGit {
    original: Vec<u8>,
}

impl StructuredGit for StatusDisclosureGit {
    fn status(&self, request: AuthorizedGitStatus) -> Result<RawGitStatusResult, PortError> {
        Ok(RawGitStatusResult {
            digest: digest(&self.original),
            bytes: self.original.clone(),
            repository_id: local_agent_terminal_domain::RepositoryId::new("repo-1").unwrap(),
            revision: GitObjectId::new("a".repeat(40)).unwrap(),
            path_scope: request.worktree,
            truncated: false,
        })
    }

    fn diff(&self, _: AuthorizedGitDiff) -> Result<RawGitDiffResult, PortError> {
        Ok(RawGitDiffResult {
            digest: digest(&self.original),
            bytes: self.original.clone(),
            repository_id: local_agent_terminal_domain::RepositoryId::new("repo-1").unwrap(),
            revision: GitObjectId::new("b".repeat(40)).unwrap(),
            path_scope: capability("."),
            truncated: true,
        })
    }
}

struct TamperedStatusGit;

impl StructuredGit for TamperedStatusGit {
    fn status(&self, request: AuthorizedGitStatus) -> Result<RawGitStatusResult, PortError> {
        Ok(RawGitStatusResult {
            digest: digest(b"different"),
            bytes: b"raw status".to_vec(),
            repository_id: local_agent_terminal_domain::RepositoryId::new("repo-1").unwrap(),
            revision: GitObjectId::new("a".repeat(40)).unwrap(),
            path_scope: request.worktree,
            truncated: false,
        })
    }

    fn diff(&self, _: AuthorizedGitDiff) -> Result<RawGitDiffResult, PortError> {
        unreachable!()
    }
}

#[derive(Default)]
struct RootRecordingGit {
    root: Mutex<Option<CapabilityRootIdentity>>,
}

impl StructuredGit for RootRecordingGit {
    fn status(&self, request: AuthorizedGitStatus) -> Result<RawGitStatusResult, PortError> {
        *self.root.lock().unwrap() = Some(request.root_identity);
        Ok(RawGitStatusResult {
            digest: digest(b""),
            bytes: Vec::new(),
            repository_id: local_agent_terminal_domain::RepositoryId::new("repo-1").unwrap(),
            revision: GitObjectId::new("a".repeat(40)).unwrap(),
            path_scope: request.worktree,
            truncated: false,
        })
    }

    fn diff(&self, _: AuthorizedGitDiff) -> Result<RawGitDiffResult, PortError> {
        unreachable!()
    }
}

struct Process;

impl ToolControlSelfTest for Process {
    fn verify_controls(&self) -> Result<(), PortError> {
        Err(PortError::failure(
            local_agent_terminal_application::SafeErrorClassification::Unavailable,
            local_agent_terminal_application::Retryability::NonRetryable,
        ))
    }
}

impl ApprovedProcessExecutor for Process {
    fn execute(
        &self,
        _: ToolExecutionId,
        _: ApprovedProcessRequest,
        _authority: Option<&local_agent_terminal_application::ToolExecutionClaimAuthority>,
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
