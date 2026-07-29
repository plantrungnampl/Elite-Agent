use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use local_agent_terminal_application::{
    bind_tool_approval_payload, canonical_approval_payload, ApprovalDigestPayload,
    ApprovedExecutableIdentity, ApprovedProcessRequest, AuthorizedToolRequest, BoundToolApproval,
    BoundedOutput, CancellationReceipt, DurableToolExecutionArtifact,
    DurableToolExecutionArtifacts, DurableToolExecutionOutcome, DurableToolExecutionReceipt,
    ExecuteDurableTool, IdempotencyClass, IncompleteToolExecution, JobReceipt, NewToolExecution,
    NewToolIntent, OperationIntentSnapshot, PortError, ProcessReceipt, ProcessStatus,
    ResolvedExecutable, Retryability, SafeErrorClassification, SafeToolExecutionError,
    StructuredToolExecutor, ToolApprovalOperationV1, ToolApprovalPayloadV1, ToolExecutionClaim,
    ToolExecutionClaimAuthority, ToolExecutionId, ToolExecutionOutput,
    ToolExecutionRecoveryEvidence, ToolExecutionResolution, ToolExecutionResult,
    ToolExecutionStore, ToolExecutionTerminal, ToolExecutionTerminalKind,
};
use local_agent_terminal_domain::{
    ArtifactId, CapabilityRef, EnvironmentProfile, FencingToken, NetworkProfile, Phase, PlanStepId,
    ProcessBinding, ProcessInvocation, ProcessToolRequest, ProcessTrustTier, RunId, Sha256Digest,
    TaskId, WorkspaceVersion,
};

#[test]
fn claimed_execution_orders_begin_effect_resolve_and_preserves_claim_authority() {
    let fixture = authorized_fixture("execution-a", "test");
    let authority = claim_authority(
        fixture.request.execution_id.clone(),
        fixture.operation_digest.clone(),
    );
    let sequence = recording_sequence();
    let store = RecordingStore::claiming(authority.clone(), sequence.clone());
    let executor = RecordingExecutor::succeeding(
        process_receipt(
            fixture.request.execution_id.clone(),
            ProcessStatus::Exited,
            Some(0),
        ),
        sequence.clone(),
    );
    let use_case = ExecuteDurableTool::new(&store, &executor);

    let outcome = use_case.execute(fixture.request).unwrap();

    assert_eq!(
        sequence.lock().unwrap().as_slice(),
        ["begin", "effect", "resolve"]
    );
    assert_eq!(executor.calls(), 1);
    let writes = store.terminal_writes();
    assert_eq!(writes.len(), 1);
    assert_eq!(writes[0].authority(), &authority);
    assert_eq!(
        writes[0].receipt().terminal(),
        &ToolExecutionTerminal::succeeded(ToolExecutionOutput {
            exit_code: Some(0),
            output_digest: digest('9'),
            duration_ms: 25,
            artifacts: unavailable_process_artifacts(),
        })
        .unwrap()
    );
    assert_eq!(
        outcome,
        DurableToolExecutionOutcome::Completed(writes[0].receipt().clone())
    );
}

#[test]
fn operation_digest_is_revalidated_before_begin_and_distinguishes_duplicates() {
    let first = authorized_fixture("execution-a", "test");
    let second = authorized_fixture("execution-a", "check");
    assert_ne!(first.operation_digest, second.operation_digest);
    let sequence = recording_sequence();
    let completed = durable_receipt(
        claim_authority(
            ToolExecutionId::new("execution-a").unwrap(),
            first.operation_digest.clone(),
        ),
        ToolExecutionTerminal::interrupted(),
    );
    let store = RecordingStore::digest_checking(completed, sequence.clone());
    let executor = RecordingExecutor::failing(internal_failure(), sequence);
    let use_case = ExecuteDurableTool::new(&store, &executor);

    use_case.execute(first.request).unwrap();
    let error = use_case.execute(second.request).unwrap_err();

    assert_eq!(
        error.safe_classification(),
        SafeErrorClassification::Conflict
    );
    assert_eq!(
        store
            .begin_requests()
            .iter()
            .map(|request| request.operation_digest.clone())
            .collect::<Vec<_>>(),
        vec![first.operation_digest, second.operation_digest]
    );
    assert_eq!(executor.calls(), 0);
}

#[test]
fn in_flight_claim_stops_after_begin() {
    let fixture = authorized_fixture("execution-a", "test");
    let evidence = recovery_evidence(
        fixture.request.execution_id.clone(),
        fixture.operation_digest.clone(),
    );
    let sequence = recording_sequence();
    let store = RecordingStore::with_claim(
        Ok(ToolExecutionClaim::InFlight(evidence.clone())),
        sequence.clone(),
    );
    let executor = RecordingExecutor::failing(internal_failure(), sequence.clone());
    let use_case = ExecuteDurableTool::new(&store, &executor);

    let outcome = use_case.execute(fixture.request).unwrap();

    assert_eq!(outcome, DurableToolExecutionOutcome::InFlight(evidence));
    assert_eq!(sequence.lock().unwrap().as_slice(), ["begin"]);
    assert_eq!(executor.calls(), 0);
    assert!(store.terminal_writes().is_empty());
}

#[test]
fn completed_claim_stops_after_begin_and_returns_exact_durable_receipt() {
    let fixture = authorized_fixture("execution-a", "test");
    let authority = claim_authority(
        fixture.request.execution_id.clone(),
        fixture.operation_digest.clone(),
    );
    let receipt = durable_receipt(
        authority,
        ToolExecutionTerminal::failed(ToolExecutionOutput {
            exit_code: Some(3),
            output_digest: digest('7'),
            duration_ms: 91,
            artifacts: available_process_artifacts(),
        })
        .unwrap(),
    );
    let sequence = recording_sequence();
    let store = RecordingStore::with_claim(
        Ok(ToolExecutionClaim::Completed(receipt.clone())),
        sequence.clone(),
    );
    let executor = RecordingExecutor::failing(internal_failure(), sequence.clone());
    let use_case = ExecuteDurableTool::new(&store, &executor);

    let outcome = use_case.execute(fixture.request).unwrap();

    assert_eq!(outcome, DurableToolExecutionOutcome::Completed(receipt));
    assert_eq!(sequence.lock().unwrap().as_slice(), ["begin"]);
    assert_eq!(executor.calls(), 0);
    assert!(store.terminal_writes().is_empty());
}

#[test]
fn indeterminate_claim_stops_after_begin_without_retry_implication() {
    let fixture = authorized_fixture("execution-a", "test");
    let evidence = recovery_evidence(
        fixture.request.execution_id.clone(),
        fixture.operation_digest.clone(),
    );
    let sequence = recording_sequence();
    let store = RecordingStore::with_claim(
        Ok(ToolExecutionClaim::Indeterminate(evidence.clone())),
        sequence.clone(),
    );
    let executor = RecordingExecutor::failing(internal_failure(), sequence.clone());
    let use_case = ExecuteDurableTool::new(&store, &executor);

    let outcome = use_case.execute(fixture.request).unwrap();

    assert_eq!(
        outcome,
        DurableToolExecutionOutcome::Indeterminate(evidence)
    );
    assert_eq!(sequence.lock().unwrap().as_slice(), ["begin"]);
    assert_eq!(executor.calls(), 0);
    assert!(store.terminal_writes().is_empty());
}

#[test]
fn mismatched_in_flight_response_fails_closed_after_begin() {
    let fixture = authorized_fixture("execution-a", "test");
    let evidence = recovery_evidence(
        ToolExecutionId::new("execution-b").unwrap(),
        fixture.operation_digest.clone(),
    );
    let sequence = recording_sequence();
    let store =
        RecordingStore::with_claim(Ok(ToolExecutionClaim::InFlight(evidence)), sequence.clone());
    let executor = RecordingExecutor::failing(internal_failure(), sequence.clone());
    let use_case = ExecuteDurableTool::new(&store, &executor);

    let error = use_case.execute(fixture.request).unwrap_err();

    assert_eq!(
        error.safe_classification(),
        SafeErrorClassification::IntegrityFailure
    );
    assert_eq!(sequence.lock().unwrap().as_slice(), ["begin"]);
    assert_eq!(executor.calls(), 0);
    assert!(store.terminal_writes().is_empty());
}

#[test]
fn mismatched_completed_response_fails_closed_after_begin() {
    let fixture = authorized_fixture("execution-a", "test");
    let receipt = durable_receipt(
        claim_authority(
            ToolExecutionId::new("execution-b").unwrap(),
            fixture.operation_digest.clone(),
        ),
        ToolExecutionTerminal::interrupted(),
    );
    let sequence = recording_sequence();
    let store =
        RecordingStore::with_claim(Ok(ToolExecutionClaim::Completed(receipt)), sequence.clone());
    let executor = RecordingExecutor::failing(internal_failure(), sequence.clone());
    let use_case = ExecuteDurableTool::new(&store, &executor);

    let error = use_case.execute(fixture.request).unwrap_err();

    assert_eq!(
        error.safe_classification(),
        SafeErrorClassification::IntegrityFailure
    );
    assert_eq!(sequence.lock().unwrap().as_slice(), ["begin"]);
    assert_eq!(executor.calls(), 0);
    assert!(store.terminal_writes().is_empty());
}

#[test]
fn mismatched_indeterminate_response_fails_closed_after_begin() {
    let fixture = authorized_fixture("execution-a", "test");
    let mut evidence = recovery_evidence(
        fixture.request.execution_id.clone(),
        fixture.operation_digest.clone(),
    );
    evidence.task_id = TaskId::new("task-2").unwrap();
    let sequence = recording_sequence();
    let store = RecordingStore::with_claim(
        Ok(ToolExecutionClaim::Indeterminate(evidence)),
        sequence.clone(),
    );
    let executor = RecordingExecutor::failing(internal_failure(), sequence.clone());
    let use_case = ExecuteDurableTool::new(&store, &executor);

    let error = use_case.execute(fixture.request).unwrap_err();

    assert_eq!(
        error.safe_classification(),
        SafeErrorClassification::IntegrityFailure
    );
    assert_eq!(sequence.lock().unwrap().as_slice(), ["begin"]);
    assert_eq!(executor.calls(), 0);
    assert!(store.terminal_writes().is_empty());
}

#[test]
fn begin_failure_stops_after_begin() {
    let fixture = authorized_fixture("execution-a", "test");
    let sequence = recording_sequence();
    let store = RecordingStore::with_claim(Err(unavailable()), sequence.clone());
    let executor = RecordingExecutor::failing(internal_failure(), sequence.clone());
    let use_case = ExecuteDurableTool::new(&store, &executor);

    let error = use_case.execute(fixture.request).unwrap_err();

    assert_eq!(error, unavailable());
    assert_eq!(sequence.lock().unwrap().as_slice(), ["begin"]);
    assert_eq!(executor.calls(), 0);
    assert!(store.terminal_writes().is_empty());
}

#[test]
fn generic_executor_error_resolves_indeterminate_with_safe_metadata() {
    let fixture = authorized_fixture("execution-a", "test");
    let authority = claim_authority(
        fixture.request.execution_id.clone(),
        fixture.operation_digest.clone(),
    );
    let sequence = recording_sequence();
    let store = RecordingStore::claiming(authority.clone(), sequence.clone());
    let executor = RecordingExecutor::failing(internal_failure(), sequence.clone());
    let use_case = ExecuteDurableTool::new(&store, &executor);

    let outcome = use_case.execute(fixture.request).unwrap();

    assert_eq!(
        sequence.lock().unwrap().as_slice(),
        ["begin", "effect", "resolve"]
    );
    let writes = store.terminal_writes();
    assert_eq!(writes.len(), 1);
    assert_eq!(writes[0].authority(), &authority);
    assert_eq!(
        writes[0].receipt().terminal(),
        &ToolExecutionTerminal::indeterminate(SafeToolExecutionError {
            classification: SafeErrorClassification::Internal,
            retryability: Retryability::NonRetryable,
        })
    );
    assert_eq!(
        outcome,
        DurableToolExecutionOutcome::Completed(writes[0].receipt().clone())
    );
}

#[test]
fn terminal_persistence_failure_returns_typed_unresolved_outcome() {
    let fixture = authorized_fixture("execution-a", "test");
    let authority = claim_authority(
        fixture.request.execution_id.clone(),
        fixture.operation_digest.clone(),
    );
    let sequence = recording_sequence();
    let store = RecordingStore::claiming(authority.clone(), sequence.clone())
        .with_resolution_error(unavailable());
    let executor = RecordingExecutor::succeeding(
        process_receipt(
            fixture.request.execution_id.clone(),
            ProcessStatus::Exited,
            Some(0),
        ),
        sequence.clone(),
    );
    let use_case = ExecuteDurableTool::new(&store, &executor);

    let outcome = use_case.execute(fixture.request).unwrap();

    let attempted_resolution = store.terminal_writes()[0].clone();
    assert_eq!(
        outcome,
        DurableToolExecutionOutcome::TerminalPersistenceUnresolved {
            resolution: attempted_resolution,
            error: SafeToolExecutionError {
                classification: SafeErrorClassification::Unavailable,
                retryability: Retryability::Retryable,
            },
        }
    );
    assert_eq!(
        sequence.lock().unwrap().as_slice(),
        ["begin", "effect", "resolve"]
    );
}

#[test]
fn executor_receipt_for_b_resolves_a_as_indeterminate_and_never_writes_b() {
    let fixture = authorized_fixture("execution-a", "test");
    let authority = claim_authority(
        fixture.request.execution_id.clone(),
        fixture.operation_digest.clone(),
    );
    let sequence = recording_sequence();
    let store = RecordingStore::claiming(authority.clone(), sequence.clone());
    let executor = RecordingExecutor::succeeding(
        process_receipt(
            ToolExecutionId::new("execution-b").unwrap(),
            ProcessStatus::Exited,
            Some(0),
        ),
        sequence.clone(),
    );
    let use_case = ExecuteDurableTool::new(&store, &executor);

    let outcome = use_case.execute(fixture.request).unwrap();

    let writes = store.terminal_writes();
    assert_eq!(writes.len(), 1);
    assert_eq!(writes[0].authority(), &authority);
    assert_eq!(
        writes[0].receipt(),
        &DurableToolExecutionReceipt::new(
            authority.clone(),
            ToolExecutionTerminal::indeterminate(SafeToolExecutionError {
                classification: SafeErrorClassification::IntegrityFailure,
                retryability: Retryability::NonRetryable,
            }),
        )
    );
    assert!(writes
        .iter()
        .all(|write| write.authority().execution_id().as_str() != "execution-b"));
    assert_eq!(
        outcome,
        DurableToolExecutionOutcome::Completed(writes[0].receipt().clone())
    );
    assert_eq!(
        sequence.lock().unwrap().as_slice(),
        ["begin", "effect", "resolve"]
    );
}

#[test]
fn nonzero_exit_is_failed_and_retains_safe_durable_evidence() {
    assert_failed_process_outcome(Some(23));
}

#[test]
fn absent_exit_code_is_failed_and_retains_safe_durable_evidence() {
    assert_failed_process_outcome(None);
}

#[test]
fn process_terminal_constructors_reject_contradictory_exit_states() {
    assert!(ToolExecutionTerminal::succeeded(process_output(Some(9))).is_err());
    assert!(ToolExecutionTerminal::succeeded(process_output(None)).is_err());
    assert!(ToolExecutionTerminal::failed(process_output(Some(0))).is_err());
    assert!(ToolExecutionTerminal::terminated(process_output(Some(0))).is_err());
}

#[test]
fn terminal_accessors_expose_only_kind_appropriate_evidence() {
    let failed = ToolExecutionTerminal::failed(process_output(Some(9))).unwrap();
    assert_eq!(failed.kind(), ToolExecutionTerminalKind::Failed);
    assert_eq!(failed.output().unwrap().exit_code, Some(9));
    assert_eq!(failed.error(), None);

    let error = SafeToolExecutionError {
        classification: SafeErrorClassification::Unavailable,
        retryability: Retryability::Retryable,
    };
    let indeterminate = ToolExecutionTerminal::indeterminate(error);
    assert_eq!(
        indeterminate.kind(),
        ToolExecutionTerminalKind::Indeterminate
    );
    assert_eq!(indeterminate.output(), None);
    assert_eq!(indeterminate.error(), Some(&error));
}

#[test]
fn artifact_evidence_has_fixed_stream_slots_and_ordered_observed_writes() {
    let artifacts = available_process_artifacts();

    assert_eq!(
        artifacts.stdout(),
        &DurableToolExecutionArtifact::Available(ArtifactId::new("artifact-stdout").unwrap())
    );
    assert_eq!(
        artifacts.stderr(),
        &DurableToolExecutionArtifact::Available(ArtifactId::new("artifact-stderr").unwrap())
    );
    assert_eq!(
        artifacts.observed_writes(),
        &[DurableToolExecutionArtifact::Available(
            ArtifactId::new("artifact-write-0").unwrap()
        )]
    );
}

#[test]
fn incomplete_listing_returns_authoritative_recovery_evidence_read_only() {
    let fixture = authorized_fixture("execution-a", "test");
    let evidence = recovery_evidence(
        fixture.request.execution_id.clone(),
        fixture.operation_digest.clone(),
    );
    let records = vec![IncompleteToolExecution::Indeterminate(evidence.clone())];
    let sequence = recording_sequence();
    let store = RecordingStore::with_incomplete(records.clone(), sequence.clone());
    let executor = RecordingExecutor::failing(internal_failure(), sequence.clone());
    let use_case = ExecuteDurableTool::new(&store, &executor);

    let observed = use_case.incomplete().unwrap();

    assert_eq!(observed, records);
    assert_eq!(evidence.task_id, TaskId::new("task-1").unwrap());
    assert_eq!(
        evidence.authority.owner_run_id(),
        &RunId::new("run-1").unwrap()
    );
    assert_eq!(
        evidence.canonical_request_artifact_id,
        ArtifactId::new("artifact-request-a").unwrap()
    );
    assert_eq!(evidence.idempotency_class, IdempotencyClass::NonRepeatable);
    assert_eq!(evidence.authority.attempt(), 7);
    assert_eq!(
        evidence.authority.executor_fencing_token(),
        Some(FencingToken::new(19).unwrap())
    );
    assert_eq!(sequence.lock().unwrap().as_slice(), ["incomplete"]);
    assert!(store.terminal_writes().is_empty());
    assert_eq!(executor.calls(), 0);
}

fn assert_failed_process_outcome(exit_code: Option<i32>) {
    let fixture = authorized_fixture("execution-a", "test");
    let authority = claim_authority(
        fixture.request.execution_id.clone(),
        fixture.operation_digest.clone(),
    );
    let sequence = recording_sequence();
    let store = RecordingStore::claiming(authority, sequence.clone());
    let executor = RecordingExecutor::succeeding(
        process_receipt(
            fixture.request.execution_id.clone(),
            ProcessStatus::Exited,
            exit_code,
        ),
        sequence,
    );
    let use_case = ExecuteDurableTool::new(&store, &executor);

    let outcome = use_case.execute(fixture.request).unwrap();

    let DurableToolExecutionOutcome::Completed(receipt) = outcome else {
        panic!("expected a durably resolved process failure");
    };
    assert_eq!(
        receipt.terminal(),
        &ToolExecutionTerminal::failed(ToolExecutionOutput {
            exit_code,
            output_digest: digest('9'),
            duration_ms: 25,
            artifacts: unavailable_process_artifacts(),
        })
        .unwrap()
    );
}

type RecordingSequence = Arc<Mutex<Vec<&'static str>>>;

fn recording_sequence() -> RecordingSequence {
    Arc::new(Mutex::new(Vec::new()))
}

struct RecordingStore {
    claim: Result<ToolExecutionClaim, PortError>,
    incomplete: Vec<IncompleteToolExecution>,
    sequence: RecordingSequence,
    begin_requests: Mutex<Vec<NewToolExecution>>,
    terminal_writes: Mutex<Vec<ToolExecutionResolution>>,
    resolution_error: Option<PortError>,
    enforce_first_digest: bool,
}

impl RecordingStore {
    fn claiming(authority: ToolExecutionClaimAuthority, sequence: RecordingSequence) -> Self {
        Self::with_claim(Ok(ToolExecutionClaim::Claimed(authority)), sequence)
    }

    fn with_claim(
        claim: Result<ToolExecutionClaim, PortError>,
        sequence: RecordingSequence,
    ) -> Self {
        Self {
            claim,
            incomplete: Vec::new(),
            sequence,
            begin_requests: Mutex::new(Vec::new()),
            terminal_writes: Mutex::new(Vec::new()),
            resolution_error: None,
            enforce_first_digest: false,
        }
    }

    fn digest_checking(receipt: DurableToolExecutionReceipt, sequence: RecordingSequence) -> Self {
        Self {
            enforce_first_digest: true,
            ..Self::with_claim(Ok(ToolExecutionClaim::Completed(receipt)), sequence)
        }
    }

    fn with_incomplete(
        incomplete: Vec<IncompleteToolExecution>,
        sequence: RecordingSequence,
    ) -> Self {
        Self {
            incomplete,
            ..Self::with_claim(
                Ok(ToolExecutionClaim::Completed(durable_receipt(
                    claim_authority(ToolExecutionId::new("unused").unwrap(), digest('1')),
                    ToolExecutionTerminal::interrupted(),
                ))),
                sequence,
            )
        }
    }

    fn with_resolution_error(mut self, error: PortError) -> Self {
        self.resolution_error = Some(error);
        self
    }

    fn begin_requests(&self) -> Vec<NewToolExecution> {
        self.begin_requests.lock().unwrap().clone()
    }

    fn terminal_writes(&self) -> Vec<ToolExecutionResolution> {
        self.terminal_writes.lock().unwrap().clone()
    }
}

impl ToolExecutionStore for RecordingStore {
    fn reserve(&self, request: NewToolIntent) -> Result<OperationIntentSnapshot, PortError> {
        Ok(OperationIntentSnapshot {
            execution_id: request.execution_id,
            operation_digest: request.operation_digest,
        })
    }

    fn begin(&self, request: NewToolExecution) -> Result<ToolExecutionClaim, PortError> {
        self.sequence.lock().unwrap().push("begin");
        let mut requests = self.begin_requests.lock().unwrap();
        let digest_mismatch = self.enforce_first_digest
            && requests
                .first()
                .is_some_and(|first| first.operation_digest != request.operation_digest);
        requests.push(request);
        if digest_mismatch {
            return Err(conflict());
        }
        self.claim.clone()
    }

    fn resolve_terminal(
        &self,
        resolution: ToolExecutionResolution,
    ) -> Result<DurableToolExecutionReceipt, PortError> {
        self.sequence.lock().unwrap().push("resolve");
        self.terminal_writes
            .lock()
            .unwrap()
            .push(resolution.clone());
        if let Some(error) = &self.resolution_error {
            return Err(error.clone());
        }
        Ok(resolution.receipt().clone())
    }

    fn incomplete(&self) -> Result<Vec<IncompleteToolExecution>, PortError> {
        self.sequence.lock().unwrap().push("incomplete");
        Ok(self.incomplete.clone())
    }
}

struct RecordingExecutor {
    result: Mutex<Option<Result<ToolExecutionResult, PortError>>>,
    calls: AtomicUsize,
    sequence: RecordingSequence,
}

impl RecordingExecutor {
    fn succeeding(receipt: ProcessReceipt, sequence: RecordingSequence) -> Self {
        Self {
            result: Mutex::new(Some(Ok(ToolExecutionResult { receipt }))),
            calls: AtomicUsize::new(0),
            sequence,
        }
    }

    fn failing(error: PortError, sequence: RecordingSequence) -> Self {
        Self {
            result: Mutex::new(Some(Err(error))),
            calls: AtomicUsize::new(0),
            sequence,
        }
    }

    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

impl StructuredToolExecutor for RecordingExecutor {
    fn execute(&self, _: AuthorizedToolRequest) -> Result<ToolExecutionResult, PortError> {
        self.sequence.lock().unwrap().push("effect");
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.result.lock().unwrap().take().unwrap()
    }

    fn cancel(&self, execution_id: &ToolExecutionId) -> Result<CancellationReceipt, PortError> {
        Ok(CancellationReceipt {
            execution_id: execution_id.clone(),
            status: ProcessStatus::Terminated,
            job_receipt: None,
            cancelled: true,
        })
    }

    fn file_read(
        &self,
        _: local_agent_terminal_application::FileReadRequest,
    ) -> Result<
        local_agent_terminal_application::DisclosureOutcome<
            local_agent_terminal_application::PolicyBoundBytes,
        >,
        PortError,
    > {
        unreachable!()
    }

    fn file_write(
        &self,
        _: local_agent_terminal_application::FileWriteRequest,
    ) -> Result<local_agent_terminal_application::VerifiedWrite, PortError> {
        unreachable!()
    }

    fn git_status(
        &self,
        _: local_agent_terminal_application::GitStatusRequest,
    ) -> Result<
        local_agent_terminal_application::DisclosureOutcome<
            local_agent_terminal_application::GitStatusResult,
        >,
        PortError,
    > {
        unreachable!()
    }

    fn git_diff(
        &self,
        _: local_agent_terminal_application::GitDiffRequest,
    ) -> Result<
        local_agent_terminal_application::DisclosureOutcome<
            local_agent_terminal_application::GitDiffResult,
        >,
        PortError,
    > {
        unreachable!()
    }
}

struct AuthorizedFixture {
    request: AuthorizedToolRequest,
    operation_digest: Sha256Digest,
}

fn authorized_fixture(execution_id: &str, argument: &str) -> AuthorizedFixture {
    let request = approved_process_request(argument);
    let approval = approved_tool_binding(&request);
    let operation_digest =
        canonical_approval_payload(&ApprovalDigestPayload::Tool(approval.payload().clone()))
            .unwrap()
            .operation_digest;
    AuthorizedFixture {
        request: AuthorizedToolRequest::new(
            ToolExecutionId::new(execution_id).unwrap(),
            approval,
            request,
        ),
        operation_digest,
    }
}

fn approved_process_request(argument: &str) -> ApprovedProcessRequest {
    let task_id = TaskId::new("task-1").unwrap();
    let process = ProcessToolRequest::new(
        ProcessBinding::new(
            task_id.clone(),
            RunId::new("run-1").unwrap(),
            PlanStepId::new("step-1").unwrap(),
            Phase::Implementation,
            WorkspaceVersion::new(4),
            EnvironmentProfile::new("rust", digest('e')).unwrap(),
            1,
        )
        .unwrap(),
        ProcessInvocation::new(
            CapabilityRef::toolchain("cargo").unwrap(),
            vec![argument.to_owned()],
            CapabilityRef::worktree(task_id, ".").unwrap(),
            ProcessTrustTier::IsolatedWorker,
            NetworkProfile::Denied,
            Vec::new(),
            Some(FencingToken::new(19).unwrap()),
        )
        .unwrap(),
    )
    .unwrap();
    ApprovedProcessRequest {
        approved_executable: ApprovedExecutableIdentity::new(
            ResolvedExecutable {
                canonical_path: PathBuf::from(r"C:\approved\cargo.exe"),
                sha256: digest('d'),
                file_identity: local_agent_terminal_application::ExecutableFileIdentity::new(
                    "cargo-file",
                )
                .unwrap(),
                toolchain_id: "cargo".to_owned(),
            },
            "1.97.1",
        )
        .unwrap(),
        process,
        expected_reads: Vec::new(),
        memory_limit_bytes: None,
        cpu_time_limit_ms: None,
    }
}

fn approved_tool_binding(request: &ApprovedProcessRequest) -> BoundToolApproval {
    bind_tool_approval_payload(
        ToolApprovalPayloadV1 {
            schema: "approval-digest.v1".to_owned(),
            approval_type: "tool".to_owned(),
            task_id: "unbound".to_owned(),
            operation: ToolApprovalOperationV1 {
                run_id: "unbound".to_owned(),
                plan_step_id: "unbound".to_owned(),
                tool: "process.exec".to_owned(),
                executable_digest: None,
                arguments_digest: digest('0').as_str().to_owned(),
                script_digest: None,
                cwd_capability: "unbound".to_owned(),
                environment_profile_digest: digest('0').as_str().to_owned(),
                network_profile: "denied".to_owned(),
                expected_writes: Vec::new(),
                executor_fencing_token: None,
            },
            policy_snapshot_digest: digest('b').as_str().to_owned(),
            workspace_version: 0,
            requested_at: "2026-07-23T12:00:00Z".to_owned(),
            expires_at: "2026-07-23T12:15:00Z".to_owned(),
            nonce: "0123456789abcdef0123456789abcdef".to_owned(),
        },
        request,
    )
    .unwrap()
}

fn process_receipt(
    execution_id: ToolExecutionId,
    status: ProcessStatus,
    exit_code: Option<i32>,
) -> ProcessReceipt {
    ProcessReceipt {
        execution_id,
        status,
        exit_code,
        stdout: BoundedOutput {
            bytes: b"secret stdout".to_vec(),
            truncated: false,
        },
        stderr: BoundedOutput {
            bytes: b"secret stderr".to_vec(),
            truncated: false,
        },
        duration_ms: 25,
        job_receipt: JobReceipt {
            root_pid: 42,
            job_id: r"C:\secret\runtime\job".to_owned(),
            kill_on_close: true,
            no_breakaway: true,
            job_memory_limit: false,
            job_cpu_time_limit: false,
            memory_limit_bytes: 0,
            cpu_time_limit_ms: 0,
            max_active_processes: 1,
            total_user_time_ms: 10,
            resource_limit_terminated: false,
            tree_terminated: false,
        },
        observed_writes: Vec::new(),
        output_digest: digest('9'),
    }
}

fn claim_authority(
    execution_id: ToolExecutionId,
    operation_digest: Sha256Digest,
) -> ToolExecutionClaimAuthority {
    ToolExecutionClaimAuthority::from_persisted(
        execution_id,
        operation_digest,
        RunId::new("run-1").unwrap(),
        7,
        Some(FencingToken::new(19).unwrap()),
    )
    .unwrap()
}

fn recovery_evidence(
    execution_id: ToolExecutionId,
    operation_digest: Sha256Digest,
) -> ToolExecutionRecoveryEvidence {
    ToolExecutionRecoveryEvidence {
        authority: claim_authority(execution_id, operation_digest),
        task_id: TaskId::new("task-1").unwrap(),
        canonical_request_artifact_id: ArtifactId::new("artifact-request-a").unwrap(),
        idempotency_class: IdempotencyClass::NonRepeatable,
    }
}

fn durable_receipt(
    authority: ToolExecutionClaimAuthority,
    terminal: ToolExecutionTerminal,
) -> DurableToolExecutionReceipt {
    DurableToolExecutionReceipt::new(authority, terminal)
}

fn process_output(exit_code: Option<i32>) -> ToolExecutionOutput {
    ToolExecutionOutput {
        exit_code,
        output_digest: digest('9'),
        duration_ms: 25,
        artifacts: unavailable_process_artifacts(),
    }
}

fn unavailable_process_artifacts() -> DurableToolExecutionArtifacts {
    DurableToolExecutionArtifacts::new(
        DurableToolExecutionArtifact::Unavailable,
        DurableToolExecutionArtifact::Unavailable,
        Vec::new(),
    )
}

fn available_process_artifacts() -> DurableToolExecutionArtifacts {
    DurableToolExecutionArtifacts::new(
        DurableToolExecutionArtifact::Available(ArtifactId::new("artifact-stdout").unwrap()),
        DurableToolExecutionArtifact::Available(ArtifactId::new("artifact-stderr").unwrap()),
        vec![DurableToolExecutionArtifact::Available(
            ArtifactId::new("artifact-write-0").unwrap(),
        )],
    )
}

fn digest(character: char) -> Sha256Digest {
    Sha256Digest::new(format!("sha256:{}", character.to_string().repeat(64))).unwrap()
}

fn internal_failure() -> PortError {
    PortError::failure(
        SafeErrorClassification::Internal,
        Retryability::NonRetryable,
    )
}

fn unavailable() -> PortError {
    PortError::failure(
        SafeErrorClassification::Unavailable,
        Retryability::Retryable,
    )
}

fn conflict() -> PortError {
    PortError::failure(
        SafeErrorClassification::Conflict,
        Retryability::NonRetryable,
    )
}
