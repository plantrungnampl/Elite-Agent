use std::sync::{Arc, Mutex};

use local_agent_terminal_application::{
    AcquireLease, AgentRuntime, AppendOperation, AppendResult, AuthoritativeProcessBinding,
    AuthorizedFileRead, AuthorizedFileWrite, AuthorizedToolRequest, CancellationReceipt,
    CapabilityFilesystem, CreateWorktree, DeliberationArtifactRef, DeliberationBoundaryCheck,
    DeliberationBoundaryRecord, DeliberationBoundaryStore, DeliberationDispatchBinding,
    DeliberationDispatchStore, DeliberationPhaseDispatchSet, DeliberationProposalDispatchPlan,
    DeliberationRepositoryAuthority, DeliberationRunAssignment, DeliberationToolCatalog,
    DeliberationToolSchema, DiscardWorktree, DisclosureOutcome, EventStore, ExecutorLeaseStore,
    FileReadRequest, FileWriteRequest, GitDiffRequest, GitDiffResult, GitStatusRequest,
    GitStatusResult, InspectRepository, LeaseSnapshot, PolicyBoundBytes, PortError,
    RepositoryGateway, RepositoryLocator, RepositorySnapshot, Retryability, RevokeLease,
    SafeErrorClassification, StructuredToolExecutor, ToolExecutionId, ToolExecutionResult,
    VerifiedBytes, VerifiedWrite, WorktreeSnapshot,
};
use local_agent_terminal_domain::{
    AgentCancellationReceipt, AgentDescriptor, AgentRunLimits, AgentRunReceipt, ArtifactId,
    BoundAgentConnection, BoundAgentRunRequest, BoundEffectiveContext, BoundGenerationParameters,
    BoundRunConfig, CancelAgentRun, Condition, FencingToken, GitObjectId, OperationState, Phase,
    RunId, Sequence, Sha256Digest, TaskId, Timestamp, TrustTier, WorkflowState,
    WorkspaceFingerprint, WorkspaceVersion,
};
use local_agent_terminal_orchestration::{
    normative_preapproval_transitions, PhaseAdvanceRequest, PreApprovalCoordinator,
    PrePlanOperation, PrePlanReadView,
};

#[test]
fn preapproval_path_queries_only_typed_read_catalog_and_never_calls_mutation_adapters() {
    let spies = WriteSpyAdapter::new(Some(fingerprint('a')), fingerprint('a'));
    assert_write_capable_adapter(&spies);
    let read_view = spies.preapproval_view();
    let coordinator =
        PreApprovalCoordinator::from_read_view(read_view, &spies, &spies, &spies, &spies);

    coordinator
        .coordinate(PrePlanOperation::AdvanceAndDispatch {
            request: phase_request(workflow_state(Phase::ContextBuild, 1)),
            transition: normative_preapproval_transitions()[1],
            dispatch_plan: Box::new(dispatch_plan()),
        })
        .unwrap();

    assert_eq!(*spies.schema_queries.lock().unwrap(), 1);
    assert_eq!(*spies.event_writes.lock().unwrap(), 1);
    assert_eq!(*spies.binding_set_writes.lock().unwrap(), 1);
    assert_eq!(*spies.runtime_dispatches.lock().unwrap(), 2);
    assert_eq!(
        *spies.mutations.lock().unwrap(),
        MutationCalls {
            repository_writes: 0,
            worktrees_created: 0,
            branches_created: 0,
            refs_updated: 0,
            files_written: 0,
            executor_leases_acquired: 0,
            tool_mutations: 0,
        }
    );
}

#[test]
fn fingerprint_mismatch_blocks_and_invalidates_before_tools_events_or_dispatch() {
    let spies = WriteSpyAdapter::new(Some(fingerprint('a')), fingerprint('b'));
    let coordinator = PreApprovalCoordinator::new(&spies, &spies, &spies, &spies, &spies, &spies);

    let error = coordinator
        .coordinate(PrePlanOperation::AdvanceAndDispatch {
            request: phase_request(workflow_state(Phase::ContextBuild, 1)),
            transition: normative_preapproval_transitions()[1],
            dispatch_plan: Box::new(dispatch_plan()),
        })
        .unwrap_err();

    assert_eq!(
        error.safe_classification(),
        SafeErrorClassification::IntegrityFailure
    );
    let records = spies.boundaries.lock().unwrap();
    assert_eq!(records.len(), 1);
    assert!(records[0].blocked);
    assert!(records[0].invalidate_context_packages);
    assert!(records[0].invalidate_plan_approval);
    assert_eq!(*spies.schema_queries.lock().unwrap(), 0);
    assert_eq!(*spies.event_writes.lock().unwrap(), 0);
    assert_eq!(*spies.binding_set_writes.lock().unwrap(), 0);
    assert_eq!(*spies.runtime_dispatches.lock().unwrap(), 0);
}

#[test]
fn authoritative_baseline_is_captured_before_context_build_event() {
    let spies = WriteSpyAdapter::new(None, fingerprint('a'));
    let coordinator = PreApprovalCoordinator::new(&spies, &spies, &spies, &spies, &spies, &spies);

    let result = coordinator
        .coordinate(PrePlanOperation::AdvanceOnly {
            request: phase_request(workflow_state(Phase::Intake, 0)),
            transition: normative_preapproval_transitions()[0],
        })
        .unwrap();

    assert_eq!(result.next_state.phase(), Phase::ContextBuild);
    assert_eq!(*spies.baseline.lock().unwrap(), Some(fingerprint('a')));
    assert_eq!(*spies.event_writes.lock().unwrap(), 1);
}

#[test]
fn atomic_boundary_commit_is_observed_after_a_post_commit_fault_and_reopen() {
    let spies = WriteSpyAdapter::new(Some(fingerprint('a')), fingerprint('a'));
    let boundaries = FaultingBoundaryStore::new();
    let first = PreApprovalCoordinator::new(&spies, &boundaries, &spies, &spies, &spies, &spies);
    assert!(first
        .coordinate(PrePlanOperation::AdvanceOnly {
            request: phase_request(workflow_state(Phase::Intake, 0)),
            transition: normative_preapproval_transitions()[0],
        })
        .is_err());

    let reopened_boundaries = boundaries.reopen();
    PreApprovalCoordinator::new(&spies, &reopened_boundaries, &spies, &spies, &spies, &spies)
        .coordinate(PrePlanOperation::AdvanceOnly {
            request: phase_request(workflow_state(Phase::Intake, 0)),
            transition: normative_preapproval_transitions()[0],
        })
        .unwrap();

    let durable = reopened_boundaries.durable.lock().unwrap();
    assert_eq!(durable.records.len(), 1);
    assert_eq!(durable.baseline, Some(fingerprint('a')));
    assert_eq!(durable.attempts, 2);
    assert_eq!(*spies.event_writes.lock().unwrap(), 1);
}

#[derive(Debug, Default, PartialEq, Eq)]
struct MutationCalls {
    repository_writes: usize,
    worktrees_created: usize,
    branches_created: usize,
    refs_updated: usize,
    files_written: usize,
    executor_leases_acquired: usize,
    tool_mutations: usize,
}

struct WriteSpyAdapter {
    baseline: Mutex<Option<WorkspaceFingerprint>>,
    observed: WorkspaceFingerprint,
    boundaries: Mutex<Vec<DeliberationBoundaryRecord>>,
    schema_queries: Mutex<usize>,
    event_writes: Mutex<usize>,
    binding_set_writes: Mutex<usize>,
    runtime_dispatches: Mutex<usize>,
    mutations: Mutex<MutationCalls>,
}

struct FaultingBoundaryStore {
    durable: Arc<Mutex<AtomicBoundaryData>>,
}

#[derive(Default)]
struct AtomicBoundaryData {
    baseline: Option<WorkspaceFingerprint>,
    records: Vec<DeliberationBoundaryRecord>,
    attempts: usize,
    fault_after_commit: bool,
}

impl FaultingBoundaryStore {
    fn new() -> Self {
        Self {
            durable: Arc::new(Mutex::new(AtomicBoundaryData {
                fault_after_commit: true,
                ..AtomicBoundaryData::default()
            })),
        }
    }

    fn reopen(&self) -> Self {
        Self {
            durable: self.durable.clone(),
        }
    }
}

impl DeliberationBoundaryStore for FaultingBoundaryStore {
    fn compare_and_persist_boundary(
        &self,
        check: DeliberationBoundaryCheck,
    ) -> Result<DeliberationBoundaryRecord, PortError> {
        let mut durable = self.durable.lock().unwrap();
        durable.attempts += 1;
        if let Some(existing) = durable.records.last() {
            return Ok(existing.clone());
        }
        let expected = durable
            .baseline
            .clone()
            .unwrap_or_else(|| check.observed_fingerprint().clone());
        let record = check.compare_with(expected.clone())?;
        durable.baseline = Some(expected);
        durable.records.push(record.clone());
        if durable.fault_after_commit {
            durable.fault_after_commit = false;
            return Err(PortError::failure(
                SafeErrorClassification::Internal,
                Retryability::Retryable,
            ));
        }
        Ok(record)
    }
}

impl WriteSpyAdapter {
    fn new(baseline: Option<WorkspaceFingerprint>, observed: WorkspaceFingerprint) -> Self {
        Self {
            baseline: Mutex::new(baseline),
            observed,
            boundaries: Mutex::new(Vec::new()),
            schema_queries: Mutex::new(0),
            event_writes: Mutex::new(0),
            binding_set_writes: Mutex::new(0),
            runtime_dispatches: Mutex::new(0),
            mutations: Mutex::new(MutationCalls::default()),
        }
    }

    fn preapproval_view(&self) -> PrePlanReadView<'_> {
        PrePlanReadView::new(self, self)
    }
}

impl DeliberationRepositoryAuthority for WriteSpyAdapter {
    fn current_fingerprint(&self, _: &TaskId) -> Result<WorkspaceFingerprint, PortError> {
        Ok(self.observed.clone())
    }
}

impl DeliberationBoundaryStore for WriteSpyAdapter {
    fn compare_and_persist_boundary(
        &self,
        check: DeliberationBoundaryCheck,
    ) -> Result<DeliberationBoundaryRecord, PortError> {
        let mut baseline = self.baseline.lock().unwrap();
        let expected = baseline
            .clone()
            .unwrap_or_else(|| check.observed_fingerprint().clone());
        let record = check.compare_with(expected)?;
        record.validate()?;
        if baseline.is_none() {
            *baseline = Some(record.expected_fingerprint.clone());
        }
        self.boundaries.lock().unwrap().push(record.clone());
        Ok(record)
    }
}

impl DeliberationToolCatalog for WriteSpyAdapter {
    fn dispatch_schemas(&self, _: &TaskId) -> Result<Vec<DeliberationToolSchema>, PortError> {
        *self.schema_queries.lock().unwrap() += 1;
        Ok(Vec::new())
    }
}

impl EventStore for WriteSpyAdapter {
    fn append(&self, operation: AppendOperation) -> Result<AppendResult, PortError> {
        *self.event_writes.lock().unwrap() += 1;
        Ok(AppendResult {
            new_version: Sequence::new(operation.expected_version.get() + 1),
        })
    }
}

impl DeliberationDispatchStore for WriteSpyAdapter {
    fn compare_and_persist_proposal_binding_set(
        &self,
        plan: &DeliberationProposalDispatchPlan,
    ) -> Result<(), PortError> {
        plan.validate()?;
        *self.binding_set_writes.lock().unwrap() += 1;
        Ok(())
    }

    fn compare_and_persist_phase_binding_set(
        &self,
        dispatch_set: &DeliberationPhaseDispatchSet,
    ) -> Result<(), PortError> {
        dispatch_set.validate()?;
        *self.binding_set_writes.lock().unwrap() += 1;
        Ok(())
    }
}

impl AgentRuntime for WriteSpyAdapter {
    fn list_agents(&self) -> Result<Vec<AgentDescriptor>, PortError> {
        unreachable!()
    }

    fn start_run(&self, request: BoundAgentRunRequest) -> Result<AgentRunReceipt, PortError> {
        *self.runtime_dispatches.lock().unwrap() += 1;
        Ok(AgentRunReceipt {
            run_id: request.run_id,
            accepted_at: Timestamp::from_unix_seconds(2),
        })
    }

    fn cancel(&self, _: CancelAgentRun) -> Result<AgentCancellationReceipt, PortError> {
        unreachable!()
    }
}

fn assert_write_capable_adapter<T>(_: &T)
where
    T: RepositoryGateway + ExecutorLeaseStore + CapabilityFilesystem + StructuredToolExecutor,
{
}

impl RepositoryGateway for WriteSpyAdapter {
    fn inspect(&self, _: InspectRepository) -> Result<RepositorySnapshot, PortError> {
        Err(forbidden_mutation())
    }

    fn create_worktree(&self, _: CreateWorktree) -> Result<WorktreeSnapshot, PortError> {
        let mut calls = self.mutations.lock().unwrap();
        calls.repository_writes += 1;
        calls.worktrees_created += 1;
        calls.branches_created += 1;
        calls.refs_updated += 1;
        Err(forbidden_mutation())
    }

    fn list_worktrees(&self, _: &RepositoryLocator) -> Result<Vec<WorktreeSnapshot>, PortError> {
        Err(forbidden_mutation())
    }

    fn discard_worktree(&self, _: DiscardWorktree) -> Result<(), PortError> {
        self.mutations.lock().unwrap().repository_writes += 1;
        Err(forbidden_mutation())
    }
}

impl ExecutorLeaseStore for WriteSpyAdapter {
    fn acquire(&self, _: AcquireLease) -> Result<LeaseSnapshot, PortError> {
        self.mutations.lock().unwrap().executor_leases_acquired += 1;
        Err(forbidden_mutation())
    }

    fn revoke(&self, _: RevokeLease) -> Result<(), PortError> {
        self.mutations.lock().unwrap().executor_leases_acquired += 1;
        Err(forbidden_mutation())
    }

    fn fence_stale(&self) -> Result<Vec<LeaseSnapshot>, PortError> {
        self.mutations.lock().unwrap().executor_leases_acquired += 1;
        Err(forbidden_mutation())
    }

    fn assert_current(&self, _: local_agent_terminal_domain::LeaseClaim) -> Result<(), PortError> {
        self.mutations.lock().unwrap().executor_leases_acquired += 1;
        Err(forbidden_mutation())
    }
}

impl CapabilityFilesystem for WriteSpyAdapter {
    fn read(&self, _: AuthorizedFileRead) -> Result<VerifiedBytes, PortError> {
        Err(forbidden_mutation())
    }

    fn write(&self, _: AuthorizedFileWrite) -> Result<VerifiedWrite, PortError> {
        self.mutations.lock().unwrap().files_written += 1;
        Err(forbidden_mutation())
    }
}

impl StructuredToolExecutor for WriteSpyAdapter {
    fn execute(&self, _: AuthorizedToolRequest) -> Result<ToolExecutionResult, PortError> {
        self.mutations.lock().unwrap().tool_mutations += 1;
        Err(forbidden_mutation())
    }

    fn cancel(&self, _: &ToolExecutionId) -> Result<CancellationReceipt, PortError> {
        self.mutations.lock().unwrap().tool_mutations += 1;
        Err(forbidden_mutation())
    }

    fn terminate_retained_process(
        &self,
        _: &AuthoritativeProcessBinding,
    ) -> Result<CancellationReceipt, PortError> {
        self.mutations.lock().unwrap().tool_mutations += 1;
        Err(forbidden_mutation())
    }

    fn file_read(
        &self,
        _: FileReadRequest,
    ) -> Result<DisclosureOutcome<PolicyBoundBytes>, PortError> {
        Err(forbidden_mutation())
    }

    fn file_write(&self, _: FileWriteRequest) -> Result<VerifiedWrite, PortError> {
        let mut calls = self.mutations.lock().unwrap();
        calls.tool_mutations += 1;
        calls.files_written += 1;
        Err(forbidden_mutation())
    }

    fn git_status(
        &self,
        _: GitStatusRequest,
    ) -> Result<DisclosureOutcome<GitStatusResult>, PortError> {
        Err(forbidden_mutation())
    }

    fn git_diff(&self, _: GitDiffRequest) -> Result<DisclosureOutcome<GitDiffResult>, PortError> {
        Err(forbidden_mutation())
    }
}

fn forbidden_mutation() -> PortError {
    PortError::failure(
        SafeErrorClassification::InvalidInput,
        Retryability::NonRetryable,
    )
}

fn phase_request(expected_state: WorkflowState) -> PhaseAdvanceRequest {
    PhaseAdvanceRequest {
        task_id: TaskId::new("task-1").unwrap(),
        expected_state,
        event_id: local_agent_terminal_domain::EventId::new("event-phase").unwrap(),
        occurred_at: "2026-08-11T00:00:00Z".to_owned(),
        correlation_id: "task-1:orchestration".to_owned(),
        effect_artifacts: vec![DeliberationArtifactRef::new(
            ArtifactId::new("phase-effect").unwrap(),
            digest('a'),
            1,
        )
        .unwrap()],
    }
}

fn workflow_state(phase: Phase, sequence: u64) -> WorkflowState {
    WorkflowState::new(
        phase,
        Condition::Active,
        OperationState::None,
        Sequence::new(sequence),
        WorkspaceVersion::new(0),
        FencingToken::new(1).unwrap(),
    )
    .unwrap()
}

fn bound_run(run: &str) -> BoundAgentRunRequest {
    let task_id = TaskId::new("task-1").unwrap();
    let empty_digest = Sha256Digest::new(
        "sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a",
    )
    .unwrap();
    let executable_digest = digest('b');
    let context_digest = Sha256Digest::new(
        "sha256:7ce2a62fec3ddf55f1cede952bdcd4170bb0b01fa53da3ded734e531337d2b58",
    )
    .unwrap();
    let policy_digest = digest('d');
    BoundAgentRunRequest {
        run_id: RunId::new(run).unwrap(),
        task_id: task_id.clone(),
        agent_id: "agent-1".to_owned(),
        role: "reviewer".to_owned(),
        phase: "analysis".to_owned(),
        idempotency_key: format!("task-1:reviewer:{run}"),
        context: BoundEffectiveContext {
            context_package_id: "context-1".to_owned(),
            task_id: task_id.clone(),
            agent_id: "agent-1".to_owned(),
            role: "reviewer".to_owned(),
            objective: "Review the task.".to_owned(),
            manifest_artifact_id: ArtifactId::new("artifact-context-manifest-1").unwrap(),
            effective_context_artifact_id: ArtifactId::new("artifact-context-1").unwrap(),
            content_digest: context_digest.clone(),
            policy_snapshot_digest: policy_digest.clone(),
            prompt_template_version: "prompt-1".to_owned(),
            retrieval_pipeline_version: "retrieval-1".to_owned(),
            created_at: Timestamp::from_unix_seconds(1),
        },
        run_config: BoundRunConfig {
            run_config_artifact_id: ArtifactId::new(format!("artifact-run-config-{run}")).unwrap(),
            task_id,
            agent_id: "agent-1".to_owned(),
            role: "reviewer".to_owned(),
            context_package_id: "context-1".to_owned(),
            effective_context_artifact_id: ArtifactId::new("artifact-context-1").unwrap(),
            effective_context_digest: context_digest,
            trust_tier: TrustTier::CoreAdapter,
            manifest_digest: empty_digest.clone(),
            executable_digest: Some(executable_digest.clone()),
            contract_version: "1.0".to_owned(),
            adapter_version: "adapter-1".to_owned(),
            provider_id: "provider-1".to_owned(),
            model_id: "model-1".to_owned(),
            generation_parameters: BoundGenerationParameters {
                canonical_json: br#"{}"#.to_vec(),
                digest: empty_digest.clone(),
            },
            prompt_template_version: "prompt-1".to_owned(),
            response_schema_version: "agent-message.v1".to_owned(),
            policy_snapshot_digest: policy_digest,
            limits: AgentRunLimits {
                deadline: Timestamp::from_unix_seconds(1_800_000_300),
                max_output_tokens: 8_000,
                max_tool_requests: 0,
                max_context_queries: 0,
                max_specialist_requests: 0,
            },
        },
        connection: BoundAgentConnection {
            connection_id: "connection-1".to_owned(),
            agent_id: "agent-1".to_owned(),
            trust_tier: TrustTier::CoreAdapter,
            manifest_digest: empty_digest,
            executable_digest: Some(executable_digest),
            contract_version: "1.0".to_owned(),
            adapter_version: "adapter-1".to_owned(),
            binding_digest: Sha256Digest::new(
                "sha256:6e171d4e7a1d7b7db1c14807e8a2a5cc9093eac495d66a2ca76439264d09b7d5",
            )
            .unwrap(),
        },
        supersedes_run_id: None,
    }
}

fn bound_run_for(agent: &str, run: &str) -> BoundAgentRunRequest {
    let mut request = bound_run(run);
    request.agent_id = agent.to_owned();
    request.context.agent_id = agent.to_owned();
    request.run_config.agent_id = agent.to_owned();
    request.connection.agent_id = agent.to_owned();
    request.connection.binding_digest = Sha256Digest::new(match agent {
        "agent-a" => "sha256:fee954809eb23cd03870b20d408b54ffcb4112d25afb76131bb3fd2ffb29699a",
        "agent-b" => "sha256:bc052b9641fa77a028e467e8441a64ffcd7d2314ccb99509b31b4f29492216a1",
        _ => panic!("test helper supports only the two independent agents"),
    })
    .unwrap();
    request.idempotency_key = format!("task-1:{agent}:{run}");
    request
}

fn dispatch_plan() -> DeliberationProposalDispatchPlan {
    DeliberationProposalDispatchPlan::new(
        DeliberationDispatchBinding::new(
            bound_run_for("agent-a", "run-a"),
            dispatch_assignment("agent-a", "run-a", "family-a"),
        )
        .unwrap(),
        DeliberationDispatchBinding::new(
            bound_run_for("agent-b", "run-b"),
            dispatch_assignment("agent-b", "run-b", "family-b"),
        )
        .unwrap(),
    )
    .unwrap()
}

fn dispatch_assignment(agent: &str, run: &str, family: &str) -> DeliberationRunAssignment {
    DeliberationRunAssignment::new(
        RunId::new(run).unwrap(),
        agent,
        local_agent_terminal_domain::AgentFamilyKey::new(family).unwrap(),
        local_agent_terminal_domain::ActorId::new(agent).unwrap(),
    )
    .unwrap()
}

fn fingerprint(value: char) -> WorkspaceFingerprint {
    WorkspaceFingerprint::new(
        GitObjectId::new("0123456789012345678901234567890123456789").unwrap(),
        format!("sha256:{}", value.to_string().repeat(64)),
        format!(
            "sha256:{}",
            if value == 'f' { 'e' } else { 'f' }.to_string().repeat(64)
        ),
    )
    .unwrap()
}

fn digest(character: char) -> Sha256Digest {
    Sha256Digest::new(format!("sha256:{}", character.to_string().repeat(64))).unwrap()
}
