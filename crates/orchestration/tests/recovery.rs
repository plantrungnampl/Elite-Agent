use local_agent_terminal_application::{
    recover_deliberation, DeliberationAgentRunReconciliation, DeliberationAgentRunRecovery,
    DeliberationDurableBoundary, DeliberationRecoveryCheckpoint, DeliberationRecoveryInput,
    DeliberationRecoveryStore, DeliberationRunAssignment, PortError, Retryability,
    SafeErrorClassification,
};
use local_agent_terminal_domain::{
    ActorId, AgentFamilyKey, AgentRunLimits, AgentRunSnapshot, AgentRunStatus, ArtifactId,
    BoundAgentConnection, BoundAgentRunRequest, BoundEffectiveContext, BoundGenerationParameters,
    BoundRunConfig, Condition, FencingToken, OperationState, Phase, RunId, Sequence, Sha256Digest,
    TaskId, Timestamp, TrustTier, WorkflowState, WorkspaceVersion,
};
use local_agent_terminal_orchestration::{
    plan_deliberation_recovery, plan_dispatch_recovery, DeliberationRecoveryAction,
    DeliberationRecoveryCoordinator, DispatchRecovery, PersistedDispatch, RecoveryPlanningError,
};

#[test]
fn fault_injected_reopen_resumes_only_missing_durable_boundaries() {
    let required = required_boundaries();

    for fault_index in 0..required.len() {
        let store = FaultInjectedRecoveryStore::new(fault_index);
        let agent_runs = store.agent_run_recovery();
        let coordinator = DeliberationRecoveryCoordinator::new(&store, &agent_runs);
        assert!(coordinator.resume(&TaskId::new("task-1").unwrap()).is_err());

        let reopened_store = store.reopen();
        let reopened_agent_runs = reopened_store.agent_run_recovery();
        let reopened = DeliberationRecoveryCoordinator::new(&reopened_store, &reopened_agent_runs)
            .resume(&TaskId::new("task-1").unwrap())
            .unwrap();

        assert_eq!(
            reopened,
            required[fault_index + 1..].to_vec(),
            "fault boundary {fault_index} was replayed after durable completion"
        );
        let durable = reopened_store.durable.lock().unwrap();
        assert_eq!(durable.events, vec![Phase::ContextBuild]);
        assert_eq!(
            durable.artifacts,
            vec![local_agent_terminal_domain::ArtifactId::new("context-package").unwrap()]
        );
        assert_eq!(durable.dispatch_binding_sets, 1);
        assert_eq!(durable.agent_runs.len(), 1);
        assert_eq!(durable.agent_runs[0].status, AgentRunStatus::Created);
        assert!(durable.agent_runs_reconciled);
        assert_eq!(durable.runtime_recovery_retries, 1);
        assert!(durable.proposals_visible);
        assert!(durable.claim_set_persisted);
        assert!(durable.decision_draft_persisted);
        assert!(durable.plan_approval_persisted);
        assert!(durable.attempts.iter().all(|count| *count == 1));
    }
}

#[test]
fn recovery_resumes_only_missing_idempotent_dispatch_and_requires_new_retry_id() {
    assert_eq!(
        plan_dispatch_recovery(&PersistedDispatch {
            phase: Phase::ParallelAnalysis,
            run_id: RunId::new("run-a").unwrap(),
            status: AgentRunStatus::Created,
            idempotent: true,
            replacement_run_id: None,
        })
        .unwrap(),
        DispatchRecovery::ResumePersisted {
            run_id: RunId::new("run-a").unwrap()
        }
    );

    assert_eq!(
        plan_dispatch_recovery(&PersistedDispatch {
            phase: Phase::ParallelAnalysis,
            run_id: RunId::new("run-a").unwrap(),
            status: AgentRunStatus::Created,
            idempotent: false,
            replacement_run_id: None,
        })
        .unwrap(),
        DispatchRecovery::AwaitExplicitResolution
    );

    assert!(plan_dispatch_recovery(&PersistedDispatch {
        phase: Phase::ParallelAnalysis,
        run_id: RunId::new("run-a").unwrap(),
        status: AgentRunStatus::Interrupted,
        idempotent: false,
        replacement_run_id: Some(RunId::new("run-a").unwrap()),
    })
    .is_err());

    assert_eq!(
        plan_dispatch_recovery(&PersistedDispatch {
            phase: Phase::ParallelAnalysis,
            run_id: RunId::new("run-a").unwrap(),
            status: AgentRunStatus::Interrupted,
            idempotent: false,
            replacement_run_id: Some(RunId::new("run-b").unwrap()),
        })
        .unwrap(),
        DispatchRecovery::StartReplacement {
            previous_run_id: RunId::new("run-a").unwrap(),
            new_run_id: RunId::new("run-b").unwrap(),
        }
    );
}

#[test]
fn in_flight_or_indeterminate_dispatch_is_never_repeated() {
    for status in [AgentRunStatus::Accepted, AgentRunStatus::Running] {
        assert_eq!(
            plan_dispatch_recovery(&PersistedDispatch {
                phase: Phase::CrossReview,
                run_id: RunId::new("run-a").unwrap(),
                status,
                idempotent: true,
                replacement_run_id: None,
            })
            .unwrap(),
            DispatchRecovery::WaitForTerminal
        );
    }
    assert_eq!(
        plan_dispatch_recovery(&PersistedDispatch {
            phase: Phase::CrossReview,
            run_id: RunId::new("run-a").unwrap(),
            status: AgentRunStatus::Indeterminate,
            idempotent: true,
            replacement_run_id: None,
        })
        .unwrap(),
        DispatchRecovery::AwaitExplicitResolution
    );
}

#[test]
fn dispatch_recovery_rejects_phases_without_preapproval_provider_runs() {
    assert_eq!(
        plan_dispatch_recovery(&PersistedDispatch {
            phase: Phase::AwaitingPlanApproval,
            run_id: RunId::new("run-a").unwrap(),
            status: AgentRunStatus::Created,
            idempotent: true,
            replacement_run_id: None,
        }),
        Err(RecoveryPlanningError::UnexpectedPhase)
    );
}

#[test]
fn phase_recovery_chooses_only_the_next_missing_idempotent_boundary() {
    let cases = [
        (Phase::Intake, DeliberationRecoveryAction::ValidateIntake),
        (
            Phase::ContextBuild,
            DeliberationRecoveryAction::BuildInitialContext,
        ),
        (
            Phase::ParallelAnalysis,
            DeliberationRecoveryAction::AwaitIndependentProposals,
        ),
    ];

    for (phase, expected) in cases {
        let snapshot = recover_deliberation(DeliberationRecoveryInput {
            task_id: TaskId::new("task-1").unwrap(),
            task_version: 0,
            task_state: state(phase),
            run_assignments: vec![assignment()],
            facts: Vec::new(),
        })
        .unwrap();

        assert_eq!(plan_deliberation_recovery(&snapshot), expected);
    }
}

fn assignment() -> DeliberationRunAssignment {
    DeliberationRunAssignment::new(
        RunId::new("run-a").unwrap(),
        "agent-a",
        AgentFamilyKey::new("family-a").unwrap(),
        ActorId::new("agent-a").unwrap(),
    )
    .unwrap()
}

fn bound_run() -> BoundAgentRunRequest {
    let task_id = TaskId::new("task-1").unwrap();
    let empty_digest =
        digest("sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a");
    let executable_digest =
        digest("sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");
    let context_digest =
        digest("sha256:7ce2a62fec3ddf55f1cede952bdcd4170bb0b01fa53da3ded734e531337d2b58");
    let policy_digest =
        digest("sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd");
    BoundAgentRunRequest {
        run_id: RunId::new("run-a").unwrap(),
        task_id: task_id.clone(),
        agent_id: "agent-a".to_owned(),
        role: "reviewer".to_owned(),
        phase: "analysis".to_owned(),
        idempotency_key: "task-1:agent-a:run-a".to_owned(),
        context: BoundEffectiveContext {
            context_package_id: "context-1".to_owned(),
            task_id: task_id.clone(),
            agent_id: "agent-a".to_owned(),
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
            run_config_artifact_id: ArtifactId::new("artifact-run-config-run-a").unwrap(),
            task_id,
            agent_id: "agent-a".to_owned(),
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
            agent_id: "agent-a".to_owned(),
            trust_tier: TrustTier::CoreAdapter,
            manifest_digest: empty_digest,
            executable_digest: Some(executable_digest),
            contract_version: "1.0".to_owned(),
            adapter_version: "adapter-1".to_owned(),
            binding_digest: digest(
                "sha256:fee954809eb23cd03870b20d408b54ffcb4112d25afb76131bb3fd2ffb29699a",
            ),
        },
        supersedes_run_id: None,
    }
}

fn digest(value: &str) -> Sha256Digest {
    Sha256Digest::new(value).unwrap()
}

fn state(phase: Phase) -> WorkflowState {
    WorkflowState::new(
        phase,
        Condition::Active,
        OperationState::None,
        Sequence::new(0),
        WorkspaceVersion::new(0),
        FencingToken::new(1).unwrap(),
    )
    .unwrap()
}

fn required_boundaries() -> Vec<DeliberationDurableBoundary> {
    vec![
        DeliberationDurableBoundary::Event,
        DeliberationDurableBoundary::Artifact,
        DeliberationDurableBoundary::DispatchBindings,
        DeliberationDurableBoundary::AgentRunsReconciled,
        DeliberationDurableBoundary::ProposalVisibility,
        DeliberationDurableBoundary::ClaimSet,
        DeliberationDurableBoundary::DecisionDraft,
        DeliberationDurableBoundary::PlanApproval,
    ]
}

struct FaultInjectedRecoveryStore {
    fault: std::sync::Arc<std::sync::Mutex<Option<usize>>>,
    durable: std::sync::Arc<std::sync::Mutex<DurableRecoveryData>>,
}

struct FaultInjectedAgentRunRecovery {
    durable: std::sync::Arc<std::sync::Mutex<DurableRecoveryData>>,
}

#[derive(Default)]
struct DurableRecoveryData {
    events: Vec<Phase>,
    artifacts: Vec<local_agent_terminal_domain::ArtifactId>,
    dispatch_binding_sets: usize,
    agent_runs: Vec<AgentRunSnapshot>,
    agent_runs_reconciled: bool,
    runtime_recovery_retries: usize,
    proposals_visible: bool,
    claim_set_persisted: bool,
    decision_draft_persisted: bool,
    plan_approval_persisted: bool,
    attempts: Vec<usize>,
}

impl FaultInjectedRecoveryStore {
    fn new(fault_index: usize) -> Self {
        Self {
            fault: std::sync::Arc::new(std::sync::Mutex::new(Some(fault_index))),
            durable: std::sync::Arc::new(std::sync::Mutex::new(DurableRecoveryData {
                attempts: vec![0; required_boundaries().len()],
                ..DurableRecoveryData::default()
            })),
        }
    }

    fn reopen(&self) -> Self {
        Self {
            fault: self.fault.clone(),
            durable: self.durable.clone(),
        }
    }

    fn agent_run_recovery(&self) -> FaultInjectedAgentRunRecovery {
        FaultInjectedAgentRunRecovery {
            durable: self.durable.clone(),
        }
    }

    fn persist(
        &self,
        index: usize,
        write: impl FnOnce(&mut DurableRecoveryData),
    ) -> Result<(), PortError> {
        let mut durable = self.durable.lock().unwrap();
        durable.attempts[index] += 1;
        write(&mut durable);
        drop(durable);
        let mut fault = self.fault.lock().unwrap();
        if *fault == Some(index) {
            *fault = None;
            return Err(PortError::failure(
                SafeErrorClassification::Internal,
                Retryability::Retryable,
            ));
        }
        Ok(())
    }
}

impl DeliberationRecoveryStore for FaultInjectedRecoveryStore {
    fn load_checkpoint(
        &self,
        task_id: &TaskId,
    ) -> Result<DeliberationRecoveryCheckpoint, PortError> {
        let durable = self.durable.lock().unwrap();
        Ok(DeliberationRecoveryCheckpoint {
            task_id: task_id.clone(),
            event_persisted: !durable.events.is_empty(),
            artifact_persisted: !durable.artifacts.is_empty(),
            dispatch_bindings_persisted: durable.dispatch_binding_sets == 1,
            agent_runs_reconciled: durable.agent_runs_reconciled,
            proposal_visibility_persisted: durable.proposals_visible,
            claim_set_persisted: durable.claim_set_persisted,
            decision_draft_persisted: durable.decision_draft_persisted,
            plan_approval_persisted: durable.plan_approval_persisted,
        })
    }

    fn persist_recovered_event(&self, _: &TaskId) -> Result<(), PortError> {
        self.persist(0, |durable| durable.events.push(Phase::ContextBuild))
    }

    fn persist_recovered_artifact(&self, _: &TaskId) -> Result<(), PortError> {
        self.persist(1, |durable| {
            durable
                .artifacts
                .push(local_agent_terminal_domain::ArtifactId::new("context-package").unwrap())
        })
    }

    fn persist_recovered_dispatch_bindings(&self, _: &TaskId) -> Result<(), PortError> {
        self.persist(2, |durable| durable.dispatch_binding_sets += 1)
    }

    fn persist_recovered_agent_run_reconciliation(
        &self,
        reconciliation: &DeliberationAgentRunReconciliation,
    ) -> Result<(), PortError> {
        reconciliation.validate()?;
        self.persist(3, |durable| durable.agent_runs_reconciled = true)
    }

    fn persist_recovered_proposal_visibility(&self, _: &TaskId) -> Result<(), PortError> {
        self.persist(4, |durable| durable.proposals_visible = true)
    }

    fn persist_recovered_claim_set(&self, _: &TaskId) -> Result<(), PortError> {
        self.persist(5, |durable| durable.claim_set_persisted = true)
    }

    fn persist_recovered_decision_draft(&self, _: &TaskId) -> Result<(), PortError> {
        self.persist(6, |durable| durable.decision_draft_persisted = true)
    }

    fn persist_recovered_plan_approval(&self, _: &TaskId) -> Result<(), PortError> {
        self.persist(7, |durable| durable.plan_approval_persisted = true)
    }
}

impl DeliberationAgentRunRecovery for FaultInjectedAgentRunRecovery {
    fn reconcile_or_retry(
        &self,
        task_id: &TaskId,
    ) -> Result<DeliberationAgentRunReconciliation, PortError> {
        let mut durable = self.durable.lock().unwrap();
        if durable.agent_runs.is_empty() {
            durable.runtime_recovery_retries += 1;
            durable
                .agent_runs
                .push(AgentRunSnapshot::created(bound_run()).unwrap());
        }
        DeliberationAgentRunReconciliation::new(task_id.clone(), durable.agent_runs.clone())
    }
}
