use std::collections::BTreeSet;

use local_agent_terminal_application::{
    recover_deliberation, AgentRuntime, AppendOperation, AppendResult, ApprovalId,
    CanonicalDeliberationFact, Clock, CompareAndExpirePlanApproval,
    CompareAndInvalidatePlanApproval, CompareAndResolvePlanApproval, DeliberationArtifactRef,
    DeliberationBoundaryRecord, DeliberationBoundaryStore, DeliberationCommandContext,
    DeliberationDispatchBinding, DeliberationDispatchStore, DeliberationPersistenceCommand,
    DeliberationPhaseDispatchAuthority, DeliberationPhaseDispatchSet,
    DeliberationProposalDispatchPlan, DeliberationRecord, DeliberationRecoveryInput,
    DeliberationRepositoryAuthority, DeliberationRunAssignment, DeliberationSnapshot,
    DeliberationStore, DeliberationSynthesisCommand, DeliberationSynthesisStore,
    DeliberationToolAccess, DeliberationToolCatalog, DeliberationToolSchema, EventStore,
    PlanApprovalAction, PlanApprovalAuthorityBinding, PlanApprovalAuthorityProvider,
    PlanApprovalBindingInput, PlanApprovalCurrentState, PlanApprovalPathScopeV1, PlanApprovalState,
    PlanApprovalStore, PortError, PreparePlanApprovalRequestInput, ResolvePlanApproval,
    ResolvePlanApprovalInput, SafeErrorClassification, StoredPlanApproval,
    StoredPlanApprovalRehydration,
};
use local_agent_terminal_domain::{
    ActorId, AgentCancellationReceipt, AgentDescriptor, AgentFamilyKey, AgentRunLimits,
    AgentRunReceipt, ArtifactId, BoundAgentConnection, BoundAgentRunRequest, BoundEffectiveContext,
    BoundGenerationParameters, BoundRunConfig, CancelAgentRun, ClaimVerification, Condition,
    DecisionApproach, DecisionPackage, DeliberationLimits, Dissent, EvidenceCitation,
    EvidenceFreshness, FencingToken, FinalObjection, FinalObjectionSet, GitObjectId,
    GuardEvaluations, GuardName, IndependentProposal, IndependentQuorum, MaterialClaim,
    ObjectionSeverity, OperationState, Phase, ProjectId, RejectedApproach, ReviewEdge, ReviewPlan,
    RunId, Sequence, Sha256Digest, SourceIdentity, TaskId, Timestamp, TrustTier,
    VerificationMethod, WorkflowEvent, WorkflowState, WorkspaceFingerprint, WorkspaceVersion,
};
use local_agent_terminal_orchestration::{
    normative_preapproval_transitions, select_independent_agents, AgentEligibility,
    DeliberationCoordinator, PhaseAdvanceRequest, PreApprovalCoordinator, PrePlanDispatch,
    PrePlanOperation, SelectionDenial,
};

#[test]
fn normative_preapproval_sequence_never_skips_quorum_verification_or_approval() {
    let transitions = normative_preapproval_transitions();
    let phases = transitions
        .iter()
        .map(|transition| transition.from)
        .chain(transitions.last().map(|transition| transition.to))
        .collect::<Vec<_>>();

    assert_eq!(
        phases,
        vec![
            Phase::Intake,
            Phase::ContextBuild,
            Phase::ParallelAnalysis,
            Phase::CrossReview,
            Phase::PrePlanVerification,
            Phase::Synthesis,
            Phase::FinalObjection,
            Phase::AwaitingPlanApproval,
        ]
    );

    let mut state = workflow_state(Phase::Intake, 0);
    for transition in transitions {
        let event = WorkflowEvent::new(transition.event).unwrap();
        let mut guards = GuardEvaluations::new();
        if let Some(guard) = transition.guard {
            guards.insert(GuardName::new(guard).unwrap(), true);
        }
        state = *local_agent_terminal_domain::reduce(&state, &event, &guards)
            .unwrap()
            .state();
        assert_eq!(state.phase(), transition.to);
    }
}

#[test]
fn selection_requires_two_available_capable_distinct_families() {
    let same_family = family("family-a");
    let candidates = vec![
        eligible("agent-b", "run-b", same_family.clone(), true),
        eligible("agent-a", "run-a", same_family, true),
        eligible("agent-c", "run-c", family("family-c"), false),
    ];

    assert_eq!(
        select_independent_agents(&candidates, "propose"),
        Err(SelectionDenial::DependencyUnavailable)
    );

    let mut candidates = candidates;
    candidates[2].available = true;
    let selected = select_independent_agents(&candidates, "propose").unwrap();
    assert_eq!(
        selected
            .iter()
            .map(|assignment| assignment.agent_id())
            .collect::<Vec<_>>(),
        vec!["agent-a", "agent-c"]
    );
    assert_eq!(
        selected
            .iter()
            .map(|assignment| assignment.family())
            .collect::<BTreeSet<_>>()
            .len(),
        2
    );
}

#[test]
fn coordinator_checks_boundary_commits_effect_and_accepts_run_before_external_dispatch() {
    let log = std::sync::Mutex::new(Vec::new());
    let authority = RecordingAuthority { log: &log };
    let boundaries = RecordingBoundaryStore { log: &log };
    let events = RecordingEventStore { log: &log };
    let tools = RecordingToolCatalog {
        log: &log,
        schemas: Vec::new(),
    };
    let dispatches = RecordingDispatchStore { log: &log };
    let runtime = RecordingRuntime { log: &log };
    let coordinator = PreApprovalCoordinator::new(
        &authority,
        &boundaries,
        &events,
        &tools,
        &dispatches,
        &runtime,
    );
    let task_id = TaskId::new("task-1").unwrap();

    let result = coordinator
        .coordinate(PrePlanOperation::AdvanceAndDispatch {
            request: phase_request(task_id, workflow_state(Phase::ContextBuild, 1)),
            transition: normative_preapproval_transitions()[1],
            dispatch_plan: Box::new(proposal_dispatch_plan()),
        })
        .unwrap();

    assert_eq!(result.next_state.phase(), Phase::ParallelAnalysis);
    assert_eq!(result.receipts[0].run_id, RunId::new("run-a").unwrap());
    assert_eq!(result.receipts[1].run_id, RunId::new("run-b").unwrap());
    assert_eq!(
        *log.lock().unwrap(),
        vec![
            "repository-scan",
            "boundary-compare-and-persist",
            "tool-catalog",
            "phase",
            "binding-set",
            "runtime",
            "runtime",
        ]
    );
}

#[test]
fn proposal_dispatch_plan_requires_exact_two_heterogeneous_authorities() {
    let first = DeliberationDispatchBinding::new(
        bound_run_for("agent-a", "run-a"),
        dispatch_assignment("agent-a", "run-a", "family-a"),
    )
    .unwrap();
    let duplicate_agent = DeliberationDispatchBinding::new(
        bound_run_for("agent-a", "run-b"),
        dispatch_assignment("agent-a", "run-b", "family-b"),
    )
    .unwrap();
    let duplicate_family = DeliberationDispatchBinding::new(
        bound_run_for("agent-b", "run-b"),
        dispatch_assignment("agent-b", "run-b", "family-a"),
    )
    .unwrap();

    assert!(DeliberationProposalDispatchPlan::new(first.clone(), duplicate_agent).is_err());
    assert!(DeliberationProposalDispatchPlan::new(first, duplicate_family).is_err());
}

#[test]
fn later_phase_dispatch_accepts_one_bounded_authority_and_rejects_over_budget_or_mismatch() {
    let authorized = DeliberationDispatchBinding::new(
        bound_run_for("agent-a", "run-a"),
        dispatch_assignment("agent-a", "run-a", "family-a"),
    )
    .unwrap();
    let limits = DeliberationLimits::new(1, 2, 8, 2).unwrap();
    let authority = DeliberationPhaseDispatchAuthority::new(
        TaskId::new("task-1").unwrap(),
        Phase::CrossReview,
        vec![
            dispatch_assignment("agent-a", "run-a", "family-a"),
            dispatch_assignment("agent-b", "run-b", "family-a"),
        ],
        limits,
    )
    .unwrap();
    let dispatch_set =
        DeliberationPhaseDispatchSet::new(vec![authorized.clone()], authority.clone()).unwrap();

    assert_eq!(dispatch_set.bindings().len(), 1);
    assert!(DeliberationPhaseDispatchSet::new(
        vec![
            authorized,
            DeliberationDispatchBinding::new(
                bound_run_for("agent-b", "run-b"),
                dispatch_assignment("agent-b", "run-b", "family-a"),
            )
            .unwrap(),
        ],
        authority,
    )
    .is_err());
    let unauthorized = DeliberationDispatchBinding::new(
        bound_run_for("agent-a", "run-a"),
        dispatch_assignment("agent-a", "run-a", "family-a"),
    )
    .unwrap();
    let other_authority = DeliberationPhaseDispatchAuthority::new(
        TaskId::new("task-1").unwrap(),
        Phase::CrossReview,
        vec![dispatch_assignment("agent-b", "run-b", "family-b")],
        limits,
    )
    .unwrap();
    assert!(DeliberationPhaseDispatchSet::new(vec![unauthorized], other_authority).is_err());
}

#[test]
fn one_coordinator_path_guards_every_dispatching_preplan_phase() {
    for phase in [
        Phase::ParallelAnalysis,
        Phase::CrossReview,
        Phase::PrePlanVerification,
        Phase::Synthesis,
        Phase::FinalObjection,
    ] {
        let log = std::sync::Mutex::new(Vec::new());
        let authority = RecordingAuthority { log: &log };
        let boundaries = RecordingBoundaryStore { log: &log };
        let events = RecordingEventStore { log: &log };
        let tools = RecordingToolCatalog {
            log: &log,
            schemas: Vec::new(),
        };
        let dispatches = RecordingDispatchStore { log: &log };
        let runtime = RecordingRuntime { log: &log };

        let dispatch = if phase == Phase::ParallelAnalysis {
            PrePlanDispatch::Proposal(Box::new(proposal_dispatch_plan()))
        } else {
            PrePlanDispatch::Phase(
                DeliberationPhaseDispatchSet::new(
                    vec![DeliberationDispatchBinding::new(
                        bound_run_for("agent-a", "run-a"),
                        dispatch_assignment("agent-a", "run-a", "family-a"),
                    )
                    .unwrap()],
                    DeliberationPhaseDispatchAuthority::new(
                        TaskId::new("task-1").unwrap(),
                        phase,
                        vec![dispatch_assignment("agent-a", "run-a", "family-a")],
                        DeliberationLimits::new(1, 2, 8, 2).unwrap(),
                    )
                    .unwrap(),
                )
                .unwrap(),
            )
        };
        let expected_runs = dispatch.bindings().len();
        let result = PreApprovalCoordinator::new(
            &authority,
            &boundaries,
            &events,
            &tools,
            &dispatches,
            &runtime,
        )
        .coordinate(PrePlanOperation::DispatchCurrent {
            task_id: TaskId::new("task-1").unwrap(),
            expected_state: workflow_state(phase, 4),
            dispatch,
        })
        .unwrap();

        assert_eq!(result.receipts.len(), expected_runs);
        let mut expected_log = vec![
            "repository-scan",
            "boundary-compare-and-persist",
            "tool-catalog",
            "binding-set",
        ];
        expected_log.extend(std::iter::repeat_n("runtime", expected_runs));
        assert_eq!(*log.lock().unwrap(), expected_log);
    }
}

#[test]
fn coordinator_rejects_write_capability_and_nonzero_tool_budget_before_durable_work() {
    let log = std::sync::Mutex::new(Vec::new());
    let authority = RecordingAuthority { log: &log };
    let boundaries = RecordingBoundaryStore { log: &log };
    let events = RecordingEventStore { log: &log };
    let dispatches = RecordingDispatchStore { log: &log };
    let runtime = RecordingRuntime { log: &log };
    let write_tools = RecordingToolCatalog {
        log: &log,
        schemas: vec![DeliberationToolSchema::new(
            "repository.delete.read",
            DeliberationToolAccess::Write,
        )
        .unwrap()],
    };
    let coordinator = PreApprovalCoordinator::new(
        &authority,
        &boundaries,
        &events,
        &write_tools,
        &dispatches,
        &runtime,
    );

    let error = coordinator
        .coordinate(PrePlanOperation::AdvanceAndDispatch {
            request: phase_request(
                TaskId::new("task-1").unwrap(),
                workflow_state(Phase::ContextBuild, 1),
            ),
            transition: normative_preapproval_transitions()[1],
            dispatch_plan: Box::new(proposal_dispatch_plan()),
        })
        .unwrap_err();
    assert_eq!(
        error.safe_classification(),
        SafeErrorClassification::InvalidInput
    );
    assert_eq!(
        *log.lock().unwrap(),
        vec![
            "repository-scan",
            "boundary-compare-and-persist",
            "tool-catalog",
        ]
    );

    log.lock().unwrap().clear();
    let read_tools = RecordingToolCatalog {
        log: &log,
        schemas: Vec::new(),
    };
    let coordinator = PreApprovalCoordinator::new(
        &authority,
        &boundaries,
        &events,
        &read_tools,
        &dispatches,
        &runtime,
    );
    let mut request = bound_run_for("agent-a", "run-a");
    request.run_config.limits.max_tool_requests = 1;
    let nonzero_tool_plan = DeliberationProposalDispatchPlan::new(
        DeliberationDispatchBinding::new(
            request,
            dispatch_assignment("agent-a", "run-a", "family-a"),
        )
        .unwrap(),
        DeliberationDispatchBinding::new(
            bound_run_for("agent-b", "run-b"),
            dispatch_assignment("agent-b", "run-b", "family-b"),
        )
        .unwrap(),
    )
    .unwrap();

    assert_eq!(
        coordinator
            .coordinate(PrePlanOperation::AdvanceAndDispatch {
                request: phase_request(
                    TaskId::new("task-1").unwrap(),
                    workflow_state(Phase::ContextBuild, 1),
                ),
                transition: normative_preapproval_transitions()[1],
                dispatch_plan: Box::new(nonzero_tool_plan),
            })
            .unwrap_err()
            .safe_classification(),
        SafeErrorClassification::InvalidInput
    );
    assert_eq!(
        *log.lock().unwrap(),
        vec![
            "repository-scan",
            "boundary-compare-and-persist",
            "tool-catalog",
        ]
    );
}

#[test]
fn zero_tool_dispatch_rejects_even_read_only_schema_exposure() {
    let log = std::sync::Mutex::new(Vec::new());
    let authority = RecordingAuthority { log: &log };
    let boundaries = RecordingBoundaryStore { log: &log };
    let events = RecordingEventStore { log: &log };
    let tools = RecordingToolCatalog {
        log: &log,
        schemas: vec![DeliberationToolSchema::new(
            "repository.inspect",
            DeliberationToolAccess::ReadOnly,
        )
        .unwrap()],
    };
    let dispatches = RecordingDispatchStore { log: &log };
    let runtime = RecordingRuntime { log: &log };

    let error = PreApprovalCoordinator::new(
        &authority,
        &boundaries,
        &events,
        &tools,
        &dispatches,
        &runtime,
    )
    .coordinate(PrePlanOperation::AdvanceAndDispatch {
        request: phase_request(
            TaskId::new("task-1").unwrap(),
            workflow_state(Phase::ContextBuild, 1),
        ),
        transition: normative_preapproval_transitions()[1],
        dispatch_plan: Box::new(proposal_dispatch_plan()),
    })
    .unwrap_err();

    assert_eq!(
        error.safe_classification(),
        SafeErrorClassification::InvalidInput
    );
    assert!(!log.lock().unwrap().contains(&"phase"));
    assert!(!log.lock().unwrap().contains(&"binding-set"));
    assert!(!log.lock().unwrap().contains(&"runtime"));
}

#[test]
fn repository_checked_quorum_publication_reveals_only_after_two_private_proposals() {
    let log = std::sync::Mutex::new(Vec::new());
    let authority = RecordingAuthority { log: &log };
    let boundaries = RecordingBoundaryStore { log: &log };
    let store = WorkflowStore::new(unpublished_snapshot());
    assert!(store
        .snapshot
        .lock()
        .unwrap()
        .private_proposals()
        .iter()
        .all(|entry| !entry.proposal().is_revealed()));
    assert!(IndependentQuorum::new(vec![proposal(1)]).is_err());

    DeliberationCoordinator::new(&authority, &boundaries, &store)
        .publish_proposals(
            deliberation_context(
                Phase::ParallelAnalysis,
                2,
                deliberation_artifact("proposal-bundle", '8'),
                "event-quorum",
            ),
            review_plan(1),
            deliberation_artifact("review-plan", '9'),
        )
        .unwrap();

    let writes = store.writes.lock().unwrap();
    assert!(matches!(
        writes[0].record(),
        DeliberationRecord::QuorumPublication { proposals, .. }
            if proposals.len() == 2 && proposals.iter().all(IndependentProposal::is_revealed)
    ));
    for skipped in [
        "review.complete",
        "claims.checked",
        "objection.round.closed",
    ] {
        assert!(local_agent_terminal_domain::reduce(
            &workflow_state(Phase::ParallelAnalysis, 2),
            &WorkflowEvent::new(skipped).unwrap(),
            &GuardEvaluations::new(),
        )
        .is_err());
    }
}

#[test]
fn repository_checked_claim_and_verification_commands_persist_each_phase_boundary() {
    let log = std::sync::Mutex::new(Vec::new());
    let authority = RecordingAuthority { log: &log };
    let boundaries = RecordingBoundaryStore { log: &log };
    let published_facts = objection_facts(ObjectionSeverity::Low)
        .into_iter()
        .take(3)
        .collect::<Vec<_>>();
    let cross_review = WorkflowStore::new(recover_snapshot(
        Phase::CrossReview,
        3,
        published_facts.clone(),
    ));

    DeliberationCoordinator::new(&authority, &boundaries, &cross_review)
        .record_claim_set(
            deliberation_context(
                Phase::CrossReview,
                3,
                deliberation_artifact("claim-set", '3'),
                "event-claims",
            ),
            vec![material_claim(false)],
        )
        .unwrap();
    let claim_command = cross_review.writes.lock().unwrap()[0].clone();
    assert_eq!(
        claim_command.append().events[0].event_type.as_str(),
        "review.complete"
    );
    assert!(matches!(
        claim_command.append().projection_changes.as_slice(),
        [local_agent_terminal_application::ProjectionChange::TaskState { state, .. }]
            if state.phase() == Phase::PrePlanVerification
    ));

    let mut claim_facts = published_facts;
    claim_facts.push(
        CanonicalDeliberationFact::issue(
            task(),
            local_agent_terminal_domain::EventId::new("event-claims-recovered").unwrap(),
            4,
            ActorId::new("core").unwrap(),
            claim_command.record().clone(),
        )
        .unwrap(),
    );
    let verification =
        WorkflowStore::new(recover_snapshot(Phase::PrePlanVerification, 4, claim_facts));
    DeliberationCoordinator::new(&authority, &boundaries, &verification)
        .record_verification_set(
            deliberation_context(
                Phase::PrePlanVerification,
                4,
                deliberation_artifact("verification-set", '4'),
                "event-verification",
            ),
            vec![material_claim(true)],
        )
        .unwrap();

    let verification_command = verification.writes.lock().unwrap()[0].clone();
    assert_eq!(
        verification_command.append().events[0].event_type.as_str(),
        "claims.checked"
    );
    assert!(matches!(
        verification_command
            .append()
            .projection_changes
            .as_slice(),
        [local_agent_terminal_application::ProjectionChange::TaskState { state, .. }]
            if state.phase() == Phase::Synthesis
    ));
}

#[test]
fn severe_objection_reopens_one_bounded_round_and_recovery_preserves_history() {
    let log = std::sync::Mutex::new(Vec::new());
    let authority = RecordingAuthority { log: &log };
    let boundaries = RecordingBoundaryStore { log: &log };
    let facts = objection_facts(ObjectionSeverity::Severe);
    let store = WorkflowStore::new(recover_snapshot(Phase::FinalObjection, 7, facts.clone()));

    DeliberationCoordinator::new(&authority, &boundaries, &store)
        .accept_severe_objection(
            deliberation_context(
                Phase::FinalObjection,
                7,
                deliberation_artifact("review-plan-2", '7'),
                "event-severe-accepted",
            ),
            review_plan(2),
        )
        .unwrap();

    let accepted_record = store.writes.lock().unwrap()[0].record().clone();
    assert!(matches!(
        &accepted_record,
        DeliberationRecord::ObjectionSevereAccepted {
            objections,
            review_plan,
            ..
        } if objections.objections()[0].severity() == ObjectionSeverity::Severe
            && review_plan.edges().iter().all(|edge| edge.round() == 2)
    ));
    let mut recovered_facts = facts;
    recovered_facts.push(
        CanonicalDeliberationFact::issue(
            task(),
            local_agent_terminal_domain::EventId::new("event-severe-recovered").unwrap(),
            8,
            ActorId::new("core").unwrap(),
            accepted_record,
        )
        .unwrap(),
    );
    let recovered = recover_snapshot(Phase::CrossReview, 8, recovered_facts);
    assert_eq!(recovered.decision_drafts().len(), 1);
    assert_eq!(recovered.objection_sets().len(), 1);
    assert_eq!(recovered.severe_objection_acceptances().len(), 1);

    let reopened_store = WorkflowStore::new(recovered);
    assert!(
        DeliberationCoordinator::new(&authority, &boundaries, &reopened_store)
            .close_objection_round(
                deliberation_context(
                    Phase::CrossReview,
                    8,
                    deliberation_artifact("approval-request", 'a'),
                    "event-close-too-early",
                ),
                plan_approval_request(),
            )
            .is_err()
    );
    assert!(reopened_store.writes.lock().unwrap().is_empty());
}

#[test]
fn approval_close_reloads_canonical_authority_before_persisting_transition() {
    let log = std::sync::Mutex::new(Vec::new());
    let authority = RecordingAuthority { log: &log };
    let boundaries = RecordingBoundaryStore { log: &log };
    let store = WorkflowStore::new(recover_snapshot(
        Phase::FinalObjection,
        7,
        objection_facts(ObjectionSeverity::Low),
    ));
    let approvals = CountingPlanApprovalAuthority {
        calls: std::sync::Mutex::new(0),
        binding: PlanApprovalAuthorityBinding::issue(plan_approval_binding()).unwrap(),
    };

    DeliberationCoordinator::with_plan_approval_authority(
        &authority,
        &boundaries,
        &store,
        &approvals,
    )
    .close_objection_round(
        deliberation_context(
            Phase::FinalObjection,
            7,
            deliberation_artifact("approval-request", 'a'),
            "event-objection-closed",
        ),
        plan_approval_request(),
    )
    .unwrap();

    assert_eq!(*approvals.calls.lock().unwrap(), 1);
    let writes = store.writes.lock().unwrap();
    assert!(matches!(
        writes[0].record(),
        DeliberationRecord::ObjectionRoundClosed { .. }
    ));
    assert!(matches!(
        writes[0].append().projection_changes.as_slice(),
        [local_agent_terminal_application::ProjectionChange::TaskState { state, .. }]
            if state.phase() == Phase::AwaitingPlanApproval
    ));
}

#[test]
fn canonical_resolution_reloads_and_appends_exact_plan_approved_event() {
    let log = std::sync::Mutex::new(Vec::new());
    let authority = RecordingAuthority { log: &log };
    let boundaries = RecordingBoundaryStore { log: &log };
    let deliberation = WorkflowStore::new(recover_snapshot(
        Phase::FinalObjection,
        7,
        objection_facts(ObjectionSeverity::Low),
    ));
    let approvals = CountingPlanApprovalAuthority {
        calls: std::sync::Mutex::new(0),
        binding: PlanApprovalAuthorityBinding::issue(plan_approval_binding()).unwrap(),
    };
    DeliberationCoordinator::with_plan_approval_authority(
        &authority,
        &boundaries,
        &deliberation,
        &approvals,
    )
    .close_objection_round(
        deliberation_context(
            Phase::FinalObjection,
            7,
            deliberation_artifact("approval-request", 'a'),
            "event-objection-closed-for-resolution",
        ),
        plan_approval_request(),
    )
    .unwrap();
    let new_approval = match deliberation.writes.lock().unwrap()[0].record() {
        DeliberationRecord::ObjectionRoundClosed { plan_approval, .. } => plan_approval.clone(),
        record => panic!("unexpected deliberation record: {record:?}"),
    };
    let stored = StoredPlanApproval::rehydrate(StoredPlanApprovalRehydration {
        approval_id: new_approval.approval_id().clone(),
        state: PlanApprovalState::Requested,
        canonical_bytes: new_approval.canonical_bytes().to_vec(),
        operation_digest: new_approval.operation_digest().clone(),
        request_artifact: new_approval.request_artifact().clone(),
        authority_binding_bytes: new_approval.authority_binding().canonical_bytes().to_vec(),
        authority_binding_digest: new_approval.authority_binding().content_digest().clone(),
        terminal: None,
    })
    .unwrap();
    let resolution_store = ResolutionStore {
        stored,
        current: PlanApprovalCurrentState {
            phase: Phase::AwaitingPlanApproval,
            task_state: approval_workflow_state(),
            binding: new_approval.binding().clone(),
        },
        reloads: std::sync::Mutex::new(0),
        current_reloads: std::sync::Mutex::new(0),
        commands: std::sync::Mutex::new(Vec::new()),
    };

    let resolution = ResolvePlanApproval::new(&resolution_store, &ApprovalClock)
        .execute(ResolvePlanApprovalInput {
            approval_id: new_approval.approval_id().clone(),
            displayed_digest: new_approval.operation_digest().clone(),
            expected_task_version: 8,
            actor_id: ActorId::new("actor-1").unwrap(),
            action: PlanApprovalAction::Approve,
        })
        .unwrap();

    assert_eq!(*resolution_store.reloads.lock().unwrap(), 1);
    assert_eq!(*resolution_store.current_reloads.lock().unwrap(), 1);
    assert_eq!(
        resolution.append.events[0].event_type.as_str(),
        "plan.approved"
    );
    assert!(matches!(
        resolution.append.projection_changes.as_slice(),
        [local_agent_terminal_application::ProjectionChange::TaskState { state, .. }]
            if state.phase() == Phase::Implementation
    ));
}

fn phase_request(task_id: TaskId, expected_state: WorkflowState) -> PhaseAdvanceRequest {
    let next_sequence = expected_state.sequence().get() + 1;
    PhaseAdvanceRequest {
        task_id,
        expected_state,
        event_id: local_agent_terminal_domain::EventId::new(format!("event-{}", next_sequence))
            .unwrap(),
        occurred_at: "2026-08-11T00:00:00Z".to_owned(),
        correlation_id: "task-1:orchestration".to_owned(),
        effect_artifacts: vec![DeliberationArtifactRef::new(
            ArtifactId::new(format!("phase-effect-{}", next_sequence)).unwrap(),
            digest("sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
            1,
        )
        .unwrap()],
    }
}

fn family(value: &str) -> AgentFamilyKey {
    AgentFamilyKey::new(value).unwrap()
}

fn eligible(agent: &str, run: &str, family: AgentFamilyKey, available: bool) -> AgentEligibility {
    AgentEligibility {
        assignment: DeliberationRunAssignment::new(
            RunId::new(run).unwrap(),
            agent,
            family,
            ActorId::new(agent).unwrap(),
        )
        .unwrap(),
        capabilities: ["propose".to_owned()].into_iter().collect(),
        available,
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

fn approval_workflow_state() -> WorkflowState {
    WorkflowState::new(
        Phase::AwaitingPlanApproval,
        Condition::Active,
        OperationState::None,
        Sequence::new(8),
        WorkspaceVersion::new(1),
        FencingToken::new(1).unwrap(),
    )
    .unwrap()
}

fn bound_run(run: &str) -> BoundAgentRunRequest {
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
            binding_digest: digest(
                "sha256:6e171d4e7a1d7b7db1c14807e8a2a5cc9093eac495d66a2ca76439264d09b7d5",
            ),
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
    request.connection.binding_digest = match agent {
        "agent-a" => {
            digest("sha256:fee954809eb23cd03870b20d408b54ffcb4112d25afb76131bb3fd2ffb29699a")
        }
        "agent-b" => {
            digest("sha256:bc052b9641fa77a028e467e8441a64ffcd7d2314ccb99509b31b4f29492216a1")
        }
        _ => panic!("test helper supports only the two independent agents"),
    };
    request.idempotency_key = format!("task-1:{agent}:{run}");
    request
}

fn proposal_dispatch_plan() -> DeliberationProposalDispatchPlan {
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

fn dispatch_assignment(agent: &str, run: &str, family_name: &str) -> DeliberationRunAssignment {
    DeliberationRunAssignment::new(
        RunId::new(run).unwrap(),
        agent,
        family(family_name),
        ActorId::new(agent).unwrap(),
    )
    .unwrap()
}

fn digest(value: &str) -> Sha256Digest {
    Sha256Digest::new(value).unwrap()
}

struct RecordingEventStore<'a> {
    log: &'a std::sync::Mutex<Vec<&'static str>>,
}

struct RecordingAuthority<'a> {
    log: &'a std::sync::Mutex<Vec<&'static str>>,
}

impl DeliberationRepositoryAuthority for RecordingAuthority<'_> {
    fn current_fingerprint(&self, _: &TaskId) -> Result<WorkspaceFingerprint, PortError> {
        self.log.lock().unwrap().push("repository-scan");
        Ok(fingerprint())
    }
}

struct RecordingBoundaryStore<'a> {
    log: &'a std::sync::Mutex<Vec<&'static str>>,
}

impl DeliberationBoundaryStore for RecordingBoundaryStore<'_> {
    fn compare_and_persist_boundary(
        &self,
        check: local_agent_terminal_application::DeliberationBoundaryCheck,
    ) -> Result<DeliberationBoundaryRecord, PortError> {
        let record = check.compare_with(fingerprint())?;
        self.log
            .lock()
            .unwrap()
            .push("boundary-compare-and-persist");
        Ok(record)
    }
}

struct RecordingToolCatalog<'a> {
    log: &'a std::sync::Mutex<Vec<&'static str>>,
    schemas: Vec<DeliberationToolSchema>,
}

impl DeliberationToolCatalog for RecordingToolCatalog<'_> {
    fn dispatch_schemas(&self, _: &TaskId) -> Result<Vec<DeliberationToolSchema>, PortError> {
        self.log.lock().unwrap().push("tool-catalog");
        Ok(self.schemas.clone())
    }
}

struct RecordingDispatchStore<'a> {
    log: &'a std::sync::Mutex<Vec<&'static str>>,
}

impl DeliberationDispatchStore for RecordingDispatchStore<'_> {
    fn compare_and_persist_proposal_binding_set(
        &self,
        plan: &DeliberationProposalDispatchPlan,
    ) -> Result<(), PortError> {
        plan.validate()?;
        self.log.lock().unwrap().push("binding-set");
        Ok(())
    }

    fn compare_and_persist_phase_binding_set(
        &self,
        dispatch_set: &DeliberationPhaseDispatchSet,
    ) -> Result<(), PortError> {
        dispatch_set.validate()?;
        self.log.lock().unwrap().push("binding-set");
        Ok(())
    }
}

impl EventStore for RecordingEventStore<'_> {
    fn append(&self, operation: AppendOperation) -> Result<AppendResult, PortError> {
        assert_eq!(operation.events.len(), 1);
        assert_eq!(operation.projection_changes.len(), 1);
        assert_eq!(
            operation.events[0].payload["effectArtifacts"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
        self.log.lock().unwrap().push("phase");
        Ok(AppendResult {
            new_version: Sequence::new(operation.expected_version.get() + 1),
        })
    }
}

struct RecordingRuntime<'a> {
    log: &'a std::sync::Mutex<Vec<&'static str>>,
}

impl AgentRuntime for RecordingRuntime<'_> {
    fn list_agents(&self) -> Result<Vec<AgentDescriptor>, PortError> {
        unreachable!()
    }

    fn start_run(&self, request: BoundAgentRunRequest) -> Result<AgentRunReceipt, PortError> {
        self.log.lock().unwrap().push("runtime");
        Ok(AgentRunReceipt {
            run_id: request.run_id,
            accepted_at: Timestamp::from_unix_seconds(2),
        })
    }

    fn cancel(&self, _: CancelAgentRun) -> Result<AgentCancellationReceipt, PortError> {
        unreachable!()
    }
}

struct WorkflowStore {
    snapshot: std::sync::Mutex<DeliberationSnapshot>,
    writes: std::sync::Mutex<Vec<DeliberationPersistenceCommand>>,
}

impl WorkflowStore {
    fn new(snapshot: DeliberationSnapshot) -> Self {
        Self {
            snapshot: std::sync::Mutex::new(snapshot),
            writes: std::sync::Mutex::new(Vec::new()),
        }
    }
}

impl DeliberationStore for WorkflowStore {
    fn load(&self, _: &TaskId) -> Result<DeliberationSnapshot, PortError> {
        Ok(self.snapshot.lock().unwrap().clone())
    }

    fn persist(&self, command: DeliberationPersistenceCommand) -> Result<(), PortError> {
        command.validate()?;
        self.writes.lock().unwrap().push(command);
        Ok(())
    }
}

impl DeliberationSynthesisStore for WorkflowStore {
    fn persist_synthesis(&self, command: DeliberationSynthesisCommand) -> Result<(), PortError> {
        command.validate()?;
        self.writes
            .lock()
            .unwrap()
            .push(command.persistence().clone());
        Ok(())
    }
}

struct CountingPlanApprovalAuthority {
    calls: std::sync::Mutex<usize>,
    binding: PlanApprovalAuthorityBinding,
}

impl PlanApprovalAuthorityProvider for CountingPlanApprovalAuthority {
    fn current(&self, _: &TaskId) -> Result<PlanApprovalAuthorityBinding, PortError> {
        *self.calls.lock().unwrap() += 1;
        Ok(self.binding.clone())
    }
}

struct ApprovalClock;

impl Clock for ApprovalClock {
    fn now_utc(&self) -> Result<String, PortError> {
        Ok("2026-08-11T00:01:00Z".to_owned())
    }
}

struct ResolutionStore {
    stored: StoredPlanApproval,
    current: PlanApprovalCurrentState,
    reloads: std::sync::Mutex<usize>,
    current_reloads: std::sync::Mutex<usize>,
    commands: std::sync::Mutex<Vec<CompareAndResolvePlanApproval>>,
}

impl PlanApprovalStore for ResolutionStore {
    fn reload(&self, _: &ApprovalId) -> Result<Option<StoredPlanApproval>, PortError> {
        *self.reloads.lock().unwrap() += 1;
        Ok(Some(self.stored.clone()))
    }

    fn current_state(&self, _: &TaskId) -> Result<PlanApprovalCurrentState, PortError> {
        *self.current_reloads.lock().unwrap() += 1;
        Ok(self.current.clone())
    }

    fn compare_and_resolve(&self, command: CompareAndResolvePlanApproval) -> Result<(), PortError> {
        command.validate()?;
        self.commands.lock().unwrap().push(command);
        Ok(())
    }

    fn compare_and_invalidate(&self, _: CompareAndInvalidatePlanApproval) -> Result<(), PortError> {
        unreachable!("approval resolution test does not invalidate")
    }

    fn compare_and_expire(&self, _: CompareAndExpirePlanApproval) -> Result<(), PortError> {
        unreachable!("approval resolution test does not expire")
    }
}

fn unpublished_snapshot() -> DeliberationSnapshot {
    recover_snapshot(
        Phase::ParallelAnalysis,
        2,
        vec![private_fact(proposal(1), 1), private_fact(proposal(2), 2)],
    )
}

fn objection_facts(severity: ObjectionSeverity) -> Vec<CanonicalDeliberationFact> {
    let unchecked = material_claim(false);
    let checked = material_claim(true);
    vec![
        private_fact(proposal(1), 1),
        private_fact(proposal(2), 2),
        CanonicalDeliberationFact::issue(
            task(),
            local_agent_terminal_domain::EventId::new("event-quorum-history").unwrap(),
            3,
            ActorId::new("core").unwrap(),
            DeliberationRecord::QuorumPublication {
                proposals: IndependentQuorum::new(vec![proposal(1), proposal(2)])
                    .unwrap()
                    .reveal(),
                proposal_artifact: deliberation_artifact("proposal-bundle", '8'),
                review_plan: review_plan(1),
                review_artifact: deliberation_artifact("review-plan", '9'),
            },
        )
        .unwrap(),
        CanonicalDeliberationFact::issue(
            task(),
            local_agent_terminal_domain::EventId::new("event-claims-history").unwrap(),
            4,
            ActorId::new("core").unwrap(),
            DeliberationRecord::ClaimSet {
                claims: vec![unchecked],
                artifact: deliberation_artifact("claim-set", '3'),
            },
        )
        .unwrap(),
        CanonicalDeliberationFact::issue(
            task(),
            local_agent_terminal_domain::EventId::new("event-verification-history").unwrap(),
            5,
            ActorId::new("core").unwrap(),
            DeliberationRecord::VerificationSet {
                claims: vec![checked.clone()],
                artifact: deliberation_artifact("verification-set", '4'),
            },
        )
        .unwrap(),
        CanonicalDeliberationFact::issue(
            task(),
            local_agent_terminal_domain::EventId::new("event-decision-history").unwrap(),
            6,
            ActorId::new("core").unwrap(),
            DeliberationRecord::DecisionDraft {
                decision: decision(checked),
                artifact: deliberation_artifact("decision-draft", '5'),
                plan_artifact: deliberation_artifact("plan-1", '4'),
                plan_version: 1,
            },
        )
        .unwrap(),
        CanonicalDeliberationFact::issue(
            task(),
            local_agent_terminal_domain::EventId::new("event-objection-history").unwrap(),
            7,
            ActorId::new("core").unwrap(),
            DeliberationRecord::ObjectionSet {
                objections: FinalObjectionSet::new(
                    1,
                    vec![FinalObjection::new(
                        "agent-1",
                        1,
                        severity,
                        "material implementation impact",
                        vec![citation()],
                        (severity == ObjectionSeverity::Severe)
                            .then_some("workspace isolation requirement"),
                    )
                    .unwrap()],
                )
                .unwrap(),
                artifact: deliberation_artifact("objection-set", '6'),
            },
        )
        .unwrap(),
    ]
}

fn recover_snapshot(
    phase: Phase,
    version: u64,
    facts: Vec<CanonicalDeliberationFact>,
) -> DeliberationSnapshot {
    recover_deliberation(DeliberationRecoveryInput {
        task_id: task(),
        task_version: version,
        task_state: deliberation_state(phase, version),
        run_assignments: vec![run_assignment(1), run_assignment(2)],
        facts,
    })
    .unwrap()
}

fn deliberation_context(
    phase: Phase,
    version: u64,
    artifact: DeliberationArtifactRef,
    event_id: &str,
) -> DeliberationCommandContext {
    DeliberationCommandContext::new(
        task(),
        version,
        deliberation_state(phase, version),
        ActorId::new("core").unwrap(),
        artifact,
        local_agent_terminal_domain::EventId::new(event_id).unwrap(),
        "task-1:workflow",
        "2026-08-11T00:00:00Z",
    )
    .unwrap()
}

fn deliberation_state(phase: Phase, version: u64) -> WorkflowState {
    WorkflowState::new(
        phase,
        Condition::Active,
        OperationState::None,
        Sequence::new(version),
        WorkspaceVersion::new(1),
        FencingToken::new(1).unwrap(),
    )
    .unwrap()
}

fn private_fact(proposal: IndependentProposal, event_sequence: u64) -> CanonicalDeliberationFact {
    CanonicalDeliberationFact::issue(
        task(),
        local_agent_terminal_domain::EventId::new(format!("event-private-{event_sequence}"))
            .unwrap(),
        event_sequence,
        ActorId::new(proposal.agent_id()).unwrap(),
        DeliberationRecord::PrivateProposal {
            proposal: proposal.clone(),
            proposal_artifact: DeliberationArtifactRef::new(
                proposal.artifact_id().clone(),
                digest_char('7'),
                17,
            )
            .unwrap(),
            receipt: deliberation_artifact(&format!("receipt-{event_sequence}"), '6'),
        },
    )
    .unwrap()
}

fn proposal(number: u8) -> IndependentProposal {
    IndependentProposal::new(
        task(),
        RunId::new(format!("run-{number}")).unwrap(),
        &format!("agent-{number}"),
        AgentFamilyKey::new(format!("family-{number}")).unwrap(),
        ArtifactId::new(format!("proposal-{number}")).unwrap(),
        vec![citation()],
    )
    .unwrap()
}

fn run_assignment(number: u8) -> DeliberationRunAssignment {
    DeliberationRunAssignment::new(
        RunId::new(format!("run-{number}")).unwrap(),
        format!("agent-{number}"),
        AgentFamilyKey::new(format!("family-{number}")).unwrap(),
        ActorId::new(format!("agent-{number}")).unwrap(),
    )
    .unwrap()
}

fn review_plan(round: u32) -> ReviewPlan {
    ReviewPlan::new(
        DeliberationLimits::new(4, 2, 8, 2).unwrap(),
        vec![
            ReviewEdge::new("agent-2", ArtifactId::new("proposal-1").unwrap(), round).unwrap(),
            ReviewEdge::new("agent-1", ArtifactId::new("proposal-2").unwrap(), round).unwrap(),
        ],
    )
    .unwrap()
}

fn material_claim(verified: bool) -> MaterialClaim {
    let claim = MaterialClaim::new(
        "claim-a",
        "agent-1",
        ArtifactId::new("proposal-1").unwrap(),
        vec![citation()],
        VerificationMethod::SourceMatch,
    )
    .unwrap();
    if verified {
        claim.classify(ClaimVerification::Verified).unwrap()
    } else {
        claim
    }
}

fn decision(claim: MaterialClaim) -> DecisionPackage {
    DecisionPackage::new(
        DecisionApproach::new(
            "approach-a",
            ArtifactId::new("proposal-1").unwrap(),
            vec!["claim-a".to_owned()],
        )
        .unwrap(),
        vec![RejectedApproach::new(
            DecisionApproach::new(
                "approach-b",
                ArtifactId::new("proposal-2").unwrap(),
                Vec::new(),
            )
            .unwrap(),
            "higher risk",
        )
        .unwrap()],
        vec![claim],
        vec![Dissent::new(
            "dissent-1",
            "agent-2",
            ArtifactId::new("dissent-artifact").unwrap(),
            "prefer approach b",
        )
        .unwrap()],
        &["dissent-1"],
        ArtifactId::new("plan-1").unwrap(),
    )
    .unwrap()
}

fn citation() -> EvidenceCitation {
    EvidenceCitation::new(
        SourceIdentity::new(
            ProjectId::new("project-1").unwrap(),
            "0123456789012345678901234567890123456789",
            "src/lib.rs",
            digest_char('a'),
        )
        .unwrap(),
        None,
        None,
        EvidenceFreshness::Current,
    )
    .unwrap()
}

fn deliberation_artifact(id: &str, character: char) -> DeliberationArtifactRef {
    DeliberationArtifactRef::new(ArtifactId::new(id).unwrap(), digest_char(character), 17).unwrap()
}

fn plan_approval_request() -> PreparePlanApprovalRequestInput {
    PreparePlanApprovalRequestInput {
        approval_id: ApprovalId::new("approval-plan-1").unwrap(),
        request_artifact_id: ArtifactId::new("artifact-plan-approval-1").unwrap(),
    }
}

fn plan_approval_binding() -> PlanApprovalBindingInput {
    PlanApprovalBindingInput {
        task_id: "task-1".into(),
        plan_artifact_id: "plan-1".into(),
        plan_digest: digest_char('4').as_str().to_owned(),
        plan_version: 1,
        base_commit: "a".repeat(40),
        allowed_paths: vec![PlanApprovalPathScopeV1 {
            root_capability: "root-1".into(),
            patterns: vec!["src/**".into()],
        }],
        planned_tool_digests: vec![digest_char('2').as_str().to_owned()],
        verification_profile_digest: digest_char('3').as_str().to_owned(),
        risk_class: "medium".into(),
        repository_fingerprint: digest_char('4').as_str().to_owned(),
        policy_snapshot_digest: digest_char('5').as_str().to_owned(),
        agent_id: "agent-1".into(),
        agent_manifest_digest: digest_char('6').as_str().to_owned(),
        actor_id: "actor-1".into(),
        task_version: 8,
        workspace_version: 1,
        fencing_epoch: 2,
        requested_at: "2026-08-11T00:00:00Z".into(),
        expires_at: "2026-08-11T00:15:00Z".into(),
    }
}

fn task() -> TaskId {
    TaskId::new("task-1").unwrap()
}

fn digest_char(character: char) -> Sha256Digest {
    Sha256Digest::new(format!("sha256:{}", character.to_string().repeat(64))).unwrap()
}

fn fingerprint() -> WorkspaceFingerprint {
    WorkspaceFingerprint::new(
        GitObjectId::new("0123456789012345678901234567890123456789").unwrap(),
        format!("sha256:{}", "a".repeat(64)),
        format!("sha256:{}", "b".repeat(64)),
    )
    .unwrap()
}
