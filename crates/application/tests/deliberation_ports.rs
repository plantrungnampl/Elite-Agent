use std::sync::{Arc, Mutex};

use local_agent_terminal_application::{
    ApprovalId, DeliberationArtifactRef, DeliberationCommandContext, DeliberationCommands,
    DeliberationPersistenceCommand, DeliberationRecord, DeliberationRunAssignment,
    DeliberationSnapshot, DeliberationStore, PlanApprovalAuthorityBinding,
    PlanApprovalBindingInput, PlanApprovalPathScopeV1, PortError, PreparePlanApprovalRequestInput,
    ProjectionChange, Retryability, SafeErrorClassification,
};
use local_agent_terminal_domain::{
    ActorId, ArtifactId, ClaimVerification, Condition, DecisionApproach, DecisionPackage,
    DeliberationLimits, Dissent, EventId, EvidenceCitation, EvidenceFreshness, FencingToken,
    FinalObjectionSet, IndependentProposal, IndependentQuorum, MaterialClaim, ObjectionSeverity,
    OperationState, Phase, ProjectId, RejectedApproach, ReviewEdge, ReviewPlan, RunId, Sequence,
    Sha256Digest, SourceIdentity, SpecialistBudget, SpecialistRequest, TaskId, Timestamp,
    VerificationMethod, WorkflowState, WorkspaceVersion,
};

#[derive(Default)]
struct Writes {
    private: usize,
    published: usize,
    decisions: usize,
    closed: usize,
    commands: Vec<DeliberationPersistenceCommand>,
}

struct Store {
    snapshot: Mutex<DeliberationSnapshot>,
    writes: Arc<Mutex<Writes>>,
}

impl DeliberationStore for Store {
    fn load(&self, _: &TaskId) -> Result<DeliberationSnapshot, PortError> {
        Ok(self.snapshot.lock().unwrap().clone())
    }

    fn persist(&self, command: DeliberationPersistenceCommand) -> Result<(), PortError> {
        let mut writes = self.writes.lock().unwrap();
        command.validate()?;
        match command.record() {
            DeliberationRecord::PrivateProposal { .. } => writes.private += 1,
            DeliberationRecord::QuorumPublication { proposals, .. } => {
                assert!(proposals.iter().all(IndependentProposal::is_revealed));
                writes.published += 1;
            }
            DeliberationRecord::DecisionDraft { .. } => writes.decisions += 1,
            DeliberationRecord::ObjectionRoundClosed { .. } => writes.closed += 1,
            _ => {}
        }
        writes.commands.push(command);
        Ok(())
    }
}

#[test]
fn persistence_command_carries_exact_event_projection_and_artifact_authority() {
    let (store, writes) = make_store(snapshot(Phase::ParallelAnalysis));

    DeliberationCommands::new(&store)
        .publish_proposals(
            command("task-1", 7, "actor-1"),
            review_plan(),
            artifact("artifact-review-1", '8'),
        )
        .unwrap();

    let writes = writes.lock().unwrap();
    let persisted = &writes.commands[0];
    assert_eq!(persisted.task_id().as_str(), "task-1");
    assert_eq!(persisted.expected_task_version(), 7);
    assert_eq!(persisted.append().stream_id.as_str(), "task-1");
    assert_eq!(persisted.append().expected_version, Sequence::new(7));
    assert_eq!(persisted.append().events[0].event_id.as_str(), "event-1");
    assert_eq!(
        persisted.append().events[0].event_type.as_str(),
        "analysis.quorum.reached"
    );
    assert_eq!(
        persisted.append().events[0].created_at,
        "2026-08-09T00:00:00Z"
    );
    assert_eq!(persisted.append().events[0].correlation_id, "correlation-1");
    assert!(
        matches!(persisted.append().projection_changes.as_slice(), [ProjectionChange::TaskState { task_id, state, .. }] if task_id.as_str() == "task-1" && state.phase() == Phase::CrossReview && state.condition() == Condition::Active && state.operation() == OperationState::None && state.workspace_version() == WorkspaceVersion::new(1) && state.fencing_token() == FencingToken::new(1).unwrap())
    );
    assert!(
        matches!(persisted.record(), DeliberationRecord::QuorumPublication { proposal_artifact, review_plan, review_artifact, .. } if proposal_artifact.artifact_id().as_str() == "artifact-record-1" && proposal_artifact.content_digest() == &digest('9') && !review_plan.edges().is_empty() && review_artifact.artifact_id().as_str() == "artifact-review-1")
    );
}

#[test]
fn deliberation_store_is_object_safe() {
    fn accepts(_: &dyn DeliberationStore) {}
    let (store, _) = make_store(snapshot(Phase::ParallelAnalysis));
    accepts(&store);
}

#[test]
fn command_context_binds_the_complete_authoritative_state_without_accepting_an_append() {
    let state = authoritative_state(Phase::ParallelAnalysis, 7);
    let context = DeliberationCommandContext::new(
        TaskId::new("task-1").unwrap(),
        7,
        state,
        ActorId::new("actor-1").unwrap(),
        DeliberationArtifactRef::new(
            ArtifactId::new("artifact-record-1").unwrap(),
            digest('9'),
            17,
        )
        .unwrap(),
        EventId::new("event-1").unwrap(),
        "correlation-1",
        "2026-08-09T00:00:00Z",
    )
    .unwrap();

    assert_eq!(context.expected_task_state().sequence(), Sequence::new(7));
}

#[test]
fn malformed_correlation_and_timestamp_are_invalid_input_not_stale_conflicts() {
    for (correlation, occurred_at) in [
        ("", "2026-08-09T00:00:00Z"),
        ("correlation-1", "not-a-timestamp"),
    ] {
        let error = DeliberationCommandContext::new(
            TaskId::new("task-1").unwrap(),
            7,
            authoritative_state(Phase::ParallelAnalysis, 7),
            ActorId::new("actor-1").unwrap(),
            artifact("artifact-record-1", '9'),
            EventId::new("event-1").unwrap(),
            correlation,
            occurred_at,
        )
        .unwrap_err();
        assert_eq!(
            error.safe_classification(),
            SafeErrorClassification::InvalidInput
        );
    }
}

#[test]
fn caller_structural_version_mismatch_is_invalid_but_loaded_staleness_is_conflict() {
    let structural = DeliberationCommandContext::new(
        TaskId::new("task-1").unwrap(),
        8,
        authoritative_state(Phase::ParallelAnalysis, 7),
        ActorId::new("actor-1").unwrap(),
        artifact("artifact-record-1", '9'),
        EventId::new("event-1").unwrap(),
        "correlation-1",
        "2026-08-09T00:00:00Z",
    )
    .unwrap_err();
    assert_eq!(
        structural.safe_classification(),
        SafeErrorClassification::InvalidInput
    );

    let mut loaded = snapshot(Phase::ParallelAnalysis);
    loaded.task_version = 8;
    loaded.task_state = authoritative_state(Phase::ParallelAnalysis, 8);
    let (store, writes) = make_store(loaded);
    let stale = DeliberationCommands::new(&store)
        .record_private_proposal(command("task-1", 7, "actor-1"), proposal(1))
        .unwrap_err();
    assert_eq!(
        stale.safe_classification(),
        SafeErrorClassification::Conflict
    );
    assert!(writes.lock().unwrap().commands.is_empty());
}

#[test]
fn commands_reject_wrong_phase_version_task_and_actor_before_writes() {
    let invalid_contexts = [
        (
            snapshot(Phase::ContextBuild),
            command("task-1", 7, "actor-1"),
        ),
        (
            snapshot(Phase::ParallelAnalysis),
            command("task-1", 8, "actor-1"),
        ),
        (
            snapshot(Phase::ParallelAnalysis),
            command("task-2", 7, "actor-1"),
        ),
        (
            snapshot(Phase::ParallelAnalysis),
            command("task-1", 7, "actor-2"),
        ),
    ];

    for (state, context) in invalid_contexts {
        let (store, writes) = make_store(state);
        let commands = DeliberationCommands::new(&store);
        assert!(commands
            .publish_proposals(context, review_plan(), artifact("artifact-review-1", '8'))
            .is_err());
        assert_eq!(writes.lock().unwrap().published, 0);
    }
}

#[test]
fn proposal_publication_requires_independent_quorum() {
    let mut state = snapshot(Phase::ParallelAnalysis);
    state.quorum = None;
    let (store, writes) = make_store(state);

    assert!(DeliberationCommands::new(&store)
        .publish_proposals(
            command("task-1", 7, "actor-1"),
            review_plan(),
            artifact("artifact-review-1", '8'),
        )
        .is_err());
    assert_eq!(writes.lock().unwrap().published, 0);

    *store.snapshot.lock().unwrap() = snapshot(Phase::ParallelAnalysis);
    DeliberationCommands::new(&store)
        .publish_proposals(
            command("task-1", 7, "actor-1"),
            review_plan(),
            artifact("artifact-review-1", '8'),
        )
        .unwrap();
    assert_eq!(writes.lock().unwrap().published, 1);
}

#[test]
fn proposal_publication_rejects_cross_task_quorums_before_writes() {
    let mut state = snapshot(Phase::ParallelAnalysis);
    state.quorum = Some(
        IndependentQuorum::new(vec![
            proposal_for_task(1, "task-2"),
            proposal_for_task(2, "task-2"),
        ])
        .unwrap(),
    );
    let (store, writes) = make_store(state);

    assert!(DeliberationCommands::new(&store)
        .publish_proposals(
            command("task-1", 7, "actor-1"),
            review_plan(),
            artifact("artifact-review-1", '8'),
        )
        .is_err());
    assert_eq!(writes.lock().unwrap().published, 0);

    assert!(IndependentQuorum::new(vec![
        proposal_for_task(1, "task-1"),
        proposal_for_task(2, "task-2"),
    ])
    .is_err());
    assert_eq!(writes.lock().unwrap().published, 0);
}

#[test]
fn private_proposal_requires_the_exact_authoritative_run_assignment() {
    let hostile = [
        IndependentProposal::new(
            TaskId::new("task-1").unwrap(),
            RunId::new("run-forged").unwrap(),
            "agent-1",
            local_agent_terminal_domain::AgentFamilyKey::new("family-1").unwrap(),
            ArtifactId::new("proposal-forged-run").unwrap(),
            vec![citation()],
        )
        .unwrap(),
        IndependentProposal::new(
            TaskId::new("task-1").unwrap(),
            RunId::new("run-1").unwrap(),
            "agent-forged",
            local_agent_terminal_domain::AgentFamilyKey::new("family-1").unwrap(),
            ArtifactId::new("proposal-forged-agent").unwrap(),
            vec![citation()],
        )
        .unwrap(),
        IndependentProposal::new(
            TaskId::new("task-1").unwrap(),
            RunId::new("run-1").unwrap(),
            "agent-1",
            local_agent_terminal_domain::AgentFamilyKey::new("family-forged").unwrap(),
            ArtifactId::new("proposal-forged-family").unwrap(),
            vec![citation()],
        )
        .unwrap(),
    ];

    for proposal in hostile {
        let (store, writes) = make_store(snapshot(Phase::ParallelAnalysis));
        assert!(DeliberationCommands::new(&store)
            .record_private_proposal(command("task-1", 7, "actor-1"), proposal)
            .is_err());
        assert_eq!(writes.lock().unwrap().private, 0);
    }

    let (store, writes) = make_store(snapshot(Phase::ParallelAnalysis));
    DeliberationCommands::new(&store)
        .record_private_proposal(command("task-1", 7, "actor-1"), proposal(1))
        .unwrap();
    assert_eq!(writes.lock().unwrap().private, 1);
}

#[test]
fn quorum_review_edges_target_exact_revealed_proposals_and_assignments() {
    let (store, writes) = make_store(snapshot(Phase::ParallelAnalysis));
    let unrelated_plan = ReviewPlan::new(
        DeliberationLimits::new(4, 2, 8, 2).unwrap(),
        vec![
            ReviewEdge::new("agent-1", ArtifactId::new("proposal-1").unwrap(), 1).unwrap(),
            ReviewEdge::new("agent-2", ArtifactId::new("proposal-unrelated").unwrap(), 1).unwrap(),
        ],
    )
    .unwrap();
    assert!(DeliberationCommands::new(&store)
        .publish_proposals(
            command("task-1", 7, "actor-1"),
            unrelated_plan,
            artifact("artifact-review-1", '8'),
        )
        .is_err());
    assert_eq!(writes.lock().unwrap().published, 0);

    let mut forged = snapshot(Phase::ParallelAnalysis);
    forged.run_assignments[1] = DeliberationRunAssignment::new(
        RunId::new("run-2").unwrap(),
        "agent-2",
        local_agent_terminal_domain::AgentFamilyKey::new("family-forged").unwrap(),
        ActorId::new("actor-2").unwrap(),
    )
    .unwrap();
    let (store, writes) = make_store(forged);
    assert!(DeliberationCommands::new(&store)
        .publish_proposals(
            command("task-1", 7, "actor-1"),
            review_plan(),
            artifact("artifact-review-1", '8'),
        )
        .is_err());
    assert_eq!(writes.lock().unwrap().published, 0);
}

#[test]
fn synthesis_rejects_an_incomplete_authoritative_claim_set() {
    let mut state = snapshot(Phase::Synthesis);
    state.claims = vec![claim("claim-unchecked", false)];
    let (store, writes) = make_store(state);

    assert!(DeliberationCommands::new(&store)
        .synthesize(
            command("task-1", 7, "actor-1"),
            decision(claim("claim-verified", true)),
        )
        .is_err());
    assert_eq!(writes.lock().unwrap().decisions, 0);

    store.snapshot.lock().unwrap().claims =
        vec![claim("claim-verified", true), claim("claim-omitted", true)];
    assert!(DeliberationCommands::new(&store)
        .synthesize(
            command("task-1", 7, "actor-1"),
            decision(claim("claim-verified", true)),
        )
        .is_err());
    assert_eq!(writes.lock().unwrap().decisions, 0);
}

#[test]
fn synthesis_requires_unique_exact_authoritative_claim_ids() {
    let cases = [
        (
            vec![claim("claim-a", true), claim("claim-a", true)],
            vec![claim("claim-a", true), claim("claim-b", true)],
        ),
        (
            vec![claim("claim-a", true)],
            vec![claim("claim-a", true), claim("claim-b", true)],
        ),
        (
            vec![claim("claim-a", true), claim("claim-b", true)],
            vec![claim("claim-a", true)],
        ),
    ];

    for (authoritative_claims, decision_claims) in cases {
        let mut state = snapshot(Phase::Synthesis);
        state.claims = authoritative_claims;
        let (store, writes) = make_store(state);

        assert!(DeliberationCommands::new(&store)
            .synthesize(
                command_for_phase("task-1", 7, "actor-1", Phase::Synthesis),
                decision_with_claims(decision_claims),
            )
            .is_err());
        assert_eq!(writes.lock().unwrap().decisions, 0);
    }
}

#[test]
fn synthesis_requires_exact_authoritative_claim_records() {
    let authoritative = claim("claim-a", true);
    let hostile_cases = [
        (
            vec![authoritative.clone()],
            vec![classified_claim(
                "claim-a",
                "agent-2",
                "proposal-1",
                vec![citation()],
                VerificationMethod::SourceMatch,
                ClaimVerification::Verified,
            )],
        ),
        (
            vec![authoritative.clone()],
            vec![classified_claim(
                "claim-a",
                "agent-1",
                "proposal-2",
                vec![citation()],
                VerificationMethod::SourceMatch,
                ClaimVerification::Verified,
            )],
        ),
        (
            vec![authoritative.clone()],
            vec![classified_claim(
                "claim-a",
                "agent-1",
                "proposal-1",
                vec![citation_for("src/other.rs", 'b')],
                VerificationMethod::SourceMatch,
                ClaimVerification::Verified,
            )],
        ),
        (
            vec![authoritative.clone()],
            vec![classified_claim(
                "claim-a",
                "agent-1",
                "proposal-1",
                vec![citation()],
                VerificationMethod::DeterministicCheck,
                ClaimVerification::Verified,
            )],
        ),
        (
            vec![authoritative, claim("claim-b", true)],
            vec![
                claim("claim-b", true),
                classified_claim(
                    "claim-a",
                    "agent-1",
                    "proposal-1",
                    vec![citation()],
                    VerificationMethod::SourceMatch,
                    ClaimVerification::Inconclusive,
                ),
            ],
        ),
    ];

    for (authoritative_claims, decision_claims) in hostile_cases {
        let mut state = snapshot(Phase::Synthesis);
        state.claims = authoritative_claims;
        let (store, writes) = make_store(state);

        assert!(DeliberationCommands::new(&store)
            .synthesize(
                command_for_phase("task-1", 7, "actor-1", Phase::Synthesis),
                decision_with_claims(decision_claims),
            )
            .is_err());
        assert_eq!(writes.lock().unwrap().decisions, 0);
    }

    let mut state = snapshot(Phase::Synthesis);
    state.claims = vec![claim("claim-b", true), claim("claim-a", true)];
    let (store, writes) = make_store(state);
    DeliberationCommands::new(&store)
        .synthesize(
            command_for_phase("task-1", 7, "actor-1", Phase::Synthesis),
            decision_with_claims(vec![claim("claim-a", true), claim("claim-b", true)]),
        )
        .unwrap();
    assert_eq!(writes.lock().unwrap().decisions, 1);
}

#[test]
fn objection_round_cannot_close_while_an_accepted_severe_objection_remains() {
    let mut state = snapshot(Phase::FinalObjection);
    state.accepted_severe_objection = true;
    let (store, writes) = make_store(state);

    assert!(DeliberationCommands::new(&store)
        .close_objection_round(
            command_for_phase("task-1", 7, "actor-1", Phase::FinalObjection,),
            plan_approval_request()
        )
        .is_err());
    assert_eq!(writes.lock().unwrap().closed, 0);

    store.snapshot.lock().unwrap().accepted_severe_objection = false;
    DeliberationCommands::new(&store)
        .close_objection_round(
            command_for_phase("task-1", 7, "actor-1", Phase::FinalObjection),
            plan_approval_request(),
        )
        .unwrap();
    assert_eq!(writes.lock().unwrap().closed, 1);
    assert!(matches!(
        writes.lock().unwrap().commands.last().unwrap().record(),
        DeliberationRecord::ObjectionRoundClosed { plan_approval, .. }
            if plan_approval.validate().is_ok()
                && plan_approval.binding().task_version == 8
                && plan_approval.binding().workspace_version == 1
    ));
    let writes = writes.lock().unwrap();
    let persisted = writes.commands.last().unwrap();
    let DeliberationRecord::ObjectionRoundClosed { plan_approval, .. } = persisted.record() else {
        panic!("expected objection close record");
    };
    assert_eq!(
        persisted.append().events[0].payload["approvalAuthorityBindingDigest"],
        plan_approval.authority_binding().content_digest().as_str()
    );
    assert_eq!(
        persisted.append().events[0].payload["approvalAuthorityBinding"],
        serde_json::from_slice::<serde_json::Value>(
            plan_approval.authority_binding().canonical_bytes()
        )
        .unwrap()
    );
    let _: ObjectionSeverity = ObjectionSeverity::Severe;
}

#[test]
fn every_deliberation_record_category_has_a_checked_exact_event_path() {
    let (store, writes) = make_store(snapshot(Phase::ParallelAnalysis));
    DeliberationCommands::new(&store)
        .record_private_proposal(command("task-1", 7, "actor-1"), proposal(1))
        .unwrap();
    assert_record_event(&writes, "agent.message.created", false);

    let (store, writes) = make_store(snapshot(Phase::CrossReview));
    DeliberationCommands::new(&store)
        .record_review_edges(
            command_for_phase("task-1", 7, "actor-1", Phase::CrossReview),
            review_plan(),
        )
        .unwrap();
    assert_record_event(&writes, "review.edges.assigned", false);

    let (store, writes) = make_store(snapshot(Phase::CrossReview));
    DeliberationCommands::new(&store)
        .record_thread_summary(
            command_for_phase("task-1", 7, "actor-1", Phase::CrossReview),
            "thread-1",
        )
        .unwrap();
    assert_record_event(&writes, "thread.summary.created", false);

    let (store, writes) = make_store(snapshot(Phase::ParallelAnalysis));
    DeliberationCommands::new(&store)
        .request_specialist(command("task-1", 7, "actor-1"), specialist_request())
        .unwrap();
    assert_record_event(&writes, "specialist.requested", false);

    let (store, writes) = make_store(snapshot(Phase::CrossReview));
    DeliberationCommands::new(&store)
        .record_claim_set(
            command_for_phase("task-1", 7, "actor-1", Phase::CrossReview),
            vec![claim("claim-a", false)],
        )
        .unwrap();
    assert_record_event(&writes, "review.complete", true);

    let mut state = snapshot(Phase::PrePlanVerification);
    state.claims = vec![claim("claim-a", false)];
    let (store, writes) = make_store(state);
    DeliberationCommands::new(&store)
        .record_verification_set(
            command_for_phase("task-1", 7, "actor-1", Phase::PrePlanVerification),
            vec![claim("claim-a", true)],
        )
        .unwrap();
    assert_record_event(&writes, "claims.checked", true);

    let mut state = snapshot(Phase::Synthesis);
    state.claims = vec![claim("claim-a", true)];
    let (store, writes) = make_store(state);
    DeliberationCommands::new(&store)
        .synthesize(
            command_for_phase("task-1", 7, "actor-1", Phase::Synthesis),
            decision(claim("claim-a", true)),
        )
        .unwrap();
    assert_record_event(&writes, "decision.draft.created", true);

    let (store, writes) = make_store(snapshot(Phase::FinalObjection));
    DeliberationCommands::new(&store)
        .record_objection_set(
            command_for_phase("task-1", 7, "actor-1", Phase::FinalObjection),
            FinalObjectionSet::new(1, Vec::new()).unwrap(),
        )
        .unwrap();
    assert_record_event(&writes, "objection.set.created", false);

    let (store, writes) = make_store(snapshot(Phase::Synthesis));
    DeliberationCommands::new(&store)
        .record_supersession(
            command_for_phase("task-1", 7, "actor-1", Phase::Synthesis),
            artifact("artifact-old", '7'),
        )
        .unwrap();
    assert_record_event(&writes, "agent.message.superseded", false);
}

#[test]
fn exact_authoritative_state_rejects_condition_operation_workspace_and_fencing_substitution() {
    let snapshot = snapshot(Phase::ParallelAnalysis);
    let hostile_states = [
        WorkflowState::new(
            Phase::ParallelAnalysis,
            Condition::Paused,
            OperationState::None,
            Sequence::new(7),
            WorkspaceVersion::new(1),
            FencingToken::new(1).unwrap(),
        )
        .unwrap(),
        WorkflowState::new(
            Phase::ParallelAnalysis,
            Condition::Active,
            OperationState::Running,
            Sequence::new(7),
            WorkspaceVersion::new(1),
            FencingToken::new(1).unwrap(),
        )
        .unwrap(),
        WorkflowState::new(
            Phase::ParallelAnalysis,
            Condition::Active,
            OperationState::None,
            Sequence::new(7),
            WorkspaceVersion::new(2),
            FencingToken::new(1).unwrap(),
        )
        .unwrap(),
        WorkflowState::new(
            Phase::ParallelAnalysis,
            Condition::Active,
            OperationState::None,
            Sequence::new(7),
            WorkspaceVersion::new(1),
            FencingToken::new(2).unwrap(),
        )
        .unwrap(),
    ];

    for hostile_state in hostile_states {
        let (store, writes) = make_store(snapshot.clone());
        let context = DeliberationCommandContext::new(
            TaskId::new("task-1").unwrap(),
            7,
            hostile_state,
            ActorId::new("actor-1").unwrap(),
            artifact("artifact-record-1", '9'),
            EventId::new("event-1").unwrap(),
            "correlation-1",
            "2026-08-09T00:00:00Z",
        )
        .unwrap();
        assert!(DeliberationCommands::new(&store)
            .record_private_proposal(context, proposal(3))
            .is_err());
        assert!(writes.lock().unwrap().commands.is_empty());
    }
}

fn make_store(snapshot: DeliberationSnapshot) -> (Store, Arc<Mutex<Writes>>) {
    let writes = Arc::new(Mutex::new(Writes::default()));
    (
        Store {
            snapshot: Mutex::new(snapshot),
            writes: Arc::clone(&writes),
        },
        writes,
    )
}

fn snapshot(phase: Phase) -> DeliberationSnapshot {
    DeliberationSnapshot {
        task_id: TaskId::new("task-1").unwrap(),
        task_version: 7,
        task_state: authoritative_state(phase, 7),
        authorized_actors: vec![ActorId::new("actor-1").unwrap()],
        run_assignments: vec![run_assignment(1), run_assignment(2)],
        quorum: Some(IndependentQuorum::new(vec![proposal(1), proposal(2)]).unwrap()),
        claims: Vec::new(),
        accepted_severe_objection: false,
        plan_approval_authority: Some(
            PlanApprovalAuthorityBinding::issue(plan_approval_binding()).unwrap(),
        ),
    }
}

fn command(task: &str, version: u64, actor: &str) -> DeliberationCommandContext {
    DeliberationCommandContext::new(
        TaskId::new(task).unwrap(),
        version,
        authoritative_state(Phase::ParallelAnalysis, version),
        ActorId::new(actor).unwrap(),
        artifact("artifact-record-1", '9'),
        EventId::new("event-1").unwrap(),
        "correlation-1",
        "2026-08-09T00:00:00Z",
    )
    .unwrap()
}

fn command_for_phase(
    task: &str,
    version: u64,
    actor: &str,
    phase: Phase,
) -> DeliberationCommandContext {
    DeliberationCommandContext::new(
        TaskId::new(task).unwrap(),
        version,
        authoritative_state(phase, version),
        ActorId::new(actor).unwrap(),
        artifact("artifact-record-1", '9'),
        EventId::new("event-1").unwrap(),
        "correlation-1",
        "2026-08-09T00:00:00Z",
    )
    .unwrap()
}

fn authoritative_state(phase: Phase, sequence: u64) -> WorkflowState {
    WorkflowState::new(
        phase,
        Condition::Active,
        OperationState::None,
        Sequence::new(sequence),
        WorkspaceVersion::new(1),
        FencingToken::new(1).unwrap(),
    )
    .unwrap()
}

fn artifact(id: &str, digest_character: char) -> DeliberationArtifactRef {
    DeliberationArtifactRef::new(ArtifactId::new(id).unwrap(), digest(digest_character), 17)
        .unwrap()
}

fn review_plan() -> ReviewPlan {
    ReviewPlan::new(
        DeliberationLimits::new(4, 2, 8, 2).unwrap(),
        vec![
            ReviewEdge::new("agent-2", ArtifactId::new("proposal-1").unwrap(), 1).unwrap(),
            ReviewEdge::new("agent-1", ArtifactId::new("proposal-2").unwrap(), 1).unwrap(),
        ],
    )
    .unwrap()
}

fn run_assignment(number: u8) -> DeliberationRunAssignment {
    DeliberationRunAssignment::new(
        RunId::new(format!("run-{number}")).unwrap(),
        format!("agent-{number}"),
        local_agent_terminal_domain::AgentFamilyKey::new(format!("family-{number}")).unwrap(),
        ActorId::new(format!("actor-{number}")).unwrap(),
    )
    .unwrap()
}

fn specialist_request() -> SpecialistRequest {
    SpecialistRequest::new(
        "specialist-1",
        TaskId::new("task-1").unwrap(),
        RunId::new("run-1").unwrap(),
        "repository-analysis",
        "inspect repository invariants",
        vec![ArtifactId::new("context-1").unwrap()],
        SpecialistBudget::new(512, Timestamp::from_unix_seconds(1_800_000_000)).unwrap(),
    )
    .unwrap()
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
        plan_digest: digest('1').as_str().to_owned(),
        plan_version: 1,
        base_commit: "a".repeat(40),
        allowed_paths: vec![PlanApprovalPathScopeV1 {
            root_capability: "root-1".into(),
            patterns: vec!["src/**".into()],
        }],
        planned_tool_digests: vec![digest('2').as_str().to_owned()],
        verification_profile_digest: digest('3').as_str().to_owned(),
        risk_class: "medium".into(),
        repository_fingerprint: digest('4').as_str().to_owned(),
        policy_snapshot_digest: digest('5').as_str().to_owned(),
        agent_id: "agent-1".into(),
        agent_manifest_digest: digest('6').as_str().to_owned(),
        actor_id: "actor-1".into(),
        task_version: 8,
        workspace_version: 1,
        fencing_epoch: 2,
        requested_at: "2026-08-09T00:00:00Z".into(),
        expires_at: "2026-08-09T00:15:00Z".into(),
    }
}

fn assert_record_event(writes: &Arc<Mutex<Writes>>, event_type: &str, changes_phase: bool) {
    let writes = writes.lock().unwrap();
    let command = writes.commands.last().unwrap();
    assert_eq!(command.append().events.len(), 1);
    assert_eq!(command.append().events[0].event_type.as_str(), event_type);
    assert_eq!(
        command.append().projection_changes.len(),
        usize::from(changes_phase)
    );
    command.validate().unwrap();
}

fn proposal(number: u8) -> IndependentProposal {
    proposal_for_task(number, "task-1")
}

fn proposal_for_task(number: u8, task_id: &str) -> IndependentProposal {
    IndependentProposal::new(
        TaskId::new(task_id).unwrap(),
        RunId::new(format!("run-{number}")).unwrap(),
        &format!("agent-{number}"),
        local_agent_terminal_domain::AgentFamilyKey::new(format!("family-{number}")).unwrap(),
        ArtifactId::new(format!("proposal-{number}")).unwrap(),
        vec![citation()],
    )
    .unwrap()
}

fn claim(id: &str, verified: bool) -> MaterialClaim {
    let claim = MaterialClaim::new(
        id,
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

fn classified_claim(
    id: &str,
    claimant: &str,
    artifact_id: &str,
    citations: Vec<EvidenceCitation>,
    method: VerificationMethod,
    verification: ClaimVerification,
) -> MaterialClaim {
    MaterialClaim::new(
        id,
        claimant,
        ArtifactId::new(artifact_id).unwrap(),
        citations,
        method,
    )
    .unwrap()
    .classify(verification)
    .unwrap()
}

fn decision(verified_claim: MaterialClaim) -> DecisionPackage {
    decision_with_claims(vec![verified_claim])
}

fn decision_with_claims(verified_claims: Vec<MaterialClaim>) -> DecisionPackage {
    DecisionPackage::new(
        DecisionApproach::new(
            "selected",
            ArtifactId::new("proposal-1").unwrap(),
            vec![verified_claims[0].claim_id().to_owned()],
        )
        .unwrap(),
        vec![RejectedApproach::new(
            DecisionApproach::new(
                "rejected",
                ArtifactId::new("proposal-2").unwrap(),
                Vec::new(),
            )
            .unwrap(),
            "less evidence",
        )
        .unwrap()],
        verified_claims,
        vec![Dissent::new(
            "dissent-1",
            "agent-2",
            ArtifactId::new("proposal-2").unwrap(),
            "remaining concern",
        )
        .unwrap()],
        &["dissent-1"],
        ArtifactId::new("plan-1").unwrap(),
    )
    .unwrap()
}

fn citation() -> EvidenceCitation {
    citation_for("src/lib.rs", 'a')
}

fn citation_for(path: &str, digest_character: char) -> EvidenceCitation {
    EvidenceCitation::new(
        SourceIdentity::new(
            ProjectId::new("project-1").unwrap(),
            "commit-1",
            path,
            digest(digest_character),
        )
        .unwrap(),
        None,
        None,
        EvidenceFreshness::Current,
    )
    .unwrap()
}

fn digest(character: char) -> Sha256Digest {
    Sha256Digest::new(format!("sha256:{}", character.to_string().repeat(64))).unwrap()
}

fn _invalid_input() -> PortError {
    PortError::failure(
        SafeErrorClassification::InvalidInput,
        Retryability::NonRetryable,
    )
}
