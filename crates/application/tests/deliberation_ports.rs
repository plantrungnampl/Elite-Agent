use std::sync::{Arc, Mutex};

use local_agent_terminal_application::{
    recover_deliberation, ApprovalId, CanonicalDeliberationFact, DeliberationArtifactRef,
    DeliberationCommandContext, DeliberationCommands, DeliberationPersistenceCommand,
    DeliberationRecord, DeliberationRecoveryInput, DeliberationRunAssignment, DeliberationSnapshot,
    DeliberationStore, PlanApprovalAuthorityBinding, PlanApprovalAuthorityProvider,
    PlanApprovalBindingInput, PlanApprovalPathScopeV1, PortError, PreparePlanApprovalRequestInput,
    ProjectionChange, Retryability, SafeErrorClassification,
};
use local_agent_terminal_domain::{
    ActorId, ArtifactId, ClaimVerification, Condition, DecisionApproach, DecisionPackage,
    DeliberationLimits, Dissent, EventId, EvidenceCitation, EvidenceFreshness, FencingToken,
    FinalObjection, FinalObjectionSet, IndependentProposal, IndependentQuorum, MaterialClaim,
    ObjectionSeverity, OperationState, Phase, ProjectId, RejectedApproach, ReviewEdge, ReviewPlan,
    RunId, Sequence, Sha256Digest, SourceIdentity, SpecialistBudget, SpecialistRequest, TaskId,
    Timestamp, VerificationMethod, WorkflowState, WorkspaceVersion,
};

#[derive(Default)]
struct Writes {
    private: usize,
    published: usize,
    decisions: usize,
    accepted_severe: usize,
    closed: usize,
    commands: Vec<DeliberationPersistenceCommand>,
}

struct Store {
    snapshot: Mutex<DeliberationSnapshot>,
    writes: Arc<Mutex<Writes>>,
}

struct FixedPlanApprovalAuthority {
    binding: PlanApprovalAuthorityBinding,
}

impl PlanApprovalAuthorityProvider for FixedPlanApprovalAuthority {
    fn current(&self, _task_id: &TaskId) -> Result<PlanApprovalAuthorityBinding, PortError> {
        Ok(self.binding.clone())
    }
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
            DeliberationRecord::ObjectionSevereAccepted { .. } => writes.accepted_severe += 1,
            DeliberationRecord::ObjectionRoundClosed { .. } => writes.closed += 1,
            _ => {}
        }
        writes.commands.push(command);
        Ok(())
    }
}

#[test]
fn persistence_command_carries_exact_event_projection_and_artifact_authority() {
    let (store, writes) = make_store(unpublished_snapshot());

    DeliberationCommands::new(&store)
        .publish_proposals(
            command("task-1", 7, "core"),
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
        matches!(persisted.record(), DeliberationRecord::QuorumPublication { proposals, proposal_artifact, review_plan, review_artifact } if proposals == &IndependentQuorum::new(vec![proposal(1), proposal(2)]).unwrap().reveal() && proposal_artifact.artifact_id().as_str() == "artifact-record-1" && proposal_artifact.content_digest() == &digest('9') && !review_plan.edges().is_empty() && review_artifact.artifact_id().as_str() == "artifact-review-1")
    );
}

#[test]
fn objection_close_requires_a_trusted_exact_plan_authority_provider() {
    let (store, writes) = make_store(snapshot_with_objection_set(ObjectionSeverity::Low));
    assert!(DeliberationCommands::new(&store)
        .close_objection_round(
            command_for_phase("task-1", 7, "core", Phase::FinalObjection),
            plan_approval_request(),
        )
        .is_err());
    assert!(writes.lock().unwrap().commands.is_empty());

    let authority = FixedPlanApprovalAuthority {
        binding: PlanApprovalAuthorityBinding::issue(plan_approval_binding()).unwrap(),
    };
    DeliberationCommands::with_plan_approval_authority(&store, &authority)
        .close_objection_round(
            command_for_phase("task-1", 7, "core", Phase::FinalObjection),
            plan_approval_request(),
        )
        .unwrap();
    assert_eq!(writes.lock().unwrap().closed, 1);

    let mut hostile_binding = plan_approval_binding();
    hostile_binding.plan_digest = digest('f').as_str().to_owned();
    let hostile = FixedPlanApprovalAuthority {
        binding: PlanApprovalAuthorityBinding::issue(hostile_binding).unwrap(),
    };
    let (store, writes) = make_store(snapshot_with_objection_set(ObjectionSeverity::Low));
    assert!(
        DeliberationCommands::with_plan_approval_authority(&store, &hostile)
            .close_objection_round(
                command_for_phase("task-1", 7, "core", Phase::FinalObjection),
                plan_approval_request(),
            )
            .is_err()
    );
    assert!(writes.lock().unwrap().commands.is_empty());
}

#[test]
fn deliberation_store_is_object_safe() {
    fn accepts(_: &dyn DeliberationStore) {}
    let (store, _) = make_store(snapshot(Phase::ParallelAnalysis));
    accepts(&store);
}

#[test]
fn core_cannot_emit_agent_owned_records_without_writes() {
    let (store, writes) = make_store(unpublished_snapshot());
    assert!(DeliberationCommands::new(&store)
        .record_private_proposal(
            command("task-1", 7, "core"),
            proposal(1),
            artifact("proposal-1", '7'),
        )
        .is_err());
    assert!(writes.lock().unwrap().commands.is_empty());

    let (store, writes) = make_store(unpublished_snapshot());
    assert!(DeliberationCommands::new(&store)
        .request_specialist(command("task-1", 7, "core"), specialist_request())
        .is_err());
    assert!(writes.lock().unwrap().commands.is_empty());
}

#[test]
fn specialist_request_requires_the_requesting_run_assignment_actor() {
    let (store, writes) = make_store(snapshot(Phase::ParallelAnalysis));
    assert!(DeliberationCommands::new(&store)
        .request_specialist(command("task-1", 7, "agent-2"), specialist_request(),)
        .is_err());
    assert!(writes.lock().unwrap().commands.is_empty());
}

#[test]
fn agents_cannot_emit_core_owned_records_without_writes() {
    let mut outcomes = Vec::new();

    let (store, writes) = make_store(unpublished_snapshot());
    outcomes.push((
        "quorum",
        rejected_without_writes(
            DeliberationCommands::new(&store).publish_proposals(
                command("task-1", 7, "agent-1"),
                review_plan(),
                artifact("artifact-review-1", '8'),
            ),
            &writes,
        ),
    ));

    let (store, writes) = make_store(snapshot(Phase::CrossReview));
    outcomes.push((
        "review_edges",
        rejected_without_writes(
            DeliberationCommands::new(&store).record_review_edges(
                command_for_phase("task-1", 7, "agent-1", Phase::CrossReview),
                review_plan(),
            ),
            &writes,
        ),
    ));

    let (store, writes) = make_store(snapshot(Phase::CrossReview));
    outcomes.push((
        "thread_summary",
        rejected_without_writes(
            DeliberationCommands::new(&store).record_thread_summary(
                command_for_phase("task-1", 7, "agent-1", Phase::CrossReview),
                "thread-1",
            ),
            &writes,
        ),
    ));

    let (store, writes) = make_store(snapshot(Phase::CrossReview));
    outcomes.push((
        "claim_set",
        rejected_without_writes(
            DeliberationCommands::new(&store).record_claim_set(
                command_for_phase("task-1", 7, "agent-1", Phase::CrossReview),
                vec![claim("claim-a", false)],
            ),
            &writes,
        ),
    ));

    let state = snapshot(Phase::PrePlanVerification);
    let (store, writes) = make_store(state);
    outcomes.push((
        "verification_set",
        rejected_without_writes(
            DeliberationCommands::new(&store).record_verification_set(
                command_for_phase("task-1", 7, "agent-1", Phase::PrePlanVerification),
                vec![claim("claim-a", true)],
            ),
            &writes,
        ),
    ));

    let state = snapshot(Phase::Synthesis);
    let (store, writes) = make_store(state);
    outcomes.push((
        "decision",
        rejected_without_writes(
            DeliberationCommands::new(&store).synthesize(
                command_for_phase("task-1", 7, "agent-1", Phase::Synthesis),
                decision(claim("claim-a", true)),
                artifact("plan-1", '4'),
                1,
            ),
            &writes,
        ),
    ));

    let (store, writes) = make_store(snapshot(Phase::FinalObjection));
    outcomes.push((
        "objection_set",
        rejected_without_writes(
            DeliberationCommands::new(&store).record_objection_set(
                command_for_phase("task-1", 7, "agent-1", Phase::FinalObjection),
                FinalObjectionSet::new(1, Vec::new()).unwrap(),
            ),
            &writes,
        ),
    ));

    let (store, writes) = make_store(snapshot(Phase::FinalObjection));
    outcomes.push((
        "objection_close",
        rejected_without_writes(
            DeliberationCommands::new(&store).close_objection_round(
                command_for_phase("task-1", 7, "agent-1", Phase::FinalObjection),
                plan_approval_request(),
            ),
            &writes,
        ),
    ));

    let (store, writes) = make_store(snapshot(Phase::Synthesis));
    outcomes.push((
        "supersession",
        rejected_without_writes(
            DeliberationCommands::new(&store).record_supersession(
                command_for_phase("task-1", 7, "agent-1", Phase::Synthesis),
                artifact("artifact-old", '7'),
            ),
            &writes,
        ),
    ));

    assert!(
        outcomes.iter().all(|(_, rejected)| *rejected),
        "{outcomes:?}"
    );
}

#[test]
fn emitted_events_use_exact_actor_and_observation_schema() {
    let (store, writes) = make_store(snapshot(Phase::ParallelAnalysis));
    DeliberationCommands::new(&store)
        .record_private_proposal(
            command("task-1", 7, "agent-1"),
            proposal(1),
            artifact("proposal-1", '7'),
        )
        .unwrap();
    assert_event_authority(&writes, "agent", "agent-1", "agent_claimed");

    let (store, writes) = make_store(snapshot(Phase::ParallelAnalysis));
    DeliberationCommands::new(&store)
        .request_specialist(command("task-1", 7, "agent-1"), specialist_request())
        .unwrap();
    assert_event_authority(&writes, "agent", "agent-1", "agent_claimed");

    let (store, writes) = make_store(unpublished_snapshot());
    DeliberationCommands::new(&store)
        .publish_proposals(
            command("task-1", 7, "core"),
            review_plan(),
            artifact("artifact-review-1", '8'),
        )
        .unwrap();
    assert_event_authority(&writes, "core", "core", "core_observed");
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
        .record_private_proposal(
            command("task-1", 7, "agent-1"),
            proposal(1),
            artifact("proposal-1", '7'),
        )
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
        (snapshot(Phase::ContextBuild), command("task-1", 7, "core")),
        (
            snapshot(Phase::ParallelAnalysis),
            command("task-1", 8, "core"),
        ),
        (
            snapshot(Phase::ParallelAnalysis),
            command("task-2", 7, "core"),
        ),
        (
            snapshot(Phase::ParallelAnalysis),
            command("task-1", 7, "agent-1"),
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
    let (store, writes) = make_store(snapshot(Phase::ParallelAnalysis));

    assert!(DeliberationCommands::new(&store)
        .publish_proposals(
            command("task-1", 7, "core"),
            review_plan(),
            artifact("artifact-review-1", '8'),
        )
        .is_err());
    assert_eq!(writes.lock().unwrap().published, 0);

    *store.snapshot.lock().unwrap() = unpublished_snapshot();
    DeliberationCommands::new(&store)
        .publish_proposals(
            command("task-1", 7, "core"),
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
            command("task-1", 7, "core"),
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
        let proposal_artifact =
            DeliberationArtifactRef::new(proposal.artifact_id().clone(), digest('7'), 17).unwrap();
        let (store, writes) = make_store(snapshot(Phase::ParallelAnalysis));
        assert!(DeliberationCommands::new(&store)
            .record_private_proposal(command("task-1", 7, "agent-1"), proposal, proposal_artifact,)
            .is_err());
        assert_eq!(writes.lock().unwrap().private, 0);
    }

    let (store, writes) = make_store(snapshot(Phase::ParallelAnalysis));
    DeliberationCommands::new(&store)
        .record_private_proposal(
            command("task-1", 7, "agent-1"),
            proposal(1),
            artifact("proposal-1", '7'),
        )
        .unwrap();
    let writes = writes.lock().unwrap();
    assert_eq!(writes.private, 1);
    assert!(matches!(
        writes.commands[0].record(),
        DeliberationRecord::PrivateProposal {
            proposal_artifact,
            receipt,
            ..
        } if proposal_artifact.artifact_id().as_str() == "proposal-1"
            && receipt.artifact_id().as_str() == "artifact-record-1"
            && proposal_artifact != receipt
    ));
}

#[test]
fn private_proposal_rejects_existing_run_or_artifact_but_allows_retry_identity() {
    let duplicate_run = IndependentProposal::new(
        TaskId::new("task-1").unwrap(),
        RunId::new("run-1").unwrap(),
        "agent-1",
        local_agent_terminal_domain::AgentFamilyKey::new("family-1").unwrap(),
        ArtifactId::new("proposal-new").unwrap(),
        vec![citation()],
    )
    .unwrap();
    let (store, writes) = make_store(unpublished_snapshot());
    assert!(DeliberationCommands::new(&store)
        .record_private_proposal(
            command("task-1", 7, "agent-1"),
            duplicate_run,
            artifact("proposal-new", '7'),
        )
        .is_err());
    assert!(writes.lock().unwrap().commands.is_empty());

    let mut duplicate_artifact_state = unpublished_snapshot();
    duplicate_artifact_state
        .run_assignments
        .push(run_assignment(4));
    let duplicate_artifact = IndependentProposal::new(
        TaskId::new("task-1").unwrap(),
        RunId::new("run-4").unwrap(),
        "agent-4",
        local_agent_terminal_domain::AgentFamilyKey::new("family-4").unwrap(),
        ArtifactId::new("proposal-1").unwrap(),
        vec![citation()],
    )
    .unwrap();
    let (store, writes) = make_store(duplicate_artifact_state);
    assert!(DeliberationCommands::new(&store)
        .record_private_proposal(
            command("task-1", 7, "agent-4"),
            duplicate_artifact,
            artifact("proposal-1", '7'),
        )
        .is_err());
    assert!(writes.lock().unwrap().commands.is_empty());

    let mut retry_state = unpublished_snapshot();
    retry_state.run_assignments.push(
        DeliberationRunAssignment::new(
            RunId::new("run-4").unwrap(),
            "agent-1",
            local_agent_terminal_domain::AgentFamilyKey::new("family-1").unwrap(),
            ActorId::new("agent-1").unwrap(),
        )
        .unwrap(),
    );
    let retry = IndependentProposal::new(
        TaskId::new("task-1").unwrap(),
        RunId::new("run-4").unwrap(),
        "agent-1",
        local_agent_terminal_domain::AgentFamilyKey::new("family-1").unwrap(),
        ArtifactId::new("proposal-4").unwrap(),
        vec![citation()],
    )
    .unwrap();
    let (store, writes) = make_store(retry_state);
    DeliberationCommands::new(&store)
        .record_private_proposal(
            command("task-1", 7, "agent-1"),
            retry,
            artifact("proposal-4", '7'),
        )
        .unwrap();
    assert_eq!(writes.lock().unwrap().private, 1);
}

#[test]
fn commands_reject_fabricated_quorum_publication_snapshots_without_writes() {
    let mut missing_quorum = snapshot(Phase::CrossReview);
    missing_quorum.quorum = None;
    let (store, writes) = make_store(missing_quorum);
    assert!(DeliberationCommands::new(&store)
        .record_review_edges(
            command_for_phase("task-1", 7, "core", Phase::CrossReview),
            review_plan(),
        )
        .is_err());
    assert!(writes.lock().unwrap().commands.is_empty());

    let mut mismatched_quorum = snapshot(Phase::CrossReview);
    mismatched_quorum.run_assignments.push(run_assignment(3));
    mismatched_quorum.quorum = Some(
        IndependentQuorum::from_revealed(
            IndependentQuorum::new(vec![proposal(1), proposal(3)])
                .unwrap()
                .reveal(),
        )
        .unwrap(),
    );
    let (store, writes) = make_store(mismatched_quorum);
    assert!(DeliberationCommands::new(&store)
        .record_review_edges(
            command_for_phase("task-1", 7, "core", Phase::CrossReview),
            review_plan(),
        )
        .is_err());
    assert!(writes.lock().unwrap().commands.is_empty());
}

#[test]
fn phase_neutral_writers_require_exact_active_history_without_writes() {
    let (store, writes) = make_store(snapshot_with_specialist_request());
    assert!(DeliberationCommands::new(&store)
        .request_specialist(command("task-1", 7, "agent-1"), specialist_request())
        .is_err());
    assert!(writes.lock().unwrap().commands.is_empty());

    let (store, writes) = make_store(snapshot_with_review_edges());
    assert!(DeliberationCommands::new(&store)
        .record_review_edges(
            command_for_phase("task-1", 7, "core", Phase::CrossReview),
            review_plan(),
        )
        .is_err());
    assert!(writes.lock().unwrap().commands.is_empty());

    let (store, writes) = make_store(snapshot(Phase::CrossReview));
    assert!(DeliberationCommands::new(&store)
        .record_review_edges(
            command_for_phase("task-1", 7, "core", Phase::CrossReview),
            review_plan_for_round(2),
        )
        .is_err());
    assert!(writes.lock().unwrap().commands.is_empty());

    let (store, writes) = make_store(snapshot(Phase::CrossReview));
    assert!(DeliberationCommands::new(&store)
        .record_review_edges(
            command_for_phase_with_artifact(
                "task-1",
                7,
                "core",
                Phase::CrossReview,
                artifact("review-plan-other", '8'),
            ),
            review_plan(),
        )
        .is_err());
    assert!(writes.lock().unwrap().commands.is_empty());

    let (store, writes) = make_store(snapshot_with_thread_summary());
    assert!(DeliberationCommands::new(&store)
        .record_thread_summary(
            command_for_phase("task-1", 7, "core", Phase::CrossReview),
            "thread-1",
        )
        .is_err());
    assert!(writes.lock().unwrap().commands.is_empty());

    let mut no_publication = snapshot(Phase::ParallelAnalysis);
    no_publication.task_state = authoritative_state(Phase::CrossReview, 7);
    let (store, writes) = make_store(no_publication);
    assert!(DeliberationCommands::new(&store)
        .record_thread_summary(
            command_for_phase("task-1", 7, "core", Phase::CrossReview),
            "thread-1",
        )
        .is_err());
    assert!(writes.lock().unwrap().commands.is_empty());
}

#[test]
fn parallel_writers_reject_a_forged_post_publication_snapshot_without_writes() {
    let mut forged = snapshot(Phase::CrossReview);
    forged.task_state = authoritative_state(Phase::ParallelAnalysis, 7);
    assert!(forged.validate().is_err());

    let (store, writes) = make_store(forged.clone());
    assert!(DeliberationCommands::new(&store)
        .record_private_proposal(
            command("task-1", 7, "agent-1"),
            proposal(1),
            artifact("proposal-1", '7'),
        )
        .is_err());
    assert!(writes.lock().unwrap().commands.is_empty());

    let (store, writes) = make_store(forged);
    assert!(DeliberationCommands::new(&store)
        .request_specialist(command("task-1", 7, "agent-1"), specialist_request())
        .is_err());
    assert!(writes.lock().unwrap().commands.is_empty());
}

#[test]
fn publication_accepts_multiple_reviewers_when_target_set_is_exact() {
    let mut state = unpublished_snapshot();
    state.run_assignments.push(
        DeliberationRunAssignment::new(
            RunId::new("run-4").unwrap(),
            "agent-3",
            local_agent_terminal_domain::AgentFamilyKey::new("family-3").unwrap(),
            ActorId::new("agent-3").unwrap(),
        )
        .unwrap(),
    );
    let (store, writes) = make_store(state);

    DeliberationCommands::new(&store)
        .publish_proposals(
            command("task-1", 7, "core"),
            multi_reviewer_plan(),
            artifact("artifact-review-1", '8'),
        )
        .unwrap();

    assert_eq!(writes.lock().unwrap().published, 1);
}

#[test]
fn quorum_review_edges_target_exact_revealed_proposals_and_assignments() {
    let (store, writes) = make_store(unpublished_snapshot());
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
            command("task-1", 7, "core"),
            unrelated_plan,
            artifact("artifact-review-1", '8'),
        )
        .is_err());
    assert_eq!(writes.lock().unwrap().published, 0);

    let mut forged = unpublished_snapshot();
    forged.run_assignments[1] = DeliberationRunAssignment::new(
        RunId::new("run-2").unwrap(),
        "agent-2",
        local_agent_terminal_domain::AgentFamilyKey::new("family-forged").unwrap(),
        ActorId::new("agent-2").unwrap(),
    )
    .unwrap();
    let (store, writes) = make_store(forged);
    assert!(DeliberationCommands::new(&store)
        .publish_proposals(
            command("task-1", 7, "core"),
            review_plan(),
            artifact("artifact-review-1", '8'),
        )
        .is_err());
    assert_eq!(writes.lock().unwrap().published, 0);
}

#[test]
fn synthesis_rejects_an_incomplete_authoritative_claim_set() {
    let mut state = snapshot_with_unclassified_claims(vec![claim("claim-unchecked", false)]);
    state.task_state = authoritative_state(Phase::Synthesis, 7);
    let (store, writes) = make_store(state);

    assert!(DeliberationCommands::new(&store)
        .synthesize(
            command("task-1", 7, "core"),
            decision(claim("claim-verified", true)),
            artifact("plan-1", '4'),
            1,
        )
        .is_err());
    assert_eq!(writes.lock().unwrap().decisions, 0);

    let (store, writes) = make_store(snapshot_with_verified_claims(vec![
        claim("claim-verified", true),
        claim("claim-omitted", true),
    ]));
    assert!(DeliberationCommands::new(&store)
        .synthesize(
            command("task-1", 7, "core"),
            decision(claim("claim-verified", true)),
            artifact("plan-1", '4'),
            1,
        )
        .is_err());
    assert_eq!(writes.lock().unwrap().decisions, 0);
}

#[test]
fn claim_set_rejects_preclassified_claims_without_writes() {
    let (store, writes) = make_store(snapshot(Phase::CrossReview));

    assert!(DeliberationCommands::new(&store)
        .record_claim_set(
            command_for_phase("task-1", 7, "core", Phase::CrossReview),
            vec![claim("claim-classified", true)],
        )
        .is_err());
    assert!(writes.lock().unwrap().commands.is_empty());
}

#[test]
fn synthesis_requires_unique_exact_authoritative_claim_ids() {
    let cases = [
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
        let state = snapshot_with_verified_claims(authoritative_claims);
        let (store, writes) = make_store(state);

        assert!(DeliberationCommands::new(&store)
            .synthesize(
                command_for_phase("task-1", 7, "core", Phase::Synthesis),
                decision_with_claims(decision_claims),
                artifact("plan-1", '4'),
                1,
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
        let state = snapshot_with_verified_claims(authoritative_claims);
        let (store, writes) = make_store(state);

        assert!(DeliberationCommands::new(&store)
            .synthesize(
                command_for_phase("task-1", 7, "core", Phase::Synthesis),
                decision_with_claims(decision_claims),
                artifact("plan-1", '4'),
                1,
            )
            .is_err());
        assert_eq!(writes.lock().unwrap().decisions, 0);
    }

    let state = snapshot_with_verified_claims(vec![claim("claim-b", true), claim("claim-a", true)]);
    let (store, writes) = make_store(state);
    DeliberationCommands::new(&store)
        .synthesize(
            command_for_phase("task-1", 7, "core", Phase::Synthesis),
            decision_with_claims(vec![claim("claim-a", true), claim("claim-b", true)]),
            artifact("plan-1", '4'),
            1,
        )
        .unwrap();
    assert_eq!(writes.lock().unwrap().decisions, 1);
}

#[test]
fn synthesis_binds_exact_plan_reference_and_json_safe_version() {
    let state = snapshot(Phase::Synthesis);
    let (store, writes) = make_store(state);
    let plan_artifact = artifact("plan-1", '4');

    DeliberationCommands::new(&store)
        .synthesize(
            command_for_phase("task-1", 7, "core", Phase::Synthesis),
            decision(claim("claim-a", true)),
            plan_artifact.clone(),
            9_007_199_254_740_991,
        )
        .unwrap();

    let writes = writes.lock().unwrap();
    let persisted = writes.commands.last().unwrap();
    assert!(matches!(
        persisted.record(),
        DeliberationRecord::DecisionDraft {
            artifact,
            plan_artifact: persisted_plan,
            plan_version,
            ..
        } if artifact == &self::artifact("artifact-record-1", '9')
            && persisted_plan == &plan_artifact
            && *plan_version == 9_007_199_254_740_991
    ));
    let payload = &persisted.append().events[0].payload;
    assert_eq!(payload["planArtifactId"], "plan-1");
    assert_eq!(payload["planArtifactDigest"], digest('4').as_str());
    assert_eq!(payload["planArtifactSizeBytes"], 17);
    assert_eq!(payload["planVersion"], 9_007_199_254_740_991_u64);
}

#[test]
fn synthesis_rejects_mismatched_plan_and_unsafe_version_without_writes() {
    for (plan_artifact, plan_version) in [
        (artifact("plan-other", '4'), 3),
        (artifact("plan-1", '4'), 0),
        (artifact("plan-1", '4'), 9_007_199_254_740_992),
    ] {
        let state = snapshot(Phase::Synthesis);
        let (store, writes) = make_store(state);

        assert!(DeliberationCommands::new(&store)
            .synthesize(
                command_for_phase("task-1", 7, "core", Phase::Synthesis),
                decision(claim("claim-a", true)),
                plan_artifact,
                plan_version,
            )
            .is_err());
        assert!(writes.lock().unwrap().commands.is_empty());
    }
}

#[test]
fn accepted_severe_objection_transitions_to_cross_review_and_close_then_rejects() {
    let state = snapshot_with_objection_set(ObjectionSeverity::Severe);
    let (store, writes) = make_store(state);

    DeliberationCommands::new(&store)
        .accept_severe_objection(
            command_for_phase("task-1", 7, "core", Phase::FinalObjection),
            review_plan_for_round(2),
        )
        .unwrap();
    assert_eq!(writes.lock().unwrap().accepted_severe, 1);
    assert_event_authority(&writes, "core", "core", "core_observed");
    assert!(matches!(
        writes.lock().unwrap().commands.last().unwrap().record(),
        DeliberationRecord::ObjectionSevereAccepted {
            objections,
            objection_artifact,
            review_plan,
            review_artifact,
        } if objections == &objection_set(1, ObjectionSeverity::Severe)
            && objection_artifact == &artifact("objection-set-1", '6')
            && review_plan == &review_plan_for_round(2)
            && review_artifact == &artifact("artifact-record-1", '9')
    ));
    let next_state = match &writes
        .lock()
        .unwrap()
        .commands
        .last()
        .unwrap()
        .append()
        .projection_changes[0]
    {
        ProjectionChange::TaskState { state, .. } => *state,
    };
    assert_eq!(next_state.phase(), Phase::CrossReview);

    let mut reopened = snapshot(Phase::CrossReview);
    reopened.task_version = 8;
    reopened.task_state = next_state;
    let (store, close_writes) = make_store(reopened);
    assert!(DeliberationCommands::new(&store)
        .close_objection_round(
            command_for_phase("task-1", 8, "core", Phase::CrossReview),
            plan_approval_request(),
        )
        .is_err());
    assert!(close_writes.lock().unwrap().commands.is_empty());
}

#[test]
fn reopened_round_writers_require_exact_active_history_and_supersession() {
    let reopen_plan = review_plan_for_round(2);
    let review_artifact = artifact("review-plan-2", '7');
    let mut reopened_facts =
        lifecycle_facts_to_severe_acceptance(reopen_plan.clone(), review_artifact.clone());
    let reopened = recover_history_snapshot_at(Phase::CrossReview, 8, reopened_facts.clone());
    let (store, writes) = make_store(reopened);
    DeliberationCommands::new(&store)
        .record_review_edges(
            command_for_phase_with_artifact(
                "task-1",
                8,
                "core",
                Phase::CrossReview,
                review_artifact.clone(),
            ),
            reopen_plan.clone(),
        )
        .unwrap();
    assert!(matches!(
        writes.lock().unwrap().commands.last().unwrap().record(),
        DeliberationRecord::ReviewEdges { plan, artifact }
            if plan == &reopen_plan && artifact == &review_artifact
    ));

    reopened_facts.push(review_edges_fact_for(
        "event-review-edges-2",
        9,
        reopen_plan,
        review_artifact,
    ));
    let reopened = recover_history_snapshot_at(Phase::CrossReview, 9, reopened_facts.clone());
    let (store, writes) = make_store(reopened);
    DeliberationCommands::new(&store)
        .record_claim_set(
            command_for_phase("task-1", 9, "core", Phase::CrossReview),
            vec![claim("claim-a", false)],
        )
        .unwrap();
    assert!(matches!(
        writes.lock().unwrap().commands.last().unwrap().record(),
        DeliberationRecord::ClaimSet { .. }
    ));

    reopened_facts.push(claim_set_fact_for_round(
        "event-claim-set-2",
        vec![claim("claim-a", false)],
        10,
        2,
    ));
    let verifying =
        recover_history_snapshot_at(Phase::PrePlanVerification, 10, reopened_facts.clone());
    let (store, writes) = make_store(verifying);
    DeliberationCommands::new(&store)
        .record_verification_set(
            command_for_phase("task-1", 10, "core", Phase::PrePlanVerification),
            vec![claim("claim-a", true)],
        )
        .unwrap();
    assert!(matches!(
        writes.lock().unwrap().commands.last().unwrap().record(),
        DeliberationRecord::VerificationSet { .. }
    ));

    reopened_facts.push(verification_set_fact_for_round(
        "event-verification-set-2",
        vec![claim("claim-a", true)],
        11,
        2,
    ));
    let synthesis = recover_history_snapshot_at(Phase::Synthesis, 11, reopened_facts.clone());
    let (store, writes) = make_store(synthesis.clone());
    assert!(DeliberationCommands::new(&store)
        .synthesize(
            command_for_phase_with_artifact(
                "task-1",
                11,
                "core",
                Phase::Synthesis,
                artifact("decision-draft-2", '8'),
            ),
            decision_for_plan(claim("claim-a", true), "plan-2"),
            artifact("plan-2", '4'),
            2,
        )
        .is_err());
    assert!(writes.lock().unwrap().commands.is_empty());

    let (store, writes) = make_store(synthesis.clone());
    assert!(DeliberationCommands::new(&store)
        .record_supersession(
            command_for_phase_with_artifact(
                "task-1",
                11,
                "core",
                Phase::Synthesis,
                artifact("decision-draft-2", '8'),
            ),
            artifact("decision-other", '5'),
        )
        .is_err());
    assert!(writes.lock().unwrap().commands.is_empty());

    let (store, writes) = make_store(synthesis);
    DeliberationCommands::new(&store)
        .record_supersession(
            command_for_phase_with_artifact(
                "task-1",
                11,
                "core",
                Phase::Synthesis,
                artifact("decision-draft-2", '8'),
            ),
            artifact("decision-draft-1", '5'),
        )
        .unwrap();
    assert!(matches!(
        writes.lock().unwrap().commands.last().unwrap().record(),
        DeliberationRecord::Supersession {
            superseded,
            replacement,
        } if superseded == &artifact("decision-draft-1", '5')
            && replacement == &artifact("decision-draft-2", '8')
    ));

    reopened_facts.push(supersession_fact_for(
        12,
        artifact("decision-draft-1", '5'),
        artifact("decision-draft-2", '8'),
    ));
    let synthesis = recover_history_snapshot_at(Phase::Synthesis, 12, reopened_facts);
    let (store, writes) = make_store(synthesis);
    DeliberationCommands::new(&store)
        .synthesize(
            command_for_phase_with_artifact(
                "task-1",
                12,
                "core",
                Phase::Synthesis,
                artifact("decision-draft-2", '8'),
            ),
            decision_for_plan(claim("claim-a", true), "plan-2"),
            artifact("plan-2", '4'),
            2,
        )
        .unwrap();
    assert_eq!(writes.lock().unwrap().decisions, 1);
}

#[test]
fn severe_objection_acceptance_rejects_non_authoritative_or_invalid_reopen_plan_without_writes() {
    let cases = [
        (
            objection_set(1, ObjectionSeverity::Low),
            review_plan_for_round(2),
        ),
        (
            objection_set(1, ObjectionSeverity::Severe),
            review_plan_with("agent-2", "proposal-other", 2),
        ),
        (
            objection_set(1, ObjectionSeverity::Severe),
            review_plan_with("agent-other", "proposal-1", 2),
        ),
        (
            objection_set(1, ObjectionSeverity::Severe),
            review_plan_for_round(1),
        ),
    ];

    for (objections, plan) in cases {
        let mut state = snapshot(Phase::FinalObjection);
        state.objections = Some(objections);
        state.objection_artifact = Some(artifact("objection-set-1", '6'));
        let (store, writes) = make_store(state);
        assert!(DeliberationCommands::new(&store)
            .accept_severe_objection(
                command_for_phase("task-1", 7, "core", Phase::FinalObjection),
                plan,
            )
            .is_err());
        assert!(writes.lock().unwrap().commands.is_empty());
    }

    let mut state = snapshot(Phase::FinalObjection);
    state.objections = Some(objection_set(1, ObjectionSeverity::Severe));
    state.objection_artifact = Some(artifact("objection-set-1", '6'));
    let (store, writes) = make_store(state);
    assert!(DeliberationCommands::new(&store)
        .accept_severe_objection(
            command_for_phase("task-1", 7, "agent-1", Phase::FinalObjection),
            review_plan_for_round(2),
        )
        .is_err());
    assert!(writes.lock().unwrap().commands.is_empty());

    let mut state = snapshot(Phase::FinalObjection);
    state.objections = Some(objection_set(1, ObjectionSeverity::Severe));
    state.objection_artifact = Some(artifact("objection-set-1", '6'));
    state.quorum = None;
    let (store, writes) = make_store(state);
    assert!(DeliberationCommands::new(&store)
        .accept_severe_objection(
            command_for_phase("task-1", 7, "core", Phase::FinalObjection),
            review_plan_for_round(2),
        )
        .is_err());
    assert!(writes.lock().unwrap().commands.is_empty());

    let mut state = snapshot(Phase::FinalObjection);
    state.objections = Some(objection_set(1, ObjectionSeverity::Severe));
    state.objection_artifact = Some(artifact("objection-set-1", '6'));
    let (store, writes) = make_store(state);
    assert!(DeliberationCommands::new(&store)
        .accept_severe_objection(
            command_for_phase("task-1", 6, "core", Phase::FinalObjection),
            review_plan_for_round(2),
        )
        .is_err());
    assert!(writes.lock().unwrap().commands.is_empty());
}

#[test]
fn severe_objection_acceptance_rejects_forged_objection_projections_without_writes() {
    let mut state = snapshot_with_objection_set(ObjectionSeverity::Severe);
    state.objections = Some(objection_set(1, ObjectionSeverity::Low));
    state.objection_artifact = Some(artifact("objection-set-forged", '6'));
    assert!(state.validate().is_err());
    let (store, writes) = make_store(state);

    assert!(DeliberationCommands::new(&store)
        .accept_severe_objection(
            command_for_phase("task-1", 7, "core", Phase::FinalObjection),
            review_plan_for_round(2),
        )
        .is_err());
    assert!(writes.lock().unwrap().commands.is_empty());
}

#[test]
fn severe_objection_acceptance_allows_selective_reviewers_when_history_has_extra_assignments() {
    let mut state = snapshot_with_objection_set(ObjectionSeverity::Severe);
    state.run_assignments.push(run_assignment(3));
    let (store, writes) = make_store(state);

    DeliberationCommands::new(&store)
        .accept_severe_objection(
            command_for_phase("task-1", 7, "core", Phase::FinalObjection),
            review_plan_for_round(2),
        )
        .unwrap();

    assert_eq!(writes.lock().unwrap().accepted_severe, 1);
}

#[test]
fn every_deliberation_record_category_has_a_checked_exact_event_path() {
    let (store, writes) = make_store(snapshot(Phase::ParallelAnalysis));
    DeliberationCommands::new(&store)
        .record_private_proposal(
            command("task-1", 7, "agent-1"),
            proposal(1),
            artifact("proposal-1", '7'),
        )
        .unwrap();
    assert_record_event(&writes, "agent.message.created", false);

    let (store, writes) = make_store(snapshot(Phase::CrossReview));
    DeliberationCommands::new(&store)
        .record_review_edges(
            command_for_phase("task-1", 7, "core", Phase::CrossReview),
            review_plan(),
        )
        .unwrap();
    assert_record_event(&writes, "review.edges.assigned", false);

    let (store, writes) = make_store(snapshot(Phase::CrossReview));
    DeliberationCommands::new(&store)
        .record_thread_summary(
            command_for_phase("task-1", 7, "core", Phase::CrossReview),
            "thread-1",
        )
        .unwrap();
    assert_record_event(&writes, "thread.summary.created", false);

    let (store, writes) = make_store(snapshot(Phase::ParallelAnalysis));
    DeliberationCommands::new(&store)
        .request_specialist(command("task-1", 7, "agent-1"), specialist_request())
        .unwrap();
    assert_record_event(&writes, "specialist.requested", false);

    let (store, writes) = make_store(snapshot(Phase::CrossReview));
    DeliberationCommands::new(&store)
        .record_claim_set(
            command_for_phase("task-1", 7, "core", Phase::CrossReview),
            vec![claim("claim-a", false)],
        )
        .unwrap();
    assert_record_event(&writes, "review.complete", true);

    let state = snapshot(Phase::PrePlanVerification);
    let (store, writes) = make_store(state);
    DeliberationCommands::new(&store)
        .record_verification_set(
            command_for_phase("task-1", 7, "core", Phase::PrePlanVerification),
            vec![claim("claim-a", true)],
        )
        .unwrap();
    assert_record_event(&writes, "claims.checked", true);

    let state = snapshot(Phase::Synthesis);
    let (store, writes) = make_store(state);
    DeliberationCommands::new(&store)
        .synthesize(
            command_for_phase("task-1", 7, "core", Phase::Synthesis),
            decision(claim("claim-a", true)),
            artifact("plan-1", '4'),
            1,
        )
        .unwrap();
    assert_record_event(&writes, "decision.draft.created", true);

    let (store, writes) = make_store(snapshot(Phase::FinalObjection));
    DeliberationCommands::new(&store)
        .record_objection_set(
            command_for_phase("task-1", 7, "core", Phase::FinalObjection),
            FinalObjectionSet::new(1, Vec::new()).unwrap(),
        )
        .unwrap();
    assert_record_event(&writes, "objection.set.created", false);

    let state = snapshot_with_objection_set(ObjectionSeverity::Severe);
    let (store, writes) = make_store(state);
    DeliberationCommands::new(&store)
        .accept_severe_objection(
            command_for_phase("task-1", 7, "core", Phase::FinalObjection),
            review_plan_for_round(2),
        )
        .unwrap();
    assert_record_event(&writes, "objection.severe.accepted", true);

    let (store, writes) = make_store(snapshot_with_objection_set(ObjectionSeverity::Low));
    let authority = FixedPlanApprovalAuthority {
        binding: PlanApprovalAuthorityBinding::issue(plan_approval_binding()).unwrap(),
    };
    DeliberationCommands::with_plan_approval_authority(&store, &authority)
        .close_objection_round(
            command_for_phase("task-1", 7, "core", Phase::FinalObjection),
            plan_approval_request(),
        )
        .unwrap();
    assert_record_event(&writes, "objection.round.closed", true);

    let (store, writes) = make_store(snapshot_for_reopened_synthesis());
    DeliberationCommands::new(&store)
        .record_supersession(
            command_for_phase("task-1", 10, "core", Phase::Synthesis),
            artifact("decision-draft-1", '5'),
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
            ActorId::new("agent-1").unwrap(),
            artifact("artifact-record-1", '9'),
            EventId::new("event-1").unwrap(),
            "correlation-1",
            "2026-08-09T00:00:00Z",
        )
        .unwrap();
        assert!(DeliberationCommands::new(&store)
            .record_private_proposal(context, proposal(3), artifact("proposal-3", '7'))
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

fn rejected_without_writes(result: Result<(), PortError>, writes: &Arc<Mutex<Writes>>) -> bool {
    result.is_err() && writes.lock().unwrap().commands.is_empty()
}

fn assert_event_authority(
    writes: &Arc<Mutex<Writes>>,
    actor_type: &str,
    actor_id: &str,
    observation_class: &str,
) {
    let writes = writes.lock().unwrap();
    let event = &writes.commands.last().unwrap().append().events[0];
    assert_eq!(event.actor_type, actor_type);
    assert_eq!(event.actor_id.as_str(), actor_id);
    assert_eq!(event.observation_class, observation_class);
    assert_ne!(event.observation_class, "agent_asserted");
}

fn snapshot(phase: Phase) -> DeliberationSnapshot {
    let mut facts = Vec::new();
    if !matches!(phase, Phase::ContextBuild | Phase::ParallelAnalysis) {
        facts.extend([
            private_fact(proposal(1), 1),
            private_fact(proposal(2), 2),
            quorum_publication_fact(3),
        ]);
        if phase != Phase::CrossReview {
            facts.push(claim_set_fact_for(vec![claim("claim-a", false)], 4));
        }
        if !matches!(
            phase,
            Phase::ContextBuild
                | Phase::ParallelAnalysis
                | Phase::CrossReview
                | Phase::PrePlanVerification
        ) {
            facts.push(verification_set_fact_for(vec![claim("claim-a", true)], 5));
        }
        if !matches!(
            phase,
            Phase::ContextBuild
                | Phase::ParallelAnalysis
                | Phase::CrossReview
                | Phase::PrePlanVerification
                | Phase::Synthesis
        ) {
            facts.push(decision_draft_fact_for(decision(claim("claim-a", true)), 6));
        }
        if !matches!(
            phase,
            Phase::CrossReview
                | Phase::PrePlanVerification
                | Phase::Synthesis
                | Phase::FinalObjection
        ) {
            facts.push(
                CanonicalDeliberationFact::issue(
                    TaskId::new("task-1").unwrap(),
                    EventId::new("event-later-phase").unwrap(),
                    7,
                    ActorId::new("core").unwrap(),
                    DeliberationRecord::Supersession {
                        superseded: artifact("artifact-superseded", 'e'),
                        replacement: artifact("artifact-replacement", 'f'),
                    },
                )
                .unwrap(),
            );
        }
    }
    recover_deliberation(DeliberationRecoveryInput {
        task_id: TaskId::new("task-1").unwrap(),
        task_version: 7,
        task_state: authoritative_state(phase, 7),
        run_assignments: vec![run_assignment(1), run_assignment(2)],
        facts,
    })
    .unwrap()
}

fn snapshot_with_unclassified_claims(claims: Vec<MaterialClaim>) -> DeliberationSnapshot {
    let mut facts = published_facts();
    facts.push(claim_set_fact_for(claims, 4));
    recover_history_snapshot(Phase::PrePlanVerification, facts)
}

fn snapshot_with_verified_claims(claims: Vec<MaterialClaim>) -> DeliberationSnapshot {
    let unclassified = claims
        .iter()
        .map(|claim| {
            MaterialClaim::new(
                claim.claim_id(),
                claim.claimant(),
                claim.artifact_id().clone(),
                claim.citations().to_vec(),
                claim.method(),
            )
            .unwrap()
        })
        .collect();
    let mut facts = published_facts();
    facts.push(claim_set_fact_for(unclassified, 4));
    facts.push(verification_set_fact_for(claims, 5));
    recover_history_snapshot(Phase::Synthesis, facts)
}

fn snapshot_with_specialist_request() -> DeliberationSnapshot {
    recover_history_snapshot(
        Phase::ParallelAnalysis,
        vec![CanonicalDeliberationFact::issue(
            TaskId::new("task-1").unwrap(),
            EventId::new("event-specialist-1").unwrap(),
            1,
            ActorId::new("agent-1").unwrap(),
            DeliberationRecord::SpecialistRequest {
                request: specialist_request(),
                artifact: artifact("specialist-request-1", '2'),
            },
        )
        .unwrap()],
    )
}

fn snapshot_with_review_edges() -> DeliberationSnapshot {
    let mut facts = published_facts();
    facts.push(
        CanonicalDeliberationFact::issue(
            TaskId::new("task-1").unwrap(),
            EventId::new("event-review-edges").unwrap(),
            4,
            ActorId::new("core").unwrap(),
            DeliberationRecord::ReviewEdges {
                plan: review_plan(),
                artifact: artifact("artifact-record-1", '9'),
            },
        )
        .unwrap(),
    );
    recover_history_snapshot(Phase::CrossReview, facts)
}

fn snapshot_with_thread_summary() -> DeliberationSnapshot {
    let mut facts = published_facts();
    facts.push(
        CanonicalDeliberationFact::issue(
            TaskId::new("task-1").unwrap(),
            EventId::new("event-thread-summary").unwrap(),
            4,
            ActorId::new("core").unwrap(),
            DeliberationRecord::ThreadSummary {
                thread_id: "thread-1".to_owned(),
                artifact: artifact("thread-summary-1", '1'),
            },
        )
        .unwrap(),
    );
    recover_history_snapshot(Phase::CrossReview, facts)
}

fn snapshot_with_objection_set(severity: ObjectionSeverity) -> DeliberationSnapshot {
    let mut facts = published_facts();
    facts.extend([
        claim_set_fact_for(vec![claim("claim-a", false)], 4),
        verification_set_fact_for(vec![claim("claim-a", true)], 5),
        decision_draft_fact_for(decision(claim("claim-a", true)), 6),
        CanonicalDeliberationFact::issue(
            TaskId::new("task-1").unwrap(),
            EventId::new("event-objection-set-1").unwrap(),
            7,
            ActorId::new("core").unwrap(),
            DeliberationRecord::ObjectionSet {
                objections: objection_set(1, severity),
                artifact: artifact("objection-set-1", '6'),
            },
        )
        .unwrap(),
    ]);
    recover_history_snapshot_at(Phase::FinalObjection, 7, facts)
}

fn snapshot_for_reopened_synthesis() -> DeliberationSnapshot {
    let mut facts = lifecycle_facts_to_severe_acceptance(
        review_plan_for_round(2),
        artifact("review-plan-2", '7'),
    );
    facts.extend([
        claim_set_fact_for_round("event-claim-set-2", vec![claim("claim-a", false)], 9, 2),
        verification_set_fact_for_round(
            "event-verification-set-2",
            vec![claim("claim-a", true)],
            10,
            2,
        ),
    ]);
    recover_history_snapshot_at(Phase::Synthesis, 10, facts)
}

fn published_facts() -> Vec<CanonicalDeliberationFact> {
    vec![
        private_fact(proposal(1), 1),
        private_fact(proposal(2), 2),
        quorum_publication_fact(3),
    ]
}

fn recover_history_snapshot(
    phase: Phase,
    facts: Vec<CanonicalDeliberationFact>,
) -> DeliberationSnapshot {
    recover_history_snapshot_at(phase, 7, facts)
}

fn recover_history_snapshot_at(
    phase: Phase,
    task_version: u64,
    facts: Vec<CanonicalDeliberationFact>,
) -> DeliberationSnapshot {
    recover_deliberation(DeliberationRecoveryInput {
        task_id: TaskId::new("task-1").unwrap(),
        task_version,
        task_state: authoritative_state(phase, task_version),
        run_assignments: vec![run_assignment(1), run_assignment(2)],
        facts,
    })
    .unwrap()
}

fn lifecycle_facts_to_severe_acceptance(
    reopen_plan: ReviewPlan,
    review_artifact: DeliberationArtifactRef,
) -> Vec<CanonicalDeliberationFact> {
    let severe_objections = objection_set(1, ObjectionSeverity::Severe);
    let objection_artifact = artifact("objection-set-1", '6');
    let mut facts = published_facts();
    facts.extend([
        claim_set_fact_for(vec![claim("claim-a", false)], 4),
        verification_set_fact_for(vec![claim("claim-a", true)], 5),
        decision_draft_fact_for(decision(claim("claim-a", true)), 6),
        CanonicalDeliberationFact::issue(
            TaskId::new("task-1").unwrap(),
            EventId::new("event-objection-set-1").unwrap(),
            7,
            ActorId::new("core").unwrap(),
            DeliberationRecord::ObjectionSet {
                objections: severe_objections.clone(),
                artifact: objection_artifact.clone(),
            },
        )
        .unwrap(),
        CanonicalDeliberationFact::issue(
            TaskId::new("task-1").unwrap(),
            EventId::new("event-severe-accepted-1").unwrap(),
            8,
            ActorId::new("core").unwrap(),
            DeliberationRecord::ObjectionSevereAccepted {
                objections: severe_objections,
                objection_artifact,
                review_plan: reopen_plan,
                review_artifact,
            },
        )
        .unwrap(),
    ]);
    facts
}

fn review_edges_fact_for(
    event_id: &str,
    event_sequence: u64,
    plan: ReviewPlan,
    artifact: DeliberationArtifactRef,
) -> CanonicalDeliberationFact {
    CanonicalDeliberationFact::issue(
        TaskId::new("task-1").unwrap(),
        EventId::new(event_id).unwrap(),
        event_sequence,
        ActorId::new("core").unwrap(),
        DeliberationRecord::ReviewEdges { plan, artifact },
    )
    .unwrap()
}

fn claim_set_fact_for_round(
    event_id: &str,
    claims: Vec<MaterialClaim>,
    event_sequence: u64,
    round: u32,
) -> CanonicalDeliberationFact {
    CanonicalDeliberationFact::issue(
        TaskId::new("task-1").unwrap(),
        EventId::new(event_id).unwrap(),
        event_sequence,
        ActorId::new("core").unwrap(),
        DeliberationRecord::ClaimSet {
            claims,
            artifact: artifact(&format!("claim-set-{round}"), '3'),
        },
    )
    .unwrap()
}

fn verification_set_fact_for_round(
    event_id: &str,
    claims: Vec<MaterialClaim>,
    event_sequence: u64,
    round: u32,
) -> CanonicalDeliberationFact {
    CanonicalDeliberationFact::issue(
        TaskId::new("task-1").unwrap(),
        EventId::new(event_id).unwrap(),
        event_sequence,
        ActorId::new("core").unwrap(),
        DeliberationRecord::VerificationSet {
            claims,
            artifact: artifact(&format!("verification-set-{round}"), '4'),
        },
    )
    .unwrap()
}

fn supersession_fact_for(
    event_sequence: u64,
    superseded: DeliberationArtifactRef,
    replacement: DeliberationArtifactRef,
) -> CanonicalDeliberationFact {
    CanonicalDeliberationFact::issue(
        TaskId::new("task-1").unwrap(),
        EventId::new("event-supersession-1").unwrap(),
        event_sequence,
        ActorId::new("core").unwrap(),
        DeliberationRecord::Supersession {
            superseded,
            replacement,
        },
    )
    .unwrap()
}

fn unpublished_snapshot() -> DeliberationSnapshot {
    let retry = IndependentProposal::new(
        TaskId::new("task-1").unwrap(),
        RunId::new("run-3").unwrap(),
        "agent-1",
        local_agent_terminal_domain::AgentFamilyKey::new("family-1").unwrap(),
        ArtifactId::new("proposal-3").unwrap(),
        vec![citation()],
    )
    .unwrap();
    recover_deliberation(DeliberationRecoveryInput {
        task_id: TaskId::new("task-1").unwrap(),
        task_version: 7,
        task_state: authoritative_state(Phase::ParallelAnalysis, 7),
        run_assignments: vec![
            run_assignment(1),
            run_assignment(2),
            DeliberationRunAssignment::new(
                RunId::new("run-3").unwrap(),
                "agent-1",
                local_agent_terminal_domain::AgentFamilyKey::new("family-1").unwrap(),
                ActorId::new("agent-1").unwrap(),
            )
            .unwrap(),
        ],
        facts: vec![
            private_fact(proposal(1), 1),
            private_fact(proposal(2), 2),
            private_fact(retry, 3),
        ],
    })
    .unwrap()
}

fn private_fact(proposal: IndependentProposal, event_sequence: u64) -> CanonicalDeliberationFact {
    let number = proposal.run_id().as_str().trim_start_matches("run-");
    CanonicalDeliberationFact::issue(
        TaskId::new("task-1").unwrap(),
        EventId::new(format!("event-private-{number}")).unwrap(),
        event_sequence,
        ActorId::new(proposal.agent_id()).unwrap(),
        DeliberationRecord::PrivateProposal {
            proposal: proposal.clone(),
            proposal_artifact: DeliberationArtifactRef::new(
                proposal.artifact_id().clone(),
                digest('7'),
                17,
            )
            .unwrap(),
            receipt: artifact(&format!("receipt-{number}"), '6'),
        },
    )
    .unwrap()
}

fn quorum_publication_fact(event_sequence: u64) -> CanonicalDeliberationFact {
    CanonicalDeliberationFact::issue(
        TaskId::new("task-1").unwrap(),
        EventId::new("event-quorum-publication").unwrap(),
        event_sequence,
        ActorId::new("core").unwrap(),
        DeliberationRecord::QuorumPublication {
            proposals: IndependentQuorum::new(vec![proposal(1), proposal(2)])
                .unwrap()
                .reveal(),
            proposal_artifact: artifact("proposal-bundle-1", '8'),
            review_plan: review_plan(),
            review_artifact: artifact("artifact-record-1", '9'),
        },
    )
    .unwrap()
}

fn claim_set_fact_for(
    claims: Vec<MaterialClaim>,
    event_sequence: u64,
) -> CanonicalDeliberationFact {
    CanonicalDeliberationFact::issue(
        TaskId::new("task-1").unwrap(),
        EventId::new("event-claim-set").unwrap(),
        event_sequence,
        ActorId::new("core").unwrap(),
        DeliberationRecord::ClaimSet {
            claims,
            artifact: artifact("claim-set-1", '3'),
        },
    )
    .unwrap()
}

fn verification_set_fact_for(
    claims: Vec<MaterialClaim>,
    event_sequence: u64,
) -> CanonicalDeliberationFact {
    CanonicalDeliberationFact::issue(
        TaskId::new("task-1").unwrap(),
        EventId::new("event-verification-set").unwrap(),
        event_sequence,
        ActorId::new("core").unwrap(),
        DeliberationRecord::VerificationSet {
            claims,
            artifact: artifact("verification-set-1", '4'),
        },
    )
    .unwrap()
}

fn decision_draft_fact_for(
    decision: DecisionPackage,
    event_sequence: u64,
) -> CanonicalDeliberationFact {
    CanonicalDeliberationFact::issue(
        TaskId::new("task-1").unwrap(),
        EventId::new("event-decision-draft").unwrap(),
        event_sequence,
        ActorId::new("core").unwrap(),
        DeliberationRecord::DecisionDraft {
            decision,
            artifact: artifact("decision-draft-1", '5'),
            plan_artifact: artifact("plan-1", '4'),
            plan_version: 1,
        },
    )
    .unwrap()
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

fn command_for_phase_with_artifact(
    task: &str,
    version: u64,
    actor: &str,
    phase: Phase,
    record_artifact: DeliberationArtifactRef,
) -> DeliberationCommandContext {
    DeliberationCommandContext::new(
        TaskId::new(task).unwrap(),
        version,
        authoritative_state(phase, version),
        ActorId::new(actor).unwrap(),
        record_artifact,
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

fn multi_reviewer_plan() -> ReviewPlan {
    ReviewPlan::new(
        DeliberationLimits::new(3, 2, 4, 2).unwrap(),
        vec![
            ReviewEdge::new("agent-2", ArtifactId::new("proposal-1").unwrap(), 1).unwrap(),
            ReviewEdge::new("agent-3", ArtifactId::new("proposal-1").unwrap(), 1).unwrap(),
            ReviewEdge::new("agent-1", ArtifactId::new("proposal-2").unwrap(), 1).unwrap(),
        ],
    )
    .unwrap()
}

fn review_plan_for_round(round: u32) -> ReviewPlan {
    ReviewPlan::new(
        DeliberationLimits::new(4, round.max(2), 8, 2).unwrap(),
        vec![
            ReviewEdge::new("agent-2", ArtifactId::new("proposal-1").unwrap(), round).unwrap(),
            ReviewEdge::new("agent-1", ArtifactId::new("proposal-2").unwrap(), round).unwrap(),
        ],
    )
    .unwrap()
}

fn review_plan_with(reviewer: &str, target: &str, round: u32) -> ReviewPlan {
    ReviewPlan::new(
        DeliberationLimits::new(4, round.max(2), 8, 2).unwrap(),
        vec![
            ReviewEdge::new(reviewer, ArtifactId::new(target).unwrap(), round).unwrap(),
            ReviewEdge::new("agent-1", ArtifactId::new("proposal-2").unwrap(), round).unwrap(),
        ],
    )
    .unwrap()
}

fn objection_set(round: u32, severity: ObjectionSeverity) -> FinalObjectionSet {
    FinalObjectionSet::new(
        round,
        vec![FinalObjection::new(
            "agent-1",
            round,
            severity,
            "material reopening condition",
            vec![citation()],
            (severity == ObjectionSeverity::Severe).then_some("workspace isolation requirement"),
        )
        .unwrap()],
    )
    .unwrap()
}

fn run_assignment(number: u8) -> DeliberationRunAssignment {
    DeliberationRunAssignment::new(
        RunId::new(format!("run-{number}")).unwrap(),
        format!("agent-{number}"),
        local_agent_terminal_domain::AgentFamilyKey::new(format!("family-{number}")).unwrap(),
        ActorId::new(format!("agent-{number}")).unwrap(),
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
        plan_digest: digest('4').as_str().to_owned(),
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
    let (actor_type, actor_id, observation_class) = match event_type {
        "agent.message.created" | "specialist.requested" => ("agent", "agent-1", "agent_claimed"),
        _ => ("core", "core", "core_observed"),
    };
    let event = &command.append().events[0];
    assert_eq!(event.actor_type, actor_type);
    assert_eq!(event.actor_id.as_str(), actor_id);
    assert_eq!(event.observation_class, observation_class);
    assert_ne!(event.observation_class, "agent_asserted");
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
    decision_with_claims_for_plan(verified_claims, "plan-1")
}

fn decision_for_plan(verified_claim: MaterialClaim, plan_id: &str) -> DecisionPackage {
    decision_with_claims_for_plan(vec![verified_claim], plan_id)
}

fn decision_with_claims_for_plan(
    verified_claims: Vec<MaterialClaim>,
    plan_id: &str,
) -> DecisionPackage {
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
        ArtifactId::new(plan_id).unwrap(),
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
