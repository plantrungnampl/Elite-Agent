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
