
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
fn exact_authoritative_state_rejects_all_v3_axis_substitution() {
    let snapshot = snapshot(Phase::ParallelAnalysis);
    let task_state_snapshot = snapshot.task_state.snapshot();
    let hostile_states = [
        WorkflowState::rehydrate(WorkflowStateSnapshot {
            condition: Condition::Paused,
            ..task_state_snapshot.clone()
        })
        .unwrap(),
        WorkflowState::rehydrate(WorkflowStateSnapshot {
            operation: OperationState::Running,
            ..task_state_snapshot.clone()
        })
        .unwrap(),
        WorkflowState::rehydrate(WorkflowStateSnapshot {
            workspace_version: 2,
            ..task_state_snapshot.clone()
        })
        .unwrap(),
        WorkflowState::rehydrate(WorkflowStateSnapshot {
            fencing_epoch: 2,
            ..task_state_snapshot.clone()
        })
        .unwrap(),
        WorkflowState::rehydrate(WorkflowStateSnapshot {
            workflow_profile: WorkflowProfile::Quick,
            ..task_state_snapshot.clone()
        })
        .unwrap(),
        WorkflowState::rehydrate(WorkflowStateSnapshot {
            outcome_mode: TaskOutcomeMode::ReadOnlyDeliverable,
            ..task_state_snapshot
        })
        .unwrap(),
    ];

    for hostile_state in hostile_states {
        let (store, writes) = make_store(snapshot.clone());
        let context = DeliberationCommandContext::new(
            TaskId::new("task-1").unwrap(),
            7,
            hostile_state,
            task_budget(),
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
        task_budget(),
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
        task_budget(),
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
        task_budget(),
        ActorId::new(actor).unwrap(),
        record_artifact,
        EventId::new("event-1").unwrap(),
        "correlation-1",
        "2026-08-09T00:00:00Z",
    )
    .unwrap()
}

fn authoritative_state(phase: Phase, sequence: u64) -> WorkflowState {
    WorkflowState::rehydrate(WorkflowStateSnapshot {
        phase,
        condition: Condition::Active,
        operation: OperationState::None,
        workflow_profile: WorkflowProfile::Standard,
        outcome_mode: TaskOutcomeMode::WorkspaceChange,
        stream_version: sequence,
        profile_revision: 1,
        workspace_version: 1,
        fencing_epoch: 1,
        last_transition_event_id: Some("transition-7".to_owned()),
        last_profile_revision_id: Some("profile-revision-1".to_owned()),
    })
    .unwrap()
}

fn command_with_budget(
    phase: Phase,
    actor: &str,
    budget: DeliberationTaskBudget,
    occurred_at: &str,
) -> DeliberationCommandContext {
    DeliberationCommandContext::new(
        TaskId::new("task-1").unwrap(),
        7,
        authoritative_state(phase, 7),
        budget,
        ActorId::new(actor).unwrap(),
        artifact("artifact-record-1", '9'),
        EventId::new("event-1").unwrap(),
        "correlation-1",
        occurred_at,
    )
    .unwrap()
}

fn task_budget() -> DeliberationTaskBudget {
    DeliberationTaskBudget::new(
        64,
        1_000_000,
        1_000_000_000_000,
        Timestamp::from_unix_seconds(2_000_000_000),
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
    specialist_request_with_id("specialist-1")
}

fn specialist_request_with_id(request_id: &str) -> SpecialistRequest {
    SpecialistRequest::new(
        request_id,
        TaskId::new("task-1").unwrap(),
        RunId::new("run-1").unwrap(),
        "repository-analysis",
        "inspect repository invariants",
        vec![ArtifactId::new("context-1").unwrap()],
        SpecialistBudget::new(512, 5_120, Timestamp::from_unix_seconds(1_800_000_000)).unwrap(),
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
