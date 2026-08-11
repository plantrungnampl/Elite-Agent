use local_agent_terminal_application::{
    canonical_plan_approval_payload, recover_deliberation, ApprovalId, CanonicalDeliberationFact,
    DeliberationArtifactRef, DeliberationRecord, DeliberationRecoveryInput,
    DeliberationRunAssignment, NewPlanApproval, NewPlanApprovalRehydration,
    PlanApprovalAuthorityBinding, PlanApprovalBindingInput, PlanApprovalPathScopeV1,
    PlanApprovalRequestArtifact,
};
use local_agent_terminal_domain::{
    ActorId, ArtifactId, ClaimVerification, Condition, DecisionApproach, DecisionPackage,
    DeliberationLimits, Dissent, EventId, FencingToken, FinalObjection, FinalObjectionSet,
    IndependentProposal, IndependentQuorum, MaterialClaim, ObjectionSeverity, OperationState,
    Phase, RejectedApproach, ReviewEdge, ReviewPlan, RunId, Sequence, Sha256Digest,
    SpecialistBudget, SpecialistRequest, TaskId, Timestamp, VerificationMethod, WorkflowState,
    WorkspaceVersion,
};
use sha2::{Digest, Sha256};

#[test]
fn zero_record_recovery_is_valid_without_inventing_quorum_or_authority() {
    let recovered = recover_deliberation(DeliberationRecoveryInput {
        task_id: task_id(),
        task_version: 7,
        task_state: state(Phase::ParallelAnalysis, 7),
        run_assignments: vec![
            assignment("run-1", "agent-1", "family-1", "agent-1"),
            assignment("run-2", "agent-2", "family-2", "agent-2"),
        ],
        facts: Vec::new(),
    })
    .unwrap();

    assert!(recovered.private_proposals().is_empty());
    assert!(recovered.quorum().is_none());
    assert!(recovered.plan_approval().is_none());
}

#[test]
fn canonical_fact_round_trips_exact_task_event_record_and_artifact_refs() {
    let proposal = IndependentProposal::new(
        task_id(),
        RunId::new("run-1").unwrap(),
        "agent-1",
        local_agent_terminal_domain::AgentFamilyKey::new("family-1").unwrap(),
        ArtifactId::new("proposal-1").unwrap(),
        vec![citation()],
    )
    .unwrap();
    let record = DeliberationRecord::PrivateProposal {
        proposal,
        proposal_artifact: artifact("proposal-1", 'c'),
        receipt: artifact("receipt-1", 'a'),
    };
    let issued = CanonicalDeliberationFact::issue(
        task_id(),
        EventId::new("event-1").unwrap(),
        3,
        ActorId::new("agent-1").unwrap(),
        record,
    )
    .unwrap();

    let reopened = CanonicalDeliberationFact::rehydrate(
        issued.canonical_bytes().to_vec(),
        issued.content_digest().clone(),
    )
    .unwrap();

    assert_eq!(reopened, issued);
    assert_eq!(reopened.task_id(), &task_id());
    assert_eq!(reopened.event_id().as_str(), "event-1");
    assert_eq!(reopened.event_sequence(), 3);
    assert!(matches!(
        reopened.record(),
        DeliberationRecord::PrivateProposal {
            proposal,
            proposal_artifact,
            receipt,
        }
            if proposal.run_id().as_str() == "run-1"
                && proposal.agent_id() == "agent-1"
                && proposal.family().as_str() == "family-1"
                && proposal.artifact_id().as_str() == "proposal-1"
                && proposal_artifact.artifact_id().as_str() == "proposal-1"
                && proposal_artifact.content_digest() == &digest('c')
                && proposal_artifact.size_bytes() == 17
                && receipt.artifact_id().as_str() == "receipt-1"
                && receipt.content_digest() == &digest('a')
                && receipt.size_bytes() == 17
    ));
}

#[test]
fn recovery_rejects_private_proposal_without_exact_verified_assignment() {
    let fact = private_proposal_fact();
    let mismatches = [
        assignment("run-2", "agent-1", "family-1", "agent-1"),
        assignment("run-1", "agent-2", "family-1", "agent-2"),
        assignment("run-1", "agent-1", "family-2", "agent-1"),
        assignment("run-1", "agent-1", "family-1", "actor-1"),
    ];

    for mismatch in mismatches {
        assert!(recover_deliberation(DeliberationRecoveryInput {
            task_id: task_id(),
            task_version: 7,
            task_state: state(Phase::ParallelAnalysis, 7),
            run_assignments: vec![mismatch],
            facts: vec![fact.clone()],
        })
        .is_err());
    }
}

#[test]
fn recovery_rejects_duplicate_run_assignments() {
    assert!(recover_deliberation(DeliberationRecoveryInput {
        task_id: task_id(),
        task_version: 7,
        task_state: state(Phase::ParallelAnalysis, 7),
        run_assignments: vec![
            assignment("run-1", "agent-1", "family-1", "agent-1"),
            assignment("run-1", "agent-2", "family-2", "agent-2"),
        ],
        facts: Vec::new(),
    })
    .is_err());
}

#[test]
fn recovery_allows_retry_assignments_to_reuse_agent_and_family() {
    let recovered = recover_deliberation(DeliberationRecoveryInput {
        task_id: task_id(),
        task_version: 7,
        task_state: state(Phase::ParallelAnalysis, 7),
        run_assignments: vec![
            assignment("run-1", "agent-1", "family-1", "agent-1"),
            assignment("run-2", "agent-1", "family-1", "agent-1"),
        ],
        facts: Vec::new(),
    })
    .unwrap();

    assert!(recovered.private_proposals().is_empty());
}

#[test]
fn recovery_replays_private_proposals_and_exact_published_quorum_with_gaps() {
    let facts = vec![
        private_proposal_fact_for(1, "event-private-1", 1),
        private_proposal_fact_for(2, "event-private-2", 3),
        retry_private_proposal_fact("event-private-retry", 4),
        quorum_fact(quorum_proposals(), "event-quorum-replay-1", 5),
    ];
    let recovered = recover_deliberation(DeliberationRecoveryInput {
        task_id: task_id(),
        task_version: 7,
        task_state: state(Phase::CrossReview, 7),
        run_assignments: vec![
            assignment("run-1", "agent-1", "family-1", "agent-1"),
            assignment("run-2", "agent-2", "family-2", "agent-2"),
            assignment("run-3", "agent-1", "family-1", "agent-1"),
        ],
        facts,
    })
    .unwrap();

    assert_eq!(recovered.private_proposals().len(), 3);
    assert!(recovered
        .private_proposals()
        .iter()
        .all(|record| !record.proposal().is_revealed()));
    let retry = &recovered.private_proposals()[2];
    assert_eq!(retry.proposal().run_id().as_str(), "run-3");
    assert_eq!(retry.proposal().agent_id(), "agent-1");
    assert_eq!(retry.proposal().family().as_str(), "family-1");
    assert_eq!(retry.proposal_artifact(), &artifact("proposal-3", 'f'));
    assert_eq!(retry.receipt(), &artifact("receipt-3", 'a'));
    let quorum = recovered.quorum().unwrap();
    assert_eq!(quorum.proposals(), quorum_proposals());
    assert!(quorum
        .proposals()
        .iter()
        .all(IndependentProposal::is_revealed));
    assert_eq!(recovered.review_plan(), Some(&review_plan()));
    let publication = recovered.quorum_publication().unwrap();
    assert_eq!(publication.event_id().as_str(), "event-quorum-replay-1");
    assert_eq!(publication.event_sequence(), 5);
    assert_eq!(
        publication.proposal_artifact(),
        &artifact("proposal-bundle-1", 'd')
    );
    assert_eq!(
        publication.review_artifact(),
        &artifact("review-plan-1", 'e')
    );
}

#[test]
fn recovery_allows_specialist_request_between_private_proposals_before_publication() {
    let request = specialist_request();
    let recovered = recover_deliberation(DeliberationRecoveryInput {
        task_id: task_id(),
        task_version: 7,
        task_state: state(Phase::CrossReview, 7),
        run_assignments: vec![
            assignment("run-1", "agent-1", "family-1", "agent-1"),
            assignment("run-2", "agent-2", "family-2", "agent-2"),
        ],
        facts: vec![
            private_proposal_fact_for(1, "event-private-1", 1),
            specialist_request_fact(request.clone(), "event-specialist-1", 2),
            private_proposal_fact_for(2, "event-private-2", 3),
            quorum_fact(quorum_proposals(), "event-quorum-1", 4),
        ],
    })
    .unwrap();

    assert_eq!(recovered.private_proposals().len(), 2);
    let specialist = &recovered.specialist_requests()[0];
    assert_eq!(specialist.request(), &request);
    assert_eq!(
        specialist.artifact(),
        &artifact("specialist-request-1", '2')
    );
    assert_eq!(specialist.event_id().as_str(), "event-specialist-1");
    assert_eq!(specialist.event_sequence(), 2);
    assert_eq!(specialist.actor_id().as_str(), "agent-1");
    assert!(recovered.quorum().is_some());
}

#[test]
fn recovery_rejects_specialist_request_without_exact_requesting_run_actor_assignment() {
    let fact = specialist_request_fact(specialist_request(), "event-specialist-1", 1);
    for assignment in [
        assignment("run-2", "agent-1", "family-1", "agent-1"),
        assignment("run-1", "agent-2", "family-2", "agent-2"),
    ] {
        assert!(recover_deliberation(DeliberationRecoveryInput {
            task_id: task_id(),
            task_version: 7,
            task_state: state(Phase::ParallelAnalysis, 7),
            run_assignments: vec![assignment],
            facts: vec![fact.clone()],
        })
        .is_err());
    }
}

#[test]
fn quorum_target_set_allows_multiple_reviewers_for_one_selected_proposal() {
    let plan = multi_reviewer_plan();
    let recovered = recover_deliberation(DeliberationRecoveryInput {
        task_id: task_id(),
        task_version: 7,
        task_state: state(Phase::CrossReview, 7),
        run_assignments: vec![
            assignment("run-1", "agent-1", "family-1", "agent-1"),
            assignment("run-2", "agent-2", "family-2", "agent-2"),
            assignment("run-3", "agent-3", "family-3", "agent-3"),
        ],
        facts: vec![
            private_proposal_fact_for(1, "event-private-1", 1),
            private_proposal_fact_for(2, "event-private-2", 2),
            quorum_fact_with_plan(quorum_proposals(), plan.clone(), "event-quorum-1", 3),
        ],
    })
    .unwrap();

    assert_eq!(recovered.review_plan(), Some(&plan));
    assert_eq!(recovered.quorum().unwrap().proposals(), quorum_proposals());
}

#[test]
fn recovery_retains_exact_review_edge_and_thread_summary_history() {
    let recovered = recover_deliberation(DeliberationRecoveryInput {
        task_id: task_id(),
        task_version: 7,
        task_state: state(Phase::CrossReview, 7),
        run_assignments: vec![
            assignment("run-1", "agent-1", "family-1", "agent-1"),
            assignment("run-2", "agent-2", "family-2", "agent-2"),
        ],
        facts: vec![
            private_proposal_fact_for(1, "event-private-1", 1),
            private_proposal_fact_for(2, "event-private-2", 2),
            quorum_fact(quorum_proposals(), "event-quorum-1", 3),
            review_edges_fact("event-review-1", 4),
            thread_summary_fact("thread-1", "event-thread-1", 5),
        ],
    })
    .unwrap();

    let review = recovered.review_edges().unwrap();
    assert_eq!(review.plan(), &review_plan());
    assert_eq!(review.artifact(), &artifact("review-plan-1", 'e'));
    assert_eq!(review.event_id().as_str(), "event-review-1");
    assert_eq!(review.event_sequence(), 4);
    assert_eq!(review.actor_id().as_str(), "core");
    let thread = &recovered.thread_summaries()[0];
    assert_eq!(thread.thread_id(), "thread-1");
    assert_eq!(thread.artifact(), &artifact("thread-summary-1", '1'));
    assert_eq!(thread.event_id().as_str(), "event-thread-1");
    assert_eq!(thread.event_sequence(), 5);
    assert_eq!(thread.actor_id().as_str(), "core");
}

#[test]
fn recovery_replays_exact_claim_verification_and_decision_boundaries() {
    let recovered = recover_deliberation(DeliberationRecoveryInput {
        task_id: task_id(),
        task_version: 7,
        task_state: state(Phase::FinalObjection, 7),
        run_assignments: vec![
            assignment("run-1", "agent-1", "family-1", "agent-1"),
            assignment("run-2", "agent-2", "family-2", "agent-2"),
        ],
        facts: lifecycle_facts_to_decision(),
    })
    .unwrap();

    let claim_set = recovered.claim_set().unwrap();
    assert_eq!(claim_set.claims(), unclassified_claims());
    assert_eq!(claim_set.artifact(), &artifact("claim-set-1", '3'));
    assert_eq!(claim_set.event_sequence(), 4);
    let verification = recovered.verification_set().unwrap();
    assert_eq!(verification.claims(), classified_claims());
    assert_eq!(
        verification.artifact(),
        &artifact("verification-set-1", '4')
    );
    assert_eq!(recovered.claims(), classified_claims());
    let decision = &recovered.decision_drafts()[0];
    assert_eq!(decision.decision(), &decision_package());
    assert_eq!(decision.artifact(), &artifact("decision-record-1", '5'));
    assert_eq!(decision.plan_artifact(), &artifact("plan-1", '4'));
    assert_eq!(decision.plan_version(), 3);
    assert_eq!(decision.event_sequence(), 6);
}

#[test]
fn recovery_replays_severe_objection_reopen_supersession_and_close_exactly() {
    let first_objections = objection_set_for(1, ObjectionSeverity::Severe);
    let second_objections = objection_set_for(2, ObjectionSeverity::Low);
    let reopen_plan = reopen_review_plan(2);
    let approval = plan_approval_for("task-1", 14, "plan-2", '4', 2);
    let mut facts = lifecycle_facts_to_decision();
    facts.extend([
        objection_set_fact(
            "event-objections-1",
            7,
            first_objections.clone(),
            artifact("objection-set-1", '6'),
        ),
        severe_acceptance_fact(
            "event-severe-accepted-1",
            8,
            first_objections.clone(),
            artifact("objection-set-1", '6'),
            reopen_plan.clone(),
            artifact("review-plan-2", '7'),
        ),
        review_edges_fact_with(
            reopen_plan,
            artifact("review-plan-2", '7'),
            "event-review-edges-2",
            9,
        ),
        claim_set_fact_for_round("event-claims-2", 10, 2),
        verification_set_fact_for_round("event-verification-2", 11, 2),
        supersession_fact(
            "event-supersession-1",
            12,
            artifact("decision-record-1", '5'),
            artifact("decision-record-2", '8'),
        ),
        decision_draft_fact_for_round("event-decision-2", 13, 2),
        objection_set_fact(
            "event-objections-2",
            14,
            second_objections.clone(),
            artifact("objection-set-2", '9'),
        ),
        objection_round_closed_fact("event-objection-closed-1", 15, approval.clone()),
    ]);

    let recovered = recover_deliberation(DeliberationRecoveryInput {
        task_id: task_id(),
        task_version: 15,
        task_state: state(Phase::AwaitingPlanApproval, 15),
        run_assignments: vec![
            assignment("run-1", "agent-1", "family-1", "agent-1"),
            assignment("run-2", "agent-2", "family-2", "agent-2"),
        ],
        facts,
    })
    .unwrap();

    assert_eq!(recovered.claim_sets().len(), 2);
    assert_eq!(recovered.verification_sets().len(), 2);
    assert_eq!(recovered.decision_drafts().len(), 2);
    assert_eq!(recovered.objection_sets().len(), 2);
    assert_eq!(recovered.severe_objection_acceptances().len(), 1);
    assert_eq!(recovered.supersessions().len(), 1);
    assert_eq!(recovered.objections, Some(second_objections));
    assert_eq!(
        recovered.objection_artifact,
        Some(artifact("objection-set-2", '9'))
    );
    assert_eq!(recovered.plan_approval(), Some(&approval));
    assert_eq!(
        recovered.decision_drafts()[1].artifact(),
        &artifact("decision-record-2", '8')
    );
    assert_eq!(
        recovered.supersessions()[0].superseded(),
        &artifact("decision-record-1", '5')
    );
    assert_eq!(
        recovered.supersessions()[0].replacement(),
        &artifact("decision-record-2", '8')
    );
}

#[test]
fn recovery_rejects_broken_severe_objection_and_supersession_chains() {
    let severe = objection_set_for(1, ObjectionSeverity::Severe);
    let reopen_plan = reopen_review_plan(2);
    let lifecycle = lifecycle_facts_to_decision();

    let mut acceptance_without_objections = lifecycle.clone();
    acceptance_without_objections.push(severe_acceptance_fact(
        "event-severe-accepted-1",
        7,
        severe.clone(),
        artifact("objection-set-1", '6'),
        reopen_plan.clone(),
        artifact("review-plan-2", '7'),
    ));

    let mut changed_objection_reference = lifecycle.clone();
    changed_objection_reference.extend([
        objection_set_fact(
            "event-objections-1",
            7,
            severe.clone(),
            artifact("objection-set-1", '6'),
        ),
        severe_acceptance_fact(
            "event-severe-accepted-1",
            8,
            severe.clone(),
            artifact("objection-set-other", '6'),
            reopen_plan.clone(),
            artifact("review-plan-2", '7'),
        ),
    ]);

    let mut replacement_without_supersession = lifecycle.clone();
    replacement_without_supersession.extend([
        objection_set_fact(
            "event-objections-1",
            7,
            severe.clone(),
            artifact("objection-set-1", '6'),
        ),
        severe_acceptance_fact(
            "event-severe-accepted-1",
            8,
            severe,
            artifact("objection-set-1", '6'),
            reopen_plan,
            artifact("review-plan-2", '7'),
        ),
        claim_set_fact_for_round("event-claims-2", 9, 2),
        verification_set_fact_for_round("event-verification-2", 10, 2),
        decision_draft_fact_for_round("event-decision-2", 11, 2),
    ]);

    for facts in [
        acceptance_without_objections,
        changed_objection_reference,
        replacement_without_supersession,
    ] {
        assert!(recover_deliberation(DeliberationRecoveryInput {
            task_id: task_id(),
            task_version: facts.last().unwrap().event_sequence(),
            task_state: state(
                Phase::FinalObjection,
                facts.last().unwrap().event_sequence()
            ),
            run_assignments: vec![
                assignment("run-1", "agent-1", "family-1", "agent-1"),
                assignment("run-2", "agent-2", "family-2", "agent-2"),
            ],
            facts,
        })
        .is_err());
    }
}

#[test]
fn recovery_rejects_reopen_plans_outside_quorum_and_assignment_authority() {
    let severe = objection_set_for(1, ObjectionSeverity::Severe);
    for hostile_plan in [
        reopen_review_plan_with("agent-2", "proposal-other"),
        reopen_review_plan_with("agent-other", "proposal-1"),
    ] {
        let mut facts = lifecycle_facts_to_decision();
        facts.extend([
            objection_set_fact(
                "event-objections-1",
                7,
                severe.clone(),
                artifact("objection-set-1", '6'),
            ),
            severe_acceptance_fact(
                "event-severe-accepted-1",
                8,
                severe.clone(),
                artifact("objection-set-1", '6'),
                hostile_plan,
                artifact("review-plan-2", '7'),
            ),
        ]);

        assert!(recover_deliberation(DeliberationRecoveryInput {
            task_id: task_id(),
            task_version: 8,
            task_state: state(Phase::CrossReview, 8),
            run_assignments: vec![
                assignment("run-1", "agent-1", "family-1", "agent-1"),
                assignment("run-2", "agent-2", "family-2", "agent-2"),
            ],
            facts,
        })
        .is_err());
    }
}

#[test]
fn recovery_rejects_review_records_outside_the_active_cross_review_window() {
    let severe = objection_set_for(1, ObjectionSeverity::Severe);
    let mut stale_initial_edges = lifecycle_facts_to_decision();
    stale_initial_edges.extend([
        objection_set_fact(
            "event-objections-1",
            7,
            severe.clone(),
            artifact("objection-set-1", '6'),
        ),
        severe_acceptance_fact(
            "event-severe-accepted-1",
            8,
            severe,
            artifact("objection-set-1", '6'),
            reopen_review_plan(2),
            artifact("review-plan-2", '7'),
        ),
        review_edges_fact_with(
            review_plan(),
            artifact("review-plan-1", 'e'),
            "event-stale-review-edges",
            9,
        ),
    ]);

    let mut summary_after_claim = vec![
        private_proposal_fact_for(1, "event-private-1", 1),
        private_proposal_fact_for(2, "event-private-2", 2),
        quorum_fact(quorum_proposals(), "event-quorum-1", 3),
        claim_set_fact("event-claims-1", 4),
    ];
    summary_after_claim.push(thread_summary_fact(
        "thread-after-claim",
        "event-thread-after-claim",
        5,
    ));

    for (phase, facts) in [
        (Phase::CrossReview, stale_initial_edges),
        (Phase::PrePlanVerification, summary_after_claim),
    ] {
        let task_version = facts.last().unwrap().event_sequence();
        assert!(recover_deliberation(DeliberationRecoveryInput {
            task_id: task_id(),
            task_version,
            task_state: state(phase, task_version),
            run_assignments: vec![
                assignment("run-1", "agent-1", "family-1", "agent-1"),
                assignment("run-2", "agent-2", "family-2", "agent-2"),
            ],
            facts,
        })
        .is_err());
    }
}

#[test]
fn recovery_rejects_claim_verification_and_decision_out_of_order_or_repeated() {
    let published = || {
        vec![
            private_proposal_fact_for(1, "event-private-1", 1),
            private_proposal_fact_for(2, "event-private-2", 2),
            quorum_fact(quorum_proposals(), "event-quorum-1", 3),
        ]
    };
    let mut verification_before_claim = published();
    verification_before_claim.push(verification_set_fact("event-verification-1", 4));
    let mut decision_before_verification = published();
    decision_before_verification.push(claim_set_fact("event-claims-1", 4));
    decision_before_verification.push(decision_draft_fact("event-decision-1", 5));
    let mut repeated_claim_set = published();
    repeated_claim_set.push(claim_set_fact("event-claims-1", 4));
    repeated_claim_set.push(claim_set_fact("event-claims-2", 5));
    let mut repeated_verification = lifecycle_facts_to_decision();
    repeated_verification.pop();
    repeated_verification.push(verification_set_fact("event-verification-2", 6));
    let mut repeated_decision = lifecycle_facts_to_decision();
    repeated_decision.push(decision_draft_fact("event-decision-2", 7));

    for facts in [
        vec![claim_set_fact("event-claims-1", 1)],
        verification_before_claim,
        decision_before_verification,
        repeated_claim_set,
        repeated_verification,
        repeated_decision,
    ] {
        assert!(recover_deliberation(DeliberationRecoveryInput {
            task_id: task_id(),
            task_version: 7,
            task_state: state(Phase::FinalObjection, 7),
            run_assignments: vec![
                assignment("run-1", "agent-1", "family-1", "agent-1"),
                assignment("run-2", "agent-2", "family-2", "agent-2"),
            ],
            facts,
        })
        .is_err());
    }
}

#[test]
fn recovery_rejects_changed_verification_authority_and_decision_evidence() {
    let changed = MaterialClaim::new(
        "claim-a",
        "agent-2",
        ArtifactId::new("proposal-1").unwrap(),
        vec![citation()],
        VerificationMethod::SourceMatch,
    )
    .unwrap()
    .classify(ClaimVerification::Verified)
    .unwrap();
    let mut changed_verification = vec![
        private_proposal_fact_for(1, "event-private-1", 1),
        private_proposal_fact_for(2, "event-private-2", 2),
        quorum_fact(quorum_proposals(), "event-quorum-1", 3),
        claim_set_fact("event-claims-1", 4),
    ];
    changed_verification.push(
        CanonicalDeliberationFact::issue(
            task_id(),
            EventId::new("event-verification-1").unwrap(),
            5,
            ActorId::new("core").unwrap(),
            DeliberationRecord::VerificationSet {
                claims: vec![
                    changed,
                    material_claim(
                        "claim-b",
                        VerificationMethod::PolicyReview,
                        Some(ClaimVerification::Rejected),
                    ),
                ],
                artifact: artifact("verification-set-1", '4'),
            },
        )
        .unwrap(),
    );
    let mut changed_decision = lifecycle_facts_to_decision();
    changed_decision.pop();
    changed_decision.push(decision_draft_fact_with(
        DecisionPackage::new(
            DecisionApproach::new(
                "approach-selected",
                ArtifactId::new("approach-selected-artifact").unwrap(),
                vec!["claim-a".to_owned()],
            )
            .unwrap(),
            Vec::new(),
            vec![material_claim(
                "claim-a",
                VerificationMethod::SourceMatch,
                Some(ClaimVerification::Verified),
            )],
            Vec::new(),
            &[],
            ArtifactId::new("plan-1").unwrap(),
        )
        .unwrap(),
        "event-decision-1",
        6,
    ));

    for facts in [changed_verification, changed_decision] {
        assert!(recover_deliberation(DeliberationRecoveryInput {
            task_id: task_id(),
            task_version: 7,
            task_state: state(Phase::FinalObjection, 7),
            run_assignments: vec![
                assignment("run-1", "agent-1", "family-1", "agent-1"),
                assignment("run-2", "agent-2", "family-2", "agent-2"),
            ],
            facts,
        })
        .is_err());
    }
}

#[test]
fn recovery_rejects_phase_neutral_records_outside_their_logical_phase() {
    let assignments = vec![
        assignment("run-1", "agent-1", "family-1", "agent-1"),
        assignment("run-2", "agent-2", "family-2", "agent-2"),
    ];
    let private = private_proposal_fact_for(1, "event-private-1", 1);
    let private_two = private_proposal_fact_for(2, "event-private-2", 2);
    let publication = quorum_fact(quorum_proposals(), "event-quorum-1", 3);
    for (label, phase, facts) in [
        (
            "specialist after publication",
            Phase::CrossReview,
            vec![
                private.clone(),
                private_two.clone(),
                publication.clone(),
                specialist_request_fact(specialist_request(), "event-specialist-1", 4),
            ],
        ),
        (
            "review before publication",
            Phase::ParallelAnalysis,
            vec![private.clone(), review_edges_fact("event-review-1", 2)],
        ),
        (
            "thread before publication",
            Phase::ParallelAnalysis,
            vec![
                private.clone(),
                thread_summary_fact("thread-1", "event-thread-1", 2),
            ],
        ),
    ] {
        assert!(
            recover_deliberation(DeliberationRecoveryInput {
                task_id: task_id(),
                task_version: 7,
                task_state: state(phase, 7),
                run_assignments: assignments.clone(),
                facts,
            })
            .is_err(),
            "{label}"
        );
    }
}

#[test]
fn recovery_rejects_duplicate_specialist_review_and_thread_history() {
    let assignments = vec![
        assignment("run-1", "agent-1", "family-1", "agent-1"),
        assignment("run-2", "agent-2", "family-2", "agent-2"),
    ];
    let prefix = vec![
        private_proposal_fact_for(1, "event-private-1", 1),
        private_proposal_fact_for(2, "event-private-2", 2),
        quorum_fact(quorum_proposals(), "event-quorum-1", 3),
    ];
    let duplicate_specialist = vec![
        private_proposal_fact_for(1, "event-private-1", 1),
        specialist_request_fact(specialist_request(), "event-specialist-1", 2),
        specialist_request_fact(specialist_request(), "event-specialist-2", 3),
    ];
    let mut duplicate_review = prefix.clone();
    duplicate_review.extend([
        review_edges_fact("event-review-1", 4),
        review_edges_fact("event-review-2", 5),
    ]);
    let mut duplicate_thread = prefix;
    duplicate_thread.extend([
        thread_summary_fact("thread-1", "event-thread-1", 4),
        thread_summary_fact("thread-1", "event-thread-2", 5),
    ]);
    for (label, phase, facts) in [
        (
            "specialist request id",
            Phase::ParallelAnalysis,
            duplicate_specialist,
        ),
        ("review mirror", Phase::CrossReview, duplicate_review),
        ("thread id", Phase::CrossReview, duplicate_thread),
    ] {
        assert!(
            recover_deliberation(DeliberationRecoveryInput {
                task_id: task_id(),
                task_version: 7,
                task_state: state(phase, 7),
                run_assignments: assignments.clone(),
                facts,
            })
            .is_err(),
            "{label}"
        );
    }
}

#[test]
fn recovery_rejects_review_mirror_plan_or_artifact_mismatch() {
    for (label, review) in [
        (
            "plan",
            review_edges_fact_with(
                reopen_review_plan(2),
                artifact("review-plan-1", 'e'),
                "event-review-plan",
                4,
            ),
        ),
        (
            "artifact",
            review_edges_fact_with(
                review_plan(),
                artifact("review-plan-other", 'f'),
                "event-review-artifact",
                4,
            ),
        ),
    ] {
        assert!(
            recover_deliberation(DeliberationRecoveryInput {
                task_id: task_id(),
                task_version: 7,
                task_state: state(Phase::CrossReview, 7),
                run_assignments: vec![
                    assignment("run-1", "agent-1", "family-1", "agent-1"),
                    assignment("run-2", "agent-2", "family-2", "agent-2"),
                ],
                facts: vec![
                    private_proposal_fact_for(1, "event-private-1", 1),
                    private_proposal_fact_for(2, "event-private-2", 2),
                    quorum_fact(quorum_proposals(), "event-quorum-1", 3),
                    review,
                ],
            })
            .is_err(),
            "{label}"
        );
    }
}

#[test]
fn recovery_rejects_reordered_duplicate_or_conflicting_proposal_facts() {
    let first = private_proposal_fact_for(1, "event-private-1", 1);
    let second = private_proposal_fact_for(2, "event-private-2", 3);
    for facts in [
        vec![second.clone(), first.clone()],
        vec![first.clone(), first.clone()],
        vec![
            first.clone(),
            private_proposal_fact_for(1, "event-private-retry", 2),
        ],
    ] {
        assert!(recover_deliberation(DeliberationRecoveryInput {
            task_id: task_id(),
            task_version: 7,
            task_state: state(Phase::ParallelAnalysis, 7),
            run_assignments: vec![
                assignment("run-1", "agent-1", "family-1", "agent-1"),
                assignment("run-2", "agent-2", "family-2", "agent-2"),
            ],
            facts,
        })
        .is_err());
    }
}

#[test]
fn recovery_rejects_duplicate_event_identity_even_when_sequences_increase() {
    assert!(recover_deliberation(DeliberationRecoveryInput {
        task_id: task_id(),
        task_version: 7,
        task_state: state(Phase::ParallelAnalysis, 7),
        run_assignments: vec![
            assignment("run-1", "agent-1", "family-1", "agent-1"),
            assignment("run-2", "agent-2", "family-2", "agent-2"),
        ],
        facts: vec![
            private_proposal_fact_for(1, "event-shared", 1),
            private_proposal_fact_for(2, "event-shared", 2),
        ],
    })
    .is_err());
}

#[test]
fn recovery_rejects_duplicate_run_and_duplicate_artifact_independently() {
    let duplicate_run = IndependentProposal::new(
        task_id(),
        RunId::new("run-1").unwrap(),
        "agent-1",
        local_agent_terminal_domain::AgentFamilyKey::new("family-1").unwrap(),
        ArtifactId::new("proposal-new").unwrap(),
        vec![citation()],
    )
    .unwrap();
    let duplicate_artifact = IndependentProposal::new(
        task_id(),
        RunId::new("run-2").unwrap(),
        "agent-2",
        local_agent_terminal_domain::AgentFamilyKey::new("family-2").unwrap(),
        ArtifactId::new("proposal-1").unwrap(),
        vec![citation()],
    )
    .unwrap();
    for (label, second) in [
        ("duplicate run", duplicate_run),
        ("duplicate artifact", duplicate_artifact),
    ] {
        let second = CanonicalDeliberationFact::issue(
            task_id(),
            EventId::new(format!("event-{label}").replace(' ', "-")).unwrap(),
            2,
            ActorId::new(second.agent_id()).unwrap(),
            DeliberationRecord::PrivateProposal {
                proposal_artifact: artifact(second.artifact_id().as_str(), 'c'),
                receipt: artifact(&format!("receipt-{label}").replace(' ', "-"), 'a'),
                proposal: second,
            },
        )
        .unwrap();
        assert!(
            recover_deliberation(DeliberationRecoveryInput {
                task_id: task_id(),
                task_version: 7,
                task_state: state(Phase::ParallelAnalysis, 7),
                run_assignments: vec![
                    assignment("run-1", "agent-1", "family-1", "agent-1"),
                    assignment("run-2", "agent-2", "family-2", "agent-2"),
                ],
                facts: vec![private_proposal_fact_for(1, "event-private-1", 1), second,],
            })
            .is_err(),
            "{label}"
        );
    }
}

#[test]
fn recovery_rejects_quorum_before_or_different_from_private_proposal_set() {
    let assignments = vec![
        assignment("run-1", "agent-1", "family-1", "agent-1"),
        assignment("run-2", "agent-2", "family-2", "agent-2"),
        assignment("run-3", "agent-3", "family-3", "agent-3"),
    ];
    let before = vec![quorum_fact(quorum_proposals(), "event-quorum-before", 1)];
    let mismatched = vec![
        private_proposal_fact_for(1, "event-private-1", 1),
        private_proposal_fact_for(2, "event-private-2", 2),
        quorum_fact(
            IndependentQuorum::new(vec![proposal(1), proposal(3)])
                .unwrap()
                .reveal(),
            "event-quorum-mismatch",
            3,
        ),
    ];

    for facts in [before, mismatched] {
        assert!(recover_deliberation(DeliberationRecoveryInput {
            task_id: task_id(),
            task_version: 7,
            task_state: state(Phase::CrossReview, 7),
            run_assignments: assignments.clone(),
            facts,
        })
        .is_err());
    }
}

#[test]
fn recovery_rejects_supported_prefix_phase_divergence() {
    for (facts, phase) in [
        (
            vec![private_proposal_fact_for(1, "event-private-1", 1)],
            Phase::CrossReview,
        ),
        (
            vec![
                private_proposal_fact_for(1, "event-private-1", 1),
                private_proposal_fact_for(2, "event-private-2", 2),
                quorum_fact(quorum_proposals(), "event-quorum-replay-1", 3),
            ],
            Phase::ParallelAnalysis,
        ),
    ] {
        assert!(recover_deliberation(DeliberationRecoveryInput {
            task_id: task_id(),
            task_version: 7,
            task_state: state(phase, 7),
            run_assignments: vec![
                assignment("run-1", "agent-1", "family-1", "agent-1"),
                assignment("run-2", "agent-2", "family-2", "agent-2"),
            ],
            facts,
        })
        .is_err());
    }
}

#[test]
fn recovery_rejects_an_objection_before_a_decision_draft() {
    let later_fact = CanonicalDeliberationFact::issue(
        task_id(),
        EventId::new("event-objection-later").unwrap(),
        6,
        ActorId::new("core").unwrap(),
        issued_objection_set().record().clone(),
    )
    .unwrap();
    assert!(recover_deliberation(DeliberationRecoveryInput {
        task_id: task_id(),
        task_version: 7,
        task_state: state(Phase::Synthesis, 7),
        run_assignments: vec![
            assignment("run-1", "agent-1", "family-1", "agent-1"),
            assignment("run-2", "agent-2", "family-2", "agent-2"),
        ],
        facts: vec![
            private_proposal_fact_for(1, "event-private-1", 1),
            private_proposal_fact_for(2, "event-private-2", 2),
            quorum_fact(quorum_proposals(), "event-quorum-replay-1", 5),
            later_fact,
        ],
    })
    .is_err());
}

#[test]
fn canonical_fact_rejects_proposal_artifact_with_wrong_identity() {
    let proposal = proposal(1);
    assert!(CanonicalDeliberationFact::issue(
        task_id(),
        EventId::new("event-1").unwrap(),
        3,
        ActorId::new("agent-1").unwrap(),
        DeliberationRecord::PrivateProposal {
            proposal,
            proposal_artifact: artifact("proposal-other", 'c'),
            receipt: artifact("receipt-1", 'a'),
        },
    )
    .is_err());
}

#[test]
fn canonical_quorum_publication_round_trips_revealed_proposals_and_full_refs() {
    let record = DeliberationRecord::QuorumPublication {
        proposals: quorum_proposals(),
        proposal_artifact: artifact("proposal-bundle-1", 'd'),
        review_plan: review_plan(),
        review_artifact: artifact("review-plan-1", 'e'),
    };

    let reopened = round_trip("event-quorum-1", ActorId::new("core").unwrap(), record);

    assert!(matches!(
        reopened.record(),
        DeliberationRecord::QuorumPublication {
            proposals,
            proposal_artifact,
            review_plan,
            review_artifact,
        } if proposals.len() == 2
            && proposals.iter().all(IndependentProposal::is_revealed)
            && proposal_artifact == &artifact("proposal-bundle-1", 'd')
            && review_plan == &self::review_plan()
            && review_artifact == &artifact("review-plan-1", 'e')
    ));
}

#[test]
fn canonical_quorum_issue_rejects_singleton_and_duplicate_revealed_proposals() {
    let revealed = quorum_proposals();
    for proposals in [
        vec![revealed[0].clone()],
        vec![revealed[0].clone(), revealed[0].clone()],
    ] {
        assert!(CanonicalDeliberationFact::issue(
            task_id(),
            EventId::new("event-quorum-hostile-1").unwrap(),
            3,
            ActorId::new("core").unwrap(),
            DeliberationRecord::QuorumPublication {
                proposals,
                proposal_artifact: artifact("proposal-bundle-1", 'd'),
                review_plan: review_plan(),
                review_artifact: artifact("review-plan-1", 'e'),
            },
        )
        .is_err());
    }
}

#[test]
fn canonical_review_edges_round_trips_exact_edges_and_full_ref() {
    let record = DeliberationRecord::ReviewEdges {
        plan: review_plan(),
        artifact: artifact("review-edges-1", 'f'),
    };

    let reopened = round_trip("event-review-1", ActorId::new("core").unwrap(), record);

    assert!(matches!(
        reopened.record(),
        DeliberationRecord::ReviewEdges { plan, artifact }
            if plan == &review_plan() && artifact == &self::artifact("review-edges-1", 'f')
    ));
}

#[test]
fn canonical_thread_summary_round_trips_exact_thread_and_full_ref() {
    let record = DeliberationRecord::ThreadSummary {
        thread_id: "thread-1".to_owned(),
        artifact: artifact("thread-summary-1", '1'),
    };

    let reopened = round_trip("event-thread-1", ActorId::new("core").unwrap(), record);

    assert!(matches!(
        reopened.record(),
        DeliberationRecord::ThreadSummary { thread_id, artifact }
            if thread_id == "thread-1"
                && artifact == &self::artifact("thread-summary-1", '1')
    ));
}

#[test]
fn canonical_specialist_request_round_trips_every_request_leaf_and_full_ref() {
    let record = DeliberationRecord::SpecialistRequest {
        request: specialist_request(),
        artifact: artifact("specialist-request-1", '2'),
    };

    let reopened = round_trip(
        "event-specialist-1",
        ActorId::new("agent-1").unwrap(),
        record,
    );

    assert!(matches!(
        reopened.record(),
        DeliberationRecord::SpecialistRequest { request, artifact }
            if request.request_id() == "specialist-1"
                && request.task_id() == &task_id()
                && request.requesting_run().as_str() == "run-1"
                && request.capability() == "repository-analysis"
                && request.reason() == "inspect repository invariants"
                && request.required_context()
                    == [ArtifactId::new("context-1").unwrap(), ArtifactId::new("context-2").unwrap()]
                && request.budget().max_tokens() == 512
                && request.budget().deadline().unix_seconds() == 1_800_000_000
                && artifact == &self::artifact("specialist-request-1", '2')
    ));
}

#[test]
fn canonical_legacy_specialist_request_without_cost_rehydrates_with_token_cost_default() {
    let issued = CanonicalDeliberationFact::issue(
        task_id(),
        EventId::new("event-specialist-legacy").unwrap(),
        3,
        ActorId::new("agent-1").unwrap(),
        DeliberationRecord::SpecialistRequest {
            request: specialist_request(),
            artifact: artifact("specialist-request-legacy", '2'),
        },
    )
    .unwrap();
    let mut value: serde_json::Value =
        serde_json::from_slice(issued.canonical_bytes()).unwrap();
    value["fact"]["request"]["budget"]
        .as_object_mut()
        .unwrap()
        .remove("maxCostMicrounits");
    let legacy_bytes = serde_json_canonicalizer::to_vec(&value).unwrap();

    let reopened = CanonicalDeliberationFact::rehydrate(
        legacy_bytes.clone(),
        digest_bytes(&legacy_bytes),
    )
    .unwrap();

    assert_eq!(reopened.canonical_bytes(), legacy_bytes);
    assert!(matches!(
        reopened.record(),
        DeliberationRecord::SpecialistRequest { request, .. }
            if request.budget().max_tokens() == 512
                && request.budget().max_cost_microunits() == 512
    ));
}

#[test]
fn canonical_supported_records_reject_actor_class_substitution() {
    let cases = [
        (
            DeliberationRecord::PrivateProposal {
                proposal: proposal(1),
                proposal_artifact: artifact("proposal-1", 'c'),
                receipt: artifact("receipt-1", 'a'),
            },
            ActorId::new("core").unwrap(),
        ),
        (
            DeliberationRecord::QuorumPublication {
                proposals: quorum_proposals(),
                proposal_artifact: artifact("proposal-bundle-1", 'd'),
                review_plan: review_plan(),
                review_artifact: artifact("review-plan-1", 'e'),
            },
            ActorId::new("agent-1").unwrap(),
        ),
        (
            DeliberationRecord::ReviewEdges {
                plan: review_plan(),
                artifact: artifact("review-edges-1", 'f'),
            },
            ActorId::new("agent-1").unwrap(),
        ),
        (
            DeliberationRecord::ThreadSummary {
                thread_id: "thread-1".to_owned(),
                artifact: artifact("thread-summary-1", '1'),
            },
            ActorId::new("agent-1").unwrap(),
        ),
        (
            DeliberationRecord::SpecialistRequest {
                request: specialist_request(),
                artifact: artifact("specialist-request-1", '2'),
            },
            ActorId::new("core").unwrap(),
        ),
    ];

    for (record, actor_id) in cases {
        assert!(CanonicalDeliberationFact::issue(
            task_id(),
            EventId::new("event-hostile-1").unwrap(),
            3,
            actor_id,
            record,
        )
        .is_err());
    }
}

#[test]
fn canonical_claim_set_round_trips_ordered_unclassified_claims_and_full_ref() {
    let claims = vec![
        material_claim("claim-b", VerificationMethod::PolicyReview, None),
        material_claim("claim-a", VerificationMethod::SourceMatch, None),
    ];
    let reopened = round_trip(
        "event-claims-1",
        ActorId::new("core").unwrap(),
        DeliberationRecord::ClaimSet {
            claims: claims.clone(),
            artifact: artifact("claim-set-1", '3'),
        },
    );

    assert!(matches!(
        reopened.record(),
        DeliberationRecord::ClaimSet {
            claims: reopened_claims,
            artifact,
        } if reopened_claims == &claims
            && reopened_claims.iter().all(|claim| claim.verification().is_none())
            && artifact == &self::artifact("claim-set-1", '3')
    ));
    let canonical: serde_json::Value = serde_json::from_slice(reopened.canonical_bytes()).unwrap();
    assert_eq!(canonical["fact"]["claims"][0]["method"], "policy_review");
    assert!(canonical["fact"]["claims"][0]["verification"].is_null());
}

#[test]
fn canonical_verification_set_round_trips_exact_terminal_claims_and_full_ref() {
    let claims = vec![
        material_claim(
            "claim-b",
            VerificationMethod::DeterministicCheck,
            Some(ClaimVerification::Rejected),
        ),
        material_claim(
            "claim-a",
            VerificationMethod::NotApplicable,
            Some(ClaimVerification::NotApplicable),
        ),
    ];
    let reopened = round_trip(
        "event-verification-1",
        ActorId::new("core").unwrap(),
        DeliberationRecord::VerificationSet {
            claims: claims.clone(),
            artifact: artifact("verification-set-1", '4'),
        },
    );

    assert!(matches!(
        reopened.record(),
        DeliberationRecord::VerificationSet {
            claims: reopened_claims,
            artifact,
        } if reopened_claims == &claims
            && reopened_claims.iter().all(|claim| claim.verification().is_some())
            && artifact == &self::artifact("verification-set-1", '4')
    ));
    let canonical: serde_json::Value = serde_json::from_slice(reopened.canonical_bytes()).unwrap();
    assert_eq!(
        canonical["fact"]["claims"][0]["method"],
        "deterministic_check"
    );
    assert_eq!(canonical["fact"]["claims"][0]["verification"], "rejected");
}
