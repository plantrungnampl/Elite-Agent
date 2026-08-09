use local_agent_terminal_domain::{
    ActorId, AgentFamilyKey, ApprovalAuthority, ApprovalExecution, ApprovalScope, ArtifactId,
    ClaimVerification, DecisionApproach, DecisionPackage, DeliberationBudget, DeliberationError,
    DeliberationLimits, Dissent, EvidenceCitation, EvidenceFreshness, FinalObjection,
    FinalObjectionSet, GitObjectId, IndependentProposal, IndependentQuorum, LineRange,
    MaterialClaim, ObjectionSeverity, PlanApprovalBinding, PlanIdentity, ProjectId,
    RejectedApproach, ReviewEdge, ReviewPlan, RunId, Sha256Digest, SourceIdentity,
    SpecialistBudget, SpecialistRequest, StructuredToolName, TaskId, Timestamp, VerificationMethod,
};

#[test]
fn quorum_requires_distinct_run_agent_and_exact_family_identity() {
    let first = proposal("run-1", "agent-1", "family-a", "proposal-1");

    assert!(IndependentQuorum::new(vec![
        first.clone(),
        proposal("run-1", "agent-2", "family-b", "proposal-2"),
    ])
    .is_err());
    assert!(IndependentQuorum::new(vec![
        first.clone(),
        proposal("run-2", "agent-1", "family-b", "proposal-2"),
    ])
    .is_err());
    assert!(IndependentQuorum::new(vec![
        first,
        proposal("run-2", "agent-2", "family-a", "proposal-2"),
    ])
    .is_err());

    assert!(IndependentQuorum::new(vec![
        proposal("run-1", "agent-1", "family-a", "proposal-1"),
        proposal("run-2", "agent-2", "Family-A", "proposal-2"),
    ])
    .is_ok());
}

#[test]
fn quorum_enforces_the_hard_agent_boundary_independently_of_external_limits() {
    for (agent_count, expected_valid) in [(64, true), (65, false)] {
        let proposals = (0..agent_count)
            .map(|index| {
                proposal(
                    &format!("run-{index}"),
                    &format!("agent-{index}"),
                    &format!("family-{index}"),
                    &format!("proposal-{index}"),
                )
            })
            .collect();

        assert_eq!(IndependentQuorum::new(proposals).is_ok(), expected_valid);
    }
}

#[test]
fn proposals_remain_hidden_until_a_valid_quorum_reveals_them() {
    let proposals = vec![
        proposal("run-1", "agent-1", "family-a", "proposal-1"),
        proposal("run-2", "agent-2", "family-b", "proposal-2"),
    ];
    assert!(proposals.iter().all(|proposal| !proposal.is_revealed()));

    let revealed = IndependentQuorum::new(proposals).unwrap().reveal();
    assert!(revealed.iter().all(IndependentProposal::is_revealed));
}

#[test]
fn review_plans_reject_duplicate_edges_and_limit_overruns() {
    let limits = DeliberationLimits::new(2, 2, 2, 1).unwrap();
    let edge = ReviewEdge::new("reviewer-1", artifact_id("proposal-1"), 1).unwrap();

    assert!(ReviewPlan::new(limits, vec![edge.clone(), edge]).is_err());
    assert!(ReviewPlan::new(
        limits,
        vec![ReviewEdge::new("reviewer-1", artifact_id("proposal-1"), 3).unwrap()],
    )
    .is_err());
    assert!(ReviewPlan::new(
        limits,
        vec![
            ReviewEdge::new("reviewer-1", artifact_id("proposal-1"), 1).unwrap(),
            ReviewEdge::new("reviewer-2", artifact_id("proposal-2"), 1).unwrap(),
            ReviewEdge::new("reviewer-3", artifact_id("proposal-3"), 1).unwrap(),
        ],
    )
    .is_err());
}

#[test]
fn review_edges_enforce_the_hard_round_boundary_at_construction() {
    const MAX_DELIBERATION_ROUNDS: u32 = 32;

    assert!(ReviewEdge::new(
        "reviewer-1",
        artifact_id("proposal-1"),
        MAX_DELIBERATION_ROUNDS,
    )
    .is_ok());
    assert!(ReviewEdge::new(
        "reviewer-1",
        artifact_id("proposal-1"),
        MAX_DELIBERATION_ROUNDS + 1,
    )
    .is_err());
    assert!(ReviewEdge::new("reviewer-1", artifact_id("proposal-1"), u32::MAX).is_err());
}

#[test]
fn deliberation_limits_reject_zero_and_effectively_unbounded_values() {
    assert!(DeliberationLimits::new(0, 1, 1, 1).is_err());
    assert!(DeliberationLimits::new(1, 0, 1, 1).is_err());
    assert!(DeliberationLimits::new(1, 1, 0, 1).is_err());
    assert!(DeliberationLimits::new(1, 1, 1, 0).is_err());
    assert!(DeliberationLimits::new(u32::MAX, 1, 1, 1).is_err());
    assert!(DeliberationLimits::new(1, u32::MAX, 1, 1).is_err());
    assert!(DeliberationLimits::new(1, 1, u32::MAX, 1).is_err());
    assert!(DeliberationLimits::new(1, 1, 1, u32::MAX).is_err());
}

#[test]
fn specialist_requests_require_reason_context_and_positive_budget() {
    let context = vec![artifact_id("proposal-1")];
    let budget = specialist_budget();

    assert!(SpecialistRequest::new(
        "request-1",
        task_id(),
        run_id("run-1"),
        "security-review",
        "",
        context.clone(),
        budget,
    )
    .is_err());
    assert!(SpecialistRequest::new(
        "request-1",
        task_id(),
        run_id("run-1"),
        "security-review",
        "Review a severe risk.",
        Vec::new(),
        budget,
    )
    .is_err());
    assert!(SpecialistBudget::new(0, Timestamp::from_unix_seconds(10)).is_err());
    assert!(SpecialistBudget::new(100, Timestamp::from_unix_seconds(0)).is_err());
}

#[test]
fn deliberation_budget_usage_is_monotonic_and_overflow_safe() {
    let mut budget = DeliberationBudget::new(100, 3).unwrap();
    let mut previous_tokens = budget.used_tokens();
    let mut previous_requests = budget.used_specialist_requests();

    for tokens in [3, 5, 8] {
        budget.reserve(tokens).unwrap();
        assert!(budget.used_tokens() >= previous_tokens);
        assert!(budget.used_specialist_requests() >= previous_requests);
        previous_tokens = budget.used_tokens();
        previous_requests = budget.used_specialist_requests();
    }

    assert!(budget.reserve(u64::MAX).is_err());
    assert_eq!(budget.used_tokens(), previous_tokens);
    assert_eq!(budget.used_specialist_requests(), previous_requests);
    assert!(budget.reserve(1).is_err());
}

#[test]
fn material_claims_require_citations_and_current_evidence_for_verified_status() {
    assert!(MaterialClaim::new(
        "claim-1",
        "agent-1",
        artifact_id("proposal-1"),
        Vec::new(),
        VerificationMethod::SourceMatch,
    )
    .is_err());

    let stale = claim("claim-1", EvidenceFreshness::Stale);
    assert!(stale.classify(ClaimVerification::Verified).is_err());

    let current = claim("claim-1", EvidenceFreshness::Current)
        .classify(ClaimVerification::Verified)
        .unwrap();
    assert_eq!(current.verification(), Some(ClaimVerification::Verified));
}

#[test]
fn synthesis_rejects_nonterminal_claims_and_selected_approaches_without_evidence() {
    let pending = claim("claim-1", EvidenceFreshness::Current);
    assert!(decision_package(
        DecisionApproach::new(
            "approach-1",
            artifact_id("proposal-1"),
            vec!["claim-1".into()]
        )
        .unwrap(),
        vec![pending],
        Vec::new(),
        &[],
    )
    .is_err());

    let terminal = claim("claim-1", EvidenceFreshness::Current)
        .classify(ClaimVerification::Inconclusive)
        .unwrap();
    assert!(decision_package(
        DecisionApproach::new("approach-1", artifact_id("proposal-1"), Vec::new()).unwrap(),
        vec![terminal],
        Vec::new(),
        &[],
    )
    .is_err());
}

#[test]
fn selected_approach_requires_every_supporting_claim_to_be_verified() {
    let selected = selected_approach("approach-1", "claim-1");

    for verification in [
        ClaimVerification::Rejected,
        ClaimVerification::Inconclusive,
        ClaimVerification::NotApplicable,
    ] {
        let evidence = claim("claim-1", EvidenceFreshness::Current)
            .classify(verification)
            .unwrap();
        assert!(decision_package(selected.clone(), vec![evidence], Vec::new(), &[]).is_err());
    }

    let verified = claim("claim-1", EvidenceFreshness::Current)
        .classify(ClaimVerification::Verified)
        .unwrap();
    assert!(decision_package(selected, vec![verified], Vec::new(), &[]).is_ok());
}

#[test]
fn synthesis_rejects_lost_dissent() {
    let terminal = terminal_claim("claim-1");
    let selected = selected_approach("approach-1", "claim-1");

    assert!(decision_package(
        selected.clone(),
        vec![terminal.clone()],
        Vec::new(),
        &["dissent-1"]
    )
    .is_err());

    let preserved = vec![Dissent::new(
        "dissent-1",
        "agent-2",
        artifact_id("dissent-artifact-1"),
        "The rollback evidence is incomplete.",
    )
    .unwrap()];
    assert!(decision_package(selected, vec![terminal], preserved, &["dissent-1"]).is_ok());
}

#[test]
fn terminal_claim_classification_is_exhaustive_and_one_shot() {
    let terminal_classifications = [
        ClaimVerification::Verified,
        ClaimVerification::Rejected,
        ClaimVerification::Inconclusive,
        ClaimVerification::NotApplicable,
    ];

    for first in terminal_classifications {
        assert!(first.is_terminal());
        let claim = claim("claim-1", EvidenceFreshness::Current)
            .classify(first)
            .unwrap();
        assert_eq!(claim.verification(), Some(first));

        for second in terminal_classifications {
            assert_eq!(
                claim.clone().classify(second).unwrap_err(),
                DeliberationError::ClaimAlreadyClassified,
                "first {first:?}, second {second:?}",
            );
            assert_eq!(claim.verification(), Some(first));
        }
    }
}

#[test]
fn decision_members_use_stable_canonical_order() {
    let selected = selected_approach("approach-selected", "claim-b");
    let evidence = vec![terminal_claim("claim-b"), terminal_claim("claim-a")];
    let rejected = vec![
        rejected_approach("approach-c", "claim-a"),
        rejected_approach("approach-b", "claim-a"),
    ];
    let dissent = vec![
        dissent("dissent-b", "agent-3"),
        dissent("dissent-a", "agent-2"),
    ];

    let package = DecisionPackage::new(
        selected,
        rejected,
        evidence,
        dissent,
        &["dissent-b", "dissent-a"],
        artifact_id("plan-1"),
    )
    .unwrap();

    assert_eq!(
        package
            .rejected()
            .iter()
            .map(RejectedApproach::approach_id)
            .collect::<Vec<_>>(),
        ["approach-b", "approach-c"]
    );
    assert_eq!(
        package
            .evidence()
            .iter()
            .map(MaterialClaim::claim_id)
            .collect::<Vec<_>>(),
        ["claim-a", "claim-b"]
    );
    assert_eq!(
        package
            .dissent()
            .iter()
            .map(Dissent::dissent_id)
            .collect::<Vec<_>>(),
        ["dissent-a", "dissent-b"]
    );
}

#[test]
fn severe_objections_require_impact_evidence_and_a_violated_requirement() {
    assert!(FinalObjection::new(
        "agent-1",
        1,
        ObjectionSeverity::Severe,
        "",
        vec![citation(EvidenceFreshness::Current)],
        Some("security requirement"),
    )
    .is_err());
    assert!(FinalObjection::new(
        "agent-1",
        1,
        ObjectionSeverity::Severe,
        "Repository data could be lost.",
        Vec::new(),
        Some("security requirement"),
    )
    .is_err());
    assert!(FinalObjection::new(
        "agent-1",
        1,
        ObjectionSeverity::Severe,
        "Repository data could be lost.",
        vec![citation(EvidenceFreshness::Current)],
        None,
    )
    .is_err());
}

#[test]
fn final_objection_enforces_the_hard_round_boundary() {
    for (round, expected_valid) in [(32, true), (33, false), (u32::MAX, false)] {
        let result = FinalObjection::new(
            "agent-1",
            round,
            ObjectionSeverity::Low,
            "A material risk remains.",
            vec![citation(EvidenceFreshness::Current)],
            None,
        );

        assert_eq!(result.is_ok(), expected_valid, "round {round}");
    }
}

#[test]
fn final_objection_set_enforces_the_hard_participant_boundary() {
    for (participant_count, expected_valid) in [(64, true), (65, false)] {
        let objections = (0..participant_count)
            .map(|index| objection(&format!("agent-{index}"), 32, ObjectionSeverity::Low))
            .collect();

        assert_eq!(
            FinalObjectionSet::new(32, objections).is_ok(),
            expected_valid,
            "participant count {participant_count}",
        );
    }
}

#[test]
fn final_objection_set_defensively_rejects_unbounded_rounds() {
    for round in [33, u32::MAX] {
        assert!(FinalObjectionSet::new(round, Vec::new()).is_err());
    }
}

#[test]
fn objection_round_rejects_multiple_submissions_from_one_participant() {
    let first = objection("agent-1", 1, ObjectionSeverity::Moderate);
    let second = objection("agent-1", 1, ObjectionSeverity::Low);

    assert!(FinalObjectionSet::new(1, vec![first, second]).is_err());
    assert!(
        FinalObjectionSet::new(1, vec![objection("agent-2", 2, ObjectionSeverity::Low)],).is_err()
    );
}

#[test]
fn plan_approval_binding_rejects_incomplete_or_expired_inputs() {
    assert!(PlanIdentity::new(artifact_id("plan-1"), digest('a'), 0).is_err());
    assert!(ApprovalScope::new(Vec::new(), vec!["crates/domain".into()]).is_err());
    assert!(ApprovalScope::new(vec!["crates/domain".into()], Vec::new()).is_err());
    assert!(ApprovalAuthority::new(
        actor_id(),
        Timestamp::from_unix_seconds(10),
        Timestamp::from_unix_seconds(10),
    )
    .is_err());

    assert!(ApprovalExecution::new(approval_scope(), Vec::new(), "verification-v1",).is_err());
    assert!(
        ApprovalExecution::new(approval_scope(), vec![StructuredToolName::FileWrite], "",).is_err()
    );
    assert!(ActorId::new("").is_err());

    assert!(PlanApprovalBinding::new(
        plan_identity(),
        task_id(),
        base_commit(),
        digest('b'),
        digest('c'),
        approval_execution(),
        approval_authority(),
    )
    .is_ok());
}

#[test]
fn exact_family_diversity_and_quorum_are_order_independent() {
    for proposals in [
        vec![
            proposal("run-1", "agent-1", "family-a", "proposal-1"),
            proposal("run-2", "agent-2", "family-b", "proposal-2"),
        ],
        vec![
            proposal("run-2", "agent-2", "family-b", "proposal-2"),
            proposal("run-1", "agent-1", "family-a", "proposal-1"),
        ],
    ] {
        let quorum = IndependentQuorum::new(proposals).unwrap();
        assert_eq!(quorum.family_count(), 2);
        assert_eq!(
            quorum
                .proposals()
                .iter()
                .map(|proposal| proposal.artifact_id().as_str())
                .collect::<Vec<_>>(),
            ["proposal-1", "proposal-2"]
        );
    }
}

fn proposal(run: &str, agent: &str, family: &str, artifact: &str) -> IndependentProposal {
    IndependentProposal::new(
        task_id(),
        run_id(run),
        agent,
        AgentFamilyKey::new(family).unwrap(),
        artifact_id(artifact),
        vec![citation(EvidenceFreshness::Current)],
    )
    .unwrap()
}

fn specialist_budget() -> SpecialistBudget {
    SpecialistBudget::new(100, Timestamp::from_unix_seconds(10)).unwrap()
}

fn claim(id: &str, freshness: EvidenceFreshness) -> MaterialClaim {
    MaterialClaim::new(
        id,
        "agent-1",
        artifact_id("proposal-1"),
        vec![citation(freshness)],
        VerificationMethod::SourceMatch,
    )
    .unwrap()
}

fn terminal_claim(id: &str) -> MaterialClaim {
    claim(id, EvidenceFreshness::Current)
        .classify(ClaimVerification::Verified)
        .unwrap()
}

fn selected_approach(id: &str, claim_id: &str) -> DecisionApproach {
    DecisionApproach::new(
        id,
        artifact_id("proposal-selected"),
        vec![claim_id.to_owned()],
    )
    .unwrap()
}

fn rejected_approach(id: &str, claim_id: &str) -> RejectedApproach {
    RejectedApproach::new(
        DecisionApproach::new(id, artifact_id(id), vec![claim_id.to_owned()]).unwrap(),
        "Higher risk than the selected approach.",
    )
    .unwrap()
}

fn dissent(id: &str, participant: &str) -> Dissent {
    Dissent::new(
        id,
        participant,
        artifact_id(id),
        "A material tradeoff remains unresolved.",
    )
    .unwrap()
}

fn decision_package(
    selected: DecisionApproach,
    evidence: Vec<MaterialClaim>,
    dissent: Vec<Dissent>,
    expected_dissent: &[&str],
) -> Result<DecisionPackage, local_agent_terminal_domain::DeliberationError> {
    DecisionPackage::new(
        selected,
        Vec::new(),
        evidence,
        dissent,
        expected_dissent,
        artifact_id("plan-1"),
    )
}

fn objection(participant: &str, round: u32, severity: ObjectionSeverity) -> FinalObjection {
    FinalObjection::new(
        participant,
        round,
        severity,
        "A material risk remains.",
        vec![citation(EvidenceFreshness::Current)],
        Some("verified repository behavior"),
    )
    .unwrap()
}

fn plan_identity() -> PlanIdentity {
    PlanIdentity::new(artifact_id("plan-1"), digest('a'), 1).unwrap()
}

fn approval_scope() -> ApprovalScope {
    ApprovalScope::new(
        vec!["crates/domain".into()],
        vec!["crates/domain/src".into()],
    )
    .unwrap()
}

fn approval_authority() -> ApprovalAuthority {
    ApprovalAuthority::new(
        actor_id(),
        Timestamp::from_unix_seconds(10),
        Timestamp::from_unix_seconds(20),
    )
    .unwrap()
}

fn approval_execution() -> ApprovalExecution {
    ApprovalExecution::new(
        approval_scope(),
        vec![StructuredToolName::FileWrite],
        "verification-v1",
    )
    .unwrap()
}

fn citation(freshness: EvidenceFreshness) -> EvidenceCitation {
    EvidenceCitation::new(
        SourceIdentity::new(
            ProjectId::new("project-1").unwrap(),
            "revision-1",
            "src/lib.rs",
            digest('f'),
        )
        .unwrap(),
        Some(LineRange::new(1, 2).unwrap()),
        Some("symbol"),
        freshness,
    )
    .unwrap()
}

fn artifact_id(value: &str) -> ArtifactId {
    ArtifactId::new(value).unwrap()
}

fn actor_id() -> ActorId {
    ActorId::new("user-1").unwrap()
}

fn base_commit() -> GitObjectId {
    GitObjectId::new("a".repeat(40)).unwrap()
}

fn run_id(value: &str) -> RunId {
    RunId::new(value).unwrap()
}

fn task_id() -> TaskId {
    TaskId::new("task-1").unwrap()
}

fn digest(value: char) -> Sha256Digest {
    Sha256Digest::new(format!("sha256:{}", value.to_string().repeat(64))).unwrap()
}
