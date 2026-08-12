use std::collections::{BTreeMap, BTreeSet};
use std::sync::Mutex;

use local_agent_terminal_application::{
    recover_deliberation, CanonicalDeliberationFact, DeliberationArtifactRef,
    DeliberationBoundaryCheck, DeliberationBoundaryRecord, DeliberationBoundaryStore,
    DeliberationClaimCandidate, DeliberationClaimSource, DeliberationCommandContext,
    DeliberationPersistenceCommand, DeliberationPlanDto, DeliberationRecord,
    DeliberationRecoveryInput, DeliberationRejectedAlternativeDto, DeliberationRepositoryAuthority,
    DeliberationRunAssignment, DeliberationSnapshot, DeliberationStore,
    DeliberationSynthesisCommand, DeliberationSynthesisStore, PortError,
};
use local_agent_terminal_domain::{
    ActorId, AgentFamilyKey, ArtifactId, ClaimVerification, Condition, DecisionApproach,
    DecisionPackage, DeliberationBudget, DeliberationLimits, DeliberationTaskBudget, Dissent,
    EventId, EvidenceCitation, EvidenceFreshness, FencingToken, GitObjectId, IndependentProposal,
    IndependentQuorum, LineRange, MaterialClaim, OperationState, ProjectId, RejectedApproach,
    ReviewEdge, ReviewPlan, RunId, Sequence, Sha256Digest, SourceIdentity, SpecialistBudget,
    SpecialistRequest, TaskId, Timestamp, VerificationMethod, WorkflowState, WorkspaceFingerprint,
    WorkspaceVersion,
};
use local_agent_terminal_orchestration::{
    assign_bounded_reviews, authorize_specialist, classify_material_claims,
    extract_material_claims, normalize_material_claims, AgentEligibility, DeliberationCoordinator,
    SpecialistDenial, SynthesisRequest,
};

#[test]
fn review_assignment_is_bounded_deterministic_and_not_a_broadcast() {
    let reviewers = vec![
        eligible("agent-a", "run-a", "family-a", &["review"]),
        eligible("agent-b", "run-b", "family-b", &["review"]),
        eligible("agent-c", "run-c", "family-c", &["review"]),
    ];
    let proposals = vec![artifact("proposal-a"), artifact("proposal-b")];
    let plan = assign_bounded_reviews(
        &reviewers,
        &proposals,
        1,
        DeliberationLimits::new(3, 2, 2, 2).unwrap(),
    )
    .unwrap();

    assert_eq!(plan.edges().len(), 2);
    assert_eq!(
        plan.edges()
            .iter()
            .map(|edge| edge.target_proposal())
            .collect::<BTreeSet<_>>()
            .len(),
        2
    );
    assert!(plan.edges().len() < reviewers.len() * proposals.len());
}

#[test]
fn specialist_request_is_bounded_and_denial_is_typed() {
    let request = SpecialistRequest::new(
        "specialist-request-1",
        task(),
        RunId::new("run-a").unwrap(),
        "security",
        "Review the risk.",
        vec![artifact("thread-context")],
        SpecialistBudget::new(50, 500, Timestamp::from_unix_seconds(100)).unwrap(),
    )
    .unwrap();
    let candidates = vec![eligible(
        "agent-security",
        "run-security",
        "family-security",
        &["security"],
    )];
    let mut budget = DeliberationBudget::new(40, 1).unwrap();

    assert_eq!(
        authorize_specialist(
            &request,
            &candidates,
            &mut budget,
            Timestamp::from_unix_seconds(1)
        ),
        Err(SpecialistDenial::BudgetExceeded)
    );

    let mut budget = DeliberationBudget::new(100, 1).unwrap();
    let selected = authorize_specialist(
        &request,
        &candidates,
        &mut budget,
        Timestamp::from_unix_seconds(1),
    )
    .unwrap();
    assert_eq!(selected.agent_id(), "agent-security");
    assert_eq!(budget.used_tokens(), 50);
}

#[test]
fn deterministic_claim_checks_run_first_and_stale_citations_cannot_verify() {
    let claims = vec![
        claim(
            "claim-source",
            VerificationMethod::SourceMatch,
            EvidenceFreshness::Current,
        ),
        claim(
            "claim-deterministic",
            VerificationMethod::DeterministicCheck,
            EvidenceFreshness::Current,
        ),
    ];
    let normalized = normalize_material_claims(claims).unwrap();
    let order = std::cell::RefCell::new(Vec::new());
    let classified = classify_material_claims(normalized, |claim| {
        order.borrow_mut().push(claim.claim_id().to_owned());
        Ok(ClaimVerification::Verified)
    })
    .unwrap();

    assert_eq!(*order.borrow(), vec!["claim-deterministic", "claim-source"]);
    assert!(classified
        .iter()
        .all(|claim| claim.verification() == Some(ClaimVerification::Verified)));

    let stale = vec![claim(
        "claim-stale",
        VerificationMethod::SourceMatch,
        EvidenceFreshness::Stale,
    )];
    assert!(classify_material_claims(stale, |_| Ok(ClaimVerification::Verified)).is_err());
}

#[test]
fn stable_claim_extraction_promotes_only_durable_core_accepted_summaries() {
    let snapshot = synthesis_snapshot(vec![
        classified_claim("claim-verified", ClaimVerification::Verified),
        classified_claim("claim-inconclusive", ClaimVerification::Inconclusive),
    ]);
    let source = ClaimAuthorityStore::new([
        (
            "proposal-1",
            vec![claim_candidate(
                "claim-proposal",
                VerificationMethod::SourceMatch,
            )],
        ),
        ("proposal-2", Vec::new()),
        (
            "summary-a",
            vec![claim_candidate(
                "claim-summary",
                VerificationMethod::DeterministicCheck,
            )],
        ),
    ]);

    let extracted = extract_material_claims(&snapshot, &source).unwrap();
    let reordered = extract_material_claims(&snapshot, &source).unwrap();

    assert_eq!(extracted, reordered);
    assert_eq!(
        extracted
            .iter()
            .map(|claim| (claim.claim_id(), claim.artifact_id().as_str()))
            .collect::<Vec<_>>(),
        vec![
            ("claim-proposal", "proposal-1"),
            ("claim-summary", "summary-a"),
        ]
    );
    assert_eq!(
        *source.requested.lock().unwrap(),
        vec![
            "proposal-1",
            "proposal-2",
            "summary-a",
            "proposal-1",
            "proposal-2",
            "summary-a",
        ]
    );
}

#[test]
fn synthesis_validates_complete_plan_and_persists_through_application_commands() {
    let claims = vec![
        classified_claim("claim-verified", ClaimVerification::Verified),
        classified_claim("claim-inconclusive", ClaimVerification::Inconclusive),
    ];
    let decision = decision(claims.clone());
    let store = SynthesisStore {
        snapshot: synthesis_snapshot(claims),
        ordinary_writes: Mutex::new(Vec::new()),
        synthesis_writes: Mutex::new(Vec::new()),
        fault_after_commit: Mutex::new(false),
    };

    let repository = FixedRepositoryAuthority;
    let boundaries = SynthesisBoundaryStore::default();
    DeliberationCoordinator::new(&repository, &boundaries, &store)
        .synthesize(SynthesisRequest {
            context: synthesis_context(),
            decision: decision.clone(),
            plan: plan_dto(),
            plan_artifact: deliberation_artifact("plan-1", '4'),
            plan_version: 1,
        })
        .unwrap();

    assert!(store.ordinary_writes.lock().unwrap().is_empty());
    let writes = store.synthesis_writes.lock().unwrap();
    assert_eq!(writes.len(), 1);
    assert_eq!(writes[0].plan(), &plan_dto());
    assert!(matches!(
        writes[0].persistence().record(),
        DeliberationRecord::DecisionDraft {
            decision: persisted,
            plan_artifact,
            plan_version: 1,
            ..
        } if persisted == &decision && plan_artifact.artifact_id().as_str() == "plan-1"
    ));
}

#[test]
fn synthesis_post_commit_fault_never_exposes_a_partial_decision_or_plan() {
    let claims = vec![
        classified_claim("claim-verified", ClaimVerification::Verified),
        classified_claim("claim-inconclusive", ClaimVerification::Inconclusive),
    ];
    let store = SynthesisStore {
        snapshot: synthesis_snapshot(claims.clone()),
        ordinary_writes: Mutex::new(Vec::new()),
        synthesis_writes: Mutex::new(Vec::new()),
        fault_after_commit: Mutex::new(true),
    };
    let repository = FixedRepositoryAuthority;
    let boundaries = SynthesisBoundaryStore::default();

    assert!(
        DeliberationCoordinator::new(&repository, &boundaries, &store)
            .synthesize(SynthesisRequest {
                context: synthesis_context(),
                decision: decision(claims),
                plan: plan_dto(),
                plan_artifact: deliberation_artifact("plan-1", '4'),
                plan_version: 1,
            })
            .is_err()
    );

    assert!(store.ordinary_writes.lock().unwrap().is_empty());
    let durable = store.synthesis_writes.lock().unwrap();
    assert_eq!(durable.len(), 1);
    durable[0].validate().unwrap();
    assert_eq!(durable[0].plan(), &plan_dto());
}

#[test]
fn synthesis_rejects_dto_divergence_before_application_persistence() {
    let claims = vec![
        classified_claim("claim-verified", ClaimVerification::Verified),
        classified_claim("claim-inconclusive", ClaimVerification::Inconclusive),
    ];
    let store = SynthesisStore {
        snapshot: synthesis_snapshot(claims.clone()),
        ordinary_writes: Mutex::new(Vec::new()),
        synthesis_writes: Mutex::new(Vec::new()),
        fault_after_commit: Mutex::new(false),
    };
    let mut plan = plan_dto();
    plan.selected_approach_id = "approach-forged".to_owned();

    let repository = FixedRepositoryAuthority;
    let boundaries = SynthesisBoundaryStore::default();
    assert!(
        DeliberationCoordinator::new(&repository, &boundaries, &store)
            .synthesize(SynthesisRequest {
                context: synthesis_context(),
                decision: decision(claims),
                plan,
                plan_artifact: deliberation_artifact("plan-1", '4'),
                plan_version: 1,
            })
            .is_err()
    );
    assert!(store.ordinary_writes.lock().unwrap().is_empty());
    assert!(store.synthesis_writes.lock().unwrap().is_empty());
}

fn eligible(agent: &str, run: &str, family: &str, capabilities: &[&str]) -> AgentEligibility {
    AgentEligibility {
        assignment: DeliberationRunAssignment::new(
            RunId::new(run).unwrap(),
            agent,
            AgentFamilyKey::new(family).unwrap(),
            ActorId::new(agent).unwrap(),
        )
        .unwrap(),
        capabilities: capabilities
            .iter()
            .map(|value| (*value).to_owned())
            .collect(),
        available: true,
    }
}

fn claim(id: &str, method: VerificationMethod, freshness: EvidenceFreshness) -> MaterialClaim {
    MaterialClaim::new(
        id,
        "agent-a",
        artifact("proposal-a"),
        vec![EvidenceCitation::new(
            SourceIdentity::new(
                ProjectId::new("project-1").unwrap(),
                "0123456789012345678901234567890123456789",
                "src/lib.rs",
                Sha256Digest::new(format!("sha256:{}", "a".repeat(64))).unwrap(),
            )
            .unwrap(),
            Some(LineRange::new(1, 2).unwrap()),
            None,
            freshness,
        )
        .unwrap()],
        method,
    )
    .unwrap()
}

fn claim_candidate(id: &str, method: VerificationMethod) -> DeliberationClaimCandidate {
    DeliberationClaimCandidate::new(
        id,
        "agent-a",
        vec![EvidenceCitation::new(
            SourceIdentity::new(
                ProjectId::new("project-1").unwrap(),
                "0123456789012345678901234567890123456789",
                "src/lib.rs",
                Sha256Digest::new(format!("sha256:{}", "a".repeat(64))).unwrap(),
            )
            .unwrap(),
            Some(LineRange::new(1, 2).unwrap()),
            None,
            EvidenceFreshness::Current,
        )
        .unwrap()],
        method,
    )
    .unwrap()
}

struct SynthesisStore {
    snapshot: DeliberationSnapshot,
    ordinary_writes: Mutex<Vec<DeliberationPersistenceCommand>>,
    synthesis_writes: Mutex<Vec<DeliberationSynthesisCommand>>,
    fault_after_commit: Mutex<bool>,
}

struct ClaimAuthorityStore {
    candidates: BTreeMap<String, Vec<DeliberationClaimCandidate>>,
    requested: Mutex<Vec<String>>,
}

impl ClaimAuthorityStore {
    fn new<const N: usize>(entries: [(&str, Vec<DeliberationClaimCandidate>); N]) -> Self {
        Self {
            candidates: entries
                .into_iter()
                .map(|(artifact_id, claims)| (artifact_id.to_owned(), claims))
                .collect(),
            requested: Mutex::new(Vec::new()),
        }
    }
}

impl DeliberationClaimSource for ClaimAuthorityStore {
    fn claims_for_artifact(
        &self,
        _: &TaskId,
        artifact: &DeliberationArtifactRef,
    ) -> Result<Vec<DeliberationClaimCandidate>, PortError> {
        let artifact_id = artifact.artifact_id().as_str();
        self.requested.lock().unwrap().push(artifact_id.to_owned());
        Ok(self
            .candidates
            .get(artifact_id)
            .cloned()
            .unwrap_or_default())
    }
}

struct FixedRepositoryAuthority;

impl DeliberationRepositoryAuthority for FixedRepositoryAuthority {
    fn current_fingerprint(&self, _: &TaskId) -> Result<WorkspaceFingerprint, PortError> {
        Ok(repository_fingerprint())
    }
}

#[derive(Default)]
struct SynthesisBoundaryStore {
    records: Mutex<Vec<DeliberationBoundaryRecord>>,
}

impl DeliberationBoundaryStore for SynthesisBoundaryStore {
    fn compare_and_persist_boundary(
        &self,
        check: DeliberationBoundaryCheck,
    ) -> Result<DeliberationBoundaryRecord, PortError> {
        let record = check.compare_with(repository_fingerprint())?;
        self.records.lock().unwrap().push(record.clone());
        Ok(record)
    }
}

impl DeliberationStore for SynthesisStore {
    fn load(&self, _: &TaskId) -> Result<DeliberationSnapshot, PortError> {
        Ok(self.snapshot.clone())
    }

    fn persist(&self, command: DeliberationPersistenceCommand) -> Result<(), PortError> {
        command.validate()?;
        self.ordinary_writes.lock().unwrap().push(command);
        Ok(())
    }
}

impl DeliberationSynthesisStore for SynthesisStore {
    fn persist_synthesis(&self, command: DeliberationSynthesisCommand) -> Result<(), PortError> {
        command.validate()?;
        self.synthesis_writes.lock().unwrap().push(command);
        let mut fault = self.fault_after_commit.lock().unwrap();
        if *fault {
            *fault = false;
            return Err(PortError::failure(
                local_agent_terminal_application::SafeErrorClassification::Internal,
                local_agent_terminal_application::Retryability::Retryable,
            ));
        }
        Ok(())
    }
}

fn synthesis_snapshot(classified: Vec<MaterialClaim>) -> DeliberationSnapshot {
    let unclassified = classified
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
        .collect::<Vec<_>>();
    recover_deliberation(DeliberationRecoveryInput {
        task_id: task(),
        task_version: 6,
        task_state: synthesis_state(),
        run_assignments: vec![run_assignment(1), run_assignment(2)],
        facts: vec![
            private_fact(proposal(1), 1),
            private_fact(proposal(2), 2),
            CanonicalDeliberationFact::issue(
                task(),
                EventId::new("event-quorum").unwrap(),
                3,
                ActorId::new("core").unwrap(),
                DeliberationRecord::QuorumPublication {
                    proposals: IndependentQuorum::new(vec![proposal(1), proposal(2)])
                        .unwrap()
                        .reveal(),
                    proposal_artifact: deliberation_artifact("proposal-bundle", '8'),
                    review_plan: review_plan(),
                    review_artifact: deliberation_artifact("review-plan", '9'),
                },
            )
            .unwrap(),
            CanonicalDeliberationFact::issue(
                task(),
                EventId::new("event-summary-a").unwrap(),
                4,
                ActorId::new("core").unwrap(),
                DeliberationRecord::ThreadSummary {
                    thread_id: "thread-a".to_owned(),
                    artifact: deliberation_artifact("summary-a", '2'),
                },
            )
            .unwrap(),
            CanonicalDeliberationFact::issue(
                task(),
                EventId::new("event-claim-set").unwrap(),
                5,
                ActorId::new("core").unwrap(),
                DeliberationRecord::ClaimSet {
                    claims: unclassified,
                    artifact: deliberation_artifact("claim-set", '3'),
                },
            )
            .unwrap(),
            CanonicalDeliberationFact::issue(
                task(),
                EventId::new("event-verification-set").unwrap(),
                6,
                ActorId::new("core").unwrap(),
                DeliberationRecord::VerificationSet {
                    claims: classified,
                    artifact: deliberation_artifact("verification-set", '4'),
                },
            )
            .unwrap(),
        ],
    })
    .unwrap()
}

fn synthesis_context() -> DeliberationCommandContext {
    DeliberationCommandContext::new(
        task(),
        6,
        synthesis_state(),
        DeliberationTaskBudget::new(
            4,
            100_000,
            10_000,
            Timestamp::from_unix_seconds(2_000_000_000),
        )
        .unwrap(),
        ActorId::new("core").unwrap(),
        deliberation_artifact("decision-draft", '5'),
        EventId::new("event-decision-draft").unwrap(),
        "task-1:synthesis",
        "2026-08-11T00:00:00Z",
    )
    .unwrap()
}

fn synthesis_state() -> WorkflowState {
    WorkflowState::new(
        local_agent_terminal_domain::Phase::Synthesis,
        Condition::Active,
        OperationState::None,
        Sequence::new(6),
        WorkspaceVersion::new(1),
        FencingToken::new(1).unwrap(),
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

fn proposal(number: u8) -> IndependentProposal {
    IndependentProposal::new(
        task(),
        RunId::new(format!("run-{number}")).unwrap(),
        &format!("agent-{number}"),
        AgentFamilyKey::new(format!("family-{number}")).unwrap(),
        artifact(&format!("proposal-{number}")),
        vec![citation()],
    )
    .unwrap()
}

fn private_fact(proposal: IndependentProposal, event_sequence: u64) -> CanonicalDeliberationFact {
    CanonicalDeliberationFact::issue(
        task(),
        EventId::new(format!("event-private-{event_sequence}")).unwrap(),
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
            receipt: deliberation_artifact(&format!("receipt-{event_sequence}"), '6'),
        },
    )
    .unwrap()
}

fn review_plan() -> ReviewPlan {
    ReviewPlan::new(
        DeliberationLimits::new(4, 2, 8, 2).unwrap(),
        vec![
            ReviewEdge::new("agent-2", artifact("proposal-1"), 1).unwrap(),
            ReviewEdge::new("agent-1", artifact("proposal-2"), 1).unwrap(),
        ],
    )
    .unwrap()
}

fn classified_claim(id: &str, verification: ClaimVerification) -> MaterialClaim {
    claim(
        id,
        VerificationMethod::SourceMatch,
        EvidenceFreshness::Current,
    )
    .classify(verification)
    .unwrap()
}

fn decision(evidence: Vec<MaterialClaim>) -> DecisionPackage {
    DecisionPackage::new(
        DecisionApproach::new(
            "approach-a",
            artifact("proposal-1"),
            vec!["claim-verified".to_owned()],
        )
        .unwrap(),
        vec![RejectedApproach::new(
            DecisionApproach::new("approach-b", artifact("proposal-2"), Vec::new()).unwrap(),
            "higher risk",
        )
        .unwrap()],
        evidence,
        vec![Dissent::new(
            "dissent-1",
            "agent-2",
            artifact("proposal-2"),
            "prefer the rejected alternative",
        )
        .unwrap()],
        artifact("plan-1"),
    )
    .unwrap()
}

fn plan_dto() -> DeliberationPlanDto {
    DeliberationPlanDto {
        selected_approach_id: "approach-a".to_owned(),
        rejected_alternatives: vec![DeliberationRejectedAlternativeDto {
            approach_id: "approach-b".to_owned(),
            reason: "higher risk".to_owned(),
        }],
        verified_claim_ids: vec!["claim-verified".to_owned()],
        inconclusive_claim_ids: vec!["claim-inconclusive".to_owned()],
        dissent_ids: vec!["dissent-1".to_owned()],
        affected_files: vec!["crates/orchestration/src/coordinator.rs".to_owned()],
        implementation_steps: vec!["persist before dispatch".to_owned()],
        planned_tools: vec!["cargo.test".to_owned()],
        verification_profile: "m4-task-7".to_owned(),
        rollback_plan: "revert the local commit".to_owned(),
        risk: "medium".to_owned(),
        estimated_cost_microunits: Some(12),
        estimated_duration_seconds: Some(30),
        confidence: 82,
    }
}

fn deliberation_artifact(id: &str, character: char) -> DeliberationArtifactRef {
    DeliberationArtifactRef::new(artifact(id), digest(character), 17).unwrap()
}

fn citation() -> EvidenceCitation {
    EvidenceCitation::new(
        SourceIdentity::new(
            ProjectId::new("project-1").unwrap(),
            "0123456789012345678901234567890123456789",
            "src/lib.rs",
            digest('a'),
        )
        .unwrap(),
        Some(LineRange::new(1, 2).unwrap()),
        None,
        EvidenceFreshness::Current,
    )
    .unwrap()
}

fn digest(character: char) -> Sha256Digest {
    Sha256Digest::new(format!("sha256:{}", character.to_string().repeat(64))).unwrap()
}

fn repository_fingerprint() -> WorkspaceFingerprint {
    WorkspaceFingerprint::new(
        GitObjectId::new("0123456789012345678901234567890123456789").unwrap(),
        format!("sha256:{}", "e".repeat(64)),
        format!("sha256:{}", "f".repeat(64)),
    )
    .unwrap()
}

fn artifact(value: &str) -> ArtifactId {
    ArtifactId::new(value).unwrap()
}

fn task() -> TaskId {
    TaskId::new("task-1").unwrap()
}

#[allow(dead_code)]
fn commit() -> GitObjectId {
    GitObjectId::new("0123456789012345678901234567890123456789").unwrap()
}
