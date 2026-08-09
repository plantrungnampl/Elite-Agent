use std::sync::{Arc, Mutex};

use local_agent_terminal_application::{
    DeliberationCommandContext, DeliberationCommands, DeliberationSnapshot, DeliberationStore,
    PortError, Retryability, SafeErrorClassification,
};
use local_agent_terminal_domain::{
    ActorId, ArtifactId, ClaimVerification, DecisionApproach, DecisionPackage, Dissent,
    EvidenceCitation, EvidenceFreshness, IndependentProposal, IndependentQuorum, MaterialClaim,
    ObjectionSeverity, Phase, ProjectId, RejectedApproach, RunId, Sha256Digest, SourceIdentity,
    TaskId, VerificationMethod,
};

#[derive(Default)]
struct Writes {
    private: usize,
    published: usize,
    decisions: usize,
    closed: usize,
}

struct Store {
    snapshot: Mutex<DeliberationSnapshot>,
    writes: Arc<Mutex<Writes>>,
}

impl DeliberationStore for Store {
    fn load(&self, _: &TaskId) -> Result<DeliberationSnapshot, PortError> {
        Ok(self.snapshot.lock().unwrap().clone())
    }

    fn record_private_proposal(
        &self,
        _: &DeliberationCommandContext,
        _: IndependentProposal,
    ) -> Result<(), PortError> {
        self.writes.lock().unwrap().private += 1;
        Ok(())
    }

    fn publish_proposals(
        &self,
        _: &DeliberationCommandContext,
        proposals: Vec<IndependentProposal>,
    ) -> Result<(), PortError> {
        assert!(proposals.iter().all(IndependentProposal::is_revealed));
        self.writes.lock().unwrap().published += 1;
        Ok(())
    }

    fn record_decision(
        &self,
        _: &DeliberationCommandContext,
        _: DecisionPackage,
    ) -> Result<(), PortError> {
        self.writes.lock().unwrap().decisions += 1;
        Ok(())
    }

    fn close_objection_round(&self, _: &DeliberationCommandContext) -> Result<(), PortError> {
        self.writes.lock().unwrap().closed += 1;
        Ok(())
    }
}

#[test]
fn deliberation_store_is_object_safe() {
    fn accepts(_: &dyn DeliberationStore) {}
    let (store, _) = store(snapshot(Phase::ParallelAnalysis));
    accepts(&store);
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
        let (store, writes) = store(state);
        let commands = DeliberationCommands::new(&store);
        assert!(commands.publish_proposals(context).is_err());
        assert_eq!(writes.lock().unwrap().published, 0);
    }
}

#[test]
fn proposal_publication_requires_independent_quorum() {
    let mut state = snapshot(Phase::ParallelAnalysis);
    state.quorum = None;
    let (store, writes) = store(state);

    assert!(DeliberationCommands::new(&store)
        .publish_proposals(command("task-1", 7, "actor-1"))
        .is_err());
    assert_eq!(writes.lock().unwrap().published, 0);

    *store.snapshot.lock().unwrap() = snapshot(Phase::ParallelAnalysis);
    DeliberationCommands::new(&store)
        .publish_proposals(command("task-1", 7, "actor-1"))
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
    let (store, writes) = store(state);

    assert!(DeliberationCommands::new(&store)
        .publish_proposals(command("task-1", 7, "actor-1"))
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
fn synthesis_rejects_an_incomplete_authoritative_claim_set() {
    let mut state = snapshot(Phase::Synthesis);
    state.claims = vec![claim("claim-unchecked", false)];
    let (store, writes) = store(state);

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
        let (store, writes) = store(state);

        assert!(DeliberationCommands::new(&store)
            .synthesize(
                command("task-1", 7, "actor-1"),
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
        let (store, writes) = store(state);

        assert!(DeliberationCommands::new(&store)
            .synthesize(
                command("task-1", 7, "actor-1"),
                decision_with_claims(decision_claims),
            )
            .is_err());
        assert_eq!(writes.lock().unwrap().decisions, 0);
    }

    let mut state = snapshot(Phase::Synthesis);
    state.claims = vec![claim("claim-b", true), claim("claim-a", true)];
    let (store, writes) = store(state);
    DeliberationCommands::new(&store)
        .synthesize(
            command("task-1", 7, "actor-1"),
            decision_with_claims(vec![claim("claim-a", true), claim("claim-b", true)]),
        )
        .unwrap();
    assert_eq!(writes.lock().unwrap().decisions, 1);
}

#[test]
fn objection_round_cannot_close_while_an_accepted_severe_objection_remains() {
    let mut state = snapshot(Phase::FinalObjection);
    state.accepted_severe_objection = true;
    let (store, writes) = store(state);

    assert!(DeliberationCommands::new(&store)
        .close_objection_round(command("task-1", 7, "actor-1"))
        .is_err());
    assert_eq!(writes.lock().unwrap().closed, 0);

    store.snapshot.lock().unwrap().accepted_severe_objection = false;
    DeliberationCommands::new(&store)
        .close_objection_round(command("task-1", 7, "actor-1"))
        .unwrap();
    assert_eq!(writes.lock().unwrap().closed, 1);
    let _: ObjectionSeverity = ObjectionSeverity::Severe;
}

fn store(snapshot: DeliberationSnapshot) -> (Store, Arc<Mutex<Writes>>) {
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
        phase,
        task_version: 7,
        authorized_actors: vec![ActorId::new("actor-1").unwrap()],
        quorum: Some(IndependentQuorum::new(vec![proposal(1), proposal(2)]).unwrap()),
        claims: Vec::new(),
        accepted_severe_objection: false,
    }
}

fn command(task: &str, version: u64, actor: &str) -> DeliberationCommandContext {
    DeliberationCommandContext {
        task_id: TaskId::new(task).unwrap(),
        expected_task_version: version,
        actor_id: ActorId::new(actor).unwrap(),
    }
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
