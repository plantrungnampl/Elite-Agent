use local_agent_terminal_domain::{
    ActorId, AgentFamilyKey, ArtifactId, ClaimVerification, DecisionApproach, DecisionPackage,
    DeliberationLimits, Dissent, EventId, EvidenceCitation, EvidenceFreshness, FinalObjection,
    FinalObjectionSet, IndependentProposal, IndependentQuorum, LineRange, MaterialClaim,
    ObjectionSeverity, Phase, ProjectId, RejectedApproach, ReviewEdge, ReviewPlan, RunId,
    Sha256Digest, SourceIdentity, SpecialistBudget, SpecialistRequest, TaskId, Timestamp,
    VerificationMethod, WorkflowState,
};
use serde::{Deserialize, Serialize};

use crate::deliberation::{
    review_plan_is_authorized, ClaimSetSnapshot, DecisionDraftSnapshot,
    ObjectionRoundClosedSnapshot, ObjectionSetSnapshot, RecoveredDeliberationState,
    SevereObjectionAcceptanceSnapshot, SupersessionSnapshot, VerificationSetSnapshot,
};
use crate::{
    canonical_json::sha256_digest, ApprovalId, DeliberationArtifactRef, DeliberationRecord,
    DeliberationRunAssignment, DeliberationSnapshot, NewPlanApproval, NewPlanApprovalRehydration,
    PlanApprovalRequestArtifact, PortError, PrivateProposalSnapshot, QuorumPublicationSnapshot,
    Retryability, ReviewEdgesSnapshot, SafeErrorClassification, SpecialistRequestSnapshot,
    ThreadSummarySnapshot,
};

const DELIBERATION_RECORD_SCHEMA: &str = "deliberation-record.v1";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanonicalDeliberationFact {
    task_id: TaskId,
    event_id: EventId,
    event_sequence: u64,
    actor_id: ActorId,
    actor_type: String,
    observation_class: String,
    record: DeliberationRecord,
    canonical_bytes: Vec<u8>,
    content_digest: Sha256Digest,
}

impl CanonicalDeliberationFact {
    pub fn issue(
        task_id: TaskId,
        event_id: EventId,
        event_sequence: u64,
        actor_id: ActorId,
        record: DeliberationRecord,
    ) -> Result<Self, PortError> {
        if event_sequence == 0 {
            return Err(invalid_input());
        }
        record.validate(&task_id)?;
        let (actor_type, observation_class) = record.authority_labels(&actor_id)?;
        let envelope = DeliberationFactEnvelopeV1 {
            schema: DELIBERATION_RECORD_SCHEMA.to_owned(),
            schema_version: 1,
            task_id: task_id.as_str().to_owned(),
            event_id: event_id.as_str().to_owned(),
            event_sequence,
            event_type: record.event_type().to_owned(),
            actor_type: actor_type.to_owned(),
            actor_id: actor_id.as_str().to_owned(),
            observation_class: observation_class.to_owned(),
            fact: fact_from_record(&record)?,
        };
        let value = serde_json::to_value(&envelope).map_err(|_| integrity_failure())?;
        let canonical_bytes =
            serde_json_canonicalizer::to_vec(&value).map_err(|_| integrity_failure())?;
        let content_digest = digest(&canonical_bytes)?;
        Ok(Self {
            task_id,
            event_id,
            event_sequence,
            actor_id,
            actor_type: actor_type.to_owned(),
            observation_class: observation_class.to_owned(),
            record,
            canonical_bytes,
            content_digest,
        })
    }

    pub fn rehydrate(
        canonical_bytes: Vec<u8>,
        content_digest: Sha256Digest,
    ) -> Result<Self, PortError> {
        if digest(&canonical_bytes)? != content_digest {
            return Err(integrity_failure());
        }
        let value: serde_json::Value =
            serde_json::from_slice(&canonical_bytes).map_err(|_| integrity_failure())?;
        let recanonicalized =
            serde_json_canonicalizer::to_vec(&value).map_err(|_| integrity_failure())?;
        if recanonicalized != canonical_bytes {
            return Err(integrity_failure());
        }
        let envelope: DeliberationFactEnvelopeV1 =
            serde_json::from_value(value).map_err(|_| integrity_failure())?;
        if envelope.schema != DELIBERATION_RECORD_SCHEMA || envelope.schema_version != 1 {
            return Err(integrity_failure());
        }
        let task_id = TaskId::new(&envelope.task_id).map_err(|_| integrity_failure())?;
        let event_id = EventId::new(&envelope.event_id).map_err(|_| integrity_failure())?;
        let actor_id = ActorId::new(&envelope.actor_id).map_err(|_| integrity_failure())?;
        let record = record_from_fact(envelope.fact, &task_id)?;
        let reopened = Self::issue(task_id, event_id, envelope.event_sequence, actor_id, record)?;
        if reopened.canonical_bytes != canonical_bytes
            || reopened.content_digest != content_digest
            || reopened.actor_type != envelope.actor_type
            || reopened.observation_class != envelope.observation_class
            || reopened.record.event_type() != envelope.event_type
        {
            return Err(integrity_failure());
        }
        Ok(reopened)
    }

    pub fn task_id(&self) -> &TaskId {
        &self.task_id
    }

    pub fn event_id(&self) -> &EventId {
        &self.event_id
    }

    pub const fn event_sequence(&self) -> u64 {
        self.event_sequence
    }

    pub fn actor_id(&self) -> &ActorId {
        &self.actor_id
    }

    pub fn actor_type(&self) -> &str {
        &self.actor_type
    }

    pub fn observation_class(&self) -> &str {
        &self.observation_class
    }

    pub fn record(&self) -> &DeliberationRecord {
        &self.record
    }

    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical_bytes
    }

    pub fn content_digest(&self) -> &Sha256Digest {
        &self.content_digest
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeliberationRecoveryInput {
    pub task_id: TaskId,
    pub task_version: u64,
    pub task_state: WorkflowState,
    pub run_assignments: Vec<DeliberationRunAssignment>,
    pub facts: Vec<CanonicalDeliberationFact>,
}

pub fn recover_deliberation(
    input: DeliberationRecoveryInput,
) -> Result<DeliberationSnapshot, PortError> {
    if input.task_version != input.task_state.sequence().get()
        || !valid_assignments(&input.run_assignments)
    {
        return Err(conflict());
    }
    let mut previous_sequence = 0;
    let mut previous_event_ids = std::collections::BTreeSet::new();
    let mut private_proposals = Vec::new();
    let mut quorum = None;
    let mut quorum_publication = None;
    let mut specialist_requests = Vec::new();
    let mut review_edges = Vec::new();
    let mut thread_summaries = Vec::new();
    let mut claim_sets = Vec::new();
    let mut verification_sets = Vec::new();
    let mut decision_drafts = Vec::new();
    let mut objection_sets = Vec::new();
    let mut severe_objection_acceptances = Vec::new();
    let mut supersessions = Vec::new();
    let mut objection_round_closures = Vec::new();
    let mut replay_phase = Phase::ParallelAnalysis;
    for fact in &input.facts {
        if fact.task_id != input.task_id
            || fact.event_sequence <= previous_sequence
            || fact.event_sequence > input.task_version
            || !previous_event_ids.insert(fact.event_id.clone())
        {
            return Err(conflict());
        }
        previous_sequence = fact.event_sequence;
        match &fact.record {
            DeliberationRecord::PrivateProposal {
                proposal,
                proposal_artifact,
                receipt,
            } => {
                if replay_phase != Phase::ParallelAnalysis
                    || quorum.is_some()
                    || !input
                        .run_assignments
                        .iter()
                        .any(|assignment| assignment.matches(proposal, &fact.actor_id))
                    || private_proposals
                        .iter()
                        .any(|existing: &PrivateProposalSnapshot| {
                            existing.proposal().run_id() == proposal.run_id()
                                || existing.proposal().artifact_id() == proposal.artifact_id()
                        })
                {
                    return Err(conflict());
                }
                private_proposals.push(PrivateProposalSnapshot::new(
                    proposal.clone(),
                    proposal_artifact.clone(),
                    receipt.clone(),
                )?);
            }
            DeliberationRecord::QuorumPublication {
                proposals,
                proposal_artifact,
                review_plan: published_review_plan,
                review_artifact,
            } => {
                if replay_phase != Phase::ParallelAnalysis
                    || quorum.is_some()
                    || fact.actor_id.as_str() != "core"
                {
                    return Err(conflict());
                }
                let selected_private = proposals
                    .iter()
                    .map(|published| {
                        private_proposals
                            .iter()
                            .find(|record| {
                                record.proposal().artifact_id() == published.artifact_id()
                            })
                            .map(|record| record.proposal().clone())
                            .ok_or_else(conflict)
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                let expected_proposals = IndependentQuorum::new(selected_private)
                    .map_err(|_| conflict())?
                    .reveal();
                let expected_targets = expected_proposals
                    .iter()
                    .map(IndependentProposal::artifact_id)
                    .collect::<std::collections::BTreeSet<_>>();
                let actual_targets = published_review_plan
                    .edges()
                    .iter()
                    .map(|edge| edge.target_proposal())
                    .collect::<std::collections::BTreeSet<_>>();
                if proposals != &expected_proposals
                    || actual_targets != expected_targets
                    || published_review_plan.edges().iter().any(|edge| {
                        !input
                            .run_assignments
                            .iter()
                            .any(|assignment| assignment.agent_id() == edge.reviewer_id())
                    })
                {
                    return Err(conflict());
                }
                quorum = Some(
                    IndependentQuorum::from_revealed(proposals.clone()).map_err(|_| conflict())?,
                );
                quorum_publication = Some(QuorumPublicationSnapshot::new(
                    fact.event_id.clone(),
                    fact.event_sequence,
                    proposal_artifact.clone(),
                    published_review_plan.clone(),
                    review_artifact.clone(),
                )?);
                replay_phase = Phase::CrossReview;
            }
            DeliberationRecord::SpecialistRequest { request, artifact } => {
                if replay_phase != Phase::ParallelAnalysis
                    || quorum.is_some()
                    || !input
                        .run_assignments
                        .iter()
                        .any(|assignment| assignment.matches_specialist(request, &fact.actor_id))
                    || specialist_requests
                        .iter()
                        .any(|existing: &SpecialistRequestSnapshot| {
                            existing.request().request_id() == request.request_id()
                        })
                {
                    return Err(conflict());
                }
                specialist_requests.push(SpecialistRequestSnapshot::new(
                    fact.event_id.clone(),
                    fact.event_sequence,
                    fact.actor_id.clone(),
                    request.clone(),
                    artifact.clone(),
                )?);
            }
            DeliberationRecord::ReviewEdges { plan, artifact } => {
                let Some(publication) = &quorum_publication else {
                    return Err(conflict());
                };
                let (active_plan, active_artifact) = severe_objection_acceptances
                    .last()
                    .map(|accepted: &SevereObjectionAcceptanceSnapshot| {
                        (accepted.review_plan(), accepted.review_artifact())
                    })
                    .unwrap_or((publication.review_plan(), publication.review_artifact()));
                if replay_phase != Phase::CrossReview
                    || fact.actor_id.as_str() != "core"
                    || plan != active_plan
                    || artifact != active_artifact
                    || review_edges.iter().any(|existing: &ReviewEdgesSnapshot| {
                        existing.plan() == plan && existing.artifact() == artifact
                    })
                {
                    return Err(conflict());
                }
                review_edges.push(ReviewEdgesSnapshot::new(
                    fact.event_id.clone(),
                    fact.event_sequence,
                    fact.actor_id.clone(),
                    plan.clone(),
                    artifact.clone(),
                )?);
            }
            DeliberationRecord::ThreadSummary {
                thread_id,
                artifact,
            } => {
                if replay_phase != Phase::CrossReview
                    || quorum.is_none()
                    || fact.actor_id.as_str() != "core"
                    || thread_summaries
                        .iter()
                        .any(|existing: &ThreadSummarySnapshot| existing.thread_id() == thread_id)
                {
                    return Err(conflict());
                }
                thread_summaries.push(ThreadSummarySnapshot::new(
                    fact.event_id.clone(),
                    fact.event_sequence,
                    fact.actor_id.clone(),
                    thread_id.clone(),
                    artifact.clone(),
                )?);
            }
            DeliberationRecord::ClaimSet { claims, artifact } => {
                if replay_phase != Phase::CrossReview
                    || quorum.is_none()
                    || fact.actor_id.as_str() != "core"
                    || claim_sets.len() != decision_drafts.len()
                    || verification_sets.len() != claim_sets.len()
                    || (!claim_sets.is_empty()
                        && severe_objection_acceptances.len() != claim_sets.len())
                {
                    return Err(conflict());
                }
                claim_sets.push(ClaimSetSnapshot::new(
                    fact.event_id.clone(),
                    fact.event_sequence,
                    fact.actor_id.clone(),
                    claims.clone(),
                    artifact.clone(),
                )?);
                replay_phase = Phase::PrePlanVerification;
            }
            DeliberationRecord::VerificationSet { claims, artifact } => {
                let Some(original) = claim_sets.last() else {
                    return Err(conflict());
                };
                if replay_phase != Phase::PrePlanVerification
                    || fact.actor_id.as_str() != "core"
                    || verification_sets.len() + 1 != claim_sets.len()
                    || !super::deliberation::same_claim_authority(original.claims(), claims)
                {
                    return Err(conflict());
                }
                verification_sets.push(VerificationSetSnapshot::new(
                    fact.event_id.clone(),
                    fact.event_sequence,
                    fact.actor_id.clone(),
                    claims.clone(),
                    artifact.clone(),
                )?);
                replay_phase = Phase::Synthesis;
            }
            DeliberationRecord::DecisionDraft {
                decision,
                artifact,
                plan_artifact,
                plan_version,
            } => {
                let Some(verification) = verification_sets.last() else {
                    return Err(conflict());
                };
                let replacement_matches = if decision_drafts.is_empty() {
                    supersessions.is_empty()
                } else {
                    supersessions
                        .last()
                        .is_some_and(|supersession: &SupersessionSnapshot| {
                            supersessions.len() == decision_drafts.len()
                                && supersession.replacement() == artifact
                        })
                };
                if replay_phase != Phase::Synthesis
                    || fact.actor_id.as_str() != "core"
                    || decision_drafts.len() + 1 != verification_sets.len()
                    || !replacement_matches
                    || !super::deliberation::same_claim_records(
                        verification.claims(),
                        decision.evidence(),
                    )
                {
                    return Err(conflict());
                }
                decision_drafts.push(DecisionDraftSnapshot::new(
                    fact.event_id.clone(),
                    fact.event_sequence,
                    fact.actor_id.clone(),
                    decision.clone(),
                    artifact.clone(),
                    plan_artifact.clone(),
                    *plan_version,
                )?);
                replay_phase = Phase::FinalObjection;
            }
            DeliberationRecord::ObjectionSet {
                objections,
                artifact,
            } => {
                if replay_phase != Phase::FinalObjection
                    || fact.actor_id.as_str() != "core"
                    || objection_sets.len() + 1 != decision_drafts.len()
                    || severe_objection_acceptances.len() != objection_sets.len()
                    || objections.round() != objection_sets.len() as u32 + 1
                {
                    return Err(conflict());
                }
                objection_sets.push(ObjectionSetSnapshot::new(
                    fact.event_id.clone(),
                    fact.event_sequence,
                    fact.actor_id.clone(),
                    objections.clone(),
                    artifact.clone(),
                )?);
            }
            DeliberationRecord::ObjectionSevereAccepted {
                objections,
                objection_artifact,
                review_plan,
                review_artifact,
            } => {
                let Some(current) = objection_sets.last() else {
                    return Err(conflict());
                };
                let Some(active_quorum) = quorum.as_ref() else {
                    return Err(conflict());
                };
                if replay_phase != Phase::FinalObjection
                    || fact.actor_id.as_str() != "core"
                    || severe_objection_acceptances.len() + 1 != objection_sets.len()
                    || !severe_objection_acceptances.is_empty()
                    || objections != current.objections()
                    || objection_artifact != current.artifact()
                    || !review_plan_is_authorized(
                        active_quorum,
                        &input.run_assignments,
                        review_plan,
                    )
                {
                    return Err(conflict());
                }
                severe_objection_acceptances.push(SevereObjectionAcceptanceSnapshot::new(
                    fact.event_id.clone(),
                    fact.event_sequence,
                    fact.actor_id.clone(),
                    objections.clone(),
                    objection_artifact.clone(),
                    review_plan.clone(),
                    review_artifact.clone(),
                )?);
                replay_phase = Phase::CrossReview;
            }
            DeliberationRecord::Supersession {
                superseded,
                replacement,
            } => {
                let Some(current_decision) = decision_drafts.last() else {
                    return Err(conflict());
                };
                if replay_phase != Phase::Synthesis
                    || fact.actor_id.as_str() != "core"
                    || supersessions.len() + 1 != decision_drafts.len()
                    || verification_sets.len() != decision_drafts.len() + 1
                    || severe_objection_acceptances.len() != decision_drafts.len()
                    || superseded != current_decision.artifact()
                {
                    return Err(conflict());
                }
                supersessions.push(SupersessionSnapshot::new(
                    fact.event_id.clone(),
                    fact.event_sequence,
                    fact.actor_id.clone(),
                    superseded.clone(),
                    replacement.clone(),
                )?);
            }
            DeliberationRecord::ObjectionRoundClosed {
                artifact,
                plan_approval,
            } => {
                let Some(current_objections) = objection_sets.last() else {
                    return Err(conflict());
                };
                if replay_phase != Phase::FinalObjection
                    || fact.actor_id.as_str() != "core"
                    || !objection_round_closures.is_empty()
                    || severe_objection_acceptances.len() >= objection_sets.len()
                    || current_objections.event_sequence() >= fact.event_sequence
                {
                    return Err(conflict());
                }
                objection_round_closures.push(ObjectionRoundClosedSnapshot::new(
                    fact.event_id.clone(),
                    fact.event_sequence,
                    fact.actor_id.clone(),
                    artifact.clone(),
                    plan_approval.as_ref().clone(),
                )?);
                replay_phase = Phase::AwaitingPlanApproval;
            }
        }
    }
    if !input.facts.is_empty() && replay_phase != input.task_state.phase() {
        return Err(conflict());
    }
    DeliberationSnapshot::from_recovery(RecoveredDeliberationState {
        task_id: input.task_id,
        task_version: input.task_version,
        task_state: input.task_state,
        run_assignments: input.run_assignments,
        private_proposals,
        quorum,
        quorum_publication,
        specialist_requests,
        review_edges,
        thread_summaries,
        claim_sets,
        verification_sets,
        decision_drafts,
        objection_sets,
        severe_objection_acceptances,
        supersessions,
        objection_round_closures,
    })
}

fn valid_assignments(assignments: &[DeliberationRunAssignment]) -> bool {
    if assignments.is_empty() {
        return true;
    }
    let unique_runs = assignments
        .iter()
        .map(DeliberationRunAssignment::run_id)
        .collect::<std::collections::BTreeSet<_>>()
        .len();

    unique_runs == assignments.len()
        && assignments
            .iter()
            .all(|assignment| assignment.actor_id().as_str() == assignment.agent_id())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct DeliberationFactEnvelopeV1 {
    schema: String,
    schema_version: u8,
    task_id: String,
    event_id: String,
    event_sequence: u64,
    event_type: String,
    actor_type: String,
    actor_id: String,
    observation_class: String,
    fact: DeliberationFactV1,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
enum DeliberationFactV1 {
    PrivateProposal {
        proposal: ProposalV1,
        proposal_artifact: ArtifactRefV1,
        receipt: ArtifactRefV1,
    },
    QuorumPublication {
        proposals: Vec<ProposalV1>,
        proposal_artifact: ArtifactRefV1,
        review_plan: ReviewPlanV1,
        review_artifact: ArtifactRefV1,
    },
    ReviewEdges {
        plan: ReviewPlanV1,
        artifact: ArtifactRefV1,
    },
    ThreadSummary {
        thread_id: String,
        artifact: ArtifactRefV1,
    },
    SpecialistRequest {
        request: SpecialistRequestV1,
        artifact: ArtifactRefV1,
    },
    ClaimSet {
        claims: Vec<MaterialClaimV1>,
        artifact: ArtifactRefV1,
    },
    VerificationSet {
        claims: Vec<MaterialClaimV1>,
        artifact: ArtifactRefV1,
    },
    DecisionDraft {
        decision: DecisionPackageV1,
        artifact: ArtifactRefV1,
        plan_artifact: ArtifactRefV1,
        plan_version: u64,
    },
    ObjectionSet {
        objections: FinalObjectionSetV1,
        artifact: ArtifactRefV1,
    },
    ObjectionSevereAccepted {
        objections: FinalObjectionSetV1,
        objection_artifact: ArtifactRefV1,
        review_plan: ReviewPlanV1,
        review_artifact: ArtifactRefV1,
    },
    ObjectionRoundClosed {
        artifact: ArtifactRefV1,
        plan_approval: NewPlanApprovalV1,
    },
    Supersession {
        superseded: ArtifactRefV1,
        replacement: ArtifactRefV1,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ProposalV1 {
    task_id: String,
    run_id: String,
    agent_id: String,
    family: String,
    artifact_id: String,
    citations: Vec<CitationV1>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ReviewPlanV1 {
    edges: Vec<ReviewEdgeV1>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ReviewEdgeV1 {
    reviewer_id: String,
    target_proposal: String,
    round: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SpecialistRequestV1 {
    request_id: String,
    task_id: String,
    requesting_run: String,
    capability: String,
    reason: String,
    required_context: Vec<String>,
    budget: SpecialistBudgetV1,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SpecialistBudgetV1 {
    max_tokens: u64,
    deadline_unix_seconds: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct MaterialClaimV1 {
    claim_id: String,
    claimant: String,
    artifact_id: String,
    citations: Vec<CitationV1>,
    method: VerificationMethodV1,
    verification: Option<ClaimVerificationV1>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum VerificationMethodV1 {
    SourceMatch,
    DeterministicCheck,
    PolicyReview,
    NotApplicable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum ClaimVerificationV1 {
    Verified,
    Rejected,
    Inconclusive,
    NotApplicable,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct DecisionPackageV1 {
    selected: DecisionApproachV1,
    rejected: Vec<RejectedApproachV1>,
    evidence: Vec<MaterialClaimV1>,
    dissent: Vec<DissentV1>,
    plan_artifact_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct DecisionApproachV1 {
    approach_id: String,
    artifact_id: String,
    evidence_claim_ids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RejectedApproachV1 {
    approach: DecisionApproachV1,
    reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct DissentV1 {
    dissent_id: String,
    participant_id: String,
    artifact_id: String,
    reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct FinalObjectionSetV1 {
    round: u32,
    objections: Vec<FinalObjectionV1>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct FinalObjectionV1 {
    participant_id: String,
    round: u32,
    severity: ObjectionSeverityV1,
    impact: String,
    evidence: Vec<CitationV1>,
    violated_requirement: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum ObjectionSeverityV1 {
    Low,
    Moderate,
    Severe,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct NewPlanApprovalV1 {
    approval_id: String,
    canonical_bytes: Vec<u8>,
    operation_digest: String,
    request_artifact: PlanApprovalRequestArtifactV1,
    authority_binding_bytes: Vec<u8>,
    authority_binding_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PlanApprovalRequestArtifactV1 {
    artifact_id: String,
    content_digest: String,
    size_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ArtifactRefV1 {
    artifact_id: String,
    content_digest: String,
    size_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CitationV1 {
    project_id: String,
    revision: String,
    path_identity: String,
    content_hash: String,
    line_range: Option<LineRangeV1>,
    symbol: Option<String>,
    freshness: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct LineRangeV1 {
    start: u32,
    end: u32,
}

fn fact_from_record(record: &DeliberationRecord) -> Result<DeliberationFactV1, PortError> {
    match record {
        DeliberationRecord::PrivateProposal {
            proposal,
            proposal_artifact,
            receipt,
        } => Ok(DeliberationFactV1::PrivateProposal {
            proposal: proposal_to_v1(proposal),
            proposal_artifact: artifact_to_v1(proposal_artifact),
            receipt: artifact_to_v1(receipt),
        }),
        DeliberationRecord::QuorumPublication {
            proposals,
            proposal_artifact,
            review_plan,
            review_artifact,
        } => Ok(DeliberationFactV1::QuorumPublication {
            proposals: proposals.iter().map(proposal_to_v1).collect(),
            proposal_artifact: artifact_to_v1(proposal_artifact),
            review_plan: review_plan_to_v1(review_plan),
            review_artifact: artifact_to_v1(review_artifact),
        }),
        DeliberationRecord::ReviewEdges { plan, artifact } => Ok(DeliberationFactV1::ReviewEdges {
            plan: review_plan_to_v1(plan),
            artifact: artifact_to_v1(artifact),
        }),
        DeliberationRecord::ThreadSummary {
            thread_id,
            artifact,
        } => Ok(DeliberationFactV1::ThreadSummary {
            thread_id: thread_id.clone(),
            artifact: artifact_to_v1(artifact),
        }),
        DeliberationRecord::SpecialistRequest { request, artifact } => {
            Ok(DeliberationFactV1::SpecialistRequest {
                request: specialist_request_to_v1(request),
                artifact: artifact_to_v1(artifact),
            })
        }
        DeliberationRecord::ClaimSet { claims, artifact } => Ok(DeliberationFactV1::ClaimSet {
            claims: claims.iter().map(material_claim_to_v1).collect(),
            artifact: artifact_to_v1(artifact),
        }),
        DeliberationRecord::VerificationSet { claims, artifact } => {
            Ok(DeliberationFactV1::VerificationSet {
                claims: claims.iter().map(material_claim_to_v1).collect(),
                artifact: artifact_to_v1(artifact),
            })
        }
        DeliberationRecord::DecisionDraft {
            decision,
            artifact,
            plan_artifact,
            plan_version,
        } => Ok(DeliberationFactV1::DecisionDraft {
            decision: decision_package_to_v1(decision),
            artifact: artifact_to_v1(artifact),
            plan_artifact: artifact_to_v1(plan_artifact),
            plan_version: *plan_version,
        }),
        DeliberationRecord::ObjectionSet {
            objections,
            artifact,
        } => Ok(DeliberationFactV1::ObjectionSet {
            objections: objection_set_to_v1(objections),
            artifact: artifact_to_v1(artifact),
        }),
        DeliberationRecord::ObjectionSevereAccepted {
            objections,
            objection_artifact,
            review_plan,
            review_artifact,
        } => Ok(DeliberationFactV1::ObjectionSevereAccepted {
            objections: objection_set_to_v1(objections),
            objection_artifact: artifact_to_v1(objection_artifact),
            review_plan: review_plan_to_v1(review_plan),
            review_artifact: artifact_to_v1(review_artifact),
        }),
        DeliberationRecord::ObjectionRoundClosed {
            artifact,
            plan_approval,
        } => Ok(DeliberationFactV1::ObjectionRoundClosed {
            artifact: artifact_to_v1(artifact),
            plan_approval: plan_approval_to_v1(plan_approval),
        }),
        DeliberationRecord::Supersession {
            superseded,
            replacement,
        } => Ok(DeliberationFactV1::Supersession {
            superseded: artifact_to_v1(superseded),
            replacement: artifact_to_v1(replacement),
        }),
    }
}

fn record_from_fact(
    fact: DeliberationFactV1,
    task_id: &TaskId,
) -> Result<DeliberationRecord, PortError> {
    match fact {
        DeliberationFactV1::PrivateProposal {
            proposal,
            proposal_artifact,
            receipt,
        } => {
            let proposal = proposal_from_v1(proposal)?;
            if proposal.task_id() != task_id {
                return Err(integrity_failure());
            }
            Ok(DeliberationRecord::PrivateProposal {
                proposal,
                proposal_artifact: artifact_from_v1(proposal_artifact)?,
                receipt: artifact_from_v1(receipt)?,
            })
        }
        DeliberationFactV1::QuorumPublication {
            proposals,
            proposal_artifact,
            review_plan,
            review_artifact,
        } => {
            let private_proposals = proposals
                .into_iter()
                .map(proposal_from_v1)
                .collect::<Result<Vec<_>, _>>()?;
            if private_proposals
                .iter()
                .any(|proposal| proposal.task_id() != task_id)
            {
                return Err(integrity_failure());
            }
            let proposals = IndependentQuorum::new(private_proposals)
                .map_err(|_| integrity_failure())?
                .reveal();
            Ok(DeliberationRecord::QuorumPublication {
                proposals,
                proposal_artifact: artifact_from_v1(proposal_artifact)?,
                review_plan: review_plan_from_v1(review_plan)?,
                review_artifact: artifact_from_v1(review_artifact)?,
            })
        }
        DeliberationFactV1::ReviewEdges { plan, artifact } => Ok(DeliberationRecord::ReviewEdges {
            plan: review_plan_from_v1(plan)?,
            artifact: artifact_from_v1(artifact)?,
        }),
        DeliberationFactV1::ThreadSummary {
            thread_id,
            artifact,
        } => Ok(DeliberationRecord::ThreadSummary {
            thread_id,
            artifact: artifact_from_v1(artifact)?,
        }),
        DeliberationFactV1::SpecialistRequest { request, artifact } => {
            let request = specialist_request_from_v1(request)?;
            if request.task_id() != task_id {
                return Err(integrity_failure());
            }
            Ok(DeliberationRecord::SpecialistRequest {
                request,
                artifact: artifact_from_v1(artifact)?,
            })
        }
        DeliberationFactV1::ClaimSet { claims, artifact } => {
            let claims = claims
                .into_iter()
                .map(material_claim_from_v1)
                .collect::<Result<Vec<_>, _>>()?;
            Ok(DeliberationRecord::ClaimSet {
                claims,
                artifact: artifact_from_v1(artifact)?,
            })
        }
        DeliberationFactV1::VerificationSet { claims, artifact } => {
            let claims = claims
                .into_iter()
                .map(material_claim_from_v1)
                .collect::<Result<Vec<_>, _>>()?;
            Ok(DeliberationRecord::VerificationSet {
                claims,
                artifact: artifact_from_v1(artifact)?,
            })
        }
        DeliberationFactV1::DecisionDraft {
            decision,
            artifact,
            plan_artifact,
            plan_version,
        } => Ok(DeliberationRecord::DecisionDraft {
            decision: decision_package_from_v1(decision)?,
            artifact: artifact_from_v1(artifact)?,
            plan_artifact: artifact_from_v1(plan_artifact)?,
            plan_version,
        }),
        DeliberationFactV1::ObjectionSet {
            objections,
            artifact,
        } => Ok(DeliberationRecord::ObjectionSet {
            objections: objection_set_from_v1(objections)?,
            artifact: artifact_from_v1(artifact)?,
        }),
        DeliberationFactV1::ObjectionSevereAccepted {
            objections,
            objection_artifact,
            review_plan,
            review_artifact,
        } => Ok(DeliberationRecord::ObjectionSevereAccepted {
            objections: objection_set_from_v1(objections)?,
            objection_artifact: artifact_from_v1(objection_artifact)?,
            review_plan: review_plan_from_v1(review_plan)?,
            review_artifact: artifact_from_v1(review_artifact)?,
        }),
        DeliberationFactV1::ObjectionRoundClosed {
            artifact,
            plan_approval,
        } => Ok(DeliberationRecord::ObjectionRoundClosed {
            artifact: artifact_from_v1(artifact)?,
            plan_approval: Box::new(plan_approval_from_v1(plan_approval)?),
        }),
        DeliberationFactV1::Supersession {
            superseded,
            replacement,
        } => Ok(DeliberationRecord::Supersession {
            superseded: artifact_from_v1(superseded)?,
            replacement: artifact_from_v1(replacement)?,
        }),
    }
}

fn proposal_to_v1(proposal: &IndependentProposal) -> ProposalV1 {
    ProposalV1 {
        task_id: proposal.task_id().as_str().to_owned(),
        run_id: proposal.run_id().as_str().to_owned(),
        agent_id: proposal.agent_id().to_owned(),
        family: proposal.family().as_str().to_owned(),
        artifact_id: proposal.artifact_id().as_str().to_owned(),
        citations: proposal.citations().iter().map(citation_to_v1).collect(),
    }
}

fn proposal_from_v1(value: ProposalV1) -> Result<IndependentProposal, PortError> {
    IndependentProposal::new(
        TaskId::new(value.task_id).map_err(|_| integrity_failure())?,
        RunId::new(value.run_id).map_err(|_| integrity_failure())?,
        &value.agent_id,
        AgentFamilyKey::new(value.family).map_err(|_| integrity_failure())?,
        ArtifactId::new(value.artifact_id).map_err(|_| integrity_failure())?,
        value
            .citations
            .into_iter()
            .map(citation_from_v1)
            .collect::<Result<_, _>>()?,
    )
    .map_err(|_| integrity_failure())
}

fn review_plan_to_v1(plan: &ReviewPlan) -> ReviewPlanV1 {
    ReviewPlanV1 {
        edges: plan
            .edges()
            .iter()
            .map(|edge| ReviewEdgeV1 {
                reviewer_id: edge.reviewer_id().to_owned(),
                target_proposal: edge.target_proposal().as_str().to_owned(),
                round: edge.round(),
            })
            .collect(),
    }
}

fn review_plan_from_v1(value: ReviewPlanV1) -> Result<ReviewPlan, PortError> {
    let edges = value
        .edges
        .into_iter()
        .map(|edge| {
            ReviewEdge::new(
                &edge.reviewer_id,
                ArtifactId::new(edge.target_proposal).map_err(|_| integrity_failure())?,
                edge.round,
            )
            .map_err(|_| integrity_failure())
        })
        .collect::<Result<Vec<_>, _>>()?;
    let limits = review_limits_from_edges(&edges)?;
    ReviewPlan::new(limits, edges).map_err(|_| integrity_failure())
}

fn review_limits_from_edges(edges: &[ReviewEdge]) -> Result<DeliberationLimits, PortError> {
    let max_rounds = edges
        .iter()
        .map(ReviewEdge::round)
        .max()
        .ok_or_else(integrity_failure)?;
    let max_agents = u32::try_from(
        edges
            .iter()
            .map(ReviewEdge::reviewer_id)
            .collect::<std::collections::BTreeSet<_>>()
            .len(),
    )
    .map_err(|_| integrity_failure())?;
    let max_review_edges = u32::try_from(edges.len()).map_err(|_| integrity_failure())?;
    DeliberationLimits::new(max_agents, max_rounds, max_review_edges, max_agents)
        .map_err(|_| integrity_failure())
}

fn specialist_request_to_v1(request: &SpecialistRequest) -> SpecialistRequestV1 {
    SpecialistRequestV1 {
        request_id: request.request_id().to_owned(),
        task_id: request.task_id().as_str().to_owned(),
        requesting_run: request.requesting_run().as_str().to_owned(),
        capability: request.capability().to_owned(),
        reason: request.reason().to_owned(),
        required_context: request
            .required_context()
            .iter()
            .map(|artifact| artifact.as_str().to_owned())
            .collect(),
        budget: SpecialistBudgetV1 {
            max_tokens: request.budget().max_tokens(),
            deadline_unix_seconds: request.budget().deadline().unix_seconds(),
        },
    }
}

fn specialist_request_from_v1(value: SpecialistRequestV1) -> Result<SpecialistRequest, PortError> {
    let budget = SpecialistBudget::new(
        value.budget.max_tokens,
        Timestamp::from_unix_seconds(value.budget.deadline_unix_seconds),
    )
    .map_err(|_| integrity_failure())?;
    SpecialistRequest::new(
        &value.request_id,
        TaskId::new(value.task_id).map_err(|_| integrity_failure())?,
        RunId::new(value.requesting_run).map_err(|_| integrity_failure())?,
        &value.capability,
        &value.reason,
        value
            .required_context
            .into_iter()
            .map(|artifact| ArtifactId::new(artifact).map_err(|_| integrity_failure()))
            .collect::<Result<_, _>>()?,
        budget,
    )
    .map_err(|_| integrity_failure())
}

fn material_claim_to_v1(claim: &MaterialClaim) -> MaterialClaimV1 {
    MaterialClaimV1 {
        claim_id: claim.claim_id().to_owned(),
        claimant: claim.claimant().to_owned(),
        artifact_id: claim.artifact_id().as_str().to_owned(),
        citations: claim.citations().iter().map(citation_to_v1).collect(),
        method: verification_method_to_v1(claim.method()),
        verification: claim.verification().map(claim_verification_to_v1),
    }
}

fn material_claim_from_v1(value: MaterialClaimV1) -> Result<MaterialClaim, PortError> {
    let claim = MaterialClaim::new(
        &value.claim_id,
        &value.claimant,
        ArtifactId::new(value.artifact_id).map_err(|_| integrity_failure())?,
        value
            .citations
            .into_iter()
            .map(citation_from_v1)
            .collect::<Result<_, _>>()?,
        verification_method_from_v1(value.method),
    )
    .map_err(|_| integrity_failure())?;
    match value.verification {
        Some(verification) => claim
            .classify(claim_verification_from_v1(verification))
            .map_err(|_| integrity_failure()),
        None => Ok(claim),
    }
}

const fn verification_method_to_v1(value: VerificationMethod) -> VerificationMethodV1 {
    match value {
        VerificationMethod::SourceMatch => VerificationMethodV1::SourceMatch,
        VerificationMethod::DeterministicCheck => VerificationMethodV1::DeterministicCheck,
        VerificationMethod::PolicyReview => VerificationMethodV1::PolicyReview,
        VerificationMethod::NotApplicable => VerificationMethodV1::NotApplicable,
    }
}

const fn verification_method_from_v1(value: VerificationMethodV1) -> VerificationMethod {
    match value {
        VerificationMethodV1::SourceMatch => VerificationMethod::SourceMatch,
        VerificationMethodV1::DeterministicCheck => VerificationMethod::DeterministicCheck,
        VerificationMethodV1::PolicyReview => VerificationMethod::PolicyReview,
        VerificationMethodV1::NotApplicable => VerificationMethod::NotApplicable,
    }
}

const fn claim_verification_to_v1(value: ClaimVerification) -> ClaimVerificationV1 {
    match value {
        ClaimVerification::Verified => ClaimVerificationV1::Verified,
        ClaimVerification::Rejected => ClaimVerificationV1::Rejected,
        ClaimVerification::Inconclusive => ClaimVerificationV1::Inconclusive,
        ClaimVerification::NotApplicable => ClaimVerificationV1::NotApplicable,
    }
}

const fn claim_verification_from_v1(value: ClaimVerificationV1) -> ClaimVerification {
    match value {
        ClaimVerificationV1::Verified => ClaimVerification::Verified,
        ClaimVerificationV1::Rejected => ClaimVerification::Rejected,
        ClaimVerificationV1::Inconclusive => ClaimVerification::Inconclusive,
        ClaimVerificationV1::NotApplicable => ClaimVerification::NotApplicable,
    }
}

fn decision_package_to_v1(decision: &DecisionPackage) -> DecisionPackageV1 {
    DecisionPackageV1 {
        selected: decision_approach_to_v1(decision.selected()),
        rejected: decision
            .rejected()
            .iter()
            .map(|rejected| RejectedApproachV1 {
                approach: decision_approach_to_v1(rejected.approach()),
                reason: rejected.reason().to_owned(),
            })
            .collect(),
        evidence: decision
            .evidence()
            .iter()
            .map(material_claim_to_v1)
            .collect(),
        dissent: decision
            .dissent()
            .iter()
            .map(|dissent| DissentV1 {
                dissent_id: dissent.dissent_id().to_owned(),
                participant_id: dissent.participant_id().to_owned(),
                artifact_id: dissent.artifact_id().as_str().to_owned(),
                reason: dissent.reason().to_owned(),
            })
            .collect(),
        plan_artifact_id: decision.plan().as_str().to_owned(),
    }
}

fn decision_package_from_v1(value: DecisionPackageV1) -> Result<DecisionPackage, PortError> {
    let selected = decision_approach_from_v1(value.selected)?;
    let rejected = value
        .rejected
        .into_iter()
        .map(|rejected| {
            RejectedApproach::new(
                decision_approach_from_v1(rejected.approach)?,
                &rejected.reason,
            )
            .map_err(|_| integrity_failure())
        })
        .collect::<Result<Vec<_>, _>>()?;
    let evidence = value
        .evidence
        .into_iter()
        .map(material_claim_from_v1)
        .collect::<Result<Vec<_>, _>>()?;
    let dissent = value
        .dissent
        .into_iter()
        .map(|dissent| {
            Dissent::new(
                &dissent.dissent_id,
                &dissent.participant_id,
                ArtifactId::new(dissent.artifact_id).map_err(|_| integrity_failure())?,
                &dissent.reason,
            )
            .map_err(|_| integrity_failure())
        })
        .collect::<Result<Vec<_>, _>>()?;
    let expected_dissent_ids = dissent
        .iter()
        .map(|dissent| dissent.dissent_id().to_owned())
        .collect::<Vec<_>>();
    let expected_dissent_refs = expected_dissent_ids
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>();
    DecisionPackage::new(
        selected,
        rejected,
        evidence,
        dissent,
        &expected_dissent_refs,
        ArtifactId::new(value.plan_artifact_id).map_err(|_| integrity_failure())?,
    )
    .map_err(|_| integrity_failure())
}

fn decision_approach_to_v1(approach: &DecisionApproach) -> DecisionApproachV1 {
    DecisionApproachV1 {
        approach_id: approach.approach_id().to_owned(),
        artifact_id: approach.artifact_id().as_str().to_owned(),
        evidence_claim_ids: approach.evidence_claim_ids().to_vec(),
    }
}

fn decision_approach_from_v1(value: DecisionApproachV1) -> Result<DecisionApproach, PortError> {
    DecisionApproach::new(
        &value.approach_id,
        ArtifactId::new(value.artifact_id).map_err(|_| integrity_failure())?,
        value.evidence_claim_ids,
    )
    .map_err(|_| integrity_failure())
}

fn objection_set_to_v1(objections: &FinalObjectionSet) -> FinalObjectionSetV1 {
    FinalObjectionSetV1 {
        round: objections.round(),
        objections: objections
            .objections()
            .iter()
            .map(|objection| FinalObjectionV1 {
                participant_id: objection.participant_id().to_owned(),
                round: objection.round(),
                severity: objection_severity_to_v1(objection.severity()),
                impact: objection.impact().to_owned(),
                evidence: objection.evidence().iter().map(citation_to_v1).collect(),
                violated_requirement: objection.violated_requirement().map(str::to_owned),
            })
            .collect(),
    }
}

fn objection_set_from_v1(value: FinalObjectionSetV1) -> Result<FinalObjectionSet, PortError> {
    let objections = value
        .objections
        .into_iter()
        .map(|objection| {
            FinalObjection::new(
                &objection.participant_id,
                objection.round,
                objection_severity_from_v1(objection.severity),
                &objection.impact,
                objection
                    .evidence
                    .into_iter()
                    .map(citation_from_v1)
                    .collect::<Result<_, _>>()?,
                objection.violated_requirement.as_deref(),
            )
            .map_err(|_| integrity_failure())
        })
        .collect::<Result<Vec<_>, _>>()?;
    FinalObjectionSet::new(value.round, objections).map_err(|_| integrity_failure())
}

const fn objection_severity_to_v1(value: ObjectionSeverity) -> ObjectionSeverityV1 {
    match value {
        ObjectionSeverity::Low => ObjectionSeverityV1::Low,
        ObjectionSeverity::Moderate => ObjectionSeverityV1::Moderate,
        ObjectionSeverity::Severe => ObjectionSeverityV1::Severe,
    }
}

const fn objection_severity_from_v1(value: ObjectionSeverityV1) -> ObjectionSeverity {
    match value {
        ObjectionSeverityV1::Low => ObjectionSeverity::Low,
        ObjectionSeverityV1::Moderate => ObjectionSeverity::Moderate,
        ObjectionSeverityV1::Severe => ObjectionSeverity::Severe,
    }
}

fn plan_approval_to_v1(approval: &NewPlanApproval) -> NewPlanApprovalV1 {
    NewPlanApprovalV1 {
        approval_id: approval.approval_id().as_str().to_owned(),
        canonical_bytes: approval.canonical_bytes().to_vec(),
        operation_digest: approval.operation_digest().as_str().to_owned(),
        request_artifact: PlanApprovalRequestArtifactV1 {
            artifact_id: approval.request_artifact().artifact_id.as_str().to_owned(),
            content_digest: approval
                .request_artifact()
                .content_digest
                .as_str()
                .to_owned(),
            size_bytes: approval.request_artifact().size_bytes,
        },
        authority_binding_bytes: approval.authority_binding().canonical_bytes().to_vec(),
        authority_binding_digest: approval
            .authority_binding()
            .content_digest()
            .as_str()
            .to_owned(),
    }
}

fn plan_approval_from_v1(value: NewPlanApprovalV1) -> Result<NewPlanApproval, PortError> {
    NewPlanApproval::rehydrate(NewPlanApprovalRehydration {
        approval_id: ApprovalId::new(value.approval_id).map_err(|_| integrity_failure())?,
        canonical_bytes: value.canonical_bytes,
        operation_digest: Sha256Digest::new(value.operation_digest)
            .map_err(|_| integrity_failure())?,
        request_artifact: PlanApprovalRequestArtifact {
            artifact_id: ArtifactId::new(value.request_artifact.artifact_id)
                .map_err(|_| integrity_failure())?,
            content_digest: Sha256Digest::new(value.request_artifact.content_digest)
                .map_err(|_| integrity_failure())?,
            size_bytes: value.request_artifact.size_bytes,
        },
        authority_binding_bytes: value.authority_binding_bytes,
        authority_binding_digest: Sha256Digest::new(value.authority_binding_digest)
            .map_err(|_| integrity_failure())?,
    })
    .map_err(|_| integrity_failure())
}

fn citation_to_v1(citation: &EvidenceCitation) -> CitationV1 {
    let source = citation.source();
    CitationV1 {
        project_id: source.project_id().as_str().to_owned(),
        revision: source.revision().to_owned(),
        path_identity: source.path_identity().to_owned(),
        content_hash: source.content_hash().as_str().to_owned(),
        line_range: citation.range().map(|range| LineRangeV1 {
            start: range.start(),
            end: range.end(),
        }),
        symbol: citation.symbol().map(str::to_owned),
        freshness: match citation.freshness() {
            EvidenceFreshness::Current => "current",
            EvidenceFreshness::Stale => "stale",
        }
        .to_owned(),
    }
}

fn citation_from_v1(value: CitationV1) -> Result<EvidenceCitation, PortError> {
    let freshness = match value.freshness.as_str() {
        "current" => EvidenceFreshness::Current,
        "stale" => EvidenceFreshness::Stale,
        _ => return Err(integrity_failure()),
    };
    EvidenceCitation::new(
        SourceIdentity::new(
            ProjectId::new(value.project_id).map_err(|_| integrity_failure())?,
            value.revision,
            value.path_identity,
            Sha256Digest::new(value.content_hash).map_err(|_| integrity_failure())?,
        )
        .map_err(|_| integrity_failure())?,
        value
            .line_range
            .map(|range| LineRange::new(range.start, range.end).map_err(|_| integrity_failure()))
            .transpose()?,
        value.symbol.as_deref(),
        freshness,
    )
    .map_err(|_| integrity_failure())
}

fn artifact_to_v1(reference: &DeliberationArtifactRef) -> ArtifactRefV1 {
    ArtifactRefV1 {
        artifact_id: reference.artifact_id().as_str().to_owned(),
        content_digest: reference.content_digest().as_str().to_owned(),
        size_bytes: reference.size_bytes(),
    }
}

fn artifact_from_v1(value: ArtifactRefV1) -> Result<DeliberationArtifactRef, PortError> {
    DeliberationArtifactRef::new(
        ArtifactId::new(value.artifact_id).map_err(|_| integrity_failure())?,
        Sha256Digest::new(value.content_digest).map_err(|_| integrity_failure())?,
        value.size_bytes,
    )
}

fn digest(bytes: &[u8]) -> Result<Sha256Digest, PortError> {
    Sha256Digest::new(sha256_digest(bytes)).map_err(|_| integrity_failure())
}

fn invalid_input() -> PortError {
    PortError::failure(
        SafeErrorClassification::InvalidInput,
        Retryability::NonRetryable,
    )
}

fn integrity_failure() -> PortError {
    PortError::failure(
        SafeErrorClassification::IntegrityFailure,
        Retryability::NonRetryable,
    )
}

fn conflict() -> PortError {
    PortError::failure(
        SafeErrorClassification::Conflict,
        Retryability::NonRetryable,
    )
}
