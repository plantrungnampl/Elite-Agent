use std::collections::BTreeSet;
use std::fmt;

use sha2::{Digest, Sha256};

use crate::{
    ActorId, ArtifactId, EvidenceCitation, EvidenceFreshness, GitObjectId, RunId, Sha256Digest,
    StructuredToolName, TaskId, Timestamp,
};

const MAX_IDENTIFIER_LENGTH: usize = 256;
const MAX_TEXT_LENGTH: usize = 65_536;
const MAX_AGENTS: u32 = 64;
const MAX_ROUNDS: u32 = 32;
const MAX_REVIEW_EDGES: u32 = 4_096;
const MAX_SPECIALIST_REQUESTS: u32 = 256;
const MAX_TOKENS: u64 = 1_000_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeliberationError {
    InvalidIdentity,
    InvalidProposal,
    InvalidQuorum,
    InvalidLimits,
    DuplicateReviewEdge,
    LimitExceeded,
    InvalidSpecialistRequest,
    InvalidBudget,
    BudgetExceeded,
    InvalidClaim,
    ClaimAlreadyClassified,
    StaleVerifiedClaim,
    InvalidDecision,
    LostDissent,
    InvalidObjection,
    DuplicateObjection,
    InvalidApprovalBinding,
}

impl fmt::Display for DeliberationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidIdentity => "deliberation identity is invalid",
            Self::InvalidProposal => "independent proposal is invalid",
            Self::InvalidQuorum => "independent proposal quorum is invalid",
            Self::InvalidLimits => "deliberation limits are invalid",
            Self::DuplicateReviewEdge => "review edge is duplicated",
            Self::LimitExceeded => "deliberation limit is exceeded",
            Self::InvalidSpecialistRequest => "specialist request is invalid",
            Self::InvalidBudget => "deliberation budget is invalid",
            Self::BudgetExceeded => "deliberation budget is exceeded",
            Self::InvalidClaim => "material claim is invalid",
            Self::ClaimAlreadyClassified => "material claim is already classified",
            Self::StaleVerifiedClaim => "verified claim cites stale evidence",
            Self::InvalidDecision => "decision package is invalid",
            Self::LostDissent => "decision package does not preserve all dissent",
            Self::InvalidObjection => "final objection is invalid",
            Self::DuplicateObjection => "participant already objected in this round",
            Self::InvalidApprovalBinding => "plan approval binding is invalid",
        })
    }
}

impl std::error::Error for DeliberationError {}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AgentFamilyKey(String);

impl AgentFamilyKey {
    pub fn new(value: impl Into<String>) -> Result<Self, DeliberationError> {
        let value = value.into();
        if !valid_identifier(&value) {
            return Err(DeliberationError::InvalidIdentity);
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn from_provider_model(
        provider_id: &str,
        model_id: &str,
    ) -> Result<Self, DeliberationError> {
        if !valid_identifier(provider_id) || !valid_identifier(model_id) {
            return Err(DeliberationError::InvalidIdentity);
        }
        let value = serde_json::json!({
            "modelId": model_id,
            "providerId": provider_id,
        });
        let canonical = serde_json_canonicalizer::to_vec(&value)
            .map_err(|_| DeliberationError::InvalidIdentity)?;
        Self::new(format!("sha256:{:x}", Sha256::digest(canonical)))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProposalVisibility {
    Hidden,
    Revealed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IndependentProposal {
    task_id: TaskId,
    run_id: RunId,
    agent_id: String,
    family: AgentFamilyKey,
    artifact_id: ArtifactId,
    citations: Vec<EvidenceCitation>,
    visibility: ProposalVisibility,
}

impl IndependentProposal {
    pub fn new(
        task_id: TaskId,
        run_id: RunId,
        agent_id: &str,
        family: AgentFamilyKey,
        artifact_id: ArtifactId,
        mut citations: Vec<EvidenceCitation>,
    ) -> Result<Self, DeliberationError> {
        if !valid_identifier(task_id.as_str())
            || !valid_identifier(run_id.as_str())
            || !valid_identifier(agent_id)
            || !valid_identifier(artifact_id.as_str())
            || citations.is_empty()
        {
            return Err(DeliberationError::InvalidProposal);
        }
        citations.sort();
        citations.dedup();
        Ok(Self {
            task_id,
            run_id,
            agent_id: agent_id.to_owned(),
            family,
            artifact_id,
            citations,
            visibility: ProposalVisibility::Hidden,
        })
    }

    pub fn task_id(&self) -> &TaskId {
        &self.task_id
    }

    pub fn run_id(&self) -> &RunId {
        &self.run_id
    }

    pub fn agent_id(&self) -> &str {
        &self.agent_id
    }

    pub fn family(&self) -> &AgentFamilyKey {
        &self.family
    }

    pub fn artifact_id(&self) -> &ArtifactId {
        &self.artifact_id
    }

    pub fn citations(&self) -> &[EvidenceCitation] {
        &self.citations
    }

    pub const fn is_revealed(&self) -> bool {
        matches!(self.visibility, ProposalVisibility::Revealed)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IndependentQuorum {
    proposals: Vec<IndependentProposal>,
}

impl IndependentQuorum {
    pub fn new(proposals: Vec<IndependentProposal>) -> Result<Self, DeliberationError> {
        Self::from_visibility(proposals, false)
    }

    /// Rehydrates an already-published quorum while enforcing the same independence rules.
    pub fn from_revealed(proposals: Vec<IndependentProposal>) -> Result<Self, DeliberationError> {
        Self::from_visibility(proposals, true)
    }

    fn from_visibility(
        mut proposals: Vec<IndependentProposal>,
        expected_revealed: bool,
    ) -> Result<Self, DeliberationError> {
        if proposals.len() < 2 || proposals.len() > MAX_AGENTS as usize {
            return Err(DeliberationError::InvalidQuorum);
        }
        proposals.sort_by(|left, right| left.artifact_id.as_str().cmp(right.artifact_id.as_str()));
        let task = proposals[0].task_id.clone();
        let runs: BTreeSet<_> = proposals.iter().map(|proposal| &proposal.run_id).collect();
        let agents: BTreeSet<_> = proposals
            .iter()
            .map(|proposal| proposal.agent_id.as_str())
            .collect();
        let families: BTreeSet<_> = proposals.iter().map(|proposal| &proposal.family).collect();
        let artifacts: BTreeSet<_> = proposals
            .iter()
            .map(|proposal| &proposal.artifact_id)
            .collect();
        if proposals
            .iter()
            .any(|proposal| proposal.task_id != task || proposal.is_revealed() != expected_revealed)
            || runs.len() != proposals.len()
            || agents.len() != proposals.len()
            || families.len() != proposals.len()
            || artifacts.len() != proposals.len()
        {
            return Err(DeliberationError::InvalidQuorum);
        }
        Ok(Self { proposals })
    }

    pub fn proposals(&self) -> &[IndependentProposal] {
        &self.proposals
    }

    pub fn family_count(&self) -> usize {
        self.proposals
            .iter()
            .map(|proposal| &proposal.family)
            .collect::<BTreeSet<_>>()
            .len()
    }

    pub fn reveal(mut self) -> Vec<IndependentProposal> {
        for proposal in &mut self.proposals {
            proposal.visibility = ProposalVisibility::Revealed;
        }
        self.proposals
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeliberationLimits {
    max_agents: u32,
    max_rounds: u32,
    max_review_edges: u32,
    max_specialist_requests: u32,
}

impl DeliberationLimits {
    pub fn new(
        max_agents: u32,
        max_rounds: u32,
        max_review_edges: u32,
        max_specialist_requests: u32,
    ) -> Result<Self, DeliberationError> {
        if !(1..=MAX_AGENTS).contains(&max_agents)
            || !valid_deliberation_round(max_rounds)
            || !(1..=MAX_REVIEW_EDGES).contains(&max_review_edges)
            || !(1..=MAX_SPECIALIST_REQUESTS).contains(&max_specialist_requests)
        {
            return Err(DeliberationError::InvalidLimits);
        }
        Ok(Self {
            max_agents,
            max_rounds,
            max_review_edges,
            max_specialist_requests,
        })
    }

    pub const fn max_agents(self) -> u32 {
        self.max_agents
    }

    pub const fn max_rounds(self) -> u32 {
        self.max_rounds
    }

    pub const fn max_review_edges(self) -> u32 {
        self.max_review_edges
    }

    pub const fn max_specialist_requests(self) -> u32 {
        self.max_specialist_requests
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReviewEdge {
    reviewer_id: String,
    target_proposal: ArtifactId,
    round: u32,
}

impl ReviewEdge {
    pub fn new(
        reviewer_id: &str,
        target_proposal: ArtifactId,
        round: u32,
    ) -> Result<Self, DeliberationError> {
        if !valid_identifier(reviewer_id)
            || !valid_identifier(target_proposal.as_str())
            || !valid_deliberation_round(round)
        {
            return Err(DeliberationError::InvalidIdentity);
        }
        Ok(Self {
            reviewer_id: reviewer_id.to_owned(),
            target_proposal,
            round,
        })
    }

    pub fn reviewer_id(&self) -> &str {
        &self.reviewer_id
    }

    pub fn target_proposal(&self) -> &ArtifactId {
        &self.target_proposal
    }

    pub const fn round(&self) -> u32 {
        self.round
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReviewPlan {
    edges: Vec<ReviewEdge>,
}

impl ReviewPlan {
    pub fn new(
        limits: DeliberationLimits,
        mut edges: Vec<ReviewEdge>,
    ) -> Result<Self, DeliberationError> {
        if edges.len() > limits.max_review_edges as usize
            || edges.iter().any(|edge| edge.round > limits.max_rounds)
            || edges
                .iter()
                .map(|edge| edge.reviewer_id.as_str())
                .collect::<BTreeSet<_>>()
                .len()
                > limits.max_agents as usize
        {
            return Err(DeliberationError::LimitExceeded);
        }
        edges.sort_by(|left, right| {
            (
                left.round,
                left.reviewer_id.as_str(),
                left.target_proposal.as_str(),
            )
                .cmp(&(
                    right.round,
                    right.reviewer_id.as_str(),
                    right.target_proposal.as_str(),
                ))
        });
        if edges.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(DeliberationError::DuplicateReviewEdge);
        }
        Ok(Self { edges })
    }

    pub fn edges(&self) -> &[ReviewEdge] {
        &self.edges
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SpecialistBudget {
    max_tokens: u64,
    deadline: Timestamp,
}

impl SpecialistBudget {
    pub fn new(max_tokens: u64, deadline: Timestamp) -> Result<Self, DeliberationError> {
        if !(1..=MAX_TOKENS).contains(&max_tokens) || deadline.unix_seconds() <= 0 {
            return Err(DeliberationError::InvalidBudget);
        }
        Ok(Self {
            max_tokens,
            deadline,
        })
    }

    pub const fn max_tokens(self) -> u64 {
        self.max_tokens
    }

    pub const fn deadline(self) -> Timestamp {
        self.deadline
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpecialistRequest {
    request_id: String,
    task_id: TaskId,
    requesting_run: RunId,
    capability: String,
    reason: String,
    required_context: Vec<ArtifactId>,
    budget: SpecialistBudget,
}

impl SpecialistRequest {
    pub fn new(
        request_id: &str,
        task_id: TaskId,
        requesting_run: RunId,
        capability: &str,
        reason: &str,
        mut required_context: Vec<ArtifactId>,
        budget: SpecialistBudget,
    ) -> Result<Self, DeliberationError> {
        if !valid_identifier(request_id)
            || !valid_identifier(task_id.as_str())
            || !valid_identifier(requesting_run.as_str())
            || !valid_identifier(capability)
            || !valid_text(reason)
            || required_context.is_empty()
            || required_context
                .iter()
                .any(|artifact| !valid_identifier(artifact.as_str()))
        {
            return Err(DeliberationError::InvalidSpecialistRequest);
        }
        required_context.sort_by(|left, right| left.as_str().cmp(right.as_str()));
        required_context.dedup();
        Ok(Self {
            request_id: request_id.to_owned(),
            task_id,
            requesting_run,
            capability: capability.to_owned(),
            reason: reason.to_owned(),
            required_context,
            budget,
        })
    }

    pub fn request_id(&self) -> &str {
        &self.request_id
    }

    pub fn task_id(&self) -> &TaskId {
        &self.task_id
    }

    pub fn requesting_run(&self) -> &RunId {
        &self.requesting_run
    }

    pub fn capability(&self) -> &str {
        &self.capability
    }

    pub fn reason(&self) -> &str {
        &self.reason
    }

    pub fn required_context(&self) -> &[ArtifactId] {
        &self.required_context
    }

    pub const fn budget(&self) -> SpecialistBudget {
        self.budget
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeliberationBudget {
    max_tokens: u64,
    max_specialist_requests: u32,
    used_tokens: u64,
    used_specialist_requests: u32,
}

impl DeliberationBudget {
    pub fn new(max_tokens: u64, max_specialist_requests: u32) -> Result<Self, DeliberationError> {
        if !(1..=MAX_TOKENS).contains(&max_tokens)
            || !(1..=MAX_SPECIALIST_REQUESTS).contains(&max_specialist_requests)
        {
            return Err(DeliberationError::InvalidBudget);
        }
        Ok(Self {
            max_tokens,
            max_specialist_requests,
            used_tokens: 0,
            used_specialist_requests: 0,
        })
    }

    pub fn reserve(&mut self, tokens: u64) -> Result<(), DeliberationError> {
        let Some(next_tokens) = self.used_tokens.checked_add(tokens) else {
            return Err(DeliberationError::BudgetExceeded);
        };
        let Some(next_requests) = self.used_specialist_requests.checked_add(1) else {
            return Err(DeliberationError::BudgetExceeded);
        };
        if tokens == 0
            || next_tokens > self.max_tokens
            || next_requests > self.max_specialist_requests
        {
            return Err(DeliberationError::BudgetExceeded);
        }
        self.used_tokens = next_tokens;
        self.used_specialist_requests = next_requests;
        Ok(())
    }

    pub const fn used_tokens(self) -> u64 {
        self.used_tokens
    }

    pub const fn used_specialist_requests(self) -> u32 {
        self.used_specialist_requests
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ClaimVerification {
    Verified,
    Rejected,
    Inconclusive,
    NotApplicable,
}

impl ClaimVerification {
    pub const fn is_terminal(self) -> bool {
        true
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum VerificationMethod {
    SourceMatch,
    DeterministicCheck,
    PolicyReview,
    NotApplicable,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MaterialClaim {
    claim_id: String,
    claimant: String,
    artifact_id: ArtifactId,
    citations: Vec<EvidenceCitation>,
    method: VerificationMethod,
    verification: Option<ClaimVerification>,
}

impl MaterialClaim {
    pub fn new(
        claim_id: &str,
        claimant: &str,
        artifact_id: ArtifactId,
        mut citations: Vec<EvidenceCitation>,
        method: VerificationMethod,
    ) -> Result<Self, DeliberationError> {
        if !valid_identifier(claim_id)
            || !valid_identifier(claimant)
            || !valid_identifier(artifact_id.as_str())
            || citations.is_empty()
        {
            return Err(DeliberationError::InvalidClaim);
        }
        citations.sort();
        citations.dedup();
        Ok(Self {
            claim_id: claim_id.to_owned(),
            claimant: claimant.to_owned(),
            artifact_id,
            citations,
            method,
            verification: None,
        })
    }

    pub fn classify(mut self, verification: ClaimVerification) -> Result<Self, DeliberationError> {
        if self.verification.is_some() {
            return Err(DeliberationError::ClaimAlreadyClassified);
        }
        if verification == ClaimVerification::Verified
            && self
                .citations
                .iter()
                .any(|citation| citation.freshness() != EvidenceFreshness::Current)
        {
            return Err(DeliberationError::StaleVerifiedClaim);
        }
        self.verification = Some(verification);
        Ok(self)
    }

    pub fn claim_id(&self) -> &str {
        &self.claim_id
    }

    pub fn claimant(&self) -> &str {
        &self.claimant
    }

    pub fn artifact_id(&self) -> &ArtifactId {
        &self.artifact_id
    }

    pub fn citations(&self) -> &[EvidenceCitation] {
        &self.citations
    }

    pub const fn method(&self) -> VerificationMethod {
        self.method
    }

    pub const fn verification(&self) -> Option<ClaimVerification> {
        self.verification
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecisionApproach {
    approach_id: String,
    artifact_id: ArtifactId,
    evidence_claim_ids: Vec<String>,
}

impl DecisionApproach {
    pub fn new(
        approach_id: &str,
        artifact_id: ArtifactId,
        mut evidence_claim_ids: Vec<String>,
    ) -> Result<Self, DeliberationError> {
        if !valid_identifier(approach_id)
            || !valid_identifier(artifact_id.as_str())
            || evidence_claim_ids.iter().any(|id| !valid_identifier(id))
        {
            return Err(DeliberationError::InvalidDecision);
        }
        evidence_claim_ids.sort();
        evidence_claim_ids.dedup();
        Ok(Self {
            approach_id: approach_id.to_owned(),
            artifact_id,
            evidence_claim_ids,
        })
    }

    pub fn approach_id(&self) -> &str {
        &self.approach_id
    }

    pub fn artifact_id(&self) -> &ArtifactId {
        &self.artifact_id
    }

    pub fn evidence_claim_ids(&self) -> &[String] {
        &self.evidence_claim_ids
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RejectedApproach {
    approach: DecisionApproach,
    reason: String,
}

impl RejectedApproach {
    pub fn new(approach: DecisionApproach, reason: &str) -> Result<Self, DeliberationError> {
        if !valid_text(reason) {
            return Err(DeliberationError::InvalidDecision);
        }
        Ok(Self {
            approach,
            reason: reason.to_owned(),
        })
    }

    pub fn approach_id(&self) -> &str {
        self.approach.approach_id()
    }

    pub fn approach(&self) -> &DecisionApproach {
        &self.approach
    }

    pub fn reason(&self) -> &str {
        &self.reason
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dissent {
    dissent_id: String,
    participant_id: String,
    artifact_id: ArtifactId,
    reason: String,
}

impl Dissent {
    pub fn new(
        dissent_id: &str,
        participant_id: &str,
        artifact_id: ArtifactId,
        reason: &str,
    ) -> Result<Self, DeliberationError> {
        if !valid_identifier(dissent_id)
            || !valid_identifier(participant_id)
            || !valid_identifier(artifact_id.as_str())
            || !valid_text(reason)
        {
            return Err(DeliberationError::InvalidDecision);
        }
        Ok(Self {
            dissent_id: dissent_id.to_owned(),
            participant_id: participant_id.to_owned(),
            artifact_id,
            reason: reason.to_owned(),
        })
    }

    pub fn dissent_id(&self) -> &str {
        &self.dissent_id
    }

    pub fn participant_id(&self) -> &str {
        &self.participant_id
    }

    pub fn artifact_id(&self) -> &ArtifactId {
        &self.artifact_id
    }

    pub fn reason(&self) -> &str {
        &self.reason
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecisionPackage {
    selected: DecisionApproach,
    rejected: Vec<RejectedApproach>,
    evidence: Vec<MaterialClaim>,
    dissent: Vec<Dissent>,
    plan: ArtifactId,
}

impl DecisionPackage {
    pub fn new(
        selected: DecisionApproach,
        mut rejected: Vec<RejectedApproach>,
        mut evidence: Vec<MaterialClaim>,
        mut dissent: Vec<Dissent>,
        expected_dissent_ids: &[&str],
        plan: ArtifactId,
    ) -> Result<Self, DeliberationError> {
        if selected.evidence_claim_ids.is_empty()
            || evidence.is_empty()
            || evidence.iter().any(|claim| claim.verification.is_none())
            || !valid_identifier(plan.as_str())
        {
            return Err(DeliberationError::InvalidDecision);
        }
        evidence.sort_by(|left, right| left.claim_id.cmp(&right.claim_id));
        if evidence
            .windows(2)
            .any(|pair| pair[0].claim_id == pair[1].claim_id)
        {
            return Err(DeliberationError::InvalidDecision);
        }
        let verified_claim_ids: BTreeSet<_> = evidence
            .iter()
            .filter(|claim| claim.verification == Some(ClaimVerification::Verified))
            .map(|claim| claim.claim_id.as_str())
            .collect();
        if selected
            .evidence_claim_ids
            .iter()
            .any(|claim_id| !verified_claim_ids.contains(claim_id.as_str()))
        {
            return Err(DeliberationError::InvalidDecision);
        }

        rejected.sort_by(|left, right| left.approach_id().cmp(right.approach_id()));
        if rejected
            .windows(2)
            .any(|pair| pair[0].approach_id() == pair[1].approach_id())
            || rejected
                .iter()
                .any(|approach| approach.approach_id() == selected.approach_id())
        {
            return Err(DeliberationError::InvalidDecision);
        }

        dissent.sort_by(|left, right| left.dissent_id.cmp(&right.dissent_id));
        if dissent
            .windows(2)
            .any(|pair| pair[0].dissent_id == pair[1].dissent_id)
        {
            return Err(DeliberationError::InvalidDecision);
        }
        let actual_dissent: BTreeSet<_> = dissent
            .iter()
            .map(|entry| entry.dissent_id.as_str())
            .collect();
        let expected_dissent: BTreeSet<_> = expected_dissent_ids.iter().copied().collect();
        if expected_dissent.len() != expected_dissent_ids.len()
            || expected_dissent.iter().any(|id| !valid_identifier(id))
            || actual_dissent != expected_dissent
        {
            return Err(DeliberationError::LostDissent);
        }

        Ok(Self {
            selected,
            rejected,
            evidence,
            dissent,
            plan,
        })
    }

    pub fn selected(&self) -> &DecisionApproach {
        &self.selected
    }

    pub fn rejected(&self) -> &[RejectedApproach] {
        &self.rejected
    }

    pub fn evidence(&self) -> &[MaterialClaim] {
        &self.evidence
    }

    pub fn dissent(&self) -> &[Dissent] {
        &self.dissent
    }

    pub fn plan(&self) -> &ArtifactId {
        &self.plan
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ObjectionSeverity {
    Low,
    Moderate,
    Severe,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FinalObjection {
    participant_id: String,
    round: u32,
    severity: ObjectionSeverity,
    impact: String,
    evidence: Vec<EvidenceCitation>,
    violated_requirement: Option<String>,
}

impl FinalObjection {
    pub fn new(
        participant_id: &str,
        round: u32,
        severity: ObjectionSeverity,
        impact: &str,
        mut evidence: Vec<EvidenceCitation>,
        violated_requirement: Option<&str>,
    ) -> Result<Self, DeliberationError> {
        if !valid_identifier(participant_id)
            || !valid_deliberation_round(round)
            || !valid_text(impact)
            || evidence.is_empty()
            || violated_requirement.is_some_and(|requirement| !valid_text(requirement))
            || (severity == ObjectionSeverity::Severe && violated_requirement.is_none())
        {
            return Err(DeliberationError::InvalidObjection);
        }
        evidence.sort();
        evidence.dedup();
        Ok(Self {
            participant_id: participant_id.to_owned(),
            round,
            severity,
            impact: impact.to_owned(),
            evidence,
            violated_requirement: violated_requirement.map(str::to_owned),
        })
    }

    pub fn participant_id(&self) -> &str {
        &self.participant_id
    }

    pub const fn round(&self) -> u32 {
        self.round
    }

    pub const fn severity(&self) -> ObjectionSeverity {
        self.severity
    }

    pub fn impact(&self) -> &str {
        &self.impact
    }

    pub fn evidence(&self) -> &[EvidenceCitation] {
        &self.evidence
    }

    pub fn violated_requirement(&self) -> Option<&str> {
        self.violated_requirement.as_deref()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FinalObjectionSet {
    round: u32,
    objections: Vec<FinalObjection>,
}

impl FinalObjectionSet {
    pub fn new(round: u32, mut objections: Vec<FinalObjection>) -> Result<Self, DeliberationError> {
        let participant_count = objections
            .iter()
            .map(|objection| objection.participant_id.as_str())
            .collect::<BTreeSet<_>>()
            .len();
        if !valid_deliberation_round(round)
            || participant_count > MAX_AGENTS as usize
            || objections.iter().any(|objection| {
                !valid_deliberation_round(objection.round) || objection.round != round
            })
        {
            return Err(DeliberationError::InvalidObjection);
        }
        objections.sort_by(|left, right| left.participant_id.cmp(&right.participant_id));
        if objections
            .windows(2)
            .any(|pair| pair[0].participant_id == pair[1].participant_id)
        {
            return Err(DeliberationError::DuplicateObjection);
        }
        Ok(Self { round, objections })
    }

    pub const fn round(&self) -> u32 {
        self.round
    }

    pub fn objections(&self) -> &[FinalObjection] {
        &self.objections
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlanIdentity {
    artifact_id: ArtifactId,
    content_digest: Sha256Digest,
    version: u64,
}

impl PlanIdentity {
    pub fn new(
        artifact_id: ArtifactId,
        content_digest: Sha256Digest,
        version: u64,
    ) -> Result<Self, DeliberationError> {
        if !valid_identifier(artifact_id.as_str()) || version == 0 {
            return Err(DeliberationError::InvalidApprovalBinding);
        }
        Ok(Self {
            artifact_id,
            content_digest,
            version,
        })
    }

    pub fn artifact_id(&self) -> &ArtifactId {
        &self.artifact_id
    }

    pub fn content_digest(&self) -> &Sha256Digest {
        &self.content_digest
    }

    pub const fn version(&self) -> u64 {
        self.version
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovalScope {
    task_scope: Vec<String>,
    writable_scope: Vec<String>,
}

impl ApprovalScope {
    pub fn new(
        mut task_scope: Vec<String>,
        mut writable_scope: Vec<String>,
    ) -> Result<Self, DeliberationError> {
        if task_scope.is_empty()
            || writable_scope.is_empty()
            || task_scope.iter().any(|scope| !valid_identifier(scope))
            || writable_scope.iter().any(|scope| !valid_identifier(scope))
        {
            return Err(DeliberationError::InvalidApprovalBinding);
        }
        task_scope.sort();
        task_scope.dedup();
        writable_scope.sort();
        writable_scope.dedup();
        Ok(Self {
            task_scope,
            writable_scope,
        })
    }

    pub fn task_scope(&self) -> &[String] {
        &self.task_scope
    }

    pub fn writable_scope(&self) -> &[String] {
        &self.writable_scope
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovalAuthority {
    actor_id: ActorId,
    requested_at: Timestamp,
    expires_at: Timestamp,
}

impl ApprovalAuthority {
    pub fn new(
        actor_id: ActorId,
        requested_at: Timestamp,
        expires_at: Timestamp,
    ) -> Result<Self, DeliberationError> {
        if !valid_identifier(actor_id.as_str())
            || requested_at.unix_seconds() <= 0
            || expires_at <= requested_at
        {
            return Err(DeliberationError::InvalidApprovalBinding);
        }
        Ok(Self {
            actor_id,
            requested_at,
            expires_at,
        })
    }

    pub fn actor_id(&self) -> &ActorId {
        &self.actor_id
    }

    pub const fn requested_at(&self) -> Timestamp {
        self.requested_at
    }

    pub const fn expires_at(&self) -> Timestamp {
        self.expires_at
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovalExecution {
    scope: ApprovalScope,
    allowed_tools: Vec<StructuredToolName>,
    verification_profile: String,
}

impl ApprovalExecution {
    pub fn new(
        scope: ApprovalScope,
        allowed_tools: Vec<StructuredToolName>,
        verification_profile: &str,
    ) -> Result<Self, DeliberationError> {
        if allowed_tools.is_empty()
            || has_duplicate_tools(&allowed_tools)
            || !valid_identifier(verification_profile)
        {
            return Err(DeliberationError::InvalidApprovalBinding);
        }
        Ok(Self {
            scope,
            allowed_tools,
            verification_profile: verification_profile.to_owned(),
        })
    }

    pub fn scope(&self) -> &ApprovalScope {
        &self.scope
    }

    pub fn allowed_tools(&self) -> &[StructuredToolName] {
        &self.allowed_tools
    }

    pub fn verification_profile(&self) -> &str {
        &self.verification_profile
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlanApprovalBinding {
    plan: PlanIdentity,
    task_id: TaskId,
    base_commit: GitObjectId,
    repository_fingerprint: Sha256Digest,
    policy_snapshot_digest: Sha256Digest,
    execution: ApprovalExecution,
    authority: ApprovalAuthority,
}

impl PlanApprovalBinding {
    pub fn new(
        plan: PlanIdentity,
        task_id: TaskId,
        base_commit: GitObjectId,
        repository_fingerprint: Sha256Digest,
        policy_snapshot_digest: Sha256Digest,
        execution: ApprovalExecution,
        authority: ApprovalAuthority,
    ) -> Result<Self, DeliberationError> {
        if !valid_identifier(task_id.as_str()) {
            return Err(DeliberationError::InvalidApprovalBinding);
        }
        Ok(Self {
            plan,
            task_id,
            base_commit,
            repository_fingerprint,
            policy_snapshot_digest,
            execution,
            authority,
        })
    }

    pub fn plan(&self) -> &PlanIdentity {
        &self.plan
    }

    pub fn task_id(&self) -> &TaskId {
        &self.task_id
    }

    pub fn base_commit(&self) -> &GitObjectId {
        &self.base_commit
    }

    pub fn repository_fingerprint(&self) -> &Sha256Digest {
        &self.repository_fingerprint
    }

    pub fn policy_snapshot_digest(&self) -> &Sha256Digest {
        &self.policy_snapshot_digest
    }

    pub fn scope(&self) -> &ApprovalScope {
        self.execution.scope()
    }

    pub fn allowed_tools(&self) -> &[StructuredToolName] {
        self.execution.allowed_tools()
    }

    pub fn verification_profile(&self) -> &str {
        self.execution.verification_profile()
    }

    pub fn authority(&self) -> &ApprovalAuthority {
        &self.authority
    }
}

fn has_duplicate_tools(tools: &[StructuredToolName]) -> bool {
    tools
        .iter()
        .enumerate()
        .any(|(index, tool)| tools[index + 1..].contains(tool))
}

fn valid_identifier(value: &str) -> bool {
    !value.trim().is_empty() && value.len() <= MAX_IDENTIFIER_LENGTH && !value.contains('\0')
}

fn valid_deliberation_round(round: u32) -> bool {
    (1..=MAX_ROUNDS).contains(&round)
}

fn valid_text(value: &str) -> bool {
    !value.trim().is_empty() && value.len() <= MAX_TEXT_LENGTH && !value.contains('\0')
}
