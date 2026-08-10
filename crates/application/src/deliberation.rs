use std::collections::{BTreeMap, BTreeSet};

use local_agent_terminal_domain::{
    reduce, ActorId, AgentFamilyKey, ArtifactId, DecisionPackage, EventId, FinalObjectionSet,
    GuardEvaluations, GuardName, IndependentProposal, IndependentQuorum, MaterialClaim,
    ObjectionSeverity, Phase, ReviewPlan, RunId, Sha256Digest, SpecialistRequest, StreamId, TaskId,
    WorkflowEvent, WorkflowState,
};

use crate::{
    parse_policy_timestamp, AppendOperation, CanonicalDeliberationFact, NewEvent, NewPlanApproval,
    PlanApprovalAuthorityBinding, PlanApprovalCurrentState, PortError, PreparePlanApprovalRequest,
    PreparePlanApprovalRequestInput, ProjectionChange, Retryability, SafeErrorClassification,
};

const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeliberationCommandContext {
    task_id: TaskId,
    expected_task_version: u64,
    expected_task_state: WorkflowState,
    actor_id: ActorId,
    record_artifact: DeliberationArtifactRef,
    event_id: EventId,
    correlation_id: String,
    occurred_at: String,
}

impl DeliberationCommandContext {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        task_id: TaskId,
        expected_task_version: u64,
        expected_task_state: WorkflowState,
        actor_id: ActorId,
        record_artifact: DeliberationArtifactRef,
        event_id: EventId,
        correlation_id: impl Into<String>,
        occurred_at: impl Into<String>,
    ) -> Result<Self, PortError> {
        let context = Self {
            task_id,
            expected_task_version,
            expected_task_state,
            actor_id,
            record_artifact,
            event_id,
            correlation_id: correlation_id.into(),
            occurred_at: occurred_at.into(),
        };
        context.validate()?;
        Ok(context)
    }

    pub fn task_id(&self) -> &TaskId {
        &self.task_id
    }

    pub const fn expected_task_version(&self) -> u64 {
        self.expected_task_version
    }

    pub const fn expected_task_state(&self) -> WorkflowState {
        self.expected_task_state
    }

    fn validate(&self) -> Result<(), PortError> {
        if self.expected_task_version != self.expected_task_state.sequence().get() {
            return Err(invalid_input());
        }
        validate_label(&self.correlation_id)?;
        parse_policy_timestamp(&self.occurred_at).map_err(|_| invalid_input())?;
        self.record_artifact.validate()
    }

    fn event_authority(&self) -> EventAuthority {
        EventAuthority {
            actor_id: self.actor_id.clone(),
            event_id: self.event_id.clone(),
            correlation_id: self.correlation_id.clone(),
            occurred_at: self.occurred_at.clone(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeliberationArtifactRef {
    artifact_id: ArtifactId,
    content_digest: Sha256Digest,
    size_bytes: u64,
}

impl DeliberationArtifactRef {
    pub fn new(
        artifact_id: ArtifactId,
        content_digest: Sha256Digest,
        size_bytes: u64,
    ) -> Result<Self, PortError> {
        if size_bytes == 0 {
            return Err(invalid_input());
        }
        Ok(Self {
            artifact_id,
            content_digest,
            size_bytes,
        })
    }

    pub fn artifact_id(&self) -> &ArtifactId {
        &self.artifact_id
    }

    pub fn content_digest(&self) -> &Sha256Digest {
        &self.content_digest
    }

    pub const fn size_bytes(&self) -> u64 {
        self.size_bytes
    }

    pub fn validate(&self) -> Result<(), PortError> {
        if self.size_bytes == 0 {
            Err(invalid_input())
        } else {
            Ok(())
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeliberationRecord {
    PrivateProposal {
        proposal: IndependentProposal,
        proposal_artifact: DeliberationArtifactRef,
        receipt: DeliberationArtifactRef,
    },
    QuorumPublication {
        proposals: Vec<IndependentProposal>,
        proposal_artifact: DeliberationArtifactRef,
        review_plan: ReviewPlan,
        review_artifact: DeliberationArtifactRef,
    },
    ReviewEdges {
        plan: ReviewPlan,
        artifact: DeliberationArtifactRef,
    },
    ThreadSummary {
        thread_id: String,
        artifact: DeliberationArtifactRef,
    },
    SpecialistRequest {
        request: SpecialistRequest,
        artifact: DeliberationArtifactRef,
    },
    ClaimSet {
        claims: Vec<MaterialClaim>,
        artifact: DeliberationArtifactRef,
    },
    VerificationSet {
        claims: Vec<MaterialClaim>,
        artifact: DeliberationArtifactRef,
    },
    DecisionDraft {
        decision: DecisionPackage,
        artifact: DeliberationArtifactRef,
        plan_artifact: DeliberationArtifactRef,
        plan_version: u64,
    },
    ObjectionSet {
        objections: FinalObjectionSet,
        artifact: DeliberationArtifactRef,
    },
    ObjectionSevereAccepted {
        objections: FinalObjectionSet,
        objection_artifact: DeliberationArtifactRef,
        review_plan: ReviewPlan,
        review_artifact: DeliberationArtifactRef,
    },
    ObjectionRoundClosed {
        artifact: DeliberationArtifactRef,
        plan_approval: Box<NewPlanApproval>,
    },
    Supersession {
        superseded: DeliberationArtifactRef,
        replacement: DeliberationArtifactRef,
    },
}

impl DeliberationRecord {
    pub fn validate(&self, task_id: &TaskId) -> Result<(), PortError> {
        match self {
            Self::PrivateProposal {
                proposal,
                proposal_artifact,
                receipt,
            } => {
                proposal_artifact.validate()?;
                receipt.validate()?;
                if proposal.task_id() != task_id
                    || proposal.is_revealed()
                    || proposal.artifact_id() != proposal_artifact.artifact_id()
                {
                    return Err(conflict());
                }
            }
            Self::QuorumPublication {
                proposals,
                proposal_artifact,
                review_plan,
                review_artifact,
            } => {
                proposal_artifact.validate()?;
                review_artifact.validate()?;
                if IndependentQuorum::from_revealed(proposals.clone()).is_err()
                    || proposals
                        .iter()
                        .any(|proposal| proposal.task_id() != task_id)
                    || review_plan.edges().is_empty()
                {
                    return Err(conflict());
                }
            }
            Self::ReviewEdges { plan, artifact } => {
                artifact.validate()?;
                if plan.edges().is_empty() {
                    return Err(conflict());
                }
            }
            Self::ThreadSummary {
                thread_id,
                artifact,
            } => {
                artifact.validate()?;
                validate_label(thread_id)?;
            }
            Self::SpecialistRequest { request, artifact } => {
                artifact.validate()?;
                if request.task_id() != task_id {
                    return Err(conflict());
                }
            }
            Self::ClaimSet { claims, artifact } => {
                artifact.validate()?;
                validate_claim_set(claims, false)?;
            }
            Self::VerificationSet { claims, artifact } => {
                artifact.validate()?;
                validate_claim_set(claims, true)?;
            }
            Self::DecisionDraft {
                decision,
                artifact,
                plan_artifact,
                plan_version,
            } => {
                artifact.validate()?;
                plan_artifact.validate()?;
                if decision.plan() != plan_artifact.artifact_id()
                    || !(1..=MAX_SAFE_INTEGER).contains(plan_version)
                {
                    return Err(conflict());
                }
            }
            Self::ObjectionSet { artifact, .. } => artifact.validate()?,
            Self::ObjectionSevereAccepted {
                objections,
                objection_artifact,
                review_plan,
                review_artifact,
            } => {
                objection_artifact.validate()?;
                review_artifact.validate()?;
                let next_round = objections.round().checked_add(1).ok_or_else(conflict)?;
                if !objections
                    .objections()
                    .iter()
                    .any(|objection| objection.severity() == ObjectionSeverity::Severe)
                    || review_plan.edges().is_empty()
                    || review_plan
                        .edges()
                        .iter()
                        .any(|edge| edge.round() != next_round)
                {
                    return Err(conflict());
                }
            }
            Self::ObjectionRoundClosed {
                artifact,
                plan_approval,
            } => {
                artifact.validate()?;
                plan_approval.validate()?;
                if plan_approval.task_id() != task_id {
                    return Err(conflict());
                }
            }
            Self::Supersession {
                superseded,
                replacement,
            } => {
                superseded.validate()?;
                replacement.validate()?;
                if superseded.artifact_id == replacement.artifact_id {
                    return Err(conflict());
                }
            }
        }
        Ok(())
    }

    const fn expected_phase(&self) -> Phase {
        match self {
            Self::PrivateProposal { .. }
            | Self::QuorumPublication { .. }
            | Self::SpecialistRequest { .. } => Phase::ParallelAnalysis,
            Self::ReviewEdges { .. } | Self::ThreadSummary { .. } | Self::ClaimSet { .. } => {
                Phase::CrossReview
            }
            Self::VerificationSet { .. } => Phase::PrePlanVerification,
            Self::DecisionDraft { .. } | Self::Supersession { .. } => Phase::Synthesis,
            Self::ObjectionSet { .. }
            | Self::ObjectionSevereAccepted { .. }
            | Self::ObjectionRoundClosed { .. } => Phase::FinalObjection,
        }
    }

    pub(crate) const fn event_type(&self) -> &'static str {
        match self {
            Self::PrivateProposal { .. } => "agent.message.created",
            Self::QuorumPublication { .. } => "analysis.quorum.reached",
            Self::ReviewEdges { .. } => "review.edges.assigned",
            Self::ThreadSummary { .. } => "thread.summary.created",
            Self::SpecialistRequest { .. } => "specialist.requested",
            Self::ClaimSet { .. } => "review.complete",
            Self::VerificationSet { .. } => "claims.checked",
            Self::DecisionDraft { .. } => "decision.draft.created",
            Self::ObjectionSet { .. } => "objection.set.created",
            Self::ObjectionSevereAccepted { .. } => "objection.severe.accepted",
            Self::ObjectionRoundClosed { .. } => "objection.round.closed",
            Self::Supersession { .. } => "agent.message.superseded",
        }
    }

    const fn transition_guard(&self) -> Option<&'static str> {
        match self {
            Self::QuorumPublication { .. } => Some("minimum_independent_results"),
            Self::ClaimSet { .. } => Some("review_outputs_or_bounded_stop"),
            Self::VerificationSet { .. } => Some("all_material_claims_classified"),
            Self::DecisionDraft { .. } => Some("decision_schema_and_evidence_valid"),
            Self::ObjectionSevereAccepted { .. } => Some("reopen_criteria_satisfied"),
            Self::ObjectionRoundClosed { .. } => Some("no_accepted_severe_objection"),
            _ => None,
        }
    }

    const fn changes_phase(&self) -> bool {
        matches!(
            self,
            Self::QuorumPublication { .. }
                | Self::ClaimSet { .. }
                | Self::VerificationSet { .. }
                | Self::DecisionDraft { .. }
                | Self::ObjectionSevereAccepted { .. }
                | Self::ObjectionRoundClosed { .. }
        )
    }

    fn primary_artifact(&self) -> &DeliberationArtifactRef {
        match self {
            Self::PrivateProposal { receipt, .. } => receipt,
            Self::QuorumPublication {
                proposal_artifact, ..
            } => proposal_artifact,
            Self::ReviewEdges { artifact, .. }
            | Self::ThreadSummary { artifact, .. }
            | Self::SpecialistRequest { artifact, .. }
            | Self::ClaimSet { artifact, .. }
            | Self::VerificationSet { artifact, .. }
            | Self::DecisionDraft { artifact, .. }
            | Self::ObjectionSet { artifact, .. }
            | Self::ObjectionRoundClosed { artifact, .. } => artifact,
            Self::ObjectionSevereAccepted {
                review_artifact, ..
            } => review_artifact,
            Self::Supersession { replacement, .. } => replacement,
        }
    }

    fn event_payload(
        &self,
        task_id: &TaskId,
        canonical_record_digest: &Sha256Digest,
    ) -> serde_json::Value {
        let artifact = self.primary_artifact();
        let mut payload = serde_json::json!({
            "taskId": task_id.as_str(),
            "recordType": self.event_type(),
            "canonicalRecordDigest": canonical_record_digest.as_str(),
            "artifactId": artifact.artifact_id.as_str(),
            "artifactDigest": artifact.content_digest.as_str(),
            "artifactSizeBytes": artifact.size_bytes,
        });
        if let Self::QuorumPublication {
            review_artifact, ..
        } = self
        {
            payload["reviewArtifactId"] =
                serde_json::Value::String(review_artifact.artifact_id.as_str().to_owned());
            payload["reviewArtifactDigest"] =
                serde_json::Value::String(review_artifact.content_digest.as_str().to_owned());
            payload["reviewArtifactSizeBytes"] = serde_json::json!(review_artifact.size_bytes);
        }
        if let Self::Supersession { superseded, .. } = self {
            payload["supersededArtifactId"] =
                serde_json::Value::String(superseded.artifact_id.as_str().to_owned());
            payload["supersededArtifactDigest"] =
                serde_json::Value::String(superseded.content_digest.as_str().to_owned());
        }
        if let Self::ObjectionSevereAccepted {
            objection_artifact, ..
        } = self
        {
            payload["objectionArtifactId"] =
                serde_json::Value::String(objection_artifact.artifact_id.as_str().to_owned());
            payload["objectionArtifactDigest"] =
                serde_json::Value::String(objection_artifact.content_digest.as_str().to_owned());
            payload["objectionArtifactSizeBytes"] =
                serde_json::json!(objection_artifact.size_bytes);
        }
        if let Self::DecisionDraft {
            plan_artifact,
            plan_version,
            ..
        } = self
        {
            payload["planArtifactId"] =
                serde_json::Value::String(plan_artifact.artifact_id.as_str().to_owned());
            payload["planArtifactDigest"] =
                serde_json::Value::String(plan_artifact.content_digest.as_str().to_owned());
            payload["planArtifactSizeBytes"] = serde_json::json!(plan_artifact.size_bytes);
            payload["planVersion"] = serde_json::json!(plan_version);
        }
        if let Self::ObjectionRoundClosed { plan_approval, .. } = self {
            payload["approvalId"] =
                serde_json::Value::String(plan_approval.approval_id().as_str().to_owned());
            payload["approvalArtifactId"] = serde_json::Value::String(
                plan_approval
                    .request_artifact()
                    .artifact_id
                    .as_str()
                    .to_owned(),
            );
            payload["approvalDigest"] =
                serde_json::Value::String(plan_approval.operation_digest().as_str().to_owned());
            payload["approvalAuthorityBinding"] =
                serde_json::from_slice(plan_approval.authority_binding().canonical_bytes())
                    .expect("validated canonical approval authority binding");
            payload["approvalAuthorityBindingDigest"] = serde_json::Value::String(
                plan_approval
                    .authority_binding()
                    .content_digest()
                    .as_str()
                    .to_owned(),
            );
        }
        payload
    }

    fn validate_authority(
        &self,
        actor_id: &ActorId,
        run_assignments: &[DeliberationRunAssignment],
    ) -> Result<(), PortError> {
        match self {
            Self::PrivateProposal { proposal, .. } => {
                if run_assignments
                    .iter()
                    .any(|assignment| assignment.matches(proposal, actor_id))
                {
                    Ok(())
                } else {
                    Err(permission_denied())
                }
            }
            Self::SpecialistRequest { request, .. } => {
                if run_assignments
                    .iter()
                    .any(|assignment| assignment.matches_specialist(request, actor_id))
                {
                    Ok(())
                } else {
                    Err(permission_denied())
                }
            }
            _ if actor_id.as_str() == "core" => Ok(()),
            _ => Err(permission_denied()),
        }
    }

    pub(crate) fn authority_labels(
        &self,
        actor_id: &ActorId,
    ) -> Result<(&'static str, &'static str), PortError> {
        let authority = self.authority_schema(actor_id)?;
        Ok((authority.actor_type(), authority.observation_class()))
    }

    fn authority_schema(&self, actor_id: &ActorId) -> Result<RecordAuthority, PortError> {
        match self {
            Self::PrivateProposal { proposal, .. } if actor_id.as_str() == proposal.agent_id() => {
                Ok(RecordAuthority::AgentClaimed)
            }
            Self::SpecialistRequest { .. } if actor_id.as_str() != "core" => {
                Ok(RecordAuthority::AgentClaimed)
            }
            Self::PrivateProposal { .. } | Self::SpecialistRequest { .. } => {
                Err(permission_denied())
            }
            _ if actor_id.as_str() == "core" => Ok(RecordAuthority::CoreObserved),
            _ => Err(permission_denied()),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RecordAuthority {
    AgentClaimed,
    CoreObserved,
}

impl RecordAuthority {
    const fn actor_type(self) -> &'static str {
        match self {
            Self::AgentClaimed => "agent",
            Self::CoreObserved => "core",
        }
    }

    const fn observation_class(self) -> &'static str {
        match self {
            Self::AgentClaimed => "agent_claimed",
            Self::CoreObserved => "core_observed",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeliberationPersistenceCommand {
    task_id: TaskId,
    expected_task_version: u64,
    expected_task_state: WorkflowState,
    actor_id: ActorId,
    event_authority: EventAuthority,
    record: DeliberationRecord,
    append: AppendOperation,
}

impl DeliberationPersistenceCommand {
    pub fn task_id(&self) -> &TaskId {
        &self.task_id
    }

    pub const fn expected_task_version(&self) -> u64 {
        self.expected_task_version
    }

    pub const fn expected_task_state(&self) -> WorkflowState {
        self.expected_task_state
    }

    pub fn record(&self) -> &DeliberationRecord {
        &self.record
    }

    pub fn append(&self) -> &AppendOperation {
        &self.append
    }

    pub fn validate(&self) -> Result<(), PortError> {
        self.record.validate(&self.task_id)?;
        if self.expected_task_version != self.expected_task_state.sequence().get()
            || self.expected_task_state.phase() != self.record.expected_phase()
            || self.actor_id != self.event_authority.actor_id
        {
            return Err(conflict());
        }
        let expected = build_append(
            &self.task_id,
            self.expected_task_version,
            &self.expected_task_state,
            &self.event_authority,
            &self.record,
        )?;
        if self.append != expected {
            return Err(conflict());
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct EventAuthority {
    actor_id: ActorId,
    event_id: EventId,
    correlation_id: String,
    occurred_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeliberationRunAssignment {
    run_id: RunId,
    agent_id: String,
    family: AgentFamilyKey,
    actor_id: ActorId,
}

impl DeliberationRunAssignment {
    pub fn new(
        run_id: RunId,
        agent_id: impl Into<String>,
        family: AgentFamilyKey,
        actor_id: ActorId,
    ) -> Result<Self, PortError> {
        let assignment = Self {
            run_id,
            agent_id: agent_id.into(),
            family,
            actor_id,
        };
        validate_label(&assignment.agent_id)?;
        Ok(assignment)
    }

    pub(crate) fn run_id(&self) -> &RunId {
        &self.run_id
    }

    pub(crate) fn agent_id(&self) -> &str {
        &self.agent_id
    }

    pub(crate) fn actor_id(&self) -> &ActorId {
        &self.actor_id
    }

    pub(crate) fn matches(&self, proposal: &IndependentProposal, actor_id: &ActorId) -> bool {
        self.run_id == *proposal.run_id()
            && self.agent_id == proposal.agent_id()
            && self.family == *proposal.family()
            && self.actor_id == *actor_id
    }

    pub(crate) fn matches_specialist(
        &self,
        request: &SpecialistRequest,
        actor_id: &ActorId,
    ) -> bool {
        self.run_id == *request.requesting_run()
            && self.agent_id == actor_id.as_str()
            && self.actor_id == *actor_id
    }

    fn matches_proposal(&self, proposal: &IndependentProposal) -> bool {
        self.run_id == *proposal.run_id()
            && self.agent_id == proposal.agent_id()
            && self.family == *proposal.family()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrivateProposalSnapshot {
    proposal: IndependentProposal,
    proposal_artifact: DeliberationArtifactRef,
    receipt: DeliberationArtifactRef,
}

impl PrivateProposalSnapshot {
    pub(crate) fn new(
        proposal: IndependentProposal,
        proposal_artifact: DeliberationArtifactRef,
        receipt: DeliberationArtifactRef,
    ) -> Result<Self, PortError> {
        proposal_artifact.validate()?;
        receipt.validate()?;
        if proposal.is_revealed() || proposal.artifact_id() != proposal_artifact.artifact_id() {
            return Err(conflict());
        }
        Ok(Self {
            proposal,
            proposal_artifact,
            receipt,
        })
    }

    pub fn proposal(&self) -> &IndependentProposal {
        &self.proposal
    }

    pub fn proposal_artifact(&self) -> &DeliberationArtifactRef {
        &self.proposal_artifact
    }

    pub fn receipt(&self) -> &DeliberationArtifactRef {
        &self.receipt
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuorumPublicationSnapshot {
    event_id: EventId,
    event_sequence: u64,
    proposal_artifact: DeliberationArtifactRef,
    review_plan: ReviewPlan,
    review_artifact: DeliberationArtifactRef,
}

impl QuorumPublicationSnapshot {
    pub(crate) fn new(
        event_id: EventId,
        event_sequence: u64,
        proposal_artifact: DeliberationArtifactRef,
        review_plan: ReviewPlan,
        review_artifact: DeliberationArtifactRef,
    ) -> Result<Self, PortError> {
        proposal_artifact.validate()?;
        review_artifact.validate()?;
        if event_sequence == 0 || review_plan.edges().is_empty() {
            return Err(conflict());
        }
        Ok(Self {
            event_id,
            event_sequence,
            proposal_artifact,
            review_plan,
            review_artifact,
        })
    }

    pub fn event_id(&self) -> &EventId {
        &self.event_id
    }

    pub const fn event_sequence(&self) -> u64 {
        self.event_sequence
    }

    pub fn proposal_artifact(&self) -> &DeliberationArtifactRef {
        &self.proposal_artifact
    }

    pub fn review_plan(&self) -> &ReviewPlan {
        &self.review_plan
    }

    pub fn review_artifact(&self) -> &DeliberationArtifactRef {
        &self.review_artifact
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpecialistRequestSnapshot {
    event_id: EventId,
    event_sequence: u64,
    actor_id: ActorId,
    request: SpecialistRequest,
    artifact: DeliberationArtifactRef,
}

impl SpecialistRequestSnapshot {
    pub(crate) fn new(
        event_id: EventId,
        event_sequence: u64,
        actor_id: ActorId,
        request: SpecialistRequest,
        artifact: DeliberationArtifactRef,
    ) -> Result<Self, PortError> {
        artifact.validate()?;
        if event_sequence == 0 {
            return Err(conflict());
        }
        Ok(Self {
            event_id,
            event_sequence,
            actor_id,
            request,
            artifact,
        })
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

    pub fn request(&self) -> &SpecialistRequest {
        &self.request
    }

    pub fn artifact(&self) -> &DeliberationArtifactRef {
        &self.artifact
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReviewEdgesSnapshot {
    event_id: EventId,
    event_sequence: u64,
    actor_id: ActorId,
    plan: ReviewPlan,
    artifact: DeliberationArtifactRef,
}

impl ReviewEdgesSnapshot {
    pub(crate) fn new(
        event_id: EventId,
        event_sequence: u64,
        actor_id: ActorId,
        plan: ReviewPlan,
        artifact: DeliberationArtifactRef,
    ) -> Result<Self, PortError> {
        artifact.validate()?;
        if event_sequence == 0 || plan.edges().is_empty() {
            return Err(conflict());
        }
        Ok(Self {
            event_id,
            event_sequence,
            actor_id,
            plan,
            artifact,
        })
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

    pub fn plan(&self) -> &ReviewPlan {
        &self.plan
    }

    pub fn artifact(&self) -> &DeliberationArtifactRef {
        &self.artifact
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ThreadSummarySnapshot {
    event_id: EventId,
    event_sequence: u64,
    actor_id: ActorId,
    thread_id: String,
    artifact: DeliberationArtifactRef,
}

impl ThreadSummarySnapshot {
    pub(crate) fn new(
        event_id: EventId,
        event_sequence: u64,
        actor_id: ActorId,
        thread_id: String,
        artifact: DeliberationArtifactRef,
    ) -> Result<Self, PortError> {
        artifact.validate()?;
        validate_label(&thread_id)?;
        if event_sequence == 0 {
            return Err(conflict());
        }
        Ok(Self {
            event_id,
            event_sequence,
            actor_id,
            thread_id,
            artifact,
        })
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

    pub fn thread_id(&self) -> &str {
        &self.thread_id
    }

    pub fn artifact(&self) -> &DeliberationArtifactRef {
        &self.artifact
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClaimSetSnapshot {
    event_id: EventId,
    event_sequence: u64,
    actor_id: ActorId,
    claims: Vec<MaterialClaim>,
    artifact: DeliberationArtifactRef,
}

impl ClaimSetSnapshot {
    pub(crate) fn new(
        event_id: EventId,
        event_sequence: u64,
        actor_id: ActorId,
        claims: Vec<MaterialClaim>,
        artifact: DeliberationArtifactRef,
    ) -> Result<Self, PortError> {
        artifact.validate()?;
        validate_claim_set(&claims, false)?;
        if event_sequence == 0 || actor_id.as_str() != "core" {
            return Err(conflict());
        }
        Ok(Self {
            event_id,
            event_sequence,
            actor_id,
            claims,
            artifact,
        })
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

    pub fn claims(&self) -> &[MaterialClaim] {
        &self.claims
    }

    pub fn artifact(&self) -> &DeliberationArtifactRef {
        &self.artifact
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerificationSetSnapshot {
    event_id: EventId,
    event_sequence: u64,
    actor_id: ActorId,
    claims: Vec<MaterialClaim>,
    artifact: DeliberationArtifactRef,
}

impl VerificationSetSnapshot {
    pub(crate) fn new(
        event_id: EventId,
        event_sequence: u64,
        actor_id: ActorId,
        claims: Vec<MaterialClaim>,
        artifact: DeliberationArtifactRef,
    ) -> Result<Self, PortError> {
        artifact.validate()?;
        validate_claim_set(&claims, true)?;
        if event_sequence == 0 || actor_id.as_str() != "core" {
            return Err(conflict());
        }
        Ok(Self {
            event_id,
            event_sequence,
            actor_id,
            claims,
            artifact,
        })
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

    pub fn claims(&self) -> &[MaterialClaim] {
        &self.claims
    }

    pub fn artifact(&self) -> &DeliberationArtifactRef {
        &self.artifact
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecisionDraftSnapshot {
    event_id: EventId,
    event_sequence: u64,
    actor_id: ActorId,
    decision: DecisionPackage,
    artifact: DeliberationArtifactRef,
    plan_artifact: DeliberationArtifactRef,
    plan_version: u64,
}

impl DecisionDraftSnapshot {
    pub(crate) fn new(
        event_id: EventId,
        event_sequence: u64,
        actor_id: ActorId,
        decision: DecisionPackage,
        artifact: DeliberationArtifactRef,
        plan_artifact: DeliberationArtifactRef,
        plan_version: u64,
    ) -> Result<Self, PortError> {
        artifact.validate()?;
        plan_artifact.validate()?;
        if event_sequence == 0
            || actor_id.as_str() != "core"
            || decision.plan() != plan_artifact.artifact_id()
            || !(1..=MAX_SAFE_INTEGER).contains(&plan_version)
        {
            return Err(conflict());
        }
        Ok(Self {
            event_id,
            event_sequence,
            actor_id,
            decision,
            artifact,
            plan_artifact,
            plan_version,
        })
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

    pub fn decision(&self) -> &DecisionPackage {
        &self.decision
    }

    pub fn artifact(&self) -> &DeliberationArtifactRef {
        &self.artifact
    }

    pub fn plan_artifact(&self) -> &DeliberationArtifactRef {
        &self.plan_artifact
    }

    pub const fn plan_version(&self) -> u64 {
        self.plan_version
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObjectionSetSnapshot {
    event_id: EventId,
    event_sequence: u64,
    actor_id: ActorId,
    objections: FinalObjectionSet,
    artifact: DeliberationArtifactRef,
}

impl ObjectionSetSnapshot {
    pub(crate) fn new(
        event_id: EventId,
        event_sequence: u64,
        actor_id: ActorId,
        objections: FinalObjectionSet,
        artifact: DeliberationArtifactRef,
    ) -> Result<Self, PortError> {
        artifact.validate()?;
        if event_sequence == 0 || actor_id.as_str() != "core" {
            return Err(conflict());
        }
        Ok(Self {
            event_id,
            event_sequence,
            actor_id,
            objections,
            artifact,
        })
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

    pub fn objections(&self) -> &FinalObjectionSet {
        &self.objections
    }

    pub fn artifact(&self) -> &DeliberationArtifactRef {
        &self.artifact
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SevereObjectionAcceptanceSnapshot {
    event_id: EventId,
    event_sequence: u64,
    actor_id: ActorId,
    objections: FinalObjectionSet,
    objection_artifact: DeliberationArtifactRef,
    review_plan: ReviewPlan,
    review_artifact: DeliberationArtifactRef,
}

impl SevereObjectionAcceptanceSnapshot {
    pub(crate) fn new(
        event_id: EventId,
        event_sequence: u64,
        actor_id: ActorId,
        objections: FinalObjectionSet,
        objection_artifact: DeliberationArtifactRef,
        review_plan: ReviewPlan,
        review_artifact: DeliberationArtifactRef,
    ) -> Result<Self, PortError> {
        let record = DeliberationRecord::ObjectionSevereAccepted {
            objections: objections.clone(),
            objection_artifact: objection_artifact.clone(),
            review_plan: review_plan.clone(),
            review_artifact: review_artifact.clone(),
        };
        record.validate(&TaskId::new("recovery-validation").map_err(|_| conflict())?)?;
        if event_sequence == 0 || actor_id.as_str() != "core" {
            return Err(conflict());
        }
        Ok(Self {
            event_id,
            event_sequence,
            actor_id,
            objections,
            objection_artifact,
            review_plan,
            review_artifact,
        })
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

    pub fn objections(&self) -> &FinalObjectionSet {
        &self.objections
    }

    pub fn objection_artifact(&self) -> &DeliberationArtifactRef {
        &self.objection_artifact
    }

    pub fn review_plan(&self) -> &ReviewPlan {
        &self.review_plan
    }

    pub fn review_artifact(&self) -> &DeliberationArtifactRef {
        &self.review_artifact
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SupersessionSnapshot {
    event_id: EventId,
    event_sequence: u64,
    actor_id: ActorId,
    superseded: DeliberationArtifactRef,
    replacement: DeliberationArtifactRef,
}

impl SupersessionSnapshot {
    pub(crate) fn new(
        event_id: EventId,
        event_sequence: u64,
        actor_id: ActorId,
        superseded: DeliberationArtifactRef,
        replacement: DeliberationArtifactRef,
    ) -> Result<Self, PortError> {
        let record = DeliberationRecord::Supersession {
            superseded: superseded.clone(),
            replacement: replacement.clone(),
        };
        record.validate(&TaskId::new("recovery-validation").map_err(|_| conflict())?)?;
        if event_sequence == 0 || actor_id.as_str() != "core" {
            return Err(conflict());
        }
        Ok(Self {
            event_id,
            event_sequence,
            actor_id,
            superseded,
            replacement,
        })
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

    pub fn superseded(&self) -> &DeliberationArtifactRef {
        &self.superseded
    }

    pub fn replacement(&self) -> &DeliberationArtifactRef {
        &self.replacement
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObjectionRoundClosedSnapshot {
    event_id: EventId,
    event_sequence: u64,
    actor_id: ActorId,
    artifact: DeliberationArtifactRef,
    plan_approval: NewPlanApproval,
}

impl ObjectionRoundClosedSnapshot {
    pub(crate) fn new(
        event_id: EventId,
        event_sequence: u64,
        actor_id: ActorId,
        artifact: DeliberationArtifactRef,
        plan_approval: NewPlanApproval,
    ) -> Result<Self, PortError> {
        artifact.validate()?;
        plan_approval.validate()?;
        if event_sequence == 0 || actor_id.as_str() != "core" {
            return Err(conflict());
        }
        Ok(Self {
            event_id,
            event_sequence,
            actor_id,
            artifact,
            plan_approval,
        })
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

    pub fn artifact(&self) -> &DeliberationArtifactRef {
        &self.artifact
    }

    pub fn plan_approval(&self) -> &NewPlanApproval {
        &self.plan_approval
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeliberationSnapshot {
    pub task_id: TaskId,
    pub task_version: u64,
    pub task_state: WorkflowState,
    pub run_assignments: Vec<DeliberationRunAssignment>,
    pub quorum: Option<IndependentQuorum>,
    claims: Vec<MaterialClaim>,
    pub objections: Option<FinalObjectionSet>,
    pub objection_artifact: Option<DeliberationArtifactRef>,
    private_proposals: Vec<PrivateProposalSnapshot>,
    quorum_publication: Option<QuorumPublicationSnapshot>,
    specialist_requests: Vec<SpecialistRequestSnapshot>,
    review_edges: Vec<ReviewEdgesSnapshot>,
    thread_summaries: Vec<ThreadSummarySnapshot>,
    claim_sets: Vec<ClaimSetSnapshot>,
    verification_sets: Vec<VerificationSetSnapshot>,
    decision_drafts: Vec<DecisionDraftSnapshot>,
    objection_sets: Vec<ObjectionSetSnapshot>,
    severe_objection_acceptances: Vec<SevereObjectionAcceptanceSnapshot>,
    supersessions: Vec<SupersessionSnapshot>,
    objection_round_closures: Vec<ObjectionRoundClosedSnapshot>,
    plan_approval: Option<NewPlanApproval>,
}

pub(crate) struct RecoveredDeliberationState {
    pub task_id: TaskId,
    pub task_version: u64,
    pub task_state: WorkflowState,
    pub run_assignments: Vec<DeliberationRunAssignment>,
    pub private_proposals: Vec<PrivateProposalSnapshot>,
    pub quorum: Option<IndependentQuorum>,
    pub quorum_publication: Option<QuorumPublicationSnapshot>,
    pub specialist_requests: Vec<SpecialistRequestSnapshot>,
    pub review_edges: Vec<ReviewEdgesSnapshot>,
    pub thread_summaries: Vec<ThreadSummarySnapshot>,
    pub claim_sets: Vec<ClaimSetSnapshot>,
    pub verification_sets: Vec<VerificationSetSnapshot>,
    pub decision_drafts: Vec<DecisionDraftSnapshot>,
    pub objection_sets: Vec<ObjectionSetSnapshot>,
    pub severe_objection_acceptances: Vec<SevereObjectionAcceptanceSnapshot>,
    pub supersessions: Vec<SupersessionSnapshot>,
    pub objection_round_closures: Vec<ObjectionRoundClosedSnapshot>,
}

impl DeliberationSnapshot {
    pub(crate) fn from_recovery(recovered: RecoveredDeliberationState) -> Result<Self, PortError> {
        let claims = recovered
            .verification_sets
            .last()
            .map(|record| record.claims.clone())
            .or_else(|| {
                recovered
                    .claim_sets
                    .last()
                    .map(|record| record.claims.clone())
            })
            .unwrap_or_default();
        let objections = recovered
            .objection_sets
            .last()
            .map(|record| record.objections.clone());
        let objection_artifact = recovered
            .objection_sets
            .last()
            .map(|record| record.artifact.clone());
        let plan_approval = recovered
            .objection_round_closures
            .last()
            .map(|record| record.plan_approval.clone());
        let snapshot = Self {
            task_id: recovered.task_id,
            task_version: recovered.task_version,
            task_state: recovered.task_state,
            run_assignments: recovered.run_assignments,
            quorum: recovered.quorum,
            claims,
            objections,
            objection_artifact,
            private_proposals: recovered.private_proposals,
            quorum_publication: recovered.quorum_publication,
            specialist_requests: recovered.specialist_requests,
            review_edges: recovered.review_edges,
            thread_summaries: recovered.thread_summaries,
            claim_sets: recovered.claim_sets,
            verification_sets: recovered.verification_sets,
            decision_drafts: recovered.decision_drafts,
            objection_sets: recovered.objection_sets,
            severe_objection_acceptances: recovered.severe_objection_acceptances,
            supersessions: recovered.supersessions,
            objection_round_closures: recovered.objection_round_closures,
            plan_approval,
        };
        snapshot.validate_recovery()?;
        Ok(snapshot)
    }

    pub fn private_proposals(&self) -> &[PrivateProposalSnapshot] {
        &self.private_proposals
    }

    pub fn quorum(&self) -> Option<&IndependentQuorum> {
        self.quorum.as_ref()
    }

    pub fn review_plan(&self) -> Option<&ReviewPlan> {
        self.quorum_publication
            .as_ref()
            .map(QuorumPublicationSnapshot::review_plan)
    }

    pub fn quorum_publication(&self) -> Option<&QuorumPublicationSnapshot> {
        self.quorum_publication.as_ref()
    }

    pub fn specialist_requests(&self) -> &[SpecialistRequestSnapshot] {
        &self.specialist_requests
    }

    pub fn review_edges(&self) -> Option<&ReviewEdgesSnapshot> {
        self.review_edges.last()
    }

    pub fn review_edges_history(&self) -> &[ReviewEdgesSnapshot] {
        &self.review_edges
    }

    pub fn thread_summaries(&self) -> &[ThreadSummarySnapshot] {
        &self.thread_summaries
    }

    pub fn claims(&self) -> &[MaterialClaim] {
        &self.claims
    }

    pub fn claim_set(&self) -> Option<&ClaimSetSnapshot> {
        self.claim_sets.last()
    }

    pub fn claim_sets(&self) -> &[ClaimSetSnapshot] {
        &self.claim_sets
    }

    pub fn verification_set(&self) -> Option<&VerificationSetSnapshot> {
        self.verification_sets.last()
    }

    pub fn verification_sets(&self) -> &[VerificationSetSnapshot] {
        &self.verification_sets
    }

    pub fn decision_drafts(&self) -> &[DecisionDraftSnapshot] {
        &self.decision_drafts
    }

    pub fn objection_sets(&self) -> &[ObjectionSetSnapshot] {
        &self.objection_sets
    }

    pub fn severe_objection_acceptances(&self) -> &[SevereObjectionAcceptanceSnapshot] {
        &self.severe_objection_acceptances
    }

    pub fn supersessions(&self) -> &[SupersessionSnapshot] {
        &self.supersessions
    }

    pub fn objection_round_closures(&self) -> &[ObjectionRoundClosedSnapshot] {
        &self.objection_round_closures
    }

    pub fn plan_approval(&self) -> Option<&NewPlanApproval> {
        self.plan_approval.as_ref()
    }

    fn validate_recovery(&self) -> Result<(), PortError> {
        self.validate()
    }

    pub fn validate(&self) -> Result<(), PortError> {
        if self.task_version != self.task_state.sequence().get()
            || self.run_assignments.is_empty()
            || self
                .run_assignments
                .iter()
                .map(|assignment| &assignment.run_id)
                .collect::<BTreeSet<_>>()
                .len()
                != self.run_assignments.len()
            || self
                .run_assignments
                .iter()
                .any(|assignment| assignment.actor_id.as_str() != assignment.agent_id)
            || self
                .private_proposals
                .iter()
                .map(|record| record.proposal.run_id())
                .collect::<BTreeSet<_>>()
                .len()
                != self.private_proposals.len()
            || self
                .private_proposals
                .iter()
                .map(|record| record.proposal.artifact_id())
                .collect::<BTreeSet<_>>()
                .len()
                != self.private_proposals.len()
            || self.private_proposals.iter().any(|record| {
                record.proposal.task_id() != &self.task_id
                    || record.proposal.is_revealed()
                    || record.proposal.artifact_id() != record.proposal_artifact.artifact_id()
                    || !self
                        .run_assignments
                        .iter()
                        .any(|assignment| assignment.matches_proposal(&record.proposal))
            })
            || (self.quorum_publication.is_some()
                && self.task_state.phase() <= Phase::ParallelAnalysis)
            || self
                .supported_history_phase()
                .is_some_and(|phase| phase != self.task_state.phase())
            || !self.has_valid_quorum_publication()
            || !self.has_valid_phase_neutral_history()
            || !self.has_valid_decision_history()
            || self.objections.as_ref()
                != self
                    .objection_sets
                    .last()
                    .map(ObjectionSetSnapshot::objections)
            || self.objection_artifact.as_ref()
                != self
                    .objection_sets
                    .last()
                    .map(ObjectionSetSnapshot::artifact)
        {
            Err(conflict())
        } else {
            Ok(())
        }
    }

    fn has_valid_quorum_publication(&self) -> bool {
        let (Some(quorum), Some(publication)) = (&self.quorum, &self.quorum_publication) else {
            return self.quorum.is_none() && self.quorum_publication.is_none();
        };
        if publication.event_sequence > self.task_version
            || publication.proposal_artifact.validate().is_err()
            || publication.review_artifact.validate().is_err()
        {
            return false;
        }
        let targets = publication
            .review_plan
            .edges()
            .iter()
            .map(|edge| edge.target_proposal())
            .collect::<BTreeSet<_>>();
        if publication.review_plan.edges().iter().any(|edge| {
            !self
                .run_assignments
                .iter()
                .any(|assignment| assignment.agent_id() == edge.reviewer_id())
        }) {
            return false;
        }
        let selected = self
            .private_proposals
            .iter()
            .filter(|record| targets.contains(record.proposal.artifact_id()))
            .map(|record| record.proposal.clone())
            .collect::<Vec<_>>();
        selected.len() == targets.len()
            && IndependentQuorum::new(selected)
                .map(IndependentQuorum::reveal)
                .is_ok_and(|expected| expected == quorum.proposals())
    }

    fn supported_history_phase(&self) -> Option<Phase> {
        if !self.objection_round_closures.is_empty() {
            Some(Phase::AwaitingPlanApproval)
        } else if self.claim_sets.len() > self.decision_drafts.len() {
            if self.verification_sets.len() < self.claim_sets.len() {
                Some(Phase::PrePlanVerification)
            } else {
                Some(Phase::Synthesis)
            }
        } else if self.severe_objection_acceptances.len() == self.decision_drafts.len()
            && !self.severe_objection_acceptances.is_empty()
        {
            Some(Phase::CrossReview)
        } else if !self.decision_drafts.is_empty() {
            Some(Phase::FinalObjection)
        } else if self.quorum_publication.is_some() {
            Some(Phase::CrossReview)
        } else if !self.private_proposals.is_empty() || !self.specialist_requests.is_empty() {
            Some(Phase::ParallelAnalysis)
        } else {
            None
        }
    }

    fn has_valid_phase_neutral_history(&self) -> bool {
        let publication_sequence = self
            .quorum_publication
            .as_ref()
            .map(QuorumPublicationSnapshot::event_sequence);
        if self
            .specialist_requests
            .windows(2)
            .any(|pair| pair[0].event_sequence >= pair[1].event_sequence)
            || self
                .thread_summaries
                .windows(2)
                .any(|pair| pair[0].event_sequence >= pair[1].event_sequence)
            || self
                .specialist_requests
                .iter()
                .map(|record| record.request.request_id())
                .collect::<BTreeSet<_>>()
                .len()
                != self.specialist_requests.len()
            || self
                .thread_summaries
                .iter()
                .map(|record| record.thread_id.as_str())
                .collect::<BTreeSet<_>>()
                .len()
                != self.thread_summaries.len()
        {
            return false;
        }
        let mut event_ids = BTreeSet::new();
        let mut event_sequences = BTreeSet::new();
        if let Some(publication) = &self.quorum_publication {
            event_ids.insert(&publication.event_id);
            event_sequences.insert(publication.event_sequence);
        }
        for record in &self.specialist_requests {
            if record.event_sequence > self.task_version
                || publication_sequence.is_some_and(|sequence| record.event_sequence >= sequence)
                || record.request.task_id() != &self.task_id
                || record.artifact.validate().is_err()
                || !self.run_assignments.iter().any(|assignment| {
                    assignment.matches_specialist(&record.request, &record.actor_id)
                })
                || !event_ids.insert(&record.event_id)
                || !event_sequences.insert(record.event_sequence)
            {
                return false;
            }
        }
        if self.quorum_publication.is_none() {
            return self.review_edges.is_empty() && self.thread_summaries.is_empty();
        }
        for record in &self.review_edges {
            if !self.matches_review_window(record.event_sequence, &record.plan, &record.artifact)
                || record.event_sequence > self.task_version
                || record.actor_id.as_str() != "core"
                || record.artifact.validate().is_err()
                || !event_ids.insert(&record.event_id)
                || !event_sequences.insert(record.event_sequence)
            {
                return false;
            }
        }
        self.thread_summaries.iter().all(|record| {
            self.is_cross_review_sequence(record.event_sequence)
                && record.event_sequence <= self.task_version
                && record.actor_id.as_str() == "core"
                && record.artifact.validate().is_ok()
                && event_ids.insert(&record.event_id)
                && event_sequences.insert(record.event_sequence)
        })
    }

    fn is_cross_review_sequence(&self, event_sequence: u64) -> bool {
        let initial = self.quorum_publication.as_ref().is_some_and(|publication| {
            event_sequence > publication.event_sequence
                && self
                    .claim_sets
                    .first()
                    .is_none_or(|claim_set| event_sequence < claim_set.event_sequence)
        });
        initial
            || self
                .severe_objection_acceptances
                .iter()
                .enumerate()
                .any(|(index, accepted)| {
                    event_sequence > accepted.event_sequence
                        && self
                            .claim_sets
                            .get(index + 1)
                            .is_none_or(|claim_set| event_sequence < claim_set.event_sequence)
                })
    }

    fn matches_review_window(
        &self,
        event_sequence: u64,
        plan: &ReviewPlan,
        artifact: &DeliberationArtifactRef,
    ) -> bool {
        let initial = self.quorum_publication.as_ref().is_some_and(|publication| {
            event_sequence > publication.event_sequence
                && self
                    .claim_sets
                    .first()
                    .is_none_or(|claim_set| event_sequence < claim_set.event_sequence)
                && plan == &publication.review_plan
                && artifact == &publication.review_artifact
        });
        initial
            || self
                .severe_objection_acceptances
                .iter()
                .enumerate()
                .any(|(index, accepted)| {
                    event_sequence > accepted.event_sequence
                        && self
                            .claim_sets
                            .get(index + 1)
                            .is_none_or(|claim_set| event_sequence < claim_set.event_sequence)
                        && plan == &accepted.review_plan
                        && artifact == &accepted.review_artifact
                })
    }

    fn has_valid_decision_history(&self) -> bool {
        if self.claim_sets.is_empty() {
            return self.verification_sets.is_empty()
                && self.decision_drafts.is_empty()
                && self.objection_sets.is_empty()
                && self.severe_objection_acceptances.is_empty()
                && self.supersessions.is_empty()
                && self.objection_round_closures.is_empty()
                && self.claims.is_empty();
        }
        let Some(publication) = &self.quorum_publication else {
            return false;
        };
        if self.claim_sets.len() > 2
            || self.verification_sets.len() > self.claim_sets.len()
            || self.decision_drafts.len() > self.verification_sets.len()
            || self.objection_sets.len() > self.decision_drafts.len()
            || self.severe_objection_acceptances.len() > 1
            || self.supersessions.len() > 1
            || self.objection_round_closures.len() > 1
            || self.claim_sets.len() > self.severe_objection_acceptances.len() + 1
        {
            return false;
        }
        for (index, claim_set) in self.claim_sets.iter().enumerate() {
            let lower_bound = if index == 0 {
                publication.event_sequence
            } else {
                let Some(accepted) = self.severe_objection_acceptances.get(index - 1) else {
                    return false;
                };
                accepted.event_sequence
            };
            let latest_review_sequence = self
                .thread_summaries
                .iter()
                .filter(|record| {
                    record.event_sequence > lower_bound
                        && record.event_sequence < claim_set.event_sequence
                })
                .map(ThreadSummarySnapshot::event_sequence)
                .chain(
                    self.review_edges
                        .iter()
                        .filter(|record| {
                            record.event_sequence > lower_bound
                                && record.event_sequence < claim_set.event_sequence
                        })
                        .map(ReviewEdgesSnapshot::event_sequence),
                )
                .chain(std::iter::once(lower_bound))
                .max()
                .expect("lower review boundary is present");
            if claim_set.event_sequence <= latest_review_sequence
                || claim_set.event_sequence > self.task_version
                || claim_set.actor_id.as_str() != "core"
                || claim_set.artifact.validate().is_err()
                || validate_claim_set(&claim_set.claims, false).is_err()
            {
                return false;
            }
            let Some(verification_set) = self.verification_sets.get(index) else {
                continue;
            };
            if verification_set.event_sequence <= claim_set.event_sequence
                || verification_set.event_sequence > self.task_version
                || verification_set.actor_id.as_str() != "core"
                || verification_set.artifact.validate().is_err()
                || validate_claim_set(&verification_set.claims, true).is_err()
                || !same_claim_authority(&claim_set.claims, &verification_set.claims)
            {
                return false;
            }
            let Some(decision) = self.decision_drafts.get(index) else {
                continue;
            };
            let decision_lower_bound = if index == 0 {
                verification_set.event_sequence
            } else {
                let Some(supersession) = self.supersessions.get(index - 1) else {
                    return false;
                };
                if supersession.event_sequence <= verification_set.event_sequence
                    || supersession.superseded != self.decision_drafts[index - 1].artifact
                    || supersession.replacement != decision.artifact
                {
                    return false;
                }
                supersession.event_sequence
            };
            if decision.event_sequence <= decision_lower_bound
                || decision.event_sequence > self.task_version
                || decision.actor_id.as_str() != "core"
                || decision.artifact.validate().is_err()
                || decision.plan_artifact.validate().is_err()
                || decision.decision.plan() != decision.plan_artifact.artifact_id()
                || !(1..=MAX_SAFE_INTEGER).contains(&decision.plan_version)
                || !same_claim_records(&verification_set.claims, decision.decision.evidence())
            {
                return false;
            }
        }
        if self.supersessions.len()
            > self
                .decision_drafts
                .len()
                .saturating_sub(1)
                .saturating_add(1)
        {
            return false;
        }
        if let Some(pending) = self
            .supersessions
            .get(self.decision_drafts.len().saturating_sub(1))
        {
            let Some(current) = self.decision_drafts.last() else {
                return false;
            };
            let Some(verification) = self.verification_sets.get(self.decision_drafts.len()) else {
                return false;
            };
            if pending.event_sequence <= verification.event_sequence
                || pending.superseded != current.artifact
            {
                return false;
            }
        }
        if !self.has_valid_objection_history() {
            return false;
        }
        self.claims
            == self
                .verification_sets
                .last()
                .map(|record| &record.claims)
                .or_else(|| self.claim_sets.last().map(|record| &record.claims))
                .cloned()
                .unwrap_or_default()
    }

    fn has_valid_objection_history(&self) -> bool {
        for (index, objection_set) in self.objection_sets.iter().enumerate() {
            let Some(decision) = self.decision_drafts.get(index) else {
                return false;
            };
            if objection_set.event_sequence <= decision.event_sequence
                || objection_set.event_sequence > self.task_version
                || objection_set.actor_id.as_str() != "core"
                || objection_set.artifact.validate().is_err()
                || objection_set.objections.round() != index as u32 + 1
            {
                return false;
            }
        }
        for (index, accepted) in self.severe_objection_acceptances.iter().enumerate() {
            let Some(objection_set) = self.objection_sets.get(index) else {
                return false;
            };
            if accepted.event_sequence <= objection_set.event_sequence
                || accepted.event_sequence > self.task_version
                || accepted.actor_id.as_str() != "core"
                || accepted.objections != objection_set.objections
                || accepted.objection_artifact != objection_set.artifact
                || self.quorum.as_ref().is_none_or(|quorum| {
                    !review_plan_is_authorized(quorum, &self.run_assignments, &accepted.review_plan)
                })
            {
                return false;
            }
        }
        let expected_plan_approval = self
            .objection_round_closures
            .last()
            .map(|record| &record.plan_approval);
        if self.plan_approval.as_ref() != expected_plan_approval {
            return false;
        }
        let Some(closed) = self.objection_round_closures.first() else {
            return true;
        };
        let Some(objection_set) = self.objection_sets.last() else {
            return false;
        };
        let Some(decision) = self.decision_drafts.last() else {
            return false;
        };
        let binding = closed.plan_approval.binding();
        closed.event_sequence > objection_set.event_sequence
            && closed.event_sequence <= self.task_version
            && closed.actor_id.as_str() == "core"
            && closed.artifact.validate().is_ok()
            && closed.plan_approval.validate().is_ok()
            && closed.plan_approval.task_id() == &self.task_id
            && self.severe_objection_acceptances.len() < self.objection_sets.len()
            && binding.plan_artifact_id == decision.plan_artifact.artifact_id().as_str()
            && binding.plan_digest == decision.plan_artifact.content_digest().as_str()
            && binding.plan_version == decision.plan_version
    }
}

pub trait DeliberationStore: Send + Sync {
    fn load(&self, task_id: &TaskId) -> Result<DeliberationSnapshot, PortError>;
    /// Atomically persists the deliberation record, its exact event append, and every reducer-
    /// derived projection change. Implementations must reject commands whose `validate` method
    /// fails and must never expose a partial record/event/projection write.
    fn persist(&self, command: DeliberationPersistenceCommand) -> Result<(), PortError>;
}

pub trait PlanApprovalAuthorityProvider: Send + Sync {
    fn current(&self, task_id: &TaskId) -> Result<PlanApprovalAuthorityBinding, PortError>;
}

pub struct DeliberationCommands<'a> {
    store: &'a dyn DeliberationStore,
    plan_approval_authority: Option<&'a dyn PlanApprovalAuthorityProvider>,
}

impl<'a> DeliberationCommands<'a> {
    pub const fn new(store: &'a dyn DeliberationStore) -> Self {
        Self {
            store,
            plan_approval_authority: None,
        }
    }

    pub const fn with_plan_approval_authority(
        store: &'a dyn DeliberationStore,
        plan_approval_authority: &'a dyn PlanApprovalAuthorityProvider,
    ) -> Self {
        Self {
            store,
            plan_approval_authority: Some(plan_approval_authority),
        }
    }

    pub fn record_private_proposal(
        &self,
        context: DeliberationCommandContext,
        proposal: IndependentProposal,
        proposal_artifact: DeliberationArtifactRef,
    ) -> Result<(), PortError> {
        let snapshot = self.authorize(&context, Phase::ParallelAnalysis)?;
        if snapshot.quorum.is_some()
            || snapshot.quorum_publication.is_some()
            || snapshot.private_proposals.iter().any(|existing| {
                existing.proposal.run_id() == proposal.run_id()
                    || existing.proposal.artifact_id() == proposal.artifact_id()
            })
        {
            return Err(conflict());
        }
        self.persist_authorized(
            context.clone(),
            snapshot,
            DeliberationRecord::PrivateProposal {
                proposal,
                proposal_artifact,
                receipt: context.record_artifact.clone(),
            },
        )
    }

    pub fn publish_proposals(
        &self,
        context: DeliberationCommandContext,
        review_plan: ReviewPlan,
        review_artifact: DeliberationArtifactRef,
    ) -> Result<(), PortError> {
        let snapshot = self.authorize(&context, Phase::ParallelAnalysis)?;
        if snapshot.quorum.is_some() || snapshot.quorum_publication.is_some() {
            return Err(conflict());
        }
        let review_targets: BTreeSet<_> = review_plan
            .edges()
            .iter()
            .map(|edge| edge.target_proposal())
            .collect();
        let selected = snapshot
            .private_proposals
            .iter()
            .filter(|record| review_targets.contains(record.proposal.artifact_id()))
            .map(|record| record.proposal.clone())
            .collect::<Vec<_>>();
        if selected.len() != review_targets.len()
            || review_plan.edges().iter().any(|edge| {
                !snapshot
                    .run_assignments
                    .iter()
                    .any(|assignment| assignment.agent_id() == edge.reviewer_id())
            })
        {
            return Err(conflict());
        }
        let proposals = IndependentQuorum::new(selected)
            .map_err(|_| conflict())?
            .reveal();
        self.persist_authorized(
            context.clone(),
            snapshot,
            DeliberationRecord::QuorumPublication {
                proposals,
                proposal_artifact: context.record_artifact.clone(),
                review_plan,
                review_artifact,
            },
        )
    }

    pub fn record_review_edges(
        &self,
        context: DeliberationCommandContext,
        plan: ReviewPlan,
    ) -> Result<(), PortError> {
        let snapshot = self.authorize(&context, Phase::CrossReview)?;
        let (active_plan, active_artifact) = snapshot
            .severe_objection_acceptances
            .last()
            .map(|accepted| (&accepted.review_plan, &accepted.review_artifact))
            .or_else(|| {
                snapshot
                    .quorum_publication
                    .as_ref()
                    .map(|publication| (&publication.review_plan, &publication.review_artifact))
            })
            .ok_or_else(conflict)?;
        if snapshot
            .review_edges
            .iter()
            .any(|existing| existing.plan == *active_plan && existing.artifact == *active_artifact)
            || plan != *active_plan
            || context.record_artifact != *active_artifact
        {
            return Err(conflict());
        }
        self.persist_authorized(
            context.clone(),
            snapshot,
            DeliberationRecord::ReviewEdges {
                plan,
                artifact: context.record_artifact.clone(),
            },
        )
    }

    pub fn record_thread_summary(
        &self,
        context: DeliberationCommandContext,
        thread_id: impl Into<String>,
    ) -> Result<(), PortError> {
        let snapshot = self.authorize(&context, Phase::CrossReview)?;
        let thread_id = thread_id.into();
        if snapshot.quorum_publication.is_none()
            || snapshot
                .thread_summaries
                .iter()
                .any(|existing| existing.thread_id == thread_id)
        {
            return Err(conflict());
        }
        self.persist_authorized(
            context.clone(),
            snapshot,
            DeliberationRecord::ThreadSummary {
                thread_id,
                artifact: context.record_artifact.clone(),
            },
        )
    }

    pub fn request_specialist(
        &self,
        context: DeliberationCommandContext,
        request: SpecialistRequest,
    ) -> Result<(), PortError> {
        let snapshot = self.authorize(&context, Phase::ParallelAnalysis)?;
        if snapshot.quorum.is_some()
            || snapshot.quorum_publication.is_some()
            || snapshot
                .specialist_requests
                .iter()
                .any(|existing| existing.request.request_id() == request.request_id())
        {
            return Err(conflict());
        }
        self.persist_authorized(
            context.clone(),
            snapshot,
            DeliberationRecord::SpecialistRequest {
                request,
                artifact: context.record_artifact.clone(),
            },
        )
    }

    pub fn record_claim_set(
        &self,
        context: DeliberationCommandContext,
        claims: Vec<MaterialClaim>,
    ) -> Result<(), PortError> {
        let snapshot = self.authorize(&context, Phase::CrossReview)?;
        if snapshot.quorum_publication.is_none()
            || snapshot.claim_sets.len() != snapshot.decision_drafts.len()
            || snapshot.verification_sets.len() != snapshot.claim_sets.len()
        {
            return Err(conflict());
        }
        self.persist_authorized(
            context.clone(),
            snapshot,
            DeliberationRecord::ClaimSet {
                claims,
                artifact: context.record_artifact.clone(),
            },
        )
    }

    pub fn record_verification_set(
        &self,
        context: DeliberationCommandContext,
        claims: Vec<MaterialClaim>,
    ) -> Result<(), PortError> {
        let snapshot = self.authorize(&context, Phase::PrePlanVerification)?;
        let Some(claim_set) = snapshot.claim_sets.last() else {
            return Err(conflict());
        };
        if snapshot.verification_sets.len() + 1 != snapshot.claim_sets.len()
            || !same_claim_authority(&claim_set.claims, &claims)
        {
            return Err(conflict());
        }
        self.persist_authorized(
            context.clone(),
            snapshot,
            DeliberationRecord::VerificationSet {
                claims,
                artifact: context.record_artifact.clone(),
            },
        )
    }

    pub fn synthesize(
        &self,
        context: DeliberationCommandContext,
        decision: DecisionPackage,
        plan_artifact: DeliberationArtifactRef,
        plan_version: u64,
    ) -> Result<(), PortError> {
        let snapshot = self.authorize(&context, Phase::Synthesis)?;
        let Some(verification_set) = snapshot.verification_sets.last() else {
            return Err(conflict());
        };
        let authoritative_claims: BTreeMap<_, _> = verification_set
            .claims
            .iter()
            .map(|claim| (claim.claim_id(), claim))
            .collect();
        let decision_claims: BTreeMap<_, _> = decision
            .evidence()
            .iter()
            .map(|claim| (claim.claim_id(), claim))
            .collect();
        let replacement_matches = if snapshot.decision_drafts.is_empty() {
            snapshot.supersessions.is_empty()
        } else {
            snapshot.supersessions.len() == snapshot.decision_drafts.len()
                && snapshot
                    .supersessions
                    .last()
                    .is_some_and(|record| record.replacement == context.record_artifact)
        };
        if snapshot.decision_drafts.len() + 1 != snapshot.verification_sets.len()
            || !replacement_matches
            || verification_set
                .claims
                .iter()
                .any(|claim| claim.verification().is_none())
            || authoritative_claims.len() != verification_set.claims.len()
            || decision_claims.len() != decision.evidence().len()
            || authoritative_claims != decision_claims
        {
            return Err(conflict());
        }
        self.persist_authorized(
            context.clone(),
            snapshot,
            DeliberationRecord::DecisionDraft {
                decision,
                artifact: context.record_artifact.clone(),
                plan_artifact,
                plan_version,
            },
        )
    }

    pub fn record_objection_set(
        &self,
        context: DeliberationCommandContext,
        objections: FinalObjectionSet,
    ) -> Result<(), PortError> {
        let snapshot = self.authorize(&context, Phase::FinalObjection)?;
        if snapshot.objection_sets.len() + 1 != snapshot.decision_drafts.len()
            || snapshot.severe_objection_acceptances.len() != snapshot.objection_sets.len()
            || objections.round() != snapshot.objection_sets.len() as u32 + 1
        {
            return Err(conflict());
        }
        self.persist_authorized(
            context.clone(),
            snapshot,
            DeliberationRecord::ObjectionSet {
                objections,
                artifact: context.record_artifact.clone(),
            },
        )
    }

    pub fn accept_severe_objection(
        &self,
        context: DeliberationCommandContext,
        review_plan: ReviewPlan,
    ) -> Result<(), PortError> {
        let snapshot = self.authorize(&context, Phase::FinalObjection)?;
        let current_objections = snapshot.objection_sets.last().ok_or_else(conflict)?;
        let objections = current_objections.objections.clone();
        let objection_artifact = current_objections.artifact.clone();
        let quorum = snapshot.quorum.as_ref().ok_or_else(conflict)?;
        if snapshot.severe_objection_acceptances.len() + 1 != snapshot.objection_sets.len()
            || !snapshot.severe_objection_acceptances.is_empty()
            || !review_plan_is_authorized(quorum, &snapshot.run_assignments, &review_plan)
        {
            return Err(conflict());
        }
        self.persist_authorized(
            context.clone(),
            snapshot,
            DeliberationRecord::ObjectionSevereAccepted {
                objections,
                objection_artifact,
                review_plan,
                review_artifact: context.record_artifact.clone(),
            },
        )
    }

    pub fn close_objection_round(
        &self,
        context: DeliberationCommandContext,
        approval_input: PreparePlanApprovalRequestInput,
    ) -> Result<(), PortError> {
        let snapshot = self.authorize(&context, Phase::FinalObjection)?;
        if !snapshot.objection_round_closures.is_empty()
            || snapshot.objection_sets.len() != snapshot.decision_drafts.len()
            || snapshot.severe_objection_acceptances.len() >= snapshot.objection_sets.len()
        {
            return Err(conflict());
        }
        let transition = WorkflowEvent::new("objection.round.closed").map_err(|_| conflict())?;
        let mut guards = GuardEvaluations::new();
        guards.insert(
            GuardName::new("no_accepted_severe_objection").map_err(|_| conflict())?,
            true,
        );
        let next_state = *reduce(&snapshot.task_state, &transition, &guards)
            .map_err(|_| conflict())?
            .state();
        let approval_authority = self
            .plan_approval_authority
            .ok_or_else(conflict)?
            .current(&snapshot.task_id)?;
        approval_authority.validate()?;
        let current_decision = snapshot.decision_drafts.last().ok_or_else(conflict)?;
        let binding = approval_authority.binding();
        if binding.plan_artifact_id != current_decision.plan_artifact.artifact_id().as_str()
            || binding.plan_digest != current_decision.plan_artifact.content_digest().as_str()
            || binding.plan_version != current_decision.plan_version
        {
            return Err(conflict());
        }
        let approval_state = PlanApprovalCurrentState {
            phase: next_state.phase(),
            task_state: next_state,
            binding: approval_authority.binding().clone(),
        };
        let plan_approval = PreparePlanApprovalRequest::execute(
            approval_input,
            &approval_authority,
            &approval_state,
        )?;
        self.persist_authorized(
            context.clone(),
            snapshot,
            DeliberationRecord::ObjectionRoundClosed {
                artifact: context.record_artifact.clone(),
                plan_approval: Box::new(plan_approval),
            },
        )
    }

    pub fn record_supersession(
        &self,
        context: DeliberationCommandContext,
        superseded: DeliberationArtifactRef,
    ) -> Result<(), PortError> {
        let snapshot = self.authorize(&context, Phase::Synthesis)?;
        let Some(current_decision) = snapshot.decision_drafts.last() else {
            return Err(conflict());
        };
        if superseded != current_decision.artifact
            || snapshot.verification_sets.len() != snapshot.decision_drafts.len() + 1
            || snapshot.severe_objection_acceptances.len() != snapshot.decision_drafts.len()
            || snapshot.supersessions.len() + 1 != snapshot.decision_drafts.len()
        {
            return Err(conflict());
        }
        self.persist_authorized(
            context.clone(),
            snapshot,
            DeliberationRecord::Supersession {
                superseded,
                replacement: context.record_artifact.clone(),
            },
        )
    }

    fn persist_authorized(
        &self,
        context: DeliberationCommandContext,
        snapshot: DeliberationSnapshot,
        record: DeliberationRecord,
    ) -> Result<(), PortError> {
        record.validate(&snapshot.task_id)?;
        record.validate_authority(&context.actor_id, &snapshot.run_assignments)?;
        let event_authority = context.event_authority();
        let append = build_append(
            &snapshot.task_id,
            snapshot.task_version,
            &snapshot.task_state,
            &event_authority,
            &record,
        )?;
        let command = DeliberationPersistenceCommand {
            task_id: snapshot.task_id,
            expected_task_version: snapshot.task_version,
            expected_task_state: snapshot.task_state,
            actor_id: context.actor_id,
            event_authority,
            record,
            append,
        };
        command.validate()?;
        self.store.persist(command)
    }

    fn authorize(
        &self,
        context: &DeliberationCommandContext,
        expected_phase: Phase,
    ) -> Result<DeliberationSnapshot, PortError> {
        context.validate()?;
        let snapshot = self.store.load(&context.task_id)?;
        snapshot.validate()?;
        if snapshot.task_id != context.task_id
            || snapshot.task_version != context.expected_task_version
            || snapshot.task_state != context.expected_task_state
            || snapshot.task_state.phase() != expected_phase
        {
            return Err(conflict());
        }
        Ok(snapshot)
    }
}

fn build_append(
    task_id: &TaskId,
    expected_task_version: u64,
    expected_task_state: &WorkflowState,
    authority: &EventAuthority,
    record: &DeliberationRecord,
) -> Result<AppendOperation, PortError> {
    let event_type = WorkflowEvent::new(record.event_type()).map_err(|_| conflict())?;
    let (actor_type, observation_class) = record.authority_labels(&authority.actor_id)?;
    let event_sequence = expected_task_version.checked_add(1).ok_or_else(conflict)?;
    let canonical_record = CanonicalDeliberationFact::issue(
        task_id.clone(),
        authority.event_id.clone(),
        event_sequence,
        authority.actor_id.clone(),
        record.clone(),
    )?;
    let projection_changes = if record.changes_phase() {
        let mut guards = GuardEvaluations::new();
        let guard = record.transition_guard().ok_or_else(conflict)?;
        guards.insert(GuardName::new(guard).map_err(|_| conflict())?, true);
        let state = *reduce(expected_task_state, &event_type, &guards)
            .map_err(|_| conflict())?
            .state();
        vec![ProjectionChange::TaskState {
            task_id: task_id.clone(),
            state,
            updated_at: authority.occurred_at.clone(),
        }]
    } else {
        Vec::new()
    };
    Ok(AppendOperation {
        stream_id: StreamId::new(task_id.as_str()).map_err(|_| conflict())?,
        expected_version: local_agent_terminal_domain::Sequence::new(expected_task_version),
        events: vec![NewEvent {
            event_id: authority.event_id.clone(),
            event_type,
            schema_version: 1,
            actor_type: actor_type.to_owned(),
            actor_id: authority.actor_id.clone(),
            observation_class: observation_class.to_owned(),
            payload: record.event_payload(task_id, canonical_record.content_digest()),
            metadata: serde_json::json!({}),
            causation_id: None,
            correlation_id: authority.correlation_id.clone(),
            created_at: authority.occurred_at.clone(),
        }],
        projection_changes,
    })
}

fn validate_claim_set(claims: &[MaterialClaim], require_terminal: bool) -> Result<(), PortError> {
    if claims.is_empty()
        || claims
            .iter()
            .map(MaterialClaim::claim_id)
            .collect::<BTreeSet<_>>()
            .len()
            != claims.len()
        || (!require_terminal && claims.iter().any(|claim| claim.verification().is_some()))
        || (require_terminal && claims.iter().any(|claim| claim.verification().is_none()))
    {
        Err(conflict())
    } else {
        Ok(())
    }
}

pub(crate) fn review_plan_is_authorized(
    quorum: &IndependentQuorum,
    assignments: &[DeliberationRunAssignment],
    review_plan: &ReviewPlan,
) -> bool {
    let expected_targets = quorum
        .proposals()
        .iter()
        .map(IndependentProposal::artifact_id)
        .collect::<BTreeSet<_>>();
    let actual_targets = review_plan
        .edges()
        .iter()
        .map(|edge| edge.target_proposal())
        .collect::<BTreeSet<_>>();
    let authorized_reviewers = assignments
        .iter()
        .map(DeliberationRunAssignment::agent_id)
        .collect::<BTreeSet<_>>();
    let actual_reviewers = review_plan
        .edges()
        .iter()
        .map(|edge| edge.reviewer_id())
        .collect::<BTreeSet<_>>();
    expected_targets == actual_targets
        && !actual_reviewers.is_empty()
        && actual_reviewers.is_subset(&authorized_reviewers)
}

pub(crate) fn same_claim_authority(expected: &[MaterialClaim], actual: &[MaterialClaim]) -> bool {
    if expected.len() != actual.len() {
        return false;
    }
    let expected: BTreeMap<_, _> = expected
        .iter()
        .map(|claim| (claim.claim_id(), claim))
        .collect();
    let actual: BTreeMap<_, _> = actual
        .iter()
        .map(|claim| (claim.claim_id(), claim))
        .collect();
    expected.len() == actual.len()
        && expected.iter().all(|(id, expected)| {
            actual.get(id).is_some_and(|actual| {
                expected.claimant() == actual.claimant()
                    && expected.artifact_id() == actual.artifact_id()
                    && expected.citations() == actual.citations()
                    && expected.method() == actual.method()
                    && actual.verification().is_some()
            })
        })
}

pub(crate) fn same_claim_records(expected: &[MaterialClaim], actual: &[MaterialClaim]) -> bool {
    if expected.len() != actual.len() {
        return false;
    }
    let expected: BTreeMap<_, _> = expected
        .iter()
        .map(|claim| (claim.claim_id(), claim))
        .collect();
    let actual: BTreeMap<_, _> = actual
        .iter()
        .map(|claim| (claim.claim_id(), claim))
        .collect();
    expected.len() == actual.len() && expected == actual
}

fn validate_label(value: &str) -> Result<(), PortError> {
    if value.trim().is_empty() || value.len() > 256 || value.contains('\0') {
        Err(invalid_input())
    } else {
        Ok(())
    }
}

fn invalid_input() -> PortError {
    PortError::failure(
        SafeErrorClassification::InvalidInput,
        Retryability::NonRetryable,
    )
}

fn conflict() -> PortError {
    PortError::failure(
        SafeErrorClassification::Conflict,
        Retryability::NonRetryable,
    )
}

fn permission_denied() -> PortError {
    PortError::failure(
        SafeErrorClassification::PermissionDenied,
        Retryability::NonRetryable,
    )
}

#[cfg(test)]
mod authority_tests {
    use local_agent_terminal_domain::{
        Condition, FencingToken, OperationState, Sequence, WorkspaceVersion,
    };

    use super::*;

    #[test]
    fn private_persistence_validator_rejects_wrong_event_and_arbitrary_task_projection() {
        let task_id = TaskId::new("task-1").unwrap();
        let state = WorkflowState::new(
            Phase::CrossReview,
            Condition::Active,
            OperationState::None,
            Sequence::new(7),
            WorkspaceVersion::new(1),
            FencingToken::new(1).unwrap(),
        )
        .unwrap();
        let record = DeliberationRecord::ThreadSummary {
            thread_id: "thread-1".to_owned(),
            artifact: DeliberationArtifactRef::new(
                ArtifactId::new("artifact-thread-1").unwrap(),
                Sha256Digest::new(format!("sha256:{}", "a".repeat(64))).unwrap(),
                17,
            )
            .unwrap(),
        };
        let authority = EventAuthority {
            actor_id: ActorId::new("core").unwrap(),
            event_id: EventId::new("event-1").unwrap(),
            correlation_id: "correlation-1".to_owned(),
            occurred_at: "2026-08-09T00:00:00Z".to_owned(),
        };
        let append = build_append(&task_id, 7, &state, &authority, &record).unwrap();
        let command = DeliberationPersistenceCommand {
            task_id: task_id.clone(),
            expected_task_version: 7,
            expected_task_state: state,
            actor_id: authority.actor_id.clone(),
            event_authority: authority.clone(),
            record: record.clone(),
            append: append.clone(),
        };
        command.validate().unwrap();

        let mut wrong_event = command.clone();
        wrong_event.append.events[0].event_type =
            WorkflowEvent::new("deliberation.arbitrary").unwrap();
        assert!(wrong_event.validate().is_err());

        let mut wrong_projection = command;
        wrong_projection
            .append
            .projection_changes
            .push(ProjectionChange::TaskState {
                task_id,
                state: WorkflowState::new(
                    Phase::ParallelAnalysis,
                    Condition::Active,
                    OperationState::Running,
                    Sequence::new(8),
                    WorkspaceVersion::new(2),
                    FencingToken::new(2).unwrap(),
                )
                .unwrap(),
                updated_at: authority.occurred_at,
            });
        assert!(wrong_projection.validate().is_err());
    }
}
