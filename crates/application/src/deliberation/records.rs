use std::collections::{BTreeMap, BTreeSet};

use local_agent_terminal_domain::{
    reduce, ActorId, AgentFamilyKey, AgentRunSnapshot, ArtifactId, BoundAgentRunRequest,
    DecisionPackage, DeliberationLimits, DeliberationTaskBudget, EventId, FinalObjectionSet,
    GuardEvaluations, GuardName, IndependentProposal, IndependentQuorum, MaterialClaim,
    ObjectionSeverity, Phase, ReviewPlan, RunId, Sha256Digest, SpecialistRequest, StreamId, TaskId,
    WorkflowEvent, WorkflowState, WorkspaceFingerprint,
};

use crate::{
    parse_policy_timestamp, AppendOperation, CanonicalDeliberationFact, DeliberationPlanDto,
    NewEvent, NewPlanApproval, PlanApprovalAuthorityBinding, PlanApprovalCurrentState, PortError,
    PreparePlanApprovalRequest, PreparePlanApprovalRequestInput, ProjectionChange, Retryability,
    SafeErrorClassification,
};

const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeliberationCommandContext {
    task_id: TaskId,
    expected_task_version: u64,
    expected_task_state: WorkflowState,
    task_budget: DeliberationTaskBudget,
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
        task_budget: DeliberationTaskBudget,
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
            task_budget,
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

    pub const fn task_budget(&self) -> DeliberationTaskBudget {
        self.task_budget
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

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DeliberationBudgetReservation {
    thread_count: u32,
    token_count: u64,
    cost_microunits: u64,
}

impl DeliberationBudgetReservation {
    pub const fn thread_count(self) -> u32 {
        self.thread_count
    }

    pub const fn token_count(self) -> u64 {
        self.token_count
    }

    pub const fn cost_microunits(self) -> u64 {
        self.cost_microunits
    }

    pub fn checked_add(self, additional: Self) -> Result<Self, PortError> {
        Ok(Self {
            thread_count: self
                .thread_count
                .checked_add(additional.thread_count)
                .ok_or_else(conflict)?,
            token_count: self
                .token_count
                .checked_add(additional.token_count)
                .ok_or_else(conflict)?,
            cost_microunits: self
                .cost_microunits
                .checked_add(additional.cost_microunits)
                .ok_or_else(conflict)?,
        })
    }

    fn validate_within(self, budget: DeliberationTaskBudget) -> Result<(), PortError> {
        if self.thread_count > budget.max_threads()
            || self.token_count > budget.max_tokens()
            || self.cost_microunits > budget.max_cost_microunits()
        {
            Err(conflict())
        } else {
            Ok(())
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
    pub fn budget_reservation(&self) -> DeliberationBudgetReservation {
        match self {
            Self::ThreadSummary { .. } => DeliberationBudgetReservation::default(),
            Self::SpecialistRequest { request, .. } => DeliberationBudgetReservation {
                thread_count: 1,
                token_count: request.budget().max_tokens(),
                cost_microunits: request.budget().max_cost_microunits(),
            },
            _ => DeliberationBudgetReservation::default(),
        }
    }

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
        task_budget: DeliberationTaskBudget,
        reservation: DeliberationBudgetReservation,
    ) -> serde_json::Value {
        let artifact = self.primary_artifact();
        let mut payload = serde_json::json!({
            "taskId": task_id.as_str(),
            "recordType": self.event_type(),
            "canonicalRecordDigest": canonical_record_digest.as_str(),
            "artifactId": artifact.artifact_id.as_str(),
            "artifactDigest": artifact.content_digest.as_str(),
            "artifactSizeBytes": artifact.size_bytes,
            "taskBudget": {
                "maxThreads": task_budget.max_threads(),
                "maxTokens": task_budget.max_tokens(),
                "maxCostMicrounits": task_budget.max_cost_microunits(),
                "deadlineUnixSeconds": task_budget.deadline().unix_seconds(),
            },
            "budgetReservation": {
                "threads": reservation.thread_count(),
                "tokens": reservation.token_count(),
                "costMicrounits": reservation.cost_microunits(),
            },
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
    task_budget: DeliberationTaskBudget,
    budget_reservation: DeliberationBudgetReservation,
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

    pub const fn task_budget(&self) -> DeliberationTaskBudget {
        self.task_budget
    }

    pub const fn budget_reservation(&self) -> DeliberationBudgetReservation {
        self.budget_reservation
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
            || self.budget_reservation != self.record.budget_reservation()
        {
            return Err(conflict());
        }
        self.budget_reservation.validate_within(self.task_budget)?;
        if parse_policy_timestamp(&self.event_authority.occurred_at)? > self.task_budget.deadline() {
            return Err(conflict());
        }
        let expected = build_append(
            &self.task_id,
            self.expected_task_version,
            &self.expected_task_state,
            &self.event_authority,
            &self.record,
            self.task_budget,
            self.budget_reservation,
        )?;
        if self.append != expected {
            return Err(conflict());
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeliberationSynthesisCommand {
    persistence: DeliberationPersistenceCommand,
    plan: DeliberationPlanDto,
}

impl DeliberationSynthesisCommand {
    pub fn persistence(&self) -> &DeliberationPersistenceCommand {
        &self.persistence
    }

    pub fn plan(&self) -> &DeliberationPlanDto {
        &self.plan
    }

    pub fn validate(&self) -> Result<(), PortError> {
        self.persistence.validate()?;
        let DeliberationRecord::DecisionDraft { decision, .. } = self.persistence.record() else {
            return Err(conflict());
        };
        validate_synthesis_plan(&self.plan, decision)
    }
}
