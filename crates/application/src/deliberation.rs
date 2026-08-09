use std::collections::{BTreeMap, BTreeSet};

use local_agent_terminal_domain::{
    reduce, ActorId, AgentFamilyKey, ArtifactId, DecisionPackage, EventId, FinalObjectionSet,
    GuardEvaluations, GuardName, IndependentProposal, IndependentQuorum, MaterialClaim, Phase,
    ReviewPlan, RunId, Sha256Digest, SpecialistRequest, StreamId, TaskId, WorkflowEvent,
    WorkflowState,
};

use crate::{
    parse_policy_timestamp, AppendOperation, NewEvent, NewPlanApproval,
    PlanApprovalAuthorityBinding, PlanApprovalCurrentState, PortError, PreparePlanApprovalRequest,
    PreparePlanApprovalRequestInput, ProjectionChange, Retryability, SafeErrorClassification,
};

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
    },
    ObjectionSet {
        objections: FinalObjectionSet,
        artifact: DeliberationArtifactRef,
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
            Self::PrivateProposal { proposal, receipt } => {
                receipt.validate()?;
                if proposal.task_id() != task_id || proposal.is_revealed() {
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
                if proposals.is_empty()
                    || proposals
                        .iter()
                        .any(|proposal| proposal.task_id() != task_id || !proposal.is_revealed())
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
            Self::DecisionDraft { artifact, .. } | Self::ObjectionSet { artifact, .. } => {
                artifact.validate()?
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
            Self::ObjectionSet { .. } | Self::ObjectionRoundClosed { .. } => Phase::FinalObjection,
        }
    }

    const fn event_type(&self) -> &'static str {
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
            Self::Supersession { replacement, .. } => replacement,
        }
    }

    fn event_payload(&self, task_id: &TaskId) -> serde_json::Value {
        let artifact = self.primary_artifact();
        let mut payload = serde_json::json!({
            "taskId": task_id.as_str(),
            "recordType": self.event_type(),
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

    fn matches(&self, proposal: &IndependentProposal, actor_id: &ActorId) -> bool {
        self.run_id == *proposal.run_id()
            && self.agent_id == proposal.agent_id()
            && self.family == *proposal.family()
            && self.actor_id == *actor_id
    }

    fn matches_proposal(&self, proposal: &IndependentProposal) -> bool {
        self.run_id == *proposal.run_id()
            && self.agent_id == proposal.agent_id()
            && self.family == *proposal.family()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeliberationSnapshot {
    pub task_id: TaskId,
    pub task_version: u64,
    pub task_state: WorkflowState,
    pub authorized_actors: Vec<ActorId>,
    pub run_assignments: Vec<DeliberationRunAssignment>,
    pub quorum: Option<IndependentQuorum>,
    pub claims: Vec<MaterialClaim>,
    pub accepted_severe_objection: bool,
    pub plan_approval_authority: Option<PlanApprovalAuthorityBinding>,
}

impl DeliberationSnapshot {
    pub fn validate(&self) -> Result<(), PortError> {
        if self.task_version != self.task_state.sequence().get()
            || self.authorized_actors.is_empty()
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
                .map(|assignment| assignment.agent_id.as_str())
                .collect::<BTreeSet<_>>()
                .len()
                != self.run_assignments.len()
            || self.quorum.as_ref().is_some_and(|quorum| {
                quorum.proposals().iter().any(|proposal| {
                    !self
                        .run_assignments
                        .iter()
                        .any(|assignment| assignment.matches_proposal(proposal))
                })
            })
            || self
                .plan_approval_authority
                .as_ref()
                .is_some_and(|authority| authority.validate().is_err())
        {
            Err(conflict())
        } else {
            Ok(())
        }
    }
}

pub trait DeliberationStore: Send + Sync {
    fn load(&self, task_id: &TaskId) -> Result<DeliberationSnapshot, PortError>;
    /// Atomically persists the deliberation record, its exact event append, and every reducer-
    /// derived projection change. Implementations must reject commands whose `validate` method
    /// fails and must never expose a partial record/event/projection write.
    fn persist(&self, command: DeliberationPersistenceCommand) -> Result<(), PortError>;
}

pub struct DeliberationCommands<'a> {
    store: &'a dyn DeliberationStore,
}

impl<'a> DeliberationCommands<'a> {
    pub const fn new(store: &'a dyn DeliberationStore) -> Self {
        Self { store }
    }

    pub fn record_private_proposal(
        &self,
        context: DeliberationCommandContext,
        proposal: IndependentProposal,
    ) -> Result<(), PortError> {
        let snapshot = self.authorize(&context, Phase::ParallelAnalysis)?;
        if !snapshot
            .run_assignments
            .iter()
            .any(|assignment| assignment.matches(&proposal, &context.actor_id))
        {
            return Err(conflict());
        }
        self.persist_authorized(
            context.clone(),
            snapshot,
            DeliberationRecord::PrivateProposal {
                proposal,
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
        let quorum = snapshot.quorum.clone().ok_or_else(conflict)?;
        let proposals = quorum.reveal();
        let proposal_artifacts: BTreeSet<_> = proposals
            .iter()
            .map(IndependentProposal::artifact_id)
            .collect();
        let review_targets: BTreeSet<_> = review_plan
            .edges()
            .iter()
            .map(|edge| edge.target_proposal())
            .collect();
        if proposal_artifacts != review_targets {
            return Err(conflict());
        }
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
        self.persist(
            context.clone(),
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
        self.persist(
            context.clone(),
            DeliberationRecord::ThreadSummary {
                thread_id: thread_id.into(),
                artifact: context.record_artifact.clone(),
            },
        )
    }

    pub fn request_specialist(
        &self,
        context: DeliberationCommandContext,
        request: SpecialistRequest,
    ) -> Result<(), PortError> {
        self.persist(
            context.clone(),
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
        self.persist(
            context.clone(),
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
        if !same_claim_authority(&snapshot.claims, &claims) {
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
    ) -> Result<(), PortError> {
        let snapshot = self.authorize(&context, Phase::Synthesis)?;
        let authoritative_claims: BTreeMap<_, _> = snapshot
            .claims
            .iter()
            .map(|claim| (claim.claim_id(), claim))
            .collect();
        let decision_claims: BTreeMap<_, _> = decision
            .evidence()
            .iter()
            .map(|claim| (claim.claim_id(), claim))
            .collect();
        if snapshot
            .claims
            .iter()
            .any(|claim| claim.verification().is_none())
            || authoritative_claims.len() != snapshot.claims.len()
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
            },
        )
    }

    pub fn record_objection_set(
        &self,
        context: DeliberationCommandContext,
        objections: FinalObjectionSet,
    ) -> Result<(), PortError> {
        self.persist(
            context.clone(),
            DeliberationRecord::ObjectionSet {
                objections,
                artifact: context.record_artifact.clone(),
            },
        )
    }

    pub fn close_objection_round(
        &self,
        context: DeliberationCommandContext,
        approval_input: PreparePlanApprovalRequestInput,
    ) -> Result<(), PortError> {
        let snapshot = self.authorize(&context, Phase::FinalObjection)?;
        if snapshot.accepted_severe_objection {
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
        let approval_authority = snapshot
            .plan_approval_authority
            .as_ref()
            .ok_or_else(conflict)?;
        let approval_state = PlanApprovalCurrentState {
            phase: next_state.phase(),
            task_state: next_state,
            binding: approval_authority.binding().clone(),
        };
        let plan_approval = PreparePlanApprovalRequest::execute(
            approval_input,
            approval_authority,
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
        self.persist(
            context.clone(),
            DeliberationRecord::Supersession {
                superseded,
                replacement: context.record_artifact.clone(),
            },
        )
    }

    fn persist(
        &self,
        context: DeliberationCommandContext,
        record: DeliberationRecord,
    ) -> Result<(), PortError> {
        let snapshot = self.authorize(&context, record.expected_phase())?;
        self.persist_authorized(context, snapshot, record)
    }

    fn persist_authorized(
        &self,
        context: DeliberationCommandContext,
        snapshot: DeliberationSnapshot,
        record: DeliberationRecord,
    ) -> Result<(), PortError> {
        record.validate(&snapshot.task_id)?;
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
        if !snapshot.authorized_actors.contains(&context.actor_id) {
            return Err(permission_denied());
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
            actor_type: "agent".to_owned(),
            actor_id: authority.actor_id.clone(),
            observation_class: "agent_asserted".to_owned(),
            payload: record.event_payload(task_id),
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
        || (require_terminal && claims.iter().any(|claim| claim.verification().is_none()))
    {
        Err(conflict())
    } else {
        Ok(())
    }
}

fn same_claim_authority(expected: &[MaterialClaim], actual: &[MaterialClaim]) -> bool {
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
            actor_id: ActorId::new("actor-1").unwrap(),
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
