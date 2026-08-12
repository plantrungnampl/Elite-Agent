
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

    pub fn run_id(&self) -> &RunId {
        &self.run_id
    }

    pub fn agent_id(&self) -> &str {
        &self.agent_id
    }

    pub fn family(&self) -> &AgentFamilyKey {
        &self.family
    }

    pub fn actor_id(&self) -> &ActorId {
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
    fn budget_reservation(&self) -> Result<DeliberationBudgetReservation, PortError> {
        let thread_count =
            u32::try_from(self.specialist_requests.len()).map_err(|_| conflict())?;
        self.specialist_requests.iter().try_fold(
            DeliberationBudgetReservation {
                thread_count,
                ..DeliberationBudgetReservation::default()
            },
            |reservation, existing| {
                reservation.checked_add(DeliberationBudgetReservation {
                    thread_count: 0,
                    token_count: existing.request.budget().max_tokens(),
                    cost_microunits: existing.request.budget().max_cost_microunits(),
                })
            },
        )
    }

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
                .is_some_and(|phase| {
                    phase != self.task_state.phase()
                        && !(phase == Phase::AwaitingPlanApproval
                            && matches!(
                                self.task_state.phase(),
                                Phase::Synthesis | Phase::Implementation | Phase::Cancelled
                            ))
                })
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
