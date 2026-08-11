
pub trait DeliberationStore: Send + Sync {
    fn load(&self, task_id: &TaskId) -> Result<DeliberationSnapshot, PortError>;
    /// Atomically persists the deliberation record, its exact event append, and every reducer-
    /// derived projection change. Implementations must reject commands whose `validate` method
    /// fails and must never expose a partial record/event/projection write.
    fn persist(&self, command: DeliberationPersistenceCommand) -> Result<(), PortError>;
}

/// Atomically persists the validated decision record/event/projections and the complete synthesis
/// execution DTO. Implementations must reject a command whose `validate` method fails and must not
/// expose either half independently.
pub trait DeliberationSynthesisStore: DeliberationStore {
    fn persist_synthesis(&self, command: DeliberationSynthesisCommand) -> Result<(), PortError>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InitialDeliberationPhaseRequest {
    pub task_id: TaskId,
    pub expected_state: WorkflowState,
    pub event_id: EventId,
    pub occurred_at: String,
    pub correlation_id: String,
    pub effect_artifacts: Vec<DeliberationArtifactRef>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreparedInitialDeliberationPhase {
    pub append: AppendOperation,
    pub next_state: WorkflowState,
}

pub fn prepare_initial_deliberation_phase(
    request: InitialDeliberationPhaseRequest,
    event_type: &str,
    guard: &str,
    expected_phase: Phase,
) -> Result<PreparedInitialDeliberationPhase, PortError> {
    if !matches!(
        request.expected_state.phase(),
        Phase::Intake | Phase::ContextBuild
    ) || request.effect_artifacts.is_empty()
        || request
            .effect_artifacts
            .iter()
            .any(|artifact| artifact.validate().is_err())
        || request.correlation_id.trim().is_empty()
        || parse_policy_timestamp(&request.occurred_at).is_err()
    {
        return Err(invalid_input());
    }
    let event = WorkflowEvent::new(event_type).map_err(|_| invalid_input())?;
    let mut guards = GuardEvaluations::new();
    guards.insert(GuardName::new(guard).map_err(|_| invalid_input())?, true);
    let next_state = *reduce(&request.expected_state, &event, &guards)
        .map_err(|_| invalid_input())?
        .state();
    if next_state.phase() != expected_phase {
        return Err(conflict());
    }
    let effect_artifacts = request
        .effect_artifacts
        .iter()
        .map(|artifact| {
            serde_json::json!({
                "artifactId": artifact.artifact_id().as_str(),
                "contentDigest": artifact.content_digest().as_str(),
                "sizeBytes": artifact.size_bytes(),
            })
        })
        .collect::<Vec<_>>();
    let append = AppendOperation {
        stream_id: StreamId::new(request.task_id.as_str()).map_err(|_| invalid_input())?,
        expected_version: request.expected_state.sequence(),
        events: vec![NewEvent {
            event_id: request.event_id,
            event_type: event,
            schema_version: 1,
            actor_type: "core".to_owned(),
            actor_id: ActorId::new("core").map_err(|_| conflict())?,
            observation_class: "core_observed".to_owned(),
            payload: serde_json::json!({
                "taskId": request.task_id.as_str(),
                "effectArtifacts": effect_artifacts,
            }),
            metadata: serde_json::json!({}),
            causation_id: None,
            correlation_id: request.correlation_id,
            created_at: request.occurred_at.clone(),
        }],
        projection_changes: vec![ProjectionChange::TaskState {
            task_id: request.task_id,
            state: next_state,
            updated_at: request.occurred_at,
        }],
    };
    Ok(PreparedInitialDeliberationPhase { append, next_state })
}

/// A read-only authority used by pre-approval orchestration to rescan repository identity.
/// Implementations must not create or mutate repository-visible state.
pub trait DeliberationRepositoryAuthority: Send + Sync {
    fn current_fingerprint(&self, task_id: &TaskId) -> Result<WorkspaceFingerprint, PortError>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeliberationBoundaryRecord {
    pub task_id: TaskId,
    pub phase: Phase,
    pub expected_fingerprint: WorkspaceFingerprint,
    pub observed_fingerprint: WorkspaceFingerprint,
    pub blocked: bool,
    pub invalidate_context_packages: bool,
    pub invalidate_plan_approval: bool,
}

impl DeliberationBoundaryRecord {
    pub fn checked(
        task_id: TaskId,
        phase: Phase,
        expected_fingerprint: WorkspaceFingerprint,
        observed_fingerprint: WorkspaceFingerprint,
    ) -> Self {
        let blocked = expected_fingerprint != observed_fingerprint;
        Self {
            task_id,
            phase,
            expected_fingerprint,
            observed_fingerprint,
            blocked,
            invalidate_context_packages: blocked,
            invalidate_plan_approval: blocked,
        }
    }

    pub fn validate(&self) -> Result<(), PortError> {
        let blocked = self.expected_fingerprint != self.observed_fingerprint;
        if self.blocked != blocked
            || self.invalidate_context_packages != blocked
            || self.invalidate_plan_approval != blocked
        {
            Err(conflict())
        } else {
            Ok(())
        }
    }
}

/// Persists a repository boundary observation together with any invalidation decision.
/// A mismatch record is one atomic block-and-invalidate command, not independent best-effort
/// writes.
pub trait DeliberationBoundaryStore: Send + Sync {
    /// Atomically loads or captures the task baseline, compares the supplied authoritative
    /// observation, and persists the resulting block/invalidation record. Implementations must
    /// not expose a baseline read and later compare as separate transactions.
    fn compare_and_persist_boundary(
        &self,
        check: DeliberationBoundaryCheck,
    ) -> Result<DeliberationBoundaryRecord, PortError>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeliberationBoundaryCheck {
    task_id: TaskId,
    phase: Phase,
    observed_fingerprint: WorkspaceFingerprint,
}

impl DeliberationBoundaryCheck {
    pub fn new(task_id: TaskId, phase: Phase, observed_fingerprint: WorkspaceFingerprint) -> Self {
        Self {
            task_id,
            phase,
            observed_fingerprint,
        }
    }

    pub fn task_id(&self) -> &TaskId {
        &self.task_id
    }

    pub const fn phase(&self) -> Phase {
        self.phase
    }

    pub fn observed_fingerprint(&self) -> &WorkspaceFingerprint {
        &self.observed_fingerprint
    }

    pub fn compare_with(
        &self,
        expected_fingerprint: WorkspaceFingerprint,
    ) -> Result<DeliberationBoundaryRecord, PortError> {
        let record = DeliberationBoundaryRecord::checked(
            self.task_id.clone(),
            self.phase,
            expected_fingerprint,
            self.observed_fingerprint.clone(),
        );
        record.validate()?;
        Ok(record)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeliberationDispatchBinding {
    request: BoundAgentRunRequest,
    assignment: DeliberationRunAssignment,
    estimated_cost_microunits: u64,
}

impl DeliberationDispatchBinding {
    pub fn new(
        request: BoundAgentRunRequest,
        assignment: DeliberationRunAssignment,
        estimated_cost_microunits: u64,
    ) -> Result<Self, PortError> {
        let binding = Self {
            request,
            assignment,
            estimated_cost_microunits,
        };
        binding.validate()?;
        Ok(binding)
    }

    pub fn request(&self) -> &BoundAgentRunRequest {
        &self.request
    }

    pub fn assignment(&self) -> &DeliberationRunAssignment {
        &self.assignment
    }

    pub fn family(&self) -> &AgentFamilyKey {
        self.assignment.family()
    }

    pub const fn estimated_cost_microunits(&self) -> u64 {
        self.estimated_cost_microunits
    }

    fn budget_reservation(&self) -> DeliberationBudgetReservation {
        DeliberationBudgetReservation {
            thread_count: 0,
            token_count: self.request.run_config.limits.max_output_tokens,
            cost_microunits: self.estimated_cost_microunits,
        }
    }

    pub fn validate(&self) -> Result<(), PortError> {
        self.request.validate().map_err(|_| invalid_input())?;
        if self.estimated_cost_microunits == 0
            || self.request.run_id != *self.assignment.run_id()
            || self.request.agent_id != self.assignment.agent_id()
        {
            return Err(invalid_input());
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeliberationProposalDispatchPlan {
    task_id: TaskId,
    bindings: [DeliberationDispatchBinding; 2],
    task_budget: DeliberationTaskBudget,
}

impl DeliberationProposalDispatchPlan {
    pub fn new(
        first: DeliberationDispatchBinding,
        second: DeliberationDispatchBinding,
        task_budget: DeliberationTaskBudget,
    ) -> Result<Self, PortError> {
        let plan = Self {
            task_id: first.request.task_id.clone(),
            bindings: [first, second],
            task_budget,
        };
        plan.validate()?;
        Ok(plan)
    }

    pub fn task_id(&self) -> &TaskId {
        &self.task_id
    }

    pub const fn phase(&self) -> Phase {
        Phase::ParallelAnalysis
    }

    pub fn bindings(&self) -> &[DeliberationDispatchBinding; 2] {
        &self.bindings
    }

    pub const fn task_budget(&self) -> DeliberationTaskBudget {
        self.task_budget
    }

    pub fn budget_reservation(&self) -> Result<DeliberationBudgetReservation, PortError> {
        dispatch_budget_reservation(&self.bindings)
    }

    pub fn validate(&self) -> Result<(), PortError> {
        let [first, second] = &self.bindings;
        first.validate()?;
        second.validate()?;
        self.budget_reservation()?.validate_within(self.task_budget)?;
        if first.request.task_id != self.task_id
            || second.request.task_id != self.task_id
            || first.request.run_id == second.request.run_id
            || first.request.agent_id == second.request.agent_id
            || first.assignment.family() == second.assignment.family()
            || first.request.run_config.limits.deadline > self.task_budget.deadline()
            || second.request.run_config.limits.deadline > self.task_budget.deadline()
        {
            return Err(invalid_input());
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeliberationPhaseDispatchAuthority {
    task_id: TaskId,
    phase: Phase,
    round: u32,
    assignments: Vec<DeliberationRunAssignment>,
    limits: DeliberationLimits,
    task_budget: DeliberationTaskBudget,
}

impl DeliberationPhaseDispatchAuthority {
    pub fn new(
        task_id: TaskId,
        phase: Phase,
        assignments: Vec<DeliberationRunAssignment>,
        limits: DeliberationLimits,
        task_budget: DeliberationTaskBudget,
    ) -> Result<Self, PortError> {
        let authority = Self {
            task_id,
            phase,
            round: 0,
            assignments,
            limits,
            task_budget,
        };
        authority.validate()?;
        Ok(authority)
    }

    pub fn for_round(
        task_id: TaskId,
        phase: Phase,
        round: u32,
        assignments: Vec<DeliberationRunAssignment>,
        limits: DeliberationLimits,
        task_budget: DeliberationTaskBudget,
    ) -> Result<Self, PortError> {
        let authority = Self {
            task_id,
            phase,
            round,
            assignments,
            limits,
            task_budget,
        };
        authority.validate()?;
        Ok(authority)
    }

    pub fn task_id(&self) -> &TaskId {
        &self.task_id
    }

    pub const fn phase(&self) -> Phase {
        self.phase
    }

    pub const fn round(&self) -> u32 {
        self.round
    }

    pub fn assignments(&self) -> &[DeliberationRunAssignment] {
        &self.assignments
    }

    pub const fn limits(&self) -> DeliberationLimits {
        self.limits
    }

    pub const fn task_budget(&self) -> DeliberationTaskBudget {
        self.task_budget
    }

    pub fn validate(&self) -> Result<(), PortError> {
        let maximum_assignments =
            self.limits
                .max_agents()
                .saturating_mul(self.limits.max_rounds().saturating_add(1)) as usize;
        if !matches!(
            self.phase,
            Phase::CrossReview
                | Phase::PrePlanVerification
                | Phase::Synthesis
                | Phase::FinalObjection
        ) || self.round > self.limits.max_rounds()
            || self.assignments.is_empty()
            || self.assignments.len() > maximum_assignments
        {
            return Err(invalid_input());
        }
        let mut run_ids = BTreeSet::new();
        for assignment in &self.assignments {
            if !run_ids.insert(assignment.run_id().clone()) {
                return Err(invalid_input());
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeliberationPhaseDispatchSet {
    bindings: Vec<DeliberationDispatchBinding>,
    authority: DeliberationPhaseDispatchAuthority,
}

impl DeliberationPhaseDispatchSet {
    pub fn new(
        bindings: Vec<DeliberationDispatchBinding>,
        authority: DeliberationPhaseDispatchAuthority,
    ) -> Result<Self, PortError> {
        let dispatch_set = Self {
            bindings,
            authority,
        };
        dispatch_set.validate()?;
        Ok(dispatch_set)
    }

    pub fn task_id(&self) -> &TaskId {
        self.authority.task_id()
    }

    pub const fn phase(&self) -> Phase {
        self.authority.phase()
    }

    pub fn bindings(&self) -> &[DeliberationDispatchBinding] {
        &self.bindings
    }

    pub fn authority(&self) -> &DeliberationPhaseDispatchAuthority {
        &self.authority
    }

    pub const fn task_budget(&self) -> DeliberationTaskBudget {
        self.authority.task_budget()
    }

    pub fn budget_reservation(&self) -> Result<DeliberationBudgetReservation, PortError> {
        dispatch_budget_reservation(&self.bindings)
    }

    pub fn validate(&self) -> Result<(), PortError> {
        self.authority.validate()?;
        self.budget_reservation()?
            .validate_within(self.authority.task_budget())?;
        if self.bindings.is_empty()
            || self.bindings.len() > self.authority.limits().max_agents() as usize
        {
            return Err(invalid_input());
        }
        let mut run_ids = BTreeSet::new();
        let mut agent_ids = BTreeSet::new();
        for binding in &self.bindings {
            binding.validate()?;
            if binding.request.task_id != *self.authority.task_id()
                || binding.request.run_config.limits.deadline
                    > self.authority.task_budget().deadline()
                || !self
                    .authority
                    .assignments()
                    .iter()
                    .any(|assignment| assignment == binding.assignment())
                || !run_ids.insert(binding.request.run_id.clone())
                || !agent_ids.insert(binding.request.agent_id.clone())
            {
                return Err(invalid_input());
            }
        }
        Ok(())
    }
}

fn dispatch_budget_reservation(
    bindings: &[DeliberationDispatchBinding],
) -> Result<DeliberationBudgetReservation, PortError> {
    bindings.iter().try_fold(
        DeliberationBudgetReservation::default(),
        |reservation, binding| reservation.checked_add(binding.budget_reservation()),
    )
}

/// Atomically compares complete dispatch-binding sets with durable assignment and budget authority
/// and persists them before effects. These methods record selection authority only and must not
/// insert an AgentRun;
/// `AgentRuntime::start_run` remains the sole normal owner of the bound-run durable insert before
/// the provider effect.
pub trait DeliberationDispatchStore: Send + Sync {
    fn compare_and_persist_proposal_binding_set(
        &self,
        plan: &DeliberationProposalDispatchPlan,
    ) -> Result<(), PortError>;
    fn compare_and_persist_phase_binding_set(
        &self,
        dispatch_set: &DeliberationPhaseDispatchSet,
    ) -> Result<(), PortError>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeliberationToolAccess {
    ReadOnly,
    Write,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeliberationToolSchema {
    schema_id: String,
    access: DeliberationToolAccess,
}

impl DeliberationToolSchema {
    pub fn new(
        schema_id: impl Into<String>,
        access: DeliberationToolAccess,
    ) -> Result<Self, PortError> {
        let schema = Self {
            schema_id: schema_id.into(),
            access,
        };
        validate_label(&schema.schema_id)?;
        Ok(schema)
    }

    pub fn schema_id(&self) -> &str {
        &self.schema_id
    }

    pub const fn access(&self) -> DeliberationToolAccess {
        self.access
    }
}

/// Read-side catalog used to construct the exact tool surface for pre-approval agent runs.
pub trait DeliberationToolCatalog: Send + Sync {
    fn dispatch_schemas(&self, task_id: &TaskId) -> Result<Vec<DeliberationToolSchema>, PortError>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeliberationClaimCandidate {
    claim_id: String,
    claimant: String,
    citations: Vec<local_agent_terminal_domain::EvidenceCitation>,
    method: local_agent_terminal_domain::VerificationMethod,
}

impl DeliberationClaimCandidate {
    pub fn new(
        claim_id: impl Into<String>,
        claimant: impl Into<String>,
        citations: Vec<local_agent_terminal_domain::EvidenceCitation>,
        method: local_agent_terminal_domain::VerificationMethod,
    ) -> Result<Self, PortError> {
        let candidate = Self {
            claim_id: claim_id.into(),
            claimant: claimant.into(),
            citations,
            method,
        };
        candidate
            .to_material_claim(ArtifactId::new("claim-candidate").map_err(|_| invalid_input())?)?;
        Ok(candidate)
    }

    pub fn to_material_claim(&self, artifact_id: ArtifactId) -> Result<MaterialClaim, PortError> {
        MaterialClaim::new(
            &self.claim_id,
            &self.claimant,
            artifact_id,
            self.citations.clone(),
            self.method,
        )
        .map_err(|_| invalid_input())
    }
}

/// Loads claim candidates only for an exact artifact already authorized by a durable
/// `DeliberationSnapshot`. Implementations must reject artifact substitution and return the
/// canonical stored candidate order for that artifact.
pub trait DeliberationClaimSource: Send + Sync {
    fn claims_for_artifact(
        &self,
        task_id: &TaskId,
        artifact: &DeliberationArtifactRef,
    ) -> Result<Vec<DeliberationClaimCandidate>, PortError>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeliberationAgentRunReconciliation {
    task_id: TaskId,
    runs: Vec<AgentRunSnapshot>,
}

impl DeliberationAgentRunReconciliation {
    pub fn new(task_id: TaskId, runs: Vec<AgentRunSnapshot>) -> Result<Self, PortError> {
        let reconciliation = Self { task_id, runs };
        reconciliation.validate()?;
        Ok(reconciliation)
    }

    pub fn task_id(&self) -> &TaskId {
        &self.task_id
    }

    pub fn runs(&self) -> &[AgentRunSnapshot] {
        &self.runs
    }

    pub fn validate(&self) -> Result<(), PortError> {
        if self.runs.is_empty() {
            return Err(invalid_input());
        }
        let mut run_ids = BTreeSet::new();
        for run in &self.runs {
            run.request.validate().map_err(|_| invalid_input())?;
            if run.request.task_id != self.task_id || !run_ids.insert(run.request.run_id.clone()) {
                return Err(invalid_input());
            }
        }
        Ok(())
    }
}

/// Recovery-only AgentRun authority. Implementations observe runtime-owned AgentRuns, reconcile
/// durable status, and request only authorized idempotent resume or distinct retry through the
/// runtime recovery path. This port must not directly perform the normal
/// `AgentRunStore::create_bound_run` insertion.
pub trait DeliberationAgentRunRecovery: Send + Sync {
    fn reconcile_or_retry(
        &self,
        task_id: &TaskId,
    ) -> Result<DeliberationAgentRunReconciliation, PortError>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeliberationDurableBoundary {
    Event,
    Artifact,
    DispatchBindings,
    AgentRunsReconciled,
    ProposalVisibility,
    ClaimSet,
    DecisionDraft,
    PlanApproval,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeliberationRecoveryCheckpoint {
    pub task_id: TaskId,
    pub event_persisted: bool,
    pub artifact_persisted: bool,
    pub dispatch_bindings_persisted: bool,
    pub agent_runs_reconciled: bool,
    pub proposal_visibility_persisted: bool,
    pub claim_set_persisted: bool,
    pub decision_draft_persisted: bool,
    pub plan_approval_persisted: bool,
}

impl DeliberationRecoveryCheckpoint {
    pub fn validate(&self, task_id: &TaskId) -> Result<(), PortError> {
        if &self.task_id != task_id {
            return Err(conflict());
        }
        let ordered = [
            self.event_persisted,
            self.artifact_persisted,
            self.dispatch_bindings_persisted,
            self.agent_runs_reconciled,
            self.proposal_visibility_persisted,
            self.claim_set_persisted,
            self.decision_draft_persisted,
            self.plan_approval_persisted,
        ];
        if ordered.windows(2).any(|pair| !pair[0] && pair[1]) {
            return Err(conflict());
        }
        Ok(())
    }
}

/// Recovery port for the real deliberation persistence boundaries. Each recovery method must
/// idempotently persist its underlying workflow record and the corresponding checkpoint as one
/// durable unit. `load_checkpoint` must observe that unit after a process reopens, including when
/// the previous caller failed immediately after the durable commit.
pub trait DeliberationRecoveryStore: Send + Sync {
    fn load_checkpoint(
        &self,
        task_id: &TaskId,
    ) -> Result<DeliberationRecoveryCheckpoint, PortError>;
    fn persist_recovered_event(&self, task_id: &TaskId) -> Result<(), PortError>;
    fn persist_recovered_artifact(&self, task_id: &TaskId) -> Result<(), PortError>;
    fn persist_recovered_dispatch_bindings(&self, task_id: &TaskId) -> Result<(), PortError>;
    /// Persists the validated runtime-owned reconciliation and this checkpoint as one durable
    /// unit. This method records recovery evidence only and must not insert an AgentRun.
    fn persist_recovered_agent_run_reconciliation(
        &self,
        reconciliation: &DeliberationAgentRunReconciliation,
    ) -> Result<(), PortError>;
    fn persist_recovered_proposal_visibility(&self, task_id: &TaskId) -> Result<(), PortError>;
    fn persist_recovered_claim_set(&self, task_id: &TaskId) -> Result<(), PortError>;
    fn persist_recovered_decision_draft(&self, task_id: &TaskId) -> Result<(), PortError>;
    fn persist_recovered_plan_approval(&self, task_id: &TaskId) -> Result<(), PortError>;
}

pub trait PlanApprovalAuthorityProvider: Send + Sync {
    fn current(&self, task_id: &TaskId) -> Result<PlanApprovalAuthorityBinding, PortError>;
}
