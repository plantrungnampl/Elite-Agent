use local_agent_terminal_application::{
    prepare_initial_deliberation_phase, AgentRuntime, DeliberationArtifactRef,
    DeliberationBoundaryCheck, DeliberationBoundaryStore, DeliberationCommandContext,
    DeliberationCommands, DeliberationDispatchBinding, DeliberationDispatchStore,
    DeliberationPhaseDispatchSet, DeliberationProposalDispatchPlan,
    DeliberationRepositoryAuthority, DeliberationSynthesisStore, DeliberationToolAccess,
    DeliberationToolCatalog, DeliberationToolSchema, DeliberationWorkflowAuthority,
    InitialDeliberationPhaseRequest, PlanApprovalAuthorityProvider, PortError,
    PreparePlanApprovalRequestInput, Retryability, SafeErrorClassification,
};
use local_agent_terminal_domain::{
    AgentRunReceipt, MaterialClaim, Phase, ReviewPlan, TaskId, WorkflowState,
};

use crate::claims::{persist_synthesis, SynthesisRequest};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NormativeTransition {
    pub from: Phase,
    pub event: &'static str,
    pub guard: Option<&'static str>,
    pub to: Phase,
}

pub const fn normative_preapproval_transitions() -> [NormativeTransition; 7] {
    [
        NormativeTransition {
            from: Phase::Intake,
            event: "task.validated",
            guard: Some("repository_policy_budgets_valid"),
            to: Phase::ContextBuild,
        },
        NormativeTransition {
            from: Phase::ContextBuild,
            event: "context.initial.ready",
            guard: Some("required_context_packages_valid"),
            to: Phase::ParallelAnalysis,
        },
        NormativeTransition {
            from: Phase::ParallelAnalysis,
            event: "analysis.quorum.reached",
            guard: Some("minimum_independent_results"),
            to: Phase::CrossReview,
        },
        NormativeTransition {
            from: Phase::CrossReview,
            event: "review.complete",
            guard: Some("review_outputs_or_bounded_stop"),
            to: Phase::PrePlanVerification,
        },
        NormativeTransition {
            from: Phase::PrePlanVerification,
            event: "claims.checked",
            guard: Some("all_material_claims_classified"),
            to: Phase::Synthesis,
        },
        NormativeTransition {
            from: Phase::Synthesis,
            event: "decision.draft.created",
            guard: Some("decision_schema_and_evidence_valid"),
            to: Phase::FinalObjection,
        },
        NormativeTransition {
            from: Phase::FinalObjection,
            event: "objection.round.closed",
            guard: Some("no_accepted_severe_objection"),
            to: Phase::AwaitingPlanApproval,
        },
    ]
}

pub type PhaseAdvanceRequest = InitialDeliberationPhaseRequest;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreApprovalAdvance {
    pub next_state: WorkflowState,
    pub receipts: Vec<AgentRunReceipt>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PrePlanDispatch {
    Proposal(Box<DeliberationProposalDispatchPlan>),
    Phase(DeliberationPhaseDispatchSet),
}

impl PrePlanDispatch {
    pub fn task_id(&self) -> &TaskId {
        match self {
            Self::Proposal(plan) => plan.task_id(),
            Self::Phase(dispatch_set) => dispatch_set.task_id(),
        }
    }

    pub const fn phase(&self) -> Phase {
        match self {
            Self::Proposal(plan) => plan.phase(),
            Self::Phase(dispatch_set) => dispatch_set.phase(),
        }
    }

    pub fn bindings(&self) -> &[DeliberationDispatchBinding] {
        match self {
            Self::Proposal(plan) => plan.bindings(),
            Self::Phase(dispatch_set) => dispatch_set.bindings(),
        }
    }

    fn validate(&self) -> Result<(), PortError> {
        match self {
            Self::Proposal(plan) => plan.validate(),
            Self::Phase(dispatch_set) => dispatch_set.validate(),
        }
    }

    fn persist(&self, store: &dyn DeliberationDispatchStore) -> Result<(), PortError> {
        match self {
            Self::Proposal(plan) => store.compare_and_persist_proposal_binding_set(plan),
            Self::Phase(dispatch_set) => store.compare_and_persist_phase_binding_set(dispatch_set),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PrePlanOperation {
    AdvanceOnly {
        request: PhaseAdvanceRequest,
        transition: NormativeTransition,
    },
    AdvanceAndDispatch {
        request: PhaseAdvanceRequest,
        transition: NormativeTransition,
        dispatch_plan: Box<DeliberationProposalDispatchPlan>,
    },
    DispatchCurrent {
        task_id: TaskId,
        expected_state: WorkflowState,
        dispatch: PrePlanDispatch,
    },
}

#[derive(Clone, Copy)]
pub struct PrePlanReadView<'a> {
    authority: &'a dyn DeliberationRepositoryAuthority,
    tools: &'a dyn DeliberationToolCatalog,
}

impl<'a> PrePlanReadView<'a> {
    pub const fn new(
        authority: &'a dyn DeliberationRepositoryAuthority,
        tools: &'a dyn DeliberationToolCatalog,
    ) -> Self {
        Self { authority, tools }
    }
}

pub struct PreApprovalCoordinator<'a> {
    authority: &'a dyn DeliberationRepositoryAuthority,
    boundaries: &'a dyn DeliberationBoundaryStore,
    workflow_authority: &'a dyn DeliberationWorkflowAuthority,
    tools: &'a dyn DeliberationToolCatalog,
    dispatches: &'a dyn DeliberationDispatchStore,
    runtime: &'a dyn AgentRuntime,
}

impl<'a> PreApprovalCoordinator<'a> {
    pub const fn new(
        authority: &'a dyn DeliberationRepositoryAuthority,
        boundaries: &'a dyn DeliberationBoundaryStore,
        workflow_authority: &'a dyn DeliberationWorkflowAuthority,
        tools: &'a dyn DeliberationToolCatalog,
        dispatches: &'a dyn DeliberationDispatchStore,
        runtime: &'a dyn AgentRuntime,
    ) -> Self {
        Self::from_read_view(
            PrePlanReadView::new(authority, tools),
            boundaries,
            workflow_authority,
            dispatches,
            runtime,
        )
    }

    pub const fn from_read_view(
        read_view: PrePlanReadView<'a>,
        boundaries: &'a dyn DeliberationBoundaryStore,
        workflow_authority: &'a dyn DeliberationWorkflowAuthority,
        dispatches: &'a dyn DeliberationDispatchStore,
        runtime: &'a dyn AgentRuntime,
    ) -> Self {
        Self {
            authority: read_view.authority,
            boundaries,
            workflow_authority,
            tools: read_view.tools,
            dispatches,
            runtime,
        }
    }

    pub fn coordinate(&self, operation: PrePlanOperation) -> Result<PreApprovalAdvance, PortError> {
        let (task_id, boundary_phase) = match &operation {
            PrePlanOperation::AdvanceOnly {
                request,
                transition,
            }
            | PrePlanOperation::AdvanceAndDispatch {
                request,
                transition,
                ..
            } => {
                if request.expected_state.phase() != transition.from {
                    return Err(invalid_input());
                }
                (&request.task_id, transition.from)
            }
            PrePlanOperation::DispatchCurrent {
                task_id,
                expected_state,
                ..
            } => (task_id, expected_state.phase()),
        };
        if verify_repository_boundary(self.authority, self.boundaries, task_id, boundary_phase)
            .map_err(|error| {
                eprintln!("preapproval boundary failed: {error:?}");
                error
            })?
            == BoundaryOutcome::Blocked
        {
            return Err(integrity_failure());
        }
        PreApprovalSurface::new(self.tools.dispatch_schemas(task_id).map_err(|error| {
            eprintln!("preapproval tool catalog failed: {error:?}");
            error
        })?)?;

        match &operation {
            PrePlanOperation::AdvanceOnly { transition, .. } => {
                if transition.from != Phase::Intake || transition.to != Phase::ContextBuild {
                    return Err(invalid_input());
                }
            }
            PrePlanOperation::AdvanceAndDispatch {
                request,
                transition,
                dispatch_plan,
            } => {
                if transition.from != Phase::ContextBuild
                    || transition.to != Phase::ParallelAnalysis
                    || dispatch_plan.task_id() != &request.task_id
                    || dispatch_plan.phase() != transition.to
                {
                    return Err(invalid_input());
                }
                dispatch_plan.validate()?;
                validate_dispatch_bindings(dispatch_plan.task_id(), dispatch_plan.bindings())?;
            }
            PrePlanOperation::DispatchCurrent {
                task_id: _,
                expected_state,
                dispatch,
            } => {
                if !matches!(
                    expected_state.phase(),
                    Phase::ParallelAnalysis
                        | Phase::CrossReview
                        | Phase::PrePlanVerification
                        | Phase::Synthesis
                        | Phase::FinalObjection
                ) || dispatch.task_id() != task_id
                    || dispatch.phase() != expected_state.phase()
                {
                    return Err(invalid_input());
                }
                validate_dispatch(dispatch)?;
            }
        }

        let (next_state, dispatch_plan) = match operation {
            PrePlanOperation::AdvanceOnly {
                request,
                transition,
            } => (self.advance(request, transition)?, None),
            PrePlanOperation::AdvanceAndDispatch {
                request,
                transition,
                dispatch_plan,
            } => (
                self.advance(request, transition)?,
                Some(PrePlanDispatch::Proposal(dispatch_plan)),
            ),
            PrePlanOperation::DispatchCurrent {
                task_id: _,
                expected_state,
                dispatch,
            } => (expected_state, Some(dispatch)),
        };
        let Some(dispatch) = dispatch_plan else {
            return Ok(PreApprovalAdvance {
                next_state,
                receipts: Vec::new(),
            });
        };
        for binding in dispatch.bindings() {
            self.runtime
                .prepare_run(binding.request())
                .map_err(|error| {
                    eprintln!(
                        "preapproval run preparation failed for {}: {error:?}",
                        binding.request().run_id.as_str()
                    );
                    error
                })?;
        }
        dispatch.persist(self.dispatches).map_err(|error| {
            eprintln!("preapproval dispatch persistence failed: {error:?}");
            error
        })?;
        let mut receipts = Vec::with_capacity(dispatch.bindings().len());
        for binding in dispatch.bindings() {
            receipts.push(self.runtime.start_run(binding.request().clone())?);
        }
        Ok(PreApprovalAdvance {
            next_state,
            receipts,
        })
    }

    fn advance(
        &self,
        request: PhaseAdvanceRequest,
        transition: NormativeTransition,
    ) -> Result<WorkflowState, PortError> {
        let guard = transition.guard.ok_or_else(invalid_input)?;
        let prepared =
            prepare_initial_deliberation_phase(request, transition.event, guard, transition.to)?;
        self.workflow_authority.transition(prepared.transition)?;
        Ok(prepared.next_state)
    }
}

fn validate_dispatch(dispatch: &PrePlanDispatch) -> Result<(), PortError> {
    dispatch.validate()?;
    validate_dispatch_bindings(dispatch.task_id(), dispatch.bindings())
}

fn validate_dispatch_bindings(
    task_id: &TaskId,
    bindings: &[DeliberationDispatchBinding],
) -> Result<(), PortError> {
    if bindings.iter().any(|binding| {
        binding.request().run_config.limits.max_tool_requests != 0
            || binding.request().task_id != *task_id
    }) {
        return Err(invalid_input());
    }
    Ok(())
}

pub struct DeliberationCoordinator<'a> {
    authority: &'a dyn DeliberationRepositoryAuthority,
    boundaries: &'a dyn DeliberationBoundaryStore,
    store: &'a dyn DeliberationSynthesisStore,
    workflow_authority: Option<&'a dyn DeliberationWorkflowAuthority>,
    plan_approval_authority: Option<&'a dyn PlanApprovalAuthorityProvider>,
}

impl<'a> DeliberationCoordinator<'a> {
    pub const fn new(
        authority: &'a dyn DeliberationRepositoryAuthority,
        boundaries: &'a dyn DeliberationBoundaryStore,
        store: &'a dyn DeliberationSynthesisStore,
    ) -> Self {
        Self {
            authority,
            boundaries,
            store,
            workflow_authority: None,
            plan_approval_authority: None,
        }
    }

    pub const fn with_workflow_authority(
        authority: &'a dyn DeliberationRepositoryAuthority,
        boundaries: &'a dyn DeliberationBoundaryStore,
        store: &'a dyn DeliberationSynthesisStore,
        workflow_authority: &'a dyn DeliberationWorkflowAuthority,
    ) -> Self {
        Self {
            authority,
            boundaries,
            store,
            workflow_authority: Some(workflow_authority),
            plan_approval_authority: None,
        }
    }

    pub const fn with_plan_approval_authority(
        authority: &'a dyn DeliberationRepositoryAuthority,
        boundaries: &'a dyn DeliberationBoundaryStore,
        store: &'a dyn DeliberationSynthesisStore,
        plan_approval_authority: &'a dyn PlanApprovalAuthorityProvider,
    ) -> Self {
        Self {
            authority,
            boundaries,
            store,
            workflow_authority: None,
            plan_approval_authority: Some(plan_approval_authority),
        }
    }

    pub const fn with_authorities(
        authority: &'a dyn DeliberationRepositoryAuthority,
        boundaries: &'a dyn DeliberationBoundaryStore,
        store: &'a dyn DeliberationSynthesisStore,
        workflow_authority: &'a dyn DeliberationWorkflowAuthority,
        plan_approval_authority: &'a dyn PlanApprovalAuthorityProvider,
    ) -> Self {
        Self {
            authority,
            boundaries,
            store,
            workflow_authority: Some(workflow_authority),
            plan_approval_authority: Some(plan_approval_authority),
        }
    }

    pub fn publish_proposals(
        &self,
        context: DeliberationCommandContext,
        review_plan: ReviewPlan,
        review_artifact: DeliberationArtifactRef,
    ) -> Result<(), PortError> {
        self.verify_current(&context)?;
        self.commands()
            .publish_proposals(context, review_plan, review_artifact)
    }

    pub fn accept_severe_objection(
        &self,
        context: DeliberationCommandContext,
        review_plan: ReviewPlan,
    ) -> Result<(), PortError> {
        self.verify_current(&context)?;
        self.commands()
            .accept_severe_objection(context, review_plan)
    }

    pub fn record_claim_set(
        &self,
        context: DeliberationCommandContext,
        claims: Vec<MaterialClaim>,
    ) -> Result<(), PortError> {
        self.verify_current(&context)?;
        self.commands().record_claim_set(context, claims)
    }

    pub fn record_verification_set(
        &self,
        context: DeliberationCommandContext,
        claims: Vec<MaterialClaim>,
    ) -> Result<(), PortError> {
        self.verify_current(&context)?;
        self.commands().record_verification_set(context, claims)
    }

    pub fn synthesize(&self, request: SynthesisRequest) -> Result<(), PortError> {
        self.verify_current(&request.context)?;
        persist_synthesis(
            self.store,
            self.workflow_authority.ok_or_else(integrity_failure)?,
            request,
        )
    }

    pub fn close_objection_round(
        &self,
        context: DeliberationCommandContext,
        approval_input: PreparePlanApprovalRequestInput,
    ) -> Result<(), PortError> {
        self.verify_current(&context)?;
        self.commands()
            .close_objection_round(context, approval_input)
    }

    fn commands(&self) -> DeliberationCommands<'_> {
        match (self.workflow_authority, self.plan_approval_authority) {
            (Some(workflow), Some(plan)) => {
                DeliberationCommands::with_authorities(self.store, workflow, plan)
            }
            (Some(workflow), None) => {
                DeliberationCommands::with_workflow_authority(self.store, workflow)
            }
            (None, Some(plan)) => {
                DeliberationCommands::with_plan_approval_authority(self.store, plan)
            }
            (None, None) => DeliberationCommands::new(self.store),
        }
    }

    fn verify_current(&self, context: &DeliberationCommandContext) -> Result<(), PortError> {
        if verify_repository_boundary(
            self.authority,
            self.boundaries,
            context.task_id(),
            context.expected_task_state().phase(),
        )? == BoundaryOutcome::Blocked
        {
            return Err(integrity_failure());
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BoundaryOutcome {
    Current,
    Blocked,
}

/// Compares the current repository fingerprint with the task baseline and durably invalidates
/// context packages before any caller may resume an external effect.
pub fn verify_repository_boundary(
    authority: &dyn DeliberationRepositoryAuthority,
    store: &dyn DeliberationBoundaryStore,
    task_id: &TaskId,
    phase: Phase,
) -> Result<BoundaryOutcome, PortError> {
    let observed = authority.current_fingerprint(task_id)?;
    let record = store.compare_and_persist_boundary(DeliberationBoundaryCheck::new(
        task_id.clone(),
        phase,
        observed,
    ))?;
    record.validate()?;
    let outcome = if record.blocked {
        BoundaryOutcome::Blocked
    } else {
        BoundaryOutcome::Current
    };
    Ok(outcome)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PreApprovalSurface;

impl PreApprovalSurface {
    fn new(schemas: Vec<DeliberationToolSchema>) -> Result<Self, PortError> {
        if schemas
            .iter()
            .any(|tool| tool.access() == DeliberationToolAccess::Write)
            || !schemas.is_empty()
        {
            return Err(invalid_input());
        }
        Ok(Self)
    }
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
