#![forbid(unsafe_code)]

mod claims;
mod coordinator;
mod recovery;
mod selection;

pub use claims::{
    classify_material_claims, extract_material_claims, normalize_material_claims,
    ClaimOrchestrationError, SynthesisRequest,
};
pub use coordinator::{
    normative_preapproval_transitions, DeliberationCoordinator, NormativeTransition,
    PhaseAdvanceRequest, PreApprovalAdvance, PreApprovalCoordinator, PrePlanDispatch,
    PrePlanOperation, PrePlanReadView,
};
pub use recovery::{
    plan_deliberation_recovery, plan_dispatch_recovery, DeliberationRecoveryAction,
    DeliberationRecoveryCoordinator, DispatchRecovery, PersistedDispatch, RecoveryPlanningError,
};
pub use selection::{
    assign_bounded_reviews, authorize_specialist, select_independent_agents, AgentEligibility,
    SelectionDenial, SpecialistDenial,
};
