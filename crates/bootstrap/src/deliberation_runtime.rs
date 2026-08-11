use std::sync::Arc;

use local_agent_terminal_application::{
    DeliberationBoundaryStore, DeliberationRepositoryAuthority, DeliberationSynthesisStore,
    PlanApprovalAuthorityProvider,
};
use local_agent_terminal_orchestration::DeliberationCoordinator;

/// Owns the outer ports used by the deliberation coordinator.
///
/// Repository-boundary checks and deliberation transition policy remain in
/// `orchestration`; this type only supplies their concrete application ports.
pub struct DeliberationRuntime {
    authority: Arc<dyn DeliberationRepositoryAuthority>,
    boundaries: Arc<dyn DeliberationBoundaryStore>,
    store: Arc<dyn DeliberationSynthesisStore>,
    plan_approval_authority: Option<Arc<dyn PlanApprovalAuthorityProvider>>,
}

impl DeliberationRuntime {
    pub fn new(
        authority: Arc<dyn DeliberationRepositoryAuthority>,
        boundaries: Arc<dyn DeliberationBoundaryStore>,
        store: Arc<dyn DeliberationSynthesisStore>,
    ) -> Self {
        Self {
            authority,
            boundaries,
            store,
            plan_approval_authority: None,
        }
    }

    pub fn with_plan_approval_authority(
        authority: Arc<dyn DeliberationRepositoryAuthority>,
        boundaries: Arc<dyn DeliberationBoundaryStore>,
        store: Arc<dyn DeliberationSynthesisStore>,
        plan_approval_authority: Arc<dyn PlanApprovalAuthorityProvider>,
    ) -> Self {
        Self {
            authority,
            boundaries,
            store,
            plan_approval_authority: Some(plan_approval_authority),
        }
    }

    pub fn coordinator(&self) -> DeliberationCoordinator<'_> {
        match self.plan_approval_authority.as_deref() {
            Some(plan_approval_authority) => DeliberationCoordinator::with_plan_approval_authority(
                self.authority.as_ref(),
                self.boundaries.as_ref(),
                self.store.as_ref(),
                plan_approval_authority,
            ),
            None => DeliberationCoordinator::new(
                self.authority.as_ref(),
                self.boundaries.as_ref(),
                self.store.as_ref(),
            ),
        }
    }
}
