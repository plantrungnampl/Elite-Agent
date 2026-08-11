use std::sync::Arc;

use local_agent_terminal_application::{DisclosurePolicyEvaluator, PolicyDecisionStore, PortError};
use local_agent_terminal_context_engine::{
    BuiltContextPackage, ContextPackageBuildRequest, ContextPackageBuilder,
};

/// Owns the outer ports needed to construct policy-bound context packages.
///
/// Context selection, budgeting, disclosure, and redaction policy remain in
/// `context-engine`; this type only supplies the concrete application ports.
pub struct ContextRuntime {
    disclosures: Arc<dyn DisclosurePolicyEvaluator>,
    policy_decisions: Arc<dyn PolicyDecisionStore>,
}

impl ContextRuntime {
    pub fn new(
        disclosures: Arc<dyn DisclosurePolicyEvaluator>,
        policy_decisions: Arc<dyn PolicyDecisionStore>,
    ) -> Self {
        Self {
            disclosures,
            policy_decisions,
        }
    }

    pub fn build(
        &self,
        request: ContextPackageBuildRequest,
    ) -> Result<BuiltContextPackage, PortError> {
        ContextPackageBuilder::new(self.disclosures.as_ref(), self.policy_decisions.as_ref())
            .build(request)
    }
}
