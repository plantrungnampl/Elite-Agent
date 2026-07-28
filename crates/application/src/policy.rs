use local_agent_terminal_domain::{PolicyDecisionDraft, PolicyRequest, Sha256Digest, Timestamp};

use crate::PortError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyDecision {
    pub draft: PolicyDecisionDraft,
    pub operation_digest: Sha256Digest,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordedPolicyDecision {
    pub decision: PolicyDecision,
    pub recorded_at: Timestamp,
}

pub trait PolicyEvaluator: Send + Sync {
    fn evaluate(&self, request: PolicyRequest) -> Result<PolicyDecision, PortError>;
}

pub trait PolicyDecisionStore: Send + Sync {
    fn record(&self, decision: RecordedPolicyDecision) -> Result<(), PortError>;
}
