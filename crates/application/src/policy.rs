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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DisclosureChannel {
    FileRead,
    GitStatus,
    GitDiff,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DisclosureRequest {
    pub policy_request: PolicyRequest,
    pub channel: DisclosureChannel,
    pub bytes: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyApprovedDisclosure {
    pub decision: PolicyDecision,
    pub original_digest: Sha256Digest,
    pub effective_bytes: Option<Vec<u8>>,
    pub effective_digest: Option<Sha256Digest>,
}

pub trait DisclosurePolicyEvaluator: Send + Sync {
    fn disclose(&self, request: DisclosureRequest) -> Result<PolicyApprovedDisclosure, PortError>;
}

pub trait PolicyDecisionStore: Send + Sync {
    fn record(&self, decision: RecordedPolicyDecision) -> Result<(), PortError>;
}
