use local_agent_terminal_domain::{ResourceClass, TrustTier};

use crate::{
    canonical_json::sha256_digest,
    lease::{LeaseSnapshot, LeaseState},
    PortError, Retryability, SafeErrorClassification, ToolRequest,
};

const MAX_AUTHORITY_RESOURCE_BYTES: usize = 8 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolAuthoritySnapshot {
    request: ToolRequest,
}

impl ToolAuthoritySnapshot {
    pub fn new(
        request: ToolRequest,
        resource_bytes: &[u8],
        lease: Option<LeaseSnapshot>,
    ) -> Result<Self, PortError> {
        if resource_bytes.len() > MAX_AUTHORITY_RESOURCE_BYTES
            || sha256_digest(resource_bytes) != request.policy().resource().content_digest.as_str()
            || !lease_matches(&request, lease.as_ref())
        {
            return Err(authority_integrity_failure());
        }
        Ok(Self { request })
    }

    pub const fn request(&self) -> &ToolRequest {
        &self.request
    }

    pub const fn effective_role(&self) -> TrustTier {
        self.request.policy().actor().trust_tier
    }
}

pub trait ToolAuthorityResolver: Send + Sync {
    fn resolve(&self, request: &ToolRequest) -> Result<ToolAuthoritySnapshot, PortError>;
}

pub fn validate_authoritative_tool_request(
    expected: &ToolRequest,
    current: &ToolAuthoritySnapshot,
) -> Result<(), PortError> {
    let current_request = current.request();
    let expected_policy = expected.policy();
    let current_policy = current_request.policy();

    if expected.execution_id() != current_request.execution_id()
        || expected.process() != current_request.process()
        || expected_policy.actor() != current_policy.actor()
        || expected_policy.action() != current_policy.action()
        || expected_policy.resource().capability != current_policy.resource().capability
        || expected_policy.resource().content_digest != current_policy.resource().content_digest
        || expected_policy.task_risk() != current_policy.task_risk()
        || expected_policy.purpose() != current_policy.purpose()
        || expected_policy.policy_snapshot_digest() != current_policy.policy_snapshot_digest()
        || !resource_class_is_at_least(
            current_policy.resource().resource_class,
            expected_policy.resource().resource_class,
        )
    {
        return Err(authority_integrity_failure());
    }
    Ok(())
}

fn lease_matches(request: &ToolRequest, lease: Option<&LeaseSnapshot>) -> bool {
    let process = request.process().process();
    match (process.executor_fencing_token(), lease) {
        (None, None) => true,
        (Some(token), Some(lease)) => {
            let binding = process.binding();
            lease.state == LeaseState::Active
                && lease.released_at.is_none()
                && lease.task_id == *binding.task_id()
                && lease.holder_run_id == *binding.run_id()
                && lease.token == token
        }
        _ => false,
    }
}

pub(crate) const fn resource_class_is_at_least(
    candidate: ResourceClass,
    expected: ResourceClass,
) -> bool {
    resource_class_rank(candidate) >= resource_class_rank(expected)
}

const fn resource_class_rank(resource_class: ResourceClass) -> u8 {
    match resource_class {
        ResourceClass::Public => 0,
        ResourceClass::InternalCode => 1,
        ResourceClass::Restricted => 2,
        ResourceClass::Secret => 3,
    }
}

fn authority_integrity_failure() -> PortError {
    PortError::failure(
        SafeErrorClassification::IntegrityFailure,
        Retryability::NonRetryable,
    )
}
