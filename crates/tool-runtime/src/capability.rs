use local_agent_terminal_application::{
    CapabilityRequest, CapabilityResolver, PortError, ResolvedCapability, Retryability,
    SafeErrorClassification,
};
use local_agent_terminal_domain::{CapabilityRef, Sha256Digest, TaskId};

pub(crate) fn resolve(
    resolver: &dyn CapabilityResolver,
    task_id: &TaskId,
    capability: &CapabilityRef,
    expected_digest: Option<&Sha256Digest>,
) -> Result<ResolvedCapability, PortError> {
    let resolved = resolver
        .resolve(CapabilityRequest {
            task_id: task_id.clone(),
            capability: capability.clone(),
        })
        .map_err(|_| denied())?;
    if &resolved.capability != capability
        || expected_digest
            .is_some_and(|expected| resolved.content_digest.as_ref() != Some(expected))
    {
        return Err(denied());
    }
    Ok(resolved)
}

pub(crate) fn denied() -> PortError {
    PortError::failure(
        SafeErrorClassification::PermissionDenied,
        Retryability::NonRetryable,
    )
}

pub(crate) fn conflict() -> PortError {
    PortError::failure(
        SafeErrorClassification::Conflict,
        Retryability::NonRetryable,
    )
}
