use local_agent_terminal_application::{
    AuthorizedFileRead, AuthorizedFileWrite, CapabilityFilesystem, CapabilityResolver,
    ExecutorLeaseStore, FileReadRequest, FileWriteRequest, PortError, VerifiedBytes, VerifiedWrite,
    WorkspaceMutationStore,
};
use sha2::{Digest, Sha256};

use crate::capability::{conflict, denied, resolve};

pub(crate) fn read(
    resolver: &dyn CapabilityResolver,
    filesystem: &dyn CapabilityFilesystem,
    request: FileReadRequest,
) -> Result<VerifiedBytes, PortError> {
    let resolved = resolve(
        resolver,
        &request.task_id,
        &request.capability,
        request.expected_digest.as_ref(),
    )?;
    let result = filesystem
        .read(AuthorizedFileRead {
            task_id: request.task_id,
            root_identity: resolved.root_identity,
            relative_components: resolved.relative_components,
            expected_digest: request.expected_digest,
        })
        .map_err(|_| denied())?;
    if digest(&result.bytes) != result.digest {
        return Err(denied());
    }
    Ok(result)
}

pub(crate) fn write(
    resolver: &dyn CapabilityResolver,
    filesystem: &dyn CapabilityFilesystem,
    leases: &dyn ExecutorLeaseStore,
    mutations: &dyn WorkspaceMutationStore,
    request: FileWriteRequest,
) -> Result<VerifiedWrite, PortError> {
    let resolved = resolve(
        resolver,
        &request.task_id,
        &request.capability,
        request.expected_digest.as_ref(),
    )?;
    if request.lease_claim.task_id() != &request.task_id
        || request.lease_claim.token() != request.fencing_token
        || request.workspace_mutation.task_id != request.task_id
        || request.workspace_mutation.claim != request.lease_claim
        || request.workspace_mutation.pre_evidence.task_id.as_ref() != Some(&request.task_id)
        || request.workspace_mutation.post_evidence.task_id.as_ref() != Some(&request.task_id)
    {
        return Err(conflict());
    }
    leases.assert_current(request.lease_claim.clone())?;
    let expected_digest = digest(&request.bytes);
    let result = filesystem
        .write(AuthorizedFileWrite {
            task_id: request.task_id,
            root_identity: resolved.root_identity,
            relative_components: resolved.relative_components,
            expected_digest: request.expected_digest,
            bytes: request.bytes,
            fencing_token: request.fencing_token,
            lease_claim: request.lease_claim,
        })
        .map_err(|_| conflict())?;
    if result.digest != expected_digest {
        return Err(conflict());
    }
    mutations.record_workspace_mutation(request.workspace_mutation)?;
    Ok(result)
}

fn digest(bytes: &[u8]) -> local_agent_terminal_domain::Sha256Digest {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    local_agent_terminal_domain::Sha256Digest::new(format!("sha256:{:x}", hasher.finalize()))
        .expect("SHA-256 formatting is valid")
}
