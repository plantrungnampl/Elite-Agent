use local_agent_terminal_application::{
    canonical_file_write_recovery_request, AuthorizedFileRead, CapabilityFileWriteSession,
    CapabilityFileWriteSessionFactory, CapabilityFilesystem, CapabilityResolver,
    CaptureFileWritePostEvidence, CaptureFileWritePreEvidence, ExecutorLeaseStore, FileReadRequest,
    FileWriteEvidenceStore, FileWritePolicyBinding, FileWritePostExpectation, FileWritePreImage,
    FileWriteRecoveryCompletion, FileWriteRecoveryIntent, FileWriteRecoverySnapshot,
    FileWriteRecoveryState, FileWriteRecoveryStore, FileWriteRequest, ObservedFileImage,
    OpenFileWriteSession, PortError, ResolvedCapabilityTarget, Retryability,
    SafeErrorClassification, VerifiedBytes, VerifiedFileWriteCompensation, VerifiedWrite,
    WorkspaceWriteCoordinator,
};
use sha2::{Digest, Sha256};

use crate::capability::{conflict, denied, resolve};

const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;

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
    let relative_components = match resolved.target {
        ResolvedCapabilityTarget::Relative(components) => components,
        ResolvedCapabilityTarget::Root => return Err(denied()),
    };
    let result = filesystem
        .read(AuthorizedFileRead {
            task_id: request.task_id,
            root_identity: resolved.root_identity,
            relative_components,
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
    sessions: &dyn CapabilityFileWriteSessionFactory,
    leases: &dyn ExecutorLeaseStore,
    evidence: &dyn FileWriteEvidenceStore,
    recovery: &dyn FileWriteRecoveryStore,
    writes: &WorkspaceWriteCoordinator,
    request: FileWriteRequest,
) -> Result<VerifiedWrite, PortError> {
    let FileWriteRequest {
        execution_id,
        task_id,
        capability,
        expected_digest,
        bytes,
        lease_claim,
        policy,
    } = request;
    let resolved = resolve(resolver, &task_id, &capability, expected_digest.as_ref())?;
    let relative_components = match resolved.target {
        ResolvedCapabilityTarget::Relative(components) => components,
        ResolvedCapabilityTarget::Root => return Err(denied()),
    };
    if lease_claim.task_id() != &task_id {
        return Err(conflict());
    }
    let expected_post = FileWritePostExpectation::new(
        digest(&bytes),
        u64::try_from(bytes.len()).map_err(|_| conflict())?,
    )
    .map_err(|_| conflict())?;
    let _permit = writes.monitor_permit(leases, lease_claim.clone())?;
    let open_request = OpenFileWriteSession::new(
        execution_id.clone(),
        task_id,
        resolved.root_identity,
        relative_components,
        expected_digest,
        lease_claim.clone(),
    )
    .map_err(|_| conflict())?;
    let mut session = sessions.open(open_request.clone())?;
    let pre_image = session.pre_image().clone();
    let capture = CaptureFileWritePreEvidence::new(
        open_request.clone(),
        expected_post.clone(),
        pre_image.clone(),
    )
    .map_err(|_| conflict())?;
    let intent = evidence.capture_pre_write(capture)?;
    validate_intent(&intent, &open_request, &expected_post, &pre_image, &policy)?;

    let prepared = recovery.prepare(intent.clone())?;
    validate_snapshot(&prepared, &intent, FileWriteRecoveryState::Prepared)?;
    let started = recovery.start(&execution_id)?;
    validate_snapshot(&started, &intent, FileWriteRecoveryState::Started)?;
    leases.assert_current(lease_claim)?;

    let effect_result = apply_and_complete(
        session.as_mut(),
        evidence,
        recovery,
        &intent,
        &expected_post,
        &bytes,
    );
    effect_result.map_err(|error| {
        compensate_after_effect(session.as_mut(), recovery, &intent, &pre_image, error)
    })
}

fn digest(bytes: &[u8]) -> local_agent_terminal_domain::Sha256Digest {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    local_agent_terminal_domain::Sha256Digest::new(format!("sha256:{:x}", hasher.finalize()))
        .expect("SHA-256 formatting is valid")
}

fn apply_and_complete(
    session: &mut dyn CapabilityFileWriteSession,
    evidence: &dyn FileWriteEvidenceStore,
    recovery: &dyn FileWriteRecoveryStore,
    intent: &FileWriteRecoveryIntent,
    expected_post: &FileWritePostExpectation,
    bytes: &[u8],
) -> Result<VerifiedWrite, PortError> {
    session.apply(bytes)?;
    let verified = session.verify_post_image(expected_post)?;
    if verified.digest != *expected_post.digest()
        || verified.size_bytes != expected_post.size_bytes()
    {
        return Err(integrity_failure());
    }
    let capture = CaptureFileWritePostEvidence::new(intent.request.clone(), verified.clone())
        .map_err(|_| integrity_failure())?;
    let completion = evidence.capture_post_write(capture)?;
    validate_completion(&completion, intent)?;
    let completed = recovery.complete(completion)?;
    validate_snapshot(&completed, intent, FileWriteRecoveryState::Completed)?;
    Ok(verified)
}

fn validate_intent(
    intent: &FileWriteRecoveryIntent,
    open_request: &OpenFileWriteSession,
    expected_post: &FileWritePostExpectation,
    observed_pre_image: &ObservedFileImage,
    policy: &FileWritePolicyBinding,
) -> Result<(), PortError> {
    let request = &intent.request;
    let exact_request = request.execution_id == *open_request.execution_id()
        && request.task_id == *open_request.task_id()
        && request.root_identity == *open_request.root_identity()
        && request.relative_components == *open_request.relative_components()
        && request.lease_claim == *open_request.lease_claim()
        && request.expected_post_digest == *expected_post.digest()
        && request.expected_post_size == expected_post.size_bytes()
        && request.policy == *policy;
    if !exact_request || !pre_image_matches(request, observed_pre_image) {
        return Err(integrity_failure());
    }

    let canonical =
        canonical_file_write_recovery_request(request).map_err(|_| integrity_failure())?;
    let artifact = &intent.request_artifact;
    let canonical_size =
        u64::try_from(canonical.canonical_bytes.len()).map_err(|_| integrity_failure())?;
    if artifact.content_hash != canonical.operation_digest.as_str()
        || artifact.size_bytes != canonical_size
        || artifact.task_id.as_ref() != Some(open_request.task_id())
        || artifact.project_id != request.pre_evidence.project_id
        || artifact.storage_key.trim().is_empty()
    {
        return Err(integrity_failure());
    }
    Ok(())
}

fn pre_image_matches(
    request: &local_agent_terminal_application::FileWriteRecoveryRequest,
    observed: &ObservedFileImage,
) -> bool {
    match (observed.present_bytes(), &request.pre_image) {
        (None, FileWritePreImage::Absent) => true,
        (Some(observed), FileWritePreImage::Artifact(artifact)) => {
            artifact.content_hash == observed.digest.as_str()
                && u64::try_from(observed.bytes.len()).is_ok_and(|size| artifact.size_bytes == size)
                && artifact.task_id.as_ref() == Some(&request.task_id)
                && artifact.project_id == request.pre_evidence.project_id
        }
        _ => false,
    }
}

fn validate_completion(
    completion: &FileWriteRecoveryCompletion,
    intent: &FileWriteRecoveryIntent,
) -> Result<(), PortError> {
    let request = &intent.request;
    let evidence = &completion.post_evidence;
    let exact_completion = completion.execution_id == request.execution_id
        && completion.observed_post_digest == request.expected_post_digest
        && evidence.task_id.as_ref() == Some(&request.task_id)
        && evidence.project_id == request.pre_evidence.project_id
        && !evidence.storage_key.trim().is_empty()
        && evidence.size_bytes <= MAX_SAFE_INTEGER
        && local_agent_terminal_domain::Sha256Digest::new(evidence.content_hash.clone()).is_ok();
    if !exact_completion {
        return Err(integrity_failure());
    }
    Ok(())
}

fn validate_snapshot(
    snapshot: &FileWriteRecoverySnapshot,
    intent: &FileWriteRecoveryIntent,
    expected_state: FileWriteRecoveryState,
) -> Result<(), PortError> {
    if snapshot.request != intent.request
        || snapshot.request_artifact != intent.request_artifact
        || snapshot.state != expected_state
    {
        return Err(integrity_failure());
    }
    Ok(())
}

fn compensate_after_effect(
    session: &mut dyn CapabilityFileWriteSession,
    recovery: &dyn FileWriteRecoveryStore,
    intent: &FileWriteRecoveryIntent,
    pre_image: &ObservedFileImage,
    original_error: PortError,
) -> PortError {
    let compensation = session.restore_pre_image_and_verify();
    if compensation
        .as_ref()
        .is_ok_and(|result| compensation_matches(pre_image, result))
    {
        return original_error;
    }

    let mark_result = recovery
        .mark_indeterminate(&intent.request.execution_id)
        .and_then(|snapshot| {
            validate_snapshot(&snapshot, intent, FileWriteRecoveryState::Indeterminate)
        });
    // The write must fail closed whether persisting or validating indeterminate state failed.
    drop(mark_result);
    integrity_failure()
}

fn compensation_matches(
    pre_image: &ObservedFileImage,
    compensation: &VerifiedFileWriteCompensation,
) -> bool {
    match (pre_image.present_bytes(), compensation) {
        (None, VerifiedFileWriteCompensation::Absent) => true,
        (Some(observed), VerifiedFileWriteCompensation::Restored(restored)) => {
            restored.digest == observed.digest
                && u64::try_from(observed.bytes.len()).is_ok_and(|size| restored.size_bytes == size)
        }
        _ => false,
    }
}

fn integrity_failure() -> PortError {
    PortError::failure(
        SafeErrorClassification::IntegrityFailure,
        Retryability::NonRetryable,
    )
}
