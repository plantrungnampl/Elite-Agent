
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanonicalFileWriteRecoveryRequest {
    pub canonical_bytes: Vec<u8>,
    pub operation_digest: Sha256Digest,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FileWritePreImage {
    /// Recovery may remove the new file only after the platform adapter
    /// authoritatively re-observes absence under the retained target handle.
    Absent,
    Artifact(crate::CanonicalEvidenceRef),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileWritePolicyBinding {
    pub decision_id: String,
    pub operation_digest: Sha256Digest,
    pub policy_snapshot_digest: Sha256Digest,
    pub effect: PolicyEffect,
    pub approval_id: Option<ApprovalId>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileWriteRecoveryRequest {
    pub execution_id: ToolExecutionId,
    pub task_id: TaskId,
    pub root_identity: CapabilityRootIdentity,
    pub relative_components: RelativePathComponents,
    pub lease_claim: LeaseClaim,
    pub expected_sequence: Sequence,
    pub pre_image: FileWritePreImage,
    pub expected_post_digest: Sha256Digest,
    pub expected_post_size: u64,
    pub pre_fingerprint: WorkspaceFingerprint,
    pub pre_evidence: crate::CanonicalEvidenceRef,
    pub actor_id: ActorId,
    pub correlation_id: String,
    pub policy: FileWritePolicyBinding,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileWriteRecoveryIntent {
    pub request: FileWriteRecoveryRequest,
    pub request_artifact: crate::CanonicalEvidenceRef,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileWriteRecoveryCompletion {
    pub execution_id: ToolExecutionId,
    pub observed_post_digest: Sha256Digest,
    pub post_fingerprint: WorkspaceFingerprint,
    pub post_evidence: crate::CanonicalEvidenceRef,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileWriteRecoveryState {
    Prepared,
    Started,
    Failed,
    RecoveredNoNetEffect,
    Compensated,
    Completed,
    Indeterminate,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FileWriteRecoveryFailure {
    NotStarted,
    RecoveredNoNetEffect(VerifiedFileWriteCompensation),
    Compensated(VerifiedFileWriteCompensation),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileWriteRecoverySnapshot {
    pub request: FileWriteRecoveryRequest,
    pub request_artifact: crate::CanonicalEvidenceRef,
    pub state: FileWriteRecoveryState,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaptureFileWritePostEvidence {
    recovery_request: FileWriteRecoveryRequest,
    observed_post: VerifiedWrite,
}

impl CaptureFileWritePostEvidence {
    pub fn new(
        recovery_request: FileWriteRecoveryRequest,
        observed_post: VerifiedWrite,
    ) -> Result<Self, PortError> {
        if observed_post.digest != recovery_request.expected_post_digest
            || observed_post.size_bytes != recovery_request.expected_post_size
        {
            return Err(invalid_input());
        }
        Ok(Self {
            recovery_request,
            observed_post,
        })
    }

    pub const fn recovery_request(&self) -> &FileWriteRecoveryRequest {
        &self.recovery_request
    }

    pub const fn observed_post(&self) -> &VerifiedWrite {
        &self.observed_post
    }
}

pub trait FileWriteEvidenceStore: Send + Sync {
    fn capture_pre_write(
        &self,
        request: CaptureFileWritePreEvidence,
    ) -> Result<FileWriteRecoveryIntent, PortError>;
    fn capture_post_write(
        &self,
        request: CaptureFileWritePostEvidence,
    ) -> Result<FileWriteRecoveryCompletion, PortError>;
}

pub trait FileWriteRecoveryStore: Send + Sync {
    fn prepare(
        &self,
        intent: FileWriteRecoveryIntent,
    ) -> Result<FileWriteRecoverySnapshot, PortError>;
    fn start(&self, execution_id: &ToolExecutionId)
        -> Result<FileWriteRecoverySnapshot, PortError>;
    fn complete(
        &self,
        completion: FileWriteRecoveryCompletion,
    ) -> Result<FileWriteRecoverySnapshot, PortError>;
    fn complete_recovery(
        &self,
        completion: FileWriteRecoveryCompletion,
    ) -> Result<FileWriteRecoverySnapshot, PortError> {
        self.complete(completion)
    }
    fn fail(
        &self,
        execution_id: &ToolExecutionId,
        failure: FileWriteRecoveryFailure,
    ) -> Result<FileWriteRecoverySnapshot, PortError>;
    fn mark_indeterminate(
        &self,
        execution_id: &ToolExecutionId,
    ) -> Result<FileWriteRecoverySnapshot, PortError>;
    fn recover(&self) -> Result<Vec<FileWriteRecoverySnapshot>, PortError>;
}

pub fn canonical_file_write_recovery_request(
    request: &FileWriteRecoveryRequest,
) -> Result<CanonicalFileWriteRecoveryRequest, PortError> {
    validate_file_write_recovery_request(request)?;
    let pre_image = match &request.pre_image {
        FileWritePreImage::Absent => json!({"state": "absent"}),
        FileWritePreImage::Artifact(artifact) => {
            json!({"state": "artifact", "artifact": evidence_value(artifact)})
        }
    };
    let value = json!({
        "schema": "file-write-recovery.v1",
        "executionId": request.execution_id.as_str(),
        "taskId": request.task_id.as_str(),
        "target": {
            "rootIdentity": request.root_identity.as_str(),
            "relativeComponents": request.relative_components.as_slice(),
        },
        "lease": {
            "taskId": request.lease_claim.task_id().as_str(),
            "holderRunId": request.lease_claim.holder_run_id().as_str(),
            "fencingToken": request.lease_claim.token().get(),
        },
        "expectedSequence": request.expected_sequence.get(),
        "preImage": pre_image,
        "expectedPostImage": {
            "digest": request.expected_post_digest.as_str(),
            "sizeBytes": request.expected_post_size,
        },
        "workspaceMutation": {
            "preFingerprint": fingerprint_value(&request.pre_fingerprint),
            "preEvidence": evidence_value(&request.pre_evidence),
            "actorId": request.actor_id.as_str(),
            "correlationId": request.correlation_id,
        },
        "policy": {
            "decisionId": request.policy.decision_id,
            "operationDigest": request.policy.operation_digest.as_str(),
            "policySnapshotDigest": request.policy.policy_snapshot_digest.as_str(),
            "effect": policy_effect_name(request.policy.effect),
            "approvalId": request.policy.approval_id.as_ref().map(ApprovalId::as_str),
        },
    });
    let canonical_bytes = serde_json_canonicalizer::to_vec(&value).map_err(|_| invalid_input())?;
    let operation_digest =
        Sha256Digest::new(sha256_digest(&canonical_bytes)).map_err(|_| invalid_input())?;
    Ok(CanonicalFileWriteRecoveryRequest {
        canonical_bytes,
        operation_digest,
    })
}

pub fn parse_file_write_recovery_request(
    bytes: &[u8],
) -> Result<FileWriteRecoveryRequest, PortError> {
    let value: Value = serde_json::from_slice(bytes).map_err(|_| invalid_input())?;
    let canonical = serde_json_canonicalizer::to_vec(&value).map_err(|_| invalid_input())?;
    if canonical != bytes {
        return Err(invalid_input());
    }
    let raw: RawFileWriteRecoveryRequest =
        serde_json::from_value(value).map_err(|_| invalid_input())?;
    if raw.schema != "file-write-recovery.v1" {
        return Err(invalid_input());
    }
    let task_id = TaskId::new(raw.task_id).map_err(|_| invalid_input())?;
    let request = FileWriteRecoveryRequest {
        execution_id: ToolExecutionId::new(raw.execution_id)?,
        task_id: task_id.clone(),
        root_identity: CapabilityRootIdentity::new(raw.target.root_identity)?,
        relative_components: RelativePathComponents::new(raw.target.relative_components)?,
        lease_claim: LeaseClaim::new(
            TaskId::new(raw.lease.task_id).map_err(|_| invalid_input())?,
            RunId::new(raw.lease.holder_run_id).map_err(|_| invalid_input())?,
            FencingToken::new(raw.lease.fencing_token).map_err(|_| invalid_input())?,
        ),
        expected_sequence: Sequence::new(raw.expected_sequence),
        pre_image: match raw.pre_image {
            RawPreImage::Absent => FileWritePreImage::Absent,
            RawPreImage::Artifact { artifact } => {
                FileWritePreImage::Artifact(parse_evidence(artifact)?)
            }
        },
        expected_post_digest: Sha256Digest::new(raw.expected_post_image.digest)
            .map_err(|_| invalid_input())?,
        expected_post_size: raw.expected_post_image.size_bytes,
        pre_fingerprint: parse_fingerprint(raw.workspace_mutation.pre_fingerprint)?,
        pre_evidence: parse_evidence(raw.workspace_mutation.pre_evidence)?,
        actor_id: ActorId::new(raw.workspace_mutation.actor_id).map_err(|_| invalid_input())?,
        correlation_id: raw.workspace_mutation.correlation_id,
        policy: FileWritePolicyBinding {
            decision_id: raw.policy.decision_id,
            operation_digest: Sha256Digest::new(raw.policy.operation_digest)
                .map_err(|_| invalid_input())?,
            policy_snapshot_digest: Sha256Digest::new(raw.policy.policy_snapshot_digest)
                .map_err(|_| invalid_input())?,
            effect: parse_policy_effect(&raw.policy.effect)?,
            approval_id: raw.policy.approval_id.map(ApprovalId::new).transpose()?,
        },
    };
    validate_file_write_recovery_request(&request)?;
    Ok(request)
}

pub trait CapabilityResolver: Send + Sync {
    fn resolve(&self, request: CapabilityRequest) -> Result<ResolvedCapability, PortError>;
}

pub trait CapabilityFilesystem: Send + Sync {
    fn read(&self, request: AuthorizedFileRead) -> Result<VerifiedBytes, PortError>;
    fn write(&self, request: AuthorizedFileWrite) -> Result<VerifiedWrite, PortError>;
}

pub trait StructuredGit: Send + Sync {
    fn status(&self, request: AuthorizedGitStatus) -> Result<RawGitStatusResult, PortError>;
    fn diff(&self, request: AuthorizedGitDiff) -> Result<RawGitDiffResult, PortError>;
}

pub trait ProcessLauncher: ToolControlSelfTest + Send + Sync {
    fn execute(
        &self,
        request: AuthorizedProcessRequest,
        authority: &ToolExecutionClaimAuthority,
        bindings: &dyn ProcessExecutionBindingStore,
    ) -> Result<ProcessReceipt, PortError>;
    fn cancel(&self, execution_id: &ToolExecutionId) -> Result<CancellationReceipt, PortError>;
    fn terminate_retained_process(
        &self,
        _binding: &AuthoritativeProcessBinding,
    ) -> Result<CancellationReceipt, PortError> {
        Err(PortError::failure(
            SafeErrorClassification::Unavailable,
            Retryability::NonRetryable,
        ))
    }
}

pub trait RetainedProcessController: Send + Sync {
    fn terminate_retained_process(
        &self,
        binding: &AuthoritativeProcessBinding,
    ) -> Result<CancellationReceipt, PortError>;
}

pub trait ToolControlSelfTest: Send + Sync {
    fn verify_controls(&self) -> Result<(), PortError>;
}

impl<T> RetainedProcessController for T
where
    T: ProcessLauncher + ?Sized,
{
    fn terminate_retained_process(
        &self,
        binding: &AuthoritativeProcessBinding,
    ) -> Result<CancellationReceipt, PortError> {
        ProcessLauncher::terminate_retained_process(self, binding)
    }
}

pub trait ProcessExecutionBindingStore: Send + Sync {
    fn load_claimed_authority(
        &self,
        execution_id: &ToolExecutionId,
    ) -> Result<ToolExecutionClaimAuthority, PortError>;
    fn record_process_binding(&self, binding: AuthoritativeProcessBinding)
        -> Result<(), PortError>;
}

pub trait ExecutableVerificationGuard: Send + Sync {}

pub trait ExecutableArtifactInspector: Send + Sync {
    fn inspect_and_retain(
        &self,
        configured_absolute_path: &str,
        toolchain_id: &str,
        expected_sha256: &Sha256Digest,
    ) -> Result<(ResolvedExecutable, Box<dyn ExecutableVerificationGuard>), PortError>;
}

pub trait ExecutableProfileResolver: ToolControlSelfTest + Send + Sync {
    fn resolve_registered(
        &self,
        toolchain_id: &str,
    ) -> Result<ApprovedExecutableIdentity, PortError>;
    fn verify_and_retain(
        &self,
        executable: &ResolvedExecutable,
    ) -> Result<Box<dyn ExecutableVerificationGuard>, PortError>;
}

pub trait PrivateRuntimeDirectoryVerificationGuard: Send + Sync {}

pub trait PrivateRuntimeDirectoryInspector: Send + Sync {
    fn inspect_and_retain(
        &self,
        configured_absolute_path: &str,
        registration_id: &str,
    ) -> Result<
        (
            ResolvedPrivateRuntimeDirectory,
            Box<dyn PrivateRuntimeDirectoryVerificationGuard>,
        ),
        PortError,
    >;
}

pub trait EnvironmentProfileResolver: ToolControlSelfTest + Send + Sync {
    fn resolve(
        &self,
        name: &str,
        expected_digest: &Sha256Digest,
    ) -> Result<ResolvedEnvironmentProfile, PortError>;
}

pub trait NetworkProfileVerifier: Send + Sync {
    fn verify(&self, profile: &EnforcedNetworkProfile) -> Result<(), PortError>;
}

pub trait ApprovedProcessExecutor: ToolControlSelfTest + Send + Sync {
    fn execute(
        &self,
        execution_id: ToolExecutionId,
        request: ApprovedProcessRequest,
        authority: Option<&ToolExecutionClaimAuthority>,
    ) -> Result<ProcessReceipt, PortError>;
    fn cancel(&self, execution_id: &ToolExecutionId) -> Result<CancellationReceipt, PortError>;
    fn terminate_retained_process(
        &self,
        _binding: &AuthoritativeProcessBinding,
    ) -> Result<CancellationReceipt, PortError> {
        Err(PortError::failure(
            SafeErrorClassification::Unavailable,
            Retryability::NonRetryable,
        ))
    }
}

pub trait ToolExecutionStore: Send + Sync {
    fn reserve(&self, request: NewToolIntent) -> Result<OperationIntentSnapshot, PortError>;
    fn begin(&self, request: NewToolExecution) -> Result<ToolExecutionClaim, PortError>;
    fn begin_authorized(
        &self,
        request: AuthorizedToolExecutionClaim,
    ) -> Result<ToolExecutionClaim, PortError>;
    fn load_denied(
        &self,
        request_artifact_id: &ArtifactId,
        request: &ImmutableToolRequest,
    ) -> Result<Option<DeniedToolExecution>, PortError>;
    fn resolve_denied(
        &self,
        request: ToolExecutionDenialRequest,
    ) -> Result<DeniedToolExecution, PortError>;
    fn request_cancellation(
        &self,
        execution_id: &ToolExecutionId,
    ) -> Result<ToolExecutionCancellationClaim, PortError>;
    fn resolve_terminal(
        &self,
        resolution: ToolExecutionResolution,
    ) -> Result<DurableToolExecutionReceipt, PortError>;
    fn incomplete(&self) -> Result<Vec<IncompleteToolExecution>, PortError>;
}

pub trait StructuredToolExecutor: Send + Sync {
    fn execute(&self, request: AuthorizedToolRequest) -> Result<ToolExecutionResult, PortError>;
    fn cancel(&self, execution_id: &ToolExecutionId) -> Result<CancellationReceipt, PortError>;
    fn terminate_retained_process(
        &self,
        _binding: &AuthoritativeProcessBinding,
    ) -> Result<CancellationReceipt, PortError> {
        Err(PortError::failure(
            SafeErrorClassification::Unavailable,
            Retryability::NonRetryable,
        ))
    }
    fn file_read(
        &self,
        request: FileReadRequest,
    ) -> Result<crate::DisclosureOutcome<crate::PolicyBoundBytes>, PortError>;
    fn file_write(&self, request: FileWriteRequest) -> Result<VerifiedWrite, PortError>;
    fn git_status(
        &self,
        request: GitStatusRequest,
    ) -> Result<crate::DisclosureOutcome<GitStatusResult>, PortError>;
    fn git_diff(
        &self,
        request: GitDiffRequest,
    ) -> Result<crate::DisclosureOutcome<GitDiffResult>, PortError>;
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RawFileWriteRecoveryRequest {
    schema: String,
    execution_id: String,
    task_id: String,
    target: RawRecoveryTarget,
    lease: RawRecoveryLease,
    expected_sequence: u64,
    pre_image: RawPreImage,
    expected_post_image: RawExpectedPostImage,
    workspace_mutation: RawWorkspaceMutation,
    policy: RawPolicyBinding,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RawRecoveryTarget {
    root_identity: String,
    relative_components: Vec<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RawRecoveryLease {
    task_id: String,
    holder_run_id: String,
    fencing_token: u64,
}

#[derive(Deserialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
enum RawPreImage {
    Absent,
    Artifact { artifact: RawEvidence },
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RawExpectedPostImage {
    digest: String,
    size_bytes: u64,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RawWorkspaceMutation {
    pre_fingerprint: RawFingerprint,
    pre_evidence: RawEvidence,
    actor_id: String,
    correlation_id: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RawPolicyBinding {
    decision_id: String,
    operation_digest: String,
    policy_snapshot_digest: String,
    effect: String,
    approval_id: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RawFingerprint {
    head: String,
    index_digest: String,
    status_digest: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RawEvidence {
    artifact_id: String,
    content_hash: String,
    storage_key: String,
    size_bytes: u64,
    project_id: String,
    task_id: Option<String>,
}

fn validate_file_write_recovery_request(
    request: &FileWriteRecoveryRequest,
) -> Result<(), PortError> {
    if request.lease_claim.task_id() != &request.task_id
        || request.correlation_id.trim().is_empty()
        || request.policy.decision_id.trim().is_empty()
        || [
            request.expected_sequence.get(),
            request.lease_claim.token().get(),
            request.expected_post_size,
        ]
        .into_iter()
        .any(|value| value > MAX_SAFE_INTEGER)
    {
        return Err(invalid_input());
    }
    validate_recovery_evidence(&request.pre_evidence, &request.task_id)?;
    if let FileWritePreImage::Artifact(pre_image) = &request.pre_image {
        validate_recovery_evidence(pre_image, &request.task_id)?;
        if pre_image.project_id != request.pre_evidence.project_id {
            return Err(invalid_input());
        }
    }
    Ok(())
}

fn validate_recovery_evidence(
    evidence: &crate::CanonicalEvidenceRef,
    task_id: &TaskId,
) -> Result<(), PortError> {
    if evidence.task_id.as_ref() != Some(task_id)
        || evidence.storage_key.trim().is_empty()
        || evidence.size_bytes > MAX_SAFE_INTEGER
        || Sha256Digest::new(evidence.content_hash.clone()).is_err()
    {
        return Err(invalid_input());
    }
    Ok(())
}

fn evidence_value(evidence: &crate::CanonicalEvidenceRef) -> Value {
    json!({
        "artifactId": evidence.artifact_id.as_str(),
        "contentHash": evidence.content_hash,
        "storageKey": evidence.storage_key,
        "sizeBytes": evidence.size_bytes,
        "projectId": evidence.project_id.as_str(),
        "taskId": evidence.task_id.as_ref().map(TaskId::as_str),
    })
}

fn fingerprint_value(fingerprint: &WorkspaceFingerprint) -> Value {
    json!({
        "head": fingerprint.head().as_str(),
        "indexDigest": fingerprint.index_digest(),
        "statusDigest": fingerprint.status_digest(),
    })
}

fn parse_evidence(raw: RawEvidence) -> Result<crate::CanonicalEvidenceRef, PortError> {
    Ok(crate::CanonicalEvidenceRef {
        artifact_id: ArtifactId::new(raw.artifact_id).map_err(|_| invalid_input())?,
        content_hash: raw.content_hash,
        storage_key: raw.storage_key,
        size_bytes: raw.size_bytes,
        project_id: ProjectId::new(raw.project_id).map_err(|_| invalid_input())?,
        task_id: raw
            .task_id
            .map(TaskId::new)
            .transpose()
            .map_err(|_| invalid_input())?,
    })
}

fn parse_fingerprint(raw: RawFingerprint) -> Result<WorkspaceFingerprint, PortError> {
    WorkspaceFingerprint::new(
        GitObjectId::new(raw.head).map_err(|_| invalid_input())?,
        raw.index_digest,
        raw.status_digest,
    )
    .map_err(|_| invalid_input())
}

const fn policy_effect_name(effect: PolicyEffect) -> &'static str {
    match effect {
        PolicyEffect::Allow => "allow",
        PolicyEffect::Deny => "deny",
        PolicyEffect::RequireApproval => "require_approval",
        PolicyEffect::AllowWithRedaction => "allow_with_redaction",
    }
}

fn parse_policy_effect(value: &str) -> Result<PolicyEffect, PortError> {
    match value {
        "allow" => Ok(PolicyEffect::Allow),
        "deny" => Ok(PolicyEffect::Deny),
        "require_approval" => Ok(PolicyEffect::RequireApproval),
        "allow_with_redaction" => Ok(PolicyEffect::AllowWithRedaction),
        _ => Err(invalid_input()),
    }
}

fn valid_path_component(value: &str) -> bool {
    let stem = value
        .split('.')
        .next()
        .unwrap_or_default()
        .to_ascii_uppercase();
    !value.is_empty()
        && value.len() <= 255
        && !matches!(value, "." | "..")
        && !value.ends_with(['.', ' '])
        && !value.contains(['\0', '/', '\\', ':'])
        && !matches!(
            stem.as_str(),
            "CON"
                | "PRN"
                | "AUX"
                | "NUL"
                | "COM1"
                | "COM2"
                | "COM3"
                | "COM4"
                | "COM5"
                | "COM6"
                | "COM7"
                | "COM8"
                | "COM9"
                | "LPT1"
                | "LPT2"
                | "LPT3"
                | "LPT4"
                | "LPT5"
                | "LPT6"
                | "LPT7"
                | "LPT8"
                | "LPT9"
        )
}
