use local_agent_terminal_domain::{
    ArtifactId, FencingToken, RunId, Sha256Digest, TaskId, Timestamp, WorkspaceVersion,
};

use crate::{
    ApprovalId, ApprovalState, OperationIntentStatus, PolicyDecisionId, PolicyRequestBindingDigest,
    PortError, Retryability, SafeErrorClassification, ToolExecutionId, ToolRequestBindingDigest,
};

/// The immutable relation needed to resume an approval by its opaque ID.
///
/// The snapshot contains persisted approval terms only. It does not accept a
/// caller-supplied request body or approval terms.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovalResumeSnapshot {
    pub approval_id: ApprovalId,
    pub execution_id: ToolExecutionId,
    pub policy_decision_id: PolicyDecisionId,
    pub policy_request_binding_digest: PolicyRequestBindingDigest,
    pub approval_operation_digest: Sha256Digest,
    pub tool_request_binding_digest: ToolRequestBindingDigest,
    pub task_id: TaskId,
    pub run_id: RunId,
    pub request_artifact_id: ArtifactId,
    pub request_content_digest: Sha256Digest,
    pub intent_id: String,
    pub workspace_version: WorkspaceVersion,
    pub policy_snapshot_digest: Sha256Digest,
    pub fencing_token: Option<FencingToken>,
    pub expires_at: Timestamp,
    pub nonce: String,
    pub state: ApprovalState,
}

impl ApprovalResumeSnapshot {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        approval_id: ApprovalId,
        execution_id: ToolExecutionId,
        policy_decision_id: PolicyDecisionId,
        policy_request_binding_digest: PolicyRequestBindingDigest,
        approval_operation_digest: Sha256Digest,
        tool_request_binding_digest: ToolRequestBindingDigest,
        task_id: TaskId,
        run_id: RunId,
        request_artifact_id: ArtifactId,
        request_content_digest: Sha256Digest,
        intent_id: String,
        workspace_version: WorkspaceVersion,
        policy_snapshot_digest: Sha256Digest,
        fencing_token: Option<FencingToken>,
        expires_at: Timestamp,
        nonce: String,
        state: ApprovalState,
    ) -> Result<Self, PortError> {
        validate_nonce(&nonce)?;
        validate_intent_id(&intent_id)?;
        Ok(Self {
            approval_id,
            execution_id,
            policy_decision_id,
            policy_request_binding_digest,
            approval_operation_digest,
            tool_request_binding_digest,
            task_id,
            run_id,
            request_artifact_id,
            request_content_digest,
            intent_id,
            workspace_version,
            policy_snapshot_digest,
            fencing_token,
            expires_at,
            nonce,
            state,
        })
    }
}

/// The exact execution and intent rows reached through an approval relation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolExecutionResumeSnapshot {
    pub execution_id: ToolExecutionId,
    pub approval_id: ApprovalId,
    pub approval_policy_decision_id: PolicyDecisionId,
    pub approval_operation_digest: Sha256Digest,
    pub policy_request_binding_digest: PolicyRequestBindingDigest,
    pub request_binding_digest: ToolRequestBindingDigest,
    pub task_id: TaskId,
    pub run_id: RunId,
    pub workspace_version: WorkspaceVersion,
    pub policy_snapshot_digest: Sha256Digest,
    pub fencing_token: Option<FencingToken>,
    pub approval_expires_at: Timestamp,
    pub approval_nonce: String,
    pub request_artifact_id: ArtifactId,
    pub request_content_digest: Sha256Digest,
    pub intent_operation_digest: Sha256Digest,
    pub intent_id: String,
    pub intent_status: OperationIntentStatus,
}

impl ToolExecutionResumeSnapshot {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        execution_id: ToolExecutionId,
        approval_id: ApprovalId,
        approval_policy_decision_id: PolicyDecisionId,
        approval_operation_digest: Sha256Digest,
        policy_request_binding_digest: PolicyRequestBindingDigest,
        request_binding_digest: ToolRequestBindingDigest,
        task_id: TaskId,
        run_id: RunId,
        workspace_version: WorkspaceVersion,
        policy_snapshot_digest: Sha256Digest,
        fencing_token: Option<FencingToken>,
        approval_expires_at: Timestamp,
        approval_nonce: String,
        request_artifact_id: ArtifactId,
        request_content_digest: Sha256Digest,
        intent_operation_digest: Sha256Digest,
        intent_id: String,
        intent_status: OperationIntentStatus,
    ) -> Result<Self, PortError> {
        validate_nonce(&approval_nonce)?;
        validate_intent_id(&intent_id)?;
        Ok(Self {
            execution_id,
            approval_id,
            approval_policy_decision_id,
            approval_operation_digest,
            policy_request_binding_digest,
            request_binding_digest,
            task_id,
            run_id,
            workspace_version,
            policy_snapshot_digest,
            fencing_token,
            approval_expires_at,
            approval_nonce,
            request_artifact_id,
            request_content_digest,
            intent_operation_digest,
            intent_id,
            intent_status,
        })
    }
}

/// Reads the immutable approval relation using only an opaque ID and trusted
/// application time.
pub trait ApprovalResumeStore: Send + Sync {
    fn load_for_resume(
        &self,
        approval_id: &ApprovalId,
        checked_at: Timestamp,
    ) -> Result<ApprovalResumeSnapshot, PortError>;
}

/// Reads the exact execution intent reached from the approval relation.
pub trait ToolExecutionResumeStore: Send + Sync {
    fn load_intent(
        &self,
        execution_id: &ToolExecutionId,
    ) -> Result<ToolExecutionResumeSnapshot, PortError>;
}

/// Validates only the persisted approval -> execution -> intent identity.
///
/// Lifecycle state and freshness are intentionally left to
/// [`validate_pending_approval_resume`], so terminal rows remain replayable.
pub fn validate_approval_resume_relation(
    approval: &ApprovalResumeSnapshot,
    execution: &ToolExecutionResumeSnapshot,
) -> Result<(), PortError> {
    if !valid_nonce(&approval.nonce)
        || !valid_nonce(&execution.approval_nonce)
        || !valid_intent_id(&approval.intent_id)
        || !valid_intent_id(&execution.intent_id)
        || approval.approval_id != execution.approval_id
        || approval.execution_id != execution.execution_id
        || approval.policy_decision_id != execution.approval_policy_decision_id
        || approval.policy_request_binding_digest != execution.policy_request_binding_digest
        || approval.approval_operation_digest != execution.approval_operation_digest
        || approval.tool_request_binding_digest != execution.request_binding_digest
        || approval.task_id != execution.task_id
        || approval.run_id != execution.run_id
        || approval.request_artifact_id != execution.request_artifact_id
        || approval.request_content_digest != execution.request_content_digest
        || approval.intent_id != execution.intent_id
        || approval.workspace_version != execution.workspace_version
        || approval.policy_snapshot_digest != execution.policy_snapshot_digest
        || approval.fencing_token != execution.fencing_token
        || approval.expires_at != execution.approval_expires_at
        || approval.nonce != execution.approval_nonce
        || execution.request_content_digest != execution.intent_operation_digest
    {
        return Err(resume_integrity_failure());
    }
    Ok(())
}

/// Validates an approval relation for a new pending execution attempt.
///
/// This is the read-only gate used before the later atomic begin/consume
/// transaction. It does not mutate or consume the approval.
pub fn validate_pending_approval_resume(
    approval: &ApprovalResumeSnapshot,
    execution: &ToolExecutionResumeSnapshot,
    checked_at: Timestamp,
) -> Result<(), PortError> {
    validate_approval_resume_relation(approval, execution)?;
    if approval.state != ApprovalState::Approved
        || approval.expires_at <= checked_at
        || execution.intent_status != OperationIntentStatus::Pending
    {
        return Err(resume_integrity_failure());
    }
    Ok(())
}

fn valid_nonce(value: &str) -> bool {
    (32..=256).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
}

fn valid_intent_id(value: &str) -> bool {
    !value.trim().is_empty() && value.len() <= 256 && !value.contains('\0')
}

fn validate_nonce(value: &str) -> Result<(), PortError> {
    if !valid_nonce(value) {
        return Err(invalid_resume_input());
    }
    Ok(())
}

fn validate_intent_id(value: &str) -> Result<(), PortError> {
    if !valid_intent_id(value) {
        return Err(invalid_resume_input());
    }
    Ok(())
}

fn invalid_resume_input() -> PortError {
    PortError::failure(
        SafeErrorClassification::InvalidInput,
        Retryability::NonRetryable,
    )
}

fn resume_integrity_failure() -> PortError {
    PortError::failure(
        SafeErrorClassification::IntegrityFailure,
        Retryability::NonRetryable,
    )
}
