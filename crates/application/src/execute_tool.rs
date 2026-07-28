use crate::{
    approval::valid_approval_nonce, ApprovalCheck, ApprovalClaim, ApprovalSnapshot, ApprovalState,
    ApprovalStore, AuthorizedToolRequest, Clock, PortError, SafeErrorClassification,
    StructuredToolExecutor, ToolExecutionResult,
};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

pub struct ExecuteApprovedTool<'a> {
    approvals: &'a dyn ApprovalStore,
    executor: &'a dyn StructuredToolExecutor,
    clock: &'a dyn Clock,
}

impl<'a> ExecuteApprovedTool<'a> {
    pub const fn new(
        approvals: &'a dyn ApprovalStore,
        executor: &'a dyn StructuredToolExecutor,
        clock: &'a dyn Clock,
    ) -> Self {
        Self {
            approvals,
            executor,
            clock,
        }
    }

    pub fn execute(
        &self,
        check: ApprovalCheck,
        request: AuthorizedToolRequest,
    ) -> Result<ToolExecutionResult, PortError> {
        let now = self.clock.now_utc()?;
        let request_binding = request
            .revalidated_request_binding_digest()
            .map_err(|_| denied())?
            .clone();
        if !same_instant(&now, &check.checked_at) || !request_matches(&request, &check) {
            return Err(denied());
        }
        let claim = ApprovalClaim {
            approval_id: check.approval_id,
            expected_operation_digest: check.expected_operation_digest,
            task_id: check.task_id,
            workspace_version: check.workspace_version,
            policy_snapshot_digest: check.policy_snapshot_digest,
            fencing_token: check.fencing_token,
            tool_request_binding_digest: request_binding,
            nonce: request.approval_nonce().to_owned(),
            claimed_at: now.clone(),
        };
        let approval = self.approvals.claim(claim.clone())?.ok_or_else(denied)?;
        validate_claimed_approval(&approval, &claim)?;
        self.executor.execute(request)
    }
}

fn validate_claimed_approval(
    approval: &ApprovalSnapshot,
    claim: &ApprovalClaim,
) -> Result<(), PortError> {
    if approval.state != ApprovalState::Consumed
        || approval.approval_id != claim.approval_id
        || is_expired(&approval.expires_at, &claim.claimed_at)
        || approval.operation_digest != claim.expected_operation_digest
        || approval.task_id != claim.task_id
        || approval.workspace_version != claim.workspace_version
        || approval.policy_snapshot_digest != claim.policy_snapshot_digest
        || approval.fencing_token != claim.fencing_token
        || approval.tool_request_binding_digest.as_ref() != Some(&claim.tool_request_binding_digest)
        || !valid_approval_nonce(&approval.nonce)
        || approval.nonce != claim.nonce
    {
        return Err(denied());
    }
    Ok(())
}

fn request_matches(request: &AuthorizedToolRequest, check: &ApprovalCheck) -> bool {
    let process_request = request.process_request();
    let process = &process_request.process;
    request
        .revalidated_operation_digest()
        .is_ok_and(|digest| digest == check.expected_operation_digest)
        && process.binding().task_id() == &check.task_id
        && process.binding().workspace_version() == check.workspace_version
        && process.executor_fencing_token().map(|token| token.get()) == check.fencing_token
        && process_request.expected_reads.iter().all(|capability| {
            capability
                .worktree_task_id()
                .is_none_or(|task_id| task_id == &check.task_id)
        })
}

fn same_instant(left: &str, right: &str) -> bool {
    match (parse_timestamp(left), parse_timestamp(right)) {
        (Some(left), Some(right)) => left == right,
        _ => false,
    }
}

fn is_expired(expires_at: &str, now: &str) -> bool {
    match (parse_timestamp(expires_at), parse_timestamp(now)) {
        (Some(expires_at), Some(now)) => expires_at <= now,
        _ => true,
    }
}

fn parse_timestamp(value: &str) -> Option<OffsetDateTime> {
    OffsetDateTime::parse(value, &Rfc3339).ok()
}

fn denied() -> PortError {
    PortError::failure(
        SafeErrorClassification::PermissionDenied,
        crate::Retryability::NonRetryable,
    )
}
