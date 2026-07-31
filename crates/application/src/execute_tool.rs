use crate::{
    approval::valid_approval_nonce, canonical_policy_binding_digest, policy_request_for_tool,
    validate_tool_approval_request, ApprovalCheck, ApprovalClaim, ApprovalRequestDto,
    ApprovalSnapshot, ApprovalState, ApprovalStore, AuthorizedToolExecutionClaim,
    AuthorizedToolRequest, Clock, DeniedToolExecution, DurableToolCancellationOutcome,
    DurableToolExecutionOutcome, DurableToolExecutionReceipt, ImmutableToolRequest,
    IncompleteToolExecution, NewToolExecution, PortError, PreEffectOutcome, ProcessStatus,
    Retryability, SafeErrorClassification, SafeToolExecutionError, StructuredToolExecutor,
    ToolExecutionCancellationClaim, ToolExecutionClaim, ToolExecutionClaimAuthority,
    ToolExecutionId, ToolExecutionOrchestration, ToolExecutionResolution, ToolExecutionResult,
    ToolExecutionStore, ToolExecutionTerminal, ToolRequest,
};
use local_agent_terminal_domain::{FencingToken, RunId, Sha256Digest, TaskId};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ToolOutcome {
    ApprovalRequired(ApprovalRequestDto),
    Denied(DeniedToolExecution),
    Execution(DurableToolExecutionOutcome),
}

pub struct ExecuteTool<'a> {
    pre_effect: ToolExecutionOrchestration<'a>,
    executor: &'a dyn StructuredToolExecutor,
}

impl<'a> ExecuteTool<'a> {
    pub const fn new(
        pre_effect: ToolExecutionOrchestration<'a>,
        executor: &'a dyn StructuredToolExecutor,
    ) -> Self {
        Self {
            pre_effect,
            executor,
        }
    }

    pub fn execute(&self, request: ToolRequest) -> Result<ToolOutcome, PortError> {
        let outcome = self.pre_effect.execute(request)?;
        self.finish_pre_effect(outcome)
    }

    pub fn resume_approved(
        &self,
        approval_id: crate::ApprovalId,
    ) -> Result<ToolOutcome, PortError> {
        let outcome = self.pre_effect.resume_approved(approval_id)?;
        self.finish_pre_effect(outcome)
    }

    pub fn cancel(
        &self,
        execution_id: &ToolExecutionId,
    ) -> Result<DurableToolCancellationOutcome, PortError> {
        ExecuteDurableTool::new(self.pre_effect.execution_store(), self.executor)
            .cancel(execution_id)
    }

    fn finish_pre_effect(&self, outcome: PreEffectOutcome) -> Result<ToolOutcome, PortError> {
        match outcome {
            PreEffectOutcome::ApprovalRequired(request) => {
                Ok(ToolOutcome::ApprovalRequired(request))
            }
            PreEffectOutcome::Denied(denied) => Ok(ToolOutcome::Denied(denied)),
            PreEffectOutcome::Allowed(ready) => {
                self.pre_effect.revalidate_ready(&ready)?;
                let (claim, immutable, authoritative_request) = (*ready).into_authorized_parts();
                let outcome =
                    ExecuteDurableTool::new(self.pre_effect.execution_store(), self.executor)
                        .execute_authorized(claim, immutable, authoritative_request)?;
                Ok(ToolOutcome::Execution(outcome))
            }
        }
    }
}

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
            nonce: request.approval_nonce().ok_or_else(denied)?.to_owned(),
            claimed_at: now.clone(),
        };
        let approval = self.approvals.claim(claim.clone())?.ok_or_else(denied)?;
        validate_claimed_approval(&approval, &claim)?;
        self.executor.execute(request)
    }
}

pub struct ExecuteDurableTool<'a> {
    executions: &'a dyn ToolExecutionStore,
    executor: &'a dyn StructuredToolExecutor,
}

impl<'a> ExecuteDurableTool<'a> {
    pub const fn new(
        executions: &'a dyn ToolExecutionStore,
        executor: &'a dyn StructuredToolExecutor,
    ) -> Self {
        Self {
            executions,
            executor,
        }
    }

    pub fn execute(
        &self,
        request: AuthorizedToolRequest,
    ) -> Result<DurableToolExecutionOutcome, PortError> {
        let execution_id = request.execution_id.clone();
        let binding = request.process_request().process().binding();
        let task_id = binding.task_id().clone();
        let owner_run_id = binding.run_id().clone();
        let executor_fencing_token = request.process_request().process().executor_fencing_token();
        let operation_digest = request.revalidated_operation_digest()?;
        let claim = self.executions.begin(NewToolExecution {
            execution_id: execution_id.clone(),
            operation_digest: operation_digest.clone(),
        })?;
        self.execute_claim(
            claim,
            request,
            execution_id,
            operation_digest,
            task_id,
            owner_run_id,
            executor_fencing_token,
        )
    }

    fn execute_authorized(
        &self,
        claim: AuthorizedToolExecutionClaim,
        immutable: ImmutableToolRequest,
        authoritative_request: ToolRequest,
    ) -> Result<DurableToolExecutionOutcome, PortError> {
        validate_authorized_execution_claim(&claim, &immutable, &authoritative_request)?;
        let execution_id = claim.execution_id.clone();
        let operation_digest = claim.request_content_digest.clone();
        let task_id = claim.task_id.clone();
        let owner_run_id = claim.run_id.clone();
        let executor_fencing_token = claim.fencing_token;
        let request = AuthorizedToolRequest::from_immutable(&immutable)?;
        let execution_claim = self.executions.begin_authorized(claim)?;
        self.execute_claim(
            execution_claim,
            request,
            execution_id,
            operation_digest,
            task_id,
            owner_run_id,
            executor_fencing_token,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn execute_claim(
        &self,
        claim: ToolExecutionClaim,
        request: AuthorizedToolRequest,
        execution_id: ToolExecutionId,
        operation_digest: Sha256Digest,
        task_id: TaskId,
        owner_run_id: RunId,
        executor_fencing_token: Option<FencingToken>,
    ) -> Result<DurableToolExecutionOutcome, PortError> {
        match claim {
            ToolExecutionClaim::Claimed(authority) => {
                validate_claim_authority(
                    &authority,
                    &execution_id,
                    &operation_digest,
                    &owner_run_id,
                    executor_fencing_token,
                )?;
                let receipt =
                    receipt_from_executor_result(authority, self.executor.execute(request));
                let resolution = ToolExecutionResolution::new(receipt);
                match self.executions.resolve_terminal(resolution.clone()) {
                    Ok(receipt)
                        if validate_claim_authority(
                            receipt.authority(),
                            &execution_id,
                            &operation_digest,
                            &owner_run_id,
                            executor_fencing_token,
                        )
                        .is_ok() =>
                    {
                        Ok(DurableToolExecutionOutcome::Completed(receipt))
                    }
                    Ok(_) => Ok(DurableToolExecutionOutcome::TerminalPersistenceUnresolved {
                        resolution,
                        error: integrity_error(),
                    }),
                    Err(error) => Ok(DurableToolExecutionOutcome::TerminalPersistenceUnresolved {
                        resolution,
                        error: SafeToolExecutionError::from_error(&error),
                    }),
                }
            }
            ToolExecutionClaim::InFlight(evidence) => {
                validate_recovery_evidence(
                    &evidence,
                    &execution_id,
                    &operation_digest,
                    &task_id,
                    &owner_run_id,
                    executor_fencing_token,
                )?;
                Ok(DurableToolExecutionOutcome::InFlight(evidence))
            }
            ToolExecutionClaim::Completed(receipt) => {
                validate_claim_authority(
                    receipt.authority(),
                    &execution_id,
                    &operation_digest,
                    &owner_run_id,
                    executor_fencing_token,
                )?;
                Ok(DurableToolExecutionOutcome::Completed(receipt))
            }
            ToolExecutionClaim::Indeterminate(evidence) => {
                validate_recovery_evidence(
                    &evidence,
                    &execution_id,
                    &operation_digest,
                    &task_id,
                    &owner_run_id,
                    executor_fencing_token,
                )?;
                Ok(DurableToolExecutionOutcome::Indeterminate(evidence))
            }
        }
    }

    pub fn incomplete(&self) -> Result<Vec<IncompleteToolExecution>, PortError> {
        self.executions.incomplete()
    }

    pub fn cancel(
        &self,
        execution_id: &ToolExecutionId,
    ) -> Result<DurableToolCancellationOutcome, PortError> {
        match self.executions.request_cancellation(execution_id)? {
            ToolExecutionCancellationClaim::Claimed(authority) => {
                validate_cancellation_authority(&authority, execution_id)?;
                let receipt = self.executor.cancel(execution_id)?;
                if receipt.execution_id != *execution_id
                    || receipt.status != ProcessStatus::Terminated
                    || !receipt.cancelled
                {
                    return Err(integrity_failure());
                }
                Ok(DurableToolCancellationOutcome::Requested { authority, receipt })
            }
            ToolExecutionCancellationClaim::InFlight(authority) => {
                validate_cancellation_authority(&authority, execution_id)?;
                Ok(DurableToolCancellationOutcome::InFlight(authority))
            }
            ToolExecutionCancellationClaim::Completed(receipt) => {
                validate_cancellation_authority(receipt.authority(), execution_id)?;
                Ok(DurableToolCancellationOutcome::Completed(receipt))
            }
        }
    }
}

fn validate_authorized_execution_claim(
    claim: &AuthorizedToolExecutionClaim,
    immutable: &ImmutableToolRequest,
    authoritative_request: &ToolRequest,
) -> Result<(), PortError> {
    let request = immutable.request();
    let process = authoritative_request.process().process();
    let binding = process.binding();
    let expected_policy_binding = canonical_policy_binding_digest(&policy_request_for_tool(
        authoritative_request,
        claim.checked_at,
    ))?;
    if request.execution_id() != authoritative_request.execution_id()
        || request.process() != authoritative_request.process()
        || claim.execution_id != *request.execution_id()
        || claim.request_content_digest != *immutable.binding_digest().as_sha256()
        || claim.request_binding_digest != *immutable.binding_digest()
        || claim.task_id != *binding.task_id()
        || claim.run_id != *binding.run_id()
        || claim.tool_name != "process.exec"
        || claim.policy_request_binding_digest != expected_policy_binding
        || claim.workspace_version != binding.workspace_version()
        || claim.policy_snapshot_digest != *authoritative_request.policy().policy_snapshot_digest()
        || claim.fencing_token != process.executor_fencing_token()
    {
        return Err(integrity_failure());
    }
    if let Some(approval) = &claim.approval {
        validate_tool_approval_request(
            authoritative_request,
            immutable,
            &claim.request_artifact_id,
            &claim.policy_request_binding_digest,
            approval,
        )?;
    }
    Ok(())
}

fn validate_cancellation_authority(
    authority: &ToolExecutionClaimAuthority,
    execution_id: &ToolExecutionId,
) -> Result<(), PortError> {
    if authority.execution_id() == execution_id {
        Ok(())
    } else {
        Err(integrity_failure())
    }
}

fn receipt_from_executor_result(
    authority: ToolExecutionClaimAuthority,
    result: Result<ToolExecutionResult, PortError>,
) -> DurableToolExecutionReceipt {
    match result {
        Ok(result) if result.receipt.execution_id == *authority.execution_id() => {
            match DurableToolExecutionReceipt::from_process_receipt(
                authority.clone(),
                result.receipt,
            ) {
                Ok(receipt) => receipt,
                Err(_) => indeterminate_receipt(authority, integrity_error()),
            }
        }
        Ok(_) => indeterminate_receipt(authority, integrity_error()),
        Err(error) => {
            let safe_error = SafeToolExecutionError::from_error(&error);
            indeterminate_receipt(authority, safe_error)
        }
    }
}

fn indeterminate_receipt(
    authority: ToolExecutionClaimAuthority,
    error: SafeToolExecutionError,
) -> DurableToolExecutionReceipt {
    DurableToolExecutionReceipt::new(authority, ToolExecutionTerminal::indeterminate(error))
}

fn validate_recovery_evidence(
    evidence: &crate::ToolExecutionRecoveryEvidence,
    execution_id: &crate::ToolExecutionId,
    operation_digest: &Sha256Digest,
    task_id: &TaskId,
    owner_run_id: &RunId,
    executor_fencing_token: Option<FencingToken>,
) -> Result<(), PortError> {
    validate_claim_authority(
        &evidence.authority,
        execution_id,
        operation_digest,
        owner_run_id,
        executor_fencing_token,
    )?;
    if &evidence.task_id != task_id {
        return Err(integrity_failure());
    }
    Ok(())
}

fn validate_claim_authority(
    authority: &ToolExecutionClaimAuthority,
    execution_id: &crate::ToolExecutionId,
    operation_digest: &Sha256Digest,
    owner_run_id: &RunId,
    executor_fencing_token: Option<FencingToken>,
) -> Result<(), PortError> {
    if authority.execution_id() != execution_id
        || authority.operation_digest() != operation_digest
        || authority.owner_run_id() != owner_run_id
        || authority.executor_fencing_token() != executor_fencing_token
    {
        return Err(integrity_failure());
    }
    Ok(())
}

fn integrity_failure() -> PortError {
    PortError::failure(
        SafeErrorClassification::IntegrityFailure,
        Retryability::NonRetryable,
    )
}

fn integrity_error() -> SafeToolExecutionError {
    SafeToolExecutionError::from_error(&integrity_failure())
}

fn validate_claimed_approval(
    approval: &ApprovalSnapshot,
    claim: &ApprovalClaim,
) -> Result<(), PortError> {
    if approval.state != ApprovalState::Consumed || !approval_bindings_match(approval, claim) {
        return Err(denied());
    }
    Ok(())
}

fn approval_bindings_match(approval: &ApprovalSnapshot, claim: &ApprovalClaim) -> bool {
    approval.approval_id == claim.approval_id
        && !is_expired(&approval.expires_at, &claim.claimed_at)
        && approval.operation_digest == claim.expected_operation_digest
        && approval.task_id == claim.task_id
        && approval.workspace_version == claim.workspace_version
        && approval.policy_snapshot_digest == claim.policy_snapshot_digest
        && approval.fencing_token == claim.fencing_token
        && approval.tool_request_binding_digest.as_ref() == Some(&claim.tool_request_binding_digest)
        && valid_approval_nonce(&approval.nonce)
        && approval.nonce == claim.nonce
}

fn request_matches(request: &AuthorizedToolRequest, check: &ApprovalCheck) -> bool {
    let process_request = request.process_request();
    let process = process_request.process();
    request
        .revalidated_operation_digest()
        .is_ok_and(|digest| digest == check.expected_operation_digest)
        && process.binding().task_id() == &check.task_id
        && process.binding().workspace_version() == check.workspace_version
        && process.executor_fencing_token().map(|token| token.get()) == check.fencing_token
        && process_request.expected_reads().iter().all(|capability| {
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
