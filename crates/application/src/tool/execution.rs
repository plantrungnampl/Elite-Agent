
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessReceipt {
    pub execution_id: ToolExecutionId,
    pub status: ProcessStatus,
    pub exit_code: Option<i32>,
    pub stdout: BoundedOutput,
    pub stderr: BoundedOutput,
    pub duration_ms: u64,
    pub job_receipt: JobReceipt,
    pub observed_writes: Vec<ObservedProcessWrite>,
    /// Retained for the existing durable receipt schema.
    pub output_digest: Sha256Digest,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CancellationReceipt {
    pub execution_id: ToolExecutionId,
    pub status: ProcessStatus,
    pub job_receipt: Option<JobReceipt>,
    /// Retained for the existing durable receipt schema.
    pub cancelled: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoundedOutput {
    pub bytes: Vec<u8>,
    pub truncated: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolExecutionStreamMetadata {
    pub digest: Sha256Digest,
    pub size_bytes: u64,
    pub truncated: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolExecutionPostEffectReceipt {
    pub execution_id: ToolExecutionId,
    pub status: ProcessStatus,
    pub exit_code: Option<i32>,
    pub stdout: ToolExecutionStreamMetadata,
    pub stderr: ToolExecutionStreamMetadata,
    pub duration_ms: u64,
    pub output_digest: Sha256Digest,
    pub observed_writes: Vec<VerifiedWrite>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessStatus {
    Exited,
    Terminated,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JobReceipt {
    pub root_pid: u32,
    pub job_id: String,
    pub kill_on_close: bool,
    pub no_breakaway: bool,
    pub job_memory_limit: bool,
    pub job_cpu_time_limit: bool,
    pub memory_limit_bytes: u64,
    pub cpu_time_limit_ms: u64,
    pub max_active_processes: u32,
    pub total_user_time_ms: u64,
    pub resource_limit_terminated: bool,
    pub tree_terminated: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ToolExecutionId(String);

impl ToolExecutionId {
    pub fn new(value: impl Into<String>) -> Result<Self, PortError> {
        let value = value.into();
        if value.trim().is_empty() || value.len() > 256 || value.contains('\0') {
            return Err(crate::canonical_json::invalid_input());
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewToolIntent {
    pub execution_id: ToolExecutionId,
    pub operation_digest: Sha256Digest,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OperationIntentSnapshot {
    pub execution_id: ToolExecutionId,
    pub operation_digest: Sha256Digest,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewToolExecution {
    pub execution_id: ToolExecutionId,
    pub operation_digest: Sha256Digest,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizedToolExecutionClaim {
    pub execution_id: ToolExecutionId,
    pub request_artifact_id: ArtifactId,
    pub request_content_digest: Sha256Digest,
    pub request_binding_digest: ToolRequestBindingDigest,
    pub task_id: TaskId,
    pub run_id: RunId,
    pub tool_name: String,
    pub policy_decision_id: PolicyDecisionId,
    pub policy_request_binding_digest: PolicyRequestBindingDigest,
    pub approval: Option<ToolApprovalRequest>,
    pub workspace_version: WorkspaceVersion,
    pub policy_snapshot_digest: Sha256Digest,
    pub fencing_token: Option<FencingToken>,
    pub checked_at: Timestamp,
    pub effect_checked_at: Timestamp,
    pub approval_checked_at: Option<Timestamp>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolExecutionDenialRequest {
    pub request_artifact_id: ArtifactId,
    pub request: ImmutableToolRequest,
    pub policy_decision_id: PolicyDecisionId,
    pub policy_request_binding_digest: PolicyRequestBindingDigest,
    pub effect: PolicyEffect,
    pub checked_at: Timestamp,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeniedToolExecution {
    execution_id: ToolExecutionId,
    request_artifact_id: ArtifactId,
    policy_decision_id: PolicyDecisionId,
}

impl DeniedToolExecution {
    pub const fn new(
        execution_id: ToolExecutionId,
        request_artifact_id: ArtifactId,
        policy_decision_id: PolicyDecisionId,
    ) -> Self {
        Self {
            execution_id,
            request_artifact_id,
            policy_decision_id,
        }
    }

    pub const fn execution_id(&self) -> &ToolExecutionId {
        &self.execution_id
    }

    pub const fn request_artifact_id(&self) -> &ArtifactId {
        &self.request_artifact_id
    }

    pub const fn policy_decision_id(&self) -> &PolicyDecisionId {
        &self.policy_decision_id
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DurableToolExecutionArtifact {
    Available(ArtifactId),
    Unavailable,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DurableToolExecutionArtifacts {
    stdout: DurableToolExecutionArtifact,
    stderr: DurableToolExecutionArtifact,
    observed_writes: Vec<DurableToolExecutionArtifact>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DisclosedToolExecutionArtifacts {
    stdout: PolicyBoundBytes,
    stderr: PolicyBoundBytes,
    observed_writes: Vec<PolicyBoundBytes>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuarantinedToolExecutionArtifacts {
    receipt: ToolExecutionPostEffectReceipt,
    error: SafeToolExecutionError,
}

impl QuarantinedToolExecutionArtifacts {
    pub fn new(receipt: ToolExecutionPostEffectReceipt, error: SafeToolExecutionError) -> Self {
        Self { receipt, error }
    }

    pub const fn receipt(&self) -> &ToolExecutionPostEffectReceipt {
        &self.receipt
    }

    pub const fn error(&self) -> &SafeToolExecutionError {
        &self.error
    }
}

impl DisclosedToolExecutionArtifacts {
    pub fn new(
        stdout: PolicyBoundBytes,
        stderr: PolicyBoundBytes,
        observed_writes: Vec<PolicyBoundBytes>,
    ) -> Self {
        Self {
            stdout,
            stderr,
            observed_writes,
        }
    }

    pub const fn stdout(&self) -> &PolicyBoundBytes {
        &self.stdout
    }

    pub const fn stderr(&self) -> &PolicyBoundBytes {
        &self.stderr
    }

    pub fn observed_writes(&self) -> &[PolicyBoundBytes] {
        &self.observed_writes
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ToolExecutionArtifactEvidence {
    Disclosed(DisclosedToolExecutionArtifacts),
    Published(DurableToolExecutionArtifacts),
    Quarantined(QuarantinedToolExecutionArtifacts),
}

impl DurableToolExecutionArtifacts {
    pub fn new(
        stdout: DurableToolExecutionArtifact,
        stderr: DurableToolExecutionArtifact,
        observed_writes: Vec<DurableToolExecutionArtifact>,
    ) -> Self {
        Self {
            stdout,
            stderr,
            observed_writes,
        }
    }

    pub const fn stdout(&self) -> &DurableToolExecutionArtifact {
        &self.stdout
    }

    pub const fn stderr(&self) -> &DurableToolExecutionArtifact {
        &self.stderr
    }

    pub fn observed_writes(&self) -> &[DurableToolExecutionArtifact] {
        &self.observed_writes
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolExecutionOutput {
    pub exit_code: Option<i32>,
    pub output_digest: Sha256Digest,
    pub duration_ms: u64,
    pub artifacts: DurableToolExecutionArtifacts,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SafeToolExecutionError {
    pub classification: SafeErrorClassification,
    pub retryability: Retryability,
}

impl SafeToolExecutionError {
    pub(crate) fn from_error(error: &PortError) -> Self {
        Self {
            classification: error.safe_classification(),
            retryability: error.retryability(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ToolExecutionTerminalKind {
    Succeeded,
    Failed,
    Cancelled,
    Terminated,
    Interrupted,
    Indeterminate,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ToolExecutionTerminalState {
    Succeeded(ToolExecutionOutput),
    Failed(ToolExecutionOutput),
    Cancelled,
    Terminated(ToolExecutionOutput),
    Interrupted,
    Indeterminate {
        error: SafeToolExecutionError,
        post_effect: Option<Box<ToolExecutionPostEffectReceipt>>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolExecutionTerminal {
    state: ToolExecutionTerminalState,
}

impl ToolExecutionTerminal {
    pub fn succeeded(output: ToolExecutionOutput) -> Result<Self, PortError> {
        if output.exit_code != Some(0) {
            return Err(invalid_input());
        }
        Ok(Self {
            state: ToolExecutionTerminalState::Succeeded(output),
        })
    }

    pub fn failed(output: ToolExecutionOutput) -> Result<Self, PortError> {
        if output.exit_code == Some(0) {
            return Err(invalid_input());
        }
        Ok(Self {
            state: ToolExecutionTerminalState::Failed(output),
        })
    }

    pub fn terminated(output: ToolExecutionOutput) -> Result<Self, PortError> {
        if output.exit_code == Some(0) {
            return Err(invalid_input());
        }
        Ok(Self {
            state: ToolExecutionTerminalState::Terminated(output),
        })
    }

    pub const fn cancelled() -> Self {
        Self {
            state: ToolExecutionTerminalState::Cancelled,
        }
    }

    pub const fn interrupted() -> Self {
        Self {
            state: ToolExecutionTerminalState::Interrupted,
        }
    }

    pub const fn indeterminate(error: SafeToolExecutionError) -> Self {
        Self {
            state: ToolExecutionTerminalState::Indeterminate {
                error,
                post_effect: None,
            },
        }
    }

    pub fn indeterminate_with_post_effect(
        error: SafeToolExecutionError,
        post_effect: ToolExecutionPostEffectReceipt,
    ) -> Self {
        Self {
            state: ToolExecutionTerminalState::Indeterminate {
                error,
                post_effect: Some(Box::new(post_effect)),
            },
        }
    }

    pub const fn kind(&self) -> ToolExecutionTerminalKind {
        match self.state {
            ToolExecutionTerminalState::Succeeded(_) => ToolExecutionTerminalKind::Succeeded,
            ToolExecutionTerminalState::Failed(_) => ToolExecutionTerminalKind::Failed,
            ToolExecutionTerminalState::Cancelled => ToolExecutionTerminalKind::Cancelled,
            ToolExecutionTerminalState::Terminated(_) => ToolExecutionTerminalKind::Terminated,
            ToolExecutionTerminalState::Interrupted => ToolExecutionTerminalKind::Interrupted,
            ToolExecutionTerminalState::Indeterminate { .. } => {
                ToolExecutionTerminalKind::Indeterminate
            }
        }
    }

    pub const fn output(&self) -> Option<&ToolExecutionOutput> {
        match &self.state {
            ToolExecutionTerminalState::Succeeded(output)
            | ToolExecutionTerminalState::Failed(output)
            | ToolExecutionTerminalState::Terminated(output) => Some(output),
            ToolExecutionTerminalState::Cancelled
            | ToolExecutionTerminalState::Interrupted
            | ToolExecutionTerminalState::Indeterminate { .. } => None,
        }
    }

    pub const fn error(&self) -> Option<&SafeToolExecutionError> {
        match &self.state {
            ToolExecutionTerminalState::Indeterminate { error, .. } => Some(error),
            ToolExecutionTerminalState::Succeeded(_)
            | ToolExecutionTerminalState::Failed(_)
            | ToolExecutionTerminalState::Cancelled
            | ToolExecutionTerminalState::Terminated(_)
            | ToolExecutionTerminalState::Interrupted => None,
        }
    }

    pub fn post_effect(&self) -> Option<&ToolExecutionPostEffectReceipt> {
        match &self.state {
            ToolExecutionTerminalState::Indeterminate { post_effect, .. } => post_effect.as_deref(),
            ToolExecutionTerminalState::Succeeded(_)
            | ToolExecutionTerminalState::Failed(_)
            | ToolExecutionTerminalState::Cancelled
            | ToolExecutionTerminalState::Terminated(_)
            | ToolExecutionTerminalState::Interrupted => None,
        }
    }

    fn from_process(status: ProcessStatus, output: ToolExecutionOutput) -> Result<Self, PortError> {
        match status {
            ProcessStatus::Exited if output.exit_code == Some(0) => Self::succeeded(output),
            ProcessStatus::Exited => Self::failed(output),
            ProcessStatus::Terminated => Self::terminated(output),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DurableToolExecutionReceipt {
    authority: ToolExecutionClaimAuthority,
    terminal: ToolExecutionTerminal,
    process_termination: Option<Box<AuthoritativeProcessTermination>>,
}

impl DurableToolExecutionReceipt {
    pub fn new(authority: ToolExecutionClaimAuthority, terminal: ToolExecutionTerminal) -> Self {
        Self {
            authority,
            terminal,
            process_termination: None,
        }
    }

    #[must_use]
    pub fn recovered_process_termination(
        classification: SafeErrorClassification,
        process_termination: AuthoritativeProcessTermination,
    ) -> Self {
        Self {
            authority: process_termination.binding.authority.clone(),
            terminal: ToolExecutionTerminal::indeterminate(SafeToolExecutionError {
                classification,
                retryability: Retryability::NonRetryable,
            }),
            process_termination: Some(Box::new(process_termination)),
        }
    }

    pub(crate) fn from_process_receipt(
        authority: ToolExecutionClaimAuthority,
        receipt: ProcessReceipt,
        artifacts: DurableToolExecutionArtifacts,
    ) -> Result<Self, PortError> {
        if authority.execution_id != receipt.execution_id
            || matches!(
                artifacts.stdout(),
                DurableToolExecutionArtifact::Unavailable
            )
            || matches!(
                artifacts.stderr(),
                DurableToolExecutionArtifact::Unavailable
            )
            || artifacts.observed_writes().len() != receipt.observed_writes.len()
            || artifacts
                .observed_writes()
                .iter()
                .any(|artifact| matches!(artifact, DurableToolExecutionArtifact::Unavailable))
        {
            return Err(invalid_input());
        }
        let ProcessReceipt {
            status,
            exit_code,
            duration_ms,
            output_digest,
            ..
        } = receipt;
        let output = ToolExecutionOutput {
            exit_code,
            output_digest,
            duration_ms,
            artifacts,
        };
        ToolExecutionTerminal::from_process(status, output)
            .map(|terminal| Self::new(authority, terminal))
    }

    pub fn from_post_effect_receipt(
        authority: ToolExecutionClaimAuthority,
        receipt: ToolExecutionPostEffectReceipt,
        error: SafeToolExecutionError,
    ) -> Result<Self, PortError> {
        if authority.execution_id != receipt.execution_id {
            return Err(invalid_input());
        }
        Ok(Self::new(
            authority,
            ToolExecutionTerminal::indeterminate_with_post_effect(error, receipt),
        ))
    }

    pub const fn authority(&self) -> &ToolExecutionClaimAuthority {
        &self.authority
    }

    pub const fn terminal(&self) -> &ToolExecutionTerminal {
        &self.terminal
    }

    pub fn process_termination(&self) -> Option<&AuthoritativeProcessTermination> {
        self.process_termination.as_deref()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolExecutionClaimAuthority {
    execution_id: ToolExecutionId,
    operation_digest: Sha256Digest,
    owner_run_id: RunId,
    attempt: u32,
    executor_fencing_token: Option<FencingToken>,
}

impl ToolExecutionClaimAuthority {
    pub fn from_persisted(
        execution_id: ToolExecutionId,
        operation_digest: Sha256Digest,
        owner_run_id: RunId,
        attempt: u32,
        executor_fencing_token: Option<FencingToken>,
    ) -> Result<Self, PortError> {
        if attempt == 0 {
            return Err(invalid_input());
        }
        Ok(Self {
            execution_id,
            operation_digest,
            owner_run_id,
            attempt,
            executor_fencing_token,
        })
    }

    pub const fn execution_id(&self) -> &ToolExecutionId {
        &self.execution_id
    }

    pub const fn operation_digest(&self) -> &Sha256Digest {
        &self.operation_digest
    }

    pub const fn owner_run_id(&self) -> &RunId {
        &self.owner_run_id
    }

    pub const fn attempt(&self) -> u32 {
        self.attempt
    }

    pub const fn executor_fencing_token(&self) -> Option<FencingToken> {
        self.executor_fencing_token
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthoritativeProcessBinding {
    authority: ToolExecutionClaimAuthority,
    root_pid: u32,
    job_id: String,
}

impl AuthoritativeProcessBinding {
    pub fn new(
        authority: ToolExecutionClaimAuthority,
        root_pid: u32,
        job_id: impl Into<String>,
    ) -> Result<Self, PortError> {
        let job_id = job_id.into();
        if root_pid == 0 || job_id.trim().is_empty() || job_id.len() > 256 || job_id.contains('\0')
        {
            return Err(invalid_input());
        }
        Ok(Self {
            authority,
            root_pid,
            job_id,
        })
    }

    pub const fn authority(&self) -> &ToolExecutionClaimAuthority {
        &self.authority
    }

    pub const fn root_pid(&self) -> u32 {
        self.root_pid
    }

    pub fn job_id(&self) -> &str {
        &self.job_id
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthoritativeProcessTermination {
    binding: AuthoritativeProcessBinding,
    receipt: CancellationReceipt,
}

impl AuthoritativeProcessTermination {
    pub fn new(
        binding: AuthoritativeProcessBinding,
        receipt: CancellationReceipt,
    ) -> Result<Self, PortError> {
        let Some(job) = receipt.job_receipt.as_ref() else {
            return Err(invalid_input());
        };
        if receipt.execution_id != *binding.authority().execution_id()
            || receipt.status != ProcessStatus::Terminated
            || !receipt.cancelled
            || job.root_pid != binding.root_pid()
            || job.job_id != binding.job_id()
            || !job.kill_on_close
            || !job.no_breakaway
            || !job.tree_terminated
        {
            return Err(invalid_input());
        }
        Ok(Self { binding, receipt })
    }

    pub const fn binding(&self) -> &AuthoritativeProcessBinding {
        &self.binding
    }

    pub const fn receipt(&self) -> &CancellationReceipt {
        &self.receipt
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ToolExecutionRecoveryState {
    Claimed,
    Started,
    Indeterminate,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolExecutionRecoveryEvidence {
    pub authority: ToolExecutionClaimAuthority,
    pub task_id: TaskId,
    pub canonical_request_artifact_id: ArtifactId,
    pub idempotency_class: crate::IdempotencyClass,
    pub state: ToolExecutionRecoveryState,
    pub process_binding: Option<AuthoritativeProcessBinding>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IncompleteToolExecution {
    InFlight(ToolExecutionRecoveryEvidence),
    Indeterminate(ToolExecutionRecoveryEvidence),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolExecutionResolution {
    receipt: DurableToolExecutionReceipt,
}

impl ToolExecutionResolution {
    pub fn new(receipt: DurableToolExecutionReceipt) -> Self {
        Self { receipt }
    }

    pub const fn authority(&self) -> &ToolExecutionClaimAuthority {
        self.receipt.authority()
    }

    pub const fn receipt(&self) -> &DurableToolExecutionReceipt {
        &self.receipt
    }

    pub fn into_receipt(self) -> DurableToolExecutionReceipt {
        self.receipt
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ToolExecutionClaim {
    Claimed(ToolExecutionClaimAuthority),
    InFlight(ToolExecutionRecoveryEvidence),
    Completed(DurableToolExecutionReceipt),
    Indeterminate(ToolExecutionRecoveryEvidence),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ToolExecutionCancellationClaim {
    Claimed(ToolExecutionClaimAuthority),
    InFlight(ToolExecutionClaimAuthority),
    Completed(DurableToolExecutionReceipt),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DurableToolCancellationOutcome {
    Requested {
        authority: ToolExecutionClaimAuthority,
        receipt: CancellationReceipt,
    },
    InFlight(ToolExecutionClaimAuthority),
    Completed(DurableToolExecutionReceipt),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DurableToolExecutionOutcome {
    InFlight(ToolExecutionRecoveryEvidence),
    Completed(DurableToolExecutionReceipt),
    Indeterminate(ToolExecutionRecoveryEvidence),
    TerminalPersistenceUnresolved {
        resolution: ToolExecutionResolution,
        error: SafeToolExecutionError,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizedToolRequest {
    pub execution_id: ToolExecutionId,
    request: ApprovedProcessRequest,
    request_binding_digest: ToolRequestBindingDigest,
    approval: Option<BoundToolApproval>,
    authority: Option<ToolExecutionClaimAuthority>,
}

impl AuthorizedToolRequest {
    pub fn new(
        execution_id: ToolExecutionId,
        approval: BoundToolApproval,
        request: ApprovedProcessRequest,
    ) -> Self {
        let request_binding_digest = approval.request_binding_digest.clone();
        Self {
            execution_id,
            request,
            request_binding_digest,
            approval: Some(approval),
            authority: None,
        }
    }

    pub(crate) fn from_immutable(request: &ImmutableToolRequest) -> Result<Self, PortError> {
        let process = request.request().process().clone();
        let request_binding_digest = canonical_tool_request_binding(&process)?;
        Ok(Self {
            execution_id: request.request().execution_id().clone(),
            request: process,
            request_binding_digest,
            approval: None,
            authority: None,
        })
    }

    #[cfg(test)]
    pub(crate) fn revalidated_operation_digest(&self) -> Result<Sha256Digest, PortError> {
        if let Some(approval) = &self.approval {
            let rebound = bind_process_request(approval.payload.clone(), &self.request)?;
            if rebound != approval.payload {
                return Err(invalid_input());
            }
            return canonical_approval_payload(&ApprovalDigestPayload::Tool(rebound))
                .map(|canonical| canonical.operation_digest);
        }
        canonical_tool_request_binding(&self.request).map(|binding| binding.as_sha256().clone())
    }

    pub fn process_request(&self) -> &ApprovedProcessRequest {
        &self.request
    }

    pub fn into_process_request(self) -> ApprovedProcessRequest {
        self.request
    }

    pub(crate) fn with_authority(mut self, authority: ToolExecutionClaimAuthority) -> Self {
        self.authority = Some(authority);
        self
    }

    pub const fn authority(&self) -> Option<&ToolExecutionClaimAuthority> {
        self.authority.as_ref()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolExecutionResult {
    pub receipt: ProcessReceipt,
    pub artifacts: ToolExecutionArtifactEvidence,
}
