use local_agent_terminal_domain::{
    CapabilityRef, FencingToken, ProcessToolRequest, Sha256Digest, TaskId, WorkspaceVersion,
};

use crate::PortError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapabilityRequest {
    pub task_id: TaskId,
    pub capability: CapabilityRef,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedCapability {
    pub capability: CapabilityRef,
    pub content_digest: Option<Sha256Digest>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizedFileRead {
    pub task_id: TaskId,
    pub capability: CapabilityRef,
    pub expected_digest: Option<Sha256Digest>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizedFileWrite {
    pub task_id: TaskId,
    pub capability: CapabilityRef,
    pub expected_digest: Option<Sha256Digest>,
    pub bytes: Vec<u8>,
    pub fencing_token: FencingToken,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedBytes {
    pub digest: Sha256Digest,
    pub bytes: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedWrite {
    pub digest: Sha256Digest,
    pub workspace_version: WorkspaceVersion,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizedGitStatus {
    pub task_id: TaskId,
    pub worktree: CapabilityRef,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizedGitDiff {
    pub task_id: TaskId,
    pub worktree: CapabilityRef,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitStatusResult {
    pub digest: Sha256Digest,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitDiffResult {
    pub digest: Sha256Digest,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizedProcessRequest {
    pub process: ProcessToolRequest,
    pub expected_reads: Vec<CapabilityRef>,
    pub memory_limit_bytes: Option<u64>,
    pub cpu_time_limit_ms: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessReceipt {
    pub execution_id: ToolExecutionId,
    pub exit_code: Option<i32>,
    pub output_digest: Sha256Digest,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CancellationReceipt {
    pub execution_id: ToolExecutionId,
    pub cancelled: bool,
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
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolExecutionCompletion {
    pub execution_id: ToolExecutionId,
    pub receipt: ProcessReceipt,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolExecutionSnapshot {
    pub execution_id: ToolExecutionId,
    pub completed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizedToolRequest {
    pub execution_id: ToolExecutionId,
    pub operation_digest: Sha256Digest,
    pub request: AuthorizedProcessRequest,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolExecutionResult {
    pub receipt: ProcessReceipt,
}

pub trait CapabilityResolver: Send + Sync {
    fn resolve(&self, request: CapabilityRequest) -> Result<ResolvedCapability, PortError>;
}

pub trait CapabilityFilesystem: Send + Sync {
    fn read(&self, request: AuthorizedFileRead) -> Result<VerifiedBytes, PortError>;
    fn write(&self, request: AuthorizedFileWrite) -> Result<VerifiedWrite, PortError>;
}

pub trait StructuredGit: Send + Sync {
    fn status(&self, request: AuthorizedGitStatus) -> Result<GitStatusResult, PortError>;
    fn diff(&self, request: AuthorizedGitDiff) -> Result<GitDiffResult, PortError>;
}

pub trait ProcessLauncher: Send + Sync {
    fn execute(&self, request: AuthorizedProcessRequest) -> Result<ProcessReceipt, PortError>;
    fn cancel(&self, execution_id: &ToolExecutionId) -> Result<CancellationReceipt, PortError>;
}

pub trait ToolExecutionStore: Send + Sync {
    fn reserve(&self, request: NewToolIntent) -> Result<OperationIntentSnapshot, PortError>;
    fn begin(&self, request: NewToolExecution) -> Result<ToolExecutionSnapshot, PortError>;
    fn finish(
        &self,
        completion: ToolExecutionCompletion,
    ) -> Result<ToolExecutionSnapshot, PortError>;
    fn incomplete(&self) -> Result<Vec<ToolExecutionSnapshot>, PortError>;
}

pub trait StructuredToolExecutor: Send + Sync {
    fn execute(&self, request: AuthorizedToolRequest) -> Result<ToolExecutionResult, PortError>;
    fn cancel(&self, execution_id: &ToolExecutionId) -> Result<CancellationReceipt, PortError>;
}
