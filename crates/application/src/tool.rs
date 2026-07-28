use local_agent_terminal_domain::{
    CapabilityRef, FencingToken, GitObjectId, LeaseClaim, NetworkProfile, ProcessToolRequest,
    ProcessTrustTier, RepositoryId, Sha256Digest, TaskId,
};
use serde_json::{json, Value};

use crate::approval::{canonical_approval_payload, ApprovalDigestPayload, ToolApprovalPayloadV1};
use crate::canonical_json::{invalid_input, sha256_digest};
use crate::{PortError, WorkspaceMutationRequest};

const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapabilityRequest {
    pub task_id: TaskId,
    pub capability: CapabilityRef,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedCapability {
    pub capability: CapabilityRef,
    pub content_digest: Option<Sha256Digest>,
    pub root_identity: CapabilityRootIdentity,
    pub relative_components: RelativePathComponents,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapabilityRootIdentity(String);

impl CapabilityRootIdentity {
    pub fn new(value: impl Into<String>) -> Result<Self, PortError> {
        let value = value.into();
        if value.trim().is_empty() || value.len() > 256 || value.contains(['\0', '/', '\\', ':']) {
            return Err(invalid_input());
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelativePathComponents(Vec<String>);

impl RelativePathComponents {
    pub fn new(components: Vec<String>) -> Result<Self, PortError> {
        if components.is_empty()
            || components
                .iter()
                .any(|component| !valid_path_component(component))
        {
            return Err(invalid_input());
        }
        Ok(Self(components))
    }

    pub fn as_slice(&self) -> &[String] {
        &self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileReadRequest {
    pub task_id: TaskId,
    pub capability: CapabilityRef,
    pub expected_digest: Option<Sha256Digest>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizedFileRead {
    pub task_id: TaskId,
    pub root_identity: CapabilityRootIdentity,
    pub relative_components: RelativePathComponents,
    pub expected_digest: Option<Sha256Digest>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileWriteRequest {
    pub task_id: TaskId,
    pub capability: CapabilityRef,
    pub expected_digest: Option<Sha256Digest>,
    pub bytes: Vec<u8>,
    pub fencing_token: FencingToken,
    pub lease_claim: LeaseClaim,
    pub workspace_mutation: WorkspaceMutationRequest,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizedFileWrite {
    pub task_id: TaskId,
    pub root_identity: CapabilityRootIdentity,
    pub relative_components: RelativePathComponents,
    pub expected_digest: Option<Sha256Digest>,
    pub bytes: Vec<u8>,
    pub fencing_token: FencingToken,
    pub lease_claim: LeaseClaim,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedBytes {
    pub digest: Sha256Digest,
    pub bytes: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedWrite {
    pub digest: Sha256Digest,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizedGitStatus {
    pub task_id: TaskId,
    pub worktree: CapabilityRef,
    pub policy_decision_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizedGitDiff {
    pub task_id: TaskId,
    pub worktree: CapabilityRef,
    pub policy_decision_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitStatusResult {
    pub digest: Sha256Digest,
    pub repository_id: RepositoryId,
    pub revision: GitObjectId,
    pub path_scope: CapabilityRef,
    pub truncated: bool,
    pub policy_decision_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitDiffResult {
    pub digest: Sha256Digest,
    pub repository_id: RepositoryId,
    pub revision: GitObjectId,
    pub path_scope: CapabilityRef,
    pub truncated: bool,
    pub policy_decision_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizedProcessRequest {
    pub process: ProcessToolRequest,
    pub expected_reads: Vec<CapabilityRef>,
    pub memory_limit_bytes: Option<u64>,
    pub cpu_time_limit_ms: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolRequestBindingDigest(Sha256Digest);

impl ToolRequestBindingDigest {
    pub const fn as_sha256(&self) -> &Sha256Digest {
        &self.0
    }

    /// Restores a syntactically validated digest loaded from authoritative persistence.
    ///
    /// Construction does not authorize a request; callers must still compare every
    /// persisted binding during the atomic approval claim.
    #[must_use]
    pub const fn from_persisted(digest: Sha256Digest) -> Self {
        Self(digest)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoundToolApproval {
    payload: ToolApprovalPayloadV1,
    request_binding_digest: ToolRequestBindingDigest,
}

impl BoundToolApproval {
    pub const fn payload(&self) -> &ToolApprovalPayloadV1 {
        &self.payload
    }

    pub const fn request_binding_digest(&self) -> &ToolRequestBindingDigest {
        &self.request_binding_digest
    }
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
    request: AuthorizedProcessRequest,
    approval: BoundToolApproval,
}

impl AuthorizedToolRequest {
    pub fn new(
        execution_id: ToolExecutionId,
        approval: BoundToolApproval,
        request: AuthorizedProcessRequest,
    ) -> Self {
        Self {
            execution_id,
            request,
            approval,
        }
    }

    pub(crate) fn revalidated_operation_digest(&self) -> Result<Sha256Digest, PortError> {
        let rebound = bind_process_request(self.approval.payload.clone(), &self.request)?;
        if rebound != self.approval.payload {
            return Err(invalid_input());
        }
        canonical_approval_payload(&ApprovalDigestPayload::Tool(rebound))
            .map(|canonical| canonical.operation_digest)
    }

    pub(crate) fn revalidated_request_binding_digest(
        &self,
    ) -> Result<&ToolRequestBindingDigest, PortError> {
        let current = canonical_tool_request_binding(&self.request)?;
        if current != self.approval.request_binding_digest {
            return Err(invalid_input());
        }
        Ok(&self.approval.request_binding_digest)
    }

    pub(crate) fn approval_nonce(&self) -> &str {
        &self.approval.payload.nonce
    }

    pub fn process_request(&self) -> &AuthorizedProcessRequest {
        &self.request
    }

    pub fn into_process_request(self) -> AuthorizedProcessRequest {
        self.request
    }
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
    fn file_read(&self, request: FileReadRequest) -> Result<VerifiedBytes, PortError>;
    fn file_write(&self, request: FileWriteRequest) -> Result<VerifiedWrite, PortError>;
    fn git_status(&self, request: AuthorizedGitStatus) -> Result<GitStatusResult, PortError>;
    fn git_diff(&self, request: AuthorizedGitDiff) -> Result<GitDiffResult, PortError>;
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

pub fn bind_tool_approval_payload(
    payload: ToolApprovalPayloadV1,
    request: &AuthorizedProcessRequest,
) -> Result<BoundToolApproval, PortError> {
    let payload = bind_process_request(payload, request)?;
    canonical_approval_payload(&ApprovalDigestPayload::Tool(payload.clone()))?;
    Ok(BoundToolApproval {
        payload,
        request_binding_digest: canonical_tool_request_binding(request)?,
    })
}

fn bind_process_request(
    mut payload: ToolApprovalPayloadV1,
    request: &AuthorizedProcessRequest,
) -> Result<ToolApprovalPayloadV1, PortError> {
    let process = &request.process;
    let binding = process.binding();
    payload.task_id = binding.task_id().as_str().to_owned();
    payload.operation.run_id = binding.run_id().as_str().to_owned();
    payload.operation.plan_step_id = binding.plan_step_id().as_str().to_owned();
    payload.operation.tool = "process.exec".to_owned();
    payload.operation.arguments_digest = canonical_process_arguments_digest(process)?.to_string();
    payload.operation.cwd_capability = logical_capability(process.cwd());
    payload.operation.environment_profile_digest =
        binding.environment_profile().digest().as_str().to_owned();
    payload.operation.network_profile = network_profile(process.network()).to_owned();
    payload.operation.expected_writes = process
        .expected_writes()
        .iter()
        .map(|write| logical_capability(write.capability()))
        .collect();
    payload.operation.executor_fencing_token =
        process.executor_fencing_token().map(FencingToken::get);
    payload.workspace_version = binding.workspace_version().get();
    Ok(payload)
}

fn canonical_process_arguments_digest(
    request: &ProcessToolRequest,
) -> Result<Sha256Digest, PortError> {
    let value = json!({
        "schema": "process-argv.v1",
        "argv": request.argv(),
    });
    let canonical_bytes = serde_json_canonicalizer::to_vec(&value).map_err(|_| invalid_input())?;
    Sha256Digest::new(sha256_digest(&canonical_bytes)).map_err(|_| invalid_input())
}

fn canonical_tool_request_binding(
    request: &AuthorizedProcessRequest,
) -> Result<ToolRequestBindingDigest, PortError> {
    validate_safe_integer_fields(request)?;
    let process = &request.process;
    let binding = process.binding();
    let value = json!({
        "schema": "authorized-process-request.v1",
        "taskId": binding.task_id().as_str(),
        "runId": binding.run_id().as_str(),
        "planStepId": binding.plan_step_id().as_str(),
        "workflowPhase": binding.workflow_phase().as_str(),
        "workspaceVersion": binding.workspace_version().get(),
        "environmentProfile": {
            "name": binding.environment_profile().name(),
            "digest": binding.environment_profile().digest().as_str(),
        },
        "timeoutMs": binding.timeout_ms(),
        "executable": capability_value(process.executable()),
        "argv": process.argv(),
        "cwd": capability_value(process.cwd()),
        "trustTier": trust_tier(process.trust_tier()),
        "networkProfile": network_profile(process.network()),
        "expectedReads": request
            .expected_reads
            .iter()
            .map(capability_value)
            .collect::<Vec<_>>(),
        "expectedWrites": process
            .expected_writes()
            .iter()
            .map(|write| capability_value(write.capability()))
            .collect::<Vec<_>>(),
        "memoryLimitBytes": request.memory_limit_bytes,
        "cpuTimeLimitMs": request.cpu_time_limit_ms,
        "executorFencingToken": process.executor_fencing_token().map(FencingToken::get),
    });
    let canonical_bytes = serde_json_canonicalizer::to_vec(&value).map_err(|_| invalid_input())?;
    Sha256Digest::new(sha256_digest(&canonical_bytes))
        .map(ToolRequestBindingDigest)
        .map_err(|_| invalid_input())
}

fn validate_safe_integer_fields(request: &AuthorizedProcessRequest) -> Result<(), PortError> {
    let process = &request.process;
    let binding = process.binding();
    let unsafe_integer = [
        binding.workspace_version().get(),
        binding.timeout_ms(),
        process
            .executor_fencing_token()
            .map(FencingToken::get)
            .unwrap_or_default(),
        request.memory_limit_bytes.unwrap_or_default(),
        request.cpu_time_limit_ms.unwrap_or_default(),
    ]
    .into_iter()
    .any(|value| value > MAX_SAFE_INTEGER);
    if unsafe_integer {
        return Err(invalid_input());
    }
    Ok(())
}

fn capability_value(capability: &CapabilityRef) -> Value {
    match capability {
        CapabilityRef::Source(value) => {
            json!({"kind": "source", "revision": value.revision(), "path": value.path()})
        }
        CapabilityRef::Artifact(value) => {
            json!({"kind": "artifact", "artifactId": value.artifact_id().as_str()})
        }
        CapabilityRef::Worktree(value) => {
            json!({"kind": "worktree", "taskId": value.task_id().as_str(), "path": value.path()})
        }
        CapabilityRef::Toolchain(value) => {
            json!({"kind": "toolchain", "name": value.name()})
        }
    }
}

fn logical_capability(capability: &CapabilityRef) -> String {
    match capability {
        CapabilityRef::Source(value) => {
            format!("source:{}:{}", value.revision(), value.path())
        }
        CapabilityRef::Artifact(value) => format!("artifact:{}", value.artifact_id().as_str()),
        CapabilityRef::Worktree(value) if value.path() == "." => {
            format!("worktree:{}", value.task_id().as_str())
        }
        CapabilityRef::Worktree(value) => {
            format!("worktree:{}:{}", value.task_id().as_str(), value.path())
        }
        CapabilityRef::Toolchain(value) => format!("toolchain:{}", value.name()),
    }
}

const fn trust_tier(value: ProcessTrustTier) -> &'static str {
    match value {
        ProcessTrustTier::BrokeredProcess => "brokered_process",
        ProcessTrustTier::IsolatedWorker => "isolated_worker",
    }
}

const fn network_profile(value: NetworkProfile) -> &'static str {
    match value {
        NetworkProfile::Denied => "denied",
        NetworkProfile::ProviderEndpointOnly => "provider_endpoint_only",
        NetworkProfile::ApprovedDestinations => "approved_destinations",
    }
}
