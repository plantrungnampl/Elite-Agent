use std::collections::BTreeMap;
use std::path::{Component, Path, PathBuf};
use std::str::FromStr;

#[cfg(windows)]
use std::path::Prefix;

use local_agent_terminal_domain::{
    ActorId, ActorLocality, ArtifactId, CapabilityRef, EnvironmentProfile, ExpectedWrite,
    FencingToken, GitObjectId, LeaseClaim, NetworkProfile, Phase, PlanStepId, PolicyAction,
    PolicyActor, PolicyEffect, PolicyRequest, PolicyResource, ProcessBinding, ProcessInvocation,
    ProcessToolRequest, ProcessTrustTier, ProjectId, RepositoryId, ResourceClass, RunId, Sequence,
    Sha256Digest, TaskId, TaskRisk, Timestamp, TrustTier, WorkspaceFingerprint, WorkspaceVersion,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::approval::{
    canonical_approval_payload, ApprovalDigestPayload, ApprovalId, ToolApprovalOperationV1,
    ToolApprovalPayloadV1, ToolApprovalRequest,
};
use crate::canonical_json::{invalid_input, sha256_digest};
use crate::{
    PolicyDecisionId, PolicyRequestBindingDigest, PortError, Retryability, SafeErrorClassification,
};

const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;
const MAX_PROCESS_WRITE_SCOPES: usize = 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutableFileIdentity(String);

impl ExecutableFileIdentity {
    pub fn new(value: impl Into<String>) -> Result<Self, PortError> {
        let value = value.into();
        if value.trim().is_empty() || value.len() > 256 || value.contains('\0') {
            return Err(invalid_input());
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedExecutable {
    pub canonical_path: PathBuf,
    pub sha256: Sha256Digest,
    pub file_identity: ExecutableFileIdentity,
    pub toolchain_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovedExecutableIdentity {
    executable: ResolvedExecutable,
    version: String,
}

impl ApprovedExecutableIdentity {
    pub fn new(
        executable: ResolvedExecutable,
        version: impl Into<String>,
    ) -> Result<Self, PortError> {
        let version = version.into();
        if !valid_registration_name(&executable.toolchain_id)
            || !valid_registration_name(&version)
            || !valid_canonical_executable_path(&executable.canonical_path)
        {
            return Err(invalid_input());
        }
        Ok(Self {
            executable,
            version,
        })
    }

    pub const fn executable(&self) -> &ResolvedExecutable {
        &self.executable
    }

    pub fn version(&self) -> &str {
        &self.version
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirectoryFileIdentity(String);

impl DirectoryFileIdentity {
    pub fn new(value: impl Into<String>) -> Result<Self, PortError> {
        let value = value.into();
        if value.trim().is_empty() || value.len() > 256 || value.contains('\0') {
            return Err(invalid_input());
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedPrivateRuntimeDirectory {
    pub canonical_path: PathBuf,
    pub file_identity: DirectoryFileIdentity,
    pub registration_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedEnvironmentProfile {
    pub name: String,
    pub values: BTreeMap<String, String>,
    pub digest: Sha256Digest,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkEnforcementReceipt {
    enforcement_id: String,
    profile_digest: Sha256Digest,
}

impl NetworkEnforcementReceipt {
    pub fn new(
        enforcement_id: impl Into<String>,
        profile_digest: Sha256Digest,
    ) -> Result<Self, PortError> {
        let enforcement_id = enforcement_id.into();
        if enforcement_id.trim().is_empty()
            || enforcement_id.len() > 256
            || enforcement_id.contains(['\0', '\r', '\n'])
        {
            return Err(invalid_input());
        }
        Ok(Self {
            enforcement_id,
            profile_digest,
        })
    }

    pub fn enforcement_id(&self) -> &str {
        &self.enforcement_id
    }

    pub const fn profile_digest(&self) -> &Sha256Digest {
        &self.profile_digest
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnforcedNetworkProfile {
    pub profile: NetworkProfile,
    pub profile_digest: Sha256Digest,
    pub receipt: NetworkEnforcementReceipt,
}

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
    pub target: ResolvedCapabilityTarget,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResolvedCapabilityTarget {
    Root,
    Relative(RelativePathComponents),
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
    pub execution_id: ToolExecutionId,
    pub task_id: TaskId,
    pub capability: CapabilityRef,
    pub expected_digest: Option<Sha256Digest>,
    pub bytes: Vec<u8>,
    pub lease_claim: LeaseClaim,
    pub policy: FileWritePolicyBinding,
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
    pub size_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenFileWriteSession {
    execution_id: ToolExecutionId,
    task_id: TaskId,
    root_identity: CapabilityRootIdentity,
    relative_components: RelativePathComponents,
    expected_pre_digest: Option<Sha256Digest>,
    lease_claim: LeaseClaim,
}

impl OpenFileWriteSession {
    pub fn new(
        execution_id: ToolExecutionId,
        task_id: TaskId,
        root_identity: CapabilityRootIdentity,
        relative_components: RelativePathComponents,
        expected_pre_digest: Option<Sha256Digest>,
        lease_claim: LeaseClaim,
    ) -> Result<Self, PortError> {
        if lease_claim.task_id() != &task_id {
            return Err(invalid_input());
        }
        Ok(Self {
            execution_id,
            task_id,
            root_identity,
            relative_components,
            expected_pre_digest,
            lease_claim,
        })
    }

    pub const fn execution_id(&self) -> &ToolExecutionId {
        &self.execution_id
    }

    pub const fn task_id(&self) -> &TaskId {
        &self.task_id
    }

    pub const fn root_identity(&self) -> &CapabilityRootIdentity {
        &self.root_identity
    }

    pub fn relative_components(&self) -> &RelativePathComponents {
        &self.relative_components
    }

    pub const fn expected_pre_digest(&self) -> Option<&Sha256Digest> {
        self.expected_pre_digest.as_ref()
    }

    pub const fn lease_claim(&self) -> &LeaseClaim {
        &self.lease_claim
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObservedFileImage {
    present: Option<VerifiedBytes>,
}

impl ObservedFileImage {
    pub const fn absent() -> Self {
        Self { present: None }
    }

    pub fn present(bytes: Vec<u8>) -> Self {
        let digest = Sha256Digest::new(sha256_digest(&bytes))
            .expect("SHA-256 formatting is valid for observed file bytes");
        Self {
            present: Some(VerifiedBytes { digest, bytes }),
        }
    }

    pub const fn present_bytes(&self) -> Option<&VerifiedBytes> {
        self.present.as_ref()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileWritePostExpectation {
    digest: Sha256Digest,
    size_bytes: u64,
}

impl FileWritePostExpectation {
    pub fn new(digest: Sha256Digest, size_bytes: u64) -> Result<Self, PortError> {
        if size_bytes > MAX_SAFE_INTEGER {
            return Err(invalid_input());
        }
        Ok(Self { digest, size_bytes })
    }

    pub const fn digest(&self) -> &Sha256Digest {
        &self.digest
    }

    pub const fn size_bytes(&self) -> u64 {
        self.size_bytes
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifiedFileWriteCompensation {
    Absent,
    Restored(VerifiedWrite),
}

pub trait CapabilityFileWriteSession: Send {
    fn pre_image(&self) -> &ObservedFileImage;
    fn apply(&mut self, bytes: &[u8]) -> Result<(), PortError>;
    fn verify_post_image(
        &mut self,
        expected: &FileWritePostExpectation,
    ) -> Result<VerifiedWrite, PortError>;
    fn restore_pre_image_and_verify(&mut self) -> Result<VerifiedFileWriteCompensation, PortError>;
}

pub trait CapabilityFileWriteSessionFactory: Send + Sync {
    fn open(
        &self,
        request: OpenFileWriteSession,
    ) -> Result<Box<dyn CapabilityFileWriteSession>, PortError>;
    fn observe_recovery_target(
        &self,
        request: &FileWriteRecoveryRequest,
    ) -> Result<ObservedFileImage, PortError>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaptureFileWritePreEvidence {
    session: OpenFileWriteSession,
    expected_post: FileWritePostExpectation,
    pre_image: ObservedFileImage,
}

impl CaptureFileWritePreEvidence {
    pub fn new(
        session: OpenFileWriteSession,
        expected_post: FileWritePostExpectation,
        pre_image: ObservedFileImage,
    ) -> Result<Self, PortError> {
        if let Some(expected) = session.expected_pre_digest() {
            let Some(observed) = pre_image.present_bytes() else {
                return Err(invalid_input());
            };
            if &observed.digest != expected {
                return Err(invalid_input());
            }
        }
        Ok(Self {
            session,
            expected_post,
            pre_image,
        })
    }

    pub const fn session(&self) -> &OpenFileWriteSession {
        &self.session
    }

    pub const fn expected_post(&self) -> &FileWritePostExpectation {
        &self.expected_post
    }

    pub const fn pre_image(&self) -> &ObservedFileImage {
        &self.pre_image
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitStatusRequest {
    pub task_id: TaskId,
    pub worktree: CapabilityRef,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitDiffRequest {
    pub task_id: TaskId,
    pub worktree: CapabilityRef,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizedGitStatus {
    pub task_id: TaskId,
    pub worktree: CapabilityRef,
    pub root_identity: CapabilityRootIdentity,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizedGitDiff {
    pub task_id: TaskId,
    pub worktree: CapabilityRef,
    pub root_identity: CapabilityRootIdentity,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawGitStatusResult {
    pub digest: Sha256Digest,
    pub bytes: Vec<u8>,
    pub repository_id: RepositoryId,
    pub revision: GitObjectId,
    pub path_scope: CapabilityRef,
    pub truncated: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawGitDiffResult {
    pub digest: Sha256Digest,
    pub bytes: Vec<u8>,
    pub repository_id: RepositoryId,
    pub revision: GitObjectId,
    pub path_scope: CapabilityRef,
    pub truncated: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitStatusResult {
    pub disclosure: crate::PolicyBoundBytes,
    pub repository_id: RepositoryId,
    pub revision: GitObjectId,
    pub path_scope: CapabilityRef,
    pub truncated: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitDiffResult {
    pub disclosure: crate::PolicyBoundBytes,
    pub repository_id: RepositoryId,
    pub revision: GitObjectId,
    pub path_scope: CapabilityRef,
    pub truncated: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovedProcessRequest {
    approved_executable: ApprovedExecutableIdentity,
    process: ProcessToolRequest,
    expected_reads: Vec<CapabilityRef>,
    memory_limit_bytes: Option<u64>,
    cpu_time_limit_ms: Option<u64>,
}

impl ApprovedProcessRequest {
    pub fn new(
        approved_executable: ApprovedExecutableIdentity,
        process: ProcessToolRequest,
        expected_reads: Vec<CapabilityRef>,
        memory_limit_bytes: Option<u64>,
        cpu_time_limit_ms: Option<u64>,
    ) -> Result<Self, PortError> {
        let request = Self {
            approved_executable,
            process,
            expected_reads,
            memory_limit_bytes,
            cpu_time_limit_ms,
        };
        validate_approved_process_request(&request)?;
        Ok(request)
    }

    pub const fn approved_executable(&self) -> &ApprovedExecutableIdentity {
        &self.approved_executable
    }

    pub const fn process(&self) -> &ProcessToolRequest {
        &self.process
    }

    pub fn expected_reads(&self) -> &[CapabilityRef] {
        &self.expected_reads
    }

    pub const fn memory_limit_bytes(&self) -> Option<u64> {
        self.memory_limit_bytes
    }

    pub const fn cpu_time_limit_ms(&self) -> Option<u64> {
        self.cpu_time_limit_ms
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolPolicyContext {
    actor: PolicyActor,
    action: PolicyAction,
    resource: PolicyResource,
    task_risk: TaskRisk,
    purpose: String,
    policy_snapshot_digest: Sha256Digest,
}

impl ToolPolicyContext {
    pub fn new(
        actor: PolicyActor,
        action: PolicyAction,
        resource: PolicyResource,
        task_risk: TaskRisk,
        purpose: impl Into<String>,
        policy_snapshot_digest: Sha256Digest,
    ) -> Result<Self, PortError> {
        let purpose = purpose.into();
        if !valid_text(&actor.connection_id, 256)
            || !valid_text(&actor.agent_id, 256)
            || !valid_text(&purpose, 65_536)
        {
            return Err(invalid_input());
        }
        Ok(Self {
            actor,
            action,
            resource,
            task_risk,
            purpose,
            policy_snapshot_digest,
        })
    }

    pub const fn actor(&self) -> &PolicyActor {
        &self.actor
    }

    pub const fn action(&self) -> &PolicyAction {
        &self.action
    }

    pub const fn resource(&self) -> &PolicyResource {
        &self.resource
    }

    pub const fn task_risk(&self) -> TaskRisk {
        self.task_risk
    }

    pub fn purpose(&self) -> &str {
        &self.purpose
    }

    pub const fn policy_snapshot_digest(&self) -> &Sha256Digest {
        &self.policy_snapshot_digest
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolRequest {
    execution_id: ToolExecutionId,
    process: ApprovedProcessRequest,
    policy: ToolPolicyContext,
}

impl ToolRequest {
    pub fn new(
        execution_id: ToolExecutionId,
        process: ApprovedProcessRequest,
        policy: ToolPolicyContext,
    ) -> Result<Self, PortError> {
        let task_id = process.process().binding().task_id();
        if policy.resource().capability.worktree_task_id() != Some(task_id) {
            return Err(invalid_input());
        }
        Ok(Self {
            execution_id,
            process,
            policy,
        })
    }

    pub const fn execution_id(&self) -> &ToolExecutionId {
        &self.execution_id
    }

    pub const fn process(&self) -> &ApprovedProcessRequest {
        &self.process
    }

    pub const fn policy(&self) -> &ToolPolicyContext {
        &self.policy
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImmutableToolRequest {
    request: ToolRequest,
    canonical_bytes: Vec<u8>,
    binding_digest: ToolRequestBindingDigest,
}

impl ImmutableToolRequest {
    pub const fn request(&self) -> &ToolRequest {
        &self.request
    }

    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical_bytes
    }

    pub const fn binding_digest(&self) -> &ToolRequestBindingDigest {
        &self.binding_digest
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizedExpectedWrite {
    capability: CapabilityRef,
    root_identity: CapabilityRootIdentity,
    target: ResolvedCapabilityTarget,
}

impl AuthorizedExpectedWrite {
    pub fn new(
        task_id: &TaskId,
        expected: &ExpectedWrite,
        resolved: ResolvedCapability,
    ) -> Result<Self, PortError> {
        let expected_target = expected_write_target(expected)?;
        if expected.capability() != &resolved.capability
            || expected.capability().worktree_task_id() != Some(task_id)
            || resolved.capability.worktree_task_id() != Some(task_id)
            || resolved.target != expected_target
        {
            return Err(invalid_input());
        }
        Ok(Self {
            capability: resolved.capability,
            root_identity: resolved.root_identity,
            target: resolved.target,
        })
    }

    pub const fn capability(&self) -> &CapabilityRef {
        &self.capability
    }

    pub const fn root_identity(&self) -> &CapabilityRootIdentity {
        &self.root_identity
    }

    pub const fn target(&self) -> &ResolvedCapabilityTarget {
        &self.target
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObservedProcessWrite {
    capability: CapabilityRef,
    root_identity: CapabilityRootIdentity,
    target: ResolvedCapabilityTarget,
    write: VerifiedWrite,
}

impl ObservedProcessWrite {
    pub const fn new(
        capability: CapabilityRef,
        root_identity: CapabilityRootIdentity,
        target: ResolvedCapabilityTarget,
        write: VerifiedWrite,
    ) -> Self {
        Self {
            capability,
            root_identity,
            target,
            write,
        }
    }

    pub const fn capability(&self) -> &CapabilityRef {
        &self.capability
    }

    pub const fn root_identity(&self) -> &CapabilityRootIdentity {
        &self.root_identity
    }

    pub const fn target(&self) -> &ResolvedCapabilityTarget {
        &self.target
    }

    pub const fn write(&self) -> &VerifiedWrite {
        &self.write
    }
}

/// Validates process write evidence as an exact set and returns it in approval order.
pub fn validate_and_order_process_writes(
    approved: &[AuthorizedExpectedWrite],
    observed: Vec<ObservedProcessWrite>,
) -> Result<Vec<ObservedProcessWrite>, PortError> {
    if approved.len() > MAX_PROCESS_WRITE_SCOPES
        || approved.len() != observed.len()
        || has_duplicate_approved_scope(approved)
        || has_duplicate_observed_scope(&observed)
    {
        return Err(process_write_integrity_failure());
    }
    let mut remaining = observed;
    let ordered = approved
        .iter()
        .map(|scope| {
            let index = remaining
                .iter()
                .position(|observation| observed_scope_matches(scope, observation))
                .ok_or_else(process_write_integrity_failure)?;
            Ok(remaining.remove(index))
        })
        .collect::<Result<Vec<_>, _>>()?;
    if !remaining.is_empty() {
        return Err(process_write_integrity_failure());
    }
    Ok(ordered)
}

fn has_duplicate_approved_scope(approved: &[AuthorizedExpectedWrite]) -> bool {
    approved.iter().enumerate().any(|(index, scope)| {
        approved[..index].iter().any(|prior| {
            prior.root_identity() == scope.root_identity() && prior.target() == scope.target()
        })
    })
}

fn has_duplicate_observed_scope(observed: &[ObservedProcessWrite]) -> bool {
    observed.iter().enumerate().any(|(index, candidate)| {
        observed[..index]
            .iter()
            .any(|prior| same_observed_scope(prior, candidate))
    })
}

fn same_observed_scope(left: &ObservedProcessWrite, right: &ObservedProcessWrite) -> bool {
    left.root_identity() == right.root_identity() && left.target() == right.target()
}

fn observed_scope_matches(
    approved: &AuthorizedExpectedWrite,
    observed: &ObservedProcessWrite,
) -> bool {
    observed.capability() == approved.capability()
        && observed.root_identity() == approved.root_identity()
        && observed.target() == approved.target()
}

fn process_write_integrity_failure() -> PortError {
    PortError::failure(
        SafeErrorClassification::IntegrityFailure,
        Retryability::NonRetryable,
    )
}

fn expected_write_target(expected: &ExpectedWrite) -> Result<ResolvedCapabilityTarget, PortError> {
    let CapabilityRef::Worktree(worktree) = expected.capability() else {
        return Err(invalid_input());
    };
    if worktree.path() == "." {
        return Ok(ResolvedCapabilityTarget::Root);
    }
    RelativePathComponents::new(
        worktree
            .path()
            .split(['/', '\\'])
            .map(str::to_owned)
            .collect(),
    )
    .map(ResolvedCapabilityTarget::Relative)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProcessWorkingDirectory {
    PrivateRuntime(ResolvedPrivateRuntimeDirectory),
    IsolatedWorktree(ResolvedCapability),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessLimits {
    pub memory_limit_bytes: u64,
    pub cpu_time_limit_ms: u64,
    pub max_stdout_bytes: u64,
    pub max_stderr_bytes: u64,
    pub max_active_processes: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizedProcessRequest {
    pub execution_id: ToolExecutionId,
    pub trust_tier: ProcessTrustTier,
    pub executable: ResolvedExecutable,
    pub argv: Vec<String>,
    pub cwd: ProcessWorkingDirectory,
    pub environment: ResolvedEnvironmentProfile,
    pub network: EnforcedNetworkProfile,
    pub timeout_ms: u64,
    pub limits: ProcessLimits,
    pub expected_writes: Vec<AuthorizedExpectedWrite>,
    pub executor_claim: LeaseClaim,
    pub executor_fence: crate::workspace::ProcessFenceBinding,
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
    Indeterminate(SafeToolExecutionError),
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
            state: ToolExecutionTerminalState::Indeterminate(error),
        }
    }

    pub const fn kind(&self) -> ToolExecutionTerminalKind {
        match self.state {
            ToolExecutionTerminalState::Succeeded(_) => ToolExecutionTerminalKind::Succeeded,
            ToolExecutionTerminalState::Failed(_) => ToolExecutionTerminalKind::Failed,
            ToolExecutionTerminalState::Cancelled => ToolExecutionTerminalKind::Cancelled,
            ToolExecutionTerminalState::Terminated(_) => ToolExecutionTerminalKind::Terminated,
            ToolExecutionTerminalState::Interrupted => ToolExecutionTerminalKind::Interrupted,
            ToolExecutionTerminalState::Indeterminate(_) => {
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
            | ToolExecutionTerminalState::Indeterminate(_) => None,
        }
    }

    pub const fn error(&self) -> Option<&SafeToolExecutionError> {
        match &self.state {
            ToolExecutionTerminalState::Indeterminate(error) => Some(error),
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
}

impl DurableToolExecutionReceipt {
    pub fn new(authority: ToolExecutionClaimAuthority, terminal: ToolExecutionTerminal) -> Self {
        Self {
            authority,
            terminal,
        }
    }

    pub(crate) fn from_process_receipt(
        authority: ToolExecutionClaimAuthority,
        receipt: ProcessReceipt,
    ) -> Result<Self, PortError> {
        if authority.execution_id != receipt.execution_id {
            return Err(invalid_input());
        }
        let ProcessReceipt {
            status,
            exit_code,
            duration_ms,
            output_digest,
            observed_writes,
            ..
        } = receipt;
        let artifacts = DurableToolExecutionArtifacts::new(
            DurableToolExecutionArtifact::Unavailable,
            DurableToolExecutionArtifact::Unavailable,
            observed_writes
                .into_iter()
                .map(|_| DurableToolExecutionArtifact::Unavailable)
                .collect(),
        );
        let output = ToolExecutionOutput {
            exit_code,
            output_digest,
            duration_ms,
            artifacts,
        };
        ToolExecutionTerminal::from_process(status, output)
            .map(|terminal| Self::new(authority, terminal))
    }

    pub const fn authority(&self) -> &ToolExecutionClaimAuthority {
        &self.authority
    }

    pub const fn terminal(&self) -> &ToolExecutionTerminal {
        &self.terminal
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
pub struct ToolExecutionRecoveryEvidence {
    pub authority: ToolExecutionClaimAuthority,
    pub task_id: TaskId,
    pub canonical_request_artifact_id: ArtifactId,
    pub idempotency_class: crate::IdempotencyClass,
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
        })
    }

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

    pub(crate) fn revalidated_request_binding_digest(
        &self,
    ) -> Result<&ToolRequestBindingDigest, PortError> {
        let current = canonical_tool_request_binding(&self.request)?;
        if current != self.request_binding_digest {
            return Err(invalid_input());
        }
        Ok(&self.request_binding_digest)
    }

    pub(crate) fn approval_nonce(&self) -> Option<&str> {
        self.approval
            .as_ref()
            .map(|approval| approval.payload.nonce.as_str())
    }

    pub fn process_request(&self) -> &ApprovedProcessRequest {
        &self.request
    }

    pub fn into_process_request(self) -> ApprovedProcessRequest {
        self.request
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolExecutionResult {
    pub receipt: ProcessReceipt,
}

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

pub trait ProcessLauncher: Send + Sync {
    fn execute(
        &self,
        request: AuthorizedProcessRequest,
        authority: &ToolExecutionClaimAuthority,
        bindings: &dyn ProcessExecutionBindingStore,
    ) -> Result<ProcessReceipt, PortError>;
    fn cancel(&self, execution_id: &ToolExecutionId) -> Result<CancellationReceipt, PortError>;
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

pub trait ExecutableProfileResolver: Send + Sync {
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

pub trait EnvironmentProfileResolver: Send + Sync {
    fn resolve(
        &self,
        name: &str,
        expected_digest: &Sha256Digest,
    ) -> Result<ResolvedEnvironmentProfile, PortError>;
}

pub trait NetworkProfileVerifier: Send + Sync {
    fn verify(&self, profile: &EnforcedNetworkProfile) -> Result<(), PortError>;
}

pub trait ApprovedProcessExecutor: Send + Sync {
    fn execute(
        &self,
        execution_id: ToolExecutionId,
        request: ApprovedProcessRequest,
    ) -> Result<ProcessReceipt, PortError>;
    fn cancel(&self, execution_id: &ToolExecutionId) -> Result<CancellationReceipt, PortError>;
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

pub fn bind_tool_approval_payload(
    payload: ToolApprovalPayloadV1,
    request: &ApprovedProcessRequest,
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
    request: &ApprovedProcessRequest,
) -> Result<ToolApprovalPayloadV1, PortError> {
    let process = &request.process;
    let binding = process.binding();
    payload.task_id = binding.task_id().as_str().to_owned();
    payload.operation = process_approval_operation(request)?;
    payload.workspace_version = binding.workspace_version().get();
    Ok(payload)
}

pub(crate) fn process_approval_operation(
    request: &ApprovedProcessRequest,
) -> Result<ToolApprovalOperationV1, PortError> {
    let process = request.process();
    let binding = process.binding();
    let approved_executable = approved_executable_identity(request)?;
    Ok(ToolApprovalOperationV1 {
        run_id: binding.run_id().as_str().to_owned(),
        plan_step_id: binding.plan_step_id().as_str().to_owned(),
        tool: "process.exec".to_owned(),
        executable_digest: Some(approved_executable.executable().sha256.as_str().to_owned()),
        arguments_digest: canonical_process_arguments_digest(process)?.to_string(),
        script_digest: None,
        cwd_capability: logical_capability(process.cwd()),
        environment_profile_digest: binding.environment_profile().digest().as_str().to_owned(),
        network_profile: network_profile(process.network()).to_owned(),
        expected_writes: process
            .expected_writes()
            .iter()
            .map(|write| logical_capability(write.capability()))
            .collect(),
        executor_fencing_token: process.executor_fencing_token().map(FencingToken::get),
    })
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

pub fn canonical_tool_request(request: &ToolRequest) -> Result<ImmutableToolRequest, PortError> {
    let wire = RawToolRequest::from(request);
    let canonical_bytes = serde_json_canonicalizer::to_vec(&wire).map_err(|_| invalid_input())?;
    immutable_tool_request(request.clone(), canonical_bytes)
}

pub fn parse_tool_request(bytes: &[u8]) -> Result<ImmutableToolRequest, PortError> {
    let wire: RawToolRequest = serde_json::from_slice(bytes).map_err(|_| invalid_input())?;
    let request = ToolRequest::try_from(wire)?;
    let canonical = canonical_tool_request(&request)?;
    if canonical.canonical_bytes() != bytes {
        return Err(invalid_input());
    }
    Ok(canonical)
}

fn immutable_tool_request(
    request: ToolRequest,
    canonical_bytes: Vec<u8>,
) -> Result<ImmutableToolRequest, PortError> {
    let digest = Sha256Digest::new(sha256_digest(&canonical_bytes)).map_err(|_| invalid_input())?;
    Ok(ImmutableToolRequest {
        request,
        canonical_bytes,
        binding_digest: ToolRequestBindingDigest(digest),
    })
}

fn canonical_tool_request_binding(
    request: &ApprovedProcessRequest,
) -> Result<ToolRequestBindingDigest, PortError> {
    validate_approved_process_request(request)?;
    let canonical_bytes = serde_json_canonicalizer::to_vec(&RawProcessRequest::from(request))
        .map_err(|_| invalid_input())?;
    Sha256Digest::new(sha256_digest(&canonical_bytes))
        .map(ToolRequestBindingDigest)
        .map_err(|_| invalid_input())
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RawToolRequest {
    schema: String,
    execution_id: String,
    process: RawProcessRequest,
    policy: RawPolicyContext,
}

impl From<&ToolRequest> for RawToolRequest {
    fn from(request: &ToolRequest) -> Self {
        Self {
            schema: "tool-request.v1".to_owned(),
            execution_id: request.execution_id().as_str().to_owned(),
            process: RawProcessRequest::from(request.process()),
            policy: RawPolicyContext::from(request.policy()),
        }
    }
}

impl TryFrom<RawToolRequest> for ToolRequest {
    type Error = PortError;

    fn try_from(raw: RawToolRequest) -> Result<Self, Self::Error> {
        if raw.schema != "tool-request.v1" {
            return Err(invalid_input());
        }
        Self::new(
            ToolExecutionId::new(raw.execution_id)?,
            ApprovedProcessRequest::try_from(raw.process)?,
            ToolPolicyContext::try_from(raw.policy)?,
        )
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RawProcessRequest {
    schema: String,
    task_id: String,
    run_id: String,
    plan_step_id: String,
    workflow_phase: String,
    workspace_version: u64,
    environment_profile: RawEnvironmentProfile,
    timeout_ms: u64,
    executable: RawCapability,
    approved_executable: RawApprovedExecutable,
    argv: Vec<String>,
    cwd: RawCapability,
    trust_tier: String,
    network_profile: String,
    expected_reads: Vec<RawCapability>,
    expected_writes: Vec<RawCapability>,
    memory_limit_bytes: Option<u64>,
    cpu_time_limit_ms: Option<u64>,
    executor_fencing_token: Option<u64>,
}

impl From<&ApprovedProcessRequest> for RawProcessRequest {
    fn from(request: &ApprovedProcessRequest) -> Self {
        let process = request.process();
        let binding = process.binding();
        let executable = request.approved_executable();
        Self {
            schema: "authorized-process-request.v1".to_owned(),
            task_id: binding.task_id().as_str().to_owned(),
            run_id: binding.run_id().as_str().to_owned(),
            plan_step_id: binding.plan_step_id().as_str().to_owned(),
            workflow_phase: binding.workflow_phase().as_str().to_owned(),
            workspace_version: binding.workspace_version().get(),
            environment_profile: RawEnvironmentProfile {
                name: binding.environment_profile().name().to_owned(),
                digest: binding.environment_profile().digest().to_string(),
            },
            timeout_ms: binding.timeout_ms(),
            executable: RawCapability::from(process.executable()),
            approved_executable: RawApprovedExecutable::from(executable),
            argv: process.argv().to_vec(),
            cwd: RawCapability::from(process.cwd()),
            trust_tier: trust_tier(process.trust_tier()).to_owned(),
            network_profile: network_profile(process.network()).to_owned(),
            expected_reads: request
                .expected_reads()
                .iter()
                .map(RawCapability::from)
                .collect(),
            expected_writes: process
                .expected_writes()
                .iter()
                .map(|write| RawCapability::from(write.capability()))
                .collect(),
            memory_limit_bytes: request.memory_limit_bytes(),
            cpu_time_limit_ms: request.cpu_time_limit_ms(),
            executor_fencing_token: process.executor_fencing_token().map(FencingToken::get),
        }
    }
}

impl TryFrom<RawProcessRequest> for ApprovedProcessRequest {
    type Error = PortError;

    fn try_from(raw: RawProcessRequest) -> Result<Self, Self::Error> {
        if raw.schema != "authorized-process-request.v1"
            || raw.expected_writes.len() > MAX_PROCESS_WRITE_SCOPES
        {
            return Err(invalid_input());
        }
        let task_id = TaskId::new(raw.task_id).map_err(|_| invalid_input())?;
        let binding = ProcessBinding::new(
            task_id,
            RunId::new(raw.run_id).map_err(|_| invalid_input())?,
            PlanStepId::new(raw.plan_step_id).map_err(|_| invalid_input())?,
            Phase::from_str(&raw.workflow_phase).map_err(|_| invalid_input())?,
            WorkspaceVersion::new(raw.workspace_version),
            EnvironmentProfile::new(
                raw.environment_profile.name,
                Sha256Digest::new(raw.environment_profile.digest).map_err(|_| invalid_input())?,
            )
            .map_err(|_| invalid_input())?,
            raw.timeout_ms,
        )
        .map_err(|_| invalid_input())?;
        let expected_writes = raw
            .expected_writes
            .into_iter()
            .map(CapabilityRef::try_from)
            .map(|capability| {
                capability.and_then(|capability| {
                    ExpectedWrite::new(capability).map_err(|_| invalid_input())
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        let invocation = ProcessInvocation::new(
            CapabilityRef::try_from(raw.executable)?,
            raw.argv,
            CapabilityRef::try_from(raw.cwd)?,
            parse_process_trust_tier(&raw.trust_tier)?,
            parse_network_profile(&raw.network_profile)?,
            expected_writes,
            raw.executor_fencing_token
                .map(|token| FencingToken::new(token).map_err(|_| invalid_input()))
                .transpose()?,
        )
        .map_err(|_| invalid_input())?;
        let process = ProcessToolRequest::new(binding, invocation).map_err(|_| invalid_input())?;
        let expected_reads = raw
            .expected_reads
            .into_iter()
            .map(CapabilityRef::try_from)
            .collect::<Result<Vec<_>, _>>()?;
        Self::new(
            ApprovedExecutableIdentity::try_from(raw.approved_executable)?,
            process,
            expected_reads,
            raw.memory_limit_bytes,
            raw.cpu_time_limit_ms,
        )
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RawEnvironmentProfile {
    name: String,
    digest: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RawApprovedExecutable {
    toolchain_id: String,
    version: String,
    canonical_path: String,
    sha256: String,
    file_identity: String,
}

impl From<&ApprovedExecutableIdentity> for RawApprovedExecutable {
    fn from(identity: &ApprovedExecutableIdentity) -> Self {
        let executable = identity.executable();
        Self {
            toolchain_id: executable.toolchain_id.clone(),
            version: identity.version().to_owned(),
            canonical_path: executable.canonical_path.to_string_lossy().into_owned(),
            sha256: executable.sha256.to_string(),
            file_identity: executable.file_identity.as_str().to_owned(),
        }
    }
}

impl TryFrom<RawApprovedExecutable> for ApprovedExecutableIdentity {
    type Error = PortError;

    fn try_from(raw: RawApprovedExecutable) -> Result<Self, Self::Error> {
        Self::new(
            ResolvedExecutable {
                canonical_path: PathBuf::from(raw.canonical_path),
                sha256: Sha256Digest::new(raw.sha256).map_err(|_| invalid_input())?,
                file_identity: ExecutableFileIdentity::new(raw.file_identity)?,
                toolchain_id: raw.toolchain_id,
            },
            raw.version,
        )
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "lowercase",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
enum RawCapability {
    Source { revision: String, path: String },
    Artifact { artifact_id: String },
    Worktree { task_id: String, path: String },
    Toolchain { name: String },
}

impl From<&CapabilityRef> for RawCapability {
    fn from(capability: &CapabilityRef) -> Self {
        match capability {
            CapabilityRef::Source(value) => Self::Source {
                revision: value.revision().to_owned(),
                path: value.path().to_owned(),
            },
            CapabilityRef::Artifact(value) => Self::Artifact {
                artifact_id: value.artifact_id().as_str().to_owned(),
            },
            CapabilityRef::Worktree(value) => Self::Worktree {
                task_id: value.task_id().as_str().to_owned(),
                path: value.path().to_owned(),
            },
            CapabilityRef::Toolchain(value) => Self::Toolchain {
                name: value.name().to_owned(),
            },
        }
    }
}

impl TryFrom<RawCapability> for CapabilityRef {
    type Error = PortError;

    fn try_from(raw: RawCapability) -> Result<Self, Self::Error> {
        match raw {
            RawCapability::Source { revision, path } => Self::source(revision, path),
            RawCapability::Artifact { artifact_id } => {
                Self::artifact(ArtifactId::new(artifact_id).map_err(|_| invalid_input())?)
            }
            RawCapability::Worktree { task_id, path } => {
                Self::worktree(TaskId::new(task_id).map_err(|_| invalid_input())?, path)
            }
            RawCapability::Toolchain { name } => Self::toolchain(name),
        }
        .map_err(|_| invalid_input())
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RawPolicyContext {
    actor: RawPolicyActor,
    action: String,
    resource: RawPolicyResource,
    task_risk: String,
    purpose: String,
    policy_snapshot_digest: String,
}

impl From<&ToolPolicyContext> for RawPolicyContext {
    fn from(policy: &ToolPolicyContext) -> Self {
        Self {
            actor: RawPolicyActor {
                connection_id: policy.actor().connection_id.clone(),
                agent_id: policy.actor().agent_id.clone(),
                trust_tier: actor_trust_tier(policy.actor().trust_tier).to_owned(),
                locality: actor_locality(policy.actor().locality).to_owned(),
            },
            action: policy.action().as_str().to_owned(),
            resource: RawPolicyResource {
                capability: RawCapability::from(&policy.resource().capability),
                content_digest: policy.resource().content_digest.to_string(),
                resource_class: resource_class(policy.resource().resource_class).to_owned(),
            },
            task_risk: task_risk(policy.task_risk()).to_owned(),
            purpose: policy.purpose().to_owned(),
            policy_snapshot_digest: policy.policy_snapshot_digest().to_string(),
        }
    }
}

impl TryFrom<RawPolicyContext> for ToolPolicyContext {
    type Error = PortError;

    fn try_from(raw: RawPolicyContext) -> Result<Self, Self::Error> {
        Self::new(
            PolicyActor {
                connection_id: raw.actor.connection_id,
                agent_id: raw.actor.agent_id,
                trust_tier: parse_actor_trust_tier(&raw.actor.trust_tier)?,
                locality: parse_actor_locality(&raw.actor.locality)?,
            },
            PolicyAction::new(raw.action).map_err(|_| invalid_input())?,
            PolicyResource {
                capability: CapabilityRef::try_from(raw.resource.capability)?,
                content_digest: Sha256Digest::new(raw.resource.content_digest)
                    .map_err(|_| invalid_input())?,
                resource_class: parse_resource_class(&raw.resource.resource_class)?,
            },
            parse_task_risk(&raw.task_risk)?,
            raw.purpose,
            Sha256Digest::new(raw.policy_snapshot_digest).map_err(|_| invalid_input())?,
        )
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RawPolicyActor {
    connection_id: String,
    agent_id: String,
    trust_tier: String,
    locality: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RawPolicyResource {
    capability: RawCapability,
    content_digest: String,
    resource_class: String,
}

const fn actor_trust_tier(value: TrustTier) -> &'static str {
    match value {
        TrustTier::CoreAdapter => "core_adapter",
        TrustTier::BrokeredProcess => "brokered_process",
        TrustTier::IsolatedWorker => "isolated_worker",
    }
}

const fn actor_locality(value: ActorLocality) -> &'static str {
    match value {
        ActorLocality::Local => "local",
        ActorLocality::Cloud => "cloud",
    }
}

const fn resource_class(value: ResourceClass) -> &'static str {
    match value {
        ResourceClass::Public => "public",
        ResourceClass::InternalCode => "internal_code",
        ResourceClass::Restricted => "restricted",
        ResourceClass::Secret => "secret",
    }
}

const fn task_risk(value: TaskRisk) -> &'static str {
    match value {
        TaskRisk::Low => "low",
        TaskRisk::Medium => "medium",
        TaskRisk::High => "high",
        TaskRisk::Critical => "critical",
    }
}

fn parse_process_trust_tier(value: &str) -> Result<ProcessTrustTier, PortError> {
    match value {
        "brokered_process" => Ok(ProcessTrustTier::BrokeredProcess),
        "isolated_worker" => Ok(ProcessTrustTier::IsolatedWorker),
        _ => Err(invalid_input()),
    }
}

fn parse_network_profile(value: &str) -> Result<NetworkProfile, PortError> {
    match value {
        "denied" => Ok(NetworkProfile::Denied),
        "provider_endpoint_only" => Ok(NetworkProfile::ProviderEndpointOnly),
        "approved_destinations" => Ok(NetworkProfile::ApprovedDestinations),
        _ => Err(invalid_input()),
    }
}

fn parse_actor_trust_tier(value: &str) -> Result<TrustTier, PortError> {
    match value {
        "core_adapter" => Ok(TrustTier::CoreAdapter),
        "brokered_process" => Ok(TrustTier::BrokeredProcess),
        "isolated_worker" => Ok(TrustTier::IsolatedWorker),
        _ => Err(invalid_input()),
    }
}

fn parse_actor_locality(value: &str) -> Result<ActorLocality, PortError> {
    match value {
        "local" => Ok(ActorLocality::Local),
        "cloud" => Ok(ActorLocality::Cloud),
        _ => Err(invalid_input()),
    }
}

fn parse_resource_class(value: &str) -> Result<ResourceClass, PortError> {
    match value {
        "public" => Ok(ResourceClass::Public),
        "internal_code" => Ok(ResourceClass::InternalCode),
        "restricted" => Ok(ResourceClass::Restricted),
        "secret" => Ok(ResourceClass::Secret),
        _ => Err(invalid_input()),
    }
}

fn parse_task_risk(value: &str) -> Result<TaskRisk, PortError> {
    match value {
        "low" => Ok(TaskRisk::Low),
        "medium" => Ok(TaskRisk::Medium),
        "high" => Ok(TaskRisk::High),
        "critical" => Ok(TaskRisk::Critical),
        _ => Err(invalid_input()),
    }
}

pub fn canonical_policy_binding_digest(
    request: &PolicyRequest,
) -> Result<PolicyRequestBindingDigest, PortError> {
    let value = json!({
        "schema": "policy-request-binding.v1",
        "taskId": request.task_id.as_str(),
        "actor": {
            "connectionId": request.actor.connection_id,
            "agentId": request.actor.agent_id,
            "trustTier": actor_trust_tier(request.actor.trust_tier),
            "locality": actor_locality(request.actor.locality),
        },
        "action": request.action.as_str(),
        "resource": {
            "capability": capability_value(&request.resource.capability),
            "contentDigest": request.resource.content_digest.as_str(),
            "resourceClass": resource_class(request.resource.resource_class),
        },
        "taskRisk": task_risk(request.task_risk),
        "workflowPhase": request.workflow_phase,
        "purpose": request.purpose,
        "policySnapshotDigest": request.policy_snapshot_digest.as_str(),
    });
    let canonical = serde_json_canonicalizer::to_vec(&value).map_err(|_| invalid_input())?;
    Sha256Digest::new(sha256_digest(&canonical))
        .map(PolicyRequestBindingDigest::new)
        .map_err(|_| invalid_input())
}

fn approved_executable_identity(
    request: &ApprovedProcessRequest,
) -> Result<&ApprovedExecutableIdentity, PortError> {
    let CapabilityRef::Toolchain(toolchain) = request.process.executable() else {
        return Err(invalid_input());
    };
    if toolchain.name() != request.approved_executable.executable().toolchain_id {
        return Err(invalid_input());
    }
    Ok(&request.approved_executable)
}

fn validate_approved_process_request(request: &ApprovedProcessRequest) -> Result<(), PortError> {
    approved_executable_identity(request)?;
    validate_safe_integer_fields(request)?;
    if request.process.expected_writes().len() > MAX_PROCESS_WRITE_SCOPES
        || request.memory_limit_bytes == Some(0)
        || request.cpu_time_limit_ms == Some(0)
    {
        return Err(invalid_input());
    }
    Ok(())
}

fn valid_registration_name(value: &str) -> bool {
    !value.trim().is_empty()
        && value.len() <= 256
        && !value.contains(['\0', '/', '\\', ':', '\r', '\n'])
}

fn valid_canonical_executable_path(path: &Path) -> bool {
    let Some(text) = path.to_str() else {
        return false;
    };
    if text.contains('\0')
        || text
            .split(['/', '\\'])
            .any(|component| matches!(component, "." | ".."))
    {
        return false;
    }

    let mut components = path.components();
    #[cfg(windows)]
    {
        let Some(Component::Prefix(prefix)) = components.next() else {
            return false;
        };
        if !matches!(prefix.kind(), Prefix::Disk(_) | Prefix::VerbatimDisk(_))
            || !matches!(components.next(), Some(Component::RootDir))
        {
            return false;
        }
    }
    #[cfg(not(windows))]
    if !matches!(components.next(), Some(Component::RootDir)) {
        return false;
    }

    components.all(|component| match component {
        Component::Normal(name) => {
            #[cfg(windows)]
            {
                name.to_str().is_some_and(|name| !name.contains(':'))
            }
            #[cfg(not(windows))]
            {
                true
            }
        }
        _ => false,
    })
}

fn valid_text(value: &str, max_len: usize) -> bool {
    !value.trim().is_empty() && value.len() <= max_len && !value.contains('\0')
}

fn validate_safe_integer_fields(request: &ApprovedProcessRequest) -> Result<(), PortError> {
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

pub(crate) fn logical_capability(capability: &CapabilityRef) -> String {
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
