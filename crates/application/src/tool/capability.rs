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
    PolicyBoundBytes, PolicyDecisionId, PolicyRequestBindingDigest, PortError, Retryability,
    SafeErrorClassification,
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
    disk_write_limit_bytes: Option<u64>,
}

impl ApprovedProcessRequest {
    pub fn new(
        approved_executable: ApprovedExecutableIdentity,
        process: ProcessToolRequest,
        expected_reads: Vec<CapabilityRef>,
        memory_limit_bytes: Option<u64>,
        cpu_time_limit_ms: Option<u64>,
        disk_write_limit_bytes: Option<u64>,
    ) -> Result<Self, PortError> {
        let request = Self {
            approved_executable,
            process,
            expected_reads,
            memory_limit_bytes,
            cpu_time_limit_ms,
            disk_write_limit_bytes,
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

    pub const fn disk_write_limit_bytes(&self) -> Option<u64> {
        self.disk_write_limit_bytes
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
        if policy.action().as_str() != "process.exec"
            || policy.resource().capability.worktree_task_id() != Some(task_id)
        {
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

    pub fn canonical_evidence(&self) -> Result<VerifiedBytes, PortError> {
        let target = match &self.target {
            ResolvedCapabilityTarget::Root => json!({"kind": "root"}),
            ResolvedCapabilityTarget::Relative(components) => {
                json!({"kind": "relative", "components": components.as_slice()})
            }
        };
        let bytes = serde_json_canonicalizer::to_vec(&json!({
            "capability": capability_value(&self.capability),
            "contentDigest": self.write.digest.as_str(),
            "rootIdentity": self.root_identity.as_str(),
            "schema": "process-write-evidence.v1",
            "sizeBytes": self.write.size_bytes,
            "target": target,
        }))
        .map_err(|_| invalid_input())?;
        Ok(VerifiedBytes {
            digest: Sha256Digest::new(sha256_digest(&bytes)).map_err(|_| invalid_input())?,
            bytes,
        })
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
    pub disk_write_limit_bytes: Option<u64>,
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
