use std::collections::BTreeSet;
use std::fmt;

use crate::{ArtifactId, FencingToken, Phase, RunId, Sha256Digest, TaskId, WorkspaceVersion};

const MAX_IDENTIFIER_LENGTH: usize = 256;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CapabilityRef {
    Source(SourceCapability),
    Artifact(ArtifactCapability),
    Worktree(WorktreeCapability),
    Toolchain(ToolchainCapability),
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SourceCapability {
    revision: String,
    path: String,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ArtifactCapability {
    artifact_id: ArtifactId,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct WorktreeCapability {
    task_id: TaskId,
    path: String,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ToolchainCapability {
    name: String,
}

impl CapabilityRef {
    pub fn source(revision: impl Into<String>, path: impl Into<String>) -> Result<Self, ToolError> {
        let revision = revision.into();
        let path = path.into();
        validate_component(&revision)?;
        validate_relative_path(&path)?;
        Ok(Self::Source(SourceCapability { revision, path }))
    }

    pub fn artifact(artifact_id: ArtifactId) -> Result<Self, ToolError> {
        validate_binding_id(artifact_id.as_str())?;
        Ok(Self::Artifact(ArtifactCapability { artifact_id }))
    }

    pub fn worktree(task_id: TaskId, path: impl Into<String>) -> Result<Self, ToolError> {
        let path = path.into();
        validate_binding_id(task_id.as_str())?;
        validate_relative_path(&path)?;
        Ok(Self::Worktree(WorktreeCapability { task_id, path }))
    }

    pub fn toolchain(name: impl Into<String>) -> Result<Self, ToolError> {
        let name = name.into();
        validate_component(&name)?;
        Ok(Self::Toolchain(ToolchainCapability { name }))
    }

    pub fn validate(&self) -> Result<(), ToolError> {
        match self {
            Self::Source(capability) => {
                validate_component(&capability.revision)?;
                validate_relative_path(&capability.path)
            }
            Self::Artifact(capability) => validate_binding_id(capability.artifact_id.as_str()),
            Self::Worktree(capability) => {
                validate_binding_id(capability.task_id.as_str())?;
                validate_relative_path(&capability.path)
            }
            Self::Toolchain(capability) => validate_component(&capability.name),
        }
    }

    pub fn worktree_task_id(&self) -> Option<&TaskId> {
        match self {
            Self::Worktree(capability) => Some(&capability.task_id),
            _ => None,
        }
    }
}

impl SourceCapability {
    pub fn revision(&self) -> &str {
        &self.revision
    }

    pub fn path(&self) -> &str {
        &self.path
    }
}

impl ArtifactCapability {
    pub const fn artifact_id(&self) -> &ArtifactId {
        &self.artifact_id
    }
}

impl WorktreeCapability {
    pub const fn task_id(&self) -> &TaskId {
        &self.task_id
    }

    pub fn path(&self) -> &str {
        &self.path
    }
}

impl ToolchainCapability {
    pub fn name(&self) -> &str {
        &self.name
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StructuredToolName {
    FileRead,
    FileWrite,
    GitStatus,
    GitDiff,
    ProcessExec,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessTrustTier {
    BrokeredProcess,
    IsolatedWorker,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkProfile {
    Denied,
    ProviderEndpointOnly,
    ApprovedDestinations,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PlanStepId(String);

impl PlanStepId {
    pub fn new(value: impl Into<String>) -> Result<Self, ToolError> {
        let value = value.into();
        validate_binding_id(&value)?;
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnvironmentProfile {
    name: String,
    digest: Sha256Digest,
}

impl EnvironmentProfile {
    pub fn new(name: impl Into<String>, digest: Sha256Digest) -> Result<Self, ToolError> {
        let name = name.into();
        validate_component(&name)?;
        Ok(Self { name, digest })
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub const fn digest(&self) -> &Sha256Digest {
        &self.digest
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessBinding {
    task_id: TaskId,
    run_id: RunId,
    plan_step_id: PlanStepId,
    workflow_phase: Phase,
    workspace_version: WorkspaceVersion,
    environment_profile: EnvironmentProfile,
    timeout_ms: u64,
}

impl ProcessBinding {
    pub fn new(
        task_id: TaskId,
        run_id: RunId,
        plan_step_id: PlanStepId,
        workflow_phase: Phase,
        workspace_version: WorkspaceVersion,
        environment_profile: EnvironmentProfile,
        timeout_ms: u64,
    ) -> Result<Self, ToolError> {
        validate_binding_id(task_id.as_str())?;
        validate_binding_id(run_id.as_str())?;
        if timeout_ms == 0 {
            return Err(ToolError::InvalidTimeout);
        }
        Ok(Self {
            task_id,
            run_id,
            plan_step_id,
            workflow_phase,
            workspace_version,
            environment_profile,
            timeout_ms,
        })
    }

    pub const fn task_id(&self) -> &TaskId {
        &self.task_id
    }

    pub const fn run_id(&self) -> &RunId {
        &self.run_id
    }

    pub const fn plan_step_id(&self) -> &PlanStepId {
        &self.plan_step_id
    }

    pub const fn workflow_phase(&self) -> Phase {
        self.workflow_phase
    }

    pub const fn workspace_version(&self) -> WorkspaceVersion {
        self.workspace_version
    }

    pub const fn environment_profile(&self) -> &EnvironmentProfile {
        &self.environment_profile
    }

    pub const fn timeout_ms(&self) -> u64 {
        self.timeout_ms
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ExpectedWrite(CapabilityRef);

impl ExpectedWrite {
    pub fn new(capability: CapabilityRef) -> Result<Self, ToolError> {
        if capability.worktree_task_id().is_none() {
            return Err(ToolError::InvalidExpectedWrite);
        }
        capability.validate()?;
        Ok(Self(capability))
    }

    pub const fn capability(&self) -> &CapabilityRef {
        &self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessInvocation {
    executable: CapabilityRef,
    argv: Vec<String>,
    cwd: CapabilityRef,
    trust_tier: ProcessTrustTier,
    network: NetworkProfile,
    expected_writes: Vec<ExpectedWrite>,
    executor_fencing_token: Option<FencingToken>,
}

impl ProcessInvocation {
    pub fn new(
        executable: CapabilityRef,
        argv: Vec<String>,
        cwd: CapabilityRef,
        trust_tier: ProcessTrustTier,
        network: NetworkProfile,
        expected_writes: Vec<ExpectedWrite>,
        executor_fencing_token: Option<FencingToken>,
    ) -> Result<Self, ToolError> {
        if !matches!(executable, CapabilityRef::Toolchain(_)) {
            return Err(ToolError::RegisteredExecutableRequired);
        }
        executable.validate()?;
        if argv.is_empty()
            || argv
                .iter()
                .any(|argument| argument.is_empty() || argument.contains('\0'))
        {
            return Err(ToolError::InvalidArgv);
        }
        if cwd.worktree_task_id().is_none() {
            return Err(ToolError::WorktreeCapabilityRequired);
        }
        if trust_tier == ProcessTrustTier::BrokeredProcess {
            return Err(ToolError::BrokeredProcessWorktreeDenied);
        }
        cwd.validate()?;
        if !expected_writes.is_empty() && executor_fencing_token.is_none() {
            return Err(ToolError::MissingFencingToken);
        }
        let unique_writes: BTreeSet<_> = expected_writes.iter().collect();
        if unique_writes.len() != expected_writes.len() {
            return Err(ToolError::DuplicateExpectedWrite);
        }
        Ok(Self {
            executable,
            argv,
            cwd,
            trust_tier,
            network,
            expected_writes,
            executor_fencing_token,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessToolRequest {
    binding: ProcessBinding,
    invocation: ProcessInvocation,
}

impl ProcessToolRequest {
    pub fn new(binding: ProcessBinding, invocation: ProcessInvocation) -> Result<Self, ToolError> {
        if invocation.cwd.worktree_task_id() != Some(binding.task_id()) {
            return Err(ToolError::MismatchedTaskScope);
        }
        if invocation
            .expected_writes
            .iter()
            .any(|write| write.capability().worktree_task_id() != Some(binding.task_id()))
        {
            return Err(ToolError::MismatchedTaskScope);
        }

        Ok(Self {
            binding,
            invocation,
        })
    }

    pub const fn tool(&self) -> StructuredToolName {
        StructuredToolName::ProcessExec
    }

    pub const fn binding(&self) -> &ProcessBinding {
        &self.binding
    }

    pub const fn executable(&self) -> &CapabilityRef {
        &self.invocation.executable
    }

    pub fn argv(&self) -> &[String] {
        &self.invocation.argv
    }

    pub const fn cwd(&self) -> &CapabilityRef {
        &self.invocation.cwd
    }

    pub const fn trust_tier(&self) -> ProcessTrustTier {
        self.invocation.trust_tier
    }

    pub const fn network(&self) -> NetworkProfile {
        self.invocation.network
    }

    pub fn expected_writes(&self) -> &[ExpectedWrite] {
        &self.invocation.expected_writes
    }

    pub const fn executor_fencing_token(&self) -> Option<FencingToken> {
        self.invocation.executor_fencing_token
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawShellRequest {
    shell: CapabilityRef,
    script_digest: Sha256Digest,
    cwd: CapabilityRef,
}

impl RawShellRequest {
    pub fn new(
        shell: CapabilityRef,
        script_digest: Sha256Digest,
        cwd: CapabilityRef,
    ) -> Result<Self, ToolError> {
        if !matches!(shell, CapabilityRef::Toolchain(_)) {
            return Err(ToolError::RegisteredExecutableRequired);
        }
        if cwd.worktree_task_id().is_none() {
            return Err(ToolError::WorktreeCapabilityRequired);
        }
        shell.validate()?;
        cwd.validate()?;
        Ok(Self {
            shell,
            script_digest,
            cwd,
        })
    }

    pub fn validate_default_profile(&self) -> Result<(), ToolError> {
        let _ = (&self.shell, &self.script_digest, &self.cwd);
        Err(ToolError::RawShellDenied)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ToolError {
    InvalidCapability,
    PathEscapesCapability,
    InvalidBinding,
    InvalidTimeout,
    RegisteredExecutableRequired,
    WorktreeCapabilityRequired,
    BrokeredProcessWorktreeDenied,
    MismatchedTaskScope,
    InvalidArgv,
    InvalidExpectedWrite,
    DuplicateExpectedWrite,
    MissingFencingToken,
    RawShellDenied,
}

impl fmt::Display for ToolError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidCapability => "capability is invalid",
            Self::PathEscapesCapability => "capability path escapes its root",
            Self::InvalidBinding => "process binding is invalid",
            Self::InvalidTimeout => "timeout must be positive",
            Self::RegisteredExecutableRequired => "registered executable capability is required",
            Self::WorktreeCapabilityRequired => "worktree capability is required",
            Self::BrokeredProcessWorktreeDenied => {
                "brokered processes cannot receive a worktree capability"
            }
            Self::MismatchedTaskScope => "capability task does not match process binding",
            Self::InvalidArgv => "argv is invalid",
            Self::InvalidExpectedWrite => "expected write is invalid",
            Self::DuplicateExpectedWrite => "expected writes must be unique",
            Self::MissingFencingToken => "write-capable request requires a fencing token",
            Self::RawShellDenied => "raw shell is denied by the default profile",
        })
    }
}

impl std::error::Error for ToolError {}

fn validate_binding_id(value: &str) -> Result<(), ToolError> {
    if value.trim().is_empty() || value.len() > MAX_IDENTIFIER_LENGTH || value.contains('\0') {
        return Err(ToolError::InvalidBinding);
    }
    Ok(())
}

fn validate_component(value: &str) -> Result<(), ToolError> {
    if value.trim().is_empty()
        || value.len() > MAX_IDENTIFIER_LENGTH
        || value.contains('\0')
        || value.contains(['/', '\\', ':'])
    {
        return Err(ToolError::InvalidCapability);
    }
    Ok(())
}

fn validate_relative_path(value: &str) -> Result<(), ToolError> {
    if value == "." {
        return Ok(());
    }
    if value.is_empty()
        || value.len() > 4_096
        || value.contains('\0')
        || value.starts_with(['/', '\\'])
        || value.contains(':')
        || value
            .split(['/', '\\'])
            .any(|part| part.is_empty() || part == "." || part == "..")
    {
        return Err(ToolError::PathEscapesCapability);
    }
    Ok(())
}
