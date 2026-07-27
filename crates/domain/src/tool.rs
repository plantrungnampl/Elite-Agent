use std::collections::BTreeSet;
use std::fmt;

use crate::{ArtifactId, FencingToken, Sha256Digest, TaskId};

const MAX_CAPABILITY_COMPONENT_LENGTH: usize = 256;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CapabilityRef {
    Source { revision: String, path: String },
    Artifact { artifact_id: ArtifactId },
    Worktree { task_id: TaskId, path: String },
    Toolchain { name: String },
}

impl CapabilityRef {
    pub fn source(revision: impl Into<String>, path: impl Into<String>) -> Result<Self, ToolError> {
        let capability = Self::Source {
            revision: revision.into(),
            path: path.into(),
        };
        capability.validate()?;
        Ok(capability)
    }

    pub fn artifact(artifact_id: ArtifactId) -> Self {
        Self::Artifact { artifact_id }
    }

    pub fn worktree(task_id: TaskId, path: impl Into<String>) -> Result<Self, ToolError> {
        let capability = Self::Worktree {
            task_id,
            path: path.into(),
        };
        capability.validate()?;
        Ok(capability)
    }

    pub fn toolchain(name: impl Into<String>) -> Result<Self, ToolError> {
        let capability = Self::Toolchain { name: name.into() };
        capability.validate()?;
        Ok(capability)
    }

    pub fn validate(&self) -> Result<(), ToolError> {
        match self {
            Self::Source { revision, path } => {
                validate_component(revision)?;
                validate_relative_path(path)
            }
            Self::Artifact { artifact_id } => validate_component(artifact_id.as_str()),
            Self::Worktree { task_id, path } => {
                validate_component(task_id.as_str())?;
                validate_relative_path(path)
            }
            Self::Toolchain { name } => validate_component(name),
        }
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
pub struct ExpectedWrite(CapabilityRef);

impl ExpectedWrite {
    pub fn new(capability: CapabilityRef) -> Result<Self, ToolError> {
        if !matches!(capability, CapabilityRef::Worktree { .. }) {
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
pub struct ProcessToolRequest {
    executable: CapabilityRef,
    argv: Vec<String>,
    cwd: CapabilityRef,
    trust_tier: ProcessTrustTier,
    network: NetworkProfile,
    expected_writes: Vec<ExpectedWrite>,
    executor_fencing_token: Option<FencingToken>,
}

impl ProcessToolRequest {
    pub fn new(
        executable: CapabilityRef,
        argv: Vec<String>,
        cwd: CapabilityRef,
        trust_tier: ProcessTrustTier,
        network: NetworkProfile,
        expected_writes: Vec<ExpectedWrite>,
        executor_fencing_token: Option<FencingToken>,
    ) -> Result<Self, ToolError> {
        if !matches!(executable, CapabilityRef::Toolchain { .. }) {
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
        if !matches!(cwd, CapabilityRef::Worktree { .. }) {
            return Err(ToolError::WorktreeCapabilityRequired);
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

    pub const fn tool(&self) -> StructuredToolName {
        StructuredToolName::ProcessExec
    }

    pub const fn executable(&self) -> &CapabilityRef {
        &self.executable
    }

    pub fn argv(&self) -> &[String] {
        &self.argv
    }

    pub const fn cwd(&self) -> &CapabilityRef {
        &self.cwd
    }

    pub const fn trust_tier(&self) -> ProcessTrustTier {
        self.trust_tier
    }

    pub const fn network(&self) -> NetworkProfile {
        self.network
    }

    pub fn expected_writes(&self) -> &[ExpectedWrite] {
        &self.expected_writes
    }

    pub const fn executor_fencing_token(&self) -> Option<FencingToken> {
        self.executor_fencing_token
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
        if !matches!(shell, CapabilityRef::Toolchain { .. }) {
            return Err(ToolError::RegisteredExecutableRequired);
        }
        if !matches!(cwd, CapabilityRef::Worktree { .. }) {
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
    RegisteredExecutableRequired,
    WorktreeCapabilityRequired,
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
            Self::RegisteredExecutableRequired => "registered executable capability is required",
            Self::WorktreeCapabilityRequired => "worktree capability is required",
            Self::InvalidArgv => "argv is invalid",
            Self::InvalidExpectedWrite => "expected write is invalid",
            Self::DuplicateExpectedWrite => "expected writes must be unique",
            Self::MissingFencingToken => "write-capable request requires a fencing token",
            Self::RawShellDenied => "raw shell is denied by the default profile",
        })
    }
}

impl std::error::Error for ToolError {}

fn validate_component(value: &str) -> Result<(), ToolError> {
    if value.trim().is_empty()
        || value.len() > MAX_CAPABILITY_COMPONENT_LENGTH
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
