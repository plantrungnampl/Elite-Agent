use std::path::PathBuf;

use local_agent_terminal_domain::{
    GitObjectId, LeaseClaim, ProjectId, RepositoryId, TaskBranch, TaskId, WorkspaceFingerprint,
    WorkspaceVersion, WorktreeId,
};

use crate::{
    NewProject, PortError, ProjectSettings, ProjectSnapshot, Retryability, SafeErrorClassification,
    WorkspaceStateStore,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObjectFormat {
    Sha1,
    Sha256,
}

impl ObjectFormat {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Sha1 => "sha1",
            Self::Sha256 => "sha256",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RepositoryHealth {
    Healthy,
    Dirty,
    Unsafe,
    Unsupported,
}

impl RepositoryHealth {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Healthy => "healthy",
            Self::Dirty => "dirty",
            Self::Unsafe => "unsafe",
            Self::Unsupported => "unsupported",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "healthy" => Some(Self::Healthy),
            "dirty" => Some(Self::Dirty),
            "unsafe" => Some(Self::Unsafe),
            "unsupported" => Some(Self::Unsupported),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OriginalCheckoutState {
    Clean,
    Dirty,
    Detached,
    Unborn,
    Unavailable,
}

impl OriginalCheckoutState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Clean => "clean",
            Self::Dirty => "dirty",
            Self::Detached => "detached",
            Self::Unborn => "unborn",
            Self::Unavailable => "unavailable",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "clean" => Some(Self::Clean),
            "dirty" => Some(Self::Dirty),
            "detached" => Some(Self::Detached),
            "unborn" => Some(Self::Unborn),
            "unavailable" => Some(Self::Unavailable),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RepositoryHazardReason {
    HooksConfigured,
    FiltersConfigured,
    LfsConfigured,
    SubmodulesPresent,
    UnsafeConfiguration,
    UnsupportedObjectFormat,
    PathConflict,
}

impl RepositoryHazardReason {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::HooksConfigured => "hooks_configured",
            Self::FiltersConfigured => "filters_configured",
            Self::LfsConfigured => "lfs_configured",
            Self::SubmodulesPresent => "submodules_present",
            Self::UnsafeConfiguration => "unsafe_configuration",
            Self::UnsupportedObjectFormat => "unsupported_object_format",
            Self::PathConflict => "path_conflict",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "hooks_configured" => Some(Self::HooksConfigured),
            "filters_configured" => Some(Self::FiltersConfigured),
            "lfs_configured" => Some(Self::LfsConfigured),
            "submodules_present" => Some(Self::SubmodulesPresent),
            "unsafe_configuration" => Some(Self::UnsafeConfiguration),
            "unsupported_object_format" => Some(Self::UnsupportedObjectFormat),
            "path_conflict" => Some(Self::PathConflict),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepositoryHazard {
    pub reason: RepositoryHazardReason,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepositoryLocator {
    pub repository_id: RepositoryId,
    pub stable_identity: String,
    pub canonical_workdir: PathBuf,
    pub canonical_common_dir: PathBuf,
    pub object_format: ObjectFormat,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManagedWorktreePath {
    pub trusted_root_id: String,
    pub relative_leaf: PathBuf,
    pub redacted_display: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InspectRepository {
    pub locator: RepositoryLocator,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepositorySnapshot {
    pub repository_id: RepositoryId,
    pub health: RepositoryHealth,
    pub stable_identity: String,
    pub default_branch: Option<TaskBranch>,
    pub base_commit: Option<GitObjectId>,
    pub original_checkout: OriginalCheckoutState,
    pub hazards: Vec<RepositoryHazard>,
    pub fingerprint: WorkspaceFingerprint,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorktreeState {
    Planned,
    Present,
    Missing,
    Conflict,
    Discarded,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExpectedPresence {
    Absent,
    Present,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorktreeSnapshot {
    pub worktree_id: WorktreeId,
    pub repository_id: RepositoryId,
    pub repository_identity: String,
    pub task_id: TaskId,
    pub branch: TaskBranch,
    pub base_commit: GitObjectId,
    pub target_path_display: String,
    pub state: WorktreeState,
    pub expected_presence: ExpectedPresence,
    pub fingerprint: WorkspaceFingerprint,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreateWorktree {
    pub repository: RepositoryLocator,
    pub managed_path: ManagedWorktreePath,
    pub task_id: TaskId,
    pub lease_claim: LeaseClaim,
    pub expected_workspace_version: WorkspaceVersion,
    pub worktree_id: WorktreeId,
    pub branch: TaskBranch,
    pub base_commit: GitObjectId,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscardWorktree {
    pub repository: RepositoryLocator,
    pub managed_path: ManagedWorktreePath,
    pub task_id: TaskId,
    pub lease_claim: LeaseClaim,
    pub expected_workspace_version: WorkspaceVersion,
    pub worktree_id: WorktreeId,
    pub branch: TaskBranch,
    pub base_commit: GitObjectId,
}

pub trait RepositoryGateway: Send + Sync {
    fn inspect(&self, request: InspectRepository) -> Result<RepositorySnapshot, PortError>;
    fn create_worktree(&self, request: CreateWorktree) -> Result<WorktreeSnapshot, PortError>;
    fn list_worktrees(
        &self,
        repository: &RepositoryLocator,
    ) -> Result<Vec<WorktreeSnapshot>, PortError>;
    fn discard_worktree(&self, request: DiscardWorktree) -> Result<(), PortError>;
}

pub struct OnboardRepository<'a> {
    repositories: &'a dyn RepositoryGateway,
    workspaces: &'a dyn WorkspaceStateStore,
}

impl<'a> OnboardRepository<'a> {
    pub const fn new(
        repositories: &'a dyn RepositoryGateway,
        workspaces: &'a dyn WorkspaceStateStore,
    ) -> Self {
        Self {
            repositories,
            workspaces,
        }
    }

    pub fn execute(
        &self,
        project_id: ProjectId,
        name: String,
        created_at: String,
        settings: ProjectSettings,
        inspection: InspectRepository,
    ) -> Result<ProjectSnapshot, PortError> {
        let repository_path = inspection
            .locator
            .canonical_workdir
            .to_str()
            .ok_or_else(invalid_input)?
            .to_owned();
        if name.trim().is_empty()
            || name.len() > 200
            || created_at.trim().is_empty()
            || settings.policy_profile_id.trim().is_empty()
            || settings.artifact_root_path.trim().is_empty()
        {
            return Err(invalid_input());
        }

        let repository = self.repositories.inspect(inspection)?;
        self.workspaces.create_project(NewProject {
            project_id,
            name,
            repository,
            repository_path,
            settings,
            created_at,
        })
    }
}

fn invalid_input() -> PortError {
    PortError::failure(
        SafeErrorClassification::InvalidInput,
        Retryability::NonRetryable,
    )
}
