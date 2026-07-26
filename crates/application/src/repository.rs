use std::path::PathBuf;

use local_agent_terminal_domain::{
    GitObjectId, LeaseClaim, ProjectId, RepositoryId, TaskBranch, TaskId, WorkspaceFingerprint,
    WorkspaceVersion, WorktreeId,
};

use crate::{
    NewProject, PortError, ProjectSnapshot, Retryability, SafeErrorClassification,
    WorkspaceStateStore,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObjectFormat {
    Sha1,
    Sha256,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RepositoryHealth {
    Healthy,
    Dirty,
    Unsafe,
    Unsupported,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OriginalCheckoutState {
    Clean,
    Dirty,
    Detached,
    Unborn,
    Unavailable,
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
        inspection: InspectRepository,
    ) -> Result<ProjectSnapshot, PortError> {
        if name.trim().is_empty() || name.len() > 200 || created_at.trim().is_empty() {
            return Err(invalid_input());
        }

        let repository = self.repositories.inspect(inspection)?;
        self.workspaces.create_project(NewProject {
            project_id,
            name,
            repository,
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
