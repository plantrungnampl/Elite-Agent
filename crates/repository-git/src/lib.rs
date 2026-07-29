#![deny(unsafe_op_in_unsafe_fn)]

mod hazards;
mod inspect;
mod paths;
mod tools;
mod unsafe_checkout;
mod worktree;

use std::path::{Path, PathBuf};
use std::sync::Mutex;
#[cfg(feature = "test-seams")]
use std::sync::{Arc, Barrier};

use local_agent_terminal_application::{
    CapabilityRootIdentity, CreateWorktree, DiscardWorktree, ExpectedPresence, InspectRepository,
    InspectWorktree, ManagedWorktreePath, PortError, RepositoryGateway, RepositoryLocator,
    RepositorySnapshot, Retryability, SafeErrorClassification, TaskQuery, WorktreeObservation,
    WorktreeSnapshot, WorktreeState,
};
use local_agent_terminal_domain::{GitObjectId, TaskId};
use sha2::{Digest, Sha256};

pub struct GitStructuredTools {
    registrations: Vec<GitWorktreeRegistration>,
    #[cfg(feature = "test-seams")]
    snapshot_hook: Option<std::sync::Arc<dyn Fn() + Send + Sync>>,
    #[cfg(feature = "test-seams")]
    before_generation_hook: Option<std::sync::Arc<dyn Fn() + Send + Sync>>,
    #[cfg(feature = "test-seams")]
    after_initial_binding_hook: Option<std::sync::Arc<dyn Fn() -> bool + Send + Sync>>,
    #[cfg(feature = "test-seams")]
    before_return_hook: Option<std::sync::Arc<dyn Fn() -> bool + Send + Sync>>,
}

struct GitWorktreeRegistration {
    root_identity: CapabilityRootIdentity,
    task_id: TaskId,
    locator: RepositoryLocator,
    revision: GitObjectId,
    worktree_identity: Vec<u8>,
    common_dir_identity: Vec<u8>,
}

struct RepositoryBinding {
    worktree: paths::DirectoryGuard,
    common_dir: paths::DirectoryGuard,
}

impl GitStructuredTools {
    /// Loads task/worktree ownership from the authoritative application projection.
    ///
    /// Composition must supply its durable [`TaskQuery`] implementation; caller-provided
    /// task, locator, revision, and root tuples are intentionally not accepted.
    pub fn from_owned_tasks(
        gateway: &GitRepositoryGateway,
        tasks: &dyn TaskQuery,
        task_ids: &[TaskId],
    ) -> Result<Self, PortError> {
        let registrations = task_ids
            .iter()
            .map(|task_id| GitWorktreeRegistration::from_owned_task(gateway, tasks, task_id))
            .collect::<Result<Vec<_>, _>>()?;
        Self::new(registrations)
    }

    fn new(registrations: Vec<GitWorktreeRegistration>) -> Result<Self, PortError> {
        if registrations.is_empty()
            || registrations
                .iter()
                .enumerate()
                .any(|(index, registration)| {
                    registrations[index + 1..].iter().any(|other| {
                        registration.root_identity == other.root_identity
                            || (registration.task_id == other.task_id
                                && registration.locator.repository_id
                                    == other.locator.repository_id)
                    })
                })
        {
            return Err(paths::invalid());
        }
        for registration in &registrations {
            registration.verify_current()?;
        }
        Ok(Self {
            registrations,
            #[cfg(feature = "test-seams")]
            snapshot_hook: None,
            #[cfg(feature = "test-seams")]
            before_generation_hook: None,
            #[cfg(feature = "test-seams")]
            after_initial_binding_hook: None,
            #[cfg(feature = "test-seams")]
            before_return_hook: None,
        })
    }

    pub fn root_identity(&self, task_id: &TaskId) -> Option<&CapabilityRootIdentity> {
        self.registrations
            .iter()
            .find(|registration| &registration.task_id == task_id)
            .map(|registration| &registration.root_identity)
    }

    #[cfg(feature = "test-seams")]
    pub fn with_snapshot_hook_for_test(mut self, hook: impl Fn() + Send + Sync + 'static) -> Self {
        self.snapshot_hook = Some(std::sync::Arc::new(hook));
        self
    }

    #[cfg(feature = "test-seams")]
    pub fn with_before_generation_hook_for_test(
        mut self,
        hook: impl Fn() + Send + Sync + 'static,
    ) -> Self {
        self.before_generation_hook = Some(std::sync::Arc::new(hook));
        self
    }

    #[cfg(feature = "test-seams")]
    pub fn with_after_initial_binding_hook_for_test(
        mut self,
        hook: impl Fn() -> bool + Send + Sync + 'static,
    ) -> Self {
        self.after_initial_binding_hook = Some(std::sync::Arc::new(hook));
        self
    }

    #[cfg(feature = "test-seams")]
    pub fn with_before_return_hook_for_test(
        mut self,
        hook: impl Fn() -> bool + Send + Sync + 'static,
    ) -> Self {
        self.before_return_hook = Some(std::sync::Arc::new(hook));
        self
    }
}

impl GitWorktreeRegistration {
    fn from_owned_task(
        gateway: &GitRepositoryGateway,
        tasks: &dyn TaskQuery,
        task_id: &TaskId,
    ) -> Result<Self, PortError> {
        let task = tasks.task(task_id).map_err(|_| denied())?;
        let worktree = task.worktree.as_ref().ok_or_else(denied)?;
        if &task.task_id != task_id
            || &worktree.task_id != task_id
            || worktree.state != WorktreeState::Present
            || worktree.expected_presence != ExpectedPresence::Present
            || task.task_branch.as_ref() != Some(&worktree.branch)
            || task.base_commit != worktree.base_commit
        {
            return Err(denied());
        }
        let managed_path = ManagedWorktreePath {
            trusted_root_id: gateway.trusted_root_id().to_owned(),
            relative_leaf: PathBuf::from(worktree.worktree_id.as_str()),
            redacted_display: worktree.target_path_display.clone(),
        };
        let expected_path = paths::recovery_path(gateway, &managed_path).map_err(|_| denied())?;
        let locator = gateway
            .locate_persisted(&expected_path)
            .map_err(|_| denied())?;
        if locator.repository_id != worktree.repository_id
            || locator.stable_identity != worktree.repository_identity
        {
            return Err(denied());
        }
        Self::validate(task.task_id, locator, worktree.base_commit.clone()).map_err(|_| denied())
    }

    fn validate(
        task_id: TaskId,
        locator: RepositoryLocator,
        revision: GitObjectId,
    ) -> Result<Self, PortError> {
        let (repository, _) = paths::open_for_locator(&locator)?;
        tools::verify_revision(&repository, &revision)?;
        let worktree_identity = paths::directory_binding_identity(&locator.canonical_workdir)?;
        let common_dir_identity = paths::directory_binding_identity(&locator.canonical_common_dir)?;
        let root_identity = derive_worktree_root(
            &task_id,
            &locator,
            &revision,
            &worktree_identity,
            &common_dir_identity,
        )?;
        Ok(Self {
            root_identity,
            task_id,
            locator,
            revision,
            worktree_identity,
            common_dir_identity,
        })
    }

    fn verify_current(&self) -> Result<(), PortError> {
        let (repository, _) = paths::open_for_locator(&self.locator)?;
        let binding = self.retain_binding()?;
        self.verify_opened(&repository, &binding)
    }

    fn verify_initial(&self, repository: &git2::Repository) -> Result<(), PortError> {
        let binding = self.retain_binding()?;
        self.verify_opened(repository, &binding)
    }

    fn retain_binding(&self) -> Result<RepositoryBinding, PortError> {
        Ok(RepositoryBinding {
            worktree: paths::DirectoryGuard::open(&self.locator.canonical_workdir)?,
            common_dir: paths::DirectoryGuard::open(&self.locator.canonical_common_dir)?,
        })
    }

    fn verify_opened(
        &self,
        repository: &git2::Repository,
        binding: &RepositoryBinding,
    ) -> Result<(), PortError> {
        tools::verify_revision(repository, &self.revision)?;
        binding.worktree.verify()?;
        binding.common_dir.verify()?;
        let retained_worktree_identity = binding.worktree.binding_identity()?;
        let retained_common_dir_identity = binding.common_dir.binding_identity()?;
        let current_worktree_identity =
            paths::directory_binding_identity(&self.locator.canonical_workdir)?;
        let current_common_dir_identity =
            paths::directory_binding_identity(&self.locator.canonical_common_dir)?;
        let repository_workdir = repository.workdir().ok_or_else(paths::conflict)?;
        if paths::canonical_directory(repository_workdir)? != self.locator.canonical_workdir
            || paths::canonical_directory(repository.commondir())?
                != self.locator.canonical_common_dir
        {
            return Err(paths::conflict());
        }
        let expected_root = derive_worktree_root(
            &self.task_id,
            &self.locator,
            &self.revision,
            &retained_worktree_identity,
            &retained_common_dir_identity,
        )?;
        if retained_worktree_identity != self.worktree_identity
            || current_worktree_identity != self.worktree_identity
            || retained_common_dir_identity != self.common_dir_identity
            || current_common_dir_identity != self.common_dir_identity
            || expected_root != self.root_identity
        {
            return Err(paths::conflict());
        }
        Ok(())
    }
}

fn denied() -> PortError {
    PortError::failure(
        SafeErrorClassification::PermissionDenied,
        Retryability::NonRetryable,
    )
}

fn derive_worktree_root(
    task_id: &TaskId,
    locator: &RepositoryLocator,
    revision: &GitObjectId,
    worktree_identity: &[u8],
    common_dir_identity: &[u8],
) -> Result<CapabilityRootIdentity, PortError> {
    let mut hasher = Sha256::new();
    for part in [
        task_id.as_str().as_bytes(),
        locator.repository_id.as_str().as_bytes(),
        locator.stable_identity.as_bytes(),
        revision.as_str().as_bytes(),
        worktree_identity,
        common_dir_identity,
    ] {
        hasher.update(
            u64::try_from(part.len())
                .map_err(|_| paths::invalid())?
                .to_le_bytes(),
        );
        hasher.update(part);
    }
    CapabilityRootIdentity::new(format!("git-root-{:x}", hasher.finalize()))
}

pub struct GitRepositoryGateway {
    pub(crate) trusted_workspace_root: PathBuf,
    pub(crate) excluded_roots: Vec<PathBuf>,
    pub(crate) trusted_root_id: String,
    pub(crate) calls: Mutex<()>,
    #[cfg(feature = "test-seams")]
    pub(crate) test_hooks: TestHooks,
}

#[cfg(feature = "test-seams")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PostAddStage {
    AfterAdd,
    AfterParentVerify,
    AfterTargetValidate,
    AfterTargetOpen,
    AfterConfigAttach,
    AfterSnapshot,
    AfterRefVerify,
    AfterOriginalVerify,
}

#[cfg(feature = "test-seams")]
#[derive(Clone, Default)]
pub struct TestHooks {
    pub before_checkout: Option<Arc<Barrier>>,
    pub during_checkout: Option<Arc<Barrier>>,
    pub after_cleanup_ownership_check: Option<Arc<Barrier>>,
    pub after_discard_validation: Option<Arc<Barrier>>,
    pub after_discard_rename: Option<Arc<Barrier>>,
    pub fail_at: Option<PostAddStage>,
}

impl GitRepositoryGateway {
    pub fn open(
        trusted_workspace_root: &Path,
        excluded_roots: &[PathBuf],
    ) -> Result<Self, PortError> {
        paths::new_gateway(trusted_workspace_root, excluded_roots)
    }

    pub fn locate(&self, workdir: &Path) -> Result<RepositoryLocator, PortError> {
        let _guard = self.calls.lock().map_err(|_| paths::internal())?;
        paths::locate(self, workdir)
    }

    pub fn locate_persisted(&self, workdir: &Path) -> Result<RepositoryLocator, PortError> {
        let _guard = self.calls.lock().map_err(|_| paths::internal())?;
        paths::locate_persisted(self, workdir)
    }

    pub fn trusted_root_id(&self) -> &str {
        &self.trusted_root_id
    }

    #[cfg(feature = "test-seams")]
    pub fn set_test_hooks(&mut self, hooks: TestHooks) {
        self.test_hooks = hooks;
    }
}

impl RepositoryGateway for GitRepositoryGateway {
    fn inspect(&self, request: InspectRepository) -> Result<RepositorySnapshot, PortError> {
        let _guard = self.calls.lock().map_err(|_| paths::internal())?;
        inspect::inspect(self, request)
    }

    fn create_worktree(&self, request: CreateWorktree) -> Result<WorktreeSnapshot, PortError> {
        let _guard = self.calls.lock().map_err(|_| paths::internal())?;
        worktree::create(self, request)
    }

    fn list_worktrees(
        &self,
        repository: &RepositoryLocator,
    ) -> Result<Vec<WorktreeSnapshot>, PortError> {
        let _guard = self.calls.lock().map_err(|_| paths::internal())?;
        worktree::list(self, repository)
    }

    fn discard_worktree(&self, request: DiscardWorktree) -> Result<(), PortError> {
        let _guard = self.calls.lock().map_err(|_| paths::internal())?;
        worktree::discard(self, request)
    }

    fn inspect_worktree(&self, request: InspectWorktree) -> Result<WorktreeObservation, PortError> {
        let _guard = self.calls.lock().map_err(|_| paths::internal())?;
        worktree::inspect_expected(self, request)
    }
}
