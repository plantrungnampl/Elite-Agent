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
    CapabilityRootIdentity, CreateWorktree, DiscardWorktree, InspectRepository, InspectWorktree,
    PortError, RepositoryGateway, RepositoryLocator, RepositorySnapshot, WorktreeObservation,
    WorktreeSnapshot,
};
use local_agent_terminal_domain::{GitObjectId, TaskId};
use sha2::{Digest, Sha256};

pub struct GitStructuredTools {
    registrations: Vec<GitWorktreeRegistration>,
    #[cfg(feature = "test-seams")]
    snapshot_hook: Option<std::sync::Arc<dyn Fn() + Send + Sync>>,
    #[cfg(feature = "test-seams")]
    before_generation_hook: Option<std::sync::Arc<dyn Fn() + Send + Sync>>,
}

pub struct GitWorktreeRegistration {
    root_identity: CapabilityRootIdentity,
    task_id: TaskId,
    locator: RepositoryLocator,
    revision: GitObjectId,
    worktree_identity: Vec<u8>,
}

impl GitStructuredTools {
    pub fn new(registrations: Vec<GitWorktreeRegistration>) -> Result<Self, PortError> {
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
}

impl GitWorktreeRegistration {
    pub fn validate(
        task_id: TaskId,
        locator: RepositoryLocator,
        revision: GitObjectId,
    ) -> Result<Self, PortError> {
        let (repository, _) = paths::open_for_locator(&locator)?;
        tools::verify_revision(&repository, &revision)?;
        let worktree_identity = paths::directory_binding_identity(&locator.canonical_workdir)?;
        let root_identity =
            derive_worktree_root(&task_id, &locator, &revision, &worktree_identity)?;
        Ok(Self {
            root_identity,
            task_id,
            locator,
            revision,
            worktree_identity,
        })
    }

    pub const fn root_identity(&self) -> &CapabilityRootIdentity {
        &self.root_identity
    }

    fn verify_current(&self) -> Result<(), PortError> {
        let (repository, _) = paths::open_for_locator(&self.locator)?;
        self.verify_opened(&repository)
    }

    fn verify_opened(&self, repository: &git2::Repository) -> Result<(), PortError> {
        tools::verify_revision(repository, &self.revision)?;
        let current_identity = paths::directory_binding_identity(&self.locator.canonical_workdir)?;
        let expected_root = derive_worktree_root(
            &self.task_id,
            &self.locator,
            &self.revision,
            &current_identity,
        )?;
        if current_identity != self.worktree_identity || expected_root != self.root_identity {
            return Err(paths::conflict());
        }
        Ok(())
    }
}

fn derive_worktree_root(
    task_id: &TaskId,
    locator: &RepositoryLocator,
    revision: &GitObjectId,
    worktree_identity: &[u8],
) -> Result<CapabilityRootIdentity, PortError> {
    let mut hasher = Sha256::new();
    for part in [
        task_id.as_str().as_bytes(),
        locator.repository_id.as_str().as_bytes(),
        locator.stable_identity.as_bytes(),
        revision.as_str().as_bytes(),
        worktree_identity,
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
