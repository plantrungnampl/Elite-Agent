use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Barrier};
use std::thread;

use local_agent_terminal_application::{
    AcquireLease, CreateWorktree, DiscardWorktree, ExecutorLeaseStore, InspectRepository,
    LeaseSnapshot, LeaseState, ManagedWorktreePath, PortError, ProcessFenceAuthority,
    RepositoryGateway, RepositoryLocator, RepositorySnapshot, RevokeLease,
    WorkspaceWriteCoordinator, WorktreeSnapshot,
};
use local_agent_terminal_domain::{
    FencingToken, GitObjectId, LeaseClaim, RepositoryId, RunId, TaskBranch, TaskId,
    WorkspaceVersion, WorktreeId,
};

#[test]
fn stale_token_is_rejected_before_the_repository_effect() {
    let leases = TestLeaseStore::at_token(2);
    let repositories = SpyRepository::default();
    let coordinator = WorkspaceWriteCoordinator::new();

    let error = coordinator
        .discard_worktree(&leases, &repositories, discard_request(1))
        .expect_err("stale request");

    assert!(matches!(
        error,
        PortError::StaleLease {
            current,
            supplied
        } if current.get() == 2 && supplied.get() == 1
    ));
    assert_eq!(repositories.discard_calls.load(Ordering::SeqCst), 0);
}

#[test]
fn current_token_is_checked_immediately_before_the_repository_effect() {
    let calls = Arc::new(std::sync::Mutex::new(Vec::new()));
    let leases = TestLeaseStore::with_calls(1, Arc::clone(&calls));
    let repositories = SpyRepository::with_calls(Arc::clone(&calls));
    let coordinator = WorkspaceWriteCoordinator::new();

    coordinator
        .discard_worktree(&leases, &repositories, discard_request(1))
        .expect("current request");

    assert_eq!(
        *calls.lock().expect("calls"),
        ["assert_current", "discard_worktree"]
    );
    assert_eq!(repositories.discard_calls.load(Ordering::SeqCst), 1);
}

#[test]
fn process_fence_bindings_compare_authority_identity() {
    let leases = Arc::new(TestLeaseStore::at_token(1));
    let writes = Arc::new(WorkspaceWriteCoordinator::new());
    let authority = ProcessFenceAuthority::new(leases.clone(), writes.clone());
    let separately_minted = ProcessFenceAuthority::new(leases, writes);

    assert_eq!(authority.binding(), authority.binding());
    assert_ne!(authority.binding(), separately_minted.binding());
}

#[test]
fn queued_old_request_cannot_write_after_lease_replacement() {
    let replace_entered = Arc::new(Barrier::new(2));
    let release_replacement = Arc::new(Barrier::new(2));
    let leases = Arc::new(TestLeaseStore::blocking_replacement(
        Arc::clone(&replace_entered),
        Arc::clone(&release_replacement),
    ));
    let repositories = Arc::new(SpyRepository::default());
    let coordinator = Arc::new(WorkspaceWriteCoordinator::new());

    let replacement = {
        let leases = Arc::clone(&leases);
        let coordinator = Arc::clone(&coordinator);
        thread::spawn(move || {
            coordinator
                .acquire_lease(
                    leases.as_ref(),
                    AcquireLease {
                        task_id: task_id(),
                        holder_run_id: RunId::new("run-2").expect("run"),
                        expected_fencing_epoch: 1,
                        acquired_at: "2026-07-26T00:00:01Z".to_owned(),
                        expires_at: "2026-07-26T01:00:01Z".to_owned(),
                    },
                )
                .expect("replacement")
        })
    };
    replace_entered.wait();

    let old_ready = Arc::new(Barrier::new(2));
    let old_request = {
        let leases = Arc::clone(&leases);
        let repositories = Arc::clone(&repositories);
        let coordinator = Arc::clone(&coordinator);
        let old_ready = Arc::clone(&old_ready);
        thread::spawn(move || {
            old_ready.wait();
            coordinator.discard_worktree(leases.as_ref(), repositories.as_ref(), discard_request(1))
        })
    };
    old_ready.wait();
    release_replacement.wait();

    assert_eq!(
        replacement.join().expect("replacement thread").token.get(),
        2
    );
    let error = old_request
        .join()
        .expect("old request thread")
        .expect_err("old request must be fenced");
    assert!(matches!(
        error,
        PortError::StaleLease {
            current,
            supplied
        } if current.get() == 2 && supplied.get() == 1
    ));
    assert_eq!(repositories.discard_calls.load(Ordering::SeqCst), 0);
}

struct TestLeaseStore {
    current: AtomicU64,
    calls: Option<Arc<std::sync::Mutex<Vec<&'static str>>>>,
    replace_entered: Option<Arc<Barrier>>,
    release_replacement: Option<Arc<Barrier>>,
}

impl TestLeaseStore {
    fn at_token(token: u64) -> Self {
        Self {
            current: AtomicU64::new(token),
            calls: None,
            replace_entered: None,
            release_replacement: None,
        }
    }

    fn with_calls(token: u64, calls: Arc<std::sync::Mutex<Vec<&'static str>>>) -> Self {
        Self {
            current: AtomicU64::new(token),
            calls: Some(calls),
            replace_entered: None,
            release_replacement: None,
        }
    }

    fn blocking_replacement(
        replace_entered: Arc<Barrier>,
        release_replacement: Arc<Barrier>,
    ) -> Self {
        Self {
            current: AtomicU64::new(1),
            calls: None,
            replace_entered: Some(replace_entered),
            release_replacement: Some(release_replacement),
        }
    }
}

impl ExecutorLeaseStore for TestLeaseStore {
    fn acquire(&self, request: AcquireLease) -> Result<LeaseSnapshot, PortError> {
        if let Some(barrier) = &self.replace_entered {
            barrier.wait();
        }
        if let Some(barrier) = &self.release_replacement {
            barrier.wait();
        }
        self.current.store(2, Ordering::SeqCst);
        Ok(LeaseSnapshot {
            task_id: request.task_id,
            holder_run_id: request.holder_run_id,
            token: FencingToken::new(2).expect("token"),
            state: LeaseState::Active,
            acquired_at: request.acquired_at,
            expires_at: request.expires_at,
            released_at: None,
        })
    }

    fn revoke(&self, _request: RevokeLease) -> Result<(), PortError> {
        unreachable!("not used by this contract")
    }

    fn fence_stale(&self) -> Result<Vec<LeaseSnapshot>, PortError> {
        unreachable!("not used by this contract")
    }

    fn assert_current(&self, claim: LeaseClaim) -> Result<(), PortError> {
        if let Some(calls) = &self.calls {
            calls.lock().expect("calls").push("assert_current");
        }
        let current = FencingToken::new(self.current.load(Ordering::SeqCst)).expect("token");
        if claim.token() != current {
            return Err(PortError::stale_lease(current, claim.token()));
        }
        Ok(())
    }
}

#[derive(Default)]
struct SpyRepository {
    discard_calls: AtomicUsize,
    calls: Option<Arc<std::sync::Mutex<Vec<&'static str>>>>,
}

impl SpyRepository {
    fn with_calls(calls: Arc<std::sync::Mutex<Vec<&'static str>>>) -> Self {
        Self {
            discard_calls: AtomicUsize::new(0),
            calls: Some(calls),
        }
    }
}

impl RepositoryGateway for SpyRepository {
    fn inspect(&self, _request: InspectRepository) -> Result<RepositorySnapshot, PortError> {
        unreachable!("not used by this contract")
    }

    fn create_worktree(&self, _request: CreateWorktree) -> Result<WorktreeSnapshot, PortError> {
        unreachable!("not used by this contract")
    }

    fn list_worktrees(
        &self,
        _repository: &RepositoryLocator,
    ) -> Result<Vec<WorktreeSnapshot>, PortError> {
        unreachable!("not used by this contract")
    }

    fn discard_worktree(&self, _request: DiscardWorktree) -> Result<(), PortError> {
        if let Some(calls) = &self.calls {
            calls.lock().expect("calls").push("discard_worktree");
        }
        self.discard_calls.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}

fn discard_request(token: u64) -> DiscardWorktree {
    DiscardWorktree {
        repository: RepositoryLocator {
            repository_id: RepositoryId::new("repository-1").expect("repository"),
            stable_identity: "repository-identity-1".to_owned(),
            canonical_workdir: PathBuf::from("C:/source"),
            canonical_common_dir: PathBuf::from("C:/source/.git"),
            object_format: local_agent_terminal_application::ObjectFormat::Sha1,
        },
        managed_path: ManagedWorktreePath {
            trusted_root_id: "managed-root-1".to_owned(),
            relative_leaf: PathBuf::from("worktree-task-1"),
            redacted_display: "<managed>/worktree-task-1".to_owned(),
        },
        task_id: task_id(),
        lease_claim: LeaseClaim::new(
            task_id(),
            RunId::new("run-1").expect("run"),
            FencingToken::new(token).expect("token"),
        ),
        expected_workspace_version: WorkspaceVersion::new(0),
        worktree_id: WorktreeId::new("worktree-task-1").expect("worktree"),
        branch: TaskBranch::new("codex/task-1").expect("branch"),
        base_commit: GitObjectId::new("1111111111111111111111111111111111111111")
            .expect("base commit"),
    }
}

fn task_id() -> TaskId {
    TaskId::new("task-1").expect("task")
}
