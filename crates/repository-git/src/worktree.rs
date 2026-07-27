use std::ffi::OsString;
use std::fs;
use std::path::Path;

use git2::{Oid, ReferenceType, Repository, WorktreePruneOptions};
use local_agent_terminal_application::{
    CreateWorktree, DiscardWorktree, ExpectedPresence, InspectWorktree, OriginalCheckoutState,
    PortError, RecoveryReason, WorktreeObservation, WorktreeSnapshot, WorktreeState,
};
use local_agent_terminal_domain::{GitObjectId, TaskBranch, TaskId, WorktreeId};

use crate::{inspect, paths, unsafe_checkout, GitRepositoryGateway};

pub(crate) fn create(
    gateway: &GitRepositoryGateway,
    request: CreateWorktree,
) -> Result<WorktreeSnapshot, PortError> {
    let target = paths::managed_path(gateway, &request.managed_path)?;
    let (repository, config) = paths::open_for_locator(&request.repository)?;
    if paths_overlap(&target, &request.repository.canonical_workdir)
        || paths_overlap(&target, &request.repository.canonical_common_dir)
    {
        return Err(paths::conflict());
    }
    let before = inspect::inspect_opened(&repository, &config, &request.repository)?;
    if !before.hazards.is_empty() || before.original_checkout != OriginalCheckoutState::Clean {
        return Err(paths::conflict());
    }
    let expected_base = before.base_commit.clone().ok_or_else(paths::conflict)?;
    if expected_base != request.base_commit {
        return Err(paths::conflict());
    }
    let oid = parse_oid(&repository, &request.base_commit)?;
    let reference_name = format!("refs/heads/{}", request.branch.as_str());
    if repository
        .find_reference(&reference_name)
        .map(|_| true)
        .or_else(|error| {
            if error.code() == git2::ErrorCode::NotFound {
                Ok(false)
            } else {
                Err(error)
            }
        })
        .map_err(paths::map_git_error)?
    {
        return Err(paths::conflict());
    }
    let zero = zero_oid(&repository);
    let reference = repository
        .reference_matching(
            &reference_name,
            oid,
            false,
            zero,
            "local-agent-terminal create managed worktree",
        )
        .map_err(paths::map_git_error)?;
    let worktree_name = request.worktree_id.as_str().to_owned();
    validate_worktree_name(&worktree_name)?;
    let parent_guard = paths::DirectoryGuard::open(target.parent().ok_or_else(paths::invalid)?)?;
    pause_before_checkout(gateway);
    let added = match unsafe_checkout::add(
        &repository,
        &worktree_name,
        &target,
        &reference,
        &parent_guard,
        #[cfg(feature = "test-seams")]
        gateway,
    ) {
        Ok(worktree) => worktree,
        Err(_error) => {
            drop(reference);
            return Err(preserve_failed_create(
                gateway,
                &repository,
                FailedCreate {
                    worktree_name: &worktree_name,
                    target: &target,
                    reference_name: &reference_name,
                    expected_oid: oid,
                    locator: &request.repository,
                    branch: &request.branch,
                },
            ));
        }
    };
    let unsafe_checkout::AddedWorktree {
        worktree,
        target_guard,
    } = added;
    drop(reference);
    let result = (|| {
        fail_after(gateway, PostAddPoint::Add)?;
        parent_guard.verify()?;
        target_guard.verify()?;
        fail_after(gateway, PostAddPoint::ParentVerify)?;
        let target_path = paths::validate_existing_target(gateway, &target)?;
        if target_path != target {
            return Err(paths::conflict());
        }
        fail_after(gateway, PostAddPoint::TargetValidate)?;
        let target_repository = paths::open_repository(&target)?;
        fail_after(gateway, PostAddPoint::TargetOpen)?;
        let target_config = git2::Config::open(&repository.path().join("config"))
            .map_err(|_| paths::unavailable())?;
        target_repository
            .set_config(&target_config)
            .map_err(|_| paths::unavailable())?;
        fail_after(gateway, PostAddPoint::ConfigAttach)?;
        let target_snapshot = inspect::worktree_snapshot(
            &target_repository,
            &request.repository,
            inspect::WorktreeSnapshotInput {
                worktree_id: request.worktree_id.clone(),
                task_id: request.task_id.clone(),
                branch: request.branch.clone(),
                base_commit: request.base_commit.clone(),
                target_path_display: request.managed_path.redacted_display.clone(),
                state: WorktreeState::Present,
                expected_presence: ExpectedPresence::Present,
            },
        )?;
        fail_after(gateway, PostAddPoint::Snapshot)?;
        let current_reference = repository
            .find_reference(&reference_name)
            .map_err(paths::map_git_error)?;
        if current_reference.target() != Some(oid) {
            return Err(paths::conflict());
        }
        fail_after(gateway, PostAddPoint::RefVerify)?;
        let after = inspect::inspect_opened(&repository, &config, &request.repository)?;
        if before.fingerprint != after.fingerprint
            || before.default_branch != after.default_branch
            || before.base_commit != after.base_commit
        {
            return Err(paths::conflict());
        }
        fail_after(gateway, PostAddPoint::OriginalVerify)?;
        Ok(target_snapshot)
    })();
    match result {
        Ok(snapshot) => {
            drop(worktree);
            drop(target_guard);
            Ok(snapshot)
        }
        Err(_error) => {
            drop(worktree);
            drop(target_guard);
            Err(preserve_failed_create(
                gateway,
                &repository,
                FailedCreate {
                    worktree_name: &worktree_name,
                    target: &target,
                    reference_name: &reference_name,
                    expected_oid: oid,
                    locator: &request.repository,
                    branch: &request.branch,
                },
            ))
        }
    }
}

pub(crate) fn list(
    gateway: &GitRepositoryGateway,
    locator: &local_agent_terminal_application::RepositoryLocator,
) -> Result<Vec<WorktreeSnapshot>, PortError> {
    let (repository, _config) = paths::open_for_locator(locator)?;
    let names = repository.worktrees().map_err(paths::map_git_error)?;
    let source_head = repository
        .head()
        .ok()
        .and_then(|head| head.target())
        .unwrap_or_else(|| zero_oid(&repository));
    let source_base = GitObjectId::new(source_head.to_string()).map_err(|_| paths::integrity())?;
    let source_branch = repository
        .head()
        .ok()
        .and_then(|head| head.shorthand().ok().map(str::to_owned))
        .and_then(|name| TaskBranch::new(name).ok())
        .unwrap_or_else(|| TaskBranch::new("recovered/unknown").expect("static branch"));
    let mut snapshots = Vec::new();
    for name in names.iter() {
        let Some(name) = name.map_err(|_| paths::integrity())? else {
            return Err(paths::integrity());
        };
        let worktree_id = WorktreeId::new(name).map_err(|_| paths::conflict())?;
        let worktree = repository
            .find_worktree(name)
            .map_err(paths::map_git_error)?;
        let path = worktree.path().to_path_buf();
        let display = path
            .strip_prefix(&gateway.trusted_workspace_root)
            .ok()
            .map(|path| path.to_string_lossy().replace('\\', "/"))
            .unwrap_or_else(|| "<outside-managed-root>".to_owned());
        let task_id = TaskId::new(format!("recovered-{name}")).map_err(|_| paths::integrity())?;
        let Some(target) = path.as_path().is_dir().then_some(path.clone()) else {
            let fingerprint = inspect::fingerprint(&repository, source_head, &[])?;
            snapshots.push(WorktreeSnapshot {
                worktree_id,
                repository_id: locator.repository_id.clone(),
                repository_identity: locator.stable_identity.clone(),
                task_id,
                branch: source_branch.clone(),
                base_commit: source_base.clone(),
                target_path_display: display,
                state: WorktreeState::Missing,
                expected_presence: ExpectedPresence::Present,
                fingerprint,
            });
            continue;
        };
        let target = match paths::canonical_directory(&target) {
            Ok(target) => target,
            Err(_) => {
                let fingerprint = inspect::fingerprint(&repository, source_head, &[])?;
                snapshots.push(WorktreeSnapshot {
                    worktree_id,
                    repository_id: locator.repository_id.clone(),
                    repository_identity: locator.stable_identity.clone(),
                    task_id,
                    branch: source_branch.clone(),
                    base_commit: source_base.clone(),
                    target_path_display: display,
                    state: WorktreeState::Conflict,
                    expected_presence: ExpectedPresence::Present,
                    fingerprint,
                });
                continue;
            }
        };
        if !paths::is_within(&gateway.trusted_workspace_root, &target)
            || paths::is_excluded(gateway, &target)
            || worktree.validate().is_err()
        {
            let fingerprint = inspect::fingerprint(&repository, source_head, &[])?;
            snapshots.push(WorktreeSnapshot {
                worktree_id,
                repository_id: locator.repository_id.clone(),
                repository_identity: locator.stable_identity.clone(),
                task_id,
                branch: source_branch.clone(),
                base_commit: source_base.clone(),
                target_path_display: display,
                state: WorktreeState::Conflict,
                expected_presence: ExpectedPresence::Present,
                fingerprint,
            });
            continue;
        }
        let target_repository = paths::open_repository(&target)?;
        let target_config = git2::Config::open(&repository.path().join("config"))
            .map_err(|_| paths::unavailable())?;
        target_repository
            .set_config(&target_config)
            .map_err(|_| paths::unavailable())?;
        let target_head = target_repository
            .head()
            .ok()
            .and_then(|head| head.target())
            .unwrap_or(source_head);
        let target_base =
            GitObjectId::new(target_head.to_string()).map_err(|_| paths::integrity())?;
        let target_branch = target_repository
            .head()
            .ok()
            .and_then(|head| head.shorthand().ok().map(str::to_owned))
            .and_then(|name| TaskBranch::new(name).ok())
            .unwrap_or_else(|| source_branch.clone());
        snapshots.push(inspect::worktree_snapshot(
            &target_repository,
            locator,
            inspect::WorktreeSnapshotInput {
                worktree_id,
                task_id,
                branch: target_branch,
                base_commit: target_base,
                target_path_display: display,
                state: WorktreeState::Present,
                expected_presence: ExpectedPresence::Present,
            },
        )?);
    }
    Ok(snapshots)
}

pub(crate) fn discard(
    gateway: &GitRepositoryGateway,
    request: DiscardWorktree,
) -> Result<(), PortError> {
    let target = gateway
        .trusted_workspace_root
        .join(&request.managed_path.relative_leaf);
    let target = paths::validate_existing_target(gateway, &target)?;
    let (repository, _config) = paths::open_for_locator(&request.repository)?;
    let worktree = repository
        .find_worktree(request.worktree_id.as_str())
        .map_err(paths::map_git_error)?;
    let recorded_path = paths::canonical_directory(worktree.path())?;
    if recorded_path != target {
        return Err(paths::conflict());
    }
    if recorded_path == request.repository.canonical_workdir
        || paths::is_within(&request.repository.canonical_common_dir, &recorded_path)
        || paths::is_within(&recorded_path, &request.repository.canonical_common_dir)
        || paths::is_within(&recorded_path, &request.repository.canonical_workdir)
    {
        return Err(paths::conflict());
    }
    let target_repository = paths::open_repository(&target)?;
    let head = target_repository.head().map_err(paths::map_git_error)?;
    let target_oid = head.target().ok_or_else(paths::conflict)?;
    let expected_oid = parse_oid(&repository, &request.base_commit)?;
    if target_oid != expected_oid
        || head
            .shorthand()
            .ok()
            .and_then(|name| TaskBranch::new(name).ok())
            .as_ref()
            != Some(&request.branch)
    {
        return Err(paths::conflict());
    }
    let reference_name = format!("refs/heads/{}", request.branch.as_str());
    let reference = repository
        .find_reference(&reference_name)
        .map_err(paths::map_git_error)?;
    if reference.kind() != Some(ReferenceType::Direct) || reference.target() != Some(expected_oid) {
        return Err(paths::conflict());
    }
    reject_reparse_root(&target)?;
    pause_after_discard_validation(gateway);
    let parent_guard = paths::DirectoryGuard::open(target.parent().ok_or_else(paths::invalid)?)?;
    let mut target_guard = paths::DirectoryGuard::open_child_for_rename(&parent_guard, &target)?;
    revalidate_discard_target(
        &repository,
        &request,
        &target,
        expected_oid,
        &reference_name,
    )?;
    target_guard.verify()?;
    let mut reference_transaction = repository.transaction().map_err(paths::map_git_error)?;
    reference_transaction
        .lock_ref(&reference_name)
        .map_err(paths::map_git_error)?;
    let locked_reference = repository
        .find_reference(&reference_name)
        .map_err(paths::map_git_error)?;
    if locked_reference.kind() != Some(ReferenceType::Direct)
        || locked_reference.target() != Some(expected_oid)
    {
        return Err(paths::conflict());
    }
    drop(locked_reference);
    reference_transaction
        .remove(&reference_name)
        .map_err(paths::map_git_error)?;
    drop(head);
    drop(target_repository);
    drop(reference);
    let tombstone_leaf = discard_tombstone(&request.worktree_id)?;
    let tombstone = target_guard.rename_to(&parent_guard, &tombstone_leaf)?;
    drop(target_guard);
    fs::remove_dir_all(&tombstone).map_err(|_| paths::conflict())?;
    worktree.unlock().map_err(paths::map_git_error)?;
    let mut prune = WorktreePruneOptions::new();
    worktree
        .prune(Some(&mut prune))
        .map_err(paths::map_git_error)?;
    reference_transaction
        .commit()
        .map_err(paths::map_git_error)?;
    Ok(())
}

fn revalidate_discard_target(
    repository: &Repository,
    request: &DiscardWorktree,
    target: &Path,
    expected_oid: Oid,
    reference_name: &str,
) -> Result<(), PortError> {
    let worktree = repository
        .find_worktree(request.worktree_id.as_str())
        .map_err(|_| paths::conflict())?;
    if paths::canonical_directory(worktree.path()).map_err(|_| paths::conflict())? != target {
        return Err(paths::conflict());
    }
    let target_repository = paths::open_repository(target).map_err(|_| paths::conflict())?;
    if paths::canonical_directory(target_repository.commondir()).map_err(|_| paths::conflict())?
        != request.repository.canonical_common_dir
    {
        return Err(paths::conflict());
    }
    let head = target_repository.head().map_err(|_| paths::conflict())?;
    if head.target() != Some(expected_oid)
        || head.name().ok() != Some(reference_name)
        || head.shorthand().ok() != Some(request.branch.as_str())
    {
        return Err(paths::conflict());
    }
    Ok(())
}

fn discard_tombstone(worktree_id: &WorktreeId) -> Result<OsString, PortError> {
    let mut nonce = [0_u8; 16];
    getrandom::fill(&mut nonce).map_err(|_| paths::unavailable())?;
    Ok(OsString::from(format!(
        ".local-agent-terminal-discard-{}-{}",
        worktree_id.as_str(),
        paths::hex_digest(&nonce)
    )))
}

pub(crate) fn inspect_expected(
    gateway: &GitRepositoryGateway,
    request: InspectWorktree,
) -> Result<WorktreeObservation, PortError> {
    let target = paths::recovery_path(gateway, &request.managed_path)?;
    let (repository, config) = paths::open_for_locator(&request.repository)?;
    let repository_snapshot = inspect::inspect_opened(&repository, &config, &request.repository)?;
    if !repository_snapshot.hazards.is_empty()
        || paths_overlap(&target, &request.repository.canonical_workdir)
        || paths_overlap(&target, &request.repository.canonical_common_dir)
    {
        return Ok(WorktreeObservation::Conflict(
            RecoveryReason::RepositoryMismatch,
        ));
    }
    let worktree = optional_git(repository.find_worktree(request.worktree_id.as_str()))?;
    let reference_name = format!("refs/heads/{}", request.branch.as_str());
    let reference = optional_git(repository.find_reference(&reference_name))?;
    let target_exists = match fs::symlink_metadata(&target) {
        Ok(_) => true,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
        Err(_) => return Err(paths::unavailable()),
    };
    if worktree.is_none() && reference.is_none() && !target_exists {
        return Ok(WorktreeObservation::AuthoritativelyAbsent);
    }
    let (Some(worktree), Some(reference)) = (worktree, reference) else {
        return Ok(WorktreeObservation::Conflict(
            RecoveryReason::PresenceMismatch,
        ));
    };
    if !target_exists
        || reference.kind() != Some(ReferenceType::Direct)
        || reference.target() != Some(parse_oid(&repository, &request.base_commit)?)
        || worktree.validate().is_err()
    {
        return Ok(WorktreeObservation::Conflict(
            RecoveryReason::PresenceMismatch,
        ));
    }
    let recorded_path = match paths::canonical_directory(worktree.path()) {
        Ok(path) => path,
        Err(_) => return Ok(WorktreeObservation::Conflict(RecoveryReason::PathMismatch)),
    };
    let target = match paths::validate_existing_target(gateway, &target) {
        Ok(path) => path,
        Err(_) => return Ok(WorktreeObservation::Conflict(RecoveryReason::PathMismatch)),
    };
    if recorded_path != target {
        return Ok(WorktreeObservation::Conflict(RecoveryReason::PathMismatch));
    }
    let target_repository = match paths::open_repository(&target) {
        Ok(repository) => repository,
        Err(_) => {
            return Ok(WorktreeObservation::Conflict(
                RecoveryReason::PresenceMismatch,
            ))
        }
    };
    if paths::canonical_directory(target_repository.commondir())?
        != request.repository.canonical_common_dir
    {
        return Ok(WorktreeObservation::Conflict(
            RecoveryReason::RepositoryMismatch,
        ));
    }
    let head = target_repository.head().map_err(paths::map_git_error)?;
    if head.target() != Some(parse_oid(&repository, &request.base_commit)?)
        || head.shorthand().ok() != Some(request.branch.as_str())
    {
        return Ok(WorktreeObservation::Conflict(
            RecoveryReason::BranchMismatch,
        ));
    }
    let target_config =
        git2::Config::open(&repository.path().join("config")).map_err(|_| paths::unavailable())?;
    target_repository
        .set_config(&target_config)
        .map_err(|_| paths::unavailable())?;
    let snapshot = inspect::worktree_snapshot(
        &target_repository,
        &request.repository,
        inspect::WorktreeSnapshotInput {
            worktree_id: request.worktree_id,
            task_id: request.task_id,
            branch: request.branch,
            base_commit: request.base_commit,
            target_path_display: request.managed_path.redacted_display,
            state: WorktreeState::Present,
            expected_presence: ExpectedPresence::Present,
        },
    )?;
    Ok(WorktreeObservation::Exact(Box::new(snapshot)))
}

fn parse_oid(repository: &Repository, value: &GitObjectId) -> Result<Oid, PortError> {
    Oid::from_str_ext(value.as_str(), repository.object_format()).map_err(paths::map_git_error)
}

fn zero_oid(repository: &Repository) -> Oid {
    match repository.object_format() {
        git2::ObjectFormat::Sha256 => Oid::ZERO_SHA256,
        _ => Oid::ZERO_SHA1,
    }
}

fn validate_worktree_name(name: &str) -> Result<(), PortError> {
    if name.is_empty()
        || name == "."
        || name == ".."
        || name.contains('/')
        || name.contains('\\')
        || name.contains("..")
        || name.bytes().any(|byte| byte <= b' ' || byte == 0x7f)
    {
        return Err(paths::invalid());
    }
    Ok(())
}

fn reject_reparse_root(path: &Path) -> Result<(), PortError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| paths::not_found())?;
    if metadata.file_type().is_symlink() {
        return Err(paths::conflict());
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
        if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(paths::conflict());
        }
    }
    Ok(())
}

struct FailedCreate<'a> {
    worktree_name: &'a str,
    target: &'a Path,
    reference_name: &'a str,
    expected_oid: Oid,
    locator: &'a local_agent_terminal_application::RepositoryLocator,
    branch: &'a TaskBranch,
}

fn preserve_failed_create(
    gateway: &GitRepositoryGateway,
    repository: &Repository,
    attempt: FailedCreate<'_>,
) -> PortError {
    let _owned_attempt_observed = failed_create_still_matches(
        repository,
        attempt.worktree_name,
        attempt.target,
        attempt.reference_name,
        attempt.expected_oid,
        attempt.locator,
        attempt.branch,
    );
    pause_after_cleanup_ownership_check(gateway);
    // Target paths and worktree metadata do not expose an atomic compare-and-delete
    // operation. Preserve all attempt state so a concurrent replacement can never
    // be deleted after a successful ownership observation.
    paths::conflict()
}

fn failed_create_still_matches(
    repository: &Repository,
    worktree_name: &str,
    target: &Path,
    reference_name: &str,
    expected_oid: Oid,
    locator: &local_agent_terminal_application::RepositoryLocator,
    branch: &TaskBranch,
) -> bool {
    let reference_matches = repository
        .find_reference(reference_name)
        .map(|reference| {
            reference.kind() == Some(ReferenceType::Direct)
                && reference.target() == Some(expected_oid)
        })
        .unwrap_or(false);
    let worktree_matches = repository
        .find_worktree(worktree_name)
        .ok()
        .and_then(|worktree| paths::canonical_directory(worktree.path()).ok())
        .is_some_and(|path| path == target);
    let target_matches = paths::canonical_directory(target)
        .ok()
        .filter(|path| path == target)
        .and_then(|path| paths::open_repository(&path).ok())
        .is_some_and(|target_repository| {
            paths::canonical_directory(target_repository.commondir())
                .is_ok_and(|common_dir| common_dir == locator.canonical_common_dir)
                && target_repository.head().is_ok_and(|head| {
                    head.target() == Some(expected_oid)
                        && head.name().ok() == Some(reference_name)
                        && head.shorthand().ok() == Some(branch.as_str())
                })
        });
    reference_matches && worktree_matches && target_matches
}

#[derive(Clone, Copy)]
enum PostAddPoint {
    Add,
    ParentVerify,
    TargetValidate,
    TargetOpen,
    ConfigAttach,
    Snapshot,
    RefVerify,
    OriginalVerify,
}

#[cfg(feature = "test-seams")]
fn fail_after(gateway: &GitRepositoryGateway, point: PostAddPoint) -> Result<(), PortError> {
    use crate::PostAddStage;

    let stage = match point {
        PostAddPoint::Add => PostAddStage::AfterAdd,
        PostAddPoint::ParentVerify => PostAddStage::AfterParentVerify,
        PostAddPoint::TargetValidate => PostAddStage::AfterTargetValidate,
        PostAddPoint::TargetOpen => PostAddStage::AfterTargetOpen,
        PostAddPoint::ConfigAttach => PostAddStage::AfterConfigAttach,
        PostAddPoint::Snapshot => PostAddStage::AfterSnapshot,
        PostAddPoint::RefVerify => PostAddStage::AfterRefVerify,
        PostAddPoint::OriginalVerify => PostAddStage::AfterOriginalVerify,
    };
    if gateway.test_hooks.fail_at == Some(stage) {
        Err(paths::unavailable())
    } else {
        Ok(())
    }
}

#[cfg(not(feature = "test-seams"))]
fn fail_after(_gateway: &GitRepositoryGateway, _point: PostAddPoint) -> Result<(), PortError> {
    Ok(())
}

#[cfg(feature = "test-seams")]
fn pause_before_checkout(gateway: &GitRepositoryGateway) {
    if let Some(barrier) = &gateway.test_hooks.before_checkout {
        barrier.wait();
        barrier.wait();
    }
}

#[cfg(not(feature = "test-seams"))]
fn pause_before_checkout(_gateway: &GitRepositoryGateway) {}

#[cfg(feature = "test-seams")]
fn pause_after_cleanup_ownership_check(gateway: &GitRepositoryGateway) {
    if let Some(barrier) = &gateway.test_hooks.after_cleanup_ownership_check {
        barrier.wait();
        barrier.wait();
    }
}

#[cfg(not(feature = "test-seams"))]
fn pause_after_cleanup_ownership_check(_gateway: &GitRepositoryGateway) {}

#[cfg(feature = "test-seams")]
fn pause_after_discard_validation(gateway: &GitRepositoryGateway) {
    if let Some(barrier) = &gateway.test_hooks.after_discard_validation {
        barrier.wait();
        barrier.wait();
    }
}

#[cfg(not(feature = "test-seams"))]
fn pause_after_discard_validation(_gateway: &GitRepositoryGateway) {}

fn paths_overlap(left: &Path, right: &Path) -> bool {
    paths::is_within(left, right) || paths::is_within(right, left)
}

fn optional_git<T>(result: Result<T, git2::Error>) -> Result<Option<T>, PortError> {
    match result {
        Ok(value) => Ok(Some(value)),
        Err(error) if error.code() == git2::ErrorCode::NotFound => Ok(None),
        Err(error) => Err(paths::map_git_error(error)),
    }
}
