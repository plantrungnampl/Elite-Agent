use std::fs;

use git2::{ErrorCode, Oid, Repository, StatusOptions};
use local_agent_terminal_application::{
    InspectRepository, OriginalCheckoutState, PortError, RepositoryHazard, RepositoryHazardReason,
    RepositorySnapshot, WorktreeSnapshot,
};
use local_agent_terminal_domain::{GitObjectId, TaskBranch, WorkspaceFingerprint};
use sha2::{Digest, Sha256};

use crate::{hazards, paths, GitRepositoryGateway};

pub(crate) fn inspect(
    _gateway: &GitRepositoryGateway,
    request: InspectRepository,
) -> Result<RepositorySnapshot, PortError> {
    let (repository, config) = paths::open_for_locator(&request.locator)?;
    inspect_opened(&repository, &config, &request.locator)
}

pub(crate) fn inspect_opened(
    repository: &Repository,
    config: &git2::Config,
    locator: &local_agent_terminal_application::RepositoryLocator,
) -> Result<RepositorySnapshot, PortError> {
    let mut hazard_list = hazards::scan(repository, config);
    if !hazards::config_worktree_matches(repository) {
        hazard_list.push(RepositoryHazard {
            reason: RepositoryHazardReason::UnsafeConfiguration,
            detail: "core worktree is outside the opened checkout".to_owned(),
        });
    }
    let status_records = if hazard_list.iter().any(|hazard| {
        matches!(
            hazard.reason,
            RepositoryHazardReason::FiltersConfigured
                | RepositoryHazardReason::UnsafeConfiguration
                | RepositoryHazardReason::LfsConfigured
                | RepositoryHazardReason::SubmodulesPresent
        )
    }) {
        Vec::new()
    } else {
        status_records(repository)?
    };
    let dirty = !status_records.is_empty();
    let (mut original_checkout, default_branch, base_commit, head_oid) =
        head_snapshot(repository, &mut hazard_list);
    if dirty && original_checkout == OriginalCheckoutState::Clean {
        original_checkout = OriginalCheckoutState::Dirty;
    }
    let fingerprint = fingerprint(repository, head_oid, &status_records)?;
    let health = hazards::health(&hazard_list, dirty);
    Ok(RepositorySnapshot {
        repository_id: locator.repository_id.clone(),
        health,
        stable_identity: locator.stable_identity.clone(),
        default_branch,
        base_commit,
        original_checkout,
        hazards: hazard_list,
        fingerprint,
    })
}

pub(crate) fn status_records(repository: &Repository) -> Result<Vec<(Vec<u8>, u32)>, PortError> {
    let mut options = StatusOptions::new();
    options
        .include_untracked(true)
        .recurse_untracked_dirs(true)
        .include_ignored(false)
        .renames_head_to_index(false)
        .renames_index_to_workdir(false);
    let statuses = repository
        .statuses(Some(&mut options))
        .map_err(paths::map_git_error)?;
    let mut records = statuses
        .iter()
        .map(|entry| (entry.path_bytes().to_vec(), entry.status().bits()))
        .collect::<Vec<_>>();
    records.sort();
    Ok(records)
}

fn head_snapshot(
    repository: &Repository,
    hazards: &mut Vec<RepositoryHazard>,
) -> (
    OriginalCheckoutState,
    Option<TaskBranch>,
    Option<GitObjectId>,
    Oid,
) {
    let format = repository.object_format();
    let zero = match format {
        git2::ObjectFormat::Sha256 => Oid::ZERO_SHA256,
        _ => Oid::ZERO_SHA1,
    };
    let head = match repository.head() {
        Ok(head) => head,
        Err(error) if error.code() == ErrorCode::UnbornBranch => {
            return (OriginalCheckoutState::Unborn, None, None, zero)
        }
        Err(_) => return (OriginalCheckoutState::Unavailable, None, None, zero),
    };
    let Some(target) = head.target() else {
        return (OriginalCheckoutState::Unborn, None, None, zero);
    };
    let commit = GitObjectId::new(target.to_string()).ok();
    if !head.is_branch() {
        return (OriginalCheckoutState::Detached, None, commit, target);
    }
    let branch = head
        .shorthand()
        .ok()
        .and_then(|value| TaskBranch::new(value).ok());
    if branch.is_none() {
        hazards.push(RepositoryHazard {
            reason: RepositoryHazardReason::PathConflict,
            detail: "HEAD branch name is not a managed branch".to_owned(),
        });
    }
    (OriginalCheckoutState::Clean, branch, commit, target)
}

pub(crate) fn fingerprint(
    repository: &Repository,
    head: Oid,
    status_records: &[(Vec<u8>, u32)],
) -> Result<WorkspaceFingerprint, PortError> {
    let head = GitObjectId::new(head.to_string()).map_err(|_| paths::integrity())?;
    let index_bytes = repository
        .index()
        .map_err(paths::map_git_error)?
        .path()
        .and_then(|path| fs::read(path).ok())
        .unwrap_or_default();
    let index_digest = digest(&index_bytes);
    let mut status_bytes = Vec::new();
    for (path, flags) in status_records {
        status_bytes.extend_from_slice(&(path.len() as u64).to_be_bytes());
        status_bytes.extend_from_slice(path);
        status_bytes.extend_from_slice(&flags.to_be_bytes());
    }
    let status_digest = digest(&status_bytes);
    WorkspaceFingerprint::new(head, index_digest, status_digest).map_err(|_| paths::integrity())
}

fn digest(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("sha256:{}", paths::hex_digest(hasher.finalize().as_slice()))
}

pub(crate) struct WorktreeSnapshotInput {
    pub(crate) worktree_id: local_agent_terminal_domain::WorktreeId,
    pub(crate) task_id: local_agent_terminal_domain::TaskId,
    pub(crate) branch: TaskBranch,
    pub(crate) base_commit: GitObjectId,
    pub(crate) target_path_display: String,
    pub(crate) state: local_agent_terminal_application::WorktreeState,
    pub(crate) expected_presence: local_agent_terminal_application::ExpectedPresence,
}

pub(crate) fn worktree_snapshot(
    repository: &Repository,
    locator: &local_agent_terminal_application::RepositoryLocator,
    input: WorktreeSnapshotInput,
) -> Result<WorktreeSnapshot, PortError> {
    let statuses = status_records(repository)?;
    let head = repository
        .head()
        .ok()
        .and_then(|head| head.target())
        .unwrap_or_else(|| match repository.object_format() {
            git2::ObjectFormat::Sha256 => Oid::ZERO_SHA256,
            _ => Oid::ZERO_SHA1,
        });
    Ok(WorktreeSnapshot {
        worktree_id: input.worktree_id,
        repository_id: locator.repository_id.clone(),
        repository_identity: locator.stable_identity.clone(),
        task_id: input.task_id,
        branch: input.branch,
        base_commit: input.base_commit,
        target_path_display: input.target_path_display,
        state: input.state,
        expected_presence: input.expected_presence,
        fingerprint: fingerprint(repository, head, &statuses)?,
    })
}
