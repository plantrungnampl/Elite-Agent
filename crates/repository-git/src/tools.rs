use std::fs;

use git2::{DiffFormat, DiffOptions};
use local_agent_terminal_application::{
    AuthorizedGitDiff, AuthorizedGitStatus, GitDiffResult, GitStatusResult, PortError,
    Retryability, SafeErrorClassification, StructuredGit,
};
use local_agent_terminal_domain::{CapabilityRef, GitObjectId, Sha256Digest};
use sha2::{Digest, Sha256};

use crate::{hazards, inspect, paths, GitStructuredTools};

const MAX_OUTPUT_BYTES: usize = 64 * 1024;

impl StructuredGit for GitStructuredTools {
    fn status(&self, request: AuthorizedGitStatus) -> Result<GitStatusResult, PortError> {
        self.authorize(&request.task_id, &request.worktree)?;
        let (repository, config) = paths::open_for_locator(&self.locator)?;
        self.reject_hazards(&repository, &config)?;
        let output = bounded_status(&repository)?;
        self.status_result(request, &repository, output)
    }

    fn diff(&self, request: AuthorizedGitDiff) -> Result<GitDiffResult, PortError> {
        self.authorize(&request.task_id, &request.worktree)?;
        let (repository, config) = paths::open_for_locator(&self.locator)?;
        self.reject_hazards(&repository, &config)?;
        let output = bounded_diff(&repository)?;
        self.diff_result(request, &repository, output)
    }
}

impl GitStructuredTools {
    fn authorize(
        &self,
        task_id: &local_agent_terminal_domain::TaskId,
        capability: &CapabilityRef,
    ) -> Result<(), PortError> {
        if task_id != &self.task_id
            || !matches!(capability, CapabilityRef::Worktree(worktree) if worktree.task_id() == task_id && worktree.path() == ".")
        {
            return Err(denied());
        }
        Ok(())
    }

    fn reject_hazards(
        &self,
        repository: &git2::Repository,
        config: &git2::Config,
    ) -> Result<(), PortError> {
        if !hazards::scan(repository, config)?.is_empty() || hostile_attributes(repository) {
            return Err(denied());
        }
        Ok(())
    }

    fn status_result(
        &self,
        request: AuthorizedGitStatus,
        repository: &git2::Repository,
        output: BoundedOutput,
    ) -> Result<GitStatusResult, PortError> {
        Ok(GitStatusResult {
            digest: digest(&output.bytes),
            repository_id: self.locator.repository_id.clone(),
            revision: revision(repository)?,
            path_scope: request.worktree,
            truncated: output.truncated,
            policy_decision_id: request.policy_decision_id,
        })
    }

    fn diff_result(
        &self,
        request: AuthorizedGitDiff,
        repository: &git2::Repository,
        output: BoundedOutput,
    ) -> Result<GitDiffResult, PortError> {
        Ok(GitDiffResult {
            digest: digest(&output.bytes),
            repository_id: self.locator.repository_id.clone(),
            revision: revision(repository)?,
            path_scope: request.worktree,
            truncated: output.truncated,
            policy_decision_id: request.policy_decision_id,
        })
    }
}

struct BoundedOutput {
    bytes: Vec<u8>,
    truncated: bool,
}

fn bounded_status(repository: &git2::Repository) -> Result<BoundedOutput, PortError> {
    let mut output = BoundedOutput {
        bytes: Vec::new(),
        truncated: false,
    };
    for (path, flags) in inspect::status_records(repository)? {
        append_bounded(&mut output, &path);
        append_bounded(&mut output, b"\t");
        append_bounded(&mut output, format!("{flags:08x}\n").as_bytes());
        if output.truncated {
            break;
        }
    }
    Ok(output)
}

fn bounded_diff(repository: &git2::Repository) -> Result<BoundedOutput, PortError> {
    let mut options = DiffOptions::new();
    options
        .include_untracked(false)
        .recurse_untracked_dirs(false);
    let diff = repository
        .diff_index_to_workdir(None, Some(&mut options))
        .map_err(paths::map_git_error)?;
    let mut output = BoundedOutput {
        bytes: Vec::new(),
        truncated: false,
    };
    let printed = diff.print(DiffFormat::Patch, |_delta, _hunk, line| {
        if output.bytes.len().saturating_add(line.content().len()) > MAX_OUTPUT_BYTES {
            output.truncated = true;
            return false;
        }
        output.bytes.extend_from_slice(line.content());
        true
    });
    if printed.is_err() && !output.truncated {
        return Err(denied());
    }
    Ok(output)
}

fn hostile_attributes(repository: &git2::Repository) -> bool {
    let Some(workdir) = repository.workdir() else {
        return true;
    };
    [".gitattributes", ".gitmodules", ".lfsconfig"]
        .into_iter()
        .any(|name| fs::symlink_metadata(workdir.join(name)).is_ok())
}

fn append_bounded(output: &mut BoundedOutput, bytes: &[u8]) {
    if output.bytes.len().saturating_add(bytes.len()) > MAX_OUTPUT_BYTES {
        output.truncated = true;
        return;
    }
    output.bytes.extend_from_slice(bytes);
}

fn revision(repository: &git2::Repository) -> Result<GitObjectId, PortError> {
    let oid = repository
        .head()
        .map_err(|_| denied())?
        .target()
        .ok_or_else(denied)?;
    GitObjectId::new(oid.to_string()).map_err(|_| denied())
}

fn digest(bytes: &[u8]) -> Sha256Digest {
    Sha256Digest::new(format!("sha256:{:x}", Sha256::digest(bytes)))
        .expect("SHA-256 formatting is valid")
}

fn denied() -> PortError {
    PortError::failure(
        SafeErrorClassification::PermissionDenied,
        Retryability::NonRetryable,
    )
}
