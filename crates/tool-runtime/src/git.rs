use local_agent_terminal_application::{
    AuthorizedGitDiff, AuthorizedGitStatus, CapabilityResolver, GitDiffRequest, GitStatusRequest,
    PortError, RawGitDiffResult, RawGitStatusResult, ResolvedCapabilityTarget, StructuredGit,
};

use crate::capability::{denied, resolve};

pub(crate) fn status(
    resolver: &dyn CapabilityResolver,
    git: &dyn StructuredGit,
    request: GitStatusRequest,
) -> Result<RawGitStatusResult, PortError> {
    let resolved = resolve(resolver, &request.task_id, &request.worktree, None)?;
    if resolved.target != ResolvedCapabilityTarget::Root {
        return Err(denied());
    }
    git.status(AuthorizedGitStatus {
        task_id: request.task_id,
        worktree: request.worktree,
        root_identity: resolved.root_identity,
    })
}

pub(crate) fn diff(
    resolver: &dyn CapabilityResolver,
    git: &dyn StructuredGit,
    request: GitDiffRequest,
) -> Result<RawGitDiffResult, PortError> {
    let resolved = resolve(resolver, &request.task_id, &request.worktree, None)?;
    if resolved.target != ResolvedCapabilityTarget::Root {
        return Err(denied());
    }
    git.diff(AuthorizedGitDiff {
        task_id: request.task_id,
        worktree: request.worktree,
        root_identity: resolved.root_identity,
    })
}
