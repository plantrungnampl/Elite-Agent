use local_agent_terminal_application::{
    AuthorizedGitDiff, AuthorizedGitStatus, CapabilityResolver, GitDiffResult, GitStatusResult,
    PortError, StructuredGit,
};

use crate::capability::resolve;

pub(crate) fn status(
    resolver: &dyn CapabilityResolver,
    git: &dyn StructuredGit,
    request: AuthorizedGitStatus,
) -> Result<GitStatusResult, PortError> {
    resolve(resolver, &request.task_id, &request.worktree, None)?;
    git.status(request)
}

pub(crate) fn diff(
    resolver: &dyn CapabilityResolver,
    git: &dyn StructuredGit,
    request: AuthorizedGitDiff,
) -> Result<GitDiffResult, PortError> {
    resolve(resolver, &request.task_id, &request.worktree, None)?;
    git.diff(request)
}
