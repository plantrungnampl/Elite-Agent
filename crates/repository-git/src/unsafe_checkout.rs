use std::path::Path;

use git2::{Reference, Repository, Worktree, WorktreeAddOptions};
use local_agent_terminal_application::PortError;

use crate::paths;

pub(crate) fn add(
    repository: &Repository,
    name: &str,
    path: &Path,
    reference: &Reference<'_>,
) -> Result<Worktree, PortError> {
    let mut options = WorktreeAddOptions::new();
    options
        .lock(true)
        .checkout_existing(false)
        .reference(Some(reference));
    if !disable_filters(&mut options) {
        return Err(paths::unavailable());
    }
    repository
        .worktree(name, path, Some(&options))
        .map_err(paths::map_git_error)
}

fn disable_filters(options: &mut WorktreeAddOptions<'_>) -> bool {
    // The git2 0.21 wrapper exposes the worktree options as an opaque pointer.
    // libgit2-sys 0.18.4 is pinned to the exact layout used here.
    let raw = options.raw() as *mut libgit2_sys::git_worktree_add_options;
    // SAFETY: `WorktreeAddOptions::raw` points to its initialized in-place
    // libgit2-sys representation and the dependency version is pinned.
    unsafe {
        if (*raw).version != libgit2_sys::GIT_WORKTREE_ADD_OPTIONS_VERSION
            || (*raw).checkout_options.version != libgit2_sys::GIT_CHECKOUT_OPTIONS_VERSION
        {
            return false;
        }
        (*raw).checkout_options.disable_filters = 1;
    }
    true
}

#[cfg(test)]
mod tests {
    use git2::WorktreeAddOptions;

    #[test]
    fn checkout_option_layout_sentinel_is_supported() {
        let mut options = WorktreeAddOptions::new();
        assert!(super::disable_filters(&mut options));
    }
}
