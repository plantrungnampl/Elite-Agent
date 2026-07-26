# Known M1 limitations

- Windows paths whose resolved checkout exceeds the current libgit2 path limit fail closed. Owned branch/worktree/target state is removed only after exact identity checks; ambiguous or concurrently replaced state is preserved and reported as a conflict for recovery.
- The local verification account cannot create symbolic links directly, so the Windows matrix creates an inert NTFS junction as the equivalent reparse-point fixture. GitHub-hosted CI runs the same test.
- Network transports, credentials, hooks, filters, remote helpers, submodules, and LFS execution remain disabled and are represented only by inert, offline fixtures.
