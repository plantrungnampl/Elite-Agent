# Known M1 limitations

- Windows paths whose resolved checkout exceeds the current libgit2 path limit fail closed. Because target/worktree deletion cannot be made atomic with ownership comparison, failed creation preserves its branch/worktree/target attempt and reports a conflict for explicit recovery.
- The local verification account cannot create symbolic links directly, so the Windows matrix creates an inert NTFS junction as the equivalent reparse-point fixture. GitHub-hosted CI runs the same test.
- Network transports, credentials, hooks, filters, remote helpers, submodules, and LFS execution remain disabled and are represented only by inert, offline fixtures.
