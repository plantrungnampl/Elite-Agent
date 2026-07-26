# Known M1 limitations

- Windows paths whose resolved checkout exceeds the current libgit2 path limit fail closed; the adapter removes partial worktree metadata, target bytes, and its conditionally-created branch.
- The local verification account cannot create symbolic links directly, so the Windows matrix creates an inert NTFS junction as the equivalent reparse-point fixture. GitHub-hosted CI runs the same test.
- Network transports, credentials, hooks, filters, remote helpers, submodules, and LFS execution remain disabled and are represented only by inert, offline fixtures.
