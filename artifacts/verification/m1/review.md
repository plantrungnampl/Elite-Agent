# M1 review

## Spec compliance: pass

The Windows acceptance matrix covers the repository, path, Git-configuration, object-format, recovery, fencing, projection, approval invalidation, browser, and crash-boundary cases listed in the M1 Task 9 brief. Mandatory approval evidence is available for checkout filter disabling, path containment, exact SHA-256 object IDs, non-forcing conditional references, managed worktrees, and LFS/submodule fail-closed handling.

All hostile fixtures are local and inert. Each execution-capable fixture has its own marker-producing sentinel, and the matrix proves every marker remains absent. The production repository adapter uses typed in-process `git2`/libgit2 calls only; the architecture gate rejects direct, grouped, and aliased process/PATH access. Original checkout bytes, HEAD, and index are asserted unchanged across success and failure cases.

## Code quality: pass

The focused Windows matrices, complete Rust workspace, clippy, formatting, Node contracts, frontend unit tests, real-browser accessibility/recovery tests, frontend build, and Windows desktop debug build pass. Every post-add validation boundary is fault-injected. Rollback locks and re-reads the exact ref, revalidates the exact worktree path and repository identity, and preserves concurrently replaced branch or target state as a conflict.

## Evidence review: pass

The manifest is generated only after the gates run. It binds the source commit, platform, toolchain, UTC start times, durations, exit codes, and independently re-hashed captured output files to each fixture classification. The verifier is intentionally outside the manifest, rejects tampered logs and stale commits, and derives approval blockers from observed test names. The immutable design directory has no diff from `321734f`.
