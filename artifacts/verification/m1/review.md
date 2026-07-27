# M1 independent review

## Independent approval: PASS

M1 is independently approved at source commit `a7c604a` with evidence commit `33de728`; the broad review baseline was `ed5a66f`. The first independent review found two Critical and two Important findings. Fix round 1 addressed the stale-poll overwrite, but re-review still found two Critical and two Important findings, including the newly identified `project.created` v1 compatibility regression. Fix round 2 closed the target-child checkout race, exact-discard tombstone race, changed-evidence onboarding recovery gap, and v1 compatibility regression. The final reviewer found every carried finding addressed and no new Critical or Important breakage.

One deferred Minor remains: a referenced Git object that is missing is classified as `NotFound` rather than `IntegrityFailure`. The path fails closed without fallback or side effect, so this diagnostic inconsistency does not block M1.

## Spec compliance: PASS

The Windows acceptance matrix covers repository identity and health, path and Git hazards, exact SHA-1/SHA-256 object IDs, worktree recovery, fencing, projections, approval invalidation, crash boundaries, browser recovery, and accessibility. Checkout materializes the exact commit tree through retained handle-relative Windows operations, rejects special entries and reparse escapes, and never delegates checkout to repository-controlled hooks, filters, helpers, LFS, submodules, PATH, or a shell. Exact discard renames and removes the verified tombstone through retained handles without reopening an attacker-replaceable pathname.

All hostile fixtures are local and inert, and their execution sentinels remain absent. Success and failure paths preserve the original checkout bytes, HEAD, and index. Startup recovery is idempotent across repository-evidence changes, preserves the stable v1 `project.created` payload contract, and never silently retries an unknown operation.

## Code quality: PASS

The final verification set passes formatting, clippy, all workspace targets, doctests, the frontend build, the Windows desktop build, architecture contracts, design contracts, and evidence gates. Focused counts are Windows matrix 33/33, SQLite recovery 14/14, bootstrap recovery 16/16, frontend 19, browser 5, post-final verifier contracts 14, and Node contracts 25. The React dashboard rejects stale polling responses with a monotonic generation guard, so mutation responses remain authoritative.

The implementation preserves clean-architecture direction: domain rules remain pure, application owns ports and DTOs, adapters implement those ports, Tauri stays narrow, and bootstrap remains the composition root.

## Evidence review: PASS

The finalized manifest binds source commit `a7c604a`, platform and toolchain versions, UTC timing, exit codes, captured output hashes, fixture classifications, and review artifacts. Independent verification rejects tampered output, stale source binding, unapproved tracked changes, and skipped post-final verifier contracts. The immutable design directory has no diff from `321734f`.

The existing limitations in `known-limitations.md` remain accurate and accepted for M1.
