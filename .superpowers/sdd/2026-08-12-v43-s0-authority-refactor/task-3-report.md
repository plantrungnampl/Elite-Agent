# Task 3 report: SQLite v7 authority

Date: 2026-08-12

Base: `086fe55a63ea`

Commit subject: `feat: install sqlite v7 authority`

## Scope implemented

- Replaced the application migration-number chain with structural schema recognition.
- Embedded and executed the exact normative `sqlite-v6.sql`, `sqlite-v7.sql`, and
  `migrate-v6-to-v7.sql` scripts.
- Compared every non-internal `sqlite_schema` object as normalized
  `(type, name, tbl_name, sql)` data. A version row is never trusted as identity.
- Empty databases install v7; exact v6 migrates; exact v7 and exact v7 plus the
  adapter projections reopen; all other non-empty surfaces return
  `OpenError::UnsupportedSchema { found: 0, supported: 7 }`.
- Unsupported databases are recognized before runtime pragmas are changed.
- Installed only live, non-authoritative adapter projections absent from v7:
  `agent_run_outputs`, `deliberation_records`, task budgets and dispatch
  reservations, repository baseline/boundary records, synthesis plans,
  specialist threads/dispatches, and context-package invalidations, together
  with their indexes and immutability guards.
- The projection script contains no insert or update of
  `task_workflow_authority`; clean installation creates no compatibility
  Standard/WorkspaceChange row.
- Startup verifies the complete structural surface, `foreign_keys=ON`, WAL,
  synchronous FULL, 5000 ms busy timeout, WAL autocheckpoint, recursive
  triggers, `foreign_key_check`, and `integrity_check=ok`.

The codebase graph showed a production consumer for every projection above in
`agent_store`, `context_store`, `deliberation_store`,
`deliberation_budget_store`, `deliberation_dispatch_store`, or
`deliberation_boundary_store`. No speculative projection was added.

Production source sizes after the change:

- `migrations.rs`: 301 lines
- `app_projection_schema.sql`: 277 lines
- `lib.rs`: 150 lines

Clean-code assessment: 9/10. Schema classification, installation, projection
installation, and health verification are separate named operations; the
remaining public legacy `ChecksumMismatch` variant is retained only to avoid an
unrelated cross-crate API change.

## TDD evidence

Initial RED command:

```text
cargo test -p local-agent-terminal-storage-sqlite --test schema_v7 -- --nocapture

running 8 tests
test nonempty_unknown_schema_is_rejected_without_mutation ... ok
test initialized_connections_enforce_runtime_pragmas_and_integrity ... ok
...
test result: FAILED. 2 passed; 6 failed; 0 ignored; 0 measured; 0 filtered out
```

The six expected failures showed historical v1/v9 installation, v6/v7
rejection, missing `task_workflow_authority`, and the old schema shape.

A second RED regression tightened fail-closed behavior:

```text
cargo test -p local-agent-terminal-storage-sqlite --test schema_v7 nonempty_unknown_schema_is_rejected_without_mutation -- --exact --nocapture

assertion `left == right` failed
  left: "wal"
 right: "delete"
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 7 filtered out
```

After moving runtime pragma changes behind structural recognition, the same
test passed `1 passed; 0 failed`.

## Fresh focused verification

```text
cargo fmt --all -- --check
Exit code: 0

cargo check -p local-agent-terminal-storage-sqlite --all-targets
Finished `dev` profile ...
Exit code: 0

cargo test -p local-agent-terminal-storage-sqlite --test schema_v7
test result: ok. 8 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out
Exit code: 0

cargo test -p local-agent-terminal-storage-sqlite --test schema_health
test result: ok. 6 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out
Exit code: 0
```

The `schema_v7` suite proves the exact 481-object clean/migrated authority,
the normative v6 row upcast, exact v7 reopen, no fabricated task authority,
marker/unknown rejection, rejection without journal mutation, runtime pragmas,
integrity, and the workflow-authority write guard.

## Broader regression blocker

The requested package-wide command was run fresh after the final implementation:

```text
cargo test -p local-agent-terminal-storage-sqlite

running 1 test
test tool_execution_store::tests::incomplete_reads_candidates_and_rows_from_one_snapshot ... FAILED

called `Result::unwrap()` on an `Err` value:
SqliteFailure(... Some("project repository identity must be a sha256 digest"))

test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out
Exit code: 1
```

A diagnostic `cargo test -p local-agent-terminal-storage-sqlite --tests
--no-fail-fast` also completed and reported nine failing legacy targets. The
dominant incompatibilities are outside Task 3 ownership:

- legacy fixtures insert `projects.repository_identity = 'repo-1'`, which the
  exact normative v7 authority correctly rejects because it requires a
  SHA-256 digest;
- deliberation fixtures insert the removed historical
  `agent_descriptors.containment_verified` column instead of v7 containment
  attestation authority;
- workspace onboarding callers/fixtures still submit values rejected by the
  closed v7 constraints and surface `InvalidInput`.

These failures cannot be made green from the Task 3 paths without weakening or
altering the exact 481-object normative authority. They require the subsequent
caller and fixture cutover tasks. No out-of-scope test was weakened or edited.

## Scope safety

- No file under `docs/multi-agent-terminal-design/**` was edited or staged.
- The implementation plan and its checkboxes were not modified.
- The initial Task 3 commit staged only its five foundation paths and this
  report; Fix Round 1 expands the scoped staging set to the storage callers and
  fixtures required for a package-wide v7 cutover.

## Fix Round 1: review remediation

Date: 2026-08-13

This round supersedes the earlier regression blocker. The initial review found
two critical and three important authority defects; each was addressed without
changing the normative design package:

- SQL structural comparison now tokenizes quoted literals and token
  boundaries instead of lowercasing/removing whitespace inside literals.
  Regression tests reject both a changed v7 string literal and `IS NULL`
  changed to `ISNULL`.
- Structural verification now compares the exact seeded mutable workflow
  authority in all six rule/source/profile/outcome/guard/effect tables.
- Exact-v6 foreign-key preflight runs before the migration transaction can
  commit, and an orphaned v6 database is rejected without mutation.
- `deliberation_task_budgets` was removed from app projections. The legacy
  budget port fails closed with `IntegrityFailure` instead of creating a
  second budget authority.
- Storage callers and fixtures were cut over to exact v7 authority. Legacy
  mutation ports that cannot carry mandatory decision, attempt, process, or
  terminal receipt identities fail closed before mutation; only the explicit
  authorized execution path creates an operation attempt.

The tool-recovery tests were consolidated around valid v7 state transitions.
Historical v6 success expectations were replaced with explicit
`IntegrityFailure` and no-mutation assertions; tests for exact policy,
approval, concurrency, replay, rollback, canonical artifact paths, and
snapshot consistency remain.

The refactor removed 6,421 lines and added 1,630 lines across the scoped
storage implementation and tests. Every modified source/test file is below
2,000 lines; the largest is `tests/agent_store.rs` at 1,671 lines and the
largest production file is `src/agent_store.rs` at 1,651 lines.

Clean-code assessment after remediation: 8/10. Unreachable legacy mutation
branches and their orphan helpers are gone, authority-bearing paths are
explicit, and all files satisfy the requested size ceiling. The remaining
deduction is for large but cohesive adapter/test modules above 1,000 lines;
splitting them further is outside this authority correction.

## Fix Round 1 verification

```text
cargo fmt --all -- --check
Exit code: 0

cargo check -p local-agent-terminal-storage-sqlite --all-targets
Exit code: 0

cargo clippy -p local-agent-terminal-storage-sqlite --all-targets -- -D warnings
Exit code: 0

cargo test -p local-agent-terminal-storage-sqlite
1 lib + 123 integration tests passed; 0 failed
Doc-tests: 0 passed; 0 failed
Exit code: 0
```

Focused evidence from the same remediation state:

- `schema_v7`: 13 passed, including literal/token tamper detection, exact
  seeded workflow authority, v6 orphan preflight, and projection isolation.
- `schema_health`: 6 passed.
- `tool_recovery`: 20 passed.
- `agent_store`: 23 passed; `context_store`: 7 passed;
  `deliberation_store`: 12 passed; `event_store`: 8 passed;
  `plan_approval_store`: 11 passed; `policy_tool_store`: 9 passed;
  `workspace_recovery`: 14 passed.

The independent Fix Round 1 re-review found all five findings addressed, no
new Critical/Important breakage, and no out-of-scope observations. Task 3 is
therefore checked complete in the plan.
