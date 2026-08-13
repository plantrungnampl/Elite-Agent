# Task 2 report: adopt workflow v3 domain authority

## Result

Status: complete.

Commit: `291e0e128407f870a83fce6a5c8ae2a578bc1440` -- `feat: adopt workflow v3 domain authority`

The pure workflow model now consumes the normative v3 transition JSON, exposes the v3 state snapshot and command request surfaces, resolves only the 33 ID-bearing command rules, and routes the six ID-less condition rules through the separate condition reducer.

## Delivered behavior

- Split the workflow facade into `types.rs`, `specification.rs`, and `reducer.rs`.
- Parsed the exact production `workflow-transitions.v3.json` constant with strict unknown-field rejection. Structural validation covers the four profiles, three outcome modes, 30 phase rules, two global rules, one workspace-dirty rule, six condition rules, profile escalations, unique command IDs/selectors, and condition selectors.
- Added `WorkflowStateSnapshot`, profile/outcome state, profile revision, borrowed event-ID getters, and `TransitionRequest` exact evidence/effect-kind sets.
- Command reduction verifies rule ID, source, event, profile, outcome, and exact declared evidence/effect sets; condition reduction requires its declared guard and emits no command rule ID or effects.
- Updated all four production command callers to supply the exact v3 rule/evidence/effect authority. New post-approval phases map to existing recovery `PostApproval` behavior.
- Updated named regressions to use complete v3 snapshots. The workspace-dirty regression now correctly retains workspace version because v3 `WF-W001` declares fencing advancement but not `increment_workspace_version`.
- Added the controller-approved test-only clones in `crates/storage-sqlite/tests/deliberation_store.rs` and `crates/bootstrap/tests/deliberation_e2e.rs` for the now owned `WorkflowState` fields.

## RED evidence

Before production implementation, the required command was deliberately RED:

```powershell
cargo test -p local-agent-terminal-domain --test workflow_contract -- --nocapture
```

It failed to compile because the v1 surface lacked `reduce_condition`, `TaskOutcomeMode`, `TransitionRequest`, `WorkflowProfile`, `WorkflowStateSnapshot`, and `WorkflowState::rehydrate`; the old reducer still had the three-argument v1 signature and loaded the v1 transition specification.

## Final verification

Required Task 2 gates all passed after the final implementation:

| Command | Result |
| --- | --- |
| `cargo fmt --all -- --check` | PASS |
| `cargo test -p local-agent-terminal-domain --all-features` | PASS; includes 9 v3 workflow-contract tests and 2 strict-parser tests |
| `cargo test -p local-agent-terminal-application --tests` | PASS; all application test binaries |
| `cargo test -p local-agent-terminal-orchestration --test workflow_contract -- --nocapture` | PASS; 15 tests |
| `cargo test -p local-agent-terminal-storage-sqlite --test workspace_recovery -- --nocapture` | PASS; 14 tests |
| `cargo test -p local-agent-terminal-storage-sqlite --test deliberation_store -- --nocapture` | PASS; 12 tests |
| `cargo test -p local-agent-terminal-bootstrap --test deliberation_e2e -- --nocapture` | PASS; 5 tests |
| `cargo check --workspace --all-targets` | PASS |
| task-owned scoped `cargo clippy ... -D warnings` checks | PASS for domain, application, orchestration, storage library/recovery, and bootstrap E2E slices |
| `cargo test --workspace --doc` | PASS |

Additional checks:

- `rg -n --glob '*.rs' 'workflow-transitions\.v1\.json' crates` produced no production reference.
- Workflow source line counts are within the 2,000-line guard: facade 9, types 562, specification 636, reducer 114.

## Extra-suite results kept out of Task 2 scope

The required gates above are green. Two broader workspace checks found pre-existing, out-of-scope failures and were not modified:

- `cargo clippy --workspace --all-targets --all-features -- -D warnings` stops at `crates/storage-sqlite/tests/plan_approval_store.rs:348` (`clippy::single_element_loop`, "for loop over a single element") and `crates/bootstrap/src/deliberation_runtime.rs:962` (`clippy::items_after_test_module`, "items after a test module").
- `cargo test --workspace --all-features` reached `crates/bootstrap/tests/tool_broker.rs` and failed only `production_runtime_writes_with_durable_recovery_evidence` at line 342 and `production_startup_completes_a_started_file_write_with_the_exact_post_image` at line 442; each assertion reported `left: 0`, `right: 1` (20 passed, 2 failed in that target).

## Committed files

- Domain: `crates/domain/src/lib.rs`, `crates/domain/src/workflow.rs`, `crates/domain/src/workflow/types.rs`, `crates/domain/src/workflow/specification.rs`, `crates/domain/src/workflow/reducer.rs`, `crates/domain/tests/workflow_contract.rs`
- Application: `crates/application/src/plan_approval.rs`, `crates/application/src/deliberation/commands.rs`, `crates/application/src/deliberation/ports.rs`, `crates/application/src/deliberation/records.rs`, `crates/application/tests/plan_approval_digest.rs`, `crates/application/tests/deliberation_ports/objections_and_approval.rs`, `crates/application/tests/deliberation_ports/persistence.rs`
- Orchestration: `crates/orchestration/src/recovery.rs`, `crates/orchestration/tests/workflow_contract.rs`
- SQLite: `crates/storage-sqlite/src/workspace_store.rs`, `crates/storage-sqlite/tests/workspace_recovery.rs`, `crates/storage-sqlite/tests/deliberation_store.rs`
- Bootstrap: `crates/bootstrap/tests/deliberation_e2e.rs`

## Self-review

- The staged scope was exactly the 19 controller-authorized Task 2 paths. It excluded `docs/multi-agent-terminal-design/**` and the controller-owned plan amendment.
- `git diff --cached --check` was clean before commit; `git show --check --format=fuller --stat HEAD` is clean for commit `291e0e128407f870a83fce6a5c8ae2a578bc1440`.
- `Phase` now exactly reflects the v3 phase list; `LocalCommit` remains solely a `TaskOutcomeMode`.
- The compatibility `WorkflowState::new` constructor remains for unchanged callers and supplies `Standard` / `WorkspaceChange` / profile revision `1`; authority-aware code uses `WorkflowState::rehydrate(WorkflowStateSnapshot { ... })`.

## Concerns

- The worktree intentionally retains user-owned documentation changes and the controller-owned plan amendment. A whole-worktree `git diff --check` reports trailing whitespace in `docs/multi-agent-terminal-design/00-README.md` and `docs/multi-agent-terminal-design/18-validation-report.md`; neither file was changed or staged by this task.
- The full-workspace Clippy and test-suite failures listed above remain out of scope. They must not be reported as green verification gates for this Task 2 commit.

## Fix Round 1: SQLite v7 workflow-authority rehydration

Status: complete.

### Delivered behavior

- `deliberation_store::load_workflow_state` now joins `tasks` to the authoritative v7 `task_workflow_authority` row and calls `WorkflowState::rehydrate(WorkflowStateSnapshot { ... })` with the exact authority profile, outcome, stream version, profile revision, and causal IDs plus task condition, operation, workspace version, and fencing epoch.
- The reader fails closed when the authority row is absent, contains malformed values, disagrees with the task projection, contains empty/incomplete causal IDs, or points to an accepted transition/profile revision that does not match the task and rehydrated state.
- Workspace mutation reconstruction now reuses that reader instead of rebuilding a state through `WorkflowState::new`, so reducer output retains the persisted v7 profile/outcome/stream/profile-revision lineage.
- The default deliberation and workspace test fixtures now seed authoritative v7 rows. Their exact-state regressions assert `HighAssurance`, `LocalCommit`, stream/profile revisions, fencing, and both causal IDs.

### RED evidence and scope ruling

Before the production change, these focused regressions were deliberately RED because the readers fabricated `Standard`/`WorkspaceChange` defaults through `WorkflowState::new`:

```powershell
cargo test -p local-agent-terminal-storage-sqlite --test deliberation_store deliberation_load_rehydrates_exact_v7_workflow_authority -- --exact --nocapture
cargo test -p local-agent-terminal-storage-sqlite --test workspace_recovery workspace_mutation_rehydrates_exact_v7_workflow_authority -- --exact --nocapture
cargo test -p local-agent-terminal-storage-sqlite --test deliberation_store deliberation_load_fails_closed_when_v7_workflow_authority_is_missing -- --exact --nocapture
```

The first two asserted `HighAssurance` but observed fabricated `Standard`; the third returned a fabricated `DeliberationSnapshot` instead of `IntegrityFailure`. A later authority-transition mismatch regression was also RED until the reader validated the causal record.

The first complete SQLite package run then exposed five RED `plan_approval_store` tests whose shared fixture omitted workflow authority. The controller approved a scope expansion for exactly `crates/storage-sqlite/tests/plan_approval_store.rs`. Its common fixture now creates a trigger-valid authority history: Intake through `WF-P001`, `WF-P002`, `WF-P004`–`WF-P007`, a real `Standard` to `HighAssurance` profile revision, then `WF-P013` to `AwaitingPlanApproval` at stream version 8. Existing approval assertions remain unchanged.

### Final verification

| Command | Result |
| --- | --- |
| `cargo test -p local-agent-terminal-storage-sqlite --test deliberation_store -- --nocapture` | PASS; 15 tests |
| `cargo test -p local-agent-terminal-storage-sqlite --test workspace_recovery -- --nocapture` | PASS; 15 tests |
| `cargo test -p local-agent-terminal-storage-sqlite --test plan_approval_store -- --nocapture` | PASS; 11 tests |
| `cargo test -p local-agent-terminal-storage-sqlite --test agent_store -- --nocapture` | PASS; 23 tests |
| `cargo test -p local-agent-terminal-storage-sqlite` | PASS; complete package, including schema v7 and doc tests |
| `cargo fmt --all -- --check` | PASS |
| `cargo check -p local-agent-terminal-storage-sqlite --all-targets` | PASS |
| `cargo clippy -p local-agent-terminal-storage-sqlite --all-targets -- -D warnings` | PASS |

One interim package attempt timed out at the initial two-minute runner limit. A later attempt encountered transient `agent_store` temporary-database `UnsupportedSchema { found: 0, supported: 7 }` setup failures; the isolated `agent_store` binary passed, and the final normal package rerun passed end-to-end. The final complete package gate above is the completion evidence.
