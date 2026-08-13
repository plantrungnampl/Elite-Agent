# Task 6 report - workflow assurance authority

## Scope

- Added monotonic workflow-profile escalation over the v7 workflow authority stream.
- Added closed, canonical assurance-degradation receipts with separate semantic and physical digests.
- Added actor-proved `ContinueDegraded` persistence bound to an exact, task-scoped acceptance artifact.
- Added strict run-set, independence-group, executor/reviewer, requested-profile, and policy-requirement verification.
- Repaired the deployed v7 degradation-scope trigger narrowly: the original trigger compared a semantic receipt digest with the final artifact's physical content hash. The adapter now verifies those two facts independently.
- Kept `docs/multi-agent-terminal-design/**` read-only.

## TDD evidence

- The initial application tests were RED because the assurance policy, escalation command, canonical receipt, and store port did not exist.
- The initial SQLite tests were RED because no adapter implemented monotonic escalation or degradation persistence.
- Review Round 0 found four Important issues: exact escalation replay failed after a later escalation, an arbitrary verified artifact could satisfy degraded acceptance, callers could understate HighAssurance requirements, and the schema-v7 regression did not model both approved repairs. All four were fixed with regressions.
- Independent re-review returned `ship` with no Critical or Important findings. Its remaining minor suggestion was implemented by adding hostile closed-schema parse tests with recomputed semantic digests.

## Implementation

- Only `Quick -> Standard`, `Quick -> HighAssurance`, and `Standard -> HighAssurance` are accepted; downgrades, lateral changes, and transitions involving `ReadOnlyResearch` fail closed.
- Exact historical replay remains idempotent after later monotonic escalation and returns the latest workflow state without adding another revision.
- Receipt issuance sorts run references, validates distinct independence groups and exact role separation, preserves the requested profile, hashes canonical bytes without `receiptDigest`, then emits the final closed canonical schema.
- `ContinueDegraded` requires both a current user actor binding and an exact canonical `assurance-acceptance` artifact whose bytes bind the actor, task, receipt ID, receipt digest, requested profile, decision, and acceptance reference.
- The SQLite adapter validates physical artifact bytes/hash/size separately from semantic receipt/configuration digests and appends a receipt once.

## Fresh verification

- `cargo fmt --all -- --check` - exit 0.
- `cargo check --workspace --all-targets` - exit 0.
- `cargo clippy --workspace --all-targets --all-features -- -D warnings` - exit 0.
- `cargo test -p local-agent-terminal-domain assurance` - 1 passed.
- `cargo test -p local-agent-terminal-application --test assurance` - 5 passed.
- `cargo test -p local-agent-terminal-storage-sqlite --test assurance_store` - 7 passed.
- `cargo test -p local-agent-terminal-storage-sqlite --test schema_v7` - 13 passed.
- `cargo test -p local-agent-terminal-storage-sqlite --test schema_health` - 8 passed.
- `cargo test -p local-agent-terminal-domain --all-features` - all targets passed.
- `cargo test -p local-agent-terminal-application --all-features` - all targets passed.
- `cargo test -p local-agent-terminal-storage-sqlite --all-features --no-fail-fast` - all targets passed in 525.6 seconds; an earlier resource-contended run was superseded by this isolated fresh run.
- `cargo test --workspace --doc` - exit 0.

`cargo test --workspace --all-features --no-fail-fast` completed but is not green: 12 downstream targets failed. Focused reruns prove the failures are legacy fixtures assigned to Task 8's authority cutover, not Task 6 assurance behavior. Bootstrap's three failing lib tests cannot transition a v6-style intent into `Started` under v7 authority (`IntegrityFailure`), and all 12 storage-files crash-matrix cases seed a non-SHA-256 repository identity rejected by the v7 trigger. The result is recorded as failed, not hidden or reported as green.

## File-size gate

- `crates/domain/src/assurance.rs`: 532 lines.
- `crates/application/src/assurance.rs`: 133 lines.
- `crates/application/tests/assurance.rs`: 269 lines.
- `crates/storage-sqlite/src/assurance_store.rs`: 607 lines.
- `crates/storage-sqlite/tests/assurance_store.rs`: 377 lines.

No Task 6 production or test file exceeds 2,000 lines.

## Review and completion

Independent re-review verdict: `ship`. All five Task 6 plan steps are complete. The integrated legacy-fixture cutover remains explicitly owned by Task 8 Step 6.
