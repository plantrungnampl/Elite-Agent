# Task 4 report - workflow command authority

## Scope

- Added canonical workflow-transition command preparation in application.
- Added an application publisher boundary so execution publishes the immutable command before authority persistence.
- Added the SQLite v7 workflow authority adapter using an immediate transaction.
- Kept `docs/multi-agent-terminal-design/**` read-only.

## RED evidence

- Initial application test did not compile because the workflow authority command/input/store surface did not exist.
- Initial SQLite test did not compile because the workflow authority adapter/module did not exist.
- The publication-order regression test initially failed to compile because `WorkflowCommandPublisher` was absent.
- Requiring physical artifact verification initially exposed synthetic test storage keys as `IntegrityFailure`; fixtures were corrected to publish real content-addressed bytes and command artifacts through `JournaledArtifactWriter`.

## Implementation

- `prepare_workflow_transition` validates bounded schema fields, requires canonical `(kind, reference)` order, rejects duplicate kinds, and asks the v3 domain reducer for the exact transition.
- The application constructs the schema-v1 value, hashes RFC 8785 bytes with `commandDigest` omitted, inserts that digest, and canonicalizes the final immutable artifact.
- `TransitionWorkflow::execute` loads current authority, publishes the command through `WorkflowCommandPublisher`, then invokes the authority store. Publication failure prevents persistence.
- `SqliteStore::persist_transition` recomputes the prepared command, requires a configured artifact reader, verifies journal completion, metadata, hash, size, and physical bytes, then opens `TransactionBehavior::Immediate`.
- The transaction validates current authority and scoped evidence, inserts the prepared event, exact guard rows, exact effect rows, accepts the event, updates authority by CAS, updates the task projection, and commits.
- Trigger/constraint/CAS failures are classified as non-retryable `Conflict`; unavailable physical artifact verification remains retryable `Unavailable` before mutation.

## Verification

- `cargo fmt --all -- --check` - exit 0.
- `cargo check -p local-agent-terminal-application --all-targets` - exit 0.
- `cargo clippy -p local-agent-terminal-application --all-targets -- -D warnings` - exit 0.
- `cargo check -p local-agent-terminal-storage-sqlite --all-targets` - exit 0.
- `cargo clippy -p local-agent-terminal-storage-sqlite --all-targets -- -D warnings` - exit 0.
- `cargo test -p local-agent-terminal-application --test workflow_authority -- --nocapture` - 6 passed.
- `cargo test -p local-agent-terminal-storage-sqlite --test workflow_authority_store -- --nocapture` - 7 passed.
- `cargo test -p local-agent-terminal-application --all-features` - all unit, integration, and doc tests passed.
- `cargo test -p local-agent-terminal-storage-sqlite --all-features` with a fresh isolated `TEMP`/`TMP` - all unit, integration, and doc tests passed.

The first package-wide SQLite attempt followed an earlier wrapper timeout and collided with directories owned by the still-running prior test process (`AlreadyExists` in an unrelated `deliberation_store` fixture). A fresh isolated TEMP run completed with exit 0; no unrelated fixture code was changed.

## File-size gate

- `crates/application/src/workflow_authority.rs`: below 2,000 lines.
- `crates/storage-sqlite/src/workflow_authority_store.rs`: below 2,000 lines.
- Both new integration test files: below 2,000 lines.

## Review status

Round 0 found three Important issues: caller-selected trusted-core identity, a non-RFC3339 monotonic fallback, and direct-SQL tests that stopped before the intended trigger. Fix Round 1 now:

- requires a composition-bound trusted-core digest through `WorkflowAuthorityStore`, checks it before artifact publication, and rechecks it at SQLite persistence;
- advances a regressed/equal clock to the next SQLite-representable RFC3339 instant;
- proves the exact profile-route, terminal accepted-replay, and cross-task plan-receipt triggers with their precise abort messages.

Fresh focused evidence after Fix Round 1: application 7 passed; SQLite integration 11 passed; SQLite timestamp unit tests 2 passed; format, package checks, and package Clippy all exited 0. Fresh package-wide `--all-features` reruns passed for application and storage-sqlite; the storage gate used an isolated TEMP/TMP and exited 0 after 433.6 seconds.

Independent re-review of `6d9c539..3524620` was clean with no Critical, Important, or Minor findings. All six Task 4 plan steps are now complete.
