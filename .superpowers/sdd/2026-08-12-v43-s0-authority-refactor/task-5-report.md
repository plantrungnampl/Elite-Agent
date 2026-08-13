# Task 5 report - normative RunConfiguration v1

## Scope

- Added closed, typed `RunConfiguration v1` domain values and RFC 8785 canonical issuance.
- Added separate application publication and binding boundaries so immutable bytes are published before a preallocated run is bound.
- Added the SQLite v7 `run_configuration_bindings` adapter with independent semantic-config and physical-artifact verification.
- Repaired the deployed v7 scope trigger narrowly after the user-approved ruling that the normative trigger incorrectly equated semantic `configDigest` with the hash of the final artifact bytes.
- Kept `docs/multi-agent-terminal-design/**` read-only.

The existing `agent-run-config.v1/v2` reconstruction in `agent_store.rs` remains a temporary production compatibility path. Task 8 owns its removal and the bootstrap/runtime cutover because the legacy request cannot supply the normative capability, data-policy, fallback, and independence facts without invented defaults.

## TDD evidence

- The initial domain/application tests were RED because the typed v1 shape, issuance, publication, and binding surfaces did not exist.
- The initial SQLite binding test exposed a design contradiction: semantic `configDigest` excludes its own field, while the physical artifact hash covers final bytes. The approved adapter repair preserves both facts and verifies them independently.
- Review Round 0 found three issues: incomplete fact reconstructibility, an unusable publish-and-bind sequence before the run foreign key exists, and one test that changed hash and size together. Fixes added `RunConfiguration::unsigned`, split `PublishRunConfiguration` from `BindRunConfiguration`, and separated the two physical-integrity regressions.

## Implementation

- Closed serde shapes reject unknown fields, hostile credential-key names, invalid enums, incomplete independence dimensions, invalid fallback rules, and unbounded values.
- `RunConfiguration::issue` canonicalizes the unsigned value without `configDigest`, calculates SHA-256, adds `credentialsExcluded=true` and the semantic digest, then stores final canonical bytes.
- The application boundary now supports the required sequence: issue, publish immutable bytes, create the run, then bind the exact artifact/configuration tuple.
- The SQLite adapter recomputes semantic and physical digests, verifies physical bytes, size, scope, availability, task/run coherence, immutable replay, and exact provider/model/fingerprint reconstruction.

## Fresh verification

- `cargo fmt --all -- --check` - exit 0.
- `cargo test -p local-agent-terminal-domain run_configuration` - 1 passed.
- `cargo test -p local-agent-terminal-application --test run_configuration` - 8 passed.
- `cargo test -p local-agent-terminal-storage-sqlite --test run_configuration_store` - 7 passed.
- `cargo test -p local-agent-terminal-storage-sqlite --test agent_store` - 23 passed.
- `cargo test -p local-agent-terminal-domain --all-features` - all unit, integration, and doc tests passed.
- `cargo test -p local-agent-terminal-application --all-features` - all unit, integration, and doc tests passed.
- `cargo test -p local-agent-terminal-storage-sqlite --all-features --no-fail-fast` with isolated `TEMP`/`TMP` - all binaries and doc tests passed in 429.2 seconds.
- `cargo check --workspace --all-targets` - exit 0.
- `cargo clippy --workspace --all-targets --all-features -- -D warnings` - exit 0.
- `cargo test --workspace --doc` - exit 0.

A final isolated `cargo test --workspace --all-features --no-fail-fast` did not return a result before the 15-minute command timeout, so the complete workspace runtime gate is recorded as inconclusive rather than green. Earlier workspace evidence identified bootstrap fixtures that still seed v6 workspace-intent/budget authority; the approved plan assigns those M1-M4 regression cutovers to Task 8.

## Compatibility repair discovered by the full gate

Commit `d8c0e77` corrected runtime readers that still referenced removed v6 columns, made repository stable identity a valid `sha256:` digest while preserving the public repository-ID shape, and changed the stale specialist bootstrap regression to prove fail-closed behavior without a trusted budget authority. The full SQLite package, repository regression, focused bootstrap regression, package checks, and package Clippy all passed after the repair.

## File-size gate

- `crates/domain/src/run_configuration.rs`: 622 lines.
- `crates/application/src/run_configuration.rs`: 107 lines.
- `crates/application/tests/run_configuration.rs`: 430 lines.
- `crates/storage-sqlite/src/run_configuration_store.rs`: 220 lines.
- `crates/storage-sqlite/tests/run_configuration_store.rs`: 484 lines.
- `crates/storage-sqlite/src/agent_store.rs`: 1,651 lines.
- `crates/storage-sqlite/tests/agent_store.rs`: 1,671 lines.

No Task 5 production or test file exceeds 2,000 lines.

## Review and commits

Independent re-review of the Task 5 implementation range returned `ship` with no Critical, Important, or Minor findings.

- `ed3db88 feat: bind normative run configurations`
- `ebd2335 test: reject invalid run configuration publications`
- `9a8b500 fix: expose run configuration sequencing`
- `009fee1 fix: keep bootstrap tests last`
- `d8c0e77 fix: align runtime reads with sqlite v7`

All six Task 5 plan steps are complete under the approved Task 8 cutover boundary.
