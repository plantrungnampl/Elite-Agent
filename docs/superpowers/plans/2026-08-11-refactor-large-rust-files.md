# Large Rust File Refactoring Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Refactor every maintainer-owned tracked Rust file over 2,000 lines into cohesive files of at most 2,000 lines without changing behavior or public APIs.

**Architecture:** Apply Extract File at top-level Rust item boundaries. The original module or integration-test target remains the stable entry point and uses ordered `include!` fragments named by responsibility, preserving the exact module namespace, privacy relationships, test target, item order, and public paths while making each physical file bounded and navigable.

**Tech Stack:** Rust 1.97.1, Cargo workspace, rustfmt, Clippy, PowerShell verification.

## Global Constraints

- Refactoring hat only: no feature, bug-fix, protocol, schema, persistence, or behavior changes.
- Do not modify `docs/multi-agent-terminal-design`.
- Exclude generated lockfiles (`Cargo.lock`, `pnpm-lock.yaml`) from manual file splitting.
- Every tracked maintainer-owned `*.rs` file must contain at most 2,000 physical lines after the refactor.
- Split only at complete top-level item boundaries; never split a function, `impl`, type, attribute group, or nested test module.
- Preserve item order and existing public/private visibility exactly.
- Add no dependencies and do not update lockfiles.

---

### Task 1: Establish the green baseline and exact inventory

**Files:**

- Create: `docs/superpowers/plans/2026-08-11-refactor-large-rust-files.md`

**Interfaces:**

- Consumes: current branch `codex/m4-context-deliberation` at the completed M4 Task 7 commit.
- Produces: a verified baseline and an explicit list of the 12 maintainer-owned Rust files requiring extraction.

- [x] **Step 1: Run the complete baseline test suite**

```powershell
cargo fmt --all -- --check
cargo check --workspace --all-targets
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
cargo test --workspace --doc
node scripts/check-architecture.mjs
```

- [x] **Step 2: Verify the inventory**

Measure tracked files with `[System.IO.File]::ReadAllLines()` and confirm the only generated files over the limit are `Cargo.lock` and `pnpm-lock.yaml`. The maintainer-owned Rust inventory must be exactly:

```text
crates/platform-windows/tests/process_matrix.rs
crates/storage-sqlite/src/tool_execution_store.rs
crates/storage-sqlite/tests/tool_recovery.rs
crates/agent-runtime/tests/runtime_contract.rs
crates/application/src/deliberation.rs
crates/application/src/tool.rs
crates/agent-runtime/src/runtime.rs
crates/application/tests/deliberation_recovery.rs
crates/application/tests/deliberation_ports.rs
crates/application/src/context.rs
crates/application/tests/execute_tool.rs
crates/tool-runtime/tests/capability_tools.rs
```

### Task 2: Extract bounded application source fragments

**Files:**

- Modify: `crates/application/src/context.rs`
- Create: `crates/application/src/context/core.rs`
- Create: `crates/application/src/context/manifest_tests.rs`
- Modify: `crates/application/src/deliberation.rs`
- Create: `crates/application/src/deliberation/records.rs`
- Create: `crates/application/src/deliberation/snapshots.rs`
- Create: `crates/application/src/deliberation/ports.rs`
- Create: `crates/application/src/deliberation/commands.rs`
- Create: `crates/application/src/deliberation/authority_tests.rs`
- Modify: `crates/application/src/tool.rs`
- Create: `crates/application/src/tool/capability.rs`
- Create: `crates/application/src/tool/execution.rs`
- Create: `crates/application/src/tool/file_write_recovery.rs`
- Create: `crates/application/src/tool/request_binding.rs`

**Interfaces:**

- Consumes: the existing `application::{context, deliberation, tool}` module namespaces.
- Produces: the identical exported application API and identical private item relationships through ordered same-module fragments.

- [x] **Step 1: Extract context at top-level boundary 1980**

Keep lines 1-1979 in `context/core.rs`, keep the complete `#[cfg(test)] mod manifest_tests` item in `context/manifest_tests.rs`, and replace `context.rs` with ordered `include!` statements.

- [x] **Step 2: Extract deliberation at boundaries 628, 1976, 2623, and 3372**

Map the original ranges to `records.rs`, `snapshots.rs`, `ports.rs`, `commands.rs`, and `authority_tests.rs` in that order; replace `deliberation.rs` with ordered `include!` statements.

- [x] **Step 3: Extract tool contracts at boundaries 929, 1741, and 2406**

Map the original ranges to `capability.rs`, `execution.rs`, `file_write_recovery.rs`, and `request_binding.rs` in that order; replace `tool.rs` with ordered `include!` statements.

- [x] **Step 4: Verify the application group**

```powershell
cargo fmt --all -- --check
cargo test -p local-agent-terminal-application
cargo check -p local-agent-terminal-application --all-targets
```

### Task 3: Extract bounded runtime and SQLite source fragments

**Files:**

- Modify: `crates/agent-runtime/src/runtime.rs`
- Create: `crates/agent-runtime/src/runtime/connection.rs`
- Create: `crates/agent-runtime/src/runtime/lifecycle.rs`
- Create: `crates/agent-runtime/src/runtime/sink.rs`
- Create: `crates/agent-runtime/src/runtime/protocol.rs`
- Create: `crates/agent-runtime/src/runtime/tests.rs`
- Modify: `crates/storage-sqlite/src/tool_execution_store.rs`
- Create: `crates/storage-sqlite/src/tool_execution_store/model.rs`
- Create: `crates/storage-sqlite/src/tool_execution_store/file_write_recovery.rs`
- Create: `crates/storage-sqlite/src/tool_execution_store/execution_store.rs`
- Create: `crates/storage-sqlite/src/tool_execution_store/authorization.rs`
- Create: `crates/storage-sqlite/src/tool_execution_store/file_write_validation.rs`
- Create: `crates/storage-sqlite/src/tool_execution_store/artifact_store.rs`
- Create: `crates/storage-sqlite/src/tool_execution_store/terminal_receipts.rs`
- Create: `crates/storage-sqlite/src/tool_execution_store/tests.rs`

**Interfaces:**

- Consumes: existing `runtime` and `tool_execution_store` namespaces.
- Produces: byte-for-byte-equivalent item bodies in the same compilation namespaces and order.

- [x] **Step 1: Extract runtime at boundaries 561, 1300, 2183, and 2820**

Map the original ranges to `connection.rs`, `lifecycle.rs`, `sink.rs`, `protocol.rs`, and `tests.rs` in that order; replace the original file with ordered `include!` statements.

- [x] **Step 2: Extract the SQLite tool store at boundaries 80, 546, 1052, 1169, 2101, 2818, 3505, and 4509**

Map the original ranges in order to `model.rs`, `file_write_recovery.rs`, `execution_store.rs`, `authorization.rs`, `file_write_validation.rs`, `artifact_store.rs`, `terminal_receipts.rs`, and `tests.rs`; replace the original file with ordered `include!` statements.

- [x] **Step 3: Verify the runtime and storage group**

```powershell
cargo fmt --all -- --check
cargo test -p local-agent-terminal-agent-runtime
cargo test -p local-agent-terminal-storage-sqlite
cargo check -p local-agent-terminal-agent-runtime --all-targets
cargo check -p local-agent-terminal-storage-sqlite --all-targets
```

### Task 4: Extract bounded application and runtime integration-test fragments

**Files:**

- Modify: `crates/agent-runtime/tests/runtime_contract.rs`
- Create: `crates/agent-runtime/tests/runtime_contract/lifecycle.rs`
- Create: `crates/agent-runtime/tests/runtime_contract/request_routing.rs`
- Create: `crates/agent-runtime/tests/runtime_contract/acceptance_and_recovery.rs`
- Modify: `crates/application/tests/deliberation_recovery.rs`
- Create: `crates/application/tests/deliberation_recovery/replay.rs`
- Create: `crates/application/tests/deliberation_recovery/claim_authority.rs`
- Modify: `crates/application/tests/deliberation_ports.rs`
- Create: `crates/application/tests/deliberation_ports/persistence.rs`
- Create: `crates/application/tests/deliberation_ports/objections_and_approval.rs`
- Modify: `crates/application/tests/execute_tool.rs`
- Create: `crates/application/tests/execute_tool/execution_flow.rs`
- Create: `crates/application/tests/execute_tool/policy_authority.rs`

**Interfaces:**

- Consumes: the existing integration-test target namespaces and shared fixtures.
- Produces: the same tests, helpers, names, and execution semantics in bounded ordered fragments.

- [x] **Step 1: Extract runtime contract at boundaries 1394 and 2687**

Map the ranges to `lifecycle.rs`, `request_routing.rs`, and `acceptance_and_recovery.rs`; replace the original test target with ordered `include!` statements.

- [x] **Step 2: Extract deliberation recovery at boundary 1301**

Map the ranges to `replay.rs` and `claim_authority.rs`; replace the original test target with ordered `include!` statements.

- [x] **Step 3: Extract deliberation ports at boundary 1238**

Map the ranges to `persistence.rs` and `objections_and_approval.rs`; replace the original test target with ordered `include!` statements.

- [x] **Step 4: Extract execute-tool tests at boundary 1182**

Map the ranges to `execution_flow.rs` and `policy_authority.rs`; replace the original test target with ordered `include!` statements.

- [x] **Step 5: Verify the application and runtime test targets**

```powershell
cargo fmt --all -- --check
cargo test -p local-agent-terminal-agent-runtime --test runtime_contract
cargo test -p local-agent-terminal-application --test deliberation_recovery --test deliberation_ports --test execute_tool
```

### Task 5: Extract bounded platform, SQLite, and tool-runtime integration-test fragments

**Files:**

- Modify: `crates/platform-windows/tests/process_matrix.rs`
- Create: `crates/platform-windows/tests/process_matrix/process_and_credentials.rs`
- Create: `crates/platform-windows/tests/process_matrix/network_isolation.rs`
- Create: `crates/platform-windows/tests/process_matrix/environment_and_write_scope.rs`
- Create: `crates/platform-windows/tests/process_matrix/write_evidence.rs`
- Modify: `crates/storage-sqlite/tests/tool_recovery.rs`
- Create: `crates/storage-sqlite/tests/tool_recovery/authorization.rs`
- Create: `crates/storage-sqlite/tests/tool_recovery/ownership_and_claims.rs`
- Create: `crates/storage-sqlite/tests/tool_recovery/incomplete_and_file_write.rs`
- Create: `crates/storage-sqlite/tests/tool_recovery/fixtures.rs`
- Modify: `crates/tool-runtime/tests/capability_tools.rs`
- Create: `crates/tool-runtime/tests/capability_tools/authorization.rs`
- Create: `crates/tool-runtime/tests/capability_tools/execution_harness.rs`

**Interfaces:**

- Consumes: existing platform, storage, and tool-runtime integration-test target namespaces.
- Produces: unchanged test cases and fixture sharing, with every physical test file bounded.

- [x] **Step 1: Extract process matrix at boundaries 1363, 2703, and 4056**

Map the ranges to `process_and_credentials.rs`, `network_isolation.rs`, `environment_and_write_scope.rs`, and `write_evidence.rs`; preserve the full attribute group beginning at each boundary.

- [x] **Step 2: Extract SQLite recovery tests at boundaries 1203, 2470, and 3633**

Map the ranges to `authorization.rs`, `ownership_and_claims.rs`, `incomplete_and_file_write.rs`, and `fixtures.rs`.

- [x] **Step 3: Extract capability-tool tests at boundary 1169**

Map the ranges to `authorization.rs` and `execution_harness.rs`, preserving platform `#[cfg]` attribute groups.

- [x] **Step 4: Verify the platform, storage, and tool-runtime test targets**

```powershell
cargo fmt --all -- --check
cargo test -p local-agent-terminal-platform-windows --test process_matrix --all-features
cargo test -p local-agent-terminal-storage-sqlite --test tool_recovery
cargo test -p local-agent-terminal-tool-runtime --test capability_tools
```

### Task 6: Enforce the line limit and run final gates

**Files:**

- Modify: `docs/superpowers/plans/2026-08-11-refactor-large-rust-files.md`

**Interfaces:**

- Consumes: all extracted source and test fragments from Tasks 2-5.
- Produces: a clean, committed refactor ready for M4 Task 8.

- [x] **Step 1: Verify no maintained Rust file exceeds 2,000 lines**

Use `git ls-files '*.rs'` plus untracked `*.rs` files and `[System.IO.File]::ReadAllLines()`; the result set where `Lines -gt 2000` must be empty.

- [x] **Step 2: Verify exact-content preservation**

Concatenate each ordered fragment in memory and compare it byte-for-byte with the corresponding pre-refactor file from `HEAD`, allowing only the root file replacement by `include!` statements and newline normalization already enforced by `.gitattributes`.

- [x] **Step 3: Run all required repository gates**

```powershell
cargo fmt --all -- --check
cargo check --workspace --all-targets
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
cargo test --workspace --doc
node scripts/check-architecture.mjs
git diff --exit-code HEAD -- docs/multi-agent-terminal-design
git diff --check
```

- [x] **Step 4: Review and commit**

Confirm the diff contains only mechanical file extraction and this plan, then commit:

```powershell
git add crates/application crates/agent-runtime crates/storage-sqlite crates/platform-windows crates/tool-runtime docs/superpowers/plans/2026-08-11-refactor-large-rust-files.md
git diff --cached --check
git commit -m "refactor: split oversized rust files"
```
