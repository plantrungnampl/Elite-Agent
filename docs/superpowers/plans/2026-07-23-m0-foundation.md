# M0 Domain and Persistence Foundation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan.

**Goal:** Establish a runnable, test-driven clean-architecture foundation that enforces the design contracts, persists immutable workflow evidence, reconciles artifact writes after crashes, and boots a minimal accessible Tauri/React desktop shell.

**Architecture:** A root Cargo workspace contains pure `domain`, application ports/use cases, SQLite and filesystem adapters, and a single bootstrap composition root. `apps/desktop` is generated with `create-tauri-app` and remains an outer adapter. The first vertical slice is `open application -> validate stores -> list/create project metadata -> render trustworthy startup/health state`; it does not yet execute agents or mutate user repositories.

**Tech Stack:** Git, Rust stable, Cargo, SQLite through `rusqlite`, `serde`/`serde_json`, `thiserror`, `tracing`, Tauri 2, React/TypeScript/Vite, pnpm, Node `node:test` and `node:sqlite`, Vitest, React Testing Library, user-event, and axe-core.

## Global Constraints

- Follow every Global Constraint in `docs/superpowers/plans/2026-07-23-product-delivery-program.md`.
- M0 may establish only boundaries needed by M0. Do not create empty crates for future milestones.
- `domain` has no Tauri, async runtime, database, filesystem, Git, process, provider, or OS dependency.
- `application` owns output-port traits. Concrete storage/files/bootstrap crates implement or compose them.
- The normative workflow JSON, approval JSON Schema, protocol JSON Schema, and SQLite DDL remain executable design artifacts and must be tested directly.
- Fix these known machine-contract gaps before relying on the contracts: actor-bound approvals; phase/expected-read/fenced-write tool approvals; immutable event rows; monotonic task fencing epochs; containment required before enabling brokered/isolated agents.
- Approval operation digests use RFC 8785 JSON Canonicalization Scheme and SHA-256 prefixed by `sha256:`. The implementation must pass the RFC 8785 number, Unicode, escaping, and object-order vectors; approval DTO timestamp strings are normalized to UTC RFC 3339 before canonicalization.
- Event append and its projection update occur in one `BEGIN IMMEDIATE` transaction and reject an unexpected stream version.
- Artifact content is written to a same-volume temporary file, flushed, hashed, atomically renamed, directory-flushed where supported, and reconciled from a durable operation journal.
- The React shell receives typed DTOs only. It cannot import Rust internals, read SQLite, replace an approval operation payload, or infer workflow legality.
- The shell must work without network access and must expose startup failure/recovery states as text, not as a spinner that can become success.
- Generated scaffold/configuration is the only test-first exception. All handwritten production behavior requires a failing test before implementation.

---

## Task 1: Establish the Git baseline and isolated implementation worktree

**Files:**

- Create: `.gitignore`
- Create: `.gitattributes`
- Verify: all existing `docs/**`

**Step 1: Add repository hygiene**

Use `apply_patch` to ignore `.worktrees/`, Rust/Node build output, local databases, logs, provider credentials, signing material, and `.superpowers/sdd/`. Mark `*.sh` as LF and Rust/TypeScript/JSON/Markdown/SQL as text without changing existing documentation contents.

**Step 2: Initialize and verify the baseline**

Run:

```powershell
git init -b main
git add .gitignore .gitattributes docs
git diff --cached --check
git commit -m "docs: establish product implementation baseline"
git status --short
```

Expected: the baseline commit succeeds and status is clean.

**Step 3: Create the feature worktree**

Run:

```powershell
git worktree add .worktrees/product-build -b feat/product-build
git -C .worktrees/product-build branch --show-current
```

Expected: branch is `feat/product-build`. Every later task in this plan runs from `D:\multiagent\.worktrees\product-build`.

## Task 2: Install/validate the Windows build toolchain and generate the desktop shell

**Files:**

- Generate: `apps/desktop/**`
- Create: `Cargo.toml`
- Create: `pnpm-workspace.yaml`
- Create: `rust-toolchain.toml`
- Modify: `apps/desktop/package.json`
- Modify: `apps/desktop/src-tauri/Cargo.toml`
- Modify: `apps/desktop/src-tauri/tauri.conf.json`

**Step 1: Validate prerequisites**

Run:

```powershell
node --version
pnpm --version
git --version
rustup --version
cargo --version
```

If Rust is absent, install the official Rustup package and select stable MSVC. If MSVC C++ Build Tools or WebView2 is absent, install the official Tauri Windows prerequisites. Record exact installed versions in `artifacts/verification/m0/toolchain.txt`.

**Step 2: Generate with the authorized CLI exception**

Run from the feature worktree:

```powershell
pnpm dlx create-tauri-app@4.6.2 apps/desktop --manager pnpm --template react-ts --identifier com.localagentterminal.desktop --tauri-version 2 --yes --force
```

Expected: `apps/desktop` contains Vite React TypeScript and `apps/desktop/src-tauri` contains a Tauri 2 Rust application.

**Step 3: Wire the minimal workspaces**

Use `apply_patch` to create a Cargo workspace with only `apps/desktop/src-tauri` initially and a pnpm workspace containing `apps/desktop`. Pin generated dependency versions through both lockfiles. Rename generated placeholder product/package identifiers to `Local Agent Terminal`.

**Step 4: Prove the untouched scaffold**

Run:

```powershell
pnpm install --frozen-lockfile=false
pnpm --dir apps/desktop build
cargo metadata --no-deps --format-version 1
cargo check -p local-agent-terminal-desktop
```

Expected: frontend build and Rust check pass.

**Step 5: Commit**

```powershell
git add Cargo.toml Cargo.lock pnpm-workspace.yaml pnpm-lock.yaml rust-toolchain.toml apps/desktop
git diff --cached --check
git commit -m "build: bootstrap Tauri React desktop shell"
```

## Task 3: Characterize and close executable design-contract gaps

**Files:**

- Create: `tests/contracts/design-contracts.test.mjs`
- Create: `scripts/verify-design-contracts.mjs`
- Modify: `docs/multi-agent-terminal-design/schemas/approval-digest.v1.schema.json`
- Modify: `docs/multi-agent-terminal-design/schemas/sqlite-v1.sql`
- Modify: `docs/multi-agent-terminal-design/schemas/README.md`
- Modify: `docs/multi-agent-terminal-design/18-validation-report.md`
- Modify mechanically: `docs/multi-agent-terminal-design/SHA256SUMS.txt`

**Step 1: Write failing contract tests**

Add Node built-in tests that assert:

1. every approval requires an `actorBindingDigest`;
2. a tool operation requires `workflowPhase` and `expectedReads`;
3. a tool operation with non-empty `expectedWrites` requires a positive non-null `executorFencingToken`;
4. `events` rejects `UPDATE` and `DELETE`;
5. `tasks.fencing_epoch` rejects decrement or reuse;
6. enabled `brokered_process` and `isolated_worker` descriptors require `containment_verified = 1`;
7. all JSON artifacts parse, workflow references are closed, SQLite applies with foreign keys enabled, and the checked-in checksum manifest is exact.

Run:

```powershell
node --test tests/contracts/design-contracts.test.mjs
```

Expected: tests 1–6 fail against the baseline and the existing integrity checks pass.

**Step 2: Make the JSON approval contract pass**

Use `apply_patch` to:

- add required top-level `actorBindingDigest` using the existing SHA-256 definition;
- add required `workflowPhase` and `expectedReads` to `toolOperation`;
- define `expectedReads` with the same bounded unique path representation as expected writes;
- express the conditional rule that non-empty expected writes require a positive integer fencing token, while read-only operations may use `null`;
- update schema documentation without changing unrelated protocol fields.

Run the Node tests. Expected: approval tests pass; SQL tests still fail.

**Step 3: Make the SQLite invariants pass**

Use `apply_patch` to add narrowly scoped triggers/checks:

- forbid event update and delete;
- require `tasks.fencing_epoch` to strictly increase when changed;
- prevent enabling a brokered/isolated agent without verified containment;
- preserve the existing rule that full-access legacy agents remain disabled.

Run the Node tests. Expected: all behavioral contract tests pass.

**Step 4: Refresh validation evidence**

Extend the validation script to regenerate and verify `SHA256SUMS.txt` deterministically, update the validation report with the new checks and date, then run:

```powershell
node scripts/verify-design-contracts.mjs
node --test tests/contracts/design-contracts.test.mjs
```

Expected: both commands exit 0 and report exact checksum coverage.

**Step 5: Commit**

```powershell
git add tests/contracts scripts/verify-design-contracts.mjs docs/multi-agent-terminal-design
git diff --cached --check
git commit -m "test: enforce approval and persistence contracts"
```

## Task 4: Build the pure workflow domain from the transition specification

**Files:**

- Create: `crates/domain/Cargo.toml`
- Create: `crates/domain/src/lib.rs`
- Create: `crates/domain/src/workflow.rs`
- Create: `crates/domain/src/identity.rs`
- Create: `crates/domain/src/event.rs`
- Create: `crates/domain/tests/workflow_contract.rs`
- Modify: `Cargo.toml`

**Step 1: Write failing domain tests**

Create tests for:

- parsing every phase, condition, and operation state in the normative workflow JSON;
- accepting every declared transition when its named guard is satisfied;
- rejecting undeclared transitions;
- rejecting a transition when any named guard is false;
- preserving `WorkspaceDirty`, recovery, approval, verification/repair, and terminal-state semantics;
- typed non-empty IDs, nonnegative sequence/workspace version, and strictly positive fencing tokens;
- domain crate dependency audit showing no forbidden framework/IO dependency.

Run:

```powershell
cargo test -p local-agent-terminal-domain
```

Expected: compile/test failure because domain types and reducer do not exist.

**Step 2: Implement the minimum pure model**

Implement value objects and a table-driven transition reducer. Embed or generate from the normative transition JSON without duplicating transition rules in handwritten match trees. Guards are explicit typed inputs; the reducer returns a domain error and emits no side effect.

**Step 3: Add property tests**

Generate arbitrary valid states and assert:

- a rejected transition leaves state unchanged;
- accepted transitions always appear in the normative transition table;
- sequence and workspace versions never decrease;
- terminal states do not leave terminality except through an explicitly declared recovery transition.

Run:

```powershell
cargo test -p local-agent-terminal-domain
```

Expected: all domain and property tests pass without Tauri, database, async runtime, shell, Git, or OS services.

**Step 4: Commit**

```powershell
git add Cargo.toml Cargo.lock crates/domain
git diff --cached --check
git commit -m "feat(domain): enforce workflow transitions"
```

## Task 5: Define application ports and optimistic event append use case

**Files:**

- Create: `crates/application/Cargo.toml`
- Create: `crates/application/src/lib.rs`
- Create: `crates/application/src/error.rs`
- Create: `crates/application/src/ports.rs`
- Create: `crates/application/src/append_events.rs`
- Create: `crates/application/src/dto.rs`
- Create: `crates/application/tests/append_events.rs`
- Modify: `Cargo.toml`

**Step 1: Write failing use-case tests with in-memory fakes**

Test:

- expected stream version is passed unchanged to the event store;
- events and requested projection changes are one application operation;
- a version conflict returns a typed non-retryable conflict classification;
- retryability and safe user-facing classification are explicit on all port errors;
- no concrete adapter type appears in a public application signature.

Run:

```powershell
cargo test -p local-agent-terminal-application
```

Expected: failure because ports/use case do not exist.

**Step 2: Implement the smallest ports and use case**

Define `EventStore`, `ArtifactStore`, `ArtifactJournal`, `Clock`, and `IdGenerator` output ports only. Add DTOs for the startup slice and an append use case that delegates transaction ownership to the event-store port.

**Step 3: Run tests and commit**

```powershell
cargo test -p local-agent-terminal-application
git add Cargo.toml Cargo.lock crates/application
git diff --cached --check
git commit -m "feat(application): add event and artifact ports"
```

## Task 6: Implement the SQLite event store and startup schema validation

**Files:**

- Create: `crates/storage-sqlite/Cargo.toml`
- Create: `crates/storage-sqlite/src/lib.rs`
- Create: `crates/storage-sqlite/src/migrations.rs`
- Create: `crates/storage-sqlite/src/event_store.rs`
- Create: `crates/storage-sqlite/src/artifact_journal.rs`
- Create: `crates/storage-sqlite/src/health.rs`
- Create: `crates/storage-sqlite/tests/event_store.rs`
- Create: `crates/storage-sqlite/tests/schema_health.rs`
- Modify: `Cargo.toml`

**Step 1: Write failing real-SQLite integration tests**

Test against temporary on-disk databases:

- first startup applies the normative DDL and records its checksum;
- later startup rejects a checksum mismatch or unsupported schema;
- WAL, foreign keys, and busy timeout are active;
- append uses `BEGIN IMMEDIATE`, verifies expected stream sequence, inserts immutable events, updates `tasks.current_sequence` in the same transaction, and commits atomically;
- two writers with the same expected version yield exactly one success and one conflict;
- failed projection update rolls back event insertion;
- artifact-journal intent/state transitions implement the application port and reject backward or invented-success transitions;
- integrity check and artifact-root validation produce typed health results.

Run:

```powershell
cargo test -p local-agent-terminal-storage-sqlite
```

Expected: failure because the adapter does not exist.

**Step 2: Implement the adapter**

Use the normative SQL as embedded migration input, parameterized SQL only, explicit transaction boundaries, and a connection initializer that applies every required pragma.

**Step 3: Run tests and commit**

```powershell
cargo test -p local-agent-terminal-storage-sqlite
git add Cargo.toml Cargo.lock crates/storage-sqlite
git diff --cached --check
git commit -m "feat(storage): add optimistic SQLite event store"
```

## Task 7: Implement content-addressed artifacts and crash reconciliation

**Files:**

- Create: `crates/storage-files/Cargo.toml`
- Create: `crates/storage-files/src/lib.rs`
- Create: `crates/storage-files/src/content_address.rs`
- Create: `crates/storage-files/src/journal.rs`
- Create: `crates/storage-files/src/reconcile.rs`
- Create: `crates/storage-files/tests/artifact_store.rs`
- Create: `crates/storage-files/tests/crash_matrix.rs`
- Modify: `Cargo.toml`

**Step 1: Write failing adapter tests**

Cover:

- identical bytes deduplicate to one SHA-256 storage key;
- logical metadata remains separate from immutable content;
- path traversal and cross-root resolution fail;
- a hash/size mismatch quarantines the temporary artifact;
- fault injection before write, after write, after flush, after journal transition, after rename, and before completion record reconciles to the documented deterministic state;
- reconciliation never invents success and never retries an indeterminate non-repeatable external operation.

Run:

```powershell
cargo test -p local-agent-terminal-storage-files
```

Expected: failure because the store does not exist.

**Step 2: Implement the minimal journaled store**

Use same-root temporary files, explicit flush/sync, content hashing, atomic rename, and journal state transitions represented by the existing SQLite `artifact_operations` contract through an application-owned port. Keep platform-specific directory sync behind a small internal function.

**Step 3: Run tests and commit**

```powershell
cargo test -p local-agent-terminal-storage-files
git add Cargo.toml Cargo.lock crates/storage-files
git diff --cached --check
git commit -m "feat(storage): add crash-safe artifact store"
```

## Task 8: Compose startup and expose typed Tauri commands

**Files:**

- Create: `crates/bootstrap/Cargo.toml`
- Create: `crates/bootstrap/src/lib.rs`
- Create: `crates/bootstrap/src/startup.rs`
- Create: `crates/bootstrap/src/logging.rs`
- Create: `crates/bootstrap/tests/startup.rs`
- Modify: `apps/desktop/src-tauri/Cargo.toml`
- Modify: `apps/desktop/src-tauri/src/lib.rs`
- Modify: `apps/desktop/src-tauri/src/main.rs`
- Modify: `Cargo.toml`

**Step 1: Write failing bootstrap tests**

Test:

- bootstrap is the only crate constructing SQLite/filesystem adapters;
- startup validates database schema, artifact root, and required application directories before returning ready;
- failures return stable codes, safe user text, recovery actions, and detailed local diagnostic context;
- structured logs include trust tier and observation class and redact configured secret values;
- the Tauri-facing DTO is immutable serializable data and contains no database handle/path capability.

Run:

```powershell
cargo test -p local-agent-terminal-bootstrap
```

Expected: failure because composition does not exist.

**Step 2: Implement composition and commands**

Compose adapters into the startup use case. Expose only `get_startup_status`, `retry_startup_validation`, and `get_local_diagnostics` Tauri commands for M0. Do not expose generic SQL, filesystem, or shell commands.

**Step 3: Run tests and commit**

```powershell
cargo test -p local-agent-terminal-bootstrap
cargo check -p local-agent-terminal-desktop
git add Cargo.toml Cargo.lock crates/bootstrap apps/desktop/src-tauri
git diff --cached --check
git commit -m "feat(desktop): compose secure startup boundary"
```

## Task 9: Replace the generated React demo with an accessible startup shell

**Files:**

- Create: `apps/desktop/src/api/startup.ts`
- Create: `apps/desktop/src/features/startup/StartupScreen.tsx`
- Create: `apps/desktop/src/features/startup/StartupScreen.test.tsx`
- Create: `apps/desktop/src/features/startup/startup-model.ts`
- Create: `apps/desktop/src/styles/tokens.css`
- Create: `apps/desktop/src/styles/base.css`
- Create: `apps/desktop/src/test/setup.ts`
- Modify: `apps/desktop/src/App.tsx`
- Modify: `apps/desktop/src/main.tsx`
- Modify: `apps/desktop/index.html`
- Modify: `apps/desktop/package.json`
- Delete: generated demo assets/styles no longer referenced

**Step 1: Read the relevant React rule files**

Before editing React, read:

- React performance `bundle-barrel-imports`;
- `async-parallel`;
- `rerender-derived-state-no-effect`;
- `rerender-move-effect-to-event`;
- `rendering-content-visibility`;
- `rendering-conditional-render`.

Record the applied rules in the task report.

**Step 2: Write failing interaction/accessibility tests**

Test:

- loading, ready, recoverable failure, and indeterminate states render exact text and never infer success;
- retry is an explicit user event and cannot double-submit;
- diagnostics are reachable by keyboard;
- initial focus, retry focus, and status announcements are correct;
- semantic landmarks/headings exist;
- no obvious axe-core violations;
- status is not conveyed by color alone;
- reduced-motion and 200% zoom styles retain usable layout.

Run:

```powershell
pnpm --dir apps/desktop test --run
```

Expected: failure because the startup feature and test setup do not exist.

**Step 3: Implement the minimum shell**

Create a restrained desktop layout with a skip link, header, main startup/health region, and local diagnostics disclosure. Use direct imports, native buttons/details, a fixed token scale, one primary retry action, visible focus, an `aria-live` status region, and no decorative dashboard charts.

**Step 4: Verify and commit**

```powershell
pnpm --dir apps/desktop test --run
pnpm --dir apps/desktop build
git add apps/desktop
git diff --cached --check
git commit -m "feat(ui): add accessible startup health shell"
```

## Task 10: Add architecture guards, CI, and the M0 verification artifact

**Files:**

- Create: `scripts/check-architecture.mjs`
- Create: `tests/contracts/architecture.test.mjs`
- Create: `.github/workflows/ci.yml`
- Create: `artifacts/verification/m0/manifest.json`
- Create: `artifacts/verification/m0/review.md`
- Create: `artifacts/verification/m0/known-limitations.md`
- Modify: root workspace configuration only if required by the checks

**Step 1: Write a failing architecture check**

Assert from `cargo metadata` that:

- `domain` has no forbidden dependency;
- `application` depends only on domain and general-purpose serialization/error libraries;
- storage/bootstrap/Tauri dependency arrows point inward;
- no workspace crate cycle exists;
- React imports no Rust source, generated SQL handle, or generic invoke wrapper outside `src/api`.

Run:

```powershell
node --test tests/contracts/architecture.test.mjs
```

Expected: fail until the checker and any missing workspace metadata are wired.

**Step 2: Implement the guard and CI jobs**

CI runs design contracts, architecture checks, Rust format/lint/tests, frontend typecheck/tests/build, and a Windows Tauri debug build. Keep secret-dependent provider/signing jobs out of M0.

**Step 3: Run the complete M0 gate**

Run:

```powershell
node scripts/verify-design-contracts.mjs
node --test tests/contracts/*.test.mjs
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace --all-targets
pnpm --dir apps/desktop test --run
pnpm --dir apps/desktop build
cargo build -p local-agent-terminal-desktop
git diff --check
```

Expected: every command exits 0.

**Step 4: Record evidence**

Populate `artifacts/verification/m0/manifest.json` with tool versions, commands, exit codes, timestamps, and SHA-256 output hashes. `review.md` must contain both spec-compliance and code-quality verdicts. `known-limitations.md` must state that repository mutation, agents, tools, and provider calls are intentionally unavailable until their milestones.

**Step 5: Commit**

```powershell
git add .github scripts tests artifacts/verification/m0 Cargo.toml apps/desktop crates
git diff --cached --check
git commit -m "ci: enforce M0 architecture and release gates"
```

## Task 11: Perform milestone review and prepare M1

**Files:**

- Modify: `.superpowers/sdd/progress.md`
- Modify: `artifacts/verification/m0/review.md`
- Create: `docs/superpowers/plans/2026-07-23-m1-workspace-recovery.md`

**Step 1: Generate a full milestone diff package**

Use the baseline commit recorded before Task 2 and the current `HEAD`. Dispatch a fresh final reviewer with the M0 brief, implementer reports, verification manifest, and full diff package.

**Step 2: Resolve every critical/important finding**

Dispatch one fix worker with the complete finding list, rerun covering tests, regenerate the diff package, and re-review until both spec compliance and code quality are approved.

**Step 3: Re-run the M0 gate**

Run the full Task 10 command set again and update evidence hashes.

**Step 4: Write the detailed M1 plan**

Base the next plan on the proven M0 interfaces and exact M1 exit criteria. Do not begin M1 implementation before its plan passes a conflict scan.

**Step 5: Commit reviewed evidence and the next plan**

```powershell
git add artifacts/verification/m0 docs/superpowers/plans/2026-07-23-m1-workspace-recovery.md
git diff --cached --check
git commit -m "docs: approve M0 and plan workspace recovery"
```
