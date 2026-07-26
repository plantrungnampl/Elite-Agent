# M1 Repository Isolation and Workspace Recovery Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax so progress can be tracked without changing the immutable design package.

**Goal:** Add the first safe repository vertical slice: trusted repository health inspection, durable project/task/worktree records, isolated task worktrees, one fenced executor lease, authoritative mutation detection, deterministic startup reconciliation, and an accessible task/recovery dashboard. The original user checkout and index must remain unchanged.

**Architecture:** Keep the existing Clean Architecture dependency direction. `domain` remains pure and reuses its existing `WorkflowState`/`reduce` implementation for `WorkspaceDirty` and fencing semantics. `application` owns repository, workspace, lease, query, and recovery ports. A new `repository-git` adapter uses an in-process, vendored libgit2 implementation for local Git operations; it never exposes a generic Git command. SQLite implements the new durable ports using the existing normative tables. `bootstrap` composes the adapters and performs startup reconciliation. Tauri remains a thin typed command adapter, and React renders only core DTOs.

**Tech Stack:** Rust 1.97 MSVC, Cargo workspace, SQLite/rusqlite, cap-std/cap-fs-ext, `serde_json_canonicalizer` 0.3, `git2` 0.21 with `default-features = false` and features `vendored-libgit2,unstable-sha256` plus its matching `libgit2-sys` 0.18.4 checkout-options binding, Tauri 2, React/TypeScript/Vite, Vitest, Testing Library, Playwright, axe-core, Node `node:test`, and GitHub Actions Windows runners.

## Global Constraints

- All implementation changes in this plan happen in `D:\multiagent` on the existing `codex/product-build-root` branch. Do not create or use a developer Git worktree. Tests may create disposable temporary Git worktrees; those are product fixtures, not implementation worktrees.
- `docs/multi-agent-terminal-design/**` is immutable. Do not edit, reformat, regenerate, or update its checksums.
- Follow the approved product-delivery program and the M1 exit criteria in `11-mvp-roadmap.md`: unchanged original checkout, stale-token rejection, `WorkspaceDirty`, no silent unknown-command replay, and explicit Windows path/junction/lock/submodule/LFS results.
- Reuse the existing `WorkflowState`, `WorkflowEvent`, `FencingToken`, `WorkspaceVersion`, `Phase::WorkspaceDirty`, and `reduce` behavior. Do not create a second workflow or mutation state machine.
- The domain crate has no filesystem, Git, process, database, Tauri, or OS dependency. Application traits are object-safe and own all adapter-facing contracts.
- `repository-git` is trusted core code only. It uses libgit2 APIs and typed requests; there is no shell, arbitrary command, user-controlled executable, PATH lookup, or process spawn.
- Before any checkout or worktree materialization, inspect an isolated configuration snapshot with system/global/environment includes disabled, and inspect tree attributes and `.gitmodules`. Fail closed for `include`/`includeIf`, `core.hooksPath`, `core.fsmonitor`, `credential.helper`, `core.sshCommand`, remote helpers/URLs, every `filter.*` process/smudge/clean driver, LFS, submodule recursion, unsafe diff/merge drivers, unsupported Git extensions, detached/unborn HEAD, and unsafe path forms. M1 never enables or executes hooks, filters, submodules, LFS, build scripts, tests, or repository executables. All checkout filters, including CRLF normalization, are disabled at the libgit2 boundary; the CRLF fixture must explicitly prove exact blob bytes and no false `WorkspaceDirty`. Those capabilities require M2 containment and policy.
- Persist a queryable worktree operation intent and its canonical request evidence before a Git side effect. Worktree creation is queryable; startup adopts only an exact repository identity/base/branch/path match. Conflicts, missing metadata, orphan refs, and pruned worktrees are preserved and surfaced, never force-reset, pruned, overwritten, or silently deleted.
- Every lease-controlled write path validates the current fencing token immediately before its effect. Token epochs are durable, strictly increasing, never reused, and stale requests produce a typed conflict with zero Git/filesystem effect. A stale rejection may append a non-workspace security/audit event, but it does not fabricate `workspace.mutated` evidence or change repository bytes; only an authoritative observed mutation enters `WorkspaceDirty`. Lease replacement and workspace mutation are serialized in SQLite `BEGIN IMMEDIATE` transactions, and the coordinator serializes the assertion and adapter call as one boundary.
- The existing one-row-per-task `executor_leases` shape and its `holder_run_id` foreign key are respected. Production code creates a real trusted core system-run record (including its descriptor/context/artifact references) before acquiring a lease; replacement preserves the prior token and holder in an immutable lease-replacement event and leaves the row in the DDL-approved `revoked` state until the new claim is committed. Tests do not insert dangling IDs or disable foreign keys.
- `workspace.mutated` atomically appends evidence, updates the task projection through the existing domain reducer, increments workspace/fencing versions, revokes the lease, and blocks new writes. The UI never performs optimistic state mutation.
- Unknown or non-repeatable started operations become interrupted/indeterminate evidence and are never replayed merely because completion is absent. Only a known queryable worktree intent may be offered an explicit reconcile/retry action after authoritative absence is proven.
- Tauri commands are a narrow allowlist of typed DTOs. React cannot import Rust/SQLite/path handles, invoke Git, select an operation payload, or invent recovery actions. No raw shell, terminal, provider, agent, approval, policy, process, network, or exact-tree commit feature is added in M1.
- Handwritten production behavior is test-first. Each task below has a failing test, a minimal implementation, a passing focused test, and a reviewable commit. Use `apply_patch` for source edits and keep unrelated files untouched.

## Task 1: Pin executable M1 contracts and architecture seams

**Files:**

- Create: `tests/contracts/m1-contracts.test.mjs`
- Create: `tests/contracts/fixtures/m1/unknown-operation.json`
- Create: `tests/contracts/fixtures/m1/repository-git-outward-metadata.json`
- Modify: `scripts/check-architecture.mjs`
- Modify: `tests/contracts/architecture.test.mjs`
- Verify: `docs/multi-agent-terminal-design/11-mvp-roadmap.md`, `15-crash-consistency-recovery.md`, `16-workflow-transition-specification.md`

**Interfaces:**
- Consumes/produces: Consumes the existing normative workflow/SQLite contracts and Cargo metadata. Produces executable checks for the new `repository-git` adapter boundary, typed command allowlist, immutable design package, and M1-only scope.

- [ ] **Step 1 — Write failing contract tests**

Add Node tests that fail against M0 because the architecture checker does not yet understand the M1 adapter fixture. The tests must assert:

1. A synthetic `repository-git` package depends inward only on `application`/`domain` plus justified Git libraries, and the outward-dependency fixture is rejected.
2. `domain` and `application` do not depend on `repository-git`, SQLite, filesystem, or Tauri.
3. Concrete Git/SQLite/artifact construction remains in `bootstrap`.
4. React invokes only through `src/api/`, and no source contains generic shell/Git/filesystem invocation.
5. The design directory is byte-for-byte unchanged from baseline.
6. The architecture checker rejects generic Tauri command names such as `shell`, `git`, `filesystem`, `exec`, or `run_command`; production command presence is activated in Task 8.
7. M1 fixtures classify an unknown started operation as indeterminate and do not contain an executable replay instruction.

Run:

```powershell
node --test tests/contracts/m1-contracts.test.mjs
```

Expected failure: the new synthetic adapter/command rules are absent. The baseline immutability assertion must already pass.

- [ ] **Step 2 — Implement only the contract checker**

Extend `scripts/check-architecture.mjs` with the new inward dependency allowlist and the React/Tauri command checks. Keep the existing M0 rules intact. Do not add production code to satisfy a contract in this task.

- [ ] **Step 3 — Run the focused checks**

```powershell
node --test tests/contracts/m1-contracts.test.mjs
node tests/contracts/design-contracts.test.mjs
```

Expected: the new fixture is rejected for the intended outward edge, the unknown-operation fixture remains non-replayable, and all M0 contract checks remain green. No committed test is left intentionally failing.

- [ ] **Step 4 — Commit**

```powershell
git add tests/contracts scripts/check-architecture.mjs
git diff --cached --check
git commit -m "test: pin repository recovery architecture contracts"
```

## Task 2: Extend pure identity and lease domain rules without duplicating workflow state

**Files:**

- Modify: `crates/domain/src/identity.rs`
- Modify: `crates/domain/src/lib.rs`
- Create: `crates/domain/src/workspace.rs`
- Create: `crates/domain/tests/workspace_contract.rs`

**Interfaces:**
- Consumes/produces: Consumes existing `TaskId`, `FencingToken`, `WorkspaceVersion`, `WorkflowState`, and `ValueError`. Produces validated `ProjectId`, `RunId`, `ArtifactId`, `RepositoryId`, `WorktreeId`, `GitObjectId`, `TaskBranch`, `WorkspaceFingerprint`, `LeaseClaim`, and a pure stale-token guard.

- [ ] **Step 1 — Write failing unit tests**

Cover empty/whitespace identifiers, branch/ref characters, SHA-1 and SHA-256 object IDs, malformed fingerprints, token monotonicity, and the rule that `supplied_token == current_token` is the only authorized write. Assert that a stale token returns a typed domain error and never changes a version.

```powershell
cargo test -p local-agent-terminal-domain --test workspace_contract
```

Expected failure: the new types and guard are absent.

- [ ] **Step 2 — Implement the smallest value objects**

Use the existing non-empty-ID macro style. Keep paths out of the domain; represent repository identity and Git objects as opaque validated strings. Add `WorkspaceFingerprint { head, index_digest, status_digest }` and `LeaseClaim { task_id, holder_run_id, token }` with equality and display methods needed by adapters. Add `authorize_fenced_write(current, claim)` returning a typed `StaleFencingToken`/`LeaseNotActive` error.

Do not add a second `WorkspaceDirty` enum or alter the normative workflow JSON. The existing reducer remains the sole source of phase/version/fence transitions.

- [ ] **Step 3 — Run focused and regression tests**

```powershell
cargo fmt --all -- --check
cargo test -p local-agent-terminal-domain --test workspace_contract
cargo test -p local-agent-terminal-domain
```

Expected: all new and existing domain tests pass.

- [ ] **Step 4 — Commit**

```powershell
git add crates/domain
git diff --cached --check
git commit -m "feat: add repository and fenced workspace identities"
```

## Task 3: Add application-owned repository, workspace, lease, and query ports

**Files:**

- Create: `crates/application/src/repository.rs`
- Create: `crates/application/src/workspace.rs`
- Create: `crates/application/src/lease.rs`
- Create: `crates/application/src/canonical_json.rs`
- Modify: `crates/application/Cargo.toml`
- Modify: `crates/application/src/ports.rs`
- Modify: `crates/application/src/dto.rs`
- Modify: `crates/application/src/error.rs`
- Modify: `crates/application/src/lib.rs`
- Create: `crates/application/tests/workspace_ports.rs`

**Interfaces:**
- Consumes/produces: Consumes domain identities and the existing event/artifact/clock/id ports. Produces object-safe ports and typed request/response DTOs for onboarding, worktree intents, lease operations, mutation recording, timeline queries, and recovery actions.

- [ ] **Step 1 — Write failing fake-adapter tests**

Define fakes that prove:

- repository inspection returns health, stable identity, default branch, base commit, original checkout status, and hazard reasons without exposing an OS handle;
- a worktree intent is recorded before `create`;
- exact-match adoption is accepted while a path/branch/base mismatch is preserved as a conflict;
- lease acquisition has one winner, replacement tokens increase, and stale authorization returns `PortError::VersionConflict`/`SafeErrorClassification::Conflict`;
- `record_workspace_mutation` is one atomic application operation, not a UI-side sequence;
- timeline results are ordered by persisted sequence;
- non-repeatable indeterminate intents expose no retry action;
- RFC 8785 number, Unicode, escaping, and object-order vectors produce stable canonical bytes and `sha256:` digests.

```powershell
cargo test -p local-agent-terminal-application --test workspace_ports
```

Expected failure: the ports, DTOs, and typed error variant are absent.

- [ ] **Step 2 — Define stable port signatures**

Add these application-owned contracts (names may be module-qualified but must remain equivalent):

```rust
pub trait RepositoryGateway: Send + Sync {
    fn inspect(&self, request: InspectRepository) -> Result<RepositorySnapshot, PortError>;
    fn create_worktree(&self, request: CreateWorktree) -> Result<WorktreeSnapshot, PortError>;
    fn list_worktrees(&self, repository: &RepositoryLocator) -> Result<Vec<WorktreeSnapshot>, PortError>;
    fn discard_worktree(&self, request: DiscardWorktree) -> Result<(), PortError>;
}

pub trait WorkspaceStateStore: Send + Sync {
    fn create_project(&self, project: NewProject) -> Result<ProjectSnapshot, PortError>;
    fn create_task(&self, task: NewTask) -> Result<TaskSnapshot, PortError>;
    fn begin_worktree_intent(&self, intent: WorktreeIntent) -> Result<OperationIntent, PortError>;
    fn transition_worktree_intent(&self, transition: IntentTransition) -> Result<(), PortError>;
    fn reconcile_intents(&self) -> Result<Vec<RecoveryCandidate>, PortError>;
    fn dashboard(&self, project: &ProjectId) -> Result<WorkspaceDashboardDto, PortError>;
}

pub trait ExecutorLeaseStore: Send + Sync {
    fn acquire(&self, request: AcquireLease) -> Result<LeaseSnapshot, PortError>;
    fn revoke(&self, request: RevokeLease) -> Result<(), PortError>;
    fn fence_stale(&self) -> Result<Vec<LeaseSnapshot>, PortError>;
    fn assert_current(&self, claim: LeaseClaim) -> Result<(), PortError>;
}

pub trait WorkspaceMutationStore: Send + Sync {
    fn record_workspace_mutation(
        &self,
        request: WorkspaceMutationRequest,
    ) -> Result<WorkspaceMutationResult, PortError>;
}

pub trait TaskQuery: Send + Sync {
    fn task(&self, task_id: &TaskId) -> Result<TaskSnapshot, PortError>;
    fn timeline(&self, task_id: &TaskId) -> Result<Vec<TimelineEntryDto>, PortError>;
}
```

Define the minimum owned DTO shapes in this module so every adapter and Tauri command has one contract:

```rust
pub struct WorkspaceDashboardDto {
    pub project_id: ProjectId,
    pub repository: RepositorySnapshot,
    pub tasks: Vec<TaskSnapshot>,
    pub recovery: Vec<RecoveryCandidate>,
}

pub struct TimelineEntryDto {
    pub sequence: u64,
    pub event_type: String,
    pub created_at: String,
    pub summary: String,
    pub evidence: Option<EvidenceSummaryDto>,
}

pub struct EvidenceSummaryDto {
    pub artifact_id: String,
    pub content_hash: String,
    pub size_bytes: u64,
}

```

`RepositorySnapshot`, `WorktreeSnapshot`, `ProjectSnapshot`, `TaskSnapshot`, `OperationIntent`,
`RecoveryCandidate`, `NewProject`, `NewTask`, `WorktreeIntent`, `IntentTransition`, `InspectRepository`,
`CreateWorktree`, `DiscardWorktree`, `AcquireLease`, `RevokeLease`, `LeaseSnapshot`,
`WorkspaceMutationRequest`, `WorkspaceMutationResult`, `CanonicalJsonRequest`, and
`CanonicalEvidenceRef` are owned Rust structs with bounded strings, opaque IDs, explicit expected/current
versions, and no filesystem or OS handles. `RepositoryLocator` and `ManagedWorktreePath` are trusted
non-serializable application values containing a canonical path plus the repository identity; they never
cross Tauri. `CreateWorktree` and `DiscardWorktree` each carry a `LeaseClaim`, expected workspace version,
and a `ManagedWorktreePath`. Their
minimum required fields are:

```text
RepositorySnapshot:
  repository_id, health, stable_identity, default_branch?, base_commit?,
  original_checkout, hazards[], fingerprint
RepositoryLocator (non-serializable):
  repository_id, stable_identity, canonical_workdir, canonical_common_dir, object_format
ManagedWorktreePath (non-serializable):
  trusted_root_id, relative_leaf, redacted_display
WorktreeSnapshot:
  worktree_id, repository_id, task_id, branch, base_commit, target_path_display,
  state, expected_presence, fingerprint
CreateWorktree / DiscardWorktree:
  repository_locator, managed_path, task_id, lease_claim, expected_workspace_version,
  exact branch/base/worktree identity
TaskSnapshot:
  task_id, project_id, title, phase, condition, operation_state,
  base_branch, base_commit, task_branch?, worktree?, workspace_version, fencing_epoch,
  lease_state, recovery_candidates[]
OperationIntent:
  id, task_id, operation_kind, idempotency_class, idempotency_key,
  canonical_request_artifact_id, operation_digest, status, executor_fencing_token?,
  attempt_count, created_at, updated_at
RecoveryCandidate:
  intent_id?, worktree_id?, reason, evidence, actions[]
CanonicalJsonRequest:
  artifact_id, project_id, task_id?, artifact_type, logical_path, created_by_type,
  created_by_id, canonical_bytes, expected_hash, expected_size, idempotency_key
CanonicalEvidenceRef:
  artifact_id, content_hash, storage_key, size_bytes, project_id, task_id?
WorkspaceMutationRequest:
  task_id, expected_sequence, claim, pre_fingerprint, post_fingerprint,
  pre_evidence, post_evidence, actor_id, correlation_id
WorkspaceMutationResult:
  event_id, new_sequence, task_state, resume_target?, invalidated_approval_ids[]
```

`health`, `original_checkout`, `state`, `lease_state`, `idempotency_class`, `status`, and `reason` are
closed enums serialized by the outer DTO layer; no adapter string is treated as an action or executable.
`RecoveryActionDto` is the only action vocabulary exposed to the UI. Add a typed stale-lease error while
preserving safe classification/retryability semantics. `CanonicalJsonRequest` is RFC 8785/JCS
canonicalized and hashed as `sha256:<lowercase-hex>` before the file writer is called; the returned
`CanonicalEvidenceRef.artifact_id` is the value used by the SQLite foreign key. Do not add a one-implementation
evidence-store abstraction: reuse the existing `ArtifactJournal`, `ArtifactWriteReservation`,
`JournaledArtifactWriter`, and `ArtifactRef` types. A pure
`canonical_evidence(request, artifact_ref) -> Result<CanonicalEvidenceRef, PortError>` helper only verifies
that the published hash/size match the reservation and joins the existing artifact ID to the file reference.

- [ ] **Step 3 — Implement focused use-case shells**

Add `OnboardRepository`, `PrepareTaskWorkspace`, `ReconcileWorkspaces`, `ObserveWorkspaceMutation`, `AcquireExecutorLease`, and `GetWorkspaceDashboard` as thin application services. They validate domain inputs and sequence ports; they do not import adapters or Tauri. Implement canonical JSON once with `serde_json_canonicalizer` 0.3 and SHA-256; run the RFC 8785 number, Unicode, escaping, and property-order vectors here rather than duplicating serializers in adapters.

- [ ] **Step 4 — Run tests and architecture checks**

```powershell
cargo test -p local-agent-terminal-application --test workspace_ports
node scripts/check-architecture.mjs
```

Expected: all fake-port tests pass; the architecture checker still reports the not-yet-created adapter package only if the contract fixture intentionally requires it.

- [ ] **Step 5 — Commit**

```powershell
git add crates/application
git diff --cached --check
git commit -m "feat: define repository and recovery application ports"
```

## Task 4: Implement SQLite project/task intents, timelines, system runs, and fenced leases

**Files:**

- Create: `crates/storage-sqlite/src/project_store.rs`
- Create: `crates/storage-sqlite/src/workspace_store.rs`
- Create: `crates/storage-sqlite/src/lease_store.rs`
- Create: `crates/storage-sqlite/src/task_query.rs`
- Modify: `crates/storage-sqlite/src/lib.rs`
- Modify: `crates/storage-sqlite/src/event_store.rs`
- Create: `crates/storage-sqlite/tests/workspace_recovery.rs`
- Modify: `crates/storage-sqlite/tests/schema_health.rs`

**Interfaces:**
- Consumes/produces: Implements the application ports from Task 3 on `SqliteStore`, using the existing normative `projects`, `tasks`, `events`, `artifacts`, `operation_intents`, `agent_descriptors`, `context_packages`, `agent_runs`, and `executor_leases` tables. No schema migration is added unless a failing invariant test proves a missing constraint; any such migration must be additive, versioned, checksum-validated, and preserve v1/v2 checksums.

- [ ] **Step 1 — Write failing SQLite tests**

Use temporary databases and real concurrent connections to test:

1. project onboarding stores identity/health metadata without touching repository bytes;
2. task creation persists base branch/commit, branch/path intent, and canonical evidence before Git work;
3. one lease acquisition wins under a race;
4. stale token validation rejects with no projection or filesystem callback;
5. replacement increments the task epoch, records the old token/holder in an immutable lease event, and never deletes the lease row;
6. a trusted core system-run row satisfies the `holder_run_id` foreign key;
7. `workspace.mutated` appends its event, updates phase/workspace/fence, revokes the lease, and invalidates candidate state in one transaction;
8. timeline queries are sequence ordered and event payloads remain immutable;
9. started unknown/non-repeatable intents become indeterminate on reconciliation and are never replayed;
10. exact worktree intent adoption requires repository identity, base commit, branch, target path, and Git metadata to all match;
11. mutation invalidates pending plan/tool/commit approvals with a reason and clears `tasks.active_candidate_tree`, with rollback proving all-or-nothing behavior;
12. rebuilding task/workspace/lease projections from events and artifact references performs no Git/filesystem call.

```powershell
cargo test -p local-agent-terminal-storage-sqlite --test workspace_recovery
```

Expected failure: the new tables’ adapters and transaction methods are absent.

- [ ] **Step 2 — Add a trusted core system-run path**

Implement one deterministic helper invoked after the task row exists and before a lease can be acquired. For each manifest/context/run-config artifact, reuse the existing sequence: reserve the `artifacts` row plus `artifact_operations` intent, write/flush/hash/rename through `JournaledArtifactWriter`, transition the artifact to `available`, then open a separate `BEGIN IMMEDIATE` transaction to insert/reuse the `core_adapter` descriptor, task-bound context package, and `agent_runs` row with a stable idempotency key and connection-binding digest. Never call the filesystem writer while holding the SQLite transaction or claim cross-store atomicity. A crash leaves a queryable artifact journal entry that startup reconciles before the run/lease can exist.

- [ ] **Step 3 — Implement transactional stores**

Use `BEGIN IMMEDIATE` for project/task/intents/lease operations. Canonical evidence follows the same existing artifact-journal sequence and must be `available` before a separate transaction inserts `operation_intents.canonical_request_artifact_id`; reuse the stable idempotency key if a published artifact survived a crash. Persist repository health/hazards/fingerprint as a canonical artifact referenced by a `repository.inspected` project-stream event. Persist worktree expected presence/repository identity/base/branch/path in the queryable intent artifact and project `task_branch`/`worktree_path` into `tasks`. No schema migration is needed unless these event/artifact projections fail a concrete invariant test.

Acquire a lease by incrementing `tasks.fencing_epoch`, then inserting/updating the matching lease token in the same transaction. Revoke/fence stale leases without deleting history. Implement mutation recording as one transaction that appends `workspace.mutated` with pre/post artifact IDs and `resumeTarget`, applies the existing reducer-produced phase/workspace/fence projection, clears `tasks.active_candidate_tree`, invalidates affected pending approvals with `invalidation_reason`, and revokes the lease. `resumeTarget` lives in the immutable event/recovery projection, not in `WorkflowState`.

Keep `event_store.rs`’s optimistic stream version behavior and add one dedicated atomic mutation projection variant. Dashboard/rebuild code reads the latest immutable events/artifacts and task projection only; it never calls Git or the filesystem.

- [ ] **Step 4 — Run focused and regression tests**

```powershell
cargo fmt --all -- --check
cargo test -p local-agent-terminal-storage-sqlite --test workspace_recovery
cargo test -p local-agent-terminal-storage-sqlite
cargo test --workspace --all-targets
```

Expected: all new race/recovery tests and all M0 tests pass.

- [ ] **Step 5 — Commit**

```powershell
git add crates/storage-sqlite
git diff --cached --check
git commit -m "feat: persist workspace intents and fenced leases"
```

## Task 5: Build the trusted in-process Git repository adapter

**Files:**

- Create: `crates/repository-git/Cargo.toml`
- Create: `crates/repository-git/src/lib.rs`
- Create: `crates/repository-git/src/inspect.rs`
- Create: `crates/repository-git/src/paths.rs`
- Create: `crates/repository-git/src/worktree.rs`
- Create: `crates/repository-git/src/hazards.rs`
- Create: `crates/repository-git/src/unsafe_checkout.rs`
- Create: `crates/repository-git/tests/repository_matrix.rs`
- Create: `crates/repository-git/tests/support/mod.rs`
- Modify: `Cargo.toml`
- Modify: `scripts/check-architecture.mjs`

**Interfaces:**
- Consumes/produces: `GitRepositoryGateway::open(trusted_workspace_root: &Path, excluded_roots: &[PathBuf]) -> Result<Self, PortError>` implements `RepositoryGateway` without exposing `git2::Repository`, OS handles, or arbitrary commands to application/Tauri. It stores validated roots plus a process-local `Mutex<()>`; each call reopens the repository from a non-serializable `RepositoryLocator` while holding the mutex because `git2::Repository` is not `Sync` and SHA-256 support is serialized.

- [ ] **Step 1 — Write failing adapter tests**

Create temporary repositories with `tests/support/mod.rs`, using only `git2::Repository::init` plus direct inert file/config writes—never `Command`, shell, PATH, hooks, or repository executables—and assert:

- clean, dirty, staged, unstaged, untracked, detached, unborn, shallow, sparse, Unicode, spaces, long paths, locked target, and case-collision outcomes are typed;
- repository identity is stable across repeated inspection and includes canonical common-dir/object-format evidence;
- default branch and base commit are captured only when HEAD is born and attached;
- the original checkout files, index bytes, HEAD, and status are byte-for-byte unchanged after worktree creation;
- target branch/path conflicts are preserved;
- custom hooks/filter/process/LFS/submodule hazards are rejected before checkout;
- a sentinel hook/filter executable is never touched;
- system/global/include config, inherited `GIT_*`, fsmonitor, credential/SSH/remote helpers, `core.worktree`, gitdir indirection, and reparse-point swaps are rejected or isolated before checkout;
- the target is a fresh child under the configured trusted workspace root and outside the original checkout, common Git directory, and artifact root;
- worktree list parsing accepts only exact records and reports pruned/orphan/conflicting records;
- SHA-1 and SHA-256 object IDs are retained without truncation, with concurrent SHA-256 calls serialized;
- a concurrent branch/ref move makes the no-force conditional update fail with no ref/worktree overwrite.

```powershell
cargo test -p local-agent-terminal-repository-git --test repository_matrix
```

Expected failure: the crate and gateway implementation are absent.

- [ ] **Step 2 — Add the safe adapter boundary**

Use `git2` 0.21 with `default-features = false`, `vendored-libgit2`, and `unstable-sha256`; enable no network/SSH feature and serialize all libgit2 calls with the adapter mutex. SHA-256 open/read/CAS tests are a hard M1 gate, not an optional limitation.

Keep all adapter code safe except one reviewed `unsafe_checkout.rs` helper using the matching `libgit2-sys` 0.18.4 type. It mutates the vendored `git_worktree_add_options.checkout_options.disable_filters` field before `Repository::worktree`, denies unsafe operations inside unsafe functions, and has a sentinel integration test proving a configured filter process is never touched. There is no fallback checkout path: if the libgit2 option layout/version cannot be initialized and verified, worktree creation returns a typed unavailable error and Task 5/M1 cannot pass.

Open repositories read-only for inspection with system/global/environment config and includes excluded. Reject every untrusted executable/config surface listed in the global constraints. Validate the selected workdir, `.git` file target, common directory, object format, and `core.worktree` containment. On Windows, open the trusted workspace root and fresh empty target directory with directory handles that do not share delete access, reject reparse tags, validate final handle paths/file IDs, keep those handles alive through `Repository::worktree`, and revalidate immediately after. If the platform cannot maintain that last-responsible-moment containment guarantee, fail closed without pruning/deleting anything. Reject UNC/device/ADS forms, case/reserved-name collisions, and any target inside the original checkout/common Git directory/artifact root.

- [ ] **Step 3 — Implement queryable worktree operations**

Create an application-generated branch name and managed target path only after the canonical intent is durable. The coordinator transitions the intent from `pending` to `started`, recording attempt count and current fencing token, immediately before crossing into `GitRepositoryGateway`; after return it records `succeeded` or typed `failed`. A crash leaves `started`, which startup queries rather than replays.

Create the branch with libgit2’s no-force conditional ref API: the branch must be absent and based on the captured exact base OID; any existing/moved ref is a conflict and remains untouched. Later ref changes use `reference_matching(current_id, new_id)` and treat `GIT_EMODIFIED` as a typed conflict. Conditional ref support, exact OIDs, worktrees, and LFS/submodule evidence are hard M1 gates.

Use the filter-disabled worktree helper, no recursive submodule updates, and no network. Record repository identity, base object ID, branch, target path, expected absence/presence, hazard summary, and workspace fingerprint. List/adopt only an exact match. Authoritative absence requires both no matching Git worktree metadata and no target branch/ref; orphan refs/paths are conflicts and are preserved. Discard only an exact managed worktree while the same containment handles are held and only when safety is proven; otherwise preserve it.

- [ ] **Step 4 — Run focused security and regression tests**

```powershell
cargo fmt --all -- --check
cargo test -p local-agent-terminal-repository-git --test repository_matrix
cargo test --workspace --all-targets
node scripts/check-architecture.mjs
```

Expected: all fixture cases pass and no untrusted sentinel is executed or opened.

- [ ] **Step 5 — Commit**

```powershell
git add Cargo.toml Cargo.lock crates/repository-git scripts/check-architecture.mjs
git diff --cached --check
git commit -m "feat: add trusted repository health and worktree adapter"
```

## Task 6: Compose task/worktree orchestration and deterministic startup recovery

**Files:**

- Create: `crates/bootstrap/src/workspace_runtime.rs`
- Modify: `crates/bootstrap/src/startup.rs`
- Modify: `crates/bootstrap/src/lib.rs`
- Modify: `crates/bootstrap/Cargo.toml`
- Create: `crates/bootstrap/tests/workspace_startup.rs`

**Interfaces:**
- Consumes/produces: Consumes application ports, `SqliteStore`, `ContentAddressedArtifactStore`, `repository-git`, and `RecoveryLock`. Produces a runtime coordinator with onboarding, task/worktree, lease, timeline, and recovery methods.

- [ ] **Step 1 — Write failing startup/recovery tests**

Test the exact recovery order: recovery lock, SQLite schema/health, artifact health/reconciliation, stale lease fencing, repository/worktree reconciliation, operation-intent reconciliation, then runtime exposure. Test concurrent startup lock failure, retry after unlock, exact worktree adoption, conflicting worktree preservation, and unknown operation indeterminate state. A started worktree intent is adopted only on an exact metadata/path/ref/base match; absence is recoverable only when both worktree metadata and target ref are absent. Assert no Git operation is issued while rebuilding projections or for an unknown intent.

```powershell
cargo test -p local-agent-terminal-bootstrap --test workspace_startup
```

Expected failure: `Runtime` has no workspace coordinator and startup stops after artifacts.

- [ ] **Step 2 — Add composition-root construction**

Construct concrete adapters only in `bootstrap`: `GitRepositoryGateway::open`, existing `SqliteStore`, existing `ContentAddressedArtifactStore`/`JournaledArtifactWriter`, and the application services. Extend `StartupConfig` with the trusted workspace root and artifact-root exclusion; keep secrets/logging redacted. Extend `Runtime` with the coordinator and stop/drop any monitor before replacing runtime on retry.

- [ ] **Step 3 — Implement the recovery state machine**

On startup, fence old leases before granting new ones, query each durable worktree intent, adopt only exact matches, mark a queryable worktree intent recoverable only after both worktree metadata and target ref are authoritatively absent, preserve conflicts/orphans, and mark unknown/non-repeatable started intents indeterminate. Recovery actions are persisted events/operation records and are safe to retry only after that query; startup never transitions `pending`/`started` back into execution on its own.

- [ ] **Step 4 — Run tests**

```powershell
cargo test -p local-agent-terminal-bootstrap --test workspace_startup
cargo test --workspace --all-targets
```

Expected: startup tests and all M0 tests pass with the new diagnostics still sanitized.

- [ ] **Step 5 — Commit**

```powershell
git add crates/bootstrap
git diff --cached --check
git commit -m "feat: reconcile worktrees and leases during startup"
```

## Task 7: Add authoritative mutation monitoring and fenced write rejection

**Files:**

- Create: `crates/bootstrap/src/workspace_monitor.rs`
- Modify: `crates/bootstrap/src/workspace_runtime.rs`
- Modify: `crates/application/src/workspace.rs`
- Modify: `crates/storage-sqlite/src/workspace_store.rs`
- Create: `crates/bootstrap/tests/workspace_monitor.rs`
- Create: `crates/application/tests/fencing_contract.rs`

**Interfaces:**
- Consumes/produces: Consumes `WorkspaceFingerprint`, `ExecutorLeaseStore`, `WorkspaceMutationStore`, and `RepositoryGateway`; produces a lifecycle-safe monitor and a fenced mutation boundary used by future M2 tools.

- [ ] **Step 1 — Write failing tests**

Use a spy write port and real temporary repositories to prove:

- an unchanged fingerprint is a no-op;
- an out-of-band file/index/status change triggers one authoritative rescan;
- `reduce(workspace.mutated)` enters `WorkspaceDirty` and increments workspace/fencing versions, while the same SQLite transaction stores `resumeTarget` in the event payload, clears the candidate, invalidates affected approvals with reasons, and revokes the lease;
- an old token is rejected before the spy effect, leaves repository bytes/mutation evidence unchanged, and may append only a typed non-workspace security rejection event;
- replacing a lease while an old request is queued never lets the old request write;
- rollback at any mutation-projection update leaves event, task, approvals, candidate, and lease unchanged;
- monitor shutdown on bootstrap retry/drop leaves no background thread holding adapters.

- [ ] **Step 2 — Implement the minimal monitor**

Use lifecycle-bound authoritative scans plus a low-rate runtime poll from the dashboard/runtime coordinator. Fast filesystem notifications are optional; every transition is guarded by a fresh Git/filesystem rescan. Do not add a broad watcher or process tool before measurement or M2 containment.

- [ ] **Step 3 — Implement the fenced boundary**

Require a `LeaseClaim` on every M1 write-capable workspace operation, including worktree create/discard. Under the coordinator’s single serialized boundary call `ExecutorLeaseStore::assert_current(claim)` immediately before the adapter call, with no queue or callback between them. Return typed conflict and no Git/filesystem effect for stale claims. Route authoritative pre/post evidence through the atomic SQLite operation from Task 4; rejected stale claims do not fabricate a `workspace.mutated` event.

- [ ] **Step 4 — Run tests**

```powershell
cargo test -p local-agent-terminal-application --test fencing_contract
cargo test -p local-agent-terminal-bootstrap --test workspace_monitor
cargo test --workspace --all-targets
```

Expected: all stale-token, mutation, and shutdown tests pass.

- [ ] **Step 5 — Commit**

```powershell
git add crates/application crates/bootstrap crates/storage-sqlite
git diff --cached --check
git commit -m "feat: detect workspace mutations and fence stale writers"
```

## Task 8: Expose typed Tauri commands and the accessible workspace/recovery UI

**Files:**

- Modify: `crates/application/src/dto.rs`
- Modify: `crates/bootstrap/src/lib.rs`
- Modify: `apps/desktop/src-tauri/src/lib.rs`
- Create: `apps/desktop/src/api/workspace.ts`
- Modify: `apps/desktop/src/App.tsx`
- Create: `apps/desktop/src/features/workspace/WorkspaceScreen.tsx`
- Create: `apps/desktop/src/features/workspace/workspace-model.ts`
- Create: `apps/desktop/src/features/workspace/WorkspaceScreen.test.tsx`
- Modify: `apps/desktop/src/styles/base.css`
- Modify: `apps/desktop/src/styles/tokens.css` only when a focused contrast test requires it
- Create: `apps/desktop/tests/browser/workspace-recovery.spec.ts`
- Modify: `apps/desktop/tests/browser/startup-smoke.spec.ts`

**Interfaces:**
- Consumes/produces: Consumes core `WorkspaceDashboardDto`, `RecoveryActionDto`, `TimelineEntryDto`, and typed bootstrap methods. Produces only these allowlisted commands: `get_workspace_dashboard`, `onboard_repository`, `create_task_workspace`, `reconcile_workspace`, `preserve_workspace`, and `discard_workspace`.

Use these exact outer contracts (Tauri state parameter omitted here for readability):

```rust
pub enum RecoveryActionCodeDto {
    Reconcile,
    Preserve,
    Discard,
}

pub struct RecoveryActionDto {
    pub candidate_id: String,
    pub code: RecoveryActionCodeDto,
    pub label: String,
}

fn get_workspace_dashboard(
    request: WorkspaceDashboardRequestDto,
) -> Result<WorkspaceDashboardDto, CommandErrorDto>;
fn onboard_repository(
    request: OnboardRepositoryRequestDto,
) -> Result<ProjectSnapshot, CommandErrorDto>;
fn create_task_workspace(
    request: CreateTaskWorkspaceRequestDto,
) -> Result<TaskSnapshot, CommandErrorDto>;
fn reconcile_workspace(
    request: RecoveryCandidateRequestDto,
) -> Result<WorkspaceDashboardDto, CommandErrorDto>;
fn preserve_workspace(
    request: RecoveryCandidateRequestDto,
) -> Result<WorkspaceDashboardDto, CommandErrorDto>;
fn discard_workspace(
    request: ConfirmDiscardWorkspaceRequestDto,
) -> Result<WorkspaceDashboardDto, CommandErrorDto>;
```

Every recovery request carries `candidate_id`, `project_id`, `task_id`, and expected workspace version;
discard additionally requires `confirmed: true`. The core reloads the candidate and verifies that the
requested closed enum action is currently authorized before executing it. Labels are display-only bounded
text, never action selectors.

- [ ] **Step 1 — Write failing component/API/browser tests**

Cover loading versus ready versus indeterminate, repository health/default branch/base commit, dirty/unsafe blocking of task creation, exact worktree and timeline rendering, prominent `WorkspaceDirty`, current fencing/revoked lease evidence, no Retry for indeterminate non-repeatable operations, single-submit recovery actions, discard confirmation, hostile text rendering, startup hard gate, keyboard skip/focus flow, 320px/200% reflow, reduced motion, and real-browser axe with color contrast enabled.

```powershell
pnpm --dir apps/desktop test --run
pnpm --dir apps/desktop test:browser
```

Expected failure: no workspace DTO/API/screen exists and the current app always renders only `StartupScreen`.

- [ ] **Step 2 — Add DTOs and thin command wrappers**

Serialize only bounded data and the closed `RecoveryActionCodeDto` enum. Do not return database connections, absolute application paths, Git handles, shell commands, or arbitrary path capabilities; `target_path_display` is explicitly redacted display text, not a capability. Validate repository path input and candidate/action IDs in Rust before onboarding/recovery; React cannot call Git or filesystem APIs or fabricate an action by sending a string.

- [ ] **Step 3 — Build the minimal screen**

Use semantic `main`, `form`, `dl`, `ol`, `time`, `details`, `button`, and `role="alert"`/`aria-live`. Show every state with icon plus text, never color alone. Keep the startup gate, visible focus, 44px controls, 320px layout, reduced-motion behavior, double-submit guard, and focus restoration after recovery. Render only actions returned by the core; discard requires explicit confirmation and preserves evidence on cancellation/failure.

- [ ] **Step 4 — Run focused frontend and browser checks**

```powershell
pnpm --dir apps/desktop test --run
pnpm --dir apps/desktop test:browser
pnpm --dir apps/desktop build
```

Expected: all component and real-browser accessibility tests pass; the post-startup screen appears only after authoritative `Ready`.

- [ ] **Step 5 — Commit**

```powershell
git add crates/application crates/bootstrap apps/desktop
git diff --cached --check
git commit -m "feat: add workspace timeline and recovery dashboard"
```

## Task 9: Complete the Windows/Git matrix, architecture guard, CI, and evidence

**Files:**

- Create: `artifacts/verification/m1/manifest.json`
- Create: `artifacts/verification/m1/review.md`
- Create: `artifacts/verification/m1/known-limitations.md`
- Create: `artifacts/verification/m1/toolchain.txt`
- Create: `scripts/verify-m1-evidence.mjs`
- Modify: `scripts/check-architecture.mjs`
- Modify: `tests/contracts/m1-contracts.test.mjs`
- Modify: `.github/workflows/ci.yml`
- Create/modify: `crates/repository-git/tests/windows_matrix.rs`
- Create/modify: `crates/bootstrap/tests/recovery_matrix.rs`
- Create/modify: `apps/desktop/tests/browser/workspace-recovery.spec.ts`

**Interfaces:**
- Consumes/produces: Consumes all M1 adapters/use cases/UI and produces reproducible gate evidence and Windows-specific acceptance records. No design document is regenerated.

- [ ] **Step 1 — Write failing matrix/evidence checks**

Assert a real temporary-repository matrix for clean/dirty/original-index preservation, spaces/metacharacters, Unicode, long paths, locks, static and swap-race junctions/symlinks, UNC/device/ADS rejection, nested/common-dir/artifact-root target rejection, branch/path/CAS conflicts, crash boundaries and pending/started intent recovery, stale lease replacement, projection-only replay, approval/candidate invalidation rollback, unknown intent handling, SHA-1/SHA-256 exact IDs, submodule/LFS/custom filter/hook/fsmonitor/include/credential/SSH/remote-helper fail-closed behavior, shallow/sparse/detached/unborn repositories, and CRLF configuration with checkout filters disabled. The in-process adapter must prove no child process is spawned and every sentinel executable remains untouched.

Run the focused matrix and expect failures for the absent adapter evidence/CI entries.

- [ ] **Step 2 — Implement evidence and CI**

Record exact tool versions, command exit codes, durations, output hashes, fixture classifications, and known limitations. Add a Windows runner job with Rust/Cargo, pnpm, frontend, browser, architecture, and Git matrix gates. Keep tests offline and use inert hostile fixtures only. M1 approval is blocked—not merely documented as limited—if filter disabling, path containment, SHA-256 exact OIDs, no-force conditional refs, worktrees, or LFS/submodule evidence is unavailable.

- [ ] **Step 3 — Run the full M1 gate**

```powershell
pnpm install --frozen-lockfile
node scripts/verify-design-contracts.mjs
node --test tests/contracts/*.test.mjs
node scripts/verify-m1-evidence.mjs
node scripts/check-architecture.mjs
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace --all-targets
pnpm --dir apps/desktop test --run
pnpm --dir apps/desktop test:browser
pnpm --dir apps/desktop build
cargo build -p local-agent-terminal-desktop
git diff --check
git diff --exit-code 321734f -- docs/multi-agent-terminal-design
```

Expected: every command exits 0, the M1 evidence manifest hashes the outputs, and the design directory has no diff.

- [ ] **Step 4 — Commit**

```powershell
git add artifacts/verification/m1 scripts tests .github/workflows/ci.yml
git diff --cached --check
git commit -m "test: verify repository recovery on Windows"
```

## Task 10: Independent M1 review and handoff

**Files:**

- Update local-only (ignored scratch): `.superpowers/sdd/2026-07-23-m1-workspace-recovery/progress.md`
- Modify: `artifacts/verification/m1/review.md`
- Create: `docs/superpowers/plans/2026-07-23-m2-policy-tools.md` only after M1 is approved

**Interfaces:**
- Consumes/produces: Consumes the complete M1 diff, evidence manifest, design-contract results, and the M1 exit criteria. Produces an independent spec/code-quality decision and, only on approval, the next plan.

- [ ] **Step 1 — Build the review package**

Compare the baseline-to-HEAD diff with this plan, the immutable design package, all M1 evidence, and the current workspace. Review specifically for original-checkout mutation, stale-token side effects, unsafe Git execution, replay of unknown intents, FK bypasses, raw DTO capabilities, accessibility regressions, and hidden M2 scope.

- [ ] **Step 2 — Resolve findings**

Critical or important findings require a focused fix worker, fresh covering tests, regenerated evidence, and a new review. Do not waive a finding by editing the design docs or weakening a test. Stop after five fix rounds and report a genuine blocker if the same external condition repeats three times.

- [ ] **Step 3 — Approve only with fresh evidence**

The review is PASS only when all M1 exit criteria and full gate commands pass, the original checkout/index snapshot is unchanged, all Windows/Git classifications are explicit, and the design diff is empty. Then update the ledger and prepare M2’s policy/tool-broker plan; do not start M2 implementation in this task.

- [ ] **Step 4 — Commit**

```powershell
git add artifacts/verification/m1 docs/superpowers/plans/2026-07-23-m2-policy-tools.md
git diff --cached --check
git commit -m "docs: approve M1 and plan policy tools"
```

## Definition of Done

- Repository onboarding returns typed health, stable identity, default branch, base commit, and original checkout status without content mutation.
- A task’s branch/worktree is isolated from the original checkout; worktree intent is durable and exact-match recovery is deterministic.
- One executor lease exists per task; tokens increase monotonically and stale claims cause no write.
- An authoritative out-of-band mutation enters `WorkspaceDirty`, increments both versions, revokes the lease, preserves evidence, and blocks writes.
- Restart fences stale leases, adopts only exact worktrees, preserves conflicts, and never silently replays an unknown/non-repeatable operation.
- The dashboard/timeline/recovery UI is keyboard accessible, honest about loading/indeterminate states, uses core-authorized actions, and passes real-browser axe including contrast.
- All M1 Rust/frontend/browser/architecture/Windows matrix checks pass; no design document changed; evidence is reproducible.
