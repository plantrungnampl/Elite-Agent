# M4 Task 4 Authority and Artifact Hardening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close the four blocking M4 Task 4 review findings by using live plan-approval authority, hardened content-addressed artifact reads, and immutable artifact identity metadata.

**Architecture:** The application layer defines a live authority port and a root-aware artifact-reader port. The SQLite adapter combines live authority with durable task and approval state inside every compare-and-terminalize path, while storage-files implements the physical reader with the existing capability-rooted content-addressed store and bootstrap injects it at the agent-runtime composition root. Migration V6 freezes artifact identity fields but preserves the two journal-owned lifecycle fields.

**Tech Stack:** Rust 2021, rusqlite 0.32, SHA-256 domain digests, `local-agent-terminal-storage-files`, SQLite strict tables and triggers.

## Global Constraints

- Implement directly in `D:\multiagent`; do not create or use a Git worktree.
- `docs/multi-agent-terminal-design/**` is normative and must not be modified.
- Preserve exact migration checksums for V1 through V5.
- A store without a live plan-approval authority source must fail closed and write no terminal event or approval state.
- Repository identity and historical context packages are not live authority sources.
- SQLite artifact reads must cross `ArtifactRootReader`; the storage-files implementation must use the existing `ArtifactStore::read` contract.
- Artifact journal transitions may continue changing only `availability` and `verification_state`.
- Apply test-driven development: observe each focused regression fail before implementing its minimal fix.
- Mark a checkbox only after its command or stated verification has succeeded.
- The corrective tasks modify interdependent files in the already-dirty parent Task 4 implementation; record verified checkpoints after Tasks 1-3 and create one buildable parent Task 4 source commit only after fresh review and full gates.

---

### Task 1: Bind plan approval to live repository and policy authority

**Files:**

- Modify: `crates/application/src/plan_approval.rs`
- Modify: `crates/application/src/lib.rs`
- Modify: `crates/storage-sqlite/src/lib.rs`
- Modify: `crates/storage-sqlite/src/plan_approval_store.rs`
- Modify: `crates/storage-sqlite/tests/plan_approval_store.rs`

**Interfaces:**

- Produces: `PlanApprovalCurrentAuthority { repository_fingerprint: Sha256Digest, policy_snapshot_digest: Sha256Digest }`.
- Produces: `PlanApprovalCurrentAuthoritySource::current_authority(&TaskId) -> Result<PlanApprovalCurrentAuthority, PortError>`.
- Produces: `SqliteStore::with_plan_approval_authority_source(Arc<dyn PlanApprovalCurrentAuthoritySource>) -> SqliteStore`.
- Consumes: the stored `PlanApprovalBindingInput` and durable workflow state already loaded by `PlanApprovalStore`.

- [x] **Step 1: Write live-authority RED tests**

Add a thread-safe test provider whose values survive store reopen:

```rust
#[derive(Clone)]
struct MutableAuthority {
    current: Arc<Mutex<PlanApprovalCurrentAuthority>>,
}

impl PlanApprovalCurrentAuthoritySource for MutableAuthority {
    fn current_authority(
        &self,
        _task_id: &TaskId,
    ) -> Result<PlanApprovalCurrentAuthority, PortError> {
        Ok(self.current.lock().unwrap().clone())
    }
}
```

Change `TestDatabase::store()` to reopen SQLite and attach the same provider. Add focused tests with these assertions:

```rust
#[test]
fn live_repository_change_rejects_resolution_across_reopen_without_mutation() {
    let database = TestDatabase::new();
    database.set_repository_fingerprint(digest(b"repository changed"));
    let error = ResolvePlanApproval::new(&database.store(), &WithinWindow)
        .execute(resolve_input(&database, PlanApprovalAction::Approve))
        .unwrap_err();
    assert_eq!(error.safe_classification(), SafeErrorClassification::Conflict);
    assert_pending_without_terminal_event(&database);
}

#[test]
fn live_policy_change_rejects_resolution_across_reopen_without_mutation() {
    let database = TestDatabase::new();
    database.set_policy_snapshot_digest(digest(b"policy changed"));
    let error = ResolvePlanApproval::new(&database.store(), &WithinWindow)
        .execute(resolve_input(&database, PlanApprovalAction::Approve))
        .unwrap_err();
    assert_eq!(error.safe_classification(), SafeErrorClassification::Conflict);
    assert_pending_without_terminal_event(&database);
}

#[test]
fn missing_live_authority_fails_closed_without_mutation() {
    let database = TestDatabase::new();
    let store = SqliteStore::open(&database.path).unwrap();
    let error = store.current_state(&TaskId::new("task-1").unwrap()).unwrap_err();
    assert_eq!(error.safe_classification(), SafeErrorClassification::Unavailable);
    assert_pending_without_terminal_event(&database);
}
```

Retain the existing task-version, manifest-drift, expiry, and reopen cases. Add a concurrent approve/reject SQLite regression that starts both resolvers together and proves exactly one success, one failure, one terminal event, and one task-sequence advance.

- [x] **Step 2: Run the focused RED tests**

Run:

```powershell
cargo test -p local-agent-terminal-storage-sqlite --test plan_approval_store live_repository_change_rejects_resolution_across_reopen_without_mutation -- --exact
cargo test -p local-agent-terminal-storage-sqlite --test plan_approval_store live_policy_change_rejects_resolution_across_reopen_without_mutation -- --exact
cargo test -p local-agent-terminal-storage-sqlite --test plan_approval_store missing_live_authority_fails_closed_without_mutation -- --exact
```

Expected: FAIL because `PlanApprovalCurrentAuthoritySource` and configured-store behavior do not exist yet.

- [x] **Step 3: Add the application port and explicit store configuration**

Add and export the validated live value and source:

```rust
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlanApprovalCurrentAuthority {
    pub repository_fingerprint: Sha256Digest,
    pub policy_snapshot_digest: Sha256Digest,
}

pub trait PlanApprovalCurrentAuthoritySource: Send + Sync {
    fn current_authority(
        &self,
        task_id: &TaskId,
    ) -> Result<PlanApprovalCurrentAuthority, PortError>;
}
```

Store the source as `Option<Arc<dyn PlanApprovalCurrentAuthoritySource>>` on `SqliteStore`, preserve it through `Clone`, and add:

```rust
#[must_use]
pub fn with_plan_approval_authority_source(
    mut self,
    source: Arc<dyn PlanApprovalCurrentAuthoritySource>,
) -> Self {
    self.plan_approval_authority_source = Some(source);
    self
}
```

Implement `Debug` manually so the trait object is not required to implement `Debug`; expose only whether the source is configured, never its internals.

- [x] **Step 4: Replace historical inference in every approval comparison**

Remove `normalize_repository_fingerprint`, the `projects.repository_identity` projection, and the newest-`context_packages` policy query from `current_state_for_binding`.

Before opening each `current_state`, resolve, invalidate, or expire SQLite transaction, load:

```rust
let live_authority = self
    .plan_approval_authority_source()
    .ok_or_else(unavailable)?
    .current_authority(task_id)?;
```

Pass `&PlanApprovalCurrentAuthority` into `current_state_for_binding` and assign both live digests to the cloned binding. In terminal CAS methods, obtain the task ID from the validated expected binding, observe live authority before opening the immediate transaction, and compare that exact observation inside `compare_expected`. Any missing, malformed, or mismatched observation must return without appending an event or changing `approvals.status`.

- [x] **Step 5: Run Task 1 GREEN tests and record the verified checkpoint**

Run:

```powershell
cargo fmt --all
cargo test -p local-agent-terminal-storage-sqlite --test plan_approval_store
cargo test -p local-agent-terminal-application plan_approval
```

Expected: PASS, including reopen, repo drift, policy drift, missing provider, task/manifest drift, expiry, and one-winner CAS.

Do not create a partial commit: `crates/storage-sqlite/src/lib.rs` already registers the
uncommitted parent Task 4 modules, so a Task 1-only commit would not build from a clean checkout.

---

### Task 2: Route SQLite artifact reads through the hardened capability store

**Files:**

- Modify: `crates/application/src/ports.rs`
- Modify: `crates/application/src/lib.rs`
- Modify: `crates/storage-sqlite/Cargo.toml`
- Modify: `crates/storage-sqlite/src/lib.rs`
- Modify: `crates/storage-sqlite/src/agent_store.rs`
- Modify: `crates/storage-sqlite/src/context_store.rs`
- Modify: `crates/storage-sqlite/tests/agent_store.rs`
- Modify: `crates/storage-sqlite/tests/context_store.rs`
- Modify: `crates/storage-files/src/content_address.rs`
- Modify: `crates/storage-files/src/lib.rs`
- Modify: `crates/storage-files/tests/crash_matrix.rs`
- Modify: `crates/bootstrap/src/agent_runtime.rs`
- Modify: `crates/bootstrap/tests/agent_runtime_e2e.rs`

**Interfaces:**

- Produces: `ArtifactRootReader::read_from_root(&Path, &ArtifactRef) -> Result<ArtifactContent, PortError>` in application.
- Produces: `ContentAddressedArtifactReader`, which opens the supplied root and delegates to `ArtifactStore::read`.
- Produces: `SqliteStore::with_artifact_reader(Arc<dyn ArtifactRootReader>)` without a storage-sqlite to storage-files dependency.
- Produces: `validate_available_artifact_kind(connection, reader, artifact_id, task_id, expected_kind, expected_hash, expected_size)` for adapter-owned semantic checks.
- Produces: context-package manifest validation with exact artifact kind `manifest`.

- [x] **Step 1: Write adapter-boundary RED tests**

Add regressions proving the SQLite adapter cannot bypass the injected reader:

```rust
#[test]
fn available_artifact_with_non_hash_derived_storage_key_is_rejected() {
    let database = TestDatabase::new();
    database.rewrite_artifact_storage_key_for_legacy_fixture(
        "artifact-context-1",
        "objects/00/not-the-content-hash",
    );
    assert_integrity_failure(database.reopen_context_package());
}

#[test]
fn context_package_rejects_a_non_manifest_manifest_artifact() {
    let fixture = ContextFixture::new();
    fixture.change_artifact_kind("artifact-agent-manifest-1", "content");
    let error = fixture.persist_package().unwrap_err();
    assert_eq!(error.safe_classification(), SafeErrorClassification::IntegrityFailure);
}
```

The key-rewrite test must use a legacy/pre-V6 fixture or perform the rewrite before installing the V6 immutability trigger; Task 3 will separately prove post-V6 metadata updates are blocked.

- [x] **Step 2: Run the focused RED tests**

Run:

```powershell
cargo test -p local-agent-terminal-storage-sqlite --test agent_store available_artifact_with_non_hash_derived_storage_key_is_rejected -- --exact
cargo test -p local-agent-terminal-storage-sqlite --test context_store context_package_rejects_a_non_manifest_manifest_artifact -- --exact
```

Expected: at least one test FAILS because `load_available_artifact` still calls `fs::read` and package persistence does not require manifest kind.

- [x] **Step 3: Delegate physical access through the inward reader port**

Define the root-aware port in application and inject it into `SqliteStore`:

```rust
pub trait ArtifactRootReader: Send + Sync {
    fn read_from_root(
        &self,
        root: &Path,
        reference: &ArtifactRef,
    ) -> Result<ArtifactContent, PortError>;
}
```

Implement the port in storage-files by opening `ContentAddressedArtifactStore` for the per-project root and calling `ArtifactStore::read`. Keep the existing SQLite checks for task owner, availability, artifact kind, expected hash, and expected size before physical access. Return only the verified same-handle bytes. Configure the reader in bootstrap's agent-runtime composition and keep a missing reader fail-closed.

- [x] **Step 4: Require manifest kind at context-package persistence**

Add a kind-aware helper that forwards to `load_available_artifact` with `Some(expected_kind)`. Call it for `descriptor.agent_manifest_artifact_id()` with `"manifest"`; leave content/source artifact callers on their existing semantic kind rules.

- [x] **Step 5: Run Task 2 GREEN and hardened-reader regressions**

Run:

```powershell
cargo fmt --all
cargo test -p local-agent-terminal-storage-sqlite --test agent_store --test context_store --test plan_approval_store
cargo test -p local-agent-terminal-storage-files
cargo test -p local-agent-terminal-bootstrap --test agent_runtime_e2e loopback_sse_persists_a_terminal_run_and_reconstructs_its_bound_inputs_after_reopen -- --exact
```

Expected: PASS. The storage-files suite is the verification source for traversal, non-hash key, symlink/junction or reparse escape, special-file rejection, bounded oversize rejection, and post-open growth/replacement on the same handle. The bootstrap e2e proves production composition supplies the reader and reopens a terminal run.

Record the passing commands in the plan; defer the interdependent source commit to Task 4.

---

### Task 3: Freeze persisted artifact identity in migration V6

**Files:**

- Modify: `crates/storage-sqlite/src/migrations.rs`
- Modify: `crates/storage-sqlite/tests/schema_health.rs`
- Modify: `crates/storage-sqlite/tests/context_store.rs`

**Interfaces:**

- Produces: SQLite trigger `artifact_identity_immutable` in V6.
- Preserves: updates that change only `availability` and/or `verification_state`.
- Preserves: exact deployed checksums for migration versions 1 through 5.

- [x] **Step 1: Write migration RED tests**

Extend the exact V5-to-V6 test to require `artifact_identity_immutable`. Add a behavioral regression:

```rust
#[test]
fn v6_freezes_artifact_identity_but_allows_journal_state_updates() {
    let database = seeded_v6_database();
    let connection = database.connection();
    for sql in [
        "UPDATE artifacts SET content_hash = 'sha256:0000000000000000000000000000000000000000000000000000000000000000' WHERE id = 'artifact-1'",
        "UPDATE artifacts SET storage_key = 'objects/00/substitute' WHERE id = 'artifact-1'",
        "UPDATE artifacts SET size_bytes = size_bytes + 1 WHERE id = 'artifact-1'",
        "UPDATE artifacts SET artifact_type = 'substitute' WHERE id = 'artifact-1'",
    ] {
        assert!(connection.execute(sql, []).is_err(), "identity update passed: {sql}");
    }
    connection.execute(
        "UPDATE artifacts SET availability = 'missing', verification_state = 'unverified' WHERE id = 'artifact-1'",
        [],
    ).unwrap();
}
```

Also reopen a V5 fixture after upgrade and prove the trigger exists without changing the recorded V5 checksum.

- [x] **Step 2: Run migration RED tests**

Run:

```powershell
cargo test -p local-agent-terminal-storage-sqlite --test schema_health v6_freezes_artifact_identity_but_allows_journal_state_updates -- --exact
cargo test -p local-agent-terminal-storage-sqlite --test schema_health exact_deployed_v5_database_adds_context_hardening_without_rewriting_v5 -- --exact
```

Expected: FAIL because V6 does not yet install `artifact_identity_immutable`.

- [x] **Step 3: Add the minimal V6 update trigger**

Append this shape to `V6_CONTEXT_HARDENING_SQL`, listing every identity/location field and intentionally omitting only `availability` and `verification_state`:

```sql
CREATE TRIGGER artifact_identity_immutable
BEFORE UPDATE ON artifacts
FOR EACH ROW
WHEN NEW.id IS NOT OLD.id
    OR NEW.task_id IS NOT OLD.task_id
    OR NEW.project_id IS NOT OLD.project_id
    OR NEW.artifact_type IS NOT OLD.artifact_type
    OR NEW.logical_path IS NOT OLD.logical_path
    OR NEW.content_hash IS NOT OLD.content_hash
    OR NEW.storage_key IS NOT OLD.storage_key
    OR NEW.size_bytes IS NOT OLD.size_bytes
    OR NEW.mime_type IS NOT OLD.mime_type
    OR NEW.created_by_type IS NOT OLD.created_by_type
    OR NEW.created_by_id IS NOT OLD.created_by_id
    OR NEW.created_at IS NOT OLD.created_at
    OR NEW.supersedes IS NOT OLD.supersedes
BEGIN
    SELECT RAISE(ABORT, 'artifact identity is immutable');
END;
```

Do not modify V1-V5 SQL constants or their checksum functions.

- [x] **Step 4: Run Task 3 GREEN tests**

Run:

```powershell
cargo fmt --all
cargo test -p local-agent-terminal-storage-sqlite --test schema_health
cargo test -p local-agent-terminal-storage-sqlite --test context_store
```

Expected: PASS, including V1/V3/V4/V5 upgrade preservation and permitted artifact journal state updates.

Record the passing commands in the plan; defer the interdependent source commit to Task 4.

---

### Task 4: Re-review, verify the full Task 4 implementation, and close the parent plan

**Files:**

- Modify: `docs/superpowers/plans/2026-08-10-m4-task4-authority-hardening.md`
- Modify: `docs/superpowers/plans/2026-07-23-m4-context-deliberation.md`
- Modify: `.superpowers/sdd/progress.md`
- Commit: all remaining M4 Task 4 application/domain/storage files already listed by the parent plan.

**Interfaces:**

- Consumes: all three corrective tasks plus the existing context/deliberation/approval persistence implementation.
- Produces: a reviewer-approved, fully gated M4 Task 4 commit and synchronized plan/progress checkboxes.

- [x] **Step 1: Request a fresh read-only code review**

Provide the reviewer with the approved spec, this plan, `git diff cabce5f..HEAD`, and remaining working-tree diff. Require explicit review of:

```text
1. live repo and policy authority on current_state plus every terminal CAS;
2. no fallback to repository_identity or historical context_packages;
3. content-addressed no-follow/same-handle reads at the SQLite boundary;
4. immutable artifact metadata with journal lifecycle compatibility;
5. no regression in canonical deliberation/event binding or plan approval schema.
```

Expected: no Critical or Important finding remains. If a finding is valid, add a RED regression, fix it, rerun the focused suite, and request review again before continuing.

- [x] **Step 2: Run the complete Rust and architecture gates**

Run fresh, without relying on earlier output:

```powershell
cargo fmt --all -- --check
cargo check --workspace --all-targets
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
cargo test --workspace --doc
cargo test -p local-agent-terminal-storage-files
node scripts/check-architecture.mjs
git diff --check
```

Expected: every command exits 0.

- [x] **Step 3: Synchronize plan and progress checkboxes**

Only after review and all gates pass:

1. mark every completed checkbox in this corrective plan;
2. mark Task 4 Steps 1-4 in `docs/superpowers/plans/2026-07-23-m4-context-deliberation.md` complete;
3. update `.superpowers/sdd/progress.md` with Task 4 completion evidence and the exact gate commands;
4. confirm `docs/multi-agent-terminal-design/**` remains unchanged.

- [x] **Step 4: Commit the remaining parent Task 4 implementation**

Run:

```powershell
git status --short
git diff -- docs/multi-agent-terminal-design
git add crates/application crates/bootstrap crates/domain crates/storage-files crates/storage-sqlite docs/superpowers/plans .superpowers/sdd/progress.md
git diff --cached --check
git commit -m "feat: persist m4 context deliberation state"
git status --short
```

Expected: the normative design diff is empty, commit succeeds, and the working tree is clean.
