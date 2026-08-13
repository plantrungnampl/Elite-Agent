# v4.3 S0 Authority Refactor Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace historical production authority with the v4.3 S0 SQLite, workflow, protocol, run-configuration, and assurance contracts while preserving valid existing behavior.

**Architecture:** The pure domain reducer consumes workflow v3; application use cases prepare canonical command/config/receipt artifacts and own output ports; SQLite v7 enforces atomic authority; protocol/runtime/provider adapters use MACP v2. Existing deliberation data becomes append-only evidence or projection and can no longer mutate workflow authority directly.

**Tech Stack:** Rust 1.97.1, SQLite/rusqlite, serde/serde_json, typify, Tauri, React/TypeScript, Vitest, pnpm 11.7.0, Node 24.16.0.

## Global Constraints

- Work in the main checkout `D:\multiagent`; do not create a Git worktree.
- Treat `docs/multi-agent-terminal-design` as user-owned, read-only normative authority; never stage or edit it.
- Preserve unrelated user changes and stage only the exact files named by each commit step.
- A production source file may contain at most 2,000 lines.
- `bootstrap` remains the only composition root; `domain`, `application`, and `orchestration` do not construct concrete adapters.
- Production code uses SQLite v7, workflow transitions v3, MACP v2, RunConfiguration v1, and AssuranceDegradationReceipt v1 only.
- Support the exact normative SQLite v6-to-v7 migration; reject the unrelated current application schema v9.
- Use red-green-refactor for every behavior change.
- Use Conventional Commit prefixes `feat:`, `fix:`, or `test:`.
- Mark a checkbox `[x]` only after its exact command or evidence is green.
- Keep historical M4 Task 10 Steps 4-6 unchecked until their own acceptance conditions pass.

---

### Task 1: Stabilize and preserve the inherited M4 implementation baseline

**Files:**
- Modify: `crates/storage-sqlite/tests/deliberation_store.rs`
- Verify/stage existing implementation changes under: `apps/desktop/src/api/deliberation.ts`, `apps/desktop/src/api/deliberation.test.ts`, `apps/desktop/src/features/deliberation/PlanApprovalPanel.tsx`, `apps/desktop/src/features/deliberation/PlanApprovalPanel.test.tsx`, `crates/application/src/deliberation/commands.rs`, `crates/application/src/deliberation/ports.rs`, `crates/application/src/deliberation/records.rs`, `crates/application/src/deliberation/snapshots.rs`, `crates/application/src/deliberation_recovery.rs`, `crates/application/src/dto.rs`, `crates/application/src/plan_approval.rs`, `crates/bootstrap/src/agent_runtime.rs`, `crates/bootstrap/src/agent_runtime_support.rs`, `crates/bootstrap/src/agent_specialist_context.rs`, `crates/bootstrap/src/deliberation_runtime.rs`, `crates/bootstrap/src/lib.rs`, `crates/domain/src/deliberation.rs`, `crates/orchestration/src/coordinator.rs`, `crates/orchestration/src/lib.rs`, `crates/storage-sqlite/src/context_store.rs`, `crates/storage-sqlite/src/deliberation_store.rs`
- Verify/stage existing tests under: `crates/application/tests/deliberation_ports/objections_and_approval.rs`, `crates/application/tests/deliberation_ports/persistence.rs`, `crates/application/tests/deliberation_recovery/claim_authority.rs`, `crates/application/tests/deliberation_recovery/replay.rs`, `crates/application/tests/plan_approval_digest.rs`, `crates/bootstrap/tests/agent_runtime_e2e.rs`, `crates/bootstrap/tests/deliberation_e2e.rs`, `crates/domain/tests/deliberation_contract.rs`, `crates/orchestration/tests/request_contract.rs`, `crates/orchestration/tests/workflow_contract.rs`, `crates/orchestration/tests/zero_mutation.rs`, `crates/storage-sqlite/tests/plan_approval_store.rs`

**Interfaces:**
- Consumes: the current `DecisionPackage::new` contract and the quorum-position preservation check already present in the dirty implementation.
- Produces: a green, committed pre-S0 code baseline without staging `docs/multi-agent-terminal-design/**`.

- [x] **Step 1: Reproduce the inherited red regression**

Run:

```powershell
cargo test -p local-agent-terminal-storage-sqlite --test deliberation_store private_receipts_replay_without_messages_then_quorum_publishes_atomically_and_reopens -- --exact --nocapture
```

Expected: FAIL at synthesis preparation with `SafeErrorClassification::Conflict` because the helper decision omits the second quorum position.

- [x] **Step 2: Correct the fixture without weakening production invariants**

Update `decision` so proposal 2 is represented once as a rejected approach and once as dissent:

```rust
fn decision(plan_artifact_id: &str, evidence: MaterialClaim) -> DecisionPackage {
    let rejected = RejectedApproach::new(
        DecisionApproach::new(
            "rejected-approach",
            ArtifactId::new("proposal-2").unwrap(),
            Vec::new(),
        )
        .unwrap(),
        "The verified evidence supports proposal 1.",
    )
    .unwrap();
    let dissent = Dissent::new(
        "dissent-agent-2",
        "agent-2",
        ArtifactId::new("proposal-2").unwrap(),
        "Agent 2 retains proposal 2 as the rejected alternative.",
    )
    .unwrap();
    DecisionPackage::new(
        DecisionApproach::new(
            "selected-approach",
            ArtifactId::new("proposal-1").unwrap(),
            vec![evidence.claim_id().to_owned()],
        )
        .unwrap(),
        vec![rejected],
        vec![evidence],
        vec![dissent],
        ArtifactId::new(plan_artifact_id).unwrap(),
    )
    .unwrap()
}
```

Import `RejectedApproach` and `Dissent` from `local_agent_terminal_domain` in the test module.

- [x] **Step 3: Verify the focused regression is green**

Run the Step 1 command again.

Expected: PASS with one test executed.

- [x] **Step 4: Verify the inherited code baseline**

Run:

```powershell
cargo fmt --all -- --check
cargo check --workspace --all-targets
cargo test -p local-agent-terminal-application -p local-agent-terminal-domain -p local-agent-terminal-orchestration -p local-agent-terminal-bootstrap -p local-agent-terminal-storage-sqlite --tests
pnpm --dir apps/desktop test --run
```

Expected: every command exits 0. If another test is red, stop and use `superpowers:systematic-debugging` before changing code.

- [x] **Step 5: Commit only the inherited non-design implementation baseline**

Stage the exact code and test paths listed in this task, verify the staged name list contains no `docs/multi-agent-terminal-design` path, then commit:

```powershell
git diff --cached --name-only
git diff --cached --check
git commit -m "fix: preserve m4 authority invariants"
```

Expected: one commit containing the existing M4 fixes plus the corrected fixture; the user-owned design package remains unstaged.

---

### Task 2: Replace the pure workflow model and reducer with workflow v3

**Files:**
- Modify: `crates/domain/src/lib.rs`
- Modify: `crates/domain/src/workflow.rs`
- Create: `crates/domain/src/workflow/types.rs`
- Create: `crates/domain/src/workflow/specification.rs`
- Create: `crates/domain/src/workflow/reducer.rs`
- Modify: `crates/domain/tests/workflow_contract.rs`
- Modify: `crates/application/src/plan_approval.rs`
- Modify: `crates/application/src/deliberation/commands.rs`
- Modify: `crates/application/src/deliberation/ports.rs`
- Modify: `crates/application/src/deliberation/records.rs`
- Modify: `crates/orchestration/src/recovery.rs`
- Modify: `crates/storage-sqlite/src/workspace_store.rs`
- Modify: `crates/application/tests/plan_approval_digest.rs`
- Modify: `crates/application/tests/deliberation_ports/objections_and_approval.rs`
- Modify: `crates/application/tests/deliberation_ports/persistence.rs`
- Modify: `crates/bootstrap/tests/deliberation_e2e.rs`
- Modify: `crates/orchestration/tests/workflow_contract.rs`
- Modify: `crates/storage-sqlite/tests/deliberation_store.rs`
- Modify: `crates/storage-sqlite/tests/workspace_recovery.rs`

**Interfaces:**
- Consumes: `schemas/workflow-transitions.v3.json` and the existing `Sha256Digest`, `TaskId`, `Sequence`, `WorkspaceVersion`, and `FencingToken` value objects.
- Produces:

```rust
pub struct WorkflowStateSnapshot {
    pub phase: Phase,
    pub condition: Condition,
    pub operation: OperationState,
    pub workflow_profile: WorkflowProfile,
    pub outcome_mode: TaskOutcomeMode,
    pub stream_version: u64,
    pub profile_revision: u64,
    pub workspace_version: u64,
    pub fencing_epoch: u64,
    pub last_transition_event_id: Option<String>,
    pub last_profile_revision_id: Option<String>,
}

pub struct TransitionRequest {
    pub rule_id: String,
    pub event: WorkflowEvent,
    pub guard_evidence_kinds: BTreeSet<String>,
    pub effect_kinds: BTreeSet<String>,
}

pub fn reduce(
    state: &WorkflowState,
    request: &TransitionRequest,
) -> Result<Transition, WorkflowError>;

pub fn reduce_condition(
    state: &WorkflowState,
    event: &WorkflowEvent,
    guards: &GuardEvaluations,
) -> Result<Transition, WorkflowError>;
```

`reduce` resolves only the 33 command-authoritative `WF-P`, `WF-W`, and `WF-G` rules accepted by `WorkflowTransitionCommand v1` and normalized by SQLite v7. `reduce_condition` resolves the six ID-less condition rules against their declared guard while preserving phase, profile, outcome, and operation. Do not invent `WF-C` IDs.

- [x] **Step 1: Write RED tests for the v3 state and route surface**

Add tests that assert:

```rust
#[test]
fn v3_state_retains_profile_outcome_and_authority_versions() {
    let state = WorkflowState::rehydrate(WorkflowStateSnapshot {
        phase: Phase::ContextBuild,
        condition: Condition::Active,
        operation: OperationState::None,
        workflow_profile: WorkflowProfile::Quick,
        outcome_mode: TaskOutcomeMode::WorkspaceChange,
        stream_version: 7,
        profile_revision: 2,
        workspace_version: 3,
        fencing_epoch: 4,
        last_transition_event_id: Some("transition-7".to_owned()),
        last_profile_revision_id: Some("profile-revision-2".to_owned()),
    })
    .unwrap();
    assert_eq!(state.workflow_profile(), WorkflowProfile::Quick);
    assert_eq!(state.outcome_mode(), TaskOutcomeMode::WorkspaceChange);
    assert_eq!(state.stream_version(), 7);
    assert_eq!(state.profile_revision(), 2);
}
```

Add RED cases for `WF-P003`, `WF-P008`, `WF-P009`, `WF-P015`, all terminal paths, missing required effects, wrong-profile severe-objection routing, and all six condition transitions through `reduce_condition`.

- [x] **Step 2: Run the workflow contract and confirm the v1 implementation is red**

Run:

```powershell
cargo test -p local-agent-terminal-domain --test workflow_contract -- --nocapture
```

Expected: compile/test failure because v3 types and signatures do not exist and production still loads `workflow-transitions.v1.json`.

- [x] **Step 3: Split workflow responsibilities and implement the v3 parser**

Move value/state declarations to `types.rs`, JSON parsing and structural validation to `specification.rs`, and reduction to `reducer.rs`. Keep `workflow.rs` as the public module facade.

The production constant must be exactly:

```rust
const WORKFLOW_JSON: &str = include_str!(
    "../../../../docs/multi-agent-terminal-design/schemas/workflow-transitions.v3.json"
);
```

Parse all four profiles, three outcome modes, 30 phase rules, two global rules, six condition rules, profile escalations, and the workspace-dirty rule. Reject unknown fields, duplicate selectors, missing IDs on ID-bearing `WF-P/W/G` rules, and ambiguous profile routes. Condition rules are structurally validated by `(from, event, to, guard)` and intentionally have no rule ID or effect set.

- [x] **Step 4: Implement the pure v3 reducer**

The command reducer must resolve the caller-supplied `rule_id` among the 33 `WF-P/W/G` rules, verify source/profile/outcome/event, require the exact declared guard/effect kind sets, apply only the declared axis/effects, increment stream version once, and preserve profile revision unless the separate escalation reducer is used. The condition reducer must select exactly one of the six ID-less rules by current condition and event, require its declared guard evaluation, change only condition plus stream version, and never produce a transition-command rule ID.

Use an exact-set check:

```rust
fn exact_set(actual: &BTreeSet<String>, required: &[String]) -> bool {
    actual.len() == required.len() && required.iter().all(|item| actual.contains(item))
}
```

Do not infer approval evidence from a Boolean guard.

- [x] **Step 5: Update domain callers and run focused tests**

Update the four production `reduce` callers identified by the code graph (`plan_approval.rs`, deliberation `commands.rs`, deliberation `ports.rs`, and `workspace_store.rs`) to construct `TransitionRequest` with exact rule/evidence/effect kinds. Make only the compile-preserving support edits required by the expanded v3 phase/state shape: map the new post-approval phases to the existing recovery `PostApproval` category and clone non-`Copy` workflow state/event IDs only at existing owned DTO/record/test boundaries. Adapt only the named regression tests. Run:

```powershell
cargo fmt --all -- --check
cargo test -p local-agent-terminal-domain --all-features
cargo test -p local-agent-terminal-application --tests
```

Expected: all commands exit 0.

- [x] **Step 6: Commit the v3 pure workflow slice**

```powershell
git add crates/domain/src/lib.rs crates/domain/src/workflow.rs crates/domain/src/workflow/types.rs crates/domain/src/workflow/specification.rs crates/domain/src/workflow/reducer.rs crates/domain/tests/workflow_contract.rs crates/application/src/plan_approval.rs crates/application/src/deliberation/commands.rs crates/application/src/deliberation/ports.rs crates/application/src/deliberation/records.rs crates/orchestration/src/recovery.rs crates/storage-sqlite/src/workspace_store.rs crates/application/tests/plan_approval_digest.rs crates/application/tests/deliberation_ports/objections_and_approval.rs crates/application/tests/deliberation_ports/persistence.rs crates/bootstrap/tests/deliberation_e2e.rs crates/orchestration/tests/workflow_contract.rs crates/storage-sqlite/tests/deliberation_store.rs crates/storage-sqlite/tests/workspace_recovery.rs
git diff --cached --check
git commit -m "feat: adopt workflow v3 domain authority"
```

Before committing, confirm no production line references `workflow-transitions.v1.json`.

---

### Task 3: Install and verify SQLite v7 plus the exact v6-to-v7 migration

**Execution dependency:** Run this task as the persistence prerequisite for the open Task 2 review finding. Task 2 remains incomplete until this task is reviewed clean and both production workflow readers are subsequently changed to rehydrate the full v7 authority row.

**Files:**
- Replace: `crates/storage-sqlite/src/migrations.rs`
- Create: `crates/storage-sqlite/src/app_projection_schema.sql`
- Modify: `crates/storage-sqlite/src/lib.rs`
- Create: `crates/storage-sqlite/tests/schema_v7.rs`
- Modify: `crates/storage-sqlite/tests/schema_health.rs`

**Interfaces:**
- Consumes: `schemas/sqlite-v6.sql`, `schemas/sqlite-v7.sql`, and `schemas/migrate-v6-to-v7.sql`.
- Produces:

```rust
pub(crate) fn validate_or_migrate(connection: &mut Connection) -> Result<(), OpenError>;
pub(crate) fn verify_required_schema(connection: &Connection) -> Result<(), OpenError>;
```

Empty databases install v7; exact normative v6 databases migrate to v7; v7 databases reopen; application schema v9 and all other surfaces fail closed.

The completed schema must expose `task_workflow_authority.workflow_profile`, `outcome_mode`, `stream_version`, `profile_revision`, `last_transition_event_id`, and `last_profile_revision_id` as the only trusted persistence source for Task 2's production rehydration fix. Do not populate clean-v7 task authority with compatibility defaults: initial profile/outcome selection remains an explicit trusted application command in later tasks. Exact normative v6 rows migrate according to `migrate-v6-to-v7.sql`; unrelated application v9 data is reset/rejected per the approved policy.

- [x] **Step 1: Write RED clean/migration/rejection tests**

Create tests that install the normative scripts into temporary SQLite files and assert:

```rust
#[test]
fn clean_v7_and_migrated_v7_have_identical_authority_objects() {
    let clean = install_clean_v7();
    let migrated = install_v6_then_open_store();
    assert_eq!(authority_objects(&clean), authority_objects(&migrated));
    assert_eq!(authority_objects(&clean).len(), 481);
}

#[test]
fn application_version_marker_is_not_accepted_as_normative_v7() {
    let database = NamedTempFile::new().unwrap();
    let connection = Connection::open(database.path()).unwrap();
    connection
        .execute_batch(
            "CREATE TABLE schema_migrations(version INTEGER NOT NULL);\n\
             INSERT INTO schema_migrations(version) VALUES (9);",
        )
        .unwrap();
    drop(connection);

    let error = SqliteStore::open(database.path()).unwrap_err();
    assert!(matches!(error, OpenError::UnsupportedSchema { .. }));
}
```

Add a separate non-empty unknown-object rejection test, plus tests for runtime `foreign_keys=ON`, WAL, synchronous mode, busy timeout, and `integrity_check=ok`. Together the marker and unknown-object cases prove that the old application version number or an arbitrary non-empty schema cannot be mistaken for normative v7.

- [x] **Step 2: Run schema tests and confirm RED**

```powershell
cargo test -p local-agent-terminal-storage-sqlite --test schema_v7 -- --nocapture
```

Expected: FAIL because the store still installs historical v1 plus internal migrations.

- [x] **Step 3: Implement exact schema recognition and installation**

Embed the three normative scripts with `include_str!`. Build expected v6/v7 object maps by applying the embedded scripts to in-memory SQLite connections; compare `(type, name, table, SQL)` for every non-internal object. Do not identify a schema from an untrusted version integer alone.

`validate_or_migrate` must follow:

```rust
match recognize_schema(connection)? {
    SchemaKind::Empty => install_v7(connection)?,
    SchemaKind::NormativeV6 => migrate_v6_to_v7(connection)?,
    SchemaKind::NormativeV7 => {}
    SchemaKind::Unsupported => return Err(OpenError::UnsupportedSchema {
        found: 0,
        supported: 7,
    }),
}
install_or_verify_app_projections(connection)?;
verify_required_schema(connection)
```

- [x] **Step 4: Extract only non-authoritative application projections**

Move the current app-only tables and immutable/projection guards required by existing adapters into `app_projection_schema.sql`. Exclude every table/trigger already supplied by v7. Add a trigger test proving no app projection can update `task_workflow_authority`.

- [x] **Step 5: Run storage schema and existing adapter tests**

```powershell
cargo fmt --all -- --check
cargo test -p local-agent-terminal-storage-sqlite --test schema_v7
cargo test -p local-agent-terminal-storage-sqlite --test schema_health
cargo test -p local-agent-terminal-storage-sqlite --tests
```

Expected: all commands exit 0; clean and migrated v7 expose the same 481 authority objects before app projections.

- [x] **Step 6: Commit the v7 storage foundation**

```powershell
git add crates/storage-sqlite/src/migrations.rs crates/storage-sqlite/src/app_projection_schema.sql crates/storage-sqlite/src/lib.rs crates/storage-sqlite/tests/schema_v7.rs crates/storage-sqlite/tests/schema_health.rs
git diff --cached --check
git commit -m "feat: install sqlite v7 authority"
```

---

### Task 4: Add the application transition use case and atomic SQLite authority store

**Files:**
- Create: `crates/application/src/workflow_authority.rs`
- Modify: `crates/application/src/lib.rs`
- Create: `crates/application/tests/workflow_authority.rs`
- Create: `crates/storage-sqlite/src/workflow_authority_store.rs`
- Modify: `crates/storage-sqlite/src/lib.rs`
- Create: `crates/storage-sqlite/tests/workflow_authority_store.rs`

**Interfaces:**
- Consumes: Task 2 `WorkflowState`/`TransitionRequest`, application canonical JSON/digest helpers, artifact identities, and SQLite v7 workflow tables.
- Produces:

```rust
pub struct WorkflowGuardEvidence {
    pub kind: String,
    pub reference: String,
    pub subject_digest: Option<Sha256Digest>,
    pub evidence_digest: Sha256Digest,
    pub artifact_id: Option<ArtifactId>,
    pub approval_receipt_id: Option<String>,
}

pub struct WorkflowEffectBinding {
    pub kind: String,
    pub reference: String,
    pub effect_digest: Sha256Digest,
    pub artifact_id: Option<ArtifactId>,
}

pub struct TransitionWorkflowInput {
    pub command_id: String,
    pub transition_event_id: String,
    pub task_id: TaskId,
    pub rule_id: String,
    pub expected_stream_version: u64,
    pub event: WorkflowEvent,
    pub guards: Vec<WorkflowGuardEvidence>,
    pub effects: Vec<WorkflowEffectBinding>,
    pub core_actor_digest: Sha256Digest,
    pub reducer_version: String,
    pub prepared_at: Timestamp,
}

pub trait WorkflowAuthorityStore: Send + Sync {
    fn load_workflow(&self, task_id: &TaskId) -> Result<WorkflowState, PortError>;
    fn persist_transition(
        &self,
        command: &PreparedWorkflowTransition,
    ) -> Result<WorkflowState, PortError>;
}
```

- [x] **Step 1: Write RED application tests for canonical command preparation**

Test `WF-P015` with exact approval evidence and both required effects. Assert omission, substitution, duplicate kind, wrong stream version, and non-canonical ordering return `Conflict` before storage dispatch. Assert `commandDigest` is SHA-256 of RFC 8785 bytes with the digest field omitted, then inserted into the final artifact.

- [x] **Step 2: Write RED SQLite tests for structural bypasses**

Add direct SQL negative cases for raw projection update, prepared event without a required guard, prepared event without a required effect, wrong profile route, accepted-event replay, and cross-task evidence. Add one positive transaction for `WF-P015`.

Run:

```powershell
cargo test -p local-agent-terminal-application --test workflow_authority -- --nocapture
cargo test -p local-agent-terminal-storage-sqlite --test workflow_authority_store -- --nocapture
```

Expected: RED because the use case/store do not exist.

- [x] **Step 3: Implement canonical preparation in application**

Sort guard/effect records by `(kind, reference)`, reject duplicates, ask the domain reducer for the exact transition, construct the schema-v1 command object, canonicalize without `commandDigest`, compute SHA-256, insert the digest, and canonicalize the final artifact.

- [x] **Step 4: Implement the one-transaction SQLite store**

Use `TransactionBehavior::Immediate`. Insert the command artifact before the transition transaction through the existing artifact operation protocol. Inside the transaction perform prepared event, exact guard rows, exact effect rows, accepted status, and projection CAS in that order. Convert trigger/CAS failures to `SafeErrorClassification::Conflict` without retrying.

- [x] **Step 5: Verify application and SQLite authority tests**

```powershell
cargo fmt --all -- --check
cargo test -p local-agent-terminal-application --test workflow_authority
cargo test -p local-agent-terminal-storage-sqlite --test workflow_authority_store
```

Expected: all tests pass, including every negative bypass.

- [x] **Step 6: Commit the workflow authority vertical slice**

```powershell
git add crates/application/src/workflow_authority.rs crates/application/src/lib.rs crates/application/tests/workflow_authority.rs crates/storage-sqlite/src/workflow_authority_store.rs crates/storage-sqlite/src/lib.rs crates/storage-sqlite/tests/workflow_authority_store.rs
git diff --cached --check
git commit -m "feat: persist accepted workflow commands"
```

---

### Task 5: Replace the internal run-config artifact with RunConfiguration v1

**Files:**
- Create: `crates/domain/src/run_configuration.rs`
- Modify: `crates/domain/src/lib.rs`
- Modify: `crates/domain/src/agent.rs`
- Create: `crates/application/src/run_configuration.rs`
- Modify: `crates/application/src/lib.rs`
- Create: `crates/application/tests/run_configuration.rs`
- Modify: `crates/storage-sqlite/src/agent_store.rs`
- Create: `crates/storage-sqlite/src/run_configuration_store.rs`
- Modify: `crates/storage-sqlite/src/lib.rs`
- Modify: `crates/storage-sqlite/tests/agent_store.rs`
- Create: `crates/storage-sqlite/tests/run_configuration_store.rs`

**Interfaces:**
- Consumes: `run-configuration.v1.schema.json`, canonical JSON/SHA-256 helpers, preallocated `RunId`, and v7 `run_configuration_bindings`.
- Produces:

```rust
pub struct UnsignedRunConfiguration {
    pub run_configuration_id: String,
    pub task_id: TaskId,
    pub provider_connection_ref: String,
    pub adapter: AdapterConfiguration,
    pub model_endpoint: ModelEndpointConfiguration,
    pub agent_profile: AgentProfileConfiguration,
    pub generation_parameters: GenerationParameters,
    pub capability_snapshot: CapabilitySnapshot,
    pub data_policy_snapshot: DataPolicySnapshot,
    pub budget_reservation: RunBudgetReservation,
    pub fallback_policy: FallbackPolicy,
    pub independence: IndependenceConfiguration,
    pub created_at: Timestamp,
}

impl RunConfiguration {
    pub fn issue(unsigned: UnsignedRunConfiguration) -> Result<Self, RunConfigurationError>;
    pub fn canonical_bytes(&self) -> &[u8];
    pub fn config_digest(&self) -> &Sha256Digest;
}

pub trait RunConfigurationStore: Send + Sync {
    fn bind_run_configuration(
        &self,
        run_id: &RunId,
        artifact: &ArtifactRef,
        configuration: &RunConfiguration,
    ) -> Result<(), PortError>;
}
```

- [ ] **Step 1: Write RED shape, digest, and credential-exclusion tests**

Validate all required top-level sections, bounded values, exact enums, fallback rules, and independence dimensions. Deserialize a hostile object with `apiKey`, `token`, or `credential` keys and assert rejection. Assert changing any section changes `configDigest`.

- [ ] **Step 2: Write RED v7 binding tests**

Test exact run/task/artifact scope, immutable binding, one configuration per run, provider/model/fingerprint round-trip, cross-task rejection, unavailable artifact rejection, and changed digest conflict.

- [ ] **Step 3: Implement immutable domain configuration values**

Define closed serde shapes matching the normative camelCase schema. `RunConfiguration::issue` canonicalizes the unsigned object without `configDigest`, hashes it, inserts `credentialsExcluded=true` and the digest, then stores final canonical bytes. Do not retain a generic `serde_json::Value` field that could hide credential material.

- [ ] **Step 4: Implement the application builder and SQLite binding**

The application builder resolves the provider/model/capability/policy/budget facts before issuance. Publish bytes through the artifact store, then insert one v7 `run_configuration_bindings` row tied to the preallocated run.

Remove `agent-run-config.v1` and `agent-run-config.v2` from production parsing; historical test fixtures may remain under tests only.

- [ ] **Step 5: Verify run configuration contracts**

```powershell
cargo fmt --all -- --check
cargo test -p local-agent-terminal-domain run_configuration
cargo test -p local-agent-terminal-application --test run_configuration
cargo test -p local-agent-terminal-storage-sqlite --test run_configuration_store
cargo test -p local-agent-terminal-storage-sqlite --test agent_store
```

Expected: all commands exit 0.

- [ ] **Step 6: Commit RunConfiguration v1**

```powershell
git add crates/domain/src/run_configuration.rs crates/domain/src/lib.rs crates/domain/src/agent.rs crates/application/src/run_configuration.rs crates/application/src/lib.rs crates/application/tests/run_configuration.rs crates/storage-sqlite/src/agent_store.rs crates/storage-sqlite/src/run_configuration_store.rs crates/storage-sqlite/src/lib.rs crates/storage-sqlite/tests/agent_store.rs crates/storage-sqlite/tests/run_configuration_store.rs
git diff --cached --check
git commit -m "feat: bind normative run configurations"
```

---

### Task 6: Add monotonic profile escalation and actor-proved assurance degradation

**Files:**
- Create: `crates/domain/src/assurance.rs`
- Modify: `crates/domain/src/lib.rs`
- Create: `crates/application/src/assurance.rs`
- Modify: `crates/application/src/lib.rs`
- Create: `crates/application/tests/assurance.rs`
- Create: `crates/storage-sqlite/src/assurance_store.rs`
- Modify: `crates/storage-sqlite/src/lib.rs`
- Create: `crates/storage-sqlite/tests/assurance_store.rs`

**Interfaces:**
- Consumes: Task 2 workflow profile/version types, Task 5 independence groups, actor binding IDs, artifacts, and v7 profile/assurance tables.
- Produces:

```rust
pub enum AssuranceDecision {
    Pause,
    Cancel,
    ContinueDegraded,
}

pub struct ProfileEscalationCommand {
    pub revision_id: String,
    pub task_id: TaskId,
    pub expected_stream_version: u64,
    pub from_profile: WorkflowProfile,
    pub to_profile: WorkflowProfile,
    pub reason_artifact_id: ArtifactId,
    pub policy_digest: Sha256Digest,
    pub actor_binding_id: Option<String>,
    pub created_at: Timestamp,
}

pub trait AssuranceStore: Send + Sync {
    fn persist_profile_escalation(
        &self,
        command: &ProfileEscalationCommand,
    ) -> Result<WorkflowState, PortError>;
    fn persist_degradation(
        &self,
        receipt: &AssuranceDegradationReceipt,
        artifact: &ArtifactRef,
    ) -> Result<(), PortError>;
}
```

- [ ] **Step 1: Write RED escalation and degradation tests**

Cover Quick to Standard, Quick to HighAssurance, Standard to HighAssurance, all downgrades, ReadOnlyResearch changes, version replay, insufficient groups, same executor/reviewer, and all three decisions. Assert `ContinueDegraded` without both actor binding and acceptance artifact is invalid.

- [ ] **Step 2: Run focused tests and confirm RED**

```powershell
cargo test -p local-agent-terminal-application --test assurance -- --nocapture
cargo test -p local-agent-terminal-storage-sqlite --test assurance_store -- --nocapture
```

- [ ] **Step 3: Implement pure policy and canonical receipts**

Count distinct `independence.group_id` values and compare exact executor/reviewer run IDs. Preserve the requested profile on degraded continuation. Compute `receiptDigest` from canonical bytes with the digest omitted, then serialize the final closed schema.

- [ ] **Step 4: Implement v7 profile/degradation persistence**

Profile escalation uses one immediate transaction, inserts the immutable revision, increments stream/profile revisions once, updates `last_profile_revision_id`, and leaves phase unchanged. Degradation rows are append-only and task/run-set scoped.

- [ ] **Step 5: Verify and commit assurance authority**

```powershell
cargo fmt --all -- --check
cargo test -p local-agent-terminal-domain assurance
cargo test -p local-agent-terminal-application --test assurance
cargo test -p local-agent-terminal-storage-sqlite --test assurance_store
git add crates/domain/src/assurance.rs crates/domain/src/lib.rs crates/application/src/assurance.rs crates/application/src/lib.rs crates/application/tests/assurance.rs crates/storage-sqlite/src/assurance_store.rs crates/storage-sqlite/src/lib.rs crates/storage-sqlite/tests/assurance_store.rs
git diff --cached --check
git commit -m "feat: enforce workflow assurance policy"
```

Expected: tests pass and the commit contains no design-package files.

---

### Task 7: Upgrade the complete protocol/runtime/provider surface to MACP v2

**Files:**
- Modify: `crates/agent-protocol/src/generated.rs`
- Modify: `crates/agent-protocol/src/codec.rs`
- Modify: `crates/agent-protocol/src/session.rs`
- Modify: `crates/agent-protocol/src/peer.rs`
- Modify: `crates/agent-protocol/src/error.rs`
- Modify: `crates/agent-protocol/tests/codec.rs`
- Modify: `crates/agent-protocol/tests/conformance.rs`
- Modify: `crates/agent-protocol/tests/schema_types.rs`
- Modify: `crates/agent-protocol/tests/session_contract.rs`
- Modify: `crates/agent-runtime/src/runtime/protocol.rs`
- Modify: `crates/agent-runtime/src/runtime/connection.rs`
- Modify: `crates/agent-runtime/src/runtime/lifecycle.rs`
- Modify: `crates/agent-runtime/src/runtime/tests.rs`
- Modify: `crates/agent-runtime/tests/fake_conformance.rs`
- Modify: `crates/agent-runtime/tests/runtime_contract.rs`
- Modify: `crates/agent-runtime/tests/runtime_contract/acceptance_and_recovery.rs`
- Modify: `crates/agent-runtime/tests/runtime_contract/lifecycle.rs`
- Modify: `crates/provider-openai/src/adapter.rs`
- Modify: `crates/provider-openai/tests/conformance.rs`
- Modify: `crates/provider-openai/tests/request_contract.rs`
- Modify: `crates/provider-openai/tests/streaming_contract.rs`
- Modify: `crates/provider-anthropic/src/adapter.rs`
- Modify: `crates/provider-anthropic/src/request.rs`
- Modify: `crates/provider-anthropic/tests/conformance.rs`
- Modify: `crates/provider-anthropic/tests/request_contract.rs`
- Modify: `crates/provider-anthropic/tests/streaming_contract.rs`

**Interfaces:**
- Consumes: `agent-protocol.v2.schema.json`, 13 canonical `schemas/examples-v2` frames, existing durable protocol request/stream ports, and Task 5 run bindings.
- Produces: generated v2 frame types, protocol version `2.0`, v2 method ownership and correlation, and runtime/provider descriptors that pass the shared v2 conformance suite.

- [ ] **Step 1: Point generated types and contract tests at v2 and confirm RED**

Change `generated.rs` to:

```rust
typify::import_types!(
    schema = "../../docs/multi-agent-terminal-design/schemas/agent-protocol.v2.schema.json"
);
```

Update schema test paths to v2 and add a test loading all canonical examples-v2 frames. Run:

```powershell
cargo test -p local-agent-terminal-agent-protocol --all-features -- --nocapture
```

Expected: compile/test failures expose every v1 field/method assumption.

- [ ] **Step 2: Implement the closed v2 codec and method-specific response validation**

Bundle v2, remove supplemental v1 schema patches, validate each request/response definition directly, use `capabilities` rather than historical `features`, enforce core/agent request-ID prefixes, and keep notifications response-free.

- [ ] **Step 3: Update session and conformance state**

Negotiate version `2.0`, persist `(connection_id, request_id, method, digest)`, validate response shape from the durable pending method, enforce exactly one terminal request, contiguous stream sequence, replay digest identity, pending limits, and high/low watermark behavior.

- [ ] **Step 4: Update runtime frames and provider descriptors**

Generate `initialize`, `initialized`, `agent.run.start`, cancel, complete, context, tool, specialist, heartbeat, shutdown, and exit frames from v2 shapes. `agent.run.start` includes only `runId`, `taskId`, `contextPackageRef`, `idempotencyKey`, and optional `role`; do not duplicate RunConfiguration fields into the wire frame.

Every provider descriptor advertises `2.0` and the v2 capability names.

- [ ] **Step 5: Run protocol, runtime, and provider contracts**

```powershell
cargo fmt --all -- --check
cargo test -p local-agent-terminal-agent-protocol --all-features
cargo test -p local-agent-terminal-agent-runtime --all-features
cargo test -p local-agent-terminal-provider-openai --all-features
cargo test -p local-agent-terminal-provider-anthropic --all-features
```

Expected: all commands exit 0; all 13 canonical v2 frames validate and no production source references `agent-protocol.v1.schema.json` or protocol `1.0`.

- [ ] **Step 6: Commit MACP v2**

```powershell
git add crates/agent-protocol/src/generated.rs crates/agent-protocol/src/codec.rs crates/agent-protocol/src/session.rs crates/agent-protocol/src/peer.rs crates/agent-protocol/src/error.rs crates/agent-protocol/tests/codec.rs crates/agent-protocol/tests/conformance.rs crates/agent-protocol/tests/schema_types.rs crates/agent-protocol/tests/session_contract.rs crates/agent-runtime/src/runtime/protocol.rs crates/agent-runtime/src/runtime/connection.rs crates/agent-runtime/src/runtime/lifecycle.rs crates/agent-runtime/src/runtime/tests.rs crates/agent-runtime/tests/fake_conformance.rs crates/agent-runtime/tests/runtime_contract.rs crates/agent-runtime/tests/runtime_contract/acceptance_and_recovery.rs crates/agent-runtime/tests/runtime_contract/lifecycle.rs crates/provider-openai/src/adapter.rs crates/provider-openai/tests/conformance.rs crates/provider-openai/tests/request_contract.rs crates/provider-openai/tests/streaming_contract.rs crates/provider-anthropic/src/adapter.rs crates/provider-anthropic/src/request.rs crates/provider-anthropic/tests/conformance.rs crates/provider-anthropic/tests/request_contract.rs crates/provider-anthropic/tests/streaming_contract.rs
git diff --cached --check
git commit -m "feat: upgrade agent control protocol to v2"
```

---

### Task 8: Rewire deliberation, orchestration, runtime, bootstrap, and DTOs to the new authority

**Files:**
- Modify: `crates/application/src/deliberation/commands.rs`
- Modify: `crates/application/src/deliberation/ports.rs`
- Modify: `crates/application/src/deliberation/records.rs`
- Modify: `crates/application/src/deliberation/snapshots.rs`
- Modify: `crates/application/src/orchestration.rs`
- Modify: `crates/application/src/dto.rs`
- Modify: `crates/orchestration/src/coordinator.rs`
- Modify: `crates/orchestration/src/recovery.rs`
- Modify: `crates/orchestration/src/selection.rs`
- Modify: `crates/storage-sqlite/src/deliberation_store.rs`
- Modify: `crates/storage-sqlite/src/agent_store.rs`
- Modify: `crates/bootstrap/src/agent_runtime.rs`
- Create: `crates/bootstrap/src/agent_run_configuration.rs`
- Modify: `crates/bootstrap/src/deliberation_runtime.rs`
- Modify: `crates/bootstrap/src/startup.rs`
- Modify: `crates/bootstrap/src/lib.rs`
- Modify: `apps/desktop/src/api/deliberation.ts`
- Modify: `apps/desktop/src/api/deliberation.test.ts`
- Modify: `crates/application/tests/deliberation_ports/objections_and_approval.rs`
- Modify: `crates/application/tests/deliberation_ports/persistence.rs`
- Modify: `crates/application/tests/deliberation_recovery/claim_authority.rs`
- Modify: `crates/application/tests/deliberation_recovery/replay.rs`
- Modify: `crates/application/tests/plan_approval_digest.rs`
- Modify: `crates/orchestration/tests/recovery.rs`
- Modify: `crates/orchestration/tests/request_contract.rs`
- Modify: `crates/orchestration/tests/workflow_contract.rs`
- Modify: `crates/bootstrap/tests/agent_runtime_e2e.rs`
- Modify: `crates/bootstrap/tests/deliberation_e2e.rs`
- Modify: `crates/bootstrap/tests/deliberation_e2e/assertions.rs`
- Modify: `crates/bootstrap/tests/deliberation_e2e/support.rs`
- Modify: `crates/bootstrap/tests/deliberation_recovery.rs`
- Modify: `crates/bootstrap/tests/startup.rs`
- Modify: `crates/storage-sqlite/tests/deliberation_store.rs`

**Interfaces:**
- Consumes: Tasks 4-7 application ports/stores and v3/v2 domain/protocol surfaces.
- Produces: one production workflow authority path, config-before-dispatch, visible profile/outcome/degraded state DTOs, and no legacy v1 authority path.

- [ ] **Step 1: Write RED integration tests for one authority path**

Add tests proving:

```rust
#[test]
fn deliberation_phase_change_uses_accepted_transition_authority() {
    let result = run_parallel_analysis_to_cross_review();
    assert_eq!(result.transition_events, 1);
    assert_eq!(result.accepted_events, 1);
    assert_eq!(result.raw_projection_updates, 0);
    assert_eq!(result.workflow_state.phase(), Phase::CrossReview);
}

#[test]
fn dispatch_requires_context_and_normative_run_configuration_binding() {
    let result = attempt_dispatch_without_run_configuration();
    assert_eq!(result.unwrap_err().safe_classification(), SafeErrorClassification::Conflict);
}
```

Add restart tests that reload profile/outcome/stream/profile revision, config binding, and degraded receipt exactly.

- [ ] **Step 2: Run integration tests and confirm RED**

```powershell
cargo test -p local-agent-terminal-orchestration --tests -- --nocapture
cargo test -p local-agent-terminal-bootstrap --tests -- --nocapture
cargo test -p local-agent-terminal-storage-sqlite --test deliberation_store -- --nocapture
```

- [ ] **Step 3: Remove direct deliberation projection construction**

Delete the `ProjectionChange::TaskState` branch from deliberation `build_append`. Persist immutable deliberation evidence first, then call `TransitionWorkflow` with the exact v3 rule, guard evidence, and effects. Reads join `task_workflow_authority` and `tasks` to reconstruct the full state.

- [ ] **Step 4: Make run configuration mandatory before dispatch**

Move config construction out of `agent_runtime.rs` into `agent_run_configuration.rs`. Bootstrap injects the builder/store. The runtime rejects a run lacking the exact context/config bindings before provider invocation. Keep `agent_runtime.rs` below 2,000 lines.

- [ ] **Step 5: Rewire profile selection, escalation, and degraded state**

The trusted coordinator selects initial profile/outcome, invokes the separate escalation use case on risk change, evaluates HighAssurance groups from Task 5 fingerprints, and exposes degradation receipts through application DTOs. React remains presentation-only and cannot construct authority payloads.

- [ ] **Step 6: Remove production legacy paths and adapt regressions**

Remove production `workflow-transitions.v1`, `agent-protocol.v1`, protocol `1.0`, and `agent-run-config.v1/v2` references. Keep historical schema files only under the normative package and historical fixture tests. Update M1-M4 tests to seed v7 authority through public application/storage ports rather than direct task phase updates.

- [ ] **Step 7: Run the integrated S0 regression set**

```powershell
cargo fmt --all -- --check
cargo check --workspace --all-targets
cargo test -p local-agent-terminal-application --all-features
cargo test -p local-agent-terminal-orchestration --all-features
cargo test -p local-agent-terminal-storage-sqlite --all-features
cargo test -p local-agent-terminal-bootstrap --all-features
pnpm --dir apps/desktop test --run
pnpm --dir apps/desktop build
```

Expected: all commands exit 0.

- [ ] **Step 8: Commit the production cutover**

```powershell
git add crates/application/src/deliberation/commands.rs crates/application/src/deliberation/ports.rs crates/application/src/deliberation/records.rs crates/application/src/deliberation/snapshots.rs crates/application/src/orchestration.rs crates/application/src/dto.rs crates/application/tests/deliberation_ports/objections_and_approval.rs crates/application/tests/deliberation_ports/persistence.rs crates/application/tests/deliberation_recovery/claim_authority.rs crates/application/tests/deliberation_recovery/replay.rs crates/application/tests/plan_approval_digest.rs crates/orchestration/src/coordinator.rs crates/orchestration/src/recovery.rs crates/orchestration/src/selection.rs crates/orchestration/tests/recovery.rs crates/orchestration/tests/request_contract.rs crates/orchestration/tests/workflow_contract.rs crates/storage-sqlite/src/deliberation_store.rs crates/storage-sqlite/src/agent_store.rs crates/storage-sqlite/tests/deliberation_store.rs crates/bootstrap/src/agent_runtime.rs crates/bootstrap/src/agent_run_configuration.rs crates/bootstrap/src/deliberation_runtime.rs crates/bootstrap/src/startup.rs crates/bootstrap/src/lib.rs crates/bootstrap/tests/agent_runtime_e2e.rs crates/bootstrap/tests/deliberation_e2e.rs crates/bootstrap/tests/deliberation_e2e/assertions.rs crates/bootstrap/tests/deliberation_e2e/support.rs crates/bootstrap/tests/deliberation_recovery.rs crates/bootstrap/tests/startup.rs apps/desktop/src/api/deliberation.ts apps/desktop/src/api/deliberation.test.ts
git diff --cached --check
git commit -m "feat: cut over runtime to v4.3 authority"
```

Review the staged list and unstage any user-owned design-package file before committing.

---

### Task 9: Run the complete S0 gate, audit legacy removal, and close only proven checkboxes

**Files:**
- Modify: `docs/superpowers/plans/2026-08-12-v43-s0-authority-refactor.md`
- Do not modify: `docs/multi-agent-terminal-design/**`

**Interfaces:**
- Consumes: the complete Tasks 1-8 implementation.
- Produces: reproducible verification results, a zero-current-authority-v1 audit, accurate plan checkboxes, and a reviewable branch state.

- [ ] **Step 1: Prove formatting, compilation, lints, tests, and docs**

Run from `D:\multiagent`:

```powershell
cargo fmt --all -- --check
cargo check --workspace --all-targets
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
cargo test --workspace --doc
pnpm --dir apps/desktop test --run
pnpm --dir apps/desktop build
```

Expected: every command exits 0. Do not mark this step complete from a subset.

- [ ] **Step 2: Run architecture and design-package gates separately**

Run the repository architecture contracts, then validate a temporary copy of the design package so the normative source remains untouched:

```powershell
node --test tests/contracts/*.test.mjs
$designAuditRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("multiagent-v43-design-audit-" + [guid]::NewGuid().ToString("N"))
Copy-Item -LiteralPath docs\multi-agent-terminal-design -Destination $designAuditRoot -Recurse
python -m venv "$designAuditRoot\.venv"
& "$designAuditRoot\.venv\Scripts\python.exe" -m pip install jsonschema
Push-Location $designAuditRoot
try {
    & ".\.venv\Scripts\python.exe" validation\validate_package.py
} finally {
    Pop-Location
}
```

Expected: architecture contracts pass and the isolated design package reports `182/182`. The design validator is recorded separately from runtime checks.

- [ ] **Step 3: Audit current-authority references and file sizes**

Run:

```powershell
rg -n "workflow-transitions\.v1|agent-protocol\.v1|protocol_version:\s*\"1\.0\"|agent-run-config\.v[12]" crates apps
```

Expected: no production match; historical test-only matches must be explicitly allowlisted and explained.

Run:

```powershell
$sourceFiles = Get-ChildItem -Path crates,apps,scripts,tests -Recurse -File | Where-Object {
    $_.Extension -in '.rs','.ts','.tsx','.js','.mjs','.sql' -and
    $_.FullName -notmatch '\\(target|node_modules|dist|build|generated)\\'
}
$oversizedSources = $sourceFiles | ForEach-Object {
    [pscustomobject]@{ Path = $_.FullName; Lines = (Get-Content -LiteralPath $_.FullName).Count }
} | Where-Object Lines -gt 2000 | Sort-Object Lines -Descending
$oversizedSources | Format-Table -AutoSize
if ($oversizedSources) { throw "Production source file exceeds 2,000 lines." }
```

Expected: no source file exceeds 2,000 lines.

- [ ] **Step 4: Request a fresh code review against the approved S0 spec**

Use `superpowers:requesting-code-review` with the range from `640c4a9` to the current implementation HEAD. The review prompt must check:

- one workflow authority path;
- exact v7/v6 migration behavior;
- v2 protocol method/correlation behavior;
- config credential exclusion and immutability;
- escalation/degradation actor proof;
- recovery and cross-task scope;
- no file over 2,000 lines.

Expected: zero unresolved critical/high findings. Fix findings through TDD and rerun affected/full gates.

- [ ] **Step 5: Mark only exact green plan steps**

Update this file with `[x]` only for steps whose stated commands/evidence passed. Leave any failed, deferred, or unrun step unchecked and list it in the final handoff. Do not change historical M4 Task 10 Steps 4-6.

- [ ] **Step 6: Commit plan evidence and verify scoped status**

```powershell
git add docs/superpowers/plans/2026-08-12-v43-s0-authority-refactor.md
git diff --cached --check
git commit -m "test: record v4.3 s0 verification"
git status --short --branch
```

Expected: implementation/plan commits are present; any remaining dirty paths are the user's pre-existing normative design update and are reported explicitly rather than staged.
