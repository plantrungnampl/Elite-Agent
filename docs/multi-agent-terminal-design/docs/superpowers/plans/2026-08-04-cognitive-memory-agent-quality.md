# Cognitive Memory and Agent Quality Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a verified cognitive lifecycle that improves agent memory and measurable task quality without weakening v3.2 authority, privacy, recovery, approval, or local-first guarantees.

**Architecture:** SQLite remains the single authority store and the Artifact Store retains exact bytes. Application-owned ports isolate memory authority, retrieval, context compilation, evaluation, and learning; retrieval/index adapters only return candidates. Every long-term memory record begins as `candidate`, every context manifest binds one preallocated run, and quality claims require equal-configuration benchmark evidence.

**Tech Stack:** Rust, Tauri, React, TypeScript, SQLite STRICT tables/FTS, JSON Schema Draft 2020-12, Python validation, the repository's locked Rust and JavaScript dependency versions.

## Global Constraints

- New Rust code lives under `src-tauri/src`; Rust integration tests live under `src-tauri/tests`.
- Frontend code lives under `src/features`; Vitest/Testing Library tests sit beside the feature or under `src/features/__tests__`.
- SQLite remains the only local authority writer; agents, retrieval adapters, and sidecars never receive a writable authority handle.
- Artifact bytes remain content-addressed outside SQLite.
- `schemas/sqlite-v3.sql`, `schemas/migrate-v2-to-v3.sql`, and the JSON Schemas are normative contracts; implementation structs must serialize to them exactly.
- `contentHash` in a context manifest hashes the separate effective-input artifact, not the manifest containing the field.
- One context package may be consumed by exactly one preallocated run; retries compile a new package.
- A stale memory record is never reactivated in place; reuse creates a new version and `supersedes` relation.
- Existing workflow, fencing, approval, policy, protocol, and crash-recovery suites must remain green after every task.
- Each task starts with a failing test, implements only the behavior needed for that task, runs focused and regression tests, and ends with one reviewable commit.

## Target workspace map

```text
src-tauri/
├── src/
│   ├── domain/cognition/          # pure types and transition rules
│   ├── application/cognition/     # use cases and orchestration
│   ├── application/benchmark/     # locked quality benchmark execution
│   ├── ports/                     # authority-independent interfaces
│   ├── adapters/sqlite_memory/    # SQLite authority implementation
│   ├── adapters/retrieval_embedded/
│   ├── adapters/retrieval_sidecar/
│   ├── adapters/evaluator_rules/
│   └── protocol/handlers/
└── tests/
    ├── domain/
    ├── cognition/
    ├── storage/
    ├── protocol/
    ├── workflow/
    ├── benchmark/
    └── migration/
src/features/
├── context-debugger/
├── memory-explorer/
├── learning-review/
└── quality-dashboard/
benchmarks/engineering-v1/
```

## Canonical Rust interfaces

Create these names once and reuse them unchanged in later tasks:

```rust
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum MemoryType {
    Episodic,
    Semantic,
    Procedural,
    Negative,
    Preference,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum MemoryStatus {
    Candidate,
    Verified,
    Approved,
    Active,
    Rejected,
    Stale,
    Superseded,
    Retracted,
}

pub struct MemoryTransitionCommand {
    pub memory_id: MemoryId,
    pub expected_status: MemoryStatus,
    pub new_status: MemoryStatus,
    pub changed_at: OffsetDateTime,
    pub activated_at: Option<OffsetDateTime>,
}

#[async_trait]
pub trait MemoryRepository: Send + Sync {
    async fn create_candidate(&self, input: NewMemoryRecord) -> Result<MemoryRecord, MemoryStoreError>;
    async fn link_evidence(&self, input: NewMemoryEvidence) -> Result<MemoryEvidence, MemoryStoreError>;
    async fn record_review(&self, input: NewPromotionReview) -> Result<PromotionReview, MemoryStoreError>;
    async fn relate(&self, input: NewMemoryRelation) -> Result<MemoryRelation, MemoryStoreError>;
    async fn transition(&self, command: MemoryTransitionCommand) -> Result<MemoryRecord, MemoryStoreError>;
    async fn active_for_scope(&self, query: ActiveMemoryQuery) -> Result<Vec<MemoryRecord>, MemoryStoreError>;
}

#[async_trait]
pub trait RetrievalEngine: Send + Sync {
    async fn index(&self, request: IndexRequest) -> Result<IndexReceipt, RetrievalError>;
    async fn retrieve(&self, request: RetrievalRequest) -> Result<RetrievalResult, RetrievalError>;
    async fn invalidate(&self, request: InvalidateRequest) -> Result<InvalidationReceipt, RetrievalError>;
    async fn health(&self) -> Result<RetrievalHealth, RetrievalError>;
}

#[async_trait]
pub trait ContextCompiler: Send + Sync {
    async fn compile(&self, request: ContextCompileRequest) -> Result<ContextPackageReceipt, ContextError>;
    async fn supplement(&self, request: ContextSupplementRequest) -> Result<ContextSupplementReceipt, ContextError>;
}

#[async_trait]
pub trait RunEvaluator: Send + Sync {
    async fn evaluate(&self, input: EvaluationInput) -> Result<RunEvaluation, EvaluationError>;
}

#[async_trait]
pub trait LearningEngine: Send + Sync {
    async fn extract(&self, input: LearningInput) -> Result<Vec<MemoryProposal>, LearningError>;
}
```

---

### Task 1: Cognitive domain types and lifecycle

**Files:**
- Create: `src-tauri/src/domain/cognition/mod.rs`
- Create: `src-tauri/src/domain/cognition/memory.rs`
- Create: `src-tauri/src/domain/cognition/working_memory.rs`
- Create: `src-tauri/src/domain/cognition/evaluation.rs`
- Create: `src-tauri/src/domain/cognition/invariants.rs`
- Test: `src-tauri/tests/domain/cognition_lifecycle.rs`

**Interfaces:**
- Produces: `MemoryType`, `MemoryStatus`, `MemoryRecord`, `MemoryTransitionCommand`, `WorkingMemoryEvent`, `RunEvaluation`, `validate_memory_transition`.
- No database, filesystem, network, model, or clock dependency is allowed in this task.

- [ ] **Step 1: Write the failing lifecycle tests**

```rust
#[test]
fn candidate_cannot_activate_directly() {
    let result = validate_memory_transition(
        MemoryType::Negative,
        MemoryStatus::Candidate,
        MemoryStatus::Active,
    );
    assert_eq!(result, Err(MemoryInvariantError::InvalidTransition));
}

#[test]
fn stale_memory_cannot_return_to_verified() {
    let result = validate_memory_transition(
        MemoryType::Semantic,
        MemoryStatus::Stale,
        MemoryStatus::Verified,
    );
    assert_eq!(result, Err(MemoryInvariantError::InvalidTransition));
}

#[test]
fn working_is_not_a_durable_memory_type() {
    let result = serde_json::from_str::<MemoryType>(r#""working""#);
    assert!(result.is_err());
}
```

- [ ] **Step 2: Run the test and verify the intended failure**

```bash
cargo test --manifest-path src-tauri/Cargo.toml --test cognition_lifecycle -- --nocapture
```

Expected: compilation fails because the cognition domain types and transition function do not exist.

- [ ] **Step 3: Implement the pure transition matrix and typed statements**

```rust
pub fn validate_memory_transition(
    memory_type: MemoryType,
    from: MemoryStatus,
    to: MemoryStatus,
) -> Result<(), MemoryInvariantError> {
    let allowed = matches!(
        (from, to),
        (MemoryStatus::Candidate, MemoryStatus::Verified | MemoryStatus::Rejected | MemoryStatus::Stale | MemoryStatus::Superseded | MemoryStatus::Retracted)
            | (MemoryStatus::Verified, MemoryStatus::Approved | MemoryStatus::Rejected | MemoryStatus::Stale | MemoryStatus::Superseded | MemoryStatus::Retracted)
            | (MemoryStatus::Approved, MemoryStatus::Active | MemoryStatus::Rejected | MemoryStatus::Stale | MemoryStatus::Superseded | MemoryStatus::Retracted)
            | (MemoryStatus::Active, MemoryStatus::Stale | MemoryStatus::Superseded | MemoryStatus::Retracted)
            | (MemoryStatus::Stale, MemoryStatus::Superseded | MemoryStatus::Retracted)
    );

    allowed.then_some(()).ok_or(MemoryInvariantError::InvalidTransition)
}
```

Define working-memory statement variants `Fact { evidence }`, `Inference { supporting_fact_ids, confidence }`, `Unknown`, `Hypothesis`, `NextAction`, and `RequiredCheck`; constructors reject facts without evidence and inferences without supporting facts.

- [ ] **Step 4: Run focused and existing domain tests**

```bash
cargo test --manifest-path src-tauri/Cargo.toml --test cognition_lifecycle
cargo test --manifest-path src-tauri/Cargo.toml domain::
```

Expected: all tests pass; no I/O dependency appears in the domain module.

- [ ] **Step 5: Commit**

```bash
git add src-tauri/src/domain/cognition src-tauri/tests/domain/cognition_lifecycle.rs
git commit -m "feat: add cognitive memory domain lifecycle"
```

### Task 2: SQLite v3 migration and authority adapter

**Files:**
- Create: `src-tauri/migrations/003_cognitive_memory.sql`
- Create: `src-tauri/src/ports/memory_repository.rs`
- Create: `src-tauri/src/adapters/sqlite_memory/mod.rs`
- Create: `src-tauri/src/adapters/sqlite_memory/repository.rs`
- Create: `src-tauri/src/adapters/sqlite_memory/row_mapping.rs`
- Test: `src-tauri/tests/storage/cognitive_memory_sqlite.rs`

**Interfaces:**
- Consumes: Task 1 domain types.
- Produces: `SqliteMemoryRepository` implementing the canonical `MemoryRepository` interface.
- The migration file must be byte-identical to `schemas/migrate-v2-to-v3.sql` or generated from the same reviewed source with an asserted SHA-256.

- [ ] **Step 1: Write failing storage tests**

```rust
#[tokio::test]
async fn active_requires_evidence_review_and_ordered_transitions() {
    let store = test_store().await;
    let memory = store.create_candidate(negative_memory_fixture()).await.unwrap();

    let direct = store.transition(MemoryTransitionCommand {
        memory_id: memory.id,
        expected_status: MemoryStatus::Candidate,
        new_status: MemoryStatus::Active,
        changed_at: ts(10),
        activated_at: Some(ts(10)),
    }).await;

    assert!(matches!(direct, Err(MemoryStoreError::InvariantViolation(_))));
}

#[tokio::test]
async fn stale_reuse_requires_a_new_version_and_relation() {
    let store = seeded_active_memory_store().await;
    store.transition(stale_command("m1", ts(40))).await.unwrap();
    assert!(store.transition(verify_command("m1", ts(50))).await.is_err());

    let replacement = store.create_candidate(version_two_fixture()).await.unwrap();
    assert_eq!(replacement.version, 2);
}

#[tokio::test]
async fn working_memory_cannot_enter_durable_memory_records() {
    let result = raw_test_connection().execute(
        "INSERT INTO memory_records(id,project_id,logical_key,memory_type,version,status,content_artifact_id,applicability_json,invalidation_conditions_json,confidence_millionths,sensitivity,created_at,status_changed_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
        params!["wm", "p1", "wm", "working", 1, "candidate", "a1", scoped_applicability(), invalidation_conditions(), 0, "internal", ts(1), ts(1)],
    );
    assert!(result.is_err());
}
```

- [ ] **Step 2: Run focused tests and verify failure**

```bash
cargo test --manifest-path src-tauri/Cargo.toml --test cognitive_memory_sqlite -- --nocapture
```

Expected: failure because the migration and repository do not exist.

- [ ] **Step 3: Implement transactional repository methods**

Use `BEGIN IMMEDIATE` for transitions that combine evidence/review/relation checks. Map SQLite constraint messages to stable `MemoryStoreError::InvariantViolation { code, detail }`; do not parse them into success paths.

```rust
pub async fn transition(&self, command: MemoryTransitionCommand) -> Result<MemoryRecord, MemoryStoreError> {
    validate_memory_transition(self.memory_type(command.memory_id).await?, command.expected_status, command.new_status)?;
    let mut tx = self.pool.begin().await?;
    let changed = sqlx::query(
        "UPDATE memory_records SET status=?, status_changed_at=?, activated_at=COALESCE(?, activated_at) \
         WHERE id=? AND status=?"
    )
    .bind(command.new_status.as_db())
    .bind(command.changed_at)
    .bind(command.activated_at)
    .bind(command.memory_id)
    .bind(command.expected_status.as_db())
    .execute(&mut *tx)
    .await?;
    if changed.rows_affected() != 1 {
        return Err(MemoryStoreError::ConcurrentTransition);
    }
    tx.commit().await?;
    self.get(command.memory_id).await
}
```

All reads for retrieval use `status='active'`, unexpired time, exact project scope, and current content/evidence hashes. The adapter also proves that activation timestamps can only be set atomically during `approved → active`, expired records cannot activate, and a partial unique index permits only one active version per `(project_id, logical_key)`.

- [ ] **Step 4: Run storage, migration, and package authority suites**

```bash
cargo test --manifest-path src-tauri/Cargo.toml --test cognitive_memory_sqlite
python validation/validate_v4_memory.py
python validation/validate_v3.py
python validation/validate_v32_hardening.py
```

Expected: Rust tests pass; Python results include `79/79 v4 cognitive checks passed`, `39/39`, and `68/68`. The storage suite must also prove that retained `memory_entries` rows are readable but cannot be inserted, updated, or deleted after v4 installation.

- [ ] **Step 5: Commit**

```bash
git add src-tauri/migrations src-tauri/src/ports/memory_repository.rs src-tauri/src/adapters/sqlite_memory src-tauri/tests/storage/cognitive_memory_sqlite.rs
git commit -m "feat: add sqlite cognitive memory authority"
```

### Task 3: RetrievalEngine port and deterministic embedded baseline

**Files:**
- Create: `src-tauri/src/ports/retrieval_engine.rs`
- Create: `src-tauri/src/application/cognition/retrieval_plan.rs`
- Create: `src-tauri/src/adapters/retrieval_embedded/mod.rs`
- Create: `src-tauri/src/adapters/retrieval_embedded/exact.rs`
- Create: `src-tauri/src/adapters/retrieval_embedded/fts.rs`
- Create: `src-tauri/src/adapters/retrieval_embedded/rank_fusion.rs`
- Test: `src-tauri/tests/cognition/retrieval_conformance.rs`

**Interfaces:**
- Produces: the canonical `RetrievalEngine`, `RetrievalRequest`, `RetrievalResult`, `RetrievalCandidate`, and `RetrievalPlan` matching `cognitive-memory.v1.schema.json`.
- Vector and graph branches are injected optional adapters; they never appear in application/domain interfaces.

- [ ] **Step 1: Write failing deterministic retrieval tests**

```rust
#[tokio::test]
async fn same_fixture_produces_same_order_and_trace_digest() {
    let engine = embedded_engine(fixed_index_fixture()).await;
    let request = retrieval_request("QRQC NUM ID warning close");
    let first = engine.retrieve(request.clone()).await.unwrap();
    let second = engine.retrieve(request).await.unwrap();
    assert_eq!(first.candidates, second.candidates);
    assert_eq!(first.trace_digest, second.trace_digest);
}

#[tokio::test]
async fn stale_or_cross_project_memory_is_never_returned() {
    let result = embedded_engine(mixed_scope_fixture()).await
        .retrieve(retrieval_request_for_project("p1"))
        .await
        .unwrap();
    assert!(result.candidates.iter().all(|c| {
        c.freshness == Freshness::Current
            && !matches!(c.source.source_id.as_str(), "p2-memory" | "stale-memory")
    }));
}
```

- [ ] **Step 2: Run the test and verify failure**

```bash
cargo test --manifest-path src-tauri/Cargo.toml --test retrieval_conformance -- --nocapture
```

Expected: missing port/adapter errors.

- [ ] **Step 3: Implement exact/FTS branches and weighted reciprocal-rank fusion**

```rust
pub fn reciprocal_rank_fusion(branches: &[RankedBranch], k: u32) -> Vec<FusedCandidate> {
    let mut scores = BTreeMap::<SourceIdentity, u64>::new();
    for branch in branches {
        for (zero_based_rank, item) in branch.items.iter().enumerate() {
            let denominator = k as u64 + zero_based_rank as u64 + 1;
            *scores.entry(item.source.clone()).or_default() += branch.weight_millionths as u64 / denominator;
        }
    }
    stable_sort_by_score_then_identity(scores)
}
```

Persist branch status and an exact content-addressed trace artifact. A terminal retrieval stores the matching artifact ID/digest atomically, freezes branch status, and rejects later trace mutation. If vector/graph is unavailable, return typed degraded status while exact/FTS continues; do not silently claim full hybrid retrieval.

- [ ] **Step 4: Run conformance twice and compare serialized results**

```bash
cargo test --manifest-path src-tauri/Cargo.toml --test retrieval_conformance
cargo test --manifest-path src-tauri/Cargo.toml --test retrieval_conformance
```

Expected: both runs pass with identical fixture snapshots and trace digests.

- [ ] **Step 5: Commit**

```bash
git add src-tauri/src/ports/retrieval_engine.rs src-tauri/src/application/cognition/retrieval_plan.rs src-tauri/src/adapters/retrieval_embedded src-tauri/tests/cognition/retrieval_conformance.rs
git commit -m "feat: add deterministic hybrid retrieval baseline"
```

### Task 4: Context Compiler and progressive supplements

**Files:**
- Create: `src-tauri/src/ports/context_compiler.rs`
- Create: `src-tauri/src/application/cognition/compile_context.rs`
- Create: `src-tauri/src/application/cognition/supplement_context.rs`
- Create: `src-tauri/src/application/cognition/canonical_context.rs`
- Test: `src-tauri/tests/cognition/context_compiler.rs`

**Interfaces:**
- Consumes: `RetrievalEngine`, `MemoryRepository`, existing `PolicyEvaluator`, and `ArtifactStore`.
- Produces: `ContextPackageReceipt` and `ContextSupplementReceipt`; the manifest and effective input are separate artifacts.

- [ ] **Step 1: Write failing package tests**

```rust
#[tokio::test]
async fn manifest_hash_points_to_effective_bytes_not_itself() {
    let result = compiler_fixture().compile(context_request()).await.unwrap();
    let effective = artifact_store().read(result.effective_content_artifact_id).await.unwrap();
    let manifest = artifact_store().read(result.manifest_artifact_id).await.unwrap();
    assert_eq!(sha256(&effective), result.manifest.content_hash);
    assert_ne!(sha256(&manifest), result.manifest.content_hash);
}

#[tokio::test]
async fn supplement_cannot_broaden_permissions_or_budget() {
    let compiler = compiler_fixture();
    let parent = compiler.compile(context_request()).await.unwrap();
    let denied = compiler.supplement(request_more_with_network(parent.package_id)).await;
    assert!(matches!(denied, Err(ContextError::PermissionBroadening)));
}
```

- [ ] **Step 2: Run the test and verify failure**

```bash
cargo test --manifest-path src-tauri/Cargo.toml --test context_compiler -- --nocapture
```

- [ ] **Step 3: Implement canonical compilation**

The order is fixed: validate scope → authoritative source re-read → freshness/hash check → contradiction separation → policy/redaction → token allocation → canonical serialization → outbound scan → persist effective artifact → persist manifest artifact → insert package/items. Preallocate `run_id` before compilation and reject reuse of `package_id`.

```rust
let effective_bytes = canonical_effective_input(&selected_items, &request)?;
let content_hash = sha256_digest(&effective_bytes);
let effective_artifact = artifacts.put(effective_bytes, request.scope()).await?;
let manifest = ContextPackageManifest { content_hash, ..build_manifest(request, selected_items)? };
let manifest_artifact = artifacts.put(canonical_json(&manifest)?, request.scope()).await?;
```

- [ ] **Step 4: Verify byte reconstruction and single-run binding**

```bash
cargo test --manifest-path src-tauri/Cargo.toml --test context_compiler
python validation/validate_v4_memory.py
```

Expected: reconstructed effective bytes are identical in a fresh process; package reuse fails; Python cognitive suite remains green.

- [ ] **Step 5: Commit**

```bash
git add src-tauri/src/ports/context_compiler.rs src-tauri/src/application/cognition src-tauri/tests/cognition/context_compiler.rs
git commit -m "feat: compile immutable role-specific context"
```

### Task 5: Structured working memory and protocol extension

**Files:**
- Create: `src-tauri/src/application/cognition/record_working_memory.rs`
- Modify: `src-tauri/src/protocol/handlers/context.rs`
- Create: `src-tauri/src/protocol/handlers/cognitive.rs`
- Test: `src-tauri/tests/protocol/working_memory_extension.rs`

**Interfaces:**
- Consumes: `workingMemoryEvent` and context supplement payloads from `cognitive-memory.v1.schema.json`.
- Produces: sequenced `WorkingMemorySnapshot` artifacts and protocol receipts.

- [ ] **Step 1: Write failing protocol tests**

```rust
#[tokio::test]
async fn fact_without_evidence_is_rejected() {
    let frame = json!({
        "eventId": "wm-1", "runId": "r1", "sequence": 1,
        "eventType": "fact.recorded", "statement": "SQL filters by NUM"
    });
    let result = handler().record_working_memory(frame).await;
    assert!(matches!(result, Err(ProtocolError::SchemaViolation(_))));
}

#[tokio::test]
async fn conflicting_duplicate_sequence_is_rejected() {
    let h = handler();
    h.record_working_memory(fact_event(1, "A")).await.unwrap();
    assert!(matches!(h.record_working_memory(fact_event(1, "B")).await, Err(ProtocolError::ReplayConflict)));
}
```

- [ ] **Step 2: Run the focused test**

```bash
cargo test --manifest-path src-tauri/Cargo.toml --test working_memory_extension -- --nocapture
```

- [ ] **Step 3: Implement validation, sequence handling, and checkpoints**

Identical duplicate bytes are idempotent; conflicting duplicates and sequence gaps fail. Facts/check completions require evidence; inferences/hypotheses require supporting fact IDs and confidence. Store checkpoint bytes as artifacts and append immutable snapshot rows.

- [ ] **Step 4: Verify crash recovery**

```bash
cargo test --manifest-path src-tauri/Cargo.toml --test working_memory_extension recovery_from_latest_snapshot -- --nocapture
```

Expected: after process restart, facts, inferences, unknowns, hypotheses, next action, and stop condition match the last committed sequence.

- [ ] **Step 5: Commit**

```bash
git add src-tauri/src/application/cognition/record_working_memory.rs src-tauri/src/protocol/handlers src-tauri/tests/protocol/working_memory_extension.rs
git commit -m "feat: add structured recoverable working memory"
```

### Task 6: Evidence-backed Run Evaluator

**Files:**
- Create: `src-tauri/src/ports/run_evaluator.rs`
- Create: `src-tauri/src/application/cognition/evaluate_run.rs`
- Create: `src-tauri/src/adapters/evaluator_rules/mod.rs`
- Create: `src-tauri/src/adapters/evaluator_rules/role_gates.rs`
- Test: `src-tauri/tests/cognition/run_evaluation.rs`

**Interfaces:**
- Produces: immutable `RunEvaluation` matching the JSON Schema, with `evaluatorKind`, reviewed metric names, gate decision, and source evidence.

- [ ] **Step 1: Write failing evaluator tests**

```rust
#[tokio::test]
async fn unsupported_claim_forces_repair() {
    let evaluation = evaluator().evaluate(input_with_unsupported_claim()).await.unwrap();
    assert_eq!(evaluation.gate_decision, GateDecision::Repair);
    assert_eq!(evaluation.unsupported_claims.len(), 1);
}

#[tokio::test]
async fn model_judge_cannot_override_deterministic_failure() {
    let evaluation = evaluator_with_positive_judge().evaluate(input_with_failed_test_receipt()).await.unwrap();
    assert_ne!(evaluation.gate_decision, GateDecision::Pass);
}
```

- [ ] **Step 2: Run the focused test**

```bash
cargo test --manifest-path src-tauri/Cargo.toml --test run_evaluation -- --nocapture
```

- [ ] **Step 3: Implement deterministic scoring and role gates**

Use only the schema metric names: correctness, evidence grounding, requirement coverage, constraint adherence, completeness, efficiency, tool-use quality, uncertainty calibration, regression risk, and preference adherence. Missing mandatory deterministic evidence yields `blocked` or `indeterminate`; optional judge output may annotate but never erase a failure.

- [ ] **Step 4: Run planner, implementer, critic, verifier, and researcher fixtures**

```bash
cargo test --manifest-path src-tauri/Cargo.toml --test run_evaluation
```

Expected: role-specific fixtures produce stable scores and immutable evidence artifacts.

- [ ] **Step 5: Commit**

```bash
git add src-tauri/src/ports/run_evaluator.rs src-tauri/src/application/cognition/evaluate_run.rs src-tauri/src/adapters/evaluator_rules src-tauri/tests/cognition/run_evaluation.rs
git commit -m "feat: add evidence-backed run evaluation"
```

### Task 7: Learning Engine and promotion review

**Files:**
- Create: `src-tauri/src/ports/learning_engine.rs`
- Create: `src-tauri/src/application/cognition/propose_lessons.rs`
- Create: `src-tauri/src/application/cognition/review_memory.rs`
- Test: `src-tauri/tests/cognition/verified_learning.rs`

**Interfaces:**
- Consumes: terminal run, verifier receipt, immutable evaluation, reflection, user corrections.
- Produces: `MemoryProposal` only; authority transitions continue through `MemoryRepository`.

- [ ] **Step 1: Write failing trust-boundary tests**

```rust
#[tokio::test]
async fn reflection_cannot_activate_its_own_proposal() {
    let proposals = learning_engine().extract(successful_learning_input()).await.unwrap();
    let receipt = proposal_service().persist(proposals[0].clone()).await.unwrap();
    assert_eq!(receipt.status, MemoryStatus::Candidate);
    assert!(memory_store().active_for_scope(scope()).await.unwrap().is_empty());
}

#[tokio::test]
async fn preference_without_explicit_subject_is_rejected() {
    let result = review_service().submit(preference_without_subject()).await;
    assert!(matches!(result, Err(LearningError::MissingPreferenceSubject)));
}
```

- [ ] **Step 2: Run the focused test**

```bash
cargo test --manifest-path src-tauri/Cargo.toml --test verified_learning -- --nocapture
```

- [ ] **Step 3: Implement proposal extraction and review commands**

Reject success procedures without verified success evidence, negative memories without failure evidence, and preference memory without explicit subject/scope. A granted review records exact evidence IDs, decision digest, reviewer identity, and time; then the application issues explicit `verified → approved → active` transitions.

- [ ] **Step 4: Run lifecycle and learning tests together**

```bash
cargo test --manifest-path src-tauri/Cargo.toml --test cognition_lifecycle --test cognitive_memory_sqlite --test verified_learning
```

- [ ] **Step 5: Commit**

```bash
git add src-tauri/src/ports/learning_engine.rs src-tauri/src/application/cognition/propose_lessons.rs src-tauri/src/application/cognition/review_memory.rs src-tauri/tests/cognition/verified_learning.rs
git commit -m "feat: add verified agent learning loop"
```

### Task 8: Repeated-error guard

**Files:**
- Create: `src-tauri/src/application/cognition/check_known_failures.rs`
- Modify: `src-tauri/src/application/workflow/approve_plan.rs`
- Modify: `src-tauri/src/application/tools/authorize_write.rs`
- Test: `src-tauri/tests/workflow/repeated_error_guard.rs`

**Interfaces:**
- Consumes: active negative memory, applicability scope, invalidation conditions, proposed plan/write action.
- Produces: `KnownFailureDecision::{Clear, Conflict, RequiresResolution}` and an immutable resolution receipt.

- [ ] **Step 1: Write the failing QRQC regression test**

```rust
#[tokio::test]
async fn blocks_num_id_mapping_regression_until_resolved() {
    let guard = guard_with_negative_memory("SQL filters by NUM; do not populate ID").await;
    let decision = guard.check(write_action("d_qrqc.ID = lbl_num.Text")).await.unwrap();
    assert!(matches!(decision, KnownFailureDecision::Conflict { .. }));
}
```

- [ ] **Step 2: Run the test and verify the write currently proceeds**

```bash
cargo test --manifest-path src-tauri/Cargo.toml --test repeated_error_guard -- --nocapture
```

- [ ] **Step 3: Implement applicability matching and resolution policy**

A high-risk conflicting write is denied until the plan changes, authoritative invalidation evidence proves the memory obsolete, or an explicit approved exception receipt is bound to the exact operation digest. Similarity alone cannot block a write; the guard requires matched scope and evidence-backed conflict rules.

- [ ] **Step 4: Verify obsolete and out-of-scope memories do not block**

```bash
cargo test --manifest-path src-tauri/Cargo.toml --test repeated_error_guard
```

Expected: current applicable negative memory blocks; stale, expired, retracted, superseded, cross-project, and authoritatively invalidated memory does not.

- [ ] **Step 5: Commit**

```bash
git add src-tauri/src/application/cognition/check_known_failures.rs src-tauri/src/application/workflow/approve_plan.rs src-tauri/src/application/tools/authorize_write.rs src-tauri/tests/workflow/repeated_error_guard.rs
git commit -m "feat: prevent repeated known agent errors"
```

### Task 9: Cognitive desktop UX

**Files:**
- Create: `src/features/context-debugger/ContextDebugger.tsx`
- Create: `src/features/memory-explorer/MemoryExplorer.tsx`
- Create: `src/features/learning-review/LearningReviewQueue.tsx`
- Create: `src/features/quality-dashboard/QualityDashboard.tsx`
- Create: `src/features/cognition-api.ts`
- Test: `src/features/__tests__/cognition.test.tsx`

**Interfaces:**
- Consumes: read-only cognitive DTOs plus explicit `approve`, `reject`, `reverify`, `retract`, and `requestSupplement` commands.
- Produces: inspectable context, memory, review, degraded-state, and benchmark views; no direct SQL or index API access.

- [ ] **Step 1: Write failing component tests**

```tsx
it("shows assertion and verified-memory states distinctly", async () => {
  render(<ContextDebugger packageId="cp1" />);
  expect(await screen.findByText("Verified memory")).toBeVisible();
  expect(screen.getByText("Assertion")).toBeVisible();
});

it("does not offer bulk approval for sensitive proposals", async () => {
  render(<LearningReviewQueue />);
  expect(await screen.findByText("internal-code")).toBeVisible();
  expect(screen.queryByRole("button", { name: /approve all/i })).not.toBeInTheDocument();
});
```

- [ ] **Step 2: Run the frontend test**

```bash
pnpm vitest run src/features/__tests__/cognition.test.tsx
```

- [ ] **Step 3: Implement the four surfaces**

Render authority state, source revision/hash, inclusion reason, contradictions, stale/expired status, index branch health, immutable review history, per-case quality regressions, loading/empty/error/degraded states, and keyboard-accessible review dialogs. Never label model confidence as verification.

- [ ] **Step 4: Run component and accessibility tests**

```bash
pnpm vitest run src/features/__tests__/cognition.test.tsx
pnpm test:a11y
```

- [ ] **Step 5: Commit**

```bash
git add src/features
git commit -m "feat: add cognitive memory inspection ux"
```

### Task 10: Locked benchmark harness and release evidence

**Files:**
- Create: `benchmarks/engineering-v1/manifest.json`
- Create: `benchmarks/engineering-v1/cases/qrqc-num-id.json`
- Create: `src-tauri/src/application/benchmark/run_suite.rs`
- Create: `src-tauri/src/application/benchmark/compare.rs`
- Create: `validation/validate_quality_report.py`
- Test: `src-tauri/tests/benchmark/comparison_integrity.rs`

**Interfaces:**
- Produces: benchmark suite/case/run/comparison records matching `agent-quality-benchmark.v1.schema.json` and immutable report artifacts.

- [ ] **Step 1: Write failing comparability tests**

```rust
#[test]
fn different_evaluator_configuration_is_invalid() {
    let result = compare_runs(run("eval-a"), run("eval-b"));
    assert_eq!(result, Err(ComparisonError::EvaluatorMismatch));
}

#[test]
fn aggregate_improvement_cannot_hide_case_regression() {
    let report = compare_suite(baseline_fixture(), candidate_with_one_regression()).unwrap();
    assert_eq!(report.result, ComparisonResult::Regressed);
    assert_eq!(report.regressions, vec![CaseId::from("qrqc-num-id")]);
}
```

- [ ] **Step 2: Run the focused test**

```bash
cargo test --manifest-path src-tauri/Cargo.toml --test comparison_integrity -- --nocapture
```

- [ ] **Step 3: Implement locked fixture and equal-configuration binding**

Bind suite version, case digest, repository revision set, task input, budget profile, policy snapshot, system configuration, evaluator configuration, and acceptance rules. Persist every case result and explicit regression list before calculating aggregate metrics.

- [ ] **Step 4: Run baseline and candidate with the same manifest**

```bash
cargo run --manifest-path src-tauri/Cargo.toml -- benchmark run benchmarks/engineering-v1/manifest.json --label v3.2-baseline
cargo run --manifest-path src-tauri/Cargo.toml -- benchmark run benchmarks/engineering-v1/manifest.json --label v4-candidate
python validation/validate_quality_report.py artifacts/benchmark-comparison.json
```

Expected: comparison is rejected on any configuration mismatch; accepted output lists every per-case regression.

- [ ] **Step 5: Commit**

```bash
git add benchmarks src-tauri/src/application/benchmark validation/validate_quality_report.py src-tauri/tests/benchmark/comparison_integrity.rs
git commit -m "feat: add reproducible agent quality benchmark"
```

### Task 11: Optional retrieval sidecar conformance

**Files:**
- Create: `src-tauri/src/adapters/retrieval_sidecar/mod.rs`
- Create: `src-tauri/src/adapters/retrieval_sidecar/client.rs`
- Create: `src-tauri/src/adapters/retrieval_sidecar/lifecycle.rs`
- Test: `src-tauri/tests/cognition/sidecar_conformance.rs`

**Interfaces:**
- Consumes/produces: the exact `RetrievalEngine` request/result types from Task 3.
- The sidecar receives opaque source IDs and permitted bytes only; it never receives SQLite paths, writable repository handles, approval credentials, or authority tokens.

- [ ] **Step 1: Write failing sidecar tests**

```rust
#[tokio::test]
async fn crash_degrades_without_losing_authority() {
    let fixture = sidecar_fixture().await;
    fixture.kill_during_retrieval().await;
    let result = fixture.engine.retrieve(retrieval_request()).await.unwrap();
    assert_eq!(result.status, RetrievalStatus::Degraded);
    assert!(result.branches.iter().any(|b| b.name == "exact" && b.succeeded));
    assert_eq!(fixture.authority_row_count().await, fixture.initial_authority_row_count());
}
```

- [ ] **Step 2: Run the focused test**

```bash
cargo test --manifest-path src-tauri/Cargo.toml --test sidecar_conformance -- --nocapture
```

- [ ] **Step 3: Implement authenticated local IPC and bounded lifecycle**

Bind each request to protocol version, project/task/run scope, policy snapshot, request digest, deadline, and maximum response size. Verify response digest and source references before accepting candidates. Retry only idempotent retrieval/index requests and record each attempt.

- [ ] **Step 4: Run crash, stale-source, disclosure, and cross-project cases**

```bash
cargo test --manifest-path src-tauri/Cargo.toml --test sidecar_conformance
```

- [ ] **Step 5: Commit**

```bash
git add src-tauri/src/adapters/retrieval_sidecar src-tauri/tests/cognition/sidecar_conformance.rs
git commit -m "feat: add conformant retrieval sidecar"
```

### Task 12: Migration rehearsal and full release verification

**Files:**
- Create: `src-tauri/src/application/cognition/migrate_v32.rs`
- Create: `src-tauri/tests/migration/v32_to_v4.rs`
- Create: `validation/validate_migration_report.py`
- Modify: `validation/validate_package.py`

**Interfaces:**
- Consumes: exact v2 database checksum, v4 migration contract, authority/artifact backups.
- Produces: deterministic mapping plan, per-record receipts, quarantine report, schema-equivalence report, rebuilt index generation, and G11/G12 evidence bundle.

- [ ] **Step 1: Create the failing migration fixture and assertions**

```rust
#[tokio::test]
async fn migration_reconciles_every_legacy_row() {
    let fixture = legacy_fixture_with_valid_invalid_and_cyclic_rows().await;
    let report = migrate(fixture).await.unwrap();
    assert_eq!(report.legacy_total, report.migrated + report.safely_skipped + report.quarantined);
    assert!(report.schema_objects_equivalent);
    assert!(report.cross_project_links.is_empty());
    assert!(report.quarantine.iter().any(|q| q.reason == "cycle"));
}
```

- [ ] **Step 2: Run migration tests and verify failure**

```bash
cargo test --manifest-path src-tauri/Cargo.toml --test v32_to_v4 -- --nocapture
```

- [ ] **Step 3: Implement the exact migration sequence**

Implement checksum verification, backup receipt, schema installation, deterministic chain analysis, UUIDv5 ID mapping, candidate-first writes, evidence reconstruction, status transitions, supersession relations, quarantine, index rebuild, cutover receipt, and idempotent resume exactly as specified in `26-v3.2-to-v4-migration-contract.md`.

- [ ] **Step 4: Run all release gates from a clean checkout**

```bash
cargo fmt --manifest-path src-tauri/Cargo.toml -- --check
cargo clippy --manifest-path src-tauri/Cargo.toml --all-targets --all-features -- -D warnings
cargo test --manifest-path src-tauri/Cargo.toml --all-features
pnpm lint
pnpm vitest run
python validation/validate_v3.py
python validation/validate_v32_hardening.py
python validation/validate_v4_memory.py
python validation/validate_v4_traceability.py
python validation/validate_package.py
python validation/validate_migration_report.py artifacts/migration-report.json
```

Expected: no skipped critical gate; historical suites remain green; migration report reconciles all rows; quality report lists regressions explicitly.

- [ ] **Step 5: Commit**

```bash
git add src-tauri/src/application/cognition/migrate_v32.rs src-tauri/tests/migration validation/validate_migration_report.py validation/validate_package.py
git commit -m "test: verify cognitive memory v4 release gates"
```

## Plan self-review checklist

- Every FR-029 through FR-037 is implemented by at least one task.
- Every NFR-011 through NFR-014 has a focused test and release command.
- Canonical interface names are used consistently across tasks.
- No task allows retrieval, reflection, evaluation, or sidecar code to transition memory authority directly.
- Stale memory replacement, preference subject/scope, package/effective hash separation, one-package-per-run, migration quarantine, and equal-configuration benchmarks are explicitly tested.
- Optional sidecar work can be omitted without changing embedded authority semantics; all other tasks are required for G11/G12.
