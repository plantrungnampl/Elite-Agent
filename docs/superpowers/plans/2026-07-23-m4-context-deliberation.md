# M4 Context and Deliberation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Use superpowers:test-driven-development for every behavior change, vercel-react-best-practices before React work, and superpowers:verification-before-completion before marking any step complete. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Deliver policy-safe repository context, two-provider independent deliberation, evidence-linked synthesis and objection handling, exact plan approval, and a built-in Anthropic `core_adapter` while proving no repository-visible mutation occurs before plan approval.

**Architecture:** Preserve Clean Architecture. `domain` owns pure context, citation, deliberation, quorum, claim, dissent, objection, and plan-binding invariants. `application` owns context/deliberation/approval use cases and ports. New `context-engine` and `orchestration` crates implement deterministic retrieval and coordination through those ports. `repository-git` supplies coherent read-only source snapshots; `policy-engine` performs every metadata/content/final-payload disclosure; `storage-sqlite` and `storage-files` persist reconstructible artifacts and workflow state. `agent-runtime` routes bounded typed agent requests. New `provider-anthropic` maps Anthropic Messages API into the provider-neutral protocol. `bootstrap` alone composes concrete adapters. Tauri and React expose only immutable core DTOs and opaque approval actions.

**Tech Stack:** Rust 1.97 MSVC, Cargo workspace, serde/serde_json, existing RFC 8785/SHA-256 helpers, SQLite/rusqlite, content-addressed artifacts, vendored libgit2, existing policy engine, existing agent protocol/runtime, `reqwest` blocking client with rustls and no default features, bounded stdlib SSE parsing, Tauri 2, React 19/TypeScript/Vitest/Testing Library/Playwright/axe-core, Node `node:test` contracts, and deterministic loopback provider fixtures. No live provider call is required for the gate.

## Global Constraints

- Work in `D:\multiagent` on `codex/m4-context-deliberation`. Do not create or use a developer Git worktree.
- Baseline before M4 execution artifacts is `9b182a33a3cb568efb68770ed64828ae17692dc6`. The derived design commit is `882d746`.
- `docs/multi-agent-terminal-design/**` is immutable. Verify it against the baseline after every architecture/evidence task.
- The approved derived design is `docs/superpowers/specs/2026-08-09-m4-context-deliberation-design.md`. If it contradicts a normative contract, stop and follow the normative contract.
- Stay inside M4. Do not implement vector/embedding retrieval, repository-graph retrieval, project-memory promotion, the M5 executor/candidate-tree/commit path, a brokered process, marketplace discovery, or live provider configuration UI.
- Implement keyword and metadata retrieval only. Keyword state is non-authoritative and rebuildable; source revision/hash and immutable artifacts remain authoritative.
- Run metadata and content through policy before any index/cache write. Denied bytes never reach `source_chunks`, artifacts, keyword structures, context packages, logs, DTOs, provider requests, or evidence.
- Treat filenames, symbols, metadata, summaries, tool output, and provider output as potentially sensitive. A denied logical path is persisted only as a stable redacted identifier when audit metadata is required.
- Context packages are immutable. Persist exact effective bytes plus policy decisions, redaction report, revisions, hashes, prompt/retrieval/tokenizer versions, manifest/adapter/provider/model configuration, and run binding before dispatch.
- Require two hidden independent proposals from different recorded provider/model-family keys for the M4 heterogeneous gate. Equality is used only for diversity/audit; orchestration never branches on provider names.
- Tool requests remain denied in every pre-plan phase. Do not grant a writer lease, create a task worktree, branch, ref, repository-local artifact, or repository file before exact plan approval.
- Anthropic is a built-in `core_adapter` using `POST /v1/messages`, `x-api-key`, `anthropic-version: 2023-06-01`, and named SSE events. Model ID is mandatory bound run configuration; no silently upgraded default is allowed.
- Provider credentials are explicit in-memory bootstrap input. Never read them from ambient environment, serialize them, derive identity from them, or include them in `Debug`, errors, logs, SQLite, artifacts, DTOs, tests, or evidence.
- Handwritten behavior is test-first: focused RED, minimum GREEN, focused regression, checkbox update, review, then one Conventional Commit per task.
- Mark a checkbox `[x]` immediately only after its stated verification passes. Never pre-mark a step, task, evidence item, or review.
- After each reviewed task commit, append its task number, commit, tests, and review disposition to `.superpowers/sdd/progress.md` without rewriting earlier history.
- Preserve unrelated user changes. Every changed line must trace to this plan.

---

## Task 1: Pin executable M4 contracts and dependency boundaries

**Files:**

- Create: `tests/contracts/m4-contracts.test.mjs`
- Create: `tests/contracts/fixtures/m4/context-engine-outward-metadata.json`
- Create: `tests/contracts/fixtures/m4/orchestration-outward-metadata.json`
- Create: `tests/contracts/fixtures/m4/provider-anthropic-outward-metadata.json`
- Create: `tests/contracts/fixtures/m4/provider-name-branch.rs`
- Create: `tests/contracts/fixtures/m4/preapproval-write.rs`
- Modify: `scripts/check-architecture.mjs`
- Modify: `tests/contracts/architecture.test.mjs`
- Verify only: `docs/multi-agent-terminal-design/**`

**Dependency contract:**

```text
domain <- application
domain + application <- context-engine
domain + application <- orchestration
domain + application <- storage-sqlite
domain + application <- repository-git
agent-protocol <- provider-openai
agent-protocol <- provider-anthropic
application + orchestration + context-engine + providers + adapters <- bootstrap
bootstrap <- Tauri <- React API modules
```

- [x] **Step 1 - Write failing M4 contract tests**

Assert the three new crates and exact internal allowlists, no crate cycles, no provider DTO/name/policy logic in inner crates, no HTTP outside provider crates, no provider construction outside bootstrap, no concrete storage/repository/policy construction in `context-engine` or `orchestration`, no direct Tauri invoke outside `apps/desktop/src/api`, and no pre-approval write-capable call path.

Assert the normative workflow includes every M4 phase/effect, the SQLite schema includes source/context/message/approval relations, and M4 does not add vector/graph execution or relax `brokered_process` containment.

```powershell
node --test tests/contracts/m4-contracts.test.mjs
```

Expected RED: M4 fixtures, allowlists, and required-crate checks do not exist.

- [x] **Step 2 - Add only contract checker rules and hostile fixtures**

Permit partial M4 crate presence while Tasks 2–8 are in progress, but enforce each present crate's exact dependency allowlist. Add `--require-m4` to require all final crates, desktop API routing, zero provider-name branches, and absence of forbidden M5/M6 features.

- [x] **Step 3 - Verify M0–M4 contracts and immutable design**

```powershell
node --test tests/contracts/m4-contracts.test.mjs tests/contracts/architecture.test.mjs tests/contracts/design-contracts.test.mjs tests/contracts/m3-contracts.test.mjs
node scripts/check-architecture.mjs
git diff --exit-code 9b182a3 -- docs/multi-agent-terminal-design
```

- [x] **Step 4 - Commit and record progress**

```powershell
git add scripts/check-architecture.mjs tests/contracts .superpowers/sdd/progress.md
git diff --cached --check
git commit -m "test: pin m4 context deliberation contracts"
```

## Task 2: Add pure context, evidence, and deliberation domain rules

**Files:**

- Create: `crates/domain/src/context.rs`
- Create: `crates/domain/src/deliberation.rs`
- Modify: `crates/domain/src/agent.rs`
- Modify: `crates/domain/src/lib.rs`
- Create: `crates/domain/tests/context_contract.rs`
- Create: `crates/domain/tests/deliberation_contract.rs`
- Modify: `crates/domain/tests/agent_contract.rs`

**Minimum domain surface:**

```rust
pub struct SourceIdentity { /* project, revision, path identity, content hash */ }
pub struct EvidenceCitation { /* source identity, range, symbol */ }
pub struct ContextPackageBinding { /* package, policy, artifact, content digest */ }
pub enum ClaimVerification { Verified, Rejected, Inconclusive, NotApplicable }
pub struct IndependentProposal { /* run, agent family, artifact, citations */ }
pub struct ReviewEdge { /* reviewer, target proposal, bounded round */ }
pub struct MaterialClaim { /* claimant, artifact, citations, method */ }
pub struct DecisionPackage { /* selected/rejected/evidence/dissent/plan */ }
pub struct FinalObjection { /* severity, impact, evidence */ }
pub struct PlanApprovalBinding { /* plan/base/policy/scope/tools/actor/expiry */ }
```

- [x] **Step 1 - Write failing context invariant tests**

Reject empty/oversized IDs and objectives, invalid or inverted line ranges, missing revision/hash provenance, cross-task package references, duplicate policy decisions, unversioned prompt/retrieval/tokenizer identity, a package whose exact effective artifact digest differs, stale evidence accepted as current, denied/redacted entries without stable reports, and token budgets that overflow or reserve no response capacity.

- [x] **Step 2 - Write failing deliberation invariant tests**

Reject same-run/same-agent/same-family quorum, revealed-before-quorum proposals, duplicate review edges, unbounded rounds/agents/requests, specialist requests without reason/context/budget, claims without citations, nonterminal claim sets at synthesis, lost dissent, selected approaches without evidence, malformed severe objections, multiple final objections per participant/round, and incomplete plan approval bindings.

Add table-driven property-style loops proving order-independent deduplication, monotonic budget use, terminal claim classification, stable canonical member ordering, and equality-only family diversity.

```powershell
cargo test -p local-agent-terminal-domain --test context_contract --test deliberation_contract --test agent_contract
```

Expected RED: context/deliberation modules and extended request limits do not exist.

- [x] **Step 3 - Implement the minimum validated value objects**

Use enums rather than state strings, borrowed inputs where ownership is unnecessary, private fields where invariants matter, and narrow constructors. Extend `AgentRunLimits` with explicit context-query and specialist-request counts while keeping old run artifacts parseable through versioned application decoding.

- [x] **Step 4 - Verify and commit**

```powershell
cargo fmt --all -- --check
cargo test -p local-agent-terminal-domain
node scripts/check-architecture.mjs
git add crates/domain .superpowers/sdd/progress.md
git diff --cached --check
git commit -m "feat: add context deliberation domain rules"
```

## Task 3: Define context, deliberation, and plan-approval application ports

**Files:**

- Create: `crates/application/src/context.rs`
- Create: `crates/application/src/deliberation.rs`
- Create: `crates/application/src/plan_approval.rs`
- Modify: `crates/application/src/agent.rs`
- Modify: `crates/application/src/policy.rs`
- Modify: `crates/application/src/dto.rs`
- Modify: `crates/application/src/lib.rs`
- Create: `crates/application/tests/context_ports.rs`
- Create: `crates/application/tests/deliberation_ports.rs`
- Create: `crates/application/tests/plan_approval_digest.rs`
- Modify: `crates/application/tests/agent_ports.rs`

**Ports and use cases:**

```rust
pub trait RepositoryContextSource: Send + Sync {
    fn snapshot(&self, request: SourceSnapshotRequest) -> Result<SourceSnapshot, PortError>;
}

pub trait ContextStore: Send + Sync { /* source, chunk, package, policy links */ }
pub trait ContextArtifactPublisher: Send + Sync { /* exact immutable bytes */ }
pub trait DeliberationStore: Send + Sync { /* private/public artifacts and state */ }
pub trait PlanApprovalStore: Send + Sync { /* request, resolve, invalidate, reload */ }
pub trait AgentRequestHandler: Send + Sync { /* context query, specialist request */ }

pub struct BuildInitialContext { /* ports only */ }
pub struct QueryContext { /* ports only */ }
pub struct DeliberationCommands { /* deterministic commands */ }
pub struct ResolvePlanApproval { /* canonical reload and compare */ }
```

- [x] **Step 1 - Write failing object-safety and use-case tests**

Use recording ports to prove coherent source identity is preserved, policy is called before any persistence port, denied content never reaches the artifact/index port, final serialized disclosure happens before package publish, and every package includes all decision relations.

Prove deliberation commands reject wrong phase/version/task/actor, cannot publish a proposal before quorum, cannot synthesize incomplete claim sets, cannot close an accepted severe objection, and cannot approve a stale plan.

- [x] **Step 2 - Write failing canonical plan-approval tests**

Define `PlanApprovalPayloadV1` with plan artifact/digest/version, base commit, repository fingerprint, policy snapshot, task scope, writable scope, tools, verification profile, actor, fencing epoch, requested-at, and expiry. Make every scalar, list member, ordering, and Unicode form affect canonical bytes/digest one leaf at a time. Reject duplicate JSON keys and noncanonical persisted payloads.

Approve input contains only approval ID, displayed digest, expected task version, actor, and action. The use case reloads canonical bytes and recomputes the digest.

```powershell
cargo test -p local-agent-terminal-application --test context_ports --test deliberation_ports --test plan_approval_digest --test agent_ports
```

- [x] **Step 3 - Implement minimum ports, use cases, DTOs, and safe errors**

Add explicit policy channels for index metadata, index content, retrieved item, and final context package. Do not leak physical paths, source bytes, provider payloads, or secret match detail through DTOs/errors. Reuse the existing event, artifact, approval, policy, workflow reducer, and canonical JSON utilities.

- [x] **Step 4 - Verify and commit**

```powershell
cargo fmt --all -- --check
cargo test -p local-agent-terminal-application
node scripts/check-architecture.mjs
git add crates/application .superpowers/sdd/progress.md
git diff --cached --check
git commit -m "feat: define context deliberation use cases"
```

## Task 4: Persist source, package, deliberation, and plan-approval state

**Files:**

- Modify: `crates/storage-sqlite/src/migrations.rs`
- Modify: `crates/storage-sqlite/src/lib.rs`
- Create: `crates/storage-sqlite/src/context_store.rs`
- Create: `crates/storage-sqlite/src/deliberation_store.rs`
- Create: `crates/storage-sqlite/src/plan_approval_store.rs`
- Modify: `crates/storage-sqlite/src/agent_store.rs`
- Create: `crates/storage-sqlite/tests/context_store.rs`
- Create: `crates/storage-sqlite/tests/deliberation_store.rs`
- Create: `crates/storage-sqlite/tests/plan_approval_store.rs`
- Modify: `crates/storage-sqlite/tests/schema_health.rs`
- Modify: `crates/storage-sqlite/tests/agent_store.rs`

- [x] **Step 1 - Write failing migration and context-store tests**

Use the existing normative `source_documents`, `source_chunks`, `context_packages`, and `context_package_policy_decisions` tables. Add only adapter-hardening migration triggers/indexes required for immutable package fields, safe source-state transitions, and immutable package-policy relations; do not modify the normative SQL.

Test idempotent exact replay, conflict on changed canonical bytes, denied documents without chunks/content artifacts, redacted logical identifiers, current-to-stale transition, revision/hash lookup, package-before-run persistence, all policy links, and unavailable/tampered artifact rejection.

- [x] **Step 2 - Write failing private-deliberation and approval tests**

Persist private proposal receipt as immutable artifact/event without a shared `messages` projection. Publish proposal projections atomically only after quorum. Persist review edges, thread summaries, claim sets, verification sets, decision drafts, objections, and supersession through exact artifact/event references.

Use `approvals` with `approval_type = plan` through a dedicated application port. Test exact replay, changed payload conflict, expiry, invalidation after policy/repository/task/agent change, one terminal resolution, startup reconciliation, and no tool-approval regression.

```powershell
cargo test -p local-agent-terminal-storage-sqlite --test context_store --test deliberation_store --test plan_approval_store --test schema_health --test agent_store
```

- [x] **Step 3 - Implement transactional adapters and recovery reads**

Keep authoritative payload bytes in the content-addressed artifact store; SQLite stores verified references and projections. Reuse optimistic stream versions and `ProjectionChange::TaskState` so phase events and task projections commit atomically. Do not add a mutable in-memory sole source.

Keep `create_bound_run` compatible with M3: it may idempotently verify an already-persisted context package but must reject a different package with the same identity.

- [ ] **Step 4 - Run crash/reopen regressions and commit**

```powershell
cargo fmt --all -- --check
cargo test -p local-agent-terminal-storage-sqlite
cargo test -p local-agent-terminal-storage-files
node scripts/check-architecture.mjs
git add crates/storage-sqlite .superpowers/sdd/progress.md
git diff --cached --check
git commit -m "feat: persist m4 context deliberation state"
```

## Task 5: Implement pre-index filtering and keyword/metadata context packages

**Files:**

- Modify: `Cargo.toml`
- Create: `crates/context-engine/Cargo.toml`
- Create: `crates/context-engine/src/lib.rs`
- Create: `crates/context-engine/src/ingest.rs`
- Create: `crates/context-engine/src/chunk.rs`
- Create: `crates/context-engine/src/keyword.rs`
- Create: `crates/context-engine/src/package.rs`
- Create: `crates/context-engine/src/budget.rs`
- Create: `crates/context-engine/tests/pre_index_filter.rs`
- Create: `crates/context-engine/tests/retrieval.rs`
- Create: `crates/context-engine/tests/package_contract.rs`
- Create: `crates/repository-git/src/context_source.rs`
- Modify: `crates/repository-git/src/lib.rs`
- Create: `crates/repository-git/tests/context_source.rs`
- Modify: `crates/policy-engine/src/lib.rs`
- Modify: `crates/policy-engine/src/classification.rs`
- Create: `crates/policy-engine/tests/context_disclosure.rs`

- [ ] **Step 1 - Write failing coherent source-reader tests**

Enumerate the committed base tree through libgit2 without checkout/process execution. Overlay any accepted current tracked-worktree bytes only when they are bound to one coherent workspace fingerprint; label committed and overlay revisions distinctly. Reject repository identity changes, blob/hash mismatch, submodule/symlink/device ambiguity, path traversal, unsupported binary/oversized content, and mutation during capture. Prove HEAD/index/worktree bytes are unchanged.

- [ ] **Step 2 - Write failing pre-index filtering tests**

Use recording persistence ports and fake canaries to prove metadata disclosure precedes content disclosure, both precede chunk/index/artifact writes, all deny/scan failures fail closed, denied names become stable redacted identifiers, prompt-injection and secret patterns are redacted or denied, and no original canary occurs in persisted/indexed/diagnostic output.

- [ ] **Step 3 - Write failing keyword/metadata retrieval tests**

Test exact path/symbol/term ranking, role relevance, accepted-decision boost, deterministic tie order, hash deduplication, metadata-only degraded mode, current/stale/failed/denied states, changed revision rejection, and bounded result count. Do not add FTS/vector/graph dependencies; a deterministic normalized inverted map is sufficient and rebuildable.

- [ ] **Step 4 - Write failing package-builder tests**

Use a conservative `byte-token-v1` budget where one retained UTF-8 byte consumes at least one budget unit; this may underfill but cannot overrun the provider-neutral cap. Test role-sensitive allocations, response reserve, stable serialization, exact artifact digest, all policy relations, redaction/provenance completeness, final serialized-payload disclosure, and unchanged source citation identity.

```powershell
cargo test -p local-agent-terminal-repository-git --test context_source
cargo test -p local-agent-terminal-policy-engine --test context_disclosure
cargo test -p local-agent-terminal-context-engine
```

- [ ] **Step 5 - Implement the minimum engine and adapters**

Chunk UTF-8 text on bounded line/paragraph boundaries; preserve path, revision, content hash, line range, language, and optional supplied symbol. Keep the index non-authoritative and rebuildable. Avoid speculative parsers, embeddings, caches, or generic plugin abstractions.

- [ ] **Step 6 - Verify security/regressions and commit**

```powershell
cargo fmt --all -- --check
cargo test -p local-agent-terminal-policy-engine
cargo test -p local-agent-terminal-repository-git
cargo test -p local-agent-terminal-context-engine
node scripts/check-architecture.mjs
git add Cargo.toml Cargo.lock crates/context-engine crates/repository-git crates/policy-engine .superpowers/sdd/progress.md
git diff --cached --check
git commit -m "feat: build policy safe context packages"
```

## Task 6: Route bounded context and specialist protocol requests

**Files:**

- Modify: `crates/domain/src/agent.rs`
- Modify: `crates/application/src/agent.rs`
- Modify: `crates/agent-runtime/src/runtime.rs`
- Modify: `crates/agent-runtime/src/fakes.rs`
- Modify: `crates/agent-runtime/tests/runtime_contract.rs`
- Modify: `crates/agent-runtime/tests/fake_conformance.rs`
- Modify: `crates/agent-protocol/tests/session_contract.rs`
- Modify: `crates/agent-protocol/tests/conformance.rs`
- Modify: `crates/bootstrap/src/agent_runtime.rs`
- Modify: `crates/bootstrap/tests/agent_recovery.rs`

- [ ] **Step 1 - Write failing runtime request-routing tests**

Replace the M3 blanket denial only for negotiated `context/query` and `specialist/request` frames. Verify run/task/connection/request ownership, capability negotiation, unique IDs, item/token/request/deadline limits, exact one typed response, durable audit before success, and isolation across concurrent runs.

Keep `tool/request` policy-denied. Reject notification misuse, wrong origin, stale run, cross-task references, unrequested artifacts, over-budget requests, conflicting duplicates, response-after-terminal, and handler errors without leaking payload bytes.

- [ ] **Step 2 - Add handler ports and per-run counters**

Inject `AgentRequestHandler` into `ProtocolAgentRuntime`. Provide a default deny handler so existing M3 construction remains safe. Count context/specialist requests under the bound run limits and persist accepted/rejected request artifacts/events through the handler before responding.

- [ ] **Step 3 - Extend deterministic peers and conformance**

Add scripted context-query and specialist-request peers, including malicious cross-task, overflow, duplicate, slow, and crashing cases. The shared harness must prove every request gets exactly one typed response and no request can manufacture a workflow event.

- [ ] **Step 4 - Verify and commit**

```powershell
cargo fmt --all -- --check
cargo test -p local-agent-terminal-agent-protocol
cargo test -p local-agent-terminal-agent-runtime
cargo test -p local-agent-terminal-bootstrap --test agent_recovery
node scripts/check-architecture.mjs
git add crates/domain crates/application crates/agent-protocol crates/agent-runtime crates/bootstrap .superpowers/sdd/progress.md
git diff --cached --check
git commit -m "feat: route bounded agent context requests"
```

## Task 7: Implement deterministic deliberation orchestration and recovery

**Files:**

- Modify: `Cargo.toml`
- Create: `crates/orchestration/Cargo.toml`
- Create: `crates/orchestration/src/lib.rs`
- Create: `crates/orchestration/src/coordinator.rs`
- Create: `crates/orchestration/src/selection.rs`
- Create: `crates/orchestration/src/claims.rs`
- Create: `crates/orchestration/src/recovery.rs`
- Create: `crates/orchestration/tests/workflow_contract.rs`
- Create: `crates/orchestration/tests/request_contract.rs`
- Create: `crates/orchestration/tests/recovery.rs`
- Create: `crates/orchestration/tests/zero_mutation.rs`
- Modify: `crates/application/src/deliberation.rs`
- Modify: `crates/application/src/dto.rs`

- [ ] **Step 1 - Write failing phase and quorum tests**

Drive the exact normative sequence:

```text
Intake -> ContextBuild -> ParallelAnalysis -> CrossReview
-> PrePlanVerification -> Synthesis -> FinalObjection
-> AwaitingPlanApproval
```

Prove every phase event is accepted by the normative reducer, every required effect is persisted before dispatch, two distinct family keys are required, proposals remain hidden until quorum, early consensus never skips quorum/verification/approval, and provider unavailability blocks rather than inventing a single-provider pass.

- [ ] **Step 2 - Write failing review, specialist, verification, and dissent tests**

Test bounded review-edge assignment without broadcast, one review per edge, bounded specialist eligibility/budget/thread context, accepted summary promotion, and typed denial.

Extract stable material claims, run deterministic checks first, require one terminal classification per claim, reject stale citations, and prevent agent confidence from changing trusted status. Synthesis must preserve selected/rejected alternatives, verified/inconclusive evidence, dissent, files, steps, tools, verification, rollback, risk, cost, and confidence.

- [ ] **Step 3 - Write failing objection and approval-transition tests**

Test one objection per participant/round, structured severity/impact/evidence, accepted severe objection reopening one bounded CrossReview round, preserved superseded draft/history, no close while severe accepted objection remains, and exact `plan.approved` transition only after canonical approval reload succeeds.

- [ ] **Step 4 - Write failing recovery and zero-mutation tests**

Crash after each event/artifact/run/visibility/claim/draft/approval boundary. Reopen and resume only missing idempotent work with new run IDs where required. Capture authoritative repository fingerprint before ContextBuild and at every phase boundary; any mismatch blocks and invalidates packages/approval.

Use a write-spy repository/tool/lease adapter to prove no pre-approval call can create a worktree/branch/ref/file, acquire an executor lease, or expose a write tool schema.

```powershell
cargo test -p local-agent-terminal-orchestration
```

- [ ] **Step 5 - Implement the smallest resumable coordinator**

Use application traits only. Keep selection capability-based, use family equality solely for diversity, append events/projection changes transactionally, and store all dispatch bindings before calling external runtimes. Do not add a generic supervisor DSL or provider-specific orchestration.

- [ ] **Step 6 - Verify and commit**

```powershell
cargo fmt --all -- --check
cargo test -p local-agent-terminal-orchestration
cargo test -p local-agent-terminal-application
cargo test -p local-agent-terminal-domain
node scripts/check-architecture.mjs
git add Cargo.toml Cargo.lock crates/orchestration crates/application .superpowers/sdd/progress.md
git diff --cached --check
git commit -m "feat: orchestrate evidence linked deliberation"
```

## Task 8: Add Anthropic core adapter and compose two providers

**Files:**

- Modify: `Cargo.toml`
- Create: `crates/provider-anthropic/Cargo.toml`
- Create: `crates/provider-anthropic/src/lib.rs`
- Create: `crates/provider-anthropic/src/config.rs`
- Create: `crates/provider-anthropic/src/request.rs`
- Create: `crates/provider-anthropic/src/sse.rs`
- Create: `crates/provider-anthropic/src/adapter.rs`
- Create: `crates/provider-anthropic/tests/request_contract.rs`
- Create: `crates/provider-anthropic/tests/streaming_contract.rs`
- Create: `crates/provider-anthropic/tests/conformance.rs`
- Modify: `crates/bootstrap/Cargo.toml`
- Modify: `crates/bootstrap/src/agent_runtime.rs`
- Create: `crates/bootstrap/src/context_runtime.rs`
- Create: `crates/bootstrap/src/deliberation_runtime.rs`
- Modify: `crates/bootstrap/src/startup.rs`
- Modify: `crates/bootstrap/src/lib.rs`
- Modify: `crates/bootstrap/tests/agent_runtime_e2e.rs`
- Modify: `crates/bootstrap/tests/agent_recovery.rs`
- Modify: `crates/bootstrap/tests/startup.rs`

- [ ] **Step 1 - Write failing Anthropic request tests**

Assert exact `POST /v1/messages` path, HTTPS-only production endpoint, loopback-only test HTTP, `x-api-key`, `anthropic-version: 2023-06-01`, content type, mandatory configured model, max tokens, optional temperature, stream flag, stable system instructions, and one user content block carrying the bound effective context representation.

Change every bound input leaf and prove the request changes. Reject unsupported generation parameters, invalid endpoint redirects, oversized context, missing model, invalid header values, and any credential appearance in serialized/debug/error output.

- [ ] **Step 2 - Write failing bounded SSE and lifecycle tests**

Handle documented `message_start`, `content_block_start`, `content_block_delta` text, `content_block_stop`, `message_delta`, `message_stop`, and permitted `ping`. Bound line/event/aggregate bytes before growth. Reject invalid order, malformed JSON/UTF-8, unknown required content, conflicting IDs, duplicate stop, premature EOF, missing text, usage regression, HTTP errors, timeout, overload, malformed retry-after, cancellation races, worker panic, and shutdown join failure.

Map exactly one terminal protocol result after durable sink acceptance. Deltas remain presentation-only.

- [ ] **Step 3 - Pass the shared protocol conformance suite**

Use deterministic loopback HTTP/SSE fixtures and the same start/cancel/terminal harness as OpenAI. No live key, DNS, internet, or billable call is allowed.

```powershell
cargo test -p local-agent-terminal-provider-anthropic
```

- [ ] **Step 4 - Refactor bootstrap composition for multiple trusted peers**

Replace single descriptor/connection fields with maps keyed by bound agent ID. Compose zero, one, or both provider configs into one `ProtocolAgentRuntime` peer vector. `prepare_run` resolves and verifies the requested binding without provider-name branching. Reconcile every descriptor/connection, publish exact manifest/run config, share durable artifacts, isolate failures, and serialize shutdown.

Keep explicit `OpenAiBootstrapConfig` compatibility and add `AnthropicBootstrapConfig`. Startup may operate with one provider, but orchestration reports heterogeneous quorum unavailable until two eligible families exist.

Compose the context engine and deliberation coordinator in their own bootstrap
modules. Those modules adapt the existing SQLite/event/artifact/policy/repository
instances to application ports; they must not move orchestration policy back
into the composition root.

- [ ] **Step 5 - Verify credential isolation, recovery, and commit**

```powershell
cargo fmt --all -- --check
cargo test -p local-agent-terminal-provider-openai
cargo test -p local-agent-terminal-provider-anthropic
cargo test -p local-agent-terminal-bootstrap --test agent_runtime_e2e --test agent_recovery --test startup
node scripts/check-architecture.mjs
git add Cargo.toml Cargo.lock crates/provider-anthropic crates/bootstrap .superpowers/sdd/progress.md
git diff --cached --check
git commit -m "feat: add anthropic core adapter"
```

## Task 9: Expose typed deliberation controls and accessible desktop views

Before editing React, read and apply `vercel-react-best-practices`. Keep state local to the view unless shared ownership is demonstrated.

**Files:**

- Modify: `apps/desktop/src-tauri/Cargo.toml`
- Modify: `apps/desktop/src-tauri/src/lib.rs`
- Create: `apps/desktop/src/api/deliberation.ts`
- Create: `apps/desktop/src/api/deliberation.test.ts`
- Create: `apps/desktop/src/features/deliberation/deliberation-model.ts`
- Create: `apps/desktop/src/features/deliberation/DeliberationScreen.tsx`
- Create: `apps/desktop/src/features/deliberation/ContextInspector.tsx`
- Create: `apps/desktop/src/features/deliberation/PlanApprovalPanel.tsx`
- Create: `apps/desktop/src/features/deliberation/DeliberationScreen.test.tsx`
- Create: `apps/desktop/src/features/deliberation/ContextInspector.test.tsx`
- Create: `apps/desktop/src/features/deliberation/PlanApprovalPanel.test.tsx`
- Create: `apps/desktop/tests/browser/deliberation.spec.ts`
- Modify: `apps/desktop/src/App.tsx`
- Modify: `apps/desktop/src/styles/base.css`
- Modify: `apps/desktop/src/styles/tokens.css` only if a focused contrast test requires it

**Typed outer commands:**

```text
get_deliberation_workspace(taskId)
get_context_package(packageId)
resolve_plan_approval(approvalId, displayedDigest, expectedTaskVersion, action)
```

- [ ] **Step 1 - Write failing Tauri/API boundary tests**

React sends only opaque IDs, displayed digest, expected task version, and an allowlisted action enum. Reject raw plan/provider/policy/path/event/tool/workflow payloads, generic command names, invoke outside `src/api`, stale task version, and cross-task IDs. Tauri maps bootstrap/application DTOs without database handles or provider types.

- [ ] **Step 2 - Write failing component tests**

Render workflow rail, agent roster, proposal/review/evidence/objection/decision cards, bounded thread, exact Context Inspector redactions/provenance/policy IDs, and Plan Approval selected/rejected alternatives, agreement, dissent, files, tools, security, cost/duration, versions, and digest.

Use one primary Approve action and plainly labeled Revise, Reopen, Add/replace agent, and Reject actions. Test loading, success, empty, blocked, unavailable, rejected, stale evidence, redacted, expired, digest-changed, and recoverable error states.

- [ ] **Step 3 - Write failing accessibility/browser tests**

Cover full keyboard order, skip link, visible focus, dialog focus trap/restore, live-region phase/approval feedback, non-color labels, no hover-only information, 44px targets where applicable, reduced motion, 4.5:1 text contrast, 200% zoom/reflow at 1280x720, narrow viewport, stale approval invalidation, and axe with zero serious/critical violations.

```powershell
pnpm --dir apps/desktop test --run
pnpm --dir apps/desktop test:browser -- deliberation.spec.ts
```

- [ ] **Step 4 - Implement minimum typed UI and commands**

Extend the existing view navigation without rewriting workspace/tool screens. Reuse existing styles/tokens and semantic components. Do not add speculative routing/state libraries.

- [ ] **Step 5 - Verify frontend, Tauri, architecture, and commit**

```powershell
pnpm --dir apps/desktop test --run
pnpm --dir apps/desktop build
pnpm --dir apps/desktop test:browser
cargo test -p local-agent-terminal-desktop
cargo build -p local-agent-terminal-desktop
node scripts/check-architecture.mjs
git add apps/desktop .superpowers/sdd/progress.md
git diff --cached --check
git commit -m "feat: add deliberation approval workspace"
```

## Task 10: Prove M4 end-to-end behavior, review, and record evidence

**Files:**

- Create: `crates/bootstrap/tests/deliberation_e2e.rs`
- Create: `crates/bootstrap/tests/deliberation_recovery.rs`
- Create: `scripts/m4-evidence-spec.mjs`
- Create: `scripts/run-m4-evidence.mjs`
- Create: `scripts/verify-m4-evidence.mjs`
- Create: `tests/contracts/m4-evidence-contracts.test.mjs`
- Create: `artifacts/verification/m4/review.md`
- Create: `artifacts/verification/m4/known-limitations.md`
- Generate: `artifacts/verification/m4/manifest.json`
- Generate: `artifacts/verification/m4/outputs/*.log`
- Modify: `.superpowers/sdd/progress.md`
- Modify: `docs/superpowers/plans/2026-07-23-m4-context-deliberation.md`

- [ ] **Step 1 - Write failing bootstrap E2E and recovery tests**

Compose real SQLite/content-addressed artifacts, read-only libgit2 source capture, policy engine, context engine, orchestration, agent runtime, deterministic OpenAI/Anthropic loopback fixtures, and typed approvals.

Prove:

1. metadata/content secrets are blocked before index writes;
2. two role-specific packages have exact policy/redaction/provenance bindings;
3. OpenAI and Anthropic proposals are hidden until heterogeneous quorum;
4. controlled cross-review and a bounded specialist request complete;
5. stale evidence is rejected and every material claim is classified;
6. synthesis preserves selected/rejected approaches, evidence, and dissent;
7. a severe objection reopens one bounded round;
8. stale/replayed approval fails and exact approval reaches `Implementation`;
9. provider failure remains isolated and restart reconstructs durable state;
10. pre/post repository HEAD, refs, index, tracked/untracked bytes, modes, and worktree list are identical before exact approval.

- [ ] **Step 2 - Write failing evidence contracts**

Require a source-commit-bound manifest, pinned tool versions, hashes for every retained output, zero skipped approval-critical tests, immutable design proof, complete M0–M3 regressions, context security matrix, retrieval/freshness matrix, two-provider conformance, deliberation/recovery matrix, UI/browser accessibility, exact plan approval, repository no-mutation proof, credential canary absence, and independent final review with no unresolved Critical/Important finding.

- [ ] **Step 3 - Run the complete M4 gate**

```powershell
node --test tests/contracts/*.test.mjs
node scripts/verify-design-contracts.mjs
node scripts/check-architecture.mjs --require-m4
cargo fmt --all -- --check
cargo check --workspace --all-targets
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-targets
cargo test --workspace --all-features
cargo test --workspace --doc
pnpm --dir apps/desktop test --run
pnpm --dir apps/desktop build
pnpm --dir apps/desktop test:browser
cargo build -p local-agent-terminal-desktop
git diff --exit-code 9b182a3 -- docs/multi-agent-terminal-design
node scripts/run-m4-evidence.mjs
node scripts/verify-m4-evidence.mjs
```

- [ ] **Step 4 - Request and resolve fresh final review**

Use `superpowers:requesting-code-review` on the complete baseline-to-HEAD diff. Review specifically for pre-index leakage, path/metadata leakage, stale citation acceptance, package non-reconstructibility, proposal visibility races, fake heterogeneity, provider-name orchestration, unbounded specialist/round budgets, direct model transitions, lost dissent, approval TOCTOU/replay, pre-approval writes, provider credential/DTO leakage, SSE allocation/order bugs, crash retry duplication, UI payload substitution, stale approval display, and incomplete evidence.

Fix every Critical/Important finding using TDD and rerun the affected focused and complete gates. Record reviewer identity, inspected commit range, findings, resolutions, and final disposition in `artifacts/verification/m4/review.md` and `.superpowers/sdd/progress.md`.

- [ ] **Step 5 - Bind final evidence and close checkboxes**

Bind the evidence manifest to the reviewed implementation source commit. Mark each plan checkbox `[x]` only when its exact command/evidence is green. Leave deferred or failed work unchecked and list it in known limitations; do not describe an unchecked exit criterion as complete.

- [ ] **Step 6 - Commit evidence and verify clean branch**

```powershell
git add docs/superpowers/plans/2026-07-23-m4-context-deliberation.md .superpowers/sdd/progress.md scripts tests/contracts crates/bootstrap/tests artifacts/verification/m4
git diff --cached --check
git commit -m "test: record approved m4 evidence"
node scripts/verify-m4-evidence.mjs --require-approved
git status --short
```

## M4 Exit Criteria

1. Secret or denied metadata/content cannot enter any index, cache, package, provider request, log, DTO, or evidence output.
2. Keyword/metadata retrieval is deterministic, rebuildable, policy-filtered, and excludes stale source by exact revision/hash.
3. Every context package is role-specific, immutable, reconstructible, final-scan-approved, and linked to every item-level policy decision and redaction/provenance record.
4. OpenAI and Anthropic deterministic fixtures produce hidden independent proposals from different recorded family keys before quorum publication.
5. Cross-review edges, specialist requests, threads, agents, rounds, tokens, cost, and deadlines remain bounded and durably auditable.
6. Every material claim has a terminal verification class; stale citations cannot be verified; confidence cannot change trusted state.
7. Synthesis preserves selected approach, rejected alternatives, verified/inconclusive evidence, remaining dissent, steps/files/tools/tests/rollback/risk/cost/confidence.
8. A credible severe objection reopens a bounded review round; objection and superseded decision history remain immutable.
9. Plan approval is valid only for exact plan/base/policy/scope/tools/verification/actor/expiry/task-version inputs and is invalidated on any canonical change.
10. No repository-visible state, worktree, branch, ref, index, file, hook, or writer lease changes before exact plan approval.
11. Anthropic passes provider-neutral conformance, bounded SSE, cancellation, outage, recovery, and credential-nondisclosure tests without a live call.
12. Provider outage/malformed output cannot corrupt another run, deliberation state, artifacts, or workflow projection.
13. Typed Tauri/React views expose exact safe core DTOs, reject payload substitution, make redaction/staleness/dissent visible, and pass accessibility/browser gates.
14. All M0–M3 regressions, full Rust/frontend/browser/Tauri gates, immutable design proof, fresh final review, and approved M4 evidence verification pass.

## Deliberate M4 Deferrals

- Vector embeddings, semantic retrieval, repository graph, incremental vector invalidation, and verified project memory remain M6.
- Fenced write execution, task worktree creation, candidate Git tree, verification/repair loop, final commit approval, and exact-tree local commit remain M5.
- `brokered_process` and `isolated_worker` agent integrations remain disabled; M4's second provider is a signed built-in `core_adapter`.
- Live Anthropic/OpenAI smoke tests require explicit user-supplied credentials, network authorization, and cost authorization; deterministic loopback conformance is mandatory.
- Provider credential storage/UI, installer, update signing, and broad production hardening remain later operations/release work.
