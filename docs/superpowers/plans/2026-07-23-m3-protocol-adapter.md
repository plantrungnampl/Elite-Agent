# M3 Protocol and First Trusted Adapter Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Deliver the provider-agnostic Open Agent Protocol v1, a durable run runtime with deterministic conformance agents, and one built-in OpenAI Responses API `core_adapter` whose failures, cancellation, streaming, and terminal results cannot bypass protocol limits or corrupt workflow state.

**Architecture:** Keep JSON-RPC/schema and provider DTOs outside the inner circles. `domain` owns only pure agent/run/message invariants. `application` owns `AgentRuntime` and durable agent-state ports expressed in provider-neutral DTOs. `agent-protocol` imports types from the normative JSON Schema and owns NDJSON/session validation. `agent-runtime` implements the application runtime using a protocol peer and durable store. `provider-openai` translates the provider-neutral protocol request to and from the OpenAI Responses API. `storage-sqlite` persists descriptors, context bindings, runs, messages, usage, and terminal state. `bootstrap` is the only composition root.

**Tech Stack:** Rust 1.97 MSVC, Cargo workspace, serde/serde_json, `typify` 0.7 for compile-time JSON-Schema type generation, existing RFC 8785/SHA-256 utilities, SQLite/rusqlite, `reqwest` blocking client with rustls and no default features, stdlib SSE/NDJSON parsing and cancellation primitives, Node `node:test` architecture/evidence contracts, and deterministic local HTTP fixtures. No live provider call is required for the release gate.

## Global Constraints

- Implement every task in `D:\multiagent` on the existing `codex/product-build-root` branch. Do not create or use a developer Git worktree. Disposable databases and loopback HTTP servers are allowed only as inert test fixtures.
- `docs/multi-agent-terminal-design/**` is immutable. The normative sources are `03-agent-protocol.md`, `schemas/agent-protocol.v1.schema.json`, the agent/context/run/message tables in `schemas/sqlite-v1.sql`, M3 in `11-mvp-roadmap.md`, provider/recovery cases in `09-testing-reliability.md` and `15-crash-consistency-recovery.md`, `13-trust-sandbox-model.md`, ADR-005/015/018, and the adapter decision in `17-review-resolution-matrix.md`.
- Stay inside M3. Do not add M4 context retrieval/deliberation, M5 repository execution/finalization, marketplace discovery, a second provider, WebSocket transport, or an externally launched agent. `brokered_process` and `isolated_worker` descriptors remain disabled unless their existing containment contract is satisfied.
- The first trusted adapter is OpenAI Responses API as an in-process `core_adapter`. The model identifier is mandatory run configuration; there is no hard-coded or silently upgraded default. Provider DTOs and HTTP/SSE behavior remain confined to `provider-openai`.
- Follow the current official OpenAI Responses API and streaming guide at implementation time. Use `POST /v1/responses`, `stream: true`, semantic SSE events, and handle at least `response.output_text.delta`, `response.completed`, `response.failed`, `response.incomplete`, and `error`. Do not send hosted tools or grant repository access in M3.
- Provider credentials are explicit bootstrap input, never source, fixture, artifact, log, `Debug`, serialized run configuration, inherited child environment, or default environment lookup. Tests use a canary credential and a loopback server and assert the canary is absent from durable and diagnostic output.
- Every request has a connection-unique string ID with the required `core:`/`agent:` origin. Notifications receive no response. A terminal success/error response is emitted only after its corresponding durable state change succeeds.
- One NDJSON frame is one UTF-8 line. Enforce the negotiated frame maximum before allocation/parse where possible; default to 8 MiB. Reject malformed UTF-8/JSON, invalid schema frames, duplicate request IDs, wrong ownership, sequence gaps/conflicts, duplicate terminals, heartbeat regressions, and messages for another bound run/connection.
- Stream sequence begins at one. Exact byte-identical duplicate deltas are ignored. A conflicting duplicate or gap fails the affected run. Deltas are presentation-only and never evidence or the authoritative terminal result.
- Enforce deadline, output-byte/token, tool-request, heartbeat, and cancellation limits. Reaching a limit cancels/fails the run; never truncate an unknown suffix and then accept a terminal result.
- Bind descriptor ID, trust tier, manifest digest, executable/core-release digest, connection ID, protocol version, adapter version, provider/model ID, generation parameters, prompt/response schema versions, policy snapshot, run-config artifact, and exact effective-context artifact/digest before dispatch. Retrying creates a new run with `supersedes_run_id`.
- Unexpected adapter loss marks every active run on that connection `interrupted`. A provider outage may update only agent-run/message audit state; it must not advance or rewrite the task workflow projection.
- Handwritten behavior is test-first. Each task begins with a focused failing test, implements the smallest code that passes, runs focused/regression gates, updates its checkboxes immediately, and creates one reviewable Conventional Commit.

---

## Task 1: Pin executable M3 contracts and crate boundaries

**Files:**

- Create: `tests/contracts/m3-contracts.test.mjs`
- Create: `tests/contracts/fixtures/m3/agent-protocol-outward-metadata.json`
- Create: `tests/contracts/fixtures/m3/agent-runtime-outward-metadata.json`
- Create: `tests/contracts/fixtures/m3/provider-openai-outward-metadata.json`
- Create: `tests/contracts/fixtures/m3/duplicate-request-id.ndjson`
- Create: `tests/contracts/fixtures/m3/oversize-frame.ndjson`
- Modify: `scripts/check-architecture.mjs`
- Modify: `tests/contracts/architecture.test.mjs`
- Verify only: `docs/multi-agent-terminal-design/schemas/agent-protocol.v1.schema.json`

**Dependency contract:**

```text
domain <- application
application + domain <- storage-sqlite
application + domain + agent-protocol <- agent-runtime
agent-protocol <- provider-openai
application + agent-runtime + provider-openai + storage adapters <- bootstrap
```

- [x] **Step 1 - Write failing contract tests**

Assert that a synthetic final workspace contains the three new crates; `agent-protocol` has no internal dependency; `provider-openai` depends only on `agent-protocol` internally; `agent-runtime` depends inward on `application`, `domain`, and `agent-protocol`; only `bootstrap` constructs runtime/provider concrete types; provider names do not occur in `domain`, `application`, or orchestration policy; and direct provider HTTP/credential access is confined to `provider-openai`. During Tasks 2, 6, and 7, the real workspace may contain zero or a partial subset of the three crates; whenever a named M3 crate is present, its exact internal allowlist applies. Task 9 requires all three actual workspace members.

Also assert that the normative schema still has all fourteen frame variants, string request IDs with origin prefixes, strict top-level payloads, the 8 MiB documented default, and the M3 hostile fixtures are rejected by the future conformance binary.

```powershell
node --test tests/contracts/m3-contracts.test.mjs
```

Expected RED: M3 allowlists, crates, fixtures, and source guards do not exist.

- [x] **Step 2 - Implement only contract checker rules and fixtures**

Remove the temporary M2 assertion that all M3 packages are absent and replace it with the exact M3 allowlist above. Retain all M0-M2 restrictions. Reject `std::env` credential lookup, `Authorization` logging, provider construction outside bootstrap, raw TCP/TLS in inner crates, provider-name branching in application policy, and external process launch from the new crates.

- [x] **Step 3 - Verify contracts and immutable design**

```powershell
node --test tests/contracts/m3-contracts.test.mjs tests/contracts/architecture.test.mjs tests/contracts/design-contracts.test.mjs tests/contracts/m2-contracts.test.mjs
node scripts/check-architecture.mjs
git diff --exit-code 321734f -- docs/multi-agent-terminal-design
```

- [x] **Step 4 - Commit**

```powershell
git add scripts/check-architecture.mjs tests/contracts
git diff --cached --check
git commit -m "test: pin agent protocol contracts"
```

## Task 2: Generate protocol v1 types and implement the bounded NDJSON codec

**Files:**

- Modify: `Cargo.toml`
- Create: `crates/agent-protocol/Cargo.toml`
- Create: `crates/agent-protocol/src/lib.rs`
- Create: `crates/agent-protocol/src/generated.rs`
- Create: `crates/agent-protocol/src/codec.rs`
- Create: `crates/agent-protocol/src/error.rs`
- Create: `crates/agent-protocol/tests/schema_types.rs`
- Create: `crates/agent-protocol/tests/codec.rs`

**Interfaces:**

```rust
pub const DEFAULT_MAX_FRAME_BYTES: usize = 8 * 1024 * 1024;

pub struct NdjsonCodec {
    max_frame_bytes: usize,
}

impl NdjsonCodec {
    pub fn decode(&self, line: &[u8]) -> Result<ProtocolFrame, ProtocolError>;
    pub fn encode(&self, frame: &ProtocolFrame) -> Result<Vec<u8>, ProtocolError>;
}
```

`ProtocolFrame` is the `typify::import_types!` result from `../../docs/multi-agent-terminal-design/schemas/agent-protocol.v1.schema.json`, re-exported behind stable local aliases where generated names are awkward. The normative schema remains the single source; do not copy or edit it.

- [x] **Step 1 - Write failing schema/codec tests**

Load every normative example and round-trip it. Reject missing/number request IDs, unknown required structure, request IDs over 128 bytes, invalid origin prefixes, malformed UTF-8/JSON, empty/multiple frames, embedded raw newline, and exact/one-byte-over configured limits. Assert encoding always returns exactly one LF-terminated UTF-8 object and never logs frame content on error.

```powershell
cargo test -p local-agent-terminal-agent-protocol --test schema_types --test codec
```

- [x] **Step 2 - Add generated types and minimum codec**

Use `typify = "0.7"`, `serde`, and `serde_json`; do not add a second JSON Schema validator. Check byte bounds before deserialization, rely on generated schema constraints for payload shape, and perform only protocol-specific checks not expressible by generated serde types.

- [x] **Step 3 - Verify and commit**

```powershell
cargo fmt --all -- --check
cargo test -p local-agent-terminal-agent-protocol
node scripts/check-architecture.mjs
git diff --check
git add Cargo.toml Cargo.lock crates/agent-protocol
git commit -m "feat: add bounded agent protocol codec"
```

## Task 3: Enforce connection, request, stream, heartbeat, and terminal invariants

**Files:**

- Create: `crates/agent-protocol/src/session.rs`
- Create: `crates/agent-protocol/src/peer.rs`
- Modify: `crates/agent-protocol/src/lib.rs`
- Create: `crates/agent-protocol/tests/session_contract.rs`
- Create: `crates/agent-protocol/tests/conformance.rs`

**Interfaces:**

```rust
pub struct ConnectionBinding {
    pub connection_id: String,
    pub agent_id: String,
    pub manifest_digest: String,
    pub executable_digest: String,
    pub trust_tier: ProtocolTrustTier,
}

pub enum InboundDisposition {
    Request(ProtocolFrame),
    Notification(ProtocolFrame),
    DuplicateStreamDelta,
}

pub trait ProtocolPeer: Send + Sync {
    fn descriptor(&self) -> PeerDescriptor;
    fn start(&self, request: RunStart, sink: Box<dyn PeerEventSink>)
        -> Result<RunAcceptance, ProtocolError>;
    fn cancel(&self, request: RunCancel) -> Result<CancelAcceptance, ProtocolError>;
    fn shutdown(&self) -> Result<(), ProtocolError>;
}
```

- [x] **Step 1 - Write failing state-machine tests**

Cover offered/selected protocol mismatch, capability escalation, binding mismatch, reused request ID, response without pending request, response origin mismatch, notification response attempts, foreign run IDs, stream start other than one, gaps, exact duplicates, conflicting duplicates, output-byte overflow, tool-request overflow, heartbeat sequence regression/timeout, complete-before-start, duplicate/conflicting terminal, post-terminal frames, cancellation deadline, and connection loss.

- [x] **Step 2 - Implement one explicit session state machine**

Keep one `HashSet` for seen request IDs, one bounded per-run stream record with only the last sequence/delta bytes, one terminal flag, and monotonic heartbeat state. Do not retain complete streams in the protocol layer. Return typed categories matching section 13 of the protocol design.

- [x] **Step 3 - Build reusable conformance cases**

Export a data-driven `run_conformance(peer)` harness covering happy start/stream/complete plus malicious, slow, cancelled, crashed, malformed, oversize, sequence-gap, and duplicate-terminal cases. The harness is reused by fake agents and OpenAI adapter tests.

- [x] **Step 4 - Verify and commit**

```powershell
cargo test -p local-agent-terminal-agent-protocol --test session_contract --test conformance
cargo clippy -p local-agent-terminal-agent-protocol --all-targets -- -D warnings
git add crates/agent-protocol
git commit -m "feat: enforce agent protocol sessions"
```

## Task 4: Add pure agent lifecycle types and application-owned runtime ports

**Files:**

- Create: `crates/domain/src/agent.rs`
- Modify: `crates/domain/src/lib.rs`
- Create: `crates/domain/tests/agent_contract.rs`
- Create: `crates/application/src/agent.rs`
- Modify: `crates/application/src/lib.rs`
- Create: `crates/application/tests/agent_ports.rs`

**Interfaces:**

```rust
pub enum AgentRunStatus {
    Created,
    Accepted,
    Running,
    Succeeded,
    Failed,
    CancelledCleanly,
    Terminated,
    Interrupted,
    Indeterminate,
}

pub struct BoundAgentRunRequest {
    pub run_id: RunId,
    pub task_id: TaskId,
    pub agent_id: String,
    pub role: String,
    pub phase: String,
    pub idempotency_key: String,
    pub context: BoundEffectiveContext,
    pub run_config: BoundRunConfig,
    pub connection: BoundAgentConnection,
    pub supersedes_run_id: Option<RunId>,
}

pub trait AgentRuntime: Send + Sync {
    fn list_agents(&self) -> Result<Vec<AgentDescriptor>, PortError>;
    fn start_run(&self, request: BoundAgentRunRequest) -> Result<AgentRunReceipt, PortError>;
    fn cancel(&self, request: CancelAgentRun) -> Result<AgentCancellationReceipt, PortError>;
}

pub trait AgentRunStore: Send + Sync {
    fn register_descriptor(&self, descriptor: &AgentDescriptor) -> Result<(), PortError>;
    fn create_bound_run(&self, request: &BoundAgentRunRequest) -> Result<AgentRunSnapshot, PortError>;
    fn accept_run(&self, run_id: &RunId, accepted_at: &str) -> Result<(), PortError>;
    fn mark_running(&self, run_id: &RunId, started_at: &str) -> Result<(), PortError>;
    fn persist_terminal(&self, terminal: &AgentRunTerminal) -> Result<(), PortError>;
    fn interrupt_connection(&self, connection_digest: &str, at: &str) -> Result<Vec<RunId>, PortError>;
    fn load_run(&self, run_id: &RunId) -> Result<Option<AgentRunSnapshot>, PortError>;
}
```

- [x] **Step 1 - Write failing domain and port tests**

Reject invalid status transitions, empty/oversized IDs/text, malformed digests, a core adapter without an executable/core-release digest, enabled legacy agents, mismatched task/context/artifact bindings, same-run supersession, unbounded generation parameters, terminal message/run mismatch, evidence line inversion, negative usage, and terminal persistence without authoritative receipt time.

- [x] **Step 2 - Implement minimal pure values and object-safe ports**

Reuse `RunId`, `TaskId`, `ArtifactId`, `Sha256Digest`, `Timestamp`, `TrustTier`, `PortError`, and existing artifact ports. Keep provider/model as opaque validated strings. Store generation parameters as bounded canonical JSON bytes plus digest; no OpenAI DTO crosses inward.

- [x] **Step 3 - Verify dependency direction and commit**

```powershell
cargo test -p local-agent-terminal-domain --test agent_contract
cargo test -p local-agent-terminal-application --test agent_ports
node scripts/check-architecture.mjs
git add crates/domain crates/application
git commit -m "feat: add durable agent runtime ports"
```

## Task 5: Persist reconstructible agent descriptors, contexts, runs, and terminals

**Files:**

- Create: `crates/storage-sqlite/src/agent_store.rs`
- Modify: `crates/storage-sqlite/src/lib.rs`
- Create: `crates/storage-sqlite/tests/agent_store.rs`
- Modify only if an executable mismatch is proven: `crates/storage-sqlite/src/migrations.rs`

**Transaction contract:**

```text
register descriptor -> verify canonical manifest digest and trust containment
create run -> verify task + descriptor + context artifacts + run-config artifact -> insert created
terminal -> insert authoritative message + update run terminal + usage/error in one SQLite transaction
acknowledge agent only after terminal transaction commit
```

- [ ] **Step 1 - Write failing persistence tests**

Cover idempotent descriptor registration with exact-byte equality; manifest/executable drift conflict; missing/foreign context and run-config artifacts; duplicate idempotency key; valid supersession; forward-only status; exact message/run binding; separate provider/core usage; duplicate terminal rollback; forced SQLite failure before acknowledgement; active-run interruption by connection digest; startup reopen; and provider outage leaving task sequence/workflow projection unchanged.

- [ ] **Step 2 - Implement `AgentRunStore` with existing schema**

Use the existing `agent_descriptors`, `context_packages`, `agent_runs`, and `messages` tables. Do not add a migration unless a test proves the approved schema cannot represent a required field. Persist the canonical run-config artifact before `create_bound_run`; compare every referenced artifact's task, availability, content hash, and kind.

- [ ] **Step 3 - Verify and commit**

```powershell
cargo test -p local-agent-terminal-storage-sqlite --test agent_store
cargo test -p local-agent-terminal-storage-sqlite
git add crates/storage-sqlite
git commit -m "feat: persist bound agent runs"
```

## Task 6: Implement the runtime and deterministic conformance agents

**Files:**

- Modify: `Cargo.toml`
- Create: `crates/agent-runtime/Cargo.toml`
- Create: `crates/agent-runtime/src/lib.rs`
- Create: `crates/agent-runtime/src/runtime.rs`
- Create: `crates/agent-runtime/src/fakes.rs`
- Create: `crates/agent-runtime/tests/runtime_contract.rs`
- Create: `crates/agent-runtime/tests/fake_conformance.rs`

**Runtime contract:**

```rust
pub struct ProtocolAgentRuntime {
    store: Arc<dyn AgentRunStore>,
    clock: Arc<dyn Clock>,
    peers: BTreeMap<String, Arc<dyn ProtocolPeer>>,
}
```

`start_run` validates descriptor/connection/context/config, durably creates the run, asks the peer to accept promptly, marks accepted/running, and returns. Peer events arrive through a sink that validates session state and persists a terminal before returning terminal acknowledgement. Runtime-owned worker handles are joined on shutdown; no detached task owns authoritative state.

- [ ] **Step 1 - Write failing runtime tests**

Prove prompt acceptance, one result per request ID, terminal persistence before ack, exact stream deduplication, limit-triggered cancel, cooperative cancellation, deadline termination classification, heartbeat timeout, crash-to-interrupted, retry with new run/supersedes, shutdown interruption, and no workflow projection mutation on every peer failure.

- [ ] **Step 2 - Implement five deterministic roles plus hostile modes**

Provide proposer, critic, verifier, malicious, slow, and crashing peers as one small scripted peer with an enum script rather than six implementations. Each output is deterministic from the request IDs/context digest. The malicious script covers malformed frame, wrong connection/run, duplicate/conflicting terminal, sequence gap, and oversize output.

- [ ] **Step 3 - Run shared conformance against all scripts**

```powershell
cargo test -p local-agent-terminal-agent-runtime --test runtime_contract --test fake_conformance
cargo test -p local-agent-terminal-agent-protocol --test conformance
```

- [ ] **Step 4 - Commit**

```powershell
git add Cargo.toml Cargo.lock crates/agent-runtime
git commit -m "feat: add conformant agent runtime"
```

## Task 7: Add the OpenAI Responses API core adapter

**Files:**

- Modify: `Cargo.toml`
- Create: `crates/provider-openai/Cargo.toml`
- Create: `crates/provider-openai/src/lib.rs`
- Create: `crates/provider-openai/src/config.rs`
- Create: `crates/provider-openai/src/request.rs`
- Create: `crates/provider-openai/src/sse.rs`
- Create: `crates/provider-openai/src/adapter.rs`
- Create: `crates/provider-openai/tests/request_contract.rs`
- Create: `crates/provider-openai/tests/streaming_contract.rs`
- Create: `crates/provider-openai/tests/conformance.rs`

**Provider boundary:**

```rust
pub struct OpenAiProviderConfig {
    endpoint: Url,
    api_key: OpenAiApiKey,
    connect_timeout: Duration,
    read_timeout: Duration,
}

pub struct OpenAiResponsesAdapter { /* reqwest blocking client + active cancellations */ }
```

The adapter implements `ProtocolPeer`. It accepts provider-neutral run input, posts `model`, `input`, `stream: true`, `store: false`, and the bound output limit, then translates provider semantic events into protocol deltas and one terminal. It does not expose the API key through `Debug` or serialization and does not provide hosted tools.

- [ ] **Step 1 - Write failing request and secret-boundary tests**

Use a loopback `TcpListener` fixture to capture the request. Assert exact endpoint/method/headers/body; required caller-supplied model; `stream: true`; `store: false`; no hosted tools; bounded prompt and output; authorization canary present only on the wire; and canary absent from all errors, `Debug`, artifacts, run config, and captured sanitized diagnostics. Reject non-HTTPS production endpoints; allow HTTP only through a test-only constructor scoped to loopback.

- [ ] **Step 2 - Write failing SSE/lifecycle tests**

Cover chunk boundaries across lines, CRLF, comments, multiple `data:` lines, output deltas, completed usage, failed/incomplete/error events, invalid JSON, oversized event, premature EOF, 401/429/5xx classification, `Retry-After`, timeout, user cancellation, response ID capture, and refusal/no-text terminal behavior.

- [ ] **Step 3 - Implement with existing/std dependencies only where possible**

Use `reqwest` blocking + rustls for HTTP/TLS and `BufRead` for SSE; do not add an EventSource/SSE crate or OpenAI SDK. Maintain one cancellation flag per active run and remove it at terminal. Map provider sequence numbers to protocol sequence, but let protocol session validation remain authoritative.

- [ ] **Step 4 - Run shared conformance and commit**

```powershell
cargo test -p local-agent-terminal-provider-openai
cargo test -p local-agent-terminal-provider-openai --test conformance
cargo clippy -p local-agent-terminal-provider-openai --all-targets -- -D warnings
git add Cargo.toml Cargo.lock crates/provider-openai
git commit -m "feat: add OpenAI responses adapter"
```

## Task 8: Compose the trusted adapter and prove crash-safe end-to-end behavior

**Files:**

- Modify: `crates/bootstrap/Cargo.toml`
- Create: `crates/bootstrap/src/agent_runtime.rs`
- Modify: `crates/bootstrap/src/startup.rs`
- Modify: `crates/bootstrap/src/lib.rs`
- Create: `crates/bootstrap/tests/agent_runtime_e2e.rs`
- Create: `crates/bootstrap/tests/agent_recovery.rs`

**Composition contract:**

```rust
pub struct OpenAiBootstrapConfig {
    pub endpoint: String,
    pub api_key: OpenAiApiKey,
    pub manifest_digest: Sha256Digest,
    pub core_release_digest: Sha256Digest,
    pub adapter_version: String,
}

pub struct StartupConfig {
    // existing fields unchanged
    pub openai: Option<OpenAiBootstrapConfig>,
}
```

If no explicit provider config is supplied, startup succeeds with no OpenAI agent registered. If supplied, bootstrap constructs the concrete adapter/runtime, registers one disabled-until-bound or enabled `core_adapter` descriptor as appropriate, and exposes the provider-neutral `Arc<dyn AgentRuntime>` to later orchestration. It never reads `OPENAI_API_KEY` itself.

- [ ] **Step 1 - Write failing bootstrap tests**

Prove optional configuration, exact descriptor/manifest/core-release binding, deterministic fake-provider run, real OpenAI adapter against loopback SSE, immediate start receipt, stream/terminal storage, cancellation, provider outage, process/app restart interruption, and exact reconstruction of effective context plus run config after reopening SQLite. Assert task workflow state/sequence is unchanged by every provider failure.

- [ ] **Step 2 - Implement bootstrap-only construction**

Reuse the existing SQLite and content-addressed artifact instances. Canonicalize and publish effective context and run configuration before dispatch. Store only provider ID/model/generation parameters and digests; never the API key or endpoint credentials.

- [ ] **Step 3 - Verify and commit**

```powershell
cargo test -p local-agent-terminal-bootstrap --test agent_runtime_e2e --test agent_recovery
cargo test -p local-agent-terminal-bootstrap
node scripts/check-architecture.mjs
git add crates/bootstrap
git commit -m "feat: compose trusted agent adapter"
```

## Task 9: Run the M3 evidence gate and close the plan

**Files:**

- Create: `scripts/m3-evidence-spec.mjs`
- Create: `scripts/run-m3-evidence.mjs`
- Create: `scripts/verify-m3-evidence.mjs`
- Create: `tests/contracts/m3-evidence-contracts.test.mjs`
- Create: `artifacts/verification/m3/review.md`
- Create: `artifacts/verification/m3/known-limitations.md`
- Generate: `artifacts/verification/m3/manifest.json`
- Generate: `artifacts/verification/m3/outputs/*.log`
- Modify: `docs/superpowers/plans/2026-07-23-m3-protocol-adapter.md`

- [ ] **Step 1 - Write failing evidence contracts**

Require a source-commit-bound manifest, tool versions, hashes for every retained output, no skipped approval-critical test, immutable design proof, full Rust/Node/frontend regressions, protocol/schema/conformance matrices, fake-agent matrix, OpenAI loopback matrix, persistence/recovery tests, and an explicit credential canary absence check.

- [ ] **Step 2 - Run the complete M3 gate**

```powershell
node --test tests/contracts/*.test.mjs
node scripts/verify-design-contracts.mjs
node scripts/check-architecture.mjs --require-m3
cargo fmt --all -- --check
cargo check --workspace --all-targets
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-targets
cargo test --workspace --all-features
cargo test --workspace --doc
pnpm --dir apps/desktop test --run
pnpm --dir apps/desktop build
cargo build -p local-agent-terminal-desktop
git diff --exit-code 321734f -- docs/multi-agent-terminal-design
node scripts/run-m3-evidence.mjs
node scripts/verify-m3-evidence.mjs
```

- [ ] **Step 3 - Perform final M3 review**

Review baseline-to-HEAD for Critical/Important findings, specifically malformed/oversize allocation, request-ID confusion, response-to-notification, capability escalation, binding substitution, stream gap/conflict, double terminal, terminal-before-persist, unsafe retry/resume, credential disclosure, provider DTO leakage, provider-name orchestration, cancellation races, detached workers, SQLite partial commit, outage workflow mutation, and stale/non-reconstructible context or run config. Fix and rerun evidence until none remain.

- [ ] **Step 4 - Mark every completed step and commit evidence**

Update `[ ]` to `[x]` immediately for every genuinely completed step. Do not mark deferred/failed steps. Bind final evidence to the implementation source commit, run post-final verification, then commit only plan/evidence files.

```powershell
git add docs/superpowers/plans/2026-07-23-m3-protocol-adapter.md scripts tests/contracts artifacts/verification/m3
git diff --cached --check
git commit -m "test: record approved m3 evidence"
git status --short
```

## M3 Exit Criteria

1. Every request has a unique origin-prefixed string ID and exactly one response; notifications receive none.
2. Schema-invalid, malformed, oversized, wrong-owner, binding-mismatched, sequence-gap/conflict, heartbeat-invalid, and duplicate-terminal input fails safely.
3. Streaming is presentation-only, bounded, cancelable, and cannot substitute for the durable terminal message.
4. The single terminal result and its message/usage are committed atomically before acknowledgement.
5. Exact effective context, policy snapshot, protocol/adapter/provider/model identifiers, generation parameters, prompt/response schema versions, manifest/core-release/connection digests, and run-config artifact are reconstructible after restart.
6. Proposer, critic, verifier, malicious, slow, and crashing deterministic agents pass the shared conformance matrix.
7. The OpenAI Responses API adapter passes the same conformance suite against deterministic loopback HTTP/SSE fixtures without a live credential.
8. Cancellation, timeouts, rate limits, provider errors, premature EOF, adapter crash, and app restart produce typed terminal/interrupted state without task workflow corruption or silent generation resume.
9. No API key is present in source, logs, DTOs, artifacts, SQLite, errors, `Debug`, or evidence output.
10. All M0-M2 regressions, architecture contracts, full Rust gates, frontend gates, desktop build, immutable design proof, and M3 evidence verification pass.

## Deliberate M3 Deferrals

- External stdio agent launch/containment activation remains disabled; M3 proves the protocol codec and peers without relaxing M2 process isolation.
- Context retrieval, specialist orchestration, and mediated tool execution are parsed and validated protocol methods but are wired to their full use cases in M4/M5.
- The second heterogeneous provider adapter is M4.
- Live OpenAI smoke tests run only when the user explicitly supplies credentials and authorizes network cost; deterministic loopback conformance is the mandatory M3 gate.
- Provider configuration UI and OS secret-store lifecycle belong to the later operations/package milestone; M3 accepts only explicit in-memory bootstrap configuration.
