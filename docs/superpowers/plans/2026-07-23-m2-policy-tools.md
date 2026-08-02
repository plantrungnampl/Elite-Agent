# M2 Policy and Structured Tool Broker Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Deliver a deny-overrides policy engine and a capability-scoped structured tool broker that can classify and redact data, bind risky operations to canonical approvals, execute trusted filesystem/Git/diff/process tools, terminate complete Windows process trees, and retain authoritative audit evidence without granting agents ambient repository, shell, credential, or network access.

**Architecture:** Preserve the existing Clean Architecture direction. `domain` owns pure policy combination and validated tool value objects. `application` owns policy, approval, capability, process, audit, and tool-execution ports plus the `ExecuteTool` use case. `policy-engine`, `tool-runtime`, `platform-core`, `platform-windows`, `repository-git`, and `storage-sqlite` implement those ports. `bootstrap` is the only composition root. Tauri exposes narrow immutable DTOs; React renders core state and may select only an approval ID or cancellation ID, never an operation payload.

**Tech Stack:** Rust 1.97 MSVC, Cargo workspace, serde/serde_json, RFC 8785 through the existing `serde_json_canonicalizer`, SHA-256, SQLite/rusqlite, existing in-process libgit2 adapter, Windows directory handles and Job Objects through `windows-sys`, Tauri 2, React/TypeScript/Vite, Vitest, Testing Library, Playwright, axe-core, Node `node:test`, and GitHub Actions Windows runners.

## Global Constraints

- Implement every task in `D:\multiagent` on the existing `codex/product-build-root` branch. Do not create or use a developer Git worktree. Disposable repositories and child processes are allowed only as inert test fixtures.
- `docs/multi-agent-terminal-design/**` is immutable. The normative M2 sources are `11-mvp-roadmap.md` section 4; `02-system-architecture.md` sections 4, 5, 7, and 10; threats T-001 through T-012 and sections 6, 8, and 10 of `06-security-threat-model.md`; the policy, approval, tool-execution, operation-intent, event, and projection contracts in `07-storage-data-model.md` and `schemas/sqlite-v1.sql`; `13-trust-sandbox-model.md` sections 4 through 12; tool and policy-exception definitions in `schemas/approval-digest.v1.schema.json`; `09-testing-reliability.md`; `08-desktop-ux.md`; and ADR-012, ADR-015 through ADR-018, and ADR-021.
- Stay inside M2. Do not add the M3 JSON-RPC transport, provider adapters, or agent runtime. Do not add the M5 implementation workflow, candidate-tree finalization, hook execution, or local commit creation.
- The design package is already approved. If prose and an executable schema conflict, stop and report the exact conflict; never edit the design to make a test pass.
- Keep `domain` free of filesystem, database, process, Git, async-runtime, Tauri, or OS dependencies. Application traits remain object-safe and own every outward contract. Concrete adapters depend inward, and only `bootstrap` constructs them.
- Agents receive logical capabilities and immutable IDs, never repository/application-data OS paths, process handles, environment secrets, approval payloads, or SQLite handles. Every capability is resolved from trusted metadata at the last responsible moment.
- Deny overrides every other matched policy effect. A decision is bound to the complete actor, resource digest/class, action, purpose, workflow phase, policy snapshot, workspace version where applicable, and expiry. Missing or unverifiable input denies.
- Approval payloads are built in Rust core, validated against the exact schema with unknown fields rejected, canonicalized using RFC 8785, and hashed as `sha256:<lowercase-hex>`. Changing any bound field invalidates approval. React never constructs or replaces authorization-bearing JSON.
- One writer only. Every write-capable tool carries the current executor fencing token, which is rechecked immediately before the side effect. Stale claims cause no filesystem, Git, process, projection, or workspace-version side effect.
- `process.exec` accepts a registered executable identity and an argv array. It never accepts or repairs a command string, performs PATH lookup, infers a shell, or accepts an unapproved response file. `shell.raw` is denied by the default MVP policy.
- Job Objects and ConPTY are lifecycle/I/O controls, not a sandbox. If the promised identity, ACL, filesystem, registry, credential, network, or process-tree boundary cannot be created and verified, the affected integration fails closed. There is no fallback to the user's full token.
- A `brokered_process` receives a private runtime directory and context by value; it receives no repository/worktree or user-profile ACL. A process that executes repository-controlled code or needs a worktree mount requires an approved `isolated_worker` container/VM adapter that passes Task 10. If that adapter is unavailable, those requests remain disabled; a restricted token plus Job Object is not relabeled as an isolated worker.
- No command, build, test, hook, filter, helper, LFS/submodule action, or executable from an untrusted repository may run until Task 10's containment suite passes on the supported Windows build. Earlier tasks use only this trusted product repository and inert hostile fixtures.
- Every side effect follows intent -> claim/fence -> policy -> digest/approval -> immediate revalidation -> effect -> authoritative audit. Interrupted non-repeatable effects become `indeterminate` and are never silently retried.
- Outputs, filenames, metadata, diagnostics, artifact references, and serialized outbound bytes are disclosure channels. Classification, redaction, and secret scanning cover all of them. Secret bytes never enter ordinary logs, events, indexes, environments, or UI DTOs.
- Tauri commands remain narrow and typed. WCAG 2.1 AA, keyboard operation, visible focus, focus restoration, status live regions, non-color state labels, contrast, 200% zoom/reflow, and reduced motion are release contracts.
- Handwritten behavior is test-first. Each task starts with a focused failing test, implements only enough to satisfy it, runs the focused and regression gates, receives a task-scoped review, and creates one reviewable commit.

---

## Task 1: Pin executable M2 contracts and dependency seams

**Files:**

- Create: `tests/contracts/m2-contracts.test.mjs`
- Create: `tests/contracts/fixtures/m2/policy-engine-outward-metadata.json`
- Create: `tests/contracts/fixtures/m2/tool-runtime-outward-metadata.json`
- Create: `tests/contracts/fixtures/m2/raw-shell-request.json`
- Create: `tests/contracts/fixtures/m2/tool-approval-valid.json`
- Create: `tests/contracts/fixtures/m2/tool-approval-unknown-field.json`
- Modify: `scripts/check-architecture.mjs`
- Modify: `tests/contracts/architecture.test.mjs`
- Verify: `docs/multi-agent-terminal-design/schemas/approval-digest.v1.schema.json`
- Verify: `docs/multi-agent-terminal-design/schemas/sqlite-v1.sql`

**Interfaces:**
- Consumes the approved Cargo dependency graph, approval JSON Schema, SQLite v1 DDL, and M2 roadmap. Produces executable constraints for `policy-engine`, `tool-runtime`, `platform-core`, and `platform-windows`, plus negative fixtures for outward dependencies, generic execution, raw shell, and authorization-bearing unknown fields.

- [x] **Step 1 - Write failing contract tests**

Add Node tests that assert:

1. `domain` has no outward dependency; `application` depends only on `domain` and canonicalization libraries; new adapters depend inward on `application`/`domain` and never on Tauri/React.
2. `tool-runtime` cannot import `std::process`, `Command`, shell APIs, PATH/environment discovery, Win32 process APIs, or `repository-git` concrete types. It receives `ProcessLauncher`, `CapabilityFilesystem`, and `StructuredGit` ports.
3. Only `platform-windows` may import Job Object/process-token/Windows filesystem APIs; only `bootstrap` may construct concrete M2 adapters.
4. Generic Tauri commands (`shell`, `exec`, `run_command`, `filesystem`, `git`) and frontend invokes outside `src/api/` are rejected.
5. `tool-approval-valid.json` validates against the normative schema; the unknown-field fixture and a string-form `process.exec` request are rejected; `shell.raw` is explicitly denied in the default fixture.
6. No M3 protocol/provider package or M5 finalization/commit command is introduced, and the immutable design directory matches baseline `321734f`.

Run:

```powershell
node --test tests/contracts/m2-contracts.test.mjs
```

Expected RED: the M2 package allowlist, generic-execution scan, and new fixtures are absent. The design immutability assertion already passes.

- [x] **Step 2 - Implement only the contract checker and fixtures**

Extend `scripts/check-architecture.mjs` with explicit allowed edges:

```text
domain <- application
application <- policy-engine, tool-runtime, platform-core, platform-windows, repository-git, storage-sqlite
application/adapters <- bootstrap <- tauri-app
```

Reject reverse edges, crate cycles, process construction outside `platform-windows`, concrete adapter construction outside `bootstrap`, raw command strings, raw path-bearing frontend DTOs, and generic Tauri command names. Do not create production crates in this task.

- [x] **Step 3 - Run focused and regression checks**

```powershell
node --test tests/contracts/m2-contracts.test.mjs tests/contracts/architecture.test.mjs tests/contracts/design-contracts.test.mjs
node scripts/check-architecture.mjs
git diff --exit-code 321734f -- docs/multi-agent-terminal-design
```

Expected GREEN: every hostile fixture fails for its intended reason, valid schema fixtures pass, existing M0/M1 checks remain green, and the design diff is empty.

- [x] **Step 4 - Commit**

```powershell
git add tests/contracts scripts/check-architecture.mjs
git diff --cached --check
git commit -m "test: pin policy tool broker contracts"
```

## Task 2: Add pure policy and structured-tool domain rules

**Files:**

- Create: `crates/domain/src/policy.rs`
- Create: `crates/domain/src/tool.rs`
- Modify: `crates/domain/src/identity.rs`
- Modify: `crates/domain/src/lib.rs`
- Create: `crates/domain/tests/policy_contract.rs`
- Create: `crates/domain/tests/tool_contract.rs`

**Interfaces:**
- Consumes existing `TaskId`, `RunId`, `FencingToken`, `WorkspaceVersion`, workflow phase names, and validated SHA-256 conventions. Produces pure validated policy/tool values and deterministic rule combination; it performs no I/O and makes no approval, persistence, or OS decision.

- [x] **Step 1 - Write failing domain tests**

Cover empty/oversized IDs, malformed digests, unsupported policy versions, incomplete actor/resource bindings, expired decisions, duplicate rule IDs, deterministic rule order, no-match denial, and all effect combinations. Prove `deny > require_approval > allow_with_redaction > allow`, independent of input order. Add structured-tool tests that reject an empty executable/argv boundary, absolute or traversal capability paths, null bytes, duplicate expected writes, a write without a fencing token, and any `shell.raw` request in the default profile.

```powershell
cargo test -p local-agent-terminal-domain --test policy_contract --test tool_contract
```

Expected RED: `policy` and `tool` modules and their value objects do not exist.

- [x] **Step 2 - Implement the smallest pure model**

Use these contracts consistently in subsequent tasks:

```rust
pub enum PolicyEffect { Allow, Deny, RequireApproval, AllowWithRedaction }

pub struct PolicyActor {
    pub connection_id: String,
    pub agent_id: String,
    pub trust_tier: TrustTier,
    pub locality: ActorLocality,
}

pub struct PolicyResource {
    pub capability: CapabilityRef,
    pub content_digest: Sha256Digest,
    pub resource_class: ResourceClass,
}

pub struct PolicyRequest {
    pub task_id: TaskId,
    pub actor: PolicyActor,
    pub action: PolicyAction,
    pub resource: PolicyResource,
    pub task_risk: TaskRisk,
    pub workflow_phase: String,
    pub purpose: String,
    pub policy_snapshot_digest: Sha256Digest,
    pub evaluated_at: Timestamp,
}

pub struct MatchedPolicyRule {
    pub rule_id: PolicyRuleId,
    pub effect: PolicyEffect,
    pub redactions: Vec<RedactionDirective>,
}

pub fn combine_policy_rules(
    request: PolicyRequest,
    policy_version: PolicyVersion,
    matches: Vec<MatchedPolicyRule>,
    expires_at: Option<Timestamp>,
) -> Result<PolicyDecisionDraft, PolicyError>;
```

`combine_policy_rules` sorts and deduplicates rule IDs, denies on no match or invalid/expired binding, applies deny-overrides, and retains every matched rule plus required redaction directives. Add `CapabilityRef::{Source, Artifact, Worktree, Toolchain}`, `StructuredToolName::{FileRead, FileWrite, GitStatus, GitDiff, ProcessExec}`, `ProcessTrustTier::{BrokeredProcess, IsolatedWorker}`, `NetworkProfile::{Denied, ProviderEndpointOnly, ApprovedDestinations}`, and typed `ExpectedWrite`. `full_access_legacy` is not a constructible M2 process tier. Do not put an OS path or process handle in these values.

- [x] **Step 3 - Run focused, property, and regression tests**

```powershell
cargo fmt --all -- --check
cargo test -p local-agent-terminal-domain --test policy_contract --test tool_contract
cargo test -p local-agent-terminal-domain
```

Expected GREEN: precedence is deterministic across permutations, invalid values fail closed, and all existing workflow/workspace tests pass.

- [x] **Step 4 - Commit**

```powershell
git add crates/domain
git diff --cached --check
git commit -m "feat: add pure policy and tool rules"
```

## Task 3: Define application ports, canonical approvals, and immutable DTOs

**Files:**

- Create: `crates/application/src/policy.rs`
- Create: `crates/application/src/approval.rs`
- Create: `crates/application/src/tool.rs`
- Create: `crates/application/src/execute_tool.rs`
- Modify: `crates/application/src/canonical_json.rs`
- Modify: `crates/application/src/dto.rs`
- Modify: `crates/application/src/error.rs`
- Modify: `crates/application/src/lib.rs`
- Modify: `crates/application/Cargo.toml`
- Create: `crates/application/tests/policy_tool_ports.rs`
- Create: `crates/application/tests/approval_digest.rs`

**Interfaces:**
- Consumes the Task 2 domain values, existing `CanonicalJsonRequest`, `ExecutorLeaseStore`, `ArtifactStore`, `EventStore`, clock/ID ports, and the exact approval-digest v1 schema. Produces object-safe application ports, typed request/result records, immutable approval DTOs, and one canonical digest implementation reused by policy and tool execution.

- [x] **Step 1 - Write failing port and digest tests**

Add compile-time/object-safety tests and fakes that prove application ports accept only domain/application types. Add RFC 8785 vectors for object ordering, Unicode, escaping, integer bounds, negative zero/floating-point rejection, duplicate-key rejection at the parser boundary, and timestamp normalization. Deserialize the normative valid tool/policy-exception fixtures with `deny_unknown_fields`; mutate each bound field one at a time and prove the operation digest changes. Prove expired approvals, nonce reuse, policy/workspace/fencing changes, and a digest mismatch return typed non-retryable errors before a fake executor is called.

```powershell
cargo test -p local-agent-terminal-application --test policy_tool_ports --test approval_digest
```

Expected RED: the policy, approval, tool, and execution ports and schema-bound payload types are absent.

- [x] **Step 2 - Add object-safe ports and exact records**

Define and export these inward contracts:

```rust
pub trait PolicyEvaluator: Send + Sync {
    fn evaluate(&self, request: PolicyRequest) -> Result<PolicyDecision, PortError>;
}

pub trait PolicyDecisionStore: Send + Sync {
    fn record(&self, decision: RecordedPolicyDecision) -> Result<(), PortError>;
}

pub trait ApprovalStore: Send + Sync {
    fn request(&self, approval: NewApproval) -> Result<ApprovalSnapshot, PortError>;
    fn resolve(&self, resolution: ApprovalResolution) -> Result<ApprovalSnapshot, PortError>;
    fn valid_for(&self, check: ApprovalCheck) -> Result<Option<ApprovalSnapshot>, PortError>;
    fn invalidate(&self, request: ApprovalInvalidation) -> Result<u64, PortError>;
}

pub trait CapabilityResolver: Send + Sync {
    fn resolve(&self, request: CapabilityRequest) -> Result<ResolvedCapability, PortError>;
}

pub trait CapabilityFilesystem: Send + Sync {
    fn read(&self, request: AuthorizedFileRead) -> Result<VerifiedBytes, PortError>;
    fn write(&self, request: AuthorizedFileWrite) -> Result<VerifiedWrite, PortError>;
}

pub trait StructuredGit: Send + Sync {
    fn status(&self, request: AuthorizedGitStatus) -> Result<GitStatusResult, PortError>;
    fn diff(&self, request: AuthorizedGitDiff) -> Result<GitDiffResult, PortError>;
}

pub trait ProcessLauncher: Send + Sync {
    fn execute(&self, request: AuthorizedProcessRequest) -> Result<ProcessReceipt, PortError>;
    fn cancel(&self, execution_id: &ToolExecutionId) -> Result<CancellationReceipt, PortError>;
}

pub trait ToolExecutionStore: Send + Sync {
    fn reserve(&self, request: NewToolIntent) -> Result<OperationIntentSnapshot, PortError>;
    fn begin(&self, request: NewToolExecution) -> Result<ToolExecutionSnapshot, PortError>;
    fn finish(&self, completion: ToolExecutionCompletion) -> Result<ToolExecutionSnapshot, PortError>;
    fn incomplete(&self) -> Result<Vec<ToolExecutionSnapshot>, PortError>;
}

pub trait StructuredToolExecutor: Send + Sync {
    fn execute(&self, request: AuthorizedToolRequest) -> Result<ToolExecutionResult, PortError>;
    fn cancel(&self, execution_id: &ToolExecutionId) -> Result<CancellationReceipt, PortError>;
}
```

Represent a process request as registered executable identity, `Vec<String>` argv, capability cwd, environment-profile digest, network profile, timeout/resource limits, expected reads/writes, task/run/plan-step/phase, and optional fencing token. There is no command-string field.

Add `ToolApprovalPayloadV1` and `PolicyExceptionApprovalPayloadV1` with `#[serde(deny_unknown_fields)]`, exact field names from the schema, and a `build_approval_request` function that validates, canonicalizes with the existing RFC 8785 path, hashes SHA-256 bytes, and returns both an artifact request and digest. Add `ApprovalRequestDto` containing only immutable core-generated summary, full digest, expiry, exact scopes, and an opaque approval ID. Input DTOs contain only `{ approvalId, expectedOperationDigest }` or `{ executionId }`.

- [x] **Step 3 - Run focused and regression checks**

```powershell
cargo fmt --all -- --check
cargo test -p local-agent-terminal-application --test policy_tool_ports --test approval_digest
cargo test -p local-agent-terminal-application
node --test tests/contracts/m2-contracts.test.mjs
```

Expected GREEN: every port is object-safe, canonical vectors are stable, every bound mutation invalidates the digest, unknown fields fail, and existing M0/M1 application tests remain green.

- [x] **Step 4 - Commit**

```powershell
git add crates/application
git diff --cached --check
git commit -m "feat: define policy approval and tool ports"
```

## Task 4: Persist policy, approvals, tool executions, and crash state atomically

**Files:**

- Create: `crates/storage-sqlite/src/policy_store.rs`
- Create: `crates/storage-sqlite/src/approval_store.rs`
- Create: `crates/storage-sqlite/src/tool_execution_store.rs`
- Modify: `crates/storage-sqlite/src/migrations.rs`
- Modify: `crates/storage-sqlite/src/lib.rs`
- Create: `crates/storage-sqlite/tests/policy_tool_store.rs`
- Create: `crates/storage-sqlite/tests/tool_recovery.rs`

**Interfaces:**
- Implements `PolicyDecisionStore`, `ApprovalStore`, and `ToolExecutionStore` against the existing SQLite v1 `policy_decisions`, `approvals`, `tool_executions`, `operation_intents`, `artifacts`, `events`, and projection tables. All foreign keys stay enabled; no test or production connection may bypass them.

- [x] **Step 1 - Write failing SQLite contract and crash tests**

Seed a real project, task, trusted system run, canonical request artifact, and active lease. Test all allowed effects/statuses, required foreign keys, unique `(run_id, request_id)` idempotency, operation-digest length/case, immutable granted approval contents, expiry, resolution races, nonce/digest replay rejection, and invalidation by workspace/policy/fencing changes. Prove `begin` atomically creates/claims the operation intent, tool execution, policy reference, and `tool.execution.started` event; inject a failure at each statement and assert total rollback.

For completion, inject failures before/after result-artifact reservation, status transition, output/write evidence attachment, projection update, and `tool.execution.completed`. Reopen SQLite after each boundary. `reserve` records the canonical request artifact and pending operation intent before any external effect; `begin` compare-transitions that exact intent and inserts the execution after a persisted policy decision exists. An idempotent or queryable intent may reconcile only from authoritative evidence; an incomplete non-repeatable process is `indeterminate`, never `succeeded` and never redispatched.

```powershell
cargo test -p local-agent-terminal-storage-sqlite --test policy_tool_store --test tool_recovery
```

Expected RED: the three stores and transactional M2 operations do not exist.

- [x] **Step 2 - Implement exact SQLite v1 adapters**

Reuse the normative tables without changing their public v1 meanings. Use `BEGIN IMMEDIATE` for approval resolution/invalidation and tool begin/finish transitions. Persist canonical arguments as a content-addressed artifact; persist `policy_decision_id`, optional `approval_id`, intent ID, fencing token, output artifact IDs, status, timestamps, exit code, correlation/causation IDs, and observation class.

Implement state transitions as compare-and-set updates:

```text
approval: pending -> granted | denied | expired | invalidated
intent: pending -> started -> completed | failed | interrupted | indeterminate
execution: pending -> running -> succeeded | failed | terminated | interrupted | indeterminate | denied
```

Reject all backward or ambiguous transitions. `valid_for` reads the stored request artifact, verifies its hash/size, checks exact digest/type/task/status/expiry, and returns no grant on malformed or missing evidence. Completion is idempotent only when all stored result fields match byte-for-byte.

- [x] **Step 3 - Run focused, schema, and regression checks**

```powershell
cargo fmt --all -- --check
cargo test -p local-agent-terminal-storage-sqlite --test policy_tool_store --test tool_recovery
cargo test -p local-agent-terminal-storage-sqlite
node --test tests/contracts/design-contracts.test.mjs tests/contracts/m2-contracts.test.mjs
```

Expected GREEN: FK checks remain enabled, every injected boundary is deterministic after reopen, duplicate requests are exact/idempotent, non-repeatable ambiguity is retained, and existing storage tests pass.

- [x] **Step 4 - Commit**

```powershell
git add crates/storage-sqlite
git diff --cached --check
git commit -m "feat: persist policy approvals and tool audit"
```

## Task 5: Implement classification, secret scanning, redaction, and deny-overrides evaluation

**Files:**

- Create: `crates/policy-engine/Cargo.toml`
- Create: `crates/policy-engine/src/lib.rs`
- Create: `crates/policy-engine/src/bundle.rs`
- Create: `crates/policy-engine/src/classification.rs`
- Create: `crates/policy-engine/src/redaction.rs`
- Create: `crates/policy-engine/tests/deny_overrides.rs`
- Create: `crates/policy-engine/tests/disclosure_matrix.rs`
- Create: `crates/policy-engine/tests/fixtures/policy-v1.json`
- Modify: `Cargo.toml`

**Interfaces:**
- Implements application `PolicyEvaluator`. Consumes a versioned, trusted policy snapshot and complete `PolicyRequest`; produces a decision with actor/resource/operation/policy digests, sorted matched rules, effect, expiry, and a content-addressed redaction report. It never reads a repository path or sends data to a provider.

- [x] **Step 1 - Write failing policy and disclosure tests**

Create deterministic fixtures containing API tokens, private keys, connection strings, proprietary classifications, prompt-injection text, secret-bearing filenames, archive metadata, error messages, and Unicode/CRLF variants. Test direct read, filename/metadata listing, Git diff/status, diagnostic, artifact, summary, and final serialized-payload channels. Assert:

- any matching deny wins, regardless of rule ordering;
- cloud/locality/trust-tier/purpose/phase/resource changes produce distinct decisions;
- denied bytes and stable secret fragments appear in no effective payload, report, error, log field, or DTO;
- `allow_with_redaction` returns exact effective bytes plus offsets/categories and original/effective SHA-256 digests;
- `require_approval` carries the effective-payload and redaction-report digests required by policy-exception approval;
- missing policy snapshot, unsupported version, malformed rule, scanner failure, or output rescan failure denies.

```powershell
cargo test -p local-agent-terminal-policy-engine --test deny_overrides --test disclosure_matrix
```

Expected RED: the policy-engine crate and fixtures are absent.

- [x] **Step 2 - Implement the minimal deterministic engine**

Parse `PolicyBundleV1` with `deny_unknown_fields`, validate unique rule IDs and a canonical snapshot digest, then compile only explicit built-in matchers. Classify trusted metadata separately from hostile content. Scan before indexing/read disclosure and scan the final serialized effective payload again. Use byte offsets internally so redaction does not depend on Unicode character width.

Implement:

```rust
pub struct EvaluatedDisclosure {
    pub decision: PolicyDecision,
    pub original_digest: Sha256Digest,
    pub effective_bytes: Option<Vec<u8>>,
    pub effective_digest: Option<Sha256Digest>,
    pub redaction_report: RedactionReport,
}

impl PolicyEvaluator for VersionedPolicyEngine {
    fn evaluate(&self, request: PolicyRequest) -> Result<PolicyDecision, PortError>;
}

impl VersionedPolicyEngine {
    pub fn disclose(&self, request: DisclosureRequest) -> Result<EvaluatedDisclosure, PortError>;
}
```

Ordinary diagnostics expose only category, rule IDs, byte counts, and stable redacted identifiers. Do not persist exact secret matches in normal artifacts.

- [x] **Step 3 - Run focused, property, and architecture checks**

```powershell
cargo fmt --all -- --check
cargo test -p local-agent-terminal-policy-engine --test deny_overrides --test disclosure_matrix
cargo test -p local-agent-terminal-policy-engine
node scripts/check-architecture.mjs
```

Expected GREEN: all channels obey the same decision, deny-overrides is order-independent, failed enforcement denies, and the new crate has only inward edges.

- [x] **Step 4 - Commit**

```powershell
git add Cargo.toml Cargo.lock crates/policy-engine
git diff --cached --check
git commit -m "feat: enforce classification and redaction policy"
```

## Task 6: Build capability-scoped filesystem, Git, and diff tools

**Files:**

- Create: `crates/tool-runtime/Cargo.toml`
- Create: `crates/tool-runtime/src/lib.rs`
- Create: `crates/tool-runtime/src/capability.rs`
- Create: `crates/tool-runtime/src/filesystem.rs`
- Create: `crates/tool-runtime/src/git.rs`
- Create: `crates/tool-runtime/tests/capability_tools.rs`
- Modify: `crates/repository-git/src/lib.rs`
- Create: `crates/repository-git/src/tools.rs`
- Create: `crates/repository-git/tests/structured_tools.rs`
- Modify: `Cargo.toml`

**Interfaces:**
- `tool-runtime` implements `StructuredToolExecutor` for `file.read`, `file.write`, `git.status`, and `git.diff` by dispatching only to application ports. `repository-git` implements `StructuredGit` in-process. Capability resolution returns opaque root identity plus normalized relative components; it never returns a serializable OS path.

- [x] **Step 1 - Write failing capability and Git security tests**

Use temporary repositories and an outside sentinel. Cover source/artifact/worktree/toolchain capability ownership, wrong task/revision, absolute paths, `..`, empty/dot components, drive-relative forms, UNC, device paths, ADS, reserved names, case collisions, long paths, static and swap-race junctions/symlinks, and replacement after validation. A denied read must not reveal bytes, filename, size, existence, or error detail. A stale-token write must leave bytes, Git state, workspace versions, approvals, and sentinel unchanged.

For Git/status/diff, include malicious hooks, filters, `diff.external`, textconv, credential/remote helpers, `.gitmodules`, LFS pointers, response-file-like names, and missing/malformed objects. Prove no child process starts, no network path is consulted, original checkout/index/HEAD remains unchanged, output is bounded and policy-scanned, and unsupported hazards fail closed.

```powershell
cargo test -p local-agent-terminal-tool-runtime --test capability_tools
cargo test -p local-agent-terminal-repository-git --test structured_tools
```

Expected RED: the tool-runtime crate, dispatch, and structured Git port implementation are absent.

- [x] **Step 2 - Implement typed dispatch and in-process Git tools**

Resolve logical capabilities from trusted records, normalize only relative components, evaluate policy, and pass an `AuthorizedFileRead`/`AuthorizedFileWrite` to the injected `CapabilityFilesystem`. Immediately before writes call `ExecutorLeaseStore::assert_current`; after an exact verified write, hash bytes and invoke the existing atomic workspace-mutation path so versions advance and stale approvals are invalidated.

Implement Git status/diff through `git2` with configuration/environment includes disabled and callbacks that never invoke hooks, filters, helpers, LFS, submodules, external diff/textconv, or a shell. Bind every result to repository ID, base/revision object ID, path scope, content hash, truncation state, and policy decision ID. Do not add generic `git(args)` or `execute(name, Value)` entry points.

- [x] **Step 3 - Run focused Windows and regression checks**

```powershell
cargo fmt --all -- --check
cargo test -p local-agent-terminal-tool-runtime --test capability_tools
cargo test -p local-agent-terminal-repository-git --test structured_tools
cargo test -p local-agent-terminal-repository-git --test windows_matrix --features test-seams
node scripts/check-architecture.mjs
```

Expected GREEN: every capability escape and execution-capable Git fixture fails closed, allowed reads/diffs are content-bound, stale writes have zero effect, and the M1 Windows matrix remains green.

- [x] **Step 4 - Commit**

```powershell
git add Cargo.toml Cargo.lock crates/tool-runtime crates/repository-git
git diff --cached --check
git commit -m "feat: add capability filesystem and git tools"
```

## Task 7: Enforce executable, environment, network, and Windows process boundaries

**Files:**

- Create: `crates/platform-core/Cargo.toml`
- Create: `crates/platform-core/src/lib.rs`
- Create: `crates/platform-core/src/executable_registry.rs`
- Create: `crates/platform-core/src/environment.rs`
- Create: `crates/platform-core/src/network.rs`
- Create: `crates/platform-core/tests/profile_contract.rs`
- Create: `crates/platform-windows/Cargo.toml`
- Create: `crates/platform-windows/src/lib.rs`
- Create: `crates/platform-windows/src/filesystem.rs`
- Create: `crates/platform-windows/src/process.rs`
- Create: `crates/platform-windows/src/job.rs`
- Create: `crates/platform-windows/tests/process_matrix.rs`
- Create: `crates/platform-windows/tests/filesystem_matrix.rs`
- Modify: `crates/tool-runtime/src/lib.rs`
- Create: `crates/tool-runtime/src/process.rs`
- Modify: `Cargo.toml`

**Interfaces:**
- `platform-core` resolves trusted executable registrations and immutable environment/network profiles without spawning. `platform-windows` implements `CapabilityFilesystem` with retained directory handles and the Windows lifecycle portion of `ProcessLauncher` with a verified restricted identity/boundary plus a kill-on-close, no-breakaway Job Object. `tool-runtime` exposes only typed `process.exec`; `shell.raw` remains denied. A brokered request cannot use a worktree cwd or repository reads/writes. Worktree execution dispatches only to a separately approved `isolated_worker` adapter and otherwise fails closed.

- [x] **Step 1 - Write failing profile, filesystem, and process tests**

Profile tests reject relative executable paths, PATH lookup, mutable/replaced executables, digest/version mismatch, duplicate environment names, inherited environment, secret-looking values, unregistered cwd, unsupported network mode, redirect/rebinding ambiguity, response-file arguments, and raw script fields. Assert deterministic canonical profile digests.

Windows tests launch a purpose-built inert child tree that attempts denied reads/writes in repository, user profile, application data, sibling worktree, registry, and credential locations; denied loopback/LAN/internet connections; junction/UNC/device/ADS escapes; inherited credential enumeration; named-pipe access; breakaway/detached grandchildren; and output/CPU/memory/wall-time limits. A `brokered_process` request with worktree cwd/expected writes is denied. An `isolated_worker` request starts only when the injected container/VM adapter presents a passing enforcement receipt; the default no-adapter case starts nothing. Cancellation and timeout must terminate every descendant and preserve PID/job evidence. If the low-privilege identity, ACL, network adapter, Job assignment, or handle-relative filesystem self-test cannot be verified, no child starts.

```powershell
cargo test -p local-agent-terminal-platform-core --test profile_contract
cargo test -p local-agent-terminal-platform-windows --test filesystem_matrix --test process_matrix
cargo test -p local-agent-terminal-tool-runtime process
```

Expected RED: platform crates, profile registries, handle-relative adapter, and Job Object launcher are absent.

- [x] **Step 2 - Implement registered profiles and handle-relative filesystem access**

`ExecutableRegistry` loads only trusted application configuration and returns `ResolvedExecutable { canonical_path, sha256, file_identity, toolchain_id }`. Reopen and verify identity/digest immediately before launch. `EnvironmentProfile` starts from an empty map and adds only named nonsecret values. `NetworkPolicyAdapter::prepare` either returns a verifiable enforcement receipt for `Denied`, `ProviderEndpointOnly`, or `ApprovedDestinations`, or denies.

Implement Windows filesystem opens relative to retained trusted root handles; reject reparse points and unsupported path forms at every component; retain ancestor/leaf handles through the effect; use atomic create/replace where supported; and hash the exact opened/written bytes. Lexical prefix checks are never authorization.

- [x] **Step 3 - Implement Job Object process lifecycle and typed process dispatch**

Use this launch contract without a shell:

```rust
pub struct AuthorizedProcessRequest {
    pub execution_id: ToolExecutionId,
    pub trust_tier: ProcessTrustTier,
    pub executable: ResolvedExecutable,
    pub argv: Vec<String>,
    pub cwd: ResolvedCapability,
    pub environment: ResolvedEnvironmentProfile,
    pub network: EnforcedNetworkProfile,
    pub timeout_ms: u64,
    pub limits: ProcessLimits,
    pub expected_writes: Vec<ExpectedWrite>,
    pub executor_claim: LeaseClaim,
}

pub struct ProcessReceipt {
    pub status: ProcessStatus,
    pub exit_code: Option<i32>,
    pub stdout: BoundedOutput,
    pub stderr: BoundedOutput,
    pub duration_ms: u64,
    pub job_receipt: JobReceipt,
    pub observed_writes: Vec<VerifiedWrite>,
}
```

Create the child suspended, assign it to a Job Object configured for kill-on-close and no breakaway, verify the enforced token/ACL/network receipts, then resume. On cancel, timeout, output overflow, launcher drop, or app shutdown, close/terminate the job, wait for the complete tree, and record `terminated` rather than `cancelled_cleanly` when graceful shutdown is unproven. Never pass an untrusted command line to `cmd.exe` or PowerShell.

- [x] **Step 4 - Run focused and architecture checks**

```powershell
cargo fmt --all -- --check
cargo test -p local-agent-terminal-platform-core --test profile_contract
cargo test -p local-agent-terminal-platform-windows --test filesystem_matrix --test process_matrix
cargo test -p local-agent-terminal-tool-runtime
node scripts/check-architecture.mjs
```

Expected GREEN: argv boundaries survive metacharacters literally, no denied canary is accessible, no descendant survives cancellation, enforcement failure starts nothing, and process/Windows imports remain in the approved adapter.

- [x] **Step 5 - Commit**

```powershell
git add Cargo.toml Cargo.lock crates/platform-core crates/platform-windows crates/tool-runtime
git diff --cached --check
git commit -m "feat: enforce windows tool process boundaries"
```

## Task 8: Orchestrate digest-bound tools, approvals, audit, cancellation, and recovery

**Files:**

- Modify: `crates/application/src/execute_tool.rs`
- Modify: `crates/application/src/approval.rs`
- Modify: `crates/application/src/tool.rs`
- Create: `crates/application/tests/execute_tool.rs`
- Create: `crates/bootstrap/src/tool_runtime.rs`
- Modify: `crates/bootstrap/src/startup.rs`
- Modify: `crates/bootstrap/src/lib.rs`
- Modify: `crates/bootstrap/Cargo.toml`
- Create: `crates/bootstrap/tests/tool_broker.rs`
- Create: `crates/bootstrap/tests/tool_recovery.rs`

**Interfaces:**
- Implements the application `ExecuteTool` use case using only injected ports. `bootstrap` wires policy, approval, persistence, capability, Git, filesystem, executable/profile, process, clock, artifact, event, and lease adapters. It does not move authorization logic into the composition root.

- [x] **Step 1 - Write failing orchestration and crash tests**

Use recording fakes to assert this exact order for every read and write path:

```text
validate typed request
persist/claim intent and request artifact
assert lease/fencing when write-capable
resolve capability and authoritative resource digest
evaluate and persist policy decision
construct canonical operation and digest
return deny, immutable approval request, or continue
reload approval and every bound authoritative field
recompute digest immediately before effect
perform exactly one typed effect
capture/scan/hash outputs and observed writes
atomically finish execution, append event, and update projection
```

Prove deny and approval-required paths never call an executor. Mutate actor, resource bytes, purpose, phase, policy snapshot, workspace version, executable identity, argv, cwd, environment, network, expected writes, expiry, nonce, or fencing token between approval and effect; each mutation invalidates the grant and has zero side effect. Prove duplicate request IDs return the same terminal receipt, concurrent writers have one winner, cancellation reaches `ProcessLauncher`, and stop-all cancels each running execution once.

Inject a crash at every persisted/effect boundary. On restart, recover idempotent/queryable work only from authoritative receipts; mark a launched process without authoritative completion `interrupted` or `indeterminate`; never automatically relaunch a non-repeatable process. Append audit records with actor binding, effective role, request/operation digests, policy/approval IDs, exact capability scope, fencing token, observation class, result, and correlation/causation IDs.

```powershell
cargo test -p local-agent-terminal-application --test execute_tool
cargo test -p local-agent-terminal-bootstrap --test tool_broker --test tool_recovery
```

Expected RED: `ExecuteTool` has contracts but no complete orchestration, and bootstrap has no M2 composition/recovery path.

- [x] **Step 2 - Implement the application use case**

Expose one typed entry point:

```rust
pub struct ExecuteTool<'a> {
    pub policies: &'a dyn PolicyEvaluator,
    pub policy_decisions: &'a dyn PolicyDecisionStore,
    pub approvals: &'a dyn ApprovalStore,
    pub capabilities: &'a dyn CapabilityResolver,
    pub leases: &'a dyn ExecutorLeaseStore,
    pub executions: &'a dyn ToolExecutionStore,
    pub executor: &'a dyn StructuredToolExecutor,
    pub artifacts: &'a dyn ArtifactStore,
    pub events: &'a dyn EventStore,
    pub clock: &'a dyn Clock,
    pub ids: &'a dyn IdGenerator,
}

impl ExecuteTool<'_> {
    pub fn execute(&self, request: ToolRequest) -> Result<ToolOutcome, PortError>;
    pub fn resume_approved(&self, approval_id: ApprovalId) -> Result<ToolOutcome, PortError>;
    pub fn cancel(&self, execution_id: ToolExecutionId) -> Result<CancellationReceipt, PortError>;
}
```

`ToolOutcome` is `Succeeded`, `Denied`, or `ApprovalRequired(ApprovalRequestDto)` plus typed failure classes; it never returns an OS path or secret-bearing raw diagnostic. Both initial execution and `resume_approved` rebuild the canonical payload from authoritative records. Keep one code path for pre-effect checks so approved execution cannot bypass normal policy/fencing validation.

- [x] **Step 3 - Compose adapters and deterministic startup recovery**

Create a `ToolRuntime` holder in `bootstrap` and inject concrete stores/adapters once. Startup runs profile/control self-tests before marking tools available, fences stale leases, reconciles incomplete M2 intents/executions, terminates any retained local Job handle, expires approvals, and exposes typed `ready`, `degraded_read_only`, or `unavailable` state. An unenforceable requested boundary disables that tool/profile and never changes it to full-access execution.

- [x] **Step 4 - Run focused, recovery, and regression checks**

```powershell
cargo fmt --all -- --check
cargo test -p local-agent-terminal-application --test execute_tool
cargo test -p local-agent-terminal-bootstrap --test tool_broker --test tool_recovery
cargo test -p local-agent-terminal-bootstrap
cargo test -p local-agent-terminal-storage-sqlite --test tool_recovery
```

Expected GREEN: call ordering and crash outcomes are deterministic, every canonical mutation blocks execution, cancellation is audited, restart never repeats ambiguous work, and M0/M1 startup/recovery stays green.

- [x] **Step 5 - Commit**

```powershell
git add crates/application crates/bootstrap
git diff --cached --check
git commit -m "feat: orchestrate audited structured tools"
```

## Task 9: Expose narrow Tauri controls and an accessible approval/tool activity view

**Files:**

- Modify: `apps/desktop/src-tauri/src/lib.rs`
- Modify: `apps/desktop/src-tauri/Cargo.toml`
- Create: `apps/desktop/src/api/tools.ts`
- Create: `apps/desktop/src/api/tools.test.ts`
- Create: `apps/desktop/src/features/tools/tool-model.ts`
- Create: `apps/desktop/src/features/tools/ToolActivityScreen.tsx`
- Create: `apps/desktop/src/features/tools/ToolActivityScreen.test.tsx`
- Modify: `apps/desktop/src/App.tsx`
- Modify: `apps/desktop/src/styles/base.css`
- Modify: `apps/desktop/src/styles/tokens.css`
- Create: `apps/desktop/tests/browser/tool-approval.spec.ts`

**Interfaces:**
- Tauri commands call the Task 8 use cases and queries. React consumes immutable camelCase DTOs and submits only opaque IDs plus the digest/version it displayed. The UI cannot select a tool, executable, argv, capability, environment, network profile, expected write, fencing token, or policy exception payload.

- [x] **Step 1 - Write failing API, component, and browser tests**

Test an exact invoke allowlist:

```text
get_tool_activity
get_approval_request
resolve_tool_approval
cancel_tool_execution
stop_all_tools
```

API tests reject unknown DTO fields and assert resolution input is `{ approvalId, expectedOperationDigest, decision }`; cancellation input is `{ executionId }`. Component tests cover loading, empty, denied, redacted, approval-required, running, cancelling, terminated, failed, interrupted, indeterminate, stale-digest, and unavailable-boundary states. Simulate an approval invalidation while the dialog is open: close it, restore focus to the trigger, announce the stale state, and never send the old resolution.

Browser tests cover full keyboard flow, one primary action, explicit confirmation for risky approval/stop-all, Escape/cancel behavior, focus trap/restoration, status live regions, text+icon semantics, 200% zoom and narrow reflow, reduced motion, and axe including 4.5:1 text and 3:1 control contrast. The exact executable/argv or typed arguments, cwd capability, read/write scope, actor/reason, environment, network, expiry, fencing token, policy rules, redaction state, and full digest are inspectable without exposing secrets or OS paths.

```powershell
pnpm --dir apps/desktop test --run src/api/tools.test.ts src/features/tools/ToolActivityScreen.test.tsx
pnpm --dir apps/desktop test:browser -- tool-approval.spec.ts
```

Expected RED: the API module, screen, and commands do not exist.

- [x] **Step 2 - Add immutable Rust DTO commands**

Add `#[serde(deny_unknown_fields)]` request DTOs and serialize only application DTOs. `get_approval_request` loads the existing core-built request; `resolve_tool_approval` compare-checks the displayed full digest and delegates the decision; grant resumes through `ExecuteTool::resume_approved`. `cancel_tool_execution` and `stop_all_tools` return authoritative receipts. Rust enforces all privilege; command names never encode generic execution.

- [x] **Step 3 - Build the minimal accessible React view**

Keep API calls in `src/api/tools.ts`, derive view state during render, and keep interaction state in event handlers/refs rather than effects. Render a semantic activity table for exact auditable fields and a dialog for one approval. Use an `aria-live` status for policy/cancel results, visible focus, non-color labels, existing design tokens, and reduced-motion styles. On every refresh/mutation, use a monotonic request generation so a delayed poll cannot overwrite an approval invalidation or cancellation response.

- [x] **Step 4 - Run frontend, browser, Tauri, and architecture checks**

```powershell
pnpm --dir apps/desktop test --run
pnpm --dir apps/desktop test:browser -- tool-approval.spec.ts
pnpm --dir apps/desktop build
cargo test -p local-agent-terminal-desktop
cargo build -p local-agent-terminal-desktop
node scripts/check-architecture.mjs
```

Expected GREEN: typed IPC and all UI states are covered, stale dialogs cannot grant, keyboard/axe/contrast/reflow checks pass, the frontend build succeeds, and no generic capability reaches React.

- [x] **Step 5 - Commit**

```powershell
git add apps/desktop
git diff --cached --check
git commit -m "feat: add policy approval and tool activity ui"
```

## Task 10: Prove Windows containment, finalize evidence, and obtain independent M2 approval

**Files:**

- Create: `tests/fixtures/m2-containment-probe/Cargo.toml`
- Create: `tests/fixtures/m2-containment-probe/src/main.rs`
- Create: `crates/tool-runtime/tests/security_matrix.rs`
- Create: `crates/bootstrap/tests/tool_broker_e2e.rs`
- Modify: `crates/platform-windows/tests/process_matrix.rs`
- Modify: `crates/platform-windows/tests/filesystem_matrix.rs`
- Modify: `apps/desktop/tests/browser/tool-approval.spec.ts`
- Create: `scripts/m2-evidence-worktree.mjs`
- Create: `scripts/run-m2-evidence.mjs`
- Create: `scripts/verify-m2-evidence.mjs`
- Create: `scripts/run-m2-post-final-contracts.mjs`
- Create: `scripts/verify-m2-post-final-log.mjs`
- Create: `tests/contracts/m2-evidence-contracts.test.mjs`
- Modify: `.github/workflows/ci.yml`
- Create: `artifacts/verification/m2/manifest.json`
- Create: `artifacts/verification/m2/review.md`
- Create: `artifacts/verification/m2/known-limitations.md`
- Create: `artifacts/verification/m2/toolchain.txt`
- Update local-only: `.superpowers/sdd/2026-07-23-m2-policy-tools/progress.md`

**Interfaces:**
- Exercises the complete `Tauri -> application use case -> policy/approval -> structured broker -> Windows/Git/filesystem adapter -> SQLite/artifact/event audit` slice with real local boundaries and inert hostile probes. Produces tamper-evident command/evidence output and an independent spec/code-quality decision.

- [x] **Step 1 - Write the failing complete security matrix**

The probe attempts each denied action through direct OS APIs rather than cooperating with the broker. Run it through every enabled process profile and exercise every structured read/write/status/diff path. Include canaries in the repository, original checkout, sibling worktree, user profile, application data, credential/registry locations, and capability-adjacent directories; denied loopback/LAN/internet targets; inherited environment/provider credentials; named pipes; junction/symlink, UNC, device, ADS, case-folding, Unicode, long-path, and replacement races; stale fencing; executable/PATH substitution; shell metacharacters; response files; breakaway/detached descendants; and output, process-count, memory, CPU, wall-time, and disk budgets.

Assert every marker remains absent, every denied result has a non-leaking typed classification, no child survives cancellation/app exit, the original checkout/index/HEAD is unchanged, and all decisions/approvals/intents/executions/outputs/writes/events are reconstructible with matching hashes and observation labels. Prove a requested but unenforceable network/identity/ACL/Job boundary starts no process.

```powershell
cargo test -p local-agent-terminal-tool-runtime --test security_matrix
cargo test -p local-agent-terminal-platform-windows --test filesystem_matrix --test process_matrix
cargo test -p local-agent-terminal-bootstrap --test tool_broker_e2e
```

Expected RED: the aggregate matrix, probe, and some full-slice assertions are absent.

- [x] **Step 2 - Close only matrix gaps and wire CI**

Add the smallest fixtures or adapter corrections needed for the matrix. Do not weaken a denied canary, skip a supported Windows runner, grant the probe repository/user-profile access, or reclassify a failed enforcement control as success. CI runs the exact containment tests on the supported Windows profile before any future test may execute untrusted repository code.

Add evidence-contract tests that reject dirty tracked source outside `artifacts/verification/m2/**`, stale/non-ancestor source commits, missing/failed commands, skipped containment cases, mismatched output hashes, changed toolchain/platform, tampered review/limitations artifacts, absent post-final contract output, and any diff under the immutable design directory.

- [ ] **Step 3 - Run the complete M2 gate from a clean source commit**

Commit the final production/test correction before generating evidence:

```powershell
git add Cargo.toml Cargo.lock crates tests apps/desktop .github scripts
git diff --cached --check
git commit -m "test: complete m2 containment matrix"
```

Then run:

```powershell
pnpm install --frozen-lockfile
node --test tests/contracts/*.test.mjs
node scripts/verify-design-contracts.mjs
node scripts/check-architecture.mjs
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace --all-targets
cargo test --workspace --doc
cargo test -p local-agent-terminal-tool-runtime --test security_matrix
cargo test -p local-agent-terminal-platform-windows --test filesystem_matrix --test process_matrix
cargo test -p local-agent-terminal-bootstrap --test tool_broker_e2e --test tool_recovery
pnpm --dir apps/desktop test --run
pnpm --dir apps/desktop exec playwright install chromium
pnpm --dir apps/desktop test:browser
pnpm --dir apps/desktop build
cargo build -p local-agent-terminal-desktop
git diff --check
git diff --exit-code 321734f -- docs/multi-agent-terminal-design
node scripts/run-m2-evidence.mjs
node scripts/verify-m2-evidence.mjs
node scripts/run-m2-post-final-contracts.mjs
node scripts/verify-m2-post-final-log.mjs
```

Expected GREEN: all gates pass on Windows, the design diff is empty, evidence binds the exact source commit and every required containment classification, and post-final verifier contracts run without skip.

- [ ] **Step 4 - Perform task-scoped and broad independent reviews**

For each Task 1 through 9 commit, use a fresh reviewer to compare the task diff with this plan and the normative design. Fix every Critical or Important finding with a focused failing test, a minimal correction, fresh focused/full evidence as applicable, and a re-review.

After Step 3, build one baseline-to-HEAD review package. A separate reviewer checks all M2 exit criteria and specifically searches for ambient OS paths, fail-open policy/scanner errors, incomplete canonical binding, approval TOCTOU, stale-writer effects, unsafe retries, FK bypass, subprocess/shell/PATH access outside `platform-windows`, Job escape, network fallback, audit omissions, raw React capabilities, accessibility regressions, and hidden M3/M5 scope. M2 is not approved until no Critical or Important finding remains and evidence is fresh.

- [ ] **Step 5 - Finalize evidence and commit approval artifacts**

Write `review.md` with independent spec and code-quality verdicts and `known-limitations.md` even if it says `None`. Regenerate the artifact hashes, verify them, and commit only evidence output:

```powershell
node scripts/run-m2-evidence.mjs
node scripts/verify-m2-evidence.mjs
node scripts/run-m2-post-final-contracts.mjs
node scripts/verify-m2-post-final-log.mjs
git add artifacts/verification/m2
git diff --cached --check
git commit -m "test: record approved m2 evidence"
```

## Definition of Done

- A versioned evaluator uses deterministic deny-overrides semantics and binds complete actor, resource, action, purpose, phase, policy snapshot, expiry, and effective payload data. Missing/unverifiable enforcement denies.
- Classification and secret scanning cover direct content, indexes, filenames, metadata, Git/diff/tool output, errors, summaries, artifacts, and final serialized outbound bytes. Redaction evidence binds original/effective digests without leaking secret bytes.
- Agents and React receive logical capabilities and immutable DTOs only. They have no ambient OS path, shell, process, Git, credential, registry, environment, network, approval-payload, or database capability.
- Tool and policy-exception approvals validate the exact v1 schema, reject unknown fields, use RFC 8785 plus SHA-256, expire, and are invalidated by every bound actor/resource/purpose/phase/policy/workspace/executable/argv/cwd/environment/network/write-scope/fencing/nonce change. The digest is recomputed immediately before effect.
- SQLite retains FK-valid, idempotent, transactionally consistent policy decisions, approvals, operation intents, tool executions, outputs, writes, events, and projections. Restart never silently repeats an indeterminate non-repeatable process.
- Filesystem tools resolve trusted logical capabilities through retained Windows handles, reject traversal/reparse/UNC/device/ADS/case/long-path escapes, recheck fencing immediately before writes, hash results, and trigger authoritative workspace mutation/invalidation.
- Git status/diff are typed in-process operations. Hooks, filters, helpers, external diff/textconv, LFS, submodules, remote transports, PATH, response files, and repository-controlled executables remain disabled and inert.
- `process.exec` uses a registered absolute executable plus argv, verified executable identity/digest, empty-by-default environment profile, enforced network profile, capability cwd, limits, and expected writes. A brokered process has no repository/worktree ACL; repository-controlled execution requires a separately approved contained worker and otherwise stays disabled. Default policy denies `shell.raw`; no shell syntax is inferred.
- Every enabled process is assigned before resume to a verified kill-on-close/no-breakaway Job Object inside the promised identity/ACL/network boundary. Cancellation, timeout, output overflow, shutdown, and crash leave no descendant. Unavailable controls fail closed with no full-token fallback or sandbox overclaim.
- The broker follows durable intent, fence, policy, digest/approval, immediate revalidation, effect, audit, and recovery ordering. Denied/stale/invalid approval paths have zero side effect; outputs, writes, duration, status, decisions, and cancellations are auditable.
- The Tauri/React view cannot replace an operation, invalidates stale dialogs, exposes exact safe approval context, supports cancel/stop-all, and passes keyboard, focus, live-region, contrast, reduced-motion, 200% zoom/reflow, and real-browser axe checks.
- Every denied canary across every tool path fails, the original checkout/index/HEAD remains unchanged, all complete Rust/Node/frontend/browser/Tauri/Windows gates pass, the immutable design diff is empty, evidence is reproducible, and independent review has no unresolved Critical or Important finding.
- No M3 protocol/provider implementation and no M5 candidate-tree/final-commit implementation was introduced.
