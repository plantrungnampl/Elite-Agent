# M4 Context and Deliberation — Derived Execution Design

Date: 2026-08-09

Status: Approved architecture choice; pending written-spec review

Milestone: M4 — Context and deliberation

## 1. Authority and scope

This document is an implementation design derived from the normative package in
docs/multi-agent-terminal-design. It does not amend or replace that package.
When this document and a normative contract disagree, the normative contract
wins.

The selected heterogeneous integration is a second built-in trusted
core_adapter for Anthropic's Messages API. A brokered_process adapter is not part
of M4.

M4 delivers:

- secret and sensitivity filtering before any index write;
- keyword and metadata retrieval over revision-bound repository evidence;
- immutable, role-specific context packages with exact effective bytes;
- independent analysis, controlled cross-review, bounded specialist requests,
  claim verification, evidence-linked synthesis, final objection, and plan
  approval;
- a second heterogeneous built-in provider adapter;
- a typed desktop view for deliberation, context inspection, evidence, and plan
  approval;
- reproducible evidence proving policy-compliant context, preserved dissent,
  heterogeneous independent proposals, and zero pre-approval repository
  mutation.

## 2. Non-goals

M4 does not implement:

- vector embeddings, semantic retrieval, or repository-graph retrieval;
- verified long-term project-memory promotion;
- a brokered or isolated external agent process;
- the fenced write executor, candidate Git tree, repair loop, or exact-tree
  commit;
- live-provider calls in the release gate;
- generic shell, filesystem, Git mutation, or user-supplied provider endpoints.

Vector and graph retrieval remain M6 work. Controlled writes and exact-tree
commit remain M5 work.

## 3. Architectural boundaries

The implementation preserves the repository's inward dependency direction.

### 3.1 Domain

crates/domain owns pure, validated value objects and invariants for:

- source documents and chunks;
- context queries, retrieved evidence, redactions, provenance, and immutable
  packages;
- proposals, reviews, specialist requests, material claims, claim verification,
  decision packages, objections, and plan approval bindings;
- independent-quorum, evidence-citation, dissent-preservation, bounded-round,
  and approval-digest rules.

Domain code has no filesystem, database, HTTP, provider, Tauri, process, or
clock dependency.

### 3.2 Application

crates/application owns ports and use cases for:

- reading a coherent repository snapshot without mutation;
- classifying and disclosing candidate content through policy;
- persisting source metadata, chunks, context packages, messages, claims,
  decisions, approvals, events, and immutable artifacts;
- building context, querying context, starting deliberation, answering bounded
  agent requests, verifying claims, closing objection rounds, and resolving
  plan approval;
- projecting typed task, context, evidence, deliberation, and approval DTOs.

Application services sequence ports and define transaction boundaries. They do
not construct concrete adapters.

### 3.3 Context engine

A new crates/context-engine adapter implements deterministic indexing,
keyword/metadata retrieval, ranking, deduplication, freshness checks, token
budgeting, and exact context-package serialization. It depends only on domain
and application ports.

It does not call SQLite, policy-engine, repository-git, or storage-files through
concrete types. Bootstrap injects those adapters behind application-owned
ports.

### 3.4 Orchestration

A new crates/orchestration crate coordinates work inside the normative workflow
phases. It depends only on domain and application.

It:

- dispatches work only after the durable workflow command succeeds;
- uses agent capabilities and equality of recorded family identities for
  eligibility, never provider-name branches;
- keeps independent proposals hidden until quorum;
- assigns bounded review edges;
- routes context and specialist requests through application ports;
- requires every material claim to reach a terminal verification class;
- creates immutable decision and approval artifacts;
- resumes from durable state without repeating non-idempotent work.

Model output may propose a command or artifact, but only deterministic
application/domain code may accept it and advance workflow state.

### 3.5 Provider adapter

A new crates/provider-anthropic adapter implements agent-protocol's ProtocolPeer
for Anthropic Messages API:

- endpoint: POST /v1/messages;
- authentication: x-api-key supplied from the trusted bootstrap configuration;
- required version header: anthropic-version;
- streaming: named SSE events with bounded incremental text;
- model and generation parameters: taken only from the bound run configuration;
- terminal output: mapped into the same provider-neutral protocol result used by
  provider-openai.

The API key is never serialized into Debug output, SQLite, artifacts, errors,
DTOs, logs, or evidence. Production permits only the configured HTTPS provider
endpoint. Loopback HTTP exists only behind test construction.

### 3.6 Bootstrap and presentation

crates/bootstrap is the sole composition root. It constructs both built-in
provider peers, the context engine, orchestration services, storage adapters,
policy adapter, and repository snapshot adapter.

Tauri exposes a narrow allowlist of immutable DTO commands. React calls them
only through apps/desktop/src/api and never supplies an operation payload,
provider request, path, policy decision, workflow event, or plan contents for
approval.

## 4. Context ingestion and retrieval

### 4.1 Coherent read snapshot

Context ingestion starts from an authoritative repository identity containing:

- project and task identity;
- base Git revision;
- logical path;
- exact content hash;
- current workspace fingerprint;
- captured timestamp from the trusted clock.

The repository adapter returns bytes and identity from one coherent read. If
the revision, path identity, or content hash changes during the read, ingestion
fails closed and the item is retried only from a fresh snapshot.

### 4.2 Pre-index filtering

Every candidate passes this order before any source document, chunk, keyword,
metadata cache, summary, or artifact containing candidate bytes is written:

1. classify the logical metadata, including filename and symbol;
2. scan the content for known secret, restricted, and prompt-injection patterns;
3. evaluate disclosure policy for the target task, role, trust tier, purpose,
   and policy snapshot;
4. deny the item or produce stable redacted bytes plus a redaction report;
5. scan the exact candidate index record again;
6. persist only the allowed/redacted form.

A denied item creates no chunk and no content-bearing artifact. When audit
metadata is required, its logical path is replaced by a stable redacted
identifier so a sensitive filename cannot leak through the index.

The existing policy-engine scanner and disclosure semantics are reused through
application ports. M4 does not create a second secret-classification system.

### 4.3 Source persistence

The existing normative source_documents and source_chunks tables store
searchable metadata. Chunk bytes live in the content-addressed artifact store;
metadata carries the immutable artifact reference, source revision, logical
path or stable redacted identifier, line range, optional symbol, language,
sensitivity, content hash, and classification digest.

Keyword indexes are explicitly non-authoritative and may be rebuilt from
current source metadata and verified chunk artifacts. A missing or corrupt
keyword index degrades to metadata/path retrieval; it never makes stale or
unverified content authoritative.

### 4.4 Retrieval

The M4 retrieval sequence is:

1. policy pre-filter the query and eligible source classes;
2. retrieve keyword and metadata candidates;
3. rank exact logical-path, symbol, term, task-file, accepted-decision, role,
   and freshness matches;
4. deduplicate by authoritative source identity and content hash;
5. revalidate revision and content hash;
6. apply item-level disclosure and redaction;
7. allocate the role-sensitive token budget;
8. serialize the complete outbound package;
9. scan the exact serialized bytes;
10. bind content digest, policy snapshot, decisions, redaction report, retrieval
    version, prompt version, and provenance;
11. persist the exact effective bytes as an immutable artifact before dispatch.

Stale content is excluded by default. The package builder never silently
replaces a cited revision with newer bytes.

### 4.5 Context query requests

An agent context-query request is accepted only when:

- the peer declared the capability;
- the run is active and bound to the same task and connection;
- the requested resource class and purpose are allowed;
- item, token, request-count, and deadline budgets remain;
- returned evidence passes the same retrieval, freshness, redaction, and final
  serialization checks.

Every request receives one typed response. Tool requests remain denied in all
pre-plan phases.

## 5. Immutable context package

The effective package contains:

- package, task, agent, role, objective, and creation identity;
- task scope, risk, phase, budget, and policy constraints;
- shared summary, accepted decisions, and unresolved objections allowed for the
  role;
- bounded active-thread messages;
- retrieved chunks with revision/hash-bound citations;
- permissions and available protocol capabilities;
- provenance and redaction entries;
- all item-level policy decision IDs;
- policy, prompt-template, retrieval-pipeline, tokenizer, and schema versions;
- exact content hash.

Independent analyzers receive role-specific packages built before either
proposal is visible. The stored effective bytes are the bytes supplied to the
provider mapping. Reconstructibility includes the run configuration, adapter
version, provider/model identifiers, generation parameters, response schema,
manifest/executable identity, and authoritative core receipt time.

## 6. Deliberation lifecycle

### 6.1 ContextBuild

The orchestrator captures the repository fingerprint, indexes allowed content,
selects two eligible heterogeneous agents, builds their packages, and persists
all dispatch bindings. It advances only when both required packages validate.

### 6.2 ParallelAnalysis

Two independent proposer runs are required when both configured adapters are
eligible. Independence means:

- different agent identities;
- different recorded provider/model-family keys for the M4 gate;
- neither package includes the other proposal;
- proposal artifacts remain private to orchestration until quorum.

Provider/model identity is compared only for diversity and audit. It never
selects provider-specific orchestration behavior.

If one provider is unavailable, the task remains in the current phase with a
typed blocked or budget condition. The M4 heterogeneous gate cannot pass in a
single-provider degraded run.

### 6.3 CrossReview

After quorum, the orchestrator publishes only the selected immutable proposal
artifacts and assigns explicit review edges. It does not broadcast every
artifact to every participant.

Review packages contain the target proposal, relevant evidence, known
objections, and bounded parent context. Reviews must cite evidence for material
factual claims and identify agreement, contradiction, omission, feasibility,
and policy risk.

### 6.4 Specialist requests and threads

An agent may request a specialist only through the typed protocol request. The
orchestrator validates:

- requesting run, task, phase, capability, and reason;
- requested role/skill availability;
- maximum agents, concurrent runs, round count, tokens, cost, and deadline;
- exact required context references;
- policy and disclosure eligibility.

Accepted requests create a bounded context package and direct thread. Rejected
requests receive a typed reason. A thread promotes only its accepted summary,
evidence, and unresolved objections to the shared room.

### 6.5 PrePlanVerification

Every material claim is extracted into a stable claim record containing its
source artifact, citation set, claimant, and expected verification method.

Deterministic evidence checks run first. A verifier agent may analyze evidence
but cannot set trusted state directly. Application code assigns exactly one
terminal classification:

- verified;
- rejected;
- inconclusive;
- not_applicable.

Revision or hash mismatch makes the citation stale and prevents verified
status. Agent confidence never changes verification state.

### 6.6 Synthesis

The lead receives only the classified claim set, immutable proposals/reviews,
accepted thread summaries, and remaining objections. The decision package must
contain:

- selected approach;
- rejected alternatives and reasons;
- verified evidence;
- explicitly marked inconclusive material;
- remaining dissent without lossy majority collapse;
- affected files and implementation steps;
- planned tools and verification profile;
- rollback plan, risk, confidence, cost, and duration.

Schema, evidence references, and dissent preservation are validated before the
draft is accepted.

### 6.7 FinalObjection

Each eligible participant may file one structured objection containing
severity, impact, evidence, and violated requirement or invariant.

A credible severe objection may reopen one bounded CrossReview round. The
orchestrator preserves the superseded draft and objection history. When no
accepted severe objection remains, it creates the plan approval request.

### 6.8 AwaitingPlanApproval

The canonical plan approval binding contains:

- plan artifact ID, content digest, and version;
- base commit and repository fingerprint;
- policy snapshot;
- task scope and writable scope;
- allowed tools and verification profile;
- actor and task identity;
- fencing epoch reserved for later implementation;
- request time and expiry.

Approve, revise, reopen, replace/add agent, and reject are distinct typed user
actions. Approve supplies only approval ID, displayed digest, expected task
version, and actor identity. The core reloads canonical bytes and recomputes the
digest before changing phase.

Revision returns to Synthesis and preserves history. Reopen returns to bounded
discussion. Reject cancels or preserves the task according to the selected
action.

## 7. Zero pre-approval mutation

Before a valid plan approval:

- no executor lease is granted;
- no write-capable tool schema is exposed to an agent;
- protocol tool requests receive policy_denied;
- repository-git exposes snapshot/read operations only;
- no worktree, branch, ref, index, tracked file, untracked file, hook, or
  repository-local artifact directory is created or modified;
- SQLite and content-addressed artifacts remain under application data, outside
  the repository;
- every phase boundary rechecks the repository fingerprint;
- an out-of-band repository mutation blocks the workflow and invalidates
  affected packages and approval requests.

The M4 end-to-end gate records the authoritative repository state before task
start and after plan approval/rejection and proves byte-for-byte identity of
the repository-visible state.

## 8. Anthropic core adapter

The adapter follows the same lifecycle and conformance contract as
provider-openai:

- exact descriptor, manifest, connection, and core executable digest binding;
- one acceptance per run;
- bounded request body and response stream;
- monotonically increasing provider-neutral deltas;
- exactly one authoritative terminal result;
- cancellation, timeout, shutdown, and worker-join handling;
- typed HTTP, malformed-stream, usage, refusal, overload, and retry-after
  classification;
- no provider DTO crossing into domain, application, orchestration, Tauri, or
  React.

The request mapper uses the bound role/objective and immutable effective context
to create the provider request. It sends the configured model, max output
tokens, optional temperature, stream flag, stable system instructions, and one
user content block carrying the exact effective context representation.

The SSE parser accepts the documented message/content-block lifecycle, ignores
permitted ping events, bounds event and aggregate sizes, maps only text deltas
to presentation streaming, records usage from authoritative message events, and
fails closed on gaps, invalid order, duplicate terminal events, unknown
required shapes, or missing terminal text.

Tests use a deterministic loopback server. No live key or billable call is part
of CI or milestone evidence.

## 9. Desktop behavior

The task workspace adds:

- workflow rail with the current phase, blockers, rounds, and approval gate;
- agent roster with role, provider/locality, status, context scope, usage, trust
  tier, and health;
- shared-room cards that visibly distinguish proposal, critique, evidence,
  objection, decision, redaction, and stale evidence;
- bounded thread view;
- evidence panel with revision, hash, line/symbol metadata, verification state,
  and stale warning;
- Context Inspector showing the exact immutable package, provenance, policy
  decisions, and stable redaction markers;
- Plan Approval view showing selected/rejected approaches, agreement map,
  unresolved dissent, affected files, planned commands, security impact, cost,
  duration, plan version, policy snapshot, and operation digest.

The approval page has one visually primary action: Approve plan. Revise, reopen,
replace/add agent, and reject remain plainly labeled secondary actions. The UI
shows progress and terminal feedback, restores focus after dialogs, exposes
live-region status, works without hover, supports keyboard operation and 200%
zoom/reflow, honors reduced motion, and never relies on color alone.

A stale digest, task version, policy snapshot, repository fingerprint, agent
identity, or expiry closes the approval action and tells the user what changed
and how to refresh.

## 10. Persistence and recovery

M4 uses the existing normative SQLite tables:

- source_documents and source_chunks for searchable source metadata;
- context_packages and context_package_policy_decisions for reconstructible
  inputs;
- agent_descriptors, agent_runs, messages, artifacts, events, approvals, and
  operation_intents for durable workflow state.

Proposals, reviews, claim sets, decision packages, objection sets, package
payloads, redaction reports, and plan versions are immutable artifacts. Events
and projections reference their exact hashes.

Startup recovery:

1. replays the task stream through the normative workflow reducer;
2. reconciles pending artifact operations;
3. interrupts runs without authoritative terminal evidence;
4. validates package artifacts, policy bindings, and provider connections;
5. reconstructs proposal visibility, review edges, claims, objections, and open
   approval;
6. rechecks the repository fingerprint;
7. resumes only idempotent missing dispatch or waits for explicit user action.

Provider requests are not blindly retried. A retry creates a new run ID and
explicit supersession binding.

## 11. Error semantics

Errors crossing application boundaries remain typed and safe:

- invalid input for malformed IDs, schemas, citations, budgets, or transitions;
- permission denied for policy, capability, phase, or disclosure denial;
- conflict for stale versions, changed digests, duplicate bindings, or quorum
  races;
- not found for missing immutable references;
- unavailable for provider/index dependencies;
- integrity failure for hash, revision, artifact, event, or reconstruction
  mismatch;
- indeterminate only when an external operation's outcome cannot be proven.

Errors never include source bytes, secret matches, API keys, full provider
responses, physical paths, or attacker-controlled terminal text.

## 12. Verification strategy

Implementation follows test-driven development in these layers:

1. architecture contracts for new crate boundaries, provider isolation, typed
   Tauri commands, frontend API routing, and immutable normative docs;
2. domain unit/property tests for package, citation, quorum, bounded-round,
   claim-state, dissent, approval, and zero-write invariants;
3. context-engine tests for pre-index denial, stable redaction, keyword/metadata
   retrieval, ranking, freshness, token budgets, final scans, and deterministic
   serialization;
4. storage integration and crash tests for source records, package-policy
   relations, private proposal visibility, claims, decisions, objections,
   approvals, and recovery;
5. orchestration tests using deterministic proposer, critic, verifier,
   malicious, slow, and crashing peers;
6. Anthropic request, SSE, cancellation, outage, malformed-response, usage,
   conformance, and credential-nondisclosure tests;
7. bootstrap E2E proving two heterogeneous independent proposals, controlled
   review, bounded specialist handling, verified claims, preserved dissent,
   objection reopen, digest-bound plan approval, and no repository mutation;
8. React unit, real-browser accessibility, stale-approval, keyboard, focus,
   live-region, contrast, and reflow tests;
9. full Rust, frontend, browser, architecture, security, recovery, and evidence
   gates.

The M4 evidence manifest records commands, pinned tool versions, timestamps,
exit codes, output hashes, source commit, policy snapshot, package hashes,
provider fixture identities, proposal-family identities, plan digest, and
pre/post repository fingerprint. Evidence contains no prompts, source code,
provider output, paths, credentials, or secrets.

## 13. Acceptance criteria

M4 is complete only when:

1. secret or denied metadata/content cannot enter any index, cache, package, or
   outbound provider request;
2. every retrieved citation is bound to source revision, content hash, and
   precise range/symbol metadata when available;
3. every package is role-specific, policy-compliant, immutable, reconstructible,
   and linked to all item-level policy decisions;
4. OpenAI and Anthropic deterministic fixtures produce independent proposals
   without seeing each other's proposal before quorum;
5. cross-review and specialist requests remain within explicit edges and
   budgets;
6. every material claim has a terminal verification class before synthesis;
7. the decision package preserves rejected alternatives and unresolved dissent;
8. a severe accepted objection reopens a bounded review round;
9. plan approval is valid only for the exact canonical digest and inputs;
10. no repository-visible state changes before plan approval;
11. provider outage or malformed output cannot corrupt workflow, artifacts, or
    another provider run;
12. desktop context and approval views expose exact safe core DTOs and pass the
    accessibility contracts;
13. all M0–M3 regressions and complete M4 evidence gates pass;
14. the normative design directory has no implementation-authored diff.

## 14. Delivery sequence

After this written design is reviewed, the implementation plan will decompose
the work into small, independently verifiable tasks:

1. pin executable M4 architecture and evidence contracts;
2. add pure context and deliberation domain rules;
3. add application ports, use cases, canonical plan approval, and DTOs;
4. persist source, package, deliberation, approval, and recovery state;
5. implement pre-index filtering and keyword/metadata context engine;
6. extend agent runtime for bounded context/specialist requests;
7. implement deterministic deliberation orchestration;
8. add and compose the Anthropic core adapter with multi-provider runtime;
9. expose typed Tauri controls and accessible desktop views;
10. run the end-to-end security/recovery matrix, independent review, and M4
    evidence gate.
