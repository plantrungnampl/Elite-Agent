# MVP Delivery Roadmap

## 1. Delivery strategy

Build a narrow vertical slice without violating the final product's security
claims. Policy, operation journaling, fencing, and safe tool execution precede
cloud disclosure or external agent execution. Vector retrieval, automatic
memory, PTY compatibility, and third-party plugins are later capabilities, not
prerequisites for proving the workflow.

Each milestone must leave the application in a releasable internal state. A
later milestone may add an adapter or index, but cannot retrofit the core trust
boundary.

## 2. Milestone 0 — Domain and persistence foundation

Deliverables:

- Rust workspace and React/Tauri shell;
- pure domain state and transition guards;
- application use cases and owned output ports;
- explicit bootstrap composition root;
- SQLite migrations from [`schemas/sqlite-v1.sql`](schemas/sqlite-v1.sql);
- content-addressed artifact store and operation journal;
- structured logging with trust labels;
- CI checks for forbidden dependency edges and crate cycles.

Exit criteria:

- domain tests run without Tauri, database, provider, shell, or OS services;
- event append and projection update use optimistic concurrency;
- crash injection across artifact-write boundaries reconciles deterministically;
- application startup validates schema and artifact roots.

## 3. Milestone 1 — Repository isolation and recovery

Deliverables:

- repository health validation;
- stable repository identity and base-commit capture;
- branch/worktree manager;
- executor lease and monotonically increasing fencing token;
- workspace mutation monitor;
- startup reconciliation for worktrees, leases, intents, and artifacts;
- task timeline and recovery UI.

Exit criteria:

- a task creates an isolated worktree without changing the user's checked-out
  working tree;
- a stale token cannot write;
- an out-of-band change enters `WorkspaceDirty`;
- restart reconstructs the task and never silently repeats an unknown command;
- Windows path, junction, long-path, Unicode, lock, submodule, and LFS cases
  have explicit test results.

## 4. Milestone 2 — Policy and structured tool broker

Deliverables:

- versioned policy evaluator with deny-overrides semantics;
- file classification and secret scanning;
- structured filesystem, Git, diff, and process tools;
- canonical operation digest and approval flow;
- absolute executable resolution and environment profiles;
- network policy adapter;
- Job Object lifecycle integration;
- no raw shell in the default profile.

Exit criteria:

- denied canary files cannot be read through any tool;
- process execution uses executable plus argv, never inferred shell syntax;
- changing canonical input invalidates approval;
- command cancellation terminates the process tree;
- tool output, writes, and policy decisions are auditable;
- inability to enforce a requested boundary fails closed.

## 5. Milestone 3 — Protocol and one trusted adapter

Deliverables:

- JSON-RPC v1 implementation and generated schema types;
- deterministic fake proposer, critic, verifier, malicious, slow, and crashing
  agents;
- one built-in `core_adapter` for an API provider;
- identity, manifest, executable, and connection binding;
- streaming, limits, cancellation, heartbeat, and terminal result validation;
- protocol conformance suite.

Exit criteria:

- every request that expects a result has a JSON-RPC ID;
- malformed frames, sequence gaps, duplicate terminal results, and oversize
  output fail safely;
- exact effective context and run configuration are reconstructible;
- provider outage or crash cannot corrupt workflow state.

## 6. Milestone 4 — Context and deliberation

Deliverables:

- repository scanner with pre-index secret filtering;
- keyword and metadata retrieval;
- immutable context-package builder;
- independent analysis and controlled cross-review;
- direct threads and bounded specialist requests;
- pre-plan claim verification;
- synthesis, final objection, and plan approval;
- second heterogeneous built-in adapter or a `brokered_process` that has passed
  the containment suite.

Exit criteria:

- two heterogeneous agents produce independent proposals;
- each receives only policy-compliant, role-specific context;
- claims cite revision- and hash-bound evidence;
- a lead produces an evidence-linked plan preserving dissent;
- no repository file mutation occurs before approval.

## 7. Milestone 5 — Controlled implementation and exact-tree commit

Deliverables:

- one fenced executor;
- mediated writes and plan-step tracking;
- candidate Git-tree materialization;
- verification profiles run against the candidate tree and bounded repair;
- final reviewer and scope-drift detection;
- final approval schema and immutable approval DTO;
- exact-tree local commit with explicit hook policy.

Exit criteria:

- every write checks the current fencing token;
- final review inspects an immutable candidate tree;
- any later workspace mutation invalidates approval;
- the resulting commit tree equals the approved tree ID;
- original user working-tree content remains unchanged;
- crash at each finalization boundary has a deterministic recovery path.

This milestone is the first external MVP candidate.

## 8. Milestone 6 — Retrieval and verified memory

Deliverables:

- embedded vector-store adapter and local embedding model;
- optional repository graph behind `RepositoryGraph`;
- incremental invalidation and degraded mode;
- thread and phase summaries;
- project-memory candidate, verification, approval, supersession, and retraction;
- context cost and retrieval diagnostics.

Exit criteria:

- vector or graph failure degrades to authoritative file/event retrieval;
- stale chunks and edges are rejected;
- secret material never reaches an index;
- model agreement alone cannot promote memory;
- memory entries retain authoritative source references.

## 9. Milestone 7 — Production hardening

Deliverables:

- WebView CSP and IPC security suite;
- terminal OSC/ANSI safety controls;
- untrusted-process containment suite;
- crash, power-loss, disk-full, and fault-injection matrix;
- signed installer and signed update metadata;
- backward-compatible migration and complete rollback testing;
- resource controls and large-repository benchmarks;
- accessibility pass and user-generated diagnostics.

Exit criteria:

- every release gate in the testing strategy passes;
- no critical/high security finding remains;
- update failure restores a compatible complete state;
- performance results declare corpus, hardware, cache state, sample count, and
  percentiles;
- recovery and trust limitations are documented in the product UI.

## 10. Explicitly deferred

- Git push and pull requests;
- multi-user collaboration and cloud sync;
- remote distributed workers;
- visual workflow authoring;
- simultaneous writers, including “non-overlapping” writers;
- full-access legacy coding CLIs;
- unsigned third-party executable plugins;
- automatic raw PowerShell or command-shell access;
- workflow/provider marketplace;
- mobile client and enterprise organization controls.

## 11. Recommended demonstrations

### Internal security slice

1. Import a hostile test repository.
2. Start a task and create an isolated worktree.
3. Demonstrate denied secret, path-escape, network, and stale-token requests.
4. Crash at an artifact-journal boundary.
5. Restart and show deterministic reconciliation.

### Product-value slice

1. Two trusted heterogeneous adapters analyze a failing authentication test.
2. They critique each other and verify repository evidence.
3. Lead creates a plan; user approves.
4. One fenced executor changes the isolated worktree.
5. Verification fails once; bounded repair succeeds.
6. Final reviewer inspects the candidate Git tree.
7. User approves the exact tree.
8. The created commit is proven to contain the same tree ID.

Together these demonstrations prove both the collaboration value and the
security/recovery claims without requiring a plugin ecosystem.
