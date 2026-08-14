# Testing and Reliability Strategy

> **v4.3 authority notice:** the current package gate includes `validation/validate_v43_implementation_product_proof.py` and the equal-budget orchestration benchmark defined in `40-orchestration-product-proof-benchmark.md`.


## 1. Quality goals

- deterministic workflow behavior;
- no unauthorized data access;
- recoverable local state;
- reproducible context packages;
- safe process and worktree lifecycle;
- provider failures do not corrupt tasks;
- final commits correspond to approved and verified changes.

## 2. Test pyramid

### Unit tests

Focus on pure domain logic:

- state transition guards;
- agent eligibility and role assignment;
- budget enforcement;
- policy rule evaluation;
- context ranking and token allocation;
- message and event validation;
- path canonicalization;
- approval digest calculation;
- stale chunk detection.
- executor lease and fencing-token guards;
- canonical JSON and approval digest generation;
- operation idempotency classification;
- workspace mutation invalidation;
- workflow transition table conformance.

### Contract tests

- agent protocol request/response schemas;
- transport framing and streaming order;
- adapter capability negotiation;
- vector-store interface behavior;
- event-store optimistic concurrency;
- artifact-store atomicity;
- Tauri command DTO compatibility.
- bidirectional JSON-RPC request/response ownership;
- exactly-one run terminal result;
- stream duplicate/gap/out-of-order handling;
- protocol frame and output limits;
- approval-digest schema compatibility.

### Executable SQLite contract regression

The checked-in `validation/validate_v3.py` suite is a minimum structural gate, not a substitute for runtime acceptance. It must reject direct task updates without a row-version increment, cross-task run/message/protocol bindings, mutable authority identity, evidence overwrite or clearing, deletion of attempt/protocol history, terminal reversal, and protocol sequence gaps. Every newly discovered SQL counterexample is added as a failing test before its trigger is changed.

### Integration tests

- SQLite transactions and recovery;
- filesystem artifact persistence;
- Git branch/worktree creation and cleanup;
- ConPTY process lifecycle;
- tool mediation and output capture;
- context retrieval with redaction;
- provider adapter retries and cancellation.
- operation-intent claiming and lease expiry;
- artifact journal reconciliation at every crash boundary;
- exact-object finalization using an isolated Git index;
- stale executor rejection;
- consistent SQLite online backup and restore;
- Tauri IPC authorization and terminal escape filtering.

### End-to-end tests

Use temporary repositories and deterministic fake agents.

Critical E2E scenarios:

1. Successful task from intake to local commit.
2. Conflicting proposals resolved by cross-review.
3. Severe final objection reopens discussion.
4. User rejects plan before any file mutation.
5. Verification fails, repair succeeds.
6. Repair limit is exceeded and task stops safely.
7. App restarts during analysis and resumes.
8. App restarts during tool execution and marks operation interrupted.
9. Cloud agent requests denied secret file.
10. Agent process hangs and its process tree is terminated.
11. Original repository working tree remains unchanged.
12. Final review detects out-of-plan file modification.
13. User terminal mutation enters `WorkspaceDirty` and invalidates approval.
14. A stale executor process cannot write after a newer lease is issued.
15. Commit tree equals the approved candidate tree.
16. Crash after artifact rename but before metadata completion reconciles safely.
17. Crash after provider request dispatch never silently repeats an
    indeterminate non-idempotent operation.
18. Forward migration followed by failed startup restores a compatible complete
    backup or remains on the new compatible schema.
19. Git hook behavior matches the approved hook policy.
20. An untrusted agent fails denied file, registry, credential, network,
    junction, child-process, and user-profile canary tests.

## 3. Deterministic fake agents

Create protocol-compatible fixtures:

- proposer agent;
- critic agent;
- verifier agent;
- executor agent;
- malformed-output agent;
- slow agent;
- crashing agent;
- malicious prompt-injection agent;
- context-overflow agent.

These make orchestration tests independent of external model behavior and cost.

## 4. Property-based tests

Useful invariants:

- event sequence is strictly increasing per stream;
- replay of the same stream yields the same workflow state;
- denied resources never appear in a context package;
- a path accepted by the tool runtime always remains under an authorized root;
- only the executor lease holder may write;
- approval is valid only for the exact operation digest;
- budget counters never decrease;
- no terminal phase transitions back to an active phase;
- every task mutation increments `row_version` exactly once;
- no run, message, protocol request, response artifact, or execution authority edge crosses task scope;
- retained attempt/protocol history cannot be deleted and recreated to reset evidence or replay state.
- fencing tokens never repeat and older tokens never regain authority;
- a commit created after approval has the approved tree ID;
- a context package contains every referenced policy decision and exact
  effective-content digest;
- an indeterminate non-repeatable operation is never automatically retried;
- every transition emitted by the implementation exists in the normative
  transition specification.

## 5. Fault injection

Inject failures at boundaries:

- after event append but before dispatch;
- after child process start but before PID persistence;
- during artifact write before rename;
- during vector update;
- during worktree creation;
- during commit creation;
- between approval and execution;
- provider timeout after partial stream.
- after artifact intent but before temp write;
- after artifact fsync but before rename;
- after artifact rename but before SQLite completion;
- after executor lease replacement but before stale-process termination;
- after final tree creation but before approval persistence;
- after approval but before exact-object commit;
- during online backup and migration health check;
- on disk full, access denied, sharing violation, and antivirus-induced file
  lock.

Expected behavior must be documented and tested for each point.

## 6. Security testing

- path traversal, symlink, and Windows junction attacks;
- secret-pattern redaction;
- prompt injection in repository files;
- malicious agent tool requests;
- command-line quoting and shell metacharacters;
- environment-variable leakage;
- approval replay;
- artifact tampering;
- SQLite injection and malformed JSON payloads;
- oversized message and log payloads;
- network restriction tests.
- direct OS API access attempts from an untrusted process;
- stale fencing token and lease-race tests;
- Tauri IPC fuzzing and authorization bypass attempts;
- CSP and remote-navigation tests;
- ANSI/OSC terminal escape and clipboard tests;
- Git hook, attributes, submodule, LFS, response-file, and executable-path
  substitution attacks;
- approval canonicalization and Unicode normalization tests;
- update signature and downgrade/rollback tests.

## 7. Performance testing

Representative repository sizes:

- small: 1,000 files;
- medium: 20,000 files;
- large: 100,000 files.

Measure:

- initial repository scan;
- incremental re-index;
- context query latency;
- event replay time;
- UI rendering with long task history;
- stream throughput;
- memory usage with multiple agents;
- worktree creation time.
- final-tree materialization and digest time;
- startup reconciliation with large intent journals;
- policy and final outbound scanning latency.

Windows test corpora include long paths, Unicode and case collisions, reserved
device names, alternate data streams, UNC paths, symlinks, junctions, locked
files, CRLF changes, Git LFS pointers, submodules, sparse checkouts, shallow
clones, detached HEAD, and worktree-prune recovery.

## 8. Reliability patterns

- optimistic concurrency for state-changing commands;
- idempotency keys for external operations;
- bounded retry with jitter for provider APIs;
- no automatic retry for destructive or non-idempotent commands;
- process heartbeats for long-lived agents;
- cancellation propagation;
- atomic artifact writes;
- startup reconciliation;
- explicit degraded mode when vector retrieval is unavailable.

## 9. Release gates

A release candidate must pass:

- all unit and integration tests;
- protocol compatibility suite;
- security regression suite;
- Windows installer smoke test;
- crash-recovery E2E suite;
- worktree isolation suite;
- migration test from previous production schema;
- no critical or high unresolved security findings.
- untrusted-process containment suite;
- exact-object approval/commit suite;
- artifact-journal crash matrix;
- normative workflow-transition conformance;
- signed update and schema rollback-compatibility test.

## 10. Telemetry policy

No telemetry is required for core operation. If optional diagnostics are added later:

- opt-in only;
- no source code, prompts, agent responses, paths, or secrets;
- locally inspectable payload;
- documented retention and destination;
- disable switch enforced in the Rust core.

## 11. v3 executable assurance stack

Release evaluation runs in this order:

1. SQLite clean-install, migration, and negative invariant tests;
2. reducer/property tests against the machine transition specification;
3. captured-wire frame, authenticated-correlation, and durable protocol-trace tests through restart;
4. broker four-pause race tests around filesystem/Git commit points;
5. effect-specific crash matrix for artifacts, Git objects/refs, worktrees, processes, and providers;
6. actor/OID approval replay and three-way ref recovery tests;
7. installed exact-tuple containment suite;
8. hostile-repository end-to-end tests;
9. update/restore, accessibility, and performance gates.

The package includes `validation/validate_package.py`, the 39-case core regression suite, and the 68-case v3.2 adversarial hardening suite. The package gate also parses every JSON file, compiles every JSON Schema, validates all checked examples, resolves Markdown links, aligns workflow enums with SQLite, and rejects active placeholders. It does not prove broker races, power-loss durability, installed containment, update rollback, or production performance. Those remain explicit release blockers rather than implied successes.

## 12. v4 cognitive and agent-quality assurance

### 12.1 Locked benchmark corpus

Benchmark cases contain objective, repository revision, setup artifacts, required facts, required evidence, forbidden mistakes, expected tests, budgets, role configuration, and acceptance rules. Cases are immutable within a suite version.

Minimum benchmark classes:

- bug diagnosis;
- code modification;
- architecture design;
- security review;
- repository onboarding;
- migration planning;
- regression investigation;
- evidence-backed research.

### 12.2 Comparative execution

A comparison is valid only when baseline and candidate runs share:

- benchmark suite and case version;
- repository revision and fixture state;
- success and forbidden-mistake rules;
- tool and network policy;
- model/provider, prompt, retrieval, tool, and system configuration digest;
- token, time, and cost budget profile;
- evaluator configuration or deterministic assertion set.

Report per-case regressions before aggregate metrics.

### 12.3 Memory conformance tests

Every retrieval and memory adapter must pass:

- zero cross-project and cross-task leakage;
- legacy `memory_entries` stays readable after v4 schema installation, while insert, update, and delete are rejected;
- stale hash exclusion;
- superseded and retracted memory exclusion;
- negative-memory applicability filtering;
- deterministic source reconstruction;
- index deletion and full rebuild;
- denied-secret canary absence across all routes;
- degraded branch reporting;
- duplicate suppression;
- contradiction retrieval on seeded opposing evidence;
- remote embedding/reranking disclosure receipt enforcement.

### 12.4 Learning-loop tests

- agent reflection cannot activate memory;
- failed or indeterminate outcomes cannot produce verified success procedures;
- user correction supersedes conflicting unverified preference proposals;
- promotion requires matching evidence and scope;
- activation cannot preload or rewrite its timestamp, cannot activate an expired version, and cannot create two active versions for one logical key;
- working-memory and reflection digests must match exact artifact bytes;
- evaluation cannot be overwritten;
- retracted memory remains auditable but is not retrieved;
- repeated-error guard blocks a seeded known failure unless explicitly resolved.

### 12.5 Retrieval quality metrics

For labeled cases measure precision@k, recall@k, mean reciprocal rank, contradiction recall, useful-context ratio, stale retrieval rate, source diversity, and context utilization.

### 12.6 Agent quality metrics

Measure first-pass verifier acceptance, correctness gate pass, unsupported claims, requirement omissions, repeated errors, repair loops, tool-call efficiency, human corrections, accepted-outcome latency, and accepted-outcome cost.

### 12.7 Release gates

A candidate fails regardless of aggregate score when any of these occurs:

- cross-project memory leakage;
- active memory without required verification;
- denied content in an embedding, reranker, package, supplement, or diagnostic payload;
- context package or terminal retrieval trace that cannot be reconstructed;
- evaluation or terminal trace evidence overwrite;
- benchmark system/evaluator configuration mismatch or cross-scope terminal result;
- statistically or practically material regression in a critical correctness class without explicit release exception.

## 13. v4.1 cognitive ablation and utility tests

Cognitive testing uses four controlled arms:

1. no memory;
2. current-run compaction only;
3. authoritative state and evidence retrieval;
4. evidence retrieval plus eligible experience memory.

Compared runs must bind equal model configuration, evaluator configuration, repository revision, policy, budget, and acceptance rules.

Required negative tests:

- older preference cannot override a current instruction;
- project setting cannot override a task override;
- prose-only invalidation conditions are rejected for new v4.1 memory;
- memory with missing, failed, expired, or indeterminate invalidation evidence is excluded;
- stale v4.0 memory cannot be treated as current v4.1 authority without revalidation;
- policy/deterministic promotion cannot bypass shadow evaluation;
- a passing shadow result cannot contain new forbidden mistakes or unsupported claims;
- utility snapshots cannot mutate memory lifecycle;
- consolidation cannot delete source memory;
- budget allocations must sum to their total and remain task/run/package coherent;
- retrieval stops when coverage is sufficient or marginal utility is below cost.

Required quality reports:

- per-case and aggregate outcomes;
- repeated known-error rate;
- first-pass verifier acceptance;
- unsupported claims;
- stale-memory use;
- cross-scope leakage;
- token and latency overhead;
- helpful, harmful, redundant, and conclusion-used memory rates;
- shadow promotion pass/fail distribution;
- confidence intervals or variance disclosure for probabilistic runs.


## 14. v4.1.1 loop-review regression suite

The v4.1.1 suite adds positive transition tests as well as rejection tests. A guard is incomplete when it only rejects invalid rows but also blocks the intended valid lifecycle.

Required cases include:

- new state is active and valid at creation; historical terminal state receives deterministic `ended_at` during migration;
- future, expired, duplicate, cross-scope, and lower-precedence state candidates are rejected;
- equal-rank divergence cannot resolve without an explicit conflict ID; one recorded conflict accepts exactly one matching resolution receipt;
- unsupported invalidation kinds, duplicate rule IDs, malformed kind payloads, future evaluations, and unrelated-task evaluations cannot authorize retrieval;
- a project memory can use a current task-specific evaluation without being blocked by another task's result;
- an experience-memory context item requires the exact selected retrieval candidate from the same preallocated package run;
- memory origin requires coherent actor kind, actor-binding digest, exact evidence artifact/digest, valid scope/time, candidate-time insertion, and existence before verification; verified legacy memory cannot be reclassified;
- shadow control/candidate arms use equal model, budget, and policy digests; control has no memory binding; candidate has exactly the evaluated memory;
- shadow evaluation time is unique per memory, the latest result controls promotion, and legacy unbound passes cannot be grandfathered;
- passing shadow results add no forbidden mistake, unsupported claim, cross-scope leak, or stale-memory use;
- included usage events bind both the exact retrieval candidate and exact context item from the same run/package and enforce flag implications;
- consolidation shape and observable application effect are checked; autonomous split remains rejected;
- context allocations are integers and allocation plus reserves stays within the declared maximum.

The package runner executes all historical suites and the v4.1.1 suite, then parses JSON, compiles schemas, validates examples, resolves Markdown links, checks workflow/SQLite enum alignment, and rejects active placeholders. Structural green status is not a runtime quality claim.

## 14. v4.2 controlled benchmark authority

This section supersedes earlier shorthand requiring the entire system configuration
to be equal. A controlled comparison has two separate authorities:

1. `controlledConfigurationDigest` covers repository revision, fixture manifest,
   objective, budget profile, policy, tool permissions, model/provider, prompt,
   evaluator, and acceptance rules. Every run also stores each component digest
   explicitly; a shared aggregate digest alone is insufficient.
2. `treatmentConfiguration` contains only `retrievalPipeline`,
   `contextCompiler`, and `memoryPolicy`. The comparison receipt declares which
   of those dimensions may differ. Any changed but undeclared treatment or any
   changed control makes the comparison invalid.

Every benchmark run immutably binds the actual repository revision, fixture,
task objective, budget profile, actual usage receipt, policy, tool permission,
model, prompt, evaluator, acceptance rules, result artifact, timestamps, suite
version, and logical case version. Suite and case logical IDs survive version
increments through separate storage row IDs.

Normative wire contracts are:

- `schemas/benchmark-suite.v3.schema.json`;
- `schemas/benchmark-run-receipt.v1.schema.json`;
- `schemas/benchmark-case-result.v1.schema.json`;
- `schemas/benchmark-comparison-report.v1.schema.json`;
- `schemas/quality-release-decision.v1.schema.json`.

The authoritative SQLite tables are `benchmark_suite_versions`,
`benchmark_case_versions`, `benchmark_run_receipts_v2`, and
`benchmark_comparison_receipts_v2`. Legacy `benchmark_suites`,
`benchmark_cases`, `benchmark_runs`, and `benchmark_comparisons` remain retained
v4.1.1 evidence and are not valid for new quality claims.
