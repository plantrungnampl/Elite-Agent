# Testing and Reliability Strategy

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
- exact-tree finalization using an isolated Git index;
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
- no terminal phase transitions back to an active phase.
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
- after approval but before exact-tree commit;
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
- exact-tree approval/commit suite;
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
