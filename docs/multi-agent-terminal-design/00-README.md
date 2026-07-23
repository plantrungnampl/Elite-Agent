# Local-First Multi-Agent Engineering Terminal

**Design package status:** Implementation-ready baseline v2  
**Date:** 2026-07-23  
**Target platform:** Windows-first, portable core  
**Primary stack:** Tauri + Rust + React + TypeScript

This v2 package closes the principal implementation gaps in the original
baseline: enforceable trust tiers, a bidirectional JSON-RPC contract,
crash-consistent cross-store operations, executor fencing, exact-tree approval,
an explicit composition root, and machine-readable storage and workflow
schemas.

## 1. Product definition

This product is a local-first desktop engineering environment in which multiple AI agents can independently analyze a task, read one another's proposals, challenge assumptions, request evidence, collaborate through shared and private threads, and produce a verified implementation inside an isolated Git worktree.

It is not merely a multi-model chat UI. It is a controlled multi-agent runtime with:

- provider-agnostic agent adapters;
- an open agent protocol;
- shared context assembled from files, an event store, and a vector index;
- role-based deliberation and direct agent-to-agent requests;
- a hybrid deterministic state machine with bounded agent autonomy;
- explicit policy enforcement and approval gates;
- isolated code execution, verification, review, and local commit;
- complete local auditability and project memory.

## 2. Locked product decisions

| Area | Decision |
|---|---|
| Product scope | Coding-first, extensible to non-coding workflows |
| Collaboration model | Role-based workflow plus direct agent-to-agent requests |
| Termination | Early consensus allowed, hard iteration and budget limits enforced |
| Provider support | Open-ended through a versioned adapter protocol; two built-in adapters in MVP |
| Transports | stdio/JSON-RPC first; HTTP, WebSocket, MCP bridges later |
| Context | File-based source of truth + event store + vector retrieval + orchestrator |
| History | Event-sourced and immutable; amendments are new events |
| Assignment | User may lock roles; orchestrator assigns the rest |
| Specialist agents | Agents may request specialists; orchestrator approves or rejects |
| Decision | Lead synthesis + verification + final objection round + risk-based approval |
| Security | Per-agent policy, redaction, enforced trust tiers, capability broker, audit trail |
| UX | Desktop GUI with user terminal; agent PTY only after isolated-worker acceptance |
| Actions | Read-first; write, command, commit actions governed by approval policy |
| Deployment | Fully local-first; cloud AI optional under explicit policy |
| Scheduling | Parallel independent analysis, then controlled cross-review |
| Memory | Session, project, global configuration, private temporary scratch space |
| Primary workflow | End-to-end coding workflow |
| Git | Per-task branch and worktree; local commit only in MVP |
| Stack | Rust + Tauri + React + TypeScript |
| Vector storage | Abstract interface; embedded implementation in MVP |
| Orchestration | Hybrid state machine with controlled agent discretion |
| Platform | Windows-first, portable core |
| Agent trust | Built-in adapters are trusted core code; external agent processes are untrusted and receive no ambient repository access |
| Process isolation | Job Objects and ConPTY manage lifecycle and I/O, not filesystem or network authorization |
| Tool execution | Structured tools with absolute executables and argument arrays; raw shell is a separately approved high-risk tool |
| Write ownership | Exactly one fenced executor lease; delegated writers must acquire the lease sequentially |
| Final approval | Approval binds an immutable Git tree, base commit, verification evidence, plan version, commit message, and hook policy |
| Cross-store consistency | SQLite intent journal + content-addressed artifact store + deterministic startup reconciliation |

## 3. Package contents

1. [Product requirements](01-product-requirements.md)
2. [System architecture](02-system-architecture.md)
3. [Agent protocol](03-agent-protocol.md)
4. [Context and memory](04-context-memory.md)
5. [Workflow orchestration](05-workflow-orchestration.md)
6. [Security and threat model](06-security-threat-model.md)
7. [Storage and data model](07-storage-data-model.md)
8. [Desktop UX](08-desktop-ux.md)
9. [Testing and reliability](09-testing-reliability.md)
10. [Operations and packaging](10-operations-packaging.md)
11. [MVP delivery roadmap](11-mvp-roadmap.md)
12. [Architecture decision records](12-architecture-decisions.md)
13. [Trust and sandbox model](13-trust-sandbox-model.md)
14. [Finalization and approval integrity](14-finalization-approval-integrity.md)
15. [Crash consistency and recovery](15-crash-consistency-recovery.md)
16. [Workflow transition specification](16-workflow-transition-specification.md)
17. [Review resolution matrix](17-review-resolution-matrix.md)
18. [Validation report](18-validation-report.md)
19. [Machine-readable contracts](schemas/README.md)
20. [Protocol JSON Schema](schemas/agent-protocol.v1.schema.json)
21. [Approval digest JSON Schema](schemas/approval-digest.v1.schema.json)
22. [SQLite v1 schema](schemas/sqlite-v1.sql)
23. [Machine-readable workflow transitions](schemas/workflow-transitions.v1.json)

## 4. System invariants

These rules are mandatory across all implementations:

1. Original files and immutable events are the source of truth. Vector search is only an index.
2. No cloud agent receives data that has not passed policy evaluation and redaction.
3. No untrusted agent receives ambient shell, filesystem, registry, credential,
   or network access. Every granted capability is brokered by the trusted core.
4. Only the holder of the current executor lease and fencing token may request
   a write. The trusted tool runtime revalidates the token at execution time.
5. Every state transition, agent message, context package, tool call, approval, file mutation, and verification result is auditable.
6. A workflow must be resumable after application restart.
7. Agent autonomy is bounded by workflow phase, policy, cost, time, and iteration limits.
8. A model provider is never referenced from orchestration domain logic.
9. Human approval is mandatory for destructive commands, final local commit, and policy exceptions.
10. Project memory contains verified knowledge, not unvalidated model claims.
11. Job Objects, ConPTY, working-directory restrictions, and environment
    filtering are defense-in-depth controls, not a security sandbox.
12. A final approval authorizes one canonical operation digest and one immutable
    Git tree. Any later workspace mutation invalidates that approval.
13. SQLite and filesystem writes are never assumed to be one transaction.
    Incomplete intents are reconciled explicitly after restart.
14. Agent-provided identity, timestamps, cost, and execution claims are
    untrusted until bound or verified by the core.

## 5. Recommended implementation order

Build one narrow vertical slice before broad provider coverage:

1. Domain, application use cases, composition root, event store, and
   crash-consistent artifact journal.
2. Repository import, worktree isolation, policy evaluation, structured tool
   broker, and executor fencing.
3. Deterministic fake agent plus one trusted API adapter behind the protocol.
4. Independent analysis, cross-review, synthesis, and plan approval.
5. Single-executor implementation, verification, exact-tree final review, and
   local commit.
6. A second heterogeneous trusted adapter and recovery testing.
7. Embedded retrieval and evidence-backed project memory.
8. Sandboxed external agents, PTY integrations, and third-party plugins only
   after isolation, signing/trust, and permission-change acceptance tests pass.

The MVP succeeds when two heterogeneous agents can debate one coding task, produce an approved plan, implement it in isolation, verify it, and create a reviewed local commit with a complete audit trail.
