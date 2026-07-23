# Review Resolution Matrix

## 1. Purpose

This matrix records how v2 addresses the implementation blockers found in the
original design. “Resolved in design” means the normative behavior is now
specified; implementation and acceptance tests are still required before the
corresponding guarantee can be claimed by a release.

## 2. Resolution status

| Original issue | Severity | v2 resolution | Status |
|---|---:|---|---|
| Job Objects/ConPTY presented as process isolation | P0 | Explicit trust tiers, no ambient repository access, Windows control matrix, containment suite | Resolved in design |
| Logical single writer could be bypassed by stale process | P0 | Durable lease plus monotonic fencing token checked by every write tool | Resolved in design |
| User/agent terminal could mutate after review | P0 | Out-of-band mutation enters `WorkspaceDirty`, revokes lease, and invalidates approvals | Resolved in design |
| Final commit could differ from reviewed worktree | P0 | Immutable candidate Git tree, clean-tree verification, canonical final approval, conditional ref update | Resolved in design |
| SQLite/filesystem transaction assumed atomic | P0 | Intent journal, content-addressed objects, explicit crash matrix, startup reconciliation | Resolved in design |
| JSON-RPC agent-to-core requests omitted IDs | P1 | Bidirectional request ownership, IDs, terminal request, framing, limits, schema | Resolved in design |
| Run lifecycle and streaming completion ambiguous | P1 | Immediate start acknowledgement and exactly one `agent.run.complete` request | Resolved in design |
| `Failed`/`Blocked`/`BudgetExhausted` inconsistent | P1 | State tuple separates phase, condition, and operation; normative transition table | Resolved in design |
| Agent consensus could verify project memory | P1 | Consensus only nominates a candidate; authoritative evidence or human approval required | Resolved in design |
| “Response reproducibility” overstated | P1 | Exact input is reconstructible; probabilistic output is not promised reproducible | Resolved in design |
| Security and tool mediation scheduled too late | P1 | Policy, sandbox boundary, journal, and tool broker moved before live agent deliberation | Resolved in design |
| Forward-only migration conflicted with binary rollback | P1 | Expand/contract rollback window or complete database/artifact/config restore | Resolved in design |
| Data model lacked enforceable DDL/indexes/leases/outbox | P1 | Added SQLite v1 DDL with constraints, indexes, intent journal, leases, and update journal | Resolved in design |
| Clean Architecture lacked composition root and dependency DAG | P2 | Added application-owned ports, `bootstrap` composition root, dependency graph and CI rule | Resolved in design |
| Graph retrieval had no declared persistence boundary | P2 | Added optional `RepositoryGraph` port and SQLite metadata schema; degraded branch is explicit | Resolved in design |
| WebView/terminal output were absent from threat model | P2 | Added Tauri IPC, CSP, remote-navigation, ANSI/OSC, clipboard, and link controls | Resolved in design |

## 3. Decisions intentionally left to implementation milestones

The design does not pretend that every implementation choice is already made.
These decisions have an explicit deadline:

| Decision | Must be selected by | Constraint |
|---|---|---|
| Concrete Windows restricted-worker mechanism | Before Milestone 2 exits | Must pass the containment suite; otherwise external processes stay disabled |
| First and second provider adapters | Before Milestones 3 and 4 exit | Must be built-in `core_adapter` or pass brokered-process containment |
| Embedded vector implementation and local embedding model | Before Milestone 6 starts | Must support rebuild, local default, policy filtering, and Windows packaging |
| Git library versus process adapter details | Before Milestone 1 exits | Must support exact object IDs, conditional ref update, worktrees, LFS/submodule evidence |
| OS-protected audit signing key | Before claiming tamper evidence against local store modification | Plain hashes alone may only claim corruption detection |
| Project-local artifact mode | Before enabling it | Must enforce Git exclusion, ACLs, and no placement inside task worktree |

## 4. Release claim rule

A release may claim a control only when:

1. the corresponding normative document is implemented;
2. the machine-readable schema and contract tests pass;
3. negative acceptance tests demonstrate denied behavior;
4. degraded or unavailable controls fail closed;
5. the UI describes the effective guarantee without stronger wording.

Until then, the package is an implementation-ready design baseline, not proof
that a built binary is secure or production-ready.
