# Local Multi-Agent Engineering Terminal Delivery Program

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement each milestone plan.

**Goal:** Deliver the complete Windows-first, local-first multi-agent engineering terminal specified by `docs/multi-agent-terminal-design`, including the M5 external MVP and every M7 production release gate.

**Architecture:** Use a Rust clean-architecture core with pure domain rules, application-owned ports, and outward adapters for SQLite, files, Git, tools, agents, Windows, and Tauri. React is a DTO-only desktop adapter: it renders immutable core state and invokes typed Tauri commands, while all workflow, policy, approval, fencing, recovery, and exact-tree decisions remain in Rust.

**Tech Stack:** Rust stable, Cargo workspace, SQLite, Git CLI/libgit2 only where justified, Tauri 2, React with TypeScript and Vite, pnpm, Windows Job Objects and ConPTY, JSON-RPC 2.0 over NDJSON, Node's built-in test runner for executable design-contract checks, Rust unit/integration/property tests, Vitest + React Testing Library, Playwright + axe for desktop-web accessibility checks.

## Global Constraints

- The normative source of truth is `docs/multi-agent-terminal-design`, especially `schemas/workflow-transitions.v1.json`, `schemas/approval-digest.v1.schema.json`, `schemas/agent-protocol.v1.schema.json`, and `schemas/sqlite-v1.sql`.
- Preserve the full phase/condition/operation workflow and its guarded transitions. UI navigation never bypasses a domain transition.
- Agents are untrusted by default and receive no ambient filesystem, shell, process, Git, credential, or network access. All capabilities are mediated, policy-evaluated, digest-bound, and audited.
- One writer only. Every mutation requires the current monotonically increasing fencing token; a stale token must fail before any side effect.
- Events and approval requests are immutable. Approval validity binds actor identity, exact canonical operation, policy snapshot, workspace version, relevant executable/environment identity, fencing epoch, and expiration.
- No repository mutation occurs before plan approval. Final approval binds an immutable candidate Git tree, and the created local commit must contain exactly that tree.
- Uncertainty remains explicit. An indeterminate non-repeatable operation is never silently retried or displayed as successful.
- SQLite and filesystem artifacts are authoritative. Vector and graph indexes are derived, optional, reject stale sources, and fail into a documented degraded mode.
- Clean-architecture dependency direction is enforced in CI: `domain <- application <- orchestration/bootstrap`, with concrete adapters depending inward on application ports. Tauri is an outer adapter and bootstrap is the only composition root.
- Keep module boundaries deep and minimal. Create a crate only for a real policy, platform, or volatility boundary; do not mirror every documentation noun with a crate.
- Handwritten behavior follows red-green-refactor. Generated CLI bootstrap and mechanical configuration are the only test-first exceptions already authorized by the user.
- React uses direct imports, avoids barrel files and request waterfalls, derives view state during render, moves interaction logic into event handlers, dynamically loads genuinely heavy views, and applies `content-visibility` to long immutable timelines.
- The desktop UI shows evidence and control, not simulated personalities. Proposal, fact, verification, objection, decision, approval, recovery, trust tier, and uncertainty are textually distinct and never color-only.
- WCAG 2.1 AA is a release contract: semantic structure, full keyboard operation, visible focus, correct focus restoration, status live regions, 4.5:1 normal-text contrast, 3:1 control contrast, 200% zoom, reduced motion, and NVDA/manual keyboard evidence.
- Use one primary action per view, visible labels, explicit recovery text, a fixed spacing/type/color token system, and tables when precise auditable data matters more than decoration.
- Default tool execution uses an absolute executable plus argv, never inferred shell syntax. Raw shell remains disabled unless a separately approved operation displays exact script bytes and execution context.
- Windows containment must fail closed when a promised boundary cannot be enforced. Process-tree cancellation, long/Unicode paths, locks, junctions, submodules, LFS, WebView IPC, ANSI/OSC, disk-full, and power-loss cases have explicit results.
- Telemetry is local and opt-in only as specified. Logs and diagnostics redact secrets and carry trust/observation labels.
- Explicitly deferred scope in `11-mvp-roadmap.md` stays deferred: no push/PR creation, cloud sync, multi-user mode, distributed workers, simultaneous writers, marketplace, unsigned executable plugins, or mobile client.
- No production claim may rely only on mocks. Deterministic fakes prove orchestration and fault paths; release gates also exercise real SQLite, filesystem, Git, Tauri, and Windows process boundaries.
- Milestones are risk/state-machine vertical slices, not screen-first batches. Each slice crosses domain, persistence, IPC DTO, React, recovery, and acceptance evidence before the next slice starts.
- No command, build, test, hook, filter, or executable from an untrusted repository may run until the M2 containment suite passes on the current supported Windows build. Earlier milestones execute only this trusted product repository and inert hostile fixtures.
- Each milestone ends with a task-scoped review and a broad milestone review. Critical or important findings block progression.

---

## Approved Assumptions

1. The design package is the already-approved product design; implementation does not reopen product discovery unless an executable contract contradicts prose.
2. The repository starts with documentation only, so initializing Git and using a feature worktree is part of bootstrap.
3. `create-tauri-app` may generate the Tauri/React/Vite shell. All subsequent handwritten behavior remains test-driven.
4. Provider credentials, code-signing certificates, and production update-signing material are external secrets. The product must support secure configuration and deterministic conformance without them; credentialed provider smoke tests and production signing run when those secrets are supplied.
5. The first trusted provider adapter and the second heterogeneous adapter are selected from providers with official, documented HTTP APIs at implementation time. Provider-specific DTOs remain anti-corruption layers outside the protocol and orchestration core.
6. The app is Windows-first but core domain, application, protocol, policy, storage, and Git behavior remain portable.

## Definition of Complete

The product is complete only when:

1. Milestones M0 through M7 below have approved task reviews and milestone reviews.
2. Both recommended demonstrations in `11-mvp-roadmap.md` pass from a clean installed build.
3. Every release gate in `09-testing-reliability.md` has retained command output or an artifact reference.
4. The signed installer/update gate has production signing evidence, not only a developer certificate.
5. No unresolved critical/high security finding or WCAG 2.1 AA blocker remains.
6. The exact-tree proof shows `approved candidate tree == committed tree`, including crash recovery around each finalization boundary.

## Milestone Program

### M0 — Domain and persistence foundation

Detailed plan: `docs/superpowers/plans/2026-07-23-m0-foundation.md`

Deliver:

- Git/worktree baseline and CLI-generated Tauri 2 + React/TypeScript/Vite shell;
- executable design-contract tests and corrected machine contracts;
- pure workflow domain with guarded transitions;
- application-owned event/artifact ports;
- SQLite optimistic event append and projections;
- content-addressed artifact journal and deterministic reconciliation;
- startup validation, structured trust-labelled logging, and architecture guards.

Gate:

- all M0 exit criteria from `11-mvp-roadmap.md`;
- `node --test tests/contracts/*.test.mjs`;
- `cargo test --workspace --all-targets`;
- `pnpm --dir apps/desktop test --run`;
- `pnpm --dir apps/desktop build`;
- dependency graph check and a Tauri debug build on Windows.

### M1 — Repository isolation and recovery

Plan file to create before implementation: `docs/superpowers/plans/2026-07-23-m1-workspace-recovery.md`

Deliver repository identity/health, base capture, isolated task worktrees, single executor lease, monotonic fencing, mutation monitoring, startup reconciliation, task timeline, and recovery UI.

Gate every M1 exit criterion, including unchanged user checkout, stale-token rejection, `WorkspaceDirty`, no silent unknown-command replay, and the full Windows path/junction/lock/submodule/LFS matrix.

### M2 — Policy and structured tool broker

Plan file to create before implementation: `docs/superpowers/plans/2026-07-23-m2-policy-tools.md`

Deliver deny-overrides policy evaluation, classification/redaction, secret scanning, capability paths, structured filesystem/Git/diff/process tools, canonical operation digests, approvals, environment/network profiles, Windows Job Object lifecycle, and audited cancellation.

Gate denied canaries across every tool path, argv-only process execution, approval invalidation on any canonical change, process-tree termination, complete audit evidence, and fail-closed enforcement.

### M3 — Protocol and first trusted adapter

Plan file to create before implementation: `docs/superpowers/plans/2026-07-23-m3-protocol-adapter.md`

Deliver JSON-RPC v1 types and codec, conformance suite, deterministic proposer/critic/verifier/malicious/slow/crashing agents, identity/manifest/executable/connection binding, one trusted provider adapter, streaming, limits, cancellation, heartbeat, and terminal-result validation.

Gate request IDs, malformed/oversize/sequence/duplicate-terminal defenses, reconstructible effective context and run configuration, and provider-crash isolation.

### M4 — Context and deliberation

Plan file to create before implementation: `docs/superpowers/plans/2026-07-23-m4-context-deliberation.md`

Deliver pre-index secret filtering, keyword/metadata retrieval, immutable role-specific context packages, independent analysis, controlled cross-review, bounded specialist requests, pre-plan verification, evidence-linked synthesis, final objection, plan approval, and a second heterogeneous contained adapter.

Gate heterogeneous independent proposals, policy-compliant context, hash/revision-bound citations, preserved dissent, and zero pre-approval repository mutation.

### M5 — Controlled implementation and exact-tree commit

Plan file to create before implementation: `docs/superpowers/plans/2026-07-23-m5-exact-tree.md`

Deliver the fenced executor, mediated writes, plan-step tracking, candidate-tree materialization, verification/repair loop, scope-drift review, immutable final approval DTO, exact-tree local commit, hook policy, and crash-safe finalization.

Gate every write with fencing, immutable final review, invalidation after mutation, exact committed tree, unchanged original checkout, and deterministic recovery at every finalization boundary. Passing this milestone creates the external MVP candidate.

### M6 — Retrieval and verified memory

Plan file to create before implementation: `docs/superpowers/plans/2026-07-23-m6-retrieval-memory.md`

Deliver an embedded vector adapter and local embeddings, optional repository graph behind a port, incremental invalidation, authoritative degraded mode, summaries, verified/approved/superseded/retracted project memory, and retrieval diagnostics.

Gate fallback behavior, stale-source rejection, pre-index secret exclusion, evidence-based memory promotion, and durable authoritative source references.

### M7 — Production hardening

Plan file to create before implementation: `docs/superpowers/plans/2026-07-23-m7-production.md`

Deliver WebView CSP/IPC hardening, terminal ANSI/OSC safety, containment suite, crash/power/disk/fault matrix, signed installer and update metadata, migration/rollback suite, resource controls, large-repository benchmarks, accessibility evidence, and privacy-safe diagnostics.

Gate all release criteria, no critical/high finding, compatible rollback, reproducible benchmark reporting, documented trust limitations, and production signature verification.

## Cross-Milestone Evidence Ledger

Each detailed milestone plan must write:

- `.superpowers/sdd/progress.md` for reviewed task/commit ranges;
- `artifacts/verification/<milestone>/manifest.json` with commands, versions, timestamps, exit codes, and output artifact hashes;
- `artifacts/verification/<milestone>/review.md` with spec and code-quality verdicts;
- `artifacts/verification/<milestone>/known-limitations.md`, even when the result is `None`.

These local artifacts are excluded from release binaries but remain available for the final audit.
