# Architecture Decision Records

## ADR-001 — Local-first persistent architecture

**Status:** Accepted  
**Decision:** Persistent state, events, artifacts, indexes, policies, and secrets remain local. Cloud agents are optional external processors.  
**Reason:** Privacy, offline capability, user ownership, and resilience without a control server.  
**Consequence:** Sync and multi-user collaboration are deferred.

## ADR-002 — Hybrid deterministic orchestration

**Status:** Accepted  
**Decision:** Use a deterministic state machine for phases and approvals while allowing bounded agent discretion inside phases.  
**Reason:** Purely fixed workflows are inflexible; fully autonomous AI supervisors are unpredictable and difficult to audit.  
**Consequence:** Agent recommendations are translated into domain commands and validated before transition.

## ADR-003 — Event-sourced task history

**Status:** Accepted  
**Decision:** Task history is immutable. Amendments, retractions, and supersession are new events.  
**Reason:** Audit, recovery, debugging, and trustworthy decision history.  
**Consequence:** Projections and event-versioning infrastructure are required.

## ADR-004 — Files are authoritative; vectors are an index

**Status:** Accepted  
**Decision:** Original files, events, artifacts, and verified memory are authoritative. Vector search only locates relevant sources.  
**Reason:** Embeddings can be stale, lossy, model-dependent, and rebuildable.  
**Consequence:** Every vector chunk requires a source reference and hash.

## ADR-005 — Open provider-agnostic agent protocol

**Status:** Accepted  
**Decision:** Agents integrate through a versioned protocol, beginning with stdio/JSON-RPC.  
**Reason:** Avoid hard-coding OpenAI, Anthropic, Gemini, or any other provider.  
**Consequence:** Capability negotiation and adapter contract tests are mandatory.

## ADR-006 — Per-agent context and permissions

**Status:** Accepted  
**Decision:** Context is assembled separately for each agent and evaluated against policy.  
**Reason:** Different roles and providers need different evidence and disclosure levels.  
**Consequence:** Context packages are immutable and include provenance, redaction, and policy metadata.

## ADR-007 — Git worktree isolation

**Status:** Accepted  
**Decision:** Each implementation task uses a dedicated branch and worktree.  
**Reason:** Protect the user's current working tree and allow simple rollback and inspection.  
**Consequence:** Worktree lifecycle and orphan recovery become core responsibilities.

## ADR-008 — Single writable executor

**Status:** Accepted  
**Decision:** Only one executor owns write access at a time.  
**Reason:** Prevent conflicting edits and unclear ownership.  
**Consequence:** Other agents review or propose changes. Delegation transfers a
durable lease and creates a newer fencing token; simultaneous writers,
including non-overlapping writers, are outside MVP scope.

## ADR-009 — Rust, Tauri, React, and TypeScript

**Status:** Accepted  
**Decision:** Rust core and Tauri desktop shell with React/TypeScript UI.  
**Reason:** Strong local process, filesystem, security, and portability characteristics with a mature UI ecosystem.  
**Consequence:** Clear IPC contracts and strict UI/core responsibility separation are required.

## ADR-010 — Windows-first portable core

**Status:** Accepted  
**Decision:** Support Windows first while placing PTY, process, secret-store, and path behavior behind platform interfaces.  
**Reason:** Reduce initial scope without creating a Windows-only architecture.  
**Consequence:** Windows integration uses ConPTY and OS security facilities; Linux/macOS adapters follow later.

## ADR-011 — Embedded vector store behind an abstraction

**Status:** Accepted  
**Decision:** MVP uses an embedded vector implementation behind `VectorStore`.  
**Reason:** Avoid requiring a separate service while preserving future options.  
**Consequence:** The system must operate in degraded mode when the vector store is unavailable.

## ADR-012 — Tool mediation instead of direct shell access

**Status:** Accepted  
**Decision:** Agents request tools from the core; they do not receive unrestricted shell or filesystem access.  
**Reason:** Security, audit, repeatability, and approval enforcement.  
**Consequence:** Tool schemas, policy integration, process lifecycle, and output capture are production-critical.

## ADR-013 — Lead synthesis is not sole authority

**Status:** Accepted  
**Decision:** Lead synthesis is followed by verification and a final objection round, with user approval for important actions.  
**Reason:** A single model should not silently determine architecture or execute risky changes.  
**Consequence:** Decision packages preserve dissent and evidence.

## ADR-014 — Local commit only in MVP

**Status:** Accepted  
**Decision:** The application may create an approved local commit but shall not push or open a pull request in MVP.  
**Reason:** Proves end-to-end value while limiting credential, network, and destructive-operation risk.  
**Consequence:** Remote repository integration is a later milestone.

## ADR-015 — Application-owned ports and explicit composition root

**Status:** Accepted  
**Decision:** Pure domain policy is separated from application use cases.
Application use cases own output ports; outer adapters implement them.
`bootstrap` is the only composition root.  
**Reason:** Prevent a catch-all domain crate from depending on asynchronous
infrastructure concepts and make the dependency graph enforceable.  
**Consequence:** CI rejects forbidden crate edges and dependency cycles.

## ADR-016 — Job Objects and ConPTY are not a sandbox

**Status:** Accepted  
**Decision:** ConPTY is used for terminal I/O and Job Objects for lifecycle and
resource control. Neither satisfies filesystem or network isolation.  
**Reason:** A process running under the user's token can bypass a tool broker
through direct OS APIs.  
**Consequence:** Untrusted agents receive context by value with no ambient
repository access, or run in an approved low-privilege/VM boundary.
`full_access_legacy` integrations are disabled in MVP.

## ADR-017 — Structured tools, raw shell as a separate risk class

**Status:** Accepted  
**Decision:** Safe process tools take a canonical executable reference, argument
array, cwd, environment profile, network mode, timeout, and expected-write
scope. Raw shell is a separate tool requiring explicit policy and approval.  
**Reason:** PowerShell and command-shell strings cannot be reliably classified
by searching for dangerous tokens.  
**Consequence:** Existing coding CLIs that require unrestricted shell access are
not represented as mediated integrations.

## ADR-018 — Journaled cross-store consistency

**Status:** Accepted  
**Decision:** SQLite intent records, content-addressed artifact bytes, Git, and
external processes use explicit operation state machines and startup
reconciliation. No transaction is claimed across stores.  
**Reason:** Atomic filesystem rename and SQLite transaction cannot commit as one
unit, and remote/process side effects can outlive a crash.  
**Consequence:** Every side-effecting operation declares idempotency,
authoritative completion evidence, and indeterminate recovery behavior.

## ADR-019 — Fenced executor leases

**Status:** Accepted  
**Decision:** Every write-capable request carries a monotonically increasing
fencing token validated immediately before the side effect.  
**Reason:** A logical owner flag cannot stop a delayed or surviving process from
writing after ownership changes.  
**Consequence:** Lease transfer invalidates older requests, and unexpected
workspace mutation enters `WorkspaceDirty`.

## ADR-020 — Exact-tree final approval

**Status:** Accepted  
**Decision:** Final review and approval bind an immutable Git tree, base commit,
plan version, verification artifacts, commit message, policy snapshot, and hook
policy. The local commit is created from that exact tree.  
**Reason:** Reviewing a mutable worktree leaves a time-of-check/time-of-use gap.  
**Consequence:** Entering final review revokes write access; any mutation
invalidates the candidate and approval.

## ADR-021 — RFC 8785 canonical approval digests

**Status:** Accepted  
**Decision:** Approval payloads use RFC 8785 JSON Canonicalization Scheme and
SHA-256 over a versioned schema.  
**Reason:** Equivalent-looking JSON can hash differently, while omitted fields
can create authorization ambiguity.  
**Consequence:** Canonicalization test vectors and Unicode/number edge cases are
release gates.

## ADR-022 — Verified memory requires authoritative evidence

**Status:** Accepted  
**Decision:** Model consensus may nominate a memory candidate but cannot verify
or activate it. Verification requires deterministic evidence, an approved
committed change, or explicit human approval grounded in current authoritative
sources.  
**Reason:** Correlated agents can confidently agree on the same false claim.  
**Consequence:** Memory promotion stores evidence hashes, verification method,
approval, supersession, and retraction state.
