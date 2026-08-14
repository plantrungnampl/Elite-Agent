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

## ADR-023 — Logical intent is separate from dispatch attempt

**Decision:** A logical effect has a stable operation intent. Every actual send or execution creates an immutable numbered attempt with its own owner, fencing token, policy/approval binding, boundary evidence, receipt, result, and terminal state.

**Reason:** Mutable single-row retry state destroys forensic evidence and allows stale completion to overwrite the current effect.

## ADR-024 — External mutation uses broker-only promotion

**Decision:** Workers prepare output in private per-attempt staging. Only the trusted broker can promote files or update Git refs after an in-barrier fencing recheck.

## ADR-025 — Final approval binds a pre-created Git commit OID

**Decision:** Create and verify the exact commit object before approval. Approval binds the candidate commit OID, not only the tree and a partial metadata recipe.

## ADR-026 — Approval decision is an immutable actor-bound receipt

**Decision:** Approval status is a projection over an immutable decision receipt binding request digest, logical intent, actor/session evidence, nonce, decision, and time.

## ADR-027 — External enablement requires exact-tuple attestation

**Decision:** No external executable is enabled from a Boolean trust flag. Enablement references an immutable, unrevoked attestation for the exact installed tuple.

## ADR-028 — Release claims require invariant-to-evidence traceability

**Decision:** Every high-impact claim maps to a normative primitive, negative test, evidence artifact, owner, and capability gate in the invariant registry.

## ADR-029 — Cognitive lifecycle instead of static context retrieval

**Decision:** adopt observe → retrieve → compile → act → verify → evaluate → learn as the agent-quality lifecycle.

**Reason:** retrieval alone cannot prevent repeated mistakes or prove quality improvement.

## ADR-030 — Typed memory with verified promotion

**Decision:** separate working, episodic, semantic, procedural, negative, and scoped preference memory. Long-term activation requires authoritative verification.

**Reason:** different memory classes have different risks, retention, and applicability.

## ADR-031 — Retrieval engines are non-authoritative adapters

**Decision:** keyword, vector, graph, sidecar, and remote engines return candidate references only. The core re-reads authoritative bytes and compiles final context.

**Reason:** engine replacement, rebuild, privacy, and audit must not change authority semantics.

## ADR-032 — Role-specific Context Compiler

**Decision:** compile immutable context packages and supplements from task state, evidence, memory, contradictions, role, policy, and budget.

**Reason:** sending the same retrieval dump to every role wastes context and weakens quality.

## ADR-033 — Evaluation precedes learning

**Decision:** verify and evaluate a run before lesson extraction; the Learning Engine may only propose memory.

**Reason:** self-reported success and reflection cannot safely validate durable knowledge.

## ADR-034 — Negative memory is first-class

**Decision:** preserve verified failed approaches, invalid assumptions, and regression patterns with applicability and invalidation conditions.

**Reason:** preventing known repeated errors is a direct, measurable quality improvement.

## ADR-035 — Quality claims require locked comparative benchmarks

**Decision:** no release claim about better memory or agent quality is accepted without equal-input baseline comparison and per-case regression reporting.

**Reason:** subjective demos and aggregate judge scores are insufficient evidence.

## ADR-036 — Preserve SQLite authority storage

**Decision:** extend SQLite for cognitive authority records while keeping large artifacts in files and indexes replaceable.

**Reason:** the product remains single-user, local-first, and single-writer; changing databases does not solve retrieval or learning quality.
