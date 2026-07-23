# Product Requirements Document

## 1. Product vision

Create a local-first desktop engineering workspace where heterogeneous AI agents collaborate as an auditable software team rather than as isolated chatbots. Agents should independently reason, review one another's work, request additional evidence, implement approved changes, run verification, and present a decision package to the user.

## 2. Problem statement

Current AI coding tools usually operate in isolated sessions. Their limitations include:

- each agent has a separate and incomplete context;
- users manually copy responses between providers;
- proposals are not systematically challenged or verified;
- agents often overwrite work or make conflicting edits;
- source code and internal context may be over-shared to cloud providers;
- the reasoning path behind a final implementation is difficult to audit;
- long-running context becomes expensive, stale, and hard to manage;
- restarting an application can lose workflow state.

The product solves these problems through a local orchestration layer, structured collaboration protocol, contextual retrieval, policy enforcement, isolated Git workspaces, and event-sourced recovery.

## 3. Target users

### 3.1 Primary

- individual software engineers using multiple AI providers;
- engineers who mix cloud models with local models;
- developers working in sensitive or proprietary repositories;
- technical users comfortable with Git, terminals, and local development tools.

### 3.2 Secondary

- small engineering teams evaluating multi-agent workflows;
- security reviewers and architects who need evidence-backed design debate;
- researchers building custom AI agents and adapters.

## 4. Primary jobs to be done

1. Open a local repository and submit a coding task.
2. Ask several agents to analyze the task independently.
3. Let agents review and challenge one another's assumptions.
4. Inspect the discussion, evidence, unresolved objections, and estimated cost.
5. Approve a concrete implementation plan.
6. Allow one controlled executor to modify an isolated worktree.
7. Run deterministic build, test, lint, and review checks.
8. Approve and create a local commit.
9. Preserve verified decisions and project knowledge for future tasks.

## 5. Functional requirements

### FR-001 Repository onboarding

The system shall open an existing Git repository, validate repository health, detect the default branch, inspect working-tree status, and create a project record without modifying repository content.

### FR-002 Task creation

The user shall create a task with:

- natural-language objective;
- optional file or module scope;
- risk classification;
- provider and agent preferences;
- cost, time, and iteration budgets;
- data-sharing policy overrides;
- desired validation commands.

### FR-003 Isolated workspace

For every implementation task, the system shall create a dedicated branch and
Git worktree. The original checked-out working-tree files and index shall remain
untouched. Git's shared administrative metadata may gain the explicit branch
and worktree records required by this operation.

### FR-004 Agent discovery

The system shall discover agents from local manifests and registered API providers. Discovery shall not require changes to orchestration domain logic.

### FR-005 Capability-based assignment

Agents shall declare capabilities. The user may lock an agent to a role. The orchestrator shall assign remaining roles based on capability, availability, policy, cost, and task needs.

### FR-006 Independent analysis

The first reasoning phase shall allow multiple agents to analyze the task independently without seeing other proposals, unless the workflow configuration explicitly disables independence.

### FR-007 Cross-review

After independent analysis, the system shall distribute selected proposals for critique. Agents may support, reject, question, or request evidence for claims.

### FR-008 Direct collaboration

An agent may request a direct thread with another agent or request a specialist capability. The orchestrator shall authorize the request before execution.

### FR-009 Structured messages

Agent outputs shall include a typed envelope such as proposal, critique, evidence request, evidence, objection, decision recommendation, tool request, or execution result.

### FR-010 Context retrieval

The context orchestrator shall assemble per-agent context from:

- repository files;
- immutable workflow events;
- verified project memory;
- semantic retrieval results;
- current task artifacts;
- active thread messages.

### FR-011 Context query

An agent may request additional context using a structured query. The request shall pass through policy enforcement and token budgeting.

### FR-012 Lead synthesis

A lead agent shall produce a decision package containing the selected approach, rejected alternatives, evidence, unresolved objections, implementation scope, risks, and test strategy.

### FR-013 Plan approval

In the MVP, no repository file mutation shall occur before the plan approval
gate. A future policy may permit autonomous low-risk changes, but that mode is
explicitly outside the MVP and must not weaken destructive-command, policy
exception, or final-commit approval.

### FR-014 Tool mediation

Untrusted agents shall have no ambient repository or shell access. They shall
issue structured tool requests through the tool runtime, which validates the
request, evaluates policy, binds approvals, executes the operation, and records
the result. Raw shell execution is a distinct high-risk tool and is never
inferred from a free-form command string.

### FR-015 Single executor

Only one executor shall own the current write lease and fencing token for a task
worktree. Other agents may review or propose patches but cannot write. A
delegated writer must acquire a newer lease sequentially; simultaneous
non-overlapping writers are outside MVP scope.

### FR-016 Verification

The system shall support configured verification commands including format, lint, type checking, build, unit tests, integration tests, and security checks.

### FR-017 Repair loop

Verification failure may trigger a bounded repair loop. The loop shall stop when successful, budget-exhausted, iteration-exhausted, cancelled, or blocked by an approval requirement.

### FR-018 Final review

A reviewer shall compare the final diff against the approved plan and identify scope drift, missing tests, unsafe changes, placeholders, regressions, and unresolved risks.

### FR-019 Final approval and commit

The user shall be able to approve, request repair, keep the worktree, discard
the worktree, or create a local commit. Approval shall bind the base commit,
immutable Git tree, plan version, verification artifacts, commit message, and
hook policy. Push and pull-request creation are out of MVP scope.

### FR-020 Event-sourced audit

Every externally meaningful action shall create an immutable event. Amendments and retractions shall be represented by new events rather than mutation of history.

### FR-021 Recovery

After restart or crash, the system shall reconstruct workflow state from
persisted events and artifacts, reconcile incomplete cross-store intents, fence
stale executors, and safely resume or mark interrupted operations. An external
operation is never automatically repeated merely because its completion record
is missing.

### FR-022 Project memory

Only validated, user-approved, or mechanically verified knowledge shall be promoted into project memory.

### FR-023 Local-first operation

All persistent state, secrets, event history, vector indexes, artifacts, and configuration shall remain local. Cloud providers are optional integrations, not infrastructure dependencies.

### FR-024 Policy enforcement

Access decisions shall consider agent identity, provider location, requested resource, operation, data sensitivity, task risk, workflow phase, and user policy.

### FR-025 Cost and token visibility

The system shall track estimated or actual token usage, cost, duration, retries, and agent participation per task.

### FR-026 Agent trust tiers

Every agent integration shall declare one of these enforced trust tiers:

- `core_adapter`: trusted code shipped with the application;
- `brokered_process`: untrusted process with no ambient repository access;
- `isolated_worker`: untrusted process inside an approved OS or VM sandbox;
- `full_access_legacy`: explicitly unsafe compatibility mode, disabled in MVP.

The UI shall display the effective tier. A manifest claim cannot elevate trust.

### FR-027 Workspace mutation detection

The system shall detect repository mutations not performed by the current
fenced executor. Such a mutation shall revoke the active lease, invalidate open
approvals, mark the task `WorkspaceDirty`, and require reconciliation before
execution or commit continues.

### FR-028 Exact outbound and execution records

For every cloud disclosure and tool execution, the core shall record the
canonical request digest, effective policy version, redaction rules, actor
binding, and authoritative receipt time. Secret material shall not be copied
into ordinary diagnostic logs.

## 6. Non-functional requirements

### NFR-001 Reliability

No approved file modification shall be lost after a clean application restart.
After a crash, incomplete artifact and process operations shall converge to a
documented terminal or retryable state. Interrupted commands shall be
represented as interrupted rather than silently repeated.

### NFR-002 Performance

- UI state updates should appear within 100 ms after local event persistence.
- Repository metadata queries should complete within 2 seconds for ordinary repositories.
- Context retrieval should return within 3 seconds for a warmed local index.
- Streaming agent output should be rendered incrementally.

### NFR-003 Security

Provider secrets shall be protected with operating-system facilities. Sensitive
file patterns shall be denied before indexing and again before outbound
serialization. Tool execution shall use least privilege. Process lifecycle
controls such as ConPTY, working-directory restrictions, and Job Objects shall
not be represented as filesystem or network isolation.

### NFR-004 Portability

Windows is the supported MVP platform. Core domain modules shall not depend directly on Windows-specific APIs. Platform-specific behavior shall be behind interfaces.

### NFR-005 Observability

The system shall expose task timelines, workflow state, agent runs, context provenance, policy decisions, command output, and verification results.

### NFR-006 Extensibility

New agent providers, transports, vector stores, embedding providers, and tools shall be addable without modifying orchestration domain rules.

### NFR-007 Deterministic control

Workflow phase transitions and approval requirements shall be deterministic and testable. Model output may advise transitions but shall not directly mutate workflow state.

### NFR-008 Data integrity

Artifacts and source chunks shall include hashes. Stale vector chunks shall never be treated as current source evidence.

### NFR-009 Approval integrity

Operation digests shall use RFC 8785 JSON Canonicalization Scheme and SHA-256.
An approval shall be valid only for the exact canonical input, policy version,
workspace revision, expiry, and actor scope that the user reviewed.

### NFR-010 Measurability

Performance acceptance tests shall publish hardware, repository corpus, cache
state, percentile, and sample count. Unqualified averages do not satisfy the
performance requirements.

## 7. MVP scope

### Included

- Windows desktop application;
- repository onboarding;
- branch and worktree isolation;
- two heterogeneous built-in adapters, or one built-in adapter plus one
  external process that passes the containment suite;
- independent analysis and cross-review;
- lead synthesis and approval gate;
- one writable executor;
- structured filesystem, Git, process, and test tool mediation;
- event-sourced SQLite persistence;
- file artifact store;
- vector retrieval port with an embedded adapter after the core vertical slice;
- final review and local commit;
- task recovery after restart;
- a structured non-shell tool broker;
- executor leases with fencing tokens;
- exact-tree approval and commit;
- intent journal and startup reconciliation;

### Excluded

- cloud synchronization;
- multi-user collaboration;
- remote distributed workers;
- automatic push or pull request;
- marketplace and billing;
- unrestricted autonomous execution;
- simultaneous conflicting writers;
- unsigned third-party executable plugins;
- a compatibility mode that grants a coding CLI ambient repository access;
- raw autonomous PowerShell or command-shell access;
- production support for every provider and protocol;
- mobile or browser-only clients.

## 8. Success metrics

The MVP is considered successful when:

1. A user can complete an end-to-end task with at least two different agent runtimes.
2. The original checked-out working-tree files and index remain unchanged until
   the user explicitly integrates the result.
3. Every final code change is traceable to an approved plan, executor action, and verification result.
4. A task can be resumed after application restart without losing its phase or audit history.
5. A cloud agent cannot access a denied file or secret through context retrieval or tools.
6. The final review identifies intentional plan deviations and presents them to the user.
7. The user can inspect why the selected proposal won over rejected alternatives.
8. A process classified as untrusted cannot read a denied canary file, write
   outside its authorized root, access a denied network endpoint, or use a stale
   executor token.
9. The committed Git tree exactly matches the tree ID displayed during final
   approval.
10. Crash injection at every artifact-journal boundary reaches a deterministic,
    auditable state after restart.
