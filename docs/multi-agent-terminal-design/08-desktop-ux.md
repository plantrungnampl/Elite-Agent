# Desktop UX Design

## 1. UX principles

- show control and evidence, not simulated personalities;
- make agent activity observable without overwhelming the user;
- distinguish proposal, fact, verification, and decision;
- make approvals explicit and digest-bound;
- keep terminal power available while preserving mediation;
- allow inspection of the exact context provided to each agent;
- surface cost, privacy, and risk before execution.
- distinguish trusted core adapters, brokered processes, isolated workers, and
  disabled full-access compatibility integrations.

## 2. Main application layout

```text
┌────────────────────────────────────────────────────────────────────┐
│ Project / Task                 Workflow Phase       Cost / Policy  │
├──────────────┬───────────────────────────────────┬─────────────────┤
│ Task & Agent │ Shared Room / Thread              │ Evidence        │
│ Navigator    │                                   │ Context / Diff  │
│              │                                   │ Decisions       │
├──────────────┴───────────────────────────────────┴─────────────────┤
│ Terminal / Tool Output / Tests / Logs                              │
└────────────────────────────────────────────────────────────────────┘
```

Panels are resizable and may be hidden.

## 3. Primary screens

### 3.1 Project dashboard

- repository health;
- active worktrees;
- pending approvals;
- recent tasks;
- agent health;
- project policy;
- project-memory changes.

### 3.2 New task wizard

Steps:

1. objective and scope;
2. risk and data policy;
3. agents and locked roles;
4. cost/time/round limits;
5. validation commands;
6. review and create.

The wizard shows expected external data sharing before task creation.

### 3.3 Task workspace

#### Workflow rail

Displays current phase, completed phases, blockers, retries, and approval gates.

#### Agent roster

For each agent:

- role;
- provider/locality;
- current status;
- context scope;
- token and cost usage;
- health;
- permissions.
- enforced trust tier and sandbox status;
- executable/manifest identity change warning.

#### Shared room

Structured cards for:

- proposals;
- critiques;
- evidence;
- objections;
- decisions;
- status changes.

#### Thread view

Direct agent-to-agent discussion with a summary promoted back to the shared room.

#### Evidence panel

Shows cited files, line ranges, tool output, verification state, and stale warnings.

#### Context inspector

Shows the exact immutable context package sent to the selected agent, including redactions and provenance.

### 3.4 Plan approval

The approval view contains:

- selected proposal;
- rejected alternatives;
- agent agreement map;
- unresolved objections;
- files expected to change;
- planned commands;
- security implications;
- estimated cost and duration;
- approval operation digest.
- plan version and policy snapshot;
- exact writable scope and executor fencing epoch.

Actions:

- approve;
- request changes;
- reopen discussion;
- add/replace agent;
- reject task.

### 3.5 Implementation view

- approved step list;
- current executor;
- changed files;
- terminal sessions;
- tool requests;
- plan deviation warnings;
- repair-loop counter.

### 3.6 Final review

- side-by-side or unified diff;
- approved-plan mapping;
- test matrix;
- reviewer findings;
- known limitations;
- commit message;
- local commit action.
- approved base commit and candidate Git tree ID;
- hook policy and verification artifact hashes;
- visible indication that the candidate is frozen.

## 4. Terminal integration

Use `xterm.js` in React and a Rust ConPTY bridge on Windows.

Terminal modes:

- **User terminal:** interactive shell controlled directly by user and treated
  as an out-of-band actor.
- **Agent CLI terminal:** future visible PTY session for a CLI agent running
  inside an approved isolated worker; disabled in the core MVP.
- **Tool execution output:** non-interactive audited command log.

The UI must clearly identify which mode is active. An agent CLI terminal is not
treated as permission to execute arbitrary project commands outside the tool
runtime.

The user terminal does not participate in a controlled task by default. If the
user opens it in a task worktree, the UI displays a persistent warning. Any
mutation:

1. revokes the executor lease;
2. invalidates affected approvals;
3. transitions the task to `WorkspaceDirty`;
4. requires a new scan, verification, and final review.

Terminal rendering disables clipboard-setting OSC sequences and silent URL/file
launch. Hyperlinks require an allowlisted scheme and explicit user action.

## 5. Visual semantics

Avoid using color alone. Every state includes icon and text:

- Verified;
- Unverified;
- Rejected;
- Inconclusive;
- Approval required;
- Redacted;
- Stale evidence;
- Local agent;
- Cloud agent.

## 6. User control

The user can at any time:

- pause new agent runs;
- cancel a run;
- stop all tools;
- lower budgets;
- revoke an agent;
- inspect outbound cloud context;
- preserve or discard a worktree;
- export the task audit package.
- reconcile or preserve an externally modified worktree;
- disable a changed agent executable or manifest.

## 7. Accessibility

- full keyboard navigation;
- screen-reader labels for phase and agent status;
- adjustable font sizes;
- terminal contrast settings;
- no critical information conveyed by animation;
- reduced-motion support;
- searchable conversation and evidence.

## 8. UX safety requirements

- destructive actions require typed or explicit confirmation depending on severity;
- approval dialog displays exact command, file scope, agent, and reason;
- changed operation digest invalidates an open approval dialog;
- changed Git tree, base commit, policy snapshot, executable identity, hook
  policy, environment profile, or executor fencing epoch invalidates the
  corresponding approval;
- cloud context preview is available before first disclosure under a policy profile;
- hidden or redacted content is visibly marked, not silently omitted.
- final commit approval is rendered from an immutable core DTO and confirms the
  candidate commit OID and tree ID; React never supplies a replacement operation payload.
- raw shell approval shows the executable shell, exact script bytes, cwd,
  environment profile, network mode, expected writes, and reason.

## 9. Recovery and indeterminate states

The UI never converts uncertainty into success. It distinguishes:

- interrupted before execution;
- execution outcome indeterminate;
- side effect verified after recovery;
- stale approval;
- stale executor;
- artifact quarantined;
- workspace dirty;
- recovery action required.

Retry is disabled for an indeterminate non-repeatable operation. The user can
inspect evidence, mark an externally verified outcome, preserve the task, or
cancel it.

## 10. v3 authority and uncertainty presentation

The UI displays workflow phase, stop condition, and external operation state as separate axes. It must not collapse `indeterminate` into failure or safe retry.

Approval screens render the canonical request constructed by the core: actor, repository identity, task, logical intent, expected ref and old OID, candidate commit OID, diff/scope, verification, policy exceptions, nonce, expiry, and digest fingerprint. The UI sends only the decision reference and credential evidence; it does not reconstruct the operation payload.

Recovery screens show immutable attempt history and typed resource receipts. A generic Retry button is forbidden for `non_repeatable` or unresolved effects. Trust badges are derived from the current attestation tuple and revocation state, not from manifest declarations or a cached Boolean.

## 11. Cognitive memory and quality workspace

### 11.1 Context debugger

The Context Inspector becomes a debugger with:

- package and supplement timeline;
- token budget by segment;
- retrieval branches used, degraded, or denied;
- per-item source, revision, hash, score components, and inclusion reason;
- supportive and contradictory evidence shown separately;
- stale, redacted, restricted, and superseded states;
- “used in conclusion” and verifier feedback markers;
- exact package digest and exportable reconstruction receipt.

### 11.2 Memory explorer

The Memory Explorer filters by type, project, task, status, applicability, source, confidence, and age. Each record displays:

- content and narrow applicability statement;
- evidence and verification method;
- lifecycle and version history;
- relations such as contradicts or supersedes;
- tasks where it was retrieved and whether it was useful;
- expiration or invalidation conditions;
- actions to approve, reject, supersede, retract, or request reverification.

No UI action edits an active memory record in place.

### 11.3 Working-memory view

For an active run, the user can inspect facts, inferences, unknowns, hypotheses, next action, and required checks. Visual treatment must clearly distinguish verified evidence from agent assertion.

### 11.4 Learning review queue

Memory proposals show the originating run, verified outcome, quality score, proposed type, applicability, evidence, conflicts, and expected benefit. Bulk approval is disabled for security-sensitive, preference, or negative-memory proposals.

### 11.5 Agent quality dashboard

The dashboard shows per-role and per-configuration:

- first-pass acceptance;
- repair loops;
- repeated-error and unsupported-claim rates;
- context usefulness and contradiction recall;
- latency, token, tool-call, and cost distributions;
- benchmark regressions with direct links to evidence.

Aggregate scores never hide a failed security, privacy, or correctness gate.

### 11.6 Degraded-state UX

If a retrieval branch is unavailable, the task workspace states what is missing, expected quality impact, whether work may continue, and available recovery action such as rebuild index or restart sidecar.
