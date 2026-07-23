# Workflow Transition Specification

## 1. Normative model

Workflow state is:

```text
WorkflowState {
  phase: Phase,
  condition: Active | Paused | Blocked | BudgetExhausted,
  operation: None | AwaitingApproval | Running | Cancelling | Indeterminate,
  streamVersion: u64,
  workspaceVersion: u64,
  fencingEpoch: u64
}
```

`phase` describes business progress. `condition` explains why phase work can or
cannot dispatch. `operation` tracks one privileged or external operation without
inventing a new business phase.

Terminal phases are `Completed`, `Cancelled`, and `Failed`. Terminal phases
always have `condition = Active` and `operation = None`.

The machine-readable projection is
[`schemas/workflow-transitions.v1.json`](schemas/workflow-transitions.v1.json).
Implementation tests load that file and assert that every emitted phase change
is declared here.

## 2. Phases

```text
Intake
ContextBuild
ParallelAnalysis
CrossReview
PrePlanVerification
Synthesis
FinalObjection
AwaitingPlanApproval
Implementation
Verification
Repair
FinalReview
AwaitingCommitApproval
LocalCommit
WorkspaceDirty
Completed
Cancelled
Failed
```

## 3. Primary phase transitions

| From | Event | Guard | To | Required effects |
|---|---|---|---|---|
| `Intake` | `task.validated` | repository, policy, budgets valid | `ContextBuild` | persist risk and base identity |
| `ContextBuild` | `context.initial.ready` | required packages valid | `ParallelAnalysis` | freeze independent inputs |
| `ParallelAnalysis` | `analysis.quorum.reached` | minimum independent results | `CrossReview` | reveal selected proposals and review edges |
| `CrossReview` | `review.complete` | review outputs or bounded stop | `PrePlanVerification` | freeze material claims |
| `PrePlanVerification` | `claims.checked` | every material claim classified | `Synthesis` | persist verified/rejected/inconclusive set |
| `Synthesis` | `decision.draft.created` | schema and evidence valid | `FinalObjection` | publish immutable draft |
| `FinalObjection` | `objection.severe.accepted` | reopen criteria satisfied | `CrossReview` | create bounded new round |
| `FinalObjection` | `objection.round.closed` | no accepted severe objection | `AwaitingPlanApproval` | create plan approval request |
| `AwaitingPlanApproval` | `plan.revision.requested` | user supplied feedback | `Synthesis` | supersede draft, preserve history |
| `AwaitingPlanApproval` | `plan.approved` | exact digest valid | `Implementation` | create approved plan version |
| `Implementation` | `implementation.submitted` | no in-flight writes | `Verification` | revoke executor lease, reconcile workspace, create candidate tree |
| `Verification` | `verification.failed` | repair budget available | `Repair` | discard candidate, provide bounded failure evidence |
| `Verification` | `verification.passed` | required suite complete | `FinalReview` | freeze verified candidate evidence |
| `Repair` | `repair.submitted` | current fenced executor, scoped writes | `Verification` | persist workspace version, revoke lease, create new candidate |
| `FinalReview` | `review.changes.required` | finding accepted | `Repair` | discard candidate tree and reacquire lease |
| `FinalReview` | `review.accepted` | review cites candidate tree | `AwaitingCommitApproval` | create final approval request |
| `AwaitingCommitApproval` | `commit.repair.requested` | user feedback | `Repair` | invalidate candidate and approval |
| `AwaitingCommitApproval` | `commit.approved` | canonical inputs unchanged | `LocalCommit` | persist approval before side effect |
| `LocalCommit` | `commit.verified` | commit tree equals candidate | `Completed` | persist commit and completion package |
| `WorkspaceDirty` | `workspace.repair.authorized` | evidence preserved | `Repair` | allocate new fencing token |
| `WorkspaceDirty` | `workspace.reconciled` | no change needed, candidate rebuilt and verified | `FinalReview` | create new candidate and evidence |

No other phase transition is legal without a schema version change.

## 4. Global transitions

### Cancellation

The user may request cancellation from every nonterminal phase.

```text
task.cancel.requested
→ stop new dispatch
→ condition remains visible
→ operation = Cancelling while in-flight work is resolved
→ task.cancelled
→ phase = Cancelled
```

If an external operation is indeterminate, the task may remain blocked rather
than falsely becoming safely cancelled. The user can preserve the task and
inspect recovery evidence.

### Pause

`task.paused` changes only `condition` to `Paused`. It does not cancel an
already started non-idempotent operation. `task.resumed` restores `Active` after
policy, budget, approval, workspace, and lease revalidation.

### Budget exhaustion

`budget.exhausted` sets `condition = BudgetExhausted`, preserving phase.
`budget.extended` may restore `Active`. Declining extension leads to preserve or
cancel; it is not a forced `Failed` transition.

### Policy or dependency block

`workflow.blocked` sets `condition = Blocked` with a typed reason and required
resolution. `workflow.unblocked` restores `Active` only after the guard is
re-evaluated.

### Fatal failure

`task.failed` is permitted from a nonterminal phase only when:

- no external operation remains running or indeterminate;
- recovery cannot preserve a resumable state;
- failure evidence is persisted;
- no uncommitted work is deleted.

## 5. Workspace mutation transition

From `Implementation`, `Verification`, `Repair`, `FinalReview`, or
`AwaitingCommitApproval`, an unexpected `workspace.mutated` event moves phase to
`WorkspaceDirty`.

Required effects:

1. revoke the executor lease;
2. increment fencing epoch;
3. invalidate affected approvals and candidate tree;
4. stop write-capable tools;
5. capture Git and filesystem evidence;
6. preserve `resumeTarget` for UI guidance.

Fast filesystem notifications may trigger the transition, but the guard uses an
authoritative Git/filesystem rescan.

## 6. Operation substates

| Current | Event | Next | Rule |
|---|---|---|---|
| `None` | `operation.approval.required` | `AwaitingApproval` | persist canonical request |
| `AwaitingApproval` | `approval.granted` | `Running` | recompute digest before dispatch |
| `AwaitingApproval` | `approval.denied` | `None` | phase remains unchanged |
| `Running` | `operation.succeeded` | `None` | persist evidence first |
| `Running` | `operation.failed` | `None` | persist typed failure |
| `Running` | `operation.cancel.requested` | `Cancelling` | stop new effects |
| `Cancelling` | `operation.terminated` | `None` | record clean/forced result |
| `Running` or `Cancelling` | `operation.outcome.unknown` | `Indeterminate` | no automatic retry |
| `Indeterminate` | `operation.outcome.verified` | `None` | trusted reconciler only |

An operation result may cause a later phase event, but operation state itself
never advances the phase.

## 7. Completion guards

### Independent analysis

- at least two eligible independent results when two are available;
- “independent” means proposals were hidden, not merely different role labels;
- same provider/model family is recorded and cannot be used as evidence of
  independent factual verification;
- early consensus can stop additional rounds only after minimum quorum.

### Pre-plan verification

Every material claim is:

- `verified`;
- `rejected`;
- `inconclusive`;
- `not_applicable`.

Agent confidence does not change verification state.

### Plan approval

The plan digest, base commit, policy snapshot, scope, tools, verification
profile, actor, and expiry must match.

### Verification

All required checks have terminal records tied to the current candidate
workspace version. Optional or flaky checks are visibly classified.

### Final review

Review cites the immutable candidate Git tree and covers every changed path,
binary/mode/submodule change, verification result, plan deviation, and policy
exception.

### Commit

Final approval is unexpired, all canonical inputs still match, branch ref has
the approved old value, no writer lease exists, and the resulting commit tree
equals the candidate tree.

## 8. Deterministic command processing

For every command:

1. load stream and expected version;
2. reject terminal phase mutations;
3. validate global condition and operation state;
4. validate phase-specific guard;
5. calculate deterministic events;
6. append events and operation intents transactionally;
7. dispatch effects after commit.

Model output can propose a command but cannot call the reducer or emit a trusted
event.

## 9. Replay and versioning

Replaying the same ordered event stream must produce the same state tuple.
Readers upcast old event payloads without rewriting history. Adding or removing
a legal transition requires:

- workflow schema version increment;
- updated machine-readable transition file;
- migration/upcaster impact review;
- property and replay tests;
- documentation and UI compatibility update.

## 10. Core invariants

- terminal phases never transition;
- phase and operation transitions are separately validated;
- conditions preserve phase;
- budget counters never decrease;
- workspace version never decreases;
- fencing epoch never decreases or repeats;
- only one active executor lease exists per task;
- no write occurs without the current fencing token;
- no approval survives a change to its canonical inputs;
- no model output directly changes workflow state.
