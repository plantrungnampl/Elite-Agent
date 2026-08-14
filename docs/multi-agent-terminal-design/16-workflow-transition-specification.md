# Workflow Transition Specification v4.3

## 1. Normative state

```text
WorkflowStateV3 {
  phase: PhaseV3,
  condition: Active | Paused | Blocked | BudgetExhausted,
  operation: None | AwaitingApproval | Running | Cancelling | Indeterminate,
  workflowProfile: Quick | Standard | HighAssurance | ReadOnlyResearch,
  outcomeMode: ReadOnlyDeliverable | WorkspaceChange | LocalCommit,
  streamVersion: u64,
  profileRevision: u64,
  workspaceVersion: u64,
  fencingEpoch: u64,
  lastTransitionEventId: Option<TransitionEventId>,
  lastProfileRevisionId: Option<ProfileRevisionId>
}
```

The current machine projection is [`schemas/workflow-transitions.v3.json`](schemas/workflow-transitions.v3.json) plus [`schemas/sqlite-v7.sql`](schemas/sqlite-v7.sql). The reducer command wire contract is [`schemas/workflow-transition-command.v1.schema.json`](schemas/workflow-transition-command.v1.schema.json).

## 2. Authority split

The trusted application reducer decides whether a command satisfies full domain policy. SQLite is the invariant boundary and rejects a projection update unless it points to the matching accepted event or profile-revision receipt.

A phase transition transaction must:

1. read the current phase/profile/outcome and `streamVersion`;
2. resolve one declared rule;
3. insert the exact command artifact and a `prepared` event;
4. bind all required guard evidence and effects;
5. change the event to `accepted`;
6. update phase, accepted-event pointer, and stream version by exactly one;
7. commit atomically.

A rejected event remains immutable. A corrected command may retry the same stream version using a new command/event ID. An accepted event cannot be replayed.

## 3. Profile paths

- **Quick:** `Intake -> ContextBuild -> PrePlanVerification -> Synthesis -> FinalObjection`.
- **Standard:** includes `ParallelAnalysis -> CrossReview` before verification/synthesis.
- **HighAssurance:** uses the Standard structural path plus policy-required quorum, independent groups, and hard executor/reviewer separation.
- **ReadOnlyResearch:** uses evidence-oriented analysis/review and can finish only as `ReadOnlyDeliverable`.

A severe accepted objection returns Quick to `PrePlanVerification`; Standard, HighAssurance, and ReadOnlyResearch return to `CrossReview`. The profile-specific rule relation makes the routes mutually exclusive.

## 4. Profile escalation

The only in-task profile changes are:

- `Quick -> Standard`;
- `Quick -> HighAssurance`;
- `Standard -> HighAssurance`.

Escalation is a separate atomic command, requires a scoped reason artifact and immutable revision receipt, increments `streamVersion` and `profileRevision`, and does not change phase. Downgrade is forbidden. ReadOnlyResearch cannot acquire a write outcome in place; the user creates an approved child task.

## 5. Outcome paths

| Outcome | Required terminal path | Exact terminal evidence |
|---|---|---|
| `ReadOnlyDeliverable` | `AwaitingDeliverableApproval -> Completed` | deliverable acceptance receipt and completion package |
| `WorkspaceChange` | plan, implementation, verification, final review, `AwaitingWorkspaceApproval -> Completed` | exact workspace acceptance and verified candidate tuple; no ref change |
| `LocalCommit` | plan, implementation, verification, final review, `AwaitingCommitApproval -> RefPromotion -> Completed` | exact granted commit approval, one-time consumption, and successful ref CAS |

`AwaitingPlanApproval -> Implementation` requires the exact granted plan approval receipt plus effects `persist_approved_plan_version` and `allocate_executor_lease`.

## 6. Candidate and repair invariant

`candidate.prepared` creates the complete commit object before verification. Verification and final review cite both tree and commit OIDs. Repair invalidates candidate tree, candidate commit, dependent verification, and dependent approvals together. `RefPromotion` performs only expected-old-value CAS and never constructs or rewrites the commit.

## 7. Workspace mutation

Any mutation detected in a write-capable phase uses the global workspace-dirty rule. It revokes the executor, increments fencing, invalidates affected approvals/candidates, stops write tools, captures evidence, and moves to `WorkspaceDirty`. Recovery requires a declared reconciliation or repair command.

## 8. Terminal and condition rules

Conditions do not advance phase. Privileged effects use the operation substate. `Completed`, `Cancelled`, and `Failed` are irreversible and require a completion timestamp. Historical authority is retained; correction creates a new event or receipt.
