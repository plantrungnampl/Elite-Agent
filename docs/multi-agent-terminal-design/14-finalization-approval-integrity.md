# Finalization and Approval Integrity v3

## 1. Goal

Finalization must update the task ref to the exact Git commit object reviewed and approved by the bound human actor. Tree equality alone is insufficient because a commit OID also depends on parent ordering, author/committer identities, timestamps/timezones, message, headers, and optional signature.

The normative request schema is [`schemas/approval-digest.v2.schema.json`](schemas/approval-digest.v2.schema.json). The decision receipt schema is [`schemas/approval-decision-receipt.v1.schema.json`](schemas/approval-decision-receipt.v1.schema.json).

## 2. Approval classes

- **Plan:** approved plan version, base, paths, tools, verification profile, policy, and risk.
- **Tool:** exact executable/typed request, arguments digest, cwd/environment/network profiles, expected writes, run/step, and fencing token.
- **Policy exception:** actor, purpose, resource/destination, exact effective payload and redaction report.
- **Final commit:** repository, task, logical intent, ref transition, exact candidate commit OID, plan/review/verification, metadata, actor, policy, nonce, expiry, workspace version, and fencing epoch.

## 3. Finalization preparation

Finalization starts only after implementation/repair has stopped:

1. stop accepting new write requests;
2. revoke/terminalize the active executor lease and commit a newer fencing epoch;
3. terminate or await every write-capable process;
4. reconcile all operation attempts and filesystem/Git observations;
5. reject unresolved merge/conflict, nested repository, submodule/LFS, or indeterminate-write conditions not covered by policy;
6. create a private Git index from the approved base;
7. apply only intended in-scope bytes, including explicitly selected untracked files;
8. write the candidate tree;
9. construct the complete commit object with exact ordered parents, identities, timestamps/timezones, message, headers, hook policy, and optional signature;
10. persist immutable `final_commit_candidates` evidence containing both tree and commit OIDs.

The user's original index is not used or modified.

## 4. Exact-object verification

Materialize the pre-created candidate commit object in a disposable worktree. Verification records candidate OID/tree, profile, command/tool digests, environment/network, toolchain, stdout/stderr/results, timing, exit status, and unexpected writes.

A formatter, generator, hook, or test that changes intended source invalidates the candidate. The workflow returns to repair and creates a new tree, commit object, verification set, review, and approval request.

## 5. Review package

The reviewer receives:

- objective and approved plan;
- base/parent OIDs and candidate commit/tree OIDs;
- canonical diff and complete file manifest;
- modes, symlinks, binaries, submodules, LFS pointers, generated/ignored files;
- scope-to-plan mapping;
- exact verification evidence;
- policy exceptions, objections, and recovery status;
- complete proposed commit metadata and digest fingerprint.

A review citing any other OID is stale.

## 6. Canonical approval request

The core constructs and canonicalizes the request; UI and agents cannot supply a replacement body. Required final-commit operation fields include:

```json
{
  "repositoryIdentityDigest": "sha256:...",
  "baseCommit": "012345...",
  "expectedRef": "refs/heads/agent/task-1",
  "expectedOldRefValue": "012345...",
  "candidateTree": "fedcba...",
  "candidateCommitOid": "89abcd...",
  "plan": {"id": "plan-7", "version": 3, "contentDigest": "sha256:..."},
  "verificationSetDigest": "sha256:...",
  "reviewArtifactDigest": "sha256:...",
  "commit": {
    "messageDigest": "sha256:...",
    "authorIdentityRef": "user:git-author",
    "authorTimestamp": "2026-08-04T08:00:00Z",
    "committerIdentityRef": "core:finalizer",
    "committerTimestamp": "2026-08-04T08:00:00Z",
    "hookPolicy": "disabled_exact_object"
  },
  "executorFencingEpoch": 20
}
```

The top-level request additionally binds `taskId`, `operationIntentId`, `actorBindingDigest`, policy snapshot, workspace version, requested/expiry times, and nonce. Canonicalization follows RFC 8785 and SHA-256 after exact schema validation.

## 7. Actor-bound decision receipt

Approval produces an immutable receipt binding:

- canonical approval request digest;
- task and logical operation intent;
- actor/session binding digest;
- nonce and decision;
- credential evidence digest;
- core decision time and receipt digest.

`resolved_by` text is not authorization evidence. A Windows Hello or equivalent signature may prove the actor gesture, but the application still defines and verifies the canonical challenge and replay scope.

## 8. Commit/ref operation

After approval, the broker does not reconstruct or restage the commit. Under the per-task barrier it:

1. verifies the exact granted receipt, current fencing epoch, repository identity, ref, expected old OID, and candidate commit OID;
2. verifies the candidate object still exists and its tree/headers match immutable evidence;
3. performs expected-old-value ref compare-and-swap to the approved candidate OID;
4. rereads the ref/object and persists a typed receipt against the exact operation attempt;
5. updates the isolated worktree/index as cleanup without changing the authoritative commit result.

Hooks do not run implicitly. `preverified_hooks` run earlier as isolated verification tools; any state change creates a new candidate.

## 9. Replay and recovery

Approval authorizes one logical effect, not one process call and not an unlimited bearer capability. Multiple dispatch attempts may reconcile the same exact tuple.

Recovery is three-way:

- ref still equals expected old OID: retry the same CAS to the same candidate OID;
- ref equals candidate OID: recover success without another update;
- ref equals anything else: invalidate/block and never overwrite automatically.

Different actor/session, repository, task, intent, ref, old OID, candidate OID, digest, nonce, or expiry fails.

## 10. Acceptance invariants

- changing any commit metadata changes the candidate OID and invalidates approval;
- final ref new value always equals the approved candidate OID;
- wrong actor/session and cross-effect replay are rejected;
- workspace mutation after candidate creation cannot enter the approved object;
- crash after ref update but before database receipt recovers by ref query without duplicate effect;
- no terminal success is emitted before the ref/object receipt is persisted.
## v4.2 exact finalization correction

The only valid local-commit sequence is:

1. build the candidate tree;
2. construct the complete immutable commit object, including parents, author,
   committer, timestamps, message, headers, signatures, and tree;
3. persist `candidate_tree_oid` and `candidate_commit_oid`;
4. verify the exact tuple and create `final_commit_verification_receipts`;
5. perform final review citing both OIDs;
6. issue a credential-bound approval for the exact candidate commit OID,
   expected ref, and expected old OID;
7. enter `RefPromotion` and perform only expected-old-value ref CAS;
8. prove the resulting ref equals the approved candidate commit OID.

No step after approval may construct, amend, sign, retimestamp, or otherwise
change the commit. Repair discards or invalidates both candidate OIDs,
verification evidence, and dependent approval. `LocalCommit` is a historical v1
phase name and must not be implemented as commit construction.

Read-only deliverables and workspace-only outcomes use their own acceptance and
completion packages. They never overload final-commit approval.
