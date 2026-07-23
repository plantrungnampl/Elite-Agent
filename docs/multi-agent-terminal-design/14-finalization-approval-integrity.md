# Finalization and Approval Integrity

## 1. Goal

The final commit must contain exactly the Git tree that the reviewer and user
saw. An approval of a mutable worktree, a diff without its base, or a command
string without its environment is insufficient.

This specification closes three gaps:

- time-of-check/time-of-use between review and commit;
- stale executor writes after review;
- ambiguous or noncanonical approval payloads.

The normative payload schema is
[`schemas/approval-digest.v1.schema.json`](schemas/approval-digest.v1.schema.json).
A schema-valid final-commit fixture is in
[`schemas/examples/approval-final-commit.example.json`](schemas/examples/approval-final-commit.example.json).

## 2. Approval classes

### Plan approval

Binds:

- task and risk class;
- plan ID, version, and content digest;
- base commit;
- allowed path scopes;
- planned structured tools and commands;
- policy snapshot;
- expected verification profile;
- expiry.

It authorizes implementation within scope. It does not authorize arbitrary
shell, policy exceptions, destructive actions, or commit.

### Tool approval

Binds the exact structured request:

- executable identity and argv or typed tool arguments;
- cwd capability;
- environment and network profiles;
- expected reads/writes;
- task, run, plan step, phase, fencing token;
- policy snapshot and expiry.

### Policy-exception approval

Binds the actor, purpose, exact resource digest, disclosure destination,
redaction result, duration, and policy version.

### Final commit approval

Binds the immutable candidate tree and commit operation described below.

## 3. Canonical digest

All approval payloads contain:

```json
{
  "schema": "approval-digest.v1",
  "approvalType": "final_commit",
  "taskId": "task-1",
  "operation": {},
  "policySnapshotDigest": "sha256:...",
  "workspaceVersion": 42,
  "requestedAt": "2026-07-23T13:20:00Z",
  "expiresAt": "2026-07-23T13:35:00Z",
  "nonce": "..."
}
```

Digest algorithm:

1. validate against the exact schema version;
2. reject unknown fields for authorization-bearing objects;
3. canonicalize with RFC 8785 JSON Canonicalization Scheme;
4. hash the UTF-8 bytes using SHA-256;
5. store `sha256:<lowercase-hex>`;
6. display a short fingerprint while retaining the complete digest.

The core, not React or an agent, constructs and canonicalizes the payload.
Execution reconstructs it from authoritative records and recomputes the digest.

Canonicalization test vectors cover object ordering, Unicode, escaping, integer
boundaries, negative zero, floating-point rejection, duplicate keys, and
timestamp normalization. Authorization payloads prefer integers and
fixed-format decimal strings over binary floating point.

## 4. Candidate tree creation

Finalization starts only after implementation and repair stop:

1. stop accepting new write requests;
2. revoke the executor lease and persist a new fencing epoch;
3. terminate or await every write-capable process;
4. reconcile operation intents and filesystem events;
5. record Git HEAD, index, worktree, submodule, and untracked-file state;
6. reject unresolved merges, conflicts, unsupported nested repositories, or
   indeterminate writes;
7. create a private temporary Git index;
8. populate it from the approved base and intended worktree changes;
9. apply path-scope and plan validation;
10. create a candidate Git tree with `git write-tree`;
11. persist the tree ID, base commit, diff artifact, file manifest, and
    workspace version.

The application does not use or modify the user's original repository index.
Untracked intended files must be explicitly included. Ignored/generated files
are listed separately and cannot silently enter the candidate.

Submodules are represented by their gitlink commit IDs. Git LFS pointer bytes
and required object availability are recorded. Filters and attributes that can
change staged bytes are part of the candidate-tree evidence.

## 5. Verification of the exact tree

Verification runs against a clean disposable worktree materialized from the
candidate tree, not against an earlier mutable approximation.

For each check the system records:

- candidate tree ID;
- verification profile and command digest;
- toolchain paths and versions;
- environment and network profiles;
- stdout/stderr/result artifacts;
- start/end core timestamps;
- exit status;
- files created or changed by the check.

Test-generated changes do not alter the candidate tree. If a required formatter
or generator produces intended source changes, finalization stops, returns to
repair, and creates a new candidate tree after the changes are approved.

Flaky or quarantined checks remain visible and cannot be converted into
`verified` solely by an agent assertion.

## 6. Final review

The reviewer receives:

- task objective and approved plan version;
- base commit and candidate tree ID;
- canonical diff between them;
- added, deleted, renamed, binary, submodule, LFS, mode, and symlink changes;
- scope-to-plan mapping;
- exact verification results;
- policy exceptions and unresolved objections;
- known generated or ignored files;
- proposed commit metadata and hook policy.

Reviewer output cites the candidate tree ID. A review of any other revision is
stale.

## 7. Final approval payload

The `operation` for `final_commit` contains at minimum:

```json
{
  "baseCommit": "0123456789abcdef...",
  "expectedRef": "refs/heads/agent/task-1",
  "expectedOldRefValue": "0123456789abcdef...",
  "candidateTree": "fedcba9876543210...",
  "plan": {
    "id": "plan-7",
    "version": 3,
    "contentDigest": "sha256:..."
  },
  "verificationSetDigest": "sha256:...",
  "reviewArtifactDigest": "sha256:...",
  "commit": {
    "messageDigest": "sha256:...",
    "authorIdentityRef": "user:configured-git-author",
    "hookPolicy": "disabled_exact_tree"
  },
  "executorFencingEpoch": 20
}
```

The approval UI displays human-readable details generated from this immutable
object. It cannot submit a new operation body with the approval click.

## 8. Commit creation

Default hook policy is `disabled_exact_tree`:

1. construct the commit object from the approved tree, parent, author,
   committer, and exact message;
2. use a plumbing-level exact-tree operation rather than restaging mutable
   files;
3. atomically update the task branch only if the ref still equals
   `expectedOldRefValue`;
4. read the resulting commit and verify its tree equals `candidateTree`;
5. synchronize the isolated task worktree index to the approved tree without
   changing worktree files, then verify expected clean/ignored state;
6. persist the commit object ID and verification event;
7. mark the task completed only after the event append succeeds.

An implementation may use `git commit-tree` plus expected-old-value
`git update-ref` semantics. Concrete command selection belongs to the Git
adapter and must pass compatibility tests. Failure to synchronize the isolated
worktree index does not invalidate an already verified exact-tree commit, but
the task remains in a cleanup-required recovery state rather than claiming a
clean worktree.

## 9. Git hooks

Hooks are repository-controlled code and are not allowed to run implicitly
during the exact-tree commit.

Policies:

- `disabled_exact_tree`: default; no commit hook executes;
- `preverified_hooks`: selected hooks run earlier as isolated verification
  tools against the candidate tree;
- `legacy_commit_hooks`: outside MVP because hooks may alter state between
  approval and commit.

If a preverified hook changes intended source, the candidate is discarded and
the workflow returns to repair. Hook executable, bytes, arguments, environment,
network, result, and resulting writes are recorded.

## 10. Approval invalidation

An open approval becomes invalid when any bound field changes, including:

- candidate tree or base commit;
- branch ref value;
- workspace version;
- plan or verification set;
- review artifact;
- policy snapshot;
- commit message or identity;
- hook/environment/network policy;
- executor fencing epoch;
- actor, task, expiry, or nonce.

Filesystem monitoring provides fast notification, but correctness does not
depend on it. The core recomputes authoritative Git and digest state immediately
before commit.

## 11. Crash recovery

| Crash point | Recovery |
|---|---|
| Before candidate tree persisted | Discard temporary index; restart finalization |
| After tree persisted, before verification | Reuse tree after hash/ref validation |
| During verification | Mark check interrupted; rerun only if its contract permits |
| After approval, before commit object | Revalidate approval and refs; user need not reapprove if all inputs still match and approval is unexpired |
| After commit object, before ref update | Reuse commit object after verifying tree and metadata |
| After ref update, before index synchronization | Detect exact commit, synchronize isolated index, or mark cleanup required |
| After index synchronization, before completion event | Detect expected commit at ref and append recovered completion |
| Ref changed unexpectedly | Do not overwrite; invalidate approval and enter `WorkspaceDirty` or blocked recovery |

No force push, reset hard, clean, or ref overwrite is used for recovery.

## 12. Acceptance invariants

- no write-capable lease exists during final review or commit approval;
- every verification result names the candidate tree;
- the approved digest is recomputed immediately before effect;
- the branch ref update is conditional on the approved old value;
- the resulting commit tree equals the approved tree;
- any external mutation invalidates the candidate;
- hooks cannot execute implicitly;
- recovery never overwrites an unexpected ref.
