# M4 Task 4 Authority and Artifact Hardening Design

## Scope

This corrective design closes four review findings in M4 Task 4 without changing
the normative documents in `docs/multi-agent-terminal-design`:

1. plan approval must compare against live repository state;
2. plan approval must compare against the live policy snapshot;
3. SQLite-backed artifact reads must use the hardened content-addressed reader;
4. persisted artifact identity metadata must be immutable.

The existing transactional context, deliberation, event, and approval projections
remain unchanged except where these authority checks require a narrower boundary.

## Architecture

### Live plan-approval authority

Add an application port that returns the current repository fingerprint and policy
snapshot digest for one task. `SqliteStore` receives this port explicitly when it is
used as a `PlanApprovalStore`. A store without the port fails closed when asked for
current approval state or when executing a compare-and-terminalize operation.

The live provider owns repository and policy observation. SQLite continues to own
durable approval bytes, task state, base commit, risk class, workspace version,
fencing epoch, and registered agent manifest. It must not infer live repository
state from `projects.repository_identity`, because that value identifies the Git
repository location and object format rather than mutable source state. It must not
infer current policy from the newest historical context package.

Every `current_state`, resolve, invalidate, and expire CAS reads the live authority
before opening its SQLite transaction, then compares the resulting digests with the
stored approval binding inside the transaction. Missing, malformed, or mismatched
authority fails closed and writes no terminal event or approval status.

### Hardened artifact reads

Replace direct `fs::read(root.join(storage_key))` with
`ContentAddressedArtifactStore` through the existing `ArtifactStore::read` contract.
The SQLite adapter constructs an `ArtifactRef` from verified metadata and delegates
physical access to the capability-rooted reader. That reader enforces the
hash-derived object key, no-follow open, regular-file type, declared size, bounded
same-handle read, and content hash.

SQLite still checks task ownership, availability, artifact kind, expected digest,
and expected size before accepting the physical bytes.

### Immutable artifact identity

Extend migration V6 hardening with an update trigger that forbids changes to artifact
identity and content-location fields after insertion: task/project ownership, type,
logical path, content hash, storage key, size, MIME type, creator identity/time,
supersession relation, and artifact ID. Existing artifact-journal transitions may
change only `availability` and `verification_state` according to their existing
constraints.

Context package persistence also requires the manifest artifact kind `manifest`.
An exact package replay therefore cannot silently bind the same manifest artifact ID
to different physical content.

## Data and error flow

1. Load the canonical approval request and immutable event authority from SQLite.
2. Ask the live authority provider for repository and policy digests.
3. Build current approval state from live digests plus transactional SQLite state.
4. Compare every bound leaf and append at most one terminal event/status atomically.
5. Return a safe conflict/integrity/unavailable classification without exposing paths,
   policy internals, or repository details.

Approval resolution is never authorized from cached historical context-package data
or stable repository identity.

## Verification

Add RED/GREEN regressions for:

- live repository fingerprint change rejecting stale resolution, including reopen;
- live policy snapshot change rejecting stale resolution, including reopen;
- missing live authority failing closed without mutation;
- task version and agent manifest drift continuing to fail CAS;
- concurrent terminal CAS retaining one winner;
- non-hash-derived storage keys, symlink/reparse substitution, oversized/special files,
  and post-open replacement using the hardened reader contract;
- artifact metadata substitution rejected by the V6 trigger;
- context manifests requiring the expected artifact kind;
- exact prior migration checksums and V5-to-V6 upgrade compatibility.

Run the Task 4 targeted tests, affected domain/application suites, storage-files suite,
full Rust quality gates, and architecture contracts before commit.
