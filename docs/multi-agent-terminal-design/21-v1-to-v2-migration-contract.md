# SQLite v1 to v2 Migration Contract

## 1. Principle

The migration must preserve evidence. It must not fabricate actor identity, attempt boundaries, containment proof, or final commit OIDs that v1 did not record.

## 2. Classification

Each v1 row is classified as:

- **safe transform:** complete data can map deterministically to v2;
- **quarantine:** contradictory, cross-scope, overwritten, or unverifiable data is retained in a read-only legacy artifact and blocks the affected capability;
- **manual resolution:** a user/admin supplies a new amendment or decision; original evidence remains unchanged.

## 3. Required transformations

- copy events and checkpoints, then verify append-only hashes;
- convert each operation intent into one logical intent plus the best-supported attempt history; if prior attempts were overwritten, mark the intent `indeterminate` and attach the v1 row as legacy evidence;
- validate task/run/policy/approval/intent coherence; quarantine spliced chains;
- migrate approvals as requests only unless a matching actor-bound decision receipt can be reconstructed from authoritative credential evidence; otherwise invalidate and require reapproval;
- do not enable external descriptors from `containment_verified`; require a fresh exact-tuple attestation;
- final commit approvals without a pre-created candidate commit OID are invalidated and must be recreated;
- lease history that cannot prove monotonic transfer becomes revoked/indeterminate and requires a fresh grant.

## 4. Acceptance

Migration runs on a copy, emits a deterministic report, preserves v1 source bytes/checksum, and performs no write-capability activation. The new database must pass all v2 negative tests. Any quarantined P0 row keeps the related capability disabled until explicit resolution.
## v3.2 pre-release checksum rule

The v3.2 package hardens the pre-release `sqlite-v2.sql` clean-install contract without claiming compatibility with databases created from earlier v3 or v3.1 drafts. A migration runner must compare the recorded schema checksum with the packaged checksum. A mismatch is fail-closed: development fixtures are recreated, while any retained database requires a separately reviewed migration and validation evidence. The application must not overwrite the recorded checksum or continue writes against an unrecognized v2 layout.

