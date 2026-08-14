# Open Governance Hardening Verification

**Date:** 2026-08-06

## Outcome

The three reviewed gaps are closed in the design package and executable contracts.

1. Artifact lifecycle is database-enforced across the v3.2 baseline, clean v4 schema, and v2-to-v3 migration.
2. The optional external retrieval sidecar defaults to the `brokered_process` trust tier, with explicit `isolated_worker` escalation when a mounted task volume or local execution is required.
3. Crash-open retrieval sessions can close as terminal `indeterminate` only with a task-scoped exact trace artifact and completion time.

## Artifact lifecycle contract

Availability permits only:

- `reserved → available|quarantined|missing`;
- `available → quarantined|missing`;
- `missing → available|quarantined`;
- no-op updates.

`quarantined` is terminal in place.

Verification permits only:

- `unverified → hash_verified|tool_verified|rejected`;
- `hash_verified → tool_verified|user_approved|rejected`;
- `tool_verified → user_approved|rejected`;
- `user_approved → rejected`;
- no-op updates.

`rejected` is terminal in place. Artifact metadata rows are retained, and an existing ID or `(project_id, logical_path, content_hash)` identity cannot be replaced through `INSERT OR REPLACE`.

## Retrieval recovery contract

A new retrieval session starts `running`. It may terminalize as `succeeded`, `degraded`, `failed`, or `indeterminate`. Every terminal state requires `completed_at`, `trace_artifact_id`, and matching `trace_digest`; terminal state and trace evidence are immutable. Startup recovery writes `indeterminate` when no authoritative outcome can be proved. Retry creates a new session.

## Red-green evidence

Before the fixes:

- v3.2 artifact hardening: `64/66`, then bypass review `66/68`;
- v4 cognitive suite: `73/77`, then bypass review `77/79`;
- v4 traceability: `27/30`.

After the fixes:

- core regression: `39/39`;
- v3.2 adversarial hardening: `68/68`;
- v4 cognitive memory and quality: `79/79`;
- v4 traceability: `30/30`;
- full package validation: `56/56`;
- clean and migrated SQLite schemas: `294/294` normalized objects equivalent;
- SQLite `integrity_check`: `ok`;
- SQLite `foreign_key_check`: no rows.

## Remaining runtime evidence

This package proves design-contract behavior, not installed-product containment. The exact sidecar executable, manifest, policy, identity, ACL, network profile, process-tree containment, disclosure routes, and crash behavior still require runtime release evidence under G7 and G11.
