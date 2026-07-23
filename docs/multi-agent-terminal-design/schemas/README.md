# Machine-Readable Contracts

## Contents

- `agent-protocol.v1.schema.json`: JSON-RPC frame and payload contract;
- `approval-digest.v1.schema.json`: canonical authorization payload contract;
- `workflow-transitions.v1.json`: allowed phase, condition, and operation
  transitions;
- `sqlite-v1.sql`: normative SQLite schema, constraints, indexes, and triggers;
- `examples/`: schema-valid request and approval fixtures.

## Authority

When prose and a machine-readable contract disagree:

1. security invariants fail closed;
2. the versioned machine contract governs serialization or persistence;
3. the discrepancy is a design defect and must be corrected before release.

Schemas do not grant permission. A schema-valid request still requires identity
binding, workflow guards, current policy, approval, budget, and fencing checks.

## Versioning

- incompatible changes create a new major schema file;
- additive optional fields may create a minor protocol/schema version;
- event payloads use independent versions and upcasters;
- SQLite migrations are forward-only expand/contract steps;
- old files remain in the compatibility suite for the declared support window.

## Validation expectations

CI shall:

- compile both JSON Schemas with a Draft 2020-12 validator and format support;
- validate every file in `examples/`;
- parse and apply `sqlite-v1.sql` to a new database;
- run `PRAGMA integrity_check` and `PRAGMA foreign_key_check`;
- exercise contiguous event sequence and fencing-token triggers;
- verify every transition references a declared state and has a unique
  `(from, event)` key;
- compare implementation transition coverage with
  `workflow-transitions.v1.json`.

The migration runner records the real migration checksum and authoritative
application time after the schema transaction succeeds. Those values are not
hard-coded into `sqlite-v1.sql`.
