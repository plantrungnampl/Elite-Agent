# Storage and Data Model

## 1. Storage strategy

Use three complementary stores:

1. **SQLite:** events, metadata, state projections, approvals, agent runs, policy decisions, indexes.
2. **Filesystem:** source-backed artifacts, transcripts, plans, patches, logs, test outputs, exported packages.
3. **Embedded vector store:** semantic index referencing authoritative file or event sources.

SQLite and filesystem remain usable without the vector store.

The normative executable DDL is
[`schemas/sqlite-v1.sql`](schemas/sqlite-v1.sql). The column sketches below
explain intent and must not replace the DDL during implementation.

## 2. SQLite configuration

Recommended settings:

- WAL journaling;
- foreign keys enabled;
- busy timeout configured;
- transactional event append and projection update;
- schema migration table;
- periodic integrity check;
- explicit backup/export command;
- SQLite online backup API for consistent backups, including WAL state;
- `BEGIN IMMEDIATE` for expected-version event appends;
- explicit indexes and foreign-key actions from the normative DDL.

## 3. Core tables

### projects

```text
id TEXT PRIMARY KEY
name TEXT NOT NULL
repository_path TEXT NOT NULL
repository_identity TEXT NOT NULL
created_at TEXT NOT NULL
updated_at TEXT NOT NULL
policy_profile_id TEXT NOT NULL
artifact_root_mode TEXT NOT NULL
artifact_root_path TEXT NOT NULL
```

### tasks

```text
id TEXT PRIMARY KEY
project_id TEXT NOT NULL
title TEXT NOT NULL
objective TEXT NOT NULL
phase TEXT NOT NULL
condition TEXT NOT NULL
operation_state TEXT NOT NULL
risk_level TEXT NOT NULL
base_branch TEXT NOT NULL
base_commit TEXT NOT NULL
task_branch TEXT
worktree_path TEXT
created_at TEXT NOT NULL
updated_at TEXT NOT NULL
current_sequence INTEGER NOT NULL
workspace_version INTEGER NOT NULL
fencing_epoch INTEGER NOT NULL
active_candidate_tree TEXT
```

`current_sequence` and `workspace_version` are projections updated in the same
SQLite transaction as their corresponding event append. They are never a
second source of truth.

### events

```text
event_id TEXT PRIMARY KEY
stream_id TEXT NOT NULL
sequence INTEGER NOT NULL
event_type TEXT NOT NULL
schema_version INTEGER NOT NULL
actor_type TEXT NOT NULL
actor_id TEXT NOT NULL
observation_class TEXT NOT NULL
payload_json TEXT NOT NULL
metadata_json TEXT NOT NULL
causation_id TEXT
correlation_id TEXT NOT NULL
created_at TEXT NOT NULL
UNIQUE(stream_id, sequence)
```

### agent_descriptors

```text
id TEXT PRIMARY KEY
display_name TEXT NOT NULL
transport_type TEXT NOT NULL
trust_tier TEXT NOT NULL
manifest_json TEXT NOT NULL
manifest_digest TEXT NOT NULL
executable_digest TEXT
enabled INTEGER NOT NULL
containment_verified INTEGER NOT NULL
last_health_status TEXT
updated_at TEXT NOT NULL
```

### agent_runs

```text
id TEXT PRIMARY KEY
task_id TEXT NOT NULL
agent_id TEXT NOT NULL
role TEXT NOT NULL
phase TEXT NOT NULL
status TEXT NOT NULL
context_package_id TEXT NOT NULL
idempotency_key TEXT NOT NULL UNIQUE
started_at TEXT
completed_at TEXT
connection_binding_digest TEXT NOT NULL
run_config_artifact_id TEXT NOT NULL
provider_usage_json TEXT
core_usage_json TEXT
estimated_cost_microunits INTEGER
error_json TEXT
```

### messages

A projection for UI and search. The authoritative form remains events.

```text
id TEXT PRIMARY KEY
task_id TEXT NOT NULL
run_id TEXT NOT NULL
thread_id TEXT NOT NULL
message_type TEXT NOT NULL
reply_to TEXT
content_artifact_id TEXT NOT NULL
status TEXT NOT NULL
core_received_at TEXT NOT NULL
superseded_by TEXT
```

### artifacts

```text
id TEXT PRIMARY KEY
task_id TEXT
project_id TEXT NOT NULL
artifact_type TEXT NOT NULL
logical_path TEXT NOT NULL
content_hash TEXT NOT NULL
storage_key TEXT NOT NULL
size_bytes INTEGER NOT NULL
mime_type TEXT
availability TEXT NOT NULL
created_by_type TEXT NOT NULL
created_by_id TEXT NOT NULL
created_at TEXT NOT NULL
supersedes TEXT
verification_state TEXT NOT NULL
```

### context_packages

```text
id TEXT PRIMARY KEY
task_id TEXT NOT NULL
agent_id TEXT NOT NULL
role TEXT NOT NULL
objective TEXT NOT NULL
manifest_artifact_id TEXT NOT NULL
content_hash TEXT NOT NULL
policy_snapshot_digest TEXT NOT NULL
effective_content_artifact_id TEXT NOT NULL
prompt_template_version TEXT NOT NULL
retrieval_pipeline_version TEXT NOT NULL
created_at TEXT NOT NULL
```

A package may depend on many item-level decisions, represented by
`context_package_policy_decisions(package_id, policy_decision_id)`.

### policy_decisions

```text
id TEXT PRIMARY KEY
task_id TEXT
actor_json TEXT NOT NULL
actor_binding_digest TEXT NOT NULL
action TEXT NOT NULL
resource_json TEXT NOT NULL
resource_digest TEXT NOT NULL
purpose TEXT NOT NULL
workflow_phase TEXT NOT NULL
effect TEXT NOT NULL
matched_rules_json TEXT NOT NULL
policy_snapshot_digest TEXT NOT NULL
operation_digest TEXT NOT NULL
created_at TEXT NOT NULL
expires_at TEXT
approval_id TEXT
```

### approvals

```text
id TEXT PRIMARY KEY
task_id TEXT NOT NULL
approval_type TEXT NOT NULL
schema_version TEXT NOT NULL
operation_digest TEXT NOT NULL
status TEXT NOT NULL
requested_at TEXT NOT NULL
resolved_at TEXT
resolved_by TEXT
expires_at TEXT NOT NULL
request_artifact_id TEXT NOT NULL
invalidation_reason TEXT
```

The request artifact conforms to
[`schemas/approval-digest.v1.schema.json`](schemas/approval-digest.v1.schema.json).
Approval validity is re-evaluated against the canonical request immediately
before execution.

### tool_executions

```text
id TEXT PRIMARY KEY
task_id TEXT NOT NULL
run_id TEXT
request_id TEXT NOT NULL
tool_name TEXT NOT NULL
arguments_artifact_id TEXT NOT NULL
policy_decision_id TEXT NOT NULL
approval_id TEXT
operation_intent_id TEXT NOT NULL
status TEXT NOT NULL
started_at TEXT
completed_at TEXT
exit_code INTEGER
stdout_artifact_id TEXT
stderr_artifact_id TEXT
executor_fencing_token INTEGER
UNIQUE(run_id, request_id)
```

### executor_leases

```text
task_id TEXT PRIMARY KEY
holder_run_id TEXT NOT NULL
fencing_token INTEGER NOT NULL
status TEXT NOT NULL
acquired_at TEXT NOT NULL
expires_at TEXT NOT NULL
released_at TEXT
```

Tokens increase monotonically for a task and are never reused. The lease row is
not sufficient by itself: every write-capable operation persists and rechecks
the token immediately before its side effect.

### operation_intents

```text
id TEXT PRIMARY KEY
task_id TEXT NOT NULL
run_id TEXT
operation_kind TEXT NOT NULL
idempotency_class TEXT NOT NULL
idempotency_key TEXT NOT NULL UNIQUE
canonical_request_artifact_id TEXT NOT NULL
operation_digest TEXT NOT NULL
status TEXT NOT NULL
executor_fencing_token INTEGER
lease_owner TEXT
lease_expires_at TEXT
attempt_count INTEGER NOT NULL
result_artifact_id TEXT
external_receipt_json TEXT
error_json TEXT
created_at TEXT NOT NULL
updated_at TEXT NOT NULL
```

Allowed idempotency classes:

- `idempotent`;
- `queryable`;
- `non_repeatable`.

An incomplete `non_repeatable` intent becomes `indeterminate` unless external
evidence proves the result.

### artifact_operations

```text
id TEXT PRIMARY KEY
artifact_id TEXT NOT NULL
temp_name TEXT NOT NULL
expected_hash TEXT NOT NULL
expected_size INTEGER NOT NULL
status TEXT NOT NULL
created_at TEXT NOT NULL
updated_at TEXT NOT NULL
completed_at TEXT
error_json TEXT
```

This journal reconciles SQLite metadata with content-addressed filesystem
bytes. SQLite and the filesystem are never treated as one transaction.

### context_package_policy_decisions

```text
package_id TEXT NOT NULL
policy_decision_id TEXT NOT NULL
PRIMARY KEY(package_id, policy_decision_id)
```

### signed_checkpoints

```text
id TEXT PRIMARY KEY
last_event_id TEXT NOT NULL
stream_heads_artifact_id TEXT NOT NULL
previous_checkpoint_hash TEXT
checkpoint_hash TEXT NOT NULL
signature BLOB
created_at TEXT NOT NULL
```

Signed checkpoints are optional. An unsigned hash stored beside mutable data is
corruption detection, not protection against a local attacker able to rewrite
the store.

### memory_entries

```text
id TEXT PRIMARY KEY
project_id TEXT NOT NULL
memory_type TEXT NOT NULL
status TEXT NOT NULL
content_artifact_id TEXT NOT NULL
source_refs_json TEXT NOT NULL
verification_method TEXT
verification_artifact_id TEXT
confidence_millionths INTEGER NOT NULL
approved_by TEXT
created_at TEXT NOT NULL
superseded_by TEXT
```

## 4. Event naming

Use past-tense facts:

```text
task.created
workspace.prepared
context.package.created
agent.run.started
agent.message.created
agent.message.superseded
agent.run.completed
specialist.requested
specialist.approved
policy.evaluated
approval.requested
approval.granted
tool.execution.started
tool.execution.completed
file.change.applied
verification.completed
workflow.phase.changed
commit.created
task.completed
```

## 5. Event versioning

Every event payload contains `schemaVersion`. Event readers must support upcasting old payloads to the current in-memory form. Historical rows are never rewritten during ordinary migration.

## 6. Artifact naming and atomic writes

Artifacts are written using:

1. calculate the intended content hash and persist an `artifact_operations`
   intent plus reserved artifact ID;
2. create a temporary file in the content-addressed-store directory;
3. write, flush, synchronize, and verify size/hash;
4. atomically rename to the hash-derived storage key;
5. complete artifact metadata and journal status in SQLite;
6. reconcile incomplete intents and quarantine unverifiable bytes at startup.

The exact state table and crash boundaries are defined in
[Crash consistency and recovery](15-crash-consistency-recovery.md).

Example layout:

```text
<artifact-root>/tasks/task-001/
├── context-packages/ctx-501.json
├── proposals/proposal-architecture.md
├── discussions/thread-auth-security.jsonl
├── plans/approved-plan.md
├── patches/implementation.patch
├── test-results/unit-tests.txt
├── logs/tool-77.stdout.log
└── final/decision-package.md
```

`<artifact-root>` defaults to `%LOCALAPPDATA%/AgentTerminal/artifacts`. An
opt-in project-local root is excluded from Git and cannot be inside the task
worktree.

## 7. Projections

Read models include:

- current task state;
- task timeline;
- active agent runs;
- shared-room conversation;
- unresolved objections;
- approval queue;
- cost and usage summary;
- verification dashboard;
- project memory browser.

Projections can be rebuilt from events and artifact metadata.

Projection rebuilds run into shadow tables and swap only after validation.
Projection failure cannot mutate the event stream.

## 8. Backup and export

A project export includes:

- SQLite subset for the project;
- project policy;
- project memory;
- selected task artifacts;
- manifest with hashes and schema versions;
- optional encrypted provider configuration references, never plaintext keys.

The export is created from a consistent SQLite snapshot and a frozen artifact
manifest. Missing, mismatched, or changing artifacts fail the export rather
than producing a partial package marked complete.

## 9. Retention

Default retention:

- events and decisions: retained;
- approved plans and final artifacts: retained;
- raw stream deltas: compact after task completion;
- large command logs: configurable retention;
- private scratch data: deleted after task completion unless promoted;
- vector index: rebuildable and removable.

Retention never deletes bytes referenced by active events, approvals,
checkpoints, or exports. Garbage collection first writes a candidate manifest,
revalidates reachability, and moves content to quarantine before eventual
deletion.
