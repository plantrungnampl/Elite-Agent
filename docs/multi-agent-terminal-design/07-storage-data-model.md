# Storage and Data Model v4.2

> **v4.3 authority notice:** `schemas/sqlite-v7.sql` is the current clean-install contract and `schemas/migrate-v6-to-v7.sql` is the current migration. Earlier schema references are historical unless explicitly preserved.


## 1. Storage strategy

The system uses three complementary stores:

1. **SQLite authority store:** task state, immutable evidence, authority bindings, protocol trace, leases, approvals, attempts, and recovery metadata.
2. **Content-addressed artifact store:** canonical requests, context payloads, transcripts, receipts, logs, verification outputs, migration evidence, and exports.
3. **Embedded retrieval index:** vector/keyword/graph indexes that reference authoritative source documents and can be rebuilt.

The vector store is never authoritative. SQLite and artifacts remain sufficient to reconstruct decisions and recovery state.

The normative v4.2 clean-install DDL is [`schemas/sqlite-v6.sql`](schemas/sqlite-v6.sql). [`schemas/migrate-v5-to-v6.sql`](schemas/migrate-v5-to-v6.sql) accepts only the exact reviewed v4.1.1 `sqlite-v5.sql` contract. Older schemas remain immutable migration and regression baselines.

## 2. Connection contract

Every authoritative connection is created by one storage factory. Before dispatch opens, the factory sets and query-verifies:

- `foreign_keys=ON`;
- WAL mode;
- the selected synchronous durability level;
- busy timeout;
- defensive/trusted-schema policy supported by the runtime;
- expected application and schema versions.

Failure is fail-closed for writes. A `PRAGMA` inside a migration file does not prove later connections use the setting.

## 3. Authority records

### Tasks and optimistic transitions

`tasks` carries the workflow projection, monotonic `workspace_version` and `fencing_epoch`, and an exact `row_version`. Every accepted authoritative command supplies the expected row version and increments it exactly once. The DDL rejects every task update that does not set `row_version = OLD.row_version + 1`; fencing and workspace versions also cannot decrease.

### Immutable event and checkpoint evidence

`events`, schema migration records, signed checkpoints, approval requests/receipts/consumptions, containment attestations/revocations, agent runs, messages, policy decisions, operation intents/attempts, tool executions, protocol trace state, and update-journal records are retained where they form authority or recovery evidence. Correction uses a new amendment, supersession, revocation, or event; source evidence is never edited in place.

### Agent descriptors and containment attestations

An external descriptor does not carry a trusted Boolean. It references an immutable attestation for the exact tuple:

`(descriptor, executable digest, manifest digest, launcher digest, isolation profile digest, OS build, architecture, suite version)`.

Revocation is a separate append-only row and immediately disables the affected descriptor. An enabled external descriptor must reference a matching, current, unrevoked attestation both when it is enabled and when each run is created. Tuple changes require a new attestation.

### Context packages

A context package is an immutable disclosure receipt. Its effective artifact hash must match `content_hash`; manifest/effective artifacts must belong to the same task project and cannot be borrowed from another task. `content_hash` is the digest of the effective model-input artifact, while the manifest artifact has its own artifact-store digest. A run ID is preallocated before compilation, and a unique index prevents one package from being consumed by multiple runs.

### Agent runs and messages

A run can be inserted only when its task, agent, role, context package, run-configuration artifact, and optional superseded run form one coherent scope. Run role, phase, and authority identity are immutable. A message must bind a run and content artifact from the same task/project; reply and supersession links remain in the same task/thread. At most one `terminal_result` message exists per run. Agent claims remain distinguished from core/tool observations.

## 4. Logical operations and attempts

`operation_intents` represent stable logical effects. Identity includes task, optional same-task run, operation kind, idempotency class/key, canonical request artifact, operation digest, and actor binding. The canonical request artifact hash must equal the operation digest. Intent rows are retained, and the aggregate cannot advance its attempt number without the corresponding persisted attempt.

`operation_attempts` represent individual dispatches. Each attempt records:

- strictly increasing attempt number;
- owner run and fencing token;
- exact policy and approval bindings;
- external request ID;
- started/boundary/terminal timestamps;
- typed result, receipt, and error artifacts;
- terminal state.

At most one attempt is active. Identity fields are immutable, attempt rows cannot be deleted, and evidence fields are task-scoped and set-once using NULL-safe comparisons so persisted evidence cannot be cleared back to `NULL`. A `require_approval` policy must name the exact granted, unexpired approval used by the attempt. A successful attempt requires a persisted receipt. A terminal attempt or logical intent cannot be reversed, and a terminal logical intent requires its matching current terminal attempt. A late completion may affect only its exact attempt and may update the aggregate only through a current-attempt compare-and-set.

## 5. Scope-coherent authority chain

Before an attempt or tool execution is accepted, SQLite/runtime checks that:

- task, run, intent, attempt, policy, and approval belong to the same task;
- policy and approval bind the exact operation digest and actor binding;
- approval is granted and unexpired when required;
- attempt number is the next number;
- the write fencing token matches the current active lease at broker commit time.

A set of individually valid IDs from different tasks is not a valid authority chain.

## 6. Executor leases

Lease history uses immutable rows keyed by task and fencing token. Transfer creates a new row; it never edits the old holder/token. Only one lease per task may be active. Grant/transfer is one `BEGIN IMMEDIATE` transaction that:

1. verifies expected task row/fencing version;
2. terminalizes the old active lease;
3. increments the task fencing epoch exactly once;
4. inserts the new active lease and grant evidence;
5. commits.

SQLite linearizes the grant in the database. The shared broker barrier described in the architecture linearizes it against external filesystem/Git mutation.

## 7. Approval and final commit records

An approval request starts pending and binds task, logical intent, actor binding, operation digest, nonce, expiry, policy, and an immutable task-scoped request artifact. Resolution requires a matching immutable decision receipt with task-scoped credential evidence and the same authoritative decision time. Resolution/invalidation evidence is set-once.

`final_commit_candidates` retain an immutable SHA-256 repository identity, expected ref/old OID, candidate tree OID, pre-created candidate commit OID, exact metadata digest, and verification digest. A `git.final_commit` intent accepts only a `final_commit` approval. Approval consumption is scoped to the exact repository/ref/old-OID/candidate-OID logical effect; retry attempts may reconcile that same effect but cannot reuse approval for another task/ref/OID.

## 8. Protocol trace

`protocol_requests` stores durable `(connectionId, requestId, method, requestDigest)` correlation. A run-bound request must use a run from the same task. Identity is immutable, terminal status cannot reverse, and rows cannot be deleted and recreated to reset replay history. A completed request requires a persisted, task-scoped response artifact and completion time; response evidence is set-once. The same ID with another digest is a conflict.

`protocol_stream_heads` enforces contiguous sequence advancement per immutable connection/run/channel identity. Stream-head rows cannot be deleted or renamed to reset sequence history. Pending requests cannot carry a completion time; completed and failed requests require terminal timing, and completed requests require persisted response evidence. Durable protocol state survives process restart.

## 9. Artifact commit protocol

Artifact writes use same-volume staging under the artifact root:

1. reserve deterministic content identity and operation intent;
2. create a private temporary file;
3. write bytes and flush according to the Windows adapter contract;
4. verify size and hash;
5. promote using the selected same-volume primitive;
6. reopen/verify final identity, bytes, size, and hash;
7. persist the typed receipt against the exact attempt.

Failure or crash is reconciled from both database state and actual resource identity. A generic successful `rename` return is not by itself a durability receipt.

## 10. Projections, backup, retention, and migration

Read models may be updated by compare-and-set or rebuilt from immutable history. Projection checkpoints cannot move backwards.

Backup is whole-state: SQLite online backup, reachable artifacts, policy/config, update journal, and credential references. Garbage collection uses authoritative reachability and quarantine before deletion.

The v1-to-v2 migration follows [`21-v1-to-v2-migration-contract.md`](21-v1-to-v2-migration-contract.md). Missing actor, attempt, containment, or candidate-commit evidence is not invented; affected records are invalidated, marked indeterminate, or quarantined.
## 11. v3.2 artifact, run, tool, and retrieval guards

Artifact identity (task/project/type/path/hash/storage key/size/creator/time/supersession) is immutable. Supersession stays within one project/task/type/logical path. An unreferenced artifact must be quarantined before physical byte garbage collection. The artifact metadata row is retained and its identity cannot be replaced. Artifact operation identity and terminal evidence are retained for startup reconciliation.

Artifact availability follows an explicit graph: `reserved → available|quarantined|missing`, `available → quarantined|missing`, and `missing → available|quarantined`. `quarantined` is terminal in place; restoration creates a new verified artifact row and may use `supersedes` rather than reviving quarantined bytes. Verification follows `unverified → hash_verified|tool_verified|rejected`, `hash_verified → tool_verified|user_approved|rejected`, `tool_verified → user_approved|rejected`, and `user_approved → rejected`. `rejected` is terminal in place. No-op updates remain valid.

Agent-run identity and terminal/usage/error evidence are set-once and retained. Messages are retained; terminal message status cannot reverse, and a superseded message requires one immutable replacement link. Tool execution must use the exact active attempt's policy and approval, task-scoped argument/output artifacts, terminal completion time, and set-once evidence.

Retrieval records are not authority, but privacy scope is still enforced: task-bound source documents must belong to the task project, memory content/verification artifacts must belong to the memory project, and graph edges cannot connect nodes from another project.

## 12. v4 cognitive authority records

`schemas/sqlite-v3.sql` extends v2 with:

- `memory_records` and `memory_evidence_links` for typed, logical-keyed, versioned memory;
- `memory_relations` for scoped relations such as supersedes, contradicts, and derived-from;
- `working_memory_snapshots` for recoverable run state;
- `episodes` and `episode_steps` for verified execution experience;
- `retrieval_sessions` and `retrieval_candidates` for explainable retrieval traces;
- `context_package_items` and `context_item_feedback` for item-level provenance and immutable usefulness feedback;
- `run_reflections` and `run_evaluations` for learning and quality evidence;
- `memory_promotion_reviews` for immutable promotion decisions;
- `index_generations` for replaceable engine lifecycle and rebuild receipts;
- `benchmark_suites`, `benchmark_cases`, `benchmark_runs`, and `benchmark_comparisons` for comparable quality evidence.

Authority rules:

- every memory starts as `candidate`; `verified` requires supporting evidence, `approved` requires a granted review, and `active` requires both plus an atomic activation timestamp equal to the status transition time;
- activation evidence cannot be preloaded or rewritten, expired records cannot activate, and a project/logical key has at most one active version;
- a `stale` memory cannot return to `verified`; reuse requires a new immutable version, fresh evidence, a new review, and a `supersedes` relation;
- any transition to `superseded` requires an existing `supersedes` relation from a newer record with the same logical key and memory type; candidate/verified/approved records may be terminalized without first becoming active;
- `applicability_json` is structured and validated: it contains a non-empty summary and explicit scope; project/task scopes must match the authority record, and preference memory additionally requires an explicit subject;
- memory versions are immutable; correction creates a new record and relation;
- working-memory snapshots and reflections bind their stored digest to the exact artifact bytes and remain append-only;
- reflection and evaluation records are append-only;
- retrieval scores are trace evidence, not authority; terminal retrievals require a matching exact trace artifact and immutable final branch status;
- crash recovery may terminalize an open retrieval as `indeterminate`; retry creates a new session instead of rewriting the uncertain receipt;
- every context item belongs to the same task/project as its package and references an authoritative artifact, source chunk, or active memory record;
- index generations can be deleted or rebuilt only through journaled operations; authority records survive;
- benchmark suite manifests bind exact artifact digests; result artifact scope is checked again when terminal evidence is attached;
- benchmark runs bind suite version, system and evaluator configuration digests, repository revision set, and budget profile, and comparisons require both configuration digests to match.

The legacy `memory_entries` table remains readable during migration, but v4 schema installation makes it write-frozen: `INSERT`, `UPDATE`, and `DELETE` are rejected by database triggers. The backfill reads the retained rows through `SELECT` only, and all new writes target `memory_records`.

## 13. Historical v4.1 authoritative state and memory utility records

`schemas/sqlite-v4.sql` is the v4.1 normative clean-install authority contract. `schemas/migrate-v3-to-v4.sql` is the additive migration from the exact reviewed v4.0 `sqlite-v3.sql` baseline.

New authority and evidence tables:

- `state_records` stores structured current values with fixed precedence, scope, validity, source digest, and supersession;
- `state_evidence_links` retains additional defining or retracting evidence;
- `state_resolution_receipts` records all candidates and the deterministic winning state;
- `memory_invalidation_evaluations` records typed rule results used to determine retrieval eligibility;
- `memory_shadow_evaluations` binds equal-input control and candidate benchmark runs;
- `memory_usage_events` records retrieved, included, cited, conclusion-used, helpful, misleading, and redundant observations;
- `memory_utility_snapshots` is a rebuildable derived projection retained by generation;
- `memory_consolidation_actions` records merge, split, retain, supersede, stale, and retract proposals and decisions;
- `context_budget_decisions` binds adaptive allocation and stopping evidence to one task, run, and context package.

Authority rules:

- state precedence is fixed and checked by both JSON and SQLite contracts;
- state value and identity are immutable; correction creates a new record and supersession link;
- a resolution receipt must choose the highest-precedence active candidate from its declared candidate set;
- v4.1 memory inserts require typed invalidation-rule objects rather than prose-only arrays;
- durable memory retrieval requires a current passing invalidation evaluation for every declared rule;
- deterministic or policy approval of semantic, procedural, or negative memory requires a passing shadow evaluation;
- usage and utility records are immutable and cannot authorize lifecycle transitions;
- consolidation actions retain all source memories;
- budget allocations must be non-negative, sum to the declared total, and match the exact task/run/package scope.

For historical traceability, `schemas/sqlite-v3.sql` was the normative v4.0 clean-install DDL. The v4.0 `sqlite-v3.sql` contract and v4.1 `sqlite-v4.sql` contract remain historical baselines and migration inputs. Neither is the v4.1.1 production authority contract.


## 14. v4.1.1 loop-reviewed authority records

Historically, `schemas/sqlite-v5.sql` was the v4.1.1 clean-install contract and `schemas/migrate-v4-to-v5.sql` its upgrade path. For v4.2, `schemas/sqlite-v6.sql` and `schemas/migrate-v5-to-v6.sql` supersede them. Clean and migrated v4.2 schemas must expose the same explicit tables, indexes, triggers, views, and relevant columns.

### State integrity

- new state starts active and must be valid at creation time;
- terminal state carries immutable `ended_at=status_changed_at`; migration backfills historical terminal records;
- equal-precedence divergent values require `state_resolution_conflicts`;
- a conflict resolution receipt carries `conflict_id`, binds the exact candidate set, and is one-to-one with the conflict;
- resolution rechecks project/task/key/status/validity, highest precedence, result artifact, digest, policy snapshot, and conflict identity.

### Memory eligibility and context inclusion

- invalidation rules are checked for supported kind, cadence, unique ID, and kind-specific target/expected payload;
- an evaluation is immutable, references a declared rule, uses coherent evidence, and is applicable to the memory scope;
- retrieval selects only applicable evaluations at or before retrieval start and still valid at that time;
- a memory context item must bind the exact selected retrieval candidate from the same preallocated package run, preventing direct insertion and cross-run candidate reuse.

### Shadow and origin integrity

- `memory_origin_records` distinguishes model-generated, user-explicit, approved-decision, imported-verified, and legacy-unknown origins and binds each origin to an allowed actor kind/ID, actor-binding digest, and exact artifact evidence/digest while the memory is still a candidate; verification requires that immutable origin;
- `benchmark_run_arms` binds model, budget, policy, and experiment arm;
- `benchmark_run_memory_bindings` gives the candidate run exactly one available evaluated memory while the control has none;
- shadow time is unique per memory, and promotion independently rechecks the latest result and exact run/memory isolation;
- historical unbound shadow rows remain retained but cannot authorize policy/deterministic promotion.

### Contribution, consolidation, and budget integrity

- included, cited, conclusion-used, helpful, misleading, and redundant usage events bind both the exact selected retrieval candidate and exact context item from the same run/package and enforce retrieved/included/cited/conclusion implications;
- consolidation cannot be marked applied before the corresponding lifecycle or relation effect exists;
- split is deferred because the current one-result shape cannot represent multiple outputs;
- allocations are integer values, sum exactly, and allocated + output reserve + verification reserve cannot exceed `max_budget_tokens`.

## v4.2 authority tables

SQLite v6 adds bounded authority tables rather than repurposing ambiguous v5
rows:

- `task_workflow_authority`, `task_acceptance_receipts`, and
  `task_completion_packages`;
- `actor_bindings`, `credential_challenges`,
  `credential_challenge_receipts`, and `approval_actor_proof_bindings`;
- `final_commit_verification_receipts` and `ref_promotion_receipts`;
- `memory_wire_contracts_v2` and `memory_subject_bindings`;
- `benchmark_suite_versions`, `benchmark_case_versions`,
  `benchmark_run_receipts_v2`, `benchmark_comparison_receipts_v2`, and
  `quality_release_decisions_v2`.

Legacy task phase and benchmark tables remain retained projections/evidence.
New v4.2 decisions must use the new authority tables.
