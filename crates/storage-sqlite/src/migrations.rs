use std::fmt;

use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use sha2::{Digest, Sha256};

const SUPPORTED_SCHEMA_VERSION: i64 = 9;
const NORMATIVE_SQL: &str =
    include_str!("../../../docs/multi-agent-terminal-design/schemas/sqlite-v1.sql");
const V1_ADAPTER_HARDENING_SQL: &str = r#"
CREATE TRIGGER events_update_forbidden
BEFORE UPDATE ON events
FOR EACH ROW
BEGIN
    SELECT RAISE(ABORT, 'events are immutable');
END;

CREATE TRIGGER events_delete_forbidden
BEFORE DELETE ON events
FOR EACH ROW
BEGIN
    SELECT RAISE(ABORT, 'events are immutable');
END;

CREATE TRIGGER artifact_operation_status_forward_only
BEFORE UPDATE OF status ON artifact_operations
FOR EACH ROW
WHEN NOT (
    (OLD.status = 'intent' AND NEW.status IN ('staging', 'aborted', 'quarantined'))
    OR (OLD.status = 'staging' AND NEW.status IN ('renamed', 'aborted', 'quarantined'))
    OR (OLD.status = 'renamed' AND NEW.status IN ('completed', 'quarantined'))
)
BEGIN
    SELECT RAISE(ABORT, 'artifact operation status must move forward');
END;

CREATE TRIGGER artifact_operation_completion_required
BEFORE UPDATE OF status, completed_at ON artifact_operations
FOR EACH ROW
WHEN NEW.status = 'completed' AND NEW.completed_at IS NULL
BEGIN
    SELECT RAISE(ABORT, 'completed artifact operation requires completed_at');
END;
"#;

const V2_UPGRADE_SQL: &str = r#"
CREATE TRIGGER task_fencing_epoch_monotonic
BEFORE UPDATE OF fencing_epoch ON tasks
FOR EACH ROW
WHEN NEW.fencing_epoch <= OLD.fencing_epoch
BEGIN
    SELECT RAISE(ABORT, 'task fencing epoch must increase');
END;

CREATE TRIGGER enabled_agent_requires_containment_insert
BEFORE INSERT ON agent_descriptors
FOR EACH ROW
WHEN NEW.enabled = 1
    AND NEW.trust_tier IN ('brokered_process', 'isolated_worker')
    AND NEW.containment_verified <> 1
BEGIN
    SELECT RAISE(ABORT, 'enabled agent requires verified containment');
END;

CREATE TRIGGER enabled_agent_requires_containment_update
BEFORE UPDATE OF enabled, trust_tier, containment_verified ON agent_descriptors
FOR EACH ROW
WHEN NEW.enabled = 1
    AND NEW.trust_tier IN ('brokered_process', 'isolated_worker')
    AND NEW.containment_verified <> 1
BEGIN
    SELECT RAISE(ABORT, 'enabled agent requires verified containment');
END;
"#;

const V3_POLICY_TOOL_HARDENING_SQL: &str = r#"
CREATE TRIGGER policy_decisions_update_forbidden
BEFORE UPDATE ON policy_decisions
FOR EACH ROW
BEGIN
    SELECT RAISE(ABORT, 'policy decisions are immutable');
END;

CREATE TRIGGER policy_decisions_delete_forbidden
BEFORE DELETE ON policy_decisions
FOR EACH ROW
BEGIN
    SELECT RAISE(ABORT, 'policy decisions are immutable');
END;

CREATE TRIGGER approval_request_fields_immutable
BEFORE UPDATE ON approvals
FOR EACH ROW
WHEN NEW.task_id <> OLD.task_id
    OR NEW.approval_type <> OLD.approval_type
    OR NEW.schema_version <> OLD.schema_version
    OR NEW.operation_digest <> OLD.operation_digest
    OR NEW.requested_at <> OLD.requested_at
    OR NEW.expires_at <> OLD.expires_at
    OR NEW.request_artifact_id <> OLD.request_artifact_id
BEGIN
    SELECT RAISE(ABORT, 'approval request fields are immutable');
END;

CREATE TRIGGER approval_status_forward_only
BEFORE UPDATE OF status ON approvals
FOR EACH ROW
WHEN OLD.status <> NEW.status
    AND NOT (
        (OLD.status = 'pending'
            AND NEW.status IN ('granted', 'denied', 'expired', 'invalidated'))
        OR (OLD.status = 'granted'
            AND NEW.status IN ('expired', 'invalidated'))
    )
BEGIN
    SELECT RAISE(ABORT, 'approval status must move forward');
END;

CREATE TRIGGER operation_intent_status_forward_only
BEFORE UPDATE OF status ON operation_intents
FOR EACH ROW
WHEN OLD.status <> NEW.status
    AND NOT (
        (OLD.status = 'pending'
            AND NEW.status IN ('claimed', 'started', 'cancelled'))
        OR (OLD.status = 'claimed'
            AND NEW.status IN ('pending', 'started', 'cancelled'))
        OR (OLD.status = 'started'
            AND NEW.status IN (
                'succeeded', 'failed', 'interrupted', 'indeterminate', 'cancelled'
            ))
        OR (OLD.status = 'interrupted' AND NEW.status IN ('pending', 'cancelled'))
        OR (OLD.status = 'indeterminate'
            AND NEW.status IN ('succeeded', 'failed', 'cancelled'))
        OR (OLD.status = 'succeeded'
            AND NEW.status IN ('interrupted', 'indeterminate'))
    )
BEGIN
    SELECT RAISE(ABORT, 'operation intent status must move forward');
END;

CREATE TRIGGER tool_execution_status_forward_only
BEFORE UPDATE OF status ON tool_executions
FOR EACH ROW
WHEN OLD.status <> NEW.status
    AND NOT (
        (OLD.status = 'pending' AND NEW.status IN ('running', 'denied'))
        OR (OLD.status = 'running'
            AND NEW.status IN (
                'succeeded', 'failed', 'terminated', 'interrupted', 'indeterminate', 'denied'
            ))
    )
BEGIN
    SELECT RAISE(ABORT, 'tool execution status must move forward');
END;

CREATE UNIQUE INDEX tool_execution_approval_single_use
ON tool_executions(approval_id)
WHERE approval_id IS NOT NULL;
"#;

const V4_TOOL_EXECUTION_LIFECYCLE_SQL: &str = r#"
DROP TRIGGER tool_execution_status_forward_only;
DROP INDEX tool_execution_approval_single_use;

CREATE TABLE tool_executions_v4 (
    id TEXT PRIMARY KEY,
    task_id TEXT NOT NULL REFERENCES tasks(id) ON DELETE RESTRICT,
    run_id TEXT REFERENCES agent_runs(id) ON DELETE RESTRICT,
    request_id TEXT NOT NULL,
    tool_name TEXT NOT NULL,
    arguments_artifact_id TEXT NOT NULL
        REFERENCES artifacts(id) ON DELETE RESTRICT,
    policy_decision_id TEXT NOT NULL
        REFERENCES policy_decisions(id) ON DELETE RESTRICT,
    approval_id TEXT REFERENCES approvals(id) ON DELETE RESTRICT,
    operation_intent_id TEXT NOT NULL UNIQUE
        REFERENCES operation_intents(id) ON DELETE RESTRICT,
    executor_fencing_token INTEGER CHECK (
        executor_fencing_token IS NULL OR executor_fencing_token >= 1
    ),
    status TEXT NOT NULL CHECK (
        status IN (
            'pending',
            'running',
            'succeeded',
            'failed',
            'cancelled',
            'terminated',
            'interrupted',
            'indeterminate',
            'denied'
        )
    ),
    started_at TEXT,
    completed_at TEXT,
    exit_code INTEGER,
    stdout_artifact_id TEXT REFERENCES artifacts(id) ON DELETE RESTRICT,
    stderr_artifact_id TEXT REFERENCES artifacts(id) ON DELETE RESTRICT,
    UNIQUE (run_id, request_id)
) STRICT;

INSERT INTO tool_executions_v4 (
    id, task_id, run_id, request_id, tool_name, arguments_artifact_id,
    policy_decision_id, approval_id, operation_intent_id, executor_fencing_token,
    status, started_at, completed_at, exit_code, stdout_artifact_id,
    stderr_artifact_id
)
SELECT
    id, task_id, run_id, request_id, tool_name, arguments_artifact_id,
    policy_decision_id, approval_id, operation_intent_id, executor_fencing_token,
    status, started_at, completed_at, exit_code, stdout_artifact_id,
    stderr_artifact_id
FROM tool_executions;

DROP TABLE tool_executions;
ALTER TABLE tool_executions_v4 RENAME TO tool_executions;

CREATE TRIGGER tool_execution_status_forward_only
BEFORE UPDATE OF status ON tool_executions
FOR EACH ROW
WHEN OLD.status <> NEW.status
    AND NOT (
        (OLD.status = 'pending' AND NEW.status IN ('running', 'denied'))
        OR (OLD.status = 'running'
            AND NEW.status IN (
                'succeeded', 'failed', 'cancelled', 'terminated', 'interrupted',
                'indeterminate', 'denied'
            ))
    )
BEGIN
    SELECT RAISE(ABORT, 'tool execution status must move forward');
END;

CREATE UNIQUE INDEX tool_execution_approval_single_use
ON tool_executions(approval_id)
WHERE approval_id IS NOT NULL;
"#;

const V5_PRE_EFFECT_TERMINAL_SQL: &str = r#"
DROP TRIGGER operation_intent_status_forward_only;
DROP TRIGGER tool_execution_status_forward_only;

CREATE TRIGGER operation_intent_status_forward_only
BEFORE UPDATE OF status ON operation_intents
FOR EACH ROW
WHEN OLD.status <> NEW.status
    AND NOT (
        (OLD.status = 'pending'
            AND NEW.status IN ('claimed', 'started', 'cancelled'))
        OR (OLD.status = 'claimed'
            AND NEW.status IN (
                'pending', 'started', 'interrupted', 'indeterminate', 'cancelled'
            ))
        OR (OLD.status = 'started'
            AND NEW.status IN (
                'succeeded', 'failed', 'interrupted', 'indeterminate', 'cancelled'
            ))
        OR (OLD.status = 'interrupted' AND NEW.status IN ('pending', 'cancelled'))
        OR (OLD.status = 'indeterminate'
            AND NEW.status IN ('succeeded', 'failed', 'cancelled'))
        OR (OLD.status = 'succeeded'
            AND NEW.status IN ('interrupted', 'indeterminate'))
    )
BEGIN
    SELECT RAISE(ABORT, 'operation intent status must move forward');
END;

CREATE TRIGGER tool_execution_status_forward_only
BEFORE UPDATE OF status ON tool_executions
FOR EACH ROW
WHEN OLD.status <> NEW.status
    AND NOT (
        (OLD.status = 'pending'
            AND NEW.status IN ('running', 'interrupted', 'indeterminate', 'denied'))
        OR (OLD.status = 'running'
            AND NEW.status IN (
                'succeeded', 'failed', 'cancelled', 'terminated', 'interrupted',
                'indeterminate', 'denied'
            ))
    )
BEGIN
    SELECT RAISE(ABORT, 'tool execution status must move forward');
END;
"#;

const V6_CONTEXT_HARDENING_SQL: &str = r#"
CREATE TRIGGER context_packages_update_forbidden
BEFORE UPDATE ON context_packages
FOR EACH ROW
BEGIN
    SELECT RAISE(ABORT, 'context packages are immutable');
END;

CREATE TRIGGER context_packages_delete_forbidden
BEFORE DELETE ON context_packages
FOR EACH ROW
BEGIN
    SELECT RAISE(ABORT, 'context packages are immutable');
END;

CREATE TRIGGER context_package_policy_decisions_update_forbidden
BEFORE UPDATE ON context_package_policy_decisions
FOR EACH ROW
BEGIN
    SELECT RAISE(ABORT, 'context package policy decisions are immutable');
END;

CREATE TRIGGER context_package_policy_decisions_delete_forbidden
BEFORE DELETE ON context_package_policy_decisions
FOR EACH ROW
BEGIN
    SELECT RAISE(ABORT, 'context package policy decisions are immutable');
END;

CREATE TRIGGER artifact_identity_immutable
BEFORE UPDATE ON artifacts
FOR EACH ROW
WHEN NEW.id IS NOT OLD.id
    OR NEW.task_id IS NOT OLD.task_id
    OR NEW.project_id IS NOT OLD.project_id
    OR NEW.artifact_type IS NOT OLD.artifact_type
    OR NEW.logical_path IS NOT OLD.logical_path
    OR NEW.content_hash IS NOT OLD.content_hash
    OR NEW.storage_key IS NOT OLD.storage_key
    OR NEW.size_bytes IS NOT OLD.size_bytes
    OR NEW.mime_type IS NOT OLD.mime_type
    OR NEW.created_by_type IS NOT OLD.created_by_type
    OR NEW.created_by_id IS NOT OLD.created_by_id
    OR NEW.created_at IS NOT OLD.created_at
    OR NEW.supersedes IS NOT OLD.supersedes
BEGIN
    SELECT RAISE(ABORT, 'artifact identity is immutable');
END;

CREATE TRIGGER source_document_identity_immutable
BEFORE UPDATE ON source_documents
FOR EACH ROW
WHEN NEW.project_id IS NOT OLD.project_id
    OR NEW.task_id IS NOT OLD.task_id
    OR NEW.source_kind IS NOT OLD.source_kind
    OR NEW.logical_path IS NOT OLD.logical_path
    OR NEW.revision IS NOT OLD.revision
    OR NEW.content_hash IS NOT OLD.content_hash
    OR NEW.sensitivity IS NOT OLD.sensitivity
    OR NEW.classification_digest IS NOT OLD.classification_digest
BEGIN
    SELECT RAISE(ABORT, 'source document identity is immutable');
END;

CREATE TRIGGER source_document_state_forward_only
BEFORE UPDATE OF index_state ON source_documents
FOR EACH ROW
WHEN OLD.index_state <> NEW.index_state
    AND NOT (
        (OLD.index_state = 'pending'
            AND NEW.index_state IN ('current', 'denied', 'failed'))
        OR (OLD.index_state = 'current' AND NEW.index_state = 'stale')
    )
BEGIN
    SELECT RAISE(ABORT, 'source document state must move forward');
END;

CREATE INDEX source_documents_revision_hash_lookup
ON source_documents(task_id, revision, content_hash, index_state);

CREATE INDEX source_chunks_document_lookup
ON source_chunks(document_id, created_at, id);

CREATE TABLE deliberation_records (
    event_id TEXT PRIMARY KEY REFERENCES events(event_id) ON DELETE RESTRICT,
    task_id TEXT NOT NULL REFERENCES tasks(id) ON DELETE RESTRICT,
    sequence INTEGER NOT NULL CHECK (sequence >= 1),
    record_type TEXT NOT NULL,
    primary_artifact_id TEXT NOT NULL REFERENCES artifacts(id) ON DELETE RESTRICT,
    canonical_record_json TEXT NOT NULL CHECK (json_valid(canonical_record_json)),
    canonical_record_digest TEXT NOT NULL CHECK (
        length(canonical_record_digest) = 71
        AND substr(canonical_record_digest, 1, 7) = 'sha256:'
        AND substr(canonical_record_digest, 8) NOT GLOB '*[^0-9a-f]*'
    ),
    created_at TEXT NOT NULL,
    UNIQUE (task_id, sequence)
) STRICT;

CREATE TRIGGER deliberation_records_update_forbidden
BEFORE UPDATE ON deliberation_records
FOR EACH ROW
BEGIN
    SELECT RAISE(ABORT, 'deliberation recovery records are immutable');
END;

CREATE TRIGGER deliberation_records_delete_forbidden
BEFORE DELETE ON deliberation_records
FOR EACH ROW
BEGIN
    SELECT RAISE(ABORT, 'deliberation recovery records are immutable');
END;

CREATE INDEX deliberation_records_task_sequence
ON deliberation_records(task_id, sequence);
"#;

const V7_PRIVATE_AGENT_RUN_OUTPUTS_SQL: &str = r#"
CREATE TABLE agent_run_outputs (
    run_id TEXT PRIMARY KEY REFERENCES agent_runs(id) ON DELETE RESTRICT,
    task_id TEXT NOT NULL REFERENCES tasks(id) ON DELETE RESTRICT,
    message_id TEXT NOT NULL UNIQUE,
    thread_id TEXT NOT NULL,
    message_type TEXT NOT NULL,
    reply_to TEXT,
    content_artifact_id TEXT NOT NULL REFERENCES artifacts(id) ON DELETE RESTRICT,
    core_received_at TEXT NOT NULL
) STRICT;

CREATE INDEX agent_run_outputs_task_received
ON agent_run_outputs(task_id, core_received_at, run_id);

CREATE TRIGGER agent_run_outputs_update_forbidden
BEFORE UPDATE ON agent_run_outputs
FOR EACH ROW
BEGIN
    SELECT RAISE(ABORT, 'private agent run outputs are immutable');
END;

CREATE TRIGGER agent_run_outputs_delete_forbidden
BEFORE DELETE ON agent_run_outputs
FOR EACH ROW
BEGIN
    SELECT RAISE(ABORT, 'private agent run outputs are immutable');
END;
"#;

const V8_DELIBERATION_TASK_BUDGETS_SQL: &str = r#"
CREATE TABLE deliberation_task_budgets (
    task_id TEXT PRIMARY KEY REFERENCES tasks(id) ON DELETE RESTRICT,
    max_threads INTEGER NOT NULL CHECK (max_threads BETWEEN 1 AND 4096),
    max_tokens INTEGER NOT NULL CHECK (max_tokens BETWEEN 1 AND 1000000),
    max_cost_microunits INTEGER NOT NULL
        CHECK (max_cost_microunits BETWEEN 1 AND 1000000000000),
    deadline_unix_seconds INTEGER NOT NULL CHECK (deadline_unix_seconds > 0),
    reserved_threads INTEGER NOT NULL DEFAULT 0
        CHECK (reserved_threads BETWEEN 0 AND max_threads),
    reserved_tokens INTEGER NOT NULL DEFAULT 0
        CHECK (reserved_tokens BETWEEN 0 AND max_tokens),
    reserved_cost_microunits INTEGER NOT NULL DEFAULT 0
        CHECK (reserved_cost_microunits BETWEEN 0 AND max_cost_microunits)
) STRICT;

CREATE TRIGGER deliberation_task_budget_authority_immutable
BEFORE UPDATE ON deliberation_task_budgets
FOR EACH ROW
WHEN NEW.task_id IS NOT OLD.task_id
    OR NEW.max_threads IS NOT OLD.max_threads
    OR NEW.max_tokens IS NOT OLD.max_tokens
    OR NEW.max_cost_microunits IS NOT OLD.max_cost_microunits
    OR NEW.deadline_unix_seconds IS NOT OLD.deadline_unix_seconds
BEGIN
    SELECT RAISE(ABORT, 'deliberation task budget authority is immutable');
END;

CREATE TRIGGER deliberation_task_budget_reservations_monotonic
BEFORE UPDATE ON deliberation_task_budgets
FOR EACH ROW
WHEN NEW.reserved_threads < OLD.reserved_threads
    OR NEW.reserved_tokens < OLD.reserved_tokens
    OR NEW.reserved_cost_microunits < OLD.reserved_cost_microunits
BEGIN
    SELECT RAISE(ABORT, 'deliberation task budget reservations must increase');
END;

CREATE TRIGGER deliberation_task_budget_delete_forbidden
BEFORE DELETE ON deliberation_task_budgets
FOR EACH ROW
BEGIN
    SELECT RAISE(ABORT, 'deliberation task budget authority is immutable');
END;

CREATE TABLE deliberation_dispatch_reservations (
    run_id TEXT PRIMARY KEY,
    task_id TEXT NOT NULL REFERENCES tasks(id) ON DELETE RESTRICT,
    phase TEXT NOT NULL CHECK (phase IN (
        'ParallelAnalysis', 'CrossReview', 'PrePlanVerification', 'Synthesis', 'FinalObjection'
    )),
    agent_id TEXT NOT NULL,
    family_key TEXT NOT NULL,
    max_tokens INTEGER NOT NULL CHECK (max_tokens BETWEEN 1 AND 1000000),
    estimated_cost_microunits INTEGER NOT NULL CHECK (estimated_cost_microunits > 0),
    deadline_unix_seconds INTEGER NOT NULL CHECK (deadline_unix_seconds > 0),
    run_config_artifact_id TEXT NOT NULL,
    connection_binding_digest TEXT NOT NULL
) STRICT;

CREATE INDEX deliberation_dispatch_reservations_task
ON deliberation_dispatch_reservations(task_id, phase, run_id);

CREATE TRIGGER deliberation_dispatch_reservations_update_forbidden
BEFORE UPDATE ON deliberation_dispatch_reservations
FOR EACH ROW
BEGIN
    SELECT RAISE(ABORT, 'deliberation dispatch reservations are immutable');
END;

CREATE TRIGGER deliberation_dispatch_reservations_delete_forbidden
BEFORE DELETE ON deliberation_dispatch_reservations
FOR EACH ROW
BEGIN
    SELECT RAISE(ABORT, 'deliberation dispatch reservations are immutable');
END;
"#;

const V9_DELIBERATION_DISPATCH_ROUNDS_SQL: &str = r#"
ALTER TABLE deliberation_dispatch_reservations
ADD COLUMN dispatch_round INTEGER NOT NULL DEFAULT 0 CHECK (dispatch_round BETWEEN 0 AND 64);

DROP INDEX deliberation_dispatch_reservations_task;
CREATE INDEX deliberation_dispatch_reservations_task
ON deliberation_dispatch_reservations(task_id, phase, dispatch_round, run_id);

CREATE TABLE deliberation_repository_baselines (
    task_id TEXT PRIMARY KEY REFERENCES tasks(id) ON DELETE RESTRICT,
    head TEXT NOT NULL,
    index_digest TEXT NOT NULL,
    status_digest TEXT NOT NULL,
    captured_at TEXT NOT NULL
) STRICT;

CREATE TABLE deliberation_repository_boundary_records (
    id INTEGER PRIMARY KEY,
    task_id TEXT NOT NULL REFERENCES tasks(id) ON DELETE RESTRICT,
    phase TEXT NOT NULL,
    expected_head TEXT NOT NULL,
    expected_index_digest TEXT NOT NULL,
    expected_status_digest TEXT NOT NULL,
    observed_head TEXT NOT NULL,
    observed_index_digest TEXT NOT NULL,
    observed_status_digest TEXT NOT NULL,
    blocked INTEGER NOT NULL CHECK (blocked IN (0, 1)),
    observed_at TEXT NOT NULL,
    UNIQUE (
        task_id, phase, expected_head, expected_index_digest, expected_status_digest,
        observed_head, observed_index_digest, observed_status_digest
    )
) STRICT;

CREATE TABLE deliberation_synthesis_plans (
    event_id TEXT PRIMARY KEY REFERENCES deliberation_records(event_id) ON DELETE RESTRICT,
    task_id TEXT NOT NULL REFERENCES tasks(id) ON DELETE RESTRICT,
    plan_json TEXT NOT NULL CHECK (json_valid(plan_json)),
    plan_digest TEXT NOT NULL,
    created_at TEXT NOT NULL
) STRICT;

CREATE TABLE deliberation_specialist_threads (
    thread_id TEXT PRIMARY KEY,
    task_id TEXT NOT NULL REFERENCES tasks(id) ON DELETE RESTRICT,
    parent_run_id TEXT NOT NULL REFERENCES agent_runs(id) ON DELETE RESTRICT,
    specialist_run_id TEXT NOT NULL UNIQUE,
    specialist_agent_id TEXT NOT NULL,
    context_package_artifact_id TEXT NOT NULL REFERENCES artifacts(id) ON DELETE RESTRICT,
    created_at TEXT NOT NULL
) STRICT;

CREATE TABLE deliberation_specialist_dispatches (
    event_id TEXT PRIMARY KEY REFERENCES deliberation_records(event_id) ON DELETE RESTRICT,
    request_id TEXT NOT NULL,
    task_id TEXT NOT NULL REFERENCES tasks(id) ON DELETE RESTRICT,
    parent_run_id TEXT NOT NULL REFERENCES agent_runs(id) ON DELETE RESTRICT,
    specialist_run_id TEXT NOT NULL UNIQUE,
    specialist_agent_id TEXT NOT NULL,
    specialist_actor_id TEXT NOT NULL,
    family_key TEXT NOT NULL,
    thread_id TEXT NOT NULL UNIQUE
        REFERENCES deliberation_specialist_threads(thread_id) ON DELETE RESTRICT,
    context_package_artifact_id TEXT NOT NULL REFERENCES artifacts(id) ON DELETE RESTRICT,
    status TEXT NOT NULL CHECK (status = 'reserved'),
    created_at TEXT NOT NULL,
    UNIQUE (task_id, parent_run_id, request_id)
) STRICT;

CREATE TABLE deliberation_context_package_invalidations (
    context_package_id TEXT NOT NULL REFERENCES context_packages(id) ON DELETE RESTRICT,
    boundary_record_id INTEGER NOT NULL
        REFERENCES deliberation_repository_boundary_records(id) ON DELETE RESTRICT,
    task_id TEXT NOT NULL REFERENCES tasks(id) ON DELETE RESTRICT,
    reason TEXT NOT NULL CHECK (reason = 'repository_fingerprint_changed'),
    invalidated_at TEXT NOT NULL,
    PRIMARY KEY (context_package_id, boundary_record_id)
) STRICT;

CREATE TRIGGER deliberation_repository_baselines_update_forbidden
BEFORE UPDATE ON deliberation_repository_baselines
FOR EACH ROW BEGIN
    SELECT RAISE(ABORT, 'deliberation repository baselines are immutable');
END;

CREATE TRIGGER deliberation_repository_baselines_delete_forbidden
BEFORE DELETE ON deliberation_repository_baselines
FOR EACH ROW BEGIN
    SELECT RAISE(ABORT, 'deliberation repository baselines are immutable');
END;

CREATE TRIGGER deliberation_repository_boundary_records_update_forbidden
BEFORE UPDATE ON deliberation_repository_boundary_records
FOR EACH ROW BEGIN
    SELECT RAISE(ABORT, 'deliberation repository boundary records are immutable');
END;

CREATE TRIGGER deliberation_repository_boundary_records_delete_forbidden
BEFORE DELETE ON deliberation_repository_boundary_records
FOR EACH ROW BEGIN
    SELECT RAISE(ABORT, 'deliberation repository boundary records are immutable');
END;

CREATE TRIGGER deliberation_synthesis_plans_update_forbidden
BEFORE UPDATE ON deliberation_synthesis_plans
FOR EACH ROW BEGIN
    SELECT RAISE(ABORT, 'deliberation synthesis plans are immutable');
END;

CREATE TRIGGER deliberation_synthesis_plans_delete_forbidden
BEFORE DELETE ON deliberation_synthesis_plans
FOR EACH ROW BEGIN
    SELECT RAISE(ABORT, 'deliberation synthesis plans are immutable');
END;

CREATE TRIGGER deliberation_specialist_threads_update_forbidden
BEFORE UPDATE ON deliberation_specialist_threads
FOR EACH ROW BEGIN
    SELECT RAISE(ABORT, 'deliberation specialist threads are immutable');
END;

CREATE TRIGGER deliberation_specialist_threads_delete_forbidden
BEFORE DELETE ON deliberation_specialist_threads
FOR EACH ROW BEGIN
    SELECT RAISE(ABORT, 'deliberation specialist threads are immutable');
END;

CREATE TRIGGER deliberation_specialist_dispatches_update_forbidden
BEFORE UPDATE ON deliberation_specialist_dispatches
FOR EACH ROW BEGIN
    SELECT RAISE(ABORT, 'deliberation specialist dispatches are immutable');
END;

CREATE TRIGGER deliberation_specialist_dispatches_delete_forbidden
BEFORE DELETE ON deliberation_specialist_dispatches
FOR EACH ROW BEGIN
    SELECT RAISE(ABORT, 'deliberation specialist dispatches are immutable');
END;

CREATE TRIGGER deliberation_context_package_invalidations_update_forbidden
BEFORE UPDATE ON deliberation_context_package_invalidations
FOR EACH ROW BEGIN
    SELECT RAISE(ABORT, 'deliberation context package invalidations are immutable');
END;

CREATE TRIGGER deliberation_context_package_invalidations_delete_forbidden
BEFORE DELETE ON deliberation_context_package_invalidations
FOR EACH ROW BEGIN
    SELECT RAISE(ABORT, 'deliberation context package invalidations are immutable');
END;
"#;

#[derive(Debug)]
pub enum OpenError {
    Database(rusqlite::Error),
    ChecksumMismatch {
        recorded: String,
        expected: String,
    },
    UnsupportedSchema {
        found: i64,
        supported: i64,
    },
    ForeignKeyViolation {
        table: String,
        rowid: i64,
        parent: String,
        foreign_key: i64,
    },
}

impl fmt::Display for OpenError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Database(error) => write!(formatter, "SQLite startup failed: {error}"),
            Self::ChecksumMismatch { recorded, expected } => write!(
                formatter,
                "schema checksum mismatch: recorded {recorded}, expected {expected}"
            ),
            Self::UnsupportedSchema { found, supported } => write!(
                formatter,
                "unsupported schema version {found}; this binary supports {supported}"
            ),
            Self::ForeignKeyViolation {
                table,
                rowid,
                parent,
                foreign_key,
            } => write!(
                formatter,
                "SQLite foreign-key check failed for {table} row {rowid} -> {parent} (constraint {foreign_key})"
            ),
        }
    }
}

impl std::error::Error for OpenError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Database(error) => Some(error),
            Self::ChecksumMismatch { .. }
            | Self::UnsupportedSchema { .. }
            | Self::ForeignKeyViolation { .. } => None,
        }
    }
}

impl From<rusqlite::Error> for OpenError {
    fn from(error: rusqlite::Error) -> Self {
        Self::Database(error)
    }
}

pub fn migration_checksum() -> String {
    checksum(V9_DELIBERATION_DISPATCH_ROUNDS_SQL)
}

fn v8_migration_checksum() -> String {
    checksum(V8_DELIBERATION_TASK_BUDGETS_SQL)
}

fn v7_migration_checksum() -> String {
    checksum(V7_PRIVATE_AGENT_RUN_OUTPUTS_SQL)
}

fn v1_migration_checksum() -> String {
    checksum(&v1_migration_sql())
}

fn v2_migration_checksum() -> String {
    checksum(V2_UPGRADE_SQL)
}

fn v3_migration_checksum() -> String {
    checksum(V3_POLICY_TOOL_HARDENING_SQL)
}

fn v4_migration_checksum() -> String {
    checksum(V4_TOOL_EXECUTION_LIFECYCLE_SQL)
}

fn v5_migration_checksum() -> String {
    checksum(V5_PRE_EFFECT_TERMINAL_SQL)
}

fn v6_migration_checksum() -> String {
    checksum(V6_CONTEXT_HARDENING_SQL)
}

fn checksum(sql: &str) -> String {
    let digest = Sha256::digest(sql.as_bytes());
    format!("sha256:{digest:x}")
}

pub(crate) fn validate_or_migrate(connection: &mut Connection) -> Result<(), OpenError> {
    let has_migration_table: bool = connection.query_row(
        "SELECT EXISTS(
            SELECT 1 FROM sqlite_schema WHERE type = 'table' AND name = 'schema_migrations'
         )",
        [],
        |row| row.get(0),
    )?;

    if !has_migration_table {
        let has_user_objects: bool = connection.query_row(
            "SELECT EXISTS(
                SELECT 1 FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%'
             )",
            [],
            |row| row.get(0),
        )?;
        if has_user_objects {
            return Err(OpenError::UnsupportedSchema {
                found: 0,
                supported: SUPPORTED_SCHEMA_VERSION,
            });
        }
        apply_initial_migration(connection)?;
        return validate_foreign_keys(connection);
    }

    let version: Option<i64> = connection
        .query_row("SELECT MAX(version) FROM schema_migrations", [], |row| {
            row.get(0)
        })
        .optional()?
        .flatten();
    let Some(version) = version else {
        return Err(OpenError::UnsupportedSchema {
            found: 0,
            supported: SUPPORTED_SCHEMA_VERSION,
        });
    };
    if !(1..=SUPPORTED_SCHEMA_VERSION).contains(&version) {
        return Err(OpenError::UnsupportedSchema {
            found: version,
            supported: SUPPORTED_SCHEMA_VERSION,
        });
    }
    for installed_version in 1..=version {
        validate_checksum(
            connection,
            installed_version,
            checksum_for_version(installed_version),
        )?;
    }
    if version < SUPPORTED_SCHEMA_VERSION {
        apply_upgrade_migrations(connection, version)?;
    }
    validate_foreign_keys(connection)
}

pub(crate) fn reject_unknown_schema_without_mutation(
    connection: &Connection,
) -> Result<(), OpenError> {
    let has_migration_table: bool = connection.query_row(
        "SELECT EXISTS(
            SELECT 1 FROM sqlite_schema WHERE type = 'table' AND name = 'schema_migrations'
         )",
        [],
        |row| row.get(0),
    )?;
    if has_migration_table {
        return Ok(());
    }
    let has_user_objects: bool = connection.query_row(
        "SELECT EXISTS(
            SELECT 1 FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%'
         )",
        [],
        |row| row.get(0),
    )?;
    if has_user_objects {
        return Err(OpenError::UnsupportedSchema {
            found: 0,
            supported: SUPPORTED_SCHEMA_VERSION,
        });
    }
    Ok(())
}

fn validate_foreign_keys(connection: &Connection) -> Result<(), OpenError> {
    let violation = connection
        .query_row("PRAGMA foreign_key_check", [], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, i64>(3)?,
            ))
        })
        .optional()?;
    if let Some((table, rowid, parent, foreign_key)) = violation {
        return Err(OpenError::ForeignKeyViolation {
            table,
            rowid,
            parent,
            foreign_key,
        });
    }
    Ok(())
}

fn validate_checksum(
    connection: &Connection,
    version: i64,
    expected: String,
) -> Result<(), OpenError> {
    let recorded: Option<String> = connection
        .query_row(
            "SELECT checksum FROM schema_migrations WHERE version = ?1",
            [version],
            |row| row.get(0),
        )
        .optional()?;
    let Some(recorded) = recorded else {
        return Err(OpenError::UnsupportedSchema {
            found: version,
            supported: SUPPORTED_SCHEMA_VERSION,
        });
    };
    if recorded != expected {
        return Err(OpenError::ChecksumMismatch { recorded, expected });
    }
    Ok(())
}

fn apply_initial_migration(connection: &mut Connection) -> Result<(), OpenError> {
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    transaction.execute_batch(&v1_migration_sql())?;
    transaction.execute(
        "INSERT INTO schema_migrations (
            version, name, applied_at, application_version, checksum
         ) VALUES (?1, ?2, strftime('%Y-%m-%dT%H:%M:%fZ', 'now'), ?3, ?4)",
        params![
            1,
            "initial",
            env!("CARGO_PKG_VERSION"),
            v1_migration_checksum()
        ],
    )?;
    transaction.execute_batch(V2_UPGRADE_SQL)?;
    transaction.execute(
        "INSERT INTO schema_migrations (
            version, name, applied_at, application_version, checksum
         ) VALUES (?1, ?2, strftime('%Y-%m-%dT%H:%M:%fZ', 'now'), ?3, ?4)",
        params![
            2,
            "adapter_hardening_v2",
            env!("CARGO_PKG_VERSION"),
            v2_migration_checksum()
        ],
    )?;
    transaction.execute_batch(V3_POLICY_TOOL_HARDENING_SQL)?;
    transaction.execute(
        "INSERT INTO schema_migrations (
            version, name, applied_at, application_version, checksum
         ) VALUES (?1, ?2, strftime('%Y-%m-%dT%H:%M:%fZ', 'now'), ?3, ?4)",
        params![
            3,
            "policy_tool_hardening_v3",
            env!("CARGO_PKG_VERSION"),
            v3_migration_checksum()
        ],
    )?;
    transaction.execute_batch(V4_TOOL_EXECUTION_LIFECYCLE_SQL)?;
    transaction.execute(
        "INSERT INTO schema_migrations (
            version, name, applied_at, application_version, checksum
         ) VALUES (?1, ?2, strftime('%Y-%m-%dT%H:%M:%fZ', 'now'), ?3, ?4)",
        params![
            4,
            "tool_execution_lifecycle_v4",
            env!("CARGO_PKG_VERSION"),
            v4_migration_checksum()
        ],
    )?;
    transaction.execute_batch(V5_PRE_EFFECT_TERMINAL_SQL)?;
    transaction.execute(
        "INSERT INTO schema_migrations (
            version, name, applied_at, application_version, checksum
         ) VALUES (?1, ?2, strftime('%Y-%m-%dT%H:%M:%fZ', 'now'), ?3, ?4)",
        params![
            5,
            "pre_effect_terminal_v5",
            env!("CARGO_PKG_VERSION"),
            v5_migration_checksum()
        ],
    )?;
    transaction.execute_batch(V6_CONTEXT_HARDENING_SQL)?;
    transaction.execute(
        "INSERT INTO schema_migrations (
            version, name, applied_at, application_version, checksum
         ) VALUES (?1, ?2, strftime('%Y-%m-%dT%H:%M:%fZ', 'now'), ?3, ?4)",
        params![
            6,
            "context_hardening_v6",
            env!("CARGO_PKG_VERSION"),
            v6_migration_checksum()
        ],
    )?;
    transaction.execute_batch(V7_PRIVATE_AGENT_RUN_OUTPUTS_SQL)?;
    transaction.execute(
        "INSERT INTO schema_migrations (
            version, name, applied_at, application_version, checksum
         ) VALUES (?1, ?2, strftime('%Y-%m-%dT%H:%M:%fZ', 'now'), ?3, ?4)",
        params![
            7,
            "private_agent_run_outputs_v7",
            env!("CARGO_PKG_VERSION"),
            v7_migration_checksum()
        ],
    )?;
    transaction.execute_batch(V8_DELIBERATION_TASK_BUDGETS_SQL)?;
    transaction.execute(
        "INSERT INTO schema_migrations (
            version, name, applied_at, application_version, checksum
         ) VALUES (?1, ?2, strftime('%Y-%m-%dT%H:%M:%fZ', 'now'), ?3, ?4)",
        params![
            8,
            "deliberation_task_budgets_v8",
            env!("CARGO_PKG_VERSION"),
            v8_migration_checksum()
        ],
    )?;
    transaction.execute_batch(V9_DELIBERATION_DISPATCH_ROUNDS_SQL)?;
    transaction.execute(
        "INSERT INTO schema_migrations (
            version, name, applied_at, application_version, checksum
         ) VALUES (?1, ?2, strftime('%Y-%m-%dT%H:%M:%fZ', 'now'), ?3, ?4)",
        params![
            9,
            "deliberation_dispatch_rounds_v9",
            env!("CARGO_PKG_VERSION"),
            migration_checksum()
        ],
    )?;
    transaction.commit()?;
    Ok(())
}

fn apply_upgrade_migrations(connection: &mut Connection, version: i64) -> Result<(), OpenError> {
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let migrations = [
        (2, "adapter_hardening_v2", V2_UPGRADE_SQL),
        (3, "policy_tool_hardening_v3", V3_POLICY_TOOL_HARDENING_SQL),
        (
            4,
            "tool_execution_lifecycle_v4",
            V4_TOOL_EXECUTION_LIFECYCLE_SQL,
        ),
        (5, "pre_effect_terminal_v5", V5_PRE_EFFECT_TERMINAL_SQL),
        (6, "context_hardening_v6", V6_CONTEXT_HARDENING_SQL),
        (
            7,
            "private_agent_run_outputs_v7",
            V7_PRIVATE_AGENT_RUN_OUTPUTS_SQL,
        ),
        (
            8,
            "deliberation_task_budgets_v8",
            V8_DELIBERATION_TASK_BUDGETS_SQL,
        ),
        (
            9,
            "deliberation_dispatch_rounds_v9",
            V9_DELIBERATION_DISPATCH_ROUNDS_SQL,
        ),
    ];
    for (next_version, name, sql) in migrations
        .into_iter()
        .filter(|(next_version, _, _)| *next_version > version)
    {
        transaction.execute_batch(sql)?;
        transaction.execute(
            "INSERT INTO schema_migrations (
                version, name, applied_at, application_version, checksum
             ) VALUES (?1, ?2, strftime('%Y-%m-%dT%H:%M:%fZ', 'now'), ?3, ?4)",
            params![
                next_version,
                name,
                env!("CARGO_PKG_VERSION"),
                checksum_for_version(next_version)
            ],
        )?;
    }
    validate_foreign_keys(&transaction)?;
    transaction.commit()?;
    Ok(())
}

fn checksum_for_version(version: i64) -> String {
    match version {
        1 => v1_migration_checksum(),
        2 => v2_migration_checksum(),
        3 => v3_migration_checksum(),
        4 => v4_migration_checksum(),
        5 => v5_migration_checksum(),
        6 => v6_migration_checksum(),
        7 => v7_migration_checksum(),
        8 => v8_migration_checksum(),
        9 => migration_checksum(),
        _ => String::new(),
    }
}

fn v1_migration_sql() -> String {
    let (_, body) = NORMATIVE_SQL
        .split_once("BEGIN IMMEDIATE;")
        .expect("normative migration must start an immediate transaction");
    let (body, _) = body
        .rsplit_once("COMMIT;")
        .expect("normative migration must commit its transaction");
    format!("{body}\n{V1_ADAPTER_HARDENING_SQL}")
}
