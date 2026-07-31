use std::fmt;

use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use sha2::{Digest, Sha256};

const SUPPORTED_SCHEMA_VERSION: i64 = 5;
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

#[derive(Debug)]
pub enum OpenError {
    Database(rusqlite::Error),
    ChecksumMismatch { recorded: String, expected: String },
    UnsupportedSchema { found: i64, supported: i64 },
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
        }
    }
}

impl std::error::Error for OpenError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Database(error) => Some(error),
            Self::ChecksumMismatch { .. } | Self::UnsupportedSchema { .. } => None,
        }
    }
}

impl From<rusqlite::Error> for OpenError {
    fn from(error: rusqlite::Error) -> Self {
        Self::Database(error)
    }
}

pub fn migration_checksum() -> String {
    checksum(V5_PRE_EFFECT_TERMINAL_SQL)
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
        return Ok(());
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
    match version {
        1 => {
            validate_checksum(connection, 1, v1_migration_checksum())?;
            apply_v2_migration(connection)?;
            apply_v3_migration(connection)?;
            apply_v4_migration(connection)?;
            apply_v5_migration(connection)?;
        }
        2 => {
            validate_checksum(connection, 1, v1_migration_checksum())?;
            validate_checksum(connection, 2, v2_migration_checksum())?;
            apply_v3_migration(connection)?;
            apply_v4_migration(connection)?;
            apply_v5_migration(connection)?;
        }
        3 => {
            validate_checksum(connection, 1, v1_migration_checksum())?;
            validate_checksum(connection, 2, v2_migration_checksum())?;
            validate_checksum(connection, 3, v3_migration_checksum())?;
            apply_v4_migration(connection)?;
            apply_v5_migration(connection)?;
        }
        4 => {
            validate_checksum(connection, 1, v1_migration_checksum())?;
            validate_checksum(connection, 2, v2_migration_checksum())?;
            validate_checksum(connection, 3, v3_migration_checksum())?;
            validate_checksum(connection, 4, v4_migration_checksum())?;
            apply_v5_migration(connection)?;
        }
        SUPPORTED_SCHEMA_VERSION => {
            validate_checksum(connection, 1, v1_migration_checksum())?;
            validate_checksum(connection, 2, v2_migration_checksum())?;
            validate_checksum(connection, 3, v3_migration_checksum())?;
            validate_checksum(connection, 4, v4_migration_checksum())?;
            validate_checksum(connection, 5, migration_checksum())?;
        }
        _ => {
            return Err(OpenError::UnsupportedSchema {
                found: version,
                supported: SUPPORTED_SCHEMA_VERSION,
            });
        }
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
            migration_checksum()
        ],
    )?;
    transaction.commit()?;
    Ok(())
}

fn apply_v2_migration(connection: &mut Connection) -> Result<(), OpenError> {
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
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
    transaction.commit()?;
    Ok(())
}

fn apply_v3_migration(connection: &mut Connection) -> Result<(), OpenError> {
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
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
    transaction.commit()?;
    Ok(())
}

fn apply_v4_migration(connection: &mut Connection) -> Result<(), OpenError> {
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
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
    transaction.commit()?;
    Ok(())
}

fn apply_v5_migration(connection: &mut Connection) -> Result<(), OpenError> {
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    transaction.execute_batch(V5_PRE_EFFECT_TERMINAL_SQL)?;
    transaction.execute(
        "INSERT INTO schema_migrations (
            version, name, applied_at, application_version, checksum
         ) VALUES (?1, ?2, strftime('%Y-%m-%dT%H:%M:%fZ', 'now'), ?3, ?4)",
        params![
            5,
            "pre_effect_terminal_v5",
            env!("CARGO_PKG_VERSION"),
            migration_checksum()
        ],
    )?;
    transaction.commit()?;
    Ok(())
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
