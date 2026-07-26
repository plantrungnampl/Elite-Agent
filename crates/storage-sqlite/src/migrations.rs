use std::fmt;

use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use sha2::{Digest, Sha256};

const SUPPORTED_SCHEMA_VERSION: i64 = 2;
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
    checksum(V2_UPGRADE_SQL)
}

fn v1_migration_checksum() -> String {
    checksum(&v1_migration_sql())
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
        }
        SUPPORTED_SCHEMA_VERSION => {
            validate_checksum(connection, 1, v1_migration_checksum())?;
            validate_checksum(connection, 2, migration_checksum())?;
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
            SUPPORTED_SCHEMA_VERSION,
            "adapter_hardening_v2",
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
            SUPPORTED_SCHEMA_VERSION,
            "adapter_hardening_v2",
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
