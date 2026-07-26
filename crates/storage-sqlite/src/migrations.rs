use std::fmt;

use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use sha2::{Digest, Sha256};

const SUPPORTED_SCHEMA_VERSION: i64 = 1;
const NORMATIVE_SQL: &str =
    include_str!("../../../docs/multi-agent-terminal-design/schemas/sqlite-v1.sql");
const ADAPTER_HARDENING_SQL: &str = r#"
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
    let digest = Sha256::digest(migration_sql().as_bytes());
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
    if version != SUPPORTED_SCHEMA_VERSION {
        return Err(OpenError::UnsupportedSchema {
            found: version,
            supported: SUPPORTED_SCHEMA_VERSION,
        });
    }

    let recorded: String = connection.query_row(
        "SELECT checksum FROM schema_migrations WHERE version = ?1",
        [SUPPORTED_SCHEMA_VERSION],
        |row| row.get(0),
    )?;
    let expected = migration_checksum();
    if recorded != expected {
        return Err(OpenError::ChecksumMismatch { recorded, expected });
    }
    Ok(())
}

fn apply_initial_migration(connection: &mut Connection) -> Result<(), OpenError> {
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    transaction.execute_batch(&migration_sql())?;
    transaction.execute(
        "INSERT INTO schema_migrations (
            version, name, applied_at, application_version, checksum
         ) VALUES (?1, ?2, strftime('%Y-%m-%dT%H:%M:%fZ', 'now'), ?3, ?4)",
        params![
            SUPPORTED_SCHEMA_VERSION,
            "initial",
            env!("CARGO_PKG_VERSION"),
            migration_checksum()
        ],
    )?;
    transaction.commit()?;
    Ok(())
}

fn migration_sql() -> String {
    let (_, body) = NORMATIVE_SQL
        .split_once("BEGIN IMMEDIATE;")
        .expect("normative migration must start an immediate transaction");
    let (body, _) = body
        .rsplit_once("COMMIT;")
        .expect("normative migration must commit its transaction");
    format!("{body}\n{ADAPTER_HARDENING_SQL}")
}
