use std::collections::BTreeMap;
use std::fmt;
use std::sync::OnceLock;

use rusqlite::{Connection, OptionalExtension};
use sha2::{Digest, Sha256};

const SUPPORTED_SCHEMA_VERSION: i64 = 7;
const SQLITE_V6: &str =
    include_str!("../../../docs/multi-agent-terminal-design/schemas/sqlite-v6.sql");
const SQLITE_V7: &str =
    include_str!("../../../docs/multi-agent-terminal-design/schemas/sqlite-v7.sql");
const MIGRATE_V6_TO_V7: &str =
    include_str!("../../../docs/multi-agent-terminal-design/schemas/migrate-v6-to-v7.sql");
const APP_PROJECTION_SCHEMA: &str = include_str!("app_projection_schema.sql");

static EXPECTED_V6_OBJECTS: OnceLock<SchemaObjects> = OnceLock::new();
static EXPECTED_V7_OBJECTS: OnceLock<SchemaObjects> = OnceLock::new();
static EXPECTED_COMPLETE_OBJECTS: OnceLock<SchemaObjects> = OnceLock::new();

type ObjectKey = (String, String);
type ObjectDefinition = (String, String);
type SchemaObjects = BTreeMap<ObjectKey, ObjectDefinition>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SchemaKind {
    Empty,
    NormativeV6,
    NormativeV7,
    Unsupported,
}

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
    let digest = Sha256::digest(SQLITE_V7.as_bytes());
    format!("sha256:{digest:x}")
}

pub(crate) fn validate_or_migrate(connection: &mut Connection) -> Result<(), OpenError> {
    let schema_kind = recognize_schema(connection)?;
    if schema_kind == SchemaKind::Unsupported {
        return Err(unsupported_schema());
    }
    configure_runtime_pragmas(connection)?;

    match schema_kind {
        SchemaKind::Empty => install_v7(connection)?,
        SchemaKind::NormativeV6 => migrate_v6_to_v7(connection)?,
        SchemaKind::NormativeV7 => {}
        SchemaKind::Unsupported => unreachable!("unsupported schemas return before mutation"),
    }

    install_or_verify_app_projections(connection)?;
    verify_required_schema(connection)
}

pub(crate) fn verify_required_schema(connection: &Connection) -> Result<(), OpenError> {
    if schema_objects(connection)? != *expected_complete_objects()? {
        return Err(unsupported_schema());
    }

    verify_runtime_pragmas(connection)?;
    validate_foreign_keys(connection)?;
    let integrity: String = connection.query_row("PRAGMA integrity_check", [], |row| row.get(0))?;
    if integrity != "ok" {
        return Err(unsupported_schema());
    }
    Ok(())
}

fn recognize_schema(connection: &Connection) -> Result<SchemaKind, OpenError> {
    let actual = schema_objects(connection)?;
    if actual.is_empty() {
        return Ok(SchemaKind::Empty);
    }
    if actual == *expected_v6_objects()? {
        return Ok(SchemaKind::NormativeV6);
    }
    if actual == *expected_v7_objects()? || actual == *expected_complete_objects()? {
        return Ok(SchemaKind::NormativeV7);
    }
    Ok(SchemaKind::Unsupported)
}

fn install_v7(connection: &Connection) -> Result<(), OpenError> {
    connection.execute_batch(SQLITE_V7)?;
    verify_exact_objects(connection, expected_v7_objects()?)
}

fn migrate_v6_to_v7(connection: &Connection) -> Result<(), OpenError> {
    connection.execute_batch(MIGRATE_V6_TO_V7)?;
    verify_exact_objects(connection, expected_v7_objects()?)
}

fn install_or_verify_app_projections(connection: &Connection) -> Result<(), OpenError> {
    let actual = schema_objects(connection)?;
    if actual == *expected_complete_objects()? {
        return Ok(());
    }
    if actual != *expected_v7_objects()? {
        return Err(unsupported_schema());
    }

    connection.execute_batch(APP_PROJECTION_SCHEMA)?;
    verify_exact_objects(connection, expected_complete_objects()?)
}

fn verify_exact_objects(
    connection: &Connection,
    expected: &SchemaObjects,
) -> Result<(), OpenError> {
    if schema_objects(connection)? == *expected {
        Ok(())
    } else {
        Err(unsupported_schema())
    }
}

fn expected_v6_objects() -> Result<&'static SchemaObjects, OpenError> {
    cached_schema(&EXPECTED_V6_OBJECTS, &[SQLITE_V6])
}

fn expected_v7_objects() -> Result<&'static SchemaObjects, OpenError> {
    cached_schema(&EXPECTED_V7_OBJECTS, &[SQLITE_V7])
}

fn expected_complete_objects() -> Result<&'static SchemaObjects, OpenError> {
    cached_schema(
        &EXPECTED_COMPLETE_OBJECTS,
        &[SQLITE_V7, APP_PROJECTION_SCHEMA],
    )
}

fn cached_schema(
    cache: &'static OnceLock<SchemaObjects>,
    scripts: &[&str],
) -> Result<&'static SchemaObjects, OpenError> {
    if let Some(objects) = cache.get() {
        return Ok(objects);
    }

    let connection = Connection::open_in_memory()?;
    for script in scripts {
        connection.execute_batch(script)?;
    }
    let objects = schema_objects(&connection)?;
    let _ = cache.set(objects);
    Ok(cache
        .get()
        .expect("schema cache is initialized by this call or a concurrent caller"))
}

fn schema_objects(connection: &Connection) -> Result<SchemaObjects, OpenError> {
    let mut statement = connection.prepare(
        "SELECT type, name, tbl_name, sql
         FROM sqlite_schema
         WHERE name NOT LIKE 'sqlite_%'
         ORDER BY type, name",
    )?;
    let rows = statement.query_map([], |row| {
        let object_type: String = row.get(0)?;
        let name: String = row.get(1)?;
        let table_name: String = row.get(2)?;
        let sql: Option<String> = row.get(3)?;
        Ok((
            (object_type, name),
            (
                table_name,
                normalize_sql(sql.as_deref().unwrap_or_default()),
            ),
        ))
    })?;
    rows.collect::<Result<_, _>>().map_err(OpenError::from)
}

fn normalize_sql(sql: &str) -> String {
    sql.chars()
        .filter(|character| !character.is_whitespace())
        .flat_map(char::to_lowercase)
        .collect()
}

fn verify_runtime_pragmas(connection: &Connection) -> Result<(), OpenError> {
    let foreign_keys: i64 = connection.query_row("PRAGMA foreign_keys", [], |row| row.get(0))?;
    let journal_mode: String = connection.query_row("PRAGMA journal_mode", [], |row| row.get(0))?;
    let synchronous: i64 = connection.query_row("PRAGMA synchronous", [], |row| row.get(0))?;
    let busy_timeout: i64 = connection.query_row("PRAGMA busy_timeout", [], |row| row.get(0))?;
    let wal_autocheckpoint: i64 =
        connection.query_row("PRAGMA wal_autocheckpoint", [], |row| row.get(0))?;
    let recursive_triggers: i64 =
        connection.query_row("PRAGMA recursive_triggers", [], |row| row.get(0))?;
    if foreign_keys != 1
        || !journal_mode.eq_ignore_ascii_case("wal")
        || synchronous != 2
        || busy_timeout != 5000
        || wal_autocheckpoint != 1000
        || recursive_triggers != 1
    {
        return Err(unsupported_schema());
    }
    Ok(())
}

fn configure_runtime_pragmas(connection: &Connection) -> Result<(), OpenError> {
    connection.pragma_update(None, "foreign_keys", "ON")?;
    connection.query_row("PRAGMA journal_mode = WAL", [], |_| Ok(()))?;
    connection.pragma_update(None, "synchronous", "FULL")?;
    connection.pragma_update(None, "busy_timeout", 5000)?;
    connection.pragma_update(None, "wal_autocheckpoint", 1000)?;
    connection.pragma_update(None, "recursive_triggers", "ON")?;
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

fn unsupported_schema() -> OpenError {
    OpenError::UnsupportedSchema {
        found: 0,
        supported: SUPPORTED_SCHEMA_VERSION,
    }
}
