use std::collections::BTreeMap;
use std::fmt;
use std::sync::OnceLock;

use rusqlite::types::ValueRef;
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
const RUN_CONFIGURATION_BINDING_REPAIR: &str = r#"
BEGIN IMMEDIATE;
DROP TRIGGER run_configuration_binding_scope;
CREATE TRIGGER run_configuration_binding_scope BEFORE INSERT ON run_configuration_bindings FOR EACH ROW BEGIN
    SELECT CASE WHEN NOT EXISTS (
        SELECT 1
        FROM agent_runs r
        JOIN tasks t ON t.id=r.task_id
        JOIN artifacts a ON a.id=NEW.config_artifact_id
        WHERE r.id=NEW.run_id
          AND r.run_config_artifact_id=NEW.config_artifact_id
          AND a.project_id=t.project_id
          AND (a.task_id IS NULL OR a.task_id=r.task_id)
    ) THEN RAISE(ABORT,'run configuration binding must match the exact run artifact') END;
END;
COMMIT;
"#;
const ASSURANCE_DEGRADATION_SCOPE_REPAIR: &str = r#"
BEGIN IMMEDIATE;
DROP TRIGGER assurance_degradation_scope;
CREATE TRIGGER assurance_degradation_scope BEFORE INSERT ON assurance_degradation_receipts FOR EACH ROW BEGIN
    SELECT CASE WHEN NOT EXISTS (
        SELECT 1
        FROM tasks t
        JOIN artifacts a ON a.id=NEW.receipt_artifact_id
        WHERE t.id=NEW.task_id
          AND a.project_id=t.project_id
          AND (a.task_id IS NULL OR a.task_id=NEW.task_id)
    ) THEN RAISE(ABORT,'assurance degradation receipt must be exact and task-scoped') END;
    SELECT CASE WHEN NEW.decision='continue_degraded' AND NEW.actor_binding_id IS NULL THEN RAISE(ABORT,'continuing with degraded assurance requires explicit actor proof') END;
END;
COMMIT;
"#;

static EXPECTED_V6_OBJECTS: OnceLock<SchemaObjects> = OnceLock::new();
static EXPECTED_V7_OBJECTS: OnceLock<SchemaObjects> = OnceLock::new();
static EXPECTED_PRIOR_COMPLETE_OBJECTS: OnceLock<SchemaObjects> = OnceLock::new();
static EXPECTED_RUN_CONFIGURATION_REPAIRED_COMPLETE_OBJECTS: OnceLock<SchemaObjects> =
    OnceLock::new();
static EXPECTED_REPAIRED_COMPLETE_OBJECTS: OnceLock<SchemaObjects> = OnceLock::new();
static EXPECTED_WORKFLOW_RULE_AUTHORITY: OnceLock<WorkflowRuleAuthority> = OnceLock::new();

const WORKFLOW_RULE_TABLES: [&str; 6] = [
    "workflow_transition_rules",
    "workflow_transition_rule_sources",
    "workflow_transition_rule_profiles",
    "workflow_transition_rule_outcomes",
    "workflow_transition_rule_guard_requirements",
    "workflow_transition_rule_effect_requirements",
];

type ObjectKey = (String, String);
type ObjectDefinition = (String, String);
type SchemaObjects = BTreeMap<ObjectKey, ObjectDefinition>;
type WorkflowRuleAuthority = BTreeMap<String, Vec<Vec<AuthorityValue>>>;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum AuthorityValue {
    Null,
    Integer(i64),
    Real(u64),
    Text(Vec<u8>),
    Blob(Vec<u8>),
}

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
    validate_foreign_keys(connection)?;
    validate_integrity(connection)?;
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
    if schema_objects(connection)? != *expected_repaired_complete_objects()? {
        return Err(unsupported_schema());
    }
    verify_workflow_rule_authority(connection)?;

    verify_runtime_pragmas(connection)?;
    validate_foreign_keys(connection)?;
    validate_integrity(connection)
}

fn recognize_schema(connection: &Connection) -> Result<SchemaKind, OpenError> {
    let actual = schema_objects(connection)?;
    if actual.is_empty() {
        return Ok(SchemaKind::Empty);
    }
    if actual == *expected_v6_objects()? {
        return Ok(SchemaKind::NormativeV6);
    }
    if actual == *expected_v7_objects()?
        || actual == *expected_prior_complete_objects()?
        || actual == *expected_run_configuration_repaired_complete_objects()?
        || actual == *expected_repaired_complete_objects()?
    {
        verify_workflow_rule_authority(connection)?;
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
    if actual == *expected_repaired_complete_objects()? {
        return Ok(());
    }
    if actual == *expected_v7_objects()? {
        connection.execute_batch(APP_PROJECTION_SCHEMA)?;
        connection.execute_batch(RUN_CONFIGURATION_BINDING_REPAIR)?;
        connection.execute_batch(ASSURANCE_DEGRADATION_SCOPE_REPAIR)?;
    } else if actual == *expected_prior_complete_objects()? {
        connection.execute_batch(RUN_CONFIGURATION_BINDING_REPAIR)?;
        connection.execute_batch(ASSURANCE_DEGRADATION_SCOPE_REPAIR)?;
    } else if actual == *expected_run_configuration_repaired_complete_objects()? {
        connection.execute_batch(ASSURANCE_DEGRADATION_SCOPE_REPAIR)?;
    } else {
        return Err(unsupported_schema());
    }
    verify_exact_objects(connection, expected_repaired_complete_objects()?)
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

fn expected_prior_complete_objects() -> Result<&'static SchemaObjects, OpenError> {
    cached_schema(
        &EXPECTED_PRIOR_COMPLETE_OBJECTS,
        &[SQLITE_V7, APP_PROJECTION_SCHEMA],
    )
}

fn expected_repaired_complete_objects() -> Result<&'static SchemaObjects, OpenError> {
    cached_schema(
        &EXPECTED_REPAIRED_COMPLETE_OBJECTS,
        &[
            SQLITE_V7,
            APP_PROJECTION_SCHEMA,
            RUN_CONFIGURATION_BINDING_REPAIR,
            ASSURANCE_DEGRADATION_SCOPE_REPAIR,
        ],
    )
}

fn expected_run_configuration_repaired_complete_objects(
) -> Result<&'static SchemaObjects, OpenError> {
    cached_schema(
        &EXPECTED_RUN_CONFIGURATION_REPAIRED_COMPLETE_OBJECTS,
        &[
            SQLITE_V7,
            APP_PROJECTION_SCHEMA,
            RUN_CONFIGURATION_BINDING_REPAIR,
        ],
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
    let mut normalized = String::with_capacity(sql.len());
    let mut characters = sql.chars().peekable();
    while let Some(character) = characters.next() {
        match character {
            character if character.is_whitespace() => {}
            '-' if characters.peek() == Some(&'-') => {
                characters.next();
                for comment_character in characters.by_ref() {
                    if comment_character == '\n' {
                        break;
                    }
                }
            }
            '/' if characters.peek() == Some(&'*') => {
                characters.next();
                let mut prior = '\0';
                for comment_character in characters.by_ref() {
                    if prior == '*' && comment_character == '/' {
                        break;
                    }
                    prior = comment_character;
                }
            }
            '\'' | '"' | '`' | '[' => {
                let closing = if character == '[' { ']' } else { character };
                let mut token = String::from(character);
                while let Some(quoted_character) = characters.next() {
                    token.push(quoted_character);
                    if quoted_character == closing {
                        if characters.peek() == Some(&closing) {
                            token.push(characters.next().expect("peeked closing quote exists"));
                        } else {
                            break;
                        }
                    }
                }
                append_sql_token(&mut normalized, 'q', &token);
            }
            character if is_sql_word_character(character) => {
                let mut token = String::from(character);
                while characters
                    .peek()
                    .is_some_and(|next| is_sql_word_character(*next))
                {
                    token.push(characters.next().expect("peeked word character exists"));
                }
                append_sql_token(&mut normalized, 'w', &token.to_lowercase());
            }
            character => {
                let token = String::from(character);
                append_sql_token(&mut normalized, 'p', &token);
            }
        }
    }
    normalized
}

fn is_sql_word_character(character: char) -> bool {
    character.is_alphanumeric() || matches!(character, '_' | '$')
}

fn append_sql_token(normalized: &mut String, kind: char, token: &str) {
    normalized.push(kind);
    normalized.push_str(&token.len().to_string());
    normalized.push(':');
    normalized.push_str(token);
}

fn expected_workflow_rule_authority() -> Result<&'static WorkflowRuleAuthority, OpenError> {
    if let Some(authority) = EXPECTED_WORKFLOW_RULE_AUTHORITY.get() {
        return Ok(authority);
    }

    let connection = Connection::open_in_memory()?;
    connection.execute_batch(SQLITE_V7)?;
    let authority = workflow_rule_authority(&connection)?;
    let _ = EXPECTED_WORKFLOW_RULE_AUTHORITY.set(authority);
    Ok(EXPECTED_WORKFLOW_RULE_AUTHORITY
        .get()
        .expect("workflow rule authority cache is initialized by this call or a concurrent caller"))
}

fn verify_workflow_rule_authority(connection: &Connection) -> Result<(), OpenError> {
    if workflow_rule_authority(connection)? == *expected_workflow_rule_authority()? {
        Ok(())
    } else {
        Err(unsupported_schema())
    }
}

fn workflow_rule_authority(connection: &Connection) -> Result<WorkflowRuleAuthority, OpenError> {
    WORKFLOW_RULE_TABLES
        .into_iter()
        .map(|table| {
            let mut statement = connection.prepare(&format!("SELECT * FROM {table}"))?;
            let column_count = statement.column_count();
            let rows = statement.query_map([], |row| {
                (0..column_count)
                    .map(|index| match row.get_ref(index)? {
                        ValueRef::Null => Ok(AuthorityValue::Null),
                        ValueRef::Integer(value) => Ok(AuthorityValue::Integer(value)),
                        ValueRef::Real(value) => Ok(AuthorityValue::Real(value.to_bits())),
                        ValueRef::Text(value) => Ok(AuthorityValue::Text(value.to_vec())),
                        ValueRef::Blob(value) => Ok(AuthorityValue::Blob(value.to_vec())),
                    })
                    .collect::<Result<Vec<_>, rusqlite::Error>>()
            })?;
            let mut rows = rows.collect::<Result<Vec<_>, _>>()?;
            rows.sort();
            Ok((table.to_owned(), rows))
        })
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

fn validate_integrity(connection: &Connection) -> Result<(), OpenError> {
    let integrity: String = connection.query_row("PRAGMA integrity_check", [], |row| row.get(0))?;
    if integrity == "ok" {
        Ok(())
    } else {
        Err(unsupported_schema())
    }
}

fn unsupported_schema() -> OpenError {
    OpenError::UnsupportedSchema {
        found: 0,
        supported: SUPPORTED_SCHEMA_VERSION,
    }
}
