use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use local_agent_terminal_application::SafeErrorClassification;
use local_agent_terminal_domain::TaskId;
use local_agent_terminal_storage_sqlite::{OpenError, SqliteStore};
use rusqlite::{params, Connection};

const SQLITE_V6: &str =
    include_str!("../../../docs/multi-agent-terminal-design/schemas/sqlite-v6.sql");
const SQLITE_V7: &str =
    include_str!("../../../docs/multi-agent-terminal-design/schemas/sqlite-v7.sql");
const REPAIRED_RUN_CONFIGURATION_BINDING_SCOPE: &str = r#"
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
"#;

static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone, PartialEq, Eq)]
struct SchemaObject {
    table: String,
    sql: String,
}

type SchemaObjects = BTreeMap<(String, String), SchemaObject>;

struct TempDirectory(PathBuf);

impl TempDirectory {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "local-agent-terminal-schema-v7-test-{}-{}",
            std::process::id(),
            NEXT_TEMP.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }

    fn database_path(&self) -> PathBuf {
        self.0.join("state.sqlite3")
    }
}

impl Drop for TempDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn clean_v7_and_migrated_v7_have_identical_authority_objects() {
    let expected = runtime_v7_objects();
    assert_eq!(expected.len(), 481);

    let clean_directory = TempDirectory::new();
    let clean_path = clean_directory.database_path();
    SqliteStore::open(&clean_path).unwrap();

    let migrated_directory = TempDirectory::new();
    let migrated_path = migrated_directory.database_path();
    install_script(&migrated_path, SQLITE_V6);
    SqliteStore::open(&migrated_path).unwrap();

    assert_eq!(authority_objects(&clean_path, &expected), expected);
    assert_eq!(authority_objects(&migrated_path, &expected), expected);
}

#[test]
fn exact_normative_v7_reopens_with_only_the_approved_trigger_repair() {
    let expected = runtime_v7_objects();
    let directory = TempDirectory::new();
    let path = directory.database_path();
    install_script(&path, SQLITE_V7);

    SqliteStore::open(&path).unwrap();
    SqliteStore::open(&path).unwrap();

    assert_eq!(authority_objects(&path, &expected), expected);
}

#[test]
fn exact_v6_authority_row_migrates_with_normative_v7_fields() {
    let directory = TempDirectory::new();
    let path = directory.database_path();
    let connection = Connection::open(&path).unwrap();
    connection.execute_batch(SQLITE_V6).unwrap();
    seed_task(&connection);
    connection
        .execute(
            "INSERT INTO task_workflow_authority (
                task_id, workflow_profile, outcome_mode, phase, selected_by_kind,
                selected_by_actor_binding_id, selection_policy_digest, created_at,
                updated_at, completed_at
             ) VALUES (?1, 'Standard', 'WorkspaceChange', 'Intake', 'core', NULL, ?2, ?3, ?3, NULL)",
            params!["task-1", digest('b'), "2026-08-12T00:00:00.000Z"],
        )
        .unwrap();
    drop(connection);

    SqliteStore::open(&path).unwrap();

    let connection = Connection::open(path).unwrap();
    let authority: (String, String, i64, i64, Option<String>, Option<String>) = connection
        .query_row(
            "SELECT workflow_profile, outcome_mode, stream_version, profile_revision,
                    last_transition_event_id, last_profile_revision_id
             FROM task_workflow_authority WHERE task_id = 'task-1'",
            [],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                ))
            },
        )
        .unwrap();
    assert_eq!(
        authority,
        (
            "Standard".to_owned(),
            "WorkspaceChange".to_owned(),
            0,
            1,
            None,
            None,
        )
    );
}

#[test]
fn clean_v7_does_not_fabricate_task_workflow_authority() {
    let directory = TempDirectory::new();
    let path = directory.database_path();

    SqliteStore::open(&path).unwrap();

    let connection = Connection::open(path).unwrap();
    let count: i64 = connection
        .query_row("SELECT COUNT(*) FROM task_workflow_authority", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(count, 0);
}

#[test]
fn unavailable_trusted_budget_authority_fails_closed_without_projection() {
    let directory = TempDirectory::new();
    let path = directory.database_path();
    let store = SqliteStore::open(&path).unwrap();

    let error = store
        .deliberation_task_budget(&TaskId::new("task-1").unwrap())
        .unwrap_err();
    assert_eq!(
        error.safe_classification(),
        SafeErrorClassification::IntegrityFailure
    );

    let connection = Connection::open(path).unwrap();
    let budget_projection_count: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM sqlite_schema
             WHERE type = 'table' AND name = 'deliberation_task_budgets'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(budget_projection_count, 0);
}

#[test]
fn application_version_marker_is_not_accepted_as_normative_v7() {
    let directory = TempDirectory::new();
    let path = directory.database_path();
    let connection = Connection::open(&path).unwrap();
    connection
        .execute_batch(
            "CREATE TABLE schema_migrations(version INTEGER NOT NULL);\n\
             INSERT INTO schema_migrations(version) VALUES (9);",
        )
        .unwrap();
    drop(connection);

    let error = SqliteStore::open(path).unwrap_err();
    assert!(matches!(error, OpenError::UnsupportedSchema { .. }));
}

#[test]
fn altered_normative_v7_string_literal_is_rejected() {
    let directory = TempDirectory::new();
    let path = directory.database_path();
    let altered = SQLITE_V7.replacen("'Intake'", "'intake'", 1);
    install_script(&path, &altered);

    let error = SqliteStore::open(path).unwrap_err();

    assert!(matches!(error, OpenError::UnsupportedSchema { .. }));
}

#[test]
fn altered_normative_v7_token_boundary_is_rejected() {
    let directory = TempDirectory::new();
    let path = directory.database_path();
    let altered = SQLITE_V7.replacen(" IS NULL", " ISNULL", 1);
    install_script(&path, &altered);

    let error = SqliteStore::open(path).unwrap_err();

    assert!(matches!(error, OpenError::UnsupportedSchema { .. }));
}

#[test]
fn tampered_workflow_rule_profile_authority_is_rejected() {
    let directory = TempDirectory::new();
    let path = directory.database_path();
    install_script(&path, SQLITE_V7);
    let connection = Connection::open(&path).unwrap();
    connection
        .execute(
            "INSERT INTO workflow_transition_rule_profiles (rule_id, workflow_profile)
             VALUES ('WF-P009', 'Standard')",
            [],
        )
        .unwrap();
    drop(connection);

    let error = SqliteStore::open(path).unwrap_err();

    assert!(matches!(error, OpenError::UnsupportedSchema { .. }));
}

#[test]
fn nonempty_unknown_schema_is_rejected_without_mutation() {
    let directory = TempDirectory::new();
    let path = directory.database_path();
    let connection = Connection::open(&path).unwrap();
    connection
        .execute_batch("CREATE TABLE unknown_authority(id TEXT PRIMARY KEY) STRICT;")
        .unwrap();
    let before = schema_objects(&connection);
    let journal_mode_before: String = connection
        .query_row("PRAGMA journal_mode", [], |row| row.get(0))
        .unwrap();
    drop(connection);

    let error = SqliteStore::open(&path).unwrap_err();
    assert!(matches!(error, OpenError::UnsupportedSchema { .. }));

    let connection = Connection::open(path).unwrap();
    assert_eq!(schema_objects(&connection), before);
    let journal_mode_after: String = connection
        .query_row("PRAGMA journal_mode", [], |row| row.get(0))
        .unwrap();
    assert_eq!(journal_mode_after, journal_mode_before);
}

#[test]
fn exact_v6_with_orphaned_rows_fails_before_migration_without_mutation() {
    let directory = TempDirectory::new();
    let path = directory.database_path();
    install_script(&path, SQLITE_V6);
    let connection = Connection::open(&path).unwrap();
    connection
        .pragma_update(None, "foreign_keys", "OFF")
        .unwrap();
    connection
        .execute(
            "INSERT INTO tasks (
                id, project_id, title, objective, phase, condition, operation_state,
                risk_level, base_branch, base_commit, task_branch, worktree_path,
                current_sequence, workspace_version, fencing_epoch, row_version,
                active_candidate_commit_oid, active_candidate_tree, created_at, updated_at
             ) VALUES (
                'orphan-task', 'missing-project', 'Task', 'Objective', 'Intake', 'Active',
                'None', 'medium', 'main', ?1, NULL, NULL, 0, 0, 0, 0, NULL, NULL, ?2, ?2
             )",
            params![
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "2026-08-12T00:00:00.000Z",
            ],
        )
        .unwrap();
    let before = schema_objects(&connection);
    drop(connection);

    let error = SqliteStore::open(&path).unwrap_err();

    assert!(matches!(
        error,
        OpenError::ForeignKeyViolation { ref table, ref parent, .. }
            if table == "tasks" && parent == "projects"
    ));
    let connection = Connection::open(path).unwrap();
    assert_eq!(schema_objects(&connection), before);
    assert_eq!(
        connection
            .query_row(
                "SELECT COUNT(*) FROM tasks WHERE id = 'orphan-task'",
                [],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
        1
    );
    assert_eq!(
        connection
            .query_row(
                "SELECT COUNT(*) FROM sqlite_schema
                 WHERE type = 'table' AND name = 'workflow_transition_rules'",
                [],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
        0
    );
}

#[test]
fn initialized_connections_enforce_runtime_pragmas_and_integrity() {
    let directory = TempDirectory::new();
    let path = directory.database_path();
    let store = SqliteStore::open(&path).unwrap();

    let settings = store.pragma_settings().unwrap();
    assert!(settings.foreign_keys);
    assert_eq!(settings.journal_mode.to_ascii_lowercase(), "wal");
    assert_eq!(settings.synchronous, 2);
    assert_eq!(settings.busy_timeout_ms, 5000);

    let connection = Connection::open(path).unwrap();
    let integrity: String = connection
        .query_row("PRAGMA integrity_check", [], |row| row.get(0))
        .unwrap();
    assert_eq!(integrity, "ok");
}

#[test]
fn app_projections_cannot_write_task_workflow_authority() {
    let expected = normative_v7_objects();
    let authority_names: BTreeSet<_> = expected.keys().cloned().collect();
    let directory = TempDirectory::new();
    let path = directory.database_path();
    SqliteStore::open(&path).unwrap();

    let connection = Connection::open(path).unwrap();
    connection
        .pragma_update(None, "foreign_keys", "ON")
        .unwrap();
    let installed = schema_objects(&connection);
    let projection_writers: Vec<_> = installed
        .iter()
        .filter(|(key, object)| {
            !authority_names.contains(key) && object.sql.contains("updatetask_workflow_authority")
        })
        .map(|(key, _)| key.clone())
        .collect();
    assert!(projection_writers.is_empty(), "{projection_writers:?}");

    seed_task(&connection);
    connection
        .execute(
            "INSERT INTO task_workflow_authority (
                task_id, workflow_profile, outcome_mode, phase, selected_by_kind,
                selected_by_actor_binding_id, selection_policy_digest, created_at,
                updated_at, completed_at, stream_version, last_transition_event_id,
                profile_revision, last_profile_revision_id
             ) VALUES (?1, 'Standard', 'WorkspaceChange', 'Intake', 'core', NULL, ?2, ?3, ?3, NULL, 0, NULL, 1, NULL)",
            params!["task-1", digest('b'), "2026-08-12T00:00:00.000Z"],
        )
        .unwrap();
    let error = connection
        .execute(
            "UPDATE task_workflow_authority
             SET phase = 'ContextBuild', stream_version = 1, updated_at = ?1
             WHERE task_id = 'task-1'",
            ["2026-08-12T00:00:01.000Z"],
        )
        .unwrap_err();
    assert!(error
        .to_string()
        .contains("matching accepted transition event"));
}

fn normative_v7_objects() -> SchemaObjects {
    let connection = Connection::open_in_memory().unwrap();
    connection.execute_batch(SQLITE_V7).unwrap();
    schema_objects(&connection)
}

fn runtime_v7_objects() -> SchemaObjects {
    let mut objects = normative_v7_objects();
    let repaired_scope = REPAIRED_RUN_CONFIGURATION_BINDING_SCOPE
        .trim()
        .trim_end_matches(';');
    objects
        .get_mut(&(
            "trigger".to_owned(),
            "run_configuration_binding_scope".to_owned(),
        ))
        .expect("normative v7 run configuration trigger exists")
        .sql = normalize_sql(repaired_scope);
    objects
}

fn install_script(path: &Path, script: &str) {
    let connection = Connection::open(path).unwrap();
    connection.execute_batch(script).unwrap();
}

fn authority_objects(path: &Path, expected: &SchemaObjects) -> SchemaObjects {
    let connection = Connection::open(path).unwrap();
    schema_objects(&connection)
        .into_iter()
        .filter(|(key, _)| expected.contains_key(key))
        .collect()
}

fn schema_objects(connection: &Connection) -> SchemaObjects {
    let mut statement = connection
        .prepare(
            "SELECT type, name, tbl_name, sql
             FROM sqlite_schema
             WHERE name NOT LIKE 'sqlite_%'
             ORDER BY type, name",
        )
        .unwrap();
    statement
        .query_map([], |row| {
            let object_type: String = row.get(0)?;
            let name: String = row.get(1)?;
            let table: String = row.get(2)?;
            let sql: Option<String> = row.get(3)?;
            Ok((
                (object_type, name),
                SchemaObject {
                    table,
                    sql: normalize_sql(sql.as_deref().unwrap_or_default()),
                },
            ))
        })
        .unwrap()
        .map(Result::unwrap)
        .collect()
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

fn seed_task(connection: &Connection) {
    connection
        .execute(
            "INSERT INTO projects (
                id, name, repository_path, repository_identity, created_at, updated_at,
                policy_profile_id, artifact_root_mode, artifact_root_path
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?5, ?6, 'application_data', ?7)",
            params![
                "project-1",
                "Project",
                "D:/repository",
                digest('c'),
                "2026-08-12T00:00:00.000Z",
                "policy-1",
                "D:/artifacts",
            ],
        )
        .unwrap();
    connection
        .execute(
            "INSERT INTO tasks (
                id, project_id, title, objective, phase, condition, operation_state,
                risk_level, base_branch, base_commit, task_branch, worktree_path,
                current_sequence, workspace_version, fencing_epoch, row_version,
                active_candidate_commit_oid, active_candidate_tree, created_at, updated_at
             ) VALUES (
                ?1, 'project-1', 'Task', 'Objective', 'Intake', 'Active', 'None',
                'medium', 'main', ?2, NULL, NULL, 0, 0, 0, 0, NULL, NULL, ?3, ?3
             )",
            params![
                "task-1",
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "2026-08-12T00:00:00.000Z",
            ],
        )
        .unwrap();
}

fn digest(character: char) -> String {
    format!("sha256:{}", character.to_string().repeat(64))
}
