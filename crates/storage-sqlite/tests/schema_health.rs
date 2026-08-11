use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use local_agent_terminal_application::{
    canonical_approval_payload, parse_approval_payload, ApprovalDigestPayload,
    DurableToolExecutionArtifact, NewToolExecution, ToolExecutionClaim, ToolExecutionId,
    ToolExecutionResolution, ToolExecutionStore,
};
use local_agent_terminal_domain::Sha256Digest;
use local_agent_terminal_storage_sqlite::{
    artifact_root_health, migration_checksum, ArtifactRootIssue, DatabaseHealth, OpenError,
    SqliteStore,
};
use rusqlite::{params, Connection, TransactionBehavior};
use sha2::{Digest, Sha256};

const NORMATIVE_SQL: &str =
    include_str!("../../../docs/multi-agent-terminal-design/schemas/sqlite-v1.sql");
const PRIOR_V1_CHECKSUM: &str =
    "sha256:016173b278c07b241c61d9a0e93533803b787861b945d4393ca26ee24d165f62";
const PRIOR_V2_CHECKSUM: &str =
    "sha256:c2487f24da333edafd83e6e25853f142933dde21f0e419ac4a8795996469b086";
const PRIOR_V3_CHECKSUM: &str =
    "sha256:58b6d7303fb5cdbe028b0bcd1248de2d86ae913406200d5821ff4b5efd899038";
const PRIOR_V4_CHECKSUM: &str =
    "sha256:8ca12bde024e22f87161de6b682e65ae083e20db8dd019454daba0407e42c91e";
const PRIOR_V5_CHECKSUM: &str =
    "sha256:7dd21c89f2cc576cf597dde5e108cb675eb38fb3c7676b99d837af19aa363a97";
const PRIOR_V6_CHECKSUM: &str =
    "sha256:3b1c844cc613dbce727218b29b4cf9276cfdda257775d2d37146f21a453435f0";
const MIGRATIONS_SOURCE: &str = include_str!("../src/migrations.rs");
const TOOL_FIXTURE: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../tests/contracts/fixtures/m2/tool-approval-valid.json"
));
const PRIOR_V1_HARDENING: &str = r#"
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

static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

struct TempDirectory(PathBuf);

impl TempDirectory {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "local-agent-terminal-schema-test-{}-{}",
            std::process::id(),
            NEXT_TEMP.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
}

impl Drop for TempDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn first_startup_applies_schema_and_records_checksum() {
    let directory = TempDirectory::new();
    let path = directory.0.join("state.sqlite3");

    SqliteStore::open(&path).unwrap();

    let connection = Connection::open(path).unwrap();
    let latest: (i64, String) = connection
        .query_row(
            "SELECT version, checksum FROM schema_migrations ORDER BY version DESC LIMIT 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(latest, (9, migration_checksum()));
    assert_eq!(
        connection
            .query_row("SELECT COUNT(*) FROM schema_migrations", [], |row| {
                row.get::<_, i64>(0)
            })
            .unwrap(),
        9
    );
    assert_eq!(
        connection
            .query_row(
                "SELECT COUNT(*) FROM sqlite_schema WHERE type = 'table' AND name = 'events'",
                [],
                |row| row.get::<_, i64>(0)
            )
            .unwrap(),
        1
    );
    for table in [
        "deliberation_task_budgets",
        "deliberation_dispatch_reservations",
    ] {
        assert_eq!(
            connection
                .query_row(
                    "SELECT COUNT(*) FROM sqlite_schema WHERE type = 'table' AND name = ?1",
                    [table],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            1
        );
    }
    assert_eq!(
        connection
            .query_row(
                "SELECT COUNT(*) FROM sqlite_schema
                 WHERE type = 'trigger' AND name = 'deliberation_task_budget_delete_forbidden'",
                [],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
        1
    );
}

#[test]
fn exact_prior_v1_database_upgrades_to_v9_without_losing_data() {
    let directory = TempDirectory::new();
    let path = directory.0.join("state.sqlite3");
    let mut connection = Connection::open(&path).unwrap();
    install_prior_v1(&mut connection);
    seed_project_and_task(&connection);
    drop(connection);

    SqliteStore::open(&path).unwrap();

    let connection = Connection::open(path).unwrap();
    assert_eq!(
        connection
            .query_row(
                "SELECT name FROM projects WHERE id = 'project-1'",
                [],
                |row| { row.get::<_, String>(0) }
            )
            .unwrap(),
        "Project"
    );
    assert_eq!(
        connection
            .query_row("SELECT MAX(version) FROM schema_migrations", [], |row| {
                row.get::<_, i64>(0)
            })
            .unwrap(),
        9
    );
    assert!(connection
        .execute("UPDATE tasks SET fencing_epoch = 0 WHERE id = 'task-1'", [])
        .is_err());
    assert!(connection
        .execute(
            "INSERT INTO agent_descriptors (
                id, display_name, transport_type, trust_tier, manifest_json, manifest_digest,
                executable_digest, enabled, containment_verified, last_health_status, updated_at
             ) VALUES ('brokered', 'agent', 'local', 'brokered_process', '{}', ?1, NULL, 1, 0, NULL, '2026-07-26T00:00:00Z')",
            [format!("sha256:{}", "a".repeat(64))],
        )
        .is_err());
}

#[test]
fn exact_prior_v2_database_upgrades_without_rewriting_its_checksum() {
    let directory = TempDirectory::new();
    let path = directory.0.join("state.sqlite3");
    let mut connection = Connection::open(&path).unwrap();
    install_prior_v2(&mut connection);
    drop(connection);

    SqliteStore::open(&path).unwrap();

    let connection = Connection::open(path).unwrap();
    assert_eq!(
        connection
            .query_row("SELECT MAX(version) FROM schema_migrations", [], |row| {
                row.get::<_, i64>(0)
            })
            .unwrap(),
        9
    );
    assert_eq!(
        connection
            .query_row(
                "SELECT checksum FROM schema_migrations WHERE version = 2",
                [],
                |row| row.get::<_, String>(0),
            )
            .unwrap(),
        PRIOR_V2_CHECKSUM
    );
    assert_eq!(
        connection
            .query_row(
                "SELECT COUNT(*) FROM sqlite_schema
                 WHERE type = 'trigger' AND name = 'approval_status_forward_only'",
                [],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
        1
    );
}

#[test]
fn exact_deployed_v3_database_upgrades_to_v9_and_preserves_v3_checksum() {
    let directory = TempDirectory::new();
    let path = directory.0.join("state.sqlite3");
    let mut connection = Connection::open(&path).unwrap();
    install_prior_v3(&mut connection);
    seed_project_and_task(&connection);
    drop(connection);

    SqliteStore::open(&path).unwrap();

    let connection = Connection::open(path).unwrap();
    assert_eq!(
        connection
            .query_row("SELECT MAX(version) FROM schema_migrations", [], |row| {
                row.get::<_, i64>(0)
            })
            .unwrap(),
        9
    );
    assert_eq!(
        connection
            .query_row(
                "SELECT checksum FROM schema_migrations WHERE version = 3",
                [],
                |row| row.get::<_, String>(0),
            )
            .unwrap(),
        PRIOR_V3_CHECKSUM
    );
    let table_sql: String = connection
        .query_row(
            "SELECT sql FROM sqlite_schema
             WHERE type = 'table' AND name = 'tool_executions'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert!(table_sql.contains("'cancelled'"));
    let trigger_sql: String = connection
        .query_row(
            "SELECT sql FROM sqlite_schema
             WHERE type = 'trigger' AND name = 'tool_execution_status_forward_only'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert!(trigger_sql.contains("'cancelled'"));
}

#[test]
fn exact_deployed_v4_database_upgrades_to_v9_and_preserves_v4_checksum() {
    let directory = TempDirectory::new();
    let path = directory.0.join("state.sqlite3");
    let mut connection = Connection::open(&path).unwrap();
    let prior_v4_checksum = install_prior_v4(&mut connection);
    seed_project_and_task(&connection);
    drop(connection);

    SqliteStore::open(&path).unwrap();

    let connection = Connection::open(path).unwrap();
    assert_eq!(
        connection
            .query_row("SELECT MAX(version) FROM schema_migrations", [], |row| {
                row.get::<_, i64>(0)
            })
            .unwrap(),
        9
    );
    assert_eq!(
        connection
            .query_row(
                "SELECT checksum FROM schema_migrations WHERE version = 4",
                [],
                |row| row.get::<_, String>(0),
            )
            .unwrap(),
        prior_v4_checksum
    );
    let intent_trigger_sql: String = connection
        .query_row(
            "SELECT sql FROM sqlite_schema
             WHERE type = 'trigger' AND name = 'operation_intent_status_forward_only'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert!(intent_trigger_sql.contains("'claimed'"));
    assert!(intent_trigger_sql.contains("'interrupted'"));
    let execution_trigger_sql: String = connection
        .query_row(
            "SELECT sql FROM sqlite_schema
             WHERE type = 'trigger' AND name = 'tool_execution_status_forward_only'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert!(execution_trigger_sql.contains("'pending'"));
    assert!(execution_trigger_sql.contains("'interrupted'"));
}

#[test]
fn exact_deployed_v5_database_adds_context_hardening_without_rewriting_v5() {
    let directory = TempDirectory::new();
    let path = directory.0.join("state.sqlite3");
    let mut connection = Connection::open(&path).unwrap();
    let prior_v5_checksum = install_prior_v5(&mut connection);
    drop(connection);

    SqliteStore::open(&path).unwrap();

    let connection = Connection::open(path).unwrap();
    assert_eq!(
        connection
            .query_row("SELECT MAX(version) FROM schema_migrations", [], |row| {
                row.get::<_, i64>(0)
            })
            .unwrap(),
        9
    );
    assert_eq!(
        connection
            .query_row(
                "SELECT checksum FROM schema_migrations WHERE version = 5",
                [],
                |row| row.get::<_, String>(0),
            )
            .unwrap(),
        prior_v5_checksum
    );
    for object in [
        "context_packages_update_forbidden",
        "context_packages_delete_forbidden",
        "context_package_policy_decisions_update_forbidden",
        "context_package_policy_decisions_delete_forbidden",
        "artifact_identity_immutable",
        "source_document_identity_immutable",
        "source_document_state_forward_only",
        "source_documents_revision_hash_lookup",
        "source_chunks_document_lookup",
        "deliberation_records",
        "deliberation_records_update_forbidden",
        "deliberation_records_delete_forbidden",
        "deliberation_records_task_sequence",
    ] {
        assert_eq!(
            connection
                .query_row(
                    "SELECT COUNT(*) FROM sqlite_schema WHERE name = ?1",
                    [object],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            1,
            "missing migration object {object}"
        );
    }
}

#[test]
fn exact_deployed_v6_database_adds_private_run_outputs_without_rewriting_v6() {
    let directory = TempDirectory::new();
    let path = directory.0.join("state.sqlite3");
    let mut connection = Connection::open(&path).unwrap();
    install_prior_v6(&mut connection);
    drop(connection);

    SqliteStore::open(&path).unwrap();

    let connection = Connection::open(path).unwrap();
    assert_eq!(
        connection
            .query_row("SELECT MAX(version) FROM schema_migrations", [], |row| {
                row.get::<_, i64>(0)
            })
            .unwrap(),
        9
    );
    assert_eq!(
        connection
            .query_row(
                "SELECT checksum FROM schema_migrations WHERE version = 6",
                [],
                |row| row.get::<_, String>(0),
            )
            .unwrap(),
        PRIOR_V6_CHECKSUM
    );
    for object in [
        "agent_run_outputs",
        "agent_run_outputs_task_received",
        "agent_run_outputs_update_forbidden",
        "agent_run_outputs_delete_forbidden",
    ] {
        assert_eq!(
            connection
                .query_row(
                    "SELECT COUNT(*) FROM sqlite_schema WHERE name = ?1",
                    [object],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            1,
            "missing migration object {object}"
        );
    }
}

#[test]
fn exact_deployed_v7_database_adds_deliberation_budgets_without_rewriting_v7() {
    let directory = TempDirectory::new();
    let path = directory.0.join("state.sqlite3");
    let mut connection = Connection::open(&path).unwrap();
    let prior_v7_checksum = install_prior_v7(&mut connection);
    drop(connection);

    SqliteStore::open(&path).unwrap();

    let connection = Connection::open(path).unwrap();
    assert_eq!(
        connection
            .query_row("SELECT MAX(version) FROM schema_migrations", [], |row| {
                row.get::<_, i64>(0)
            })
            .unwrap(),
        9
    );
    assert_eq!(
        connection
            .query_row(
                "SELECT checksum FROM schema_migrations WHERE version = 7",
                [],
                |row| row.get::<_, String>(0),
            )
            .unwrap(),
        prior_v7_checksum
    );
    for table in [
        "deliberation_task_budgets",
        "deliberation_dispatch_reservations",
    ] {
        assert_eq!(
            connection
                .query_row(
                    "SELECT COUNT(*) FROM sqlite_schema WHERE type = 'table' AND name = ?1",
                    [table],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            1
        );
    }
}

#[test]
fn v6_freezes_artifact_identity_but_allows_journal_state_updates() {
    let directory = TempDirectory::new();
    let path = directory.0.join("state.sqlite3");
    SqliteStore::open(&path).unwrap();
    let connection = Connection::open(path).unwrap();
    connection
        .execute_batch("PRAGMA foreign_keys = ON;")
        .unwrap();
    seed_project_and_task(&connection);
    let content_hash = format!("sha256:{}", "a".repeat(64));
    connection
        .execute(
            "INSERT INTO artifacts (
                id, task_id, project_id, artifact_type, logical_path, content_hash,
                storage_key, size_bytes, mime_type, availability, created_by_type,
                created_by_id, created_at, supersedes, verification_state
             ) VALUES ('artifact-1', 'task-1', 'project-1', 'context',
                'context/artifact-1.json', ?1, 'objects/aa/artifact-1', 1,
                'application/json', 'available', 'core', 'core',
                '2026-08-10T00:00:00Z', NULL, 'hash_verified')",
            [&content_hash],
        )
        .unwrap();

    for sql in [
        "UPDATE artifacts SET content_hash = 'sha256:0000000000000000000000000000000000000000000000000000000000000000' WHERE id = 'artifact-1'",
        "UPDATE artifacts SET storage_key = 'objects/00/substitute' WHERE id = 'artifact-1'",
        "UPDATE artifacts SET size_bytes = size_bytes + 1 WHERE id = 'artifact-1'",
        "UPDATE artifacts SET artifact_type = 'substitute' WHERE id = 'artifact-1'",
    ] {
        assert!(
            connection.execute(sql, []).is_err(),
            "identity update passed: {sql}"
        );
    }

    connection
        .execute(
            "UPDATE artifacts
             SET availability = 'missing', verification_state = 'unverified'
             WHERE id = 'artifact-1'",
            [],
        )
        .unwrap();
    assert_eq!(
        connection
            .query_row(
                "SELECT availability || ':' || verification_state
                 FROM artifacts WHERE id = 'artifact-1'",
                [],
                |row| row.get::<_, String>(0),
            )
            .unwrap(),
        "missing:unverified"
    );

    let trigger_sql: String = connection
        .query_row(
            "SELECT sql FROM sqlite_schema
             WHERE type = 'trigger' AND name = 'artifact_identity_immutable'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    for field in [
        "id",
        "task_id",
        "project_id",
        "artifact_type",
        "logical_path",
        "content_hash",
        "storage_key",
        "size_bytes",
        "mime_type",
        "created_by_type",
        "created_by_id",
        "created_at",
        "supersedes",
    ] {
        assert!(
            trigger_sql.contains(&format!("NEW.{field} IS NOT OLD.{field}")),
            "identity field missing from trigger: {field}"
        );
    }
}

#[test]
fn populated_deployed_v3_tool_completion_upcasts_without_legacy_receipt_leakage() {
    let directory = TempDirectory::new();
    let path = directory.0.join("state.sqlite3");
    let mut connection = Connection::open(&path).unwrap();
    install_prior_v3(&mut connection);
    let operation_digest =
        seed_completed_v3_tool_execution(&connection, &directory.0, LegacyReceiptFixture::Valid);
    drop(connection);

    let store = SqliteStore::open(&path).unwrap();
    let request = NewToolExecution {
        execution_id: ToolExecutionId::new("legacy-completed").unwrap(),
        operation_digest: operation_digest.clone(),
    };
    let ToolExecutionClaim::Completed(receipt) = store.begin(request.clone()).unwrap() else {
        panic!("the deployed V3 completion must replay as a completed execution");
    };

    assert_eq!(
        receipt.authority().execution_id().as_str(),
        "legacy-completed"
    );
    assert_eq!(receipt.authority().operation_digest(), &operation_digest);
    assert_eq!(receipt.authority().owner_run_id().as_str(), "run-1");
    assert_eq!(receipt.authority().attempt(), 1);
    assert_eq!(
        receipt
            .authority()
            .executor_fencing_token()
            .map(|token| token.get()),
        Some(19)
    );
    assert_eq!(
        receipt.terminal().kind(),
        local_agent_terminal_application::ToolExecutionTerminalKind::Succeeded
    );
    let output = receipt.terminal().output().unwrap();
    assert_eq!(output.exit_code, Some(0));
    assert_eq!(output.duration_ms, 42);
    assert_eq!(
        output.artifacts.stdout(),
        &DurableToolExecutionArtifact::Available(
            local_agent_terminal_domain::ArtifactId::new("legacy-output").unwrap()
        )
    );
    assert_eq!(
        output.artifacts.stderr(),
        &DurableToolExecutionArtifact::Unavailable
    );
    assert_eq!(
        output.artifacts.observed_writes(),
        &[
            DurableToolExecutionArtifact::Unavailable,
            DurableToolExecutionArtifact::Unavailable,
            DurableToolExecutionArtifact::Unavailable,
        ]
    );
    let safe_projection = format!("{receipt:?}");
    for forbidden in [
        "legacy-secret-job",
        "rootPid",
        "legacy-secret-worktree",
        "secret-path.txt",
        "legacy-artifact-id",
        "legacy-toolchain",
        "second-secret-path.txt",
        "raw-command-output",
    ] {
        assert!(!safe_projection.contains(forbidden), "{forbidden}");
    }

    assert_eq!(
        store
            .resolve_terminal(ToolExecutionResolution::new(receipt.clone()))
            .unwrap(),
        receipt
    );
    drop(store);
    let reopened = SqliteStore::open(&path).unwrap();
    assert_eq!(
        reopened.begin(request).unwrap(),
        ToolExecutionClaim::Completed(receipt)
    );
    assert_eq!(
        Connection::open(path)
            .unwrap()
            .query_row(
                "SELECT COUNT(*) FROM events WHERE stream_id = 'task-1'",
                [],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
        2
    );
}

#[test]
fn malformed_deployed_v3_tool_receipt_fails_closed_without_mutation() {
    let directory = TempDirectory::new();
    let path = directory.0.join("state.sqlite3");
    let mut connection = Connection::open(&path).unwrap();
    install_prior_v3(&mut connection);
    let operation_digest = seed_completed_v3_tool_execution(
        &connection,
        &directory.0,
        LegacyReceiptFixture::MalformedReceipt,
    );
    drop(connection);

    let store = SqliteStore::open(&path).unwrap();
    let before = database_fingerprint(&path);
    let error = store
        .begin(NewToolExecution {
            execution_id: ToolExecutionId::new("legacy-completed").unwrap(),
            operation_digest,
        })
        .expect_err("malformed legacy receipt must fail closed");

    assert_eq!(
        error.safe_classification(),
        local_agent_terminal_application::SafeErrorClassification::IntegrityFailure
    );
    assert_eq!(database_fingerprint(&path), before);
}

#[test]
fn malformed_deployed_v3_observed_write_fails_closed_without_mutation() {
    let directory = TempDirectory::new();
    let path = directory.0.join("state.sqlite3");
    let mut connection = Connection::open(&path).unwrap();
    install_prior_v3(&mut connection);
    let operation_digest = seed_completed_v3_tool_execution(
        &connection,
        &directory.0,
        LegacyReceiptFixture::MalformedObservedWrite,
    );
    drop(connection);

    let store = SqliteStore::open(&path).unwrap();
    let before = database_fingerprint(&path);
    let error = store
        .begin(NewToolExecution {
            execution_id: ToolExecutionId::new("legacy-completed").unwrap(),
            operation_digest,
        })
        .expect_err("malformed legacy observed-write evidence must fail closed");

    assert_eq!(
        error.safe_classification(),
        local_agent_terminal_application::SafeErrorClassification::IntegrityFailure
    );
    assert_eq!(database_fingerprint(&path), before);
}

#[test]
fn later_startup_rejects_changed_or_unsupported_schema() {
    for version in 1..=9 {
        let mismatch_directory = TempDirectory::new();
        let mismatch_path = mismatch_directory.0.join("state.sqlite3");
        SqliteStore::open(&mismatch_path).unwrap();
        Connection::open(&mismatch_path)
            .unwrap()
            .execute(
                "UPDATE schema_migrations SET checksum = ?1 WHERE version = ?2",
                params![format!("sha256:{}", "0".repeat(64)), version],
            )
            .unwrap();
        assert!(matches!(
            SqliteStore::open(&mismatch_path),
            Err(OpenError::ChecksumMismatch { .. })
        ));
    }

    let unsupported_directory = TempDirectory::new();
    let unsupported_path = unsupported_directory.0.join("state.sqlite3");
    SqliteStore::open(&unsupported_path).unwrap();
    Connection::open(&unsupported_path)
        .unwrap()
        .execute(
            "INSERT INTO schema_migrations
             (version, name, applied_at, application_version, checksum)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                10,
                "future",
                "2026-07-26T00:00:00Z",
                "9.0.0",
                format!("sha256:{}", "1".repeat(64))
            ],
        )
        .unwrap();
    assert!(matches!(
        SqliteStore::open(&unsupported_path),
        Err(OpenError::UnsupportedSchema {
            found: 10,
            supported: 9
        })
    ));
}

#[test]
fn task_fencing_epoch_must_increase_when_changed() {
    let directory = TempDirectory::new();
    let path = directory.0.join("state.sqlite3");
    SqliteStore::open(&path).unwrap();
    let connection = Connection::open(path).unwrap();
    seed_project_and_task(&connection);

    connection
        .execute("UPDATE tasks SET fencing_epoch = 1 WHERE id = 'task-1'", [])
        .unwrap();
    assert!(connection
        .execute("UPDATE tasks SET fencing_epoch = 1 WHERE id = 'task-1'", [])
        .is_err());
    assert!(connection
        .execute("UPDATE tasks SET fencing_epoch = 0 WHERE id = 'task-1'", [])
        .is_err());
}

#[test]
fn enabled_brokered_and_isolated_agents_require_verified_containment() {
    let directory = TempDirectory::new();
    let path = directory.0.join("state.sqlite3");
    SqliteStore::open(&path).unwrap();
    let connection = Connection::open(path).unwrap();

    for trust_tier in ["brokered_process", "isolated_worker"] {
        assert!(connection
            .execute(
                "INSERT INTO agent_descriptors (
                    id, display_name, transport_type, trust_tier, manifest_json, manifest_digest,
                    executable_digest, enabled, containment_verified, last_health_status, updated_at
                 ) VALUES (?1, 'agent', 'local', ?2, '{}', ?3, NULL, 1, 0, NULL, '2026-07-26T00:00:00Z')",
                params![
                    format!("{trust_tier}-agent"),
                    trust_tier,
                    format!("sha256:{}", "a".repeat(64))
                ],
            )
            .is_err());
    }
}

fn seed_project_and_task(connection: &Connection) {
    connection
        .execute(
            "INSERT INTO projects (
                id, name, repository_path, repository_identity, created_at, updated_at,
                policy_profile_id, artifact_root_mode, artifact_root_path
             ) VALUES (
                'project-1', 'Project', 'C:/repo', 'repo-1', '2026-07-26T00:00:00Z',
                '2026-07-26T00:00:00Z', 'policy-1', 'application_data', 'C:/artifacts'
             )",
            [],
        )
        .unwrap();
    connection
        .execute(
            "INSERT INTO tasks (
                id, project_id, title, objective, phase, condition, operation_state, risk_level,
                base_branch, base_commit, created_at, updated_at
             ) VALUES (
                'task-1', 'project-1', 'Task', 'Objective', 'Intake', 'Active', 'None', 'low',
                'main', ?1, '2026-07-26T00:00:00Z', '2026-07-26T00:00:00Z'
             )",
            ["a".repeat(40)],
        )
        .unwrap();
}

#[derive(Clone, Copy)]
enum LegacyReceiptFixture {
    Valid,
    MalformedReceipt,
    MalformedObservedWrite,
}

fn seed_completed_v3_tool_execution(
    connection: &Connection,
    artifact_root: &std::path::Path,
    fixture: LegacyReceiptFixture,
) -> Sha256Digest {
    connection
        .execute(
            "INSERT INTO projects (
                id, name, repository_path, repository_identity, created_at, updated_at,
                policy_profile_id, artifact_root_mode, artifact_root_path
             ) VALUES ('project-1', 'Project', 'C:/repo', 'repo-1',
                '2026-07-23T00:00:00Z', '2026-07-23T00:00:00Z',
                'policy-1', 'application_data', ?1)",
            [artifact_root.to_string_lossy().as_ref()],
        )
        .unwrap();
    connection
        .execute(
            "INSERT INTO tasks (
                id, project_id, title, objective, phase, condition, operation_state, risk_level,
                base_branch, base_commit, workspace_version, fencing_epoch, current_sequence,
                created_at, updated_at
             ) VALUES ('task-1', 'project-1', 'Task', 'Objective', 'Implementation', 'Active',
                'None', 'high', 'main', ?1, 4, 19, 0,
                '2026-07-23T00:00:00Z', '2026-07-23T00:00:00Z')",
            ["a".repeat(40)],
        )
        .unwrap();

    let seed_hash = format!("sha256:{}", "d".repeat(64));
    for (id, logical_path) in [
        ("manifest", "seed/manifest"),
        ("effective", "seed/effective"),
        ("run-config", "seed/run-config"),
    ] {
        connection
            .execute(
                "INSERT INTO artifacts (
                    id, task_id, project_id, artifact_type, logical_path, content_hash,
                    storage_key, size_bytes, mime_type, availability, created_by_type,
                    created_by_id, created_at, supersedes, verification_state
                 ) VALUES (?1, 'task-1', 'project-1', 'seed', ?2, ?3, ?1, 0, NULL,
                    'available', 'core', 'core', '2026-07-23T00:00:00Z', NULL, 'hash_verified')",
                params![id, logical_path, seed_hash],
            )
            .unwrap();
    }
    connection
        .execute(
            "INSERT INTO agent_descriptors (
                id, display_name, transport_type, trust_tier, manifest_json, manifest_digest,
                executable_digest, enabled, containment_verified, last_health_status, updated_at
             ) VALUES ('agent-1', 'Agent', 'in_process', 'core_adapter', '{}', ?1,
                NULL, 1, 1, 'healthy', '2026-07-23T00:00:00Z')",
            [&seed_hash],
        )
        .unwrap();
    connection
        .execute(
            "INSERT INTO context_packages (
                id, task_id, agent_id, role, objective, manifest_artifact_id,
                effective_content_artifact_id, content_hash, policy_snapshot_digest,
                prompt_template_version, retrieval_pipeline_version, created_at
             ) VALUES ('context-1', 'task-1', 'agent-1', 'executor', 'execute',
                'manifest', 'effective', ?1, ?2, 'v1', 'v1', '2026-07-23T00:00:00Z')",
            params![seed_hash, format!("sha256:{}", "0".repeat(64))],
        )
        .unwrap();
    connection
        .execute(
            "INSERT INTO agent_runs (
                id, task_id, agent_id, role, phase, status, context_package_id,
                idempotency_key, connection_binding_digest, run_config_artifact_id, started_at
             ) VALUES ('run-1', 'task-1', 'agent-1', 'executor', 'Implementation', 'running',
                'context-1', 'run-1-key', ?1, 'run-config', '2026-07-23T00:00:00Z')",
            [format!("sha256:{}", "e".repeat(64))],
        )
        .unwrap();
    connection
        .execute(
            "INSERT INTO executor_leases (
                task_id, holder_run_id, fencing_token, status, acquired_at, expires_at, released_at
             ) VALUES ('task-1', 'run-1', 19, 'active',
                '2026-07-23T00:00:00Z', '2026-08-23T00:00:00Z', NULL)",
            [],
        )
        .unwrap();

    let payload = parse_approval_payload(TOOL_FIXTURE).unwrap();
    let canonical = canonical_approval_payload(&payload).unwrap();
    let ApprovalDigestPayload::Tool(tool_payload) = payload else {
        unreachable!();
    };
    insert_physical_artifact(
        connection,
        artifact_root,
        "request-artifact",
        "tool-requests/legacy-completed.json",
        "tool-request",
        &canonical.canonical_bytes,
    );
    let output_bytes = b"raw-command-output";
    let output_digest = insert_physical_artifact(
        connection,
        artifact_root,
        "legacy-output",
        "tool-output/legacy-completed",
        "tool-output",
        output_bytes,
    );
    connection
        .execute(
            "INSERT INTO policy_decisions (
                id, task_id, actor_json, actor_binding_digest, action, resource_json,
                resource_digest, purpose, workflow_phase, effect, matched_rules_json,
                policy_snapshot_digest, operation_digest, created_at, expires_at, approval_id
             ) VALUES ('policy-1', 'task-1', '{}', ?1, 'process.exec', '{}', ?1,
                'test', 'Implementation', 'allow', '[]', ?2, ?3,
                '2026-07-23T12:00:00Z', NULL, NULL)",
            params![
                format!("sha256:{}", "0".repeat(64)),
                tool_payload.policy_snapshot_digest,
                canonical.operation_digest.as_str(),
            ],
        )
        .unwrap();

    let mut legacy_receipt = serde_json::json!({
        "schemaVersion": 1,
        "executionId": "legacy-completed",
        "status": "exited",
        "exitCode": 0,
        "outputDigest": output_digest.as_str(),
        "stdout": {
            "byteCount": output_bytes.len(),
            "truncated": false,
        },
        "stderr": {
            "byteCount": 0,
            "truncated": false,
        },
        "durationMs": 42,
        "job": {
            "rootPid": 4242,
            "jobId": "legacy-secret-job",
            "killOnClose": true,
            "noBreakaway": true,
            "jobMemoryLimit": true,
            "jobCpuTimeLimit": true,
            "memoryLimitBytes": 1048576,
            "cpuTimeLimitMs": 1000,
            "maxActiveProcesses": 1,
            "totalUserTimeMs": 7,
            "resourceLimitTerminated": false,
            "treeTerminated": true,
        },
        "observedWrites": [{
            "capability": {
                "kind": "worktree",
                "taskId": "task-1",
                "path": "C:/legacy-secret-worktree",
            },
            "rootIdentity": "legacy-secret-root",
            "target": {
                "kind": "relative",
                "components": ["secret-path.txt"],
            },
            "digest": format!("sha256:{}", "f".repeat(64)),
            "sizeBytes": 5,
        }, {
            "capability": {
                "kind": "artifact",
                "artifactId": "legacy-artifact-id",
            },
            "rootIdentity": "legacy-secret-root-2",
            "target": {
                "kind": "root",
            },
            "digest": format!("sha256:{}", "e".repeat(64)),
            "sizeBytes": 6,
        }, {
            "capability": {
                "kind": "toolchain",
                "name": "legacy-toolchain",
            },
            "rootIdentity": "legacy-secret-root-3",
            "target": {
                "kind": "relative",
                "components": ["second-secret-path.txt"],
            },
            "digest": format!("sha256:{}", "c".repeat(64)),
            "sizeBytes": 7,
        }],
    });
    match fixture {
        LegacyReceiptFixture::Valid => {}
        LegacyReceiptFixture::MalformedReceipt => {
            legacy_receipt = serde_json::json!({});
        }
        LegacyReceiptFixture::MalformedObservedWrite => {
            legacy_receipt["observedWrites"] =
                serde_json::json!([{"rootIdentity": "legacy-secret-root"}]);
        }
    };
    connection
        .execute(
            "INSERT INTO operation_intents (
                id, task_id, run_id, operation_kind, idempotency_class, idempotency_key,
                canonical_request_artifact_id, operation_digest, status,
                executor_fencing_token, lease_owner, lease_expires_at, attempt_count,
                result_artifact_id, external_receipt_json, error_json, created_at, updated_at
             ) VALUES ('legacy-completed', 'task-1', 'run-1', 'process.exec',
                'non_repeatable', 'tool:run-1:legacy-completed', 'request-artifact', ?1,
                'succeeded', 19, 'run-1', NULL, 1, 'legacy-output', ?2, NULL,
                '2026-07-23T12:00:00Z', '2026-07-23T12:00:42Z')",
            params![
                canonical.operation_digest.as_str(),
                legacy_receipt.to_string()
            ],
        )
        .unwrap();
    connection
        .execute(
            "INSERT INTO tool_executions (
                id, task_id, run_id, request_id, tool_name, arguments_artifact_id,
                policy_decision_id, approval_id, operation_intent_id,
                executor_fencing_token, status, started_at, completed_at, exit_code,
                stdout_artifact_id, stderr_artifact_id
             ) VALUES ('legacy-completed', 'task-1', 'run-1', 'legacy-completed',
                'process.exec', 'request-artifact', 'policy-1', NULL, 'legacy-completed',
                19, 'succeeded', '2026-07-23T12:00:00Z', '2026-07-23T12:00:42Z',
                0, 'legacy-output', NULL)",
            [],
        )
        .unwrap();

    let started_payload = serde_json::json!({
        "executionId": "legacy-completed",
        "operationDigest": canonical.operation_digest.as_str(),
        "policyDecisionId": "policy-1",
        "approvalId": serde_json::Value::Null,
        "executorFencingToken": 19,
    });
    let completed_payload = serde_json::json!({
        "executionId": "legacy-completed",
        "status": "succeeded",
        "exitCode": 0,
        "outputArtifactId": "legacy-output",
        "outputDigest": output_digest.as_str(),
        "receipt": legacy_receipt,
    });
    for (sequence, event_type, payload, created_at) in [
        (
            1,
            "tool.execution.started",
            started_payload,
            "2026-07-23T12:00:00Z",
        ),
        (
            2,
            "tool.execution.completed",
            completed_payload,
            "2026-07-23T12:00:42Z",
        ),
    ] {
        connection
            .execute(
                "INSERT INTO events (
                    event_id, stream_id, sequence, event_type, schema_version, actor_type,
                    actor_id, observation_class, payload_json, metadata_json, causation_id,
                    correlation_id, created_at
                 ) VALUES (?1, 'task-1', ?2, ?3, 1, 'tool', 'legacy-completed',
                    'tool_verified', ?4, '{}', 'tool-execution:legacy-completed',
                    'tool-execution:legacy-completed', ?5)",
                params![
                    format!("{event_type}:legacy-completed:{sequence}"),
                    sequence,
                    event_type,
                    payload.to_string(),
                    created_at,
                ],
            )
            .unwrap();
    }
    connection
        .execute(
            "UPDATE tasks
             SET current_sequence = 2, operation_state = 'None',
                 updated_at = '2026-07-23T12:00:42Z'
             WHERE id = 'task-1'",
            [],
        )
        .unwrap();

    canonical.operation_digest
}

fn insert_physical_artifact(
    connection: &Connection,
    artifact_root: &std::path::Path,
    id: &str,
    logical_path: &str,
    artifact_type: &str,
    bytes: &[u8],
) -> Sha256Digest {
    let digest = Sha256Digest::new(format!("sha256:{:x}", Sha256::digest(bytes))).unwrap();
    let storage_key = format!("objects/{}", &digest.as_str()[7..]);
    let object_path = artifact_root.join(&storage_key);
    fs::create_dir_all(object_path.parent().unwrap()).unwrap();
    fs::write(object_path, bytes).unwrap();
    connection
        .execute(
            "INSERT INTO artifacts (
                id, task_id, project_id, artifact_type, logical_path, content_hash, storage_key,
                size_bytes, mime_type, availability, created_by_type, created_by_id, created_at,
                supersedes, verification_state
             ) VALUES (?1, 'task-1', 'project-1', ?2, ?3, ?4, ?5, ?6, NULL, 'available',
                'tool', 'legacy-completed', '2026-07-23T12:00:00Z', NULL, 'hash_verified')",
            params![
                id,
                artifact_type,
                logical_path,
                digest.as_str(),
                storage_key,
                bytes.len() as i64,
            ],
        )
        .unwrap();
    digest
}

fn database_fingerprint(path: &std::path::Path) -> (String, String, i64, i64) {
    Connection::open(path)
        .unwrap()
        .query_row(
            "SELECT
                (SELECT status || ':' || COALESCE(external_receipt_json, '')
                 FROM operation_intents WHERE id = 'legacy-completed'),
                (SELECT status || ':' || COALESCE(stdout_artifact_id, '')
                 FROM tool_executions WHERE id = 'legacy-completed'),
                (SELECT current_sequence FROM tasks WHERE id = 'task-1'),
                (SELECT COUNT(*) FROM events WHERE stream_id = 'task-1')",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .unwrap()
}

fn install_prior_v1(connection: &mut Connection) {
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .unwrap();
    let (_, body) = NORMATIVE_SQL.split_once("BEGIN IMMEDIATE;").unwrap();
    let (body, _) = body.rsplit_once("COMMIT;").unwrap();
    let migration = format!("{body}\n{PRIOR_V1_HARDENING}");
    assert_eq!(
        format!("sha256:{:x}", Sha256::digest(migration.as_bytes())),
        PRIOR_V1_CHECKSUM
    );
    transaction.execute_batch(&migration).unwrap();
    transaction
        .execute(
            "INSERT INTO schema_migrations (
                version, name, applied_at, application_version, checksum
             ) VALUES (1, 'initial', '2026-07-26T00:00:00Z', '0.1.0', ?1)",
            [PRIOR_V1_CHECKSUM],
        )
        .unwrap();
    transaction.commit().unwrap();
}

fn install_prior_v2(connection: &mut Connection) {
    install_prior_v1(connection);
    let migration = migration_sql("V2_UPGRADE_SQL");
    assert_eq!(
        format!("sha256:{:x}", Sha256::digest(migration.as_bytes())),
        PRIOR_V2_CHECKSUM
    );
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .unwrap();
    transaction.execute_batch(migration).unwrap();
    transaction
        .execute(
            "INSERT INTO schema_migrations (
                version, name, applied_at, application_version, checksum
             ) VALUES (2, 'adapter_hardening_v2',
                '2026-07-26T00:00:00Z', '0.1.0', ?1)",
            [PRIOR_V2_CHECKSUM],
        )
        .unwrap();
    transaction.commit().unwrap();
}

fn install_prior_v3(connection: &mut Connection) {
    install_prior_v2(connection);
    let migration = migration_sql("V3_POLICY_TOOL_HARDENING_SQL");
    assert_eq!(
        format!("sha256:{:x}", Sha256::digest(migration.as_bytes())),
        PRIOR_V3_CHECKSUM
    );
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .unwrap();
    transaction.execute_batch(migration).unwrap();
    transaction
        .execute(
            "INSERT INTO schema_migrations (
                version, name, applied_at, application_version, checksum
             ) VALUES (3, 'policy_tool_hardening_v3',
                '2026-07-26T00:00:00Z', '0.1.0', ?1)",
            [PRIOR_V3_CHECKSUM],
        )
        .unwrap();
    transaction.commit().unwrap();
}

fn install_prior_v4(connection: &mut Connection) -> String {
    install_prior_v3(connection);
    let migration = migration_sql("V4_TOOL_EXECUTION_LIFECYCLE_SQL");
    let checksum = format!("sha256:{:x}", Sha256::digest(migration.as_bytes()));
    assert_eq!(checksum, PRIOR_V4_CHECKSUM);
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .unwrap();
    transaction.execute_batch(migration).unwrap();
    transaction
        .execute(
            "INSERT INTO schema_migrations (
                version, name, applied_at, application_version, checksum
             ) VALUES (4, 'tool_execution_lifecycle_v4',
                '2026-07-30T00:00:00Z', '0.1.0', ?1)",
            [PRIOR_V4_CHECKSUM],
        )
        .unwrap();
    transaction.commit().unwrap();
    PRIOR_V4_CHECKSUM.to_owned()
}

fn install_prior_v5(connection: &mut Connection) -> String {
    install_prior_v4(connection);
    let migration = migration_sql("V5_PRE_EFFECT_TERMINAL_SQL");
    let checksum = format!("sha256:{:x}", Sha256::digest(migration.as_bytes()));
    assert_eq!(checksum, PRIOR_V5_CHECKSUM);
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .unwrap();
    transaction.execute_batch(migration).unwrap();
    transaction
        .execute(
            "INSERT INTO schema_migrations (
                version, name, applied_at, application_version, checksum
             ) VALUES (5, 'pre_effect_terminal_v5',
                '2026-07-30T00:00:00Z', '0.1.0', ?1)",
            [PRIOR_V5_CHECKSUM],
        )
        .unwrap();
    transaction.commit().unwrap();
    PRIOR_V5_CHECKSUM.to_owned()
}

fn install_prior_v6(connection: &mut Connection) {
    install_prior_v5(connection);
    let migration = migration_sql("V6_CONTEXT_HARDENING_SQL");
    assert_eq!(
        format!("sha256:{:x}", Sha256::digest(migration.as_bytes())),
        PRIOR_V6_CHECKSUM
    );
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .unwrap();
    transaction.execute_batch(migration).unwrap();
    transaction
        .execute(
            "INSERT INTO schema_migrations (
                version, name, applied_at, application_version, checksum
             ) VALUES (6, 'context_hardening_v6',
                '2026-08-10T00:00:00Z', '0.1.0', ?1)",
            [PRIOR_V6_CHECKSUM],
        )
        .unwrap();
    transaction.commit().unwrap();
}

fn install_prior_v7(connection: &mut Connection) -> String {
    install_prior_v6(connection);
    let migration = migration_sql("V7_PRIVATE_AGENT_RUN_OUTPUTS_SQL");
    let checksum = format!("sha256:{:x}", Sha256::digest(migration.as_bytes()));
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .unwrap();
    transaction.execute_batch(migration).unwrap();
    transaction
        .execute(
            "INSERT INTO schema_migrations (
                version, name, applied_at, application_version, checksum
             ) VALUES (7, 'private_agent_run_outputs_v7',
                '2026-08-11T00:00:00Z', '0.1.0', ?1)",
            [&checksum],
        )
        .unwrap();
    transaction.commit().unwrap();
    checksum
}

fn migration_sql(name: &str) -> &'static str {
    let declaration = format!("const {name}: &str = r#\"");
    let start = MIGRATIONS_SOURCE
        .find(&declaration)
        .map(|index| index + declaration.len())
        .unwrap();
    let remaining = &MIGRATIONS_SOURCE[start..];
    &remaining[..remaining.find("\"#;").unwrap()]
}

#[test]
fn startup_rejects_unknown_nonempty_database_without_mutating_it() {
    let directory = TempDirectory::new();
    let path = directory.0.join("state.sqlite3");
    let connection = Connection::open(&path).unwrap();
    connection
        .execute("CREATE TABLE unrelated (value TEXT NOT NULL)", [])
        .unwrap();
    let original_journal_mode: String = connection
        .query_row("PRAGMA journal_mode", [], |row| row.get(0))
        .unwrap();
    drop(connection);
    let original_files = directory_entries(&directory.0);

    assert!(matches!(
        SqliteStore::open(&path),
        Err(OpenError::UnsupportedSchema {
            found: 0,
            supported: 9
        })
    ));

    let connection = Connection::open(path).unwrap();
    let journal_mode: String = connection
        .query_row("PRAGMA journal_mode", [], |row| row.get(0))
        .unwrap();
    assert_eq!(journal_mode, original_journal_mode);
    assert_eq!(
        connection
            .query_row(
                "SELECT COUNT(*) FROM sqlite_schema WHERE name = 'unrelated'",
                [],
                |row| row.get::<_, i64>(0)
            )
            .unwrap(),
        1
    );
    assert_eq!(
        connection
            .query_row(
                "SELECT COUNT(*) FROM sqlite_schema WHERE name = 'events'",
                [],
                |row| row.get::<_, i64>(0)
            )
            .unwrap(),
        0
    );
    drop(connection);
    assert_eq!(directory_entries(&directory.0), original_files);
}

#[test]
fn upgrade_rejects_orphaned_rows_before_committing_the_new_schema() {
    let directory = TempDirectory::new();
    let path = directory.0.join("state.sqlite3");
    let mut connection = Connection::open(&path).unwrap();
    connection
        .pragma_update(None, "foreign_keys", "OFF")
        .unwrap();
    install_prior_v4(&mut connection);
    connection
        .execute(
            "INSERT INTO tasks (
                id, project_id, title, objective, phase, condition, operation_state,
                risk_level, base_branch, base_commit, created_at, updated_at
             ) VALUES ('orphan-task', 'missing-project', 'orphan', 'orphan',
                'Implementation', 'Active', 'None', 'high', 'main', ?1,
                '2026-07-30T00:00:00Z', '2026-07-30T00:00:00Z')",
            ["a".repeat(40)],
        )
        .unwrap();
    drop(connection);

    assert!(matches!(
        SqliteStore::open(&path),
        Err(OpenError::ForeignKeyViolation {
            table,
            rowid: _,
            parent,
            foreign_key: _
        }) if table == "tasks" && parent == "projects"
    ));

    let connection = Connection::open(path).unwrap();
    assert_eq!(
        connection
            .query_row("SELECT MAX(version) FROM schema_migrations", [], |row| {
                row.get::<_, i64>(0)
            })
            .unwrap(),
        4
    );
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
}

fn directory_entries(directory: &std::path::Path) -> Vec<std::ffi::OsString> {
    let mut entries: Vec<_> = fs::read_dir(directory)
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect();
    entries.sort();
    entries
}

#[test]
fn every_initialized_connection_enables_required_pragmas() {
    let directory = TempDirectory::new();
    let store = SqliteStore::open(directory.0.join("state.sqlite3")).unwrap();

    let pragmas = store.pragma_settings().unwrap();

    assert_eq!(pragmas.journal_mode, "wal");
    assert!(pragmas.foreign_keys);
    assert_eq!(pragmas.busy_timeout_ms, 5000);
    assert_eq!(pragmas.synchronous, 2);
    assert_eq!(pragmas.wal_autocheckpoint, 1000);
    assert!(pragmas.recursive_triggers);
}

#[test]
fn database_and_artifact_root_health_are_typed() {
    let directory = TempDirectory::new();
    let database_path = directory.0.join("state.sqlite3");
    let store = SqliteStore::open(&database_path).unwrap();
    assert_eq!(store.database_health(), DatabaseHealth::Healthy);

    let missing = directory.0.join("missing");
    assert_eq!(
        artifact_root_health(&missing),
        Err(ArtifactRootIssue::Missing)
    );

    let file = directory.0.join("file");
    fs::write(&file, b"not a directory").unwrap();
    assert_eq!(
        artifact_root_health(&file),
        Err(ArtifactRootIssue::NotDirectory)
    );
    assert_eq!(artifact_root_health(&directory.0), Ok(()));
}

#[test]
fn artifact_root_probe_collision_preserves_preexisting_paths() {
    let directory = TempDirectory::new();
    for suffix in 0..64 {
        fs::write(
            directory
                .0
                .join(format!(".write-probe-{}-{suffix}", std::process::id())),
            b"owned-by-someone-else",
        )
        .unwrap();
    }

    assert_eq!(
        artifact_root_health(&directory.0),
        Err(ArtifactRootIssue::NotWritable)
    );
    for suffix in 0..64 {
        assert_eq!(
            fs::read(
                directory
                    .0
                    .join(format!(".write-probe-{}-{suffix}", std::process::id()))
            )
            .unwrap(),
            b"owned-by-someone-else"
        );
    }
}

#[test]
fn artifact_root_symlink_is_rejected_without_touching_target() {
    let directory = TempDirectory::new();
    let target = directory.0.join("target");
    let link = directory.0.join("link");
    fs::create_dir(&target).unwrap();
    fs::write(target.join("marker"), b"keep").unwrap();
    create_directory_symlink(&target, &link);

    assert_eq!(
        artifact_root_health(&link),
        Err(ArtifactRootIssue::NotDirectory)
    );
    let mut target_entries: Vec<_> = fs::read_dir(target)
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect();
    target_entries.sort();
    assert_eq!(target_entries, ["marker"]);
}

#[cfg(unix)]
fn create_directory_symlink(target: &std::path::Path, link: &std::path::Path) {
    std::os::unix::fs::symlink(target, link).unwrap();
}

#[cfg(windows)]
fn create_directory_symlink(target: &std::path::Path, link: &std::path::Path) {
    assert!(std::process::Command::new("cmd.exe")
        .args(["/C", "mklink", "/J"])
        .arg(link)
        .arg(target)
        .output()
        .unwrap()
        .status
        .success());
}
