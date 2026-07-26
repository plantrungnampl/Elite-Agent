use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::path::Path;
use std::process::{Command, Stdio};

use local_agent_terminal_application::{Clock, PortError, ReservedArtifact, StartupStateDto};
use local_agent_terminal_bootstrap::{Bootstrap, StartupConfig};
use local_agent_terminal_storage_files::{
    ContentAddressedArtifactStore, FaultPoint, JournaledArtifactWriter, RecoveryLock,
};
use local_agent_terminal_storage_sqlite::SqliteStore;
use rusqlite::{params, Connection};
use tempfile::TempDir;

const HELLO_HASH: &str = "sha256:2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824";

#[test]
fn first_startup_creates_and_validates_required_local_state() {
    let parent = TempDir::new().unwrap();
    let app_data = parent.path().join("app-data");

    let bootstrap = Bootstrap::new(config(&app_data));

    assert_eq!(bootstrap.status().state, StartupStateDto::Ready);
    let _released_startup_lock = RecoveryLock::acquire(&app_data).unwrap();
    assert!(app_data.join("state.sqlite3").is_file());
    for relative in [
        "artifacts/objects",
        "artifacts/staging",
        "artifacts/quarantine",
    ] {
        assert!(app_data.join(relative).is_dir(), "{relative} was not ready");
    }
    assert_eq!(
        SqliteStore::open(app_data.join("state.sqlite3"))
            .unwrap()
            .database_health(),
        local_agent_terminal_storage_sqlite::DatabaseHealth::Healthy
    );
    let codes: Vec<_> = bootstrap
        .local_diagnostics()
        .iter()
        .map(|record| record.code.as_str())
        .collect();
    assert_eq!(
        codes,
        [
            "startup.app_directories.validated",
            "startup.recovery_lock.acquired",
            "startup.database.validated",
            "startup.artifacts.validated",
            "startup.artifacts.reconciled",
            "startup.ready",
        ]
    );
}

#[test]
fn startup_reconciles_a_durable_renamed_artifact_before_ready() {
    let parent = TempDir::new().unwrap();
    let app_data = parent.path().join("app-data");
    let artifacts = ContentAddressedArtifactStore::open(app_data.join("artifacts")).unwrap();
    let database_path = app_data.join("state.sqlite3");
    let database = SqliteStore::open(&database_path).unwrap();
    seed_project(&database_path);
    let reservation = reservation();
    let result = JournaledArtifactWriter::new(&artifacts, &database, &FixedClock).write_with_fault(
        reservation,
        b"hello",
        |point| {
            if point == FaultPoint::BeforeCompletionRecord {
                Err(PortError::failure(
                    local_agent_terminal_application::SafeErrorClassification::Internal,
                    local_agent_terminal_application::Retryability::NonRetryable,
                ))
            } else {
                Ok(())
            }
        },
    );
    assert!(result.is_err());
    drop(database);
    drop(artifacts);

    let bootstrap = Bootstrap::new(config(&app_data));

    assert_eq!(bootstrap.status().state, StartupStateDto::Ready);
    let status: String = Connection::open(database_path)
        .unwrap()
        .query_row(
            "SELECT status FROM artifact_operations WHERE id = 'operation-1'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(status, "completed");
    assert!(bootstrap.local_diagnostics().iter().any(|record| {
        record.code == "startup.artifacts.reconciled" && record.detail.contains("completed=1")
    }));
}

#[test]
fn schema_failure_has_stable_safe_recovery_and_sanitized_diagnostics() {
    let parent = TempDir::new().unwrap();
    let app_data = parent.path().join("app-data");
    ContentAddressedArtifactStore::open(app_data.join("artifacts")).unwrap();
    let database_path = app_data.join("state.sqlite3");
    SqliteStore::open(&database_path).unwrap();
    Connection::open(&database_path)
        .unwrap()
        .execute(
            "UPDATE schema_migrations SET checksum = ?1 WHERE version = 1",
            [format!("sha256:{}", "0".repeat(64))],
        )
        .unwrap();

    let bootstrap = Bootstrap::new(StartupConfig {
        app_data_dir: app_data,
        secret_values: vec!["sha256:".to_owned()],
    });

    assert_eq!(
        bootstrap.status().state,
        StartupStateDto::RecoverableFailure
    );
    let issue = bootstrap.status().issues.first().unwrap();
    assert_eq!(issue.code, "startup.database_schema_invalid");
    assert_eq!(
        issue.message,
        "The local database schema could not be validated."
    );
    assert_eq!(
        issue
            .recovery_actions
            .iter()
            .map(|action| action.code.as_str())
            .collect::<Vec<_>>(),
        ["retry_startup_validation", "get_local_diagnostics"]
    );
    let rendered = serde_json::to_string(bootstrap.local_diagnostics()).unwrap();
    assert!(!rendered.contains("sha256:"));
    assert!(!rendered.contains(parent.path().to_string_lossy().as_ref()));
}

#[test]
fn database_failure_precedes_artifact_storage_mutation() {
    let parent = TempDir::new().unwrap();
    let app_data = parent.path().join("app-data");
    fs::create_dir(&app_data).unwrap();
    let database_path = app_data.join("state.sqlite3");
    SqliteStore::open(&database_path).unwrap();
    Connection::open(&database_path)
        .unwrap()
        .execute(
            "UPDATE schema_migrations SET checksum = ?1",
            [format!("sha256:{}", "a".repeat(64))],
        )
        .unwrap();

    let bootstrap = Bootstrap::new(config(&app_data));

    assert_eq!(
        bootstrap.status().issues[0].code,
        "startup.database_schema_invalid"
    );
    assert!(!app_data.join("artifacts").exists());
    let _released_failure_lock = RecoveryLock::acquire(&app_data).unwrap();
}

#[test]
fn recovery_lock_holder_process() {
    let Some(root) = std::env::var_os("LOCAL_AGENT_TERMINAL_LOCK_TEST_ROOT") else {
        return;
    };
    let _lock = RecoveryLock::acquire(Path::new(&root)).unwrap();
    println!("RECOVERY_LOCK_HELD");
    std::io::stdout().flush().unwrap();
    let mut release = [0_u8; 1];
    std::io::stdin().read_exact(&mut release).unwrap();
}

#[test]
fn concurrent_startup_fails_closed_without_mutating_shared_state() {
    let parent = TempDir::new().unwrap();
    let app_data = parent.path().join("app-data");
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "recovery_lock_holder_process",
            "--nocapture",
            "--test-threads=1",
        ])
        .env("LOCAL_AGENT_TERMINAL_LOCK_TEST_ROOT", &app_data)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut child_input = child.stdin.take().unwrap();
    let mut child_output = BufReader::new(child.stdout.take().unwrap());
    let mut line = String::new();
    loop {
        line.clear();
        assert_ne!(child_output.read_line(&mut line).unwrap(), 0);
        if line.contains("RECOVERY_LOCK_HELD") {
            break;
        }
    }

    let bootstrap = Bootstrap::new(config(&app_data));

    assert_ne!(bootstrap.status().state, StartupStateDto::Ready);
    assert_eq!(
        bootstrap.status().issues[0].code,
        "startup.recovery_lock_unavailable"
    );
    assert!(!app_data.join("state.sqlite3").exists());
    assert!(!app_data.join("artifacts").exists());
    child_input.write_all(&[1]).unwrap();
    assert!(child.wait().unwrap().success());
}

#[test]
fn attacker_controlled_adapter_context_never_crosses_serialization_boundary() {
    let parent = TempDir::new().unwrap();
    let attacker_path = "private-repo-SELECT-secret-FROM-credentials";
    let attacker_checksum = format!("sha256:{}", "a".repeat(64));
    let app_data = parent.path().join(attacker_path);
    ContentAddressedArtifactStore::open(app_data.join("artifacts")).unwrap();
    let database_path = app_data.join("state.sqlite3");
    SqliteStore::open(&database_path).unwrap();
    Connection::open(&database_path)
        .unwrap()
        .execute(
            "UPDATE schema_migrations SET checksum = ?1 WHERE version = 1",
            [&attacker_checksum],
        )
        .unwrap();

    let bootstrap = Bootstrap::new(config(&app_data));
    let rendered = format!(
        "{} {}",
        serde_json::to_string(bootstrap.status()).unwrap(),
        serde_json::to_string(bootstrap.local_diagnostics()).unwrap()
    );

    for forbidden in [
        attacker_path,
        "SELECT-secret",
        "credentials",
        attacker_checksum.as_str(),
    ] {
        assert!(!rendered.contains(forbidden), "leaked {forbidden}");
    }
}

#[test]
fn retry_revalidates_state_and_never_fabricates_ready() {
    let parent = TempDir::new().unwrap();
    let app_data = parent.path().join("app-data");
    fs::write(&app_data, b"not a directory").unwrap();
    let mut bootstrap = Bootstrap::new(config(&app_data));
    assert_ne!(bootstrap.status().state, StartupStateDto::Ready);
    assert_eq!(
        bootstrap.status().issues[0].code,
        "startup.app_directories_unavailable"
    );

    fs::remove_file(&app_data).unwrap();
    assert_eq!(
        bootstrap.retry_startup_validation().state,
        StartupStateDto::Ready
    );

    let database_path = app_data.join("state.sqlite3");
    Connection::open(database_path)
        .unwrap()
        .execute(
            "UPDATE schema_migrations SET checksum = ?1 WHERE version = 1",
            [format!("sha256:{}", "f".repeat(64))],
        )
        .unwrap();
    assert_ne!(
        bootstrap.retry_startup_validation().state,
        StartupStateDto::Ready
    );
}

#[test]
fn tauri_facing_values_are_serializable_data_without_resource_capabilities() {
    let parent = TempDir::new().unwrap();
    let bootstrap = Bootstrap::new(config(&parent.path().join("app-data")));

    let status = serde_json::to_value(bootstrap.status()).unwrap();
    let diagnostics = serde_json::to_value(bootstrap.local_diagnostics()).unwrap();

    assert_eq!(status["state"], "ready");
    for forbidden in ["path", "handle", "connection", "sql", "filesystem", "shell"] {
        assert!(
            !contains_key(&status, forbidden) && !contains_key(&diagnostics, forbidden),
            "serialized Tauri data exposed {forbidden}"
        );
    }
}

#[test]
fn desktop_depends_on_bootstrap_instead_of_concrete_storage_adapters() {
    let metadata: serde_json::Value = serde_json::from_slice(
        &Command::new(env!("CARGO"))
            .args(["metadata", "--no-deps", "--format-version", "1"])
            .output()
            .unwrap()
            .stdout,
    )
    .unwrap();
    let packages = metadata["packages"].as_array().unwrap();
    let desktop = packages
        .iter()
        .find(|package| package["name"] == "local-agent-terminal-desktop")
        .unwrap();
    let bootstrap = packages
        .iter()
        .find(|package| package["name"] == "local-agent-terminal-bootstrap")
        .unwrap();

    assert_eq!(
        normal_dependencies(desktop),
        ["local-agent-terminal-bootstrap", "tauri"]
    );
    assert!(normal_dependencies(bootstrap).contains(&"local-agent-terminal-storage-files"));
    assert!(normal_dependencies(bootstrap).contains(&"local-agent-terminal-storage-sqlite"));
}

fn config(app_data_dir: &Path) -> StartupConfig {
    StartupConfig {
        app_data_dir: app_data_dir.to_owned(),
        secret_values: Vec::new(),
    }
}

fn contains_key(value: &serde_json::Value, forbidden: &str) -> bool {
    match value {
        serde_json::Value::Object(values) => values.iter().any(|(key, value)| {
            key.to_ascii_lowercase().contains(forbidden) || contains_key(value, forbidden)
        }),
        serde_json::Value::Array(values) => {
            values.iter().any(|value| contains_key(value, forbidden))
        }
        _ => false,
    }
}

fn normal_dependencies(package: &serde_json::Value) -> Vec<&str> {
    let mut dependencies: Vec<_> = package["dependencies"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|dependency| dependency["kind"].is_null())
        .map(|dependency| dependency["name"].as_str().unwrap())
        .collect();
    dependencies.sort_unstable();
    dependencies
}

struct FixedClock;

impl Clock for FixedClock {
    fn now_utc(&self) -> Result<String, PortError> {
        Ok("2026-07-26T00:00:00Z".to_owned())
    }
}

fn seed_project(path: &Path) {
    Connection::open(path)
        .unwrap()
        .execute(
            "INSERT INTO projects (
                id, name, repository_path, repository_identity, created_at, updated_at,
                policy_profile_id, artifact_root_mode, artifact_root_path
             ) VALUES (?1, 'Project', 'C:/repo', 'repo-identity', ?2, ?2,
                'default', 'application_data', 'C:/artifacts')",
            params!["project-1", "2026-07-26T00:00:00Z"],
        )
        .unwrap();
}

fn reservation() -> local_agent_terminal_application::ArtifactWriteReservation {
    local_agent_terminal_application::ArtifactWriteReservation {
        operation_id: "operation-1".to_owned(),
        artifact: ReservedArtifact {
            artifact_id: "artifact-1".to_owned(),
            task_id: None,
            project_id: "project-1".to_owned(),
            artifact_type: "test".to_owned(),
            logical_path: "artifact.txt".to_owned(),
            content_hash: HELLO_HASH.to_owned(),
            storage_key: format!("objects/2c/{}", &HELLO_HASH[7..]),
            size_bytes: 5,
            mime_type: Some("text/plain".to_owned()),
            created_by_type: "core".to_owned(),
            created_by_id: "core".to_owned(),
            created_at: "2026-07-26T00:00:00Z".to_owned(),
            supersedes: None,
        },
        temp_name: "operation-1.tmp".to_owned(),
        created_at: "2026-07-26T00:00:00Z".to_owned(),
    }
}
