use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use local_agent_terminal_storage_sqlite::{
    artifact_root_health, migration_checksum, ArtifactRootIssue, DatabaseHealth, OpenError,
    SqliteStore,
};
use rusqlite::{params, Connection};

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
    let migration: (i64, String) = connection
        .query_row(
            "SELECT version, checksum FROM schema_migrations",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(migration, (1, migration_checksum()));
    assert_eq!(migration.1.len(), 71);
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
}

#[test]
fn later_startup_rejects_changed_or_unsupported_schema() {
    let mismatch_directory = TempDirectory::new();
    let mismatch_path = mismatch_directory.0.join("state.sqlite3");
    SqliteStore::open(&mismatch_path).unwrap();
    Connection::open(&mismatch_path)
        .unwrap()
        .execute(
            "UPDATE schema_migrations SET checksum = ?1 WHERE version = ?2",
            params![format!("sha256:{}", "0".repeat(64)), 1],
        )
        .unwrap();
    assert!(matches!(
        SqliteStore::open(&mismatch_path),
        Err(OpenError::ChecksumMismatch { .. })
    ));

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
                2,
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
            found: 2,
            supported: 1
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
            supported: 1
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
