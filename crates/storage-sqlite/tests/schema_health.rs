use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use local_agent_terminal_storage_sqlite::{
    artifact_root_health, ArtifactRootIssue, DatabaseHealth, SqliteStore,
};
use rusqlite::{params, Connection};

static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

struct TempDirectory(PathBuf);

impl TempDirectory {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "local-agent-terminal-schema-health-test-{}-{}",
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
fn task_fencing_epoch_cannot_decrease() {
    let directory = TempDirectory::new();
    let path = directory.0.join("state.sqlite3");
    SqliteStore::open(&path).unwrap();
    let connection = Connection::open(path).unwrap();
    seed_project_and_task(&connection);

    connection
        .execute(
            "UPDATE tasks SET fencing_epoch = 1, row_version = 1 WHERE id = 'task-1'",
            [],
        )
        .unwrap();
    connection
        .execute(
            "UPDATE tasks SET fencing_epoch = 1, row_version = 2 WHERE id = 'task-1'",
            [],
        )
        .unwrap();
    assert!(connection
        .execute(
            "UPDATE tasks SET fencing_epoch = 0, row_version = 3 WHERE id = 'task-1'",
            [],
        )
        .is_err());
}

#[test]
fn enabled_external_agents_require_current_exact_containment_attestation() {
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
                 ) VALUES (?1, 'agent', 'local', ?2, '{}', ?3, NULL, 1, 0, NULL,
                    '2026-08-12T00:00:00.000Z')",
                params![format!("{trust_tier}-agent"), trust_tier, digest('a'),],
            )
            .is_err());
    }
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

fn seed_project_and_task(connection: &Connection) {
    connection
        .execute(
            "INSERT INTO projects (
                id, name, repository_path, repository_identity, created_at, updated_at,
                policy_profile_id, artifact_root_mode, artifact_root_path
             ) VALUES (
                'project-1', 'Project', 'D:/repository', ?1, ?2, ?2,
                'policy-1', 'application_data', 'D:/artifacts'
             )",
            params![digest('b'), "2026-08-12T00:00:00.000Z"],
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
                'task-1', 'project-1', 'Task', 'Objective', 'Intake', 'Active', 'None',
                'low', 'main', ?1, NULL, NULL, 0, 0, 0, 0, NULL, NULL, ?2, ?2
             )",
            params![
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "2026-08-12T00:00:00.000Z",
            ],
        )
        .unwrap();
}

fn digest(character: char) -> String {
    format!("sha256:{}", character.to_string().repeat(64))
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
