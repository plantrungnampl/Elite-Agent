use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Barrier};
use std::thread;

use local_agent_terminal_application::{
    AppendOperation, ArtifactJournal, ArtifactJournalStatus, ArtifactJournalTransition,
    ArtifactWriteReservation, EventStore, NewEvent, PortError, ProjectionChange, ReservedArtifact,
};
use local_agent_terminal_domain::{
    ActorId, Condition, EventId, FencingToken, OperationState, Phase, Sequence, StreamId, TaskId,
    WorkflowEvent, WorkflowState, WorkspaceVersion,
};
use local_agent_terminal_storage_sqlite::SqliteStore;
use rusqlite::{params, Connection};
use serde_json::json;

static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

struct TempDatabase {
    directory: PathBuf,
    path: PathBuf,
}

impl TempDatabase {
    fn new() -> Self {
        let directory = std::env::temp_dir().join(format!(
            "local-agent-terminal-storage-test-{}-{}",
            std::process::id(),
            NEXT_TEMP.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&directory).unwrap();
        Self {
            path: directory.join("state.sqlite3"),
            directory,
        }
    }
}

impl Drop for TempDatabase {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.directory);
    }
}

fn seed_task(path: &Path, task_id: &str) {
    let connection = Connection::open(path).unwrap();
    connection
        .execute_batch("PRAGMA foreign_keys = ON;")
        .unwrap();
    connection
        .execute(
            "INSERT OR IGNORE INTO projects (
                id, name, repository_path, repository_identity, created_at, updated_at,
                policy_profile_id, artifact_root_mode, artifact_root_path
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?5, ?6, ?7, ?8)",
            params![
                "project-1",
                "Project",
                "C:/repo",
                "repo-identity",
                "2026-07-26T00:00:00Z",
                "default",
                "application_data",
                "C:/artifacts"
            ],
        )
        .unwrap();
    connection
        .execute(
            "INSERT INTO tasks (
                id, project_id, title, objective, phase, condition, operation_state,
                risk_level, base_branch, base_commit, current_sequence, workspace_version,
                fencing_epoch, created_at, updated_at
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, 0, 0, 1, ?11, ?11)",
            params![
                task_id,
                "project-1",
                "Task",
                "Test SQLite",
                "Intake",
                "Active",
                "None",
                "low",
                "main",
                "0123456789abcdef0123456789abcdef01234567",
                "2026-07-26T00:00:00Z"
            ],
        )
        .unwrap();
}

fn event(id: &str) -> NewEvent {
    NewEvent {
        event_id: EventId::new(id).unwrap(),
        event_type: WorkflowEvent::new("task.created").unwrap(),
        schema_version: 1,
        actor_type: "core".to_owned(),
        actor_id: ActorId::new("core").unwrap(),
        observation_class: "core_observed".to_owned(),
        payload: json!({"taskId": "task-1"}),
        metadata: json!({}),
        causation_id: None,
        correlation_id: "correlation-1".to_owned(),
        created_at: "2026-07-26T00:00:01Z".to_owned(),
    }
}

fn state(sequence: u64) -> WorkflowState {
    WorkflowState::new(
        Phase::ContextBuild,
        Condition::Active,
        OperationState::None,
        Sequence::new(sequence),
        WorkspaceVersion::new(0),
        FencingToken::new(1).unwrap(),
    )
    .unwrap()
}

fn append_operation(expected: u64, event_id: &str, projection_task: &str) -> AppendOperation {
    AppendOperation {
        stream_id: StreamId::new("task-1").unwrap(),
        expected_version: Sequence::new(expected),
        events: vec![event(event_id)],
        projection_changes: vec![ProjectionChange::TaskState {
            task_id: TaskId::new(projection_task).unwrap(),
            state: state(expected + 1),
            updated_at: "2026-07-26T00:00:01Z".to_owned(),
        }],
    }
}

fn reservation(operation_id: &str, artifact_id: &str) -> ArtifactWriteReservation {
    ArtifactWriteReservation {
        operation_id: operation_id.to_owned(),
        artifact: ReservedArtifact {
            artifact_id: artifact_id.to_owned(),
            task_id: Some(TaskId::new("task-1").unwrap()),
            project_id: "project-1".to_owned(),
            artifact_type: "report".to_owned(),
            logical_path: format!("reports/{artifact_id}.md"),
            content_hash: format!("sha256:{}", "a".repeat(64)),
            storage_key: format!("aa/{artifact_id}"),
            size_bytes: 12,
            mime_type: Some("text/markdown".to_owned()),
            created_by_type: "core".to_owned(),
            created_by_id: "core".to_owned(),
            created_at: "2026-07-26T00:00:00Z".to_owned(),
            supersedes: None,
        },
        temp_name: format!(".{artifact_id}.tmp"),
        created_at: "2026-07-26T00:00:00Z".to_owned(),
    }
}

#[test]
fn append_updates_event_and_projection_atomically() {
    let database = TempDatabase::new();
    let store = SqliteStore::open(&database.path).unwrap();
    seed_task(&database.path, "task-1");

    let result = store
        .append(append_operation(0, "event-1", "task-1"))
        .unwrap();

    assert_eq!(result.new_version, Sequence::new(1));
    let connection = Connection::open(&database.path).unwrap();
    let event: (i64, String, String) = connection
        .query_row(
            "SELECT sequence, payload_json, metadata_json FROM events WHERE event_id = ?1",
            ["event-1"],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap();
    assert_eq!(
        event,
        (1, r#"{"taskId":"task-1"}"#.to_owned(), "{}".to_owned())
    );
    let projection: (i64, String) = connection
        .query_row(
            "SELECT current_sequence, phase FROM tasks WHERE id = ?1",
            ["task-1"],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(projection, (1, "ContextBuild".to_owned()));
}

#[test]
fn append_advances_stream_head_without_a_projection_payload() {
    let database = TempDatabase::new();
    let store = SqliteStore::open(&database.path).unwrap();
    seed_task(&database.path, "task-1");
    let mut operation = append_operation(0, "event-1", "task-1");
    operation.projection_changes.clear();

    store.append(operation).unwrap();

    let connection = Connection::open(&database.path).unwrap();
    assert_eq!(
        connection
            .query_row(
                "SELECT current_sequence FROM tasks WHERE id = ?1",
                ["task-1"],
                |row| row.get::<_, i64>(0)
            )
            .unwrap(),
        1
    );
}

#[test]
fn competing_writers_yield_one_success_and_one_version_conflict() {
    let database = TempDatabase::new();
    let store = SqliteStore::open(&database.path).unwrap();
    seed_task(&database.path, "task-1");
    let barrier = Arc::new(Barrier::new(3));

    let handles: Vec<_> = ["event-a", "event-b"]
        .into_iter()
        .map(|event_id| {
            let store = store.clone();
            let barrier = barrier.clone();
            thread::spawn(move || {
                barrier.wait();
                store.append(append_operation(0, event_id, "task-1"))
            })
        })
        .collect();
    barrier.wait();
    let results: Vec<_> = handles
        .into_iter()
        .map(|handle| handle.join().unwrap())
        .collect();

    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
    assert_eq!(
        results
            .iter()
            .filter(|result| matches!(result, Err(PortError::VersionConflict { expected, actual }) if *expected == Sequence::new(0) && *actual == Sequence::new(1)))
            .count(),
        1
    );
}

#[test]
fn failed_projection_rolls_back_inserted_events() {
    let database = TempDatabase::new();
    let store = SqliteStore::open(&database.path).unwrap();
    seed_task(&database.path, "task-1");

    assert!(store
        .append(append_operation(0, "event-1", "missing-task"))
        .is_err());

    let connection = Connection::open(&database.path).unwrap();
    assert_eq!(
        connection
            .query_row("SELECT COUNT(*) FROM events", [], |row| row
                .get::<_, i64>(0))
            .unwrap(),
        0
    );
    assert_eq!(
        connection
            .query_row(
                "SELECT current_sequence FROM tasks WHERE id = 'task-1'",
                [],
                |row| row.get::<_, i64>(0)
            )
            .unwrap(),
        0
    );
}

#[test]
fn persisted_events_are_immutable() {
    let database = TempDatabase::new();
    let store = SqliteStore::open(&database.path).unwrap();
    seed_task(&database.path, "task-1");
    store
        .append(append_operation(0, "event-1", "task-1"))
        .unwrap();
    let connection = Connection::open(&database.path).unwrap();

    assert!(connection
        .execute(
            "UPDATE events SET event_type = ?1 WHERE event_id = ?2",
            params!["changed", "event-1"]
        )
        .is_err());
    assert!(connection
        .execute("DELETE FROM events WHERE event_id = ?1", ["event-1"])
        .is_err());
}

#[test]
fn artifact_reservation_is_atomic_and_transitions_only_move_forward() {
    let database = TempDatabase::new();
    let store = SqliteStore::open(&database.path).unwrap();
    seed_task(&database.path, "task-1");

    store
        .reserve(reservation("operation-1", "artifact-1"))
        .unwrap();
    let connection = Connection::open(&database.path).unwrap();
    let reserved: (String, String) = connection
        .query_row(
            "SELECT a.availability, o.status FROM artifacts a
             JOIN artifact_operations o ON o.artifact_id = a.id WHERE a.id = ?1",
            ["artifact-1"],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(reserved, ("reserved".to_owned(), "intent".to_owned()));

    let invented_success = ArtifactJournalTransition {
        operation_id: "operation-1".to_owned(),
        expected_status: ArtifactJournalStatus::Intent,
        next_status: ArtifactJournalStatus::Completed,
        updated_at: "2026-07-26T00:00:01Z".to_owned(),
        completed_at: Some("2026-07-26T00:00:01Z".to_owned()),
        error: None,
    };
    assert!(store.transition(invented_success).is_err());

    for (expected_status, next_status, completed_at) in [
        (
            ArtifactJournalStatus::Intent,
            ArtifactJournalStatus::Staging,
            None,
        ),
        (
            ArtifactJournalStatus::Staging,
            ArtifactJournalStatus::Renamed,
            None,
        ),
        (
            ArtifactJournalStatus::Renamed,
            ArtifactJournalStatus::Completed,
            Some("2026-07-26T00:00:04Z".to_owned()),
        ),
    ] {
        store
            .transition(ArtifactJournalTransition {
                operation_id: "operation-1".to_owned(),
                expected_status,
                next_status,
                updated_at: "2026-07-26T00:00:04Z".to_owned(),
                completed_at,
                error: None,
            })
            .unwrap();
    }

    let backward = ArtifactJournalTransition {
        operation_id: "operation-1".to_owned(),
        expected_status: ArtifactJournalStatus::Completed,
        next_status: ArtifactJournalStatus::Renamed,
        updated_at: "2026-07-26T00:00:05Z".to_owned(),
        completed_at: None,
        error: None,
    };
    assert!(store.transition(backward).is_err());
    assert_eq!(
        connection
            .query_row(
                "SELECT availability FROM artifacts WHERE id = ?1",
                ["artifact-1"],
                |row| row.get::<_, String>(0)
            )
            .unwrap(),
        "available"
    );
    assert!(store.incomplete().unwrap().is_empty());
}

#[test]
fn failed_journal_insert_rolls_back_reserved_artifact_metadata() {
    let database = TempDatabase::new();
    let store = SqliteStore::open(&database.path).unwrap();
    seed_task(&database.path, "task-1");
    store
        .reserve(reservation("operation-1", "artifact-1"))
        .unwrap();

    assert!(store
        .reserve(reservation("operation-1", "artifact-2"))
        .is_err());

    let connection = Connection::open(&database.path).unwrap();
    assert_eq!(
        connection
            .query_row(
                "SELECT COUNT(*) FROM artifacts WHERE id = ?1",
                ["artifact-2"],
                |row| row.get::<_, i64>(0)
            )
            .unwrap(),
        0
    );
}
