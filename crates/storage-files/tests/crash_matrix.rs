use std::fs;
use std::path::{Path, PathBuf};

use local_agent_terminal_application::{
    ArtifactJournal, ArtifactStore, ArtifactWriteReservation, Clock, NewArtifact, PortError,
    ReservedArtifact, Retryability, SafeErrorClassification,
};
use local_agent_terminal_storage_files::{
    reconcile_artifacts, ContentAddressedArtifactStore, FaultPoint, JournaledArtifactWriter,
};
use local_agent_terminal_storage_sqlite::SqliteStore;
use rusqlite::{params, Connection};
use tempfile::TempDir;

const HELLO_HASH: &str = "sha256:2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824";
const WORLD_HASH: &str = "sha256:486ea46224d1bb4fb680f34f7c9ad96a8f24ec88be73ea8e5a6c65260e9cb8a7";

struct Fixture {
    _directory: TempDir,
    database_path: PathBuf,
    store: ContentAddressedArtifactStore,
    journal: SqliteStore,
    clock: FixedClock,
}

impl Fixture {
    fn new() -> Self {
        let directory = TempDir::new().unwrap();
        let database_path = directory.path().join("state.sqlite3");
        let journal = SqliteStore::open(&database_path).unwrap();
        seed_project(&database_path);
        let store =
            ContentAddressedArtifactStore::open(directory.path().join("artifacts")).unwrap();
        Self {
            _directory: directory,
            database_path,
            store,
            journal,
            clock: FixedClock,
        }
    }

    fn state(&self, operation_id: &str) -> (String, String) {
        Connection::open(&self.database_path)
            .unwrap()
            .query_row(
                "SELECT o.status, a.availability FROM artifact_operations o
                 JOIN artifacts a ON a.id = o.artifact_id WHERE o.id = ?1",
                [operation_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap()
    }
}

struct FixedClock;

impl Clock for FixedClock {
    fn now_utc(&self) -> Result<String, PortError> {
        Ok("2026-07-26T00:00:01Z".to_owned())
    }
}

#[test]
fn crash_boundaries_reconcile_to_deterministic_states() {
    for (index, fault) in [
        FaultPoint::BeforeWrite,
        FaultPoint::AfterWrite,
        FaultPoint::AfterFlush,
        FaultPoint::AfterJournalTransition,
        FaultPoint::AfterRename,
        FaultPoint::BeforeCompletionRecord,
    ]
    .into_iter()
    .enumerate()
    {
        let fixture = Fixture::new();
        let operation_id = format!("operation-{index}");
        let reservation = reservation(&operation_id, &format!("artifact-{index}"), "hello.txt");
        let writer = JournaledArtifactWriter::new(&fixture.store, &fixture.journal, &fixture.clock);

        let result = writer.write_with_fault(reservation, b"hello", |boundary| {
            if boundary == fault {
                Err(injected_crash())
            } else {
                Ok(())
            }
        });
        assert!(result.is_err(), "{fault:?} did not interrupt the write");

        reconcile_artifacts(&fixture.store, &fixture.journal, &fixture.clock).unwrap();

        let expected = if fault == FaultPoint::BeforeWrite {
            ("aborted".to_owned(), "missing".to_owned())
        } else {
            ("completed".to_owned(), "available".to_owned())
        };
        assert_eq!(fixture.state(&operation_id), expected, "{fault:?}");
        assert!(fixture.journal.incomplete().unwrap().is_empty());
        let evidence = quarantine_evidence(&fixture);
        assert_eq!(
            reconcile_artifacts(&fixture.store, &fixture.journal, &fixture.clock).unwrap(),
            Default::default(),
            "{fault:?} was not idempotent"
        );
        assert_eq!(fixture.state(&operation_id), expected, "{fault:?}");
        assert_eq!(quarantine_evidence(&fixture), evidence, "{fault:?}");
    }
}

#[test]
fn invalid_staging_bytes_are_quarantined_and_preserved() {
    let fixture = Fixture::new();
    let reservation = reservation("operation-bad", "artifact-bad", "bad.txt");
    let temp_name = reservation.temp_name.clone();
    let writer = JournaledArtifactWriter::new(&fixture.store, &fixture.journal, &fixture.clock);
    assert!(writer
        .write_with_fault(reservation, b"hello", |point| {
            if point == FaultPoint::AfterWrite {
                Err(injected_crash())
            } else {
                Ok(())
            }
        })
        .is_err());
    fs::write(
        fixture.store.root().join("staging").join(temp_name),
        b"tampered",
    )
    .unwrap();

    reconcile_artifacts(&fixture.store, &fixture.journal, &fixture.clock).unwrap();

    assert_eq!(
        fixture.state("operation-bad"),
        ("quarantined".to_owned(), "quarantined".to_owned())
    );
    let quarantined: Vec<_> = fs::read_dir(fixture.store.root().join("quarantine"))
        .unwrap()
        .map(|entry| fs::read(entry.unwrap().path()).unwrap())
        .collect();
    assert_eq!(quarantined, [b"tampered".to_vec()]);
    assert_eq!(
        reconcile_artifacts(&fixture.store, &fixture.journal, &fixture.clock).unwrap(),
        Default::default()
    );
    assert_eq!(
        fixture.state("operation-bad"),
        ("quarantined".to_owned(), "quarantined".to_owned())
    );
    assert_eq!(quarantine_evidence(&fixture), quarantined);
}

#[test]
fn completed_missing_and_corrupt_objects_are_invalidated() {
    for corrupt in [false, true] {
        let fixture = Fixture::new();
        let suffix = if corrupt { "corrupt" } else { "missing" };
        let operation_id = format!("operation-{suffix}");
        let artifact_id = format!("artifact-{suffix}");
        let writer = JournaledArtifactWriter::new(&fixture.store, &fixture.journal, &fixture.clock);
        let reference = writer
            .write(
                reservation(&operation_id, &artifact_id, &format!("{suffix}.txt")),
                b"hello",
            )
            .unwrap();
        let object = fixture.store.root().join(reference.storage_key);
        if corrupt {
            fs::write(&object, b"tampered").unwrap();
        } else {
            fs::remove_file(&object).unwrap();
        }

        reconcile_artifacts(&fixture.store, &fixture.journal, &fixture.clock).unwrap();

        let expected = if corrupt { "quarantined" } else { "missing" };
        assert_eq!(
            fixture.state(&operation_id),
            ("completed".to_owned(), expected.to_owned())
        );
        let evidence = quarantine_evidence(&fixture);
        assert_eq!(
            reconcile_artifacts(&fixture.store, &fixture.journal, &fixture.clock).unwrap(),
            Default::default()
        );
        assert_eq!(
            fixture.state(&operation_id),
            ("completed".to_owned(), expected.to_owned())
        );
        assert_eq!(quarantine_evidence(&fixture), evidence);
    }
}

#[test]
fn logical_metadata_is_separate_from_deduplicated_content() {
    let fixture = Fixture::new();
    let writer = JournaledArtifactWriter::new(&fixture.store, &fixture.journal, &fixture.clock);
    let first = writer
        .write(
            reservation("operation-1", "artifact-1", "first.txt"),
            b"hello",
        )
        .unwrap();
    let second = writer
        .write(
            reservation("operation-2", "artifact-2", "second.txt"),
            b"hello",
        )
        .unwrap();

    assert_eq!(first, second);
    let connection = Connection::open(&fixture.database_path).unwrap();
    assert_eq!(
        connection
            .query_row("SELECT COUNT(*) FROM artifacts", [], |row| row
                .get::<_, i64>(0))
            .unwrap(),
        2
    );
    assert_eq!(
        fs::read_dir(fixture.store.root().join("objects/2c"))
            .unwrap()
            .count(),
        1
    );
}

#[test]
fn staging_bytes_without_an_intent_are_quarantined_not_deleted() {
    let fixture = Fixture::new();
    let orphan = fixture.store.root().join("staging/orphan.tmp");
    fs::write(&orphan, b"unrecognized").unwrap();

    reconcile_artifacts(&fixture.store, &fixture.journal, &fixture.clock).unwrap();

    assert!(!orphan.exists());
    let preserved: Vec<_> = fs::read_dir(fixture.store.root().join("quarantine"))
        .unwrap()
        .map(|entry| fs::read(entry.unwrap().path()).unwrap())
        .collect();
    assert_eq!(preserved, [b"unrecognized".to_vec()]);
    assert_eq!(
        reconcile_artifacts(&fixture.store, &fixture.journal, &fixture.clock).unwrap(),
        Default::default()
    );
    assert_eq!(quarantine_evidence(&fixture), preserved);
}

#[test]
fn artifact_reconciliation_does_not_retry_indeterminate_non_repeatable_operations() {
    let fixture = Fixture::new();
    seed_task(&fixture.database_path);
    let writer = JournaledArtifactWriter::new(&fixture.store, &fixture.journal, &fixture.clock);
    writer
        .write(
            reservation("artifact-operation", "request-artifact", "request.json"),
            b"hello",
        )
        .unwrap();
    let connection = Connection::open(&fixture.database_path).unwrap();
    connection
        .execute(
            "INSERT INTO operation_intents (
                id, task_id, operation_kind, idempotency_class, idempotency_key,
                canonical_request_artifact_id, operation_digest, status, attempt_count,
                created_at, updated_at
             ) VALUES (
                'external-1', 'task-1', 'external', 'non_repeatable', 'external-key',
                'request-artifact', ?1, 'indeterminate', 1, ?2, ?2
             )",
            params![HELLO_HASH, "2026-07-26T00:00:00Z"],
        )
        .unwrap();
    drop(connection);

    reconcile_artifacts(&fixture.store, &fixture.journal, &fixture.clock).unwrap();
    assert_eq!(
        reconcile_artifacts(&fixture.store, &fixture.journal, &fixture.clock).unwrap(),
        Default::default()
    );

    let state: (String, i64) = Connection::open(&fixture.database_path)
        .unwrap()
        .query_row(
            "SELECT status, attempt_count FROM operation_intents WHERE id = 'external-1'",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(state, ("indeterminate".to_owned(), 1));
}

#[test]
fn incomplete_metadata_mismatch_quarantines_staging_once() {
    let fixture = Fixture::new();
    fixture
        .store
        .put(NewArtifact {
            expected_hash: WORLD_HASH.to_owned(),
            expected_size: 5,
            content: b"world".to_vec(),
        })
        .unwrap();
    let writer = JournaledArtifactWriter::new(&fixture.store, &fixture.journal, &fixture.clock);
    assert!(writer
        .write_with_fault(
            reservation("operation-metadata", "artifact-metadata", "metadata.txt"),
            b"hello",
            |point| {
                if point == FaultPoint::AfterWrite {
                    Err(injected_crash())
                } else {
                    Ok(())
                }
            },
        )
        .is_err());
    Connection::open(&fixture.database_path)
        .unwrap()
        .execute(
            "UPDATE artifacts SET content_hash = ?1, storage_key = ?2
             WHERE id = 'artifact-metadata'",
            params![WORLD_HASH, format!("objects/48/{}", &WORLD_HASH[7..])],
        )
        .unwrap();

    let first = reconcile_artifacts(&fixture.store, &fixture.journal, &fixture.clock).unwrap();

    assert_eq!(first.quarantined, 1);
    assert_eq!(
        fixture.state("operation-metadata"),
        ("quarantined".to_owned(), "quarantined".to_owned())
    );
    assert_eq!(
        operation_error_kind(&fixture, "operation-metadata"),
        "intent_metadata_mismatch"
    );
    let evidence = quarantine_evidence(&fixture);
    assert_eq!(evidence, [b"hello".to_vec()]);
    assert_eq!(
        reconcile_artifacts(&fixture.store, &fixture.journal, &fixture.clock).unwrap(),
        Default::default()
    );
    assert_eq!(
        fixture.state("operation-metadata"),
        ("quarantined".to_owned(), "quarantined".to_owned())
    );
    assert_eq!(
        operation_error_kind(&fixture, "operation-metadata"),
        "intent_metadata_mismatch"
    );
    assert_eq!(quarantine_evidence(&fixture), evidence);
}

#[test]
fn completed_metadata_mismatch_quarantines_staging_once() {
    let fixture = Fixture::new();
    fixture
        .store
        .put(NewArtifact {
            expected_hash: WORLD_HASH.to_owned(),
            expected_size: 5,
            content: b"world".to_vec(),
        })
        .unwrap();
    let reservation = reservation(
        "operation-completed-metadata",
        "artifact-completed-metadata",
        "completed-metadata.txt",
    );
    let temp_name = reservation.temp_name.clone();
    JournaledArtifactWriter::new(&fixture.store, &fixture.journal, &fixture.clock)
        .write(reservation, b"hello")
        .unwrap();
    fs::write(
        fixture.store.root().join("staging").join(temp_name),
        b"staged evidence",
    )
    .unwrap();
    Connection::open(&fixture.database_path)
        .unwrap()
        .execute(
            "UPDATE artifacts SET content_hash = ?1, storage_key = ?2
             WHERE id = 'artifact-completed-metadata'",
            params![WORLD_HASH, format!("objects/48/{}", &WORLD_HASH[7..])],
        )
        .unwrap();

    let first = reconcile_artifacts(&fixture.store, &fixture.journal, &fixture.clock).unwrap();

    assert_eq!(first.invalidated, 1);
    assert_eq!(
        fixture.state("operation-completed-metadata"),
        ("completed".to_owned(), "quarantined".to_owned())
    );
    assert_eq!(
        operation_error_kind(&fixture, "operation-completed-metadata"),
        "intent_metadata_mismatch"
    );
    let evidence = quarantine_evidence(&fixture);
    assert_eq!(evidence, [b"staged evidence".to_vec()]);
    assert_eq!(
        reconcile_artifacts(&fixture.store, &fixture.journal, &fixture.clock).unwrap(),
        Default::default()
    );
    assert_eq!(
        fixture.state("operation-completed-metadata"),
        ("completed".to_owned(), "quarantined".to_owned())
    );
    assert_eq!(
        operation_error_kind(&fixture, "operation-completed-metadata"),
        "intent_metadata_mismatch"
    );
    assert_eq!(quarantine_evidence(&fixture), evidence);
}

#[test]
fn post_rename_corruption_is_recorded_as_quarantined_before_restart() {
    let fixture = Fixture::new();
    let reservation = reservation(
        "operation-post-rename",
        "artifact-post-rename",
        "post-rename.txt",
    );
    let target = fixture
        .store
        .root()
        .join(format!("objects/2c/{}", &HELLO_HASH[7..]));
    let result = JournaledArtifactWriter::new(&fixture.store, &fixture.journal, &fixture.clock)
        .write_with_fault(reservation, b"hello", |point| {
            if point == FaultPoint::AfterRename {
                fs::write(&target, b"jello").unwrap();
            }
            Ok(())
        });

    assert!(result.is_err());
    assert_eq!(
        fixture.state("operation-post-rename"),
        ("quarantined".to_owned(), "quarantined".to_owned())
    );
    assert_eq!(
        operation_error_kind(&fixture, "operation-post-rename"),
        "object_invalid_after_rename"
    );
    assert_eq!(quarantine_evidence(&fixture), [b"jello".to_vec()]);

    let restarted = SqliteStore::open(&fixture.database_path).unwrap();
    assert_eq!(
        reconcile_artifacts(&fixture.store, &restarted, &fixture.clock).unwrap(),
        Default::default()
    );
    assert_eq!(
        fixture.state("operation-post-rename"),
        ("quarantined".to_owned(), "quarantined".to_owned())
    );
    assert_eq!(
        operation_error_kind(&fixture, "operation-post-rename"),
        "object_invalid_after_rename"
    );
    assert_eq!(quarantine_evidence(&fixture), [b"jello".to_vec()]);
}

fn quarantine_evidence(fixture: &Fixture) -> Vec<Vec<u8>> {
    let mut evidence: Vec<_> = fs::read_dir(fixture.store.root().join("quarantine"))
        .unwrap()
        .map(|entry| fs::read(entry.unwrap().path()).unwrap())
        .collect();
    evidence.sort();
    evidence
}

fn operation_error_kind(fixture: &Fixture, operation_id: &str) -> String {
    let json: String = Connection::open(&fixture.database_path)
        .unwrap()
        .query_row(
            "SELECT error_json FROM artifact_operations WHERE id = ?1",
            [operation_id],
            |row| row.get(0),
        )
        .unwrap();
    serde_json::from_str::<serde_json::Value>(&json).unwrap()["kind"]
        .as_str()
        .unwrap()
        .to_owned()
}

fn reservation(
    operation_id: &str,
    artifact_id: &str,
    logical_path: &str,
) -> ArtifactWriteReservation {
    ArtifactWriteReservation {
        operation_id: operation_id.to_owned(),
        artifact: ReservedArtifact {
            artifact_id: artifact_id.to_owned(),
            task_id: None,
            project_id: "project-1".to_owned(),
            artifact_type: "test".to_owned(),
            logical_path: logical_path.to_owned(),
            content_hash: HELLO_HASH.to_owned(),
            storage_key: format!("objects/2c/{}", &HELLO_HASH[7..]),
            size_bytes: 5,
            mime_type: Some("text/plain".to_owned()),
            created_by_type: "core".to_owned(),
            created_by_id: "core".to_owned(),
            created_at: "2026-07-26T00:00:00Z".to_owned(),
            supersedes: None,
        },
        temp_name: format!("{operation_id}.tmp"),
        created_at: "2026-07-26T00:00:00Z".to_owned(),
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

fn seed_task(path: &Path) {
    Connection::open(path)
        .unwrap()
        .execute(
            "INSERT INTO tasks (
                id, project_id, title, objective, phase, condition, operation_state,
                risk_level, base_branch, base_commit, created_at, updated_at
             ) VALUES (
                'task-1', 'project-1', 'Task', 'Objective', 'Intake', 'Active', 'None',
                'low', 'main', ?1, ?2, ?2
             )",
            params![
                "0000000000000000000000000000000000000000",
                "2026-07-26T00:00:00Z"
            ],
        )
        .unwrap();
}

fn injected_crash() -> PortError {
    PortError::failure(
        SafeErrorClassification::Internal,
        Retryability::NonRetryable,
    )
}
