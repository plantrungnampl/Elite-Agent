use std::sync::Mutex;

use local_agent_terminal_application::{
    AppendEvents, AppendEventsError, AppendOperation, AppendResult, ArtifactContent,
    ArtifactJournal, ArtifactJournalEntry, ArtifactJournalTransition, ArtifactRef, ArtifactStore,
    Clock, EventStore, IdGenerator, LocalDiagnosticDto, NewArtifact, NewEvent, PortError,
    ProjectionChange, RecoveryActionDto, Retryability, SafeErrorClassification, StartupIssueDto,
    StartupStateDto, StartupStatusDto,
};
use local_agent_terminal_domain::{
    ActorId, EventId, FencingToken, OperationState, Phase, Sequence, StreamId, TaskId,
    WorkflowEvent, WorkflowState, WorkspaceVersion,
};
use serde_json::json;

#[derive(Debug)]
struct RecordingEventStore {
    calls: Mutex<Vec<AppendOperation>>,
    result: Mutex<Option<Result<AppendResult, PortError>>>,
}

impl RecordingEventStore {
    fn returning(result: Result<AppendResult, PortError>) -> Self {
        Self {
            calls: Mutex::new(Vec::new()),
            result: Mutex::new(Some(result)),
        }
    }

    fn calls(&self) -> Vec<AppendOperation> {
        self.calls.lock().expect("calls lock").clone()
    }
}

impl EventStore for RecordingEventStore {
    fn append(&self, operation: AppendOperation) -> Result<AppendResult, PortError> {
        self.calls.lock().expect("calls lock").push(operation);
        self.result
            .lock()
            .expect("result lock")
            .take()
            .expect("one configured result")
    }
}

fn sample_operation(expected_version: Sequence) -> AppendOperation {
    let state = WorkflowState::new(
        Phase::Intake,
        local_agent_terminal_domain::Condition::Active,
        OperationState::None,
        Sequence::new(expected_version.get() + 1),
        WorkspaceVersion::new(0),
        FencingToken::new(1).unwrap(),
    )
    .unwrap();

    AppendOperation {
        stream_id: StreamId::new("task-1").unwrap(),
        expected_version,
        events: vec![NewEvent {
            event_id: EventId::new("event-1").unwrap(),
            event_type: WorkflowEvent::new("task.created").unwrap(),
            schema_version: 1,
            actor_type: "core".to_owned(),
            actor_id: ActorId::new("core").unwrap(),
            observation_class: "core_observed".to_owned(),
            payload: json!({"title": "First task"}),
            metadata: json!({}),
            causation_id: None,
            correlation_id: "correlation-1".to_owned(),
            created_at: "2026-07-24T12:00:00Z".to_owned(),
        }],
        projection_changes: vec![ProjectionChange::TaskState {
            task_id: TaskId::new("task-1").unwrap(),
            state,
            updated_at: "2026-07-24T12:00:00Z".to_owned(),
        }],
    }
}

#[test]
fn expected_stream_version_is_passed_to_the_event_store_unchanged() {
    let expected_version = Sequence::new(41);
    let store = RecordingEventStore::returning(Ok(AppendResult {
        new_version: Sequence::new(42),
    }));

    AppendEvents::new(&store)
        .execute(sample_operation(expected_version))
        .unwrap();

    assert_eq!(store.calls()[0].expected_version, expected_version);
}

#[test]
fn events_and_projection_changes_are_submitted_as_one_store_operation() {
    let operation = sample_operation(Sequence::new(0));
    let expected_events = operation.events.clone();
    let expected_projection_changes = operation.projection_changes.clone();
    let store = RecordingEventStore::returning(Ok(AppendResult {
        new_version: Sequence::new(1),
    }));

    AppendEvents::new(&store).execute(operation).unwrap();

    let calls = store.calls();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].events, expected_events);
    assert_eq!(calls[0].projection_changes, expected_projection_changes);
}

#[test]
fn version_conflict_is_typed_non_retryable_and_safe_to_show() {
    let expected = Sequence::new(4);
    let actual = Sequence::new(5);
    let store = RecordingEventStore::returning(Err(PortError::version_conflict(expected, actual)));

    let error = AppendEvents::new(&store)
        .execute(sample_operation(expected))
        .unwrap_err();

    assert_eq!(
        error,
        AppendEventsError::VersionConflict { expected, actual }
    );
    assert_eq!(error.retryability(), Retryability::NonRetryable);
    assert_eq!(
        error.safe_classification(),
        SafeErrorClassification::Conflict
    );
}

#[test]
fn every_port_error_has_explicit_retryability_and_safe_classification() {
    let expected = Sequence::new(1);
    let actual = Sequence::new(2);
    let cases = [
        (
            PortError::version_conflict(expected, actual),
            Retryability::NonRetryable,
            SafeErrorClassification::Conflict,
        ),
        (
            PortError::failure(
                SafeErrorClassification::Unavailable,
                Retryability::Retryable,
            ),
            Retryability::Retryable,
            SafeErrorClassification::Unavailable,
        ),
        (
            PortError::failure(
                SafeErrorClassification::IntegrityFailure,
                Retryability::NonRetryable,
            ),
            Retryability::NonRetryable,
            SafeErrorClassification::IntegrityFailure,
        ),
    ];

    for (error, retryability, classification) in cases {
        assert_eq!(error.retryability(), retryability);
        assert_eq!(error.safe_classification(), classification);
    }
}

#[test]
fn startup_dtos_separate_safe_status_from_local_diagnostics() {
    let status = StartupStatusDto {
        state: StartupStateDto::RecoverableFailure,
        issues: vec![StartupIssueDto {
            code: "artifact_root_unavailable".to_owned(),
            message: "The artifact store is unavailable.".to_owned(),
            recovery_actions: vec![RecoveryActionDto {
                code: "retry_startup_validation".to_owned(),
                label: "Retry validation".to_owned(),
            }],
        }],
    };
    let diagnostic = LocalDiagnosticDto {
        code: "artifact_root_unavailable".to_owned(),
        detail: "Access denied while opening the configured artifact root.".to_owned(),
    };

    assert_eq!(status.state, StartupStateDto::RecoverableFailure);
    assert_eq!(status.issues[0].code, diagnostic.code);
    assert_ne!(status.issues[0].message, diagnostic.detail);
}

#[test]
fn public_application_api_does_not_name_concrete_adapters() {
    let root = env!("CARGO_MANIFEST_DIR");
    let source = [
        "src/lib.rs",
        "src/append_events.rs",
        "src/dto.rs",
        "src/error.rs",
        "src/ports.rs",
    ]
    .into_iter()
    .map(|path| std::fs::read_to_string(format!("{root}/{path}")).unwrap())
    .collect::<String>();

    for forbidden in [
        "rusqlite",
        "SqliteEventStore",
        "FilesystemArtifactStore",
        "storage_sqlite",
        "storage_files",
        "tauri::",
        "tokio::",
    ] {
        assert!(
            !source.contains(forbidden),
            "public application source names concrete adapter/runtime {forbidden}"
        );
    }
}

#[allow(dead_code)]
fn event_store_contract_is_object_safe(event_store: &dyn EventStore) {
    let _: Result<AppendResult, PortError> = event_store.append(sample_operation(Sequence::new(0)));
}

#[allow(dead_code)]
fn artifact_port_contracts_are_object_safe(
    artifact_store: &dyn ArtifactStore,
    artifact_journal: &dyn ArtifactJournal,
    artifact: NewArtifact,
    reference: &ArtifactRef,
    journal_entry: ArtifactJournalEntry,
    transition: ArtifactJournalTransition,
) {
    let _: Result<ArtifactRef, PortError> = artifact_store.put(artifact);
    let _: Result<ArtifactContent, PortError> = artifact_store.read(reference);
    let _: Result<(), PortError> = artifact_journal.record_intent(journal_entry);
    let _: Result<(), PortError> = artifact_journal.transition(transition);
    let _: Result<Vec<ArtifactJournalEntry>, PortError> = artifact_journal.incomplete();
}

#[allow(dead_code)]
fn utility_port_contracts_are_object_safe(clock: &dyn Clock, id_generator: &dyn IdGenerator) {
    let _: Result<String, PortError> = clock.now_utc();
    let _: Result<String, PortError> = id_generator.next_id();
}
