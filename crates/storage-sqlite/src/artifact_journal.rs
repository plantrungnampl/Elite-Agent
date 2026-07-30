use local_agent_terminal_application::{
    ArtifactJournal, ArtifactJournalEntry, ArtifactJournalInvalidation, ArtifactJournalStatus,
    ArtifactJournalTransition, ArtifactUnavailableState, ArtifactWriteReservation, PortError,
    Retryability, SafeErrorClassification,
};
use local_agent_terminal_domain::TaskId;
use rusqlite::{params, TransactionBehavior};

use crate::event_store::{open_error_to_port, sqlite_error_to_port};
use crate::SqliteStore;

impl ArtifactJournal for SqliteStore {
    fn reserve(&self, reservation: ArtifactWriteReservation) -> Result<(), PortError> {
        let mut connection = self.connection().map_err(open_error_to_port)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite_error_to_port)?;
        let artifact = &reservation.artifact;
        let task_id = artifact.task_id.as_ref().map(TaskId::as_str);
        let size = i64::try_from(artifact.size_bytes).map_err(|_| invalid_input())?;
        transaction
            .execute(
                "INSERT INTO artifacts (
                    id, task_id, project_id, artifact_type, logical_path, content_hash,
                    storage_key, size_bytes, mime_type, availability, created_by_type,
                    created_by_id, created_at, supersedes, verification_state
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, 'reserved', ?10, ?11, ?12, ?13, 'unverified')",
                params![
                    artifact.artifact_id,
                    task_id,
                    artifact.project_id,
                    artifact.artifact_type,
                    artifact.logical_path,
                    artifact.content_hash,
                    artifact.storage_key,
                    size,
                    artifact.mime_type,
                    artifact.created_by_type,
                    artifact.created_by_id,
                    artifact.created_at,
                    artifact.supersedes,
                ],
            )
            .map_err(sqlite_error_to_port)?;
        transaction
            .execute(
                "INSERT INTO artifact_operations (
                    id, artifact_id, temp_name, expected_hash, expected_size, status,
                    created_at, updated_at, completed_at, error_json
                 ) VALUES (?1, ?2, ?3, ?4, ?5, 'intent', ?6, ?6, NULL, NULL)",
                params![
                    reservation.operation_id,
                    artifact.artifact_id,
                    reservation.temp_name,
                    artifact.content_hash,
                    size,
                    reservation.created_at,
                ],
            )
            .map_err(sqlite_error_to_port)?;
        transaction.commit().map_err(sqlite_error_to_port)
    }

    fn transition(&self, transition: ArtifactJournalTransition) -> Result<(), PortError> {
        if !allowed_transition(transition.expected_status, transition.next_status) {
            return Err(invalid_input());
        }
        if transition.next_status == ArtifactJournalStatus::Completed
            && transition.completed_at.is_none()
        {
            return Err(invalid_input());
        }

        let mut connection = self.connection().map_err(open_error_to_port)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite_error_to_port)?;
        let error_json = transition.error.as_ref().map(ToString::to_string);
        let changed = transaction
            .execute(
                "UPDATE artifact_operations SET
                    status = ?1, updated_at = ?2, completed_at = ?3, error_json = ?4
                 WHERE id = ?5 AND status = ?6",
                params![
                    status_name(transition.next_status),
                    transition.updated_at,
                    transition.completed_at,
                    error_json,
                    transition.operation_id,
                    status_name(transition.expected_status),
                ],
            )
            .map_err(sqlite_error_to_port)?;
        if changed != 1 {
            return Err(PortError::failure(
                SafeErrorClassification::Conflict,
                Retryability::NonRetryable,
            ));
        }

        if let Some(availability) = terminal_availability(transition.next_status) {
            let changed = transaction
                .execute(
                    "UPDATE artifacts
                     SET availability = ?1,
                         verification_state = CASE
                             WHEN ?1 = 'available' AND verification_state = 'unverified'
                                 THEN 'hash_verified'
                             ELSE verification_state
                         END
                     WHERE id = (
                        SELECT artifact_id FROM artifact_operations WHERE id = ?2
                     )",
                    params![availability, transition.operation_id],
                )
                .map_err(sqlite_error_to_port)?;
            if changed != 1 {
                return Err(PortError::failure(
                    SafeErrorClassification::IntegrityFailure,
                    Retryability::NonRetryable,
                ));
            }
        }

        transaction.commit().map_err(sqlite_error_to_port)
    }

    fn incomplete(&self) -> Result<Vec<ArtifactJournalEntry>, PortError> {
        self.journal_entries(false)
    }

    fn completed(&self) -> Result<Vec<ArtifactJournalEntry>, PortError> {
        self.journal_entries(true)
    }

    fn invalidate_completed(
        &self,
        invalidation: ArtifactJournalInvalidation,
    ) -> Result<(), PortError> {
        let mut connection = self.connection().map_err(open_error_to_port)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite_error_to_port)?;
        let error_json = invalidation.error.to_string();
        let changed = transaction
            .execute(
                "UPDATE artifact_operations SET updated_at = ?1, error_json = ?2
                 WHERE id = ?3 AND status = 'completed'",
                params![
                    invalidation.updated_at,
                    error_json,
                    invalidation.operation_id
                ],
            )
            .map_err(sqlite_error_to_port)?;
        if changed != 1 {
            return Err(conflict());
        }
        let changed = transaction
            .execute(
                "UPDATE artifacts SET availability = ?1
                 WHERE availability = 'available' AND id = (
                    SELECT artifact_id FROM artifact_operations WHERE id = ?2
                 )",
                params![
                    unavailable_name(invalidation.unavailable_state),
                    invalidation.operation_id
                ],
            )
            .map_err(sqlite_error_to_port)?;
        if changed != 1 {
            return Err(conflict());
        }
        transaction.commit().map_err(sqlite_error_to_port)
    }
}

impl SqliteStore {
    fn journal_entries(&self, completed: bool) -> Result<Vec<ArtifactJournalEntry>, PortError> {
        let connection = self.connection().map_err(open_error_to_port)?;
        let mut statement = connection
            .prepare(
                "SELECT
                    o.id, a.id, a.task_id, a.project_id, a.artifact_type, a.logical_path,
                    a.content_hash, a.storage_key, a.size_bytes, a.mime_type, a.created_by_type,
                    a.created_by_id, a.created_at, a.supersedes, o.temp_name, o.created_at,
                    o.expected_hash, o.expected_size, o.status, o.updated_at, o.completed_at,
                    o.error_json
                 FROM artifact_operations o
                 JOIN artifacts a ON a.id = o.artifact_id
                 WHERE (?1 AND o.status = 'completed' AND a.availability = 'available')
                    OR (NOT ?1 AND o.status IN ('intent', 'staging', 'renamed'))
                 ORDER BY o.created_at, o.id",
            )
            .map_err(sqlite_error_to_port)?;
        let rows = statement
            .query_map([completed], |row| {
                Ok(RawJournalEntry {
                    operation_id: row.get(0)?,
                    artifact_id: row.get(1)?,
                    task_id: row.get(2)?,
                    project_id: row.get(3)?,
                    artifact_type: row.get(4)?,
                    logical_path: row.get(5)?,
                    content_hash: row.get(6)?,
                    storage_key: row.get(7)?,
                    size_bytes: row.get(8)?,
                    mime_type: row.get(9)?,
                    created_by_type: row.get(10)?,
                    created_by_id: row.get(11)?,
                    artifact_created_at: row.get(12)?,
                    supersedes: row.get(13)?,
                    temp_name: row.get(14)?,
                    operation_created_at: row.get(15)?,
                    expected_hash: row.get(16)?,
                    expected_size: row.get(17)?,
                    status: row.get(18)?,
                    updated_at: row.get(19)?,
                    completed_at: row.get(20)?,
                    error_json: row.get(21)?,
                })
            })
            .map_err(sqlite_error_to_port)?;

        rows.map(|row| {
            row.map_err(sqlite_error_to_port)
                .and_then(TryInto::try_into)
        })
        .collect()
    }
}

struct RawJournalEntry {
    operation_id: String,
    artifact_id: String,
    task_id: Option<String>,
    project_id: String,
    artifact_type: String,
    logical_path: String,
    content_hash: String,
    storage_key: String,
    size_bytes: i64,
    mime_type: Option<String>,
    created_by_type: String,
    created_by_id: String,
    artifact_created_at: String,
    supersedes: Option<String>,
    temp_name: String,
    operation_created_at: String,
    expected_hash: String,
    expected_size: i64,
    status: String,
    updated_at: String,
    completed_at: Option<String>,
    error_json: Option<String>,
}

impl TryFrom<RawJournalEntry> for ArtifactJournalEntry {
    type Error = PortError;

    fn try_from(row: RawJournalEntry) -> Result<Self, Self::Error> {
        let task_id = row
            .task_id
            .map(TaskId::new)
            .transpose()
            .map_err(|_| integrity_failure())?;
        let size_bytes = u64::try_from(row.size_bytes).map_err(|_| integrity_failure())?;
        let expected_size = u64::try_from(row.expected_size).map_err(|_| integrity_failure())?;
        let status = parse_status(&row.status).ok_or_else(integrity_failure)?;
        let error = row
            .error_json
            .map(|json| serde_json::from_str(&json).map_err(|_| integrity_failure()))
            .transpose()?;
        Ok(Self {
            reservation: ArtifactWriteReservation {
                operation_id: row.operation_id,
                artifact: local_agent_terminal_application::ReservedArtifact {
                    artifact_id: row.artifact_id,
                    task_id,
                    project_id: row.project_id,
                    artifact_type: row.artifact_type,
                    logical_path: row.logical_path,
                    content_hash: row.content_hash,
                    storage_key: row.storage_key,
                    size_bytes,
                    mime_type: row.mime_type,
                    created_by_type: row.created_by_type,
                    created_by_id: row.created_by_id,
                    created_at: row.artifact_created_at,
                    supersedes: row.supersedes,
                },
                temp_name: row.temp_name,
                created_at: row.operation_created_at,
            },
            expected_hash: row.expected_hash,
            expected_size,
            status,
            updated_at: row.updated_at,
            completed_at: row.completed_at,
            error,
        })
    }
}

fn allowed_transition(from: ArtifactJournalStatus, to: ArtifactJournalStatus) -> bool {
    matches!(
        (from, to),
        (
            ArtifactJournalStatus::Intent,
            ArtifactJournalStatus::Staging
                | ArtifactJournalStatus::Aborted
                | ArtifactJournalStatus::Quarantined
        ) | (
            ArtifactJournalStatus::Staging,
            ArtifactJournalStatus::Renamed
                | ArtifactJournalStatus::Aborted
                | ArtifactJournalStatus::Quarantined
        ) | (
            ArtifactJournalStatus::Renamed,
            ArtifactJournalStatus::Completed | ArtifactJournalStatus::Quarantined
        )
    )
}

fn status_name(status: ArtifactJournalStatus) -> &'static str {
    match status {
        ArtifactJournalStatus::Intent => "intent",
        ArtifactJournalStatus::Staging => "staging",
        ArtifactJournalStatus::Renamed => "renamed",
        ArtifactJournalStatus::Completed => "completed",
        ArtifactJournalStatus::Aborted => "aborted",
        ArtifactJournalStatus::Quarantined => "quarantined",
    }
}

fn parse_status(status: &str) -> Option<ArtifactJournalStatus> {
    match status {
        "intent" => Some(ArtifactJournalStatus::Intent),
        "staging" => Some(ArtifactJournalStatus::Staging),
        "renamed" => Some(ArtifactJournalStatus::Renamed),
        "completed" => Some(ArtifactJournalStatus::Completed),
        "aborted" => Some(ArtifactJournalStatus::Aborted),
        "quarantined" => Some(ArtifactJournalStatus::Quarantined),
        _ => None,
    }
}

fn terminal_availability(status: ArtifactJournalStatus) -> Option<&'static str> {
    match status {
        ArtifactJournalStatus::Completed => Some("available"),
        ArtifactJournalStatus::Aborted => Some("missing"),
        ArtifactJournalStatus::Quarantined => Some("quarantined"),
        ArtifactJournalStatus::Intent
        | ArtifactJournalStatus::Staging
        | ArtifactJournalStatus::Renamed => None,
    }
}

fn invalid_input() -> PortError {
    PortError::failure(
        SafeErrorClassification::InvalidInput,
        Retryability::NonRetryable,
    )
}

fn integrity_failure() -> PortError {
    PortError::failure(
        SafeErrorClassification::IntegrityFailure,
        Retryability::NonRetryable,
    )
}

fn conflict() -> PortError {
    PortError::failure(
        SafeErrorClassification::Conflict,
        Retryability::NonRetryable,
    )
}

fn unavailable_name(state: ArtifactUnavailableState) -> &'static str {
    match state {
        ArtifactUnavailableState::Missing => "missing",
        ArtifactUnavailableState::Quarantined => "quarantined",
    }
}
