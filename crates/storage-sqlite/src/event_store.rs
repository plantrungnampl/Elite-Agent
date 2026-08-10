use local_agent_terminal_application::{
    AppendOperation, AppendResult, EventStore, PortError, ProjectionChange, Retryability,
    SafeErrorClassification,
};
use local_agent_terminal_domain::Sequence;
use rusqlite::{params, OptionalExtension, TransactionBehavior};

use crate::{OpenError, SqliteStore};

impl EventStore for SqliteStore {
    fn append(&self, operation: AppendOperation) -> Result<AppendResult, PortError> {
        let mut connection = self.connection().map_err(open_error_to_port)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite_error_to_port)?;
        let result = append_in_transaction(&transaction, &operation)?;
        transaction.commit().map_err(sqlite_error_to_port)?;
        Ok(result)
    }
}

pub(crate) fn append_in_transaction(
    transaction: &rusqlite::Transaction<'_>,
    operation: &AppendOperation,
) -> Result<AppendResult, PortError> {
    let actual: Option<i64> = transaction
        .query_row(
            "SELECT current_sequence FROM tasks WHERE id = ?1",
            [operation.stream_id.as_str()],
            |row| row.get(0),
        )
        .optional()
        .map_err(sqlite_error_to_port)?;
    let actual = actual.ok_or_else(|| {
        PortError::failure(
            SafeErrorClassification::NotFound,
            Retryability::NonRetryable,
        )
    })?;
    let actual = Sequence::try_from(actual).map_err(|_| invalid_input())?;
    if actual != operation.expected_version {
        return Err(PortError::version_conflict(
            operation.expected_version,
            actual,
        ));
    }

    let first_sequence = operation
        .expected_version
        .get()
        .checked_add(1)
        .ok_or_else(invalid_input)?;
    for (offset, event) in operation.events.iter().enumerate() {
        let sequence = first_sequence
            .checked_add(u64::try_from(offset).map_err(|_| invalid_input())?)
            .and_then(|value| i64::try_from(value).ok())
            .ok_or_else(invalid_input)?;
        transaction
            .execute(
                "INSERT INTO events (
                        event_id, stream_id, sequence, event_type, schema_version, actor_type,
                        actor_id, observation_class, payload_json, metadata_json, causation_id,
                        correlation_id, created_at
                     ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
                params![
                    event.event_id.as_str(),
                    operation.stream_id.as_str(),
                    sequence,
                    event.event_type.as_str(),
                    event.schema_version,
                    event.actor_type,
                    event.actor_id.as_str(),
                    event.observation_class,
                    event.payload.to_string(),
                    event.metadata.to_string(),
                    event.causation_id,
                    event.correlation_id,
                    event.created_at,
                ],
            )
            .map_err(sqlite_error_to_port)?;
    }

    let new_version = operation
        .expected_version
        .get()
        .checked_add(u64::try_from(operation.events.len()).map_err(|_| invalid_input())?)
        .ok_or_else(invalid_input)?;
    let new_version_i64 = i64::try_from(new_version).map_err(|_| invalid_input())?;
    let advanced = transaction
        .execute(
            "UPDATE tasks SET current_sequence = ?1
                 WHERE id = ?2 AND current_sequence = ?3",
            params![
                new_version_i64,
                operation.stream_id.as_str(),
                i64::try_from(operation.expected_version.get()).map_err(|_| invalid_input())?
            ],
        )
        .map_err(sqlite_error_to_port)?;
    if advanced != 1 {
        return Err(PortError::version_conflict(
            operation.expected_version,
            actual,
        ));
    }
    for change in &operation.projection_changes {
        let ProjectionChange::TaskState {
            task_id,
            state,
            updated_at,
        } = change;
        let current_fencing_epoch: i64 = transaction
            .query_row(
                "SELECT fencing_epoch FROM tasks WHERE id = ?1",
                [task_id.as_str()],
                |row| row.get(0),
            )
            .map_err(sqlite_error_to_port)?;
        let next_fencing_epoch =
            i64::try_from(state.fencing_token().get()).map_err(|_| invalid_input())?;
        let changed = if current_fencing_epoch == next_fencing_epoch {
            transaction.execute(
                "UPDATE tasks SET
                        phase = ?1, condition = ?2, operation_state = ?3,
                        workspace_version = ?4, updated_at = ?5
                     WHERE id = ?6",
                params![
                    state.phase().as_str(),
                    state.condition().as_str(),
                    state.operation().as_str(),
                    i64::try_from(state.workspace_version().get()).map_err(|_| invalid_input())?,
                    updated_at,
                    task_id.as_str(),
                ],
            )
        } else {
            transaction.execute(
                "UPDATE tasks SET
                        phase = ?1, condition = ?2, operation_state = ?3,
                        workspace_version = ?4, fencing_epoch = ?5, updated_at = ?6
                     WHERE id = ?7",
                params![
                    state.phase().as_str(),
                    state.condition().as_str(),
                    state.operation().as_str(),
                    i64::try_from(state.workspace_version().get()).map_err(|_| invalid_input())?,
                    next_fencing_epoch,
                    updated_at,
                    task_id.as_str(),
                ],
            )
        }
        .map_err(sqlite_error_to_port)?;
        if changed != 1 {
            return Err(PortError::failure(
                SafeErrorClassification::NotFound,
                Retryability::NonRetryable,
            ));
        }
    }
    Ok(AppendResult {
        new_version: Sequence::new(new_version),
    })
}

pub(crate) fn open_error_to_port(error: OpenError) -> PortError {
    match error {
        OpenError::Database(error) => sqlite_error_to_port(error),
        OpenError::ChecksumMismatch { .. }
        | OpenError::UnsupportedSchema { .. }
        | OpenError::ForeignKeyViolation { .. } => PortError::failure(
            SafeErrorClassification::IntegrityFailure,
            Retryability::NonRetryable,
        ),
    }
}

pub(crate) fn sqlite_error_to_port(error: rusqlite::Error) -> PortError {
    use rusqlite::ffi::ErrorCode;

    let (classification, retryability) = match error.sqlite_error_code() {
        Some(ErrorCode::DatabaseBusy | ErrorCode::DatabaseLocked) => (
            SafeErrorClassification::Unavailable,
            Retryability::Retryable,
        ),
        Some(ErrorCode::DiskFull) => (
            SafeErrorClassification::StorageFull,
            Retryability::NonRetryable,
        ),
        Some(ErrorCode::ConstraintViolation) => (
            SafeErrorClassification::InvalidInput,
            Retryability::NonRetryable,
        ),
        _ => (
            SafeErrorClassification::Internal,
            Retryability::NonRetryable,
        ),
    };
    PortError::failure(classification, retryability)
}

fn invalid_input() -> PortError {
    PortError::failure(
        SafeErrorClassification::InvalidInput,
        Retryability::NonRetryable,
    )
}
