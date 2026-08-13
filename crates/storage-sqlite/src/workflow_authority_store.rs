use std::path::Path;

use local_agent_terminal_application::{
    prepare_workflow_transition, ArtifactRef, ArtifactRootReader, PortError,
    PreparedWorkflowTransition, SafeErrorClassification, WorkflowAuthorityStore,
};
use local_agent_terminal_domain::{ArtifactId, Sha256Digest, TaskId};
use rusqlite::{params, Connection, OptionalExtension, Transaction, TransactionBehavior};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::deliberation_store::load_workflow_state;
use crate::event_store::{open_error_to_port, sqlite_error_to_port};
use crate::SqliteStore;

impl WorkflowAuthorityStore for SqliteStore {
    fn load_workflow(
        &self,
        task_id: &TaskId,
    ) -> Result<local_agent_terminal_domain::WorkflowState, PortError> {
        let connection = self.connection().map_err(open_error_to_port)?;
        load_workflow_state(&connection, task_id)
    }

    fn persist_transition(
        &self,
        command: &PreparedWorkflowTransition,
    ) -> Result<local_agent_terminal_domain::WorkflowState, PortError> {
        validate_prepared_command(command)?;

        // Artifact publication is deliberately an earlier journal operation. This
        // command path only accepts an already available, hash-verified artifact and
        // rechecks its identity inside the same immediate transaction as authority.
        let mut connection = self.connection().map_err(open_error_to_port)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite_error_to_port)?;

        validate_current_authority(&transaction, command)?;
        let artifact_reader = configured_artifact_reader(self)?;
        validate_command_artifact(&transaction, artifact_reader, command)?;
        for guard in &command.guards {
            if let Some(artifact_id) = &guard.artifact_id {
                validate_bound_artifact(
                    &transaction,
                    artifact_reader,
                    artifact_id,
                    &command.task_id,
                    &command.command_artifact.project_id,
                )?;
            }
        }
        for effect in &command.effects {
            if let Some(artifact_id) = &effect.artifact_id {
                validate_bound_artifact(
                    &transaction,
                    artifact_reader,
                    artifact_id,
                    &command.task_id,
                    &command.command_artifact.project_id,
                )?;
            }
        }

        let prepared_at = command_prepared_at(command)?;
        let guard_set_digest = set_digest(&guard_values(command))?;
        let effect_set_digest = set_digest(&effect_values(command))?;
        insert_prepared_event(
            &transaction,
            command,
            &prepared_at,
            &guard_set_digest,
            &effect_set_digest,
        )?;
        insert_guard_bindings(&transaction, command)?;
        insert_effect_bindings(&transaction, command)?;

        let accepted_at = authority_timestamp(&transaction, &command.task_id)?;
        let accepted = transaction
            .execute(
                "UPDATE workflow_transition_events
                 SET status = 'accepted', accepted_at = ?1
                 WHERE id = ?2 AND status = 'prepared'",
                params![accepted_at, command.transition_event_id.as_str()],
            )
            .map_err(authority_sql_error)?;
        if accepted != 1 {
            return Err(conflict());
        }

        update_authority_projection(&transaction, command, &accepted_at)?;
        update_task_projection(&transaction, command, &accepted_at)?;

        transaction.commit().map_err(authority_sql_error)?;
        Ok(command.to_state.clone())
    }
}

fn validate_prepared_command(command: &PreparedWorkflowTransition) -> Result<(), PortError> {
    if command.from_state.stream_version() != command.expected_stream_version
        || command.to_state.stream_version()
            != command
                .expected_stream_version
                .checked_add(1)
                .ok_or_else(invalid_input)?
        || command.from_state.workflow_profile() != command.to_state.workflow_profile()
        || command.from_state.outcome_mode() != command.to_state.outcome_mode()
        || command.from_state.profile_revision() != command.to_state.profile_revision()
        || command.to_state.last_transition_event_id() != Some(command.transition_event_id.as_str())
        || command.command_artifact.task_id.as_ref() != Some(&command.task_id)
        || command.command_artifact.artifact_type != "workflow_transition_command"
    {
        return Err(conflict());
    }

    let rebuilt = prepare_workflow_transition(
        &command.from_state,
        command.input(),
        command.command_artifact.project_id.clone(),
        command.command_artifact.artifact_id.clone(),
    )
    .map_err(|_| conflict())?;
    if rebuilt.command_digest != command.command_digest
        || rebuilt.command_artifact != command.command_artifact
        || rebuilt.to_state != command.to_state
    {
        return Err(integrity_failure());
    }
    Ok(())
}

fn validate_current_authority(
    connection: &Connection,
    command: &PreparedWorkflowTransition,
) -> Result<(), PortError> {
    let row: Option<CurrentAuthority> = connection
        .query_row(
            "SELECT t.project_id, a.phase, a.workflow_profile, a.outcome_mode,
                    t.phase, t.condition, t.operation_state, t.workspace_version,
                    t.fencing_epoch, a.stream_version, a.profile_revision
             FROM tasks t
             JOIN task_workflow_authority a ON a.task_id = t.id
             WHERE t.id = ?1",
            [command.task_id.as_str()],
            |row| {
                Ok(CurrentAuthority {
                    project_id: row.get(0)?,
                    phase: row.get(1)?,
                    workflow_profile: row.get(2)?,
                    outcome_mode: row.get(3)?,
                    task_phase: row.get(4)?,
                    task_condition: row.get(5)?,
                    task_operation: row.get(6)?,
                    task_workspace_version: row.get(7)?,
                    task_fencing_epoch: row.get(8)?,
                    stream_version: row.get(9)?,
                    profile_revision: row.get(10)?,
                })
            },
        )
        .optional()
        .map_err(sqlite_error_to_port)?;
    let Some(current) = row else {
        let task_exists: bool = connection
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM tasks WHERE id = ?1)",
                [command.task_id.as_str()],
                |row| row.get(0),
            )
            .map_err(sqlite_error_to_port)?;
        return Err(if task_exists {
            integrity_failure()
        } else {
            not_found()
        });
    };
    if current.project_id != command.command_artifact.project_id.as_str()
        || current.phase != command.from_state.phase().as_str()
        || current.task_phase != command.from_state.phase().as_str()
        || current.task_condition != command.from_state.condition().as_str()
        || current.task_operation != command.from_state.operation().as_str()
        || current.task_workspace_version
            != i64::try_from(command.from_state.workspace_version().get())
                .map_err(|_| invalid_input())?
        || current.task_fencing_epoch
            != i64::try_from(command.from_state.fencing_token().get())
                .map_err(|_| invalid_input())?
        || current.workflow_profile != command.from_state.workflow_profile().as_str()
        || current.outcome_mode != command.from_state.outcome_mode().as_str()
        || current.stream_version
            != i64::try_from(command.expected_stream_version).map_err(|_| invalid_input())?
        || current.profile_revision
            != i64::try_from(command.from_state.profile_revision()).map_err(|_| invalid_input())?
    {
        return Err(conflict());
    }
    Ok(())
}

fn validate_command_artifact(
    connection: &Connection,
    reader: &dyn ArtifactRootReader,
    command: &PreparedWorkflowTransition,
) -> Result<(), PortError> {
    let value: Value = serde_json::from_slice(&command.command_artifact.canonical_bytes)
        .map_err(|_| integrity_failure())?;
    let object = value.as_object().ok_or_else(integrity_failure)?;
    let stored_digest = object
        .get("commandDigest")
        .and_then(Value::as_str)
        .ok_or_else(integrity_failure)?;
    if stored_digest != command.command_digest.as_str() {
        return Err(integrity_failure());
    }
    let mut without_digest = value.clone();
    without_digest
        .as_object_mut()
        .ok_or_else(integrity_failure)?
        .remove("commandDigest");
    let command_digest = digest_value(&without_digest)?;
    if command_digest != command.command_digest {
        return Err(integrity_failure());
    }
    let final_digest = digest_bytes(&command.command_artifact.canonical_bytes)?;
    if final_digest.as_str() != command.command_artifact.expected_hash
        || command.command_artifact.expected_size
            != u64::try_from(command.command_artifact.canonical_bytes.len())
                .map_err(|_| integrity_failure())?
    {
        return Err(integrity_failure());
    }

    let metadata: Option<ArtifactMetadata> = connection
        .query_row(
            "SELECT a.task_id, a.project_id, a.artifact_type, a.logical_path,
                    a.content_hash, a.storage_key, a.size_bytes, a.availability,
                    a.verification_state, a.created_by_type, a.created_by_id,
                    p.artifact_root_path
             FROM artifacts a
             JOIN projects p ON p.id = a.project_id
             WHERE a.id = ?1",
            [command.command_artifact.artifact_id.as_str()],
            |row| {
                Ok(ArtifactMetadata {
                    task_id: row.get(0)?,
                    project_id: row.get(1)?,
                    artifact_type: row.get(2)?,
                    logical_path: row.get(3)?,
                    content_hash: row.get(4)?,
                    storage_key: row.get(5)?,
                    size_bytes: row.get(6)?,
                    availability: row.get(7)?,
                    verification_state: row.get(8)?,
                    created_by_type: row.get(9)?,
                    created_by_id: row.get(10)?,
                    artifact_root_path: row.get(11)?,
                })
            },
        )
        .optional()
        .map_err(sqlite_error_to_port)?;
    let Some(metadata) = metadata else {
        return Err(integrity_failure());
    };
    if metadata.project_id != command.command_artifact.project_id.as_str()
        || metadata.task_id.as_deref() != Some(command.task_id.as_str())
        || metadata.artifact_type != command.command_artifact.artifact_type
        || metadata.logical_path != command.command_artifact.logical_path
        || metadata.content_hash != command.command_artifact.expected_hash
        || metadata.size_bytes
            != i64::try_from(command.command_artifact.expected_size)
                .map_err(|_| integrity_failure())?
        || metadata.availability != "available"
        || !matches!(
            metadata.verification_state.as_str(),
            "hash_verified" | "tool_verified" | "user_approved"
        )
        || metadata.created_by_type != command.command_artifact.created_by_type
        || metadata.created_by_id != command.command_artifact.created_by_id
    {
        return Err(integrity_failure());
    }
    validate_completed_operation(
        connection,
        command.command_artifact.artifact_id.as_str(),
        true,
    )?;
    let content = reader
        .read_from_root(
            Path::new(&metadata.artifact_root_path),
            &ArtifactRef {
                content_hash: metadata.content_hash.clone(),
                storage_key: metadata.storage_key,
                size_bytes: u64::try_from(metadata.size_bytes).map_err(|_| integrity_failure())?,
            },
        )
        .map_err(|_| integrity_failure())?;
    if content.bytes != command.command_artifact.canonical_bytes {
        return Err(integrity_failure());
    }
    Ok(())
}

fn validate_bound_artifact(
    connection: &Connection,
    reader: &dyn ArtifactRootReader,
    artifact_id: &ArtifactId,
    task_id: &TaskId,
    project_id: &local_agent_terminal_domain::ProjectId,
) -> Result<(), PortError> {
    let metadata: Option<ArtifactMetadata> = connection
        .query_row(
            "SELECT a.task_id, a.project_id, a.artifact_type, a.logical_path,
                    a.content_hash, a.storage_key, a.size_bytes, a.availability,
                    a.verification_state, a.created_by_type, a.created_by_id,
                    p.artifact_root_path
             FROM artifacts a
             JOIN projects p ON p.id = a.project_id
             WHERE a.id = ?1",
            [artifact_id.as_str()],
            |row| {
                Ok(ArtifactMetadata {
                    task_id: row.get(0)?,
                    project_id: row.get(1)?,
                    artifact_type: row.get(2)?,
                    logical_path: row.get(3)?,
                    content_hash: row.get(4)?,
                    storage_key: row.get(5)?,
                    size_bytes: row.get(6)?,
                    availability: row.get(7)?,
                    verification_state: row.get(8)?,
                    created_by_type: row.get(9)?,
                    created_by_id: row.get(10)?,
                    artifact_root_path: row.get(11)?,
                })
            },
        )
        .optional()
        .map_err(sqlite_error_to_port)?;
    let Some(metadata) = metadata else {
        return Err(integrity_failure());
    };
    if metadata.project_id != project_id.as_str()
        || metadata.task_id.as_deref() != Some(task_id.as_str())
        || metadata.availability != "available"
        || !matches!(
            metadata.verification_state.as_str(),
            "hash_verified" | "tool_verified" | "user_approved"
        )
    {
        return Err(integrity_failure());
    }
    validate_completed_operation(connection, artifact_id.as_str(), false)?;
    let content = reader
        .read_from_root(
            Path::new(&metadata.artifact_root_path),
            &ArtifactRef {
                content_hash: metadata.content_hash,
                storage_key: metadata.storage_key,
                size_bytes: u64::try_from(metadata.size_bytes).map_err(|_| integrity_failure())?,
            },
        )
        .map_err(|_| integrity_failure())?;
    if u64::try_from(content.bytes.len()).ok() != u64::try_from(metadata.size_bytes).ok() {
        return Err(integrity_failure());
    }
    Ok(())
}

fn configured_artifact_reader(store: &SqliteStore) -> Result<&dyn ArtifactRootReader, PortError> {
    store.artifact_reader().ok_or_else(unavailable)
}

fn validate_completed_operation(
    connection: &Connection,
    artifact_id: &str,
    required: bool,
) -> Result<(), PortError> {
    let operation_count: i64 = connection
        .query_row(
            "SELECT count(*) FROM artifact_operations WHERE artifact_id = ?1",
            [artifact_id],
            |row| row.get(0),
        )
        .map_err(sqlite_error_to_port)?;
    if operation_count == 0 && !required {
        return Ok(());
    }
    if operation_count != 1 {
        return Err(integrity_failure());
    }
    let completed: bool = connection
        .query_row(
            "SELECT EXISTS(
                SELECT 1 FROM artifact_operations
                WHERE artifact_id = ?1 AND status = 'completed'
            )",
            [artifact_id],
            |row| row.get(0),
        )
        .map_err(sqlite_error_to_port)?;
    if !completed {
        return Err(integrity_failure());
    }
    Ok(())
}

fn insert_prepared_event(
    transaction: &Transaction<'_>,
    command: &PreparedWorkflowTransition,
    prepared_at: &str,
    guard_set_digest: &Sha256Digest,
    effect_set_digest: &Sha256Digest,
) -> Result<(), PortError> {
    transaction
        .execute(
            "INSERT INTO workflow_transition_events (
                id, task_id, rule_id, expected_stream_version, from_phase, event_type,
                to_phase, workflow_profile, outcome_mode, transition_command_artifact_id,
                guard_set_digest, effect_set_digest, core_actor_digest, reducer_version,
                status, prepared_at, accepted_at, rejected_at
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10,
                       ?11, ?12, ?13, ?14, 'prepared', ?15, NULL, NULL)",
            params![
                command.transition_event_id,
                command.task_id.as_str(),
                command.rule_id,
                i64::try_from(command.expected_stream_version).map_err(|_| invalid_input())?,
                command.from_state.phase().as_str(),
                command.event.as_str(),
                command.to_state.phase().as_str(),
                command.from_state.workflow_profile().as_str(),
                command.from_state.outcome_mode().as_str(),
                command.command_artifact.artifact_id.as_str(),
                guard_set_digest.as_str(),
                effect_set_digest.as_str(),
                command.core_actor_digest.as_str(),
                command.reducer_version,
                prepared_at,
            ],
        )
        .map_err(authority_sql_error)?;
    Ok(())
}

fn insert_guard_bindings(
    transaction: &Transaction<'_>,
    command: &PreparedWorkflowTransition,
) -> Result<(), PortError> {
    for guard in &command.guards {
        transaction
            .execute(
                "INSERT INTO workflow_transition_guard_bindings (
                    transition_event_id, evidence_kind, evidence_ref, subject_digest,
                    evidence_digest, artifact_id, approval_receipt_id, acceptance_receipt_id,
                    verification_receipt_id, ref_promotion_receipt_id
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, NULL, NULL, NULL)",
                params![
                    command.transition_event_id,
                    guard.kind,
                    guard.reference,
                    guard.subject_digest.as_ref().map(Sha256Digest::as_str),
                    guard.evidence_digest.as_str(),
                    guard.artifact_id.as_ref().map(ArtifactId::as_str),
                    guard.approval_receipt_id,
                ],
            )
            .map_err(authority_sql_error)?;
    }
    Ok(())
}

fn insert_effect_bindings(
    transaction: &Transaction<'_>,
    command: &PreparedWorkflowTransition,
) -> Result<(), PortError> {
    for effect in &command.effects {
        transaction
            .execute(
                "INSERT INTO workflow_transition_effect_bindings (
                    transition_event_id, effect_kind, effect_ref, effect_digest, artifact_id
                 ) VALUES (?1, ?2, ?3, ?4, ?5)",
                params![
                    command.transition_event_id,
                    effect.kind,
                    effect.reference,
                    effect.effect_digest.as_str(),
                    effect.artifact_id.as_ref().map(ArtifactId::as_str),
                ],
            )
            .map_err(authority_sql_error)?;
    }
    Ok(())
}

fn update_authority_projection(
    transaction: &Transaction<'_>,
    command: &PreparedWorkflowTransition,
    updated_at: &str,
) -> Result<(), PortError> {
    let changed = transaction
        .execute(
            "UPDATE task_workflow_authority
             SET phase = ?1, stream_version = ?2, last_transition_event_id = ?3,
                 updated_at = ?4,
                 completed_at = CASE
                     WHEN ?5 IN ('Completed', 'Cancelled', 'Failed') THEN ?4
                     ELSE completed_at
                 END
             WHERE task_id = ?6 AND phase = ?7 AND workflow_profile = ?8
               AND outcome_mode = ?9 AND stream_version = ?10",
            params![
                command.to_state.phase().as_str(),
                i64::try_from(command.to_state.stream_version()).map_err(|_| invalid_input())?,
                command.transition_event_id,
                updated_at,
                command.to_state.phase().as_str(),
                command.task_id.as_str(),
                command.from_state.phase().as_str(),
                command.from_state.workflow_profile().as_str(),
                command.from_state.outcome_mode().as_str(),
                i64::try_from(command.expected_stream_version).map_err(|_| invalid_input())?,
            ],
        )
        .map_err(authority_sql_error)?;
    if changed != 1 {
        return Err(conflict());
    }
    Ok(())
}

fn update_task_projection(
    transaction: &Transaction<'_>,
    command: &PreparedWorkflowTransition,
    updated_at: &str,
) -> Result<(), PortError> {
    let changed = transaction
        .execute(
            "UPDATE tasks
             SET phase = ?1, condition = ?2, operation_state = ?3,
                 workspace_version = ?4, fencing_epoch = ?5, updated_at = ?6,
                 row_version = row_version + 1
             WHERE id = ?7 AND phase = ?8
               AND workspace_version = ?9 AND fencing_epoch = ?10",
            params![
                command.to_state.phase().as_str(),
                command.to_state.condition().as_str(),
                command.to_state.operation().as_str(),
                i64::try_from(command.to_state.workspace_version().get())
                    .map_err(|_| invalid_input())?,
                i64::try_from(command.to_state.fencing_token().get())
                    .map_err(|_| invalid_input())?,
                updated_at,
                command.task_id.as_str(),
                command.from_state.phase().as_str(),
                i64::try_from(command.from_state.workspace_version().get())
                    .map_err(|_| invalid_input())?,
                i64::try_from(command.from_state.fencing_token().get())
                    .map_err(|_| invalid_input())?,
            ],
        )
        .map_err(authority_sql_error)?;
    if changed != 1 {
        return Err(conflict());
    }
    Ok(())
}

fn command_prepared_at(command: &PreparedWorkflowTransition) -> Result<String, PortError> {
    serde_json::from_slice::<Value>(&command.command_artifact.canonical_bytes)
        .map_err(|_| integrity_failure())?
        .get("preparedAt")
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or_else(integrity_failure)
}

fn authority_timestamp(
    transaction: &Transaction<'_>,
    task_id: &TaskId,
) -> Result<String, PortError> {
    let previous: String = transaction
        .query_row(
            "SELECT updated_at FROM task_workflow_authority WHERE task_id = ?1",
            [task_id.as_str()],
            |row| row.get(0),
        )
        .map_err(sqlite_error_to_port)?;
    let now: String = transaction
        .query_row("SELECT strftime('%Y-%m-%dT%H:%M:%fZ', 'now')", [], |row| {
            row.get(0)
        })
        .map_err(sqlite_error_to_port)?;
    if now > previous {
        Ok(now)
    } else {
        Ok(format!("{previous}~"))
    }
}

fn guard_values(command: &PreparedWorkflowTransition) -> Vec<Value> {
    command
        .guards
        .iter()
        .map(|guard| {
            json!({
                "kind": guard.kind,
                "reference": guard.reference,
                "subjectDigest": guard.subject_digest.as_ref().map(Sha256Digest::as_str),
                "evidenceDigest": guard.evidence_digest.as_str(),
                "artifactId": guard.artifact_id.as_ref().map(ArtifactId::as_str),
                "approvalReceiptId": guard.approval_receipt_id,
            })
        })
        .collect()
}

fn effect_values(command: &PreparedWorkflowTransition) -> Vec<Value> {
    command
        .effects
        .iter()
        .map(|effect| {
            json!({
                "kind": effect.kind,
                "reference": effect.reference,
                "effectDigest": effect.effect_digest.as_str(),
                "artifactId": effect.artifact_id.as_ref().map(ArtifactId::as_str),
            })
        })
        .collect()
}

fn set_digest(values: &[Value]) -> Result<Sha256Digest, PortError> {
    digest_value(&Value::Array(values.to_vec()))
}

fn digest_value(value: &Value) -> Result<Sha256Digest, PortError> {
    let bytes = serde_json_canonicalizer::to_vec(value).map_err(|_| integrity_failure())?;
    digest_bytes(&bytes)
}

fn digest_bytes(bytes: &[u8]) -> Result<Sha256Digest, PortError> {
    Sha256Digest::new(format!("sha256:{:x}", Sha256::digest(bytes)))
        .map_err(|_| integrity_failure())
}

#[derive(Debug)]
struct CurrentAuthority {
    project_id: String,
    phase: String,
    workflow_profile: String,
    outcome_mode: String,
    task_phase: String,
    task_condition: String,
    task_operation: String,
    task_workspace_version: i64,
    task_fencing_epoch: i64,
    stream_version: i64,
    profile_revision: i64,
}

#[derive(Debug)]
struct ArtifactMetadata {
    task_id: Option<String>,
    project_id: String,
    artifact_type: String,
    logical_path: String,
    content_hash: String,
    storage_key: String,
    size_bytes: i64,
    availability: String,
    verification_state: String,
    created_by_type: String,
    created_by_id: String,
    artifact_root_path: String,
}

fn authority_sql_error(error: rusqlite::Error) -> PortError {
    let mapped = sqlite_error_to_port(error);
    match mapped.safe_classification() {
        SafeErrorClassification::InvalidInput | SafeErrorClassification::Internal => conflict(),
        _ => mapped,
    }
}

fn invalid_input() -> PortError {
    PortError::failure(
        SafeErrorClassification::InvalidInput,
        local_agent_terminal_application::Retryability::NonRetryable,
    )
}

fn integrity_failure() -> PortError {
    PortError::failure(
        SafeErrorClassification::IntegrityFailure,
        local_agent_terminal_application::Retryability::NonRetryable,
    )
}

fn conflict() -> PortError {
    PortError::failure(
        SafeErrorClassification::Conflict,
        local_agent_terminal_application::Retryability::NonRetryable,
    )
}

fn not_found() -> PortError {
    PortError::failure(
        SafeErrorClassification::NotFound,
        local_agent_terminal_application::Retryability::NonRetryable,
    )
}

fn unavailable() -> PortError {
    PortError::failure(
        SafeErrorClassification::Unavailable,
        local_agent_terminal_application::Retryability::Retryable,
    )
}
