use local_agent_terminal_application::{
    ArtifactRootReader, CompareAndExpirePlanApproval, CompareAndInvalidatePlanApproval,
    CompareAndResolvePlanApproval, PlanApprovalAction, PlanApprovalAuthorityBinding,
    PlanApprovalBindingInput, PlanApprovalCurrentAuthority, PlanApprovalCurrentState,
    PlanApprovalRequestArtifact, PlanApprovalState, PlanApprovalStore, PlanApprovalTerminal,
    PortError, Retryability, SafeErrorClassification, StoredPlanApproval,
    StoredPlanApprovalRehydration,
};
use local_agent_terminal_domain::{ActorId, ArtifactId, Sha256Digest, TaskId};
use rusqlite::{params, Connection, OptionalExtension, Transaction, TransactionBehavior};
use serde_json::Value;

use crate::agent_store::read_available_artifact;
use crate::deliberation_store::load_workflow_state;
use crate::event_store::{append_in_transaction, open_error_to_port, sqlite_error_to_port};
use crate::SqliteStore;

impl PlanApprovalStore for SqliteStore {
    fn reload(
        &self,
        approval_id: &local_agent_terminal_application::ApprovalId,
    ) -> Result<Option<StoredPlanApproval>, PortError> {
        let artifact_reader = configured_artifact_reader(self)?;
        let mut connection = self.connection().map_err(open_error_to_port)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Deferred)
            .map_err(sqlite_error_to_port)?;
        let approval = load_approval(&transaction, artifact_reader, approval_id)?;
        transaction.commit().map_err(sqlite_error_to_port)?;
        Ok(approval)
    }

    fn current_state(&self, task_id: &TaskId) -> Result<PlanApprovalCurrentState, PortError> {
        let live_authority = load_current_authority(self, task_id)?;
        let artifact_reader = configured_artifact_reader(self)?;
        let mut connection = self.connection().map_err(open_error_to_port)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Deferred)
            .map_err(sqlite_error_to_port)?;
        let approval_id: Option<String> = transaction
            .query_row(
                "SELECT id FROM approvals
                 WHERE task_id = ?1 AND approval_type = 'plan' AND status = 'pending'
                 ORDER BY requested_at DESC, id DESC LIMIT 1",
                [task_id.as_str()],
                |row| row.get(0),
            )
            .optional()
            .map_err(sqlite_error_to_port)?;
        let approval_id =
            local_agent_terminal_application::ApprovalId::new(approval_id.ok_or_else(not_found)?)
                .map_err(|_| integrity_failure())?;
        let approval = load_approval(&transaction, artifact_reader, &approval_id)?
            .ok_or_else(integrity_failure)?;
        let current =
            current_state_for_binding(&transaction, task_id, approval.binding(), &live_authority)?;
        transaction.commit().map_err(sqlite_error_to_port)?;
        Ok(current)
    }

    fn compare_and_resolve(&self, command: CompareAndResolvePlanApproval) -> Result<(), PortError> {
        command.validate()?;
        let task_id =
            TaskId::new(&command.expected_current.binding.task_id).map_err(|_| conflict())?;
        let live_authority = load_current_authority(self, &task_id)?;
        let artifact_reader = configured_artifact_reader(self)?;
        let mut connection = self.connection().map_err(open_error_to_port)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite_error_to_port)?;
        compare_expected(
            &transaction,
            artifact_reader,
            &command.expected_approval,
            &command.expected_current,
            &live_authority,
        )?;
        append_in_transaction(&transaction, &command.resolution.append)?;
        let (status, action) = match command.resolution.action {
            PlanApprovalAction::Approve => ("granted", "approve"),
            PlanApprovalAction::Reject => ("denied", "reject"),
            PlanApprovalAction::Revise
            | PlanApprovalAction::Reopen
            | PlanApprovalAction::AddOrReplaceAgent => return Err(conflict()),
        };
        let changed = transaction
            .execute(
                "UPDATE approvals
                 SET status = ?1, resolved_at = ?2, resolved_by = ?3,
                     invalidation_reason = NULL
                 WHERE id = ?4 AND approval_type = 'plan' AND status = 'pending'
                   AND operation_digest = ?5",
                params![
                    status,
                    command.resolution.resolved_at,
                    command.resolution.actor_id.as_str(),
                    command.resolution.approval_id.as_str(),
                    command.resolution.operation_digest.as_str(),
                ],
            )
            .map_err(sqlite_error_to_port)?;
        if changed != 1 {
            return Err(conflict());
        }
        verify_terminal_event(
            &transaction,
            &command.expected_current.binding.task_id,
            command.resolution.approval_id.as_str(),
            if action == "approve" {
                "plan.approved"
            } else {
                "task.cancelled"
            },
            Some(action),
        )?;
        transaction.commit().map_err(sqlite_error_to_port)
    }

    fn compare_and_invalidate(
        &self,
        command: CompareAndInvalidatePlanApproval,
    ) -> Result<(), PortError> {
        command.validate()?;
        let task_id =
            TaskId::new(&command.expected_current.binding.task_id).map_err(|_| conflict())?;
        let live_authority = load_current_authority(self, &task_id)?;
        let artifact_reader = configured_artifact_reader(self)?;
        let mut connection = self.connection().map_err(open_error_to_port)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite_error_to_port)?;
        compare_expected(
            &transaction,
            artifact_reader,
            &command.expected_approval,
            &command.expected_current,
            &live_authority,
        )?;
        append_in_transaction(&transaction, command.invalidation.append())?;
        let changed = transaction
            .execute(
                "UPDATE approvals
                 SET status = 'invalidated', resolved_at = ?1, resolved_by = ?2,
                     invalidation_reason = ?3
                 WHERE id = ?4 AND approval_type = 'plan' AND status = 'pending'
                   AND operation_digest = ?5",
                params![
                    command.invalidation.invalidated_at(),
                    command.invalidation.actor_id().as_str(),
                    command.invalidation.reason_code(),
                    command.invalidation.approval_id().as_str(),
                    command.expected_approval.operation_digest.as_str(),
                ],
            )
            .map_err(sqlite_error_to_port)?;
        if changed != 1 {
            return Err(conflict());
        }
        verify_terminal_event(
            &transaction,
            &command.expected_current.binding.task_id,
            command.invalidation.approval_id().as_str(),
            "approval.invalidated",
            None,
        )?;
        transaction.commit().map_err(sqlite_error_to_port)
    }

    fn compare_and_expire(&self, command: CompareAndExpirePlanApproval) -> Result<(), PortError> {
        command.validate()?;
        let task_id =
            TaskId::new(&command.expected_current.binding.task_id).map_err(|_| conflict())?;
        let live_authority = load_current_authority(self, &task_id)?;
        let artifact_reader = configured_artifact_reader(self)?;
        let mut connection = self.connection().map_err(open_error_to_port)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite_error_to_port)?;
        compare_expected(
            &transaction,
            artifact_reader,
            &command.expected_approval,
            &command.expected_current,
            &live_authority,
        )?;
        append_in_transaction(&transaction, command.expiry.append())?;
        let changed = transaction
            .execute(
                "UPDATE approvals
                 SET status = 'expired', resolved_at = ?1, resolved_by = 'core',
                     invalidation_reason = NULL
                 WHERE id = ?2 AND approval_type = 'plan' AND status = 'pending'
                   AND operation_digest = ?3",
                params![
                    command.expiry.expired_at(),
                    command.expiry.approval_id().as_str(),
                    command.expected_approval.operation_digest.as_str(),
                ],
            )
            .map_err(sqlite_error_to_port)?;
        if changed != 1 {
            return Err(conflict());
        }
        verify_terminal_event(
            &transaction,
            &command.expected_current.binding.task_id,
            command.expiry.approval_id().as_str(),
            "approval.expired",
            None,
        )?;
        transaction.commit().map_err(sqlite_error_to_port)
    }
}

struct ApprovalRow {
    task_id: String,
    operation_digest: String,
    status: String,
    requested_at: String,
    resolved_at: Option<String>,
    resolved_by: Option<String>,
    expires_at: String,
    request_artifact_id: String,
    invalidation_reason: Option<String>,
}

fn load_approval(
    connection: &Connection,
    artifact_reader: &dyn ArtifactRootReader,
    approval_id: &local_agent_terminal_application::ApprovalId,
) -> Result<Option<StoredPlanApproval>, PortError> {
    let row: Option<ApprovalRow> = connection
        .query_row(
            "SELECT task_id, operation_digest, status, requested_at, resolved_at,
                    resolved_by, expires_at, request_artifact_id, invalidation_reason
             FROM approvals WHERE id = ?1 AND approval_type = 'plan'
               AND schema_version = 'approval-digest.v1'",
            [approval_id.as_str()],
            |row| {
                Ok(ApprovalRow {
                    task_id: row.get(0)?,
                    operation_digest: row.get(1)?,
                    status: row.get(2)?,
                    requested_at: row.get(3)?,
                    resolved_at: row.get(4)?,
                    resolved_by: row.get(5)?,
                    expires_at: row.get(6)?,
                    request_artifact_id: row.get(7)?,
                    invalidation_reason: row.get(8)?,
                })
            },
        )
        .optional()
        .map_err(sqlite_error_to_port)?;
    let Some(row) = row else {
        return Ok(None);
    };
    let task_id = TaskId::new(&row.task_id).map_err(|_| integrity_failure())?;
    let operation_digest =
        Sha256Digest::new(&row.operation_digest).map_err(|_| integrity_failure())?;
    let request_artifact_id =
        ArtifactId::new(&row.request_artifact_id).map_err(|_| integrity_failure())?;
    let canonical_bytes = read_available_artifact(
        connection,
        artifact_reader,
        &request_artifact_id,
        &task_id,
        Some(operation_digest.as_str()),
        None,
    )?;
    let (authority_bytes, authority_digest) =
        load_authority_binding(connection, &task_id, approval_id)?;
    let authority =
        PlanApprovalAuthorityBinding::rehydrate(authority_bytes.clone(), authority_digest.clone())?;
    if authority.binding().task_id != row.task_id
        || authority.binding().requested_at != row.requested_at
        || authority.binding().expires_at != row.expires_at
    {
        return Err(integrity_failure());
    }
    let request_artifact = PlanApprovalRequestArtifact {
        artifact_id: request_artifact_id,
        content_digest: operation_digest.clone(),
        size_bytes: u64::try_from(canonical_bytes.len()).map_err(|_| integrity_failure())?,
    };
    let (state, terminal) = terminal_state(connection, approval_id, &task_id, &row)?;
    StoredPlanApproval::rehydrate(StoredPlanApprovalRehydration {
        approval_id: approval_id.clone(),
        state,
        canonical_bytes,
        operation_digest,
        request_artifact,
        authority_binding_bytes: authority_bytes,
        authority_binding_digest: authority_digest,
        terminal,
    })
    .map(Some)
}

fn load_authority_binding(
    connection: &Connection,
    task_id: &TaskId,
    approval_id: &local_agent_terminal_application::ApprovalId,
) -> Result<(Vec<u8>, Sha256Digest), PortError> {
    let payload: Option<String> = connection
        .query_row(
            "SELECT payload_json FROM events
             WHERE event_type = 'objection.round.closed'
               AND stream_id = ?1
               AND json_extract(payload_json, '$.approvalId') = ?2
             ORDER BY sequence DESC LIMIT 1",
            params![task_id.as_str(), approval_id.as_str()],
            |row| row.get(0),
        )
        .optional()
        .map_err(sqlite_error_to_port)?;
    let value: Value = serde_json::from_str(&payload.ok_or_else(integrity_failure)?)
        .map_err(|_| integrity_failure())?;
    let authority = value
        .get("approvalAuthorityBinding")
        .ok_or_else(integrity_failure)?;
    let bytes = serde_json_canonicalizer::to_vec(authority).map_err(|_| integrity_failure())?;
    let digest = value
        .get("approvalAuthorityBindingDigest")
        .and_then(Value::as_str)
        .ok_or_else(integrity_failure)
        .and_then(|value| Sha256Digest::new(value).map_err(|_| integrity_failure()))?;
    Ok((bytes, digest))
}

fn terminal_state(
    connection: &Connection,
    approval_id: &local_agent_terminal_application::ApprovalId,
    task_id: &TaskId,
    row: &ApprovalRow,
) -> Result<(PlanApprovalState, Option<PlanApprovalTerminal>), PortError> {
    match row.status.as_str() {
        "pending"
            if row.resolved_at.is_none()
                && row.resolved_by.is_none()
                && row.invalidation_reason.is_none() =>
        {
            Ok((PlanApprovalState::Requested, None))
        }
        "granted" | "denied" => {
            let action = if row.status == "granted" {
                PlanApprovalAction::Approve
            } else {
                PlanApprovalAction::Reject
            };
            let expected_type = if row.status == "granted" {
                "plan.approved"
            } else {
                "task.cancelled"
            };
            let event = load_terminal_event(
                connection,
                task_id.as_str(),
                approval_id.as_str(),
                expected_type,
            )?;
            let expected_action = if row.status == "granted" {
                "approve"
            } else {
                "reject"
            };
            if event.action.as_deref() != Some(expected_action)
                || row.resolved_at.as_deref() != Some(event.created_at.as_str())
                || row.resolved_by.as_deref() != Some(event.actor_id.as_str())
                || row.invalidation_reason.is_some()
            {
                return Err(integrity_failure());
            }
            Ok((
                PlanApprovalState::Resolved,
                Some(PlanApprovalTerminal::Resolved {
                    action,
                    actor_id: ActorId::new(event.actor_id).map_err(|_| integrity_failure())?,
                    resolved_at: event.created_at,
                }),
            ))
        }
        "invalidated" => {
            let event = load_terminal_event(
                connection,
                task_id.as_str(),
                approval_id.as_str(),
                "approval.invalidated",
            )?;
            let reason = event.reason_code.ok_or_else(integrity_failure)?;
            if row.resolved_at.as_deref() != Some(event.created_at.as_str())
                || row.resolved_by.as_deref() != Some(event.actor_id.as_str())
                || row.invalidation_reason.as_deref() != Some(reason.as_str())
            {
                return Err(integrity_failure());
            }
            Ok((
                PlanApprovalState::Invalidated,
                Some(PlanApprovalTerminal::Invalidated {
                    reason_code: reason,
                    actor_id: ActorId::new(event.actor_id).map_err(|_| integrity_failure())?,
                    invalidated_at: event.created_at,
                }),
            ))
        }
        "expired" => {
            let event = load_terminal_event(
                connection,
                task_id.as_str(),
                approval_id.as_str(),
                "approval.expired",
            )?;
            if row.resolved_at.as_deref() != Some(event.created_at.as_str())
                || row.resolved_by.as_deref() != Some("core")
                || event.actor_id != "core"
                || row.invalidation_reason.is_some()
            {
                return Err(integrity_failure());
            }
            Ok((
                PlanApprovalState::Expired,
                Some(PlanApprovalTerminal::Expired {
                    expired_at: event.created_at,
                }),
            ))
        }
        _ => Err(integrity_failure()),
    }
}

struct TerminalEvent {
    actor_id: String,
    created_at: String,
    action: Option<String>,
    reason_code: Option<String>,
}

fn load_terminal_event(
    connection: &Connection,
    task_id: &str,
    approval_id: &str,
    event_type: &str,
) -> Result<TerminalEvent, PortError> {
    let event: Option<(String, String, String)> = connection
        .query_row(
            "SELECT actor_id, created_at, payload_json FROM events
             WHERE stream_id = ?1 AND event_type = ?2
               AND json_extract(payload_json, '$.approvalId') = ?3
             ORDER BY sequence DESC LIMIT 1",
            params![task_id, event_type, approval_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()
        .map_err(sqlite_error_to_port)?;
    let (actor_id, created_at, payload) = event.ok_or_else(integrity_failure)?;
    let payload: Value = serde_json::from_str(&payload).map_err(|_| integrity_failure())?;
    Ok(TerminalEvent {
        actor_id,
        created_at,
        action: payload
            .get("action")
            .and_then(Value::as_str)
            .map(str::to_owned),
        reason_code: payload
            .get("reasonCode")
            .and_then(Value::as_str)
            .map(str::to_owned),
    })
}

fn current_state_for_binding(
    connection: &Connection,
    task_id: &TaskId,
    stored: &PlanApprovalBindingInput,
    live_authority: &PlanApprovalCurrentAuthority,
) -> Result<PlanApprovalCurrentState, PortError> {
    let task_state = load_workflow_state(connection, task_id)?;
    let mut binding = stored.clone();
    let (base_commit, risk_class): (String, String) = connection
        .query_row(
            "SELECT base_commit, risk_level FROM tasks WHERE id = ?1",
            [task_id.as_str()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .map_err(sqlite_error_to_port)?;
    binding.base_commit = base_commit;
    binding.risk_class = risk_class;
    binding.repository_fingerprint = live_authority.repository_fingerprint.as_str().to_owned();
    binding.policy_snapshot_digest = live_authority.policy_snapshot_digest.as_str().to_owned();
    binding.task_version = task_state.sequence().get();
    binding.workspace_version = task_state.workspace_version().get();
    binding.fencing_epoch = task_state
        .fencing_token()
        .get()
        .checked_add(1)
        .ok_or_else(integrity_failure)?;
    let manifest_digest: Option<String> = connection
        .query_row(
            "SELECT manifest_digest FROM agent_descriptors WHERE id = ?1",
            [&binding.agent_id],
            |row| row.get(0),
        )
        .optional()
        .map_err(sqlite_error_to_port)?;
    binding.agent_manifest_digest = manifest_digest.ok_or_else(integrity_failure)?;
    Ok(PlanApprovalCurrentState {
        phase: task_state.phase(),
        task_state,
        binding,
    })
}

fn load_current_authority(
    store: &SqliteStore,
    task_id: &TaskId,
) -> Result<PlanApprovalCurrentAuthority, PortError> {
    store
        .plan_approval_authority_source()
        .ok_or_else(unavailable)?
        .current_authority(task_id)
}

fn configured_artifact_reader(store: &SqliteStore) -> Result<&dyn ArtifactRootReader, PortError> {
    store.artifact_reader().ok_or_else(unavailable)
}

fn compare_expected(
    transaction: &Transaction<'_>,
    artifact_reader: &dyn ArtifactRootReader,
    expected_approval: &StoredPlanApproval,
    expected_current: &PlanApprovalCurrentState,
    live_authority: &PlanApprovalCurrentAuthority,
) -> Result<(), PortError> {
    let actual = load_approval(transaction, artifact_reader, &expected_approval.approval_id)?
        .ok_or_else(conflict)?;
    if &actual != expected_approval {
        return Err(conflict());
    }
    let task_id = TaskId::new(&expected_current.binding.task_id).map_err(|_| conflict())?;
    let current =
        current_state_for_binding(transaction, &task_id, actual.binding(), live_authority)?;
    if &current == expected_current {
        Ok(())
    } else {
        Err(conflict())
    }
}

fn verify_terminal_event(
    connection: &Connection,
    task_id: &str,
    approval_id: &str,
    event_type: &str,
    action: Option<&str>,
) -> Result<(), PortError> {
    let event = load_terminal_event(connection, task_id, approval_id, event_type)?;
    if action.is_none_or(|expected| event.action.as_deref() == Some(expected)) {
        Ok(())
    } else {
        Err(integrity_failure())
    }
}

fn conflict() -> PortError {
    PortError::failure(
        SafeErrorClassification::Conflict,
        Retryability::NonRetryable,
    )
}

fn integrity_failure() -> PortError {
    PortError::failure(
        SafeErrorClassification::IntegrityFailure,
        Retryability::NonRetryable,
    )
}

fn not_found() -> PortError {
    PortError::failure(
        SafeErrorClassification::NotFound,
        Retryability::NonRetryable,
    )
}

fn unavailable() -> PortError {
    PortError::failure(
        SafeErrorClassification::Unavailable,
        Retryability::Retryable,
    )
}
