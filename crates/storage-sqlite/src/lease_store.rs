use local_agent_terminal_application::{
    AcquireLease, ExecutorLeaseStore, LeaseSnapshot, LeaseState, PortError, Retryability,
    RevokeLease, SafeErrorClassification,
};
use local_agent_terminal_domain::{ArtifactId, FencingToken, LeaseClaim, RunId, TaskId};
use rusqlite::{params, Connection, OptionalExtension, Transaction, TransactionBehavior};
use serde_json::json;

use crate::event_store::{open_error_to_port, sqlite_error_to_port};
use crate::workspace_store::{insert_task_event, TaskEvent};
use crate::SqliteStore;

const CORE_AGENT_ID: &str = "core.workspace-coordinator";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoreSystemRunRequest {
    pub run_id: RunId,
    pub task_id: TaskId,
    pub context_package_id: String,
    pub manifest_artifact_id: ArtifactId,
    pub effective_content_artifact_id: ArtifactId,
    pub run_config_artifact_id: ArtifactId,
    pub content_hash: String,
    pub policy_snapshot_digest: String,
    pub connection_binding_digest: String,
    pub idempotency_key: String,
    pub created_at: String,
}

impl SqliteStore {
    pub fn current_lease(&self, task_id: &TaskId) -> Result<Option<LeaseSnapshot>, PortError> {
        let connection = self.connection().map_err(open_error_to_port)?;
        load_lease(&connection, task_id)
    }

    pub fn ensure_core_system_run(&self, request: CoreSystemRunRequest) -> Result<(), PortError> {
        validate_core_run(&request)?;
        let mut connection = self.connection().map_err(open_error_to_port)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite_error_to_port)?;
        for artifact_id in [
            &request.manifest_artifact_id,
            &request.effective_content_artifact_id,
            &request.run_config_artifact_id,
        ] {
            verify_available_task_artifact(
                &transaction,
                artifact_id,
                &request.task_id,
                &request.content_hash,
            )?;
        }
        transaction
            .execute(
                "INSERT INTO agent_descriptors (
                    id, display_name, transport_type, trust_tier, manifest_json,
                    manifest_digest, executable_digest, enabled, last_health_status, updated_at
                 ) VALUES (
                    ?1, 'Workspace coordinator', 'in_process', 'core_adapter', ?2,
                    ?3, NULL, 1, 'healthy', ?4
                 )
                 ON CONFLICT(id) DO UPDATE SET
                    manifest_json = excluded.manifest_json,
                    manifest_digest = excluded.manifest_digest,
                    enabled = 1,
                    last_health_status = 'healthy',
                    updated_at = excluded.updated_at",
                params![
                    CORE_AGENT_ID,
                    json!({"kind": "core_workspace_coordinator", "version": 1}).to_string(),
                    request.content_hash,
                    request.created_at,
                ],
            )
            .map_err(sqlite_error_to_port)?;
        transaction
            .execute(
                "INSERT OR IGNORE INTO context_packages (
                    id, task_id, agent_id, role, objective, manifest_artifact_id,
                    effective_content_artifact_id, content_hash, policy_snapshot_digest,
                    prompt_template_version, retrieval_pipeline_version, created_at
                 ) VALUES (
                    ?1, ?2, ?3, 'workspace_coordinator', 'Guard repository workspace state',
                    ?4, ?5, ?6, ?7, 'core-v1', 'none', ?8
                 )",
                params![
                    request.context_package_id,
                    request.task_id.as_str(),
                    CORE_AGENT_ID,
                    request.manifest_artifact_id.as_str(),
                    request.effective_content_artifact_id.as_str(),
                    request.content_hash,
                    request.policy_snapshot_digest,
                    request.created_at,
                ],
            )
            .map_err(sqlite_error_to_port)?;
        let context_matches: bool = transaction
            .query_row(
                "SELECT EXISTS(
                    SELECT 1 FROM context_packages
                    WHERE id = ?1 AND task_id = ?2 AND agent_id = ?3
                      AND manifest_artifact_id = ?4
                      AND effective_content_artifact_id = ?5
                      AND content_hash = ?6
                      AND policy_snapshot_digest = ?7
                )",
                params![
                    request.context_package_id,
                    request.task_id.as_str(),
                    CORE_AGENT_ID,
                    request.manifest_artifact_id.as_str(),
                    request.effective_content_artifact_id.as_str(),
                    request.content_hash,
                    request.policy_snapshot_digest,
                ],
                |row| row.get(0),
            )
            .map_err(sqlite_error_to_port)?;
        if !context_matches {
            return Err(conflict());
        }
        transaction
            .execute(
                "INSERT OR IGNORE INTO agent_runs (
                    id, task_id, agent_id, role, phase, status, context_package_id,
                    idempotency_key, connection_binding_digest, run_config_artifact_id,
                    supersedes_run_id, started_at, completed_at, provider_usage_json,
                    core_usage_json, estimated_cost_microunits, error_json
                 ) VALUES (
                    ?1, ?2, ?3, 'workspace_coordinator', 'system', 'running', ?4,
                    ?5, ?6, ?7, NULL, ?8, NULL, NULL, NULL, NULL, NULL
                 )",
                params![
                    request.run_id.as_str(),
                    request.task_id.as_str(),
                    CORE_AGENT_ID,
                    request.context_package_id,
                    request.idempotency_key,
                    request.connection_binding_digest,
                    request.run_config_artifact_id.as_str(),
                    request.created_at,
                ],
            )
            .map_err(sqlite_error_to_port)?;
        let run_matches: bool = transaction
            .query_row(
                "SELECT EXISTS(
                    SELECT 1 FROM agent_runs
                    WHERE id = ?1 AND task_id = ?2 AND agent_id = ?3
                      AND context_package_id = ?4 AND idempotency_key = ?5
                      AND run_config_artifact_id = ?6
                )",
                params![
                    request.run_id.as_str(),
                    request.task_id.as_str(),
                    CORE_AGENT_ID,
                    request.context_package_id,
                    request.idempotency_key,
                    request.run_config_artifact_id.as_str(),
                ],
                |row| row.get(0),
            )
            .map_err(sqlite_error_to_port)?;
        if !run_matches {
            return Err(conflict());
        }
        transaction.commit().map_err(sqlite_error_to_port)
    }
}

impl ExecutorLeaseStore for SqliteStore {
    fn acquire(&self, request: AcquireLease) -> Result<LeaseSnapshot, PortError> {
        validate_acquire(&request)?;
        let mut connection = self.connection().map_err(open_error_to_port)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite_error_to_port)?;
        verify_run(&transaction, &request.task_id, &request.holder_run_id)?;
        let task: Option<(i64, i64)> = transaction
            .query_row(
                "SELECT fencing_epoch, current_sequence FROM tasks WHERE id = ?1",
                [request.task_id.as_str()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(sqlite_error_to_port)?;
        let Some((current_epoch, current_sequence)) = task else {
            return Err(not_found());
        };
        let expected_epoch =
            i64::try_from(request.expected_fencing_epoch).map_err(|_| invalid_input())?;
        if current_epoch != expected_epoch {
            return Err(conflict());
        }
        let previous = load_lease(&transaction, &request.task_id)?;
        if previous
            .as_ref()
            .is_some_and(|lease| lease.state == LeaseState::Active)
        {
            return Err(conflict());
        }
        let next_epoch = current_epoch.checked_add(1).ok_or_else(invalid_input)?;
        let next_sequence = current_sequence.checked_add(1).ok_or_else(invalid_input)?;
        let updated = transaction
            .execute(
                "UPDATE tasks SET fencing_epoch = ?1, current_sequence = ?2, updated_at = ?3,
                    row_version = row_version + 1
                 WHERE id = ?4 AND fencing_epoch = ?5 AND current_sequence = ?6",
                params![
                    next_epoch,
                    next_sequence,
                    request.acquired_at,
                    request.task_id.as_str(),
                    current_epoch,
                    current_sequence,
                ],
            )
            .map_err(sqlite_error_to_port)?;
        if updated != 1 {
            return Err(conflict());
        }
        transaction
            .execute(
                "INSERT INTO executor_leases (
                    id, task_id, holder_run_id, fencing_token, status,
                    acquired_at, expires_at, released_at
                 ) VALUES (?1, ?2, ?3, ?4, 'active', ?5, ?6, NULL)",
                params![
                    format!("lease:{}:{next_epoch}", request.task_id.as_str()),
                    request.task_id.as_str(),
                    request.holder_run_id.as_str(),
                    next_epoch,
                    request.acquired_at,
                    request.expires_at,
                ],
            )
            .map_err(sqlite_error_to_port)?;
        let event_type = if previous.is_some() {
            "executor.lease.replaced"
        } else {
            "executor.lease.acquired"
        };
        let payload = json!({
            "taskId": request.task_id.as_str(),
            "holderRunId": request.holder_run_id.as_str(),
            "fencingToken": next_epoch,
            "previousHolderRunId": previous.as_ref().map(|lease| lease.holder_run_id.as_str()),
            "previousFencingToken": previous.as_ref().map(|lease| lease.token.get()),
            "previousState": previous.as_ref().map(|lease| lease.state.as_str()),
        });
        let event_id = format!("executor.lease:{}:{next_epoch}", request.task_id.as_str());
        let correlation_id = format!("executor-lease:{}:{next_epoch}", request.task_id.as_str());
        insert_task_event(
            &transaction,
            TaskEvent {
                task_id: request.task_id.as_str(),
                sequence: next_sequence,
                event_id: &event_id,
                event_type,
                payload: &payload,
                actor_id: CORE_AGENT_ID,
                correlation_id: &correlation_id,
                created_at: &request.acquired_at,
            },
        )?;
        transaction.commit().map_err(sqlite_error_to_port)?;

        Ok(LeaseSnapshot {
            task_id: request.task_id,
            holder_run_id: request.holder_run_id,
            token: FencingToken::try_from(next_epoch).map_err(|_| integrity_failure())?,
            state: LeaseState::Active,
            acquired_at: request.acquired_at,
            expires_at: request.expires_at,
            released_at: None,
        })
    }

    fn revoke(&self, request: RevokeLease) -> Result<(), PortError> {
        if request.revoked_at.trim().is_empty() {
            return Err(invalid_input());
        }
        let mut connection = self.connection().map_err(open_error_to_port)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite_error_to_port)?;
        let current = load_lease(&transaction, request.claim.task_id())?.ok_or_else(conflict)?;
        if current.state != LeaseState::Active
            || current.holder_run_id != *request.claim.holder_run_id()
            || current.token != request.claim.token()
        {
            return Err(stale_lease(&transaction, &request.claim));
        }
        let changed = transaction
            .execute(
                "UPDATE executor_leases SET status = 'revoked', released_at = ?1
                 WHERE task_id = ?2 AND holder_run_id = ?3
                   AND fencing_token = ?4 AND status = 'active'",
                params![
                    request.revoked_at,
                    request.claim.task_id().as_str(),
                    request.claim.holder_run_id().as_str(),
                    i64::try_from(request.claim.token().get()).map_err(|_| invalid_input())?,
                ],
            )
            .map_err(sqlite_error_to_port)?;
        if changed != 1 {
            return Err(conflict());
        }
        let current_sequence: i64 = transaction
            .query_row(
                "SELECT current_sequence FROM tasks WHERE id = ?1",
                [request.claim.task_id().as_str()],
                |row| row.get(0),
            )
            .map_err(sqlite_error_to_port)?;
        let next_sequence = current_sequence.checked_add(1).ok_or_else(invalid_input)?;
        let event_id = format!(
            "executor.lease.revoked:{}:{}",
            request.claim.task_id().as_str(),
            request.claim.token().get()
        );
        let payload = json!({
            "taskId": request.claim.task_id().as_str(),
            "holderRunId": request.claim.holder_run_id().as_str(),
            "fencingToken": request.claim.token().get(),
        });
        let correlation_id = format!(
            "executor-lease:revoke:{}:{}",
            request.claim.task_id().as_str(),
            request.claim.token().get()
        );
        insert_task_event(
            &transaction,
            TaskEvent {
                task_id: request.claim.task_id().as_str(),
                sequence: next_sequence,
                event_id: &event_id,
                event_type: "executor.lease.revoked",
                payload: &payload,
                actor_id: CORE_AGENT_ID,
                correlation_id: &correlation_id,
                created_at: &request.revoked_at,
            },
        )?;
        transaction
            .execute(
                "UPDATE tasks SET current_sequence = ?1, updated_at = ?2,
                    row_version = row_version + 1
                 WHERE id = ?3 AND current_sequence = ?4",
                params![
                    next_sequence,
                    request.revoked_at,
                    request.claim.task_id().as_str(),
                    current_sequence,
                ],
            )
            .map_err(sqlite_error_to_port)?;
        transaction.commit().map_err(sqlite_error_to_port)
    }

    fn fence_stale(&self) -> Result<Vec<LeaseSnapshot>, PortError> {
        let mut connection = self.connection().map_err(open_error_to_port)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite_error_to_port)?;
        let active = {
            let mut statement = transaction
                .prepare(
                    "SELECT task_id, holder_run_id, fencing_token, status,
                            acquired_at, expires_at, released_at
                     FROM executor_leases WHERE status = 'active'
                     ORDER BY task_id",
                )
                .map_err(sqlite_error_to_port)?;
            let rows = statement
                .query_map([], raw_lease)
                .map_err(sqlite_error_to_port)?
                .collect::<Result<Vec<_>, _>>()
                .map_err(sqlite_error_to_port)?;
            rows
        };
        let mut fenced = Vec::with_capacity(active.len());
        for mut lease in active {
            let fenced_at: String = transaction
                .query_row("SELECT strftime('%Y-%m-%dT%H:%M:%fZ', 'now')", [], |row| {
                    row.get(0)
                })
                .map_err(sqlite_error_to_port)?;
            transaction
                .execute(
                    "UPDATE executor_leases SET status = 'revoked', released_at = ?1
                     WHERE task_id = ?2 AND fencing_token = ?3 AND status = 'active'",
                    params![
                        fenced_at,
                        lease.task_id.as_str(),
                        i64::try_from(lease.token.get()).map_err(|_| invalid_input())?,
                    ],
                )
                .map_err(sqlite_error_to_port)?;
            let (current_sequence, current_epoch): (i64, i64) = transaction
                .query_row(
                    "SELECT current_sequence, fencing_epoch FROM tasks WHERE id = ?1",
                    [lease.task_id.as_str()],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .map_err(sqlite_error_to_port)?;
            let next_sequence = current_sequence.checked_add(1).ok_or_else(invalid_input)?;
            let next_epoch = current_epoch.checked_add(1).ok_or_else(invalid_input)?;
            let event_id = format!(
                "executor.lease.fenced:{}:{}",
                lease.task_id.as_str(),
                lease.token.get()
            );
            let payload = json!({
                    "taskId": lease.task_id.as_str(),
                    "holderRunId": lease.holder_run_id.as_str(),
                    "fencingToken": lease.token.get(),
                    "newFencingEpoch": next_epoch,
            });
            let correlation_id = format!(
                "executor-lease:fence:{}:{}",
                lease.task_id.as_str(),
                lease.token.get()
            );
            insert_task_event(
                &transaction,
                TaskEvent {
                    task_id: lease.task_id.as_str(),
                    sequence: next_sequence,
                    event_id: &event_id,
                    event_type: "executor.lease.fenced",
                    payload: &payload,
                    actor_id: CORE_AGENT_ID,
                    correlation_id: &correlation_id,
                    created_at: &fenced_at,
                },
            )?;
            transaction
                .execute(
                    "UPDATE tasks SET fencing_epoch = ?1, current_sequence = ?2, updated_at = ?3,
                        row_version = row_version + 1
                     WHERE id = ?4 AND current_sequence = ?5 AND fencing_epoch = ?6",
                    params![
                        next_epoch,
                        next_sequence,
                        fenced_at,
                        lease.task_id.as_str(),
                        current_sequence,
                        current_epoch,
                    ],
                )
                .map_err(sqlite_error_to_port)?;
            lease.state = LeaseState::Stale;
            lease.released_at = Some(fenced_at);
            fenced.push(lease);
        }
        transaction.commit().map_err(sqlite_error_to_port)?;
        Ok(fenced)
    }

    fn assert_current(&self, claim: LeaseClaim) -> Result<(), PortError> {
        let connection = self.connection().map_err(open_error_to_port)?;
        let current_epoch: Option<i64> = connection
            .query_row(
                "SELECT fencing_epoch FROM tasks WHERE id = ?1",
                [claim.task_id().as_str()],
                |row| row.get(0),
            )
            .optional()
            .map_err(sqlite_error_to_port)?;
        let current_epoch = current_epoch.ok_or_else(not_found)?;
        let current = connection
            .query_row(
                "SELECT task_id, holder_run_id, fencing_token, status,
                        acquired_at, expires_at, released_at
                 FROM executor_leases WHERE task_id = ?1
                 ORDER BY fencing_token DESC LIMIT 1",
                [claim.task_id().as_str()],
                raw_lease,
            )
            .optional()
            .map_err(sqlite_error_to_port)?;
        if current.as_ref().is_some_and(|lease| {
            lease.state == LeaseState::Active
                && lease.holder_run_id == *claim.holder_run_id()
                && lease.token == claim.token()
                && i64::try_from(lease.token.get()).ok() == Some(current_epoch)
        }) {
            return Ok(());
        }
        let current = FencingToken::try_from(current_epoch)
            .or_else(|_| {
                current.as_ref().map(|lease| lease.token).ok_or(
                    local_agent_terminal_domain::ValueError::MustBePositive {
                        kind: "fencing token",
                        value: current_epoch,
                    },
                )
            })
            .map_err(|_| conflict())?;
        Err(PortError::stale_lease(current, claim.token()))
    }
}

fn verify_available_task_artifact(
    transaction: &Transaction<'_>,
    artifact_id: &ArtifactId,
    task_id: &TaskId,
    expected_hash: &str,
) -> Result<(), PortError> {
    let state: Option<(Option<String>, String, String)> = transaction
        .query_row(
            "SELECT task_id, availability, content_hash FROM artifacts WHERE id = ?1",
            [artifact_id.as_str()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()
        .map_err(sqlite_error_to_port)?;
    if state
        != Some((
            Some(task_id.as_str().to_owned()),
            "available".to_owned(),
            expected_hash.to_owned(),
        ))
    {
        return Err(integrity_failure());
    }
    Ok(())
}

fn verify_run(
    transaction: &Transaction<'_>,
    task_id: &TaskId,
    run_id: &RunId,
) -> Result<(), PortError> {
    let matches: bool = transaction
        .query_row(
            "SELECT EXISTS(
                SELECT 1 FROM agent_runs
                WHERE id = ?1 AND task_id = ?2 AND agent_id = ?3
                  AND status IN ('created', 'accepted', 'running')
             )",
            params![run_id.as_str(), task_id.as_str(), CORE_AGENT_ID],
            |row| row.get(0),
        )
        .map_err(sqlite_error_to_port)?;
    if !matches {
        return Err(not_found());
    }
    Ok(())
}

fn load_lease(
    connection: &Connection,
    task_id: &TaskId,
) -> Result<Option<LeaseSnapshot>, PortError> {
    connection
        .query_row(
            "SELECT task_id, holder_run_id, fencing_token, status,
                    acquired_at, expires_at, released_at
             FROM executor_leases WHERE task_id = ?1
             ORDER BY fencing_token DESC LIMIT 1",
            [task_id.as_str()],
            raw_lease,
        )
        .optional()
        .map_err(sqlite_error_to_port)
}

fn raw_lease(row: &rusqlite::Row<'_>) -> rusqlite::Result<LeaseSnapshot> {
    let task_id: String = row.get(0)?;
    let holder_run_id: String = row.get(1)?;
    let token: i64 = row.get(2)?;
    let state: String = row.get(3)?;
    Ok(LeaseSnapshot {
        task_id: TaskId::new(task_id).map_err(|_| rusqlite::Error::InvalidQuery)?,
        holder_run_id: RunId::new(holder_run_id).map_err(|_| rusqlite::Error::InvalidQuery)?,
        token: FencingToken::try_from(token).map_err(|_| rusqlite::Error::InvalidQuery)?,
        state: LeaseState::parse(&state).ok_or(rusqlite::Error::InvalidQuery)?,
        acquired_at: row.get(4)?,
        expires_at: row.get(5)?,
        released_at: row.get(6)?,
    })
}

fn stale_lease(transaction: &Transaction<'_>, claim: &LeaseClaim) -> PortError {
    let current_epoch = transaction
        .query_row(
            "SELECT fencing_epoch FROM tasks WHERE id = ?1",
            [claim.task_id().as_str()],
            |row| row.get::<_, i64>(0),
        )
        .ok()
        .and_then(|value| FencingToken::try_from(value).ok())
        .unwrap_or_else(|| claim.token());
    PortError::stale_lease(current_epoch, claim.token())
}

fn validate_core_run(request: &CoreSystemRunRequest) -> Result<(), PortError> {
    if request.context_package_id.trim().is_empty()
        || request.idempotency_key.trim().is_empty()
        || request.created_at.trim().is_empty()
    {
        return Err(invalid_input());
    }
    Ok(())
}

fn validate_acquire(request: &AcquireLease) -> Result<(), PortError> {
    if request.acquired_at.trim().is_empty() || request.expires_at.trim().is_empty() {
        return Err(invalid_input());
    }
    Ok(())
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

fn not_found() -> PortError {
    PortError::failure(
        SafeErrorClassification::NotFound,
        Retryability::NonRetryable,
    )
}
