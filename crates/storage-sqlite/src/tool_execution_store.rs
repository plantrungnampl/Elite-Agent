use std::fs;
use std::path::{Component, Path, PathBuf};

use local_agent_terminal_application::{
    ApprovalDigestPayload, NewToolExecution, NewToolIntent, OperationIntentSnapshot, PortError,
    Retryability, SafeErrorClassification, ToolExecutionCompletion, ToolExecutionId,
    ToolExecutionSnapshot, ToolExecutionStore,
};
use local_agent_terminal_domain::Sha256Digest;
use rusqlite::{params, OptionalExtension, Transaction, TransactionBehavior};
use serde_json::json;
use sha2::{Digest, Sha256};

use crate::approval_store::parse_canonical_approval_payload;
use crate::event_store::{open_error_to_port, sqlite_error_to_port};
use crate::SqliteStore;

#[derive(Debug)]
struct PersistedExecutionCompletion {
    task_id: String,
    execution_status: String,
    exit_code: Option<i32>,
    stdout_artifact_id: Option<String>,
    stderr_artifact_id: Option<String>,
    completed_at: Option<String>,
    intent_id: String,
    intent_status: String,
    result_artifact_id: Option<String>,
    external_receipt_json: Option<String>,
}

#[derive(Debug)]
pub(crate) struct StoredArtifact {
    pub id: String,
    pub task_id: String,
    pub bytes: Vec<u8>,
}

#[derive(Debug)]
struct ToolRequestEvidence {
    artifact: StoredArtifact,
    run_id: String,
    tool_name: String,
    fencing_token: Option<u64>,
}

impl ToolExecutionStore for SqliteStore {
    fn reserve(&self, request: NewToolIntent) -> Result<OperationIntentSnapshot, PortError> {
        let evidence = self.tool_request_evidence(&request.operation_digest)?;
        let mut connection = self.connection().map_err(open_error_to_port)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite_error_to_port)?;
        let idempotency_key = format!("tool:{}:{}", evidence.run_id, request.execution_id.as_str());
        transaction
            .execute(
                "INSERT OR IGNORE INTO operation_intents (
                    id, task_id, run_id, operation_kind, idempotency_class, idempotency_key,
                    canonical_request_artifact_id, operation_digest, status,
                    executor_fencing_token, lease_owner, lease_expires_at, attempt_count,
                    result_artifact_id, external_receipt_json, error_json, created_at, updated_at
                 ) VALUES (?1, ?2, ?3, ?4, 'non_repeatable', ?5, ?6, ?7, 'pending',
                    ?8, NULL, NULL, 0, NULL, NULL, NULL,
                    strftime('%Y-%m-%dT%H:%M:%fZ', 'now'),
                    strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))",
                params![
                    request.execution_id.as_str(),
                    evidence.artifact.task_id,
                    evidence.run_id,
                    evidence.tool_name,
                    idempotency_key,
                    evidence.artifact.id,
                    request.operation_digest.as_str(),
                    evidence
                        .fencing_token
                        .map(i64::try_from)
                        .transpose()
                        .map_err(|_| invalid_input())?,
                ],
            )
            .map_err(sqlite_error_to_port)?;
        let persisted: Option<(String, String, String, String)> = transaction
            .query_row(
                "SELECT task_id, run_id, canonical_request_artifact_id, operation_digest
                 FROM operation_intents WHERE id = ?1",
                [request.execution_id.as_str()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .optional()
            .map_err(sqlite_error_to_port)?;
        if persisted
            != Some((
                evidence.artifact.task_id,
                evidence.run_id,
                evidence.artifact.id,
                request.operation_digest.as_str().to_owned(),
            ))
        {
            return Err(conflict());
        }
        transaction.commit().map_err(sqlite_error_to_port)?;
        Ok(OperationIntentSnapshot {
            execution_id: request.execution_id,
            operation_digest: request.operation_digest,
        })
    }

    fn begin(&self, request: NewToolExecution) -> Result<ToolExecutionSnapshot, PortError> {
        let mut connection = self.connection().map_err(open_error_to_port)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite_error_to_port)?;
        let intent = load_intent(&transaction, &request.execution_id)?;
        if intent.status == "started" {
            if execution_matches(&transaction, &request.execution_id, &intent)? {
                transaction.rollback().map_err(sqlite_error_to_port)?;
                return Ok(ToolExecutionSnapshot {
                    execution_id: request.execution_id,
                    completed: false,
                });
            }
            return Err(conflict());
        }
        if intent.status != "pending" {
            return Err(conflict());
        }
        verify_current_lease(&transaction, &intent)?;
        let (policy_decision_id, policy_effect, policy_snapshot_digest): (String, String, String) =
            transaction
                .query_row(
                    "SELECT id, effect, policy_snapshot_digest FROM policy_decisions
                 WHERE task_id = ?1 AND operation_digest = ?2
                   AND (expires_at IS NULL OR julianday(expires_at) > julianday('now'))
                 ORDER BY created_at DESC, id DESC LIMIT 1",
                    params![intent.task_id, intent.operation_digest],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                )
                .optional()
                .map_err(sqlite_error_to_port)?
                .ok_or_else(not_found)?;
        if policy_effect == "deny" {
            return Err(permission_denied());
        }
        let approval_id: Option<String> = transaction
            .query_row(
                "SELECT a.id
                 FROM approvals a
                 JOIN events e
                   ON e.event_type = 'approval.requested'
                  AND json_extract(e.payload_json, '$.approvalId') = a.id
                 JOIN tasks t ON t.id = a.task_id
                 WHERE a.task_id = ?1 AND a.operation_digest = ?2 AND a.approval_type = 'tool'
                   AND a.status = 'invalidated' AND a.invalidation_reason = 'consumed'
                   AND julianday(a.expires_at) > julianday('now')
                   AND json_extract(e.payload_json, '$.workspaceVersion') = t.workspace_version
                   AND json_extract(e.payload_json, '$.policySnapshotDigest') = ?3
                   AND (
                       (?4 IS NULL AND json_extract(e.payload_json, '$.fencingToken') IS NULL)
                       OR json_extract(e.payload_json, '$.fencingToken') = ?4
                   )
                   AND json_extract(e.payload_json, '$.toolRequestBindingDigest') IS NOT NULL
                   AND NOT EXISTS (
                       SELECT 1 FROM tool_executions used WHERE used.approval_id = a.id
                   )
                 ORDER BY a.requested_at DESC, a.id DESC LIMIT 1",
                params![
                    intent.task_id,
                    intent.operation_digest,
                    policy_snapshot_digest,
                    intent.fencing_token,
                ],
                |row| row.get(0),
            )
            .optional()
            .map_err(sqlite_error_to_port)?;
        if policy_effect == "require_approval" && approval_id.is_none() {
            return Err(permission_denied());
        }
        let changed = transaction
            .execute(
                "UPDATE operation_intents
                 SET status = 'started', lease_owner = run_id, attempt_count = attempt_count + 1,
                     updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
                 WHERE id = ?1 AND status = 'pending'",
                [request.execution_id.as_str()],
            )
            .map_err(sqlite_error_to_port)?;
        if changed != 1 {
            return Err(conflict());
        }
        transaction
            .execute(
                "INSERT INTO tool_executions (
                    id, task_id, run_id, request_id, tool_name, arguments_artifact_id,
                    policy_decision_id, approval_id, operation_intent_id,
                    executor_fencing_token, status, started_at, completed_at, exit_code,
                    stdout_artifact_id, stderr_artifact_id
                 ) VALUES (?1, ?2, ?3, ?1, ?4, ?5, ?6, ?7, ?1, ?8, 'running',
                    strftime('%Y-%m-%dT%H:%M:%fZ', 'now'), NULL, NULL, NULL, NULL)",
                params![
                    request.execution_id.as_str(),
                    intent.task_id,
                    intent.run_id,
                    intent.operation_kind,
                    intent.artifact_id,
                    policy_decision_id,
                    approval_id,
                    intent.fencing_token,
                ],
            )
            .map_err(sqlite_error_to_port)?;
        append_tool_event(
            &transaction,
            &intent.task_id,
            request.execution_id.as_str(),
            "tool.execution.started",
            "Running",
            json!({
                "executionId": request.execution_id.as_str(),
                "operationDigest": intent.operation_digest,
                "policyDecisionId": policy_decision_id,
                "approvalId": approval_id,
                "executorFencingToken": intent.fencing_token,
            }),
        )?;
        transaction.commit().map_err(sqlite_error_to_port)?;
        Ok(ToolExecutionSnapshot {
            execution_id: request.execution_id,
            completed: false,
        })
    }

    fn finish(
        &self,
        completion: ToolExecutionCompletion,
    ) -> Result<ToolExecutionSnapshot, PortError> {
        if completion.execution_id != completion.receipt.execution_id {
            return Err(invalid_input());
        }
        let lookup: Option<(String, String, Option<String>)> = self
            .connection()
            .map_err(open_error_to_port)?
            .query_row(
                "SELECT te.task_id, te.status, oi.result_artifact_id
                 FROM tool_executions te
                 JOIN operation_intents oi ON oi.id = te.operation_intent_id
                 WHERE te.id = ?1",
                [completion.execution_id.as_str()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()
            .map_err(sqlite_error_to_port)?;
        let Some((lookup_task_id, lookup_status, result_artifact_id)) = lookup else {
            return Err(not_found());
        };
        let output = if lookup_status == "succeeded" {
            let artifact_id = result_artifact_id.ok_or_else(integrity_failure)?;
            self.artifact_by_id(
                &artifact_id,
                &completion.receipt.output_digest,
                None,
                Some(&lookup_task_id),
            )?
        } else {
            self.artifact_by_digest(
                &completion.receipt.output_digest,
                None,
                Some(&lookup_task_id),
            )?
        };
        let expected_receipt = receipt_json(&completion);
        let mut connection = self.connection().map_err(open_error_to_port)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite_error_to_port)?;
        let persisted: Option<PersistedExecutionCompletion> = transaction
            .query_row(
                "SELECT te.task_id, te.status, te.exit_code, te.stdout_artifact_id,
                        te.stderr_artifact_id, te.completed_at, te.operation_intent_id,
                        oi.status, oi.result_artifact_id, oi.external_receipt_json
                 FROM tool_executions te
                 JOIN operation_intents oi ON oi.id = te.operation_intent_id
                 WHERE te.id = ?1",
                [completion.execution_id.as_str()],
                |row| {
                    Ok(PersistedExecutionCompletion {
                        task_id: row.get(0)?,
                        execution_status: row.get(1)?,
                        exit_code: row.get(2)?,
                        stdout_artifact_id: row.get(3)?,
                        stderr_artifact_id: row.get(4)?,
                        completed_at: row.get(5)?,
                        intent_id: row.get(6)?,
                        intent_status: row.get(7)?,
                        result_artifact_id: row.get(8)?,
                        external_receipt_json: row.get(9)?,
                    })
                },
            )
            .optional()
            .map_err(sqlite_error_to_port)?;
        let Some(persisted) = persisted else {
            return Err(not_found());
        };
        if output.task_id != persisted.task_id {
            return Err(integrity_failure());
        }
        if persisted.execution_status == "succeeded" {
            if persisted.intent_status == "succeeded"
                && persisted.exit_code == completion.receipt.exit_code
                && persisted.stdout_artifact_id.as_deref() == Some(output.id.as_str())
                && persisted.stderr_artifact_id.is_none()
                && persisted
                    .completed_at
                    .as_deref()
                    .is_some_and(|value| !value.is_empty())
                && persisted.result_artifact_id.as_deref() == Some(output.id.as_str())
                && persisted.external_receipt_json.as_deref() == Some(expected_receipt.as_str())
                && completion_audit_matches(
                    &transaction,
                    &persisted.task_id,
                    &completion,
                    &output.id,
                )?
            {
                transaction.rollback().map_err(sqlite_error_to_port)?;
                return Ok(ToolExecutionSnapshot {
                    execution_id: completion.execution_id,
                    completed: true,
                });
            }
            return Err(conflict());
        }
        if persisted.execution_status != "running" || persisted.intent_status != "started" {
            return Err(conflict());
        }
        let intent_changed = transaction
            .execute(
                "UPDATE operation_intents
                 SET status = 'succeeded', result_artifact_id = ?1, external_receipt_json = ?2,
                     updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
                 WHERE id = ?3 AND status = 'started'",
                params![output.id, expected_receipt, persisted.intent_id,],
            )
            .map_err(sqlite_error_to_port)?;
        let execution_changed = transaction
            .execute(
                "UPDATE tool_executions
                 SET status = 'succeeded',
                     completed_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now'),
                     exit_code = ?1, stdout_artifact_id = ?2
                 WHERE id = ?3 AND status = 'running'",
                params![
                    completion.receipt.exit_code,
                    output.id,
                    completion.execution_id.as_str()
                ],
            )
            .map_err(sqlite_error_to_port)?;
        if intent_changed != 1 || execution_changed != 1 {
            return Err(conflict());
        }
        append_tool_event(
            &transaction,
            &persisted.task_id,
            completion.execution_id.as_str(),
            "tool.execution.completed",
            "None",
            json!({
                "executionId": completion.execution_id.as_str(),
                "status": "succeeded",
                "exitCode": completion.receipt.exit_code,
                "outputArtifactId": output.id,
                "outputDigest": completion.receipt.output_digest.as_str(),
            }),
        )?;
        transaction.commit().map_err(sqlite_error_to_port)?;
        Ok(ToolExecutionSnapshot {
            execution_id: completion.execution_id,
            completed: true,
        })
    }

    fn incomplete(&self) -> Result<Vec<ToolExecutionSnapshot>, PortError> {
        let mut connection = self.connection().map_err(open_error_to_port)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite_error_to_port)?;
        let rows = {
            let mut statement = transaction
                .prepare(
                    "SELECT te.id, te.task_id, oi.idempotency_class
                     FROM tool_executions te
                     JOIN operation_intents oi ON oi.id = te.operation_intent_id
                     WHERE te.status = 'running' AND oi.status = 'started'
                     ORDER BY te.id",
                )
                .map_err(sqlite_error_to_port)?;
            let rows = statement
                .query_map([], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                    ))
                })
                .map_err(sqlite_error_to_port)?
                .collect::<Result<Vec<_>, _>>()
                .map_err(sqlite_error_to_port)?;
            rows
        };
        let mut snapshots = Vec::with_capacity(rows.len());
        for (execution_id, task_id, idempotency_class) in rows {
            let execution_id =
                ToolExecutionId::new(execution_id).map_err(|_| integrity_failure())?;
            if idempotency_class == "non_repeatable" {
                let intent_changed = transaction
                    .execute(
                        "UPDATE operation_intents
                         SET status = 'indeterminate',
                             updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now'),
                             error_json = '{\"classification\":\"crash_without_authoritative_receipt\"}'
                         WHERE id = ?1 AND status = 'started'",
                        [execution_id.as_str()],
                    )
                    .map_err(sqlite_error_to_port)?;
                let execution_changed = transaction
                    .execute(
                        "UPDATE tool_executions
                         SET status = 'indeterminate',
                             completed_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
                         WHERE id = ?1 AND status = 'running'",
                        [execution_id.as_str()],
                    )
                    .map_err(sqlite_error_to_port)?;
                if intent_changed != 1 || execution_changed != 1 {
                    return Err(conflict());
                }
                append_tool_event(
                    &transaction,
                    &task_id,
                    execution_id.as_str(),
                    "tool.execution.indeterminate",
                    "Indeterminate",
                    json!({
                        "executionId": execution_id.as_str(),
                        "reason": "crash_without_authoritative_receipt",
                    }),
                )?;
            }
            snapshots.push(ToolExecutionSnapshot {
                execution_id,
                completed: false,
            });
        }
        transaction.commit().map_err(sqlite_error_to_port)?;
        Ok(snapshots)
    }
}

impl SqliteStore {
    fn tool_request_evidence(
        &self,
        digest: &Sha256Digest,
    ) -> Result<ToolRequestEvidence, PortError> {
        let artifact = self.artifact_by_digest(digest, None, None)?;
        let ApprovalDigestPayload::Tool(payload) =
            parse_canonical_approval_payload(&artifact.bytes)?
        else {
            return Err(invalid_input());
        };
        if payload.task_id != artifact.task_id {
            return Err(integrity_failure());
        }
        Ok(ToolRequestEvidence {
            artifact,
            run_id: payload.operation.run_id,
            tool_name: payload.operation.tool,
            fencing_token: payload.operation.executor_fencing_token,
        })
    }

    pub(crate) fn artifact_by_digest(
        &self,
        digest: &Sha256Digest,
        logical_path: Option<&str>,
        expected_task_id: Option<&str>,
    ) -> Result<StoredArtifact, PortError> {
        let connection = self.connection().map_err(open_error_to_port)?;
        let row: Option<(String, Option<String>, String, String, i64, String)> = connection
            .query_row(
                "SELECT a.id, a.task_id, p.artifact_root_path, a.storage_key,
                        a.size_bytes, a.content_hash
                 FROM artifacts a
                 JOIN projects p ON p.id = a.project_id
                 WHERE a.content_hash = ?1 AND a.availability = 'available'
                   AND (?2 IS NULL OR a.logical_path = ?2)
                   AND (?3 IS NULL OR a.task_id = ?3)
                 ORDER BY a.id LIMIT 1",
                params![digest.as_str(), logical_path, expected_task_id],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                    ))
                },
            )
            .optional()
            .map_err(sqlite_error_to_port)?;
        let Some(row) = row else {
            return Err(not_found());
        };
        stored_artifact(row)
    }

    pub(crate) fn artifact_by_id(
        &self,
        artifact_id: &str,
        digest: &Sha256Digest,
        logical_path: Option<&str>,
        expected_task_id: Option<&str>,
    ) -> Result<StoredArtifact, PortError> {
        let connection = self.connection().map_err(open_error_to_port)?;
        let row: Option<(String, Option<String>, String, String, i64, String)> = connection
            .query_row(
                "SELECT a.id, a.task_id, p.artifact_root_path, a.storage_key,
                        a.size_bytes, a.content_hash
                 FROM artifacts a
                 JOIN projects p ON p.id = a.project_id
                 WHERE a.id = ?1 AND a.content_hash = ?2 AND a.availability = 'available'
                   AND (?3 IS NULL OR a.logical_path = ?3)
                   AND (?4 IS NULL OR a.task_id = ?4)",
                params![artifact_id, digest.as_str(), logical_path, expected_task_id,],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                    ))
                },
            )
            .optional()
            .map_err(sqlite_error_to_port)?;
        let Some(row) = row else {
            return Err(not_found());
        };
        stored_artifact(row)
    }
}

fn stored_artifact(
    (id, task_id, root, storage_key, size, content_hash): (
        String,
        Option<String>,
        String,
        String,
        i64,
        String,
    ),
) -> Result<StoredArtifact, PortError> {
    let task_id = task_id.ok_or_else(integrity_failure)?;
    let path = safe_artifact_path(Path::new(&root), &storage_key)?;
    let bytes = fs::read(path).map_err(|_| integrity_failure())?;
    if i64::try_from(bytes.len()).ok() != Some(size)
        || content_hash != format!("sha256:{:x}", Sha256::digest(&bytes))
    {
        return Err(integrity_failure());
    }
    Ok(StoredArtifact { id, task_id, bytes })
}

#[derive(Debug)]
struct IntentRow {
    task_id: String,
    run_id: String,
    operation_kind: String,
    artifact_id: String,
    operation_digest: String,
    status: String,
    fencing_token: Option<i64>,
}

fn load_intent(
    transaction: &Transaction<'_>,
    execution_id: &ToolExecutionId,
) -> Result<IntentRow, PortError> {
    transaction
        .query_row(
            "SELECT task_id, run_id, operation_kind, canonical_request_artifact_id,
                    operation_digest, status, executor_fencing_token
             FROM operation_intents WHERE id = ?1",
            [execution_id.as_str()],
            |row| {
                Ok(IntentRow {
                    task_id: row.get(0)?,
                    run_id: row
                        .get::<_, Option<String>>(1)?
                        .ok_or(rusqlite::Error::InvalidQuery)?,
                    operation_kind: row.get(2)?,
                    artifact_id: row.get(3)?,
                    operation_digest: row.get(4)?,
                    status: row.get(5)?,
                    fencing_token: row.get(6)?,
                })
            },
        )
        .optional()
        .map_err(sqlite_error_to_port)?
        .ok_or_else(not_found)
}

fn verify_current_lease(
    transaction: &Transaction<'_>,
    intent: &IntentRow,
) -> Result<(), PortError> {
    let Some(token) = intent.fencing_token else {
        return Ok(());
    };
    let current: bool = transaction
        .query_row(
            "SELECT EXISTS(
                SELECT 1 FROM executor_leases l
                JOIN tasks t ON t.id = l.task_id
                WHERE l.task_id = ?1 AND l.holder_run_id = ?2
                  AND l.fencing_token = ?3 AND l.status = 'active'
                  AND julianday(l.expires_at) > julianday('now')
                  AND t.fencing_epoch = l.fencing_token
            )",
            params![intent.task_id, intent.run_id, token],
            |row| row.get(0),
        )
        .map_err(sqlite_error_to_port)?;
    if current {
        Ok(())
    } else {
        Err(conflict())
    }
}

fn execution_matches(
    transaction: &Transaction<'_>,
    execution_id: &ToolExecutionId,
    intent: &IntentRow,
) -> Result<bool, PortError> {
    transaction
        .query_row(
            "SELECT EXISTS(
                SELECT 1 FROM tool_executions
                WHERE id = ?1 AND operation_intent_id = ?1 AND task_id = ?2
                  AND run_id = ?3 AND arguments_artifact_id = ?4 AND status = 'running'
            )",
            params![
                execution_id.as_str(),
                intent.task_id,
                intent.run_id,
                intent.artifact_id
            ],
            |row| row.get(0),
        )
        .map_err(sqlite_error_to_port)
}

fn receipt_json(completion: &ToolExecutionCompletion) -> String {
    json!({
        "executionId": completion.execution_id.as_str(),
        "exitCode": completion.receipt.exit_code,
        "outputDigest": completion.receipt.output_digest.as_str(),
    })
    .to_string()
}

fn completion_audit_matches(
    transaction: &Transaction<'_>,
    task_id: &str,
    completion: &ToolExecutionCompletion,
    output_artifact_id: &str,
) -> Result<bool, PortError> {
    let payload = json!({
        "executionId": completion.execution_id.as_str(),
        "status": "succeeded",
        "exitCode": completion.receipt.exit_code,
        "outputArtifactId": output_artifact_id,
        "outputDigest": completion.receipt.output_digest.as_str(),
    })
    .to_string();
    transaction
        .query_row(
            "SELECT
                (SELECT COUNT(*) FROM events
                 WHERE stream_id = ?1 AND event_type = 'tool.execution.completed'
                   AND payload_json = ?2) = 1
                AND (SELECT operation_state FROM tasks WHERE id = ?1) = 'None'",
            params![task_id, payload],
            |row| row.get(0),
        )
        .map_err(sqlite_error_to_port)
}

fn append_tool_event(
    transaction: &Transaction<'_>,
    task_id: &str,
    execution_id: &str,
    event_type: &str,
    operation_state: &str,
    payload: serde_json::Value,
) -> Result<(), PortError> {
    let (sequence, updated_at): (i64, String) = transaction
        .query_row(
            "SELECT current_sequence + 1, strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
             FROM tasks WHERE id = ?1",
            [task_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()
        .map_err(sqlite_error_to_port)?
        .ok_or_else(not_found)?;
    transaction
        .execute(
            "INSERT INTO events (
                event_id, stream_id, sequence, event_type, schema_version, actor_type,
                actor_id, observation_class, payload_json, metadata_json, causation_id,
                correlation_id, created_at
             ) VALUES (?1, ?2, ?3, ?4, 1, 'tool', ?5, 'tool_verified',
                ?6, '{}', ?7, ?7, ?8)",
            params![
                format!("{event_type}:{execution_id}:{sequence}"),
                task_id,
                sequence,
                event_type,
                execution_id,
                payload.to_string(),
                format!("tool-execution:{execution_id}"),
                updated_at,
            ],
        )
        .map_err(sqlite_error_to_port)?;
    let changed = transaction
        .execute(
            "UPDATE tasks SET current_sequence = ?1, operation_state = ?2, updated_at = ?3
             WHERE id = ?4 AND current_sequence = ?5",
            params![sequence, operation_state, updated_at, task_id, sequence - 1],
        )
        .map_err(sqlite_error_to_port)?;
    if changed == 1 {
        Ok(())
    } else {
        Err(conflict())
    }
}

fn safe_artifact_path(root: &Path, storage_key: &str) -> Result<PathBuf, PortError> {
    let relative = Path::new(storage_key);
    if relative.is_absolute()
        || relative
            .components()
            .any(|part| !matches!(part, Component::Normal(_)))
    {
        return Err(integrity_failure());
    }
    Ok(root.join(relative))
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

fn permission_denied() -> PortError {
    PortError::failure(
        SafeErrorClassification::PermissionDenied,
        Retryability::NonRetryable,
    )
}
