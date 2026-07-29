use std::fs;
use std::path::{Component, Path, PathBuf};

use local_agent_terminal_application::{
    canonical_file_write_recovery_request, parse_file_write_recovery_request,
    ApprovalDigestPayload, CanonicalEvidenceRef, FileWritePreImage, FileWriteRecoveryCompletion,
    FileWriteRecoveryFailure, FileWriteRecoveryIntent, FileWriteRecoveryRequest,
    FileWriteRecoverySnapshot, FileWriteRecoveryState, FileWriteRecoveryStore, NewToolExecution,
    NewToolIntent, OperationIntentSnapshot, PortError, ProcessReceipt, ProcessStatus, Retryability,
    SafeErrorClassification, ToolExecutionCompletion, ToolExecutionId, ToolExecutionSnapshot,
    ToolExecutionStore, VerifiedFileWriteCompensation, WorkspaceMutationRequest,
};
use local_agent_terminal_domain::{
    ArtifactId, PolicyEffect, ProjectId, Sequence, Sha256Digest, TaskId,
};
use rusqlite::{params, OptionalExtension, Transaction, TransactionBehavior};
use serde_json::json;
use sha2::{Digest, Sha256};

use crate::approval_store::parse_canonical_approval_payload;
use crate::event_store::{open_error_to_port, sqlite_error_to_port};
use crate::workspace_store::{
    record_workspace_mutation_in_transaction, verify_evidence_ref_in_transaction,
};
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
    pub project_id: String,
    pub content_hash: String,
    pub storage_key: String,
    pub size_bytes: u64,
    pub bytes: Vec<u8>,
}

type StoredArtifactRow = (String, Option<String>, String, String, String, i64, String);

#[derive(Debug)]
struct ToolRequestEvidence {
    artifact: StoredArtifact,
    run_id: String,
    tool_name: String,
    fencing_token: Option<u64>,
}

impl FileWriteRecoveryStore for SqliteStore {
    fn prepare(
        &self,
        intent: FileWriteRecoveryIntent,
    ) -> Result<FileWriteRecoverySnapshot, PortError> {
        let canonical = canonical_file_write_recovery_request(&intent.request)?;
        if intent.request_artifact.content_hash != canonical.operation_digest.as_str()
            || intent.request_artifact.task_id.as_ref() != Some(&intent.request.task_id)
            || intent.request_artifact.project_id != intent.request.pre_evidence.project_id
        {
            return Err(invalid_input());
        }
        let request_artifact = self.artifact_by_id(
            intent.request_artifact.artifact_id.as_str(),
            &canonical.operation_digest,
            None,
            Some(intent.request.task_id.as_str()),
        )?;
        if request_artifact.bytes != canonical.canonical_bytes {
            return Err(integrity_failure());
        }
        verify_pre_image_bytes(self, &intent.request)?;

        let mut connection = self.connection().map_err(open_error_to_port)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite_error_to_port)?;
        verify_evidence_ref_in_transaction(
            &transaction,
            &intent.request_artifact,
            &intent.request.task_id,
        )?;
        verify_evidence_ref_in_transaction(
            &transaction,
            &intent.request.pre_evidence,
            &intent.request.task_id,
        )?;
        if let FileWritePreImage::Artifact(pre_image) = &intent.request.pre_image {
            verify_evidence_ref_in_transaction(&transaction, pre_image, &intent.request.task_id)?;
        }
        verify_file_write_policy(&transaction, &intent.request, &canonical.operation_digest)?;

        let idempotency_key = format!(
            "file.write:{}:{}",
            intent.request.lease_claim.holder_run_id().as_str(),
            intent.request.execution_id.as_str()
        );
        let token =
            i64::try_from(intent.request.lease_claim.token().get()).map_err(|_| invalid_input())?;
        transaction
            .execute(
                "INSERT OR IGNORE INTO operation_intents (
                    id, task_id, run_id, operation_kind, idempotency_class, idempotency_key,
                    canonical_request_artifact_id, operation_digest, status,
                    executor_fencing_token, lease_owner, lease_expires_at, attempt_count,
                    result_artifact_id, external_receipt_json, error_json, created_at, updated_at
                 ) VALUES (?1, ?2, ?3, 'file.write', 'queryable', ?4, ?5, ?6, 'pending',
                    ?7, NULL, NULL, 0, NULL, NULL, NULL,
                    strftime('%Y-%m-%dT%H:%M:%fZ', 'now'),
                    strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))",
                params![
                    intent.request.execution_id.as_str(),
                    intent.request.task_id.as_str(),
                    intent.request.lease_claim.holder_run_id().as_str(),
                    idempotency_key,
                    intent.request_artifact.artifact_id.as_str(),
                    canonical.operation_digest.as_str(),
                    token,
                ],
            )
            .map_err(sqlite_error_to_port)?;
        transaction
            .execute(
                "INSERT OR IGNORE INTO tool_executions (
                    id, task_id, run_id, request_id, tool_name, arguments_artifact_id,
                    policy_decision_id, approval_id, operation_intent_id,
                    executor_fencing_token, status, started_at, completed_at, exit_code,
                    stdout_artifact_id, stderr_artifact_id
                 ) VALUES (?1, ?2, ?3, ?1, 'file.write', ?4, ?5, ?6, ?1, ?7,
                    'pending', NULL, NULL, NULL, NULL, NULL)",
                params![
                    intent.request.execution_id.as_str(),
                    intent.request.task_id.as_str(),
                    intent.request.lease_claim.holder_run_id().as_str(),
                    intent.request_artifact.artifact_id.as_str(),
                    intent.request.policy.decision_id,
                    intent
                        .request
                        .policy
                        .approval_id
                        .as_ref()
                        .map(local_agent_terminal_application::ApprovalId::as_str),
                    token,
                ],
            )
            .map_err(sqlite_error_to_port)?;
        if !file_write_identity_matches(
            &transaction,
            &intent,
            &canonical.operation_digest,
            &idempotency_key,
        )? {
            return Err(conflict());
        }
        transaction.commit().map_err(sqlite_error_to_port)?;
        load_file_write_snapshot(self, &intent.request.execution_id)
    }

    fn start(
        &self,
        execution_id: &ToolExecutionId,
    ) -> Result<FileWriteRecoverySnapshot, PortError> {
        let snapshot = load_file_write_snapshot(self, execution_id)?;
        if snapshot.state == FileWriteRecoveryState::Started {
            return Ok(snapshot);
        }
        if snapshot.state != FileWriteRecoveryState::Prepared {
            return Err(conflict());
        }
        let canonical = canonical_file_write_recovery_request(&snapshot.request)?;
        let mut connection = self.connection().map_err(open_error_to_port)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite_error_to_port)?;
        verify_file_write_policy(&transaction, &snapshot.request, &canonical.operation_digest)?;
        verify_file_write_lease_and_sequence(&transaction, &snapshot.request)?;
        let intent_changed = transaction
            .execute(
                "UPDATE operation_intents
                 SET status = 'started', lease_owner = run_id,
                     attempt_count = attempt_count + 1,
                     updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
                 WHERE id = ?1 AND operation_kind = 'file.write' AND status = 'pending'",
                [execution_id.as_str()],
            )
            .map_err(sqlite_error_to_port)?;
        let execution_changed = transaction
            .execute(
                "UPDATE tool_executions
                 SET status = 'running',
                     started_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
                 WHERE id = ?1 AND tool_name = 'file.write' AND status = 'pending'",
                [execution_id.as_str()],
            )
            .map_err(sqlite_error_to_port)?;
        if intent_changed != 1 || execution_changed != 1 {
            return Err(conflict());
        }
        append_tool_event(
            &transaction,
            snapshot.request.task_id.as_str(),
            execution_id.as_str(),
            "tool.execution.started",
            "Running",
            json!({
                "executionId": execution_id.as_str(),
                "operationDigest": canonical.operation_digest.as_str(),
                "policyDecisionId": snapshot.request.policy.decision_id,
                "approvalId": snapshot
                    .request
                    .policy
                    .approval_id
                    .as_ref()
                    .map(local_agent_terminal_application::ApprovalId::as_str),
                "executorFencingToken": snapshot.request.lease_claim.token().get(),
            }),
        )?;
        transaction.commit().map_err(sqlite_error_to_port)?;
        load_file_write_snapshot(self, execution_id)
    }

    fn complete(
        &self,
        completion: FileWriteRecoveryCompletion,
    ) -> Result<FileWriteRecoverySnapshot, PortError> {
        let snapshot = load_file_write_snapshot(self, &completion.execution_id)?;
        validate_file_write_completion(&snapshot, &completion)?;
        if snapshot.state == FileWriteRecoveryState::Completed {
            if file_write_completion_matches(self, &snapshot, &completion)? {
                return Ok(snapshot);
            }
            return Err(conflict());
        }
        if snapshot.state != FileWriteRecoveryState::Started {
            return Err(conflict());
        }
        let post_digest = Sha256Digest::new(completion.post_evidence.content_hash.clone())
            .map_err(|_| {
                PortError::failure(
                    SafeErrorClassification::InvalidInput,
                    Retryability::NonRetryable,
                )
            })?;
        self.artifact_by_id(
            completion.post_evidence.artifact_id.as_str(),
            &post_digest,
            None,
            Some(snapshot.request.task_id.as_str()),
        )?;
        let expected_sequence = snapshot
            .request
            .expected_sequence
            .get()
            .checked_add(1)
            .ok_or_else(invalid_input)?;
        let mutation = WorkspaceMutationRequest {
            task_id: snapshot.request.task_id.clone(),
            expected_sequence: Sequence::new(expected_sequence),
            claim: snapshot.request.lease_claim.clone(),
            pre_fingerprint: snapshot.request.pre_fingerprint.clone(),
            post_fingerprint: completion.post_fingerprint.clone(),
            pre_evidence: snapshot.request.pre_evidence.clone(),
            post_evidence: completion.post_evidence.clone(),
            actor_id: snapshot.request.actor_id.clone(),
            correlation_id: snapshot.request.correlation_id.clone(),
        };
        let mut connection = self.connection().map_err(open_error_to_port)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite_error_to_port)?;
        verify_evidence_ref_in_transaction(
            &transaction,
            &completion.post_evidence,
            &snapshot.request.task_id,
        )?;
        let mutation_result = record_workspace_mutation_in_transaction(&transaction, mutation)?;
        let receipt = file_write_receipt(&snapshot, &completion, mutation_result.event_id.as_str());
        let intent_changed = transaction
            .execute(
                "UPDATE operation_intents
                 SET status = 'succeeded', result_artifact_id = ?1,
                     external_receipt_json = ?2,
                     updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
                 WHERE id = ?3 AND operation_kind = 'file.write' AND status = 'started'",
                params![
                    completion.post_evidence.artifact_id.as_str(),
                    receipt,
                    completion.execution_id.as_str(),
                ],
            )
            .map_err(sqlite_error_to_port)?;
        let execution_changed = transaction
            .execute(
                "UPDATE tool_executions
                 SET status = 'succeeded',
                     completed_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now'),
                     stdout_artifact_id = ?1
                 WHERE id = ?2 AND tool_name = 'file.write' AND status = 'running'",
                params![
                    completion.post_evidence.artifact_id.as_str(),
                    completion.execution_id.as_str(),
                ],
            )
            .map_err(sqlite_error_to_port)?;
        if intent_changed != 1 || execution_changed != 1 {
            return Err(conflict());
        }
        append_tool_event(
            &transaction,
            snapshot.request.task_id.as_str(),
            completion.execution_id.as_str(),
            "tool.execution.completed",
            "None",
            file_write_completed_event(&snapshot, &completion, mutation_result.event_id.as_str()),
        )?;
        transaction.commit().map_err(sqlite_error_to_port)?;
        load_file_write_snapshot(self, &completion.execution_id)
    }

    fn fail(
        &self,
        execution_id: &ToolExecutionId,
        failure: FileWriteRecoveryFailure,
    ) -> Result<FileWriteRecoverySnapshot, PortError> {
        let snapshot = load_file_write_snapshot(self, execution_id)?;
        let terminal = file_write_failure_transition(&snapshot, &failure)?;
        if snapshot.state == terminal.state {
            return Ok(snapshot);
        }
        let receipt = json!({
            "schema": "file-write-terminal.v1",
            "executionId": execution_id.as_str(),
            "outcome": terminal.outcome,
        })
        .to_string();
        let error = json!({
            "classification": terminal.outcome,
        })
        .to_string();
        let mut connection = self.connection().map_err(open_error_to_port)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite_error_to_port)?;
        let intent_changed = transaction
            .execute(
                "UPDATE operation_intents
                 SET status = ?1, external_receipt_json = ?2, error_json = ?3,
                     updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
                 WHERE id = ?4 AND operation_kind = 'file.write' AND status = ?5",
                params![
                    terminal.intent_status,
                    receipt,
                    error,
                    execution_id.as_str(),
                    terminal.expected_intent_status,
                ],
            )
            .map_err(sqlite_error_to_port)?;
        let execution_changed = transaction
            .execute(
                "UPDATE tool_executions
                 SET status = ?1,
                     completed_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
                 WHERE id = ?2 AND tool_name = 'file.write' AND status = ?3",
                params![
                    terminal.execution_status,
                    execution_id.as_str(),
                    terminal.expected_execution_status,
                ],
            )
            .map_err(sqlite_error_to_port)?;
        if intent_changed != 1 || execution_changed != 1 {
            return Err(conflict());
        }
        append_tool_event(
            &transaction,
            snapshot.request.task_id.as_str(),
            execution_id.as_str(),
            "tool.execution.completed",
            "None",
            json!({
                "executionId": execution_id.as_str(),
                "status": "failed",
                "outcome": terminal.outcome,
            }),
        )?;
        transaction.commit().map_err(sqlite_error_to_port)?;
        let terminal_snapshot = load_file_write_snapshot(self, execution_id)?;
        if terminal_snapshot.state == terminal.state {
            Ok(terminal_snapshot)
        } else {
            Err(integrity_failure())
        }
    }

    fn mark_indeterminate(
        &self,
        execution_id: &ToolExecutionId,
    ) -> Result<FileWriteRecoverySnapshot, PortError> {
        let snapshot = load_file_write_snapshot(self, execution_id)?;
        if snapshot.state == FileWriteRecoveryState::Indeterminate {
            return Ok(snapshot);
        }
        if snapshot.state != FileWriteRecoveryState::Started {
            return Err(conflict());
        }
        let mut connection = self.connection().map_err(open_error_to_port)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite_error_to_port)?;
        let intent_changed = transaction
            .execute(
                "UPDATE operation_intents
                 SET status = 'indeterminate',
                     error_json = '{\"classification\":\"file_write_outcome_indeterminate\"}',
                     updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
                 WHERE id = ?1 AND operation_kind = 'file.write' AND status = 'started'",
                [execution_id.as_str()],
            )
            .map_err(sqlite_error_to_port)?;
        let execution_changed = transaction
            .execute(
                "UPDATE tool_executions
                 SET status = 'indeterminate',
                     completed_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
                 WHERE id = ?1 AND tool_name = 'file.write' AND status = 'running'",
                [execution_id.as_str()],
            )
            .map_err(sqlite_error_to_port)?;
        if intent_changed != 1 || execution_changed != 1 {
            return Err(conflict());
        }
        append_tool_event(
            &transaction,
            snapshot.request.task_id.as_str(),
            execution_id.as_str(),
            "tool.execution.indeterminate",
            "Indeterminate",
            json!({
                "executionId": execution_id.as_str(),
                "reason": "file_write_outcome_indeterminate",
            }),
        )?;
        transaction.commit().map_err(sqlite_error_to_port)?;
        load_file_write_snapshot(self, execution_id)
    }

    fn recover(&self) -> Result<Vec<FileWriteRecoverySnapshot>, PortError> {
        let connection = self.connection().map_err(open_error_to_port)?;
        let mut statement = connection
            .prepare(
                "SELECT te.id
                 FROM tool_executions te
                 JOIN operation_intents oi ON oi.id = te.operation_intent_id
                 WHERE te.tool_name = 'file.write'
                   AND (
                       (te.status = 'pending' AND oi.status = 'pending')
                       OR (te.status = 'running' AND oi.status = 'started')
                       OR (te.status = 'indeterminate' AND oi.status = 'indeterminate')
                   )
                 ORDER BY te.id",
            )
            .map_err(sqlite_error_to_port)?;
        let ids = statement
            .query_map([], |row| row.get::<_, String>(0))
            .map_err(sqlite_error_to_port)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(sqlite_error_to_port)?;
        drop(statement);
        drop(connection);
        ids.into_iter()
            .map(|id| {
                ToolExecutionId::new(id)
                    .map_err(|_| integrity_failure())
                    .and_then(|id| load_file_write_snapshot(self, &id))
            })
            .collect()
    }
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
        let outcome = durable_process_outcome(&completion.receipt);
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
        let output = if lookup_status == outcome.execution_status {
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
        if persisted.execution_status == outcome.execution_status {
            if persisted.intent_status == outcome.intent_status
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
                 SET status = ?1, result_artifact_id = ?2, external_receipt_json = ?3,
                      updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
                 WHERE id = ?4 AND status = 'started'",
                params![
                    outcome.intent_status,
                    output.id,
                    expected_receipt,
                    persisted.intent_id,
                ],
            )
            .map_err(sqlite_error_to_port)?;
        let execution_changed = transaction
            .execute(
                "UPDATE tool_executions
                 SET status = ?1,
                      completed_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now'),
                      exit_code = ?2, stdout_artifact_id = ?3
                 WHERE id = ?4 AND status = 'running'",
                params![
                    outcome.execution_status,
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
                "status": outcome.event_status,
                "exitCode": completion.receipt.exit_code,
                "outputArtifactId": output.id,
                "outputDigest": completion.receipt.output_digest.as_str(),
                "receipt": receipt_value(&completion),
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

struct FileWriteFailureTransition {
    state: FileWriteRecoveryState,
    outcome: &'static str,
    expected_intent_status: &'static str,
    intent_status: &'static str,
    expected_execution_status: &'static str,
    execution_status: &'static str,
}

fn file_write_failure_transition(
    snapshot: &FileWriteRecoverySnapshot,
    failure: &FileWriteRecoveryFailure,
) -> Result<FileWriteFailureTransition, PortError> {
    let transition = match failure {
        FileWriteRecoveryFailure::NotStarted => FileWriteFailureTransition {
            state: FileWriteRecoveryState::Failed,
            outcome: "not_started",
            expected_intent_status: "pending",
            intent_status: "cancelled",
            expected_execution_status: "pending",
            execution_status: "denied",
        },
        FileWriteRecoveryFailure::RecoveredNoNetEffect(evidence) => {
            validate_recovered_pre_image(&snapshot.request, evidence)?;
            FileWriteFailureTransition {
                state: FileWriteRecoveryState::RecoveredNoNetEffect,
                outcome: "recovered_no_net_effect",
                expected_intent_status: "started",
                intent_status: "failed",
                expected_execution_status: "running",
                execution_status: "failed",
            }
        }
        FileWriteRecoveryFailure::Compensated(evidence) => {
            validate_recovered_pre_image(&snapshot.request, evidence)?;
            FileWriteFailureTransition {
                state: FileWriteRecoveryState::Compensated,
                outcome: "compensated",
                expected_intent_status: "started",
                intent_status: "failed",
                expected_execution_status: "running",
                execution_status: "failed",
            }
        }
    };
    let valid_source = snapshot.state == transition.state
        || matches!(
            (&snapshot.state, failure),
            (
                FileWriteRecoveryState::Prepared,
                FileWriteRecoveryFailure::NotStarted
            ) | (
                FileWriteRecoveryState::Started,
                FileWriteRecoveryFailure::RecoveredNoNetEffect(_)
                    | FileWriteRecoveryFailure::Compensated(_)
            )
        );
    if valid_source {
        Ok(transition)
    } else {
        Err(conflict())
    }
}

fn validate_recovered_pre_image(
    request: &FileWriteRecoveryRequest,
    evidence: &VerifiedFileWriteCompensation,
) -> Result<(), PortError> {
    let matches = match (&request.pre_image, evidence) {
        (FileWritePreImage::Absent, VerifiedFileWriteCompensation::Absent) => true,
        (
            FileWritePreImage::Artifact(pre_image),
            VerifiedFileWriteCompensation::Restored(restored),
        ) => {
            pre_image.content_hash == restored.digest.as_str()
                && pre_image.size_bytes == restored.size_bytes
        }
        _ => false,
    };
    if matches {
        Ok(())
    } else {
        Err(integrity_failure())
    }
}

#[derive(Debug)]
struct FileWriteRow {
    task_id: String,
    run_id: String,
    request_artifact_id: String,
    operation_digest: String,
    fencing_token: i64,
    intent_status: String,
    execution_status: String,
    policy_decision_id: String,
    approval_id: Option<String>,
    result_artifact_id: Option<String>,
    external_receipt_json: Option<String>,
    stdout_artifact_id: Option<String>,
    completed_at: Option<String>,
}

fn load_file_write_snapshot(
    store: &SqliteStore,
    execution_id: &ToolExecutionId,
) -> Result<FileWriteRecoverySnapshot, PortError> {
    let connection = store.connection().map_err(open_error_to_port)?;
    let row: FileWriteRow = connection
        .query_row(
            "SELECT oi.task_id, oi.run_id, oi.canonical_request_artifact_id,
                    oi.operation_digest, oi.executor_fencing_token, oi.status, te.status,
                    te.policy_decision_id, te.approval_id, oi.result_artifact_id,
                    oi.external_receipt_json, te.stdout_artifact_id, te.completed_at
             FROM operation_intents oi
             JOIN tool_executions te ON te.operation_intent_id = oi.id
             WHERE oi.id = ?1 AND oi.operation_kind = 'file.write'
               AND te.id = oi.id AND te.tool_name = 'file.write'",
            [execution_id.as_str()],
            |row| {
                Ok(FileWriteRow {
                    task_id: row.get(0)?,
                    run_id: row
                        .get::<_, Option<String>>(1)?
                        .ok_or(rusqlite::Error::InvalidQuery)?,
                    request_artifact_id: row.get(2)?,
                    operation_digest: row.get(3)?,
                    fencing_token: row
                        .get::<_, Option<i64>>(4)?
                        .ok_or(rusqlite::Error::InvalidQuery)?,
                    intent_status: row.get(5)?,
                    execution_status: row.get(6)?,
                    policy_decision_id: row.get(7)?,
                    approval_id: row.get(8)?,
                    result_artifact_id: row.get(9)?,
                    external_receipt_json: row.get(10)?,
                    stdout_artifact_id: row.get(11)?,
                    completed_at: row.get(12)?,
                })
            },
        )
        .optional()
        .map_err(sqlite_error_to_port)?
        .ok_or_else(not_found)?;
    let operation_digest =
        Sha256Digest::new(row.operation_digest.clone()).map_err(|_| integrity_failure())?;
    let artifact = store.artifact_by_id(
        &row.request_artifact_id,
        &operation_digest,
        None,
        Some(&row.task_id),
    )?;
    let request = parse_file_write_recovery_request(&artifact.bytes)?;
    let canonical = canonical_file_write_recovery_request(&request)?;
    if canonical.operation_digest != operation_digest
        || canonical.canonical_bytes != artifact.bytes
        || request.execution_id != *execution_id
        || request.task_id.as_str() != row.task_id
        || request.lease_claim.holder_run_id().as_str() != row.run_id
        || i64::try_from(request.lease_claim.token().get()).ok() != Some(row.fencing_token)
        || request.policy.decision_id != row.policy_decision_id
        || request.policy.approval_id.as_ref().map(|id| id.as_str()) != row.approval_id.as_deref()
    {
        return Err(integrity_failure());
    }
    verify_pre_image_bytes(store, &request)?;
    let state = match (row.intent_status.as_str(), row.execution_status.as_str()) {
        ("pending", "pending") => FileWriteRecoveryState::Prepared,
        ("started", "running") => FileWriteRecoveryState::Started,
        ("cancelled", "denied") => {
            require_file_write_terminal_receipt(&row, "not_started")?;
            FileWriteRecoveryState::Failed
        }
        ("failed", "failed") => match file_write_terminal_outcome(&row)?.as_str() {
            "compensated" => FileWriteRecoveryState::Compensated,
            "recovered_no_net_effect" => FileWriteRecoveryState::RecoveredNoNetEffect,
            _ => return Err(integrity_failure()),
        },
        ("succeeded", "succeeded") => {
            if row.result_artifact_id.is_none()
                || row.result_artifact_id != row.stdout_artifact_id
                || row.external_receipt_json.is_none()
                || row.completed_at.as_deref().is_none_or(str::is_empty)
            {
                return Err(integrity_failure());
            }
            FileWriteRecoveryState::Completed
        }
        ("indeterminate", "indeterminate") => FileWriteRecoveryState::Indeterminate,
        _ => return Err(integrity_failure()),
    };
    Ok(FileWriteRecoverySnapshot {
        request,
        request_artifact: artifact.evidence_ref()?,
        state,
    })
}

fn file_write_terminal_outcome(row: &FileWriteRow) -> Result<String, PortError> {
    let receipt = row
        .external_receipt_json
        .as_deref()
        .ok_or_else(integrity_failure)?;
    if row.completed_at.as_deref().is_none_or(str::is_empty)
        || row.result_artifact_id.is_some()
        || row.stdout_artifact_id.is_some()
    {
        return Err(integrity_failure());
    }
    let value: serde_json::Value =
        serde_json::from_str(receipt).map_err(|_| integrity_failure())?;
    if value.get("schema").and_then(serde_json::Value::as_str) != Some("file-write-terminal.v1") {
        return Err(integrity_failure());
    }
    value
        .get("outcome")
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned)
        .ok_or_else(integrity_failure)
}

fn require_file_write_terminal_receipt(
    row: &FileWriteRow,
    expected_outcome: &str,
) -> Result<(), PortError> {
    if file_write_terminal_outcome(row)? == expected_outcome {
        Ok(())
    } else {
        Err(integrity_failure())
    }
}

fn verify_pre_image_bytes(
    store: &SqliteStore,
    request: &FileWriteRecoveryRequest,
) -> Result<(), PortError> {
    if let FileWritePreImage::Artifact(pre_image) = &request.pre_image {
        let digest =
            Sha256Digest::new(pre_image.content_hash.clone()).map_err(|_| invalid_input())?;
        let artifact = store.artifact_by_id(
            pre_image.artifact_id.as_str(),
            &digest,
            None,
            Some(request.task_id.as_str()),
        )?;
        if artifact.evidence_ref()? != *pre_image {
            return Err(integrity_failure());
        }
    }
    Ok(())
}

fn verify_file_write_policy(
    transaction: &Transaction<'_>,
    request: &FileWriteRecoveryRequest,
    request_operation_digest: &Sha256Digest,
) -> Result<(), PortError> {
    let row: Option<(String, String, String, String, Option<String>)> = transaction
        .query_row(
            "SELECT task_id, operation_digest, policy_snapshot_digest, effect, expires_at
             FROM policy_decisions WHERE id = ?1",
            [request.policy.decision_id.as_str()],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                ))
            },
        )
        .optional()
        .map_err(sqlite_error_to_port)?;
    let Some((task_id, operation_digest, policy_snapshot_digest, effect, expires_at)) = row else {
        return Err(not_found());
    };
    if task_id != request.task_id.as_str()
        || operation_digest != request.policy.operation_digest.as_str()
        || policy_snapshot_digest != request.policy.policy_snapshot_digest.as_str()
        || effect != policy_effect_name(request.policy.effect)
    {
        return Err(conflict());
    }
    if let Some(expires_at) = expires_at {
        if !future_timestamp(transaction, &expires_at)? {
            return Err(conflict());
        }
    }
    match request.policy.effect {
        PolicyEffect::Deny => Err(permission_denied()),
        PolicyEffect::RequireApproval => {
            verify_file_write_approval(transaction, request, request_operation_digest)
        }
        PolicyEffect::Allow | PolicyEffect::AllowWithRedaction => {
            if request.policy.approval_id.is_some() {
                Err(conflict())
            } else {
                Ok(())
            }
        }
    }
}

fn verify_file_write_approval(
    transaction: &Transaction<'_>,
    request: &FileWriteRecoveryRequest,
    request_operation_digest: &Sha256Digest,
) -> Result<(), PortError> {
    let Some(approval_id) = &request.policy.approval_id else {
        return Err(permission_denied());
    };
    let fencing_token =
        i64::try_from(request.lease_claim.token().get()).map_err(|_| invalid_input())?;
    let valid: bool = transaction
        .query_row(
            "SELECT EXISTS(
                SELECT 1
                FROM approvals a
                JOIN events e
                  ON e.event_type = 'approval.requested'
                 AND json_extract(e.payload_json, '$.approvalId') = a.id
                JOIN tasks t ON t.id = a.task_id
                WHERE a.id = ?1 AND a.task_id = ?2 AND a.approval_type = 'tool'
                  AND a.operation_digest = ?3
                  AND a.status = 'invalidated' AND a.invalidation_reason = 'consumed'
                  AND julianday(a.expires_at) > julianday('now')
                  AND json_extract(e.payload_json, '$.workspaceVersion') = t.workspace_version
                  AND json_extract(e.payload_json, '$.policySnapshotDigest') = ?4
                  AND json_extract(e.payload_json, '$.fencingToken') = ?5
                  AND json_extract(e.payload_json, '$.toolRequestBindingDigest') IS NOT NULL
                  AND NOT EXISTS (
                      SELECT 1 FROM tool_executions used
                      WHERE used.approval_id = a.id AND used.id <> ?6
                  )
            )",
            params![
                approval_id.as_str(),
                request.task_id.as_str(),
                request_operation_digest.as_str(),
                request.policy.policy_snapshot_digest.as_str(),
                fencing_token,
                request.execution_id.as_str(),
            ],
            |row| row.get(0),
        )
        .map_err(sqlite_error_to_port)?;
    if valid {
        Ok(())
    } else {
        Err(permission_denied())
    }
}

fn verify_file_write_lease_and_sequence(
    transaction: &Transaction<'_>,
    request: &FileWriteRecoveryRequest,
) -> Result<(), PortError> {
    let expected_sequence =
        i64::try_from(request.expected_sequence.get()).map_err(|_| invalid_input())?;
    let expected_token =
        i64::try_from(request.lease_claim.token().get()).map_err(|_| invalid_input())?;
    let valid: bool = transaction
        .query_row(
            "SELECT EXISTS(
                SELECT 1 FROM tasks t
                JOIN executor_leases l ON l.task_id = t.id
                WHERE t.id = ?1 AND t.current_sequence = ?2
                  AND t.fencing_epoch = ?3
                  AND l.holder_run_id = ?4 AND l.fencing_token = ?3
                  AND l.status = 'active'
                  AND julianday(l.expires_at) > julianday('now')
            )",
            params![
                request.task_id.as_str(),
                expected_sequence,
                expected_token,
                request.lease_claim.holder_run_id().as_str(),
            ],
            |row| row.get(0),
        )
        .map_err(sqlite_error_to_port)?;
    if valid {
        Ok(())
    } else {
        Err(conflict())
    }
}

fn file_write_identity_matches(
    transaction: &Transaction<'_>,
    intent: &FileWriteRecoveryIntent,
    operation_digest: &Sha256Digest,
    idempotency_key: &str,
) -> Result<bool, PortError> {
    transaction
        .query_row(
            "SELECT EXISTS(
                SELECT 1
                FROM operation_intents oi
                JOIN tool_executions te ON te.operation_intent_id = oi.id
                WHERE oi.id = ?1 AND oi.task_id = ?2 AND oi.run_id = ?3
                  AND oi.operation_kind = 'file.write' AND oi.idempotency_class = 'queryable'
                  AND oi.idempotency_key = ?4 AND oi.canonical_request_artifact_id = ?5
                  AND oi.operation_digest = ?6 AND oi.executor_fencing_token = ?7
                  AND te.id = oi.id AND te.task_id = oi.task_id AND te.run_id = oi.run_id
                  AND te.request_id = oi.id AND te.tool_name = 'file.write'
                  AND te.arguments_artifact_id = oi.canonical_request_artifact_id
                  AND te.policy_decision_id = ?8
                  AND (
                      (?9 IS NULL AND te.approval_id IS NULL)
                      OR te.approval_id = ?9
                  )
                  AND te.executor_fencing_token = oi.executor_fencing_token
            )",
            params![
                intent.request.execution_id.as_str(),
                intent.request.task_id.as_str(),
                intent.request.lease_claim.holder_run_id().as_str(),
                idempotency_key,
                intent.request_artifact.artifact_id.as_str(),
                operation_digest.as_str(),
                intent.request.lease_claim.token().get(),
                intent.request.policy.decision_id,
                intent
                    .request
                    .policy
                    .approval_id
                    .as_ref()
                    .map(local_agent_terminal_application::ApprovalId::as_str),
            ],
            |row| row.get(0),
        )
        .map_err(sqlite_error_to_port)
}

fn validate_file_write_completion(
    snapshot: &FileWriteRecoverySnapshot,
    completion: &FileWriteRecoveryCompletion,
) -> Result<(), PortError> {
    if completion.execution_id != snapshot.request.execution_id
        || completion.observed_post_digest != snapshot.request.expected_post_digest
        || completion.post_evidence.task_id.as_ref() != Some(&snapshot.request.task_id)
        || completion.post_evidence.project_id != snapshot.request.pre_evidence.project_id
    {
        return Err(invalid_input());
    }
    Ok(())
}

fn file_write_receipt(
    snapshot: &FileWriteRecoverySnapshot,
    completion: &FileWriteRecoveryCompletion,
    mutation_event_id: &str,
) -> String {
    json!({
        "schema": "file-write-receipt.v1",
        "executionId": completion.execution_id.as_str(),
        "observedPostDigest": completion.observed_post_digest.as_str(),
        "postEvidenceArtifactId": completion.post_evidence.artifact_id.as_str(),
        "workspaceMutationEventId": mutation_event_id,
        "rootIdentity": snapshot.request.root_identity.as_str(),
        "relativeComponents": snapshot.request.relative_components.as_slice(),
    })
    .to_string()
}

fn file_write_completed_event(
    snapshot: &FileWriteRecoverySnapshot,
    completion: &FileWriteRecoveryCompletion,
    mutation_event_id: &str,
) -> serde_json::Value {
    json!({
        "executionId": completion.execution_id.as_str(),
        "status": "succeeded",
        "outputDigest": completion.observed_post_digest.as_str(),
        "outputArtifactId": completion.post_evidence.artifact_id.as_str(),
        "workspaceMutationEventId": mutation_event_id,
        "rootIdentity": snapshot.request.root_identity.as_str(),
        "relativeComponents": snapshot.request.relative_components.as_slice(),
    })
}

fn file_write_completion_matches(
    store: &SqliteStore,
    snapshot: &FileWriteRecoverySnapshot,
    completion: &FileWriteRecoveryCompletion,
) -> Result<bool, PortError> {
    let mutation_sequence = snapshot
        .request
        .expected_sequence
        .get()
        .checked_add(2)
        .ok_or_else(invalid_input)?;
    let mutation_event_id = format!(
        "workspace.mutated:{}:{mutation_sequence}",
        snapshot.request.task_id.as_str()
    );
    let receipt = file_write_receipt(snapshot, completion, &mutation_event_id);
    let event_payload =
        file_write_completed_event(snapshot, completion, &mutation_event_id).to_string();
    let connection = store.connection().map_err(open_error_to_port)?;
    let matches: bool = connection
        .query_row(
            "SELECT
                oi.status = 'succeeded'
                AND te.status = 'succeeded'
                AND oi.result_artifact_id = ?1
                AND te.stdout_artifact_id = ?1
                AND te.stderr_artifact_id IS NULL
                AND te.completed_at IS NOT NULL AND te.completed_at <> ''
                AND oi.external_receipt_json = ?2
                AND (
                    SELECT COUNT(*) FROM events
                    WHERE stream_id = ?3 AND event_type = 'tool.execution.completed'
                      AND payload_json = ?4
                ) = 1
             FROM operation_intents oi
             JOIN tool_executions te ON te.operation_intent_id = oi.id
             WHERE oi.id = ?5",
            params![
                completion.post_evidence.artifact_id.as_str(),
                receipt,
                snapshot.request.task_id.as_str(),
                event_payload,
                completion.execution_id.as_str(),
            ],
            |row| row.get(0),
        )
        .map_err(sqlite_error_to_port)?;
    Ok(matches)
}

fn future_timestamp(transaction: &Transaction<'_>, value: &str) -> Result<bool, PortError> {
    transaction
        .query_row("SELECT julianday(?1) > julianday('now')", [value], |row| {
            row.get(0)
        })
        .map_err(sqlite_error_to_port)
}

const fn policy_effect_name(effect: PolicyEffect) -> &'static str {
    match effect {
        PolicyEffect::Allow => "allow",
        PolicyEffect::Deny => "deny",
        PolicyEffect::RequireApproval => "require_approval",
        PolicyEffect::AllowWithRedaction => "allow_with_redaction",
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
        let row: Option<StoredArtifactRow> = connection
            .query_row(
                "SELECT a.id, a.task_id, a.project_id, p.artifact_root_path, a.storage_key,
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
                        row.get(6)?,
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
        let row: Option<StoredArtifactRow> = connection
            .query_row(
                "SELECT a.id, a.task_id, a.project_id, p.artifact_root_path, a.storage_key,
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
                        row.get(6)?,
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

fn stored_artifact(row: StoredArtifactRow) -> Result<StoredArtifact, PortError> {
    let (id, task_id, project_id, root, storage_key, size, content_hash) = row;
    let task_id = task_id.ok_or_else(integrity_failure)?;
    let path = safe_artifact_path(Path::new(&root), &storage_key)?;
    let bytes = fs::read(path).map_err(|_| integrity_failure())?;
    if i64::try_from(bytes.len()).ok() != Some(size)
        || content_hash != format!("sha256:{:x}", Sha256::digest(&bytes))
    {
        return Err(integrity_failure());
    }
    let size_bytes = u64::try_from(size).map_err(|_| integrity_failure())?;
    Ok(StoredArtifact {
        id,
        task_id,
        project_id,
        content_hash,
        storage_key,
        size_bytes,
        bytes,
    })
}

impl StoredArtifact {
    fn evidence_ref(&self) -> Result<CanonicalEvidenceRef, PortError> {
        Ok(CanonicalEvidenceRef {
            artifact_id: ArtifactId::new(self.id.clone()).map_err(|_| integrity_failure())?,
            project_id: ProjectId::new(self.project_id.clone()).map_err(|_| integrity_failure())?,
            task_id: Some(TaskId::new(self.task_id.clone()).map_err(|_| integrity_failure())?),
            content_hash: self.content_hash.clone(),
            size_bytes: self.size_bytes,
            storage_key: self.storage_key.clone(),
        })
    }
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
    receipt_value(completion).to_string()
}

fn receipt_value(completion: &ToolExecutionCompletion) -> serde_json::Value {
    let receipt = &completion.receipt;
    json!({
        "schemaVersion": 1,
        "executionId": completion.execution_id.as_str(),
        "status": process_status(receipt.status),
        "exitCode": receipt.exit_code,
        "outputDigest": receipt.output_digest.as_str(),
        "stdout": {
            "byteCount": receipt.stdout.bytes.len(),
            "truncated": receipt.stdout.truncated,
        },
        "stderr": {
            "byteCount": receipt.stderr.bytes.len(),
            "truncated": receipt.stderr.truncated,
        },
        "durationMs": receipt.duration_ms,
        "job": {
            "rootPid": receipt.job_receipt.root_pid,
            "jobId": receipt.job_receipt.job_id,
            "killOnClose": receipt.job_receipt.kill_on_close,
            "noBreakaway": receipt.job_receipt.no_breakaway,
            "jobMemoryLimit": receipt.job_receipt.job_memory_limit,
            "jobCpuTimeLimit": receipt.job_receipt.job_cpu_time_limit,
            "memoryLimitBytes": receipt.job_receipt.memory_limit_bytes,
            "cpuTimeLimitMs": receipt.job_receipt.cpu_time_limit_ms,
            "maxActiveProcesses": receipt.job_receipt.max_active_processes,
            "totalUserTimeMs": receipt.job_receipt.total_user_time_ms,
            "resourceLimitTerminated": receipt.job_receipt.resource_limit_terminated,
            "treeTerminated": receipt.job_receipt.tree_terminated,
        },
        "observedWrites": receipt.observed_writes.iter().map(|write| json!({
            "digest": write.digest.as_str(),
            "sizeBytes": write.size_bytes,
        })).collect::<Vec<_>>(),
    })
}

fn completion_audit_matches(
    transaction: &Transaction<'_>,
    task_id: &str,
    completion: &ToolExecutionCompletion,
    output_artifact_id: &str,
) -> Result<bool, PortError> {
    let outcome = durable_process_outcome(&completion.receipt);
    let payload = json!({
        "executionId": completion.execution_id.as_str(),
        "status": outcome.event_status,
        "exitCode": completion.receipt.exit_code,
        "outputArtifactId": output_artifact_id,
        "outputDigest": completion.receipt.output_digest.as_str(),
        "receipt": receipt_value(completion),
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

struct DurableProcessOutcome {
    execution_status: &'static str,
    intent_status: &'static str,
    event_status: &'static str,
}

fn durable_process_outcome(receipt: &ProcessReceipt) -> DurableProcessOutcome {
    match (receipt.status, receipt.exit_code) {
        (ProcessStatus::Exited, Some(0)) => DurableProcessOutcome {
            execution_status: "succeeded",
            intent_status: "succeeded",
            event_status: "succeeded",
        },
        (ProcessStatus::Exited, _) => DurableProcessOutcome {
            execution_status: "failed",
            intent_status: "failed",
            event_status: "failed",
        },
        (ProcessStatus::Terminated, _) => DurableProcessOutcome {
            execution_status: "terminated",
            intent_status: "failed",
            event_status: "terminated",
        },
    }
}

fn process_status(status: ProcessStatus) -> &'static str {
    match status {
        ProcessStatus::Exited => "exited",
        ProcessStatus::Terminated => "terminated",
    }
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
