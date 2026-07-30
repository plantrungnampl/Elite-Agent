use std::fs;
use std::path::{Component, Path, PathBuf};

use local_agent_terminal_application::{
    canonical_file_write_recovery_request, canonical_policy_binding_digest,
    parse_file_write_recovery_request, parse_tool_request, policy_request_for_tool,
    validate_tool_approval_request, ApprovalDigestPayload, AuthorizedToolExecutionClaim,
    CanonicalEvidenceRef, DeniedToolExecution, DurableToolExecutionArtifact,
    DurableToolExecutionArtifacts, DurableToolExecutionReceipt, FileWritePreImage,
    FileWriteRecoveryCompletion, FileWriteRecoveryFailure, FileWriteRecoveryIntent,
    FileWriteRecoveryRequest, FileWriteRecoverySnapshot, FileWriteRecoveryState,
    FileWriteRecoveryStore, IdempotencyClass, ImmutableToolRequest, IncompleteToolExecution,
    NewToolExecution, NewToolIntent, OperationIntentSnapshot, PolicyDecisionId,
    PolicyRequestBindingDigest, PortError, Retryability, SafeErrorClassification,
    SafeToolExecutionError, ToolExecutionClaim, ToolExecutionClaimAuthority,
    ToolExecutionDenialRequest, ToolExecutionId, ToolExecutionOutput,
    ToolExecutionRecoveryEvidence, ToolExecutionResolution, ToolExecutionStore,
    ToolExecutionTerminal, ToolExecutionTerminalKind, VerifiedFileWriteCompensation,
    WorkspaceMutationRequest,
};
use local_agent_terminal_domain::{
    ArtifactId, FencingToken, PolicyEffect, ProjectId, RunId, Sequence, Sha256Digest, TaskId,
    Timestamp,
};
use rusqlite::{params, OptionalExtension, Transaction, TransactionBehavior};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::approval_store::{append_approval_event, parse_canonical_approval_payload};
use crate::event_store::{open_error_to_port, sqlite_error_to_port};
use crate::policy_store::{actor_json, digest_json, effect_name, resource_json};
use crate::workspace_store::{
    record_workspace_mutation_in_transaction, verify_evidence_ref_in_transaction,
};
use crate::SqliteStore;

#[derive(Debug)]
struct PersistedToolExecution {
    task_id: String,
    run_id: Option<String>,
    request_id: String,
    tool_name: String,
    arguments_artifact_id: String,
    policy_decision_id: String,
    approval_id: Option<String>,
    operation_intent_id: String,
    executor_fencing_token: Option<i64>,
    status: String,
    started_at: Option<String>,
    exit_code: Option<i32>,
    stdout_artifact_id: Option<String>,
    stderr_artifact_id: Option<String>,
    completed_at: Option<String>,
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

    fn begin(&self, request: NewToolExecution) -> Result<ToolExecutionClaim, PortError> {
        let mut connection = self.connection().map_err(open_error_to_port)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite_error_to_port)?;
        let intent = load_intent(&transaction, &request.execution_id)?;
        validate_tool_intent(&transaction, &request.execution_id, &intent)?;
        if intent.operation_digest != request.operation_digest.as_str() {
            return Err(conflict());
        }
        match intent.status.as_str() {
            "started" => {
                let execution = load_tool_execution(&transaction, &request.execution_id)?;
                validate_tool_execution_identity(&request.execution_id, &intent, &execution)?;
                if execution.status != "running" {
                    return Err(integrity_failure());
                }
                let evidence = recovery_evidence(&request.execution_id, &intent)?;
                transaction.rollback().map_err(sqlite_error_to_port)?;
                return Ok(ToolExecutionClaim::InFlight(evidence));
            }
            "succeeded" | "failed" | "cancelled" | "interrupted" => {
                let receipt = load_terminal_receipt(&transaction, &request.execution_id, &intent)?;
                transaction.rollback().map_err(sqlite_error_to_port)?;
                return Ok(ToolExecutionClaim::Completed(receipt));
            }
            "indeterminate" if intent.external_receipt_json.is_some() => {
                let receipt = load_terminal_receipt(&transaction, &request.execution_id, &intent)?;
                transaction.rollback().map_err(sqlite_error_to_port)?;
                return Ok(ToolExecutionClaim::Completed(receipt));
            }
            "indeterminate" => {
                let execution = load_tool_execution(&transaction, &request.execution_id)?;
                validate_tool_execution_identity(&request.execution_id, &intent, &execution)?;
                if execution.status != "indeterminate"
                    || execution.completed_at.as_deref().is_some_and(str::is_empty)
                {
                    return Err(integrity_failure());
                }
                let evidence = recovery_evidence(&request.execution_id, &intent)?;
                transaction.rollback().map_err(sqlite_error_to_port)?;
                return Ok(ToolExecutionClaim::Indeterminate(evidence));
            }
            "pending" => {}
            _ => return Err(integrity_failure()),
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
        let authority = start_tool_execution(
            &transaction,
            &request.execution_id,
            &intent,
            &policy_decision_id,
            approval_id.as_deref(),
        )?;
        transaction.commit().map_err(sqlite_error_to_port)?;
        Ok(ToolExecutionClaim::Claimed(authority))
    }

    fn begin_authorized(
        &self,
        request: AuthorizedToolExecutionClaim,
    ) -> Result<ToolExecutionClaim, PortError> {
        let mut connection = self.connection().map_err(open_error_to_port)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite_error_to_port)?;
        let intent = load_intent(&transaction, &request.execution_id)?;
        validate_tool_intent(&transaction, &request.execution_id, &intent)?;
        let immutable = validate_authorized_request(&transaction, &request, &intent)?;
        if intent.status != "pending" {
            validate_existing_authorization(&transaction, &request, &immutable, &intent)?;
            return replay_existing_claim(&transaction, &request.execution_id, &intent);
        }
        verify_current_lease(&transaction, &intent)?;
        validate_exact_policy(&transaction, &request, immutable.request())?;
        let approval_id = if let Some(approval) = request.approval.as_ref() {
            validate_exact_approval(
                &transaction,
                &request,
                &immutable,
                approval,
                ExactApprovalState::Granted,
            )?;
            consume_exact_approval(&transaction, &request, approval)?;
            Some(approval.approval_id().as_str())
        } else {
            None
        };
        let authority = start_tool_execution(
            &transaction,
            &request.execution_id,
            &intent,
            request.policy_decision_id.as_str(),
            approval_id,
        )?;
        transaction.commit().map_err(sqlite_error_to_port)?;
        Ok(ToolExecutionClaim::Claimed(authority))
    }

    fn load_denied(
        &self,
        request_artifact_id: &ArtifactId,
        request: &ImmutableToolRequest,
    ) -> Result<Option<DeniedToolExecution>, PortError> {
        let mut connection = self.connection().map_err(open_error_to_port)?;
        let transaction = connection.transaction().map_err(sqlite_error_to_port)?;
        let execution_id = request.request().execution_id();
        let intent = load_intent(&transaction, execution_id)?;
        validate_denial_request_artifact(&transaction, request_artifact_id, request, &intent)?;
        if intent.status == "pending" {
            transaction.rollback().map_err(sqlite_error_to_port)?;
            return Ok(None);
        }
        if intent.status != "cancelled" {
            return Err(conflict());
        }
        let outcome = load_denied_projection(
            &transaction,
            execution_id,
            request_artifact_id,
            request,
            &intent,
        )?;
        transaction.rollback().map_err(sqlite_error_to_port)?;
        Ok(Some(outcome))
    }

    fn resolve_denied(
        &self,
        request: ToolExecutionDenialRequest,
    ) -> Result<DeniedToolExecution, PortError> {
        let mut connection = self.connection().map_err(open_error_to_port)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite_error_to_port)?;
        let execution_id = request.request.request().execution_id().clone();
        let intent = load_intent(&transaction, &execution_id)?;
        validate_denial_request_artifact(
            &transaction,
            &request.request_artifact_id,
            &request.request,
            &intent,
        )?;
        if intent.status == "cancelled" {
            validate_denial_policy(&transaction, &request, PolicyValidationMode::Terminal)?;
            let outcome = load_denied_projection(
                &transaction,
                &execution_id,
                &request.request_artifact_id,
                &request.request,
                &intent,
            )?;
            if outcome.policy_decision_id() != &request.policy_decision_id {
                return Err(integrity_failure());
            }
            transaction.rollback().map_err(sqlite_error_to_port)?;
            return Ok(outcome);
        }
        if intent.status != "pending"
            || intent.attempt_count != 0
            || intent.lease_owner.is_some()
            || intent.result_artifact_id.is_some()
            || intent.external_receipt_json.is_some()
            || intent.error_json.is_some()
        {
            return Err(conflict());
        }
        validate_denial_policy(&transaction, &request, PolicyValidationMode::Fresh)?;
        persist_denied_projection(&transaction, &request, &intent)?;
        transaction.commit().map_err(sqlite_error_to_port)?;
        Ok(DeniedToolExecution::new(
            execution_id,
            request.request_artifact_id,
            request.policy_decision_id,
        ))
    }

    fn resolve_terminal(
        &self,
        resolution: ToolExecutionResolution,
    ) -> Result<DurableToolExecutionReceipt, PortError> {
        let mut connection = self.connection().map_err(open_error_to_port)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite_error_to_port)?;
        let execution_id = resolution.authority().execution_id().clone();
        let intent = load_intent(&transaction, &execution_id).map_err(|error| {
            if error.safe_classification() == SafeErrorClassification::NotFound {
                conflict()
            } else {
                error
            }
        })?;
        let persisted_authority = authority_from_intent(&execution_id, &intent)?;
        if resolution.authority() != &persisted_authority {
            return Err(conflict());
        }
        validate_tool_intent(&transaction, &execution_id, &intent)?;
        if matches!(
            intent.status.as_str(),
            "succeeded" | "failed" | "cancelled" | "interrupted"
        ) || (intent.status == "indeterminate" && intent.external_receipt_json.is_some())
        {
            let persisted = load_terminal_receipt(&transaction, &execution_id, &intent)?;
            if persisted == *resolution.receipt() {
                transaction.rollback().map_err(sqlite_error_to_port)?;
                return Ok(persisted);
            }
            return Err(conflict());
        }
        if intent.status != "started" {
            return Err(conflict());
        }
        let execution = load_tool_execution(&transaction, &execution_id)?;
        validate_tool_execution_identity(&execution_id, &intent, &execution)?;
        if execution.status != "running" {
            return Err(integrity_failure());
        }
        validate_terminal_artifacts(
            &transaction,
            &intent.task_id,
            resolution.receipt().terminal(),
        )?;
        let outcome = terminal_outcome(resolution.receipt().terminal());
        let expected_receipt = terminal_receipt_json(resolution.receipt());
        let result_artifact_id = primary_artifact_id(resolution.receipt().terminal());
        let stdout_artifact_id =
            artifact_id(resolution.receipt().terminal(), ToolArtifactSlot::Stdout);
        let stderr_artifact_id =
            artifact_id(resolution.receipt().terminal(), ToolArtifactSlot::Stderr);
        let exit_code = resolution
            .receipt()
            .terminal()
            .output()
            .and_then(|output| output.exit_code);
        let error_json = terminal_error_json(resolution.receipt().terminal());
        let intent_changed = transaction
            .execute(
                "UPDATE operation_intents
                 SET status = ?1, result_artifact_id = ?2, external_receipt_json = ?3,
                     error_json = ?4,
                     updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
                 WHERE id = ?5 AND status = 'started' AND attempt_count = ?6",
                params![
                    outcome.intent_status,
                    result_artifact_id,
                    expected_receipt,
                    error_json,
                    execution_id.as_str(),
                    persisted_authority.attempt(),
                ],
            )
            .map_err(sqlite_error_to_port)?;
        let execution_changed = transaction
            .execute(
                "UPDATE tool_executions
                 SET status = ?1,
                      completed_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now'),
                      exit_code = ?2, stdout_artifact_id = ?3, stderr_artifact_id = ?4
                 WHERE id = ?5 AND status = 'running'",
                params![
                    outcome.execution_status,
                    exit_code,
                    stdout_artifact_id,
                    stderr_artifact_id,
                    execution_id.as_str(),
                ],
            )
            .map_err(sqlite_error_to_port)?;
        if intent_changed != 1 || execution_changed != 1 {
            return Err(conflict());
        }
        append_tool_event(
            &transaction,
            &intent.task_id,
            execution_id.as_str(),
            "tool.execution.completed",
            terminal_operation_state(resolution.receipt().terminal().kind()),
            terminal_event_payload(resolution.receipt()),
        )?;
        transaction.commit().map_err(sqlite_error_to_port)?;
        Ok(resolution.into_receipt())
    }

    fn incomplete(&self) -> Result<Vec<IncompleteToolExecution>, PortError> {
        incomplete_with_checkpoint(self, || {})
    }
}

fn validate_authorized_request(
    transaction: &Transaction<'_>,
    request: &AuthorizedToolExecutionClaim,
    intent: &IntentRow,
) -> Result<ImmutableToolRequest, PortError> {
    if intent.artifact_id != request.request_artifact_id.as_str()
        || intent.operation_digest != request.request_content_digest.as_str()
        || intent.task_id != request.task_id.as_str()
        || intent.run_id != request.run_id.as_str()
        || intent.operation_kind != request.tool_name
        || intent.fencing_token
            != request
                .fencing_token
                .map(FencingToken::get)
                .map(i64::try_from)
                .transpose()
                .map_err(|_| integrity_failure())?
    {
        return Err(integrity_failure());
    }
    validate_artifact_type(
        transaction,
        request.request_artifact_id.as_str(),
        "tool-request",
    )?;
    let artifact = artifact_by_id_on_connection(
        transaction,
        request.request_artifact_id.as_str(),
        &request.request_content_digest,
        request.task_id.as_str(),
    )?;
    let immutable = parse_tool_request(&artifact.bytes).map_err(|_| integrity_failure())?;
    let tool_request = immutable.request();
    let process = tool_request.process().process();
    let binding = process.binding();
    if immutable.binding_digest() != &request.request_binding_digest
        || tool_request.execution_id() != &request.execution_id
        || binding.task_id() != &request.task_id
        || binding.run_id() != &request.run_id
        || request.tool_name != "process.exec"
        || binding.workspace_version() != request.workspace_version
        || tool_request.policy().policy_snapshot_digest() != &request.policy_snapshot_digest
        || process.executor_fencing_token() != request.fencing_token
    {
        return Err(integrity_failure());
    }
    Ok(immutable)
}

fn validate_denial_request_artifact(
    transaction: &Transaction<'_>,
    request_artifact_id: &ArtifactId,
    request: &ImmutableToolRequest,
    intent: &IntentRow,
) -> Result<(), PortError> {
    let tool_request = request.request();
    let execution_id = tool_request.execution_id();
    let process = tool_request.process().process();
    let binding = process.binding();
    validate_tool_intent(transaction, execution_id, intent)?;
    let fencing_token = process
        .executor_fencing_token()
        .map(FencingToken::get)
        .map(i64::try_from)
        .transpose()
        .map_err(|_| integrity_failure())?;
    if intent.artifact_id != request_artifact_id.as_str()
        || intent.operation_digest != request.binding_digest().as_sha256().as_str()
        || intent.task_id != binding.task_id().as_str()
        || intent.run_id != binding.run_id().as_str()
        || intent.operation_kind != "process.exec"
        || intent.fencing_token != fencing_token
    {
        return Err(integrity_failure());
    }
    validate_artifact_type(transaction, request_artifact_id.as_str(), "tool-request")?;
    let logical_path: String = transaction
        .query_row(
            "SELECT logical_path FROM artifacts WHERE id = ?1",
            [request_artifact_id.as_str()],
            |row| row.get(0),
        )
        .optional()
        .map_err(sqlite_error_to_port)?
        .ok_or_else(not_found)?;
    if logical_path != format!("tool-requests/{}.json", execution_id.as_str()) {
        return Err(integrity_failure());
    }
    let artifact = artifact_by_id_on_connection(
        transaction,
        request_artifact_id.as_str(),
        request.binding_digest().as_sha256(),
        binding.task_id().as_str(),
    )?;
    let persisted = parse_tool_request(&artifact.bytes).map_err(|_| integrity_failure())?;
    if persisted != *request {
        return Err(integrity_failure());
    }
    Ok(())
}

fn validate_denial_policy(
    transaction: &Transaction<'_>,
    request: &ToolExecutionDenialRequest,
    mode: PolicyValidationMode,
) -> Result<(), PortError> {
    if !matches!(
        request.effect,
        PolicyEffect::Deny | PolicyEffect::AllowWithRedaction
    ) {
        return Err(integrity_failure());
    }
    let expected_binding = canonical_policy_binding_digest(&policy_request_for_tool(
        request.request.request(),
        request.checked_at,
    ))
    .map_err(|_| integrity_failure())?;
    if expected_binding != request.policy_request_binding_digest {
        return Err(integrity_failure());
    }
    validate_policy_identity(
        transaction,
        &request.policy_decision_id,
        &request.policy_request_binding_digest,
        request.request.request(),
        request.checked_at,
        effect_name(request.effect),
        mode,
    )
}

fn persist_denied_projection(
    transaction: &Transaction<'_>,
    request: &ToolExecutionDenialRequest,
    intent: &IntentRow,
) -> Result<(), PortError> {
    let execution_id = request.request.request().execution_id();
    let error = denial_error(
        execution_id,
        &request.request_artifact_id,
        &request.policy_decision_id,
    );
    let changed = transaction
        .execute(
            "UPDATE operation_intents
             SET status = 'cancelled', error_json = ?1,
                 updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
             WHERE id = ?2 AND status = 'pending' AND attempt_count = 0
               AND lease_owner IS NULL",
            params![error.to_string(), execution_id.as_str()],
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
             ) VALUES (?1, ?2, ?3, ?1, ?4, ?5, ?6, NULL, ?1, ?7, 'denied',
                NULL, strftime('%Y-%m-%dT%H:%M:%fZ', 'now'), NULL, NULL, NULL)",
            params![
                execution_id.as_str(),
                intent.task_id,
                intent.run_id,
                intent.operation_kind,
                request.request_artifact_id.as_str(),
                request.policy_decision_id.as_str(),
                intent.fencing_token,
            ],
        )
        .map_err(sqlite_error_to_port)?;
    append_tool_event(
        transaction,
        &intent.task_id,
        execution_id.as_str(),
        "tool.execution.denied",
        "None",
        denial_event_payload(
            request,
            request.request.binding_digest().as_sha256().as_str(),
        ),
    )
}

fn load_denied_projection(
    transaction: &Transaction<'_>,
    execution_id: &ToolExecutionId,
    request_artifact_id: &ArtifactId,
    request: &ImmutableToolRequest,
    intent: &IntentRow,
) -> Result<DeniedToolExecution, PortError> {
    if intent.status != "cancelled"
        || intent.attempt_count != 0
        || intent.lease_owner.is_some()
        || intent.result_artifact_id.is_some()
        || intent.external_receipt_json.is_some()
    {
        return Err(integrity_failure());
    }
    let execution = load_tool_execution(transaction, execution_id)?;
    validate_tool_execution_identity(execution_id, intent, &execution)?;
    if execution.status != "denied"
        || execution.approval_id.is_some()
        || execution.started_at.is_some()
        || execution.completed_at.as_deref().is_none_or(str::is_empty)
        || execution.exit_code.is_some()
        || execution.stdout_artifact_id.is_some()
        || execution.stderr_artifact_id.is_some()
    {
        return Err(integrity_failure());
    }
    let (policy_decision_id, effect, evaluated_at, policy_binding) =
        load_denied_policy(transaction, &execution.policy_decision_id, request)?;
    let expected_error = denial_error(execution_id, request_artifact_id, &policy_decision_id);
    let actual_error: Value =
        serde_json::from_str(intent.error_json.as_deref().ok_or_else(integrity_failure)?)
            .map_err(|_| integrity_failure())?;
    if actual_error != expected_error {
        return Err(integrity_failure());
    }
    let expected_event = denial_event_payload(
        &ToolExecutionDenialRequest {
            request_artifact_id: request_artifact_id.clone(),
            request: request.clone(),
            policy_decision_id: policy_decision_id.clone(),
            policy_request_binding_digest: policy_binding,
            effect,
            checked_at: evaluated_at,
        },
        request.binding_digest().as_sha256().as_str(),
    );
    let mut statement = transaction
        .prepare(
            "SELECT payload_json FROM events
             WHERE stream_id = ?1 AND event_type = 'tool.execution.denied'
               AND json_extract(payload_json, '$.executionId') = ?2
             ORDER BY sequence",
        )
        .map_err(sqlite_error_to_port)?;
    let payloads = statement
        .query_map(params![intent.task_id, execution_id.as_str()], |row| {
            row.get::<_, String>(0)
        })
        .map_err(sqlite_error_to_port)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(sqlite_error_to_port)?;
    let [payload] = payloads.as_slice() else {
        return Err(integrity_failure());
    };
    let payload: Value = serde_json::from_str(payload).map_err(|_| integrity_failure())?;
    if payload != expected_event {
        return Err(integrity_failure());
    }
    Ok(DeniedToolExecution::new(
        execution_id.clone(),
        request_artifact_id.clone(),
        policy_decision_id,
    ))
}

fn load_denied_policy(
    transaction: &Transaction<'_>,
    policy_decision_id: &str,
    request: &ImmutableToolRequest,
) -> Result<
    (
        PolicyDecisionId,
        PolicyEffect,
        Timestamp,
        PolicyRequestBindingDigest,
    ),
    PortError,
> {
    let (effect, evaluated_at): (String, i64) = transaction
        .query_row(
            "SELECT effect, unixepoch(created_at) FROM policy_decisions WHERE id = ?1",
            [policy_decision_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()
        .map_err(sqlite_error_to_port)?
        .ok_or_else(not_found)?;
    let effect = denial_effect(&effect)?;
    let evaluated_at = Timestamp::from_unix_seconds(evaluated_at);
    let policy_decision_id = PolicyDecisionId::from_persisted(policy_decision_id.to_owned())
        .map_err(|_| integrity_failure())?;
    let policy_binding =
        canonical_policy_binding_digest(&policy_request_for_tool(request.request(), evaluated_at))
            .map_err(|_| integrity_failure())?;
    validate_policy_identity(
        transaction,
        &policy_decision_id,
        &policy_binding,
        request.request(),
        evaluated_at,
        effect_name(effect),
        PolicyValidationMode::Terminal,
    )?;
    Ok((policy_decision_id, effect, evaluated_at, policy_binding))
}

fn denial_effect(value: &str) -> Result<PolicyEffect, PortError> {
    match value {
        "deny" => Ok(PolicyEffect::Deny),
        "allow_with_redaction" => Ok(PolicyEffect::AllowWithRedaction),
        _ => Err(integrity_failure()),
    }
}

fn denial_error(
    execution_id: &ToolExecutionId,
    request_artifact_id: &ArtifactId,
    policy_decision_id: &PolicyDecisionId,
) -> Value {
    json!({
        "kind": "policy_denied",
        "executionId": execution_id.as_str(),
        "requestArtifactId": request_artifact_id.as_str(),
        "policyDecisionId": policy_decision_id.as_str(),
    })
}

fn denial_event_payload(request: &ToolExecutionDenialRequest, operation_digest: &str) -> Value {
    json!({
        "executionId": request.request.request().execution_id().as_str(),
        "requestArtifactId": request.request_artifact_id.as_str(),
        "operationDigest": operation_digest,
        "requestBindingDigest": request.request.binding_digest().as_sha256().as_str(),
        "policyDecisionId": request.policy_decision_id.as_str(),
        "policyRequestBindingDigest": request.policy_request_binding_digest.as_sha256().as_str(),
        "policyEffect": effect_name(request.effect),
        "evaluatedAtUnix": request.checked_at.unix_seconds(),
    })
}

#[derive(Debug)]
struct ExactPolicyRow {
    task_id: Option<String>,
    actor_json: String,
    actor_binding_digest: String,
    action: String,
    resource_json: String,
    resource_digest: String,
    purpose: String,
    workflow_phase: String,
    effect: String,
    policy_snapshot_digest: String,
    operation_digest: String,
    recorded_at: Option<i64>,
    live: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PolicyValidationMode {
    Fresh,
    Approval,
    Consumed,
    Terminal,
}

fn validate_exact_policy(
    transaction: &Transaction<'_>,
    request: &AuthorizedToolExecutionClaim,
    tool_request: &local_agent_terminal_application::ToolRequest,
) -> Result<(), PortError> {
    validate_policy_identity(
        transaction,
        &request.policy_decision_id,
        &request.policy_request_binding_digest,
        tool_request,
        request.checked_at,
        if request.approval.is_some() {
            "require_approval"
        } else {
            "allow"
        },
        PolicyValidationMode::Fresh,
    )
}

fn validate_policy_identity(
    transaction: &Transaction<'_>,
    decision_id: &PolicyDecisionId,
    binding_digest: &PolicyRequestBindingDigest,
    tool_request: &local_agent_terminal_application::ToolRequest,
    checked_at: local_agent_terminal_domain::Timestamp,
    expected_effect: &str,
    mode: PolicyValidationMode,
) -> Result<(), PortError> {
    let policy_request = policy_request_for_tool(tool_request, checked_at);
    if canonical_policy_binding_digest(&policy_request).map_err(|_| integrity_failure())?
        != *binding_digest
    {
        return Err(integrity_failure());
    }
    let row = transaction
        .query_row(
            "SELECT task_id, actor_json, actor_binding_digest, action, resource_json,
                    resource_digest, purpose, workflow_phase, effect,
                    policy_snapshot_digest, operation_digest,
                    unixepoch(created_at),
                    expires_at IS NULL OR unixepoch(expires_at) > ?2
            FROM policy_decisions WHERE id = ?1",
            params![decision_id.as_str(), checked_at.unix_seconds(),],
            |row| {
                Ok(ExactPolicyRow {
                    task_id: row.get(0)?,
                    actor_json: row.get(1)?,
                    actor_binding_digest: row.get(2)?,
                    action: row.get(3)?,
                    resource_json: row.get(4)?,
                    resource_digest: row.get(5)?,
                    purpose: row.get(6)?,
                    workflow_phase: row.get(7)?,
                    effect: row.get(8)?,
                    policy_snapshot_digest: row.get(9)?,
                    operation_digest: row.get(10)?,
                    recorded_at: row.get(11)?,
                    live: row.get(12)?,
                })
            },
        )
        .optional()
        .map_err(sqlite_error_to_port)?
        .ok_or_else(not_found)?;
    let expected_actor = actor_json(&policy_request);
    let expected_resource = resource_json(&policy_request);
    let (expected_recorded_at, require_live) = match mode {
        PolicyValidationMode::Fresh => (Some(checked_at.unix_seconds()), true),
        PolicyValidationMode::Approval => (None, true),
        PolicyValidationMode::Consumed => (None, false),
        PolicyValidationMode::Terminal => (Some(checked_at.unix_seconds()), false),
    };
    let actor: Value = serde_json::from_str(&row.actor_json).map_err(|_| integrity_failure())?;
    let resource: Value =
        serde_json::from_str(&row.resource_json).map_err(|_| integrity_failure())?;
    let decision_digest = decision_id
        .as_str()
        .strip_prefix("policy-decision:")
        .map(|digest| format!("sha256:{digest}"))
        .ok_or_else(integrity_failure)?;
    if row.task_id.as_deref() != Some(policy_request.task_id.as_str())
        || actor != expected_actor
        || row.actor_binding_digest != digest_json(&expected_actor)?
        || row.action != policy_request.action.as_str()
        || resource != expected_resource
        || row.resource_digest != policy_request.resource.content_digest.as_str()
        || row.purpose != policy_request.purpose
        || row.workflow_phase != policy_request.workflow_phase
        || row.effect != expected_effect
        || row.policy_snapshot_digest != policy_request.policy_snapshot_digest.as_str()
        || row.operation_digest != decision_digest
        || expected_recorded_at.is_some_and(|expected| row.recorded_at != Some(expected))
        || (require_live && !row.live)
    {
        return Err(integrity_failure());
    }
    Ok(())
}

pub(crate) fn validate_tool_approval_policy(
    transaction: &Transaction<'_>,
    decision_id: &PolicyDecisionId,
    binding_digest: &PolicyRequestBindingDigest,
    request: &local_agent_terminal_application::ToolRequest,
    checked_at: Timestamp,
    approval_expires_at: Timestamp,
) -> Result<(), PortError> {
    let policy_expires_at: Option<i64> = transaction
        .query_row(
            "SELECT unixepoch(expires_at) FROM policy_decisions WHERE id = ?1",
            [decision_id.as_str()],
            |row| row.get(0),
        )
        .optional()
        .map_err(sqlite_error_to_port)?;
    if policy_expires_at.is_some_and(|expires_at| approval_expires_at.unix_seconds() > expires_at) {
        return Err(integrity_failure());
    }
    validate_policy_identity(
        transaction,
        decision_id,
        binding_digest,
        request,
        checked_at,
        "require_approval",
        PolicyValidationMode::Fresh,
    )
}

#[derive(Debug)]
struct ExactApprovalRow {
    task_id: String,
    approval_type: String,
    schema_version: String,
    operation_digest: String,
    status: String,
    invalidation_reason: Option<String>,
    requested_at: String,
    expires_at: String,
    request_artifact_id: String,
    artifact_logical_path: String,
    live: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ExactApprovalState {
    Granted,
    Consumed,
}

fn validate_exact_approval(
    transaction: &Transaction<'_>,
    request: &AuthorizedToolExecutionClaim,
    immutable: &ImmutableToolRequest,
    approval: &local_agent_terminal_application::ToolApprovalRequest,
    expected_state: ExactApprovalState,
) -> Result<(), PortError> {
    if approval.execution_id() != &request.execution_id
        || approval.tool_request_artifact_id() != &request.request_artifact_id
        || approval.tool_request_binding_digest() != &request.request_binding_digest
        || approval.policy_request_binding_digest() != &request.policy_request_binding_digest
    {
        return Err(integrity_failure());
    }
    let row = transaction
        .query_row(
            "SELECT a.task_id, a.approval_type, a.schema_version, a.operation_digest,
                    a.status, a.invalidation_reason, a.requested_at, a.expires_at,
                    a.request_artifact_id,
                    ar.logical_path, unixepoch(a.expires_at) > ?2
             FROM approvals a
             JOIN artifacts ar ON ar.id = a.request_artifact_id
             WHERE a.id = ?1",
            params![
                approval.approval_id().as_str(),
                request.checked_at.unix_seconds(),
            ],
            |row| {
                Ok(ExactApprovalRow {
                    task_id: row.get(0)?,
                    approval_type: row.get(1)?,
                    schema_version: row.get(2)?,
                    operation_digest: row.get(3)?,
                    status: row.get(4)?,
                    invalidation_reason: row.get(5)?,
                    requested_at: row.get(6)?,
                    expires_at: row.get(7)?,
                    request_artifact_id: row.get(8)?,
                    artifact_logical_path: row.get(9)?,
                    live: row.get(10)?,
                })
            },
        )
        .optional()
        .map_err(sqlite_error_to_port)?
        .ok_or_else(not_found)?;
    if row.task_id != request.task_id.as_str()
        || row.approval_type != "tool"
        || row.schema_version != "approval-digest.v1"
        || row.operation_digest != approval.canonical_payload().operation_digest.as_str()
        || row.requested_at != approval.payload().requested_at
        || row.expires_at != approval.payload().expires_at
        || row.request_artifact_id != approval.approval_artifact_id().as_str()
        || row.artifact_logical_path
            != format!("approvals/{}.json", approval.approval_id().as_str())
    {
        return Err(integrity_failure());
    }
    let state_matches = match expected_state {
        ExactApprovalState::Granted => row.status == "granted" && row.invalidation_reason.is_none(),
        ExactApprovalState::Consumed => {
            row.status == "invalidated" && row.invalidation_reason.as_deref() == Some("consumed")
        }
    };
    if !state_matches || (expected_state == ExactApprovalState::Granted && !row.live) {
        return Err(permission_denied());
    }
    validate_artifact_type(
        transaction,
        approval.approval_artifact_id().as_str(),
        "approval-payload",
    )?;
    let artifact = artifact_by_id_on_connection(
        transaction,
        approval.approval_artifact_id().as_str(),
        &approval.canonical_payload().operation_digest,
        request.task_id.as_str(),
    )?;
    if artifact.bytes != approval.canonical_payload().canonical_bytes {
        return Err(integrity_failure());
    }
    let mut statement = transaction
        .prepare(
            "SELECT payload_json FROM events
             WHERE stream_id = ?1 AND event_type = 'approval.requested'
               AND json_extract(payload_json, '$.approvalId') = ?2
             ORDER BY sequence",
        )
        .map_err(sqlite_error_to_port)?;
    let payloads = statement
        .query_map(
            params![request.task_id.as_str(), approval.approval_id().as_str()],
            |row| row.get::<_, String>(0),
        )
        .map_err(sqlite_error_to_port)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(sqlite_error_to_port)?;
    let [payload_json] = payloads.as_slice() else {
        return Err(integrity_failure());
    };
    let payload: Value = serde_json::from_str(payload_json).map_err(|_| integrity_failure())?;
    let expected = json!({
        "approvalId": approval.approval_id().as_str(),
        "approvalType": "tool",
        "operationDigest": approval.canonical_payload().operation_digest.as_str(),
        "executionId": request.execution_id.as_str(),
        "approvalPolicyDecisionId": approval.policy_decision_id().as_str(),
        "policyRequestBindingDigest": request.policy_request_binding_digest.as_sha256().as_str(),
        "toolRequestArtifactId": request.request_artifact_id.as_str(),
        "toolRequestBindingDigest": request.request_binding_digest.as_sha256().as_str(),
        "workspaceVersion": request.workspace_version.get(),
        "policySnapshotDigest": request.policy_snapshot_digest.as_str(),
        "fencingToken": request.fencing_token.map(FencingToken::get),
        "nonce": approval.payload().nonce,
        "requestArtifactId": approval.approval_artifact_id().as_str(),
    });
    if expected.as_object().is_none_or(|fields| {
        fields
            .iter()
            .any(|(key, value)| payload.get(key) != Some(value))
    }) {
        return Err(integrity_failure());
    }
    validate_tool_approval_request(
        immutable.request(),
        immutable,
        &request.request_artifact_id,
        &request.policy_request_binding_digest,
        approval,
    )?;
    validate_policy_identity(
        transaction,
        approval.policy_decision_id(),
        approval.policy_request_binding_digest(),
        immutable.request(),
        request.checked_at,
        "require_approval",
        match expected_state {
            ExactApprovalState::Granted => PolicyValidationMode::Approval,
            ExactApprovalState::Consumed => PolicyValidationMode::Consumed,
        },
    )
}

pub(crate) fn validate_artifact_type(
    transaction: &Transaction<'_>,
    artifact_id: &str,
    expected: &str,
) -> Result<(), PortError> {
    let artifact_type = transaction
        .query_row(
            "SELECT artifact_type FROM artifacts WHERE id = ?1",
            [artifact_id],
            |row| row.get::<_, String>(0),
        )
        .optional()
        .map_err(sqlite_error_to_port)?;
    if artifact_type.as_deref() == Some(expected) {
        Ok(())
    } else {
        Err(integrity_failure())
    }
}

fn consume_exact_approval(
    transaction: &Transaction<'_>,
    request: &AuthorizedToolExecutionClaim,
    approval: &local_agent_terminal_application::ToolApprovalRequest,
) -> Result<(), PortError> {
    let changed = transaction
        .execute(
            "UPDATE approvals
             SET status = 'invalidated', invalidation_reason = 'consumed'
             WHERE id = ?1 AND status = 'granted'
               AND unixepoch(expires_at) > ?2",
            params![
                approval.approval_id().as_str(),
                request.checked_at.unix_seconds(),
            ],
        )
        .map_err(sqlite_error_to_port)?;
    if changed != 1 {
        return Err(permission_denied());
    }
    append_approval_event(
        transaction,
        &request.task_id,
        approval.approval_id(),
        "approval.consumed",
        Some("None"),
        json!({
            "approvalId": approval.approval_id().as_str(),
            "executionId": request.execution_id.as_str(),
            "operationDigest": approval.canonical_payload().operation_digest.as_str(),
            "nonce": approval.payload().nonce,
        }),
    )
}

fn validate_existing_authorization(
    transaction: &Transaction<'_>,
    request: &AuthorizedToolExecutionClaim,
    immutable: &ImmutableToolRequest,
    intent: &IntentRow,
) -> Result<(), PortError> {
    let execution = load_tool_execution(transaction, &request.execution_id)?;
    validate_tool_execution_identity(&request.execution_id, intent, &execution)?;
    let approval_id = request
        .approval
        .as_ref()
        .map(|approval| approval.approval_id().as_str());
    if execution.policy_decision_id != request.policy_decision_id.as_str()
        || execution.approval_id.as_deref() != approval_id
    {
        return Err(integrity_failure());
    }
    if let Some(approval) = request.approval.as_ref() {
        validate_exact_approval(
            transaction,
            request,
            immutable,
            approval,
            ExactApprovalState::Consumed,
        )?;
    }
    Ok(())
}

fn replay_existing_claim(
    transaction: &Transaction<'_>,
    execution_id: &ToolExecutionId,
    intent: &IntentRow,
) -> Result<ToolExecutionClaim, PortError> {
    match intent.status.as_str() {
        "started" => {
            let execution = load_tool_execution(transaction, execution_id)?;
            validate_tool_execution_identity(execution_id, intent, &execution)?;
            if execution.status != "running" {
                return Err(integrity_failure());
            }
            recovery_evidence(execution_id, intent).map(ToolExecutionClaim::InFlight)
        }
        "succeeded" | "failed" | "cancelled" | "interrupted" => {
            load_terminal_receipt(transaction, execution_id, intent)
                .map(ToolExecutionClaim::Completed)
        }
        "indeterminate" if intent.external_receipt_json.is_some() => {
            load_terminal_receipt(transaction, execution_id, intent)
                .map(ToolExecutionClaim::Completed)
        }
        "indeterminate" => {
            let execution = load_tool_execution(transaction, execution_id)?;
            validate_tool_execution_identity(execution_id, intent, &execution)?;
            if execution.status != "indeterminate"
                || execution.completed_at.as_deref().is_some_and(str::is_empty)
            {
                return Err(integrity_failure());
            }
            recovery_evidence(execution_id, intent).map(ToolExecutionClaim::Indeterminate)
        }
        _ => Err(integrity_failure()),
    }
}

fn start_tool_execution(
    transaction: &Transaction<'_>,
    execution_id: &ToolExecutionId,
    intent: &IntentRow,
    policy_decision_id: &str,
    approval_id: Option<&str>,
) -> Result<ToolExecutionClaimAuthority, PortError> {
    let changed = transaction
        .execute(
            "UPDATE operation_intents
             SET status = 'started', lease_owner = run_id, attempt_count = attempt_count + 1,
                 updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
             WHERE id = ?1 AND status = 'pending'",
            [execution_id.as_str()],
        )
        .map_err(sqlite_error_to_port)?;
    if changed != 1 {
        return Err(conflict());
    }
    let attempt = intent
        .attempt_count
        .checked_add(1)
        .and_then(|value| u32::try_from(value).ok())
        .ok_or_else(integrity_failure)?;
    let authority = claim_authority(execution_id, intent, attempt)?;
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
                execution_id.as_str(),
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
        transaction,
        &intent.task_id,
        execution_id.as_str(),
        "tool.execution.started",
        "Running",
        json!({
            "executionId": execution_id.as_str(),
            "operationDigest": intent.operation_digest,
            "policyDecisionId": policy_decision_id,
            "approvalId": approval_id,
            "executorFencingToken": intent.fencing_token,
            "ownerRunId": authority.owner_run_id().as_str(),
            "attempt": authority.attempt(),
        }),
    )?;
    Ok(authority)
}

fn incomplete_with_checkpoint(
    store: &SqliteStore,
    after_candidate_read: impl FnOnce(),
) -> Result<Vec<IncompleteToolExecution>, PortError> {
    let mut connection = store.connection().map_err(open_error_to_port)?;
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Deferred)
        .map_err(sqlite_error_to_port)?;
    let execution_ids = {
        let mut statement = transaction
            .prepare(
                "SELECT oi.id
                 FROM operation_intents oi
                 JOIN tool_executions te ON te.operation_intent_id = oi.id
                 WHERE NOT (
                     oi.operation_kind = 'file.write'
                     AND te.tool_name = 'file.write'
                 )
                 ORDER BY oi.id",
            )
            .map_err(sqlite_error_to_port)?;
        let execution_ids = statement
            .query_map([], |row| row.get::<_, String>(0))
            .map_err(sqlite_error_to_port)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(sqlite_error_to_port)?;
        execution_ids
    };
    after_candidate_read();
    let mut incomplete = Vec::with_capacity(execution_ids.len());
    for execution_id in execution_ids {
        let execution_id = ToolExecutionId::new(execution_id).map_err(|_| integrity_failure())?;
        let intent = load_intent(&transaction, &execution_id)?;
        validate_tool_intent(&transaction, &execution_id, &intent)?;
        let execution = load_tool_execution(&transaction, &execution_id)?;
        validate_tool_execution_identity(&execution_id, &intent, &execution)?;
        match (intent.status.as_str(), execution.status.as_str()) {
            ("started", "running") => {
                incomplete.push(IncompleteToolExecution::InFlight(recovery_evidence(
                    &execution_id,
                    &intent,
                )?));
            }
            ("indeterminate", "indeterminate") if intent.external_receipt_json.is_none() => {
                incomplete.push(IncompleteToolExecution::Indeterminate(recovery_evidence(
                    &execution_id,
                    &intent,
                )?));
            }
            ("cancelled", "denied") if intent.attempt_count == 0 => {
                let request_artifact_id =
                    ArtifactId::new(intent.artifact_id.clone()).map_err(|_| integrity_failure())?;
                let operation_digest = Sha256Digest::new(intent.operation_digest.clone())
                    .map_err(|_| integrity_failure())?;
                let artifact = artifact_by_id_on_connection(
                    &transaction,
                    request_artifact_id.as_str(),
                    &operation_digest,
                    &intent.task_id,
                )?;
                let request =
                    parse_tool_request(&artifact.bytes).map_err(|_| integrity_failure())?;
                validate_denial_request_artifact(
                    &transaction,
                    &request_artifact_id,
                    &request,
                    &intent,
                )?;
                load_denied_projection(
                    &transaction,
                    &execution_id,
                    &request_artifact_id,
                    &request,
                    &intent,
                )?;
            }
            ("succeeded" | "failed" | "cancelled" | "interrupted", _)
            | ("indeterminate", "indeterminate") => {
                load_terminal_receipt(&transaction, &execution_id, &intent)?;
            }
            _ => return Err(integrity_failure()),
        }
    }
    transaction.rollback().map_err(sqlite_error_to_port)?;
    Ok(incomplete)
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
        if let Ok(immutable) = parse_tool_request(&artifact.bytes) {
            let request = immutable.request();
            let process = request.process().process();
            if process.binding().task_id().as_str() != artifact.task_id {
                return Err(integrity_failure());
            }
            return Ok(ToolRequestEvidence {
                artifact,
                run_id: process.binding().run_id().as_str().to_owned(),
                tool_name: "process.exec".to_owned(),
                fencing_token: process.executor_fencing_token().map(FencingToken::get),
            });
        }
        let ApprovalDigestPayload::Tool(payload) =
            parse_canonical_approval_payload(&artifact.bytes).map_err(|_| integrity_failure())?
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
    idempotency_class: String,
    idempotency_key: String,
    artifact_id: String,
    operation_digest: String,
    status: String,
    fencing_token: Option<i64>,
    lease_owner: Option<String>,
    attempt_count: i64,
    result_artifact_id: Option<String>,
    external_receipt_json: Option<String>,
    error_json: Option<String>,
}

fn load_intent(
    connection: &rusqlite::Connection,
    execution_id: &ToolExecutionId,
) -> Result<IntentRow, PortError> {
    connection
        .query_row(
            "SELECT task_id, run_id, operation_kind, idempotency_class, idempotency_key,
                    canonical_request_artifact_id, operation_digest, status,
                    executor_fencing_token, lease_owner, attempt_count, result_artifact_id,
                    external_receipt_json, error_json
             FROM operation_intents WHERE id = ?1",
            [execution_id.as_str()],
            |row| {
                Ok(IntentRow {
                    task_id: row.get(0)?,
                    run_id: row
                        .get::<_, Option<String>>(1)?
                        .ok_or(rusqlite::Error::InvalidQuery)?,
                    operation_kind: row.get(2)?,
                    idempotency_class: row.get(3)?,
                    idempotency_key: row.get(4)?,
                    artifact_id: row.get(5)?,
                    operation_digest: row.get(6)?,
                    status: row.get(7)?,
                    fencing_token: row.get(8)?,
                    lease_owner: row.get(9)?,
                    attempt_count: row.get(10)?,
                    result_artifact_id: row.get(11)?,
                    external_receipt_json: row.get(12)?,
                    error_json: row.get(13)?,
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

fn validate_tool_intent(
    connection: &rusqlite::Connection,
    execution_id: &ToolExecutionId,
    intent: &IntentRow,
) -> Result<(), PortError> {
    let operation_digest =
        Sha256Digest::new(intent.operation_digest.clone()).map_err(|_| integrity_failure())?;
    TaskId::new(intent.task_id.clone()).map_err(|_| integrity_failure())?;
    RunId::new(intent.run_id.clone()).map_err(|_| integrity_failure())?;
    ArtifactId::new(intent.artifact_id.clone()).map_err(|_| integrity_failure())?;
    if IdempotencyClass::parse(&intent.idempotency_class) != Some(IdempotencyClass::NonRepeatable)
        || intent.idempotency_key != format!("tool:{}:{}", intent.run_id, execution_id.as_str())
        || intent.attempt_count < 0
    {
        return Err(integrity_failure());
    }
    let artifact = artifact_by_id_on_connection(
        connection,
        &intent.artifact_id,
        &operation_digest,
        &intent.task_id,
    )?;
    let persisted_fencing_token = intent
        .fencing_token
        .map(|value| u64::try_from(value).map_err(|_| integrity_failure()))
        .transpose()?;
    if let Ok(immutable) = parse_tool_request(&artifact.bytes) {
        let request = immutable.request();
        let process = request.process().process();
        if request.execution_id() != execution_id
            || process.binding().task_id().as_str() != intent.task_id
            || process.binding().run_id().as_str() != intent.run_id
            || intent.operation_kind != "process.exec"
            || process.executor_fencing_token().map(FencingToken::get) != persisted_fencing_token
        {
            return Err(integrity_failure());
        }
    } else {
        let ApprovalDigestPayload::Tool(payload) =
            parse_canonical_approval_payload(&artifact.bytes)?
        else {
            return Err(integrity_failure());
        };
        if payload.task_id != intent.task_id
            || payload.operation.run_id != intent.run_id
            || payload.operation.tool != intent.operation_kind
            || payload.operation.executor_fencing_token != persisted_fencing_token
        {
            return Err(integrity_failure());
        }
    }
    match intent.status.as_str() {
        "pending"
            if intent.attempt_count == 0
                && intent.lease_owner.is_none()
                && intent.result_artifact_id.is_none()
                && intent.external_receipt_json.is_none()
                && intent.error_json.is_none() =>
        {
            Ok(())
        }
        "cancelled"
            if intent.attempt_count == 0
                && intent.lease_owner.is_none()
                && intent.result_artifact_id.is_none()
                && intent.external_receipt_json.is_none()
                && intent.error_json.is_some() =>
        {
            Ok(())
        }
        "started" | "succeeded" | "failed" | "cancelled" | "interrupted" | "indeterminate"
            if intent.attempt_count > 0
                && intent.lease_owner.as_deref() == Some(intent.run_id.as_str()) =>
        {
            validate_started_event(connection, execution_id, intent)
        }
        _ => Err(integrity_failure()),
    }
}

fn validate_started_event(
    connection: &rusqlite::Connection,
    execution_id: &ToolExecutionId,
    intent: &IntentRow,
) -> Result<(), PortError> {
    let valid: bool = connection
        .query_row(
            "SELECT COUNT(*) = 1
             FROM events
             WHERE stream_id = ?1 AND event_type = 'tool.execution.started'
               AND json_extract(payload_json, '$.executionId') = ?2
               AND json_extract(payload_json, '$.operationDigest') = ?3
               AND (
                   (
                       json_extract(payload_json, '$.ownerRunId') = ?4
                       AND json_extract(payload_json, '$.attempt') = ?5
                   )
                   OR (
                       json_type(payload_json, '$.ownerRunId') IS NULL
                       AND json_type(payload_json, '$.attempt') IS NULL
                   )
               )
               AND (
                   (?6 IS NULL
                       AND json_type(payload_json, '$.executorFencingToken') = 'null')
                   OR json_extract(payload_json, '$.executorFencingToken') = ?6
               )",
            params![
                intent.task_id,
                execution_id.as_str(),
                intent.operation_digest,
                intent.run_id,
                intent.attempt_count,
                intent.fencing_token,
            ],
            |row| row.get(0),
        )
        .map_err(sqlite_error_to_port)?;
    if valid {
        Ok(())
    } else {
        Err(integrity_failure())
    }
}

pub(crate) fn artifact_by_id_on_connection(
    connection: &rusqlite::Connection,
    artifact_id: &str,
    digest: &Sha256Digest,
    task_id: &str,
) -> Result<StoredArtifact, PortError> {
    let row: Option<StoredArtifactRow> = connection
        .query_row(
            "SELECT a.id, a.task_id, a.project_id, p.artifact_root_path, a.storage_key,
                    a.size_bytes, a.content_hash
             FROM artifacts a
             JOIN projects p ON p.id = a.project_id
             WHERE a.id = ?1 AND a.content_hash = ?2 AND a.availability = 'available'
               AND a.verification_state IN (
                   'hash_verified', 'tool_verified', 'user_approved'
               )
               AND a.task_id = ?3",
            params![artifact_id, digest.as_str(), task_id],
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
    stored_artifact(row.ok_or_else(integrity_failure)?)
}

fn load_tool_execution(
    connection: &rusqlite::Connection,
    execution_id: &ToolExecutionId,
) -> Result<PersistedToolExecution, PortError> {
    connection
        .query_row(
            "SELECT task_id, run_id, request_id, tool_name, arguments_artifact_id,
                    policy_decision_id, approval_id, operation_intent_id,
                    executor_fencing_token, status, started_at, exit_code,
                    stdout_artifact_id, stderr_artifact_id, completed_at
             FROM tool_executions WHERE id = ?1",
            [execution_id.as_str()],
            |row| {
                Ok(PersistedToolExecution {
                    task_id: row.get(0)?,
                    run_id: row.get(1)?,
                    request_id: row.get(2)?,
                    tool_name: row.get(3)?,
                    arguments_artifact_id: row.get(4)?,
                    policy_decision_id: row.get(5)?,
                    approval_id: row.get(6)?,
                    operation_intent_id: row.get(7)?,
                    executor_fencing_token: row.get(8)?,
                    status: row.get(9)?,
                    started_at: row.get(10)?,
                    exit_code: row.get(11)?,
                    stdout_artifact_id: row.get(12)?,
                    stderr_artifact_id: row.get(13)?,
                    completed_at: row.get(14)?,
                })
            },
        )
        .optional()
        .map_err(sqlite_error_to_port)?
        .ok_or_else(integrity_failure)
}

fn validate_tool_execution_identity(
    execution_id: &ToolExecutionId,
    intent: &IntentRow,
    execution: &PersistedToolExecution,
) -> Result<(), PortError> {
    if execution.task_id != intent.task_id
        || execution.run_id.as_deref() != Some(intent.run_id.as_str())
        || execution.request_id != execution_id.as_str()
        || execution.tool_name != intent.operation_kind
        || execution.arguments_artifact_id != intent.artifact_id
        || execution.operation_intent_id != execution_id.as_str()
        || execution.executor_fencing_token != intent.fencing_token
    {
        return Err(integrity_failure());
    }
    Ok(())
}

fn claim_authority(
    execution_id: &ToolExecutionId,
    intent: &IntentRow,
    attempt: u32,
) -> Result<ToolExecutionClaimAuthority, PortError> {
    ToolExecutionClaimAuthority::from_persisted(
        execution_id.clone(),
        Sha256Digest::new(intent.operation_digest.clone()).map_err(|_| integrity_failure())?,
        RunId::new(intent.run_id.clone()).map_err(|_| integrity_failure())?,
        attempt,
        intent
            .fencing_token
            .map(|value| FencingToken::try_from(value).map_err(|_| integrity_failure()))
            .transpose()?,
    )
    .map_err(|_| integrity_failure())
}

fn authority_from_intent(
    execution_id: &ToolExecutionId,
    intent: &IntentRow,
) -> Result<ToolExecutionClaimAuthority, PortError> {
    let attempt = u32::try_from(intent.attempt_count).map_err(|_| integrity_failure())?;
    claim_authority(execution_id, intent, attempt)
}

fn recovery_evidence(
    execution_id: &ToolExecutionId,
    intent: &IntentRow,
) -> Result<ToolExecutionRecoveryEvidence, PortError> {
    Ok(ToolExecutionRecoveryEvidence {
        authority: authority_from_intent(execution_id, intent)?,
        task_id: TaskId::new(intent.task_id.clone()).map_err(|_| integrity_failure())?,
        canonical_request_artifact_id: ArtifactId::new(intent.artifact_id.clone())
            .map_err(|_| integrity_failure())?,
        idempotency_class: IdempotencyClass::parse(&intent.idempotency_class)
            .ok_or_else(integrity_failure)?,
    })
}

struct TerminalOutcome {
    intent_status: &'static str,
    execution_status: &'static str,
}

fn terminal_outcome(terminal: &ToolExecutionTerminal) -> TerminalOutcome {
    match terminal.kind() {
        ToolExecutionTerminalKind::Succeeded => TerminalOutcome {
            intent_status: "succeeded",
            execution_status: "succeeded",
        },
        ToolExecutionTerminalKind::Failed => TerminalOutcome {
            intent_status: "failed",
            execution_status: "failed",
        },
        ToolExecutionTerminalKind::Cancelled => TerminalOutcome {
            intent_status: "cancelled",
            execution_status: "cancelled",
        },
        ToolExecutionTerminalKind::Terminated => TerminalOutcome {
            intent_status: "failed",
            execution_status: "terminated",
        },
        ToolExecutionTerminalKind::Interrupted => TerminalOutcome {
            intent_status: "interrupted",
            execution_status: "interrupted",
        },
        ToolExecutionTerminalKind::Indeterminate => TerminalOutcome {
            intent_status: "indeterminate",
            execution_status: "indeterminate",
        },
    }
}

#[derive(Clone, Copy)]
enum ToolArtifactSlot {
    Stdout,
    Stderr,
}

fn artifact_id(terminal: &ToolExecutionTerminal, slot: ToolArtifactSlot) -> Option<&str> {
    let artifacts = &terminal.output()?.artifacts;
    let artifact = match slot {
        ToolArtifactSlot::Stdout => artifacts.stdout(),
        ToolArtifactSlot::Stderr => artifacts.stderr(),
    };
    match artifact {
        DurableToolExecutionArtifact::Available(id) => Some(id.as_str()),
        DurableToolExecutionArtifact::Unavailable => None,
    }
}

fn primary_artifact_id(terminal: &ToolExecutionTerminal) -> Option<&str> {
    artifact_id(terminal, ToolArtifactSlot::Stdout)
        .or_else(|| artifact_id(terminal, ToolArtifactSlot::Stderr))
        .or_else(|| {
            terminal
                .output()?
                .artifacts
                .observed_writes()
                .iter()
                .find_map(|artifact| match artifact {
                    DurableToolExecutionArtifact::Available(id) => Some(id.as_str()),
                    DurableToolExecutionArtifact::Unavailable => None,
                })
        })
}

fn validate_terminal_artifacts(
    connection: &rusqlite::Connection,
    task_id: &str,
    terminal: &ToolExecutionTerminal,
) -> Result<(), PortError> {
    let Some(output) = terminal.output() else {
        return Ok(());
    };
    for artifact in std::iter::once(output.artifacts.stdout())
        .chain(std::iter::once(output.artifacts.stderr()))
        .chain(output.artifacts.observed_writes())
    {
        let DurableToolExecutionArtifact::Available(artifact_id) = artifact else {
            continue;
        };
        let content_hash: Option<String> = connection
            .query_row(
                "SELECT content_hash FROM artifacts WHERE id = ?1 AND task_id = ?2",
                params![artifact_id.as_str(), task_id],
                |row| row.get(0),
            )
            .optional()
            .map_err(sqlite_error_to_port)?;
        let digest = Sha256Digest::new(content_hash.ok_or_else(integrity_failure)?)
            .map_err(|_| integrity_failure())?;
        artifact_by_id_on_connection(connection, artifact_id.as_str(), &digest, task_id)?;
    }
    Ok(())
}

const fn terminal_operation_state(kind: ToolExecutionTerminalKind) -> &'static str {
    match kind {
        ToolExecutionTerminalKind::Indeterminate => "Indeterminate",
        ToolExecutionTerminalKind::Succeeded
        | ToolExecutionTerminalKind::Failed
        | ToolExecutionTerminalKind::Cancelled
        | ToolExecutionTerminalKind::Terminated
        | ToolExecutionTerminalKind::Interrupted => "None",
    }
}

fn terminal_receipt_json(receipt: &DurableToolExecutionReceipt) -> String {
    terminal_receipt_value(receipt).to_string()
}

fn terminal_receipt_value(receipt: &DurableToolExecutionReceipt) -> serde_json::Value {
    let authority = receipt.authority();
    json!({
        "authority": {
            "attempt": authority.attempt(),
            "executionId": authority.execution_id().as_str(),
            "executorFencingToken": authority.executor_fencing_token().map(FencingToken::get),
            "operationDigest": authority.operation_digest().as_str(),
            "ownerRunId": authority.owner_run_id().as_str(),
        },
        "schema": "tool-execution-terminal.v1",
        "terminal": terminal_value(receipt.terminal()),
    })
}

fn terminal_value(terminal: &ToolExecutionTerminal) -> serde_json::Value {
    match terminal.kind() {
        ToolExecutionTerminalKind::Succeeded
        | ToolExecutionTerminalKind::Failed
        | ToolExecutionTerminalKind::Terminated => {
            let output = terminal
                .output()
                .expect("output-bearing terminal kind has output");
            json!({
                "kind": terminal_kind_name(terminal.kind()),
                "output": {
                    "artifacts": {
                        "observedWrites": output
                            .artifacts
                            .observed_writes()
                            .iter()
                            .map(artifact_value)
                            .collect::<Vec<_>>(),
                        "stderr": artifact_value(output.artifacts.stderr()),
                        "stdout": artifact_value(output.artifacts.stdout()),
                    },
                    "durationMs": output.duration_ms,
                    "exitCode": output.exit_code,
                    "outputDigest": output.output_digest.as_str(),
                },
            })
        }
        ToolExecutionTerminalKind::Indeterminate => {
            let error = terminal
                .error()
                .expect("indeterminate terminal kind has an error");
            json!({
                "error": {
                    "classification": error_classification_name(error.classification),
                    "retryability": retryability_name(error.retryability),
                },
                "kind": terminal_kind_name(terminal.kind()),
            })
        }
        ToolExecutionTerminalKind::Cancelled | ToolExecutionTerminalKind::Interrupted => {
            json!({ "kind": terminal_kind_name(terminal.kind()) })
        }
    }
}

fn artifact_value(artifact: &DurableToolExecutionArtifact) -> serde_json::Value {
    match artifact {
        DurableToolExecutionArtifact::Available(id) => json!({
            "artifactId": id.as_str(),
            "availability": "available",
        }),
        DurableToolExecutionArtifact::Unavailable => json!({
            "availability": "unavailable",
        }),
    }
}

const fn terminal_kind_name(kind: ToolExecutionTerminalKind) -> &'static str {
    match kind {
        ToolExecutionTerminalKind::Succeeded => "succeeded",
        ToolExecutionTerminalKind::Failed => "failed",
        ToolExecutionTerminalKind::Cancelled => "cancelled",
        ToolExecutionTerminalKind::Terminated => "terminated",
        ToolExecutionTerminalKind::Interrupted => "interrupted",
        ToolExecutionTerminalKind::Indeterminate => "indeterminate",
    }
}

const fn error_classification_name(classification: SafeErrorClassification) -> &'static str {
    match classification {
        SafeErrorClassification::Conflict => "conflict",
        SafeErrorClassification::Unavailable => "unavailable",
        SafeErrorClassification::PermissionDenied => "permission_denied",
        SafeErrorClassification::NotFound => "not_found",
        SafeErrorClassification::InvalidInput => "invalid_input",
        SafeErrorClassification::IntegrityFailure => "integrity_failure",
        SafeErrorClassification::StorageFull => "storage_full",
        SafeErrorClassification::Internal => "internal",
    }
}

const fn retryability_name(retryability: Retryability) -> &'static str {
    match retryability {
        Retryability::Retryable => "retryable",
        Retryability::NonRetryable => "non_retryable",
    }
}

fn terminal_error_json(terminal: &ToolExecutionTerminal) -> Option<String> {
    terminal.error().map(|error| {
        json!({
            "classification": error_classification_name(error.classification),
            "retryability": retryability_name(error.retryability),
        })
        .to_string()
    })
}

fn terminal_event_payload(receipt: &DurableToolExecutionReceipt) -> serde_json::Value {
    json!({
        "attempt": receipt.authority().attempt(),
        "executionId": receipt.authority().execution_id().as_str(),
        "operationDigest": receipt.authority().operation_digest().as_str(),
        "ownerRunId": receipt.authority().owner_run_id().as_str(),
        "receipt": terminal_receipt_value(receipt),
    })
}

fn parse_terminal_receipt(value: &str) -> Result<DurableToolExecutionReceipt, PortError> {
    let value: serde_json::Value = serde_json::from_str(value).map_err(|_| integrity_failure())?;
    if required_string(&value, "schema")? != "tool-execution-terminal.v1" {
        return Err(integrity_failure());
    }
    let authority = required_object(&value, "authority")?;
    let execution_id = ToolExecutionId::new(required_string(authority, "executionId")?)
        .map_err(|_| integrity_failure())?;
    let operation_digest = Sha256Digest::new(required_string(authority, "operationDigest")?)
        .map_err(|_| integrity_failure())?;
    let owner_run_id =
        RunId::new(required_string(authority, "ownerRunId")?).map_err(|_| integrity_failure())?;
    let attempt =
        u32::try_from(required_u64(authority, "attempt")?).map_err(|_| integrity_failure())?;
    let executor_fencing_token = match authority.get("executorFencingToken") {
        Some(serde_json::Value::Null) => None,
        Some(value) => Some(
            FencingToken::new(value.as_u64().ok_or_else(integrity_failure)?)
                .map_err(|_| integrity_failure())?,
        ),
        None => return Err(integrity_failure()),
    };
    let authority = ToolExecutionClaimAuthority::from_persisted(
        execution_id,
        operation_digest,
        owner_run_id,
        attempt,
        executor_fencing_token,
    )
    .map_err(|_| integrity_failure())?;

    let terminal = required_object(&value, "terminal")?;
    let kind = required_string(terminal, "kind")?;
    let terminal = match kind {
        "succeeded" => ToolExecutionTerminal::succeeded(parse_terminal_output(terminal)?),
        "failed" => ToolExecutionTerminal::failed(parse_terminal_output(terminal)?),
        "terminated" => ToolExecutionTerminal::terminated(parse_terminal_output(terminal)?),
        "cancelled" => Ok(ToolExecutionTerminal::cancelled()),
        "interrupted" => Ok(ToolExecutionTerminal::interrupted()),
        "indeterminate" => {
            let error = required_object(terminal, "error")?;
            Ok(ToolExecutionTerminal::indeterminate(
                SafeToolExecutionError {
                    classification: parse_error_classification(required_string(
                        error,
                        "classification",
                    )?)?,
                    retryability: parse_retryability(required_string(error, "retryability")?)?,
                },
            ))
        }
        _ => Err(integrity_failure()),
    }
    .map_err(|_| integrity_failure())?;
    Ok(DurableToolExecutionReceipt::new(authority, terminal))
}

struct ParsedPersistedReceipt {
    receipt: DurableToolExecutionReceipt,
    audit_payload: serde_json::Value,
    current_schema: bool,
}

fn parse_persisted_terminal_receipt(
    connection: &rusqlite::Connection,
    receipt_json: &str,
    execution_id: &ToolExecutionId,
    intent: &IntentRow,
    execution: &PersistedToolExecution,
) -> Result<ParsedPersistedReceipt, PortError> {
    let value: serde_json::Value =
        serde_json::from_str(receipt_json).map_err(|_| integrity_failure())?;
    if value.get("schema").is_some() {
        let receipt = parse_terminal_receipt(receipt_json)?;
        let audit_payload = terminal_event_payload(&receipt);
        return Ok(ParsedPersistedReceipt {
            receipt,
            audit_payload,
            current_schema: true,
        });
    }
    if value
        .get("schemaVersion")
        .and_then(serde_json::Value::as_u64)
        != Some(1)
    {
        return Err(integrity_failure());
    }
    let receipt =
        parse_legacy_terminal_receipt(connection, &value, execution_id, intent, execution)?;
    let output = receipt.terminal().output().ok_or_else(integrity_failure)?;
    let output_artifact_id = execution
        .stdout_artifact_id
        .as_deref()
        .ok_or_else(integrity_failure)?;
    let audit_payload = json!({
        "executionId": execution_id.as_str(),
        "status": legacy_event_status(receipt.terminal().kind())?,
        "exitCode": output.exit_code,
        "outputArtifactId": output_artifact_id,
        "outputDigest": output.output_digest.as_str(),
        "receipt": value,
    });
    Ok(ParsedPersistedReceipt {
        receipt,
        audit_payload,
        current_schema: false,
    })
}

fn parse_legacy_terminal_receipt(
    connection: &rusqlite::Connection,
    value: &serde_json::Value,
    execution_id: &ToolExecutionId,
    intent: &IntentRow,
    execution: &PersistedToolExecution,
) -> Result<DurableToolExecutionReceipt, PortError> {
    if required_string(value, "executionId")? != execution_id.as_str() {
        return Err(integrity_failure());
    }
    validate_legacy_bounded_output(required_object(value, "stdout")?)?;
    validate_legacy_bounded_output(required_object(value, "stderr")?)?;
    validate_legacy_job_receipt(required_object(value, "job")?)?;
    let writes = value
        .get("observedWrites")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(integrity_failure)?;
    for write in writes {
        validate_legacy_observed_write(write)?;
    }
    let exit_code = match value.get("exitCode") {
        Some(serde_json::Value::Null) => None,
        Some(value) => Some(
            i32::try_from(value.as_i64().ok_or_else(integrity_failure)?)
                .map_err(|_| integrity_failure())?,
        ),
        None => return Err(integrity_failure()),
    };
    let legacy_output_digest = Sha256Digest::new(required_string(value, "outputDigest")?)
        .map_err(|_| integrity_failure())?;
    let stdout_artifact = execution
        .stdout_artifact_id
        .as_deref()
        .ok_or_else(integrity_failure)?;
    let persisted_output_digest: String = connection
        .query_row(
            "SELECT content_hash FROM artifacts
             WHERE id = ?1 AND task_id = ?2 AND availability = 'available'",
            params![stdout_artifact, intent.task_id],
            |row| row.get(0),
        )
        .optional()
        .map_err(sqlite_error_to_port)?
        .ok_or_else(integrity_failure)?;
    let output_digest =
        Sha256Digest::new(persisted_output_digest).map_err(|_| integrity_failure())?;
    if legacy_output_digest != output_digest {
        return Err(integrity_failure());
    }
    let stdout_artifact_id =
        ArtifactId::new(stdout_artifact.to_owned()).map_err(|_| integrity_failure())?;
    if execution.stderr_artifact_id.is_some() {
        return Err(integrity_failure());
    }
    let output = ToolExecutionOutput {
        exit_code,
        output_digest,
        duration_ms: required_u64(value, "durationMs")?,
        artifacts: DurableToolExecutionArtifacts::new(
            DurableToolExecutionArtifact::Available(stdout_artifact_id),
            DurableToolExecutionArtifact::Unavailable,
            writes
                .iter()
                .map(|_| DurableToolExecutionArtifact::Unavailable)
                .collect(),
        ),
    };
    let terminal = match required_string(value, "status")? {
        "exited" if exit_code == Some(0) => ToolExecutionTerminal::succeeded(output),
        "exited" => ToolExecutionTerminal::failed(output),
        "terminated" => ToolExecutionTerminal::terminated(output),
        _ => Err(integrity_failure()),
    }
    .map_err(|_| integrity_failure())?;
    Ok(DurableToolExecutionReceipt::new(
        authority_from_intent(execution_id, intent)?,
        terminal,
    ))
}

fn validate_legacy_bounded_output(value: &serde_json::Value) -> Result<(), PortError> {
    required_u64(value, "byteCount")?;
    required_bool(value, "truncated")?;
    Ok(())
}

fn validate_legacy_job_receipt(value: &serde_json::Value) -> Result<(), PortError> {
    for field in [
        "rootPid",
        "memoryLimitBytes",
        "cpuTimeLimitMs",
        "maxActiveProcesses",
        "totalUserTimeMs",
    ] {
        required_u64(value, field)?;
    }
    required_string(value, "jobId")?;
    for field in [
        "killOnClose",
        "noBreakaway",
        "jobMemoryLimit",
        "jobCpuTimeLimit",
        "resourceLimitTerminated",
        "treeTerminated",
    ] {
        required_bool(value, field)?;
    }
    Ok(())
}

fn validate_legacy_observed_write(value: &serde_json::Value) -> Result<(), PortError> {
    required_object(value, "capability")?;
    required_string(value, "rootIdentity")?;
    required_object(value, "target")?;
    Sha256Digest::new(required_string(value, "digest")?).map_err(|_| integrity_failure())?;
    required_u64(value, "sizeBytes")?;
    Ok(())
}

fn legacy_event_status(kind: ToolExecutionTerminalKind) -> Result<&'static str, PortError> {
    match kind {
        ToolExecutionTerminalKind::Succeeded => Ok("succeeded"),
        ToolExecutionTerminalKind::Failed => Ok("failed"),
        ToolExecutionTerminalKind::Terminated => Ok("terminated"),
        ToolExecutionTerminalKind::Cancelled
        | ToolExecutionTerminalKind::Interrupted
        | ToolExecutionTerminalKind::Indeterminate => Err(integrity_failure()),
    }
}

fn parse_terminal_output(terminal: &serde_json::Value) -> Result<ToolExecutionOutput, PortError> {
    let output = required_object(terminal, "output")?;
    let exit_code = match output.get("exitCode") {
        Some(serde_json::Value::Null) => None,
        Some(value) => Some(
            i32::try_from(value.as_i64().ok_or_else(integrity_failure)?)
                .map_err(|_| integrity_failure())?,
        ),
        None => return Err(integrity_failure()),
    };
    let output_digest = Sha256Digest::new(required_string(output, "outputDigest")?)
        .map_err(|_| integrity_failure())?;
    let duration_ms = required_u64(output, "durationMs")?;
    let artifacts = required_object(output, "artifacts")?;
    let observed_writes = artifacts
        .get("observedWrites")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(integrity_failure)?
        .iter()
        .map(parse_terminal_artifact)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(ToolExecutionOutput {
        exit_code,
        output_digest,
        duration_ms,
        artifacts: DurableToolExecutionArtifacts::new(
            parse_terminal_artifact(artifacts.get("stdout").ok_or_else(integrity_failure)?)?,
            parse_terminal_artifact(artifacts.get("stderr").ok_or_else(integrity_failure)?)?,
            observed_writes,
        ),
    })
}

fn parse_terminal_artifact(
    value: &serde_json::Value,
) -> Result<DurableToolExecutionArtifact, PortError> {
    match required_string(value, "availability")? {
        "available" => Ok(DurableToolExecutionArtifact::Available(
            ArtifactId::new(required_string(value, "artifactId")?)
                .map_err(|_| integrity_failure())?,
        )),
        "unavailable" => Ok(DurableToolExecutionArtifact::Unavailable),
        _ => Err(integrity_failure()),
    }
}

fn required_object<'a>(
    value: &'a serde_json::Value,
    field: &str,
) -> Result<&'a serde_json::Value, PortError> {
    value
        .get(field)
        .filter(|value| value.is_object())
        .ok_or_else(integrity_failure)
}

fn required_string<'a>(value: &'a serde_json::Value, field: &str) -> Result<&'a str, PortError> {
    value
        .get(field)
        .and_then(serde_json::Value::as_str)
        .ok_or_else(integrity_failure)
}

fn required_u64(value: &serde_json::Value, field: &str) -> Result<u64, PortError> {
    value
        .get(field)
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(integrity_failure)
}

fn required_bool(value: &serde_json::Value, field: &str) -> Result<bool, PortError> {
    value
        .get(field)
        .and_then(serde_json::Value::as_bool)
        .ok_or_else(integrity_failure)
}

fn parse_error_classification(value: &str) -> Result<SafeErrorClassification, PortError> {
    match value {
        "conflict" => Ok(SafeErrorClassification::Conflict),
        "unavailable" => Ok(SafeErrorClassification::Unavailable),
        "permission_denied" => Ok(SafeErrorClassification::PermissionDenied),
        "not_found" => Ok(SafeErrorClassification::NotFound),
        "invalid_input" => Ok(SafeErrorClassification::InvalidInput),
        "integrity_failure" => Ok(SafeErrorClassification::IntegrityFailure),
        "storage_full" => Ok(SafeErrorClassification::StorageFull),
        "internal" => Ok(SafeErrorClassification::Internal),
        _ => Err(integrity_failure()),
    }
}

fn parse_retryability(value: &str) -> Result<Retryability, PortError> {
    match value {
        "retryable" => Ok(Retryability::Retryable),
        "non_retryable" => Ok(Retryability::NonRetryable),
        _ => Err(integrity_failure()),
    }
}

fn load_terminal_receipt(
    connection: &rusqlite::Connection,
    execution_id: &ToolExecutionId,
    intent: &IntentRow,
) -> Result<DurableToolExecutionReceipt, PortError> {
    let execution = load_tool_execution(connection, execution_id)?;
    validate_tool_execution_identity(execution_id, intent, &execution)?;
    let receipt_json = intent
        .external_receipt_json
        .as_deref()
        .ok_or_else(integrity_failure)?;
    let parsed = parse_persisted_terminal_receipt(
        connection,
        receipt_json,
        execution_id,
        intent,
        &execution,
    )?;
    let receipt = parsed.receipt;
    if (parsed.current_schema && terminal_receipt_json(&receipt) != receipt_json)
        || receipt.authority() != &authority_from_intent(execution_id, intent)?
    {
        return Err(integrity_failure());
    }
    validate_terminal_artifacts(connection, &intent.task_id, receipt.terminal())?;
    let outcome = terminal_outcome(receipt.terminal());
    let expected_error = terminal_error_json(receipt.terminal());
    if intent.status != outcome.intent_status
        || execution.status != outcome.execution_status
        || execution.completed_at.as_deref().is_none_or(str::is_empty)
        || execution.exit_code
            != receipt
                .terminal()
                .output()
                .and_then(|output| output.exit_code)
        || execution.stdout_artifact_id.as_deref()
            != artifact_id(receipt.terminal(), ToolArtifactSlot::Stdout)
        || execution.stderr_artifact_id.as_deref()
            != artifact_id(receipt.terminal(), ToolArtifactSlot::Stderr)
        || intent.result_artifact_id.as_deref() != primary_artifact_id(receipt.terminal())
        || intent.error_json != expected_error
    {
        return Err(integrity_failure());
    }
    let mut statement = connection
        .prepare(
            "SELECT sequence, payload_json FROM events
             WHERE stream_id = ?1 AND event_type = 'tool.execution.completed'
               AND json_extract(payload_json, '$.executionId') = ?2",
        )
        .map_err(sqlite_error_to_port)?;
    let audit_payloads = statement
        .query_map(params![intent.task_id, execution_id.as_str()], |row| {
            Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
        })
        .map_err(sqlite_error_to_port)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(sqlite_error_to_port)?;
    if audit_payloads.len() != 1
        || serde_json::from_str::<serde_json::Value>(&audit_payloads[0].1)
            .map_err(|_| integrity_failure())?
            != parsed.audit_payload
    {
        return Err(integrity_failure());
    }
    let (current_sequence, task_operation_state, latest_event_sequence): (i64, String, i64) =
        connection
            .query_row(
                "SELECT t.current_sequence, t.operation_state,
                        COALESCE(
                            (SELECT MAX(e.sequence) FROM events e WHERE e.stream_id = t.id),
                            0
                        )
                 FROM tasks t WHERE t.id = ?1",
                [&intent.task_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .map_err(sqlite_error_to_port)?;
    if current_sequence != latest_event_sequence
        || (audit_payloads[0].0 == current_sequence
            && task_operation_state != terminal_operation_state(receipt.terminal().kind()))
    {
        return Err(integrity_failure());
    }
    Ok(receipt)
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

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::mpsc;

    use local_agent_terminal_application::{
        canonical_approval_payload, parse_approval_payload, ToolExecutionTerminal,
    };

    use super::*;

    const TOOL_FIXTURE: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../tests/contracts/fixtures/m2/tool-approval-valid.json"
    ));
    static NEXT_DATABASE: AtomicU64 = AtomicU64::new(0);

    #[test]
    fn incomplete_reads_candidates_and_rows_from_one_snapshot() {
        let directory = std::env::temp_dir().join(format!(
            "tool-incomplete-snapshot-{}-{}",
            std::process::id(),
            NEXT_DATABASE.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&directory).unwrap();
        let path = directory.join("state.sqlite3");
        let store = SqliteStore::open(&path).unwrap();
        let operation_digest = seed_tool_context(&store, &directory);
        let execution_id = ToolExecutionId::new("snapshot-execution").unwrap();
        store
            .reserve(NewToolIntent {
                execution_id: execution_id.clone(),
                operation_digest: operation_digest.clone(),
            })
            .unwrap();
        let ToolExecutionClaim::Claimed(authority) = store
            .begin(NewToolExecution {
                execution_id,
                operation_digest,
            })
            .unwrap()
        else {
            panic!("fresh execution must be claimed");
        };
        let receipt =
            DurableToolExecutionReceipt::new(authority, ToolExecutionTerminal::cancelled());
        let (start_tx, start_rx) = mpsc::channel();
        let (done_tx, done_rx) = mpsc::channel();

        let listed = std::thread::scope(|scope| {
            let writer = store.clone();
            let terminal = scope.spawn(move || {
                start_rx.recv().unwrap();
                let result = writer.resolve_terminal(ToolExecutionResolution::new(receipt.clone()));
                done_tx.send(()).unwrap();
                result
            });
            let listed = incomplete_with_checkpoint(&store, || {
                start_tx.send(()).unwrap();
                done_rx.recv().unwrap();
            });
            terminal.join().unwrap().unwrap();
            listed
        });

        assert!(matches!(
            listed.unwrap().as_slice(),
            [IncompleteToolExecution::InFlight(_)]
        ));
        drop(store);
        fs::remove_dir_all(directory).unwrap();
    }

    fn seed_tool_context(store: &SqliteStore, artifact_root: &Path) -> Sha256Digest {
        let connection = store.connection().unwrap();
        let seed_hash = format!("sha256:{}", "d".repeat(64));
        connection
            .execute(
                "INSERT INTO projects (
                    id, name, repository_path, repository_identity, created_at, updated_at,
                    policy_profile_id, artifact_root_mode, artifact_root_path
                 ) VALUES ('project-1', 'Project', 'C:/repo', 'repo-1',
                    '2026-07-23T00:00:00Z', '2026-07-23T00:00:00Z',
                    'policy-1', 'application_data', ?1)",
                [artifact_root.to_string_lossy().as_ref()],
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO tasks (
                    id, project_id, title, objective, phase, condition, operation_state,
                    risk_level, base_branch, base_commit, workspace_version, fencing_epoch,
                    created_at, updated_at
                 ) VALUES ('task-1', 'project-1', 'Task', 'Objective', 'Implementation',
                    'Active', 'None', 'high', 'main', ?1, 4, 19,
                    '2026-07-23T00:00:00Z', '2026-07-23T00:00:00Z')",
                ["a".repeat(40)],
            )
            .unwrap();
        for (id, logical_path) in [
            ("manifest", "seed/manifest"),
            ("effective", "seed/effective"),
            ("run-config", "seed/run-config"),
        ] {
            connection
                .execute(
                    "INSERT INTO artifacts (
                        id, task_id, project_id, artifact_type, logical_path, content_hash,
                        storage_key, size_bytes, mime_type, availability, created_by_type,
                        created_by_id, created_at, supersedes, verification_state
                     ) VALUES (?1, 'task-1', 'project-1', 'seed', ?2, ?3, ?1, 0, NULL,
                        'available', 'core', 'core', '2026-07-23T00:00:00Z',
                        NULL, 'hash_verified')",
                    params![id, logical_path, seed_hash],
                )
                .unwrap();
        }
        connection
            .execute(
                "INSERT INTO agent_descriptors (
                    id, display_name, transport_type, trust_tier, manifest_json, manifest_digest,
                    executable_digest, enabled, containment_verified, last_health_status, updated_at
                 ) VALUES ('agent-1', 'Agent', 'in_process', 'core_adapter', '{}', ?1,
                    NULL, 1, 1, 'healthy', '2026-07-23T00:00:00Z')",
                [&seed_hash],
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO context_packages (
                    id, task_id, agent_id, role, objective, manifest_artifact_id,
                    effective_content_artifact_id, content_hash, policy_snapshot_digest,
                    prompt_template_version, retrieval_pipeline_version, created_at
                 ) VALUES ('context-1', 'task-1', 'agent-1', 'executor', 'execute',
                    'manifest', 'effective', ?1, ?2, 'v1', 'v1',
                    '2026-07-23T00:00:00Z')",
                params![seed_hash, format!("sha256:{}", "0".repeat(64))],
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO agent_runs (
                    id, task_id, agent_id, role, phase, status, context_package_id,
                    idempotency_key, connection_binding_digest, run_config_artifact_id, started_at
                 ) VALUES ('run-1', 'task-1', 'agent-1', 'executor', 'Implementation',
                    'running', 'context-1', 'run-1-key', ?1, 'run-config',
                    '2026-07-23T00:00:00Z')",
                [format!("sha256:{}", "e".repeat(64))],
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO executor_leases (
                    task_id, holder_run_id, fencing_token, status, acquired_at, expires_at
                 ) VALUES ('task-1', 'run-1', 19, 'active',
                    '2026-07-23T00:00:00Z', '2026-08-23T00:00:00Z')",
                [],
            )
            .unwrap();

        let payload = parse_approval_payload(TOOL_FIXTURE).unwrap();
        let canonical = canonical_approval_payload(&payload).unwrap();
        let storage_key = format!("objects/{}", &canonical.operation_digest.as_str()[7..]);
        let request_path = artifact_root.join(&storage_key);
        fs::create_dir_all(request_path.parent().unwrap()).unwrap();
        fs::write(request_path, &canonical.canonical_bytes).unwrap();
        connection
            .execute(
                "INSERT INTO artifacts (
                    id, task_id, project_id, artifact_type, logical_path, content_hash,
                    storage_key, size_bytes, mime_type, availability, created_by_type,
                    created_by_id, created_at, supersedes, verification_state
                 ) VALUES ('request-artifact', 'task-1', 'project-1', 'tool-request',
                    'tool-requests/snapshot.json', ?1, ?2, ?3, NULL, 'available',
                    'tool', 'snapshot-execution', '2026-07-23T12:00:00Z',
                    NULL, 'hash_verified')",
                params![
                    canonical.operation_digest.as_str(),
                    storage_key,
                    canonical.canonical_bytes.len() as i64,
                ],
            )
            .unwrap();
        let ApprovalDigestPayload::Tool(tool_payload) = payload else {
            unreachable!();
        };
        connection
            .execute(
                "INSERT INTO policy_decisions (
                    id, task_id, actor_json, actor_binding_digest, action, resource_json,
                    resource_digest, purpose, workflow_phase, effect, matched_rules_json,
                    policy_snapshot_digest, operation_digest, created_at, expires_at, approval_id
                 ) VALUES ('policy-1', 'task-1', '{}', ?1, 'process.exec', '{}', ?1,
                    'test', 'Implementation', 'allow', '[]', ?2, ?3,
                    '2026-07-23T12:00:00Z', NULL, NULL)",
                params![
                    format!("sha256:{}", "0".repeat(64)),
                    tool_payload.policy_snapshot_digest,
                    canonical.operation_digest.as_str(),
                ],
            )
            .unwrap();
        canonical.operation_digest
    }
}
