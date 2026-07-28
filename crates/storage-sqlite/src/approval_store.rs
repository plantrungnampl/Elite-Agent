use local_agent_terminal_application::{
    canonical_approval_payload, parse_approval_payload, ApprovalCheck, ApprovalClaim,
    ApprovalDigestPayload, ApprovalId, ApprovalInvalidation, ApprovalResolution, ApprovalSnapshot,
    ApprovalState, ApprovalStore, NewApproval, PortError, Retryability, SafeErrorClassification,
};
use local_agent_terminal_domain::{Sha256Digest, TaskId, WorkspaceVersion};
use rusqlite::{params, OptionalExtension, Transaction, TransactionBehavior};
use serde_json::{json, Value};

use crate::event_store::{open_error_to_port, sqlite_error_to_port};
use crate::SqliteStore;

type RawApprovalSnapshot = (
    String,
    String,
    String,
    String,
    Option<i64>,
    String,
    String,
    String,
    Option<String>,
);

impl ApprovalStore for SqliteStore {
    fn request(&self, approval: NewApproval) -> Result<ApprovalSnapshot, PortError> {
        let logical_path = format!("approvals/{}.json", approval.approval_id.as_str());
        let artifact = self.artifact_by_digest(
            &approval.operation_digest,
            Some(&logical_path),
            Some(approval.task_id.as_str()),
        )?;
        let payload = parse_canonical_approval_payload(&artifact.bytes)?;
        let approval_type = payload_type(&payload);
        if artifact.task_id != approval.task_id.as_str()
            || payload_task_id(&payload) != approval.task_id.as_str()
            || payload_workspace_version(&payload) != approval.workspace_version.get()
            || payload_policy_digest(&payload) != approval.policy_snapshot_digest.as_str()
            || payload_fencing_token(&payload) != approval.fencing_token
            || payload_expires_at(&payload) != approval.expires_at
            || payload_nonce(&payload) != approval.nonce
        {
            return Err(invalid_input());
        }
        let binding_digest = approval
            .tool_request_binding_digest
            .as_ref()
            .map(|value| value.as_sha256().as_str().to_owned());
        let mut connection = self.connection().map_err(open_error_to_port)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite_error_to_port)?;
        let inserted = transaction
            .execute(
                "INSERT OR IGNORE INTO approvals (
                    id, task_id, approval_type, schema_version, operation_digest, status,
                    requested_at, resolved_at, resolved_by, expires_at, request_artifact_id,
                    invalidation_reason
                 ) VALUES (?1, ?2, ?3, 'approval-digest.v1', ?4, 'pending',
                    ?5, NULL, NULL, ?6, ?7, NULL)",
                params![
                    approval.approval_id.as_str(),
                    approval.task_id.as_str(),
                    approval_type,
                    approval.operation_digest.as_str(),
                    payload_requested_at(&payload),
                    approval.expires_at,
                    artifact.id,
                ],
            )
            .map_err(sqlite_error_to_port)?;
        if inserted == 1 {
            append_approval_event(
                &transaction,
                &approval.task_id,
                &approval.approval_id,
                "approval.requested",
                Some("AwaitingApproval"),
                json!({
                    "approvalId": approval.approval_id.as_str(),
                    "approvalType": approval_type,
                    "operationDigest": approval.operation_digest.as_str(),
                    "workspaceVersion": approval.workspace_version.get(),
                    "policySnapshotDigest": approval.policy_snapshot_digest.as_str(),
                    "fencingToken": approval.fencing_token,
                    "toolRequestBindingDigest": binding_digest,
                    "nonce": approval.nonce,
                    "requestArtifactId": artifact.id,
                }),
            )?;
        } else if !request_matches(&transaction, &approval, &artifact.id, approval_type)? {
            return Err(conflict());
        }
        transaction.commit().map_err(sqlite_error_to_port)?;
        Ok(snapshot_from_new(approval, ApprovalState::Requested))
    }

    fn resolve(&self, resolution: ApprovalResolution) -> Result<ApprovalSnapshot, PortError> {
        let mut connection = self.connection().map_err(open_error_to_port)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite_error_to_port)?;
        let target = if resolution.approved {
            "granted"
        } else {
            "denied"
        };
        let changed = transaction
            .execute(
                "UPDATE approvals
                 SET status = ?1, resolved_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now'),
                     resolved_by = 'user'
                 WHERE id = ?2 AND status = 'pending'
                   AND julianday(expires_at) > julianday('now')",
                params![target, resolution.approval_id.as_str()],
            )
            .map_err(sqlite_error_to_port)?;
        if changed != 1 {
            return Err(conflict());
        }
        let task_id = approval_task_id(&transaction, &resolution.approval_id)?;
        append_approval_event(
            &transaction,
            &task_id,
            &resolution.approval_id,
            if resolution.approved {
                "approval.granted"
            } else {
                "approval.denied"
            },
            Some("None"),
            json!({
                "approvalId": resolution.approval_id.as_str(),
                "status": target,
            }),
        )?;
        let snapshot = load_snapshot(&transaction, &resolution.approval_id, None)?;
        transaction.commit().map_err(sqlite_error_to_port)?;
        Ok(snapshot)
    }

    fn valid_for(&self, check: ApprovalCheck) -> Result<Option<ApprovalSnapshot>, PortError> {
        let mut connection = self.connection().map_err(open_error_to_port)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite_error_to_port)?;
        let Some(mut snapshot) = load_snapshot_optional(&transaction, &check.approval_id, None)?
        else {
            return Ok(None);
        };
        if snapshot.state != ApprovalState::Approved
            || snapshot.operation_digest != check.expected_operation_digest
            || snapshot.task_id != check.task_id
        {
            return Ok(None);
        }
        let live: bool = transaction
            .query_row(
                "SELECT julianday(?1) < julianday(expires_at)
                 FROM approvals WHERE id = ?2",
                params![check.checked_at, check.approval_id.as_str()],
                |row| row.get(0),
            )
            .map_err(sqlite_error_to_port)?;
        if !live {
            invalidate_one(
                &transaction,
                &check.approval_id,
                "expired",
                "approval.expired",
            )?;
            transaction.commit().map_err(sqlite_error_to_port)?;
            return Ok(None);
        }
        if snapshot.workspace_version != check.workspace_version
            || snapshot.policy_snapshot_digest != check.policy_snapshot_digest
            || snapshot.fencing_token != check.fencing_token
        {
            invalidate_one(
                &transaction,
                &check.approval_id,
                "canonical_binding_changed",
                "approval.invalidated",
            )?;
            transaction.commit().map_err(sqlite_error_to_port)?;
            return Ok(None);
        }
        verify_request_artifact(self, &transaction, &check.approval_id, &snapshot)?;
        snapshot.state = ApprovalState::Approved;
        transaction.commit().map_err(sqlite_error_to_port)?;
        Ok(Some(snapshot))
    }

    fn claim(&self, claim: ApprovalClaim) -> Result<Option<ApprovalSnapshot>, PortError> {
        let mut connection = self.connection().map_err(open_error_to_port)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite_error_to_port)?;
        let loaded = load_snapshot_optional(
            &transaction,
            &claim.approval_id,
            Some(claim.tool_request_binding_digest.clone()),
        );
        let Some(snapshot) = (match loaded {
            Ok(snapshot) => snapshot,
            Err(error) if error.safe_classification() == SafeErrorClassification::Conflict => {
                return Ok(None);
            }
            Err(error) => return Err(error),
        }) else {
            return Ok(None);
        };
        if snapshot.state != ApprovalState::Approved
            || snapshot.operation_digest != claim.expected_operation_digest
            || snapshot.task_id != claim.task_id
            || snapshot.workspace_version != claim.workspace_version
            || snapshot.policy_snapshot_digest != claim.policy_snapshot_digest
            || snapshot.fencing_token != claim.fencing_token
            || snapshot.nonce != claim.nonce
            || snapshot.tool_request_binding_digest.as_ref()
                != Some(&claim.tool_request_binding_digest)
        {
            return Ok(None);
        }
        let live: bool = transaction
            .query_row(
                "SELECT julianday(?1) < julianday(expires_at)
                 FROM approvals WHERE id = ?2",
                params![claim.claimed_at, claim.approval_id.as_str()],
                |row| row.get(0),
            )
            .map_err(sqlite_error_to_port)?;
        if !live {
            invalidate_one(
                &transaction,
                &claim.approval_id,
                "expired",
                "approval.expired",
            )?;
            transaction.commit().map_err(sqlite_error_to_port)?;
            return Ok(None);
        }
        verify_request_artifact(self, &transaction, &claim.approval_id, &snapshot)?;
        let changed = transaction
            .execute(
                "UPDATE approvals
                 SET status = 'invalidated', invalidation_reason = 'consumed'
                 WHERE id = ?1 AND status = 'granted'",
                [claim.approval_id.as_str()],
            )
            .map_err(sqlite_error_to_port)?;
        if changed != 1 {
            return Ok(None);
        }
        append_approval_event(
            &transaction,
            &claim.task_id,
            &claim.approval_id,
            "approval.consumed",
            Some("None"),
            json!({
                "approvalId": claim.approval_id.as_str(),
                "operationDigest": claim.expected_operation_digest.as_str(),
                "nonce": claim.nonce,
            }),
        )?;
        transaction.commit().map_err(sqlite_error_to_port)?;
        let mut consumed = snapshot;
        consumed.state = ApprovalState::Consumed;
        Ok(Some(consumed))
    }

    fn invalidate(&self, request: ApprovalInvalidation) -> Result<u64, PortError> {
        let mut connection = self.connection().map_err(open_error_to_port)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite_error_to_port)?;
        let ids = {
            let mut statement = transaction
                .prepare(
                    "SELECT a.id
                     FROM approvals a
                     JOIN events e
                       ON e.event_type = 'approval.requested'
                      AND json_extract(e.payload_json, '$.approvalId') = a.id
                     WHERE a.task_id = ?1 AND a.status IN ('pending', 'granted')
                       AND json_extract(e.payload_json, '$.workspaceVersion') <> ?2
                     ORDER BY a.id",
                )
                .map_err(sqlite_error_to_port)?;
            let rows = statement
                .query_map(
                    params![
                        request.task_id.as_str(),
                        i64::try_from(request.workspace_version.get())
                            .map_err(|_| invalid_input())?
                    ],
                    |row| row.get::<_, String>(0),
                )
                .map_err(sqlite_error_to_port)?
                .collect::<Result<Vec<_>, _>>()
                .map_err(sqlite_error_to_port)?;
            rows
        };
        for id in &ids {
            let approval_id = ApprovalId::new(id.clone()).map_err(|_| integrity_failure())?;
            invalidate_one(
                &transaction,
                &approval_id,
                "workspace_version_changed",
                "approval.invalidated",
            )?;
        }
        transaction.commit().map_err(sqlite_error_to_port)?;
        u64::try_from(ids.len()).map_err(|_| invalid_input())
    }
}

pub(crate) fn parse_canonical_approval_payload(
    bytes: &[u8],
) -> Result<ApprovalDigestPayload, PortError> {
    let raw = std::str::from_utf8(bytes).map_err(|_| integrity_failure())?;
    let payload = parse_approval_payload(raw).map_err(|_| integrity_failure())?;
    let canonical = canonical_approval_payload(&payload).map_err(|_| integrity_failure())?;
    if canonical.canonical_bytes != bytes {
        return Err(integrity_failure());
    }
    Ok(payload)
}

fn request_matches(
    transaction: &Transaction<'_>,
    approval: &NewApproval,
    artifact_id: &str,
    approval_type: &str,
) -> Result<bool, PortError> {
    transaction
        .query_row(
            "SELECT EXISTS(
                SELECT 1 FROM approvals a
                JOIN events e
                  ON e.event_type = 'approval.requested'
                 AND json_extract(e.payload_json, '$.approvalId') = a.id
                WHERE a.id = ?1 AND a.task_id = ?2 AND a.approval_type = ?3
                  AND a.schema_version = 'approval-digest.v1' AND a.operation_digest = ?4
                  AND a.status = 'pending' AND a.expires_at = ?5 AND a.request_artifact_id = ?6
                  AND COALESCE(json_extract(e.payload_json, '$.toolRequestBindingDigest'), '')
                      = COALESCE(?7, '')
            )",
            params![
                approval.approval_id.as_str(),
                approval.task_id.as_str(),
                approval_type,
                approval.operation_digest.as_str(),
                approval.expires_at,
                artifact_id,
                approval
                    .tool_request_binding_digest
                    .as_ref()
                    .map(|value| value.as_sha256().as_str()),
            ],
            |row| row.get(0),
        )
        .map_err(sqlite_error_to_port)
}

fn load_snapshot(
    transaction: &Transaction<'_>,
    approval_id: &ApprovalId,
    binding: Option<local_agent_terminal_application::ToolRequestBindingDigest>,
) -> Result<ApprovalSnapshot, PortError> {
    load_snapshot_optional(transaction, approval_id, binding)?.ok_or_else(not_found)
}

fn load_snapshot_optional(
    transaction: &Transaction<'_>,
    approval_id: &ApprovalId,
    binding: Option<local_agent_terminal_application::ToolRequestBindingDigest>,
) -> Result<Option<ApprovalSnapshot>, PortError> {
    let row: Option<RawApprovalSnapshot> = transaction
        .query_row(
            "SELECT a.task_id, a.status, a.operation_digest, a.expires_at,
                        json_extract(e.payload_json, '$.fencingToken'),
                        json_extract(e.payload_json, '$.policySnapshotDigest'),
                        json_extract(e.payload_json, '$.nonce'),
                        CAST(json_extract(e.payload_json, '$.workspaceVersion') AS TEXT),
                        json_extract(e.payload_json, '$.toolRequestBindingDigest')
                 FROM approvals a
                 JOIN events e
                   ON e.event_type = 'approval.requested'
                  AND json_extract(e.payload_json, '$.approvalId') = a.id
                 WHERE a.id = ?1
                 ORDER BY e.sequence LIMIT 1",
            [approval_id.as_str()],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    row.get(6)?,
                    row.get(7)?,
                    row.get(8)?,
                ))
            },
        )
        .optional()
        .map_err(sqlite_error_to_port)?;
    row.map(
        |(
            task_id,
            status,
            operation_digest,
            expires_at,
            fencing_token,
            policy_digest,
            nonce,
            workspace_version,
            persisted_binding,
        )| {
            let persisted_binding = persisted_binding
                .map(Sha256Digest::new)
                .transpose()
                .map_err(|_| integrity_failure())?
                .map(local_agent_terminal_application::ToolRequestBindingDigest::from_persisted);
            if binding
                .as_ref()
                .is_some_and(|expected| persisted_binding.as_ref() != Some(expected))
            {
                return Err(conflict());
            }
            Ok(ApprovalSnapshot {
                approval_id: approval_id.clone(),
                state: approval_state(transaction, approval_id, &status)?,
                operation_digest: Sha256Digest::new(operation_digest)
                    .map_err(|_| integrity_failure())?,
                task_id: TaskId::new(task_id).map_err(|_| integrity_failure())?,
                workspace_version: WorkspaceVersion::new(
                    workspace_version
                        .parse::<u64>()
                        .map_err(|_| integrity_failure())?,
                ),
                policy_snapshot_digest: Sha256Digest::new(policy_digest)
                    .map_err(|_| integrity_failure())?,
                fencing_token: fencing_token
                    .map(u64::try_from)
                    .transpose()
                    .map_err(|_| integrity_failure())?,
                tool_request_binding_digest: persisted_binding,
                expires_at,
                nonce,
            })
        },
    )
    .transpose()
}

fn approval_state(
    transaction: &Transaction<'_>,
    approval_id: &ApprovalId,
    status: &str,
) -> Result<ApprovalState, PortError> {
    Ok(match status {
        "pending" => ApprovalState::Requested,
        "granted" => ApprovalState::Approved,
        "denied" => ApprovalState::Rejected,
        "invalidated" => {
            let reason: Option<String> = transaction
                .query_row(
                    "SELECT invalidation_reason FROM approvals WHERE id = ?1",
                    [approval_id.as_str()],
                    |row| row.get(0),
                )
                .map_err(sqlite_error_to_port)?;
            if reason.as_deref() == Some("consumed") {
                ApprovalState::Consumed
            } else {
                ApprovalState::Invalidated
            }
        }
        "expired" => ApprovalState::Invalidated,
        _ => return Err(integrity_failure()),
    })
}

fn verify_request_artifact(
    store: &SqliteStore,
    transaction: &Transaction<'_>,
    approval_id: &ApprovalId,
    snapshot: &ApprovalSnapshot,
) -> Result<(), PortError> {
    let (artifact_id, logical_path): (String, String) = transaction
        .query_row(
            "SELECT request_artifact_id, 'approvals/' || id || '.json'
             FROM approvals WHERE id = ?1",
            [approval_id.as_str()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .map_err(sqlite_error_to_port)?;
    let artifact = store.artifact_by_id(
        &artifact_id,
        &snapshot.operation_digest,
        Some(&logical_path),
        Some(snapshot.task_id.as_str()),
    )?;
    let payload = parse_canonical_approval_payload(&artifact.bytes)?;
    if payload_task_id(&payload) != snapshot.task_id.as_str()
        || payload_workspace_version(&payload) != snapshot.workspace_version.get()
        || payload_policy_digest(&payload) != snapshot.policy_snapshot_digest.as_str()
        || payload_fencing_token(&payload) != snapshot.fencing_token
        || payload_nonce(&payload) != snapshot.nonce
        || payload_expires_at(&payload) != snapshot.expires_at
    {
        return Err(integrity_failure());
    }
    Ok(())
}

fn invalidate_one(
    transaction: &Transaction<'_>,
    approval_id: &ApprovalId,
    reason: &str,
    event_type: &str,
) -> Result<(), PortError> {
    let target_status = if reason == "expired" {
        "expired"
    } else {
        "invalidated"
    };
    let changed = transaction
        .execute(
            "UPDATE approvals
             SET status = ?1, invalidation_reason = ?2,
                 resolved_at = COALESCE(resolved_at, strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
                 resolved_by = COALESCE(resolved_by, 'core')
             WHERE id = ?3 AND status IN ('pending', 'granted')",
            params![target_status, reason, approval_id.as_str()],
        )
        .map_err(sqlite_error_to_port)?;
    if changed == 0 {
        return Ok(());
    }
    let task_id = approval_task_id(transaction, approval_id)?;
    append_approval_event(
        transaction,
        &task_id,
        approval_id,
        event_type,
        Some("None"),
        json!({"approvalId": approval_id.as_str(), "reason": reason}),
    )
}

fn approval_task_id(
    transaction: &Transaction<'_>,
    approval_id: &ApprovalId,
) -> Result<TaskId, PortError> {
    let value: String = transaction
        .query_row(
            "SELECT task_id FROM approvals WHERE id = ?1",
            [approval_id.as_str()],
            |row| row.get(0),
        )
        .map_err(sqlite_error_to_port)?;
    TaskId::new(value).map_err(|_| integrity_failure())
}

fn append_approval_event(
    transaction: &Transaction<'_>,
    task_id: &TaskId,
    approval_id: &ApprovalId,
    event_type: &str,
    operation_state: Option<&str>,
    payload: Value,
) -> Result<(), PortError> {
    let (current_sequence, created_at): (i64, String) = transaction
        .query_row(
            "SELECT current_sequence, strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
             FROM tasks WHERE id = ?1",
            [task_id.as_str()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .map_err(sqlite_error_to_port)?;
    let sequence = current_sequence.checked_add(1).ok_or_else(invalid_input)?;
    transaction
        .execute(
            "INSERT INTO events (
                event_id, stream_id, sequence, event_type, schema_version, actor_type,
                actor_id, observation_class, payload_json, metadata_json, causation_id,
                correlation_id, created_at
             ) VALUES (?1, ?2, ?3, ?4, 1, 'core', 'approval-store', 'core_observed',
                ?5, '{}', ?6, ?6, ?7)",
            params![
                format!("{event_type}:{}:{sequence}", approval_id.as_str()),
                task_id.as_str(),
                sequence,
                event_type,
                payload.to_string(),
                format!("approval:{}", approval_id.as_str()),
                created_at,
            ],
        )
        .map_err(sqlite_error_to_port)?;
    let changed = transaction
        .execute(
            "UPDATE tasks SET current_sequence = ?1,
                operation_state = COALESCE(?2, operation_state), updated_at = ?3
             WHERE id = ?4 AND current_sequence = ?5",
            params![
                sequence,
                operation_state,
                created_at,
                task_id.as_str(),
                current_sequence
            ],
        )
        .map_err(sqlite_error_to_port)?;
    if changed == 1 {
        Ok(())
    } else {
        Err(conflict())
    }
}

fn snapshot_from_new(approval: NewApproval, state: ApprovalState) -> ApprovalSnapshot {
    ApprovalSnapshot {
        approval_id: approval.approval_id,
        state,
        operation_digest: approval.operation_digest,
        task_id: approval.task_id,
        workspace_version: approval.workspace_version,
        policy_snapshot_digest: approval.policy_snapshot_digest,
        fencing_token: approval.fencing_token,
        tool_request_binding_digest: approval.tool_request_binding_digest,
        expires_at: approval.expires_at,
        nonce: approval.nonce,
    }
}

fn payload_type(payload: &ApprovalDigestPayload) -> &'static str {
    match payload {
        ApprovalDigestPayload::Tool(_) => "tool",
        ApprovalDigestPayload::PolicyException(_) => "policy_exception",
    }
}

fn payload_task_id(payload: &ApprovalDigestPayload) -> &str {
    match payload {
        ApprovalDigestPayload::Tool(value) => &value.task_id,
        ApprovalDigestPayload::PolicyException(value) => &value.task_id,
    }
}

fn payload_workspace_version(payload: &ApprovalDigestPayload) -> u64 {
    match payload {
        ApprovalDigestPayload::Tool(value) => value.workspace_version,
        ApprovalDigestPayload::PolicyException(value) => value.workspace_version,
    }
}

fn payload_policy_digest(payload: &ApprovalDigestPayload) -> &str {
    match payload {
        ApprovalDigestPayload::Tool(value) => &value.policy_snapshot_digest,
        ApprovalDigestPayload::PolicyException(value) => &value.policy_snapshot_digest,
    }
}

fn payload_fencing_token(payload: &ApprovalDigestPayload) -> Option<u64> {
    match payload {
        ApprovalDigestPayload::Tool(value) => value.operation.executor_fencing_token,
        ApprovalDigestPayload::PolicyException(_) => None,
    }
}

fn payload_requested_at(payload: &ApprovalDigestPayload) -> &str {
    match payload {
        ApprovalDigestPayload::Tool(value) => &value.requested_at,
        ApprovalDigestPayload::PolicyException(value) => &value.requested_at,
    }
}

fn payload_expires_at(payload: &ApprovalDigestPayload) -> &str {
    match payload {
        ApprovalDigestPayload::Tool(value) => &value.expires_at,
        ApprovalDigestPayload::PolicyException(value) => &value.expires_at,
    }
}

fn payload_nonce(payload: &ApprovalDigestPayload) -> &str {
    match payload {
        ApprovalDigestPayload::Tool(value) => &value.nonce,
        ApprovalDigestPayload::PolicyException(value) => &value.nonce,
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

fn not_found() -> PortError {
    PortError::failure(
        SafeErrorClassification::NotFound,
        Retryability::NonRetryable,
    )
}
