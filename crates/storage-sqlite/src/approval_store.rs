use local_agent_terminal_application::{
    canonical_approval_payload, parse_approval_payload, parse_policy_timestamp, parse_tool_request,
    validate_tool_approval_request, ApprovalCheck, ApprovalClaim, ApprovalDigestPayload,
    ApprovalExpiryStore, ApprovalId, ApprovalInvalidation, ApprovalResolution,
    ApprovalResumeSnapshot, ApprovalResumeStore, ApprovalSnapshot, ApprovalState, ApprovalStore,
    ImmutableToolRequest, NewApproval, OperationIntentStatus, PolicyDecisionId,
    PolicyRequestBindingDigest, PortError, Retryability, SafeErrorClassification,
    ToolApprovalPublication, ToolApprovalRequest, ToolExecutionId, ToolExecutionResumeSnapshot,
    ToolExecutionResumeStore, ToolRequestBindingDigest,
};
use local_agent_terminal_domain::{
    ArtifactId, FencingToken, RunId, Sha256Digest, TaskId, Timestamp, WorkspaceVersion,
};
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

impl ApprovalExpiryStore for SqliteStore {
    fn expire_before(&self, observed_at: &str) -> Result<u64, PortError> {
        let observed_at = parse_policy_timestamp(observed_at).map_err(|_| invalid_input())?;
        let mut connection = self.connection().map_err(open_error_to_port)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite_error_to_port)?;
        let open_approvals = {
            let mut statement = transaction
                .prepare(
                    "SELECT id, expires_at FROM approvals
                     WHERE status IN ('pending', 'granted')
                     ORDER BY id",
                )
                .map_err(sqlite_error_to_port)?;
            let rows = statement
                .query_map([], |row| {
                    Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
                })
                .map_err(sqlite_error_to_port)?
                .collect::<Result<Vec<_>, _>>()
                .map_err(sqlite_error_to_port)?;
            rows
        };
        let mut ids = Vec::new();
        for (id, expires_at) in open_approvals {
            let expires_at =
                parse_policy_timestamp(&expires_at).map_err(|_| integrity_failure())?;
            if expires_at.unix_seconds() <= observed_at.unix_seconds() {
                ids.push(id);
            }
        }
        for id in &ids {
            let approval_id = ApprovalId::new(id.clone()).map_err(|_| integrity_failure())?;
            invalidate_one(&transaction, &approval_id, "expired", "approval.expired")?;
        }
        transaction.commit().map_err(sqlite_error_to_port)?;
        u64::try_from(ids.len()).map_err(|_| invalid_input())
    }

    fn invalidate_unrevalidated(&self) -> Result<u64, PortError> {
        let mut connection = self.connection().map_err(open_error_to_port)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite_error_to_port)?;
        let ids = {
            let mut statement = transaction
                .prepare(
                    "SELECT id FROM approvals
                     WHERE status IN ('pending', 'granted')
                     ORDER BY id",
                )
                .map_err(sqlite_error_to_port)?;
            let ids = statement
                .query_map([], |row| row.get::<_, String>(0))
                .map_err(sqlite_error_to_port)?
                .collect::<Result<Vec<_>, _>>()
                .map_err(sqlite_error_to_port)?;
            ids
        };
        for id in &ids {
            let approval_id = ApprovalId::new(id.clone()).map_err(|_| integrity_failure())?;
            invalidate_one(
                &transaction,
                &approval_id,
                "startup_revalidation_required",
                "approval.invalidated",
            )?;
        }
        transaction.commit().map_err(sqlite_error_to_port)?;
        u64::try_from(ids.len()).map_err(|_| invalid_input())
    }
}

impl SqliteStore {
    pub fn record_tool_approval_request(
        &self,
        request: ToolApprovalRequest,
    ) -> Result<ToolApprovalPublication, PortError> {
        let mut connection = self.connection().map_err(open_error_to_port)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite_error_to_port)?;

        match load_tool_approval_relation(&transaction, None, Some(request.execution_id())) {
            Ok(relation) => {
                let existing = approval_request_from_relation(&transaction, relation)?;
                validate_replay_subject(&existing, &request)?;
                transaction.rollback().map_err(sqlite_error_to_port)?;
                return Ok(ToolApprovalPublication::Replayed(existing));
            }
            Err(error) if error.safe_classification() == SafeErrorClassification::NotFound => {}
            Err(error) => return Err(error),
        }

        validate_tool_approval_publication(&transaction, &request)?;
        let payload = request.payload();
        let task_id = TaskId::new(payload.task_id.clone()).map_err(|_| integrity_failure())?;
        let approval_type = "tool";
        let inserted = transaction
            .execute(
                "INSERT INTO approvals (
                    id, task_id, approval_type, schema_version, operation_digest, status,
                    requested_at, resolved_at, resolved_by, expires_at, request_artifact_id,
                    invalidation_reason
                 ) VALUES (?1, ?2, ?3, 'approval-digest.v1', ?4, 'pending',
                    ?5, NULL, NULL, ?6, ?7, NULL)",
                params![
                    request.approval_id().as_str(),
                    task_id.as_str(),
                    approval_type,
                    request.canonical_payload().operation_digest.as_str(),
                    payload.requested_at,
                    payload.expires_at,
                    request.approval_artifact_id().as_str(),
                ],
            )
            .map_err(sqlite_error_to_port)?;
        if inserted != 1 {
            return Err(conflict());
        }
        append_approval_event(
            &transaction,
            &task_id,
            request.approval_id(),
            "approval.requested",
            Some("AwaitingApproval"),
            json!({
                "approvalId": request.approval_id().as_str(),
                "approvalType": "tool",
                "operationDigest": request.canonical_payload().operation_digest.as_str(),
                "executionId": request.execution_id().as_str(),
                "approvalPolicyDecisionId": request.policy_decision_id().as_str(),
                "policyRequestBindingDigest":
                    request.policy_request_binding_digest().as_sha256().as_str(),
                "toolRequestArtifactId": request.tool_request_artifact_id().as_str(),
                "toolRequestBindingDigest":
                    request.tool_request_binding_digest().as_sha256().as_str(),
                "workspaceVersion": payload.workspace_version,
                "policySnapshotDigest": payload.policy_snapshot_digest,
                "fencingToken": payload.operation.executor_fencing_token,
                "nonce": payload.nonce,
                "requestArtifactId": request.approval_artifact_id().as_str(),
            }),
        )?;
        let relation = load_tool_approval_relation(
            &transaction,
            Some(request.approval_id()),
            Some(request.execution_id()),
        )?;
        let persisted = approval_request_from_relation(&transaction, relation)?;
        if persisted != request {
            return Err(integrity_failure());
        }
        transaction.commit().map_err(sqlite_error_to_port)?;
        Ok(ToolApprovalPublication::Created(request))
    }
}

fn approval_request_from_relation(
    transaction: &Transaction<'_>,
    relation: ToolApprovalRelation,
) -> Result<ToolApprovalRequest, PortError> {
    let logical_path = format!("approvals/{}.json", relation.approval_id.as_str());
    let stored_logical_path: String = transaction
        .query_row(
            "SELECT logical_path FROM artifacts WHERE id = ?1",
            [relation.approval_artifact_id.as_str()],
            |row| row.get(0),
        )
        .optional()
        .map_err(sqlite_error_to_port)?
        .ok_or_else(not_found)?;
    if stored_logical_path != logical_path {
        return Err(integrity_failure());
    }
    let artifact = crate::tool_execution_store::artifact_by_id_on_connection(
        transaction,
        relation.approval_artifact_id.as_str(),
        &relation.approval_operation_digest,
        relation.task_id.as_str(),
    )?;
    crate::tool_execution_store::validate_artifact_type(
        transaction,
        relation.approval_artifact_id.as_str(),
        "approval-payload",
    )?;
    let payload = parse_canonical_approval_payload(&artifact.bytes)?;
    let ApprovalDigestPayload::Tool(payload) = payload else {
        return Err(integrity_failure());
    };
    ToolApprovalRequest::from_persisted(
        relation.approval_id,
        relation.approval_artifact_id,
        relation.execution_id,
        relation.approval_policy_decision_id,
        relation.policy_request_binding_digest,
        relation.request_artifact_id,
        relation.tool_request_binding_digest,
        payload,
    )
}

fn validate_replay_subject(
    existing: &ToolApprovalRequest,
    candidate: &ToolApprovalRequest,
) -> Result<(), PortError> {
    if existing.execution_id() != candidate.execution_id()
        || existing.tool_request_artifact_id() != candidate.tool_request_artifact_id()
        || existing.tool_request_binding_digest() != candidate.tool_request_binding_digest()
        || existing.policy_request_binding_digest() != candidate.policy_request_binding_digest()
        || existing.payload().task_id != candidate.payload().task_id
        || existing.payload().operation != candidate.payload().operation
        || existing.payload().policy_snapshot_digest != candidate.payload().policy_snapshot_digest
        || existing.payload().workspace_version != candidate.payload().workspace_version
    {
        return Err(integrity_failure());
    }
    Ok(())
}

fn validate_tool_approval_publication(
    transaction: &Transaction<'_>,
    request: &ToolApprovalRequest,
) -> Result<(), PortError> {
    let task_id =
        TaskId::new(request.payload().task_id.clone()).map_err(|_| integrity_failure())?;
    let request_artifact = crate::tool_execution_store::artifact_by_id_on_connection(
        transaction,
        request.tool_request_artifact_id().as_str(),
        request.tool_request_binding_digest().as_sha256(),
        task_id.as_str(),
    )?;
    crate::tool_execution_store::validate_artifact_type(
        transaction,
        request.tool_request_artifact_id().as_str(),
        "tool-request",
    )?;
    let logical_path: String = transaction
        .query_row(
            "SELECT logical_path FROM artifacts WHERE id = ?1",
            [request.tool_request_artifact_id().as_str()],
            |row| row.get(0),
        )
        .map_err(sqlite_error_to_port)?;
    let immutable = parse_tool_request(&request_artifact.bytes)?;
    if logical_path
        != format!(
            "tool-requests/{}.json",
            immutable.request().execution_id().as_str()
        )
        || immutable.binding_digest() != request.tool_request_binding_digest()
        || immutable.request().execution_id() != request.execution_id()
    {
        return Err(integrity_failure());
    }
    validate_tool_approval_request(
        immutable.request(),
        &immutable,
        request.tool_request_artifact_id(),
        request.policy_request_binding_digest(),
        request,
    )?;

    let process = immutable.request().process().process();
    let binding = process.binding();
    let fencing_token = process
        .executor_fencing_token()
        .map(|token| i64::try_from(token.get()).map_err(|_| integrity_failure()))
        .transpose()?;
    let intent_matches: bool = transaction
        .query_row(
            "SELECT EXISTS(
                SELECT 1 FROM operation_intents
                WHERE id = ?1 AND task_id = ?2 AND run_id = ?3
                  AND canonical_request_artifact_id = ?4 AND operation_digest = ?5
                  AND operation_kind = 'process.exec' AND status = 'pending'
                  AND attempt_count = 0 AND lease_owner IS NULL
                  AND executor_fencing_token IS ?6
             )",
            params![
                request.execution_id().as_str(),
                task_id.as_str(),
                binding.run_id().as_str(),
                request.tool_request_artifact_id().as_str(),
                request.tool_request_binding_digest().as_sha256().as_str(),
                fencing_token,
            ],
            |row| row.get(0),
        )
        .map_err(sqlite_error_to_port)?;
    if !intent_matches {
        return Err(integrity_failure());
    }

    let approval_artifact = crate::tool_execution_store::artifact_by_id_on_connection(
        transaction,
        request.approval_artifact_id().as_str(),
        &request.canonical_payload().operation_digest,
        task_id.as_str(),
    )?;
    crate::tool_execution_store::validate_artifact_type(
        transaction,
        request.approval_artifact_id().as_str(),
        "approval-payload",
    )?;
    let approval_path: String = transaction
        .query_row(
            "SELECT logical_path FROM artifacts WHERE id = ?1",
            [request.approval_artifact_id().as_str()],
            |row| row.get(0),
        )
        .map_err(sqlite_error_to_port)?;
    if approval_path != format!("approvals/{}.json", request.approval_id().as_str())
        || approval_artifact.bytes != request.canonical_payload().canonical_bytes
    {
        return Err(integrity_failure());
    }

    let checked_at =
        parse_policy_timestamp(&request.payload().requested_at).map_err(|_| integrity_failure())?;
    let approval_expires_at =
        parse_policy_timestamp(&request.payload().expires_at).map_err(|_| integrity_failure())?;
    crate::tool_execution_store::validate_tool_approval_policy(
        transaction,
        request.policy_decision_id(),
        request.policy_request_binding_digest(),
        immutable.request(),
        checked_at,
        approval_expires_at,
    )
}

impl ApprovalResumeStore for SqliteStore {
    fn load_for_resume(
        &self,
        approval_id: &ApprovalId,
        _checked_at: Timestamp,
    ) -> Result<ApprovalResumeSnapshot, PortError> {
        let mut connection = self.connection().map_err(open_error_to_port)?;
        let transaction = connection.transaction().map_err(sqlite_error_to_port)?;
        let relation = load_tool_approval_relation(&transaction, Some(approval_id), None)?;
        let snapshot = ApprovalResumeSnapshot::new(
            relation.approval_id,
            relation.execution_id,
            relation.approval_policy_decision_id,
            relation.policy_request_binding_digest,
            relation.approval_operation_digest,
            relation.tool_request_binding_digest,
            relation.task_id,
            relation.run_id,
            relation.request_artifact_id,
            relation.request_content_digest,
            relation.intent_id,
            relation.workspace_version,
            relation.policy_snapshot_digest,
            relation.fencing_token,
            relation.expires_at,
            relation.nonce,
            relation.state,
        )?;
        if snapshot.approval_id != *approval_id {
            return Err(integrity_failure());
        }
        transaction.rollback().map_err(sqlite_error_to_port)?;
        Ok(snapshot)
    }

    fn load_approval_request(
        &self,
        approval_id: &ApprovalId,
    ) -> Result<ToolApprovalRequest, PortError> {
        let mut connection = self.connection().map_err(open_error_to_port)?;
        let transaction = connection.transaction().map_err(sqlite_error_to_port)?;
        let relation = load_tool_approval_relation(&transaction, Some(approval_id), None)?;
        let request = approval_request_from_relation(&transaction, relation)?;
        transaction.rollback().map_err(sqlite_error_to_port)?;
        Ok(request)
    }
}

impl ToolExecutionResumeStore for SqliteStore {
    fn load_intent(
        &self,
        execution_id: &ToolExecutionId,
    ) -> Result<ToolExecutionResumeSnapshot, PortError> {
        let mut connection = self.connection().map_err(open_error_to_port)?;
        let transaction = connection.transaction().map_err(sqlite_error_to_port)?;
        let relation = load_tool_approval_relation(&transaction, None, Some(execution_id))?;
        let snapshot = ToolExecutionResumeSnapshot::new(
            relation.execution_id,
            relation.approval_id,
            relation.approval_policy_decision_id,
            relation.approval_operation_digest,
            relation.policy_request_binding_digest,
            relation.tool_request_binding_digest,
            relation.task_id,
            relation.run_id,
            relation.workspace_version,
            relation.policy_snapshot_digest,
            relation.fencing_token,
            relation.expires_at,
            relation.nonce,
            relation.request_artifact_id,
            relation.request_content_digest.clone(),
            relation.intent_operation_digest,
            relation.intent_id,
            relation.intent_status,
        )?;
        transaction.rollback().map_err(sqlite_error_to_port)?;
        Ok(snapshot)
    }

    fn load_request_artifact(
        &self,
        artifact_id: &ArtifactId,
    ) -> Result<ImmutableToolRequest, PortError> {
        let mut connection = self.connection().map_err(open_error_to_port)?;
        let transaction = connection.transaction().map_err(sqlite_error_to_port)?;
        let (content_hash, task_id, artifact_type, logical_path): (String, String, String, String) =
            transaction
                .query_row(
                    "SELECT content_hash, task_id, artifact_type, logical_path
                 FROM artifacts WHERE id = ?1",
                    [artifact_id.as_str()],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
                )
                .optional()
                .map_err(sqlite_error_to_port)?
                .ok_or_else(not_found)?;
        if artifact_type != "tool-request" {
            return Err(integrity_failure());
        }
        let digest = Sha256Digest::new(content_hash).map_err(|_| integrity_failure())?;
        let artifact = crate::tool_execution_store::artifact_by_id_on_connection(
            &transaction,
            artifact_id.as_str(),
            &digest,
            task_id.as_str(),
        )?;
        let immutable = local_agent_terminal_application::parse_tool_request(&artifact.bytes)
            .map_err(|_| integrity_failure())?;
        let request = immutable.request();
        if logical_path != format!("tool-requests/{}.json", request.execution_id().as_str())
            || request.process().process().binding().task_id().as_str() != task_id
        {
            return Err(integrity_failure());
        }
        transaction.rollback().map_err(sqlite_error_to_port)?;
        Ok(immutable)
    }
}

#[derive(Debug)]
struct RawToolApprovalRelation {
    approval_id: String,
    task_id: String,
    approval_status: String,
    invalidation_reason: Option<String>,
    approval_operation_digest: String,
    approval_expires_at: String,
    approval_artifact_id: String,
    event_payload: String,
    intent_id: String,
    run_id: Option<String>,
    operation_kind: String,
    idempotency_class: String,
    idempotency_key: String,
    request_artifact_id: String,
    intent_operation_digest: String,
    intent_status: String,
    intent_fencing_token: Option<i64>,
    intent_attempt_count: i64,
    intent_lease_owner: Option<String>,
    intent_task_id: String,
}

#[derive(Debug)]
struct ToolApprovalRelation {
    approval_id: ApprovalId,
    execution_id: ToolExecutionId,
    approval_policy_decision_id: PolicyDecisionId,
    policy_request_binding_digest: PolicyRequestBindingDigest,
    approval_operation_digest: Sha256Digest,
    tool_request_binding_digest: ToolRequestBindingDigest,
    task_id: TaskId,
    run_id: RunId,
    request_artifact_id: ArtifactId,
    request_content_digest: Sha256Digest,
    intent_operation_digest: Sha256Digest,
    intent_id: String,
    workspace_version: WorkspaceVersion,
    policy_snapshot_digest: Sha256Digest,
    fencing_token: Option<FencingToken>,
    expires_at: Timestamp,
    nonce: String,
    state: ApprovalState,
    intent_status: OperationIntentStatus,
    approval_artifact_id: ArtifactId,
}

fn load_tool_approval_relation(
    transaction: &Transaction<'_>,
    approval_id: Option<&ApprovalId>,
    execution_id: Option<&ToolExecutionId>,
) -> Result<ToolApprovalRelation, PortError> {
    let mut statement = transaction
        .prepare(
            "SELECT a.id, a.task_id, a.status, a.invalidation_reason,
                    a.operation_digest, a.expires_at, a.request_artifact_id,
                    e.payload_json,
                    oi.id, oi.run_id, oi.operation_kind, oi.idempotency_class,
                    oi.idempotency_key, oi.canonical_request_artifact_id,
                    oi.operation_digest, oi.status, oi.executor_fencing_token,
                    oi.attempt_count, oi.lease_owner, oi.task_id
             FROM approvals a
             JOIN events e
               ON e.stream_id = a.task_id
              AND e.event_type = 'approval.requested'
              AND json_extract(e.payload_json, '$.approvalId') = a.id
             JOIN operation_intents oi
               ON oi.id = json_extract(e.payload_json, '$.executionId')
             WHERE (?1 IS NULL OR a.id = ?1)
               AND (?2 IS NULL OR json_extract(e.payload_json, '$.executionId') = ?2)
             ORDER BY e.sequence",
        )
        .map_err(sqlite_error_to_port)?;
    let rows = statement
        .query_map(
            params![
                approval_id.map(ApprovalId::as_str),
                execution_id.map(ToolExecutionId::as_str),
            ],
            |row| {
                Ok(RawToolApprovalRelation {
                    approval_id: row.get(0)?,
                    task_id: row.get(1)?,
                    approval_status: row.get(2)?,
                    invalidation_reason: row.get(3)?,
                    approval_operation_digest: row.get(4)?,
                    approval_expires_at: row.get(5)?,
                    approval_artifact_id: row.get(6)?,
                    event_payload: row.get(7)?,
                    intent_id: row.get(8)?,
                    run_id: row.get(9)?,
                    operation_kind: row.get(10)?,
                    idempotency_class: row.get(11)?,
                    idempotency_key: row.get(12)?,
                    request_artifact_id: row.get(13)?,
                    intent_operation_digest: row.get(14)?,
                    intent_status: row.get(15)?,
                    intent_fencing_token: row.get(16)?,
                    intent_attempt_count: row.get(17)?,
                    intent_lease_owner: row.get(18)?,
                    intent_task_id: row.get(19)?,
                })
            },
        )
        .map_err(sqlite_error_to_port)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(sqlite_error_to_port)?;
    let [raw] = rows.as_slice() else {
        return Err(if rows.is_empty() {
            not_found()
        } else {
            integrity_failure()
        });
    };
    let payload: Value =
        serde_json::from_str(&raw.event_payload).map_err(|_| integrity_failure())?;
    let approval_id_value =
        ApprovalId::new(raw.approval_id.clone()).map_err(|_| integrity_failure())?;
    let execution_id_value = parse_event_id(&payload, "executionId", ToolExecutionId::new)?;
    if payload_string(&payload, "approvalId")? != raw.approval_id
        || payload_string(&payload, "approvalType")? != "tool"
        || payload_string(&payload, "operationDigest")? != raw.approval_operation_digest
        || payload_string(&payload, "requestArtifactId")? != raw.approval_artifact_id
        || payload_string(&payload, "toolRequestArtifactId")? != raw.request_artifact_id
        || execution_id_value.as_str() != raw.intent_id
        || raw.intent_task_id != raw.task_id
        || raw.run_id.as_deref().is_none_or(str::is_empty)
        || raw.operation_kind != "process.exec"
        || raw.idempotency_class != "non_repeatable"
        || raw.idempotency_key
            != format!(
                "tool:{}:{}",
                raw.run_id.as_deref().unwrap_or_default(),
                raw.intent_id
            )
        || (raw.intent_status == "pending"
            && (raw.intent_attempt_count != 0 || raw.intent_lease_owner.is_some()))
    {
        return Err(integrity_failure());
    }
    let task_id = TaskId::new(raw.task_id.clone()).map_err(|_| integrity_failure())?;
    let run_id = RunId::new(raw.run_id.clone().ok_or_else(integrity_failure)?)
        .map_err(|_| integrity_failure())?;
    let approval_policy_decision_id =
        PolicyDecisionId::from_persisted(payload_string(&payload, "approvalPolicyDecisionId")?)
            .map_err(|_| integrity_failure())?;
    let policy_request_binding_digest =
        parse_policy_binding(payload_string(&payload, "policyRequestBindingDigest")?)?;
    let approval_operation_digest = Sha256Digest::new(raw.approval_operation_digest.clone())
        .map_err(|_| integrity_failure())?;
    let tool_request_binding_digest =
        parse_tool_binding(payload_string(&payload, "toolRequestBindingDigest")?)?;
    let request_artifact_id =
        ArtifactId::new(raw.request_artifact_id.clone()).map_err(|_| integrity_failure())?;
    let request_content_digest =
        Sha256Digest::new(raw.intent_operation_digest.clone()).map_err(|_| integrity_failure())?;
    let intent_operation_digest =
        Sha256Digest::new(raw.intent_operation_digest.clone()).map_err(|_| integrity_failure())?;
    let policy_snapshot_digest =
        Sha256Digest::new(payload_string(&payload, "policySnapshotDigest")?)
            .map_err(|_| integrity_failure())?;
    let workspace_version = WorkspaceVersion::new(payload_u64(&payload, "workspaceVersion")?);
    let fencing_token = payload_optional_fencing_token(&payload, "fencingToken")?;
    let intent_fencing_token = raw
        .intent_fencing_token
        .map(FencingToken::try_from)
        .transpose()
        .map_err(|_| integrity_failure())?;
    if fencing_token != intent_fencing_token
        || payload_u64(&payload, "workspaceVersion")? > 9_007_199_254_740_991
    {
        return Err(integrity_failure());
    }
    let expires_at =
        parse_policy_timestamp(&raw.approval_expires_at).map_err(|_| integrity_failure())?;
    let state = approval_state_from_row(&raw.approval_status, raw.invalidation_reason.as_deref())?;
    let intent_status =
        OperationIntentStatus::parse(&raw.intent_status).ok_or_else(integrity_failure)?;
    if intent_status == OperationIntentStatus::Pending && raw.intent_attempt_count != 0 {
        return Err(integrity_failure());
    }
    Ok(ToolApprovalRelation {
        approval_id: approval_id_value,
        execution_id: execution_id_value,
        approval_policy_decision_id,
        policy_request_binding_digest,
        approval_operation_digest,
        tool_request_binding_digest,
        task_id,
        run_id,
        request_artifact_id,
        request_content_digest,
        intent_operation_digest,
        intent_id: raw.intent_id.clone(),
        workspace_version,
        policy_snapshot_digest,
        fencing_token,
        expires_at,
        nonce: payload_string(&payload, "nonce")?,
        state,
        intent_status,
        approval_artifact_id: ArtifactId::new(raw.approval_artifact_id.clone())
            .map_err(|_| integrity_failure())?,
    })
}

fn payload_string(payload: &Value, key: &str) -> Result<String, PortError> {
    payload
        .get(key)
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or_else(integrity_failure)
}

fn payload_u64(payload: &Value, key: &str) -> Result<u64, PortError> {
    payload
        .get(key)
        .and_then(Value::as_u64)
        .ok_or_else(integrity_failure)
}

fn payload_optional_fencing_token(
    payload: &Value,
    key: &str,
) -> Result<Option<FencingToken>, PortError> {
    let value = payload.get(key).ok_or_else(integrity_failure)?;
    value
        .as_u64()
        .map(FencingToken::new)
        .transpose()
        .map_err(|_| integrity_failure())
}

fn parse_event_id<T>(
    payload: &Value,
    key: &str,
    parse: impl FnOnce(String) -> Result<T, PortError>,
) -> Result<T, PortError> {
    parse(payload_string(payload, key)?).map_err(|_| integrity_failure())
}

fn parse_policy_binding(value: String) -> Result<PolicyRequestBindingDigest, PortError> {
    Ok(PolicyRequestBindingDigest::from_persisted(
        Sha256Digest::new(value).map_err(|_| integrity_failure())?,
    ))
}

fn parse_tool_binding(value: String) -> Result<ToolRequestBindingDigest, PortError> {
    Ok(ToolRequestBindingDigest::from_persisted(
        Sha256Digest::new(value).map_err(|_| integrity_failure())?,
    ))
}

fn approval_state_from_row(
    status: &str,
    invalidation_reason: Option<&str>,
) -> Result<ApprovalState, PortError> {
    match status {
        "pending" => Ok(ApprovalState::Requested),
        "granted" => Ok(ApprovalState::Approved),
        "denied" => Ok(ApprovalState::Rejected),
        "invalidated" if invalidation_reason == Some("consumed") => Ok(ApprovalState::Consumed),
        "invalidated" | "expired" => Ok(ApprovalState::Invalidated),
        _ => Err(integrity_failure()),
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

pub(crate) fn append_approval_event(
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
