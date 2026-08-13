
impl ProcessExecutionBindingStore for SqliteStore {
    fn load_claimed_authority(
        &self,
        execution_id: &ToolExecutionId,
    ) -> Result<ToolExecutionClaimAuthority, PortError> {
        let mut connection = self.connection().map_err(open_error_to_port)?;
        let transaction = connection.transaction().map_err(sqlite_error_to_port)?;
        let intent = load_intent(&transaction, execution_id)?;
        validate_tool_intent(&transaction, execution_id, &intent)?;
        let execution = load_tool_execution(&transaction, execution_id)?;
        validate_tool_execution_identity(execution_id, &intent, &execution)?;
        if intent.status != "claimed" || execution.status != "pending" {
            return Err(conflict());
        }
        let authority = authority_from_intent(execution_id, &intent)?;
        transaction.rollback().map_err(sqlite_error_to_port)?;
        Ok(authority)
    }

    fn record_process_binding(
        &self,
        _binding: AuthoritativeProcessBinding,
    ) -> Result<(), PortError> {
        // Normative v7 has no trustworthy column for this process-binding receipt.
        // Refuse dispatch until the caller supplies a persisted receipt artifact vertical.
        Err(integrity_failure())
    }
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
}

fn validate_authorized_request(
    transaction: &Transaction<'_>,
    request: &AuthorizedToolExecutionClaim,
    intent: &IntentRow,
) -> Result<ImmutableToolRequest, PortError> {
    if request.approval.is_some() != request.approval_checked_at.is_some()
        || intent.artifact_id != request.request_artifact_id.as_str()
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

fn validate_exact_policy(
    transaction: &Transaction<'_>,
    request: &AuthorizedToolExecutionClaim,
    tool_request: &local_agent_terminal_application::ToolRequest,
) -> Result<(), PortError> {
    validate_policy_identity_at(
        transaction,
        &request.policy_decision_id,
        &request.policy_request_binding_digest,
        tool_request,
        request.checked_at,
        request.effect_checked_at,
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
    validate_policy_identity_at(
        transaction,
        decision_id,
        binding_digest,
        tool_request,
        checked_at,
        checked_at,
        expected_effect,
        mode,
    )
}

#[allow(clippy::too_many_arguments)]
fn validate_policy_identity_at(
    transaction: &Transaction<'_>,
    decision_id: &PolicyDecisionId,
    binding_digest: &PolicyRequestBindingDigest,
    tool_request: &local_agent_terminal_application::ToolRequest,
    checked_at: local_agent_terminal_domain::Timestamp,
    observed_at: local_agent_terminal_domain::Timestamp,
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
            params![decision_id.as_str(), observed_at.unix_seconds(),],
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
            |row| row.get::<_, Option<i64>>(0),
        )
        .optional()
        .map_err(sqlite_error_to_port)?
        .flatten();
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
    let approval_checked_at = request.approval_checked_at.ok_or_else(integrity_failure)?;
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
                approval_checked_at.unix_seconds(),
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
        || row.operation_digest != request.request_content_digest.as_str()
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
            row.status == "granted"
                && row.invalidation_reason.is_none()
                && transaction
                    .query_row(
                        "SELECT EXISTS(
                            SELECT 1 FROM approval_effect_consumptions consumption
                            JOIN approval_decision_receipts receipt
                              ON receipt.id = consumption.approval_receipt_id
                            WHERE receipt.approval_id = ?1
                              AND consumption.operation_intent_id = ?2
                         )",
                        params![approval.approval_id().as_str(), request.execution_id.as_str()],
                        |row| row.get::<_, bool>(0),
                    )
                    .map_err(sqlite_error_to_port)?
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
        "operationDigest": request.request_content_digest.as_str(),
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
        approval_checked_at,
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
    let approval_checked_at = request.approval_checked_at.ok_or_else(integrity_failure)?;
    let receipt_id: String = transaction
        .query_row(
            "SELECT id FROM approval_decision_receipts
             WHERE approval_id = ?1 AND decision = 'granted'",
            [approval.approval_id().as_str()],
            |row| row.get(0),
        )
        .map_err(sqlite_error_to_port)?;
    let changed = transaction
        .execute(
            "INSERT OR IGNORE INTO approval_effect_consumptions (
                id, approval_receipt_id, operation_intent_id, consumed_at
             ) SELECT ?1, ?2, ?3, strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
             WHERE EXISTS (
                SELECT 1 FROM approvals
                WHERE id = ?4 AND status = 'granted' AND unixepoch(expires_at) > ?5
             )",
            params![
                format!("approval-consumption:{}", approval.approval_id().as_str()),
                receipt_id,
                request.execution_id.as_str(),
                approval.approval_id().as_str(),
                approval_checked_at.unix_seconds(),
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
        "claimed" | "started" => {
            let execution = load_tool_execution(transaction, execution_id)?;
            validate_tool_execution_identity(execution_id, intent, &execution)?;
            let expected_status = if intent.status == "claimed" {
                "pending"
            } else {
                "running"
            };
            if execution.status != expected_status {
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

#[allow(clippy::too_many_arguments)]
fn insert_operation_attempt(
    transaction: &Transaction<'_>,
    attempt_id: &str,
    execution_id: &ToolExecutionId,
    intent: &IntentRow,
    attempt: u32,
    policy_decision_id: &str,
    approval_id: Option<&str>,
    status: &str,
) -> Result<(), PortError> {
    let inserted = transaction
        .execute(
            "INSERT INTO operation_attempts (
                id, operation_intent_id, task_id, attempt_no, owner_run_id,
                fencing_token, policy_decision_id, approval_id, status,
                external_request_id, boundary_crossed_at, started_at, terminal_at,
                result_artifact_id, receipt_artifact_id, error_artifact_id
             ) VALUES (?1, ?2, ?3, ?4, ?5,
                (SELECT fencing_token FROM executor_leases
                 WHERE task_id = ?3 AND holder_run_id = ?5 AND status = 'active'
                 ORDER BY fencing_token DESC LIMIT 1),
                ?6, ?7, ?8, ?2, NULL,
                strftime('%Y-%m-%dT%H:%M:%fZ', 'now'), NULL, NULL, NULL, NULL)",
            params![
                attempt_id,
                execution_id.as_str(),
                intent.task_id,
                i64::from(attempt),
                intent.run_id,
                policy_decision_id,
                approval_id,
                status,
            ],
        )
        .map_err(sqlite_error_to_port)?;
    if inserted == 1 {
        Ok(())
    } else {
        Err(conflict())
    }
}

fn claim_tool_execution(
    transaction: &Transaction<'_>,
    execution_id: &ToolExecutionId,
    intent: &IntentRow,
    policy_decision_id: &str,
    approval_id: Option<&str>,
) -> Result<ToolExecutionClaimAuthority, PortError> {
    let attempt = intent
        .attempt_count
        .checked_add(1)
        .and_then(|value| u32::try_from(value).ok())
        .ok_or_else(integrity_failure)?;
    let attempt_id = format!("{}:attempt:{attempt}", execution_id.as_str());
    insert_operation_attempt(
        transaction,
        &attempt_id,
        execution_id,
        intent,
        attempt,
        policy_decision_id,
        approval_id,
        "claimed",
    )?;
    let changed = transaction
        .execute(
            "UPDATE operation_intents
             SET status = 'claimed', current_attempt_no = current_attempt_no + 1,
                  updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
             WHERE id = ?1 AND status = 'pending'",
            [execution_id.as_str()],
        )
        .map_err(sqlite_error_to_port)?;
    if changed != 1 {
        return Err(conflict());
    }
    let current = load_intent(transaction, execution_id)?;
    let authority = claim_authority(execution_id, &current, attempt)?;
    transaction
        .execute(
            "INSERT INTO tool_executions (
                id, task_id, run_id, request_id, tool_name, arguments_artifact_id,
                policy_decision_id, approval_id, operation_intent_id, operation_attempt_id,
                executor_fencing_token, status, started_at, completed_at, exit_code,
                stdout_artifact_id, stderr_artifact_id
             ) VALUES (?1, ?2, ?3, ?1, ?4, ?5, ?6, ?7, ?1, ?8, ?9, 'pending',
                NULL, NULL, NULL, NULL, NULL)",
            params![
                execution_id.as_str(),
                intent.task_id,
                intent.run_id,
                intent.operation_kind,
                intent.artifact_id,
                policy_decision_id,
                approval_id,
                attempt_id,
                current.fencing_token,
            ],
        )
        .map_err(sqlite_error_to_port)?;
    Ok(authority)
}
