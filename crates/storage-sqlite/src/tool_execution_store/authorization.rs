
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
        binding: AuthoritativeProcessBinding,
    ) -> Result<(), PortError> {
        let mut connection = self.connection().map_err(open_error_to_port)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite_error_to_port)?;
        let execution_id = binding.authority().execution_id();
        let intent = load_intent(&transaction, execution_id)?;
        validate_tool_intent(&transaction, execution_id, &intent)?;
        if authority_from_intent(execution_id, &intent)? != *binding.authority() {
            return Err(integrity_failure());
        }
        let execution = load_tool_execution(&transaction, execution_id)?;
        validate_tool_execution_identity(execution_id, &intent, &execution)?;
        let binding_value = process_binding_value(&binding);
        if intent.status == "started" {
            let persisted = intent
                .external_receipt_json
                .as_deref()
                .ok_or_else(integrity_failure)
                .and_then(|value| {
                    serde_json::from_str::<Value>(value).map_err(|_| integrity_failure())
                })?;
            if execution.status != "running" || persisted != binding_value {
                return Err(integrity_failure());
            }
            transaction.rollback().map_err(sqlite_error_to_port)?;
            return Ok(());
        }
        if intent.status != "claimed"
            || execution.status != "pending"
            || intent.external_receipt_json.is_some()
        {
            return Err(conflict());
        }
        let binding_json =
            serde_json::to_string(&binding_value).map_err(|_| integrity_failure())?;
        let fencing_token = binding
            .authority()
            .executor_fencing_token()
            .map(FencingToken::get)
            .map(i64::try_from)
            .transpose()
            .map_err(|_| integrity_failure())?;
        let intent_changed = transaction
            .execute(
                "UPDATE operation_intents
                 SET status = 'started', external_receipt_json = ?1,
                     updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
                 WHERE id = ?2 AND status = 'claimed' AND operation_digest = ?3
                   AND lease_owner = ?4 AND attempt_count = ?5
                   AND executor_fencing_token IS ?6",
                params![
                    binding_json,
                    execution_id.as_str(),
                    binding.authority().operation_digest().as_str(),
                    binding.authority().owner_run_id().as_str(),
                    binding.authority().attempt(),
                    fencing_token,
                ],
            )
            .map_err(sqlite_error_to_port)?;
        let execution_changed = transaction
            .execute(
                "UPDATE tool_executions
                 SET status = 'running',
                     started_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
                 WHERE id = ?1 AND status = 'pending' AND started_at IS NULL",
                [execution_id.as_str()],
            )
            .map_err(sqlite_error_to_port)?;
        if intent_changed != 1 || execution_changed != 1 {
            return Err(conflict());
        }
        append_tool_event(
            &transaction,
            &intent.task_id,
            execution_id.as_str(),
            "tool.execution.started",
            "Running",
            json!({
                "executionId": execution_id.as_str(),
                "operationDigest": binding.authority().operation_digest().as_str(),
                "policyDecisionId": execution.policy_decision_id,
                "approvalId": execution.approval_id,
                "executorFencingToken": fencing_token,
                "ownerRunId": binding.authority().owner_run_id().as_str(),
                "attempt": binding.authority().attempt(),
                "rootPid": binding.root_pid(),
                "jobId": binding.job_id(),
            }),
        )?;
        transaction.commit().map_err(sqlite_error_to_port)
    }
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
    let expected_event = audited_tool_event_payload(
        transaction,
        &intent.task_id,
        execution_id.as_str(),
        denial_event_payload(
            &ToolExecutionDenialRequest {
                request_artifact_id: request_artifact_id.clone(),
                request: request.clone(),
                policy_decision_id: policy_decision_id.clone(),
                policy_request_binding_digest: policy_binding,
                effect,
                checked_at: evaluated_at,
            },
            request.binding_digest().as_sha256().as_str(),
        ),
    )?
    .payload;
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
    let changed = transaction
        .execute(
            "UPDATE approvals
             SET status = 'invalidated', invalidation_reason = 'consumed'
             WHERE id = ?1 AND status = 'granted'
               AND unixepoch(expires_at) > ?2",
            params![
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

fn claim_tool_execution(
    transaction: &Transaction<'_>,
    execution_id: &ToolExecutionId,
    intent: &IntentRow,
    policy_decision_id: &str,
    approval_id: Option<&str>,
) -> Result<ToolExecutionClaimAuthority, PortError> {
    let changed = transaction
        .execute(
            "UPDATE operation_intents
             SET status = 'claimed', lease_owner = run_id, attempt_count = attempt_count + 1,
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
             ) VALUES (?1, ?2, ?3, ?1, ?4, ?5, ?6, ?7, ?1, ?8, 'pending',
                NULL, NULL, NULL, NULL, NULL)",
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
    Ok(authority)
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
