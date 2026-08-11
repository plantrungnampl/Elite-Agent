
fn process_binding_value(binding: &AuthoritativeProcessBinding) -> Value {
    json!({
        "schema": "process-binding.v1",
        "executionId": binding.authority().execution_id().as_str(),
        "operationDigest": binding.authority().operation_digest().as_str(),
        "ownerRunId": binding.authority().owner_run_id().as_str(),
        "attempt": binding.authority().attempt(),
        "executorFencingToken": binding
            .authority()
            .executor_fencing_token()
            .map(FencingToken::get),
        "rootPid": binding.root_pid(),
        "jobId": binding.job_id(),
    })
}

fn authoritative_process_binding_from_intent(
    execution_id: &ToolExecutionId,
    intent: &IntentRow,
    authority: &ToolExecutionClaimAuthority,
) -> Result<Option<AuthoritativeProcessBinding>, PortError> {
    let Some(binding_json) = intent.external_receipt_json.as_deref() else {
        return Ok(None);
    };
    if intent.status != "started" {
        return Err(integrity_failure());
    }
    let value = serde_json::from_str::<Value>(binding_json).map_err(|_| integrity_failure())?;
    let persisted_fencing_token = match value.get("executorFencingToken") {
        Some(Value::Null) => None,
        Some(value) => Some(value.as_u64().ok_or_else(integrity_failure)?),
        None => return Err(integrity_failure()),
    };
    if required_string(&value, "schema")? != "process-binding.v1"
        || required_string(&value, "executionId")? != execution_id.as_str()
        || required_string(&value, "operationDigest")? != authority.operation_digest().as_str()
        || required_string(&value, "ownerRunId")? != authority.owner_run_id().as_str()
        || required_u64(&value, "attempt")? != u64::from(authority.attempt())
        || persisted_fencing_token != authority.executor_fencing_token().map(FencingToken::get)
    {
        return Err(integrity_failure());
    }
    let root_pid =
        u32::try_from(required_u64(&value, "rootPid")?).map_err(|_| integrity_failure())?;
    let binding = AuthoritativeProcessBinding::new(
        authority.clone(),
        root_pid,
        required_string(&value, "jobId")?,
    )
    .map_err(|_| integrity_failure())?;
    if process_binding_value(&binding) != value {
        return Err(integrity_failure());
    }
    Ok(Some(binding))
}

fn validate_process_termination_resolution(
    execution_id: &ToolExecutionId,
    intent: &IntentRow,
    receipt: &DurableToolExecutionReceipt,
) -> Result<(), PortError> {
    let Some(termination) = receipt.process_termination() else {
        return Ok(());
    };
    let persisted =
        authoritative_process_binding_from_intent(execution_id, intent, receipt.authority())?
            .ok_or_else(integrity_failure)?;
    if termination.binding() != &persisted {
        return Err(integrity_failure());
    }
    Ok(())
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
            ("claimed", "pending") | ("started", "running") => {
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
    mutation_sequence_offset: u64,
) -> Result<bool, PortError> {
    let mutation_sequence = snapshot
        .request
        .expected_sequence
        .get()
        .checked_add(mutation_sequence_offset)
        .ok_or_else(invalid_input)?;
    let mutation_event_id = format!(
        "workspace.mutated:{}:{mutation_sequence}",
        snapshot.request.task_id.as_str()
    );
    let receipt = file_write_receipt(snapshot, completion, &mutation_event_id);
    let connection = store.connection().map_err(open_error_to_port)?;
    let event_payload = audited_tool_event_payload(
        &connection,
        snapshot.request.task_id.as_str(),
        completion.execution_id.as_str(),
        file_write_completed_event(snapshot, completion, &mutation_event_id),
    )?
    .payload
    .to_string();
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
