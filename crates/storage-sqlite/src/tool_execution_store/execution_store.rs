
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
        let authority = claim_tool_execution(
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

    fn request_cancellation(
        &self,
        execution_id: &ToolExecutionId,
    ) -> Result<ToolExecutionCancellationClaim, PortError> {
        let mut connection = self.connection().map_err(open_error_to_port)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite_error_to_port)?;
        let intent = load_intent(&transaction, execution_id)?;
        validate_tool_intent(&transaction, execution_id, &intent)?;
        if matches!(
            intent.status.as_str(),
            "succeeded" | "failed" | "interrupted"
        ) || (matches!(intent.status.as_str(), "cancelled" | "indeterminate")
            && intent.external_receipt_json.is_some())
        {
            let receipt = load_terminal_receipt(&transaction, execution_id, &intent)?;
            transaction.rollback().map_err(sqlite_error_to_port)?;
            return Ok(ToolExecutionCancellationClaim::Completed(receipt));
        }
        if intent.status != "started" {
            return Err(conflict());
        }
        let execution = load_tool_execution(&transaction, execution_id)?;
        validate_tool_execution_identity(execution_id, &intent, &execution)?;
        if execution.status != "running" {
            return Err(integrity_failure());
        }
        let authority = authority_from_intent(execution_id, &intent)?;
        let cancellation_payloads = {
            let mut statement = transaction
                .prepare(
                    "SELECT payload_json FROM events
                     WHERE stream_id = ?1 AND event_type = 'operation.cancel.requested'
                       AND actor_type = 'tool'
                       AND json_extract(payload_json, '$.executionId') = ?2",
                )
                .map_err(sqlite_error_to_port)?;
            let payloads = statement
                .query_map(params![intent.task_id, execution_id.as_str()], |row| {
                    row.get::<_, String>(0)
                })
                .map_err(sqlite_error_to_port)?
                .collect::<Result<Vec<_>, _>>()
                .map_err(sqlite_error_to_port)?;
            payloads
        };
        let expected_payload = cancellation_event_payload(&authority);
        let expected_audit_payload = audited_tool_event_payload(
            &transaction,
            &intent.task_id,
            execution_id.as_str(),
            expected_payload.clone(),
        )?
        .payload;
        match cancellation_payloads.as_slice() {
            [] => {
                append_tool_event(
                    &transaction,
                    &intent.task_id,
                    execution_id.as_str(),
                    "operation.cancel.requested",
                    "Cancelling",
                    expected_payload,
                )?;
                transaction.commit().map_err(sqlite_error_to_port)?;
                Ok(ToolExecutionCancellationClaim::Claimed(authority))
            }
            [payload]
                if serde_json::from_str::<Value>(payload).map_err(|_| integrity_failure())?
                    == expected_audit_payload =>
            {
                let (state, current_sequence, latest_sequence): (String, i64, i64) = transaction
                    .query_row(
                        "SELECT operation_state, current_sequence,
                                COALESCE(
                                    (SELECT MAX(sequence) FROM events WHERE stream_id = tasks.id),
                                    0
                                )
                         FROM tasks WHERE id = ?1",
                        [&intent.task_id],
                        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                    )
                    .map_err(sqlite_error_to_port)?;
                if state != "Cancelling" || current_sequence != latest_sequence {
                    return Err(integrity_failure());
                }
                transaction.rollback().map_err(sqlite_error_to_port)?;
                Ok(ToolExecutionCancellationClaim::InFlight(authority))
            }
            _ => Err(integrity_failure()),
        }
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
        validate_process_termination_resolution(&execution_id, &intent, resolution.receipt())?;
        let (expected_intent_status, expected_execution_status) = match (
            intent.status.as_str(),
            resolution.receipt().terminal().kind(),
        ) {
            ("started", _) => ("started", "running"),
            (
                "claimed",
                ToolExecutionTerminalKind::Interrupted | ToolExecutionTerminalKind::Indeterminate,
            ) => ("claimed", "pending"),
            _ => return Err(conflict()),
        };
        let execution = load_tool_execution(&transaction, &execution_id)?;
        validate_tool_execution_identity(&execution_id, &intent, &execution)?;
        if execution.status != expected_execution_status {
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
                 WHERE id = ?5 AND status = ?6 AND attempt_count = ?7",
                params![
                    outcome.intent_status,
                    result_artifact_id,
                    expected_receipt,
                    error_json,
                    execution_id.as_str(),
                    expected_intent_status,
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
                 WHERE id = ?5 AND status = ?6",
                params![
                    outcome.execution_status,
                    exit_code,
                    stdout_artifact_id,
                    stderr_artifact_id,
                    execution_id.as_str(),
                    expected_execution_status,
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
