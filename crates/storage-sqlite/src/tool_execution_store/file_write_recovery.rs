
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
        complete_file_write(self, completion, FileWriteCompletionAuthority::ActiveLease)
    }

    fn complete_recovery(
        &self,
        completion: FileWriteRecoveryCompletion,
    ) -> Result<FileWriteRecoverySnapshot, PortError> {
        complete_file_write(
            self,
            completion,
            FileWriteCompletionAuthority::StartupRecovery,
        )
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

#[derive(Clone, Copy)]
enum FileWriteCompletionAuthority {
    ActiveLease,
    StartupRecovery,
}

fn complete_file_write(
    store: &SqliteStore,
    completion: FileWriteRecoveryCompletion,
    authority: FileWriteCompletionAuthority,
) -> Result<FileWriteRecoverySnapshot, PortError> {
    let snapshot = load_file_write_snapshot(store, &completion.execution_id)?;
    validate_file_write_completion(&snapshot, &completion)?;
    let sequence_offset = match authority {
        FileWriteCompletionAuthority::ActiveLease => 1,
        FileWriteCompletionAuthority::StartupRecovery => 2,
    };
    if snapshot.state == FileWriteRecoveryState::Completed {
        if file_write_completion_matches(store, &snapshot, &completion, sequence_offset + 1)? {
            return Ok(snapshot);
        }
        return Err(conflict());
    }
    if snapshot.state != FileWriteRecoveryState::Started {
        return Err(conflict());
    }
    let post_digest =
        Sha256Digest::new(completion.post_evidence.content_hash.clone()).map_err(|_| {
            PortError::failure(
                SafeErrorClassification::InvalidInput,
                Retryability::NonRetryable,
            )
        })?;
    store.artifact_by_id(
        completion.post_evidence.artifact_id.as_str(),
        &post_digest,
        None,
        Some(snapshot.request.task_id.as_str()),
    )?;
    let expected_sequence = snapshot
        .request
        .expected_sequence
        .get()
        .checked_add(sequence_offset)
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
    let mut connection = store.connection().map_err(open_error_to_port)?;
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(sqlite_error_to_port)?;
    verify_evidence_ref_in_transaction(
        &transaction,
        &completion.post_evidence,
        &snapshot.request.task_id,
    )?;
    let mutation_result = match authority {
        FileWriteCompletionAuthority::ActiveLease => {
            record_workspace_mutation_in_transaction(&transaction, mutation)?
        }
        FileWriteCompletionAuthority::StartupRecovery => {
            record_recovered_workspace_mutation_in_transaction(&transaction, mutation)?
        }
    };
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
    load_file_write_snapshot(store, &completion.execution_id)
}
