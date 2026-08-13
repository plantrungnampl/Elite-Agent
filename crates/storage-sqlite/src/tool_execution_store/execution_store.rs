
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
                    canonical_request_artifact_id, operation_digest, actor_binding_digest,
                    status, current_attempt_no, created_at, updated_at
                 ) VALUES (?1, ?2, ?3, ?4, 'non_repeatable', ?5, ?6, ?7, ?8,
                    'pending', 0,
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
                    evidence.actor_binding_digest,
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

    fn begin(&self, _request: NewToolExecution) -> Result<ToolExecutionClaim, PortError> {
        // `NewToolExecution` carries neither the exact policy decision nor an
        // approval decision receipt required to create a v7 operation attempt.
        missing_v7_lifecycle_authority()
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
        _request_artifact_id: &ArtifactId,
        _request: &ImmutableToolRequest,
    ) -> Result<Option<DeniedToolExecution>, PortError> {
        missing_v7_lifecycle_authority()
    }

    fn resolve_denied(
        &self,
        _request: ToolExecutionDenialRequest,
    ) -> Result<DeniedToolExecution, PortError> {
        missing_v7_lifecycle_authority()
    }

    fn request_cancellation(
        &self,
        _execution_id: &ToolExecutionId,
    ) -> Result<ToolExecutionCancellationClaim, PortError> {
        missing_v7_lifecycle_authority()
    }

    fn resolve_terminal(
        &self,
        _resolution: ToolExecutionResolution,
    ) -> Result<DurableToolExecutionReceipt, PortError> {
        missing_v7_lifecycle_authority()
    }

    fn incomplete(&self) -> Result<Vec<IncompleteToolExecution>, PortError> {
        incomplete_with_checkpoint(self, || {})
    }
}

fn missing_v7_lifecycle_authority<T>() -> Result<T, PortError> {
    // These legacy commands do not carry the immutable v7 decision/attempt receipt
    // artifact identities required to mutate or replay lifecycle authority.
    Err(integrity_failure())
}
