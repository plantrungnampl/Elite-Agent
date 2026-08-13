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
            ("claimed", "pending") => {
                incomplete.push(IncompleteToolExecution::InFlight(recovery_evidence(
                    &execution_id,
                    &intent,
                )?));
            }
            _ => return Err(integrity_failure()),
        }
    }
    transaction.rollback().map_err(sqlite_error_to_port)?;
    Ok(incomplete)
}
