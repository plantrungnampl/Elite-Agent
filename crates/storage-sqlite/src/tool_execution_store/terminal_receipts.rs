
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
    let mut value = json!({
        "authority": {
            "attempt": authority.attempt(),
            "executionId": authority.execution_id().as_str(),
            "executorFencingToken": authority.executor_fencing_token().map(FencingToken::get),
            "operationDigest": authority.operation_digest().as_str(),
            "ownerRunId": authority.owner_run_id().as_str(),
        },
        "schema": "tool-execution-terminal.v1",
        "terminal": terminal_value(receipt.terminal()),
    });
    if let Some(termination) = receipt.process_termination() {
        value["schema"] = json!("tool-execution-terminal.v2");
        value["processTermination"] = process_termination_value(termination);
    }
    value
}

fn process_termination_value(termination: &AuthoritativeProcessTermination) -> serde_json::Value {
    let binding = termination.binding();
    let receipt = termination.receipt();
    let job = receipt
        .job_receipt
        .as_ref()
        .expect("authoritative process termination has a Job receipt");
    json!({
        "binding": {
            "jobId": binding.job_id(),
            "rootPid": binding.root_pid(),
        },
        "receipt": {
            "cancelled": receipt.cancelled,
            "executionId": receipt.execution_id.as_str(),
            "job": {
                "cpuTimeLimitMs": job.cpu_time_limit_ms,
                "jobCpuTimeLimit": job.job_cpu_time_limit,
                "jobId": job.job_id,
                "jobMemoryLimit": job.job_memory_limit,
                "killOnClose": job.kill_on_close,
                "maxActiveProcesses": job.max_active_processes,
                "memoryLimitBytes": job.memory_limit_bytes,
                "noBreakaway": job.no_breakaway,
                "resourceLimitTerminated": job.resource_limit_terminated,
                "rootPid": job.root_pid,
                "totalUserTimeMs": job.total_user_time_ms,
                "treeTerminated": job.tree_terminated,
            },
            "status": "terminated",
        },
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
            let mut value = json!({
                "error": {
                    "classification": error_classification_name(error.classification),
                    "retryability": retryability_name(error.retryability),
                },
                "kind": terminal_kind_name(terminal.kind()),
            });
            if let Some(post_effect) = terminal.post_effect() {
                value["postEffect"] = post_effect_value(post_effect);
            }
            value
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

fn post_effect_value(receipt: &ToolExecutionPostEffectReceipt) -> serde_json::Value {
    json!({
        "executionId": receipt.execution_id.as_str(),
        "status": match receipt.status {
            ProcessStatus::Exited => "exited",
            ProcessStatus::Terminated => "terminated",
        },
        "exitCode": receipt.exit_code,
        "stdout": stream_metadata_value(&receipt.stdout),
        "stderr": stream_metadata_value(&receipt.stderr),
        "durationMs": receipt.duration_ms,
        "outputDigest": receipt.output_digest.as_str(),
        "observedWrites": receipt
            .observed_writes
            .iter()
            .map(|write| json!({
                "digest": write.digest.as_str(),
                "sizeBytes": write.size_bytes,
            }))
            .collect::<Vec<_>>(),
    })
}

fn stream_metadata_value(metadata: &ToolExecutionStreamMetadata) -> serde_json::Value {
    json!({
        "digest": metadata.digest.as_str(),
        "sizeBytes": metadata.size_bytes,
        "truncated": metadata.truncated,
    })
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
        let mut value = json!({
            "classification": error_classification_name(error.classification),
            "retryability": retryability_name(error.retryability),
        });
        if let Some(post_effect) = terminal.post_effect() {
            value["postEffect"] = post_effect_value(post_effect);
        }
        value.to_string()
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
    let schema = required_string(&value, "schema")?;
    if !matches!(
        schema,
        "tool-execution-terminal.v1" | "tool-execution-terminal.v2"
    ) {
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
            let error = SafeToolExecutionError {
                classification: parse_error_classification(required_string(
                    error,
                    "classification",
                )?)?,
                retryability: parse_retryability(required_string(error, "retryability")?)?,
            };
            match terminal.get("postEffect") {
                Some(post_effect) => Ok(ToolExecutionTerminal::indeterminate_with_post_effect(
                    error,
                    parse_post_effect_receipt(post_effect, authority.execution_id())?,
                )),
                None => Ok(ToolExecutionTerminal::indeterminate(error)),
            }
        }
        _ => Err(integrity_failure()),
    }
    .map_err(|_| integrity_failure())?;
    match schema {
        "tool-execution-terminal.v1" => {
            if value.get("processTermination").is_some() {
                return Err(integrity_failure());
            }
            Ok(DurableToolExecutionReceipt::new(authority, terminal))
        }
        "tool-execution-terminal.v2" => {
            let error = terminal.error().copied().ok_or_else(integrity_failure)?;
            let termination = parse_process_termination(&value, authority)?;
            let receipt = DurableToolExecutionReceipt::recovered_process_termination(
                error.classification,
                termination,
            );
            if receipt.terminal() != &terminal {
                return Err(integrity_failure());
            }
            Ok(receipt)
        }
        _ => Err(integrity_failure()),
    }
}

fn parse_post_effect_receipt(
    value: &serde_json::Value,
    expected_execution_id: &ToolExecutionId,
) -> Result<ToolExecutionPostEffectReceipt, PortError> {
    let execution_id = ToolExecutionId::new(required_string(value, "executionId")?)
        .map_err(|_| integrity_failure())?;
    if &execution_id != expected_execution_id {
        return Err(integrity_failure());
    }
    let status = match required_string(value, "status")? {
        "exited" => ProcessStatus::Exited,
        "terminated" => ProcessStatus::Terminated,
        _ => return Err(integrity_failure()),
    };
    let stdout = parse_stream_metadata(required_object(value, "stdout")?)?;
    let stderr = parse_stream_metadata(required_object(value, "stderr")?)?;
    let observed_writes = value
        .get("observedWrites")
        .and_then(Value::as_array)
        .ok_or_else(integrity_failure)?
        .iter()
        .map(|write| {
            Ok(local_agent_terminal_application::VerifiedWrite {
                digest: Sha256Digest::new(required_string(write, "digest")?)
                    .map_err(|_| integrity_failure())?,
                size_bytes: required_u64(write, "sizeBytes")?,
            })
        })
        .collect::<Result<Vec<_>, PortError>>()?;
    Ok(ToolExecutionPostEffectReceipt {
        execution_id,
        status,
        exit_code: match value.get("exitCode") {
            None | Some(Value::Null) => None,
            Some(value) => Some(
                value
                    .as_i64()
                    .ok_or_else(integrity_failure)
                    .and_then(|value| i32::try_from(value).map_err(|_| integrity_failure()))?,
            ),
        },
        stdout,
        stderr,
        duration_ms: required_u64(value, "durationMs")?,
        output_digest: Sha256Digest::new(required_string(value, "outputDigest")?)
            .map_err(|_| integrity_failure())?,
        observed_writes,
    })
}

fn parse_stream_metadata(value: &Value) -> Result<ToolExecutionStreamMetadata, PortError> {
    Ok(ToolExecutionStreamMetadata {
        digest: Sha256Digest::new(required_string(value, "digest")?)
            .map_err(|_| integrity_failure())?,
        size_bytes: required_u64(value, "sizeBytes")?,
        truncated: required_bool(value, "truncated")?,
    })
}

fn parse_process_termination(
    value: &serde_json::Value,
    authority: ToolExecutionClaimAuthority,
) -> Result<AuthoritativeProcessTermination, PortError> {
    let termination = required_object(value, "processTermination")?;
    let binding = required_object(termination, "binding")?;
    let root_pid =
        u32::try_from(required_u64(binding, "rootPid")?).map_err(|_| integrity_failure())?;
    let binding =
        AuthoritativeProcessBinding::new(authority, root_pid, required_string(binding, "jobId")?)
            .map_err(|_| integrity_failure())?;

    let receipt = required_object(termination, "receipt")?;
    if required_string(receipt, "status")? != "terminated" {
        return Err(integrity_failure());
    }
    let job = required_object(receipt, "job")?;
    let cancellation = CancellationReceipt {
        execution_id: ToolExecutionId::new(required_string(receipt, "executionId")?)
            .map_err(|_| integrity_failure())?,
        status: ProcessStatus::Terminated,
        job_receipt: Some(JobReceipt {
            root_pid: u32::try_from(required_u64(job, "rootPid")?)
                .map_err(|_| integrity_failure())?,
            job_id: required_string(job, "jobId")?.to_owned(),
            kill_on_close: required_bool(job, "killOnClose")?,
            no_breakaway: required_bool(job, "noBreakaway")?,
            job_memory_limit: required_bool(job, "jobMemoryLimit")?,
            job_cpu_time_limit: required_bool(job, "jobCpuTimeLimit")?,
            memory_limit_bytes: required_u64(job, "memoryLimitBytes")?,
            cpu_time_limit_ms: required_u64(job, "cpuTimeLimitMs")?,
            max_active_processes: u32::try_from(required_u64(job, "maxActiveProcesses")?)
                .map_err(|_| integrity_failure())?,
            total_user_time_ms: required_u64(job, "totalUserTimeMs")?,
            resource_limit_terminated: required_bool(job, "resourceLimitTerminated")?,
            tree_terminated: required_bool(job, "treeTerminated")?,
        }),
        cancelled: required_bool(receipt, "cancelled")?,
    };
    AuthoritativeProcessTermination::new(binding, cancellation).map_err(|_| integrity_failure())
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
    let expected_audit_payload = if parsed.current_schema {
        audited_tool_event_payload(
            connection,
            &intent.task_id,
            execution_id.as_str(),
            parsed.audit_payload.clone(),
        )?
    } else {
        parsed.audit_payload.clone()
    };
    if audit_payloads.len() != 1
        || serde_json::from_str::<serde_json::Value>(&audit_payloads[0].1)
            .map_err(|_| integrity_failure())?
            != expected_audit_payload
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

struct ToolAuditContext {
    actor_id: String,
    actor_json: String,
    actor_binding_digest: String,
    effective_role: String,
    request_digest: String,
    operation_digest: String,
    policy_decision_id: String,
    policy_snapshot_digest: String,
    approval_id: Option<String>,
    resource_json: String,
    fencing_token: Option<i64>,
}

fn audited_tool_event_payload(
    connection: &rusqlite::Connection,
    task_id: &str,
    execution_id: &str,
    mut payload: Value,
) -> Result<Value, PortError> {
    let context = connection
        .query_row(
            "SELECT ar.agent_id, pd.actor_json, pd.actor_binding_digest, ar.role,
                    a.content_hash, oi.operation_digest, te.policy_decision_id,
                    pd.policy_snapshot_digest, te.approval_id, pd.resource_json,
                    te.executor_fencing_token
             FROM tool_executions te
             JOIN operation_intents oi ON oi.id = te.operation_intent_id
             JOIN policy_decisions pd ON pd.id = te.policy_decision_id
             JOIN artifacts a ON a.id = te.arguments_artifact_id
             JOIN agent_runs ar ON ar.id = te.run_id AND ar.task_id = te.task_id
             WHERE te.id = ?1 AND te.task_id = ?2",
            params![execution_id, task_id],
            |row| {
                Ok(ToolAuditContext {
                    actor_id: row.get(0)?,
                    actor_json: row.get(1)?,
                    actor_binding_digest: row.get(2)?,
                    effective_role: row.get(3)?,
                    request_digest: row.get(4)?,
                    operation_digest: row.get(5)?,
                    policy_decision_id: row.get(6)?,
                    policy_snapshot_digest: row.get(7)?,
                    approval_id: row.get(8)?,
                    resource_json: row.get(9)?,
                    fencing_token: row.get(10)?,
                })
            },
        )
        .optional()
        .map_err(sqlite_error_to_port)?
        .ok_or_else(integrity_failure)?;
    let actor: Value =
        serde_json::from_str(&context.actor_json).map_err(|_| integrity_failure())?;
    let scope: Value =
        serde_json::from_str(&context.resource_json).map_err(|_| integrity_failure())?;
    let fields = [
        ("auditSchema", json!("tool-audit.v1")),
        ("actorId", json!(context.actor_id)),
        (
            "actorBinding",
            json!({"actor": actor, "digest": context.actor_binding_digest}),
        ),
        ("effectiveRole", json!(context.effective_role)),
        ("requestDigest", json!(context.request_digest)),
        ("operationDigest", json!(context.operation_digest)),
        ("policyDecisionId", json!(context.policy_decision_id)),
        (
            "policySnapshotDigest",
            json!(context.policy_snapshot_digest),
        ),
        ("approvalId", json!(context.approval_id)),
        ("scope", scope),
        ("executorFencingToken", json!(context.fencing_token)),
        ("observationClass", json!("tool_verified")),
    ];
    let object = payload.as_object_mut().ok_or_else(integrity_failure)?;
    for (field, value) in fields {
        if object.get(field).is_some_and(|existing| existing != &value) {
            return Err(integrity_failure());
        }
        object.insert(field.to_owned(), value);
    }
    Ok(payload)
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
