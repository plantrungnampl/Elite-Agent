
impl SqliteStore {
    fn tool_request_evidence(
        &self,
        digest: &Sha256Digest,
    ) -> Result<ToolRequestEvidence, PortError> {
        let artifact = self.artifact_by_digest(digest, None, None)?;
        if let Ok(immutable) = parse_tool_request(&artifact.bytes) {
            let request = immutable.request();
            let process = request.process().process();
            if process.binding().task_id().as_str() != artifact.task_id {
                return Err(integrity_failure());
            }
            return Ok(ToolRequestEvidence {
                artifact,
                run_id: process.binding().run_id().as_str().to_owned(),
                tool_name: "process.exec".to_owned(),
                actor_binding_digest: digest_json(&json!({
                    "connectionId": request.policy().actor().connection_id,
                    "agentId": request.policy().actor().agent_id,
                    "trustTier": request.policy().actor().trust_tier.as_str(),
                    "locality": match request.policy().actor().locality {
                        local_agent_terminal_domain::ActorLocality::Local => "local",
                        local_agent_terminal_domain::ActorLocality::Cloud => "cloud",
                    },
                }))?,
            });
        }
        let ApprovalDigestPayload::Tool(payload) =
            parse_canonical_approval_payload(&artifact.bytes).map_err(|_| integrity_failure())?
        else {
            return Err(invalid_input());
        };
        if payload.task_id != artifact.task_id {
            return Err(integrity_failure());
        }
        let _ = payload;
        Err(integrity_failure())
    }

    pub(crate) fn artifact_by_digest(
        &self,
        digest: &Sha256Digest,
        logical_path: Option<&str>,
        expected_task_id: Option<&str>,
    ) -> Result<StoredArtifact, PortError> {
        let connection = self.connection().map_err(open_error_to_port)?;
        let row: Option<StoredArtifactRow> = connection
            .query_row(
                "SELECT a.id, a.task_id, a.project_id, p.artifact_root_path, a.storage_key,
                        a.size_bytes, a.content_hash
                 FROM artifacts a
                 JOIN projects p ON p.id = a.project_id
                 WHERE a.content_hash = ?1 AND a.availability = 'available'
                   AND (?2 IS NULL OR a.logical_path = ?2)
                   AND (?3 IS NULL OR a.task_id = ?3)
                 ORDER BY a.id LIMIT 1",
                params![digest.as_str(), logical_path, expected_task_id],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                        row.get(6)?,
                    ))
                },
            )
            .optional()
            .map_err(sqlite_error_to_port)?;
        let Some(row) = row else {
            return Err(not_found());
        };
        stored_artifact(row)
    }

    pub(crate) fn artifact_by_id(
        &self,
        artifact_id: &str,
        digest: &Sha256Digest,
        logical_path: Option<&str>,
        expected_task_id: Option<&str>,
    ) -> Result<StoredArtifact, PortError> {
        let connection = self.connection().map_err(open_error_to_port)?;
        let row: Option<StoredArtifactRow> = connection
            .query_row(
                "SELECT a.id, a.task_id, a.project_id, p.artifact_root_path, a.storage_key,
                        a.size_bytes, a.content_hash
                 FROM artifacts a
                 JOIN projects p ON p.id = a.project_id
                 WHERE a.id = ?1 AND a.content_hash = ?2 AND a.availability = 'available'
                   AND (?3 IS NULL OR a.logical_path = ?3)
                   AND (?4 IS NULL OR a.task_id = ?4)",
                params![artifact_id, digest.as_str(), logical_path, expected_task_id,],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                        row.get(6)?,
                    ))
                },
            )
            .optional()
            .map_err(sqlite_error_to_port)?;
        let Some(row) = row else {
            return Err(not_found());
        };
        stored_artifact(row)
    }
}

fn stored_artifact(row: StoredArtifactRow) -> Result<StoredArtifact, PortError> {
    let (id, task_id, _project_id, root, storage_key, size, content_hash) = row;
    let task_id = task_id.ok_or_else(integrity_failure)?;
    let path = safe_artifact_path(Path::new(&root), &storage_key)?;
    let bytes = fs::read(path).map_err(|_| integrity_failure())?;
    if i64::try_from(bytes.len()).ok() != Some(size)
        || content_hash != format!("sha256:{:x}", Sha256::digest(&bytes))
    {
        return Err(integrity_failure());
    }
    Ok(StoredArtifact {
        id,
        task_id,
        bytes,
    })
}

#[derive(Debug)]
struct IntentRow {
    task_id: String,
    run_id: String,
    operation_kind: String,
    idempotency_class: String,
    idempotency_key: String,
    artifact_id: String,
    operation_digest: String,
    status: String,
    fencing_token: Option<i64>,
    lease_owner: Option<String>,
    attempt_count: i64,
    result_artifact_id: Option<String>,
    external_receipt_json: Option<String>,
    error_json: Option<String>,
}

fn load_intent(
    connection: &rusqlite::Connection,
    execution_id: &ToolExecutionId,
) -> Result<IntentRow, PortError> {
    connection
        .query_row(
            "SELECT oi.task_id, oi.run_id, oi.operation_kind, oi.idempotency_class,
                    oi.idempotency_key, oi.canonical_request_artifact_id,
                    oi.operation_digest, oi.status,
                    COALESCE(attempt.fencing_token, (
                        SELECT lease.fencing_token FROM executor_leases lease
                        WHERE lease.task_id = oi.task_id AND lease.holder_run_id = oi.run_id
                          AND lease.status = 'active'
                        ORDER BY lease.fencing_token DESC LIMIT 1
                    )), attempt.owner_run_id, oi.current_attempt_no,
                    attempt.result_artifact_id, NULL, NULL
             FROM operation_intents oi
             LEFT JOIN operation_attempts attempt
               ON attempt.operation_intent_id = oi.id
              AND attempt.attempt_no = oi.current_attempt_no
             WHERE oi.id = ?1",
            [execution_id.as_str()],
            |row| {
                Ok(IntentRow {
                    task_id: row.get(0)?,
                    run_id: row
                        .get::<_, Option<String>>(1)?
                        .ok_or(rusqlite::Error::InvalidQuery)?,
                    operation_kind: row.get(2)?,
                    idempotency_class: row.get(3)?,
                    idempotency_key: row.get(4)?,
                    artifact_id: row.get(5)?,
                    operation_digest: row.get(6)?,
                    status: row.get(7)?,
                    fencing_token: row.get(8)?,
                    lease_owner: row.get(9)?,
                    attempt_count: row.get(10)?,
                    result_artifact_id: row.get(11)?,
                    external_receipt_json: row.get(12)?,
                    error_json: row.get(13)?,
                })
            },
        )
        .optional()
        .map_err(sqlite_error_to_port)?
        .ok_or_else(not_found)
}

fn verify_current_lease(
    transaction: &Transaction<'_>,
    intent: &IntentRow,
) -> Result<(), PortError> {
    let Some(token) = intent.fencing_token else {
        return Ok(());
    };
    let current: bool = transaction
        .query_row(
            "SELECT EXISTS(
                SELECT 1 FROM executor_leases l
                JOIN tasks t ON t.id = l.task_id
                WHERE l.task_id = ?1 AND l.holder_run_id = ?2
                  AND l.fencing_token = ?3 AND l.status = 'active'
                  AND julianday(l.expires_at) > julianday('now')
                  AND t.fencing_epoch = l.fencing_token
            )",
            params![intent.task_id, intent.run_id, token],
            |row| row.get(0),
        )
        .map_err(sqlite_error_to_port)?;
    if current {
        Ok(())
    } else {
        Err(conflict())
    }
}

fn validate_tool_intent(
    connection: &rusqlite::Connection,
    execution_id: &ToolExecutionId,
    intent: &IntentRow,
) -> Result<(), PortError> {
    let operation_digest =
        Sha256Digest::new(intent.operation_digest.clone()).map_err(|_| integrity_failure())?;
    TaskId::new(intent.task_id.clone()).map_err(|_| integrity_failure())?;
    RunId::new(intent.run_id.clone()).map_err(|_| integrity_failure())?;
    ArtifactId::new(intent.artifact_id.clone()).map_err(|_| integrity_failure())?;
    if IdempotencyClass::parse(&intent.idempotency_class) != Some(IdempotencyClass::NonRepeatable)
        || intent.idempotency_key != format!("tool:{}:{}", intent.run_id, execution_id.as_str())
        || intent.attempt_count < 0
    {
        return Err(integrity_failure());
    }
    let artifact = artifact_by_id_on_connection(
        connection,
        &intent.artifact_id,
        &operation_digest,
        &intent.task_id,
    )?;
    let persisted_fencing_token = intent
        .fencing_token
        .map(|value| u64::try_from(value).map_err(|_| integrity_failure()))
        .transpose()?;
    if let Ok(immutable) = parse_tool_request(&artifact.bytes) {
        let request = immutable.request();
        let process = request.process().process();
        if request.execution_id() != execution_id
            || process.binding().task_id().as_str() != intent.task_id
            || process.binding().run_id().as_str() != intent.run_id
            || intent.operation_kind != "process.exec"
            || process.executor_fencing_token().map(FencingToken::get) != persisted_fencing_token
        {
            return Err(integrity_failure());
        }
    } else {
        let ApprovalDigestPayload::Tool(payload) =
            parse_canonical_approval_payload(&artifact.bytes)?
        else {
            return Err(integrity_failure());
        };
        if payload.task_id != intent.task_id
            || payload.operation.run_id != intent.run_id
            || payload.operation.tool != intent.operation_kind
            || payload.operation.executor_fencing_token != persisted_fencing_token
        {
            return Err(integrity_failure());
        }
    }
    match intent.status.as_str() {
        "pending"
            if intent.attempt_count == 0
                && intent.lease_owner.is_none()
                && intent.result_artifact_id.is_none()
                && intent.external_receipt_json.is_none()
                && intent.error_json.is_none() =>
        {
            Ok(())
        }
        "claimed"
            if intent.attempt_count > 0
                && intent.lease_owner.as_deref() == Some(intent.run_id.as_str())
                && intent.result_artifact_id.is_none()
                && intent.external_receipt_json.is_none()
                && intent.error_json.is_none() =>
        {
            Ok(())
        }
        "cancelled"
            if intent.attempt_count == 0
                && intent.lease_owner.is_none()
                && intent.result_artifact_id.is_none()
                && intent.external_receipt_json.is_none()
                && intent.error_json.is_some() =>
        {
            Ok(())
        }
        "interrupted" | "indeterminate"
            if intent.attempt_count > 0
                && intent.lease_owner.as_deref() == Some(intent.run_id.as_str()) =>
        {
            validate_terminal_origin(connection, execution_id, intent)
        }
        "started" | "succeeded" | "failed" | "cancelled"
            if intent.attempt_count > 0
                && intent.lease_owner.as_deref() == Some(intent.run_id.as_str()) =>
        {
            validate_started_event(connection, execution_id, intent)
        }
        _ => Err(integrity_failure()),
    }
}

fn validate_terminal_origin(
    connection: &rusqlite::Connection,
    execution_id: &ToolExecutionId,
    intent: &IntentRow,
) -> Result<(), PortError> {
    let started_event_count: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM events
             WHERE event_type = 'tool.execution.started'
               AND json_extract(payload_json, '$.executionId') = ?1",
            [execution_id.as_str()],
            |row| row.get(0),
        )
        .map_err(sqlite_error_to_port)?;
    match started_event_count {
        1 => return validate_started_event(connection, execution_id, intent),
        0 => {}
        _ => return Err(integrity_failure()),
    }
    let execution = load_tool_execution(connection, execution_id)?;
    validate_tool_execution_identity(execution_id, intent, &execution)?;
    if intent.external_receipt_json.is_none()
        || execution.status != intent.status
        || execution.started_at.is_some()
        || execution.completed_at.as_deref().is_none_or(str::is_empty)
        || execution.exit_code.is_some()
        || execution.stdout_artifact_id.is_some()
        || execution.stderr_artifact_id.is_some()
        || intent.result_artifact_id.is_some()
    {
        return Err(integrity_failure());
    }
    Ok(())
}

fn validate_started_event(
    connection: &rusqlite::Connection,
    execution_id: &ToolExecutionId,
    intent: &IntentRow,
) -> Result<(), PortError> {
    let expected_binding = expected_started_process_binding(execution_id, intent)?;
    let expected_root_pid = expected_binding
        .as_ref()
        .map(|binding| i64::from(binding.root_pid()));
    let expected_job_id = expected_binding
        .as_ref()
        .map(AuthoritativeProcessBinding::job_id);
    let valid: bool = connection
        .query_row(
            "SELECT COUNT(*) = 1
             FROM events
             WHERE stream_id = ?1 AND event_type = 'tool.execution.started'
               AND json_extract(payload_json, '$.executionId') = ?2
               AND json_extract(payload_json, '$.operationDigest') = ?3
               AND (
                   (
                       json_extract(payload_json, '$.ownerRunId') = ?4
                       AND json_extract(payload_json, '$.attempt') = ?5
                   )
                   OR (
                       json_type(payload_json, '$.ownerRunId') IS NULL
                       AND json_type(payload_json, '$.attempt') IS NULL
                   )
               )
               AND (
                   (?6 IS NULL
                       AND json_type(payload_json, '$.executorFencingToken') = 'null')
                   OR json_extract(payload_json, '$.executorFencingToken') = ?6
               )
               AND (
                   (?7 IS NULL AND ?8 IS NULL)
                   OR (
                       json_extract(payload_json, '$.rootPid') = ?7
                       AND json_extract(payload_json, '$.jobId') = ?8
                   )
               )",
            params![
                intent.task_id,
                execution_id.as_str(),
                intent.operation_digest,
                intent.run_id,
                intent.attempt_count,
                intent.fencing_token,
                expected_root_pid,
                expected_job_id,
            ],
            |row| row.get(0),
        )
        .map_err(sqlite_error_to_port)?;
    if valid {
        Ok(())
    } else {
        Err(integrity_failure())
    }
}

fn expected_started_process_binding(
    execution_id: &ToolExecutionId,
    intent: &IntentRow,
) -> Result<Option<AuthoritativeProcessBinding>, PortError> {
    let authority = authority_from_intent(execution_id, intent)?;
    if intent.status == "started" {
        return authoritative_process_binding_from_intent(execution_id, intent, &authority);
    }
    let Some(receipt_json) = intent.external_receipt_json.as_deref() else {
        return Ok(None);
    };
    let value = serde_json::from_str::<Value>(receipt_json).map_err(|_| integrity_failure())?;
    if value.get("schema").and_then(Value::as_str) != Some("tool-execution-terminal.v2") {
        return Ok(None);
    }
    let receipt = parse_terminal_receipt(receipt_json)?;
    if receipt.authority() != &authority {
        return Err(integrity_failure());
    }
    receipt
        .process_termination()
        .map(|termination| termination.binding().clone())
        .ok_or_else(integrity_failure)
        .map(Some)
}

pub(crate) fn artifact_by_id_on_connection(
    connection: &rusqlite::Connection,
    artifact_id: &str,
    digest: &Sha256Digest,
    task_id: &str,
) -> Result<StoredArtifact, PortError> {
    let row: Option<StoredArtifactRow> = connection
        .query_row(
            "SELECT a.id, a.task_id, a.project_id, p.artifact_root_path, a.storage_key,
                    a.size_bytes, a.content_hash
             FROM artifacts a
             JOIN projects p ON p.id = a.project_id
             WHERE a.id = ?1 AND a.content_hash = ?2 AND a.availability = 'available'
               AND a.verification_state IN (
                   'hash_verified', 'tool_verified', 'user_approved'
               )
               AND a.task_id = ?3",
            params![artifact_id, digest.as_str(), task_id],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    row.get(6)?,
                ))
            },
        )
        .optional()
        .map_err(sqlite_error_to_port)?;
    stored_artifact(row.ok_or_else(integrity_failure)?)
}

fn load_tool_execution(
    connection: &rusqlite::Connection,
    execution_id: &ToolExecutionId,
) -> Result<PersistedToolExecution, PortError> {
    connection
        .query_row(
            "SELECT task_id, run_id, request_id, tool_name, arguments_artifact_id,
                    policy_decision_id, approval_id, operation_intent_id,
                    executor_fencing_token, status, started_at, exit_code,
                    stdout_artifact_id, stderr_artifact_id, completed_at
             FROM tool_executions WHERE id = ?1",
            [execution_id.as_str()],
            |row| {
                Ok(PersistedToolExecution {
                    task_id: row.get(0)?,
                    run_id: row.get(1)?,
                    request_id: row.get(2)?,
                    tool_name: row.get(3)?,
                    arguments_artifact_id: row.get(4)?,
                    policy_decision_id: row.get(5)?,
                    approval_id: row.get(6)?,
                    operation_intent_id: row.get(7)?,
                    executor_fencing_token: row.get(8)?,
                    status: row.get(9)?,
                    started_at: row.get(10)?,
                    exit_code: row.get(11)?,
                    stdout_artifact_id: row.get(12)?,
                    stderr_artifact_id: row.get(13)?,
                    completed_at: row.get(14)?,
                })
            },
        )
        .optional()
        .map_err(sqlite_error_to_port)?
        .ok_or_else(integrity_failure)
}

fn validate_tool_execution_identity(
    execution_id: &ToolExecutionId,
    intent: &IntentRow,
    execution: &PersistedToolExecution,
) -> Result<(), PortError> {
    if execution.task_id != intent.task_id
        || execution.run_id.as_deref() != Some(intent.run_id.as_str())
        || execution.request_id != execution_id.as_str()
        || execution.tool_name != intent.operation_kind
        || execution.arguments_artifact_id != intent.artifact_id
        || execution.operation_intent_id != execution_id.as_str()
        || execution.executor_fencing_token != intent.fencing_token
    {
        return Err(integrity_failure());
    }
    Ok(())
}

fn claim_authority(
    execution_id: &ToolExecutionId,
    intent: &IntentRow,
    attempt: u32,
) -> Result<ToolExecutionClaimAuthority, PortError> {
    ToolExecutionClaimAuthority::from_persisted(
        execution_id.clone(),
        Sha256Digest::new(intent.operation_digest.clone()).map_err(|_| integrity_failure())?,
        RunId::new(intent.run_id.clone()).map_err(|_| integrity_failure())?,
        attempt,
        intent
            .fencing_token
            .map(|value| FencingToken::try_from(value).map_err(|_| integrity_failure()))
            .transpose()?,
    )
    .map_err(|_| integrity_failure())
}

fn authority_from_intent(
    execution_id: &ToolExecutionId,
    intent: &IntentRow,
) -> Result<ToolExecutionClaimAuthority, PortError> {
    let attempt = u32::try_from(intent.attempt_count).map_err(|_| integrity_failure())?;
    claim_authority(execution_id, intent, attempt)
}

fn recovery_evidence(
    execution_id: &ToolExecutionId,
    intent: &IntentRow,
) -> Result<ToolExecutionRecoveryEvidence, PortError> {
    let authority = authority_from_intent(execution_id, intent)?;
    let process_binding =
        authoritative_process_binding_from_intent(execution_id, intent, &authority)?;
    let state = match intent.status.as_str() {
        "claimed" => ToolExecutionRecoveryState::Claimed,
        "started" => ToolExecutionRecoveryState::Started,
        "indeterminate" => ToolExecutionRecoveryState::Indeterminate,
        _ => return Err(integrity_failure()),
    };
    Ok(ToolExecutionRecoveryEvidence {
        authority,
        task_id: TaskId::new(intent.task_id.clone()).map_err(|_| integrity_failure())?,
        canonical_request_artifact_id: ArtifactId::new(intent.artifact_id.clone())
            .map_err(|_| integrity_failure())?,
        idempotency_class: IdempotencyClass::parse(&intent.idempotency_class)
            .ok_or_else(integrity_failure)?,
        state,
        process_binding,
    })
}

struct TerminalOutcome {
    intent_status: &'static str,
    execution_status: &'static str,
}

fn terminal_outcome(terminal: &ToolExecutionTerminal) -> TerminalOutcome {
    match terminal.kind() {
        ToolExecutionTerminalKind::Succeeded => TerminalOutcome {
            intent_status: "succeeded",
            execution_status: "succeeded",
        },
        ToolExecutionTerminalKind::Failed => TerminalOutcome {
            intent_status: "failed",
            execution_status: "failed",
        },
        ToolExecutionTerminalKind::Cancelled => TerminalOutcome {
            intent_status: "cancelled",
            execution_status: "cancelled",
        },
        ToolExecutionTerminalKind::Terminated => TerminalOutcome {
            intent_status: "failed",
            execution_status: "terminated",
        },
        ToolExecutionTerminalKind::Interrupted => TerminalOutcome {
            intent_status: "interrupted",
            execution_status: "interrupted",
        },
        ToolExecutionTerminalKind::Indeterminate => TerminalOutcome {
            intent_status: "indeterminate",
            execution_status: "indeterminate",
        },
    }
}

#[derive(Clone, Copy)]
enum ToolArtifactSlot {
    Stdout,
    Stderr,
}

fn artifact_id(terminal: &ToolExecutionTerminal, slot: ToolArtifactSlot) -> Option<&str> {
    let artifacts = &terminal.output()?.artifacts;
    let artifact = match slot {
        ToolArtifactSlot::Stdout => artifacts.stdout(),
        ToolArtifactSlot::Stderr => artifacts.stderr(),
    };
    match artifact {
        DurableToolExecutionArtifact::Available(id) => Some(id.as_str()),
        DurableToolExecutionArtifact::Unavailable => None,
    }
}

fn primary_artifact_id(terminal: &ToolExecutionTerminal) -> Option<&str> {
    artifact_id(terminal, ToolArtifactSlot::Stdout)
        .or_else(|| artifact_id(terminal, ToolArtifactSlot::Stderr))
        .or_else(|| {
            terminal
                .output()?
                .artifacts
                .observed_writes()
                .iter()
                .find_map(|artifact| match artifact {
                    DurableToolExecutionArtifact::Available(id) => Some(id.as_str()),
                    DurableToolExecutionArtifact::Unavailable => None,
                })
        })
}

fn validate_terminal_artifacts(
    connection: &rusqlite::Connection,
    task_id: &str,
    terminal: &ToolExecutionTerminal,
) -> Result<(), PortError> {
    let Some(output) = terminal.output() else {
        return Ok(());
    };
    for artifact in std::iter::once(output.artifacts.stdout())
        .chain(std::iter::once(output.artifacts.stderr()))
        .chain(output.artifacts.observed_writes())
    {
        let DurableToolExecutionArtifact::Available(artifact_id) = artifact else {
            continue;
        };
        let content_hash: Option<String> = connection
            .query_row(
                "SELECT content_hash FROM artifacts WHERE id = ?1 AND task_id = ?2",
                params![artifact_id.as_str(), task_id],
                |row| row.get(0),
            )
            .optional()
            .map_err(sqlite_error_to_port)?;
        let digest = Sha256Digest::new(content_hash.ok_or_else(integrity_failure)?)
            .map_err(|_| integrity_failure())?;
        artifact_by_id_on_connection(connection, artifact_id.as_str(), &digest, task_id)?;
    }
    Ok(())
}
