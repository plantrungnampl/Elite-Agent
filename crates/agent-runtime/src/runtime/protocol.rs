
#[derive(Clone)]
struct RuntimeTime {
    text: String,
    date_time: DateTime<Utc>,
    timestamp: Timestamp,
}

enum HandlerWaitError {
    Rejected(&'static str),
    Internal,
}

fn runtime_time(clock: &dyn Clock) -> Result<RuntimeTime, PortError> {
    let text = clock.now_utc()?;
    let date_time = DateTime::parse_from_rfc3339(&text)
        .map_err(|_| invalid_input())?
        .with_timezone(&Utc);
    Ok(RuntimeTime {
        text,
        date_time,
        timestamp: Timestamp::from_unix_seconds(date_time.timestamp()),
    })
}

fn timestamp_date_time(timestamp: Timestamp) -> Result<DateTime<Utc>, PortError> {
    DateTime::from_timestamp(timestamp.unix_seconds(), 0).ok_or_else(invalid_input)
}

fn validate_descriptor(
    descriptor: &AgentDescriptor,
    peer: &PeerDescriptor,
) -> Result<(), PortError> {
    let executable = descriptor
        .executable_digest
        .as_ref()
        .map(Sha256Digest::as_str);
    if descriptor.agent_id != peer.binding.agent_id
        || descriptor.manifest_digest.as_str() != peer.binding.manifest_digest
        || executable != Some(peer.binding.executable_digest.as_str())
        || trust_tier(descriptor.trust_tier) != peer.binding.trust_tier
    {
        return Err(invalid_input());
    }
    Ok(())
}

fn validate_request_peer(
    request: &BoundAgentRunRequest,
    peer: &PeerDescriptor,
    authoritative_connection_digest: &Sha256Digest,
) -> Result<(), PortError> {
    if request.connection.connection_id != peer.binding.connection_id
        || request.connection.agent_id != peer.binding.agent_id
        || request.connection.manifest_digest.as_str() != peer.binding.manifest_digest
        || request
            .connection
            .executable_digest
            .as_ref()
            .map(Sha256Digest::as_str)
            != Some(peer.binding.executable_digest.as_str())
        || trust_tier(request.connection.trust_tier) != peer.binding.trust_tier
        || request.connection.contract_version != peer.protocol_version
        || &request.connection.binding_digest != authoritative_connection_digest
        || !peer.capabilities.roles.contains(&request.role)
    {
        return Err(invalid_input());
    }
    Ok(())
}

fn protocol_request_error_category(error: ProtocolError) -> &'static str {
    match error {
        ProtocolError::OutputLimitExceeded => "output_limit_exceeded",
        ProtocolError::Timeout => "request_deadline_exceeded",
        ProtocolError::PolicyDenied => "policy_denied",
        ProtocolError::ApprovalRequired => "approval_required",
        ProtocolError::StaleFencingToken => "stale_fencing_token",
        _ => "invalid_request",
    }
}

fn trust_tier(value: TrustTier) -> ProtocolTrustTier {
    match value {
        TrustTier::CoreAdapter => ProtocolTrustTier::CoreAdapter,
        TrustTier::BrokeredProcess => ProtocolTrustTier::BrokeredProcess,
        TrustTier::IsolatedWorker => ProtocolTrustTier::IsolatedWorker,
        TrustTier::FullAccessLegacy => ProtocolTrustTier::FullAccessLegacy,
    }
}

fn initialize_frame(
    descriptor: &PeerDescriptor,
    request_id: &str,
) -> Result<ProtocolFrame, PortError> {
    decode_frame(json!({
        "jsonrpc": "2.0",
        "id": request_id,
        "method": "initialize",
        "params": {
            "protocolVersions": [descriptor.protocol_version],
            "client": { "name": "local-agent-terminal", "version": "0.1.0" },
            "transport": { "type": "stdio-ndjson", "maxFrameBytes": DEFAULT_MAX_FRAME_BYTES },
            "features": features(&descriptor.capabilities),
            "launchBinding": {
                "connectionId": descriptor.binding.connection_id,
                "manifestDigest": descriptor.binding.manifest_digest,
                "executableDigest": descriptor.binding.executable_digest,
                "trustTier": descriptor.binding.trust_tier.as_str()
            }
        }
    }))
}

fn initialize_response(
    descriptor: &PeerDescriptor,
    request_id: &str,
) -> Result<ProtocolFrame, PortError> {
    success_response(
        request_id,
        json!({
            "protocolVersion": descriptor.protocol_version,
            "agent": {
                "id": descriptor.binding.agent_id,
                "displayName": descriptor.binding.agent_id,
                "implementationVersion": "1"
            },
            "capabilities": capabilities_json(&descriptor.capabilities)
        }),
    )
}

fn initialized_frame(descriptor: &PeerDescriptor) -> Result<ProtocolFrame, PortError> {
    decode_frame(json!({
        "jsonrpc": "2.0",
        "method": "initialized",
        "params": {
            "connectionId": descriptor.binding.connection_id,
            "effectiveCapabilitiesDigest": effective_capabilities_digest(&descriptor.capabilities)
        }
    }))
}

fn run_start_frame(
    request: &BoundAgentRunRequest,
    descriptor: &PeerDescriptor,
    request_id: &str,
) -> Result<ProtocolFrame, PortError> {
    let mut value = json!({
        "jsonrpc": "2.0",
        "id": request_id,
        "method": "agent.run.start",
        "params": {
            "runId": request.run_id.as_str(),
            "idempotencyKey": request.idempotency_key,
            "taskId": request.task_id.as_str(),
            "role": request.role,
            "objective": request.context.objective,
            "contextPackage": {
                "packageId": request.context.context_package_id,
                "contentDigest": request.context.content_digest.as_str(),
                "manifestRef": request.context.manifest_artifact_id.as_str()
            },
            "permissions": {
                "contextQuery": descriptor.capabilities.context_query,
                "toolRequest": descriptor.capabilities.tool_requests,
                "writeFiles": false
            },
            "responseSchema": request.run_config.response_schema_version,
            "limits": {
                "deadline": timestamp_date_time(request.run_config.limits.deadline)?.to_rfc3339(),
                "maxOutputTokens": request.run_config.limits.max_output_tokens,
                "maxToolRequests": request.run_config.limits.max_tool_requests
            }
        }
    });
    if let Some(supersedes_run_id) = &request.supersedes_run_id {
        value
            .pointer_mut("/params")
            .and_then(Value::as_object_mut)
            .ok_or_else(internal_failure)?
            .insert(
                "supersedesRunId".to_owned(),
                Value::String(supersedes_run_id.as_str().to_owned()),
            );
    }
    decode_frame(value)
}

fn cancel_frame(
    run_id: &RunId,
    request_id: &str,
    reason: &str,
    deadline_ms: u64,
) -> Result<ProtocolFrame, PortError> {
    decode_frame(json!({
        "jsonrpc": "2.0",
        "id": request_id,
        "method": "agent.run.cancel",
        "params": { "runId": run_id.as_str(), "reason": reason, "deadlineMs": deadline_ms }
    }))
}

fn success_response(request_id: &str, result: Value) -> Result<ProtocolFrame, PortError> {
    decode_frame(json!({ "jsonrpc": "2.0", "id": request_id, "result": result }))
}

fn error_response(
    request_id: &str,
    category: &str,
    retryable: bool,
) -> Result<ProtocolFrame, PortError> {
    decode_frame(json!({
        "jsonrpc": "2.0",
        "id": request_id,
        "error": {
            "code": -32040,
            "message": "Agent-originated request is not available",
            "data": { "category": category, "retryable": retryable }
        }
    }))
}

fn decode_frame(value: Value) -> Result<ProtocolFrame, PortError> {
    let bytes = serde_json::to_vec(&value).map_err(|_| internal_failure())?;
    NdjsonCodec::default()
        .decode(&bytes)
        .map_err(protocol_port_error)
}

fn features(capabilities: &ProtocolCapabilities) -> Vec<&'static str> {
    let mut features = Vec::new();
    if capabilities.streaming {
        features.push("streaming");
    }
    if capabilities.context_query {
        features.push("context-query");
    }
    if capabilities.tool_requests {
        features.push("tool-request");
    }
    if capabilities.specialist_requests {
        features.push("specialist-request");
    }
    features
}

fn capabilities_json(capabilities: &ProtocolCapabilities) -> Value {
    json!({
        "roles": capabilities.roles,
        "skills": capabilities.skills,
        "streaming": capabilities.streaming,
        "contextQuery": capabilities.context_query,
        "toolRequests": capabilities.tool_requests,
        "specialistRequests": capabilities.specialist_requests,
        "maxConcurrentRuns": capabilities.max_concurrent_runs,
        "maxContextTokens": capabilities.max_context_tokens
    })
}

fn effective_capabilities_digest(capabilities: &ProtocolCapabilities) -> String {
    let bytes = serde_json::to_vec(&capabilities_json(capabilities))
        .expect("capabilities JSON must be serializable");
    format!("sha256:{:x}", Sha256::digest(bytes))
}

fn terminal_from_frame(
    frame: &ProtocolFrame,
    request: &BoundAgentRunRequest,
    content_artifact_id: ArtifactId,
    at: Timestamp,
) -> Result<AgentRunTerminal, ProtocolError> {
    let value = frame_value(frame)?;
    let params = value
        .get("params")
        .and_then(Value::as_object)
        .ok_or(ProtocolError::InvalidRequest)?;
    let message = params
        .get("message")
        .and_then(Value::as_object)
        .ok_or(ProtocolError::InvalidRequest)?;
    let message_id = required_string(&value, "/params/message/messageId")?;
    let status = match required_string(&value, "/params/status")?.as_str() {
        "succeeded" => AgentRunStatus::Succeeded,
        "failed" => AgentRunStatus::Failed,
        "cancelled_cleanly" => AgentRunStatus::CancelledCleanly,
        _ => return Err(ProtocolError::InvalidRequest),
    };
    let claims = message
        .get("claims")
        .and_then(Value::as_array)
        .ok_or(ProtocolError::InvalidRequest)?
        .iter()
        .map(parse_claim)
        .collect::<Result<Vec<_>, _>>()?;
    let usage = params
        .get("usage")
        .and_then(Value::as_object)
        .map(|usage| AgentUsage {
            input_tokens: usage
                .get("inputTokens")
                .and_then(Value::as_i64)
                .unwrap_or(0),
            output_tokens: usage
                .get("outputTokens")
                .and_then(Value::as_i64)
                .unwrap_or(0),
            cost_microunits: usage
                .get("providerReportedCost")
                .and_then(Value::as_f64)
                .map(|cost| (cost * 1_000_000.0).round() as i64),
        });
    let terminal = AgentRunTerminal {
        run_id: request.run_id.clone(),
        task_id: request.task_id.clone(),
        status,
        message: AgentRunMessage {
            message_id,
            task_id: request.task_id.clone(),
            run_id: request.run_id.clone(),
            thread_id: message
                .get("threadId")
                .and_then(Value::as_str)
                .map(str::to_owned)
                .unwrap_or_else(|| stable_id("thread", request.run_id.as_str())),
            message_type: required_string(&value, "/params/message/type")?,
            reply_to: message
                .get("replyTo")
                .and_then(Value::as_str)
                .map(str::to_owned),
            content_artifact_id,
            claims,
        },
        provider_usage: usage,
        core_usage: None,
        estimated_cost_microunits: None,
        error: (status == AgentRunStatus::Failed).then(|| "agent reported failure".to_owned()),
        core_received_at: Some(at),
    };
    terminal
        .validate()
        .map_err(|_| ProtocolError::InvalidRequest)?;
    Ok(terminal)
}

fn parse_claim(value: &Value) -> Result<AgentClaim, ProtocolError> {
    let object = value.as_object().ok_or(ProtocolError::InvalidRequest)?;
    let evidence = object
        .get("evidenceRefs")
        .and_then(Value::as_array)
        .ok_or(ProtocolError::InvalidRequest)?
        .iter()
        .map(parse_evidence)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(AgentClaim {
        claim_id: required_object_string(object, "claimId")?,
        text: required_object_string(object, "text")?,
        evidence,
        confidence: object
            .get("confidence")
            .and_then(Value::as_f64)
            .ok_or(ProtocolError::InvalidRequest)?,
    })
}

fn parse_evidence(value: &Value) -> Result<AgentEvidenceRef, ProtocolError> {
    let object = value.as_object().ok_or(ProtocolError::InvalidRequest)?;
    Ok(AgentEvidenceRef {
        source_type: required_object_string(object, "sourceType")?,
        source_id: required_object_string(object, "sourceId")?,
        revision: required_object_string(object, "revision")?,
        content_digest: Sha256Digest::new(required_object_string(object, "contentDigest")?)
            .map_err(|_| ProtocolError::InvalidRequest)?,
        start_line: optional_u32(object.get("startLine"))?,
        end_line: optional_u32(object.get("endLine"))?,
        symbol: object
            .get("symbol")
            .and_then(Value::as_str)
            .map(str::to_owned),
    })
}

fn optional_u32(value: Option<&Value>) -> Result<Option<u32>, ProtocolError> {
    value
        .map(|value| {
            value
                .as_u64()
                .and_then(|value| u32::try_from(value).ok())
                .ok_or(ProtocolError::InvalidRequest)
        })
        .transpose()
}

fn runtime_terminal(
    request: &BoundAgentRunRequest,
    status: AgentRunStatus,
    error: &str,
    content_artifact_id: ArtifactId,
    at: Timestamp,
) -> AgentRunTerminal {
    AgentRunTerminal {
        run_id: request.run_id.clone(),
        task_id: request.task_id.clone(),
        status,
        message: AgentRunMessage {
            message_id: stable_id("runtime-message", request.run_id.as_str()),
            task_id: request.task_id.clone(),
            run_id: request.run_id.clone(),
            thread_id: stable_id("thread", request.run_id.as_str()),
            message_type: "status".to_owned(),
            reply_to: None,
            content_artifact_id,
            claims: Vec::new(),
        },
        provider_usage: None,
        core_usage: None,
        estimated_cost_microunits: None,
        error: Some(error.to_owned()),
        core_received_at: Some(at),
    }
}

fn terminal_content(frame: &ProtocolFrame) -> Result<String, ProtocolError> {
    required_string(&frame_value(frame)?, "/params/message/content")
}

fn publish_runtime_terminal(
    artifacts: &dyn AgentArtifactStore,
    store: &dyn AgentRunStore,
    request: &BoundAgentRunRequest,
    status: AgentRunStatus,
    error: &str,
    at: Timestamp,
) -> Result<(), PortError> {
    let message_id = stable_id("runtime-message", request.run_id.as_str());
    let content_artifact_id = artifacts.publish_agent_message(&AgentMessageArtifact {
        task_id: request.task_id.clone(),
        run_id: request.run_id.clone(),
        message_id,
        content: error.as_bytes().to_vec(),
    })?;
    store.persist_terminal(&runtime_terminal(
        request,
        status,
        error,
        content_artifact_id,
        at,
    ))
}

fn stable_id(prefix: &str, value: &str) -> String {
    format!("{prefix}-{:x}", Sha256::digest(value.as_bytes()))
}

fn digest_bytes(bytes: &[u8]) -> Sha256Digest {
    Sha256Digest::new(format!("sha256:{:x}", Sha256::digest(bytes)))
        .expect("SHA-256 formatting is valid")
}

fn frame_value(frame: &ProtocolFrame) -> Result<Value, ProtocolError> {
    serde_json::to_value(frame).map_err(|_| ProtocolError::InvalidRequest)
}

fn required_string(value: &Value, pointer: &str) -> Result<String, ProtocolError> {
    value
        .pointer(pointer)
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or(ProtocolError::InvalidRequest)
}

fn required_u64(value: &Value, pointer: &str) -> Result<u64, ProtocolError> {
    value
        .pointer(pointer)
        .and_then(Value::as_u64)
        .ok_or(ProtocolError::InvalidRequest)
}

fn required_string_array(value: &Value, pointer: &str) -> Result<Vec<String>, ProtocolError> {
    value
        .pointer(pointer)
        .and_then(Value::as_array)
        .ok_or(ProtocolError::InvalidRequest)?
        .iter()
        .map(|item| {
            item.as_str()
                .map(str::to_owned)
                .ok_or(ProtocolError::InvalidRequest)
        })
        .collect()
}

fn has_duplicate_strings(values: &[String]) -> bool {
    let unique = values.iter().collect::<BTreeSet<_>>();
    unique.len() != values.len()
}

fn valid_context_response(
    response: &AgentContextQueryResponse,
    request: &BoundAgentRunRequest,
    query_id: &str,
    max_items: u32,
    max_tokens: u64,
) -> bool {
    response.run_id == request.run_id
        && response.task_id == request.task_id
        && response.query_id == query_id
        && valid_opaque_reference(&response.supplement_id)
        && response.token_count <= max_tokens
        && u32::try_from(response.item_ids.len()).is_ok_and(|count| count <= max_items)
        && response
            .item_ids
            .iter()
            .all(|item| valid_opaque_reference(item))
        && response
            .policy_decision_ids
            .iter()
            .all(|decision| valid_opaque_reference(decision))
        && response
            .provenance
            .iter()
            .all(|provenance| valid_opaque_reference(provenance))
        && response
            .redactions
            .iter()
            .all(|redaction| valid_opaque_reference(redaction))
        && !has_duplicate_strings(&response.item_ids)
        && !has_duplicate_strings(&response.policy_decision_ids)
        && !has_duplicate_strings(&response.provenance)
        && !has_duplicate_strings(&response.redactions)
}

fn valid_opaque_reference(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-'))
}

fn valid_specialist_reason(accepted: bool, reason: &str) -> bool {
    if accepted {
        reason == "specialist_approved"
    } else {
        matches!(
            reason,
            "budget_exhausted"
                | "capability_unavailable"
                | "handler_rejected"
                | "policy_denied"
                | "request_cancelled"
                | "request_deadline_exceeded"
                | "request_limit_exceeded"
                | "unrequested_context"
        )
    }
}

fn handler_error_category(error: &PortError) -> &'static str {
    if error.safe_classification() == SafeErrorClassification::PermissionDenied {
        "policy_denied"
    } else {
        "handler_failed"
    }
}

fn required_object_string(
    object: &serde_json::Map<String, Value>,
    key: &str,
) -> Result<String, ProtocolError> {
    object
        .get(key)
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or(ProtocolError::InvalidRequest)
}

fn protocol_port_error(error: ProtocolError) -> PortError {
    let (classification, retryability) = match error {
        ProtocolError::ProviderUnavailable | ProtocolError::RateLimited => (
            SafeErrorClassification::Unavailable,
            Retryability::Retryable,
        ),
        ProtocolError::InternalAgentFailure | ProtocolError::Timeout => (
            SafeErrorClassification::Unavailable,
            Retryability::NonRetryable,
        ),
        ProtocolError::PolicyDenied | ProtocolError::ApprovalRequired => (
            SafeErrorClassification::PermissionDenied,
            Retryability::NonRetryable,
        ),
        ProtocolError::EmptyFrame
        | ProtocolError::FrameTooLarge { .. }
        | ProtocolError::MultipleFrames
        | ProtocolError::InvalidUtf8
        | ProtocolError::InvalidJson
        | ProtocolError::InvalidFrame
        | ProtocolError::Encode
        | ProtocolError::ProtocolIncompatible
        | ProtocolError::InvalidRequest
        | ProtocolError::IdentityBindingFailed
        | ProtocolError::ContextTooLarge
        | ProtocolError::OutputLimitExceeded
        | ProtocolError::Cancelled
        | ProtocolError::StaleFencingToken
        | ProtocolError::MalformedStructuredOutput => (
            SafeErrorClassification::InvalidInput,
            Retryability::NonRetryable,
        ),
    };
    PortError::failure(classification, retryability)
}

fn invalid_input() -> PortError {
    PortError::failure(
        SafeErrorClassification::InvalidInput,
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

fn conflict() -> PortError {
    PortError::failure(
        SafeErrorClassification::Conflict,
        Retryability::NonRetryable,
    )
}

fn internal_failure() -> PortError {
    PortError::failure(
        SafeErrorClassification::Internal,
        Retryability::NonRetryable,
    )
}
