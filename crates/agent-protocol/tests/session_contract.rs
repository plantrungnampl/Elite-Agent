use std::{collections::BTreeSet, time::Duration};

use chrono::{DateTime, TimeZone, Utc};
use local_agent_terminal_agent_protocol::{
    ConnectionBinding, InboundDisposition, NdjsonCodec, ProtocolCapabilities, ProtocolError,
    ProtocolFrame, ProtocolOffer, ProtocolSession, ProtocolTrustTier, RunCancel,
    RunExecutionBinding, RunStart, SessionLimits,
};
use serde_json::{json, Value};

#[test]
fn rejects_unoffered_protocol_versions_and_capability_escalation() {
    let mut version_mismatch = raw_session(capabilities());
    version_mismatch
        .outbound(initialize_request(&binding(), true), at(0))
        .expect("the offered initialize request must be accepted");

    assert!(matches!(
        version_mismatch.receive_response(
            initialize_response("core:initialize", "2.0", "agent-1", true),
            at(0),
        ),
        Err(ProtocolError::ProtocolIncompatible)
    ));

    let mut offered = capabilities();
    offered.streaming = false;
    let mut capability_mismatch = raw_session(offered);
    capability_mismatch
        .outbound(initialize_request(&binding(), false), at(0))
        .expect("the reduced initialize request must be accepted");

    assert!(matches!(
        capability_mismatch.receive_response(
            initialize_response("core:initialize", "1.0", "agent-1", true),
            at(0),
        ),
        Err(ProtocolError::ProtocolIncompatible)
    ));
}

#[test]
fn rejects_features_the_agent_did_not_select_during_handshake() {
    let mut session = raw_session(capabilities());
    session
        .outbound(initialize_request(&binding(), true), at(0))
        .expect("the initialization request is valid");
    session
        .receive_response(
            initialize_response("core:initialize", "1.0", "agent-1", false),
            at(0),
        )
        .expect("the agent may reduce offered capabilities");
    session
        .outbound(initialized("connection-1"), at(0))
        .expect("the reduced handshake completes");
    start_run(&mut session, "run-no-stream", 1, at(30));

    assert!(matches!(
        session.receive(stream_delta("run-no-stream", 1, "delta"), at(0)),
        Err(ProtocolError::InvalidRequest)
    ));
}

#[test]
fn rejects_launch_and_agent_binding_mismatches() {
    let mut session = raw_session(capabilities());
    let mut wrong_binding = serde_json::to_value(initialize_request(&binding(), true))
        .expect("the fixture frame must serialize");
    wrong_binding["params"]["launchBinding"]["manifestDigest"] =
        json!("sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc");

    assert!(matches!(
        session.outbound(decode(wrong_binding), at(0)),
        Err(ProtocolError::IdentityBindingFailed)
    ));

    session
        .outbound(initialize_request(&binding(), true), at(0))
        .expect("the bound initialize request must be accepted");
    assert!(matches!(
        session.receive_response(
            initialize_response("core:initialize", "1.0", "another-agent", true),
            at(0),
        ),
        Err(ProtocolError::IdentityBindingFailed)
    ));
}

#[test]
fn enforces_connection_unique_request_ids_and_response_provenance() {
    let mut session = raw_session(capabilities());
    let initialize = initialize_request(&binding(), true);
    session
        .outbound(initialize.clone(), at(0))
        .expect("the first request id is new");

    assert!(matches!(
        session.outbound(initialize, at(0)),
        Err(ProtocolError::InvalidRequest)
    ));
    assert!(matches!(
        session.receive_response(success_response("core:unknown", json!({})), at(0)),
        Err(ProtocolError::InvalidRequest)
    ));

    session
        .receive_response(
            initialize_response("core:initialize", "1.0", "agent-1", true),
            at(0),
        )
        .expect("the original request remains pending");
    session
        .outbound(initialized("connection-1"), at(0))
        .expect("initialization completes after its response");
    start_run(&mut session, "run-1", 1, at(30));
    session
        .receive(tool_request("run-1", "agent:tool-1"), at(0))
        .expect("the agent request creates a pending core response");

    assert!(matches!(
        session.receive_response(success_response("agent:tool-1", json!({})), at(0)),
        Err(ProtocolError::InvalidRequest)
    ));
}

#[test]
fn context_and_specialist_requests_receive_exactly_one_core_response() {
    let mut session = ready_session();
    start_run(&mut session, "run-1", 1, at(30));

    let context = context_query("run-1", "agent:context-1", "query-1", 1);
    assert!(matches!(
        session.receive(context, at(0)),
        Ok(InboundDisposition::Request(
            ProtocolFrame::ContextQueryRequest(_)
        ))
    ));
    let context_response = success_response(
        "agent:context-1",
        json!({
            "supplementId": "supplement-1",
            "contentDigest": "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
            "items": [],
            "provenance": [],
            "redactions": [],
            "policyDecisionIds": []
        }),
    );
    session
        .outbound(context_response.clone(), at(0))
        .expect("the core answers the pending context request once");
    assert!(matches!(
        session.outbound(context_response, at(0)),
        Err(ProtocolError::InvalidRequest)
    ));

    let specialist = specialist_request("run-1", "agent:specialist-1", &[]);
    assert!(matches!(
        session.receive(specialist, at(0)),
        Ok(InboundDisposition::Request(
            ProtocolFrame::SpecialistRequest(_)
        ))
    ));
    session
        .outbound(
            success_response(
                "agent:specialist-1",
                json!({
                    "requestId": "agent:specialist-1",
                    "accepted": false,
                    "reasonCode": "budget_exhausted"
                }),
            ),
            at(0),
        )
        .expect("the core answers the pending specialist request once");

    assert!(matches!(
        session.receive(
            context_query("run-1", "core:wrong-origin", "query-wrong-origin", 1),
            at(0),
        ),
        Err(ProtocolError::InvalidRequest)
    ));
    assert!(matches!(
        session.receive(specialist_request("run-1", "agent:context-1", &[]), at(0),),
        Err(ProtocolError::InvalidRequest)
    ));
}

#[test]
fn context_and_specialist_requests_are_rejected_after_run_terminal() {
    let mut session = ready_session();
    start_run(&mut session, "run-1", 1, at(30));
    session
        .receive(run_complete("run-1", "agent:complete-1", "done"), at(0))
        .expect("the first terminal request is accepted");

    assert!(matches!(
        session.receive(
            context_query("run-1", "agent:late-context", "query-late", 1),
            at(0),
        ),
        Err(ProtocolError::InvalidRequest)
    ));
    assert!(matches!(
        session.receive(
            specialist_request("run-1", "agent:late-specialist", &[]),
            at(0),
        ),
        Err(ProtocolError::InvalidRequest)
    ));
}

#[test]
fn enforces_method_ownership_and_never_responds_to_notifications() {
    let mut session = raw_session(capabilities());
    assert!(matches!(
        session.receive(run_start_request("run-1", "core:start-1", 1, at(30)), at(0)),
        Err(ProtocolError::InvalidRequest)
    ));
    assert!(matches!(
        session.outbound(stream_delta("run-1", 1, "delta"), at(0)),
        Err(ProtocolError::InvalidRequest)
    ));

    finish_initialization(&mut session);
    start_run(&mut session, "run-1", 1, at(30));
    session
        .receive(stream_delta("run-1", 1, "delta"), at(0))
        .expect("the notification is accepted without a response");

    assert!(matches!(
        session.outbound(success_response("agent:stream-1", json!({})), at(0)),
        Err(ProtocolError::InvalidRequest)
    ));
}

#[test]
fn rejects_foreign_runs_and_terminalizes_runs_after_stream_sequence_violations() {
    let mut session = ready_session();
    start_run(&mut session, "run-1", 1, at(30));

    assert!(matches!(
        session.receive(stream_delta("other-run", 1, "delta"), at(0)),
        Err(ProtocolError::InvalidRequest)
    ));
    assert!(matches!(
        session.receive(stream_delta("run-1", 2, "delta"), at(0)),
        Err(ProtocolError::InvalidRequest)
    ));
    assert!(matches!(
        session.receive(stream_delta("run-1", 1, "delta"), at(0)),
        Err(ProtocolError::InvalidRequest)
    ));
    assert!(matches!(
        session.receive(run_complete("run-1", "agent:bad-initial", "done"), at(0)),
        Err(ProtocolError::InvalidRequest)
    ));

    let mut duplicate_session = ready_session();
    start_run(&mut duplicate_session, "run-duplicate", 1, at(30));
    duplicate_session
        .receive(stream_delta("run-duplicate", 1, "delta"), at(0))
        .expect("the first stream delta starts at one");
    assert!(matches!(
        duplicate_session.receive(stream_delta("run-duplicate", 1, "delta"), at(0)),
        Ok(InboundDisposition::DuplicateStreamDelta)
    ));

    let mut conflicting_duplicate_session = ready_session();
    start_run(
        &mut conflicting_duplicate_session,
        "run-conflict",
        1,
        at(30),
    );
    conflicting_duplicate_session
        .receive(stream_delta("run-conflict", 1, "delta"), at(0))
        .expect("the first stream delta starts at one");
    assert!(matches!(
        conflicting_duplicate_session.receive(stream_delta("run-conflict", 1, "changed"), at(0)),
        Err(ProtocolError::InvalidRequest)
    ));
    assert!(matches!(
        conflicting_duplicate_session.receive(stream_delta("run-conflict", 2, "delta"), at(0)),
        Err(ProtocolError::InvalidRequest)
    ));
    assert!(matches!(
        conflicting_duplicate_session.receive(
            run_complete("run-conflict", "agent:conflict", "done"),
            at(0),
        ),
        Err(ProtocolError::InvalidRequest)
    ));

    let mut gap_session = ready_session();
    start_run(&mut gap_session, "run-2", 1, at(30));
    gap_session
        .receive(stream_delta("run-2", 1, "delta"), at(0))
        .expect("the first stream delta starts at one");
    assert!(matches!(
        gap_session.receive(stream_delta("run-2", 3, "delta"), at(0)),
        Err(ProtocolError::InvalidRequest)
    ));
    assert!(matches!(
        gap_session.receive(stream_delta("run-2", 2, "delta"), at(0)),
        Err(ProtocolError::InvalidRequest)
    ));
    assert!(matches!(
        gap_session.receive(run_complete("run-2", "agent:gap", "done"), at(0)),
        Err(ProtocolError::InvalidRequest)
    ));
}

#[test]
fn fails_runs_when_output_or_tool_limits_are_exceeded() {
    let mut output_session = ready_session_with_limits(3);
    start_run(&mut output_session, "run-output", 1, at(30));
    assert!(matches!(
        output_session.receive(stream_delta("run-output", 1, "four"), at(0)),
        Err(ProtocolError::OutputLimitExceeded)
    ));

    let mut tool_session = ready_session();
    start_run(&mut tool_session, "run-tools", 1, at(30));
    assert!(matches!(
        tool_session.receive(tool_request("run-tools", "agent:tool-1"), at(0)),
        Ok(InboundDisposition::Request(_))
    ));
    assert!(matches!(
        tool_session.receive(tool_request("run-tools", "agent:tool-2"), at(0)),
        Err(ProtocolError::OutputLimitExceeded)
    ));
}

#[test]
fn rejects_terminal_usage_that_exceeds_the_run_output_token_limit() {
    let mut session = ready_session();
    session
        .outbound(
            run_start_with_output_tokens("run-token-limit", "core:start-token-limit", 1, at(30)),
            at(0),
        )
        .expect("the run starts with a one-token output limit");
    session
        .receive_response(
            success_response(
                "core:start-token-limit",
                json!({ "accepted": true, "runId": "run-token-limit" }),
            ),
            at(0),
        )
        .expect("the run start response is accepted");

    assert!(matches!(
        session.receive(
            run_complete_with_output_tokens("run-token-limit", "agent:complete-token-limit", 2),
            at(0),
        ),
        Err(ProtocolError::OutputLimitExceeded)
    ));
}

#[test]
fn rejects_heartbeat_regressions_and_times_out_stalled_connections() {
    let mut session = ready_session();
    session
        .receive(heartbeat("connection-1", 1), at(0))
        .expect("the first heartbeat is valid");
    assert!(matches!(
        session.receive(heartbeat("connection-1", 1), at(1)),
        Err(ProtocolError::InvalidRequest)
    ));
    assert!(matches!(
        session.check_timeouts(at(6)),
        Err(ProtocolError::Timeout)
    ));
}

#[test]
fn rejects_terminal_frames_before_start_and_after_the_one_terminal_result() {
    let mut before_start = ready_session();
    assert!(matches!(
        before_start.receive(run_complete("run-1", "agent:complete-1", "first"), at(0)),
        Err(ProtocolError::InvalidRequest)
    ));

    let mut session = ready_session();
    start_run(&mut session, "run-1", 1, at(30));
    assert!(matches!(
        session.receive(run_complete("run-1", "agent:complete-1", "first"), at(0)),
        Ok(InboundDisposition::Request(_))
    ));
    assert!(matches!(
        session.receive(run_complete("run-1", "agent:complete-2", "first"), at(0)),
        Err(ProtocolError::InvalidRequest)
    ));
    assert!(matches!(
        session.receive(run_complete("run-1", "agent:complete-3", "changed"), at(0)),
        Err(ProtocolError::InvalidRequest)
    ));
    assert!(matches!(
        session.receive(stream_delta("run-1", 1, "late"), at(0)),
        Err(ProtocolError::InvalidRequest)
    ));
}

#[test]
fn applies_run_and_cancellation_deadlines_and_interrupts_connection_runs() {
    let mut deadline_session = ready_session();
    start_run(&mut deadline_session, "run-deadline", 1, at(2));
    assert!(matches!(
        deadline_session.check_timeouts(at(3)),
        Err(ProtocolError::Timeout)
    ));

    let mut cancellation_session = ready_session();
    start_run(&mut cancellation_session, "run-cancel", 1, at(30));
    cancellation_session
        .outbound(run_cancel_request("run-cancel", "core:cancel-1", 10), at(0))
        .expect("a cancellation request is valid for an active run");
    assert!(matches!(
        cancellation_session.check_timeouts(at_millis(11)),
        Err(ProtocolError::Timeout)
    ));

    let mut lost_session = ready_session();
    start_run(&mut lost_session, "run-lost", 1, at(30));
    assert_eq!(lost_session.connection_lost(), vec!["run-lost".to_owned()]);
    assert!(matches!(
        lost_session.receive(stream_delta("run-lost", 1, "late"), at(0)),
        Err(ProtocolError::InternalAgentFailure)
    ));
}

#[test]
fn connection_loss_only_interrupts_runs_accepted_by_the_agent() {
    let mut session = ready_session();
    session
        .outbound(
            run_start_request("run-rejected", "core:start-rejected", 1, at(30)),
            at(0),
        )
        .expect("the pending start request is valid");
    session
        .receive_response(error_response("core:start-rejected"), at(0))
        .expect("the rejection is the response to the pending start request");

    assert!(session.connection_lost().is_empty());
}

#[test]
fn opaque_run_requests_only_wrap_their_schema_method() {
    assert!(RunStart::new(
        run_start_request("run-1", "core:start-1", 1, at(30)),
        execution_binding(),
    )
    .is_ok());
    assert!(RunStart::new(stream_delta("run-1", 1, "delta"), execution_binding()).is_err());
    assert!(RunCancel::try_from(run_cancel_request("run-1", "core:cancel-1", 1)).is_ok());
    assert!(RunCancel::try_from(run_complete("run-1", "agent:complete-1", "done")).is_err());
}

fn execution_binding() -> RunExecutionBinding {
    RunExecutionBinding {
        provider_id: "provider-1".to_owned(),
        model_id: "model-1".to_owned(),
        generation_parameters: b"{}".to_vec(),
        generation_parameters_digest:
            "sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a".to_owned(),
        effective_context: b"context".to_vec(),
        effective_context_artifact_id: "artifact-context-1".to_owned(),
        effective_context_digest:
            "sha256:ea7792a26f405e2ae9c6f49ca93bbe6076ceac0a1fc53d83426c7d7f2d9377e4".to_owned(),
        supersedes_run_id: None,
    }
}

fn ready_session() -> ProtocolSession {
    ready_session_with_limits(10)
}

fn ready_session_with_limits(max_output_bytes: usize) -> ProtocolSession {
    let mut session = raw_session_with_limits(capabilities(), max_output_bytes);
    finish_initialization(&mut session);
    session
}

fn raw_session(capabilities: ProtocolCapabilities) -> ProtocolSession {
    raw_session_with_limits(capabilities, 10)
}

fn raw_session_with_limits(
    capabilities: ProtocolCapabilities,
    max_output_bytes: usize,
) -> ProtocolSession {
    ProtocolSession::new(
        binding(),
        ProtocolOffer {
            protocol_versions: strings(["1.0"]),
            capabilities,
        },
        SessionLimits {
            max_output_bytes,
            heartbeat_timeout: Duration::from_secs(5),
        },
        at(0),
    )
}

fn finish_initialization(session: &mut ProtocolSession) {
    session
        .outbound(initialize_request(&binding(), true), at(0))
        .expect("the initialization request must be valid");
    session
        .receive_response(
            initialize_response("core:initialize", "1.0", "agent-1", true),
            at(0),
        )
        .expect("the selected protocol and capabilities are offered");
    session
        .outbound(initialized("connection-1"), at(0))
        .expect("the initialized notification completes the handshake");
}

fn start_run(
    session: &mut ProtocolSession,
    run_id: &str,
    max_tool_requests: u64,
    deadline: DateTime<Utc>,
) {
    let request_id = format!("core:start-{run_id}");
    session
        .outbound(
            run_start_request(run_id, &request_id, max_tool_requests, deadline),
            at(0),
        )
        .expect("the run start request must be valid");
    session
        .receive_response(
            success_response(&request_id, json!({ "accepted": true, "runId": run_id })),
            at(0),
        )
        .expect("the agent accepts the run before it emits events");
}

fn binding() -> ConnectionBinding {
    ConnectionBinding {
        connection_id: "connection-1".to_owned(),
        agent_id: "agent-1".to_owned(),
        manifest_digest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            .to_owned(),
        executable_digest:
            "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_owned(),
        trust_tier: ProtocolTrustTier::CoreAdapter,
    }
}

fn capabilities() -> ProtocolCapabilities {
    ProtocolCapabilities {
        roles: strings(["critic"]),
        skills: strings(["testing"]),
        streaming: true,
        context_query: true,
        tool_requests: true,
        specialist_requests: true,
        max_concurrent_runs: 1,
        max_context_tokens: 1_024,
    }
}

fn initialize_request(binding: &ConnectionBinding, streaming: bool) -> ProtocolFrame {
    decode(json!({
        "jsonrpc": "2.0",
        "id": "core:initialize",
        "method": "initialize",
        "params": {
            "protocolVersions": ["1.0"],
            "client": { "name": "core", "version": "1" },
            "transport": { "type": "stdio-ndjson", "maxFrameBytes": 1024 },
            "features": features(streaming),
            "launchBinding": {
                "connectionId": binding.connection_id,
                "manifestDigest": binding.manifest_digest,
                "executableDigest": binding.executable_digest,
                "trustTier": "core_adapter"
            }
        }
    }))
}

fn initialize_response(
    id: &str,
    protocol_version: &str,
    agent_id: &str,
    streaming: bool,
) -> ProtocolFrame {
    success_response(
        id,
        json!({
            "protocolVersion": protocol_version,
            "agent": {
                "id": agent_id,
                "displayName": "Agent",
                "implementationVersion": "1"
            },
            "capabilities": {
                "roles": ["critic"],
                "skills": ["testing"],
                "streaming": streaming,
                "contextQuery": true,
                "toolRequests": true,
                "specialistRequests": true,
                "maxConcurrentRuns": 1,
                "maxContextTokens": 1024
            }
        }),
    )
}

fn initialized(connection_id: &str) -> ProtocolFrame {
    decode(json!({
        "jsonrpc": "2.0",
        "method": "initialized",
        "params": {
            "connectionId": connection_id,
            "effectiveCapabilitiesDigest": "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
        }
    }))
}

fn run_start_request(
    run_id: &str,
    id: &str,
    max_tool_requests: u64,
    deadline: DateTime<Utc>,
) -> ProtocolFrame {
    decode(json!({
        "jsonrpc": "2.0",
        "id": id,
        "method": "agent.run.start",
        "params": {
            "runId": run_id,
            "idempotencyKey": format!("key-{run_id}"),
            "taskId": "task-1",
            "role": "critic",
            "objective": "Review the implementation",
            "contextPackage": {
                "packageId": "context-1",
                "contentDigest": "sha256:ea7792a26f405e2ae9c6f49ca93bbe6076ceac0a1fc53d83426c7d7f2d9377e4",
                "manifestRef": "artifact:context-1"
            },
            "permissions": {
                "contextQuery": true,
                "toolRequest": true,
                "writeFiles": false
            },
            "responseSchema": "agent-message.v1",
            "limits": {
                "deadline": deadline.to_rfc3339(),
                "maxOutputTokens": 100,
                "maxToolRequests": max_tool_requests
            }
        }
    }))
}

fn run_start_with_output_tokens(
    run_id: &str,
    id: &str,
    max_output_tokens: u64,
    deadline: DateTime<Utc>,
) -> ProtocolFrame {
    let mut value = serde_json::to_value(run_start_request(run_id, id, 1, deadline))
        .expect("the fixture frame must serialize");
    value["params"]["limits"]["maxOutputTokens"] = json!(max_output_tokens);
    decode(value)
}

fn run_cancel_request(run_id: &str, id: &str, deadline_ms: u64) -> ProtocolFrame {
    decode(json!({
        "jsonrpc": "2.0",
        "id": id,
        "method": "agent.run.cancel",
        "params": { "runId": run_id, "reason": "user_cancelled", "deadlineMs": deadline_ms }
    }))
}

fn stream_delta(run_id: &str, sequence: u64, delta: &str) -> ProtocolFrame {
    decode(json!({
        "jsonrpc": "2.0",
        "method": "agent.stream.delta",
        "params": { "runId": run_id, "sequence": sequence, "channel": "content", "delta": delta }
    }))
}

fn tool_request(run_id: &str, id: &str) -> ProtocolFrame {
    decode(json!({
        "jsonrpc": "2.0",
        "id": id,
        "method": "tool.request",
        "params": {
            "runId": run_id,
            "requestId": format!("request-{id}"),
            "tool": "git.diff",
            "arguments": {},
            "reason": "Inspect the change"
        }
    }))
}

fn context_query(run_id: &str, id: &str, query_id: &str, max_tokens: u64) -> ProtocolFrame {
    decode(json!({
        "jsonrpc": "2.0",
        "id": id,
        "method": "context.query",
        "params": {
            "runId": run_id,
            "queryId": query_id,
            "query": "More context",
            "scopes": ["repository"],
            "maxItems": 1,
            "maxTokens": max_tokens
        }
    }))
}

fn specialist_request(run_id: &str, id: &str, required_context: &[&str]) -> ProtocolFrame {
    decode(json!({
        "jsonrpc": "2.0",
        "id": id,
        "method": "specialist.request",
        "params": {
            "runId": run_id,
            "capability": "review",
            "reason": "Need review",
            "requiredContext": required_context
        }
    }))
}

fn heartbeat(connection_id: &str, sequence: u64) -> ProtocolFrame {
    decode(json!({
        "jsonrpc": "2.0",
        "method": "agent.heartbeat",
        "params": { "connectionId": connection_id, "sequence": sequence }
    }))
}

fn run_complete(run_id: &str, id: &str, content: &str) -> ProtocolFrame {
    decode(json!({
        "jsonrpc": "2.0",
        "id": id,
        "method": "agent.run.complete",
        "params": {
            "runId": run_id,
            "status": "succeeded",
            "message": {
                "messageId": format!("message-{id}"),
                "type": "answer",
                "content": content,
                "claims": []
            }
        }
    }))
}

fn run_complete_with_output_tokens(run_id: &str, id: &str, output_tokens: u64) -> ProtocolFrame {
    let mut value = serde_json::to_value(run_complete(run_id, id, "done"))
        .expect("the fixture frame must serialize");
    value["params"]["usage"] = json!({
        "inputTokens": 0,
        "outputTokens": output_tokens,
        "providerReportedCost": 0.0
    });
    decode(value)
}

fn success_response(id: &str, result: Value) -> ProtocolFrame {
    decode(json!({ "jsonrpc": "2.0", "id": id, "result": result }))
}

fn error_response(id: &str) -> ProtocolFrame {
    decode(json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": { "code": -32000, "message": "rejected" }
    }))
}

fn features(streaming: bool) -> Vec<&'static str> {
    let mut features = vec!["context-query", "tool-request", "specialist-request"];
    if streaming {
        features.push("streaming");
    }
    features
}

fn decode(frame: Value) -> ProtocolFrame {
    NdjsonCodec::default()
        .decode(&serde_json::to_vec(&frame).expect("fixture must serialize"))
        .expect("fixture must match the immutable schema")
}

fn strings<const N: usize>(values: [&str; N]) -> BTreeSet<String> {
    values.into_iter().map(str::to_owned).collect()
}

fn at(seconds: i64) -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 7, 23, 13, 20, 0)
        .single()
        .expect("fixed timestamp is valid")
        + chrono::Duration::seconds(seconds)
}

fn at_millis(milliseconds: i64) -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 7, 23, 13, 20, 0)
        .single()
        .expect("fixed timestamp is valid")
        + chrono::Duration::milliseconds(milliseconds)
}
