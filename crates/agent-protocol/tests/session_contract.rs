use std::{collections::BTreeSet, time::Duration};

use chrono::{DateTime, TimeZone, Utc};
use local_agent_terminal_agent_protocol::{
    ConnectionBinding, InboundDisposition, NdjsonCodec, ProtocolCapabilities, ProtocolError,
    ProtocolFrame, ProtocolOffer, ProtocolSession, ProtocolTrustTier, SessionLimits,
};
use serde_json::{json, Value};

const BINDING_DIGEST: &str =
    "sha256:0000000000000000000000000000000000000000000000000000000000000000";
const CONTEXT_DIGEST: &str =
    "sha256:ea7792a26f405e2ae9c6f49ca93bbe6076ceac0a1fc53d83426c7d7f2d9377e4";

#[test]
fn initializes_and_starts_a_v2_run_with_only_contract_fields() {
    let mut session = raw_session();

    finish_initialization(&mut session);
    session
        .outbound(run_start("run-1", "core:start-1"), at(0))
        .expect("the v2 run start is accepted after initialization");
    session
        .receive_response(
            response(
                "core:start-1",
                json!({ "runId": "run-1", "accepted": true }),
            ),
            at(0),
        )
        .expect("the method-specific start response is accepted");
}

#[test]
fn initialize_response_cannot_expand_policy_selected_capabilities() {
    let mut session = raw_session();
    let mut request = initialize();
    request["params"]["capabilities"] = json!(["agent.stream.delta"]);
    session.outbound(decode(request), at(0)).unwrap();

    assert!(matches!(
        session.receive_response(
            response(
                "core:initialize",
                json!({
                    "protocolVersion": "2.0",
                    "capabilities": ["agent.stream.delta", "context.query"],
                    "connectionId": "connection-1",
                    "limits": {
                        "maxFrameBytes": 8388608,
                        "maxPendingRequests": 128,
                        "streamHighWatermark": 512,
                        "streamLowWatermark": 256
                    }
                }),
            ),
            at(0),
        ),
        Err(ProtocolError::ProtocolIncompatible)
    ));
}

#[test]
fn rejects_v1_fields_and_unknown_closed_shapes() {
    let mut v1 = initialize();
    v1["params"]["features"] = json!(["streaming"]);
    assert!(matches!(
        decode_result(v1),
        Err(ProtocolError::InvalidFrame)
    ));

    let mut start = start_value("run-1", "core:start-1");
    start["params"]["runConfigurationRef"] = json!("run-config-1");
    assert!(matches!(
        decode_result(start),
        Err(ProtocolError::InvalidFrame)
    ));

    let mut notification = stream_value("run-1", 1, "delta");
    notification["id"] = json!("agent:illegal-notification-response");
    assert!(matches!(
        decode_result(notification),
        Err(ProtocolError::InvalidFrame)
    ));
}

#[test]
fn validates_responses_against_the_durable_pending_method() {
    let mut session = ready_session();
    start_run(&mut session, "run-1");
    let request = context_query("run-1", "agent:context-1", "query-1", "query");
    assert!(matches!(
        session.receive(request, at(0)),
        Ok(InboundDisposition::Request(_))
    ));

    assert!(matches!(
        session.outbound(
            response(
                "agent:context-1",
                json!({
                    "requestId": "tool-1",
                    "decision": "allowed",
                    "operationIntentId": "intent-1",
                    "status": "succeeded"
                })
            ),
            at(0),
        ),
        Err(ProtocolError::InvalidFrame)
    ));

    session
        .outbound(
            response(
                "agent:context-1",
                json!({
                    "queryId": "query-1",
                    "items": [{
                        "itemId": "item-1",
                        "contentRef": "artifact-context-1",
                        "contentDigest": CONTEXT_DIGEST,
                        "sourceRefs": ["artifact-context-1"],
                        "observationClass": "core_observed"
                    }],
                    "truncated": false,
                    "effectivePayloadDigest": CONTEXT_DIGEST,
                    "redactionReportDigest": BINDING_DIGEST
                }),
            ),
            at(0),
        )
        .expect("the context-query response matches its durable pending method");
}

#[test]
fn restores_pending_run_start_for_method_specific_response() {
    let mut session = ready_session();
    session
        .restore_pending_request(run_start("run-restore", "core:restore-start"), at(0))
        .expect("the durable run-start request is restored without dispatch");

    session
        .receive_response(
            response(
                "core:restore-start",
                json!({ "runId": "run-restore", "accepted": true }),
            ),
            at(0),
        )
        .expect("the restored run-start accepts its method-specific response");
}

#[test]
fn restored_run_start_rejects_context_query_response_for_same_id() {
    let mut session = ready_session();
    session
        .restore_pending_request(run_start("run-restore", "core:restore-start"), at(0))
        .expect("the durable run-start request is restored");

    assert!(matches!(
        session.receive_response(
            response(
                "core:restore-start",
                json!({
                    "queryId": "query-1",
                    "items": [{
                        "itemId": "item-1",
                        "contentRef": "artifact-context-1",
                        "contentDigest": CONTEXT_DIGEST,
                        "sourceRefs": ["artifact-context-1"],
                        "observationClass": "core_observed"
                    }],
                    "truncated": false,
                    "effectivePayloadDigest": CONTEXT_DIGEST,
                    "redactionReportDigest": BINDING_DIGEST
                }),
            ),
            at(0),
        ),
        Err(ProtocolError::InvalidFrame)
    ));
}

#[test]
fn restoring_exact_pending_run_start_is_idempotent() {
    let mut session = ready_session();
    let request = run_start("run-restore", "core:restore-start");
    session
        .restore_pending_request(request.clone(), at(0))
        .expect("the first durable run-start restore succeeds");
    session
        .restore_pending_request(request, at(1))
        .expect("restoring the exact pending tuple is idempotent");

    session
        .receive_response(
            response(
                "core:restore-start",
                json!({ "runId": "run-restore", "accepted": true }),
            ),
            at(1),
        )
        .expect("the idempotent restore leaves one usable pending response");
}

#[test]
fn restoring_changed_pending_run_start_digest_conflicts() {
    let mut session = ready_session();
    session
        .restore_pending_request(run_start("run-restore", "core:restore-start"), at(0))
        .expect("the original durable run-start request is restored");

    let mut changed = start_value("run-restore", "core:restore-start");
    changed["params"]["taskId"] = json!("task-2");
    assert!(matches!(
        session.restore_pending_request(decode(changed), at(0)),
        Err(ProtocolError::ProtocolConflict)
    ));
}

#[test]
fn enforces_core_and_agent_prefixes_and_keeps_notifications_response_free() {
    let mut session = ready_session();
    let mut wrong_start_origin = start_value("run-1", "core:start-1");
    wrong_start_origin["id"] = json!("agent:start-1");
    assert!(matches!(
        decode_result(wrong_start_origin),
        Err(ProtocolError::InvalidFrame)
    ));
    start_run(&mut session, "run-1");

    assert!(matches!(
        decode_result(json!({
            "jsonrpc": "2.0",
            "id": "core:context-1",
            "method": "context.query",
            "params": {
                "runId": "run-1",
                "queryId": "query-1",
                "query": "query",
                "scopes": ["repository"],
                "maxItems": 1,
                "maxTokens": 1
            }
        })),
        Err(ProtocolError::InvalidFrame)
    ));
    assert!(matches!(
        session.receive(stream_delta("run-1", 1, "delta"), at(0)),
        Ok(InboundDisposition::Notification(_))
    ));
    assert!(matches!(
        session.outbound(
            response(
                "agent:stream-1",
                json!({
                    "runId": "run-1",
                    "recorded": true,
                    "terminalStatus": "succeeded"
                }),
            ),
            at(0)
        ),
        Err(ProtocolError::InvalidRequest)
    ));
}

#[test]
fn correlates_replays_by_request_id_method_and_digest() {
    let mut session = ready_session();
    start_run(&mut session, "run-1");
    let request = context_query("run-1", "agent:context-1", "query-1", "query");

    assert!(matches!(
        session.receive(request.clone(), at(0)),
        Ok(InboundDisposition::Request(_))
    ));
    assert!(matches!(
        session.receive(request, at(0)),
        Ok(InboundDisposition::ReplayRequest(_))
    ));
    assert!(matches!(
        session.receive(
            context_query("run-1", "agent:context-1", "query-1", "changed query"),
            at(0),
        ),
        Err(ProtocolError::ProtocolConflict)
    ));
}

#[test]
fn permits_exactly_one_terminal_request_per_run() {
    let mut session = ready_session();
    start_run(&mut session, "run-1");
    let terminal = run_complete("run-1", "agent:complete-1", "succeeded");

    assert!(matches!(
        session.receive(terminal.clone(), at(0)),
        Ok(InboundDisposition::Request(_))
    ));
    session
        .outbound(
            response(
                "agent:complete-1",
                json!({
                    "runId": "run-1",
                    "recorded": true,
                    "terminalStatus": "succeeded"
                }),
            ),
            at(0),
        )
        .expect("the terminal acknowledgement matches the pending complete method");

    assert!(matches!(
        session.receive(terminal, at(0)),
        Ok(InboundDisposition::ReplayRequest(_))
    ));

    assert!(matches!(
        session.receive(
            run_complete("run-1", "agent:complete-2", "succeeded"),
            at(0)
        ),
        Err(ProtocolError::InvalidRequest)
    ));
    assert!(matches!(
        session.receive(stream_delta("run-1", 1, "late"), at(0)),
        Err(ProtocolError::InvalidRequest)
    ));
}

#[test]
fn rejected_post_terminal_requests_do_not_consume_pending_capacity() {
    let mut session = ready_session();
    start_run(&mut session, "run-1");
    let terminal = run_complete("run-1", "agent:complete-1", "succeeded");
    session
        .receive(terminal, at(0))
        .expect("the first terminal request is accepted");
    session
        .outbound(
            response(
                "agent:complete-1",
                json!({
                    "runId": "run-1",
                    "recorded": true,
                    "terminalStatus": "succeeded"
                }),
            ),
            at(0),
        )
        .expect("the terminal acknowledgement completes its pending request");

    for index in 0..128 {
        assert!(matches!(
            session.receive(
                context_query(
                    "run-1",
                    &format!("agent:late-{index}"),
                    &format!("late-{index}"),
                    "query",
                ),
                at(0),
            ),
            Err(ProtocolError::InvalidRequest)
        ));
    }

    start_run(&mut session, "run-2");
    assert!(matches!(
        session.receive(
            context_query("run-2", "agent:live", "live-query", "query"),
            at(0),
        ),
        Ok(InboundDisposition::Request(_))
    ));
}

#[test]
fn rejects_stream_sequence_gaps_and_terminalizes_that_run() {
    let mut session = ready_session();
    start_run(&mut session, "run-1");
    session
        .receive(stream_delta("run-1", 1, "first"), at(0))
        .expect("the first stream sequence is one");

    assert!(matches!(
        session.receive(stream_delta("run-1", 3, "gap"), at(0)),
        Err(ProtocolError::InvalidRequest)
    ));
    assert!(matches!(
        session.receive(stream_delta("run-1", 2, "late"), at(0)),
        Err(ProtocolError::InvalidRequest)
    ));
}

#[test]
fn restores_durable_per_channel_stream_heads_before_receiving_the_next_delta() {
    let mut session = ready_session();
    start_run(&mut session, "run-1");
    session
        .restore_stream_head("run-1", "content", 2)
        .expect("the persisted content head is restored after run acceptance");

    assert!(matches!(
        session.receive(stream_delta("run-1", 3, "third"), at(0)),
        Ok(InboundDisposition::Notification(_))
    ));
    assert!(matches!(
        session.receive(
            stream_delta_with_channel("run-1", 1, "status", "running"),
            at(0)
        ),
        Ok(InboundDisposition::Notification(_))
    ));
    assert!(matches!(
        session.receive(stream_delta("run-1", 2, "unknown prior delta"), at(0)),
        Err(ProtocolError::InvalidRequest)
    ));
}

#[test]
fn enforces_pending_limit_and_stream_high_low_watermarks() {
    let mut pending_session = ready_session();
    start_run(&mut pending_session, "pending-run");
    for index in 0..128 {
        pending_session
            .receive(
                context_query(
                    "pending-run",
                    &format!("agent:context-{index}"),
                    &format!("query-{index}"),
                    "query",
                ),
                at(0),
            )
            .expect("each pending request below the negotiated limit is accepted");
    }
    assert!(matches!(
        pending_session.receive(
            context_query(
                "pending-run",
                "agent:context-overflow",
                "query-overflow",
                "query"
            ),
            at(0),
        ),
        Err(ProtocolError::PendingLimitExceeded)
    ));

    let mut stream_session = ready_session();
    start_run(&mut stream_session, "stream-run");
    for sequence in 1..=512 {
        stream_session
            .receive(stream_delta("stream-run", sequence, "x"), at(0))
            .expect("contiguous stream deltas remain valid");
    }
    assert!(stream_session
        .stream_backpressured("stream-run")
        .expect("active run exists"));
    assert!(!stream_session
        .acknowledge_stream("stream-run", 256)
        .expect("acknowledging to the low watermark releases backpressure"));
}

fn raw_session() -> ProtocolSession {
    ProtocolSession::new_with_binding_digest(
        binding(),
        BINDING_DIGEST.to_owned(),
        ProtocolOffer {
            protocol_versions: strings(["2.0"]),
            capabilities: capabilities(),
        },
        SessionLimits {
            max_output_bytes: 1_000_000,
            heartbeat_timeout: Duration::from_secs(30),
        },
        at(0),
    )
}

fn ready_session() -> ProtocolSession {
    let mut session = raw_session();
    finish_initialization(&mut session);
    session
}

fn finish_initialization(session: &mut ProtocolSession) {
    session
        .outbound(decode(initialize()), at(0))
        .expect("the v2 initialize request is valid");
    session
        .receive_response(
            response(
                "core:initialize",
                json!({
                    "protocolVersion": "2.0",
                    "capabilities": [
                        "agent.stream.delta",
                        "context.query",
                        "tool.request",
                        "specialist.request"
                    ],
                    "connectionId": "connection-1",
                    "limits": {
                        "maxFrameBytes": 8388608,
                        "maxPendingRequests": 128,
                        "streamHighWatermark": 512,
                        "streamLowWatermark": 256
                    }
                }),
            ),
            at(0),
        )
        .expect("the selected v2 capabilities are offered");
    session
        .outbound(
            decode(json!({
                "jsonrpc": "2.0",
                "method": "initialized",
                "params": { "connectionId": "connection-1" }
            })),
            at(0),
        )
        .expect("the initialized notification completes the handshake");
}

fn start_run(session: &mut ProtocolSession, run_id: &str) {
    let id = format!("core:start-{run_id}");
    session
        .outbound(run_start(run_id, &id), at(0))
        .expect("the start request is valid");
    session
        .receive_response(
            response(&id, json!({ "runId": run_id, "accepted": true })),
            at(0),
        )
        .expect("the run start response is valid");
}

fn binding() -> ConnectionBinding {
    ConnectionBinding {
        connection_id: "connection-1".to_owned(),
        agent_id: "agent-1".to_owned(),
        manifest_digest: BINDING_DIGEST.to_owned(),
        executable_digest: CONTEXT_DIGEST.to_owned(),
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

fn initialize() -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": "core:initialize",
        "method": "initialize",
        "params": {
            "protocolVersions": ["2.0"],
            "capabilities": [
                "agent.stream.delta",
                "context.query",
                "tool.request",
                "specialist.request"
            ],
            "connectionBindingDigest": BINDING_DIGEST
        }
    })
}

fn run_start(run_id: &str, id: &str) -> ProtocolFrame {
    decode(start_value(run_id, id))
}

fn start_value(run_id: &str, id: &str) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "method": "agent.run.start",
        "params": {
            "runId": run_id,
            "taskId": "task-1",
            "contextPackageRef": "artifact-context-1",
            "idempotencyKey": format!("key-{run_id}"),
            "role": "critic"
        }
    })
}

fn context_query(run_id: &str, id: &str, query_id: &str, query: &str) -> ProtocolFrame {
    decode(json!({
        "jsonrpc": "2.0",
        "id": id,
        "method": "context.query",
        "params": {
            "runId": run_id,
            "queryId": query_id,
            "query": query,
            "scopes": ["repository"],
            "maxItems": 1,
            "maxTokens": 1
        }
    }))
}

fn stream_delta(run_id: &str, sequence: u64, delta: &str) -> ProtocolFrame {
    decode(stream_value(run_id, sequence, delta))
}

fn stream_value(run_id: &str, sequence: u64, delta: &str) -> Value {
    stream_value_with_channel(run_id, sequence, "content", delta)
}

fn stream_delta_with_channel(
    run_id: &str,
    sequence: u64,
    channel: &str,
    delta: &str,
) -> ProtocolFrame {
    decode(stream_value_with_channel(run_id, sequence, channel, delta))
}

fn stream_value_with_channel(run_id: &str, sequence: u64, channel: &str, delta: &str) -> Value {
    json!({
        "jsonrpc": "2.0",
        "method": "agent.stream.delta",
        "params": { "runId": run_id, "sequence": sequence, "channel": channel, "delta": delta }
    })
}

fn run_complete(run_id: &str, id: &str, status: &str) -> ProtocolFrame {
    decode(json!({
        "jsonrpc": "2.0",
        "id": id,
        "method": "agent.run.complete",
        "params": {
            "runId": run_id,
            "status": status,
            "message": {
                "messageId": format!("message-{id}"),
                "type": "answer",
                "content": "done",
                "claims": []
            }
        }
    }))
}

fn response(id: &str, result: Value) -> ProtocolFrame {
    decode(json!({ "jsonrpc": "2.0", "id": id, "result": result }))
}

fn decode(value: Value) -> ProtocolFrame {
    decode_result(value).expect("fixture matches the immutable v2 schema")
}

fn decode_result(value: Value) -> Result<ProtocolFrame, ProtocolError> {
    NdjsonCodec::default().decode(&serde_json::to_vec(&value).expect("fixture serializes"))
}

fn strings<const N: usize>(values: [&str; N]) -> BTreeSet<String> {
    values.into_iter().map(str::to_owned).collect()
}

fn at(seconds: i64) -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 8, 14, 0, 0, 0)
        .single()
        .expect("fixed timestamp is valid")
        + chrono::Duration::seconds(seconds)
}
