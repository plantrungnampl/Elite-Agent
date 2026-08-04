use std::fs;
use std::path::{Path, PathBuf};

use local_agent_terminal_agent_protocol::{
    NdjsonCodec, ProtocolError, ProtocolFrame, DEFAULT_MAX_FRAME_BYTES,
};
use serde_json::{json, Map, Value};

#[test]
fn decodes_one_utf8_json_object_line() {
    let codec = NdjsonCodec::default();
    let mut line = shutdown_request();
    line.push(b'\n');

    assert!(codec.decode(&line).is_ok());
}

#[test]
fn rejects_invalid_frame_shapes_and_ids() {
    let codec = NdjsonCodec::default();
    let overlong_id = format!(
        "{{\"jsonrpc\":\"2.0\",\"id\":\"core:{}\",\"method\":\"shutdown\",\"params\":{{}}}}",
        "a".repeat(124),
    );

    for input in [
        b"{\"jsonrpc\":\"2.0\",\"method\":\"shutdown\",\"params\":{}}".as_slice(),
        b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"shutdown\",\"params\":{}}".as_slice(),
        b"{\"jsonrpc\":\"2.0\",\"id\":\"user:1\",\"method\":\"shutdown\",\"params\":{}}".as_slice(),
        b"{\"jsonrpc\":\"2.0\",\"id\":\"core:1\",\"method\":\"unknown.method\",\"params\":{}}".as_slice(),
        b"{\"jsonrpc\":\"2.0\",\"id\":\"core:1\",\"method\":\"initialize\",\"params\":{}}".as_slice(),
        b"{\"jsonrpc\":\"2.0\",\"id\":\"core:1\",\"method\":\"shutdown\",\"params\":{},\"unknown\":true}".as_slice(),
        overlong_id.as_bytes(),
    ] {
        assert!(codec.decode(input).is_err(), "invalid frame must be rejected");
    }
}

#[test]
fn rejects_malformed_utf8_json_and_line_boundaries() {
    let codec = NdjsonCodec::default();
    let mut multiple = shutdown_request();
    multiple.push(b'\n');
    multiple.extend(shutdown_request());

    for input in [
        b"".as_slice(),
        b"\n".as_slice(),
        b"{".as_slice(),
        b"\xff".as_slice(),
        b"{\"jsonrpc\":\"2.0\",\"id\":\"core:shutdown\",\n\"method\":\"shutdown\",\"params\":{}}"
            .as_slice(),
        b"{\"jsonrpc\":\"2.0\",\"id\":\"core:shutdown\",\r\"method\":\"shutdown\",\"params\":{}}"
            .as_slice(),
        multiple.as_slice(),
    ] {
        assert!(
            codec.decode(input).is_err(),
            "invalid NDJSON input must be rejected"
        );
    }
}

#[test]
fn enforces_configured_limits_before_deserialization() {
    let limit = 512;
    let codec = NdjsonCodec::new(limit);
    let exact = tool_request_with_length(limit);
    let over = tool_request_with_length(limit + 1);

    assert_eq!(exact.len(), limit);
    assert!(codec.decode(&exact).is_ok());
    assert!(matches!(
        codec.decode(&over),
        Err(ProtocolError::FrameTooLarge { max_frame_bytes }) if max_frame_bytes == limit
    ));
}

#[test]
fn encoding_respects_the_configured_limit() {
    let frame = NdjsonCodec::default()
        .decode(&tool_request_with_length(512))
        .expect("bounded fixture frame must decode");

    let exact = NdjsonCodec::new(512)
        .encode(&frame)
        .expect("exact body limit must encode");
    assert_eq!(exact.len(), 513);
    assert!(matches!(
        NdjsonCodec::new(511).encode(&frame),
        Err(ProtocolError::FrameTooLarge {
            max_frame_bytes: 511
        })
    ));
}

#[test]
fn consumes_hostile_ndjson_fixtures() {
    let codec = NdjsonCodec::default();
    let duplicate = fs::read(fixture_path("duplicate-request-id.ndjson"))
        .expect("duplicate request fixture must be readable");
    let oversize =
        fs::read(fixture_path("oversize-frame.ndjson")).expect("oversize fixture must be readable");

    assert!(matches!(
        codec.decode(&duplicate),
        Err(ProtocolError::MultipleFrames)
    ));
    assert!(oversize.len() > DEFAULT_MAX_FRAME_BYTES);
    assert!(matches!(
        codec.decode(&oversize),
        Err(ProtocolError::FrameTooLarge {
            max_frame_bytes: DEFAULT_MAX_FRAME_BYTES
        })
    ));
}

#[test]
fn encoding_is_one_lf_terminated_utf8_object() {
    let codec = NdjsonCodec::default();
    let frame = codec
        .decode(&shutdown_request())
        .expect("shutdown request must decode");
    let encoded = codec.encode(&frame).expect("frame must encode");

    let text = std::str::from_utf8(&encoded).expect("encoded frame must be UTF-8");
    assert!(text.ends_with('\n'));
    assert_eq!(encoded.iter().filter(|&&byte| byte == b'\n').count(), 1);
    assert!(codec.decode(&encoded).is_ok());
}

#[test]
fn errors_never_include_frame_content() {
    let codec = NdjsonCodec::default();
    let canary = "protocol-error-canary";
    let input = format!(
        "{{\"jsonrpc\":\"2.0\",\"id\":\"core:1\",\"method\":\"shutdown\",\"params\":{{}},\"secret\":\"{canary}\"}}"
    );
    let error = codec
        .decode(input.as_bytes())
        .expect_err("unknown field must fail");

    assert!(!error.to_string().contains(canary));
    assert!(!format!("{error:?}").contains(canary));
}

#[test]
fn rejects_array_cardinality_uniqueness_and_property_constraints() {
    let codec = NdjsonCodec::default();
    let mut duplicate_protocol_versions = initialize_request();
    duplicate_protocol_versions["params"]["protocolVersions"] = json!(["1.0", "1.0"]);
    let mut duplicate_features = initialize_request();
    duplicate_features["params"]["features"] = json!(["streaming", "streaming"]);
    let mut duplicate_scopes = context_query_request();
    duplicate_scopes["params"]["scopes"] = json!(["task", "task"]);

    for (name, frame) in [
        (
            "empty protocol versions",
            with_value(
                initialize_request(),
                &["params", "protocolVersions"],
                json!([]),
            ),
        ),
        ("duplicate protocol versions", duplicate_protocol_versions),
        ("duplicate features", duplicate_features),
        (
            "empty context scopes",
            with_value(context_query_request(), &["params", "scopes"], json!([])),
        ),
        ("duplicate context scopes", duplicate_scopes),
        ("too many claims", run_complete_request(claims(1025))),
        (
            "too many evidence references",
            run_complete_request(vec![claim(evidence_references(129))]),
        ),
        (
            "too many required context entries",
            with_value(
                specialist_request(),
                &["params", "requiredContext"],
                strings(129),
            ),
        ),
        (
            "too many tool argument properties",
            with_value(
                tool_request(),
                &["params", "arguments"],
                object_with_properties(257),
            ),
        ),
        (
            "too many error data properties",
            with_value(
                error_response(),
                &["error", "data"],
                object_with_properties(257),
            ),
        ),
        (
            "shutdown params must stay empty",
            with_value(
                shutdown_request_value(),
                &["params"],
                json!({ "extra": true }),
            ),
        ),
        (
            "exit params must stay empty",
            with_value(exit_notification(), &["params"], json!({ "extra": true })),
        ),
    ] {
        assert_rejected(&codec, frame, name);
    }
}

#[test]
fn enforces_every_numeric_schema_boundary() {
    let codec = NdjsonCodec::default();
    let schema = normative_schema();

    for (name, frame, path) in [
        (
            "transport max frame bytes",
            initialize_with_max_frame_bytes as fn(i64) -> Value,
            "/$defs/initializeRequest/allOf/1/properties/params/properties/transport/properties/maxFrameBytes",
        ),
        (
            "run output tokens",
            run_start_with_output_tokens,
            "/$defs/runStartRequest/allOf/1/properties/params/properties/limits/properties/maxOutputTokens",
        ),
        (
            "run tool requests",
            run_start_with_tool_requests,
            "/$defs/runStartRequest/allOf/1/properties/params/properties/limits/properties/maxToolRequests",
        ),
        (
            "cancel deadline",
            run_cancel_with_deadline,
            "/$defs/runCancelRequest/allOf/1/properties/params/properties/deadlineMs",
        ),
        (
            "evidence start line",
            run_complete_with_start_line,
            "/$defs/evidenceRef/properties/startLine",
        ),
        (
            "evidence end line",
            run_complete_with_end_line,
            "/$defs/evidenceRef/properties/endLine",
        ),
        (
            "input token usage",
            run_complete_with_input_tokens,
            "/$defs/runCompleteRequest/allOf/1/properties/params/properties/usage/properties/inputTokens",
        ),
        (
            "output token usage",
            run_complete_with_output_tokens,
            "/$defs/runCompleteRequest/allOf/1/properties/params/properties/usage/properties/outputTokens",
        ),
        (
            "stream sequence",
            stream_delta_with_sequence,
            "/$defs/streamDeltaNotification/allOf/1/properties/params/properties/sequence",
        ),
        (
            "context max items",
            context_query_with_max_items,
            "/$defs/contextQueryRequest/allOf/1/properties/params/properties/maxItems",
        ),
        (
            "context max tokens",
            context_query_with_max_tokens,
            "/$defs/contextQueryRequest/allOf/1/properties/params/properties/maxTokens",
        ),
        (
            "fencing token",
            tool_request_with_fence,
            "/$defs/toolRequest/allOf/1/properties/params/properties/executorFencingToken",
        ),
        (
            "heartbeat sequence",
            heartbeat_with_sequence,
            "/$defs/heartbeatNotification/allOf/1/properties/params/properties/sequence",
        ),
    ] {
        let (min, max) = schema_integer_bounds(&schema, path);
        assert_integer_boundaries(&codec, name, frame, min, max);
    }

    let (min, max) = schema_number_bounds(&schema, "/$defs/claim/properties/confidence");
    assert_number_boundaries(
        &codec,
        "claim confidence",
        run_complete_with_confidence,
        min,
        max,
    );
    let (min, max) = schema_number_bounds(
        &schema,
        "/$defs/runCompleteRequest/allOf/1/properties/params/properties/usage/properties/providerReportedCost",
    );
    assert_number_boundaries(&codec, "reported cost", run_complete_with_cost, min, max);
    assert!(codec.decode(&tool_request_with_null_fence()).is_ok());
}

#[test]
fn rejects_unsigned_values_that_exceed_i64_for_bounded_integer_constraints() {
    let codec = NdjsonCodec::default();
    let beyond_i64 = json!(9_223_372_036_854_775_808_u64);

    for (name, frame) in [
        (
            "transport max frame bytes",
            with_value(
                initialize_request(),
                &["params", "transport", "maxFrameBytes"],
                beyond_i64.clone(),
            ),
        ),
        (
            "run output tokens",
            with_value(
                run_start_request(),
                &["params", "limits", "maxOutputTokens"],
                beyond_i64.clone(),
            ),
        ),
        (
            "run tool requests",
            with_value(
                run_start_request(),
                &["params", "limits", "maxToolRequests"],
                beyond_i64.clone(),
            ),
        ),
        (
            "cancel deadline",
            with_value(
                run_cancel_with_deadline(1),
                &["params", "deadlineMs"],
                beyond_i64.clone(),
            ),
        ),
        (
            "context max items",
            with_value(
                context_query_request(),
                &["params", "maxItems"],
                beyond_i64.clone(),
            ),
        ),
        (
            "context max tokens",
            with_value(
                context_query_request(),
                &["params", "maxTokens"],
                beyond_i64,
            ),
        ),
    ] {
        assert_rejected(&codec, frame, name);
    }
}

#[test]
fn encoding_rechecks_representable_schema_constraints() {
    let codec = NdjsonCodec::default();

    for (name, value) in [
        (
            "empty protocol versions",
            with_value(
                initialize_request(),
                &["params", "protocolVersions"],
                json!([]),
            ),
        ),
        (
            "empty context scopes",
            with_value(context_query_request(), &["params", "scopes"], json!([])),
        ),
        ("too many claims", run_complete_request(claims(1025))),
        (
            "too many evidence references",
            run_complete_request(vec![claim(evidence_references(129))]),
        ),
        (
            "too many required context entries",
            with_value(
                specialist_request(),
                &["params", "requiredContext"],
                strings(129),
            ),
        ),
        (
            "too many tool argument properties",
            with_value(
                tool_request(),
                &["params", "arguments"],
                object_with_properties(257),
            ),
        ),
        (
            "too many error data properties",
            with_value(
                error_response(),
                &["error", "data"],
                object_with_properties(257),
            ),
        ),
        (
            "max frame above",
            initialize_with_max_frame_bytes(67_108_865),
        ),
        ("max frame below", initialize_with_max_frame_bytes(1_023)),
        (
            "output tokens above",
            run_start_with_output_tokens(1_000_001),
        ),
        (
            "output tokens above i64 max",
            with_value(
                run_start_request(),
                &["params", "limits", "maxOutputTokens"],
                json!(9_223_372_036_854_775_808_u64),
            ),
        ),
        ("tool requests above", run_start_with_tool_requests(10_001)),
        ("cancel deadline above", run_cancel_with_deadline(300_001)),
        ("confidence above", run_complete_with_confidence(1.1)),
        (
            "context max items above",
            context_query_with_max_items(1_001),
        ),
        (
            "context max tokens above",
            context_query_with_max_tokens(1_000_001),
        ),
        ("reported cost below", run_complete_with_usage(0, 0, -0.1)),
    ] {
        let frame: ProtocolFrame = serde_json::from_value(value)
            .unwrap_or_else(|error| panic!("{name} must remain representable: {error}"));
        assert!(codec.encode(&frame).is_err(), "{name} must not encode");
    }
}

fn shutdown_request() -> Vec<u8> {
    b"{\"jsonrpc\":\"2.0\",\"id\":\"core:shutdown\",\"method\":\"shutdown\",\"params\":{}}".to_vec()
}

fn tool_request_with_length(length: usize) -> Vec<u8> {
    const PREFIX: &str = "{\"jsonrpc\":\"2.0\",\"id\":\"agent:1\",\"method\":\"tool.request\",\"params\":{\"runId\":\"run\",\"requestId\":\"request\",\"tool\":\"tool\",\"arguments\":{\"padding\":\"";
    const SUFFIX: &str = "\"},\"reason\":\"reason\"}}";
    assert!(length >= PREFIX.len() + SUFFIX.len());

    format!(
        "{PREFIX}{}{SUFFIX}",
        "a".repeat(length - PREFIX.len() - SUFFIX.len())
    )
    .into_bytes()
}

fn fixture_path(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/contracts/fixtures/m3")
        .join(name)
}

fn assert_rejected(codec: &NdjsonCodec, frame: Value, name: &str) {
    assert!(
        codec.decode(&json_bytes(&frame)).is_err(),
        "{name} must be rejected"
    );
}

fn normative_schema() -> Value {
    serde_json::from_str(include_str!(
        "../../../docs/multi-agent-terminal-design/schemas/agent-protocol.v1.schema.json"
    ))
    .expect("normative schema must be valid JSON")
}

fn schema_integer_bounds(schema: &Value, path: &str) -> (i64, Option<i64>) {
    let constraint = schema
        .pointer(path)
        .expect("numeric constraint path must exist");
    let min = constraint
        .get("minimum")
        .and_then(Value::as_u64)
        .and_then(|value| i64::try_from(value).ok())
        .expect("numeric minimum must fit i64");
    let max = constraint.get("maximum").map(|value| {
        value
            .as_u64()
            .and_then(|value| i64::try_from(value).ok())
            .expect("numeric maximum must fit i64")
    });
    (min, max)
}

fn schema_number_bounds(schema: &Value, path: &str) -> (f64, Option<f64>) {
    let constraint = schema
        .pointer(path)
        .expect("numeric constraint path must exist");
    let min = constraint
        .get("minimum")
        .and_then(Value::as_f64)
        .expect("numeric minimum must exist");
    let max = constraint.get("maximum").and_then(Value::as_f64);
    (min, max)
}

fn assert_integer_boundaries(
    codec: &NdjsonCodec,
    name: &str,
    frame: fn(i64) -> Value,
    min: i64,
    max: Option<i64>,
) {
    for (value, accepted) in [(min - 1, false), (min, true), (min + 1, true)] {
        assert_eq!(
            codec.decode(&json_bytes(&frame(value))).is_ok(),
            accepted,
            "{name} {value}",
        );
    }
    if let Some(max) = max {
        for (value, accepted) in [(max - 1, true), (max, true), (max + 1, false)] {
            assert_eq!(
                codec.decode(&json_bytes(&frame(value))).is_ok(),
                accepted,
                "{name} {value}",
            );
        }
    }
}

fn assert_number_boundaries(
    codec: &NdjsonCodec,
    name: &str,
    frame: fn(f64) -> Value,
    min: f64,
    max: Option<f64>,
) {
    const STEP: f64 = 0.1;

    for (value, accepted) in [(min - STEP, false), (min, true), (min + STEP, true)] {
        assert_eq!(
            codec.decode(&json_bytes(&frame(value))).is_ok(),
            accepted,
            "{name} {value}",
        );
    }
    if let Some(max) = max {
        for (value, accepted) in [(max - STEP, true), (max, true), (max + STEP, false)] {
            assert_eq!(
                codec.decode(&json_bytes(&frame(value))).is_ok(),
                accepted,
                "{name} {value}",
            );
        }
    }
}

fn json_bytes(value: &Value) -> Vec<u8> {
    serde_json::to_vec(value).expect("test frame must serialize")
}

fn with_value(mut frame: Value, path: &[&str], value: Value) -> Value {
    let (last, parents) = path.split_last().expect("fixture path must not be empty");
    let mut current = &mut frame;
    for parent in parents {
        current = current
            .get_mut(*parent)
            .expect("fixture path must exist before replacement");
    }
    current
        .as_object_mut()
        .expect("fixture replacement parent must be an object")
        .insert((*last).to_owned(), value);
    frame
}

fn initialize_request() -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": "core:initialize",
        "method": "initialize",
        "params": {
            "protocolVersions": ["1.0"],
            "client": { "name": "client", "version": "1" },
            "transport": { "type": "stdio-ndjson", "maxFrameBytes": 1024 },
            "features": ["streaming"],
            "launchBinding": {
                "connectionId": "connection",
                "manifestDigest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "executableDigest": "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                "trustTier": "brokered_process"
            }
        }
    })
}

fn initialize_with_max_frame_bytes(max_frame_bytes: i64) -> Value {
    with_value(
        initialize_request(),
        &["params", "transport", "maxFrameBytes"],
        json!(max_frame_bytes),
    )
}

fn run_start_request() -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": "core:start",
        "method": "agent.run.start",
        "params": {
            "runId": "run",
            "idempotencyKey": "key",
            "taskId": "task",
            "role": "role",
            "objective": "objective",
            "contextPackage": {
                "packageId": "package",
                "contentDigest": "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
                "manifestRef": "manifest"
            },
            "permissions": {
                "contextQuery": true,
                "toolRequest": true,
                "writeFiles": false
            },
            "responseSchema": "agent-message.v1",
            "limits": {
                "deadline": "2026-07-23T13:20:00Z",
                "maxOutputTokens": 1,
                "maxToolRequests": 0
            }
        }
    })
}

fn run_start_with_output_tokens(max_output_tokens: i64) -> Value {
    with_value(
        run_start_request(),
        &["params", "limits", "maxOutputTokens"],
        json!(max_output_tokens),
    )
}

fn run_start_with_tool_requests(max_tool_requests: i64) -> Value {
    with_value(
        run_start_request(),
        &["params", "limits", "maxToolRequests"],
        json!(max_tool_requests),
    )
}

fn run_cancel_with_deadline(deadline_ms: i64) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": "core:cancel",
        "method": "agent.run.cancel",
        "params": { "runId": "run", "reason": "reason", "deadlineMs": deadline_ms }
    })
}

fn run_complete_request(claims: Vec<Value>) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": "agent:complete",
        "method": "agent.run.complete",
        "params": {
            "runId": "run",
            "status": "succeeded",
            "message": agent_message(claims)
        }
    })
}

fn run_complete_with_evidence_lines(start_line: i64, end_line: i64) -> Value {
    run_complete_request(vec![claim(vec![evidence_reference(start_line, end_line)])])
}

fn run_complete_with_start_line(start_line: i64) -> Value {
    run_complete_with_evidence_lines(start_line, 1)
}

fn run_complete_with_end_line(end_line: i64) -> Value {
    run_complete_with_evidence_lines(1, end_line)
}

fn run_complete_with_confidence(confidence: f64) -> Value {
    let mut frame = run_complete_request(vec![claim(Vec::new())]);
    frame["params"]["message"]["claims"][0]["confidence"] = json!(confidence);
    frame
}

fn run_complete_with_usage(input_tokens: i64, output_tokens: i64, cost: f64) -> Value {
    let mut frame = run_complete_request(Vec::new());
    frame["params"]["usage"] = json!({
        "inputTokens": input_tokens,
        "outputTokens": output_tokens,
        "providerReportedCost": cost
    });
    frame
}

fn run_complete_with_input_tokens(input_tokens: i64) -> Value {
    run_complete_with_usage(input_tokens, 0, 0.0)
}

fn run_complete_with_output_tokens(output_tokens: i64) -> Value {
    run_complete_with_usage(0, output_tokens, 0.0)
}

fn run_complete_with_cost(cost: f64) -> Value {
    run_complete_with_usage(0, 0, cost)
}

fn agent_message(claims: Vec<Value>) -> Value {
    json!({
        "messageId": "message",
        "type": "answer",
        "content": "content",
        "claims": claims
    })
}

fn claims(count: usize) -> Vec<Value> {
    (0..count).map(|_| claim(Vec::new())).collect()
}

fn claim(evidence_refs: Vec<Value>) -> Value {
    json!({
        "claimId": "claim",
        "text": "claim",
        "evidenceRefs": evidence_refs,
        "confidence": 0.5
    })
}

fn evidence_references(count: usize) -> Vec<Value> {
    (0..count).map(|_| evidence_reference(1, 1)).collect()
}

fn evidence_reference(start_line: i64, end_line: i64) -> Value {
    json!({
        "sourceType": "repository",
        "sourceId": "source",
        "revision": "revision",
        "contentDigest": "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
        "startLine": start_line,
        "endLine": end_line
    })
}

fn stream_delta_with_sequence(sequence: i64) -> Value {
    json!({
        "jsonrpc": "2.0",
        "method": "agent.stream.delta",
        "params": { "runId": "run", "sequence": sequence, "channel": "content", "delta": "delta" }
    })
}

fn context_query_request() -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": "agent:context",
        "method": "context.query",
        "params": {
            "runId": "run",
            "queryId": "query",
            "query": "query",
            "scopes": ["task"],
            "maxItems": 1,
            "maxTokens": 1
        }
    })
}

fn context_query_with_max_items(max_items: i64) -> Value {
    with_value(
        context_query_request(),
        &["params", "maxItems"],
        json!(max_items),
    )
}

fn context_query_with_max_tokens(max_tokens: i64) -> Value {
    with_value(
        context_query_request(),
        &["params", "maxTokens"],
        json!(max_tokens),
    )
}

fn tool_request() -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": "agent:tool",
        "method": "tool.request",
        "params": {
            "runId": "run",
            "requestId": "request",
            "tool": "tool",
            "arguments": {},
            "reason": "reason"
        }
    })
}

fn tool_request_with_fence(executor_fencing_token: i64) -> Value {
    with_value(
        tool_request(),
        &["params", "executorFencingToken"],
        json!(executor_fencing_token),
    )
}

fn tool_request_with_null_fence() -> Vec<u8> {
    json_bytes(&with_value(
        tool_request(),
        &["params", "executorFencingToken"],
        Value::Null,
    ))
}

fn specialist_request() -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": "agent:specialist",
        "method": "specialist.request",
        "params": {
            "runId": "run",
            "capability": "capability",
            "reason": "reason",
            "requiredContext": []
        }
    })
}

fn heartbeat_with_sequence(sequence: i64) -> Value {
    json!({
        "jsonrpc": "2.0",
        "method": "agent.heartbeat",
        "params": { "connectionId": "connection", "sequence": sequence }
    })
}

fn shutdown_request_value() -> Value {
    json!({ "jsonrpc": "2.0", "id": "core:shutdown", "method": "shutdown", "params": {} })
}

fn exit_notification() -> Value {
    json!({ "jsonrpc": "2.0", "method": "exit", "params": {} })
}

fn error_response() -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": "agent:error",
        "error": { "code": -32000, "message": "error", "data": {} }
    })
}

fn object_with_properties(count: usize) -> Value {
    let mut object = Map::new();
    for index in 0..count {
        object.insert(format!("property-{index}"), Value::Bool(true));
    }
    Value::Object(object)
}

fn strings(count: usize) -> Value {
    Value::Array(
        (0..count)
            .map(|index| Value::String(format!("context-{index}")))
            .collect(),
    )
}
