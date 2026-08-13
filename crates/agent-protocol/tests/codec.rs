use std::{fs, path::Path};

use local_agent_terminal_agent_protocol::{
    NdjsonCodec, ProtocolError, ProtocolFrame, DEFAULT_MAX_FRAME_BYTES,
};
use serde_json::{json, Value};

const CANONICAL_V2_FRAMES: [&str; 13] = [
    "protocol-initialize.request.json",
    "protocol-initialize.response.json",
    "protocol-initialized.notification.json",
    "protocol-run-start.request.json",
    "protocol-run-start.response.json",
    "protocol-stream-delta.notification.json",
    "protocol-context-query.request.json",
    "protocol-context-query.response.json",
    "protocol-tool.request.json",
    "protocol-specialist.request.json",
    "protocol-run-complete.request.json",
    "protocol-run-cancel.request.json",
    "protocol-error.response.json",
];

#[test]
fn decodes_every_canonical_v2_frame() {
    let codec = NdjsonCodec::default();
    for name in CANONICAL_V2_FRAMES {
        let bytes = compact_fixture(name);
        codec
            .decode(&bytes)
            .unwrap_or_else(|error| panic!("{name} must decode: {error}"));
    }
}

#[test]
fn decodes_the_supplemental_tool_response() {
    let bytes = compact_fixture("protocol-tool.response.json");
    assert!(NdjsonCodec::default().decode(&bytes).is_ok());
}

#[test]
fn rejects_v1_fields_and_run_configuration_duplication() {
    let codec = NdjsonCodec::default();
    let mut initialize = frame("protocol-initialize.request.json");
    initialize["params"]["features"] = json!(["streaming"]);
    let mut start = frame("protocol-run-start.request.json");
    start["params"]["runConfigurationRef"] = json!("run-config-1");
    start["params"]["limits"] = json!({ "maxOutputTokens": 1 });

    for value in [initialize, start] {
        assert!(codec.decode(&json_bytes(&value)).is_err());
    }
}

#[test]
fn rejects_invalid_prefixes_notifications_with_ids_and_unknown_methods() {
    let codec = NdjsonCodec::default();
    let mut initialize = frame("protocol-initialize.request.json");
    initialize["id"] = json!("user:1");
    let mut core_request = frame("protocol-initialize.request.json");
    core_request["id"] = json!("agent:1");
    let mut agent_request = frame("protocol-run-complete.request.json");
    agent_request["id"] = json!("core:1");
    let mut notification = frame("protocol-initialized.notification.json");
    notification["id"] = json!("agent:1");
    let mut unknown = frame("protocol-run-cancel.request.json");
    unknown["method"] = json!("unknown.method");

    for value in [
        initialize,
        core_request,
        agent_request,
        notification,
        unknown,
    ] {
        assert!(codec.decode(&json_bytes(&value)).is_err());
    }
}

#[test]
fn enforces_closed_v2_request_and_response_shapes() {
    let codec = NdjsonCodec::default();
    let mut request = frame("protocol-tool.request.json");
    request["params"]["argumentsDigest"] = json!("sha256:not-a-digest");
    let mut response = frame("protocol-run-start.response.json");
    response["result"]["unexpected"] = json!(true);

    for value in [request, response] {
        assert!(codec.decode(&json_bytes(&value)).is_err());
    }
}

#[test]
fn enforces_v2_schema_boundaries() {
    let codec = NdjsonCodec::default();
    let mut sequence_zero = frame("protocol-stream-delta.notification.json");
    sequence_zero["params"]["sequence"] = json!(0);
    let mut too_many_items = frame("protocol-context-query.request.json");
    too_many_items["params"]["maxItems"] = json!(1001);
    let mut invalid_cost = frame("protocol-run-complete.request.json");
    invalid_cost["params"]["usage"]["providerReportedCostMicrounits"] = json!(-1);

    for value in [sequence_zero, too_many_items, invalid_cost] {
        assert!(codec.decode(&json_bytes(&value)).is_err());
    }
}

#[test]
fn preserves_ndjson_transport_boundaries() {
    let codec = NdjsonCodec::default();
    let bytes = compact_fixture("protocol-run-start.request.json");
    let frame = codec.decode(&bytes).expect("start frame must decode");
    let encoded = codec.encode(&frame).expect("start frame must encode");

    assert_eq!(encoded.last(), Some(&b'\n'));
    assert!(codec.decode(&encoded).is_ok());
    assert!(matches!(
        codec.decode(b"\n"),
        Err(ProtocolError::EmptyFrame)
    ));
    assert!(matches!(
        codec.decode(b"{}\n{}"),
        Err(ProtocolError::MultipleFrames)
    ));
}

#[test]
fn enforces_configured_frame_limit() {
    let frame = NdjsonCodec::default()
        .decode(&compact_fixture("protocol-tool.request.json"))
        .unwrap();
    let bytes = NdjsonCodec::default().encode(&frame).unwrap();
    let body = bytes.len() - 1;

    assert!(NdjsonCodec::new(body).encode(&frame).is_ok());
    assert!(matches!(
        NdjsonCodec::new(body - 1).encode(&frame),
        Err(ProtocolError::FrameTooLarge { .. })
    ));
    assert!(DEFAULT_MAX_FRAME_BYTES > body);
}

#[test]
fn generated_frames_remain_representable_after_decode() {
    let codec = NdjsonCodec::default();
    let source = compact_fixture("protocol-run-complete.request.json");
    let decoded: ProtocolFrame = codec.decode(&source).unwrap();
    assert_eq!(
        serde_json::from_slice::<Value>(&source).unwrap(),
        serde_json::to_value(decoded).unwrap()
    );
}

fn frame(name: &str) -> Value {
    serde_json::from_slice(
        &fs::read(example_path(name)).unwrap_or_else(|_| panic!("{name} must be readable")),
    )
    .unwrap_or_else(|_| panic!("{name} must be JSON"))
}

fn json_bytes(value: &Value) -> Vec<u8> {
    serde_json::to_vec(value).expect("test value must encode")
}

fn compact_fixture(name: &str) -> Vec<u8> {
    json_bytes(&frame(name))
}

fn example_path(name: &str) -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/multi-agent-terminal-design/schemas/examples-v2")
        .join(name)
}
