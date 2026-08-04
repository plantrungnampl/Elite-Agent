use std::fs;
use std::path::{Path, PathBuf};

use local_agent_terminal_agent_protocol::{NdjsonCodec, ProtocolError, DEFAULT_MAX_FRAME_BYTES};

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
