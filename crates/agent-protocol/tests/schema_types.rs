use std::{fs, path::Path};

use local_agent_terminal_agent_protocol::ProtocolFrame;

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
fn every_annotated_canonical_v2_frame_round_trips_through_generated_types() {
    for name in CANONICAL_V2_FRAMES {
        let source = fs::read(example_path(name)).expect("canonical v2 frame must be readable");
        let frame: ProtocolFrame = serde_json::from_slice(&source)
            .unwrap_or_else(|error| panic!("{name} must deserialize: {error}"));
        let encoded = serde_json::to_vec(&frame)
            .unwrap_or_else(|error| panic!("{name} must serialize: {error}"));

        let round_trip: ProtocolFrame = serde_json::from_slice(&encoded)
            .unwrap_or_else(|error| panic!("{name} must deserialize after serialization: {error}"));
        assert_eq!(
            encoded,
            serde_json::to_vec(&round_trip)
                .unwrap_or_else(|error| panic!("{name} must serialize after round trip: {error}")),
            "{name} must retain a stable generated representation",
        );
    }
}

#[test]
fn supplemental_tool_response_round_trips_separately() {
    let source = fs::read(example_path("protocol-tool.response.json")).unwrap();
    let _: ProtocolFrame = serde_json::from_slice(&source).unwrap();
}

fn example_path(name: &str) -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/multi-agent-terminal-design/schemas/examples-v2")
        .join(name)
}
