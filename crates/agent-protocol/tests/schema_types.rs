use std::fs;
use std::path::{Path, PathBuf};

use local_agent_terminal_agent_protocol::ProtocolFrame;

#[test]
fn every_protocol_example_round_trips_through_generated_types() {
    let mut examples =
        fs::read_dir(workspace_root().join("docs/multi-agent-terminal-design/schemas/examples"))
            .expect("normative examples directory must exist")
            .map(|entry| {
                entry
                    .expect("example directory entry must be readable")
                    .path()
            })
            .filter(|path| {
                path.file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| name.starts_with("protocol-") && name.ends_with(".json"))
            })
            .collect::<Vec<_>>();
    examples.sort();
    assert!(!examples.is_empty(), "protocol examples must exist");

    for path in examples {
        let source = fs::read(&path).expect("normative example must be readable");
        let frame: ProtocolFrame = serde_json::from_slice(&source)
            .unwrap_or_else(|error| panic!("{} must deserialize: {error}", path.display()));
        let encoded = serde_json::to_vec(&frame)
            .unwrap_or_else(|error| panic!("{} must serialize: {error}", path.display()));

        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&source).expect("example must be JSON"),
            serde_json::from_slice::<serde_json::Value>(&encoded)
                .expect("generated frame serialization must be JSON"),
            "{} must round-trip without changing its JSON value",
            path.display(),
        );
    }
}

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("workspace root")
}
