use local_agent_terminal_application::{
    ProtocolRequestBegin, ProtocolRequestIdentity, ProtocolRequestTerminal,
    ProtocolRequestTerminalStatus, ProtocolResponseArtifact, ProtocolStreamAdvance,
    ProtocolStreamIdentity,
};
use local_agent_terminal_domain::{ArtifactId, RunId, Sequence, Sha256Digest, TaskId};

const REQUEST_DIGEST: &str =
    "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

#[test]
fn terminal_protocol_records_bind_exact_request_response_bytes_and_stream_sequence() {
    let identity = ProtocolRequestIdentity::new(
        "connection-1",
        "agent:request-1",
        "context.query",
        Sha256Digest::new(REQUEST_DIGEST).unwrap(),
    )
    .unwrap();
    let begin = ProtocolRequestBegin::new(
        identity.clone(),
        Some(TaskId::new("task-1").unwrap()),
        Some(RunId::new("run-1").unwrap()),
        "2026-08-14T00:00:00Z",
    )
    .unwrap();
    let response = ProtocolResponseArtifact::new(
        ArtifactId::new("protocol-response-1").unwrap(),
        br#"{"jsonrpc":"2.0","id":"agent:request-1","result":{}}"#.to_vec(),
    )
    .unwrap();
    let terminal = ProtocolRequestTerminal::new(
        identity,
        ProtocolRequestTerminalStatus::Failed,
        response.clone(),
        "2026-08-14T00:00:01Z",
    )
    .unwrap();
    let stream = ProtocolStreamAdvance::new(
        "connection-1",
        RunId::new("run-1").unwrap(),
        "content",
        Sequence::new(1),
    )
    .unwrap();
    let stream_identity =
        ProtocolStreamIdentity::new("connection-1", RunId::new("run-1").unwrap(), "content")
            .unwrap();

    assert_eq!(begin.task_id().unwrap().as_str(), "task-1");
    assert_eq!(begin.run_id().unwrap().as_str(), "run-1");
    assert_eq!(terminal.status(), ProtocolRequestTerminalStatus::Failed);
    assert_eq!(terminal.response().bytes(), response.bytes());
    assert_eq!(stream_identity.channel(), "content");
    assert_eq!(stream.sequence().get(), 1);
}

#[test]
fn protocol_record_construction_rejects_incoherent_or_empty_values() {
    let identity = ProtocolRequestIdentity::new(
        "connection-1",
        "agent:request-1",
        "context.query",
        Sha256Digest::new(REQUEST_DIGEST).unwrap(),
    )
    .unwrap();

    assert!(ProtocolRequestBegin::new(
        identity.clone(),
        None,
        Some(RunId::new("run-1").unwrap()),
        "2026-08-14T00:00:00Z",
    )
    .is_err());
    assert!(ProtocolResponseArtifact::new(
        ArtifactId::new("protocol-response-1").unwrap(),
        Vec::new(),
    )
    .is_err());
    assert!(ProtocolResponseArtifact::new(
        ArtifactId::new("protocol-response-2").unwrap(),
        b"not json".to_vec(),
    )
    .is_err());
    assert!(ProtocolStreamAdvance::new(
        "connection-1",
        RunId::new("run-1").unwrap(),
        "content",
        Sequence::new(0),
    )
    .is_err());
}
