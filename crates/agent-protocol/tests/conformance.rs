use std::collections::BTreeSet;

use local_agent_terminal_agent_protocol::{
    conformance_cases, run_conformance, CancelAcceptance, ConnectionBinding, NdjsonCodec,
    PeerDescriptor, PeerEventSink, ProtocolCapabilities, ProtocolError, ProtocolFrame,
    ProtocolPeer, ProtocolTrustTier, RunAcceptance, RunCancel, RunStart,
};
use serde_json::json;

#[test]
fn shared_harness_exercises_the_required_protocol_cases() {
    let case_names: Vec<_> = conformance_cases().iter().map(|case| case.name).collect();
    for expected in [
        "happy",
        "malicious",
        "slow",
        "cancelled",
        "crashed",
        "malformed",
        "oversize",
        "sequence-gap",
        "duplicate-terminal",
    ] {
        assert!(
            case_names.contains(&expected),
            "missing {expected} conformance case"
        );
    }

    run_conformance(&ConformantPeer).expect("a peer with the protocol contract passes");
}

#[test]
fn shared_harness_rejects_a_peer_that_never_emits_a_terminal_result() {
    assert!(matches!(
        run_conformance(&SilentPeer),
        Err(ProtocolError::Timeout)
    ));
}

struct ConformantPeer;

impl ProtocolPeer for ConformantPeer {
    fn descriptor(&self) -> PeerDescriptor {
        PeerDescriptor {
            binding: ConnectionBinding {
                connection_id: "connection-1".to_owned(),
                agent_id: "agent-1".to_owned(),
                manifest_digest:
                    "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                        .to_owned(),
                executable_digest:
                    "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                        .to_owned(),
                trust_tier: ProtocolTrustTier::CoreAdapter,
            },
            protocol_version: "1.0".to_owned(),
            capabilities: ProtocolCapabilities {
                roles: strings(["critic"]),
                skills: strings(["testing"]),
                streaming: true,
                context_query: true,
                tool_requests: true,
                specialist_requests: true,
                max_concurrent_runs: 1,
                max_context_tokens: 1_024,
            },
        }
    }

    fn start(
        &self,
        request: RunStart,
        sink: Box<dyn PeerEventSink>,
    ) -> Result<RunAcceptance, ProtocolError> {
        let run_id = request.run_id();
        sink.receive(stream_delta(&run_id, 1))?;
        sink.receive(terminal(&run_id))?;
        Ok(RunAcceptance {
            run_id,
            accepted: true,
        })
    }

    fn cancel(&self, request: RunCancel) -> Result<CancelAcceptance, ProtocolError> {
        Ok(CancelAcceptance {
            run_id: request.run_id(),
            accepted: true,
        })
    }

    fn shutdown(&self) -> Result<(), ProtocolError> {
        Ok(())
    }
}

struct SilentPeer;

impl ProtocolPeer for SilentPeer {
    fn descriptor(&self) -> PeerDescriptor {
        ConformantPeer.descriptor()
    }

    fn start(
        &self,
        request: RunStart,
        _sink: Box<dyn PeerEventSink>,
    ) -> Result<RunAcceptance, ProtocolError> {
        Ok(RunAcceptance {
            run_id: request.run_id(),
            accepted: true,
        })
    }

    fn cancel(&self, request: RunCancel) -> Result<CancelAcceptance, ProtocolError> {
        Ok(CancelAcceptance {
            run_id: request.run_id(),
            accepted: true,
        })
    }

    fn shutdown(&self) -> Result<(), ProtocolError> {
        Ok(())
    }
}

fn strings<const N: usize>(values: [&str; N]) -> BTreeSet<String> {
    values.into_iter().map(str::to_owned).collect()
}

fn stream_delta(run_id: &str, sequence: u64) -> ProtocolFrame {
    decode(json!({
        "jsonrpc": "2.0",
        "method": "agent.stream.delta",
        "params": { "runId": run_id, "sequence": sequence, "channel": "content", "delta": "ok" }
    }))
}

fn terminal(run_id: &str) -> ProtocolFrame {
    decode(json!({
        "jsonrpc": "2.0",
        "id": "agent:conformance-complete",
        "method": "agent.run.complete",
        "params": {
            "runId": run_id,
            "status": "succeeded",
            "message": {
                "messageId": "message-conformance",
                "type": "answer",
                "content": "done",
                "claims": []
            }
        }
    }))
}

fn decode(frame: serde_json::Value) -> ProtocolFrame {
    NdjsonCodec::default()
        .decode(&serde_json::to_vec(&frame).expect("fixture must serialize"))
        .expect("fixture must match the immutable schema")
}
