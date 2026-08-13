use std::{
    collections::BTreeSet,
    sync::{Arc, Mutex},
};

use local_agent_terminal_agent_protocol::{
    run_conformance, ConnectionBinding, InboundDisposition, NdjsonCodec, PeerDescriptor,
    PeerEventSink, ProtocolCapabilities, ProtocolError, ProtocolFrame, ProtocolPeer,
    ProtocolTrustTier, RunExecutionBinding, RunStart,
};
use local_agent_terminal_agent_runtime::{
    RequestScript, Script, ScriptedPeer, ScriptedPeerFactory,
};
use serde_json::{json, Value};

#[test]
fn every_script_passes_the_shared_protocol_conformance_matrix() {
    run_conformance(&ScriptedPeerFactory::new(descriptor()))
        .expect("the single scripted peer model must pass every shared case");
}

#[test]
fn request_scripts_are_deterministic_and_never_emit_workflow_notifications() {
    for (script, expected_methods, expected_responses) in [
        (
            RequestScript::ContextQuery,
            vec!["context.query"],
            vec!["context"],
        ),
        (
            RequestScript::SpecialistRequest,
            vec!["specialist.request"],
            vec!["specialist"],
        ),
        (
            RequestScript::ContextOverflow,
            vec!["context.query"],
            vec!["context"],
        ),
        (
            RequestScript::DuplicateContextQuery,
            vec!["context.query", "context.query"],
            vec!["context", "context"],
        ),
        (
            RequestScript::CrossRun,
            vec!["context.query"],
            vec!["error"],
        ),
    ] {
        let peer = ScriptedPeer::new(Script::RequestingScenario(script), descriptor());
        let observations = Arc::new(Mutex::new(RequestObservations::default()));
        let sink = RecordingRequestSink {
            observations: Arc::clone(&observations),
        };
        peer.start(run_start(), Box::new(sink)).unwrap();

        peer.drive().unwrap();

        let observations = observations.lock().unwrap();
        assert_eq!(observations.methods, expected_methods, "script {script:?}");
        assert_eq!(observations.response_ids, observations.request_ids);
        assert_eq!(
            observations.response_shapes, expected_responses,
            "script {script:?}"
        );
        assert_eq!(observations.notifications, 0, "script {script:?}");
        assert_eq!(observations.connection_losses, 0, "script {script:?}");
    }
}

#[derive(Default)]
struct RequestObservations {
    methods: Vec<String>,
    request_ids: Vec<String>,
    response_ids: Vec<String>,
    response_shapes: Vec<String>,
    notifications: usize,
    connection_losses: usize,
}

struct RecordingRequestSink {
    observations: Arc<Mutex<RequestObservations>>,
}

impl PeerEventSink for RecordingRequestSink {
    fn receive(&self, _frame: ProtocolFrame) -> Result<InboundDisposition, ProtocolError> {
        self.observations.lock().unwrap().notifications += 1;
        Err(ProtocolError::InvalidRequest)
    }

    fn request(&self, frame: ProtocolFrame) -> Result<ProtocolFrame, ProtocolError> {
        let value = serde_json::to_value(&frame).map_err(|_| ProtocolError::InvalidRequest)?;
        let method = value
            .get("method")
            .and_then(Value::as_str)
            .ok_or(ProtocolError::InvalidRequest)?
            .to_owned();
        let request_id = value
            .get("id")
            .and_then(Value::as_str)
            .ok_or(ProtocolError::InvalidRequest)?
            .to_owned();
        let run_id = value
            .pointer("/params/runId")
            .and_then(Value::as_str)
            .ok_or(ProtocolError::InvalidRequest)?;
        {
            let mut observations = self.observations.lock().unwrap();
            observations.methods.push(method.clone());
            observations.request_ids.push(request_id.clone());
        }
        let response = if run_id != "conformance-run" {
            decode(json!({
                "jsonrpc": "2.0",
                "id": request_id,
                "error": {
                    "code": -32602,
                    "message": "request rejected",
                    "data": {
                        "category": "request_ownership_mismatch",
                        "retryable": false
                    }
                }
            }))
        } else if method == "context.query" {
            decode(json!({
                "jsonrpc": "2.0",
                "id": request_id,
                "result": {
                    "queryId": value.pointer("/params/queryId").and_then(Value::as_str).unwrap(),
                    "items": [{
                        "itemId": "ctx-fake-item",
                        "contentRef": "ctx-fake-supplement",
                        "contentDigest": "sha256:ea7792a26f405e2ae9c6f49ca93bbe6076ceac0a1fc53d83426c7d7f2d9377e4",
                        "sourceRefs": ["ctx-fake-supplement"],
                        "observationClass": "core_observed"
                    }],
                    "truncated": false,
                    "effectivePayloadDigest": "sha256:ea7792a26f405e2ae9c6f49ca93bbe6076ceac0a1fc53d83426c7d7f2d9377e4",
                    "redactionReportDigest": "sha256:0000000000000000000000000000000000000000000000000000000000000000"
                }
            }))
        } else if method == "specialist.request" {
            decode(json!({
                "jsonrpc": "2.0",
                "id": request_id,
                "result": {
                    "requestId": value.pointer("/params/requestId").and_then(Value::as_str).unwrap(),
                    "decision": "accepted",
                    "specialistRunId": "specialist-fake-run"
                }
            }))
        } else {
            decode(json!({
                "jsonrpc": "2.0",
                "id": request_id,
                "error": {
                    "code": -32600,
                    "message": "request rejected",
                    "data": {
                        "category": "policy_denied",
                        "retryable": false
                    }
                }
            }))
        };
        let response_value = serde_json::to_value(&response).unwrap();
        let response_shape = if response_value.pointer("/result/queryId").is_some() {
            "context"
        } else if response_value.pointer("/result/decision").is_some() {
            "specialist"
        } else {
            "error"
        };
        let mut observations = self.observations.lock().unwrap();
        observations.response_ids.push(request_id);
        observations.response_shapes.push(response_shape.to_owned());
        Ok(response)
    }

    fn receive_raw(&self, _bytes: &[u8]) -> Result<InboundDisposition, ProtocolError> {
        Err(ProtocolError::InvalidRequest)
    }

    fn connection_lost(&self) -> Result<(), ProtocolError> {
        self.observations.lock().unwrap().connection_losses += 1;
        Ok(())
    }
}

fn run_start() -> RunStart {
    RunStart::new(
        decode(json!({
            "jsonrpc": "2.0",
            "id": "core:fake-start",
            "method": "agent.run.start",
            "params": {
                "runId": "conformance-run",
                "taskId": "task-1",
                "contextPackageRef": "context-1",
                "idempotencyKey": "fake-start",
                "role": "critic",
            }
        })),
        RunExecutionBinding {
            provider_id: "provider-1".to_owned(),
            model_id: "model-1".to_owned(),
            max_output_tokens: 100,
            generation_parameters: b"{}".to_vec(),
            generation_parameters_digest:
                "sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a"
                    .to_owned(),
            effective_context: b"context".to_vec(),
            effective_context_artifact_id: "artifact-context-1".to_owned(),
            effective_context_digest:
                "sha256:ea7792a26f405e2ae9c6f49ca93bbe6076ceac0a1fc53d83426c7d7f2d9377e4"
                    .to_owned(),
            supersedes_run_id: None,
        },
    )
    .unwrap()
}

fn decode(value: Value) -> ProtocolFrame {
    NdjsonCodec::default()
        .decode(&serde_json::to_vec(&value).unwrap())
        .unwrap()
}

fn descriptor() -> PeerDescriptor {
    PeerDescriptor {
        binding: ConnectionBinding {
            connection_id: "connection-1".to_owned(),
            agent_id: "agent-1".to_owned(),
            manifest_digest:
                "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_owned(),
            executable_digest:
                "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_owned(),
            trust_tier: ProtocolTrustTier::CoreAdapter,
        },
        protocol_version: "2.0".to_owned(),
        capabilities: ProtocolCapabilities {
            roles: BTreeSet::from(["critic".to_owned()]),
            skills: BTreeSet::from(["testing".to_owned()]),
            streaming: true,
            context_query: true,
            tool_requests: true,
            specialist_requests: true,
            max_concurrent_runs: 1,
            max_context_tokens: 1_024,
        },
    }
}
