use std::{
    collections::BTreeSet,
    sync::{Arc, Condvar, Mutex},
    thread::{self, JoinHandle},
};

use local_agent_terminal_agent_protocol::{
    conformance_cases, run_conformance, CancelAcceptance, ConformanceCase, ConformancePeerFactory,
    ConformanceScenario, ConnectionBinding, NdjsonCodec, PeerDescriptor, PeerEventSink,
    ProtocolCapabilities, ProtocolError, ProtocolFrame, ProtocolPeer, ProtocolTrustTier,
    RunAcceptance, RunCancel, RunStart,
};
use serde_json::json;

#[test]
fn shared_harness_drives_every_case_through_a_deferred_peer() {
    let factory = ScriptedFactory::expected();

    run_conformance(&factory).expect("a deferred peer with the protocol contract passes");

    let case_names: Vec<_> = conformance_cases().iter().map(|case| case.name).collect();
    assert_eq!(
        case_names,
        vec![
            "happy",
            "malicious",
            "slow",
            "cancelled",
            "crashed",
            "malformed",
            "oversize",
            "sequence-gap",
            "duplicate-terminal",
        ]
    );
    let calls = factory.calls();
    assert_eq!(calls.started, conformance_scenarios());
    assert_eq!(calls.cancelled, vec![ConformanceScenario::Cancelled]);
    assert_eq!(calls.connection_losses, vec![ConformanceScenario::Crashed]);
    assert_eq!(
        calls.raw_frames,
        vec![
            ConformanceScenario::Malformed,
            ConformanceScenario::Oversize,
        ]
    );
}

#[test]
fn shared_harness_rejects_events_emitted_before_start_acceptance() {
    let factory = ScriptedFactory::early_happy();

    assert_eq!(
        run_conformance(&factory),
        Err(ProtocolError::InvalidRequest)
    );
    assert_eq!(factory.calls().started, vec![ConformanceScenario::Happy]);
}

#[test]
fn shared_harness_rejects_a_peer_that_never_emits_a_terminal_result() {
    let factory = ScriptedFactory::silent_happy();

    assert_eq!(run_conformance(&factory), Err(ProtocolError::Timeout));
    assert_eq!(factory.calls().started, vec![ConformanceScenario::Happy]);
}

#[derive(Clone, Copy)]
enum FactoryMode {
    Expected,
    EarlyHappy,
    SilentHappy,
}

type ReleaseGate = Arc<(Mutex<bool>, Condvar)>;

struct ScriptedFactory {
    mode: FactoryMode,
    gates: Arc<Mutex<Vec<(ConformanceScenario, ReleaseGate)>>>,
    calls: Arc<Mutex<Calls>>,
}

#[derive(Default, Debug)]
struct Calls {
    started: Vec<ConformanceScenario>,
    cancelled: Vec<ConformanceScenario>,
    connection_losses: Vec<ConformanceScenario>,
    raw_frames: Vec<ConformanceScenario>,
}

impl ScriptedFactory {
    fn expected() -> Self {
        Self::new(FactoryMode::Expected)
    }

    fn early_happy() -> Self {
        Self::new(FactoryMode::EarlyHappy)
    }

    fn silent_happy() -> Self {
        Self::new(FactoryMode::SilentHappy)
    }

    fn new(mode: FactoryMode) -> Self {
        Self {
            mode,
            gates: Arc::new(Mutex::new(Vec::new())),
            calls: Arc::new(Mutex::new(Calls::default())),
        }
    }

    fn calls(&self) -> Calls {
        let calls = self
            .calls
            .lock()
            .expect("test call log lock is not poisoned");
        Calls {
            started: calls.started.clone(),
            cancelled: calls.cancelled.clone(),
            connection_losses: calls.connection_losses.clone(),
            raw_frames: calls.raw_frames.clone(),
        }
    }
}

impl ConformancePeerFactory for ScriptedFactory {
    fn peer_for(&self, case: ConformanceCase) -> Result<Box<dyn ProtocolPeer>, ProtocolError> {
        let gate = Arc::new((Mutex::new(false), Condvar::new()));
        self.gates
            .lock()
            .map_err(|_| ProtocolError::InternalAgentFailure)?
            .push((case.scenario, gate.clone()));
        Ok(Box::new(ScriptedPeer {
            scenario: case.scenario,
            mode: self.mode,
            gate,
            calls: Arc::clone(&self.calls),
            worker: Mutex::new(None),
        }))
    }

    fn start_accepted(&self, case: ConformanceCase) -> Result<(), ProtocolError> {
        let gate = self
            .gates
            .lock()
            .map_err(|_| ProtocolError::InternalAgentFailure)?
            .iter()
            .find(|(scenario, _)| *scenario == case.scenario)
            .map(|(_, gate)| Arc::clone(gate))
            .ok_or(ProtocolError::InternalAgentFailure)?;
        let (released, ready) = &*gate;
        *released
            .lock()
            .map_err(|_| ProtocolError::InternalAgentFailure)? = true;
        ready.notify_all();
        Ok(())
    }
}

struct ScriptedPeer {
    scenario: ConformanceScenario,
    mode: FactoryMode,
    gate: ReleaseGate,
    calls: Arc<Mutex<Calls>>,
    worker: Mutex<Option<JoinHandle<Result<(), ProtocolError>>>>,
}

impl ProtocolPeer for ScriptedPeer {
    fn descriptor(&self) -> PeerDescriptor {
        descriptor()
    }

    fn start(
        &self,
        request: RunStart,
        sink: Box<dyn PeerEventSink>,
    ) -> Result<RunAcceptance, ProtocolError> {
        self.calls
            .lock()
            .map_err(|_| ProtocolError::InternalAgentFailure)?
            .started
            .push(self.scenario);
        let run_id = request.run_id();
        if matches!(self.mode, FactoryMode::EarlyHappy)
            && self.scenario == ConformanceScenario::Happy
        {
            sink.receive(stream_delta(&run_id, 1))?;
        } else if !(matches!(self.mode, FactoryMode::SilentHappy)
            && self.scenario == ConformanceScenario::Happy)
            && !matches!(
                self.scenario,
                ConformanceScenario::Slow | ConformanceScenario::Cancelled
            )
        {
            let scenario = self.scenario;
            let gate = Arc::clone(&self.gate);
            let calls = Arc::clone(&self.calls);
            let worker_run_id = run_id.clone();
            let worker = thread::spawn(move || {
                wait_for_start_acceptance(&gate)?;
                emit_scenario(scenario, &worker_run_id, sink, &calls)
            });
            *self
                .worker
                .lock()
                .map_err(|_| ProtocolError::InternalAgentFailure)? = Some(worker);
        }

        Ok(RunAcceptance {
            run_id,
            accepted: true,
        })
    }

    fn cancel(&self, request: RunCancel) -> Result<CancelAcceptance, ProtocolError> {
        self.calls
            .lock()
            .map_err(|_| ProtocolError::InternalAgentFailure)?
            .cancelled
            .push(self.scenario);
        Ok(CancelAcceptance {
            run_id: request.run_id(),
            accepted: true,
        })
    }

    fn shutdown(&self) -> Result<(), ProtocolError> {
        let worker = self
            .worker
            .lock()
            .map_err(|_| ProtocolError::InternalAgentFailure)?
            .take();
        match worker {
            Some(worker) => worker
                .join()
                .map_err(|_| ProtocolError::InternalAgentFailure)?,
            None => Ok(()),
        }
    }
}

fn emit_scenario(
    scenario: ConformanceScenario,
    run_id: &str,
    sink: Box<dyn PeerEventSink>,
    calls: &Arc<Mutex<Calls>>,
) -> Result<(), ProtocolError> {
    match scenario {
        ConformanceScenario::Happy => {
            sink.receive(stream_delta(run_id, 1))?;
            sink.receive(terminal(run_id, "agent:conformance-complete"))?;
        }
        ConformanceScenario::Malicious => {
            expect_rejection(sink.receive(heartbeat("wrong-connection", 1)))?;
        }
        ConformanceScenario::Crashed => {
            calls
                .lock()
                .map_err(|_| ProtocolError::InternalAgentFailure)?
                .connection_losses
                .push(scenario);
            sink.connection_lost()?;
        }
        ConformanceScenario::Malformed => {
            calls
                .lock()
                .map_err(|_| ProtocolError::InternalAgentFailure)?
                .raw_frames
                .push(scenario);
            expect_rejection(sink.receive_raw(b"{"))?;
            expect_error(
                sink.receive(stream_delta(run_id, 1)),
                ProtocolError::InternalAgentFailure,
            )?;
        }
        ConformanceScenario::Oversize => {
            calls
                .lock()
                .map_err(|_| ProtocolError::InternalAgentFailure)?
                .raw_frames
                .push(scenario);
            expect_rejection(sink.receive_raw(b"{}"))?;
            expect_error(
                sink.receive(stream_delta(run_id, 1)),
                ProtocolError::InternalAgentFailure,
            )?;
        }
        ConformanceScenario::SequenceGap => {
            expect_rejection(sink.receive(stream_delta(run_id, 2)))?;
        }
        ConformanceScenario::DuplicateTerminal => {
            sink.receive(terminal(run_id, "agent:conformance-complete-1"))?;
            expect_rejection(sink.receive(terminal(run_id, "agent:conformance-complete-2")))?;
        }
        ConformanceScenario::Slow | ConformanceScenario::Cancelled => {}
    }
    Ok(())
}

fn expect_rejection(
    result: Result<local_agent_terminal_agent_protocol::InboundDisposition, ProtocolError>,
) -> Result<(), ProtocolError> {
    if result.is_ok() {
        Err(ProtocolError::InternalAgentFailure)
    } else {
        Ok(())
    }
}

fn expect_error(
    result: Result<local_agent_terminal_agent_protocol::InboundDisposition, ProtocolError>,
    expected: ProtocolError,
) -> Result<(), ProtocolError> {
    match result {
        Err(error) if error == expected => Ok(()),
        Ok(_) | Err(_) => Err(ProtocolError::InternalAgentFailure),
    }
}

fn wait_for_start_acceptance(gate: &ReleaseGate) -> Result<(), ProtocolError> {
    let (released, ready) = &**gate;
    let mut released = released
        .lock()
        .map_err(|_| ProtocolError::InternalAgentFailure)?;
    while !*released {
        released = ready
            .wait(released)
            .map_err(|_| ProtocolError::InternalAgentFailure)?;
    }
    Ok(())
}

fn conformance_scenarios() -> Vec<ConformanceScenario> {
    conformance_cases()
        .iter()
        .map(|case| case.scenario)
        .collect()
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

fn heartbeat(connection_id: &str, sequence: u64) -> ProtocolFrame {
    decode(json!({
        "jsonrpc": "2.0",
        "method": "agent.heartbeat",
        "params": { "connectionId": connection_id, "sequence": sequence }
    }))
}

fn terminal(run_id: &str, id: &str) -> ProtocolFrame {
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
