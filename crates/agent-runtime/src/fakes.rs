use std::sync::{Arc, Mutex};

use local_agent_terminal_agent_protocol::{
    CancelAcceptance, ConformanceCase, ConformancePeerFactory, ConformanceScenario,
    InboundDisposition, NdjsonCodec, PeerDescriptor, PeerEventSink, ProtocolError, ProtocolFrame,
    ProtocolPeer, RunAcceptance, RunCancel, RunStart,
};
use serde_json::{json, Value};

use crate::runtime::MAX_OUTPUT_BYTES;

pub type ScriptLog = Arc<Mutex<Vec<&'static str>>>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Script {
    Proposer,
    Critic,
    Verifier,
    Requesting,
    Malicious(MaliciousScript),
    Slow,
    Crashing,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MaliciousScript {
    MalformedFrame,
    WrongConnection,
    WrongRun,
    DuplicateTerminal,
    ConflictingTerminal,
    SequenceGap,
    OversizeFrame,
    OversizeOutput,
}

#[derive(Clone)]
pub struct ScriptedPeer {
    inner: Arc<ScriptedPeerInner>,
}

struct ScriptedPeerInner {
    script: Script,
    descriptor: PeerDescriptor,
    pending: Mutex<Option<PendingRun>>,
    start_requests: Mutex<Vec<RunStart>>,
    request_responses: Mutex<Vec<ProtocolFrame>>,
    outputs: Mutex<Vec<String>>,
    duplicate_stream_deltas: Mutex<usize>,
    terminal_acknowledgements: Mutex<usize>,
    cancel_count: Mutex<usize>,
    shutdown: Mutex<bool>,
    log: ScriptLog,
}

struct PendingRun {
    request_id: String,
    run_id: String,
    context_digest: String,
    sink: Box<dyn PeerEventSink>,
}

impl ScriptedPeer {
    pub fn new(script: Script, descriptor: PeerDescriptor) -> Self {
        Self::with_log(script, descriptor, Arc::new(Mutex::new(Vec::new())))
    }

    pub fn with_log(script: Script, descriptor: PeerDescriptor, log: ScriptLog) -> Self {
        Self {
            inner: Arc::new(ScriptedPeerInner {
                script,
                descriptor,
                pending: Mutex::new(None),
                start_requests: Mutex::new(Vec::new()),
                request_responses: Mutex::new(Vec::new()),
                outputs: Mutex::new(Vec::new()),
                duplicate_stream_deltas: Mutex::new(0),
                terminal_acknowledgements: Mutex::new(0),
                cancel_count: Mutex::new(0),
                shutdown: Mutex::new(false),
                log,
            }),
        }
    }

    pub fn drive(&self) -> Result<(), ProtocolError> {
        let pending = self
            .inner
            .pending
            .lock()
            .map_err(|_| ProtocolError::InternalAgentFailure)?
            .take()
            .ok_or(ProtocolError::InvalidRequest)?;
        match self.inner.script {
            Script::Proposer => self.emit_success(pending, "proposer"),
            Script::Critic => self.emit_success(pending, "critic"),
            Script::Verifier => self.emit_success(pending, "verifier"),
            Script::Requesting => self.emit_requests(pending),
            Script::Slow => {
                *self
                    .inner
                    .pending
                    .lock()
                    .map_err(|_| ProtocolError::InternalAgentFailure)? = Some(pending);
                Ok(())
            }
            Script::Crashing => pending.sink.connection_lost(),
            Script::Malicious(script) => self.emit_malicious(pending, script),
        }
    }

    pub fn outputs(&self) -> Vec<String> {
        self.inner.outputs.lock().expect("script log lock").clone()
    }

    pub fn start_requests(&self) -> Vec<RunStart> {
        self.inner
            .start_requests
            .lock()
            .expect("script request lock")
            .clone()
    }

    pub fn request_responses(&self) -> Vec<ProtocolFrame> {
        self.inner
            .request_responses
            .lock()
            .expect("script response lock")
            .clone()
    }

    pub fn duplicate_stream_deltas(&self) -> usize {
        *self
            .inner
            .duplicate_stream_deltas
            .lock()
            .expect("script count lock")
    }

    pub fn terminal_acknowledgements(&self) -> usize {
        *self
            .inner
            .terminal_acknowledgements
            .lock()
            .expect("script count lock")
    }

    pub fn cancel_count(&self) -> usize {
        *self.inner.cancel_count.lock().expect("script count lock")
    }

    pub fn was_shutdown(&self) -> bool {
        *self.inner.shutdown.lock().expect("script state lock")
    }

    fn emit_success(&self, pending: PendingRun, role: &str) -> Result<(), ProtocolError> {
        let output = format!("{role}:{}:{}", pending.request_id, pending.context_digest);
        self.inner
            .outputs
            .lock()
            .map_err(|_| ProtocolError::InternalAgentFailure)?
            .push(output.clone());
        let delta = stream_delta(&pending.run_id, 1, "ok")?;
        pending.sink.receive(delta.clone())?;
        if matches!(
            pending.sink.receive(delta)?,
            InboundDisposition::DuplicateStreamDelta
        ) {
            *self
                .inner
                .duplicate_stream_deltas
                .lock()
                .map_err(|_| ProtocolError::InternalAgentFailure)? += 1;
        }
        self.acknowledge_terminal(&pending, terminal(&pending, "succeeded", &output, "one")?)
    }

    fn emit_malicious(
        &self,
        pending: PendingRun,
        script: MaliciousScript,
    ) -> Result<(), ProtocolError> {
        match script {
            MaliciousScript::MalformedFrame => expect_rejected(pending.sink.receive_raw(b"{")),
            MaliciousScript::WrongConnection => {
                expect_rejected(pending.sink.receive(heartbeat("wrong-connection", 1)?))
            }
            MaliciousScript::WrongRun => {
                expect_rejected(pending.sink.receive(stream_delta("wrong-run", 1, "bad")?))
            }
            MaliciousScript::SequenceGap => expect_rejected(pending.sink.receive(stream_delta(
                &pending.run_id,
                2,
                "gap",
            )?)),
            MaliciousScript::OversizeFrame => expect_rejected(pending.sink.receive_raw(b"{}")),
            MaliciousScript::OversizeOutput => expect_rejected(pending.sink.receive(stream_delta(
                &pending.run_id,
                1,
                &"x".repeat(MAX_OUTPUT_BYTES + 1),
            )?)),
            MaliciousScript::DuplicateTerminal => {
                let terminal = terminal(&pending, "succeeded", "done", "one")?;
                self.acknowledge_terminal(&pending, terminal.clone())?;
                expect_request_rejected(pending.sink.request(terminal))
            }
            MaliciousScript::ConflictingTerminal => {
                self.acknowledge_terminal(
                    &pending,
                    terminal(&pending, "succeeded", "done", "one")?,
                )?;
                expect_request_rejected(pending.sink.request(terminal(
                    &pending,
                    "failed",
                    "different",
                    "two",
                )?))
            }
        }
    }

    fn acknowledge_terminal(
        &self,
        pending: &PendingRun,
        frame: ProtocolFrame,
    ) -> Result<(), ProtocolError> {
        pending.sink.request(frame)?;
        *self
            .inner
            .terminal_acknowledgements
            .lock()
            .map_err(|_| ProtocolError::InternalAgentFailure)? += 1;
        self.inner
            .log
            .lock()
            .map_err(|_| ProtocolError::InternalAgentFailure)?
            .push("peer.terminal.acknowledged");
        Ok(())
    }

    fn emit_requests(&self, pending: PendingRun) -> Result<(), ProtocolError> {
        let frames = [
            context_query(&pending.run_id)?,
            tool_request(&pending.run_id)?,
            specialist_request(&pending.run_id)?,
        ];
        let mut responses = Vec::with_capacity(frames.len());
        for frame in frames {
            responses.push(pending.sink.request(frame)?);
        }
        self.inner
            .request_responses
            .lock()
            .map_err(|_| ProtocolError::InternalAgentFailure)?
            .extend(responses);
        Ok(())
    }
}

impl ProtocolPeer for ScriptedPeer {
    fn descriptor(&self) -> PeerDescriptor {
        self.inner.descriptor.clone()
    }

    fn start(
        &self,
        request: RunStart,
        sink: Box<dyn PeerEventSink>,
    ) -> Result<RunAcceptance, ProtocolError> {
        self.inner
            .start_requests
            .lock()
            .map_err(|_| ProtocolError::InternalAgentFailure)?
            .push(request.clone());
        let value = frame_value(request.as_frame())?;
        let request_id = required_string(&value, "/id")?;
        let context_digest = required_string(&value, "/params/contextPackage/contentDigest")?;
        let run_id = request.run_id();
        let mut pending = self
            .inner
            .pending
            .lock()
            .map_err(|_| ProtocolError::InternalAgentFailure)?;
        if pending.is_some() {
            return Err(ProtocolError::InvalidRequest);
        }
        *pending = Some(PendingRun {
            request_id,
            run_id: run_id.clone(),
            context_digest,
            sink,
        });
        Ok(RunAcceptance {
            run_id,
            accepted: true,
        })
    }

    fn cancel(&self, request: RunCancel) -> Result<CancelAcceptance, ProtocolError> {
        *self
            .inner
            .cancel_count
            .lock()
            .map_err(|_| ProtocolError::InternalAgentFailure)? += 1;
        if !matches!(self.inner.script, Script::Slow | Script::Malicious(_)) {
            let pending = self
                .inner
                .pending
                .lock()
                .map_err(|_| ProtocolError::InternalAgentFailure)?
                .take();
            if let Some(pending) = pending {
                self.acknowledge_terminal(
                    &pending,
                    terminal(&pending, "cancelled_cleanly", "cancelled", "cancel")?,
                )?;
            }
        }
        Ok(CancelAcceptance {
            run_id: request.run_id(),
            accepted: true,
        })
    }

    fn shutdown(&self) -> Result<(), ProtocolError> {
        *self
            .inner
            .shutdown
            .lock()
            .map_err(|_| ProtocolError::InternalAgentFailure)? = true;
        Ok(())
    }
}

pub struct ScriptedPeerFactory {
    descriptor: PeerDescriptor,
    peers: Mutex<Vec<(ConformanceScenario, ScriptedPeer)>>,
}

impl ScriptedPeerFactory {
    pub fn new(descriptor: PeerDescriptor) -> Self {
        Self {
            descriptor,
            peers: Mutex::new(Vec::new()),
        }
    }
}

impl ConformancePeerFactory for ScriptedPeerFactory {
    fn peer_for(&self, case: ConformanceCase) -> Result<Box<dyn ProtocolPeer>, ProtocolError> {
        let script = match case.scenario {
            ConformanceScenario::Happy => Script::Proposer,
            ConformanceScenario::Malicious => Script::Malicious(MaliciousScript::WrongConnection),
            ConformanceScenario::Slow => Script::Slow,
            ConformanceScenario::Cancelled => Script::Slow,
            ConformanceScenario::Crashed => Script::Crashing,
            ConformanceScenario::Malformed => Script::Malicious(MaliciousScript::MalformedFrame),
            ConformanceScenario::Oversize => Script::Malicious(MaliciousScript::OversizeFrame),
            ConformanceScenario::SequenceGap => Script::Malicious(MaliciousScript::SequenceGap),
            ConformanceScenario::DuplicateTerminal => {
                Script::Malicious(MaliciousScript::DuplicateTerminal)
            }
        };
        let peer = ScriptedPeer::new(script, self.descriptor.clone());
        self.peers
            .lock()
            .map_err(|_| ProtocolError::InternalAgentFailure)?
            .push((case.scenario, peer.clone()));
        Ok(Box::new(peer))
    }

    fn start_accepted(&self, case: ConformanceCase) -> Result<(), ProtocolError> {
        let peer = self
            .peers
            .lock()
            .map_err(|_| ProtocolError::InternalAgentFailure)?
            .iter()
            .find(|(scenario, _)| *scenario == case.scenario)
            .map(|(_, peer)| peer.clone())
            .ok_or(ProtocolError::InternalAgentFailure)?;
        peer.drive()
    }
}

fn terminal(
    pending: &PendingRun,
    status: &str,
    content: &str,
    suffix: &str,
) -> Result<ProtocolFrame, ProtocolError> {
    decode(json!({
        "jsonrpc": "2.0",
        "id": format!("agent:{suffix}"),
        "method": "agent.run.complete",
        "params": {
            "runId": pending.run_id,
            "status": status,
            "message": {
                "messageId": format!("message-{}-{suffix}", pending.run_id),
                "type": "answer",
                "content": content,
                "claims": []
            },
            "usage": { "inputTokens": 1, "outputTokens": 1, "providerReportedCost": 0.0 }
        }
    }))
}

fn stream_delta(run_id: &str, sequence: u64, delta: &str) -> Result<ProtocolFrame, ProtocolError> {
    decode(json!({
        "jsonrpc": "2.0",
        "method": "agent.stream.delta",
        "params": { "runId": run_id, "sequence": sequence, "channel": "content", "delta": delta }
    }))
}

fn heartbeat(connection_id: &str, sequence: u64) -> Result<ProtocolFrame, ProtocolError> {
    decode(json!({
        "jsonrpc": "2.0",
        "method": "agent.heartbeat",
        "params": { "connectionId": connection_id, "sequence": sequence }
    }))
}

fn context_query(run_id: &str) -> Result<ProtocolFrame, ProtocolError> {
    decode(json!({
        "jsonrpc": "2.0",
        "id": "agent:context-1",
        "method": "context.query",
        "params": {
            "runId": run_id,
            "queryId": "query-1",
            "query": "More context",
            "scopes": ["repository"],
            "maxItems": 1,
            "maxTokens": 1
        }
    }))
}

fn tool_request(run_id: &str) -> Result<ProtocolFrame, ProtocolError> {
    decode(json!({
        "jsonrpc": "2.0",
        "id": "agent:tool-1",
        "method": "tool.request",
        "params": {
            "runId": run_id,
            "requestId": "tool-1",
            "planStepId": "step-1",
            "executorFencingToken": null,
            "tool": "git.diff",
            "arguments": {},
            "reason": "Verify"
        }
    }))
}

fn specialist_request(run_id: &str) -> Result<ProtocolFrame, ProtocolError> {
    decode(json!({
        "jsonrpc": "2.0",
        "id": "agent:specialist-1",
        "method": "specialist.request",
        "params": {
            "runId": run_id,
            "capability": "review",
            "reason": "Need review",
            "requiredContext": []
        }
    }))
}

fn decode(value: Value) -> Result<ProtocolFrame, ProtocolError> {
    NdjsonCodec::default()
        .decode(&serde_json::to_vec(&value).map_err(|_| ProtocolError::InternalAgentFailure)?)
}

fn frame_value(frame: &ProtocolFrame) -> Result<Value, ProtocolError> {
    serde_json::to_value(frame).map_err(|_| ProtocolError::InvalidRequest)
}

fn required_string(value: &Value, pointer: &str) -> Result<String, ProtocolError> {
    value
        .pointer(pointer)
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or(ProtocolError::InvalidRequest)
}

fn expect_rejected(result: Result<InboundDisposition, ProtocolError>) -> Result<(), ProtocolError> {
    if result.is_err() {
        Ok(())
    } else {
        Err(ProtocolError::InternalAgentFailure)
    }
}

fn expect_request_rejected(
    result: Result<ProtocolFrame, ProtocolError>,
) -> Result<(), ProtocolError> {
    if result.is_err() {
        Ok(())
    } else {
        Err(ProtocolError::InternalAgentFailure)
    }
}
