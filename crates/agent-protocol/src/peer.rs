use std::{
    collections::BTreeSet,
    sync::{Arc, Condvar, Mutex},
    time::Duration,
};

use chrono::{DateTime, TimeZone, Utc};
use serde_json::{json, Value};

use crate::{
    ConnectionBinding, InboundDisposition, NdjsonCodec, ProtocolCapabilities, ProtocolError,
    ProtocolFrame, ProtocolOffer, ProtocolSession, SessionLimits,
};

#[derive(Debug, Clone)]
pub struct RunStart {
    frame: ProtocolFrame,
    run_id: String,
}

impl RunStart {
    pub fn as_frame(&self) -> &ProtocolFrame {
        &self.frame
    }

    pub fn run_id(&self) -> String {
        self.run_id.clone()
    }
}

impl TryFrom<ProtocolFrame> for RunStart {
    type Error = ProtocolError;

    fn try_from(frame: ProtocolFrame) -> Result<Self, Self::Error> {
        if !matches!(&frame, ProtocolFrame::RunStartRequest(_)) {
            return Err(ProtocolError::InvalidRequest);
        }
        Ok(Self {
            run_id: run_id(&frame)?,
            frame,
        })
    }
}

#[derive(Debug, Clone)]
pub struct RunCancel {
    frame: ProtocolFrame,
    run_id: String,
}

impl RunCancel {
    pub fn as_frame(&self) -> &ProtocolFrame {
        &self.frame
    }

    pub fn run_id(&self) -> String {
        self.run_id.clone()
    }
}

impl TryFrom<ProtocolFrame> for RunCancel {
    type Error = ProtocolError;

    fn try_from(frame: ProtocolFrame) -> Result<Self, Self::Error> {
        if !matches!(&frame, ProtocolFrame::RunCancelRequest(_)) {
            return Err(ProtocolError::InvalidRequest);
        }
        Ok(Self {
            run_id: run_id(&frame)?,
            frame,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunAcceptance {
    pub run_id: String,
    pub accepted: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CancelAcceptance {
    pub run_id: String,
    pub accepted: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerDescriptor {
    pub binding: ConnectionBinding,
    pub protocol_version: String,
    pub capabilities: ProtocolCapabilities,
}

pub trait PeerEventSink: Send + Sync {
    fn receive(&self, frame: ProtocolFrame) -> Result<InboundDisposition, ProtocolError>;
    fn connection_lost(&self) -> Result<(), ProtocolError>;
}

pub trait ProtocolPeer: Send + Sync {
    fn descriptor(&self) -> PeerDescriptor;
    fn start(
        &self,
        request: RunStart,
        sink: Box<dyn PeerEventSink>,
    ) -> Result<RunAcceptance, ProtocolError>;
    fn cancel(&self, request: RunCancel) -> Result<CancelAcceptance, ProtocolError>;
    fn shutdown(&self) -> Result<(), ProtocolError>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConformanceScenario {
    Happy,
    Malicious,
    Slow,
    Cancelled,
    Crashed,
    Malformed,
    Oversize,
    SequenceGap,
    DuplicateTerminal,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConformanceCase {
    pub name: &'static str,
    pub scenario: ConformanceScenario,
}

const CONFORMANCE_CASES: [ConformanceCase; 9] = [
    ConformanceCase {
        name: "happy",
        scenario: ConformanceScenario::Happy,
    },
    ConformanceCase {
        name: "malicious",
        scenario: ConformanceScenario::Malicious,
    },
    ConformanceCase {
        name: "slow",
        scenario: ConformanceScenario::Slow,
    },
    ConformanceCase {
        name: "cancelled",
        scenario: ConformanceScenario::Cancelled,
    },
    ConformanceCase {
        name: "crashed",
        scenario: ConformanceScenario::Crashed,
    },
    ConformanceCase {
        name: "malformed",
        scenario: ConformanceScenario::Malformed,
    },
    ConformanceCase {
        name: "oversize",
        scenario: ConformanceScenario::Oversize,
    },
    ConformanceCase {
        name: "sequence-gap",
        scenario: ConformanceScenario::SequenceGap,
    },
    ConformanceCase {
        name: "duplicate-terminal",
        scenario: ConformanceScenario::DuplicateTerminal,
    },
];

pub fn conformance_cases() -> &'static [ConformanceCase] {
    &CONFORMANCE_CASES
}

pub fn run_conformance(peer: &dyn ProtocolPeer) -> Result<(), ProtocolError> {
    let descriptor = peer.descriptor();
    if descriptor.protocol_version != "1.0" {
        return Err(ProtocolError::ProtocolIncompatible);
    }

    for case in conformance_cases() {
        run_case(peer, &descriptor, case.scenario)?;
    }
    peer.shutdown()
}

fn run_case(
    peer: &dyn ProtocolPeer,
    descriptor: &PeerDescriptor,
    scenario: ConformanceScenario,
) -> Result<(), ProtocolError> {
    match scenario {
        ConformanceScenario::Happy => run_happy(peer, descriptor),
        ConformanceScenario::Malicious => run_malicious(descriptor),
        ConformanceScenario::Slow => run_slow(descriptor),
        ConformanceScenario::Cancelled => run_cancelled(peer, descriptor),
        ConformanceScenario::Crashed => run_crashed(descriptor),
        ConformanceScenario::Malformed => run_malformed(),
        ConformanceScenario::Oversize => run_oversize(),
        ConformanceScenario::SequenceGap => run_sequence_gap(descriptor),
        ConformanceScenario::DuplicateTerminal => run_duplicate_terminal(descriptor),
    }
}

fn run_happy(peer: &dyn ProtocolPeer, descriptor: &PeerDescriptor) -> Result<(), ProtocolError> {
    let (session, start) = active_session(descriptor)?;
    let sink = ConformanceSink::new(session);
    let acceptance = peer.start(RunStart::try_from(start)?, Box::new(sink.clone()))?;
    if !acceptance.accepted || acceptance.run_id != "conformance-run" {
        return Err(ProtocolError::InternalAgentFailure);
    }
    sink.wait_for_happy_events()
}

fn run_malicious(descriptor: &PeerDescriptor) -> Result<(), ProtocolError> {
    let mut session = initialized_session(descriptor)?;
    match session.receive(heartbeat("wrong-connection", 1)?, conformance_time()) {
        Err(ProtocolError::IdentityBindingFailed) => Ok(()),
        _ => Err(ProtocolError::InternalAgentFailure),
    }
}

fn run_slow(descriptor: &PeerDescriptor) -> Result<(), ProtocolError> {
    let mut session = initialized_session(descriptor)?;
    match session.check_timeouts(conformance_time() + chrono::Duration::seconds(6)) {
        Err(ProtocolError::Timeout) => Ok(()),
        _ => Err(ProtocolError::InternalAgentFailure),
    }
}

fn run_cancelled(
    peer: &dyn ProtocolPeer,
    descriptor: &PeerDescriptor,
) -> Result<(), ProtocolError> {
    let (mut session, _) = active_session(descriptor)?;
    let cancel = cancel("conformance-run", "core:conformance-cancel", 10)?;
    session.outbound(cancel.clone(), conformance_time())?;
    let acceptance = peer.cancel(RunCancel::try_from(cancel)?)?;
    if acceptance.accepted && acceptance.run_id == "conformance-run" {
        Ok(())
    } else {
        Err(ProtocolError::Cancelled)
    }
}

fn run_crashed(descriptor: &PeerDescriptor) -> Result<(), ProtocolError> {
    let (mut session, _) = active_session(descriptor)?;
    if session.connection_lost() == ["conformance-run"] {
        Ok(())
    } else {
        Err(ProtocolError::InternalAgentFailure)
    }
}

fn run_malformed() -> Result<(), ProtocolError> {
    if NdjsonCodec::default().decode(b"{").is_err() {
        Ok(())
    } else {
        Err(ProtocolError::InternalAgentFailure)
    }
}

fn run_oversize() -> Result<(), ProtocolError> {
    match NdjsonCodec::new(1).decode(b"{}") {
        Err(ProtocolError::FrameTooLarge { .. }) => Ok(()),
        _ => Err(ProtocolError::InternalAgentFailure),
    }
}

fn run_sequence_gap(descriptor: &PeerDescriptor) -> Result<(), ProtocolError> {
    let (mut session, _) = active_session(descriptor)?;
    match session.receive(
        stream_delta("conformance-run", 2, "gap")?,
        conformance_time(),
    ) {
        Err(ProtocolError::InvalidRequest) => Ok(()),
        _ => Err(ProtocolError::InternalAgentFailure),
    }
}

fn run_duplicate_terminal(descriptor: &PeerDescriptor) -> Result<(), ProtocolError> {
    let (mut session, _) = active_session(descriptor)?;
    session.receive(
        terminal("conformance-run", "agent:conformance-complete-1")?,
        conformance_time(),
    )?;
    match session.receive(
        terminal("conformance-run", "agent:conformance-complete-2")?,
        conformance_time(),
    ) {
        Err(ProtocolError::InvalidRequest) => Ok(()),
        _ => Err(ProtocolError::InternalAgentFailure),
    }
}

fn initialized_session(descriptor: &PeerDescriptor) -> Result<ProtocolSession, ProtocolError> {
    let now = conformance_time();
    let mut session = ProtocolSession::new(
        descriptor.binding.clone(),
        ProtocolOffer {
            protocol_versions: BTreeSet::from([descriptor.protocol_version.clone()]),
            capabilities: descriptor.capabilities.clone(),
        },
        SessionLimits {
            max_output_bytes: 16,
            heartbeat_timeout: std::time::Duration::from_secs(5),
        },
        now,
    );
    session.outbound(initialize(descriptor)?, now)?;
    session.receive_response(initialize_response(descriptor)?, now)?;
    session.outbound(initialized(&descriptor.binding.connection_id)?, now)?;
    Ok(session)
}

fn active_session(
    descriptor: &PeerDescriptor,
) -> Result<(ProtocolSession, ProtocolFrame), ProtocolError> {
    let now = conformance_time();
    let mut session = initialized_session(descriptor)?;
    let start = start("conformance-run")?;
    session.outbound(start.clone(), now)?;
    session.receive_response(
        success_response(
            "core:conformance-start",
            json!({ "accepted": true, "runId": "conformance-run" }),
        )?,
        now,
    )?;
    Ok((session, start))
}

#[derive(Clone)]
struct ConformanceSink {
    session: Arc<Mutex<ProtocolSession>>,
    observations: Arc<(Mutex<ConformanceObservations>, Condvar)>,
}

#[derive(Default)]
struct ConformanceObservations {
    saw_stream: bool,
    saw_terminal: bool,
    error: Option<ProtocolError>,
}

impl ConformanceSink {
    fn new(session: ProtocolSession) -> Self {
        Self {
            session: Arc::new(Mutex::new(session)),
            observations: Arc::new((
                Mutex::new(ConformanceObservations::default()),
                Condvar::new(),
            )),
        }
    }

    fn wait_for_happy_events(&self) -> Result<(), ProtocolError> {
        let (observations, ready) = &*self.observations;
        let observations = observations
            .lock()
            .map_err(|_| ProtocolError::InternalAgentFailure)?;
        let (observations, _) = ready
            .wait_timeout_while(observations, Duration::from_millis(100), |observations| {
                observations.error.is_none()
                    && !(observations.saw_stream && observations.saw_terminal)
            })
            .map_err(|_| ProtocolError::InternalAgentFailure)?;
        if let Some(error) = observations.error {
            Err(error)
        } else if observations.saw_stream && observations.saw_terminal {
            Ok(())
        } else {
            Err(ProtocolError::Timeout)
        }
    }

    fn record(&self, disposition: &InboundDisposition) -> Result<(), ProtocolError> {
        let (observations, ready) = &*self.observations;
        let mut observations = observations
            .lock()
            .map_err(|_| ProtocolError::InternalAgentFailure)?;
        match disposition {
            InboundDisposition::Notification(ProtocolFrame::StreamDeltaNotification(_)) => {
                observations.saw_stream = true;
            }
            InboundDisposition::Request(ProtocolFrame::RunCompleteRequest(_)) => {
                observations.saw_terminal = true;
            }
            InboundDisposition::Request(_)
            | InboundDisposition::Notification(_)
            | InboundDisposition::DuplicateStreamDelta => {}
        }
        ready.notify_all();
        Ok(())
    }

    fn record_error(&self, error: ProtocolError) -> Result<(), ProtocolError> {
        let (observations, ready) = &*self.observations;
        let mut observations = observations
            .lock()
            .map_err(|_| ProtocolError::InternalAgentFailure)?;
        observations.error = Some(error);
        ready.notify_all();
        Ok(())
    }
}

impl PeerEventSink for ConformanceSink {
    fn receive(&self, frame: ProtocolFrame) -> Result<InboundDisposition, ProtocolError> {
        let result = self
            .session
            .lock()
            .map_err(|_| ProtocolError::InternalAgentFailure)?
            .receive(frame, conformance_time());
        match result {
            Ok(disposition) => {
                self.record(&disposition)?;
                Ok(disposition)
            }
            Err(error) => {
                self.record_error(error)?;
                Err(error)
            }
        }
    }

    fn connection_lost(&self) -> Result<(), ProtocolError> {
        self.session
            .lock()
            .map_err(|_| ProtocolError::InternalAgentFailure)?
            .connection_lost();
        self.record_error(ProtocolError::InternalAgentFailure)?;
        Ok(())
    }
}

fn run_id(frame: &ProtocolFrame) -> Result<String, ProtocolError> {
    serde_json::to_value(frame)
        .map_err(|_| ProtocolError::InvalidRequest)?
        .pointer("/params/runId")
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or(ProtocolError::InvalidRequest)
}

fn initialize(descriptor: &PeerDescriptor) -> Result<ProtocolFrame, ProtocolError> {
    frame(json!({
        "jsonrpc": "2.0",
        "id": "core:conformance-initialize",
        "method": "initialize",
        "params": {
            "protocolVersions": [descriptor.protocol_version],
            "client": { "name": "conformance", "version": "1" },
            "transport": { "type": "stdio-ndjson", "maxFrameBytes": 1024 },
            "features": features(&descriptor.capabilities),
            "launchBinding": {
                "connectionId": descriptor.binding.connection_id,
                "manifestDigest": descriptor.binding.manifest_digest,
                "executableDigest": descriptor.binding.executable_digest,
                "trustTier": descriptor.binding.trust_tier.as_str()
            }
        }
    }))
}

fn initialize_response(descriptor: &PeerDescriptor) -> Result<ProtocolFrame, ProtocolError> {
    success_response(
        "core:conformance-initialize",
        json!({
            "protocolVersion": descriptor.protocol_version,
            "agent": {
                "id": descriptor.binding.agent_id,
                "displayName": "Conformance Peer",
                "implementationVersion": "1"
            },
            "capabilities": capabilities_json(&descriptor.capabilities)
        }),
    )
}

fn initialized(connection_id: &str) -> Result<ProtocolFrame, ProtocolError> {
    frame(json!({
        "jsonrpc": "2.0",
        "method": "initialized",
        "params": {
            "connectionId": connection_id,
            "effectiveCapabilitiesDigest": "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
        }
    }))
}

fn start(run_id: &str) -> Result<ProtocolFrame, ProtocolError> {
    frame(json!({
        "jsonrpc": "2.0",
        "id": "core:conformance-start",
        "method": "agent.run.start",
        "params": {
            "runId": run_id,
            "idempotencyKey": "conformance-key",
            "taskId": "conformance-task",
            "role": "critic",
            "objective": "Conformance check",
            "contextPackage": {
                "packageId": "conformance-context",
                "contentDigest": "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
                "manifestRef": "artifact:conformance-context"
            },
            "permissions": { "contextQuery": true, "toolRequest": true, "writeFiles": false },
            "responseSchema": "agent-message.v1",
            "limits": {
                "deadline": (conformance_time() + chrono::Duration::seconds(30)).to_rfc3339(),
                "maxOutputTokens": 100,
                "maxToolRequests": 1
            }
        }
    }))
}

fn cancel(run_id: &str, id: &str, deadline_ms: u64) -> Result<ProtocolFrame, ProtocolError> {
    frame(json!({
        "jsonrpc": "2.0",
        "id": id,
        "method": "agent.run.cancel",
        "params": { "runId": run_id, "reason": "conformance", "deadlineMs": deadline_ms }
    }))
}

fn stream_delta(run_id: &str, sequence: u64, delta: &str) -> Result<ProtocolFrame, ProtocolError> {
    frame(json!({
        "jsonrpc": "2.0",
        "method": "agent.stream.delta",
        "params": { "runId": run_id, "sequence": sequence, "channel": "content", "delta": delta }
    }))
}

fn heartbeat(connection_id: &str, sequence: u64) -> Result<ProtocolFrame, ProtocolError> {
    frame(json!({
        "jsonrpc": "2.0",
        "method": "agent.heartbeat",
        "params": { "connectionId": connection_id, "sequence": sequence }
    }))
}

fn terminal(run_id: &str, id: &str) -> Result<ProtocolFrame, ProtocolError> {
    frame(json!({
        "jsonrpc": "2.0",
        "id": id,
        "method": "agent.run.complete",
        "params": {
            "runId": run_id,
            "status": "succeeded",
            "message": {
                "messageId": "conformance-message",
                "type": "answer",
                "content": "done",
                "claims": []
            }
        }
    }))
}

fn success_response(id: &str, result: Value) -> Result<ProtocolFrame, ProtocolError> {
    frame(json!({ "jsonrpc": "2.0", "id": id, "result": result }))
}

fn frame(value: Value) -> Result<ProtocolFrame, ProtocolError> {
    NdjsonCodec::default()
        .decode(&serde_json::to_vec(&value).map_err(|_| ProtocolError::InvalidRequest)?)
}

fn features(capabilities: &ProtocolCapabilities) -> Vec<&'static str> {
    let mut features = Vec::new();
    if capabilities.streaming {
        features.push("streaming");
    }
    if capabilities.context_query {
        features.push("context-query");
    }
    if capabilities.tool_requests {
        features.push("tool-request");
    }
    if capabilities.specialist_requests {
        features.push("specialist-request");
    }
    features
}

fn capabilities_json(capabilities: &ProtocolCapabilities) -> Value {
    json!({
        "roles": capabilities.roles,
        "skills": capabilities.skills,
        "streaming": capabilities.streaming,
        "contextQuery": capabilities.context_query,
        "toolRequests": capabilities.tool_requests,
        "specialistRequests": capabilities.specialist_requests,
        "maxConcurrentRuns": capabilities.max_concurrent_runs,
        "maxContextTokens": capabilities.max_context_tokens
    })
}

fn conformance_time() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 7, 23, 13, 20, 0)
        .single()
        .expect("the fixed conformance timestamp is valid")
}
