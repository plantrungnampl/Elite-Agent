use std::{
    collections::BTreeSet,
    sync::{Arc, Condvar, Mutex},
    time::Duration,
};

use chrono::{DateTime, TimeZone, Utc};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::{
    ConnectionBinding, InboundDisposition, NdjsonCodec, ProtocolCapabilities, ProtocolError,
    ProtocolFrame, ProtocolOffer, ProtocolSession, SessionLimits,
};

#[derive(Debug, Clone)]
pub struct RunStart {
    frame: ProtocolFrame,
    run_id: String,
    execution_binding: RunExecutionBinding,
}

impl RunStart {
    pub fn new(
        frame: ProtocolFrame,
        execution_binding: RunExecutionBinding,
    ) -> Result<Self, ProtocolError> {
        if !matches!(&frame, ProtocolFrame::RunStartRequest(_)) {
            return Err(ProtocolError::InvalidRequest);
        }
        let run_id = run_id(&frame)?;
        let value = serde_json::to_value(&frame).map_err(|_| ProtocolError::InvalidRequest)?;
        let wire_context_digest = value
            .pointer("/params/contextPackage/contentDigest")
            .and_then(Value::as_str)
            .ok_or(ProtocolError::InvalidRequest)?;
        let wire_supersedes = value
            .pointer("/params/supersedesRunId")
            .and_then(Value::as_str);
        if !execution_binding.is_valid()
            || wire_context_digest != execution_binding.effective_context_digest
            || wire_supersedes != execution_binding.supersedes_run_id.as_deref()
        {
            return Err(ProtocolError::InvalidRequest);
        }
        Ok(Self {
            frame,
            run_id,
            execution_binding,
        })
    }

    pub fn as_frame(&self) -> &ProtocolFrame {
        &self.frame
    }

    pub fn run_id(&self) -> String {
        self.run_id.clone()
    }

    pub fn execution_binding(&self) -> &RunExecutionBinding {
        &self.execution_binding
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunExecutionBinding {
    pub provider_id: String,
    pub model_id: String,
    pub generation_parameters: Vec<u8>,
    pub generation_parameters_digest: String,
    pub effective_context: Vec<u8>,
    pub effective_context_artifact_id: String,
    pub effective_context_digest: String,
    pub supersedes_run_id: Option<String>,
}

impl RunExecutionBinding {
    fn is_valid(&self) -> bool {
        !self.provider_id.trim().is_empty()
            && !self.model_id.trim().is_empty()
            && canonical_json(&self.generation_parameters)
            && digest_matches(
                &self.generation_parameters,
                &self.generation_parameters_digest,
            )
            && !self.effective_context.is_empty()
            && !self.effective_context_artifact_id.trim().is_empty()
            && digest_matches(&self.effective_context, &self.effective_context_digest)
            && self
                .supersedes_run_id
                .as_deref()
                .is_none_or(|run_id| !run_id.trim().is_empty())
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
    fn request(&self, frame: ProtocolFrame) -> Result<ProtocolFrame, ProtocolError>;

    /// Decodes one raw transport frame before it enters the session state machine.
    fn receive_raw(&self, bytes: &[u8]) -> Result<InboundDisposition, ProtocolError>;
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

/// Creates a peer configured to exercise one conformance scenario.
pub trait ConformancePeerFactory: Send + Sync {
    fn peer_for(&self, case: ConformanceCase) -> Result<Box<dyn ProtocolPeer>, ProtocolError>;

    /// Releases peers that defer events until the start acceptance is recorded.
    fn start_accepted(&self, _case: ConformanceCase) -> Result<(), ProtocolError> {
        Ok(())
    }
}

/// Runs every shared scenario against peers produced by `factory`.
pub fn run_conformance(factory: &dyn ConformancePeerFactory) -> Result<(), ProtocolError> {
    for case in conformance_cases() {
        let peer = factory.peer_for(*case)?;
        let descriptor = peer.descriptor();
        let result = if descriptor.protocol_version == "1.0" {
            run_case(peer.as_ref(), factory, &descriptor, *case)
        } else {
            Err(ProtocolError::ProtocolIncompatible)
        };
        let shutdown_result = peer.shutdown();
        result?;
        shutdown_result?;
    }
    Ok(())
}

fn run_case(
    peer: &dyn ProtocolPeer,
    factory: &dyn ConformancePeerFactory,
    descriptor: &PeerDescriptor,
    case: ConformanceCase,
) -> Result<(), ProtocolError> {
    let sink = start_case(peer, factory, descriptor, case)?;
    match case.scenario {
        ConformanceScenario::Happy => sink.wait_for_happy_events(),
        ConformanceScenario::Malicious => {
            sink.wait_for_error(ProtocolError::IdentityBindingFailed, false)
        }
        ConformanceScenario::Slow => match sink.trigger_timeout() {
            Err(ProtocolError::Timeout) => sink.wait_for_error(ProtocolError::Timeout, false),
            _ => Err(ProtocolError::InternalAgentFailure),
        },
        ConformanceScenario::Cancelled => run_cancelled(peer, &sink),
        ConformanceScenario::Crashed => {
            sink.wait_for_error(ProtocolError::InternalAgentFailure, true)
        }
        ConformanceScenario::Malformed => sink.wait_for_error(ProtocolError::InvalidJson, true),
        ConformanceScenario::Oversize => {
            sink.wait_for_error(ProtocolError::FrameTooLarge { max_frame_bytes: 1 }, true)
        }
        ConformanceScenario::SequenceGap | ConformanceScenario::DuplicateTerminal => {
            sink.wait_for_error(ProtocolError::InvalidRequest, false)
        }
    }
}

fn start_case(
    peer: &dyn ProtocolPeer,
    factory: &dyn ConformancePeerFactory,
    descriptor: &PeerDescriptor,
    case: ConformanceCase,
) -> Result<ConformanceSink, ProtocolError> {
    let (session, start) = pending_session(descriptor)?;
    let sink = ConformanceSink::new(session, conformance_codec(case.scenario));
    let acceptance = peer.start(
        RunStart::new(start, conformance_execution_binding())?,
        Box::new(sink.clone()),
    )?;
    if !acceptance.accepted || acceptance.run_id != "conformance-run" {
        return Err(ProtocolError::InternalAgentFailure);
    }
    if let Some(error) = sink.error()? {
        return Err(error);
    }
    sink.accept_start()?;
    factory.start_accepted(case)?;
    Ok(sink)
}

fn run_cancelled(peer: &dyn ProtocolPeer, sink: &ConformanceSink) -> Result<(), ProtocolError> {
    let cancel = cancel("conformance-run", "core:conformance-cancel", 10)?;
    sink.outbound(cancel.clone())?;
    let acceptance = peer.cancel(RunCancel::try_from(cancel)?)?;
    if acceptance.accepted && acceptance.run_id == "conformance-run" {
        Ok(())
    } else {
        Err(ProtocolError::Cancelled)
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

fn pending_session(
    descriptor: &PeerDescriptor,
) -> Result<(ProtocolSession, ProtocolFrame), ProtocolError> {
    let now = conformance_time();
    let mut session = initialized_session(descriptor)?;
    let start = start("conformance-run")?;
    session.outbound(start.clone(), now)?;
    Ok((session, start))
}

#[derive(Clone)]
struct ConformanceSink {
    session: Arc<Mutex<ProtocolSession>>,
    codec: NdjsonCodec,
    observations: Arc<(Mutex<ConformanceObservations>, Condvar)>,
}

#[derive(Default)]
struct ConformanceObservations {
    saw_stream: bool,
    saw_terminal: bool,
    error: Option<ProtocolError>,
    connection_lost: bool,
}

impl ConformanceSink {
    fn new(session: ProtocolSession, codec: NdjsonCodec) -> Self {
        Self {
            session: Arc::new(Mutex::new(session)),
            codec,
            observations: Arc::new((
                Mutex::new(ConformanceObservations::default()),
                Condvar::new(),
            )),
        }
    }

    fn accept_start(&self) -> Result<(), ProtocolError> {
        let result = self
            .session
            .lock()
            .map_err(|_| ProtocolError::InternalAgentFailure)?
            .receive_response(
                success_response(
                    "core:conformance-start",
                    json!({ "accepted": true, "runId": "conformance-run" }),
                )?,
                conformance_time(),
            );
        if let Err(error) = result {
            self.record_error(error)?;
            return Err(error);
        }
        Ok(())
    }

    fn outbound(&self, frame: ProtocolFrame) -> Result<(), ProtocolError> {
        let result = self
            .session
            .lock()
            .map_err(|_| ProtocolError::InternalAgentFailure)?
            .outbound(frame, conformance_time());
        if let Err(error) = result {
            self.record_error(error)?;
            return Err(error);
        }
        Ok(())
    }

    fn trigger_timeout(&self) -> Result<(), ProtocolError> {
        let result = self
            .session
            .lock()
            .map_err(|_| ProtocolError::InternalAgentFailure)?
            .check_timeouts(conformance_time() + chrono::Duration::seconds(6));
        if let Err(error) = result {
            self.record_error(error)?;
            return Err(error);
        }
        Ok(())
    }

    fn error(&self) -> Result<Option<ProtocolError>, ProtocolError> {
        let (observations, _) = &*self.observations;
        Ok(observations
            .lock()
            .map_err(|_| ProtocolError::InternalAgentFailure)?
            .error)
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

    fn wait_for_error(
        &self,
        expected: ProtocolError,
        requires_connection_loss: bool,
    ) -> Result<(), ProtocolError> {
        let (observations, ready) = &*self.observations;
        let observations = observations
            .lock()
            .map_err(|_| ProtocolError::InternalAgentFailure)?;
        let (observations, _) = ready
            .wait_timeout_while(observations, Duration::from_millis(100), |observations| {
                observations.error.is_none()
            })
            .map_err(|_| ProtocolError::InternalAgentFailure)?;
        match observations.error {
            Some(error)
                if error == expected
                    && (!requires_connection_loss || observations.connection_lost) =>
            {
                Ok(())
            }
            Some(error) => Err(error),
            None => Err(ProtocolError::Timeout),
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
        observations.error.get_or_insert(error);
        ready.notify_all();
        Ok(())
    }

    fn close_connection(&self) -> Result<(), ProtocolError> {
        self.session
            .lock()
            .map_err(|_| ProtocolError::InternalAgentFailure)?
            .connection_lost();
        let (observations, ready) = &*self.observations;
        observations
            .lock()
            .map_err(|_| ProtocolError::InternalAgentFailure)?
            .connection_lost = true;
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

    fn receive_raw(&self, bytes: &[u8]) -> Result<InboundDisposition, ProtocolError> {
        match self.codec.decode(bytes) {
            Ok(frame) => self.receive(frame),
            Err(error) => {
                self.close_connection()?;
                self.record_error(error)?;
                Err(error)
            }
        }
    }

    fn request(&self, request_frame: ProtocolFrame) -> Result<ProtocolFrame, ProtocolError> {
        let disposition = self.receive(request_frame.clone())?;
        if !matches!(disposition, InboundDisposition::Request(_)) {
            return Err(ProtocolError::InvalidRequest);
        }
        let value =
            serde_json::to_value(&request_frame).map_err(|_| ProtocolError::InvalidRequest)?;
        let request_id = frame_request_id(&value)?;
        let response = match request_frame {
            ProtocolFrame::ContextQueryRequest(_) => success_response(
                request_id,
                json!({
                    "supplementId": "ctx-conformance-supplement",
                    "contentDigest": "sha256:ea7792a26f405e2ae9c6f49ca93bbe6076ceac0a1fc53d83426c7d7f2d9377e4",
                    "items": ["artifact-context-1"],
                    "provenance": [],
                    "redactions": [],
                    "policyDecisionIds": ["policy-conformance-1"]
                }),
            )?,
            ProtocolFrame::SpecialistRequest(_) => success_response(
                request_id,
                json!({
                    "requestId": request_id,
                    "accepted": true,
                    "reasonCode": "specialist_approved"
                }),
            )?,
            ProtocolFrame::RunCompleteRequest(_) => {
                success_response(request_id, json!({ "accepted": true }))?
            }
            ProtocolFrame::ToolRequest(_) => frame(json!({
                "jsonrpc": "2.0",
                "id": request_id,
                "error": {
                    "code": -32600,
                    "message": "request rejected",
                    "data": { "category": "policy_denied", "retryable": false }
                }
            }))?,
            _ => return Err(ProtocolError::InvalidRequest),
        };
        validate_conformance_response(&value, &response)?;
        self.outbound(response.clone())?;
        Ok(response)
    }

    fn connection_lost(&self) -> Result<(), ProtocolError> {
        self.close_connection()?;
        self.record_error(ProtocolError::InternalAgentFailure)?;
        Ok(())
    }
}

fn validate_conformance_response(
    request: &Value,
    response: &ProtocolFrame,
) -> Result<(), ProtocolError> {
    let response = serde_json::to_value(response).map_err(|_| ProtocolError::InvalidRequest)?;
    if response.get("id").and_then(Value::as_str) != request.get("id").and_then(Value::as_str) {
        return Err(ProtocolError::InvalidRequest);
    }
    match request.get("method").and_then(Value::as_str) {
        Some("context.query")
            if response
                .pointer("/result/supplementId")
                .and_then(Value::as_str)
                .is_some()
                && response
                    .pointer("/result/contentDigest")
                    .and_then(Value::as_str)
                    .is_some()
                && response
                    .pointer("/result/items")
                    .and_then(Value::as_array)
                    .is_some()
                && response
                    .pointer("/result/provenance")
                    .and_then(Value::as_array)
                    .is_some()
                && response
                    .pointer("/result/redactions")
                    .and_then(Value::as_array)
                    .is_some()
                && response
                    .pointer("/result/policyDecisionIds")
                    .and_then(Value::as_array)
                    .is_some() =>
        {
            Ok(())
        }
        Some("specialist.request")
            if response
                .pointer("/result/requestId")
                .and_then(Value::as_str)
                == request.get("id").and_then(Value::as_str)
                && response
                    .pointer("/result/accepted")
                    .and_then(Value::as_bool)
                    .is_some()
                && response
                    .pointer("/result/reasonCode")
                    .and_then(Value::as_str)
                    .is_some() =>
        {
            Ok(())
        }
        Some("tool.request") if response.pointer("/error/data/category").is_some() => Ok(()),
        Some("agent.run.complete")
            if response
                .pointer("/result/accepted")
                .and_then(Value::as_bool)
                == Some(true) =>
        {
            Ok(())
        }
        _ => Err(ProtocolError::InvalidRequest),
    }
}

fn conformance_codec(scenario: ConformanceScenario) -> NdjsonCodec {
    match scenario {
        ConformanceScenario::Oversize => NdjsonCodec::new(1),
        ConformanceScenario::Happy
        | ConformanceScenario::Malicious
        | ConformanceScenario::Slow
        | ConformanceScenario::Cancelled
        | ConformanceScenario::Crashed
        | ConformanceScenario::Malformed
        | ConformanceScenario::SequenceGap
        | ConformanceScenario::DuplicateTerminal => NdjsonCodec::default(),
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

fn frame_request_id(value: &Value) -> Result<&str, ProtocolError> {
    value
        .get("id")
        .and_then(Value::as_str)
        .ok_or(ProtocolError::InvalidRequest)
}

fn valid_digest(value: &str) -> bool {
    value.len() == 71
        && value.starts_with("sha256:")
        && value[7..]
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn canonical_json(bytes: &[u8]) -> bool {
    serde_json::from_slice::<Value>(bytes)
        .ok()
        .and_then(|value| serde_json_canonicalizer::to_vec(&value).ok())
        .is_some_and(|canonical| canonical == bytes)
}

fn digest_matches(bytes: &[u8], digest: &str) -> bool {
    valid_digest(digest) && format!("sha256:{:x}", Sha256::digest(bytes)) == digest
}

fn conformance_execution_binding() -> RunExecutionBinding {
    RunExecutionBinding {
        provider_id: "conformance-provider".to_owned(),
        model_id: "conformance-model".to_owned(),
        generation_parameters: b"{}".to_vec(),
        generation_parameters_digest:
            "sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a".to_owned(),
        effective_context: b"conformance context".to_vec(),
        effective_context_artifact_id: "artifact-conformance-context".to_owned(),
        effective_context_digest:
            "sha256:cf5515229a79d1eeed0c2281346c68418af289215570fe3135a624217bec0c29".to_owned(),
        supersedes_run_id: None,
    }
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
                "contentDigest": "sha256:cf5515229a79d1eeed0c2281346c68418af289215570fe3135a624217bec0c29",
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
