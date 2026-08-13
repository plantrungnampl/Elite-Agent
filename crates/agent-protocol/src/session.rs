use std::{
    collections::{BTreeSet, HashMap},
    time::Duration,
};

use chrono::{DateTime, Duration as ChronoDuration, Utc};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

use crate::{codec::validate_response_for_method, ProtocolError, ProtocolFrame};

const STREAM_DELTA_CAPABILITY: &str = "agent.stream.delta";
const CONTEXT_QUERY_CAPABILITY: &str = "context.query";
const TOOL_REQUEST_CAPABILITY: &str = "tool.request";
const SPECIALIST_REQUEST_CAPABILITY: &str = "specialist.request";
const MAX_PENDING_REQUESTS: usize = 128;
const STREAM_HIGH_WATERMARK: usize = 512;
const STREAM_LOW_WATERMARK: usize = 256;
const CANCEL_TIMEOUT_SECONDS: i64 = 30;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectionBinding {
    pub connection_id: String,
    pub agent_id: String,
    pub manifest_digest: String,
    pub executable_digest: String,
    pub trust_tier: ProtocolTrustTier,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtocolTrustTier {
    CoreAdapter,
    BrokeredProcess,
    IsolatedWorker,
    FullAccessLegacy,
}

impl ProtocolTrustTier {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CoreAdapter => "core_adapter",
            Self::BrokeredProcess => "brokered_process",
            Self::IsolatedWorker => "isolated_worker",
            Self::FullAccessLegacy => "full_access_legacy",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtocolCapabilities {
    pub roles: BTreeSet<String>,
    pub skills: BTreeSet<String>,
    pub streaming: bool,
    pub context_query: bool,
    pub tool_requests: bool,
    pub specialist_requests: bool,
    pub max_concurrent_runs: u64,
    pub max_context_tokens: u64,
}

impl ProtocolCapabilities {
    pub fn advertised(&self) -> BTreeSet<String> {
        let mut capabilities = BTreeSet::new();
        if self.streaming {
            capabilities.insert(STREAM_DELTA_CAPABILITY.to_owned());
        }
        if self.context_query {
            capabilities.insert(CONTEXT_QUERY_CAPABILITY.to_owned());
        }
        if self.tool_requests {
            capabilities.insert(TOOL_REQUEST_CAPABILITY.to_owned());
        }
        if self.specialist_requests {
            capabilities.insert(SPECIALIST_REQUEST_CAPABILITY.to_owned());
        }
        capabilities
    }

    fn permits(&self, selected: &BTreeSet<String>) -> bool {
        selected.is_subset(&self.advertised())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtocolOffer {
    pub protocol_versions: BTreeSet<String>,
    pub capabilities: ProtocolCapabilities,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionLimits {
    pub max_output_bytes: usize,
    pub heartbeat_timeout: Duration,
}

#[derive(Debug, Clone)]
pub enum InboundDisposition {
    Request(ProtocolFrame),
    ReplayRequest(ProtocolFrame),
    Notification(ProtocolFrame),
    DuplicateStreamDelta,
}

pub struct ProtocolSession {
    binding: ConnectionBinding,
    connection_binding_digest: String,
    offer: ProtocolOffer,
    limits: SessionLimits,
    pending_responses: HashMap<String, PendingRequest>,
    completed_requests: HashMap<String, PendingRequest>,
    runs: HashMap<String, RunRecord>,
    negotiated: bool,
    initialized: bool,
    requested_capabilities: Option<BTreeSet<String>>,
    selected_capabilities: Option<BTreeSet<String>>,
    last_heartbeat_sequence: Option<u64>,
    last_heartbeat_at: DateTime<Utc>,
    connection_lost: bool,
}

#[derive(Clone)]
struct PendingRequest {
    connection_id: String,
    method: String,
    digest: String,
    origin: RequestOrigin,
    run_id: Option<String>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum RequestOrigin {
    Core,
    Agent,
}

struct RunRecord {
    accepted: bool,
    stream_heads: HashMap<String, StreamHead>,
    output_bytes: usize,
    terminal: bool,
    cancellation_deadline: Option<DateTime<Utc>>,
    buffered_stream_frames: usize,
    stream_backpressured: bool,
}

struct StreamHead {
    last_sequence: u64,
    last_delta: Option<Vec<u8>>,
}

impl ProtocolSession {
    pub fn new(
        binding: ConnectionBinding,
        offer: ProtocolOffer,
        limits: SessionLimits,
        opened_at: DateTime<Utc>,
    ) -> Self {
        let connection_binding_digest = binding_digest(&binding);
        Self::new_with_binding_digest(binding, connection_binding_digest, offer, limits, opened_at)
    }

    pub fn new_with_binding_digest(
        binding: ConnectionBinding,
        connection_binding_digest: String,
        offer: ProtocolOffer,
        limits: SessionLimits,
        opened_at: DateTime<Utc>,
    ) -> Self {
        Self {
            binding,
            connection_binding_digest,
            offer,
            limits,
            pending_responses: HashMap::new(),
            completed_requests: HashMap::new(),
            runs: HashMap::new(),
            negotiated: false,
            initialized: false,
            requested_capabilities: None,
            selected_capabilities: None,
            last_heartbeat_sequence: None,
            last_heartbeat_at: opened_at,
            connection_lost: false,
        }
    }

    pub fn outbound(
        &mut self,
        frame: ProtocolFrame,
        at: DateTime<Utc>,
    ) -> Result<(), ProtocolError> {
        self.ensure_connected()?;
        let value = frame_value(&frame)?;
        if is_response(&value) {
            return self.outbound_response(&value);
        }

        match frame {
            ProtocolFrame::InitializeRequest(_) => self.outbound_initialize(&value),
            ProtocolFrame::InitializedNotification(_) => self.outbound_initialized(&value),
            ProtocolFrame::RunStartRequest(_) => self.outbound_run_start(&value),
            ProtocolFrame::RunCancelRequest(_) => self.outbound_run_cancel(&value, at),
            ProtocolFrame::ShutdownRequest(_) => self.outbound_shutdown(&value),
            ProtocolFrame::ExitNotification(_) => self.outbound_exit(),
            ProtocolFrame::RunCompleteRequest(_)
            | ProtocolFrame::StreamDeltaNotification(_)
            | ProtocolFrame::ContextQueryRequest(_)
            | ProtocolFrame::ToolRequest(_)
            | ProtocolFrame::SpecialistRequest(_)
            | ProtocolFrame::HeartbeatNotification(_) => Err(ProtocolError::InvalidRequest),
            _ => Err(ProtocolError::InvalidRequest),
        }
    }

    /// Restores one durable core request that is still awaiting a response.
    ///
    /// Restoration only updates session correlation state; it does not dispatch the frame. An
    /// exact pending replay is idempotent, while a request ID with different durable identity is
    /// rejected as a protocol conflict.
    pub fn restore_pending_request(
        &mut self,
        frame: ProtocolFrame,
        at: DateTime<Utc>,
    ) -> Result<(), ProtocolError> {
        self.ensure_connected()?;
        let value = frame_value(&frame)?;
        let method = match &frame {
            ProtocolFrame::InitializeRequest(_) => "initialize",
            ProtocolFrame::RunStartRequest(_) => "agent.run.start",
            ProtocolFrame::RunCancelRequest(_) => "agent.run.cancel",
            ProtocolFrame::ShutdownRequest(_) => "shutdown",
            ProtocolFrame::InitializedNotification(_)
            | ProtocolFrame::ExitNotification(_)
            | ProtocolFrame::RunCompleteRequest(_)
            | ProtocolFrame::StreamDeltaNotification(_)
            | ProtocolFrame::ContextQueryRequest(_)
            | ProtocolFrame::ToolRequest(_)
            | ProtocolFrame::SpecialistRequest(_)
            | ProtocolFrame::HeartbeatNotification(_) => return Err(ProtocolError::InvalidRequest),
            _ => return Err(ProtocolError::InvalidRequest),
        };
        let id = request_id(&value)?;
        if !is_core_id(id) {
            return Err(ProtocolError::InvalidRequest);
        }
        let digest = request_digest(&value)?;
        if self.request_replays(id, method, &digest, RequestOrigin::Core)? {
            return self
                .pending_responses
                .contains_key(id)
                .then_some(())
                .ok_or(ProtocolError::ProtocolConflict);
        }

        self.outbound(frame, at)
    }

    pub fn receive_response(
        &mut self,
        frame: ProtocolFrame,
        _at: DateTime<Utc>,
    ) -> Result<(), ProtocolError> {
        self.validate_response(&frame)?;
        let value = frame_value(&frame)?;
        let id = request_id(&value)?;
        let pending = self.pending_core_response(&value)?;

        if pending.method == "initialize" && value.get("result").is_some() {
            self.selected_capabilities = Some(self.validate_initialize_response(&value)?);
            self.negotiated = true;
        }
        if pending.method == "agent.run.start" && value.get("result").is_some() {
            self.accept_run_start(
                &value,
                pending
                    .run_id
                    .clone()
                    .ok_or(ProtocolError::InvalidRequest)?,
            )?;
        }
        self.complete_request(id, pending);
        Ok(())
    }

    /// Validates a core response without completing correlation or changing negotiated/run state.
    pub fn validate_response(&self, frame: &ProtocolFrame) -> Result<(), ProtocolError> {
        self.ensure_connected()?;
        let value = frame_value(frame)?;
        let pending = self.pending_core_response(&value)?;
        validate_response_for_method(&value, &pending.method)?;

        if pending.method == "initialize" && value.get("result").is_some() {
            self.validate_initialize_response(&value)?;
        }
        if pending.method == "agent.run.start" && value.get("result").is_some() {
            self.validate_run_start_response(
                &value,
                pending
                    .run_id
                    .as_deref()
                    .ok_or(ProtocolError::InvalidRequest)?,
            )?;
        }
        Ok(())
    }

    /// Validates a response to an agent-originated request without completing correlation.
    pub fn validate_outbound_response(&self, frame: &ProtocolFrame) -> Result<(), ProtocolError> {
        self.ensure_connected()?;
        let value = frame_value(frame)?;
        self.validate_outbound_response_value(&value)
    }

    fn validate_outbound_response_value(&self, value: &Value) -> Result<(), ProtocolError> {
        let id = request_id(value)?;
        if !is_agent_id(id) {
            return Err(ProtocolError::InvalidRequest);
        }
        let pending = self
            .pending_responses
            .get(id)
            .ok_or(ProtocolError::InvalidRequest)?;
        if pending.origin != RequestOrigin::Agent
            || pending.connection_id != self.binding.connection_id
        {
            return Err(ProtocolError::InvalidRequest);
        }
        validate_response_for_method(value, &pending.method)
    }

    pub fn receive(
        &mut self,
        frame: ProtocolFrame,
        at: DateTime<Utc>,
    ) -> Result<InboundDisposition, ProtocolError> {
        self.ensure_connected()?;
        if !self.initialized {
            return Err(ProtocolError::InvalidRequest);
        }
        let value = frame_value(&frame)?;

        match frame {
            ProtocolFrame::RunCompleteRequest(_) => {
                let id = agent_request_id(&value)?;
                let digest = request_digest(&value)?;
                if self.request_replays(id, "agent.run.complete", &digest, RequestOrigin::Agent)? {
                    return Ok(InboundDisposition::ReplayRequest(frame));
                }
                let run_id = run_id_from_value(&value)?;
                self.active_run(&run_id)?;
                self.insert_request(
                    id,
                    "agent.run.complete",
                    digest,
                    RequestOrigin::Agent,
                    Some(run_id.clone()),
                )?;
                self.active_run_mut(&run_id)?.terminal = true;
                Ok(InboundDisposition::Request(frame))
            }
            ProtocolFrame::ContextQueryRequest(_) => {
                self.require_capability(CONTEXT_QUERY_CAPABILITY)?;
                self.receive_agent_request_for_active_run(&value, "context.query", frame)
            }
            ProtocolFrame::ToolRequest(_) => {
                self.require_capability(TOOL_REQUEST_CAPABILITY)?;
                self.receive_agent_request_for_active_run(&value, "tool.request", frame)
            }
            ProtocolFrame::SpecialistRequest(_) => {
                self.require_capability(SPECIALIST_REQUEST_CAPABILITY)?;
                self.receive_agent_request_for_active_run(&value, "specialist.request", frame)
            }
            ProtocolFrame::StreamDeltaNotification(_) => {
                self.require_capability(STREAM_DELTA_CAPABILITY)?;
                if self.receive_stream_delta(&value)? {
                    Ok(InboundDisposition::DuplicateStreamDelta)
                } else {
                    Ok(InboundDisposition::Notification(frame))
                }
            }
            ProtocolFrame::HeartbeatNotification(_) => {
                self.receive_heartbeat(&value, at)?;
                Ok(InboundDisposition::Notification(frame))
            }
            ProtocolFrame::InitializeRequest(_)
            | ProtocolFrame::InitializedNotification(_)
            | ProtocolFrame::RunStartRequest(_)
            | ProtocolFrame::RunCancelRequest(_)
            | ProtocolFrame::ShutdownRequest(_)
            | ProtocolFrame::ExitNotification(_) => Err(ProtocolError::InvalidRequest),
            _ => Err(ProtocolError::InvalidRequest),
        }
    }

    pub fn check_timeouts(&mut self, at: DateTime<Utc>) -> Result<(), ProtocolError> {
        self.ensure_connected()?;
        let heartbeat_timeout = ChronoDuration::from_std(self.limits.heartbeat_timeout)
            .map_err(|_| ProtocolError::Timeout)?;
        if at.signed_duration_since(self.last_heartbeat_at) >= heartbeat_timeout {
            self.close_active_runs();
            return Err(ProtocolError::Timeout);
        }

        if self.runs.values_mut().any(|run| {
            !run.terminal
                && run
                    .cancellation_deadline
                    .is_some_and(|deadline| at >= deadline)
        }) {
            self.close_active_runs();
            return Err(ProtocolError::Timeout);
        }
        Ok(())
    }

    pub fn connection_lost(&mut self) -> Vec<String> {
        if self.connection_lost {
            return Vec::new();
        }
        self.connection_lost = true;
        let mut interrupted = self
            .runs
            .iter_mut()
            .filter_map(|(run_id, run)| {
                (run.accepted && !run.terminal).then(|| {
                    run.terminal = true;
                    run_id.clone()
                })
            })
            .collect::<Vec<_>>();
        interrupted.sort();
        interrupted
    }

    pub fn acknowledge_stream(
        &mut self,
        run_id: &str,
        count: usize,
    ) -> Result<bool, ProtocolError> {
        let run = self
            .runs
            .get_mut(run_id)
            .ok_or(ProtocolError::InvalidRequest)?;
        if count > run.buffered_stream_frames {
            return Err(ProtocolError::InvalidRequest);
        }
        run.buffered_stream_frames -= count;
        if run.stream_backpressured && run.buffered_stream_frames <= STREAM_LOW_WATERMARK {
            run.stream_backpressured = false;
        }
        Ok(run.stream_backpressured)
    }

    pub fn stream_backpressured(&self, run_id: &str) -> Result<bool, ProtocolError> {
        self.runs
            .get(run_id)
            .map(|run| run.stream_backpressured)
            .ok_or(ProtocolError::InvalidRequest)
    }

    /// Restores a durable stream position before the next delta arrives.
    ///
    /// The durable protocol store records sequence heads but not delta bytes. A repeated restored
    /// sequence is therefore rejected rather than accepted as an unverifiable duplicate.
    pub fn restore_stream_head(
        &mut self,
        run_id: &str,
        channel: &str,
        sequence: u64,
    ) -> Result<(), ProtocolError> {
        if !matches!(channel, "content" | "status" | "telemetry") || sequence == 0 {
            return Err(ProtocolError::InvalidRequest);
        }
        let run = self.active_run_mut(run_id)?;
        if run.stream_heads.contains_key(channel) {
            return Err(ProtocolError::InvalidRequest);
        }
        run.stream_heads.insert(
            channel.to_owned(),
            StreamHead {
                last_sequence: sequence,
                last_delta: None,
            },
        );
        Ok(())
    }

    fn outbound_response(&mut self, value: &Value) -> Result<(), ProtocolError> {
        self.validate_outbound_response_value(value)?;
        let id = request_id(value)?;
        let pending = self
            .pending_responses
            .get(id)
            .cloned()
            .ok_or(ProtocolError::InvalidRequest)?;
        self.complete_request(id, pending);
        Ok(())
    }

    fn outbound_initialize(&mut self, value: &Value) -> Result<(), ProtocolError> {
        if self.negotiated || self.initialized || !self.limits_are_valid() {
            return Err(ProtocolError::InvalidRequest);
        }
        let params = params(value)?;
        let versions = string_set(params, "protocolVersions")?;
        if !versions.contains("2.0") || !versions.is_subset(&self.offer.protocol_versions) {
            return Err(ProtocolError::ProtocolIncompatible);
        }
        let capabilities = string_set(params, "capabilities")?;
        if !self.offer.capabilities.permits(&capabilities)
            || required_str(params, "connectionBindingDigest")? != self.connection_binding_digest
        {
            return Err(ProtocolError::ProtocolIncompatible);
        }
        self.register_core_request(value, "initialize")?;
        self.requested_capabilities = Some(capabilities);
        Ok(())
    }

    fn outbound_initialized(&mut self, value: &Value) -> Result<(), ProtocolError> {
        if !self.negotiated || self.initialized {
            return Err(ProtocolError::InvalidRequest);
        }
        if required_str(params(value)?, "connectionId")? != self.binding.connection_id {
            return Err(ProtocolError::IdentityBindingFailed);
        }
        self.initialized = true;
        Ok(())
    }

    fn outbound_run_start(&mut self, value: &Value) -> Result<(), ProtocolError> {
        if !self.initialized {
            return Err(ProtocolError::InvalidRequest);
        }
        let run_id = run_id_from_value(value)?;
        if self.runs.contains_key(&run_id) {
            return Err(ProtocolError::InvalidRequest);
        }
        self.register_core_request(value, "agent.run.start")?;
        self.runs.insert(
            run_id,
            RunRecord {
                accepted: false,
                stream_heads: HashMap::new(),
                output_bytes: 0,
                terminal: false,
                cancellation_deadline: None,
                buffered_stream_frames: 0,
                stream_backpressured: false,
            },
        );
        Ok(())
    }

    fn outbound_run_cancel(
        &mut self,
        value: &Value,
        at: DateTime<Utc>,
    ) -> Result<(), ProtocolError> {
        let run_id = run_id_from_value(value)?;
        self.active_run(&run_id)?;
        self.register_core_request(value, "agent.run.cancel")?;
        let timeout = ChronoDuration::seconds(CANCEL_TIMEOUT_SECONDS);
        let deadline = at
            .checked_add_signed(timeout)
            .ok_or(ProtocolError::Timeout)?;
        self.runs
            .get_mut(&run_id)
            .ok_or(ProtocolError::InvalidRequest)?
            .cancellation_deadline = Some(deadline);
        Ok(())
    }

    fn outbound_shutdown(&mut self, value: &Value) -> Result<(), ProtocolError> {
        self.register_core_request(value, "shutdown")
    }

    fn outbound_exit(&self) -> Result<(), ProtocolError> {
        self.pending_responses
            .values()
            .any(|pending| pending.method == "shutdown")
            .then_some(())
            .map_or(Ok(()), |_| Err(ProtocolError::InvalidRequest))
    }

    fn validate_initialize_response(
        &self,
        value: &Value,
    ) -> Result<BTreeSet<String>, ProtocolError> {
        let result = object_field(
            value.as_object().ok_or(ProtocolError::InvalidRequest)?,
            "result",
        )?;
        if required_str(result, "protocolVersion")? != "2.0"
            || !self.offer.protocol_versions.contains("2.0")
            || required_str(result, "connectionId")? != self.binding.connection_id
        {
            return Err(ProtocolError::ProtocolIncompatible);
        }
        let selected = string_set(result, "capabilities")?;
        if !self.offer.capabilities.permits(&selected)
            || !selected.is_subset(
                self.requested_capabilities
                    .as_ref()
                    .ok_or(ProtocolError::InvalidRequest)?,
            )
        {
            return Err(ProtocolError::ProtocolIncompatible);
        }
        let limits = object_field(result, "limits")?;
        if required_u64(limits, "maxFrameBytes")? != crate::DEFAULT_MAX_FRAME_BYTES as u64
            || required_u64(limits, "maxPendingRequests")? != MAX_PENDING_REQUESTS as u64
            || required_u64(limits, "streamHighWatermark")? != STREAM_HIGH_WATERMARK as u64
            || required_u64(limits, "streamLowWatermark")? != STREAM_LOW_WATERMARK as u64
        {
            return Err(ProtocolError::ProtocolIncompatible);
        }
        Ok(selected)
    }

    fn pending_core_response(&self, value: &Value) -> Result<PendingRequest, ProtocolError> {
        if !is_response(value) {
            return Err(ProtocolError::InvalidRequest);
        }
        let id = request_id(value)?;
        if !is_core_id(id) {
            return Err(ProtocolError::InvalidRequest);
        }
        let pending = self
            .pending_responses
            .get(id)
            .cloned()
            .ok_or(ProtocolError::InvalidRequest)?;
        if pending.origin != RequestOrigin::Core
            || pending.connection_id != self.binding.connection_id
        {
            return Err(ProtocolError::InvalidRequest);
        }
        Ok(pending)
    }

    fn validate_run_start_response(
        &self,
        value: &Value,
        expected_run_id: &str,
    ) -> Result<(), ProtocolError> {
        let result = object_field(
            value.as_object().ok_or(ProtocolError::InvalidRequest)?,
            "result",
        )?;
        if required_bool(result, "accepted")?
            && required_str(result, "runId")? == expected_run_id
            && self.runs.contains_key(expected_run_id)
        {
            Ok(())
        } else {
            Err(ProtocolError::InvalidRequest)
        }
    }

    fn accept_run_start(
        &mut self,
        value: &Value,
        expected_run_id: String,
    ) -> Result<(), ProtocolError> {
        self.validate_run_start_response(value, &expected_run_id)?;
        self.runs
            .get_mut(&expected_run_id)
            .ok_or(ProtocolError::InvalidRequest)?
            .accepted = true;
        Ok(())
    }

    fn receive_agent_request_for_active_run(
        &mut self,
        value: &Value,
        method: &str,
        frame: ProtocolFrame,
    ) -> Result<InboundDisposition, ProtocolError> {
        let id = agent_request_id(value)?;
        let digest = request_digest(value)?;
        if self.request_replays(id, method, &digest, RequestOrigin::Agent)? {
            return Ok(InboundDisposition::ReplayRequest(frame));
        }
        let run_id = run_id_from_value(value)?;
        self.active_run(&run_id)?;
        self.insert_request(id, method, digest, RequestOrigin::Agent, Some(run_id))?;
        Ok(InboundDisposition::Request(frame))
    }

    fn receive_stream_delta(&mut self, value: &Value) -> Result<bool, ProtocolError> {
        let params = params(value)?;
        let run_id = required_str(params, "runId")?.to_owned();
        let channel = required_str(params, "channel")?;
        let sequence = required_u64(params, "sequence")?;
        let delta = required_str(params, "delta")?.as_bytes();
        let max_output_bytes = self.limits.max_output_bytes;
        let high_watermark = STREAM_HIGH_WATERMARK;
        let run = self.active_run_mut(&run_id)?;

        let invalid_sequence = match run.stream_heads.get(channel) {
            None => sequence != 1,
            Some(StreamHead {
                last_sequence,
                last_delta: Some(last_delta),
            }) if sequence == *last_sequence => {
                if last_delta == delta {
                    return Ok(true);
                }
                true
            }
            Some(StreamHead { last_sequence, .. }) if sequence == *last_sequence => true,
            Some(StreamHead { last_sequence, .. }) => {
                last_sequence.checked_add(1) != Some(sequence)
            }
        };
        if invalid_sequence {
            run.terminal = true;
            return Err(ProtocolError::InvalidRequest);
        }

        let output_bytes = run
            .output_bytes
            .checked_add(delta.len())
            .ok_or(ProtocolError::OutputLimitExceeded)?;
        if output_bytes > max_output_bytes {
            run.terminal = true;
            return Err(ProtocolError::OutputLimitExceeded);
        }
        run.stream_heads.insert(
            channel.to_owned(),
            StreamHead {
                last_sequence: sequence,
                last_delta: Some(delta.to_vec()),
            },
        );
        run.output_bytes = output_bytes;
        run.buffered_stream_frames = run
            .buffered_stream_frames
            .checked_add(1)
            .ok_or(ProtocolError::InvalidRequest)?;
        if run.buffered_stream_frames >= high_watermark {
            run.stream_backpressured = true;
        }
        Ok(false)
    }

    fn receive_heartbeat(&mut self, value: &Value, at: DateTime<Utc>) -> Result<(), ProtocolError> {
        let params = params(value)?;
        if required_str(params, "connectionId")? != self.binding.connection_id {
            return Err(ProtocolError::IdentityBindingFailed);
        }
        let sequence = required_u64(params, "sequence")?;
        if self
            .last_heartbeat_sequence
            .is_some_and(|previous| sequence <= previous)
        {
            return Err(ProtocolError::InvalidRequest);
        }
        self.last_heartbeat_sequence = Some(sequence);
        self.last_heartbeat_at = at;
        Ok(())
    }

    fn register_core_request(&mut self, value: &Value, method: &str) -> Result<(), ProtocolError> {
        let id = request_id(value)?;
        if !is_core_id(id) {
            return Err(ProtocolError::InvalidRequest);
        }
        let digest = request_digest(value)?;
        if self.request_replays(id, method, &digest, RequestOrigin::Core)? {
            return Err(ProtocolError::ProtocolConflict);
        }
        self.insert_request(
            id,
            method,
            digest,
            RequestOrigin::Core,
            run_id_from_value(value).ok(),
        )
    }

    fn request_replays(
        &self,
        id: &str,
        method: &str,
        digest: &str,
        origin: RequestOrigin,
    ) -> Result<bool, ProtocolError> {
        if let Some(existing) = self
            .pending_responses
            .get(id)
            .or_else(|| self.completed_requests.get(id))
        {
            return (existing.connection_id == self.binding.connection_id
                && existing.method == method
                && existing.digest == digest
                && existing.origin == origin)
                .then_some(true)
                .ok_or(ProtocolError::ProtocolConflict);
        }
        Ok(false)
    }

    fn insert_request(
        &mut self,
        id: &str,
        method: &str,
        digest: String,
        origin: RequestOrigin,
        run_id: Option<String>,
    ) -> Result<(), ProtocolError> {
        if self.pending_responses.len() >= MAX_PENDING_REQUESTS {
            return Err(ProtocolError::PendingLimitExceeded);
        }
        self.pending_responses.insert(
            id.to_owned(),
            PendingRequest {
                connection_id: self.binding.connection_id.clone(),
                method: method.to_owned(),
                digest,
                origin,
                run_id,
            },
        );
        Ok(())
    }

    fn complete_request(&mut self, id: &str, pending: PendingRequest) {
        self.pending_responses.remove(id);
        self.completed_requests.insert(id.to_owned(), pending);
    }

    fn active_run(&self, run_id: &str) -> Result<&RunRecord, ProtocolError> {
        let run = self.runs.get(run_id).ok_or(ProtocolError::InvalidRequest)?;
        if !run.accepted || run.terminal {
            return Err(ProtocolError::InvalidRequest);
        }
        Ok(run)
    }

    fn active_run_mut(&mut self, run_id: &str) -> Result<&mut RunRecord, ProtocolError> {
        let run = self
            .runs
            .get_mut(run_id)
            .ok_or(ProtocolError::InvalidRequest)?;
        if !run.accepted || run.terminal {
            return Err(ProtocolError::InvalidRequest);
        }
        Ok(run)
    }

    fn close_active_runs(&mut self) {
        for run in self.runs.values_mut() {
            if run.accepted {
                run.terminal = true;
            }
        }
    }

    fn ensure_connected(&self) -> Result<(), ProtocolError> {
        (!self.connection_lost)
            .then_some(())
            .ok_or(ProtocolError::InternalAgentFailure)
    }

    fn require_capability(&self, capability: &str) -> Result<(), ProtocolError> {
        self.selected_capabilities
            .as_ref()
            .is_some_and(|capabilities| capabilities.contains(capability))
            .then_some(())
            .ok_or(ProtocolError::InvalidRequest)
    }

    fn limits_are_valid(&self) -> bool {
        MAX_PENDING_REQUESTS > 0
            && STREAM_HIGH_WATERMARK > 0
            && STREAM_LOW_WATERMARK < STREAM_HIGH_WATERMARK
    }
}

fn frame_value(frame: &ProtocolFrame) -> Result<Value, ProtocolError> {
    serde_json::to_value(frame).map_err(|_| ProtocolError::InvalidRequest)
}

fn is_response(value: &Value) -> bool {
    value.get("method").is_none() && (value.get("result").is_some() || value.get("error").is_some())
}

fn request_id(value: &Value) -> Result<&str, ProtocolError> {
    value
        .get("id")
        .and_then(Value::as_str)
        .ok_or(ProtocolError::InvalidRequest)
}

fn agent_request_id(value: &Value) -> Result<&str, ProtocolError> {
    let id = request_id(value)?;
    is_agent_id(id)
        .then_some(id)
        .ok_or(ProtocolError::InvalidRequest)
}

fn params(value: &Value) -> Result<&Map<String, Value>, ProtocolError> {
    value
        .get("params")
        .and_then(Value::as_object)
        .ok_or(ProtocolError::InvalidRequest)
}

fn object_field<'a>(
    object: &'a Map<String, Value>,
    field: &str,
) -> Result<&'a Map<String, Value>, ProtocolError> {
    object
        .get(field)
        .and_then(Value::as_object)
        .ok_or(ProtocolError::InvalidRequest)
}

fn required_str<'a>(object: &'a Map<String, Value>, field: &str) -> Result<&'a str, ProtocolError> {
    object
        .get(field)
        .and_then(Value::as_str)
        .ok_or(ProtocolError::InvalidRequest)
}

fn required_u64(object: &Map<String, Value>, field: &str) -> Result<u64, ProtocolError> {
    object
        .get(field)
        .and_then(Value::as_u64)
        .ok_or(ProtocolError::InvalidRequest)
}

fn required_bool(object: &Map<String, Value>, field: &str) -> Result<bool, ProtocolError> {
    object
        .get(field)
        .and_then(Value::as_bool)
        .ok_or(ProtocolError::InvalidRequest)
}

fn string_set(object: &Map<String, Value>, field: &str) -> Result<BTreeSet<String>, ProtocolError> {
    object
        .get(field)
        .and_then(Value::as_array)
        .ok_or(ProtocolError::InvalidRequest)?
        .iter()
        .map(|value| {
            value
                .as_str()
                .map(str::to_owned)
                .ok_or(ProtocolError::InvalidRequest)
        })
        .collect()
}

fn run_id_from_value(value: &Value) -> Result<String, ProtocolError> {
    required_str(params(value)?, "runId").map(str::to_owned)
}

fn request_digest(value: &Value) -> Result<String, ProtocolError> {
    let canonical =
        serde_json_canonicalizer::to_vec(value).map_err(|_| ProtocolError::InvalidRequest)?;
    Ok(format!("sha256:{:x}", Sha256::digest(canonical)))
}

/// Returns the RFC 8785 digest used for durable request correlation.
pub fn canonical_request_digest(frame: &ProtocolFrame) -> Result<String, ProtocolError> {
    request_digest(&frame_value(frame)?)
}

pub(crate) fn binding_digest(binding: &ConnectionBinding) -> String {
    let value = serde_json::json!({
        "connectionId": binding.connection_id,
        "agentId": binding.agent_id,
        "manifestDigest": binding.manifest_digest,
        "executableDigest": binding.executable_digest,
        "trustTier": binding.trust_tier.as_str(),
    });
    request_digest(&value).expect("connection binding must canonicalize")
}

fn is_core_id(id: &str) -> bool {
    id.starts_with("core:")
}

fn is_agent_id(id: &str) -> bool {
    id.starts_with("agent:")
}
