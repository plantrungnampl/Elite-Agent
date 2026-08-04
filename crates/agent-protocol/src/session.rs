use std::{
    collections::{BTreeSet, HashMap, HashSet},
    time::Duration,
};

use chrono::{DateTime, Duration as ChronoDuration, Utc};
use serde_json::{Map, Value};

use crate::{ProtocolError, ProtocolFrame};

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
    fn permits(&self, selected: &Self) -> bool {
        selected.roles.is_subset(&self.roles)
            && selected.skills.is_subset(&self.skills)
            && (!selected.streaming || self.streaming)
            && (!selected.context_query || self.context_query)
            && (!selected.tool_requests || self.tool_requests)
            && (!selected.specialist_requests || self.specialist_requests)
            && selected.max_concurrent_runs <= self.max_concurrent_runs
            && selected.max_context_tokens <= self.max_context_tokens
    }

    fn allows_feature(&self, feature: &str) -> bool {
        match feature {
            "streaming" => self.streaming,
            "context-query" => self.context_query,
            "tool-request" => self.tool_requests,
            "specialist-request" => self.specialist_requests,
            _ => false,
        }
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
    Notification(ProtocolFrame),
    DuplicateStreamDelta,
}

pub struct ProtocolSession {
    binding: ConnectionBinding,
    offer: ProtocolOffer,
    limits: SessionLimits,
    request_ids: HashSet<String>,
    pending_responses: HashMap<String, PendingResponse>,
    runs: HashMap<String, RunRecord>,
    negotiated: bool,
    initialized: bool,
    selected_capabilities: Option<ProtocolCapabilities>,
    last_heartbeat_sequence: Option<u64>,
    last_heartbeat_at: DateTime<Utc>,
    connection_lost: bool,
}

#[derive(Clone)]
enum PendingResponse {
    Initialize,
    RunStart { run_id: String },
    RunCancel,
    Shutdown,
    AgentRequest,
}

struct RunRecord {
    accepted: bool,
    last_sequence: Option<u64>,
    last_delta: Vec<u8>,
    output_bytes: usize,
    tool_requests: u64,
    max_output_tokens: u64,
    max_tool_requests: u64,
    terminal: bool,
    deadline: DateTime<Utc>,
    cancellation_deadline: Option<DateTime<Utc>>,
}

impl ProtocolSession {
    pub fn new(
        binding: ConnectionBinding,
        offer: ProtocolOffer,
        limits: SessionLimits,
        opened_at: DateTime<Utc>,
    ) -> Self {
        Self {
            binding,
            offer,
            limits,
            request_ids: HashSet::new(),
            pending_responses: HashMap::new(),
            runs: HashMap::new(),
            negotiated: false,
            initialized: false,
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

        match frame {
            ProtocolFrame::SuccessResponse(_) | ProtocolFrame::ErrorResponse(_) => {
                self.outbound_response(&value)
            }
            ProtocolFrame::InitializeRequest(_) => self.outbound_initialize(&value),
            ProtocolFrame::InitializedNotification(_) => self.outbound_initialized(&value),
            ProtocolFrame::RunStartRequest(_) => self.outbound_run_start(&value),
            ProtocolFrame::RunCancelRequest(_) => self.outbound_run_cancel(&value, at),
            ProtocolFrame::ShutdownRequest(_) => self.outbound_shutdown(&value),
            ProtocolFrame::ExitNotification(_) => self.outbound_exit(&value),
            ProtocolFrame::RunCompleteRequest(_)
            | ProtocolFrame::StreamDeltaNotification(_)
            | ProtocolFrame::ContextQueryRequest(_)
            | ProtocolFrame::ToolRequest(_)
            | ProtocolFrame::SpecialistRequest(_)
            | ProtocolFrame::HeartbeatNotification(_) => Err(ProtocolError::InvalidRequest),
        }
    }

    pub fn receive_response(
        &mut self,
        frame: ProtocolFrame,
        _at: DateTime<Utc>,
    ) -> Result<(), ProtocolError> {
        self.ensure_connected()?;
        let is_success = matches!(frame, ProtocolFrame::SuccessResponse(_));
        if !is_success && !matches!(frame, ProtocolFrame::ErrorResponse(_)) {
            return Err(ProtocolError::InvalidRequest);
        }

        let value = frame_value(&frame)?;
        let id = request_id(&value)?;
        if !is_core_id(id) {
            return Err(ProtocolError::InvalidRequest);
        }
        let Some(pending) = self.pending_responses.get(id).cloned() else {
            return Err(ProtocolError::InvalidRequest);
        };
        if matches!(pending, PendingResponse::AgentRequest) {
            return Err(ProtocolError::InvalidRequest);
        }

        match pending {
            PendingResponse::Initialize => {
                if is_success {
                    self.selected_capabilities = Some(self.validate_initialize_response(&value)?);
                    self.negotiated = true;
                }
            }
            PendingResponse::RunStart { run_id } => {
                if is_success {
                    self.accept_run_start(&value, &run_id)?;
                }
            }
            PendingResponse::RunCancel | PendingResponse::Shutdown => {}
            PendingResponse::AgentRequest => return Err(ProtocolError::InvalidRequest),
        }
        self.pending_responses.remove(id);
        Ok(())
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
                self.receive_agent_request(&value, RequestKind::Terminal)?;
                Ok(InboundDisposition::Request(frame))
            }
            ProtocolFrame::ContextQueryRequest(_) => {
                if !self.selected_capabilities()?.context_query {
                    return Err(ProtocolError::InvalidRequest);
                }
                self.receive_agent_request(&value, RequestKind::Context)?;
                Ok(InboundDisposition::Request(frame))
            }
            ProtocolFrame::ToolRequest(_) => {
                if !self.selected_capabilities()?.tool_requests {
                    return Err(ProtocolError::InvalidRequest);
                }
                self.receive_agent_request(&value, RequestKind::Tool)?;
                Ok(InboundDisposition::Request(frame))
            }
            ProtocolFrame::SpecialistRequest(_) => {
                if !self.selected_capabilities()?.specialist_requests {
                    return Err(ProtocolError::InvalidRequest);
                }
                self.receive_agent_request(&value, RequestKind::Specialist)?;
                Ok(InboundDisposition::Request(frame))
            }
            ProtocolFrame::StreamDeltaNotification(_) => {
                if !self.selected_capabilities()?.streaming {
                    return Err(ProtocolError::InvalidRequest);
                }
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
            | ProtocolFrame::ExitNotification(_)
            | ProtocolFrame::SuccessResponse(_)
            | ProtocolFrame::ErrorResponse(_) => Err(ProtocolError::InvalidRequest),
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

        let mut timed_out = false;
        for run in self.runs.values_mut() {
            if !run.terminal
                && (at >= run.deadline
                    || run
                        .cancellation_deadline
                        .is_some_and(|deadline| at >= deadline))
            {
                run.terminal = true;
                timed_out = true;
            }
        }
        if timed_out {
            Err(ProtocolError::Timeout)
        } else {
            Ok(())
        }
    }

    pub fn connection_lost(&mut self) -> Vec<String> {
        if self.connection_lost {
            return Vec::new();
        }
        self.connection_lost = true;
        let mut interrupted = Vec::new();
        for (run_id, run) in &mut self.runs {
            if run.accepted && !run.terminal {
                run.terminal = true;
                interrupted.push(run_id.clone());
            }
        }
        interrupted.sort();
        interrupted
    }

    fn outbound_response(&mut self, value: &Value) -> Result<(), ProtocolError> {
        let id = request_id(value)?;
        if !is_agent_id(id)
            || !matches!(
                self.pending_responses.get(id),
                Some(PendingResponse::AgentRequest)
            )
        {
            return Err(ProtocolError::InvalidRequest);
        }
        self.pending_responses.remove(id);
        Ok(())
    }

    fn outbound_initialize(&mut self, value: &Value) -> Result<(), ProtocolError> {
        if self.negotiated || self.initialized {
            return Err(ProtocolError::InvalidRequest);
        }
        let params = params(value)?;
        let versions = string_set(params, "protocolVersions")?;
        if !versions.is_subset(&self.offer.protocol_versions) {
            return Err(ProtocolError::ProtocolIncompatible);
        }
        for feature in string_array(params, "features")? {
            if !self.offer.capabilities.allows_feature(feature) {
                return Err(ProtocolError::ProtocolIncompatible);
            }
        }
        let launch_binding = object_field(params, "launchBinding")?;
        if required_str(launch_binding, "connectionId")? != self.binding.connection_id
            || required_str(launch_binding, "manifestDigest")? != self.binding.manifest_digest
            || required_str(launch_binding, "executableDigest")? != self.binding.executable_digest
            || required_str(launch_binding, "trustTier")? != self.binding.trust_tier.as_str()
        {
            return Err(ProtocolError::IdentityBindingFailed);
        }
        self.register_core_request(request_id(value)?.to_owned(), PendingResponse::Initialize)
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
        let params = params(value)?;
        let run_id = required_str(params, "runId")?.to_owned();
        if self.runs.contains_key(&run_id) {
            return Err(ProtocolError::InvalidRequest);
        }
        let limits = object_field(params, "limits")?;
        let deadline = DateTime::parse_from_rfc3339(required_str(limits, "deadline")?)
            .map_err(|_| ProtocolError::InvalidRequest)?
            .with_timezone(&Utc);
        let max_output_tokens = required_u64(limits, "maxOutputTokens")?;
        let max_tool_requests = required_u64(limits, "maxToolRequests")?;

        self.register_core_request(
            request_id(value)?.to_owned(),
            PendingResponse::RunStart {
                run_id: run_id.clone(),
            },
        )?;
        self.runs.insert(
            run_id,
            RunRecord {
                accepted: false,
                last_sequence: None,
                last_delta: Vec::new(),
                output_bytes: 0,
                tool_requests: 0,
                max_output_tokens,
                max_tool_requests,
                terminal: false,
                deadline,
                cancellation_deadline: None,
            },
        );
        Ok(())
    }

    fn outbound_run_cancel(
        &mut self,
        value: &Value,
        at: DateTime<Utc>,
    ) -> Result<(), ProtocolError> {
        let params = params(value)?;
        let run_id = required_str(params, "runId")?.to_owned();
        self.active_run(&run_id)?;
        let deadline_ms = required_u64(params, "deadlineMs")?;
        let duration_ms = i64::try_from(deadline_ms).map_err(|_| ProtocolError::InvalidRequest)?;
        let deadline = at
            .checked_add_signed(ChronoDuration::milliseconds(duration_ms))
            .ok_or(ProtocolError::Timeout)?;
        self.register_core_request(request_id(value)?.to_owned(), PendingResponse::RunCancel)?;
        self.runs
            .get_mut(&run_id)
            .ok_or(ProtocolError::InvalidRequest)?
            .cancellation_deadline = Some(deadline);
        Ok(())
    }

    fn outbound_shutdown(&mut self, value: &Value) -> Result<(), ProtocolError> {
        self.register_core_request(request_id(value)?.to_owned(), PendingResponse::Shutdown)
    }

    fn outbound_exit(&mut self, _value: &Value) -> Result<(), ProtocolError> {
        if self
            .pending_responses
            .values()
            .any(|pending| matches!(pending, PendingResponse::Shutdown))
        {
            return Err(ProtocolError::InvalidRequest);
        }
        Ok(())
    }

    fn validate_initialize_response(
        &self,
        value: &Value,
    ) -> Result<ProtocolCapabilities, ProtocolError> {
        let result = object_field(
            value.as_object().ok_or(ProtocolError::InvalidRequest)?,
            "result",
        )?;
        let selected_version = required_str(result, "protocolVersion")?;
        if !self.offer.protocol_versions.contains(selected_version) {
            return Err(ProtocolError::ProtocolIncompatible);
        }
        let agent = object_field(result, "agent")?;
        if required_str(agent, "id")? != self.binding.agent_id {
            return Err(ProtocolError::IdentityBindingFailed);
        }
        let selected = parse_capabilities(object_field(result, "capabilities")?)?;
        if !self.offer.capabilities.permits(&selected) {
            return Err(ProtocolError::ProtocolIncompatible);
        }
        Ok(selected)
    }

    fn accept_run_start(
        &mut self,
        value: &Value,
        expected_run_id: &str,
    ) -> Result<(), ProtocolError> {
        let result = object_field(
            value.as_object().ok_or(ProtocolError::InvalidRequest)?,
            "result",
        )?;
        if required_bool(result, "accepted")? && required_str(result, "runId")? == expected_run_id {
            self.runs
                .get_mut(expected_run_id)
                .ok_or(ProtocolError::InvalidRequest)?
                .accepted = true;
            Ok(())
        } else {
            Err(ProtocolError::InvalidRequest)
        }
    }

    fn receive_agent_request(
        &mut self,
        value: &Value,
        kind: RequestKind,
    ) -> Result<(), ProtocolError> {
        let id = request_id(value)?.to_owned();
        if !is_agent_id(&id) {
            return Err(ProtocolError::InvalidRequest);
        }
        let run_id = required_str(params(value)?, "runId")?.to_owned();
        let run = self.active_run(&run_id)?;
        if matches!(kind, RequestKind::Terminal)
            && output_tokens(params(value)?)? > run.max_output_tokens
        {
            self.mark_terminal(&run_id);
            return Err(ProtocolError::OutputLimitExceeded);
        }
        if matches!(kind, RequestKind::Tool) && run.tool_requests >= run.max_tool_requests {
            self.mark_terminal(&run_id);
            return Err(ProtocolError::OutputLimitExceeded);
        }

        self.register_agent_request(id)?;
        let run = self.active_run_mut(&run_id)?;
        match kind {
            RequestKind::Tool => run.tool_requests += 1,
            RequestKind::Terminal => run.terminal = true,
            RequestKind::Context | RequestKind::Specialist => {}
        }
        Ok(())
    }

    fn receive_stream_delta(&mut self, value: &Value) -> Result<bool, ProtocolError> {
        let params = params(value)?;
        let run_id = required_str(params, "runId")?.to_owned();
        let sequence = required_u64(params, "sequence")?;
        let delta = required_str(params, "delta")?.as_bytes();
        let max_output_bytes = self.limits.max_output_bytes;
        let run = self.active_run_mut(&run_id)?;

        let invalid_sequence = match run.last_sequence {
            None => sequence != 1,
            Some(last_sequence) if sequence == last_sequence => {
                if run.last_delta == delta {
                    return Ok(true);
                }
                true
            }
            Some(last_sequence) => last_sequence.checked_add(1) != Some(sequence),
        };
        if invalid_sequence {
            run.terminal = true;
            return Err(ProtocolError::InvalidRequest);
        }

        let Some(output_bytes) = run.output_bytes.checked_add(delta.len()) else {
            run.terminal = true;
            return Err(ProtocolError::OutputLimitExceeded);
        };
        if output_bytes > max_output_bytes {
            run.terminal = true;
            return Err(ProtocolError::OutputLimitExceeded);
        }
        run.last_sequence = Some(sequence);
        run.last_delta = delta.to_vec();
        run.output_bytes = output_bytes;
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

    fn register_core_request(
        &mut self,
        id: String,
        pending: PendingResponse,
    ) -> Result<(), ProtocolError> {
        if !is_core_id(&id) || !self.request_ids.insert(id.clone()) {
            return Err(ProtocolError::InvalidRequest);
        }
        self.pending_responses.insert(id, pending);
        Ok(())
    }

    fn register_agent_request(&mut self, id: String) -> Result<(), ProtocolError> {
        if !self.request_ids.insert(id.clone()) {
            return Err(ProtocolError::InvalidRequest);
        }
        self.pending_responses
            .insert(id, PendingResponse::AgentRequest);
        Ok(())
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

    fn mark_terminal(&mut self, run_id: &str) {
        if let Some(run) = self.runs.get_mut(run_id) {
            run.terminal = true;
        }
    }

    fn close_active_runs(&mut self) {
        for run in self.runs.values_mut() {
            if run.accepted {
                run.terminal = true;
            }
        }
    }

    fn ensure_connected(&self) -> Result<(), ProtocolError> {
        if self.connection_lost {
            Err(ProtocolError::InternalAgentFailure)
        } else {
            Ok(())
        }
    }

    fn selected_capabilities(&self) -> Result<&ProtocolCapabilities, ProtocolError> {
        self.selected_capabilities
            .as_ref()
            .ok_or(ProtocolError::InvalidRequest)
    }
}

#[derive(Clone, Copy)]
enum RequestKind {
    Terminal,
    Context,
    Tool,
    Specialist,
}

fn frame_value(frame: &ProtocolFrame) -> Result<Value, ProtocolError> {
    serde_json::to_value(frame).map_err(|_| ProtocolError::InvalidRequest)
}

fn request_id(value: &Value) -> Result<&str, ProtocolError> {
    value
        .get("id")
        .and_then(Value::as_str)
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

fn output_tokens(params: &Map<String, Value>) -> Result<u64, ProtocolError> {
    let Some(usage) = params.get("usage") else {
        return Ok(0);
    };
    let usage = usage.as_object().ok_or(ProtocolError::InvalidRequest)?;
    usage.get("outputTokens").map_or(Ok(0), |value| {
        value.as_u64().ok_or(ProtocolError::InvalidRequest)
    })
}

fn string_array<'a>(
    object: &'a Map<String, Value>,
    field: &str,
) -> Result<Vec<&'a str>, ProtocolError> {
    object
        .get(field)
        .and_then(Value::as_array)
        .ok_or(ProtocolError::InvalidRequest)?
        .iter()
        .map(|value| value.as_str().ok_or(ProtocolError::InvalidRequest))
        .collect()
}

fn string_set(object: &Map<String, Value>, field: &str) -> Result<BTreeSet<String>, ProtocolError> {
    string_array(object, field).map(|values| values.into_iter().map(str::to_owned).collect())
}

fn parse_capabilities(object: &Map<String, Value>) -> Result<ProtocolCapabilities, ProtocolError> {
    Ok(ProtocolCapabilities {
        roles: string_set(object, "roles")?,
        skills: string_set(object, "skills")?,
        streaming: required_bool(object, "streaming")?,
        context_query: required_bool(object, "contextQuery")?,
        tool_requests: required_bool(object, "toolRequests")?,
        specialist_requests: required_bool(object, "specialistRequests")?,
        max_concurrent_runs: required_u64(object, "maxConcurrentRuns")?,
        max_context_tokens: required_u64(object, "maxContextTokens")?,
    })
}

fn is_core_id(id: &str) -> bool {
    id.starts_with("core:")
}

fn is_agent_id(id: &str) -> bool {
    id.starts_with("agent:")
}
