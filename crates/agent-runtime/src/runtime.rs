use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc, Condvar, Mutex,
    },
    thread::{self, ThreadId},
    time::Duration,
};

use chrono::{DateTime, Duration as ChronoDuration, Utc};
use local_agent_terminal_agent_protocol::{
    InboundDisposition, NdjsonCodec, PeerDescriptor, PeerEventSink, ProtocolCapabilities,
    ProtocolError, ProtocolFrame, ProtocolOffer, ProtocolPeer, ProtocolSession, ProtocolTrustTier,
    RunCancel, RunExecutionBinding, RunStart, SessionLimits, DEFAULT_MAX_FRAME_BYTES,
};
use local_agent_terminal_application::{
    AgentArtifactStore, AgentMessageArtifact, AgentRunStore, AgentRuntime, Clock, PortError,
    Retryability, SafeErrorClassification,
};
use local_agent_terminal_domain::{
    AgentCancellationReceipt, AgentClaim, AgentDescriptor, AgentEvidenceRef, AgentRunMessage,
    AgentRunReceipt, AgentRunStatus, AgentRunTerminal, AgentUsage, ArtifactId,
    BoundAgentRunRequest, CancelAgentRun, RunId, Sha256Digest, Timestamp, TrustTier,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

pub const DEFAULT_HEARTBEAT_TIMEOUT_SECS: i64 = 30;
pub const DEFAULT_RUN_DEADLINE_SECS: i64 = 300;
pub(crate) const MAX_OUTPUT_BYTES: usize = 64 * 1024;

pub struct ProtocolAgentRuntime {
    store: Arc<dyn AgentRunStore>,
    artifacts: Arc<dyn AgentArtifactStore>,
    clock: Arc<dyn Clock>,
    peers: BTreeMap<String, Arc<dyn ProtocolPeer>>,
    descriptors: BTreeMap<String, AgentDescriptor>,
    sessions: Arc<Mutex<BTreeMap<String, Arc<Mutex<ProtocolSession>>>>>,
    active_runs: Arc<Mutex<BTreeMap<String, ActiveRun>>>,
    slots: Arc<ConnectionSlots>,
    next_request_id: AtomicU64,
}

#[derive(Clone)]
struct ActiveRun {
    request: BoundAgentRunRequest,
    peer: Arc<dyn ProtocolPeer>,
    session: Arc<Mutex<ProtocolSession>>,
    slot: RunSlot,
    deadline: DateTime<Utc>,
    cancellation_deadline: Option<DateTime<Utc>>,
}

#[derive(Default)]
struct ConnectionSlots {
    state: Mutex<ConnectionSlotState>,
}

#[derive(Default)]
struct ConnectionSlotState {
    runs: BTreeMap<String, BTreeSet<String>>,
    digests: BTreeMap<String, String>,
    handshakes: BTreeMap<String, Arc<Mutex<()>>>,
    poisoned_digests: BTreeSet<String>,
    retired_connection_ids: BTreeSet<String>,
}

impl ConnectionSlotState {
    fn is_retired(&self, connection_digest: &str) -> bool {
        self.digests.iter().any(|(connection_id, digest)| {
            digest == connection_digest && self.retired_connection_ids.contains(connection_id)
        })
    }

    fn is_unavailable(&self, connection_digest: &str) -> bool {
        self.poisoned_digests.contains(connection_digest) || self.is_retired(connection_digest)
    }
}

impl ConnectionSlots {
    fn reserve(
        self: &Arc<Self>,
        connection_id: &str,
        connection_digest: &str,
        run_id: &RunId,
        capacity: u64,
    ) -> Result<RunSlot, PortError> {
        let mut state = self.state.lock().map_err(|_| internal_failure())?;
        if state.retired_connection_ids.contains(connection_id)
            || state.poisoned_digests.contains(connection_digest)
            || state
                .digests
                .get(connection_id)
                .is_some_and(|digest| digest != connection_digest)
        {
            return Err(conflict());
        }
        state
            .digests
            .insert(connection_id.to_owned(), connection_digest.to_owned());
        state
            .handshakes
            .entry(connection_id.to_owned())
            .or_insert_with(|| Arc::new(Mutex::new(())));
        let runs = state.runs.entry(connection_digest.to_owned()).or_default();
        if u64::try_from(runs.len()).map_err(|_| internal_failure())? >= capacity
            || !runs.insert(run_id.as_str().to_owned())
        {
            return Err(conflict());
        }
        Ok(RunSlot(Arc::new(RunSlotInner {
            slots: Arc::clone(self),
            connection_digest: connection_digest.to_owned(),
            run_id: run_id.as_str().to_owned(),
            released: AtomicBool::new(false),
        })))
    }

    fn release(&self, connection_digest: &str, run_id: &str) {
        if let Ok(mut state) = self.state.lock() {
            if state.is_unavailable(connection_digest) {
                return;
            }
            if let Some(runs) = state.runs.get_mut(connection_digest) {
                runs.remove(run_id);
                if runs.is_empty() {
                    state.runs.remove(connection_digest);
                }
            }
        }
    }

    fn cleanup_connection(&self, connection_digest: &str) {
        if let Ok(mut state) = self.state.lock() {
            state.runs.remove(connection_digest);
            if !state.is_retired(connection_digest) {
                state.poisoned_digests.remove(connection_digest);
            }
        }
    }

    fn poison_connection(&self, connection_digest: &str) -> Result<(), PortError> {
        let mut state = self.state.lock().map_err(|_| internal_failure())?;
        if !state.is_retired(connection_digest) {
            state.poisoned_digests.insert(connection_digest.to_owned());
        }
        Ok(())
    }

    fn retire_connection(&self, connection_id: &str) -> Result<(), PortError> {
        let handshake = {
            let mut state = self.state.lock().map_err(|_| internal_failure())?;
            state
                .retired_connection_ids
                .insert(connection_id.to_owned());
            Arc::clone(
                state
                    .handshakes
                    .entry(connection_id.to_owned())
                    .or_insert_with(|| Arc::new(Mutex::new(()))),
            )
        };
        drop(handshake.lock().map_err(|_| internal_failure())?);
        Ok(())
    }

    fn start_handshake<T>(
        &self,
        connection_id: &str,
        connection_digest: &str,
        start: impl FnOnce() -> T,
    ) -> Result<T, PortError> {
        let handshake = {
            let state = self.state.lock().map_err(|_| internal_failure())?;
            if state.retired_connection_ids.contains(connection_id)
                || state.poisoned_digests.contains(connection_digest)
            {
                return Err(conflict());
            }
            state
                .handshakes
                .get(connection_id)
                .cloned()
                .ok_or_else(internal_failure)?
        };
        let _handshake = handshake.lock().map_err(|_| internal_failure())?;
        {
            let state = self.state.lock().map_err(|_| internal_failure())?;
            if state.retired_connection_ids.contains(connection_id)
                || state.poisoned_digests.contains(connection_digest)
            {
                return Err(conflict());
            }
        }
        Ok(start())
    }

    fn known_digests(&self) -> Result<BTreeSet<String>, PortError> {
        Ok(self
            .state
            .lock()
            .map_err(|_| internal_failure())?
            .digests
            .values()
            .cloned()
            .collect())
    }
}

#[derive(Clone)]
struct RunSlot(Arc<RunSlotInner>);

struct RunSlotInner {
    slots: Arc<ConnectionSlots>,
    connection_digest: String,
    run_id: String,
    released: AtomicBool,
}

impl RunSlot {
    fn release(&self) {
        if !self.0.released.swap(true, Ordering::AcqRel) {
            self.0
                .slots
                .release(&self.0.connection_digest, &self.0.run_id);
        }
    }
}

impl Drop for RunSlotInner {
    fn drop(&mut self) {
        if !self.released.load(Ordering::Acquire) {
            self.slots.release(&self.connection_digest, &self.run_id);
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SinkReadiness {
    Starting,
    Accepted,
    Ready,
    Failed,
}

struct SinkGate {
    starting_thread: ThreadId,
    readiness: Mutex<SinkReadiness>,
    changed: Condvar,
}

impl SinkGate {
    fn new() -> Self {
        Self {
            starting_thread: thread::current().id(),
            readiness: Mutex::new(SinkReadiness::Starting),
            changed: Condvar::new(),
        }
    }

    fn accepted(&self) -> Result<(), PortError> {
        *self.readiness.lock().map_err(|_| internal_failure())? = SinkReadiness::Accepted;
        self.changed.notify_all();
        Ok(())
    }

    fn ready(&self) -> Result<(), PortError> {
        *self.readiness.lock().map_err(|_| internal_failure())? = SinkReadiness::Ready;
        self.changed.notify_all();
        Ok(())
    }

    fn fail(&self) {
        if let Ok(mut readiness) = self.readiness.lock() {
            *readiness = SinkReadiness::Failed;
            self.changed.notify_all();
        }
    }

    fn wait_until_ready(&self) -> Result<(), ProtocolError> {
        let mut readiness = self
            .readiness
            .lock()
            .map_err(|_| ProtocolError::InternalAgentFailure)?;
        loop {
            match *readiness {
                SinkReadiness::Starting if thread::current().id() == self.starting_thread => {
                    return Err(ProtocolError::InvalidRequest);
                }
                SinkReadiness::Starting | SinkReadiness::Accepted => {
                    readiness = self
                        .changed
                        .wait(readiness)
                        .map_err(|_| ProtocolError::InternalAgentFailure)?;
                }
                SinkReadiness::Failed => return Err(ProtocolError::InvalidRequest),
                SinkReadiness::Ready => return Ok(()),
            }
        }
    }
}

impl ProtocolAgentRuntime {
    pub fn new(
        store: Arc<dyn AgentRunStore>,
        artifacts: Arc<dyn AgentArtifactStore>,
        clock: Arc<dyn Clock>,
        agents: Vec<(AgentDescriptor, Arc<dyn ProtocolPeer>)>,
    ) -> Result<Self, PortError> {
        let mut agent_ids = BTreeSet::new();
        let mut connection_ids = BTreeSet::new();
        for (descriptor, peer) in &agents {
            descriptor.validate().map_err(|_| invalid_input())?;
            validate_descriptor(descriptor, &peer.descriptor())?;
            if !agent_ids.insert(descriptor.agent_id.clone())
                || !connection_ids.insert(peer.descriptor().binding.connection_id)
            {
                return Err(conflict());
            }
        }
        let mut peers = BTreeMap::new();
        let mut descriptors = BTreeMap::new();
        for (descriptor, peer) in agents {
            store.register_descriptor(&descriptor)?;
            peers.insert(descriptor.agent_id.clone(), peer);
            descriptors.insert(descriptor.agent_id.clone(), descriptor);
        }
        Ok(Self {
            store,
            artifacts,
            clock,
            peers,
            descriptors,
            sessions: Arc::new(Mutex::new(BTreeMap::new())),
            active_runs: Arc::new(Mutex::new(BTreeMap::new())),
            slots: Arc::new(ConnectionSlots::default()),
            next_request_id: AtomicU64::new(1),
        })
    }

    pub fn check_timeouts(&self) -> Result<Vec<RunId>, PortError> {
        let now = match self.now() {
            Ok(now) => now,
            Err(error) => {
                let digests = self
                    .active_runs
                    .lock()
                    .map_err(|_| internal_failure())?
                    .values()
                    .map(|run| run.request.connection.binding_digest.as_str().to_owned())
                    .collect::<BTreeSet<_>>();
                for digest in digests {
                    self.slots.poison_connection(&digest)?;
                }
                return Err(error);
            }
        };
        let active = self
            .active_runs
            .lock()
            .map_err(|_| internal_failure())?
            .values()
            .cloned()
            .collect::<Vec<_>>();
        let mut resolved = Vec::new();
        let mut checked_connections = BTreeSet::new();
        for run in active {
            if !self.is_active(&run.request.run_id)? {
                continue;
            }
            if now.date_time >= run.deadline
                || run
                    .cancellation_deadline
                    .is_some_and(|deadline| now.date_time >= deadline)
            {
                let _ = run
                    .session
                    .lock()
                    .map_err(|_| internal_failure())?
                    .check_timeouts(now.date_time);
                self.persist_runtime_terminal(
                    &run.request,
                    AgentRunStatus::Terminated,
                    "agent run deadline expired",
                    now.timestamp,
                )?;
                self.active_runs
                    .lock()
                    .map_err(|_| internal_failure())?
                    .remove(run.request.run_id.as_str());
                run.slot.release();
                if let Ok(frame) =
                    cancel_frame(&run.request.run_id, &self.request_id(), "deadline", 1)
                {
                    if let Ok(cancel) = RunCancel::try_from(frame) {
                        let _ = run.peer.cancel(cancel);
                    }
                }
                resolved.push(run.request.run_id);
                continue;
            }

            let connection_id = run.request.connection.connection_id.clone();
            if !checked_connections.insert(connection_id) {
                continue;
            }
            let timed_out = matches!(
                run.session
                    .lock()
                    .map_err(|_| internal_failure())?
                    .check_timeouts(now.date_time),
                Err(ProtocolError::Timeout)
            );
            if timed_out {
                resolved.extend(self.interrupt_connection(
                    run.request.connection.binding_digest.as_str(),
                    &now.text,
                )?);
            }
        }
        Ok(resolved)
    }

    pub fn shutdown(&self) -> Result<(), PortError> {
        let mut peer_error = None;
        for peer in self.peers.values() {
            self.slots
                .retire_connection(&peer.descriptor().binding.connection_id)?;
            if let Err(error) = peer.shutdown() {
                peer_error.get_or_insert(error);
            }
        }
        let now = self.now()?;
        let digests = self.slots.known_digests()?;
        for digest in digests {
            self.interrupt_connection(&digest, &now.text)?;
        }
        if let Some(error) = peer_error {
            Err(protocol_port_error(error))
        } else {
            Ok(())
        }
    }

    fn start(&self, request: BoundAgentRunRequest) -> Result<AgentRunReceipt, PortError> {
        request.validate().map_err(|_| invalid_input())?;
        let peer = self
            .peers
            .get(&request.agent_id)
            .cloned()
            .ok_or_else(not_found)?;
        if !self
            .descriptors
            .get(&request.agent_id)
            .is_some_and(|descriptor| descriptor.enabled)
        {
            return Err(permission_denied());
        }
        validate_request_peer(&request, &peer.descriptor())?;
        let effective_context = self.artifacts.load_effective_context(&request.context)?;
        if digest_bytes(&effective_context) != request.context.content_digest {
            return Err(invalid_input());
        }
        let now = self.now()?;
        if request.run_config.limits.deadline <= now.timestamp {
            return Err(invalid_input());
        }
        let slot = self.slots.reserve(
            &request.connection.connection_id,
            request.connection.binding_digest.as_str(),
            &request.run_id,
            peer.descriptor().capabilities.max_concurrent_runs,
        )?;
        self.store.create_bound_run(&request)?;

        let session = self.session(&request, &peer.descriptor(), now.date_time)?;
        let request_id = self.request_id();
        let deadline = timestamp_date_time(request.run_config.limits.deadline)?;
        let start = run_start_frame(&request, &peer.descriptor(), &request_id)?;
        session
            .lock()
            .map_err(|_| internal_failure())?
            .outbound(start.clone(), now.date_time)
            .map_err(protocol_port_error)?;

        let gate = Arc::new(SinkGate::new());
        let sink = RuntimeSink {
            store: Arc::clone(&self.store),
            artifacts: Arc::clone(&self.artifacts),
            clock: Arc::clone(&self.clock),
            session: Arc::clone(&session),
            peer: Arc::clone(&peer),
            request: request.clone(),
            active_runs: Arc::clone(&self.active_runs),
            sessions: Arc::clone(&self.sessions),
            slot: slot.clone(),
            gate: Arc::clone(&gate),
            slots: Arc::clone(&self.slots),
            codec: NdjsonCodec::default(),
        };
        let run_start = RunStart::new(
            start,
            RunExecutionBinding {
                provider_id: request.run_config.provider_id.clone(),
                model_id: request.run_config.model_id.clone(),
                generation_parameters: request
                    .run_config
                    .generation_parameters
                    .canonical_json
                    .clone(),
                generation_parameters_digest: request
                    .run_config
                    .generation_parameters
                    .digest
                    .as_str()
                    .to_owned(),
                effective_context,
                effective_context_artifact_id: request
                    .context
                    .effective_context_artifact_id
                    .as_str()
                    .to_owned(),
                effective_context_digest: request.context.content_digest.as_str().to_owned(),
                supersedes_run_id: request
                    .supersedes_run_id
                    .as_ref()
                    .map(|run_id| run_id.as_str().to_owned()),
            },
        )
        .map_err(protocol_port_error)?;
        let started = self.slots.start_handshake(
            &request.connection.connection_id,
            request.connection.binding_digest.as_str(),
            || peer.start(run_start, Box::new(sink)),
        );
        let acceptance = match started {
            Err(error) => {
                gate.fail();
                self.cleanup_unstarted_run(&request)?;
                return Err(error);
            }
            Ok(started) => match started {
                Ok(acceptance)
                    if acceptance.accepted && acceptance.run_id == request.run_id.as_str() =>
                {
                    acceptance
                }
                Ok(_) => {
                    gate.fail();
                    let error = invalid_input();
                    self.compensate_started_run(
                        &request,
                        peer.as_ref(),
                        AgentRunStatus::Failed,
                        "peer rejected the bound run",
                    );
                    return Err(error);
                }
                Err(error) => {
                    gate.fail();
                    let original = protocol_port_error(error);
                    self.compensate_started_run(
                        &request,
                        peer.as_ref(),
                        AgentRunStatus::Interrupted,
                        "peer failed before acceptance",
                    );
                    return Err(original);
                }
            },
        };
        if let Err(error) = gate.accepted() {
            gate.fail();
            self.compensate_started_run(
                &request,
                peer.as_ref(),
                AgentRunStatus::Interrupted,
                "peer start could not be committed",
            );
            return Err(error);
        }

        let after_start = (|| {
            let accepted = self.now()?;
            session
                .lock()
                .map_err(|_| internal_failure())?
                .receive_response(
                    success_response(
                        &request_id,
                        json!({ "accepted": acceptance.accepted, "runId": acceptance.run_id }),
                    )?,
                    accepted.date_time,
                )
                .map_err(protocol_port_error)?;
            self.store.accept_run(&request.run_id, &accepted.text)?;
            let running = self.now()?;
            self.store.mark_running(&request.run_id, &running.text)?;
            self.active_runs
                .lock()
                .map_err(|_| internal_failure())?
                .insert(
                    request.run_id.as_str().to_owned(),
                    ActiveRun {
                        request: request.clone(),
                        peer: Arc::clone(&peer),
                        session: Arc::clone(&session),
                        slot: slot.clone(),
                        deadline,
                        cancellation_deadline: None,
                    },
                );
            gate.ready()?;
            Ok::<_, PortError>(accepted)
        })();
        let accepted = match after_start {
            Ok(accepted) => accepted,
            Err(error) => {
                gate.fail();
                self.compensate_started_run(
                    &request,
                    peer.as_ref(),
                    AgentRunStatus::Interrupted,
                    "peer start could not be committed",
                );
                return Err(error);
            }
        };
        Ok(AgentRunReceipt {
            run_id: request.run_id,
            accepted_at: accepted.timestamp,
        })
    }

    fn cancel_run(&self, request: CancelAgentRun) -> Result<AgentCancellationReceipt, PortError> {
        request.validate().map_err(|_| invalid_input())?;
        let active = self
            .active_runs
            .lock()
            .map_err(|_| internal_failure())?
            .get(request.run_id.as_str())
            .cloned()
            .ok_or_else(not_found)?;
        let now = self.now()?;
        let request_id = self.request_id();
        let frame = cancel_frame(
            &request.run_id,
            &request_id,
            &request.reason,
            request.deadline_ms,
        )?;
        active
            .session
            .lock()
            .map_err(|_| internal_failure())?
            .outbound(frame.clone(), now.date_time)
            .map_err(protocol_port_error)?;
        self.active_runs
            .lock()
            .map_err(|_| internal_failure())?
            .get_mut(request.run_id.as_str())
            .ok_or_else(not_found)?
            .cancellation_deadline = Some(
            now.date_time
                + ChronoDuration::milliseconds(
                    i64::try_from(request.deadline_ms).map_err(|_| invalid_input())?,
                ),
        );
        let acceptance = active
            .peer
            .cancel(RunCancel::try_from(frame).map_err(protocol_port_error)?)
            .map_err(protocol_port_error)?;
        if !acceptance.accepted || acceptance.run_id != request.run_id.as_str() {
            return Err(invalid_input());
        }
        active
            .session
            .lock()
            .map_err(|_| internal_failure())?
            .receive_response(
                success_response(
                    &request_id,
                    json!({ "accepted": true, "runId": acceptance.run_id }),
                )?,
                now.date_time,
            )
            .map_err(protocol_port_error)?;
        Ok(AgentCancellationReceipt {
            run_id: request.run_id,
            accepted_at: now.timestamp,
        })
    }

    fn session(
        &self,
        request: &BoundAgentRunRequest,
        descriptor: &PeerDescriptor,
        now: DateTime<Utc>,
    ) -> Result<Arc<Mutex<ProtocolSession>>, PortError> {
        let mut sessions = self.sessions.lock().map_err(|_| internal_failure())?;
        let session_key = request.connection.binding_digest.as_str();
        if let Some(session) = sessions.get(session_key) {
            return Ok(Arc::clone(session));
        }
        let mut session = ProtocolSession::new(
            descriptor.binding.clone(),
            ProtocolOffer {
                protocol_versions: BTreeSet::from([descriptor.protocol_version.clone()]),
                capabilities: descriptor.capabilities.clone(),
            },
            SessionLimits {
                max_output_bytes: MAX_OUTPUT_BYTES,
                heartbeat_timeout: Duration::from_secs(
                    u64::try_from(DEFAULT_HEARTBEAT_TIMEOUT_SECS)
                        .expect("positive heartbeat timeout"),
                ),
            },
            now,
        );
        let initialize_id = self.request_id();
        session
            .outbound(initialize_frame(descriptor, &initialize_id)?, now)
            .map_err(protocol_port_error)?;
        session
            .receive_response(initialize_response(descriptor, &initialize_id)?, now)
            .map_err(protocol_port_error)?;
        session
            .outbound(initialized_frame(descriptor)?, now)
            .map_err(protocol_port_error)?;
        let session = Arc::new(Mutex::new(session));
        sessions.insert(session_key.to_owned(), Arc::clone(&session));
        Ok(session)
    }

    fn now(&self) -> Result<RuntimeTime, PortError> {
        runtime_time(self.clock.as_ref())
    }

    fn request_id(&self) -> String {
        format!(
            "core:{}",
            self.next_request_id.fetch_add(1, Ordering::Relaxed)
        )
    }

    fn persist_runtime_terminal(
        &self,
        request: &BoundAgentRunRequest,
        status: AgentRunStatus,
        error: &str,
        at: Timestamp,
    ) -> Result<(), PortError> {
        publish_runtime_terminal(
            self.artifacts.as_ref(),
            self.store.as_ref(),
            request,
            status,
            error,
            at,
        )
    }

    fn compensate_started_run(
        &self,
        request: &BoundAgentRunRequest,
        peer: &dyn ProtocolPeer,
        status: AgentRunStatus,
        error: &str,
    ) {
        if let Ok(frame) = cancel_frame(
            &request.run_id,
            "core:start-compensation",
            "start_failed",
            1,
        ) {
            if let Ok(cancel) = RunCancel::try_from(frame) {
                let _ = peer.cancel(cancel);
            }
        }
        if self
            .slots
            .retire_connection(&request.connection.connection_id)
            .is_err()
        {
            return;
        }
        let _ = peer.shutdown();
        let connection_digest = request.connection.binding_digest.as_str();
        if let Ok(now) = self.now() {
            let _ = self.persist_runtime_terminal(request, status, error, now.timestamp);
            let _ = self.interrupt_connection(connection_digest, &now.text);
        }
    }

    fn cleanup_unstarted_run(&self, request: &BoundAgentRunRequest) -> Result<(), PortError> {
        let now = self.now()?;
        self.interrupt_connection(request.connection.binding_digest.as_str(), &now.text)?;
        Ok(())
    }

    fn interrupt_connection(&self, digest: &str, at: &str) -> Result<Vec<RunId>, PortError> {
        let interrupted = match self.store.interrupt_connection(digest, at) {
            Ok(interrupted) => interrupted,
            Err(error) => {
                self.slots.poison_connection(digest)?;
                return Err(error);
            }
        };
        self.active_runs
            .lock()
            .map_err(|_| internal_failure())?
            .retain(|_, run| run.request.connection.binding_digest.as_str() != digest);
        self.sessions
            .lock()
            .map_err(|_| internal_failure())?
            .remove(digest);
        self.slots.cleanup_connection(digest);
        Ok(interrupted)
    }

    fn is_active(&self, run_id: &RunId) -> Result<bool, PortError> {
        Ok(self
            .active_runs
            .lock()
            .map_err(|_| internal_failure())?
            .contains_key(run_id.as_str()))
    }
}

impl AgentRuntime for ProtocolAgentRuntime {
    fn list_agents(&self) -> Result<Vec<AgentDescriptor>, PortError> {
        Ok(self.descriptors.values().cloned().collect())
    }

    fn start_run(&self, request: BoundAgentRunRequest) -> Result<AgentRunReceipt, PortError> {
        self.start(request)
    }

    fn cancel(&self, request: CancelAgentRun) -> Result<AgentCancellationReceipt, PortError> {
        self.cancel_run(request)
    }
}

struct RuntimeSink {
    store: Arc<dyn AgentRunStore>,
    artifacts: Arc<dyn AgentArtifactStore>,
    clock: Arc<dyn Clock>,
    session: Arc<Mutex<ProtocolSession>>,
    peer: Arc<dyn ProtocolPeer>,
    request: BoundAgentRunRequest,
    active_runs: Arc<Mutex<BTreeMap<String, ActiveRun>>>,
    sessions: Arc<Mutex<BTreeMap<String, Arc<Mutex<ProtocolSession>>>>>,
    slot: RunSlot,
    gate: Arc<SinkGate>,
    slots: Arc<ConnectionSlots>,
    codec: NdjsonCodec,
}

impl RuntimeSink {
    fn receive_frame(&self, frame: ProtocolFrame) -> Result<InboundDisposition, ProtocolError> {
        self.gate.wait_until_ready()?;
        if matches!(
            frame,
            ProtocolFrame::RunCompleteRequest(_)
                | ProtocolFrame::ContextQueryRequest(_)
                | ProtocolFrame::ToolRequest(_)
                | ProtocolFrame::SpecialistRequest(_)
        ) {
            return Err(ProtocolError::InvalidRequest);
        }
        let now =
            runtime_time(self.clock.as_ref()).map_err(|_| ProtocolError::InternalAgentFailure)?;
        let received = {
            let mut session = self
                .session
                .lock()
                .map_err(|_| ProtocolError::InternalAgentFailure)?;
            session.receive(frame.clone(), now.date_time)
        };
        let disposition = match received {
            Ok(disposition) => disposition,
            Err(error) => {
                self.handle_protocol_error(error, now)?;
                return Err(error);
            }
        };
        Ok(disposition)
    }

    fn request_frame(&self, frame: ProtocolFrame) -> Result<ProtocolFrame, ProtocolError> {
        self.gate.wait_until_ready()?;
        let now =
            runtime_time(self.clock.as_ref()).map_err(|_| ProtocolError::InternalAgentFailure)?;
        let received = self
            .session
            .lock()
            .map_err(|_| ProtocolError::InternalAgentFailure)?
            .receive(frame.clone(), now.date_time);
        let disposition = match received {
            Ok(InboundDisposition::Request(frame)) => frame,
            Ok(_) => return Err(ProtocolError::InvalidRequest),
            Err(error) => {
                self.handle_protocol_error(error, now)?;
                return Err(error);
            }
        };
        let id = required_string(&frame_value(&frame)?, "/id")?;
        let response = if matches!(disposition, ProtocolFrame::RunCompleteRequest(_)) {
            let content = terminal_content(&frame)?;
            let message_id = required_string(&frame_value(&frame)?, "/params/message/messageId")?;
            let content_artifact_id = self
                .artifacts
                .publish_agent_message(&AgentMessageArtifact {
                    task_id: self.request.task_id.clone(),
                    run_id: self.request.run_id.clone(),
                    message_id,
                    content: content.into_bytes(),
                })
                .map_err(|_| ProtocolError::InternalAgentFailure)?;
            let terminal =
                terminal_from_frame(&frame, &self.request, content_artifact_id, now.timestamp)?;
            self.store
                .persist_terminal(&terminal)
                .map_err(|_| ProtocolError::InternalAgentFailure)?;
            self.active_runs
                .lock()
                .map_err(|_| ProtocolError::InternalAgentFailure)?
                .remove(self.request.run_id.as_str());
            self.slot.release();
            success_response(&id, json!({ "accepted": true }))
                .map_err(|_| ProtocolError::InternalAgentFailure)?
        } else {
            error_response(&id, "policy_denied", false)
                .map_err(|_| ProtocolError::InternalAgentFailure)?
        };
        self.session
            .lock()
            .map_err(|_| ProtocolError::InternalAgentFailure)?
            .outbound(response.clone(), now.date_time)?;
        Ok(response)
    }

    fn handle_protocol_error(
        &self,
        error: ProtocolError,
        now: RuntimeTime,
    ) -> Result<(), ProtocolError> {
        if error == ProtocolError::OutputLimitExceeded {
            publish_runtime_terminal(
                self.artifacts.as_ref(),
                self.store.as_ref(),
                &self.request,
                AgentRunStatus::Failed,
                "agent output limit exceeded",
                now.timestamp,
            )
            .map_err(|_| ProtocolError::InternalAgentFailure)?;
            self.active_runs
                .lock()
                .map_err(|_| ProtocolError::InternalAgentFailure)?
                .remove(self.request.run_id.as_str());
            self.slot.release();
            let frame = cancel_frame(&self.request.run_id, "core:limit", "output_limit", 1)
                .map_err(|_| ProtocolError::InternalAgentFailure)?;
            let cancel = RunCancel::try_from(frame)?;
            let _ = self.peer.cancel(cancel);
            return Ok(());
        }
        self.session
            .lock()
            .map_err(|_| ProtocolError::InternalAgentFailure)?
            .connection_lost();
        self.interrupt(now)
    }

    fn interrupt(&self, now: RuntimeTime) -> Result<(), ProtocolError> {
        let digest = self.request.connection.binding_digest.as_str();
        if self.store.interrupt_connection(digest, &now.text).is_err() {
            self.slots
                .poison_connection(digest)
                .map_err(|_| ProtocolError::InternalAgentFailure)?;
            return Err(ProtocolError::InternalAgentFailure);
        }
        self.active_runs
            .lock()
            .map_err(|_| ProtocolError::InternalAgentFailure)?
            .retain(|_, run| {
                run.request.connection.binding_digest != self.request.connection.binding_digest
            });
        self.sessions
            .lock()
            .map_err(|_| ProtocolError::InternalAgentFailure)?
            .remove(self.request.connection.binding_digest.as_str());
        self.slots.cleanup_connection(digest);
        Ok(())
    }
}

impl PeerEventSink for RuntimeSink {
    fn receive(&self, frame: ProtocolFrame) -> Result<InboundDisposition, ProtocolError> {
        self.receive_frame(frame)
    }

    fn receive_raw(&self, bytes: &[u8]) -> Result<InboundDisposition, ProtocolError> {
        match self.codec.decode(bytes) {
            Ok(frame) => self.receive_frame(frame),
            Err(error) => {
                self.connection_lost()?;
                Err(error)
            }
        }
    }

    fn request(&self, frame: ProtocolFrame) -> Result<ProtocolFrame, ProtocolError> {
        self.request_frame(frame)
    }

    fn connection_lost(&self) -> Result<(), ProtocolError> {
        let now = match runtime_time(self.clock.as_ref()) {
            Ok(now) => now,
            Err(_) => {
                self.slots
                    .poison_connection(self.request.connection.binding_digest.as_str())
                    .map_err(|_| ProtocolError::InternalAgentFailure)?;
                return Err(ProtocolError::InternalAgentFailure);
            }
        };
        self.session
            .lock()
            .map_err(|_| ProtocolError::InternalAgentFailure)?
            .connection_lost();
        self.interrupt(now)
    }
}

#[derive(Clone)]
struct RuntimeTime {
    text: String,
    date_time: DateTime<Utc>,
    timestamp: Timestamp,
}

fn runtime_time(clock: &dyn Clock) -> Result<RuntimeTime, PortError> {
    let text = clock.now_utc()?;
    let date_time = DateTime::parse_from_rfc3339(&text)
        .map_err(|_| invalid_input())?
        .with_timezone(&Utc);
    Ok(RuntimeTime {
        text,
        date_time,
        timestamp: Timestamp::from_unix_seconds(date_time.timestamp()),
    })
}

fn timestamp_date_time(timestamp: Timestamp) -> Result<DateTime<Utc>, PortError> {
    DateTime::from_timestamp(timestamp.unix_seconds(), 0).ok_or_else(invalid_input)
}

fn validate_descriptor(
    descriptor: &AgentDescriptor,
    peer: &PeerDescriptor,
) -> Result<(), PortError> {
    let executable = descriptor
        .executable_digest
        .as_ref()
        .map(Sha256Digest::as_str);
    if descriptor.agent_id != peer.binding.agent_id
        || descriptor.manifest_digest.as_str() != peer.binding.manifest_digest
        || executable != Some(peer.binding.executable_digest.as_str())
        || trust_tier(descriptor.trust_tier) != peer.binding.trust_tier
    {
        return Err(invalid_input());
    }
    Ok(())
}

fn validate_request_peer(
    request: &BoundAgentRunRequest,
    peer: &PeerDescriptor,
) -> Result<(), PortError> {
    if request.connection.connection_id != peer.binding.connection_id
        || request.connection.agent_id != peer.binding.agent_id
        || request.connection.manifest_digest.as_str() != peer.binding.manifest_digest
        || request
            .connection
            .executable_digest
            .as_ref()
            .map(Sha256Digest::as_str)
            != Some(peer.binding.executable_digest.as_str())
        || trust_tier(request.connection.trust_tier) != peer.binding.trust_tier
        || request.connection.contract_version != peer.protocol_version
        || !peer.capabilities.roles.contains(&request.role)
    {
        return Err(invalid_input());
    }
    Ok(())
}

fn trust_tier(value: TrustTier) -> ProtocolTrustTier {
    match value {
        TrustTier::CoreAdapter => ProtocolTrustTier::CoreAdapter,
        TrustTier::BrokeredProcess => ProtocolTrustTier::BrokeredProcess,
        TrustTier::IsolatedWorker => ProtocolTrustTier::IsolatedWorker,
        TrustTier::FullAccessLegacy => ProtocolTrustTier::FullAccessLegacy,
    }
}

fn initialize_frame(
    descriptor: &PeerDescriptor,
    request_id: &str,
) -> Result<ProtocolFrame, PortError> {
    decode_frame(json!({
        "jsonrpc": "2.0",
        "id": request_id,
        "method": "initialize",
        "params": {
            "protocolVersions": [descriptor.protocol_version],
            "client": { "name": "local-agent-terminal", "version": "0.1.0" },
            "transport": { "type": "stdio-ndjson", "maxFrameBytes": DEFAULT_MAX_FRAME_BYTES },
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

fn initialize_response(
    descriptor: &PeerDescriptor,
    request_id: &str,
) -> Result<ProtocolFrame, PortError> {
    success_response(
        request_id,
        json!({
            "protocolVersion": descriptor.protocol_version,
            "agent": {
                "id": descriptor.binding.agent_id,
                "displayName": descriptor.binding.agent_id,
                "implementationVersion": "1"
            },
            "capabilities": capabilities_json(&descriptor.capabilities)
        }),
    )
}

fn initialized_frame(descriptor: &PeerDescriptor) -> Result<ProtocolFrame, PortError> {
    decode_frame(json!({
        "jsonrpc": "2.0",
        "method": "initialized",
        "params": {
            "connectionId": descriptor.binding.connection_id,
            "effectiveCapabilitiesDigest": descriptor.binding.manifest_digest
        }
    }))
}

fn run_start_frame(
    request: &BoundAgentRunRequest,
    descriptor: &PeerDescriptor,
    request_id: &str,
) -> Result<ProtocolFrame, PortError> {
    let mut value = json!({
        "jsonrpc": "2.0",
        "id": request_id,
        "method": "agent.run.start",
        "params": {
            "runId": request.run_id.as_str(),
            "idempotencyKey": request.idempotency_key,
            "taskId": request.task_id.as_str(),
            "role": request.role,
            "objective": request.context.objective,
            "contextPackage": {
                "packageId": request.context.context_package_id,
                "contentDigest": request.context.content_digest.as_str(),
                "manifestRef": request.context.manifest_artifact_id.as_str()
            },
            "permissions": {
                "contextQuery": descriptor.capabilities.context_query,
                "toolRequest": descriptor.capabilities.tool_requests,
                "writeFiles": false
            },
            "responseSchema": request.run_config.response_schema_version,
            "limits": {
                "deadline": timestamp_date_time(request.run_config.limits.deadline)?.to_rfc3339(),
                "maxOutputTokens": request.run_config.limits.max_output_tokens,
                "maxToolRequests": request.run_config.limits.max_tool_requests
            }
        }
    });
    if let Some(supersedes_run_id) = &request.supersedes_run_id {
        value
            .pointer_mut("/params")
            .and_then(Value::as_object_mut)
            .ok_or_else(internal_failure)?
            .insert(
                "supersedesRunId".to_owned(),
                Value::String(supersedes_run_id.as_str().to_owned()),
            );
    }
    decode_frame(value)
}

fn cancel_frame(
    run_id: &RunId,
    request_id: &str,
    reason: &str,
    deadline_ms: u64,
) -> Result<ProtocolFrame, PortError> {
    decode_frame(json!({
        "jsonrpc": "2.0",
        "id": request_id,
        "method": "agent.run.cancel",
        "params": { "runId": run_id.as_str(), "reason": reason, "deadlineMs": deadline_ms }
    }))
}

fn success_response(request_id: &str, result: Value) -> Result<ProtocolFrame, PortError> {
    decode_frame(json!({ "jsonrpc": "2.0", "id": request_id, "result": result }))
}

fn error_response(
    request_id: &str,
    category: &str,
    retryable: bool,
) -> Result<ProtocolFrame, PortError> {
    decode_frame(json!({
        "jsonrpc": "2.0",
        "id": request_id,
        "error": {
            "code": -32040,
            "message": "Agent-originated request is not available",
            "data": { "category": category, "retryable": retryable }
        }
    }))
}

fn decode_frame(value: Value) -> Result<ProtocolFrame, PortError> {
    let bytes = serde_json::to_vec(&value).map_err(|_| internal_failure())?;
    NdjsonCodec::default()
        .decode(&bytes)
        .map_err(protocol_port_error)
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

fn terminal_from_frame(
    frame: &ProtocolFrame,
    request: &BoundAgentRunRequest,
    content_artifact_id: ArtifactId,
    at: Timestamp,
) -> Result<AgentRunTerminal, ProtocolError> {
    let value = frame_value(frame)?;
    let params = value
        .get("params")
        .and_then(Value::as_object)
        .ok_or(ProtocolError::InvalidRequest)?;
    let message = params
        .get("message")
        .and_then(Value::as_object)
        .ok_or(ProtocolError::InvalidRequest)?;
    let message_id = required_string(&value, "/params/message/messageId")?;
    let status = match required_string(&value, "/params/status")?.as_str() {
        "succeeded" => AgentRunStatus::Succeeded,
        "failed" => AgentRunStatus::Failed,
        "cancelled_cleanly" => AgentRunStatus::CancelledCleanly,
        _ => return Err(ProtocolError::InvalidRequest),
    };
    let claims = message
        .get("claims")
        .and_then(Value::as_array)
        .ok_or(ProtocolError::InvalidRequest)?
        .iter()
        .map(parse_claim)
        .collect::<Result<Vec<_>, _>>()?;
    let usage = params
        .get("usage")
        .and_then(Value::as_object)
        .map(|usage| AgentUsage {
            input_tokens: usage
                .get("inputTokens")
                .and_then(Value::as_i64)
                .unwrap_or(0),
            output_tokens: usage
                .get("outputTokens")
                .and_then(Value::as_i64)
                .unwrap_or(0),
            cost_microunits: usage
                .get("providerReportedCost")
                .and_then(Value::as_f64)
                .map(|cost| (cost * 1_000_000.0).round() as i64),
        });
    let terminal = AgentRunTerminal {
        run_id: request.run_id.clone(),
        task_id: request.task_id.clone(),
        status,
        message: AgentRunMessage {
            message_id,
            task_id: request.task_id.clone(),
            run_id: request.run_id.clone(),
            thread_id: message
                .get("threadId")
                .and_then(Value::as_str)
                .map(str::to_owned)
                .unwrap_or_else(|| stable_id("thread", request.run_id.as_str())),
            message_type: required_string(&value, "/params/message/type")?,
            reply_to: message
                .get("replyTo")
                .and_then(Value::as_str)
                .map(str::to_owned),
            content_artifact_id,
            claims,
        },
        provider_usage: usage,
        core_usage: None,
        estimated_cost_microunits: None,
        error: (status == AgentRunStatus::Failed).then(|| "agent reported failure".to_owned()),
        core_received_at: Some(at),
    };
    terminal
        .validate()
        .map_err(|_| ProtocolError::InvalidRequest)?;
    Ok(terminal)
}

fn parse_claim(value: &Value) -> Result<AgentClaim, ProtocolError> {
    let object = value.as_object().ok_or(ProtocolError::InvalidRequest)?;
    let evidence = object
        .get("evidenceRefs")
        .and_then(Value::as_array)
        .ok_or(ProtocolError::InvalidRequest)?
        .iter()
        .map(parse_evidence)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(AgentClaim {
        claim_id: required_object_string(object, "claimId")?,
        text: required_object_string(object, "text")?,
        evidence,
        confidence: object
            .get("confidence")
            .and_then(Value::as_f64)
            .ok_or(ProtocolError::InvalidRequest)?,
    })
}

fn parse_evidence(value: &Value) -> Result<AgentEvidenceRef, ProtocolError> {
    let object = value.as_object().ok_or(ProtocolError::InvalidRequest)?;
    Ok(AgentEvidenceRef {
        source_type: required_object_string(object, "sourceType")?,
        source_id: required_object_string(object, "sourceId")?,
        revision: required_object_string(object, "revision")?,
        content_digest: Sha256Digest::new(required_object_string(object, "contentDigest")?)
            .map_err(|_| ProtocolError::InvalidRequest)?,
        start_line: optional_u32(object.get("startLine"))?,
        end_line: optional_u32(object.get("endLine"))?,
        symbol: object
            .get("symbol")
            .and_then(Value::as_str)
            .map(str::to_owned),
    })
}

fn optional_u32(value: Option<&Value>) -> Result<Option<u32>, ProtocolError> {
    value
        .map(|value| {
            value
                .as_u64()
                .and_then(|value| u32::try_from(value).ok())
                .ok_or(ProtocolError::InvalidRequest)
        })
        .transpose()
}

fn runtime_terminal(
    request: &BoundAgentRunRequest,
    status: AgentRunStatus,
    error: &str,
    content_artifact_id: ArtifactId,
    at: Timestamp,
) -> AgentRunTerminal {
    AgentRunTerminal {
        run_id: request.run_id.clone(),
        task_id: request.task_id.clone(),
        status,
        message: AgentRunMessage {
            message_id: stable_id("runtime-message", request.run_id.as_str()),
            task_id: request.task_id.clone(),
            run_id: request.run_id.clone(),
            thread_id: stable_id("thread", request.run_id.as_str()),
            message_type: "status".to_owned(),
            reply_to: None,
            content_artifact_id,
            claims: Vec::new(),
        },
        provider_usage: None,
        core_usage: None,
        estimated_cost_microunits: None,
        error: Some(error.to_owned()),
        core_received_at: Some(at),
    }
}

fn terminal_content(frame: &ProtocolFrame) -> Result<String, ProtocolError> {
    required_string(&frame_value(frame)?, "/params/message/content")
}

fn publish_runtime_terminal(
    artifacts: &dyn AgentArtifactStore,
    store: &dyn AgentRunStore,
    request: &BoundAgentRunRequest,
    status: AgentRunStatus,
    error: &str,
    at: Timestamp,
) -> Result<(), PortError> {
    let message_id = stable_id("runtime-message", request.run_id.as_str());
    let content_artifact_id = artifacts.publish_agent_message(&AgentMessageArtifact {
        task_id: request.task_id.clone(),
        run_id: request.run_id.clone(),
        message_id,
        content: error.as_bytes().to_vec(),
    })?;
    store.persist_terminal(&runtime_terminal(
        request,
        status,
        error,
        content_artifact_id,
        at,
    ))
}

fn stable_id(prefix: &str, value: &str) -> String {
    format!("{prefix}-{:x}", Sha256::digest(value.as_bytes()))
}

fn digest_bytes(bytes: &[u8]) -> Sha256Digest {
    Sha256Digest::new(format!("sha256:{:x}", Sha256::digest(bytes)))
        .expect("SHA-256 formatting is valid")
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

fn required_object_string(
    object: &serde_json::Map<String, Value>,
    key: &str,
) -> Result<String, ProtocolError> {
    object
        .get(key)
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or(ProtocolError::InvalidRequest)
}

fn protocol_port_error(error: ProtocolError) -> PortError {
    let (classification, retryability) = match error {
        ProtocolError::ProviderUnavailable | ProtocolError::RateLimited => (
            SafeErrorClassification::Unavailable,
            Retryability::Retryable,
        ),
        ProtocolError::InternalAgentFailure | ProtocolError::Timeout => (
            SafeErrorClassification::Unavailable,
            Retryability::NonRetryable,
        ),
        ProtocolError::PolicyDenied | ProtocolError::ApprovalRequired => (
            SafeErrorClassification::PermissionDenied,
            Retryability::NonRetryable,
        ),
        ProtocolError::EmptyFrame
        | ProtocolError::FrameTooLarge { .. }
        | ProtocolError::MultipleFrames
        | ProtocolError::InvalidUtf8
        | ProtocolError::InvalidJson
        | ProtocolError::InvalidFrame
        | ProtocolError::Encode
        | ProtocolError::ProtocolIncompatible
        | ProtocolError::InvalidRequest
        | ProtocolError::IdentityBindingFailed
        | ProtocolError::ContextTooLarge
        | ProtocolError::OutputLimitExceeded
        | ProtocolError::Cancelled
        | ProtocolError::StaleFencingToken
        | ProtocolError::MalformedStructuredOutput => (
            SafeErrorClassification::InvalidInput,
            Retryability::NonRetryable,
        ),
    };
    PortError::failure(classification, retryability)
}

fn invalid_input() -> PortError {
    PortError::failure(
        SafeErrorClassification::InvalidInput,
        Retryability::NonRetryable,
    )
}

fn not_found() -> PortError {
    PortError::failure(
        SafeErrorClassification::NotFound,
        Retryability::NonRetryable,
    )
}

fn permission_denied() -> PortError {
    PortError::failure(
        SafeErrorClassification::PermissionDenied,
        Retryability::NonRetryable,
    )
}

fn conflict() -> PortError {
    PortError::failure(
        SafeErrorClassification::Conflict,
        Retryability::NonRetryable,
    )
}

fn internal_failure() -> PortError {
    PortError::failure(
        SafeErrorClassification::Internal,
        Retryability::NonRetryable,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retirement_keeps_a_reservation_until_durable_cleanup() {
        let slots = Arc::new(ConnectionSlots::default());
        let run_id = RunId::new("run-1").unwrap();
        let slot = slots
            .reserve("connection-1", "digest-1", &run_id, 1)
            .unwrap();
        slots.retire_connection("connection-1").unwrap();

        drop(slot);

        assert!(slots
            .state
            .lock()
            .unwrap()
            .runs
            .get("digest-1")
            .is_some_and(|runs| runs.contains("run-1")));
        slots.cleanup_connection("digest-1");
        assert!(!slots.state.lock().unwrap().runs.contains_key("digest-1"));
    }
}
