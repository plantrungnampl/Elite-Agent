use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        mpsc::{self, RecvTimeoutError},
        Arc, Condvar, Mutex,
    },
    thread::{self, JoinHandle, ThreadId},
    time::Duration,
};

use chrono::{DateTime, Duration as ChronoDuration, Utc};
use local_agent_terminal_agent_protocol::{
    canonical_request_digest, InboundDisposition, NdjsonCodec, PeerDescriptor, PeerEventSink,
    ProtocolError, ProtocolFrame, ProtocolOffer, ProtocolPeer, ProtocolSession, ProtocolTrustTier,
    RunCancel, RunExecutionBinding, RunStart, SessionLimits, DEFAULT_MAX_FRAME_BYTES,
};
use local_agent_terminal_application::{
    AgentArtifactStore, AgentContextQueryRequest, AgentContextQueryResponse, AgentMessageArtifact,
    AgentRequestAudit, AgentRequestAuditDecision, AgentRequestAuditFence, AgentRequestCancellation,
    AgentRequestHandler, AgentRequestKind, AgentRunStore, AgentRuntime, AgentSpecialistRequest,
    AgentSpecialistResponse, Clock, PortError, ProtocolRequestStore,
    ProtocolRequestBegin, ProtocolRequestBeginResult, ProtocolRequestIdentity,
    ProtocolRequestTerminal, ProtocolRequestTerminalStatus, ProtocolResponseArtifact,
    ProtocolResponseArtifactPublisher, ProtocolStreamAdvance, ProtocolStreamIdentity,
    Retryability, SafeErrorClassification,
};
use local_agent_terminal_domain::{
    AgentCancellationReceipt, AgentClaim, AgentDescriptor, AgentRunMessage,
    AgentRunReceipt, AgentRunStatus, AgentRunTerminal, AgentUsage, ArtifactId,
    BoundAgentRunRequest, CancelAgentRun, RunId, Sha256Digest, Timestamp, TrustTier,
    Sequence,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

pub const DEFAULT_HEARTBEAT_TIMEOUT_SECS: i64 = 30;
pub const DEFAULT_RUN_DEADLINE_SECS: i64 = 300;
pub(crate) const MAX_OUTPUT_BYTES: usize = 64 * 1024;

pub struct ProtocolAgentRuntime {
    store: Arc<dyn AgentRunStore>,
    artifacts: Arc<dyn AgentArtifactStore>,
    protocol_requests: Arc<dyn ProtocolRequestStore>,
    response_artifacts: Arc<dyn ProtocolResponseArtifactPublisher>,
    clock: Arc<dyn Clock>,
    request_handler: Arc<dyn AgentRequestHandler>,
    request_routing_enabled: bool,
    peers: BTreeMap<String, Arc<dyn ProtocolPeer>>,
    descriptors: BTreeMap<String, AgentDescriptor>,
    authoritative_connection_digests: BTreeMap<String, Sha256Digest>,
    sessions: Arc<Mutex<BTreeMap<String, Arc<Mutex<ProtocolSession>>>>>,
    active_runs: Arc<Mutex<BTreeMap<String, ActiveRun>>>,
    slots: Arc<ConnectionSlots>,
    pending_run_cleanups: Mutex<BTreeMap<String, PendingCleanup>>,
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
    request_gate: Arc<Mutex<()>>,
    cancellation: AgentRequestCancellation,
}

struct PendingCleanup {
    request: BoundAgentRunRequest,
    content_artifact_id: Option<ArtifactId>,
}

#[derive(Default)]
struct RunRequestState {
    context_queries: u64,
    specialist_requests: u64,
    context_query_ids: BTreeSet<String>,
}

struct DenyAgentRequestHandler;

impl AgentRequestHandler for DenyAgentRequestHandler {
    fn query_context(
        &self,
        _request: AgentContextQueryRequest,
    ) -> Result<AgentContextQueryResponse, PortError> {
        Err(permission_denied())
    }

    fn request_specialist(
        &self,
        _request: AgentSpecialistRequest,
    ) -> Result<AgentSpecialistResponse, PortError> {
        Err(permission_denied())
    }

    fn persist_audit(&self, _audit: AgentRequestAudit) -> Result<(), PortError> {
        Ok(())
    }
}

#[derive(Default)]
struct ConnectionSlots {
    state: Mutex<ConnectionSlotState>,
}

#[derive(Default)]
struct ConnectionSlotState {
    connections: BTreeMap<String, ConnectionLifecycle>,
}

struct ConnectionLifecycle {
    binding_digest: Option<String>,
    handshake: Arc<Mutex<()>>,
    generation: u64,
    phase: ConnectionPhase,
    capacity: u64,
    reservations: BTreeSet<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ConnectionPhase {
    Healthy,
    Poisoned { token: u64 },
    Retired,
}

#[derive(Clone)]
struct ConnectionPoison {
    connection_id: String,
    binding_digest: String,
    generation: u64,
    token: u64,
}

enum ConnectionCleanup {
    Poisoned(ConnectionPoison),
    Retired {
        connection_id: String,
        binding_digest: String,
        generation: u64,
    },
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
        if !state.connections.contains_key(connection_id) {
            state.connections.insert(
                connection_id.to_owned(),
                ConnectionLifecycle {
                    binding_digest: Some(connection_digest.to_owned()),
                    handshake: Arc::new(Mutex::new(())),
                    generation: 0,
                    phase: ConnectionPhase::Healthy,
                    capacity,
                    reservations: BTreeSet::new(),
                },
            );
        }
        let lifecycle = state
            .connections
            .get_mut(connection_id)
            .ok_or_else(internal_failure)?;
        if lifecycle.phase != ConnectionPhase::Healthy
            || lifecycle.binding_digest.as_deref() != Some(connection_digest)
            || lifecycle.capacity != capacity
            || u64::try_from(lifecycle.reservations.len()).map_err(|_| internal_failure())?
                >= lifecycle.capacity
            || !lifecycle.reservations.insert(run_id.as_str().to_owned())
        {
            return Err(conflict());
        }
        Ok(RunSlot(Arc::new(RunSlotInner {
            slots: Arc::clone(self),
            connection_id: connection_id.to_owned(),
            connection_digest: connection_digest.to_owned(),
            generation: lifecycle.generation,
            run_id: run_id.as_str().to_owned(),
            released: AtomicBool::new(false),
        })))
    }

    fn release(&self, slot: &RunSlotInner) {
        if let Ok(mut state) = self.state.lock() {
            if let Some(lifecycle) = state.connections.get_mut(&slot.connection_id) {
                if lifecycle.binding_digest.as_deref() == Some(&slot.connection_digest)
                    && lifecycle.generation == slot.generation
                    && lifecycle.phase == ConnectionPhase::Healthy
                {
                    lifecycle.reservations.remove(&slot.run_id);
                }
            }
        }
    }

    fn complete_cleanup(&self, poison: &ConnectionPoison) -> Result<(), PortError> {
        let mut state = self.state.lock().map_err(|_| internal_failure())?;
        let Some(lifecycle) = state.connections.get_mut(&poison.connection_id) else {
            return Ok(());
        };
        if lifecycle.binding_digest.as_deref() == Some(&poison.binding_digest)
            && lifecycle.generation == poison.generation
            && lifecycle.phase
                == (ConnectionPhase::Poisoned {
                    token: poison.token,
                })
        {
            lifecycle.generation = next_generation(lifecycle.generation)?;
            lifecycle.phase = ConnectionPhase::Healthy;
            lifecycle.reservations.clear();
        }
        Ok(())
    }

    fn poison_connection(&self, connection_digest: &str) -> Result<ConnectionPoison, PortError> {
        let handshake = self.handshake_for_digest(connection_digest)?;
        let _handshake = handshake.lock().map_err(|_| internal_failure())?;
        self.mark_poisoned(connection_digest)
    }

    fn mark_poisoned(&self, connection_digest: &str) -> Result<ConnectionPoison, PortError> {
        let mut state = self.state.lock().map_err(|_| internal_failure())?;
        let (connection_id, lifecycle) = state
            .connections
            .iter_mut()
            .find(|(_, lifecycle)| lifecycle.binding_digest.as_deref() == Some(connection_digest))
            .ok_or_else(internal_failure)?;
        match lifecycle.phase {
            ConnectionPhase::Healthy => {
                lifecycle.generation = next_generation(lifecycle.generation)?;
                lifecycle.phase = ConnectionPhase::Poisoned {
                    token: lifecycle.generation,
                };
                lifecycle.reservations.clear();
            }
            ConnectionPhase::Poisoned { .. } => {}
            ConnectionPhase::Retired => return Err(conflict()),
        }
        let ConnectionPhase::Poisoned { token } = lifecycle.phase else {
            return Err(internal_failure());
        };
        Ok(ConnectionPoison {
            connection_id: connection_id.clone(),
            binding_digest: connection_digest.to_owned(),
            generation: lifecycle.generation,
            token,
        })
    }

    fn retire_connection(&self, connection_id: &str) -> Result<(), PortError> {
        let handshake = {
            let mut state = self.state.lock().map_err(|_| internal_failure())?;
            if !state.connections.contains_key(connection_id) {
                state.connections.insert(
                    connection_id.to_owned(),
                    ConnectionLifecycle {
                        binding_digest: None,
                        handshake: Arc::new(Mutex::new(())),
                        generation: 1,
                        phase: ConnectionPhase::Retired,
                        capacity: 0,
                        reservations: BTreeSet::new(),
                    },
                );
            }
            let lifecycle = state
                .connections
                .get_mut(connection_id)
                .ok_or_else(internal_failure)?;
            if lifecycle.phase != ConnectionPhase::Retired {
                lifecycle.generation = next_generation(lifecycle.generation)?;
                lifecycle.phase = ConnectionPhase::Retired;
                lifecycle.reservations.clear();
            }
            Arc::clone(&lifecycle.handshake)
        };
        drop(handshake.lock().map_err(|_| internal_failure())?);
        Ok(())
    }

    fn start_handshake<T>(
        &self,
        slot: &RunSlot,
        start: impl FnOnce() -> T,
    ) -> Result<T, PortError> {
        let handshake = {
            let state = self.state.lock().map_err(|_| internal_failure())?;
            let lifecycle = state
                .connections
                .get(&slot.0.connection_id)
                .ok_or_else(internal_failure)?;
            if !slot_matches(lifecycle, &slot.0) {
                return Err(conflict());
            }
            Arc::clone(&lifecycle.handshake)
        };
        let _handshake = handshake.lock().map_err(|_| internal_failure())?;
        {
            let state = self.state.lock().map_err(|_| internal_failure())?;
            let lifecycle = state
                .connections
                .get(&slot.0.connection_id)
                .ok_or_else(internal_failure)?;
            if !slot_matches(lifecycle, &slot.0) {
                return Err(conflict());
            }
        }
        Ok(start())
    }

    fn interrupt<T>(
        &self,
        connection_digest: &str,
        action: impl FnOnce(&ConnectionCleanup) -> Result<T, PortError>,
    ) -> Result<T, PortError> {
        let handshake = self.handshake_for_digest(connection_digest)?;
        let _handshake = handshake.lock().map_err(|_| internal_failure())?;
        let cleanup = self.cleanup_token(connection_digest)?;
        action(&cleanup)
    }

    fn retry_poison<T>(
        &self,
        poison: &ConnectionPoison,
        action: impl FnOnce() -> Result<T, PortError>,
    ) -> Result<Option<T>, PortError> {
        let handshake = {
            let state = self.state.lock().map_err(|_| internal_failure())?;
            let Some(lifecycle) = state.connections.get(&poison.connection_id) else {
                return Ok(None);
            };
            Arc::clone(&lifecycle.handshake)
        };
        let _handshake = handshake.lock().map_err(|_| internal_failure())?;
        {
            let state = self.state.lock().map_err(|_| internal_failure())?;
            let Some(lifecycle) = state.connections.get(&poison.connection_id) else {
                return Ok(None);
            };
            if lifecycle.binding_digest.as_deref() != Some(&poison.binding_digest)
                || lifecycle.generation != poison.generation
                || lifecycle.phase
                    != (ConnectionPhase::Poisoned {
                        token: poison.token,
                    })
            {
                return Ok(None);
            }
        }
        action().map(Some)
    }

    fn cleanup_token(&self, connection_digest: &str) -> Result<ConnectionCleanup, PortError> {
        let mut state = self.state.lock().map_err(|_| internal_failure())?;
        let (connection_id, lifecycle) = state
            .connections
            .iter_mut()
            .find(|(_, lifecycle)| lifecycle.binding_digest.as_deref() == Some(connection_digest))
            .ok_or_else(internal_failure)?;
        match lifecycle.phase {
            ConnectionPhase::Healthy => {
                lifecycle.generation = next_generation(lifecycle.generation)?;
                lifecycle.phase = ConnectionPhase::Poisoned {
                    token: lifecycle.generation,
                };
                lifecycle.reservations.clear();
                Ok(ConnectionCleanup::Poisoned(ConnectionPoison {
                    connection_id: connection_id.clone(),
                    binding_digest: connection_digest.to_owned(),
                    generation: lifecycle.generation,
                    token: lifecycle.generation,
                }))
            }
            ConnectionPhase::Poisoned { token } => {
                Ok(ConnectionCleanup::Poisoned(ConnectionPoison {
                    connection_id: connection_id.clone(),
                    binding_digest: connection_digest.to_owned(),
                    generation: lifecycle.generation,
                    token,
                }))
            }
            ConnectionPhase::Retired => Ok(ConnectionCleanup::Retired {
                connection_id: connection_id.clone(),
                binding_digest: connection_digest.to_owned(),
                generation: lifecycle.generation,
            }),
        }
    }

    fn complete_interruption(&self, cleanup: &ConnectionCleanup) -> Result<(), PortError> {
        match cleanup {
            ConnectionCleanup::Poisoned(poison) => self.complete_cleanup(poison),
            ConnectionCleanup::Retired {
                connection_id,
                binding_digest,
                generation,
            } => {
                let mut state = self.state.lock().map_err(|_| internal_failure())?;
                if let Some(lifecycle) = state.connections.get_mut(connection_id) {
                    if lifecycle.binding_digest.as_deref() == Some(binding_digest)
                        && lifecycle.generation == *generation
                        && lifecycle.phase == ConnectionPhase::Retired
                    {
                        lifecycle.reservations.clear();
                    }
                }
                Ok(())
            }
        }
    }

    fn handshake_for_digest(&self, connection_digest: &str) -> Result<Arc<Mutex<()>>, PortError> {
        let state = self.state.lock().map_err(|_| internal_failure())?;
        state
            .connections
            .values()
            .find(|lifecycle| lifecycle.binding_digest.as_deref() == Some(connection_digest))
            .map(|lifecycle| Arc::clone(&lifecycle.handshake))
            .ok_or_else(internal_failure)
    }

    fn known_digests(&self) -> Result<BTreeSet<String>, PortError> {
        Ok(self
            .state
            .lock()
            .map_err(|_| internal_failure())?
            .connections
            .values()
            .filter_map(|lifecycle| lifecycle.binding_digest.clone())
            .collect())
    }

    fn poisoned_connections(&self) -> Result<Vec<ConnectionPoison>, PortError> {
        let state = self.state.lock().map_err(|_| internal_failure())?;
        Ok(state
            .connections
            .iter()
            .filter_map(|(connection_id, lifecycle)| {
                let ConnectionPhase::Poisoned { token } = lifecycle.phase else {
                    return None;
                };
                Some(ConnectionPoison {
                    connection_id: connection_id.clone(),
                    binding_digest: lifecycle.binding_digest.clone()?,
                    generation: lifecycle.generation,
                    token,
                })
            })
            .collect())
    }
}

fn next_generation(generation: u64) -> Result<u64, PortError> {
    generation.checked_add(1).ok_or_else(internal_failure)
}

fn slot_matches(lifecycle: &ConnectionLifecycle, slot: &RunSlotInner) -> bool {
    lifecycle.binding_digest.as_deref() == Some(&slot.connection_digest)
        && lifecycle.generation == slot.generation
        && lifecycle.phase == ConnectionPhase::Healthy
        && lifecycle.reservations.contains(&slot.run_id)
}

#[derive(Clone)]
struct RunSlot(Arc<RunSlotInner>);

struct RunSlotInner {
    slots: Arc<ConnectionSlots>,
    connection_id: String,
    connection_digest: String,
    generation: u64,
    run_id: String,
    released: AtomicBool,
}

impl RunSlot {
    fn release(&self) {
        if !self.0.released.swap(true, Ordering::AcqRel) {
            self.0.slots.release(&self.0);
        }
    }
}

impl Drop for RunSlotInner {
    fn drop(&mut self) {
        if !self.released.load(Ordering::Acquire) {
            self.slots.release(self);
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
