use std::{
    fmt,
    sync::{
        atomic::{AtomicBool, AtomicU8, Ordering},
        Arc,
    },
};

use local_agent_terminal_domain::{
    AgentCancellationReceipt, AgentDescriptor, AgentRunReceipt, AgentRunSnapshot, AgentRunTerminal,
    ArtifactId, BoundAgentRunRequest, BoundEffectiveContext, CancelAgentRun, RunId, Sha256Digest,
    TaskId, Timestamp,
};

use crate::PortError;

#[derive(Clone, Default)]
pub struct AgentRequestCancellation {
    state: Arc<AtomicBool>,
}

impl AgentRequestCancellation {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn revoke(&self) {
        self.state.store(true, Ordering::Release);
    }

    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        self.state.load(Ordering::Acquire)
    }
}

impl fmt::Debug for AgentRequestCancellation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AgentRequestCancellation")
            .field("cancelled", &self.is_cancelled())
            .finish()
    }
}

impl PartialEq for AgentRequestCancellation {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.state, &other.state)
    }
}

impl Eq for AgentRequestCancellation {}

#[derive(Clone, Default)]
pub struct AgentRequestAuditFence {
    state: Arc<AtomicU8>,
}

impl AgentRequestAuditFence {
    const OPEN: u8 = 0;
    const COMMITTING: u8 = 1;
    const REVOKED: u8 = 2;
    const FINISHED: u8 = 3;

    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Revokes an open fence and returns `true`. Returns `false` once commit has claimed the fence.
    #[must_use]
    pub fn revoke(&self) -> bool {
        match self.state.compare_exchange(
            Self::OPEN,
            Self::REVOKED,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) | Err(Self::REVOKED) => true,
            Err(Self::COMMITTING | Self::FINISHED) => false,
            Err(_) => false,
        }
    }

    /// Atomically claims authority to start the durable transaction.
    #[must_use]
    pub fn try_begin_commit(&self) -> bool {
        self.state
            .compare_exchange(
                Self::OPEN,
                Self::COMMITTING,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok()
    }

    /// Marks a claimed transaction finished, regardless of its storage result.
    pub fn finish_commit(&self) {
        let _ = self.state.compare_exchange(
            Self::COMMITTING,
            Self::FINISHED,
            Ordering::AcqRel,
            Ordering::Acquire,
        );
    }

    #[must_use]
    pub fn is_revoked(&self) -> bool {
        self.state.load(Ordering::Acquire) == Self::REVOKED
    }
}

impl fmt::Debug for AgentRequestAuditFence {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AgentRequestAuditFence")
            .field("state", &self.state.load(Ordering::Acquire))
            .finish()
    }
}

impl PartialEq for AgentRequestAuditFence {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.state, &other.state)
    }
}

impl Eq for AgentRequestAuditFence {}

pub trait AgentRuntime: Send + Sync {
    fn list_agents(&self) -> Result<Vec<AgentDescriptor>, PortError>;
    fn start_run(&self, request: BoundAgentRunRequest) -> Result<AgentRunReceipt, PortError>;
    fn cancel(&self, request: CancelAgentRun) -> Result<AgentCancellationReceipt, PortError>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentMessageArtifact {
    pub task_id: TaskId,
    pub run_id: RunId,
    pub message_id: String,
    pub content: Vec<u8>,
}

pub trait AgentArtifactStore: Send + Sync {
    fn load_effective_context(&self, context: &BoundEffectiveContext)
        -> Result<Vec<u8>, PortError>;
    fn publish_agent_message(
        &self,
        artifact: &AgentMessageArtifact,
    ) -> Result<ArtifactId, PortError>;
}

pub trait AgentRunStore: Send + Sync {
    fn register_descriptor(&self, descriptor: &AgentDescriptor) -> Result<(), PortError>;
    fn create_bound_run(
        &self,
        request: &BoundAgentRunRequest,
    ) -> Result<AgentRunSnapshot, PortError>;
    fn accept_run(&self, run_id: &RunId, accepted_at: &str) -> Result<(), PortError>;
    fn mark_running(&self, run_id: &RunId, started_at: &str) -> Result<(), PortError>;
    fn persist_terminal(&self, terminal: &AgentRunTerminal) -> Result<(), PortError>;
    fn interrupt_connection(
        &self,
        connection_digest: &str,
        at: &str,
    ) -> Result<Vec<RunId>, PortError>;
    fn load_run(&self, run_id: &RunId) -> Result<Option<AgentRunSnapshot>, PortError>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentContextQueryRequest {
    pub run_id: RunId,
    pub task_id: TaskId,
    pub connection_id: String,
    pub connection_binding_digest: Sha256Digest,
    pub phase: String,
    pub query_id: String,
    pub query: String,
    pub scopes: Vec<String>,
    pub max_items: u32,
    pub max_tokens: u64,
    pub deadline: Timestamp,
    pub cancellation: AgentRequestCancellation,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentContextQueryResponse {
    pub run_id: RunId,
    pub task_id: TaskId,
    pub query_id: String,
    pub supplement_id: String,
    pub content_digest: Sha256Digest,
    pub item_ids: Vec<String>,
    pub token_count: u64,
    pub policy_decision_ids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentSpecialistRequest {
    pub run_id: RunId,
    pub task_id: TaskId,
    pub connection_id: String,
    pub connection_binding_digest: Sha256Digest,
    pub phase: String,
    pub request_id: String,
    pub capability: String,
    pub reason: String,
    pub required_context_ids: Vec<String>,
    pub max_tokens: u64,
    pub deadline: Timestamp,
    pub cancellation: AgentRequestCancellation,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentSpecialistResponse {
    pub run_id: RunId,
    pub task_id: TaskId,
    pub request_id: String,
    pub accepted: bool,
    pub reason_code: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AgentRequestKind {
    ContextQuery,
    SpecialistRequest,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AgentRequestAuditDecision {
    Accepted,
    Rejected,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentRequestAudit {
    pub run_id: RunId,
    pub task_id: TaskId,
    pub connection_id: String,
    pub connection_binding_digest: Sha256Digest,
    pub request_id: String,
    pub kind: AgentRequestKind,
    pub request_digest: Sha256Digest,
    pub decision: AgentRequestAuditDecision,
    pub reason_code: Option<String>,
    pub deadline: Timestamp,
    pub fence: AgentRequestAuditFence,
}

pub trait AgentRequestHandler: Send + Sync {
    /// Computes a context response without durable or workflow side effects.
    ///
    /// The runtime may revoke `request.cancellation` and abandon late computation. Implementations
    /// must observe revocation and must not publish artifacts, events, or workflow transitions here.
    fn query_context(
        &self,
        request: AgentContextQueryRequest,
    ) -> Result<AgentContextQueryResponse, PortError>;

    /// Computes a specialist decision without scheduling or starting a specialist.
    ///
    /// The runtime may revoke `request.cancellation` and abandon late computation. Implementations
    /// must observe revocation; durable decisions are committed only through `persist_audit`.
    fn request_specialist(
        &self,
        request: AgentSpecialistRequest,
    ) -> Result<AgentSpecialistResponse, PortError>;

    /// Commits the final request decision durably before the runtime discloses its response.
    /// Implementations must be idempotent for the audit identity, honor `deadline`, and check
    /// `try_begin_commit` immediately before the durable transaction and `finish_commit` after it.
    /// This makes commit claim and runtime revocation mutually exclusive.
    fn persist_audit(&self, audit: AgentRequestAudit) -> Result<(), PortError>;
}
