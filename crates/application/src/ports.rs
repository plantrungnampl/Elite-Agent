use local_agent_terminal_domain::{
    ActorId, EventId, Sequence, StreamId, TaskId, WorkflowEvent, WorkflowState,
};
use serde_json::Value;

use crate::PortError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewEvent {
    pub event_id: EventId,
    pub event_type: WorkflowEvent,
    pub schema_version: u32,
    pub actor_type: String,
    pub actor_id: ActorId,
    pub observation_class: String,
    pub payload: Value,
    pub metadata: Value,
    pub causation_id: Option<String>,
    pub correlation_id: String,
    pub created_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProjectionChange {
    TaskState {
        task_id: TaskId,
        state: WorkflowState,
        updated_at: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppendOperation {
    pub stream_id: StreamId,
    pub expected_version: Sequence,
    pub events: Vec<NewEvent>,
    pub projection_changes: Vec<ProjectionChange>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AppendResult {
    pub new_version: Sequence,
}

pub trait EventStore: Send + Sync {
    fn append(&self, operation: AppendOperation) -> Result<AppendResult, PortError>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewArtifact {
    pub expected_hash: String,
    pub expected_size: u64,
    pub content: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArtifactRef {
    pub content_hash: String,
    pub storage_key: String,
    pub size_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArtifactContent {
    pub bytes: Vec<u8>,
}

pub trait ArtifactStore: Send + Sync {
    fn put(&self, artifact: NewArtifact) -> Result<ArtifactRef, PortError>;
    fn read(&self, reference: &ArtifactRef) -> Result<ArtifactContent, PortError>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArtifactJournalStatus {
    Intent,
    Staging,
    Renamed,
    Completed,
    Aborted,
    Quarantined,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArtifactJournalEntry {
    pub operation_id: String,
    pub artifact_id: String,
    pub temp_name: String,
    pub expected_hash: String,
    pub expected_size: u64,
    pub status: ArtifactJournalStatus,
    pub created_at: String,
    pub updated_at: String,
    pub completed_at: Option<String>,
    pub error: Option<Value>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArtifactJournalTransition {
    pub operation_id: String,
    pub expected_status: ArtifactJournalStatus,
    pub next_status: ArtifactJournalStatus,
    pub updated_at: String,
    pub completed_at: Option<String>,
    pub error: Option<Value>,
}

pub trait ArtifactJournal: Send + Sync {
    fn record_intent(&self, entry: ArtifactJournalEntry) -> Result<(), PortError>;
    fn transition(&self, transition: ArtifactJournalTransition) -> Result<(), PortError>;
    fn incomplete(&self) -> Result<Vec<ArtifactJournalEntry>, PortError>;
}

pub trait Clock: Send + Sync {
    fn now_utc(&self) -> Result<String, PortError>;
}

pub trait IdGenerator: Send + Sync {
    fn next_id(&self) -> Result<String, PortError>;
}
