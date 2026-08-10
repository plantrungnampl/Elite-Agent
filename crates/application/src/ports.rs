use std::path::Path;

use local_agent_terminal_domain::{
    ActorId, ArtifactId, EventId, Sequence, StreamId, TaskId, WorkflowEvent, WorkflowState,
};
use serde_json::Value;

use crate::{
    CanonicalEvidenceRef, PortError, TaskSnapshot, TimelineEntryDto, WorkspaceMutationRequest,
    WorkspaceMutationResult, WorkspaceObservationLossRequest,
};

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

pub trait WorkspaceMutationStore: Send + Sync {
    fn record_workspace_mutation(
        &self,
        request: WorkspaceMutationRequest,
    ) -> Result<WorkspaceMutationResult, PortError>;

    fn record_workspace_observation_loss(
        &self,
        request: WorkspaceObservationLossRequest,
    ) -> Result<(), PortError>;
}

pub trait WorkspaceEvidenceStore: Send + Sync {
    fn available_evidence(
        &self,
        artifact_id: &ArtifactId,
    ) -> Result<Option<CanonicalEvidenceRef>, PortError>;
}

pub trait TaskQuery: Send + Sync {
    fn task(&self, task_id: &TaskId) -> Result<TaskSnapshot, PortError>;
    fn timeline(&self, task_id: &TaskId) -> Result<Vec<TimelineEntryDto>, PortError>;
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

pub trait ArtifactRootReader: Send + Sync {
    fn read_from_root(
        &self,
        root: &Path,
        reference: &ArtifactRef,
    ) -> Result<ArtifactContent, PortError>;
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
pub struct ReservedArtifact {
    pub artifact_id: String,
    pub task_id: Option<TaskId>,
    pub project_id: String,
    pub artifact_type: String,
    pub logical_path: String,
    pub content_hash: String,
    pub storage_key: String,
    pub size_bytes: u64,
    pub mime_type: Option<String>,
    pub created_by_type: String,
    pub created_by_id: String,
    pub created_at: String,
    pub supersedes: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArtifactWriteReservation {
    pub operation_id: String,
    pub artifact: ReservedArtifact,
    pub temp_name: String,
    pub created_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArtifactJournalEntry {
    pub reservation: ArtifactWriteReservation,
    pub expected_hash: String,
    pub expected_size: u64,
    pub status: ArtifactJournalStatus,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArtifactUnavailableState {
    Missing,
    Quarantined,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArtifactJournalInvalidation {
    pub operation_id: String,
    pub unavailable_state: ArtifactUnavailableState,
    pub updated_at: String,
    pub error: Value,
}

pub trait ArtifactJournal: Send + Sync {
    /// Atomically creates reserved artifact metadata and its write intent.
    fn reserve(&self, reservation: ArtifactWriteReservation) -> Result<(), PortError>;
    fn transition(&self, transition: ArtifactJournalTransition) -> Result<(), PortError>;
    fn incomplete(&self) -> Result<Vec<ArtifactJournalEntry>, PortError>;
    fn completed(&self) -> Result<Vec<ArtifactJournalEntry>, PortError>;
    /// Records failed verification without inventing a new successful transition.
    fn invalidate_completed(
        &self,
        invalidation: ArtifactJournalInvalidation,
    ) -> Result<(), PortError>;
}

pub trait Clock: Send + Sync {
    fn now_utc(&self) -> Result<String, PortError>;
}

pub trait IdGenerator: Send + Sync {
    fn next_id(&self) -> Result<String, PortError>;
}
