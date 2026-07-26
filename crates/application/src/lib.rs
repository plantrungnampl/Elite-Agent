#![forbid(unsafe_code)]

mod append_events;
mod canonical_json;
mod dto;
mod error;
mod lease;
mod ports;
mod repository;
mod workspace;

pub use append_events::AppendEvents;
pub use canonical_json::{canonical_evidence, CanonicalEvidenceRef, CanonicalJsonRequest};
pub use dto::{
    DiagnosticSeverityDto, EvidenceSummaryDto, LocalDiagnosticDto, ObservationClassDto,
    RecoveryActionDto, StartupIssueDto, StartupStateDto, StartupStatusDto, TimelineEntryDto,
    TrustLabelDto, WorkspaceDashboardDto,
};
pub use error::{PortError, Retryability, SafeErrorClassification};
pub use lease::{
    AcquireExecutorLease, AcquireLease, ExecutorLeaseStore, LeaseSnapshot, LeaseState, RevokeLease,
};
pub use ports::{
    AppendOperation, AppendResult, ArtifactContent, ArtifactJournal, ArtifactJournalEntry,
    ArtifactJournalInvalidation, ArtifactJournalStatus, ArtifactJournalTransition, ArtifactRef,
    ArtifactStore, ArtifactUnavailableState, ArtifactWriteReservation, Clock, EventStore,
    IdGenerator, NewArtifact, NewEvent, ProjectionChange, ReservedArtifact, TaskQuery,
    WorkspaceMutationStore,
};
pub use repository::{
    CreateWorktree, DiscardWorktree, ExpectedPresence, InspectRepository, ManagedWorktreePath,
    ObjectFormat, OnboardRepository, OriginalCheckoutState, RepositoryGateway, RepositoryHazard,
    RepositoryHazardReason, RepositoryHealth, RepositoryLocator, RepositorySnapshot,
    WorktreeSnapshot, WorktreeState,
};
pub use workspace::{
    GetWorkspaceDashboard, IdempotencyClass, IntentTransition, NewProject, NewTask,
    ObserveWorkspaceMutation, OperationIntent, OperationIntentStatus, PrepareTaskWorkspace,
    ProjectSnapshot, ReconcileWorkspaces, RecoveryAction, RecoveryCandidate, RecoveryEvidence,
    RecoveryReason, TaskLeaseState, TaskSnapshot, WorkspaceMutationRequest,
    WorkspaceMutationResult, WorkspaceStateStore, WorktreeIntent, WorktreeMatch,
};
