#![forbid(unsafe_code)]

pub use local_agent_terminal_domain::{
    ActorId, ArtifactId, FencingToken, GitObjectId, LeaseClaim, Phase, ProjectId, RepositoryId,
    RunId, Sequence, TaskBranch, TaskId, WorkspaceFingerprint, WorkspaceVersion, WorktreeId,
};

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
    WorkspaceEvidenceStore, WorkspaceMutationStore,
};
pub use repository::{
    CreateWorktree, DiscardWorktree, ExpectedPresence, InspectRepository, InspectWorktree,
    ManagedWorktreePath, ObjectFormat, OnboardRepository, OriginalCheckoutState, RepositoryGateway,
    RepositoryHazard, RepositoryHazardReason, RepositoryHealth, RepositoryLocator,
    RepositorySnapshot, WorktreeObservation, WorktreeSnapshot, WorktreeState,
};
pub use workspace::{
    ArtifactRootMode, GetWorkspaceDashboard, IdempotencyClass, IntentTransition, NewProject,
    NewTask, ObserveWorkspaceMutation, OperationIntent, OperationIntentStatus,
    PrepareTaskWorkspace, ProjectSettings, ProjectSnapshot, ReconcileWorkspaces, RecoveryAction,
    RecoveryCandidate, RecoveryEvidence, RecoveryProject, RecoveryReason,
    RepositoryInspectionRecord, RiskLevel, StartedRecovery, TaskLeaseState, TaskSnapshot,
    WorkspaceMutationRequest, WorkspaceMutationResult, WorkspaceRecoveryStore, WorkspaceStateStore,
    WorkspaceWriteCoordinator, WorkspaceWritePermit, WorktreeIntent, WorktreeMatch,
};
