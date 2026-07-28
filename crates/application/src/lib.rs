#![forbid(unsafe_code)]

pub use local_agent_terminal_domain::{
    ActorId, ArtifactId, FencingToken, GitObjectId, LeaseClaim, Phase, ProjectId, RepositoryId,
    RunId, Sequence, TaskBranch, TaskId, WorkspaceFingerprint, WorkspaceVersion, WorktreeId,
};

mod append_events;
mod approval;
mod canonical_json;
mod dto;
mod error;
mod execute_tool;
mod lease;
mod policy;
mod ports;
mod repository;
mod tool;
mod workspace;

pub use append_events::AppendEvents;
pub use approval::{
    build_approval_request, canonical_approval_payload, parse_approval_payload, ApprovalCheck,
    ApprovalClaim, ApprovalDigestPayload, ApprovalId, ApprovalInvalidation, ApprovalRequestBuild,
    ApprovalResolution, ApprovalSnapshot, ApprovalState, ApprovalStore, CanonicalApprovalPayload,
    NewApproval, PolicyExceptionApprovalOperationV1, PolicyExceptionApprovalPayloadV1,
    ToolApprovalOperationV1, ToolApprovalPayloadV1,
};
pub use canonical_json::{canonical_evidence, CanonicalEvidenceRef, CanonicalJsonRequest};
pub use dto::{
    ApprovalRequestDto, ApproveOperationRequestDto, CancelToolExecutionRequestDto, CommandErrorDto,
    ConfirmDiscardWorkspaceRequestDto, CreateTaskWorkspaceRequestDto, DiagnosticSeverityDto,
    EvidenceSummaryDto, LocalDiagnosticDto, ObservationClassDto, OnboardRepositoryRequestDto,
    RecoveryActionCodeDto, RecoveryActionDto, RecoveryCandidateRequestDto, StartupIssueDto,
    StartupRecoveryActionDto, StartupStateDto, StartupStatusDto, TimelineEntryDto, TrustLabelDto,
    WorkspaceDashboardDto, WorkspaceDashboardRequestDto,
};
pub use error::{PortError, Retryability, SafeErrorClassification};
pub use execute_tool::ExecuteApprovedTool;
pub use lease::{
    AcquireExecutorLease, AcquireLease, ExecutorLeaseStore, LeaseSnapshot, LeaseState, RevokeLease,
};
pub use policy::{PolicyDecision, PolicyDecisionStore, PolicyEvaluator, RecordedPolicyDecision};
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
pub use tool::{
    bind_tool_approval_payload, AuthorizedFileRead, AuthorizedFileWrite, AuthorizedGitDiff,
    AuthorizedGitStatus, AuthorizedProcessRequest, AuthorizedToolRequest, BoundToolApproval,
    CancellationReceipt, CapabilityFilesystem, CapabilityRequest, CapabilityResolver,
    CapabilityRootIdentity, FileReadRequest, FileWriteRequest, GitDiffResult, GitStatusResult,
    NewToolExecution, NewToolIntent, OperationIntentSnapshot, ProcessLauncher, ProcessReceipt,
    RelativePathComponents, ResolvedCapability, StructuredGit, StructuredToolExecutor,
    ToolExecutionCompletion, ToolExecutionId, ToolExecutionResult, ToolExecutionSnapshot,
    ToolExecutionStore, ToolRequestBindingDigest, VerifiedBytes, VerifiedWrite,
};
pub use workspace::{
    ArtifactRootMode, GetWorkspaceDashboard, IdempotencyClass, IntentTransition, NewProject,
    NewTask, ObserveWorkspaceMutation, OperationIntent, OperationIntentStatus,
    PrepareTaskWorkspace, ProjectSettings, ProjectSnapshot, ReconcileWorkspaces, RecoveryAction,
    RecoveryCandidate, RecoveryEvidence, RecoveryOperationIntent, RecoveryProject, RecoveryReason,
    RepositoryInspectionRecord, RiskLevel, StartedRecovery, TaskLeaseState, TaskSnapshot,
    WorkspaceMutationRequest, WorkspaceMutationResult, WorkspaceObservationLossRequest,
    WorkspaceRecoveryStore, WorkspaceStateStore, WorkspaceWriteCoordinator, WorkspaceWritePermit,
    WorktreeIntent, WorktreeMatch,
};
