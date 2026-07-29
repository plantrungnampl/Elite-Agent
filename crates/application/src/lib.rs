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
pub use policy::{
    bind_disclosure_channel, parse_policy_timestamp, DisclosureChannel, DisclosureContextProvider,
    DisclosureContextRequest, DisclosureOutcome, DisclosurePolicyEvaluator, DisclosureRequest,
    PolicyApprovalBinding, PolicyApprovedDisclosure, PolicyBoundBytes, PolicyDecision,
    PolicyDecisionId, PolicyDecisionStore, PolicyEvaluator, RecordedPolicyDecision,
    TrustedDisclosureContext,
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
pub use tool::{
    bind_tool_approval_payload, canonical_file_write_recovery_request,
    parse_file_write_recovery_request, ApprovedExecutableIdentity, ApprovedProcessExecutor,
    ApprovedProcessRequest, AuthorizedFileRead, AuthorizedFileWrite, AuthorizedGitDiff,
    AuthorizedGitStatus, AuthorizedProcessRequest, AuthorizedToolRequest, BoundToolApproval,
    BoundedOutput, CancellationReceipt, CanonicalFileWriteRecoveryRequest,
    CapabilityFileWriteSession, CapabilityFileWriteSessionFactory, CapabilityFilesystem,
    CapabilityRequest, CapabilityResolver, CapabilityRootIdentity, CaptureFileWritePostEvidence,
    CaptureFileWritePreEvidence, DirectoryFileIdentity, EnforcedNetworkProfile,
    EnvironmentProfileResolver, ExecutableArtifactInspector, ExecutableFileIdentity,
    ExecutableProfileResolver, ExecutableVerificationGuard, FileReadRequest,
    FileWriteEvidenceStore, FileWritePolicyBinding, FileWritePostExpectation, FileWritePreImage,
    FileWriteRecoveryCompletion, FileWriteRecoveryFailure, FileWriteRecoveryIntent,
    FileWriteRecoveryRequest, FileWriteRecoverySnapshot, FileWriteRecoveryState,
    FileWriteRecoveryStore, FileWriteRequest, GitDiffRequest, GitDiffResult, GitStatusRequest,
    GitStatusResult, JobReceipt, NetworkEnforcementReceipt, NetworkProfileVerifier,
    NewToolExecution, NewToolIntent, ObservedFileImage, OpenFileWriteSession,
    OperationIntentSnapshot, PrivateRuntimeDirectoryInspector,
    PrivateRuntimeDirectoryVerificationGuard, ProcessLauncher, ProcessLimits, ProcessReceipt,
    ProcessStatus, ProcessWorkingDirectory, RawGitDiffResult, RawGitStatusResult,
    RelativePathComponents, ResolvedCapability, ResolvedCapabilityTarget,
    ResolvedEnvironmentProfile, ResolvedExecutable, ResolvedPrivateRuntimeDirectory, StructuredGit,
    StructuredToolExecutor, ToolExecutionCompletion, ToolExecutionId, ToolExecutionResult,
    ToolExecutionSnapshot, ToolExecutionStore, ToolRequestBindingDigest, VerifiedBytes,
    VerifiedFileWriteCompensation, VerifiedWrite,
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
