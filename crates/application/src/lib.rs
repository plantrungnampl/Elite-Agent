#![forbid(unsafe_code)]

pub use local_agent_terminal_domain::{
    ActorId, ActorLocality, AgentCancellationReceipt, AgentClaim, AgentDescriptor, AgentError,
    AgentEvidenceRef, AgentRunLimits, AgentRunMessage, AgentRunReceipt, AgentRunSnapshot,
    AgentRunStatus, AgentRunTerminal, AgentUsage, ArtifactId, BoundAgentConnection,
    BoundAgentRunRequest, BoundEffectiveContext, BoundGenerationParameters, BoundRunConfig,
    CancelAgentRun, ContextBudget, ContextError, ContextPackageArtifact, ContextPackageBinding,
    ContextPackageDescriptor, ContextPackageIdentity, ContextPackageMember, ContextVersionSet,
    DeliberationError, FencingToken, GitObjectId, LeaseClaim, LineRange, Phase, PolicyAction,
    PolicyActor, PolicyDecisionSet, PolicyResource, ProjectId, RepositoryId, ResourceClass, RunId,
    Sequence, Sha256Digest, SourceIdentity, TaskBranch, TaskId, TaskRisk, TrustTier,
    WorkspaceFingerprint, WorkspaceVersion, WorktreeId, MAX_GENERATION_PARAMETERS_BYTES,
};

mod agent;
mod append_events;
mod approval;
mod authority;
mod canonical_json;
mod context;
mod deliberation;
mod deliberation_recovery;
mod dto;
mod error;
mod execute_tool;
mod lease;
mod orchestration;
mod plan_approval;
mod policy;
mod ports;
mod repository;
mod resume;
mod tool;
mod workspace;

pub use agent::{
    AgentArtifactStore, AgentContextQueryRequest, AgentContextQueryResponse, AgentMessageArtifact,
    AgentRequestAudit, AgentRequestAuditDecision, AgentRequestAuditFence, AgentRequestCancellation,
    AgentRequestHandler, AgentRequestKind, AgentRunStore, AgentRuntime, AgentSpecialistRequest,
    AgentSpecialistResponse,
};
pub use append_events::AppendEvents;
pub use approval::{
    build_approval_request, canonical_approval_payload, parse_approval_payload,
    parse_canonical_approval_payload, ApprovalCheck, ApprovalClaim, ApprovalDigestPayload,
    ApprovalExpiryStore, ApprovalId, ApprovalInvalidation, ApprovalRequestBuild,
    ApprovalResolution, ApprovalSnapshot, ApprovalState, ApprovalStore, CanonicalApprovalPayload,
    NewApproval, PlanApprovalOperationV1, PlanApprovalPathScopeV1, PlanApprovalPayloadV1,
    PlanApprovalPlanRefV1, PolicyExceptionApprovalOperationV1, PolicyExceptionApprovalPayloadV1,
    ToolApprovalOperationV1, ToolApprovalPayloadV1, ToolApprovalPublication, ToolApprovalRequest,
    ToolApprovalRequestPublisher,
};
pub use authority::{
    validate_authoritative_tool_request, ToolAuthorityResolver, ToolAuthoritySnapshot,
};
pub use canonical_json::{canonical_evidence, CanonicalEvidenceRef, CanonicalJsonRequest};
pub use context::{
    BuildInitialContext, BuildInitialContextRequest, ContextArtifactKind, ContextArtifactPublisher,
    ContextArtifactReader, ContextArtifactRef, ContextBuildPolicy, ContextChunkRecord,
    ContextClassificationOutcome, ContextIndexProvenance, ContextIndexProvenanceRehydration,
    ContextLogicalIdentity, ContextPackageDraft, ContextPackagePersistence, ContextPackageRecord,
    ContextPolicyDecisionRef, ContextQuery, ContextSensitivity, ContextSourceClassification,
    ContextSourceClassifier, ContextSourceKind, ContextSourceRecord, ContextSourceState,
    ContextStore, ImmutableContextArtifact, QueryContext, QueryContextRequest,
    RepositoryContextSource, RetrievedContextItem, SourceClassificationRequest,
    SourceIndexMetadata, SourceSnapshot, SourceSnapshotItem, SourceSnapshotRequest,
    SourceStateTransition,
};
pub use deliberation::{
    ClaimSetSnapshot, DecisionDraftSnapshot, DeliberationArtifactRef, DeliberationCommandContext,
    DeliberationCommands, DeliberationPersistenceCommand, DeliberationRecord,
    DeliberationRunAssignment, DeliberationSnapshot, DeliberationStore,
    ObjectionRoundClosedSnapshot, ObjectionSetSnapshot, PlanApprovalAuthorityProvider,
    PrivateProposalSnapshot, QuorumPublicationSnapshot, ReviewEdgesSnapshot,
    SevereObjectionAcceptanceSnapshot, SpecialistRequestSnapshot, SupersessionSnapshot,
    ThreadSummarySnapshot, VerificationSetSnapshot,
};
pub use deliberation_recovery::{
    recover_deliberation, CanonicalDeliberationFact, DeliberationRecoveryInput,
};
pub use dto::{
    present_tool_activity_record, tool_request_context, ApprovalRequestDto,
    ApproveOperationRequestDto, CancelToolExecutionRequestDto, CommandErrorDto,
    ConfirmDiscardWorkspaceRequestDto, ContextPackageDto, CreateTaskWorkspaceRequestDto,
    DeliberationWorkspaceDto, DiagnosticSeverityDto, EvidenceSummaryDto, GetApprovalRequestDto,
    LocalDiagnosticDto, ObservationClassDto, OnboardRepositoryRequestDto, RecoveryActionCodeDto,
    RecoveryActionDto, RecoveryCandidateRequestDto, ResolvePlanApprovalRequestDto,
    ResolveToolApprovalRequestDto, StartupIssueDto, StartupRecoveryActionDto, StartupStateDto,
    StartupStatusDto, StopAllToolsReceiptDto, TimelineEntryDto, ToolActivityDto,
    ToolActivityEntryDto, ToolActivityRecord, ToolActivityStatusDto, ToolApprovalDecisionDto,
    ToolApprovalRequestDto, ToolApprovalResolutionDto, ToolCancellationReceiptDto,
    ToolRedactionStateDto, ToolRequestContext, ToolRuntimeAvailabilityDto, TrustLabelDto,
    WorkspaceDashboardDto, WorkspaceDashboardRequestDto,
};
pub use error::{PortError, Retryability, SafeErrorClassification};
pub use execute_tool::{ExecuteTool, ToolOutcome};
pub use lease::{
    AcquireExecutorLease, AcquireLease, ExecutorLeaseStore, LeaseSnapshot, LeaseState, RevokeLease,
};
pub use orchestration::{
    policy_request_for_tool, validate_tool_approval_request, PreEffectOutcome, PreEffectReady,
    ToolExecutionOrchestration, ToolRequestPublisher,
};
pub use plan_approval::{
    canonical_plan_approval_payload, parse_canonical_plan_approval_payload, plan_approval_payload,
    CompareAndExpirePlanApproval, CompareAndInvalidatePlanApproval, CompareAndResolvePlanApproval,
    InvalidatePlanApproval, InvalidatePlanApprovalInput, NewPlanApproval,
    NewPlanApprovalRehydration, PlanApprovalAction, PlanApprovalAuthorityBinding,
    PlanApprovalBindingInput, PlanApprovalCurrentAuthority, PlanApprovalCurrentAuthoritySource,
    PlanApprovalCurrentState, PlanApprovalExpiry, PlanApprovalInvalidation,
    PlanApprovalRequestArtifact, PlanApprovalResolution, PlanApprovalState, PlanApprovalStore,
    PlanApprovalTerminal, PreparePlanApprovalRequest, PreparePlanApprovalRequestInput,
    ResolvePlanApproval, ResolvePlanApprovalInput, StoredPlanApproval,
    StoredPlanApprovalRehydration,
};
pub use policy::{
    bind_disclosure_channel, parse_policy_timestamp, DisclosureChannel, DisclosureContextProvider,
    DisclosureContextRequest, DisclosureOutcome, DisclosurePolicyEvaluator, DisclosureRequest,
    PolicyApprovalBinding, PolicyApprovedDisclosure, PolicyBoundBytes, PolicyDecision,
    PolicyDecisionId, PolicyDecisionStore, PolicyEvaluator, PolicyRequestBindingDigest,
    RecordedPolicyDecision, TrustedDisclosureContext,
};
pub use ports::{
    AppendOperation, AppendResult, ArtifactContent, ArtifactJournal, ArtifactJournalEntry,
    ArtifactJournalInvalidation, ArtifactJournalStatus, ArtifactJournalTransition, ArtifactRef,
    ArtifactRootReader, ArtifactStore, ArtifactUnavailableState, ArtifactWriteReservation, Clock,
    EventStore, IdGenerator, NewArtifact, NewEvent, ProjectionChange, ReservedArtifact, TaskQuery,
    WorkspaceEvidenceStore, WorkspaceMutationStore,
};
pub use repository::{
    CreateWorktree, DiscardWorktree, ExpectedPresence, InspectRepository, InspectWorktree,
    ManagedWorktreePath, ObjectFormat, OnboardRepository, OriginalCheckoutState, RepositoryGateway,
    RepositoryHazard, RepositoryHazardReason, RepositoryHealth, RepositoryLocator,
    RepositorySnapshot, WorktreeObservation, WorktreeSnapshot, WorktreeState,
};
pub use resume::{
    validate_approval_resume_relation, validate_pending_approval_resume, ApprovalResumeSnapshot,
    ApprovalResumeStore, ToolExecutionResumeSnapshot, ToolExecutionResumeStore,
};
pub use tool::{
    bind_tool_approval_payload, canonical_file_write_recovery_request,
    canonical_policy_binding_digest, canonical_tool_request, parse_file_write_recovery_request,
    parse_tool_request, validate_and_order_process_writes, ApprovedExecutableIdentity,
    ApprovedProcessExecutor, ApprovedProcessRequest, AuthoritativeProcessBinding,
    AuthoritativeProcessTermination, AuthorizedExpectedWrite, AuthorizedFileRead,
    AuthorizedFileWrite, AuthorizedGitDiff, AuthorizedGitStatus, AuthorizedProcessRequest,
    AuthorizedToolExecutionClaim, AuthorizedToolRequest, BoundToolApproval, BoundedOutput,
    CancellationReceipt, CanonicalFileWriteRecoveryRequest, CapabilityFileWriteSession,
    CapabilityFileWriteSessionFactory, CapabilityFilesystem, CapabilityRequest, CapabilityResolver,
    CapabilityRootIdentity, CaptureFileWritePostEvidence, CaptureFileWritePreEvidence,
    DeniedToolExecution, DirectoryFileIdentity, DisclosedToolExecutionArtifacts,
    DurableToolCancellationOutcome, DurableToolExecutionArtifact, DurableToolExecutionArtifacts,
    DurableToolExecutionOutcome, DurableToolExecutionReceipt, EnforcedNetworkProfile,
    EnvironmentProfileResolver, ExecutableArtifactInspector, ExecutableFileIdentity,
    ExecutableProfileResolver, ExecutableVerificationGuard, FileReadRequest,
    FileWriteEvidenceStore, FileWritePolicyBinding, FileWritePostExpectation, FileWritePreImage,
    FileWriteRecoveryCompletion, FileWriteRecoveryFailure, FileWriteRecoveryIntent,
    FileWriteRecoveryRequest, FileWriteRecoverySnapshot, FileWriteRecoveryState,
    FileWriteRecoveryStore, FileWriteRequest, GitDiffRequest, GitDiffResult, GitStatusRequest,
    GitStatusResult, ImmutableToolRequest, IncompleteToolExecution, JobReceipt,
    NetworkEnforcementReceipt, NetworkProfileVerifier, NewToolExecution, NewToolIntent,
    ObservedFileImage, ObservedProcessWrite, OpenFileWriteSession, OperationIntentSnapshot,
    PrivateRuntimeDirectoryInspector, PrivateRuntimeDirectoryVerificationGuard,
    ProcessExecutionBindingStore, ProcessLauncher, ProcessLimits, ProcessReceipt, ProcessStatus,
    ProcessWorkingDirectory, QuarantinedToolExecutionArtifacts, RawGitDiffResult,
    RawGitStatusResult, RelativePathComponents, ResolvedCapability, ResolvedCapabilityTarget,
    ResolvedEnvironmentProfile, ResolvedExecutable, ResolvedPrivateRuntimeDirectory,
    RetainedProcessController, SafeToolExecutionError, StructuredGit, StructuredToolExecutor,
    ToolControlSelfTest, ToolExecutionArtifactEvidence, ToolExecutionCancellationClaim,
    ToolExecutionClaim, ToolExecutionClaimAuthority, ToolExecutionDenialRequest, ToolExecutionId,
    ToolExecutionOutput, ToolExecutionPostEffectReceipt, ToolExecutionRecoveryEvidence,
    ToolExecutionRecoveryState, ToolExecutionResolution, ToolExecutionResult, ToolExecutionStore,
    ToolExecutionStreamMetadata, ToolExecutionTerminal, ToolExecutionTerminalKind,
    ToolPolicyContext, ToolRequest, ToolRequestBindingDigest, VerifiedBytes,
    VerifiedFileWriteCompensation, VerifiedWrite,
};
pub use workspace::{
    ArtifactRootMode, GetWorkspaceDashboard, IdempotencyClass, IntentTransition, NewProject,
    NewTask, ObserveWorkspaceMutation, OperationIntent, OperationIntentStatus,
    PrepareTaskWorkspace, ProcessFenceAuthority, ProcessFenceBinding, ProjectSettings,
    ProjectSnapshot, ReconcileWorkspaces, RecoveryAction, RecoveryCandidate, RecoveryEvidence,
    RecoveryOperationIntent, RecoveryProject, RecoveryReason, RepositoryInspectionRecord,
    RiskLevel, StartedRecovery, TaskLeaseState, TaskSnapshot, WorkspaceMutationRequest,
    WorkspaceMutationResult, WorkspaceObservationLossRequest, WorkspaceRecoveryStore,
    WorkspaceStateStore, WorkspaceWriteCoordinator, WorkspaceWritePermit, WorktreeIntent,
    WorktreeMatch,
};
