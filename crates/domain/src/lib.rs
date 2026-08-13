#![forbid(unsafe_code)]

mod agent;
mod assurance;
mod context;
mod deliberation;
mod event;
mod identity;
mod policy;
mod run_configuration;
mod tool;
mod workflow;
mod workspace;

pub use agent::{
    AgentCancellationReceipt, AgentClaim, AgentDescriptor, AgentError, AgentEvidenceRef,
    AgentRunLimits, AgentRunMessage, AgentRunReceipt, AgentRunSnapshot, AgentRunStatus,
    AgentRunTerminal, AgentUsage, BoundAgentConnection, BoundAgentRunRequest,
    BoundEffectiveContext, BoundGenerationParameters, BoundRunConfig, CancelAgentRun,
    MAX_GENERATION_PARAMETERS_BYTES,
};
pub use assurance::{
    AssuranceAssessment, AssuranceDecision, AssuranceDegradationInput, AssuranceDegradationReceipt,
    AssuranceError, AssuranceObserved, AssuranceReasonCode, AssuranceRequirements,
    AssuranceRunEvidence,
};
pub use context::{
    ContextBudget, ContextError, ContextPackageArtifact, ContextPackageBinding,
    ContextPackageDescriptor, ContextPackageIdentity, ContextPackageMember, ContextVersionSet,
    Disclosure, DisclosureKind, EvidenceCitation, EvidenceFreshness, LineRange, PolicyDecisionSet,
    SourceIdentity,
};
pub use deliberation::{
    AgentFamilyKey, ApprovalAuthority, ApprovalExecution, ApprovalScope, ClaimVerification,
    DecisionApproach, DecisionPackage, DeliberationBudget, DeliberationError, DeliberationLimits,
    DeliberationTaskBudget, Dissent, FinalObjection, FinalObjectionSet, IndependentProposal,
    IndependentQuorum, MaterialClaim, ObjectionSeverity, PlanApprovalBinding, PlanIdentity,
    RejectedApproach, ReviewEdge, ReviewPlan, SpecialistBudget, SpecialistRequest,
    VerificationMethod,
};
pub use event::{Effect, GuardEvaluations, GuardName, WorkflowEvent};
pub use identity::{
    ActorId, ArtifactId, EventId, FencingToken, ProjectId, RepositoryId, RunId, Sequence,
    Sha256Digest, StreamId, TaskId, Timestamp, ValueError, WorkspaceVersion, WorktreeId,
};
pub use policy::{
    combine_policy_rules, ActorLocality, MatchedPolicyRule, PolicyAction, PolicyActor,
    PolicyDecisionDraft, PolicyEffect, PolicyError, PolicyRequest, PolicyResource, PolicyRuleId,
    PolicyVersion, RedactionDirective, ResourceClass, TaskRisk, TrustTier,
};
pub use run_configuration::{
    AdapterConfiguration, AdapterProtocol, AdapterTransport, AgentProfileConfiguration, AgentRole,
    AllowedDataClass, CapabilitySnapshot, DataPolicySnapshot, EndpointClass, FallbackCandidate,
    FallbackMode, FallbackPolicy, GenerationParameters, IndependenceConfiguration,
    IndependenceDimensions, ModelEndpointConfiguration, NetworkScope, ProviderTrainingUse,
    RetentionClass, RunBudgetReservation, RunConfiguration, RunConfigurationError,
    UnsignedRunConfiguration,
};
pub use tool::{
    ArtifactCapability, CapabilityRef, EnvironmentProfile, ExpectedWrite, NetworkProfile,
    PlanStepId, ProcessBinding, ProcessInvocation, ProcessToolRequest, ProcessTrustTier,
    RawShellRequest, SourceCapability, StructuredToolName, ToolError, ToolchainCapability,
    WorktreeCapability,
};
pub use workflow::{
    reduce, reduce_condition, Condition, OperationState, ParseWorkflowValueError, Phase,
    TaskOutcomeMode, Transition, TransitionRequest, WorkflowError, WorkflowProfile, WorkflowState,
    WorkflowStateSnapshot,
};
pub use workspace::{
    authorize_fenced_write, FencedWriteError, GitObjectId, LeaseClaim, TaskBranch,
    WorkspaceFingerprint,
};
