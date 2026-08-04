#![forbid(unsafe_code)]

mod agent;
mod event;
mod identity;
mod policy;
mod tool;
mod workflow;
mod workspace;

pub use agent::{
    AgentCancellationReceipt, AgentClaim, AgentDescriptor, AgentError, AgentEvidenceRef,
    AgentRunMessage, AgentRunReceipt, AgentRunSnapshot, AgentRunStatus, AgentRunTerminal,
    AgentTrustTier, AgentUsage, BoundAgentConnection, BoundAgentRunRequest, BoundEffectiveContext,
    BoundGenerationParameters, BoundRunConfig, CancelAgentRun, MAX_GENERATION_PARAMETERS_BYTES,
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
pub use tool::{
    ArtifactCapability, CapabilityRef, EnvironmentProfile, ExpectedWrite, NetworkProfile,
    PlanStepId, ProcessBinding, ProcessInvocation, ProcessToolRequest, ProcessTrustTier,
    RawShellRequest, SourceCapability, StructuredToolName, ToolError, ToolchainCapability,
    WorktreeCapability,
};
pub use workflow::{
    reduce, Condition, OperationState, ParseWorkflowValueError, Phase, Transition, WorkflowError,
    WorkflowState,
};
pub use workspace::{
    authorize_fenced_write, FencedWriteError, GitObjectId, LeaseClaim, TaskBranch,
    WorkspaceFingerprint,
};
