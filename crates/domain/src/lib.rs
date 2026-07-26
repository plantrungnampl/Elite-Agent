#![forbid(unsafe_code)]

mod event;
mod identity;
mod workflow;
mod workspace;

pub use event::{Effect, GuardEvaluations, GuardName, WorkflowEvent};
pub use identity::{
    ActorId, ArtifactId, EventId, FencingToken, ProjectId, RepositoryId, RunId, Sequence, StreamId,
    TaskId, ValueError, WorkspaceVersion, WorktreeId,
};
pub use workflow::{
    reduce, Condition, OperationState, ParseWorkflowValueError, Phase, Transition, WorkflowError,
    WorkflowState,
};
pub use workspace::{
    authorize_fenced_write, FencedWriteError, GitObjectId, LeaseClaim, TaskBranch,
    WorkspaceFingerprint,
};
