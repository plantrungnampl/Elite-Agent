use local_agent_terminal_domain::{
    AgentCancellationReceipt, AgentDescriptor, AgentRunReceipt, AgentRunSnapshot, AgentRunTerminal,
    ArtifactId, BoundAgentRunRequest, BoundEffectiveContext, CancelAgentRun, RunId, TaskId,
};

use crate::PortError;

pub trait AgentRuntime: Send + Sync {
    fn list_agents(&self) -> Result<Vec<AgentDescriptor>, PortError>;
    fn start_run(&self, request: BoundAgentRunRequest) -> Result<AgentRunReceipt, PortError>;
    fn cancel(&self, request: CancelAgentRun) -> Result<AgentCancellationReceipt, PortError>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentMessageArtifact {
    pub task_id: TaskId,
    pub run_id: RunId,
    pub message_id: String,
    pub content: Vec<u8>,
}

pub trait AgentArtifactStore: Send + Sync {
    fn load_effective_context(&self, context: &BoundEffectiveContext)
        -> Result<Vec<u8>, PortError>;
    fn publish_agent_message(
        &self,
        artifact: &AgentMessageArtifact,
    ) -> Result<ArtifactId, PortError>;
}

pub trait AgentRunStore: Send + Sync {
    fn register_descriptor(&self, descriptor: &AgentDescriptor) -> Result<(), PortError>;
    fn create_bound_run(
        &self,
        request: &BoundAgentRunRequest,
    ) -> Result<AgentRunSnapshot, PortError>;
    fn accept_run(&self, run_id: &RunId, accepted_at: &str) -> Result<(), PortError>;
    fn mark_running(&self, run_id: &RunId, started_at: &str) -> Result<(), PortError>;
    fn persist_terminal(&self, terminal: &AgentRunTerminal) -> Result<(), PortError>;
    fn interrupt_connection(
        &self,
        connection_digest: &str,
        at: &str,
    ) -> Result<Vec<RunId>, PortError>;
    fn load_run(&self, run_id: &RunId) -> Result<Option<AgentRunSnapshot>, PortError>;
}
