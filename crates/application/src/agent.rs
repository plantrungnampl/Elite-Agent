use local_agent_terminal_domain::{
    AgentCancellationReceipt, AgentDescriptor, AgentRunReceipt, AgentRunSnapshot, AgentRunTerminal,
    BoundAgentRunRequest, CancelAgentRun, RunId,
};

use crate::PortError;

pub trait AgentRuntime: Send + Sync {
    fn list_agents(&self) -> Result<Vec<AgentDescriptor>, PortError>;
    fn start_run(&self, request: BoundAgentRunRequest) -> Result<AgentRunReceipt, PortError>;
    fn cancel(&self, request: CancelAgentRun) -> Result<AgentCancellationReceipt, PortError>;
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
