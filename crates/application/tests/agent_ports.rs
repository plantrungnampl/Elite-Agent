use local_agent_terminal_application::{
    AgentCancellationReceipt, AgentDescriptor, AgentRunReceipt, AgentRunSnapshot, AgentRunStatus,
    AgentRunStore, AgentRunTerminal, AgentRuntime, BoundAgentRunRequest, CancelAgentRun, PortError,
    RunId,
};
use local_agent_terminal_domain::Timestamp;

#[test]
fn agent_ports_are_object_safe_and_keep_only_bound_values_at_the_boundary() {
    struct Runtime;

    impl AgentRuntime for Runtime {
        fn list_agents(&self) -> Result<Vec<AgentDescriptor>, PortError> {
            Ok(vec![])
        }

        fn start_run(&self, request: BoundAgentRunRequest) -> Result<AgentRunReceipt, PortError> {
            Ok(AgentRunReceipt {
                run_id: request.run_id,
                accepted_at: Timestamp::from_unix_seconds(1),
            })
        }

        fn cancel(&self, request: CancelAgentRun) -> Result<AgentCancellationReceipt, PortError> {
            Ok(AgentCancellationReceipt {
                run_id: request.run_id,
                accepted_at: Timestamp::from_unix_seconds(2),
            })
        }
    }

    struct Store;

    impl AgentRunStore for Store {
        fn register_descriptor(&self, _: &AgentDescriptor) -> Result<(), PortError> {
            Ok(())
        }

        fn create_bound_run(
            &self,
            request: &BoundAgentRunRequest,
        ) -> Result<AgentRunSnapshot, PortError> {
            AgentRunSnapshot::created(request.clone()).map_err(|_| invalid_input())
        }

        fn accept_run(&self, _: &RunId, _: &str) -> Result<(), PortError> {
            Ok(())
        }

        fn mark_running(&self, _: &RunId, _: &str) -> Result<(), PortError> {
            Ok(())
        }

        fn persist_terminal(&self, _: &AgentRunTerminal) -> Result<(), PortError> {
            Ok(())
        }

        fn interrupt_connection(&self, _: &str, _: &str) -> Result<Vec<RunId>, PortError> {
            Ok(vec![])
        }

        fn load_run(&self, _: &RunId) -> Result<Option<AgentRunSnapshot>, PortError> {
            Ok(None)
        }
    }

    fn accepts_runtime(_: &dyn AgentRuntime) {}
    fn accepts_store(_: &dyn AgentRunStore) {}

    let runtime = Runtime;
    let store = Store;
    accepts_runtime(&runtime);
    accepts_store(&store);

    let _: AgentRunStatus = AgentRunStatus::Created;
}

fn invalid_input() -> PortError {
    PortError::failure(
        local_agent_terminal_application::SafeErrorClassification::InvalidInput,
        local_agent_terminal_application::Retryability::NonRetryable,
    )
}
