use local_agent_terminal_application::{
    AgentArtifactStore, AgentCancellationReceipt, AgentContextQueryRequest,
    AgentContextQueryResponse, AgentDescriptor, AgentMessageArtifact, AgentRequestAudit,
    AgentRequestAuditFence, AgentRequestCancellation, AgentRequestHandler, AgentRunReceipt,
    AgentRunSnapshot, AgentRunStatus, AgentRunStore, AgentRunTerminal, AgentRuntime,
    AgentSpecialistRequest, AgentSpecialistResponse, ArtifactId, BoundAgentRunRequest,
    BoundEffectiveContext, CancelAgentRun, PortError, RunId,
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

    impl AgentArtifactStore for Store {
        fn load_effective_context(&self, _: &BoundEffectiveContext) -> Result<Vec<u8>, PortError> {
            Ok(vec![])
        }

        fn publish_agent_message(&self, _: &AgentMessageArtifact) -> Result<ArtifactId, PortError> {
            ArtifactId::new("artifact-message-1").map_err(|_| invalid_input())
        }
    }

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

    impl AgentRequestHandler for Store {
        fn query_context(
            &self,
            request: AgentContextQueryRequest,
        ) -> Result<AgentContextQueryResponse, PortError> {
            Ok(AgentContextQueryResponse {
                run_id: request.run_id,
                task_id: request.task_id,
                query_id: request.query_id,
                supplement_id: "supplement-1".to_owned(),
                content_digest: local_agent_terminal_domain::Sha256Digest::new(format!(
                    "sha256:{}",
                    "1".repeat(64)
                ))
                .unwrap(),
                item_ids: Vec::new(),
                token_count: 0,
                policy_decision_ids: Vec::new(),
            })
        }

        fn request_specialist(
            &self,
            request: AgentSpecialistRequest,
        ) -> Result<AgentSpecialistResponse, PortError> {
            Ok(AgentSpecialistResponse {
                run_id: request.run_id,
                task_id: request.task_id,
                request_id: request.request_id,
                accepted: false,
                reason_code: "budget_exhausted".to_owned(),
            })
        }

        fn persist_audit(&self, _: AgentRequestAudit) -> Result<(), PortError> {
            Ok(())
        }
    }

    fn accepts_runtime(_: &dyn AgentRuntime) {}
    fn accepts_store(_: &dyn AgentRunStore) {}
    fn accepts_artifact_store(_: &dyn AgentArtifactStore) {}
    fn accepts_request_handler(_: &dyn AgentRequestHandler) {}

    let runtime = Runtime;
    let store = Store;
    accepts_runtime(&runtime);
    accepts_store(&store);
    accepts_artifact_store(&store);
    accepts_request_handler(&store);

    let _: AgentRunStatus = AgentRunStatus::Created;
}

#[test]
fn request_cancellation_revokes_every_clone_without_exposing_mutable_state() {
    let cancellation = AgentRequestCancellation::new();
    let worker_view = cancellation.clone();

    assert!(!worker_view.is_cancelled());
    cancellation.revoke();

    assert!(worker_view.is_cancelled());
    assert_eq!(cancellation, worker_view);
}

#[test]
fn audit_fence_revocation_is_visible_to_late_committers() {
    let fence = AgentRequestAuditFence::new();
    let late_committer = fence.clone();

    assert!(!late_committer.is_revoked());
    assert!(fence.revoke());

    assert!(late_committer.is_revoked());
    assert!(!late_committer.try_begin_commit());
    assert_eq!(fence, late_committer);
}

#[test]
fn audit_fence_commit_claim_prevents_late_revocation() {
    let fence = AgentRequestAuditFence::new();
    let runtime_view = fence.clone();

    assert!(fence.try_begin_commit());
    assert!(!runtime_view.revoke());
    fence.finish_commit();

    assert!(!runtime_view.is_revoked());
}

fn invalid_input() -> PortError {
    PortError::failure(
        local_agent_terminal_application::SafeErrorClassification::InvalidInput,
        local_agent_terminal_application::Retryability::NonRetryable,
    )
}
