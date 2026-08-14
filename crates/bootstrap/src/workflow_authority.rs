use std::sync::Arc;

use local_agent_terminal_application::{
    ArtifactId, CanonicalJsonRequest, DeliberationPhaseTransition, DeliberationWorkflowAuthority,
    PortError, Retryability, SafeErrorClassification, Sha256Digest, TaskQuery, TransitionWorkflow,
    TransitionWorkflowInput, WorkflowCommandPublisher,
};
use local_agent_terminal_storage_files::ContentAddressedArtifactStore;
use local_agent_terminal_storage_sqlite::SqliteStore;
use sha2::{Digest, Sha256};

use crate::workspace_monitor::publish_canonical_json;

pub(crate) fn trusted_workflow_core_digest() -> Sha256Digest {
    Sha256Digest::new(format!(
        "sha256:{:x}",
        Sha256::digest(b"local-agent-terminal:trusted-workflow-core:v1")
    ))
    .expect("SHA-256 formatting is valid")
}

pub(crate) struct ProductionWorkflowAuthority {
    database: SqliteStore,
    artifacts: Arc<ContentAddressedArtifactStore>,
}

impl ProductionWorkflowAuthority {
    pub(crate) fn new(
        database: SqliteStore,
        artifacts: Arc<ContentAddressedArtifactStore>,
    ) -> Self {
        Self {
            database,
            artifacts,
        }
    }
}

impl DeliberationWorkflowAuthority for ProductionWorkflowAuthority {
    fn transition(&self, request: DeliberationPhaseTransition) -> Result<(), PortError> {
        let task = TaskQuery::task(&self.database, request.task_id())?;
        let command_id = format!(
            "deliberation:{}:{}:{}",
            request.task_id().as_str(),
            request.expected_stream_version(),
            request.transition_event_id(),
        );
        let event_digest = format!(
            "{:x}",
            Sha256::digest(request.transition_event_id().as_bytes())
        );
        let artifact_id = ArtifactId::new(format!(
            "workflow-transition-command-{}-{}-{}",
            request.task_id().as_str(),
            request.expected_stream_version(),
            &event_digest[..16],
        ))
        .map_err(|_| invalid_input())?;
        let input = TransitionWorkflowInput {
            command_id,
            transition_event_id: request.transition_event_id().to_owned(),
            task_id: request.task_id().clone(),
            rule_id: request.rule_id().to_owned(),
            expected_stream_version: request.expected_stream_version(),
            event: request.event().clone(),
            guards: request.guards().to_vec(),
            effects: request.effects().to_vec(),
            core_actor_digest: trusted_workflow_core_digest(),
            reducer_version: "workflow-reducer-1.0.0".to_owned(),
            prepared_at: request.prepared_at(),
        };
        let workflow = TransitionWorkflow::new(&self.database, self);
        let prepared = workflow
            .prepare(input, task.project_id, artifact_id)
            .map_err(|error| {
                eprintln!("workflow authority prepare failed: {error:?}");
                error
            })?;
        self.publish_command(prepared.artifact_request())
            .map_err(|error| {
                eprintln!("workflow authority publish failed: {error:?}");
                error
            })?;
        workflow.persist(&prepared).map_err(|error| {
            eprintln!("workflow authority persist failed: {error:?}");
            error
        })?;
        Ok(())
    }
}

impl WorkflowCommandPublisher for ProductionWorkflowAuthority {
    fn publish_command(&self, request: &CanonicalJsonRequest) -> Result<(), PortError> {
        publish_canonical_json(&self.database, self.artifacts.as_ref(), request.clone())?;
        Ok(())
    }
}

fn invalid_input() -> PortError {
    PortError::failure(
        SafeErrorClassification::InvalidInput,
        Retryability::NonRetryable,
    )
}
