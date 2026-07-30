use local_agent_terminal_domain::{PolicyRequest, Timestamp};

use crate::{
    canonical_tool_request, ArtifactId, ImmutableToolRequest, PortError, ToolExecutionId,
    ToolRequest, ToolRequestBindingDigest,
};

pub fn policy_request_for_tool(request: &ToolRequest, evaluated_at: Timestamp) -> PolicyRequest {
    let binding = request.process().process().binding();
    let policy = request.policy();
    PolicyRequest {
        task_id: binding.task_id().clone(),
        actor: policy.actor().clone(),
        action: policy.action().clone(),
        resource: policy.resource().clone(),
        task_risk: policy.task_risk(),
        workflow_phase: binding.workflow_phase().as_str().to_owned(),
        purpose: policy.purpose().to_owned(),
        policy_snapshot_digest: policy.policy_snapshot_digest().clone(),
        evaluated_at,
    }
}

pub trait ToolRequestPublisher: Send + Sync {
    fn publish(&self, request: &ImmutableToolRequest) -> Result<ArtifactId, PortError>;
}

pub struct ToolExecutionOrchestration<'a> {
    publisher: &'a dyn ToolRequestPublisher,
}

impl<'a> ToolExecutionOrchestration<'a> {
    pub const fn new(publisher: &'a dyn ToolRequestPublisher) -> Self {
        Self { publisher }
    }

    pub fn execute(&self, request: ToolRequest) -> Result<PreEffectReady, PortError> {
        let immutable = canonical_tool_request(&request)?;
        let request_artifact_id = self.publisher.publish(&immutable)?;
        Ok(PreEffectReady {
            execution_id: request.execution_id().clone(),
            request_artifact_id,
            request_binding_digest: immutable.binding_digest().clone(),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreEffectReady {
    execution_id: ToolExecutionId,
    request_artifact_id: ArtifactId,
    request_binding_digest: ToolRequestBindingDigest,
}

impl PreEffectReady {
    pub const fn execution_id(&self) -> &ToolExecutionId {
        &self.execution_id
    }

    pub const fn request_artifact_id(&self) -> &ArtifactId {
        &self.request_artifact_id
    }

    pub const fn request_binding_digest(&self) -> &ToolRequestBindingDigest {
        &self.request_binding_digest
    }
}
