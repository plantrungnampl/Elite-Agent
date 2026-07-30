use crate::{
    canonical_tool_request, ArtifactId, ImmutableToolRequest, PortError, ToolExecutionId,
    ToolRequest, ToolRequestBindingDigest,
};

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
