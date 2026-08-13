use local_agent_terminal_application::{
    ArtifactRef, ArtifactStore, ArtifactWriteReservation, Clock, PortError, ProtocolRequestBegin,
    ProtocolResponseArtifact, ProtocolResponseArtifactPublisher, ReservedArtifact, TaskQuery,
    WorkspaceEvidenceStore,
};
use local_agent_terminal_storage_files::{ContentAddressedArtifactStore, JournaledArtifactWriter};

use crate::{
    agent_runtime::DurableAgentArtifacts,
    agent_runtime_support::{integrity_failure, invalid_input, stable_digest},
};

impl ProtocolResponseArtifactPublisher for DurableAgentArtifacts {
    fn publish_protocol_response(
        &self,
        begin: &ProtocolRequestBegin,
        response: &ProtocolResponseArtifact,
    ) -> Result<ProtocolResponseArtifact, PortError> {
        let task_id = begin.task_id().ok_or_else(invalid_input)?;
        let task = self.database.task(task_id)?;
        if let Some(existing) = self.database.available_evidence(response.artifact_id())? {
            if existing.task_id.as_ref() != Some(task_id) || existing.project_id != task.project_id
            {
                return Err(integrity_failure());
            }
            let bytes = self
                .artifacts
                .read(&ArtifactRef {
                    content_hash: existing.content_hash.clone(),
                    storage_key: existing.storage_key.clone(),
                    size_bytes: existing.size_bytes,
                })?
                .bytes;
            let restored = ProtocolResponseArtifact::new(response.artifact_id().clone(), bytes)
                .map_err(|_| integrity_failure())?;
            if restored.content_digest().as_str() != existing.content_hash
                || restored.size_bytes() != existing.size_bytes
            {
                return Err(integrity_failure());
            }
            return Ok(restored);
        }

        let created_at = self.database.now_utc()?;
        JournaledArtifactWriter::new(self.artifacts.as_ref(), &self.database, &self.database)
            .write(
                ArtifactWriteReservation {
                    operation_id: format!("protocol-response:{}", response.artifact_id().as_str()),
                    artifact: ReservedArtifact {
                        artifact_id: response.artifact_id().as_str().to_owned(),
                        task_id: Some(task_id.clone()),
                        project_id: task.project_id.as_str().to_owned(),
                        artifact_type: "protocol-response".to_owned(),
                        logical_path: format!(
                            "protocol-responses/{}.json",
                            stable_digest(response.artifact_id().as_str())
                        ),
                        content_hash: response.content_digest().as_str().to_owned(),
                        storage_key: ContentAddressedArtifactStore::storage_key(
                            response.content_digest().as_str(),
                        )?,
                        size_bytes: response.size_bytes(),
                        mime_type: Some("application/json".to_owned()),
                        created_by_type: "core".to_owned(),
                        created_by_id: "agent-runtime".to_owned(),
                        created_at: created_at.clone(),
                        supersedes: None,
                    },
                    temp_name: format!("{}.tmp", response.artifact_id().as_str()),
                    created_at,
                },
                response.bytes(),
            )?;
        Ok(response.clone())
    }
}
