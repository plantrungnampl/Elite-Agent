use std::fmt::Write;

use local_agent_terminal_domain::{ArtifactId, ProjectId, TaskId};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::{ArtifactRef, PortError, Retryability, SafeErrorClassification};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanonicalJsonRequest {
    pub artifact_id: ArtifactId,
    pub project_id: ProjectId,
    pub task_id: Option<TaskId>,
    pub artifact_type: String,
    pub logical_path: String,
    pub created_by_type: String,
    pub created_by_id: String,
    pub canonical_bytes: Vec<u8>,
    pub expected_hash: String,
    pub expected_size: u64,
    pub idempotency_key: String,
}

impl CanonicalJsonRequest {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        artifact_id: ArtifactId,
        project_id: ProjectId,
        task_id: Option<TaskId>,
        artifact_type: impl Into<String>,
        logical_path: impl Into<String>,
        created_by_type: impl Into<String>,
        created_by_id: impl Into<String>,
        value: &Value,
        idempotency_key: impl Into<String>,
    ) -> Result<Self, PortError> {
        let artifact_type = artifact_type.into();
        let logical_path = logical_path.into();
        let created_by_type = created_by_type.into();
        let created_by_id = created_by_id.into();
        let idempotency_key = idempotency_key.into();
        if [
            artifact_type.as_str(),
            logical_path.as_str(),
            created_by_type.as_str(),
            created_by_id.as_str(),
            idempotency_key.as_str(),
        ]
        .iter()
        .any(|value| value.trim().is_empty())
        {
            return Err(invalid_input());
        }

        let canonical_bytes =
            serde_json_canonicalizer::to_vec(value).map_err(|_| invalid_input())?;
        let expected_hash = sha256_digest(&canonical_bytes);
        let expected_size = canonical_bytes.len() as u64;

        Ok(Self {
            artifact_id,
            project_id,
            task_id,
            artifact_type,
            logical_path,
            created_by_type,
            created_by_id,
            canonical_bytes,
            expected_hash,
            expected_size,
            idempotency_key,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanonicalEvidenceRef {
    pub artifact_id: ArtifactId,
    pub content_hash: String,
    pub storage_key: String,
    pub size_bytes: u64,
    pub project_id: ProjectId,
    pub task_id: Option<TaskId>,
}

pub fn canonical_evidence(
    request: &CanonicalJsonRequest,
    artifact: &ArtifactRef,
) -> Result<CanonicalEvidenceRef, PortError> {
    if artifact.content_hash != request.expected_hash
        || artifact.size_bytes != request.expected_size
    {
        return Err(PortError::failure(
            SafeErrorClassification::IntegrityFailure,
            Retryability::NonRetryable,
        ));
    }

    Ok(CanonicalEvidenceRef {
        artifact_id: request.artifact_id.clone(),
        content_hash: artifact.content_hash.clone(),
        storage_key: artifact.storage_key.clone(),
        size_bytes: artifact.size_bytes,
        project_id: request.project_id.clone(),
        task_id: request.task_id.clone(),
    })
}

pub(crate) fn sha256_digest(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut encoded = String::with_capacity(71);
    encoded.push_str("sha256:");
    for byte in digest {
        write!(encoded, "{byte:02x}").expect("writing to String cannot fail");
    }
    encoded
}

pub(crate) fn invalid_input() -> PortError {
    PortError::failure(
        SafeErrorClassification::InvalidInput,
        Retryability::NonRetryable,
    )
}
