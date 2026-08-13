use std::path::Path;

use local_agent_terminal_application::{
    PortError, PublishedRunConfigurationArtifact, Retryability, RunConfigurationStore,
    SafeErrorClassification,
};
use local_agent_terminal_domain::{RunConfiguration, RunId, Sha256Digest};
use rusqlite::{params, OptionalExtension, TransactionBehavior};
use sha2::{Digest, Sha256};

use crate::event_store::{open_error_to_port, sqlite_error_to_port};
use crate::SqliteStore;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredRunConfigurationBinding {
    pub run_id: RunId,
    pub config_artifact_id: String,
    pub config_digest: Sha256Digest,
    pub provider_connection_ref: String,
    pub adapter_id: String,
    pub resolved_model_id: String,
    pub independence_group: String,
    pub independence_fingerprint: Sha256Digest,
    pub created_at: String,
}

impl SqliteStore {
    pub fn run_configuration_binding(
        &self,
        run_id: &RunId,
    ) -> Result<Option<StoredRunConfigurationBinding>, PortError> {
        let connection = self.connection().map_err(open_error_to_port)?;
        let raw = connection
            .query_row(
                "SELECT config_artifact_id, config_digest, provider_connection_ref,
                        adapter_id, resolved_model_id, independence_group,
                        independence_fingerprint, created_at
                 FROM run_configuration_bindings WHERE run_id = ?1",
                [run_id.as_str()],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, String>(4)?,
                        row.get::<_, String>(5)?,
                        row.get::<_, String>(6)?,
                        row.get::<_, String>(7)?,
                    ))
                },
            )
            .optional()
            .map_err(sqlite_error_to_port)?;
        raw.map(|raw| {
            Ok(StoredRunConfigurationBinding {
                run_id: run_id.clone(),
                config_artifact_id: raw.0,
                config_digest: Sha256Digest::new(raw.1).map_err(|_| integrity_failure())?,
                provider_connection_ref: raw.2,
                adapter_id: raw.3,
                resolved_model_id: raw.4,
                independence_group: raw.5,
                independence_fingerprint: Sha256Digest::new(raw.6)
                    .map_err(|_| integrity_failure())?,
                created_at: raw.7,
            })
        })
        .transpose()
    }
}

impl RunConfigurationStore for SqliteStore {
    fn bind_run_configuration(
        &self,
        run_id: &RunId,
        artifact: &PublishedRunConfigurationArtifact,
        configuration: &RunConfiguration,
    ) -> Result<(), PortError> {
        let reader = self.artifact_reader().ok_or_else(unavailable)?;
        let mut connection = self.connection().map_err(open_error_to_port)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite_error_to_port)?;
        let existing: Option<(String, String)> = transaction
            .query_row(
                "SELECT config_artifact_id, config_digest
                 FROM run_configuration_bindings WHERE run_id=?1",
                [run_id.as_str()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(sqlite_error_to_port)?;
        if existing.as_ref().is_some_and(|(artifact_id, digest)| {
            artifact_id != artifact.artifact_id.as_str()
                || digest != configuration.config_digest().as_str()
        }) {
            return Err(conflict());
        }
        if artifact.reference.size_bytes != configuration.canonical_bytes().len() as u64 {
            return Err(integrity_failure());
        }
        let root: Option<String> = transaction
            .query_row(
                "SELECT p.artifact_root_path
                 FROM agent_runs r
                 JOIN tasks t ON t.id = r.task_id
                 JOIN projects p ON p.id = t.project_id
                 JOIN artifacts a ON a.id = ?2
                 WHERE r.id = ?1 AND r.task_id = ?3
                   AND r.run_config_artifact_id = a.id
                   AND a.project_id = t.project_id
                   AND (a.task_id IS NULL OR a.task_id = r.task_id)
                   AND a.artifact_type = 'run-config'
                   AND a.availability = 'available'
                   AND a.verification_state IN ('hash_verified','tool_verified','user_approved')
                   AND a.content_hash = ?4 AND a.storage_key = ?5 AND a.size_bytes = ?6",
                params![
                    run_id.as_str(),
                    artifact.artifact_id.as_str(),
                    configuration.task_id().as_str(),
                    artifact.reference.content_hash,
                    artifact.reference.storage_key,
                    i64::try_from(artifact.reference.size_bytes).map_err(|_| integrity_failure())?,
                ],
                |row| row.get(0),
            )
            .optional()
            .map_err(sqlite_error_to_port)?;
        let root = root.ok_or_else(conflict)?;
        let content = reader
            .read_from_root(Path::new(&root), &artifact.reference)
            .map_err(|_| integrity_failure())?;
        if physical_digest(&content.bytes) != artifact.reference.content_hash
            || content.bytes != configuration.canonical_bytes()
            || RunConfiguration::from_canonical_bytes(&content.bytes).is_err()
        {
            return Err(integrity_failure());
        }
        transaction
            .execute(
                "INSERT OR IGNORE INTO run_configuration_bindings (
                    run_id, config_artifact_id, config_digest, provider_connection_ref,
                    adapter_id, resolved_model_id, independence_group,
                    independence_fingerprint, created_at
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                params![
                    run_id.as_str(),
                    artifact.artifact_id.as_str(),
                    configuration.config_digest().as_str(),
                    configuration.provider_connection_ref(),
                    configuration.adapter().adapter_id,
                    configuration.model_endpoint().resolved_model_id,
                    configuration.independence().group_id,
                    configuration.independence().fingerprint.as_str(),
                    configuration.created_at_rfc3339(),
                ],
            )
            .map_err(sqlite_binding_error)?;
        let exact: bool = transaction
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM run_configuration_bindings
                 WHERE run_id=?1 AND config_artifact_id=?2 AND config_digest=?3
                   AND provider_connection_ref=?4 AND adapter_id=?5
                   AND resolved_model_id=?6 AND independence_group=?7
                   AND independence_fingerprint=?8 AND created_at=?9)",
                params![
                    run_id.as_str(),
                    artifact.artifact_id.as_str(),
                    configuration.config_digest().as_str(),
                    configuration.provider_connection_ref(),
                    configuration.adapter().adapter_id,
                    configuration.model_endpoint().resolved_model_id,
                    configuration.independence().group_id,
                    configuration.independence().fingerprint.as_str(),
                    configuration.created_at_rfc3339(),
                ],
                |row| row.get(0),
            )
            .map_err(sqlite_error_to_port)?;
        if !exact {
            return Err(conflict());
        }
        transaction.commit().map_err(sqlite_error_to_port)
    }
}

fn physical_digest(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}

fn sqlite_binding_error(error: rusqlite::Error) -> PortError {
    match &error {
        rusqlite::Error::SqliteFailure(_, Some(message))
            if message.contains("run configuration")
                || message.contains("UNIQUE constraint failed") =>
        {
            conflict()
        }
        _ => sqlite_error_to_port(error),
    }
}
fn conflict() -> PortError {
    PortError::failure(
        SafeErrorClassification::Conflict,
        Retryability::NonRetryable,
    )
}
fn integrity_failure() -> PortError {
    PortError::failure(
        SafeErrorClassification::IntegrityFailure,
        Retryability::NonRetryable,
    )
}
fn unavailable() -> PortError {
    PortError::failure(
        SafeErrorClassification::Unavailable,
        Retryability::Retryable,
    )
}
