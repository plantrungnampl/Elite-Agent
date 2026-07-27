use local_agent_terminal_application::{
    ArtifactRootMode, NewProject, PortError, ProjectSettings, ProjectSnapshot, RecoveryProject,
    RepositoryHazard, RepositoryHazardReason, RepositoryHealth, RepositoryInspectionRecord,
    RepositorySnapshot, Retryability, SafeErrorClassification,
};
use local_agent_terminal_domain::{
    ArtifactId, GitObjectId, ProjectId, RepositoryId, TaskBranch, WorkspaceFingerprint,
};
use rusqlite::{params, Connection, OptionalExtension, Transaction, TransactionBehavior};
use serde_json::{json, Value};

use crate::event_store::{open_error_to_port, sqlite_error_to_port};
use crate::SqliteStore;

impl SqliteStore {
    pub(crate) fn load_recovery_projects(&self) -> Result<Vec<RecoveryProject>, PortError> {
        let connection = self.connection().map_err(open_error_to_port)?;
        let projects = {
            let mut statement = connection
                .prepare(
                    "SELECT id, name, repository_path, repository_identity, created_at,
                            policy_profile_id, artifact_root_mode, artifact_root_path
                     FROM projects ORDER BY created_at, id",
                )
                .map_err(sqlite_error_to_port)?;
            let rows = statement
                .query_map([], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        ProjectRow {
                            name: row.get(1)?,
                            repository_path: row.get(2)?,
                            repository_identity: row.get(3)?,
                            created_at: row.get(4)?,
                            policy_profile_id: row.get(5)?,
                            artifact_root_mode: row.get(6)?,
                            artifact_root_path: row.get(7)?,
                        },
                    ))
                })
                .map_err(sqlite_error_to_port)?
                .collect::<Result<Vec<_>, _>>()
                .map_err(sqlite_error_to_port)?;
            rows
        };
        let mut recovery = Vec::with_capacity(projects.len());
        for (project_id, project) in projects {
            let project_id = ProjectId::new(project_id).map_err(|_| integrity_failure())?;
            let intent_payload: String = connection
                .query_row(
                    "SELECT payload_json FROM events
                     WHERE stream_id = ?1 AND event_type = 'project.created'
                     ORDER BY sequence LIMIT 1",
                    [project_stream_id(&project_id)],
                    |row| row.get(0),
                )
                .map_err(sqlite_error_to_port)?;
            let intent_payload: Value =
                serde_json::from_str(&intent_payload).map_err(|_| integrity_failure())?;
            let (repository_id, repository_identity) =
                parse_project_created(&intent_payload, &project_id)?;
            if repository_identity != project.repository_identity {
                return Err(conflict());
            }
            let completion_payload: Option<String> = connection
                .query_row(
                    "SELECT payload_json FROM events
                     WHERE stream_id = ?1 AND event_type = 'repository.inspected'
                     ORDER BY sequence DESC LIMIT 1",
                    [project_stream_id(&project_id)],
                    |row| row.get(0),
                )
                .optional()
                .map_err(sqlite_error_to_port)?;
            let (repository, repository_evidence_artifact_id) = match completion_payload {
                Some(payload) => {
                    let payload: Value =
                        serde_json::from_str(&payload).map_err(|_| integrity_failure())?;
                    let repository = parse_repository_snapshot(&payload)?;
                    if repository.repository_id != repository_id
                        || repository.stable_identity != repository_identity
                    {
                        return Err(integrity_failure());
                    }
                    let evidence = evidence_artifact_id(&payload)?.ok_or_else(integrity_failure)?;
                    verify_recovery_evidence(&connection, &project_id, &evidence)?;
                    (Some(repository), Some(evidence))
                }
                None => (None, None),
            };
            recovery.push(RecoveryProject {
                project_id,
                repository_path: project.repository_path,
                repository_id,
                repository_identity,
                repository,
                repository_evidence_artifact_id,
            });
        }
        Ok(recovery)
    }

    pub(crate) fn insert_project(&self, project: NewProject) -> Result<ProjectSnapshot, PortError> {
        validate_new_project(&project)?;
        let mut connection = self.connection().map_err(open_error_to_port)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite_error_to_port)?;
        if let Some(existing) = project_row_optional(&transaction, &project.project_id)? {
            if !same_project(&existing, &project) {
                return Err(conflict());
            }
            let requested_repository = project.repository.clone();
            let mut persisted_project = project;
            persisted_project
                .created_at
                .clone_from(&existing.created_at);
            let payload: String = transaction
                .query_row(
                    "SELECT payload_json FROM events
                     WHERE stream_id = ?1 AND event_type = 'project.created'
                     ORDER BY sequence LIMIT 1",
                    [project_stream_id(&persisted_project.project_id)],
                    |row| row.get(0),
                )
                .map_err(sqlite_error_to_port)?;
            let payload: Value = serde_json::from_str(&payload).map_err(|_| integrity_failure())?;
            let (intent_repository_id, intent_repository_identity) =
                parse_project_created(&payload, &persisted_project.project_id)?;
            if intent_repository_id != requested_repository.repository_id
                || intent_repository_identity != requested_repository.stable_identity
            {
                return Err(conflict());
            }
            let completion: Option<String> = transaction
                .query_row(
                    "SELECT payload_json FROM events
                     WHERE stream_id = ?1 AND event_type = 'repository.inspected'
                     ORDER BY sequence DESC LIMIT 1",
                    [project_stream_id(&persisted_project.project_id)],
                    |row| row.get(0),
                )
                .optional()
                .map_err(sqlite_error_to_port)?;
            let completion = completion
                .map(|payload| {
                    let payload: Value =
                        serde_json::from_str(&payload).map_err(|_| integrity_failure())?;
                    let repository = parse_repository_snapshot(&payload)?;
                    if repository.repository_id != requested_repository.repository_id
                        || repository.stable_identity != requested_repository.stable_identity
                    {
                        return Err(conflict());
                    }
                    let evidence = evidence_artifact_id(&payload)?.ok_or_else(integrity_failure)?;
                    Ok((repository, evidence))
                })
                .transpose()?;
            let repository_evidence_artifact_id =
                completion.as_ref().map(|(_, evidence)| evidence.clone());
            persisted_project.repository = completion
                .map(|(repository, _)| repository)
                .unwrap_or(requested_repository);
            transaction.rollback().map_err(sqlite_error_to_port)?;
            return Ok(project_snapshot(
                persisted_project,
                repository_evidence_artifact_id,
            ));
        }
        let conflicting_identity: Option<String> = transaction
            .query_row(
                "SELECT id FROM projects WHERE repository_identity = ?1",
                [&project.repository.stable_identity],
                |row| row.get(0),
            )
            .optional()
            .map_err(sqlite_error_to_port)?;
        if conflicting_identity.is_some() {
            return Err(conflict());
        }
        transaction
            .execute(
                "INSERT INTO projects (
                    id, name, repository_path, repository_identity, created_at, updated_at,
                    policy_profile_id, artifact_root_mode, artifact_root_path
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?5, ?6, ?7, ?8)",
                params![
                    project.project_id.as_str(),
                    project.name,
                    project.repository_path,
                    project.repository.stable_identity,
                    project.created_at,
                    project.settings.policy_profile_id,
                    project.settings.artifact_root_mode.as_str(),
                    project.settings.artifact_root_path,
                ],
            )
            .map_err(sqlite_error_to_port)?;
        let stream_id = project_stream_id(&project.project_id);
        transaction
            .execute(
                "INSERT INTO events (
                    event_id, stream_id, sequence, event_type, schema_version, actor_type,
                    actor_id, observation_class, payload_json, metadata_json, causation_id,
                    correlation_id, created_at
                 ) VALUES (?1, ?2, 1, 'project.created', 1, 'core', 'workspace-coordinator',
                    'core_observed', ?3, '{}', NULL, ?4, ?5)",
                params![
                    format!("project.created:{}", project.project_id.as_str()),
                    stream_id,
                    project_created_json(&project).to_string(),
                    format!("project:create:{}", project.project_id.as_str()),
                    project.created_at,
                ],
            )
            .map_err(sqlite_error_to_port)?;
        transaction.commit().map_err(sqlite_error_to_port)?;

        Ok(project_snapshot(project, None))
    }

    pub(crate) fn insert_repository_inspection(
        &self,
        inspection: RepositoryInspectionRecord,
    ) -> Result<ProjectSnapshot, PortError> {
        validate_inspection(&inspection)?;
        let mut connection = self.connection().map_err(open_error_to_port)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite_error_to_port)?;
        let project = project_row(&transaction, &inspection.project_id)?;
        if project.repository_identity != inspection.repository.stable_identity {
            return Err(conflict());
        }
        verify_available_evidence(&transaction, &inspection)?;

        let stream_id = project_stream_id(&inspection.project_id);
        let payload = repository_snapshot_json(
            &inspection.repository,
            Some(&inspection.evidence.artifact_id),
        );
        let existing: Option<(String, String, String, String)> = transaction
            .query_row(
                "SELECT payload_json, actor_id, correlation_id, created_at FROM events
                 WHERE stream_id = ?1 AND event_type = 'repository.inspected'
                 ORDER BY sequence DESC LIMIT 1",
                [&stream_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .optional()
            .map_err(sqlite_error_to_port)?;
        if let Some((existing_payload, actor_id, correlation_id, created_at)) = existing {
            let existing_payload: Value =
                serde_json::from_str(&existing_payload).map_err(|_| integrity_failure())?;
            if existing_payload != payload
                || actor_id != inspection.actor_id.as_str()
                || correlation_id != inspection.correlation_id
                || created_at != inspection.observed_at
            {
                return Err(conflict());
            }
            transaction.rollback().map_err(sqlite_error_to_port)?;
            let settings = project.settings()?;
            return Ok(ProjectSnapshot {
                project_id: inspection.project_id,
                name: project.name,
                repository: inspection.repository,
                repository_path: project.repository_path,
                settings,
                repository_evidence_artifact_id: Some(inspection.evidence.artifact_id),
                created_at: project.created_at,
            });
        }
        let sequence: i64 = transaction
            .query_row(
                "SELECT COALESCE(MAX(sequence), 0) + 1 FROM events WHERE stream_id = ?1",
                [&stream_id],
                |row| row.get(0),
            )
            .map_err(sqlite_error_to_port)?;
        transaction
            .execute(
                "INSERT INTO events (
                    event_id, stream_id, sequence, event_type, schema_version, actor_type,
                    actor_id, observation_class, payload_json, metadata_json, causation_id,
                    correlation_id, created_at
                 ) VALUES (?1, ?2, ?3, 'repository.inspected', 1, 'core', ?4,
                    'core_observed', ?5, '{}', NULL, ?6, ?7)",
                params![
                    format!(
                        "repository.inspected:{}:{sequence}",
                        inspection.project_id.as_str()
                    ),
                    stream_id,
                    sequence,
                    inspection.actor_id.as_str(),
                    payload.to_string(),
                    inspection.correlation_id,
                    inspection.observed_at,
                ],
            )
            .map_err(sqlite_error_to_port)?;
        transaction.commit().map_err(sqlite_error_to_port)?;

        let settings = project.settings()?;
        Ok(ProjectSnapshot {
            project_id: inspection.project_id,
            name: project.name,
            repository: inspection.repository,
            repository_path: project.repository_path,
            settings,
            repository_evidence_artifact_id: Some(inspection.evidence.artifact_id),
            created_at: project.created_at,
        })
    }
}

pub(crate) fn project_stream_id(project_id: &ProjectId) -> String {
    format!("project:{}", project_id.as_str())
}

pub(crate) fn repository_snapshot_json(
    repository: &RepositorySnapshot,
    evidence_artifact_id: Option<&ArtifactId>,
) -> Value {
    json!({
        "repositoryId": repository.repository_id.as_str(),
        "health": repository.health.as_str(),
        "stableIdentity": repository.stable_identity,
        "defaultBranch": repository.default_branch.as_ref().map(TaskBranch::as_str),
        "baseCommit": repository.base_commit.as_ref().map(GitObjectId::as_str),
        "originalCheckout": repository.original_checkout.as_str(),
        "hazards": repository.hazards.iter().map(|hazard| json!({
            "reason": hazard.reason.as_str(),
            "detail": hazard.detail,
        })).collect::<Vec<_>>(),
        "fingerprint": {
            "head": repository.fingerprint.head().as_str(),
            "indexDigest": repository.fingerprint.index_digest(),
            "statusDigest": repository.fingerprint.status_digest(),
        },
        "evidenceArtifactId": evidence_artifact_id.map(ArtifactId::as_str),
    })
}

pub(crate) fn parse_repository_snapshot(value: &Value) -> Result<RepositorySnapshot, PortError> {
    let text = |name: &str| {
        value
            .get(name)
            .and_then(Value::as_str)
            .ok_or_else(integrity_failure)
    };
    let fingerprint = value
        .get("fingerprint")
        .and_then(Value::as_object)
        .ok_or_else(integrity_failure)?;
    let fingerprint_text = |name: &str| {
        fingerprint
            .get(name)
            .and_then(Value::as_str)
            .ok_or_else(integrity_failure)
    };
    let hazards = value
        .get("hazards")
        .and_then(Value::as_array)
        .ok_or_else(integrity_failure)?
        .iter()
        .map(|hazard| {
            let reason = hazard
                .get("reason")
                .and_then(Value::as_str)
                .and_then(RepositoryHazardReason::parse)
                .ok_or_else(integrity_failure)?;
            let detail = hazard
                .get("detail")
                .and_then(Value::as_str)
                .ok_or_else(integrity_failure)?
                .to_owned();
            Ok(RepositoryHazard { reason, detail })
        })
        .collect::<Result<Vec<_>, PortError>>()?;

    Ok(RepositorySnapshot {
        repository_id: RepositoryId::new(text("repositoryId")?).map_err(|_| integrity_failure())?,
        health: RepositoryHealth::parse(text("health")?).ok_or_else(integrity_failure)?,
        stable_identity: text("stableIdentity")?.to_owned(),
        default_branch: value
            .get("defaultBranch")
            .and_then(Value::as_str)
            .map(TaskBranch::new)
            .transpose()
            .map_err(|_| integrity_failure())?,
        base_commit: value
            .get("baseCommit")
            .and_then(Value::as_str)
            .map(GitObjectId::new)
            .transpose()
            .map_err(|_| integrity_failure())?,
        original_checkout: local_agent_terminal_application::OriginalCheckoutState::parse(text(
            "originalCheckout",
        )?)
        .ok_or_else(integrity_failure)?,
        hazards,
        fingerprint: WorkspaceFingerprint::new(
            GitObjectId::new(fingerprint_text("head")?).map_err(|_| integrity_failure())?,
            fingerprint_text("indexDigest")?,
            fingerprint_text("statusDigest")?,
        )
        .map_err(|_| integrity_failure())?,
    })
}

pub(crate) fn parse_artifact_root_mode(value: &str) -> Option<ArtifactRootMode> {
    match value {
        "application_data" => Some(ArtifactRootMode::ApplicationData),
        "project_local" => Some(ArtifactRootMode::ProjectLocal),
        _ => None,
    }
}

struct ProjectRow {
    name: String,
    repository_path: String,
    repository_identity: String,
    created_at: String,
    policy_profile_id: String,
    artifact_root_mode: String,
    artifact_root_path: String,
}

impl ProjectRow {
    fn settings(&self) -> Result<ProjectSettings, PortError> {
        Ok(ProjectSettings {
            policy_profile_id: self.policy_profile_id.clone(),
            artifact_root_mode: parse_artifact_root_mode(&self.artifact_root_mode)
                .ok_or_else(integrity_failure)?,
            artifact_root_path: self.artifact_root_path.clone(),
        })
    }
}

fn project_row(
    transaction: &Transaction<'_>,
    project_id: &ProjectId,
) -> Result<ProjectRow, PortError> {
    project_row_optional(transaction, project_id)?.ok_or_else(not_found)
}

fn project_row_optional(
    transaction: &Transaction<'_>,
    project_id: &ProjectId,
) -> Result<Option<ProjectRow>, PortError> {
    transaction
        .query_row(
            "SELECT name, repository_path, repository_identity, created_at, policy_profile_id,
                    artifact_root_mode, artifact_root_path
             FROM projects WHERE id = ?1",
            [project_id.as_str()],
            |row| {
                Ok(ProjectRow {
                    name: row.get(0)?,
                    repository_path: row.get(1)?,
                    repository_identity: row.get(2)?,
                    created_at: row.get(3)?,
                    policy_profile_id: row.get(4)?,
                    artifact_root_mode: row.get(5)?,
                    artifact_root_path: row.get(6)?,
                })
            },
        )
        .optional()
        .map_err(sqlite_error_to_port)
}

fn project_created_json(project: &NewProject) -> Value {
    json!({
        "projectId": project.project_id.as_str(),
        "repositoryId": project.repository.repository_id.as_str(),
        "repositoryIdentity": project.repository.stable_identity,
    })
}

fn parse_project_created(
    value: &Value,
    expected_project_id: &ProjectId,
) -> Result<(RepositoryId, String), PortError> {
    if value.get("projectId").and_then(Value::as_str) != Some(expected_project_id.as_str()) {
        return Err(integrity_failure());
    }
    if let Some(repository) = value.get("repository") {
        let repository = parse_repository_snapshot(repository)?;
        return Ok((repository.repository_id, repository.stable_identity));
    }
    let repository_id = value
        .get("repositoryId")
        .and_then(Value::as_str)
        .and_then(|value| RepositoryId::new(value).ok())
        .ok_or_else(integrity_failure)?;
    let repository_identity = value
        .get("repositoryIdentity")
        .and_then(Value::as_str)
        .map(str::to_owned)
        .filter(|value| !value.is_empty())
        .ok_or_else(integrity_failure)?;
    Ok((repository_id, repository_identity))
}

fn same_project(existing: &ProjectRow, requested: &NewProject) -> bool {
    existing.name == requested.name
        && existing.repository_path == requested.repository_path
        && existing.repository_identity == requested.repository.stable_identity
        && existing.policy_profile_id == requested.settings.policy_profile_id
        && existing.artifact_root_mode == requested.settings.artifact_root_mode.as_str()
        && existing.artifact_root_path == requested.settings.artifact_root_path
}

fn project_snapshot(
    project: NewProject,
    repository_evidence_artifact_id: Option<ArtifactId>,
) -> ProjectSnapshot {
    ProjectSnapshot {
        project_id: project.project_id,
        name: project.name,
        repository: project.repository,
        repository_path: project.repository_path,
        settings: project.settings,
        repository_evidence_artifact_id,
        created_at: project.created_at,
    }
}

fn evidence_artifact_id(payload: &Value) -> Result<Option<ArtifactId>, PortError> {
    payload
        .get("evidenceArtifactId")
        .ok_or_else(integrity_failure)?
        .as_str()
        .map(ArtifactId::new)
        .transpose()
        .map_err(|_| integrity_failure())
}

fn verify_recovery_evidence(
    connection: &Connection,
    project_id: &ProjectId,
    artifact_id: &ArtifactId,
) -> Result<(), PortError> {
    let evidence: Option<(String, Option<String>, String)> = connection
        .query_row(
            "SELECT project_id, task_id, availability FROM artifacts WHERE id = ?1",
            [artifact_id.as_str()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()
        .map_err(sqlite_error_to_port)?;
    if evidence != Some((project_id.as_str().to_owned(), None, "available".to_owned())) {
        return Err(integrity_failure());
    }
    Ok(())
}

fn verify_available_evidence(
    transaction: &Transaction<'_>,
    inspection: &RepositoryInspectionRecord,
) -> Result<(), PortError> {
    let artifact: Option<(String, Option<String>, String, String, i64, String)> = transaction
        .query_row(
            "SELECT project_id, task_id, content_hash, storage_key, size_bytes, availability
             FROM artifacts WHERE id = ?1",
            [inspection.evidence.artifact_id.as_str()],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                ))
            },
        )
        .optional()
        .map_err(sqlite_error_to_port)?;
    let Some((project_id, task_id, hash, storage_key, size, availability)) = artifact else {
        return Err(integrity_failure());
    };
    let size = u64::try_from(size).map_err(|_| integrity_failure())?;
    if project_id != inspection.project_id.as_str()
        || task_id.is_some()
        || hash != inspection.evidence.content_hash
        || storage_key != inspection.evidence.storage_key
        || size != inspection.evidence.size_bytes
        || availability != "available"
    {
        return Err(integrity_failure());
    }
    Ok(())
}

fn validate_new_project(project: &NewProject) -> Result<(), PortError> {
    if project.name.trim().is_empty()
        || project.repository_path.trim().is_empty()
        || project.settings.policy_profile_id.trim().is_empty()
        || project.settings.artifact_root_path.trim().is_empty()
        || project.created_at.trim().is_empty()
    {
        return Err(invalid_input());
    }
    Ok(())
}

fn validate_inspection(inspection: &RepositoryInspectionRecord) -> Result<(), PortError> {
    if inspection.project_id != inspection.evidence.project_id
        || inspection.evidence.task_id.is_some()
        || inspection.correlation_id.trim().is_empty()
        || inspection.observed_at.trim().is_empty()
    {
        return Err(invalid_input());
    }
    Ok(())
}

fn invalid_input() -> PortError {
    PortError::failure(
        SafeErrorClassification::InvalidInput,
        Retryability::NonRetryable,
    )
}

fn integrity_failure() -> PortError {
    PortError::failure(
        SafeErrorClassification::IntegrityFailure,
        Retryability::NonRetryable,
    )
}

fn conflict() -> PortError {
    PortError::failure(
        SafeErrorClassification::Conflict,
        Retryability::NonRetryable,
    )
}

fn not_found() -> PortError {
    PortError::failure(
        SafeErrorClassification::NotFound,
        Retryability::NonRetryable,
    )
}
