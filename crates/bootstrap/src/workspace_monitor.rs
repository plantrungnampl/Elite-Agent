use std::fmt::Write;
use std::path::{Path, PathBuf};

use local_agent_terminal_application::{
    canonical_evidence, ArtifactWriteReservation, CanonicalEvidenceRef, CanonicalJsonRequest,
    Clock, ExpectedPresence, InspectWorktree, LeaseClaim, PortError, RepositoryGateway,
    SafeErrorClassification, TaskQuery, WorkspaceEvidenceStore, WorkspaceFingerprint,
    WorkspaceMutationRequest, WorkspaceMutationResult, WorkspaceMutationStore,
    WorkspaceRecoveryStore, WorkspaceWriteCoordinator, WorktreeObservation, WorktreeState,
};
use local_agent_terminal_application::{ActorId, ArtifactId, Phase, TaskId};
use local_agent_terminal_repository_git::GitRepositoryGateway;
use local_agent_terminal_storage_files::{ContentAddressedArtifactStore, JournaledArtifactWriter};
use local_agent_terminal_storage_sqlite::SqliteStore;
use serde_json::json;

pub(crate) struct WorkspaceMonitor;

impl WorkspaceMonitor {
    pub(crate) fn poll(
        &self,
        database: &SqliteStore,
        artifacts: &ContentAddressedArtifactStore,
        repositories: &GitRepositoryGateway,
        writes: &WorkspaceWriteCoordinator,
        task_id: &TaskId,
        claim: LeaseClaim,
    ) -> Result<Option<WorkspaceMutationResult>, PortError> {
        if claim.task_id() != task_id {
            return Err(failure(SafeErrorClassification::InvalidInput));
        }
        let _permit = writes.monitor_permit(database, claim.clone())?;
        let task = database.task(task_id)?;
        if !monitorable_phase(task.phase) {
            return Ok(None);
        }
        let Some(worktree) = task.worktree.as_ref() else {
            return Ok(None);
        };
        if worktree.state != WorktreeState::Present
            || worktree.expected_presence != ExpectedPresence::Present
        {
            return Ok(None);
        }
        let project = database
            .recovery_projects()?
            .into_iter()
            .find(|project| project.project_id == task.project_id)
            .ok_or_else(|| failure(SafeErrorClassification::NotFound))?;
        let locator = repositories.locate(Path::new(&project.repository_path))?;
        if locator.repository_id != worktree.repository_id
            || locator.stable_identity != worktree.repository_identity
        {
            return Err(failure(SafeErrorClassification::Conflict));
        }
        let observation = repositories.inspect_worktree(InspectWorktree {
            repository: locator,
            managed_path: local_agent_terminal_application::ManagedWorktreePath {
                trusted_root_id: repositories.trusted_root_id().to_owned(),
                relative_leaf: PathBuf::from(worktree.worktree_id.as_str()),
                redacted_display: worktree.target_path_display.clone(),
            },
            task_id: task.task_id.clone(),
            worktree_id: worktree.worktree_id.clone(),
            branch: worktree.branch.clone(),
            base_commit: worktree.base_commit.clone(),
        })?;
        let observed = match observation {
            WorktreeObservation::Exact(snapshot) => *snapshot,
            WorktreeObservation::AuthoritativelyAbsent | WorktreeObservation::Conflict(_) => {
                return Err(failure(SafeErrorClassification::Conflict));
            }
        };
        if observed.fingerprint == worktree.fingerprint {
            return Ok(None);
        }

        let pre_evidence =
            publish_fingerprint(database, artifacts, &task, "pre", &worktree.fingerprint)?;
        let post_evidence =
            publish_fingerprint(database, artifacts, &task, "post", &observed.fingerprint)?;
        let result = database.record_workspace_mutation(WorkspaceMutationRequest {
            task_id: task.task_id.clone(),
            expected_sequence: task.current_sequence,
            claim,
            pre_fingerprint: worktree.fingerprint.clone(),
            post_fingerprint: observed.fingerprint,
            pre_evidence,
            post_evidence,
            actor_id: ActorId::new("workspace-monitor")
                .map_err(|_| failure(SafeErrorClassification::InvalidInput))?,
            correlation_id: format!(
                "workspace-monitor:{}:{}",
                task.task_id.as_str(),
                task.current_sequence.get()
            ),
        })?;
        Ok(Some(result))
    }
}

fn monitorable_phase(phase: Phase) -> bool {
    matches!(
        phase,
        Phase::Implementation
            | Phase::Verification
            | Phase::Repair
            | Phase::FinalReview
            | Phase::AwaitingCommitApproval
    )
}

fn publish_fingerprint(
    database: &SqliteStore,
    artifacts: &ContentAddressedArtifactStore,
    task: &local_agent_terminal_application::TaskSnapshot,
    role: &str,
    fingerprint: &WorkspaceFingerprint,
) -> Result<CanonicalEvidenceRef, PortError> {
    let fingerprint_key = hex_identifier(&format!(
        "{}:{}:{}",
        fingerprint.head().as_str(),
        fingerprint.index_digest(),
        fingerprint.status_digest()
    ));
    let artifact_id = ArtifactId::new(format!(
        "workspace-fingerprint-{}-{}-{role}-{}",
        hex_identifier(task.task_id.as_str()),
        task.current_sequence.get(),
        &fingerprint_key[..24]
    ))
    .map_err(|_| failure(SafeErrorClassification::InvalidInput))?;
    let request = CanonicalJsonRequest::new(
        artifact_id,
        task.project_id.clone(),
        Some(task.task_id.clone()),
        "workspace_fingerprint",
        format!("workspace/{}/{}.json", task.task_id.as_str(), role),
        "core",
        "workspace-monitor",
        &json!({
            "taskId": task.task_id.as_str(),
            "role": role,
            "sequence": task.current_sequence.get(),
            "fingerprint": {
                "head": fingerprint.head().as_str(),
                "indexDigest": fingerprint.index_digest(),
                "statusDigest": fingerprint.status_digest(),
            },
        }),
        format!(
            "workspace-fingerprint:{}:{}:{role}:{}",
            task.task_id.as_str(),
            task.current_sequence.get(),
            &fingerprint_key[..24]
        ),
    )?;
    if let Some(existing) = database.available_evidence(&request.artifact_id)? {
        if existing.project_id != request.project_id
            || existing.task_id.as_ref() != request.task_id.as_ref()
            || existing.content_hash != request.expected_hash
            || existing.size_bytes != request.expected_size
        {
            return Err(failure(SafeErrorClassification::IntegrityFailure));
        }
        return Ok(existing);
    }
    let created_at = database.now_utc()?;
    let artifact_ref = JournaledArtifactWriter::new(artifacts, database, database).write(
        ArtifactWriteReservation {
            operation_id: request.idempotency_key.clone(),
            artifact: local_agent_terminal_application::ReservedArtifact {
                artifact_id: request.artifact_id.as_str().to_owned(),
                task_id: request.task_id.clone(),
                project_id: request.project_id.as_str().to_owned(),
                artifact_type: request.artifact_type.clone(),
                logical_path: request.logical_path.clone(),
                content_hash: request.expected_hash.clone(),
                storage_key: storage_key(&request.expected_hash)?,
                size_bytes: request.expected_size,
                mime_type: Some("application/json".to_owned()),
                created_by_type: request.created_by_type.clone(),
                created_by_id: request.created_by_id.clone(),
                created_at: created_at.clone(),
                supersedes: None,
            },
            temp_name: format!("{}.tmp", request.artifact_id.as_str()),
            created_at,
        },
        &request.canonical_bytes,
    )?;
    canonical_evidence(&request, &artifact_ref)
}

fn storage_key(hash: &str) -> Result<String, PortError> {
    let encoded = hash
        .strip_prefix("sha256:")
        .filter(|value| value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit()))
        .ok_or_else(|| failure(SafeErrorClassification::IntegrityFailure))?;
    Ok(format!("objects/{}/{}", &encoded[..2], encoded))
}

fn hex_identifier(value: &str) -> String {
    let mut encoded = String::with_capacity(value.len() * 2);
    for byte in value.as_bytes() {
        write!(encoded, "{byte:02x}").expect("writing to String cannot fail");
    }
    encoded
}

fn failure(classification: SafeErrorClassification) -> PortError {
    PortError::failure(
        classification,
        local_agent_terminal_application::Retryability::NonRetryable,
    )
}
