use local_agent_terminal_application::{
    AgentRunStore, ArtifactId, ArtifactRef, ArtifactStore, CanonicalJsonRequest,
    DeliberationArtifactRef, DeliberationRunAssignment, PortError, Retryability,
    SafeErrorClassification, Sha256Digest, SpecialistRequest, TaskQuery, WorkspaceEvidenceStore,
};
use local_agent_terminal_storage_files::ContentAddressedArtifactStore;
use local_agent_terminal_storage_sqlite::SqliteStore;
use serde_json::json;
use sha2::{Digest, Sha256};

use crate::workspace_monitor::publish_canonical_json;

pub(crate) fn publish_specialist_context_package(
    database: &SqliteStore,
    artifacts: &ContentAddressedArtifactStore,
    request: &SpecialistRequest,
    assignment: &DeliberationRunAssignment,
    thread_id: &str,
    audit_artifact: &DeliberationArtifactRef,
) -> Result<DeliberationArtifactRef, PortError> {
    let parent_run = AgentRunStore::load_run(database, request.requesting_run())?
        .ok_or_else(permission_denied)?;
    let parent_context = database
        .context_package_view(&parent_run.request.context.context_package_id)?
        .ok_or_else(permission_denied)?;
    if parent_run.request.task_id != *request.task_id()
        || parent_context.task_id != request.task_id().as_str()
        || parent_context.agent_id != parent_run.request.agent_id
        || parent_context.role != parent_run.request.role
        || parent_context.artifact_id
            != parent_run
                .request
                .context
                .effective_context_artifact_id
                .as_str()
        || parent_context.policy_snapshot_digest
            != parent_run.request.context.policy_snapshot_digest.as_str()
        || request.required_context().len() != 1
        || request.required_context()[0].as_str() != parent_context.artifact_id
    {
        return Err(integrity_failure());
    }
    let mut disclosed_bytes = 0_u64;
    let mut members = Vec::with_capacity(request.required_context().len());
    for artifact_id in request.required_context() {
        let evidence = database
            .available_evidence(artifact_id)?
            .ok_or_else(permission_denied)?;
        if evidence.task_id.as_ref() != Some(request.task_id()) {
            return Err(permission_denied());
        }
        let content = artifacts.read(&ArtifactRef {
            content_hash: evidence.content_hash.clone(),
            storage_key: evidence.storage_key.clone(),
            size_bytes: evidence.size_bytes,
        })?;
        disclosed_bytes = disclosed_bytes
            .checked_add(evidence.size_bytes)
            .ok_or_else(invalid_input)?;
        if disclosed_bytes > request.budget().max_tokens() {
            return Err(conflict());
        }
        members.push(json!({
            "artifactId": artifact_id.as_str(),
            "contentDigest": evidence.content_hash,
            "sizeBytes": evidence.size_bytes,
            "contentBytes": content.bytes,
        }));
    }
    let package_identity = format!(
        "{}:{}:{}",
        request.task_id().as_str(),
        request.request_id(),
        assignment.run_id().as_str(),
    );
    let package_id = ArtifactId::new(format!(
        "specialist-context-{}",
        stable_digest(&package_identity)
    ))
    .map_err(|_| integrity_failure())?;
    let value = json!({
        "schema": "specialist-context-package.v1",
        "packageId": package_id.as_str(),
        "taskId": request.task_id().as_str(),
        "requestId": request.request_id(),
        "parentRunId": request.requesting_run().as_str(),
        "specialist": {
            "runId": assignment.run_id().as_str(),
            "agentId": assignment.agent_id(),
            "actorId": assignment.actor_id().as_str(),
            "family": assignment.family().as_str(),
            "capability": request.capability(),
            "reasonDigest": stable_digest(request.reason()),
        },
        "directThreadId": thread_id,
        "budget": {
            "maxTokens": request.budget().max_tokens(),
            "maxCostMicrounits": request.budget().max_cost_microunits(),
            "deadlineUnixSeconds": request.budget().deadline().unix_seconds(),
            "disclosedBytes": disclosed_bytes,
        },
        "permissions": ["context.read"],
        "policyConstraints": [
            "read-only-preapproval",
            "required-context-artifacts-only",
            "no-tool-access",
        ],
        "provenance": {
            "parentContextPackageId": parent_context.package_id,
            "parentContextArtifactId": parent_context.artifact_id,
            "parentContextPolicySnapshotDigest": parent_context.policy_snapshot_digest,
            "parentContextPolicyDecisionIds": parent_context.policy_decision_ids,
            "parentPromptTemplateVersion": parent_context.prompt_template_version,
            "parentRetrievalPipelineVersion": parent_context.retrieval_pipeline_version,
            "requestAuditArtifactId": audit_artifact.artifact_id().as_str(),
            "requestAuditDigest": audit_artifact.content_digest().as_str(),
        },
        "members": members,
    });
    let published = publish_canonical_json(
        database,
        artifacts,
        CanonicalJsonRequest::new(
            package_id.clone(),
            database.task(request.task_id())?.project_id,
            Some(request.task_id().clone()),
            "specialist-context-package",
            format!("specialist-context-packages/{}.json", package_id.as_str()),
            "core",
            "agent-runtime",
            &value,
            format!("specialist-context-package:{}", package_id.as_str()),
        )?,
    )?;
    DeliberationArtifactRef::new(
        published.artifact_id,
        Sha256Digest::new(published.content_hash).map_err(|_| integrity_failure())?,
        published.size_bytes,
    )
}

fn stable_digest(value: &str) -> String {
    format!("{:x}", Sha256::digest(value.as_bytes()))
}

fn invalid_input() -> PortError {
    PortError::failure(
        SafeErrorClassification::InvalidInput,
        Retryability::NonRetryable,
    )
}

fn conflict() -> PortError {
    PortError::failure(
        SafeErrorClassification::Conflict,
        Retryability::NonRetryable,
    )
}

fn permission_denied() -> PortError {
    PortError::failure(
        SafeErrorClassification::PermissionDenied,
        Retryability::NonRetryable,
    )
}

fn integrity_failure() -> PortError {
    PortError::failure(
        SafeErrorClassification::IntegrityFailure,
        Retryability::NonRetryable,
    )
}
