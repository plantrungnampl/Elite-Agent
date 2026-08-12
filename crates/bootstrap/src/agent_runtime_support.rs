use local_agent_terminal_application::{
    BoundAgentConnection, DeliberationSnapshot, PortError, ProjectId, Retryability,
    SafeErrorClassification, Sha256Digest, TaskId, TaskQuery,
};
use local_agent_terminal_storage_sqlite::SqliteStore;
use serde_json::json;
use sha2::{Digest, Sha256};

pub(super) struct AuthoritativeContextContract {
    pub shared_summary: String,
    pub accepted_decisions: Vec<String>,
    pub unresolved_objections: Vec<String>,
    pub active_thread_messages: Vec<String>,
}

pub(super) fn deliberation_context_contract(
    deliberation: &DeliberationSnapshot,
    objective: &str,
) -> AuthoritativeContextContract {
    let accepted_decisions = deliberation
        .decision_drafts()
        .iter()
        .map(|decision| {
            format!(
                "decision:{}:artifact={}:planVersion={}:selected={}",
                decision.event_id().as_str(),
                decision.artifact().artifact_id().as_str(),
                decision.plan_version(),
                decision.decision().selected().approach_id(),
            )
        })
        .collect();
    let unresolved_objections = deliberation
        .objection_sets()
        .last()
        .map(|set| {
            set.objections()
                .objections()
                .iter()
                .map(|objection| {
                    format!(
                        "objection:{}:round={}:severity={:?}",
                        objection.participant_id(),
                        objection.round(),
                        objection.severity(),
                    )
                })
                .collect()
        })
        .unwrap_or_default();
    let active_thread_messages = deliberation
        .thread_summaries()
        .iter()
        .map(|thread| {
            format!(
                "thread:{}:summaryArtifact={}",
                thread.thread_id(),
                thread.artifact().artifact_id().as_str(),
            )
        })
        .collect();
    AuthoritativeContextContract {
        shared_summary: format!(
            "task={};phase={};version={};objective={objective}",
            deliberation.task_id.as_str(),
            deliberation.task_state.phase().as_str(),
            deliberation.task_version,
        ),
        accepted_decisions,
        unresolved_objections,
        active_thread_messages,
    }
}

pub(super) fn connection_digest(
    connection: &BoundAgentConnection,
) -> Result<Sha256Digest, PortError> {
    let value = json!({
        "schema": "agent-connection-binding.v1",
        "identity": {
            "connectionId": connection.connection_id,
            "agentId": connection.agent_id,
        },
        "manifestDigest": connection.manifest_digest.as_str(),
        "executableDigest": connection.executable_digest.as_ref().map(Sha256Digest::as_str),
        "trustTier": connection.trust_tier.as_str(),
        "contractVersion": connection.contract_version,
        "adapterVersion": connection.adapter_version,
    });
    let canonical = serde_json_canonicalizer::to_vec(&value).map_err(|_| integrity_failure())?;
    Ok(digest_bytes(&canonical))
}

pub(super) fn project_id(database: &SqliteStore, task_id: &TaskId) -> Result<ProjectId, PortError> {
    Ok(database.task(task_id)?.project_id)
}

pub(super) fn digest_bytes(bytes: &[u8]) -> Sha256Digest {
    Sha256Digest::new(format!("sha256:{:x}", Sha256::digest(bytes)))
        .expect("SHA-256 formatting is valid")
}

pub(super) fn stable_digest(value: &str) -> String {
    format!("{:x}", Sha256::digest(value.as_bytes()))
}

pub(super) fn invalid_input() -> PortError {
    failure(SafeErrorClassification::InvalidInput)
}

pub(super) fn not_found() -> PortError {
    failure(SafeErrorClassification::NotFound)
}

pub(super) fn unavailable() -> PortError {
    failure(SafeErrorClassification::Unavailable)
}

pub(super) fn integrity_failure() -> PortError {
    failure(SafeErrorClassification::IntegrityFailure)
}

pub(super) fn conflict() -> PortError {
    failure(SafeErrorClassification::Conflict)
}

pub(super) fn permission_denied() -> PortError {
    failure(SafeErrorClassification::PermissionDenied)
}

fn failure(classification: SafeErrorClassification) -> PortError {
    PortError::failure(classification, Retryability::NonRetryable)
}
