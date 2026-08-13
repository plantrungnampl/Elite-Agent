use local_agent_terminal_domain::{
    ArtifactId, AssuranceDegradationReceipt, Sha256Digest, TaskId, Timestamp, WorkflowProfile,
    WorkflowState,
};
use serde_json::json;
use sha2::{Digest, Sha256};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

use crate::{ArtifactRef, PortError, Retryability, SafeErrorClassification};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProfileEscalationCommand {
    pub revision_id: String,
    pub task_id: TaskId,
    pub expected_stream_version: u64,
    pub from_profile: WorkflowProfile,
    pub to_profile: WorkflowProfile,
    pub reason_artifact_id: ArtifactId,
    pub policy_digest: Sha256Digest,
    pub actor_binding_id: Option<String>,
    pub created_at: Timestamp,
}

impl ProfileEscalationCommand {
    pub fn validate(&self) -> Result<(), PortError> {
        let monotonic = matches!(
            (self.from_profile, self.to_profile),
            (WorkflowProfile::Quick, WorkflowProfile::Standard)
                | (WorkflowProfile::Quick, WorkflowProfile::HighAssurance)
                | (WorkflowProfile::Standard, WorkflowProfile::HighAssurance)
        );
        if !monotonic
            || self.revision_id.trim().is_empty()
            || self.revision_id.chars().count() > 256
            || self.task_id.as_str().chars().count() > 256
            || self.created_at.unix_seconds() < 0
            || self
                .actor_binding_id
                .as_deref()
                .is_some_and(|binding| binding.trim().is_empty() || binding.chars().count() > 256)
        {
            return Err(invalid_input());
        }
        Ok(())
    }

    pub fn receipt_digest(&self) -> Result<Sha256Digest, PortError> {
        self.validate()?;
        let value = json!({
            "actorBindingId": self.actor_binding_id,
            "createdAtUnixSeconds": self.created_at.unix_seconds(),
            "expectedStreamVersion": self.expected_stream_version,
            "fromProfile": self.from_profile.as_str(),
            "policyDigest": self.policy_digest.as_str(),
            "reasonArtifactId": self.reason_artifact_id.as_str(),
            "revisionId": self.revision_id,
            "taskId": self.task_id.as_str(),
            "toProfile": self.to_profile.as_str(),
        });
        let bytes = serde_json_canonicalizer::to_vec(&value).map_err(|_| integrity_failure())?;
        Sha256Digest::new(format!("sha256:{:x}", Sha256::digest(bytes)))
            .map_err(|_| integrity_failure())
    }

    pub fn created_at_rfc3339(&self) -> Result<String, PortError> {
        self.validate()?;
        OffsetDateTime::from_unix_timestamp(self.created_at.unix_seconds())
            .map_err(|_| invalid_input())?
            .format(&Rfc3339)
            .map_err(|_| integrity_failure())
    }
}

pub fn prepare_assurance_acceptance_artifact(
    receipt: &AssuranceDegradationReceipt,
) -> Result<crate::NewArtifact, PortError> {
    if !matches!(
        receipt.decision(),
        local_agent_terminal_domain::AssuranceDecision::ContinueDegraded
    ) {
        return Err(invalid_input());
    }
    let actor_binding_id = receipt.actor_binding_id().ok_or_else(invalid_input)?;
    if receipt.acceptance_artifact_ref().is_none() {
        return Err(invalid_input());
    }
    let value = json!({
        "acceptanceKind": "assurance_degradation",
        "acceptanceArtifactRef": receipt.acceptance_artifact_ref(),
        "actorBindingId": actor_binding_id,
        "createdAt": receipt.created_at_rfc3339(),
        "decision": receipt.decision().as_str(),
        "receiptDigest": receipt.receipt_digest().as_str(),
        "receiptId": receipt.receipt_id(),
        "requestedProfile": receipt.requested_profile().as_str(),
        "schemaVersion": "1.0",
        "taskId": receipt.task_id().as_str(),
    });
    let content = serde_json_canonicalizer::to_vec(&value).map_err(|_| integrity_failure())?;
    Ok(crate::NewArtifact {
        expected_hash: format!("sha256:{:x}", Sha256::digest(&content)),
        expected_size: content.len() as u64,
        content,
    })
}

pub trait AssuranceStore: Send + Sync {
    fn persist_profile_escalation(
        &self,
        command: &ProfileEscalationCommand,
    ) -> Result<WorkflowState, PortError>;

    fn persist_degradation(
        &self,
        receipt: &AssuranceDegradationReceipt,
        artifact: &ArtifactRef,
    ) -> Result<(), PortError>;
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
