use local_agent_terminal_domain::{
    CapabilityRef, PolicyActor, PolicyDecisionDraft, PolicyRequest, ResourceClass, Sha256Digest,
    TaskId, TaskRisk, Timestamp,
};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

use crate::{
    canonical_json::{invalid_input, sha256_digest},
    PortError,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyDecision {
    pub draft: PolicyDecisionDraft,
    pub operation_digest: Sha256Digest,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyDecisionId(String);

impl PolicyDecisionId {
    pub fn from_decision(decision: &PolicyDecision) -> Self {
        let digest = decision
            .operation_digest
            .as_str()
            .strip_prefix("sha256:")
            .expect("validated SHA-256 digests always carry the prefix");
        Self(format!("policy-decision:{digest}"))
    }

    pub fn from_persisted(value: impl Into<String>) -> Result<Self, PortError> {
        let value = value.into();
        let Some(digest) = value.strip_prefix("policy-decision:") else {
            return Err(invalid_input());
        };
        if digest.len() != 64
            || !digest
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(invalid_input());
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyRequestBindingDigest(Sha256Digest);

impl PolicyRequestBindingDigest {
    pub const fn as_sha256(&self) -> &Sha256Digest {
        &self.0
    }

    pub(crate) const fn new(digest: Sha256Digest) -> Self {
        Self(digest)
    }

    pub const fn from_persisted(digest: Sha256Digest) -> Self {
        Self(digest)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordedPolicyDecision {
    pub decision: PolicyDecision,
    pub recorded_at: Timestamp,
}

pub trait PolicyEvaluator: Send + Sync {
    fn evaluate(&self, request: PolicyRequest) -> Result<PolicyDecision, PortError>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DisclosureChannel {
    IndexMetadata,
    IndexContent,
    RetrievedItem,
    FinalContextPackage,
    FileRead,
    ListMetadata,
    GitStatus,
    GitDiff,
    Diagnostic,
    Artifact,
    Summary,
    FinalSerializedPayload,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DisclosureContextRequest {
    pub task_id: TaskId,
    pub capability: CapabilityRef,
    pub channel: DisclosureChannel,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustedDisclosureContext {
    pub actor: PolicyActor,
    pub resource_class: ResourceClass,
    pub task_risk: TaskRisk,
    pub workflow_phase: String,
    pub purpose: String,
    pub policy_snapshot_digest: Sha256Digest,
}

pub trait DisclosureContextProvider: Send + Sync {
    fn context(
        &self,
        request: DisclosureContextRequest,
    ) -> Result<TrustedDisclosureContext, PortError>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DisclosureRequest {
    pub policy_request: PolicyRequest,
    pub channel: DisclosureChannel,
    pub bytes: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyApprovalBinding {
    pub effective_payload_digest: Sha256Digest,
    pub redaction_report_digest: Sha256Digest,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyApprovedDisclosure {
    pub decision: PolicyDecision,
    pub channel: DisclosureChannel,
    pub original_digest: Sha256Digest,
    pub effective_bytes: Option<Vec<u8>>,
    pub effective_digest: Option<Sha256Digest>,
    pub redaction_report_digest: Sha256Digest,
    pub approval_binding: Option<PolicyApprovalBinding>,
}

pub trait DisclosurePolicyEvaluator: Send + Sync {
    fn disclose(&self, request: DisclosureRequest) -> Result<PolicyApprovedDisclosure, PortError>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyBoundBytes {
    pub policy_decision_id: PolicyDecisionId,
    pub original_digest: Sha256Digest,
    pub redaction_report_digest: Sha256Digest,
    pub digest: Sha256Digest,
    pub bytes: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DisclosureOutcome<T> {
    Disclosed(T),
    Denied,
    ApprovalRequired { binding: PolicyApprovalBinding },
}

impl<T> DisclosureOutcome<T> {
    pub fn map<U>(self, transform: impl FnOnce(T) -> U) -> DisclosureOutcome<U> {
        match self {
            Self::Disclosed(value) => DisclosureOutcome::Disclosed(transform(value)),
            Self::Denied => DisclosureOutcome::Denied,
            Self::ApprovalRequired { binding } => DisclosureOutcome::ApprovalRequired { binding },
        }
    }
}

pub trait PolicyDecisionStore: Send + Sync {
    fn record(&self, decision: RecordedPolicyDecision) -> Result<PolicyDecisionId, PortError>;
}

pub fn parse_policy_timestamp(value: &str) -> Result<Timestamp, PortError> {
    let timestamp = OffsetDateTime::parse(value, &Rfc3339).map_err(|_| invalid_input())?;
    Ok(Timestamp::from_unix_seconds(timestamp.unix_timestamp()))
}

pub fn bind_disclosure_channel(
    mut decision: PolicyDecision,
    channel: DisclosureChannel,
) -> Result<PolicyDecision, PortError> {
    let value = serde_json::json!({
        "operationDigest": decision.operation_digest.as_str(),
        "disclosureChannel": disclosure_channel_name(channel),
    });
    let canonical = serde_json_canonicalizer::to_vec(&value).map_err(|_| invalid_input())?;
    decision.operation_digest =
        Sha256Digest::new(sha256_digest(&canonical)).map_err(|_| invalid_input())?;
    Ok(decision)
}

const fn disclosure_channel_name(channel: DisclosureChannel) -> &'static str {
    match channel {
        DisclosureChannel::IndexMetadata => "index_metadata",
        DisclosureChannel::IndexContent => "index_content",
        DisclosureChannel::RetrievedItem => "retrieved_item",
        DisclosureChannel::FinalContextPackage => "final_context_package",
        DisclosureChannel::FileRead => "file_read",
        DisclosureChannel::ListMetadata => "list_metadata",
        DisclosureChannel::GitStatus => "git_status",
        DisclosureChannel::GitDiff => "git_diff",
        DisclosureChannel::Diagnostic => "diagnostic",
        DisclosureChannel::Artifact => "artifact",
        DisclosureChannel::Summary => "summary",
        DisclosureChannel::FinalSerializedPayload => "final_serialized_payload",
    }
}
