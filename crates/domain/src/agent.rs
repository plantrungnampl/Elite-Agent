use std::fmt;

use crate::{ArtifactId, RunId, Sha256Digest, TaskId, Timestamp, TrustTier};
use sha2::{Digest, Sha256};

const MAX_IDENTIFIER_LENGTH: usize = 256;
const MAX_DESCRIPTOR_TEXT_LENGTH: usize = MAX_IDENTIFIER_LENGTH;
const MAX_CONTEXT_TEXT_LENGTH: usize = 65_536;
const MAX_CLAIM_TEXT_LENGTH: usize = 131_072;
const MAX_ERROR_TEXT_LENGTH: usize = 65_536;
const MAX_MESSAGE_TYPE_LENGTH: usize = 256;
const MAX_SYMBOL_LENGTH: usize = 1_024;
const MAX_MANIFEST_BYTES: usize = 1_048_576;
const MAX_CLAIMS: usize = 1_024;
const MAX_EVIDENCE_PER_CLAIM: usize = 128;

pub const MAX_GENERATION_PARAMETERS_BYTES: usize = 65_536;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AgentRunStatus {
    Created,
    Accepted,
    Running,
    Succeeded,
    Failed,
    CancelledCleanly,
    Terminated,
    Interrupted,
    Indeterminate,
}

impl AgentRunStatus {
    pub const fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Succeeded
                | Self::Failed
                | Self::CancelledCleanly
                | Self::Terminated
                | Self::Interrupted
                | Self::Indeterminate
        )
    }

    pub const fn can_transition_to(self, next: Self) -> bool {
        match self {
            Self::Created => matches!(
                next,
                Self::Accepted
                    | Self::Failed
                    | Self::CancelledCleanly
                    | Self::Terminated
                    | Self::Interrupted
                    | Self::Indeterminate
            ),
            Self::Accepted => matches!(
                next,
                Self::Running
                    | Self::Failed
                    | Self::CancelledCleanly
                    | Self::Terminated
                    | Self::Interrupted
                    | Self::Indeterminate
            ),
            Self::Running => next.is_terminal(),
            Self::Succeeded
            | Self::Failed
            | Self::CancelledCleanly
            | Self::Terminated
            | Self::Interrupted
            | Self::Indeterminate => false,
        }
    }

    pub fn transition_to(self, next: Self) -> Result<Self, AgentError> {
        if self.can_transition_to(next) {
            Ok(next)
        } else {
            Err(AgentError::InvalidStatusTransition)
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentDescriptor {
    pub agent_id: String,
    pub display_name: String,
    pub trust_tier: TrustTier,
    pub manifest_json: Vec<u8>,
    pub manifest_digest: Sha256Digest,
    pub executable_digest: Option<Sha256Digest>,
    pub enabled: bool,
    pub containment_verified: bool,
}

impl AgentDescriptor {
    pub fn validate(&self) -> Result<(), AgentError> {
        if !valid_identifier(&self.agent_id)
            || !valid_text(&self.display_name, MAX_DESCRIPTOR_TEXT_LENGTH)
            || !valid_json_object(&self.manifest_json, MAX_MANIFEST_BYTES)
            || !digest_matches(&self.manifest_json, &self.manifest_digest)
        {
            return Err(AgentError::InvalidDescriptor);
        }
        validate_trust_binding(
            self.trust_tier,
            self.executable_digest.as_ref(),
            self.enabled,
            self.containment_verified,
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoundEffectiveContext {
    pub context_package_id: String,
    pub task_id: TaskId,
    pub agent_id: String,
    pub role: String,
    pub objective: String,
    pub manifest_artifact_id: ArtifactId,
    pub effective_context_artifact_id: ArtifactId,
    pub content_digest: Sha256Digest,
    pub policy_snapshot_digest: Sha256Digest,
    pub prompt_template_version: String,
    pub retrieval_pipeline_version: String,
    pub created_at: Timestamp,
}

impl BoundEffectiveContext {
    pub fn validate(&self) -> Result<(), AgentError> {
        if !valid_identifier(&self.context_package_id)
            || !valid_identifier(self.task_id.as_str())
            || !valid_identifier(&self.agent_id)
            || !valid_identifier(&self.role)
            || !valid_text(&self.objective, MAX_CONTEXT_TEXT_LENGTH)
            || !valid_identifier(self.manifest_artifact_id.as_str())
            || !valid_identifier(self.effective_context_artifact_id.as_str())
            || !valid_identifier(&self.prompt_template_version)
            || !valid_identifier(&self.retrieval_pipeline_version)
        {
            return Err(AgentError::InvalidContext);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoundGenerationParameters {
    pub canonical_json: Vec<u8>,
    pub digest: Sha256Digest,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AgentRunLimits {
    pub deadline: Timestamp,
    pub max_output_tokens: u64,
    pub max_tool_requests: u64,
    pub max_context_queries: u64,
    pub max_specialist_requests: u64,
}

impl AgentRunLimits {
    pub fn validate(self) -> Result<(), AgentError> {
        if self.deadline.unix_seconds() <= 0
            || !(1..=1_000_000).contains(&self.max_output_tokens)
            || self.max_tool_requests > 10_000
            || self.max_context_queries > 10_000
            || self.max_specialist_requests > 10_000
        {
            Err(AgentError::InvalidRunLimits)
        } else {
            Ok(())
        }
    }
}

impl BoundGenerationParameters {
    pub fn validate(&self) -> Result<(), AgentError> {
        let Some(canonical) =
            canonical_json_object(&self.canonical_json, MAX_GENERATION_PARAMETERS_BYTES)
        else {
            return Err(AgentError::InvalidGenerationParameters);
        };
        if canonical != self.canonical_json || !digest_matches(&canonical, &self.digest) {
            return Err(AgentError::InvalidGenerationParameters);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoundRunConfig {
    pub run_config_artifact_id: ArtifactId,
    pub task_id: TaskId,
    pub agent_id: String,
    pub role: String,
    pub context_package_id: String,
    pub effective_context_artifact_id: ArtifactId,
    pub effective_context_digest: Sha256Digest,
    pub trust_tier: TrustTier,
    pub manifest_digest: Sha256Digest,
    pub executable_digest: Option<Sha256Digest>,
    pub contract_version: String,
    pub adapter_version: String,
    pub provider_id: String,
    pub model_id: String,
    pub generation_parameters: BoundGenerationParameters,
    pub prompt_template_version: String,
    pub response_schema_version: String,
    pub policy_snapshot_digest: Sha256Digest,
    pub limits: AgentRunLimits,
}

impl BoundRunConfig {
    pub fn validate(&self) -> Result<(), AgentError> {
        if !valid_identifier(self.run_config_artifact_id.as_str())
            || !valid_identifier(self.task_id.as_str())
            || !valid_identifier(&self.agent_id)
            || !valid_identifier(&self.role)
            || !valid_identifier(&self.context_package_id)
            || !valid_identifier(self.effective_context_artifact_id.as_str())
            || !valid_identifier(&self.contract_version)
            || !valid_identifier(&self.adapter_version)
            || !valid_identifier(&self.provider_id)
            || !valid_identifier(&self.model_id)
            || !valid_identifier(&self.prompt_template_version)
            || !valid_identifier(&self.response_schema_version)
        {
            return Err(AgentError::InvalidRunConfig);
        }
        validate_executable_trust_binding(self.trust_tier, self.executable_digest.as_ref())?;
        self.generation_parameters.validate()?;
        self.limits.validate()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoundAgentConnection {
    pub connection_id: String,
    pub agent_id: String,
    pub trust_tier: TrustTier,
    pub manifest_digest: Sha256Digest,
    pub executable_digest: Option<Sha256Digest>,
    pub contract_version: String,
    pub adapter_version: String,
    pub binding_digest: Sha256Digest,
}

impl BoundAgentConnection {
    pub fn validate(&self) -> Result<(), AgentError> {
        if !valid_identifier(&self.connection_id)
            || !valid_identifier(&self.agent_id)
            || !valid_identifier(&self.contract_version)
            || !valid_identifier(&self.adapter_version)
        {
            return Err(AgentError::InvalidConnection);
        }
        validate_executable_trust_binding(self.trust_tier, self.executable_digest.as_ref())?;
        if connection_binding_digest_matches(self) {
            Ok(())
        } else {
            Err(AgentError::InvalidConnection)
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoundAgentRunRequest {
    pub run_id: RunId,
    pub task_id: TaskId,
    pub agent_id: String,
    pub role: String,
    pub phase: String,
    pub idempotency_key: String,
    pub context: BoundEffectiveContext,
    pub run_config: BoundRunConfig,
    pub connection: BoundAgentConnection,
    pub supersedes_run_id: Option<RunId>,
}

impl BoundAgentRunRequest {
    pub fn validate(&self) -> Result<(), AgentError> {
        if !valid_identifier(self.run_id.as_str())
            || !valid_identifier(self.task_id.as_str())
            || !valid_identifier(&self.agent_id)
            || !valid_identifier(&self.role)
            || !valid_identifier(&self.phase)
            || !valid_identifier(&self.idempotency_key)
        {
            return Err(AgentError::InvalidRunRequest);
        }
        if let Some(supersedes_run_id) = &self.supersedes_run_id {
            if !valid_identifier(supersedes_run_id.as_str()) {
                return Err(AgentError::InvalidRunRequest);
            }
            if supersedes_run_id == &self.run_id {
                return Err(AgentError::SameRunSupersession);
            }
        }
        self.context.validate()?;
        self.run_config.validate()?;
        self.connection.validate()?;

        if self.task_id != self.context.task_id
            || self.task_id != self.run_config.task_id
            || self.agent_id != self.context.agent_id
            || self.agent_id != self.run_config.agent_id
            || self.agent_id != self.connection.agent_id
            || self.role != self.context.role
            || self.role != self.run_config.role
            || self.context.context_package_id != self.run_config.context_package_id
            || self.context.effective_context_artifact_id
                != self.run_config.effective_context_artifact_id
            || self.context.content_digest != self.run_config.effective_context_digest
            || self.context.policy_snapshot_digest != self.run_config.policy_snapshot_digest
            || self.run_config.trust_tier != self.connection.trust_tier
            || self.run_config.manifest_digest != self.connection.manifest_digest
            || self.run_config.executable_digest != self.connection.executable_digest
            || self.run_config.contract_version != self.connection.contract_version
            || self.run_config.adapter_version != self.connection.adapter_version
        {
            return Err(AgentError::MismatchedBinding);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentRunSnapshot {
    pub request: BoundAgentRunRequest,
    pub status: AgentRunStatus,
    pub accepted_at: Option<Timestamp>,
    pub started_at: Option<Timestamp>,
    pub completed_at: Option<Timestamp>,
}

impl AgentRunSnapshot {
    pub fn created(request: BoundAgentRunRequest) -> Result<Self, AgentError> {
        request.validate()?;
        Ok(Self {
            request,
            status: AgentRunStatus::Created,
            accepted_at: None,
            started_at: None,
            completed_at: None,
        })
    }

    pub fn transition_to(&mut self, next: AgentRunStatus, at: Timestamp) -> Result<(), AgentError> {
        if let Some(previous) = self.completed_at.or(self.started_at).or(self.accepted_at) {
            if at < previous {
                return Err(AgentError::NonMonotonicTimestamp);
            }
        }
        self.status.transition_to(next)?;
        match next {
            AgentRunStatus::Accepted => self.accepted_at = Some(at),
            AgentRunStatus::Running => self.started_at = Some(at),
            AgentRunStatus::Created => return Err(AgentError::InvalidStatusTransition),
            AgentRunStatus::Succeeded
            | AgentRunStatus::Failed
            | AgentRunStatus::CancelledCleanly
            | AgentRunStatus::Terminated
            | AgentRunStatus::Interrupted
            | AgentRunStatus::Indeterminate => self.completed_at = Some(at),
        }
        self.status = next;
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct AgentEvidenceRef {
    pub source_type: String,
    pub source_id: String,
    pub revision: String,
    pub content_digest: Sha256Digest,
    pub start_line: Option<u32>,
    pub end_line: Option<u32>,
    pub symbol: Option<String>,
}

impl AgentEvidenceRef {
    pub fn validate(&self) -> Result<(), AgentError> {
        if !valid_identifier(&self.source_type)
            || !valid_identifier(&self.source_id)
            || !valid_identifier(&self.revision)
            || self
                .symbol
                .as_deref()
                .is_some_and(|symbol| !valid_text(symbol, MAX_SYMBOL_LENGTH))
        {
            return Err(AgentError::InvalidEvidence);
        }
        match (self.start_line, self.end_line) {
            (None, None) => Ok(()),
            (Some(start), Some(end)) if start > 0 && end >= start => Ok(()),
            _ => Err(AgentError::InvalidEvidenceRange),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct AgentClaim {
    pub claim_id: String,
    pub text: String,
    pub evidence: Vec<AgentEvidenceRef>,
    pub confidence: f64,
}

impl AgentClaim {
    pub fn validate(&self) -> Result<(), AgentError> {
        if !valid_identifier(&self.claim_id)
            || !valid_text(&self.text, MAX_CLAIM_TEXT_LENGTH)
            || self.evidence.len() > MAX_EVIDENCE_PER_CLAIM
            || !self.confidence.is_finite()
            || !(0.0..=1.0).contains(&self.confidence)
        {
            return Err(AgentError::InvalidClaim);
        }
        self.evidence
            .iter()
            .try_for_each(AgentEvidenceRef::validate)
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct AgentRunMessage {
    pub message_id: String,
    pub task_id: TaskId,
    pub run_id: RunId,
    pub thread_id: String,
    pub message_type: String,
    pub reply_to: Option<String>,
    pub content_artifact_id: ArtifactId,
    pub claims: Vec<AgentClaim>,
}

impl AgentRunMessage {
    pub fn validate(&self) -> Result<(), AgentError> {
        if !valid_identifier(&self.message_id)
            || !valid_identifier(self.task_id.as_str())
            || !valid_identifier(self.run_id.as_str())
            || !valid_identifier(&self.thread_id)
            || !valid_text(&self.message_type, MAX_MESSAGE_TYPE_LENGTH)
            || !valid_identifier(self.content_artifact_id.as_str())
            || self.claims.len() > MAX_CLAIMS
            || self
                .reply_to
                .as_deref()
                .is_some_and(|reply_to| !valid_identifier(reply_to))
        {
            return Err(AgentError::InvalidMessage);
        }
        self.claims.iter().try_for_each(AgentClaim::validate)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentUsage {
    pub input_tokens: i64,
    pub output_tokens: i64,
    pub cost_microunits: Option<i64>,
}

impl AgentUsage {
    pub fn validate(&self) -> Result<(), AgentError> {
        if self.input_tokens < 0
            || self.output_tokens < 0
            || self.cost_microunits.is_some_and(|cost| cost < 0)
        {
            Err(AgentError::NegativeUsage)
        } else {
            Ok(())
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct AgentRunTerminal {
    pub run_id: RunId,
    pub task_id: TaskId,
    pub status: AgentRunStatus,
    pub message: AgentRunMessage,
    pub provider_usage: Option<AgentUsage>,
    pub core_usage: Option<AgentUsage>,
    pub estimated_cost_microunits: Option<i64>,
    pub error: Option<String>,
    pub core_received_at: Option<Timestamp>,
}

impl AgentRunTerminal {
    pub fn validate(&self) -> Result<(), AgentError> {
        if !valid_identifier(self.run_id.as_str())
            || !valid_identifier(self.task_id.as_str())
            || !self.status.is_terminal()
            || self.message.run_id != self.run_id
            || self.message.task_id != self.task_id
            || self.estimated_cost_microunits.is_some_and(|cost| cost < 0)
            || self
                .error
                .as_deref()
                .is_some_and(|error| !valid_text(error, MAX_ERROR_TEXT_LENGTH))
        {
            return Err(AgentError::InvalidTerminal);
        }
        if self.core_received_at.is_none() {
            return Err(AgentError::MissingCoreReceipt);
        }
        self.message.validate()?;
        if let Some(usage) = &self.provider_usage {
            usage.validate()?;
        }
        if let Some(usage) = &self.core_usage {
            usage.validate()?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentRunReceipt {
    pub run_id: RunId,
    pub accepted_at: Timestamp,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CancelAgentRun {
    pub run_id: RunId,
    pub reason: String,
    pub deadline_ms: u64,
}

impl CancelAgentRun {
    pub fn validate(&self) -> Result<(), AgentError> {
        if !valid_identifier(self.run_id.as_str())
            || !valid_identifier(&self.reason)
            || self.deadline_ms == 0
            || self.deadline_ms > 300_000
        {
            Err(AgentError::InvalidCancellation)
        } else {
            Ok(())
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentCancellationReceipt {
    pub run_id: RunId,
    pub accepted_at: Timestamp,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AgentError {
    InvalidStatusTransition,
    InvalidDescriptor,
    CoreAdapterDigestRequired,
    LegacyAgentEnabled,
    ContainmentRequired,
    InvalidContext,
    InvalidGenerationParameters,
    InvalidRunLimits,
    InvalidRunConfig,
    InvalidConnection,
    InvalidRunRequest,
    SameRunSupersession,
    MismatchedBinding,
    NonMonotonicTimestamp,
    InvalidEvidence,
    InvalidEvidenceRange,
    InvalidClaim,
    InvalidMessage,
    NegativeUsage,
    InvalidTerminal,
    MissingCoreReceipt,
    InvalidCancellation,
}

impl fmt::Display for AgentError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidStatusTransition => "agent run status transition is invalid",
            Self::InvalidDescriptor => "agent descriptor is invalid",
            Self::CoreAdapterDigestRequired => "core adapter requires an implementation digest",
            Self::LegacyAgentEnabled => "full-access legacy agent must remain disabled",
            Self::ContainmentRequired => "enabled agent requires verified containment",
            Self::InvalidContext => "bound context is invalid",
            Self::InvalidGenerationParameters => "generation parameters are invalid",
            Self::InvalidRunLimits => "agent run limits are invalid",
            Self::InvalidRunConfig => "bound run configuration is invalid",
            Self::InvalidConnection => "bound connection is invalid",
            Self::InvalidRunRequest => "bound run request is invalid",
            Self::SameRunSupersession => "run cannot supersede itself",
            Self::MismatchedBinding => "bound agent values do not match",
            Self::NonMonotonicTimestamp => "agent lifecycle time moved backward",
            Self::InvalidEvidence => "agent evidence is invalid",
            Self::InvalidEvidenceRange => "agent evidence line range is invalid",
            Self::InvalidClaim => "agent claim is invalid",
            Self::InvalidMessage => "agent message is invalid",
            Self::NegativeUsage => "agent usage must be nonnegative",
            Self::InvalidTerminal => "agent terminal result is invalid",
            Self::MissingCoreReceipt => "agent terminal result requires a core receipt time",
            Self::InvalidCancellation => "agent cancellation is invalid",
        })
    }
}

impl std::error::Error for AgentError {}

fn validate_trust_binding(
    trust_tier: TrustTier,
    executable_digest: Option<&Sha256Digest>,
    enabled: bool,
    containment_verified: bool,
) -> Result<(), AgentError> {
    if matches!(trust_tier, TrustTier::CoreAdapter) && executable_digest.is_none() {
        return Err(AgentError::CoreAdapterDigestRequired);
    }
    if matches!(trust_tier, TrustTier::FullAccessLegacy) && enabled {
        return Err(AgentError::LegacyAgentEnabled);
    }
    if enabled && trust_tier.requires_containment() && !containment_verified {
        return Err(AgentError::ContainmentRequired);
    }
    Ok(())
}

fn validate_executable_trust_binding(
    trust_tier: TrustTier,
    executable_digest: Option<&Sha256Digest>,
) -> Result<(), AgentError> {
    if matches!(trust_tier, TrustTier::FullAccessLegacy) {
        return Err(AgentError::LegacyAgentEnabled);
    }
    validate_trust_binding(trust_tier, executable_digest, false, true)
}

fn valid_identifier(value: &str) -> bool {
    !value.trim().is_empty() && value.len() <= MAX_IDENTIFIER_LENGTH && !value.contains('\0')
}

fn valid_text(value: &str, maximum_length: usize) -> bool {
    !value.trim().is_empty() && value.len() <= maximum_length && !value.contains('\0')
}

fn valid_json_object(value: &[u8], maximum_length: usize) -> bool {
    if value.is_empty() || value.len() > maximum_length {
        return false;
    }
    matches!(
        serde_json::from_slice::<serde_json::Value>(value),
        Ok(serde_json::Value::Object(_))
    )
}

fn canonical_json_object(value: &[u8], maximum_length: usize) -> Option<Vec<u8>> {
    if value.is_empty() || value.len() > maximum_length {
        return None;
    }
    let parsed = serde_json::from_slice::<serde_json::Value>(value).ok()?;
    if !parsed.is_object() {
        return None;
    }
    serde_json_canonicalizer::to_vec(&parsed).ok()
}

fn connection_binding_digest_matches(connection: &BoundAgentConnection) -> bool {
    let value = serde_json::json!({
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
    serde_json_canonicalizer::to_vec(&value)
        .ok()
        .is_some_and(|canonical| digest_matches(&canonical, &connection.binding_digest))
}

fn digest_matches(bytes: &[u8], expected: &Sha256Digest) -> bool {
    format!("sha256:{:x}", Sha256::digest(bytes)) == expected.as_str()
}
