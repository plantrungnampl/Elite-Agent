use std::collections::BTreeSet;

use local_agent_terminal_domain::{ArtifactId, ProjectId, Sha256Digest, TaskId, WorkspaceVersion};
use serde::de::{DeserializeSeed, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

use crate::canonical_json::sha256_digest;
use crate::{CanonicalJsonRequest, PortError, Retryability, SafeErrorClassification};

const SCHEMA: &str = "approval-digest.v1";
const SHA256_LENGTH: usize = 71;
const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ToolApprovalPayloadV1 {
    pub schema: String,
    pub approval_type: String,
    pub task_id: String,
    pub operation: ToolApprovalOperationV1,
    pub policy_snapshot_digest: String,
    pub workspace_version: u64,
    pub requested_at: String,
    pub expires_at: String,
    pub nonce: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ToolApprovalOperationV1 {
    pub run_id: String,
    pub plan_step_id: String,
    pub tool: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub executable_digest: Option<String>,
    pub arguments_digest: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub script_digest: Option<String>,
    pub cwd_capability: String,
    pub environment_profile_digest: String,
    pub network_profile: String,
    pub expected_writes: Vec<String>,
    pub executor_fencing_token: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PolicyExceptionApprovalPayloadV1 {
    pub schema: String,
    pub approval_type: String,
    pub task_id: String,
    pub operation: PolicyExceptionApprovalOperationV1,
    pub policy_snapshot_digest: String,
    pub workspace_version: u64,
    pub requested_at: String,
    pub expires_at: String,
    pub nonce: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PolicyExceptionApprovalOperationV1 {
    pub actor_binding_digest: String,
    pub purpose: String,
    pub resource_digest: String,
    pub destination: String,
    pub effective_payload_digest: String,
    pub redaction_report_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApprovalDigestPayload {
    Tool(ToolApprovalPayloadV1),
    PolicyException(PolicyExceptionApprovalPayloadV1),
}

impl Serialize for ApprovalDigestPayload {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            Self::Tool(payload) => payload.serialize(serializer),
            Self::PolicyException(payload) => payload.serialize(serializer),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanonicalApprovalPayload {
    pub canonical_bytes: Vec<u8>,
    pub operation_digest: Sha256Digest,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovalRequestBuild {
    pub artifact_request: CanonicalJsonRequest,
    pub operation_digest: Sha256Digest,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ApprovalId(String);

impl ApprovalId {
    pub fn new(value: impl Into<String>) -> Result<Self, PortError> {
        let value = value.into();
        if !valid_identifier(&value) {
            return Err(invalid_input());
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApprovalState {
    Requested,
    Approved,
    Rejected,
    Invalidated,
    Consumed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewApproval {
    pub approval_id: ApprovalId,
    pub operation_digest: Sha256Digest,
    pub task_id: TaskId,
    pub workspace_version: WorkspaceVersion,
    pub policy_snapshot_digest: Sha256Digest,
    pub fencing_token: Option<u64>,
    pub expires_at: String,
    pub nonce: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovalSnapshot {
    pub approval_id: ApprovalId,
    pub state: ApprovalState,
    pub operation_digest: Sha256Digest,
    pub task_id: TaskId,
    pub workspace_version: WorkspaceVersion,
    pub policy_snapshot_digest: Sha256Digest,
    pub fencing_token: Option<u64>,
    pub expires_at: String,
    pub nonce: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovalResolution {
    pub approval_id: ApprovalId,
    pub approved: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovalCheck {
    pub approval_id: ApprovalId,
    pub expected_operation_digest: Sha256Digest,
    pub task_id: TaskId,
    pub workspace_version: WorkspaceVersion,
    pub policy_snapshot_digest: Sha256Digest,
    pub fencing_token: Option<u64>,
    pub checked_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovalInvalidation {
    pub task_id: TaskId,
    pub workspace_version: WorkspaceVersion,
}

pub trait ApprovalStore: Send + Sync {
    fn request(&self, approval: NewApproval) -> Result<ApprovalSnapshot, PortError>;
    fn resolve(&self, resolution: ApprovalResolution) -> Result<ApprovalSnapshot, PortError>;
    fn valid_for(&self, check: ApprovalCheck) -> Result<Option<ApprovalSnapshot>, PortError>;
    fn invalidate(&self, request: ApprovalInvalidation) -> Result<u64, PortError>;
}

pub fn parse_approval_payload(raw: &str) -> Result<ApprovalDigestPayload, PortError> {
    reject_noncanonical_numbers(raw)?;
    let mut deserializer = serde_json::Deserializer::from_str(raw);
    RejectDuplicateKeys
        .deserialize(&mut deserializer)
        .map_err(|_| invalid_input())?;
    deserializer.end().map_err(|_| invalid_input())?;

    let value: Value = serde_json::from_str(raw).map_err(|_| invalid_input())?;
    let approval_type = value
        .get("approvalType")
        .and_then(Value::as_str)
        .ok_or_else(invalid_input)?;
    let payload = match approval_type {
        "tool" => {
            ApprovalDigestPayload::Tool(serde_json::from_value(value).map_err(|_| invalid_input())?)
        }
        "policy_exception" => ApprovalDigestPayload::PolicyException(
            serde_json::from_value(value).map_err(|_| invalid_input())?,
        ),
        _ => return Err(invalid_input()),
    };
    validate_payload(&payload)?;
    normalize_payload_timestamps(payload)
}

pub fn canonical_approval_payload(
    payload: &ApprovalDigestPayload,
) -> Result<CanonicalApprovalPayload, PortError> {
    validate_payload(payload)?;
    let payload = normalize_payload_timestamps(payload.clone())?;
    let value = serde_json::to_value(payload).map_err(|_| invalid_input())?;
    let canonical_bytes = serde_json_canonicalizer::to_vec(&value).map_err(|_| invalid_input())?;
    let operation_digest =
        Sha256Digest::new(sha256_digest(&canonical_bytes)).map_err(|_| invalid_input())?;
    Ok(CanonicalApprovalPayload {
        canonical_bytes,
        operation_digest,
    })
}

#[allow(clippy::too_many_arguments)]
pub fn build_approval_request(
    artifact_id: ArtifactId,
    project_id: ProjectId,
    task_id: TaskId,
    approval_id: &ApprovalId,
    payload: &ApprovalDigestPayload,
    created_by_id: impl Into<String>,
) -> Result<ApprovalRequestBuild, PortError> {
    if payload_task_id(payload) != task_id.as_str() {
        return Err(invalid_input());
    }
    let canonical = canonical_approval_payload(payload)?;
    let artifact_request = CanonicalJsonRequest::new(
        artifact_id,
        project_id,
        Some(task_id),
        "approval-payload",
        format!("approvals/{}.json", approval_id.as_str()),
        "trusted-core",
        created_by_id,
        &serde_json::from_slice(&canonical.canonical_bytes).map_err(|_| invalid_input())?,
        approval_id.as_str(),
    )?;
    Ok(ApprovalRequestBuild {
        artifact_request,
        operation_digest: canonical.operation_digest,
    })
}

fn validate_payload(payload: &ApprovalDigestPayload) -> Result<(), PortError> {
    match payload {
        ApprovalDigestPayload::Tool(value) => {
            validate_common(
                &value.schema,
                &value.approval_type,
                &value.task_id,
                &value.policy_snapshot_digest,
                value.workspace_version,
                &value.requested_at,
                &value.expires_at,
                &value.nonce,
            )?;
            let operation = &value.operation;
            if value.approval_type != "tool"
                || !valid_identifier(&operation.run_id)
                || !valid_identifier(&operation.plan_step_id)
                || !valid_identifier(&operation.tool)
                || !valid_digest(&operation.arguments_digest)
                || !valid_identifier(&operation.cwd_capability)
                || !valid_digest(&operation.environment_profile_digest)
                || !matches!(
                    operation.network_profile.as_str(),
                    "denied" | "provider_endpoint_only" | "approved_destinations"
                )
                || operation.expected_writes.len() > 1024
                || operation
                    .expected_writes
                    .iter()
                    .any(|path| path.is_empty() || path.len() > 4096)
                || operation
                    .expected_writes
                    .iter()
                    .collect::<BTreeSet<_>>()
                    .len()
                    != operation.expected_writes.len()
                || operation
                    .executor_fencing_token
                    .is_some_and(|token| token == 0 || token > MAX_SAFE_INTEGER)
                || operation
                    .executable_digest
                    .as_deref()
                    .is_some_and(|digest| !valid_digest(digest))
                || operation
                    .script_digest
                    .as_deref()
                    .is_some_and(|digest| !valid_digest(digest))
            {
                return Err(invalid_input());
            }
        }
        ApprovalDigestPayload::PolicyException(value) => {
            validate_common(
                &value.schema,
                &value.approval_type,
                &value.task_id,
                &value.policy_snapshot_digest,
                value.workspace_version,
                &value.requested_at,
                &value.expires_at,
                &value.nonce,
            )?;
            let operation = &value.operation;
            if value.approval_type != "policy_exception"
                || !valid_digest(&operation.actor_binding_digest)
                || operation.purpose.trim().is_empty()
                || operation.purpose.len() > 65_536
                || !valid_digest(&operation.resource_digest)
                || !valid_identifier(&operation.destination)
                || !valid_digest(&operation.effective_payload_digest)
                || !valid_digest(&operation.redaction_report_digest)
            {
                return Err(invalid_input());
            }
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn validate_common(
    schema: &str,
    approval_type: &str,
    task_id: &str,
    policy_snapshot_digest: &str,
    workspace_version: u64,
    requested_at: &str,
    expires_at: &str,
    nonce: &str,
) -> Result<(), PortError> {
    if schema != SCHEMA
        || !matches!(approval_type, "tool" | "policy_exception")
        || !valid_identifier(task_id)
        || !valid_digest(policy_snapshot_digest)
        || !valid_nonce(nonce)
        || workspace_version_is_unsafe(workspace_version)
        || timestamps_are_invalid(requested_at, expires_at)
    {
        return Err(invalid_input());
    }
    Ok(())
}

fn workspace_version_is_unsafe(workspace_version: u64) -> bool {
    workspace_version > MAX_SAFE_INTEGER
}

fn timestamps_are_invalid(requested_at: &str, expires_at: &str) -> bool {
    let Ok(requested_at) = parse_timestamp(requested_at) else {
        return true;
    };
    let Ok(expires_at) = parse_timestamp(expires_at) else {
        return true;
    };
    expires_at <= requested_at
}

fn normalize_payload_timestamps(
    payload: ApprovalDigestPayload,
) -> Result<ApprovalDigestPayload, PortError> {
    match payload {
        ApprovalDigestPayload::Tool(mut value) => {
            value.requested_at = normalize_timestamp(&value.requested_at)?;
            value.expires_at = normalize_timestamp(&value.expires_at)?;
            Ok(ApprovalDigestPayload::Tool(value))
        }
        ApprovalDigestPayload::PolicyException(mut value) => {
            value.requested_at = normalize_timestamp(&value.requested_at)?;
            value.expires_at = normalize_timestamp(&value.expires_at)?;
            Ok(ApprovalDigestPayload::PolicyException(value))
        }
    }
}

fn normalize_timestamp(value: &str) -> Result<String, PortError> {
    parse_timestamp(value)?
        .to_offset(time::UtcOffset::UTC)
        .format(&Rfc3339)
        .map_err(|_| invalid_input())
}

fn parse_timestamp(value: &str) -> Result<OffsetDateTime, PortError> {
    OffsetDateTime::parse(value, &Rfc3339).map_err(|_| invalid_input())
}

fn payload_task_id(payload: &ApprovalDigestPayload) -> &str {
    match payload {
        ApprovalDigestPayload::Tool(payload) => &payload.task_id,
        ApprovalDigestPayload::PolicyException(payload) => &payload.task_id,
    }
}

fn valid_identifier(value: &str) -> bool {
    !value.trim().is_empty() && value.len() <= 256 && !value.contains('\0')
}

fn valid_digest(value: &str) -> bool {
    value.len() == SHA256_LENGTH
        && value.starts_with("sha256:")
        && value[7..]
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn valid_nonce(value: &str) -> bool {
    (32..=256).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
}

fn invalid_input() -> PortError {
    PortError::failure(
        SafeErrorClassification::InvalidInput,
        Retryability::NonRetryable,
    )
}

fn reject_noncanonical_numbers(raw: &str) -> Result<(), PortError> {
    let bytes = raw.as_bytes();
    let mut index = 0;
    let mut in_string = false;
    while index < bytes.len() {
        match bytes[index] {
            b'\\' if in_string => index += 2,
            b'"' => {
                in_string = !in_string;
                index += 1;
            }
            b'-' | b'0'..=b'9' if !in_string => {
                let start = index;
                index += 1;
                while index < bytes.len()
                    && matches!(bytes[index], b'0'..=b'9' | b'.' | b'e' | b'E' | b'+' | b'-')
                {
                    index += 1;
                }
                let number = &raw[start..index];
                if number == "-0" || number.contains(['.', 'e', 'E']) || !integer_is_safe(number) {
                    return Err(invalid_input());
                }
            }
            _ => index += 1,
        }
    }
    if in_string {
        Err(invalid_input())
    } else {
        Ok(())
    }
}

fn integer_is_safe(value: &str) -> bool {
    if value.starts_with('-') {
        value
            .parse::<i64>()
            .is_ok_and(|value| value >= -(MAX_SAFE_INTEGER as i64))
    } else {
        value
            .parse::<u64>()
            .is_ok_and(|value| value <= MAX_SAFE_INTEGER)
    }
}

struct RejectDuplicateKeys;

impl<'de> DeserializeSeed<'de> for RejectDuplicateKeys {
    type Value = ();

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(RejectDuplicateKeysVisitor)
    }
}

struct RejectDuplicateKeysVisitor;

impl<'de> Visitor<'de> for RejectDuplicateKeysVisitor {
    type Value = ();

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("JSON without duplicate object keys")
    }

    fn visit_bool<E>(self, _: bool) -> Result<(), E>
    where
        E: serde::de::Error,
    {
        Ok(())
    }
    fn visit_i64<E>(self, _: i64) -> Result<(), E>
    where
        E: serde::de::Error,
    {
        Ok(())
    }
    fn visit_u64<E>(self, _: u64) -> Result<(), E>
    where
        E: serde::de::Error,
    {
        Ok(())
    }
    fn visit_str<E>(self, _: &str) -> Result<(), E>
    where
        E: serde::de::Error,
    {
        Ok(())
    }
    fn visit_string<E>(self, _: String) -> Result<(), E>
    where
        E: serde::de::Error,
    {
        Ok(())
    }
    fn visit_none<E>(self) -> Result<(), E>
    where
        E: serde::de::Error,
    {
        Ok(())
    }
    fn visit_unit<E>(self) -> Result<(), E>
    where
        E: serde::de::Error,
    {
        Ok(())
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<(), A::Error>
    where
        A: SeqAccess<'de>,
    {
        while sequence.next_element_seed(RejectDuplicateKeys)?.is_some() {}
        Ok(())
    }

    fn visit_map<A>(self, mut map: A) -> Result<(), A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut keys = BTreeSet::new();
        while let Some(key) = map.next_key::<String>()? {
            if !keys.insert(key) {
                return Err(serde::de::Error::custom("duplicate object key"));
            }
            map.next_value_seed(RejectDuplicateKeys)?;
        }
        Ok(())
    }
}
