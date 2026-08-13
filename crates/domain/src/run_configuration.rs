use std::fmt;

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};

use crate::{Sha256Digest, TaskId, Timestamp};

const MAX_ID: usize = 256;
const MAX_REF: usize = 512;

#[derive(Debug, Clone, PartialEq)]
pub struct RunConfiguration {
    unsigned: UnsignedRunConfiguration,
    config_digest: Sha256Digest,
    canonical_bytes: Vec<u8>,
    created_at_rfc3339: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct UnsignedRunConfiguration {
    pub run_configuration_id: String,
    #[serde(
        serialize_with = "serialize_task_id",
        deserialize_with = "deserialize_task_id"
    )]
    pub task_id: TaskId,
    pub provider_connection_ref: String,
    pub adapter: AdapterConfiguration,
    pub model_endpoint: ModelEndpointConfiguration,
    pub agent_profile: AgentProfileConfiguration,
    pub generation_parameters: GenerationParameters,
    pub capability_snapshot: CapabilitySnapshot,
    pub data_policy_snapshot: DataPolicySnapshot,
    pub budget_reservation: RunBudgetReservation,
    pub fallback_policy: FallbackPolicy,
    pub independence: IndependenceConfiguration,
    #[serde(
        serialize_with = "serialize_timestamp",
        deserialize_with = "deserialize_timestamp"
    )]
    pub created_at: Timestamp,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AdapterConfiguration {
    pub adapter_id: String,
    pub adapter_version: String,
    pub transport: AdapterTransport,
    pub protocol: AdapterProtocol,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "optional_digest"
    )]
    pub implementation_digest: Option<Sha256Digest>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AdapterTransport {
    Inproc,
    Stdio,
    Http,
    Websocket,
    AcpBridge,
    McpBridge,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AdapterProtocol {
    #[serde(rename = "mat-agent-control-v2")]
    MatAgentControlV2,
    #[serde(rename = "acp")]
    Acp,
    #[serde(rename = "mcp")]
    Mcp,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ModelEndpointConfiguration {
    pub provider_id: String,
    pub resolved_model_id: String,
    pub model_family: String,
    pub endpoint_class: EndpointClass,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub region: Option<String>,
    pub context_window_tokens: u64,
    pub max_output_tokens: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EndpointClass {
    HostedApi,
    LocalRuntime,
    ManagedCli,
    EnterpriseGateway,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AgentProfileConfiguration {
    pub profile_id: String,
    pub role: AgentRole,
    pub prompt_template_version: String,
    pub tool_policy_ref: String,
    pub response_schema_ref: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentRole {
    Lead,
    Analyst,
    Reviewer,
    Implementer,
    Verifier,
    Specialist,
    Researcher,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GenerationParameters {
    pub temperature: f64,
    pub top_p: f64,
    pub max_output_tokens: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seed: Option<i64>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub stop_sequences: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CapabilitySnapshot {
    pub tool_calling: bool,
    pub structured_output: bool,
    pub streaming: bool,
    pub cancellation: bool,
    pub context_query: bool,
    pub vision: bool,
    pub max_parallel_tool_calls: u64,
    #[serde(with = "digest")]
    pub capability_digest: Sha256Digest,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DataPolicySnapshot {
    #[serde(with = "digest")]
    pub policy_digest: Sha256Digest,
    pub retention_class: RetentionClass,
    pub provider_training_use: ProviderTrainingUse,
    pub allowed_data_classes: Vec<AllowedDataClass>,
    pub network_scope: NetworkScope,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub region_constraint: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RetentionClass {
    None,
    Ephemeral,
    ProviderStandard,
    EnterpriseControlled,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderTrainingUse {
    Forbidden,
    ContractuallyDisabled,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AllowedDataClass {
    Public,
    Internal,
    Confidential,
    SourceCode,
    PersonalData,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NetworkScope {
    Offline,
    Allowlisted,
    ProviderOnly,
    PolicyBrokered,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RunBudgetReservation {
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub tool_calls: u64,
    pub wall_time_ms: u64,
    pub cost_microunits: u64,
    pub currency: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FallbackPolicy {
    pub mode: FallbackMode,
    pub user_approval_required: bool,
    pub candidates: Vec<FallbackCandidate>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FallbackMode {
    None,
    ExplicitOnly,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FallbackCandidate {
    pub provider_connection_ref: String,
    pub resolved_model_id: String,
    pub independence_group: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct IndependenceConfiguration {
    pub group_id: String,
    #[serde(with = "digest")]
    pub fingerprint: Sha256Digest,
    pub dimensions: IndependenceDimensions,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct IndependenceDimensions {
    pub provider: String,
    pub model_family: String,
    pub prompt_family: String,
    pub context_corpus: String,
    pub retrieval_pipeline: String,
    pub tool_policy: String,
    pub adapter_implementation: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct WireRunConfiguration {
    schema_version: String,
    #[serde(flatten)]
    unsigned: UnsignedRunConfiguration,
    credentials_excluded: bool,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "optional_digest"
    )]
    config_digest: Option<Sha256Digest>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RunConfigurationError {
    Invalid,
    Serialization,
}

impl fmt::Display for RunConfigurationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Invalid => "invalid run configuration",
            Self::Serialization => "run configuration serialization failed",
        })
    }
}
impl std::error::Error for RunConfigurationError {}

impl RunConfiguration {
    pub fn issue(unsigned: UnsignedRunConfiguration) -> Result<Self, RunConfigurationError> {
        validate(&unsigned)?;
        let unsigned_wire = WireRunConfiguration {
            schema_version: "1.0".to_owned(),
            unsigned: unsigned.clone(),
            credentials_excluded: true,
            config_digest: None,
        };
        let unsigned_bytes = serde_json_canonicalizer::to_vec(&unsigned_wire)
            .map_err(|_| RunConfigurationError::Serialization)?;
        let config_digest = sha256(&unsigned_bytes);
        let final_wire = WireRunConfiguration {
            schema_version: "1.0".to_owned(),
            unsigned: unsigned.clone(),
            credentials_excluded: true,
            config_digest: Some(config_digest.clone()),
        };
        let canonical_bytes = serde_json_canonicalizer::to_vec(&final_wire)
            .map_err(|_| RunConfigurationError::Serialization)?;
        let created_at_rfc3339 = format_timestamp(unsigned.created_at)?;
        Ok(Self {
            unsigned,
            config_digest,
            canonical_bytes,
            created_at_rfc3339,
        })
    }

    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, RunConfigurationError> {
        let wire: WireRunConfiguration =
            serde_json::from_slice(bytes).map_err(|_| RunConfigurationError::Invalid)?;
        let canonical = serde_json_canonicalizer::to_vec(&wire)
            .map_err(|_| RunConfigurationError::Serialization)?;
        if canonical != bytes || wire.schema_version != "1.0" || !wire.credentials_excluded {
            return Err(RunConfigurationError::Invalid);
        }
        let expected = wire
            .config_digest
            .clone()
            .ok_or(RunConfigurationError::Invalid)?;
        let issued = Self::issue(wire.unsigned)?;
        if issued.config_digest != expected || issued.canonical_bytes != bytes {
            return Err(RunConfigurationError::Invalid);
        }
        Ok(issued)
    }

    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical_bytes
    }
    pub fn config_digest(&self) -> &Sha256Digest {
        &self.config_digest
    }
    pub fn unsigned(&self) -> &UnsignedRunConfiguration {
        &self.unsigned
    }
    pub fn task_id(&self) -> &TaskId {
        &self.unsigned.task_id
    }
    pub fn run_configuration_id(&self) -> &str {
        &self.unsigned.run_configuration_id
    }
    pub fn provider_connection_ref(&self) -> &str {
        &self.unsigned.provider_connection_ref
    }
    pub fn adapter(&self) -> &AdapterConfiguration {
        &self.unsigned.adapter
    }
    pub fn model_endpoint(&self) -> &ModelEndpointConfiguration {
        &self.unsigned.model_endpoint
    }
    pub fn independence(&self) -> &IndependenceConfiguration {
        &self.unsigned.independence
    }
    pub fn created_at(&self) -> Timestamp {
        self.unsigned.created_at
    }
    pub fn created_at_rfc3339(&self) -> &str {
        &self.created_at_rfc3339
    }
}

fn validate(value: &UnsignedRunConfiguration) -> Result<(), RunConfigurationError> {
    let required = [
        (&value.run_configuration_id, MAX_ID),
        (&value.provider_connection_ref, MAX_REF),
        (&value.adapter.adapter_id, MAX_ID),
        (&value.adapter.adapter_version, 128),
        (&value.model_endpoint.provider_id, 128),
        (&value.model_endpoint.resolved_model_id, MAX_ID),
        (&value.model_endpoint.model_family, MAX_ID),
        (&value.agent_profile.profile_id, MAX_ID),
        (&value.agent_profile.prompt_template_version, 128),
        (&value.agent_profile.tool_policy_ref, MAX_REF),
        (&value.agent_profile.response_schema_ref, MAX_REF),
        (&value.independence.group_id, MAX_ID),
        (&value.independence.dimensions.provider, MAX_ID),
        (&value.independence.dimensions.model_family, MAX_ID),
        (&value.independence.dimensions.prompt_family, MAX_ID),
        (&value.independence.dimensions.context_corpus, MAX_ID),
        (&value.independence.dimensions.retrieval_pipeline, MAX_ID),
        (&value.independence.dimensions.tool_policy, MAX_ID),
        (
            &value.independence.dimensions.adapter_implementation,
            MAX_ID,
        ),
    ];
    if required
        .iter()
        .any(|(s, max)| s.is_empty() || s.chars().count() > *max)
        || value.task_id.as_str().chars().count() > MAX_ID
        || value
            .model_endpoint
            .endpoint_ref
            .as_ref()
            .is_some_and(|s| s.is_empty() || s.chars().count() > MAX_REF)
        || value
            .model_endpoint
            .region
            .as_ref()
            .is_some_and(|s| s.is_empty() || s.chars().count() > 128)
        || value
            .data_policy_snapshot
            .region_constraint
            .as_ref()
            .is_some_and(|s| s.is_empty() || s.chars().count() > 128)
        || value.model_endpoint.context_window_tokens < 1024
        || value.model_endpoint.max_output_tokens == 0
        || !(0.0..=2.0).contains(&value.generation_parameters.temperature)
        || !(0.0..=1.0).contains(&value.generation_parameters.top_p)
        || value.generation_parameters.top_p == 0.0
        || value.generation_parameters.max_output_tokens == 0
        || value.generation_parameters.stop_sequences.len() > 32
        || value
            .generation_parameters
            .stop_sequences
            .iter()
            .any(|s| s.chars().count() > MAX_ID)
        || value.capability_snapshot.max_parallel_tool_calls > 128
        || value.data_policy_snapshot.allowed_data_classes.is_empty()
        || has_duplicates(&value.data_policy_snapshot.allowed_data_classes)
        || value.budget_reservation.wall_time_ms == 0
        || !valid_currency(&value.budget_reservation.currency)
        || value.fallback_policy.candidates.len() > 8
        || value.created_at.unix_seconds() < 0
    {
        return Err(RunConfigurationError::Invalid);
    }
    match value.fallback_policy.mode {
        FallbackMode::None if !value.fallback_policy.candidates.is_empty() => {
            return Err(RunConfigurationError::Invalid)
        }
        FallbackMode::ExplicitOnly
            if !value.fallback_policy.user_approval_required
                || value.fallback_policy.candidates.is_empty() =>
        {
            return Err(RunConfigurationError::Invalid)
        }
        _ => {}
    }
    if value.fallback_policy.candidates.iter().any(|c| {
        [
            (&c.provider_connection_ref, MAX_REF),
            (&c.resolved_model_id, MAX_ID),
            (&c.independence_group, MAX_ID),
        ]
        .iter()
        .any(|(s, max)| s.is_empty() || s.chars().count() > *max)
    }) {
        return Err(RunConfigurationError::Invalid);
    }
    Ok(())
}

fn has_duplicates<T: Ord + Clone>(items: &[T]) -> bool {
    let mut sorted = items.to_vec();
    sorted.sort();
    sorted.windows(2).any(|w| w[0] == w[1])
}
fn valid_currency(value: &str) -> bool {
    value.len() == 3 && value.bytes().all(|b| b.is_ascii_uppercase())
}
fn sha256(bytes: &[u8]) -> Sha256Digest {
    Sha256Digest::new(format!("sha256:{:x}", Sha256::digest(bytes)))
        .expect("formatted SHA-256 is valid")
}

fn serialize_task_id<S: Serializer>(value: &TaskId, serializer: S) -> Result<S::Ok, S::Error> {
    serializer.serialize_str(value.as_str())
}
fn deserialize_task_id<'de, D: Deserializer<'de>>(deserializer: D) -> Result<TaskId, D::Error> {
    let value = String::deserialize(deserializer)?;
    TaskId::new(value).map_err(serde::de::Error::custom)
}

mod digest {
    use super::*;
    pub fn serialize<S: Serializer>(
        value: &Sha256Digest,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(value.as_str())
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Sha256Digest, D::Error> {
        let value = String::deserialize(deserializer)?;
        Sha256Digest::new(value).map_err(serde::de::Error::custom)
    }
}
mod optional_digest {
    use super::*;
    pub fn serialize<S: Serializer>(
        value: &Option<Sha256Digest>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        value
            .as_ref()
            .map(Sha256Digest::as_str)
            .serialize(serializer)
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Option<Sha256Digest>, D::Error> {
        Option::<String>::deserialize(deserializer)?
            .map(Sha256Digest::new)
            .transpose()
            .map_err(serde::de::Error::custom)
    }
}

fn serialize_timestamp<S: Serializer>(value: &Timestamp, serializer: S) -> Result<S::Ok, S::Error> {
    format_timestamp(*value)
        .map_err(serde::ser::Error::custom)?
        .serialize(serializer)
}

fn format_timestamp(value: Timestamp) -> Result<String, RunConfigurationError> {
    let seconds = value.unix_seconds();
    if seconds < 0 {
        return Err(RunConfigurationError::Invalid);
    }
    let days = seconds / 86_400;
    let remainder = seconds % 86_400;
    let shifted_days = days + 719_468;
    let era = shifted_days / 146_097;
    let day_of_era = shifted_days - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let mut year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_prime = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_prime + 2) / 5 + 1;
    let month = month_prime + if month_prime < 10 { 3 } else { -9 };
    year += i64::from(month <= 2);
    if year > 9999 {
        return Err(RunConfigurationError::Invalid);
    }
    Ok(format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        remainder / 3_600,
        (remainder % 3_600) / 60,
        remainder % 60
    ))
}

fn deserialize_timestamp<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Timestamp, D::Error> {
    let value = String::deserialize(deserializer)?;
    parse_timestamp(&value)
        .map(Timestamp::from_unix_seconds)
        .ok_or_else(|| serde::de::Error::custom("invalid canonical RFC3339 timestamp"))
}

fn parse_timestamp(value: &str) -> Option<i64> {
    if value.len() != 20
        || value.as_bytes().get(4) != Some(&b'-')
        || value.as_bytes().get(7) != Some(&b'-')
        || value.as_bytes().get(10) != Some(&b'T')
        || value.as_bytes().get(13) != Some(&b':')
        || value.as_bytes().get(16) != Some(&b':')
        || value.as_bytes().get(19) != Some(&b'Z')
    {
        return None;
    }
    let year = value[0..4].parse::<i64>().ok()?;
    let month = value[5..7].parse::<i64>().ok()?;
    let day = value[8..10].parse::<i64>().ok()?;
    let hour = value[11..13].parse::<i64>().ok()?;
    let minute = value[14..16].parse::<i64>().ok()?;
    let second = value[17..19].parse::<i64>().ok()?;
    if !(1..=12).contains(&month)
        || !(1..=days_in_month(year, month)).contains(&day)
        || hour > 23
        || minute > 59
        || second > 59
    {
        return None;
    }
    let adjusted_year = year - i64::from(month <= 2);
    let era = adjusted_year / 400;
    let year_of_era = adjusted_year - era * 400;
    let month_prime = month + if month > 2 { -3 } else { 9 };
    let day_of_year = (153 * month_prime + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    Some((era * 146_097 + day_of_era - 719_468) * 86_400 + hour * 3_600 + minute * 60 + second)
}

fn days_in_month(year: i64, month: i64) -> i64 {
    match month {
        2 if year % 4 == 0 && (year % 100 != 0 || year % 400 == 0) => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}

#[cfg(test)]
mod tests {
    use super::{format_timestamp, parse_timestamp};
    use crate::Timestamp;

    #[test]
    fn canonical_timestamp_is_valid_utc_and_rejects_impossible_dates() {
        assert_eq!(
            format_timestamp(Timestamp::from_unix_seconds(1)).unwrap(),
            "1970-01-01T00:00:01Z"
        );
        assert_eq!(parse_timestamp("1970-01-01T00:00:01Z"), Some(1));
        assert_eq!(parse_timestamp("2026-02-31T00:00:00Z"), None);
        assert_eq!(parse_timestamp("2026-01-01T00:00:00+01:00"), None);
    }
}
