use std::{collections::HashSet, sync::OnceLock};

use serde_json::{error::Category, Map, Value};

use crate::{ProtocolError, ProtocolFrame};

pub const DEFAULT_MAX_FRAME_BYTES: usize = 8 * 1024 * 1024;

const BUNDLED_SCHEMA_SOURCE: &str =
    include_str!("../../../docs/multi-agent-terminal-design/schemas/agent-protocol.v1.schema.json");

const PROTOCOL_VERSIONS_PATH: &str =
    "/$defs/initializeRequest/allOf/1/properties/params/properties/protocolVersions";
const FEATURES_PATH: &str =
    "/$defs/initializeRequest/allOf/1/properties/params/properties/features";
const TRANSPORT_MAX_FRAME_BYTES_PATH: &str =
    "/$defs/initializeRequest/allOf/1/properties/params/properties/transport/properties/maxFrameBytes";
const RUN_MAX_OUTPUT_TOKENS_PATH: &str =
    "/$defs/runStartRequest/allOf/1/properties/params/properties/limits/properties/maxOutputTokens";
const RUN_MAX_TOOL_REQUESTS_PATH: &str =
    "/$defs/runStartRequest/allOf/1/properties/params/properties/limits/properties/maxToolRequests";
const CANCEL_DEADLINE_MS_PATH: &str =
    "/$defs/runCancelRequest/allOf/1/properties/params/properties/deadlineMs";
const EVIDENCE_REFS_PATH: &str = "/$defs/claim/properties/evidenceRefs";
const CLAIM_CONFIDENCE_PATH: &str = "/$defs/claim/properties/confidence";
const CLAIMS_PATH: &str = "/$defs/agentMessage/properties/claims";
const EVIDENCE_START_LINE_PATH: &str = "/$defs/evidenceRef/properties/startLine";
const EVIDENCE_END_LINE_PATH: &str = "/$defs/evidenceRef/properties/endLine";
const INPUT_TOKENS_PATH: &str =
    "/$defs/runCompleteRequest/allOf/1/properties/params/properties/usage/properties/inputTokens";
const OUTPUT_TOKENS_PATH: &str =
    "/$defs/runCompleteRequest/allOf/1/properties/params/properties/usage/properties/outputTokens";
const PROVIDER_REPORTED_COST_PATH: &str =
    "/$defs/runCompleteRequest/allOf/1/properties/params/properties/usage/properties/providerReportedCost";
const STREAM_SEQUENCE_PATH: &str =
    "/$defs/streamDeltaNotification/allOf/1/properties/params/properties/sequence";
const CONTEXT_SCOPES_PATH: &str =
    "/$defs/contextQueryRequest/allOf/1/properties/params/properties/scopes";
const CONTEXT_MAX_ITEMS_PATH: &str =
    "/$defs/contextQueryRequest/allOf/1/properties/params/properties/maxItems";
const CONTEXT_MAX_TOKENS_PATH: &str =
    "/$defs/contextQueryRequest/allOf/1/properties/params/properties/maxTokens";
const EXECUTOR_FENCING_TOKEN_PATH: &str =
    "/$defs/toolRequest/allOf/1/properties/params/properties/executorFencingToken";
const TOOL_ARGUMENTS_PATH: &str =
    "/$defs/toolRequest/allOf/1/properties/params/properties/arguments";
const REQUIRED_CONTEXT_PATH: &str =
    "/$defs/specialistRequest/allOf/1/properties/params/properties/requiredContext";
const HEARTBEAT_SEQUENCE_PATH: &str =
    "/$defs/heartbeatNotification/allOf/1/properties/params/properties/sequence";
const ERROR_DATA_PATH: &str = "/$defs/errorResponse/properties/error/properties/data";

#[derive(Clone, Copy)]
enum SchemaValueKind {
    UnsignedInteger,
    Number,
    True,
}

const SUPPLEMENTAL_SCHEMA_VALUES: &[(&str, &str, SchemaValueKind)] = &[
    (
        PROTOCOL_VERSIONS_PATH,
        "minItems",
        SchemaValueKind::UnsignedInteger,
    ),
    (PROTOCOL_VERSIONS_PATH, "uniqueItems", SchemaValueKind::True),
    (FEATURES_PATH, "uniqueItems", SchemaValueKind::True),
    (
        TRANSPORT_MAX_FRAME_BYTES_PATH,
        "minimum",
        SchemaValueKind::UnsignedInteger,
    ),
    (
        TRANSPORT_MAX_FRAME_BYTES_PATH,
        "maximum",
        SchemaValueKind::UnsignedInteger,
    ),
    (
        RUN_MAX_OUTPUT_TOKENS_PATH,
        "minimum",
        SchemaValueKind::UnsignedInteger,
    ),
    (
        RUN_MAX_OUTPUT_TOKENS_PATH,
        "maximum",
        SchemaValueKind::UnsignedInteger,
    ),
    (
        RUN_MAX_TOOL_REQUESTS_PATH,
        "minimum",
        SchemaValueKind::UnsignedInteger,
    ),
    (
        RUN_MAX_TOOL_REQUESTS_PATH,
        "maximum",
        SchemaValueKind::UnsignedInteger,
    ),
    (
        CANCEL_DEADLINE_MS_PATH,
        "minimum",
        SchemaValueKind::UnsignedInteger,
    ),
    (
        CANCEL_DEADLINE_MS_PATH,
        "maximum",
        SchemaValueKind::UnsignedInteger,
    ),
    (
        EVIDENCE_REFS_PATH,
        "maxItems",
        SchemaValueKind::UnsignedInteger,
    ),
    (CLAIM_CONFIDENCE_PATH, "minimum", SchemaValueKind::Number),
    (CLAIM_CONFIDENCE_PATH, "maximum", SchemaValueKind::Number),
    (CLAIMS_PATH, "maxItems", SchemaValueKind::UnsignedInteger),
    (
        EVIDENCE_START_LINE_PATH,
        "minimum",
        SchemaValueKind::UnsignedInteger,
    ),
    (
        EVIDENCE_END_LINE_PATH,
        "minimum",
        SchemaValueKind::UnsignedInteger,
    ),
    (
        INPUT_TOKENS_PATH,
        "minimum",
        SchemaValueKind::UnsignedInteger,
    ),
    (
        OUTPUT_TOKENS_PATH,
        "minimum",
        SchemaValueKind::UnsignedInteger,
    ),
    (
        PROVIDER_REPORTED_COST_PATH,
        "minimum",
        SchemaValueKind::Number,
    ),
    (
        STREAM_SEQUENCE_PATH,
        "minimum",
        SchemaValueKind::UnsignedInteger,
    ),
    (
        CONTEXT_SCOPES_PATH,
        "minItems",
        SchemaValueKind::UnsignedInteger,
    ),
    (CONTEXT_SCOPES_PATH, "uniqueItems", SchemaValueKind::True),
    (
        CONTEXT_MAX_ITEMS_PATH,
        "minimum",
        SchemaValueKind::UnsignedInteger,
    ),
    (
        CONTEXT_MAX_ITEMS_PATH,
        "maximum",
        SchemaValueKind::UnsignedInteger,
    ),
    (
        CONTEXT_MAX_TOKENS_PATH,
        "minimum",
        SchemaValueKind::UnsignedInteger,
    ),
    (
        CONTEXT_MAX_TOKENS_PATH,
        "maximum",
        SchemaValueKind::UnsignedInteger,
    ),
    (
        EXECUTOR_FENCING_TOKEN_PATH,
        "minimum",
        SchemaValueKind::UnsignedInteger,
    ),
    (
        TOOL_ARGUMENTS_PATH,
        "maxProperties",
        SchemaValueKind::UnsignedInteger,
    ),
    (
        REQUIRED_CONTEXT_PATH,
        "maxItems",
        SchemaValueKind::UnsignedInteger,
    ),
    (
        HEARTBEAT_SEQUENCE_PATH,
        "minimum",
        SchemaValueKind::UnsignedInteger,
    ),
    (
        ERROR_DATA_PATH,
        "maxProperties",
        SchemaValueKind::UnsignedInteger,
    ),
];

static BUNDLED_SCHEMA: OnceLock<Value> = OnceLock::new();

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NdjsonCodec {
    max_frame_bytes: usize,
}

impl Default for NdjsonCodec {
    fn default() -> Self {
        Self::new(DEFAULT_MAX_FRAME_BYTES)
    }
}

impl NdjsonCodec {
    pub const fn new(max_frame_bytes: usize) -> Self {
        Self { max_frame_bytes }
    }

    pub fn decode(&self, line: &[u8]) -> Result<ProtocolFrame, ProtocolError> {
        let frame = line.strip_suffix(b"\n").unwrap_or(line);
        if frame.len() > self.max_frame_bytes {
            return Err(ProtocolError::FrameTooLarge {
                max_frame_bytes: self.max_frame_bytes,
            });
        }
        if frame.is_empty() {
            return Err(ProtocolError::EmptyFrame);
        }
        if frame.contains(&b'\n') || frame.contains(&b'\r') {
            return Err(ProtocolError::MultipleFrames);
        }

        let frame = std::str::from_utf8(frame).map_err(|_| ProtocolError::InvalidUtf8)?;
        let frame: Value = serde_json::from_str(frame).map_err(|error| match error.classify() {
            Category::Data => ProtocolError::InvalidFrame,
            Category::Io | Category::Eof | Category::Syntax => ProtocolError::InvalidJson,
        })?;
        validate_v1_constraints(&frame)?;
        serde_json::from_value(frame).map_err(|_| ProtocolError::InvalidFrame)
    }

    pub fn encode(&self, frame: &ProtocolFrame) -> Result<Vec<u8>, ProtocolError> {
        let frame = serde_json::to_value(frame).map_err(|_| ProtocolError::Encode)?;
        validate_v1_constraints(&frame)?;
        let mut encoded = serde_json::to_vec(&frame).map_err(|_| ProtocolError::Encode)?;
        if encoded.len() > self.max_frame_bytes {
            return Err(ProtocolError::FrameTooLarge {
                max_frame_bytes: self.max_frame_bytes,
            });
        }
        encoded.push(b'\n');
        Ok(encoded)
    }
}

// `typify` represents some bounded collections and scalar ranges with ordinary Rust types.
// Validate against the bundled schema before deserialization can normalize the input.
fn validate_v1_constraints(frame: &Value) -> Result<(), ProtocolError> {
    validate_supplemental_schema()?;

    let Some(frame) = frame.as_object() else {
        return Ok(());
    };

    validate_error_response(frame)?;

    let Some(method) = frame.get("method").and_then(Value::as_str) else {
        return Ok(());
    };
    let Some(params) = frame.get("params").and_then(Value::as_object) else {
        return Ok(());
    };

    match method {
        "initialize" => validate_initialize(params),
        "agent.run.start" => validate_run_start(params),
        "agent.run.cancel" => validate_run_cancel(params),
        "agent.run.complete" => validate_run_complete(params),
        "agent.stream.delta" => validate_stream_delta(params),
        "context.query" => validate_context_query(params),
        "tool.request" => validate_tool_request(params),
        "specialist.request" => validate_specialist_request(params),
        "agent.heartbeat" => validate_heartbeat(params),
        _ => Ok(()),
    }
}

fn validate_initialize(params: &Map<String, Value>) -> Result<(), ProtocolError> {
    validate_minimum_unique_array(params.get("protocolVersions"), PROTOCOL_VERSIONS_PATH)?;
    validate_unique_array(params.get("features"), FEATURES_PATH)?;

    let Some(transport) = params.get("transport").and_then(Value::as_object) else {
        return Ok(());
    };
    validate_bounded_integer(
        transport.get("maxFrameBytes"),
        TRANSPORT_MAX_FRAME_BYTES_PATH,
    )
}

fn validate_run_start(params: &Map<String, Value>) -> Result<(), ProtocolError> {
    let Some(limits) = params.get("limits").and_then(Value::as_object) else {
        return Ok(());
    };
    validate_bounded_integer(limits.get("maxOutputTokens"), RUN_MAX_OUTPUT_TOKENS_PATH)?;
    validate_bounded_integer(limits.get("maxToolRequests"), RUN_MAX_TOOL_REQUESTS_PATH)
}

fn validate_run_cancel(params: &Map<String, Value>) -> Result<(), ProtocolError> {
    validate_bounded_integer(params.get("deadlineMs"), CANCEL_DEADLINE_MS_PATH)
}

fn validate_run_complete(params: &Map<String, Value>) -> Result<(), ProtocolError> {
    validate_agent_message(params.get("message"))?;

    let Some(usage) = params.get("usage").and_then(Value::as_object) else {
        return Ok(());
    };
    validate_minimum_integer(usage.get("inputTokens"), INPUT_TOKENS_PATH)?;
    validate_minimum_integer(usage.get("outputTokens"), OUTPUT_TOKENS_PATH)?;
    validate_minimum_number(
        usage.get("providerReportedCost"),
        PROVIDER_REPORTED_COST_PATH,
    )
}

fn validate_agent_message(message: Option<&Value>) -> Result<(), ProtocolError> {
    let Some(message) = message.and_then(Value::as_object) else {
        return Ok(());
    };
    validate_maximum_array(message.get("claims"), CLAIMS_PATH)?;

    let Some(claims) = message.get("claims").and_then(Value::as_array) else {
        return Ok(());
    };
    for claim in claims {
        let Some(claim) = claim.as_object() else {
            return Err(ProtocolError::InvalidFrame);
        };
        validate_maximum_array(claim.get("evidenceRefs"), EVIDENCE_REFS_PATH)?;
        validate_bounded_number(claim.get("confidence"), CLAIM_CONFIDENCE_PATH)?;

        let Some(evidence_refs) = claim.get("evidenceRefs").and_then(Value::as_array) else {
            return Ok(());
        };
        for evidence_ref in evidence_refs {
            let Some(evidence_ref) = evidence_ref.as_object() else {
                return Err(ProtocolError::InvalidFrame);
            };
            validate_minimum_integer(evidence_ref.get("startLine"), EVIDENCE_START_LINE_PATH)?;
            validate_minimum_integer(evidence_ref.get("endLine"), EVIDENCE_END_LINE_PATH)?;
        }
    }
    Ok(())
}

fn validate_stream_delta(params: &Map<String, Value>) -> Result<(), ProtocolError> {
    validate_minimum_integer(params.get("sequence"), STREAM_SEQUENCE_PATH)
}

fn validate_context_query(params: &Map<String, Value>) -> Result<(), ProtocolError> {
    validate_minimum_unique_array(params.get("scopes"), CONTEXT_SCOPES_PATH)?;
    validate_bounded_integer(params.get("maxItems"), CONTEXT_MAX_ITEMS_PATH)?;
    validate_bounded_integer(params.get("maxTokens"), CONTEXT_MAX_TOKENS_PATH)
}

fn validate_tool_request(params: &Map<String, Value>) -> Result<(), ProtocolError> {
    validate_nullable_minimum_integer(
        params.get("executorFencingToken"),
        EXECUTOR_FENCING_TOKEN_PATH,
    )?;
    validate_max_properties(params.get("arguments"), TOOL_ARGUMENTS_PATH)
}

fn validate_specialist_request(params: &Map<String, Value>) -> Result<(), ProtocolError> {
    validate_maximum_array(params.get("requiredContext"), REQUIRED_CONTEXT_PATH)
}

fn validate_heartbeat(params: &Map<String, Value>) -> Result<(), ProtocolError> {
    validate_minimum_integer(params.get("sequence"), HEARTBEAT_SEQUENCE_PATH)
}

fn validate_error_response(frame: &Map<String, Value>) -> Result<(), ProtocolError> {
    let Some(error) = frame.get("error").and_then(Value::as_object) else {
        return Ok(());
    };
    validate_max_properties(error.get("data"), ERROR_DATA_PATH)
}

fn validate_minimum_unique_array(value: Option<&Value>, path: &str) -> Result<(), ProtocolError> {
    let min_items = schema_usize(path, "minItems")?;
    schema_true(path, "uniqueItems")?;
    let Some(items) = array(value)? else {
        return Ok(());
    };
    if items.len() < min_items {
        return Err(ProtocolError::InvalidFrame);
    }
    validate_unique_strings(items)
}

fn validate_unique_array(value: Option<&Value>, path: &str) -> Result<(), ProtocolError> {
    schema_true(path, "uniqueItems")?;
    let Some(items) = array(value)? else {
        return Ok(());
    };
    validate_unique_strings(items)
}

fn validate_maximum_array(value: Option<&Value>, path: &str) -> Result<(), ProtocolError> {
    let max_items = schema_usize(path, "maxItems")?;
    let Some(items) = array(value)? else {
        return Ok(());
    };
    if items.len() > max_items {
        return Err(ProtocolError::InvalidFrame);
    }
    Ok(())
}

fn validate_unique_strings(items: &[Value]) -> Result<(), ProtocolError> {
    let mut seen = HashSet::new();
    for item in items {
        let Some(item) = item.as_str() else {
            return Err(ProtocolError::InvalidFrame);
        };
        if !seen.insert(item) {
            return Err(ProtocolError::InvalidFrame);
        }
    }
    Ok(())
}

fn validate_max_properties(value: Option<&Value>, path: &str) -> Result<(), ProtocolError> {
    let max_properties = schema_usize(path, "maxProperties")?;
    let Some(value) = value else {
        return Ok(());
    };
    let Some(properties) = value.as_object() else {
        return Err(ProtocolError::InvalidFrame);
    };
    if properties.len() > max_properties {
        return Err(ProtocolError::InvalidFrame);
    }
    Ok(())
}

fn validate_bounded_integer(value: Option<&Value>, path: &str) -> Result<(), ProtocolError> {
    let min = schema_u64(path, "minimum")?;
    let max = schema_u64(path, "maximum")?;
    if min > max {
        return Err(ProtocolError::InvalidFrame);
    }
    validate_integer_value(value, min, Some(max))
}

fn validate_minimum_integer(value: Option<&Value>, path: &str) -> Result<(), ProtocolError> {
    validate_integer_value(value, schema_u64(path, "minimum")?, None)
}

fn validate_nullable_minimum_integer(
    value: Option<&Value>,
    path: &str,
) -> Result<(), ProtocolError> {
    let min = schema_u64(path, "minimum")?;
    if value.is_some_and(Value::is_null) {
        return Ok(());
    }
    validate_integer_value(value, min, None)
}

fn validate_integer_value(
    value: Option<&Value>,
    min: u64,
    max: Option<u64>,
) -> Result<(), ProtocolError> {
    let Some(value) = value else {
        return Ok(());
    };
    let Some(value) = value.as_u64() else {
        return Err(ProtocolError::InvalidFrame);
    };
    if value < min || max.is_some_and(|max| value > max) {
        return Err(ProtocolError::InvalidFrame);
    }
    Ok(())
}

fn validate_bounded_number(value: Option<&Value>, path: &str) -> Result<(), ProtocolError> {
    let min = schema_f64(path, "minimum")?;
    let max = schema_f64(path, "maximum")?;
    if min > max {
        return Err(ProtocolError::InvalidFrame);
    }
    validate_number_value(value, min, Some(max))
}

fn validate_minimum_number(value: Option<&Value>, path: &str) -> Result<(), ProtocolError> {
    validate_number_value(value, schema_f64(path, "minimum")?, None)
}

fn validate_number_value(
    value: Option<&Value>,
    min: f64,
    max: Option<f64>,
) -> Result<(), ProtocolError> {
    let Some(value) = value else {
        return Ok(());
    };
    let Some(value) = value.as_f64() else {
        return Err(ProtocolError::InvalidFrame);
    };
    if value < min || max.is_some_and(|max| value > max) {
        return Err(ProtocolError::InvalidFrame);
    }
    Ok(())
}

fn array(value: Option<&Value>) -> Result<Option<&Vec<Value>>, ProtocolError> {
    value
        .map(|value| value.as_array().ok_or(ProtocolError::InvalidFrame))
        .transpose()
}

fn validate_supplemental_schema() -> Result<(), ProtocolError> {
    for (path, keyword, kind) in SUPPLEMENTAL_SCHEMA_VALUES {
        match kind {
            SchemaValueKind::UnsignedInteger => {
                schema_u64(path, keyword)?;
            }
            SchemaValueKind::Number => {
                schema_f64(path, keyword)?;
            }
            SchemaValueKind::True => {
                schema_true(path, keyword)?;
            }
        }
    }
    Ok(())
}

fn schema_usize(path: &str, keyword: &str) -> Result<usize, ProtocolError> {
    usize::try_from(schema_u64(path, keyword)?).map_err(|_| ProtocolError::InvalidFrame)
}

fn schema_u64(path: &str, keyword: &str) -> Result<u64, ProtocolError> {
    schema_value(path, keyword)?
        .as_u64()
        .ok_or(ProtocolError::InvalidFrame)
}

fn schema_f64(path: &str, keyword: &str) -> Result<f64, ProtocolError> {
    schema_value(path, keyword)?
        .as_f64()
        .filter(|value| value.is_finite())
        .ok_or(ProtocolError::InvalidFrame)
}

fn schema_true(path: &str, keyword: &str) -> Result<(), ProtocolError> {
    match schema_value(path, keyword)?.as_bool() {
        Some(true) => Ok(()),
        Some(false) | None => Err(ProtocolError::InvalidFrame),
    }
}

fn schema_value(path: &str, keyword: &str) -> Result<&'static Value, ProtocolError> {
    bundled_schema()?
        .pointer(path)
        .and_then(|constraint| constraint.get(keyword))
        .ok_or(ProtocolError::InvalidFrame)
}

fn bundled_schema() -> Result<&'static Value, ProtocolError> {
    let schema = BUNDLED_SCHEMA
        .get_or_init(|| serde_json::from_str(BUNDLED_SCHEMA_SOURCE).unwrap_or(Value::Null));
    if schema.is_object() {
        Ok(schema)
    } else {
        Err(ProtocolError::InvalidFrame)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_supplemental_constraint_path_resolves_from_the_bundled_schema() {
        for (path, keyword, kind) in SUPPLEMENTAL_SCHEMA_VALUES {
            let value = schema_value(path, keyword)
                .unwrap_or_else(|_| panic!("schema constraint must resolve: {path}/{keyword}"));
            let valid = match kind {
                SchemaValueKind::UnsignedInteger => value.as_u64().is_some(),
                SchemaValueKind::Number => value.as_f64().is_some(),
                SchemaValueKind::True => value.as_bool() == Some(true),
            };
            assert!(
                valid,
                "schema constraint has the wrong type: {path}/{keyword}"
            );
        }
    }
}
