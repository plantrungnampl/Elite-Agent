use std::collections::HashSet;

use serde_json::{error::Category, Map, Value};

use crate::{ProtocolError, ProtocolFrame};

pub const DEFAULT_MAX_FRAME_BYTES: usize = 8 * 1024 * 1024;

const MIN_TRANSPORT_MAX_FRAME_BYTES: i64 = 1_024;
const MAX_TRANSPORT_MAX_FRAME_BYTES: i64 = 67_108_864;
const MAX_OUTPUT_TOKENS: i64 = 1_000_000;
const MAX_TOOL_REQUESTS: i64 = 10_000;
const MAX_CANCEL_DEADLINE_MS: i64 = 300_000;
const MAX_EVIDENCE_REFS: usize = 128;
const MAX_CLAIMS: usize = 1_024;
const MAX_CONTEXT_ITEMS: i64 = 1_000;
const MAX_CONTEXT_TOKENS: i64 = 1_000_000;
const MAX_REQUIRED_CONTEXT: usize = 128;
const MAX_OBJECT_PROPERTIES: usize = 256;

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
// Validate them before deserialization can normalize the input.
fn validate_v1_constraints(frame: &Value) -> Result<(), ProtocolError> {
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
        "shutdown" | "exit" => validate_properties(params, 0),
        _ => Ok(()),
    }
}

fn validate_initialize(params: &Map<String, Value>) -> Result<(), ProtocolError> {
    validate_array(params.get("protocolVersions"), Some(1), None, true)?;
    validate_array(params.get("features"), None, None, true)?;

    let Some(transport) = params.get("transport").and_then(Value::as_object) else {
        return Ok(());
    };
    validate_integer(
        transport.get("maxFrameBytes"),
        MIN_TRANSPORT_MAX_FRAME_BYTES,
        Some(MAX_TRANSPORT_MAX_FRAME_BYTES),
    )
}

fn validate_run_start(params: &Map<String, Value>) -> Result<(), ProtocolError> {
    let Some(limits) = params.get("limits").and_then(Value::as_object) else {
        return Ok(());
    };
    validate_integer(limits.get("maxOutputTokens"), 1, Some(MAX_OUTPUT_TOKENS))?;
    validate_integer(limits.get("maxToolRequests"), 0, Some(MAX_TOOL_REQUESTS))
}

fn validate_run_cancel(params: &Map<String, Value>) -> Result<(), ProtocolError> {
    validate_integer(params.get("deadlineMs"), 1, Some(MAX_CANCEL_DEADLINE_MS))
}

fn validate_run_complete(params: &Map<String, Value>) -> Result<(), ProtocolError> {
    validate_agent_message(params.get("message"))?;

    let Some(usage) = params.get("usage").and_then(Value::as_object) else {
        return Ok(());
    };
    validate_integer(usage.get("inputTokens"), 0, None)?;
    validate_integer(usage.get("outputTokens"), 0, None)?;
    validate_number(usage.get("providerReportedCost"), 0.0, None)
}

fn validate_agent_message(message: Option<&Value>) -> Result<(), ProtocolError> {
    let Some(message) = message.and_then(Value::as_object) else {
        return Ok(());
    };
    validate_array(message.get("claims"), None, Some(MAX_CLAIMS), false)?;

    let Some(claims) = message.get("claims").and_then(Value::as_array) else {
        return Ok(());
    };
    for claim in claims {
        let Some(claim) = claim.as_object() else {
            continue;
        };
        validate_array(
            claim.get("evidenceRefs"),
            None,
            Some(MAX_EVIDENCE_REFS),
            false,
        )?;
        validate_number(claim.get("confidence"), 0.0, Some(1.0))?;

        let Some(evidence_refs) = claim.get("evidenceRefs").and_then(Value::as_array) else {
            continue;
        };
        for evidence_ref in evidence_refs {
            let Some(evidence_ref) = evidence_ref.as_object() else {
                continue;
            };
            validate_integer(evidence_ref.get("startLine"), 1, None)?;
            validate_integer(evidence_ref.get("endLine"), 1, None)?;
        }
    }
    Ok(())
}

fn validate_stream_delta(params: &Map<String, Value>) -> Result<(), ProtocolError> {
    validate_integer(params.get("sequence"), 1, None)
}

fn validate_context_query(params: &Map<String, Value>) -> Result<(), ProtocolError> {
    validate_array(params.get("scopes"), Some(1), None, true)?;
    validate_integer(params.get("maxItems"), 1, Some(MAX_CONTEXT_ITEMS))?;
    validate_integer(params.get("maxTokens"), 1, Some(MAX_CONTEXT_TOKENS))
}

fn validate_tool_request(params: &Map<String, Value>) -> Result<(), ProtocolError> {
    validate_integer(params.get("executorFencingToken"), 1, None)?;
    validate_max_properties(params.get("arguments"), MAX_OBJECT_PROPERTIES)
}

fn validate_specialist_request(params: &Map<String, Value>) -> Result<(), ProtocolError> {
    validate_array(
        params.get("requiredContext"),
        None,
        Some(MAX_REQUIRED_CONTEXT),
        false,
    )
}

fn validate_heartbeat(params: &Map<String, Value>) -> Result<(), ProtocolError> {
    validate_integer(params.get("sequence"), 1, None)
}

fn validate_error_response(frame: &Map<String, Value>) -> Result<(), ProtocolError> {
    let Some(error) = frame.get("error").and_then(Value::as_object) else {
        return Ok(());
    };
    validate_max_properties(error.get("data"), MAX_OBJECT_PROPERTIES)
}

fn validate_array(
    value: Option<&Value>,
    min_items: Option<usize>,
    max_items: Option<usize>,
    unique_items: bool,
) -> Result<(), ProtocolError> {
    let Some(items) = value.and_then(Value::as_array) else {
        return Ok(());
    };
    if min_items.is_some_and(|min_items| items.len() < min_items)
        || max_items.is_some_and(|max_items| items.len() > max_items)
    {
        return Err(ProtocolError::InvalidFrame);
    }
    if unique_items {
        let mut seen = HashSet::new();
        for item in items {
            let Some(item) = item.as_str() else {
                continue;
            };
            if !seen.insert(item) {
                return Err(ProtocolError::InvalidFrame);
            }
        }
    }
    Ok(())
}

fn validate_max_properties(
    value: Option<&Value>,
    max_properties: usize,
) -> Result<(), ProtocolError> {
    value
        .and_then(Value::as_object)
        .map_or(Ok(()), |properties| {
            validate_properties(properties, max_properties)
        })
}

fn validate_properties(
    properties: &Map<String, Value>,
    max_properties: usize,
) -> Result<(), ProtocolError> {
    if properties.len() > max_properties {
        return Err(ProtocolError::InvalidFrame);
    }
    Ok(())
}

fn validate_integer(
    value: Option<&Value>,
    min: i64,
    max: Option<i64>,
) -> Result<(), ProtocolError> {
    let Some(value) = value else {
        return Ok(());
    };
    let in_range = value
        .as_i64()
        .is_none_or(|value| value >= min && max.is_none_or(|max| value <= max));
    if !in_range {
        return Err(ProtocolError::InvalidFrame);
    }
    Ok(())
}

fn validate_number(value: Option<&Value>, min: f64, max: Option<f64>) -> Result<(), ProtocolError> {
    let Some(value) = value.and_then(Value::as_f64) else {
        return Ok(());
    };
    if value < min || max.is_some_and(|max| value > max) {
        return Err(ProtocolError::InvalidFrame);
    }
    Ok(())
}
