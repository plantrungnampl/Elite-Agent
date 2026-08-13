use std::sync::OnceLock;

use chrono::DateTime;
use regress::Regex;
use serde_json::{error::Category, Value};

use crate::{ProtocolError, ProtocolFrame};

pub const DEFAULT_MAX_FRAME_BYTES: usize = 8 * 1024 * 1024;

const BUNDLED_SCHEMA_SOURCE: &str =
    include_str!("../../../docs/multi-agent-terminal-design/schemas/agent-protocol.v2.schema.json");

const REQUEST_DEFINITIONS: &[(&str, &str)] = &[
    ("initialize", "initializeRequest"),
    ("initialized", "initializedNotification"),
    ("agent.run.start", "runStartRequest"),
    ("agent.run.cancel", "runCancelRequest"),
    ("agent.run.complete", "runCompleteRequest"),
    ("agent.stream.delta", "streamDeltaNotification"),
    ("context.query", "contextQueryRequest"),
    ("tool.request", "toolRequest"),
    ("specialist.request", "specialistRequest"),
    ("agent.heartbeat", "heartbeatNotification"),
    ("shutdown", "shutdownRequest"),
    ("exit", "exitNotification"),
];

const RESPONSE_DEFINITIONS: &[&str] = &[
    "initializeResponse",
    "runStartResponse",
    "runCancelResponse",
    "runCompleteResponse",
    "contextQueryResponse",
    "toolResponse",
    "specialistResponse",
    "shutdownResponse",
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
        let frame = line
            .strip_suffix(b"\r\n")
            .or_else(|| line.strip_suffix(b"\n"))
            .unwrap_or(line);
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
        validate_frame(&frame)?;
        serde_json::from_value(frame).map_err(|_| ProtocolError::InvalidFrame)
    }

    pub fn encode(&self, frame: &ProtocolFrame) -> Result<Vec<u8>, ProtocolError> {
        let frame = serde_json::to_value(frame).map_err(|_| ProtocolError::Encode)?;
        validate_frame(&frame)?;
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

/// Validates a response using the durable method selected when its request was recorded.
pub(crate) fn validate_response_for_method(
    value: &Value,
    method: &str,
) -> Result<(), ProtocolError> {
    let definition = if value.get("error").is_some() {
        "errorResponse"
    } else {
        response_definition(method).ok_or(ProtocolError::InvalidRequest)?
    };
    validate_definition(value, definition)
}

fn validate_frame(value: &Value) -> Result<(), ProtocolError> {
    let method = value.get("method").and_then(Value::as_str);
    let definition = match method {
        Some(method) => request_definition(method).ok_or(ProtocolError::InvalidFrame)?,
        None if value.get("error").is_some() => "errorResponse",
        None if value.get("result").is_some() => matching_response_definition(value)?,
        None => return Err(ProtocolError::InvalidFrame),
    };
    validate_definition(value, definition)?;
    if let Some(method) = method {
        validate_request_origin(value, method)?;
    }
    Ok(())
}

fn validate_request_origin(value: &Value, method: &str) -> Result<(), ProtocolError> {
    let expected_prefix = match method {
        "initialize" | "agent.run.start" | "agent.run.cancel" | "shutdown" => Some("core:"),
        "agent.run.complete" | "context.query" | "tool.request" | "specialist.request" => {
            Some("agent:")
        }
        "initialized" | "agent.stream.delta" | "agent.heartbeat" | "exit" => None,
        _ => return Err(ProtocolError::InvalidFrame),
    };
    match expected_prefix {
        Some(prefix)
            if value
                .get("id")
                .and_then(Value::as_str)
                .is_some_and(|id| id.starts_with(prefix)) =>
        {
            Ok(())
        }
        Some(_) => Err(ProtocolError::InvalidFrame),
        None => Ok(()),
    }
}

fn request_definition(method: &str) -> Option<&'static str> {
    REQUEST_DEFINITIONS
        .iter()
        .find_map(|(known_method, definition)| (*known_method == method).then_some(*definition))
}

fn response_definition(method: &str) -> Option<&'static str> {
    match method {
        "initialize" => Some("initializeResponse"),
        "agent.run.start" => Some("runStartResponse"),
        "agent.run.cancel" => Some("runCancelResponse"),
        "agent.run.complete" => Some("runCompleteResponse"),
        "context.query" => Some("contextQueryResponse"),
        "tool.request" => Some("toolResponse"),
        "specialist.request" => Some("specialistResponse"),
        "shutdown" => Some("shutdownResponse"),
        _ => None,
    }
}

fn matching_response_definition(value: &Value) -> Result<&'static str, ProtocolError> {
    let mut matching = RESPONSE_DEFINITIONS
        .iter()
        .copied()
        .filter(|definition| validate_definition(value, definition).is_ok());
    let definition = matching.next().ok_or(ProtocolError::InvalidFrame)?;
    if matching.next().is_some() {
        return Err(ProtocolError::InvalidFrame);
    }
    Ok(definition)
}

fn validate_definition(value: &Value, definition: &str) -> Result<(), ProtocolError> {
    let schema = bundled_schema()?;
    let definition = schema
        .pointer(&format!("/$defs/{definition}"))
        .ok_or(ProtocolError::InvalidFrame)?;
    validate_schema(value, definition, schema)
        .then_some(())
        .ok_or(ProtocolError::InvalidFrame)
}

fn validate_schema(value: &Value, schema: &Value, root: &Value) -> bool {
    if let Some(reference) = schema.get("$ref").and_then(Value::as_str) {
        let Some(referenced) = resolve_reference(root, reference) else {
            return false;
        };
        return validate_schema(value, referenced, root);
    }

    if let Some(schemas) = schema.get("oneOf").and_then(Value::as_array) {
        return schemas
            .iter()
            .filter(|candidate| validate_schema(value, candidate, root))
            .take(2)
            .count()
            == 1;
    }
    if let Some(schemas) = schema.get("allOf").and_then(Value::as_array) {
        if !schemas
            .iter()
            .all(|candidate| validate_schema(value, candidate, root))
        {
            return false;
        }
    }
    if let Some(expected) = schema.get("const") {
        if value != expected {
            return false;
        }
    }
    if let Some(values) = schema.get("enum").and_then(Value::as_array) {
        if !values.iter().any(|candidate| candidate == value) {
            return false;
        }
    }
    if !matches_type(value, schema.get("type")) {
        return false;
    }
    validate_string(value, schema)
        && validate_number(value, schema)
        && validate_array(value, schema, root)
        && validate_object(value, schema, root)
}

fn resolve_reference<'a>(root: &'a Value, reference: &str) -> Option<&'a Value> {
    reference
        .strip_prefix('#')
        .and_then(|path| root.pointer(path))
}

fn matches_type(value: &Value, kind: Option<&Value>) -> bool {
    let Some(kind) = kind else {
        return true;
    };
    match kind {
        Value::String(kind) => matches_named_type(value, kind),
        Value::Array(kinds) => kinds
            .iter()
            .filter_map(Value::as_str)
            .any(|kind| matches_named_type(value, kind)),
        _ => false,
    }
}

fn matches_named_type(value: &Value, kind: &str) -> bool {
    match kind {
        "object" => value.is_object(),
        "array" => value.is_array(),
        "string" => value.is_string(),
        "integer" => value.as_i64().is_some() || value.as_u64().is_some(),
        "number" => value.as_f64().is_some(),
        "boolean" => value.is_boolean(),
        "null" => value.is_null(),
        _ => false,
    }
}

fn validate_string(value: &Value, schema: &Value) -> bool {
    let Some(value) = value.as_str() else {
        return true;
    };
    if schema
        .get("minLength")
        .and_then(Value::as_u64)
        .is_some_and(|minimum| value.chars().count() < minimum as usize)
        || schema
            .get("maxLength")
            .and_then(Value::as_u64)
            .is_some_and(|maximum| value.chars().count() > maximum as usize)
    {
        return false;
    }
    if let Some(pattern) = schema.get("pattern").and_then(Value::as_str) {
        let Ok(pattern) = Regex::new(pattern) else {
            return false;
        };
        if pattern.find(value).is_none() {
            return false;
        }
    }
    match schema.get("format").and_then(Value::as_str) {
        Some("date-time") => DateTime::parse_from_rfc3339(value).is_ok(),
        Some(_) | None => true,
    }
}

fn validate_number(value: &Value, schema: &Value) -> bool {
    let Some(value) = value.as_f64() else {
        return true;
    };
    !schema
        .get("minimum")
        .and_then(Value::as_f64)
        .is_some_and(|minimum| value < minimum)
        && !schema
            .get("maximum")
            .and_then(Value::as_f64)
            .is_some_and(|maximum| value > maximum)
}

fn validate_array(value: &Value, schema: &Value, root: &Value) -> bool {
    let Some(values) = value.as_array() else {
        return true;
    };
    if schema
        .get("minItems")
        .and_then(Value::as_u64)
        .is_some_and(|minimum| values.len() < minimum as usize)
        || schema
            .get("maxItems")
            .and_then(Value::as_u64)
            .is_some_and(|maximum| values.len() > maximum as usize)
    {
        return false;
    }
    if schema.get("uniqueItems").and_then(Value::as_bool) == Some(true)
        && values
            .iter()
            .enumerate()
            .any(|(index, value)| values[..index].contains(value))
    {
        return false;
    }
    schema.get("items").is_none_or(|items| {
        values
            .iter()
            .all(|value| validate_schema(value, items, root))
    })
}

fn validate_object(value: &Value, schema: &Value, root: &Value) -> bool {
    let Some(object) = value.as_object() else {
        return true;
    };
    let properties = schema.get("properties").and_then(Value::as_object);
    if schema
        .get("required")
        .and_then(Value::as_array)
        .is_some_and(|required| {
            required
                .iter()
                .filter_map(Value::as_str)
                .any(|name| !object.contains_key(name))
        })
        || schema
            .get("maxProperties")
            .and_then(Value::as_u64)
            .is_some_and(|maximum| object.len() > maximum as usize)
    {
        return false;
    }
    if let Some(property_names) = schema.get("propertyNames") {
        if object
            .keys()
            .any(|name| !validate_schema(&Value::String(name.clone()), property_names, root))
        {
            return false;
        }
    }

    for (name, value) in object {
        if let Some(property) = properties.and_then(|properties| properties.get(name)) {
            if !validate_schema(value, property, root) {
                return false;
            }
            continue;
        }
        match schema.get("additionalProperties") {
            Some(Value::Bool(false)) => return false,
            Some(additional) if !additional.is_boolean() => {
                if !validate_schema(value, additional, root) {
                    return false;
                }
            }
            Some(Value::Bool(true)) | None => {}
            Some(_) => return false,
        }
    }
    true
}

fn bundled_schema() -> Result<&'static Value, ProtocolError> {
    let schema = BUNDLED_SCHEMA
        .get_or_init(|| serde_json::from_str(BUNDLED_SCHEMA_SOURCE).unwrap_or(Value::Null));
    schema
        .is_object()
        .then_some(schema)
        .ok_or(ProtocolError::InvalidFrame)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_named_definition_resolves_from_the_bundled_schema() {
        for (_, definition) in REQUEST_DEFINITIONS {
            validate_definition(&serde_json::json!({}), definition)
                .expect_err("an empty object cannot validate, but the definition must resolve");
        }
        for definition in RESPONSE_DEFINITIONS {
            validate_definition(&serde_json::json!({}), definition)
                .expect_err("an empty object cannot validate, but the definition must resolve");
        }
    }
}
