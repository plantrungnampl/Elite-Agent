use local_agent_terminal_agent_protocol::{ProtocolError, RunStart, DEFAULT_MAX_FRAME_BYTES};
use serde_json::{Map, Value};

pub const MAX_PROMPT_BYTES: usize = DEFAULT_MAX_FRAME_BYTES;

pub(crate) struct PreparedRequest {
    pub(crate) run_id: String,
    pub(crate) body: Vec<u8>,
}

pub(crate) fn prepare(request: &RunStart) -> Result<PreparedRequest, ProtocolError> {
    let binding = request.execution_binding();
    if binding.effective_context.len() > MAX_PROMPT_BYTES {
        return Err(ProtocolError::ContextTooLarge);
    }
    let input = std::str::from_utf8(&binding.effective_context)
        .map_err(|_| ProtocolError::InvalidRequest)?;
    let generation_parameters: Value = serde_json::from_slice(&binding.generation_parameters)
        .map_err(|_| ProtocolError::InvalidRequest)?;
    let parameters = generation_parameters
        .as_object()
        .ok_or(ProtocolError::InvalidRequest)?;
    reject_forbidden_parameters(parameters)?;

    let mut body = parameters.clone();
    body.insert("model".to_owned(), Value::String(binding.model_id.clone()));
    body.insert("input".to_owned(), Value::String(input.to_owned()));
    body.insert("stream".to_owned(), Value::Bool(true));
    body.insert("store".to_owned(), Value::Bool(false));
    body.insert(
        "max_output_tokens".to_owned(),
        Value::Number(output_limit(request)?.into()),
    );
    Ok(PreparedRequest {
        run_id: request.run_id(),
        body: serde_json::to_vec(&body).map_err(|_| ProtocolError::Encode)?,
    })
}

fn reject_forbidden_parameters(parameters: &Map<String, Value>) -> Result<(), ProtocolError> {
    if [
        "input",
        "max_output_tokens",
        "model",
        "parallel_tool_calls",
        "store",
        "stream",
        "tool_choice",
        "tools",
    ]
    .into_iter()
    .any(|name| parameters.contains_key(name))
    {
        Err(ProtocolError::InvalidRequest)
    } else {
        Ok(())
    }
}

fn output_limit(request: &RunStart) -> Result<u64, ProtocolError> {
    serde_json::to_value(request.as_frame())
        .map_err(|_| ProtocolError::InvalidRequest)?
        .pointer("/params/limits/maxOutputTokens")
        .and_then(Value::as_u64)
        .ok_or(ProtocolError::InvalidRequest)
}
