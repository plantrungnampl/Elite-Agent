use std::{
    collections::BTreeMap,
    fmt,
    io::BufReader,
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc, Mutex,
    },
    thread::{self, JoinHandle},
    time::{Duration, SystemTime},
};

use local_agent_terminal_agent_protocol::{
    CancelAcceptance, NdjsonCodec, PeerDescriptor, PeerEventSink, ProtocolError, ProtocolPeer,
    RunAcceptance, RunCancel, RunStart,
};
use reqwest::{
    blocking::{Client, Response},
    header::{self, HeaderMap},
    StatusCode,
};
use serde_json::{json, Map, Value};

use crate::{
    config::OpenAiProviderConfig,
    request::{prepare, PreparedRequest},
    sse::{SseReader, MAX_SSE_EVENT_BYTES},
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenAiDiagnostic {
    pub run_id: String,
    pub response_id: Option<String>,
    pub retry_after: Option<Duration>,
    pub error: Option<ProtocolError>,
}

pub struct OpenAiResponsesAdapter {
    config: OpenAiProviderConfig,
    descriptor: PeerDescriptor,
    client: Client,
    cancellations: Arc<Mutex<BTreeMap<String, Arc<AtomicBool>>>>,
    diagnostics: Arc<Mutex<BTreeMap<String, OpenAiDiagnostic>>>,
    workers: Mutex<Vec<JoinHandle<()>>>,
    terminal_ids: AtomicU64,
}

struct Completion {
    response_id: Option<String>,
    text: String,
    usage: Option<Usage>,
}

struct Usage {
    input_tokens: u64,
    output_tokens: u64,
}

struct StreamFailure {
    error: ProtocolError,
    response_id: Option<String>,
    retry_after: Option<Duration>,
    message: &'static str,
}

impl StreamFailure {
    fn from_error(error: ProtocolError, response_id: Option<String>) -> Self {
        Self {
            message: safe_error_message(error),
            error,
            response_id,
            retry_after: None,
        }
    }

    fn no_text(response_id: Option<String>, refused: bool) -> Self {
        Self {
            error: ProtocolError::ProviderUnavailable,
            response_id,
            retry_after: None,
            message: if refused {
                "provider refused to produce output text"
            } else {
                "provider response contained no output text"
            },
        }
    }
}

impl OpenAiResponsesAdapter {
    pub fn new(
        config: OpenAiProviderConfig,
        descriptor: PeerDescriptor,
    ) -> Result<Self, ProtocolError> {
        let client = Client::builder()
            .connect_timeout(config.connect_timeout())
            .timeout(config.read_timeout())
            .build()
            .map_err(|_| ProtocolError::ProviderUnavailable)?;
        Ok(Self {
            config,
            descriptor,
            client,
            cancellations: Arc::new(Mutex::new(BTreeMap::new())),
            diagnostics: Arc::new(Mutex::new(BTreeMap::new())),
            workers: Mutex::new(Vec::new()),
            terminal_ids: AtomicU64::new(1),
        })
    }

    pub fn diagnostics(&self) -> Vec<OpenAiDiagnostic> {
        self.diagnostics
            .lock()
            .map(|diagnostics| diagnostics.values().cloned().collect())
            .unwrap_or_default()
    }

    fn next_terminal_id(&self) -> u64 {
        self.terminal_ids.fetch_add(1, Ordering::Relaxed)
    }

    fn reap_finished_workers(&self) -> Result<(), ProtocolError> {
        let mut workers = self
            .workers
            .lock()
            .map_err(|_| ProtocolError::InternalAgentFailure)?;
        let mut unfinished = Vec::new();
        let mut failed = false;
        for worker in std::mem::take(&mut *workers) {
            if worker.is_finished() {
                failed |= worker.join().is_err();
            } else {
                unfinished.push(worker);
            }
        }
        *workers = unfinished;
        if failed {
            Err(ProtocolError::InternalAgentFailure)
        } else {
            Ok(())
        }
    }
}

impl fmt::Debug for OpenAiResponsesAdapter {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OpenAiResponsesAdapter")
            .field("config", &self.config)
            .field("descriptor", &self.descriptor)
            .field(
                "active_runs",
                &self.cancellations.lock().map_or(0, |runs| runs.len()),
            )
            .field("diagnostics", &self.diagnostics())
            .finish()
    }
}

impl ProtocolPeer for OpenAiResponsesAdapter {
    fn descriptor(&self) -> PeerDescriptor {
        self.descriptor.clone()
    }

    fn start(
        &self,
        request: RunStart,
        sink: Box<dyn PeerEventSink>,
    ) -> Result<RunAcceptance, ProtocolError> {
        self.reap_finished_workers()?;
        let prepared = prepare(&request)?;
        let cancellation = Arc::new(AtomicBool::new(false));
        {
            let mut cancellations = self
                .cancellations
                .lock()
                .map_err(|_| ProtocolError::InternalAgentFailure)?;
            if cancellations.contains_key(&prepared.run_id) {
                return Err(ProtocolError::InvalidRequest);
            }
            cancellations.insert(prepared.run_id.clone(), Arc::clone(&cancellation));
        }

        let config = self.config.clone();
        let client = self.client.clone();
        let cancellations = Arc::clone(&self.cancellations);
        let diagnostics = Arc::clone(&self.diagnostics);
        let terminal_id = self.next_terminal_id();
        let run_id = prepared.run_id.clone();
        let worker_run_id = run_id.clone();
        let worker_cancellation = Arc::clone(&cancellation);
        let worker = thread::Builder::new()
            .name(format!("openai-response-{terminal_id}"))
            .spawn(move || {
                let outcome =
                    stream_response(&client, &config, prepared, &*sink, &worker_cancellation);
                if let Ok(mut cancellations) = cancellations.lock() {
                    cancellations.remove(&worker_run_id);
                }
                match outcome {
                    Ok(completion) => {
                        record_diagnostic(
                            &diagnostics,
                            &worker_run_id,
                            completion.response_id,
                            None,
                            None,
                        );
                        let _ = terminal(
                            &*sink,
                            &worker_run_id,
                            terminal_id,
                            "succeeded",
                            &completion.text,
                            completion.usage,
                        );
                    }
                    Err(failure) => {
                        let status = if failure.error == ProtocolError::Cancelled {
                            "cancelled_cleanly"
                        } else {
                            "failed"
                        };
                        record_diagnostic(
                            &diagnostics,
                            &worker_run_id,
                            failure.response_id,
                            failure.retry_after,
                            Some(failure.error),
                        );
                        let _ = terminal(
                            &*sink,
                            &worker_run_id,
                            terminal_id,
                            status,
                            failure.message,
                            None,
                        );
                    }
                }
            });
        let worker = match worker {
            Ok(worker) => worker,
            Err(_) => {
                self.cancellations
                    .lock()
                    .map_err(|_| ProtocolError::InternalAgentFailure)?
                    .remove(&run_id);
                return Err(ProtocolError::ProviderUnavailable);
            }
        };
        match self.workers.lock() {
            Ok(mut workers) => workers.push(worker),
            Err(_) => {
                cancellation.store(true, Ordering::Release);
                let _ = worker.join();
                if let Ok(mut cancellations) = self.cancellations.lock() {
                    cancellations.remove(&run_id);
                }
                return Err(ProtocolError::InternalAgentFailure);
            }
        }
        Ok(RunAcceptance {
            run_id,
            accepted: true,
        })
    }

    fn cancel(&self, request: RunCancel) -> Result<CancelAcceptance, ProtocolError> {
        let run_id = request.run_id();
        let accepted = self
            .cancellations
            .lock()
            .map_err(|_| ProtocolError::InternalAgentFailure)?
            .get(&run_id)
            .map(|cancellation| {
                cancellation.store(true, Ordering::Release);
                true
            })
            .unwrap_or(false);
        Ok(CancelAcceptance { run_id, accepted })
    }

    fn shutdown(&self) -> Result<(), ProtocolError> {
        {
            let cancellations = self
                .cancellations
                .lock()
                .map_err(|_| ProtocolError::InternalAgentFailure)?;
            for cancellation in cancellations.values() {
                cancellation.store(true, Ordering::Release);
            }
        }
        let workers = std::mem::take(
            &mut *self
                .workers
                .lock()
                .map_err(|_| ProtocolError::InternalAgentFailure)?,
        );
        let mut failed = false;
        for worker in workers {
            failed |= worker.join().is_err();
        }
        self.cancellations
            .lock()
            .map_err(|_| ProtocolError::InternalAgentFailure)?
            .clear();
        if failed {
            Err(ProtocolError::InternalAgentFailure)
        } else {
            Ok(())
        }
    }
}

fn stream_response(
    client: &Client,
    config: &OpenAiProviderConfig,
    prepared: PreparedRequest,
    sink: &dyn PeerEventSink,
    cancellation: &AtomicBool,
) -> Result<Completion, StreamFailure> {
    if cancellation.load(Ordering::Acquire) {
        return Err(StreamFailure::from_error(ProtocolError::Cancelled, None));
    }
    let run_id = prepared.run_id.clone();
    let response = send_request(client, config, prepared)?;
    let mut response_id = response_id_from_headers(response.headers());
    if !is_event_stream(response.headers()) {
        return Err(StreamFailure::from_error(
            ProtocolError::ProviderUnavailable,
            response_id,
        ));
    }
    let mut reader = SseReader::new(BufReader::new(response), MAX_SSE_EVENT_BYTES);
    let mut text = String::new();
    let mut sequence = SequenceMapper::default();
    let mut saw_refusal = false;

    loop {
        if cancellation.load(Ordering::Acquire) {
            return Err(StreamFailure::from_error(
                ProtocolError::Cancelled,
                response_id,
            ));
        }
        let event = reader
            .next_event()
            .map_err(|error| StreamFailure::from_error(error, response_id.clone()))?;
        let Some(event) = event else {
            return Err(StreamFailure::from_error(
                ProtocolError::ProviderUnavailable,
                response_id,
            ));
        };
        response_id = event_response_id(&event).or(response_id);
        let event_type = event.get("type").and_then(Value::as_str).ok_or_else(|| {
            StreamFailure::from_error(ProtocolError::InvalidJson, response_id.clone())
        })?;
        match event_type {
            "response.created" | "response.in_progress" => {}
            "response.output_text.delta" => {
                let delta = event.get("delta").and_then(Value::as_str).ok_or_else(|| {
                    StreamFailure::from_error(ProtocolError::InvalidJson, response_id.clone())
                })?;
                if cancellation.load(Ordering::Acquire) {
                    return Err(StreamFailure::from_error(
                        ProtocolError::Cancelled,
                        response_id,
                    ));
                }
                append_output(&mut text, delta)
                    .map_err(|error| StreamFailure::from_error(error, response_id.clone()))?;
                let provider_sequence = event.get("sequence_number").and_then(Value::as_u64);
                let protocol_sequence = sequence
                    .next(provider_sequence)
                    .map_err(|error| StreamFailure::from_error(error, response_id.clone()))?;
                let frame = stream_delta(&run_id, protocol_sequence, delta)
                    .map_err(|error| StreamFailure::from_error(error, response_id.clone()))?;
                sink.receive(frame)
                    .map_err(|error| StreamFailure::from_error(error, response_id.clone()))?;
            }
            "response.completed" => {
                if cancellation.load(Ordering::Acquire) {
                    return Err(StreamFailure::from_error(
                        ProtocolError::Cancelled,
                        response_id,
                    ));
                }
                if text.is_empty() {
                    return Err(StreamFailure::no_text(response_id, saw_refusal));
                }
                return Ok(Completion {
                    response_id,
                    text,
                    usage: usage(&event),
                });
            }
            "response.failed" | "response.incomplete" | "error" => {
                return Err(StreamFailure {
                    error: ProtocolError::ProviderUnavailable,
                    response_id,
                    retry_after: None,
                    message: "provider response failed",
                });
            }
            event_type if event_type.starts_with("response.refusal.") => saw_refusal = true,
            _ => {}
        }
    }
}

fn send_request(
    client: &Client,
    config: &OpenAiProviderConfig,
    prepared: PreparedRequest,
) -> Result<Response, StreamFailure> {
    let response = client
        .post(config.endpoint().clone())
        .header(
            header::AUTHORIZATION,
            format!("Bearer {}", config.api_key().secret()),
        )
        .header(header::CONTENT_TYPE, "application/json")
        .body(prepared.body)
        .send()
        .map_err(|error| StreamFailure::from_error(request_error(error), None))?;
    if response.status().is_success() {
        Ok(response)
    } else {
        Err(StreamFailure {
            error: status_error(response.status()),
            response_id: response_id_from_headers(response.headers()),
            retry_after: retry_after(response.headers()),
            message: "provider request failed",
        })
    }
}

fn append_output(output: &mut String, delta: &str) -> Result<(), ProtocolError> {
    let Some(length) = output.len().checked_add(delta.len()) else {
        return Err(ProtocolError::OutputLimitExceeded);
    };
    if length > MAX_SSE_EVENT_BYTES {
        return Err(ProtocolError::OutputLimitExceeded);
    }
    output.push_str(delta);
    Ok(())
}

fn stream_delta(
    run_id: &str,
    sequence: u64,
    delta: &str,
) -> Result<local_agent_terminal_agent_protocol::ProtocolFrame, ProtocolError> {
    NdjsonCodec::default().decode(
        &serde_json::to_vec(&json!({
            "jsonrpc": "2.0",
            "method": "agent.stream.delta",
            "params": {
                "runId": run_id,
                "sequence": sequence,
                "channel": "content",
                "delta": delta
            }
        }))
        .map_err(|_| ProtocolError::Encode)?,
    )
}

fn terminal(
    sink: &dyn PeerEventSink,
    run_id: &str,
    terminal_id: u64,
    status: &str,
    content: &str,
    usage: Option<Usage>,
) -> Result<(), ProtocolError> {
    let mut params = Map::new();
    params.insert("runId".to_owned(), Value::String(run_id.to_owned()));
    params.insert("status".to_owned(), Value::String(status.to_owned()));
    params.insert(
        "message".to_owned(),
        json!({
            "messageId": format!("openai-message-{terminal_id}"),
            "type": "answer",
            "content": content,
            "claims": []
        }),
    );
    if let Some(usage) = usage {
        params.insert(
            "usage".to_owned(),
            json!({
                "inputTokens": usage.input_tokens,
                "outputTokens": usage.output_tokens,
            }),
        );
    }
    let frame = NdjsonCodec::default().decode(
        &serde_json::to_vec(&json!({
            "jsonrpc": "2.0",
            "id": format!("agent:openai-{terminal_id}"),
            "method": "agent.run.complete",
            "params": Value::Object(params),
        }))
        .map_err(|_| ProtocolError::Encode)?,
    )?;
    sink.request(frame).map(|_| ())
}

fn usage(event: &Value) -> Option<Usage> {
    let usage = event.pointer("/response/usage")?.as_object()?;
    Some(Usage {
        input_tokens: usage
            .get("input_tokens")
            .and_then(Value::as_u64)
            .unwrap_or(0),
        output_tokens: usage
            .get("output_tokens")
            .and_then(Value::as_u64)
            .unwrap_or(0),
    })
}

fn event_response_id(event: &Value) -> Option<String> {
    event
        .pointer("/response/id")
        .and_then(Value::as_str)
        .map(str::to_owned)
}

fn response_id_from_headers(headers: &HeaderMap) -> Option<String> {
    headers
        .get("x-request-id")
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned)
}

fn is_event_stream(headers: &HeaderMap) -> bool {
    headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.starts_with("text/event-stream"))
}

fn retry_after(headers: &HeaderMap) -> Option<Duration> {
    let value = headers.get(header::RETRY_AFTER)?.to_str().ok()?;
    if let Ok(seconds) = value.parse::<u64>() {
        return Some(Duration::from_secs(seconds));
    }
    let at = httpdate::parse_http_date(value).ok()?;
    Some(
        at.duration_since(SystemTime::now())
            .unwrap_or(Duration::ZERO),
    )
}

fn request_error(error: reqwest::Error) -> ProtocolError {
    if error.is_timeout() {
        ProtocolError::Timeout
    } else {
        ProtocolError::ProviderUnavailable
    }
}

fn status_error(status: StatusCode) -> ProtocolError {
    if status == StatusCode::TOO_MANY_REQUESTS {
        ProtocolError::RateLimited
    } else {
        ProtocolError::ProviderUnavailable
    }
}

fn safe_error_message(error: ProtocolError) -> &'static str {
    match error {
        ProtocolError::Cancelled => "provider request was cancelled",
        ProtocolError::ContextTooLarge => "provider context exceeded the configured limit",
        ProtocolError::FrameTooLarge { .. } => {
            "provider stream event exceeded the configured limit"
        }
        ProtocolError::InvalidJson | ProtocolError::InvalidUtf8 => {
            "provider stream contained invalid event data"
        }
        ProtocolError::OutputLimitExceeded => "provider output exceeded the configured limit",
        ProtocolError::RateLimited => "provider rate limit was reached",
        ProtocolError::Timeout => "provider request timed out",
        _ => "provider request failed",
    }
}

fn record_diagnostic(
    diagnostics: &Mutex<BTreeMap<String, OpenAiDiagnostic>>,
    run_id: &str,
    response_id: Option<String>,
    retry_after: Option<Duration>,
    error: Option<ProtocolError>,
) {
    if let Ok(mut diagnostics) = diagnostics.lock() {
        diagnostics.insert(
            run_id.to_owned(),
            OpenAiDiagnostic {
                run_id: run_id.to_owned(),
                response_id,
                retry_after,
                error,
            },
        );
    }
}

#[derive(Default)]
struct SequenceMapper {
    first_provider_sequence: Option<u64>,
    next_local_sequence: u64,
}

impl SequenceMapper {
    fn next(&mut self, provider_sequence: Option<u64>) -> Result<u64, ProtocolError> {
        let sequence = match provider_sequence {
            Some(provider_sequence) => {
                let first = *self
                    .first_provider_sequence
                    .get_or_insert(provider_sequence);
                provider_sequence
                    .checked_sub(first)
                    .and_then(|offset| offset.checked_add(1))
                    .ok_or(ProtocolError::InvalidRequest)?
            }
            None => self.next_local_sequence.max(1),
        };
        self.next_local_sequence = sequence
            .checked_add(1)
            .ok_or(ProtocolError::OutputLimitExceeded)?;
        Ok(sequence)
    }
}
