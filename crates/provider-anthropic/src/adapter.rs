use std::{
    collections::BTreeMap,
    fmt,
    io::BufReader,
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc, Condvar, Mutex,
    },
    thread::{self, JoinHandle},
    time::Duration,
};

#[cfg(test)]
use std::sync::{mpsc, OnceLock};

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
use sha2::{Digest, Sha256};

use crate::{
    config::AnthropicProviderConfig,
    request::{prepare, PreparedRequest},
    sse::{SseReader, MAX_SSE_EVENT_BYTES},
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnthropicDiagnostic {
    pub run_id: String,
    pub response_id: Option<String>,
    pub retry_after: Option<Duration>,
    pub error: Option<ProtocolError>,
}

pub struct AnthropicMessagesAdapter {
    config: AnthropicProviderConfig,
    descriptor: PeerDescriptor,
    client: Client,
    lifecycle: Arc<AdapterLifecycle>,
    diagnostics: Arc<Mutex<BTreeMap<String, AnthropicDiagnostic>>>,
    terminal_ids: AtomicU64,
}

#[derive(Default)]
struct AdapterLifecycle {
    state: Mutex<LifecycleState>,
    shutdown_complete: Condvar,
}

#[derive(Default)]
struct LifecycleState {
    shutdown: ShutdownState,
    active_runs: BTreeMap<String, RunPhase>,
    workers: Vec<JoinHandle<()>>,
}

#[derive(Default)]
enum ShutdownState {
    #[default]
    Open,
    Closing,
    Closed(Result<(), ProtocolError>),
}

impl ShutdownState {
    fn is_open(&self) -> bool {
        matches!(self, Self::Open)
    }
}

enum RunPhase {
    Running(Arc<AtomicBool>),
    Completing,
}

#[derive(Default)]
struct WorkerLaunchGate {
    opened: Mutex<bool>,
    ready: Condvar,
}

impl WorkerLaunchGate {
    fn wait(&self) {
        let mut opened = self
            .opened
            .lock()
            .expect("worker launch gate mutex must not be poisoned");
        while !*opened {
            opened = self
                .ready
                .wait(opened)
                .expect("worker launch gate mutex must not be poisoned");
        }
    }

    fn open(&self) {
        *self
            .opened
            .lock()
            .expect("worker launch gate mutex must not be poisoned") = true;
        self.ready.notify_all();
    }
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

#[derive(Clone, Copy, PartialEq, Eq)]
enum StreamPhase {
    AwaitingMessageStart,
    AwaitingContentBlock,
    StreamingContent,
    AwaitingMessageDelta,
    AwaitingMessageStop,
}

struct StreamFailure {
    error: ProtocolError,
    response_id: Option<String>,
    retry_after: Option<Duration>,
    message: &'static str,
}

#[cfg(test)]
struct StartRegistrationGate {
    entered: mpsc::Sender<()>,
    release: mpsc::Receiver<()>,
}

#[cfg(test)]
static START_REGISTRATION_GATE: OnceLock<Mutex<Option<StartRegistrationGate>>> = OnceLock::new();

#[cfg(test)]
fn pause_start_registration_for_test() {
    let gate = START_REGISTRATION_GATE
        .get_or_init(|| Mutex::new(None))
        .lock()
        .ok()
        .and_then(|mut gate| gate.take());
    if let Some(gate) = gate {
        let _ = gate.entered.send(());
        let _ = gate.release.recv();
    }
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

impl AnthropicMessagesAdapter {
    pub fn new(
        config: AnthropicProviderConfig,
        descriptor: PeerDescriptor,
    ) -> Result<Self, ProtocolError> {
        let client = Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(config.connect_timeout())
            .timeout(config.read_timeout())
            .build()
            .map_err(|_| ProtocolError::ProviderUnavailable)?;
        Ok(Self {
            config,
            descriptor,
            client,
            lifecycle: Arc::new(AdapterLifecycle::default()),
            diagnostics: Arc::new(Mutex::new(BTreeMap::new())),
            terminal_ids: AtomicU64::new(1),
        })
    }

    pub fn diagnostics(&self) -> Vec<AnthropicDiagnostic> {
        self.diagnostics
            .lock()
            .map(|diagnostics| diagnostics.values().cloned().collect())
            .unwrap_or_default()
    }

    fn next_terminal_id(&self) -> u64 {
        self.terminal_ids.fetch_add(1, Ordering::Relaxed)
    }

    fn reap_finished_workers(&self) -> Result<(), ProtocolError> {
        let finished = {
            let mut lifecycle = self
                .lifecycle
                .state
                .lock()
                .map_err(|_| ProtocolError::InternalAgentFailure)?;
            if !lifecycle.shutdown.is_open() {
                return Ok(());
            }
            let mut finished = Vec::new();
            let mut unfinished = Vec::new();
            for worker in std::mem::take(&mut lifecycle.workers) {
                if worker.is_finished() {
                    finished.push(worker);
                } else {
                    unfinished.push(worker);
                }
            }
            lifecycle.workers = unfinished;
            finished
        };
        let mut failed = false;
        for worker in finished {
            failed |= worker.join().is_err();
        }
        if failed {
            Err(ProtocolError::InternalAgentFailure)
        } else {
            Ok(())
        }
    }
}

fn mark_run_completing(lifecycle: &AdapterLifecycle, run_id: &str) {
    if let Ok(mut lifecycle) = lifecycle.state.lock() {
        if matches!(
            lifecycle.active_runs.get(run_id),
            Some(RunPhase::Running(_))
        ) {
            lifecycle
                .active_runs
                .insert(run_id.to_owned(), RunPhase::Completing);
        }
    }
}

fn remove_completed_run(lifecycle: &AdapterLifecycle, run_id: &str) {
    if let Ok(mut lifecycle) = lifecycle.state.lock() {
        lifecycle.active_runs.remove(run_id);
    }
}

impl fmt::Debug for AnthropicMessagesAdapter {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AnthropicMessagesAdapter")
            .field("config", &self.config)
            .field("descriptor", &self.descriptor)
            .field(
                "active_runs",
                &self
                    .lifecycle
                    .state
                    .lock()
                    .map_or(0, |lifecycle| lifecycle.active_runs.len()),
            )
            .field("diagnostics", &self.diagnostics())
            .finish()
    }
}

impl ProtocolPeer for AnthropicMessagesAdapter {
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
        let config = self.config.clone();
        let client = self.client.clone();
        let worker_lifecycle_state = Arc::clone(&self.lifecycle);
        let diagnostics = Arc::clone(&self.diagnostics);
        let terminal_id = self.next_terminal_id();
        let run_id = prepared.run_id.clone();
        let worker_run_id = run_id.clone();
        let worker_cancellation = Arc::clone(&cancellation);
        let launch = Arc::new(WorkerLaunchGate::default());
        let worker_launch = Arc::clone(&launch);
        {
            let mut lifecycle = self
                .lifecycle
                .state
                .lock()
                .map_err(|_| ProtocolError::InternalAgentFailure)?;
            if !lifecycle.shutdown.is_open() || lifecycle.active_runs.contains_key(&run_id) {
                return Err(ProtocolError::InvalidRequest);
            }
            let worker_lifecycle = Arc::clone(&worker_lifecycle_state);
            let worker = thread::Builder::new()
                .name(format!("anthropic-message-{terminal_id}"))
                .spawn(move || {
                    worker_launch.wait();
                    let outcome =
                        stream_response(&client, &config, prepared, &*sink, &worker_cancellation);
                    mark_run_completing(&worker_lifecycle, &worker_run_id);
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
                    remove_completed_run(&worker_lifecycle, &worker_run_id);
                })
                .map_err(|_| ProtocolError::ProviderUnavailable)?;
            #[cfg(test)]
            pause_start_registration_for_test();
            lifecycle
                .active_runs
                .insert(run_id.clone(), RunPhase::Running(cancellation));
            lifecycle.workers.push(worker);
        }
        launch.open();
        Ok(RunAcceptance {
            run_id,
            accepted: true,
        })
    }

    fn cancel(&self, request: RunCancel) -> Result<CancelAcceptance, ProtocolError> {
        let run_id = request.run_id();
        let accepted = self
            .lifecycle
            .state
            .lock()
            .map_err(|_| ProtocolError::InternalAgentFailure)?
            .active_runs
            .get(&run_id)
            .and_then(|phase| match phase {
                RunPhase::Running(cancellation) => Some(cancellation),
                RunPhase::Completing => None,
            })
            .map(|cancellation| {
                cancellation.store(true, Ordering::Release);
                true
            })
            .unwrap_or(false);
        Ok(CancelAcceptance { run_id, accepted })
    }

    fn shutdown(&self) -> Result<(), ProtocolError> {
        let workers = {
            let mut lifecycle = self
                .lifecycle
                .state
                .lock()
                .map_err(|_| ProtocolError::InternalAgentFailure)?;
            loop {
                match &lifecycle.shutdown {
                    ShutdownState::Open => {
                        lifecycle.shutdown = ShutdownState::Closing;
                        for phase in lifecycle.active_runs.values() {
                            if let RunPhase::Running(cancellation) = phase {
                                cancellation.store(true, Ordering::Release);
                            }
                        }
                        break std::mem::take(&mut lifecycle.workers);
                    }
                    ShutdownState::Closing => {
                        lifecycle = self
                            .lifecycle
                            .shutdown_complete
                            .wait(lifecycle)
                            .map_err(|_| ProtocolError::InternalAgentFailure)?;
                    }
                    ShutdownState::Closed(result) => return *result,
                }
            }
        };
        let mut failed = false;
        for worker in workers {
            failed |= worker.join().is_err();
        }
        let result = if failed {
            Err(ProtocolError::InternalAgentFailure)
        } else {
            Ok(())
        };
        let mut lifecycle = self
            .lifecycle
            .state
            .lock()
            .map_err(|_| ProtocolError::InternalAgentFailure)?;
        lifecycle.active_runs.clear();
        lifecycle.shutdown = ShutdownState::Closed(result);
        self.lifecycle.shutdown_complete.notify_all();
        result
    }
}

fn stream_response(
    client: &Client,
    config: &AnthropicProviderConfig,
    prepared: PreparedRequest,
    sink: &dyn PeerEventSink,
    cancellation: &AtomicBool,
) -> Result<Completion, StreamFailure> {
    if cancellation.load(Ordering::Acquire) {
        return Err(StreamFailure::from_error(ProtocolError::Cancelled, None));
    }
    let run_id = prepared.run_id.clone();
    let response = send_request(client, config, prepared)?;
    let mut response_id = response_id_from_headers(response.headers(), config.api_key().secret());
    if !is_event_stream(response.headers()) {
        return Err(StreamFailure::from_error(
            ProtocolError::ProviderUnavailable,
            response_id,
        ));
    }
    let mut reader = SseReader::new(BufReader::new(response), MAX_SSE_EVENT_BYTES);
    let mut text = String::new();
    let mut sequence = SequenceMapper::default();
    let mut phase = StreamPhase::AwaitingMessageStart;
    let mut input_tokens = None;
    let mut output_tokens = None;

    loop {
        if cancellation.load(Ordering::Acquire) {
            return Err(StreamFailure::from_error(
                ProtocolError::Cancelled,
                response_id,
            ));
        }
        let event = reader
            .next_event(cancellation)
            .map_err(|error| StreamFailure::from_error(error, response_id.clone()))?;
        let Some(event) = event else {
            return Err(StreamFailure::from_error(
                ProtocolError::ProviderUnavailable,
                response_id,
            ));
        };
        let event_type = event.get("type").and_then(Value::as_str).ok_or_else(|| {
            StreamFailure::from_error(ProtocolError::InvalidJson, response_id.clone())
        })?;
        match event_type {
            "ping" => {}
            "message_start" if phase == StreamPhase::AwaitingMessageStart => {
                response_id = event_response_id(&event, config.api_key().secret()).or(response_id);
                let usage = event
                    .pointer("/message/usage")
                    .and_then(Value::as_object)
                    .ok_or_else(|| {
                        StreamFailure::from_error(ProtocolError::InvalidJson, response_id.clone())
                    })?;
                input_tokens = Some(required_u64(usage, "input_tokens", &response_id)?);
                output_tokens = Some(required_u64(usage, "output_tokens", &response_id)?);
                phase = StreamPhase::AwaitingContentBlock;
            }
            "content_block_start" if phase == StreamPhase::AwaitingContentBlock => {
                require_index_zero(&event, &response_id)?;
                let content_block = event
                    .get("content_block")
                    .and_then(Value::as_object)
                    .ok_or_else(|| {
                        StreamFailure::from_error(ProtocolError::InvalidJson, response_id.clone())
                    })?;
                if content_block.get("type").and_then(Value::as_str) != Some("text")
                    || content_block.get("text").and_then(Value::as_str).is_none()
                {
                    return Err(StreamFailure::from_error(
                        ProtocolError::InvalidRequest,
                        response_id,
                    ));
                }
                phase = StreamPhase::StreamingContent;
            }
            "content_block_delta" if phase == StreamPhase::StreamingContent => {
                require_index_zero(&event, &response_id)?;
                let delta = event
                    .get("delta")
                    .and_then(Value::as_object)
                    .ok_or_else(|| {
                        StreamFailure::from_error(ProtocolError::InvalidJson, response_id.clone())
                    })?;
                if delta.get("type").and_then(Value::as_str) != Some("text_delta") {
                    return Err(StreamFailure::from_error(
                        ProtocolError::InvalidRequest,
                        response_id,
                    ));
                }
                let delta = delta.get("text").and_then(Value::as_str).ok_or_else(|| {
                    StreamFailure::from_error(ProtocolError::InvalidJson, response_id.clone())
                })?;
                emit_delta(
                    &run_id,
                    delta,
                    &mut text,
                    &mut sequence,
                    sink,
                    cancellation,
                    &response_id,
                )?;
            }
            "content_block_stop" if phase == StreamPhase::StreamingContent => {
                require_index_zero(&event, &response_id)?;
                phase = StreamPhase::AwaitingMessageDelta;
            }
            "message_delta" if phase == StreamPhase::AwaitingMessageDelta => {
                let current_output = event
                    .pointer("/usage/output_tokens")
                    .and_then(Value::as_u64)
                    .ok_or_else(|| {
                        StreamFailure::from_error(ProtocolError::InvalidJson, response_id.clone())
                    })?;
                if output_tokens.is_some_and(|previous| current_output < previous) {
                    return Err(StreamFailure::from_error(
                        ProtocolError::InvalidRequest,
                        response_id,
                    ));
                }
                output_tokens = Some(current_output);
                phase = StreamPhase::AwaitingMessageStop;
            }
            "message_stop" if phase == StreamPhase::AwaitingMessageStop => {
                if text.is_empty() {
                    return Err(StreamFailure::no_text(response_id, false));
                }
                ensure_stream_ended(&mut reader, cancellation, &response_id)?;
                return Ok(Completion {
                    response_id,
                    text,
                    usage: Some(Usage {
                        input_tokens: input_tokens.unwrap_or(0),
                        output_tokens: output_tokens.unwrap_or(0),
                    }),
                });
            }
            "error" => {
                return Err(StreamFailure {
                    error: provider_error(&event),
                    response_id,
                    retry_after: None,
                    message: "provider response failed",
                });
            }
            _ => {
                return Err(StreamFailure::from_error(
                    ProtocolError::InvalidRequest,
                    response_id,
                ));
            }
        }
    }
}

fn ensure_stream_ended<R: std::io::BufRead>(
    reader: &mut SseReader<R>,
    cancellation: &AtomicBool,
    response_id: &Option<String>,
) -> Result<(), StreamFailure> {
    loop {
        let event = reader
            .next_event(cancellation)
            .map_err(|error| StreamFailure::from_error(error, response_id.clone()))?;
        let Some(event) = event else {
            return Ok(());
        };
        if event.get("type").and_then(Value::as_str) != Some("ping") {
            return Err(StreamFailure::from_error(
                ProtocolError::InvalidRequest,
                response_id.clone(),
            ));
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn emit_delta(
    run_id: &str,
    delta: &str,
    text: &mut String,
    sequence: &mut SequenceMapper,
    sink: &dyn PeerEventSink,
    cancellation: &AtomicBool,
    response_id: &Option<String>,
) -> Result<(), StreamFailure> {
    if cancellation.load(Ordering::Acquire) {
        return Err(StreamFailure::from_error(
            ProtocolError::Cancelled,
            response_id.clone(),
        ));
    }
    append_output(text, delta)
        .map_err(|error| StreamFailure::from_error(error, response_id.clone()))?;
    let protocol_sequence = sequence
        .next(None)
        .map_err(|error| StreamFailure::from_error(error, response_id.clone()))?;
    let frame = stream_delta(run_id, protocol_sequence, delta)
        .map_err(|error| StreamFailure::from_error(error, response_id.clone()))?;
    sink.receive(frame)
        .map_err(|error| StreamFailure::from_error(error, response_id.clone()))?;
    Ok(())
}

fn require_index_zero(event: &Value, response_id: &Option<String>) -> Result<(), StreamFailure> {
    if event.get("index").and_then(Value::as_u64) == Some(0) {
        Ok(())
    } else {
        Err(StreamFailure::from_error(
            ProtocolError::InvalidRequest,
            response_id.clone(),
        ))
    }
}

fn required_u64(
    object: &Map<String, Value>,
    name: &str,
    response_id: &Option<String>,
) -> Result<u64, StreamFailure> {
    object
        .get(name)
        .and_then(Value::as_u64)
        .ok_or_else(|| StreamFailure::from_error(ProtocolError::InvalidJson, response_id.clone()))
}

fn provider_error(event: &Value) -> ProtocolError {
    match event.pointer("/error/type").and_then(Value::as_str) {
        Some("rate_limit_error") => ProtocolError::RateLimited,
        Some("overloaded_error") => ProtocolError::ProviderUnavailable,
        _ => ProtocolError::ProviderUnavailable,
    }
}

fn send_request(
    client: &Client,
    config: &AnthropicProviderConfig,
    prepared: PreparedRequest,
) -> Result<Response, StreamFailure> {
    let response = client
        .post(config.endpoint().clone())
        .header("x-api-key", config.api_key().secret())
        .header("anthropic-version", "2023-06-01")
        .header(header::CONTENT_TYPE, "application/json")
        .body(prepared.body)
        .send()
        .map_err(|error| StreamFailure::from_error(request_error(error), None))?;
    if response.status().is_success() {
        Ok(response)
    } else {
        Err(StreamFailure {
            error: status_error(response.status()),
            response_id: response_id_from_headers(response.headers(), config.api_key().secret()),
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
            "messageId": terminal_message_id(run_id, terminal_id),
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
            "id": format!("agent:anthropic-{terminal_id}"),
            "method": "agent.run.complete",
            "params": Value::Object(params),
        }))
        .map_err(|_| ProtocolError::Encode)?,
    )?;
    sink.request(frame).map(|_| ())
}

fn terminal_message_id(run_id: &str, _terminal_id: u64) -> String {
    let mut digest = Sha256::new();
    digest.update(b"anthropic-terminal-message.v1\0");
    digest.update(run_id.as_bytes());
    format!("anthropic-message-{:x}", digest.finalize())
}

fn event_response_id(event: &Value, api_key: &str) -> Option<String> {
    event
        .pointer("/message/id")
        .and_then(Value::as_str)
        .and_then(|value| sanitize_response_id(value, api_key))
}

fn response_id_from_headers(headers: &HeaderMap, api_key: &str) -> Option<String> {
    headers
        .get("x-request-id")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| sanitize_response_id(value, api_key))
}

fn sanitize_response_id(value: &str, api_key: &str) -> Option<String> {
    if value.contains(api_key) {
        None
    } else {
        Some(value.to_owned())
    }
}

fn is_event_stream(headers: &HeaderMap) -> bool {
    headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| {
            value.split(';').next().is_some_and(|media_type| {
                media_type.trim().eq_ignore_ascii_case("text/event-stream")
            })
        })
}

fn retry_after(headers: &HeaderMap) -> Option<Duration> {
    let value = headers.get(header::RETRY_AFTER)?.to_str().ok()?;
    value.parse::<u64>().ok().map(Duration::from_secs)
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
    diagnostics: &Mutex<BTreeMap<String, AnthropicDiagnostic>>,
    run_id: &str,
    response_id: Option<String>,
    retry_after: Option<Duration>,
    error: Option<ProtocolError>,
) {
    if let Ok(mut diagnostics) = diagnostics.lock() {
        diagnostics.insert(
            run_id.to_owned(),
            AnthropicDiagnostic {
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

#[cfg(test)]
mod lifecycle_tests {
    use std::{
        collections::BTreeSet,
        sync::{mpsc, Arc},
        thread,
        time::Duration,
    };

    use local_agent_terminal_agent_protocol::{
        ConnectionBinding, InboundDisposition, PeerEventSink, ProtocolCapabilities, ProtocolFrame,
        ProtocolTrustTier, RunExecutionBinding,
    };
    use serde_json::json;
    use sha2::{Digest, Sha256};
    use url::Url;

    use super::*;

    #[test]
    fn recognizes_only_the_event_stream_media_type() {
        for content_type in [
            "text/event-stream",
            "TEXT/EVENT-STREAM; charset=utf-8",
            " text/event-stream ; charset=utf-8 ",
        ] {
            let mut headers = HeaderMap::new();
            headers.insert(
                header::CONTENT_TYPE,
                content_type.parse().expect("valid header value"),
            );
            assert!(
                is_event_stream(&headers),
                "expected {content_type} to match"
            );
        }

        for content_type in [
            "text/event-streaming",
            "application/text/event-stream",
            "text/event-streamish; charset=utf-8",
        ] {
            let mut headers = HeaderMap::new();
            headers.insert(
                header::CONTENT_TYPE,
                content_type.parse().expect("valid header value"),
            );
            assert!(
                !is_event_stream(&headers),
                "expected {content_type} to reject"
            );
        }
    }

    #[test]
    fn shutdown_waits_until_start_registers_its_worker() {
        let adapter = Arc::new(test_adapter());
        let (entered, wait_for_entry) = mpsc::channel();
        let (release, wait_for_release) = mpsc::channel();
        install_start_registration_gate(entered, wait_for_release);

        let start_adapter = Arc::clone(&adapter);
        let start = thread::spawn(move || {
            start_adapter.start(test_run_start("racing"), Box::new(NoopSink))
        });
        wait_for_entry.recv_timeout(Duration::from_secs(1)).unwrap();

        let shutdown_adapter = Arc::clone(&adapter);
        let (shutdown_done, wait_for_shutdown) = mpsc::channel();
        let shutdown = thread::spawn(move || {
            shutdown_done.send(shutdown_adapter.shutdown()).unwrap();
        });
        let early_shutdown = wait_for_shutdown
            .recv_timeout(Duration::from_millis(100))
            .ok();

        release.send(()).unwrap();
        let start_result = start.join().unwrap();
        let shutdown_result = early_shutdown.unwrap_or_else(|| {
            wait_for_shutdown
                .recv_timeout(Duration::from_secs(1))
                .unwrap()
        });
        shutdown.join().unwrap();
        let after_shutdown = adapter.start(test_run_start("after"), Box::new(NoopSink));
        let cleanup = adapter.shutdown();

        assert!(
            early_shutdown.is_none(),
            "shutdown drained before start registered its worker"
        );
        assert!(start_result.is_ok());
        assert_eq!(shutdown_result, Ok(()));
        assert_eq!(after_shutdown, Err(ProtocolError::InvalidRequest));
        assert_eq!(cleanup, Ok(()));
    }

    fn install_start_registration_gate(entered: mpsc::Sender<()>, release: mpsc::Receiver<()>) {
        let mut gate = START_REGISTRATION_GATE
            .get_or_init(|| Mutex::new(None))
            .lock()
            .unwrap();
        assert!(gate.is_none());
        *gate = Some(StartRegistrationGate { entered, release });
    }

    fn test_adapter() -> AnthropicMessagesAdapter {
        AnthropicMessagesAdapter::new(
            AnthropicProviderConfig::for_loopback_test(
                Url::parse("http://127.0.0.1:9/v1/messages").unwrap(),
                crate::AnthropicApiKey::new("sk-unit-test").unwrap(),
                Duration::from_secs(1),
                Duration::from_millis(20),
            )
            .unwrap(),
            PeerDescriptor {
                binding: ConnectionBinding {
                    connection_id: "connection-unit".to_owned(),
                    agent_id: "agent-unit".to_owned(),
                    manifest_digest:
                        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                            .to_owned(),
                    executable_digest:
                        "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                            .to_owned(),
                    trust_tier: ProtocolTrustTier::CoreAdapter,
                },
                protocol_version: "2.0".to_owned(),
                capabilities: ProtocolCapabilities {
                    roles: BTreeSet::from(["critic".to_owned()]),
                    skills: BTreeSet::from(["testing".to_owned()]),
                    streaming: true,
                    context_query: false,
                    tool_requests: false,
                    specialist_requests: false,
                    max_concurrent_runs: 1,
                    max_context_tokens: 1_024,
                },
            },
        )
        .unwrap()
    }

    #[test]
    fn terminal_message_id_uses_only_the_durable_run_identity() {
        let first_adapter = test_adapter();
        let first = terminal_message_id("durable-run", first_adapter.next_terminal_id());

        let warmed_adapter = test_adapter();
        let _ = warmed_adapter.next_terminal_id();
        let _ = warmed_adapter.next_terminal_id();
        let after_warmup = terminal_message_id("durable-run", warmed_adapter.next_terminal_id());
        let different_run =
            terminal_message_id("different-durable-run", warmed_adapter.next_terminal_id());

        assert_eq!(first, after_warmup);
        assert_ne!(first, different_run);
        assert!(first.len() <= 256);
        assert!(different_run.len() <= 256);
    }

    fn test_run_start(run_id: &str) -> RunStart {
        let context = b"unit prompt";
        let generation_parameters = br#"{}"#;
        let context_digest = format!("sha256:{:x}", Sha256::digest(context));
        let generation_parameters_digest =
            format!("sha256:{:x}", Sha256::digest(generation_parameters));
        let frame = NdjsonCodec::default()
            .decode(
                &serde_json::to_vec(&json!({
                    "jsonrpc": "2.0",
                    "id": format!("core:start-{run_id}"),
                    "method": "agent.run.start",
                    "params": {
                        "runId": run_id,
                        "taskId": "task-1",
                        "contextPackageRef": "context-1",
                        "idempotencyKey": format!("key-{run_id}"),
                        "role": "critic",
                    }
                }))
                .unwrap(),
            )
            .unwrap();
        RunStart::new(
            frame,
            RunExecutionBinding {
                provider_id: "anthropic".to_owned(),
                model_id: "claude-test-model".to_owned(),
                max_output_tokens: 17,
                generation_parameters: generation_parameters.to_vec(),
                generation_parameters_digest,
                effective_context: context.to_vec(),
                effective_context_artifact_id: "artifact-context-1".to_owned(),
                effective_context_digest: context_digest,
                supersedes_run_id: None,
            },
        )
        .unwrap()
    }

    struct NoopSink;

    impl PeerEventSink for NoopSink {
        fn receive(&self, frame: ProtocolFrame) -> Result<InboundDisposition, ProtocolError> {
            Ok(InboundDisposition::Notification(frame))
        }

        fn request(&self, _frame: ProtocolFrame) -> Result<ProtocolFrame, ProtocolError> {
            Err(ProtocolError::InternalAgentFailure)
        }

        fn receive_raw(&self, _bytes: &[u8]) -> Result<InboundDisposition, ProtocolError> {
            Err(ProtocolError::InvalidRequest)
        }

        fn connection_lost(&self) -> Result<(), ProtocolError> {
            Ok(())
        }
    }
}
