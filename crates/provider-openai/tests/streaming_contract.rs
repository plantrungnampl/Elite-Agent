use std::{
    collections::BTreeSet,
    io::{BufRead, BufReader, Read, Write},
    net::{TcpListener, TcpStream},
    sync::{
        atomic::{AtomicUsize, Ordering},
        mpsc, Arc, Barrier, Condvar, Mutex,
    },
    thread,
    time::Duration,
};

use local_agent_terminal_agent_protocol::{
    CancelAcceptance, ConnectionBinding, InboundDisposition, NdjsonCodec, PeerDescriptor,
    PeerEventSink, ProtocolCapabilities, ProtocolError, ProtocolFrame, ProtocolPeer,
    ProtocolTrustTier, RunCancel, RunExecutionBinding, RunStart,
};
use local_agent_terminal_provider_openai::{
    OpenAiApiKey, OpenAiProviderConfig, OpenAiResponsesAdapter, MAX_SSE_EVENT_BYTES,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use url::Url;

const API_KEY_CANARY: &str = "sk-streaming-canary";

#[test]
fn parses_fragmented_crlf_multiline_sse_and_maps_deltas_usage_and_response_id() {
    let server = LoopbackServer::responding(sse_fragments(&[
        ": ignored comment\r\n\r\n",
        "event: response.created\r\ndata: {\"type\":\"response.created\",\"response\":{\"id\":\"resp-42\"}}\r\n\r\n",
        "event: response.output_text.delta\r\ndata: {\"type\":\"response.output_text.delta\",\"sequence_number\":7,\r\n",
        "data: \"delta\":\"first\"}\r\n\r\n",
        "event: response.output_text.delta\r\ndata: {\"type\":\"response.output_text.delta\",\"sequence_number\":8,\"delta\":\" second\"}\r\n\r\n",
        "event: response.completed\r\ndata: {\"type\":\"response.completed\",\"response\":{\"id\":\"resp-42\",\"usage\":{\"input_tokens\":3,\"output_tokens\":5}}}\r\n\r\n",
    ]));
    let adapter = adapter(server.endpoint(), Duration::from_secs(1));
    let sink = RecordingSink::default();

    adapter
        .start(run_start("run-1"), Box::new(sink.clone()))
        .unwrap();
    let terminal = sink.wait_for_terminal();

    assert_eq!(sink.deltas(), vec!["first", " second"]);
    assert_eq!(sink.sequences(), vec![1, 2]);
    assert_eq!(
        terminal.pointer("/params/status").and_then(Value::as_str),
        Some("succeeded")
    );
    assert_eq!(
        terminal
            .pointer("/params/message/content")
            .and_then(Value::as_str),
        Some("first second")
    );
    assert_eq!(
        terminal
            .pointer("/params/usage/inputTokens")
            .and_then(Value::as_u64),
        Some(3)
    );
    assert_eq!(
        terminal
            .pointer("/params/usage/outputTokens")
            .and_then(Value::as_u64),
        Some(5)
    );
    assert_eq!(sink.terminal_count(), 1);
    assert_eq!(
        adapter.diagnostics()[0].response_id.as_deref(),
        Some("resp-42")
    );
    assert_eq!(adapter.diagnostics()[0].error, None);

    adapter.shutdown().unwrap();
    server.join();
}

#[test]
fn maps_failed_incomplete_and_error_events_to_one_failed_terminal() {
    for (run_id, event, response_id) in [
        (
            "failed",
            "event: response.failed\ndata: {\"type\":\"response.failed\",\"response\":{\"id\":\"resp-failed\"}}\n\n",
            Some("resp-failed"),
        ),
        (
            "incomplete",
            "event: response.incomplete\ndata: {\"type\":\"response.incomplete\",\"response\":{\"id\":\"resp-incomplete\"}}\n\n",
            Some("resp-incomplete"),
        ),
        (
            "error",
            "event: error\ndata: {\"type\":\"error\",\"error\":{\"message\":\"provider failure\"}}\n\n",
            None,
        ),
    ] {
        let server = LoopbackServer::responding(sse_fragments(&[event]));
        let adapter = adapter(server.endpoint(), Duration::from_secs(1));
        let sink = RecordingSink::default();

        adapter.start(run_start(run_id), Box::new(sink.clone())).unwrap();
        let terminal = sink.wait_for_terminal();

        assert_eq!(terminal.pointer("/params/status").and_then(Value::as_str), Some("failed"));
        assert_eq!(sink.terminal_count(), 1);
        assert_eq!(adapter.diagnostics()[0].error, Some(ProtocolError::ProviderUnavailable));
        assert_eq!(adapter.diagnostics()[0].response_id.as_deref(), response_id);
        adapter.shutdown().unwrap();
        server.join();
    }
}

#[test]
fn rejects_invalid_oversized_and_premature_sse_streams() {
    let oversized = {
        let mut line = b"data: ".to_vec();
        line.extend(std::iter::repeat_n(b'x', MAX_SSE_EVENT_BYTES + 1));
        line.extend(b"\n\n");
        line
    };
    let cases = [
        (
            sse_fragments(&["event: response.output_text.delta\ndata: {not-json}\n\n"]),
            ProtocolError::InvalidJson,
        ),
        (vec![oversized], ProtocolError::FrameTooLarge { max_frame_bytes: MAX_SSE_EVENT_BYTES }),
        (
            sse_fragments(&["event: response.created\ndata: {\"type\":\"response.created\",\"response\":{\"id\":\"resp-eof\"}}\n\n"]),
            ProtocolError::ProviderUnavailable,
        ),
    ];
    for (index, (fragments, expected)) in cases.into_iter().enumerate() {
        let server = LoopbackServer::responding(fragments);
        let adapter = adapter(server.endpoint(), Duration::from_secs(1));
        let sink = RecordingSink::default();

        adapter
            .start(
                run_start(&format!("invalid-{index}")),
                Box::new(sink.clone()),
            )
            .unwrap();
        let terminal = sink.wait_for_terminal();

        assert_eq!(
            terminal.pointer("/params/status").and_then(Value::as_str),
            Some("failed")
        );
        assert_eq!(adapter.diagnostics()[0].error, Some(expected));
        adapter.shutdown().unwrap();
        server.join();
    }
}

#[test]
fn classifies_http_failures_and_preserves_valid_retry_after_without_retrying() {
    for (run_id, status, headers, expected_error, expected_retry_after) in [
        (
            "unauthorized",
            401,
            Vec::<(String, String)>::new(),
            ProtocolError::ProviderUnavailable,
            None,
        ),
        (
            "rate-limited",
            429,
            vec![("Retry-After".to_owned(), "3".to_owned())],
            ProtocolError::RateLimited,
            Some(Duration::from_secs(3)),
        ),
        (
            "provider-failed",
            503,
            Vec::<(String, String)>::new(),
            ProtocolError::ProviderUnavailable,
            None,
        ),
    ] {
        let server = LoopbackServer::status(status, headers);
        let request_count = Arc::clone(&server.request_count);
        let adapter = adapter(server.endpoint(), Duration::from_secs(1));
        let sink = RecordingSink::default();

        adapter
            .start(run_start(run_id), Box::new(sink.clone()))
            .unwrap();
        let terminal = sink.wait_for_terminal();

        assert_eq!(
            terminal.pointer("/params/status").and_then(Value::as_str),
            Some("failed")
        );
        assert_eq!(adapter.diagnostics()[0].error, Some(expected_error));
        assert_eq!(adapter.diagnostics()[0].retry_after, expected_retry_after);
        assert_eq!(request_count.load(Ordering::Relaxed), 1);
        adapter.shutdown().unwrap();
        server.join();
    }
}

#[test]
fn maps_response_timeout_to_a_typed_failed_terminal() {
    let mut server = LoopbackServer::gated(Vec::new(), sse_fragments(&[": delayed\n"]));
    let adapter = adapter(server.endpoint(), Duration::from_millis(20));
    let sink = RecordingSink::default();

    adapter
        .start(run_start("timeout"), Box::new(sink.clone()))
        .unwrap();
    server.wait_for_request();
    let terminal = sink.wait_for_terminal();

    assert_eq!(
        terminal.pointer("/params/status").and_then(Value::as_str),
        Some("failed")
    );
    assert_eq!(adapter.diagnostics()[0].error, Some(ProtocolError::Timeout));
    server.release();
    adapter.shutdown().unwrap();
    server.join();
}

#[test]
fn cancellation_emits_cancelled_terminal_and_removes_the_active_flag() {
    let mut server = LoopbackServer::gated(
        sse_fragments(&[
            "event: response.created\ndata: {\"type\":\"response.created\",\"response\":{\"id\":\"resp-cancel\"}}\n\n",
        ]),
        sse_fragments(&[
            "event: response.output_text.delta\ndata: {\"type\":\"response.output_text.delta\",\"delta\":\"late\"}\n\n",
            "event: response.completed\ndata: {\"type\":\"response.completed\",\"response\":{\"id\":\"resp-cancel\"}}\n\n",
        ]),
    );
    let adapter = adapter(server.endpoint(), Duration::from_secs(1));
    let sink = RecordingSink::default();

    adapter
        .start(run_start("cancel"), Box::new(sink.clone()))
        .unwrap();
    server.wait_for_request();
    assert_eq!(
        adapter.cancel(run_cancel("cancel")).unwrap(),
        CancelAcceptance {
            run_id: "cancel".to_owned(),
            accepted: true,
        }
    );
    server.release();
    let terminal = sink.wait_for_terminal();

    assert_eq!(
        terminal.pointer("/params/status").and_then(Value::as_str),
        Some("cancelled_cleanly")
    );
    assert_eq!(sink.terminal_count(), 1);
    assert!(!adapter.cancel(run_cancel("cancel")).unwrap().accepted);
    adapter.shutdown().unwrap();
    server.join();
}

#[test]
fn shutdown_cancels_and_joins_an_active_worker() {
    let mut server = LoopbackServer::gated(
        sse_fragments(&[
            "event: response.output_text.delta\ndata: {\"type\":\"response.output_text.delta\",\"delta\":\"early\"}\n\n",
        ]),
        sse_fragments(&[": delayed\n"]),
    );
    let adapter = Arc::new(adapter(server.endpoint(), Duration::from_secs(1)));
    let sink = BlockingSink::default();

    adapter
        .start(run_start("shutdown"), Box::new(sink.clone()))
        .unwrap();
    server.wait_for_request();
    sink.wait_until_delta_delivery();
    let (started, start_wait) = mpsc::channel();
    let (done, done_wait) = mpsc::channel();
    let shutdown_adapter = Arc::clone(&adapter);
    let shutdown = thread::spawn(move || {
        started.send(()).unwrap();
        done.send(shutdown_adapter.shutdown()).unwrap();
    });
    start_wait.recv_timeout(Duration::from_secs(1)).unwrap();
    assert!(done_wait.recv_timeout(Duration::from_millis(30)).is_err());

    sink.release();
    server.release();
    assert_eq!(
        done_wait.recv_timeout(Duration::from_secs(1)).unwrap(),
        Ok(())
    );
    shutdown.join().unwrap();
    let terminal = sink.inner.wait_for_terminal();
    assert_eq!(
        terminal.pointer("/params/status").and_then(Value::as_str),
        Some("cancelled_cleanly")
    );
    assert!(!adapter.cancel(run_cancel("shutdown")).unwrap().accepted);
    server.join();
}

#[test]
fn rejects_start_after_shutdown() {
    let adapter = adapter(
        Url::parse("http://127.0.0.1:9/v1/responses").unwrap(),
        Duration::from_millis(20),
    );

    adapter.shutdown().unwrap();
    let start = adapter.start(run_start("closed"), Box::new(RecordingSink::default()));
    adapter.shutdown().unwrap();

    assert_eq!(start, Err(ProtocolError::InvalidRequest));
}

#[test]
fn rejects_duplicate_run_and_cancel_while_terminal_delivery_is_in_progress() {
    for (run_id, fragments) in [
        (
            "terminal-success",
            sse_fragments(&[
                "data: {\"type\":\"response.output_text.delta\",\"delta\":\"done\"}\n\n",
                "data: {\"type\":\"response.completed\",\"response\":{\"id\":\"resp-success\"}}\n\n",
            ]),
        ),
        (
            "terminal-failure",
            sse_fragments(&[
                "data: {\"type\":\"response.failed\",\"response\":{\"id\":\"resp-failure\"}}\n\n",
            ]),
        ),
    ] {
        let server = LoopbackServer::responding(fragments);
        let adapter = adapter(server.endpoint(), Duration::from_secs(1));
        let sink = TerminalBlockingSink::default();

        adapter.start(run_start(run_id), Box::new(sink.clone())).unwrap();
        sink.wait_until_terminal_delivery();
        let duplicate = adapter.start(run_start(run_id), Box::new(RecordingSink::default()));
        let cancel = adapter.cancel(run_cancel(run_id)).unwrap();

        sink.release();
        adapter.shutdown().unwrap();
        server.join();

        assert_eq!(duplicate, Err(ProtocolError::InvalidRequest));
        assert!(!cancel.accepted);
    }
}

#[test]
fn concurrent_duplicate_starts_accept_exactly_one_active_run() {
    const STARTERS: usize = 8;

    let server = LoopbackServer::responding(sse_fragments(&[
        "data: {\"type\":\"response.output_text.delta\",\"delta\":\"done\"}\n\n",
        "data: {\"type\":\"response.completed\",\"response\":{\"id\":\"resp-concurrent\"}}\n\n",
    ]));
    let adapter = Arc::new(adapter(server.endpoint(), Duration::from_secs(1)));
    let sink = BlockingSink::default();
    let barrier = Arc::new(Barrier::new(STARTERS));
    let starters = (0..STARTERS)
        .map(|_| {
            let adapter = Arc::clone(&adapter);
            let sink = sink.clone();
            let barrier = Arc::clone(&barrier);
            thread::spawn(move || {
                barrier.wait();
                adapter.start(run_start("concurrent"), Box::new(sink))
            })
        })
        .collect::<Vec<_>>();

    let results = starters
        .into_iter()
        .map(|starter| starter.join().unwrap())
        .collect::<Vec<_>>();
    sink.wait_until_delta_delivery();

    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
    assert_eq!(
        results
            .iter()
            .filter(|result| **result == Err(ProtocolError::InvalidRequest))
            .count(),
        STARTERS - 1
    );

    sink.release();
    sink.inner.wait_for_terminal();
    adapter.shutdown().unwrap();
    server.join();
}

#[test]
fn cancellation_reaps_a_live_comment_only_stream() {
    let mut server = CommentStreamServer::new();
    let adapter = adapter(server.endpoint(), Duration::from_secs(1));
    let sink = BlockingSink::default();

    adapter
        .start(run_start("comment-only"), Box::new(sink.clone()))
        .unwrap();
    server.wait_for_request();
    sink.wait_until_delta_delivery();
    server.start_comments();
    sink.release();
    server.wait_until_comments_flow();

    assert!(adapter.cancel(run_cancel("comment-only")).unwrap().accepted);
    server.close();
    let terminal = sink.inner.wait_for_terminal();

    assert_eq!(
        terminal.pointer("/params/status").and_then(Value::as_str),
        Some("cancelled_cleanly")
    );
    adapter.shutdown().unwrap();
    assert!(!adapter.cancel(run_cancel("comment-only")).unwrap().accepted);
    server.join();
}

#[test]
fn shutdown_reaps_a_live_comment_only_stream() {
    let mut server = CommentStreamServer::new();
    let adapter = Arc::new(adapter(server.endpoint(), Duration::from_secs(1)));
    let sink = BlockingSink::default();

    adapter
        .start(run_start("comment-only-shutdown"), Box::new(sink.clone()))
        .unwrap();
    server.wait_for_request();
    sink.wait_until_delta_delivery();
    server.start_comments();
    sink.release();
    server.wait_until_comments_flow();

    let (done, wait_for_shutdown) = mpsc::channel();
    let shutdown_adapter = Arc::clone(&adapter);
    let shutdown = thread::spawn(move || done.send(shutdown_adapter.shutdown()).unwrap());
    server.close();

    assert_eq!(
        wait_for_shutdown
            .recv_timeout(Duration::from_secs(1))
            .unwrap(),
        Ok(())
    );
    shutdown.join().unwrap();
    let terminal = sink.inner.wait_for_terminal();

    assert_eq!(
        terminal.pointer("/params/status").and_then(Value::as_str),
        Some("cancelled_cleanly")
    );
    assert!(
        !adapter
            .cancel(run_cancel("comment-only-shutdown"))
            .unwrap()
            .accepted
    );
    server.join();
}

#[test]
fn completed_refusal_or_no_text_emits_a_failed_terminal() {
    for (run_id, fragments, response_id, expected_message) in [
        (
            "refusal",
            sse_fragments(&[
                "event: response.refusal.delta\ndata: {\"type\":\"response.refusal.delta\",\"delta\":\"no\"}\n\n",
                "event: response.completed\ndata: {\"type\":\"response.completed\",\"response\":{\"id\":\"resp-refusal\"}}\n\n",
            ]),
            "resp-refusal",
            "provider refused to produce output text",
        ),
        (
            "empty",
            sse_fragments(&[
                "event: response.completed\ndata: {\"type\":\"response.completed\",\"response\":{\"id\":\"resp-empty\"}}\n\n",
            ]),
            "resp-empty",
            "provider response contained no output text",
        ),
    ] {
        let server = LoopbackServer::responding(fragments);
        let adapter = adapter(server.endpoint(), Duration::from_secs(1));
        let sink = RecordingSink::default();

        adapter.start(run_start(run_id), Box::new(sink.clone())).unwrap();
        let terminal = sink.wait_for_terminal();

        assert_eq!(terminal.pointer("/params/status").and_then(Value::as_str), Some("failed"));
        assert_eq!(terminal
            .pointer("/params/message/content")
            .and_then(Value::as_str)
            .unwrap(), expected_message);
        assert!(sink.deltas().is_empty());
        assert_eq!(adapter.diagnostics()[0].response_id.as_deref(), Some(response_id));
        adapter.shutdown().unwrap();
        server.join();
    }
}

#[test]
fn sanitizes_api_key_reflected_by_provider_response_ids() {
    for (run_id, headers, fragments) in [
        (
            "reflected-header-raw",
            vec![("x-request-id".to_owned(), API_KEY_CANARY.to_owned())],
            sse_fragments(&[
                "data: {\"type\":\"response.output_text.delta\",\"delta\":\"ok\"}\n\n",
                "data: {\"type\":\"response.completed\",\"response\":{}}\n\n",
            ]),
        ),
        (
            "reflected-header-bearer",
            vec![(
                "x-request-id".to_owned(),
                format!("Bearer {API_KEY_CANARY}"),
            )],
            sse_fragments(&[
                "data: {\"type\":\"response.output_text.delta\",\"delta\":\"ok\"}\n\n",
                "data: {\"type\":\"response.completed\",\"response\":{}}\n\n",
            ]),
        ),
        (
            "reflected-success-event",
            Vec::new(),
            sse_fragments(&[
                "data: {\"type\":\"response.output_text.delta\",\"delta\":\"ok\"}\n\n",
                "data: {\"type\":\"response.completed\",\"response\":{\"id\":\"sk-streaming-canary\"}}\n\n",
            ]),
        ),
        (
            "reflected-error-event",
            Vec::new(),
            sse_fragments(&[
                "data: {\"type\":\"response.failed\",\"response\":{\"id\":\"Bearer sk-streaming-canary\"}}\n\n",
            ]),
        ),
    ] {
        let server = LoopbackServer::responding_with_headers(headers, fragments);
        let adapter = adapter(server.endpoint(), Duration::from_secs(1));
        let sink = RecordingSink::default();

        adapter.start(run_start(run_id), Box::new(sink.clone())).unwrap();
        sink.wait_for_terminal();

        assert_eq!(adapter.diagnostics()[0].response_id, None);
        assert!(!format!("{:?}", adapter.diagnostics()).contains(API_KEY_CANARY));
        assert!(!format!("{adapter:?}").contains(API_KEY_CANARY));
        adapter.shutdown().unwrap();
        server.join();
    }
}

fn adapter(endpoint: Url, read_timeout: Duration) -> OpenAiResponsesAdapter {
    OpenAiResponsesAdapter::new(
        OpenAiProviderConfig::for_loopback_test(
            endpoint,
            OpenAiApiKey::new(API_KEY_CANARY).unwrap(),
            Duration::from_secs(1),
            read_timeout,
        )
        .unwrap(),
        descriptor(),
    )
    .unwrap()
}

fn descriptor() -> PeerDescriptor {
    PeerDescriptor {
        binding: ConnectionBinding {
            connection_id: "connection-1".to_owned(),
            agent_id: "agent-1".to_owned(),
            manifest_digest:
                "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_owned(),
            executable_digest:
                "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_owned(),
            trust_tier: ProtocolTrustTier::CoreAdapter,
        },
        protocol_version: "1.0".to_owned(),
        capabilities: ProtocolCapabilities {
            roles: strings(["critic"]),
            skills: strings(["testing"]),
            streaming: true,
            context_query: false,
            tool_requests: false,
            specialist_requests: false,
            max_concurrent_runs: 1,
            max_context_tokens: 1_024,
        },
    }
}

fn strings<const N: usize>(values: [&str; N]) -> BTreeSet<String> {
    values.into_iter().map(str::to_owned).collect()
}

fn run_start(run_id: &str) -> RunStart {
    let context = b"streaming prompt";
    let generation_parameters = br#"{"temperature":0}"#;
    let context_digest = format!("sha256:{:x}", Sha256::digest(context));
    let generation_parameters_digest =
        format!("sha256:{:x}", Sha256::digest(generation_parameters));
    let frame = decode(json!({
        "jsonrpc": "2.0",
        "id": format!("core:start-{run_id}"),
        "method": "agent.run.start",
        "params": {
            "runId": run_id,
            "idempotencyKey": format!("key-{run_id}"),
            "taskId": "task-1",
            "role": "critic",
            "objective": "Test adapter streaming",
            "contextPackage": {
                "packageId": "context-1",
                "contentDigest": context_digest,
                "manifestRef": "artifact:context-1"
            },
            "permissions": { "contextQuery": false, "toolRequest": false, "writeFiles": false },
            "responseSchema": "agent-message.v1",
            "limits": {
                "deadline": "2026-07-23T13:30:00Z",
                "maxOutputTokens": 17,
                "maxToolRequests": 0
            }
        }
    }));
    RunStart::new(
        frame,
        RunExecutionBinding {
            provider_id: "openai".to_owned(),
            model_id: "gpt-test-model".to_owned(),
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

fn run_cancel(run_id: &str) -> RunCancel {
    RunCancel::try_from(decode(json!({
        "jsonrpc": "2.0",
        "id": format!("core:cancel-{run_id}"),
        "method": "agent.run.cancel",
        "params": { "runId": run_id, "reason": "test", "deadlineMs": 1 }
    })))
    .unwrap()
}

fn decode(value: Value) -> ProtocolFrame {
    NdjsonCodec::default()
        .decode(&serde_json::to_vec(&value).unwrap())
        .unwrap()
}

#[derive(Clone, Default)]
struct RecordingSink {
    observations: Arc<(Mutex<Observations>, Condvar)>,
}

#[derive(Default)]
struct Observations {
    frames: Vec<ProtocolFrame>,
}

impl RecordingSink {
    fn wait_for_terminal(&self) -> Value {
        let (observations, ready) = &*self.observations;
        let observations = observations.lock().unwrap();
        let (observations, _) = ready
            .wait_timeout_while(observations, Duration::from_secs(1), |observations| {
                !observations.frames.iter().any(is_terminal)
            })
            .unwrap();
        observations
            .frames
            .iter()
            .find(|frame| is_terminal(frame))
            .map(frame_value)
            .expect("adapter must send a terminal frame")
    }

    fn deltas(&self) -> Vec<String> {
        self.observations
            .0
            .lock()
            .unwrap()
            .frames
            .iter()
            .filter_map(|frame| {
                frame_value(frame)
                    .pointer("/params/delta")
                    .and_then(Value::as_str)
                    .map(str::to_owned)
            })
            .collect()
    }

    fn sequences(&self) -> Vec<u64> {
        self.observations
            .0
            .lock()
            .unwrap()
            .frames
            .iter()
            .filter_map(|frame| {
                frame_value(frame)
                    .pointer("/params/sequence")
                    .and_then(Value::as_u64)
            })
            .collect()
    }

    fn terminal_count(&self) -> usize {
        self.observations
            .0
            .lock()
            .unwrap()
            .frames
            .iter()
            .filter(|frame| is_terminal(frame))
            .count()
    }

    fn record(&self, frame: ProtocolFrame) {
        let (observations, ready) = &*self.observations;
        observations.lock().unwrap().frames.push(frame);
        ready.notify_all();
    }
}

impl PeerEventSink for RecordingSink {
    fn receive(&self, frame: ProtocolFrame) -> Result<InboundDisposition, ProtocolError> {
        self.record(frame.clone());
        Ok(InboundDisposition::Notification(frame))
    }

    fn request(&self, frame: ProtocolFrame) -> Result<ProtocolFrame, ProtocolError> {
        let id = frame_value(&frame)
            .get("id")
            .and_then(Value::as_str)
            .unwrap()
            .to_owned();
        self.record(frame);
        Ok(decode(
            json!({ "jsonrpc": "2.0", "id": id, "result": { "accepted": true } }),
        ))
    }

    fn receive_raw(&self, _bytes: &[u8]) -> Result<InboundDisposition, ProtocolError> {
        Err(ProtocolError::InvalidRequest)
    }

    fn connection_lost(&self) -> Result<(), ProtocolError> {
        Ok(())
    }
}

#[derive(Clone)]
struct BlockingSink {
    inner: RecordingSink,
    state: Arc<(Mutex<BlockingState>, Condvar)>,
}

#[derive(Default)]
struct BlockingState {
    entered: bool,
    released: bool,
}

impl Default for BlockingSink {
    fn default() -> Self {
        Self {
            inner: RecordingSink::default(),
            state: Arc::new((Mutex::new(BlockingState::default()), Condvar::new())),
        }
    }
}

impl BlockingSink {
    fn wait_until_delta_delivery(&self) {
        let (state, ready) = &*self.state;
        let state = state.lock().unwrap();
        let (state, _) = ready
            .wait_timeout_while(state, Duration::from_secs(1), |state| !state.entered)
            .unwrap();
        assert!(state.entered);
    }

    fn release(&self) {
        let (state, ready) = &*self.state;
        state.lock().unwrap().released = true;
        ready.notify_all();
    }
}

impl PeerEventSink for BlockingSink {
    fn receive(&self, frame: ProtocolFrame) -> Result<InboundDisposition, ProtocolError> {
        let disposition = self.inner.receive(frame)?;
        let (state, ready) = &*self.state;
        let mut state = state.lock().unwrap();
        state.entered = true;
        ready.notify_all();
        let (state, _) = ready
            .wait_timeout_while(state, Duration::from_secs(1), |state| !state.released)
            .map_err(|_| ProtocolError::InternalAgentFailure)?;
        if state.released {
            Ok(disposition)
        } else {
            Err(ProtocolError::Timeout)
        }
    }

    fn request(&self, frame: ProtocolFrame) -> Result<ProtocolFrame, ProtocolError> {
        self.inner.request(frame)
    }

    fn receive_raw(&self, bytes: &[u8]) -> Result<InboundDisposition, ProtocolError> {
        self.inner.receive_raw(bytes)
    }

    fn connection_lost(&self) -> Result<(), ProtocolError> {
        self.inner.connection_lost()
    }
}

#[derive(Clone)]
struct TerminalBlockingSink {
    inner: RecordingSink,
    state: Arc<(Mutex<BlockingState>, Condvar)>,
}

impl Default for TerminalBlockingSink {
    fn default() -> Self {
        Self {
            inner: RecordingSink::default(),
            state: Arc::new((Mutex::new(BlockingState::default()), Condvar::new())),
        }
    }
}

impl TerminalBlockingSink {
    fn wait_until_terminal_delivery(&self) {
        let (state, ready) = &*self.state;
        let state = state.lock().unwrap();
        let (state, _) = ready
            .wait_timeout_while(state, Duration::from_secs(1), |state| !state.entered)
            .unwrap();
        assert!(state.entered);
    }

    fn release(&self) {
        let (state, ready) = &*self.state;
        state.lock().unwrap().released = true;
        ready.notify_all();
    }
}

impl PeerEventSink for TerminalBlockingSink {
    fn receive(&self, frame: ProtocolFrame) -> Result<InboundDisposition, ProtocolError> {
        self.inner.receive(frame)
    }

    fn request(&self, frame: ProtocolFrame) -> Result<ProtocolFrame, ProtocolError> {
        let response = self.inner.request(frame)?;
        let (state, ready) = &*self.state;
        let mut state = state.lock().unwrap();
        state.entered = true;
        ready.notify_all();
        let (state, _) = ready
            .wait_timeout_while(state, Duration::from_secs(1), |state| !state.released)
            .map_err(|_| ProtocolError::InternalAgentFailure)?;
        if state.released {
            Ok(response)
        } else {
            Err(ProtocolError::Timeout)
        }
    }

    fn receive_raw(&self, bytes: &[u8]) -> Result<InboundDisposition, ProtocolError> {
        self.inner.receive_raw(bytes)
    }

    fn connection_lost(&self) -> Result<(), ProtocolError> {
        self.inner.connection_lost()
    }
}

fn frame_value(frame: &ProtocolFrame) -> Value {
    serde_json::to_value(frame).unwrap()
}

fn is_terminal(frame: &ProtocolFrame) -> bool {
    frame_value(frame).get("method").and_then(Value::as_str) == Some("agent.run.complete")
}

struct LoopbackServer {
    endpoint: Url,
    request_count: Arc<AtomicUsize>,
    request_ready: mpsc::Receiver<()>,
    release: Option<mpsc::Sender<()>>,
    worker: Option<thread::JoinHandle<()>>,
}

struct CommentStreamServer {
    endpoint: Url,
    request_ready: mpsc::Receiver<()>,
    comments_sent: mpsc::Receiver<()>,
    start_comments: Option<mpsc::Sender<()>>,
    close: Option<mpsc::Sender<()>>,
    worker: Option<thread::JoinHandle<()>>,
}

impl CommentStreamServer {
    fn new() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let endpoint = Url::parse(&format!(
            "http://{}/v1/responses",
            listener.local_addr().unwrap()
        ))
        .unwrap();
        let (request_ready_sender, request_ready) = mpsc::channel();
        let (comments_sent_sender, comments_sent) = mpsc::channel();
        let (start_comments, wait_for_comments) = mpsc::channel();
        let (close, wait_for_close) = mpsc::channel();
        let worker = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            read_http_request(&stream);
            request_ready_sender.send(()).unwrap();
            stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nConnection: close\r\n\r\n",
                )
                .unwrap();
            stream
                .write_all(
                    b"data: {\"type\":\"response.output_text.delta\",\"delta\":\"ready\"}\n\n",
                )
                .unwrap();
            stream.flush().unwrap();
            if wait_for_comments.recv().is_err() {
                return;
            }
            let comments = b": keepalive\n".repeat(96_000);
            if stream.write_all(&comments).is_err() {
                return;
            }
            stream.flush().unwrap();
            comments_sent_sender.send(()).unwrap();
            let _ = wait_for_close.recv();
        });
        Self {
            endpoint,
            request_ready,
            comments_sent,
            start_comments: Some(start_comments),
            close: Some(close),
            worker: Some(worker),
        }
    }

    fn endpoint(&self) -> Url {
        self.endpoint.clone()
    }

    fn wait_for_request(&self) {
        self.request_ready
            .recv_timeout(Duration::from_secs(1))
            .unwrap();
    }

    fn start_comments(&mut self) {
        self.start_comments.take().unwrap().send(()).unwrap();
    }

    fn wait_until_comments_flow(&self) {
        self.comments_sent
            .recv_timeout(Duration::from_secs(1))
            .unwrap();
    }

    fn close(&mut self) {
        self.close.take().unwrap().send(()).unwrap();
    }

    fn join(mut self) {
        self.worker.take().unwrap().join().unwrap();
    }
}

impl LoopbackServer {
    fn responding(fragments: Vec<Vec<u8>>) -> Self {
        Self::response(200, Vec::new(), fragments, None, None)
    }

    fn responding_with_headers(headers: Vec<(String, String)>, fragments: Vec<Vec<u8>>) -> Self {
        Self::response(200, headers, fragments, None, None)
    }

    fn status(status: u16, headers: Vec<(String, String)>) -> Self {
        Self::response(status, headers, Vec::new(), None, None)
    }

    fn gated(before: Vec<Vec<u8>>, after: Vec<Vec<u8>>) -> Self {
        let (release, wait) = mpsc::channel();
        Self::response(200, Vec::new(), before, Some(wait), Some((release, after)))
    }

    fn response(
        status: u16,
        headers: Vec<(String, String)>,
        before: Vec<Vec<u8>>,
        wait: Option<mpsc::Receiver<()>>,
        release_after: Option<(mpsc::Sender<()>, Vec<Vec<u8>>)>,
    ) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let endpoint = Url::parse(&format!(
            "http://{}/v1/responses",
            listener.local_addr().unwrap()
        ))
        .unwrap();
        let request_count = Arc::new(AtomicUsize::new(0));
        let count = Arc::clone(&request_count);
        let (request_ready_sender, request_ready) = mpsc::channel();
        let (release, after) = release_after
            .map(|(release, after)| (Some(release), after))
            .unwrap_or((None, Vec::new()));
        let worker = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            read_http_request(&stream);
            count.fetch_add(1, Ordering::Relaxed);
            request_ready_sender.send(()).unwrap();
            let mut response = format!(
                "HTTP/1.1 {status} status\r\nContent-Type: text/event-stream\r\nConnection: close\r\n"
            );
            if wait.is_none() {
                let body_length = before.iter().map(Vec::len).sum::<usize>()
                    + after.iter().map(Vec::len).sum::<usize>();
                response.push_str(&format!("Content-Length: {body_length}\r\n"));
            }
            for (name, value) in headers {
                response.push_str(&format!("{name}: {value}\r\n"));
            }
            response.push_str("\r\n");
            if stream.write_all(response.as_bytes()).is_err() {
                return;
            }
            for fragment in before {
                if stream.write_all(&fragment).is_err() {
                    return;
                }
                let _ = stream.flush();
            }
            if let Some(wait) = wait {
                if wait.recv().is_err() {
                    return;
                }
            }
            for fragment in after {
                if stream.write_all(&fragment).is_err() {
                    return;
                }
                let _ = stream.flush();
            }
        });
        Self {
            endpoint,
            request_count,
            request_ready,
            release,
            worker: Some(worker),
        }
    }

    fn endpoint(&self) -> Url {
        self.endpoint.clone()
    }

    fn wait_for_request(&self) {
        self.request_ready
            .recv_timeout(Duration::from_secs(1))
            .unwrap();
    }

    fn release(&mut self) {
        self.release.take().unwrap().send(()).unwrap();
    }

    fn join(mut self) {
        self.worker.take().unwrap().join().unwrap();
    }
}

fn read_http_request(stream: &TcpStream) {
    let mut reader = BufReader::new(stream.try_clone().unwrap());
    let mut line = String::new();
    reader.read_line(&mut line).unwrap();
    let mut content_length = 0;
    loop {
        line.clear();
        reader.read_line(&mut line).unwrap();
        if line == "\r\n" || line == "\n" {
            break;
        }
        if let Some((name, value)) = line.trim_end().split_once(':') {
            if name.eq_ignore_ascii_case("content-length") {
                content_length = value.trim().parse().unwrap();
            }
        }
    }
    let mut body = vec![0; content_length];
    reader.read_exact(&mut body).unwrap();
}

fn sse_fragments(lines: &[&str]) -> Vec<Vec<u8>> {
    lines.iter().map(|line| line.as_bytes().to_vec()).collect()
}
