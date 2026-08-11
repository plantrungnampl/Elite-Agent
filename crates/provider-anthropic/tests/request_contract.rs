use std::{
    collections::BTreeSet,
    io::{BufRead, BufReader, Read, Write},
    net::{TcpListener, TcpStream},
    sync::{mpsc, Arc, Mutex},
    thread,
    time::Duration,
};

use local_agent_terminal_agent_protocol::{
    ConnectionBinding, InboundDisposition, NdjsonCodec, PeerDescriptor, PeerEventSink,
    ProtocolCapabilities, ProtocolError, ProtocolFrame, ProtocolPeer, ProtocolTrustTier,
    RunExecutionBinding, RunStart,
};
use local_agent_terminal_provider_anthropic::{
    AnthropicApiKey, AnthropicMessagesAdapter, AnthropicProviderConfig,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use url::Url;

const API_KEY_CANARY: &str = "anthropic-canary-must-never-escape-the-wire";
const SYSTEM_INSTRUCTIONS: &str =
    "You are an auditable local engineering agent. Return only the requested response schema.";

#[test]
fn posts_the_exact_bound_messages_request_and_keeps_the_key_off_non_wire_values() {
    let server = LoopbackServer::sse(Vec::new());
    let endpoint = server.endpoint();
    let config = loopback_config(endpoint.clone());
    let adapter = AnthropicMessagesAdapter::new(config, descriptor()).unwrap();
    let request = run_start(
        "claude-test-model",
        b"bounded context",
        br#"{"temperature":0}"#,
    );
    let sink = RecordingSink::default();

    assert_eq!(
        adapter
            .start(request.clone(), Box::new(sink.clone()))
            .unwrap(),
        local_agent_terminal_agent_protocol::RunAcceptance {
            run_id: "run-1".to_owned(),
            accepted: true,
        }
    );
    let captured = server.capture();
    assert_eq!(captured.method, "POST");
    assert_eq!(captured.target, "/v1/messages");
    assert_eq!(captured.header("x-api-key"), Some(API_KEY_CANARY));
    assert_eq!(captured.header("anthropic-version"), Some("2023-06-01"));
    assert_eq!(captured.header("content-type"), Some("application/json"));
    assert_eq!(
        captured.body,
        json!({
            "max_tokens": 17,
            "messages": [{
                "role": "user",
                "content": [{"type": "text", "text": "bounded context"}]
            }],
            "model": "claude-test-model",
            "stream": true,
            "system": SYSTEM_INSTRUCTIONS,
            "temperature": 0,
        })
    );

    adapter.shutdown().unwrap();
    let wire_start = serde_json::to_string(request.as_frame()).unwrap();
    assert!(!wire_start.contains(API_KEY_CANARY));
    assert!(!format!("{adapter:?}").contains(API_KEY_CANARY));
    assert!(!format!("{:?}", adapter.diagnostics()).contains(API_KEY_CANARY));
    assert!(
        !format!("{:?}", AnthropicApiKey::new(API_KEY_CANARY).unwrap()).contains(API_KEY_CANARY)
    );
    assert!(!format!("{:?}", loopback_config(endpoint)).contains(API_KEY_CANARY));
}

#[test]
fn every_provider_request_input_leaf_changes_the_serialized_body() {
    let baseline = capture_body(run_start(
        "claude-model-a",
        b"context-a",
        br#"{"temperature":0}"#,
    ));
    let changed_model = capture_body(run_start(
        "claude-model-b",
        b"context-a",
        br#"{"temperature":0}"#,
    ));
    let changed_context = capture_body(run_start(
        "claude-model-a",
        b"context-b",
        br#"{"temperature":0}"#,
    ));
    let changed_temperature = capture_body(run_start(
        "claude-model-a",
        b"context-a",
        br#"{"temperature":1}"#,
    ));
    let changed_max_tokens = capture_body(run_start_with_limit(
        "claude-model-a",
        b"context-a",
        br#"{"temperature":0}"#,
        18,
    ));

    for changed in [
        changed_model,
        changed_context,
        changed_temperature,
        changed_max_tokens,
    ] {
        assert_ne!(baseline, changed);
    }
}

#[test]
fn rejects_unsupported_or_invalid_generation_parameters_before_dispatch() {
    for parameters in [
        br#"{"top_p":0.5}"#.as_slice(),
        br#"{"temperature":"cold"}"#.as_slice(),
        br#"{"temperature":1.1}"#.as_slice(),
        br#"{"messages":[]}"#.as_slice(),
        br#"{"model":"override"}"#.as_slice(),
        br#"{"max_tokens":1}"#.as_slice(),
        br#"{"stream":false}"#.as_slice(),
        br#"{"system":"override"}"#.as_slice(),
    ] {
        let server = DispatchProbe::new();
        let adapter =
            AnthropicMessagesAdapter::new(loopback_config(server.endpoint()), descriptor())
                .unwrap();
        assert_eq!(
            adapter.start(
                run_start("claude-test-model", b"context", parameters),
                Box::new(RecordingSink::default()),
            ),
            Err(ProtocolError::InvalidRequest),
            "parameters must be rejected: {}",
            String::from_utf8_lossy(parameters)
        );
        assert!(!server.was_contacted());
    }
}

#[test]
fn rejects_oversized_or_invalid_context_and_missing_model_before_dispatch() {
    let server = DispatchProbe::new();
    let adapter =
        AnthropicMessagesAdapter::new(loopback_config(server.endpoint()), descriptor()).unwrap();
    assert_eq!(
        adapter.start(
            run_start(
                "claude-test-model",
                &vec![b'x'; local_agent_terminal_provider_anthropic::MAX_PROMPT_BYTES + 1],
                br#"{}"#,
            ),
            Box::new(RecordingSink::default()),
        ),
        Err(ProtocolError::ContextTooLarge)
    );
    assert_eq!(
        adapter.start(
            run_start("claude-test-model", &[0xff], br#"{}"#),
            Box::new(RecordingSink::default()),
        ),
        Err(ProtocolError::InvalidRequest)
    );
    assert!(matches!(
        try_run_start(" ", b"context", br#"{}"#, 17),
        Err(ProtocolError::InvalidRequest)
    ));
    assert!(!server.was_contacted());
}

#[test]
fn accepts_only_https_production_and_literal_loopback_http_messages_endpoints() {
    let key = AnthropicApiKey::new(API_KEY_CANARY).unwrap();
    let timeout = Duration::from_secs(1);

    assert!(AnthropicProviderConfig::new(
        Url::parse("https://api.anthropic.test/v1/messages").unwrap(),
        key.clone(),
        timeout,
        timeout,
    )
    .is_ok());
    assert!(AnthropicProviderConfig::for_loopback_test(
        Url::parse("http://127.0.0.1:1234/v1/messages").unwrap(),
        key.clone(),
        timeout,
        timeout,
    )
    .is_ok());

    for endpoint_text in [
        "http://api.anthropic.test/v1/messages",
        "https://api.anthropic.test/v1/other",
        "https://user@api.anthropic.test/v1/messages",
        "https://api.anthropic.test/v1/messages?query=1",
        "https://api.anthropic.test/v1/messages#fragment",
    ] {
        assert_eq!(
            AnthropicProviderConfig::new(
                Url::parse(endpoint_text).unwrap(),
                key.clone(),
                timeout,
                timeout,
            )
            .unwrap_err(),
            ProtocolError::InvalidRequest,
            "production endpoint must reject {endpoint_text}"
        );
    }

    for endpoint_text in [
        "http://localhost:1234/v1/messages",
        "http://192.0.2.1:1234/v1/messages",
        "http://127.0.0.1:1234/v1/other",
        "http://user@127.0.0.1:1234/v1/messages",
        "http://127.0.0.1:1234/v1/messages?query=1",
        "http://127.0.0.1:1234/v1/messages#fragment",
    ] {
        assert_eq!(
            AnthropicProviderConfig::for_loopback_test(
                Url::parse(endpoint_text).unwrap(),
                key.clone(),
                timeout,
                timeout,
            )
            .unwrap_err(),
            ProtocolError::InvalidRequest,
            "loopback endpoint must reject {endpoint_text}"
        );
    }
}

#[test]
fn rejects_invalid_api_key_header_values_without_echoing_them() {
    for invalid in ["", "   ", "key\r\ninjected: true", "key\0suffix"] {
        let error = AnthropicApiKey::new(invalid).unwrap_err();
        assert_eq!(error, ProtocolError::InvalidRequest);
        if !invalid.is_empty() {
            assert!(!error.to_string().contains(invalid));
        }
    }
}

#[test]
fn rejects_redirects_without_contacting_the_redirect_target() {
    for status in [307, 308] {
        let target = TcpListener::bind("127.0.0.1:0").unwrap();
        target.set_nonblocking(true).unwrap();
        let target_url = Url::parse(&format!(
            "http://{}/redirected",
            target.local_addr().unwrap()
        ))
        .unwrap();
        let server = RedirectServer::new(status, target_url);
        let adapter = AnthropicMessagesAdapter::new(
            AnthropicProviderConfig::for_loopback_test(
                server.endpoint(),
                AnthropicApiKey::new(API_KEY_CANARY).unwrap(),
                Duration::from_secs(1),
                Duration::from_millis(50),
            )
            .unwrap(),
            descriptor(),
        )
        .unwrap();

        adapter
            .start(
                run_start("claude-test-model", b"redirect test", br#"{}"#),
                Box::new(RecordingSink::default()),
            )
            .unwrap();
        let configured_request = server.capture();
        adapter.shutdown().unwrap();

        assert_eq!(configured_request.header("x-api-key"), Some(API_KEY_CANARY));
        assert!(matches!(
            target.accept(),
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock
        ));
        assert_eq!(
            adapter.diagnostics()[0].error,
            Some(ProtocolError::ProviderUnavailable)
        );
    }
}

fn capture_body(request: RunStart) -> Value {
    let server = LoopbackServer::sse(Vec::new());
    let adapter =
        AnthropicMessagesAdapter::new(loopback_config(server.endpoint()), descriptor()).unwrap();
    adapter
        .start(request, Box::new(RecordingSink::default()))
        .unwrap();
    let body = server.capture().body;
    adapter.shutdown().unwrap();
    body
}

fn loopback_config(endpoint: Url) -> AnthropicProviderConfig {
    AnthropicProviderConfig::for_loopback_test(
        endpoint,
        AnthropicApiKey::new(API_KEY_CANARY).unwrap(),
        Duration::from_secs(1),
        Duration::from_secs(1),
    )
    .unwrap()
}

fn descriptor() -> PeerDescriptor {
    PeerDescriptor {
        binding: ConnectionBinding {
            connection_id: "anthropic-connection-1".to_owned(),
            agent_id: "anthropic-agent-1".to_owned(),
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

fn run_start(model: &str, context: &[u8], generation_parameters: &[u8]) -> RunStart {
    try_run_start(model, context, generation_parameters, 17).unwrap()
}

fn run_start_with_limit(
    model: &str,
    context: &[u8],
    generation_parameters: &[u8],
    max_output_tokens: u64,
) -> RunStart {
    try_run_start(model, context, generation_parameters, max_output_tokens).unwrap()
}

fn try_run_start(
    model: &str,
    context: &[u8],
    generation_parameters: &[u8],
    max_output_tokens: u64,
) -> Result<RunStart, ProtocolError> {
    let context_digest = format!("sha256:{:x}", Sha256::digest(context));
    let generation_parameters_digest =
        format!("sha256:{:x}", Sha256::digest(generation_parameters));
    let frame = NdjsonCodec::default()
        .decode(
            &serde_json::to_vec(&json!({
                "jsonrpc": "2.0",
                "id": "core:start-1",
                "method": "agent.run.start",
                "params": {
                    "runId": "run-1",
                    "idempotencyKey": "key-1",
                    "taskId": "task-1",
                    "role": "critic",
                    "objective": "Test Anthropic request",
                    "contextPackage": {
                        "packageId": "context-1",
                        "contentDigest": context_digest,
                        "manifestRef": "artifact:context-1"
                    },
                    "permissions": {
                        "contextQuery": false,
                        "toolRequest": false,
                        "writeFiles": false
                    },
                    "responseSchema": "agent-message.v1",
                    "limits": {
                        "deadline": "2026-07-23T13:30:00Z",
                        "maxOutputTokens": max_output_tokens,
                        "maxToolRequests": 0
                    }
                }
            }))
            .unwrap(),
        )
        .unwrap();
    RunStart::new(
        frame,
        RunExecutionBinding {
            provider_id: "anthropic".to_owned(),
            model_id: model.to_owned(),
            generation_parameters: generation_parameters.to_vec(),
            generation_parameters_digest,
            effective_context: context.to_vec(),
            effective_context_artifact_id: "artifact-context-1".to_owned(),
            effective_context_digest: context_digest,
            supersedes_run_id: None,
        },
    )
}

#[derive(Clone, Default)]
struct RecordingSink {
    frames: Arc<Mutex<Vec<ProtocolFrame>>>,
}

impl PeerEventSink for RecordingSink {
    fn receive(&self, frame: ProtocolFrame) -> Result<InboundDisposition, ProtocolError> {
        self.frames.lock().unwrap().push(frame);
        Ok(InboundDisposition::Notification(
            NdjsonCodec::default()
                .decode(
                    &serde_json::to_vec(&json!({
                        "jsonrpc": "2.0",
                        "method": "agent.stream.delta",
                        "params": {
                            "runId": "run-1",
                            "sequence": 1,
                            "channel": "content",
                            "delta": "recorded"
                        }
                    }))
                    .unwrap(),
                )
                .unwrap(),
        ))
    }

    fn request(&self, frame: ProtocolFrame) -> Result<ProtocolFrame, ProtocolError> {
        let id = serde_json::to_value(&frame)
            .unwrap()
            .get("id")
            .and_then(Value::as_str)
            .unwrap()
            .to_owned();
        self.frames.lock().unwrap().push(frame);
        NdjsonCodec::default().decode(
            &serde_json::to_vec(
                &json!({ "jsonrpc": "2.0", "id": id, "result": { "accepted": true } }),
            )
            .unwrap(),
        )
    }

    fn receive_raw(&self, _bytes: &[u8]) -> Result<InboundDisposition, ProtocolError> {
        Err(ProtocolError::InvalidRequest)
    }

    fn connection_lost(&self) -> Result<(), ProtocolError> {
        Ok(())
    }
}

struct LoopbackServer {
    endpoint: Url,
    captured: std::sync::mpsc::Receiver<CapturedRequest>,
    worker: Option<thread::JoinHandle<()>>,
}

impl LoopbackServer {
    fn sse(body: Vec<u8>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let endpoint = Url::parse(&format!(
            "http://{}/v1/messages",
            listener.local_addr().unwrap()
        ))
        .unwrap();
        let (sender, captured) = std::sync::mpsc::channel();
        let worker = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let request = read_request(&stream);
            sender.send(request).unwrap();
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            )
            .unwrap();
            stream.write_all(&body).unwrap();
        });
        Self {
            endpoint,
            captured,
            worker: Some(worker),
        }
    }

    fn endpoint(&self) -> Url {
        self.endpoint.clone()
    }

    fn capture(self) -> CapturedRequest {
        let request = self.captured.recv_timeout(Duration::from_secs(1)).unwrap();
        self.worker.unwrap().join().unwrap();
        request
    }
}

struct RedirectServer {
    endpoint: Url,
    captured: mpsc::Receiver<CapturedRequest>,
    worker: Option<thread::JoinHandle<()>>,
}

impl RedirectServer {
    fn new(status: u16, target: Url) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let endpoint = Url::parse(&format!(
            "http://{}/v1/messages",
            listener.local_addr().unwrap()
        ))
        .unwrap();
        let (sender, captured) = mpsc::channel();
        let worker = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let request = read_request(&stream);
            sender.send(request).unwrap();
            write!(
                stream,
                "HTTP/1.1 {status} Redirect\r\nLocation: {target}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            )
            .unwrap();
        });
        Self {
            endpoint,
            captured,
            worker: Some(worker),
        }
    }

    fn endpoint(&self) -> Url {
        self.endpoint.clone()
    }

    fn capture(self) -> CapturedRequest {
        let request = self.captured.recv_timeout(Duration::from_secs(1)).unwrap();
        self.worker.unwrap().join().unwrap();
        request
    }
}

struct DispatchProbe {
    listener: TcpListener,
    endpoint: Url,
}

impl DispatchProbe {
    fn new() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let endpoint = Url::parse(&format!(
            "http://{}/v1/messages",
            listener.local_addr().unwrap()
        ))
        .unwrap();
        Self { listener, endpoint }
    }

    fn endpoint(&self) -> Url {
        self.endpoint.clone()
    }

    fn was_contacted(&self) -> bool {
        match self.listener.accept() {
            Ok(_) => true,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => false,
            Err(error) => panic!("probe accept failed: {error}"),
        }
    }
}

struct CapturedRequest {
    method: String,
    target: String,
    headers: Vec<(String, String)>,
    body: Value,
}

impl CapturedRequest {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }
}

fn read_request(stream: &TcpStream) -> CapturedRequest {
    let mut reader = BufReader::new(stream.try_clone().unwrap());
    let mut line = String::new();
    reader.read_line(&mut line).unwrap();
    let mut request_line = line.split_whitespace();
    let method = request_line.next().unwrap().to_owned();
    let target = request_line.next().unwrap().to_owned();
    let mut headers = Vec::new();
    loop {
        line.clear();
        reader.read_line(&mut line).unwrap();
        if line == "\r\n" || line == "\n" {
            break;
        }
        let (name, value) = line.trim_end().split_once(':').unwrap();
        headers.push((name.to_owned(), value.trim().to_owned()));
    }
    let content_length = headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("content-length"))
        .unwrap()
        .1
        .parse::<usize>()
        .unwrap();
    let mut body = vec![0; content_length];
    reader.read_exact(&mut body).unwrap();
    CapturedRequest {
        method,
        target,
        headers,
        body: serde_json::from_slice(&body).unwrap(),
    }
}
