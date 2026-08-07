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
use local_agent_terminal_provider_openai::{
    OpenAiApiKey, OpenAiProviderConfig, OpenAiResponsesAdapter, MAX_PROMPT_BYTES,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use url::Url;

const API_KEY_CANARY: &str = "sk-canary-must-never-escape-the-wire";

#[test]
fn posts_bound_request_and_keeps_api_key_off_everything_except_wire() {
    let server = LoopbackServer::sse(Vec::new());
    let endpoint = server.endpoint();
    let config = loopback_config(endpoint.clone());
    let adapter = OpenAiResponsesAdapter::new(config, descriptor()).unwrap();
    let request = run_start("gpt-test-model", b"bounded prompt", br#"{"temperature":0}"#);
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
    assert_eq!(captured.target, "/v1/responses");
    assert_eq!(
        captured.header("authorization"),
        Some("Bearer sk-canary-must-never-escape-the-wire")
    );
    assert_eq!(captured.header("content-type"), Some("application/json"));
    assert_eq!(
        captured.body,
        json!({
            "input": "bounded prompt",
            "max_output_tokens": 17,
            "model": "gpt-test-model",
            "store": false,
            "stream": true,
            "temperature": 0,
        })
    );
    assert!(captured.body.get("tools").is_none());
    assert!(captured.body.get("tool_choice").is_none());

    adapter.shutdown().unwrap();
    let wire_start = serde_json::to_string(request.as_frame()).unwrap();
    assert!(!wire_start.contains(API_KEY_CANARY));
    assert!(!format!("{adapter:?}").contains(API_KEY_CANARY));
    assert!(!format!("{:?}", adapter.diagnostics()).contains(API_KEY_CANARY));
    assert!(!format!("{:?}", OpenAiApiKey::new(API_KEY_CANARY).unwrap()).contains(API_KEY_CANARY));
    assert!(!format!("{:?}", loopback_config(endpoint)).contains(API_KEY_CANARY));
}

#[test]
fn rejects_non_https_or_non_loopback_http_endpoints_without_leaking_the_key() {
    let key = OpenAiApiKey::new(API_KEY_CANARY).unwrap();
    let non_https = OpenAiProviderConfig::new(
        Url::parse("http://example.com/v1/responses").unwrap(),
        key.clone(),
        Duration::from_secs(1),
        Duration::from_secs(1),
    )
    .unwrap_err();
    assert_eq!(non_https, ProtocolError::InvalidRequest);
    assert!(!non_https.to_string().contains(API_KEY_CANARY));

    let non_loopback = OpenAiProviderConfig::for_loopback_test(
        Url::parse("http://localhost/v1/responses").unwrap(),
        key,
        Duration::from_secs(1),
        Duration::from_secs(1),
    )
    .unwrap_err();
    assert_eq!(non_loopback, ProtocolError::InvalidRequest);
    assert!(!non_loopback.to_string().contains(API_KEY_CANARY));
}

#[test]
fn rejects_oversized_prompt_and_hosted_tools_before_contacting_the_provider() {
    let server = LoopbackServer::sse(Vec::new());
    let adapter =
        OpenAiResponsesAdapter::new(loopback_config(server.endpoint()), descriptor()).unwrap();

    assert_eq!(
        adapter.start(
            run_start(
                "gpt-test-model",
                &vec![b'x'; MAX_PROMPT_BYTES + 1],
                br#"{}"#
            ),
            Box::new(RecordingSink::default()),
        ),
        Err(ProtocolError::ContextTooLarge)
    );
    assert_eq!(
        adapter.start(
            run_start("gpt-test-model", b"prompt", br#"{"tools":[]}"#),
            Box::new(RecordingSink::default()),
        ),
        Err(ProtocolError::InvalidRequest)
    );
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
        let adapter = OpenAiResponsesAdapter::new(
            OpenAiProviderConfig::for_loopback_test(
                server.endpoint(),
                OpenAiApiKey::new(API_KEY_CANARY).unwrap(),
                Duration::from_secs(1),
                Duration::from_millis(50),
            )
            .unwrap(),
            descriptor(),
        )
        .unwrap();

        adapter
            .start(
                run_start("gpt-test-model", b"redirect test", br#"{}"#),
                Box::new(RecordingSink::default()),
            )
            .unwrap();
        let configured_request = server.capture();
        adapter.shutdown().unwrap();

        assert_eq!(
            configured_request.header("authorization"),
            Some("Bearer sk-canary-must-never-escape-the-wire")
        );
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

fn loopback_config(endpoint: Url) -> OpenAiProviderConfig {
    OpenAiProviderConfig::for_loopback_test(
        endpoint,
        OpenAiApiKey::new(API_KEY_CANARY).unwrap(),
        Duration::from_secs(1),
        Duration::from_secs(1),
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

fn run_start(model: &str, context: &[u8], generation_parameters: &[u8]) -> RunStart {
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
                    "objective": "Test adapter request",
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
            }))
            .unwrap(),
        )
        .unwrap();
    RunStart::new(
        frame,
        RunExecutionBinding {
            provider_id: "openai".to_owned(),
            model_id: model.to_owned(),
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
                        "params": { "runId": "run-1", "sequence": 1, "channel": "content", "delta": "recorded" }
                    }))
                    .unwrap(),
                )
                .unwrap(),
        ))
    }

    fn request(&self, frame: ProtocolFrame) -> Result<ProtocolFrame, ProtocolError> {
        let id = frame_value(&frame)
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

fn frame_value(frame: &ProtocolFrame) -> Value {
    serde_json::to_value(frame).unwrap()
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
            "http://{}/v1/responses",
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
            "http://{}/v1/responses",
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
