use std::{
    collections::BTreeSet,
    io::{BufRead, BufReader, Read, Write},
    net::{TcpListener, TcpStream},
    sync::{
        atomic::{AtomicU64, Ordering},
        mpsc, Arc, Mutex,
    },
    thread,
    time::Duration,
};

use local_agent_terminal_agent_protocol::{
    run_conformance, CancelAcceptance, ConformanceCase, ConformancePeerFactory,
    ConformanceScenario, ConnectionBinding, InboundDisposition, NdjsonCodec, PeerDescriptor,
    PeerEventSink, ProtocolCapabilities, ProtocolError, ProtocolFrame, ProtocolPeer,
    ProtocolTrustTier, RunAcceptance, RunCancel, RunStart,
};
use local_agent_terminal_provider_anthropic::{
    AnthropicApiKey, AnthropicMessagesAdapter, AnthropicProviderConfig, MAX_SSE_EVENT_BYTES,
};
use serde_json::{json, Value};
use url::Url;

#[test]
fn anthropic_adapter_passes_shared_conformance_against_loopback_sse_fixtures() {
    run_conformance(&AnthropicConformanceFactory::new())
        .expect("the Anthropic adapter must satisfy the shared peer contract");
}

struct AnthropicConformanceFactory {
    descriptor: PeerDescriptor,
    peers: Mutex<Vec<(ConformanceScenario, Arc<FixturePeer>)>>,
}

impl AnthropicConformanceFactory {
    fn new() -> Self {
        Self {
            descriptor: descriptor(),
            peers: Mutex::new(Vec::new()),
        }
    }
}

impl ConformancePeerFactory for AnthropicConformanceFactory {
    fn peer_for(&self, case: ConformanceCase) -> Result<Box<dyn ProtocolPeer>, ProtocolError> {
        let peer = Arc::new(FixturePeer::new(case.scenario, self.descriptor.clone())?);
        self.peers
            .lock()
            .map_err(|_| ProtocolError::InternalAgentFailure)?
            .push((case.scenario, Arc::clone(&peer)));
        Ok(Box::new(FixturePeerHandle(peer)))
    }

    fn start_accepted(&self, case: ConformanceCase) -> Result<(), ProtocolError> {
        if matches!(
            case.scenario,
            ConformanceScenario::Slow | ConformanceScenario::Cancelled
        ) {
            return Ok(());
        }
        let peer = self
            .peers
            .lock()
            .map_err(|_| ProtocolError::InternalAgentFailure)?
            .iter()
            .find(|(scenario, _)| *scenario == case.scenario)
            .map(|(_, peer)| Arc::clone(peer))
            .ok_or(ProtocolError::InternalAgentFailure)?;
        peer.release();
        Ok(())
    }
}

struct FixturePeer {
    scenario: ConformanceScenario,
    adapter: AnthropicMessagesAdapter,
    server: LoopbackFixture,
}

impl FixturePeer {
    fn new(
        scenario: ConformanceScenario,
        descriptor: PeerDescriptor,
    ) -> Result<Self, ProtocolError> {
        let server = LoopbackFixture::new(scenario);
        let config = AnthropicProviderConfig::for_loopback_test(
            server.endpoint(),
            AnthropicApiKey::new("sk-conformance-canary")?,
            Duration::from_secs(1),
            Duration::from_secs(1),
        )?;
        Ok(Self {
            scenario,
            adapter: AnthropicMessagesAdapter::new(config, descriptor)?,
            server,
        })
    }

    fn release(&self) {
        self.server.release();
    }

    fn shutdown(&self) -> Result<(), ProtocolError> {
        self.server.release();
        let adapter = self.adapter.shutdown();
        self.server.join()?;
        adapter
    }
}

struct FixturePeerHandle(Arc<FixturePeer>);

impl ProtocolPeer for FixturePeerHandle {
    fn descriptor(&self) -> PeerDescriptor {
        self.0.adapter.descriptor()
    }

    fn start(
        &self,
        request: RunStart,
        sink: Box<dyn PeerEventSink>,
    ) -> Result<RunAcceptance, ProtocolError> {
        self.0.adapter.start(
            request,
            Box::new(ScenarioSink {
                scenario: self.0.scenario,
                inner: sink,
                delivered_deltas: AtomicU64::new(0),
            }),
        )
    }

    fn cancel(&self, request: RunCancel) -> Result<CancelAcceptance, ProtocolError> {
        self.0.adapter.cancel(request)
    }

    fn shutdown(&self) -> Result<(), ProtocolError> {
        self.0.shutdown()
    }
}

struct ScenarioSink {
    scenario: ConformanceScenario,
    inner: Box<dyn PeerEventSink>,
    delivered_deltas: AtomicU64,
}

impl PeerEventSink for ScenarioSink {
    fn receive(&self, frame: ProtocolFrame) -> Result<InboundDisposition, ProtocolError> {
        match self.scenario {
            ConformanceScenario::Malicious => self.inner.receive(heartbeat("wrong-connection", 1)?),
            ConformanceScenario::Crashed => self
                .inner
                .connection_lost()
                .and(Err(ProtocolError::InternalAgentFailure)),
            ConformanceScenario::SequenceGap => {
                let mut value =
                    serde_json::to_value(frame).map_err(|_| ProtocolError::InternalAgentFailure)?;
                if value.get("method").and_then(Value::as_str) == Some("agent.stream.delta")
                    && self.delivered_deltas.fetch_add(1, Ordering::Relaxed) == 1
                {
                    value["params"]["sequence"] = Value::from(3_u64);
                }
                self.inner.receive(decode(value))
            }
            ConformanceScenario::Happy
            | ConformanceScenario::Slow
            | ConformanceScenario::Cancelled
            | ConformanceScenario::Malformed
            | ConformanceScenario::Oversize
            | ConformanceScenario::DuplicateTerminal => self.inner.receive(frame),
        }
    }

    fn request(&self, frame: ProtocolFrame) -> Result<ProtocolFrame, ProtocolError> {
        match self.scenario {
            ConformanceScenario::Malformed => self
                .inner
                .receive_raw(b"{")
                .and(Err(ProtocolError::InvalidJson)),
            ConformanceScenario::Oversize => self
                .inner
                .receive_raw(b"{}")
                .and(Err(ProtocolError::FrameTooLarge { max_frame_bytes: 1 })),
            ConformanceScenario::DuplicateTerminal => {
                let response = self.inner.request(frame.clone())?;
                let _ = self.inner.request(frame);
                Ok(response)
            }
            ConformanceScenario::Happy
            | ConformanceScenario::Malicious
            | ConformanceScenario::Slow
            | ConformanceScenario::Cancelled
            | ConformanceScenario::Crashed
            | ConformanceScenario::SequenceGap => self.inner.request(frame),
        }
    }

    fn receive_raw(&self, bytes: &[u8]) -> Result<InboundDisposition, ProtocolError> {
        self.inner.receive_raw(bytes)
    }

    fn connection_lost(&self) -> Result<(), ProtocolError> {
        self.inner.connection_lost()
    }
}

struct LoopbackFixture {
    endpoint: Url,
    release: mpsc::Sender<()>,
    worker: Mutex<Option<thread::JoinHandle<()>>>,
}

impl LoopbackFixture {
    fn new(scenario: ConformanceScenario) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let endpoint = Url::parse(&format!(
            "http://{}/v1/messages",
            listener.local_addr().unwrap()
        ))
        .unwrap();
        let (release, wait) = mpsc::channel();
        let body = scenario_body(scenario);
        let worker = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            read_http_request(&stream);
            let header = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            if stream.write_all(header.as_bytes()).is_err() {
                return;
            }
            if wait.recv().is_err() {
                return;
            }
            let _ = stream.write_all(&body);
        });
        Self {
            endpoint,
            release,
            worker: Mutex::new(Some(worker)),
        }
    }

    fn endpoint(&self) -> Url {
        self.endpoint.clone()
    }

    fn release(&self) {
        let _ = self.release.send(());
    }

    fn join(&self) -> Result<(), ProtocolError> {
        let worker = self
            .worker
            .lock()
            .map_err(|_| ProtocolError::InternalAgentFailure)?
            .take();
        match worker {
            Some(worker) => worker
                .join()
                .map_err(|_| ProtocolError::InternalAgentFailure),
            None => Ok(()),
        }
    }
}

fn scenario_body(scenario: ConformanceScenario) -> Vec<u8> {
    match scenario {
        ConformanceScenario::Happy | ConformanceScenario::DuplicateTerminal => sse(&[
            "data: {\"type\":\"message_start\",\"message\":{\"id\":\"msg-happy\",\"usage\":{\"input_tokens\":1,\"output_tokens\":0}}}\n\n",
            "data: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"text\",\"text\":\"\"}}\n\n",
            "data: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"ok\"}}\n\n",
            "data: {\"type\":\"content_block_stop\",\"index\":0}\n\n",
            "data: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\"},\"usage\":{\"output_tokens\":1}}\n\n",
            "data: {\"type\":\"message_stop\"}\n\n",
        ]),
        ConformanceScenario::Malicious | ConformanceScenario::Crashed => sse(&[
            "data: {\"type\":\"message_start\",\"message\":{\"id\":\"msg-adversarial\",\"usage\":{\"input_tokens\":1,\"output_tokens\":0}}}\n\n",
            "data: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"text\",\"text\":\"\"}}\n\n",
            "data: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"bad\"}}\n\n",
        ]),
        ConformanceScenario::Malformed => b"data: {\n\n".to_vec(),
        ConformanceScenario::Oversize => {
            let mut body = b"data: ".to_vec();
            body.extend(std::iter::repeat_n(b'x', MAX_SSE_EVENT_BYTES + 1));
            body.extend(b"\n\n");
            body
        }
        ConformanceScenario::SequenceGap => sse(&[
            "data: {\"type\":\"message_start\",\"message\":{\"id\":\"msg-gap\",\"usage\":{\"input_tokens\":1,\"output_tokens\":0}}}\n\n",
            "data: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"text\",\"text\":\"\"}}\n\n",
            "data: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"one\"}}\n\n",
            "data: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"gap\"}}\n\n",
        ]),
        ConformanceScenario::Slow | ConformanceScenario::Cancelled => b": delayed\n".to_vec(),
    }
}

fn sse(lines: &[&str]) -> Vec<u8> {
    lines.concat().into_bytes()
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
        protocol_version: "2.0".to_owned(),
        capabilities: ProtocolCapabilities {
            roles: strings(["critic"]),
            skills: strings(["testing"]),
            streaming: true,
            context_query: true,
            tool_requests: true,
            specialist_requests: true,
            max_concurrent_runs: 1,
            max_context_tokens: 1_024,
        },
    }
}

fn strings<const N: usize>(values: [&str; N]) -> BTreeSet<String> {
    values.into_iter().map(str::to_owned).collect()
}

fn heartbeat(connection_id: &str, sequence: u64) -> Result<ProtocolFrame, ProtocolError> {
    Ok(decode(json!({
        "jsonrpc": "2.0",
        "method": "agent.heartbeat",
        "params": { "connectionId": connection_id, "sequence": sequence }
    })))
}

fn decode(value: Value) -> ProtocolFrame {
    NdjsonCodec::default()
        .decode(&serde_json::to_vec(&value).unwrap())
        .unwrap()
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
