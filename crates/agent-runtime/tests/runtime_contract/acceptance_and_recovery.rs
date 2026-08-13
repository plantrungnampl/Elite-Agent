#[test]
fn reconstructed_runtime_does_not_resurrect_or_cancel_an_interrupted_run() {
    let store = Arc::new(RecordingStore::default());
    let artifacts = Arc::new(RecordingArtifacts::default());
    let clock = Arc::new(ManualClock::new(1_800_000_000));
    let peer = Arc::new(ScriptedPeer::new(Script::Slow, peer_descriptor()));
    let runtime = runtime_with_artifacts(
        Arc::clone(&store),
        Arc::clone(&artifacts),
        Arc::clone(&clock),
        Arc::clone(&peer),
    );
    runtime
        .start_run(run_request("run-durable-replay", None))
        .unwrap();
    runtime
        .cancel(CancelAgentRun {
            run_id: run_id("run-durable-replay"),
            reason: "replay-cancel".to_owned(),
            deadline_ms: 1_000,
        })
        .unwrap();
    assert_eq!(peer.start_requests().len(), 1);
    assert_eq!(peer.cancel_count(), 1);

    let reconstructed =
        runtime_with_artifacts(Arc::clone(&store), artifacts, clock, Arc::clone(&peer));
    let start_error = reconstructed
        .start_run(run_request("run-durable-replay", None))
        .unwrap_err();
    let cancel_error = reconstructed
        .cancel(CancelAgentRun {
            run_id: run_id("run-durable-replay"),
            reason: "replay-cancel".to_owned(),
            deadline_ms: 1_000,
        })
        .unwrap_err();

    assert_eq!(start_error.safe_classification(), SafeErrorClassification::Conflict);
    assert_eq!(cancel_error.safe_classification(), SafeErrorClassification::NotFound);
    assert_eq!(store.status("run-durable-replay"), Some(AgentRunStatus::Interrupted));
    assert_eq!(peer.start_requests().len(), 1);
    assert_eq!(peer.cancel_count(), 1);
}

#[test]
fn reconstructed_pending_core_start_is_not_redispatched_or_reported_success() {
    let store = Arc::new(RecordingStore::default());
    let artifacts = Arc::new(RecordingArtifacts::default());
    let clock = Arc::new(ManualClock::new(1_800_000_000));
    let peer = Arc::new(ScriptedPeer::new(Script::Slow, peer_descriptor()));
    let first_runtime = runtime_with_artifacts(
        Arc::clone(&store),
        Arc::clone(&artifacts),
        Arc::clone(&clock),
        Arc::clone(&peer),
    );
    first_runtime
        .start_run(run_request("run-pending-start", None))
        .unwrap();
    store.mark_protocol_request_pending(
        "connection-1",
        "core:run-start:run-pending-start",
    );
    drop(first_runtime);

    let reconstructed = runtime_with_artifacts(store.clone(), artifacts, clock, Arc::clone(&peer));
    let error = reconstructed
        .start_run(run_request("run-pending-start", None))
        .unwrap_err();

    assert_eq!(
        error.safe_classification(),
        SafeErrorClassification::Conflict
    );
    assert_eq!(peer.start_requests().len(), 1);
    assert_eq!(
        store.status("run-pending-start"),
        Some(AgentRunStatus::Interrupted)
    );
}

#[test]
fn reconstructed_runtime_rejects_changed_core_request_digest_before_peer_start() {
    let store = Arc::new(RecordingStore::default());
    let artifacts = Arc::new(RecordingArtifacts::default());
    let clock = Arc::new(ManualClock::new(1_800_000_000));
    let peer = Arc::new(ScriptedPeer::new(Script::Slow, peer_descriptor()));
    let runtime = runtime_with_artifacts(
        Arc::clone(&store),
        Arc::clone(&artifacts),
        Arc::clone(&clock),
        Arc::clone(&peer),
    );
    runtime
        .start_run(run_request("run-digest-conflict", None))
        .unwrap();

    let reconstructed = runtime_with_artifacts(store, artifacts, clock, Arc::clone(&peer));
    let mut changed = run_request("run-digest-conflict", None);
    changed.idempotency_key = "task-1:reviewer:changed".to_owned();
    let error = reconstructed.start_run(changed).unwrap_err();

    assert_eq!(
        error.safe_classification(),
        SafeErrorClassification::Conflict
    );
    assert_eq!(peer.start_requests().len(), 1);
}

#[test]
fn core_response_completion_failure_returns_no_start_receipt_or_peer_dispatch() {
    let store = Arc::new(RecordingStore::default());
    store.fail_protocol_complete();
    let artifacts = Arc::new(RecordingArtifacts::default());
    let peer = Arc::new(ScriptedPeer::new(Script::Slow, peer_descriptor()));
    let runtime = runtime_with_artifacts(
        Arc::clone(&store),
        artifacts,
        Arc::new(ManualClock::new(1_800_000_000)),
        Arc::clone(&peer),
    );

    let error = runtime
        .start_run(run_request("run-complete-failure", None))
        .unwrap_err();

    assert_eq!(
        error.safe_classification(),
        SafeErrorClassification::StorageFull
    );
    assert!(peer.start_requests().is_empty());
}

#[test]
fn core_response_artifact_failure_returns_no_start_receipt_or_peer_dispatch() {
    let store = Arc::new(RecordingStore::default());
    let artifacts = Arc::new(RecordingArtifacts::default());
    artifacts.fail_protocol_response_publish();
    let peer = Arc::new(ScriptedPeer::new(Script::Slow, peer_descriptor()));
    let runtime = runtime_with_artifacts(
        Arc::clone(&store),
        artifacts,
        Arc::new(ManualClock::new(1_800_000_000)),
        Arc::clone(&peer),
    );

    let error = runtime
        .start_run(run_request("run-artifact-failure", None))
        .unwrap_err();

    assert_eq!(
        error.safe_classification(),
        SafeErrorClassification::Internal
    );
    assert!(peer.start_requests().is_empty());
}

#[test]
fn cancel_response_completion_failure_returns_no_receipt() {
    let store = Arc::new(RecordingStore::default());
    let artifacts = Arc::new(RecordingArtifacts::default());
    let peer = Arc::new(ScriptedPeer::new(Script::Slow, peer_descriptor()));
    let runtime = runtime_with_artifacts(
        Arc::clone(&store),
        artifacts,
        Arc::new(ManualClock::new(1_800_000_000)),
        Arc::clone(&peer),
    );
    runtime
        .start_run(run_request("run-cancel-complete-failure", None))
        .unwrap();
    store.fail_protocol_complete();

    let error = runtime
        .cancel(CancelAgentRun {
            run_id: run_id("run-cancel-complete-failure"),
            reason: "durable-cancel".to_owned(),
            deadline_ms: 1_000,
        })
        .unwrap_err();

    assert_eq!(
        error.safe_classification(),
        SafeErrorClassification::StorageFull
    );
    assert_eq!(peer.cancel_count(), 1);
}

#[derive(Default)]
struct AcceptanceGateState {
    entered: bool,
    released: bool,
}

struct AcceptanceGate {
    state: Mutex<AcceptanceGateState>,
    changed: Condvar,
}

#[derive(Default)]
struct CompletionSignal {
    completed: Mutex<bool>,
    changed: Condvar,
}

impl CompletionSignal {
    fn complete(&self) {
        *self.completed.lock().unwrap() = true;
        self.changed.notify_all();
    }

    fn wait(&self, timeout: Duration) -> bool {
        let completed = self.completed.lock().unwrap();
        let (completed, _) = self
            .changed
            .wait_timeout_while(completed, timeout, |completed| !*completed)
            .unwrap();
        *completed
    }
}

impl AcceptanceGate {
    fn new() -> Self {
        Self {
            state: Mutex::new(AcceptanceGateState::default()),
            changed: Condvar::new(),
        }
    }

    fn block(&self) {
        let mut state = self.state.lock().unwrap();
        state.entered = true;
        self.changed.notify_all();
        while !state.released {
            state = self.changed.wait(state).unwrap();
        }
    }

    fn wait_until_entered(&self) {
        let mut state = self.state.lock().unwrap();
        while !state.entered {
            state = self.changed.wait(state).unwrap();
        }
    }

    fn wait_until_entered_for(&self, timeout: Duration) -> bool {
        let state = self.state.lock().unwrap();
        let (state, _) = self
            .changed
            .wait_timeout_while(state, timeout, |state| !state.entered)
            .unwrap();
        state.entered
    }

    fn release(&self) {
        self.state.lock().unwrap().released = true;
        self.changed.notify_all();
    }
}

struct ThreadedRacePeer {
    emission: ThreadedEmission,
    gate: Arc<AcceptanceGate>,
    attempted: mpsc::Sender<()>,
    completed: mpsc::Sender<Result<(), ProtocolError>>,
    workers: Mutex<Vec<JoinHandle<()>>>,
}

impl ThreadedRacePeer {
    fn new(
        emission: ThreadedEmission,
        gate: Arc<AcceptanceGate>,
    ) -> (
        Arc<Self>,
        mpsc::Receiver<()>,
        mpsc::Receiver<Result<(), ProtocolError>>,
    ) {
        let (attempted, attempted_receiver) = mpsc::channel();
        let (completed, completed_receiver) = mpsc::channel();
        (
            Arc::new(Self {
                emission,
                gate,
                attempted,
                completed,
                workers: Mutex::new(Vec::new()),
            }),
            attempted_receiver,
            completed_receiver,
        )
    }

    fn join_workers(&self) -> Result<(), ProtocolError> {
        for worker in self.workers.lock().unwrap().drain(..) {
            worker
                .join()
                .map_err(|_| ProtocolError::InternalAgentFailure)?;
        }
        Ok(())
    }
}

impl ProtocolPeer for ThreadedRacePeer {
    fn descriptor(&self) -> PeerDescriptor {
        peer_descriptor()
    }

    fn start(
        &self,
        request: RunStart,
        sink: Box<dyn PeerEventSink>,
    ) -> Result<RunAcceptance, ProtocolError> {
        let run_id = request.run_id();
        let worker_run_id = run_id.clone();
        let emission = self.emission;
        let gate = Arc::clone(&self.gate);
        let attempted = self.attempted.clone();
        let completed = self.completed.clone();
        self.workers.lock().unwrap().push(thread::spawn(move || {
            gate.wait_until_entered();
            attempted.send(()).expect("race observer");
            let result = match emission {
                ThreadedEmission::Delta => {
                    sink.receive(threaded_delta(&worker_run_id))
                        .map(|disposition| {
                            assert!(matches!(disposition, InboundDisposition::Notification(_)));
                        })
                }
                ThreadedEmission::Terminal => {
                    sink.request(threaded_terminal(&worker_run_id)).map(|_| ())
                }
            };
            completed.send(result).expect("race result observer");
        }));
        Ok(RunAcceptance {
            run_id,
            accepted: true,
        })
    }

    fn cancel(&self, request: RunCancel) -> Result<CancelAcceptance, ProtocolError> {
        Ok(CancelAcceptance {
            run_id: request.run_id(),
            accepted: true,
        })
    }

    fn shutdown(&self) -> Result<(), ProtocolError> {
        Ok(())
    }
}

struct EnteredSink {
    sink: Box<dyn PeerEventSink>,
    entered: Mutex<Option<mpsc::Sender<()>>>,
}

impl EnteredSink {
    fn notify_entered(&self) {
        if let Some(entered) = self.entered.lock().unwrap().take() {
            entered.send(()).expect("sink entry observer");
        }
    }
}

impl PeerEventSink for EnteredSink {
    fn receive(&self, frame: ProtocolFrame) -> Result<InboundDisposition, ProtocolError> {
        self.notify_entered();
        self.sink.receive(frame)
    }

    fn request(&self, frame: ProtocolFrame) -> Result<ProtocolFrame, ProtocolError> {
        self.notify_entered();
        self.sink.request(frame)
    }

    fn receive_raw(&self, bytes: &[u8]) -> Result<InboundDisposition, ProtocolError> {
        self.notify_entered();
        self.sink.receive_raw(bytes)
    }

    fn connection_lost(&self) -> Result<(), ProtocolError> {
        self.notify_entered();
        self.sink.connection_lost()
    }
}

struct PreReturnRacePeer {
    completed: mpsc::Sender<Result<InboundDisposition, ProtocolError>>,
    worker: Mutex<Option<JoinHandle<()>>>,
}

impl PreReturnRacePeer {
    fn new() -> (
        Arc<Self>,
        mpsc::Receiver<Result<InboundDisposition, ProtocolError>>,
    ) {
        let (completed, completed_receiver) = mpsc::channel();
        (
            Arc::new(Self {
                completed,
                worker: Mutex::new(None),
            }),
            completed_receiver,
        )
    }

    fn join_worker(&self) -> Result<(), ProtocolError> {
        self.worker
            .lock()
            .unwrap()
            .take()
            .expect("pre-return worker")
            .join()
            .map_err(|_| ProtocolError::InternalAgentFailure)
    }
}

impl ProtocolPeer for PreReturnRacePeer {
    fn descriptor(&self) -> PeerDescriptor {
        peer_descriptor()
    }

    fn start(
        &self,
        request: RunStart,
        sink: Box<dyn PeerEventSink>,
    ) -> Result<RunAcceptance, ProtocolError> {
        let run_id = request.run_id();
        let worker_run_id = run_id.clone();
        let completed = self.completed.clone();
        let (entered, entered_receiver) = mpsc::channel();
        *self.worker.lock().unwrap() = Some(thread::spawn(move || {
            let sink = EnteredSink {
                sink,
                entered: Mutex::new(Some(entered)),
            };
            completed
                .send(sink.receive(threaded_delta(&worker_run_id)))
                .expect("pre-return callback result observer");
        }));
        entered_receiver
            .recv_timeout(Duration::from_secs(1))
            .map_err(|_| ProtocolError::Timeout)?;
        Ok(RunAcceptance {
            run_id,
            accepted: true,
        })
    }

    fn cancel(&self, request: RunCancel) -> Result<CancelAcceptance, ProtocolError> {
        Ok(CancelAcceptance {
            run_id: request.run_id(),
            accepted: true,
        })
    }

    fn shutdown(&self) -> Result<(), ProtocolError> {
        Ok(())
    }
}

#[derive(Default)]
struct SynchronousCallbackPeer {
    callback_result: Mutex<Option<Result<(), ProtocolError>>>,
    connection_lost_result: Mutex<Option<Result<(), ProtocolError>>>,
}

impl SynchronousCallbackPeer {
    fn callback_result(&self) -> Option<Result<(), ProtocolError>> {
        *self.callback_result.lock().unwrap()
    }

    fn connection_lost_result(&self) -> Option<Result<(), ProtocolError>> {
        *self.connection_lost_result.lock().unwrap()
    }
}

impl ProtocolPeer for SynchronousCallbackPeer {
    fn descriptor(&self) -> PeerDescriptor {
        peer_descriptor()
    }

    fn start(
        &self,
        request: RunStart,
        sink: Box<dyn PeerEventSink>,
    ) -> Result<RunAcceptance, ProtocolError> {
        let run_id = request.run_id();
        *self.callback_result.lock().unwrap() =
            Some(sink.receive(threaded_delta(&run_id)).map(|_| ()));
        *self.connection_lost_result.lock().unwrap() = Some(sink.connection_lost());
        Ok(RunAcceptance {
            run_id,
            accepted: true,
        })
    }

    fn cancel(&self, request: RunCancel) -> Result<CancelAcceptance, ProtocolError> {
        Ok(CancelAcceptance {
            run_id: request.run_id(),
            accepted: true,
        })
    }

    fn shutdown(&self) -> Result<(), ProtocolError> {
        Ok(())
    }
}

struct MultiRunPeer {
    descriptor: PeerDescriptor,
    sinks: Mutex<Vec<Arc<dyn PeerEventSink>>>,
    shutdown: Mutex<bool>,
}

impl MultiRunPeer {
    fn new(descriptor: PeerDescriptor) -> Self {
        Self {
            descriptor,
            sinks: Mutex::new(Vec::new()),
            shutdown: Mutex::new(false),
        }
    }

    fn was_shutdown(&self) -> bool {
        *self.shutdown.lock().unwrap()
    }

    fn start_count(&self) -> usize {
        self.sinks.lock().unwrap().len()
    }

    fn connection_lost(&self, index: usize) -> Result<(), ProtocolError> {
        let sink = Arc::clone(&self.sinks.lock().unwrap()[index]);
        sink.connection_lost()
    }

    fn request(&self, index: usize, frame: ProtocolFrame) -> Result<ProtocolFrame, ProtocolError> {
        let sink = Arc::clone(&self.sinks.lock().unwrap()[index]);
        sink.request(frame)
    }

}

impl ProtocolPeer for MultiRunPeer {
    fn descriptor(&self) -> PeerDescriptor {
        self.descriptor.clone()
    }

    fn start(
        &self,
        request: RunStart,
        sink: Box<dyn PeerEventSink>,
    ) -> Result<RunAcceptance, ProtocolError> {
        self.sinks.lock().unwrap().push(Arc::from(sink));
        Ok(RunAcceptance {
            run_id: request.run_id(),
            accepted: true,
        })
    }

    fn cancel(&self, request: RunCancel) -> Result<CancelAcceptance, ProtocolError> {
        Ok(CancelAcceptance {
            run_id: request.run_id(),
            accepted: true,
        })
    }

    fn shutdown(&self) -> Result<(), ProtocolError> {
        *self.shutdown.lock().unwrap() = true;
        Ok(())
    }
}

fn threaded_delta(run_id: &str) -> ProtocolFrame {
    stream_delta_frame(run_id, 1, "content", "threaded")
}

fn stream_delta_frame(run_id: &str, sequence: u64, channel: &str, delta: &str) -> ProtocolFrame {
    decode_protocol_frame(serde_json::json!({
        "jsonrpc": "2.0",
        "method": "agent.stream.delta",
        "params": {
            "runId": run_id,
            "sequence": sequence,
            "channel": channel,
            "delta": delta
        }
    }))
}

fn threaded_terminal(run_id: &str) -> ProtocolFrame {
    decode_protocol_frame(serde_json::json!({
        "jsonrpc": "2.0",
        "id": "agent:threaded-terminal",
        "method": "agent.run.complete",
        "params": {
            "runId": run_id,
            "status": "succeeded",
            "message": {
                "messageId": "message-threaded-terminal",
                "type": "answer",
                "content": "threaded terminal",
                "claims": []
            },
            "usage": {
                "inputTokens": 1,
                "outputTokens": 1,
                "providerReportedCostMicrounits": 0
            }
        }
    }))
}

fn context_query_frame(
    request_id: &str,
    run_id: &str,
    query_id: &str,
    max_tokens: u64,
) -> ProtocolFrame {
    decode_protocol_frame(serde_json::json!({
        "jsonrpc": "2.0",
        "id": request_id,
        "method": "context.query",
        "params": {
            "runId": run_id,
            "queryId": query_id,
            "query": "More context",
            "scopes": ["repository"],
            "maxItems": 1,
            "maxTokens": max_tokens
        }
    }))
}

fn tool_request_frame(request_id: &str, run_id: &str) -> ProtocolFrame {
    decode_protocol_frame(serde_json::json!({
        "jsonrpc": "2.0",
        "id": request_id,
        "method": "tool.request",
        "params": {
            "runId": run_id,
            "requestId": "tool-request-1",
            "tool": "tool-1",
            "arguments": {},
            "argumentsDigest": EMPTY_JSON_DIGEST,
            "reason": "test policy rejection"
        }
    }))
}

fn specialist_request_frame(
    request_id: &str,
    run_id: &str,
    required_context: &[&str],
) -> ProtocolFrame {
    decode_protocol_frame(serde_json::json!({
        "jsonrpc": "2.0",
        "id": request_id,
        "method": "specialist.request",
        "params": {
            "runId": run_id,
            "requestId": "specialist-request-1",
            "capability": "review",
            "reason": "Need review",
            "requiredContext": required_context
        }
    }))
}

fn decode_protocol_frame(value: serde_json::Value) -> ProtocolFrame {
    NdjsonCodec::default()
        .decode(&serde_json::to_vec(&value).unwrap())
        .unwrap()
}

fn deserialize_protocol_frame(value: serde_json::Value) -> ProtocolFrame {
    serde_json::from_value(value).unwrap()
}

fn runtime(
    store: Arc<RecordingStore>,
    clock: Arc<ManualClock>,
    peer: Arc<ScriptedPeer>,
) -> ProtocolAgentRuntime {
    runtime_with_artifacts(store, Arc::new(RecordingArtifacts::default()), clock, peer)
}

fn runtime_with_artifacts(
    store: Arc<RecordingStore>,
    artifacts: Arc<RecordingArtifacts>,
    clock: Arc<ManualClock>,
    peer: Arc<ScriptedPeer>,
) -> ProtocolAgentRuntime {
    let protocol_peer: Arc<dyn ProtocolPeer> = peer;
    ProtocolAgentRuntime::new(
        store.clone(),
        artifacts.clone(),
        store,
        artifacts,
        clock,
        vec![agent_registration(protocol_peer)],
    )
    .unwrap()
}

fn runtime_with_ports(
    store: Arc<RecordingStore>,
    artifacts: Arc<RecordingArtifacts>,
    clock: Arc<dyn Clock>,
    agents: Vec<(AgentDescriptor, Sha256Digest, Arc<dyn ProtocolPeer>)>,
) -> Result<ProtocolAgentRuntime, PortError> {
    ProtocolAgentRuntime::new(
        store.clone(),
        artifacts.clone(),
        store,
        artifacts,
        clock,
        agents,
    )
}

fn runtime_with_request_handler(
    store: Arc<RecordingStore>,
    artifacts: Arc<RecordingArtifacts>,
    clock: Arc<ManualClock>,
    peer: Arc<ScriptedPeer>,
    handler: Arc<RecordingRequestHandler>,
) -> ProtocolAgentRuntime {
    let protocol_peer: Arc<dyn ProtocolPeer> = peer;
    let request_handler: Arc<dyn AgentRequestHandler> = handler;
    ProtocolAgentRuntime::new_with_request_handler(
        store.clone(),
        artifacts.clone(),
        store,
        artifacts,
        clock,
        vec![agent_registration(protocol_peer)],
        request_handler,
    )
    .unwrap()
}

fn runtime_with_protocol_peer_and_handler(
    store: Arc<RecordingStore>,
    artifacts: Arc<RecordingArtifacts>,
    clock: Arc<ManualClock>,
    peer: Arc<MultiRunPeer>,
    handler: Arc<RecordingRequestHandler>,
) -> ProtocolAgentRuntime {
    let protocol_peer: Arc<dyn ProtocolPeer> = peer;
    let request_handler: Arc<dyn AgentRequestHandler> = handler;
    ProtocolAgentRuntime::new_with_request_handler(
        store.clone(),
        artifacts.clone(),
        store,
        artifacts,
        clock,
        vec![agent_registration(protocol_peer)],
        request_handler,
    )
    .unwrap()
}

fn runtime_with_protocol_peer(
    store: Arc<RecordingStore>,
    clock: Arc<dyn Clock>,
    peer: Arc<dyn ProtocolPeer>,
) -> ProtocolAgentRuntime {
    let artifacts = Arc::new(RecordingArtifacts::default());
    ProtocolAgentRuntime::new(
        store.clone(),
        artifacts.clone(),
        store,
        artifacts,
        clock,
        vec![agent_registration(peer)],
    )
    .unwrap()
}

fn assert_start_conflict_without_row(
    runtime: &ProtocolAgentRuntime,
    store: &RecordingStore,
    run: &str,
) {
    assert_eq!(
        runtime
            .start_run(run_request(run, None))
            .unwrap_err()
            .safe_classification(),
        SafeErrorClassification::Conflict
    );
    assert!(store.snapshot(run).is_none());
}

fn agent_descriptor() -> AgentDescriptor {
    AgentDescriptor {
        agent_id: "agent-1".to_owned(),
        display_name: "Agent One".to_owned(),
        trust_tier: TrustTier::CoreAdapter,
        manifest_json: br#"{}"#.to_vec(),
        manifest_digest: digest(EMPTY_JSON_DIGEST),
        executable_digest: Some(digest(EXECUTABLE_DIGEST)),
        enabled: true,
        containment_verified: true,
    }
}

fn agent_registration(
    peer: Arc<dyn ProtocolPeer>,
) -> (AgentDescriptor, Sha256Digest, Arc<dyn ProtocolPeer>) {
    (agent_descriptor(), digest(CONNECTION_BINDING_DIGEST), peer)
}

fn peer_descriptor() -> PeerDescriptor {
    PeerDescriptor {
        binding: ConnectionBinding {
            connection_id: "connection-1".to_owned(),
            agent_id: "agent-1".to_owned(),
            manifest_digest: EMPTY_JSON_DIGEST.to_owned(),
            executable_digest: EXECUTABLE_DIGEST.to_owned(),
            trust_tier: ProtocolTrustTier::CoreAdapter,
        },
        protocol_version: "2.0".to_owned(),
        capabilities: ProtocolCapabilities {
            roles: ["reviewer".to_owned()].into_iter().collect(),
            skills: ["testing".to_owned()].into_iter().collect(),
            streaming: true,
            context_query: false,
            tool_requests: false,
            specialist_requests: false,
            max_concurrent_runs: 1,
            max_context_tokens: 1_024,
        },
    }
}

fn run_request(run: &str, supersedes: Option<&str>) -> BoundAgentRunRequest {
    let task_id = task_id("task-1");
    BoundAgentRunRequest {
        run_id: run_id(run),
        task_id: task_id.clone(),
        agent_id: "agent-1".to_owned(),
        role: "reviewer".to_owned(),
        phase: "analysis".to_owned(),
        idempotency_key: format!("task-1:reviewer:{run}"),
        context: BoundEffectiveContext {
            context_package_id: "context-1".to_owned(),
            task_id: task_id.clone(),
            agent_id: "agent-1".to_owned(),
            role: "reviewer".to_owned(),
            objective: "Review the task.".to_owned(),
            manifest_artifact_id: artifact_id("artifact-context-manifest-1"),
            effective_context_artifact_id: artifact_id("artifact-context-1"),
            content_digest: digest(CONTEXT_DIGEST),
            policy_snapshot_digest: digest(POLICY_DIGEST),
            prompt_template_version: "prompt-1".to_owned(),
            retrieval_pipeline_version: "retrieval-1".to_owned(),
            created_at: Timestamp::from_unix_seconds(1),
        },
        run_config: BoundRunConfig {
            run_config_artifact_id: artifact_id(&format!("artifact-run-config-{run}")),
            task_id: task_id.clone(),
            agent_id: "agent-1".to_owned(),
            role: "reviewer".to_owned(),
            context_package_id: "context-1".to_owned(),
            effective_context_artifact_id: artifact_id("artifact-context-1"),
            effective_context_digest: digest(CONTEXT_DIGEST),
            trust_tier: TrustTier::CoreAdapter,
            manifest_digest: digest(EMPTY_JSON_DIGEST),
            executable_digest: Some(digest(EXECUTABLE_DIGEST)),
            contract_version: "2.0".to_owned(),
            adapter_version: "adapter-1".to_owned(),
            provider_id: "provider-1".to_owned(),
            model_id: "model-1".to_owned(),
            generation_parameters: BoundGenerationParameters {
                canonical_json: br#"{}"#.to_vec(),
                digest: digest(EMPTY_JSON_DIGEST),
            },
            prompt_template_version: "prompt-1".to_owned(),
            response_schema_version: "agent-message.v1".to_owned(),
            policy_snapshot_digest: digest(POLICY_DIGEST),
            limits: AgentRunLimits {
                deadline: Timestamp::from_unix_seconds(1_800_000_300),
                max_output_tokens: 8_000,
                max_tool_requests: 8,
                max_context_queries: 0,
                max_specialist_requests: 0,
            },
        },
        connection: BoundAgentConnection {
            connection_id: "connection-1".to_owned(),
            agent_id: "agent-1".to_owned(),
            trust_tier: TrustTier::CoreAdapter,
            manifest_digest: digest(EMPTY_JSON_DIGEST),
            executable_digest: Some(digest(EXECUTABLE_DIGEST)),
            contract_version: "2.0".to_owned(),
            adapter_version: "adapter-1".to_owned(),
            binding_digest: digest(CONNECTION_BINDING_DIGEST),
        },
        supersedes_run_id: supersedes.map(run_id),
    }
}

fn run_request_with_deadline(run: &str, deadline: i64) -> BoundAgentRunRequest {
    let mut request = run_request(run, None);
    request.run_config.limits.deadline = Timestamp::from_unix_seconds(deadline);
    request
}

#[derive(Default)]
struct RecordingRequestHandler {
    context_requests: Mutex<Vec<AgentContextQueryRequest>>,
    specialist_requests: Mutex<Vec<AgentSpecialistRequest>>,
    audits: Mutex<Vec<AgentRequestAudit>>,
    fail_context: bool,
    fail_audit: bool,
    invalid_context_response: bool,
    context_gate: Option<Arc<AcceptanceGate>>,
    specialist_gate: Option<Arc<AcceptanceGate>>,
    specialist_return: Option<Arc<CompletionSignal>>,
    specialist_commits: Mutex<usize>,
    audit_gate: Option<Arc<AcceptanceGate>>,
    audit_commit_gate: Option<Arc<AcceptanceGate>>,
    audit_return: Option<Arc<CompletionSignal>>,
    blocking_query_id: Option<String>,
    leaking_context_response: bool,
    leaking_specialist_response: bool,
    fail_clock_after_audit: Option<Arc<ManualClock>>,
    log: ScriptLog,
}

impl RecordingRequestHandler {
    fn new(log: ScriptLog) -> Self {
        Self {
            log,
            ..Self::default()
        }
    }

    fn failing_context() -> Self {
        Self {
            fail_context: true,
            ..Self::default()
        }
    }

    fn failing_audit() -> Self {
        Self {
            fail_audit: true,
            ..Self::default()
        }
    }

    fn invalid_context_response() -> Self {
        Self {
            invalid_context_response: true,
            ..Self::default()
        }
    }

    fn leaking_context_response() -> Self {
        Self {
            leaking_context_response: true,
            ..Self::default()
        }
    }

    fn leaking_specialist_response() -> Self {
        Self {
            leaking_specialist_response: true,
            ..Self::default()
        }
    }

    fn failing_clock_after_audit(clock: Arc<ManualClock>) -> Self {
        Self {
            fail_clock_after_audit: Some(clock),
            ..Self::default()
        }
    }

    fn blocking_context() -> (Self, Arc<AcceptanceGate>) {
        let gate = Arc::new(AcceptanceGate::new());
        (
            Self {
                context_gate: Some(Arc::clone(&gate)),
                blocking_query_id: Some("query-slow".to_owned()),
                ..Self::default()
            },
            gate,
        )
    }

    fn blocking_specialist() -> (Self, Arc<AcceptanceGate>) {
        let gate = Arc::new(AcceptanceGate::new());
        (
            Self {
                specialist_gate: Some(Arc::clone(&gate)),
                specialist_return: Some(Arc::new(CompletionSignal::default())),
                ..Self::default()
            },
            gate,
        )
    }

    fn blocking_audit() -> (Self, Arc<AcceptanceGate>) {
        let gate = Arc::new(AcceptanceGate::new());
        (
            Self {
                audit_gate: Some(Arc::clone(&gate)),
                audit_return: Some(Arc::new(CompletionSignal::default())),
                ..Self::default()
            },
            gate,
        )
    }

    fn blocking_audit_commit() -> (Self, Arc<AcceptanceGate>) {
        let gate = Arc::new(AcceptanceGate::new());
        (
            Self {
                audit_commit_gate: Some(Arc::clone(&gate)),
                audit_return: Some(Arc::new(CompletionSignal::default())),
                ..Self::default()
            },
            gate,
        )
    }

    fn specialist_commits(&self) -> usize {
        *self.specialist_commits.lock().unwrap()
    }

    fn wait_for_specialist_return(&self, timeout: Duration) -> bool {
        self.specialist_return
            .as_ref()
            .expect("specialist return signal")
            .wait(timeout)
    }

    fn wait_for_audit_return(&self, timeout: Duration) -> bool {
        self.audit_return
            .as_ref()
            .expect("audit return signal")
            .wait(timeout)
    }

    fn context_requests(&self) -> Vec<AgentContextQueryRequest> {
        self.context_requests.lock().unwrap().clone()
    }

    fn specialist_requests(&self) -> Vec<AgentSpecialistRequest> {
        self.specialist_requests.lock().unwrap().clone()
    }

    fn audits(&self) -> Vec<AgentRequestAudit> {
        self.audits.lock().unwrap().clone()
    }
}

impl AgentRequestHandler for RecordingRequestHandler {
    fn query_context(
        &self,
        request: AgentContextQueryRequest,
    ) -> Result<AgentContextQueryResponse, PortError> {
        self.context_requests.lock().unwrap().push(request.clone());
        if self.blocking_query_id.as_deref() == Some(request.query_id.as_str()) {
            let gate = self.context_gate.as_ref().expect("blocking query gate");
            gate.block();
        }
        if self.fail_context {
            return Err(PortError::failure(
                SafeErrorClassification::Internal,
                Retryability::NonRetryable,
            ));
        }
        let mut response = AgentContextQueryResponse {
            run_id: request.run_id,
            task_id: request.task_id,
            query_id: request.query_id.clone(),
            supplement_id: format!("supplement-{}", request.query_id),
            content_digest: digest(CONTEXT_DIGEST),
            item_ids: vec!["item-1".to_owned()],
            token_count: 1,
            provenance: vec!["provenance-1".to_owned()],
            redactions: vec!["redaction-1".to_owned()],
            policy_decision_ids: vec!["policy-1".to_owned()],
            prepared_commit: None,
        };
        if self.invalid_context_response {
            response.task_id = task_id("task-2");
            response.item_ids.push("item-2".to_owned());
        }
        if self.leaking_context_response {
            response.supplement_id = r"C:\private\source.txt".to_owned();
        }
        Ok(response)
    }

    fn request_specialist(
        &self,
        request: AgentSpecialistRequest,
    ) -> Result<AgentSpecialistResponse, PortError> {
        self.specialist_requests
            .lock()
            .unwrap()
            .push(request.clone());
        if let Some(gate) = &self.specialist_gate {
            gate.block();
        }
        if request.cancellation.is_cancelled() {
            self.specialist_return
                .as_ref()
                .expect("specialist return signal")
                .complete();
            return Err(internal_failure());
        }
        *self.specialist_commits.lock().unwrap() += 1;
        let accepted = request.required_context_ids.iter().all(|artifact_id| {
            matches!(
                artifact_id.as_str(),
                "artifact-context-1" | "artifact-context-manifest-1"
            )
        });
        let prepared_commit = accepted
            .then(|| {
                SpecialistRequest::new(
                    &request.request_id,
                    request.task_id.clone(),
                    request.run_id.clone(),
                    &request.capability,
                    &request.reason,
                    request
                        .required_context_ids
                        .iter()
                        .map(|artifact| ArtifactId::new(artifact).unwrap())
                        .collect(),
                    SpecialistBudget::new(request.max_tokens, request.max_tokens, request.deadline)
                        .unwrap(),
                )
                .unwrap()
            })
            .map(|request| AgentSpecialistCommit {
                assignment: DeliberationRunAssignment::new(
                    RunId::new(format!("specialist-{}", request.request_id())).unwrap(),
                    "agent-specialist",
                    AgentFamilyKey::new("fixture-specialist-family").unwrap(),
                    ActorId::new("agent-specialist").unwrap(),
                )
                .unwrap(),
                request,
            });
        let response = AgentSpecialistResponse {
            run_id: request.run_id,
            task_id: request.task_id,
            request_id: request.request_id,
            accepted,
            reason_code: if self.leaking_specialist_response {
                r"C:\private\source.txt"
            } else if accepted {
                "specialist_approved"
            } else {
                "unrequested_context"
            }
            .to_owned(),
            prepared_commit,
        };
        if let Some(returned) = &self.specialist_return {
            returned.complete();
        }
        Ok(response)
    }

    fn persist_audit(&self, audit: AgentRequestAudit) -> Result<(), PortError> {
        if self.fail_audit {
            return Err(PortError::failure(
                SafeErrorClassification::Internal,
                Retryability::NonRetryable,
            ));
        }
        if let Some(gate) = &self.audit_gate {
            gate.block();
        }
        let fence = audit.fence.clone();
        if !fence.try_begin_commit() {
            if let Some(returned) = &self.audit_return {
                returned.complete();
            }
            return Err(internal_failure());
        }
        if let Some(gate) = &self.audit_commit_gate {
            gate.block();
        }
        let mut audits = self.audits.lock().unwrap();
        if audits.iter().any(|existing| {
            existing.run_id == audit.run_id
                && existing.request_id == audit.request_id
                && existing.request_digest == audit.request_digest
        }) {
            fence.finish_commit();
            return Ok(());
        }
        audits.push(audit);
        self.log.lock().unwrap().push("request.effect.committed");
        if let Some(clock) = &self.fail_clock_after_audit {
            clock.fail();
        }
        fence.finish_commit();
        if let Some(returned) = &self.audit_return {
            returned.complete();
        }
        Ok(())
    }
}

#[derive(Default)]
struct RecordingStore {
    runs: Mutex<BTreeMap<String, AgentRunSnapshot>>,
    protocol_requests: Mutex<BTreeMap<(String, String), RecordedProtocolRequest>>,
    protocol_stream_heads: Mutex<BTreeMap<(String, String, String), Sequence>>,
    fail_protocol_complete: Mutex<bool>,
    terminals: Mutex<Vec<AgentRunTerminal>>,
    fail_terminal: Mutex<bool>,
    fail_start: Mutex<Option<StartStoreFailure>>,
    fail_interrupt: Mutex<bool>,
    interrupt_calls: Mutex<usize>,
    interrupt_gate: Mutex<Option<Arc<AcceptanceGate>>>,
    terminal_gate: Mutex<Option<Arc<AcceptanceGate>>>,
    creation_gate: Mutex<Option<(String, Arc<AcceptanceGate>)>>,
    acceptance_gate: Mutex<Option<Arc<AcceptanceGate>>>,
    log: ScriptLog,
}

#[derive(Clone)]
struct RecordedProtocolRequest {
    begin: ProtocolRequestBegin,
    terminal: Option<ProtocolRequestTerminal>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StartStoreFailure {
    Acceptance,
    Running,
}

#[derive(Default)]
struct RecordingArtifacts {
    published: Mutex<Vec<AgentMessageArtifact>>,
    protocol_responses: Mutex<Vec<ProtocolResponseArtifact>>,
    fail_agent_message_publish: Mutex<bool>,
    fail_protocol_response_publish: Mutex<bool>,
    log: ScriptLog,
}

impl RecordingArtifacts {
    fn new(log: ScriptLog) -> Self {
        Self {
            log,
            ..Self::default()
        }
    }

    fn published_contents(&self) -> Vec<Vec<u8>> {
        self.published
            .lock()
            .unwrap()
            .iter()
            .map(|artifact| artifact.content.clone())
            .collect()
    }

    fn fail_publish(&self) {
        *self.fail_agent_message_publish.lock().unwrap() = true;
    }

    fn allow_publish(&self) {
        *self.fail_agent_message_publish.lock().unwrap() = false;
    }

    fn fail_protocol_response_publish(&self) {
        *self.fail_protocol_response_publish.lock().unwrap() = true;
    }

    fn allow_protocol_response_publish(&self) {
        *self.fail_protocol_response_publish.lock().unwrap() = false;
    }
}

impl AgentArtifactStore for RecordingArtifacts {
    fn load_effective_context(
        &self,
        context: &BoundEffectiveContext,
    ) -> Result<Vec<u8>, PortError> {
        assert_eq!(
            context.effective_context_artifact_id.as_str(),
            "artifact-context-1"
        );
        assert_eq!(context.content_digest.as_str(), CONTEXT_DIGEST);
        Ok(CONTEXT_BYTES.to_vec())
    }

    fn publish_agent_message(
        &self,
        artifact: &AgentMessageArtifact,
    ) -> Result<ArtifactId, PortError> {
        if *self.fail_agent_message_publish.lock().unwrap() {
            return Err(internal_failure());
        }
        self.published.lock().unwrap().push(artifact.clone());
        self.log.lock().unwrap().push("artifact.message.published");
        ArtifactId::new(format!("artifact-{}", artifact.message_id)).map_err(|_| invalid_input())
    }
}

impl ProtocolResponseArtifactPublisher for RecordingArtifacts {
    fn publish_protocol_response(
        &self,
        _begin: &ProtocolRequestBegin,
        response: &ProtocolResponseArtifact,
    ) -> Result<ProtocolResponseArtifact, PortError> {
        if *self.fail_protocol_response_publish.lock().unwrap() {
            return Err(internal_failure());
        }
        let mut responses = self.protocol_responses.lock().unwrap();
        if let Some(existing) = responses
            .iter()
            .find(|existing| existing.artifact_id() == response.artifact_id())
        {
            return Ok(existing.clone());
        }
        responses.push(response.clone());
        self.log.lock().unwrap().push("protocol.response.published");
        Ok(response.clone())
    }
}

impl RecordingStore {
    fn new(log: ScriptLog) -> Self {
        Self {
            log,
            ..Self::default()
        }
    }

    fn snapshot(&self, run_id: &str) -> Option<AgentRunSnapshot> {
        self.runs.lock().unwrap().get(run_id).cloned()
    }

    fn status(&self, run_id: &str) -> Option<AgentRunStatus> {
        self.snapshot(run_id).map(|run| run.status)
    }

    fn terminal_count(&self) -> usize {
        self.terminals.lock().unwrap().len()
    }

    fn protocol_request_is_pending(&self, connection_id: &str, request_id: &str) -> bool {
        self.protocol_requests
            .lock()
            .unwrap()
            .get(&(connection_id.to_owned(), request_id.to_owned()))
            .is_some_and(|request| request.terminal.is_none())
    }

    fn mark_protocol_request_pending(&self, connection_id: &str, request_id: &str) {
        self.protocol_requests
            .lock()
            .unwrap()
            .get_mut(&(connection_id.to_owned(), request_id.to_owned()))
            .expect("recorded protocol request")
            .terminal = None;
    }

    fn fail_terminal(&self) {
        *self.fail_terminal.lock().unwrap() = true;
    }

    fn allow_terminal(&self) {
        *self.fail_terminal.lock().unwrap() = false;
    }

    fn fail_protocol_complete(&self) {
        *self.fail_protocol_complete.lock().unwrap() = true;
    }

    fn allow_protocol_complete(&self) {
        *self.fail_protocol_complete.lock().unwrap() = false;
    }

    fn terminal_time(&self, run_id: &str) -> Option<Timestamp> {
        self.terminals
            .lock()
            .unwrap()
            .iter()
            .find(|terminal| terminal.run_id.as_str() == run_id)
            .and_then(|terminal| terminal.core_received_at)
    }

    fn fail_start_at(&self, failure: StartStoreFailure) {
        *self.fail_start.lock().unwrap() = Some(failure);
    }

    fn allow_start(&self) {
        *self.fail_start.lock().unwrap() = None;
    }

    fn fail_interrupt(&self) {
        *self.fail_interrupt.lock().unwrap() = true;
    }

    fn allow_interrupt(&self) {
        *self.fail_interrupt.lock().unwrap() = false;
    }

    fn interrupt_count(&self) -> usize {
        *self.interrupt_calls.lock().unwrap()
    }

    fn block_interrupt(&self) -> Arc<AcceptanceGate> {
        let gate = Arc::new(AcceptanceGate::new());
        *self.interrupt_gate.lock().unwrap() = Some(Arc::clone(&gate));
        gate
    }

    fn block_terminal(&self) -> Arc<AcceptanceGate> {
        let gate = Arc::new(AcceptanceGate::new());
        *self.terminal_gate.lock().unwrap() = Some(Arc::clone(&gate));
        gate
    }

    fn block_acceptance(&self) -> Arc<AcceptanceGate> {
        let gate = Arc::new(AcceptanceGate::new());
        *self.acceptance_gate.lock().unwrap() = Some(Arc::clone(&gate));
        gate
    }

    fn block_creation(&self, run_id: &str) -> Arc<AcceptanceGate> {
        let gate = Arc::new(AcceptanceGate::new());
        *self.creation_gate.lock().unwrap() = Some((run_id.to_owned(), Arc::clone(&gate)));
        gate
    }
}

impl AgentRunStore for RecordingStore {
    fn register_descriptor(&self, descriptor: &AgentDescriptor) -> Result<(), PortError> {
        descriptor.validate().map_err(|_| invalid_input())
    }

    fn create_bound_run(
        &self,
        request: &BoundAgentRunRequest,
    ) -> Result<AgentRunSnapshot, PortError> {
        let creation_gate = self
            .creation_gate
            .lock()
            .unwrap()
            .as_ref()
            .filter(|(run_id, _)| run_id == request.run_id.as_str())
            .cloned();
        if let Some((_, gate)) = creation_gate {
            gate.block();
        }
        if let Some(existing) = self.runs.lock().unwrap().get(request.run_id.as_str()).cloned() {
            if existing.request == *request {
                return Ok(existing);
            }
            return Err(protocol_conflict());
        }
        let snapshot = AgentRunSnapshot::created(request.clone()).map_err(|_| invalid_input())?;
        self.runs
            .lock()
            .unwrap()
            .insert(request.run_id.as_str().to_owned(), snapshot.clone());
        Ok(snapshot)
    }

    fn accept_run(&self, run_id: &RunId, accepted_at: &str) -> Result<(), PortError> {
        if *self.fail_start.lock().unwrap() == Some(StartStoreFailure::Acceptance) {
            return Err(storage_full());
        }
        if let Some(gate) = self.acceptance_gate.lock().unwrap().clone() {
            gate.block();
        }
        transition(self, run_id, AgentRunStatus::Accepted, accepted_at)
    }

    fn mark_running(&self, run_id: &RunId, started_at: &str) -> Result<(), PortError> {
        if *self.fail_start.lock().unwrap() == Some(StartStoreFailure::Running) {
            return Err(storage_full());
        }
        transition(self, run_id, AgentRunStatus::Running, started_at)
    }

    fn persist_terminal(&self, terminal: &AgentRunTerminal) -> Result<(), PortError> {
        if *self.fail_terminal.lock().unwrap() {
            return Err(PortError::failure(
                SafeErrorClassification::StorageFull,
                Retryability::Retryable,
            ));
        }
        if let Some(gate) = self.terminal_gate.lock().unwrap().clone() {
            gate.block();
        }
        terminal.validate().map_err(|_| invalid_input())?;
        let mut runs = self.runs.lock().unwrap();
        let run = runs
            .get_mut(terminal.run_id.as_str())
            .ok_or_else(invalid_input)?;
        run.transition_to(terminal.status, terminal.core_received_at.unwrap())
            .map_err(|_| invalid_input())?;
        self.terminals.lock().unwrap().push(terminal.clone());
        self.log.lock().unwrap().push("store.terminal.committed");
        Ok(())
    }

    fn interrupt_connection(
        &self,
        connection_digest: &str,
        at: &str,
    ) -> Result<Vec<RunId>, PortError> {
        *self.interrupt_calls.lock().unwrap() += 1;
        if let Some(gate) = self.interrupt_gate.lock().unwrap().clone() {
            gate.block();
        }
        if *self.fail_interrupt.lock().unwrap() {
            return Err(storage_full());
        }
        let at = parse_timestamp(at)?;
        let mut interrupted = Vec::new();
        for run in self.runs.lock().unwrap().values_mut() {
            if run.request.connection.binding_digest.as_str() == connection_digest
                && !run.status.is_terminal()
            {
                run.transition_to(AgentRunStatus::Interrupted, at)
                    .map_err(|_| invalid_input())?;
                interrupted.push(run.request.run_id.clone());
            }
        }
        Ok(interrupted)
    }

    fn load_run(&self, run_id: &RunId) -> Result<Option<AgentRunSnapshot>, PortError> {
        Ok(self.snapshot(run_id.as_str()))
    }
}

impl ProtocolRequestStore for RecordingStore {
    fn begin(&self, begin: &ProtocolRequestBegin) -> Result<ProtocolRequestBeginResult, PortError> {
        begin.validate()?;
        let key = (
            begin.identity().connection_id().to_owned(),
            begin.identity().request_id().to_owned(),
        );
        let mut requests = self.protocol_requests.lock().unwrap();
        let Some(existing) = requests.get(&key) else {
            requests.insert(
                key,
                RecordedProtocolRequest {
                    begin: begin.clone(),
                    terminal: None,
                },
            );
            return Ok(ProtocolRequestBeginResult::Begun);
        };
        if existing.begin.identity() != begin.identity() {
            return Err(protocol_conflict());
        }
        Ok(match &existing.terminal {
            Some(terminal) => ProtocolRequestBeginResult::Replayed(terminal.clone()),
            None => ProtocolRequestBeginResult::Pending,
        })
    }

    fn load(
        &self,
        identity: &ProtocolRequestIdentity,
    ) -> Result<Option<ProtocolRequestRecord>, PortError> {
        identity.validate()?;
        let key = (
            identity.connection_id().to_owned(),
            identity.request_id().to_owned(),
        );
        let requests = self.protocol_requests.lock().unwrap();
        let Some(existing) = requests.get(&key) else {
            return Ok(None);
        };
        if existing.begin.identity() != identity {
            return Err(protocol_conflict());
        }
        match &existing.terminal {
            Some(terminal) => {
                ProtocolRequestRecord::terminal(existing.begin.clone(), terminal.clone()).map(Some)
            }
            None => Ok(Some(ProtocolRequestRecord::pending(existing.begin.clone()))),
        }
    }

    fn complete(
        &self,
        terminal: &ProtocolRequestTerminal,
    ) -> Result<ProtocolRequestTerminal, PortError> {
        terminal.validate()?;
        if *self.fail_protocol_complete.lock().unwrap() {
            return Err(storage_full());
        }
        let key = (
            terminal.identity().connection_id().to_owned(),
            terminal.identity().request_id().to_owned(),
        );
        let mut requests = self.protocol_requests.lock().unwrap();
        let existing = requests.get_mut(&key).ok_or_else(invalid_input)?;
        if existing.begin.identity() != terminal.identity() {
            return Err(protocol_conflict());
        }
        match &existing.terminal {
            Some(existing_terminal) if existing_terminal == terminal => {
                Ok(existing_terminal.clone())
            }
            Some(_) => Err(protocol_conflict()),
            None => {
                existing.terminal = Some(terminal.clone());
                self.log.lock().unwrap().push("protocol.response.completed");
                Ok(terminal.clone())
            }
        }
    }

    fn load_stream_head(
        &self,
        stream: &ProtocolStreamIdentity,
    ) -> Result<Option<Sequence>, PortError> {
        stream.validate()?;
        Ok(self
            .protocol_stream_heads
            .lock()
            .unwrap()
            .get(&(
                stream.connection_id().to_owned(),
                stream.run_id().as_str().to_owned(),
                stream.channel().to_owned(),
            ))
            .copied())
    }

    fn advance_stream(&self, advance: &ProtocolStreamAdvance) -> Result<(), PortError> {
        advance.validate()?;
        let key = (
            advance.connection_id().to_owned(),
            advance.run_id().as_str().to_owned(),
            advance.channel().to_owned(),
        );
        let mut heads = self.protocol_stream_heads.lock().unwrap();
        match heads.get(&key).copied() {
            None if advance.sequence().get() == 1 => {
                heads.insert(key, advance.sequence());
                Ok(())
            }
            Some(current) if current == advance.sequence() => Ok(()),
            Some(current) if current.get().checked_add(1) == Some(advance.sequence().get()) => {
                heads.insert(key, advance.sequence());
                Ok(())
            }
            _ => Err(protocol_conflict()),
        }
    }
}

struct ManualClock {
    seconds: Mutex<i64>,
    fail: Mutex<bool>,
    next_call_gate: Mutex<Option<Arc<AcceptanceGate>>>,
}

impl ManualClock {
    fn new(seconds: i64) -> Self {
        Self {
            seconds: Mutex::new(seconds),
            fail: Mutex::new(false),
            next_call_gate: Mutex::new(None),
        }
    }

    fn advance(&self, seconds: i64) {
        *self.seconds.lock().unwrap() += seconds;
    }

    fn fail(&self) {
        *self.fail.lock().unwrap() = true;
    }

    fn recover(&self) {
        *self.fail.lock().unwrap() = false;
    }

    fn block_next_call(&self) -> Arc<AcceptanceGate> {
        let gate = Arc::new(AcceptanceGate::new());
        *self.next_call_gate.lock().unwrap() = Some(Arc::clone(&gate));
        gate
    }
}

impl Clock for ManualClock {
    fn now_utc(&self) -> Result<String, PortError> {
        let gate = self.next_call_gate.lock().unwrap().take();
        if let Some(gate) = gate {
            gate.block();
        }
        if *self.fail.lock().unwrap() {
            return Err(internal_failure());
        }
        Ok(Utc
            .timestamp_opt(*self.seconds.lock().unwrap(), 0)
            .single()
            .unwrap()
            .to_rfc3339())
    }
}

struct AdvancingClock {
    next_seconds: Mutex<i64>,
    calls: Mutex<usize>,
    fail_on_call: Mutex<Option<usize>>,
}

impl AdvancingClock {
    fn new(seconds: i64) -> Self {
        Self {
            next_seconds: Mutex::new(seconds),
            calls: Mutex::new(0),
            fail_on_call: Mutex::new(None),
        }
    }

    fn fail_on_call(&self, call: usize) {
        *self.fail_on_call.lock().unwrap() = Some(call);
    }

    fn recover(&self) {
        *self.fail_on_call.lock().unwrap() = None;
    }
}

impl Clock for AdvancingClock {
    fn now_utc(&self) -> Result<String, PortError> {
        let mut calls = self.calls.lock().unwrap();
        *calls += 1;
        if *self.fail_on_call.lock().unwrap() == Some(*calls) {
            return Err(internal_failure());
        }
        let mut seconds = self.next_seconds.lock().unwrap();
        let current = *seconds;
        *seconds += 1;
        Ok(Utc.timestamp_opt(current, 0).single().unwrap().to_rfc3339())
    }
}

fn transition(
    store: &RecordingStore,
    run_id: &RunId,
    status: AgentRunStatus,
    at: &str,
) -> Result<(), PortError> {
    store
        .runs
        .lock()
        .unwrap()
        .get_mut(run_id.as_str())
        .ok_or_else(invalid_input)?
        .transition_to(status, parse_timestamp(at)?)
        .map_err(|_| invalid_input())
}

fn parse_timestamp(value: &str) -> Result<Timestamp, PortError> {
    let parsed = chrono::DateTime::parse_from_rfc3339(value).map_err(|_| invalid_input())?;
    Ok(Timestamp::from_unix_seconds(parsed.timestamp()))
}

fn invalid_input() -> PortError {
    PortError::failure(
        SafeErrorClassification::InvalidInput,
        Retryability::NonRetryable,
    )
}

fn storage_full() -> PortError {
    PortError::failure(
        SafeErrorClassification::StorageFull,
        Retryability::Retryable,
    )
}

fn protocol_conflict() -> PortError {
    PortError::failure(
        SafeErrorClassification::Conflict,
        Retryability::NonRetryable,
    )
}

fn internal_failure() -> PortError {
    PortError::failure(
        SafeErrorClassification::Internal,
        Retryability::NonRetryable,
    )
}

fn script_log() -> ScriptLog {
    Arc::new(Mutex::new(Vec::new()))
}

fn artifact_id(value: &str) -> ArtifactId {
    ArtifactId::new(value).unwrap()
}

fn digest(value: &str) -> Sha256Digest {
    Sha256Digest::new(value).unwrap()
}

fn run_id(value: &str) -> RunId {
    RunId::new(value).unwrap()
}

fn task_id(value: &str) -> TaskId {
    TaskId::new(value).unwrap()
}
