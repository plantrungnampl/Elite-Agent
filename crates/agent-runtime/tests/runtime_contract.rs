use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
};

use chrono::{TimeZone, Utc};
use local_agent_terminal_agent_protocol::{
    ConnectionBinding, PeerDescriptor, ProtocolCapabilities, ProtocolError, ProtocolPeer,
    ProtocolTrustTier,
};
use local_agent_terminal_agent_runtime::{
    MaliciousScript, ProtocolAgentRuntime, Script, ScriptLog, ScriptedPeer,
    DEFAULT_HEARTBEAT_TIMEOUT_SECS, DEFAULT_RUN_DEADLINE_SECS,
};
use local_agent_terminal_application::{
    AgentArtifactStore, AgentMessageArtifact, AgentRunStore, AgentRuntime, Clock, PortError,
    Retryability, SafeErrorClassification,
};
use local_agent_terminal_domain::{
    AgentDescriptor, AgentRunLimits, AgentRunSnapshot, AgentRunStatus, AgentRunTerminal,
    ArtifactId, BoundAgentConnection, BoundAgentRunRequest, BoundEffectiveContext,
    BoundGenerationParameters, BoundRunConfig, CancelAgentRun, RunId, Sha256Digest, TaskId,
    Timestamp, TrustTier,
};

const EMPTY_JSON_DIGEST: &str =
    "sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a";
const CONNECTION_BINDING_DIGEST: &str =
    "sha256:6e171d4e7a1d7b7db1c14807e8a2a5cc9093eac495d66a2ca76439264d09b7d5";
const EXECUTABLE_DIGEST: &str =
    "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const CONTEXT_DIGEST: &str =
    "sha256:7ce2a62fec3ddf55f1cede952bdcd4170bb0b01fa53da3ded734e531337d2b58";
const CONTEXT_BYTES: &[u8] = b"exact context";
const POLICY_DIGEST: &str =
    "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";

#[test]
fn start_returns_after_durable_acceptance_and_scripted_output_is_deterministic() {
    let log = script_log();
    let store = Arc::new(RecordingStore::new(Arc::clone(&log)));
    let artifacts = Arc::new(RecordingArtifacts::new(Arc::clone(&log)));
    let clock = Arc::new(ManualClock::new(1_800_000_000));
    let peer = Arc::new(ScriptedPeer::with_log(
        Script::Proposer,
        peer_descriptor(),
        Arc::clone(&log),
    ));
    let runtime = runtime_with_artifacts(
        Arc::clone(&store),
        Arc::clone(&artifacts),
        Arc::clone(&clock),
        Arc::clone(&peer),
    );

    let receipt = runtime.start_run(run_request("run-1", None)).unwrap();

    assert_eq!(receipt.run_id, run_id("run-1"));
    assert_eq!(store.status("run-1"), Some(AgentRunStatus::Running));
    assert_eq!(store.terminal_count(), 0);

    peer.drive().unwrap();

    assert_eq!(store.status("run-1"), Some(AgentRunStatus::Succeeded));
    assert_eq!(peer.duplicate_stream_deltas(), 1);
    assert_eq!(peer.terminal_acknowledgements(), 1);
    assert_eq!(
        peer.outputs(),
        vec![format!("proposer:core:2:{CONTEXT_DIGEST}")]
    );
    assert_eq!(
        log.lock().unwrap().as_slice(),
        [
            "artifact.message.published",
            "store.terminal.committed",
            "peer.terminal.acknowledged"
        ]
    );
    assert_eq!(
        artifacts.published_contents(),
        vec![peer.outputs()[0].as_bytes()]
    );
}

#[test]
fn peer_receives_every_bound_execution_field_and_wire_limit_exactly() {
    let store = Arc::new(RecordingStore::default());
    let artifacts = Arc::new(RecordingArtifacts::default());
    let clock = Arc::new(ManualClock::new(1_800_000_000));
    let peer = Arc::new(ScriptedPeer::new(Script::Slow, peer_descriptor()));
    let runtime = runtime_with_artifacts(store, artifacts, clock, Arc::clone(&peer));

    runtime
        .start_run(run_request("run-2", Some("run-1")))
        .unwrap();

    let starts = peer.start_requests();
    let start = starts.first().unwrap();
    let binding = start.execution_binding();
    assert_eq!(binding.provider_id, "provider-1");
    assert_eq!(binding.model_id, "model-1");
    assert_eq!(binding.generation_parameters, br#"{}"#);
    assert_eq!(binding.generation_parameters_digest, EMPTY_JSON_DIGEST);
    assert_eq!(binding.effective_context, CONTEXT_BYTES);
    assert_eq!(binding.effective_context_artifact_id, "artifact-context-1");
    assert_eq!(binding.effective_context_digest, CONTEXT_DIGEST);
    assert_eq!(binding.supersedes_run_id.as_deref(), Some("run-1"));

    let wire = serde_json::to_value(start.as_frame()).unwrap();
    assert_eq!(wire.pointer("/params/supersedesRunId").unwrap(), "run-1");
    assert_eq!(
        wire.pointer("/params/limits/deadline").unwrap(),
        "2027-01-15T08:05:00Z"
    );
    assert_eq!(
        wire.pointer("/params/limits/maxOutputTokens").unwrap(),
        8_000
    );
    assert_eq!(wire.pointer("/params/limits/maxToolRequests").unwrap(), 8);
}

#[test]
fn proposer_critic_and_verifier_outputs_are_stable_for_the_same_bound_input() {
    for (script, role) in [
        (Script::Proposer, "proposer"),
        (Script::Critic, "critic"),
        (Script::Verifier, "verifier"),
    ] {
        let store = Arc::new(RecordingStore::default());
        let clock = Arc::new(ManualClock::new(1_800_000_000));
        let peer = Arc::new(ScriptedPeer::new(script, peer_descriptor()));
        let runtime = runtime(store, clock, Arc::clone(&peer));
        runtime.start_run(run_request("run-1", None)).unwrap();

        peer.drive().unwrap();

        assert_eq!(
            peer.outputs(),
            vec![format!("{role}:core:2:{CONTEXT_DIGEST}")]
        );
    }
}

#[test]
fn disabled_descriptor_is_listed_but_never_dispatched() {
    let store = Arc::new(RecordingStore::default());
    let artifacts = Arc::new(RecordingArtifacts::default());
    let clock = Arc::new(ManualClock::new(1_800_000_000));
    let peer = Arc::new(ScriptedPeer::new(Script::Slow, peer_descriptor()));
    let protocol_peer: Arc<dyn ProtocolPeer> = peer.clone();
    let mut descriptor = agent_descriptor();
    descriptor.enabled = false;
    let runtime = ProtocolAgentRuntime::new(
        store,
        artifacts,
        clock,
        vec![(descriptor.clone(), protocol_peer)],
    )
    .unwrap();

    assert_eq!(runtime.list_agents().unwrap(), vec![descriptor]);
    let error = runtime
        .start_run(run_request("run-disabled", None))
        .unwrap_err();
    assert_eq!(
        error.safe_classification(),
        SafeErrorClassification::PermissionDenied
    );
    assert!(peer.start_requests().is_empty());
}

#[test]
fn duplicate_peer_connection_ids_are_rejected_at_construction() {
    let store = Arc::new(RecordingStore::default());
    let artifacts = Arc::new(RecordingArtifacts::default());
    let clock = Arc::new(ManualClock::new(1_800_000_000));
    let first: Arc<dyn ProtocolPeer> = Arc::new(ScriptedPeer::new(Script::Slow, peer_descriptor()));
    let mut second_descriptor = agent_descriptor();
    second_descriptor.agent_id = "agent-2".to_owned();
    let mut second_peer_descriptor = peer_descriptor();
    second_peer_descriptor.binding.agent_id = "agent-2".to_owned();
    let second: Arc<dyn ProtocolPeer> =
        Arc::new(ScriptedPeer::new(Script::Slow, second_peer_descriptor));

    let result = ProtocolAgentRuntime::new(
        store,
        artifacts,
        clock,
        vec![(agent_descriptor(), first), (second_descriptor, second)],
    );

    let error = match result {
        Ok(_) => panic!("duplicate connection IDs must be rejected"),
        Err(error) => error,
    };
    assert_eq!(
        error.safe_classification(),
        SafeErrorClassification::Conflict
    );
}

#[test]
fn terminal_store_failure_is_never_acknowledged() {
    let log = script_log();
    let store = Arc::new(RecordingStore::new(Arc::clone(&log)));
    let clock = Arc::new(ManualClock::new(1_800_000_000));
    let peer = Arc::new(ScriptedPeer::with_log(
        Script::Verifier,
        peer_descriptor(),
        Arc::clone(&log),
    ));
    let runtime = runtime(Arc::clone(&store), clock, Arc::clone(&peer));
    runtime.start_run(run_request("run-1", None)).unwrap();
    store.fail_terminal();

    assert_eq!(peer.drive(), Err(ProtocolError::InternalAgentFailure));
    assert_eq!(peer.terminal_acknowledgements(), 0);
    assert_eq!(store.status("run-1"), Some(AgentRunStatus::Running));
}

#[test]
fn terminal_artifact_publication_failure_is_never_persisted_or_acknowledged() {
    let store = Arc::new(RecordingStore::default());
    let artifacts = Arc::new(RecordingArtifacts::default());
    let clock = Arc::new(ManualClock::new(1_800_000_000));
    let peer = Arc::new(ScriptedPeer::new(Script::Verifier, peer_descriptor()));
    let runtime = runtime_with_artifacts(
        Arc::clone(&store),
        Arc::clone(&artifacts),
        clock,
        Arc::clone(&peer),
    );
    runtime.start_run(run_request("run-1", None)).unwrap();
    artifacts.fail_publish();

    assert_eq!(peer.drive(), Err(ProtocolError::InternalAgentFailure));
    assert_eq!(peer.terminal_acknowledgements(), 0);
    assert_eq!(store.terminal_count(), 0);
    assert_eq!(store.status("run-1"), Some(AgentRunStatus::Running));
}

#[test]
fn post_start_store_failures_cancel_shutdown_and_persist_interruption() {
    for failure in [StartStoreFailure::Acceptance, StartStoreFailure::Running] {
        let store = Arc::new(RecordingStore::default());
        store.fail_start_at(failure);
        let artifacts = Arc::new(RecordingArtifacts::default());
        let clock = Arc::new(ManualClock::new(1_800_000_000));
        let peer = Arc::new(ScriptedPeer::new(Script::Slow, peer_descriptor()));
        let runtime =
            runtime_with_artifacts(Arc::clone(&store), artifacts, clock, Arc::clone(&peer));

        let error = runtime.start_run(run_request("run-1", None)).unwrap_err();

        assert_eq!(
            error.safe_classification(),
            SafeErrorClassification::StorageFull
        );
        assert_eq!(store.status("run-1"), Some(AgentRunStatus::Interrupted));
        assert_eq!(peer.cancel_count(), 1);
        assert!(peer.was_shutdown());
    }
}

#[test]
fn compensation_failure_preserves_the_original_start_failure() {
    let store = Arc::new(RecordingStore::default());
    store.fail_start_at(StartStoreFailure::Acceptance);
    let artifacts = Arc::new(RecordingArtifacts::default());
    artifacts.fail_publish();
    let clock = Arc::new(ManualClock::new(1_800_000_000));
    let peer = Arc::new(ScriptedPeer::new(Script::Slow, peer_descriptor()));
    let runtime = runtime_with_artifacts(store, artifacts, clock, Arc::clone(&peer));

    let error = runtime.start_run(run_request("run-1", None)).unwrap_err();

    assert_eq!(
        error.safe_classification(),
        SafeErrorClassification::StorageFull
    );
    assert_eq!(peer.cancel_count(), 1);
    assert!(peer.was_shutdown());
}

#[test]
fn duplicate_and_conflicting_terminal_requests_commit_one_result() {
    for malicious in [
        MaliciousScript::DuplicateTerminal,
        MaliciousScript::ConflictingTerminal,
    ] {
        let store = Arc::new(RecordingStore::default());
        let clock = Arc::new(ManualClock::new(1_800_000_000));
        let peer = Arc::new(ScriptedPeer::new(
            Script::Malicious(malicious),
            peer_descriptor(),
        ));
        let runtime = runtime(Arc::clone(&store), clock, Arc::clone(&peer));
        runtime.start_run(run_request("run-1", None)).unwrap();

        peer.drive().unwrap();

        assert_eq!(store.terminal_count(), 1);
        assert_eq!(peer.terminal_acknowledgements(), 1);
    }
}

#[test]
fn every_agent_originated_request_receives_one_typed_response() {
    let store = Arc::new(RecordingStore::default());
    let artifacts = Arc::new(RecordingArtifacts::default());
    let clock = Arc::new(ManualClock::new(1_800_000_000));
    let mut descriptor = peer_descriptor();
    descriptor.capabilities.context_query = true;
    descriptor.capabilities.tool_requests = true;
    descriptor.capabilities.specialist_requests = true;
    let peer = Arc::new(ScriptedPeer::new(Script::Requesting, descriptor));
    let runtime = runtime_with_artifacts(store, artifacts, clock, Arc::clone(&peer));
    runtime.start_run(run_request("run-1", None)).unwrap();

    peer.drive().unwrap();

    let responses = peer.request_responses();
    assert_eq!(responses.len(), 3);
    let values = responses
        .iter()
        .map(|response| serde_json::to_value(response).unwrap())
        .collect::<Vec<_>>();
    assert_eq!(
        values
            .iter()
            .map(|value| value.pointer("/id").unwrap().as_str().unwrap())
            .collect::<Vec<_>>(),
        ["agent:context-1", "agent:tool-1", "agent:specialist-1"]
    );
    assert!(values.iter().all(|value| {
        value
            .pointer("/error/data/category")
            .and_then(serde_json::Value::as_str)
            == Some("policy_denied")
    }));
}

#[test]
fn output_limit_persists_failure_and_triggers_peer_cancellation() {
    let store = Arc::new(RecordingStore::default());
    let clock = Arc::new(ManualClock::new(1_800_000_000));
    let peer = Arc::new(ScriptedPeer::new(
        Script::Malicious(MaliciousScript::OversizeOutput),
        peer_descriptor(),
    ));
    let runtime = runtime(Arc::clone(&store), clock, Arc::clone(&peer));
    runtime.start_run(run_request("run-1", None)).unwrap();

    peer.drive().unwrap();

    assert_eq!(store.status("run-1"), Some(AgentRunStatus::Failed));
    assert_eq!(peer.cancel_count(), 1);
}

#[test]
fn cooperative_cancellation_is_terminal_before_the_receipt_returns() {
    let store = Arc::new(RecordingStore::default());
    let clock = Arc::new(ManualClock::new(1_800_000_000));
    let peer = Arc::new(ScriptedPeer::new(Script::Critic, peer_descriptor()));
    let runtime = runtime(Arc::clone(&store), clock, Arc::clone(&peer));
    runtime.start_run(run_request("run-1", None)).unwrap();

    let receipt = runtime
        .cancel(CancelAgentRun {
            run_id: run_id("run-1"),
            reason: "user_cancelled".to_owned(),
            deadline_ms: 5_000,
        })
        .unwrap();

    assert_eq!(receipt.run_id, run_id("run-1"));
    assert_eq!(
        store.status("run-1"),
        Some(AgentRunStatus::CancelledCleanly)
    );
}

#[test]
fn cancellation_and_run_deadlines_are_classified_as_terminated() {
    for cancellation_deadline in [true, false] {
        let store = Arc::new(RecordingStore::default());
        let clock = Arc::new(ManualClock::new(1_800_000_000));
        let peer = Arc::new(ScriptedPeer::new(Script::Slow, peer_descriptor()));
        let runtime = runtime(Arc::clone(&store), Arc::clone(&clock), peer);
        runtime.start_run(run_request("run-1", None)).unwrap();
        if cancellation_deadline {
            runtime
                .cancel(CancelAgentRun {
                    run_id: run_id("run-1"),
                    reason: "user_cancelled".to_owned(),
                    deadline_ms: 1_000,
                })
                .unwrap();
            clock.advance(1);
        } else {
            clock.advance(DEFAULT_RUN_DEADLINE_SECS);
        }

        runtime.check_timeouts().unwrap();

        assert_eq!(store.status("run-1"), Some(AgentRunStatus::Terminated));
    }
}

#[test]
fn heartbeat_timeout_and_crash_interrupt_active_runs() {
    for script in [Script::Slow, Script::Crashing] {
        let store = Arc::new(RecordingStore::default());
        let clock = Arc::new(ManualClock::new(1_800_000_000));
        let peer = Arc::new(ScriptedPeer::new(script, peer_descriptor()));
        let runtime = runtime(Arc::clone(&store), Arc::clone(&clock), Arc::clone(&peer));
        runtime.start_run(run_request("run-1", None)).unwrap();
        if script == Script::Crashing {
            peer.drive().unwrap();
        } else {
            clock.advance(DEFAULT_HEARTBEAT_TIMEOUT_SECS);
            runtime.check_timeouts().unwrap();
        }

        assert_eq!(store.status("run-1"), Some(AgentRunStatus::Interrupted));
    }
}

#[test]
fn retry_uses_a_new_run_and_exact_supersession_binding() {
    let store = Arc::new(RecordingStore::default());
    let clock = Arc::new(ManualClock::new(1_800_000_000));
    let peer = Arc::new(ScriptedPeer::new(Script::Crashing, peer_descriptor()));
    let runtime = runtime(Arc::clone(&store), clock, Arc::clone(&peer));
    runtime.start_run(run_request("run-1", None)).unwrap();
    peer.drive().unwrap();

    runtime
        .start_run(run_request("run-2", Some("run-1")))
        .unwrap();

    assert_eq!(
        store.snapshot("run-2").unwrap().request.supersedes_run_id,
        Some(run_id("run-1"))
    );
}

#[test]
fn shutdown_interrupts_active_runs_before_reporting_completion() {
    let store = Arc::new(RecordingStore::default());
    let clock = Arc::new(ManualClock::new(1_800_000_000));
    let peer = Arc::new(ScriptedPeer::new(Script::Slow, peer_descriptor()));
    let runtime = runtime(Arc::clone(&store), clock, Arc::clone(&peer));
    runtime.start_run(run_request("run-1", None)).unwrap();

    runtime.shutdown().unwrap();

    assert!(peer.was_shutdown());
    assert_eq!(store.status("run-1"), Some(AgentRunStatus::Interrupted));
}

#[test]
fn every_hostile_peer_failure_terminates_the_run() {
    let scripts = [
        MaliciousScript::MalformedFrame,
        MaliciousScript::WrongConnection,
        MaliciousScript::WrongRun,
        MaliciousScript::SequenceGap,
        MaliciousScript::OversizeFrame,
    ];
    for malicious in scripts {
        let store = Arc::new(RecordingStore::default());
        let clock = Arc::new(ManualClock::new(1_800_000_000));
        let peer = Arc::new(ScriptedPeer::new(
            Script::Malicious(malicious),
            peer_descriptor(),
        ));
        let runtime = runtime(Arc::clone(&store), clock, Arc::clone(&peer));
        runtime.start_run(run_request("run-1", None)).unwrap();

        peer.drive().unwrap();

        assert!(store.status("run-1").unwrap().is_terminal());
    }
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
        store,
        artifacts,
        clock,
        vec![(agent_descriptor(), protocol_peer)],
    )
    .unwrap()
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

fn peer_descriptor() -> PeerDescriptor {
    PeerDescriptor {
        binding: ConnectionBinding {
            connection_id: "connection-1".to_owned(),
            agent_id: "agent-1".to_owned(),
            manifest_digest: EMPTY_JSON_DIGEST.to_owned(),
            executable_digest: EXECUTABLE_DIGEST.to_owned(),
            trust_tier: ProtocolTrustTier::CoreAdapter,
        },
        protocol_version: "1.0".to_owned(),
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
            contract_version: "1.0".to_owned(),
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
            },
        },
        connection: BoundAgentConnection {
            connection_id: "connection-1".to_owned(),
            agent_id: "agent-1".to_owned(),
            trust_tier: TrustTier::CoreAdapter,
            manifest_digest: digest(EMPTY_JSON_DIGEST),
            executable_digest: Some(digest(EXECUTABLE_DIGEST)),
            contract_version: "1.0".to_owned(),
            adapter_version: "adapter-1".to_owned(),
            binding_digest: digest(CONNECTION_BINDING_DIGEST),
        },
        supersedes_run_id: supersedes.map(run_id),
    }
}

#[derive(Default)]
struct RecordingStore {
    runs: Mutex<BTreeMap<String, AgentRunSnapshot>>,
    terminals: Mutex<Vec<AgentRunTerminal>>,
    fail_terminal: Mutex<bool>,
    fail_start: Mutex<Option<StartStoreFailure>>,
    log: ScriptLog,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StartStoreFailure {
    Acceptance,
    Running,
}

#[derive(Default)]
struct RecordingArtifacts {
    published: Mutex<Vec<AgentMessageArtifact>>,
    fail_publish: Mutex<bool>,
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
        *self.fail_publish.lock().unwrap() = true;
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
        if *self.fail_publish.lock().unwrap() {
            return Err(internal_failure());
        }
        self.published.lock().unwrap().push(artifact.clone());
        self.log.lock().unwrap().push("artifact.message.published");
        ArtifactId::new(format!("artifact-{}", artifact.message_id)).map_err(|_| invalid_input())
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

    fn fail_terminal(&self) {
        *self.fail_terminal.lock().unwrap() = true;
    }

    fn fail_start_at(&self, failure: StartStoreFailure) {
        *self.fail_start.lock().unwrap() = Some(failure);
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

struct ManualClock {
    seconds: Mutex<i64>,
}

impl ManualClock {
    fn new(seconds: i64) -> Self {
        Self {
            seconds: Mutex::new(seconds),
        }
    }

    fn advance(&self, seconds: i64) {
        *self.seconds.lock().unwrap() += seconds;
    }
}

impl Clock for ManualClock {
    fn now_utc(&self) -> Result<String, PortError> {
        Ok(Utc
            .timestamp_opt(*self.seconds.lock().unwrap(), 0)
            .single()
            .unwrap()
            .to_rfc3339())
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
