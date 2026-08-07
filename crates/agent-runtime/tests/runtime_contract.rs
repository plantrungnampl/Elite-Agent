use std::{
    collections::BTreeMap,
    sync::{mpsc, Arc, Condvar, Mutex},
    thread::{self, JoinHandle},
    time::Duration,
};

use chrono::{TimeZone, Utc};
use local_agent_terminal_agent_protocol::{
    CancelAcceptance, ConnectionBinding, InboundDisposition, NdjsonCodec, PeerDescriptor,
    PeerEventSink, ProtocolCapabilities, ProtocolError, ProtocolFrame, ProtocolPeer,
    ProtocolTrustTier, RunAcceptance, RunCancel, RunStart,
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
const ALTERNATE_CONNECTION_BINDING_DIGEST: &str =
    "sha256:19c626cd039614b089a6696156e732bc42c438da19ce49ae9f0380b2224f568d";
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
fn dispatch_rejects_a_binding_digest_not_authorized_at_registration() {
    let store = Arc::new(RecordingStore::default());
    let peer = Arc::new(ScriptedPeer::new(Script::Slow, peer_descriptor()));
    let runtime = runtime(
        store.clone(),
        Arc::new(ManualClock::new(1_800_000_000)),
        peer.clone(),
    );
    let mut request = run_request("run-other-binding", None);
    request.connection.adapter_version = "adapter-2".to_owned();
    request.connection.binding_digest = digest(ALTERNATE_CONNECTION_BINDING_DIGEST);
    request.run_config.adapter_version = "adapter-2".to_owned();

    let error = runtime.start_run(request).unwrap_err();

    assert_eq!(
        error.safe_classification(),
        SafeErrorClassification::InvalidInput
    );
    assert!(store.snapshot("run-other-binding").is_none());
    assert!(peer.start_requests().is_empty());
}

#[test]
fn threaded_delta_waits_for_durable_run_readiness() {
    let fixture = ThreadedRaceFixture::new(ThreadedEmission::Delta);

    fixture.start_and_wait_for_emission_attempt();

    assert_eq!(fixture.store.status("run-1"), Some(AgentRunStatus::Created));
    assert!(matches!(
        fixture.completed.recv_timeout(Duration::from_millis(50)),
        Err(mpsc::RecvTimeoutError::Timeout)
    ));
    fixture.release_acceptance();
    fixture.finish().unwrap();
    assert_eq!(fixture.store.status("run-1"), Some(AgentRunStatus::Running));
}

#[test]
fn threaded_terminal_ack_waits_for_durable_run_readiness_and_commit() {
    let fixture = ThreadedRaceFixture::new(ThreadedEmission::Terminal);

    fixture.start_and_wait_for_emission_attempt();

    assert_eq!(fixture.store.status("run-1"), Some(AgentRunStatus::Created));
    assert!(matches!(
        fixture.completed.recv_timeout(Duration::from_millis(50)),
        Err(mpsc::RecvTimeoutError::Timeout)
    ));
    fixture.release_acceptance();
    fixture.finish().unwrap();
    assert_eq!(
        fixture.store.status("run-1"),
        Some(AgentRunStatus::Succeeded)
    );
    assert_eq!(fixture.store.terminal_count(), 1);
}

#[test]
fn background_callback_entering_before_peer_start_returns_waits_for_durable_readiness() {
    let store = Arc::new(RecordingStore::default());
    let (peer, completed) = PreReturnRacePeer::new();
    let runtime = runtime_with_protocol_peer(
        store.clone(),
        Arc::new(ManualClock::new(1_800_000_000)),
        peer.clone(),
    );

    runtime.start_run(run_request("run-1", None)).unwrap();

    assert!(matches!(
        completed.recv_timeout(Duration::from_secs(1)).unwrap(),
        Ok(InboundDisposition::Notification(_))
    ));
    peer.join_worker().unwrap();
    assert_eq!(store.status("run-1"), Some(AgentRunStatus::Running));
    runtime
        .cancel(CancelAgentRun {
            run_id: run_id("run-1"),
            reason: "proves-active-commit".to_owned(),
            deadline_ms: 1,
        })
        .unwrap();
}

#[test]
fn synchronous_callbacks_during_peer_start_are_rejected() {
    let store = Arc::new(RecordingStore::default());
    let peer = Arc::new(SynchronousCallbackPeer::default());
    let runtime = runtime_with_protocol_peer(
        store.clone(),
        Arc::new(ManualClock::new(1_800_000_000)),
        peer.clone(),
    );

    runtime.start_run(run_request("run-1", None)).unwrap();

    assert_eq!(
        peer.callback_result(),
        Some(Err(ProtocolError::InvalidRequest))
    );
    assert_eq!(
        peer.connection_lost_result(),
        Some(Err(ProtocolError::InvalidRequest))
    );
    assert_eq!(store.status("run-1"), Some(AgentRunStatus::Running));
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
        vec![(
            descriptor.clone(),
            digest(CONNECTION_BINDING_DIGEST),
            protocol_peer,
        )],
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
        vec![
            (agent_descriptor(), digest(CONNECTION_BINDING_DIGEST), first),
            (second_descriptor, digest(CONNECTION_BINDING_DIGEST), second),
        ],
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
fn startup_recovery_deduplicates_authoritative_connection_digests() {
    let store = Arc::new(RecordingStore::default());
    let first: Arc<dyn ProtocolPeer> = Arc::new(ScriptedPeer::new(Script::Slow, peer_descriptor()));
    let mut second_descriptor = agent_descriptor();
    second_descriptor.agent_id = "agent-2".to_owned();
    let mut second_peer_descriptor = peer_descriptor();
    second_peer_descriptor.binding.connection_id = "connection-2".to_owned();
    second_peer_descriptor.binding.agent_id = "agent-2".to_owned();
    let second: Arc<dyn ProtocolPeer> =
        Arc::new(ScriptedPeer::new(Script::Slow, second_peer_descriptor));

    ProtocolAgentRuntime::new(
        store.clone(),
        Arc::new(RecordingArtifacts::default()),
        Arc::new(ManualClock::new(1_800_000_000)),
        vec![
            (agent_descriptor(), digest(CONNECTION_BINDING_DIGEST), first),
            (second_descriptor, digest(CONNECTION_BINDING_DIGEST), second),
        ],
    )
    .unwrap();

    assert_eq!(store.interrupt_count(), 1);
}

#[test]
fn startup_clock_failure_is_returned_before_runtime_is_available() {
    let store = Arc::new(RecordingStore::default());
    let artifacts = Arc::new(RecordingArtifacts::default());
    let clock = Arc::new(ManualClock::new(1_800_000_000));
    clock.fail();
    let protocol_peer: Arc<dyn ProtocolPeer> =
        Arc::new(ScriptedPeer::new(Script::Slow, peer_descriptor()));

    let result = ProtocolAgentRuntime::new(
        store.clone(),
        artifacts,
        clock,
        vec![agent_registration(protocol_peer)],
    );

    let error = match result {
        Ok(_) => panic!("clock failure must fail startup recovery"),
        Err(error) => error,
    };
    assert_eq!(
        error.safe_classification(),
        SafeErrorClassification::Internal
    );
    assert_eq!(store.interrupt_count(), 0);
}

#[test]
fn startup_store_recovery_failure_is_returned_before_runtime_is_available() {
    let store = Arc::new(RecordingStore::default());
    store.fail_interrupt();
    let protocol_peer: Arc<dyn ProtocolPeer> =
        Arc::new(ScriptedPeer::new(Script::Slow, peer_descriptor()));

    let result = ProtocolAgentRuntime::new(
        store.clone(),
        Arc::new(RecordingArtifacts::default()),
        Arc::new(ManualClock::new(1_800_000_000)),
        vec![agent_registration(protocol_peer)],
    );

    let error = match result {
        Ok(_) => panic!("store failure must fail startup recovery"),
        Err(error) => error,
    };
    assert_eq!(
        error.safe_classification(),
        SafeErrorClassification::StorageFull
    );
    assert_eq!(store.interrupt_count(), 1);
}

#[test]
fn capacity_one_reserves_an_in_flight_start_before_durable_create() {
    let store = Arc::new(RecordingStore::default());
    let acceptance_gate = store.block_acceptance();
    let peer = Arc::new(ScriptedPeer::new(Script::Slow, peer_descriptor()));
    let protocol_peer: Arc<dyn ProtocolPeer> = peer.clone();
    let runtime = Arc::new(
        ProtocolAgentRuntime::new(
            store.clone(),
            Arc::new(RecordingArtifacts::default()),
            Arc::new(ManualClock::new(1_800_000_000)),
            vec![agent_registration(protocol_peer)],
        )
        .unwrap(),
    );
    let first_runtime = Arc::clone(&runtime);
    let first = thread::spawn(move || first_runtime.start_run(run_request("run-1", None)));
    acceptance_gate.wait_until_entered();

    let second = runtime.start_run(run_request("run-2", None));
    acceptance_gate.release();
    first.join().unwrap().unwrap();

    assert_eq!(
        second.unwrap_err().safe_classification(),
        SafeErrorClassification::Conflict
    );
    assert!(store.snapshot("run-2").is_none());
    assert_eq!(peer.start_requests().len(), 1);
}

#[test]
fn terminal_completion_releases_capacity_for_the_next_run() {
    let store = Arc::new(RecordingStore::default());
    let peer = Arc::new(ScriptedPeer::new(Script::Proposer, peer_descriptor()));
    let runtime = runtime(
        store.clone(),
        Arc::new(ManualClock::new(1_800_000_000)),
        peer.clone(),
    );
    runtime.start_run(run_request("run-1", None)).unwrap();
    peer.drive().unwrap();

    runtime.start_run(run_request("run-2", None)).unwrap();

    assert_eq!(store.status("run-1"), Some(AgentRunStatus::Succeeded));
    assert_eq!(store.status("run-2"), Some(AgentRunStatus::Running));
    assert_eq!(peer.start_requests().len(), 2);
}

#[test]
fn compensation_shutdown_interrupts_and_removes_sibling_connection_runs() {
    let store = Arc::new(RecordingStore::default());
    let mut descriptor = peer_descriptor();
    descriptor.capabilities.max_concurrent_runs = 2;
    let peer = Arc::new(MultiRunPeer::new(descriptor));
    let protocol_peer: Arc<dyn ProtocolPeer> = peer.clone();
    let runtime = ProtocolAgentRuntime::new(
        store.clone(),
        Arc::new(RecordingArtifacts::default()),
        Arc::new(AdvancingClock::new(1_800_000_000)),
        vec![agent_registration(protocol_peer)],
    )
    .unwrap();
    runtime.start_run(run_request("run-1", None)).unwrap();
    store.fail_start_at(StartStoreFailure::Running);

    let error = runtime.start_run(run_request("run-2", None)).unwrap_err();

    assert_eq!(
        error.safe_classification(),
        SafeErrorClassification::StorageFull
    );
    assert_eq!(store.status("run-1"), Some(AgentRunStatus::Interrupted));
    assert_eq!(store.status("run-2"), Some(AgentRunStatus::Interrupted));
    assert!(peer.was_shutdown());
    assert_eq!(
        runtime
            .cancel(CancelAgentRun {
                run_id: run_id("run-1"),
                reason: "should-be-gone".to_owned(),
                deadline_ms: 1,
            })
            .unwrap_err()
            .safe_classification(),
        SafeErrorClassification::NotFound
    );
}

#[test]
fn retirement_prevents_a_reserved_start_from_reaching_the_shutdown_peer() {
    let store = Arc::new(RecordingStore::default());
    let creation_gate = store.block_creation("run-b");
    let mut descriptor = peer_descriptor();
    descriptor.capabilities.max_concurrent_runs = 2;
    let peer = Arc::new(MultiRunPeer::new(descriptor));
    let runtime = Arc::new(runtime_with_protocol_peer(
        store.clone(),
        Arc::new(AdvancingClock::new(1_800_000_000)),
        peer.clone(),
    ));
    let starting_runtime = Arc::clone(&runtime);
    let start_b = thread::spawn(move || starting_runtime.start_run(run_request("run-b", None)));
    creation_gate.wait_until_entered();
    store.fail_start_at(StartStoreFailure::Running);

    let start_a = runtime.start_run(run_request("run-a", None)).unwrap_err();

    assert_eq!(
        start_a.safe_classification(),
        SafeErrorClassification::StorageFull
    );
    assert!(peer.was_shutdown());
    creation_gate.release();
    let start_b = start_b.join().unwrap().unwrap_err();
    assert_eq!(
        start_b.safe_classification(),
        SafeErrorClassification::Conflict
    );
    assert_eq!(store.status("run-b"), Some(AgentRunStatus::Interrupted));
    assert_eq!(peer.start_count(), 1);
}

#[test]
fn poison_cleanup_invalidates_a_start_blocked_before_durable_create() {
    let store = Arc::new(RecordingStore::default());
    let creation_gate = store.block_creation("run-stale");
    let mut descriptor = peer_descriptor();
    descriptor.capabilities.max_concurrent_runs = 2;
    let peer = Arc::new(MultiRunPeer::new(descriptor));
    let runtime = Arc::new(runtime_with_protocol_peer(
        store.clone(),
        Arc::new(ManualClock::new(1_800_000_000)),
        peer.clone(),
    ));
    runtime.start_run(run_request("run-active", None)).unwrap();
    let stale_runtime = Arc::clone(&runtime);
    let stale_start =
        thread::spawn(move || stale_runtime.start_run(run_request("run-stale", None)));
    creation_gate.wait_until_entered();

    peer.connection_lost(0).unwrap();
    runtime.start_run(run_request("run-current", None)).unwrap();
    creation_gate.release();

    assert_eq!(
        stale_start
            .join()
            .unwrap()
            .unwrap_err()
            .safe_classification(),
        SafeErrorClassification::Conflict
    );
    assert_eq!(store.status("run-stale"), Some(AgentRunStatus::Interrupted));
    assert_eq!(store.status("run-current"), Some(AgentRunStatus::Running));
    assert_eq!(peer.start_count(), 2);
    runtime
        .start_run(run_request("run-current-2", None))
        .unwrap();
    assert_start_conflict_without_row(&runtime, &store, "run-over-capacity");
}

#[test]
fn stale_start_never_registers_in_the_current_generation_session() {
    let store = Arc::new(RecordingStore::default());
    let creation_gate = store.block_creation("run-stale");
    let clock = Arc::new(ManualClock::new(1_800_000_000));
    let mut descriptor = peer_descriptor();
    descriptor.capabilities.max_concurrent_runs = 2;
    let peer = Arc::new(MultiRunPeer::new(descriptor));
    let runtime = Arc::new(runtime_with_protocol_peer(
        store.clone(),
        clock.clone(),
        peer.clone(),
    ));
    runtime.start_run(run_request("run-active", None)).unwrap();
    let stale_runtime = Arc::clone(&runtime);
    let stale_start = thread::spawn(move || {
        stale_runtime.start_run(run_request_with_deadline("run-stale", 1_800_000_005))
    });
    creation_gate.wait_until_entered();

    peer.connection_lost(0).unwrap();
    runtime.start_run(run_request("run-current", None)).unwrap();
    creation_gate.release();
    assert_eq!(
        stale_start
            .join()
            .unwrap()
            .unwrap_err()
            .safe_classification(),
        SafeErrorClassification::Conflict
    );
    clock.advance(5);

    assert!(runtime.check_timeouts().unwrap().is_empty());
    assert_eq!(store.status("run-current"), Some(AgentRunStatus::Running));
    assert_eq!(peer.start_count(), 2);
}

#[test]
fn compensation_shutdown_retires_connection_after_durable_cleanup() {
    let store = Arc::new(RecordingStore::default());
    let peer = Arc::new(MultiRunPeer::new(peer_descriptor()));
    let runtime = runtime_with_protocol_peer(
        store.clone(),
        Arc::new(AdvancingClock::new(1_800_000_000)),
        peer.clone(),
    );
    store.fail_start_at(StartStoreFailure::Running);

    let start_error = runtime.start_run(run_request("run-1", None)).unwrap_err();

    assert_eq!(
        start_error.safe_classification(),
        SafeErrorClassification::StorageFull
    );
    assert!(peer.was_shutdown());
    assert_eq!(store.status("run-1"), Some(AgentRunStatus::Interrupted));
    store.allow_start();
    assert_start_conflict_without_row(&runtime, &store, "run-2");
    assert_eq!(peer.start_count(), 1);
}

#[test]
fn runtime_shutdown_retires_connection_after_durable_cleanup() {
    let store = Arc::new(RecordingStore::default());
    let peer = Arc::new(MultiRunPeer::new(peer_descriptor()));
    let runtime = runtime_with_protocol_peer(
        store.clone(),
        Arc::new(AdvancingClock::new(1_800_000_000)),
        peer.clone(),
    );
    runtime.start_run(run_request("run-1", None)).unwrap();

    runtime.shutdown().unwrap();

    assert!(peer.was_shutdown());
    assert_eq!(store.status("run-1"), Some(AgentRunStatus::Interrupted));
    assert_start_conflict_without_row(&runtime, &store, "run-2");
    assert_eq!(peer.start_count(), 1);
}

#[test]
fn compensation_clock_failure_retires_connection_until_later_cleanup() {
    let store = Arc::new(RecordingStore::default());
    let clock = Arc::new(AdvancingClock::new(1_800_000_000));
    clock.fail_on_call(5);
    let peer = Arc::new(MultiRunPeer::new(peer_descriptor()));
    let runtime = runtime_with_protocol_peer(store.clone(), clock.clone(), peer.clone());
    store.fail_start_at(StartStoreFailure::Running);

    let start_error = runtime.start_run(run_request("run-1", None)).unwrap_err();

    assert_eq!(
        start_error.safe_classification(),
        SafeErrorClassification::StorageFull
    );
    assert!(peer.was_shutdown());
    assert_eq!(store.status("run-1"), Some(AgentRunStatus::Accepted));
    store.allow_start();
    assert_start_conflict_without_row(&runtime, &store, "run-2");

    clock.recover();
    runtime.shutdown().unwrap();
    assert_eq!(store.status("run-1"), Some(AgentRunStatus::Interrupted));
    assert_start_conflict_without_row(&runtime, &store, "run-3");
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
fn compensation_uses_a_fresh_monotonic_timestamp_after_running_store_failure() {
    let store = Arc::new(RecordingStore::default());
    store.fail_start_at(StartStoreFailure::Running);
    let clock = Arc::new(AdvancingClock::new(1_800_000_000));
    let peer = Arc::new(ScriptedPeer::new(Script::Slow, peer_descriptor()));
    let protocol_peer: Arc<dyn ProtocolPeer> = peer.clone();
    let runtime = ProtocolAgentRuntime::new(
        store.clone(),
        Arc::new(RecordingArtifacts::default()),
        clock,
        vec![agent_registration(protocol_peer)],
    )
    .unwrap();

    let error = runtime.start_run(run_request("run-1", None)).unwrap_err();

    assert_eq!(
        error.safe_classification(),
        SafeErrorClassification::StorageFull
    );
    assert_eq!(store.status("run-1"), Some(AgentRunStatus::Interrupted));
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
fn interruption_store_failure_retains_active_state_and_capacity_until_retry_succeeds() {
    let store = Arc::new(RecordingStore::default());
    let clock = Arc::new(ManualClock::new(1_800_000_000));
    let mut descriptor = peer_descriptor();
    descriptor.capabilities.max_concurrent_runs = 2;
    let peer = Arc::new(MultiRunPeer::new(descriptor));
    let runtime = runtime_with_protocol_peer(store.clone(), clock.clone(), peer.clone());
    runtime.start_run(run_request("run-1", None)).unwrap();
    clock.advance(DEFAULT_HEARTBEAT_TIMEOUT_SECS);
    store.fail_interrupt();

    let error = runtime.check_timeouts().unwrap_err();

    assert_eq!(
        error.safe_classification(),
        SafeErrorClassification::StorageFull
    );
    assert_eq!(store.status("run-1"), Some(AgentRunStatus::Running));
    assert_start_conflict_without_row(&runtime, &store, "run-2");
    assert_eq!(peer.start_count(), 1);

    store.allow_interrupt();
    assert_eq!(runtime.check_timeouts().unwrap(), vec![run_id("run-1")]);
    assert_eq!(store.status("run-1"), Some(AgentRunStatus::Interrupted));
    assert_eq!(
        runtime
            .cancel(CancelAgentRun {
                run_id: run_id("run-1"),
                reason: "already-interrupted".to_owned(),
                deadline_ms: 1,
            })
            .unwrap_err()
            .safe_classification(),
        SafeErrorClassification::NotFound
    );
    runtime.start_run(run_request("run-2", None)).unwrap();
    assert_eq!(peer.start_count(), 2);
}

#[test]
fn interruption_poison_blocks_a_concurrent_start_before_the_store_call_finishes() {
    let store = Arc::new(RecordingStore::default());
    let clock = Arc::new(ManualClock::new(1_800_000_000));
    let mut descriptor = peer_descriptor();
    descriptor.capabilities.max_concurrent_runs = 2;
    let peer = Arc::new(MultiRunPeer::new(descriptor));
    let runtime = Arc::new(runtime_with_protocol_peer(
        store.clone(),
        clock.clone(),
        peer.clone(),
    ));
    runtime.start_run(run_request("run-1", None)).unwrap();
    clock.advance(DEFAULT_HEARTBEAT_TIMEOUT_SECS);
    let interrupt_gate = store.block_interrupt();
    store.fail_interrupt();
    let checking_runtime = Arc::clone(&runtime);
    let checking = thread::spawn(move || checking_runtime.check_timeouts());
    interrupt_gate.wait_until_entered();

    assert_start_conflict_without_row(&runtime, &store, "run-2");
    assert_eq!(peer.start_count(), 1);

    interrupt_gate.release();
    assert_eq!(
        checking.join().unwrap().unwrap_err().safe_classification(),
        SafeErrorClassification::StorageFull
    );
    assert_eq!(store.status("run-1"), Some(AgentRunStatus::Running));
}

#[test]
fn clock_recovery_retries_poison_without_waiting_for_a_session_timeout() {
    let store = Arc::new(RecordingStore::default());
    let clock = Arc::new(ManualClock::new(1_800_000_000));
    let mut descriptor = peer_descriptor();
    descriptor.capabilities.max_concurrent_runs = 2;
    let peer = Arc::new(MultiRunPeer::new(descriptor));
    let runtime = runtime_with_protocol_peer(store.clone(), clock.clone(), peer.clone());
    runtime.start_run(run_request("run-1", None)).unwrap();
    clock.fail();

    let error = runtime.check_timeouts().unwrap_err();

    assert_eq!(
        error.safe_classification(),
        SafeErrorClassification::Internal
    );
    assert_eq!(store.status("run-1"), Some(AgentRunStatus::Running));
    clock.recover();
    assert_start_conflict_without_row(&runtime, &store, "run-2");
    assert_eq!(peer.start_count(), 1);

    assert_eq!(runtime.check_timeouts().unwrap(), vec![run_id("run-1")]);
    assert_eq!(store.status("run-1"), Some(AgentRunStatus::Interrupted));
    runtime.start_run(run_request("run-2", None)).unwrap();
    assert_eq!(peer.start_count(), 2);
}

#[test]
fn two_retries_for_one_poison_do_not_interrupt_post_recovery_work() {
    let store = Arc::new(RecordingStore::default());
    let clock = Arc::new(ManualClock::new(1_800_000_000));
    let mut descriptor = peer_descriptor();
    descriptor.capabilities.max_concurrent_runs = 2;
    let peer = Arc::new(MultiRunPeer::new(descriptor));
    let runtime = Arc::new(runtime_with_protocol_peer(
        store.clone(),
        clock.clone(),
        peer.clone(),
    ));
    runtime.start_run(run_request("run-1", None)).unwrap();
    clock.fail();
    runtime.check_timeouts().unwrap_err();
    clock.recover();

    let interrupt_gate = store.block_interrupt();
    let (retry_a_done, retry_a_done_rx) = mpsc::channel();
    let retry_a_runtime = Arc::clone(&runtime);
    let retry_a = thread::spawn(move || {
        retry_a_done.send(retry_a_runtime.check_timeouts()).unwrap();
    });
    interrupt_gate.wait_until_entered();
    let retry_b_clock_gate = clock.block_next_call();
    let (retry_b_done, retry_b_done_rx) = mpsc::channel();
    let retry_b_runtime = Arc::clone(&runtime);
    let retry_b = thread::spawn(move || {
        retry_b_done.send(retry_b_runtime.check_timeouts()).unwrap();
    });
    retry_b_clock_gate.wait_until_entered();

    interrupt_gate.release();
    assert_eq!(
        retry_a_done_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("retry A must finish after durable cleanup")
            .unwrap(),
        vec![run_id("run-1")]
    );
    retry_a.join().unwrap();
    runtime.start_run(run_request("run-2", None)).unwrap();
    retry_b_clock_gate.release();

    assert!(retry_b_done_rx
        .recv_timeout(Duration::from_secs(1))
        .expect("stale retry B must no-op")
        .unwrap()
        .is_empty());
    retry_b.join().unwrap();
    assert_eq!(store.interrupt_count(), 2);
    assert_eq!(store.status("run-2"), Some(AgentRunStatus::Running));
    assert_eq!(peer.start_count(), 2);
    runtime.start_run(run_request("run-3", None)).unwrap();
    assert_eq!(peer.start_count(), 3);
}

#[test]
fn connection_loss_store_failure_is_retried_by_check_timeouts() {
    let store = Arc::new(RecordingStore::default());
    let clock = Arc::new(ManualClock::new(1_800_000_000));
    let mut descriptor = peer_descriptor();
    descriptor.capabilities.max_concurrent_runs = 2;
    let peer = Arc::new(MultiRunPeer::new(descriptor));
    let runtime = runtime_with_protocol_peer(store.clone(), clock, peer.clone());
    runtime.start_run(run_request("run-1", None)).unwrap();
    let interrupt_gate = store.block_interrupt();
    store.fail_interrupt();
    let losing_peer = Arc::clone(&peer);
    let losing = thread::spawn(move || losing_peer.connection_lost(0));
    interrupt_gate.wait_until_entered();

    assert_start_conflict_without_row(&runtime, &store, "run-2");
    interrupt_gate.release();
    assert_eq!(
        losing.join().unwrap(),
        Err(ProtocolError::InternalAgentFailure)
    );

    store.allow_interrupt();
    assert_eq!(runtime.check_timeouts().unwrap(), vec![run_id("run-1")]);
    assert_eq!(store.status("run-1"), Some(AgentRunStatus::Interrupted));
}

#[test]
fn rejected_handshake_preserves_conflict_and_poisoned_capacity() {
    let store = Arc::new(RecordingStore::default());
    let creation_gate = store.block_creation("run-2");
    let clock = Arc::new(ManualClock::new(1_800_000_000));
    let mut descriptor = peer_descriptor();
    descriptor.capabilities.max_concurrent_runs = 2;
    let peer = Arc::new(MultiRunPeer::new(descriptor));
    let runtime = Arc::new(runtime_with_protocol_peer(
        store.clone(),
        clock.clone(),
        peer.clone(),
    ));
    runtime.start_run(run_request("run-1", None)).unwrap();
    let starting_runtime = Arc::clone(&runtime);
    let starting = thread::spawn(move || starting_runtime.start_run(run_request("run-2", None)));
    creation_gate.wait_until_entered();
    clock.fail();
    assert_eq!(
        runtime.check_timeouts().unwrap_err().safe_classification(),
        SafeErrorClassification::Internal
    );
    clock.recover();

    creation_gate.release();
    assert_eq!(
        starting.join().unwrap().unwrap_err().safe_classification(),
        SafeErrorClassification::Conflict
    );
    assert_eq!(peer.start_count(), 1);
    assert_eq!(store.status("run-2"), Some(AgentRunStatus::Interrupted));
    assert_start_conflict_without_row(&runtime, &store, "run-3");

    assert_eq!(runtime.check_timeouts().unwrap(), vec![run_id("run-1")]);
    runtime.start_run(run_request("run-4", None)).unwrap();
    assert_eq!(peer.start_count(), 2);
}

struct StaleCleanupRace {
    store: Arc<RecordingStore>,
    artifacts: Arc<RecordingArtifacts>,
    clock: Arc<ManualClock>,
    peer: Arc<MultiRunPeer>,
    runtime: Arc<ProtocolAgentRuntime>,
    creation_gate: Arc<AcceptanceGate>,
    stale_start: Mutex<Option<JoinHandle<Result<(), PortError>>>>,
}

impl StaleCleanupRace {
    fn new() -> Self {
        let store = Arc::new(RecordingStore::default());
        let artifacts = Arc::new(RecordingArtifacts::default());
        let creation_gate = store.block_creation("run-stale");
        let clock = Arc::new(ManualClock::new(1_800_000_000));
        let mut descriptor = peer_descriptor();
        descriptor.capabilities.max_concurrent_runs = 2;
        let peer = Arc::new(MultiRunPeer::new(descriptor));
        let protocol_peer: Arc<dyn ProtocolPeer> = peer.clone();
        let runtime = Arc::new(
            ProtocolAgentRuntime::new(
                store.clone(),
                artifacts.clone(),
                clock.clone(),
                vec![agent_registration(protocol_peer)],
            )
            .unwrap(),
        );
        runtime.start_run(run_request("run-active", None)).unwrap();
        let stale_runtime = Arc::clone(&runtime);
        let stale_start = thread::spawn(move || {
            stale_runtime
                .start_run(run_request("run-stale", None))
                .map(|_| ())
        });
        creation_gate.wait_until_entered();
        peer.connection_lost(0).unwrap();
        Self {
            store,
            artifacts,
            clock,
            peer,
            runtime,
            creation_gate,
            stale_start: Mutex::new(Some(stale_start)),
        }
    }

    fn release_stale(&self) -> PortError {
        self.creation_gate.release();
        self.stale_start
            .lock()
            .unwrap()
            .take()
            .expect("stale start handle")
            .join()
            .unwrap()
            .unwrap_err()
    }
}

#[derive(Debug, Clone, Copy)]
enum ExactCleanupFailure {
    ArtifactPublication,
    TerminalStore,
}

#[test]
fn failed_stale_artifact_cleanup_retries_without_poisoning_current_work() {
    assert_failed_stale_cleanup_retries(ExactCleanupFailure::ArtifactPublication);
}

#[test]
fn failed_stale_terminal_cleanup_retries_without_poisoning_current_work() {
    assert_failed_stale_cleanup_retries(ExactCleanupFailure::TerminalStore);
}

#[test]
fn stale_cleanup_survives_clock_failure_before_its_first_attempt() {
    let race = StaleCleanupRace::new();
    let store = &race.store;
    let artifacts = &race.artifacts;
    let clock = &race.clock;
    let runtime = &race.runtime;
    clock.fail();

    assert_eq!(
        race.release_stale().safe_classification(),
        SafeErrorClassification::Conflict
    );
    assert_eq!(store.status("run-stale"), Some(AgentRunStatus::Created));
    assert!(artifacts.published_contents().is_empty());

    clock.recover();
    clock.advance(1);
    assert!(runtime.check_timeouts().unwrap().is_empty());
    assert_eq!(store.status("run-stale"), Some(AgentRunStatus::Interrupted));
    assert_eq!(
        store.terminal_time("run-stale"),
        Some(Timestamp::from_unix_seconds(1_800_000_001))
    );
    assert_eq!(artifacts.published_contents().len(), 1);
}

#[test]
fn runtime_recreation_recovers_memory_lost_stale_cleanup() {
    let race = StaleCleanupRace::new();
    race.store.fail_terminal();
    assert_eq!(
        race.release_stale().safe_classification(),
        SafeErrorClassification::Conflict
    );
    assert_eq!(
        race.store.status("run-stale"),
        Some(AgentRunStatus::Created)
    );
    assert_eq!(race.artifacts.published_contents().len(), 1);
    let store = Arc::clone(&race.store);
    let artifacts = Arc::clone(&race.artifacts);
    let clock = Arc::clone(&race.clock);
    drop(race);

    store.allow_terminal();
    clock.advance(1);
    let mut descriptor = peer_descriptor();
    descriptor.capabilities.max_concurrent_runs = 2;
    let second_peer = Arc::new(MultiRunPeer::new(descriptor));
    let second_protocol_peer: Arc<dyn ProtocolPeer> = second_peer.clone();
    let second_runtime = ProtocolAgentRuntime::new(
        store.clone(),
        artifacts.clone(),
        clock,
        vec![agent_registration(second_protocol_peer)],
    )
    .unwrap();

    assert_eq!(store.status("run-stale"), Some(AgentRunStatus::Interrupted));
    assert_eq!(
        store.status("run-active"),
        Some(AgentRunStatus::Interrupted)
    );
    assert_eq!(artifacts.published_contents().len(), 1);
    second_runtime
        .start_run(run_request("run-current", None))
        .unwrap();
    assert_eq!(store.status("run-current"), Some(AgentRunStatus::Running));
    assert_eq!(second_peer.start_count(), 1);
}

#[test]
fn concurrent_cleanup_retries_claim_once_and_reuse_published_artifact() {
    let race = StaleCleanupRace::new();
    let store = &race.store;
    let artifacts = &race.artifacts;
    let runtime = &race.runtime;
    store.fail_terminal();
    assert_eq!(
        race.release_stale().safe_classification(),
        SafeErrorClassification::Conflict
    );
    assert_eq!(store.status("run-stale"), Some(AgentRunStatus::Created));
    assert_eq!(artifacts.published_contents().len(), 1);

    store.allow_terminal();
    let terminal_gate = store.block_terminal();
    let (retry_a_done, retry_a_done_rx) = mpsc::channel();
    let retry_a_runtime = Arc::clone(runtime);
    let retry_a = thread::spawn(move || {
        retry_a_done.send(retry_a_runtime.check_timeouts()).unwrap();
    });
    terminal_gate.wait_until_entered();
    let (retry_b_started, retry_b_started_rx) = mpsc::channel();
    let (retry_b_done, retry_b_done_rx) = mpsc::channel();
    let retry_b_runtime = Arc::clone(runtime);
    let retry_b = thread::spawn(move || {
        retry_b_started.send(()).unwrap();
        retry_b_done.send(retry_b_runtime.check_timeouts()).unwrap();
    });
    retry_b_started_rx.recv().unwrap();
    let retry_b_before_release = match retry_b_done_rx.recv_timeout(Duration::from_secs(1)) {
        Ok(result) => Some(result),
        Err(mpsc::RecvTimeoutError::Timeout) => None,
        Err(mpsc::RecvTimeoutError::Disconnected) => panic!("retry B result channel disconnected"),
    };
    terminal_gate.release();

    let retry_a_result = retry_a_done_rx
        .recv_timeout(Duration::from_secs(1))
        .expect("retry A must finish after terminal persistence is released");
    let retry_b_completed_before_release = retry_b_before_release.is_some();
    let retry_b_result = match retry_b_before_release {
        Some(result) => result,
        None => retry_b_done_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("retry B must finish after terminal persistence is released"),
    };
    retry_a.join().unwrap();
    retry_b.join().unwrap();

    assert!(
        retry_b_completed_before_release,
        "retry B must not wait on retry A"
    );
    assert!(retry_a_result.unwrap().is_empty());
    assert!(retry_b_result.unwrap().is_empty());
    assert_eq!(artifacts.published_contents().len(), 1);
    assert_eq!(store.terminal_count(), 1);
    assert_eq!(store.status("run-stale"), Some(AgentRunStatus::Interrupted));
}

fn assert_failed_stale_cleanup_retries(failure: ExactCleanupFailure) {
    let race = StaleCleanupRace::new();
    let store = &race.store;
    let artifacts = &race.artifacts;
    let clock = &race.clock;
    let peer = &race.peer;
    let runtime = &race.runtime;
    runtime.start_run(run_request("run-current", None)).unwrap();
    match failure {
        ExactCleanupFailure::ArtifactPublication => artifacts.fail_publish(),
        ExactCleanupFailure::TerminalStore => store.fail_terminal(),
    }

    assert_eq!(
        race.release_stale().safe_classification(),
        SafeErrorClassification::Conflict,
        "{failure:?}"
    );
    assert_eq!(store.status("run-stale"), Some(AgentRunStatus::Created));
    assert_eq!(store.status("run-current"), Some(AgentRunStatus::Running));
    runtime
        .start_run(run_request("run-current-2", None))
        .unwrap();
    clock.advance(1);
    assert!(runtime.check_timeouts().is_err());
    assert_eq!(store.status("run-stale"), Some(AgentRunStatus::Created));
    assert_eq!(store.status("run-current"), Some(AgentRunStatus::Running));
    assert_eq!(store.status("run-current-2"), Some(AgentRunStatus::Running));
    assert_eq!(store.interrupt_count(), 2);

    match failure {
        ExactCleanupFailure::ArtifactPublication => artifacts.allow_publish(),
        ExactCleanupFailure::TerminalStore => store.allow_terminal(),
    }
    clock.advance(1);

    assert!(runtime.check_timeouts().unwrap().is_empty());
    assert_eq!(store.status("run-stale"), Some(AgentRunStatus::Interrupted));
    assert_eq!(
        store.terminal_time("run-stale"),
        Some(Timestamp::from_unix_seconds(1_800_000_002))
    );
    assert_eq!(store.status("run-current"), Some(AgentRunStatus::Running));
    assert_eq!(store.status("run-current-2"), Some(AgentRunStatus::Running));
    assert_eq!(store.interrupt_count(), 2);
    assert_eq!(peer.start_count(), 3);
    let terminal_count = store.terminal_count();
    assert!(runtime.check_timeouts().unwrap().is_empty());
    assert_eq!(store.terminal_count(), terminal_count);
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

#[derive(Debug, Clone, Copy)]
enum ThreadedEmission {
    Delta,
    Terminal,
}

struct ThreadedRaceFixture {
    store: Arc<RecordingStore>,
    gate: Arc<AcceptanceGate>,
    peer: Arc<ThreadedRacePeer>,
    runtime: Arc<ProtocolAgentRuntime>,
    attempted: mpsc::Receiver<()>,
    completed: mpsc::Receiver<Result<(), ProtocolError>>,
    start: Mutex<Option<JoinHandle<Result<(), PortError>>>>,
}

impl ThreadedRaceFixture {
    fn new(emission: ThreadedEmission) -> Self {
        let store = Arc::new(RecordingStore::default());
        let gate = store.block_acceptance();
        let (peer, attempted, completed) = ThreadedRacePeer::new(emission, Arc::clone(&gate));
        let protocol_peer: Arc<dyn ProtocolPeer> = peer.clone();
        let runtime = Arc::new(
            ProtocolAgentRuntime::new(
                store.clone(),
                Arc::new(RecordingArtifacts::default()),
                Arc::new(ManualClock::new(1_800_000_000)),
                vec![agent_registration(protocol_peer)],
            )
            .unwrap(),
        );
        Self {
            store,
            gate,
            peer,
            runtime,
            attempted,
            completed,
            start: Mutex::new(None),
        }
    }

    fn start_and_wait_for_emission_attempt(&self) {
        let runtime = Arc::clone(&self.runtime);
        *self.start.lock().unwrap() = Some(thread::spawn(move || {
            runtime.start_run(run_request("run-1", None)).map(|_| ())
        }));
        self.gate.wait_until_entered();
        self.attempted
            .recv_timeout(Duration::from_secs(1))
            .expect("worker must attempt its event while acceptance is blocked");
    }

    fn release_acceptance(&self) {
        self.gate.release();
    }

    fn finish(&self) -> Result<(), ProtocolError> {
        self.start
            .lock()
            .unwrap()
            .take()
            .expect("runtime start handle")
            .join()
            .expect("runtime start thread")
            .map_err(|_| ProtocolError::InternalAgentFailure)?;
        let emission = self
            .completed
            .recv_timeout(Duration::from_secs(1))
            .map_err(|_| ProtocolError::Timeout)?;
        self.peer.join_workers()?;
        emission
    }
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
        Arc::clone(&self.sinks.lock().unwrap()[index]).connection_lost()
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
    decode_protocol_frame(serde_json::json!({
        "jsonrpc": "2.0",
        "method": "agent.stream.delta",
        "params": {
            "runId": run_id,
            "sequence": 1,
            "channel": "content",
            "delta": "threaded"
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
                "providerReportedCost": 0.0
            }
        }
    }))
}

fn decode_protocol_frame(value: serde_json::Value) -> ProtocolFrame {
    NdjsonCodec::default()
        .decode(&serde_json::to_vec(&value).unwrap())
        .unwrap()
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
        vec![agent_registration(protocol_peer)],
    )
    .unwrap()
}

fn runtime_with_protocol_peer(
    store: Arc<RecordingStore>,
    clock: Arc<dyn Clock>,
    peer: Arc<dyn ProtocolPeer>,
) -> ProtocolAgentRuntime {
    ProtocolAgentRuntime::new(
        store,
        Arc::new(RecordingArtifacts::default()),
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

fn run_request_with_deadline(run: &str, deadline: i64) -> BoundAgentRunRequest {
    let mut request = run_request(run, None);
    request.run_config.limits.deadline = Timestamp::from_unix_seconds(deadline);
    request
}

#[derive(Default)]
struct RecordingStore {
    runs: Mutex<BTreeMap<String, AgentRunSnapshot>>,
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

    fn allow_publish(&self) {
        *self.fail_publish.lock().unwrap() = false;
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

    fn allow_terminal(&self) {
        *self.fail_terminal.lock().unwrap() = false;
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
