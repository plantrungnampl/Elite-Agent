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
    MaliciousScript, ProtocolAgentRuntime, RequestScript, Script, ScriptLog, ScriptedPeer,
    DEFAULT_HEARTBEAT_TIMEOUT_SECS, DEFAULT_RUN_DEADLINE_SECS,
};
use local_agent_terminal_application::{
    ActorId, AgentArtifactStore, AgentContextQueryRequest, AgentContextQueryResponse,
    AgentFamilyKey, AgentMessageArtifact, AgentRequestAudit, AgentRequestAuditDecision,
    AgentRequestHandler, AgentRequestKind, AgentRunStore, AgentRuntime, AgentSpecialistCommit,
    AgentSpecialistRequest, AgentSpecialistResponse, Clock, DeliberationRunAssignment, PortError,
    ProtocolRequestBegin, ProtocolRequestBeginResult, ProtocolRequestIdentity,
    ProtocolRequestRecord, ProtocolRequestStore, ProtocolRequestTerminal,
    ProtocolResponseArtifact, ProtocolResponseArtifactPublisher, ProtocolStreamAdvance,
    ProtocolStreamIdentity, Retryability, SafeErrorClassification,
};
use local_agent_terminal_domain::{
    AgentDescriptor, AgentRunLimits, AgentRunSnapshot, AgentRunStatus, AgentRunTerminal,
    ArtifactId, BoundAgentConnection, BoundAgentRunRequest, BoundEffectiveContext,
    BoundGenerationParameters, BoundRunConfig, CancelAgentRun, RunId, Sha256Digest,
    Sequence, SpecialistBudget, SpecialistRequest, TaskId, Timestamp, TrustTier,
};

const EMPTY_JSON_DIGEST: &str =
    "sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a";
const CONNECTION_BINDING_DIGEST: &str =
    "sha256:b26578733a878b45c3f6526cb937d53f11d13e35c7428d914cc06babb43ad729";
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
        vec!["proposer:core:run-start:run-1:context-1".to_owned()]
    );
    assert_eq!(
        log.lock().unwrap().as_slice(),
        [
            "protocol.response.published",
            "protocol.response.completed",
            "protocol.response.published",
            "protocol.response.completed",
            "artifact.message.published",
            "store.terminal.committed",
            "protocol.response.published",
            "protocol.response.completed",
            "peer.terminal.acknowledged"
        ]
    );
    assert_eq!(
        artifacts.published_contents(),
        vec![peer.outputs()[0].as_bytes()]
    );
}

#[test]
fn peer_receives_execution_binding_out_of_band_and_exact_v2_start_frame() {
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
    assert_eq!(
        wire.pointer("/params").unwrap(),
        &serde_json::json!({
            "runId": "run-2",
            "taskId": "task-1",
            "contextPackageRef": "context-1",
            "idempotencyKey": "task-1:reviewer:run-2",
            "role": "reviewer"
        })
    );
    for forbidden in [
        "/params/supersedesRunId",
        "/params/runConfigurationRef",
        "/params/limits",
        "/params/permissions",
        "/params/responseSchema",
    ] {
        assert!(wire.pointer(forbidden).is_none(), "{forbidden} must stay out of v2 wire");
    }
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
            vec![format!("{role}:core:run-start:run-1:context-1")]
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
    let runtime = runtime_with_ports(
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

    let result = runtime_with_ports(
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

    runtime_with_ports(
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

    let result = runtime_with_ports(
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

    let result = runtime_with_ports(
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
        runtime_with_ports(
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
    let runtime = runtime_with_ports(
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
    let runtime = runtime_with_ports(
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
fn negotiated_context_and_specialist_requests_are_bound_audited_and_typed() {
    let store = Arc::new(RecordingStore::default());
    let artifacts = Arc::new(RecordingArtifacts::default());
    let clock = Arc::new(ManualClock::new(1_800_000_000));
    let mut descriptor = peer_descriptor();
    descriptor.capabilities.context_query = true;
    descriptor.capabilities.tool_requests = true;
    descriptor.capabilities.specialist_requests = true;
    let peer = Arc::new(ScriptedPeer::new(Script::Requesting, descriptor));
    let handler = Arc::new(RecordingRequestHandler::default());
    let runtime = runtime_with_request_handler(
        Arc::clone(&store),
        artifacts,
        clock,
        Arc::clone(&peer),
        Arc::clone(&handler),
    );
    let mut request = run_request("run-1", None);
    request.run_config.limits.max_context_queries = 1;
    request.run_config.limits.max_specialist_requests = 1;
    runtime.start_run(request).unwrap();

    peer.drive().unwrap();

    let values = peer
        .request_responses()
        .iter()
        .map(|response| serde_json::to_value(response).unwrap())
        .collect::<Vec<_>>();
    assert_eq!(values.len(), 3);
    assert_eq!(values[0].pointer("/result/queryId").unwrap(), "query-1");
    assert_eq!(
        values[0].pointer("/result/items/0/contentDigest").unwrap(),
        CONTEXT_DIGEST
    );
    assert_eq!(values[0].pointer("/result/items/0/itemId").unwrap(), "item-1");
    assert_eq!(
        values[1]
            .pointer("/error/data/category")
            .and_then(serde_json::Value::as_str),
        Some("policy_denied")
    );
    assert_eq!(values[2].pointer("/result/decision").unwrap(), "accepted");
    assert_eq!(
        values[2].pointer("/result/specialistRunId").unwrap(),
        "specialist-specialist-request-1"
    );

    let context_requests = handler.context_requests();
    assert_eq!(context_requests.len(), 1);
    assert_eq!(context_requests[0].run_id, run_id("run-1"));
    assert_eq!(context_requests[0].task_id, task_id("task-1"));
    assert_eq!(context_requests[0].connection_id, "connection-1");
    assert_eq!(
        context_requests[0].connection_binding_digest,
        digest(CONNECTION_BINDING_DIGEST)
    );
    assert_eq!(context_requests[0].phase, "analysis");

    let specialist_requests = handler.specialist_requests();
    assert_eq!(specialist_requests.len(), 1);
    assert_eq!(specialist_requests[0].run_id, run_id("run-1"));
    assert_eq!(specialist_requests[0].task_id, task_id("task-1"));
    assert_eq!(specialist_requests[0].connection_id, "connection-1");
    assert_eq!(specialist_requests[0].phase, "analysis");

    let audits = handler.audits();
    assert_eq!(audits.len(), 2);
    assert_eq!(audits[0].kind, AgentRequestKind::ContextQuery);
    assert_eq!(audits[0].decision, AgentRequestAuditDecision::Accepted);
    assert_eq!(audits[1].kind, AgentRequestKind::SpecialistRequest);
    assert_eq!(audits[1].decision, AgentRequestAuditDecision::Accepted);
    assert!(audits.iter().all(|audit| {
        audit.run_id == run_id("run-1")
            && audit.task_id == task_id("task-1")
            && audit.connection_id == "connection-1"
            && audit.connection_binding_digest == digest(CONNECTION_BINDING_DIGEST)
            && audit.reason_code.is_none()
    }));
    assert_eq!(store.status("run-1"), Some(AgentRunStatus::Running));
    assert_eq!(store.terminal_count(), 0);
}

#[test]
fn request_budgets_reject_without_calling_the_handler_and_are_audited() {
    let store = Arc::new(RecordingStore::default());
    let artifacts = Arc::new(RecordingArtifacts::default());
    let clock = Arc::new(ManualClock::new(1_800_000_000));
    let mut descriptor = peer_descriptor();
    descriptor.capabilities.context_query = true;
    descriptor.capabilities.tool_requests = true;
    descriptor.capabilities.specialist_requests = true;
    let peer = Arc::new(ScriptedPeer::new(Script::Requesting, descriptor));
    let handler = Arc::new(RecordingRequestHandler::default());
    let runtime = runtime_with_request_handler(
        Arc::clone(&store),
        artifacts,
        clock,
        Arc::clone(&peer),
        Arc::clone(&handler),
    );
    runtime.start_run(run_request("run-1", None)).unwrap();

    peer.drive().unwrap();

    let values = peer
        .request_responses()
        .iter()
        .map(|response| serde_json::to_value(response).unwrap())
        .collect::<Vec<_>>();
    assert_eq!(values.len(), 3);
    assert_eq!(
        values[0].pointer("/error/data/category").unwrap(),
        "request_limit_exceeded"
    );
    assert_eq!(
        values[1].pointer("/error/data/category").unwrap(),
        "policy_denied"
    );
    assert_eq!(
        values[2].pointer("/error/data/category").unwrap(),
        "request_limit_exceeded"
    );
    assert!(handler.context_requests().is_empty());
    assert!(handler.specialist_requests().is_empty());
    assert_eq!(
        handler
            .audits()
            .iter()
            .map(|audit| (audit.kind, audit.decision, audit.reason_code.as_deref()))
            .collect::<Vec<_>>(),
        [
            (
                AgentRequestKind::ContextQuery,
                AgentRequestAuditDecision::Rejected,
                Some("request_limit_exceeded")
            ),
            (
                AgentRequestKind::SpecialistRequest,
                AgentRequestAuditDecision::Rejected,
                Some("request_limit_exceeded")
            )
        ]
    );
}

#[test]
fn handler_failure_returns_a_safe_typed_error_without_payload_leakage() {
    let store = Arc::new(RecordingStore::default());
    let artifacts = Arc::new(RecordingArtifacts::default());
    let clock = Arc::new(ManualClock::new(1_800_000_000));
    let mut descriptor = peer_descriptor();
    descriptor.capabilities.context_query = true;
    descriptor.capabilities.tool_requests = true;
    descriptor.capabilities.specialist_requests = true;
    let peer = Arc::new(ScriptedPeer::new(Script::Requesting, descriptor));
    let handler = Arc::new(RecordingRequestHandler::failing_context());
    let runtime = runtime_with_request_handler(
        Arc::clone(&store),
        artifacts,
        clock,
        Arc::clone(&peer),
        Arc::clone(&handler),
    );
    let mut request = run_request("run-1", None);
    request.run_config.limits.max_context_queries = 1;
    request.run_config.limits.max_specialist_requests = 1;
    runtime.start_run(request).unwrap();

    peer.drive().unwrap();

    let context = serde_json::to_value(&peer.request_responses()[0]).unwrap();
    assert_eq!(
        context.pointer("/error/data/category").unwrap(),
        "handler_failed"
    );
    let encoded = serde_json::to_string(&context).unwrap();
    assert!(!encoded.contains("sensitive handler payload"));
    assert_eq!(handler.audits().len(), 2);
    assert_eq!(
        handler.audits()[0].reason_code.as_deref(),
        Some("handler_failed")
    );
}

#[test]
fn handler_response_is_rejected_when_identity_or_item_budget_does_not_match() {
    let store = Arc::new(RecordingStore::default());
    let artifacts = Arc::new(RecordingArtifacts::default());
    let clock = Arc::new(ManualClock::new(1_800_000_000));
    let mut descriptor = peer_descriptor();
    descriptor.capabilities.context_query = true;
    descriptor.capabilities.tool_requests = true;
    descriptor.capabilities.specialist_requests = true;
    let peer = Arc::new(ScriptedPeer::new(Script::Requesting, descriptor));
    let handler = Arc::new(RecordingRequestHandler::invalid_context_response());
    let runtime = runtime_with_request_handler(
        store,
        artifacts,
        clock,
        Arc::clone(&peer),
        Arc::clone(&handler),
    );
    let mut request = run_request("run-1", None);
    request.run_config.limits.max_context_queries = 1;
    request.run_config.limits.max_specialist_requests = 1;
    runtime.start_run(request).unwrap();

    peer.drive().unwrap();

    let context = serde_json::to_value(&peer.request_responses()[0]).unwrap();
    assert_eq!(
        context.pointer("/error/data/category").unwrap(),
        "invalid_handler_response"
    );
    assert_eq!(
        handler.audits()[0].reason_code.as_deref(),
        Some("invalid_handler_response")
    );
}

#[test]
fn accepted_handler_result_is_not_disclosed_when_durable_audit_fails() {
    let store = Arc::new(RecordingStore::default());
    let artifacts = Arc::new(RecordingArtifacts::default());
    let clock = Arc::new(ManualClock::new(1_800_000_000));
    let mut descriptor = peer_descriptor();
    descriptor.capabilities.context_query = true;
    let peer = Arc::new(MultiRunPeer::new(descriptor));
    let handler = Arc::new(RecordingRequestHandler::failing_audit());
    let runtime = runtime_with_protocol_peer_and_handler(
        Arc::clone(&store),
        artifacts,
        clock,
        peer.clone(),
        Arc::clone(&handler),
    );
    let mut request = run_request("run-1", None);
    request.run_config.limits.max_context_queries = 1;
    runtime.start_run(request).unwrap();

    let response = peer
        .request(
            0,
            context_query_frame("agent:audit-failure", "run-1", "query-audit", 1),
        )
        .unwrap();
    assert_eq!(
        serde_json::to_value(response)
            .unwrap()
            .pointer("/error/data/category")
            .unwrap(),
        "internal_error"
    );
    assert_eq!(handler.context_requests().len(), 1);
    assert!(handler.audits().is_empty());
    assert_eq!(store.status("run-1"), Some(AgentRunStatus::Interrupted));
}

#[test]
fn initial_request_clock_failure_returns_no_unpersisted_response_and_poisoned_state_recovers() {
    let store = Arc::new(RecordingStore::default());
    let artifacts = Arc::new(RecordingArtifacts::default());
    let clock = Arc::new(ManualClock::new(1_800_000_000));
    let mut descriptor = peer_descriptor();
    descriptor.capabilities.context_query = true;
    let peer = Arc::new(MultiRunPeer::new(descriptor));
    let handler = Arc::new(RecordingRequestHandler::default());
    let runtime = runtime_with_protocol_peer_and_handler(
        store.clone(),
        artifacts,
        clock.clone(),
        peer.clone(),
        handler,
    );
    let mut request = run_request("run-1", None);
    request.run_config.limits.max_context_queries = 1;
    runtime.start_run(request).unwrap();
    clock.fail();

    assert!(matches!(
        peer.request(
            0,
            context_query_frame("agent:clock-initial", "run-1", "query-clock-initial", 1),
        ),
        Err(ProtocolError::InternalAgentFailure)
    ));
    assert_eq!(store.status("run-1"), Some(AgentRunStatus::Running));
    clock.recover();
    assert_eq!(runtime.check_timeouts().unwrap(), vec![run_id("run-1")]);
    assert_eq!(store.status("run-1"), Some(AgentRunStatus::Interrupted));
}

#[test]
fn response_clock_failure_after_accepted_audit_interrupts_the_run() {
    let store = Arc::new(RecordingStore::default());
    let artifacts = Arc::new(RecordingArtifacts::default());
    let clock = Arc::new(ManualClock::new(1_800_000_000));
    let mut descriptor = peer_descriptor();
    descriptor.capabilities.context_query = true;
    let peer = Arc::new(MultiRunPeer::new(descriptor));
    let handler = Arc::new(RecordingRequestHandler::failing_clock_after_audit(
        Arc::clone(&clock),
    ));
    let runtime = runtime_with_protocol_peer_and_handler(
        Arc::clone(&store),
        artifacts,
        clock,
        peer.clone(),
        Arc::clone(&handler),
    );
    let mut request = run_request("run-1", None);
    request.run_config.limits.max_context_queries = 1;
    runtime.start_run(request).unwrap();

    let result = peer.request(
        0,
        context_query_frame("agent:clock-failure", "run-1", "query-clock", 1),
    );

    let response = result.unwrap();
    assert_eq!(
        serde_json::to_value(response)
            .unwrap()
            .pointer("/error/data/category")
            .unwrap(),
        "internal_error"
    );
    assert_eq!(handler.audits().len(), 1);
    assert_eq!(
        handler.audits()[0].decision,
        AgentRequestAuditDecision::Accepted
    );
    assert_eq!(store.status("run-1"), Some(AgentRunStatus::Interrupted));
}

#[test]
fn handler_response_cannot_disclose_path_like_values_through_opaque_references() {
    let store = Arc::new(RecordingStore::default());
    let artifacts = Arc::new(RecordingArtifacts::default());
    let clock = Arc::new(ManualClock::new(1_800_000_000));
    let mut descriptor = peer_descriptor();
    descriptor.capabilities.context_query = true;
    let peer = Arc::new(MultiRunPeer::new(descriptor));
    let handler = Arc::new(RecordingRequestHandler::leaking_context_response());
    let runtime = runtime_with_protocol_peer_and_handler(
        store,
        artifacts,
        clock,
        peer.clone(),
        Arc::clone(&handler),
    );
    let mut request = run_request("run-1", None);
    request.run_config.limits.max_context_queries = 1;
    runtime.start_run(request).unwrap();

    let response = peer
        .request(
            0,
            context_query_frame("agent:leaking-query", "run-1", "query-leak", 1),
        )
        .unwrap();
    let encoded = serde_json::to_string(&response).unwrap();

    assert_eq!(
        serde_json::to_value(response)
            .unwrap()
            .pointer("/error/data/category")
            .unwrap(),
        "invalid_handler_response"
    );
    assert!(!encoded.contains("private"));
    assert_eq!(handler.audits().len(), 1);
}

#[test]
fn request_routing_rejects_cross_run_ownership_and_keeps_runs_isolated() {
    let store = Arc::new(RecordingStore::default());
    let artifacts = Arc::new(RecordingArtifacts::default());
    let clock = Arc::new(ManualClock::new(1_800_000_000));
    let mut descriptor = peer_descriptor();
    descriptor.capabilities.context_query = true;
    descriptor.capabilities.max_concurrent_runs = 2;
    let peer = Arc::new(MultiRunPeer::new(descriptor));
    let handler = Arc::new(RecordingRequestHandler::default());
    let runtime = runtime_with_protocol_peer_and_handler(
        Arc::clone(&store),
        artifacts,
        clock,
        peer.clone(),
        Arc::clone(&handler),
    );
    let mut first = run_request("run-1", None);
    first.run_config.limits.max_context_queries = 1;
    let mut second = run_request("run-2", None);
    second.task_id = task_id("task-2");
    second.context.task_id = task_id("task-2");
    second.run_config.task_id = task_id("task-2");
    second.idempotency_key = "task-2:reviewer:run-2".to_owned();
    second.run_config.limits.max_context_queries = 1;
    runtime.start_run(first).unwrap();
    runtime.start_run(second).unwrap();

    let response = peer
        .request(
            0,
            context_query_frame("agent:cross-run", "run-2", "query-cross-run", 1),
        )
        .unwrap();
    let value = serde_json::to_value(response).unwrap();

    assert_eq!(
        value.pointer("/error/data/category").unwrap(),
        "request_ownership_mismatch"
    );
    assert!(handler.context_requests().is_empty());
    let audits = handler.audits();
    assert_eq!(audits.len(), 1);
    assert_eq!(audits[0].run_id, run_id("run-1"));
    assert_eq!(audits[0].task_id, task_id("task-1"));
    assert_eq!(store.status("run-1"), Some(AgentRunStatus::Running));
    assert_eq!(store.status("run-2"), Some(AgentRunStatus::Running));
}

#[test]
fn concurrent_runs_have_independent_request_counters() {
    let store = Arc::new(RecordingStore::default());
    let artifacts = Arc::new(RecordingArtifacts::default());
    let clock = Arc::new(ManualClock::new(1_800_000_000));
    let mut descriptor = peer_descriptor();
    descriptor.capabilities.context_query = true;
    descriptor.capabilities.max_concurrent_runs = 2;
    let peer = Arc::new(MultiRunPeer::new(descriptor));
    let handler = Arc::new(RecordingRequestHandler::default());
    let runtime = runtime_with_protocol_peer_and_handler(
        store,
        artifacts,
        clock,
        peer.clone(),
        Arc::clone(&handler),
    );
    let mut first = run_request("run-1", None);
    first.run_config.limits.max_context_queries = 1;
    let mut second = run_request("run-2", None);
    second.run_config.limits.max_context_queries = 1;
    runtime.start_run(first).unwrap();
    runtime.start_run(second).unwrap();

    let first_response = peer
        .request(
            0,
            context_query_frame("agent:run-1-query", "run-1", "query-run-1", 1),
        )
        .unwrap();
    let second_response = peer
        .request(
            1,
            context_query_frame("agent:run-2-query", "run-2", "query-run-2", 1),
        )
        .unwrap();

    assert!(serde_json::to_value(first_response)
        .unwrap()
        .pointer("/result/queryId")
        .is_some());
    assert!(serde_json::to_value(second_response)
        .unwrap()
        .pointer("/result/queryId")
        .is_some());
    assert_eq!(
        handler
            .audits()
            .iter()
            .map(|audit| audit.run_id.clone())
            .collect::<Vec<_>>(),
        [run_id("run-1"), run_id("run-2")]
    );
}

#[test]
fn request_routing_rejects_duplicate_query_ids_and_context_token_overflow() {
    let store = Arc::new(RecordingStore::default());
    let artifacts = Arc::new(RecordingArtifacts::default());
    let clock = Arc::new(ManualClock::new(1_800_000_000));
    let mut descriptor = peer_descriptor();
    descriptor.capabilities.context_query = true;
    let peer = Arc::new(MultiRunPeer::new(descriptor));
    let handler = Arc::new(RecordingRequestHandler::default());
    let runtime = runtime_with_protocol_peer_and_handler(
        store,
        artifacts,
        clock,
        peer.clone(),
        Arc::clone(&handler),
    );
    let mut request = run_request("run-1", None);
    request.run_config.limits.max_context_queries = 3;
    runtime.start_run(request).unwrap();

    let accepted = peer
        .request(
            0,
            context_query_frame("agent:query-1", "run-1", "query-1", 1),
        )
        .unwrap();
    let duplicate = peer
        .request(
            0,
            context_query_frame("agent:query-2", "run-1", "query-1", 1),
        )
        .unwrap();
    let overflow = peer
        .request(
            0,
            context_query_frame("agent:query-3", "run-1", "query-3", 1_025),
        )
        .unwrap();

    assert_eq!(
        serde_json::to_value(accepted)
            .unwrap()
            .pointer("/result/queryId")
            .unwrap(),
        "query-1"
    );
    assert_eq!(
        serde_json::to_value(duplicate)
            .unwrap()
            .pointer("/error/data/category")
            .unwrap(),
        "duplicate_query_id"
    );
    assert_eq!(
        serde_json::to_value(overflow)
            .unwrap()
            .pointer("/error/data/category")
            .unwrap(),
        "context_token_limit_exceeded"
    );
    assert_eq!(handler.context_requests().len(), 1);
    assert_eq!(handler.audits().len(), 3);
}
