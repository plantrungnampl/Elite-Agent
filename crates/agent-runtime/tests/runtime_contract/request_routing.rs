
#[test]
fn request_routing_replays_exact_rpc_ids_and_rejects_conflicts_wrong_origins_and_terminal_runs() {
    let store = Arc::new(RecordingStore::default());
    let artifacts = Arc::new(RecordingArtifacts::default());
    let clock = Arc::new(ManualClock::new(1_800_000_000));
    let mut descriptor = peer_descriptor();
    descriptor.capabilities.context_query = true;
    let peer = Arc::new(MultiRunPeer::new(descriptor));
    let handler = Arc::new(RecordingRequestHandler::default());
    let runtime = runtime_with_protocol_peer_and_handler(
        Arc::clone(&store),
        artifacts,
        clock,
        peer.clone(),
        Arc::clone(&handler),
    );
    let mut request = run_request("run-1", None);
    request.run_config.limits.max_context_queries = 4;
    runtime.start_run(request).unwrap();

    let first = peer
        .request(
            0,
            context_query_frame("agent:duplicate-rpc", "run-1", "query-1", 1),
        )
        .unwrap();
    let replay = peer
        .request(
            0,
            context_query_frame("agent:duplicate-rpc", "run-1", "query-1", 1),
        )
        .unwrap();
    assert_eq!(
        serde_json::to_value(first).unwrap(),
        serde_json::to_value(replay).unwrap()
    );
    let conflict = peer
        .request(
            0,
            context_query_frame("agent:duplicate-rpc", "run-1", "query-2", 1),
        )
        .unwrap();
    let mut wrong_origin_frame = serde_json::to_value(context_query_frame(
        "agent:wrong-origin",
        "run-1",
        "query-3",
        1,
    ))
    .unwrap();
    wrong_origin_frame["id"] = serde_json::json!("core:wrong-origin");
    let wrong_origin = peer
        .request(0, deserialize_protocol_frame(wrong_origin_frame))
        .unwrap();
    peer.request(0, threaded_terminal("run-1")).unwrap();
    let after_terminal = peer
        .request(
            0,
            context_query_frame("agent:after-terminal", "run-1", "query-4", 1),
        )
        .unwrap();

    for (response, category) in [
        (conflict, "protocol_conflict"),
        (wrong_origin, "invalid_request_origin"),
        (after_terminal, "run_not_active"),
    ] {
        let value = serde_json::to_value(response).unwrap();
        assert_eq!(value.pointer("/error/data/category").unwrap(), category);
    }
    assert_eq!(handler.context_requests().len(), 1);
    assert_eq!(handler.audits().len(), 3);
    assert_eq!(store.status("run-1"), Some(AgentRunStatus::Succeeded));
}

#[test]
fn reconstructed_runtime_replays_terminal_responses_before_routing_and_rejects_tuple_drift() {
    let store = Arc::new(RecordingStore::default());
    let artifacts = Arc::new(RecordingArtifacts::default());
    let clock = Arc::new(ManualClock::new(1_800_000_000));
    let mut descriptor = peer_descriptor();
    descriptor.capabilities.context_query = true;
    descriptor.capabilities.max_concurrent_runs = 2;
    let first_peer = Arc::new(MultiRunPeer::new(descriptor.clone()));
    let handler = Arc::new(RecordingRequestHandler::default());
    let first_runtime = runtime_with_protocol_peer_and_handler(
        Arc::clone(&store),
        Arc::clone(&artifacts),
        Arc::clone(&clock),
        first_peer.clone(),
        Arc::clone(&handler),
    );
    let mut first_run = run_request("run-first", None);
    first_run.run_config.limits.max_context_queries = 2;
    first_runtime.start_run(first_run).unwrap();

    let request = context_query_frame("agent:restart-replay", "run-first", "query-1", 1);
    let first = first_peer.request(0, request.clone()).unwrap();
    let rejected = first_peer
        .request(0, tool_request_frame("agent:restart-rejected", "run-first"))
        .unwrap();
    assert_eq!(handler.context_requests().len(), 1);
    let audit_count = handler.audits().len();
    drop(first_runtime);

    let second_peer = Arc::new(MultiRunPeer::new(descriptor));
    let second_runtime = runtime_with_protocol_peer_and_handler(
        Arc::clone(&store),
        Arc::clone(&artifacts),
        clock,
        second_peer.clone(),
        Arc::clone(&handler),
    );
    let mut current_run = run_request("run-current", None);
    current_run.run_config.limits.max_context_queries = 2;
    second_runtime.start_run(current_run).unwrap();

    let replay = second_peer.request(0, request).unwrap();
    let rejected_replay = second_peer
        .request(0, tool_request_frame("agent:restart-rejected", "run-first"))
        .unwrap();
    let conflict = second_peer
        .request(
            0,
            context_query_frame("agent:restart-replay", "run-first", "changed-query", 1),
        )
        .unwrap();

    assert_eq!(
        serde_json::to_vec(&first).unwrap(),
        serde_json::to_vec(&replay).unwrap()
    );
    assert_eq!(
        serde_json::to_vec(&rejected).unwrap(),
        serde_json::to_vec(&rejected_replay).unwrap()
    );
    assert_eq!(handler.context_requests().len(), 1);
    assert_eq!(handler.audits().len(), audit_count);
    assert_eq!(
        serde_json::to_value(conflict)
            .unwrap()
            .pointer("/error/data/category")
            .unwrap(),
        "protocol_conflict"
    );
}

#[test]
fn terminal_response_is_not_returned_until_artifact_and_terminal_row_are_durable() {
    let log = script_log();
    let store = Arc::new(RecordingStore::new(Arc::clone(&log)));
    let artifacts = Arc::new(RecordingArtifacts::new(Arc::clone(&log)));
    let clock = Arc::new(ManualClock::new(1_800_000_000));
    let mut descriptor = peer_descriptor();
    descriptor.capabilities.context_query = true;
    let peer = Arc::new(MultiRunPeer::new(descriptor));
    let handler = Arc::new(RecordingRequestHandler::new(Arc::clone(&log)));
    let runtime = runtime_with_protocol_peer_and_handler(
        Arc::clone(&store),
        Arc::clone(&artifacts),
        clock,
        peer.clone(),
        Arc::clone(&handler),
    );
    let mut run = run_request("run-1", None);
    run.run_config.limits.max_context_queries = 1;
    runtime.start_run(run).unwrap();
    log.lock().unwrap().clear();
    store.fail_protocol_complete();

    let request = context_query_frame("agent:commit-order", "run-1", "query-1", 1);
    assert!(matches!(
        peer.request(0, request.clone()),
        Err(ProtocolError::InternalAgentFailure)
    ));
    assert_eq!(
        log.lock().unwrap().as_slice(),
        ["protocol.response.published", "request.effect.committed"]
    );

    store.allow_protocol_complete();
    assert!(matches!(
        peer.request(0, request),
        Err(ProtocolError::InternalAgentFailure)
    ));
    assert_eq!(
        log.lock().unwrap().as_slice(),
        [
            "protocol.response.published",
            "request.effect.committed"
        ]
    );
    assert_eq!(handler.context_requests().len(), 1);
    assert_eq!(handler.audits().len(), 1);
    assert!(store.protocol_request_is_pending("connection-1", "agent:commit-order"));
}

#[test]
fn response_artifact_failure_commits_no_agent_effect_and_pending_retry_fails_closed() {
    let log = script_log();
    let store = Arc::new(RecordingStore::new(Arc::clone(&log)));
    let artifacts = Arc::new(RecordingArtifacts::new(Arc::clone(&log)));
    let clock = Arc::new(ManualClock::new(1_800_000_000));
    let mut descriptor = peer_descriptor();
    descriptor.capabilities.context_query = true;
    let peer = Arc::new(MultiRunPeer::new(descriptor));
    let handler = Arc::new(RecordingRequestHandler::new(Arc::clone(&log)));
    let runtime = runtime_with_protocol_peer_and_handler(
        Arc::clone(&store),
        Arc::clone(&artifacts),
        clock,
        peer.clone(),
        Arc::clone(&handler),
    );
    let mut run = run_request("run-artifact-first", None);
    run.run_config.limits.max_context_queries = 1;
    runtime.start_run(run).unwrap();
    log.lock().unwrap().clear();
    artifacts.fail_protocol_response_publish();

    let request = context_query_frame(
        "agent:artifact-before-effect",
        "run-artifact-first",
        "query-artifact",
        1,
    );
    assert!(matches!(
        peer.request(0, request.clone()),
        Err(ProtocolError::InternalAgentFailure)
    ));
    assert!(handler.audits().is_empty());
    assert!(log.lock().unwrap().is_empty());

    artifacts.allow_protocol_response_publish();
    assert!(matches!(
        peer.request(0, request),
        Err(ProtocolError::InternalAgentFailure)
    ));
    assert_eq!(handler.context_requests().len(), 1);
    assert!(handler.audits().is_empty());
    assert!(log.lock().unwrap().is_empty());
    assert!(store.protocol_request_is_pending(
        "connection-1",
        "agent:artifact-before-effect"
    ));
}

#[test]
fn run_complete_pending_retry_fails_closed_without_recommitting_terminal() {
    let log = script_log();
    let store = Arc::new(RecordingStore::new(Arc::clone(&log)));
    let artifacts = Arc::new(RecordingArtifacts::new(Arc::clone(&log)));
    let peer = Arc::new(MultiRunPeer::new(peer_descriptor()));
    let protocol_peer: Arc<dyn ProtocolPeer> = peer.clone();
    let runtime = runtime_with_ports(
        Arc::clone(&store),
        Arc::clone(&artifacts),
        Arc::new(ManualClock::new(1_800_000_000)),
        vec![agent_registration(protocol_peer)],
    )
    .unwrap();
    runtime.start_run(run_request("run-terminal-retry", None)).unwrap();
    log.lock().unwrap().clear();
    store.fail_protocol_complete();

    let request = threaded_terminal("run-terminal-retry");
    assert!(matches!(
        peer.request(0, request.clone()),
        Err(ProtocolError::InternalAgentFailure)
    ));
    assert_eq!(store.terminal_count(), 1);
    assert_eq!(store.status("run-terminal-retry"), Some(AgentRunStatus::Succeeded));
    assert_eq!(
        log.lock().unwrap().as_slice(),
        [
            "protocol.response.published",
            "artifact.message.published",
            "store.terminal.committed"
        ]
    );

    store.allow_protocol_complete();
    assert!(matches!(
        peer.request(0, request),
        Err(ProtocolError::InternalAgentFailure)
    ));
    assert_eq!(store.terminal_count(), 1);
    assert_eq!(artifacts.published_contents().len(), 1);
    assert_eq!(
        log.lock().unwrap().as_slice(),
        [
            "protocol.response.published",
            "artifact.message.published",
            "store.terminal.committed"
        ]
    );
    assert!(store.protocol_request_is_pending(
        "connection-1",
        "agent:threaded-terminal"
    ));
}

#[test]
fn request_routing_rejects_context_after_the_bound_run_deadline() {
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
        Arc::clone(&clock),
        peer.clone(),
        Arc::clone(&handler),
    );
    let mut request = run_request("run-1", None);
    request.run_config.limits.max_context_queries = 1;
    runtime.start_run(request).unwrap();
    clock.advance(301);

    let response = peer
        .request(
            0,
            context_query_frame("agent:late-query", "run-1", "query-late", 1),
        )
        .unwrap();
    let value = serde_json::to_value(response).unwrap();

    assert_eq!(
        value.pointer("/error/data/category").unwrap(),
        "request_deadline_exceeded"
    );
    assert!(handler.context_requests().is_empty());
    assert_eq!(
        handler.audits()[0].reason_code.as_deref(),
        Some("request_deadline_exceeded")
    );
}

#[test]
fn slow_context_handler_cannot_disclose_success_after_the_run_deadline() {
    let store = Arc::new(RecordingStore::default());
    let artifacts = Arc::new(RecordingArtifacts::default());
    let clock = Arc::new(ManualClock::new(1_800_000_000));
    let mut descriptor = peer_descriptor();
    descriptor.capabilities.context_query = true;
    let peer = Arc::new(MultiRunPeer::new(descriptor));
    let (handler, handler_gate) = RecordingRequestHandler::blocking_context();
    let handler = Arc::new(handler);
    let runtime = runtime_with_protocol_peer_and_handler(
        store,
        artifacts,
        Arc::clone(&clock),
        peer.clone(),
        Arc::clone(&handler),
    );
    let mut request = run_request("run-1", None);
    request.run_config.limits.max_context_queries = 1;
    runtime.start_run(request).unwrap();

    let request_peer = peer.clone();
    let request_thread = thread::spawn(move || {
        request_peer.request(
            0,
            context_query_frame("agent:slow-query", "run-1", "query-slow", 1),
        )
    });
    handler_gate.wait_until_entered();
    clock.advance(301);
    let response = request_thread.join().unwrap().unwrap();
    handler_gate.release();
    let value = serde_json::to_value(response).unwrap();

    assert_eq!(
        value.pointer("/error/data/category").unwrap(),
        "request_deadline_exceeded"
    );
    let audits = handler.audits();
    assert_eq!(audits.len(), 1);
    assert_eq!(audits[0].decision, AgentRequestAuditDecision::Rejected);
}

#[test]
fn slow_context_handler_does_not_block_another_run_on_the_same_connection() {
    let store = Arc::new(RecordingStore::default());
    let artifacts = Arc::new(RecordingArtifacts::default());
    let clock = Arc::new(ManualClock::new(1_800_000_000));
    let mut descriptor = peer_descriptor();
    descriptor.capabilities.context_query = true;
    descriptor.capabilities.max_concurrent_runs = 2;
    let peer = Arc::new(MultiRunPeer::new(descriptor));
    let (handler, handler_gate) = RecordingRequestHandler::blocking_context();
    let handler = Arc::new(handler);
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

    let blocked_peer = peer.clone();
    let blocked = thread::spawn(move || {
        blocked_peer.request(
            0,
            context_query_frame("agent:blocked", "run-1", "query-slow", 1),
        )
    });
    assert!(handler_gate.wait_until_entered_for(Duration::from_secs(1)));
    let independent_peer = peer.clone();
    let (independent_sender, independent_receiver) = mpsc::channel();
    let independent_thread = thread::spawn(move || {
        let _ = independent_sender.send(independent_peer.request(
            1,
            context_query_frame("agent:independent", "run-2", "query-fast", 1),
        ));
    });
    let independent = match independent_receiver.recv_timeout(Duration::from_secs(1)) {
        Ok(result) => result.unwrap(),
        Err(error) => {
            handler_gate.release();
            panic!(
                "independent run was blocked: {error}; requests={:?}; audits={:?}",
                handler
                    .context_requests()
                    .iter()
                    .map(|request| request.query_id.as_str())
                    .collect::<Vec<_>>(),
                handler.audits()
            );
        }
    };
    handler_gate.release();
    blocked.join().unwrap().unwrap();
    independent_thread.join().unwrap();

    assert!(serde_json::to_value(independent)
        .unwrap()
        .pointer("/result/queryId")
        .is_some());
}

#[test]
fn late_specialist_worker_is_revoked_before_it_can_commit_or_audit_success() {
    let store = Arc::new(RecordingStore::default());
    let artifacts = Arc::new(RecordingArtifacts::default());
    let clock = Arc::new(ManualClock::new(1_800_000_000));
    let mut descriptor = peer_descriptor();
    descriptor.capabilities.specialist_requests = true;
    let peer = Arc::new(MultiRunPeer::new(descriptor));
    let (handler, specialist_gate) = RecordingRequestHandler::blocking_specialist();
    let handler = Arc::new(handler);
    let runtime = runtime_with_protocol_peer_and_handler(
        store.clone(),
        artifacts,
        clock.clone(),
        peer.clone(),
        Arc::clone(&handler),
    );
    let mut request = run_request("run-1", None);
    request.run_config.limits.max_specialist_requests = 1;
    request.run_config.limits.deadline = Timestamp::from_unix_seconds(1_800_000_300);
    runtime.start_run(request).unwrap();

    let request_peer = peer.clone();
    let (response_sender, response_receiver) = mpsc::channel();
    let request_thread = thread::spawn(move || {
        let _ = response_sender.send(request_peer.request(
            0,
            specialist_request_frame("agent:specialist-slow", "run-1", &["artifact-context-1"]),
        ));
    });
    assert!(specialist_gate.wait_until_entered_for(Duration::from_secs(1)));
    clock.advance(301);

    let response = match response_receiver.recv_timeout(Duration::from_secs(1)) {
        Ok(response) => response.unwrap(),
        Err(error) => {
            specialist_gate.release();
            request_thread.join().unwrap();
            panic!("specialist request exceeded its deadline: {error}");
        }
    };
    assert!(handler.specialist_requests()[0].cancellation.is_cancelled());
    assert_eq!(handler.audits().len(), 1);
    assert_eq!(
        handler.audits()[0].decision,
        AgentRequestAuditDecision::Rejected
    );
    specialist_gate.release();
    assert!(handler.wait_for_specialist_return(Duration::from_secs(1)));
    request_thread.join().unwrap();

    assert_eq!(
        serde_json::to_value(response)
            .unwrap()
            .pointer("/error/data/category")
            .unwrap(),
        "request_deadline_exceeded"
    );
    assert_eq!(handler.specialist_commits(), 0);
    assert_eq!(handler.audits().len(), 1);
}

#[test]
fn blocked_audit_is_revoked_at_deadline_and_cannot_commit_after_release() {
    let store = Arc::new(RecordingStore::default());
    let artifacts = Arc::new(RecordingArtifacts::default());
    let clock = Arc::new(ManualClock::new(1_800_000_000));
    let mut descriptor = peer_descriptor();
    descriptor.capabilities.context_query = true;
    let peer = Arc::new(MultiRunPeer::new(descriptor));
    let (handler, audit_gate) = RecordingRequestHandler::blocking_audit();
    let handler = Arc::new(handler);
    let runtime = runtime_with_protocol_peer_and_handler(
        store.clone(),
        artifacts,
        clock.clone(),
        peer.clone(),
        Arc::clone(&handler),
    );
    let mut request = run_request("run-1", None);
    request.run_config.limits.max_context_queries = 1;
    request.run_config.limits.deadline = Timestamp::from_unix_seconds(1_800_000_300);
    runtime.start_run(request).unwrap();

    let request_peer = peer.clone();
    let (response_sender, response_receiver) = mpsc::channel();
    let request_thread = thread::spawn(move || {
        let _ = response_sender.send(request_peer.request(
            0,
            context_query_frame("agent:audit-slow", "run-1", "query-audit", 1),
        ));
    });
    assert!(audit_gate.wait_until_entered_for(Duration::from_secs(1)));
    clock.advance(301);

    let response = match response_receiver.recv_timeout(Duration::from_secs(1)) {
        Ok(response) => response,
        Err(error) => {
            audit_gate.release();
            request_thread.join().unwrap();
            panic!("audit blocked the request past its deadline: {error}");
        }
    };
    assert_eq!(store.status("run-1"), Some(AgentRunStatus::Interrupted));
    assert!(handler.audits().is_empty());
    audit_gate.release();
    assert!(handler.wait_for_audit_return(Duration::from_secs(1)));
    request_thread.join().unwrap();

    assert!(matches!(response, Err(ProtocolError::InternalAgentFailure)));
    assert!(handler.audits().is_empty());
}

#[test]
fn claimed_audit_commit_finishes_before_the_runtime_responds() {
    let store = Arc::new(RecordingStore::default());
    let artifacts = Arc::new(RecordingArtifacts::default());
    let clock = Arc::new(ManualClock::new(1_800_000_000));
    let mut descriptor = peer_descriptor();
    descriptor.capabilities.context_query = true;
    let peer = Arc::new(MultiRunPeer::new(descriptor));
    let (handler, audit_commit_gate) = RecordingRequestHandler::blocking_audit_commit();
    let handler = Arc::new(handler);
    let runtime = runtime_with_protocol_peer_and_handler(
        store.clone(),
        artifacts,
        clock.clone(),
        peer.clone(),
        Arc::clone(&handler),
    );
    let mut request = run_request("run-1", None);
    request.run_config.limits.max_context_queries = 1;
    request.run_config.limits.deadline = Timestamp::from_unix_seconds(1_800_000_300);
    runtime.start_run(request).unwrap();

    let request_peer = peer.clone();
    let (response_sender, response_receiver) = mpsc::channel();
    let request_thread = thread::spawn(move || {
        let _ = response_sender.send(request_peer.request(
            0,
            context_query_frame("agent:audit-commit", "run-1", "query-audit", 1),
        ));
    });
    assert!(audit_commit_gate.wait_until_entered_for(Duration::from_secs(1)));
    clock.advance(301);

    assert!(matches!(
        response_receiver.recv_timeout(Duration::from_millis(50)),
        Err(mpsc::RecvTimeoutError::Timeout)
    ));
    assert!(handler.audits().is_empty());
    audit_commit_gate.release();
    assert!(handler.wait_for_audit_return(Duration::from_secs(1)));
    let response = response_receiver
        .recv_timeout(Duration::from_secs(1))
        .unwrap()
        .unwrap();
    request_thread.join().unwrap();

    assert!(serde_json::to_value(response)
        .unwrap()
        .pointer("/result/queryId")
        .is_some());
    assert_eq!(handler.audits().len(), 1);
    assert_eq!(
        handler.audits()[0].decision,
        AgentRequestAuditDecision::Accepted
    );
    assert_eq!(store.status("run-1"), Some(AgentRunStatus::Running));
}

#[test]
fn specialist_request_rejects_context_not_bound_to_the_parent_run() {
    let store = Arc::new(RecordingStore::default());
    let artifacts = Arc::new(RecordingArtifacts::default());
    let clock = Arc::new(ManualClock::new(1_800_000_000));
    let mut descriptor = peer_descriptor();
    descriptor.capabilities.specialist_requests = true;
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
    request.run_config.limits.max_specialist_requests = 1;
    runtime.start_run(request).unwrap();

    let response = peer
        .request(
            0,
            specialist_request_frame(
                "agent:specialist-unbound",
                "run-1",
                &["artifact-other-task"],
            ),
        )
        .unwrap();
    let value = serde_json::to_value(response).unwrap();

    assert_eq!(value.pointer("/result/decision").unwrap(), "rejected");
    assert_eq!(
        value.pointer("/result/specialistRunId").unwrap(),
        &serde_json::Value::Null
    );
    assert_eq!(handler.specialist_requests().len(), 1);
    assert_eq!(
        handler.specialist_requests()[0].deadline,
        Timestamp::from_unix_seconds(1_800_000_300)
    );
    assert_eq!(handler.audits().len(), 1);
    assert_eq!(
        handler.audits()[0].reason_code.as_deref(),
        Some("unrequested_context")
    );
}

#[test]
fn specialist_request_requires_context_bound_to_the_parent_run() {
    let store = Arc::new(RecordingStore::default());
    let artifacts = Arc::new(RecordingArtifacts::default());
    let clock = Arc::new(ManualClock::new(1_800_000_000));
    let mut descriptor = peer_descriptor();
    descriptor.capabilities.specialist_requests = true;
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
    request.run_config.limits.max_specialist_requests = 1;
    runtime.start_run(request).unwrap();

    let response = peer
        .request(
            0,
            specialist_request_frame("agent:specialist-empty", "run-1", &[]),
        )
        .unwrap();
    let value = serde_json::to_value(response).unwrap();

    assert_eq!(
        value.pointer("/error/data/category").unwrap(),
        "missing_required_context"
    );
    assert!(handler.specialist_requests().is_empty());
    assert_eq!(handler.audits().len(), 1);
}

#[test]
fn specialist_handler_reason_is_allowlisted_before_disclosure() {
    let store = Arc::new(RecordingStore::default());
    let artifacts = Arc::new(RecordingArtifacts::default());
    let clock = Arc::new(ManualClock::new(1_800_000_000));
    let mut descriptor = peer_descriptor();
    descriptor.capabilities.specialist_requests = true;
    let peer = Arc::new(MultiRunPeer::new(descriptor));
    let handler = Arc::new(RecordingRequestHandler::leaking_specialist_response());
    let runtime = runtime_with_protocol_peer_and_handler(
        store,
        artifacts,
        clock,
        peer.clone(),
        Arc::clone(&handler),
    );
    let mut request = run_request("run-1", None);
    request.run_config.limits.max_specialist_requests = 1;
    runtime.start_run(request).unwrap();

    let response = peer
        .request(
            0,
            specialist_request_frame("agent:specialist-leak", "run-1", &["artifact-context-1"]),
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
}

#[test]
fn deterministic_request_peers_cover_context_specialist_overflow_duplicate_and_cross_run() {
    for (script, context_limit, specialist_limit, expected_responses) in [
        (RequestScript::ContextQuery, 1, 0, 1),
        (RequestScript::SpecialistRequest, 0, 1, 1),
        (RequestScript::ContextOverflow, 1, 0, 1),
        (RequestScript::DuplicateContextQuery, 2, 0, 2),
        (RequestScript::CrossRun, 1, 0, 1),
    ] {
        let store = Arc::new(RecordingStore::default());
        let artifacts = Arc::new(RecordingArtifacts::default());
        let clock = Arc::new(ManualClock::new(1_800_000_000));
        let mut descriptor = peer_descriptor();
        descriptor.capabilities.context_query = true;
        descriptor.capabilities.specialist_requests = true;
        let peer = Arc::new(ScriptedPeer::new(
            Script::RequestingScenario(script),
            descriptor,
        ));
        let handler = Arc::new(RecordingRequestHandler::default());
        let runtime = runtime_with_request_handler(
            Arc::clone(&store),
            artifacts,
            clock,
            Arc::clone(&peer),
            Arc::clone(&handler),
        );
        let mut request = run_request("run-1", None);
        request.run_config.limits.max_context_queries = context_limit;
        request.run_config.limits.max_specialist_requests = specialist_limit;
        runtime.start_run(request).unwrap();

        peer.drive().unwrap();

        let responses = peer.request_responses();
        assert_eq!(responses.len(), expected_responses, "script {script:?}");
        assert_eq!(store.terminal_count(), 0, "script {script:?}");
        match script {
            RequestScript::ContextQuery => {
                assert_eq!(handler.context_requests().len(), 1);
                assert!(serde_json::to_value(&responses[0])
                    .unwrap()
                    .pointer("/result/queryId")
                    .is_some());
            }
            RequestScript::SpecialistRequest => {
                assert_eq!(handler.specialist_requests().len(), 1);
                assert_eq!(
                    serde_json::to_value(&responses[0])
                        .unwrap()
                        .pointer("/result/decision")
                        .unwrap(),
                    "accepted"
                );
            }
            RequestScript::ContextOverflow => assert_eq!(
                serde_json::to_value(&responses[0])
                    .unwrap()
                    .pointer("/error/data/category")
                    .unwrap(),
                "context_token_limit_exceeded"
            ),
            RequestScript::DuplicateContextQuery => assert_eq!(
                serde_json::to_value(&responses[1])
                    .unwrap()
                    .pointer("/error/data/category")
                    .unwrap(),
                "duplicate_query_id"
            ),
            RequestScript::CrossRun => {
                assert_eq!(store.status("run-1"), Some(AgentRunStatus::Running));
                assert_eq!(
                    serde_json::to_value(&responses[0])
                        .unwrap()
                        .pointer("/error/data/category")
                        .unwrap(),
                    "request_ownership_mismatch"
                );
                assert_eq!(handler.audits().len(), 1);
            }
        }
    }
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
            runtime_with_ports(
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
    let second_runtime = runtime_with_ports(
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
            runtime_with_ports(
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
