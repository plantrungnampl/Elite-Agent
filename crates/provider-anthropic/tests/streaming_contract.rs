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
use local_agent_terminal_provider_anthropic::{
    AnthropicApiKey, AnthropicMessagesAdapter, AnthropicProviderConfig, MAX_SSE_EVENT_BYTES,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use url::Url;

const API_KEY_CANARY: &str = "sk-streaming-canary";

#[test]
fn parses_documented_fragmented_messages_sequence_with_ping_usage_and_id() {
    let server = LoopbackServer::responding(sse_fragments(&[
        ": ignored comment\r\n\r\n",
        "event: ping\r\ndata: {\"type\":\"ping\"}\r\n\r\n",
        "event: message_start\r\ndata: {\"type\":\"message_start\",\"message\":{\"id\":\"msg-42\",\"usage\":{\"input_tokens\":3,\"output_tokens\":0}}}\r\n\r\n",
        "event: content_block_start\r\ndata: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"text\",\"text\":\"\"}}\r\n\r\n",
        "event: content_block_delta\r\ndata: {\"type\":\"content_block_delta\",\"index\":0,\r\n",
        "data: \"delta\":{\"type\":\"text_delta\",\"text\":\"first\"}}\r\n\r\n",
        "event: ping\r\ndata: {\"type\":\"ping\"}\r\n\r\n",
        "event: content_block_delta\r\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\" second\"}}\r\n\r\n",
        "event: content_block_stop\r\ndata: {\"type\":\"content_block_stop\",\"index\":0}\r\n\r\n",
        "event: message_delta\r\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\"},\"usage\":{\"output_tokens\":5}}\r\n\r\n",
        "event: message_stop\r\ndata: {\"type\":\"message_stop\"}\r\n\r\n",
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
        Some("msg-42")
    );
    assert_eq!(adapter.diagnostics()[0].error, None);

    adapter.shutdown().unwrap();
    server.join();
}

#[test]
fn terminal_message_ids_are_distinct_after_adapter_recreation() {
    let first_server =
        LoopbackServer::responding(successful_message_fragments("msg-first", "done"));
    let first_adapter = adapter(first_server.endpoint(), Duration::from_secs(1));
    let first_sink = RecordingSink::default();
    first_adapter
        .start(
            run_start("run-before-restart"),
            Box::new(first_sink.clone()),
        )
        .expect("first accepted run");
    let first_terminal = first_sink.wait_for_terminal();
    first_adapter.shutdown().expect("first adapter shutdown");
    first_server.join();

    let second_server =
        LoopbackServer::responding(successful_message_fragments("msg-second", "done"));
    let second_adapter = adapter(second_server.endpoint(), Duration::from_secs(1));
    let second_sink = RecordingSink::default();
    second_adapter
        .start(
            run_start("run-after-restart"),
            Box::new(second_sink.clone()),
        )
        .expect("second accepted run");
    let second_terminal = second_sink.wait_for_terminal();
    second_adapter.shutdown().expect("second adapter shutdown");
    second_server.join();

    let first_message_id = first_terminal
        .pointer("/params/message/messageId")
        .and_then(Value::as_str)
        .expect("first message ID");
    let second_message_id = second_terminal
        .pointer("/params/message/messageId")
        .and_then(Value::as_str)
        .expect("second message ID");
    assert_ne!(first_message_id, second_message_id);
    assert!(first_message_id.len() <= 256);
    assert!(second_message_id.len() <= 256);
}

#[test]
fn maps_anthropic_error_events_to_one_typed_failed_terminal() {
    for (run_id, event, expected_error) in [
        (
            "invalid-request",
            "event: error\ndata: {\"type\":\"error\",\"error\":{\"type\":\"invalid_request_error\",\"message\":\"bad request\"}}\n\n",
            ProtocolError::ProviderUnavailable,
        ),
        (
            "rate-limit",
            "event: error\ndata: {\"type\":\"error\",\"error\":{\"type\":\"rate_limit_error\",\"message\":\"slow down\"}}\n\n",
            ProtocolError::RateLimited,
        ),
        (
            "overloaded",
            "event: error\ndata: {\"type\":\"error\",\"error\":{\"type\":\"overloaded_error\",\"message\":\"busy\"}}\n\n",
            ProtocolError::ProviderUnavailable,
        ),
    ] {
        let server = LoopbackServer::responding(sse_fragments(&[event]));
        let adapter = adapter(server.endpoint(), Duration::from_secs(1));
        let sink = RecordingSink::default();

        adapter.start(run_start(run_id), Box::new(sink.clone())).unwrap();
        let terminal = sink.wait_for_terminal();

        assert_eq!(terminal.pointer("/params/status").and_then(Value::as_str), Some("failed"));
        assert_eq!(sink.terminal_count(), 1);
        assert_eq!(adapter.diagnostics()[0].error, Some(expected_error));
        assert_eq!(adapter.diagnostics()[0].response_id, None);
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
            sse_fragments(&["event: content_block_delta\ndata: {not-json}\n\n"]),
            ProtocolError::InvalidJson,
        ),
        (
            vec![oversized],
            ProtocolError::FrameTooLarge {
                max_frame_bytes: MAX_SSE_EVENT_BYTES,
            },
        ),
        (
            message_prefix_fragments("msg-eof", 1),
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
fn rejects_invalid_messages_order_ids_stops_usage_and_required_fields() {
    let mut conflicting_ids = message_prefix_fragments("msg-a", 1);
    conflicting_ids.push(
        b"event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"id\":\"msg-b\",\"usage\":{\"input_tokens\":1,\"output_tokens\":0}}}\n\n"
            .to_vec(),
    );

    let mut usage_regression = vec![
        b"event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"id\":\"msg-usage\",\"usage\":{\"input_tokens\":1,\"output_tokens\":2}}}\n\n"
            .to_vec(),
        message_prefix_fragments("unused", 1).remove(1),
        content_delta_fragment("text"),
    ];
    usage_regression.extend(message_suffix_fragments(1));

    let mut duplicate_block_stop = message_prefix_fragments("msg-block-stop", 1);
    duplicate_block_stop.push(content_delta_fragment("text"));
    duplicate_block_stop.extend(sse_fragments(&[
        "event: content_block_stop\ndata: {\"type\":\"content_block_stop\",\"index\":0}\n\n",
        "event: content_block_stop\ndata: {\"type\":\"content_block_stop\",\"index\":0}\n\n",
    ]));

    let mut duplicate_message_stop = successful_message_fragments("msg-message-stop", "text");
    duplicate_message_stop
        .push(b"event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n".to_vec());

    let invalid_utf8 = vec![b"event: message_start\ndata: \xff\n\n".to_vec()];
    let cases = vec![
        (
            "delta-before-start",
            vec![content_delta_fragment("early")],
            ProtocolError::InvalidRequest,
        ),
        (
            "conflicting-message-ids",
            conflicting_ids,
            ProtocolError::InvalidRequest,
        ),
        (
            "wrong-content-index",
            sse_fragments(&[
                "event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"id\":\"msg-index\",\"usage\":{\"input_tokens\":1,\"output_tokens\":0}}}\n\n",
                "event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":1,\"content_block\":{\"type\":\"text\",\"text\":\"\"}}\n\n",
            ]),
            ProtocolError::InvalidRequest,
        ),
        (
            "missing-delta-text",
            sse_fragments(&[
                "event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"id\":\"msg-missing\",\"usage\":{\"input_tokens\":1,\"output_tokens\":0}}}\n\n",
                "event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"text\",\"text\":\"\"}}\n\n",
                "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\"}}\n\n",
            ]),
            ProtocolError::InvalidJson,
        ),
        (
            "usage-regression",
            usage_regression,
            ProtocolError::InvalidRequest,
        ),
        (
            "duplicate-content-stop",
            duplicate_block_stop,
            ProtocolError::InvalidRequest,
        ),
        (
            "duplicate-message-stop",
            duplicate_message_stop,
            ProtocolError::InvalidRequest,
        ),
        (
            "unknown-required-event",
            sse_fragments(&[
                "event: future_required\ndata: {\"type\":\"future_required\",\"required\":true}\n\n",
            ]),
            ProtocolError::InvalidRequest,
        ),
        ("invalid-utf8", invalid_utf8, ProtocolError::InvalidUtf8),
    ];

    for (run_id, fragments, expected_error) in cases {
        let server = LoopbackServer::responding(fragments);
        let adapter = adapter(server.endpoint(), Duration::from_secs(1));
        let sink = RecordingSink::default();
        adapter
            .start(run_start(run_id), Box::new(sink.clone()))
            .unwrap();
        let terminal = sink.wait_for_terminal();

        assert_eq!(
            terminal.pointer("/params/status").and_then(Value::as_str),
            Some("failed"),
            "case {run_id} must fail"
        );
        assert_eq!(sink.terminal_count(), 1);
        assert_eq!(adapter.diagnostics()[0].error, Some(expected_error));
        adapter.shutdown().unwrap();
        server.join();
    }
}

#[test]
fn rejects_aggregate_output_before_growing_past_the_bound() {
    let chunk = "x".repeat(MAX_SSE_EVENT_BYTES / 2 + 1);
    let mut fragments = message_prefix_fragments("msg-aggregate", 1);
    fragments.push(content_delta_fragment(&chunk));
    fragments.push(content_delta_fragment(&chunk));
    let server = LoopbackServer::responding(fragments);
    let adapter = adapter(server.endpoint(), Duration::from_secs(1));
    let sink = RecordingSink::default();

    adapter
        .start(run_start("aggregate-limit"), Box::new(sink.clone()))
        .unwrap();
    let terminal = sink.wait_for_terminal();

    assert_eq!(
        terminal.pointer("/params/status").and_then(Value::as_str),
        Some("failed")
    );
    assert_eq!(
        adapter.diagnostics()[0].error,
        Some(ProtocolError::OutputLimitExceeded)
    );
    assert_eq!(sink.terminal_count(), 1);
    adapter.shutdown().unwrap();
    server.join();
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
        (
            "overloaded",
            529,
            Vec::<(String, String)>::new(),
            ProtocolError::ProviderUnavailable,
            None,
        ),
        (
            "malformed-retry-after",
            429,
            vec![("Retry-After".to_owned(), "not-a-date".to_owned())],
            ProtocolError::RateLimited,
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
    let before = message_prefix_fragments("msg-cancel", 1);
    let mut after = vec![content_delta_fragment("late")];
    after.extend(message_suffix_fragments(1));
    let mut server = LoopbackServer::gated(before, after);
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
    let mut before = message_prefix_fragments("msg-shutdown", 1);
    before.push(content_delta_fragment("early"));
    let mut server = LoopbackServer::gated(before, sse_fragments(&[": delayed\n"]));
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
fn concurrent_shutdown_callers_wait_for_the_authoritative_worker() {
    const SHUTDOWN_CALLERS: usize = 2;

    let mut before = message_prefix_fragments("msg-concurrent-shutdown", 1);
    before.push(content_delta_fragment("early"));
    let mut server = LoopbackServer::gated(before, sse_fragments(&[": delayed\n"]));
    let request_count = Arc::clone(&server.request_count);
    let adapter = Arc::new(adapter(server.endpoint(), Duration::from_secs(1)));
    let sink = BlockingSink::default();

    adapter
        .start(run_start("concurrent-shutdown"), Box::new(sink.clone()))
        .unwrap();
    server.wait_for_request();
    sink.wait_until_delta_delivery();

    let barrier = Arc::new(Barrier::new(SHUTDOWN_CALLERS + 1));
    let (entered, wait_for_entry) = mpsc::channel();
    let (completed, wait_for_completion) = mpsc::channel();
    let shutdowns = (0..SHUTDOWN_CALLERS)
        .map(|caller| {
            let adapter = Arc::clone(&adapter);
            let barrier = Arc::clone(&barrier);
            let entered = entered.clone();
            let completed = completed.clone();
            thread::spawn(move || {
                barrier.wait();
                entered.send(caller).unwrap();
                completed.send((caller, adapter.shutdown())).unwrap();
            })
        })
        .collect::<Vec<_>>();
    drop(entered);
    drop(completed);

    barrier.wait();
    for _ in 0..SHUTDOWN_CALLERS {
        wait_for_entry.recv_timeout(Duration::from_secs(1)).unwrap();
    }
    assert!(
        wait_for_completion
            .recv_timeout(Duration::from_millis(100))
            .is_err(),
        "a shutdown caller returned while the worker terminal was gated"
    );

    sink.release();
    server.release();
    let results = (0..SHUTDOWN_CALLERS)
        .map(|_| {
            wait_for_completion
                .recv_timeout(Duration::from_secs(1))
                .unwrap()
        })
        .collect::<Vec<_>>();
    for shutdown in shutdowns {
        shutdown.join().unwrap();
    }
    let terminal = sink.inner.wait_for_terminal();

    assert_eq!(request_count.load(Ordering::Relaxed), 1);
    assert_eq!(sink.inner.terminal_count(), 1);
    assert_eq!(
        terminal.pointer("/params/status").and_then(Value::as_str),
        Some("cancelled_cleanly")
    );
    assert!(results.into_iter().all(|(_, result)| result == Ok(())));
    assert!(
        !adapter
            .cancel(run_cancel("concurrent-shutdown"))
            .unwrap()
            .accepted
    );
    server.join();
}

#[test]
fn concurrent_shutdown_callers_share_the_authoritative_join_failure() {
    const SHUTDOWN_CALLERS: usize = 2;

    let mut fragments = message_prefix_fragments("msg-panic", 1);
    fragments.push(content_delta_fragment("panic"));
    let server = LoopbackServer::responding(fragments);
    let request_count = Arc::clone(&server.request_count);
    let adapter = Arc::new(adapter(server.endpoint(), Duration::from_secs(1)));
    let sink = BlockingSink::panicking_after_release();

    adapter
        .start(
            run_start("concurrent-shutdown-failure"),
            Box::new(sink.clone()),
        )
        .unwrap();
    server.wait_for_request();
    sink.wait_until_delta_delivery();

    let barrier = Arc::new(Barrier::new(SHUTDOWN_CALLERS + 1));
    let (entered, wait_for_entry) = mpsc::channel();
    let (completed, wait_for_completion) = mpsc::channel();
    let shutdowns = (0..SHUTDOWN_CALLERS)
        .map(|caller| {
            let adapter = Arc::clone(&adapter);
            let barrier = Arc::clone(&barrier);
            let entered = entered.clone();
            let completed = completed.clone();
            thread::spawn(move || {
                barrier.wait();
                entered.send(caller).unwrap();
                completed.send((caller, adapter.shutdown())).unwrap();
            })
        })
        .collect::<Vec<_>>();
    drop(entered);
    drop(completed);

    barrier.wait();
    for _ in 0..SHUTDOWN_CALLERS {
        wait_for_entry.recv_timeout(Duration::from_secs(1)).unwrap();
    }
    assert!(
        wait_for_completion
            .recv_timeout(Duration::from_millis(100))
            .is_err(),
        "a shutdown caller returned before the gated worker could panic"
    );

    sink.release();
    let results = (0..SHUTDOWN_CALLERS)
        .map(|_| {
            wait_for_completion
                .recv_timeout(Duration::from_secs(1))
                .unwrap()
        })
        .collect::<Vec<_>>();
    for shutdown in shutdowns {
        shutdown.join().unwrap();
    }

    assert_eq!(request_count.load(Ordering::Relaxed), 1);
    assert_eq!(sink.inner.deltas(), vec!["panic"]);
    assert!(results
        .into_iter()
        .all(|(_, result)| result == Err(ProtocolError::InternalAgentFailure)));
    assert_eq!(adapter.shutdown(), Err(ProtocolError::InternalAgentFailure));
    server.join();
}

#[test]
fn rejects_start_after_shutdown() {
    let adapter = adapter(
        Url::parse("http://127.0.0.1:9/v1/messages").unwrap(),
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
            successful_message_fragments("msg-success", "done"),
        ),
        (
            "terminal-failure",
            sse_fragments(&[
                "event: error\ndata: {\"type\":\"error\",\"error\":{\"type\":\"api_error\",\"message\":\"failed\"}}\n\n",
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

    let server = LoopbackServer::responding(successful_message_fragments("msg-concurrent", "done"));
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
fn unknown_required_content_or_missing_text_emits_one_failed_terminal() {
    let mut unknown_content = message_prefix_fragments("msg-tool", 1);
    unknown_content[1] = b"event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"tool_use\",\"id\":\"tool-1\",\"name\":\"unsafe\",\"input\":{}}}\n\n".to_vec();
    let mut missing_text = message_prefix_fragments("msg-empty", 1);
    missing_text.extend(message_suffix_fragments(0));

    for (run_id, fragments, response_id, expected_message) in [
        (
            "unknown-content",
            unknown_content,
            "msg-tool",
            "provider request failed",
        ),
        (
            "empty",
            missing_text,
            "msg-empty",
            "provider response contained no output text",
        ),
    ] {
        let server = LoopbackServer::responding(fragments);
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
        assert_eq!(
            terminal
                .pointer("/params/message/content")
                .and_then(Value::as_str)
                .unwrap(),
            expected_message
        );
        assert!(sink.deltas().is_empty());
        assert_eq!(
            adapter.diagnostics()[0].response_id.as_deref(),
            Some(response_id)
        );
        adapter.shutdown().unwrap();
        server.join();
    }
}

#[test]
fn sanitizes_api_key_reflected_by_provider_response_ids() {
    for (run_id, headers, fragments, expected_response_id) in [
        (
            "reflected-header-raw",
            vec![("x-request-id".to_owned(), API_KEY_CANARY.to_owned())],
            successful_message_fragments("msg-safe-raw", "ok"),
            Some("msg-safe-raw"),
        ),
        (
            "reflected-header-bearer",
            vec![(
                "x-request-id".to_owned(),
                format!("Bearer {API_KEY_CANARY}"),
            )],
            successful_message_fragments("msg-safe-bearer", "ok"),
            Some("msg-safe-bearer"),
        ),
        (
            "reflected-success-event",
            Vec::new(),
            successful_message_fragments(API_KEY_CANARY, "ok"),
            None,
        ),
    ] {
        let server = LoopbackServer::responding_with_headers(headers, fragments);
        let adapter = adapter(server.endpoint(), Duration::from_secs(1));
        let sink = RecordingSink::default();

        adapter
            .start(run_start(run_id), Box::new(sink.clone()))
            .unwrap();
        sink.wait_for_terminal();

        assert_eq!(
            adapter.diagnostics()[0].response_id.as_deref(),
            expected_response_id
        );
        assert!(!format!("{:?}", adapter.diagnostics()).contains(API_KEY_CANARY));
        assert!(!format!("{adapter:?}").contains(API_KEY_CANARY));
        adapter.shutdown().unwrap();
        server.join();
    }
}

fn adapter(endpoint: Url, read_timeout: Duration) -> AnthropicMessagesAdapter {
    AnthropicMessagesAdapter::new(
        AnthropicProviderConfig::for_loopback_test(
            endpoint,
            AnthropicApiKey::new(API_KEY_CANARY).unwrap(),
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
        protocol_version: "2.0".to_owned(),
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
            "taskId": "task-1",
            "contextPackageRef": "context-1",
            "idempotencyKey": format!("key-{run_id}"),
            "role": "critic",
        }
    }));
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

fn run_cancel(run_id: &str) -> RunCancel {
    RunCancel::try_from(decode(json!({
        "jsonrpc": "2.0",
        "id": format!("core:cancel-{run_id}"),
        "method": "agent.run.cancel",
        "params": { "runId": run_id, "reason": "test" }
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
        let value = frame_value(&frame);
        let result = json!({
            "runId": value.pointer("/params/runId").and_then(Value::as_str).unwrap(),
            "recorded": true,
            "terminalStatus": value.pointer("/params/status").and_then(Value::as_str).unwrap(),
        });
        self.record(frame);
        Ok(decode(
            json!({ "jsonrpc": "2.0", "id": id, "result": result }),
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
    panic_after_release: bool,
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
            panic_after_release: false,
        }
    }
}

impl BlockingSink {
    fn panicking_after_release() -> Self {
        Self {
            panic_after_release: true,
            ..Self::default()
        }
    }

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
            assert!(!self.panic_after_release, "test sink panics after release");
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
            "http://{}/v1/messages",
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
            for fragment in message_prefix_fragments("msg-comments", 1)
                .into_iter()
                .chain([content_delta_fragment("ready")])
            {
                stream.write_all(&fragment).unwrap();
            }
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
            "http://{}/v1/messages",
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

fn message_prefix_fragments(message_id: &str, input_tokens: u64) -> Vec<Vec<u8>> {
    vec![
        format!(
            "event: message_start\ndata: {{\"type\":\"message_start\",\"message\":{{\"id\":\"{message_id}\",\"usage\":{{\"input_tokens\":{input_tokens},\"output_tokens\":0}}}}}}\n\n"
        )
        .into_bytes(),
        b"event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"text\",\"text\":\"\"}}\n\n".to_vec(),
    ]
}

fn content_delta_fragment(text: &str) -> Vec<u8> {
    format!(
        "event: content_block_delta\ndata: {{\"type\":\"content_block_delta\",\"index\":0,\"delta\":{{\"type\":\"text_delta\",\"text\":{}}}}}\n\n",
        serde_json::to_string(text).unwrap()
    )
    .into_bytes()
}

fn message_suffix_fragments(output_tokens: u64) -> Vec<Vec<u8>> {
    vec![
        b"event: content_block_stop\ndata: {\"type\":\"content_block_stop\",\"index\":0}\n\n".to_vec(),
        format!(
            "event: message_delta\ndata: {{\"type\":\"message_delta\",\"delta\":{{\"stop_reason\":\"end_turn\"}},\"usage\":{{\"output_tokens\":{output_tokens}}}}}\n\n"
        )
        .into_bytes(),
        b"event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n".to_vec(),
    ]
}

fn successful_message_fragments(message_id: &str, text: &str) -> Vec<Vec<u8>> {
    let mut fragments = message_prefix_fragments(message_id, 3);
    fragments.push(content_delta_fragment(text));
    fragments.extend(message_suffix_fragments(5));
    fragments
}
