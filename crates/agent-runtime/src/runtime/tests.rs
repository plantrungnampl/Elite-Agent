
#[cfg(test)]
mod tests {
    use super::*;
    use local_agent_terminal_agent_protocol::{ConnectionBinding, ProtocolCapabilities};
    use std::sync::mpsc;

    #[test]
    fn initialized_frame_contains_only_the_v2_connection_identifier() {
        let descriptor = PeerDescriptor {
            protocol_version: "2.0".to_owned(),
            binding: ConnectionBinding {
                agent_id: "worker-1".to_owned(),
                connection_id: "connection-1".to_owned(),
                manifest_digest:
                    "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                        .to_owned(),
                executable_digest:
                    "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                        .to_owned(),
                trust_tier: ProtocolTrustTier::CoreAdapter,
            },
            capabilities: ProtocolCapabilities {
                roles: BTreeSet::from(["reviewer".to_owned()]),
                skills: BTreeSet::from(["testing".to_owned()]),
                streaming: true,
                context_query: false,
                tool_requests: false,
                specialist_requests: false,
                max_concurrent_runs: 1,
                max_context_tokens: 1024,
            },
        };

        let frame = initialized_frame(&descriptor).expect("initialized frame must encode");
        let frame_value = frame_value(&frame).expect("initialized frame must decode");
        assert_eq!(
            frame_value,
            json!({
                "jsonrpc": "2.0",
                "method": "initialized",
                "params": { "connectionId": "connection-1" }
            })
        );
    }

    #[test]
    fn retirement_invalidates_old_reservations_and_remains_permanent() {
        let slots = Arc::new(ConnectionSlots::default());
        let run_id = RunId::new("run-1").unwrap();
        let slot = slots
            .reserve("connection-1", "digest-1", &run_id, 1)
            .unwrap();
        slots.retire_connection("connection-1").unwrap();

        drop(slot);

        let state = slots.state.lock().unwrap();
        let lifecycle = state.connections.get("connection-1").unwrap();
        assert_eq!(lifecycle.phase, ConnectionPhase::Retired);
        assert!(lifecycle.reservations.is_empty());
        drop(state);
        assert!(slots
            .reserve("connection-1", "digest-1", &RunId::new("run-2").unwrap(), 1,)
            .is_err());
    }

    #[test]
    fn retirement_before_a_first_reservation_remains_permanent() {
        let slots = Arc::new(ConnectionSlots::default());

        slots.retire_connection("connection-1").unwrap();

        assert!(slots
            .reserve("connection-1", "digest-1", &RunId::new("run-1").unwrap(), 1,)
            .is_err());
    }

    #[test]
    fn poison_waits_for_an_in_flight_start_handoff() {
        let slots = Arc::new(ConnectionSlots::default());
        let slot = slots
            .reserve("connection-1", "digest-1", &RunId::new("run-1").unwrap(), 1)
            .unwrap();
        let (start_entered, start_entered_rx) = mpsc::channel();
        let (release_start, release_start_rx) = mpsc::channel();
        let starting_slots = Arc::clone(&slots);
        let starting_slot = slot.clone();
        let starting = thread::spawn(move || {
            starting_slots.start_handshake(&starting_slot, || {
                start_entered.send(()).unwrap();
                release_start_rx.recv().unwrap();
            })
        });
        start_entered_rx.recv().unwrap();
        let (poisoned, poisoned_rx) = mpsc::channel();
        let poisoning_slots = Arc::clone(&slots);
        let poisoning = thread::spawn(move || {
            let result = poisoning_slots.poison_connection("digest-1");
            poisoned.send(()).unwrap();
            result
        });

        let poisoned_during_start = poisoned_rx.recv_timeout(Duration::from_millis(50));
        release_start.send(()).unwrap();
        starting.join().unwrap().unwrap();
        if matches!(poisoned_during_start, Err(mpsc::RecvTimeoutError::Timeout)) {
            poisoned_rx.recv().unwrap();
        }
        let poison = poisoning.join().unwrap().unwrap();

        assert!(matches!(
            poisoned_during_start,
            Err(mpsc::RecvTimeoutError::Timeout)
        ));
        drop(slot);
        slots.complete_cleanup(&poison).unwrap();
        slots
            .reserve("connection-1", "digest-1", &RunId::new("run-2").unwrap(), 1)
            .unwrap();
    }

    #[test]
    fn stale_poison_retry_does_not_mutate_a_new_generation() {
        let slots = Arc::new(ConnectionSlots::default());
        let stale_slot = slots
            .reserve("connection-1", "digest-1", &RunId::new("run-1").unwrap(), 1)
            .unwrap();
        let poison_a = slots.poison_connection("digest-1").unwrap();
        let poison_b = poison_a.clone();
        let store_calls = Arc::new(AtomicU64::new(0));
        let (cleanup_entered, cleanup_entered_rx) = mpsc::channel();
        let (release_cleanup, release_cleanup_rx) = mpsc::channel();
        let cleanup_slots = Arc::clone(&slots);
        let cleanup_store_calls = Arc::clone(&store_calls);
        let cleanup = thread::spawn(move || {
            cleanup_slots.retry_poison(&poison_a, || {
                cleanup_entered.send(()).unwrap();
                release_cleanup_rx.recv().unwrap();
                cleanup_store_calls.fetch_add(1, Ordering::Relaxed);
                cleanup_slots.complete_cleanup(&poison_a)
            })
        });
        cleanup_entered_rx.recv().unwrap();
        release_cleanup.send(()).unwrap();
        assert_eq!(cleanup.join().unwrap().unwrap(), Some(()));

        let current_slot = slots
            .reserve("connection-1", "digest-1", &RunId::new("run-2").unwrap(), 1)
            .unwrap();
        assert_eq!(
            slots
                .retry_poison(&poison_b, || {
                    store_calls.fetch_add(1, Ordering::Relaxed);
                    slots.complete_cleanup(&poison_b)
                })
                .unwrap(),
            None
        );
        assert_eq!(store_calls.load(Ordering::Relaxed), 1);

        drop(stale_slot);
        let capacity_error =
            match slots.reserve("connection-1", "digest-1", &RunId::new("run-3").unwrap(), 1) {
                Ok(_) => panic!("current generation must keep its reservation"),
                Err(error) => error,
            };
        assert_eq!(
            capacity_error.safe_classification(),
            SafeErrorClassification::Conflict
        );
        drop(current_slot);
        slots
            .reserve("connection-1", "digest-1", &RunId::new("run-3").unwrap(), 1)
            .unwrap();
    }
}
