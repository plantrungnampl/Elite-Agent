
#[test]
fn concurrent_authorized_begin_has_one_claimant_and_consumes_once() {
    let database = TempDatabase::new();
    let (store, claim, approval_id, _) =
        exact_approval_claim_fixture(&database, "execution-authorized-concurrent");
    let barrier = Arc::new(Barrier::new(2));

    let outcomes = std::thread::scope(|scope| {
        let first_store = store.clone();
        let first_barrier = Arc::clone(&barrier);
        let first_claim = claim.clone();
        let first = scope.spawn(move || {
            first_barrier.wait();
            first_store.begin_authorized(first_claim)
        });
        let second_store = store.clone();
        let second_barrier = Arc::clone(&barrier);
        let second = scope.spawn(move || {
            second_barrier.wait();
            second_store.begin_authorized(claim)
        });
        [
            first.join().unwrap().unwrap(),
            second.join().unwrap().unwrap(),
        ]
    });

    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| matches!(outcome, ToolExecutionClaim::Claimed(_)))
            .count(),
        1
    );
    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| matches!(outcome, ToolExecutionClaim::InFlight(_)))
            .count(),
        1
    );
    let connection = configured_connection(&database.path);
    assert_eq!(
        connection
            .query_row(
                "SELECT COUNT(*) FROM events
                 WHERE event_type = 'approval.consumed'
                   AND json_extract(payload_json, '$.approvalId') = ?1",
                [approval_id.as_str()],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
        1
    );
    assert_eq!(
        connection
            .query_row(
                "SELECT COUNT(*) FROM tool_executions
                 WHERE id = 'execution-authorized-concurrent' AND status = 'pending'",
                [],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
        1
    );
}

#[test]
fn authorized_replay_rejects_changed_approval_terms_with_the_same_id() {
    let database = TempDatabase::new();
    let (store, claim, approval_id, _) =
        exact_approval_claim_fixture(&database, "execution-changed-approval");
    assert!(matches!(
        store.begin_authorized(claim.clone()).unwrap(),
        ToolExecutionClaim::Claimed(_)
    ));

    let mut changed = claim;
    let approval = changed.approval.take().unwrap();
    let mut payload = approval.payload().clone();
    payload.nonce = "abcdef0123456789abcdef0123456789".to_owned();
    changed.approval = Some(
        ToolApprovalRequest::from_persisted(
            approval.approval_id().clone(),
            approval.approval_artifact_id().clone(),
            approval.execution_id().clone(),
            approval.policy_decision_id().clone(),
            approval.policy_request_binding_digest().clone(),
            approval.tool_request_artifact_id().clone(),
            approval.tool_request_binding_digest().clone(),
            payload,
        )
        .unwrap(),
    );

    assert!(store.begin_authorized(changed).is_err());
    assert_eq!(
        configured_connection(&database.path)
            .query_row(
                "SELECT COUNT(*) FROM events
                 WHERE stream_id = 'task-1' AND event_type = 'approval.consumed'
                   AND json_extract(payload_json, '$.approvalId') = ?1",
                [approval_id.as_str()],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
        1
    );
}

#[test]
fn authorized_begin_rejects_wrong_request_or_approval_artifact_kinds() {
    for approval_artifact in [false, true] {
        let database = TempDatabase::new();
        let execution_id = if approval_artifact {
            "execution-wrong-approval-kind"
        } else {
            "execution-wrong-request-kind"
        };
        let overrides = if approval_artifact {
            ExactApprovalArtifactOverrides {
                approval_artifact_type: Some("evidence"),
                ..Default::default()
            }
        } else {
            ExactApprovalArtifactOverrides {
                request_artifact_type: Some("evidence"),
                ..Default::default()
            }
        };
        let (store, claim, _, _) =
            exact_approval_claim_fixture_with_overrides(&database, execution_id, overrides);

        assert!(store.begin_authorized(claim).is_err());
        assert_eq!(
            configured_connection(&database.path)
                .query_row(
                    "SELECT status || ':' || current_attempt_no FROM operation_intents
                     WHERE id = ?1",
                    [execution_id],
                    |row| row.get::<_, String>(0),
                )
                .unwrap(),
            "pending:0"
        );
    }
}

#[test]
fn authorized_begin_fault_rolls_back_grant_and_execution_together() {
    let faults = [
        "CREATE TRIGGER injected BEFORE INSERT ON approval_effect_consumptions
         BEGIN SELECT RAISE(ABORT, 'fault'); END;",
        "CREATE TRIGGER injected BEFORE INSERT ON events
         WHEN NEW.event_type = 'approval.consumed'
         BEGIN SELECT RAISE(ABORT, 'fault'); END;",
        "CREATE TRIGGER injected BEFORE UPDATE ON tasks
         WHEN NEW.operation_state = 'None' AND NEW.current_sequence > OLD.current_sequence
         BEGIN SELECT RAISE(ABORT, 'fault'); END;",
        "CREATE TRIGGER injected BEFORE UPDATE ON operation_intents
         WHEN NEW.status = 'claimed'
         BEGIN SELECT RAISE(ABORT, 'fault'); END;",
        "CREATE TRIGGER injected BEFORE INSERT ON tool_executions
         WHEN NEW.status = 'pending'
         BEGIN SELECT RAISE(ABORT, 'fault'); END;",
    ];
    for (index, trigger) in faults.into_iter().enumerate() {
        let database = TempDatabase::new();
        let execution_id = format!("execution-approval-fault-{index}");
        let (store, claim, approval_id, _) = exact_approval_claim_fixture(&database, &execution_id);
        configured_connection(&database.path)
            .execute_batch(trigger)
            .unwrap();

        assert!(store.begin_authorized(claim).is_err(), "{trigger}");

        let connection = configured_connection(&database.path);
        assert_eq!(
            connection
                .query_row(
                    "SELECT status || ':' || COALESCE(invalidation_reason, '')
                     FROM approvals WHERE id = ?1",
                    [approval_id.as_str()],
                    |row| row.get::<_, String>(0),
                )
                .unwrap(),
            "granted:",
            "{trigger}"
        );
        assert_eq!(
            connection
                .query_row(
                    "SELECT status || ':' || current_attempt_no FROM operation_intents
                     WHERE id = ?1",
                    [execution_id],
                    |row| row.get::<_, String>(0),
                )
                .unwrap(),
            "pending:0",
            "{trigger}"
        );
        assert_eq!(
            connection
                .query_row("SELECT COUNT(*) FROM tool_executions", [], |row| {
                    row.get::<_, i64>(0)
                })
                .unwrap(),
            0,
            "{trigger}"
        );
        assert_eq!(
            connection
                .query_row(
                    "SELECT operation_state || ':' || current_sequence
                     FROM tasks WHERE id = 'task-1'",
                    [],
                    |row| row.get::<_, String>(0),
                )
                .unwrap(),
            "None:2",
            "{trigger}"
        );
    }
}

#[test]
fn legacy_begin_fails_closed_before_interpreting_a_changed_digest() {
    let database = TempDatabase::new();
    let execution_id = ToolExecutionId::new("execution-digest-mismatch").unwrap();
    let operation_digest = persist_request_artifact(&database, execution_id.as_str());
    persist_policy_decision(&database.path, &operation_digest, "allow");
    let store = SqliteStore::open(&database.path).unwrap();
    store
        .reserve(NewToolIntent {
            execution_id: execution_id.clone(),
            operation_digest: operation_digest.clone(),
        })
        .unwrap();

    let error = store
        .begin(NewToolExecution {
            execution_id,
            operation_digest: digest_char('0'),
        })
        .unwrap_err();

    assert_eq!(
        error.safe_classification(),
        local_agent_terminal_application::SafeErrorClassification::IntegrityFailure
    );
    let connection = configured_connection(&database.path);
    assert_eq!(
        connection
            .query_row(
                "SELECT status || ':' || current_attempt_no
                 FROM operation_intents WHERE id = 'execution-digest-mismatch'",
                [],
                |row| row.get::<_, String>(0),
            )
            .unwrap(),
        "pending:0"
    );
    assert_eq!(
        connection
            .query_row("SELECT COUNT(*) FROM tool_executions", [], |row| {
                row.get::<_, i64>(0)
            })
            .unwrap(),
        0
    );
}

#[test]
fn concurrent_legacy_begin_fails_closed_without_explicit_v7_authority() {
    let database = TempDatabase::new();
    let store = SqliteStore::open(&database.path).unwrap();
    let execution_id = ToolExecutionId::new("execution-concurrent").unwrap();
    let operation_digest = persist_request_artifact(&database, execution_id.as_str());
    persist_policy_decision(&database.path, &operation_digest, "allow");
    store
        .reserve(NewToolIntent {
            execution_id: execution_id.clone(),
            operation_digest: operation_digest.clone(),
        })
        .unwrap();
    let barrier = Arc::new(Barrier::new(2));

    let outcomes = std::thread::scope(|scope| {
        let first_store = store.clone();
        let first_barrier = Arc::clone(&barrier);
        let first_id = execution_id.clone();
        let first_digest = operation_digest.clone();
        let first = scope.spawn(move || {
            first_barrier.wait();
            first_store.begin(NewToolExecution {
                execution_id: first_id,
                operation_digest: first_digest,
            })
        });
        let second_store = store.clone();
        let second_barrier = Arc::clone(&barrier);
        let second_id = execution_id.clone();
        let second_digest = operation_digest.clone();
        let second = scope.spawn(move || {
            second_barrier.wait();
            second_store.begin(NewToolExecution {
                execution_id: second_id,
                operation_digest: second_digest,
            })
        });
        [first.join().unwrap(), second.join().unwrap()]
    });

    for outcome in outcomes {
        assert_integrity_failure(outcome);
    }
    let connection = configured_connection(&database.path);
    let durable: (i64, i64, i64) = connection
        .query_row(
            "SELECT
                (SELECT COUNT(*) FROM tool_executions
                 WHERE id = 'execution-concurrent'),
                (SELECT COUNT(*) FROM events
                 WHERE event_type = 'tool.execution.started'),
                (SELECT current_attempt_no FROM operation_intents
                 WHERE id = 'execution-concurrent')",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap();
    assert_eq!(durable, (0, 0, 0));
}


#[test]
fn terminal_receipt_without_v7_artifact_authority_fails_closed() {
    let database = TempDatabase::new();
    let execution_id = "execution-terminal-no-receipt-authority";
    let (store, claim, _, _) = exact_approval_claim_fixture(&database, execution_id);
    let ToolExecutionClaim::Claimed(authority) = store.begin_authorized(claim).unwrap() else {
        panic!("fresh authorized execution must win the durable claim");
    };
    let receipt = DurableToolExecutionReceipt::new(
        authority,
        ToolExecutionTerminal::interrupted(),
    );
    let before = durable_read_fingerprint(&database);

    assert_integrity_failure(store.resolve_terminal(ToolExecutionResolution::new(receipt)));
    assert_eq!(durable_read_fingerprint(&database), before);
    assert_eq!(lifecycle_state(&database, execution_id), "claimed:pending:claimed");
    assert_eq!(terminal_event_count(&database), 0);
}
