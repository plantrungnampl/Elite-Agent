
#[test]
fn sqlite_resume_rejects_a_request_artifact_owned_by_another_task() {
    let database = TempDatabase::new();
    seed_other_task(&database);
    let store = SqliteStore::open(&database.path).unwrap();
    let request = exact_tool_request("execution-resume-wrong-artifact-task");
    let immutable = canonical_tool_request(&request).unwrap();
    let artifact_id = ArtifactId::new("request-execution-resume-wrong-artifact-task").unwrap();
    persist_artifact_for_task(
        &database,
        "task-2",
        artifact_id.as_str(),
        "tool-requests/execution-resume-wrong-artifact-task.json",
        "tool-request",
        immutable.canonical_bytes(),
    );

    assert_integrity_failure(store.load_request_artifact(&artifact_id));
}

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
                    "SELECT status || ':' || attempt_count FROM operation_intents
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
        "CREATE TRIGGER injected BEFORE UPDATE ON approvals
         WHEN NEW.invalidation_reason = 'consumed'
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
                    "SELECT status || ':' || attempt_count FROM operation_intents
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
fn process_binding_faults_leave_the_execution_claimed_and_suspended() {
    let faults = [
        "CREATE TRIGGER injected BEFORE UPDATE ON operation_intents
         WHEN NEW.status = 'started'
         BEGIN SELECT RAISE(ABORT, 'fault'); END;",
        "CREATE TRIGGER injected BEFORE UPDATE ON tool_executions
         WHEN NEW.status = 'running'
         BEGIN SELECT RAISE(ABORT, 'fault'); END;",
        "CREATE TRIGGER injected BEFORE INSERT ON events
         WHEN NEW.event_type = 'tool.execution.started'
         BEGIN SELECT RAISE(ABORT, 'fault'); END;",
        "CREATE TRIGGER injected BEFORE UPDATE ON tasks
         WHEN NEW.operation_state = 'Running'
         BEGIN SELECT RAISE(ABORT, 'fault'); END;",
    ];
    for (index, trigger) in faults.into_iter().enumerate() {
        let database = TempDatabase::new();
        let execution_id = format!("execution-binding-fault-{index}");
        let (store, claim, _, _) = exact_approval_claim_fixture(&database, &execution_id);
        let ToolExecutionClaim::Claimed(authority) = store.begin_authorized(claim).unwrap() else {
            panic!("fresh authorized execution must win the durable claim");
        };
        configured_connection(&database.path)
            .execute_batch(trigger)
            .unwrap();

        assert!(
            store
                .record_process_binding(
                    AuthoritativeProcessBinding::new(authority, 4_242, "job-binding-fault")
                        .unwrap(),
                )
                .is_err(),
            "{trigger}"
        );

        let connection = configured_connection(&database.path);
        assert_eq!(
            connection
                .query_row(
                    "SELECT oi.status || ':' || te.status || ':' ||
                            (oi.external_receipt_json IS NULL)
                     FROM operation_intents oi
                     JOIN tool_executions te ON te.id = oi.id
                     WHERE oi.id = ?1",
                    [execution_id.as_str()],
                    |row| row.get::<_, String>(0),
                )
                .unwrap(),
            "claimed:pending:1",
            "{trigger}"
        );
        assert_eq!(
            connection
                .query_row(
                    "SELECT COUNT(*) FROM events
                     WHERE event_type = 'tool.execution.started'
                       AND json_extract(payload_json, '$.executionId') = ?1",
                    [execution_id.as_str()],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            0,
            "{trigger}"
        );
    }
}

#[test]
fn claimed_execution_can_resolve_no_effect_terminal_before_any_process_binding() {
    let terminals = [
        ("interrupted", ToolExecutionTerminal::interrupted()),
        (
            "indeterminate",
            ToolExecutionTerminal::indeterminate(SafeToolExecutionError {
                classification:
                    local_agent_terminal_application::SafeErrorClassification::Unavailable,
                retryability: local_agent_terminal_application::Retryability::Retryable,
            }),
        ),
    ];
    for (status, terminal) in terminals {
        let database = TempDatabase::new();
        let execution_id = format!("execution-{status}-before-binding");
        let (store, claim, _, _) = exact_approval_claim_fixture(&database, &execution_id);
        let ToolExecutionClaim::Claimed(authority) = store.begin_authorized(claim).unwrap() else {
            panic!("fresh authorized execution must win the durable claim");
        };
        let receipt = DurableToolExecutionReceipt::new(authority, terminal);

        assert_eq!(
            store
                .resolve_terminal(ToolExecutionResolution::new(receipt.clone()))
                .unwrap(),
            receipt
        );
        assert_eq!(
            store
                .resolve_terminal(ToolExecutionResolution::new(receipt.clone()))
                .unwrap(),
            receipt
        );
        assert_eq!(
            lifecycle_state(&database, &execution_id),
            format!("{status}:{status}")
        );
        assert_eq!(terminal_event_count(&database), 1);
    }
}

#[test]
fn quarantined_post_effect_receipt_round_trips_without_output_bytes() {
    let database = TempDatabase::new();
    let execution_id = "execution-quarantined-post-effect";
    let (store, claim, _, _) = exact_approval_claim_fixture(&database, execution_id);
    let ToolExecutionClaim::Claimed(authority) = store.begin_authorized(claim).unwrap() else {
        panic!("fresh authorized execution must win the durable claim");
    };
    let post_effect = ToolExecutionPostEffectReceipt {
        execution_id: authority.execution_id().clone(),
        status: ProcessStatus::Exited,
        exit_code: Some(0),
        stdout: ToolExecutionStreamMetadata {
            digest: digest_char('a'),
            size_bytes: 19,
            truncated: false,
        },
        stderr: ToolExecutionStreamMetadata {
            digest: digest_char('b'),
            size_bytes: 0,
            truncated: false,
        },
        duration_ms: 42,
        output_digest: digest_char('c'),
        observed_writes: vec![VerifiedWrite {
            digest: digest_char('d'),
            size_bytes: 13,
        }],
    };
    let receipt = DurableToolExecutionReceipt::from_post_effect_receipt(
        authority,
        post_effect,
        SafeToolExecutionError {
            classification:
                local_agent_terminal_application::SafeErrorClassification::PermissionDenied,
            retryability: local_agent_terminal_application::Retryability::NonRetryable,
        },
    )
    .unwrap();
    store
        .resolve_terminal(ToolExecutionResolution::new(receipt.clone()))
        .unwrap();

    let reopened = SqliteStore::open(&database.path).unwrap();
    let replayed = reopened
        .resolve_terminal(ToolExecutionResolution::new(receipt.clone()))
        .unwrap();
    assert_eq!(replayed, receipt);
    assert_eq!(replayed.terminal().output(), None);
    assert_eq!(
        replayed.terminal().post_effect().unwrap().stdout.size_bytes,
        19
    );
}

#[test]
fn quarantined_post_effect_receipt_rejects_an_inner_execution_id_mismatch() {
    let database = TempDatabase::new();
    let execution_id = "execution-quarantined-mismatched-inner-id";
    let (store, claim, _, _) = exact_approval_claim_fixture(&database, execution_id);
    let operation_digest = claim.request_content_digest.clone();
    let ToolExecutionClaim::Claimed(authority) = store.begin_authorized(claim).unwrap() else {
        panic!("fresh authorized execution must win the durable claim");
    };
    let receipt = DurableToolExecutionReceipt::from_post_effect_receipt(
        authority.clone(),
        ToolExecutionPostEffectReceipt {
            execution_id: authority.execution_id().clone(),
            status: ProcessStatus::Exited,
            exit_code: Some(0),
            stdout: ToolExecutionStreamMetadata {
                digest: digest_char('a'),
                size_bytes: 19,
                truncated: false,
            },
            stderr: ToolExecutionStreamMetadata {
                digest: digest_char('b'),
                size_bytes: 0,
                truncated: false,
            },
            duration_ms: 42,
            output_digest: digest_char('c'),
            observed_writes: Vec::new(),
        },
        SafeToolExecutionError {
            classification:
                local_agent_terminal_application::SafeErrorClassification::PermissionDenied,
            retryability: local_agent_terminal_application::Retryability::NonRetryable,
        },
    )
    .unwrap();
    store
        .resolve_terminal(ToolExecutionResolution::new(receipt))
        .unwrap();

    let connection = configured_connection(&database.path);
    let receipt_json: String = connection
        .query_row(
            "SELECT external_receipt_json FROM operation_intents WHERE id = ?1",
            [execution_id],
            |row| row.get(0),
        )
        .unwrap();
    let mut receipt_value: serde_json::Value = serde_json::from_str(&receipt_json).unwrap();
    receipt_value["terminal"]["postEffect"]["executionId"] =
        serde_json::json!("execution-substituted");
    let event_json: String = connection
        .query_row(
            "SELECT payload_json FROM events
             WHERE event_type = 'tool.execution.completed'
               AND json_extract(payload_json, '$.executionId') = ?1",
            [execution_id],
            |row| row.get(0),
        )
        .unwrap();
    let mut event_value: serde_json::Value = serde_json::from_str(&event_json).unwrap();
    event_value["receipt"] = receipt_value.clone();
    let error_json: String = connection
        .query_row(
            "SELECT error_json FROM operation_intents WHERE id = ?1",
            [execution_id],
            |row| row.get(0),
        )
        .unwrap();
    let mut error_value: serde_json::Value = serde_json::from_str(&error_json).unwrap();
    error_value["postEffect"]["executionId"] = serde_json::json!("execution-substituted");
    connection
        .execute_batch("DROP TRIGGER events_update_forbidden;")
        .unwrap();
    connection
        .execute(
            "UPDATE operation_intents
             SET external_receipt_json = ?1, error_json = ?2
             WHERE id = ?3",
            params![
                receipt_value.to_string(),
                error_value.to_string(),
                execution_id
            ],
        )
        .unwrap();
    connection
        .execute(
            "UPDATE events SET payload_json = ?1
             WHERE event_type = 'tool.execution.completed'
               AND json_extract(payload_json, '$.executionId') = ?2",
            params![event_value.to_string(), execution_id],
        )
        .unwrap();

    assert_integrity_failure(store.begin(NewToolExecution {
        execution_id: ToolExecutionId::new(execution_id).unwrap(),
        operation_digest,
    }));
}

#[test]
fn claimed_execution_cannot_resolve_success_before_a_process_binding() {
    let database = TempDatabase::new();
    let execution_id = "execution-success-before-binding";
    let (store, claim, _, _) = exact_approval_claim_fixture(&database, execution_id);
    let ToolExecutionClaim::Claimed(authority) = store.begin_authorized(claim).unwrap() else {
        panic!("fresh authorized execution must win the durable claim");
    };
    let before = durable_read_fingerprint(&database);
    let receipt = DurableToolExecutionReceipt::new(
        authority,
        terminal_fixture(ToolExecutionTerminalKind::Succeeded, digest_char('a'), None),
    );

    let error = store
        .resolve_terminal(ToolExecutionResolution::new(receipt))
        .expect_err("an unstarted process cannot report success");

    assert_eq!(
        error.safe_classification(),
        local_agent_terminal_application::SafeErrorClassification::Conflict
    );
    assert_eq!(durable_read_fingerprint(&database), before);
    assert_eq!(lifecycle_state(&database, execution_id), "pending:claimed");
    assert_eq!(terminal_event_count(&database), 0);
}

#[test]
fn claimed_terminal_faults_leave_the_execution_recoverable() {
    let faults = [
        "CREATE TRIGGER injected BEFORE UPDATE ON operation_intents
         WHEN NEW.status = 'interrupted'
         BEGIN SELECT RAISE(ABORT, 'fault'); END;",
        "CREATE TRIGGER injected BEFORE UPDATE ON tool_executions
         WHEN NEW.status = 'interrupted'
         BEGIN SELECT RAISE(ABORT, 'fault'); END;",
        "CREATE TRIGGER injected BEFORE INSERT ON events
         WHEN NEW.event_type = 'tool.execution.completed'
         BEGIN SELECT RAISE(ABORT, 'fault'); END;",
        "CREATE TRIGGER injected BEFORE UPDATE ON tasks
         WHEN NEW.current_sequence = OLD.current_sequence + 1
         BEGIN SELECT RAISE(ABORT, 'fault'); END;",
    ];
    for (index, trigger) in faults.into_iter().enumerate() {
        let database = TempDatabase::new();
        let execution_id = format!("execution-claimed-terminal-fault-{index}");
        let (store, claim, _, _) = exact_approval_claim_fixture(&database, &execution_id);
        let ToolExecutionClaim::Claimed(authority) = store.begin_authorized(claim).unwrap() else {
            panic!("fresh authorized execution must win the durable claim");
        };
        let before = durable_read_fingerprint(&database);
        configured_connection(&database.path)
            .execute_batch(trigger)
            .unwrap();
        let resolution = ToolExecutionResolution::new(DurableToolExecutionReceipt::new(
            authority,
            ToolExecutionTerminal::interrupted(),
        ));

        assert!(store.resolve_terminal(resolution).is_err(), "{trigger}");
        assert_eq!(durable_read_fingerprint(&database), before, "{trigger}");
        assert_eq!(lifecycle_state(&database, &execution_id), "pending:claimed");
        assert_eq!(terminal_event_count(&database), 0, "{trigger}");
        assert_eq!(store.incomplete().unwrap().len(), 1, "{trigger}");
    }
}

#[test]
fn begin_rejects_a_digest_other_than_the_reserved_canonical_intent() {
    let database = TempDatabase::new();
    let operation_digest = persist_request_artifact(&database);
    persist_policy_decision(&database.path, &operation_digest, "allow");
    let execution_id = ToolExecutionId::new("execution-digest-mismatch").unwrap();
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
        local_agent_terminal_application::SafeErrorClassification::Conflict
    );
    let connection = configured_connection(&database.path);
    assert_eq!(
        connection
            .query_row(
                "SELECT status || ':' || attempt_count
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
fn concurrent_exact_begin_has_one_claimant_and_one_in_flight_observer() {
    let database = TempDatabase::new();
    let operation_digest = persist_request_artifact(&database);
    persist_policy_decision(&database.path, &operation_digest, "allow");
    let store = SqliteStore::open(&database.path).unwrap();
    let execution_id = ToolExecutionId::new("execution-concurrent").unwrap();
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
        [
            first.join().unwrap().unwrap(),
            second.join().unwrap().unwrap(),
        ]
    });

    let claimed = outcomes
        .iter()
        .find_map(|outcome| match outcome {
            ToolExecutionClaim::Claimed(authority) => Some(authority),
            _ => None,
        })
        .expect("one caller must claim");
    let in_flight = outcomes
        .iter()
        .find_map(|outcome| match outcome {
            ToolExecutionClaim::InFlight(evidence) => Some(evidence),
            _ => None,
        })
        .expect("one caller must observe the durable claim");
    assert_eq!(claimed, &in_flight.authority);
    assert_eq!(claimed.execution_id(), &execution_id);
    assert_eq!(claimed.operation_digest(), &operation_digest);
    assert_eq!(claimed.owner_run_id().as_str(), "run-1");
    assert_eq!(claimed.attempt(), 1);
    assert_eq!(claimed.executor_fencing_token().unwrap().get(), 19);
    let connection = configured_connection(&database.path);
    let durable: (i64, i64, i64) = connection
        .query_row(
            "SELECT
                (SELECT COUNT(*) FROM tool_executions
                 WHERE id = 'execution-concurrent' AND status = 'running'),
                (SELECT COUNT(*) FROM events
                 WHERE event_type = 'tool.execution.started'),
                (SELECT attempt_count FROM operation_intents
                 WHERE id = 'execution-concurrent')",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap();
    assert_eq!(durable, (1, 1, 1));
}

#[test]
fn approval_required_begin_accepts_only_an_atomically_consumed_exact_grant() {
    let database = TempDatabase::new();
    let operation_digest = persist_request_artifact(&database);
    persist_policy_decision(&database.path, &operation_digest, "require_approval");
    let store = SqliteStore::open(&database.path).unwrap();
    let execution_id = ToolExecutionId::new("execution-approved").unwrap();
    store
        .reserve(NewToolIntent {
            execution_id: execution_id.clone(),
            operation_digest: operation_digest.clone(),
        })
        .unwrap();
    let error = store
        .begin(NewToolExecution {
            execution_id: execution_id.clone(),
            operation_digest: operation_digest.clone(),
        })
        .unwrap_err();
    assert_eq!(
        error.safe_classification(),
        local_agent_terminal_application::SafeErrorClassification::PermissionDenied
    );

    seed_consumed_approval(&database.path, &operation_digest, "9999-12-31T23:59:59Z");
    assert!(matches!(
        store
            .begin(NewToolExecution {
                execution_id,
                operation_digest,
            })
            .unwrap(),
        ToolExecutionClaim::Claimed(_)
    ));
}

#[test]
fn one_publicly_claimed_approval_authorizes_exactly_one_execution() {
    let database = TempDatabase::new();
    let store = SqliteStore::open(&database.path).unwrap();
    let ApprovalDigestPayload::Tool(mut payload) = parse_approval_payload(TOOL_FIXTURE).unwrap()
    else {
        unreachable!();
    };
    payload.requested_at = "2099-01-01T00:00:00Z".to_owned();
    payload.expires_at = "2099-01-01T01:00:00Z".to_owned();
    let canonical =
        canonical_approval_payload(&ApprovalDigestPayload::Tool(payload.clone())).unwrap();
    persist_artifact(
        &database,
        "approval-public",
        "approvals/approval-public.json",
        "tool-request",
        &canonical.canonical_bytes,
    );
    let approval_id = ApprovalId::new("approval-public").unwrap();
    let binding = ToolRequestBindingDigest::from_persisted(digest_char('f'));
    store
        .request(NewApproval {
            approval_id: approval_id.clone(),
            operation_digest: canonical.operation_digest.clone(),
            task_id: TaskId::new("task-1").unwrap(),
            workspace_version: WorkspaceVersion::new(payload.workspace_version),
            policy_snapshot_digest: Sha256Digest::new(payload.policy_snapshot_digest.clone())
                .unwrap(),
            fencing_token: payload.operation.executor_fencing_token,
            tool_request_binding_digest: Some(binding.clone()),
            expires_at: payload.expires_at.clone(),
            nonce: payload.nonce.clone(),
        })
        .unwrap();
    store
        .resolve(ApprovalResolution {
            approval_id: approval_id.clone(),
            approved: true,
        })
        .unwrap();
    store
        .claim(ApprovalClaim {
            approval_id,
            expected_operation_digest: canonical.operation_digest.clone(),
            task_id: TaskId::new("task-1").unwrap(),
            workspace_version: WorkspaceVersion::new(payload.workspace_version),
            policy_snapshot_digest: Sha256Digest::new(payload.policy_snapshot_digest).unwrap(),
            fencing_token: payload.operation.executor_fencing_token,
            tool_request_binding_digest: binding,
            nonce: payload.nonce,
            claimed_at: "2099-01-01T00:01:00Z".to_owned(),
        })
        .unwrap()
        .expect("approval claim");
    persist_policy_decision(
        &database.path,
        &canonical.operation_digest,
        "require_approval",
    );
    let execution_ids = [
        ToolExecutionId::new("execution-approved-first").unwrap(),
        ToolExecutionId::new("execution-approved-second").unwrap(),
    ];
    for execution_id in &execution_ids {
        store
            .reserve(NewToolIntent {
                execution_id: execution_id.clone(),
                operation_digest: canonical.operation_digest.clone(),
            })
            .unwrap();
    }
    let barrier = Arc::new(Barrier::new(2));

    let outcomes = std::thread::scope(|scope| {
        let mut handles = Vec::new();
        for execution_id in execution_ids {
            let store = store.clone();
            let barrier = Arc::clone(&barrier);
            let operation_digest = canonical.operation_digest.clone();
            handles.push(scope.spawn(move || {
                barrier.wait();
                store.begin(NewToolExecution {
                    execution_id,
                    operation_digest,
                })
            }));
        }
        handles
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .collect::<Vec<_>>()
    });
    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| matches!(outcome, Ok(ToolExecutionClaim::Claimed(_))))
            .count(),
        1
    );
    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| {
                outcome.as_ref().is_err_and(|error| {
                    error.safe_classification()
                        == local_agent_terminal_application::SafeErrorClassification::PermissionDenied
                })
            })
            .count(),
        1
    );
}

#[test]
fn expired_consumed_approval_cannot_begin() {
    let database = TempDatabase::new();
    let operation_digest = persist_request_artifact(&database);
    persist_policy_decision(&database.path, &operation_digest, "require_approval");
    seed_consumed_approval(&database.path, &operation_digest, "2000-01-01T00:00:00Z");
    let store = SqliteStore::open(&database.path).unwrap();
    let execution_id = ToolExecutionId::new("execution-expired-approval").unwrap();
    store
        .reserve(NewToolIntent {
            execution_id: execution_id.clone(),
            operation_digest: operation_digest.clone(),
        })
        .unwrap();

    let error = store
        .begin(NewToolExecution {
            execution_id,
            operation_digest,
        })
        .unwrap_err();
    assert_eq!(
        error.safe_classification(),
        local_agent_terminal_application::SafeErrorClassification::PermissionDenied
    );
}

#[test]
fn tool_execution_statuses_and_run_request_id_uniqueness_are_enforced() {
    let allowed = [
        ("pending", "running"),
        ("pending", "denied"),
        ("running", "succeeded"),
        ("running", "failed"),
        ("running", "cancelled"),
        ("running", "terminated"),
        ("running", "interrupted"),
        ("running", "indeterminate"),
        ("running", "denied"),
    ];
    let forbidden = [
        ("pending", "succeeded"),
        ("succeeded", "running"),
        ("failed", "pending"),
        ("cancelled", "running"),
        ("denied", "running"),
    ];
    let database = TempDatabase::new();
    let operation_digest = persist_request_artifact(&database);
    persist_policy_decision(&database.path, &operation_digest, "allow");
    let store = SqliteStore::open(&database.path).unwrap();
    for (index, (from, to)) in allowed.into_iter().enumerate() {
        insert_status_test_execution(
            &database,
            &store,
            &operation_digest,
            index,
            from,
            &format!("request-{index}"),
        )
        .unwrap();
        assert!(configured_connection(&database.path)
            .execute(
                "UPDATE tool_executions SET status = ?1 WHERE id = ?2",
                params![to, format!("status-execution-{index}")],
            )
            .is_ok());
    }
    for (offset, (from, to)) in forbidden.into_iter().enumerate() {
        let index = allowed.len() + offset;
        insert_status_test_execution(
            &database,
            &store,
            &operation_digest,
            index,
            from,
            &format!("request-{index}"),
        )
        .unwrap();
        assert!(configured_connection(&database.path)
            .execute(
                "UPDATE tool_executions SET status = ?1 WHERE id = ?2",
                params![to, format!("status-execution-{index}")],
            )
            .is_err());
    }
    let first_index = allowed.len() + forbidden.len();
    insert_status_test_execution(
        &database,
        &store,
        &operation_digest,
        first_index,
        "pending",
        "duplicate-request",
    )
    .unwrap();
    let duplicate = insert_status_test_execution(
        &database,
        &store,
        &operation_digest,
        first_index + 1,
        "pending",
        "duplicate-request",
    );
    assert!(duplicate.is_err());
}

#[test]
fn every_terminal_form_round_trips_exactly_across_retry_and_reopen() {
    for kind in [
        ToolExecutionTerminalKind::Succeeded,
        ToolExecutionTerminalKind::Failed,
        ToolExecutionTerminalKind::Cancelled,
        ToolExecutionTerminalKind::Terminated,
        ToolExecutionTerminalKind::Interrupted,
        ToolExecutionTerminalKind::Indeterminate,
    ] {
        let database = TempDatabase::new();
        let execution_name = format!("execution-{}", terminal_kind_label(kind));
        let (store, operation_digest, authority) = reserve_and_claim(&database, &execution_name);
        let (artifact_id, output_digest) =
            persist_durable_artifact(&database, &format!("artifact-{execution_name}"), b"output");
        let terminal = terminal_fixture(kind, output_digest, Some(artifact_id));
        let receipt = DurableToolExecutionReceipt::new(authority, terminal);
        let resolution = ToolExecutionResolution::new(receipt.clone());

        assert_eq!(store.resolve_terminal(resolution.clone()).unwrap(), receipt);
        assert_eq!(store.resolve_terminal(resolution).unwrap(), receipt);
        drop(store);

        let reopened = SqliteStore::open(&database.path).unwrap();
        assert_eq!(
            reopened
                .begin(NewToolExecution {
                    execution_id: ToolExecutionId::new(execution_name.clone()).unwrap(),
                    operation_digest,
                })
                .unwrap(),
            ToolExecutionClaim::Completed(receipt)
        );
        let connection = configured_connection(&database.path);
        let persisted: (i64, String) = connection
            .query_row(
                "SELECT
                    (SELECT COUNT(*) FROM events
                     WHERE event_type = 'tool.execution.completed'),
                    external_receipt_json
                 FROM operation_intents WHERE id = ?1",
                [execution_name],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(persisted.0, 1);
        for forbidden in ["rootPid", "jobId", "diagnostic", "canonicalPath"] {
            assert!(!persisted.1.contains(forbidden));
        }
    }
}

#[test]
fn terminal_retry_rejects_changed_terminal_or_any_changed_authority_field() {
    let database = TempDatabase::new();
    let (store, _, authority) = reserve_and_claim(&database, "execution-authority");
    let (artifact_id, output_digest) =
        persist_durable_artifact(&database, "authority-output", b"authority output");
    let succeeded = terminal_fixture(
        ToolExecutionTerminalKind::Succeeded,
        output_digest.clone(),
        Some(artifact_id.clone()),
    );
    let receipt = DurableToolExecutionReceipt::new(authority.clone(), succeeded);
    store
        .resolve_terminal(ToolExecutionResolution::new(receipt.clone()))
        .unwrap();

    let changed_terminal = DurableToolExecutionReceipt::new(
        authority.clone(),
        terminal_fixture(
            ToolExecutionTerminalKind::Failed,
            output_digest.clone(),
            Some(artifact_id),
        ),
    );
    assert_conflict(store.resolve_terminal(ToolExecutionResolution::new(changed_terminal)));
    let changed_authorities = [
        ToolExecutionClaimAuthority::from_persisted(
            ToolExecutionId::new("wrong-execution").unwrap(),
            authority.operation_digest().clone(),
            authority.owner_run_id().clone(),
            authority.attempt(),
            authority.executor_fencing_token(),
        )
        .unwrap(),
        ToolExecutionClaimAuthority::from_persisted(
            authority.execution_id().clone(),
            digest_char('0'),
            authority.owner_run_id().clone(),
            authority.attempt(),
            authority.executor_fencing_token(),
        )
        .unwrap(),
        ToolExecutionClaimAuthority::from_persisted(
            authority.execution_id().clone(),
            authority.operation_digest().clone(),
            RunId::new("wrong-run").unwrap(),
            authority.attempt(),
            authority.executor_fencing_token(),
        )
        .unwrap(),
        ToolExecutionClaimAuthority::from_persisted(
            authority.execution_id().clone(),
            authority.operation_digest().clone(),
            authority.owner_run_id().clone(),
            authority.attempt() + 1,
            authority.executor_fencing_token(),
        )
        .unwrap(),
        ToolExecutionClaimAuthority::from_persisted(
            authority.execution_id().clone(),
            authority.operation_digest().clone(),
            authority.owner_run_id().clone(),
            authority.attempt(),
            Some(FencingToken::new(20).unwrap()),
        )
        .unwrap(),
    ];
    for changed_authority in changed_authorities {
        let changed_receipt =
            DurableToolExecutionReceipt::new(changed_authority, receipt.terminal().clone());
        assert_conflict(store.resolve_terminal(ToolExecutionResolution::new(changed_receipt)));
    }
    assert_eq!(terminal_event_count(&database), 1);
}

#[test]
fn stale_authority_after_attempt_advance_cannot_commit_a_terminal_state() {
    let database = TempDatabase::new();
    let (store, _, authority) = reserve_and_claim(&database, "execution-stale-attempt");
    configured_connection(&database.path)
        .execute(
            "UPDATE operation_intents SET attempt_count = attempt_count + 1
             WHERE id = 'execution-stale-attempt'",
            [],
        )
        .unwrap();
    let receipt = DurableToolExecutionReceipt::new(authority, ToolExecutionTerminal::interrupted());

    assert_conflict(store.resolve_terminal(ToolExecutionResolution::new(receipt)));
    assert_eq!(
        lifecycle_state(&database, "execution-stale-attempt"),
        "running:started"
    );
    assert_eq!(terminal_event_count(&database), 0);
}

#[test]
fn terminal_artifact_references_must_be_available_and_owned_by_the_task() {
    for case in ["missing", "unavailable", "cross-task"] {
        let database = TempDatabase::new();
        let (store, _, authority) =
            reserve_and_claim(&database, &format!("execution-artifact-{case}"));
        let artifact_id = match case {
            "missing" => ArtifactId::new("missing-artifact").unwrap(),
            "unavailable" => {
                let (artifact_id, _) =
                    persist_durable_artifact(&database, "unavailable-artifact", b"unavailable");
                configured_connection(&database.path)
                    .execute(
                        "UPDATE artifacts SET availability = 'missing' WHERE id = ?1",
                        [artifact_id.as_str()],
                    )
                    .unwrap();
                artifact_id
            }
            "cross-task" => {
                seed_other_task(&database);
                let (artifact_id, _) = persist_durable_artifact_for_task(
                    &database,
                    "task-2",
                    "cross-task-artifact",
                    b"cross-task",
                );
                artifact_id
            }
            _ => unreachable!(),
        };
        let terminal = terminal_fixture(
            ToolExecutionTerminalKind::Succeeded,
            digest_bytes(case.as_bytes()),
            Some(artifact_id.clone()),
        );
        let receipt = DurableToolExecutionReceipt::new(authority, terminal);

        assert_integrity_failure(store.resolve_terminal(ToolExecutionResolution::new(receipt)));
        assert_eq!(
            lifecycle_state(&database, &format!("execution-artifact-{case}")),
            "running:started"
        );
        assert_eq!(terminal_event_count(&database), 0);
    }
}

#[test]
fn terminal_artifacts_require_verified_trust_on_commit_and_replay() {
    for verification_state in ["unverified", "rejected"] {
        let database = TempDatabase::new();
        let execution_id = format!("execution-{verification_state}-commit");
        let (store, _, authority) = reserve_and_claim(&database, &execution_id);
        let (artifact_id, output_digest) = persist_durable_artifact(
            &database,
            &format!("artifact-{verification_state}-commit"),
            b"commit trust",
        );
        configured_connection(&database.path)
            .execute(
                "UPDATE artifacts SET verification_state = ?1 WHERE id = ?2",
                params![verification_state, artifact_id.as_str()],
            )
            .unwrap();
        let receipt = DurableToolExecutionReceipt::new(
            authority,
            terminal_fixture(
                ToolExecutionTerminalKind::Succeeded,
                output_digest,
                Some(artifact_id),
            ),
        );

        assert_integrity_failure(store.resolve_terminal(ToolExecutionResolution::new(receipt)));
        assert_eq!(lifecycle_state(&database, &execution_id), "running:started");
        assert_eq!(terminal_event_count(&database), 0);

        let database = TempDatabase::new();
        let execution_id = format!("execution-{verification_state}-replay");
        let (store, operation_digest, authority) = reserve_and_claim(&database, &execution_id);
        let (artifact_id, output_digest) = persist_durable_artifact(
            &database,
            &format!("artifact-{verification_state}-replay"),
            b"replay trust",
        );
        let receipt = DurableToolExecutionReceipt::new(
            authority,
            terminal_fixture(
                ToolExecutionTerminalKind::Succeeded,
                output_digest,
                Some(artifact_id.clone()),
            ),
        );
        store
            .resolve_terminal(ToolExecutionResolution::new(receipt))
            .unwrap();
        configured_connection(&database.path)
            .execute(
                "UPDATE artifacts SET verification_state = ?1 WHERE id = ?2",
                params![verification_state, artifact_id.as_str()],
            )
            .unwrap();
        let before = durable_read_fingerprint(&database);

        assert_integrity_failure(store.begin(NewToolExecution {
            execution_id: ToolExecutionId::new(execution_id).unwrap(),
            operation_digest,
        }));
        assert_eq!(durable_read_fingerprint(&database), before);
        assert_eq!(terminal_event_count(&database), 1);
    }

    for verification_state in ["hash_verified", "tool_verified", "user_approved"] {
        let database = TempDatabase::new();
        let execution_id = format!("execution-{verification_state}-accepted");
        let (store, operation_digest, authority) = reserve_and_claim(&database, &execution_id);
        let (artifact_id, output_digest) = persist_durable_artifact(
            &database,
            &format!("artifact-{verification_state}-accepted"),
            b"accepted trust",
        );
        configured_connection(&database.path)
            .execute(
                "UPDATE artifacts SET verification_state = ?1 WHERE id = ?2",
                params![verification_state, artifact_id.as_str()],
            )
            .unwrap();
        let receipt = DurableToolExecutionReceipt::new(
            authority,
            terminal_fixture(
                ToolExecutionTerminalKind::Succeeded,
                output_digest,
                Some(artifact_id),
            ),
        );

        assert_eq!(
            store
                .resolve_terminal(ToolExecutionResolution::new(receipt.clone()))
                .unwrap(),
            receipt
        );
        assert_eq!(
            store
                .begin(NewToolExecution {
                    execution_id: ToolExecutionId::new(execution_id).unwrap(),
                    operation_digest,
                })
                .unwrap(),
            ToolExecutionClaim::Completed(receipt)
        );
    }
}
