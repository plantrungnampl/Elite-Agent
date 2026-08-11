
#[test]
fn incomplete_is_a_pure_read_for_running_and_explicitly_indeterminate_records() {
    let database = TempDatabase::new();
    let operation_digest = persist_request_artifact(&database);
    persist_policy_decision(&database.path, &operation_digest, "allow");
    let store = SqliteStore::open(&database.path).unwrap();
    for execution_id in ["execution-in-flight", "execution-indeterminate"] {
        let execution_id = ToolExecutionId::new(execution_id).unwrap();
        store
            .reserve(NewToolIntent {
                execution_id: execution_id.clone(),
                operation_digest: operation_digest.clone(),
            })
            .unwrap();
        assert!(matches!(
            store
                .begin(NewToolExecution {
                    execution_id,
                    operation_digest: operation_digest.clone(),
                })
                .unwrap(),
            ToolExecutionClaim::Claimed(_)
        ));
    }
    configured_connection(&database.path)
        .execute_batch(
            "UPDATE operation_intents
             SET status = 'indeterminate',
                 error_json = '{\"classification\":\"crash_without_authoritative_receipt\"}'
             WHERE id = 'execution-indeterminate';
             UPDATE tool_executions
             SET status = 'indeterminate',
                 completed_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
             WHERE id = 'execution-indeterminate';",
        )
        .unwrap();
    let before = durable_read_fingerprint(&database);

    let first = store.incomplete().unwrap();
    let second = store.incomplete().unwrap();
    drop(store);
    let reopened = SqliteStore::open(&database.path).unwrap();
    let third = reopened.incomplete().unwrap();

    assert_eq!(first, second);
    assert_eq!(second, third);
    let IncompleteToolExecution::InFlight(in_flight) = &first[0] else {
        panic!("started execution must remain in flight");
    };
    assert_eq!(in_flight.state, ToolExecutionRecoveryState::Started);
    let IncompleteToolExecution::Indeterminate(indeterminate) = &first[1] else {
        panic!("indeterminate execution must retain its explicit state");
    };
    assert_eq!(
        indeterminate.state,
        ToolExecutionRecoveryState::Indeterminate
    );
    assert_eq!(durable_read_fingerprint(&database), before);
}

#[test]
fn historical_completed_receipt_replays_while_a_later_execution_is_running() {
    let database = TempDatabase::new();
    let operation_digest = persist_request_artifact(&database);
    persist_policy_decision(&database.path, &operation_digest, "allow");
    let store = SqliteStore::open(&database.path).unwrap();
    let execution_a = ToolExecutionId::new("execution-history-a").unwrap();
    store
        .reserve(NewToolIntent {
            execution_id: execution_a.clone(),
            operation_digest: operation_digest.clone(),
        })
        .unwrap();
    let ToolExecutionClaim::Claimed(authority_a) = store
        .begin(NewToolExecution {
            execution_id: execution_a.clone(),
            operation_digest: operation_digest.clone(),
        })
        .unwrap()
    else {
        panic!("execution A must be claimed");
    };
    let (artifact_id, output_digest) =
        persist_durable_artifact(&database, "history-a-output", b"history A");
    let receipt_a = DurableToolExecutionReceipt::new(
        authority_a,
        terminal_fixture(
            ToolExecutionTerminalKind::Succeeded,
            output_digest,
            Some(artifact_id),
        ),
    );
    store
        .resolve_terminal(ToolExecutionResolution::new(receipt_a.clone()))
        .unwrap();

    let execution_b = ToolExecutionId::new("execution-history-b").unwrap();
    store
        .reserve(NewToolIntent {
            execution_id: execution_b.clone(),
            operation_digest: operation_digest.clone(),
        })
        .unwrap();
    assert!(matches!(
        store
            .begin(NewToolExecution {
                execution_id: execution_b.clone(),
                operation_digest: operation_digest.clone(),
            })
            .unwrap(),
        ToolExecutionClaim::Claimed(_)
    ));

    let incomplete = store.incomplete().unwrap();
    assert_eq!(incomplete.len(), 1);
    assert!(matches!(
        &incomplete[0],
        IncompleteToolExecution::InFlight(evidence)
            if evidence.authority.execution_id() == &execution_b
    ));
    assert_eq!(
        store
            .begin(NewToolExecution {
                execution_id: execution_a,
                operation_digest,
            })
            .unwrap(),
        ToolExecutionClaim::Completed(receipt_a)
    );
}

#[test]
fn corrupted_current_head_terminal_projection_still_fails_closed() {
    for kind in [
        ToolExecutionTerminalKind::Succeeded,
        ToolExecutionTerminalKind::Indeterminate,
    ] {
        let database = TempDatabase::new();
        let execution_id = format!("execution-head-{}", terminal_kind_label(kind));
        let (store, operation_digest, authority) = reserve_and_claim(&database, &execution_id);
        let (artifact_id, output_digest) =
            persist_durable_artifact(&database, &format!("{execution_id}-output"), b"head");
        let receipt = DurableToolExecutionReceipt::new(
            authority,
            terminal_fixture(kind, output_digest, Some(artifact_id)),
        );
        store
            .resolve_terminal(ToolExecutionResolution::new(receipt))
            .unwrap();
        let corrupt_state = if kind == ToolExecutionTerminalKind::Indeterminate {
            "None"
        } else {
            "Indeterminate"
        };
        configured_connection(&database.path)
            .execute(
                "UPDATE tasks SET operation_state = ?1 WHERE id = 'task-1'",
                [corrupt_state],
            )
            .unwrap();
        let before = durable_read_fingerprint(&database);

        assert_integrity_failure(store.begin(NewToolExecution {
            execution_id: ToolExecutionId::new(execution_id).unwrap(),
            operation_digest,
        }));
        assert_eq!(durable_read_fingerprint(&database), before);
    }
}

#[test]
fn incomplete_fails_closed_when_candidate_idempotency_or_status_is_corrupt() {
    for corruption in [
        "UPDATE operation_intents SET idempotency_class = 'queryable'
         WHERE id = 'execution-corrupt-incomplete'",
        "DROP TRIGGER operation_intent_status_forward_only;
         UPDATE operation_intents SET status = 'claimed'
         WHERE id = 'execution-corrupt-incomplete'",
    ] {
        let database = TempDatabase::new();
        let (store, _, _) = reserve_and_claim(&database, "execution-corrupt-incomplete");
        configured_connection(&database.path)
            .execute_batch(corruption)
            .unwrap();
        let before = durable_read_fingerprint(&database);

        assert_integrity_failure(store.incomplete());
        assert_eq!(durable_read_fingerprint(&database), before);
    }
}

#[test]
fn indeterminate_terminal_projects_and_replays_unknown_operation_state() {
    let database = TempDatabase::new();
    let (store, operation_digest, authority) =
        reserve_and_claim(&database, "execution-indeterminate-projection");
    let receipt = DurableToolExecutionReceipt::new(
        authority,
        ToolExecutionTerminal::indeterminate(SafeToolExecutionError {
            classification: local_agent_terminal_application::SafeErrorClassification::Unavailable,
            retryability: local_agent_terminal_application::Retryability::Retryable,
        }),
    );

    assert_eq!(
        store
            .resolve_terminal(ToolExecutionResolution::new(receipt.clone()))
            .unwrap(),
        receipt
    );
    assert_eq!(
        configured_connection(&database.path)
            .query_row(
                "SELECT operation_state FROM tasks WHERE id = 'task-1'",
                [],
                |row| row.get::<_, String>(0),
            )
            .unwrap(),
        "Indeterminate"
    );
    assert_eq!(
        store
            .begin(NewToolExecution {
                execution_id: ToolExecutionId::new("execution-indeterminate-projection").unwrap(),
                operation_digest,
            })
            .unwrap(),
        ToolExecutionClaim::Completed(receipt)
    );
}

#[test]
fn missing_physical_artifact_file_rejects_terminal_commit_atomically() {
    let database = TempDatabase::new();
    let (store, _, authority) = reserve_and_claim(&database, "execution-missing-artifact-file");
    let (artifact_id, output_digest) =
        persist_durable_artifact(&database, "missing-file-artifact", b"missing file");
    fs::remove_file(artifact_file_path(&database, &artifact_id)).unwrap();
    let receipt = DurableToolExecutionReceipt::new(
        authority,
        terminal_fixture(
            ToolExecutionTerminalKind::Succeeded,
            output_digest,
            Some(artifact_id),
        ),
    );

    assert_integrity_failure(store.resolve_terminal(ToolExecutionResolution::new(receipt)));
    assert_eq!(
        lifecycle_state(&database, "execution-missing-artifact-file"),
        "running:started"
    );
    assert_eq!(terminal_event_count(&database), 0);
}

#[test]
fn tampered_physical_artifact_bytes_reject_terminal_commit_atomically() {
    let database = TempDatabase::new();
    let (store, _, authority) = reserve_and_claim(&database, "execution-tampered-artifact-commit");
    let (artifact_id, output_digest) =
        persist_durable_artifact(&database, "tampered-commit-artifact", b"original bytes");
    fs::write(
        artifact_file_path(&database, &artifact_id),
        b"tampered bytes",
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
    assert_eq!(
        lifecycle_state(&database, "execution-tampered-artifact-commit"),
        "running:started"
    );
    assert_eq!(terminal_event_count(&database), 0);
}

#[test]
fn tampered_physical_artifact_bytes_reject_terminal_replay() {
    let database = TempDatabase::new();
    let (store, operation_digest, authority) =
        reserve_and_claim(&database, "execution-tampered-artifact-file");
    let (artifact_id, output_digest) =
        persist_durable_artifact(&database, "tampered-file-artifact", b"original bytes");
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
    fs::write(
        artifact_file_path(&database, &artifact_id),
        b"tampered bytes",
    )
    .unwrap();
    let before = durable_read_fingerprint(&database);

    assert_integrity_failure(store.begin(NewToolExecution {
        execution_id: ToolExecutionId::new("execution-tampered-artifact-file").unwrap(),
        operation_digest,
    }));
    assert_eq!(durable_read_fingerprint(&database), before);
    assert_eq!(terminal_event_count(&database), 1);
}

#[test]
fn corrupt_persisted_identity_and_evidence_fail_closed_without_mutation() {
    let mutations = [
        "UPDATE tool_executions SET request_id = 'wrong-request'
         WHERE id = 'execution-corrupt'",
        "UPDATE operation_intents
         SET operation_digest = 'sha256:0000000000000000000000000000000000000000000000000000000000000000'
         WHERE id = 'execution-corrupt'",
        "UPDATE operation_intents SET attempt_count = 0
         WHERE id = 'execution-corrupt'",
        "UPDATE operation_intents SET attempt_count = 2
         WHERE id = 'execution-corrupt'",
        "UPDATE operation_intents SET executor_fencing_token = 18
         WHERE id = 'execution-corrupt'",
        "UPDATE operation_intents SET idempotency_class = 'queryable'
         WHERE id = 'execution-corrupt'",
        "UPDATE operation_intents SET canonical_request_artifact_id = 'corrupt-artifact'
         WHERE id = 'execution-corrupt'",
    ];
    for mutation in mutations {
        let database = TempDatabase::new();
        let (store, operation_digest, _) = reserve_and_claim(&database, "execution-corrupt");
        persist_durable_artifact(&database, "corrupt-artifact", b"wrong request");
        configured_connection(&database.path)
            .execute_batch(mutation)
            .unwrap();
        let before = durable_read_fingerprint(&database);

        assert_integrity_failure(store.begin(NewToolExecution {
            execution_id: ToolExecutionId::new("execution-corrupt").unwrap(),
            operation_digest,
        }));
        assert_eq!(durable_read_fingerprint(&database), before, "{mutation}");
    }

    let database = TempDatabase::new();
    let (store, operation_digest, authority) =
        reserve_and_claim(&database, "execution-corrupt-terminal");
    let receipt = DurableToolExecutionReceipt::new(authority, ToolExecutionTerminal::cancelled());
    store
        .resolve_terminal(ToolExecutionResolution::new(receipt))
        .unwrap();
    configured_connection(&database.path)
        .execute(
            "UPDATE operation_intents SET external_receipt_json = '{}'
             WHERE id = 'execution-corrupt-terminal'",
            [],
        )
        .unwrap();
    let before = durable_read_fingerprint(&database);
    assert_integrity_failure(store.begin(NewToolExecution {
        execution_id: ToolExecutionId::new("execution-corrupt-terminal").unwrap(),
        operation_digest,
    }));
    assert_eq!(durable_read_fingerprint(&database), before);

    let database = TempDatabase::new();
    let (store, operation_digest, authority) =
        reserve_and_claim(&database, "execution-corrupt-artifact-reference");
    let (expected_artifact, output_digest) =
        persist_durable_artifact(&database, "expected-artifact", b"expected");
    let (wrong_artifact, _) = persist_durable_artifact(&database, "wrong-artifact", b"wrong");
    let receipt = DurableToolExecutionReceipt::new(
        authority,
        terminal_fixture(
            ToolExecutionTerminalKind::Succeeded,
            output_digest,
            Some(expected_artifact),
        ),
    );
    store
        .resolve_terminal(ToolExecutionResolution::new(receipt))
        .unwrap();
    configured_connection(&database.path)
        .execute(
            "UPDATE tool_executions SET stdout_artifact_id = ?1
             WHERE id = 'execution-corrupt-artifact-reference'",
            [wrong_artifact.as_str()],
        )
        .unwrap();
    let before = durable_read_fingerprint(&database);
    assert_integrity_failure(store.begin(NewToolExecution {
        execution_id: ToolExecutionId::new("execution-corrupt-artifact-reference").unwrap(),
        operation_digest,
    }));
    assert_eq!(durable_read_fingerprint(&database), before);
}

#[test]
fn begin_and_terminal_statement_faults_leave_only_the_prior_durable_state() {
    let begin_faults = [
        "CREATE TRIGGER injected BEFORE UPDATE ON operation_intents
         WHEN NEW.status = 'started' BEGIN SELECT RAISE(ABORT, 'fault'); END;",
        "CREATE TRIGGER injected BEFORE INSERT ON tool_executions
         BEGIN SELECT RAISE(ABORT, 'fault'); END;",
        "CREATE TRIGGER injected BEFORE INSERT ON events
         WHEN NEW.event_type = 'tool.execution.started'
         BEGIN SELECT RAISE(ABORT, 'fault'); END;",
        "CREATE TRIGGER injected BEFORE UPDATE ON tasks
         WHEN NEW.operation_state = 'Running'
         BEGIN SELECT RAISE(ABORT, 'fault'); END;",
    ];
    for trigger in begin_faults {
        let database = TempDatabase::new();
        let operation_digest = persist_request_artifact(&database);
        persist_policy_decision(&database.path, &operation_digest, "allow");
        let store = SqliteStore::open(&database.path).unwrap();
        store
            .reserve(NewToolIntent {
                execution_id: ToolExecutionId::new("execution-begin-fault").unwrap(),
                operation_digest: operation_digest.clone(),
            })
            .unwrap();
        configured_connection(&database.path)
            .execute_batch(trigger)
            .unwrap();

        assert!(store
            .begin(NewToolExecution {
                execution_id: ToolExecutionId::new("execution-begin-fault").unwrap(),
                operation_digest,
            })
            .is_err());
        drop(store);
        let reopened = SqliteStore::open(&database.path).unwrap();
        assert_eq!(
            configured_connection(&database.path)
                .query_row(
                    "SELECT status || ':' || attempt_count
                     FROM operation_intents WHERE id = 'execution-begin-fault'",
                    [],
                    |row| row.get::<_, String>(0),
                )
                .unwrap(),
            "pending:0"
        );
        assert_eq!(reopened.incomplete().unwrap().len(), 0);
    }

    let terminal_faults = [
        "CREATE TRIGGER injected BEFORE UPDATE ON operation_intents
         WHEN NEW.status = 'succeeded' BEGIN SELECT RAISE(ABORT, 'fault'); END;",
        "CREATE TRIGGER injected BEFORE UPDATE ON tool_executions
         WHEN NEW.status = 'succeeded' BEGIN SELECT RAISE(ABORT, 'fault'); END;",
        "CREATE TRIGGER injected BEFORE INSERT ON events
         WHEN NEW.event_type = 'tool.execution.completed'
         BEGIN SELECT RAISE(ABORT, 'fault'); END;",
        "CREATE TRIGGER injected BEFORE UPDATE ON tasks
         WHEN OLD.operation_state = 'Running' AND NEW.operation_state = 'None'
         BEGIN SELECT RAISE(ABORT, 'fault'); END;",
    ];
    for trigger in terminal_faults {
        let database = TempDatabase::new();
        let (store, _, authority) = reserve_and_claim(&database, "execution-terminal-fault");
        let (artifact_id, digest) =
            persist_durable_artifact(&database, "terminal-fault-artifact", b"fault output");
        let receipt = DurableToolExecutionReceipt::new(
            authority,
            terminal_fixture(
                ToolExecutionTerminalKind::Succeeded,
                digest,
                Some(artifact_id),
            ),
        );
        configured_connection(&database.path)
            .execute_batch(trigger)
            .unwrap();

        assert!(store
            .resolve_terminal(ToolExecutionResolution::new(receipt))
            .is_err());
        drop(store);
        SqliteStore::open(&database.path).unwrap();
        assert_eq!(
            lifecycle_state(&database, "execution-terminal-fault"),
            "running:started"
        );
        assert_eq!(terminal_event_count(&database), 0);
    }
}

fn reserve_and_claim(
    database: &TempDatabase,
    execution_id: &str,
) -> (SqliteStore, Sha256Digest, ToolExecutionClaimAuthority) {
    let operation_digest = persist_request_artifact(database);
    persist_policy_decision(&database.path, &operation_digest, "allow");
    let store = SqliteStore::open(&database.path).unwrap();
    let execution_id = ToolExecutionId::new(execution_id).unwrap();
    store
        .reserve(NewToolIntent {
            execution_id: execution_id.clone(),
            operation_digest: operation_digest.clone(),
        })
        .unwrap();
    let claim = store
        .begin(NewToolExecution {
            execution_id,
            operation_digest: operation_digest.clone(),
        })
        .unwrap();
    let ToolExecutionClaim::Claimed(authority) = claim else {
        panic!("fresh reserved execution must be claimed");
    };
    (store, operation_digest, authority)
}

fn terminal_fixture(
    kind: ToolExecutionTerminalKind,
    output_digest: Sha256Digest,
    available_artifact: Option<ArtifactId>,
) -> ToolExecutionTerminal {
    let available = available_artifact
        .map(DurableToolExecutionArtifact::Available)
        .unwrap_or(DurableToolExecutionArtifact::Unavailable);
    let output = |exit_code| ToolExecutionOutput {
        exit_code,
        output_digest,
        duration_ms: 42,
        artifacts: DurableToolExecutionArtifacts::new(
            available.clone(),
            DurableToolExecutionArtifact::Unavailable,
            vec![available],
        ),
    };
    match kind {
        ToolExecutionTerminalKind::Succeeded => {
            ToolExecutionTerminal::succeeded(output(Some(0))).unwrap()
        }
        ToolExecutionTerminalKind::Failed => {
            ToolExecutionTerminal::failed(output(Some(7))).unwrap()
        }
        ToolExecutionTerminalKind::Terminated => {
            ToolExecutionTerminal::terminated(output(None)).unwrap()
        }
        ToolExecutionTerminalKind::Cancelled => ToolExecutionTerminal::cancelled(),
        ToolExecutionTerminalKind::Interrupted => ToolExecutionTerminal::interrupted(),
        ToolExecutionTerminalKind::Indeterminate => {
            ToolExecutionTerminal::indeterminate(SafeToolExecutionError {
                classification:
                    local_agent_terminal_application::SafeErrorClassification::Unavailable,
                retryability: local_agent_terminal_application::Retryability::Retryable,
            })
        }
    }
}

fn recovered_process_receipt(binding: &AuthoritativeProcessBinding) -> DurableToolExecutionReceipt {
    let cancellation = CancellationReceipt {
        execution_id: binding.authority().execution_id().clone(),
        status: ProcessStatus::Terminated,
        job_receipt: Some(JobReceipt {
            root_pid: binding.root_pid(),
            job_id: binding.job_id().to_owned(),
            kill_on_close: true,
            no_breakaway: true,
            job_memory_limit: true,
            job_cpu_time_limit: true,
            memory_limit_bytes: 64,
            cpu_time_limit_ms: 32,
            max_active_processes: 1,
            total_user_time_ms: 7,
            resource_limit_terminated: false,
            tree_terminated: true,
        }),
        cancelled: true,
    };
    let termination = AuthoritativeProcessTermination::new(binding.clone(), cancellation).unwrap();
    DurableToolExecutionReceipt::recovered_process_termination(
        local_agent_terminal_application::SafeErrorClassification::Unavailable,
        termination,
    )
}

fn terminal_kind_label(kind: ToolExecutionTerminalKind) -> &'static str {
    match kind {
        ToolExecutionTerminalKind::Succeeded => "succeeded",
        ToolExecutionTerminalKind::Failed => "failed",
        ToolExecutionTerminalKind::Cancelled => "cancelled",
        ToolExecutionTerminalKind::Terminated => "terminated",
        ToolExecutionTerminalKind::Interrupted => "interrupted",
        ToolExecutionTerminalKind::Indeterminate => "indeterminate",
    }
}

fn persist_durable_artifact(
    database: &TempDatabase,
    artifact_id: &str,
    bytes: &[u8],
) -> (ArtifactId, Sha256Digest) {
    persist_durable_artifact_for_task(database, "task-1", artifact_id, bytes)
}

fn persist_durable_artifact_for_task(
    database: &TempDatabase,
    task_id: &str,
    artifact_id: &str,
    bytes: &[u8],
) -> (ArtifactId, Sha256Digest) {
    persist_artifact_for_task(
        database,
        task_id,
        artifact_id,
        &format!("tool-output/{artifact_id}"),
        "tool-output",
        bytes,
    );
    (ArtifactId::new(artifact_id).unwrap(), digest_bytes(bytes))
}

fn artifact_file_path(database: &TempDatabase, artifact_id: &ArtifactId) -> PathBuf {
    let storage_key: String = configured_connection(&database.path)
        .query_row(
            "SELECT storage_key FROM artifacts WHERE id = ?1",
            [artifact_id.as_str()],
            |row| row.get(0),
        )
        .unwrap();
    database.directory.join(storage_key)
}

fn terminal_event_count(database: &TempDatabase) -> i64 {
    configured_connection(&database.path)
        .query_row(
            "SELECT COUNT(*) FROM events
             WHERE event_type = 'tool.execution.completed'",
            [],
            |row| row.get(0),
        )
        .unwrap()
}

fn lifecycle_state(database: &TempDatabase, execution_id: &str) -> String {
    configured_connection(&database.path)
        .query_row(
            "SELECT te.status || ':' || oi.status
             FROM tool_executions te
             JOIN operation_intents oi ON oi.id = te.operation_intent_id
             WHERE te.id = ?1",
            [execution_id],
            |row| row.get(0),
        )
        .unwrap()
}

fn durable_read_fingerprint(database: &TempDatabase) -> (i64, String) {
    configured_connection(&database.path)
        .query_row(
            "SELECT
                (SELECT current_sequence FROM tasks WHERE id = 'task-1'),
                group_concat(
                    oi.id || ':' || oi.status || ':' || te.status || ':' || oi.attempt_count,
                    '|'
                )
             FROM operation_intents oi
             JOIN tool_executions te ON te.operation_intent_id = oi.id
             ORDER BY oi.id",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap()
}

fn assert_conflict<T: std::fmt::Debug>(
    result: Result<T, local_agent_terminal_application::PortError>,
) {
    assert_eq!(
        result.unwrap_err().safe_classification(),
        local_agent_terminal_application::SafeErrorClassification::Conflict
    );
}

fn assert_integrity_failure<T: std::fmt::Debug>(
    result: Result<T, local_agent_terminal_application::PortError>,
) {
    assert_eq!(
        result.unwrap_err().safe_classification(),
        local_agent_terminal_application::SafeErrorClassification::IntegrityFailure
    );
}

#[test]
fn file_write_recovery_lifecycle_completes_with_workspace_mutation_atomically() {
    let database = TempDatabase::new();
    let store = SqliteStore::open(&database.path).unwrap();
    seed_pending_plan_approval(&database);
    let (intent, completion) = file_write_recovery(&database, "file-write-complete");

    let prepared = store.prepare(intent.clone()).unwrap();
    assert_eq!(prepared.state, FileWriteRecoveryState::Prepared);
    assert_eq!(store.prepare(intent).unwrap(), prepared);

    let started = store.start(&prepared.request.execution_id).unwrap();
    assert_eq!(started.state, FileWriteRecoveryState::Started);
    assert_eq!(
        store.start(&prepared.request.execution_id).unwrap(),
        started
    );

    let completed = store.complete(completion.clone()).unwrap();
    assert_eq!(completed.state, FileWriteRecoveryState::Completed);
    assert_eq!(store.complete(completion).unwrap(), completed);
    assert!(store.recover().unwrap().is_empty());

    let connection = configured_connection(&database.path);
    let state: (String, String, i64, i64, i64, String, String, String, i64) = connection
        .query_row(
            "SELECT t.phase, t.operation_state, t.workspace_version, t.fencing_epoch,
                    t.current_sequence, l.status, oi.status, te.status,
                    (SELECT COUNT(*) FROM approvals WHERE status = 'invalidated')
             FROM tasks t
             JOIN executor_leases l ON l.task_id = t.id
             JOIN operation_intents oi ON oi.task_id = t.id
             JOIN tool_executions te ON te.operation_intent_id = oi.id
             WHERE oi.id = 'file-write-complete'",
            [],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    row.get(6)?,
                    row.get(7)?,
                    row.get(8)?,
                ))
            },
        )
        .unwrap();
    assert_eq!(
        state,
        (
            "WorkspaceDirty".to_owned(),
            "None".to_owned(),
            5,
            20,
            3,
            "revoked".to_owned(),
            "succeeded".to_owned(),
            "succeeded".to_owned(),
            1,
        )
    );
}

#[test]
fn verified_compensation_is_idempotently_terminal_across_restart() {
    let database = TempDatabase::new();
    let store = SqliteStore::open(&database.path).unwrap();
    let (intent, _) = file_write_recovery(&database, "file-write-compensated");
    let execution_id = intent.request.execution_id.clone();
    let compensation = FileWriteRecoveryFailure::Compensated(
        VerifiedFileWriteCompensation::Restored(VerifiedWrite {
            digest: digest_bytes(b"old contents"),
            size_bytes: b"old contents".len() as u64,
        }),
    );
    store.prepare(intent).unwrap();
    store.start(&execution_id).unwrap();

    let terminal = store.fail(&execution_id, compensation.clone()).unwrap();

    assert_eq!(terminal.state, FileWriteRecoveryState::Compensated);
    assert_eq!(store.fail(&execution_id, compensation).unwrap(), terminal);
    assert!(store.recover().unwrap().is_empty());
    drop(store);

    let reopened = SqliteStore::open(&database.path).unwrap();
    assert!(reopened.recover().unwrap().is_empty());
    let connection = configured_connection(&database.path);
    let durable: (String, String, String, i64, String) = connection
        .query_row(
            "SELECT oi.status, te.status, oi.external_receipt_json,
                    (SELECT COUNT(*) FROM events
                     WHERE stream_id = 'task-1'
                       AND event_type = 'tool.execution.completed'),
                    (SELECT operation_state FROM tasks WHERE id = 'task-1')
             FROM operation_intents oi
             JOIN tool_executions te ON te.operation_intent_id = oi.id
             WHERE oi.id = 'file-write-compensated'",
            [],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                ))
            },
        )
        .unwrap();
    assert_eq!(durable.0, "failed");
    assert_eq!(durable.1, "failed");
    assert_eq!(durable.3, 1);
    assert_eq!(durable.4, "None");
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&durable.2).unwrap(),
        serde_json::json!({
            "executionId": "file-write-compensated",
            "outcome": "compensated",
            "schema": "file-write-terminal.v1",
        })
    );
}

#[test]
fn compensation_terminal_transaction_faults_leave_started_recoverable() {
    let triggers = [
        "CREATE TRIGGER injected BEFORE UPDATE ON operation_intents
         WHEN NEW.status = 'failed'
         BEGIN SELECT RAISE(ABORT, 'fault'); END;",
        "CREATE TRIGGER injected BEFORE UPDATE ON tool_executions
         WHEN NEW.status = 'failed'
         BEGIN SELECT RAISE(ABORT, 'fault'); END;",
        "CREATE TRIGGER injected BEFORE INSERT ON events
         WHEN NEW.event_type = 'tool.execution.completed'
         BEGIN SELECT RAISE(ABORT, 'fault'); END;",
        "CREATE TRIGGER injected BEFORE UPDATE ON tasks
         WHEN NEW.operation_state = 'None'
         BEGIN SELECT RAISE(ABORT, 'fault'); END;",
    ];
    for trigger in triggers {
        let database = TempDatabase::new();
        let store = SqliteStore::open(&database.path).unwrap();
        let (intent, _) = file_write_recovery(&database, "file-write-compensation-fault");
        let execution_id = intent.request.execution_id.clone();
        store.prepare(intent).unwrap();
        store.start(&execution_id).unwrap();
        configured_connection(&database.path)
            .execute_batch(trigger)
            .unwrap();
        let compensation = FileWriteRecoveryFailure::Compensated(
            VerifiedFileWriteCompensation::Restored(VerifiedWrite {
                digest: digest_bytes(b"old contents"),
                size_bytes: b"old contents".len() as u64,
            }),
        );

        assert!(
            store.fail(&execution_id, compensation).is_err(),
            "{trigger}"
        );

        let recoverable = store.recover().unwrap();
        assert_eq!(recoverable.len(), 1, "{trigger}");
        assert_eq!(
            recoverable[0].state,
            FileWriteRecoveryState::Started,
            "{trigger}"
        );
    }
}

#[test]
fn file_write_recovery_reopens_with_exact_preimage_and_never_redispatches() {
    let database = TempDatabase::new();
    let store = SqliteStore::open(&database.path).unwrap();
    let (intent, _) = file_write_recovery(&database, "file-write-reopen");
    let expected_request = intent.request.clone();
    store.prepare(intent).unwrap();
    store.start(&expected_request.execution_id).unwrap();
    drop(store);

    let reopened = SqliteStore::open(&database.path).unwrap();
    let recoverable = reopened.recover().unwrap();
    assert_eq!(recoverable.len(), 1);
    assert_eq!(recoverable[0].state, FileWriteRecoveryState::Started);
    assert_eq!(recoverable[0].request, expected_request);
    assert!(matches!(
        recoverable[0].request.pre_image,
        FileWritePreImage::Artifact(_)
    ));

    let indeterminate = reopened
        .mark_indeterminate(&recoverable[0].request.execution_id)
        .unwrap();
    assert_eq!(indeterminate.state, FileWriteRecoveryState::Indeterminate);
    let reopened_again = SqliteStore::open(&database.path).unwrap();
    assert_eq!(
        reopened_again.recover().unwrap()[0].state,
        FileWriteRecoveryState::Indeterminate
    );
}

#[test]
fn file_write_prepare_and_start_faults_leave_no_partial_lifecycle_state() {
    let prepare_triggers = [
        "CREATE TRIGGER injected BEFORE INSERT ON operation_intents
         WHEN NEW.operation_kind = 'file.write'
         BEGIN SELECT RAISE(ABORT, 'fault'); END;",
        "CREATE TRIGGER injected BEFORE INSERT ON tool_executions
         WHEN NEW.tool_name = 'file.write'
         BEGIN SELECT RAISE(ABORT, 'fault'); END;",
    ];
    for trigger in prepare_triggers {
        let database = TempDatabase::new();
        let store = SqliteStore::open(&database.path).unwrap();
        let (intent, _) = file_write_recovery(&database, "file-write-prepare-fault");
        configured_connection(&database.path)
            .execute_batch(trigger)
            .unwrap();

        assert!(store.prepare(intent).is_err(), "{trigger}");

        let connection = configured_connection(&database.path);
        assert_eq!(
            connection
                .query_row(
                    "SELECT (SELECT COUNT(*) FROM operation_intents)
                            + (SELECT COUNT(*) FROM tool_executions)",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            0,
            "{trigger}"
        );
    }

    let start_triggers = [
        "CREATE TRIGGER injected BEFORE UPDATE ON operation_intents
         WHEN NEW.operation_kind = 'file.write' AND NEW.status = 'started'
         BEGIN SELECT RAISE(ABORT, 'fault'); END;",
        "CREATE TRIGGER injected BEFORE UPDATE ON tool_executions
         WHEN NEW.tool_name = 'file.write' AND NEW.status = 'running'
         BEGIN SELECT RAISE(ABORT, 'fault'); END;",
        "CREATE TRIGGER injected BEFORE INSERT ON events
         WHEN NEW.event_type = 'tool.execution.started'
         BEGIN SELECT RAISE(ABORT, 'fault'); END;",
        "CREATE TRIGGER injected BEFORE UPDATE ON tasks
         WHEN NEW.operation_state = 'Running'
         BEGIN SELECT RAISE(ABORT, 'fault'); END;",
    ];
    for trigger in start_triggers {
        let database = TempDatabase::new();
        let store = SqliteStore::open(&database.path).unwrap();
        let (intent, _) = file_write_recovery(&database, "file-write-start-fault");
        let execution_id = intent.request.execution_id.clone();
        store.prepare(intent).unwrap();
        configured_connection(&database.path)
            .execute_batch(trigger)
            .unwrap();

        assert!(store.start(&execution_id).is_err(), "{trigger}");
        assert_eq!(
            store.recover().unwrap()[0].state,
            FileWriteRecoveryState::Prepared,
            "{trigger}"
        );

        let connection = configured_connection(&database.path);
        let state: (String, String, String, i64) = connection
            .query_row(
                "SELECT oi.status, te.status, t.operation_state, t.current_sequence
                 FROM operation_intents oi
                 JOIN tool_executions te ON te.operation_intent_id = oi.id
                 JOIN tasks t ON t.id = oi.task_id
                 WHERE oi.id = 'file-write-start-fault'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .unwrap();
        assert_eq!(
            state,
            (
                "pending".to_owned(),
                "pending".to_owned(),
                "None".to_owned(),
                0,
            ),
            "{trigger}"
        );
    }
}

#[test]
fn file_write_completion_faults_roll_back_mutation_and_terminal_receipt_together() {
    let triggers = [
        "CREATE TRIGGER injected BEFORE INSERT ON events
         WHEN NEW.event_type = 'workspace.mutated'
         BEGIN SELECT RAISE(ABORT, 'fault'); END;",
        "CREATE TRIGGER injected BEFORE UPDATE ON approvals
         WHEN NEW.status = 'invalidated'
         BEGIN SELECT RAISE(ABORT, 'fault'); END;",
        "CREATE TRIGGER injected BEFORE UPDATE ON executor_leases
         WHEN NEW.status = 'revoked'
         BEGIN SELECT RAISE(ABORT, 'fault'); END;",
        "CREATE TRIGGER injected BEFORE UPDATE ON operation_intents
         WHEN NEW.status = 'succeeded'
         BEGIN SELECT RAISE(ABORT, 'fault'); END;",
        "CREATE TRIGGER injected BEFORE UPDATE ON tool_executions
         WHEN NEW.status = 'succeeded'
         BEGIN SELECT RAISE(ABORT, 'fault'); END;",
        "CREATE TRIGGER injected BEFORE INSERT ON events
         WHEN NEW.event_type = 'tool.execution.completed'
         BEGIN SELECT RAISE(ABORT, 'fault'); END;",
    ];
    for trigger in triggers {
        let database = TempDatabase::new();
        let store = SqliteStore::open(&database.path).unwrap();
        seed_pending_plan_approval(&database);
        let (intent, completion) = file_write_recovery(&database, "file-write-fault");
        store.prepare(intent).unwrap();
        store
            .start(&ToolExecutionId::new("file-write-fault").unwrap())
            .unwrap();
        configured_connection(&database.path)
            .execute_batch(trigger)
            .unwrap();

        assert!(store.complete(completion).is_err(), "{trigger}");

        let connection = configured_connection(&database.path);
        let state: (
            String,
            String,
            i64,
            i64,
            i64,
            String,
            String,
            String,
            i64,
            i64,
        ) = connection
            .query_row(
                "SELECT t.phase, t.operation_state, t.workspace_version, t.fencing_epoch,
                        t.current_sequence, l.status, oi.status, te.status,
                        (SELECT COUNT(*) FROM approvals WHERE status = 'pending'),
                        (SELECT COUNT(*) FROM events
                         WHERE event_type IN ('workspace.mutated', 'tool.execution.completed'))
                 FROM tasks t
                 JOIN executor_leases l ON l.task_id = t.id
                 JOIN operation_intents oi ON oi.task_id = t.id
                 JOIN tool_executions te ON te.operation_intent_id = oi.id
                 WHERE oi.id = 'file-write-fault'",
                [],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                        row.get(6)?,
                        row.get(7)?,
                        row.get(8)?,
                        row.get(9)?,
                    ))
                },
            )
            .unwrap();
        assert_eq!(
            state,
            (
                "Implementation".to_owned(),
                "Running".to_owned(),
                4,
                19,
                1,
                "active".to_owned(),
                "started".to_owned(),
                "running".to_owned(),
                1,
                0,
            ),
            "{trigger}"
        );
    }
}

#[test]
fn file_write_prepare_rejects_policy_or_request_artifact_mismatch_without_rows() {
    for mutation in [
        "policy_task",
        "policy_digest",
        "policy_snapshot",
        "deny",
        "request_artifact_ref",
    ] {
        let database = TempDatabase::new();
        let store = SqliteStore::open(&database.path).unwrap();
        let (mut intent, _) = file_write_recovery(&database, "file-write-policy");
        match mutation {
            "policy_task" => {
                seed_other_task(&database);
                intent.request.policy.decision_id = "policy-wrong-task".to_owned();
                persist_file_policy_decision(
                    &database.path,
                    "policy-wrong-task",
                    "task-2",
                    &intent.request.policy.operation_digest,
                    &intent.request.policy.policy_snapshot_digest,
                    "allow",
                );
            }
            "policy_digest" => {
                intent.request.policy.operation_digest = digest_char('8');
            }
            "policy_snapshot" => {
                intent.request.policy.policy_snapshot_digest = digest_char('9');
            }
            "deny" => {
                intent.request.policy.decision_id = "policy-deny".to_owned();
                intent.request.policy.effect = PolicyEffect::Deny;
                persist_file_policy_decision(
                    &database.path,
                    "policy-deny",
                    "task-1",
                    &intent.request.policy.operation_digest,
                    &intent.request.policy.policy_snapshot_digest,
                    "deny",
                );
            }
            "request_artifact_ref" => {}
            _ => unreachable!(),
        }
        intent.request_artifact = persist_recovery_request_artifact(
            &database,
            &intent.request,
            &format!("request-{mutation}"),
        );
        if mutation == "request_artifact_ref" {
            intent.request_artifact.storage_key.push_str(".wrong");
        }

        assert!(store.prepare(intent).is_err(), "{mutation}");
        let connection = configured_connection(&database.path);
        assert_eq!(
            connection
                .query_row(
                    "SELECT (SELECT COUNT(*) FROM operation_intents)
                            + (SELECT COUNT(*) FROM tool_executions)",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            0,
            "{mutation}"
        );
    }
}
