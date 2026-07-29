use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Barrier};

use local_agent_terminal_application::{
    canonical_approval_payload, canonical_file_write_recovery_request, parse_approval_payload,
    ApprovalClaim, ApprovalDigestPayload, ApprovalId, ApprovalResolution, ApprovalStore,
    BoundedOutput, CanonicalEvidenceRef, CapabilityRootIdentity, FileWritePolicyBinding,
    FileWritePreImage, FileWriteRecoveryCompletion, FileWriteRecoveryFailure,
    FileWriteRecoveryIntent, FileWriteRecoveryRequest, FileWriteRecoveryState,
    FileWriteRecoveryStore, JobReceipt, NewApproval, NewToolExecution, NewToolIntent,
    ObservedProcessWrite, ProcessReceipt, ProcessStatus, RelativePathComponents,
    ResolvedCapabilityTarget, ToolExecutionCompletion, ToolExecutionId, ToolExecutionStore,
    ToolRequestBindingDigest, VerifiedFileWriteCompensation, VerifiedWrite,
};
use local_agent_terminal_domain::{
    ActorId, ArtifactId, CapabilityRef, FencingToken, GitObjectId, LeaseClaim, PolicyEffect,
    ProjectId, RunId, Sequence, Sha256Digest, TaskId, WorkspaceFingerprint, WorkspaceVersion,
};
use local_agent_terminal_storage_sqlite::SqliteStore;
use rusqlite::{params, Connection};
use sha2::{Digest, Sha256};

const TOOL_FIXTURE: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../tests/contracts/fixtures/m2/tool-approval-valid.json"
));

static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

struct TempDatabase {
    directory: PathBuf,
    path: PathBuf,
}

impl TempDatabase {
    fn new() -> Self {
        let directory = std::env::temp_dir().join(format!(
            "local-agent-terminal-tool-recovery-{}-{}",
            std::process::id(),
            NEXT_TEMP.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&directory).unwrap();
        let path = directory.join("state.sqlite3");
        SqliteStore::open(&path).unwrap();
        seed_authoritative_context(&path, &directory);
        Self { directory, path }
    }
}

impl Drop for TempDatabase {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.directory);
    }
}

#[test]
fn reserve_requires_authoritative_request_evidence() {
    let database = TempDatabase::new();
    let store = SqliteStore::open(&database.path).unwrap();

    let error = store
        .reserve(NewToolIntent {
            execution_id: ToolExecutionId::new("execution-1").unwrap(),
            operation_digest: Sha256Digest::new(format!("sha256:{}", "a".repeat(64))).unwrap(),
        })
        .expect_err("an intent cannot exist without its canonical request artifact");

    assert_eq!(
        error.safe_classification(),
        local_agent_terminal_application::SafeErrorClassification::NotFound
    );

    let canonical =
        canonical_approval_payload(&parse_approval_payload(TOOL_FIXTURE).unwrap()).unwrap();
    let mut noncanonical = vec![b' '];
    noncanonical.extend_from_slice(&canonical.canonical_bytes);
    let noncanonical_digest =
        Sha256Digest::new(format!("sha256:{:x}", Sha256::digest(&noncanonical))).unwrap();
    persist_artifact(
        &database,
        "noncanonical-request",
        "tool-requests/noncanonical.json",
        "tool-request",
        &noncanonical,
    );
    assert!(store
        .reserve(NewToolIntent {
            execution_id: ToolExecutionId::new("execution-noncanonical").unwrap(),
            operation_digest: noncanonical_digest,
        })
        .is_err());
}

#[test]
fn begin_and_finish_roll_back_at_statement_faults_and_reopen_exactly() {
    let database = TempDatabase::new();
    let store = SqliteStore::open(&database.path).unwrap();
    let operation_digest = persist_request_artifact(&database);
    persist_policy_decision(&database.path, &operation_digest, "allow");
    let execution_id = ToolExecutionId::new("execution-1").unwrap();
    let intent = NewToolIntent {
        execution_id: execution_id.clone(),
        operation_digest: operation_digest.clone(),
    };
    assert_eq!(
        store.reserve(intent.clone()).unwrap(),
        store.reserve(intent).unwrap()
    );

    configured_connection(&database.path)
        .execute_batch(
            "CREATE TRIGGER fail_tool_execution_insert
             BEFORE INSERT ON tool_executions BEGIN
                 SELECT RAISE(ABORT, 'injected begin fault');
             END;",
        )
        .unwrap();
    assert!(store
        .begin(NewToolExecution {
            execution_id: execution_id.clone(),
        })
        .is_err());
    let connection = configured_connection(&database.path);
    assert_eq!(
        connection
            .query_row(
                "SELECT status FROM operation_intents WHERE id = 'execution-1'",
                [],
                |row| row.get::<_, String>(0)
            )
            .unwrap(),
        "pending"
    );
    assert_eq!(
        connection
            .query_row("SELECT COUNT(*) FROM tool_executions", [], |row| row
                .get::<_, i64>(0))
            .unwrap(),
        0
    );
    connection
        .execute_batch("DROP TRIGGER fail_tool_execution_insert;")
        .unwrap();
    drop(connection);

    store
        .begin(NewToolExecution {
            execution_id: execution_id.clone(),
        })
        .unwrap();
    let missing_output =
        Sha256Digest::new(format!("sha256:{:x}", Sha256::digest(b"not persisted"))).unwrap();
    assert!(store
        .finish(ToolExecutionCompletion {
            execution_id: execution_id.clone(),
            receipt: process_receipt(execution_id.clone(), Some(0), missing_output),
        })
        .is_err());
    let output_digest = persist_output_artifact(&database, b"exact output");
    configured_connection(&database.path)
        .execute_batch(
            "CREATE TRIGGER fail_completion_event
             BEFORE INSERT ON events
             WHEN NEW.event_type = 'tool.execution.completed'
             BEGIN
                 SELECT RAISE(ABORT, 'injected finish fault');
             END;",
        )
        .unwrap();
    let completion = ToolExecutionCompletion {
        execution_id: execution_id.clone(),
        receipt: process_receipt(execution_id.clone(), Some(0), output_digest),
    };
    assert!(store.finish(completion.clone()).is_err());
    let connection = configured_connection(&database.path);
    assert_eq!(
        connection
            .query_row(
                "SELECT status FROM tool_executions WHERE id = 'execution-1'",
                [],
                |row| row.get::<_, String>(0)
            )
            .unwrap(),
        "running"
    );
    assert_eq!(
        connection
            .query_row(
                "SELECT status FROM operation_intents WHERE id = 'execution-1'",
                [],
                |row| row.get::<_, String>(0)
            )
            .unwrap(),
        "started"
    );
    connection
        .execute_batch("DROP TRIGGER fail_completion_event;")
        .unwrap();
    drop(connection);

    assert!(store.finish(completion.clone()).unwrap().completed);
    assert_eq!(
        store.finish(completion.clone()).unwrap(),
        store.finish(completion.clone()).unwrap()
    );
    let mut changed_completion = completion;
    changed_completion.receipt.exit_code = Some(1);
    assert!(store.finish(changed_completion).is_err());
    drop(store);
    let reopened = SqliteStore::open(&database.path).unwrap();
    assert!(reopened.incomplete().unwrap().is_empty());
    let connection = configured_connection(&database.path);
    assert_eq!(
        connection
            .query_row(
                "SELECT te.status || ':' || oi.status
                 FROM tool_executions te
                 JOIN operation_intents oi ON oi.id = te.operation_intent_id
                 WHERE te.id = 'execution-1'",
                [],
                |row| row.get::<_, String>(0)
            )
            .unwrap(),
        "succeeded:succeeded"
    );
}

#[test]
fn terminated_process_is_durable_non_success_with_complete_job_evidence() {
    let database = TempDatabase::new();
    let operation_digest = persist_request_artifact(&database);
    persist_policy_decision(&database.path, &operation_digest, "allow");
    let output_digest = persist_output_artifact(&database, b"terminated output");
    let store = SqliteStore::open(&database.path).unwrap();
    let execution_id = ToolExecutionId::new("execution-terminated").unwrap();
    store
        .reserve(NewToolIntent {
            execution_id: execution_id.clone(),
            operation_digest,
        })
        .unwrap();
    store
        .begin(NewToolExecution {
            execution_id: execution_id.clone(),
        })
        .unwrap();
    let mut receipt = process_receipt(execution_id.clone(), None, output_digest);
    receipt.status = ProcessStatus::Terminated;
    receipt.stdout.bytes = b"terminated output".to_vec();
    receipt.stdout.truncated = true;
    receipt.duration_ms = 275;
    receipt.job_receipt.root_pid = 4242;
    receipt.job_receipt.job_id = "job-execution-terminated".to_owned();
    receipt.job_receipt.total_user_time_ms = 650;
    receipt.job_receipt.resource_limit_terminated = true;
    receipt.job_receipt.tree_terminated = true;
    receipt.observed_writes = vec![observed_process_write(
        "generated.txt",
        "worktree-root",
        b"observed write",
    )];
    let completion = ToolExecutionCompletion {
        execution_id,
        receipt,
    };

    assert!(store.finish(completion.clone()).unwrap().completed);
    assert!(store.finish(completion).unwrap().completed);
    drop(store);

    let reopened = SqliteStore::open(&database.path).unwrap();
    assert!(reopened.incomplete().unwrap().is_empty());
    let connection = configured_connection(&database.path);
    let durable: (String, String, String, String) = connection
        .query_row(
            "SELECT te.status, oi.status, oi.external_receipt_json,
                    (SELECT payload_json FROM events
                     WHERE event_type = 'tool.execution.completed'
                       AND actor_id = 'execution-terminated')
             FROM tool_executions te
             JOIN operation_intents oi ON oi.id = te.operation_intent_id
             WHERE te.id = 'execution-terminated'",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .unwrap();
    assert_eq!(durable.0, "terminated");
    assert_eq!(durable.1, "failed");
    let receipt: serde_json::Value = serde_json::from_str(&durable.2).unwrap();
    assert_eq!(receipt["schemaVersion"], 1);
    assert_eq!(receipt["status"], "terminated");
    assert_eq!(receipt["job"]["rootPid"], 4242);
    assert_eq!(receipt["job"]["treeTerminated"], true);
    assert_eq!(receipt["job"]["jobMemoryLimit"], true);
    assert_eq!(receipt["job"]["jobCpuTimeLimit"], true);
    assert_eq!(receipt["job"]["resourceLimitTerminated"], true);
    assert_eq!(receipt["stdout"]["truncated"], true);
    assert_eq!(receipt["durationMs"], 275);
    assert_eq!(receipt["observedWrites"][0]["sizeBytes"], 14);
    let event: serde_json::Value = serde_json::from_str(&durable.3).unwrap();
    assert_eq!(event["status"], "terminated");
}

#[test]
fn two_scope_process_write_receipt_reopens_with_exact_mapping() {
    let database = TempDatabase::new();
    let operation_digest = persist_request_artifact(&database);
    persist_policy_decision(&database.path, &operation_digest, "allow");
    let output_digest = persist_output_artifact(&database, b"two-scope output");
    let store = SqliteStore::open(&database.path).unwrap();
    let execution_id = ToolExecutionId::new("execution-two-scopes").unwrap();
    store
        .reserve(NewToolIntent {
            execution_id: execution_id.clone(),
            operation_digest,
        })
        .unwrap();
    store
        .begin(NewToolExecution {
            execution_id: execution_id.clone(),
        })
        .unwrap();
    let mut receipt = process_receipt(execution_id.clone(), Some(0), output_digest);
    receipt.observed_writes = vec![
        observed_process_write(".", "worktree-root", b"first"),
        observed_process_write("generated/second.txt", "worktree-root", b"second"),
    ];
    let completion = ToolExecutionCompletion {
        execution_id,
        receipt,
    };

    assert!(store.finish(completion.clone()).unwrap().completed);
    drop(store);

    let connection = configured_connection(&database.path);
    let (receipt_json, event_json): (String, String) = connection
        .query_row(
            "SELECT oi.external_receipt_json,
                    (SELECT payload_json FROM events
                     WHERE event_type = 'tool.execution.completed'
                       AND actor_id = 'execution-two-scopes')
             FROM operation_intents oi WHERE oi.id = 'execution-two-scopes'",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    let receipt_value: serde_json::Value = serde_json::from_str(&receipt_json).unwrap();
    let expected = serde_json::json!([
        {
            "capability": {
                "kind": "worktree",
                "taskId": "task-1",
                "path": ".",
            },
            "rootIdentity": "worktree-root",
            "target": {
                "kind": "root",
            },
            "digest": digest_bytes(b"first").as_str(),
            "sizeBytes": 5,
        },
        {
            "capability": {
                "kind": "worktree",
                "taskId": "task-1",
                "path": "generated/second.txt",
            },
            "rootIdentity": "worktree-root",
            "target": {
                "kind": "relative",
                "components": ["generated", "second.txt"],
            },
            "digest": digest_bytes(b"second").as_str(),
            "sizeBytes": 6,
        },
    ]);
    assert_eq!(receipt_value["schemaVersion"], 1);
    assert_eq!(receipt_value["observedWrites"], expected);
    let event_value: serde_json::Value = serde_json::from_str(&event_json).unwrap();
    assert_eq!(event_value["receipt"]["observedWrites"], expected);
    drop(connection);

    let reopened = SqliteStore::open(&database.path).unwrap();
    assert!(reopened.finish(completion.clone()).unwrap().completed);
    let mut reordered = completion;
    reordered.receipt.observed_writes.reverse();
    assert!(reopened.finish(reordered).is_err());
}

#[test]
fn reopen_marks_started_non_repeatable_execution_indeterminate_once() {
    let database = TempDatabase::new();
    let operation_digest = persist_request_artifact(&database);
    persist_policy_decision(&database.path, &operation_digest, "allow");
    let store = SqliteStore::open(&database.path).unwrap();
    let execution_id = ToolExecutionId::new("execution-crashed").unwrap();
    store
        .reserve(NewToolIntent {
            execution_id: execution_id.clone(),
            operation_digest,
        })
        .unwrap();
    store.begin(NewToolExecution { execution_id }).unwrap();
    drop(store);

    let reopened = SqliteStore::open(&database.path).unwrap();
    assert_eq!(reopened.incomplete().unwrap().len(), 1);
    assert!(reopened.incomplete().unwrap().is_empty());
    let connection = configured_connection(&database.path);
    assert_eq!(
        connection
            .query_row(
                "SELECT te.status || ':' || oi.status
                 FROM tool_executions te
                 JOIN operation_intents oi ON oi.id = te.operation_intent_id
                 WHERE te.id = 'execution-crashed'",
                [],
                |row| row.get::<_, String>(0)
            )
            .unwrap(),
        "indeterminate:indeterminate"
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

#[test]
fn begin_rolls_back_at_every_sql_statement_boundary() {
    let triggers = [
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
    for trigger in triggers {
        let database = TempDatabase::new();
        let operation_digest = persist_request_artifact(&database);
        persist_policy_decision(&database.path, &operation_digest, "allow");
        let store = SqliteStore::open(&database.path).unwrap();
        store
            .reserve(NewToolIntent {
                execution_id: ToolExecutionId::new("execution-boundary").unwrap(),
                operation_digest,
            })
            .unwrap();
        configured_connection(&database.path)
            .execute_batch(trigger)
            .unwrap();

        assert!(store
            .begin(NewToolExecution {
                execution_id: ToolExecutionId::new("execution-boundary").unwrap(),
            })
            .is_err());
        drop(store);
        let connection = configured_connection(&database.path);
        assert_eq!(
            connection
                .query_row(
                    "SELECT status FROM operation_intents WHERE id = 'execution-boundary'",
                    [],
                    |row| row.get::<_, String>(0)
                )
                .unwrap(),
            "pending"
        );
        assert_eq!(
            connection
                .query_row("SELECT COUNT(*) FROM tool_executions", [], |row| {
                    row.get::<_, i64>(0)
                })
                .unwrap(),
            0
        );
        assert_eq!(
            connection
                .query_row(
                    "SELECT current_sequence FROM tasks WHERE id = 'task-1'",
                    [],
                    |row| row.get::<_, i64>(0)
                )
                .unwrap(),
            0
        );
    }
}

#[test]
fn finish_rolls_back_at_every_sql_statement_boundary() {
    let triggers = [
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
    for trigger in triggers {
        let database = TempDatabase::new();
        let operation_digest = persist_request_artifact(&database);
        persist_policy_decision(&database.path, &operation_digest, "allow");
        let output_digest = persist_output_artifact(&database, b"boundary output");
        let store = SqliteStore::open(&database.path).unwrap();
        let execution_id = ToolExecutionId::new("execution-boundary").unwrap();
        store
            .reserve(NewToolIntent {
                execution_id: execution_id.clone(),
                operation_digest,
            })
            .unwrap();
        store
            .begin(NewToolExecution {
                execution_id: execution_id.clone(),
            })
            .unwrap();
        configured_connection(&database.path)
            .execute_batch(trigger)
            .unwrap();

        assert!(store
            .finish(ToolExecutionCompletion {
                execution_id: execution_id.clone(),
                receipt: process_receipt(execution_id, Some(0), output_digest),
            })
            .is_err());
        drop(store);
        let connection = configured_connection(&database.path);
        assert_eq!(
            connection
                .query_row(
                    "SELECT te.status || ':' || oi.status
                     FROM tool_executions te
                     JOIN operation_intents oi ON oi.id = te.operation_intent_id
                     WHERE te.id = 'execution-boundary'",
                    [],
                    |row| row.get::<_, String>(0)
                )
                .unwrap(),
            "running:started"
        );
        assert_eq!(
            connection
                .query_row(
                    "SELECT current_sequence FROM tasks WHERE id = 'task-1'",
                    [],
                    |row| row.get::<_, i64>(0)
                )
                .unwrap(),
            1
        );
    }
}

#[test]
fn approval_required_begin_accepts_only_an_atomically_consumed_grant() {
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
        })
        .unwrap_err();
    assert_eq!(
        error.safe_classification(),
        local_agent_terminal_application::SafeErrorClassification::PermissionDenied
    );

    seed_consumed_approval(&database.path, &operation_digest, "9999-12-31T23:59:59Z");
    assert!(
        !store
            .begin(NewToolExecution { execution_id })
            .unwrap()
            .completed
    );
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
    let binding = ToolRequestBindingDigest::from_persisted(
        Sha256Digest::new(format!("sha256:{}", "f".repeat(64))).unwrap(),
    );
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
    let first_id = ToolExecutionId::new("execution-approved-first").unwrap();
    let second_id = ToolExecutionId::new("execution-approved-second").unwrap();
    for execution_id in [&first_id, &second_id] {
        store
            .reserve(NewToolIntent {
                execution_id: execution_id.clone(),
                operation_digest: canonical.operation_digest.clone(),
            })
            .unwrap();
    }

    let barrier = Arc::new(Barrier::new(2));
    let outcomes = std::thread::scope(|scope| {
        let first_store = store.clone();
        let first_barrier = Arc::clone(&barrier);
        let first = scope.spawn(move || {
            first_barrier.wait();
            first_store.begin(NewToolExecution {
                execution_id: first_id.clone(),
            })
        });
        let second_store = store.clone();
        let second_barrier = Arc::clone(&barrier);
        let second = scope.spawn(move || {
            second_barrier.wait();
            second_store.begin(NewToolExecution {
                execution_id: second_id.clone(),
            })
        });
        [first.join().unwrap(), second.join().unwrap()]
    });
    assert_eq!(outcomes.iter().filter(|outcome| outcome.is_ok()).count(), 1);
    assert_eq!(
        outcomes.iter().filter(|outcome| outcome.is_err()).count(),
        1
    );
    drop(store);
    let reopened = SqliteStore::open(&database.path).unwrap();
    for execution_id in ["execution-approved-first", "execution-approved-second"] {
        if configured_connection(&database.path)
            .query_row(
                "SELECT status FROM operation_intents WHERE id = ?1",
                [execution_id],
                |row| row.get::<_, String>(0),
            )
            .unwrap()
            == "pending"
        {
            assert!(reopened
                .begin(NewToolExecution {
                    execution_id: ToolExecutionId::new(execution_id).unwrap(),
                })
                .is_err());
        }
    }
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
            operation_digest,
        })
        .unwrap();

    assert!(store.begin(NewToolExecution { execution_id }).is_err());
}

#[test]
fn completion_retry_rejects_any_inconsistent_persisted_result_field() {
    let mutations = [
        "UPDATE operation_intents SET status = 'indeterminate'
         WHERE id = 'execution-tamper'",
        "UPDATE operation_intents SET result_artifact_id = 'request-artifact'
         WHERE id = 'execution-tamper'",
        "UPDATE operation_intents SET external_receipt_json = '{}'
         WHERE id = 'execution-tamper'",
        "UPDATE tool_executions SET completed_at = NULL
         WHERE id = 'execution-tamper'",
        "UPDATE tool_executions SET stderr_artifact_id = 'request-artifact'
         WHERE id = 'execution-tamper'",
        "UPDATE tasks SET operation_state = 'Running' WHERE id = 'task-1'",
    ];
    for mutation in mutations {
        let database = TempDatabase::new();
        let (store, completion) = completed_execution(&database, "execution-tamper");
        configured_connection(&database.path)
            .execute_batch(mutation)
            .unwrap();

        assert!(
            store.finish(completion).is_err(),
            "retry accepted inconsistent state after {mutation}"
        );
    }
}

#[test]
fn completion_scopes_duplicate_output_digests_to_the_execution_task() {
    let database = TempDatabase::new();
    let operation_digest = persist_request_artifact(&database);
    persist_policy_decision(&database.path, &operation_digest, "allow");
    let output_digest = persist_output_artifact(&database, b"shared output");
    persist_duplicate_artifact_metadata(
        &database,
        "000-other-task-output",
        "output-artifact",
        true,
    );
    let store = SqliteStore::open(&database.path).unwrap();
    let execution_id = ToolExecutionId::new("execution-cross-task-output").unwrap();
    store
        .reserve(NewToolIntent {
            execution_id: execution_id.clone(),
            operation_digest,
        })
        .unwrap();
    store
        .begin(NewToolExecution {
            execution_id: execution_id.clone(),
        })
        .unwrap();

    assert!(
        store
            .finish(ToolExecutionCompletion {
                execution_id: execution_id.clone(),
                receipt: process_receipt(execution_id, Some(0), output_digest),
            })
            .unwrap()
            .completed
    );
    assert_eq!(
        configured_connection(&database.path)
            .query_row(
                "SELECT stdout_artifact_id FROM tool_executions
                 WHERE id = 'execution-cross-task-output'",
                [],
                |row| row.get::<_, String>(0),
            )
            .unwrap(),
        "output-artifact"
    );
}

#[test]
fn exact_completion_retry_verifies_the_persisted_artifact_id() {
    let database = TempDatabase::new();
    let (store, completion) = completed_execution(&database, "execution-exact-artifact");
    persist_duplicate_artifact_metadata(
        &database,
        "000-same-task-output",
        "output-artifact",
        false,
    );

    assert!(store.finish(completion).unwrap().completed);
}

#[test]
fn tool_execution_statuses_and_run_request_id_uniqueness_are_enforced() {
    let allowed = [
        ("pending", "running"),
        ("pending", "denied"),
        ("running", "succeeded"),
        ("running", "failed"),
        ("running", "terminated"),
        ("running", "interrupted"),
        ("running", "indeterminate"),
        ("running", "denied"),
    ];
    let forbidden = [
        ("pending", "succeeded"),
        ("succeeded", "running"),
        ("failed", "pending"),
        ("denied", "running"),
    ];
    let database = TempDatabase::new();
    let operation_digest = persist_request_artifact(&database);
    persist_policy_decision(&database.path, &operation_digest, "allow");
    let store = SqliteStore::open(&database.path).unwrap();
    for (index, (from, to)) in allowed.into_iter().enumerate() {
        insert_tool_execution(
            &database,
            &store,
            &operation_digest,
            index,
            from,
            &format!("request-{index}"),
        );
        assert!(configured_connection(&database.path)
            .execute(
                "UPDATE tool_executions SET status = ?1 WHERE id = ?2",
                params![to, format!("status-execution-{index}")],
            )
            .is_ok());
    }
    for (offset, (from, to)) in forbidden.into_iter().enumerate() {
        let index = allowed.len() + offset;
        insert_tool_execution(
            &database,
            &store,
            &operation_digest,
            index,
            from,
            &format!("request-{index}"),
        );
        assert!(configured_connection(&database.path)
            .execute(
                "UPDATE tool_executions SET status = ?1 WHERE id = ?2",
                params![to, format!("status-execution-{index}")],
            )
            .is_err());
    }
    let first_index = allowed.len() + forbidden.len();
    insert_tool_execution(
        &database,
        &store,
        &operation_digest,
        first_index,
        "pending",
        "duplicate-request",
    );
    let second_index = first_index + 1;
    assert!(try_insert_tool_execution(
        &database,
        &store,
        &operation_digest,
        second_index,
        "pending",
        "duplicate-request",
    )
    .is_err());
}

fn completed_execution(
    database: &TempDatabase,
    execution_id: &str,
) -> (SqliteStore, ToolExecutionCompletion) {
    let operation_digest = persist_request_artifact(database);
    persist_policy_decision(&database.path, &operation_digest, "allow");
    let output_digest = persist_output_artifact(database, b"tamper output");
    let store = SqliteStore::open(&database.path).unwrap();
    let execution_id = ToolExecutionId::new(execution_id).unwrap();
    store
        .reserve(NewToolIntent {
            execution_id: execution_id.clone(),
            operation_digest,
        })
        .unwrap();
    store
        .begin(NewToolExecution {
            execution_id: execution_id.clone(),
        })
        .unwrap();
    let completion = ToolExecutionCompletion {
        execution_id: execution_id.clone(),
        receipt: process_receipt(execution_id, Some(0), output_digest),
    };
    store.finish(completion.clone()).unwrap();
    (store, completion)
}

fn process_receipt(
    execution_id: ToolExecutionId,
    exit_code: Option<i32>,
    output_digest: Sha256Digest,
) -> ProcessReceipt {
    ProcessReceipt {
        execution_id,
        status: ProcessStatus::Exited,
        exit_code,
        stdout: BoundedOutput {
            bytes: Vec::new(),
            truncated: false,
        },
        stderr: BoundedOutput {
            bytes: Vec::new(),
            truncated: false,
        },
        duration_ms: 0,
        job_receipt: JobReceipt {
            root_pid: 1,
            job_id: "storage-test-job".to_owned(),
            kill_on_close: true,
            no_breakaway: true,
            job_memory_limit: true,
            job_cpu_time_limit: true,
            memory_limit_bytes: 256 * 1024 * 1024,
            cpu_time_limit_ms: 5_000,
            max_active_processes: 8,
            total_user_time_ms: 10,
            resource_limit_terminated: false,
            tree_terminated: false,
        },
        observed_writes: Vec::new(),
        output_digest,
    }
}

fn observed_process_write(path: &str, root_identity: &str, bytes: &[u8]) -> ObservedProcessWrite {
    ObservedProcessWrite::new(
        CapabilityRef::worktree(TaskId::new("task-1").unwrap(), path).unwrap(),
        CapabilityRootIdentity::new(root_identity).unwrap(),
        if path == "." {
            ResolvedCapabilityTarget::Root
        } else {
            ResolvedCapabilityTarget::Relative(
                RelativePathComponents::new(path.split(['/', '\\']).map(str::to_owned).collect())
                    .unwrap(),
            )
        },
        VerifiedWrite {
            digest: digest_bytes(bytes),
            size_bytes: bytes.len() as u64,
        },
    )
}

fn insert_tool_execution(
    database: &TempDatabase,
    store: &SqliteStore,
    operation_digest: &Sha256Digest,
    index: usize,
    status: &str,
    request_id: &str,
) {
    try_insert_tool_execution(database, store, operation_digest, index, status, request_id)
        .unwrap();
}

fn try_insert_tool_execution(
    database: &TempDatabase,
    store: &SqliteStore,
    operation_digest: &Sha256Digest,
    index: usize,
    status: &str,
    request_id: &str,
) -> rusqlite::Result<usize> {
    let execution_id = format!("status-execution-{index}");
    store
        .reserve(NewToolIntent {
            execution_id: ToolExecutionId::new(execution_id.clone()).unwrap(),
            operation_digest: operation_digest.clone(),
        })
        .unwrap();
    configured_connection(&database.path).execute(
        "INSERT INTO tool_executions (
            id, task_id, run_id, request_id, tool_name, arguments_artifact_id,
            policy_decision_id, approval_id, operation_intent_id,
            executor_fencing_token, status
         ) VALUES (?1, 'task-1', 'run-1', ?2, 'process.exec', 'request-artifact',
            'policy-1', NULL, ?1, 19, ?3)",
        params![execution_id, request_id, status],
    )
}

fn persist_duplicate_artifact_metadata(
    database: &TempDatabase,
    duplicate_id: &str,
    source_id: &str,
    cross_task: bool,
) {
    let connection = configured_connection(&database.path);
    if cross_task {
        connection
            .execute(
                "INSERT INTO projects (
                    id, name, repository_path, repository_identity, created_at, updated_at,
                    policy_profile_id, artifact_root_mode, artifact_root_path
                 ) VALUES ('project-2', 'Other', 'C:/other', 'repo-2',
                    '2026-07-23T00:00:00Z', '2026-07-23T00:00:00Z',
                    'policy-1', 'application_data', ?1)",
                [database.directory.to_string_lossy().as_ref()],
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO tasks (
                    id, project_id, title, objective, phase, condition, operation_state,
                    risk_level, base_branch, base_commit, created_at, updated_at
                 ) VALUES ('task-2', 'project-2', 'Other', 'Other', 'Implementation',
                    'Active', 'None', 'low', 'main', ?1,
                    '2026-07-23T00:00:00Z', '2026-07-23T00:00:00Z')",
                ["b".repeat(40)],
            )
            .unwrap();
    }
    connection
        .execute(
            "INSERT INTO artifacts (
                id, task_id, project_id, artifact_type, logical_path, content_hash, storage_key,
                size_bytes, mime_type, availability, created_by_type, created_by_id, created_at,
                supersedes, verification_state
             )
             SELECT ?1, ?2, ?3, artifact_type,
                    CASE WHEN ?5 THEN logical_path ELSE logical_path || '.duplicate' END,
                    content_hash, storage_key,
                    size_bytes, mime_type, availability, created_by_type, created_by_id,
                    created_at, supersedes, verification_state
             FROM artifacts WHERE id = ?4",
            params![
                duplicate_id,
                if cross_task { "task-2" } else { "task-1" },
                if cross_task { "project-2" } else { "project-1" },
                source_id,
                cross_task,
            ],
        )
        .unwrap();
}

fn seed_authoritative_context(path: &Path, artifact_root: &Path) {
    let connection = configured_connection(path);
    connection
        .execute(
            "INSERT INTO projects (
                id, name, repository_path, repository_identity, created_at, updated_at,
                policy_profile_id, artifact_root_mode, artifact_root_path
             ) VALUES ('project-1', 'Project', 'C:/repo', 'repo-1',
                '2026-07-23T00:00:00Z', '2026-07-23T00:00:00Z',
                'policy-1', 'application_data', ?1)",
            [artifact_root.to_string_lossy().as_ref()],
        )
        .unwrap();
    connection
        .execute(
            "INSERT INTO tasks (
                id, project_id, title, objective, phase, condition, operation_state, risk_level,
                base_branch, base_commit, workspace_version, fencing_epoch, created_at, updated_at
             ) VALUES ('task-1', 'project-1', 'Task', 'Objective', 'Implementation', 'Active',
                'None', 'high', 'main', ?1, 4, 19,
                '2026-07-23T00:00:00Z', '2026-07-23T00:00:00Z')",
            ["a".repeat(40)],
        )
        .unwrap();
    let seed_hash = format!("sha256:{}", "d".repeat(64));
    for (id, path) in [
        ("manifest", "seed/manifest"),
        ("effective", "seed/effective"),
        ("run-config", "seed/run-config"),
    ] {
        connection
            .execute(
                "INSERT INTO artifacts (
                    id, task_id, project_id, artifact_type, logical_path, content_hash,
                    storage_key, size_bytes, mime_type, availability, created_by_type,
                    created_by_id, created_at, supersedes, verification_state
                 ) VALUES (?1, 'task-1', 'project-1', 'seed', ?2, ?3, ?1, 0, NULL,
                    'available', 'core', 'core', '2026-07-23T00:00:00Z', NULL, 'hash_verified')",
                params![id, path, seed_hash],
            )
            .unwrap();
    }
    connection
        .execute(
            "INSERT INTO agent_descriptors (
                id, display_name, transport_type, trust_tier, manifest_json, manifest_digest,
                executable_digest, enabled, containment_verified, last_health_status, updated_at
             ) VALUES ('agent-1', 'Agent', 'in_process', 'core_adapter', '{}', ?1,
                NULL, 1, 1, 'healthy', '2026-07-23T00:00:00Z')",
            [&seed_hash],
        )
        .unwrap();
    connection
        .execute(
            "INSERT INTO context_packages (
                id, task_id, agent_id, role, objective, manifest_artifact_id,
                effective_content_artifact_id, content_hash, policy_snapshot_digest,
                prompt_template_version, retrieval_pipeline_version, created_at
             ) VALUES ('context-1', 'task-1', 'agent-1', 'executor', 'execute',
                'manifest', 'effective', ?1, ?2, 'v1', 'v1', '2026-07-23T00:00:00Z')",
            params![seed_hash, format!("sha256:{}", "0".repeat(64))],
        )
        .unwrap();
    connection
        .execute(
            "INSERT INTO agent_runs (
                id, task_id, agent_id, role, phase, status, context_package_id,
                idempotency_key, connection_binding_digest, run_config_artifact_id, started_at
             ) VALUES ('run-1', 'task-1', 'agent-1', 'executor', 'Implementation', 'running',
                'context-1', 'run-1-key', ?1, 'run-config', '2026-07-23T00:00:00Z')",
            [format!("sha256:{}", "e".repeat(64))],
        )
        .unwrap();
    connection
        .execute(
            "INSERT INTO executor_leases (
                task_id, holder_run_id, fencing_token, status, acquired_at, expires_at, released_at
             ) VALUES ('task-1', 'run-1', 19, 'active',
                '2026-07-23T00:00:00Z', '2026-08-23T00:00:00Z', NULL)",
            [],
        )
        .unwrap();
}

fn persist_request_artifact(database: &TempDatabase) -> Sha256Digest {
    let payload = parse_approval_payload(TOOL_FIXTURE).unwrap();
    let canonical = canonical_approval_payload(&payload).unwrap();
    persist_artifact(
        database,
        "request-artifact",
        "tool-requests/execution.json",
        "tool-request",
        &canonical.canonical_bytes,
    );
    canonical.operation_digest
}

fn file_write_recovery(
    database: &TempDatabase,
    execution_id: &str,
) -> (FileWriteRecoveryIntent, FileWriteRecoveryCompletion) {
    let task_id = TaskId::new("task-1").unwrap();
    let pre_image = persist_evidence_artifact(
        database,
        &format!("{execution_id}-pre-image"),
        b"old contents",
    );
    let pre_evidence = persist_evidence_artifact(
        database,
        &format!("{execution_id}-pre-evidence"),
        b"{\"workspace\":\"before\"}",
    );
    let post_evidence = persist_evidence_artifact(
        database,
        &format!("{execution_id}-post-evidence"),
        b"{\"workspace\":\"after\"}",
    );
    let policy_operation_digest = digest_char('6');
    let policy_snapshot_digest = digest_char('0');
    persist_file_policy_decision(
        &database.path,
        "policy-file-write",
        "task-1",
        &policy_operation_digest,
        &policy_snapshot_digest,
        "allow",
    );
    let expected_post_digest =
        Sha256Digest::new(format!("sha256:{:x}", Sha256::digest(b"new contents"))).unwrap();
    let request = FileWriteRecoveryRequest {
        execution_id: ToolExecutionId::new(execution_id).unwrap(),
        task_id: task_id.clone(),
        root_identity: CapabilityRootIdentity::new("worktree-root-1").unwrap(),
        relative_components: RelativePathComponents::new(vec![
            "src".to_owned(),
            "main.rs".to_owned(),
        ])
        .unwrap(),
        lease_claim: LeaseClaim::new(
            task_id,
            RunId::new("run-1").unwrap(),
            FencingToken::new(19).unwrap(),
        ),
        expected_sequence: Sequence::new(0),
        pre_image: FileWritePreImage::Artifact(pre_image),
        expected_post_digest: expected_post_digest.clone(),
        expected_post_size: b"new contents".len() as u64,
        pre_fingerprint: workspace_fingerprint('a', '1', '2'),
        pre_evidence,
        actor_id: ActorId::new("tool-runtime").unwrap(),
        correlation_id: format!("file-write:{execution_id}"),
        policy: FileWritePolicyBinding {
            decision_id: "policy-file-write".to_owned(),
            operation_digest: policy_operation_digest,
            policy_snapshot_digest,
            effect: PolicyEffect::Allow,
            approval_id: None,
        },
    };
    let request_artifact =
        persist_recovery_request_artifact(database, &request, &format!("{execution_id}-request"));
    let completion = FileWriteRecoveryCompletion {
        execution_id: request.execution_id.clone(),
        observed_post_digest: expected_post_digest,
        post_fingerprint: workspace_fingerprint('b', '3', '4'),
        post_evidence,
    };
    (
        FileWriteRecoveryIntent {
            request,
            request_artifact,
        },
        completion,
    )
}

fn persist_recovery_request_artifact(
    database: &TempDatabase,
    request: &FileWriteRecoveryRequest,
    artifact_id: &str,
) -> CanonicalEvidenceRef {
    let canonical = canonical_file_write_recovery_request(request).unwrap();
    persist_artifact(
        database,
        artifact_id,
        &format!("tool-requests/{artifact_id}.json"),
        "file-write-request",
        &canonical.canonical_bytes,
    );
    CanonicalEvidenceRef {
        artifact_id: ArtifactId::new(artifact_id).unwrap(),
        content_hash: canonical.operation_digest.as_str().to_owned(),
        storage_key: format!("objects/{}", &canonical.operation_digest.as_str()[7..]),
        size_bytes: canonical.canonical_bytes.len() as u64,
        project_id: ProjectId::new("project-1").unwrap(),
        task_id: Some(TaskId::new("task-1").unwrap()),
    }
}

fn persist_evidence_artifact(
    database: &TempDatabase,
    artifact_id: &str,
    bytes: &[u8],
) -> CanonicalEvidenceRef {
    let digest = Sha256Digest::new(format!("sha256:{:x}", Sha256::digest(bytes))).unwrap();
    persist_artifact(
        database,
        artifact_id,
        &format!("file-write/{artifact_id}"),
        "file-write-evidence",
        bytes,
    );
    CanonicalEvidenceRef {
        artifact_id: ArtifactId::new(artifact_id).unwrap(),
        content_hash: digest.as_str().to_owned(),
        storage_key: format!("objects/{}", &digest.as_str()[7..]),
        size_bytes: bytes.len() as u64,
        project_id: ProjectId::new("project-1").unwrap(),
        task_id: Some(TaskId::new("task-1").unwrap()),
    }
}

fn persist_file_policy_decision(
    path: &Path,
    decision_id: &str,
    task_id: &str,
    operation_digest: &Sha256Digest,
    policy_snapshot_digest: &Sha256Digest,
    effect: &str,
) {
    let connection = configured_connection(path);
    connection
        .execute(
            "INSERT INTO policy_decisions (
                id, task_id, actor_json, actor_binding_digest, action, resource_json,
                resource_digest, purpose, workflow_phase, effect, matched_rules_json,
                policy_snapshot_digest, operation_digest, created_at, expires_at, approval_id
             ) VALUES (?1, ?2, '{}', ?3, 'tool.write', '{}', ?3,
                'file write', 'Implementation', ?4, '[]', ?5, ?6,
                '2026-07-23T12:00:00Z', NULL, NULL)",
            params![
                decision_id,
                task_id,
                digest_char('7').as_str(),
                effect,
                policy_snapshot_digest.as_str(),
                operation_digest.as_str(),
            ],
        )
        .unwrap();
}

fn seed_other_task(database: &TempDatabase) {
    let connection = configured_connection(&database.path);
    connection
        .execute(
            "INSERT INTO projects (
                id, name, repository_path, repository_identity, created_at, updated_at,
                policy_profile_id, artifact_root_mode, artifact_root_path
             ) VALUES ('project-2', 'Other', 'C:/other', 'repo-2',
                '2026-07-23T00:00:00Z', '2026-07-23T00:00:00Z',
                'policy-1', 'application_data', ?1)",
            [database.directory.to_string_lossy().as_ref()],
        )
        .unwrap();
    connection
        .execute(
            "INSERT INTO tasks (
                id, project_id, title, objective, phase, condition, operation_state,
                risk_level, base_branch, base_commit, created_at, updated_at
             ) VALUES ('task-2', 'project-2', 'Other', 'Other', 'Implementation',
                'Active', 'None', 'low', 'main', ?1,
                '2026-07-23T00:00:00Z', '2026-07-23T00:00:00Z')",
            ["b".repeat(40)],
        )
        .unwrap();
}

fn seed_pending_plan_approval(database: &TempDatabase) {
    configured_connection(&database.path)
        .execute(
            "INSERT INTO approvals (
                id, task_id, approval_type, schema_version, operation_digest, status,
                requested_at, resolved_at, resolved_by, expires_at, request_artifact_id,
                invalidation_reason
             ) VALUES ('plan-pending', 'task-1', 'plan', 'v1', ?1, 'pending',
                '2026-07-23T12:00:00Z', NULL, NULL, '2099-07-23T12:00:00Z',
                'manifest', NULL)",
            [digest_char('5').as_str()],
        )
        .unwrap();
}

fn workspace_fingerprint(
    head: char,
    index_digest: char,
    status_digest: char,
) -> WorkspaceFingerprint {
    WorkspaceFingerprint::new(
        GitObjectId::new(head.to_string().repeat(40)).unwrap(),
        digest_char(index_digest).as_str(),
        digest_char(status_digest).as_str(),
    )
    .unwrap()
}

fn digest_char(character: char) -> Sha256Digest {
    Sha256Digest::new(format!("sha256:{}", character.to_string().repeat(64))).unwrap()
}

fn digest_bytes(bytes: &[u8]) -> Sha256Digest {
    Sha256Digest::new(format!("sha256:{:x}", Sha256::digest(bytes))).unwrap()
}

fn persist_output_artifact(database: &TempDatabase, bytes: &[u8]) -> Sha256Digest {
    let digest = Sha256Digest::new(format!("sha256:{:x}", Sha256::digest(bytes))).unwrap();
    persist_artifact(
        database,
        "output-artifact",
        "tool-results/execution.stdout",
        "tool-output",
        bytes,
    );
    digest
}

fn persist_artifact(
    database: &TempDatabase,
    id: &str,
    logical_path: &str,
    artifact_type: &str,
    bytes: &[u8],
) {
    let hash = format!("sha256:{:x}", Sha256::digest(bytes));
    let storage_key = format!("objects/{}", &hash[7..]);
    let object = database.directory.join(&storage_key);
    fs::create_dir_all(object.parent().unwrap()).unwrap();
    fs::write(object, bytes).unwrap();
    configured_connection(&database.path)
        .execute(
            "INSERT INTO artifacts (
                id, task_id, project_id, artifact_type, logical_path, content_hash, storage_key,
                size_bytes, mime_type, availability, created_by_type, created_by_id, created_at,
                supersedes, verification_state
             ) VALUES (?1, 'task-1', 'project-1', ?2, ?3, ?4, ?5, ?6, NULL, 'available',
                'tool', 'execution', '2026-07-23T12:00:00Z', NULL, 'hash_verified')",
            params![
                id,
                artifact_type,
                logical_path,
                hash,
                storage_key,
                bytes.len() as i64
            ],
        )
        .unwrap();
}

fn persist_policy_decision(path: &Path, operation_digest: &Sha256Digest, effect: &str) {
    let digest = format!("sha256:{}", "0".repeat(64));
    let ApprovalDigestPayload::Tool(payload) = parse_approval_payload(TOOL_FIXTURE).unwrap() else {
        unreachable!();
    };
    configured_connection(path)
        .execute(
            "INSERT INTO policy_decisions (
                id, task_id, actor_json, actor_binding_digest, action, resource_json,
                resource_digest, purpose, workflow_phase, effect, matched_rules_json,
                policy_snapshot_digest, operation_digest, created_at, expires_at, approval_id
             ) VALUES ('policy-1', 'task-1', '{}', ?1, 'process.exec', '{}', ?1,
                'test', 'Implementation', ?3, '[]', ?4, ?2,
                '2026-07-23T12:00:00Z', NULL, NULL)",
            params![
                digest,
                operation_digest.as_str(),
                effect,
                payload.policy_snapshot_digest
            ],
        )
        .unwrap();
}

fn seed_consumed_approval(path: &Path, operation_digest: &Sha256Digest, expires_at: &str) {
    let connection = configured_connection(path);
    connection
        .execute(
            "INSERT INTO approvals (
                id, task_id, approval_type, schema_version, operation_digest, status,
                requested_at, resolved_at, resolved_by, expires_at, request_artifact_id,
                invalidation_reason
             ) VALUES ('approval-consumed', 'task-1', 'tool', 'approval-digest.v1', ?1,
                'invalidated', '2026-07-23T12:00:00Z', '2026-07-23T12:01:00Z', 'user',
                ?2, 'request-artifact', 'consumed')",
            params![operation_digest.as_str(), expires_at],
        )
        .unwrap();
    let ApprovalDigestPayload::Tool(payload) = parse_approval_payload(TOOL_FIXTURE).unwrap() else {
        unreachable!();
    };
    connection
        .execute(
            "INSERT INTO events (
                event_id, stream_id, sequence, event_type, schema_version, actor_type,
                actor_id, observation_class, payload_json, metadata_json, causation_id,
                correlation_id, created_at
             ) VALUES ('approval.requested:approval-consumed:1', 'task-1', 1,
                'approval.requested', 1, 'core', 'approval-store', 'core_observed',
                ?1, '{}', 'approval:approval-consumed', 'approval:approval-consumed',
                '2026-07-23T12:00:00Z')",
            [serde_json::json!({
                "approvalId": "approval-consumed",
                "workspaceVersion": 4,
                "policySnapshotDigest": payload.policy_snapshot_digest,
                "fencingToken": 19,
                "toolRequestBindingDigest": format!("sha256:{}", "f".repeat(64)),
            })
            .to_string()],
        )
        .unwrap();
    connection
        .execute(
            "UPDATE tasks SET current_sequence = 1 WHERE id = 'task-1'",
            [],
        )
        .unwrap();
}

fn configured_connection(path: &Path) -> Connection {
    let connection = Connection::open(path).unwrap();
    connection
        .pragma_update(None, "foreign_keys", "ON")
        .unwrap();
    connection
}
