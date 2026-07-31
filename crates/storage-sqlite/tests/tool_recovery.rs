use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Barrier};

use local_agent_terminal_application::{
    bind_tool_approval_payload, canonical_approval_payload, canonical_file_write_recovery_request,
    canonical_policy_binding_digest, canonical_tool_request, parse_approval_payload,
    policy_request_for_tool, validate_approval_resume_relation, ApprovalClaim,
    ApprovalDigestPayload, ApprovalId, ApprovalResolution, ApprovalResumeStore, ApprovalStore,
    ApprovedExecutableIdentity, ApprovedProcessRequest, AuthoritativeProcessBinding,
    AuthoritativeProcessTermination, AuthorizedToolExecutionClaim, CancellationReceipt,
    CanonicalEvidenceRef, CapabilityRootIdentity, DurableToolExecutionArtifact,
    DurableToolExecutionArtifacts, DurableToolExecutionReceipt, ExecutableFileIdentity,
    FileWritePolicyBinding, FileWritePreImage, FileWriteRecoveryCompletion,
    FileWriteRecoveryFailure, FileWriteRecoveryIntent, FileWriteRecoveryRequest,
    FileWriteRecoveryState, FileWriteRecoveryStore, IncompleteToolExecution, JobReceipt,
    NewApproval, NewToolExecution, NewToolIntent, PolicyDecision, PolicyDecisionStore,
    ProcessExecutionBindingStore, ProcessStatus, RecordedPolicyDecision, RelativePathComponents,
    ResolvedExecutable, SafeToolExecutionError, ToolApprovalOperationV1, ToolApprovalPayloadV1,
    ToolApprovalRequest, ToolExecutionCancellationClaim, ToolExecutionClaim,
    ToolExecutionClaimAuthority, ToolExecutionDenialRequest, ToolExecutionId, ToolExecutionOutput,
    ToolExecutionRecoveryState, ToolExecutionResolution, ToolExecutionResumeStore,
    ToolExecutionStore, ToolExecutionTerminal, ToolExecutionTerminalKind, ToolPolicyContext,
    ToolRequest, ToolRequestBindingDigest, VerifiedFileWriteCompensation, VerifiedWrite,
};
use local_agent_terminal_domain::{
    combine_policy_rules, ActorId, ActorLocality, ArtifactId, CapabilityRef, EnvironmentProfile,
    FencingToken, GitObjectId, LeaseClaim, MatchedPolicyRule, NetworkProfile, Phase, PlanStepId,
    PolicyAction, PolicyActor, PolicyEffect, PolicyResource, PolicyRuleId, PolicyVersion,
    ProcessBinding, ProcessInvocation, ProcessToolRequest, ProcessTrustTier, ProjectId,
    ResourceClass, RunId, Sequence, Sha256Digest, TaskId, TaskRisk, Timestamp, TrustTier,
    WorkspaceFingerprint, WorkspaceVersion,
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
fn authorized_begin_uses_the_exact_effective_policy_id() {
    let database = TempDatabase::new();
    let store = SqliteStore::open(&database.path).unwrap();
    let request = exact_tool_request("execution-exact-policy");
    let immutable = canonical_tool_request(&request).unwrap();
    let request_digest = immutable.binding_digest().as_sha256().clone();
    let request_artifact_id = ArtifactId::new("exact-tool-request").unwrap();
    persist_artifact(
        &database,
        request_artifact_id.as_str(),
        "tool-requests/execution-exact-policy.json",
        "tool-request",
        immutable.canonical_bytes(),
    );
    store
        .reserve(NewToolIntent {
            execution_id: request.execution_id().clone(),
            operation_digest: request_digest.clone(),
        })
        .unwrap();

    let checked_at = Timestamp::from_unix_seconds(1_753_272_300);
    let effective_policy_id =
        record_exact_policy(&store, &request, checked_at, PolicyEffect::Allow, '1');
    record_exact_policy(
        &store,
        &request,
        Timestamp::from_unix_seconds(1_753_272_360),
        PolicyEffect::Deny,
        '2',
    );
    let process = request.process().process();
    let binding = process.binding();
    let claim = AuthorizedToolExecutionClaim {
        execution_id: request.execution_id().clone(),
        request_artifact_id,
        request_content_digest: request_digest,
        request_binding_digest: immutable.binding_digest().clone(),
        task_id: binding.task_id().clone(),
        run_id: binding.run_id().clone(),
        tool_name: "process.exec".to_owned(),
        policy_decision_id: effective_policy_id.clone(),
        policy_request_binding_digest: canonical_policy_binding_digest(&policy_request_for_tool(
            &request, checked_at,
        ))
        .unwrap(),
        approval: None,
        workspace_version: binding.workspace_version(),
        policy_snapshot_digest: request.policy().policy_snapshot_digest().clone(),
        fencing_token: process.executor_fencing_token(),
        checked_at,
    };

    assert!(matches!(
        store.begin_authorized(claim).unwrap(),
        ToolExecutionClaim::Claimed(_)
    ));
    assert_eq!(
        configured_connection(&database.path)
            .query_row(
                "SELECT policy_decision_id FROM tool_executions
                 WHERE id = 'execution-exact-policy'",
                [],
                |row| row.get::<_, String>(0),
            )
            .unwrap(),
        effective_policy_id.as_str()
    );
}

#[test]
fn authorized_begin_rejects_the_approval_time_policy_as_the_fresh_policy() {
    let database = TempDatabase::new();
    let (store, mut claim, _, _) =
        exact_approval_claim_fixture(&database, "execution-stale-policy");
    claim.policy_decision_id = claim
        .approval
        .as_ref()
        .unwrap()
        .policy_decision_id()
        .clone();

    assert!(store.begin_authorized(claim).is_err());
    let connection = configured_connection(&database.path);
    assert_eq!(
        connection
            .query_row(
                "SELECT status || ':' || attempt_count FROM operation_intents
                 WHERE id = 'execution-stale-policy'",
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
fn authorized_begin_consumes_the_exact_grant_with_the_execution_claim() {
    let database = TempDatabase::new();
    let (store, claim, approval_id, effective_policy_id) =
        exact_approval_claim_fixture(&database, "execution-exact-approval");
    let approval = claim.approval.as_ref().unwrap();
    assert_ne!(
        claim.request_content_digest,
        approval.canonical_payload().operation_digest
    );
    assert_ne!(
        approval.policy_decision_id(),
        &effective_policy_id,
        "approval-time P1 must remain distinct from fresh P2"
    );

    let ToolExecutionClaim::Claimed(authority) = store.begin_authorized(claim.clone()).unwrap()
    else {
        panic!("fresh authorized execution must win the durable claim");
    };
    assert_eq!(authority.execution_id(), &claim.execution_id);
    let mut replay = claim;
    replay.checked_at = Timestamp::from_unix_seconds(4_102_444_801);
    assert!(matches!(
        store.begin_authorized(replay).unwrap(),
        ToolExecutionClaim::InFlight(_)
    ));

    let connection = configured_connection(&database.path);
    assert_eq!(
        connection
            .query_row(
                "SELECT status || ':' || invalidation_reason
                 FROM approvals WHERE id = ?1",
                [approval_id.as_str()],
                |row| row.get::<_, String>(0),
            )
            .unwrap(),
        "invalidated:consumed"
    );
    assert_eq!(
        connection
            .query_row(
                "SELECT policy_decision_id || ':' || approval_id
                 FROM tool_executions WHERE id = 'execution-exact-approval'",
                [],
                |row| row.get::<_, String>(0),
            )
            .unwrap(),
        format!("{}:{}", effective_policy_id.as_str(), approval_id.as_str())
    );
    assert_eq!(
        connection
            .query_row(
                "SELECT oi.status || ':' || te.status
                 FROM operation_intents oi
                 JOIN tool_executions te ON te.id = oi.id
                 WHERE oi.id = 'execution-exact-approval'",
                [],
                |row| row.get::<_, String>(0),
            )
            .unwrap(),
        "claimed:pending"
    );
    assert_eq!(
        connection
            .query_row(
                "SELECT COUNT(*) FROM events
                 WHERE event_type = 'tool.execution.started'
                   AND json_extract(payload_json, '$.executionId') =
                       'execution-exact-approval'",
                [],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
        0
    );
    assert_eq!(
        connection
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
fn authoritative_process_binding_starts_only_the_exact_claim() {
    let database = TempDatabase::new();
    let (store, claim, _, _) = exact_approval_claim_fixture(&database, "execution-process-binding");
    let ToolExecutionClaim::Claimed(authority) = store.begin_authorized(claim).unwrap() else {
        panic!("fresh authorized execution must win the durable claim");
    };
    assert_eq!(
        store
            .load_claimed_authority(authority.execution_id())
            .unwrap(),
        authority
    );
    let claimed_incomplete = store.incomplete().unwrap();
    let [IncompleteToolExecution::InFlight(claimed)] = claimed_incomplete.as_slice() else {
        panic!("claimed execution must be reported as in flight");
    };
    assert_eq!(claimed.state, ToolExecutionRecoveryState::Claimed);
    assert_eq!(claimed.process_binding, None);
    let binding =
        AuthoritativeProcessBinding::new(authority.clone(), 4_242, "job-process-binding").unwrap();

    store.record_process_binding(binding.clone()).unwrap();
    store.record_process_binding(binding.clone()).unwrap();

    let started_incomplete = store.incomplete().unwrap();
    let [IncompleteToolExecution::InFlight(started)] = started_incomplete.as_slice() else {
        panic!("started execution must be reported as in flight");
    };
    assert_eq!(started.state, ToolExecutionRecoveryState::Started);
    assert_eq!(started.process_binding.as_ref(), Some(&binding));

    let connection = configured_connection(&database.path);
    assert_eq!(
        connection
            .query_row(
                "SELECT oi.status || ':' || te.status || ':' ||
                        json_extract(oi.external_receipt_json, '$.schema') || ':' ||
                        json_extract(oi.external_receipt_json, '$.rootPid') || ':' ||
                        json_extract(oi.external_receipt_json, '$.jobId')
                 FROM operation_intents oi
                 JOIN tool_executions te ON te.id = oi.id
                 WHERE oi.id = 'execution-process-binding'",
                [],
                |row| row.get::<_, String>(0),
            )
            .unwrap(),
        "started:running:process-binding.v1:4242:job-process-binding"
    );
    assert_eq!(
        connection
            .query_row(
                "SELECT COUNT(*) FROM events
                 WHERE event_type = 'tool.execution.started'
                   AND json_extract(payload_json, '$.executionId') =
                       'execution-process-binding'",
                [],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
        1
    );
    assert_integrity_failure(store.record_process_binding(
        AuthoritativeProcessBinding::new(authority, 4_243, "job-process-binding").unwrap(),
    ));
}

#[test]
fn recovered_process_termination_round_trips_exact_receipt_and_audit() {
    let database = TempDatabase::new();
    let execution_id = "execution-recovered-process";
    let (store, claim, _, _) = exact_approval_claim_fixture(&database, execution_id);
    let operation_digest = claim.request_content_digest.clone();
    let ToolExecutionClaim::Claimed(authority) = store.begin_authorized(claim).unwrap() else {
        panic!("fresh authorized execution must win the durable claim");
    };
    let binding =
        AuthoritativeProcessBinding::new(authority, 4_242, "job-recovered-process").unwrap();
    store.record_process_binding(binding.clone()).unwrap();
    let receipt = recovered_process_receipt(&binding);

    assert_eq!(
        store
            .resolve_terminal(ToolExecutionResolution::new(receipt.clone()))
            .unwrap(),
        receipt
    );

    let connection = configured_connection(&database.path);
    let persisted: String = connection
        .query_row(
            "SELECT external_receipt_json FROM operation_intents WHERE id = ?1",
            [execution_id],
            |row| row.get(0),
        )
        .unwrap();
    let wire: serde_json::Value = serde_json::from_str(&persisted).unwrap();
    assert_eq!(
        wire,
        serde_json::json!({
            "authority": {
                "attempt": 1,
                "executionId": execution_id,
                "executorFencingToken": 19,
                "operationDigest": operation_digest.as_str(),
                "ownerRunId": "run-1",
            },
            "processTermination": {
                "binding": {
                    "jobId": binding.job_id(),
                    "rootPid": binding.root_pid(),
                },
                "receipt": {
                    "cancelled": true,
                    "executionId": execution_id,
                    "job": {
                        "cpuTimeLimitMs": 32,
                        "jobCpuTimeLimit": true,
                        "jobId": binding.job_id(),
                        "jobMemoryLimit": true,
                        "killOnClose": true,
                        "maxActiveProcesses": 1,
                        "memoryLimitBytes": 64,
                        "noBreakaway": true,
                        "resourceLimitTerminated": false,
                        "rootPid": binding.root_pid(),
                        "totalUserTimeMs": 7,
                        "treeTerminated": true,
                    },
                    "status": "terminated",
                },
            },
            "schema": "tool-execution-terminal.v2",
            "terminal": {
                "error": {
                    "classification": "unavailable",
                    "retryability": "non_retryable",
                },
                "kind": "indeterminate",
            },
        })
    );
    let event_payload: String = connection
        .query_row(
            "SELECT payload_json FROM events
             WHERE event_type = 'tool.execution.completed'
               AND json_extract(payload_json, '$.executionId') = ?1",
            [execution_id],
            |row| row.get(0),
        )
        .unwrap();
    let event: serde_json::Value = serde_json::from_str(&event_payload).unwrap();
    assert_eq!(event["receipt"], wire);

    let reopened = SqliteStore::open(&database.path).unwrap();
    assert_eq!(
        reopened
            .begin(NewToolExecution {
                execution_id: ToolExecutionId::new(execution_id).unwrap(),
                operation_digest: operation_digest.clone(),
            })
            .unwrap(),
        ToolExecutionClaim::Completed(receipt)
    );

    let mut corrupt = wire;
    corrupt["terminal"]["error"]["retryability"] =
        serde_json::Value::String("retryable".to_owned());
    connection
        .execute(
            "UPDATE operation_intents SET external_receipt_json = ?1 WHERE id = ?2",
            params![corrupt.to_string(), execution_id],
        )
        .unwrap();
    let before = durable_read_fingerprint(&database);
    assert_integrity_failure(reopened.begin(NewToolExecution {
        execution_id: ToolExecutionId::new(execution_id).unwrap(),
        operation_digest,
    }));
    assert_eq!(durable_read_fingerprint(&database), before);
}

#[test]
fn recovered_process_termination_rejects_binding_substitution_on_commit_and_replay() {
    let database = TempDatabase::new();
    let execution_id = "execution-recovery-binding-substitution";
    let (store, claim, _, _) = exact_approval_claim_fixture(&database, execution_id);
    let operation_digest = claim.request_content_digest.clone();
    let ToolExecutionClaim::Claimed(authority) = store.begin_authorized(claim).unwrap() else {
        panic!("fresh authorized execution must win the durable claim");
    };
    let persisted_binding =
        AuthoritativeProcessBinding::new(authority.clone(), 4_242, "job-recovery-binding-original")
            .unwrap();
    store
        .record_process_binding(persisted_binding.clone())
        .unwrap();
    let substituted_binding =
        AuthoritativeProcessBinding::new(authority, 4_243, "job-recovery-binding-substituted")
            .unwrap();
    let before = durable_read_fingerprint(&database);

    assert_integrity_failure(store.resolve_terminal(ToolExecutionResolution::new(
        recovered_process_receipt(&substituted_binding),
    )));
    assert_eq!(durable_read_fingerprint(&database), before);
    assert_eq!(lifecycle_state(&database, execution_id), "running:started");

    store
        .resolve_terminal(ToolExecutionResolution::new(recovered_process_receipt(
            &persisted_binding,
        )))
        .unwrap();
    let connection = configured_connection(&database.path);
    let receipt_json: String = connection
        .query_row(
            "SELECT external_receipt_json FROM operation_intents WHERE id = ?1",
            [execution_id],
            |row| row.get(0),
        )
        .unwrap();
    let mut substituted_receipt: serde_json::Value = serde_json::from_str(&receipt_json).unwrap();
    substituted_receipt["processTermination"]["binding"]["rootPid"] =
        serde_json::json!(substituted_binding.root_pid());
    substituted_receipt["processTermination"]["binding"]["jobId"] =
        serde_json::json!(substituted_binding.job_id());
    substituted_receipt["processTermination"]["receipt"]["job"]["rootPid"] =
        serde_json::json!(substituted_binding.root_pid());
    substituted_receipt["processTermination"]["receipt"]["job"]["jobId"] =
        serde_json::json!(substituted_binding.job_id());
    let event_json: String = connection
        .query_row(
            "SELECT payload_json FROM events
             WHERE event_type = 'tool.execution.completed'
               AND json_extract(payload_json, '$.executionId') = ?1",
            [execution_id],
            |row| row.get(0),
        )
        .unwrap();
    let mut substituted_event: serde_json::Value = serde_json::from_str(&event_json).unwrap();
    substituted_event["receipt"] = substituted_receipt.clone();
    connection
        .execute_batch("DROP TRIGGER events_update_forbidden;")
        .unwrap();
    connection
        .execute(
            "UPDATE operation_intents SET external_receipt_json = ?1 WHERE id = ?2",
            params![substituted_receipt.to_string(), execution_id],
        )
        .unwrap();
    connection
        .execute(
            "UPDATE events SET payload_json = ?1
             WHERE event_type = 'tool.execution.completed'
               AND json_extract(payload_json, '$.executionId') = ?2",
            params![substituted_event.to_string(), execution_id],
        )
        .unwrap();
    let before = durable_read_fingerprint(&database);

    assert_integrity_failure(store.begin(NewToolExecution {
        execution_id: ToolExecutionId::new(execution_id).unwrap(),
        operation_digest,
    }));
    assert_eq!(durable_read_fingerprint(&database), before);
}

#[test]
fn incomplete_rejects_corrupt_authoritative_process_binding_without_mutation() {
    let database = TempDatabase::new();
    let (store, claim, _, _) = exact_approval_claim_fixture(&database, "execution-corrupt-binding");
    let ToolExecutionClaim::Claimed(authority) = store.begin_authorized(claim).unwrap() else {
        panic!("fresh authorized execution must win the durable claim");
    };
    store
        .record_process_binding(
            AuthoritativeProcessBinding::new(authority, 4_242, "job-corrupt-binding").unwrap(),
        )
        .unwrap();
    configured_connection(&database.path)
        .execute(
            "UPDATE operation_intents
             SET external_receipt_json = json_set(
                 external_receipt_json,
                 '$.operationDigest',
                 'sha256:0000000000000000000000000000000000000000000000000000000000000000'
             )
             WHERE id = 'execution-corrupt-binding'",
            [],
        )
        .unwrap();
    let before = durable_read_fingerprint(&database);

    assert_integrity_failure(store.incomplete());
    assert_eq!(durable_read_fingerprint(&database), before);
}

#[test]
fn process_binding_rejects_stale_claim_authority_without_starting() {
    let database = TempDatabase::new();
    let (store, claim, _, _) =
        exact_approval_claim_fixture(&database, "execution-stale-process-binding");
    let ToolExecutionClaim::Claimed(authority) = store.begin_authorized(claim).unwrap() else {
        panic!("fresh authorized execution must win the durable claim");
    };
    let stale = ToolExecutionClaimAuthority::from_persisted(
        authority.execution_id().clone(),
        authority.operation_digest().clone(),
        authority.owner_run_id().clone(),
        authority.attempt() + 1,
        authority.executor_fencing_token(),
    )
    .unwrap();

    assert_integrity_failure(store.record_process_binding(
        AuthoritativeProcessBinding::new(stale, 4_242, "job-stale-binding").unwrap(),
    ));
    assert_eq!(
        configured_connection(&database.path)
            .query_row(
                "SELECT oi.status || ':' || te.status || ':' ||
                        (oi.external_receipt_json IS NULL)
                 FROM operation_intents oi
                 JOIN tool_executions te ON te.id = oi.id
                 WHERE oi.id = 'execution-stale-process-binding'",
                [],
                |row| row.get::<_, String>(0),
            )
            .unwrap(),
        "claimed:pending:1"
    );
}

#[test]
fn concurrent_cancellation_has_one_durable_claimant_and_one_cancelling_event() {
    let database = TempDatabase::new();
    let (store, _, authority) = reserve_and_claim(&database, "execution-cancel-concurrent");
    let execution_id = authority.execution_id().clone();
    let barrier = Arc::new(Barrier::new(3));
    let mut workers = Vec::new();
    for _ in 0..2 {
        let store = store.clone();
        let execution_id = execution_id.clone();
        let barrier = Arc::clone(&barrier);
        workers.push(std::thread::spawn(move || {
            barrier.wait();
            store.request_cancellation(&execution_id).unwrap()
        }));
    }
    barrier.wait();
    let outcomes = workers
        .into_iter()
        .map(|worker| worker.join().unwrap())
        .collect::<Vec<_>>();

    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| matches!(outcome, ToolExecutionCancellationClaim::Claimed(_)))
            .count(),
        1
    );
    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| matches!(outcome, ToolExecutionCancellationClaim::InFlight(_)))
            .count(),
        1
    );
    assert!(outcomes.iter().all(|outcome| match outcome {
        ToolExecutionCancellationClaim::Claimed(observed)
        | ToolExecutionCancellationClaim::InFlight(observed) => observed == &authority,
        ToolExecutionCancellationClaim::Completed(_) => false,
    }));
    let connection = configured_connection(&database.path);
    assert_eq!(
        connection
            .query_row(
                "SELECT oi.status || ':' || te.status || ':' || t.operation_state
                 FROM operation_intents oi
                 JOIN tool_executions te ON te.id = oi.id
                 JOIN tasks t ON t.id = oi.task_id
                 WHERE oi.id = ?1",
                [execution_id.as_str()],
                |row| row.get::<_, String>(0),
            )
            .unwrap(),
        "started:running:Cancelling"
    );
    assert_eq!(
        connection
            .query_row(
                "SELECT COUNT(*) FROM events
                 WHERE event_type = 'operation.cancel.requested'
                   AND json_extract(payload_json, '$.executionId') = ?1
                   AND json_extract(payload_json, '$.attempt') = ?2",
                params![execution_id.as_str(), authority.attempt()],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
        1
    );
}

#[test]
fn cancellation_rolls_back_atomically_and_replays_the_terminal_receipt() {
    let database = TempDatabase::new();
    let (store, output_digest, authority) =
        reserve_and_claim(&database, "execution-cancel-terminal");
    let execution_id = authority.execution_id().clone();
    let connection = configured_connection(&database.path);
    connection
        .execute_batch(
            "CREATE TRIGGER injected BEFORE UPDATE ON tasks
             WHEN NEW.operation_state = 'Cancelling'
             BEGIN SELECT RAISE(ABORT, 'fault'); END;",
        )
        .unwrap();

    assert!(store.request_cancellation(&execution_id).is_err());
    assert_eq!(
        connection
            .query_row(
                "SELECT t.operation_state || ':' ||
                        (SELECT COUNT(*) FROM events
                         WHERE event_type = 'operation.cancel.requested'
                           AND json_extract(payload_json, '$.executionId') = ?1)
                 FROM tasks t WHERE t.id = 'task-1'",
                [execution_id.as_str()],
                |row| row.get::<_, String>(0),
            )
            .unwrap(),
        "Running:0"
    );
    connection.execute_batch("DROP TRIGGER injected;").unwrap();

    assert_eq!(
        store.request_cancellation(&execution_id).unwrap(),
        ToolExecutionCancellationClaim::Claimed(authority.clone())
    );
    let terminal = terminal_fixture(ToolExecutionTerminalKind::Terminated, output_digest, None);
    let expected = DurableToolExecutionReceipt::new(authority, terminal);
    assert_eq!(
        store
            .resolve_terminal(ToolExecutionResolution::new(expected.clone()))
            .unwrap(),
        expected
    );
    assert_eq!(
        store.request_cancellation(&execution_id).unwrap(),
        ToolExecutionCancellationClaim::Completed(expected)
    );
    assert_eq!(
        connection
            .query_row(
                "SELECT operation_state FROM tasks WHERE id = 'task-1'",
                [],
                |row| row.get::<_, String>(0),
            )
            .unwrap(),
        "None"
    );
}

#[test]
fn denied_disposition_is_terminal_and_replayable() {
    let database = TempDatabase::new();
    let (store, denial, claim) = exact_denial_fixture(&database, "execution-denied-disposition");
    let immutable = denial.request.clone();
    let denied_policy_id = denial.policy_decision_id.clone();

    assert!(store
        .load_denied(&claim.request_artifact_id, &immutable)
        .unwrap()
        .is_none());
    let outcome = store.resolve_denied(denial.clone()).unwrap();
    assert_eq!(outcome.execution_id(), &claim.execution_id);
    assert_eq!(outcome.request_artifact_id(), &claim.request_artifact_id);
    assert_eq!(outcome.policy_decision_id(), &denied_policy_id);
    assert_eq!(
        configured_connection(&database.path)
            .query_row(
                "SELECT oi.status || ':' || te.status
                 FROM operation_intents oi
                 JOIN tool_executions te ON te.id = oi.id
                 WHERE oi.id = ?1",
                [claim.execution_id.as_str()],
                |row| row.get::<_, String>(0),
            )
            .unwrap(),
        "cancelled:denied"
    );
    let replay = store
        .load_denied(&claim.request_artifact_id, &immutable)
        .unwrap()
        .unwrap();
    assert_eq!(replay, outcome);
    assert_eq!(store.resolve_denied(denial).unwrap(), outcome);
    assert!(store.begin_authorized(claim.clone()).is_err());
    assert!(store.incomplete().unwrap().is_empty());
    assert_eq!(
        configured_connection(&database.path)
            .query_row(
                "SELECT json_extract(error_json, '$.kind') || ':' ||
                        json_extract(error_json, '$.policyDecisionId')
                 FROM operation_intents WHERE id = ?1",
                [claim.execution_id.as_str()],
                |row| row.get::<_, String>(0),
            )
            .unwrap(),
        format!("policy_denied:{}", denied_policy_id.as_str())
    );
    assert_eq!(
        configured_connection(&database.path)
            .query_row(
                "SELECT COUNT(*) FROM events
                 WHERE event_type = 'tool.execution.denied'
                   AND json_extract(payload_json, '$.policyDecisionId') = ?1",
                [denied_policy_id.as_str()],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
        1
    );
}

#[test]
fn denied_disposition_faults_leave_the_intent_pending() {
    let faults = [
        "CREATE TRIGGER injected BEFORE UPDATE ON operation_intents
         WHEN NEW.status = 'cancelled'
         BEGIN SELECT RAISE(ABORT, 'fault'); END;",
        "CREATE TRIGGER injected BEFORE INSERT ON tool_executions
         WHEN NEW.status = 'denied'
         BEGIN SELECT RAISE(ABORT, 'fault'); END;",
        "CREATE TRIGGER injected BEFORE INSERT ON events
         WHEN NEW.event_type = 'tool.execution.denied'
         BEGIN SELECT RAISE(ABORT, 'fault'); END;",
        "CREATE TRIGGER injected BEFORE UPDATE ON tasks
         WHEN NEW.current_sequence > OLD.current_sequence
         BEGIN SELECT RAISE(ABORT, 'fault'); END;",
    ];
    for (index, fault) in faults.into_iter().enumerate() {
        let database = TempDatabase::new();
        let execution_id = format!("execution-denied-fault-{index}");
        let (store, denial, _) = exact_denial_fixture(&database, &execution_id);
        configured_connection(&database.path)
            .execute_batch(fault)
            .unwrap();

        assert!(store.resolve_denied(denial).is_err());
        let connection = configured_connection(&database.path);
        assert_eq!(
            connection
                .query_row(
                    "SELECT status || ':' || COALESCE(error_json, 'null')
                     FROM operation_intents WHERE id = ?1",
                    [execution_id.as_str()],
                    |row| row.get::<_, String>(0),
                )
                .unwrap(),
            "pending:null"
        );
        assert_eq!(
            connection
                .query_row(
                    "SELECT COUNT(*) FROM tool_executions WHERE id = ?1",
                    [execution_id.as_str()],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            0
        );
        assert_eq!(
            connection
                .query_row(
                    "SELECT COUNT(*) FROM events
                     WHERE event_type = 'tool.execution.denied'
                       AND json_extract(payload_json, '$.executionId') = ?1",
                    [execution_id.as_str()],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            0
        );
    }
}

#[test]
fn concurrent_denied_disposition_creates_one_terminal_projection() {
    let database = TempDatabase::new();
    let (store, denial, _) = exact_denial_fixture(&database, "execution-denied-concurrent");
    let barrier = Arc::new(Barrier::new(2));
    let outcomes = std::thread::scope(|scope| {
        let first_store = store.clone();
        let first_denial = denial.clone();
        let first_barrier = Arc::clone(&barrier);
        let first = scope.spawn(move || {
            first_barrier.wait();
            first_store.resolve_denied(first_denial)
        });
        let second_store = store.clone();
        let second_barrier = Arc::clone(&barrier);
        let second = scope.spawn(move || {
            second_barrier.wait();
            second_store.resolve_denied(denial)
        });
        [
            first.join().unwrap().unwrap(),
            second.join().unwrap().unwrap(),
        ]
    });

    assert_eq!(outcomes[0], outcomes[1]);
    assert_eq!(
        configured_connection(&database.path)
            .query_row(
                "SELECT COUNT(*) FROM events
                 WHERE event_type = 'tool.execution.denied'
                   AND json_extract(payload_json, '$.executionId') =
                       'execution-denied-concurrent'",
                [],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
        1
    );
}

#[test]
fn denied_disposition_rejects_a_non_denial_policy_without_transition() {
    let database = TempDatabase::new();
    let (store, mut denial, authorized) =
        exact_denial_fixture(&database, "execution-denied-wrong-policy");
    denial.policy_decision_id = authorized.policy_decision_id.clone();

    assert_integrity_failure(store.resolve_denied(denial));
    assert_eq!(
        configured_connection(&database.path)
            .query_row(
                "SELECT status FROM operation_intents WHERE id = ?1",
                [authorized.execution_id.as_str()],
                |row| row.get::<_, String>(0),
            )
            .unwrap(),
        "pending"
    );
}

#[test]
fn sqlite_resume_loads_the_exact_approval_intent_and_full_request_relation() {
    let database = TempDatabase::new();
    let (store, claim, approval_id, _) =
        exact_approval_claim_fixture(&database, "execution-resume-storage");
    let approval_request = claim.approval.as_ref().unwrap();
    let approval_snapshot = store
        .load_for_resume(&approval_id, claim.checked_at)
        .unwrap();
    let execution_snapshot = store.load_intent(&claim.execution_id).unwrap();
    validate_approval_resume_relation(&approval_snapshot, &execution_snapshot).unwrap();
    let immutable = store
        .load_request_artifact(&claim.request_artifact_id)
        .unwrap();
    let loaded_approval = store.load_approval_request(&approval_id).unwrap();

    assert_eq!(approval_snapshot.approval_id, approval_id);
    assert_eq!(
        approval_snapshot.execution_id, claim.execution_id,
        "resume must follow the immutable event relation"
    );
    assert_eq!(
        execution_snapshot.request_artifact_id,
        claim.request_artifact_id
    );
    assert_eq!(immutable.binding_digest(), &claim.request_binding_digest);
    assert_eq!(&loaded_approval, approval_request);
}

#[test]
fn sqlite_resume_rejects_artifacts_outside_canonical_paths() {
    for approval_artifact in [false, true] {
        let database = TempDatabase::new();
        let (store, claim, approval_id, _) =
            exact_approval_claim_fixture(&database, "execution-resume-wrong-path");
        let artifact_id = if approval_artifact {
            claim
                .approval
                .as_ref()
                .unwrap()
                .approval_artifact_id()
                .as_str()
        } else {
            claim.request_artifact_id.as_str()
        };
        configured_connection(&database.path)
            .execute(
                "UPDATE artifacts SET logical_path = ?1 WHERE id = ?2",
                params![
                    if approval_artifact {
                        "wrong/path.json"
                    } else {
                        "tool-requests/another-execution.json"
                    },
                    artifact_id,
                ],
            )
            .unwrap();

        if approval_artifact {
            assert_integrity_failure(store.load_approval_request(&approval_id));
        } else {
            assert_integrity_failure(store.load_request_artifact(&claim.request_artifact_id));
        }
    }
}

#[test]
fn sqlite_resume_rejects_an_intent_owned_by_another_task() {
    let database = TempDatabase::new();
    let (store, claim, approval_id, _) =
        exact_approval_claim_fixture(&database, "execution-resume-wrong-task");
    seed_other_task(&database);
    configured_connection(&database.path)
        .execute(
            "UPDATE operation_intents SET task_id = 'task-2' WHERE id = ?1",
            [claim.execution_id.as_str()],
        )
        .unwrap();

    assert_integrity_failure(store.load_for_resume(&approval_id, claim.checked_at));
}

#[test]
fn sqlite_resume_rejects_a_request_artifact_owned_by_another_task() {
    let database = TempDatabase::new();
    let (store, claim, _, _) =
        exact_approval_claim_fixture(&database, "execution-resume-wrong-artifact-task");
    seed_other_task(&database);
    configured_connection(&database.path)
        .execute(
            "UPDATE artifacts SET task_id = 'task-2' WHERE id = ?1",
            [claim.request_artifact_id.as_str()],
        )
        .unwrap();

    assert_integrity_failure(store.load_request_artifact(&claim.request_artifact_id));
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
        let (store, claim, _, _) = exact_approval_claim_fixture(&database, execution_id);
        let artifact_id = if approval_artifact {
            claim
                .approval
                .as_ref()
                .unwrap()
                .approval_artifact_id()
                .as_str()
        } else {
            claim.request_artifact_id.as_str()
        };
        configured_connection(&database.path)
            .execute(
                "UPDATE artifacts SET artifact_type = 'evidence' WHERE id = ?1",
                [artifact_id],
            )
            .unwrap();

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
                let (artifact_id, _) =
                    persist_durable_artifact(&database, "cross-task-artifact", b"cross-task");
                configured_connection(&database.path)
                    .execute(
                        "UPDATE artifacts SET task_id = 'task-2' WHERE id = ?1",
                        [artifact_id.as_str()],
                    )
                    .unwrap();
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
    persist_artifact(
        database,
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

fn exact_tool_request(execution_id: &str) -> ToolRequest {
    let task_id = TaskId::new("task-1").unwrap();
    let process = ProcessToolRequest::new(
        ProcessBinding::new(
            task_id.clone(),
            RunId::new("run-1").unwrap(),
            PlanStepId::new("step-1").unwrap(),
            Phase::Implementation,
            WorkspaceVersion::new(4),
            EnvironmentProfile::new("rust", digest_char('e')).unwrap(),
            1,
        )
        .unwrap(),
        ProcessInvocation::new(
            CapabilityRef::toolchain("cargo").unwrap(),
            vec!["test".to_owned()],
            CapabilityRef::worktree(task_id.clone(), ".").unwrap(),
            ProcessTrustTier::IsolatedWorker,
            NetworkProfile::Denied,
            Vec::new(),
            Some(FencingToken::new(19).unwrap()),
        )
        .unwrap(),
    )
    .unwrap();
    let approved = ApprovedProcessRequest::new(
        ApprovedExecutableIdentity::new(
            ResolvedExecutable {
                canonical_path: PathBuf::from(resolver_canonical_executable_path()),
                sha256: digest_char('d'),
                file_identity: ExecutableFileIdentity::new("cargo-file").unwrap(),
                toolchain_id: "cargo".to_owned(),
            },
            "1.97.1",
        )
        .unwrap(),
        process,
        Vec::new(),
        None,
        None,
    )
    .unwrap();
    let policy = ToolPolicyContext::new(
        PolicyActor {
            connection_id: "connection-1".to_owned(),
            agent_id: "agent-1".to_owned(),
            trust_tier: TrustTier::IsolatedWorker,
            locality: ActorLocality::Local,
        },
        PolicyAction::new("process.exec").unwrap(),
        PolicyResource {
            capability: CapabilityRef::worktree(task_id, ".").unwrap(),
            content_digest: digest_char('a'),
            resource_class: ResourceClass::InternalCode,
        },
        TaskRisk::High,
        "run focused tests",
        digest_char('b'),
    )
    .unwrap();
    ToolRequest::new(
        ToolExecutionId::new(execution_id).unwrap(),
        approved,
        policy,
    )
    .unwrap()
}

fn record_exact_policy(
    store: &SqliteStore,
    request: &ToolRequest,
    evaluated_at: Timestamp,
    effect: PolicyEffect,
    digest_marker: char,
) -> local_agent_terminal_application::PolicyDecisionId {
    let policy_request = policy_request_for_tool(request, evaluated_at);
    let draft = combine_policy_rules(
        policy_request,
        PolicyVersion::new(1).unwrap(),
        vec![MatchedPolicyRule {
            rule_id: PolicyRuleId::new(format!("rule-{digest_marker}")).unwrap(),
            effect,
            redactions: Vec::new(),
        }],
        Some(Timestamp::from_unix_seconds(4_102_444_800)),
    )
    .unwrap();
    store
        .record(RecordedPolicyDecision {
            decision: PolicyDecision {
                draft,
                operation_digest: digest_char(digest_marker),
            },
            recorded_at: evaluated_at,
        })
        .unwrap()
}

fn exact_denial_fixture(
    database: &TempDatabase,
    execution_id: &str,
) -> (
    SqliteStore,
    ToolExecutionDenialRequest,
    AuthorizedToolExecutionClaim,
) {
    let (store, authorized, _, _) = exact_approval_claim_fixture(database, execution_id);
    let immutable = store
        .load_request_artifact(&authorized.request_artifact_id)
        .unwrap();
    let policy_decision_id = record_exact_policy(
        &store,
        immutable.request(),
        authorized.checked_at,
        PolicyEffect::Deny,
        '9',
    );
    let denial = ToolExecutionDenialRequest {
        request_artifact_id: authorized.request_artifact_id.clone(),
        request: immutable,
        policy_decision_id,
        policy_request_binding_digest: authorized.policy_request_binding_digest.clone(),
        effect: PolicyEffect::Deny,
        checked_at: authorized.checked_at,
    };
    (store, denial, authorized)
}

fn exact_approval_claim_fixture(
    database: &TempDatabase,
    execution_id: &str,
) -> (
    SqliteStore,
    AuthorizedToolExecutionClaim,
    ApprovalId,
    local_agent_terminal_application::PolicyDecisionId,
) {
    let store = SqliteStore::open(&database.path).unwrap();
    let request = exact_tool_request(execution_id);
    let immutable = canonical_tool_request(&request).unwrap();
    let request_artifact_id = ArtifactId::new(format!("request-{execution_id}")).unwrap();
    persist_artifact(
        database,
        request_artifact_id.as_str(),
        &format!("tool-requests/{execution_id}.json"),
        "tool-request",
        immutable.canonical_bytes(),
    );
    store
        .reserve(NewToolIntent {
            execution_id: request.execution_id().clone(),
            operation_digest: immutable.binding_digest().as_sha256().clone(),
        })
        .unwrap();

    let checked_at = Timestamp::from_unix_seconds(1_753_272_300);
    let approval_policy_id = record_exact_policy(
        &store,
        &request,
        Timestamp::from_unix_seconds(checked_at.unix_seconds() - 60),
        PolicyEffect::RequireApproval,
        '3',
    );
    let effective_policy_id = record_exact_policy(
        &store,
        &request,
        checked_at,
        PolicyEffect::RequireApproval,
        '4',
    );
    let policy_binding =
        canonical_policy_binding_digest(&policy_request_for_tool(&request, checked_at)).unwrap();
    let bound = bind_tool_approval_payload(
        ToolApprovalPayloadV1 {
            schema: "approval-digest.v1".to_owned(),
            approval_type: "tool".to_owned(),
            task_id: "unbound".to_owned(),
            operation: ToolApprovalOperationV1 {
                run_id: "unbound".to_owned(),
                plan_step_id: "unbound".to_owned(),
                tool: "process.exec".to_owned(),
                executable_digest: None,
                arguments_digest: digest_char('0').to_string(),
                script_digest: None,
                cwd_capability: "unbound".to_owned(),
                environment_profile_digest: digest_char('0').to_string(),
                network_profile: "denied".to_owned(),
                expected_writes: Vec::new(),
                executor_fencing_token: None,
            },
            policy_snapshot_digest: request.policy().policy_snapshot_digest().to_string(),
            workspace_version: 0,
            requested_at: "2026-07-23T12:00:00Z".to_owned(),
            expires_at: "2099-07-23T12:15:00Z".to_owned(),
            nonce: "0123456789abcdef0123456789abcdef".to_owned(),
        },
        request.process(),
    )
    .unwrap();
    let approval_id = ApprovalId::new(format!("approval-{execution_id}")).unwrap();
    let approval_artifact_id =
        ArtifactId::new(format!("approval-artifact-{execution_id}")).unwrap();
    let approval = ToolApprovalRequest::from_persisted(
        approval_id.clone(),
        approval_artifact_id.clone(),
        request.execution_id().clone(),
        approval_policy_id.clone(),
        policy_binding.clone(),
        request_artifact_id.clone(),
        immutable.binding_digest().clone(),
        bound.payload().clone(),
    )
    .unwrap();
    persist_artifact(
        database,
        approval_artifact_id.as_str(),
        &format!("approvals/{}.json", approval_id.as_str()),
        "approval-payload",
        &approval.canonical_payload().canonical_bytes,
    );
    let connection = configured_connection(&database.path);
    connection
        .execute(
            "INSERT INTO approvals (
                id, task_id, approval_type, schema_version, operation_digest, status,
                requested_at, resolved_at, resolved_by, expires_at, request_artifact_id,
                invalidation_reason
             ) VALUES (?1, 'task-1', 'tool', 'approval-digest.v1', ?2, 'granted',
                ?3, '2026-07-30T00:00:00Z', 'user', ?4, ?5, NULL)",
            params![
                approval_id.as_str(),
                approval.canonical_payload().operation_digest.as_str(),
                approval.payload().requested_at,
                approval.payload().expires_at,
                approval_artifact_id.as_str(),
            ],
        )
        .unwrap();
    connection
        .execute(
            "INSERT INTO events (
                event_id, stream_id, sequence, event_type, schema_version, actor_type,
                actor_id, observation_class, payload_json, metadata_json, causation_id,
                correlation_id, created_at
             ) VALUES (?1, 'task-1', 1, 'approval.requested', 1, 'core',
                'approval-store', 'core_observed', ?2, '{}', ?3, ?3,
                '2026-07-23T12:00:00Z')",
            params![
                format!("approval.requested:{}:1", approval_id.as_str()),
                serde_json::json!({
                    "approvalId": approval_id.as_str(),
                    "approvalType": "tool",
                    "operationDigest": approval.canonical_payload().operation_digest.as_str(),
                    "executionId": request.execution_id().as_str(),
                    "approvalPolicyDecisionId": approval_policy_id.as_str(),
                    "policyRequestBindingDigest": policy_binding.as_sha256().as_str(),
                    "toolRequestArtifactId": request_artifact_id.as_str(),
                    "toolRequestBindingDigest": immutable.binding_digest().as_sha256().as_str(),
                    "workspaceVersion": request.process().process().binding().workspace_version().get(),
                    "policySnapshotDigest": request.policy().policy_snapshot_digest().as_str(),
                    "fencingToken": request
                        .process()
                        .process()
                        .executor_fencing_token()
                        .map(FencingToken::get),
                    "nonce": approval.payload().nonce,
                    "requestArtifactId": approval_artifact_id.as_str(),
                })
                .to_string(),
                format!("approval:{}", approval_id.as_str()),
            ],
        )
        .unwrap();
    connection
        .execute(
            "INSERT INTO events (
                event_id, stream_id, sequence, event_type, schema_version, actor_type,
                actor_id, observation_class, payload_json, metadata_json, causation_id,
                correlation_id, created_at
             ) VALUES (?1, 'task-1', 2, 'approval.granted', 1, 'core',
                'approval-store', 'core_observed', ?2, '{}', ?3, ?3,
                '2026-07-30T00:00:00Z')",
            params![
                format!("approval.granted:{}:2", approval_id.as_str()),
                serde_json::json!({
                    "approvalId": approval_id.as_str(),
                    "status": "granted",
                })
                .to_string(),
                format!("approval:{}", approval_id.as_str()),
            ],
        )
        .unwrap();
    connection
        .execute(
            "UPDATE tasks SET operation_state = 'None', current_sequence = 2
             WHERE id = 'task-1'",
            [],
        )
        .unwrap();

    let process = request.process().process();
    let binding = process.binding();
    let claim = AuthorizedToolExecutionClaim {
        execution_id: request.execution_id().clone(),
        request_artifact_id,
        request_content_digest: immutable.binding_digest().as_sha256().clone(),
        request_binding_digest: immutable.binding_digest().clone(),
        task_id: binding.task_id().clone(),
        run_id: binding.run_id().clone(),
        tool_name: "process.exec".to_owned(),
        policy_decision_id: effective_policy_id.clone(),
        policy_request_binding_digest: policy_binding,
        approval: Some(approval),
        workspace_version: binding.workspace_version(),
        policy_snapshot_digest: request.policy().policy_snapshot_digest().clone(),
        fencing_token: process.executor_fencing_token(),
        checked_at,
    };
    (store, claim, approval_id, effective_policy_id)
}

#[cfg(windows)]
fn resolver_canonical_executable_path() -> &'static str {
    r"\\?\C:\approved\cargo.exe"
}

#[cfg(not(windows))]
fn resolver_canonical_executable_path() -> &'static str {
    "/approved/cargo"
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
                "toolRequestBindingDigest": digest_char('f').as_str(),
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

fn insert_status_test_execution(
    database: &TempDatabase,
    store: &SqliteStore,
    operation_digest: &Sha256Digest,
    index: usize,
    status: &str,
    request_id: &str,
) -> rusqlite::Result<()> {
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
            executor_fencing_token, status, started_at, completed_at, exit_code,
            stdout_artifact_id, stderr_artifact_id
         ) VALUES (?1, 'task-1', 'run-1', ?2, 'process.exec', 'request-artifact',
            'policy-1', NULL, ?1, 19, ?3, NULL, NULL, NULL, NULL, NULL)",
        params![execution_id, request_id, status],
    )?;
    Ok(())
}

fn configured_connection(path: &Path) -> Connection {
    let connection = Connection::open(path).unwrap();
    connection
        .pragma_update(None, "foreign_keys", "ON")
        .unwrap();
    connection
}
