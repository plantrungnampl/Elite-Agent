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
    ToolExecutionPostEffectReceipt, ToolExecutionRecoveryState, ToolExecutionResolution,
    ToolExecutionResumeStore, ToolExecutionStore, ToolExecutionStreamMetadata,
    ToolExecutionTerminal, ToolExecutionTerminalKind, ToolPolicyContext, ToolRequest,
    ToolRequestBindingDigest, VerifiedFileWriteCompensation, VerifiedWrite,
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
        effect_checked_at: checked_at,
        approval_checked_at: None,
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
fn authorized_begin_rejects_an_allow_policy_that_expires_during_effect_revalidation() {
    let database = TempDatabase::new();
    let store = SqliteStore::open(&database.path).unwrap();
    let request = exact_tool_request("execution-expired-allow");
    let immutable = canonical_tool_request(&request).unwrap();
    let request_artifact_id = ArtifactId::new("expired-allow-request").unwrap();
    persist_artifact(
        &database,
        request_artifact_id.as_str(),
        "tool-requests/execution-expired-allow.json",
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
    let policy_id = record_exact_policy_with_expiry(
        &store,
        &request,
        checked_at,
        PolicyEffect::Allow,
        '5',
        Some(Timestamp::from_unix_seconds(checked_at.unix_seconds() + 30)),
    );
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
        policy_decision_id: policy_id,
        policy_request_binding_digest: canonical_policy_binding_digest(&policy_request_for_tool(
            &request, checked_at,
        ))
        .unwrap(),
        approval: None,
        workspace_version: binding.workspace_version(),
        policy_snapshot_digest: request.policy().policy_snapshot_digest().clone(),
        fencing_token: process.executor_fencing_token(),
        checked_at,
        effect_checked_at: Timestamp::from_unix_seconds(checked_at.unix_seconds() + 31),
        approval_checked_at: None,
    };

    assert!(store.begin_authorized(claim).is_err());
    assert_eq!(
        configured_connection(&database.path)
            .query_row(
                "SELECT status || ':' || attempt_count FROM operation_intents
                 WHERE id = 'execution-expired-allow'",
                [],
                |row| row.get::<_, String>(0),
            )
            .unwrap(),
        "pending:0"
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
fn authorized_begin_keeps_fresh_policy_time_separate_from_approval_revalidation() {
    let database = TempDatabase::new();
    let (store, mut claim, _, _) =
        exact_approval_claim_fixture(&database, "execution-later-approval-check");
    claim.approval_checked_at = Some(Timestamp::from_unix_seconds(
        claim.checked_at.unix_seconds() + 60,
    ));

    assert!(matches!(
        store.begin_authorized(claim).unwrap(),
        ToolExecutionClaim::Claimed(_)
    ));
}

#[test]
fn authorized_begin_rejects_approval_without_a_revalidation_time() {
    let database = TempDatabase::new();
    let (store, mut claim, _, _) =
        exact_approval_claim_fixture(&database, "execution-missing-approval-check");
    claim.approval_checked_at = None;

    assert_integrity_failure(store.begin_authorized(claim));
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
fn tool_audit_events_retain_authority_scope_and_causal_lineage() {
    let database = TempDatabase::new();
    let execution_id = "execution-audit-envelope";
    let (store, claim, approval_id, policy_id) =
        exact_approval_claim_fixture(&database, execution_id);
    let request_digest = claim.request_content_digest.to_string();
    let ToolExecutionClaim::Claimed(authority) = store.begin_authorized(claim).unwrap() else {
        panic!("fresh authorized execution must win the durable claim");
    };
    let binding = AuthoritativeProcessBinding::new(authority, 4_242, "job-audit-envelope").unwrap();
    store.record_process_binding(binding.clone()).unwrap();
    store
        .resolve_terminal(ToolExecutionResolution::new(recovered_process_receipt(
            &binding,
        )))
        .unwrap();

    let connection = configured_connection(&database.path);
    let events = connection
        .prepare(
            "SELECT event_id, event_type, actor_id, observation_class, payload_json,
                    causation_id, correlation_id
             FROM events
             WHERE stream_id = 'task-1'
               AND json_extract(payload_json, '$.executionId') = ?1
               AND event_type IN ('tool.execution.started', 'tool.execution.completed')
             ORDER BY sequence",
        )
        .unwrap()
        .query_map([execution_id], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, String>(5)?,
                row.get::<_, String>(6)?,
            ))
        })
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    let [started, completed] = events.as_slice() else {
        panic!("expected one started and one completed audit event");
    };
    let started_payload: serde_json::Value = serde_json::from_str(&started.4).unwrap();
    let completed_payload: serde_json::Value = serde_json::from_str(&completed.4).unwrap();

    for (event, payload) in [(started, &started_payload), (completed, &completed_payload)] {
        assert_eq!(event.2, "agent-1");
        assert_eq!(event.3, "tool_verified");
        assert_eq!(payload["actorBinding"]["actor"]["agentId"], "agent-1");
        assert!(payload["actorBinding"]["digest"]
            .as_str()
            .unwrap()
            .starts_with("sha256:"));
        assert_eq!(payload["effectiveRole"], "executor");
        assert_eq!(payload["requestDigest"], request_digest);
        assert_eq!(payload["operationDigest"], request_digest);
        assert_eq!(payload["policyDecisionId"], policy_id.as_str());
        assert_eq!(payload["approvalId"], approval_id.as_str());
        assert_eq!(payload["policySnapshotDigest"], digest_char('b').as_str());
        assert_eq!(payload["scope"]["capability"]["kind"], "worktree");
        assert_eq!(payload["scope"]["capability"]["taskId"], "task-1");
        assert_eq!(payload["executorFencingToken"], 19);
        assert_eq!(event.6, format!("tool-execution:{execution_id}"));
        assert_ne!(event.5, event.6);
    }
    assert_eq!(
        started.5,
        format!("approval.consumed:{}:3", approval_id.as_str())
    );
    assert_eq!(completed.5, started.0);
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
        let overrides = if approval_artifact {
            ExactApprovalArtifactOverrides {
                approval_logical_path: Some("wrong/path.json"),
                ..Default::default()
            }
        } else {
            ExactApprovalArtifactOverrides {
                request_logical_path: Some("tool-requests/another-execution.json"),
                ..Default::default()
            }
        };
        let (store, claim, approval_id, _) = exact_approval_claim_fixture_with_overrides(
            &database,
            "execution-resume-wrong-path",
            overrides,
        );

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
