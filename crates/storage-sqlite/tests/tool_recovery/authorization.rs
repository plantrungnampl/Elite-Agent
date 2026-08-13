use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Barrier};

use local_agent_terminal_application::{
    bind_tool_approval_payload, canonical_approval_payload, canonical_file_write_recovery_request,
    canonical_policy_binding_digest, canonical_tool_request, parse_approval_payload,
    policy_request_for_tool, ApprovalDigestPayload, ApprovalId, ApprovalResumeStore,
    ApprovedExecutableIdentity, ApprovedProcessRequest, AuthoritativeProcessBinding,
    AuthorizedToolExecutionClaim, CanonicalEvidenceRef, CapabilityRootIdentity,
    DurableToolExecutionReceipt, ExecutableFileIdentity, FileWritePolicyBinding, FileWritePreImage,
    FileWriteRecoveryCompletion, FileWriteRecoveryFailure, FileWriteRecoveryIntent,
    FileWriteRecoveryRequest, FileWriteRecoveryStore, IncompleteToolExecution, NewToolExecution,
    NewToolIntent, PolicyDecision, PolicyDecisionStore, ProcessExecutionBindingStore,
    RecordedPolicyDecision, RelativePathComponents, ResolvedExecutable, ToolApprovalOperationV1,
    ToolApprovalPayloadV1, ToolApprovalRequest, ToolExecutionClaim, ToolExecutionClaimAuthority,
    ToolExecutionDenialRequest, ToolExecutionId, ToolExecutionRecoveryState,
    ToolExecutionResolution, ToolExecutionResumeStore, ToolExecutionStore, ToolExecutionTerminal,
    ToolPolicyContext, ToolRequest,
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
                "SELECT status || ':' || current_attempt_no FROM operation_intents
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
                "SELECT status || ':' || current_attempt_no FROM operation_intents
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
                "SELECT status || ':' ||
                    (SELECT COUNT(*) FROM approval_effect_consumptions consumption
                     JOIN approval_decision_receipts receipt
                       ON receipt.id = consumption.approval_receipt_id
                     WHERE receipt.approval_id = approvals.id)
                 FROM approvals WHERE id = ?1",
                [approval_id.as_str()],
                |row| row.get::<_, String>(0),
            )
            .unwrap(),
        "granted:1"
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
fn process_binding_fails_closed_without_an_authoritative_receipt_artifact() {
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
        AuthoritativeProcessBinding::new(authority, 4_242, "job-process-binding").unwrap();
    let before = durable_read_fingerprint(&database);

    assert_integrity_failure(store.record_process_binding(binding));
    assert_eq!(durable_read_fingerprint(&database), before);

    let connection = configured_connection(&database.path);
    assert_eq!(
        connection
            .query_row(
                "SELECT oi.status || ':' || te.status || ':' || oa.status
                 FROM operation_intents oi
                 JOIN tool_executions te ON te.id = oi.id
                 JOIN operation_attempts oa ON oa.id = te.operation_attempt_id
                 WHERE oi.id = 'execution-process-binding'",
                [],
                |row| row.get::<_, String>(0),
            )
            .unwrap(),
        "claimed:pending:claimed"
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
        0
    );
}

#[test]
fn incomplete_remains_pure_when_process_binding_is_rejected_without_authority() {
    let database = TempDatabase::new();
    let (store, claim, _, _) = exact_approval_claim_fixture(&database, "execution-corrupt-binding");
    let ToolExecutionClaim::Claimed(authority) = store.begin_authorized(claim).unwrap() else {
        panic!("fresh authorized execution must win the durable claim");
    };
    let before = durable_read_fingerprint(&database);

    assert_integrity_failure(store.record_process_binding(
        AuthoritativeProcessBinding::new(authority, 4_242, "job-corrupt-binding").unwrap(),
    ));
    let incomplete = store.incomplete().unwrap();
    assert_eq!(incomplete.len(), 1);
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
                "SELECT oi.status || ':' || te.status || ':' || oa.status
                 FROM operation_intents oi
                 JOIN tool_executions te ON te.id = oi.id
                 JOIN operation_attempts oa ON oa.id = te.operation_attempt_id
                 WHERE oi.id = 'execution-stale-process-binding'",
                [],
                |row| row.get::<_, String>(0),
            )
            .unwrap(),
        "claimed:pending:claimed"
    );
}

#[test]
fn legacy_denial_and_cancellation_ports_fail_closed_without_v7_receipts() {
    let database = TempDatabase::new();
    let (store, denial, authorized) =
        exact_denial_fixture(&database, "execution-legacy-lifecycle");
    let execution_id = denial.request.request().execution_id().clone();
    let immutable = store
        .load_request_artifact(&authorized.request_artifact_id)
        .unwrap();
    let before = tool_boundary_fingerprint(&database, execution_id.as_str());

    assert_integrity_failure(store.load_denied(&authorized.request_artifact_id, &immutable));
    assert_integrity_failure(store.request_cancellation(&execution_id));
    assert_integrity_failure(store.resolve_denied(denial));

    assert_eq!(
        tool_boundary_fingerprint(&database, execution_id.as_str()),
        before
    );
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
