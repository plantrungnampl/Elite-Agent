#[allow(dead_code)]
#[path = "support/mod.rs"]
mod support;

use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

use local_agent_terminal_application::{
    bind_tool_approval_payload, canonical_policy_binding_digest, canonical_tool_request,
    policy_request_for_tool, ApprovalId, ApprovalResolution, ApprovalResumeStore, ApprovalStore,
    ApprovedExecutableIdentity, ApprovedProcessRequest, AuthoritativeProcessBinding,
    AuthorizedToolRequest, BoundedOutput, CancellationReceipt, DisclosedToolExecutionArtifacts,
    DisclosureOutcome, DurableToolExecutionArtifact, FileReadRequest, FileWriteRequest,
    GitDiffRequest, GitDiffResult, GitStatusRequest, GitStatusResult, JobReceipt, PolicyBoundBytes,
    PolicyDecision, PolicyDecisionStore, PortError, ProcessExecutionBindingStore, ProcessReceipt,
    ProcessStatus, RecordedPolicyDecision, ResolveToolApprovalRequestDto, ResolvedExecutable,
    Retryability, SafeErrorClassification, StructuredToolExecutor, ToolActivityStatusDto,
    ToolApprovalDecisionDto, ToolApprovalOperationV1, ToolApprovalPayloadV1,
    ToolApprovalPublication, ToolApprovalRequest, ToolApprovalRequestPublisher,
    ToolAuthorityResolver, ToolAuthoritySnapshot, ToolControlSelfTest,
    ToolExecutionArtifactEvidence, ToolExecutionResult, ToolExecutionResumeStore, ToolOutcome,
    ToolPolicyContext, ToolRequest, ToolRequestPublisher, VerifiedWrite, WorkspaceEvidenceStore,
};
use local_agent_terminal_bootstrap::{
    Bootstrap, StartupConfig, ToolArtifactPublisher, ToolBrokerConfig, ToolRuntimeAvailability,
};
use local_agent_terminal_domain::{
    combine_policy_rules, ActorLocality, ArtifactId, CapabilityRef, EnvironmentProfile,
    MatchedPolicyRule, NetworkProfile, Phase, PlanStepId, PolicyAction, PolicyActor, PolicyEffect,
    PolicyResource, PolicyRuleId, PolicyVersion, ProcessBinding, ProcessInvocation,
    ProcessToolRequest, ProcessTrustTier, ResourceClass, RunId, Sha256Digest, TaskId, TaskRisk,
    Timestamp, TrustTier, WorkspaceVersion,
};
use local_agent_terminal_policy_engine::VersionedPolicyEngine;
use local_agent_terminal_storage_files::ContentAddressedArtifactStore;
use local_agent_terminal_storage_sqlite::SqliteStore;
use rusqlite::Connection;

use support::WorkspaceFixture;

const DENY_PROCESS_POLICY: &str =
    r#"{"version":1,"rules":[{"id":"deny-process","effect":"deny","action":"process.exec"}]}"#;
const ALLOW_PROCESS_POLICY: &str =
    r#"{"version":1,"rules":[{"id":"allow-process","effect":"allow","action":"process.exec"}]}"#;
const APPROVE_PROCESS_POLICY: &str = r#"{"version":1,"rules":[{"id":"approve-process","effect":"require_approval","action":"process.exec"}]}"#;
const DEFAULT_DENY_POLICY: &str =
    r#"{"version":1,"rules":[{"id":"default-deny","effect":"deny"}]}"#;
const EMPTY_BYTES_HASH: &str =
    "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
const SAFE_STDOUT_HASH: &str =
    "sha256:5683b63cb0db3f8a44813f2683e87a8ac594d153595d23fdae5b1cc5eb2f5de2";

#[test]
fn configured_runtime_routes_typed_requests_through_execute_tool() {
    let fixture = WorkspaceFixture::new();
    fixture.seed_present_workspace();
    let policy = VersionedPolicyEngine::from_json(DENY_PROCESS_POLICY).unwrap();
    let request =
        tool_request_for_policy("execution-runtime-denied", policy.snapshot_digest().clone());
    let executor = Arc::new(RecordingExecutor::default());
    let bootstrap = Bootstrap::with_tool_broker(
        StartupConfig {
            app_data_dir: fixture.app_data.clone(),
            trusted_workspace_root: fixture.workspace_root.clone(),
            secret_values: Vec::new(),
        },
        ToolBrokerConfig::new(
            DENY_PROCESS_POLICY,
            Arc::new(EchoAuthority),
            executor.clone(),
        ),
    );

    assert_eq!(
        bootstrap.tool_runtime().unwrap().availability().unwrap(),
        ToolRuntimeAvailability::Ready
    );
    let outcome = bootstrap.tool_runtime().unwrap().execute(request).unwrap();

    assert!(matches!(outcome, ToolOutcome::Denied(_)));
    assert_eq!(executor.execute_calls.load(Ordering::SeqCst), 0);
}

#[cfg(windows)]
#[test]
fn production_runtime_resolves_the_authoritative_task_before_default_deny() {
    let fixture = WorkspaceFixture::new();
    fixture.seed_present_workspace();
    let policy = VersionedPolicyEngine::from_json(DEFAULT_DENY_POLICY).unwrap();
    let request = tool_request_for_policy(
        "execution-production-denied",
        policy.snapshot_digest().clone(),
    );
    let bootstrap = Bootstrap::production(StartupConfig {
        app_data_dir: fixture.app_data.clone(),
        trusted_workspace_root: fixture.workspace_root.clone(),
        secret_values: Vec::new(),
    });

    assert_eq!(
        bootstrap.tool_runtime().unwrap().availability().unwrap(),
        ToolRuntimeAvailability::Ready
    );
    let outcome = bootstrap.tool_runtime().unwrap().execute(request).unwrap();

    assert!(matches!(outcome, ToolOutcome::Denied(_)));
}

#[test]
fn completed_process_publishes_scanned_stream_artifacts_before_terminal_audit() {
    let fixture = WorkspaceFixture::new();
    fixture.seed_present_workspace();
    let policy = VersionedPolicyEngine::from_json(ALLOW_PROCESS_POLICY).unwrap();
    let request =
        tool_request_for_policy("execution-runtime-output", policy.snapshot_digest().clone());
    let bootstrap = Bootstrap::with_tool_broker(
        StartupConfig {
            app_data_dir: fixture.app_data.clone(),
            trusted_workspace_root: fixture.workspace_root.clone(),
            secret_values: Vec::new(),
        },
        ToolBrokerConfig::new(
            ALLOW_PROCESS_POLICY,
            Arc::new(EchoAuthority),
            Arc::new(CompletingExecutor {
                bindings: SqliteStore::open(&fixture.database_path).unwrap(),
            }),
        ),
    );

    let outcome = bootstrap.tool_runtime().unwrap().execute(request).unwrap();

    let ToolOutcome::Execution(
        local_agent_terminal_application::DurableToolExecutionOutcome::Completed(receipt),
    ) = outcome
    else {
        panic!("allowed process must produce a durable terminal receipt: {outcome:?}");
    };
    let output = receipt.terminal().output().unwrap();
    assert!(matches!(
        output.artifacts.stdout(),
        DurableToolExecutionArtifact::Available(_)
    ));
    assert!(matches!(
        output.artifacts.stderr(),
        DurableToolExecutionArtifact::Available(_)
    ));
    assert!(output.artifacts.observed_writes().is_empty());
    let database = SqliteStore::open(&fixture.database_path).unwrap();
    for artifact in [output.artifacts.stdout(), output.artifacts.stderr()] {
        let DurableToolExecutionArtifact::Available(artifact_id) = artifact else {
            unreachable!()
        };
        assert!(database.available_evidence(artifact_id).unwrap().is_some());
    }
}

#[test]
fn stop_all_cancels_and_joins_a_runtime_owned_execution() {
    let fixture = WorkspaceFixture::new();
    fixture.seed_present_workspace();
    let policy = VersionedPolicyEngine::from_json(ALLOW_PROCESS_POLICY).unwrap();
    let request =
        tool_request_for_policy("execution-runtime-stop", policy.snapshot_digest().clone());
    let executor = Arc::new(RecordingExecutor::blocking(
        SqliteStore::open(&fixture.database_path).unwrap(),
    ));
    let bootstrap = Bootstrap::with_tool_broker(
        StartupConfig {
            app_data_dir: fixture.app_data.clone(),
            trusted_workspace_root: fixture.workspace_root.clone(),
            secret_values: Vec::new(),
        },
        ToolBrokerConfig::new(
            ALLOW_PROCESS_POLICY,
            Arc::new(EchoAuthority),
            executor.clone(),
        ),
    );
    let runtime = bootstrap.tool_runtime().unwrap();

    std::thread::scope(|scope| {
        let execution = scope.spawn(|| runtime.execute(request));
        executor.wait_until_started();
        let stopped = runtime.stop_all();
        executor.release();
        let outcome = execution.join().unwrap().unwrap();
        let receipts = stopped.unwrap();

        assert!(matches!(
            outcome,
            ToolOutcome::Execution(
                local_agent_terminal_application::DurableToolExecutionOutcome::Completed(_)
            )
        ));
        assert_eq!(receipts.len(), 1);
        assert_eq!(executor.cancel_calls.load(Ordering::SeqCst), 1);
    });
    assert!(runtime.stop_all().unwrap().is_empty());
}

#[test]
fn reconfigure_stops_and_joins_the_previous_runtime_before_replacement() {
    let fixture = WorkspaceFixture::new();
    fixture.seed_present_workspace();
    let policy = VersionedPolicyEngine::from_json(ALLOW_PROCESS_POLICY).unwrap();
    let request = tool_request_for_policy(
        "execution-runtime-reconfigure",
        policy.snapshot_digest().clone(),
    );
    let executor = Arc::new(RecordingExecutor::blocking(
        SqliteStore::open(&fixture.database_path).unwrap(),
    ));
    let config = || StartupConfig {
        app_data_dir: fixture.app_data.clone(),
        trusted_workspace_root: fixture.workspace_root.clone(),
        secret_values: Vec::new(),
    };
    let mut bootstrap = Bootstrap::with_tool_broker(
        config(),
        ToolBrokerConfig::new(
            ALLOW_PROCESS_POLICY,
            Arc::new(EchoAuthority),
            executor.clone(),
        ),
    );
    let runtime = bootstrap.tool_runtime_handle().unwrap();

    std::thread::scope(|scope| {
        let execution = scope.spawn(move || runtime.execute(request));
        executor.wait_until_started();
        let status = bootstrap.reconfigure(config()).clone();
        executor.release();
        execution.join().unwrap().unwrap();

        assert_eq!(
            status.state,
            local_agent_terminal_application::StartupStateDto::Ready
        );
        assert_eq!(executor.cancel_calls.load(Ordering::SeqCst), 1);
    });
}

#[test]
fn stop_all_cancels_started_workers_while_an_earlier_worker_is_still_registering() {
    let fixture = WorkspaceFixture::new();
    fixture.seed_present_workspace();
    let policy = VersionedPolicyEngine::from_json(ALLOW_PROCESS_POLICY).unwrap();
    let pending = tool_request_for_policy("execution-a-pending", policy.snapshot_digest().clone());
    let started = tool_request_for_policy("execution-b-started", policy.snapshot_digest().clone());
    let authority = Arc::new(BlockingAuthority::new("execution-a-pending"));
    let executor = Arc::new(RecordingExecutor::blocking(
        SqliteStore::open(&fixture.database_path).unwrap(),
    ));
    let bootstrap = Bootstrap::with_tool_broker(
        StartupConfig {
            app_data_dir: fixture.app_data.clone(),
            trusted_workspace_root: fixture.workspace_root.clone(),
            secret_values: Vec::new(),
        },
        ToolBrokerConfig::new(ALLOW_PROCESS_POLICY, authority.clone(), executor.clone()),
    );
    let runtime = bootstrap.tool_runtime().unwrap();

    std::thread::scope(|scope| {
        let pending_execution = scope.spawn(|| runtime.execute(pending));
        authority.wait_until_blocked();
        let started_execution = scope.spawn(|| runtime.execute(started));
        executor.wait_until_started();
        let shutdown = scope.spawn(|| runtime.stop_all());

        let cancelled_before_release = executor.wait_until_cancelled(Duration::from_millis(250));
        authority.release();

        shutdown.join().unwrap().unwrap();
        pending_execution.join().unwrap().unwrap();
        started_execution.join().unwrap().unwrap();
        assert!(
            cancelled_before_release,
            "a registering worker must not delay cancellation of a started worker"
        );
    });
}

#[test]
fn configured_runtime_resumes_an_approved_request_through_execute_tool() {
    let fixture = WorkspaceFixture::new();
    fixture.seed_present_workspace();
    let policy = VersionedPolicyEngine::from_json(APPROVE_PROCESS_POLICY).unwrap();
    let request = tool_request_for_policy(
        "execution-runtime-approved",
        policy.snapshot_digest().clone(),
    );
    let executor = Arc::new(RecordingExecutor::failing(
        SqliteStore::open(&fixture.database_path).unwrap(),
    ));
    let bootstrap = Bootstrap::with_tool_broker(
        StartupConfig {
            app_data_dir: fixture.app_data.clone(),
            trusted_workspace_root: fixture.workspace_root.clone(),
            secret_values: Vec::new(),
        },
        ToolBrokerConfig::new(
            APPROVE_PROCESS_POLICY,
            Arc::new(EchoAuthority),
            executor.clone(),
        ),
    );
    let runtime = bootstrap.tool_runtime().unwrap();
    let initial = runtime.execute(request);
    let ToolOutcome::ApprovalRequired(approval) = initial.unwrap() else {
        panic!("approval policy must return the immutable approval request");
    };
    let approval_id = ApprovalId::new(approval.approval_id).unwrap();
    SqliteStore::open(&fixture.database_path)
        .unwrap()
        .resolve(ApprovalResolution {
            approval_id: approval_id.clone(),
            approved: true,
        })
        .unwrap();

    let outcome = runtime.resume_approved(approval_id).unwrap();

    assert!(matches!(
        outcome,
        ToolOutcome::Execution(
            local_agent_terminal_application::DurableToolExecutionOutcome::Completed(_)
        )
    ));
    assert_eq!(executor.execute_calls.load(Ordering::SeqCst), 1);
}

#[test]
fn configured_runtime_projects_exact_approval_context_and_rejects_a_stale_digest() {
    let fixture = WorkspaceFixture::new();
    fixture.seed_present_workspace();
    let policy = VersionedPolicyEngine::from_json(APPROVE_PROCESS_POLICY).unwrap();
    let request = tool_request_for_policy(
        "execution-runtime-activity",
        policy.snapshot_digest().clone(),
    );
    let executor = Arc::new(RecordingExecutor::failing(
        SqliteStore::open(&fixture.database_path).unwrap(),
    ));
    let bootstrap = Bootstrap::with_tool_broker(
        StartupConfig {
            app_data_dir: fixture.app_data.clone(),
            trusted_workspace_root: fixture.workspace_root.clone(),
            secret_values: Vec::new(),
        },
        ToolBrokerConfig::new(
            APPROVE_PROCESS_POLICY,
            Arc::new(EchoAuthority),
            executor.clone(),
        ),
    );
    let runtime = bootstrap.tool_runtime().unwrap();
    let ToolOutcome::ApprovalRequired(published) = runtime.execute(request).unwrap() else {
        panic!("approval policy must publish one immutable request");
    };

    let activity = runtime.activity().unwrap();
    assert_eq!(activity.entries.len(), 1);
    let entry = &activity.entries[0];
    assert_eq!(entry.execution_id, "execution-runtime-activity");
    assert_eq!(entry.status, ToolActivityStatusDto::ApprovalRequired);
    assert_eq!(entry.summary, "process.exec toolchain:cargo (1 argument)");
    assert!(!entry.summary.contains("test"));
    assert_eq!(entry.actor_id, "agent-1");
    assert_eq!(entry.reason, "run focused tests");
    assert_eq!(entry.network_profile, "denied");
    assert_eq!(entry.policy_rules, ["approve-process"]);

    let approval_id = ApprovalId::new(published.approval_id.clone()).unwrap();
    let detail = runtime.approval_request(approval_id.clone()).unwrap();
    assert_eq!(detail.execution_id, "execution-runtime-activity");
    assert_eq!(detail.operation_digest, published.operation_digest);
    assert_eq!(detail.scopes, ["worktree:task-1"]);

    let error = runtime
        .resolve_approval(ResolveToolApprovalRequestDto {
            approval_id: published.approval_id.clone(),
            expected_operation_digest: format!("sha256:{}", "f".repeat(64)),
            decision: ToolApprovalDecisionDto::Approve,
        })
        .unwrap_err();
    assert_eq!(
        error.safe_classification(),
        SafeErrorClassification::Conflict
    );
    assert_eq!(executor.execute_calls.load(Ordering::SeqCst), 0);

    let resolved = runtime
        .resolve_approval(ResolveToolApprovalRequestDto {
            approval_id: published.approval_id,
            expected_operation_digest: published.operation_digest,
            decision: ToolApprovalDecisionDto::Approve,
        })
        .unwrap();
    assert_eq!(resolved.execution_id, "execution-runtime-activity");
    assert_eq!(resolved.status, ToolActivityStatusDto::Indeterminate);
    assert_eq!(executor.execute_calls.load(Ordering::SeqCst), 1);
}

#[test]
fn denying_a_projected_approval_never_calls_the_executor() {
    let fixture = WorkspaceFixture::new();
    fixture.seed_present_workspace();
    let policy = VersionedPolicyEngine::from_json(APPROVE_PROCESS_POLICY).unwrap();
    let request = tool_request_for_policy(
        "execution-runtime-denied-approval",
        policy.snapshot_digest().clone(),
    );
    let executor = Arc::new(RecordingExecutor::default());
    let bootstrap = Bootstrap::with_tool_broker(
        StartupConfig {
            app_data_dir: fixture.app_data.clone(),
            trusted_workspace_root: fixture.workspace_root.clone(),
            secret_values: Vec::new(),
        },
        ToolBrokerConfig::new(
            APPROVE_PROCESS_POLICY,
            Arc::new(EchoAuthority),
            executor.clone(),
        ),
    );
    let runtime = bootstrap.tool_runtime().unwrap();
    let ToolOutcome::ApprovalRequired(published) = runtime.execute(request).unwrap() else {
        panic!("approval policy must publish one immutable request");
    };

    let resolved = runtime
        .resolve_approval(ResolveToolApprovalRequestDto {
            approval_id: published.approval_id,
            expected_operation_digest: published.operation_digest,
            decision: ToolApprovalDecisionDto::Deny,
        })
        .unwrap();

    assert_eq!(resolved.status, ToolActivityStatusDto::Denied);
    assert_eq!(executor.execute_calls.load(Ordering::SeqCst), 0);
    assert_eq!(
        runtime.activity().unwrap().entries[0].status,
        ToolActivityStatusDto::Denied
    );
}

#[test]
fn worker_panic_after_process_binding_closes_production_dispatch() {
    let fixture = WorkspaceFixture::new();
    fixture.seed_present_workspace();
    let policy = VersionedPolicyEngine::from_json(ALLOW_PROCESS_POLICY).unwrap();
    let executor = Arc::new(RecordingExecutor::panicking(
        SqliteStore::open(&fixture.database_path).unwrap(),
    ));
    let bootstrap = Bootstrap::with_tool_broker(
        StartupConfig {
            app_data_dir: fixture.app_data.clone(),
            trusted_workspace_root: fixture.workspace_root.clone(),
            secret_values: Vec::new(),
        },
        ToolBrokerConfig::new(
            ALLOW_PROCESS_POLICY,
            Arc::new(EchoAuthority),
            executor.clone(),
        ),
    );
    let runtime = bootstrap.tool_runtime().unwrap();
    let panicking_request =
        tool_request_for_policy("execution-runtime-panics", policy.snapshot_digest().clone());
    let later_request =
        tool_request_for_policy("execution-after-panic", policy.snapshot_digest().clone());

    std::thread::scope(|scope| {
        let panicking = scope.spawn(|| runtime.execute(panicking_request));
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while runtime.availability().unwrap() != ToolRuntimeAvailability::Unavailable {
            assert!(std::time::Instant::now() < deadline);
            std::thread::yield_now();
        }

        assert!(runtime.execute(later_request).is_err());
        assert_eq!(
            panicking.join().unwrap().unwrap_err().safe_classification(),
            SafeErrorClassification::Internal
        );
    });
    assert_eq!(executor.execute_calls.load(Ordering::SeqCst), 1);
}

#[test]
fn journaled_tool_publishers_persist_distinct_verified_artifacts_and_exact_relation() {
    let fixture = WorkspaceFixture::new();
    fixture.seed_present_workspace();
    let database = SqliteStore::open(&fixture.database_path).unwrap();
    let artifacts =
        ContentAddressedArtifactStore::open(fixture.app_data.join("artifacts")).unwrap();
    let publisher = ToolArtifactPublisher::new(&database, &artifacts);
    let request = tool_request("execution-publisher");
    let immutable = canonical_tool_request(&request).unwrap();

    let request_artifact_id = publisher.publish(&immutable).unwrap();
    let approval = approval_request(&database, &request, &immutable, request_artifact_id.clone());
    let publication = publisher.publish_or_replay(approval.clone()).unwrap();

    assert_eq!(
        publication,
        ToolApprovalPublication::Created(approval.clone())
    );
    assert_ne!(request_artifact_id, approval.approval_artifact_id().clone());
    assert_eq!(
        database
            .load_request_artifact(&request_artifact_id)
            .unwrap(),
        immutable
    );
    assert_eq!(
        database
            .load_approval_request(approval.approval_id())
            .unwrap(),
        approval
    );
    let connection = Connection::open(&fixture.database_path).unwrap();
    assert_eq!(
        connection
            .query_row(
                "SELECT
                    (SELECT artifact_type || ':' || verification_state
                     FROM artifacts WHERE id = ?1) || ',' ||
                    (SELECT artifact_type || ':' || verification_state
                     FROM artifacts WHERE id = ?2)",
                [
                    request_artifact_id.as_str(),
                    approval.approval_artifact_id().as_str(),
                ],
                |row| row.get::<_, String>(0),
            )
            .unwrap(),
        "tool-request:hash_verified,approval-payload:hash_verified"
    );
    assert_eq!(
        connection
            .query_row(
                "SELECT canonical_request_artifact_id || ':' || status
                 FROM operation_intents WHERE id = ?1",
                [request.execution_id().as_str()],
                |row| row.get::<_, String>(0),
            )
            .unwrap(),
        format!("{}:pending", request_artifact_id.as_str())
    );
    assert_eq!(
        connection
            .query_row(
                "SELECT json_extract(payload_json, '$.executionId') || ':' ||
                        json_extract(payload_json, '$.approvalPolicyDecisionId')
                 FROM events
                 WHERE event_type = 'approval.requested'
                   AND json_extract(payload_json, '$.approvalId') = ?1",
                [approval.approval_id().as_str()],
                |row| row.get::<_, String>(0),
            )
            .unwrap(),
        format!(
            "{}:{}",
            request.execution_id().as_str(),
            approval.policy_decision_id().as_str()
        )
    );

    assert_eq!(publisher.publish(&immutable).unwrap(), request_artifact_id);
    assert_eq!(
        publisher.publish_or_replay(approval.clone()).unwrap(),
        ToolApprovalPublication::Replayed(approval.clone())
    );
    let mut changed_payload = approval.payload().clone();
    changed_payload.operation.arguments_digest = digest('f').to_string();
    let changed_request = ToolApprovalRequest::from_persisted(
        approval.approval_id().clone(),
        approval.approval_artifact_id().clone(),
        approval.execution_id().clone(),
        approval.policy_decision_id().clone(),
        approval.policy_request_binding_digest().clone(),
        approval.tool_request_artifact_id().clone(),
        approval.tool_request_binding_digest().clone(),
        changed_payload,
    )
    .unwrap();
    assert_eq!(
        publisher
            .publish_or_replay(changed_request)
            .unwrap_err()
            .safe_classification(),
        local_agent_terminal_application::SafeErrorClassification::IntegrityFailure
    );
    assert_eq!(
        connection
            .query_row(
                "SELECT COUNT(*) FROM events
                 WHERE event_type = 'approval.requested'
                   AND json_extract(payload_json, '$.executionId') = ?1",
                [request.execution_id().as_str()],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
        1
    );
    connection
        .execute(
            "UPDATE artifacts SET verification_state = 'unverified' WHERE id = ?1",
            [request_artifact_id.as_str()],
        )
        .unwrap();
    assert!(publisher.publish(&immutable).is_err());
    assert_eq!(
        connection
            .query_row(
                "SELECT status || ':' || attempt_count FROM operation_intents WHERE id = ?1",
                [request.execution_id().as_str()],
                |row| row.get::<_, String>(0),
            )
            .unwrap(),
        "pending:0"
    );
}

#[test]
fn approval_publication_rejects_a_non_pending_intent_without_state_change() {
    let fixture = WorkspaceFixture::new();
    fixture.seed_present_workspace();
    let database = SqliteStore::open(&fixture.database_path).unwrap();
    let artifacts =
        ContentAddressedArtifactStore::open(fixture.app_data.join("artifacts")).unwrap();
    let publisher = ToolArtifactPublisher::new(&database, &artifacts);
    let request = tool_request("execution-started");
    let immutable = canonical_tool_request(&request).unwrap();
    let request_artifact_id = publisher.publish(&immutable).unwrap();
    let approval = approval_request(&database, &request, &immutable, request_artifact_id);
    let connection = Connection::open(&fixture.database_path).unwrap();
    connection
        .execute(
            "UPDATE operation_intents SET status = 'started' WHERE id = ?1",
            [request.execution_id().as_str()],
        )
        .unwrap();

    assert_eq!(
        publisher
            .publish_or_replay(approval.clone())
            .unwrap_err()
            .safe_classification(),
        local_agent_terminal_application::SafeErrorClassification::IntegrityFailure
    );
    assert_eq!(
        connection
            .query_row(
                "SELECT COUNT(*) FROM approvals WHERE id = ?1",
                [approval.approval_id().as_str()],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
        0
    );
}

#[test]
fn approval_publication_rejects_expiry_beyond_the_policy_decision() {
    let fixture = WorkspaceFixture::new();
    fixture.seed_present_workspace();
    let database = SqliteStore::open(&fixture.database_path).unwrap();
    let artifacts =
        ContentAddressedArtifactStore::open(fixture.app_data.join("artifacts")).unwrap();
    let publisher = ToolArtifactPublisher::new(&database, &artifacts);
    let request = tool_request("execution-late-expiry");
    let immutable = canonical_tool_request(&request).unwrap();
    let request_artifact_id = publisher.publish(&immutable).unwrap();
    let approval = approval_request(&database, &request, &immutable, request_artifact_id);
    let mut payload = approval.payload().clone();
    payload.expires_at = "2101-01-01T00:00:00Z".to_owned();
    let late_expiry = ToolApprovalRequest::from_persisted(
        approval.approval_id().clone(),
        approval.approval_artifact_id().clone(),
        approval.execution_id().clone(),
        approval.policy_decision_id().clone(),
        approval.policy_request_binding_digest().clone(),
        approval.tool_request_artifact_id().clone(),
        approval.tool_request_binding_digest().clone(),
        payload,
    )
    .unwrap();

    assert_eq!(
        publisher
            .publish_or_replay(late_expiry)
            .unwrap_err()
            .safe_classification(),
        local_agent_terminal_application::SafeErrorClassification::IntegrityFailure
    );
}

fn approval_request(
    database: &SqliteStore,
    request: &ToolRequest,
    immutable: &local_agent_terminal_application::ImmutableToolRequest,
    request_artifact_id: ArtifactId,
) -> ToolApprovalRequest {
    let evaluated_at = Timestamp::from_unix_seconds(1_753_272_000);
    let policy_request = policy_request_for_tool(request, evaluated_at);
    let policy_binding = canonical_policy_binding_digest(&policy_request).unwrap();
    let decision = combine_policy_rules(
        policy_request,
        PolicyVersion::new(1).unwrap(),
        vec![MatchedPolicyRule {
            rule_id: PolicyRuleId::new("require-approval").unwrap(),
            effect: PolicyEffect::RequireApproval,
            redactions: Vec::new(),
        }],
        Some(Timestamp::from_unix_seconds(4_102_444_800)),
    )
    .unwrap();
    let policy_decision_id = database
        .record(RecordedPolicyDecision {
            decision: PolicyDecision {
                draft: decision,
                operation_digest: digest('9'),
            },
            recorded_at: evaluated_at,
        })
        .unwrap();
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
                arguments_digest: digest('0').to_string(),
                script_digest: None,
                cwd_capability: "unbound".to_owned(),
                environment_profile_digest: digest('0').to_string(),
                network_profile: "denied".to_owned(),
                expected_writes: Vec::new(),
                executor_fencing_token: None,
            },
            policy_snapshot_digest: request.policy().policy_snapshot_digest().to_string(),
            workspace_version: request
                .process()
                .process()
                .binding()
                .workspace_version()
                .get(),
            requested_at: "2025-07-23T12:00:00Z".to_owned(),
            expires_at: "2099-07-30T00:15:00Z".to_owned(),
            nonce: "0123456789abcdef0123456789abcdef".to_owned(),
        },
        request.process(),
    )
    .unwrap();
    ToolApprovalRequest::from_persisted(
        ApprovalId::new("approval-publisher").unwrap(),
        ArtifactId::new("artifact-approval-publisher").unwrap(),
        request.execution_id().clone(),
        policy_decision_id,
        policy_binding,
        request_artifact_id,
        immutable.binding_digest().clone(),
        bound.payload().clone(),
    )
    .unwrap()
}

fn tool_request(execution_id: &str) -> ToolRequest {
    tool_request_for_policy(execution_id, digest('b'))
}

fn tool_request_for_policy(
    execution_id: &str,
    policy_snapshot_digest: Sha256Digest,
) -> ToolRequest {
    let task_id = TaskId::new("task-1").unwrap();
    let process = ProcessToolRequest::new(
        ProcessBinding::new(
            task_id.clone(),
            RunId::new("run-lease-1").unwrap(),
            PlanStepId::new("step-1").unwrap(),
            Phase::Implementation,
            WorkspaceVersion::new(1),
            EnvironmentProfile::new("rust", digest('e')).unwrap(),
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
            None,
        )
        .unwrap(),
    )
    .unwrap();
    let approved = ApprovedProcessRequest::new(
        ApprovedExecutableIdentity::new(
            ResolvedExecutable {
                canonical_path: approved_executable_path(),
                sha256: digest('d'),
                file_identity: local_agent_terminal_application::ExecutableFileIdentity::new(
                    "cargo-file",
                )
                .unwrap(),
                toolchain_id: "cargo".to_owned(),
            },
            "1.97.1",
        )
        .unwrap(),
        process,
        Vec::new(),
        None,
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
            content_digest: Sha256Digest::new(EMPTY_BYTES_HASH).unwrap(),
            resource_class: ResourceClass::InternalCode,
        },
        TaskRisk::High,
        "run focused tests",
        policy_snapshot_digest,
    )
    .unwrap();
    ToolRequest::new(
        local_agent_terminal_application::ToolExecutionId::new(execution_id).unwrap(),
        approved,
        policy,
    )
    .unwrap()
}

struct EchoAuthority;

impl ToolAuthorityResolver for EchoAuthority {
    fn resolve(&self, request: &ToolRequest) -> Result<ToolAuthoritySnapshot, PortError> {
        ToolAuthoritySnapshot::new(request.clone(), b"", None)
    }
}

struct BlockingAuthority {
    execution_id: &'static str,
    state: Mutex<ExecutorState>,
    changed: Condvar,
}

impl BlockingAuthority {
    fn new(execution_id: &'static str) -> Self {
        Self {
            execution_id,
            state: Mutex::new(ExecutorState::default()),
            changed: Condvar::new(),
        }
    }

    fn wait_until_blocked(&self) {
        let state = self.state.lock().unwrap();
        let (state, timeout) = self
            .changed
            .wait_timeout_while(state, Duration::from_secs(5), |state| !state.started)
            .unwrap();
        assert!(state.started && !timeout.timed_out());
    }

    fn release(&self) {
        self.state.lock().unwrap().released = true;
        self.changed.notify_all();
    }
}

impl ToolAuthorityResolver for BlockingAuthority {
    fn resolve(&self, request: &ToolRequest) -> Result<ToolAuthoritySnapshot, PortError> {
        if request.execution_id().as_str() == self.execution_id {
            let mut state = self.state.lock().unwrap();
            state.started = true;
            self.changed.notify_all();
            while !state.released {
                state = self.changed.wait(state).unwrap();
            }
        }
        ToolAuthoritySnapshot::new(request.clone(), b"", None)
    }
}

struct CompletingExecutor {
    bindings: SqliteStore,
}

impl ToolControlSelfTest for CompletingExecutor {
    fn verify_controls(&self) -> Result<(), PortError> {
        Ok(())
    }
}

impl StructuredToolExecutor for CompletingExecutor {
    fn execute(&self, request: AuthorizedToolRequest) -> Result<ToolExecutionResult, PortError> {
        let authority = self
            .bindings
            .load_claimed_authority(&request.execution_id)?;
        self.bindings
            .record_process_binding(AuthoritativeProcessBinding::new(
                authority,
                1,
                "completed-output-job",
            )?)?;
        let stdout = policy_bound_output('1', b"safe stdout");
        let stderr = policy_bound_output('2', b"");
        Ok(ToolExecutionResult {
            receipt: ProcessReceipt {
                execution_id: request.execution_id,
                status: ProcessStatus::Exited,
                exit_code: Some(0),
                stdout: BoundedOutput {
                    bytes: stdout.bytes.clone(),
                    truncated: false,
                },
                stderr: BoundedOutput {
                    bytes: stderr.bytes.clone(),
                    truncated: false,
                },
                duration_ms: 1,
                job_receipt: JobReceipt {
                    root_pid: 1,
                    job_id: "completed-output-job".to_owned(),
                    kill_on_close: true,
                    no_breakaway: true,
                    job_memory_limit: true,
                    job_cpu_time_limit: true,
                    memory_limit_bytes: 1,
                    cpu_time_limit_ms: 1,
                    max_active_processes: 1,
                    total_user_time_ms: 1,
                    resource_limit_terminated: false,
                    tree_terminated: false,
                },
                observed_writes: Vec::new(),
                output_digest: digest('3'),
            },
            artifacts: ToolExecutionArtifactEvidence::Disclosed(
                DisclosedToolExecutionArtifacts::new(stdout, stderr, Vec::new()),
            ),
        })
    }

    fn cancel(
        &self,
        _: &local_agent_terminal_application::ToolExecutionId,
    ) -> Result<CancellationReceipt, PortError> {
        unreachable!()
    }

    fn file_read(
        &self,
        _: FileReadRequest,
    ) -> Result<DisclosureOutcome<PolicyBoundBytes>, PortError> {
        unreachable!()
    }

    fn file_write(&self, _: FileWriteRequest) -> Result<VerifiedWrite, PortError> {
        unreachable!()
    }

    fn git_status(
        &self,
        _: GitStatusRequest,
    ) -> Result<DisclosureOutcome<GitStatusResult>, PortError> {
        unreachable!()
    }

    fn git_diff(&self, _: GitDiffRequest) -> Result<DisclosureOutcome<GitDiffResult>, PortError> {
        unreachable!()
    }
}

fn policy_bound_output(marker: char, bytes: &[u8]) -> PolicyBoundBytes {
    let content_digest = if bytes.is_empty() {
        Sha256Digest::new(EMPTY_BYTES_HASH).unwrap()
    } else {
        assert_eq!(bytes, b"safe stdout");
        Sha256Digest::new(SAFE_STDOUT_HASH).unwrap()
    };
    PolicyBoundBytes {
        policy_decision_id: local_agent_terminal_application::PolicyDecisionId::from_persisted(
            format!("policy-decision:{}", marker.to_string().repeat(64)),
        )
        .unwrap(),
        original_digest: content_digest.clone(),
        redaction_report_digest: digest('4'),
        digest: content_digest,
        bytes: bytes.to_vec(),
    }
}

#[derive(Default)]
struct ExecutorState {
    started: bool,
    released: bool,
}

#[derive(Default)]
struct RecordingExecutor {
    execute_calls: AtomicUsize,
    cancel_calls: AtomicUsize,
    blocking: bool,
    panics: bool,
    bindings: Option<SqliteStore>,
    state: Mutex<ExecutorState>,
    changed: Condvar,
}

impl RecordingExecutor {
    fn blocking(bindings: SqliteStore) -> Self {
        Self {
            blocking: true,
            bindings: Some(bindings),
            ..Self::default()
        }
    }

    fn failing(bindings: SqliteStore) -> Self {
        Self {
            blocking: true,
            bindings: Some(bindings),
            state: Mutex::new(ExecutorState {
                released: true,
                ..ExecutorState::default()
            }),
            ..Self::default()
        }
    }

    fn panicking(bindings: SqliteStore) -> Self {
        Self {
            blocking: true,
            panics: true,
            bindings: Some(bindings),
            ..Self::default()
        }
    }

    fn wait_until_started(&self) {
        let state = self.state.lock().unwrap();
        let (state, timeout) = self
            .changed
            .wait_timeout_while(state, Duration::from_secs(5), |state| !state.started)
            .unwrap();
        assert!(state.started && !timeout.timed_out());
    }

    fn release(&self) {
        self.state.lock().unwrap().released = true;
        self.changed.notify_all();
    }

    fn wait_until_cancelled(&self, timeout: Duration) -> bool {
        let state = self.state.lock().unwrap();
        let (state, _) = self
            .changed
            .wait_timeout_while(state, timeout, |state| !state.released)
            .unwrap();
        state.released
    }
}

impl ToolControlSelfTest for RecordingExecutor {
    fn verify_controls(&self) -> Result<(), PortError> {
        Ok(())
    }
}

impl StructuredToolExecutor for RecordingExecutor {
    fn execute(&self, request: AuthorizedToolRequest) -> Result<ToolExecutionResult, PortError> {
        self.execute_calls.fetch_add(1, Ordering::SeqCst);
        assert!(self.blocking, "denied policy must not reach the executor");
        let bindings = self.bindings.as_ref().unwrap();
        let authority = bindings.load_claimed_authority(&request.execution_id)?;
        bindings.record_process_binding(AuthoritativeProcessBinding::new(
            authority,
            4_242,
            "runtime-owned-test-job",
        )?)?;
        let mut state = self.state.lock().unwrap();
        state.started = true;
        self.changed.notify_all();
        if self.panics {
            panic!("injected panic after authoritative process binding");
        }
        while !state.released {
            state = self.changed.wait(state).unwrap();
        }
        Err(PortError::failure(
            SafeErrorClassification::Unavailable,
            Retryability::NonRetryable,
        ))
    }

    fn cancel(
        &self,
        execution_id: &local_agent_terminal_application::ToolExecutionId,
    ) -> Result<CancellationReceipt, PortError> {
        self.cancel_calls.fetch_add(1, Ordering::SeqCst);
        self.release();
        Ok(CancellationReceipt {
            execution_id: execution_id.clone(),
            status: ProcessStatus::Terminated,
            job_receipt: None,
            cancelled: true,
        })
    }

    fn file_read(
        &self,
        _: FileReadRequest,
    ) -> Result<DisclosureOutcome<PolicyBoundBytes>, PortError> {
        unreachable!("test exercises process execution only")
    }

    fn file_write(&self, _: FileWriteRequest) -> Result<VerifiedWrite, PortError> {
        unreachable!("test exercises process execution only")
    }

    fn git_status(
        &self,
        _: GitStatusRequest,
    ) -> Result<DisclosureOutcome<GitStatusResult>, PortError> {
        unreachable!("test exercises process execution only")
    }

    fn git_diff(&self, _: GitDiffRequest) -> Result<DisclosureOutcome<GitDiffResult>, PortError> {
        unreachable!("test exercises process execution only")
    }
}

fn digest(marker: char) -> Sha256Digest {
    Sha256Digest::new(format!("sha256:{}", marker.to_string().repeat(64))).unwrap()
}

#[cfg(windows)]
fn approved_executable_path() -> PathBuf {
    PathBuf::from(r"\\?\C:\approved\cargo.exe")
}

#[cfg(not(windows))]
fn approved_executable_path() -> PathBuf {
    PathBuf::from("/approved/cargo")
}
