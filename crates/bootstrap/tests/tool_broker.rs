#[allow(dead_code)]
#[path = "support/mod.rs"]
mod support;

use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

use local_agent_terminal_application::{
    bind_tool_approval_payload, canonical_file_write_recovery_request,
    canonical_policy_binding_digest, canonical_tool_request, policy_request_for_tool, AcquireLease,
    ApprovalId, ApprovalResolution, ApprovalResumeStore, ApprovalStore, ApprovedExecutableIdentity,
    ApprovedProcessRequest, ArtifactWriteReservation, AuthoritativeProcessBinding,
    AuthorizedToolRequest, BoundedOutput, CancellationReceipt, CanonicalEvidenceRef,
    DisclosedToolExecutionArtifacts, DisclosureOutcome, DurableToolExecutionArtifact,
    FileReadRequest, FileWritePolicyBinding, FileWritePreImage, FileWriteRecoveryIntent,
    FileWriteRecoveryRequest, FileWriteRecoveryState, FileWriteRecoveryStore, FileWriteRequest,
    GitDiffRequest, GitDiffResult, GitStatusRequest, GitStatusResult, JobReceipt, PolicyBoundBytes,
    PolicyDecision, PolicyDecisionStore, PortError, ProcessExecutionBindingStore, ProcessReceipt,
    ProcessStatus, RecordedPolicyDecision, RelativePathComponents, ReservedArtifact,
    ResolveToolApprovalRequestDto, ResolvedExecutable, Retryability, SafeErrorClassification,
    StructuredToolExecutor, TaskQuery, ToolActivityStatusDto, ToolApprovalDecisionDto,
    ToolApprovalOperationV1, ToolApprovalPayloadV1, ToolApprovalPublication, ToolApprovalRequest,
    ToolApprovalRequestPublisher, ToolAuthorityResolver, ToolAuthoritySnapshot,
    ToolControlSelfTest, ToolExecutionArtifactEvidence, ToolExecutionResult,
    ToolExecutionResumeStore, ToolExecutionTerminalKind, ToolOutcome, ToolPolicyContext,
    ToolRequest, ToolRequestPublisher, VerifiedWrite, WorkspaceEvidenceStore,
};
use local_agent_terminal_bootstrap::{
    Bootstrap, StartupConfig, ToolArtifactPublisher, ToolBrokerConfig, ToolRuntimeAvailability,
};
use local_agent_terminal_domain::{
    combine_policy_rules, ActorId, ActorLocality, ArtifactId, CapabilityRef, EnvironmentProfile,
    LeaseClaim, MatchedPolicyRule, NetworkProfile, Phase, PlanStepId, PolicyAction, PolicyActor,
    PolicyEffect, PolicyResource, PolicyRuleId, PolicyVersion, ProcessBinding, ProcessInvocation,
    ProcessToolRequest, ProcessTrustTier, ProjectId, ResourceClass, RunId, Sha256Digest, TaskId,
    TaskRisk, Timestamp, TrustTier, WorkspaceVersion,
};
use local_agent_terminal_policy_engine::VersionedPolicyEngine;
use local_agent_terminal_repository_git::{GitRepositoryGateway, GitStructuredTools};
use local_agent_terminal_storage_files::{ContentAddressedArtifactStore, JournaledArtifactWriter};
use local_agent_terminal_storage_sqlite::SqliteStore;
use rusqlite::Connection;

use support::{WorkspaceFixture, EMPTY_JSON_HASH};

const DENY_PROCESS_POLICY: &str =
    r#"{"version":1,"rules":[{"id":"deny-process","effect":"deny","action":"process.exec"}]}"#;
const ALLOW_PROCESS_POLICY: &str =
    r#"{"version":1,"rules":[{"id":"allow-process","effect":"allow","action":"process.exec"}]}"#;
const APPROVE_PROCESS_POLICY: &str = r#"{"version":1,"rules":[{"id":"approve-process","effect":"require_approval","action":"process.exec"},{"id":"redact-tool-display","effect":"allow_with_redaction","action":"tool.approval.display","redactions":["secret_scanner"]}]}"#;
const DEFAULT_DENY_POLICY: &str = r#"{"version":1,"rules":[{"id":"default-deny-process","effect":"deny","action":"process.exec"},{"id":"structured-read","effect":"allow_with_redaction","action":"context.disclose","redactions":["secret_scanner"]},{"id":"tool-display","effect":"allow_with_redaction","action":"tool.approval.display","redactions":["secret_scanner"]}]}"#;
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
            openai: None,
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
    let request = production_tool_request(
        "execution-production-denied",
        policy.snapshot_digest().clone(),
    );
    let bootstrap = Bootstrap::production(StartupConfig {
        app_data_dir: fixture.app_data.clone(),
        trusted_workspace_root: fixture.workspace_root.clone(),
        secret_values: Vec::new(),
        openai: None,
    });

    assert_eq!(
        bootstrap.tool_runtime().unwrap().availability().unwrap(),
        ToolRuntimeAvailability::Ready
    );
    let outcome = bootstrap.tool_runtime().unwrap().execute(request).unwrap();

    assert!(matches!(outcome, ToolOutcome::Denied(_)));
}

#[cfg(windows)]
#[test]
fn production_runtime_rejects_forged_policy_and_task_context_before_evaluation() {
    let fixture = WorkspaceFixture::new();
    fixture.seed_present_workspace();
    let policy = VersionedPolicyEngine::from_json(DEFAULT_DENY_POLICY).unwrap();
    let trusted = production_tool_request(
        "execution-production-trusted-template",
        policy.snapshot_digest().clone(),
    );
    let forged_policy = ToolPolicyContext::new(
        PolicyActor {
            connection_id: "hostile-connection".to_owned(),
            agent_id: "hostile-agent".to_owned(),
            trust_tier: TrustTier::IsolatedWorker,
            locality: ActorLocality::Cloud,
        },
        trusted.policy().action().clone(),
        trusted.policy().resource().clone(),
        TaskRisk::Low,
        "claim a weaker policy identity",
        trusted.policy().policy_snapshot_digest().clone(),
    )
    .unwrap();
    let forged_policy_request = ToolRequest::new(
        local_agent_terminal_application::ToolExecutionId::new(
            "execution-production-forged-policy",
        )
        .unwrap(),
        trusted.process().clone(),
        forged_policy,
    )
    .unwrap();
    let forged_binding_request = rebind_tool_request(
        &trusted,
        "execution-production-forged-binding",
        Phase::Verification,
        WorkspaceVersion::new(99),
    );
    let bootstrap = Bootstrap::production(StartupConfig {
        app_data_dir: fixture.app_data.clone(),
        trusted_workspace_root: fixture.workspace_root.clone(),
        secret_values: Vec::new(),
        openai: None,
    });
    let runtime = bootstrap.tool_runtime().unwrap();

    for request in [forged_policy_request, forged_binding_request] {
        let error = runtime.execute(request).unwrap_err();
        assert_eq!(
            error.safe_classification(),
            SafeErrorClassification::IntegrityFailure
        );
    }
    let decision_count: i64 = fixture
        .database()
        .query_row("SELECT COUNT(*) FROM policy_decisions", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(decision_count, 0);
}

#[cfg(windows)]
#[test]
fn production_runtime_exposes_read_tools_and_fails_closed_for_hostile_git() {
    let fixture = WorkspaceFixture::new();
    fixture.seed_present_workspace();
    std::fs::write(
        fixture
            .workspace_root
            .join("worktree-task-1")
            .join(".gitattributes"),
        "*.txt filter=untrusted\n",
    )
    .unwrap();
    let bootstrap = Bootstrap::production(StartupConfig {
        app_data_dir: fixture.app_data.clone(),
        trusted_workspace_root: fixture.workspace_root.clone(),
        secret_values: Vec::new(),
        openai: None,
    });
    let runtime = bootstrap.tool_runtime().unwrap();
    let task_id = TaskId::new("task-1").unwrap();
    let file = CapabilityRef::worktree(task_id.clone(), "README.md").unwrap();
    let worktree = CapabilityRef::worktree(task_id.clone(), ".").unwrap();

    let DisclosureOutcome::Disclosed(read) = runtime
        .file_read(FileReadRequest {
            task_id: task_id.clone(),
            capability: file,
            expected_digest: None,
        })
        .unwrap()
    else {
        panic!("safe structured read must be disclosed");
    };
    assert_eq!(read.bytes, b"original\n");

    let status_error = runtime
        .git_status(GitStatusRequest {
            task_id: task_id.clone(),
            worktree: worktree.clone(),
        })
        .unwrap_err();
    assert_eq!(
        status_error.safe_classification(),
        SafeErrorClassification::PermissionDenied
    );

    let diff_error = runtime
        .git_diff(GitDiffRequest { task_id, worktree })
        .unwrap_err();
    assert_eq!(
        diff_error.safe_classification(),
        SafeErrorClassification::PermissionDenied
    );
}

#[cfg(windows)]
#[test]
fn production_runtime_reports_clean_git_status_and_diff() {
    let fixture = WorkspaceFixture::new();
    fixture.seed_present_workspace();
    let bootstrap = Bootstrap::production(StartupConfig {
        app_data_dir: fixture.app_data.clone(),
        trusted_workspace_root: fixture.workspace_root.clone(),
        secret_values: Vec::new(),
        openai: None,
    });
    let runtime = bootstrap.tool_runtime().unwrap();
    let task_id = TaskId::new("task-1").unwrap();
    let worktree = CapabilityRef::worktree(task_id.clone(), ".").unwrap();

    let DisclosureOutcome::Disclosed(status) = runtime
        .git_status(GitStatusRequest {
            task_id: task_id.clone(),
            worktree: worktree.clone(),
        })
        .unwrap()
    else {
        panic!("clean production status must be disclosed");
    };
    let DisclosureOutcome::Disclosed(diff) = runtime
        .git_diff(GitDiffRequest {
            task_id,
            worktree: worktree.clone(),
        })
        .unwrap()
    else {
        panic!("clean production diff must be disclosed");
    };

    assert_eq!(status.path_scope, worktree);
    assert!(!status.truncated);
    assert!(!diff.truncated);
}

#[cfg(windows)]
#[test]
fn production_runtime_writes_with_durable_recovery_evidence() {
    let fixture = WorkspaceFixture::new();
    fixture.seed_present_workspace();
    let bootstrap = Bootstrap::production(StartupConfig {
        app_data_dir: fixture.app_data.clone(),
        trusted_workspace_root: fixture.workspace_root.clone(),
        secret_values: Vec::new(),
        openai: None,
    });
    let task_id = TaskId::new("task-1").unwrap();
    let lease = bootstrap
        .workspace_runtime()
        .unwrap()
        .acquire_lease(AcquireLease {
            task_id: task_id.clone(),
            holder_run_id: RunId::new("run-lease-1").unwrap(),
            expected_fencing_epoch: 0,
            acquired_at: "2026-07-26T00:00:10Z".to_owned(),
            expires_at: "2099-07-26T01:00:10Z".to_owned(),
        })
        .unwrap();
    let policy = VersionedPolicyEngine::from_json(DEFAULT_DENY_POLICY).unwrap();
    let database = SqliteStore::open(&fixture.database_path).unwrap();
    let policy = record_file_write_policy(&database, policy.snapshot_digest().clone());
    let before_write = database.task(&task_id).unwrap();

    let verified = bootstrap
        .tool_runtime()
        .unwrap()
        .file_write(FileWriteRequest {
            execution_id: local_agent_terminal_application::ToolExecutionId::new(
                "production-file-write",
            )
            .unwrap(),
            task_id: task_id.clone(),
            capability: CapabilityRef::worktree(task_id.clone(), "generated.txt").unwrap(),
            expected_digest: None,
            bytes: b"production write\n".to_vec(),
            lease_claim: LeaseClaim::new(task_id.clone(), lease.holder_run_id, lease.token),
            policy,
        })
        .unwrap();

    assert_eq!(verified.size_bytes, b"production write\n".len() as u64);
    assert_eq!(
        std::fs::read(
            fixture
                .workspace_root
                .join("worktree-task-1")
                .join("generated.txt")
        )
        .unwrap(),
        b"production write\n"
    );
    let after_write = database.task(&task_id).unwrap();
    assert_eq!(
        after_write.current_sequence.get(),
        before_write.current_sequence.get() + 3
    );
    assert_eq!(
        after_write.workspace_version.get(),
        before_write.workspace_version.get() + 1
    );
    let status: String = fixture
        .database()
        .query_row(
            "SELECT status FROM operation_intents WHERE id = 'production-file-write'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(status, "succeeded");
    let evidence_count: i64 = fixture
        .database()
        .query_row(
            "SELECT COUNT(*) FROM artifacts WHERE id LIKE 'file-write-%-production-file-write'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(evidence_count, 3);
}

#[cfg(windows)]
#[test]
fn production_startup_terminalizes_a_prepared_file_write() {
    let fixture = WorkspaceFixture::new();
    fixture.seed_present_workspace();
    seed_production_file_write_crash(&fixture, "prepared-file-write", FileWriteCrash::Prepared);

    let bootstrap = production_bootstrap(&fixture);

    assert_eq!(
        bootstrap.tool_runtime().unwrap().availability().unwrap(),
        ToolRuntimeAvailability::Ready
    );
    assert_eq!(
        file_write_lifecycle(&fixture, "prepared-file-write"),
        "denied:cancelled"
    );
    assert!(!fixture.managed_worktree().join("recovered.txt").exists());
    assert!(SqliteStore::open(&fixture.database_path)
        .unwrap()
        .recover()
        .unwrap()
        .is_empty());
}

#[cfg(windows)]
#[test]
fn production_startup_recovers_a_started_file_write_with_no_effect() {
    let fixture = WorkspaceFixture::new();
    fixture.seed_present_workspace();
    seed_production_file_write_crash(&fixture, "started-file-write", FileWriteCrash::Started);

    let bootstrap = production_bootstrap(&fixture);

    assert_eq!(
        bootstrap.tool_runtime().unwrap().availability().unwrap(),
        ToolRuntimeAvailability::Ready
    );
    assert_eq!(
        file_write_lifecycle(&fixture, "started-file-write"),
        "failed:failed"
    );
    assert!(!fixture.managed_worktree().join("recovered.txt").exists());
    assert!(SqliteStore::open(&fixture.database_path)
        .unwrap()
        .recover()
        .unwrap()
        .is_empty());
}

#[cfg(windows)]
#[test]
fn production_startup_completes_a_started_file_write_with_the_exact_post_image() {
    let fixture = WorkspaceFixture::new();
    fixture.seed_present_workspace();
    let before_workspace_version = seed_production_file_write_crash(
        &fixture,
        "applied-file-write",
        FileWriteCrash::ExactPostImage,
    );

    let bootstrap = production_bootstrap(&fixture);
    let database = SqliteStore::open(&fixture.database_path).unwrap();

    assert_eq!(
        bootstrap.tool_runtime().unwrap().availability().unwrap(),
        ToolRuntimeAvailability::Ready
    );
    assert_eq!(
        file_write_lifecycle(&fixture, "applied-file-write"),
        "succeeded:succeeded"
    );
    assert_eq!(
        std::fs::read(fixture.managed_worktree().join("recovered.txt")).unwrap(),
        b"recovered write\n"
    );
    assert_eq!(
        database
            .task(&TaskId::new("task-1").unwrap())
            .unwrap()
            .workspace_version
            .get(),
        before_workspace_version + 1
    );
    assert!(database.recover().unwrap().is_empty());
    let codes = bootstrap
        .local_diagnostics()
        .iter()
        .map(|record| record.code.as_str())
        .collect::<Vec<_>>();
    assert!(
        codes
            .iter()
            .position(|code| *code == "startup.repositories.reconciled")
            < codes
                .iter()
                .position(|code| *code == "startup.file_writes.reconciled")
    );
    assert!(
        codes
            .iter()
            .position(|code| *code == "startup.file_writes.reconciled")
            < codes
                .iter()
                .position(|code| *code == "startup.tools.reconciled")
    );
}

#[cfg(windows)]
#[derive(Clone, Copy)]
enum FileWriteCrash {
    Prepared,
    Started,
    ExactPostImage,
}

#[cfg(windows)]
fn production_bootstrap(fixture: &WorkspaceFixture) -> Bootstrap {
    Bootstrap::production(StartupConfig {
        app_data_dir: fixture.app_data.clone(),
        trusted_workspace_root: fixture.workspace_root.clone(),
        secret_values: Vec::new(),
        openai: None,
    })
}

#[cfg(windows)]
fn seed_production_file_write_crash(
    fixture: &WorkspaceFixture,
    execution_id: &str,
    crash: FileWriteCrash,
) -> u64 {
    let bootstrap = production_bootstrap(fixture);
    let task_id = TaskId::new("task-1").unwrap();
    let lease = bootstrap
        .workspace_runtime()
        .unwrap()
        .acquire_lease(AcquireLease {
            task_id: task_id.clone(),
            holder_run_id: RunId::new("run-lease-1").unwrap(),
            expected_fencing_epoch: 0,
            acquired_at: "2026-07-26T00:00:10Z".to_owned(),
            expires_at: "2099-07-26T01:00:10Z".to_owned(),
        })
        .unwrap();
    let database = SqliteStore::open(&fixture.database_path).unwrap();
    let artifacts =
        ContentAddressedArtifactStore::open(fixture.app_data.join("artifacts")).unwrap();
    let task = database.task(&task_id).unwrap();
    let policy = VersionedPolicyEngine::from_json(DEFAULT_DENY_POLICY).unwrap();
    let policy = record_file_write_policy(&database, policy.snapshot_digest().clone());
    let repositories = GitRepositoryGateway::open(
        &fixture.workspace_root,
        &[fixture.app_data.join("artifacts")],
    )
    .unwrap();
    let git = GitStructuredTools::from_owned_tasks(
        &repositories,
        &database,
        std::slice::from_ref(&task_id),
    )
    .unwrap();
    let pre_evidence = publish_file_write_test_artifact(
        &database,
        &artifacts,
        &task.project_id,
        &task_id,
        &format!("{execution_id}-pre-fingerprint"),
        "workspace_fingerprint",
        EMPTY_JSON_HASH,
        b"{}",
    );
    let expected_post_digest = Sha256Digest::new(
        "sha256:e20bbadfebaa2068b819899960c401c01e8268392b483b4326c18b8d921ae63d",
    )
    .unwrap();
    let request = FileWriteRecoveryRequest {
        execution_id: local_agent_terminal_application::ToolExecutionId::new(execution_id).unwrap(),
        task_id: task_id.clone(),
        root_identity: git.root_identity(&task_id).unwrap().clone(),
        relative_components: RelativePathComponents::new(vec!["recovered.txt".to_owned()]).unwrap(),
        lease_claim: LeaseClaim::new(task_id.clone(), lease.holder_run_id, lease.token),
        expected_sequence: task.current_sequence,
        pre_image: FileWritePreImage::Absent,
        expected_post_digest,
        expected_post_size: b"recovered write\n".len() as u64,
        pre_fingerprint: task.worktree.as_ref().unwrap().fingerprint.clone(),
        pre_evidence,
        actor_id: ActorId::new("tool-runtime").unwrap(),
        correlation_id: format!("file-write:{execution_id}"),
        policy,
    };
    let canonical = canonical_file_write_recovery_request(&request).unwrap();
    let request_artifact = publish_file_write_test_artifact(
        &database,
        &artifacts,
        &task.project_id,
        &task_id,
        &format!("{execution_id}-request"),
        "file_write_request",
        canonical.operation_digest.as_str(),
        &canonical.canonical_bytes,
    );
    let prepared = database
        .prepare(FileWriteRecoveryIntent {
            request,
            request_artifact,
        })
        .unwrap();
    if !matches!(crash, FileWriteCrash::Prepared) {
        let started = database.start(&prepared.request.execution_id).unwrap();
        assert_eq!(started.state, FileWriteRecoveryState::Started);
    }
    if matches!(crash, FileWriteCrash::ExactPostImage) {
        std::fs::write(
            fixture.managed_worktree().join("recovered.txt"),
            b"recovered write\n",
        )
        .unwrap();
    }
    drop(bootstrap);
    task.workspace_version.get()
}

#[cfg(windows)]
#[allow(clippy::too_many_arguments)]
fn publish_file_write_test_artifact(
    database: &SqliteStore,
    artifacts: &ContentAddressedArtifactStore,
    project_id: &ProjectId,
    task_id: &TaskId,
    artifact_id: &str,
    artifact_type: &str,
    content_hash: &str,
    bytes: &[u8],
) -> CanonicalEvidenceRef {
    let storage_key = ContentAddressedArtifactStore::storage_key(content_hash).unwrap();
    let reference = JournaledArtifactWriter::new(artifacts, database, database)
        .write(
            ArtifactWriteReservation {
                operation_id: format!("publish-{artifact_id}"),
                artifact: ReservedArtifact {
                    artifact_id: artifact_id.to_owned(),
                    task_id: Some(task_id.clone()),
                    project_id: project_id.as_str().to_owned(),
                    artifact_type: artifact_type.to_owned(),
                    logical_path: format!("file-writes/{artifact_id}"),
                    content_hash: content_hash.to_owned(),
                    storage_key,
                    size_bytes: bytes.len() as u64,
                    mime_type: Some("application/json".to_owned()),
                    created_by_type: "tool".to_owned(),
                    created_by_id: "tool-runtime".to_owned(),
                    created_at: "2026-07-26T00:00:10Z".to_owned(),
                    supersedes: None,
                },
                temp_name: format!("{artifact_id}.tmp"),
                created_at: "2026-07-26T00:00:10Z".to_owned(),
            },
            bytes,
        )
        .unwrap();
    CanonicalEvidenceRef {
        artifact_id: ArtifactId::new(artifact_id).unwrap(),
        content_hash: reference.content_hash,
        storage_key: reference.storage_key,
        size_bytes: reference.size_bytes,
        project_id: project_id.clone(),
        task_id: Some(task_id.clone()),
    }
}

#[cfg(windows)]
fn file_write_lifecycle(fixture: &WorkspaceFixture, execution_id: &str) -> String {
    fixture
        .database()
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

#[test]
fn degraded_read_only_never_reaches_the_process_executor() {
    let fixture = WorkspaceFixture::new();
    fixture.seed_present_workspace();
    let policy = VersionedPolicyEngine::from_json(ALLOW_PROCESS_POLICY).unwrap();
    let request = tool_request_for_policy(
        "execution-degraded-read-only",
        policy.snapshot_digest().clone(),
    );
    let executor = Arc::new(RecordingExecutor::default());
    let bootstrap = Bootstrap::with_tool_broker(
        StartupConfig {
            app_data_dir: fixture.app_data.clone(),
            trusted_workspace_root: fixture.workspace_root.clone(),
            secret_values: Vec::new(),
            openai: None,
        },
        ToolBrokerConfig::new(
            ALLOW_PROCESS_POLICY,
            Arc::new(EchoAuthority),
            executor.clone(),
        )
        .degraded_read_only(),
    );
    let runtime = bootstrap.tool_runtime().unwrap();

    assert_eq!(
        runtime.availability().unwrap(),
        ToolRuntimeAvailability::DegradedReadOnly
    );
    let ToolOutcome::Execution(
        local_agent_terminal_application::DurableToolExecutionOutcome::Completed(receipt),
    ) = runtime.execute(request).unwrap()
    else {
        panic!("disabled process must resolve to a durable terminal receipt");
    };
    assert_eq!(
        receipt.terminal().kind(),
        ToolExecutionTerminalKind::Indeterminate
    );
    assert_eq!(
        receipt.terminal().error().unwrap().classification,
        SafeErrorClassification::Unavailable
    );
    assert!(receipt.terminal().post_effect().is_none());
    assert_eq!(executor.execute_calls.load(Ordering::SeqCst), 0);
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
            openai: None,
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
            openai: None,
        },
        ToolBrokerConfig::new(
            ALLOW_PROCESS_POLICY,
            Arc::new(EchoAuthority),
            executor.clone(),
        ),
    );
    let runtime = bootstrap.tool_runtime().unwrap();

    let first_receipts = std::thread::scope(|scope| {
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
        receipts
    });
    assert_eq!(runtime.stop_all().unwrap(), first_receipts);
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
        openai: None,
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
            openai: None,
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

        let cancelled_before_release = executor.wait_until_cancelled(Duration::from_secs(5));
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
            openai: None,
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
            openai: None,
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
    assert_eq!(entry.executable, "toolchain:cargo");
    assert_eq!(entry.arguments, ["test"]);
    assert_eq!(entry.cwd_scope, "worktree:task-1");
    assert!(entry.read_scopes.is_empty());
    assert!(entry.write_scopes.is_empty());
    assert_eq!(entry.actor_id, "agent-1");
    assert_eq!(entry.reason, "run focused tests");
    assert_eq!(entry.network_profile, "denied");
    assert_eq!(entry.policy_rules, ["approve-process"]);

    let approval_id = ApprovalId::new(published.approval_id.clone()).unwrap();
    let detail = runtime.approval_request(approval_id.clone()).unwrap();
    assert_eq!(detail.execution_id, "execution-runtime-activity");
    assert_eq!(detail.operation_digest, published.operation_digest);
    assert_eq!(detail.executable, "toolchain:cargo");
    assert_eq!(detail.arguments, ["test"]);
    assert_eq!(detail.cwd_scope, "worktree:task-1");
    assert!(detail.read_scopes.is_empty());
    assert!(detail.write_scopes.is_empty());

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
fn approval_display_redacts_secrets_without_losing_argument_boundaries() {
    let fixture = WorkspaceFixture::new();
    fixture.seed_present_workspace();
    let policy = VersionedPolicyEngine::from_json(APPROVE_PROCESS_POLICY).unwrap();
    let request = tool_request_for_policy_and_display(
        "execution-runtime-redacted-approval",
        policy.snapshot_digest().clone(),
        vec!["--token".to_owned(), "tok_test_7f89ac".to_owned()],
        "use tok_test_7f89ac for the focused test",
    );
    let bootstrap = Bootstrap::with_tool_broker(
        StartupConfig {
            app_data_dir: fixture.app_data.clone(),
            trusted_workspace_root: fixture.workspace_root.clone(),
            secret_values: Vec::new(),
            openai: None,
        },
        ToolBrokerConfig::new(
            APPROVE_PROCESS_POLICY,
            Arc::new(EchoAuthority),
            Arc::new(RecordingExecutor::default()),
        ),
    );
    let runtime = bootstrap.tool_runtime().unwrap();
    let ToolOutcome::ApprovalRequired(published) = runtime.execute(request).unwrap() else {
        panic!("approval policy must publish one immutable request");
    };

    let detail = runtime
        .approval_request(ApprovalId::new(published.approval_id).unwrap())
        .unwrap();

    assert_eq!(detail.arguments.len(), 2);
    assert_eq!(detail.arguments[0], "--token");
    assert!(detail.arguments[1].starts_with("[REDACTED:api_token:"));
    assert!(!detail.arguments[1].contains("tok_test_7f89ac"));
    assert!(!detail.reason.contains("tok_test_7f89ac"));
    assert_eq!(
        detail.redaction_state,
        local_agent_terminal_application::ToolRedactionStateDto::Redacted
    );
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
            openai: None,
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
            openai: None,
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
    tool_request_for_policy_and_display(
        execution_id,
        policy_snapshot_digest,
        vec!["test".to_owned()],
        "run focused tests",
    )
}

fn production_tool_request(
    execution_id: &str,
    policy_snapshot_digest: Sha256Digest,
) -> ToolRequest {
    let request = tool_request_for_policy(execution_id, policy_snapshot_digest.clone());
    let request = rebind_tool_request(
        &request,
        execution_id,
        Phase::Implementation,
        WorkspaceVersion::new(0),
    );
    let policy = ToolPolicyContext::new(
        PolicyActor {
            connection_id: "core.local".to_owned(),
            agent_id: "core.structured-tool".to_owned(),
            trust_tier: TrustTier::CoreAdapter,
            locality: ActorLocality::Local,
        },
        PolicyAction::new("process.exec").unwrap(),
        request.policy().resource().clone(),
        TaskRisk::High,
        "execute a structured local tool",
        policy_snapshot_digest,
    )
    .unwrap();
    ToolRequest::new(
        request.execution_id().clone(),
        request.process().clone(),
        policy,
    )
    .unwrap()
}

#[cfg(windows)]
fn record_file_write_policy(
    database: &SqliteStore,
    policy_snapshot_digest: Sha256Digest,
) -> FileWritePolicyBinding {
    let evaluated_at = Timestamp::from_unix_seconds(1_753_272_000);
    let request = production_tool_request(
        "production-file-write-policy",
        policy_snapshot_digest.clone(),
    );
    let draft = combine_policy_rules(
        policy_request_for_tool(&request, evaluated_at),
        PolicyVersion::new(1).unwrap(),
        vec![MatchedPolicyRule {
            rule_id: PolicyRuleId::new("allow-file-write").unwrap(),
            effect: PolicyEffect::Allow,
            redactions: Vec::new(),
        }],
        None,
    )
    .unwrap();
    let operation_digest = digest('e');
    let decision_id = database
        .record(RecordedPolicyDecision {
            decision: PolicyDecision {
                draft,
                operation_digest: operation_digest.clone(),
            },
            recorded_at: evaluated_at,
        })
        .unwrap();
    FileWritePolicyBinding {
        decision_id: decision_id.as_str().to_owned(),
        operation_digest,
        policy_snapshot_digest,
        effect: PolicyEffect::Allow,
        approval_id: None,
    }
}

fn rebind_tool_request(
    request: &ToolRequest,
    execution_id: &str,
    phase: Phase,
    workspace_version: WorkspaceVersion,
) -> ToolRequest {
    let approved = request.process();
    let process = approved.process();
    let binding = process.binding();
    let rebound = ProcessToolRequest::new(
        ProcessBinding::new(
            binding.task_id().clone(),
            binding.run_id().clone(),
            binding.plan_step_id().clone(),
            phase,
            workspace_version,
            binding.environment_profile().clone(),
            binding.timeout_ms(),
        )
        .unwrap(),
        ProcessInvocation::new(
            process.executable().clone(),
            process.argv().to_vec(),
            process.cwd().clone(),
            process.trust_tier(),
            process.network(),
            process.expected_writes().to_vec(),
            process.executor_fencing_token(),
        )
        .unwrap(),
    )
    .unwrap();
    let approved = ApprovedProcessRequest::new(
        approved.approved_executable().clone(),
        rebound,
        approved.expected_reads().to_vec(),
        approved.memory_limit_bytes(),
        approved.cpu_time_limit_ms(),
        approved.disk_write_limit_bytes(),
    )
    .unwrap();
    ToolRequest::new(
        local_agent_terminal_application::ToolExecutionId::new(execution_id).unwrap(),
        approved,
        request.policy().clone(),
    )
    .unwrap()
}

fn tool_request_for_policy_and_display(
    execution_id: &str,
    policy_snapshot_digest: Sha256Digest,
    arguments: Vec<String>,
    purpose: &str,
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
            arguments,
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
        purpose,
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
