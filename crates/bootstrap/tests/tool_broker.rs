#[allow(dead_code)]
mod support;

use std::path::PathBuf;

use local_agent_terminal_application::{
    bind_tool_approval_payload, canonical_policy_binding_digest, canonical_tool_request,
    policy_request_for_tool, ApprovalId, ApprovalResumeStore, ApprovedExecutableIdentity,
    ApprovedProcessRequest, PolicyDecision, PolicyDecisionStore, RecordedPolicyDecision,
    ResolvedExecutable, ToolApprovalOperationV1, ToolApprovalPayloadV1, ToolApprovalPublication,
    ToolApprovalRequest, ToolApprovalRequestPublisher, ToolExecutionResumeStore, ToolPolicyContext,
    ToolRequest, ToolRequestPublisher,
};
use local_agent_terminal_bootstrap::ToolArtifactPublisher;
use local_agent_terminal_domain::{
    combine_policy_rules, ActorLocality, ArtifactId, CapabilityRef, EnvironmentProfile,
    MatchedPolicyRule, NetworkProfile, Phase, PlanStepId, PolicyAction, PolicyActor, PolicyEffect,
    PolicyResource, PolicyRuleId, PolicyVersion, ProcessBinding, ProcessInvocation,
    ProcessToolRequest, ProcessTrustTier, ResourceClass, RunId, Sha256Digest, TaskId, TaskRisk,
    Timestamp, TrustTier, WorkspaceVersion,
};
use local_agent_terminal_storage_files::ContentAddressedArtifactStore;
use local_agent_terminal_storage_sqlite::SqliteStore;
use rusqlite::Connection;

use support::WorkspaceFixture;

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
            content_digest: digest('a'),
            resource_class: ResourceClass::InternalCode,
        },
        TaskRisk::High,
        "run focused tests",
        digest('b'),
    )
    .unwrap();
    ToolRequest::new(
        local_agent_terminal_application::ToolExecutionId::new(execution_id).unwrap(),
        approved,
        policy,
    )
    .unwrap()
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
