#[allow(dead_code)]
mod support;

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::sync::{mpsc, Arc, Condvar, Mutex};
use std::time::Duration;

use local_agent_terminal_application::{
    bind_tool_approval_payload, canonical_policy_binding_digest, canonical_tool_request,
    policy_request_for_tool, ApprovalId, ApprovalResumeStore, ApprovedExecutableIdentity,
    ApprovedProcessRequest, AuthorizedToolExecutionClaim, AuthorizedToolRequest,
    CancellationReceipt, DeniedToolExecution, DisclosureOutcome, DurableToolExecutionArtifact,
    DurableToolExecutionArtifacts, DurableToolExecutionReceipt, FileReadRequest, FileWriteRequest,
    GitDiffRequest, GitDiffResult, GitStatusRequest, GitStatusResult, ImmutableToolRequest,
    IncompleteToolExecution, NewToolExecution, NewToolIntent, OperationIntentSnapshot,
    PolicyBoundBytes, PolicyDecision, PolicyDecisionStore, PortError, ProcessStatus,
    RecordedPolicyDecision, ResolvedExecutable, Retryability, SafeErrorClassification,
    StructuredToolExecutor, ToolApprovalOperationV1, ToolApprovalPayloadV1,
    ToolApprovalPublication, ToolApprovalRequest, ToolApprovalRequestPublisher,
    ToolExecutionCancellationClaim, ToolExecutionClaim, ToolExecutionClaimAuthority,
    ToolExecutionDenialRequest, ToolExecutionId, ToolExecutionOutput, ToolExecutionResolution,
    ToolExecutionResult, ToolExecutionResumeStore, ToolExecutionStore, ToolExecutionTerminal,
    ToolExecutionTerminalKind, ToolPolicyContext, ToolRequest, ToolRequestPublisher, VerifiedWrite,
};
use local_agent_terminal_bootstrap::{ToolArtifactPublisher, ToolRuntime};
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

#[test]
fn stop_all_closes_dispatch_cancels_each_running_execution_once_and_joins_workers() {
    let authorities = ["execution-stop-a", "execution-stop-b"]
        .map(cancellation_authority)
        .to_vec();
    let events = Arc::new(Mutex::new(Vec::new()));
    let executions = Arc::new(RecordingExecutionStore::running(
        authorities.clone(),
        Arc::clone(&events),
    ));
    let executor = Arc::new(BlockingCancellationExecutor::new(Arc::clone(&events)));
    let execution_port: Arc<dyn ToolExecutionStore> = executions.clone();
    let executor_port: Arc<dyn StructuredToolExecutor> = executor.clone();
    let runtime = ToolRuntime::new(execution_port, executor_port);
    runtime.recover_startup().unwrap();
    runtime.release_dispatch().unwrap();

    for authority in authorities.clone() {
        let execution_id = authority.execution_id().clone();
        let waiting_executor = Arc::clone(&executor);
        runtime
            .dispatch(execution_id.clone(), move || {
                waiting_executor.wait_until_cancelled(&execution_id);
                Ok(terminated_receipt(authority))
            })
            .unwrap();
    }

    let receipts = runtime.stop_all().unwrap();

    assert_eq!(receipts.len(), 2);
    assert!(receipts
        .iter()
        .all(|receipt| receipt.terminal().kind() == ToolExecutionTerminalKind::Terminated));
    for authority in &authorities {
        assert_eq!(executor.cancel_count(authority.execution_id()), 1);
        assert_eq!(
            executions
                .terminal(authority.execution_id())
                .unwrap()
                .terminal()
                .kind(),
            ToolExecutionTerminalKind::Terminated
        );
        assert_event_order(
            &events.lock().unwrap(),
            authority.execution_id(),
            &["cancelling", "cancel", "terminal"],
        );
    }
    assert!(runtime
        .dispatch(ToolExecutionId::new("execution-too-late").unwrap(), || {
            unreachable!("closed dispatch must not start a worker")
        })
        .is_err());
    assert!(runtime.stop_all().unwrap().is_empty());
    assert!(authorities
        .iter()
        .all(|authority| executor.cancel_count(authority.execution_id()) == 1));
}

#[test]
fn stop_all_persists_indeterminate_after_joining_a_panicked_worker() {
    let authority = cancellation_authority("execution-stop-panic");
    let events = Arc::new(Mutex::new(Vec::new()));
    let executions = Arc::new(RecordingExecutionStore::running(
        vec![authority.clone()],
        Arc::clone(&events),
    ));
    let executor = Arc::new(BlockingCancellationExecutor::new(events));
    let execution_port: Arc<dyn ToolExecutionStore> = executions.clone();
    let executor_port: Arc<dyn StructuredToolExecutor> = executor.clone();
    let runtime = ToolRuntime::new(execution_port, executor_port);
    runtime.recover_startup().unwrap();
    runtime.release_dispatch().unwrap();
    let execution_id = authority.execution_id().clone();
    runtime
        .dispatch(execution_id.clone(), || {
            panic!("injected worker panic");
        })
        .unwrap();

    let receipts = runtime.stop_all().unwrap();

    assert_eq!(receipts.len(), 1);
    assert_eq!(
        receipts[0].terminal().kind(),
        ToolExecutionTerminalKind::Indeterminate
    );
    assert_eq!(
        executions
            .terminal(&execution_id)
            .unwrap()
            .terminal()
            .kind(),
        ToolExecutionTerminalKind::Indeterminate
    );
    assert_eq!(executor.cancel_count(&execution_id), 1);
}

#[test]
fn concurrent_stop_all_callers_wait_for_the_same_worker_join() {
    let authority = cancellation_authority("execution-stop-concurrent");
    let events = Arc::new(Mutex::new(Vec::new()));
    let executions = Arc::new(RecordingExecutionStore::running(
        vec![authority.clone()],
        Arc::clone(&events),
    ));
    let executor = Arc::new(BlockingCancellationExecutor::new(events));
    let execution_port: Arc<dyn ToolExecutionStore> = executions;
    let executor_port: Arc<dyn StructuredToolExecutor> = executor.clone();
    let runtime = Arc::new(ToolRuntime::new(execution_port, executor_port));
    runtime.recover_startup().unwrap();
    runtime.release_dispatch().unwrap();
    let execution_id = authority.execution_id().clone();
    let worker_execution_id = execution_id.clone();
    let worker_authority = authority.clone();
    let waiting_executor = Arc::clone(&executor);
    let (cancelled_tx, cancelled_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    runtime
        .dispatch(execution_id.clone(), move || {
            waiting_executor.wait_until_cancelled(&worker_execution_id);
            cancelled_tx.send(()).unwrap();
            release_rx.recv().unwrap();
            Ok(terminated_receipt(worker_authority))
        })
        .unwrap();

    let first_runtime = Arc::clone(&runtime);
    let first = std::thread::spawn(move || first_runtime.stop_all());
    cancelled_rx.recv_timeout(Duration::from_secs(5)).unwrap();
    let second_runtime = Arc::clone(&runtime);
    let (second_tx, second_rx) = mpsc::channel();
    let second = std::thread::spawn(move || {
        second_tx.send(second_runtime.stop_all()).unwrap();
    });

    assert!(matches!(
        second_rx.recv_timeout(Duration::from_millis(100)),
        Err(mpsc::RecvTimeoutError::Timeout)
    ));
    release_tx.send(()).unwrap();
    assert_eq!(first.join().unwrap().unwrap().len(), 1);
    assert!(second_rx
        .recv_timeout(Duration::from_secs(5))
        .unwrap()
        .unwrap()
        .is_empty());
    second.join().unwrap();
    assert_eq!(executor.cancel_count(authority.execution_id()), 1);
}

#[derive(Clone)]
enum RecordedExecutionState {
    Running(ToolExecutionClaimAuthority),
    Cancelling(ToolExecutionClaimAuthority),
    Terminal(DurableToolExecutionReceipt),
}

struct RecordingExecutionStore {
    states: Mutex<BTreeMap<ToolExecutionId, RecordedExecutionState>>,
    events: Arc<Mutex<Vec<String>>>,
}

impl RecordingExecutionStore {
    fn running(
        authorities: Vec<ToolExecutionClaimAuthority>,
        events: Arc<Mutex<Vec<String>>>,
    ) -> Self {
        Self {
            states: Mutex::new(
                authorities
                    .into_iter()
                    .map(|authority| {
                        (
                            authority.execution_id().clone(),
                            RecordedExecutionState::Running(authority),
                        )
                    })
                    .collect(),
            ),
            events,
        }
    }

    fn terminal(&self, execution_id: &ToolExecutionId) -> Option<DurableToolExecutionReceipt> {
        match self.states.lock().unwrap().get(execution_id) {
            Some(RecordedExecutionState::Terminal(receipt)) => Some(receipt.clone()),
            _ => None,
        }
    }
}

impl ToolExecutionStore for RecordingExecutionStore {
    fn reserve(&self, _: NewToolIntent) -> Result<OperationIntentSnapshot, PortError> {
        unreachable!()
    }

    fn begin(&self, _: NewToolExecution) -> Result<ToolExecutionClaim, PortError> {
        unreachable!()
    }

    fn begin_authorized(
        &self,
        _: AuthorizedToolExecutionClaim,
    ) -> Result<ToolExecutionClaim, PortError> {
        unreachable!()
    }

    fn load_denied(
        &self,
        _: &ArtifactId,
        _: &ImmutableToolRequest,
    ) -> Result<Option<DeniedToolExecution>, PortError> {
        unreachable!()
    }

    fn resolve_denied(
        &self,
        _: ToolExecutionDenialRequest,
    ) -> Result<DeniedToolExecution, PortError> {
        unreachable!()
    }

    fn request_cancellation(
        &self,
        execution_id: &ToolExecutionId,
    ) -> Result<ToolExecutionCancellationClaim, PortError> {
        let mut states = self.states.lock().unwrap();
        match states.get(execution_id).cloned() {
            Some(RecordedExecutionState::Running(authority)) => {
                states.insert(
                    execution_id.clone(),
                    RecordedExecutionState::Cancelling(authority.clone()),
                );
                self.events
                    .lock()
                    .unwrap()
                    .push(format!("cancelling:{}", execution_id.as_str()));
                Ok(ToolExecutionCancellationClaim::Claimed(authority))
            }
            Some(RecordedExecutionState::Cancelling(authority)) => {
                Ok(ToolExecutionCancellationClaim::InFlight(authority))
            }
            Some(RecordedExecutionState::Terminal(receipt)) => {
                Ok(ToolExecutionCancellationClaim::Completed(receipt))
            }
            None => Err(not_found()),
        }
    }

    fn resolve_terminal(
        &self,
        resolution: ToolExecutionResolution,
    ) -> Result<DurableToolExecutionReceipt, PortError> {
        let execution_id = resolution.authority().execution_id().clone();
        let mut states = self.states.lock().unwrap();
        if let Some(RecordedExecutionState::Terminal(receipt)) = states.get(&execution_id) {
            return (receipt == resolution.receipt())
                .then(|| receipt.clone())
                .ok_or_else(conflict);
        }
        states.insert(
            execution_id.clone(),
            RecordedExecutionState::Terminal(resolution.receipt().clone()),
        );
        self.events
            .lock()
            .unwrap()
            .push(format!("terminal:{}", execution_id.as_str()));
        Ok(resolution.into_receipt())
    }

    fn incomplete(&self) -> Result<Vec<IncompleteToolExecution>, PortError> {
        Ok(Vec::new())
    }
}

struct BlockingCancellationExecutor {
    cancelled: Mutex<BTreeSet<ToolExecutionId>>,
    cancel_counts: Mutex<BTreeMap<ToolExecutionId, usize>>,
    cancellation: Condvar,
    events: Arc<Mutex<Vec<String>>>,
}

impl BlockingCancellationExecutor {
    fn new(events: Arc<Mutex<Vec<String>>>) -> Self {
        Self {
            cancelled: Mutex::new(BTreeSet::new()),
            cancel_counts: Mutex::new(BTreeMap::new()),
            cancellation: Condvar::new(),
            events,
        }
    }

    fn wait_until_cancelled(&self, execution_id: &ToolExecutionId) {
        let mut cancelled = self.cancelled.lock().unwrap();
        while !cancelled.contains(execution_id) {
            cancelled = self.cancellation.wait(cancelled).unwrap();
        }
    }

    fn cancel_count(&self, execution_id: &ToolExecutionId) -> usize {
        self.cancel_counts
            .lock()
            .unwrap()
            .get(execution_id)
            .copied()
            .unwrap_or(0)
    }
}

impl StructuredToolExecutor for BlockingCancellationExecutor {
    fn execute(&self, _: AuthorizedToolRequest) -> Result<ToolExecutionResult, PortError> {
        unreachable!()
    }

    fn cancel(&self, execution_id: &ToolExecutionId) -> Result<CancellationReceipt, PortError> {
        *self
            .cancel_counts
            .lock()
            .unwrap()
            .entry(execution_id.clone())
            .or_default() += 1;
        self.events
            .lock()
            .unwrap()
            .push(format!("cancel:{}", execution_id.as_str()));
        self.cancelled.lock().unwrap().insert(execution_id.clone());
        self.cancellation.notify_all();
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

fn cancellation_authority(execution_id: &str) -> ToolExecutionClaimAuthority {
    ToolExecutionClaimAuthority::from_persisted(
        ToolExecutionId::new(execution_id).unwrap(),
        digest('c'),
        RunId::new("run-lease-1").unwrap(),
        1,
        None,
    )
    .unwrap()
}

fn terminated_receipt(authority: ToolExecutionClaimAuthority) -> DurableToolExecutionReceipt {
    DurableToolExecutionReceipt::new(
        authority,
        ToolExecutionTerminal::terminated(ToolExecutionOutput {
            exit_code: None,
            output_digest: digest('d'),
            duration_ms: 1,
            artifacts: DurableToolExecutionArtifacts::new(
                DurableToolExecutionArtifact::Unavailable,
                DurableToolExecutionArtifact::Unavailable,
                Vec::new(),
            ),
        })
        .unwrap(),
    )
}

fn assert_event_order(events: &[String], execution_id: &ToolExecutionId, expected: &[&str]) {
    let mut positions = expected.iter().map(|name| {
        events
            .iter()
            .position(|event| event == &format!("{name}:{}", execution_id.as_str()))
            .unwrap()
    });
    let first = positions.next().unwrap();
    assert!(positions
        .scan(first, |previous, current| {
            let ordered = *previous < current;
            *previous = current;
            Some(ordered)
        })
        .all(|ordered| ordered));
}

fn conflict() -> PortError {
    PortError::failure(
        SafeErrorClassification::Conflict,
        Retryability::NonRetryable,
    )
}

fn not_found() -> PortError {
    PortError::failure(
        SafeErrorClassification::NotFound,
        Retryability::NonRetryable,
    )
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
