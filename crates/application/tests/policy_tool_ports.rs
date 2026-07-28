use std::sync::atomic::{AtomicUsize, Ordering};

use local_agent_terminal_application::{
    ApprovalCheck, ApprovalId, ApprovalInvalidation, ApprovalResolution, ApprovalSnapshot,
    ApprovalState, ApprovalStore, AuthorizedProcessRequest, AuthorizedToolRequest,
    CancellationReceipt, CapabilityFilesystem, CapabilityResolver, Clock, ExecuteApprovedTool,
    NewApproval, PolicyDecisionStore, PolicyEvaluator, PortError, ProcessLauncher, StructuredGit,
    StructuredToolExecutor, ToolExecutionId, ToolExecutionResult, ToolExecutionStore,
};
use local_agent_terminal_domain::{
    CapabilityRef, EnvironmentProfile, FencingToken, NetworkProfile, Phase, PlanStepId,
    ProcessBinding, ProcessInvocation, ProcessToolRequest, ProcessTrustTier, RunId, Sha256Digest,
    TaskId, WorkspaceVersion,
};

fn assert_object_safe<T: ?Sized>() {}

#[test]
fn policy_and_tool_ports_are_object_safe() {
    assert_object_safe::<dyn PolicyEvaluator>();
    assert_object_safe::<dyn PolicyDecisionStore>();
    assert_object_safe::<dyn ApprovalStore>();
    assert_object_safe::<dyn CapabilityResolver>();
    assert_object_safe::<dyn CapabilityFilesystem>();
    assert_object_safe::<dyn StructuredGit>();
    assert_object_safe::<dyn ProcessLauncher>();
    assert_object_safe::<dyn ToolExecutionStore>();
    assert_object_safe::<dyn StructuredToolExecutor>();
}

#[test]
fn invalid_or_consumed_approvals_do_not_call_the_executor() {
    for case in [
        ApprovalCase::Expired,
        ApprovalCase::ExpiredOffset,
        ApprovalCase::Consumed,
        ApprovalCase::PolicyChanged,
        ApprovalCase::WorkspaceChanged,
        ApprovalCase::FencingChanged,
        ApprovalCase::DigestChanged,
    ] {
        let executor = CountingExecutor::default();
        let approvals = FixedApprovals {
            snapshot: snapshot(case),
        };
        let use_case = ExecuteApprovedTool::new(&approvals, &executor, &FixedClock);

        let error = use_case
            .execute(check(), authorized_tool_request())
            .expect_err("invalid approval must fail before execution");
        assert_eq!(
            error.retryability(),
            local_agent_terminal_application::Retryability::NonRetryable
        );
        assert_eq!(executor.calls.load(Ordering::SeqCst), 0, "{case:?}");
    }
}

#[test]
fn request_digest_and_scope_mismatches_do_not_call_the_executor() {
    let mut cross_task_read = authorized_tool_request();
    cross_task_read
        .request
        .expected_reads
        .push(CapabilityRef::worktree(TaskId::new("task-2").unwrap(), "src").unwrap());
    for request in [
        authorized_tool_request_with("task-1", 4, 19, 'd'),
        authorized_tool_request_with("task-2", 4, 19, 'a'),
        authorized_tool_request_with("task-1", 5, 19, 'a'),
        authorized_tool_request_with("task-1", 4, 20, 'a'),
        cross_task_read,
    ] {
        let executor = CountingExecutor::default();
        let approvals = FixedApprovals {
            snapshot: approved_snapshot(),
        };
        let use_case = ExecuteApprovedTool::new(&approvals, &executor, &FixedClock);

        let error = use_case
            .execute(check(), request)
            .expect_err("request mismatch must fail before execution");
        assert_eq!(
            error.retryability(),
            local_agent_terminal_application::Retryability::NonRetryable
        );
        assert_eq!(executor.calls.load(Ordering::SeqCst), 0);
    }
}

#[derive(Debug, Clone, Copy)]
enum ApprovalCase {
    Expired,
    ExpiredOffset,
    Consumed,
    PolicyChanged,
    WorkspaceChanged,
    FencingChanged,
    DigestChanged,
}

struct FixedApprovals {
    snapshot: ApprovalSnapshot,
}

impl ApprovalStore for FixedApprovals {
    fn request(&self, _: NewApproval) -> Result<ApprovalSnapshot, PortError> {
        unreachable!()
    }

    fn resolve(&self, _: ApprovalResolution) -> Result<ApprovalSnapshot, PortError> {
        unreachable!()
    }

    fn valid_for(&self, _: ApprovalCheck) -> Result<Option<ApprovalSnapshot>, PortError> {
        Ok(Some(self.snapshot.clone()))
    }

    fn invalidate(&self, _: ApprovalInvalidation) -> Result<u64, PortError> {
        unreachable!()
    }
}

struct FixedClock;

impl Clock for FixedClock {
    fn now_utc(&self) -> Result<String, PortError> {
        Ok("2026-07-23T12:00:00Z".to_owned())
    }
}

#[derive(Default)]
struct CountingExecutor {
    calls: AtomicUsize,
}

impl StructuredToolExecutor for CountingExecutor {
    fn execute(&self, _: AuthorizedToolRequest) -> Result<ToolExecutionResult, PortError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        unreachable!()
    }

    fn cancel(&self, execution_id: &ToolExecutionId) -> Result<CancellationReceipt, PortError> {
        Ok(CancellationReceipt {
            execution_id: execution_id.clone(),
            cancelled: true,
        })
    }
}

fn snapshot(case: ApprovalCase) -> ApprovalSnapshot {
    let mut snapshot = approved_snapshot();
    match case {
        ApprovalCase::Expired => snapshot.expires_at = "2026-07-23T11:59:59Z".to_owned(),
        ApprovalCase::ExpiredOffset => snapshot.expires_at = "2026-07-23T19:00:00+07:30".to_owned(),
        ApprovalCase::Consumed => snapshot.state = ApprovalState::Consumed,
        ApprovalCase::PolicyChanged => snapshot.policy_snapshot_digest = digest('c'),
        ApprovalCase::WorkspaceChanged => snapshot.workspace_version = WorkspaceVersion::new(5),
        ApprovalCase::FencingChanged => snapshot.fencing_token = Some(20),
        ApprovalCase::DigestChanged => snapshot.operation_digest = digest('d'),
    }
    snapshot
}

fn approved_snapshot() -> ApprovalSnapshot {
    ApprovalSnapshot {
        approval_id: ApprovalId::new("approval-1").unwrap(),
        state: ApprovalState::Approved,
        operation_digest: digest('a'),
        task_id: task_id(),
        workspace_version: WorkspaceVersion::new(4),
        policy_snapshot_digest: digest('b'),
        fencing_token: Some(19),
        expires_at: "2026-07-23T12:15:00Z".to_owned(),
        nonce: "0123456789abcdef0123456789abcdef".to_owned(),
    }
}

fn check() -> ApprovalCheck {
    ApprovalCheck {
        approval_id: ApprovalId::new("approval-1").unwrap(),
        expected_operation_digest: digest('a'),
        task_id: task_id(),
        workspace_version: WorkspaceVersion::new(4),
        policy_snapshot_digest: digest('b'),
        fencing_token: Some(19),
        checked_at: "2026-07-23T12:00:00Z".to_owned(),
    }
}

fn authorized_tool_request() -> AuthorizedToolRequest {
    authorized_tool_request_with("task-1", 4, 19, 'a')
}

fn authorized_tool_request_with(
    task: &str,
    workspace_version: u64,
    fencing_token: u64,
    operation_digest: char,
) -> AuthorizedToolRequest {
    let task_id = TaskId::new(task).unwrap();
    let binding = ProcessBinding::new(
        task_id.clone(),
        RunId::new("run-1").unwrap(),
        PlanStepId::new("step-1").unwrap(),
        Phase::Implementation,
        WorkspaceVersion::new(workspace_version),
        EnvironmentProfile::new("rust", digest('e')).unwrap(),
        1,
    )
    .unwrap();
    let process = ProcessToolRequest::new(
        binding,
        ProcessInvocation::new(
            CapabilityRef::toolchain("cargo").unwrap(),
            vec!["test".to_owned()],
            CapabilityRef::worktree(task_id, ".").unwrap(),
            ProcessTrustTier::IsolatedWorker,
            NetworkProfile::Denied,
            Vec::new(),
            Some(FencingToken::new(fencing_token).unwrap()),
        )
        .unwrap(),
    )
    .unwrap();
    AuthorizedToolRequest {
        execution_id: ToolExecutionId::new("execution-1").unwrap(),
        operation_digest: digest(operation_digest),
        request: AuthorizedProcessRequest {
            process,
            expected_reads: Vec::new(),
            memory_limit_bytes: None,
            cpu_time_limit_ms: None,
        },
    }
}

fn task_id() -> TaskId {
    TaskId::new("task-1").unwrap()
}

fn digest(character: char) -> Sha256Digest {
    Sha256Digest::new(format!("sha256:{}", character.to_string().repeat(64))).unwrap()
}
