use std::sync::atomic::{AtomicUsize, Ordering};

use local_agent_terminal_application::{
    bind_tool_approval_payload, canonical_approval_payload, ApprovalCheck, ApprovalDigestPayload,
    ApprovalId, ApprovalInvalidation, ApprovalResolution, ApprovalSnapshot, ApprovalState,
    ApprovalStore, AuthorizedProcessRequest, AuthorizedToolRequest, BoundToolApproval,
    CancellationReceipt, CapabilityFilesystem, CapabilityResolver, Clock, ExecuteApprovedTool,
    NewApproval, PolicyDecisionStore, PolicyEvaluator, PortError, ProcessLauncher, Retryability,
    SafeErrorClassification, StructuredGit, StructuredToolExecutor, ToolApprovalOperationV1,
    ToolApprovalPayloadV1, ToolExecutionId, ToolExecutionResult, ToolExecutionStore,
};
use local_agent_terminal_domain::{
    CapabilityRef, EnvironmentProfile, ExpectedWrite, FencingToken, NetworkProfile, Phase,
    PlanStepId, ProcessBinding, ProcessInvocation, ProcessToolRequest, ProcessTrustTier, RunId,
    Sha256Digest, TaskId, WorkspaceVersion,
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
fn valid_approval_reaches_the_executor_once() {
    let executor = CountingExecutor::default();
    let approvals = FixedApprovals {
        snapshot: approved_snapshot(),
    };
    let use_case = ExecuteApprovedTool::new(&approvals, &executor, &FixedClock);

    let _ = use_case.execute(check(), authorized_tool_request());

    assert_eq!(executor.calls.load(Ordering::SeqCst), 1);
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
        ApprovalCase::RequestBindingChanged,
        ApprovalCase::MissingRequestBinding,
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
    for request in [
        authorized_tool_request_with_nonce("abcdef0123456789abcdef0123456789"),
        authorized_tool_request_for(RequestMutation::Task),
        authorized_tool_request_for(RequestMutation::Workspace),
        authorized_tool_request_for(RequestMutation::Fencing),
        authorized_tool_request_for(RequestMutation::CrossTaskRead),
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

#[test]
fn every_changed_execution_detail_is_rejected_before_the_executor() {
    for mutation in [
        RequestMutation::Task,
        RequestMutation::Run,
        RequestMutation::PlanStep,
        RequestMutation::Phase,
        RequestMutation::Executable,
        RequestMutation::Arguments,
        RequestMutation::Cwd,
        RequestMutation::Environment,
        RequestMutation::TrustTier,
        RequestMutation::Network,
        RequestMutation::ExpectedReads,
        RequestMutation::ExpectedWrites,
        RequestMutation::Timeout,
        RequestMutation::MemoryLimit,
        RequestMutation::CpuLimit,
    ] {
        let executor = CountingExecutor::default();
        let approvals = FixedApprovals {
            snapshot: approved_snapshot(),
        };
        let use_case = ExecuteApprovedTool::new(&approvals, &executor, &FixedClock);

        let _ = use_case.execute(check(), authorized_tool_request_for(mutation));

        assert_eq!(executor.calls.load(Ordering::SeqCst), 0, "{mutation:?}");
    }
}

#[test]
fn arguments_digest_binds_only_argv() {
    let baseline_request = authorized_process_request_for(RequestMutation::None);
    let baseline_payload = approved_tool_payload(&baseline_request, APPROVAL_NONCE);
    let baseline_arguments_digest = baseline_payload.operation.arguments_digest.clone();
    let baseline_operation_digest =
        canonical_approval_payload(&ApprovalDigestPayload::Tool(baseline_payload))
            .unwrap()
            .operation_digest;

    for mutation in [
        RequestMutation::Task,
        RequestMutation::Run,
        RequestMutation::PlanStep,
        RequestMutation::Phase,
        RequestMutation::Workspace,
        RequestMutation::Fencing,
        RequestMutation::Executable,
        RequestMutation::Cwd,
        RequestMutation::Environment,
        RequestMutation::TrustTier,
        RequestMutation::Network,
        RequestMutation::ExpectedReads,
        RequestMutation::ExpectedWrites,
        RequestMutation::Timeout,
        RequestMutation::MemoryLimit,
        RequestMutation::CpuLimit,
    ] {
        let request = authorized_process_request_for(mutation);
        let payload = approved_tool_payload(&request, APPROVAL_NONCE);

        assert_eq!(
            payload.operation.arguments_digest, baseline_arguments_digest,
            "{mutation:?}"
        );
    }

    for mutation in [
        RequestMutation::Task,
        RequestMutation::Run,
        RequestMutation::PlanStep,
        RequestMutation::Workspace,
        RequestMutation::Fencing,
        RequestMutation::Cwd,
        RequestMutation::Environment,
        RequestMutation::Network,
        RequestMutation::ExpectedWrites,
    ] {
        let request = authorized_process_request_for(mutation);
        let payload = approved_tool_payload(&request, APPROVAL_NONCE);
        assert_ne!(
            canonical_approval_payload(&ApprovalDigestPayload::Tool(payload))
                .unwrap()
                .operation_digest,
            baseline_operation_digest,
            "{mutation:?}"
        );
    }

    for mutation in [
        RequestMutation::Phase,
        RequestMutation::Executable,
        RequestMutation::TrustTier,
        RequestMutation::ExpectedReads,
        RequestMutation::Timeout,
        RequestMutation::MemoryLimit,
        RequestMutation::CpuLimit,
    ] {
        let request = authorized_process_request_for(mutation);
        let payload = approved_tool_payload(&request, APPROVAL_NONCE);
        assert_eq!(
            canonical_approval_payload(&ApprovalDigestPayload::Tool(payload))
                .unwrap()
                .operation_digest,
            baseline_operation_digest,
            "{mutation:?}"
        );
    }

    let changed_arguments = approved_tool_payload(
        &authorized_process_request_for(RequestMutation::Arguments),
        APPROVAL_NONCE,
    );
    assert_ne!(
        changed_arguments.operation.arguments_digest,
        baseline_arguments_digest
    );
}

#[test]
fn trusted_request_binding_covers_every_execution_detail() {
    let baseline = approved_tool_binding(
        &authorized_process_request_for(RequestMutation::None),
        APPROVAL_NONCE,
    );

    for mutation in [
        RequestMutation::Task,
        RequestMutation::Run,
        RequestMutation::PlanStep,
        RequestMutation::Phase,
        RequestMutation::Workspace,
        RequestMutation::Fencing,
        RequestMutation::Executable,
        RequestMutation::Arguments,
        RequestMutation::Cwd,
        RequestMutation::Environment,
        RequestMutation::TrustTier,
        RequestMutation::Network,
        RequestMutation::ExpectedReads,
        RequestMutation::ExpectedWrites,
        RequestMutation::Timeout,
        RequestMutation::MemoryLimit,
        RequestMutation::CpuLimit,
    ] {
        let changed =
            approved_tool_binding(&authorized_process_request_for(mutation), APPROVAL_NONCE);

        assert_ne!(
            changed.request_binding_digest(),
            baseline.request_binding_digest(),
            "{mutation:?}"
        );
    }
}

#[test]
fn approval_identity_and_nonce_mismatches_do_not_call_the_executor() {
    let mut wrong_id = approved_snapshot();
    wrong_id.approval_id = ApprovalId::new("approval-2").unwrap();
    let mut missing_nonce = approved_snapshot();
    missing_nonce.nonce.clear();
    let mut wrong_nonce = approved_snapshot();
    wrong_nonce.nonce = "abcdef0123456789abcdef0123456789".to_owned();

    for snapshot in [wrong_id, missing_nonce, wrong_nonce] {
        let executor = CountingExecutor::default();
        let approvals = FixedApprovals { snapshot };
        let use_case = ExecuteApprovedTool::new(&approvals, &executor, &FixedClock);

        let _ = use_case.execute(check(), authorized_tool_request());

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
    RequestBindingChanged,
    MissingRequestBinding,
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
        Err(PortError::failure(
            SafeErrorClassification::Internal,
            Retryability::NonRetryable,
        ))
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
        ApprovalCase::RequestBindingChanged => {
            snapshot.tool_request_binding_digest = Some(
                approved_tool_binding(
                    &authorized_process_request_for(RequestMutation::Phase),
                    APPROVAL_NONCE,
                )
                .request_binding_digest()
                .clone(),
            );
        }
        ApprovalCase::MissingRequestBinding => snapshot.tool_request_binding_digest = None,
    }
    snapshot
}

fn approved_snapshot() -> ApprovalSnapshot {
    ApprovalSnapshot {
        approval_id: ApprovalId::new("approval-1").unwrap(),
        state: ApprovalState::Approved,
        operation_digest: approved_operation_digest(),
        task_id: task_id(),
        workspace_version: WorkspaceVersion::new(4),
        policy_snapshot_digest: digest('b'),
        fencing_token: Some(19),
        tool_request_binding_digest: Some(
            approved_tool_binding(
                &authorized_process_request_for(RequestMutation::None),
                APPROVAL_NONCE,
            )
            .request_binding_digest()
            .clone(),
        ),
        expires_at: "2026-07-23T12:15:00Z".to_owned(),
        nonce: "0123456789abcdef0123456789abcdef".to_owned(),
    }
}

fn check() -> ApprovalCheck {
    ApprovalCheck {
        approval_id: ApprovalId::new("approval-1").unwrap(),
        expected_operation_digest: approved_operation_digest(),
        task_id: task_id(),
        workspace_version: WorkspaceVersion::new(4),
        policy_snapshot_digest: digest('b'),
        fencing_token: Some(19),
        checked_at: "2026-07-23T12:00:00Z".to_owned(),
    }
}

fn authorized_tool_request() -> AuthorizedToolRequest {
    authorized_tool_request_for(RequestMutation::None)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RequestMutation {
    None,
    Task,
    Workspace,
    Fencing,
    Run,
    PlanStep,
    Phase,
    Executable,
    Arguments,
    Cwd,
    Environment,
    TrustTier,
    Network,
    ExpectedReads,
    CrossTaskRead,
    ExpectedWrites,
    Timeout,
    MemoryLimit,
    CpuLimit,
}

fn authorized_tool_request_for(mutation: RequestMutation) -> AuthorizedToolRequest {
    let baseline_request = authorized_process_request_for(RequestMutation::None);
    let approved_binding = approved_tool_binding(&baseline_request, APPROVAL_NONCE);
    AuthorizedToolRequest::new(
        ToolExecutionId::new("execution-1").unwrap(),
        approved_binding,
        authorized_process_request_for(mutation),
    )
}

fn authorized_tool_request_with_nonce(nonce: &str) -> AuthorizedToolRequest {
    let request = authorized_process_request_for(RequestMutation::None);
    AuthorizedToolRequest::new(
        ToolExecutionId::new("execution-1").unwrap(),
        approved_tool_binding(&request, nonce),
        request,
    )
}

fn authorized_process_request_for(mutation: RequestMutation) -> AuthorizedProcessRequest {
    let task_id = TaskId::new(if mutation == RequestMutation::Task {
        "task-2"
    } else {
        "task-1"
    })
    .unwrap();
    let environment_digest = if mutation == RequestMutation::Environment {
        digest('f')
    } else {
        digest('e')
    };
    let binding = ProcessBinding::new(
        task_id.clone(),
        RunId::new(if mutation == RequestMutation::Run {
            "run-2"
        } else {
            "run-1"
        })
        .unwrap(),
        PlanStepId::new(if mutation == RequestMutation::PlanStep {
            "step-2"
        } else {
            "step-1"
        })
        .unwrap(),
        if mutation == RequestMutation::Phase {
            Phase::Verification
        } else {
            Phase::Implementation
        },
        WorkspaceVersion::new(if mutation == RequestMutation::Workspace {
            5
        } else {
            4
        }),
        EnvironmentProfile::new("rust", environment_digest).unwrap(),
        if mutation == RequestMutation::Timeout {
            2
        } else {
            1
        },
    )
    .unwrap();
    let expected_writes = if mutation == RequestMutation::ExpectedWrites {
        vec![
            ExpectedWrite::new(CapabilityRef::worktree(task_id.clone(), "target").unwrap())
                .unwrap(),
        ]
    } else {
        Vec::new()
    };
    let process = ProcessToolRequest::new(
        binding,
        ProcessInvocation::new(
            CapabilityRef::toolchain(if mutation == RequestMutation::Executable {
                "rustc"
            } else {
                "cargo"
            })
            .unwrap(),
            if mutation == RequestMutation::Arguments {
                vec!["check".to_owned()]
            } else {
                vec!["test".to_owned()]
            },
            CapabilityRef::worktree(
                task_id.clone(),
                if mutation == RequestMutation::Cwd {
                    "src"
                } else {
                    "."
                },
            )
            .unwrap(),
            if mutation == RequestMutation::TrustTier {
                ProcessTrustTier::BrokeredProcess
            } else {
                ProcessTrustTier::IsolatedWorker
            },
            if mutation == RequestMutation::Network {
                NetworkProfile::ApprovedDestinations
            } else {
                NetworkProfile::Denied
            },
            expected_writes,
            Some(
                FencingToken::new(if mutation == RequestMutation::Fencing {
                    20
                } else {
                    19
                })
                .unwrap(),
            ),
        )
        .unwrap(),
    )
    .unwrap();
    AuthorizedProcessRequest {
        process,
        expected_reads: match mutation {
            RequestMutation::ExpectedReads => {
                vec![CapabilityRef::worktree(task_id, "src").unwrap()]
            }
            RequestMutation::CrossTaskRead => {
                vec![CapabilityRef::worktree(TaskId::new("task-2").unwrap(), "src").unwrap()]
            }
            _ => Vec::new(),
        },
        memory_limit_bytes: (mutation == RequestMutation::MemoryLimit).then_some(1024),
        cpu_time_limit_ms: (mutation == RequestMutation::CpuLimit).then_some(500),
    }
}

const APPROVAL_NONCE: &str = "0123456789abcdef0123456789abcdef";

fn approved_tool_payload(request: &AuthorizedProcessRequest, nonce: &str) -> ToolApprovalPayloadV1 {
    approved_tool_binding(request, nonce).payload().clone()
}

fn approved_tool_binding(request: &AuthorizedProcessRequest, nonce: &str) -> BoundToolApproval {
    bind_tool_approval_payload(
        ToolApprovalPayloadV1 {
            schema: "approval-digest.v1".to_owned(),
            approval_type: "tool".to_owned(),
            task_id: "unbound".to_owned(),
            operation: ToolApprovalOperationV1 {
                run_id: "unbound".to_owned(),
                plan_step_id: "unbound".to_owned(),
                tool: "process.exec".to_owned(),
                executable_digest: None,
                arguments_digest: digest('0').as_str().to_owned(),
                script_digest: None,
                cwd_capability: "unbound".to_owned(),
                environment_profile_digest: digest('0').as_str().to_owned(),
                network_profile: "denied".to_owned(),
                expected_writes: Vec::new(),
                executor_fencing_token: None,
            },
            policy_snapshot_digest: digest('b').as_str().to_owned(),
            workspace_version: 0,
            requested_at: "2026-07-23T12:00:00Z".to_owned(),
            expires_at: "2026-07-23T12:15:00Z".to_owned(),
            nonce: nonce.to_owned(),
        },
        request,
    )
    .unwrap()
}

fn approved_operation_digest() -> Sha256Digest {
    let request = authorized_process_request_for(RequestMutation::None);
    canonical_approval_payload(&ApprovalDigestPayload::Tool(approved_tool_payload(
        &request,
        APPROVAL_NONCE,
    )))
    .unwrap()
    .operation_digest
}

fn task_id() -> TaskId {
    TaskId::new("task-1").unwrap()
}

fn digest(character: char) -> Sha256Digest {
    Sha256Digest::new(format!("sha256:{}", character.to_string().repeat(64))).unwrap()
}
