use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{mpsc, Arc, Condvar, Mutex};
use std::time::Duration;

use local_agent_terminal_application::{
    ApprovedExecutableIdentity, ApprovedProcessRequest, AuthoritativeProcessBinding,
    AuthorizedToolExecutionClaim, AuthorizedToolRequest, CancellationReceipt, DeniedToolExecution,
    DisclosureOutcome, DurableToolExecutionArtifact, DurableToolExecutionArtifacts,
    DurableToolExecutionReceipt, FileReadRequest, FileWriteRequest, GitDiffRequest, GitDiffResult,
    GitStatusRequest, GitStatusResult, ImmutableToolRequest, IncompleteToolExecution,
    NewToolExecution, NewToolIntent, OperationIntentSnapshot, PolicyBoundBytes, PortError,
    ProcessExecutionBindingStore, ProcessStatus, ResolveToolApprovalRequestDto, ResolvedExecutable,
    Retryability, SafeErrorClassification, StartupStateDto, StructuredToolExecutor,
    ToolActivityStatusDto, ToolApprovalDecisionDto, ToolAuthorityResolver, ToolAuthoritySnapshot,
    ToolControlSelfTest, ToolExecutionCancellationClaim, ToolExecutionClaim,
    ToolExecutionClaimAuthority, ToolExecutionDenialRequest, ToolExecutionId, ToolExecutionOutput,
    ToolExecutionResolution, ToolExecutionResult, ToolExecutionStore, ToolExecutionTerminal,
    ToolExecutionTerminalKind, ToolPolicyContext, ToolRequest, VerifiedWrite,
};
use local_agent_terminal_domain::{
    ActorLocality, ArtifactId, CapabilityRef, EnvironmentProfile, NetworkProfile, Phase,
    PlanStepId, PolicyAction, PolicyActor, PolicyResource, ProcessBinding, ProcessInvocation,
    ProcessToolRequest, ProcessTrustTier, ResourceClass, RunId, Sha256Digest, TaskId, TaskRisk,
    TrustTier, WorkspaceVersion,
};
use local_agent_terminal_policy_engine::VersionedPolicyEngine;
use local_agent_terminal_storage_sqlite::SqliteStore;
use tempfile::TempDir;

use crate::agent_runtime::failing_runtime_for_test;
use crate::startup::{Bootstrap, StartupConfig};

#[allow(dead_code)]
mod support {
    use crate as local_agent_terminal_bootstrap;

    include!("../tests/support/mod.rs");
}

use super::{ApprovalResolutionCheckpoint, SelfTestingToolExecutor, ToolBrokerConfig, ToolRuntime};

const ALLOW_PROCESS_POLICY: &str =
    r#"{"version":1,"rules":[{"id":"allow-process","effect":"allow","action":"process.exec"}]}"#;
const APPROVE_PROCESS_POLICY: &str = r#"{"version":1,"rules":[{"id":"approve-process","effect":"require_approval","action":"process.exec"},{"id":"redact-tool-display","effect":"allow_with_redaction","action":"tool.approval.display","redactions":["secret_scanner"]}]}"#;
const EMPTY_BYTES_HASH: &str =
    "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

#[test]
fn configured_startup_exposes_ready_before_releasing_dispatch() {
    let root = TempDir::new().unwrap();
    let events = Arc::new(Mutex::new(Vec::new()));
    let executor: Arc<dyn SelfTestingToolExecutor> =
        Arc::new(BlockingCancellationExecutor::new(events));
    let bootstrap = Bootstrap::with_tool_broker(
        startup_config(&root),
        ToolBrokerConfig::new(ALLOW_PROCESS_POLICY, Arc::new(UnusedAuthority), executor),
    );

    assert_eq!(bootstrap.status().state, StartupStateDto::Ready);
    assert!(bootstrap.workspace_runtime().is_some());
    assert!(bootstrap.tool_runtime().is_some());
    let codes = bootstrap
        .local_diagnostics()
        .iter()
        .map(|record| record.code.as_str())
        .collect::<Vec<_>>();
    let ready = codes
        .iter()
        .position(|code| *code == "startup.ready")
        .unwrap();
    let released = codes
        .iter()
        .position(|code| *code == "startup.tools.dispatch_released")
        .unwrap();
    assert!(ready < released);

    assert_eq!(
        bootstrap
            .tool_runtime()
            .unwrap()
            .recover_startup()
            .unwrap_err()
            .safe_classification(),
        SafeErrorClassification::Conflict,
    );
}

#[test]
fn configured_startup_keeps_unavailable_dispatch_closed_without_failing_startup() {
    let root = TempDir::new().unwrap();
    let events = Arc::new(Mutex::new(Vec::new()));
    let executor: Arc<dyn SelfTestingToolExecutor> = Arc::new(
        BlockingCancellationExecutor::with_unavailable_controls(events),
    );
    let bootstrap = Bootstrap::with_tool_broker(
        startup_config(&root),
        ToolBrokerConfig::new(ALLOW_PROCESS_POLICY, Arc::new(UnusedAuthority), executor),
    );

    assert_eq!(bootstrap.status().state, StartupStateDto::Ready);
    let runtime = bootstrap.tool_runtime().unwrap();
    assert_eq!(
        runtime.availability().unwrap(),
        super::ToolRuntimeAvailability::Unavailable
    );
    assert!(runtime.recover_startup().is_ok());
    assert!(!bootstrap
        .local_diagnostics()
        .iter()
        .any(|record| record.code == "startup.tools.dispatch_released"));
}

#[test]
fn retry_closes_retained_tool_dispatch_after_agent_shutdown_failure() {
    let root = TempDir::new().unwrap();
    let tool_runtime = released_test_tool_runtime();
    let mut bootstrap = Bootstrap::with_runtimes_for_test(
        startup_config(&root),
        Some(failing_runtime_for_test(root.path())),
        Some(Arc::clone(&tool_runtime)),
    );
    let stale_tool_runtime = bootstrap.tool_runtime_handle().unwrap();

    assert_eq!(
        bootstrap.retry_startup_validation().state,
        StartupStateDto::RecoverableFailure
    );
    assert_eq!(
        bootstrap.status().issues[0].code,
        "startup.agent_runtime_shutdown_failed"
    );

    assert_stale_dispatch_is_closed(&stale_tool_runtime, "execution-retry-agent-failure-gate");
    assert!(bootstrap.agent_runtime_handle().is_some());
    assert!(bootstrap.tool_runtime_handle().is_none());
    assert_eq!(
        bootstrap.retry_startup_validation().state,
        StartupStateDto::RecoverableFailure
    );
    assert_eq!(
        bootstrap.status().issues[0].code,
        "startup.agent_runtime_shutdown_failed"
    );
    assert!(bootstrap.agent_runtime_handle().is_some());
}

#[test]
fn retry_retains_failed_tool_runtime_after_agent_shutdown_failure() {
    let root = TempDir::new().unwrap();
    let tool_runtime = released_test_tool_runtime();
    let execution_id = ToolExecutionId::new("execution-retry-tool-failure").unwrap();
    let (worker_started_tx, worker_started_rx) = mpsc::channel();
    tool_runtime
        .dispatch_test_worker(execution_id, move || {
            worker_started_tx.send(()).unwrap();
            Err(unavailable())
        })
        .unwrap();
    worker_started_rx
        .recv_timeout(Duration::from_secs(1))
        .unwrap();

    let mut bootstrap = Bootstrap::with_runtimes_for_test(
        startup_config(&root),
        Some(failing_runtime_for_test(root.path())),
        Some(Arc::clone(&tool_runtime)),
    );
    let stale_tool_runtime = bootstrap.tool_runtime_handle().unwrap();

    assert_eq!(
        bootstrap.retry_startup_validation().state,
        StartupStateDto::RecoverableFailure
    );
    assert_eq!(
        bootstrap.status().issues[0].code,
        "startup.agent_runtime_shutdown_failed"
    );
    assert!(bootstrap.agent_runtime_handle().is_some());
    assert!(bootstrap.tool_runtime_handle().is_some());

    assert_stale_dispatch_is_closed(&stale_tool_runtime, "execution-retry-tool-failure-gate");
    assert_eq!(
        bootstrap.retry_startup_validation().state,
        StartupStateDto::RecoverableFailure
    );
    assert_eq!(
        bootstrap.status().issues[0].code,
        "startup.agent_runtime_shutdown_failed"
    );
    assert!(bootstrap.agent_runtime_handle().is_some());
    assert!(bootstrap.tool_runtime_handle().is_some());
    assert_eq!(stale_tool_runtime.stop_all(), Err(not_found()));
}

#[test]
fn drop_closes_tool_dispatch_after_agent_shutdown_failure() {
    let root = TempDir::new().unwrap();
    let tool_runtime = released_test_tool_runtime();
    let stale_tool_runtime = Arc::clone(&tool_runtime);

    drop(Bootstrap::with_runtimes_for_test(
        startup_config(&root),
        Some(failing_runtime_for_test(root.path())),
        Some(tool_runtime),
    ));

    assert_stale_dispatch_is_closed(&stale_tool_runtime, "execution-drop-agent-failure");
}

#[test]
fn stop_all_replays_a_failed_shutdown_result() {
    let runtime = released_test_tool_runtime();
    let execution_id = ToolExecutionId::new("execution-stop-repeat-failure").unwrap();
    let (worker_started_tx, worker_started_rx) = mpsc::channel();
    runtime
        .dispatch_test_worker(execution_id, move || {
            worker_started_tx.send(()).unwrap();
            Err(unavailable())
        })
        .unwrap();
    worker_started_rx
        .recv_timeout(Duration::from_secs(1))
        .unwrap();

    let first = runtime.stop_all();

    assert_eq!(first, Err(not_found()));
    assert_eq!(runtime.stop_all(), first);
}

#[test]
fn stop_all_before_startup_recovery_makes_runtime_terminal() {
    let runtime = unrecovered_test_tool_runtime();

    let first = runtime.stop_all();
    let recovery = runtime.recover_startup();
    let release = runtime.release_dispatch();
    let authority = cancellation_authority("execution-terminal-before-recovery");
    let (worker_done_tx, worker_done_rx) = mpsc::channel();
    let dispatch = runtime.dispatch_test_worker(authority.execution_id().clone(), move || {
        worker_done_tx.send(()).unwrap();
        Ok(terminated_receipt(authority))
    });
    if dispatch.is_ok() {
        worker_done_rx.recv_timeout(Duration::from_secs(1)).unwrap();
    }
    let availability = runtime.availability();
    let repeated = runtime.stop_all();

    assert_eq!(first, Ok(Vec::new()));
    assert_eq!(
        recovery.err().map(|error| error.safe_classification()),
        Some(SafeErrorClassification::Conflict),
    );
    assert_eq!(
        release.err().map(|error| error.safe_classification()),
        Some(SafeErrorClassification::Conflict),
    );
    assert_eq!(
        availability,
        Ok(super::ToolRuntimeAvailability::Unavailable)
    );
    assert_eq!(
        dispatch.err().map(|error| error.safe_classification()),
        Some(SafeErrorClassification::Conflict),
    );
    assert_eq!(repeated, first);
}

#[test]
fn shutdown_after_survivor_inspection_blocks_recovery_and_dispatch() {
    let runtime = unrecovered_test_tool_runtime();

    runtime.inspect_survivors().unwrap();
    let first = runtime.stop_all();
    let file_writes = runtime.recover_file_writes();
    let reconciliation = runtime.reconcile_intents();
    let release = runtime.release_dispatch();
    let authority = cancellation_authority("execution-terminal-after-inspection");
    let (worker_done_tx, worker_done_rx) = mpsc::channel();
    let dispatch = runtime.dispatch_test_worker(authority.execution_id().clone(), move || {
        worker_done_tx.send(()).unwrap();
        Ok(terminated_receipt(authority))
    });
    if dispatch.is_ok() {
        worker_done_rx.recv_timeout(Duration::from_secs(1)).unwrap();
    }
    let availability = runtime.availability();

    assert_eq!(first, Ok(Vec::new()));
    assert_eq!(
        file_writes.err().map(|error| error.safe_classification()),
        Some(SafeErrorClassification::Conflict),
    );
    assert_eq!(
        reconciliation
            .err()
            .map(|error| error.safe_classification()),
        Some(SafeErrorClassification::Conflict),
    );
    assert_eq!(
        release.err().map(|error| error.safe_classification()),
        Some(SafeErrorClassification::Conflict),
    );
    assert_eq!(
        availability,
        Ok(super::ToolRuntimeAvailability::Unavailable)
    );
    assert_eq!(
        dispatch.err().map(|error| error.safe_classification()),
        Some(SafeErrorClassification::Conflict),
    );
}

#[test]
fn retry_retains_failed_tool_runtime_without_an_agent_runtime() {
    let root = TempDir::new().unwrap();
    let tool_runtime = released_test_tool_runtime();
    let execution_id = ToolExecutionId::new("execution-retry-tool-only-failure").unwrap();
    let (worker_started_tx, worker_started_rx) = mpsc::channel();
    tool_runtime
        .dispatch_test_worker(execution_id, move || {
            worker_started_tx.send(()).unwrap();
            Err(unavailable())
        })
        .unwrap();
    worker_started_rx
        .recv_timeout(Duration::from_secs(1))
        .unwrap();

    let mut bootstrap = Bootstrap::with_runtimes_for_test(
        startup_config(&root),
        None,
        Some(Arc::clone(&tool_runtime)),
    );
    let stale_tool_runtime = bootstrap.tool_runtime_handle().unwrap();

    for _ in 0..2 {
        assert_eq!(
            bootstrap.retry_startup_validation().state,
            StartupStateDto::Indeterminate
        );
        assert_eq!(
            bootstrap.status().issues[0].code,
            "startup.tool_recovery_failed"
        );
        assert!(bootstrap.agent_runtime_handle().is_none());
        assert!(bootstrap.tool_runtime_handle().is_some());
    }
    assert_eq!(stale_tool_runtime.stop_all(), Err(not_found()));
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
    let executor_port: Arc<dyn SelfTestingToolExecutor> = executor.clone();
    let runtime = ToolRuntime::new(execution_port, executor_port);
    runtime.recover_startup().unwrap();
    runtime.release_dispatch().unwrap();

    for authority in authorities.clone() {
        let execution_id = authority.execution_id().clone();
        let waiting_executor = Arc::clone(&executor);
        runtime
            .dispatch_test_worker(execution_id.clone(), move || {
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
        .dispatch_test_worker(
            ToolExecutionId::new("execution-too-late").unwrap(),
            || unreachable!("closed dispatch must not start a worker"),
        )
        .is_err());
    assert_eq!(runtime.stop_all().unwrap(), receipts);
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
    let executor_port: Arc<dyn SelfTestingToolExecutor> = executor.clone();
    let runtime = ToolRuntime::new(execution_port, executor_port);
    runtime.recover_startup().unwrap();
    runtime.release_dispatch().unwrap();
    let execution_id = authority.execution_id().clone();
    runtime
        .dispatch_test_worker(execution_id.clone(), || {
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
    let executor_port: Arc<dyn SelfTestingToolExecutor> = executor.clone();
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
        .dispatch_test_worker(execution_id, move || {
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
    let first_result = first.join().unwrap();
    let second_result = second_rx.recv_timeout(Duration::from_secs(5)).unwrap();
    assert_eq!(first_result, second_result);
    assert_eq!(first_result.unwrap().len(), 1);
    second.join().unwrap();
    assert_eq!(executor.cancel_count(authority.execution_id()), 1);
}

#[test]
fn shutdown_wins_approval_resolution_without_mutating_the_pending_approval() {
    let fixture = support::WorkspaceFixture::new();
    fixture.seed_present_workspace();
    let executor = Arc::new(BlockingApprovalExecutor::new(
        SqliteStore::open(&fixture.database_path).unwrap(),
    ));
    let bootstrap = approval_test_bootstrap(&fixture, Arc::clone(&executor));
    let runtime = bootstrap.tool_runtime_handle().unwrap();
    let policy = VersionedPolicyEngine::from_json(APPROVE_PROCESS_POLICY).unwrap();
    let local_agent_terminal_application::ToolOutcome::ApprovalRequired(approval) = runtime
        .execute(approval_test_request(
            "execution-approval-shutdown-wins",
            policy.snapshot_digest().clone(),
        ))
        .unwrap()
    else {
        panic!("approval policy must publish a pending approval");
    };
    let barrier = Arc::new(ApprovalResolutionBarrier::new(
        ApprovalResolutionCheckpoint::BeforeAdmission,
    ));
    let hook_barrier = Arc::clone(&barrier);
    runtime.set_approval_resolution_checkpoint(Arc::new(move |checkpoint| {
        hook_barrier.reach(checkpoint);
    }));
    let resolution_request = ResolveToolApprovalRequestDto {
        approval_id: approval.approval_id.clone(),
        expected_operation_digest: approval.operation_digest,
        decision: ToolApprovalDecisionDto::Approve,
    };
    let resolving_runtime = Arc::clone(&runtime);
    let resolution =
        std::thread::spawn(move || resolving_runtime.resolve_approval(resolution_request));

    barrier.wait_until(ApprovalResolutionCheckpoint::BeforeAdmission);
    let shutdown = runtime.stop_all().unwrap();
    barrier.release();
    let error = resolution.join().unwrap().unwrap_err();

    assert!(shutdown.is_empty());
    assert_eq!(
        error.safe_classification(),
        SafeErrorClassification::Conflict
    );
    assert_eq!(
        runtime.activity().unwrap().entries[0].status,
        ToolActivityStatusDto::ApprovalRequired
    );
    assert_eq!(executor.execute_calls.load(Ordering::SeqCst), 0);
}

#[test]
fn failed_approval_worker_admission_preserves_pending_approval() {
    let fixture = support::WorkspaceFixture::new();
    fixture.seed_present_workspace();
    let executor = Arc::new(BlockingApprovalExecutor::new(
        SqliteStore::open(&fixture.database_path).unwrap(),
    ));
    let bootstrap = approval_test_bootstrap(&fixture, Arc::clone(&executor));
    let runtime = bootstrap.tool_runtime_handle().unwrap();
    let policy = VersionedPolicyEngine::from_json(APPROVE_PROCESS_POLICY).unwrap();
    let execution_id = ToolExecutionId::new("execution-approval-admission-failure").unwrap();
    let local_agent_terminal_application::ToolOutcome::ApprovalRequired(approval) = runtime
        .execute(approval_test_request(
            execution_id.as_str(),
            policy.snapshot_digest().clone(),
        ))
        .unwrap()
    else {
        panic!("approval policy must publish a pending approval");
    };
    runtime.fail_next_approved_worker_start(unavailable());

    let error = runtime
        .resolve_approval(ResolveToolApprovalRequestDto {
            approval_id: approval.approval_id,
            expected_operation_digest: approval.operation_digest,
            decision: ToolApprovalDecisionDto::Approve,
        })
        .unwrap_err();

    assert_eq!(
        error.safe_classification(),
        SafeErrorClassification::Unavailable
    );
    assert_eq!(
        runtime.activity().unwrap().entries[0].status,
        ToolActivityStatusDto::ApprovalRequired
    );
    assert!(runtime.state.lock().unwrap().workers.is_empty());
    assert_eq!(executor.execute_calls.load(Ordering::SeqCst), 0);
}

#[test]
fn approval_wins_registers_its_worker_before_shutdown_can_cancel_and_join_it() {
    let fixture = support::WorkspaceFixture::new();
    fixture.seed_present_workspace();
    let executor = Arc::new(BlockingApprovalExecutor::new(
        SqliteStore::open(&fixture.database_path).unwrap(),
    ));
    let bootstrap = approval_test_bootstrap(&fixture, Arc::clone(&executor));
    let runtime = bootstrap.tool_runtime_handle().unwrap();
    let policy = VersionedPolicyEngine::from_json(APPROVE_PROCESS_POLICY).unwrap();
    let execution_id = ToolExecutionId::new("execution-approval-wins").unwrap();
    let local_agent_terminal_application::ToolOutcome::ApprovalRequired(approval) = runtime
        .execute(approval_test_request(
            execution_id.as_str(),
            policy.snapshot_digest().clone(),
        ))
        .unwrap()
    else {
        panic!("approval policy must publish a pending approval");
    };
    let barrier = Arc::new(ApprovalResolutionBarrier::new(
        ApprovalResolutionCheckpoint::WorkerRegistered,
    ));
    let hook_barrier = Arc::clone(&barrier);
    runtime.set_approval_resolution_checkpoint(Arc::new(move |checkpoint| {
        hook_barrier.reach(checkpoint);
    }));
    let resolution_request = ResolveToolApprovalRequestDto {
        approval_id: approval.approval_id,
        expected_operation_digest: approval.operation_digest,
        decision: ToolApprovalDecisionDto::Approve,
    };
    let resolving_runtime = Arc::clone(&runtime);
    let resolution =
        std::thread::spawn(move || resolving_runtime.resolve_approval(resolution_request));

    barrier.wait_until(ApprovalResolutionCheckpoint::WorkerRegistered);
    assert!(runtime
        .state
        .lock()
        .unwrap()
        .workers
        .contains_key(&execution_id));
    executor.wait_until_started();
    assert!(matches!(
        runtime.shutdown.try_lock(),
        Err(std::sync::TryLockError::WouldBlock)
    ));
    let stopping_runtime = Arc::clone(&runtime);
    let (shutdown_tx, shutdown_rx) = mpsc::channel();
    let shutdown = std::thread::spawn(move || {
        shutdown_tx.send(stopping_runtime.stop_all()).unwrap();
    });

    barrier.release();
    let receipts = shutdown_rx
        .recv_timeout(Duration::from_secs(5))
        .unwrap()
        .unwrap();
    let resolved = resolution.join().unwrap().unwrap();
    shutdown.join().unwrap();

    assert_eq!(receipts.len(), 1);
    assert_eq!(resolved.status, ToolActivityStatusDto::Indeterminate);
    assert_eq!(executor.execute_calls.load(Ordering::SeqCst), 1);
    assert_eq!(executor.cancel_calls.load(Ordering::SeqCst), 1);
}

struct ApprovalResolutionBarrier {
    blocking_checkpoint: ApprovalResolutionCheckpoint,
    state: Mutex<ApprovalResolutionBarrierState>,
    changed: Condvar,
}

#[derive(Default)]
struct ApprovalResolutionBarrierState {
    before_admission: bool,
    worker_registered: bool,
    released: bool,
}

impl ApprovalResolutionBarrier {
    fn new(blocking_checkpoint: ApprovalResolutionCheckpoint) -> Self {
        Self {
            blocking_checkpoint,
            state: Mutex::new(ApprovalResolutionBarrierState::default()),
            changed: Condvar::new(),
        }
    }

    fn reach(&self, checkpoint: ApprovalResolutionCheckpoint) {
        let mut state = self.state.lock().unwrap();
        match checkpoint {
            ApprovalResolutionCheckpoint::BeforeAdmission => state.before_admission = true,
            ApprovalResolutionCheckpoint::WorkerRegistered => state.worker_registered = true,
        }
        self.changed.notify_all();
        if checkpoint == self.blocking_checkpoint {
            while !state.released {
                state = self.changed.wait(state).unwrap();
            }
        }
    }

    fn wait_until(&self, checkpoint: ApprovalResolutionCheckpoint) {
        let state = self.state.lock().unwrap();
        let (state, timeout) = self
            .changed
            .wait_timeout_while(state, Duration::from_secs(5), |state| match checkpoint {
                ApprovalResolutionCheckpoint::BeforeAdmission => !state.before_admission,
                ApprovalResolutionCheckpoint::WorkerRegistered => !state.worker_registered,
            })
            .unwrap();
        assert!(!timeout.timed_out());
        match checkpoint {
            ApprovalResolutionCheckpoint::BeforeAdmission => assert!(state.before_admission),
            ApprovalResolutionCheckpoint::WorkerRegistered => assert!(state.worker_registered),
        }
    }

    fn release(&self) {
        self.state.lock().unwrap().released = true;
        self.changed.notify_all();
    }
}

struct ApprovalTestAuthority;

impl ToolAuthorityResolver for ApprovalTestAuthority {
    fn resolve(&self, request: &ToolRequest) -> Result<ToolAuthoritySnapshot, PortError> {
        ToolAuthoritySnapshot::new(request.clone(), b"", None)
    }
}

struct BlockingApprovalExecutor {
    database: SqliteStore,
    execute_calls: AtomicUsize,
    cancel_calls: AtomicUsize,
    state: Mutex<BlockingApprovalExecutorState>,
    changed: Condvar,
}

#[derive(Default)]
struct BlockingApprovalExecutorState {
    started: bool,
    released: bool,
}

impl BlockingApprovalExecutor {
    fn new(database: SqliteStore) -> Self {
        Self {
            database,
            execute_calls: AtomicUsize::new(0),
            cancel_calls: AtomicUsize::new(0),
            state: Mutex::new(BlockingApprovalExecutorState::default()),
            changed: Condvar::new(),
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
}

impl ToolControlSelfTest for BlockingApprovalExecutor {
    fn verify_controls(&self) -> Result<(), PortError> {
        Ok(())
    }
}

impl StructuredToolExecutor for BlockingApprovalExecutor {
    fn execute(&self, request: AuthorizedToolRequest) -> Result<ToolExecutionResult, PortError> {
        self.execute_calls.fetch_add(1, Ordering::SeqCst);
        let authority = self
            .database
            .load_claimed_authority(&request.execution_id)?;
        self.database
            .record_process_binding(AuthoritativeProcessBinding::new(
                authority,
                1,
                "approval-shutdown-test-job",
            )?)?;
        let mut state = self.state.lock().unwrap();
        state.started = true;
        self.changed.notify_all();
        while !state.released {
            state = self.changed.wait(state).unwrap();
        }
        Err(PortError::failure(
            SafeErrorClassification::Unavailable,
            Retryability::NonRetryable,
        ))
    }

    fn cancel(&self, execution_id: &ToolExecutionId) -> Result<CancellationReceipt, PortError> {
        self.cancel_calls.fetch_add(1, Ordering::SeqCst);
        self.state.lock().unwrap().released = true;
        self.changed.notify_all();
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
        unreachable!("approval shutdown tests exercise process execution only")
    }

    fn file_write(&self, _: FileWriteRequest) -> Result<VerifiedWrite, PortError> {
        unreachable!("approval shutdown tests exercise process execution only")
    }

    fn git_status(
        &self,
        _: GitStatusRequest,
    ) -> Result<DisclosureOutcome<GitStatusResult>, PortError> {
        unreachable!("approval shutdown tests exercise process execution only")
    }

    fn git_diff(&self, _: GitDiffRequest) -> Result<DisclosureOutcome<GitDiffResult>, PortError> {
        unreachable!("approval shutdown tests exercise process execution only")
    }
}

fn approval_test_bootstrap(
    fixture: &support::WorkspaceFixture,
    executor: Arc<BlockingApprovalExecutor>,
) -> Bootstrap {
    Bootstrap::with_tool_broker(
        StartupConfig {
            app_data_dir: fixture.app_data.clone(),
            trusted_workspace_root: fixture.workspace_root.clone(),
            secret_values: Vec::new(),
            openai: None,
        },
        ToolBrokerConfig::new(
            APPROVE_PROCESS_POLICY,
            Arc::new(ApprovalTestAuthority),
            executor,
        ),
    )
}

fn approval_test_request(execution_id: &str, policy_snapshot_digest: Sha256Digest) -> ToolRequest {
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
        ToolExecutionId::new(execution_id).unwrap(),
        approved,
        policy,
    )
    .unwrap()
}

#[cfg(windows)]
fn approved_executable_path() -> PathBuf {
    PathBuf::from(r"\\?\C:\approved\cargo.exe")
}

#[cfg(not(windows))]
fn approved_executable_path() -> PathBuf {
    PathBuf::from("/approved/cargo")
}

struct UnusedAuthority;

impl ToolAuthorityResolver for UnusedAuthority {
    fn resolve(&self, _: &ToolRequest) -> Result<ToolAuthoritySnapshot, PortError> {
        unreachable!("startup self-tests do not resolve tool authority")
    }
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
    controls_available: bool,
    cancelled: Mutex<BTreeSet<ToolExecutionId>>,
    cancel_counts: Mutex<BTreeMap<ToolExecutionId, usize>>,
    cancellation: Condvar,
    events: Arc<Mutex<Vec<String>>>,
}

impl BlockingCancellationExecutor {
    fn new(events: Arc<Mutex<Vec<String>>>) -> Self {
        Self {
            controls_available: true,
            cancelled: Mutex::new(BTreeSet::new()),
            cancel_counts: Mutex::new(BTreeMap::new()),
            cancellation: Condvar::new(),
            events,
        }
    }

    fn with_unavailable_controls(events: Arc<Mutex<Vec<String>>>) -> Self {
        let mut executor = Self::new(events);
        executor.controls_available = false;
        executor
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

impl ToolControlSelfTest for BlockingCancellationExecutor {
    fn verify_controls(&self) -> Result<(), PortError> {
        self.controls_available
            .then_some(())
            .ok_or_else(unavailable)
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

fn unavailable() -> PortError {
    PortError::failure(
        SafeErrorClassification::Unavailable,
        Retryability::NonRetryable,
    )
}

fn startup_config(root: &TempDir) -> StartupConfig {
    StartupConfig {
        app_data_dir: root.path().join("app-data"),
        trusted_workspace_root: root.path().join("workspaces"),
        secret_values: Vec::new(),
        openai: None,
    }
}

fn unrecovered_test_tool_runtime() -> Arc<ToolRuntime> {
    let events = Arc::new(Mutex::new(Vec::new()));
    let executions = Arc::new(RecordingExecutionStore::running(
        Vec::new(),
        Arc::clone(&events),
    ));
    let executor = Arc::new(BlockingCancellationExecutor::new(events));
    let execution_port: Arc<dyn ToolExecutionStore> = executions;
    let executor_port: Arc<dyn SelfTestingToolExecutor> = executor;
    Arc::new(ToolRuntime::new(execution_port, executor_port))
}

fn released_test_tool_runtime() -> Arc<ToolRuntime> {
    let runtime = unrecovered_test_tool_runtime();
    runtime.recover_startup().unwrap();
    runtime.release_dispatch().unwrap();
    runtime
}

fn assert_stale_dispatch_is_closed(runtime: &ToolRuntime, execution_id: &str) {
    let authority = cancellation_authority(execution_id);
    let dispatch = runtime.dispatch_test_worker(authority.execution_id().clone(), move || {
        Ok(terminated_receipt(authority))
    });
    if dispatch.is_ok() {
        let _ = runtime.stop_all();
    }
    assert!(dispatch.is_err(), "stale tool dispatch must be closed");
}

fn digest(marker: char) -> Sha256Digest {
    Sha256Digest::new(format!("sha256:{}", marker.to_string().repeat(64))).unwrap()
}
