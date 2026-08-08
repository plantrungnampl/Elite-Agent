use std::collections::{BTreeMap, BTreeSet};
use std::sync::{mpsc, Arc, Condvar, Mutex};
use std::time::Duration;

use local_agent_terminal_application::{
    AuthorizedToolExecutionClaim, AuthorizedToolRequest, CancellationReceipt, DeniedToolExecution,
    DisclosureOutcome, DurableToolExecutionArtifact, DurableToolExecutionArtifacts,
    DurableToolExecutionReceipt, FileReadRequest, FileWriteRequest, GitDiffRequest, GitDiffResult,
    GitStatusRequest, GitStatusResult, ImmutableToolRequest, IncompleteToolExecution,
    NewToolExecution, NewToolIntent, OperationIntentSnapshot, PolicyBoundBytes, PortError,
    ProcessStatus, Retryability, SafeErrorClassification, StartupStateDto, StructuredToolExecutor,
    ToolAuthorityResolver, ToolAuthoritySnapshot, ToolControlSelfTest,
    ToolExecutionCancellationClaim, ToolExecutionClaim, ToolExecutionClaimAuthority,
    ToolExecutionDenialRequest, ToolExecutionId, ToolExecutionOutput, ToolExecutionResolution,
    ToolExecutionResult, ToolExecutionStore, ToolExecutionTerminal, ToolExecutionTerminalKind,
    ToolRequest, VerifiedWrite,
};
use local_agent_terminal_domain::{ArtifactId, RunId, Sha256Digest};
use tempfile::TempDir;

use crate::agent_runtime::failing_runtime_for_test;
use crate::startup::{Bootstrap, StartupConfig};

use super::{SelfTestingToolExecutor, ToolBrokerConfig, ToolRuntime};

const ALLOW_PROCESS_POLICY: &str =
    r#"{"version":1,"rules":[{"id":"allow-process","effect":"allow","action":"process.exec"}]}"#;

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

fn released_test_tool_runtime() -> Arc<ToolRuntime> {
    let events = Arc::new(Mutex::new(Vec::new()));
    let executions = Arc::new(RecordingExecutionStore::running(
        Vec::new(),
        Arc::clone(&events),
    ));
    let executor = Arc::new(BlockingCancellationExecutor::new(events));
    let execution_port: Arc<dyn ToolExecutionStore> = executions;
    let executor_port: Arc<dyn SelfTestingToolExecutor> = executor;
    let runtime = Arc::new(ToolRuntime::new(execution_port, executor_port));
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
