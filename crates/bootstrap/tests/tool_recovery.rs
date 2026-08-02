use std::collections::BTreeMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use local_agent_terminal_application::{
    ArtifactId, AuthoritativeProcessBinding, AuthoritativeProcessTermination,
    AuthorizedToolExecutionClaim, AuthorizedToolRequest, CancellationReceipt, DeniedToolExecution,
    DisclosureOutcome, DurableToolExecutionReceipt, FileReadRequest, FileWriteRequest,
    GitDiffRequest, GitDiffResult, GitStatusRequest, GitStatusResult, IdempotencyClass,
    ImmutableToolRequest, IncompleteToolExecution, JobReceipt, NewToolExecution, NewToolIntent,
    OperationIntentSnapshot, PolicyBoundBytes, PortError, ProcessStatus, RetainedProcessController,
    Retryability, SafeErrorClassification, StructuredToolExecutor, ToolControlSelfTest,
    ToolExecutionCancellationClaim, ToolExecutionClaim, ToolExecutionClaimAuthority,
    ToolExecutionDenialRequest, ToolExecutionId, ToolExecutionRecoveryEvidence,
    ToolExecutionRecoveryState, ToolExecutionResolution, ToolExecutionResult, ToolExecutionStore,
    ToolExecutionTerminalKind, VerifiedWrite,
};
use local_agent_terminal_bootstrap::{
    ToolControlSelfTestStatus, ToolRuntime, ToolRuntimeAvailability,
};
use local_agent_terminal_domain::{RunId, Sha256Digest, TaskId};

#[test]
fn startup_recovery_interrupts_unstarted_claim_before_dispatch_release() {
    let evidence = recovery_evidence("execution-claimed", ToolExecutionRecoveryState::Claimed);
    let store = Arc::new(RecoveryExecutionStore::new(vec![
        IncompleteToolExecution::InFlight(evidence.clone()),
    ]));
    let executor = Arc::new(RecoveryExecutor::default());
    let runtime = runtime(store.clone(), executor.clone());

    assert_eq!(
        runtime.availability().unwrap(),
        ToolRuntimeAvailability::Unavailable
    );
    assert!(runtime.release_dispatch().is_err());

    let report = runtime.recover_startup().unwrap();

    assert_eq!(
        report.control_self_test,
        ToolControlSelfTestStatus::NotConfigured
    );
    assert_eq!(report.recovered, 1);
    assert_eq!(report.interrupted, 1);
    assert_eq!(report.indeterminate, 0);
    assert_eq!(report.terminated_retained_jobs, 0);
    assert_eq!(report.survivor_inspection_failures, 0);
    assert_eq!(
        runtime.availability().unwrap(),
        ToolRuntimeAvailability::Unavailable
    );
    assert!(runtime.release_dispatch().is_err());
    assert_eq!(executor.execute_calls(), 0);
    assert!(executor.terminated_bindings().is_empty());
    assert_eq!(
        store
            .terminal(evidence.authority.execution_id())
            .unwrap()
            .terminal()
            .kind(),
        ToolExecutionTerminalKind::Interrupted
    );
}

#[test]
fn startup_recovery_terminates_exact_retained_job_and_never_relaunches() {
    let mut evidence = recovery_evidence("execution-started", ToolExecutionRecoveryState::Started);
    let binding =
        AuthoritativeProcessBinding::new(evidence.authority.clone(), 4_242, "job-started").unwrap();
    evidence.process_binding = Some(binding.clone());
    let store = Arc::new(RecoveryExecutionStore::new(vec![
        IncompleteToolExecution::InFlight(evidence.clone()),
    ]));
    let cancellation = cancellation_receipt(&binding);
    let executor = Arc::new(RecoveryExecutor::with_cancellation(
        binding.authority().execution_id().clone(),
        cancellation.clone(),
    ));
    let runtime = runtime(store.clone(), executor.clone());

    let first = runtime.recover_startup().unwrap();
    let second = runtime.recover_startup().unwrap();

    assert_eq!(first, second);
    assert_eq!(
        first.control_self_test,
        ToolControlSelfTestStatus::NotConfigured
    );
    assert_eq!(first.recovered, 1);
    assert_eq!(first.interrupted, 0);
    assert_eq!(first.indeterminate, 1);
    assert_eq!(first.terminated_retained_jobs, 1);
    assert_eq!(first.survivor_inspection_failures, 0);
    assert_eq!(
        runtime.availability().unwrap(),
        ToolRuntimeAvailability::Unavailable
    );
    assert!(runtime.release_dispatch().is_err());
    assert_eq!(executor.execute_calls(), 0);
    assert_eq!(executor.terminated_bindings(), vec![binding.clone()]);
    assert_eq!(store.incomplete_calls(), 1);
    assert_eq!(store.resolution_count(), 1);
    let terminal = store.terminal(evidence.authority.execution_id()).unwrap();
    assert_eq!(
        terminal.terminal().kind(),
        ToolExecutionTerminalKind::Indeterminate
    );
    assert_eq!(
        terminal.process_termination(),
        Some(
            &AuthoritativeProcessTermination::new(binding, cancellation)
                .expect("the retained-process receipt is authoritative")
        )
    );
}

#[test]
fn survivor_inspection_terminates_jobs_before_intent_reconciliation() {
    let mut evidence = recovery_evidence(
        "execution-phased-recovery",
        ToolExecutionRecoveryState::Started,
    );
    let binding =
        AuthoritativeProcessBinding::new(evidence.authority.clone(), 4_242, "job-phased-recovery")
            .unwrap();
    evidence.process_binding = Some(binding.clone());
    let store = Arc::new(RecoveryExecutionStore::new(vec![
        IncompleteToolExecution::InFlight(evidence),
    ]));
    let executor = Arc::new(RecoveryExecutor::with_cancellation(
        binding.authority().execution_id().clone(),
        cancellation_receipt(&binding),
    ));
    let runtime = runtime(store.clone(), executor.clone());

    let inspected = runtime.inspect_survivors().unwrap();

    assert_eq!(inspected.terminated_retained_jobs, 1);
    assert_eq!(executor.terminated_bindings(), vec![binding]);
    assert_eq!(store.resolution_count(), 0);
    assert_eq!(
        runtime.availability().unwrap(),
        ToolRuntimeAvailability::Unavailable
    );

    let reconciled = runtime.reconcile_intents().unwrap();

    assert_eq!(reconciled.recovered, 1);
    assert_eq!(store.resolution_count(), 1);
}

#[test]
fn startup_recovery_fails_closed_on_untrusted_survivor_receipt() {
    let mut evidence = recovery_evidence("execution-mismatch", ToolExecutionRecoveryState::Started);
    let binding =
        AuthoritativeProcessBinding::new(evidence.authority.clone(), 4_242, "job-expected")
            .unwrap();
    evidence.process_binding = Some(binding.clone());
    let mut mismatched = cancellation_receipt(&binding);
    mismatched.job_receipt.as_mut().unwrap().job_id = "job-other".to_owned();
    let store = Arc::new(RecoveryExecutionStore::new(vec![
        IncompleteToolExecution::InFlight(evidence.clone()),
    ]));
    let executor = Arc::new(RecoveryExecutor::with_cancellation(
        binding.authority().execution_id().clone(),
        mismatched,
    ));
    let runtime = runtime(store.clone(), executor.clone());

    let report = runtime.recover_startup().unwrap();

    assert_eq!(report.recovered, 0);
    assert_eq!(report.indeterminate, 1);
    assert_eq!(report.terminated_retained_jobs, 0);
    assert_eq!(report.survivor_inspection_failures, 1);
    assert_eq!(
        runtime.availability().unwrap(),
        ToolRuntimeAvailability::Unavailable
    );
    assert!(runtime.release_dispatch().is_err());
    assert_eq!(executor.execute_calls(), 0);
    assert_eq!(executor.terminated_bindings(), vec![binding]);
    assert_eq!(store.resolution_count(), 0);
    assert!(store.terminal(evidence.authority.execution_id()).is_none());
}

#[test]
fn startup_recovery_retains_started_execution_without_process_binding() {
    let evidence = recovery_evidence("execution-unbound", ToolExecutionRecoveryState::Started);
    let store = Arc::new(RecoveryExecutionStore::new(vec![
        IncompleteToolExecution::InFlight(evidence.clone()),
    ]));
    let executor = Arc::new(RecoveryExecutor::default());
    let runtime = runtime(store.clone(), executor.clone());

    let report = runtime.recover_startup().unwrap();

    assert_eq!(report.recovered, 0);
    assert_eq!(report.indeterminate, 1);
    assert_eq!(report.terminated_retained_jobs, 0);
    assert_eq!(report.survivor_inspection_failures, 1);
    assert_eq!(
        runtime.availability().unwrap(),
        ToolRuntimeAvailability::Unavailable
    );
    assert!(runtime.release_dispatch().is_err());
    assert_eq!(executor.execute_calls(), 0);
    assert!(executor.terminated_bindings().is_empty());
    assert_eq!(store.resolution_count(), 0);
    assert!(store.terminal(evidence.authority.execution_id()).is_none());
}

#[test]
fn recovery_only_runtime_never_opens_dispatch_without_a_configured_broker() {
    let evidence = recovery_evidence(
        "execution-control-self-test",
        ToolExecutionRecoveryState::Claimed,
    );
    let store = Arc::new(RecoveryExecutionStore::new(vec![
        IncompleteToolExecution::InFlight(evidence.clone()),
    ]));
    let executor = Arc::new(RecoveryExecutor::with_control_failure());
    let runtime = runtime(store.clone(), executor.clone());

    let first = runtime.recover_startup().unwrap();
    let second = runtime.recover_startup().unwrap();

    assert_eq!(first, second);
    assert_eq!(
        first.control_self_test,
        ToolControlSelfTestStatus::NotConfigured
    );
    assert_eq!(first.recovered, 1);
    assert_eq!(executor.control_self_test_calls(), 0);
    assert_eq!(store.incomplete_calls(), 1);
    assert_eq!(
        store
            .terminal(evidence.authority.execution_id())
            .unwrap()
            .terminal()
            .kind(),
        ToolExecutionTerminalKind::Interrupted
    );
    assert_eq!(
        runtime.availability().unwrap(),
        ToolRuntimeAvailability::Unavailable
    );
    assert!(runtime.release_dispatch().is_err());
    assert_eq!(executor.execute_calls(), 0);
}

fn runtime(store: Arc<RecoveryExecutionStore>, executor: Arc<RecoveryExecutor>) -> ToolRuntime {
    let execution_port: Arc<dyn ToolExecutionStore> = store;
    let retained_processes: Arc<dyn RetainedProcessController> = executor;
    ToolRuntime::recovery_only(execution_port, retained_processes)
}

struct RecoveryExecutionStore {
    incomplete: Vec<IncompleteToolExecution>,
    incomplete_calls: AtomicUsize,
    resolutions: Mutex<BTreeMap<ToolExecutionId, DurableToolExecutionReceipt>>,
}

impl RecoveryExecutionStore {
    fn new(incomplete: Vec<IncompleteToolExecution>) -> Self {
        Self {
            incomplete,
            incomplete_calls: AtomicUsize::new(0),
            resolutions: Mutex::new(BTreeMap::new()),
        }
    }

    fn terminal(&self, execution_id: &ToolExecutionId) -> Option<DurableToolExecutionReceipt> {
        self.resolutions.lock().unwrap().get(execution_id).cloned()
    }

    fn incomplete_calls(&self) -> usize {
        self.incomplete_calls.load(Ordering::SeqCst)
    }

    fn resolution_count(&self) -> usize {
        self.resolutions.lock().unwrap().len()
    }
}

impl ToolExecutionStore for RecoveryExecutionStore {
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
        _: &ToolExecutionId,
    ) -> Result<ToolExecutionCancellationClaim, PortError> {
        unreachable!()
    }

    fn resolve_terminal(
        &self,
        resolution: ToolExecutionResolution,
    ) -> Result<DurableToolExecutionReceipt, PortError> {
        let execution_id = resolution.authority().execution_id().clone();
        let mut resolutions = self.resolutions.lock().unwrap();
        if let Some(existing) = resolutions.get(&execution_id) {
            return (existing == resolution.receipt())
                .then(|| existing.clone())
                .ok_or_else(conflict);
        }
        let receipt = resolution.into_receipt();
        resolutions.insert(execution_id, receipt.clone());
        Ok(receipt)
    }

    fn incomplete(&self) -> Result<Vec<IncompleteToolExecution>, PortError> {
        self.incomplete_calls.fetch_add(1, Ordering::SeqCst);
        Ok(self.incomplete.clone())
    }
}

#[derive(Default)]
struct RecoveryExecutor {
    cancellations: Mutex<BTreeMap<ToolExecutionId, CancellationReceipt>>,
    terminated_bindings: Mutex<Vec<AuthoritativeProcessBinding>>,
    execute_calls: AtomicUsize,
    control_self_test_calls: AtomicUsize,
    control_failure: bool,
}

impl RecoveryExecutor {
    fn with_cancellation(execution_id: ToolExecutionId, receipt: CancellationReceipt) -> Self {
        Self {
            cancellations: Mutex::new(BTreeMap::from([(execution_id, receipt)])),
            terminated_bindings: Mutex::new(Vec::new()),
            execute_calls: AtomicUsize::new(0),
            control_self_test_calls: AtomicUsize::new(0),
            control_failure: false,
        }
    }

    fn with_control_failure() -> Self {
        Self {
            control_failure: true,
            ..Self::default()
        }
    }

    fn execute_calls(&self) -> usize {
        self.execute_calls.load(Ordering::SeqCst)
    }

    fn terminated_bindings(&self) -> Vec<AuthoritativeProcessBinding> {
        self.terminated_bindings.lock().unwrap().clone()
    }

    fn control_self_test_calls(&self) -> usize {
        self.control_self_test_calls.load(Ordering::SeqCst)
    }

    fn terminate_binding(
        &self,
        binding: &AuthoritativeProcessBinding,
    ) -> Result<CancellationReceipt, PortError> {
        self.terminated_bindings
            .lock()
            .unwrap()
            .push(binding.clone());
        self.cancellations
            .lock()
            .unwrap()
            .remove(binding.authority().execution_id())
            .ok_or_else(unavailable)
    }
}

impl ToolControlSelfTest for RecoveryExecutor {
    fn verify_controls(&self) -> Result<(), PortError> {
        self.control_self_test_calls.fetch_add(1, Ordering::SeqCst);
        (!self.control_failure)
            .then_some(())
            .ok_or_else(unavailable)
    }
}

impl StructuredToolExecutor for RecoveryExecutor {
    fn execute(&self, _: AuthorizedToolRequest) -> Result<ToolExecutionResult, PortError> {
        self.execute_calls.fetch_add(1, Ordering::SeqCst);
        unreachable!("startup recovery must never relaunch an incomplete tool")
    }

    fn cancel(&self, _: &ToolExecutionId) -> Result<CancellationReceipt, PortError> {
        unreachable!("startup recovery must use the exact persisted process binding")
    }

    fn terminate_retained_process(
        &self,
        binding: &AuthoritativeProcessBinding,
    ) -> Result<CancellationReceipt, PortError> {
        self.terminate_binding(binding)
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

impl RetainedProcessController for RecoveryExecutor {
    fn terminate_retained_process(
        &self,
        binding: &AuthoritativeProcessBinding,
    ) -> Result<CancellationReceipt, PortError> {
        self.terminate_binding(binding)
    }
}

fn recovery_evidence(
    execution_id: &str,
    state: ToolExecutionRecoveryState,
) -> ToolExecutionRecoveryEvidence {
    ToolExecutionRecoveryEvidence {
        authority: ToolExecutionClaimAuthority::from_persisted(
            ToolExecutionId::new(execution_id).unwrap(),
            digest('a'),
            RunId::new("run-recovery").unwrap(),
            1,
            None,
        )
        .unwrap(),
        task_id: TaskId::new("task-recovery").unwrap(),
        canonical_request_artifact_id: ArtifactId::new("artifact-recovery").unwrap(),
        idempotency_class: IdempotencyClass::NonRepeatable,
        state,
        process_binding: None,
    }
}

fn cancellation_receipt(binding: &AuthoritativeProcessBinding) -> CancellationReceipt {
    CancellationReceipt {
        execution_id: binding.authority().execution_id().clone(),
        status: ProcessStatus::Terminated,
        job_receipt: Some(JobReceipt {
            root_pid: binding.root_pid(),
            job_id: binding.job_id().to_owned(),
            kill_on_close: true,
            no_breakaway: true,
            job_memory_limit: true,
            job_cpu_time_limit: true,
            memory_limit_bytes: 1,
            cpu_time_limit_ms: 1,
            max_active_processes: 1,
            total_user_time_ms: 1,
            resource_limit_terminated: false,
            tree_terminated: true,
        }),
        cancelled: true,
    }
}

fn digest(ch: char) -> Sha256Digest {
    Sha256Digest::new(format!("sha256:{}", ch.to_string().repeat(64))).unwrap()
}

fn conflict() -> PortError {
    PortError::failure(
        SafeErrorClassification::Conflict,
        Retryability::NonRetryable,
    )
}

fn unavailable() -> PortError {
    PortError::failure(
        SafeErrorClassification::Unavailable,
        Retryability::NonRetryable,
    )
}
