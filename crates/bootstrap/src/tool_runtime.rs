use std::collections::{BTreeMap, VecDeque};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use local_agent_terminal_application::{
    parse_policy_timestamp, ApprovalId, ApprovalResumeStore, ArtifactId, ArtifactWriteReservation,
    AuthoritativeProcessBinding, AuthoritativeProcessTermination, Clock,
    DurableToolCancellationOutcome, DurableToolExecutionOutcome, DurableToolExecutionReceipt,
    ExecuteTool, IdGenerator, ImmutableToolRequest, IncompleteToolExecution, NewToolIntent,
    OperationIntentSnapshot, PortError, ProcessStatus, ProjectId, ReservedArtifact,
    RetainedProcessController, Retryability, SafeErrorClassification, SafeToolExecutionError,
    StructuredToolExecutor, TaskId, TaskQuery, ToolApprovalPublication, ToolApprovalRequest,
    ToolApprovalRequestPublisher, ToolAuthorityResolver, ToolControlSelfTest,
    ToolExecutionCancellationClaim, ToolExecutionId, ToolExecutionOrchestration,
    ToolExecutionRecoveryState, ToolExecutionResolution, ToolExecutionResumeStore,
    ToolExecutionStore, ToolExecutionTerminal, ToolOutcome, ToolRequest, ToolRequestPublisher,
    WorkspaceEvidenceStore,
};
use local_agent_terminal_policy_engine::VersionedPolicyEngine;
use local_agent_terminal_storage_files::{ContentAddressedArtifactStore, JournaledArtifactWriter};
use local_agent_terminal_storage_sqlite::SqliteStore;

static NEXT_TEMP_FILE: AtomicU64 = AtomicU64::new(0);
static NEXT_RUNTIME_ID: AtomicU64 = AtomicU64::new(0);

type ToolWorkerResult = Result<ToolOutcome, PortError>;

pub trait SelfTestingToolExecutor: StructuredToolExecutor + ToolControlSelfTest {}

impl<T> SelfTestingToolExecutor for T where T: StructuredToolExecutor + ToolControlSelfTest {}

#[derive(Clone)]
pub struct ToolBrokerConfig {
    policy_bundle_json: String,
    authority: Arc<dyn ToolAuthorityResolver>,
    executor: Arc<dyn SelfTestingToolExecutor>,
}

impl ToolBrokerConfig {
    pub fn new(
        policy_bundle_json: impl Into<String>,
        authority: Arc<dyn ToolAuthorityResolver>,
        executor: Arc<dyn SelfTestingToolExecutor>,
    ) -> Self {
        Self {
            policy_bundle_json: policy_bundle_json.into(),
            authority,
            executor,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ToolRuntimeAvailability {
    Ready,
    DegradedReadOnly,
    Unavailable,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum ToolControlSelfTestStatus {
    #[default]
    NotConfigured,
    Passed,
    Failed,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ToolStartupRecoveryReport {
    pub control_self_test: ToolControlSelfTestStatus,
    pub recovered: usize,
    pub interrupted: usize,
    pub indeterminate: usize,
    pub terminated_retained_jobs: usize,
    pub survivor_inspection_failures: usize,
}

struct ToolRuntimeState {
    dispatch_open: bool,
    availability: ToolRuntimeAvailability,
    startup_inspection: Option<ToolStartupInspection>,
    recovery_report: Option<ToolStartupRecoveryReport>,
    workers: BTreeMap<ToolExecutionId, ToolWorker>,
}

#[derive(Clone)]
struct ToolStartupInspection {
    report: ToolStartupRecoveryReport,
    availability: ToolRuntimeAvailability,
    resolutions: Vec<ToolExecutionResolution>,
}

pub struct ToolRuntime {
    executions: Arc<dyn ToolExecutionStore>,
    executor: Option<Arc<dyn SelfTestingToolExecutor>>,
    broker: Option<Arc<ToolBroker>>,
    retained_processes: Arc<dyn RetainedProcessController>,
    state: Arc<Mutex<ToolRuntimeState>>,
    shutdown: Mutex<()>,
}

struct ToolBroker {
    database: SqliteStore,
    artifacts: ContentAddressedArtifactStore,
    policies: VersionedPolicyEngine,
    authority: Arc<dyn ToolAuthorityResolver>,
    executor: Arc<dyn SelfTestingToolExecutor>,
}

struct ToolWorker {
    handle: JoinHandle<()>,
    completion: Arc<ToolWorkerCompletion>,
}

#[derive(Default)]
struct ToolWorkerCompletion {
    result: Mutex<Option<ToolWorkerResult>>,
    ready: Condvar,
}

struct RuntimeIdGenerator;

struct StructuredExecutorProcessController {
    executor: Arc<dyn SelfTestingToolExecutor>,
}

impl RetainedProcessController for StructuredExecutorProcessController {
    fn terminate_retained_process(
        &self,
        binding: &AuthoritativeProcessBinding,
    ) -> Result<local_agent_terminal_application::CancellationReceipt, PortError> {
        self.executor.terminate_retained_process(binding)
    }
}

impl ToolBroker {
    fn new(
        database: SqliteStore,
        artifacts: ContentAddressedArtifactStore,
        config: ToolBrokerConfig,
    ) -> Result<Self, PortError> {
        let policies = VersionedPolicyEngine::from_json(&config.policy_bundle_json)?;
        Ok(Self {
            database,
            artifacts,
            policies,
            authority: config.authority,
            executor: config.executor,
        })
    }

    fn execute(&self, request: ToolRequest) -> Result<ToolOutcome, PortError> {
        self.with_execute_tool(|execute| execute.execute(request))
    }

    fn resume_approved(&self, approval_id: ApprovalId) -> Result<ToolOutcome, PortError> {
        self.with_execute_tool(|execute| execute.resume_approved(approval_id))
    }

    fn cancel(
        &self,
        execution_id: &ToolExecutionId,
    ) -> Result<DurableToolCancellationOutcome, PortError> {
        self.with_execute_tool(|execute| execute.cancel(execution_id))
    }

    fn approval_execution_id(
        &self,
        approval_id: &ApprovalId,
    ) -> Result<ToolExecutionId, PortError> {
        let observed_at = parse_policy_timestamp(&self.database.now_utc()?)?;
        let approval =
            ApprovalResumeStore::load_for_resume(&self.database, approval_id, observed_at)?;
        if approval.approval_id != *approval_id {
            return Err(integrity_failure());
        }
        Ok(approval.execution_id)
    }

    fn resolve_terminal(
        &self,
        resolution: ToolExecutionResolution,
    ) -> Result<DurableToolExecutionReceipt, PortError> {
        self.database.resolve_terminal(resolution)
    }

    fn with_execute_tool<T>(&self, operation: impl FnOnce(ExecuteTool<'_>) -> T) -> T {
        let publisher = ToolArtifactPublisher::new(&self.database, &self.artifacts);
        let orchestration = ToolExecutionOrchestration::new(
            &publisher,
            self.authority.as_ref(),
            &self.database,
            &self.policies,
            &self.database,
            &RuntimeIdGenerator,
            &publisher,
            &self.database,
            &self.database,
            &self.database,
        );
        operation(ExecuteTool::new(orchestration, self.executor.as_ref()))
    }
}

impl IdGenerator for RuntimeIdGenerator {
    fn next_id(&self) -> Result<String, PortError> {
        let elapsed = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| internal_failure())?;
        let sequence = NEXT_RUNTIME_ID.fetch_add(1, Ordering::Relaxed);
        let process = u64::from(std::process::id());
        let timestamp = elapsed.as_nanos() as u64 ^ process.rotate_left(32);
        Ok(format!("{timestamp:016x}{sequence:016x}"))
    }
}

impl ToolRuntime {
    #[cfg(test)]
    fn new(
        executions: Arc<dyn ToolExecutionStore>,
        executor: Arc<dyn SelfTestingToolExecutor>,
    ) -> Self {
        let retained_processes = Arc::new(StructuredExecutorProcessController {
            executor: Arc::clone(&executor),
        });
        Self::configured(executions, Some(executor), None, retained_processes)
    }

    pub(crate) fn with_broker(
        database: SqliteStore,
        artifacts: ContentAddressedArtifactStore,
        config: ToolBrokerConfig,
    ) -> Result<Self, PortError> {
        let broker = Arc::new(ToolBroker::new(database, artifacts, config)?);
        let executions: Arc<dyn ToolExecutionStore> = Arc::new(broker.database.clone());
        let executor = Arc::clone(&broker.executor);
        let retained_processes = Arc::new(StructuredExecutorProcessController {
            executor: Arc::clone(&executor),
        });
        Ok(Self::configured(
            executions,
            Some(executor),
            Some(broker),
            retained_processes,
        ))
    }

    pub fn recovery_only(
        executions: Arc<dyn ToolExecutionStore>,
        retained_processes: Arc<dyn RetainedProcessController>,
    ) -> Self {
        Self::configured(executions, None, None, retained_processes)
    }

    fn configured(
        executions: Arc<dyn ToolExecutionStore>,
        executor: Option<Arc<dyn SelfTestingToolExecutor>>,
        broker: Option<Arc<ToolBroker>>,
        retained_processes: Arc<dyn RetainedProcessController>,
    ) -> Self {
        Self {
            executions,
            executor,
            broker,
            retained_processes,
            state: Arc::new(Mutex::new(ToolRuntimeState {
                dispatch_open: false,
                availability: ToolRuntimeAvailability::Unavailable,
                startup_inspection: None,
                recovery_report: None,
                workers: BTreeMap::new(),
            })),
            shutdown: Mutex::new(()),
        }
    }

    pub fn availability(&self) -> Result<ToolRuntimeAvailability, PortError> {
        self.state
            .lock()
            .map(|state| state.availability)
            .map_err(|_| internal_failure())
    }

    pub fn recover_startup(&self) -> Result<ToolStartupRecoveryReport, PortError> {
        self.inspect_survivors()?;
        self.reconcile_intents()
    }

    pub fn inspect_survivors(&self) -> Result<ToolStartupRecoveryReport, PortError> {
        let _shutdown = self.shutdown.lock().map_err(|_| internal_failure())?;
        {
            let state = self.state.lock().map_err(|_| internal_failure())?;
            if state.dispatch_open || !state.workers.is_empty() {
                return Err(conflict());
            }
            if let Some(report) = &state.recovery_report {
                return Ok(report.clone());
            }
            if let Some(inspection) = &state.startup_inspection {
                return Ok(inspection.report.clone());
            }
        }

        let control_self_test = match self.executor.as_ref() {
            Some(executor) if executor.verify_controls().is_ok() => {
                ToolControlSelfTestStatus::Passed
            }
            Some(_) => ToolControlSelfTestStatus::Failed,
            None => ToolControlSelfTestStatus::NotConfigured,
        };
        let incomplete = self.executions.incomplete()?;
        let mut report = ToolStartupRecoveryReport {
            control_self_test,
            ..ToolStartupRecoveryReport::default()
        };
        let mut availability = if control_self_test == ToolControlSelfTestStatus::Passed {
            ToolRuntimeAvailability::Ready
        } else {
            ToolRuntimeAvailability::Unavailable
        };
        let mut resolutions = Vec::new();
        for incomplete_execution in incomplete {
            let (evidence, explicit_indeterminate) = match incomplete_execution {
                IncompleteToolExecution::InFlight(evidence) => (evidence, false),
                IncompleteToolExecution::Indeterminate(evidence) => (evidence, true),
            };
            validate_recovery_state(&evidence, explicit_indeterminate)?;
            let receipt = match evidence.state {
                ToolExecutionRecoveryState::Claimed => {
                    report.interrupted += 1;
                    Some(DurableToolExecutionReceipt::new(
                        evidence.authority.clone(),
                        ToolExecutionTerminal::interrupted(),
                    ))
                }
                ToolExecutionRecoveryState::Started | ToolExecutionRecoveryState::Indeterminate => {
                    report.indeterminate += 1;
                    match evidence.process_binding.as_ref() {
                        Some(binding) => {
                            match self.retained_processes.terminate_retained_process(binding) {
                                Ok(receipt) => match AuthoritativeProcessTermination::new(
                                    binding.clone(),
                                    receipt,
                                ) {
                                    Ok(termination) => {
                                        report.terminated_retained_jobs += 1;
                                        availability = degrade(availability);
                                        Some(
                                            DurableToolExecutionReceipt::recovered_process_termination(
                                                SafeErrorClassification::Unavailable,
                                                termination,
                                            ),
                                        )
                                    }
                                    Err(_) => {
                                        report.survivor_inspection_failures += 1;
                                        availability = ToolRuntimeAvailability::Unavailable;
                                        None
                                    }
                                },
                                Err(_) => {
                                    report.survivor_inspection_failures += 1;
                                    availability = ToolRuntimeAvailability::Unavailable;
                                    None
                                }
                            }
                        }
                        None if evidence.state == ToolExecutionRecoveryState::Indeterminate => {
                            availability = degrade(availability);
                            None
                        }
                        None => {
                            report.survivor_inspection_failures += 1;
                            availability = ToolRuntimeAvailability::Unavailable;
                            None
                        }
                    }
                }
            };
            let Some(receipt) = receipt else {
                continue;
            };
            resolutions.push(ToolExecutionResolution::new(receipt));
        }

        let mut state = self.state.lock().map_err(|_| internal_failure())?;
        if state.dispatch_open
            || !state.workers.is_empty()
            || state.startup_inspection.is_some()
            || state.recovery_report.is_some()
        {
            return Err(conflict());
        }
        state.startup_inspection = Some(ToolStartupInspection {
            report: report.clone(),
            availability,
            resolutions,
        });
        Ok(report)
    }

    pub fn reconcile_intents(&self) -> Result<ToolStartupRecoveryReport, PortError> {
        let _shutdown = self.shutdown.lock().map_err(|_| internal_failure())?;
        let inspection = {
            let state = self.state.lock().map_err(|_| internal_failure())?;
            if state.dispatch_open || !state.workers.is_empty() {
                return Err(conflict());
            }
            if let Some(report) = &state.recovery_report {
                return Ok(report.clone());
            }
            state.startup_inspection.clone().ok_or_else(conflict)?
        };
        let mut report = inspection.report;
        for resolution in inspection.resolutions {
            let persisted = self.executions.resolve_terminal(resolution.clone())?;
            if persisted != *resolution.receipt() {
                return Err(integrity_failure());
            }
            report.recovered += 1;
        }

        let mut state = self.state.lock().map_err(|_| internal_failure())?;
        if state.dispatch_open || !state.workers.is_empty() || state.recovery_report.is_some() {
            return Err(conflict());
        }
        state.availability = inspection.availability;
        state.startup_inspection = None;
        state.recovery_report = Some(report.clone());
        Ok(report)
    }

    pub fn release_dispatch(&self) -> Result<(), PortError> {
        let mut state = self.state.lock().map_err(|_| internal_failure())?;
        if state.recovery_report.is_none() || state.availability != ToolRuntimeAvailability::Ready {
            return Err(unavailable());
        }
        state.dispatch_open = true;
        Ok(())
    }

    pub fn execute(&self, request: ToolRequest) -> Result<ToolOutcome, PortError> {
        let execution_id = request.execution_id().clone();
        let broker = Arc::clone(self.broker.as_ref().ok_or_else(unavailable)?);
        self.dispatch_and_wait(execution_id, move || broker.execute(request))
    }

    pub fn resume_approved(&self, approval_id: ApprovalId) -> Result<ToolOutcome, PortError> {
        let broker = Arc::clone(self.broker.as_ref().ok_or_else(unavailable)?);
        let execution_id = broker.approval_execution_id(&approval_id)?;
        self.dispatch_and_wait(execution_id, move || broker.resume_approved(approval_id))
    }

    pub fn cancel(
        &self,
        execution_id: &ToolExecutionId,
    ) -> Result<DurableToolCancellationOutcome, PortError> {
        self.broker
            .as_ref()
            .ok_or_else(unavailable)?
            .cancel(execution_id)
    }

    fn dispatch_and_wait(
        &self,
        execution_id: ToolExecutionId,
        worker: impl FnOnce() -> ToolWorkerResult + Send + 'static,
    ) -> ToolWorkerResult {
        let completion = self.start_worker(execution_id.clone(), worker)?;
        let result = completion.wait();
        let owned_worker = self
            .state
            .lock()
            .map_err(|_| internal_failure())?
            .workers
            .remove(&execution_id);
        if let Some(worker) = owned_worker {
            worker.handle.join().map_err(|_| internal_failure())?;
        }
        result
    }

    fn start_worker(
        &self,
        execution_id: ToolExecutionId,
        worker: impl FnOnce() -> ToolWorkerResult + Send + 'static,
    ) -> Result<Arc<ToolWorkerCompletion>, PortError> {
        let mut state = self.state.lock().map_err(|_| internal_failure())?;
        if !state.dispatch_open
            || state.availability != ToolRuntimeAvailability::Ready
            || state.workers.contains_key(&execution_id)
        {
            return Err(conflict());
        }
        let completion = Arc::new(ToolWorkerCompletion::default());
        let worker_completion = Arc::clone(&completion);
        let runtime_state = Arc::clone(&self.state);
        let handle = thread::Builder::new()
            .spawn(move || {
                let result = match catch_unwind(AssertUnwindSafe(worker)) {
                    Ok(result) => result,
                    Err(_) => {
                        let mut state = runtime_state
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner);
                        state.dispatch_open = false;
                        state.availability = ToolRuntimeAvailability::Unavailable;
                        Err(internal_failure())
                    }
                };
                worker_completion.complete(result);
            })
            .map_err(|_| unavailable())?;
        state.workers.insert(
            execution_id,
            ToolWorker {
                handle,
                completion: Arc::clone(&completion),
            },
        );
        Ok(completion)
    }

    #[cfg(test)]
    fn dispatch_test_worker(
        &self,
        execution_id: ToolExecutionId,
        worker: impl FnOnce() -> Result<DurableToolExecutionReceipt, PortError> + Send + 'static,
    ) -> Result<(), PortError> {
        self.start_worker(execution_id, move || {
            worker().map(|receipt| {
                ToolOutcome::Execution(DurableToolExecutionOutcome::Completed(receipt))
            })
        })?;
        Ok(())
    }

    pub fn stop_all(&self) -> Result<Vec<DurableToolExecutionReceipt>, PortError> {
        let _shutdown = self.shutdown.lock().map_err(|_| internal_failure())?;
        let workers = {
            let mut state = self.state.lock().map_err(|_| internal_failure())?;
            state.dispatch_open = false;
            state.availability = ToolRuntimeAvailability::Unavailable;
            std::mem::take(&mut state.workers)
        };
        if workers.is_empty() {
            return Ok(Vec::new());
        }
        match self.broker.as_ref() {
            Some(broker) => self.stop_all_broker(workers, broker),
            None => self.stop_all_legacy(workers),
        }
    }

    fn stop_all_broker(
        &self,
        workers: BTreeMap<ToolExecutionId, ToolWorker>,
        broker: &ToolBroker,
    ) -> Result<Vec<DurableToolExecutionReceipt>, PortError> {
        let mut authorities = BTreeMap::new();
        let mut completed = BTreeMap::new();
        let mut cancellation_errors = BTreeMap::new();
        let mut pending = workers.iter().collect::<VecDeque<_>>();
        while let Some((execution_id, worker)) = pending.pop_front() {
            match broker.cancel(execution_id) {
                Ok(DurableToolCancellationOutcome::Requested { authority, .. })
                | Ok(DurableToolCancellationOutcome::InFlight(authority)) => {
                    authorities.insert(execution_id.clone(), authority);
                }
                Ok(DurableToolCancellationOutcome::Completed(receipt)) => {
                    completed.insert(execution_id.clone(), receipt);
                }
                Err(error)
                    if matches!(
                        error.safe_classification(),
                        SafeErrorClassification::NotFound | SafeErrorClassification::Conflict
                    ) =>
                {
                    if !worker
                        .completion
                        .wait_for_completion(Duration::from_millis(10))?
                    {
                        pending.push_back((execution_id, worker));
                    }
                }
                Err(error) => {
                    cancellation_errors.insert(execution_id.clone(), error);
                }
            }
        }

        let mut receipts = Vec::with_capacity(workers.len());
        let mut first_error = None;
        for (execution_id, worker) in workers {
            if worker.handle.join().is_err() {
                record_first_error(&mut first_error, internal_failure());
            }
            let worker_receipt = match worker.completion.wait() {
                Ok(ToolOutcome::Execution(DurableToolExecutionOutcome::Completed(receipt))) => {
                    Some(receipt)
                }
                Ok(ToolOutcome::Execution(
                    DurableToolExecutionOutcome::TerminalPersistenceUnresolved {
                        resolution, ..
                    },
                )) => match broker.resolve_terminal(resolution) {
                    Ok(receipt) => Some(receipt),
                    Err(error) => {
                        record_first_error(&mut first_error, error);
                        None
                    }
                },
                Ok(ToolOutcome::Execution(
                    DurableToolExecutionOutcome::InFlight(_)
                    | DurableToolExecutionOutcome::Indeterminate(_),
                ))
                | Err(_) => authorities.remove(&execution_id).map(|authority| {
                    let error = cancellation_errors
                        .remove(&execution_id)
                        .unwrap_or_else(internal_failure);
                    indeterminate_receipt(authority, &error)
                }),
                Ok(ToolOutcome::Denied(_) | ToolOutcome::ApprovalRequired(_)) => None,
            };
            if let Some(persisted) = completed.remove(&execution_id) {
                cancellation_errors.remove(&execution_id);
                if worker_receipt
                    .as_ref()
                    .is_some_and(|receipt| receipt != &persisted)
                {
                    record_first_error(&mut first_error, integrity_failure());
                }
                receipts.push(persisted);
                continue;
            }
            let Some(receipt) = worker_receipt else {
                if let Some(error) = cancellation_errors.remove(&execution_id) {
                    record_first_error(&mut first_error, error);
                }
                continue;
            };
            match broker.resolve_terminal(ToolExecutionResolution::new(receipt)) {
                Ok(receipt) => {
                    cancellation_errors.remove(&execution_id);
                    receipts.push(receipt);
                }
                Err(error) => record_first_error(&mut first_error, error),
            }
        }
        if let Some(error) = first_error {
            Err(error)
        } else {
            Ok(receipts)
        }
    }

    fn stop_all_legacy(
        &self,
        workers: BTreeMap<ToolExecutionId, ToolWorker>,
    ) -> Result<Vec<DurableToolExecutionReceipt>, PortError> {
        let executor = self.executor.as_ref().ok_or_else(unavailable)?;
        let mut authorities = BTreeMap::new();
        let mut completed = BTreeMap::new();
        let mut cancellation_errors = BTreeMap::new();
        let mut first_error = None;
        for execution_id in workers.keys() {
            match self.executions.request_cancellation(execution_id) {
                Ok(ToolExecutionCancellationClaim::Claimed(authority)) => {
                    authorities.insert(execution_id.clone(), authority);
                    match executor.cancel(execution_id) {
                        Ok(receipt)
                            if receipt.execution_id == *execution_id
                                && receipt.status == ProcessStatus::Terminated
                                && receipt.cancelled => {}
                        Ok(_) => {
                            cancellation_errors.insert(execution_id.clone(), integrity_failure());
                        }
                        Err(error) => {
                            cancellation_errors.insert(execution_id.clone(), error);
                        }
                    }
                }
                Ok(ToolExecutionCancellationClaim::InFlight(authority)) => {
                    authorities.insert(execution_id.clone(), authority);
                }
                Ok(ToolExecutionCancellationClaim::Completed(receipt)) => {
                    completed.insert(execution_id.clone(), receipt);
                }
                Err(error) => {
                    cancellation_errors.insert(execution_id.clone(), error);
                }
            }
        }

        let mut receipts = Vec::with_capacity(workers.len());
        for (execution_id, worker) in workers {
            let joined = worker.handle.join();
            let worker_receipt = match worker.completion.wait() {
                Ok(ToolOutcome::Execution(DurableToolExecutionOutcome::Completed(receipt))) => {
                    Some(receipt)
                }
                Ok(ToolOutcome::Execution(
                    DurableToolExecutionOutcome::TerminalPersistenceUnresolved {
                        resolution, ..
                    },
                )) => Some(resolution.into_receipt()),
                Ok(ToolOutcome::Execution(
                    DurableToolExecutionOutcome::InFlight(_)
                    | DurableToolExecutionOutcome::Indeterminate(_),
                ))
                | Ok(ToolOutcome::Denied(_) | ToolOutcome::ApprovalRequired(_)) => {
                    record_first_error(&mut first_error, integrity_failure());
                    None
                }
                Err(worker_error) => match authorities.remove(&execution_id) {
                    Some(authority) => {
                        let error = cancellation_errors
                            .remove(&execution_id)
                            .unwrap_or(worker_error);
                        Some(indeterminate_receipt(authority, &error))
                    }
                    None => {
                        let error = cancellation_errors
                            .remove(&execution_id)
                            .unwrap_or(worker_error);
                        record_first_error(&mut first_error, error);
                        None
                    }
                },
            };
            if joined.is_err() {
                record_first_error(&mut first_error, internal_failure());
            }
            if let Some(persisted) = completed.remove(&execution_id) {
                cancellation_errors.remove(&execution_id);
                if worker_receipt
                    .as_ref()
                    .is_some_and(|receipt| receipt != &persisted)
                {
                    record_first_error(&mut first_error, integrity_failure());
                }
                receipts.push(persisted);
                continue;
            }
            let Some(receipt) = worker_receipt else {
                continue;
            };
            match self
                .executions
                .resolve_terminal(ToolExecutionResolution::new(receipt))
            {
                Ok(receipt) => {
                    cancellation_errors.remove(&execution_id);
                    receipts.push(receipt);
                }
                Err(error) => record_first_error(&mut first_error, error),
            }
        }
        if let Some(error) = first_error {
            Err(error)
        } else {
            Ok(receipts)
        }
    }
}

impl ToolWorkerCompletion {
    fn complete(&self, worker_result: ToolWorkerResult) {
        let mut result = self
            .result
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *result = Some(worker_result);
        self.ready.notify_all();
    }

    fn wait(&self) -> ToolWorkerResult {
        let mut result = self.result.lock().map_err(|_| internal_failure())?;
        loop {
            if let Some(worker_result) = result.as_ref() {
                return worker_result.clone();
            }
            result = self.ready.wait(result).map_err(|_| internal_failure())?;
        }
    }

    fn wait_for_completion(&self, timeout: Duration) -> Result<bool, PortError> {
        let result = self.result.lock().map_err(|_| internal_failure())?;
        if result.is_some() {
            return Ok(true);
        }
        let (result, _) = self
            .ready
            .wait_timeout(result, timeout)
            .map_err(|_| internal_failure())?;
        Ok(result.is_some())
    }
}

pub struct ToolArtifactPublisher<'a> {
    database: &'a SqliteStore,
    artifacts: &'a ContentAddressedArtifactStore,
}

impl<'a> ToolArtifactPublisher<'a> {
    pub const fn new(
        database: &'a SqliteStore,
        artifacts: &'a ContentAddressedArtifactStore,
    ) -> Self {
        Self {
            database,
            artifacts,
        }
    }

    fn publish_artifact(&self, artifact: JournaledToolArtifact<'_>) -> Result<(), PortError> {
        let storage_key = ContentAddressedArtifactStore::storage_key(artifact.digest)?;
        if let Some(existing) = self.database.available_evidence(artifact.artifact_id)? {
            if existing.content_hash != artifact.digest
                || existing.storage_key != storage_key
                || existing.size_bytes != artifact.bytes.len() as u64
                || existing.project_id != *artifact.project_id
                || existing.task_id.as_ref() != Some(artifact.task_id)
            {
                return Err(integrity_failure());
            }
            return Ok(());
        }
        let created_at = self.database.now_utc()?;
        let digest_suffix = artifact
            .digest
            .strip_prefix("sha256:")
            .ok_or_else(integrity_failure)?;
        JournaledArtifactWriter::new(self.artifacts, self.database, self.database).write(
            ArtifactWriteReservation {
                operation_id: format!(
                    "publish:{}:{}",
                    artifact.artifact_type,
                    artifact.artifact_id.as_str()
                ),
                artifact: ReservedArtifact {
                    artifact_id: artifact.artifact_id.as_str().to_owned(),
                    task_id: Some(artifact.task_id.clone()),
                    project_id: artifact.project_id.as_str().to_owned(),
                    artifact_type: artifact.artifact_type.to_owned(),
                    logical_path: artifact.logical_path,
                    content_hash: artifact.digest.to_owned(),
                    storage_key,
                    size_bytes: artifact.bytes.len() as u64,
                    mime_type: Some("application/json".to_owned()),
                    created_by_type: "tool".to_owned(),
                    created_by_id: artifact.created_by_id.to_owned(),
                    created_at: created_at.clone(),
                    supersedes: None,
                },
                temp_name: format!(
                    "tool-{}-{}-{}.tmp",
                    std::process::id(),
                    NEXT_TEMP_FILE.fetch_add(1, Ordering::Relaxed),
                    &digest_suffix[..16]
                ),
                created_at,
            },
            artifact.bytes,
        )?;
        Ok(())
    }

    fn project_id(&self, task_id: &TaskId) -> Result<ProjectId, PortError> {
        let task = self.database.task(task_id)?;
        if task.task_id != *task_id {
            return Err(integrity_failure());
        }
        Ok(task.project_id)
    }
}

impl ToolRequestPublisher for ToolArtifactPublisher<'_> {
    fn publish(&self, request: &ImmutableToolRequest) -> Result<ArtifactId, PortError> {
        let tool_request = request.request();
        let process = tool_request.process().process();
        let task_id = process.binding().task_id();
        let project_id = self.project_id(task_id)?;
        let digest = request.binding_digest().as_sha256();
        let digest_suffix = digest
            .as_str()
            .strip_prefix("sha256:")
            .ok_or_else(integrity_failure)?;
        let artifact_id = ArtifactId::new(format!("tool-request-{digest_suffix}"))
            .map_err(|_| invalid_input())?;
        self.publish_artifact(JournaledToolArtifact {
            artifact_id: &artifact_id,
            task_id,
            project_id: &project_id,
            artifact_type: "tool-request",
            logical_path: format!(
                "tool-requests/{}.json",
                tool_request.execution_id().as_str()
            ),
            created_by_id: tool_request.execution_id().as_str(),
            digest: digest.as_str(),
            bytes: request.canonical_bytes(),
        })?;
        let persisted = self.database.load_request_artifact(&artifact_id)?;
        if persisted != *request {
            return Err(integrity_failure());
        }
        let reserved = ToolExecutionStore::reserve(
            self.database,
            NewToolIntent {
                execution_id: tool_request.execution_id().clone(),
                operation_digest: digest.clone(),
            },
        )?;
        validate_reservation(&reserved, tool_request.execution_id(), digest.as_str())?;
        Ok(artifact_id)
    }
}

impl ToolApprovalRequestPublisher for ToolArtifactPublisher<'_> {
    fn publish_or_replay(
        &self,
        request: ToolApprovalRequest,
    ) -> Result<ToolApprovalPublication, PortError> {
        match self.database.load_intent(request.execution_id()) {
            Ok(_) => return self.database.record_tool_approval_request(request),
            Err(error) if error.safe_classification() == SafeErrorClassification::NotFound => {}
            Err(error) => return Err(error),
        }
        let task_id =
            TaskId::new(request.payload().task_id.clone()).map_err(|_| invalid_input())?;
        let project_id = self.project_id(&task_id)?;
        let digest = &request.canonical_payload().operation_digest;
        self.publish_artifact(JournaledToolArtifact {
            artifact_id: request.approval_artifact_id(),
            task_id: &task_id,
            project_id: &project_id,
            artifact_type: "approval-payload",
            logical_path: format!("approvals/{}.json", request.approval_id().as_str()),
            created_by_id: request.approval_id().as_str(),
            digest: digest.as_str(),
            bytes: &request.canonical_payload().canonical_bytes,
        })?;
        self.database.record_tool_approval_request(request)
    }
}

struct JournaledToolArtifact<'a> {
    artifact_id: &'a ArtifactId,
    task_id: &'a TaskId,
    project_id: &'a ProjectId,
    artifact_type: &'static str,
    logical_path: String,
    created_by_id: &'a str,
    digest: &'a str,
    bytes: &'a [u8],
}

fn validate_reservation(
    snapshot: &OperationIntentSnapshot,
    execution_id: &local_agent_terminal_application::ToolExecutionId,
    digest: &str,
) -> Result<(), PortError> {
    if snapshot.execution_id != *execution_id || snapshot.operation_digest.as_str() != digest {
        return Err(integrity_failure());
    }
    Ok(())
}

fn validate_recovery_state(
    evidence: &local_agent_terminal_application::ToolExecutionRecoveryEvidence,
    explicit_indeterminate: bool,
) -> Result<(), PortError> {
    let variant_matches = if explicit_indeterminate {
        evidence.state == ToolExecutionRecoveryState::Indeterminate
    } else {
        matches!(
            evidence.state,
            ToolExecutionRecoveryState::Claimed | ToolExecutionRecoveryState::Started
        )
    };
    if !variant_matches
        || (evidence.state == ToolExecutionRecoveryState::Claimed
            && evidence.process_binding.is_some())
        || evidence
            .process_binding
            .as_ref()
            .is_some_and(|binding| binding.authority() != &evidence.authority)
    {
        return Err(integrity_failure());
    }
    Ok(())
}

const fn degrade(availability: ToolRuntimeAvailability) -> ToolRuntimeAvailability {
    match availability {
        ToolRuntimeAvailability::Ready => ToolRuntimeAvailability::DegradedReadOnly,
        ToolRuntimeAvailability::DegradedReadOnly | ToolRuntimeAvailability::Unavailable => {
            availability
        }
    }
}

fn invalid_input() -> PortError {
    PortError::failure(
        SafeErrorClassification::InvalidInput,
        Retryability::NonRetryable,
    )
}

fn integrity_failure() -> PortError {
    PortError::failure(
        SafeErrorClassification::IntegrityFailure,
        Retryability::NonRetryable,
    )
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
        Retryability::Retryable,
    )
}

fn internal_failure() -> PortError {
    PortError::failure(
        SafeErrorClassification::Internal,
        Retryability::NonRetryable,
    )
}

fn record_first_error(first: &mut Option<PortError>, error: PortError) {
    if first.is_none() {
        *first = Some(error);
    }
}

fn indeterminate_receipt(
    authority: local_agent_terminal_application::ToolExecutionClaimAuthority,
    error: &PortError,
) -> DurableToolExecutionReceipt {
    DurableToolExecutionReceipt::new(
        authority,
        ToolExecutionTerminal::indeterminate(SafeToolExecutionError {
            classification: error.safe_classification(),
            retryability: error.retryability(),
        }),
    )
}

#[cfg(test)]
#[path = "tool_runtime_tests.rs"]
mod tests;
