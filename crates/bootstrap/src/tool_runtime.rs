use std::collections::{BTreeMap, VecDeque};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use local_agent_terminal_application::{
    parse_policy_timestamp, present_tool_activity_record, ApprovalId, ApprovalResolution,
    ApprovalResumeStore, ApprovalStore, ArtifactId, ArtifactWriteReservation,
    AuthoritativeProcessBinding, AuthoritativeProcessTermination, CancelToolExecutionRequestDto,
    CanonicalEvidenceRef, Clock, DisclosedToolExecutionArtifacts, DisclosureOutcome,
    DurableToolCancellationOutcome, DurableToolExecutionArtifact, DurableToolExecutionArtifacts,
    DurableToolExecutionOutcome, DurableToolExecutionReceipt, ExecuteTool, FileReadRequest,
    FileWriteRecoverySnapshot, FileWriteRecoveryState, FileWriteRequest, GitDiffRequest,
    GitDiffResult, GitStatusRequest, GitStatusResult, IdGenerator, ImmutableToolRequest,
    IncompleteToolExecution, NewToolIntent, OperationIntentSnapshot, PolicyBoundBytes, PortError,
    ProcessStatus, ProjectId, ReservedArtifact, ResolveToolApprovalRequestDto,
    RetainedProcessController, Retryability, SafeErrorClassification, SafeToolExecutionError,
    Sha256Digest, StopAllToolsReceiptDto, StructuredToolExecutor, TaskId, TaskQuery,
    ToolActivityDto, ToolActivityStatusDto, ToolApprovalDecisionDto, ToolApprovalPublication,
    ToolApprovalRequest, ToolApprovalRequestDto, ToolApprovalRequestPublisher,
    ToolApprovalResolutionDto, ToolAuthorityResolver, ToolCancellationReceiptDto,
    ToolControlSelfTest, ToolExecutionArtifactEvidence, ToolExecutionCancellationClaim,
    ToolExecutionId, ToolExecutionOrchestration, ToolExecutionRecoveryState,
    ToolExecutionResolution, ToolExecutionResumeStore, ToolExecutionStore, ToolExecutionTerminal,
    ToolExecutionTerminalKind, ToolOutcome, ToolRequest, ToolRequestPublisher,
    ToolRuntimeAvailabilityDto, VerifiedWrite, WorkspaceEvidenceStore, WorkspaceWriteCoordinator,
};
use local_agent_terminal_policy_engine::VersionedPolicyEngine;
use local_agent_terminal_storage_files::{ContentAddressedArtifactStore, JournaledArtifactWriter};
use local_agent_terminal_storage_sqlite::SqliteStore;

static NEXT_TEMP_FILE: AtomicU64 = AtomicU64::new(0);
static NEXT_RUNTIME_ID: AtomicU64 = AtomicU64::new(0);

type ToolWorkerResult = Result<ToolOutcome, PortError>;
type StartupFileWriteRecovery =
    dyn Fn() -> Result<Vec<FileWriteRecoverySnapshot>, PortError> + Send + Sync;

pub trait SelfTestingToolExecutor: StructuredToolExecutor + ToolControlSelfTest {}

impl<T> SelfTestingToolExecutor for T where T: StructuredToolExecutor + ToolControlSelfTest {}

#[derive(Clone)]
pub struct ToolBrokerConfig {
    policy_bundle_json: String,
    authority: Arc<dyn ToolAuthorityResolver>,
    executor: Arc<dyn SelfTestingToolExecutor>,
    process_enabled: bool,
    write_enabled: bool,
    workspace_writes: Arc<WorkspaceWriteCoordinator>,
    file_write_recovery: Option<Arc<StartupFileWriteRecovery>>,
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
            process_enabled: true,
            write_enabled: true,
            workspace_writes: Arc::new(WorkspaceWriteCoordinator::new()),
            file_write_recovery: None,
        }
    }

    pub fn degraded_read_only(mut self) -> Self {
        self.process_enabled = false;
        self.write_enabled = false;
        self
    }

    pub(crate) fn without_process(mut self) -> Self {
        self.process_enabled = false;
        self
    }

    pub(crate) fn with_workspace_writes(
        mut self,
        workspace_writes: Arc<WorkspaceWriteCoordinator>,
    ) -> Self {
        self.workspace_writes = workspace_writes;
        self
    }

    pub(crate) fn with_file_write_recovery(
        mut self,
        recovery: Arc<StartupFileWriteRecovery>,
    ) -> Self {
        self.file_write_recovery = Some(recovery);
        self
    }

    pub(crate) fn workspace_writes(&self) -> Arc<WorkspaceWriteCoordinator> {
        Arc::clone(&self.workspace_writes)
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
    file_write_recovery: Option<Arc<StartupFileWriteRecovery>>,
    state: Arc<Mutex<ToolRuntimeState>>,
    shutdown: Mutex<()>,
    degraded_read_only: bool,
}

struct ToolBroker {
    database: SqliteStore,
    artifacts: ContentAddressedArtifactStore,
    policies: VersionedPolicyEngine,
    authority: Arc<dyn ToolAuthorityResolver>,
    executor: Arc<dyn SelfTestingToolExecutor>,
    process_enabled: bool,
    write_enabled: bool,
}

struct PublishingStructuredExecutor<'a, 'storage> {
    executor: &'a dyn SelfTestingToolExecutor,
    publisher: &'a ToolArtifactPublisher<'storage>,
    process_enabled: bool,
    write_enabled: bool,
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
            process_enabled: config.process_enabled,
            write_enabled: config.write_enabled,
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

    fn file_read(
        &self,
        request: FileReadRequest,
    ) -> Result<DisclosureOutcome<PolicyBoundBytes>, PortError> {
        self.executor.file_read(request)
    }

    fn file_write(&self, request: FileWriteRequest) -> Result<VerifiedWrite, PortError> {
        self.executor.file_write(request)
    }

    fn git_status(
        &self,
        request: GitStatusRequest,
    ) -> Result<DisclosureOutcome<GitStatusResult>, PortError> {
        self.executor.git_status(request)
    }

    fn git_diff(
        &self,
        request: GitDiffRequest,
    ) -> Result<DisclosureOutcome<GitDiffResult>, PortError> {
        self.executor.git_diff(request)
    }

    fn activity_entries(
        &self,
    ) -> Result<Vec<local_agent_terminal_application::ToolActivityEntryDto>, PortError> {
        let evaluated_at = parse_policy_timestamp(&self.database.now_utc()?)?;
        self.database
            .tool_activity_records()?
            .into_iter()
            .map(|record| {
                present_tool_activity_record(record, &self.policies, &self.database, evaluated_at)
            })
            .collect()
    }

    fn approval_request(
        &self,
        approval_id: &ApprovalId,
    ) -> Result<ToolApprovalRequestDto, PortError> {
        let evaluated_at = parse_policy_timestamp(&self.database.now_utc()?)?;
        let entry = present_tool_activity_record(
            self.database
                .tool_activity_record_for_approval(approval_id)?,
            &self.policies,
            &self.database,
            evaluated_at,
        )?;
        if entry.status != ToolActivityStatusDto::ApprovalRequired {
            return Err(conflict());
        }
        Ok(ToolApprovalRequestDto {
            approval_id: approval_id.as_str().to_owned(),
            execution_id: entry.execution_id,
            executable: entry.executable,
            arguments: entry.arguments,
            cwd_scope: entry.cwd_scope,
            read_scopes: entry.read_scopes,
            write_scopes: entry.write_scopes,
            operation_digest: entry.operation_digest,
            expires_at: entry.expires_at.ok_or_else(integrity_failure)?,
            actor_id: entry.actor_id,
            reason: entry.reason,
            environment_profile_digest: entry.environment_profile_digest,
            network_profile: entry.network_profile,
            fencing_token: entry.fencing_token,
            policy_rules: entry.policy_rules,
            redaction_state: entry.redaction_state,
        })
    }

    fn resolve_approval(&self, approval_id: ApprovalId, approved: bool) -> Result<(), PortError> {
        ApprovalStore::resolve(
            &self.database,
            ApprovalResolution {
                approval_id,
                approved,
            },
        )?;
        Ok(())
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
        let executor = PublishingStructuredExecutor {
            executor: self.executor.as_ref(),
            publisher: &publisher,
            process_enabled: self.process_enabled,
            write_enabled: self.write_enabled,
        };
        operation(ExecuteTool::new(orchestration, &executor))
    }
}

impl StructuredToolExecutor for PublishingStructuredExecutor<'_, '_> {
    fn execute(
        &self,
        request: local_agent_terminal_application::AuthorizedToolRequest,
    ) -> Result<local_agent_terminal_application::ToolExecutionResult, PortError> {
        if !self.process_enabled {
            return Err(unavailable());
        }
        let task_id = request
            .process_request()
            .process()
            .binding()
            .task_id()
            .clone();
        let mut result = self.executor.execute(request)?;
        result.artifacts = match result.artifacts {
            ToolExecutionArtifactEvidence::Disclosed(disclosed) => {
                ToolExecutionArtifactEvidence::Published(self.publisher.publish_tool_outputs(
                    &task_id,
                    &result.receipt.execution_id,
                    &disclosed,
                )?)
            }
            ToolExecutionArtifactEvidence::Quarantined(quarantined) => {
                ToolExecutionArtifactEvidence::Quarantined(quarantined)
            }
            ToolExecutionArtifactEvidence::Published(_) => return Err(integrity_failure()),
        };
        Ok(result)
    }

    fn cancel(
        &self,
        execution_id: &ToolExecutionId,
    ) -> Result<local_agent_terminal_application::CancellationReceipt, PortError> {
        self.executor.cancel(execution_id)
    }

    fn terminate_retained_process(
        &self,
        binding: &AuthoritativeProcessBinding,
    ) -> Result<local_agent_terminal_application::CancellationReceipt, PortError> {
        self.executor.terminate_retained_process(binding)
    }

    fn file_read(
        &self,
        request: FileReadRequest,
    ) -> Result<DisclosureOutcome<local_agent_terminal_application::PolicyBoundBytes>, PortError>
    {
        self.executor.file_read(request)
    }

    fn file_write(&self, request: FileWriteRequest) -> Result<VerifiedWrite, PortError> {
        if !self.write_enabled {
            return Err(unavailable());
        }
        self.executor.file_write(request)
    }

    fn git_status(
        &self,
        request: GitStatusRequest,
    ) -> Result<DisclosureOutcome<GitStatusResult>, PortError> {
        self.executor.git_status(request)
    }

    fn git_diff(
        &self,
        request: GitDiffRequest,
    ) -> Result<DisclosureOutcome<GitDiffResult>, PortError> {
        self.executor.git_diff(request)
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
        Self::configured(
            executions,
            Some(executor),
            None,
            retained_processes,
            None,
            false,
        )
    }

    pub(crate) fn with_broker(
        database: SqliteStore,
        artifacts: ContentAddressedArtifactStore,
        config: ToolBrokerConfig,
    ) -> Result<Self, PortError> {
        let degraded_read_only = !config.process_enabled && !config.write_enabled;
        let file_write_recovery = config.file_write_recovery.clone();
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
            file_write_recovery,
            degraded_read_only,
        ))
    }

    pub fn recovery_only(
        executions: Arc<dyn ToolExecutionStore>,
        retained_processes: Arc<dyn RetainedProcessController>,
    ) -> Self {
        Self::configured(executions, None, None, retained_processes, None, false)
    }

    fn configured(
        executions: Arc<dyn ToolExecutionStore>,
        executor: Option<Arc<dyn SelfTestingToolExecutor>>,
        broker: Option<Arc<ToolBroker>>,
        retained_processes: Arc<dyn RetainedProcessController>,
        file_write_recovery: Option<Arc<StartupFileWriteRecovery>>,
        degraded_read_only: bool,
    ) -> Self {
        Self {
            executions,
            executor,
            broker,
            retained_processes,
            file_write_recovery,
            state: Arc::new(Mutex::new(ToolRuntimeState {
                dispatch_open: false,
                availability: ToolRuntimeAvailability::Unavailable,
                startup_inspection: None,
                recovery_report: None,
                workers: BTreeMap::new(),
            })),
            shutdown: Mutex::new(()),
            degraded_read_only,
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

    pub(crate) fn recover_file_writes(&self) -> Result<Vec<FileWriteRecoverySnapshot>, PortError> {
        let _shutdown = self.shutdown.lock().map_err(|_| internal_failure())?;
        {
            let state = self.state.lock().map_err(|_| internal_failure())?;
            if state.dispatch_open
                || !state.workers.is_empty()
                || state.startup_inspection.is_none()
                || state.recovery_report.is_some()
            {
                return Err(conflict());
            }
        }
        let Some(recovery) = self.file_write_recovery.as_ref() else {
            return Ok(Vec::new());
        };
        let snapshots = recovery()?;
        if snapshots.iter().any(|snapshot| {
            matches!(
                snapshot.state,
                FileWriteRecoveryState::Prepared
                    | FileWriteRecoveryState::Started
                    | FileWriteRecoveryState::Indeterminate
            )
        }) {
            return Err(integrity_failure());
        }
        Ok(snapshots)
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
            if self.degraded_read_only {
                ToolRuntimeAvailability::DegradedReadOnly
            } else {
                ToolRuntimeAvailability::Ready
            }
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
        if state.recovery_report.is_none()
            || !matches!(
                state.availability,
                ToolRuntimeAvailability::Ready | ToolRuntimeAvailability::DegradedReadOnly
            )
        {
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

    pub fn file_read(
        &self,
        request: FileReadRequest,
    ) -> Result<DisclosureOutcome<PolicyBoundBytes>, PortError> {
        let _shutdown = self.shutdown.lock().map_err(|_| internal_failure())?;
        self.ensure_structured_dispatch(true)?;
        self.broker
            .as_ref()
            .ok_or_else(unavailable)?
            .file_read(request)
    }

    pub fn file_write(&self, request: FileWriteRequest) -> Result<VerifiedWrite, PortError> {
        let _shutdown = self.shutdown.lock().map_err(|_| internal_failure())?;
        self.ensure_structured_dispatch(false)?;
        self.broker
            .as_ref()
            .ok_or_else(unavailable)?
            .file_write(request)
    }

    pub fn git_status(
        &self,
        request: GitStatusRequest,
    ) -> Result<DisclosureOutcome<GitStatusResult>, PortError> {
        let _shutdown = self.shutdown.lock().map_err(|_| internal_failure())?;
        self.ensure_structured_dispatch(true)?;
        self.broker
            .as_ref()
            .ok_or_else(unavailable)?
            .git_status(request)
    }

    pub fn git_diff(
        &self,
        request: GitDiffRequest,
    ) -> Result<DisclosureOutcome<GitDiffResult>, PortError> {
        let _shutdown = self.shutdown.lock().map_err(|_| internal_failure())?;
        self.ensure_structured_dispatch(true)?;
        self.broker
            .as_ref()
            .ok_or_else(unavailable)?
            .git_diff(request)
    }

    pub fn activity(&self) -> Result<ToolActivityDto, PortError> {
        let (availability, entries) = match &self.broker {
            Some(broker) => (
                runtime_availability_dto(self.availability()?),
                broker.activity_entries()?,
            ),
            None => (ToolRuntimeAvailabilityDto::Unavailable, Vec::new()),
        };
        Ok(ToolActivityDto {
            availability,
            entries,
        })
    }

    pub fn approval_request(
        &self,
        approval_id: ApprovalId,
    ) -> Result<ToolApprovalRequestDto, PortError> {
        self.broker
            .as_ref()
            .ok_or_else(unavailable)?
            .approval_request(&approval_id)
    }

    pub fn resolve_approval(
        &self,
        request: ResolveToolApprovalRequestDto,
    ) -> Result<ToolApprovalResolutionDto, PortError> {
        if self.availability()? != ToolRuntimeAvailability::Ready {
            return Err(unavailable());
        }
        if !valid_sha256_digest(&request.expected_operation_digest) {
            return Err(invalid_input());
        }
        let approval_id = ApprovalId::new(request.approval_id.clone())?;
        let detail = self.approval_request(approval_id.clone())?;
        if detail.operation_digest != request.expected_operation_digest {
            return Err(conflict());
        }
        let broker = Arc::clone(self.broker.as_ref().ok_or_else(unavailable)?);
        let approved = request.decision == ToolApprovalDecisionDto::Approve;
        broker.resolve_approval(approval_id.clone(), approved)?;
        let status = if approved {
            tool_outcome_status(&self.resume_approved(approval_id.clone())?)
        } else {
            ToolActivityStatusDto::Denied
        };
        Ok(ToolApprovalResolutionDto {
            approval_id: approval_id.as_str().to_owned(),
            execution_id: detail.execution_id,
            status,
        })
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

    pub fn cancel_for_ui(
        &self,
        request: CancelToolExecutionRequestDto,
    ) -> Result<ToolCancellationReceiptDto, PortError> {
        let execution_id = ToolExecutionId::new(request.execution_id)?;
        match self.cancel(&execution_id)? {
            DurableToolCancellationOutcome::Requested { receipt, .. } => {
                Ok(ToolCancellationReceiptDto {
                    execution_id: receipt.execution_id.as_str().to_owned(),
                    status: ToolActivityStatusDto::Cancelling,
                    cancelled: receipt.cancelled,
                })
            }
            DurableToolCancellationOutcome::InFlight(authority) => Ok(ToolCancellationReceiptDto {
                execution_id: authority.execution_id().as_str().to_owned(),
                status: ToolActivityStatusDto::Cancelling,
                cancelled: false,
            }),
            DurableToolCancellationOutcome::Completed(receipt) => {
                Ok(cancellation_receipt_dto(&receipt))
            }
        }
    }

    pub fn stop_all_for_ui(&self) -> Result<StopAllToolsReceiptDto, PortError> {
        Ok(StopAllToolsReceiptDto {
            receipts: self
                .stop_all()?
                .iter()
                .map(cancellation_receipt_dto)
                .collect(),
        })
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

    fn ensure_structured_dispatch(&self, allow_degraded: bool) -> Result<(), PortError> {
        let state = self.state.lock().map_err(|_| internal_failure())?;
        if !state.dispatch_open {
            return Err(conflict());
        }
        if state.availability == ToolRuntimeAvailability::Ready
            || (allow_degraded && state.availability == ToolRuntimeAvailability::DegradedReadOnly)
        {
            Ok(())
        } else {
            Err(unavailable())
        }
    }

    fn start_worker(
        &self,
        execution_id: ToolExecutionId,
        worker: impl FnOnce() -> ToolWorkerResult + Send + 'static,
    ) -> Result<Arc<ToolWorkerCompletion>, PortError> {
        let mut state = self.state.lock().map_err(|_| internal_failure())?;
        if !state.dispatch_open
            || !matches!(
                state.availability,
                ToolRuntimeAvailability::Ready | ToolRuntimeAvailability::DegradedReadOnly
            )
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
                    mime_type: Some(artifact.mime_type.to_owned()),
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

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn publish_evidence(
        &self,
        artifact_id: ArtifactId,
        task_id: &TaskId,
        artifact_type: &'static str,
        logical_path: String,
        created_by_id: &str,
        digest: &Sha256Digest,
        bytes: &[u8],
        mime_type: &'static str,
    ) -> Result<CanonicalEvidenceRef, PortError> {
        let project_id = self.project_id(task_id)?;
        self.publish_artifact(JournaledToolArtifact {
            artifact_id: &artifact_id,
            task_id,
            project_id: &project_id,
            artifact_type,
            logical_path,
            created_by_id,
            digest: digest.as_str(),
            bytes,
            mime_type,
        })?;
        self.database
            .available_evidence(&artifact_id)?
            .ok_or_else(integrity_failure)
    }

    fn publish_tool_outputs(
        &self,
        task_id: &TaskId,
        execution_id: &ToolExecutionId,
        disclosed: &DisclosedToolExecutionArtifacts,
    ) -> Result<DurableToolExecutionArtifacts, PortError> {
        let project_id = self.project_id(task_id)?;
        let stdout = self.publish_tool_output(
            task_id,
            &project_id,
            execution_id,
            "stdout",
            0,
            "application/octet-stream",
            disclosed.stdout(),
        )?;
        let stderr = self.publish_tool_output(
            task_id,
            &project_id,
            execution_id,
            "stderr",
            0,
            "application/octet-stream",
            disclosed.stderr(),
        )?;
        let observed_writes = disclosed
            .observed_writes()
            .iter()
            .enumerate()
            .map(|(index, output)| {
                self.publish_tool_output(
                    task_id,
                    &project_id,
                    execution_id,
                    "write",
                    index,
                    "application/json",
                    output,
                )
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(DurableToolExecutionArtifacts::new(
            DurableToolExecutionArtifact::Available(stdout),
            DurableToolExecutionArtifact::Available(stderr),
            observed_writes
                .into_iter()
                .map(DurableToolExecutionArtifact::Available)
                .collect(),
        ))
    }

    #[allow(clippy::too_many_arguments)]
    fn publish_tool_output(
        &self,
        task_id: &TaskId,
        project_id: &ProjectId,
        execution_id: &ToolExecutionId,
        kind: &'static str,
        index: usize,
        mime_type: &'static str,
        output: &local_agent_terminal_application::PolicyBoundBytes,
    ) -> Result<ArtifactId, PortError> {
        let artifact_id = ArtifactId::new(format!(
            "tool-output-{kind}-{index}-{}",
            output.policy_decision_id.as_str()
        ))
        .map_err(|_| invalid_input())?;
        self.publish_artifact(JournaledToolArtifact {
            artifact_id: &artifact_id,
            task_id,
            project_id,
            artifact_type: kind,
            logical_path: format!("tool-outputs/{}.bin", artifact_id.as_str()),
            created_by_id: execution_id.as_str(),
            digest: output.digest.as_str(),
            bytes: &output.bytes,
            mime_type,
        })?;
        Ok(artifact_id)
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
            mime_type: "application/json",
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
            mime_type: "application/json",
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
    mime_type: &'static str,
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

const fn runtime_availability_dto(
    availability: ToolRuntimeAvailability,
) -> ToolRuntimeAvailabilityDto {
    match availability {
        ToolRuntimeAvailability::Ready => ToolRuntimeAvailabilityDto::Ready,
        ToolRuntimeAvailability::DegradedReadOnly => ToolRuntimeAvailabilityDto::DegradedReadOnly,
        ToolRuntimeAvailability::Unavailable => ToolRuntimeAvailabilityDto::Unavailable,
    }
}

fn tool_outcome_status(outcome: &ToolOutcome) -> ToolActivityStatusDto {
    match outcome {
        ToolOutcome::ApprovalRequired(_) => ToolActivityStatusDto::ApprovalRequired,
        ToolOutcome::Denied(_) => ToolActivityStatusDto::Denied,
        ToolOutcome::Execution(DurableToolExecutionOutcome::InFlight(_)) => {
            ToolActivityStatusDto::Running
        }
        ToolOutcome::Execution(DurableToolExecutionOutcome::Completed(receipt)) => {
            terminal_status(receipt.terminal().kind())
        }
        ToolOutcome::Execution(
            DurableToolExecutionOutcome::Indeterminate(_)
            | DurableToolExecutionOutcome::TerminalPersistenceUnresolved { .. },
        ) => ToolActivityStatusDto::Indeterminate,
    }
}

const fn terminal_status(kind: ToolExecutionTerminalKind) -> ToolActivityStatusDto {
    match kind {
        ToolExecutionTerminalKind::Succeeded => ToolActivityStatusDto::Succeeded,
        ToolExecutionTerminalKind::Failed => ToolActivityStatusDto::Failed,
        ToolExecutionTerminalKind::Cancelled | ToolExecutionTerminalKind::Terminated => {
            ToolActivityStatusDto::Terminated
        }
        ToolExecutionTerminalKind::Interrupted => ToolActivityStatusDto::Interrupted,
        ToolExecutionTerminalKind::Indeterminate => ToolActivityStatusDto::Indeterminate,
    }
}

fn cancellation_receipt_dto(receipt: &DurableToolExecutionReceipt) -> ToolCancellationReceiptDto {
    let kind = receipt.terminal().kind();
    ToolCancellationReceiptDto {
        execution_id: receipt.authority().execution_id().as_str().to_owned(),
        status: terminal_status(kind),
        cancelled: matches!(
            kind,
            ToolExecutionTerminalKind::Cancelled | ToolExecutionTerminalKind::Terminated
        ),
    }
}

fn valid_sha256_digest(value: &str) -> bool {
    value.len() == 71
        && value.starts_with("sha256:")
        && value[7..]
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
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
