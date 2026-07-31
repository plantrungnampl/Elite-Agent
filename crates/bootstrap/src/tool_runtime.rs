use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};

use local_agent_terminal_application::{
    ArtifactId, ArtifactWriteReservation, AuthoritativeProcessBinding, Clock,
    DurableToolExecutionReceipt, ImmutableToolRequest, IncompleteToolExecution, NewToolIntent,
    OperationIntentSnapshot, PortError, ProcessStatus, ProjectId, ReservedArtifact, Retryability,
    SafeErrorClassification, SafeToolExecutionError, StructuredToolExecutor, TaskId, TaskQuery,
    ToolApprovalPublication, ToolApprovalRequest, ToolApprovalRequestPublisher,
    ToolExecutionCancellationClaim, ToolExecutionId, ToolExecutionRecoveryState,
    ToolExecutionResolution, ToolExecutionResumeStore, ToolExecutionStore, ToolExecutionTerminal,
    ToolRequestPublisher, WorkspaceEvidenceStore,
};
use local_agent_terminal_storage_files::{ContentAddressedArtifactStore, JournaledArtifactWriter};
use local_agent_terminal_storage_sqlite::SqliteStore;

static NEXT_TEMP_FILE: AtomicU64 = AtomicU64::new(0);

type ToolWorkerResult = Result<DurableToolExecutionReceipt, PortError>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ToolRuntimeAvailability {
    Ready,
    DegradedReadOnly,
    Unavailable,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ToolStartupRecoveryReport {
    pub recovered: usize,
    pub interrupted: usize,
    pub indeterminate: usize,
    pub terminated_retained_jobs: usize,
    pub survivor_inspection_failures: usize,
}

struct ToolRuntimeState {
    dispatch_open: bool,
    availability: ToolRuntimeAvailability,
    recovery_report: Option<ToolStartupRecoveryReport>,
    workers: BTreeMap<ToolExecutionId, JoinHandle<ToolWorkerResult>>,
}

pub struct ToolRuntime {
    executions: Arc<dyn ToolExecutionStore>,
    executor: Arc<dyn StructuredToolExecutor>,
    state: Mutex<ToolRuntimeState>,
    shutdown: Mutex<()>,
}

impl ToolRuntime {
    pub fn new(
        executions: Arc<dyn ToolExecutionStore>,
        executor: Arc<dyn StructuredToolExecutor>,
    ) -> Self {
        Self {
            executions,
            executor,
            state: Mutex::new(ToolRuntimeState {
                dispatch_open: false,
                availability: ToolRuntimeAvailability::Unavailable,
                recovery_report: None,
                workers: BTreeMap::new(),
            }),
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
        let _shutdown = self.shutdown.lock().map_err(|_| internal_failure())?;
        {
            let state = self.state.lock().map_err(|_| internal_failure())?;
            if state.dispatch_open || !state.workers.is_empty() {
                return Err(conflict());
            }
            if let Some(report) = &state.recovery_report {
                return Ok(report.clone());
            }
        }

        let incomplete = self.executions.incomplete()?;
        let mut report = ToolStartupRecoveryReport::default();
        let mut availability = ToolRuntimeAvailability::Ready;
        for incomplete_execution in incomplete {
            let (evidence, explicit_indeterminate) = match incomplete_execution {
                IncompleteToolExecution::InFlight(evidence) => (evidence, false),
                IncompleteToolExecution::Indeterminate(evidence) => (evidence, true),
            };
            validate_recovery_state(&evidence, explicit_indeterminate)?;
            let terminal = match evidence.state {
                ToolExecutionRecoveryState::Claimed => {
                    report.interrupted += 1;
                    Some(ToolExecutionTerminal::interrupted())
                }
                ToolExecutionRecoveryState::Started | ToolExecutionRecoveryState::Indeterminate => {
                    report.indeterminate += 1;
                    match evidence.process_binding.as_ref() {
                        Some(binding) => match self.executor.terminate_retained_process(binding) {
                            Ok(receipt) if exact_termination_receipt(binding, &receipt) => {
                                report.terminated_retained_jobs += 1;
                                availability = degrade(availability);
                                Some(ToolExecutionTerminal::indeterminate(
                                    SafeToolExecutionError {
                                        classification: SafeErrorClassification::Unavailable,
                                        retryability: Retryability::NonRetryable,
                                    },
                                ))
                            }
                            Ok(_) => {
                                report.survivor_inspection_failures += 1;
                                availability = ToolRuntimeAvailability::Unavailable;
                                None
                            }
                            Err(_) => {
                                report.survivor_inspection_failures += 1;
                                availability = ToolRuntimeAvailability::Unavailable;
                                None
                            }
                        },
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
            let Some(terminal) = terminal else {
                continue;
            };
            let resolution = ToolExecutionResolution::new(DurableToolExecutionReceipt::new(
                evidence.authority,
                terminal,
            ));
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
        state.availability = availability;
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

    pub fn dispatch(
        &self,
        execution_id: ToolExecutionId,
        worker: impl FnOnce() -> Result<DurableToolExecutionReceipt, PortError> + Send + 'static,
    ) -> Result<(), PortError> {
        let mut state = self.state.lock().map_err(|_| internal_failure())?;
        if !state.dispatch_open
            || state.availability != ToolRuntimeAvailability::Ready
            || state.workers.contains_key(&execution_id)
        {
            return Err(conflict());
        }
        let handle = thread::Builder::new()
            .spawn(worker)
            .map_err(|_| unavailable())?;
        state.workers.insert(execution_id, handle);
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
        let mut authorities = BTreeMap::new();
        let mut completed = BTreeMap::new();
        let mut cancellation_errors = BTreeMap::new();
        let mut first_error = None;
        for execution_id in workers.keys() {
            match self.executions.request_cancellation(execution_id) {
                Ok(ToolExecutionCancellationClaim::Claimed(authority)) => {
                    authorities.insert(execution_id.clone(), authority);
                    match self.executor.cancel(execution_id) {
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
            let worker_receipt = match worker.join() {
                Ok(Ok(receipt)) => Some(receipt),
                Ok(Err(worker_error)) => match authorities.remove(&execution_id) {
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
                Err(_) => match authorities.remove(&execution_id) {
                    Some(authority) => {
                        let error = cancellation_errors
                            .remove(&execution_id)
                            .unwrap_or_else(internal_failure);
                        Some(indeterminate_receipt(authority, &error))
                    }
                    None => {
                        let error = cancellation_errors
                            .remove(&execution_id)
                            .unwrap_or_else(internal_failure);
                        record_first_error(&mut first_error, error);
                        None
                    }
                },
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

fn exact_termination_receipt(
    binding: &AuthoritativeProcessBinding,
    receipt: &local_agent_terminal_application::CancellationReceipt,
) -> bool {
    receipt.execution_id == *binding.authority().execution_id()
        && receipt.status == ProcessStatus::Terminated
        && receipt.cancelled
        && receipt.job_receipt.as_ref().is_some_and(|job| {
            job.root_pid == binding.root_pid()
                && job.job_id == binding.job_id()
                && job.kill_on_close
                && job.no_breakaway
                && job.tree_terminated
        })
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
