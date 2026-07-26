use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use local_agent_terminal_application::{
    AcquireLease, Clock, CreateWorktree, DiscardWorktree, ExecutorLeaseStore, ExpectedPresence,
    InspectWorktree, IntentTransition, LeaseClaim, LeaseSnapshot, ManagedWorktreePath,
    OperationIntentStatus, PortError, RecoveryCandidate, RecoveryReason, RepositoryGateway,
    RevokeLease, SafeErrorClassification, TaskQuery, TaskSnapshot, TimelineEntryDto,
    WorkspaceDashboardDto, WorkspaceRecoveryStore, WorkspaceStateStore, WorkspaceWriteCoordinator,
    WorktreeIntent, WorktreeObservation, WorktreeSnapshot,
};
use local_agent_terminal_application::{ProjectId, TaskId};
use local_agent_terminal_repository_git::GitRepositoryGateway;
use local_agent_terminal_storage_files::ContentAddressedArtifactStore;
use local_agent_terminal_storage_sqlite::SqliteStore;

use crate::workspace_monitor::WorkspaceMonitor;

pub struct WorkspaceRuntime {
    database: SqliteStore,
    artifacts: ContentAddressedArtifactStore,
    repositories: GitRepositoryGateway,
    writes: WorkspaceWriteCoordinator,
    monitor: WorkspaceMonitor,
    recovery_candidates: Vec<RecoveryCandidate>,
}

pub(crate) struct WorkspaceRecoveryReport {
    pub(crate) fenced_leases: usize,
    pub(crate) repositories_scanned: usize,
    pub(crate) recovery_candidates: Vec<RecoveryCandidate>,
}

impl WorkspaceRuntime {
    pub(crate) fn new(
        database: SqliteStore,
        artifacts: ContentAddressedArtifactStore,
        repositories: GitRepositoryGateway,
        recovery_candidates: Vec<RecoveryCandidate>,
    ) -> Self {
        Self {
            database,
            artifacts,
            repositories,
            writes: WorkspaceWriteCoordinator::new(),
            monitor: WorkspaceMonitor,
            recovery_candidates,
        }
    }

    pub fn recovery_candidates(&self) -> &[RecoveryCandidate] {
        &self.recovery_candidates
    }

    pub fn acquire_lease(&self, request: AcquireLease) -> Result<LeaseSnapshot, PortError> {
        self.writes.acquire_lease(&self.database, request)
    }

    pub fn revoke_lease(&self, request: RevokeLease) -> Result<(), PortError> {
        self.writes.revoke_lease(&self.database, request)
    }

    pub fn prepare_worktree(
        &self,
        intent: WorktreeIntent,
        request: CreateWorktree,
        observed_at: String,
    ) -> Result<WorktreeSnapshot, PortError> {
        self.writes.prepare_worktree(
            &self.database,
            &self.repositories,
            &self.database,
            intent,
            request,
            observed_at,
        )
    }

    pub fn discard_worktree(&self, request: DiscardWorktree) -> Result<(), PortError> {
        self.writes
            .discard_worktree(&self.database, &self.repositories, request)
    }

    pub fn poll_workspace(
        &self,
        task_id: &TaskId,
        claim: LeaseClaim,
    ) -> Result<Option<local_agent_terminal_application::WorkspaceMutationResult>, PortError> {
        self.monitor.poll(
            &self.database,
            &self.artifacts,
            &self.repositories,
            &self.writes,
            task_id,
            claim,
        )
    }

    pub fn task(&self, task_id: &TaskId) -> Result<TaskSnapshot, PortError> {
        self.database.task(task_id)
    }

    pub fn timeline(&self, task_id: &TaskId) -> Result<Vec<TimelineEntryDto>, PortError> {
        self.database.timeline(task_id)
    }

    pub fn dashboard(&self, project_id: &ProjectId) -> Result<WorkspaceDashboardDto, PortError> {
        self.database.dashboard(project_id)
    }
}

pub(crate) fn reconcile_startup(
    database: &SqliteStore,
    repositories: &GitRepositoryGateway,
) -> Result<WorkspaceRecoveryReport, PortError> {
    let fenced_leases = database.fence_stale()?.len();
    let started = database.started_recoveries()?;
    let projects = database
        .recovery_projects()?
        .into_iter()
        .map(|project| {
            (
                project.repository.repository_id.as_str().to_owned(),
                project,
            )
        })
        .collect::<HashMap<_, _>>();
    let mut observations = HashMap::new();
    let mut scanned = HashSet::new();

    for recovery in &started {
        let Some(expected) = recovery.candidate.expected_worktree.as_ref() else {
            continue;
        };
        let observation = projects
            .get(expected.repository_id.as_str())
            .and_then(|project| {
                let locator = repositories
                    .locate(Path::new(&project.repository_path))
                    .ok()?;
                if locator.repository_id != project.repository.repository_id
                    || locator.stable_identity != project.repository.stable_identity
                {
                    return Some(WorktreeObservation::Conflict(
                        RecoveryReason::RepositoryMismatch,
                    ));
                }
                scanned.insert(locator.repository_id.as_str().to_owned());
                let managed_path = ManagedWorktreePath {
                    trusted_root_id: repositories.trusted_root_id().to_owned(),
                    relative_leaf: PathBuf::from(expected.worktree_id.as_str()),
                    redacted_display: expected.target_path_display.clone(),
                };
                repositories
                    .inspect_worktree(InspectWorktree {
                        repository: locator,
                        managed_path,
                        task_id: expected.operation.task_id.clone(),
                        worktree_id: expected.worktree_id.clone(),
                        branch: expected.branch.clone(),
                        base_commit: expected.base_commit.clone(),
                    })
                    .ok()
            })
            .unwrap_or(WorktreeObservation::Conflict(
                RecoveryReason::RepositoryMismatch,
            ));
        observations.insert(recovery.operation.id.clone(), observation);
    }

    let mut conflicts = HashMap::new();
    for recovery in started {
        let (next, observed_fingerprint) = if recovery.candidate.expected_worktree.is_none() {
            (Some((OperationIntentStatus::Indeterminate, None)), None)
        } else {
            match observations.remove(&recovery.operation.id) {
                Some(WorktreeObservation::Exact(snapshot))
                    if snapshot.expected_presence == ExpectedPresence::Present =>
                {
                    (
                        Some((OperationIntentStatus::Succeeded, None)),
                        Some(snapshot.fingerprint),
                    )
                }
                Some(WorktreeObservation::AuthoritativelyAbsent) => (
                    Some((
                        OperationIntentStatus::Interrupted,
                        Some(SafeErrorClassification::NotFound),
                    )),
                    None,
                ),
                Some(WorktreeObservation::Conflict(reason)) => {
                    conflicts.insert(recovery.operation.id.clone(), reason);
                    (None, None)
                }
                Some(WorktreeObservation::Exact(_)) | None => (None, None),
            }
        };
        if let Some((next_status, error)) = next {
            database.transition_worktree_intent(IntentTransition {
                intent_id: recovery.operation.id,
                expected_status: OperationIntentStatus::Started,
                next_status,
                executor_fencing_token: recovery.operation.executor_fencing_token,
                attempt_count: recovery.operation.attempt_count,
                updated_at: database.now_utc()?,
                error,
                observed_fingerprint,
            })?;
        }
    }

    let mut recovery_candidates = database.persisted_recovery_candidates()?;
    for candidate in &mut recovery_candidates {
        let Some(intent_id) = candidate.intent_id.as_ref() else {
            continue;
        };
        if let Some(reason) = conflicts.get(intent_id) {
            candidate.reason = *reason;
        }
    }
    Ok(WorkspaceRecoveryReport {
        fenced_leases,
        repositories_scanned: scanned.len(),
        recovery_candidates,
    })
}
