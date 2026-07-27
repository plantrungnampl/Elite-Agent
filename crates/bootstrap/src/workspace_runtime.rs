use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use local_agent_terminal_application::{
    AcquireLease, ActorId, ArtifactId, ArtifactRootMode, CanonicalJsonRequest, Clock,
    ConfirmDiscardWorkspaceRequestDto, CreateTaskWorkspaceRequestDto, CreateWorktree,
    DiscardWorktree, ExecutorLeaseStore, ExpectedPresence, IdempotencyClass, InspectRepository,
    InspectWorktree, IntentTransition, LeaseClaim, LeaseSnapshot, ManagedWorktreePath, NewTask,
    OnboardRepository, OnboardRepositoryRequestDto, OperationIntent, OperationIntentStatus,
    PortError, ProjectSettings, ProjectSnapshot, RecoveryAction, RecoveryCandidate,
    RecoveryCandidateRequestDto, RecoveryOperationIntent, RecoveryProject, RecoveryReason,
    RepositoryGateway, RepositoryHealth, RepositoryInspectionRecord, RepositoryLocator,
    RevokeLease, RiskLevel, RunId, SafeErrorClassification, TaskBranch, TaskQuery, TaskSnapshot,
    TimelineEntryDto, WorkspaceDashboardDto, WorkspaceDashboardRequestDto, WorkspaceRecoveryStore,
    WorkspaceStateStore, WorkspaceWriteCoordinator, WorktreeId, WorktreeIntent,
    WorktreeObservation, WorktreeSnapshot, WorktreeState,
};
use local_agent_terminal_application::{ProjectId, TaskId};
use local_agent_terminal_repository_git::GitRepositoryGateway;
use local_agent_terminal_storage_files::ContentAddressedArtifactStore;
use local_agent_terminal_storage_sqlite::{CoreSystemRunRequest, SqliteStore};
use serde_json::json;

use crate::workspace_monitor::{
    monitorable_phase, publish_canonical_json, WorkspaceMonitor, WorkspacePollOutcome,
};

pub struct WorkspaceRuntime {
    database: SqliteStore,
    artifacts: ContentAddressedArtifactStore,
    repositories: GitRepositoryGateway,
    writes: WorkspaceWriteCoordinator,
    monitor: WorkspaceMonitor,
    recovery_candidates: Vec<RecoveryCandidate>,
    active_claims: Mutex<HashMap<TaskId, LeaseClaim>>,
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
            active_claims: Mutex::new(HashMap::new()),
        }
    }

    pub fn recovery_candidates(&self) -> &[RecoveryCandidate] {
        &self.recovery_candidates
    }

    pub fn acquire_lease(&self, request: AcquireLease) -> Result<LeaseSnapshot, PortError> {
        let lease = self.writes.acquire_lease(&self.database, request)?;
        let claim = LeaseClaim::new(
            lease.task_id.clone(),
            lease.holder_run_id.clone(),
            lease.token,
        );
        self.claims().insert(lease.task_id.clone(), claim);
        Ok(lease)
    }

    pub fn revoke_lease(&self, request: RevokeLease) -> Result<(), PortError> {
        let task_id = request.claim.task_id().clone();
        let claim = request.claim.clone();
        self.writes.revoke_lease(&self.database, request)?;
        if self.claims().get(&task_id) == Some(&claim) {
            self.claims().remove(&task_id);
        }
        Ok(())
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
        let observed_at = self.database.now_utc()?;
        self.poll_workspace_at(task_id, claim, &observed_at)
    }

    fn poll_workspace_at(
        &self,
        task_id: &TaskId,
        claim: LeaseClaim,
        observed_at: &str,
    ) -> Result<Option<local_agent_terminal_application::WorkspaceMutationResult>, PortError> {
        let outcome = match self.monitor.poll(
            &self.database,
            &self.artifacts,
            &self.repositories,
            &self.writes,
            task_id,
            claim.clone(),
        ) {
            Ok(outcome) => outcome,
            Err(error) => {
                return self.finish_with_revoked_lease(claim, observed_at, Err(error));
            }
        };
        match outcome {
            WorkspacePollOutcome::Unchanged => Ok(None),
            WorkspacePollOutcome::Mutated(result) => {
                if self.claims().get(task_id) == Some(&claim) {
                    self.claims().remove(task_id);
                }
                Ok(Some(result))
            }
            WorkspacePollOutcome::RecoveryRequired => {
                if self.claims().get(task_id) == Some(&claim) {
                    self.claims().remove(task_id);
                }
                Ok(None)
            }
        }
    }

    pub fn task(&self, task_id: &TaskId) -> Result<TaskSnapshot, PortError> {
        self.database.task(task_id)
    }

    pub fn timeline(&self, task_id: &TaskId) -> Result<Vec<TimelineEntryDto>, PortError> {
        self.database.timeline(task_id)
    }

    pub fn dashboard(&self, project_id: &ProjectId) -> Result<WorkspaceDashboardDto, PortError> {
        let mut dashboard = self.database.dashboard(project_id)?;
        for task in &mut dashboard.tasks {
            for candidate in &mut task.recovery_candidates {
                if let Some(authoritative) = self
                    .recovery_candidates
                    .iter()
                    .find(|authoritative| same_candidate(authoritative, candidate))
                {
                    *candidate = authoritative.clone();
                }
            }
        }
        dashboard.recovery = dashboard
            .tasks
            .iter()
            .flat_map(|task| task.recovery_candidates.iter().cloned())
            .collect();
        Ok(dashboard)
    }

    pub fn get_workspace_dashboard(
        &self,
        request: WorkspaceDashboardRequestDto,
    ) -> Result<WorkspaceDashboardDto, PortError> {
        let project_id = project_id(&request.project_id)?;
        let dashboard = self.dashboard(&project_id)?;
        let observed_at = self.database.now_utc()?;
        let claims = dashboard
            .tasks
            .iter()
            .filter(|task| {
                monitorable_phase(task.phase)
                    && task.worktree.as_ref().is_some_and(|worktree| {
                        worktree.state == WorktreeState::Present
                            && worktree.expected_presence == ExpectedPresence::Present
                    })
            })
            .map(|task| {
                let existing = self.claims().get(&task.task_id).cloned();
                existing.map_or_else(
                    || self.lease_claim_for_task(&project_id, task, &observed_at),
                    Ok,
                )
            })
            .collect::<Result<Vec<_>, PortError>>()?;
        for claim in claims {
            let task_id = claim.task_id().clone();
            self.poll_workspace_at(&task_id, claim, &observed_at)?;
        }
        self.dashboard(&project_id)
    }

    pub fn onboard_repository(
        &self,
        request: OnboardRepositoryRequestDto,
    ) -> Result<ProjectSnapshot, PortError> {
        validate_text(&request.name, 200)?;
        validate_repository_path(&request.repository_path)?;
        let project_id = project_id(&request.project_id)?;
        let locator = self
            .repositories
            .locate(Path::new(&request.repository_path))?;
        let observed_at = self.database.now_utc()?;
        let project = OnboardRepository::new(&self.repositories, &self.database).execute(
            project_id.clone(),
            request.name,
            observed_at.clone(),
            ProjectSettings {
                policy_profile_id: "default".to_owned(),
                artifact_root_mode: ArtifactRootMode::ApplicationData,
                artifact_root_path: self.artifacts.root().to_string_lossy().into_owned(),
            },
            InspectRepository { locator },
        )?;
        let artifact_id = ArtifactId::new(format!(
            "repository-inspection-{}",
            project.project_id.as_str()
        ))
        .map_err(|_| invalid_input())?;
        let evidence = publish_canonical_json(
            &self.database,
            &self.artifacts,
            CanonicalJsonRequest::new(
                artifact_id,
                project.project_id.clone(),
                None,
                "repository_inspection",
                format!("repository/{}/inspection.json", project.project_id.as_str()),
                "core",
                "workspace-coordinator",
                &repository_evidence(&project.repository),
                format!("repository-inspection:{}", project.project_id.as_str()),
            )?,
        )?;
        self.database
            .record_repository_inspection(RepositoryInspectionRecord {
                project_id: project.project_id,
                repository: project.repository,
                evidence,
                actor_id: ActorId::new("workspace-coordinator").map_err(|_| invalid_input())?,
                correlation_id: format!("repository-inspection:{}", project_id.as_str()),
                observed_at,
            })
    }

    pub fn create_task_workspace(
        &self,
        request: CreateTaskWorkspaceRequestDto,
    ) -> Result<TaskSnapshot, PortError> {
        validate_text(&request.title, 200)?;
        validate_text(&request.objective, 4_000)?;
        let project_id = project_id(&request.project_id)?;
        let task_id = task_id(&request.task_id)?;
        let risk_level = RiskLevel::parse(&request.risk_level).ok_or_else(invalid_input)?;
        let dashboard = self.database.dashboard(&project_id)?;
        if dashboard.repository.health != RepositoryHealth::Healthy
            || !dashboard.repository.hazards.is_empty()
        {
            return Err(invalid_input());
        }
        let base_branch = dashboard
            .repository
            .default_branch
            .clone()
            .ok_or_else(invalid_input)?;
        let base_commit = dashboard
            .repository
            .base_commit
            .clone()
            .ok_or_else(invalid_input)?;
        let project = self.recovery_project(&project_id)?;
        let locator = self
            .repositories
            .locate_persisted(Path::new(&project.repository_path))?;
        let current_repository = self.repositories.inspect(InspectRepository {
            locator: locator.clone(),
        })?;
        if current_repository != dashboard.repository {
            return Err(conflict());
        }
        let observed_at = self.database.now_utc()?;
        let task = match self.database.task(&task_id) {
            Ok(task) => {
                let exact_request = task.project_id == project_id
                    && task.title == request.title
                    && task.objective == request.objective
                    && task.risk_level == risk_level
                    && task.base_branch == base_branch
                    && task.base_commit == base_commit;
                if !exact_request {
                    return Err(conflict());
                }
                if task
                    .worktree
                    .as_ref()
                    .is_some_and(|worktree| worktree.state == WorktreeState::Present)
                {
                    return Ok(task);
                }
                if task.worktree.is_some() || !task.recovery_candidates.is_empty() {
                    return Err(conflict());
                }
                task
            }
            Err(error) if error.safe_classification() == SafeErrorClassification::NotFound => {
                self.database.create_task(NewTask {
                    task_id: task_id.clone(),
                    project_id: project_id.clone(),
                    title: request.title,
                    objective: request.objective,
                    risk_level,
                    base_branch,
                    base_commit: base_commit.clone(),
                    created_at: observed_at.clone(),
                })?
            }
            Err(error) => return Err(error),
        };

        self.ensure_workspace_run(&project_id, &task_id, &observed_at)?;
        let worktree_id = WorktreeId::new(format!("worktree-{}", task_id.as_str()))
            .map_err(|_| invalid_input())?;
        let task_branch =
            TaskBranch::new(format!("codex/{}", task_id.as_str())).map_err(|_| invalid_input())?;
        let target_path_display = format!("<managed-workspace>/{}", worktree_id.as_str());
        let evidence = publish_canonical_json(
            &self.database,
            &self.artifacts,
            CanonicalJsonRequest::new(
                ArtifactId::new(format!("worktree-request-{}", task_id.as_str()))
                    .map_err(|_| invalid_input())?,
                project_id.clone(),
                Some(task_id.clone()),
                "worktree_request",
                format!("workspace/{}/create.json", task_id.as_str()),
                "core",
                "workspace-coordinator",
                &json!({
                    "projectId": project_id.as_str(),
                    "taskId": task_id.as_str(),
                    "worktreeId": worktree_id.as_str(),
                    "branch": task_branch.as_str(),
                    "baseCommit": base_commit.as_str(),
                    "targetPathDisplay": target_path_display,
                }),
                format!("worktree-create:{}", task_id.as_str()),
            )?,
        )?;
        let operation = OperationIntent {
            id: format!("worktree-create-{}", task_id.as_str()),
            task_id: task_id.clone(),
            operation_kind: "worktree.create".to_owned(),
            idempotency_class: local_agent_terminal_application::IdempotencyClass::Queryable,
            idempotency_key: format!("worktree-create:{}", task_id.as_str()),
            canonical_request_artifact_id: evidence.artifact_id,
            operation_digest: evidence.content_hash,
            status: OperationIntentStatus::Pending,
            executor_fencing_token: None,
            attempt_count: 0,
            created_at: observed_at.clone(),
            updated_at: observed_at.clone(),
        };
        let intent = WorktreeIntent {
            operation,
            worktree_id: worktree_id.clone(),
            repository_id: dashboard.repository.repository_id,
            repository_identity: dashboard.repository.stable_identity,
            branch: task_branch.clone(),
            base_commit: base_commit.clone(),
            target_path_display: target_path_display.clone(),
            expected_presence: ExpectedPresence::Present,
        };
        let claim = self.lease_claim_for_task(&project_id, &task, &observed_at)?;
        let result = self.writes.prepare_worktree(
            &self.database,
            &self.repositories,
            &self.database,
            intent,
            CreateWorktree {
                repository: locator,
                managed_path: ManagedWorktreePath {
                    trusted_root_id: self.repositories.trusted_root_id().to_owned(),
                    relative_leaf: PathBuf::from(worktree_id.as_str()),
                    redacted_display: target_path_display,
                },
                task_id: task_id.clone(),
                lease_claim: claim.clone(),
                expected_workspace_version: task.workspace_version,
                worktree_id,
                branch: task_branch,
                base_commit,
            },
            observed_at.clone(),
        );
        if let Err(error) = result {
            return self.finish_with_revoked_lease(claim, &observed_at, Err(error));
        }
        self.database.task(&task_id)
    }

    pub fn reconcile_workspace(
        &self,
        request: RecoveryCandidateRequestDto,
    ) -> Result<WorkspaceDashboardDto, PortError> {
        let (project_id, task, candidate, action) = self.authorize_reconcile(&request)?;
        if action == RecoveryAction::AdoptExactMatch {
            return self.adopt_exact_workspace(&request, project_id, task, candidate);
        }
        let mut expected = candidate.expected_worktree.ok_or_else(invalid_input)?;
        if expected.operation.status != OperationIntentStatus::Interrupted {
            return Err(conflict());
        }
        let observed_at = self.database.now_utc()?;
        let project = self.recovery_project(&project_id)?;
        let locator = self
            .repositories
            .locate_persisted(Path::new(&project.repository_path))?;
        let claim = self.lease_claim_for_task(&project_id, &task, &observed_at)?;
        let recovery = match self.begin_recovery_operation(
            &project_id,
            &task,
            &request.candidate_id,
            RecoveryAction::RetryAfterAuthoritativeAbsence,
            &observed_at,
        ) {
            Ok(recovery) => recovery,
            Err(error) => {
                return self.finish_with_revoked_lease(claim, &observed_at, Err(error));
            }
        };
        if recovery.status != OperationIntentStatus::Pending {
            return self.finish_with_revoked_lease(claim, &observed_at, Err(conflict()));
        }
        let recovery_attempt = match recovery.attempt_count.checked_add(1) {
            Some(attempt) => attempt,
            None => {
                return self.finish_with_revoked_lease(claim, &observed_at, Err(invalid_input()));
            }
        };
        if let Err(error) = self.transition_operation(
            &recovery,
            (
                OperationIntentStatus::Pending,
                OperationIntentStatus::Started,
            ),
            Some(claim.token()),
            recovery_attempt,
            &observed_at,
            None,
        ) {
            return self.finish_with_revoked_lease(claim, &observed_at, Err(error));
        }
        if let Err(error) = self.transition_operation(
            &expected.operation,
            (
                OperationIntentStatus::Interrupted,
                OperationIntentStatus::Pending,
            ),
            Some(claim.token()),
            expected.operation.attempt_count,
            &observed_at,
            None,
        ) {
            let recovery_error = self
                .transition_operation(
                    &recovery,
                    (
                        OperationIntentStatus::Started,
                        OperationIntentStatus::Failed,
                    ),
                    Some(claim.token()),
                    recovery_attempt,
                    &observed_at,
                    Some(error.safe_classification()),
                )
                .err()
                .unwrap_or(error);
            return self.finish_with_revoked_lease(claim, &observed_at, Err(recovery_error));
        }
        expected.operation.status = OperationIntentStatus::Pending;
        let effect = self.writes.prepare_worktree(
            &self.database,
            &self.repositories,
            &self.database,
            expected.clone(),
            CreateWorktree {
                repository: locator,
                managed_path: ManagedWorktreePath {
                    trusted_root_id: self.repositories.trusted_root_id().to_owned(),
                    relative_leaf: PathBuf::from(expected.worktree_id.as_str()),
                    redacted_display: expected.target_path_display.clone(),
                },
                task_id: task.task_id.clone(),
                lease_claim: claim.clone(),
                expected_workspace_version: task.workspace_version,
                worktree_id: expected.worktree_id,
                branch: expected.branch,
                base_commit: expected.base_commit,
            },
            observed_at.clone(),
        );
        let next_status = if effect.is_ok() {
            OperationIntentStatus::Succeeded
        } else {
            OperationIntentStatus::Indeterminate
        };
        if let Err(error) = self.transition_operation(
            &recovery,
            (OperationIntentStatus::Started, next_status),
            Some(claim.token()),
            recovery_attempt,
            &observed_at,
            effect.as_ref().err().map(PortError::safe_classification),
        ) {
            return self.finish_with_revoked_lease(claim, &observed_at, Err(error));
        }
        if let Err(error) = effect {
            return self.finish_with_revoked_lease(claim, &observed_at, Err(error));
        }
        self.dashboard(&project_id)
    }

    fn adopt_exact_workspace(
        &self,
        request: &RecoveryCandidateRequestDto,
        project_id: ProjectId,
        task: TaskSnapshot,
        candidate: RecoveryCandidate,
    ) -> Result<WorkspaceDashboardDto, PortError> {
        let expected = candidate.expected_worktree.ok_or_else(invalid_input)?;
        if expected.operation.status != OperationIntentStatus::Indeterminate {
            return Err(conflict());
        }
        let observed_at = self.database.now_utc()?;
        let project = self.recovery_project(&project_id)?;
        let locator = locate_expected_repository(&self.repositories, &project, &expected)?;
        let claim = self.lease_claim_for_task(&project_id, &task, &observed_at)?;
        let result = (|| {
            let recovery = self.begin_recovery_operation(
                &project_id,
                &task,
                &request.candidate_id,
                RecoveryAction::AdoptExactMatch,
                &observed_at,
            )?;
            if recovery.status != OperationIntentStatus::Pending {
                return Err(conflict());
            }
            let attempt_count = recovery
                .attempt_count
                .checked_add(1)
                .ok_or_else(invalid_input)?;
            self.transition_operation(
                &recovery,
                (
                    OperationIntentStatus::Pending,
                    OperationIntentStatus::Started,
                ),
                Some(claim.token()),
                attempt_count,
                &observed_at,
                None,
            )?;
            self.database.assert_current(claim.clone())?;
            let observation = self.repositories.inspect_worktree(InspectWorktree {
                repository: locator,
                managed_path: ManagedWorktreePath {
                    trusted_root_id: self.repositories.trusted_root_id().to_owned(),
                    relative_leaf: PathBuf::from(expected.worktree_id.as_str()),
                    redacted_display: expected.target_path_display.clone(),
                },
                task_id: task.task_id,
                worktree_id: expected.worktree_id,
                branch: expected.branch,
                base_commit: expected.base_commit,
            });
            let snapshot = match observation {
                Ok(WorktreeObservation::Exact(snapshot))
                    if snapshot.expected_presence == ExpectedPresence::Present =>
                {
                    Ok(snapshot)
                }
                Ok(WorktreeObservation::AuthoritativelyAbsent) => Err(PortError::failure(
                    SafeErrorClassification::NotFound,
                    local_agent_terminal_application::Retryability::NonRetryable,
                )),
                Ok(WorktreeObservation::Conflict(_)) | Ok(WorktreeObservation::Exact(_)) => {
                    Err(conflict())
                }
                Err(error) => Err(error),
            };
            let snapshot = match snapshot {
                Ok(snapshot) => snapshot,
                Err(error) => {
                    self.transition_operation(
                        &recovery,
                        (
                            OperationIntentStatus::Started,
                            OperationIntentStatus::Failed,
                        ),
                        Some(claim.token()),
                        attempt_count,
                        &observed_at,
                        Some(error.safe_classification()),
                    )?;
                    return Err(error);
                }
            };
            self.database.transition_worktree_intent(IntentTransition {
                intent_id: expected.operation.id,
                expected_status: OperationIntentStatus::Indeterminate,
                next_status: OperationIntentStatus::Succeeded,
                executor_fencing_token: Some(claim.token()),
                attempt_count: expected.operation.attempt_count,
                updated_at: observed_at.clone(),
                error: None,
                observed_fingerprint: Some(snapshot.fingerprint),
            })?;
            self.transition_operation(
                &recovery,
                (
                    OperationIntentStatus::Started,
                    OperationIntentStatus::Succeeded,
                ),
                Some(claim.token()),
                attempt_count,
                &observed_at,
                None,
            )
        })();
        self.finish_with_revoked_lease(claim, &observed_at, result)?;
        self.dashboard(&project_id)
    }

    pub fn preserve_workspace(
        &self,
        request: RecoveryCandidateRequestDto,
    ) -> Result<WorkspaceDashboardDto, PortError> {
        let (project_id, task, _) =
            self.authorize_recovery(&request, RecoveryAction::PreserveTask)?;
        let candidate = self.database.operation_intent(&request.candidate_id)?;
        if candidate.task_id != task.task_id {
            return Err(conflict());
        }
        let observed_at = self.database.now_utc()?;
        let claim = self.lease_claim_for_task(&project_id, &task, &observed_at)?;
        let result = (|| {
            let recovery = self.begin_recovery_operation(
                &project_id,
                &task,
                &request.candidate_id,
                RecoveryAction::PreserveTask,
                &observed_at,
            )?;
            if recovery.status != OperationIntentStatus::Pending {
                return Err(conflict());
            }
            let recovery_attempt = recovery
                .attempt_count
                .checked_add(1)
                .ok_or_else(invalid_input)?;
            self.transition_operation(
                &recovery,
                (
                    OperationIntentStatus::Pending,
                    OperationIntentStatus::Started,
                ),
                Some(claim.token()),
                recovery_attempt,
                &observed_at,
                None,
            )?;
            self.transition_operation(
                &candidate,
                (candidate.status, OperationIntentStatus::Cancelled),
                Some(claim.token()),
                candidate.attempt_count,
                &observed_at,
                None,
            )?;
            self.transition_operation(
                &recovery,
                (
                    OperationIntentStatus::Started,
                    OperationIntentStatus::Succeeded,
                ),
                Some(claim.token()),
                recovery_attempt,
                &observed_at,
                None,
            )
        })();
        self.finish_with_revoked_lease(claim, &observed_at, result)?;
        self.dashboard(&project_id)
    }

    pub fn discard_workspace(
        &self,
        request: ConfirmDiscardWorkspaceRequestDto,
    ) -> Result<WorkspaceDashboardDto, PortError> {
        if !request.confirmed {
            return Err(invalid_input());
        }
        let recovery = RecoveryCandidateRequestDto {
            candidate_id: request.candidate_id,
            project_id: request.project_id,
            task_id: request.task_id,
            expected_workspace_version: request.expected_workspace_version,
        };
        let (project_id, task, candidate) =
            self.authorize_recovery(&recovery, RecoveryAction::DiscardExactWorktree)?;
        let expected = candidate.expected_worktree.ok_or_else(invalid_input)?;
        let observed_at = self.database.now_utc()?;
        let project = self.recovery_project(&project_id)?;
        let locator = locate_expected_repository(&self.repositories, &project, &expected)?;
        let claim = self.lease_claim_for_task(&project_id, &task, &observed_at)?;
        let result = (|| {
            let recovery_operation = self.begin_recovery_operation(
                &project_id,
                &task,
                &recovery.candidate_id,
                RecoveryAction::DiscardExactWorktree,
                &observed_at,
            )?;
            if recovery_operation.status != OperationIntentStatus::Pending {
                return Err(conflict());
            }
            let attempt_count = recovery_operation
                .attempt_count
                .checked_add(1)
                .ok_or_else(invalid_input)?;
            self.transition_operation(
                &recovery_operation,
                (
                    OperationIntentStatus::Pending,
                    OperationIntentStatus::Started,
                ),
                Some(claim.token()),
                attempt_count,
                &observed_at,
                None,
            )?;
            let effect = self.writes.discard_worktree(
                &self.database,
                &self.repositories,
                DiscardWorktree {
                    repository: locator,
                    managed_path: ManagedWorktreePath {
                        trusted_root_id: self.repositories.trusted_root_id().to_owned(),
                        relative_leaf: PathBuf::from(expected.worktree_id.as_str()),
                        redacted_display: expected.target_path_display,
                    },
                    task_id: task.task_id.clone(),
                    lease_claim: claim.clone(),
                    expected_workspace_version: task.workspace_version,
                    worktree_id: expected.worktree_id,
                    branch: expected.branch,
                    base_commit: expected.base_commit,
                },
            );
            let next_status = if effect.is_ok() {
                OperationIntentStatus::Succeeded
            } else {
                OperationIntentStatus::Indeterminate
            };
            self.transition_operation(
                &recovery_operation,
                (OperationIntentStatus::Started, next_status),
                Some(claim.token()),
                attempt_count,
                &observed_at,
                effect.as_ref().err().map(PortError::safe_classification),
            )?;
            effect
        })();
        self.finish_with_revoked_lease(claim, &observed_at, result)?;
        self.dashboard(&project_id)
    }

    fn authorize_recovery(
        &self,
        request: &RecoveryCandidateRequestDto,
        required_action: RecoveryAction,
    ) -> Result<(ProjectId, TaskSnapshot, RecoveryCandidate), PortError> {
        let (project_id, task, candidate) = self.recovery_candidate(request)?;
        if !candidate.actions.contains(&required_action) {
            return Err(invalid_input());
        }
        Ok((project_id, task, candidate))
    }

    fn authorize_reconcile(
        &self,
        request: &RecoveryCandidateRequestDto,
    ) -> Result<(ProjectId, TaskSnapshot, RecoveryCandidate, RecoveryAction), PortError> {
        let (project_id, task, candidate) = self.recovery_candidate(request)?;
        let action = if candidate.actions.contains(&RecoveryAction::AdoptExactMatch) {
            RecoveryAction::AdoptExactMatch
        } else if candidate
            .actions
            .contains(&RecoveryAction::RetryAfterAuthoritativeAbsence)
        {
            RecoveryAction::RetryAfterAuthoritativeAbsence
        } else {
            return Err(invalid_input());
        };
        Ok((project_id, task, candidate, action))
    }

    fn recovery_candidate(
        &self,
        request: &RecoveryCandidateRequestDto,
    ) -> Result<(ProjectId, TaskSnapshot, RecoveryCandidate), PortError> {
        validate_candidate_id(&request.candidate_id)?;
        let project_id = project_id(&request.project_id)?;
        let task_id = task_id(&request.task_id)?;
        let task = self.database.task(&task_id)?;
        if task.project_id != project_id
            || task.workspace_version.get() != request.expected_workspace_version
        {
            return Err(conflict());
        }
        let mut candidate = task
            .recovery_candidates
            .iter()
            .find(|candidate| candidate_matches_id(candidate, &request.candidate_id))
            .cloned()
            .ok_or_else(invalid_input)?;
        if let Some(authoritative) = self
            .recovery_candidates
            .iter()
            .find(|authoritative| same_candidate(authoritative, &candidate))
        {
            candidate = authoritative.clone();
        }
        Ok((project_id, task, candidate))
    }

    fn ensure_workspace_run(
        &self,
        project_id: &ProjectId,
        task_id: &TaskId,
        created_at: &str,
    ) -> Result<RunId, PortError> {
        let mut artifacts = Vec::new();
        for role in ["manifest", "content", "config"] {
            artifacts.push(publish_canonical_json(
                &self.database,
                &self.artifacts,
                CanonicalJsonRequest::new(
                    ArtifactId::new(format!("workspace-run-{role}-{}", task_id.as_str()))
                        .map_err(|_| invalid_input())?,
                    project_id.clone(),
                    Some(task_id.clone()),
                    "core_run",
                    format!("runs/{}/{role}.json", task_id.as_str()),
                    "core",
                    "workspace-coordinator",
                    &json!({"kind": "core_workspace_coordinator", "version": 1}),
                    format!("workspace-run:{role}:{}", task_id.as_str()),
                )?,
            )?);
        }
        let run_id = RunId::new(format!("workspace-run-{}", task_id.as_str()))
            .map_err(|_| invalid_input())?;
        self.database.ensure_core_system_run(CoreSystemRunRequest {
            run_id: run_id.clone(),
            task_id: task_id.clone(),
            context_package_id: format!("workspace-context-{}", task_id.as_str()),
            manifest_artifact_id: artifacts[0].artifact_id.clone(),
            effective_content_artifact_id: artifacts[1].artifact_id.clone(),
            run_config_artifact_id: artifacts[2].artifact_id.clone(),
            content_hash: artifacts[0].content_hash.clone(),
            policy_snapshot_digest: artifacts[0].content_hash.clone(),
            connection_binding_digest: artifacts[0].content_hash.clone(),
            idempotency_key: format!("workspace-run:{}", task_id.as_str()),
            created_at: created_at.to_owned(),
        })?;
        Ok(run_id)
    }

    fn begin_recovery_operation(
        &self,
        project_id: &ProjectId,
        task: &TaskSnapshot,
        candidate_id: &str,
        action: RecoveryAction,
        observed_at: &str,
    ) -> Result<OperationIntent, PortError> {
        let action_code = recovery_action_code(action).ok_or_else(invalid_input)?;
        let request_sequence = task.current_sequence.get();
        let operation_id = format!("recovery-{action_code}-{candidate_id}-{request_sequence}");
        let evidence = publish_canonical_json(
            &self.database,
            &self.artifacts,
            CanonicalJsonRequest::new(
                ArtifactId::new(format!(
                    "recovery-request-{action_code}-{candidate_id}-{request_sequence}"
                ))
                .map_err(|_| invalid_input())?,
                project_id.clone(),
                Some(task.task_id.clone()),
                "workspace_recovery_request",
                format!(
                    "workspace/{}/recovery-{action_code}-{request_sequence}.json",
                    task.task_id.as_str(),
                ),
                "core",
                "workspace-coordinator",
                &json!({
                    "candidateId": candidate_id,
                    "projectId": project_id.as_str(),
                    "taskId": task.task_id.as_str(),
                    "expectedWorkspaceVersion": task.workspace_version.get(),
                    "action": action_code,
                }),
                format!("workspace-recovery:{action_code}:{candidate_id}:{request_sequence}"),
            )?,
        )?;
        self.database
            .begin_recovery_intent(RecoveryOperationIntent {
                operation: OperationIntent {
                    id: operation_id,
                    task_id: task.task_id.clone(),
                    operation_kind: format!("workspace.recovery.{action_code}"),
                    idempotency_class: if action == RecoveryAction::PreserveTask {
                        IdempotencyClass::Idempotent
                    } else {
                        IdempotencyClass::Queryable
                    },
                    idempotency_key: format!(
                        "workspace-recovery:{action_code}:{candidate_id}:{request_sequence}"
                    ),
                    canonical_request_artifact_id: evidence.artifact_id,
                    operation_digest: evidence.content_hash,
                    status: OperationIntentStatus::Pending,
                    executor_fencing_token: None,
                    attempt_count: 0,
                    created_at: observed_at.to_owned(),
                    updated_at: observed_at.to_owned(),
                },
                candidate_id: candidate_id.to_owned(),
                action,
                expected_workspace_version: task.workspace_version,
            })
    }

    fn lease_claim_for_task(
        &self,
        project_id: &ProjectId,
        task: &TaskSnapshot,
        observed_at: &str,
    ) -> Result<LeaseClaim, PortError> {
        if let Some(claim) = self.claims().get(&task.task_id).cloned() {
            self.database.assert_current(claim.clone())?;
            return Ok(claim);
        }
        let run_id = self.ensure_workspace_run(project_id, &task.task_id, observed_at)?;
        let lease = self.acquire_lease(AcquireLease {
            task_id: task.task_id.clone(),
            holder_run_id: run_id.clone(),
            expected_fencing_epoch: task.fencing_epoch,
            acquired_at: observed_at.to_owned(),
            expires_at: "9999-12-31T23:59:59Z".to_owned(),
        })?;
        Ok(LeaseClaim::new(task.task_id.clone(), run_id, lease.token))
    }

    fn finish_with_revoked_lease<T>(
        &self,
        claim: LeaseClaim,
        observed_at: &str,
        result: Result<T, PortError>,
    ) -> Result<T, PortError> {
        let revoke = self.revoke_lease(RevokeLease {
            claim: claim.clone(),
            revoked_at: observed_at.to_owned(),
        });
        if revoke.is_err() && self.claims().get(claim.task_id()) == Some(&claim) {
            self.claims().remove(claim.task_id());
        }
        match (result, revoke) {
            (_, Err(error)) => Err(error),
            (result, Ok(())) => result,
        }
    }

    fn transition_operation(
        &self,
        operation: &OperationIntent,
        statuses: (OperationIntentStatus, OperationIntentStatus),
        fencing_token: Option<local_agent_terminal_application::FencingToken>,
        attempt_count: u32,
        observed_at: &str,
        error: Option<SafeErrorClassification>,
    ) -> Result<(), PortError> {
        let (expected_status, next_status) = statuses;
        self.database.transition_worktree_intent(IntentTransition {
            intent_id: operation.id.clone(),
            expected_status,
            next_status,
            executor_fencing_token: fencing_token,
            attempt_count,
            updated_at: observed_at.to_owned(),
            error,
            observed_fingerprint: None,
        })
    }

    fn recovery_project(
        &self,
        project_id: &ProjectId,
    ) -> Result<local_agent_terminal_application::RecoveryProject, PortError> {
        self.database
            .recovery_projects()?
            .into_iter()
            .find(|project| &project.project_id == project_id)
            .ok_or_else(not_found)
    }

    fn claims(&self) -> std::sync::MutexGuard<'_, HashMap<TaskId, LeaseClaim>> {
        self.active_claims
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
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
        let observation =
            observe_expected_worktree(&projects, repositories, &mut scanned, expected);
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

    let completed = projects
        .values()
        .map(|project| database.dashboard(&project.project_id))
        .collect::<Result<Vec<_>, PortError>>()?
        .into_iter()
        .flat_map(|dashboard| dashboard.tasks)
        .flat_map(|task| task.recovery_candidates)
        .filter(|candidate| candidate.reason == RecoveryReason::ExactMatch)
        .filter_map(|candidate| candidate.expected_worktree)
        .collect::<Vec<_>>();
    for expected in completed {
        let observation =
            observe_expected_worktree(&projects, repositories, &mut scanned, &expected);
        let (next_status, error, conflict_reason) = match observation {
            WorktreeObservation::Exact(snapshot)
                if snapshot.expected_presence == ExpectedPresence::Present =>
            {
                continue;
            }
            WorktreeObservation::AuthoritativelyAbsent => (
                OperationIntentStatus::Interrupted,
                SafeErrorClassification::NotFound,
                None,
            ),
            WorktreeObservation::Conflict(reason) => (
                OperationIntentStatus::Indeterminate,
                SafeErrorClassification::Conflict,
                Some(reason),
            ),
            WorktreeObservation::Exact(_) => (
                OperationIntentStatus::Indeterminate,
                SafeErrorClassification::Conflict,
                Some(RecoveryReason::PresenceMismatch),
            ),
        };
        if let Some(reason) = conflict_reason {
            conflicts.insert(expected.operation.id.clone(), reason);
        }
        database.transition_worktree_intent(IntentTransition {
            intent_id: expected.operation.id,
            expected_status: OperationIntentStatus::Succeeded,
            next_status,
            executor_fencing_token: expected.operation.executor_fencing_token,
            attempt_count: expected.operation.attempt_count,
            updated_at: database.now_utc()?,
            error: Some(error),
            observed_fingerprint: None,
        })?;
    }

    let mut recovery_candidates = database.persisted_recovery_candidates()?;
    recovery_candidates.retain(|candidate| candidate.reason != RecoveryReason::ExactMatch);
    for candidate in &mut recovery_candidates {
        let Some(intent_id) = candidate.intent_id.as_ref() else {
            continue;
        };
        if let Some(reason) = conflicts.get(intent_id) {
            candidate.reason = *reason;
        }
        let Some(expected) = candidate
            .expected_worktree
            .as_ref()
            .filter(|expected| {
                expected.operation.status == OperationIntentStatus::Indeterminate
                    && expected.operation.operation_kind == "worktree.create"
            })
            .cloned()
        else {
            continue;
        };
        match observe_expected_worktree(&projects, repositories, &mut scanned, &expected) {
            WorktreeObservation::Exact(snapshot)
                if snapshot.expected_presence == ExpectedPresence::Present =>
            {
                candidate.reason = RecoveryReason::ExactMatch;
                candidate.actions = vec![
                    RecoveryAction::InspectEvidence,
                    RecoveryAction::AdoptExactMatch,
                    RecoveryAction::PreserveTask,
                    RecoveryAction::DiscardExactWorktree,
                ];
            }
            WorktreeObservation::AuthoritativelyAbsent => {
                candidate.reason = RecoveryReason::AuthoritativeAbsence;
                candidate.actions = vec![
                    RecoveryAction::InspectEvidence,
                    RecoveryAction::RetryAfterAuthoritativeAbsence,
                    RecoveryAction::PreserveTask,
                    RecoveryAction::CancelTask,
                ];
            }
            WorktreeObservation::Conflict(reason) => {
                candidate.reason = reason;
                candidate.actions = vec![
                    RecoveryAction::InspectEvidence,
                    RecoveryAction::PreserveTask,
                ];
            }
            WorktreeObservation::Exact(_) => {
                candidate.reason = RecoveryReason::PresenceMismatch;
                candidate.actions = vec![
                    RecoveryAction::InspectEvidence,
                    RecoveryAction::PreserveTask,
                ];
            }
        }
    }
    Ok(WorkspaceRecoveryReport {
        fenced_leases,
        repositories_scanned: scanned.len(),
        recovery_candidates,
    })
}

fn observe_expected_worktree(
    projects: &HashMap<String, RecoveryProject>,
    repositories: &GitRepositoryGateway,
    scanned: &mut HashSet<String>,
    expected: &WorktreeIntent,
) -> WorktreeObservation {
    projects
        .get(expected.repository_id.as_str())
        .and_then(|project| {
            let locator = locate_expected_repository(repositories, project, expected).ok()?;
            scanned.insert(locator.repository_id.as_str().to_owned());
            repositories
                .inspect_worktree(InspectWorktree {
                    repository: locator,
                    managed_path: ManagedWorktreePath {
                        trusted_root_id: repositories.trusted_root_id().to_owned(),
                        relative_leaf: PathBuf::from(expected.worktree_id.as_str()),
                        redacted_display: expected.target_path_display.clone(),
                    },
                    task_id: expected.operation.task_id.clone(),
                    worktree_id: expected.worktree_id.clone(),
                    branch: expected.branch.clone(),
                    base_commit: expected.base_commit.clone(),
                })
                .ok()
        })
        .unwrap_or(WorktreeObservation::Conflict(
            RecoveryReason::RepositoryMismatch,
        ))
}

fn locate_expected_repository(
    repositories: &GitRepositoryGateway,
    project: &RecoveryProject,
    expected: &WorktreeIntent,
) -> Result<RepositoryLocator, PortError> {
    let locator = repositories.locate_persisted(Path::new(&project.repository_path))?;
    if locator.repository_id != expected.repository_id
        || locator.stable_identity != expected.repository_identity
        || locator.repository_id != project.repository.repository_id
        || locator.stable_identity != project.repository.stable_identity
    {
        return Err(conflict());
    }
    Ok(locator)
}

fn repository_evidence(
    repository: &local_agent_terminal_application::RepositorySnapshot,
) -> serde_json::Value {
    json!({
        "repositoryId": repository.repository_id.as_str(),
        "health": repository.health.as_str(),
        "stableIdentity": repository.stable_identity,
        "defaultBranch": repository.default_branch.as_ref().map(TaskBranch::as_str),
        "baseCommit": repository.base_commit.as_ref().map(|commit| commit.as_str()),
        "originalCheckout": repository.original_checkout.as_str(),
        "hazards": repository.hazards.iter().map(|hazard| json!({
            "reason": hazard.reason.as_str(),
            "detail": hazard.detail,
        })).collect::<Vec<_>>(),
        "fingerprint": {
            "head": repository.fingerprint.head().as_str(),
            "indexDigest": repository.fingerprint.index_digest(),
            "statusDigest": repository.fingerprint.status_digest(),
        },
    })
}

fn project_id(value: &str) -> Result<ProjectId, PortError> {
    validate_external_id(value)?;
    ProjectId::new(value).map_err(|_| invalid_input())
}

fn task_id(value: &str) -> Result<TaskId, PortError> {
    validate_external_id(value)?;
    TaskId::new(value).map_err(|_| invalid_input())
}

fn validate_external_id(value: &str) -> Result<(), PortError> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err(invalid_input());
    }
    Ok(())
}

fn validate_candidate_id(value: &str) -> Result<(), PortError> {
    if value.is_empty()
        || value.len() > 512
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err(invalid_input());
    }
    Ok(())
}

fn validate_text(value: &str, max_len: usize) -> Result<(), PortError> {
    if value.trim().is_empty() || value.len() > max_len || value.contains('\0') {
        return Err(invalid_input());
    }
    Ok(())
}

fn validate_repository_path(value: &str) -> Result<(), PortError> {
    if value.trim().is_empty() || value.len() > 32_767 || value.contains('\0') {
        return Err(invalid_input());
    }
    Ok(())
}

fn candidate_matches_id(candidate: &RecoveryCandidate, candidate_id: &str) -> bool {
    candidate.intent_id.as_deref() == Some(candidate_id)
        || candidate
            .worktree_id
            .as_ref()
            .is_some_and(|worktree_id| worktree_id.as_str() == candidate_id)
}

const fn recovery_action_code(action: RecoveryAction) -> Option<&'static str> {
    match action {
        RecoveryAction::AdoptExactMatch | RecoveryAction::RetryAfterAuthoritativeAbsence => {
            Some("reconcile")
        }
        RecoveryAction::PreserveTask => Some("preserve"),
        RecoveryAction::DiscardExactWorktree => Some("discard"),
        RecoveryAction::InspectEvidence | RecoveryAction::CancelTask => None,
    }
}

fn same_candidate(left: &RecoveryCandidate, right: &RecoveryCandidate) -> bool {
    let same_identity = left
        .intent_id
        .as_ref()
        .zip(right.intent_id.as_ref())
        .is_some_and(|(left, right)| left == right)
        || left
            .worktree_id
            .as_ref()
            .zip(right.worktree_id.as_ref())
            .is_some_and(|(left, right)| left == right);
    let same_operation_state = match (&left.expected_worktree, &right.expected_worktree) {
        (Some(left), Some(right)) => left.operation.status == right.operation.status,
        (None, None) => true,
        (Some(_), None) | (None, Some(_)) => false,
    };
    same_identity && same_operation_state
}

fn invalid_input() -> PortError {
    PortError::failure(
        SafeErrorClassification::InvalidInput,
        local_agent_terminal_application::Retryability::NonRetryable,
    )
}

fn conflict() -> PortError {
    PortError::failure(
        SafeErrorClassification::Conflict,
        local_agent_terminal_application::Retryability::NonRetryable,
    )
}

fn not_found() -> PortError {
    PortError::failure(
        SafeErrorClassification::NotFound,
        local_agent_terminal_application::Retryability::NonRetryable,
    )
}
