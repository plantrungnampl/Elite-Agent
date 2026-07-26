use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use local_agent_terminal_application::{
    canonical_evidence, AcquireExecutorLease, AcquireLease, ArtifactRef, ArtifactRootMode,
    CanonicalJsonRequest, CreateWorktree, DiscardWorktree, EvidenceSummaryDto, ExecutorLeaseStore,
    ExpectedPresence, GetWorkspaceDashboard, IdempotencyClass, InspectRepository, IntentTransition,
    LeaseSnapshot, LeaseState, ManagedWorktreePath, NewProject, NewTask, ObjectFormat,
    ObserveWorkspaceMutation, OnboardRepository, OperationIntent, OperationIntentStatus,
    OriginalCheckoutState, PortError, PrepareTaskWorkspace, ProjectSettings, ProjectSnapshot,
    RecoveryAction, RecoveryCandidate, RecoveryEvidence, RecoveryReason, RepositoryGateway,
    RepositoryHealth, RepositoryInspectionRecord, RepositoryLocator, RepositorySnapshot,
    RevokeLease, RiskLevel, SafeErrorClassification, TaskLeaseState, TaskQuery, TaskSnapshot,
    TimelineEntryDto, WorkspaceDashboardDto, WorkspaceMutationRequest, WorkspaceMutationResult,
    WorkspaceMutationStore, WorkspaceStateStore, WorktreeIntent, WorktreeMatch, WorktreeSnapshot,
    WorktreeState,
};
use local_agent_terminal_domain::{
    ActorId, ArtifactId, Condition, EventId, FencingToken, GitObjectId, LeaseClaim, OperationState,
    Phase, ProjectId, RepositoryId, RunId, Sequence, TaskBranch, TaskId, WorkspaceFingerprint,
    WorkspaceVersion, WorktreeId,
};
use serde_json::json;

const SHA1: &str = "1111111111111111111111111111111111111111";
const SHA256_A: &str = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const SHA256_B: &str = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

fn fingerprint() -> WorkspaceFingerprint {
    WorkspaceFingerprint::new(GitObjectId::new(SHA1).unwrap(), SHA256_A, SHA256_B).unwrap()
}

fn repository_locator() -> RepositoryLocator {
    RepositoryLocator {
        repository_id: RepositoryId::new("repository-1").unwrap(),
        stable_identity: "repo-identity-1".to_owned(),
        canonical_workdir: PathBuf::from(r"D:\source\project"),
        canonical_common_dir: PathBuf::from(r"D:\source\project\.git"),
        object_format: ObjectFormat::Sha1,
    }
}

fn repository_snapshot() -> RepositorySnapshot {
    RepositorySnapshot {
        repository_id: RepositoryId::new("repository-1").unwrap(),
        health: RepositoryHealth::Healthy,
        stable_identity: "repo-identity-1".to_owned(),
        default_branch: Some(TaskBranch::new("main").unwrap()),
        base_commit: Some(GitObjectId::new(SHA1).unwrap()),
        original_checkout: OriginalCheckoutState::Clean,
        hazards: Vec::new(),
        fingerprint: fingerprint(),
    }
}

fn managed_path() -> ManagedWorktreePath {
    ManagedWorktreePath {
        trusted_root_id: "workspace-root-1".to_owned(),
        relative_leaf: PathBuf::from("task-1"),
        redacted_display: "<workspace>/task-1".to_owned(),
    }
}

fn lease_claim(token: u64) -> LeaseClaim {
    LeaseClaim::new(
        TaskId::new("task-1").unwrap(),
        RunId::new("run-1").unwrap(),
        FencingToken::new(token).unwrap(),
    )
}

fn worktree_snapshot() -> WorktreeSnapshot {
    WorktreeSnapshot {
        worktree_id: WorktreeId::new("worktree-1").unwrap(),
        repository_id: RepositoryId::new("repository-1").unwrap(),
        repository_identity: "repo-identity-1".to_owned(),
        task_id: TaskId::new("task-1").unwrap(),
        branch: TaskBranch::new("codex/task-1").unwrap(),
        base_commit: GitObjectId::new(SHA1).unwrap(),
        target_path_display: "<workspace>/task-1".to_owned(),
        state: WorktreeState::Present,
        expected_presence: ExpectedPresence::Present,
        fingerprint: fingerprint(),
    }
}

fn task_snapshot() -> TaskSnapshot {
    TaskSnapshot {
        task_id: TaskId::new("task-1").unwrap(),
        project_id: ProjectId::new("project-1").unwrap(),
        title: "Implement repository recovery".to_owned(),
        objective: "Keep Git effects isolated".to_owned(),
        risk_level: RiskLevel::High,
        phase: Phase::Intake,
        condition: Condition::Active,
        operation_state: OperationState::None,
        base_branch: TaskBranch::new("main").unwrap(),
        base_commit: GitObjectId::new(SHA1).unwrap(),
        task_branch: Some(TaskBranch::new("codex/task-1").unwrap()),
        worktree: Some(worktree_snapshot()),
        current_sequence: Sequence::new(0),
        workspace_version: WorkspaceVersion::new(0),
        fencing_epoch: 1,
        lease_state: TaskLeaseState::Active,
        recovery_candidates: Vec::new(),
    }
}

fn operation_intent(class: IdempotencyClass) -> OperationIntent {
    OperationIntent {
        id: "intent-1".to_owned(),
        task_id: TaskId::new("task-1").unwrap(),
        operation_kind: "worktree.create".to_owned(),
        idempotency_class: class,
        idempotency_key: "worktree:create:task-1".to_owned(),
        canonical_request_artifact_id: ArtifactId::new("artifact-request-1").unwrap(),
        operation_digest: SHA256_A.to_owned(),
        status: OperationIntentStatus::Pending,
        executor_fencing_token: None,
        attempt_count: 0,
        created_at: "2026-07-26T00:00:00Z".to_owned(),
        updated_at: "2026-07-26T00:00:00Z".to_owned(),
    }
}

fn worktree_intent() -> WorktreeIntent {
    WorktreeIntent {
        operation: operation_intent(IdempotencyClass::Queryable),
        worktree_id: WorktreeId::new("worktree-1").unwrap(),
        repository_id: RepositoryId::new("repository-1").unwrap(),
        repository_identity: "repo-identity-1".to_owned(),
        branch: TaskBranch::new("codex/task-1").unwrap(),
        base_commit: GitObjectId::new(SHA1).unwrap(),
        target_path_display: "<workspace>/task-1".to_owned(),
        expected_presence: ExpectedPresence::Present,
    }
}

#[derive(Clone)]
struct FakeRepositoryGateway {
    calls: Arc<Mutex<Vec<&'static str>>>,
}

impl RepositoryGateway for FakeRepositoryGateway {
    fn inspect(&self, _request: InspectRepository) -> Result<RepositorySnapshot, PortError> {
        self.calls.lock().unwrap().push("inspect");
        Ok(repository_snapshot())
    }

    fn create_worktree(&self, _request: CreateWorktree) -> Result<WorktreeSnapshot, PortError> {
        self.calls.lock().unwrap().push("create_worktree");
        Ok(worktree_snapshot())
    }

    fn list_worktrees(
        &self,
        _repository: &RepositoryLocator,
    ) -> Result<Vec<WorktreeSnapshot>, PortError> {
        self.calls.lock().unwrap().push("list_worktrees");
        Ok(vec![worktree_snapshot()])
    }

    fn discard_worktree(&self, _request: DiscardWorktree) -> Result<(), PortError> {
        self.calls.lock().unwrap().push("discard_worktree");
        Ok(())
    }
}

#[derive(Clone)]
struct FakeWorkspaceStateStore {
    calls: Arc<Mutex<Vec<&'static str>>>,
}

impl WorkspaceStateStore for FakeWorkspaceStateStore {
    fn create_project(&self, project: NewProject) -> Result<ProjectSnapshot, PortError> {
        self.calls.lock().unwrap().push("create_project");
        Ok(ProjectSnapshot {
            project_id: project.project_id,
            name: project.name,
            repository: project.repository,
            repository_path: project.repository_path,
            settings: project.settings,
            repository_evidence_artifact_id: None,
            created_at: project.created_at,
        })
    }

    fn record_repository_inspection(
        &self,
        inspection: RepositoryInspectionRecord,
    ) -> Result<ProjectSnapshot, PortError> {
        self.calls
            .lock()
            .unwrap()
            .push("record_repository_inspection");
        Ok(ProjectSnapshot {
            project_id: inspection.project_id,
            name: "Local Agent Terminal".to_owned(),
            repository: inspection.repository,
            repository_path: r"D:\source\project".to_owned(),
            settings: ProjectSettings {
                policy_profile_id: "default".to_owned(),
                artifact_root_mode: ArtifactRootMode::ApplicationData,
                artifact_root_path: r"D:\application-data\artifacts".to_owned(),
            },
            repository_evidence_artifact_id: Some(inspection.evidence.artifact_id),
            created_at: "2026-07-26T00:00:00Z".to_owned(),
        })
    }

    fn create_task(&self, _task: NewTask) -> Result<TaskSnapshot, PortError> {
        self.calls.lock().unwrap().push("create_task");
        Ok(task_snapshot())
    }

    fn begin_worktree_intent(&self, intent: WorktreeIntent) -> Result<OperationIntent, PortError> {
        self.calls.lock().unwrap().push("begin_intent");
        Ok(intent.operation)
    }

    fn transition_worktree_intent(&self, transition: IntentTransition) -> Result<(), PortError> {
        if matches!(
            transition.next_status,
            OperationIntentStatus::Started
                | OperationIntentStatus::Succeeded
                | OperationIntentStatus::Failed
        ) {
            assert_eq!(
                transition.executor_fencing_token.unwrap().get(),
                1,
                "worktree effects must retain the current fencing token"
            );
        }
        self.calls
            .lock()
            .unwrap()
            .push(match transition.next_status {
                OperationIntentStatus::Started => "start_intent",
                OperationIntentStatus::Succeeded => "succeed_intent",
                OperationIntentStatus::Failed => "fail_intent",
                _ => "other_intent_transition",
            });
        Ok(())
    }

    fn reconcile_intents(&self) -> Result<Vec<RecoveryCandidate>, PortError> {
        self.calls.lock().unwrap().push("reconcile_intents");
        Ok(Vec::new())
    }

    fn dashboard(&self, project: &ProjectId) -> Result<WorkspaceDashboardDto, PortError> {
        self.calls.lock().unwrap().push("dashboard");
        Ok(WorkspaceDashboardDto {
            project_id: project.clone(),
            repository: repository_snapshot(),
            tasks: vec![task_snapshot()],
            recovery: Vec::new(),
        })
    }
}

#[test]
fn repository_onboarding_returns_typed_health_without_exposing_handles() {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let repositories = FakeRepositoryGateway {
        calls: Arc::clone(&calls),
    };
    let workspaces = FakeWorkspaceStateStore {
        calls: Arc::clone(&calls),
    };
    let use_case = OnboardRepository::new(&repositories, &workspaces);

    let project = use_case
        .execute(
            ProjectId::new("project-1").unwrap(),
            "Local Agent Terminal".to_owned(),
            "2026-07-26T00:00:00Z".to_owned(),
            ProjectSettings {
                policy_profile_id: "default".to_owned(),
                artifact_root_mode: ArtifactRootMode::ApplicationData,
                artifact_root_path: r"D:\application-data\artifacts".to_owned(),
            },
            InspectRepository {
                locator: repository_locator(),
            },
        )
        .unwrap();

    assert_eq!(*calls.lock().unwrap(), ["inspect", "create_project"]);
    assert_eq!(project.repository.health, RepositoryHealth::Healthy);
    assert_eq!(project.repository.default_branch.unwrap().as_str(), "main");
    assert_eq!(project.repository.base_commit.unwrap().as_str(), SHA1);
    assert_eq!(
        project.repository.original_checkout,
        OriginalCheckoutState::Clean
    );
    assert!(project.repository.hazards.is_empty());
}

#[test]
fn prepare_workspace_persists_and_starts_intent_before_git_create() {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let repositories = FakeRepositoryGateway {
        calls: Arc::clone(&calls),
    };
    let workspaces = FakeWorkspaceStateStore {
        calls: Arc::clone(&calls),
    };
    let leases = FakeLeaseStore::new();
    leases
        .acquire(AcquireLease {
            task_id: TaskId::new("task-1").unwrap(),
            holder_run_id: RunId::new("run-1").unwrap(),
            expected_fencing_epoch: 0,
            acquired_at: "2026-07-26T00:00:00Z".to_owned(),
            expires_at: "2026-07-26T00:05:00Z".to_owned(),
        })
        .unwrap();
    let use_case = PrepareTaskWorkspace::new(&workspaces, &repositories, &leases);

    let result = use_case
        .execute(
            worktree_intent(),
            CreateWorktree {
                repository: repository_locator(),
                managed_path: managed_path(),
                task_id: TaskId::new("task-1").unwrap(),
                lease_claim: lease_claim(1),
                expected_workspace_version: WorkspaceVersion::new(0),
                worktree_id: WorktreeId::new("worktree-1").unwrap(),
                branch: TaskBranch::new("codex/task-1").unwrap(),
                base_commit: GitObjectId::new(SHA1).unwrap(),
            },
            "2026-07-26T00:00:01Z".to_owned(),
        )
        .unwrap();

    assert_eq!(result.worktree_id.as_str(), "worktree-1");
    assert_eq!(
        *calls.lock().unwrap(),
        [
            "begin_intent",
            "start_intent",
            "create_worktree",
            "succeed_intent"
        ]
    );
}

#[test]
fn stale_worktree_create_claim_is_rejected_before_repository_effect() {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let repositories = FakeRepositoryGateway {
        calls: Arc::clone(&calls),
    };
    let workspaces = FakeWorkspaceStateStore {
        calls: Arc::clone(&calls),
    };
    let leases = FakeLeaseStore::new();
    let first = leases
        .acquire(AcquireLease {
            task_id: TaskId::new("task-1").unwrap(),
            holder_run_id: RunId::new("run-1").unwrap(),
            expected_fencing_epoch: 0,
            acquired_at: "2026-07-26T00:00:00Z".to_owned(),
            expires_at: "2026-07-26T00:05:00Z".to_owned(),
        })
        .unwrap();
    leases
        .revoke(RevokeLease {
            claim: LeaseClaim::new(
                first.task_id.clone(),
                first.holder_run_id.clone(),
                first.token,
            ),
            revoked_at: "2026-07-26T00:01:00Z".to_owned(),
        })
        .unwrap();

    let result = PrepareTaskWorkspace::new(&workspaces, &repositories, &leases).execute(
        worktree_intent(),
        CreateWorktree {
            repository: repository_locator(),
            managed_path: managed_path(),
            task_id: TaskId::new("task-1").unwrap(),
            lease_claim: lease_claim(1),
            expected_workspace_version: WorkspaceVersion::new(0),
            worktree_id: WorktreeId::new("worktree-1").unwrap(),
            branch: TaskBranch::new("codex/task-1").unwrap(),
            base_commit: GitObjectId::new(SHA1).unwrap(),
        },
        "2026-07-26T00:00:01Z".to_owned(),
    );

    assert!(matches!(
        result,
        Err(PortError::StaleLease {
            current,
            supplied
        }) if current.get() == 1 && supplied.get() == 1
    ));
    assert_eq!(
        *calls.lock().unwrap(),
        ["begin_intent", "start_intent", "fail_intent"]
    );
}

#[test]
fn exact_worktree_observation_matches_but_each_identity_mismatch_conflicts() {
    let intent = worktree_intent();
    let exact = worktree_snapshot();
    assert_eq!(intent.compare_observation(&exact), WorktreeMatch::Exact);

    let mut mismatch = exact.clone();
    mismatch.branch = TaskBranch::new("codex/other").unwrap();
    assert_eq!(
        intent.compare_observation(&mismatch),
        WorktreeMatch::Conflict(RecoveryReason::BranchMismatch)
    );

    mismatch = exact.clone();
    mismatch.base_commit = GitObjectId::new("2222222222222222222222222222222222222222").unwrap();
    assert_eq!(
        intent.compare_observation(&mismatch),
        WorktreeMatch::Conflict(RecoveryReason::BaseCommitMismatch)
    );

    mismatch = exact;
    mismatch.target_path_display = "<workspace>/other".to_owned();
    assert_eq!(
        intent.compare_observation(&mismatch),
        WorktreeMatch::Conflict(RecoveryReason::PathMismatch)
    );

    mismatch = worktree_snapshot();
    mismatch.state = WorktreeState::Conflict;
    assert_eq!(
        intent.compare_observation(&mismatch),
        WorktreeMatch::Conflict(RecoveryReason::PresenceMismatch)
    );
}

struct FakeLeaseStore {
    lease: Mutex<Option<LeaseSnapshot>>,
    last_token: Mutex<u64>,
}

impl FakeLeaseStore {
    fn new() -> Self {
        Self {
            lease: Mutex::new(None),
            last_token: Mutex::new(0),
        }
    }
}

impl ExecutorLeaseStore for FakeLeaseStore {
    fn acquire(&self, request: AcquireLease) -> Result<LeaseSnapshot, PortError> {
        let mut lease = self.lease.lock().unwrap();
        if lease
            .as_ref()
            .is_some_and(|current| current.state == LeaseState::Active)
        {
            return Err(PortError::failure(
                SafeErrorClassification::Conflict,
                local_agent_terminal_application::Retryability::NonRetryable,
            ));
        }

        let mut last_token = self.last_token.lock().unwrap();
        if request.expected_fencing_epoch != *last_token {
            return Err(PortError::stale_lease(
                FencingToken::new(*last_token).unwrap(),
                FencingToken::new(request.expected_fencing_epoch.max(1)).unwrap(),
            ));
        }
        *last_token += 1;
        let acquired = LeaseSnapshot {
            task_id: request.task_id,
            holder_run_id: request.holder_run_id,
            token: FencingToken::new(*last_token).unwrap(),
            state: LeaseState::Active,
            acquired_at: request.acquired_at,
            expires_at: request.expires_at,
            released_at: None,
        };
        *lease = Some(acquired.clone());
        Ok(acquired)
    }

    fn revoke(&self, request: RevokeLease) -> Result<(), PortError> {
        let mut lease = self.lease.lock().unwrap();
        let current = lease.as_mut().ok_or_else(|| {
            PortError::failure(
                SafeErrorClassification::Conflict,
                local_agent_terminal_application::Retryability::NonRetryable,
            )
        })?;
        if current.token != request.claim.token() {
            return Err(PortError::stale_lease(current.token, request.claim.token()));
        }
        current.state = LeaseState::Revoked;
        current.released_at = Some(request.revoked_at);
        Ok(())
    }

    fn fence_stale(&self) -> Result<Vec<LeaseSnapshot>, PortError> {
        Ok(Vec::new())
    }

    fn assert_current(&self, claim: LeaseClaim) -> Result<(), PortError> {
        let lease = self.lease.lock().unwrap();
        let current = lease.as_ref().ok_or_else(|| {
            PortError::failure(
                SafeErrorClassification::Conflict,
                local_agent_terminal_application::Retryability::NonRetryable,
            )
        })?;
        if current.task_id != *claim.task_id()
            || current.holder_run_id != *claim.holder_run_id()
            || current.token != claim.token()
            || current.state != LeaseState::Active
        {
            return Err(PortError::stale_lease(current.token, claim.token()));
        }
        Ok(())
    }
}

#[test]
fn lease_has_one_winner_increasing_replacement_tokens_and_typed_stale_rejection() {
    let store = Arc::new(FakeLeaseStore::new());
    let acquire = |run: &str, expected_fencing_epoch| AcquireLease {
        task_id: TaskId::new("task-1").unwrap(),
        holder_run_id: RunId::new(run).unwrap(),
        expected_fencing_epoch,
        acquired_at: "2026-07-26T00:00:00Z".to_owned(),
        expires_at: "2026-07-26T00:05:00Z".to_owned(),
    };

    let contenders = ["run-1", "run-2"].map(|run| {
        let store = Arc::clone(&store);
        std::thread::spawn(move || {
            AcquireExecutorLease::new(store.as_ref()).execute(acquire(run, 0))
        })
    });
    let outcomes: Vec<_> = contenders
        .into_iter()
        .map(|thread| thread.join().unwrap())
        .collect();
    assert_eq!(outcomes.iter().filter(|outcome| outcome.is_ok()).count(), 1);

    let first = outcomes.into_iter().find_map(Result::ok).unwrap();
    store
        .revoke(RevokeLease {
            claim: LeaseClaim::new(
                first.task_id.clone(),
                first.holder_run_id.clone(),
                first.token,
            ),
            revoked_at: "2026-07-26T00:01:00Z".to_owned(),
        })
        .unwrap();
    let replacement = store.acquire(acquire("run-3", 1)).unwrap();
    assert_eq!(replacement.token.get(), 2);

    let stale = store.assert_current(LeaseClaim::new(
        first.task_id,
        first.holder_run_id,
        first.token,
    ));
    assert!(matches!(stale, Err(PortError::StaleLease { .. })));
    assert_eq!(
        stale.unwrap_err().safe_classification(),
        SafeErrorClassification::Conflict
    );
}

struct FakeMutationStore {
    calls: Mutex<u64>,
}

impl WorkspaceMutationStore for FakeMutationStore {
    fn record_workspace_mutation(
        &self,
        request: WorkspaceMutationRequest,
    ) -> Result<WorkspaceMutationResult, PortError> {
        *self.calls.lock().unwrap() += 1;
        Ok(WorkspaceMutationResult {
            event_id: EventId::new("event-1").unwrap(),
            new_sequence: Sequence::new(request.expected_sequence.get() + 1),
            task_state: local_agent_terminal_domain::WorkflowState::new(
                Phase::WorkspaceDirty,
                Condition::Active,
                OperationState::None,
                Sequence::new(request.expected_sequence.get() + 1),
                WorkspaceVersion::new(1),
                FencingToken::new(2).unwrap(),
            )
            .unwrap(),
            resume_target: Some(Phase::Implementation),
            invalidated_approval_ids: vec!["approval-1".to_owned()],
        })
    }
}

#[test]
fn workspace_mutation_is_one_atomic_application_port_call() {
    let store = FakeMutationStore {
        calls: Mutex::new(0),
    };
    let use_case = ObserveWorkspaceMutation::new(&store);
    let pre = canonical_evidence_fixture("artifact-pre", SHA256_A);
    let post = canonical_evidence_fixture("artifact-post", SHA256_B);

    let result = use_case
        .execute(WorkspaceMutationRequest {
            task_id: TaskId::new("task-1").unwrap(),
            expected_sequence: Sequence::new(4),
            claim: lease_claim(1),
            pre_fingerprint: fingerprint(),
            post_fingerprint: fingerprint(),
            pre_evidence: pre,
            post_evidence: post,
            actor_id: ActorId::new("workspace-monitor").unwrap(),
            correlation_id: "correlation-1".to_owned(),
        })
        .unwrap();

    assert_eq!(*store.calls.lock().unwrap(), 1);
    assert_eq!(result.new_sequence.get(), 5);
    assert_eq!(result.task_state.phase(), Phase::WorkspaceDirty);
    assert_eq!(result.resume_target, Some(Phase::Implementation));
}

fn canonical_evidence_fixture(
    artifact_id: &str,
    hash: &str,
) -> local_agent_terminal_application::CanonicalEvidenceRef {
    local_agent_terminal_application::CanonicalEvidenceRef {
        artifact_id: ArtifactId::new(artifact_id).unwrap(),
        content_hash: hash.to_owned(),
        storage_key: format!("objects/{}", &hash[7..]),
        size_bytes: 2,
        project_id: ProjectId::new("project-1").unwrap(),
        task_id: Some(TaskId::new("task-1").unwrap()),
    }
}

struct FakeTaskQuery;

impl TaskQuery for FakeTaskQuery {
    fn task(&self, _task_id: &TaskId) -> Result<TaskSnapshot, PortError> {
        Ok(task_snapshot())
    }

    fn timeline(&self, _task_id: &TaskId) -> Result<Vec<TimelineEntryDto>, PortError> {
        Ok(vec![
            TimelineEntryDto {
                sequence: 1,
                event_type: "task.created".to_owned(),
                created_at: "2026-07-26T00:00:00Z".to_owned(),
                summary: "Task created".to_owned(),
                evidence: None,
            },
            TimelineEntryDto {
                sequence: 2,
                event_type: "worktree.created".to_owned(),
                created_at: "2026-07-26T00:00:01Z".to_owned(),
                summary: "Worktree created".to_owned(),
                evidence: Some(EvidenceSummaryDto {
                    artifact_id: "artifact-1".to_owned(),
                    content_hash: SHA256_A.to_owned(),
                    size_bytes: 2,
                }),
            },
        ])
    }
}

#[test]
fn task_timeline_contract_preserves_persisted_sequence_order() {
    let timeline = FakeTaskQuery
        .timeline(&TaskId::new("task-1").unwrap())
        .unwrap();
    assert_eq!(
        timeline
            .iter()
            .map(|entry| entry.sequence)
            .collect::<Vec<_>>(),
        [1, 2]
    );
}

#[test]
fn indeterminate_non_repeatable_candidate_never_exposes_retry() {
    let intent = operation_intent(IdempotencyClass::NonRepeatable);
    let candidate = RecoveryCandidate::indeterminate(
        &intent,
        RecoveryEvidence {
            summary: "Outcome cannot be proven".to_owned(),
            artifact_id: Some(ArtifactId::new("artifact-evidence-1").unwrap()),
        },
    );

    assert_eq!(candidate.reason, RecoveryReason::IndeterminateNonRepeatable);
    assert!(!candidate
        .actions
        .contains(&RecoveryAction::RetryAfterAuthoritativeAbsence));
    assert!(candidate.actions.contains(&RecoveryAction::InspectEvidence));
    assert!(candidate.actions.contains(&RecoveryAction::PreserveTask));
}

#[test]
fn dashboard_use_case_reads_one_application_owned_projection() {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let workspaces = FakeWorkspaceStateStore {
        calls: Arc::clone(&calls),
    };
    let dashboard = GetWorkspaceDashboard::new(&workspaces)
        .execute(&ProjectId::new("project-1").unwrap())
        .unwrap();

    assert_eq!(*calls.lock().unwrap(), ["dashboard"]);
    assert_eq!(dashboard.tasks.len(), 1);
}

#[test]
fn rfc8785_vectors_have_stable_canonical_bytes_and_sha256_digest() {
    let metadata = (
        ArtifactId::new("artifact-request-1").unwrap(),
        ProjectId::new("project-1").unwrap(),
        Some(TaskId::new("task-1").unwrap()),
    );
    let first = CanonicalJsonRequest::new(
        metadata.0.clone(),
        metadata.1.clone(),
        metadata.2.clone(),
        "worktree_request",
        "requests/worktree.json",
        "core",
        "workspace-coordinator",
        &json!({
            "z": 0.0,
            "numbers": [1.0, 1e30, 0.002, -0.0],
            "escaping": "\n\t\u{000f}\"\\/",
            "unicode": "€😀",
            "unicodeKeys": {"😀": "grinning", "€": "euro", "a": "latin"},
            "a": {"b": 2, "a": 1}
        }),
        "worktree:create:task-1",
    )
    .unwrap();
    let second = CanonicalJsonRequest::new(
        metadata.0,
        metadata.1,
        metadata.2,
        "worktree_request",
        "requests/worktree.json",
        "core",
        "workspace-coordinator",
        &json!({
            "unicode": "€😀",
            "unicodeKeys": {"a": "latin", "€": "euro", "😀": "grinning"},
            "a": {"a": 1, "b": 2},
            "escaping": "\n\t\u{000f}\"\\/",
            "numbers": [1, 1e30, 0.002, 0],
            "z": 0
        }),
        "worktree:create:task-1",
    )
    .unwrap();

    assert_eq!(
        std::str::from_utf8(&first.canonical_bytes).unwrap(),
        "{\"a\":{\"a\":1,\"b\":2},\"escaping\":\"\\n\\t\\u000f\\\"\\\\/\",\"numbers\":[1,1e+30,0.002,0],\"unicode\":\"€😀\",\"unicodeKeys\":{\"a\":\"latin\",\"€\":\"euro\",\"😀\":\"grinning\"},\"z\":0}"
    );
    assert_eq!(first.canonical_bytes, second.canonical_bytes);
    assert_eq!(
        first.expected_hash,
        "sha256:d83cc3c77bc3834aad023bc893ea013ee930058084f2ede907678e2a01b50f5c"
    );
    assert_eq!(first.expected_size as usize, first.canonical_bytes.len());

    let reference = ArtifactRef {
        content_hash: first.expected_hash.clone(),
        storage_key: "objects/51/604315".to_owned(),
        size_bytes: first.expected_size,
    };
    let evidence = canonical_evidence(&first, &reference).unwrap();
    assert_eq!(evidence.artifact_id.as_str(), "artifact-request-1");
    assert_eq!(evidence.content_hash, first.expected_hash);

    let wrong_reference = ArtifactRef {
        size_bytes: reference.size_bytes + 1,
        ..reference
    };
    assert_eq!(
        canonical_evidence(&first, &wrong_reference)
            .unwrap_err()
            .safe_classification(),
        SafeErrorClassification::IntegrityFailure
    );
}
