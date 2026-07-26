use std::sync::{Mutex, MutexGuard};

use local_agent_terminal_domain::{
    ActorId, ArtifactId, Condition, EventId, FencingToken, GitObjectId, LeaseClaim, OperationState,
    Phase, ProjectId, RepositoryId, Sequence, TaskBranch, TaskId, WorkflowState,
    WorkspaceFingerprint, WorkspaceVersion, WorktreeId,
};

use crate::{
    AcquireLease, CanonicalEvidenceRef, CreateWorktree, DiscardWorktree, ExecutorLeaseStore,
    ExpectedPresence, LeaseSnapshot, PortError, RepositoryGateway, RepositorySnapshot,
    Retryability, RevokeLease, SafeErrorClassification, TimelineEntryDto, WorkspaceDashboardDto,
    WorkspaceMutationStore, WorktreeSnapshot,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewProject {
    pub project_id: ProjectId,
    pub name: String,
    pub repository: RepositorySnapshot,
    pub repository_path: String,
    pub settings: ProjectSettings,
    pub created_at: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArtifactRootMode {
    ApplicationData,
    ProjectLocal,
}

impl ArtifactRootMode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ApplicationData => "application_data",
            Self::ProjectLocal => "project_local",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProjectSettings {
    pub policy_profile_id: String,
    pub artifact_root_mode: ArtifactRootMode,
    pub artifact_root_path: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProjectSnapshot {
    pub project_id: ProjectId,
    pub name: String,
    pub repository: RepositorySnapshot,
    pub repository_path: String,
    pub settings: ProjectSettings,
    pub repository_evidence_artifact_id: Option<ArtifactId>,
    pub created_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepositoryInspectionRecord {
    pub project_id: ProjectId,
    pub repository: RepositorySnapshot,
    pub evidence: CanonicalEvidenceRef,
    pub actor_id: ActorId,
    pub correlation_id: String,
    pub observed_at: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RiskLevel {
    Low,
    Medium,
    High,
    Critical,
}

impl RiskLevel {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "low" => Some(Self::Low),
            "medium" => Some(Self::Medium),
            "high" => Some(Self::High),
            "critical" => Some(Self::Critical),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewTask {
    pub task_id: TaskId,
    pub project_id: ProjectId,
    pub title: String,
    pub objective: String,
    pub risk_level: RiskLevel,
    pub base_branch: TaskBranch,
    pub base_commit: GitObjectId,
    pub created_at: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaskLeaseState {
    None,
    Active,
    Released,
    Expired,
    Revoked,
    Stale,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskSnapshot {
    pub task_id: TaskId,
    pub project_id: ProjectId,
    pub title: String,
    pub objective: String,
    pub risk_level: RiskLevel,
    pub phase: Phase,
    pub condition: Condition,
    pub operation_state: OperationState,
    pub base_branch: TaskBranch,
    pub base_commit: GitObjectId,
    pub task_branch: Option<TaskBranch>,
    pub worktree: Option<WorktreeSnapshot>,
    pub current_sequence: Sequence,
    pub workspace_version: WorkspaceVersion,
    pub fencing_epoch: u64,
    pub lease_state: TaskLeaseState,
    pub recovery_candidates: Vec<RecoveryCandidate>,
    pub timeline: Vec<TimelineEntryDto>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdempotencyClass {
    Idempotent,
    Queryable,
    NonRepeatable,
}

impl IdempotencyClass {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Idempotent => "idempotent",
            Self::Queryable => "queryable",
            Self::NonRepeatable => "non_repeatable",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "idempotent" => Some(Self::Idempotent),
            "queryable" => Some(Self::Queryable),
            "non_repeatable" => Some(Self::NonRepeatable),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OperationIntentStatus {
    Pending,
    Claimed,
    Started,
    Succeeded,
    Failed,
    Interrupted,
    Indeterminate,
    Cancelled,
}

impl OperationIntentStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Claimed => "claimed",
            Self::Started => "started",
            Self::Succeeded => "succeeded",
            Self::Failed => "failed",
            Self::Interrupted => "interrupted",
            Self::Indeterminate => "indeterminate",
            Self::Cancelled => "cancelled",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "pending" => Some(Self::Pending),
            "claimed" => Some(Self::Claimed),
            "started" => Some(Self::Started),
            "succeeded" => Some(Self::Succeeded),
            "failed" => Some(Self::Failed),
            "interrupted" => Some(Self::Interrupted),
            "indeterminate" => Some(Self::Indeterminate),
            "cancelled" => Some(Self::Cancelled),
            _ => None,
        }
    }
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OperationIntent {
    pub id: String,
    pub task_id: TaskId,
    pub operation_kind: String,
    pub idempotency_class: IdempotencyClass,
    pub idempotency_key: String,
    pub canonical_request_artifact_id: ArtifactId,
    pub operation_digest: String,
    pub status: OperationIntentStatus,
    pub executor_fencing_token: Option<FencingToken>,
    pub attempt_count: u32,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorktreeIntent {
    pub operation: OperationIntent,
    pub worktree_id: WorktreeId,
    pub repository_id: RepositoryId,
    pub repository_identity: String,
    pub branch: TaskBranch,
    pub base_commit: GitObjectId,
    pub target_path_display: String,
    pub expected_presence: ExpectedPresence,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryOperationIntent {
    pub operation: OperationIntent,
    pub candidate_id: String,
    pub action: RecoveryAction,
    pub expected_workspace_version: WorkspaceVersion,
}

impl WorktreeIntent {
    pub fn compare_observation(&self, observed: &WorktreeSnapshot) -> WorktreeMatch {
        if self.repository_id != observed.repository_id
            || self.repository_identity != observed.repository_identity
        {
            return WorktreeMatch::Conflict(RecoveryReason::RepositoryMismatch);
        }
        if self.worktree_id != observed.worktree_id {
            return WorktreeMatch::Conflict(RecoveryReason::WorktreeIdentityMismatch);
        }
        if self.operation.task_id != observed.task_id {
            return WorktreeMatch::Conflict(RecoveryReason::TaskMismatch);
        }
        if self.branch != observed.branch {
            return WorktreeMatch::Conflict(RecoveryReason::BranchMismatch);
        }
        if self.base_commit != observed.base_commit {
            return WorktreeMatch::Conflict(RecoveryReason::BaseCommitMismatch);
        }
        if self.target_path_display != observed.target_path_display {
            return WorktreeMatch::Conflict(RecoveryReason::PathMismatch);
        }
        let observed_presence_matches = match self.expected_presence {
            ExpectedPresence::Present => observed.state == crate::WorktreeState::Present,
            ExpectedPresence::Absent => observed.state == crate::WorktreeState::Missing,
        };
        if self.expected_presence != observed.expected_presence || !observed_presence_matches {
            return WorktreeMatch::Conflict(RecoveryReason::PresenceMismatch);
        }
        WorktreeMatch::Exact
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IntentTransition {
    pub intent_id: String,
    pub expected_status: OperationIntentStatus,
    pub next_status: OperationIntentStatus,
    pub executor_fencing_token: Option<FencingToken>,
    pub attempt_count: u32,
    pub updated_at: String,
    pub error: Option<SafeErrorClassification>,
    pub observed_fingerprint: Option<WorkspaceFingerprint>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoveryReason {
    ExactMatch,
    AuthoritativeAbsence,
    RepositoryMismatch,
    WorktreeIdentityMismatch,
    TaskMismatch,
    BranchMismatch,
    BaseCommitMismatch,
    PathMismatch,
    PresenceMismatch,
    IndeterminateNonRepeatable,
    OutcomeIndeterminate,
    UnknownOperation,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorktreeMatch {
    Exact,
    Conflict(RecoveryReason),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoveryAction {
    InspectEvidence,
    AdoptExactMatch,
    RetryAfterAuthoritativeAbsence,
    PreserveTask,
    DiscardExactWorktree,
    CancelTask,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryEvidence {
    pub summary: String,
    pub artifact_id: Option<ArtifactId>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryCandidate {
    pub intent_id: Option<String>,
    pub worktree_id: Option<WorktreeId>,
    pub reason: RecoveryReason,
    pub evidence: RecoveryEvidence,
    pub actions: Vec<RecoveryAction>,
    pub expected_worktree: Option<WorktreeIntent>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryProject {
    pub project_id: ProjectId,
    pub repository_path: String,
    pub repository: RepositorySnapshot,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StartedRecovery {
    pub operation: OperationIntent,
    pub candidate: RecoveryCandidate,
}

pub trait WorkspaceRecoveryStore: Send + Sync {
    fn recovery_projects(&self) -> Result<Vec<RecoveryProject>, PortError>;
    fn started_recoveries(&self) -> Result<Vec<StartedRecovery>, PortError>;
    fn persisted_recovery_candidates(&self) -> Result<Vec<RecoveryCandidate>, PortError>;
}

impl RecoveryCandidate {
    pub fn indeterminate(intent: &OperationIntent, evidence: RecoveryEvidence) -> Self {
        let (reason, actions) = match intent.idempotency_class {
            IdempotencyClass::NonRepeatable => (
                RecoveryReason::IndeterminateNonRepeatable,
                vec![
                    RecoveryAction::InspectEvidence,
                    RecoveryAction::PreserveTask,
                    RecoveryAction::CancelTask,
                ],
            ),
            IdempotencyClass::Idempotent | IdempotencyClass::Queryable => (
                RecoveryReason::OutcomeIndeterminate,
                vec![
                    RecoveryAction::InspectEvidence,
                    RecoveryAction::PreserveTask,
                ],
            ),
        };
        Self {
            intent_id: Some(intent.id.clone()),
            worktree_id: None,
            reason,
            evidence,
            actions,
            expected_worktree: None,
        }
    }
}

pub trait WorkspaceStateStore: Send + Sync {
    fn create_project(&self, project: NewProject) -> Result<ProjectSnapshot, PortError>;
    fn record_repository_inspection(
        &self,
        inspection: RepositoryInspectionRecord,
    ) -> Result<ProjectSnapshot, PortError>;
    fn create_task(&self, task: NewTask) -> Result<TaskSnapshot, PortError>;
    fn begin_worktree_intent(&self, intent: WorktreeIntent) -> Result<OperationIntent, PortError>;
    fn begin_recovery_intent(
        &self,
        intent: RecoveryOperationIntent,
    ) -> Result<OperationIntent, PortError>;
    fn transition_worktree_intent(&self, transition: IntentTransition) -> Result<(), PortError>;
    fn reconcile_intents(&self) -> Result<Vec<RecoveryCandidate>, PortError>;
    fn dashboard(&self, project: &ProjectId) -> Result<WorkspaceDashboardDto, PortError>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkspaceMutationRequest {
    pub task_id: TaskId,
    pub expected_sequence: Sequence,
    pub claim: LeaseClaim,
    pub pre_fingerprint: WorkspaceFingerprint,
    pub post_fingerprint: WorkspaceFingerprint,
    pub pre_evidence: CanonicalEvidenceRef,
    pub post_evidence: CanonicalEvidenceRef,
    pub actor_id: ActorId,
    pub correlation_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkspaceMutationResult {
    pub event_id: EventId,
    pub new_sequence: Sequence,
    pub task_state: WorkflowState,
    pub resume_target: Option<Phase>,
    pub invalidated_approval_ids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkspaceObservationLossRequest {
    pub task_id: TaskId,
    pub expected_sequence: Sequence,
    pub claim: LeaseClaim,
    pub operation: OperationIntent,
    pub next_status: OperationIntentStatus,
    pub observed_at: String,
    pub error: SafeErrorClassification,
}

pub struct PrepareTaskWorkspace<'a> {
    workspaces: &'a dyn WorkspaceStateStore,
    repositories: &'a dyn RepositoryGateway,
    leases: &'a dyn ExecutorLeaseStore,
}

impl<'a> PrepareTaskWorkspace<'a> {
    pub const fn new(
        workspaces: &'a dyn WorkspaceStateStore,
        repositories: &'a dyn RepositoryGateway,
        leases: &'a dyn ExecutorLeaseStore,
    ) -> Self {
        Self {
            workspaces,
            repositories,
            leases,
        }
    }

    pub fn execute(
        &self,
        intent: WorktreeIntent,
        request: CreateWorktree,
        observed_at: String,
    ) -> Result<WorktreeSnapshot, PortError> {
        validate_worktree_request(&intent, &request, &observed_at)?;
        let operation = self.workspaces.begin_worktree_intent(intent)?;
        if operation.status != OperationIntentStatus::Pending {
            return Err(conflict());
        }
        let attempt_count = operation
            .attempt_count
            .checked_add(1)
            .ok_or_else(internal_failure)?;
        let fencing_token = request.lease_claim.token();
        self.workspaces
            .transition_worktree_intent(IntentTransition {
                intent_id: operation.id.clone(),
                expected_status: OperationIntentStatus::Pending,
                next_status: OperationIntentStatus::Started,
                executor_fencing_token: Some(fencing_token),
                attempt_count,
                updated_at: observed_at.clone(),
                error: None,
                observed_fingerprint: None,
            })?;

        let result = self
            .leases
            .assert_current(request.lease_claim.clone())
            .and_then(|()| self.repositories.create_worktree(request));
        match result {
            Ok(worktree) => {
                self.workspaces
                    .transition_worktree_intent(IntentTransition {
                        intent_id: operation.id,
                        expected_status: OperationIntentStatus::Started,
                        next_status: OperationIntentStatus::Succeeded,
                        executor_fencing_token: Some(fencing_token),
                        attempt_count,
                        updated_at: observed_at,
                        error: None,
                        observed_fingerprint: Some(worktree.fingerprint.clone()),
                    })?;
                Ok(worktree)
            }
            Err(error) => {
                self.workspaces
                    .transition_worktree_intent(IntentTransition {
                        intent_id: operation.id,
                        expected_status: OperationIntentStatus::Started,
                        next_status: OperationIntentStatus::Indeterminate,
                        executor_fencing_token: Some(fencing_token),
                        attempt_count,
                        updated_at: observed_at,
                        error: Some(error.safe_classification()),
                        observed_fingerprint: None,
                    })?;
                Err(error)
            }
        }
    }
}

pub struct WorkspaceWriteCoordinator {
    gate: Mutex<()>,
}

pub struct WorkspaceWritePermit<'a> {
    _guard: MutexGuard<'a, ()>,
}

impl WorkspaceWriteCoordinator {
    pub const fn new() -> Self {
        Self {
            gate: Mutex::new(()),
        }
    }

    pub fn acquire_lease(
        &self,
        leases: &dyn ExecutorLeaseStore,
        request: AcquireLease,
    ) -> Result<LeaseSnapshot, PortError> {
        let _guard = self.gate.lock().map_err(|_| internal_failure())?;
        leases.acquire(request)
    }

    pub fn revoke_lease(
        &self,
        leases: &dyn ExecutorLeaseStore,
        request: RevokeLease,
    ) -> Result<(), PortError> {
        let _guard = self.gate.lock().map_err(|_| internal_failure())?;
        leases.revoke(request)
    }

    pub fn monitor_permit<'a>(
        &'a self,
        leases: &dyn ExecutorLeaseStore,
        claim: LeaseClaim,
    ) -> Result<WorkspaceWritePermit<'a>, PortError> {
        let guard = self.gate.lock().map_err(|_| internal_failure())?;
        leases.assert_current(claim)?;
        Ok(WorkspaceWritePermit { _guard: guard })
    }

    pub fn prepare_worktree(
        &self,
        workspaces: &dyn WorkspaceStateStore,
        repositories: &dyn RepositoryGateway,
        leases: &dyn ExecutorLeaseStore,
        intent: WorktreeIntent,
        request: CreateWorktree,
        observed_at: String,
    ) -> Result<WorktreeSnapshot, PortError> {
        let _guard = self.gate.lock().map_err(|_| internal_failure())?;
        PrepareTaskWorkspace::new(workspaces, repositories, leases).execute(
            intent,
            request,
            observed_at,
        )
    }

    pub fn discard_worktree(
        &self,
        leases: &dyn ExecutorLeaseStore,
        repositories: &dyn RepositoryGateway,
        request: DiscardWorktree,
    ) -> Result<(), PortError> {
        if request.lease_claim.task_id() != &request.task_id {
            return Err(invalid_input());
        }
        let _guard = self.gate.lock().map_err(|_| internal_failure())?;
        leases.assert_current(request.lease_claim.clone())?;
        repositories.discard_worktree(request)
    }

    pub fn record_mutation(
        &self,
        mutations: &dyn WorkspaceMutationStore,
        request: WorkspaceMutationRequest,
    ) -> Result<WorkspaceMutationResult, PortError> {
        let _guard = self.gate.lock().map_err(|_| internal_failure())?;
        mutations.record_workspace_mutation(request)
    }
}

impl Default for WorkspaceWriteCoordinator {
    fn default() -> Self {
        Self::new()
    }
}

pub struct ReconcileWorkspaces<'a> {
    workspaces: &'a dyn WorkspaceStateStore,
}

impl<'a> ReconcileWorkspaces<'a> {
    pub const fn new(workspaces: &'a dyn WorkspaceStateStore) -> Self {
        Self { workspaces }
    }

    pub fn execute(&self) -> Result<Vec<RecoveryCandidate>, PortError> {
        self.workspaces.reconcile_intents()
    }
}

pub struct ObserveWorkspaceMutation<'a> {
    mutations: &'a dyn WorkspaceMutationStore,
}

impl<'a> ObserveWorkspaceMutation<'a> {
    pub const fn new(mutations: &'a dyn WorkspaceMutationStore) -> Self {
        Self { mutations }
    }

    pub fn execute(
        &self,
        request: WorkspaceMutationRequest,
    ) -> Result<WorkspaceMutationResult, PortError> {
        self.mutations.record_workspace_mutation(request)
    }
}

pub struct GetWorkspaceDashboard<'a> {
    workspaces: &'a dyn WorkspaceStateStore,
}

impl<'a> GetWorkspaceDashboard<'a> {
    pub const fn new(workspaces: &'a dyn WorkspaceStateStore) -> Self {
        Self { workspaces }
    }

    pub fn execute(&self, project: &ProjectId) -> Result<WorkspaceDashboardDto, PortError> {
        self.workspaces.dashboard(project)
    }
}

fn validate_worktree_request(
    intent: &WorktreeIntent,
    request: &CreateWorktree,
    observed_at: &str,
) -> Result<(), PortError> {
    let exact_match = intent.operation.operation_kind == "worktree.create"
        && intent.operation.idempotency_class == IdempotencyClass::Queryable
        && intent.operation.status == OperationIntentStatus::Pending
        && intent.operation.task_id == request.task_id
        && request.lease_claim.task_id() == &request.task_id
        && intent.repository_id == request.repository.repository_id
        && intent.repository_identity == request.repository.stable_identity
        && intent.worktree_id == request.worktree_id
        && intent.branch == request.branch
        && intent.base_commit == request.base_commit
        && intent.target_path_display == request.managed_path.redacted_display
        && intent.expected_presence == ExpectedPresence::Present;
    if !exact_match || observed_at.trim().is_empty() {
        return Err(invalid_input());
    }
    Ok(())
}

fn invalid_input() -> PortError {
    PortError::failure(
        SafeErrorClassification::InvalidInput,
        Retryability::NonRetryable,
    )
}

fn conflict() -> PortError {
    PortError::failure(
        SafeErrorClassification::Conflict,
        Retryability::NonRetryable,
    )
}

fn internal_failure() -> PortError {
    PortError::failure(
        SafeErrorClassification::Internal,
        Retryability::NonRetryable,
    )
}
