use local_agent_terminal_domain::{NetworkProfile, ProjectId, TrustTier};
use serde::{Deserialize, Serialize, Serializer};

use crate::{
    canonical_json::invalid_input, tool::logical_capability, ExpectedPresence, PortError,
    ProjectSnapshot, RecoveryAction, RecoveryCandidate, RecoveryReason, RepositorySnapshot,
    Retryability, SafeErrorClassification, TaskLeaseState, TaskSnapshot, ToolRequest,
    WorktreeSnapshot, WorktreeState,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum StartupStateDto {
    Ready,
    RecoverableFailure,
    Indeterminate,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StartupRecoveryActionDto {
    pub code: String,
    pub label: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StartupIssueDto {
    pub code: String,
    pub message: String,
    pub recovery_actions: Vec<StartupRecoveryActionDto>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StartupStatusDto {
    pub state: StartupStateDto,
    pub issues: Vec<StartupIssueDto>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LocalDiagnosticDto {
    pub code: String,
    pub component: String,
    pub severity: DiagnosticSeverityDto,
    pub trust_label: TrustLabelDto,
    pub observation_class: ObservationClassDto,
    pub error_category: Option<String>,
    pub correlation_id: Option<String>,
    pub detail: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum DiagnosticSeverityDto {
    Info,
    Error,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum TrustLabelDto {
    TrustedCore,
    Untrusted,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum ObservationClassDto {
    CoreObservation,
    UntrustedClaim,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum RecoveryActionCodeDto {
    Reconcile,
    Preserve,
    Discard,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RecoveryActionDto {
    pub candidate_id: String,
    pub code: RecoveryActionCodeDto,
    pub label: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WorkspaceDashboardRequestDto {
    pub project_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OnboardRepositoryRequestDto {
    pub project_id: String,
    pub name: String,
    pub repository_path: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CreateTaskWorkspaceRequestDto {
    pub project_id: String,
    pub task_id: String,
    pub title: String,
    pub objective: String,
    pub risk_level: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RecoveryCandidateRequestDto {
    pub candidate_id: String,
    pub project_id: String,
    pub task_id: String,
    pub expected_workspace_version: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ConfirmDiscardWorkspaceRequestDto {
    pub candidate_id: String,
    pub project_id: String,
    pub task_id: String,
    pub expected_workspace_version: u64,
    pub confirmed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ApproveOperationRequestDto {
    pub approval_id: String,
    pub expected_operation_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CancelToolExecutionRequestDto {
    pub execution_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GetApprovalRequestDto {
    pub approval_id: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ToolApprovalDecisionDto {
    Approve,
    Deny,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ResolveToolApprovalRequestDto {
    pub approval_id: String,
    pub expected_operation_digest: String,
    pub decision: ToolApprovalDecisionDto,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ToolRuntimeAvailabilityDto {
    Ready,
    DegradedReadOnly,
    Unavailable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ToolActivityStatusDto {
    Denied,
    ApprovalRequired,
    Running,
    Cancelling,
    Succeeded,
    Terminated,
    Failed,
    Interrupted,
    Indeterminate,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ToolRedactionStateDto {
    None,
    Redacted,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ToolActivityEntryDto {
    pub execution_id: String,
    pub approval_id: Option<String>,
    pub tool_name: String,
    pub status: ToolActivityStatusDto,
    pub summary: String,
    pub actor_id: String,
    pub effective_role: String,
    pub reason: String,
    pub operation_digest: String,
    pub policy_decision_id: Option<String>,
    pub policy_snapshot_digest: String,
    pub scopes: Vec<String>,
    pub environment_profile_digest: String,
    pub network_profile: String,
    pub expires_at: Option<String>,
    pub fencing_token: Option<u64>,
    pub policy_rules: Vec<String>,
    pub redaction_state: ToolRedactionStateDto,
    pub started_at: Option<String>,
    pub completed_at: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ToolActivityDto {
    pub availability: ToolRuntimeAvailabilityDto,
    pub entries: Vec<ToolActivityEntryDto>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ToolApprovalRequestDto {
    pub approval_id: String,
    pub execution_id: String,
    pub summary: String,
    pub operation_digest: String,
    pub expires_at: String,
    pub scopes: Vec<String>,
    pub actor_id: String,
    pub reason: String,
    pub environment_profile_digest: String,
    pub network_profile: String,
    pub fencing_token: Option<u64>,
    pub policy_rules: Vec<String>,
    pub redaction_state: ToolRedactionStateDto,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ToolApprovalResolutionDto {
    pub approval_id: String,
    pub execution_id: String,
    pub status: ToolActivityStatusDto,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ToolCancellationReceiptDto {
    pub execution_id: String,
    pub status: ToolActivityStatusDto,
    pub cancelled: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StopAllToolsReceiptDto {
    pub receipts: Vec<ToolCancellationReceiptDto>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolRequestContextDto {
    pub summary: String,
    pub actor_id: String,
    pub fallback_role: String,
    pub reason: String,
    pub policy_snapshot_digest: String,
    pub scopes: Vec<String>,
    pub environment_profile_digest: String,
    pub network_profile: String,
    pub fencing_token: Option<u64>,
}

pub fn tool_request_context(request: &ToolRequest) -> Result<ToolRequestContextDto, PortError> {
    let process = request.process().process();
    let argv = serde_json::to_string(process.argv()).map_err(|_| invalid_input())?;
    let mut scopes = Vec::with_capacity(
        1 + request.process().expected_reads().len() + process.expected_writes().len(),
    );
    scopes.push(logical_capability(process.cwd()));
    scopes.extend(
        request
            .process()
            .expected_reads()
            .iter()
            .map(logical_capability),
    );
    scopes.extend(
        process
            .expected_writes()
            .iter()
            .map(|write| logical_capability(write.capability())),
    );
    Ok(ToolRequestContextDto {
        summary: format!(
            "process.exec {} {argv}",
            logical_capability(process.executable())
        ),
        actor_id: request.policy().actor().agent_id.clone(),
        fallback_role: trust_tier_name(request.policy().actor().trust_tier).to_owned(),
        reason: request.policy().purpose().to_owned(),
        policy_snapshot_digest: request
            .policy()
            .policy_snapshot_digest()
            .as_str()
            .to_owned(),
        scopes,
        environment_profile_digest: process
            .binding()
            .environment_profile()
            .digest()
            .as_str()
            .to_owned(),
        network_profile: network_profile_name(process.network()).to_owned(),
        fencing_token: process.executor_fencing_token().map(|token| token.get()),
    })
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ApprovalRequestDto {
    pub approval_id: String,
    pub summary: String,
    pub operation_digest: String,
    pub expires_at: String,
    pub scopes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CommandErrorDto {
    pub code: String,
    pub message: String,
    pub retryable: bool,
}

impl CommandErrorDto {
    pub fn startup_not_ready() -> Self {
        Self {
            code: "startup_not_ready".to_owned(),
            message: "Startup validation has not reached a safe ready state.".to_owned(),
            retryable: false,
        }
    }

    pub fn internal_state_unavailable() -> Self {
        Self {
            code: "internal".to_owned(),
            message: "The trusted local state is unavailable.".to_owned(),
            retryable: false,
        }
    }
}

impl From<PortError> for CommandErrorDto {
    fn from(error: PortError) -> Self {
        let classification = error.safe_classification();
        Self {
            code: classification_name(classification).to_owned(),
            message: classification_message(classification).to_owned(),
            retryable: error.retryability() == Retryability::Retryable,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkspaceDashboardDto {
    pub project_id: ProjectId,
    pub repository: RepositorySnapshot,
    pub tasks: Vec<TaskSnapshot>,
    pub recovery: Vec<RecoveryCandidate>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TimelineEntryDto {
    pub sequence: u64,
    pub event_type: String,
    pub created_at: String,
    pub summary: String,
    pub evidence: Option<EvidenceSummaryDto>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EvidenceSummaryDto {
    pub artifact_id: String,
    pub content_hash: String,
    pub size_bytes: u64,
}

impl Serialize for WorkspaceDashboardDto {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let recovery = self
            .tasks
            .iter()
            .flat_map(recovery_views)
            .collect::<Vec<_>>();
        WorkspaceDashboardView {
            project_id: self.project_id.as_str(),
            repository: repository_view(&self.repository),
            tasks: self.tasks.iter().map(task_view).collect(),
            recovery,
        }
        .serialize(serializer)
    }
}

impl Serialize for ProjectSnapshot {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        ProjectView {
            project_id: self.project_id.as_str(),
            name: &self.name,
            repository: repository_view(&self.repository),
            settings: ProjectSettingsView {
                policy_profile_id: &self.settings.policy_profile_id,
                artifact_root_mode: self.settings.artifact_root_mode.as_str(),
            },
            repository_evidence_artifact_id: self
                .repository_evidence_artifact_id
                .as_ref()
                .map(|id| id.as_str()),
            created_at: &self.created_at,
        }
        .serialize(serializer)
    }
}

impl Serialize for TaskSnapshot {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        task_view(self).serialize(serializer)
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct WorkspaceDashboardView<'a> {
    project_id: &'a str,
    repository: RepositoryView<'a>,
    tasks: Vec<TaskView<'a>>,
    recovery: Vec<RecoveryCandidateView<'a>>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ProjectView<'a> {
    project_id: &'a str,
    name: &'a str,
    repository: RepositoryView<'a>,
    settings: ProjectSettingsView<'a>,
    repository_evidence_artifact_id: Option<&'a str>,
    created_at: &'a str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ProjectSettingsView<'a> {
    policy_profile_id: &'a str,
    artifact_root_mode: &'a str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RepositoryView<'a> {
    repository_id: &'a str,
    health: &'a str,
    stable_identity: &'a str,
    default_branch: Option<&'a str>,
    base_commit: Option<&'a str>,
    original_checkout: &'a str,
    hazards: Vec<RepositoryHazardView<'a>>,
    fingerprint: FingerprintView<'a>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RepositoryHazardView<'a> {
    reason: &'a str,
    detail: &'a str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct FingerprintView<'a> {
    head: &'a str,
    index_digest: &'a str,
    status_digest: &'a str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct TaskView<'a> {
    task_id: &'a str,
    project_id: &'a str,
    title: &'a str,
    objective: &'a str,
    risk_level: &'a str,
    phase: &'a str,
    condition: &'a str,
    operation_state: &'a str,
    base_branch: &'a str,
    base_commit: &'a str,
    task_branch: Option<&'a str>,
    worktree: Option<WorktreeView<'a>>,
    current_sequence: u64,
    workspace_version: u64,
    fencing_epoch: u64,
    lease_state: &'a str,
    recovery_candidates: Vec<RecoveryCandidateView<'a>>,
    timeline: &'a [TimelineEntryDto],
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct WorktreeView<'a> {
    worktree_id: &'a str,
    repository_id: &'a str,
    task_id: &'a str,
    branch: &'a str,
    base_commit: &'a str,
    target_path_display: &'a str,
    state: &'a str,
    expected_presence: &'a str,
    fingerprint: FingerprintView<'a>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RecoveryCandidateView<'a> {
    candidate_id: &'a str,
    task_id: &'a str,
    expected_workspace_version: u64,
    reason: &'a str,
    evidence: RecoveryEvidenceView<'a>,
    actions: Vec<RecoveryActionDto>,
    expected_worktree: Option<WorktreeIntentView<'a>>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RecoveryEvidenceView<'a> {
    summary: &'a str,
    artifact_id: Option<&'a str>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct WorktreeIntentView<'a> {
    worktree_id: &'a str,
    repository_id: &'a str,
    task_id: &'a str,
    branch: &'a str,
    base_commit: &'a str,
    target_path_display: &'a str,
    expected_presence: &'a str,
}

fn repository_view(repository: &RepositorySnapshot) -> RepositoryView<'_> {
    RepositoryView {
        repository_id: repository.repository_id.as_str(),
        health: repository.health.as_str(),
        stable_identity: &repository.stable_identity,
        default_branch: repository
            .default_branch
            .as_ref()
            .map(|branch| branch.as_str()),
        base_commit: repository
            .base_commit
            .as_ref()
            .map(|commit| commit.as_str()),
        original_checkout: repository.original_checkout.as_str(),
        hazards: repository
            .hazards
            .iter()
            .map(|hazard| RepositoryHazardView {
                reason: hazard.reason.as_str(),
                detail: &hazard.detail,
            })
            .collect(),
        fingerprint: fingerprint_view(&repository.fingerprint),
    }
}

fn task_view(task: &TaskSnapshot) -> TaskView<'_> {
    TaskView {
        task_id: task.task_id.as_str(),
        project_id: task.project_id.as_str(),
        title: &task.title,
        objective: &task.objective,
        risk_level: task.risk_level.as_str(),
        phase: task.phase.as_str(),
        condition: task.condition.as_str(),
        operation_state: task.operation_state.as_str(),
        base_branch: task.base_branch.as_str(),
        base_commit: task.base_commit.as_str(),
        task_branch: task.task_branch.as_ref().map(|branch| branch.as_str()),
        worktree: task.worktree.as_ref().map(worktree_view),
        current_sequence: task.current_sequence.get(),
        workspace_version: task.workspace_version.get(),
        fencing_epoch: task.fencing_epoch,
        lease_state: lease_state_name(task.lease_state),
        recovery_candidates: recovery_views(task),
        timeline: &task.timeline,
    }
}

fn worktree_view(worktree: &WorktreeSnapshot) -> WorktreeView<'_> {
    WorktreeView {
        worktree_id: worktree.worktree_id.as_str(),
        repository_id: worktree.repository_id.as_str(),
        task_id: worktree.task_id.as_str(),
        branch: worktree.branch.as_str(),
        base_commit: worktree.base_commit.as_str(),
        target_path_display: &worktree.target_path_display,
        state: worktree_state_name(worktree.state),
        expected_presence: expected_presence_name(worktree.expected_presence),
        fingerprint: fingerprint_view(&worktree.fingerprint),
    }
}

fn fingerprint_view(
    fingerprint: &local_agent_terminal_domain::WorkspaceFingerprint,
) -> FingerprintView<'_> {
    FingerprintView {
        head: fingerprint.head().as_str(),
        index_digest: fingerprint.index_digest(),
        status_digest: fingerprint.status_digest(),
    }
}

fn recovery_views(task: &TaskSnapshot) -> Vec<RecoveryCandidateView<'_>> {
    task.recovery_candidates
        .iter()
        .filter_map(|candidate| {
            let candidate_id = candidate_id(candidate)?;
            Some(RecoveryCandidateView {
                candidate_id,
                task_id: task.task_id.as_str(),
                expected_workspace_version: task.workspace_version.get(),
                reason: recovery_reason_name(candidate.reason),
                evidence: RecoveryEvidenceView {
                    summary: &candidate.evidence.summary,
                    artifact_id: candidate
                        .evidence
                        .artifact_id
                        .as_ref()
                        .map(|id| id.as_str()),
                },
                actions: recovery_actions(candidate, candidate_id),
                expected_worktree: candidate.expected_worktree.as_ref().map(|worktree| {
                    WorktreeIntentView {
                        worktree_id: worktree.worktree_id.as_str(),
                        repository_id: worktree.repository_id.as_str(),
                        task_id: worktree.operation.task_id.as_str(),
                        branch: worktree.branch.as_str(),
                        base_commit: worktree.base_commit.as_str(),
                        target_path_display: &worktree.target_path_display,
                        expected_presence: expected_presence_name(worktree.expected_presence),
                    }
                }),
            })
        })
        .collect()
}

fn candidate_id(candidate: &RecoveryCandidate) -> Option<&str> {
    candidate
        .intent_id
        .as_deref()
        .or_else(|| candidate.worktree_id.as_ref().map(|id| id.as_str()))
}

fn recovery_actions(candidate: &RecoveryCandidate, candidate_id: &str) -> Vec<RecoveryActionDto> {
    let mut actions = Vec::new();
    for action in &candidate.actions {
        let mapped = match action {
            RecoveryAction::AdoptExactMatch | RecoveryAction::RetryAfterAuthoritativeAbsence => {
                Some((RecoveryActionCodeDto::Reconcile, "Reconcile workspace"))
            }
            RecoveryAction::PreserveTask => {
                Some((RecoveryActionCodeDto::Preserve, "Preserve workspace"))
            }
            RecoveryAction::DiscardExactWorktree => {
                Some((RecoveryActionCodeDto::Discard, "Discard exact worktree"))
            }
            RecoveryAction::InspectEvidence | RecoveryAction::CancelTask => None,
        };
        if let Some((code, label)) = mapped {
            if actions
                .iter()
                .all(|existing: &RecoveryActionDto| existing.code != code)
            {
                actions.push(RecoveryActionDto {
                    candidate_id: candidate_id.to_owned(),
                    code,
                    label: label.to_owned(),
                });
            }
        }
    }
    actions
}

const fn worktree_state_name(state: WorktreeState) -> &'static str {
    match state {
        WorktreeState::Planned => "planned",
        WorktreeState::Present => "present",
        WorktreeState::Missing => "missing",
        WorktreeState::Conflict => "conflict",
        WorktreeState::Discarded => "discarded",
    }
}

const fn expected_presence_name(presence: ExpectedPresence) -> &'static str {
    match presence {
        ExpectedPresence::Absent => "absent",
        ExpectedPresence::Present => "present",
    }
}

const fn lease_state_name(state: TaskLeaseState) -> &'static str {
    match state {
        TaskLeaseState::None => "none",
        TaskLeaseState::Active => "active",
        TaskLeaseState::Released => "released",
        TaskLeaseState::Expired => "expired",
        TaskLeaseState::Revoked => "revoked",
        TaskLeaseState::Stale => "stale",
    }
}

const fn recovery_reason_name(reason: RecoveryReason) -> &'static str {
    match reason {
        RecoveryReason::ExactMatch => "exact_match",
        RecoveryReason::AuthoritativeAbsence => "authoritative_absence",
        RecoveryReason::RepositoryMismatch => "repository_mismatch",
        RecoveryReason::WorktreeIdentityMismatch => "worktree_identity_mismatch",
        RecoveryReason::TaskMismatch => "task_mismatch",
        RecoveryReason::BranchMismatch => "branch_mismatch",
        RecoveryReason::BaseCommitMismatch => "base_commit_mismatch",
        RecoveryReason::PathMismatch => "path_mismatch",
        RecoveryReason::PresenceMismatch => "presence_mismatch",
        RecoveryReason::IndeterminateNonRepeatable => "indeterminate_non_repeatable",
        RecoveryReason::OutcomeIndeterminate => "outcome_indeterminate",
        RecoveryReason::UnknownOperation => "unknown_operation",
    }
}

const fn classification_name(classification: SafeErrorClassification) -> &'static str {
    match classification {
        SafeErrorClassification::Conflict => "conflict",
        SafeErrorClassification::Unavailable => "unavailable",
        SafeErrorClassification::PermissionDenied => "permission_denied",
        SafeErrorClassification::NotFound => "not_found",
        SafeErrorClassification::InvalidInput => "invalid_input",
        SafeErrorClassification::IntegrityFailure => "integrity_failure",
        SafeErrorClassification::StorageFull => "storage_full",
        SafeErrorClassification::Internal => "internal",
    }
}

const fn trust_tier_name(trust_tier: TrustTier) -> &'static str {
    match trust_tier {
        TrustTier::CoreAdapter => "core_adapter",
        TrustTier::BrokeredProcess => "brokered_process",
        TrustTier::IsolatedWorker => "isolated_worker",
    }
}

const fn network_profile_name(network_profile: NetworkProfile) -> &'static str {
    match network_profile {
        NetworkProfile::Denied => "denied",
        NetworkProfile::ProviderEndpointOnly => "provider_endpoint_only",
        NetworkProfile::ApprovedDestinations => "approved_destinations",
    }
}

const fn classification_message(classification: SafeErrorClassification) -> &'static str {
    match classification {
        SafeErrorClassification::Conflict => {
            "The workspace changed. Reload authoritative state and try again."
        }
        SafeErrorClassification::Unavailable => "The trusted local service is unavailable.",
        SafeErrorClassification::PermissionDenied => {
            "The requested local operation is not permitted."
        }
        SafeErrorClassification::NotFound => "The requested local record was not found.",
        SafeErrorClassification::InvalidInput => "The request contains invalid data.",
        SafeErrorClassification::IntegrityFailure => "Local evidence failed an integrity check.",
        SafeErrorClassification::StorageFull => "Local storage has insufficient free space.",
        SafeErrorClassification::Internal => "The trusted local operation failed.",
    }
}
