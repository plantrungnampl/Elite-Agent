use local_agent_terminal_domain::ProjectId;
use serde::Serialize;

use crate::{RecoveryAction, RecoveryCandidate, RepositorySnapshot, TaskSnapshot};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum StartupStateDto {
    Ready,
    RecoverableFailure,
    Indeterminate,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RecoveryActionDto {
    pub code: String,
    pub label: String,
}

impl From<RecoveryAction> for RecoveryActionDto {
    fn from(action: RecoveryAction) -> Self {
        let (code, label) = match action {
            RecoveryAction::InspectEvidence => ("inspect_evidence", "Inspect evidence"),
            RecoveryAction::AdoptExactMatch => ("adopt_exact_match", "Adopt exact worktree"),
            RecoveryAction::RetryAfterAuthoritativeAbsence => (
                "retry_after_authoritative_absence",
                "Retry after verified absence",
            ),
            RecoveryAction::PreserveTask => ("preserve_task", "Preserve task"),
            RecoveryAction::DiscardExactWorktree => {
                ("discard_exact_worktree", "Discard exact worktree")
            }
            RecoveryAction::CancelTask => ("cancel_task", "Cancel task"),
        };
        Self {
            code: code.to_owned(),
            label: label.to_owned(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StartupIssueDto {
    pub code: String,
    pub message: String,
    pub recovery_actions: Vec<RecoveryActionDto>,
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkspaceDashboardDto {
    pub project_id: ProjectId,
    pub repository: RepositorySnapshot,
    pub tasks: Vec<TaskSnapshot>,
    pub recovery: Vec<RecoveryCandidate>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TimelineEntryDto {
    pub sequence: u64,
    pub event_type: String,
    pub created_at: String,
    pub summary: String,
    pub evidence: Option<EvidenceSummaryDto>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvidenceSummaryDto {
    pub artifact_id: String,
    pub content_hash: String,
    pub size_bytes: u64,
}
