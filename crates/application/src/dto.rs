use serde::Serialize;

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
