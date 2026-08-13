use std::collections::BTreeSet;
use std::fmt;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::run_configuration::{format_timestamp, parse_timestamp};
use crate::{RunId, Sha256Digest, TaskId, Timestamp, WorkflowProfile};

const MAX_ID: usize = 256;
const MAX_REF: usize = 512;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AssuranceDecision {
    Pause,
    Cancel,
    ContinueDegraded,
}

impl AssuranceDecision {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pause => "pause",
            Self::Cancel => "cancel",
            Self::ContinueDegraded => "continue_degraded",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AssuranceReasonCode {
    InsufficientIndependenceGroups,
    RoleSeparationUnavailable,
    ProviderUnavailable,
    BudgetInsufficient,
}

impl AssuranceReasonCode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InsufficientIndependenceGroups => "insufficient_independence_groups",
            Self::RoleSeparationUnavailable => "role_separation_unavailable",
            Self::ProviderUnavailable => "provider_unavailable",
            Self::BudgetInsufficient => "budget_insufficient",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AssuranceRequirements {
    pub minimum_distinct_independence_groups: u8,
    pub executor_reviewer_separation_required: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AssuranceRunEvidence {
    pub run_id: RunId,
    pub independence_group: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AssuranceAssessment {
    pub runs: Vec<AssuranceRunEvidence>,
    pub executor_run_id: Option<RunId>,
    pub reviewer_run_id: Option<RunId>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AssuranceDegradationInput {
    pub receipt_id: String,
    pub task_id: TaskId,
    pub requested_profile: WorkflowProfile,
    pub requirements: AssuranceRequirements,
    pub assessment: AssuranceAssessment,
    pub reason_code: AssuranceReasonCode,
    pub decision: AssuranceDecision,
    pub actor_binding_id: Option<String>,
    pub acceptance_artifact_ref: Option<String>,
    pub created_at: Timestamp,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AssuranceObserved {
    pub distinct_independence_groups: u8,
    pub run_refs: Vec<RunId>,
    pub role_separation_satisfied: bool,
    pub run_set_digest: Sha256Digest,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AssuranceDegradationReceipt {
    receipt_id: String,
    task_id: TaskId,
    requested_profile: WorkflowProfile,
    requirements: AssuranceRequirements,
    observed: AssuranceObserved,
    reason_code: AssuranceReasonCode,
    decision: AssuranceDecision,
    actor_binding_id: Option<String>,
    acceptance_artifact_ref: Option<String>,
    created_at: Timestamp,
    created_at_rfc3339: String,
    receipt_digest: Sha256Digest,
    canonical_bytes: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct WireReceipt {
    schema_version: String,
    receipt_id: String,
    task_id: String,
    requested_profile: String,
    requirements: AssuranceRequirements,
    observed: WireObserved,
    reason_code: AssuranceReasonCode,
    decision: AssuranceDecision,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    actor_binding_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    acceptance_artifact_ref: Option<String>,
    created_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    receipt_digest: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct WireObserved {
    distinct_independence_groups: u8,
    run_refs: Vec<String>,
    role_separation_satisfied: bool,
    run_set_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AssuranceError {
    Invalid,
    Serialization,
}

impl fmt::Display for AssuranceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Invalid => "invalid assurance receipt",
            Self::Serialization => "assurance receipt serialization failed",
        })
    }
}

impl std::error::Error for AssuranceError {}

impl AssuranceDegradationReceipt {
    pub fn issue(input: AssuranceDegradationInput) -> Result<Self, AssuranceError> {
        validate_input(&input)?;
        let observed = observe(&input.assessment)?;
        validate_reason(&input, &observed)?;
        let created_at_rfc3339 =
            format_timestamp(input.created_at).map_err(|_| AssuranceError::Invalid)?;
        let unsigned = wire(&input, &observed, &created_at_rfc3339, None);
        let receipt_digest = sha256(&canonical(&unsigned)?);
        let final_wire = wire(
            &input,
            &observed,
            &created_at_rfc3339,
            Some(receipt_digest.as_str()),
        );
        let canonical_bytes = canonical(&final_wire)?;
        Ok(Self {
            receipt_id: input.receipt_id,
            task_id: input.task_id,
            requested_profile: input.requested_profile,
            requirements: input.requirements,
            observed,
            reason_code: input.reason_code,
            decision: input.decision,
            actor_binding_id: input.actor_binding_id,
            acceptance_artifact_ref: input.acceptance_artifact_ref,
            created_at: input.created_at,
            created_at_rfc3339,
            receipt_digest,
            canonical_bytes,
        })
    }

    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, AssuranceError> {
        let wire: WireReceipt =
            serde_json::from_slice(bytes).map_err(|_| AssuranceError::Invalid)?;
        if canonical(&wire)? != bytes || wire.schema_version != "1.0" {
            return Err(AssuranceError::Invalid);
        }
        let expected =
            Sha256Digest::new(wire.receipt_digest.clone().ok_or(AssuranceError::Invalid)?)
                .map_err(|_| AssuranceError::Invalid)?;
        let created_at = parse_timestamp(&wire.created_at)
            .map(Timestamp::from_unix_seconds)
            .ok_or(AssuranceError::Invalid)?;
        let run_refs = wire
            .observed
            .run_refs
            .iter()
            .cloned()
            .map(RunId::new)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| AssuranceError::Invalid)?;
        let observed = AssuranceObserved {
            distinct_independence_groups: wire.observed.distinct_independence_groups,
            run_refs,
            role_separation_satisfied: wire.observed.role_separation_satisfied,
            run_set_digest: Sha256Digest::new(wire.observed.run_set_digest.clone())
                .map_err(|_| AssuranceError::Invalid)?,
        };
        validate_wire(&wire, &observed)?;
        let mut unsigned = wire.clone();
        unsigned.receipt_digest = None;
        if sha256(&canonical(&unsigned)?) != expected {
            return Err(AssuranceError::Invalid);
        }
        Ok(Self {
            receipt_id: wire.receipt_id,
            task_id: TaskId::new(wire.task_id).map_err(|_| AssuranceError::Invalid)?,
            requested_profile: parse_requested_profile(&wire.requested_profile)?,
            requirements: wire.requirements,
            observed,
            reason_code: wire.reason_code,
            decision: wire.decision,
            actor_binding_id: wire.actor_binding_id,
            acceptance_artifact_ref: wire.acceptance_artifact_ref,
            created_at,
            created_at_rfc3339: wire.created_at,
            receipt_digest: expected,
            canonical_bytes: bytes.to_vec(),
        })
    }

    pub fn receipt_id(&self) -> &str {
        &self.receipt_id
    }
    pub fn task_id(&self) -> &TaskId {
        &self.task_id
    }
    pub fn requested_profile(&self) -> WorkflowProfile {
        self.requested_profile
    }
    pub fn requirements(&self) -> &AssuranceRequirements {
        &self.requirements
    }
    pub fn observed(&self) -> &AssuranceObserved {
        &self.observed
    }
    pub fn reason_code(&self) -> AssuranceReasonCode {
        self.reason_code
    }
    pub fn decision(&self) -> AssuranceDecision {
        self.decision
    }
    pub fn actor_binding_id(&self) -> Option<&str> {
        self.actor_binding_id.as_deref()
    }
    pub fn acceptance_artifact_ref(&self) -> Option<&str> {
        self.acceptance_artifact_ref.as_deref()
    }
    pub fn created_at(&self) -> Timestamp {
        self.created_at
    }
    pub fn created_at_rfc3339(&self) -> &str {
        &self.created_at_rfc3339
    }
    pub fn receipt_digest(&self) -> &Sha256Digest {
        &self.receipt_digest
    }
    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical_bytes
    }
}

fn validate_input(input: &AssuranceDegradationInput) -> Result<(), AssuranceError> {
    if !bounded(&input.receipt_id, MAX_ID)
        || input.task_id.as_str().chars().count() > MAX_ID
        || !matches!(
            input.requested_profile,
            WorkflowProfile::Standard | WorkflowProfile::HighAssurance
        )
        || !valid_profile_requirements(input.requested_profile, &input.requirements)
        || !(1..=16).contains(&input.requirements.minimum_distinct_independence_groups)
        || input.created_at.unix_seconds() < 0
        || input
            .actor_binding_id
            .as_deref()
            .is_some_and(|value| !bounded(value, MAX_ID))
        || input
            .acceptance_artifact_ref
            .as_deref()
            .is_some_and(|value| !bounded(value, MAX_REF))
        || input.assessment.runs.len() > 16
        || input.assessment.runs.iter().any(|run| {
            run.run_id.as_str().chars().count() > MAX_ID
                || !bounded(&run.independence_group, MAX_ID)
        })
        || matches!(input.decision, AssuranceDecision::ContinueDegraded)
            && (input.actor_binding_id.is_none() || input.acceptance_artifact_ref.is_none())
    {
        return Err(AssuranceError::Invalid);
    }
    Ok(())
}

fn observe(assessment: &AssuranceAssessment) -> Result<AssuranceObserved, AssuranceError> {
    let mut runs = assessment.runs.clone();
    runs.sort_by(|left, right| left.run_id.cmp(&right.run_id));
    if runs.windows(2).any(|pair| pair[0].run_id == pair[1].run_id) {
        return Err(AssuranceError::Invalid);
    }
    let run_refs = runs
        .iter()
        .map(|run| run.run_id.clone())
        .collect::<Vec<_>>();
    for role in [
        assessment.executor_run_id.as_ref(),
        assessment.reviewer_run_id.as_ref(),
    ]
    .into_iter()
    .flatten()
    {
        if run_refs.binary_search(role).is_err() {
            return Err(AssuranceError::Invalid);
        }
    }
    let groups = runs
        .iter()
        .map(|run| run.independence_group.as_str())
        .collect::<BTreeSet<_>>();
    let distinct_independence_groups =
        u8::try_from(groups.len()).map_err(|_| AssuranceError::Invalid)?;
    let role_separation_satisfied = matches!(
        (&assessment.executor_run_id, &assessment.reviewer_run_id),
        (Some(executor), Some(reviewer)) if executor != reviewer
    );
    let run_set = run_refs.iter().map(RunId::as_str).collect::<Vec<_>>();
    let run_set_digest = sha256(&canonical(&run_set)?);
    Ok(AssuranceObserved {
        distinct_independence_groups,
        run_refs,
        role_separation_satisfied,
        run_set_digest,
    })
}

fn validate_reason(
    input: &AssuranceDegradationInput,
    observed: &AssuranceObserved,
) -> Result<(), AssuranceError> {
    validate_observed_reason(&input.requirements, observed, input.reason_code)
}

fn validate_observed_reason(
    requirements: &AssuranceRequirements,
    observed: &AssuranceObserved,
    reason_code: AssuranceReasonCode,
) -> Result<(), AssuranceError> {
    let supported = match reason_code {
        AssuranceReasonCode::InsufficientIndependenceGroups => {
            observed.distinct_independence_groups
                < requirements.minimum_distinct_independence_groups
        }
        AssuranceReasonCode::RoleSeparationUnavailable => {
            requirements.executor_reviewer_separation_required
                && !observed.role_separation_satisfied
        }
        AssuranceReasonCode::ProviderUnavailable | AssuranceReasonCode::BudgetInsufficient => true,
    };
    if supported {
        Ok(())
    } else {
        Err(AssuranceError::Invalid)
    }
}

fn validate_wire(wire: &WireReceipt, observed: &AssuranceObserved) -> Result<(), AssuranceError> {
    if !bounded(&wire.receipt_id, MAX_ID)
        || !bounded(&wire.task_id, MAX_ID)
        || !matches!(
            wire.requested_profile.as_str(),
            "Standard" | "HighAssurance"
        )
        || !valid_profile_requirements(
            parse_requested_profile(&wire.requested_profile)?,
            &wire.requirements,
        )
        || !(1..=16).contains(&wire.requirements.minimum_distinct_independence_groups)
        || wire.observed.run_refs.len() > 16
        || wire
            .observed
            .run_refs
            .iter()
            .any(|run| !bounded(run, MAX_ID))
        || wire
            .observed
            .run_refs
            .windows(2)
            .any(|pair| pair[0] >= pair[1])
        || wire.observed.distinct_independence_groups > 16
        || observed.run_set_digest != sha256(&canonical(&wire.observed.run_refs)?)
        || wire
            .actor_binding_id
            .as_deref()
            .is_some_and(|value| !bounded(value, MAX_ID))
        || wire
            .acceptance_artifact_ref
            .as_deref()
            .is_some_and(|value| !bounded(value, MAX_REF))
        || matches!(wire.decision, AssuranceDecision::ContinueDegraded)
            && (wire.actor_binding_id.is_none() || wire.acceptance_artifact_ref.is_none())
    {
        return Err(AssuranceError::Invalid);
    }
    validate_observed_reason(&wire.requirements, observed, wire.reason_code)
}

fn wire(
    input: &AssuranceDegradationInput,
    observed: &AssuranceObserved,
    created_at: &str,
    receipt_digest: Option<&str>,
) -> WireReceipt {
    WireReceipt {
        schema_version: "1.0".to_owned(),
        receipt_id: input.receipt_id.clone(),
        task_id: input.task_id.as_str().to_owned(),
        requested_profile: input.requested_profile.as_str().to_owned(),
        requirements: input.requirements.clone(),
        observed: WireObserved {
            distinct_independence_groups: observed.distinct_independence_groups,
            run_refs: observed
                .run_refs
                .iter()
                .map(|run| run.as_str().to_owned())
                .collect(),
            role_separation_satisfied: observed.role_separation_satisfied,
            run_set_digest: observed.run_set_digest.as_str().to_owned(),
        },
        reason_code: input.reason_code,
        decision: input.decision,
        actor_binding_id: input.actor_binding_id.clone(),
        acceptance_artifact_ref: input.acceptance_artifact_ref.clone(),
        created_at: created_at.to_owned(),
        receipt_digest: receipt_digest.map(str::to_owned),
    }
}

fn parse_requested_profile(value: &str) -> Result<WorkflowProfile, AssuranceError> {
    match value {
        "Standard" => Ok(WorkflowProfile::Standard),
        "HighAssurance" => Ok(WorkflowProfile::HighAssurance),
        _ => Err(AssuranceError::Invalid),
    }
}

fn valid_profile_requirements(
    profile: WorkflowProfile,
    requirements: &AssuranceRequirements,
) -> bool {
    requirements.executor_reviewer_separation_required
        && match profile {
            WorkflowProfile::Standard => requirements.minimum_distinct_independence_groups >= 1,
            WorkflowProfile::HighAssurance => {
                requirements.minimum_distinct_independence_groups >= 2
            }
            WorkflowProfile::Quick | WorkflowProfile::ReadOnlyResearch => false,
        }
}

fn canonical<T: Serialize>(value: &T) -> Result<Vec<u8>, AssuranceError> {
    serde_json_canonicalizer::to_vec(value).map_err(|_| AssuranceError::Serialization)
}

fn sha256(bytes: &[u8]) -> Sha256Digest {
    Sha256Digest::new(format!("sha256:{:x}", Sha256::digest(bytes)))
        .expect("formatted SHA-256 is valid")
}

fn bounded(value: &str, maximum: usize) -> bool {
    !value.trim().is_empty() && value.chars().count() <= maximum
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn assurance_receipt_digest_excludes_its_own_field_and_round_trips() {
        let receipt = AssuranceDegradationReceipt::issue(AssuranceDegradationInput {
            receipt_id: "receipt-1".to_owned(),
            task_id: TaskId::new("task-1").unwrap(),
            requested_profile: WorkflowProfile::HighAssurance,
            requirements: AssuranceRequirements {
                minimum_distinct_independence_groups: 2,
                executor_reviewer_separation_required: true,
            },
            assessment: AssuranceAssessment {
                runs: vec![AssuranceRunEvidence {
                    run_id: RunId::new("run-1").unwrap(),
                    independence_group: "group-1".to_owned(),
                }],
                executor_run_id: Some(RunId::new("run-1").unwrap()),
                reviewer_run_id: Some(RunId::new("run-1").unwrap()),
            },
            reason_code: AssuranceReasonCode::InsufficientIndependenceGroups,
            decision: AssuranceDecision::ContinueDegraded,
            actor_binding_id: Some("actor-1".to_owned()),
            acceptance_artifact_ref: Some("artifact/acceptance-1".to_owned()),
            created_at: Timestamp::from_unix_seconds(1),
        })
        .unwrap();

        let mut unsigned: serde_json::Value =
            serde_json::from_slice(receipt.canonical_bytes()).unwrap();
        unsigned.as_object_mut().unwrap().remove("receiptDigest");
        assert_eq!(
            sha256(&serde_json_canonicalizer::to_vec(&unsigned).unwrap()),
            *receipt.receipt_digest()
        );
        assert_eq!(receipt.created_at_rfc3339(), "1970-01-01T00:00:01Z");
        assert_eq!(
            AssuranceDegradationReceipt::from_canonical_bytes(receipt.canonical_bytes()).unwrap(),
            receipt
        );
    }
}
