use std::collections::BTreeSet;

use local_agent_terminal_application::{
    DeliberationArtifactRef, DeliberationClaimSource, DeliberationCommandContext,
    DeliberationPlanDto, DeliberationSnapshot, DeliberationSynthesisStore,
    DeliberationWorkflowAuthority, PersistDeliberationSynthesis, PortError,
};
use local_agent_terminal_domain::{
    ClaimVerification, DecisionPackage, DeliberationError, MaterialClaim, VerificationMethod,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClaimOrchestrationError {
    DuplicateClaim,
    InvalidCandidate(DeliberationError),
    InvalidClassification(DeliberationError),
    Port(PortError),
}

pub fn extract_material_claims(
    snapshot: &DeliberationSnapshot,
    source: &dyn DeliberationClaimSource,
) -> Result<Vec<MaterialClaim>, ClaimOrchestrationError> {
    snapshot.validate().map_err(ClaimOrchestrationError::Port)?;
    if snapshot.quorum_publication().is_none() {
        return Err(ClaimOrchestrationError::InvalidCandidate(
            DeliberationError::InvalidClaim,
        ));
    }
    let mut proposal_artifacts = snapshot
        .private_proposals()
        .iter()
        .map(|proposal| proposal.proposal_artifact())
        .collect::<Vec<_>>();
    proposal_artifacts.sort_by_key(|artifact| artifact.artifact_id().as_str());
    let mut summaries = snapshot.thread_summaries().iter().collect::<Vec<_>>();
    summaries.sort_by(|left, right| {
        (left.thread_id(), left.artifact().artifact_id().as_str())
            .cmp(&(right.thread_id(), right.artifact().artifact_id().as_str()))
    });
    let mut extracted = Vec::new();
    for artifact in proposal_artifacts
        .into_iter()
        .chain(summaries.into_iter().map(|summary| summary.artifact()))
    {
        let candidates = source
            .claims_for_artifact(&snapshot.task_id, artifact)
            .map_err(ClaimOrchestrationError::Port)?;
        for candidate in candidates {
            extracted.push(
                candidate
                    .to_material_claim(artifact.artifact_id().clone())
                    .map_err(ClaimOrchestrationError::Port)?,
            );
        }
    }
    normalize_material_claims(extracted)
}

pub struct SynthesisRequest {
    pub context: DeliberationCommandContext,
    pub decision: DecisionPackage,
    pub plan: DeliberationPlanDto,
    pub plan_artifact: DeliberationArtifactRef,
    pub plan_version: u64,
}

pub(crate) fn persist_synthesis(
    store: &dyn DeliberationSynthesisStore,
    workflow_authority: &dyn DeliberationWorkflowAuthority,
    request: SynthesisRequest,
) -> Result<(), PortError> {
    PersistDeliberationSynthesis::with_workflow_authority(store, workflow_authority).execute(
        request.context,
        request.decision,
        request.plan,
        request.plan_artifact,
        request.plan_version,
    )
}

pub fn normalize_material_claims(
    mut claims: Vec<MaterialClaim>,
) -> Result<Vec<MaterialClaim>, ClaimOrchestrationError> {
    let unique = claims
        .iter()
        .map(MaterialClaim::claim_id)
        .collect::<BTreeSet<_>>();
    if claims.is_empty() || unique.len() != claims.len() {
        return Err(ClaimOrchestrationError::DuplicateClaim);
    }
    claims.sort_by(|left, right| left.claim_id().cmp(right.claim_id()));
    Ok(claims)
}

pub fn classify_material_claims<F>(
    claims: Vec<MaterialClaim>,
    mut checker: F,
) -> Result<Vec<MaterialClaim>, ClaimOrchestrationError>
where
    F: FnMut(&MaterialClaim) -> Result<ClaimVerification, PortError>,
{
    let mut claims = normalize_material_claims(claims)?;
    claims.sort_by(|left, right| {
        (method_order(left.method()), left.claim_id())
            .cmp(&(method_order(right.method()), right.claim_id()))
    });
    let mut classified = Vec::with_capacity(claims.len());
    for claim in claims {
        let verification = checker(&claim).map_err(ClaimOrchestrationError::Port)?;
        classified.push(
            claim
                .classify(verification)
                .map_err(ClaimOrchestrationError::InvalidClassification)?,
        );
    }
    classified.sort_by(|left, right| left.claim_id().cmp(right.claim_id()));
    Ok(classified)
}

const fn method_order(method: VerificationMethod) -> u8 {
    match method {
        VerificationMethod::DeterministicCheck => 0,
        VerificationMethod::SourceMatch => 1,
        VerificationMethod::PolicyReview => 2,
        VerificationMethod::NotApplicable => 3,
    }
}
