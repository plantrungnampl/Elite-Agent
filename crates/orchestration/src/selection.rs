use std::collections::{BTreeSet, HashSet};

use local_agent_terminal_application::DeliberationRunAssignment;
use local_agent_terminal_domain::{
    ArtifactId, DeliberationBudget, DeliberationLimits, ReviewEdge, ReviewPlan, SpecialistRequest,
    Timestamp,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentEligibility {
    pub assignment: DeliberationRunAssignment,
    pub capabilities: BTreeSet<String>,
    pub available: bool,
}

impl AgentEligibility {
    fn supports(&self, capability: &str) -> bool {
        self.capabilities.contains(capability)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SelectionDenial {
    InvalidCapability,
    InsufficientEligibleAgents,
    InsufficientDiversity,
    DependencyUnavailable,
    ReviewLimitExceeded,
}

pub fn select_independent_agents(
    candidates: &[AgentEligibility],
    capability: &str,
) -> Result<Vec<DeliberationRunAssignment>, SelectionDenial> {
    if !valid_label(capability) {
        return Err(SelectionDenial::InvalidCapability);
    }
    let mut capable = candidates
        .iter()
        .filter(|candidate| candidate.supports(capability))
        .collect::<Vec<_>>();
    capable.sort_by(|left, right| {
        (
            left.assignment.agent_id(),
            left.assignment.run_id().as_str(),
        )
            .cmp(&(
                right.assignment.agent_id(),
                right.assignment.run_id().as_str(),
            ))
    });
    let available = capable
        .iter()
        .copied()
        .filter(|candidate| candidate.available)
        .collect::<Vec<_>>();
    for (index, left) in available.iter().enumerate() {
        if let Some(right) = available[index + 1..]
            .iter()
            .find(|right| right.assignment.family() != left.assignment.family())
        {
            return Ok(vec![left.assignment.clone(), right.assignment.clone()]);
        }
    }
    let available_families = available
        .iter()
        .map(|candidate| candidate.assignment.family())
        .collect::<BTreeSet<_>>();
    let capable_families = capable
        .iter()
        .map(|candidate| candidate.assignment.family())
        .collect::<BTreeSet<_>>();
    if capable.len() >= 2
        && capable_families.len() >= 2
        && (available.len() < 2 || available_families.len() < 2)
    {
        Err(SelectionDenial::DependencyUnavailable)
    } else if available.len() >= 2 {
        Err(SelectionDenial::InsufficientDiversity)
    } else {
        Err(SelectionDenial::InsufficientEligibleAgents)
    }
}

pub fn assign_bounded_reviews(
    candidates: &[AgentEligibility],
    proposal_artifacts: &[ArtifactId],
    round: u32,
    limits: DeliberationLimits,
) -> Result<ReviewPlan, SelectionDenial> {
    let mut reviewers = candidates
        .iter()
        .filter(|candidate| candidate.available && candidate.supports("review"))
        .collect::<Vec<_>>();
    reviewers.sort_by(|left, right| left.assignment.agent_id().cmp(right.assignment.agent_id()));
    let unique_targets = proposal_artifacts.iter().collect::<HashSet<_>>();
    if reviewers.is_empty()
        || proposal_artifacts.is_empty()
        || unique_targets.len() != proposal_artifacts.len()
        || proposal_artifacts.len() > limits.max_review_edges() as usize
    {
        return Err(SelectionDenial::ReviewLimitExceeded);
    }
    let mut targets = proposal_artifacts.to_vec();
    targets.sort_by(|left, right| left.as_str().cmp(right.as_str()));
    let edges = targets
        .into_iter()
        .enumerate()
        .map(|(index, target)| {
            ReviewEdge::new(
                reviewers[index % reviewers.len()].assignment.agent_id(),
                target,
                round,
            )
            .map_err(|_| SelectionDenial::ReviewLimitExceeded)
        })
        .collect::<Result<Vec<_>, _>>()?;
    ReviewPlan::new(limits, edges).map_err(|_| SelectionDenial::ReviewLimitExceeded)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpecialistDenial {
    RequestExpired,
    CapabilityUnavailable,
    DependencyUnavailable,
    BudgetExceeded,
}

pub fn authorize_specialist(
    request: &SpecialistRequest,
    candidates: &[AgentEligibility],
    budget: &mut DeliberationBudget,
    now: Timestamp,
) -> Result<DeliberationRunAssignment, SpecialistDenial> {
    if request.budget().deadline() <= now {
        return Err(SpecialistDenial::RequestExpired);
    }
    let mut capable = candidates
        .iter()
        .filter(|candidate| candidate.supports(request.capability()))
        .collect::<Vec<_>>();
    capable.sort_by(|left, right| left.assignment.agent_id().cmp(right.assignment.agent_id()));
    let Some(selected) = capable.iter().find(|candidate| candidate.available) else {
        return if capable.is_empty() {
            Err(SpecialistDenial::CapabilityUnavailable)
        } else {
            Err(SpecialistDenial::DependencyUnavailable)
        };
    };
    budget
        .reserve(request.budget().max_tokens())
        .map_err(|_| SpecialistDenial::BudgetExceeded)?;
    Ok(selected.assignment.clone())
}

fn valid_label(value: &str) -> bool {
    !value.trim().is_empty() && value.len() <= 256 && !value.contains('\0')
}
