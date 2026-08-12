use std::collections::BTreeSet;

use crate::{Effect, GuardEvaluations, GuardName, WorkflowEvent};

use super::specification::workflow_specification;
use super::{Transition, TransitionRequest, WorkflowError, WorkflowState};

pub fn reduce(
    state: &WorkflowState,
    request: &TransitionRequest,
) -> Result<Transition, WorkflowError> {
    if state.phase().is_terminal() {
        return Err(WorkflowError::TerminalPhase {
            phase: state.phase(),
        });
    }

    let specification = workflow_specification()?;
    let rule = specification
        .command_rule(&request.rule_id)
        .ok_or_else(|| WorkflowError::UnknownRuleId {
            rule_id: request.rule_id.clone(),
        })?;
    if !rule.allows_source(state.phase()) {
        return Err(WorkflowError::RuleSourceMismatch {
            rule_id: rule.rule_id().to_owned(),
            phase: state.phase(),
        });
    }
    if rule.event() != request.event.as_str() {
        return Err(WorkflowError::RuleEventMismatch {
            rule_id: rule.rule_id().to_owned(),
            event: request.event.clone(),
        });
    }
    if !rule.allows_profile(state.workflow_profile()) {
        return Err(WorkflowError::ProfileNotAllowed {
            rule_id: rule.rule_id().to_owned(),
            profile: state.workflow_profile(),
        });
    }
    if !rule.allows_outcome(state.outcome_mode()) {
        return Err(WorkflowError::OutcomeNotAllowed {
            rule_id: rule.rule_id().to_owned(),
            outcome: state.outcome_mode(),
        });
    }
    if !exact_set(
        &request.guard_evidence_kinds,
        rule.required_evidence_kinds(),
    ) {
        return Err(WorkflowError::GuardEvidenceMismatch {
            rule_id: rule.rule_id().to_owned(),
        });
    }
    if !exact_set(&request.effect_kinds, rule.required_effect_kinds()) {
        return Err(WorkflowError::EffectKindsMismatch {
            rule_id: rule.rule_id().to_owned(),
        });
    }

    let effects = rule
        .effects()
        .iter()
        .map(|kind| {
            Effect::new(kind)
                .map_err(|error| WorkflowError::InvalidSpecification(error.to_string()))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let next = state.transition_phase(rule.target(), &effects)?;
    Ok(Transition::command(
        next,
        effects,
        rule.rule_id().to_owned(),
    ))
}

pub fn reduce_condition(
    state: &WorkflowState,
    event: &WorkflowEvent,
    guards: &GuardEvaluations,
) -> Result<Transition, WorkflowError> {
    if state.phase().is_terminal() {
        return Err(WorkflowError::TerminalPhase {
            phase: state.phase(),
        });
    }

    let specification = workflow_specification()?;
    let rule = specification
        .condition_rule(state.condition(), event.as_str())
        .ok_or_else(|| WorkflowError::UndeclaredTransition {
            phase: state.phase(),
            condition: state.condition(),
            operation: state.operation(),
            event: event.clone(),
        })?;
    validate_guard(&rule.guard, guards)?;
    Ok(Transition::condition(state.transition_condition(rule.to)?))
}

fn exact_set(actual: &BTreeSet<String>, required: &[String]) -> bool {
    actual.len() == required.len() && required.iter().all(|item| actual.contains(item))
}

fn validate_guard(guard: &str, evaluations: &GuardEvaluations) -> Result<(), WorkflowError> {
    let guard = GuardName::new(guard)
        .map_err(|error| WorkflowError::InvalidSpecification(error.to_string()))?;
    match evaluations.get(&guard) {
        Some(true) => Ok(()),
        Some(false) => Err(WorkflowError::GuardRejected { guard }),
        None => Err(WorkflowError::GuardNotEvaluated { guard }),
    }
}
