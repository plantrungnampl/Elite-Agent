use std::collections::{BTreeMap, BTreeSet};
use std::sync::OnceLock;

use serde::Deserialize;

use super::{Condition, OperationState, Phase, TaskOutcomeMode, WorkflowError, WorkflowProfile};

const WORKFLOW_JSON: &str = include_str!(
    "../../../../docs/multi-agent-terminal-design/schemas/workflow-transitions.v3.json"
);

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct WorkflowSpecification {
    schema_version: u64,
    authority_model: AuthorityModel,
    state_shape: StateShape,
    workflow_profiles: Vec<WorkflowProfile>,
    profile_rank: BTreeMap<WorkflowProfile, u64>,
    profile_escalations: Vec<ProfileEscalationRule>,
    profile_downgrade_within_task_forbidden: bool,
    read_only_research_write_conversion: String,
    task_outcome_modes: Vec<TaskOutcomeMode>,
    trusted_profile_selection: TrustedProfileSelection,
    phases: Vec<Phase>,
    terminal_phases: Vec<Phase>,
    conditions: Vec<Condition>,
    operation_states: Vec<OperationState>,
    phase_transitions: Vec<PhaseTransitionRule>,
    global_phase_transitions: Vec<GlobalPhaseTransitionRule>,
    workspace_dirty_transition: WorkspaceDirtyTransitionRule,
    condition_transitions: Vec<ConditionTransitionRule>,
}

#[derive(Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct AuthorityModel {
    semantic_authority: String,
    persistence_boundary: String,
    command_schema: String,
    atomic_order: Vec<String>,
    raw_projection_update_forbidden: bool,
}

#[derive(Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct StateShape {
    phase: String,
    condition: String,
    operation: String,
    workflow_profile: String,
    outcome_mode: String,
    stream_version: String,
    workspace_version: String,
    fencing_epoch: String,
    profile_revision: String,
    last_transition_event_id: String,
}

#[derive(Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct TrustedProfileSelection {
    selected_by: String,
    inputs: Vec<String>,
    agent_selection_forbidden: bool,
}

#[derive(Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ProfileEscalationRule {
    from: WorkflowProfile,
    to: WorkflowProfile,
    required_evidence_kinds: Vec<String>,
    required_effect_kinds: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct PhaseTransitionRule {
    rule_id: String,
    from: Phase,
    event: String,
    to: Phase,
    allowed_profiles: Vec<WorkflowProfile>,
    allowed_outcomes: Vec<TaskOutcomeMode>,
    guard: String,
    required_evidence_kinds: Vec<String>,
    effects: Vec<String>,
    required_effect_kinds: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct GlobalPhaseTransitionRule {
    rule_id: String,
    from_phases: Vec<Phase>,
    event: String,
    to: Phase,
    allowed_profiles: Vec<WorkflowProfile>,
    allowed_outcomes: Vec<TaskOutcomeMode>,
    guard: String,
    required_evidence_kinds: Vec<String>,
    effects: Vec<String>,
    required_effect_kinds: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct WorkspaceDirtyTransitionRule {
    rule_id: String,
    from_phases: Vec<Phase>,
    event: String,
    to: Phase,
    allowed_profiles: Vec<WorkflowProfile>,
    allowed_outcomes: Vec<TaskOutcomeMode>,
    guard: String,
    required_evidence_kinds: Vec<String>,
    effects: Vec<String>,
    required_effect_kinds: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct ConditionTransitionRule {
    pub(super) from: Condition,
    pub(super) event: String,
    pub(super) to: Condition,
    pub(super) guard: String,
}

impl WorkflowSpecification {
    fn parse() -> Result<Self, String> {
        Self::parse_json(WORKFLOW_JSON)
    }

    fn parse_json(json: &str) -> Result<Self, String> {
        let specification: Self = serde_json::from_str(json).map_err(|error| error.to_string())?;
        specification.validate()?;
        Ok(specification)
    }

    fn validate(&self) -> Result<(), String> {
        if self.schema_version != 3 {
            return Err(format!(
                "unsupported schema version {}",
                self.schema_version
            ));
        }
        self.validate_authority_model()?;
        self.validate_state_shape()?;
        self.validate_enums()?;
        self.validate_profile_rules()?;
        self.validate_command_rules()?;
        self.validate_condition_rules()?;
        Ok(())
    }

    fn validate_authority_model(&self) -> Result<(), String> {
        let expected = AuthorityModel {
            semantic_authority: "trusted_application_reducer".to_owned(),
            persistence_boundary: "sqlite_invariant_boundary".to_owned(),
            command_schema: "workflow-transition-command.v1".to_owned(),
            atomic_order: [
                "prepare_transition_event",
                "bind_guard_evidence",
                "bind_effects",
                "accept_transition_event",
                "update_projection",
            ]
            .into_iter()
            .map(str::to_owned)
            .collect(),
            raw_projection_update_forbidden: true,
        };
        if self.authority_model != expected {
            return Err("authority model does not match the v3 contract".to_owned());
        }
        Ok(())
    }

    fn validate_state_shape(&self) -> Result<(), String> {
        let expected = StateShape {
            phase: "PhaseV2".to_owned(),
            condition: "Condition".to_owned(),
            operation: "OperationState".to_owned(),
            workflow_profile: "WorkflowProfile".to_owned(),
            outcome_mode: "TaskOutcomeMode".to_owned(),
            stream_version: "u64".to_owned(),
            workspace_version: "u64".to_owned(),
            fencing_epoch: "u64".to_owned(),
            profile_revision: "u64".to_owned(),
            last_transition_event_id: "TransitionEventId".to_owned(),
        };
        if self.state_shape != expected {
            return Err("state shape does not match the v3 domain model".to_owned());
        }
        Ok(())
    }

    fn validate_enums(&self) -> Result<(), String> {
        if self.workflow_profiles.as_slice() != WorkflowProfile::ALL {
            return Err("workflow profile enum does not match the normative table".to_owned());
        }
        if self.task_outcome_modes.as_slice() != TaskOutcomeMode::ALL {
            return Err("task outcome enum does not match the normative table".to_owned());
        }
        if self.phases.as_slice() != Phase::ALL {
            return Err("phase enum does not match the normative table".to_owned());
        }
        if self.terminal_phases.as_slice() != [Phase::Completed, Phase::Cancelled, Phase::Failed] {
            return Err("terminal phase list does not match the domain model".to_owned());
        }
        if self.conditions.as_slice() != Condition::ALL {
            return Err("condition enum does not match the normative table".to_owned());
        }
        if self.operation_states.as_slice() != OperationState::ALL {
            return Err("operation enum does not match the normative table".to_owned());
        }
        Ok(())
    }

    fn validate_profile_rules(&self) -> Result<(), String> {
        let expected_ranks = BTreeMap::from([
            (WorkflowProfile::Quick, 1),
            (WorkflowProfile::Standard, 2),
            (WorkflowProfile::HighAssurance, 3),
        ]);
        if self.profile_rank != expected_ranks {
            return Err("profile ranks do not match the v3 contract".to_owned());
        }
        let expected_escalations = [
            (WorkflowProfile::Quick, WorkflowProfile::Standard),
            (WorkflowProfile::Quick, WorkflowProfile::HighAssurance),
            (WorkflowProfile::Standard, WorkflowProfile::HighAssurance),
        ];
        if self.profile_escalations.len() != expected_escalations.len()
            || self
                .profile_escalations
                .iter()
                .zip(expected_escalations)
                .any(|(rule, (from, to))| {
                    rule.from != from
                        || rule.to != to
                        || rule.required_evidence_kinds != ["risk_reassessment_receipt"]
                        || rule.required_effect_kinds
                            != [
                                "persist_profile_revision",
                                "recompute_assurance_requirements",
                            ]
                })
        {
            return Err("profile escalations do not match the v3 contract".to_owned());
        }
        if !self.profile_downgrade_within_task_forbidden
            || self.read_only_research_write_conversion
                != "new_child_task_with_explicit_approval_boundary"
        {
            return Err("profile downgrade policy does not match the v3 contract".to_owned());
        }
        let expected_selection = TrustedProfileSelection {
            selected_by: "trusted_core".to_owned(),
            inputs: ["risk", "scope", "policy", "user_override"]
                .into_iter()
                .map(str::to_owned)
                .collect(),
            agent_selection_forbidden: true,
        };
        if self.trusted_profile_selection != expected_selection {
            return Err("trusted profile selection does not match the v3 contract".to_owned());
        }
        Ok(())
    }

    fn validate_command_rules(&self) -> Result<(), String> {
        if self.phase_transitions.len() != 30
            || self.global_phase_transitions.len() != 2
            || self.workspace_dirty_transition.rule_id != "WF-W001"
        {
            return Err("v3 command rule counts do not match the authority contract".to_owned());
        }

        let mut ids = BTreeSet::new();
        let mut selectors = BTreeMap::new();
        for rule in &self.phase_transitions {
            validate_command_values(
                &rule.rule_id,
                "WF-P",
                CommandRuleAuthority {
                    event: &rule.event,
                    guard: &rule.guard,
                    profiles: &rule.allowed_profiles,
                    outcomes: &rule.allowed_outcomes,
                    evidence: &rule.required_evidence_kinds,
                    effects: &rule.effects,
                    required_effects: &rule.required_effect_kinds,
                },
            )?;
            claim_rule_id(&mut ids, &rule.rule_id)?;
            claim_command_selectors(
                &mut selectors,
                &rule.rule_id,
                std::slice::from_ref(&rule.from),
                &rule.event,
                &rule.allowed_profiles,
                &rule.allowed_outcomes,
            )?;
        }
        for rule in &self.global_phase_transitions {
            validate_command_values(
                &rule.rule_id,
                "WF-G",
                CommandRuleAuthority {
                    event: &rule.event,
                    guard: &rule.guard,
                    profiles: &rule.allowed_profiles,
                    outcomes: &rule.allowed_outcomes,
                    evidence: &rule.required_evidence_kinds,
                    effects: &rule.effects,
                    required_effects: &rule.required_effect_kinds,
                },
            )?;
            claim_rule_id(&mut ids, &rule.rule_id)?;
            claim_command_selectors(
                &mut selectors,
                &rule.rule_id,
                &rule.from_phases,
                &rule.event,
                &rule.allowed_profiles,
                &rule.allowed_outcomes,
            )?;
        }
        let rule = &self.workspace_dirty_transition;
        validate_command_values(
            &rule.rule_id,
            "WF-W",
            CommandRuleAuthority {
                event: &rule.event,
                guard: &rule.guard,
                profiles: &rule.allowed_profiles,
                outcomes: &rule.allowed_outcomes,
                evidence: &rule.required_evidence_kinds,
                effects: &rule.effects,
                required_effects: &rule.required_effect_kinds,
            },
        )?;
        claim_rule_id(&mut ids, &rule.rule_id)?;
        claim_command_selectors(
            &mut selectors,
            &rule.rule_id,
            &rule.from_phases,
            &rule.event,
            &rule.allowed_profiles,
            &rule.allowed_outcomes,
        )?;
        if ids.len() != 33 {
            return Err("command rule IDs must be unique".to_owned());
        }
        Ok(())
    }

    fn validate_condition_rules(&self) -> Result<(), String> {
        if self.condition_transitions.len() != 6 {
            return Err("v3 condition rule count does not match the authority contract".to_owned());
        }
        let mut routes = BTreeSet::new();
        let mut selectors = BTreeMap::new();
        for rule in &self.condition_transitions {
            if rule.event.trim().is_empty() || rule.guard.trim().is_empty() {
                return Err("condition rules require non-empty event and guard".to_owned());
            }
            let route = (rule.from, rule.event.clone(), rule.to, rule.guard.clone());
            if !routes.insert(route) {
                return Err("duplicate condition route".to_owned());
            }
            let selector = (rule.from, rule.event.clone());
            if let Some(previous) = selectors.insert(selector, rule.to) {
                return Err(format!(
                    "ambiguous condition route from {} for {} and {}",
                    rule.from, rule.event, previous
                ));
            }
        }
        Ok(())
    }

    pub(super) fn command_rule(&self, rule_id: &str) -> Option<CommandRule<'_>> {
        self.phase_transitions
            .iter()
            .find(|rule| rule.rule_id == rule_id)
            .map(CommandRule::Phase)
            .or_else(|| {
                self.global_phase_transitions
                    .iter()
                    .find(|rule| rule.rule_id == rule_id)
                    .map(CommandRule::Global)
            })
            .or_else(|| {
                (self.workspace_dirty_transition.rule_id == rule_id)
                    .then_some(CommandRule::Workspace(&self.workspace_dirty_transition))
            })
    }

    pub(super) fn condition_rule(
        &self,
        condition: Condition,
        event: &str,
    ) -> Option<&ConditionTransitionRule> {
        self.condition_transitions
            .iter()
            .find(|rule| rule.from == condition && rule.event == event)
    }
}

struct CommandRuleAuthority<'a> {
    event: &'a str,
    guard: &'a str,
    profiles: &'a [WorkflowProfile],
    outcomes: &'a [TaskOutcomeMode],
    evidence: &'a [String],
    effects: &'a [String],
    required_effects: &'a [String],
}

fn validate_command_values(
    rule_id: &str,
    prefix: &str,
    authority: CommandRuleAuthority<'_>,
) -> Result<(), String> {
    if !valid_rule_id(rule_id, prefix) {
        return Err(format!("missing or invalid {prefix} rule ID {rule_id:?}"));
    }
    if authority.event.trim().is_empty() || authority.guard.trim().is_empty() {
        return Err(format!("rule {rule_id} requires non-empty event and guard"));
    }
    if authority.profiles.is_empty()
        || authority.outcomes.is_empty()
        || authority.evidence.is_empty()
        || authority.effects.is_empty()
        || authority.required_effects.is_empty()
        || !unique(authority.profiles)
        || !unique(authority.outcomes)
        || !unique(authority.evidence)
        || !unique(authority.effects)
        || !unique(authority.required_effects)
        || authority.effects != authority.required_effects
    {
        return Err(format!("rule {rule_id} has invalid authority sets"));
    }
    Ok(())
}

fn valid_rule_id(rule_id: &str, prefix: &str) -> bool {
    rule_id.len() == 7
        && rule_id.starts_with(prefix)
        && rule_id.as_bytes()[4..].iter().all(u8::is_ascii_digit)
}

fn unique<T>(values: &[T]) -> bool
where
    T: Ord + Clone,
{
    values.iter().cloned().collect::<BTreeSet<_>>().len() == values.len()
}

fn claim_rule_id(ids: &mut BTreeSet<String>, rule_id: &str) -> Result<(), String> {
    if !ids.insert(rule_id.to_owned()) {
        return Err(format!("duplicate rule ID {rule_id}"));
    }
    Ok(())
}

type CommandSelector = (Phase, String, WorkflowProfile, TaskOutcomeMode);

fn claim_command_selectors(
    selectors: &mut BTreeMap<CommandSelector, String>,
    rule_id: &str,
    phases: &[Phase],
    event: &str,
    profiles: &[WorkflowProfile],
    outcomes: &[TaskOutcomeMode],
) -> Result<(), String> {
    if phases.is_empty() || !unique(phases) {
        return Err(format!("rule {rule_id} has invalid source phases"));
    }
    for phase in phases {
        for profile in profiles {
            for outcome in outcomes {
                let selector = (*phase, event.to_owned(), *profile, *outcome);
                if let Some(previous) = selectors.insert(selector, rule_id.to_owned()) {
                    return Err(format!(
                        "ambiguous profile route for {event} from {phase}: {previous} and {rule_id}"
                    ));
                }
            }
        }
    }
    Ok(())
}

pub(super) enum CommandRule<'a> {
    Phase(&'a PhaseTransitionRule),
    Global(&'a GlobalPhaseTransitionRule),
    Workspace(&'a WorkspaceDirtyTransitionRule),
}

impl CommandRule<'_> {
    pub(super) fn rule_id(&self) -> &str {
        match self {
            Self::Phase(rule) => &rule.rule_id,
            Self::Global(rule) => &rule.rule_id,
            Self::Workspace(rule) => &rule.rule_id,
        }
    }

    pub(super) fn event(&self) -> &str {
        match self {
            Self::Phase(rule) => &rule.event,
            Self::Global(rule) => &rule.event,
            Self::Workspace(rule) => &rule.event,
        }
    }

    pub(super) fn target(&self) -> Phase {
        match self {
            Self::Phase(rule) => rule.to,
            Self::Global(rule) => rule.to,
            Self::Workspace(rule) => rule.to,
        }
    }

    pub(super) fn allows_source(&self, phase: Phase) -> bool {
        match self {
            Self::Phase(rule) => rule.from == phase,
            Self::Global(rule) => rule.from_phases.contains(&phase),
            Self::Workspace(rule) => rule.from_phases.contains(&phase),
        }
    }

    pub(super) fn allows_profile(&self, profile: WorkflowProfile) -> bool {
        match self {
            Self::Phase(rule) => rule.allowed_profiles.contains(&profile),
            Self::Global(rule) => rule.allowed_profiles.contains(&profile),
            Self::Workspace(rule) => rule.allowed_profiles.contains(&profile),
        }
    }

    pub(super) fn allows_outcome(&self, outcome: TaskOutcomeMode) -> bool {
        match self {
            Self::Phase(rule) => rule.allowed_outcomes.contains(&outcome),
            Self::Global(rule) => rule.allowed_outcomes.contains(&outcome),
            Self::Workspace(rule) => rule.allowed_outcomes.contains(&outcome),
        }
    }

    pub(super) fn required_evidence_kinds(&self) -> &[String] {
        match self {
            Self::Phase(rule) => &rule.required_evidence_kinds,
            Self::Global(rule) => &rule.required_evidence_kinds,
            Self::Workspace(rule) => &rule.required_evidence_kinds,
        }
    }

    pub(super) fn required_effect_kinds(&self) -> &[String] {
        match self {
            Self::Phase(rule) => &rule.required_effect_kinds,
            Self::Global(rule) => &rule.required_effect_kinds,
            Self::Workspace(rule) => &rule.required_effect_kinds,
        }
    }

    pub(super) fn effects(&self) -> &[String] {
        match self {
            Self::Phase(rule) => &rule.effects,
            Self::Global(rule) => &rule.effects,
            Self::Workspace(rule) => &rule.effects,
        }
    }
}

static SPECIFICATION: OnceLock<Result<WorkflowSpecification, String>> = OnceLock::new();

pub(super) fn workflow_specification() -> Result<&'static WorkflowSpecification, WorkflowError> {
    SPECIFICATION
        .get_or_init(WorkflowSpecification::parse)
        .as_ref()
        .map_err(|message| WorkflowError::InvalidSpecification(message.clone()))
}

#[cfg(test)]
mod tests {
    use serde_json::{json, Value};

    use super::*;

    fn normative_value() -> Value {
        serde_json::from_str(WORKFLOW_JSON).expect("normative workflow JSON")
    }

    fn parse_for_test(value: Value) -> Result<WorkflowSpecification, String> {
        WorkflowSpecification::parse_json(&serde_json::to_string(&value).unwrap())
    }

    #[test]
    fn specification_rejects_unknown_rule_fields_missing_rule_ids_and_ambiguous_profiles() {
        let mut unknown = normative_value();
        unknown["phaseTransitions"][0]["invented"] = json!(true);
        assert!(parse_for_test(unknown).is_err());

        let mut missing_id = normative_value();
        missing_id["phaseTransitions"][0]
            .as_object_mut()
            .unwrap()
            .remove("ruleId");
        assert!(parse_for_test(missing_id).is_err());

        let mut ambiguous = normative_value();
        ambiguous["phaseTransitions"]
            .as_array_mut()
            .unwrap()
            .iter_mut()
            .find(|rule| rule["ruleId"] == "WF-P009")
            .unwrap()["allowedProfiles"] = json!(["Standard"]);
        assert!(parse_for_test(ambiguous).is_err());
    }

    #[test]
    fn specification_rejects_condition_rule_ids_and_effects() {
        let mut id = normative_value();
        id["conditionTransitions"][0]["ruleId"] = json!("WF-C001");
        assert!(parse_for_test(id).is_err());

        let mut effects = normative_value();
        effects["conditionTransitions"][0]["effects"] = json!(["invented"]);
        assert!(parse_for_test(effects).is_err());
    }
}
