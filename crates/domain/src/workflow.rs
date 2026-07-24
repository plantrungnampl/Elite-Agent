use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::str::FromStr;
use std::sync::OnceLock;

use serde::Deserialize;

use crate::{
    Effect, FencingToken, GuardEvaluations, GuardName, Sequence, WorkflowEvent, WorkspaceVersion,
};

const WORKFLOW_JSON: &str =
    include_str!("../../../docs/multi-agent-terminal-design/schemas/workflow-transitions.v1.json");
const OBSERVED_WORKSPACE_MUTATION_EVENT: &str = "workspace.mutated";

macro_rules! workflow_enum {
    ($name:ident { $($variant:ident),+ $(,)? }) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize)]
        pub enum $name {
            $($variant),+
        }

        impl $name {
            pub const ALL: &'static [Self] = &[$(Self::$variant),+];

            pub const fn as_str(self) -> &'static str {
                match self {
                    $(Self::$variant => stringify!($variant)),+
                }
            }
        }

        impl FromStr for $name {
            type Err = ParseWorkflowValueError;

            fn from_str(value: &str) -> Result<Self, Self::Err> {
                Self::ALL
                    .iter()
                    .copied()
                    .find(|candidate| candidate.as_str() == value)
                    .ok_or_else(|| ParseWorkflowValueError {
                        kind: stringify!($name),
                        value: value.to_owned(),
                    })
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(self.as_str())
            }
        }
    };
}

workflow_enum!(Phase {
    Intake,
    ContextBuild,
    ParallelAnalysis,
    CrossReview,
    PrePlanVerification,
    Synthesis,
    FinalObjection,
    AwaitingPlanApproval,
    Implementation,
    Verification,
    Repair,
    FinalReview,
    AwaitingCommitApproval,
    LocalCommit,
    WorkspaceDirty,
    Completed,
    Cancelled,
    Failed,
});

impl Phase {
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Completed | Self::Cancelled | Self::Failed)
    }
}

workflow_enum!(Condition {
    Active,
    Paused,
    Blocked,
    BudgetExhausted,
});

workflow_enum!(OperationState {
    None,
    AwaitingApproval,
    Running,
    Cancelling,
    Indeterminate,
});

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseWorkflowValueError {
    kind: &'static str,
    value: String,
}

impl fmt::Display for ParseWorkflowValueError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "unknown {} value {:?}", self.kind, self.value)
    }
}

impl std::error::Error for ParseWorkflowValueError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WorkflowState {
    phase: Phase,
    condition: Condition,
    operation: OperationState,
    sequence: Sequence,
    workspace_version: WorkspaceVersion,
    fencing_token: FencingToken,
}

impl WorkflowState {
    pub fn new(
        phase: Phase,
        condition: Condition,
        operation: OperationState,
        sequence: Sequence,
        workspace_version: WorkspaceVersion,
        fencing_token: FencingToken,
    ) -> Result<Self, WorkflowError> {
        if phase.is_terminal()
            && (condition != Condition::Active || operation != OperationState::None)
        {
            return Err(WorkflowError::InvalidTerminalState {
                phase,
                condition,
                operation,
            });
        }

        Ok(Self {
            phase,
            condition,
            operation,
            sequence,
            workspace_version,
            fencing_token,
        })
    }

    pub const fn phase(&self) -> Phase {
        self.phase
    }

    pub const fn condition(&self) -> Condition {
        self.condition
    }

    pub const fn operation(&self) -> OperationState {
        self.operation
    }

    pub const fn sequence(&self) -> Sequence {
        self.sequence
    }

    pub const fn workspace_version(&self) -> WorkspaceVersion {
        self.workspace_version
    }

    pub const fn fencing_token(&self) -> FencingToken {
        self.fencing_token
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Transition {
    state: WorkflowState,
    effects: Vec<Effect>,
}

impl Transition {
    pub fn state(&self) -> &WorkflowState {
        &self.state
    }

    pub fn effects(&self) -> &[Effect] {
        &self.effects
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WorkflowError {
    InvalidSpecification(String),
    InvalidTerminalState {
        phase: Phase,
        condition: Condition,
        operation: OperationState,
    },
    TerminalPhase {
        phase: Phase,
    },
    UndeclaredTransition {
        phase: Phase,
        condition: Condition,
        operation: OperationState,
        event: WorkflowEvent,
    },
    GuardNotEvaluated {
        guard: GuardName,
    },
    GuardRejected {
        guard: GuardName,
    },
    PhaseNotDispatchable {
        condition: Condition,
        operation: OperationState,
    },
    OperationNotDispatchable {
        condition: Condition,
    },
    OperationNotResolved {
        operation: OperationState,
    },
    VersionOverflow {
        field: &'static str,
    },
}

impl fmt::Display for WorkflowError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidSpecification(message) => {
                write!(formatter, "invalid workflow specification: {message}")
            }
            Self::InvalidTerminalState {
                phase,
                condition,
                operation,
            } => write!(
                formatter,
                "terminal phase {phase} requires Active/None, got {condition}/{operation}"
            ),
            Self::TerminalPhase { phase } => {
                write!(formatter, "terminal phase {phase} cannot transition")
            }
            Self::UndeclaredTransition {
                phase,
                condition,
                operation,
                event,
            } => write!(
                formatter,
                "event {event} is undeclared from {phase}/{condition}/{operation}"
            ),
            Self::GuardNotEvaluated { guard } => {
                write!(formatter, "guard {guard} was not evaluated")
            }
            Self::GuardRejected { guard } => write!(formatter, "guard {guard} rejected"),
            Self::PhaseNotDispatchable {
                condition,
                operation,
            } => write!(
                formatter,
                "phase cannot advance with condition {condition} and operation {operation}"
            ),
            Self::OperationNotDispatchable { condition } => {
                write!(
                    formatter,
                    "operation cannot start with condition {condition}"
                )
            }
            Self::OperationNotResolved { operation } => {
                write!(formatter, "operation {operation} is not resolved")
            }
            Self::VersionOverflow { field } => write!(formatter, "{field} overflow"),
        }
    }
}

impl std::error::Error for WorkflowError {}

pub fn reduce(
    state: &WorkflowState,
    event: &WorkflowEvent,
    guards: &GuardEvaluations,
) -> Result<Transition, WorkflowError> {
    if state.phase.is_terminal() {
        return Err(WorkflowError::TerminalPhase { phase: state.phase });
    }

    let specification = workflow_specification()?;
    let selected = select_transition(specification, state, event).ok_or_else(|| {
        WorkflowError::UndeclaredTransition {
            phase: state.phase,
            condition: state.condition,
            operation: state.operation,
            event: event.clone(),
        }
    })?;

    if selected.is_primary_phase()
        && (state.condition != Condition::Active || state.operation != OperationState::None)
    {
        return Err(WorkflowError::PhaseNotDispatchable {
            condition: state.condition,
            operation: state.operation,
        });
    }
    if selected.enters_running_operation() && state.condition != Condition::Active {
        return Err(WorkflowError::OperationNotDispatchable {
            condition: state.condition,
        });
    }

    selected.validate_preconditions(state)?;
    validate_guard(selected.guard(), guards)?;

    let effects = selected.effects()?;
    let observed_workspace_mutation = selected.is_observed_workspace_mutation();
    let mut next = *state;
    selected.apply_axis(&mut next);
    apply_effect_semantics(&effects, observed_workspace_mutation, &mut next)?;
    normalize_terminal(&mut next);
    next.sequence = state
        .sequence
        .checked_increment()
        .ok_or(WorkflowError::VersionOverflow { field: "sequence" })?;

    Ok(Transition {
        state: next,
        effects,
    })
}

fn validate_guard(
    guard: Option<&str>,
    evaluations: &GuardEvaluations,
) -> Result<(), WorkflowError> {
    let Some(name) = guard else {
        return Ok(());
    };
    let guard = GuardName::new(name)
        .map_err(|error| WorkflowError::InvalidSpecification(error.to_string()))?;
    match evaluations.get(&guard) {
        Some(true) => Ok(()),
        Some(false) => Err(WorkflowError::GuardRejected { guard }),
        None => Err(WorkflowError::GuardNotEvaluated { guard }),
    }
}

fn apply_effect_semantics(
    effects: &[Effect],
    observed_workspace_mutation: bool,
    state: &mut WorkflowState,
) -> Result<(), WorkflowError> {
    // Cross-document invariant: docs/multi-agent-terminal-design/
    // 13-trust-sandbox-model.md §10 requires every observed workspace mutation to
    // increment the version; this is not a JSON-declared effect.
    let increment_workspace = observed_workspace_mutation
        || effects
            .iter()
            .any(|effect| effect.as_str() == "increment_workspace_version");
    if increment_workspace {
        state.workspace_version =
            state
                .workspace_version
                .checked_increment()
                .ok_or(WorkflowError::VersionOverflow {
                    field: "workspace version",
                })?;
    }

    let increment_fencing = effects.iter().any(|effect| {
        matches!(
            effect.as_str(),
            "increment_fencing_epoch" | "allocate_executor_lease" | "allocate_new_executor_token"
        )
    });
    if increment_fencing {
        state.fencing_token =
            state
                .fencing_token
                .checked_increment()
                .ok_or(WorkflowError::VersionOverflow {
                    field: "fencing token",
                })?;
    }

    if effects
        .iter()
        .any(|effect| effect.as_str() == "stop_new_dispatch_and_resolve_in_flight_operation")
        && state.operation == OperationState::Running
    {
        state.operation = OperationState::Cancelling;
    }

    Ok(())
}

fn normalize_terminal(state: &mut WorkflowState) {
    if state.phase.is_terminal() {
        state.condition = Condition::Active;
        state.operation = OperationState::None;
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct WorkflowSpecification {
    schema_version: u64,
    state_shape: StateShape,
    phases: Vec<Phase>,
    terminal_phases: Vec<Phase>,
    conditions: Vec<Condition>,
    operation_states: Vec<OperationState>,
    phase_transitions: Vec<PhaseTransitionRule>,
    workspace_dirty_sources: Vec<Phase>,
    workspace_dirty_transition: WorkspaceDirtyRule,
    condition_transitions: Vec<ConditionTransitionRule>,
    operation_transitions: Vec<OperationTransitionRule>,
    global_events: BTreeMap<String, GlobalRule>,
}

#[derive(Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct StateShape {
    phase: String,
    condition: String,
    operation: String,
    stream_version: String,
    workspace_version: String,
    fencing_epoch: String,
}

impl WorkflowSpecification {
    fn parse() -> Result<Self, String> {
        let specification: Self =
            serde_json::from_str(WORKFLOW_JSON).map_err(|error| error.to_string())?;
        specification.validate()?;
        Ok(specification)
    }

    fn validate(&self) -> Result<(), String> {
        if self.schema_version != 1 {
            return Err(format!(
                "unsupported schema version {}",
                self.schema_version
            ));
        }
        let expected_shape = StateShape {
            phase: "Phase".to_owned(),
            condition: "Condition".to_owned(),
            operation: "OperationState".to_owned(),
            stream_version: "u64".to_owned(),
            workspace_version: "u64".to_owned(),
            fencing_epoch: "u64".to_owned(),
        };
        if self.state_shape != expected_shape {
            return Err("state shape does not match the domain model".to_owned());
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
        if self.workspace_dirty_transition.event != OBSERVED_WORKSPACE_MUTATION_EVENT
            || self.workspace_dirty_transition.to != Phase::WorkspaceDirty
        {
            return Err("observed workspace mutation rule must target WorkspaceDirty".to_owned());
        }
        self.validate_unique_transition_selectors()?;
        Ok(())
    }

    fn validate_unique_transition_selectors(&self) -> Result<(), String> {
        let mut phase_selectors = BTreeSet::new();
        for rule in &self.phase_transitions {
            if !phase_selectors.insert((rule.from, rule.event.as_str())) {
                return Err(format!(
                    "duplicate phase transition selector ({}, {})",
                    rule.from, rule.event
                ));
            }
        }

        let mut condition_selectors = BTreeSet::new();
        for rule in &self.condition_transitions {
            if !condition_selectors.insert((rule.from, rule.event.as_str())) {
                return Err(format!(
                    "duplicate condition transition selector ({}, {})",
                    rule.from, rule.event
                ));
            }
        }

        let mut operation_selectors = BTreeSet::new();
        for rule in &self.operation_transitions {
            if !operation_selectors.insert((rule.from, rule.event.as_str())) {
                return Err(format!(
                    "duplicate operation transition selector ({}, {})",
                    rule.from, rule.event
                ));
            }
        }

        let mut workspace_dirty_selectors = BTreeSet::new();
        for source in &self.workspace_dirty_sources {
            if !workspace_dirty_selectors
                .insert((*source, self.workspace_dirty_transition.event.as_str()))
            {
                return Err(format!(
                    "duplicate workspace transition selector ({}, {})",
                    source, self.workspace_dirty_transition.event
                ));
            }
        }

        Ok(())
    }
}

static SPECIFICATION: OnceLock<Result<WorkflowSpecification, String>> = OnceLock::new();

fn workflow_specification() -> Result<&'static WorkflowSpecification, WorkflowError> {
    SPECIFICATION
        .get_or_init(WorkflowSpecification::parse)
        .as_ref()
        .map_err(|message| WorkflowError::InvalidSpecification(message.clone()))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PhaseTransitionRule {
    from: Phase,
    event: String,
    to: Phase,
    guard: Option<String>,
    #[serde(default)]
    effects: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct WorkspaceDirtyRule {
    event: String,
    to: Phase,
    #[serde(default)]
    effects: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ConditionTransitionRule {
    from: Condition,
    event: String,
    to: Condition,
    guard: Option<String>,
    #[serde(default)]
    effects: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct OperationTransitionRule {
    from: OperationState,
    event: String,
    to: OperationState,
    guard: Option<String>,
    #[serde(default)]
    effects: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
enum AllowedFrom {
    AnyNonterminalPhase,
    AnyNonterminalPhaseAfterResolution,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct GlobalRule {
    allowed_from: AllowedFrom,
    effect: Option<String>,
    guard: Option<String>,
    to: Option<Phase>,
}

enum SelectedTransition<'a> {
    Phase(&'a PhaseTransitionRule),
    WorkspaceDirty(&'a WorkspaceDirtyRule),
    Condition(&'a ConditionTransitionRule),
    Operation(&'a OperationTransitionRule),
    Global(&'a GlobalRule),
}

impl SelectedTransition<'_> {
    fn is_primary_phase(&self) -> bool {
        matches!(self, Self::Phase(_))
    }

    fn enters_running_operation(&self) -> bool {
        matches!(self, Self::Operation(rule) if rule.to == OperationState::Running)
    }

    fn is_observed_workspace_mutation(&self) -> bool {
        matches!(self, Self::WorkspaceDirty(_))
    }

    fn guard(&self) -> Option<&str> {
        match self {
            Self::Phase(rule) => rule.guard.as_deref(),
            Self::WorkspaceDirty(_) => None,
            Self::Condition(rule) => rule.guard.as_deref(),
            Self::Operation(rule) => rule.guard.as_deref(),
            Self::Global(rule) => rule.guard.as_deref(),
        }
    }

    fn effects(&self) -> Result<Vec<Effect>, WorkflowError> {
        let names: Vec<&str> = match self {
            Self::Phase(rule) => rule.effects.iter().map(String::as_str).collect(),
            Self::WorkspaceDirty(rule) => rule.effects.iter().map(String::as_str).collect(),
            Self::Condition(rule) => rule.effects.iter().map(String::as_str).collect(),
            Self::Operation(rule) => rule.effects.iter().map(String::as_str).collect(),
            Self::Global(rule) => rule.effect.iter().map(String::as_str).collect(),
        };
        names
            .into_iter()
            .map(|name| {
                Effect::new(name)
                    .map_err(|error| WorkflowError::InvalidSpecification(error.to_string()))
            })
            .collect()
    }

    fn apply_axis(&self, state: &mut WorkflowState) {
        match self {
            Self::Phase(rule) => state.phase = rule.to,
            Self::WorkspaceDirty(rule) => state.phase = rule.to,
            Self::Condition(rule) => state.condition = rule.to,
            Self::Operation(rule) => state.operation = rule.to,
            Self::Global(rule) => {
                if let Some(phase) = rule.to {
                    state.phase = phase;
                }
            }
        }
    }

    fn validate_preconditions(&self, state: &WorkflowState) -> Result<(), WorkflowError> {
        let Self::Global(rule) = self else {
            return Ok(());
        };

        if matches!(
            rule.allowed_from,
            AllowedFrom::AnyNonterminalPhaseAfterResolution
        ) && state.operation != OperationState::None
        {
            return Err(WorkflowError::OperationNotResolved {
                operation: state.operation,
            });
        }
        if rule.to == Some(Phase::Failed)
            && matches!(
                state.operation,
                OperationState::Running | OperationState::Indeterminate
            )
        {
            return Err(WorkflowError::OperationNotResolved {
                operation: state.operation,
            });
        }
        Ok(())
    }
}

fn select_transition<'a>(
    specification: &'a WorkflowSpecification,
    state: &WorkflowState,
    event: &WorkflowEvent,
) -> Option<SelectedTransition<'a>> {
    if let Some(rule) = specification
        .phase_transitions
        .iter()
        .find(|rule| rule.from == state.phase && rule.event == event.as_str())
    {
        return Some(SelectedTransition::Phase(rule));
    }

    if specification.workspace_dirty_sources.contains(&state.phase)
        && specification.workspace_dirty_transition.event == event.as_str()
    {
        return Some(SelectedTransition::WorkspaceDirty(
            &specification.workspace_dirty_transition,
        ));
    }

    if let Some(rule) = specification
        .condition_transitions
        .iter()
        .find(|rule| rule.from == state.condition && rule.event == event.as_str())
    {
        return Some(SelectedTransition::Condition(rule));
    }

    if let Some(rule) = specification
        .operation_transitions
        .iter()
        .find(|rule| rule.from == state.operation && rule.event == event.as_str())
    {
        return Some(SelectedTransition::Operation(rule));
    }

    specification
        .global_events
        .get(event.as_str())
        .map(SelectedTransition::Global)
}

#[cfg(test)]
mod specification_tests {
    use serde_json::{json, Value};

    use super::*;

    fn normative_value() -> Value {
        serde_json::from_str(WORKFLOW_JSON).expect("normative workflow JSON")
    }

    fn parse_for_test(value: Value) -> Result<WorkflowSpecification, String> {
        let specification: WorkflowSpecification =
            serde_json::from_value(value).map_err(|error| error.to_string())?;
        specification.validate()?;
        Ok(specification)
    }

    #[test]
    fn specification_rejects_wrong_missing_and_unknown_state_shape_fields() {
        let mut wrong = normative_value();
        wrong["stateShape"]["phase"] = json!("WrongPhaseType");

        let mut missing = normative_value();
        missing["stateShape"]
            .as_object_mut()
            .unwrap()
            .remove("fencingEpoch");

        let mut unknown = normative_value();
        unknown["stateShape"]["invented"] = json!("u64");

        for invalid in [wrong, missing, unknown] {
            assert!(parse_for_test(invalid).is_err());
        }
    }

    #[test]
    fn specification_rejects_unknown_fields_in_nested_rules() {
        for group in [
            "phaseTransitions",
            "conditionTransitions",
            "operationTransitions",
        ] {
            let mut invalid = normative_value();
            invalid[group][0]["invented"] = json!(true);
            assert!(parse_for_test(invalid).is_err(), "{group}");
        }

        let mut workspace_dirty = normative_value();
        workspace_dirty["workspaceDirtyTransition"]["invented"] = json!(true);
        assert!(parse_for_test(workspace_dirty).is_err());

        let mut global = normative_value();
        global["globalEvents"]["task.failed"]["invented"] = json!(true);
        assert!(parse_for_test(global).is_err());
    }

    #[test]
    fn specification_rejects_duplicate_transition_selectors() {
        for group in [
            "phaseTransitions",
            "conditionTransitions",
            "operationTransitions",
        ] {
            let mut invalid = normative_value();
            let duplicate = invalid[group][0].clone();
            invalid[group].as_array_mut().unwrap().push(duplicate);
            assert!(parse_for_test(invalid).is_err(), "{group}");
        }

        let mut workspace_dirty = normative_value();
        let duplicate_source = workspace_dirty["workspaceDirtySources"][0].clone();
        workspace_dirty["workspaceDirtySources"]
            .as_array_mut()
            .unwrap()
            .push(duplicate_source);
        assert!(parse_for_test(workspace_dirty).is_err());
    }

    #[test]
    fn specification_pins_the_observed_workspace_mutation_rule() {
        let mut wrong_event = normative_value();
        wrong_event["workspaceDirtyTransition"]["event"] = json!("workspace.changed");

        let mut wrong_target = normative_value();
        wrong_target["workspaceDirtyTransition"]["to"] = json!("Repair");

        for invalid in [wrong_event, wrong_target] {
            assert!(parse_for_test(invalid).is_err());
        }
    }
}
