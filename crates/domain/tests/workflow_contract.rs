use std::collections::BTreeSet;
use std::str::FromStr;

use local_agent_terminal_domain::{
    reduce, reduce_condition, Condition, FencingToken, GuardEvaluations, GuardName, OperationState,
    Phase, TaskOutcomeMode, TransitionRequest, WorkflowEvent, WorkflowProfile, WorkflowState,
    WorkflowStateSnapshot,
};
use serde_json::Value;

const WORKFLOW_JSON: &str =
    include_str!("../../../docs/multi-agent-terminal-design/schemas/workflow-transitions.v3.json");

fn specification() -> Value {
    serde_json::from_str(WORKFLOW_JSON).expect("normative workflow JSON must parse")
}

fn event(name: &str) -> WorkflowEvent {
    WorkflowEvent::new(name).expect("declared event is non-empty")
}

fn string_set(values: &Value) -> BTreeSet<String> {
    values
        .as_array()
        .expect("kind array")
        .iter()
        .map(|value| value.as_str().expect("kind").to_owned())
        .collect()
}

fn state(
    phase: Phase,
    condition: Condition,
    operation: OperationState,
    workflow_profile: WorkflowProfile,
    outcome_mode: TaskOutcomeMode,
) -> WorkflowState {
    WorkflowState::rehydrate(WorkflowStateSnapshot {
        phase,
        condition,
        operation,
        workflow_profile,
        outcome_mode,
        stream_version: 7,
        profile_revision: 2,
        workspace_version: 3,
        fencing_epoch: 4,
        last_transition_event_id: Some("transition-7".to_owned()),
        last_profile_revision_id: Some("profile-revision-2".to_owned()),
    })
    .expect("valid workflow state")
}

fn active_state(phase: Phase, profile: WorkflowProfile, outcome: TaskOutcomeMode) -> WorkflowState {
    state(
        phase,
        Condition::Active,
        OperationState::None,
        profile,
        outcome,
    )
}

fn command_request(rule: &Value) -> TransitionRequest {
    TransitionRequest {
        rule_id: rule["ruleId"].as_str().expect("rule ID").to_owned(),
        event: event(rule["event"].as_str().expect("event")),
        guard_evidence_kinds: string_set(&rule["requiredEvidenceKinds"]),
        effect_kinds: string_set(&rule["requiredEffectKinds"]),
    }
}

fn rule<'a>(specification: &'a Value, rule_id: &str) -> &'a Value {
    specification["phaseTransitions"]
        .as_array()
        .expect("phase rules")
        .iter()
        .chain(
            specification["globalPhaseTransitions"]
                .as_array()
                .expect("global rules"),
        )
        .chain(std::iter::once(&specification["workspaceDirtyTransition"]))
        .find(|candidate| candidate["ruleId"].as_str() == Some(rule_id))
        .unwrap_or_else(|| panic!("missing {rule_id}"))
}

fn effect_names(transition: &local_agent_terminal_domain::Transition) -> Vec<&str> {
    transition
        .effects()
        .iter()
        .map(|effect| effect.as_str())
        .collect()
}

fn effect_names_from(rule: &Value) -> Vec<&str> {
    rule["effects"]
        .as_array()
        .expect("effects")
        .iter()
        .map(|effect| effect.as_str().expect("effect"))
        .collect()
}

fn guard_evaluations(guard: &str, satisfied: bool) -> GuardEvaluations {
    let mut evaluations = GuardEvaluations::new();
    evaluations.insert(GuardName::new(guard).expect("declared guard"), satisfied);
    evaluations
}

#[test]
fn v3_state_retains_profile_outcome_and_authority_versions() {
    let state = WorkflowState::rehydrate(WorkflowStateSnapshot {
        phase: Phase::ContextBuild,
        condition: Condition::Active,
        operation: OperationState::None,
        workflow_profile: WorkflowProfile::Quick,
        outcome_mode: TaskOutcomeMode::WorkspaceChange,
        stream_version: 7,
        profile_revision: 2,
        workspace_version: 3,
        fencing_epoch: 4,
        last_transition_event_id: Some("transition-7".to_owned()),
        last_profile_revision_id: Some("profile-revision-2".to_owned()),
    })
    .unwrap();

    assert_eq!(state.workflow_profile(), WorkflowProfile::Quick);
    assert_eq!(state.outcome_mode(), TaskOutcomeMode::WorkspaceChange);
    assert_eq!(state.stream_version(), 7);
    assert_eq!(state.profile_revision(), 2);
    assert_eq!(state.workspace_version().get(), 3);
    assert_eq!(state.fencing_token(), FencingToken::new(4).unwrap());
    assert_eq!(state.last_transition_event_id(), Some("transition-7"));
    assert_eq!(state.last_profile_revision_id(), Some("profile-revision-2"));
}

#[test]
fn v3_enums_and_authoritative_rule_counts_match_the_schema() {
    let specification = specification();

    assert_eq!(
        specification["workflowProfiles"].as_array().unwrap().len(),
        4
    );
    assert_eq!(
        specification["taskOutcomeModes"].as_array().unwrap().len(),
        3
    );
    assert_eq!(
        specification["phaseTransitions"].as_array().unwrap().len(),
        30
    );
    assert_eq!(
        specification["globalPhaseTransitions"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
    assert!(specification["workspaceDirtyTransition"]["ruleId"]
        .as_str()
        .unwrap()
        .starts_with("WF-W"));
    assert_eq!(
        specification["conditionTransitions"]
            .as_array()
            .unwrap()
            .len(),
        6
    );

    for name in specification["phases"].as_array().unwrap() {
        let name = name.as_str().unwrap();
        assert_eq!(Phase::from_str(name).unwrap().as_str(), name);
    }
    for name in specification["workflowProfiles"].as_array().unwrap() {
        let name = name.as_str().unwrap();
        assert_eq!(WorkflowProfile::from_str(name).unwrap().as_str(), name);
    }
    for name in specification["taskOutcomeModes"].as_array().unwrap() {
        let name = name.as_str().unwrap();
        assert_eq!(TaskOutcomeMode::from_str(name).unwrap().as_str(), name);
    }
    for condition in specification["conditionTransitions"].as_array().unwrap() {
        assert!(condition.get("ruleId").is_none());
        assert!(condition.get("effects").is_none());
        assert!(condition.get("requiredEffectKinds").is_none());
    }
}

#[test]
fn every_id_bearing_rule_accepts_its_declared_source_profile_outcome_and_exact_sets() {
    let specification = specification();
    let rules = specification["phaseTransitions"]
        .as_array()
        .unwrap()
        .iter()
        .chain(specification["globalPhaseTransitions"].as_array().unwrap())
        .chain(std::iter::once(&specification["workspaceDirtyTransition"]));

    for rule in rules {
        let source_phase = rule
            .get("from")
            .and_then(Value::as_str)
            .or_else(|| rule["fromPhases"][0].as_str())
            .expect("source phase");
        let profile = WorkflowProfile::from_str(
            rule["allowedProfiles"][0]
                .as_str()
                .expect("allowed profile"),
        )
        .unwrap();
        let outcome = TaskOutcomeMode::from_str(
            rule["allowedOutcomes"][0]
                .as_str()
                .expect("allowed outcome"),
        )
        .unwrap();
        let source = active_state(Phase::from_str(source_phase).unwrap(), profile, outcome);
        let transition = reduce(&source, &command_request(rule)).unwrap_or_else(|error| {
            panic!(
                "{} should reduce: {error:?}",
                rule["ruleId"].as_str().unwrap()
            )
        });

        assert_eq!(
            transition.state().phase(),
            Phase::from_str(rule["to"].as_str().unwrap()).unwrap()
        );
        assert_eq!(transition.state().stream_version(), 8);
        assert_eq!(
            transition.state().workflow_profile(),
            source.workflow_profile()
        );
        assert_eq!(transition.state().outcome_mode(), source.outcome_mode());
        assert_eq!(transition.rule_id(), rule["ruleId"].as_str());
        assert_eq!(effect_names(&transition), effect_names_from(rule));
    }
}

#[test]
fn quick_context_path_uses_wf_p003_and_not_standard_route() {
    let specification = specification();
    let source = active_state(
        Phase::ContextBuild,
        WorkflowProfile::Quick,
        TaskOutcomeMode::WorkspaceChange,
    );

    let quick = reduce(&source, &command_request(rule(&specification, "WF-P003"))).unwrap();
    assert_eq!(quick.state().phase(), Phase::PrePlanVerification);
    assert!(reduce(&source, &command_request(rule(&specification, "WF-P002"))).is_err());
}

#[test]
fn severe_objection_routes_are_profile_specific() {
    let specification = specification();
    let quick = active_state(
        Phase::FinalObjection,
        WorkflowProfile::Quick,
        TaskOutcomeMode::WorkspaceChange,
    );
    let standard = active_state(
        Phase::FinalObjection,
        WorkflowProfile::Standard,
        TaskOutcomeMode::WorkspaceChange,
    );

    assert_eq!(
        reduce(&quick, &command_request(rule(&specification, "WF-P009")))
            .unwrap()
            .state()
            .phase(),
        Phase::PrePlanVerification
    );
    assert!(reduce(&quick, &command_request(rule(&specification, "WF-P008"))).is_err());
    assert_eq!(
        reduce(&standard, &command_request(rule(&specification, "WF-P008")))
            .unwrap()
            .state()
            .phase(),
        Phase::CrossReview
    );
    assert!(reduce(&standard, &command_request(rule(&specification, "WF-P009"))).is_err());
}

#[test]
fn plan_approval_requires_wf_p015_exact_effect_set_and_preserves_profile_revision() {
    let specification = specification();
    let source = active_state(
        Phase::AwaitingPlanApproval,
        WorkflowProfile::Standard,
        TaskOutcomeMode::WorkspaceChange,
    );
    let rule = rule(&specification, "WF-P015");

    let transition = reduce(&source, &command_request(rule)).unwrap();
    assert_eq!(transition.state().phase(), Phase::Implementation);
    assert_eq!(transition.state().profile_revision(), 2);
    assert_eq!(
        effect_names(&transition),
        vec!["persist_approved_plan_version", "allocate_executor_lease"]
    );

    let mut missing_effect = command_request(rule);
    missing_effect.effect_kinds.clear();
    assert!(reduce(&source, &missing_effect).is_err());

    let mut extra_effect = command_request(rule);
    extra_effect
        .effect_kinds
        .insert("invented_effect".to_owned());
    assert!(reduce(&source, &extra_effect).is_err());
}

#[test]
fn global_terminal_paths_accept_every_declared_source_then_become_irreversible() {
    let specification = specification();

    for rule in specification["globalPhaseTransitions"].as_array().unwrap() {
        for source in rule["fromPhases"].as_array().unwrap() {
            let source = state(
                Phase::from_str(source.as_str().unwrap()).unwrap(),
                Condition::Paused,
                OperationState::Running,
                WorkflowProfile::Standard,
                TaskOutcomeMode::WorkspaceChange,
            );
            let terminal = reduce(&source, &command_request(rule)).unwrap();
            assert!(terminal.state().phase().is_terminal());
            assert_eq!(terminal.state().condition(), Condition::Active);
            assert_eq!(terminal.state().operation(), OperationState::None);
            assert!(reduce(terminal.state(), &command_request(rule)).is_err());
        }
    }
}

#[test]
fn condition_rules_are_idless_and_change_only_condition_and_stream_version() {
    let specification = specification();

    for rule in specification["conditionTransitions"].as_array().unwrap() {
        let source = state(
            Phase::Verification,
            Condition::from_str(rule["from"].as_str().unwrap()).unwrap(),
            OperationState::Running,
            WorkflowProfile::HighAssurance,
            TaskOutcomeMode::LocalCommit,
        );
        let transition = reduce_condition(
            &source,
            &event(rule["event"].as_str().unwrap()),
            &guard_evaluations(rule["guard"].as_str().unwrap(), true),
        )
        .unwrap_or_else(|error| panic!("condition rule should reduce: {error:?}"));

        assert_eq!(
            transition.state().condition(),
            Condition::from_str(rule["to"].as_str().unwrap()).unwrap()
        );
        assert_eq!(transition.state().phase(), source.phase());
        assert_eq!(transition.state().operation(), source.operation());
        assert_eq!(
            transition.state().workflow_profile(),
            source.workflow_profile()
        );
        assert_eq!(transition.state().outcome_mode(), source.outcome_mode());
        assert_eq!(
            transition.state().profile_revision(),
            source.profile_revision()
        );
        assert_eq!(
            transition.state().workspace_version(),
            source.workspace_version()
        );
        assert_eq!(transition.state().fencing_token(), source.fencing_token());
        assert_eq!(
            transition.state().stream_version(),
            source.stream_version() + 1
        );
        assert_eq!(transition.rule_id(), None);
        assert!(transition.effects().is_empty());
    }
}

#[test]
fn condition_rules_require_their_declared_guard() {
    let specification = specification();
    let rule = &specification["conditionTransitions"][0];
    let source = active_state(
        Phase::ContextBuild,
        WorkflowProfile::Standard,
        TaskOutcomeMode::WorkspaceChange,
    );
    let event = event(rule["event"].as_str().unwrap());

    assert!(reduce_condition(&source, &event, &GuardEvaluations::new()).is_err());
    assert!(reduce_condition(
        &source,
        &event,
        &guard_evaluations(rule["guard"].as_str().unwrap(), false)
    )
    .is_err());
}
