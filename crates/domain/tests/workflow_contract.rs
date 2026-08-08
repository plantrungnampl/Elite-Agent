use std::collections::BTreeSet;
use std::str::FromStr;

use local_agent_terminal_domain::{
    reduce, ActorId, Condition, EventId, FencingToken, GuardEvaluations, GuardName, OperationState,
    Phase, Sequence, StreamId, TaskId, WorkflowError, WorkflowEvent, WorkflowState,
    WorkspaceVersion,
};
use serde_json::Value;

const WORKFLOW_JSON: &str =
    include_str!("../../../docs/multi-agent-terminal-design/schemas/workflow-transitions.v1.json");

fn specification() -> Value {
    serde_json::from_str(WORKFLOW_JSON).expect("normative workflow JSON must parse")
}

fn enum_names(specification: &Value, field: &str) -> Vec<String> {
    specification[field]
        .as_array()
        .expect("enum list")
        .iter()
        .map(|value| value.as_str().expect("enum name").to_owned())
        .collect()
}

fn event(name: &str) -> WorkflowEvent {
    WorkflowEvent::new(name).expect("declared event is non-empty")
}

fn guard_evaluations(values: impl IntoIterator<Item = (String, bool)>) -> GuardEvaluations {
    let mut evaluations = GuardEvaluations::new();
    for (name, satisfied) in values {
        evaluations.insert(
            GuardName::new(name).expect("declared guard is non-empty"),
            satisfied,
        );
    }
    evaluations
}

fn guard_for(rule: &Value, satisfied: bool) -> GuardEvaluations {
    rule.get("guard")
        .and_then(Value::as_str)
        .map(|name| guard_evaluations([(name.to_owned(), satisfied)]))
        .unwrap_or_default()
}

fn all_satisfied_guards(specification: &Value) -> GuardEvaluations {
    let transition_groups = [
        "phaseTransitions",
        "conditionTransitions",
        "operationTransitions",
    ];
    let mut names = BTreeSet::new();

    for group in transition_groups {
        for rule in specification[group].as_array().expect("transition list") {
            if let Some(name) = rule.get("guard").and_then(Value::as_str) {
                names.insert(name.to_owned());
            }
        }
    }
    for rule in specification["globalEvents"]
        .as_object()
        .expect("global event map")
        .values()
    {
        if let Some(name) = rule.get("guard").and_then(Value::as_str) {
            names.insert(name.to_owned());
        }
    }

    guard_evaluations(names.into_iter().map(|name| (name, true)))
}

fn state(phase: Phase, condition: Condition, operation: OperationState) -> WorkflowState {
    state_with_versions(phase, condition, operation, 7, 3, 2)
}

fn state_with_versions(
    phase: Phase,
    condition: Condition,
    operation: OperationState,
    sequence: i64,
    workspace_version: i64,
    fencing_token: i64,
) -> WorkflowState {
    WorkflowState::new(
        phase,
        condition,
        operation,
        Sequence::try_from(sequence).expect("nonnegative sequence"),
        WorkspaceVersion::try_from(workspace_version).expect("nonnegative workspace version"),
        FencingToken::try_from(fencing_token).expect("positive fencing token"),
    )
    .expect("valid workflow state")
}

fn effect_names(outcome: &local_agent_terminal_domain::Transition) -> Vec<&str> {
    outcome
        .effects()
        .iter()
        .map(|effect| effect.as_str())
        .collect()
}

fn expected_effects(rule: &Value) -> Vec<&str> {
    rule.get("effects")
        .and_then(Value::as_array)
        .map(|effects| {
            effects
                .iter()
                .map(|effect| effect.as_str().expect("effect name"))
                .collect()
        })
        .unwrap_or_default()
}

fn declared_event_names(specification: &Value) -> Vec<String> {
    let mut names = BTreeSet::new();
    for group in [
        "phaseTransitions",
        "conditionTransitions",
        "operationTransitions",
    ] {
        for rule in specification[group].as_array().expect("transition list") {
            names.insert(rule["event"].as_str().expect("transition event").to_owned());
        }
    }
    names.insert(
        specification["workspaceDirtyTransition"]["event"]
            .as_str()
            .expect("workspace dirty event")
            .to_owned(),
    );
    names.extend(
        specification["globalEvents"]
            .as_object()
            .expect("global event map")
            .keys()
            .cloned(),
    );
    names.into_iter().collect()
}

fn generated_valid_states() -> Vec<WorkflowState> {
    let mut states = Vec::new();
    for phase in Phase::ALL {
        if phase.is_terminal() {
            states.push(state(*phase, Condition::Active, OperationState::None));
            continue;
        }
        for condition in Condition::ALL {
            for operation in OperationState::ALL {
                states.push(state(*phase, *condition, *operation));
            }
        }
    }
    states
}

fn is_declared_for(specification: &Value, source: &WorkflowState, event_name: &str) -> bool {
    let phase_declared = specification["phaseTransitions"]
        .as_array()
        .expect("phase transitions")
        .iter()
        .any(|rule| {
            rule["from"].as_str() == Some(source.phase().as_str())
                && rule["event"].as_str() == Some(event_name)
        });
    let condition_declared = specification["conditionTransitions"]
        .as_array()
        .expect("condition transitions")
        .iter()
        .any(|rule| {
            rule["from"].as_str() == Some(source.condition().as_str())
                && rule["event"].as_str() == Some(event_name)
        });
    let operation_declared = specification["operationTransitions"]
        .as_array()
        .expect("operation transitions")
        .iter()
        .any(|rule| {
            rule["from"].as_str() == Some(source.operation().as_str())
                && rule["event"].as_str() == Some(event_name)
        });
    let workspace_dirty_declared = specification["workspaceDirtySources"]
        .as_array()
        .expect("workspace dirty sources")
        .iter()
        .any(|phase| phase.as_str() == Some(source.phase().as_str()))
        && specification["workspaceDirtyTransition"]["event"].as_str() == Some(event_name);
    let global_declared = !source.phase().is_terminal()
        && specification["globalEvents"]
            .as_object()
            .expect("global events")
            .contains_key(event_name);

    phase_declared
        || condition_declared
        || operation_declared
        || workspace_dirty_declared
        || global_declared
}

#[test]
fn parses_every_normative_phase_condition_and_operation_state() {
    let specification = specification();

    let phases = enum_names(&specification, "phases");
    assert_eq!(phases.len(), Phase::ALL.len());
    for name in phases {
        let parsed = Phase::from_str(&name).expect("declared phase must parse");
        assert_eq!(parsed.as_str(), name);
    }

    let conditions = enum_names(&specification, "conditions");
    assert_eq!(conditions.len(), Condition::ALL.len());
    for name in conditions {
        let parsed = Condition::from_str(&name).expect("declared condition must parse");
        assert_eq!(parsed.as_str(), name);
    }

    let operations = enum_names(&specification, "operationStates");
    assert_eq!(operations.len(), OperationState::ALL.len());
    for name in operations {
        let parsed = OperationState::from_str(&name).expect("declared operation state must parse");
        assert_eq!(parsed.as_str(), name);
    }

    assert!(Phase::from_str("Invented").is_err());
    assert!(Condition::from_str("Invented").is_err());
    assert!(OperationState::from_str("Invented").is_err());
}

#[test]
fn accepts_every_declared_phase_transition_and_exact_effects() {
    let specification = specification();

    for rule in specification["phaseTransitions"]
        .as_array()
        .expect("phase transitions")
    {
        let from = Phase::from_str(rule["from"].as_str().expect("from phase")).unwrap();
        let to = Phase::from_str(rule["to"].as_str().expect("to phase")).unwrap();
        let event_name = rule["event"].as_str().expect("event");
        let source = state(from, Condition::Active, OperationState::None);

        let outcome = reduce(&source, &event(event_name), &guard_for(rule, true))
            .unwrap_or_else(|error| panic!("{from:?} --{event_name}--> {to:?}: {error:?}"));

        assert_eq!(outcome.state().phase(), to);
        assert_eq!(
            outcome.state().sequence().get(),
            source.sequence().get() + 1
        );
        assert_eq!(effect_names(&outcome), expected_effects(rule));
    }
}

#[test]
fn accepts_every_declared_condition_transition_without_changing_phase() {
    let specification = specification();

    for rule in specification["conditionTransitions"]
        .as_array()
        .expect("condition transitions")
    {
        let from = Condition::from_str(rule["from"].as_str().expect("from condition")).unwrap();
        let to = Condition::from_str(rule["to"].as_str().expect("to condition")).unwrap();
        let source = state(Phase::ContextBuild, from, OperationState::None);

        let outcome = reduce(
            &source,
            &event(rule["event"].as_str().expect("event")),
            &guard_for(rule, true),
        )
        .unwrap();

        assert_eq!(outcome.state().phase(), source.phase());
        assert_eq!(outcome.state().condition(), to);
        assert_eq!(outcome.state().operation(), source.operation());
    }
}

#[test]
fn accepts_every_declared_operation_transition_without_changing_phase() {
    let specification = specification();

    for rule in specification["operationTransitions"]
        .as_array()
        .expect("operation transitions")
    {
        let from =
            OperationState::from_str(rule["from"].as_str().expect("from operation")).unwrap();
        let to = OperationState::from_str(rule["to"].as_str().expect("to operation")).unwrap();
        let source = state(Phase::ContextBuild, Condition::Active, from);

        let outcome = reduce(
            &source,
            &event(rule["event"].as_str().expect("event")),
            &guard_for(rule, true),
        )
        .unwrap();

        assert_eq!(outcome.state().phase(), source.phase());
        assert_eq!(outcome.state().condition(), source.condition());
        assert_eq!(outcome.state().operation(), to);
    }
}

#[test]
fn accepts_workspace_dirty_and_global_transitions_from_their_declared_sources() {
    let specification = specification();
    let dirty_rule = &specification["workspaceDirtyTransition"];

    for source_name in enum_names(&specification, "workspaceDirtySources") {
        let source_phase = Phase::from_str(&source_name).unwrap();
        let source = state(source_phase, Condition::Active, OperationState::None);
        let outcome = reduce(
            &source,
            &event(dirty_rule["event"].as_str().unwrap()),
            &GuardEvaluations::new(),
        )
        .unwrap();

        assert_eq!(outcome.state().phase(), Phase::WorkspaceDirty);
        assert_eq!(effect_names(&outcome), expected_effects(dirty_rule));
    }

    for (event_name, rule) in specification["globalEvents"].as_object().unwrap() {
        let source = state(Phase::ContextBuild, Condition::Active, OperationState::None);
        let outcome = reduce(&source, &event(event_name), &guard_for(rule, true)).unwrap();
        let expected_phase = rule
            .get("to")
            .and_then(Value::as_str)
            .map(|name| Phase::from_str(name).unwrap())
            .unwrap_or(source.phase());

        assert_eq!(outcome.state().phase(), expected_phase);
        let expected_global_effect = rule
            .get("effect")
            .and_then(Value::as_str)
            .into_iter()
            .collect::<Vec<_>>();
        assert_eq!(effect_names(&outcome), expected_global_effect);
    }
}

#[test]
fn rejects_each_named_guard_when_false_or_missing() {
    let specification = specification();

    for group in [
        "phaseTransitions",
        "conditionTransitions",
        "operationTransitions",
    ] {
        for rule in specification[group].as_array().unwrap() {
            let Some(guard_name) = rule.get("guard").and_then(Value::as_str) else {
                continue;
            };
            let source = match group {
                "phaseTransitions" => state(
                    Phase::from_str(rule["from"].as_str().unwrap()).unwrap(),
                    Condition::Active,
                    OperationState::None,
                ),
                "conditionTransitions" => state(
                    Phase::ContextBuild,
                    Condition::from_str(rule["from"].as_str().unwrap()).unwrap(),
                    OperationState::None,
                ),
                "operationTransitions" => state(
                    Phase::ContextBuild,
                    Condition::Active,
                    OperationState::from_str(rule["from"].as_str().unwrap()).unwrap(),
                ),
                _ => unreachable!(),
            };
            let transition_event = event(rule["event"].as_str().unwrap());

            let false_error =
                reduce(&source, &transition_event, &guard_for(rule, false)).unwrap_err();
            assert!(matches!(
                false_error,
                WorkflowError::GuardRejected { ref guard } if guard.as_str() == guard_name
            ));

            let missing_error =
                reduce(&source, &transition_event, &GuardEvaluations::new()).unwrap_err();
            assert!(matches!(
                missing_error,
                WorkflowError::GuardNotEvaluated { ref guard } if guard.as_str() == guard_name
            ));
        }
    }

    for (event_name, rule) in specification["globalEvents"].as_object().unwrap() {
        let Some(guard_name) = rule.get("guard").and_then(Value::as_str) else {
            continue;
        };
        let source = state(Phase::ContextBuild, Condition::Active, OperationState::None);
        let error = reduce(&source, &event(event_name), &guard_for(rule, false)).unwrap_err();
        assert!(matches!(
            error,
            WorkflowError::GuardRejected { ref guard } if guard.as_str() == guard_name
        ));
    }
}

#[test]
fn rejects_undeclared_transitions_and_paused_phase_advancement() {
    let intake = state(Phase::Intake, Condition::Active, OperationState::None);
    let before = intake;
    let error = reduce(
        &intake,
        &event("context.initial.ready"),
        &guard_evaluations([("required_context_packages_valid".to_owned(), true)]),
    )
    .unwrap_err();
    assert!(matches!(error, WorkflowError::UndeclaredTransition { .. }));
    assert_eq!(intake, before);

    let paused = state(Phase::Intake, Condition::Paused, OperationState::None);
    let error = reduce(
        &paused,
        &event("task.validated"),
        &guard_evaluations([("repository_policy_budgets_valid".to_owned(), true)]),
    )
    .unwrap_err();
    assert!(matches!(error, WorkflowError::PhaseNotDispatchable { .. }));

    let error = reduce(
        &intake,
        &event("workspace.mutated"),
        &GuardEvaluations::new(),
    )
    .unwrap_err();
    assert!(matches!(error, WorkflowError::UndeclaredTransition { .. }));
}

#[test]
fn observed_workspace_mutation_increments_version_outside_json_effects() {
    let source = state(Phase::FinalReview, Condition::Active, OperationState::None);
    let dirty_rule = &specification()["workspaceDirtyTransition"];
    assert!(
        !expected_effects(dirty_rule).contains(&"increment_workspace_version"),
        "workspace version is a cross-document trust invariant, not a declared JSON effect"
    );
    let dirty = reduce(
        &source,
        &event("workspace.mutated"),
        &GuardEvaluations::new(),
    )
    .unwrap();

    assert_eq!(dirty.state().phase(), Phase::WorkspaceDirty);
    assert_eq!(
        dirty.state().workspace_version().get(),
        source.workspace_version().get() + 1
    );
}

#[test]
fn preserves_workspace_dirty_recovery_and_fencing_semantics() {
    let source = state(Phase::FinalReview, Condition::Active, OperationState::None);
    let dirty = reduce(
        &source,
        &event("workspace.mutated"),
        &GuardEvaluations::new(),
    )
    .unwrap();

    assert_eq!(dirty.state().phase(), Phase::WorkspaceDirty);
    assert_eq!(
        dirty.state().fencing_token().get(),
        source.fencing_token().get() + 1
    );
    assert!(effect_names(&dirty).contains(&"invalidate_affected_approvals"));

    let repaired = reduce(
        dirty.state(),
        &event("workspace.repair.authorized"),
        &guard_evaluations([("mutation_evidence_preserved".to_owned(), true)]),
    )
    .unwrap();
    assert_eq!(repaired.state().phase(), Phase::Repair);
    assert_eq!(
        repaired.state().fencing_token().get(),
        dirty.state().fencing_token().get() + 1
    );

    let reconciled_source = state(
        Phase::WorkspaceDirty,
        Condition::Active,
        OperationState::None,
    );
    let reconciled = reduce(
        &reconciled_source,
        &event("workspace.reconciled"),
        &guard_evaluations([("candidate_rebuilt_and_verified".to_owned(), true)]),
    )
    .unwrap();
    assert_eq!(reconciled.state().phase(), Phase::FinalReview);
}

#[test]
fn condition_changes_inside_workspace_dirty_do_not_invent_new_mutations() {
    let dirty = state(
        Phase::WorkspaceDirty,
        Condition::Active,
        OperationState::None,
    );
    let paused = reduce(
        &dirty,
        &event("task.paused"),
        &guard_evaluations([("phase_nonterminal".to_owned(), true)]),
    )
    .unwrap();

    assert_eq!(paused.state().condition(), Condition::Paused);
    assert_eq!(
        paused.state().workspace_version(),
        dirty.workspace_version()
    );
    assert_eq!(paused.state().fencing_token(), dirty.fencing_token());
}

#[test]
fn preserves_approval_and_verification_repair_semantics() {
    let awaiting_plan = state(
        Phase::AwaitingPlanApproval,
        Condition::Active,
        OperationState::None,
    );
    let approved = reduce(
        &awaiting_plan,
        &event("plan.approved"),
        &guard_evaluations([("plan_approval_digest_valid".to_owned(), true)]),
    )
    .unwrap();
    assert_eq!(approved.state().phase(), Phase::Implementation);
    assert_eq!(
        approved.state().fencing_token().get(),
        awaiting_plan.fencing_token().get() + 1
    );

    let approval_required = reduce(
        &state(
            Phase::Implementation,
            Condition::Active,
            OperationState::None,
        ),
        &event("operation.approval.required"),
        &GuardEvaluations::new(),
    )
    .unwrap();
    assert_eq!(
        approval_required.state().operation(),
        OperationState::AwaitingApproval
    );
    let running = reduce(
        approval_required.state(),
        &event("approval.granted"),
        &guard_evaluations([("approval_digest_recomputed".to_owned(), true)]),
    )
    .unwrap();
    assert_eq!(running.state().operation(), OperationState::Running);

    let verification = state(Phase::Verification, Condition::Active, OperationState::None);
    let repair = reduce(
        &verification,
        &event("verification.failed"),
        &guard_evaluations([("repair_budget_available".to_owned(), true)]),
    )
    .unwrap();
    assert_eq!(repair.state().phase(), Phase::Repair);
    assert_eq!(
        repair.state().fencing_token().get(),
        verification.fencing_token().get() + 1
    );

    let submitted = reduce(
        repair.state(),
        &event("repair.submitted"),
        &guard_evaluations([("current_fenced_executor_and_scoped_writes".to_owned(), true)]),
    )
    .unwrap();
    assert_eq!(submitted.state().phase(), Phase::Verification);
    assert_eq!(
        submitted.state().workspace_version().get(),
        repair.state().workspace_version().get() + 1
    );
}

#[test]
fn approval_granted_requires_an_active_condition() {
    let guards = guard_evaluations([("approval_digest_recomputed".to_owned(), true)]);

    for condition in [
        Condition::Paused,
        Condition::Blocked,
        Condition::BudgetExhausted,
    ] {
        let source = state(
            Phase::Implementation,
            condition,
            OperationState::AwaitingApproval,
        );
        let before = source;

        let result = reduce(&source, &event("approval.granted"), &guards);

        assert!(
            result.is_err(),
            "approval entered Running while condition was {condition}"
        );
        assert_eq!(source, before);
    }
}

#[test]
fn terminal_states_are_normalized_and_cannot_transition() {
    assert!(WorkflowState::new(
        Phase::Completed,
        Condition::Paused,
        OperationState::None,
        Sequence::try_from(0).unwrap(),
        WorkspaceVersion::try_from(0).unwrap(),
        FencingToken::try_from(1).unwrap(),
    )
    .is_err());

    let local_commit = state(Phase::LocalCommit, Condition::Active, OperationState::None);
    let completed = reduce(
        &local_commit,
        &event("commit.verified"),
        &guard_evaluations([("commit_tree_equals_candidate_tree".to_owned(), true)]),
    )
    .unwrap();
    assert_eq!(completed.state().phase(), Phase::Completed);
    assert_eq!(completed.state().condition(), Condition::Active);
    assert_eq!(completed.state().operation(), OperationState::None);

    for event_name in declared_event_names(&specification()) {
        let error = reduce(
            completed.state(),
            &event(&event_name),
            &all_satisfied_guards(&specification()),
        )
        .unwrap_err();
        assert!(matches!(error, WorkflowError::TerminalPhase { .. }));
    }
}

#[test]
fn cancellation_and_failure_require_resolved_external_operations() {
    let running = state(
        Phase::Implementation,
        Condition::Active,
        OperationState::Running,
    );
    let requested = reduce(
        &running,
        &event("task.cancel.requested"),
        &GuardEvaluations::new(),
    )
    .unwrap();
    assert_eq!(requested.state().phase(), Phase::Implementation);
    assert_eq!(requested.state().operation(), OperationState::Cancelling);

    let error = reduce(&running, &event("task.cancelled"), &GuardEvaluations::new()).unwrap_err();
    assert!(matches!(error, WorkflowError::OperationNotResolved { .. }));

    let indeterminate = state(
        Phase::Implementation,
        Condition::Active,
        OperationState::Indeterminate,
    );
    let error = reduce(
        &indeterminate,
        &event("task.failed"),
        &guard_evaluations([(
            "no_running_or_indeterminate_operation_and_failure_evidence_persisted".to_owned(),
            true,
        )]),
    )
    .unwrap_err();
    assert!(matches!(error, WorkflowError::OperationNotResolved { .. }));

    let resolved = state(
        Phase::Implementation,
        Condition::Paused,
        OperationState::None,
    );
    let cancelled = reduce(
        &resolved,
        &event("task.cancelled"),
        &GuardEvaluations::new(),
    )
    .unwrap();
    assert_eq!(cancelled.state().phase(), Phase::Cancelled);
    assert_eq!(cancelled.state().condition(), Condition::Active);
    assert_eq!(cancelled.state().operation(), OperationState::None);
}

#[test]
fn task_failed_excludes_exactly_running_and_indeterminate_operations() {
    let guards = guard_evaluations([(
        "no_running_or_indeterminate_operation_and_failure_evidence_persisted".to_owned(),
        true,
    )]);

    for operation in [
        OperationState::None,
        OperationState::AwaitingApproval,
        OperationState::Cancelling,
    ] {
        let source = state(Phase::Implementation, Condition::Paused, operation);
        let failed = reduce(&source, &event("task.failed"), &guards)
            .unwrap_or_else(|error| panic!("{operation} should be accepted: {error}"));

        assert_eq!(failed.state().phase(), Phase::Failed);
        assert_eq!(failed.state().condition(), Condition::Active);
        assert_eq!(failed.state().operation(), OperationState::None);
    }

    for operation in [OperationState::Running, OperationState::Indeterminate] {
        let source = state(Phase::Implementation, Condition::Active, operation);
        assert!(matches!(
            reduce(&source, &event("task.failed"), &guards),
            Err(WorkflowError::OperationNotResolved {
                operation: rejected
            }) if rejected == operation
        ));
    }
}

#[test]
fn task_cancelled_still_requires_a_fully_resolved_operation() {
    for operation in OperationState::ALL
        .iter()
        .copied()
        .filter(|operation| *operation != OperationState::None)
    {
        let source = state(Phase::Implementation, Condition::Active, operation);
        assert!(matches!(
            reduce(
                &source,
                &event("task.cancelled"),
                &GuardEvaluations::new()
            ),
            Err(WorkflowError::OperationNotResolved {
                operation: rejected
            }) if rejected == operation
        ));
    }
}

#[test]
fn typed_ids_and_numeric_values_reject_invalid_boundaries() {
    assert_eq!(TaskId::new("task-1").unwrap().as_str(), "task-1");
    assert_eq!(StreamId::new("stream-1").unwrap().as_str(), "stream-1");
    assert_eq!(EventId::new("event-1").unwrap().as_str(), "event-1");
    assert_eq!(ActorId::new("actor-1").unwrap().as_str(), "actor-1");

    assert!(TaskId::new("").is_err());
    assert!(StreamId::new("  ").is_err());
    assert!(EventId::new("\n").is_err());
    assert!(ActorId::new("\t").is_err());

    assert_eq!(Sequence::try_from(0).unwrap().get(), 0);
    assert!(Sequence::try_from(-1).is_err());
    assert_eq!(WorkspaceVersion::try_from(0).unwrap().get(), 0);
    assert!(WorkspaceVersion::try_from(-1).is_err());
    assert_eq!(FencingToken::try_from(1).unwrap().get(), 1);
    assert!(FencingToken::try_from(0).is_err());
    assert!(FencingToken::try_from(-1).is_err());
}

#[test]
fn numeric_values_cover_the_normative_u64_range_and_reject_overflow() {
    assert_eq!(Sequence::new(u64::MAX).get(), u64::MAX);
    assert_eq!(WorkspaceVersion::new(u64::MAX).get(), u64::MAX);
    assert_eq!(FencingToken::new(u64::MAX).unwrap().get(), u64::MAX);
    assert!(FencingToken::new(0).is_err());

    let source = WorkflowState::new(
        Phase::Intake,
        Condition::Active,
        OperationState::None,
        Sequence::new(u64::MAX),
        WorkspaceVersion::new(0),
        FencingToken::new(1).unwrap(),
    )
    .unwrap();
    let before = source;
    let error = reduce(
        &source,
        &event("task.validated"),
        &guard_evaluations([("repository_policy_budgets_valid".to_owned(), true)]),
    )
    .unwrap_err();

    assert!(matches!(
        error,
        WorkflowError::VersionOverflow { field: "sequence" }
    ));
    assert_eq!(source, before);
}

#[test]
fn generated_rejections_leave_state_unchanged() {
    for source in generated_valid_states() {
        let before = source;
        let result = reduce(
            &source,
            &event("undeclared.property.event"),
            &GuardEvaluations::new(),
        );

        assert!(result.is_err());
        assert_eq!(source, before);
    }
}

#[test]
fn generated_accepted_transitions_are_normative_and_versions_never_decrease() {
    let specification = specification();
    let guards = all_satisfied_guards(&specification);
    let events = declared_event_names(&specification);

    for source in generated_valid_states() {
        for event_name in &events {
            if let Ok(outcome) = reduce(&source, &event(event_name), &guards) {
                assert!(
                    is_declared_for(&specification, &source, event_name),
                    "accepted undeclared transition from {:?} on {event_name}",
                    source
                );
                assert_eq!(
                    outcome.state().sequence().get(),
                    source.sequence().get() + 1
                );
                assert!(
                    outcome.state().workspace_version().get() >= source.workspace_version().get()
                );
                assert!(outcome.state().fencing_token().get() >= source.fencing_token().get());
            }
        }
    }
}

#[test]
fn generated_terminal_states_never_leave_terminality_without_a_declared_recovery() {
    let specification = specification();
    let guards = all_satisfied_guards(&specification);

    for phase in Phase::ALL
        .iter()
        .copied()
        .filter(|phase| phase.is_terminal())
    {
        let terminal = state(phase, Condition::Active, OperationState::None);
        for event_name in declared_event_names(&specification) {
            let explicitly_declared_recovery = specification["phaseTransitions"]
                .as_array()
                .unwrap()
                .iter()
                .any(|rule| {
                    rule["from"].as_str() == Some(phase.as_str())
                        && rule["event"].as_str() == Some(event_name.as_str())
                });
            let result = reduce(&terminal, &event(&event_name), &guards);

            assert!(
                result.is_err() || explicitly_declared_recovery,
                "terminal phase {phase:?} left terminality on {event_name}"
            );
        }
    }
}

#[test]
fn domain_crate_declares_only_pure_data_dependencies() {
    const MANIFEST: &str = include_str!("../Cargo.toml");
    const SOURCES: [&str; 8] = [
        include_str!("../src/agent.rs"),
        include_str!("../src/lib.rs"),
        include_str!("../src/event.rs"),
        include_str!("../src/identity.rs"),
        include_str!("../src/policy.rs"),
        include_str!("../src/tool.rs"),
        include_str!("../src/workflow.rs"),
        include_str!("../src/workspace.rs"),
    ];

    let dependency_section = MANIFEST
        .split_once("[dependencies]")
        .expect("dependency section")
        .1
        .split("\n[")
        .next()
        .expect("dependency body");
    let direct_dependencies = dependency_section
        .lines()
        .filter_map(|line| line.split_once('=').map(|(name, _)| name.trim()))
        .filter(|name| !name.is_empty())
        .collect::<BTreeSet<_>>();

    assert_eq!(
        direct_dependencies,
        BTreeSet::from(["serde", "serde_json", "serde_json_canonicalizer", "sha2"])
    );

    for source in SOURCES {
        let lowercase = source.to_ascii_lowercase();
        for forbidden in [
            "tauri",
            "tokio",
            "async_std",
            "rusqlite",
            "sqlx",
            "std::fs",
            "std::process",
            "git2",
            "windows::",
        ] {
            assert!(
                !lowercase.contains(forbidden),
                "domain source contains forbidden dependency {forbidden}"
            );
        }
    }
}
