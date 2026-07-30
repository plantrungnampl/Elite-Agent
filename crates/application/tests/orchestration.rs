use std::sync::Mutex;

use local_agent_terminal_application::{
    canonical_policy_binding_digest, policy_request_for_tool, ArtifactId, Clock,
    ImmutableToolRequest, PolicyDecision, PolicyDecisionId, PolicyDecisionStore, PolicyEvaluator,
    PortError, PreEffectOutcome, RecordedPolicyDecision, SafeErrorClassification, ToolExecutionId,
    ToolExecutionOrchestration, ToolPolicyContext, ToolRequest, ToolRequestPublisher,
};
use local_agent_terminal_domain::{
    combine_policy_rules, ActorLocality, CapabilityRef, EnvironmentProfile, FencingToken,
    MatchedPolicyRule, NetworkProfile, Phase, PlanStepId, PolicyAction, PolicyActor, PolicyEffect,
    PolicyRequest, PolicyResource, PolicyRuleId, PolicyVersion, ProcessBinding, ProcessInvocation,
    ProcessToolRequest, ProcessTrustTier, ResourceClass, RunId, Sha256Digest, TaskId, TaskRisk,
    Timestamp, TrustTier, WorkspaceVersion,
};

#[test]
fn policy_request_maps_exact_validated_tool_identity() {
    let request = tool_request();
    let evaluated_at = Timestamp::from_unix_seconds(1_753_272_000);

    let actual = policy_request_for_tool(&request, evaluated_at);

    assert_eq!(
        actual,
        PolicyRequest {
            task_id: TaskId::new("task-1").unwrap(),
            actor: PolicyActor {
                connection_id: "connection-1".to_owned(),
                agent_id: "agent-1".to_owned(),
                trust_tier: TrustTier::IsolatedWorker,
                locality: ActorLocality::Local,
            },
            action: PolicyAction::new("process.exec").unwrap(),
            resource: PolicyResource {
                capability: CapabilityRef::worktree(TaskId::new("task-1").unwrap(), ".",).unwrap(),
                content_digest: digest('a'),
                resource_class: ResourceClass::InternalCode,
            },
            task_risk: TaskRisk::High,
            workflow_phase: "Implementation".to_owned(),
            purpose: "run focused tests".to_owned(),
            policy_snapshot_digest: digest('b'),
            evaluated_at,
        }
    );
}

#[test]
fn evaluation_time_is_injected_but_not_echoed_into_policy_identity() {
    let request = tool_request();
    let first_time = Timestamp::from_unix_seconds(1_753_272_000);
    let second_time = Timestamp::from_unix_seconds(1_753_272_060);

    let first = policy_request_for_tool(&request, first_time);
    let second = policy_request_for_tool(&request, second_time);

    assert_eq!(first.evaluated_at, first_time);
    assert_eq!(second.evaluated_at, second_time);
    assert_eq!(
        canonical_policy_binding_digest(&first).unwrap(),
        canonical_policy_binding_digest(&second).unwrap()
    );
}

#[test]
fn mismatched_policy_task_is_invalid_before_policy_request_mapping() {
    let request = tool_request();
    let policy = request.policy();
    let mismatched_policy = ToolPolicyContext::new(
        policy.actor().clone(),
        policy.action().clone(),
        PolicyResource {
            capability: CapabilityRef::worktree(TaskId::new("task-2").unwrap(), ".").unwrap(),
            content_digest: policy.resource().content_digest.clone(),
            resource_class: policy.resource().resource_class,
        },
        policy.task_risk(),
        policy.purpose(),
        policy.policy_snapshot_digest().clone(),
    )
    .unwrap();

    let error = ToolRequest::new(
        ToolExecutionId::new("execution-mismatched-policy-task").unwrap(),
        request.process().clone(),
        mismatched_policy,
    )
    .unwrap_err();

    assert_eq!(
        error.safe_classification(),
        SafeErrorClassification::InvalidInput
    );
}

/// RED contract for the shared pre-effect boundary.
///
/// Initial execution and approval resume must converge on this boundary before
/// any durable execution claim or executor invocation is possible.
#[test]
fn allow_publishes_before_pre_effect_ready() {
    let events = Mutex::new(Vec::new());
    let records = Mutex::new(Vec::new());
    let publisher = RecordingPublisher {
        events: &events,
        artifact_id: ArtifactId::new("artifact-tool-request-1").unwrap(),
    };
    let request = tool_request();
    let evaluated_at = Timestamp::from_unix_seconds(1_753_272_000);
    let decision = policy_decision(
        policy_request_for_tool(&request, evaluated_at),
        PolicyEffect::Allow,
    );
    let decision_id = PolicyDecisionId::from_decision(&decision);
    let clock = RecordingClock {
        events: &events,
        value: "2025-07-23T12:00:00Z",
    };
    let evaluator = RecordingEvaluator {
        events: &events,
        decision: decision.clone(),
    };
    let policy_store = RecordingPolicyStore {
        events: &events,
        records: &records,
        decision_id: decision_id.clone(),
    };
    let orchestrator =
        ToolExecutionOrchestration::new(&publisher, &clock, &evaluator, &policy_store);

    let execution_id = request.execution_id().clone();
    let outcome = orchestrator.execute(request).unwrap();
    let PreEffectOutcome::Allowed(ready) = outcome else {
        panic!("allow decision did not produce a ready outcome");
    };

    assert_eq!(
        events.into_inner().unwrap(),
        ["publish", "clock", "evaluate", "record"]
    );
    assert_eq!(records.into_inner().unwrap()[0].recorded_at, evaluated_at);
    assert_eq!(ready.execution_id(), &execution_id);
    assert_eq!(
        ready.request_artifact_id().as_str(),
        "artifact-tool-request-1"
    );
    assert_eq!(ready.policy_decision_id(), &decision_id);
    assert!(ready
        .request_binding_digest()
        .as_sha256()
        .as_str()
        .starts_with("sha256:"));
}

#[test]
fn deny_is_recorded_once_before_typed_branch() {
    let request = tool_request();
    let evaluated_at = Timestamp::from_unix_seconds(1_753_272_000);
    let decision = policy_decision(
        policy_request_for_tool(&request, evaluated_at),
        PolicyEffect::Deny,
    );
    let decision_id = PolicyDecisionId::from_decision(&decision);
    let (result, events, records) = execute_with_decision(decision, decision_id.clone());

    assert_eq!(
        result.unwrap(),
        PreEffectOutcome::Denied {
            policy_decision_id: decision_id,
        }
    );
    assert_eq!(events, ["publish", "clock", "evaluate", "record"]);
    assert_eq!(records.len(), 1);
}

#[test]
fn require_approval_is_typed_without_constructing_approval_terms() {
    let request = tool_request();
    let evaluated_at = Timestamp::from_unix_seconds(1_753_272_000);
    let decision = policy_decision(
        policy_request_for_tool(&request, evaluated_at),
        PolicyEffect::RequireApproval,
    );
    let decision_id = PolicyDecisionId::from_decision(&decision);
    let (result, events, records) = execute_with_decision(decision, decision_id.clone());

    assert_eq!(
        result.unwrap(),
        PreEffectOutcome::ApprovalRequired {
            policy_decision_id: decision_id,
        }
    );
    assert_eq!(events, ["publish", "clock", "evaluate", "record"]);
    assert_eq!(records.len(), 1);
}

#[test]
fn allow_with_redaction_fails_closed_for_process_execution() {
    let request = tool_request();
    let evaluated_at = Timestamp::from_unix_seconds(1_753_272_000);
    let decision = policy_decision(
        policy_request_for_tool(&request, evaluated_at),
        PolicyEffect::AllowWithRedaction,
    );
    let decision_id = PolicyDecisionId::from_decision(&decision);
    let (result, events, records) = execute_with_decision(decision, decision_id.clone());

    assert_eq!(
        result.unwrap(),
        PreEffectOutcome::Denied {
            policy_decision_id: decision_id,
        }
    );
    assert_eq!(events, ["publish", "clock", "evaluate", "record"]);
    assert_eq!(records.len(), 1);
}

#[test]
fn evaluator_echo_mutations_fail_integrity_before_recording() {
    let request =
        policy_request_for_tool(&tool_request(), Timestamp::from_unix_seconds(1_753_272_000));
    let mut mutations = Vec::new();

    let mut changed = request.clone();
    changed.task_id = TaskId::new("task-2").unwrap();
    mutations.push(changed);
    let mut changed = request.clone();
    changed.actor.connection_id = "connection-2".to_owned();
    mutations.push(changed);
    let mut changed = request.clone();
    changed.actor.agent_id = "agent-2".to_owned();
    mutations.push(changed);
    let mut changed = request.clone();
    changed.actor.trust_tier = TrustTier::CoreAdapter;
    mutations.push(changed);
    let mut changed = request.clone();
    changed.actor.locality = ActorLocality::Cloud;
    mutations.push(changed);
    let mut changed = request.clone();
    changed.action = PolicyAction::new("process.check").unwrap();
    mutations.push(changed);
    let mut changed = request.clone();
    changed.resource.capability =
        CapabilityRef::worktree(TaskId::new("task-1").unwrap(), "src").unwrap();
    mutations.push(changed);
    let mut changed = request.clone();
    changed.resource.content_digest = digest('c');
    mutations.push(changed);
    let mut changed = request.clone();
    changed.task_risk = TaskRisk::Critical;
    mutations.push(changed);
    let mut changed = request.clone();
    changed.workflow_phase = "Verification".to_owned();
    mutations.push(changed);
    let mut changed = request.clone();
    changed.purpose = "mutated purpose".to_owned();
    mutations.push(changed);
    let mut changed = request.clone();
    changed.policy_snapshot_digest = digest('c');
    mutations.push(changed);
    let mut changed = request;
    changed.evaluated_at = Timestamp::from_unix_seconds(1_753_272_001);
    mutations.push(changed);

    for mutation in mutations {
        let decision = policy_decision(mutation, PolicyEffect::Allow);
        let expected_id = PolicyDecisionId::from_decision(&decision);
        let (result, events, records) = execute_with_decision(decision, expected_id);

        assert_eq!(
            result.unwrap_err().safe_classification(),
            SafeErrorClassification::IntegrityFailure
        );
        assert_eq!(events, ["publish", "clock", "evaluate"]);
        assert!(records.is_empty());
    }
}

#[test]
fn evaluator_resource_class_may_upgrade_but_not_downgrade() {
    let request =
        policy_request_for_tool(&tool_request(), Timestamp::from_unix_seconds(1_753_272_000));

    let mut upgraded = request.clone();
    upgraded.resource.resource_class = ResourceClass::Secret;
    let upgraded_decision = policy_decision(upgraded, PolicyEffect::Allow);
    let upgraded_id = PolicyDecisionId::from_decision(&upgraded_decision);
    let (result, events, records) = execute_with_decision(upgraded_decision, upgraded_id.clone());
    let PreEffectOutcome::Allowed(ready) = result.unwrap() else {
        panic!("resource-class upgrade did not remain allowable");
    };
    assert_eq!(ready.policy_decision_id(), &upgraded_id);
    assert_eq!(events, ["publish", "clock", "evaluate", "record"]);
    assert_eq!(records.len(), 1);

    let mut downgraded = request;
    downgraded.resource.resource_class = ResourceClass::Public;
    let downgraded_decision = policy_decision(downgraded, PolicyEffect::Allow);
    let downgraded_id = PolicyDecisionId::from_decision(&downgraded_decision);
    let (result, events, records) = execute_with_decision(downgraded_decision, downgraded_id);
    assert_eq!(
        result.unwrap_err().safe_classification(),
        SafeErrorClassification::IntegrityFailure
    );
    assert_eq!(events, ["publish", "clock", "evaluate"]);
    assert!(records.is_empty());
}

#[test]
fn decision_id_mismatch_fails_integrity_after_one_record() {
    let request = tool_request();
    let evaluated_at = Timestamp::from_unix_seconds(1_753_272_000);
    let decision = policy_decision(
        policy_request_for_tool(&request, evaluated_at),
        PolicyEffect::Allow,
    );
    let wrong_id = PolicyDecisionId::from_decision(&policy_decision_with_digest(
        policy_request_for_tool(&request, evaluated_at),
        PolicyEffect::Allow,
        'd',
    ));
    let (result, events, records) = execute_with_decision(decision, wrong_id);

    assert_eq!(
        result.unwrap_err().safe_classification(),
        SafeErrorClassification::IntegrityFailure
    );
    assert_eq!(events, ["publish", "clock", "evaluate", "record"]);
    assert_eq!(records.len(), 1);
}

#[test]
fn invalid_clock_timestamp_stops_before_policy_evaluation() {
    let events = Mutex::new(Vec::new());
    let records = Mutex::new(Vec::new());
    let publisher = RecordingPublisher {
        events: &events,
        artifact_id: ArtifactId::new("artifact-tool-request-1").unwrap(),
    };
    let clock = RecordingClock {
        events: &events,
        value: "not-a-timestamp",
    };
    let evaluator = RecordingEvaluator {
        events: &events,
        decision: policy_decision(
            policy_request_for_tool(&tool_request(), Timestamp::from_unix_seconds(1_753_272_000)),
            PolicyEffect::Allow,
        ),
    };
    let policy_store = RecordingPolicyStore {
        events: &events,
        records: &records,
        decision_id: PolicyDecisionId::from_decision(&evaluator.decision),
    };
    let orchestrator =
        ToolExecutionOrchestration::new(&publisher, &clock, &evaluator, &policy_store);

    let result = orchestrator.execute(tool_request());

    assert_eq!(
        result.unwrap_err().safe_classification(),
        SafeErrorClassification::InvalidInput
    );
    assert_eq!(events.into_inner().unwrap(), ["publish", "clock"]);
    assert!(records.into_inner().unwrap().is_empty());
}

struct RecordingPublisher<'a> {
    events: &'a Mutex<Vec<&'static str>>,
    artifact_id: ArtifactId,
}

impl ToolRequestPublisher for RecordingPublisher<'_> {
    fn publish(&self, request: &ImmutableToolRequest) -> Result<ArtifactId, PortError> {
        assert_eq!(
            request.request().execution_id().as_str(),
            "execution-orchestration"
        );
        self.events.lock().unwrap().push("publish");
        Ok(self.artifact_id.clone())
    }
}

struct RecordingClock<'a> {
    events: &'a Mutex<Vec<&'static str>>,
    value: &'static str,
}

impl Clock for RecordingClock<'_> {
    fn now_utc(&self) -> Result<String, PortError> {
        self.events.lock().unwrap().push("clock");
        Ok(self.value.to_owned())
    }
}

struct RecordingEvaluator<'a> {
    events: &'a Mutex<Vec<&'static str>>,
    decision: PolicyDecision,
}

impl PolicyEvaluator for RecordingEvaluator<'_> {
    fn evaluate(&self, _request: PolicyRequest) -> Result<PolicyDecision, PortError> {
        self.events.lock().unwrap().push("evaluate");
        Ok(self.decision.clone())
    }
}

struct RecordingPolicyStore<'a> {
    events: &'a Mutex<Vec<&'static str>>,
    records: &'a Mutex<Vec<RecordedPolicyDecision>>,
    decision_id: PolicyDecisionId,
}

impl PolicyDecisionStore for RecordingPolicyStore<'_> {
    fn record(&self, decision: RecordedPolicyDecision) -> Result<PolicyDecisionId, PortError> {
        self.events.lock().unwrap().push("record");
        self.records.lock().unwrap().push(decision);
        Ok(self.decision_id.clone())
    }
}

fn execute_with_decision(
    decision: PolicyDecision,
    decision_id: PolicyDecisionId,
) -> (
    Result<PreEffectOutcome, PortError>,
    Vec<&'static str>,
    Vec<RecordedPolicyDecision>,
) {
    let events = Mutex::new(Vec::new());
    let records = Mutex::new(Vec::new());
    let publisher = RecordingPublisher {
        events: &events,
        artifact_id: ArtifactId::new("artifact-tool-request-1").unwrap(),
    };
    let clock = RecordingClock {
        events: &events,
        value: "2025-07-23T12:00:00Z",
    };
    let evaluator = RecordingEvaluator {
        events: &events,
        decision,
    };
    let policy_store = RecordingPolicyStore {
        events: &events,
        records: &records,
        decision_id,
    };
    let result = {
        let orchestrator =
            ToolExecutionOrchestration::new(&publisher, &clock, &evaluator, &policy_store);
        orchestrator.execute(tool_request())
    };

    (
        result,
        events.into_inner().unwrap(),
        records.into_inner().unwrap(),
    )
}

fn policy_decision(request: PolicyRequest, effect: PolicyEffect) -> PolicyDecision {
    policy_decision_with_digest(request, effect, 'c')
}

fn policy_decision_with_digest(
    request: PolicyRequest,
    effect: PolicyEffect,
    digest_character: char,
) -> PolicyDecision {
    let draft = combine_policy_rules(
        request,
        PolicyVersion::new(1).unwrap(),
        vec![MatchedPolicyRule {
            rule_id: PolicyRuleId::new("rule-process").unwrap(),
            effect,
            redactions: Vec::new(),
        }],
        None,
    )
    .unwrap();
    PolicyDecision {
        draft,
        operation_digest: digest(digest_character),
    }
}

fn tool_request() -> ToolRequest {
    let task_id = TaskId::new("task-1").unwrap();
    let process = ProcessToolRequest::new(
        ProcessBinding::new(
            task_id.clone(),
            RunId::new("run-1").unwrap(),
            PlanStepId::new("step-1").unwrap(),
            Phase::Implementation,
            WorkspaceVersion::new(4),
            EnvironmentProfile::new("rust", digest('e')).unwrap(),
            1,
        )
        .unwrap(),
        ProcessInvocation::new(
            CapabilityRef::toolchain("cargo").unwrap(),
            vec!["test".to_owned()],
            CapabilityRef::worktree(task_id.clone(), ".").unwrap(),
            ProcessTrustTier::IsolatedWorker,
            NetworkProfile::Denied,
            Vec::new(),
            Some(FencingToken::new(19).unwrap()),
        )
        .unwrap(),
    )
    .unwrap();
    let approved = local_agent_terminal_application::ApprovedProcessRequest::new(
        local_agent_terminal_application::ApprovedExecutableIdentity::new(
            local_agent_terminal_application::ResolvedExecutable {
                canonical_path: std::path::PathBuf::from(executable_path()),
                sha256: digest('f'),
                file_identity: local_agent_terminal_application::ExecutableFileIdentity::new(
                    "file-1",
                )
                .unwrap(),
                toolchain_id: "cargo".to_owned(),
            },
            "1.0".to_owned(),
        )
        .unwrap(),
        process,
        Vec::new(),
        None,
        None,
    )
    .unwrap();
    ToolRequest::new(
        local_agent_terminal_application::ToolExecutionId::new("execution-orchestration").unwrap(),
        approved,
        local_agent_terminal_application::ToolPolicyContext::new(
            PolicyActor {
                connection_id: "connection-1".to_owned(),
                agent_id: "agent-1".to_owned(),
                trust_tier: TrustTier::IsolatedWorker,
                locality: ActorLocality::Local,
            },
            PolicyAction::new("process.exec").unwrap(),
            PolicyResource {
                capability: CapabilityRef::worktree(task_id, ".").unwrap(),
                content_digest: digest('a'),
                resource_class: ResourceClass::InternalCode,
            },
            TaskRisk::High,
            "run focused tests",
            digest('b'),
        )
        .unwrap(),
    )
    .unwrap()
}

fn digest(character: char) -> Sha256Digest {
    Sha256Digest::new(format!("sha256:{}", character.to_string().repeat(64))).unwrap()
}

#[cfg(windows)]
fn executable_path() -> &'static str {
    r"C:\approved\cargo.exe"
}

#[cfg(not(windows))]
fn executable_path() -> &'static str {
    "/approved/cargo"
}
