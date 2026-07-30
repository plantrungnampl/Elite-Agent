use std::sync::Mutex;

use local_agent_terminal_application::{
    canonical_policy_binding_digest, policy_request_for_tool, ArtifactId, ImmutableToolRequest,
    PortError, SafeErrorClassification, ToolExecutionId, ToolExecutionOrchestration,
    ToolPolicyContext, ToolRequest, ToolRequestPublisher,
};
use local_agent_terminal_domain::{
    ActorLocality, CapabilityRef, EnvironmentProfile, FencingToken, NetworkProfile, Phase,
    PlanStepId, PolicyAction, PolicyActor, PolicyRequest, PolicyResource, ProcessBinding,
    ProcessInvocation, ProcessToolRequest, ProcessTrustTier, ResourceClass, RunId, Sha256Digest,
    TaskId, TaskRisk, Timestamp, TrustTier, WorkspaceVersion,
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
    let publisher = RecordingPublisher {
        events: &events,
        artifact_id: ArtifactId::new("artifact-tool-request-1").unwrap(),
    };
    let orchestrator = ToolExecutionOrchestration::new(&publisher);

    let request = tool_request();
    let execution_id = request.execution_id().clone();
    let ready = orchestrator.execute(request).unwrap();

    assert_eq!(events.into_inner().unwrap(), ["publish"]);
    assert_eq!(ready.execution_id(), &execution_id);
    assert_eq!(
        ready.request_artifact_id().as_str(),
        "artifact-tool-request-1"
    );
    assert!(ready
        .request_binding_digest()
        .as_sha256()
        .as_str()
        .starts_with("sha256:"));
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
