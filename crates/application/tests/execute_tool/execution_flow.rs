use std::collections::VecDeque;
use std::sync::Mutex;

use local_agent_terminal_application::{
    canonical_policy_binding_digest, canonical_tool_request, policy_request_for_tool, ApprovalId,
    ApprovalResumeSnapshot, ApprovalResumeStore, ApprovalState, ArtifactId,
    AuthorizedToolExecutionClaim, AuthorizedToolRequest, BoundedOutput, Clock, DeniedToolExecution,
    DurableToolExecutionArtifact, DurableToolExecutionArtifacts, DurableToolExecutionOutcome,
    DurableToolExecutionReceipt, ExecuteTool, IdGenerator, ImmutableToolRequest,
    IncompleteToolExecution, JobReceipt, LeaseSnapshot, LeaseState, NewToolExecution,
    NewToolIntent, OperationIntentSnapshot, OperationIntentStatus, PolicyDecision,
    PolicyDecisionId, PolicyDecisionStore, PolicyEvaluator, PortError, PreEffectOutcome,
    ProcessReceipt, ProcessStatus, RecordedPolicyDecision, Retryability, SafeErrorClassification,
    StructuredToolExecutor, ToolApprovalPublication, ToolApprovalRequest,
    ToolApprovalRequestPublisher, ToolAuthorityResolver, ToolAuthoritySnapshot,
    ToolExecutionArtifactEvidence, ToolExecutionClaim, ToolExecutionClaimAuthority,
    ToolExecutionDenialRequest, ToolExecutionId, ToolExecutionOrchestration,
    ToolExecutionResolution, ToolExecutionResult, ToolExecutionResumeSnapshot,
    ToolExecutionResumeStore, ToolExecutionStore, ToolExecutionTerminalKind, ToolOutcome,
    ToolPolicyContext, ToolRequest, ToolRequestPublisher,
};
use local_agent_terminal_domain::{
    combine_policy_rules, ActorLocality, CapabilityRef, EnvironmentProfile, FencingToken,
    MatchedPolicyRule, NetworkProfile, Phase, PlanStepId, PolicyAction, PolicyActor, PolicyEffect,
    PolicyRequest, PolicyResource, PolicyRuleId, PolicyVersion, ProcessBinding, ProcessInvocation,
    ProcessToolRequest, ProcessTrustTier, ResourceClass, RunId, Sha256Digest, TaskId, TaskRisk,
    Timestamp, TrustTier, WorkspaceVersion,
};
use sha2::{Digest, Sha256};

const AUTHORITY_RESOURCE_BYTES: &[u8] = b"orchestration authority";

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
                content_digest: resource_digest(AUTHORITY_RESOURCE_BYTES),
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

#[test]
fn process_request_rejects_a_mismatched_policy_action() {
    let request = tool_request();
    let policy = request.policy();
    let mismatched_policy = ToolPolicyContext::new(
        policy.actor().clone(),
        PolicyAction::new("file.read").unwrap(),
        policy.resource().clone(),
        policy.task_risk(),
        policy.purpose(),
        policy.policy_snapshot_digest().clone(),
    )
    .unwrap();

    let error = ToolRequest::new(
        ToolExecutionId::new("execution-mismatched-policy-action").unwrap(),
        request.process().clone(),
        mismatched_policy,
    )
    .unwrap_err();

    assert_eq!(
        error.safe_classification(),
        SafeErrorClassification::InvalidInput
    );
}

#[test]
fn approval_publication_port_is_object_safe() {
    fn accepts(_: &dyn ToolApprovalRequestPublisher) {}

    let publisher = RecordingApprovalPublisher::new();
    accepts(&publisher);
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
    let authority = RecordingAuthority {
        events: &events,
        current: request.clone(),
    };
    let ids = SequenceIds::new(&events);
    let approval_requests = RecordingApprovalPublisher::new();
    let resumes = UnusedResumeStore;
    let orchestrator = ToolExecutionOrchestration::new(
        &publisher,
        &authority,
        &clock,
        &evaluator,
        &policy_store,
        &ids,
        &approval_requests,
        &resumes,
        &resumes,
        &NO_DENIALS,
    );

    let execution_id = request.execution_id().clone();
    let outcome = orchestrator.execute(request).unwrap();
    let PreEffectOutcome::Allowed(ready) = outcome else {
        panic!("allow decision did not produce a ready outcome");
    };

    assert_eq!(
        events.into_inner().unwrap(),
        ["publish", "authority", "clock", "evaluate", "record"]
    );
    assert_eq!(
        records.into_inner().unwrap()[0].recorded_at(),
        evaluated_at
    );
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
fn execute_tool_claims_exact_current_authorization_before_effect_and_terminal() {
    let events = Mutex::new(Vec::new());
    let request = tool_request();
    let immutable = canonical_tool_request(&request).unwrap();
    let execution_id = request.execution_id().clone();
    let operation_digest = immutable.binding_digest().as_sha256().clone();
    let evaluated_at = Timestamp::from_unix_seconds(1_753_272_000);
    let decision_id = PolicyDecisionId::from_decision(&policy_decision(
        policy_request_for_tool(&request, evaluated_at),
        PolicyEffect::Allow,
    ));
    let authority = RecordingAuthority {
        events: &events,
        current: request.clone(),
    };
    let claim_authority = ToolExecutionClaimAuthority::from_persisted(
        execution_id.clone(),
        operation_digest.clone(),
        RunId::new("run-1").unwrap(),
        1,
        Some(FencingToken::new(19).unwrap()),
    )
    .unwrap();
    let executions = TestExecutionStore::executing(&events, claim_authority);
    let executor = RecordingStructuredExecutor { events: &events };
    let outcome =
        execute_allowed_tool(request, &authority, &events, &executions, &executor).unwrap();

    let ToolOutcome::Execution(DurableToolExecutionOutcome::Completed(receipt)) = outcome else {
        panic!("allowed execution did not complete");
    };
    assert_eq!(
        receipt.terminal().kind(),
        ToolExecutionTerminalKind::Succeeded
    );
    assert_eq!(
        *events.lock().unwrap(),
        [
            "publish",
            "authority",
            "clock",
            "evaluate",
            "record",
            "authority",
            "clock",
            "begin-authorized",
            "effect",
            "resolve-terminal",
        ]
    );
    let claims = executions.authorized_claims.into_inner().unwrap();
    assert_eq!(claims.len(), 1);
    let claim = &claims[0];
    assert_eq!(claim.execution_id, execution_id);
    assert_eq!(claim.request_content_digest, operation_digest);
    assert_eq!(claim.request_binding_digest, *immutable.binding_digest());
    assert_eq!(claim.task_id, TaskId::new("task-1").unwrap());
    assert_eq!(claim.run_id, RunId::new("run-1").unwrap());
    assert_eq!(claim.tool_name, "process.exec");
    assert_eq!(claim.policy_decision_id, decision_id);
    assert_eq!(claim.workspace_version, WorkspaceVersion::new(4));
    assert_eq!(claim.policy_snapshot_digest, digest('b'));
    assert_eq!(claim.fencing_token, Some(FencingToken::new(19).unwrap()));
    assert_eq!(claim.checked_at, evaluated_at);
    assert!(claim.approval.is_none());
}

#[test]
fn authority_change_after_policy_record_stops_before_claim_and_effect() {
    let events = Mutex::new(Vec::new());
    let request = tool_request();
    let immutable = canonical_tool_request(&request).unwrap();
    let authority = ChangingAuthority {
        events: &events,
        current: Mutex::new(VecDeque::from([
            request.clone(),
            tool_request_with_resource_class(&request, ResourceClass::Secret),
        ])),
    };
    let claim_authority = ToolExecutionClaimAuthority::from_persisted(
        request.execution_id().clone(),
        immutable.binding_digest().as_sha256().clone(),
        RunId::new("run-1").unwrap(),
        1,
        Some(FencingToken::new(19).unwrap()),
    )
    .unwrap();
    let executions = TestExecutionStore::executing(&events, claim_authority);
    let executor = RecordingStructuredExecutor { events: &events };
    let error =
        execute_allowed_tool(request, &authority, &events, &executions, &executor).unwrap_err();

    assert_eq!(
        error.safe_classification(),
        SafeErrorClassification::IntegrityFailure
    );
    assert_eq!(
        *events.lock().unwrap(),
        [
            "publish",
            "authority",
            "clock",
            "evaluate",
            "record",
            "authority",
        ]
    );
    assert!(executions.authorized_claims.lock().unwrap().is_empty());
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
        PreEffectOutcome::Denied(DeniedToolExecution::new(
            ToolExecutionId::new("execution-orchestration").unwrap(),
            ArtifactId::new("artifact-tool-request-1").unwrap(),
            decision_id,
        ))
    );
    assert_eq!(
        events,
        [
            "publish",
            "authority",
            "clock",
            "evaluate",
            "record",
            "resolve-denied",
        ]
    );
    assert_eq!(records.len(), 1);
}

#[test]
fn replayed_denial_skips_clock_policy_and_approval_publication() {
    let events = Mutex::new(Vec::new());
    let records = Mutex::new(Vec::new());
    let request = tool_request();
    let evaluated_at = Timestamp::from_unix_seconds(1_753_272_000);
    let decision = policy_decision(
        policy_request_for_tool(&request, evaluated_at),
        PolicyEffect::Deny,
    );
    let decision_id = PolicyDecisionId::from_decision(&decision);
    let artifact_id = ArtifactId::new("artifact-tool-request-1").unwrap();
    let executions = TestExecutionStore::replaying(
        &events,
        DeniedToolExecution::new(
            request.execution_id().clone(),
            artifact_id.clone(),
            decision_id.clone(),
        ),
    );
    let publisher = RecordingPublisher {
        events: &events,
        artifact_id,
    };
    let authority = RecordingAuthority {
        events: &events,
        current: request.clone(),
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
    let ids = SequenceIds::new(&events);
    let approval_requests = RecordingApprovalPublisher::new();
    let resumes = UnusedResumeStore;
    let orchestrator = ToolExecutionOrchestration::new(
        &publisher,
        &authority,
        &clock,
        &evaluator,
        &policy_store,
        &ids,
        &approval_requests,
        &resumes,
        &resumes,
        &executions,
    );

    assert!(matches!(
        orchestrator.execute(request).unwrap(),
        PreEffectOutcome::Denied(_)
    ));
    assert_eq!(events.into_inner().unwrap(), ["publish", "authority"]);
    assert!(records.into_inner().unwrap().is_empty());
    assert!(approval_requests
        .candidates
        .into_inner()
        .unwrap()
        .is_empty());
}

#[test]
fn require_approval_constructs_core_owned_canonical_terms_after_policy_recording() {
    let request = tool_request();
    let immutable = canonical_tool_request(&request).unwrap();
    let evaluated_at = Timestamp::from_unix_seconds(1_753_272_000);
    let policy_binding =
        canonical_policy_binding_digest(&policy_request_for_tool(&request, evaluated_at)).unwrap();
    let approval_requests = RecordingApprovalPublisher::new();

    with_require_approval_orchestrator(
        &request,
        &approval_requests,
        None,
        |orchestrator, events, records, decision_id| {
            let outcome = orchestrator.execute(request.clone()).unwrap();
            let PreEffectOutcome::ApprovalRequired(dto) = outcome else {
                panic!("require-approval decision did not return the immutable request");
            };
            let published = approval_requests.stored.lock().unwrap().clone().unwrap();

            assert_eq!(
                *events.lock().unwrap(),
                [
                    "publish",
                    "authority",
                    "clock",
                    "evaluate",
                    "record",
                    "id",
                    "id",
                    "id"
                ]
            );
            assert_eq!(records.lock().unwrap().len(), 1);
            assert_eq!(published.approval_id().as_str(), "approval-1");
            assert_eq!(
                published.approval_artifact_id().as_str(),
                "approval-artifact-1"
            );
            assert_eq!(published.execution_id().as_str(), "execution-orchestration");
            assert_eq!(published.policy_decision_id(), decision_id);
            assert_eq!(published.policy_request_binding_digest(), &policy_binding);
            assert_eq!(
                published.tool_request_artifact_id().as_str(),
                "artifact-tool-request-1"
            );
            assert_eq!(
                published.tool_request_binding_digest(),
                immutable.binding_digest()
            );
            assert_eq!(published.payload().requested_at, "2025-07-23T12:00:00Z");
            assert_eq!(published.payload().expires_at, "2025-07-23T12:15:00Z");
            assert_eq!(
                published.payload().nonce,
                "0123456789abcdef0123456789abcdef"
            );
            assert_eq!(published.payload().operation.tool, "process.exec");
            assert_eq!(
                published.payload().operation.executable_digest.as_deref(),
                Some(digest('f').as_str())
            );
            assert_eq!(
                published.payload().policy_snapshot_digest,
                digest('b').as_str()
            );
            assert_ne!(
                published.canonical_payload().operation_digest.as_str(),
                immutable.binding_digest().as_sha256().as_str()
            );
            assert_ne!(
                published.canonical_payload().operation_digest.as_str(),
                policy_binding.as_sha256().as_str()
            );
            assert_eq!(dto.approval_id, "approval-1");
            assert_eq!(
                dto.operation_digest,
                published.canonical_payload().operation_digest.as_str()
            );
            assert_eq!(dto.expires_at, "2025-07-23T12:15:00Z");
        },
    );
}

#[test]
fn approval_expiry_never_outlives_the_policy_decision() {
    let request = tool_request();
    let approval_requests = RecordingApprovalPublisher::new();
    with_require_approval_orchestrator(
        &request,
        &approval_requests,
        Some(Timestamp::from_unix_seconds(1_753_272_300)),
        |orchestrator, _, _, _| {
            let PreEffectOutcome::ApprovalRequired(dto) =
                orchestrator.execute(request.clone()).unwrap()
            else {
                panic!("require-approval decision did not return an approval request");
            };
            assert_eq!(dto.expires_at, "2025-07-23T12:05:00Z");
        },
    );
}

#[test]
fn repeated_execution_id_replays_one_immutable_approval_request() {
    let request = tool_request();
    let approval_requests = RecordingApprovalPublisher::new();
    with_require_approval_orchestrator(
        &request,
        &approval_requests,
        None,
        |orchestrator, _, _, _| {
            let first = orchestrator.execute(request.clone()).unwrap();
            let second = orchestrator.execute(request.clone()).unwrap();

            assert_eq!(first, second);
            assert_eq!(*approval_requests.inserts.lock().unwrap(), 1);
            let candidates = approval_requests.candidates.lock().unwrap();
            assert_eq!(candidates.len(), 2);
            assert_eq!(candidates[0].approval_id().as_str(), "approval-1");
            assert_eq!(candidates[1].approval_id().as_str(), "approval-2");
            assert_ne!(candidates[0].payload().nonce, candidates[1].payload().nonce);
        },
    );
}

#[test]
fn replay_keeps_original_policy_decision_separate_from_fresh_decision() {
    let request = tool_request();
    let approval_requests = RecordingApprovalPublisher::new();
    let run = |clock_value: &'static str,
               evaluated_at: Timestamp,
               decision_digest: char,
               id_values: [&'static str; 3]| {
        let events = Mutex::new(Vec::new());
        let records = Mutex::new(Vec::new());
        let publisher = RecordingPublisher {
            events: &events,
            artifact_id: ArtifactId::new("artifact-tool-request-1").unwrap(),
        };
        let clock = RecordingClock {
            events: &events,
            value: clock_value,
        };
        let decision = policy_decision_with_digest(
            policy_request_for_tool(&request, evaluated_at),
            PolicyEffect::RequireApproval,
            decision_digest,
        );
        let decision_id = PolicyDecisionId::from_decision(&decision);
        let evaluator = RecordingEvaluator {
            events: &events,
            decision,
        };
        let policy_store = RecordingPolicyStore {
            events: &events,
            records: &records,
            decision_id: decision_id.clone(),
        };
        let authority = RecordingAuthority {
            events: &events,
            current: request.clone(),
        };
        let ids = SequenceIds::with_values(&events, id_values);
        let resumes = UnusedResumeStore;
        let orchestrator = ToolExecutionOrchestration::new(
            &publisher,
            &authority,
            &clock,
            &evaluator,
            &policy_store,
            &ids,
            &approval_requests,
            &resumes,
            &resumes,
            &NO_DENIALS,
        );
        (orchestrator.execute(request.clone()).unwrap(), decision_id)
    };

    let (first, original_policy_decision_id) = run(
        "2025-07-23T12:00:00Z",
        Timestamp::from_unix_seconds(1_753_272_000),
        'c',
        [
            "approval-1",
            "approval-artifact-1",
            "0123456789abcdef0123456789abcdef",
        ],
    );
    let (replayed, fresh_policy_decision_id) = run(
        "2025-07-23T12:01:00Z",
        Timestamp::from_unix_seconds(1_753_272_060),
        'd',
        [
            "approval-2",
            "approval-artifact-2",
            "fedcba9876543210fedcba9876543210",
        ],
    );

    assert_ne!(original_policy_decision_id, fresh_policy_decision_id);
    assert_eq!(
        approval_requests
            .stored
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .policy_decision_id(),
        &original_policy_decision_id
    );
    assert_eq!(first, replayed);
    assert_eq!(*approval_requests.inserts.lock().unwrap(), 1);
}

#[test]
fn approved_resume_reloads_exact_records_and_reuses_pre_effect_path() {
    let request = tool_request();
    let immutable = canonical_tool_request(&request).unwrap();
    let initial_approvals = RecordingApprovalPublisher::new();
    let published = with_require_approval_orchestrator(
        &request,
        &initial_approvals,
        None,
        |orchestrator, _, _, _| {
            orchestrator.execute(request.clone()).unwrap();
            initial_approvals.stored.lock().unwrap().clone().unwrap()
        },
    );
    let request_content_digest = resource_digest(immutable.canonical_bytes());
    let binding = request.process().process().binding();
    let expires_at = Timestamp::from_unix_seconds(1_753_272_900);
    let intent_id = "intent-orchestration-1".to_owned();
    let approval = ApprovalResumeSnapshot::new(
        published.approval_id().clone(),
        published.execution_id().clone(),
        published.policy_decision_id().clone(),
        published.policy_request_binding_digest().clone(),
        published.canonical_payload().operation_digest.clone(),
        published.tool_request_binding_digest().clone(),
        binding.task_id().clone(),
        binding.run_id().clone(),
        published.tool_request_artifact_id().clone(),
        request_content_digest.clone(),
        intent_id.clone(),
        binding.workspace_version(),
        request.policy().policy_snapshot_digest().clone(),
        request.process().process().executor_fencing_token(),
        expires_at,
        published.payload().nonce.clone(),
        ApprovalState::Approved,
    )
    .unwrap();
    let execution = ToolExecutionResumeSnapshot::new(
        published.execution_id().clone(),
        published.approval_id().clone(),
        published.policy_decision_id().clone(),
        published.canonical_payload().operation_digest.clone(),
        published.policy_request_binding_digest().clone(),
        published.tool_request_binding_digest().clone(),
        binding.task_id().clone(),
        binding.run_id().clone(),
        binding.workspace_version(),
        request.policy().policy_snapshot_digest().clone(),
        request.process().process().executor_fencing_token(),
        expires_at,
        published.payload().nonce.clone(),
        published.tool_request_artifact_id().clone(),
        request_content_digest.clone(),
        request_content_digest,
        intent_id,
        OperationIntentStatus::Pending,
    )
    .unwrap();

    let events = Mutex::new(Vec::new());
    let records = Mutex::new(Vec::new());
    let mut resumes = RecordingResumeStore {
        events: &events,
        checked_at: Timestamp::from_unix_seconds(1_753_272_300),
        approval,
        execution,
        approval_request: published.clone(),
        immutable,
    };
    let publisher = RecordingPublisher {
        events: &events,
        artifact_id: published.tool_request_artifact_id().clone(),
    };
    let authority = RecordingAuthority {
        events: &events,
        current: request.clone(),
    };
    let clock = RecordingClock {
        events: &events,
        value: "2025-07-23T12:05:00Z",
    };
    let decision = policy_decision_with_digest(
        policy_request_for_tool(&request, Timestamp::from_unix_seconds(1_753_272_300)),
        PolicyEffect::RequireApproval,
        'd',
    );
    let fresh_policy_decision_id = PolicyDecisionId::from_decision(&decision);
    let evaluator = RecordingEvaluator {
        events: &events,
        decision,
    };
    let policy_store = RecordingPolicyStore {
        events: &events,
        records: &records,
        decision_id: fresh_policy_decision_id.clone(),
    };
    let ids = SequenceIds::new(&events);
    let replay_publications = RecordingApprovalPublisher::new();
    {
        let orchestrator = ToolExecutionOrchestration::new(
            &publisher,
            &authority,
            &clock,
            &evaluator,
            &policy_store,
            &ids,
            &replay_publications,
            &resumes,
            &resumes,
            &NO_DENIALS,
        );

        let outcome = orchestrator
            .resume_approved(published.approval_id().clone())
            .unwrap();
        let PreEffectOutcome::Allowed(ready) = outcome else {
            panic!("approved resume did not reach pre-effect ready");
        };

        assert_eq!(ready.approval_id(), Some(published.approval_id()));
        assert_eq!(ready.policy_decision_id(), &fresh_policy_decision_id);
        assert_ne!(ready.policy_decision_id(), published.policy_decision_id());
        assert_eq!(
            *events.lock().unwrap(),
            [
                "clock",
                "approval-resume",
                "execution-resume",
                "request-artifact",
                "approval-artifact",
                "authority",
                "evaluate",
                "record"
            ]
        );
        assert!(replay_publications.candidates.lock().unwrap().is_empty());
    }

    events.lock().unwrap().clear();
    records.lock().unwrap().clear();
    resumes.immutable =
        canonical_tool_request(&tool_request_with_argv(vec!["check".to_owned()])).unwrap();
    let orchestrator = ToolExecutionOrchestration::new(
        &publisher,
        &authority,
        &clock,
        &evaluator,
        &policy_store,
        &ids,
        &replay_publications,
        &resumes,
        &resumes,
        &NO_DENIALS,
    );

    let error = orchestrator
        .resume_approved(published.approval_id().clone())
        .unwrap_err();

    assert_eq!(
        error.safe_classification(),
        SafeErrorClassification::IntegrityFailure
    );
    assert_eq!(
        *events.lock().unwrap(),
        [
            "clock",
            "approval-resume",
            "execution-resume",
            "request-artifact",
            "approval-artifact"
        ]
    );
    assert!(records.lock().unwrap().is_empty());
}

#[test]
fn approval_expiring_during_revalidation_stops_before_begin_and_effect() {
    let request = tool_request();
    let immutable = canonical_tool_request(&request).unwrap();
    let initial_approvals = RecordingApprovalPublisher::new();
    let published = with_require_approval_orchestrator(
        &request,
        &initial_approvals,
        None,
        |orchestrator, _, _, _| {
            orchestrator.execute(request.clone()).unwrap();
            initial_approvals.stored.lock().unwrap().clone().unwrap()
        },
    );
    let request_content_digest = resource_digest(immutable.canonical_bytes());
    let binding = request.process().process().binding();
    let expires_at = Timestamp::from_unix_seconds(1_753_272_900);
    let intent_id = "intent-expiring-approval".to_owned();
    let approval = ApprovalResumeSnapshot::new(
        published.approval_id().clone(),
        published.execution_id().clone(),
        published.policy_decision_id().clone(),
        published.policy_request_binding_digest().clone(),
        published.canonical_payload().operation_digest.clone(),
        published.tool_request_binding_digest().clone(),
        binding.task_id().clone(),
        binding.run_id().clone(),
        published.tool_request_artifact_id().clone(),
        request_content_digest.clone(),
        intent_id.clone(),
        binding.workspace_version(),
        request.policy().policy_snapshot_digest().clone(),
        request.process().process().executor_fencing_token(),
        expires_at,
        published.payload().nonce.clone(),
        ApprovalState::Approved,
    )
    .unwrap();
    let execution = ToolExecutionResumeSnapshot::new(
        published.execution_id().clone(),
        published.approval_id().clone(),
        published.policy_decision_id().clone(),
        published.canonical_payload().operation_digest.clone(),
        published.policy_request_binding_digest().clone(),
        published.tool_request_binding_digest().clone(),
        binding.task_id().clone(),
        binding.run_id().clone(),
        binding.workspace_version(),
        request.policy().policy_snapshot_digest().clone(),
        request.process().process().executor_fencing_token(),
        expires_at,
        published.payload().nonce.clone(),
        published.tool_request_artifact_id().clone(),
        request_content_digest.clone(),
        request_content_digest.clone(),
        intent_id,
        OperationIntentStatus::Pending,
    )
    .unwrap();
    let events = Mutex::new(Vec::new());
    let records = Mutex::new(Vec::new());
    let resumes = RecordingResumeStore {
        events: &events,
        checked_at: Timestamp::from_unix_seconds(1_753_272_300),
        approval,
        execution,
        approval_request: published.clone(),
        immutable,
    };
    let publisher = RecordingPublisher {
        events: &events,
        artifact_id: published.tool_request_artifact_id().clone(),
    };
    let authority = RecordingAuthority {
        events: &events,
        current: request.clone(),
    };
    let clock = AdvancingClock {
        events: &events,
        values: Mutex::new(VecDeque::from([
            "2025-07-23T12:05:00Z",
            "2025-07-23T12:15:00Z",
        ])),
    };
    let decision = policy_decision_with_digest(
        policy_request_for_tool(&request, Timestamp::from_unix_seconds(1_753_272_300)),
        PolicyEffect::RequireApproval,
        'd',
    );
    let policy_store = RecordingPolicyStore {
        events: &events,
        records: &records,
        decision_id: PolicyDecisionId::from_decision(&decision),
    };
    let evaluator = RecordingEvaluator {
        events: &events,
        decision,
    };
    let claim_authority = ToolExecutionClaimAuthority::from_persisted(
        request.execution_id().clone(),
        request_content_digest,
        binding.run_id().clone(),
        1,
        request.process().process().executor_fencing_token(),
    )
    .unwrap();
    let executions = TestExecutionStore::executing(&events, claim_authority);
    let executor = RecordingStructuredExecutor { events: &events };
    let ids = SequenceIds::new(&events);
    let approvals = RecordingApprovalPublisher::new();
    let orchestration = ToolExecutionOrchestration::new(
        &publisher,
        &authority,
        &clock,
        &evaluator,
        &policy_store,
        &ids,
        &approvals,
        &resumes,
        &resumes,
        &executions,
    );

    let error = ExecuteTool::new(orchestration, &executor)
        .resume_approved(published.approval_id().clone())
        .unwrap_err();

    assert_eq!(
        error.safe_classification(),
        SafeErrorClassification::IntegrityFailure
    );
    assert_eq!(
        *events.lock().unwrap(),
        [
            "clock",
            "approval-resume",
            "execution-resume",
            "request-artifact",
            "approval-artifact",
            "authority",
            "evaluate",
            "record",
            "authority",
            "clock",
        ]
    );
    assert!(executions.authorized_claims.lock().unwrap().is_empty());

    events.lock().unwrap().clear();
    let fresh_clock = AdvancingClock {
        events: &events,
        values: Mutex::new(VecDeque::from([
            "2025-07-23T12:05:00Z",
            "2025-07-23T12:14:00Z",
        ])),
    };
    let orchestration = ToolExecutionOrchestration::new(
        &publisher,
        &authority,
        &fresh_clock,
        &evaluator,
        &policy_store,
        &ids,
        &approvals,
        &resumes,
        &resumes,
        &executions,
    );

    ExecuteTool::new(orchestration, &executor)
        .resume_approved(published.approval_id().clone())
        .unwrap();

    let claims = executions.authorized_claims.lock().unwrap();
    assert_eq!(claims.len(), 1);
    assert_eq!(
        claims[0].checked_at,
        Timestamp::from_unix_seconds(1_753_272_300)
    );
    assert_eq!(
        claims[0].approval_checked_at,
        Some(Timestamp::from_unix_seconds(1_753_272_840))
    );
    assert_eq!(
        claims[0].policy_request_binding_digest,
        *published.policy_request_binding_digest()
    );
    assert_eq!(claims[0].approval.as_ref(), Some(&published));
}

#[test]
fn replay_with_changed_full_request_binding_fails_closed() {
    let request = tool_request();
    let approval_requests = RecordingApprovalPublisher::new();
    with_require_approval_orchestrator(
        &request,
        &approval_requests,
        None,
        |orchestrator, _, _, _| {
            orchestrator.execute(request.clone()).unwrap();
            let error = orchestrator
                .execute(tool_request_with_argv(vec!["check".to_owned()]))
                .unwrap_err();

            assert_eq!(
                error.safe_classification(),
                SafeErrorClassification::IntegrityFailure
            );
            assert_eq!(*approval_requests.inserts.lock().unwrap(), 1);
        },
    );
}

#[test]
fn created_approval_term_mutations_are_rejected() {
    for mutation in [
        ApprovalTermMutation::ApprovalId,
        ApprovalTermMutation::Nonce,
        ApprovalTermMutation::Expiry,
    ] {
        let request = tool_request();
        let approval_requests = TamperingApprovalPublisher { mutation };
        with_require_approval_orchestrator(
            &request,
            &approval_requests,
            None,
            |orchestrator, _, _, _| {
                let error = orchestrator.execute(request.clone()).unwrap_err();
                assert_eq!(
                    error.safe_classification(),
                    SafeErrorClassification::IntegrityFailure
                );
            },
        );
    }
}

#[test]
fn approval_publication_failure_is_propagated_after_policy_recording() {
    let request = tool_request();
    let approval_requests = FailingApprovalPublisher;
    with_require_approval_orchestrator(
        &request,
        &approval_requests,
        None,
        |orchestrator, _, records, _| {
            let error = orchestrator.execute(request.clone()).unwrap_err();
            assert_eq!(
                error.safe_classification(),
                SafeErrorClassification::Unavailable
            );
            assert_eq!(records.lock().unwrap().len(), 1);
        },
    );
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
        PreEffectOutcome::Denied(DeniedToolExecution::new(
            ToolExecutionId::new("execution-orchestration").unwrap(),
            ArtifactId::new("artifact-tool-request-1").unwrap(),
            decision_id,
        ))
    );
    assert_eq!(
        events,
        [
            "publish",
            "authority",
            "clock",
            "evaluate",
            "record",
            "resolve-denied",
        ]
    );
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
        assert_eq!(events, ["publish", "authority", "clock", "evaluate"]);
        assert!(records.is_empty());
    }
}
