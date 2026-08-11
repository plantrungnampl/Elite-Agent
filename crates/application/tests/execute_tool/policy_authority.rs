
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
    assert_eq!(
        events,
        ["publish", "authority", "clock", "evaluate", "record"]
    );
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
    assert_eq!(events, ["publish", "authority", "clock", "evaluate"]);
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
    assert_eq!(
        events,
        ["publish", "authority", "clock", "evaluate", "record"]
    );
    assert_eq!(records.len(), 1);
}

#[test]
fn invalid_clock_timestamp_stops_before_policy_evaluation() {
    let request = tool_request();
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
            policy_request_for_tool(&request, Timestamp::from_unix_seconds(1_753_272_000)),
            PolicyEffect::Allow,
        ),
    };
    let policy_store = RecordingPolicyStore {
        events: &events,
        records: &records,
        decision_id: PolicyDecisionId::from_decision(&evaluator.decision),
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

    let result = orchestrator.execute(request);

    assert_eq!(
        result.unwrap_err().safe_classification(),
        SafeErrorClassification::InvalidInput
    );
    assert_eq!(
        events.into_inner().unwrap(),
        ["publish", "authority", "clock"]
    );
    assert!(records.into_inner().unwrap().is_empty());
}

#[test]
fn authoritative_request_mutation_stops_before_policy_evaluation() {
    let request = tool_request();
    let evaluated_at = Timestamp::from_unix_seconds(1_753_272_000);
    let decision = policy_decision(
        policy_request_for_tool(&request, evaluated_at),
        PolicyEffect::Allow,
    );
    let decision_id = PolicyDecisionId::from_decision(&decision);

    let (result, events, records) = execute_with_authority(
        tool_request_with_argv(vec!["check".to_owned()]),
        decision,
        decision_id,
    );

    assert_eq!(
        result.unwrap_err().safe_classification(),
        SafeErrorClassification::IntegrityFailure
    );
    assert_eq!(events, ["publish", "authority"]);
    assert!(records.is_empty());
}

static NO_DENIALS: TestExecutionStore<'static> = TestExecutionStore {
    events: None,
    denied: Mutex::new(None),
    claim_authority: None,
    authorized_claims: Mutex::new(Vec::new()),
    resolutions: Mutex::new(Vec::new()),
};

struct TestExecutionStore<'a> {
    events: Option<&'a Mutex<Vec<&'static str>>>,
    denied: Mutex<Option<DeniedToolExecution>>,
    claim_authority: Option<ToolExecutionClaimAuthority>,
    authorized_claims: Mutex<Vec<AuthorizedToolExecutionClaim>>,
    resolutions: Mutex<Vec<ToolExecutionResolution>>,
}

impl<'a> TestExecutionStore<'a> {
    fn recording(events: &'a Mutex<Vec<&'static str>>) -> Self {
        Self {
            events: Some(events),
            denied: Mutex::new(None),
            claim_authority: None,
            authorized_claims: Mutex::new(Vec::new()),
            resolutions: Mutex::new(Vec::new()),
        }
    }

    fn replaying(events: &'a Mutex<Vec<&'static str>>, denied: DeniedToolExecution) -> Self {
        Self {
            events: Some(events),
            denied: Mutex::new(Some(denied)),
            claim_authority: None,
            authorized_claims: Mutex::new(Vec::new()),
            resolutions: Mutex::new(Vec::new()),
        }
    }

    fn executing(
        events: &'a Mutex<Vec<&'static str>>,
        claim_authority: ToolExecutionClaimAuthority,
    ) -> Self {
        Self {
            events: Some(events),
            denied: Mutex::new(None),
            claim_authority: Some(claim_authority),
            authorized_claims: Mutex::new(Vec::new()),
            resolutions: Mutex::new(Vec::new()),
        }
    }
}

impl ToolExecutionStore for TestExecutionStore<'_> {
    fn reserve(&self, _: NewToolIntent) -> Result<OperationIntentSnapshot, PortError> {
        unreachable!("pre-effect orchestration does not reserve execution intents")
    }

    fn begin(&self, _: NewToolExecution) -> Result<ToolExecutionClaim, PortError> {
        unreachable!("pre-effect orchestration does not begin execution")
    }

    fn begin_authorized(
        &self,
        request: AuthorizedToolExecutionClaim,
    ) -> Result<ToolExecutionClaim, PortError> {
        let authority = self
            .claim_authority
            .clone()
            .unwrap_or_else(|| unreachable!("pre-effect orchestration does not begin execution"));
        self.events
            .expect("execution tests must use a recording execution store")
            .lock()
            .unwrap()
            .push("begin-authorized");
        self.authorized_claims.lock().unwrap().push(request);
        Ok(ToolExecutionClaim::Claimed(authority))
    }

    fn load_denied(
        &self,
        _: &ArtifactId,
        _: &ImmutableToolRequest,
    ) -> Result<Option<DeniedToolExecution>, PortError> {
        Ok(self.denied.lock().unwrap().clone())
    }

    fn resolve_denied(
        &self,
        request: ToolExecutionDenialRequest,
    ) -> Result<DeniedToolExecution, PortError> {
        self.events
            .expect("denial tests must use a recording execution store")
            .lock()
            .unwrap()
            .push("resolve-denied");
        let denied = DeniedToolExecution::new(
            request.request.request().execution_id().clone(),
            request.request_artifact_id,
            request.policy_decision_id,
        );
        *self.denied.lock().unwrap() = Some(denied.clone());
        Ok(denied)
    }

    fn resolve_terminal(
        &self,
        resolution: ToolExecutionResolution,
    ) -> Result<DurableToolExecutionReceipt, PortError> {
        if self.claim_authority.is_none() {
            unreachable!("pre-effect orchestration does not resolve execution");
        }
        self.events
            .expect("execution tests must use a recording execution store")
            .lock()
            .unwrap()
            .push("resolve-terminal");
        let receipt = resolution.receipt().clone();
        self.resolutions.lock().unwrap().push(resolution);
        Ok(receipt)
    }

    fn request_cancellation(
        &self,
        _: &local_agent_terminal_application::ToolExecutionId,
    ) -> Result<local_agent_terminal_application::ToolExecutionCancellationClaim, PortError> {
        unreachable!("pre-effect orchestration does not cancel execution")
    }

    fn incomplete(&self) -> Result<Vec<IncompleteToolExecution>, PortError> {
        unreachable!("pre-effect orchestration does not inspect incomplete execution")
    }
}

struct RecordingStructuredExecutor<'a> {
    events: &'a Mutex<Vec<&'static str>>,
}

impl StructuredToolExecutor for RecordingStructuredExecutor<'_> {
    fn execute(&self, request: AuthorizedToolRequest) -> Result<ToolExecutionResult, PortError> {
        self.events.lock().unwrap().push("effect");
        Ok(ToolExecutionResult {
            receipt: ProcessReceipt {
                execution_id: request.execution_id,
                status: ProcessStatus::Exited,
                exit_code: Some(0),
                stdout: BoundedOutput {
                    bytes: Vec::new(),
                    truncated: false,
                },
                stderr: BoundedOutput {
                    bytes: Vec::new(),
                    truncated: false,
                },
                duration_ms: 1,
                job_receipt: JobReceipt {
                    root_pid: 42,
                    job_id: "execution-orchestration".to_owned(),
                    kill_on_close: true,
                    no_breakaway: true,
                    job_memory_limit: true,
                    job_cpu_time_limit: true,
                    memory_limit_bytes: 1024,
                    cpu_time_limit_ms: 1000,
                    max_active_processes: 1,
                    total_user_time_ms: 1,
                    resource_limit_terminated: false,
                    tree_terminated: false,
                },
                observed_writes: Vec::new(),
                output_digest: digest('9'),
            },
            artifacts: ToolExecutionArtifactEvidence::Published(
                DurableToolExecutionArtifacts::new(
                    DurableToolExecutionArtifact::Available(
                        ArtifactId::new("artifact-stdout").unwrap(),
                    ),
                    DurableToolExecutionArtifact::Available(
                        ArtifactId::new("artifact-stderr").unwrap(),
                    ),
                    Vec::new(),
                ),
            ),
        })
    }

    fn cancel(
        &self,
        _: &ToolExecutionId,
    ) -> Result<local_agent_terminal_application::CancellationReceipt, PortError> {
        unreachable!("execution test does not cancel")
    }

    fn file_read(
        &self,
        _: local_agent_terminal_application::FileReadRequest,
    ) -> Result<
        local_agent_terminal_application::DisclosureOutcome<
            local_agent_terminal_application::PolicyBoundBytes,
        >,
        PortError,
    > {
        unreachable!("execution test does not read files")
    }

    fn file_write(
        &self,
        _: local_agent_terminal_application::FileWriteRequest,
    ) -> Result<local_agent_terminal_application::VerifiedWrite, PortError> {
        unreachable!("execution test does not write files")
    }

    fn git_status(
        &self,
        _: local_agent_terminal_application::GitStatusRequest,
    ) -> Result<
        local_agent_terminal_application::DisclosureOutcome<
            local_agent_terminal_application::GitStatusResult,
        >,
        PortError,
    > {
        unreachable!("execution test does not query Git status")
    }

    fn git_diff(
        &self,
        _: local_agent_terminal_application::GitDiffRequest,
    ) -> Result<
        local_agent_terminal_application::DisclosureOutcome<
            local_agent_terminal_application::GitDiffResult,
        >,
        PortError,
    > {
        unreachable!("execution test does not query Git diff")
    }
}

struct RecordingPublisher<'a> {
    events: &'a Mutex<Vec<&'static str>>,
    artifact_id: ArtifactId,
}

struct RecordingAuthority<'a> {
    events: &'a Mutex<Vec<&'static str>>,
    current: ToolRequest,
}

impl ToolAuthorityResolver for RecordingAuthority<'_> {
    fn resolve(&self, _: &ToolRequest) -> Result<ToolAuthoritySnapshot, PortError> {
        self.events.lock().unwrap().push("authority");
        authority_snapshot(self.current.clone())
    }
}

struct ChangingAuthority<'a> {
    events: &'a Mutex<Vec<&'static str>>,
    current: Mutex<VecDeque<ToolRequest>>,
}

impl ToolAuthorityResolver for ChangingAuthority<'_> {
    fn resolve(&self, _: &ToolRequest) -> Result<ToolAuthoritySnapshot, PortError> {
        self.events.lock().unwrap().push("authority");
        authority_snapshot(
            self.current
                .lock()
                .unwrap()
                .pop_front()
                .expect("test authority observation"),
        )
    }
}

struct UnusedResumeStore;

impl ApprovalResumeStore for UnusedResumeStore {
    fn load_for_resume(
        &self,
        _: &ApprovalId,
        _: Timestamp,
    ) -> Result<ApprovalResumeSnapshot, PortError> {
        unreachable!("initial execution does not read approval resume state")
    }

    fn load_approval_request(&self, _: &ApprovalId) -> Result<ToolApprovalRequest, PortError> {
        unreachable!("initial execution does not read approval artifacts")
    }
}

impl ToolExecutionResumeStore for UnusedResumeStore {
    fn load_intent(&self, _: &ToolExecutionId) -> Result<ToolExecutionResumeSnapshot, PortError> {
        unreachable!("initial execution does not read execution resume state")
    }

    fn load_request_artifact(&self, _: &ArtifactId) -> Result<ImmutableToolRequest, PortError> {
        unreachable!("initial execution does not read request artifacts")
    }
}

struct RecordingResumeStore<'a> {
    events: &'a Mutex<Vec<&'static str>>,
    checked_at: Timestamp,
    approval: ApprovalResumeSnapshot,
    execution: ToolExecutionResumeSnapshot,
    approval_request: ToolApprovalRequest,
    immutable: ImmutableToolRequest,
}

impl ApprovalResumeStore for RecordingResumeStore<'_> {
    fn load_for_resume(
        &self,
        approval_id: &ApprovalId,
        checked_at: Timestamp,
    ) -> Result<ApprovalResumeSnapshot, PortError> {
        assert_eq!(approval_id, &self.approval.approval_id);
        assert_eq!(checked_at, self.checked_at);
        self.events.lock().unwrap().push("approval-resume");
        Ok(self.approval.clone())
    }

    fn load_approval_request(
        &self,
        approval_id: &ApprovalId,
    ) -> Result<ToolApprovalRequest, PortError> {
        assert_eq!(approval_id, self.approval_request.approval_id());
        self.events.lock().unwrap().push("approval-artifact");
        Ok(self.approval_request.clone())
    }
}

impl ToolExecutionResumeStore for RecordingResumeStore<'_> {
    fn load_intent(
        &self,
        execution_id: &ToolExecutionId,
    ) -> Result<ToolExecutionResumeSnapshot, PortError> {
        assert_eq!(execution_id, &self.execution.execution_id);
        self.events.lock().unwrap().push("execution-resume");
        Ok(self.execution.clone())
    }

    fn load_request_artifact(
        &self,
        artifact_id: &ArtifactId,
    ) -> Result<ImmutableToolRequest, PortError> {
        assert_eq!(artifact_id, &self.execution.request_artifact_id);
        self.events.lock().unwrap().push("request-artifact");
        Ok(self.immutable.clone())
    }
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

struct AdvancingClock<'a> {
    events: &'a Mutex<Vec<&'static str>>,
    values: Mutex<VecDeque<&'static str>>,
}

impl Clock for AdvancingClock<'_> {
    fn now_utc(&self) -> Result<String, PortError> {
        self.events.lock().unwrap().push("clock");
        Ok(self
            .values
            .lock()
            .unwrap()
            .pop_front()
            .expect("test clock observation")
            .to_owned())
    }
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

struct SequenceIds<'a> {
    events: &'a Mutex<Vec<&'static str>>,
    values: Mutex<VecDeque<String>>,
}

impl<'a> SequenceIds<'a> {
    fn new(events: &'a Mutex<Vec<&'static str>>) -> Self {
        Self::with_values(
            events,
            [
                "approval-1",
                "approval-artifact-1",
                "0123456789abcdef0123456789abcdef",
                "approval-2",
                "approval-artifact-2",
                "fedcba9876543210fedcba9876543210",
            ],
        )
    }

    fn with_values(
        events: &'a Mutex<Vec<&'static str>>,
        values: impl IntoIterator<Item = &'static str>,
    ) -> Self {
        Self {
            events,
            values: Mutex::new(values.into_iter().map(str::to_owned).collect()),
        }
    }
}

impl IdGenerator for SequenceIds<'_> {
    fn next_id(&self) -> Result<String, PortError> {
        self.events.lock().unwrap().push("id");
        self.values.lock().unwrap().pop_front().ok_or_else(|| {
            PortError::failure(
                SafeErrorClassification::Unavailable,
                Retryability::NonRetryable,
            )
        })
    }
}

struct RecordingApprovalPublisher {
    stored: Mutex<Option<ToolApprovalRequest>>,
    candidates: Mutex<Vec<ToolApprovalRequest>>,
    inserts: Mutex<usize>,
}

impl RecordingApprovalPublisher {
    fn new() -> Self {
        Self {
            stored: Mutex::new(None),
            candidates: Mutex::new(Vec::new()),
            inserts: Mutex::new(0),
        }
    }
}

impl ToolApprovalRequestPublisher for RecordingApprovalPublisher {
    fn publish_or_replay(
        &self,
        request: ToolApprovalRequest,
    ) -> Result<ToolApprovalPublication, PortError> {
        self.candidates.lock().unwrap().push(request.clone());
        let mut stored = self.stored.lock().unwrap();
        if let Some(existing) = stored.as_ref() {
            return Ok(ToolApprovalPublication::Replayed(existing.clone()));
        }
        *self.inserts.lock().unwrap() += 1;
        *stored = Some(request.clone());
        Ok(ToolApprovalPublication::Created(request))
    }
}

#[derive(Debug, Clone, Copy)]
enum ApprovalTermMutation {
    ApprovalId,
    Nonce,
    Expiry,
}

struct TamperingApprovalPublisher {
    mutation: ApprovalTermMutation,
}

impl ToolApprovalRequestPublisher for TamperingApprovalPublisher {
    fn publish_or_replay(
        &self,
        request: ToolApprovalRequest,
    ) -> Result<ToolApprovalPublication, PortError> {
        let approval_id = if matches!(self.mutation, ApprovalTermMutation::ApprovalId) {
            ApprovalId::new("approval-mutated").unwrap()
        } else {
            request.approval_id().clone()
        };
        let mut payload = request.payload().clone();
        if matches!(self.mutation, ApprovalTermMutation::Nonce) {
            payload.nonce = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_owned();
        }
        if matches!(self.mutation, ApprovalTermMutation::Expiry) {
            payload.expires_at = "2025-07-23T12:16:00Z".to_owned();
        }
        let mutated = ToolApprovalRequest::from_persisted(
            approval_id,
            request.approval_artifact_id().clone(),
            request.execution_id().clone(),
            request.policy_decision_id().clone(),
            request.policy_request_binding_digest().clone(),
            request.tool_request_artifact_id().clone(),
            request.tool_request_binding_digest().clone(),
            payload,
        )?;
        Ok(ToolApprovalPublication::Created(mutated))
    }
}

struct FailingApprovalPublisher;

impl ToolApprovalRequestPublisher for FailingApprovalPublisher {
    fn publish_or_replay(
        &self,
        _: ToolApprovalRequest,
    ) -> Result<ToolApprovalPublication, PortError> {
        Err(PortError::failure(
            SafeErrorClassification::Unavailable,
            Retryability::Retryable,
        ))
    }
}

fn with_require_approval_orchestrator<R>(
    request: &ToolRequest,
    approval_requests: &dyn ToolApprovalRequestPublisher,
    policy_expires_at: Option<Timestamp>,
    run: impl FnOnce(
        &ToolExecutionOrchestration<'_>,
        &Mutex<Vec<&'static str>>,
        &Mutex<Vec<RecordedPolicyDecision>>,
        &PolicyDecisionId,
    ) -> R,
) -> R {
    let events = Mutex::new(Vec::new());
    let records = Mutex::new(Vec::new());
    let evaluated_at = Timestamp::from_unix_seconds(1_753_272_000);
    let decision = policy_decision_with_expiry(
        policy_request_for_tool(request, evaluated_at),
        PolicyEffect::RequireApproval,
        policy_expires_at,
    );
    let decision_id = PolicyDecisionId::from_decision(&decision);
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
        decision_id: decision_id.clone(),
    };
    let authority = RecordingAuthority {
        events: &events,
        current: request.clone(),
    };
    let ids = SequenceIds::new(&events);
    let resumes = UnusedResumeStore;
    let orchestrator = ToolExecutionOrchestration::new(
        &publisher,
        &authority,
        &clock,
        &evaluator,
        &policy_store,
        &ids,
        approval_requests,
        &resumes,
        &resumes,
        &NO_DENIALS,
    );
    run(&orchestrator, &events, &records, &decision_id)
}

fn execute_with_decision(
    decision: PolicyDecision,
    decision_id: PolicyDecisionId,
) -> (
    Result<PreEffectOutcome, PortError>,
    Vec<&'static str>,
    Vec<RecordedPolicyDecision>,
) {
    execute_with_authority(tool_request(), decision, decision_id)
}

fn execute_with_authority(
    current_request: ToolRequest,
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
    let request = tool_request();
    let authority = RecordingAuthority {
        events: &events,
        current: current_request,
    };
    let ids = SequenceIds::new(&events);
    let approval_requests = RecordingApprovalPublisher::new();
    let resumes = UnusedResumeStore;
    let executions = TestExecutionStore::recording(&events);
    let result = {
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
        orchestrator.execute(request)
    };

    (
        result,
        events.into_inner().unwrap(),
        records.into_inner().unwrap(),
    )
}

fn execute_allowed_tool(
    request: ToolRequest,
    authority: &dyn ToolAuthorityResolver,
    events: &Mutex<Vec<&'static str>>,
    executions: &dyn ToolExecutionStore,
    executor: &dyn StructuredToolExecutor,
) -> Result<ToolOutcome, PortError> {
    let evaluated_at = Timestamp::from_unix_seconds(1_753_272_000);
    let decision = policy_decision(
        policy_request_for_tool(&request, evaluated_at),
        PolicyEffect::Allow,
    );
    let records = Mutex::new(Vec::new());
    let publisher = RecordingPublisher {
        events,
        artifact_id: ArtifactId::new("artifact-tool-request-1").unwrap(),
    };
    let clock = RecordingClock {
        events,
        value: "2025-07-23T12:00:00Z",
    };
    let evaluator = RecordingEvaluator {
        events,
        decision: decision.clone(),
    };
    let policy_store = RecordingPolicyStore {
        events,
        records: &records,
        decision_id: PolicyDecisionId::from_decision(&decision),
    };
    let ids = SequenceIds::new(events);
    let approval_requests = RecordingApprovalPublisher::new();
    let resumes = UnusedResumeStore;
    let pre_effect = ToolExecutionOrchestration::new(
        &publisher,
        authority,
        &clock,
        &evaluator,
        &policy_store,
        &ids,
        &approval_requests,
        &resumes,
        &resumes,
        executions,
    );
    ExecuteTool::new(pre_effect, executor).execute(request)
}

fn policy_decision(request: PolicyRequest, effect: PolicyEffect) -> PolicyDecision {
    policy_decision_with_digest(request, effect, 'c')
}

fn policy_decision_with_expiry(
    request: PolicyRequest,
    effect: PolicyEffect,
    expires_at: Option<Timestamp>,
) -> PolicyDecision {
    let draft = combine_policy_rules(
        request,
        PolicyVersion::new(1).unwrap(),
        vec![MatchedPolicyRule {
            rule_id: PolicyRuleId::new("rule-process").unwrap(),
            effect,
            redactions: Vec::new(),
        }],
        expires_at,
    )
    .unwrap();
    PolicyDecision {
        draft,
        operation_digest: digest('c'),
    }
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
    tool_request_with_argv(vec!["test".to_owned()])
}

fn tool_request_with_argv(argv: Vec<String>) -> ToolRequest {
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
            argv,
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
        vec![CapabilityRef::worktree(task_id.clone(), "src").unwrap()],
        None,
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
                content_digest: resource_digest(AUTHORITY_RESOURCE_BYTES),
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

fn tool_request_with_resource_class(
    request: &ToolRequest,
    resource_class: ResourceClass,
) -> ToolRequest {
    let policy = request.policy();
    let resource = policy.resource();
    ToolRequest::new(
        request.execution_id().clone(),
        request.process().clone(),
        ToolPolicyContext::new(
            policy.actor().clone(),
            policy.action().clone(),
            PolicyResource {
                capability: resource.capability.clone(),
                content_digest: resource.content_digest.clone(),
                resource_class,
            },
            policy.task_risk(),
            policy.purpose(),
            policy.policy_snapshot_digest().clone(),
        )
        .unwrap(),
    )
    .unwrap()
}

fn authority_snapshot(request: ToolRequest) -> Result<ToolAuthoritySnapshot, PortError> {
    let binding = request.process().process().binding();
    let lease = request
        .process()
        .process()
        .executor_fencing_token()
        .map(|token| LeaseSnapshot {
            task_id: binding.task_id().clone(),
            holder_run_id: binding.run_id().clone(),
            token,
            state: LeaseState::Active,
            acquired_at: "2025-07-23T11:00:00Z".to_owned(),
            expires_at: "2025-07-23T13:00:00Z".to_owned(),
            released_at: None,
        });
    ToolAuthoritySnapshot::new(request, AUTHORITY_RESOURCE_BYTES, lease)
}

fn resource_digest(bytes: &[u8]) -> Sha256Digest {
    Sha256Digest::new(format!("sha256:{:x}", Sha256::digest(bytes))).unwrap()
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
