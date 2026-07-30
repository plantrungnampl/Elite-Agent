use local_agent_terminal_application::{
    validate_approval_resume_relation, validate_pending_approval_resume, ApprovalId,
    ApprovalResumeSnapshot, ApprovalResumeStore, ApprovalState, ArtifactId, ImmutableToolRequest,
    OperationIntentStatus, PolicyDecisionId, PolicyRequestBindingDigest, PortError, Retryability,
    SafeErrorClassification, ToolApprovalRequest, ToolExecutionId, ToolExecutionResumeSnapshot,
    ToolExecutionResumeStore, ToolRequestBindingDigest,
};
use local_agent_terminal_domain::{
    FencingToken, RunId, Sha256Digest, TaskId, Timestamp, WorkspaceVersion,
};

#[test]
fn resume_ports_are_object_safe_and_lookup_only_typed_inputs() {
    struct ApprovalReader;
    impl ApprovalResumeStore for ApprovalReader {
        fn load_for_resume(
            &self,
            approval_id: &ApprovalId,
            checked_at: Timestamp,
        ) -> Result<ApprovalResumeSnapshot, PortError> {
            assert_eq!(approval_id.as_str(), "approval-1");
            assert_eq!(checked_at, Timestamp::from_unix_seconds(100));
            Ok(resume_pair().0)
        }

        fn load_approval_request(&self, _: &ApprovalId) -> Result<ToolApprovalRequest, PortError> {
            unreachable!("object-safety test does not read approval artifacts")
        }
    }

    struct ExecutionReader;
    impl ToolExecutionResumeStore for ExecutionReader {
        fn load_intent(
            &self,
            execution_id: &ToolExecutionId,
        ) -> Result<ToolExecutionResumeSnapshot, PortError> {
            assert_eq!(execution_id.as_str(), "execution-1");
            Ok(resume_pair().1)
        }

        fn load_request_artifact(&self, _: &ArtifactId) -> Result<ImmutableToolRequest, PortError> {
            unreachable!("object-safety test does not read request artifacts")
        }
    }

    fn accepts_approval_port(_: &dyn ApprovalResumeStore) {}
    fn accepts_execution_port(_: &dyn ToolExecutionResumeStore) {}

    let approval_reader = ApprovalReader;
    let execution_reader = ExecutionReader;
    accepts_approval_port(&approval_reader);
    accepts_execution_port(&execution_reader);

    let approval_id = ApprovalId::new("approval-1").unwrap();
    let execution_id = ToolExecutionId::new("execution-1").unwrap();
    approval_reader
        .load_for_resume(&approval_id, Timestamp::from_unix_seconds(100))
        .unwrap();
    execution_reader.load_intent(&execution_id).unwrap();
}

#[test]
fn exact_approval_execution_intent_relation_is_accepted() {
    let (approval, execution) = resume_pair();

    validate_approval_resume_relation(&approval, &execution).unwrap();
    validate_pending_approval_resume(&approval, &execution, Timestamp::from_unix_seconds(100))
        .unwrap();
}

#[test]
fn terminal_or_expired_rows_keep_exact_relation_but_fail_pending_gate() {
    for (approval_state, intent_status) in [
        (ApprovalState::Consumed, OperationIntentStatus::Claimed),
        (ApprovalState::Approved, OperationIntentStatus::Started),
        (ApprovalState::Approved, OperationIntentStatus::Succeeded),
        (
            ApprovalState::Approved,
            OperationIntentStatus::Indeterminate,
        ),
    ] {
        let (mut approval, mut execution) = resume_pair();
        approval.state = approval_state;
        execution.intent_status = intent_status;
        validate_approval_resume_relation(&approval, &execution).unwrap();
        assert!(validate_pending_approval_resume(
            &approval,
            &execution,
            Timestamp::from_unix_seconds(100),
        )
        .is_err());
    }

    let (mut approval, mut execution) = resume_pair();
    approval.expires_at = Timestamp::from_unix_seconds(99);
    execution.approval_expires_at = Timestamp::from_unix_seconds(99);
    validate_approval_resume_relation(&approval, &execution).unwrap();
    assert!(validate_pending_approval_resume(
        &approval,
        &execution,
        Timestamp::from_unix_seconds(100),
    )
    .is_err());
}

#[test]
fn malformed_public_snapshot_fields_fail_relation_boundary() {
    let (mut approval, mut execution) = resume_pair();
    approval.nonce = "bad".to_owned();
    execution.approval_nonce = "bad".to_owned();
    assert!(validate_approval_resume_relation(&approval, &execution).is_err());

    let (mut approval, mut execution) = resume_pair();
    approval.intent_id = "\0".to_owned();
    execution.intent_id = "\0".to_owned();
    assert!(validate_approval_resume_relation(&approval, &execution).is_err());
}

#[test]
fn swapped_resume_bindings_fail_closed_as_non_retryable_integrity_errors() {
    type Mutation = fn(&mut ApprovalResumeSnapshot, &mut ToolExecutionResumeSnapshot);
    let mutations: [Mutation; 15] = [
        |approval, _| approval.execution_id = ToolExecutionId::new("execution-2").unwrap(),
        |approval, _| approval.task_id = TaskId::new("task-2").unwrap(),
        |approval, _| approval.run_id = RunId::new("run-2").unwrap(),
        |approval, _| approval.request_artifact_id = ArtifactId::new("artifact-2").unwrap(),
        |approval, _| approval.request_content_digest = digest('c'),
        |approval, _| approval.tool_request_binding_digest = binding('c'),
        |approval, _| {
            approval.policy_decision_id = policy_id('2');
        },
        |approval, _| {
            approval.approval_operation_digest = digest('c');
        },
        |approval, _| {
            approval.expires_at = Timestamp::from_unix_seconds(99);
        },
        |approval, _| {
            approval.nonce = "m".repeat(32);
        },
        |approval, _| {
            approval.workspace_version = WorkspaceVersion::new(9);
        },
        |approval, _| {
            approval.policy_snapshot_digest = digest('c');
        },
        |approval, _| {
            approval.fencing_token = Some(FencingToken::new(9).unwrap());
        },
        |approval, _| {
            approval.approval_id = ApprovalId::new("approval-2").unwrap();
        },
        |approval, _| approval.intent_id = "intent-2".to_owned(),
    ];

    for (index, mutate) in mutations.into_iter().enumerate() {
        let (mut approval, mut execution) = resume_pair();
        mutate(&mut approval, &mut execution);
        let result = validate_approval_resume_relation(&approval, &execution);
        assert!(
            result.is_err(),
            "swapped relation unexpectedly passed at mutation {index}"
        );
        let error = result.unwrap_err();
        assert_eq!(
            error.safe_classification(),
            SafeErrorClassification::IntegrityFailure
        );
        assert_eq!(error.retryability(), Retryability::NonRetryable);
    }
}

fn resume_pair() -> (ApprovalResumeSnapshot, ToolExecutionResumeSnapshot) {
    let approval_id = ApprovalId::new("approval-1").unwrap();
    let execution_id = ToolExecutionId::new("execution-1").unwrap();
    let policy_decision_id = policy_id('1');
    let task_id = TaskId::new("task-1").unwrap();
    let run_id = RunId::new("run-1").unwrap();
    let workspace_version = WorkspaceVersion::new(4);
    let policy_snapshot_digest = digest('b');
    let request_artifact_id = ArtifactId::new("artifact-tool-request-1").unwrap();
    let request_content_digest = digest('d');
    let request_binding_digest = binding('e');
    let approval_operation_digest = digest('f');
    let expires_at = Timestamp::from_unix_seconds(200);
    let nonce = "n".repeat(32);
    let intent_operation_digest = request_content_digest.clone();

    let approval = ApprovalResumeSnapshot::new(
        approval_id.clone(),
        execution_id.clone(),
        policy_decision_id.clone(),
        policy_binding('a'),
        approval_operation_digest.clone(),
        request_binding_digest.clone(),
        task_id.clone(),
        run_id.clone(),
        request_artifact_id.clone(),
        request_content_digest.clone(),
        "intent-1".to_owned(),
        workspace_version,
        policy_snapshot_digest.clone(),
        Some(FencingToken::new(7).unwrap()),
        expires_at,
        nonce.clone(),
        ApprovalState::Approved,
    )
    .unwrap();
    let execution = ToolExecutionResumeSnapshot::new(
        execution_id,
        approval_id,
        policy_decision_id,
        approval_operation_digest,
        policy_binding('a'),
        request_binding_digest,
        task_id,
        run_id,
        workspace_version,
        policy_snapshot_digest,
        Some(FencingToken::new(7).unwrap()),
        expires_at,
        nonce,
        request_artifact_id,
        request_content_digest,
        intent_operation_digest,
        "intent-1".to_owned(),
        OperationIntentStatus::Pending,
    )
    .unwrap();
    (approval, execution)
}

fn policy_binding(value: char) -> PolicyRequestBindingDigest {
    PolicyRequestBindingDigest::from_persisted(digest(value))
}

fn policy_id(value: char) -> PolicyDecisionId {
    PolicyDecisionId::from_persisted(format!("policy-decision:{}", value.to_string().repeat(64)))
        .unwrap()
}

fn binding(value: char) -> ToolRequestBindingDigest {
    ToolRequestBindingDigest::from_persisted(digest(value))
}

fn digest(value: char) -> Sha256Digest {
    Sha256Digest::new(format!("sha256:{}", value.to_string().repeat(64))).unwrap()
}
