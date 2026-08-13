use std::sync::Mutex;

use local_agent_terminal_application::{
    CanonicalJsonRequest, PortError, PreparedWorkflowTransition, Sha256Digest, TransitionWorkflow,
    TransitionWorkflowInput, WorkflowAuthorityStore, WorkflowCommandPublisher,
    WorkflowEffectBinding, WorkflowGuardEvidence,
};
use local_agent_terminal_domain::{
    ArtifactId, Condition, OperationState, Phase, ProjectId, TaskId, Timestamp, WorkflowEvent,
    WorkflowProfile, WorkflowState, WorkflowStateSnapshot,
};
use sha2::{Digest, Sha256};

fn digest(byte: u8) -> Sha256Digest {
    Sha256Digest::new(format!("sha256:{}", (byte as char).to_string().repeat(64))).unwrap()
}

fn state() -> WorkflowState {
    WorkflowState::rehydrate(WorkflowStateSnapshot {
        phase: Phase::AwaitingPlanApproval,
        condition: Condition::Active,
        operation: OperationState::None,
        workflow_profile: WorkflowProfile::Standard,
        outcome_mode: local_agent_terminal_domain::TaskOutcomeMode::WorkspaceChange,
        stream_version: 8,
        profile_revision: 1,
        workspace_version: 0,
        fencing_epoch: 1,
        last_transition_event_id: Some("transition-8".to_owned()),
        last_profile_revision_id: None,
    })
    .unwrap()
}

fn input() -> TransitionWorkflowInput {
    TransitionWorkflowInput {
        command_id: "command-p015".to_owned(),
        transition_event_id: "transition-p015".to_owned(),
        task_id: TaskId::new("task-1").unwrap(),
        rule_id: "WF-P015".to_owned(),
        expected_stream_version: 8,
        event: WorkflowEvent::new("plan.approved").unwrap(),
        guards: vec![WorkflowGuardEvidence {
            kind: "plan_approval_receipt".to_owned(),
            reference: "receipt-1".to_owned(),
            subject_digest: Some(digest(b'a')),
            evidence_digest: digest(b'b'),
            artifact_id: Some(ArtifactId::new("receipt-artifact").unwrap()),
            approval_receipt_id: Some("receipt-1".to_owned()),
        }],
        effects: vec![
            WorkflowEffectBinding {
                kind: "allocate_executor_lease".to_owned(),
                reference: "lease-1".to_owned(),
                effect_digest: digest(b'd'),
                artifact_id: None,
            },
            WorkflowEffectBinding {
                kind: "persist_approved_plan_version".to_owned(),
                reference: "plan-1".to_owned(),
                effect_digest: digest(b'c'),
                artifact_id: None,
            },
        ],
        core_actor_digest: digest(b'e'),
        reducer_version: "v3".to_owned(),
        prepared_at: Timestamp::from_unix_seconds(1_760_000_000),
    }
}

#[test]
fn wf_p015_preparation_emits_canonical_command_digest() {
    let prepared = local_agent_terminal_application::prepare_workflow_transition(
        &state(),
        input(),
        ProjectId::new("project-1").unwrap(),
        ArtifactId::new("command-artifact").unwrap(),
    )
    .unwrap();
    let value: serde_json::Value =
        serde_json::from_slice(&prepared.command_artifact.canonical_bytes).unwrap();
    let command_digest = value
        .get("commandDigest")
        .and_then(serde_json::Value::as_str)
        .unwrap();
    let mut without_digest = value.clone();
    without_digest
        .as_object_mut()
        .unwrap()
        .remove("commandDigest");
    let canonical = serde_json_canonicalizer::to_vec(&without_digest).unwrap();
    assert_eq!(
        command_digest,
        format!("sha256:{:x}", Sha256::digest(canonical))
    );
    assert_eq!(
        prepared.command_artifact.canonical_bytes,
        serde_json_canonicalizer::to_vec(&value).unwrap()
    );
    assert_eq!(
        prepared.command_artifact.expected_hash,
        format!(
            "sha256:{:x}",
            Sha256::digest(&prepared.command_artifact.canonical_bytes)
        )
    );
    assert_eq!(prepared.to_state.phase(), Phase::Implementation);
}

#[test]
fn wf_p015_rejects_missing_bindings_before_storage_dispatch() {
    let mut missing_guard = input();
    missing_guard.guards.clear();
    assert_conflict(missing_guard);

    let mut missing_effect = input();
    missing_effect.effects.pop();
    assert_conflict(missing_effect);
}

#[test]
fn wf_p015_rejects_duplicate_or_noncanonical_bindings() {
    let mut request = input();
    request.effects.swap(0, 1);
    assert_conflict(request);

    let mut duplicate_effect = input();
    duplicate_effect
        .effects
        .push(duplicate_effect.effects[0].clone());
    assert_conflict(duplicate_effect);

    let mut duplicate_guard = input();
    duplicate_guard
        .guards
        .push(duplicate_guard.guards[0].clone());
    assert_conflict(duplicate_guard);
}

#[test]
fn wf_p015_rejects_substitution_and_wrong_stream_before_storage_dispatch() {
    let mut substituted = input();
    substituted.guards[0].kind = "wrong_receipt".to_owned();
    assert_conflict(substituted);

    let mut substituted = input();
    substituted.effects[0].kind = "wrong_effect".to_owned();
    assert_conflict(substituted);

    let mut stale = input();
    stale.expected_stream_version = 7;
    assert_conflict(stale);

    let mut oversized = input();
    oversized.command_id = "x".repeat(257);
    assert_conflict(oversized);
}

fn assert_conflict(request: TransitionWorkflowInput) {
    let error = local_agent_terminal_application::prepare_workflow_transition(
        &state(),
        request,
        ProjectId::new("project-1").unwrap(),
        ArtifactId::new("command-artifact").unwrap(),
    )
    .unwrap_err();
    assert_eq!(
        error.safe_classification(),
        local_agent_terminal_application::SafeErrorClassification::Conflict
    );
}

#[derive(Default)]
struct RecordingAuthority {
    calls: Mutex<Vec<&'static str>>,
}

impl WorkflowAuthorityStore for RecordingAuthority {
    fn trusted_core_actor_digest(&self) -> Result<Sha256Digest, PortError> {
        self.calls.lock().unwrap().push("actor");
        Ok(digest(b'e'))
    }

    fn load_workflow(&self, _task_id: &TaskId) -> Result<WorkflowState, PortError> {
        self.calls.lock().unwrap().push("load");
        Ok(state())
    }

    fn persist_transition(
        &self,
        command: &PreparedWorkflowTransition,
    ) -> Result<WorkflowState, PortError> {
        self.calls.lock().unwrap().push("persist");
        Ok(command.to_state.clone())
    }
}

impl WorkflowCommandPublisher for RecordingAuthority {
    fn publish_command(&self, _request: &CanonicalJsonRequest) -> Result<(), PortError> {
        self.calls.lock().unwrap().push("publish");
        Ok(())
    }
}

struct FailingPublisher;

impl WorkflowCommandPublisher for FailingPublisher {
    fn publish_command(&self, _request: &CanonicalJsonRequest) -> Result<(), PortError> {
        Err(PortError::failure(
            local_agent_terminal_application::SafeErrorClassification::IntegrityFailure,
            local_agent_terminal_application::Retryability::NonRetryable,
        ))
    }
}

#[test]
fn execute_publishes_command_before_authority_transaction() {
    let authority = RecordingAuthority::default();
    let next = TransitionWorkflow::new(&authority, &authority)
        .execute(
            input(),
            ProjectId::new("project-1").unwrap(),
            ArtifactId::new("command-artifact").unwrap(),
        )
        .unwrap();

    assert_eq!(next.phase(), Phase::Implementation);
    assert_eq!(
        authority.calls.lock().unwrap().as_slice(),
        ["actor", "load", "publish", "persist"]
    );
}

#[test]
fn execute_rejects_untrusted_core_actor_before_publication() {
    let authority = RecordingAuthority::default();
    let mut request = input();
    request.core_actor_digest = digest(b'f');

    let error = TransitionWorkflow::new(&authority, &authority)
        .execute(
            request,
            ProjectId::new("project-1").unwrap(),
            ArtifactId::new("command-artifact").unwrap(),
        )
        .unwrap_err();

    assert_eq!(
        error.safe_classification(),
        local_agent_terminal_application::SafeErrorClassification::Conflict
    );
    assert_eq!(authority.calls.lock().unwrap().as_slice(), ["actor"]);
}

#[test]
fn execute_does_not_persist_when_command_publication_fails() {
    let authority = RecordingAuthority::default();
    let error = TransitionWorkflow::new(&authority, &FailingPublisher)
        .execute(
            input(),
            ProjectId::new("project-1").unwrap(),
            ArtifactId::new("command-artifact").unwrap(),
        )
        .unwrap_err();

    assert_eq!(
        error.safe_classification(),
        local_agent_terminal_application::SafeErrorClassification::IntegrityFailure
    );
    assert_eq!(
        authority.calls.lock().unwrap().as_slice(),
        ["actor", "load"]
    );
}
