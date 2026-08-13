use std::collections::BTreeSet;

use local_agent_terminal_domain::{
    ArtifactId, ProjectId, Sha256Digest, TaskId, Timestamp, WorkflowEvent, WorkflowState,
};
use serde_json::{json, Value};
use time::{format_description::well_known::Rfc3339, OffsetDateTime};

use crate::canonical_json::{sha256_digest, CanonicalJsonRequest};
use crate::{PortError, Retryability, SafeErrorClassification};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkflowGuardEvidence {
    pub kind: String,
    pub reference: String,
    pub subject_digest: Option<Sha256Digest>,
    pub evidence_digest: Sha256Digest,
    pub artifact_id: Option<ArtifactId>,
    pub approval_receipt_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkflowEffectBinding {
    pub kind: String,
    pub reference: String,
    pub effect_digest: Sha256Digest,
    pub artifact_id: Option<ArtifactId>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransitionWorkflowInput {
    pub command_id: String,
    pub transition_event_id: String,
    pub task_id: TaskId,
    pub rule_id: String,
    pub expected_stream_version: u64,
    pub event: WorkflowEvent,
    pub guards: Vec<WorkflowGuardEvidence>,
    pub effects: Vec<WorkflowEffectBinding>,
    pub core_actor_digest: Sha256Digest,
    pub reducer_version: String,
    pub prepared_at: Timestamp,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreparedWorkflowTransition {
    pub command_id: String,
    pub transition_event_id: String,
    pub task_id: TaskId,
    pub rule_id: String,
    pub expected_stream_version: u64,
    pub event: WorkflowEvent,
    pub guards: Vec<WorkflowGuardEvidence>,
    pub effects: Vec<WorkflowEffectBinding>,
    pub core_actor_digest: Sha256Digest,
    pub reducer_version: String,
    pub prepared_at: Timestamp,
    pub from_state: WorkflowState,
    pub to_state: WorkflowState,
    pub command_artifact: CanonicalJsonRequest,
    pub command_digest: Sha256Digest,
}

impl PreparedWorkflowTransition {
    pub fn input(&self) -> TransitionWorkflowInput {
        TransitionWorkflowInput {
            command_id: self.command_id.clone(),
            transition_event_id: self.transition_event_id.clone(),
            task_id: self.task_id.clone(),
            rule_id: self.rule_id.clone(),
            expected_stream_version: self.expected_stream_version,
            event: self.event.clone(),
            guards: self.guards.clone(),
            effects: self.effects.clone(),
            core_actor_digest: self.core_actor_digest.clone(),
            reducer_version: self.reducer_version.clone(),
            prepared_at: self.prepared_at,
        }
    }

    pub fn artifact_request(&self) -> &CanonicalJsonRequest {
        &self.command_artifact
    }
}

pub trait WorkflowAuthorityStore: Send + Sync {
    fn load_workflow(&self, task_id: &TaskId) -> Result<WorkflowState, PortError>;
    fn persist_transition(
        &self,
        command: &PreparedWorkflowTransition,
    ) -> Result<WorkflowState, PortError>;
}

pub trait WorkflowCommandPublisher: Send + Sync {
    fn publish_command(&self, request: &CanonicalJsonRequest) -> Result<(), PortError>;
}

pub struct TransitionWorkflow<'a> {
    store: &'a dyn WorkflowAuthorityStore,
    publisher: &'a dyn WorkflowCommandPublisher,
}

impl<'a> TransitionWorkflow<'a> {
    pub const fn new(
        store: &'a dyn WorkflowAuthorityStore,
        publisher: &'a dyn WorkflowCommandPublisher,
    ) -> Self {
        Self { store, publisher }
    }

    pub fn prepare(
        &self,
        input: TransitionWorkflowInput,
        project_id: ProjectId,
        command_artifact_id: ArtifactId,
    ) -> Result<PreparedWorkflowTransition, PortError> {
        let state = self.store.load_workflow(&input.task_id)?;
        prepare_workflow_transition(&state, input, project_id, command_artifact_id)
    }

    pub fn execute(
        &self,
        input: TransitionWorkflowInput,
        project_id: ProjectId,
        command_artifact_id: ArtifactId,
    ) -> Result<WorkflowState, PortError> {
        let prepared = self.prepare(input, project_id, command_artifact_id)?;
        self.publisher
            .publish_command(prepared.artifact_request())?;
        self.store.persist_transition(&prepared)
    }

    pub fn persist(
        &self,
        prepared: &PreparedWorkflowTransition,
    ) -> Result<WorkflowState, PortError> {
        self.store.persist_transition(prepared)
    }
}

pub fn prepare_workflow_transition(
    state: &WorkflowState,
    input: TransitionWorkflowInput,
    project_id: ProjectId,
    command_artifact_id: ArtifactId,
) -> Result<PreparedWorkflowTransition, PortError> {
    validate_input(state, &input)?;
    let guards = sort_guards(input.guards.clone())?;
    let effects = sort_effects(input.effects.clone())?;
    let guard_kinds = guards
        .iter()
        .map(|guard| guard.kind.clone())
        .collect::<BTreeSet<_>>();
    let effect_kinds = effects
        .iter()
        .map(|effect| effect.kind.clone())
        .collect::<BTreeSet<_>>();
    let transition = local_agent_terminal_domain::reduce(
        state,
        &local_agent_terminal_domain::TransitionRequest {
            rule_id: input.rule_id.clone(),
            event: input.event.clone(),
            guard_evidence_kinds: guard_kinds,
            effect_kinds,
        },
    )
    .map_err(|_| conflict())?;
    let mut to_snapshot = transition.state().snapshot();
    to_snapshot.last_transition_event_id = Some(input.transition_event_id.clone());
    let to_state = WorkflowState::rehydrate(to_snapshot).map_err(|_| integrity_failure())?;
    let command_without_digest = command_value(&input, &guards, &effects, state, &to_state, None)?;
    let command_digest = Sha256Digest::new(sha256_digest(
        &serde_json_canonicalizer::to_vec(&command_without_digest).map_err(|_| invalid_input())?,
    ))
    .map_err(|_| integrity_failure())?;
    let command_value = command_value(
        &input,
        &guards,
        &effects,
        state,
        &to_state,
        Some(&command_digest),
    )?;
    let command_artifact = CanonicalJsonRequest::new(
        command_artifact_id,
        project_id,
        Some(input.task_id.clone()),
        "workflow_transition_command",
        format!("workflow/commands/{}.json", input.command_id),
        "core",
        "workflow-authority",
        &command_value,
        format!("workflow-transition:{}", input.command_id),
    )?;
    Ok(PreparedWorkflowTransition {
        command_id: input.command_id,
        transition_event_id: input.transition_event_id,
        task_id: input.task_id,
        rule_id: input.rule_id,
        expected_stream_version: input.expected_stream_version,
        event: input.event,
        guards,
        effects,
        core_actor_digest: input.core_actor_digest,
        reducer_version: input.reducer_version,
        prepared_at: input.prepared_at,
        from_state: state.clone(),
        to_state,
        command_artifact,
        command_digest,
    })
}

fn validate_input(state: &WorkflowState, input: &TransitionWorkflowInput) -> Result<(), PortError> {
    if input.command_id.trim().is_empty()
        || input.transition_event_id.trim().is_empty()
        || input.rule_id.trim().is_empty()
        || input.reducer_version.trim().is_empty()
        || input.command_id.chars().count() > 256
        || input.task_id.as_str().chars().count() > 256
        || input.rule_id.chars().count() > 256
        || input.event.as_str().chars().count() > 256
        || input.reducer_version.chars().count() > 256
        || input.expected_stream_version != state.stream_version()
    {
        return Err(conflict());
    }
    Ok(())
}

fn sort_guards(
    mut guards: Vec<WorkflowGuardEvidence>,
) -> Result<Vec<WorkflowGuardEvidence>, PortError> {
    let original = guards.clone();
    guards.sort_by(|left, right| {
        left.kind
            .cmp(&right.kind)
            .then_with(|| left.reference.cmp(&right.reference))
    });
    if guards != original {
        return Err(conflict());
    }
    let mut kinds = BTreeSet::new();
    for guard in &guards {
        if guard.kind.trim().is_empty()
            || guard.reference.trim().is_empty()
            || guard.kind.chars().count() > 256
            || guard.reference.chars().count() > 256
            || !kinds.insert(guard.kind.clone())
        {
            return Err(conflict());
        }
    }
    Ok(guards)
}

fn sort_effects(
    mut effects: Vec<WorkflowEffectBinding>,
) -> Result<Vec<WorkflowEffectBinding>, PortError> {
    let original = effects.clone();
    effects.sort_by(|left, right| {
        left.kind
            .cmp(&right.kind)
            .then_with(|| left.reference.cmp(&right.reference))
    });
    if effects != original {
        return Err(conflict());
    }
    let mut kinds = BTreeSet::new();
    for effect in &effects {
        if effect.kind.trim().is_empty()
            || effect.reference.trim().is_empty()
            || effect.kind.chars().count() > 256
            || effect.reference.chars().count() > 256
            || !kinds.insert(effect.kind.clone())
        {
            return Err(conflict());
        }
    }
    Ok(effects)
}

fn command_value(
    input: &TransitionWorkflowInput,
    guards: &[WorkflowGuardEvidence],
    effects: &[WorkflowEffectBinding],
    from_state: &WorkflowState,
    to_state: &WorkflowState,
    command_digest: Option<&Sha256Digest>,
) -> Result<Value, PortError> {
    let prepared_at = OffsetDateTime::from_unix_timestamp(input.prepared_at.unix_seconds())
        .map_err(|_| invalid_input())?
        .format(&Rfc3339)
        .map_err(|_| invalid_input())?;
    let guard_values = guards
        .iter()
        .map(|guard| {
            let mut value = serde_json::Map::new();
            value.insert("kind".to_owned(), Value::String(guard.kind.clone()));
            value.insert(
                "reference".to_owned(),
                Value::String(guard.reference.clone()),
            );
            if let Some(subject_digest) = &guard.subject_digest {
                value.insert(
                    "subjectDigest".to_owned(),
                    Value::String(subject_digest.as_str().to_owned()),
                );
            }
            value.insert(
                "evidenceDigest".to_owned(),
                Value::String(guard.evidence_digest.as_str().to_owned()),
            );
            Value::Object(value)
        })
        .collect::<Vec<_>>();
    let effect_values = effects
        .iter()
        .map(|effect| {
            json!({
                "kind": effect.kind,
                "reference": effect.reference,
                "effectDigest": effect.effect_digest.as_str(),
            })
        })
        .collect::<Vec<_>>();
    let mut value = json!({
        "commandId": input.command_id,
        "taskId": input.task_id.as_str(),
        "ruleId": input.rule_id,
        "expectedStreamVersion": input.expected_stream_version,
        "event": input.event.as_str(),
        "fromState": state_route(from_state),
        "toState": state_route(to_state),
        "guardEvidence": guard_values,
        "effects": effect_values,
        "actor": {
            "kind": "trusted_core",
            "bindingDigest": input.core_actor_digest.as_str(),
        },
        "reducerVersion": input.reducer_version,
        "preparedAt": prepared_at,
    });
    if let Some(command_digest) = command_digest {
        value.as_object_mut().ok_or_else(integrity_failure)?.insert(
            "commandDigest".to_owned(),
            Value::String(command_digest.as_str().to_owned()),
        );
    }
    Ok(value)
}

fn state_route(state: &WorkflowState) -> Value {
    json!({
        "phase": state.phase().as_str(),
        "workflowProfile": state.workflow_profile().as_str(),
        "outcomeMode": state.outcome_mode().as_str(),
    })
}

pub(crate) fn invalid_input() -> PortError {
    PortError::failure(
        SafeErrorClassification::InvalidInput,
        Retryability::NonRetryable,
    )
}

pub(crate) fn integrity_failure() -> PortError {
    PortError::failure(
        SafeErrorClassification::IntegrityFailure,
        Retryability::NonRetryable,
    )
}

pub(crate) fn conflict() -> PortError {
    PortError::failure(
        SafeErrorClassification::Conflict,
        Retryability::NonRetryable,
    )
}
