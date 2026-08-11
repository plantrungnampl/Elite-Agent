use local_agent_terminal_domain::{
    reduce, ActorId, Condition, EventId, GuardEvaluations, GuardName, OperationState, Phase,
    Sequence, Sha256Digest, StreamId, TaskId, WorkflowEvent, WorkflowState,
};
use serde::{Deserialize, Serialize};

use crate::{
    approval::approval_time_contains, canonical_approval_payload, canonical_json::sha256_digest,
    parse_canonical_approval_payload, parse_policy_timestamp, AppendOperation,
    ApprovalDigestPayload, ApprovalId, CanonicalApprovalPayload, Clock, NewEvent,
    PlanApprovalOperationV1, PlanApprovalPathScopeV1, PlanApprovalPayloadV1, PlanApprovalPlanRefV1,
    PortError, ProjectionChange, Retryability, SafeErrorClassification,
};

const BINDING_NONCE_SCHEMA: &str = "plan-approval-binding-nonce.v1";
const AUTHORITY_BINDING_SCHEMA: &str = "plan-approval-authority-binding.v1";
const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PlanApprovalBindingInput {
    pub task_id: String,
    pub plan_artifact_id: String,
    pub plan_digest: String,
    pub plan_version: u64,
    pub base_commit: String,
    pub allowed_paths: Vec<PlanApprovalPathScopeV1>,
    pub planned_tool_digests: Vec<String>,
    pub verification_profile_digest: String,
    pub risk_class: String,
    pub repository_fingerprint: String,
    pub policy_snapshot_digest: String,
    pub agent_id: String,
    pub agent_manifest_digest: String,
    pub actor_id: String,
    pub task_version: u64,
    pub workspace_version: u64,
    pub fencing_epoch: u64,
    pub requested_at: String,
    pub expires_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PlanApprovalAuthorityBindingV1 {
    schema: String,
    binding: PlanApprovalBindingInput,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlanApprovalAuthorityBinding {
    binding: PlanApprovalBindingInput,
    canonical_bytes: Vec<u8>,
    content_digest: Sha256Digest,
}

impl PlanApprovalAuthorityBinding {
    pub fn issue(binding: PlanApprovalBindingInput) -> Result<Self, PortError> {
        canonical_plan_approval_payload(&binding)?;
        let envelope = PlanApprovalAuthorityBindingV1 {
            schema: AUTHORITY_BINDING_SCHEMA.to_owned(),
            binding: binding.clone(),
        };
        let value = serde_json::to_value(envelope).map_err(|_| invalid_input())?;
        let canonical_bytes =
            serde_json_canonicalizer::to_vec(&value).map_err(|_| invalid_input())?;
        let content_digest = digest_bytes(&canonical_bytes)?;
        Ok(Self {
            binding,
            canonical_bytes,
            content_digest,
        })
    }

    pub fn rehydrate(
        canonical_bytes: Vec<u8>,
        content_digest: Sha256Digest,
    ) -> Result<Self, PortError> {
        if digest_bytes(&canonical_bytes)? != content_digest {
            return Err(integrity_failure());
        }
        let envelope: PlanApprovalAuthorityBindingV1 =
            serde_json::from_slice(&canonical_bytes).map_err(|_| integrity_failure())?;
        if envelope.schema != AUTHORITY_BINDING_SCHEMA {
            return Err(integrity_failure());
        }
        let issued = Self::issue(envelope.binding).map_err(|_| integrity_failure())?;
        if issued.canonical_bytes != canonical_bytes || issued.content_digest != content_digest {
            return Err(integrity_failure());
        }
        Ok(issued)
    }

    pub fn binding(&self) -> &PlanApprovalBindingInput {
        &self.binding
    }

    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical_bytes
    }

    pub fn content_digest(&self) -> &Sha256Digest {
        &self.content_digest
    }

    pub fn validate(&self) -> Result<(), PortError> {
        let reopened = Self::rehydrate(self.canonical_bytes.clone(), self.content_digest.clone())?;
        if reopened.binding == self.binding {
            Ok(())
        } else {
            Err(integrity_failure())
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlanApprovalRequestArtifact {
    pub artifact_id: local_agent_terminal_domain::ArtifactId,
    pub content_digest: Sha256Digest,
    pub size_bytes: u64,
}

impl PlanApprovalRequestArtifact {
    pub fn validate(&self, canonical_bytes: &[u8]) -> Result<(), PortError> {
        if self.content_digest != digest_bytes(canonical_bytes)?
            || self.size_bytes
                != u64::try_from(canonical_bytes.len()).map_err(|_| integrity_failure())?
        {
            Err(integrity_failure())
        } else {
            Ok(())
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PlanApprovalAction {
    Approve,
    Revise,
    Reopen,
    AddOrReplaceAgent,
    Reject,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlanApprovalState {
    Requested,
    Resolved,
    Invalidated,
    Expired,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PlanApprovalTerminal {
    Resolved {
        action: PlanApprovalAction,
        actor_id: ActorId,
        resolved_at: String,
    },
    Invalidated {
        reason_code: String,
        actor_id: ActorId,
        invalidated_at: String,
    },
    Expired {
        expired_at: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewPlanApproval {
    approval_id: ApprovalId,
    task_id: TaskId,
    canonical_bytes: Vec<u8>,
    operation_digest: Sha256Digest,
    request_artifact: PlanApprovalRequestArtifact,
    authority_binding: PlanApprovalAuthorityBinding,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewPlanApprovalRehydration {
    pub approval_id: ApprovalId,
    pub canonical_bytes: Vec<u8>,
    pub operation_digest: Sha256Digest,
    pub request_artifact: PlanApprovalRequestArtifact,
    pub authority_binding_bytes: Vec<u8>,
    pub authority_binding_digest: Sha256Digest,
}

impl NewPlanApproval {
    pub fn rehydrate(record: NewPlanApprovalRehydration) -> Result<Self, PortError> {
        let authority_binding = PlanApprovalAuthorityBinding::rehydrate(
            record.authority_binding_bytes,
            record.authority_binding_digest,
        )?;
        let task_id =
            TaskId::new(&authority_binding.binding().task_id).map_err(|_| integrity_failure())?;
        let approval = Self {
            approval_id: record.approval_id,
            task_id,
            canonical_bytes: record.canonical_bytes,
            operation_digest: record.operation_digest,
            request_artifact: record.request_artifact,
            authority_binding,
        };
        approval.validate()?;
        Ok(approval)
    }

    pub fn approval_id(&self) -> &ApprovalId {
        &self.approval_id
    }

    pub fn task_id(&self) -> &TaskId {
        &self.task_id
    }

    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical_bytes
    }

    pub fn operation_digest(&self) -> &Sha256Digest {
        &self.operation_digest
    }

    pub fn request_artifact(&self) -> &PlanApprovalRequestArtifact {
        &self.request_artifact
    }

    pub fn binding(&self) -> &PlanApprovalBindingInput {
        self.authority_binding.binding()
    }

    pub fn authority_binding(&self) -> &PlanApprovalAuthorityBinding {
        &self.authority_binding
    }

    pub fn validate(&self) -> Result<(), PortError> {
        self.authority_binding.validate()?;
        let binding = self.authority_binding.binding();
        let task_id = TaskId::new(&binding.task_id).map_err(|_| invalid_input())?;
        let canonical = canonical_plan_approval_payload(binding)?;
        self.request_artifact.validate(&self.canonical_bytes)?;
        if self.task_id != task_id
            || canonical.canonical_bytes != self.canonical_bytes
            || canonical.operation_digest != self.operation_digest
            || self.request_artifact.content_digest != self.operation_digest
        {
            Err(integrity_failure())
        } else {
            Ok(())
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreparePlanApprovalRequestInput {
    pub approval_id: ApprovalId,
    pub request_artifact_id: local_agent_terminal_domain::ArtifactId,
}

pub struct PreparePlanApprovalRequest;

impl PreparePlanApprovalRequest {
    pub fn execute(
        input: PreparePlanApprovalRequestInput,
        authority_binding: &PlanApprovalAuthorityBinding,
        authoritative_state: &PlanApprovalCurrentState,
    ) -> Result<NewPlanApproval, PortError> {
        authority_binding.validate()?;
        validate_current_binding(authoritative_state)?;
        if authoritative_state.task_state.phase() != Phase::AwaitingPlanApproval
            || &authoritative_state.binding != authority_binding.binding()
        {
            return Err(conflict());
        }
        let canonical = canonical_plan_approval_payload(authority_binding.binding())?;
        let task_id =
            TaskId::new(&authority_binding.binding().task_id).map_err(|_| invalid_input())?;
        let approval = NewPlanApproval {
            approval_id: input.approval_id,
            task_id,
            request_artifact: PlanApprovalRequestArtifact {
                artifact_id: input.request_artifact_id,
                content_digest: canonical.operation_digest.clone(),
                size_bytes: u64::try_from(canonical.canonical_bytes.len())
                    .map_err(|_| integrity_failure())?,
            },
            canonical_bytes: canonical.canonical_bytes,
            operation_digest: canonical.operation_digest,
            authority_binding: authority_binding.clone(),
        };
        approval.validate()?;
        Ok(approval)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredPlanApproval {
    pub approval_id: ApprovalId,
    pub state: PlanApprovalState,
    pub canonical_bytes: Vec<u8>,
    pub operation_digest: Sha256Digest,
    pub request_artifact: PlanApprovalRequestArtifact,
    pub binding: PlanApprovalBindingInput,
    pub terminal: Option<PlanApprovalTerminal>,
    authority_binding: PlanApprovalAuthorityBinding,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredPlanApprovalRehydration {
    pub approval_id: ApprovalId,
    pub state: PlanApprovalState,
    pub canonical_bytes: Vec<u8>,
    pub operation_digest: Sha256Digest,
    pub request_artifact: PlanApprovalRequestArtifact,
    pub authority_binding_bytes: Vec<u8>,
    pub authority_binding_digest: Sha256Digest,
    pub terminal: Option<PlanApprovalTerminal>,
}

impl StoredPlanApproval {
    pub fn rehydrate(record: StoredPlanApprovalRehydration) -> Result<Self, PortError> {
        let authority_binding = PlanApprovalAuthorityBinding::rehydrate(
            record.authority_binding_bytes,
            record.authority_binding_digest,
        )?;
        let stored = Self {
            approval_id: record.approval_id,
            state: record.state,
            canonical_bytes: record.canonical_bytes,
            operation_digest: record.operation_digest,
            request_artifact: record.request_artifact,
            binding: authority_binding.binding().clone(),
            terminal: record.terminal,
            authority_binding,
        };
        stored.validate()?;
        Ok(stored)
    }

    pub fn binding(&self) -> &PlanApprovalBindingInput {
        &self.binding
    }

    pub fn authority_binding(&self) -> &PlanApprovalAuthorityBinding {
        &self.authority_binding
    }

    pub fn validate(&self) -> Result<(), PortError> {
        self.authority_binding.validate()?;
        self.request_artifact.validate(&self.canonical_bytes)?;
        let canonical = canonical_plan_approval_payload(&self.binding)?;
        let terminal_matches = matches!(
            (&self.state, &self.terminal),
            (PlanApprovalState::Requested, None)
                | (
                    PlanApprovalState::Resolved,
                    Some(PlanApprovalTerminal::Resolved { .. })
                )
                | (
                    PlanApprovalState::Invalidated,
                    Some(PlanApprovalTerminal::Invalidated { .. })
                )
                | (
                    PlanApprovalState::Expired,
                    Some(PlanApprovalTerminal::Expired { .. })
                )
        );
        if canonical.canonical_bytes != self.canonical_bytes
            || canonical.operation_digest != self.operation_digest
            || self.request_artifact.content_digest != self.operation_digest
            || self.authority_binding.binding() != &self.binding
            || !terminal_matches
        {
            Err(integrity_failure())
        } else {
            Ok(())
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlanApprovalCurrentState {
    pub phase: Phase,
    pub task_state: WorkflowState,
    pub binding: PlanApprovalBindingInput,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlanApprovalCurrentAuthority {
    pub repository_fingerprint: Sha256Digest,
    pub policy_snapshot_digest: Sha256Digest,
}

pub trait PlanApprovalCurrentAuthoritySource: Send + Sync {
    fn current_authority(
        &self,
        task_id: &TaskId,
    ) -> Result<PlanApprovalCurrentAuthority, PortError>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlanApprovalResolution {
    pub approval_id: ApprovalId,
    pub action: PlanApprovalAction,
    pub actor_id: ActorId,
    pub expected_task_version: u64,
    pub operation_digest: Sha256Digest,
    pub resolved_at: String,
    pub append: AppendOperation,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompareAndResolvePlanApproval {
    pub expected_approval: StoredPlanApproval,
    pub expected_current: PlanApprovalCurrentState,
    pub resolution: PlanApprovalResolution,
}

impl CompareAndResolvePlanApproval {
    pub fn validate(&self) -> Result<(), PortError> {
        self.expected_approval.validate()?;
        validate_current_binding(&self.expected_current)?;
        if !approval_time_contains(
            &self.expected_approval.binding.requested_at,
            &self.expected_approval.binding.expires_at,
            &self.resolution.resolved_at,
        )? {
            return Err(conflict());
        }
        let expected_append = resolution_append(
            &self.expected_current,
            &self.resolution.approval_id,
            self.resolution.action,
            &self.resolution.actor_id,
            &self.resolution.resolved_at,
            &self.resolution.operation_digest,
        )?;
        if self.expected_approval.state != PlanApprovalState::Requested
            || self.expected_approval.binding != self.expected_current.binding
            || self.resolution.approval_id != self.expected_approval.approval_id
            || self.resolution.expected_task_version
                != self.expected_current.task_state.sequence().get()
            || self.resolution.operation_digest != self.expected_approval.operation_digest
            || self.resolution.append != expected_append
        {
            Err(conflict())
        } else {
            Ok(())
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompareAndInvalidatePlanApproval {
    pub expected_approval: StoredPlanApproval,
    pub expected_current: PlanApprovalCurrentState,
    pub invalidation: PlanApprovalInvalidation,
}

impl CompareAndInvalidatePlanApproval {
    pub fn validate(&self) -> Result<(), PortError> {
        self.expected_approval.validate()?;
        validate_current_binding(&self.expected_current)?;
        let expected = build_plan_approval_invalidation(
            &self.expected_current,
            self.invalidation.approval_id(),
            self.invalidation.actor_id(),
            self.invalidation.reason_code(),
            self.invalidation.invalidated_at(),
        )?;
        if self.expected_approval.state != PlanApprovalState::Requested
            || self.expected_approval.binding != self.expected_current.binding
            || self.invalidation.approval_id() != &self.expected_approval.approval_id
            || self.invalidation.task_id().as_str() != self.expected_current.binding.task_id
            || self.invalidation != expected
        {
            Err(conflict())
        } else {
            Ok(())
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompareAndExpirePlanApproval {
    pub expected_approval: StoredPlanApproval,
    pub expected_current: PlanApprovalCurrentState,
    pub expiry: PlanApprovalExpiry,
}

impl CompareAndExpirePlanApproval {
    pub fn validate(&self) -> Result<(), PortError> {
        self.expected_approval.validate()?;
        validate_current_binding(&self.expected_current)?;
        let expected = build_plan_approval_expiry(
            &self.expected_current,
            self.expiry.approval_id(),
            &self.expected_approval.binding.expires_at,
            self.expiry.expired_at(),
        )?;
        if self.expected_approval.state != PlanApprovalState::Requested
            || self.expected_approval.binding != self.expected_current.binding
            || self.expiry.approval_id() != &self.expected_approval.approval_id
            || self.expiry.task_id().as_str() != self.expected_current.binding.task_id
            || self.expiry != expected
        {
            Err(conflict())
        } else {
            Ok(())
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlanApprovalInvalidation {
    approval_id: ApprovalId,
    task_id: TaskId,
    reason_code: String,
    actor_id: ActorId,
    invalidated_at: String,
    append: AppendOperation,
}

impl PlanApprovalInvalidation {
    pub fn approval_id(&self) -> &ApprovalId {
        &self.approval_id
    }

    pub fn task_id(&self) -> &TaskId {
        &self.task_id
    }

    pub fn reason_code(&self) -> &str {
        &self.reason_code
    }

    pub fn actor_id(&self) -> &ActorId {
        &self.actor_id
    }

    pub fn invalidated_at(&self) -> &str {
        &self.invalidated_at
    }

    pub fn append(&self) -> &AppendOperation {
        &self.append
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlanApprovalExpiry {
    approval_id: ApprovalId,
    task_id: TaskId,
    expired_at: String,
    append: AppendOperation,
}

impl PlanApprovalExpiry {
    pub fn approval_id(&self) -> &ApprovalId {
        &self.approval_id
    }

    pub fn task_id(&self) -> &TaskId {
        &self.task_id
    }

    pub fn expired_at(&self) -> &str {
        &self.expired_at
    }

    pub fn append(&self) -> &AppendOperation {
        &self.append
    }
}

pub trait PlanApprovalStore: Send + Sync {
    fn reload(&self, approval_id: &ApprovalId) -> Result<Option<StoredPlanApproval>, PortError>;
    fn current_state(&self, task_id: &TaskId) -> Result<PlanApprovalCurrentState, PortError>;
    /// Atomically reloads the approval and current task authority, requires exact equality with
    /// both expected snapshots, and resolves the still-requested approval once. Any state,
    /// phase, binding, digest, version, actor, expiry, or prior-resolution mismatch is Conflict.
    fn compare_and_resolve(&self, command: CompareAndResolvePlanApproval) -> Result<(), PortError>;
    /// Atomically compares the exact approval and task snapshots, appends the validated
    /// core-built invalidation fact, and terminalizes the approval. Partial visibility is
    /// forbidden; implementations must reject commands whose `validate` method fails.
    fn compare_and_invalidate(
        &self,
        command: CompareAndInvalidatePlanApproval,
    ) -> Result<(), PortError>;
    /// Atomically compares the exact approval and task snapshots, appends the validated
    /// core-built expiry fact, and terminalizes the approval. Partial visibility is forbidden;
    /// implementations must reject commands whose `validate` method fails.
    fn compare_and_expire(&self, command: CompareAndExpirePlanApproval) -> Result<(), PortError>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvalidatePlanApprovalInput {
    pub approval_id: ApprovalId,
    pub actor_id: ActorId,
    pub reason_code: String,
}

pub struct InvalidatePlanApproval<'a> {
    store: &'a dyn PlanApprovalStore,
    clock: &'a dyn Clock,
}

impl<'a> InvalidatePlanApproval<'a> {
    pub const fn new(store: &'a dyn PlanApprovalStore, clock: &'a dyn Clock) -> Self {
        Self { store, clock }
    }

    pub fn execute(
        &self,
        input: InvalidatePlanApprovalInput,
    ) -> Result<PlanApprovalInvalidation, PortError> {
        validate_label(&input.reason_code)?;
        let stored = self
            .store
            .reload(&input.approval_id)?
            .ok_or_else(not_found)?;
        stored.validate()?;
        if stored.state != PlanApprovalState::Requested || stored.approval_id != input.approval_id {
            return Err(conflict());
        }
        let task_id = TaskId::new(&stored.binding.task_id).map_err(|_| integrity_failure())?;
        let current = self.store.current_state(&task_id)?;
        validate_current_binding(&current)?;
        if current.binding != stored.binding {
            return Err(conflict());
        }
        let invalidated_at = self.clock.now_utc()?;
        let invalidation = build_plan_approval_invalidation(
            &current,
            &input.approval_id,
            &input.actor_id,
            &input.reason_code,
            &invalidated_at,
        )?;
        self.store
            .compare_and_invalidate(CompareAndInvalidatePlanApproval {
                expected_approval: stored,
                expected_current: current,
                invalidation: invalidation.clone(),
            })?;
        Ok(invalidation)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvePlanApprovalInput {
    pub approval_id: ApprovalId,
    pub displayed_digest: Sha256Digest,
    pub expected_task_version: u64,
    pub actor_id: ActorId,
    pub action: PlanApprovalAction,
}

pub struct ResolvePlanApproval<'a> {
    store: &'a dyn PlanApprovalStore,
    clock: &'a dyn Clock,
}

impl<'a> ResolvePlanApproval<'a> {
    pub const fn new(store: &'a dyn PlanApprovalStore, clock: &'a dyn Clock) -> Self {
        Self { store, clock }
    }

    pub fn execute(
        &self,
        input: ResolvePlanApprovalInput,
    ) -> Result<PlanApprovalResolution, PortError> {
        let stored = self
            .store
            .reload(&input.approval_id)?
            .ok_or_else(not_found)?;
        stored.validate()?;
        if stored.approval_id != input.approval_id
            || stored.state != PlanApprovalState::Requested
            || stored.terminal.is_some()
        {
            return Err(conflict());
        }
        if stored.request_artifact.content_digest != stored.operation_digest
            || stored.request_artifact.size_bytes
                != u64::try_from(stored.canonical_bytes.len()).map_err(|_| conflict())?
        {
            return Err(conflict());
        }

        let stored_payload = parse_canonical_plan_approval_payload(&stored.canonical_bytes)?;
        let stored_canonical =
            canonical_approval_payload(&ApprovalDigestPayload::Plan(stored_payload.clone()))?;
        if stored_canonical.canonical_bytes != stored.canonical_bytes
            || stored_canonical.operation_digest != stored.operation_digest
            || stored_canonical.operation_digest != input.displayed_digest
        {
            return Err(conflict());
        }

        let task_id = TaskId::new(&stored_payload.task_id).map_err(|_| invalid_input())?;
        let current = self.store.current_state(&task_id)?;
        validate_resolution_current(&stored, &current, &input)?;

        let current_payload = plan_approval_payload(&current.binding)?;
        let current_canonical =
            canonical_approval_payload(&ApprovalDigestPayload::Plan(current_payload.clone()))?;
        if current_canonical.canonical_bytes != stored.canonical_bytes
            || current_canonical.operation_digest != stored.operation_digest
        {
            return Err(conflict());
        }

        let observed_at = self.clock.now_utc()?;
        if !approval_time_contains(
            &current_payload.requested_at,
            &current_payload.expires_at,
            &observed_at,
        )? {
            let requested_at = parse_policy_timestamp(&current_payload.requested_at)?;
            let expires_at = parse_policy_timestamp(&current_payload.expires_at)?;
            let observed_timestamp = parse_policy_timestamp(&observed_at)?;
            if observed_timestamp < requested_at {
                return Err(conflict());
            }
            if observed_timestamp < expires_at {
                return Err(conflict());
            }
            let expiry = build_plan_approval_expiry(
                &current,
                &input.approval_id,
                &current_payload.expires_at,
                &observed_at,
            )?;
            self.store
                .compare_and_expire(CompareAndExpirePlanApproval {
                    expected_approval: stored,
                    expected_current: current,
                    expiry,
                })?;
            return Err(conflict());
        }
        let operation_digest = current_canonical.operation_digest;
        let append = resolution_append(
            &current,
            &input.approval_id,
            input.action,
            &input.actor_id,
            &observed_at,
            &operation_digest,
        )?;
        let resolution = PlanApprovalResolution {
            approval_id: input.approval_id,
            action: input.action,
            actor_id: input.actor_id,
            expected_task_version: input.expected_task_version,
            operation_digest: operation_digest.clone(),
            resolved_at: observed_at.clone(),
            append,
        };
        self.store
            .compare_and_resolve(CompareAndResolvePlanApproval {
                expected_approval: stored,
                expected_current: current,
                resolution: resolution.clone(),
            })?;
        Ok(resolution)
    }
}

pub fn plan_approval_payload(
    binding: &PlanApprovalBindingInput,
) -> Result<PlanApprovalPayloadV1, PortError> {
    validate_binding_authority(binding)?;
    let payload = PlanApprovalPayloadV1 {
        schema: "approval-digest.v1".to_owned(),
        approval_type: "plan".to_owned(),
        task_id: binding.task_id.clone(),
        operation: PlanApprovalOperationV1 {
            plan: PlanApprovalPlanRefV1 {
                id: binding.plan_artifact_id.clone(),
                version: binding.plan_version,
                content_digest: binding.plan_digest.clone(),
            },
            base_commit: binding.base_commit.clone(),
            allowed_paths: binding.allowed_paths.clone(),
            planned_tool_digests: binding.planned_tool_digests.clone(),
            verification_profile_digest: binding.verification_profile_digest.clone(),
            risk_class: binding.risk_class.clone(),
        },
        policy_snapshot_digest: binding.policy_snapshot_digest.clone(),
        workspace_version: binding.workspace_version,
        requested_at: binding.requested_at.clone(),
        expires_at: binding.expires_at.clone(),
        nonce: binding_nonce(binding)?,
    };
    let canonical = canonical_approval_payload(&ApprovalDigestPayload::Plan(payload))?;
    parse_canonical_plan_approval_payload(&canonical.canonical_bytes)
}

fn validate_binding_authority(binding: &PlanApprovalBindingInput) -> Result<(), PortError> {
    if binding.agent_id.trim().is_empty() {
        return Err(invalid_input());
    }
    Sha256Digest::new(&binding.agent_manifest_digest).map_err(|_| invalid_input())?;
    Ok(())
}

fn validate_resolution_current(
    stored: &StoredPlanApproval,
    current: &PlanApprovalCurrentState,
    input: &ResolvePlanApprovalInput,
) -> Result<(), PortError> {
    validate_current_binding(current)?;
    if current.binding.task_version != input.expected_task_version
        || current.binding.actor_id != input.actor_id.as_str()
        || stored.binding != current.binding
    {
        Err(conflict())
    } else {
        Ok(())
    }
}

fn build_plan_approval_invalidation(
    current: &PlanApprovalCurrentState,
    approval_id: &ApprovalId,
    actor_id: &ActorId,
    reason_code: &str,
    invalidated_at: &str,
) -> Result<PlanApprovalInvalidation, PortError> {
    validate_label(reason_code)?;
    let task_id = TaskId::new(&current.binding.task_id).map_err(|_| conflict())?;
    let append = approval_fact_append(
        &task_id,
        current.task_state.sequence().get(),
        EventId::new(format!(
            "plan-approval:{}:invalidated",
            approval_id.as_str()
        ))
        .map_err(|_| conflict())?,
        "approval.invalidated",
        "user",
        actor_id.clone(),
        approval_id,
        invalidated_at,
        serde_json::json!({
            "approvalId": approval_id.as_str(),
            "reasonCode": reason_code,
        }),
    )?;
    Ok(PlanApprovalInvalidation {
        approval_id: approval_id.clone(),
        task_id,
        reason_code: reason_code.to_owned(),
        actor_id: actor_id.clone(),
        invalidated_at: invalidated_at.to_owned(),
        append,
    })
}

fn build_plan_approval_expiry(
    current: &PlanApprovalCurrentState,
    approval_id: &ApprovalId,
    expires_at: &str,
    expired_at: &str,
) -> Result<PlanApprovalExpiry, PortError> {
    if parse_policy_timestamp(expired_at)? < parse_policy_timestamp(expires_at)? {
        return Err(conflict());
    }
    let task_id = TaskId::new(&current.binding.task_id).map_err(|_| conflict())?;
    let append = approval_fact_append(
        &task_id,
        current.task_state.sequence().get(),
        EventId::new(format!("plan-approval:{}:expired", approval_id.as_str()))
            .map_err(|_| conflict())?,
        "approval.expired",
        "core",
        ActorId::new("core").map_err(|_| conflict())?,
        approval_id,
        expired_at,
        serde_json::json!({
            "approvalId": approval_id.as_str(),
            "expiresAt": expires_at,
        }),
    )?;
    Ok(PlanApprovalExpiry {
        approval_id: approval_id.clone(),
        task_id,
        expired_at: expired_at.to_owned(),
        append,
    })
}

fn resolution_append(
    current: &PlanApprovalCurrentState,
    approval_id: &ApprovalId,
    action: PlanApprovalAction,
    actor_id: &ActorId,
    resolved_at: &str,
    operation_digest: &Sha256Digest,
) -> Result<AppendOperation, PortError> {
    let (event_type, guard, explicit_phase) = match action {
        PlanApprovalAction::Approve => ("plan.approved", Some("plan_approval_digest_valid"), None),
        PlanApprovalAction::Reject => ("task.cancelled", None, None),
        PlanApprovalAction::Revise => (
            "plan.revision.requested",
            Some("user_feedback_present"),
            None,
        ),
        PlanApprovalAction::Reopen => (
            "plan.discussion.reopened",
            Some("user_feedback_present"),
            Some(Phase::CrossReview),
        ),
        PlanApprovalAction::AddOrReplaceAgent => (
            "plan.roster_change.requested",
            Some("user_feedback_present"),
            Some(Phase::ContextBuild),
        ),
    };
    let event_type = WorkflowEvent::new(event_type).map_err(|_| conflict())?;
    let mut guards = GuardEvaluations::new();
    if let Some(guard) = guard {
        guards.insert(GuardName::new(guard).map_err(|_| conflict())?, true);
    }
    let state = if let Some(phase) = explicit_phase {
        WorkflowState::new(
            phase,
            Condition::Active,
            OperationState::None,
            Sequence::new(
                current
                    .task_state
                    .sequence()
                    .get()
                    .checked_add(1)
                    .ok_or_else(conflict)?,
            ),
            current.task_state.workspace_version(),
            current.task_state.fencing_token(),
        )
        .map_err(|_| conflict())?
    } else {
        *reduce(&current.task_state, &event_type, &guards)
            .map_err(|_| conflict())?
            .state()
    };
    let task_id = TaskId::new(&current.binding.task_id).map_err(|_| conflict())?;
    Ok(AppendOperation {
        stream_id: StreamId::new(task_id.as_str()).map_err(|_| conflict())?,
        expected_version: current.task_state.sequence(),
        events: vec![NewEvent {
            event_id: EventId::new(format!("plan-approval:{}:resolution", approval_id.as_str()))
                .map_err(|_| conflict())?,
            event_type,
            schema_version: 1,
            actor_type: "user".to_owned(),
            actor_id: actor_id.clone(),
            observation_class: "user_asserted".to_owned(),
            payload: serde_json::json!({
                "approvalId": approval_id.as_str(),
                "action": action,
                "operationDigest": operation_digest.as_str(),
            }),
            metadata: serde_json::json!({}),
            causation_id: None,
            correlation_id: approval_id.as_str().to_owned(),
            created_at: resolved_at.to_owned(),
        }],
        projection_changes: vec![ProjectionChange::TaskState {
            task_id,
            state,
            updated_at: resolved_at.to_owned(),
        }],
    })
}

#[allow(clippy::too_many_arguments)]
fn approval_fact_append(
    task_id: &TaskId,
    expected_version: u64,
    event_id: EventId,
    event_type: &str,
    actor_type: &str,
    actor_id: ActorId,
    approval_id: &ApprovalId,
    occurred_at: &str,
    payload: serde_json::Value,
) -> Result<AppendOperation, PortError> {
    if occurred_at.trim().is_empty() {
        return Err(invalid_input());
    }
    let observation_class = match actor_type {
        "user" => "user_asserted",
        "core" => "core_observed",
        _ => return Err(conflict()),
    };
    Ok(AppendOperation {
        stream_id: StreamId::new(task_id.as_str()).map_err(|_| conflict())?,
        expected_version: local_agent_terminal_domain::Sequence::new(expected_version),
        events: vec![NewEvent {
            event_id,
            event_type: WorkflowEvent::new(event_type).map_err(|_| conflict())?,
            schema_version: 1,
            actor_type: actor_type.to_owned(),
            actor_id,
            observation_class: observation_class.to_owned(),
            payload,
            metadata: serde_json::json!({}),
            causation_id: None,
            correlation_id: approval_id.as_str().to_owned(),
            created_at: occurred_at.to_owned(),
        }],
        projection_changes: Vec::new(),
    })
}

fn validate_current_binding(current: &PlanApprovalCurrentState) -> Result<(), PortError> {
    if current.phase != current.task_state.phase()
        || current.task_state.sequence().get() != current.binding.task_version
        || current.task_state.workspace_version().get() != current.binding.workspace_version
        || current.task_state.fencing_token().get().checked_add(1)
            != Some(current.binding.fencing_epoch)
        || current.task_state.phase() != Phase::AwaitingPlanApproval
        || current.binding.task_id.trim().is_empty()
    {
        Err(conflict())
    } else {
        Ok(())
    }
}

pub fn canonical_plan_approval_payload(
    binding: &PlanApprovalBindingInput,
) -> Result<CanonicalApprovalPayload, PortError> {
    canonical_approval_payload(&ApprovalDigestPayload::Plan(plan_approval_payload(
        binding,
    )?))
}

pub fn parse_canonical_plan_approval_payload(
    raw: &[u8],
) -> Result<PlanApprovalPayloadV1, PortError> {
    let raw = std::str::from_utf8(raw).map_err(|_| invalid_input())?;
    match parse_canonical_approval_payload(raw)? {
        ApprovalDigestPayload::Plan(payload) => Ok(payload),
        ApprovalDigestPayload::Tool(_) | ApprovalDigestPayload::PolicyException(_) => {
            Err(invalid_input())
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PlanApprovalBindingNonceInputV1<'a> {
    schema: &'static str,
    repository_fingerprint: &'a str,
    actor_id: &'a str,
    agent_id: &'a str,
    agent_manifest_digest: &'a str,
    expected_task_sequence: u64,
    reserved_fencing_epoch: u64,
}

fn binding_nonce(binding: &PlanApprovalBindingInput) -> Result<String, PortError> {
    Sha256Digest::new(&binding.repository_fingerprint).map_err(|_| invalid_input())?;
    ActorId::new(&binding.actor_id).map_err(|_| invalid_input())?;
    if binding.fencing_epoch == 0 || binding.fencing_epoch > MAX_SAFE_INTEGER {
        return Err(invalid_input());
    }
    let input = PlanApprovalBindingNonceInputV1 {
        schema: BINDING_NONCE_SCHEMA,
        repository_fingerprint: &binding.repository_fingerprint,
        actor_id: &binding.actor_id,
        agent_id: &binding.agent_id,
        agent_manifest_digest: &binding.agent_manifest_digest,
        expected_task_sequence: binding.task_version,
        reserved_fencing_epoch: binding.fencing_epoch,
    };
    let value = serde_json::to_value(input).map_err(|_| invalid_input())?;
    let canonical = serde_json_canonicalizer::to_vec(&value).map_err(|_| invalid_input())?;
    sha256_digest(&canonical)
        .strip_prefix("sha256:")
        .map(str::to_owned)
        .ok_or_else(invalid_input)
}

fn digest_bytes(bytes: &[u8]) -> Result<Sha256Digest, PortError> {
    Sha256Digest::new(sha256_digest(bytes)).map_err(|_| integrity_failure())
}

fn validate_label(value: &str) -> Result<(), PortError> {
    if value.trim().is_empty() || value.len() > 256 || value.contains('\0') {
        Err(invalid_input())
    } else {
        Ok(())
    }
}

fn invalid_input() -> PortError {
    PortError::failure(
        SafeErrorClassification::InvalidInput,
        Retryability::NonRetryable,
    )
}

fn conflict() -> PortError {
    PortError::failure(
        SafeErrorClassification::Conflict,
        Retryability::NonRetryable,
    )
}

fn integrity_failure() -> PortError {
    PortError::failure(
        SafeErrorClassification::IntegrityFailure,
        Retryability::NonRetryable,
    )
}

fn not_found() -> PortError {
    PortError::failure(
        SafeErrorClassification::NotFound,
        Retryability::NonRetryable,
    )
}
