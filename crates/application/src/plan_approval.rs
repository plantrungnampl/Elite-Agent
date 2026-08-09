use local_agent_terminal_domain::{ActorId, Phase, Sha256Digest, TaskId};
use serde::{Deserialize, Serialize};

use crate::{
    approval::approval_time_contains, canonical_approval_payload, canonical_json::sha256_digest,
    parse_canonical_approval_payload, ApprovalDigestPayload, ApprovalId, CanonicalApprovalPayload,
    Clock, PlanApprovalOperationV1, PlanApprovalPathScopeV1, PlanApprovalPayloadV1,
    PlanApprovalPlanRefV1, PortError, Retryability, SafeErrorClassification,
};

const BINDING_NONCE_SCHEMA: &str = "plan-approval-binding-nonce.v1";
const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;

#[derive(Debug, Clone, PartialEq, Eq)]
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
    pub actor_id: String,
    pub task_version: u64,
    pub fencing_epoch: u64,
    pub requested_at: String,
    pub expires_at: String,
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
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewPlanApproval {
    pub approval_id: ApprovalId,
    pub canonical_bytes: Vec<u8>,
    pub operation_digest: Sha256Digest,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredPlanApproval {
    pub approval_id: ApprovalId,
    pub state: PlanApprovalState,
    pub canonical_bytes: Vec<u8>,
    pub operation_digest: Sha256Digest,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlanApprovalCurrentState {
    pub phase: Phase,
    pub binding: PlanApprovalBindingInput,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlanApprovalResolution {
    pub approval_id: ApprovalId,
    pub action: PlanApprovalAction,
    pub actor_id: ActorId,
    pub expected_task_version: u64,
    pub operation_digest: Sha256Digest,
    pub resolved_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompareAndResolvePlanApproval {
    pub expected_approval: StoredPlanApproval,
    pub expected_current: PlanApprovalCurrentState,
    pub resolution: PlanApprovalResolution,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlanApprovalInvalidation {
    pub task_id: TaskId,
    pub reason_code: String,
}

pub trait PlanApprovalStore: Send + Sync {
    fn request(&self, approval: NewPlanApproval) -> Result<StoredPlanApproval, PortError>;
    fn reload(&self, approval_id: &ApprovalId) -> Result<Option<StoredPlanApproval>, PortError>;
    fn current_state(&self, task_id: &TaskId) -> Result<PlanApprovalCurrentState, PortError>;
    /// Atomically reloads the approval and current task authority, requires exact equality with
    /// both expected snapshots, and resolves the still-requested approval once. Any state,
    /// phase, binding, digest, version, actor, expiry, or prior-resolution mismatch is Conflict.
    fn compare_and_resolve(&self, command: CompareAndResolvePlanApproval) -> Result<(), PortError>;
    fn invalidate(&self, invalidation: PlanApprovalInvalidation) -> Result<u64, PortError>;
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
        if stored.approval_id != input.approval_id || stored.state != PlanApprovalState::Requested {
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
        if current.phase != Phase::AwaitingPlanApproval
            || current.binding.task_version != input.expected_task_version
            || current.binding.actor_id != input.actor_id.as_str()
        {
            return Err(conflict());
        }

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
            return Err(conflict());
        }
        let resolution = PlanApprovalResolution {
            approval_id: input.approval_id,
            action: input.action,
            actor_id: input.actor_id,
            expected_task_version: input.expected_task_version,
            operation_digest: current_canonical.operation_digest,
            resolved_at: observed_at,
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
        workspace_version: binding.task_version,
        requested_at: binding.requested_at.clone(),
        expires_at: binding.expires_at.clone(),
        nonce: binding_nonce(binding)?,
    };
    let canonical = canonical_approval_payload(&ApprovalDigestPayload::Plan(payload))?;
    parse_canonical_plan_approval_payload(&canonical.canonical_bytes)
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
        reserved_fencing_epoch: binding.fencing_epoch,
    };
    let value = serde_json::to_value(input).map_err(|_| invalid_input())?;
    let canonical = serde_json_canonicalizer::to_vec(&value).map_err(|_| invalid_input())?;
    sha256_digest(&canonical)
        .strip_prefix("sha256:")
        .map(str::to_owned)
        .ok_or_else(invalid_input)
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

fn not_found() -> PortError {
    PortError::failure(
        SafeErrorClassification::NotFound,
        Retryability::NonRetryable,
    )
}
