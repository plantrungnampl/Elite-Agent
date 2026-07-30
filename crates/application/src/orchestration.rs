use local_agent_terminal_domain::{PolicyEffect, PolicyRequest, Timestamp};
use time::format_description::well_known::Rfc3339;
use time::{Duration, OffsetDateTime};

use crate::{
    approval::{
        ApprovalDigestPayload, ToolApprovalPayloadV1, ToolApprovalPublication, ToolApprovalRequest,
        ToolApprovalRequestPublisher,
    },
    authority::resource_class_is_at_least,
    canonical_approval_payload, canonical_policy_binding_digest, canonical_tool_request,
    parse_policy_timestamp,
    tool::{logical_capability, process_approval_operation},
    ApprovalId, ApprovalRequestDto, ArtifactId, Clock, IdGenerator, ImmutableToolRequest,
    PolicyDecision, PolicyDecisionId, PolicyDecisionStore, PolicyEvaluator,
    PolicyRequestBindingDigest, PortError, RecordedPolicyDecision, Retryability,
    SafeErrorClassification, ToolExecutionId, ToolRequest, ToolRequestBindingDigest,
};

const TOOL_APPROVAL_LIFETIME_MINUTES: i64 = 15;

pub fn policy_request_for_tool(request: &ToolRequest, evaluated_at: Timestamp) -> PolicyRequest {
    let binding = request.process().process().binding();
    let policy = request.policy();
    PolicyRequest {
        task_id: binding.task_id().clone(),
        actor: policy.actor().clone(),
        action: policy.action().clone(),
        resource: policy.resource().clone(),
        task_risk: policy.task_risk(),
        workflow_phase: binding.workflow_phase().as_str().to_owned(),
        purpose: policy.purpose().to_owned(),
        policy_snapshot_digest: policy.policy_snapshot_digest().clone(),
        evaluated_at,
    }
}

pub trait ToolRequestPublisher: Send + Sync {
    fn publish(&self, request: &ImmutableToolRequest) -> Result<ArtifactId, PortError>;
}

pub struct ToolExecutionOrchestration<'a> {
    publisher: &'a dyn ToolRequestPublisher,
    clock: &'a dyn Clock,
    policies: &'a dyn PolicyEvaluator,
    policy_decisions: &'a dyn PolicyDecisionStore,
    ids: &'a dyn IdGenerator,
    approval_requests: &'a dyn ToolApprovalRequestPublisher,
}

impl<'a> ToolExecutionOrchestration<'a> {
    pub const fn new(
        publisher: &'a dyn ToolRequestPublisher,
        clock: &'a dyn Clock,
        policies: &'a dyn PolicyEvaluator,
        policy_decisions: &'a dyn PolicyDecisionStore,
        ids: &'a dyn IdGenerator,
        approval_requests: &'a dyn ToolApprovalRequestPublisher,
    ) -> Self {
        Self {
            publisher,
            clock,
            policies,
            policy_decisions,
            ids,
            approval_requests,
        }
    }

    pub fn execute(&self, request: ToolRequest) -> Result<PreEffectOutcome, PortError> {
        let immutable = canonical_tool_request(&request)?;
        let request_artifact_id = self.publisher.publish(&immutable)?;
        let requested_at = self.clock.now_utc()?;
        let evaluated_at = parse_policy_timestamp(&requested_at)?;
        let policy_request = policy_request_for_tool(&request, evaluated_at);
        let policy_request_binding_digest = canonical_policy_binding_digest(&policy_request)?;
        let decision = self.policies.evaluate(policy_request.clone())?;
        validate_policy_decision(&policy_request, &decision)?;
        let expected_decision_id = PolicyDecisionId::from_decision(&decision);
        let effect = decision.draft.effect();
        let policy_expires_at = decision.draft.expires_at();
        let recorded_decision_id = self.policy_decisions.record(RecordedPolicyDecision {
            decision,
            recorded_at: evaluated_at,
        })?;
        if recorded_decision_id != expected_decision_id {
            return Err(integrity_failure());
        }

        match effect {
            PolicyEffect::Allow => Ok(PreEffectOutcome::Allowed(PreEffectReady {
                execution_id: request.execution_id().clone(),
                request_artifact_id,
                request_binding_digest: immutable.binding_digest().clone(),
                policy_decision_id: recorded_decision_id,
            })),
            PolicyEffect::Deny | PolicyEffect::AllowWithRedaction => Ok(PreEffectOutcome::Denied {
                policy_decision_id: recorded_decision_id,
            }),
            PolicyEffect::RequireApproval => self.request_approval(
                &request,
                &immutable,
                request_artifact_id,
                recorded_decision_id,
                policy_request_binding_digest,
                &requested_at,
                policy_expires_at,
            ),
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn request_approval(
        &self,
        request: &ToolRequest,
        immutable: &ImmutableToolRequest,
        tool_request_artifact_id: ArtifactId,
        policy_decision_id: PolicyDecisionId,
        policy_request_binding_digest: PolicyRequestBindingDigest,
        requested_at: &str,
        policy_expires_at: Option<Timestamp>,
    ) -> Result<PreEffectOutcome, PortError> {
        let candidate = self.new_approval_request(
            request,
            immutable,
            tool_request_artifact_id.clone(),
            policy_decision_id,
            policy_request_binding_digest.clone(),
            requested_at,
            policy_expires_at,
        )?;
        let publication = self
            .approval_requests
            .publish_or_replay(candidate.clone())?;
        let published = match publication {
            ToolApprovalPublication::Created(published) => {
                if published != candidate {
                    return Err(integrity_failure());
                }
                published
            }
            ToolApprovalPublication::Replayed(published) => published,
        };
        validate_published_approval(
            request,
            immutable,
            &tool_request_artifact_id,
            &policy_request_binding_digest,
            &published,
        )?;
        Ok(PreEffectOutcome::ApprovalRequired(approval_dto(
            request, &published,
        )?))
    }

    #[allow(clippy::too_many_arguments)]
    fn new_approval_request(
        &self,
        request: &ToolRequest,
        immutable: &ImmutableToolRequest,
        tool_request_artifact_id: ArtifactId,
        policy_decision_id: PolicyDecisionId,
        policy_request_binding_digest: PolicyRequestBindingDigest,
        requested_at: &str,
        policy_expires_at: Option<Timestamp>,
    ) -> Result<ToolApprovalRequest, PortError> {
        let approval_id = ApprovalId::new(self.ids.next_id()?)?;
        let approval_artifact_id =
            ArtifactId::new(self.ids.next_id()?).map_err(|_| invalid_input())?;
        let nonce = self.ids.next_id()?;
        let (requested_at, expires_at) = approval_window(requested_at, policy_expires_at)?;
        let binding = request.process().process().binding();
        let payload = ToolApprovalPayloadV1 {
            schema: "approval-digest.v1".to_owned(),
            approval_type: "tool".to_owned(),
            task_id: binding.task_id().as_str().to_owned(),
            operation: process_approval_operation(request.process())?,
            policy_snapshot_digest: request.policy().policy_snapshot_digest().to_string(),
            workspace_version: binding.workspace_version().get(),
            requested_at,
            expires_at,
            nonce,
        };
        ToolApprovalRequest::from_persisted(
            approval_id,
            approval_artifact_id,
            request.execution_id().clone(),
            policy_decision_id,
            policy_request_binding_digest,
            tool_request_artifact_id,
            immutable.binding_digest().clone(),
            payload,
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PreEffectOutcome {
    Allowed(PreEffectReady),
    Denied {
        policy_decision_id: PolicyDecisionId,
    },
    ApprovalRequired(ApprovalRequestDto),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreEffectReady {
    execution_id: ToolExecutionId,
    request_artifact_id: ArtifactId,
    request_binding_digest: ToolRequestBindingDigest,
    policy_decision_id: PolicyDecisionId,
}

impl PreEffectReady {
    pub const fn execution_id(&self) -> &ToolExecutionId {
        &self.execution_id
    }

    pub const fn request_artifact_id(&self) -> &ArtifactId {
        &self.request_artifact_id
    }

    pub const fn request_binding_digest(&self) -> &ToolRequestBindingDigest {
        &self.request_binding_digest
    }

    pub const fn policy_decision_id(&self) -> &PolicyDecisionId {
        &self.policy_decision_id
    }
}

fn validate_policy_decision(
    expected: &PolicyRequest,
    decision: &PolicyDecision,
) -> Result<(), PortError> {
    let echoed = decision.draft.request();
    if echoed.task_id != expected.task_id
        || echoed.actor != expected.actor
        || echoed.action != expected.action
        || echoed.resource.capability != expected.resource.capability
        || echoed.resource.content_digest != expected.resource.content_digest
        || !resource_class_is_at_least(
            echoed.resource.resource_class,
            expected.resource.resource_class,
        )
        || echoed.task_risk != expected.task_risk
        || echoed.workflow_phase != expected.workflow_phase
        || echoed.purpose != expected.purpose
        || echoed.policy_snapshot_digest != expected.policy_snapshot_digest
        || echoed.evaluated_at != expected.evaluated_at
    {
        return Err(integrity_failure());
    }
    Ok(())
}

fn validate_published_approval(
    request: &ToolRequest,
    immutable: &ImmutableToolRequest,
    tool_request_artifact_id: &ArtifactId,
    policy_request_binding_digest: &PolicyRequestBindingDigest,
    published: &ToolApprovalRequest,
) -> Result<(), PortError> {
    let rebound = crate::bind_tool_approval_payload(published.payload().clone(), request.process())
        .map_err(|_| integrity_failure())?;
    let canonical =
        canonical_approval_payload(&ApprovalDigestPayload::Tool(published.payload().clone()))
            .map_err(|_| integrity_failure())?;
    if published.execution_id() != request.execution_id()
        || published.tool_request_artifact_id() != tool_request_artifact_id
        || published.tool_request_binding_digest() != immutable.binding_digest()
        || published.policy_request_binding_digest() != policy_request_binding_digest
        || published.payload().policy_snapshot_digest
            != request.policy().policy_snapshot_digest().as_str()
        || rebound.payload() != published.payload()
        || canonical != *published.canonical_payload()
    {
        return Err(integrity_failure());
    }
    Ok(())
}

fn approval_window(
    requested_at: &str,
    policy_expires_at: Option<Timestamp>,
) -> Result<(String, String), PortError> {
    let requested_at =
        OffsetDateTime::parse(requested_at, &Rfc3339).map_err(|_| invalid_input())?;
    let lifetime_expires_at = requested_at
        .checked_add(Duration::minutes(TOOL_APPROVAL_LIFETIME_MINUTES))
        .ok_or_else(invalid_input)?;
    let expires_at = policy_expires_at
        .map(|expires_at| {
            OffsetDateTime::from_unix_timestamp(expires_at.unix_seconds())
                .map_err(|_| invalid_input())
        })
        .transpose()?
        .map_or(lifetime_expires_at, |expires_at| {
            expires_at.min(lifetime_expires_at)
        });
    if expires_at <= requested_at {
        return Err(invalid_input());
    }
    let requested_at = requested_at
        .to_offset(time::UtcOffset::UTC)
        .format(&Rfc3339)
        .map_err(|_| invalid_input())?;
    let expires_at = expires_at
        .to_offset(time::UtcOffset::UTC)
        .format(&Rfc3339)
        .map_err(|_| invalid_input())?;
    Ok((requested_at, expires_at))
}

fn approval_dto(
    request: &ToolRequest,
    published: &ToolApprovalRequest,
) -> Result<ApprovalRequestDto, PortError> {
    let process = request.process().process();
    let argv = serde_json::to_string(process.argv()).map_err(|_| invalid_input())?;
    let operation = &published.payload().operation;
    let mut scopes = Vec::with_capacity(
        1 + request.process().expected_reads().len() + operation.expected_writes.len(),
    );
    scopes.push(operation.cwd_capability.clone());
    scopes.extend(
        request
            .process()
            .expected_reads()
            .iter()
            .map(logical_capability),
    );
    scopes.extend(operation.expected_writes.iter().cloned());
    Ok(ApprovalRequestDto {
        approval_id: published.approval_id().as_str().to_owned(),
        summary: format!(
            "{} {} {argv}",
            operation.tool,
            logical_capability(process.executable())
        ),
        operation_digest: published
            .canonical_payload()
            .operation_digest
            .as_str()
            .to_owned(),
        expires_at: published.payload().expires_at.clone(),
        scopes,
    })
}

fn invalid_input() -> PortError {
    PortError::failure(
        SafeErrorClassification::InvalidInput,
        Retryability::NonRetryable,
    )
}

fn integrity_failure() -> PortError {
    PortError::failure(
        SafeErrorClassification::IntegrityFailure,
        Retryability::NonRetryable,
    )
}
