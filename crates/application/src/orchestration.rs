use local_agent_terminal_domain::{PolicyEffect, PolicyRequest, ResourceClass, Timestamp};

use crate::{
    canonical_tool_request, parse_policy_timestamp, ArtifactId, Clock, ImmutableToolRequest,
    PolicyDecision, PolicyDecisionId, PolicyDecisionStore, PolicyEvaluator, PortError,
    RecordedPolicyDecision, Retryability, SafeErrorClassification, ToolExecutionId, ToolRequest,
    ToolRequestBindingDigest,
};

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
}

impl<'a> ToolExecutionOrchestration<'a> {
    pub const fn new(
        publisher: &'a dyn ToolRequestPublisher,
        clock: &'a dyn Clock,
        policies: &'a dyn PolicyEvaluator,
        policy_decisions: &'a dyn PolicyDecisionStore,
    ) -> Self {
        Self {
            publisher,
            clock,
            policies,
            policy_decisions,
        }
    }

    pub fn execute(&self, request: ToolRequest) -> Result<PreEffectOutcome, PortError> {
        let immutable = canonical_tool_request(&request)?;
        let request_artifact_id = self.publisher.publish(&immutable)?;
        let evaluated_at = parse_policy_timestamp(&self.clock.now_utc()?)?;
        let policy_request = policy_request_for_tool(&request, evaluated_at);
        let decision = self.policies.evaluate(policy_request.clone())?;
        validate_policy_decision(&policy_request, &decision)?;
        let expected_decision_id = PolicyDecisionId::from_decision(&decision);
        let effect = decision.draft.effect();
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
            PolicyEffect::RequireApproval => Ok(PreEffectOutcome::ApprovalRequired {
                policy_decision_id: recorded_decision_id,
            }),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PreEffectOutcome {
    Allowed(PreEffectReady),
    Denied {
        policy_decision_id: PolicyDecisionId,
    },
    ApprovalRequired {
        policy_decision_id: PolicyDecisionId,
    },
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

const fn resource_class_is_at_least(candidate: ResourceClass, expected: ResourceClass) -> bool {
    resource_class_rank(candidate) >= resource_class_rank(expected)
}

const fn resource_class_rank(resource_class: ResourceClass) -> u8 {
    match resource_class {
        ResourceClass::Public => 0,
        ResourceClass::InternalCode => 1,
        ResourceClass::Restricted => 2,
        ResourceClass::Secret => 3,
    }
}

fn integrity_failure() -> PortError {
    PortError::failure(
        SafeErrorClassification::IntegrityFailure,
        Retryability::NonRetryable,
    )
}
