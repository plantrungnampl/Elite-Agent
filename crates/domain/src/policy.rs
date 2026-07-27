use std::collections::BTreeSet;
use std::fmt;

use crate::{CapabilityRef, Sha256Digest, TaskId, Timestamp, ValueError};

const MAX_IDENTIFIER_LENGTH: usize = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum PolicyEffect {
    Allow,
    Deny,
    RequireApproval,
    AllowWithRedaction,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrustTier {
    CoreAdapter,
    BrokeredProcess,
    IsolatedWorker,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActorLocality {
    Local,
    Cloud,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResourceClass {
    Public,
    InternalCode,
    Restricted,
    Secret,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaskRisk {
    Low,
    Medium,
    High,
    Critical,
}

macro_rules! policy_identifier {
    ($name:ident, $kind:literal) => {
        #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name(String);

        impl $name {
            pub fn new(value: impl Into<String>) -> Result<Self, ValueError> {
                let value = value.into();
                if !valid_identifier(&value) {
                    return Err(ValueError::Invalid { kind: $kind });
                }
                Ok(Self(value))
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }
        }
    };
}

policy_identifier!(PolicyAction, "policy action");
policy_identifier!(PolicyRuleId, "policy rule ID");
policy_identifier!(RedactionDirective, "redaction directive");

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PolicyVersion(u16);

impl PolicyVersion {
    pub fn new(value: u16) -> Result<Self, PolicyError> {
        if value != 1 {
            return Err(PolicyError::UnsupportedVersion(value));
        }
        Ok(Self(value))
    }

    pub const fn get(self) -> u16 {
        self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyActor {
    pub connection_id: String,
    pub agent_id: String,
    pub trust_tier: TrustTier,
    pub locality: ActorLocality,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyResource {
    pub capability: CapabilityRef,
    pub content_digest: Sha256Digest,
    pub resource_class: ResourceClass,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyRequest {
    pub task_id: TaskId,
    pub actor: PolicyActor,
    pub action: PolicyAction,
    pub resource: PolicyResource,
    pub task_risk: TaskRisk,
    pub workflow_phase: String,
    pub purpose: String,
    pub policy_snapshot_digest: Sha256Digest,
    pub evaluated_at: Timestamp,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MatchedPolicyRule {
    pub rule_id: PolicyRuleId,
    pub effect: PolicyEffect,
    pub redactions: Vec<RedactionDirective>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyDecisionDraft {
    request: PolicyRequest,
    policy_version: PolicyVersion,
    effect: PolicyEffect,
    rule_ids: Vec<PolicyRuleId>,
    redactions: Vec<RedactionDirective>,
    expires_at: Option<Timestamp>,
}

impl PolicyDecisionDraft {
    pub const fn request(&self) -> &PolicyRequest {
        &self.request
    }

    pub const fn policy_version(&self) -> PolicyVersion {
        self.policy_version
    }

    pub const fn effect(&self) -> PolicyEffect {
        self.effect
    }

    pub fn rule_ids(&self) -> Vec<&str> {
        self.rule_ids.iter().map(PolicyRuleId::as_str).collect()
    }

    pub fn redactions(&self) -> Vec<&str> {
        self.redactions
            .iter()
            .map(RedactionDirective::as_str)
            .collect()
    }

    pub const fn expires_at(&self) -> Option<Timestamp> {
        self.expires_at
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyError {
    UnsupportedVersion(u16),
}

impl fmt::Display for PolicyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedVersion(version) => {
                write!(formatter, "unsupported policy version {version}")
            }
        }
    }
}

impl std::error::Error for PolicyError {}

pub fn combine_policy_rules(
    request: PolicyRequest,
    policy_version: PolicyVersion,
    matches: Vec<MatchedPolicyRule>,
    expires_at: Option<Timestamp>,
) -> Result<PolicyDecisionDraft, PolicyError> {
    let mut rule_ids = BTreeSet::new();
    let mut redactions = BTreeSet::new();
    let mut effect = PolicyEffect::Allow;
    for matched in matches {
        effect = more_restrictive(effect, matched.effect);
        rule_ids.insert(matched.rule_id);
        redactions.extend(matched.redactions);
    }

    if !request_is_valid(&request)
        || rule_ids.is_empty()
        || expires_at.is_some_and(|expires_at| expires_at <= request.evaluated_at)
    {
        effect = PolicyEffect::Deny;
    }

    Ok(PolicyDecisionDraft {
        request,
        policy_version,
        effect,
        rule_ids: rule_ids.into_iter().collect(),
        redactions: redactions.into_iter().collect(),
        expires_at,
    })
}

fn valid_identifier(value: &str) -> bool {
    !value.trim().is_empty() && value.len() <= MAX_IDENTIFIER_LENGTH && !value.contains('\0')
}

fn request_is_valid(request: &PolicyRequest) -> bool {
    valid_identifier(request.task_id.as_str())
        && valid_identifier(&request.actor.connection_id)
        && valid_identifier(&request.actor.agent_id)
        && valid_identifier(request.action.as_str())
        && resource_is_valid(request)
        && valid_identifier(&request.workflow_phase)
        && !request.purpose.trim().is_empty()
        && request.purpose.len() <= 65_536
        && !request.purpose.contains('\0')
}

fn resource_is_valid(request: &PolicyRequest) -> bool {
    request.resource.capability.validate().is_ok()
        && request
            .resource
            .capability
            .worktree_task_id()
            .is_none_or(|task_id| task_id == &request.task_id)
}

fn more_restrictive(current: PolicyEffect, candidate: PolicyEffect) -> PolicyEffect {
    if policy_effect_rank(candidate) > policy_effect_rank(current) {
        candidate
    } else {
        current
    }
}

const fn policy_effect_rank(effect: PolicyEffect) -> u8 {
    match effect {
        PolicyEffect::Allow => 0,
        PolicyEffect::AllowWithRedaction => 1,
        PolicyEffect::RequireApproval => 2,
        PolicyEffect::Deny => 3,
    }
}
