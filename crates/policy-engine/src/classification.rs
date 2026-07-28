use local_agent_terminal_domain::{
    ActorLocality, MatchedPolicyRule, PolicyEffect, PolicyRequest, PolicyRuleId, PolicyVersion,
    RedactionDirective, ResourceClass, TrustTier,
};
use serde::Deserialize;

use crate::{invalid_input, PolicyBundleV1, PolicyDecision, PortError, Sha256Digest};

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum BundleEffect {
    Allow,
    Deny,
    RequireApproval,
    AllowWithRedaction,
}

impl BundleEffect {
    fn domain_effect(&self) -> PolicyEffect {
        match self {
            Self::Allow => PolicyEffect::Allow,
            Self::Deny => PolicyEffect::Deny,
            Self::RequireApproval => PolicyEffect::RequireApproval,
            Self::AllowWithRedaction => PolicyEffect::AllowWithRedaction,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum BundleLocality {
    Local,
    Cloud,
}

impl BundleLocality {
    fn matches(&self, locality: ActorLocality) -> bool {
        matches!(
            (self, locality),
            (Self::Local, ActorLocality::Local) | (Self::Cloud, ActorLocality::Cloud)
        )
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum BundleTrustTier {
    CoreAdapter,
    BrokeredProcess,
    IsolatedWorker,
}

impl BundleTrustTier {
    fn matches(&self, trust_tier: TrustTier) -> bool {
        matches!(
            (self, trust_tier),
            (Self::CoreAdapter, TrustTier::CoreAdapter)
                | (Self::BrokeredProcess, TrustTier::BrokeredProcess)
                | (Self::IsolatedWorker, TrustTier::IsolatedWorker)
        )
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum BundleResourceClass {
    Public,
    InternalCode,
    Restricted,
    Secret,
}

impl BundleResourceClass {
    fn matches(&self, resource_class: ResourceClass) -> bool {
        matches!(
            (self, resource_class),
            (Self::Public, ResourceClass::Public)
                | (Self::InternalCode, ResourceClass::InternalCode)
                | (Self::Restricted, ResourceClass::Restricted)
                | (Self::Secret, ResourceClass::Secret)
        )
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct PolicyRuleV1 {
    pub id: String,
    pub effect: BundleEffect,
    pub locality: Option<BundleLocality>,
    pub trust_tier: Option<BundleTrustTier>,
    pub resource_class: Option<BundleResourceClass>,
    pub action: Option<String>,
    #[serde(default)]
    pub redactions: Vec<String>,
    pub expires_at: Option<i64>,
}

impl PolicyBundleV1 {
    pub(crate) fn evaluate(&self, mut request: PolicyRequest) -> Result<PolicyDecision, PortError> {
        classify_trusted_metadata(&mut request);
        let mut matches = Vec::new();
        let mut expiry: Option<i64> = None;
        for rule in &self.rules {
            if !rule.matches(&request) {
                continue;
            }
            if let Some(rule_expiry) = rule.expires_at {
                expiry = Some(expiry.map_or(rule_expiry, |current| current.min(rule_expiry)));
            }
            matches.push(MatchedPolicyRule {
                rule_id: PolicyRuleId::new(rule.id.clone()).map_err(|_| invalid_input())?,
                effect: rule.effect.domain_effect(),
                redactions: rule
                    .redactions
                    .iter()
                    .cloned()
                    .map(RedactionDirective::new)
                    .collect::<Result<_, _>>()
                    .map_err(|_| invalid_input())?,
            });
        }

        let draft = local_agent_terminal_domain::combine_policy_rules(
            request,
            PolicyVersion::new(1).map_err(|_| invalid_input())?,
            matches,
            expiry.map(local_agent_terminal_domain::Timestamp::from_unix_seconds),
        )
        .map_err(|_| invalid_input())?;
        let operation_digest = operation_digest(draft.request())?;
        Ok(PolicyDecision {
            draft,
            operation_digest,
        })
    }
}

fn classify_trusted_metadata(request: &mut PolicyRequest) {
    let path = match &request.resource.capability {
        local_agent_terminal_domain::CapabilityRef::Source(source) => source.path(),
        local_agent_terminal_domain::CapabilityRef::Worktree(worktree) => worktree.path(),
        local_agent_terminal_domain::CapabilityRef::Artifact(_)
        | local_agent_terminal_domain::CapabilityRef::Toolchain(_) => return,
    };
    if is_secret_filename(path) {
        request.resource.resource_class = ResourceClass::Secret;
    }
}

fn is_secret_filename(path: &str) -> bool {
    let filename = path.rsplit(['/', '\\']).next().unwrap_or(path);
    let lowercase = filename.to_ascii_lowercase();
    lowercase == ".env"
        || lowercase.starts_with(".env.")
        || matches!(
            lowercase.as_str(),
            "id_rsa" | "credentials" | "credentials.json" | "private.key"
        )
        || [".pem", ".key", ".p12", ".pfx"]
            .iter()
            .any(|extension| lowercase.ends_with(extension))
}

impl PolicyRuleV1 {
    fn matches(&self, request: &PolicyRequest) -> bool {
        self.locality
            .as_ref()
            .is_none_or(|locality| locality.matches(request.actor.locality))
            && self
                .trust_tier
                .as_ref()
                .is_none_or(|trust_tier| trust_tier.matches(request.actor.trust_tier))
            && self.resource_class.as_ref().is_none_or(|resource_class| {
                resource_class.matches(request.resource.resource_class)
            })
            && self
                .action
                .as_ref()
                .is_none_or(|action| action == request.action.as_str())
    }
}

fn operation_digest(request: &PolicyRequest) -> Result<Sha256Digest, PortError> {
    let value = serde_json::json!({
        "taskId": request.task_id.as_str(),
        "actor": {
            "connectionId": request.actor.connection_id,
            "agentId": request.actor.agent_id,
            "trustTier": trust_tier_name(request.actor.trust_tier),
            "locality": locality_name(request.actor.locality),
        },
        "action": request.action.as_str(),
        "resource": {
            "capability": capability_value(&request.resource.capability),
            "contentDigest": request.resource.content_digest.as_str(),
            "resourceClass": resource_class_name(request.resource.resource_class),
        },
        "taskRisk": format!("{:?}", request.task_risk),
        "workflowPhase": request.workflow_phase,
        "purpose": request.purpose,
        "policySnapshotDigest": request.policy_snapshot_digest.as_str(),
        "evaluatedAt": request.evaluated_at.unix_seconds(),
    });
    let canonical = serde_json_canonicalizer::to_vec(&value).map_err(|_| invalid_input())?;
    Sha256Digest::new(crate::sha256_digest(&canonical)).map_err(|_| invalid_input())
}

fn capability_value(capability: &local_agent_terminal_domain::CapabilityRef) -> serde_json::Value {
    use local_agent_terminal_domain::CapabilityRef;

    match capability {
        CapabilityRef::Source(value) => serde_json::json!({
            "kind": "source",
            "revision": value.revision(),
            "path": value.path(),
        }),
        CapabilityRef::Artifact(value) => serde_json::json!({
            "kind": "artifact",
            "artifactId": value.artifact_id().as_str(),
        }),
        CapabilityRef::Worktree(value) => serde_json::json!({
            "kind": "worktree",
            "taskId": value.task_id().as_str(),
            "path": value.path(),
        }),
        CapabilityRef::Toolchain(value) => serde_json::json!({
            "kind": "toolchain",
            "name": value.name(),
        }),
    }
}

fn locality_name(value: ActorLocality) -> &'static str {
    match value {
        ActorLocality::Local => "local",
        ActorLocality::Cloud => "cloud",
    }
}

fn trust_tier_name(value: TrustTier) -> &'static str {
    match value {
        TrustTier::CoreAdapter => "core_adapter",
        TrustTier::BrokeredProcess => "brokered_process",
        TrustTier::IsolatedWorker => "isolated_worker",
    }
}

fn resource_class_name(value: ResourceClass) -> &'static str {
    match value {
        ResourceClass::Public => "public",
        ResourceClass::InternalCode => "internal_code",
        ResourceClass::Restricted => "restricted",
        ResourceClass::Secret => "secret",
    }
}
