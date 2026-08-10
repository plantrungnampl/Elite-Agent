use std::collections::{BTreeMap, BTreeSet};

use local_agent_terminal_application::{
    ContextArtifactKind, ContextBuildPolicy, DisclosureChannel, DisclosurePolicyEvaluator,
    DisclosureRequest, ImmutableContextArtifact, PolicyDecisionId, PolicyDecisionStore, PortError,
    RecordedPolicyDecision, Retryability, SafeErrorClassification,
};
use local_agent_terminal_domain::{
    CapabilityRef, ContextPackageDescriptor, ContextPackageMember, Disclosure, DisclosureKind,
    EvidenceCitation, EvidenceFreshness, PolicyAction, PolicyEffect, PolicyRequest, PolicyResource,
    Sha256Digest,
};
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::{ByteTokenV1, PackageSegment, RoleBudgetAllocation};

#[derive(Debug, Clone)]
pub struct ContextPackageItem {
    member_id: String,
    segment: PackageSegment,
    content: String,
    citation: Option<EvidenceCitation>,
    disclosure: Disclosure,
    policy_decision_ids: Vec<String>,
    provenance: Vec<String>,
    redaction_report_ids: Vec<String>,
}

impl ContextPackageItem {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        member_id: &str,
        segment: PackageSegment,
        content: String,
        citation: Option<EvidenceCitation>,
        disclosure: Disclosure,
        mut policy_decision_ids: Vec<String>,
        mut provenance: Vec<String>,
        mut redaction_report_ids: Vec<String>,
    ) -> Result<Self, PortError> {
        policy_decision_ids.sort();
        provenance.sort();
        redaction_report_ids.sort();
        if !valid_label(member_id)
            || content.is_empty()
            || content.contains('\0')
            || policy_decision_ids.is_empty()
            || policy_decision_ids.iter().any(|value| !valid_label(value))
            || policy_decision_ids
                .windows(2)
                .any(|pair| pair[0] == pair[1])
            || provenance.is_empty()
            || provenance.iter().any(|value| !valid_label(value))
            || provenance.windows(2).any(|pair| pair[0] == pair[1])
            || redaction_report_ids.iter().any(|value| !valid_label(value))
            || redaction_report_ids
                .windows(2)
                .any(|pair| pair[0] == pair[1])
            || (segment == PackageSegment::Evidence && citation.is_none())
            || disclosure.kind() == DisclosureKind::Denied
            || !redaction_complete(&disclosure, &redaction_report_ids)
        {
            return Err(invalid());
        }
        Ok(Self {
            member_id: member_id.to_owned(),
            segment,
            content,
            citation,
            disclosure,
            policy_decision_ids,
            provenance,
            redaction_report_ids,
        })
    }
}

pub struct ContextPackageBuildRequest {
    pub descriptor: ContextPackageDescriptor,
    pub policy: ContextBuildPolicy,
    pub items: Vec<ContextPackageItem>,
}

pub struct ContextPackageBuilder<'a> {
    disclosures: &'a dyn DisclosurePolicyEvaluator,
    policy_decisions: &'a dyn PolicyDecisionStore,
}

impl<'a> ContextPackageBuilder<'a> {
    pub const fn new(
        disclosures: &'a dyn DisclosurePolicyEvaluator,
        policy_decisions: &'a dyn PolicyDecisionStore,
    ) -> Self {
        Self {
            disclosures,
            policy_decisions,
        }
    }

    pub fn build(
        &self,
        request: ContextPackageBuildRequest,
    ) -> Result<BuiltContextPackage, PortError> {
        if request.descriptor.task_id() != &request.policy.task_id
            || request.descriptor.agent_id() != request.policy.actor.agent_id
            || request.descriptor.versions().tokenizer() != "byte-token-v1"
        {
            return Err(invalid());
        }
        let mut member_ids = BTreeSet::new();
        if request
            .items
            .iter()
            .any(|item| !member_ids.insert(item.member_id.as_str()))
        {
            return Err(invalid());
        }

        let allocation =
            RoleBudgetAllocation::new(request.descriptor.role(), request.descriptor.budget())?;
        let mut segment_usage = BTreeMap::<PackageSegment, u64>::new();
        let mut retained = Vec::new();
        for item in request.items {
            let units = ByteTokenV1::units(&item.content);
            let used = segment_usage.get(&item.segment).copied().unwrap_or(0);
            if used.saturating_add(units) <= allocation.segment_limit(item.segment) {
                segment_usage.insert(item.segment, used.saturating_add(units));
                retained.push(item);
            }
        }

        let raw_bytes = loop {
            let bytes = canonical_package_bytes(&request.descriptor, &request.policy, &retained)?;
            if u64::try_from(bytes.len()).map_err(|_| budget_exceeded())?
                <= allocation.input_limit()
            {
                break bytes;
            }
            if retained.pop().is_none() {
                return Err(budget_exceeded());
            }
        };
        let original_digest = digest(&raw_bytes);
        let capability =
            CapabilityRef::artifact(request.descriptor.effective_content_artifact_id().clone())
                .map_err(|_| invalid())?;
        let policy_request = PolicyRequest {
            task_id: request.policy.task_id.clone(),
            actor: request.policy.actor.clone(),
            action: PolicyAction::new("context.final_package").map_err(|_| invalid())?,
            resource: PolicyResource {
                capability,
                content_digest: original_digest.clone(),
                resource_class: request.policy.resource_class,
            },
            task_risk: request.policy.task_risk,
            workflow_phase: request.policy.workflow_phase.clone(),
            purpose: request.policy.purpose.clone(),
            policy_snapshot_digest: request.policy.policy_snapshot_digest.clone(),
            evaluated_at: request.policy.evaluated_at,
        };
        let disclosure = self.disclosures.disclose(DisclosureRequest {
            policy_request: policy_request.clone(),
            channel: DisclosureChannel::FinalContextPackage,
            bytes: raw_bytes.clone(),
        })?;
        if disclosure.channel != DisclosureChannel::FinalContextPackage
            || disclosure.original_digest != original_digest
            || disclosure.decision.draft.request() != &policy_request
            || disclosure.approval_binding.is_some()
        {
            return Err(integrity());
        }
        if !matches!(
            disclosure.decision.draft.effect(),
            PolicyEffect::Allow | PolicyEffect::AllowWithRedaction
        ) {
            return Err(permission());
        }
        let expected_final_id = PolicyDecisionId::from_decision(&disclosure.decision);
        let final_policy_decision_id = self.policy_decisions.record(RecordedPolicyDecision {
            decision: disclosure.decision,
            recorded_at: request.policy.evaluated_at,
        })?;
        if final_policy_decision_id != expected_final_id {
            return Err(integrity());
        }
        let bytes = disclosure.effective_bytes.ok_or_else(integrity)?;
        let content_digest = disclosure.effective_digest.ok_or_else(integrity)?;
        if bytes != raw_bytes
            || content_digest != original_digest
            || digest(&bytes) != content_digest
            || u64::try_from(bytes.len()).map_err(|_| budget_exceeded())? > allocation.input_limit()
        {
            return Err(integrity());
        }

        let mut policy_decision_ids = retained
            .iter()
            .flat_map(|item| item.policy_decision_ids.iter().cloned())
            .collect::<Vec<_>>();
        policy_decision_ids.push(final_policy_decision_id.as_str().to_owned());
        policy_decision_ids.sort();
        policy_decision_ids.dedup();
        let members = retained
            .iter()
            .filter_map(|item| {
                item.citation.as_ref().map(|citation| {
                    ContextPackageMember::new(
                        &item.member_id,
                        request.policy.task_id.clone(),
                        citation.clone(),
                        item.disclosure.clone(),
                    )
                    .map_err(|_| integrity())
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        let artifact = ImmutableContextArtifact {
            artifact_id: request.descriptor.effective_content_artifact_id().clone(),
            task_id: request.policy.task_id,
            kind: ContextArtifactKind::ContextPackage,
            bytes: bytes.clone(),
            content_digest: content_digest.clone(),
        };
        Ok(BuiltContextPackage {
            used_input_units: u64::try_from(bytes.len()).map_err(|_| budget_exceeded())?,
            bytes,
            content_digest,
            artifact,
            policy_decision_ids,
            final_policy_decision_id,
            members,
        })
    }
}

pub struct BuiltContextPackage {
    bytes: Vec<u8>,
    content_digest: Sha256Digest,
    artifact: ImmutableContextArtifact,
    used_input_units: u64,
    policy_decision_ids: Vec<String>,
    final_policy_decision_id: PolicyDecisionId,
    members: Vec<ContextPackageMember>,
}

impl BuiltContextPackage {
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn content_digest(&self) -> &Sha256Digest {
        &self.content_digest
    }

    pub fn artifact(&self) -> &ImmutableContextArtifact {
        &self.artifact
    }

    pub const fn used_input_units(&self) -> u64 {
        self.used_input_units
    }

    pub fn policy_decision_ids(&self) -> &[String] {
        &self.policy_decision_ids
    }

    pub fn final_policy_decision_id(&self) -> &PolicyDecisionId {
        &self.final_policy_decision_id
    }

    pub fn members(&self) -> &[ContextPackageMember] {
        &self.members
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SerializedPackage<'a> {
    schema: &'static str,
    version: u8,
    package_id: &'a str,
    task_id: &'a str,
    agent_id: &'a str,
    role: &'a str,
    objective: &'a str,
    agent_manifest_artifact_id: &'a str,
    effective_content_artifact_id: &'a str,
    created_at_unix_seconds: i64,
    versions: SerializedVersions<'a>,
    budget: SerializedBudget,
    policy_snapshot_digest: &'a str,
    items: Vec<SerializedItem<'a>>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SerializedVersions<'a> {
    prompt_template: &'a str,
    retrieval_pipeline: &'a str,
    tokenizer: &'a str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SerializedBudget {
    max_tokens: u64,
    reserved_response_tokens: u64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SerializedItem<'a> {
    member_id: &'a str,
    segment: &'static str,
    content: &'a str,
    citation: Option<SerializedCitation<'a>>,
    disclosure: SerializedDisclosure<'a>,
    policy_decision_ids: &'a [String],
    provenance: &'a [String],
    redaction_report_ids: &'a [String],
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SerializedCitation<'a> {
    source: SerializedSource<'a>,
    range: Option<SerializedRange>,
    symbol: Option<&'a str>,
    freshness: &'static str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SerializedSource<'a> {
    project_id: &'a str,
    revision: &'a str,
    path_identity: &'a str,
    content_hash: &'a str,
}

#[derive(Serialize)]
struct SerializedRange {
    start: u32,
    end: u32,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SerializedDisclosure<'a> {
    kind: &'static str,
    stable_report_id: Option<&'a str>,
}

fn canonical_package_bytes(
    descriptor: &ContextPackageDescriptor,
    policy: &ContextBuildPolicy,
    items: &[ContextPackageItem],
) -> Result<Vec<u8>, PortError> {
    let mut canonical_items = items.iter().collect::<Vec<_>>();
    canonical_items.sort_by(|left, right| left.member_id.cmp(&right.member_id));
    let versions = descriptor.versions();
    let budget = descriptor.budget();
    let package = SerializedPackage {
        schema: "context-package.v1",
        version: 1,
        package_id: descriptor.package_id(),
        task_id: descriptor.task_id().as_str(),
        agent_id: descriptor.agent_id(),
        role: descriptor.role(),
        objective: descriptor.objective(),
        agent_manifest_artifact_id: descriptor.agent_manifest_artifact_id().as_str(),
        effective_content_artifact_id: descriptor.effective_content_artifact_id().as_str(),
        created_at_unix_seconds: descriptor.created_at().unix_seconds(),
        versions: SerializedVersions {
            prompt_template: versions.prompt_template(),
            retrieval_pipeline: versions.retrieval_pipeline(),
            tokenizer: versions.tokenizer(),
        },
        budget: SerializedBudget {
            max_tokens: budget.max_tokens(),
            reserved_response_tokens: budget.reserved_response_tokens(),
        },
        policy_snapshot_digest: policy.policy_snapshot_digest.as_str(),
        items: canonical_items
            .into_iter()
            .map(SerializedItem::from)
            .collect(),
    };
    let value = serde_json::to_value(package).map_err(|_| integrity())?;
    serde_json_canonicalizer::to_vec(&value).map_err(|_| integrity())
}

impl<'a> From<&'a ContextPackageItem> for SerializedItem<'a> {
    fn from(item: &'a ContextPackageItem) -> Self {
        Self {
            member_id: &item.member_id,
            segment: item.segment.as_str(),
            content: &item.content,
            citation: item.citation.as_ref().map(SerializedCitation::from),
            disclosure: SerializedDisclosure {
                kind: match item.disclosure.kind() {
                    DisclosureKind::Allowed => "allowed",
                    DisclosureKind::Redacted => "redacted",
                    DisclosureKind::Denied => "denied",
                },
                stable_report_id: item.disclosure.stable_report_id(),
            },
            policy_decision_ids: &item.policy_decision_ids,
            provenance: &item.provenance,
            redaction_report_ids: &item.redaction_report_ids,
        }
    }
}

impl<'a> From<&'a EvidenceCitation> for SerializedCitation<'a> {
    fn from(citation: &'a EvidenceCitation) -> Self {
        let source = citation.source();
        Self {
            source: SerializedSource {
                project_id: source.project_id().as_str(),
                revision: source.revision(),
                path_identity: source.path_identity(),
                content_hash: source.content_hash().as_str(),
            },
            range: citation.range().map(|range| SerializedRange {
                start: range.start(),
                end: range.end(),
            }),
            symbol: citation.symbol(),
            freshness: match citation.freshness() {
                EvidenceFreshness::Current => "current",
                EvidenceFreshness::Stale => "stale",
            },
        }
    }
}

fn redaction_complete(disclosure: &Disclosure, report_ids: &[String]) -> bool {
    match disclosure.kind() {
        DisclosureKind::Allowed => report_ids.is_empty(),
        DisclosureKind::Redacted => disclosure.stable_report_id().is_some_and(|report_id| {
            report_ids
                .binary_search_by(|id| id.as_str().cmp(report_id))
                .is_ok()
        }),
        DisclosureKind::Denied => false,
    }
}

fn digest(bytes: &[u8]) -> Sha256Digest {
    Sha256Digest::new(format!("sha256:{:x}", Sha256::digest(bytes)))
        .expect("SHA-256 formatting is valid")
}

fn valid_label(value: &str) -> bool {
    !value.trim().is_empty() && value.len() <= 1_024 && !value.contains('\0')
}

fn invalid() -> PortError {
    PortError::failure(
        SafeErrorClassification::InvalidInput,
        Retryability::NonRetryable,
    )
}

fn integrity() -> PortError {
    PortError::failure(
        SafeErrorClassification::IntegrityFailure,
        Retryability::NonRetryable,
    )
}

fn permission() -> PortError {
    PortError::failure(
        SafeErrorClassification::PermissionDenied,
        Retryability::NonRetryable,
    )
}

fn budget_exceeded() -> PortError {
    PortError::failure(
        SafeErrorClassification::StorageFull,
        Retryability::NonRetryable,
    )
}
