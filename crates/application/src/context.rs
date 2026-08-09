use local_agent_terminal_domain::{
    ArtifactId, CapabilityRef, ContextPackageArtifact, ContextPackageBinding,
    ContextPackageDescriptor, ContextPackageMember, Disclosure, DisclosureKind, EvidenceFreshness,
    LineRange, PolicyAction, PolicyActor, PolicyEffect, PolicyRequest, PolicyResource, ProjectId,
    ResourceClass, Sha256Digest, SourceIdentity, TaskId, TaskRisk, Timestamp,
};
use serde::Serialize;

use crate::{
    canonical_json::sha256_digest, DisclosureChannel, DisclosurePolicyEvaluator, DisclosureRequest,
    PolicyDecisionId, PolicyDecisionSet, PolicyDecisionStore, PortError, RecordedPolicyDecision,
    Retryability, SafeErrorClassification,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceSnapshotRequest {
    pub project_id: ProjectId,
    pub task_id: TaskId,
    pub revision: String,
    pub repository_fingerprint: Sha256Digest,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceSnapshotItem {
    pub member_id: String,
    pub content_artifact_id: ArtifactId,
    pub identity: SourceIdentity,
    pub metadata: Vec<u8>,
    pub content: Vec<u8>,
    pub line_range: Option<LineRange>,
    pub symbol: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceSnapshot {
    pub request: SourceSnapshotRequest,
    pub items: Vec<SourceSnapshotItem>,
}

pub trait RepositoryContextSource: Send + Sync {
    fn snapshot(&self, request: SourceSnapshotRequest) -> Result<SourceSnapshot, PortError>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContextSourceRecord {
    pub task_id: TaskId,
    pub identity: SourceIdentity,
    pub effective_metadata: Vec<u8>,
    pub metadata_policy_decision_id: PolicyDecisionId,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContextChunkRecord {
    pub task_id: TaskId,
    pub member_id: String,
    pub identity: SourceIdentity,
    pub artifact_id: ArtifactId,
    pub content_digest: Sha256Digest,
    pub content_policy_decision_id: PolicyDecisionId,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContextPackageRecord {
    pub binding: ContextPackageBinding,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContextPackagePersistence {
    pub package: ContextPackageRecord,
    pub policy_decision_ids: Vec<PolicyDecisionId>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContextQuery {
    pub task_id: TaskId,
    pub query_id: String,
    pub terms: Vec<String>,
    pub max_items: u32,
    pub max_tokens: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RetrievedContextItem {
    pub member_id: String,
    pub artifact_id: ArtifactId,
    pub identity: SourceIdentity,
    pub bytes: Vec<u8>,
    pub line_range: Option<LineRange>,
    pub symbol: Option<String>,
}

pub trait ContextStore: Send + Sync {
    fn persist_source(&self, source: ContextSourceRecord) -> Result<(), PortError>;
    fn persist_chunk(&self, chunk: ContextChunkRecord) -> Result<(), PortError>;
    fn query(&self, query: ContextQuery) -> Result<Vec<RetrievedContextItem>, PortError>;
    /// Atomically persists the package row and its complete policy-decision relation set.
    /// Implementations must commit both together or leave neither visible.
    fn persist_package_with_policy_decisions(
        &self,
        persistence: ContextPackagePersistence,
    ) -> Result<(), PortError>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContextArtifactKind {
    SourceChunk,
    ContextPackage,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImmutableContextArtifact {
    pub artifact_id: ArtifactId,
    pub task_id: TaskId,
    pub kind: ContextArtifactKind,
    pub bytes: Vec<u8>,
    pub content_digest: Sha256Digest,
}

pub trait ContextArtifactPublisher: Send + Sync {
    fn publish(&self, artifact: ImmutableContextArtifact) -> Result<(), PortError>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContextBuildPolicy {
    pub task_id: TaskId,
    pub actor: PolicyActor,
    pub resource_class: ResourceClass,
    pub task_risk: TaskRisk,
    pub workflow_phase: String,
    pub purpose: String,
    pub policy_snapshot_digest: Sha256Digest,
    pub evaluated_at: Timestamp,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContextPackageDraft {
    pub descriptor: ContextPackageDescriptor,
    pub artifact_id: ArtifactId,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BuildInitialContextRequest {
    pub snapshot: SourceSnapshotRequest,
    pub policy: ContextBuildPolicy,
    pub package: ContextPackageDraft,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueryContextRequest {
    pub query: ContextQuery,
    pub policy: ContextBuildPolicy,
    pub package: ContextPackageDraft,
}

pub struct BuildInitialContext<'a> {
    source: &'a dyn RepositoryContextSource,
    store: &'a dyn ContextStore,
    artifacts: &'a dyn ContextArtifactPublisher,
    disclosures: &'a dyn DisclosurePolicyEvaluator,
    policy_decisions: &'a dyn PolicyDecisionStore,
}

impl<'a> BuildInitialContext<'a> {
    pub const fn new(
        source: &'a dyn RepositoryContextSource,
        store: &'a dyn ContextStore,
        artifacts: &'a dyn ContextArtifactPublisher,
        disclosures: &'a dyn DisclosurePolicyEvaluator,
        policy_decisions: &'a dyn PolicyDecisionStore,
    ) -> Self {
        Self {
            source,
            store,
            artifacts,
            disclosures,
            policy_decisions,
        }
    }

    pub fn execute(
        &self,
        request: BuildInitialContextRequest,
    ) -> Result<ContextPackageBinding, PortError> {
        validate_package_task(&request.package, &request.snapshot.task_id)?;
        if request.policy.task_id != request.snapshot.task_id {
            return Err(invalid_input());
        }
        let snapshot = self.source.snapshot(request.snapshot.clone())?;
        validate_snapshot(&request.snapshot, &snapshot)?;

        let mut members = Vec::new();
        let mut decision_ids = Vec::new();
        for item in snapshot.items {
            if let Some(member) = self.persist_allowed_item(
                &request.snapshot.task_id,
                &request.policy,
                item,
                &mut decision_ids,
            )? {
                members.push(member);
            }
        }
        finalize_package(
            self.store,
            self.artifacts,
            self.disclosures,
            self.policy_decisions,
            request.policy,
            request.package,
            members,
            decision_ids,
        )
    }

    fn persist_allowed_item(
        &self,
        task_id: &TaskId,
        policy: &ContextBuildPolicy,
        item: SourceSnapshotItem,
        decision_ids: &mut Vec<PolicyDecisionId>,
    ) -> Result<Option<ContextPackageMember>, PortError> {
        validate_source_content(&item.identity, &item.content)?;
        let metadata = disclose_source(
            self.disclosures,
            self.policy_decisions,
            policy,
            &item.identity,
            DisclosureChannel::IndexMetadata,
            item.metadata,
        )?;
        decision_ids.push(metadata.decision_id);
        let Some(metadata) = metadata.disclosed else {
            return Ok(None);
        };

        let content = disclose_source(
            self.disclosures,
            self.policy_decisions,
            policy,
            &item.identity,
            DisclosureChannel::IndexContent,
            item.content,
        )?;
        decision_ids.push(content.decision_id);
        let Some(content) = content.disclosed else {
            return Ok(None);
        };

        self.store.persist_source(ContextSourceRecord {
            task_id: task_id.clone(),
            identity: item.identity.clone(),
            effective_metadata: metadata.bytes,
            metadata_policy_decision_id: metadata.policy_decision_id,
        })?;
        self.artifacts.publish(ImmutableContextArtifact {
            artifact_id: item.content_artifact_id.clone(),
            task_id: task_id.clone(),
            kind: ContextArtifactKind::SourceChunk,
            bytes: content.bytes,
            content_digest: content.digest.clone(),
        })?;
        self.store.persist_chunk(ContextChunkRecord {
            task_id: task_id.clone(),
            member_id: item.member_id.clone(),
            identity: item.identity.clone(),
            artifact_id: item.content_artifact_id,
            content_digest: content.digest,
            content_policy_decision_id: content.policy_decision_id,
        })?;
        ContextPackageMember::new(
            &item.member_id,
            task_id.clone(),
            local_agent_terminal_domain::EvidenceCitation::new(
                item.identity,
                item.line_range,
                item.symbol.as_deref(),
                local_agent_terminal_domain::EvidenceFreshness::Current,
            )
            .map_err(|_| invalid_input())?,
            content.disclosure,
        )
        .map(Some)
        .map_err(|_| invalid_input())
    }
}

pub struct QueryContext<'a> {
    store: &'a dyn ContextStore,
    artifacts: &'a dyn ContextArtifactPublisher,
    disclosures: &'a dyn DisclosurePolicyEvaluator,
    policy_decisions: &'a dyn PolicyDecisionStore,
}

impl<'a> QueryContext<'a> {
    pub const fn new(
        store: &'a dyn ContextStore,
        artifacts: &'a dyn ContextArtifactPublisher,
        disclosures: &'a dyn DisclosurePolicyEvaluator,
        policy_decisions: &'a dyn PolicyDecisionStore,
    ) -> Self {
        Self {
            store,
            artifacts,
            disclosures,
            policy_decisions,
        }
    }

    pub fn execute(
        &self,
        request: QueryContextRequest,
    ) -> Result<ContextPackageBinding, PortError> {
        validate_package_task(&request.package, &request.query.task_id)?;
        if request.policy.task_id != request.query.task_id {
            return Err(invalid_input());
        }
        let mut members = Vec::new();
        let mut decisions = Vec::new();
        for item in self.store.query(request.query.clone())? {
            validate_source_content(&item.identity, &item.bytes)?;
            let disclosure = disclose_source(
                self.disclosures,
                self.policy_decisions,
                &request.policy,
                &item.identity,
                DisclosureChannel::RetrievedItem,
                item.bytes,
            )?;
            decisions.push(disclosure.decision_id);
            let Some(disclosed) = disclosure.disclosed else {
                continue;
            };
            let citation = local_agent_terminal_domain::EvidenceCitation::new(
                item.identity,
                item.line_range,
                item.symbol.as_deref(),
                local_agent_terminal_domain::EvidenceFreshness::Current,
            )
            .map_err(|_| invalid_input())?;
            members.push(
                ContextPackageMember::new(
                    &item.member_id,
                    request.query.task_id.clone(),
                    citation,
                    disclosed.disclosure,
                )
                .map_err(|_| invalid_input())?,
            );
        }
        finalize_package(
            self.store,
            self.artifacts,
            self.disclosures,
            self.policy_decisions,
            request.policy,
            request.package,
            members,
            decisions,
        )
    }
}

#[derive(Debug)]
struct DisclosedBytes {
    policy_decision_id: PolicyDecisionId,
    bytes: Vec<u8>,
    digest: Sha256Digest,
    disclosure: Disclosure,
}

#[derive(Debug)]
struct DisclosureResult {
    decision_id: PolicyDecisionId,
    disclosed: Option<DisclosedBytes>,
}

fn disclose_source(
    disclosures: &dyn DisclosurePolicyEvaluator,
    policy_decisions: &dyn PolicyDecisionStore,
    policy: &ContextBuildPolicy,
    identity: &SourceIdentity,
    channel: DisclosureChannel,
    bytes: Vec<u8>,
) -> Result<DisclosureResult, PortError> {
    let capability = CapabilityRef::source(identity.revision(), identity.path_identity())
        .map_err(|_| invalid_input())?;
    disclose_bytes(
        disclosures,
        policy_decisions,
        policy,
        capability,
        channel,
        bytes,
    )
}

fn disclose_bytes(
    disclosures: &dyn DisclosurePolicyEvaluator,
    policy_decisions: &dyn PolicyDecisionStore,
    policy: &ContextBuildPolicy,
    capability: CapabilityRef,
    channel: DisclosureChannel,
    bytes: Vec<u8>,
) -> Result<DisclosureResult, PortError> {
    let original_digest = digest(&bytes)?;
    let policy_request = PolicyRequest {
        task_id: policy.task_id.clone(),
        actor: policy.actor.clone(),
        action: PolicyAction::new(channel_action(channel)).map_err(|_| invalid_input())?,
        resource: PolicyResource {
            capability,
            content_digest: original_digest.clone(),
            resource_class: policy.resource_class,
        },
        task_risk: policy.task_risk,
        workflow_phase: policy.workflow_phase.clone(),
        purpose: policy.purpose.clone(),
        policy_snapshot_digest: policy.policy_snapshot_digest.clone(),
        evaluated_at: policy.evaluated_at,
    };
    let disclosure = disclosures.disclose(DisclosureRequest {
        policy_request: policy_request.clone(),
        channel,
        bytes,
    })?;
    if disclosure.channel != channel
        || disclosure.original_digest != original_digest
        || disclosure.decision.draft.request() != &policy_request
    {
        return Err(integrity_failure());
    }
    let expected_decision_id = PolicyDecisionId::from_decision(&disclosure.decision);
    let decision_id = policy_decisions.record(RecordedPolicyDecision {
        decision: disclosure.decision.clone(),
        recorded_at: policy.evaluated_at,
    })?;
    if decision_id != expected_decision_id {
        return Err(integrity_failure());
    }
    match disclosure.decision.draft.effect() {
        PolicyEffect::Deny => Ok(DisclosureResult {
            decision_id,
            disclosed: None,
        }),
        PolicyEffect::RequireApproval => Err(permission_denied()),
        PolicyEffect::Allow | PolicyEffect::AllowWithRedaction => {
            if disclosure.approval_binding.is_some() {
                return Err(integrity_failure());
            }
            let effective_bytes = disclosure.effective_bytes.ok_or_else(integrity_failure)?;
            let effective_digest = disclosure.effective_digest.ok_or_else(integrity_failure)?;
            if digest(&effective_bytes)? != effective_digest {
                return Err(integrity_failure());
            }
            let context_disclosure = if effective_digest == original_digest {
                Disclosure::allowed()
            } else {
                Disclosure::redacted(disclosure.redaction_report_digest.as_str())
                    .map_err(|_| integrity_failure())?
            };
            Ok(DisclosureResult {
                decision_id: decision_id.clone(),
                disclosed: Some(DisclosedBytes {
                    policy_decision_id: decision_id,
                    bytes: effective_bytes,
                    digest: effective_digest,
                    disclosure: context_disclosure,
                }),
            })
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn finalize_package(
    store: &dyn ContextStore,
    artifacts: &dyn ContextArtifactPublisher,
    disclosures: &dyn DisclosurePolicyEvaluator,
    policy_decisions: &dyn PolicyDecisionStore,
    policy: ContextBuildPolicy,
    draft: ContextPackageDraft,
    members: Vec<ContextPackageMember>,
    mut decision_ids: Vec<PolicyDecisionId>,
) -> Result<ContextPackageBinding, PortError> {
    let manifest_bytes = canonical_context_package_manifest(
        &draft,
        members.clone(),
        &policy.policy_snapshot_digest,
        decision_ids.clone(),
    )?;
    let manifest_digest = digest(&manifest_bytes)?;
    let final_disclosure = disclose_bytes(
        disclosures,
        policy_decisions,
        &policy,
        CapabilityRef::artifact(draft.artifact_id.clone()).map_err(|_| invalid_input())?,
        DisclosureChannel::FinalContextPackage,
        manifest_bytes.clone(),
    )?;
    decision_ids.push(final_disclosure.decision_id);
    let final_disclosure = final_disclosure.disclosed.ok_or_else(permission_denied)?;
    if final_disclosure.bytes != manifest_bytes || final_disclosure.digest != manifest_digest {
        return Err(integrity_failure());
    }
    decision_ids.sort_by(|left, right| left.as_str().cmp(right.as_str()));
    let policy_set = PolicyDecisionSet::new(
        policy.policy_snapshot_digest,
        decision_ids
            .iter()
            .map(|decision| decision.as_str().to_owned())
            .collect(),
    )
    .map_err(|_| integrity_failure())?;
    let artifact = ContextPackageArtifact::new(
        draft.artifact_id.clone(),
        manifest_digest.clone(),
        manifest_digest.clone(),
    )
    .map_err(|_| integrity_failure())?;
    let binding = ContextPackageBinding::new(draft.descriptor, policy_set, artifact, members)
        .map_err(|_| integrity_failure())?;
    artifacts.publish(ImmutableContextArtifact {
        artifact_id: draft.artifact_id,
        task_id: binding.descriptor().task_id().clone(),
        kind: ContextArtifactKind::ContextPackage,
        bytes: manifest_bytes,
        content_digest: manifest_digest,
    })?;
    let persistence = ContextPackagePersistence {
        package: ContextPackageRecord {
            binding: binding.clone(),
        },
        policy_decision_ids: decision_ids,
    };
    validate_package_persistence(&persistence)?;
    store.persist_package_with_policy_decisions(persistence)?;
    Ok(binding)
}

fn validate_package_persistence(persistence: &ContextPackagePersistence) -> Result<(), PortError> {
    let relation_ids: Vec<_> = persistence
        .policy_decision_ids
        .iter()
        .map(PolicyDecisionId::as_str)
        .collect();
    if relation_ids == persistence.package.binding.policy().decision_ids() {
        Ok(())
    } else {
        Err(integrity_failure())
    }
}

fn validate_snapshot(
    request: &SourceSnapshotRequest,
    snapshot: &SourceSnapshot,
) -> Result<(), PortError> {
    if &snapshot.request != request
        || snapshot.items.iter().any(|item| {
            item.identity.project_id() != &request.project_id
                || item.identity.revision() != request.revision
        })
    {
        Err(integrity_failure())
    } else {
        Ok(())
    }
}

fn validate_source_content(identity: &SourceIdentity, bytes: &[u8]) -> Result<(), PortError> {
    if &digest(bytes)? == identity.content_hash() {
        Ok(())
    } else {
        Err(integrity_failure())
    }
}

fn validate_package_task(package: &ContextPackageDraft, task_id: &TaskId) -> Result<(), PortError> {
    if package.descriptor.task_id() == task_id {
        Ok(())
    } else {
        Err(invalid_input())
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ContextPackageManifestV1<'a> {
    schema: &'static str,
    version: u8,
    artifact_id: &'a str,
    descriptor: ManifestDescriptor<'a>,
    members: Vec<ManifestMember<'a>>,
    policy: ManifestPolicy<'a>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ManifestDescriptor<'a> {
    package_id: &'a str,
    task_id: &'a str,
    objective: &'a str,
    versions: ManifestVersions<'a>,
    budget: ManifestBudget,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ManifestVersions<'a> {
    prompt_template: &'a str,
    retrieval_pipeline: &'a str,
    tokenizer: &'a str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ManifestBudget {
    max_tokens: u64,
    reserved_response_tokens: u64,
    used_input_tokens: u64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ManifestMember<'a> {
    member_id: &'a str,
    task_id: &'a str,
    citation: ManifestCitation<'a>,
    disclosure: ManifestDisclosure<'a>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ManifestCitation<'a> {
    source: ManifestSource<'a>,
    range: Option<ManifestRange>,
    symbol: Option<&'a str>,
    freshness: &'static str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ManifestSource<'a> {
    project_id: &'a str,
    revision: &'a str,
    path_identity: &'a str,
    content_hash: &'a str,
}

#[derive(Serialize)]
struct ManifestRange {
    start: u32,
    end: u32,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ManifestDisclosure<'a> {
    kind: &'static str,
    stable_report_id: Option<&'a str>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ManifestPolicy<'a> {
    policy_snapshot_digest: &'a str,
    item_decision_ids: Vec<&'a str>,
}

fn canonical_context_package_manifest(
    draft: &ContextPackageDraft,
    mut members: Vec<ContextPackageMember>,
    policy_snapshot_digest: &Sha256Digest,
    mut item_decision_ids: Vec<PolicyDecisionId>,
) -> Result<Vec<u8>, PortError> {
    if members
        .iter()
        .any(|member| member.task_id() != draft.descriptor.task_id())
    {
        return Err(integrity_failure());
    }
    members.sort_by(|left, right| left.member_id().cmp(right.member_id()));
    if members
        .windows(2)
        .any(|pair| pair[0].member_id() == pair[1].member_id() && pair[0] != pair[1])
    {
        return Err(integrity_failure());
    }
    members.dedup();
    item_decision_ids.sort_by(|left, right| left.as_str().cmp(right.as_str()));
    if item_decision_ids.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(integrity_failure());
    }

    let descriptor = &draft.descriptor;
    let versions = descriptor.versions();
    let budget = descriptor.budget();
    let manifest = ContextPackageManifestV1 {
        schema: "context-package-manifest",
        version: 1,
        artifact_id: draft.artifact_id.as_str(),
        descriptor: ManifestDescriptor {
            package_id: descriptor.package_id(),
            task_id: descriptor.task_id().as_str(),
            objective: descriptor.objective(),
            versions: ManifestVersions {
                prompt_template: versions.prompt_template(),
                retrieval_pipeline: versions.retrieval_pipeline(),
                tokenizer: versions.tokenizer(),
            },
            budget: ManifestBudget {
                max_tokens: budget.max_tokens(),
                reserved_response_tokens: budget.reserved_response_tokens(),
                used_input_tokens: budget.used_input_tokens(),
            },
        },
        members: members.iter().map(ManifestMember::from).collect(),
        policy: ManifestPolicy {
            policy_snapshot_digest: policy_snapshot_digest.as_str(),
            item_decision_ids: item_decision_ids
                .iter()
                .map(PolicyDecisionId::as_str)
                .collect(),
        },
    };
    let value = serde_json::to_value(manifest).map_err(|_| integrity_failure())?;
    serde_json_canonicalizer::to_vec(&value).map_err(|_| integrity_failure())
}

impl<'a> From<&'a ContextPackageMember> for ManifestMember<'a> {
    fn from(member: &'a ContextPackageMember) -> Self {
        let citation = member.citation();
        let source = citation.source();
        Self {
            member_id: member.member_id(),
            task_id: member.task_id().as_str(),
            citation: ManifestCitation {
                source: ManifestSource {
                    project_id: source.project_id().as_str(),
                    revision: source.revision(),
                    path_identity: source.path_identity(),
                    content_hash: source.content_hash().as_str(),
                },
                range: citation.range().map(|range| ManifestRange {
                    start: range.start(),
                    end: range.end(),
                }),
                symbol: citation.symbol(),
                freshness: match citation.freshness() {
                    EvidenceFreshness::Current => "current",
                    EvidenceFreshness::Stale => "stale",
                },
            },
            disclosure: ManifestDisclosure {
                kind: match member.disclosure().kind() {
                    DisclosureKind::Allowed => "allowed",
                    DisclosureKind::Redacted => "redacted",
                    DisclosureKind::Denied => "denied",
                },
                stable_report_id: member.disclosure().stable_report_id(),
            },
        }
    }
}

const fn channel_action(channel: DisclosureChannel) -> &'static str {
    match channel {
        DisclosureChannel::IndexMetadata => "context.index_metadata",
        DisclosureChannel::IndexContent => "context.index_content",
        DisclosureChannel::RetrievedItem => "context.retrieve_item",
        DisclosureChannel::FinalContextPackage => "context.final_package",
        _ => "context.disclose",
    }
}

fn digest(bytes: &[u8]) -> Result<Sha256Digest, PortError> {
    Sha256Digest::new(sha256_digest(bytes)).map_err(|_| integrity_failure())
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

fn permission_denied() -> PortError {
    PortError::failure(
        SafeErrorClassification::PermissionDenied,
        Retryability::NonRetryable,
    )
}

#[cfg(test)]
mod manifest_tests {
    use local_agent_terminal_domain::{
        ArtifactId, ContextBudget, ContextPackageDescriptor, ContextPackageMember,
        ContextVersionSet, Disclosure, DisclosureKind, EvidenceCitation, EvidenceFreshness,
        LineRange, ProjectId, Sha256Digest, SourceIdentity, TaskId,
    };

    use super::{canonical_context_package_manifest, ContextPackageDraft};
    use crate::{canonical_json::sha256_digest, PolicyDecisionId};

    type Mutation = (&'static str, Box<dyn Fn(&mut ManifestCase)>);

    #[derive(Clone)]
    struct ManifestCase {
        package_id: String,
        task_id: String,
        objective: String,
        prompt_version: String,
        retrieval_version: String,
        tokenizer_version: String,
        max_tokens: u64,
        reserved_response_tokens: u64,
        used_input_tokens: u64,
        artifact_id: String,
        member_id: String,
        project_id: String,
        revision: String,
        path_identity: String,
        content_hash: String,
        range: Option<(u32, u32)>,
        symbol: Option<String>,
        freshness: EvidenceFreshness,
        disclosure_kind: DisclosureKind,
        stable_report_id: String,
        policy_snapshot_digest: String,
        item_decision_id: String,
    }

    #[test]
    fn every_logical_manifest_leaf_changes_the_digest() {
        let baseline = ManifestCase::baseline();
        let baseline_digest = manifest_digest(&baseline);
        let mutations: Vec<Mutation> = vec![
            (
                "package_id",
                Box::new(|value| value.package_id = "package-2".into()),
            ),
            ("task_id", Box::new(|value| value.task_id = "task-2".into())),
            (
                "objective",
                Box::new(|value| value.objective = "review repository".into()),
            ),
            (
                "prompt_version",
                Box::new(|value| value.prompt_version = "prompt.v2".into()),
            ),
            (
                "retrieval_version",
                Box::new(|value| value.retrieval_version = "retrieval.v2".into()),
            ),
            (
                "tokenizer_version",
                Box::new(|value| value.tokenizer_version = "tokenizer.v2".into()),
            ),
            ("max_tokens", Box::new(|value| value.max_tokens += 1)),
            (
                "reserved_response_tokens",
                Box::new(|value| value.reserved_response_tokens += 1),
            ),
            (
                "used_input_tokens",
                Box::new(|value| value.used_input_tokens += 1),
            ),
            (
                "artifact_id",
                Box::new(|value| value.artifact_id = "artifact-package-2".into()),
            ),
            (
                "member_id",
                Box::new(|value| value.member_id = "member-2".into()),
            ),
            (
                "project_id",
                Box::new(|value| value.project_id = "project-2".into()),
            ),
            (
                "revision",
                Box::new(|value| value.revision = "commit-2".into()),
            ),
            (
                "path_identity",
                Box::new(|value| value.path_identity = "src/other.rs".into()),
            ),
            (
                "content_hash",
                Box::new(|value| value.content_hash = digest('b')),
            ),
            ("range_start", Box::new(|value| value.range = Some((2, 4)))),
            ("range_end", Box::new(|value| value.range = Some((1, 5)))),
            (
                "symbol",
                Box::new(|value| value.symbol = Some("other".into())),
            ),
            (
                "freshness",
                Box::new(|value| value.freshness = EvidenceFreshness::Stale),
            ),
            (
                "disclosure_kind",
                Box::new(|value| value.disclosure_kind = DisclosureKind::Denied),
            ),
            (
                "stable_report_id",
                Box::new(|value| value.stable_report_id = "report-2".into()),
            ),
            (
                "policy_snapshot_digest",
                Box::new(|value| value.policy_snapshot_digest = digest('c')),
            ),
            (
                "item_decision_id",
                Box::new(|value| value.item_decision_id = decision_id('d')),
            ),
        ];

        for (name, mutate) in mutations {
            let mut changed = baseline.clone();
            mutate(&mut changed);
            assert_ne!(manifest_digest(&changed), baseline_digest, "{name}");
        }
    }

    #[test]
    fn manifest_member_and_item_decision_order_matches_domain_canonical_order() {
        let baseline = ManifestCase::baseline();
        let mut second = baseline.clone();
        second.member_id = "member-2".into();
        second.path_identity = "src/other.rs".into();
        second.content_hash = digest('b');
        second.item_decision_id = decision_id('e');
        let (draft, first_member, policy_digest, first_decision) = baseline.build();
        let (_, second_member, _, second_decision) = second.build();

        let reversed = canonical_context_package_manifest(
            &draft,
            vec![second_member.clone(), first_member.clone()],
            &policy_digest,
            vec![first_decision.clone(), second_decision.clone()],
        )
        .unwrap();
        let canonical = canonical_context_package_manifest(
            &draft,
            vec![first_member, second_member],
            &policy_digest,
            vec![second_decision, first_decision],
        )
        .unwrap();

        assert_eq!(reversed, canonical);
        let manifest: serde_json::Value = serde_json::from_slice(&canonical).unwrap();
        assert_eq!(manifest["members"][0]["memberId"], "member-1");
        assert_eq!(manifest["members"][1]["memberId"], "member-2");
        assert_eq!(
            manifest["policy"]["itemDecisionIds"],
            serde_json::json!([decision_id('e'), decision_id('f')])
        );
    }

    fn manifest_digest(input: &ManifestCase) -> String {
        let (draft, member, policy_digest, decision_id) = input.build();
        let bytes = canonical_context_package_manifest(
            &draft,
            vec![member],
            &policy_digest,
            vec![decision_id],
        )
        .unwrap();
        sha256_digest(&bytes)
    }

    impl ManifestCase {
        fn baseline() -> Self {
            Self {
                package_id: "package-1".into(),
                task_id: "task-1".into(),
                objective: "analyze repository".into(),
                prompt_version: "prompt.v1".into(),
                retrieval_version: "retrieval.v1".into(),
                tokenizer_version: "tokenizer.v1".into(),
                max_tokens: 4_096,
                reserved_response_tokens: 1_024,
                used_input_tokens: 17,
                artifact_id: "artifact-package-1".into(),
                member_id: "member-1".into(),
                project_id: "project-1".into(),
                revision: "commit-1".into(),
                path_identity: "src/lib.rs".into(),
                content_hash: digest('a'),
                range: Some((1, 4)),
                symbol: Some("entry".into()),
                freshness: EvidenceFreshness::Current,
                disclosure_kind: DisclosureKind::Redacted,
                stable_report_id: "report-1".into(),
                policy_snapshot_digest: digest('e'),
                item_decision_id: decision_id('f'),
            }
        }

        fn build(
            &self,
        ) -> (
            ContextPackageDraft,
            ContextPackageMember,
            Sha256Digest,
            PolicyDecisionId,
        ) {
            let task_id = TaskId::new(&self.task_id).unwrap();
            let mut budget =
                ContextBudget::new(self.max_tokens, self.reserved_response_tokens).unwrap();
            budget.consume_input_tokens(self.used_input_tokens).unwrap();
            let descriptor = ContextPackageDescriptor::new(
                &self.package_id,
                task_id.clone(),
                &self.objective,
                ContextVersionSet::new(
                    &self.prompt_version,
                    &self.retrieval_version,
                    &self.tokenizer_version,
                )
                .unwrap(),
                budget,
            )
            .unwrap();
            let source = SourceIdentity::new(
                ProjectId::new(&self.project_id).unwrap(),
                &self.revision,
                &self.path_identity,
                Sha256Digest::new(&self.content_hash).unwrap(),
            )
            .unwrap();
            let range = self
                .range
                .map(|(start, end)| LineRange::new(start, end).unwrap());
            let citation =
                EvidenceCitation::new(source, range, self.symbol.as_deref(), self.freshness)
                    .unwrap();
            let disclosure = match self.disclosure_kind {
                DisclosureKind::Allowed => Disclosure::allowed(),
                DisclosureKind::Redacted => Disclosure::redacted(&self.stable_report_id).unwrap(),
                DisclosureKind::Denied => Disclosure::denied(&self.stable_report_id).unwrap(),
            };
            let member =
                ContextPackageMember::new(&self.member_id, task_id, citation, disclosure).unwrap();
            (
                ContextPackageDraft {
                    descriptor,
                    artifact_id: ArtifactId::new(&self.artifact_id).unwrap(),
                },
                member,
                Sha256Digest::new(&self.policy_snapshot_digest).unwrap(),
                PolicyDecisionId::from_persisted(&self.item_decision_id).unwrap(),
            )
        }
    }

    fn digest(character: char) -> String {
        format!("sha256:{}", character.to_string().repeat(64))
    }

    fn decision_id(character: char) -> String {
        format!("policy-decision:{}", character.to_string().repeat(64))
    }
}
