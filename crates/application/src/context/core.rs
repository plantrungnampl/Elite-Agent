use std::collections::BTreeMap;

use local_agent_terminal_domain::{
    ArtifactId, CapabilityRef, ContextPackageArtifact, ContextPackageBinding,
    ContextPackageDescriptor, ContextPackageMember, Disclosure, DisclosureKind, LineRange,
    PolicyAction, PolicyActor, PolicyEffect, PolicyRequest, PolicyResource, ProjectId,
    ResourceClass, Sha256Digest, SourceIdentity, TaskId, TaskRisk, Timestamp,
};
use serde::{Deserialize, Serialize};

use crate::{
    canonical_json::sha256_digest, parse_policy_timestamp, DisclosureChannel,
    DisclosurePolicyEvaluator, DisclosureRequest, PolicyDecisionId, PolicyDecisionSet,
    PolicyDecisionStore, PortError, RecordedPolicyDecision, Retryability, SafeErrorClassification,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceSnapshotRequest {
    pub project_id: ProjectId,
    pub task_id: TaskId,
    pub revision: String,
    pub repository_fingerprint: Sha256Digest,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SourceIndexMetadata {
    language: Option<String>,
    attributes: BTreeMap<String, String>,
}

impl SourceIndexMetadata {
    pub fn new<K, V, I>(language: Option<&str>, attributes: I) -> Result<Self, PortError>
    where
        K: Into<String>,
        V: Into<String>,
        I: IntoIterator<Item = (K, V)>,
    {
        let language = language.map(validated_label).transpose()?;
        let mut normalized = BTreeMap::new();
        for (key, value) in attributes {
            let key = validated_label(key)?;
            let value = validated_label(value)?;
            if normalized.insert(key, value).is_some() {
                return Err(invalid_input());
            }
        }
        Ok(Self {
            language,
            attributes: normalized,
        })
    }

    pub fn language(&self) -> Option<&str> {
        self.language.as_deref()
    }

    pub fn attributes(&self) -> &BTreeMap<String, String> {
        &self.attributes
    }

    fn validate(&self) -> Result<(), PortError> {
        if self
            .language
            .as_ref()
            .is_some_and(|value| validated_label(value).is_err())
            || self.attributes.iter().any(|(key, value)| {
                validated_label(key).is_err() || validated_label(value).is_err()
            })
        {
            Err(invalid_input())
        } else {
            Ok(())
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceSnapshotItem {
    pub document_id: String,
    pub updated_at: String,
    pub member_id: String,
    pub content_artifact_id: ArtifactId,
    pub identity: SourceIdentity,
    pub metadata: SourceIndexMetadata,
    pub content: Vec<u8>,
    pub line_range: Option<LineRange>,
    pub symbol: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContextSourceKind {
    RepositoryFile,
}

impl ContextSourceKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::RepositoryFile => "repository_file",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContextSensitivity {
    Public,
    InternalCode,
    Restricted,
    Secret,
}

impl ContextSensitivity {
    pub const fn from_resource_class(resource_class: ResourceClass) -> Self {
        match resource_class {
            ResourceClass::Public => Self::Public,
            ResourceClass::InternalCode => Self::InternalCode,
            ResourceClass::Restricted => Self::Restricted,
            ResourceClass::Secret => Self::Secret,
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Public => "public",
            Self::InternalCode => "internal-code",
            Self::Restricted => "restricted",
            Self::Secret => "secret",
        }
    }

    pub const fn resource_class(self) -> ResourceClass {
        match self {
            Self::Public => ResourceClass::Public,
            Self::InternalCode => ResourceClass::InternalCode,
            Self::Restricted => ResourceClass::Restricted,
            Self::Secret => ResourceClass::Secret,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceClassificationRequest {
    task_id: TaskId,
    document_id: String,
    member_id: String,
    identity: SourceIdentity,
    content_artifact: ContextArtifactRef,
    request_digest: Sha256Digest,
}

impl SourceClassificationRequest {
    pub fn new(
        task_id: TaskId,
        document_id: impl Into<String>,
        member_id: impl Into<String>,
        identity: SourceIdentity,
        content_artifact: ContextArtifactRef,
    ) -> Result<Self, PortError> {
        content_artifact.validate()?;
        let document_id = validated_label(document_id)?;
        let member_id = validated_label(member_id)?;
        let request_digest = classification_request_digest(
            &task_id,
            &document_id,
            &member_id,
            &identity,
            &content_artifact,
        )?;
        Ok(Self {
            task_id,
            document_id,
            member_id,
            identity,
            content_artifact,
            request_digest,
        })
    }

    fn from_item(
        task_id: &TaskId,
        item: &SourceSnapshotItem,
        content_artifact: ContextArtifactRef,
    ) -> Result<Self, PortError> {
        Self::new(
            task_id.clone(),
            &item.document_id,
            &item.member_id,
            item.identity.clone(),
            content_artifact,
        )
    }

    pub fn task_id(&self) -> &TaskId {
        &self.task_id
    }

    pub fn document_id(&self) -> &str {
        &self.document_id
    }

    pub fn member_id(&self) -> &str {
        &self.member_id
    }

    pub fn identity(&self) -> &SourceIdentity {
        &self.identity
    }

    pub fn content_artifact(&self) -> &ContextArtifactRef {
        &self.content_artifact
    }

    pub fn request_digest(&self) -> &Sha256Digest {
        &self.request_digest
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContextSourceClassification {
    request_digest: Sha256Digest,
    sensitivity: ContextSensitivity,
    evidence: ContextArtifactRef,
    result_digest: Sha256Digest,
    classified_at: Timestamp,
}

impl ContextSourceClassification {
    pub fn issue(
        request: &SourceClassificationRequest,
        sensitivity: ContextSensitivity,
        evidence: ContextArtifactRef,
        classified_at: Timestamp,
    ) -> Result<Self, PortError> {
        evidence.validate()?;
        if classified_at.unix_seconds() <= 0 {
            return Err(invalid_input());
        }
        let result_digest = classification_result_digest(
            &request.request_digest,
            sensitivity,
            &evidence,
            classified_at,
        )?;
        Ok(Self {
            request_digest: request.request_digest.clone(),
            sensitivity,
            evidence,
            result_digest,
            classified_at,
        })
    }

    pub fn validate(&self, request: &SourceClassificationRequest) -> Result<(), PortError> {
        self.validate_rehydrated()?;
        if self.request_digest != request.request_digest {
            return Err(integrity_failure());
        }
        Ok(())
    }

    pub fn rehydrate(
        request_digest: Sha256Digest,
        sensitivity: ContextSensitivity,
        evidence: ContextArtifactRef,
        result_digest: Sha256Digest,
        classified_at: Timestamp,
    ) -> Result<Self, PortError> {
        let classification = Self {
            request_digest,
            sensitivity,
            evidence,
            result_digest,
            classified_at,
        };
        classification.validate_rehydrated()?;
        Ok(classification)
    }

    fn validate_rehydrated(&self) -> Result<(), PortError> {
        self.evidence.validate()?;
        if self.classified_at.unix_seconds() <= 0 {
            return Err(invalid_input());
        }
        let expected = classification_result_digest(
            &self.request_digest,
            self.sensitivity,
            &self.evidence,
            self.classified_at,
        )?;
        if self.result_digest != expected {
            Err(integrity_failure())
        } else {
            Ok(())
        }
    }

    pub const fn sensitivity(&self) -> ContextSensitivity {
        self.sensitivity
    }

    pub fn evidence(&self) -> &ContextArtifactRef {
        &self.evidence
    }

    pub fn request_digest(&self) -> &Sha256Digest {
        &self.request_digest
    }

    pub fn result_digest(&self) -> &Sha256Digest {
        &self.result_digest
    }

    pub const fn classified_at(&self) -> Timestamp {
        self.classified_at
    }
}

pub trait ContextSourceClassifier: Send + Sync {
    fn classify(
        &self,
        request: SourceClassificationRequest,
    ) -> Result<ContextClassificationOutcome, PortError>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContextClassificationOutcome {
    pub classification: ContextSourceClassification,
    pub evidence_bytes: Vec<u8>,
}

impl ContextClassificationOutcome {
    pub fn validate(&self, request: &SourceClassificationRequest) -> Result<(), PortError> {
        self.classification.validate(request)?;
        validate_artifact_content(self.classification.evidence(), &self.evidence_bytes)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ContextLogicalIdentity {
    Disclosed(String),
    Redacted(String),
}

impl ContextLogicalIdentity {
    pub fn disclosed(value: impl Into<String>) -> Result<Self, PortError> {
        validated_label(value).map(Self::Disclosed)
    }

    pub fn redacted(stable_report_id: impl Into<String>) -> Result<Self, PortError> {
        validated_label(stable_report_id).map(Self::Redacted)
    }

    pub fn as_str(&self) -> &str {
        match self {
            Self::Disclosed(value) | Self::Redacted(value) => value,
        }
    }

    pub const fn is_redacted(&self) -> bool {
        matches!(self, Self::Redacted(_))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContextSourceState {
    Pending,
    Current,
    Stale,
    Denied,
    Failed,
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
pub struct ContextPolicyDecisionRef {
    decision_id: PolicyDecisionId,
    operation_digest: Sha256Digest,
}

impl ContextPolicyDecisionRef {
    pub fn new(decision_id: PolicyDecisionId, operation_digest: Sha256Digest) -> Self {
        Self {
            decision_id,
            operation_digest,
        }
    }

    pub fn decision_id(&self) -> &PolicyDecisionId {
        &self.decision_id
    }

    pub fn operation_digest(&self) -> &Sha256Digest {
        &self.operation_digest
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContextIndexProvenance {
    index_metadata: ContextPolicyDecisionRef,
    index_content: ContextPolicyDecisionRef,
    binding_digest: Sha256Digest,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContextIndexProvenanceRehydration {
    pub task_id: TaskId,
    pub document_id: String,
    pub member_id: String,
    pub identity: SourceIdentity,
    pub artifact: ContextArtifactRef,
    pub metadata: Vec<u8>,
    pub line_range: Option<LineRange>,
    pub symbol: Option<String>,
    pub created_at: Timestamp,
    pub classification: ContextSourceClassification,
    pub index_metadata: ContextPolicyDecisionRef,
    pub index_content: ContextPolicyDecisionRef,
    pub binding_digest: Sha256Digest,
}

#[derive(Debug, Clone, Copy)]
struct ContextIndexAuthority<'a> {
    task_id: &'a TaskId,
    document_id: &'a str,
    member_id: &'a str,
    identity: &'a SourceIdentity,
    artifact: &'a ContextArtifactRef,
    metadata: &'a [u8],
    line_range: Option<LineRange>,
    symbol: Option<&'a str>,
    created_at: Timestamp,
    classification: &'a ContextSourceClassification,
}

impl ContextIndexProvenance {
    fn issue(
        authority: ContextIndexAuthority<'_>,
        index_metadata: ContextPolicyDecisionRef,
        index_content: ContextPolicyDecisionRef,
    ) -> Result<Self, PortError> {
        let binding_digest = index_provenance_digest(authority, &index_metadata, &index_content)?;
        Ok(Self {
            index_metadata,
            index_content,
            binding_digest,
        })
    }

    fn validate(&self, authority: ContextIndexAuthority<'_>) -> Result<(), PortError> {
        let expected =
            index_provenance_digest(authority, &self.index_metadata, &self.index_content)?;
        if expected == self.binding_digest {
            Ok(())
        } else {
            Err(integrity_failure())
        }
    }

    pub fn rehydrate(record: ContextIndexProvenanceRehydration) -> Result<Self, PortError> {
        let provenance = Self {
            index_metadata: record.index_metadata,
            index_content: record.index_content,
            binding_digest: record.binding_digest,
        };
        let authority = ContextIndexAuthority {
            task_id: &record.task_id,
            document_id: &record.document_id,
            member_id: &record.member_id,
            identity: &record.identity,
            artifact: &record.artifact,
            metadata: &record.metadata,
            line_range: record.line_range,
            symbol: record.symbol.as_deref(),
            created_at: record.created_at,
            classification: &record.classification,
        };
        validate_index_authority(authority, &provenance)?;
        Ok(provenance)
    }

    pub fn index_metadata(&self) -> &ContextPolicyDecisionRef {
        &self.index_metadata
    }

    pub fn index_content(&self) -> &ContextPolicyDecisionRef {
        &self.index_content
    }

    pub fn binding_digest(&self) -> &Sha256Digest {
        &self.binding_digest
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContextSourceRecord {
    pub document_id: String,
    pub task_id: TaskId,
    pub project_id: ProjectId,
    pub logical_identity: ContextLogicalIdentity,
    pub revision: String,
    pub content_hash: Sha256Digest,
    pub source_kind: ContextSourceKind,
    pub classification: ContextSourceClassification,
    pub state: ContextSourceState,
    pub updated_at: String,
    pub metadata_policy: ContextPolicyDecisionRef,
}

impl ContextSourceRecord {
    pub fn validate(&self) -> Result<(), PortError> {
        self.classification.validate_rehydrated()?;
        let identity_matches_state = match self.state {
            ContextSourceState::Denied => self.logical_identity.is_redacted(),
            ContextSourceState::Current => true,
            ContextSourceState::Pending
            | ContextSourceState::Stale
            | ContextSourceState::Failed => true,
        };
        if validated_label(&self.document_id).is_err()
            || validated_label(&self.revision).is_err()
            || self.updated_at.trim().is_empty()
            || !identity_matches_state
        {
            return Err(invalid_input());
        }
        Ok(())
    }

    pub fn disclosed_source_identity(&self) -> Result<Option<SourceIdentity>, PortError> {
        match &self.logical_identity {
            ContextLogicalIdentity::Disclosed(path) => SourceIdentity::new(
                self.project_id.clone(),
                &self.revision,
                path,
                self.content_hash.clone(),
            )
            .map(Some)
            .map_err(|_| integrity_failure()),
            ContextLogicalIdentity::Redacted(_) => Ok(None),
        }
    }

    pub fn source_identity(&self) -> Result<SourceIdentity, PortError> {
        SourceIdentity::new(
            self.project_id.clone(),
            &self.revision,
            self.logical_identity.as_str(),
            self.content_hash.clone(),
        )
        .map_err(|_| integrity_failure())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContextChunkRecord {
    pub document_id: String,
    pub task_id: TaskId,
    pub member_id: String,
    pub identity: SourceIdentity,
    pub artifact: ContextArtifactRef,
    pub metadata: Vec<u8>,
    pub line_range: Option<LineRange>,
    pub symbol: Option<String>,
    pub created_at: Timestamp,
    pub classification: ContextSourceClassification,
    pub provenance: ContextIndexProvenance,
}

impl ContextChunkRecord {
    pub fn validate(&self) -> Result<(), PortError> {
        validate_index_authority(self.index_authority(), &self.provenance)
    }

    fn index_authority(&self) -> ContextIndexAuthority<'_> {
        ContextIndexAuthority {
            task_id: &self.task_id,
            document_id: &self.document_id,
            member_id: &self.member_id,
            identity: &self.identity,
            artifact: &self.artifact,
            metadata: &self.metadata,
            line_range: self.line_range,
            symbol: self.symbol.as_deref(),
            created_at: self.created_at,
            classification: &self.classification,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceStateTransition {
    pub document_id: String,
    pub expected_state: ContextSourceState,
    pub next_state: ContextSourceState,
    pub updated_at: String,
}

impl SourceStateTransition {
    pub fn validate(&self) -> Result<(), PortError> {
        if validated_label(&self.document_id).is_err()
            || self.updated_at.trim().is_empty()
            || self.expected_state != ContextSourceState::Current
            || self.next_state != ContextSourceState::Stale
        {
            Err(invalid_input())
        } else {
            Ok(())
        }
    }
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
    pub document_id: String,
    pub task_id: TaskId,
    pub member_id: String,
    pub artifact: ContextArtifactRef,
    pub identity: SourceIdentity,
    pub metadata: Vec<u8>,
    pub line_range: Option<LineRange>,
    pub symbol: Option<String>,
    pub created_at: Timestamp,
    pub classification: ContextSourceClassification,
    pub provenance: ContextIndexProvenance,
}

impl RetrievedContextItem {
    pub fn validate(&self, task_id: &TaskId) -> Result<(), PortError> {
        if &self.task_id != task_id {
            return Err(integrity_failure());
        }
        validate_index_authority(
            ContextIndexAuthority {
                task_id: &self.task_id,
                document_id: &self.document_id,
                member_id: &self.member_id,
                identity: &self.identity,
                artifact: &self.artifact,
                metadata: &self.metadata,
                line_range: self.line_range,
                symbol: self.symbol.as_deref(),
                created_at: self.created_at,
                classification: &self.classification,
            },
            &self.provenance,
        )
    }
}

pub trait ContextStore: Send + Sync {
    fn persist_source(&self, source: ContextSourceRecord) -> Result<(), PortError>;
    fn persist_chunk(&self, chunk: ContextChunkRecord) -> Result<(), PortError>;
    fn transition_source(&self, transition: SourceStateTransition) -> Result<(), PortError>;
    fn query(&self, query: ContextQuery) -> Result<Vec<RetrievedContextItem>, PortError>;
    /// Atomically persists the package row and its complete policy-decision relation set.
    /// Implementations must commit both together or leave neither visible.
    fn persist_package_with_policy_decisions(
        &self,
        persistence: ContextPackagePersistence,
    ) -> Result<(), PortError>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContextArtifactRef {
    artifact_id: ArtifactId,
    content_digest: Sha256Digest,
    size_bytes: u64,
}

impl ContextArtifactRef {
    pub fn new(
        artifact_id: ArtifactId,
        content_digest: Sha256Digest,
        size_bytes: u64,
    ) -> Result<Self, PortError> {
        let reference = Self {
            artifact_id,
            content_digest,
            size_bytes,
        };
        reference.validate()?;
        Ok(reference)
    }

    pub fn artifact_id(&self) -> &ArtifactId {
        &self.artifact_id
    }

    pub fn content_digest(&self) -> &Sha256Digest {
        &self.content_digest
    }

    pub const fn size_bytes(&self) -> u64 {
        self.size_bytes
    }

    pub fn validate(&self) -> Result<(), PortError> {
        if self.size_bytes == 0 {
            Err(invalid_input())
        } else {
            Ok(())
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CandidateIndexRecordV1 {
    schema: String,
    version: u8,
    document_id: String,
    task_id: String,
    member_id: String,
    source: CandidateSourceV1,
    source_kind: String,
    line_range: Option<CandidateLineRangeV1>,
    symbol: Option<String>,
    metadata: SourceIndexMetadata,
    classification: CandidateClassificationV1,
    artifact: CandidateArtifactRefV1,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CandidateSourceV1 {
    project_id: String,
    revision: String,
    logical_identity: CandidateLogicalIdentityV1,
    content_hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CandidateLogicalIdentityV1 {
    kind: String,
    value: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CandidateLineRangeV1 {
    start: u32,
    end: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CandidateClassificationV1 {
    sensitivity: String,
    request_digest: String,
    result_digest: String,
    evidence_artifact_id: String,
    evidence_content_digest: String,
    evidence_size_bytes: u64,
    classified_at_unix_seconds: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CandidateArtifactRefV1 {
    artifact_id: String,
    content_digest: String,
    size_bytes: u64,
}

impl CandidateIndexRecordV1 {
    fn from_source(
        task_id: &TaskId,
        item: &SourceSnapshotItem,
        classification: &ContextSourceClassification,
        artifact: &ContextArtifactRef,
    ) -> Result<Self, PortError> {
        item.metadata.validate()?;
        let record = Self {
            schema: "context-candidate-index.v1".to_owned(),
            version: 1,
            document_id: validated_label(&item.document_id)?,
            task_id: task_id.as_str().to_owned(),
            member_id: validated_label(&item.member_id)?,
            source: CandidateSourceV1 {
                project_id: item.identity.project_id().as_str().to_owned(),
                revision: item.identity.revision().to_owned(),
                logical_identity: CandidateLogicalIdentityV1 {
                    kind: "disclosed".to_owned(),
                    value: item.identity.path_identity().to_owned(),
                },
                content_hash: item.identity.content_hash().as_str().to_owned(),
            },
            source_kind: ContextSourceKind::RepositoryFile.as_str().to_owned(),
            line_range: item.line_range.map(|range| CandidateLineRangeV1 {
                start: range.start(),
                end: range.end(),
            }),
            symbol: item.symbol.clone(),
            metadata: item.metadata.clone(),
            classification: CandidateClassificationV1 {
                sensitivity: classification.sensitivity().as_str().to_owned(),
                request_digest: classification.request_digest().as_str().to_owned(),
                result_digest: classification.result_digest().as_str().to_owned(),
                evidence_artifact_id: classification.evidence().artifact_id.as_str().to_owned(),
                evidence_content_digest: classification
                    .evidence()
                    .content_digest
                    .as_str()
                    .to_owned(),
                evidence_size_bytes: classification.evidence().size_bytes,
                classified_at_unix_seconds: classification.classified_at().unix_seconds(),
            },
            artifact: CandidateArtifactRefV1 {
                artifact_id: artifact.artifact_id.as_str().to_owned(),
                content_digest: artifact.content_digest.as_str().to_owned(),
                size_bytes: artifact.size_bytes,
            },
        };
        record.validate_shape()?;
        Ok(record)
    }

    fn canonical_bytes(&self) -> Result<Vec<u8>, PortError> {
        let value = serde_json::to_value(self).map_err(|_| integrity_failure())?;
        serde_json_canonicalizer::to_vec(&value).map_err(|_| integrity_failure())
    }

    fn parse_effective(bytes: &[u8], original: &Self) -> Result<Self, PortError> {
        validate_canonical_metadata(bytes)?;
        let effective: Self = serde_json::from_slice(bytes).map_err(|_| integrity_failure())?;
        effective.validate_shape()?;
        if effective.schema != original.schema
            || effective.version != original.version
            || effective.document_id != original.document_id
            || effective.task_id != original.task_id
            || effective.member_id != original.member_id
            || effective.source.project_id != original.source.project_id
            || effective.source.revision != original.source.revision
            || effective.source.content_hash != original.source.content_hash
            || effective.source_kind != original.source_kind
            || effective.classification != original.classification
            || effective.artifact != original.artifact
        {
            return Err(integrity_failure());
        }
        let original_bytes = original.canonical_bytes()?;
        if bytes == original_bytes {
            if effective != *original {
                return Err(integrity_failure());
            }
        } else if effective.source.logical_identity.kind != "redacted"
            || effective.source.logical_identity.value == original.source.logical_identity.value
            || original
                .symbol
                .as_ref()
                .is_some_and(|symbol| effective.symbol.as_ref() == Some(symbol))
        {
            return Err(integrity_failure());
        }
        Ok(effective)
    }

    fn validate_shape(&self) -> Result<(), PortError> {
        if self.schema != "context-candidate-index.v1"
            || self.version != 1
            || validated_label(&self.document_id).is_err()
            || validated_label(&self.task_id).is_err()
            || validated_label(&self.member_id).is_err()
            || validated_label(&self.source.project_id).is_err()
            || validated_label(&self.source.revision).is_err()
            || validated_label(&self.source.logical_identity.value).is_err()
            || !matches!(
                self.source.logical_identity.kind.as_str(),
                "disclosed" | "redacted"
            )
            || self.source_kind != ContextSourceKind::RepositoryFile.as_str()
            || self
                .symbol
                .as_ref()
                .is_some_and(|value| validated_label(value).is_err())
            || self.artifact.size_bytes == 0
            || self.classification.evidence_size_bytes == 0
            || self.classification.classified_at_unix_seconds <= 0
        {
            return Err(integrity_failure());
        }
        ProjectId::new(&self.source.project_id).map_err(|_| integrity_failure())?;
        Sha256Digest::new(&self.source.content_hash).map_err(|_| integrity_failure())?;
        Sha256Digest::new(&self.artifact.content_digest).map_err(|_| integrity_failure())?;
        Sha256Digest::new(&self.classification.request_digest).map_err(|_| integrity_failure())?;
        Sha256Digest::new(&self.classification.result_digest).map_err(|_| integrity_failure())?;
        Sha256Digest::new(&self.classification.evidence_content_digest)
            .map_err(|_| integrity_failure())?;
        self.metadata.validate()?;
        self.line_range()?;
        Ok(())
    }

    fn logical_identity(&self) -> Result<ContextLogicalIdentity, PortError> {
        match self.source.logical_identity.kind.as_str() {
            "disclosed" => ContextLogicalIdentity::disclosed(&self.source.logical_identity.value),
            "redacted" => ContextLogicalIdentity::redacted(&self.source.logical_identity.value),
            _ => Err(integrity_failure()),
        }
    }

    fn source_identity(&self) -> Result<SourceIdentity, PortError> {
        SourceIdentity::new(
            ProjectId::new(&self.source.project_id).map_err(|_| integrity_failure())?,
            &self.source.revision,
            &self.source.logical_identity.value,
            Sha256Digest::new(&self.source.content_hash).map_err(|_| integrity_failure())?,
        )
        .map_err(|_| integrity_failure())
    }

    fn line_range(&self) -> Result<Option<LineRange>, PortError> {
        self.line_range
            .map(|range| LineRange::new(range.start, range.end).map_err(|_| integrity_failure()))
            .transpose()
    }

    fn same_index_identity(&self, other: &Self) -> bool {
        self.schema == other.schema
            && self.version == other.version
            && self.document_id == other.document_id
            && self.task_id == other.task_id
            && self.member_id == other.member_id
            && self.source == other.source
            && self.source_kind == other.source_kind
            && self.line_range == other.line_range
            && self.symbol == other.symbol
            && self.metadata == other.metadata
            && self.classification == other.classification
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContextArtifactKind {
    ClassificationEvidence,
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

pub trait ContextArtifactReader: Send + Sync {
    fn read(&self, reference: &ContextArtifactRef) -> Result<Vec<u8>, PortError>;
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContextEvidenceAssemblyItem {
    pub member: ContextPackageMember,
    pub content: String,
    pub policy_decision_ids: Vec<String>,
    pub provenance: Vec<String>,
    pub redaction_report_ids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AssembledContextPackage {
    pub descriptor: ContextPackageDescriptor,
    pub artifact: ImmutableContextArtifact,
    pub members: Vec<ContextPackageMember>,
    pub policy_decision_ids: Vec<String>,
    pub provenance: Vec<String>,
    pub redaction_report_ids: Vec<String>,
    pub used_input_tokens: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreparedContextPackage {
    artifact: ImmutableContextArtifact,
    persistence: ContextPackagePersistence,
    provenance: Vec<String>,
    redaction_report_ids: Vec<String>,
}

impl PreparedContextPackage {
    pub fn binding(&self) -> &ContextPackageBinding {
        &self.persistence.package.binding
    }

    pub fn artifact(&self) -> &ImmutableContextArtifact {
        &self.artifact
    }

    pub fn policy_decision_ids(&self) -> &[PolicyDecisionId] {
        &self.persistence.policy_decision_ids
    }

    pub fn provenance(&self) -> &[String] {
        &self.provenance
    }

    pub fn redaction_report_ids(&self) -> &[String] {
        &self.redaction_report_ids
    }
}

pub trait ContextPackageAssembler: Send + Sync {
    fn assemble(
        &self,
        descriptor: ContextPackageDescriptor,
        policy: ContextBuildPolicy,
        items: Vec<ContextEvidenceAssemblyItem>,
        policy_decision_ids: Vec<String>,
    ) -> Result<AssembledContextPackage, PortError>;
}

pub trait ContextRetrievalAuthority: Send + Sync {
    fn verify_current(
        &self,
        task_id: &TaskId,
        items: &[RetrievedContextItem],
    ) -> Result<(), PortError>;
}

pub struct BuildInitialContext<'a> {
    source: &'a dyn RepositoryContextSource,
    classifier: &'a dyn ContextSourceClassifier,
    store: &'a dyn ContextStore,
    artifacts: &'a dyn ContextArtifactPublisher,
    disclosures: &'a dyn DisclosurePolicyEvaluator,
    policy_decisions: &'a dyn PolicyDecisionStore,
    assembler: &'a dyn ContextPackageAssembler,
}

impl<'a> BuildInitialContext<'a> {
    pub const fn new(
        source: &'a dyn RepositoryContextSource,
        classifier: &'a dyn ContextSourceClassifier,
        store: &'a dyn ContextStore,
        artifacts: &'a dyn ContextArtifactPublisher,
        disclosures: &'a dyn DisclosurePolicyEvaluator,
        policy_decisions: &'a dyn PolicyDecisionStore,
        assembler: &'a dyn ContextPackageAssembler,
    ) -> Self {
        Self {
            source,
            classifier,
            store,
            artifacts,
            disclosures,
            policy_decisions,
            assembler,
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

        let mut items = Vec::new();
        let mut decision_ids = Vec::new();
        for item in snapshot.items {
            if let Some(item) = self.persist_allowed_item(
                &request.snapshot.task_id,
                &request.policy,
                item,
                &mut decision_ids,
            )? {
                items.push(item);
            }
        }
        finalize_package(
            self.store,
            self.artifacts,
            self.assembler,
            request.policy,
            request.package,
            items,
            decision_ids,
        )
    }

    fn persist_allowed_item(
        &self,
        task_id: &TaskId,
        policy: &ContextBuildPolicy,
        item: SourceSnapshotItem,
        decision_ids: &mut Vec<PolicyDecisionId>,
    ) -> Result<Option<ContextEvidenceAssemblyItem>, PortError> {
        let decision_start = decision_ids.len();
        validate_source_content(&item.identity, &item.content)?;
        item.metadata.validate()?;
        let original_artifact = ContextArtifactRef::new(
            item.content_artifact_id.clone(),
            item.identity.content_hash().clone(),
            u64::try_from(item.content.len()).map_err(|_| integrity_failure())?,
        )?;
        let classification_request =
            SourceClassificationRequest::from_item(task_id, &item, original_artifact)?;
        let classification_outcome = self.classifier.classify(classification_request.clone())?;
        classification_outcome.validate(&classification_request)?;
        let classification = classification_outcome.classification.clone();
        let resource_class = classification.sensitivity().resource_class();

        let preflight_candidate = CandidateIndexRecordV1::from_source(
            task_id,
            &item,
            &classification,
            classification_request.content_artifact(),
        )?;
        let preflight_metadata = disclose_source(
            self.disclosures,
            self.policy_decisions,
            policy,
            &item.identity,
            resource_class,
            DisclosureChannel::IndexMetadata,
            preflight_candidate.canonical_bytes()?,
        )?;
        decision_ids.push(preflight_metadata.decision_id.clone());
        let preflight_metadata_policy = ContextPolicyDecisionRef::new(
            preflight_metadata.decision_id.clone(),
            preflight_metadata.operation_digest.clone(),
        );
        let Some(preflight_metadata) = preflight_metadata.disclosed else {
            return Ok(None);
        };
        let preflight_effective = CandidateIndexRecordV1::parse_effective(
            &preflight_metadata.bytes,
            &preflight_candidate,
        )?;

        let content = disclose_source(
            self.disclosures,
            self.policy_decisions,
            policy,
            &item.identity,
            resource_class,
            DisclosureChannel::IndexContent,
            item.content.clone(),
        )?;
        decision_ids.push(content.decision_id.clone());
        let content_policy = ContextPolicyDecisionRef::new(
            content.decision_id.clone(),
            content.operation_digest.clone(),
        );
        let Some(content) = content.disclosed else {
            return Ok(None);
        };
        let artifact = ContextArtifactRef::new(
            item.content_artifact_id.clone(),
            content.digest.clone(),
            u64::try_from(content.bytes.len()).map_err(|_| integrity_failure())?,
        )?;
        let (metadata, metadata_policy, effective_candidate) = if &artifact
            == classification_request.content_artifact()
        {
            (
                preflight_metadata,
                preflight_metadata_policy,
                preflight_effective,
            )
        } else {
            let candidate =
                CandidateIndexRecordV1::from_source(task_id, &item, &classification, &artifact)?;
            let metadata = disclose_source(
                self.disclosures,
                self.policy_decisions,
                policy,
                &item.identity,
                resource_class,
                DisclosureChannel::IndexMetadata,
                candidate.canonical_bytes()?,
            )?;
            decision_ids.push(metadata.decision_id.clone());
            let metadata_policy = ContextPolicyDecisionRef::new(
                metadata.decision_id.clone(),
                metadata.operation_digest.clone(),
            );
            let Some(metadata) = metadata.disclosed else {
                return Ok(None);
            };
            let effective_candidate =
                CandidateIndexRecordV1::parse_effective(&metadata.bytes, &candidate)?;
            if !effective_candidate.same_index_identity(&preflight_effective) {
                return Err(integrity_failure());
            }
            (metadata, metadata_policy, effective_candidate)
        };
        let effective_identity = effective_candidate.source_identity()?;
        let effective_logical_identity = effective_candidate.logical_identity()?;
        let effective_line_range = effective_candidate.line_range()?;
        let created_at = parse_policy_timestamp(&item.updated_at)?;
        let provenance = ContextIndexProvenance::issue(
            ContextIndexAuthority {
                task_id,
                document_id: &effective_candidate.document_id,
                member_id: &effective_candidate.member_id,
                identity: &effective_identity,
                artifact: &artifact,
                metadata: &metadata.bytes,
                line_range: effective_line_range,
                symbol: effective_candidate.symbol.as_deref(),
                created_at,
                classification: &classification,
            },
            metadata_policy.clone(),
            content_policy,
        )?;

        let assembly_content = String::from_utf8(content.bytes.clone()).map_err(|_| invalid_input())?;
        self.artifacts.publish(ImmutableContextArtifact {
            artifact_id: classification.evidence().artifact_id.clone(),
            task_id: task_id.clone(),
            kind: ContextArtifactKind::ClassificationEvidence,
            bytes: classification_outcome.evidence_bytes,
            content_digest: classification.evidence().content_digest.clone(),
        })?;

        self.persist_source_record(
            task_id,
            &item,
            effective_logical_identity,
            classification.clone(),
            metadata_policy,
        )?;
        self.artifacts.publish(ImmutableContextArtifact {
            artifact_id: item.content_artifact_id.clone(),
            task_id: task_id.clone(),
            kind: ContextArtifactKind::SourceChunk,
            bytes: content.bytes,
            content_digest: content.digest.clone(),
        })?;
        let chunk = ContextChunkRecord {
            document_id: effective_candidate.document_id.clone(),
            task_id: task_id.clone(),
            member_id: effective_candidate.member_id.clone(),
            identity: effective_identity.clone(),
            artifact,
            metadata: metadata.bytes,
            line_range: effective_line_range,
            symbol: effective_candidate.symbol.clone(),
            created_at,
            classification,
            provenance,
        };
        chunk.validate()?;
        self.store.persist_chunk(chunk)?;
        let disclosure = if metadata.disclosure.kind() == DisclosureKind::Redacted {
            metadata.disclosure
        } else {
            content.disclosure
        };
        let member = ContextPackageMember::new(
            &effective_candidate.member_id,
            task_id.clone(),
            local_agent_terminal_domain::EvidenceCitation::new(
                effective_identity,
                effective_line_range,
                effective_candidate.symbol.as_deref(),
                local_agent_terminal_domain::EvidenceFreshness::Current,
            )
            .map_err(|_| invalid_input())?,
            disclosure,
        )
        .map_err(|_| invalid_input())?;
        let redaction_report_ids = member
            .disclosure()
            .stable_report_id()
            .map(|report| vec![report.to_owned()])
            .unwrap_or_default();
        Ok(Some(ContextEvidenceAssemblyItem {
            member,
            content: assembly_content,
            policy_decision_ids: decision_ids[decision_start..]
                .iter()
                .map(|decision| decision.as_str().to_owned())
                .collect(),
            provenance: vec![format!(
                "repository:{}:{}",
                item.identity.revision(),
                item.identity.path_identity()
            )],
            redaction_report_ids,
        }))
    }

    fn persist_source_record(
        &self,
        task_id: &TaskId,
        item: &SourceSnapshotItem,
        logical_identity: ContextLogicalIdentity,
        classification: ContextSourceClassification,
        metadata_policy: ContextPolicyDecisionRef,
    ) -> Result<(), PortError> {
        let record = ContextSourceRecord {
            document_id: item.document_id.clone(),
            task_id: task_id.clone(),
            project_id: item.identity.project_id().clone(),
            logical_identity,
            revision: item.identity.revision().to_owned(),
            content_hash: item.identity.content_hash().clone(),
            source_kind: ContextSourceKind::RepositoryFile,
            classification,
            state: ContextSourceState::Current,
            updated_at: item.updated_at.clone(),
            metadata_policy,
        };
        record.validate()?;
        self.store.persist_source(record)
    }
}

pub struct QueryContext<'a> {
    store: &'a dyn ContextStore,
    artifacts: &'a dyn ContextArtifactPublisher,
    artifact_reader: &'a dyn ContextArtifactReader,
    disclosures: &'a dyn DisclosurePolicyEvaluator,
    policy_decisions: &'a dyn PolicyDecisionStore,
    assembler: &'a dyn ContextPackageAssembler,
    authority: &'a dyn ContextRetrievalAuthority,
}

impl<'a> QueryContext<'a> {
    pub const fn new(
        store: &'a dyn ContextStore,
        artifacts: &'a dyn ContextArtifactPublisher,
        artifact_reader: &'a dyn ContextArtifactReader,
        disclosures: &'a dyn DisclosurePolicyEvaluator,
        policy_decisions: &'a dyn PolicyDecisionStore,
        assembler: &'a dyn ContextPackageAssembler,
        authority: &'a dyn ContextRetrievalAuthority,
    ) -> Self {
        Self {
            store,
            artifacts,
            artifact_reader,
            disclosures,
            policy_decisions,
            assembler,
            authority,
        }
    }

    pub fn execute(
        &self,
        request: QueryContextRequest,
    ) -> Result<ContextPackageBinding, PortError> {
        let prepared = self.prepare(request)?;
        self.commit(prepared)
    }

    pub fn prepare(&self, request: QueryContextRequest) -> Result<PreparedContextPackage, PortError> {
        validate_package_task(&request.package, &request.query.task_id)?;
        if request.policy.task_id != request.query.task_id {
            return Err(invalid_input());
        }
        let mut items = Vec::new();
        let mut decisions = Vec::new();
        let retrieved = self.store.query(request.query.clone())?;
        self.authority
            .verify_current(&request.query.task_id, &retrieved)?;
        for item in retrieved {
            item.validate(&request.query.task_id)?;
            let mut item_decisions = vec![
                item.provenance.index_metadata().decision_id().clone(),
                item.provenance.index_content().decision_id().clone(),
            ];
            let bytes = self.artifact_reader.read(&item.artifact)?;
            validate_artifact_content(&item.artifact, &bytes)?;
            let disclosure = disclose_source(
                self.disclosures,
                self.policy_decisions,
                &request.policy,
                &item.identity,
                item.classification.sensitivity().resource_class(),
                DisclosureChannel::RetrievedItem,
                bytes,
            )?;
            item_decisions.push(disclosure.decision_id);
            decisions.extend(item_decisions.iter().cloned());
            let Some(disclosed) = disclosure.disclosed else {
                continue;
            };
            let provenance = format!(
                "repository:{}:{}",
                item.identity.revision(),
                item.identity.path_identity()
            );
            let citation = local_agent_terminal_domain::EvidenceCitation::new(
                item.identity,
                item.line_range,
                item.symbol.as_deref(),
                local_agent_terminal_domain::EvidenceFreshness::Current,
            )
            .map_err(|_| invalid_input())?;
            let member = ContextPackageMember::new(
                    &item.member_id,
                    request.query.task_id.clone(),
                    citation,
                    disclosed.disclosure,
                )
                .map_err(|_| invalid_input())?;
            let redaction_report_ids = member
                .disclosure()
                .stable_report_id()
                .map(|report| vec![report.to_owned()])
                .unwrap_or_default();
            items.push(ContextEvidenceAssemblyItem {
                member,
                content: String::from_utf8(disclosed.bytes).map_err(|_| invalid_input())?,
                policy_decision_ids: item_decisions
                    .iter()
                    .map(|decision| decision.as_str().to_owned())
                    .collect(),
                provenance: vec![provenance],
                redaction_report_ids,
            });
        }
        prepare_package(
            self.assembler,
            request.policy,
            request.package,
            items,
            decisions,
        )
    }

    pub fn commit(
        &self,
        prepared: PreparedContextPackage,
    ) -> Result<ContextPackageBinding, PortError> {
        commit_prepared_package(self.store, self.artifacts, prepared)
    }
}

#[derive(Debug)]
struct DisclosedBytes {
    bytes: Vec<u8>,
    digest: Sha256Digest,
    disclosure: Disclosure,
}

#[derive(Debug)]
struct DisclosureResult {
    decision_id: PolicyDecisionId,
    operation_digest: Sha256Digest,
    disclosed: Option<DisclosedBytes>,
}

fn disclose_source(
    disclosures: &dyn DisclosurePolicyEvaluator,
    policy_decisions: &dyn PolicyDecisionStore,
    policy: &ContextBuildPolicy,
    identity: &SourceIdentity,
    resource_class: ResourceClass,
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
        resource_class,
        channel,
        bytes,
    )
}

fn disclose_bytes(
    disclosures: &dyn DisclosurePolicyEvaluator,
    policy_decisions: &dyn PolicyDecisionStore,
    policy: &ContextBuildPolicy,
    capability: CapabilityRef,
    resource_class: ResourceClass,
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
            resource_class,
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
    let operation_digest = disclosure.decision.operation_digest.clone();
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
            operation_digest,
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
                operation_digest,
                disclosed: Some(DisclosedBytes {
                    bytes: effective_bytes,
                    digest: effective_digest,
                    disclosure: context_disclosure,
                }),
            })
        }
    }
}

fn finalize_package(
    store: &dyn ContextStore,
    artifacts: &dyn ContextArtifactPublisher,
    assembler: &dyn ContextPackageAssembler,
    policy: ContextBuildPolicy,
    draft: ContextPackageDraft,
    items: Vec<ContextEvidenceAssemblyItem>,
    decision_ids: Vec<PolicyDecisionId>,
) -> Result<ContextPackageBinding, PortError> {
    let prepared = prepare_package(assembler, policy, draft, items, decision_ids)?;
    commit_prepared_package(store, artifacts, prepared)
}

fn prepare_package(
    assembler: &dyn ContextPackageAssembler,
    policy: ContextBuildPolicy,
    draft: ContextPackageDraft,
    items: Vec<ContextEvidenceAssemblyItem>,
    decision_ids: Vec<PolicyDecisionId>,
) -> Result<PreparedContextPackage, PortError> {
    let expected_artifact_id = draft.descriptor.effective_content_artifact_id().clone();
    let expected_task_id = draft.descriptor.task_id().clone();
    let assembled = assembler.assemble(
        draft.descriptor,
        policy.clone(),
        items,
        decision_ids
            .iter()
            .map(|decision| decision.as_str().to_owned())
            .collect(),
    )?;
    if assembled.artifact.artifact_id != expected_artifact_id
        || assembled.artifact.task_id != expected_task_id
        || assembled.artifact.kind != ContextArtifactKind::ContextPackage
        || assembled.artifact.content_digest != digest(&assembled.artifact.bytes)?
        || assembled.descriptor.effective_content_artifact_id() != &expected_artifact_id
        || assembled.descriptor.task_id() != &expected_task_id
        || assembled.used_input_tokens
            != u64::try_from(assembled.artifact.bytes.len()).map_err(|_| integrity_failure())?
        || assembled.descriptor.budget().used_input_tokens() != assembled.used_input_tokens
    {
        return Err(integrity_failure());
    }
    let mut decision_ids = assembled
        .policy_decision_ids
        .iter()
        .cloned()
        .map(PolicyDecisionId::from_persisted)
        .collect::<Result<Vec<_>, _>>()?;
    normalize_decision_ids(&mut decision_ids);
    let policy_set = PolicyDecisionSet::new(
        policy.policy_snapshot_digest,
        decision_ids
            .iter()
            .map(|decision| decision.as_str().to_owned())
            .collect(),
    )
    .map_err(|_| integrity_failure())?;
    let artifact = ContextPackageArtifact::new(
        expected_artifact_id,
        assembled.artifact.content_digest.clone(),
        assembled.artifact.content_digest.clone(),
    )
    .map_err(|_| integrity_failure())?;
    let binding = ContextPackageBinding::new(
        assembled.descriptor,
        policy_set,
        artifact,
        assembled.members,
    )
    .map_err(|_| integrity_failure())?;
    let persistence = ContextPackagePersistence {
        package: ContextPackageRecord {
            binding: binding.clone(),
        },
        policy_decision_ids: decision_ids,
    };
    validate_package_persistence(&persistence)?;
    Ok(PreparedContextPackage {
        artifact: assembled.artifact,
        persistence,
        provenance: assembled.provenance,
        redaction_report_ids: assembled.redaction_report_ids,
    })
}

fn commit_prepared_package(
    store: &dyn ContextStore,
    artifacts: &dyn ContextArtifactPublisher,
    prepared: PreparedContextPackage,
) -> Result<ContextPackageBinding, PortError> {
    let binding = prepared.persistence.package.binding.clone();
    artifacts.publish(prepared.artifact)?;
    store.persist_package_with_policy_decisions(prepared.persistence)?;
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
                || !snapshot_revision_matches(request, item.identity.revision())
        })
    {
        Err(integrity_failure())
    } else {
        Ok(())
    }
}

fn snapshot_revision_matches(request: &SourceSnapshotRequest, revision: &str) -> bool {
    revision == request.revision
        || revision
            == format!(
                "worktree:{}:{}",
                request.revision,
                request.repository_fingerprint.as_str()
            )
}

fn validate_source_content(identity: &SourceIdentity, bytes: &[u8]) -> Result<(), PortError> {
    if &digest(bytes)? == identity.content_hash() {
        Ok(())
    } else {
        Err(integrity_failure())
    }
}

fn validate_artifact_content(
    reference: &ContextArtifactRef,
    bytes: &[u8],
) -> Result<(), PortError> {
    if digest(bytes)? == reference.content_digest
        && u64::try_from(bytes.len()).map_err(|_| integrity_failure())? == reference.size_bytes
    {
        Ok(())
    } else {
        Err(integrity_failure())
    }
}

fn validate_canonical_metadata(bytes: &[u8]) -> Result<(), PortError> {
    let value: serde_json::Value =
        serde_json::from_slice(bytes).map_err(|_| integrity_failure())?;
    let canonical = serde_json_canonicalizer::to_vec(&value).map_err(|_| integrity_failure())?;
    if canonical == bytes {
        Ok(())
    } else {
        Err(integrity_failure())
    }
}

fn validated_label(value: impl Into<String>) -> Result<String, PortError> {
    let value = value.into();
    if value.trim().is_empty() || value.len() > 256 || value.contains('\0') {
        Err(invalid_input())
    } else {
        Ok(value)
    }
}

fn validate_package_task(package: &ContextPackageDraft, task_id: &TaskId) -> Result<(), PortError> {
    if package.descriptor.task_id() == task_id {
        Ok(())
    } else {
        Err(invalid_input())
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

fn normalize_decision_ids(decision_ids: &mut Vec<PolicyDecisionId>) {
    decision_ids.sort_by(|left, right| left.as_str().cmp(right.as_str()));
    decision_ids.dedup();
}

fn classification_request_digest(
    task_id: &TaskId,
    document_id: &str,
    member_id: &str,
    identity: &SourceIdentity,
    content_artifact: &ContextArtifactRef,
) -> Result<Sha256Digest, PortError> {
    canonical_value_digest(serde_json::json!({
        "schema": "context-classification-request.v1",
        "taskId": task_id.as_str(),
        "documentId": document_id,
        "memberId": member_id,
        "source": {
            "projectId": identity.project_id().as_str(),
            "revision": identity.revision(),
            "pathIdentity": identity.path_identity(),
            "contentHash": identity.content_hash().as_str(),
        },
        "contentArtifact": {
            "artifactId": content_artifact.artifact_id.as_str(),
            "contentDigest": content_artifact.content_digest.as_str(),
            "sizeBytes": content_artifact.size_bytes,
        },
    }))
}

fn classification_result_digest(
    request_digest: &Sha256Digest,
    sensitivity: ContextSensitivity,
    evidence: &ContextArtifactRef,
    classified_at: Timestamp,
) -> Result<Sha256Digest, PortError> {
    canonical_value_digest(serde_json::json!({
        "schema": "context-classification-result.v1",
        "requestDigest": request_digest.as_str(),
        "sensitivity": sensitivity.as_str(),
        "evidence": {
            "artifactId": evidence.artifact_id.as_str(),
            "contentDigest": evidence.content_digest.as_str(),
            "sizeBytes": evidence.size_bytes,
        },
        "classifiedAtUnixSeconds": classified_at.unix_seconds(),
    }))
}

fn index_provenance_digest(
    authority: ContextIndexAuthority<'_>,
    index_metadata: &ContextPolicyDecisionRef,
    index_content: &ContextPolicyDecisionRef,
) -> Result<Sha256Digest, PortError> {
    canonical_value_digest(serde_json::json!({
        "schema": "context-index-provenance.v1",
        "taskId": authority.task_id.as_str(),
        "documentId": authority.document_id,
        "memberId": authority.member_id,
        "source": {
            "projectId": authority.identity.project_id().as_str(),
            "revision": authority.identity.revision(),
            "pathIdentity": authority.identity.path_identity(),
            "contentHash": authority.identity.content_hash().as_str(),
        },
        "artifact": {
            "artifactId": authority.artifact.artifact_id().as_str(),
            "contentDigest": authority.artifact.content_digest().as_str(),
            "sizeBytes": authority.artifact.size_bytes(),
        },
        "metadataDigest": digest(authority.metadata)?.as_str(),
        "lineRange": authority.line_range.map(|range| serde_json::json!({
            "start": range.start(),
            "end": range.end(),
        })),
        "symbol": authority.symbol,
        "createdAtUnixSeconds": authority.created_at.unix_seconds(),
        "classificationDigest": authority.classification.result_digest().as_str(),
        "indexMetadata": {
            "decisionId": index_metadata.decision_id.as_str(),
            "operationDigest": index_metadata.operation_digest.as_str(),
        },
        "indexContent": {
            "decisionId": index_content.decision_id.as_str(),
            "operationDigest": index_content.operation_digest.as_str(),
        },
    }))
}

fn validate_index_authority(
    authority: ContextIndexAuthority<'_>,
    provenance: &ContextIndexProvenance,
) -> Result<(), PortError> {
    validate_canonical_metadata(authority.metadata)?;
    authority.artifact.validate()?;
    authority.classification.validate_rehydrated()?;
    if authority.created_at.unix_seconds() <= 0 {
        return Err(invalid_input());
    }
    provenance.validate(authority)
}

fn canonical_value_digest(value: serde_json::Value) -> Result<Sha256Digest, PortError> {
    let bytes = serde_json_canonicalizer::to_vec(&value).map_err(|_| integrity_failure())?;
    digest(&bytes)
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
