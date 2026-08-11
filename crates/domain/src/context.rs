use std::fmt;

use crate::{ArtifactId, ProjectId, Sha256Digest, TaskId, Timestamp};

const MAX_IDENTIFIER_LENGTH: usize = 256;
const MAX_OBJECTIVE_LENGTH: usize = 65_536;
const MAX_SYMBOL_LENGTH: usize = 1_024;
const MAX_CONTEXT_TOKENS: u64 = 1_000_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContextError {
    InvalidIdentity,
    InvalidLineRange,
    InvalidCitation,
    StaleEvidence,
    InvalidDisclosure,
    InvalidBudget,
    BudgetExceeded,
    InvalidVersion,
    InvalidPackage,
    DuplicatePolicyDecision,
    ArtifactDigestMismatch,
    CrossTaskReference,
    ConflictingMember,
}

impl fmt::Display for ContextError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidIdentity => "context identity is invalid",
            Self::InvalidLineRange => "evidence line range is invalid",
            Self::InvalidCitation => "evidence citation is invalid",
            Self::StaleEvidence => "evidence does not match the current source",
            Self::InvalidDisclosure => "context disclosure is invalid",
            Self::InvalidBudget => "context budget is invalid",
            Self::BudgetExceeded => "context budget is exceeded",
            Self::InvalidVersion => "context version identity is invalid",
            Self::InvalidPackage => "context package is invalid",
            Self::DuplicatePolicyDecision => "context package repeats a policy decision",
            Self::ArtifactDigestMismatch => {
                "context artifact digest does not match effective content"
            }
            Self::CrossTaskReference => "context package member belongs to another task",
            Self::ConflictingMember => "context package repeats a member with different content",
        })
    }
}

impl std::error::Error for ContextError {}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SourceIdentity {
    project_id: ProjectId,
    revision: String,
    path_identity: String,
    content_hash: Sha256Digest,
}

impl SourceIdentity {
    pub fn new(
        project_id: ProjectId,
        revision: impl Into<String>,
        path_identity: impl Into<String>,
        content_hash: Sha256Digest,
    ) -> Result<Self, ContextError> {
        let revision = revision.into();
        let path_identity = path_identity.into();
        if !valid_identifier(project_id.as_str())
            || !valid_identifier(&revision)
            || !valid_identifier(&path_identity)
        {
            return Err(ContextError::InvalidIdentity);
        }
        Ok(Self {
            project_id,
            revision,
            path_identity,
            content_hash,
        })
    }

    pub fn project_id(&self) -> &ProjectId {
        &self.project_id
    }

    pub fn revision(&self) -> &str {
        &self.revision
    }

    pub fn path_identity(&self) -> &str {
        &self.path_identity
    }

    pub fn content_hash(&self) -> &Sha256Digest {
        &self.content_hash
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct LineRange {
    start: u32,
    end: u32,
}

impl LineRange {
    pub fn new(start: u32, end: u32) -> Result<Self, ContextError> {
        if start == 0 || end < start {
            return Err(ContextError::InvalidLineRange);
        }
        Ok(Self { start, end })
    }

    pub const fn start(self) -> u32 {
        self.start
    }

    pub const fn end(self) -> u32 {
        self.end
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum EvidenceFreshness {
    Current,
    Stale,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct EvidenceCitation {
    source: SourceIdentity,
    range: Option<LineRange>,
    symbol: Option<String>,
    freshness: EvidenceFreshness,
}

impl EvidenceCitation {
    pub fn new(
        source: SourceIdentity,
        range: Option<LineRange>,
        symbol: Option<&str>,
        freshness: EvidenceFreshness,
    ) -> Result<Self, ContextError> {
        let symbol = symbol.map(str::to_owned);
        if symbol
            .as_deref()
            .is_some_and(|value| !valid_text(value, MAX_SYMBOL_LENGTH))
        {
            return Err(ContextError::InvalidCitation);
        }
        Ok(Self {
            source,
            range,
            symbol,
            freshness,
        })
    }

    pub fn source(&self) -> &SourceIdentity {
        &self.source
    }

    pub const fn range(&self) -> Option<LineRange> {
        self.range
    }

    pub fn symbol(&self) -> Option<&str> {
        self.symbol.as_deref()
    }

    pub const fn freshness(&self) -> EvidenceFreshness {
        self.freshness
    }

    pub fn validate_current(&self, current_source: &SourceIdentity) -> Result<(), ContextError> {
        if self.freshness == EvidenceFreshness::Current && self.source == *current_source {
            Ok(())
        } else {
            Err(ContextError::StaleEvidence)
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum DisclosureKind {
    Allowed,
    Redacted,
    Denied,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Disclosure {
    kind: DisclosureKind,
    stable_report_id: Option<String>,
}

impl Disclosure {
    pub const fn allowed() -> Self {
        Self {
            kind: DisclosureKind::Allowed,
            stable_report_id: None,
        }
    }

    pub fn redacted(stable_report_id: &str) -> Result<Self, ContextError> {
        Self::with_report(DisclosureKind::Redacted, stable_report_id)
    }

    pub fn denied(stable_report_id: &str) -> Result<Self, ContextError> {
        Self::with_report(DisclosureKind::Denied, stable_report_id)
    }

    fn with_report(kind: DisclosureKind, stable_report_id: &str) -> Result<Self, ContextError> {
        if !valid_identifier(stable_report_id) {
            return Err(ContextError::InvalidDisclosure);
        }
        Ok(Self {
            kind,
            stable_report_id: Some(stable_report_id.to_owned()),
        })
    }

    pub const fn kind(&self) -> DisclosureKind {
        self.kind
    }

    pub fn stable_report_id(&self) -> Option<&str> {
        self.stable_report_id.as_deref()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ContextBudget {
    max_tokens: u64,
    reserved_response_tokens: u64,
    used_input_tokens: u64,
}

impl ContextBudget {
    pub fn new(max_tokens: u64, reserved_response_tokens: u64) -> Result<Self, ContextError> {
        if max_tokens == 0
            || max_tokens > MAX_CONTEXT_TOKENS
            || reserved_response_tokens == 0
            || reserved_response_tokens >= max_tokens
        {
            return Err(ContextError::InvalidBudget);
        }
        Ok(Self {
            max_tokens,
            reserved_response_tokens,
            used_input_tokens: 0,
        })
    }

    pub fn consume_input_tokens(&mut self, tokens: u64) -> Result<(), ContextError> {
        let Some(next) = self.used_input_tokens.checked_add(tokens) else {
            return Err(ContextError::BudgetExceeded);
        };
        if next > self.max_tokens - self.reserved_response_tokens {
            return Err(ContextError::BudgetExceeded);
        }
        self.used_input_tokens = next;
        Ok(())
    }

    pub const fn max_tokens(self) -> u64 {
        self.max_tokens
    }

    pub const fn reserved_response_tokens(self) -> u64 {
        self.reserved_response_tokens
    }

    pub const fn used_input_tokens(self) -> u64 {
        self.used_input_tokens
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContextVersionSet {
    prompt_template: String,
    retrieval_pipeline: String,
    tokenizer: String,
}

impl ContextVersionSet {
    pub fn new(
        prompt_template: &str,
        retrieval_pipeline: &str,
        tokenizer: &str,
    ) -> Result<Self, ContextError> {
        if !valid_version(prompt_template)
            || !valid_version(retrieval_pipeline)
            || !valid_version(tokenizer)
        {
            return Err(ContextError::InvalidVersion);
        }
        Ok(Self {
            prompt_template: prompt_template.to_owned(),
            retrieval_pipeline: retrieval_pipeline.to_owned(),
            tokenizer: tokenizer.to_owned(),
        })
    }

    pub fn prompt_template(&self) -> &str {
        &self.prompt_template
    }

    pub fn retrieval_pipeline(&self) -> &str {
        &self.retrieval_pipeline
    }

    pub fn tokenizer(&self) -> &str {
        &self.tokenizer
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContextPackageIdentity {
    package_id: String,
    task_id: TaskId,
    agent_id: String,
    role: String,
    agent_manifest_artifact_id: ArtifactId,
    effective_content_artifact_id: ArtifactId,
    created_at: Timestamp,
}

impl ContextPackageIdentity {
    pub fn new(
        package_id: &str,
        task_id: TaskId,
        agent_id: &str,
        role: &str,
        agent_manifest_artifact_id: ArtifactId,
        effective_content_artifact_id: ArtifactId,
        created_at: Timestamp,
    ) -> Result<Self, ContextError> {
        if !valid_identifier(package_id)
            || !valid_identifier(task_id.as_str())
            || !valid_identifier(agent_id)
            || !valid_identifier(role)
            || !valid_identifier(agent_manifest_artifact_id.as_str())
            || !valid_identifier(effective_content_artifact_id.as_str())
        {
            return Err(ContextError::InvalidPackage);
        }
        Ok(Self {
            package_id: package_id.to_owned(),
            task_id,
            agent_id: agent_id.to_owned(),
            role: role.to_owned(),
            agent_manifest_artifact_id,
            effective_content_artifact_id,
            created_at,
        })
    }

    pub fn package_id(&self) -> &str {
        &self.package_id
    }

    pub fn task_id(&self) -> &TaskId {
        &self.task_id
    }

    pub fn agent_id(&self) -> &str {
        &self.agent_id
    }

    pub fn role(&self) -> &str {
        &self.role
    }

    pub fn agent_manifest_artifact_id(&self) -> &ArtifactId {
        &self.agent_manifest_artifact_id
    }

    pub fn effective_content_artifact_id(&self) -> &ArtifactId {
        &self.effective_content_artifact_id
    }

    pub const fn created_at(&self) -> Timestamp {
        self.created_at
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContextPackageDescriptor {
    identity: ContextPackageIdentity,
    objective: String,
    versions: ContextVersionSet,
    budget: ContextBudget,
}

impl ContextPackageDescriptor {
    pub fn new(
        identity: ContextPackageIdentity,
        objective: &str,
        versions: ContextVersionSet,
        budget: ContextBudget,
    ) -> Result<Self, ContextError> {
        if !valid_text(objective, MAX_OBJECTIVE_LENGTH) {
            return Err(ContextError::InvalidPackage);
        }
        Ok(Self {
            identity,
            objective: objective.to_owned(),
            versions,
            budget,
        })
    }

    pub fn package_id(&self) -> &str {
        self.identity.package_id()
    }

    pub fn task_id(&self) -> &TaskId {
        self.identity.task_id()
    }

    pub fn agent_id(&self) -> &str {
        self.identity.agent_id()
    }

    pub fn role(&self) -> &str {
        self.identity.role()
    }

    pub fn agent_manifest_artifact_id(&self) -> &ArtifactId {
        self.identity.agent_manifest_artifact_id()
    }

    pub fn effective_content_artifact_id(&self) -> &ArtifactId {
        self.identity.effective_content_artifact_id()
    }

    pub const fn created_at(&self) -> Timestamp {
        self.identity.created_at()
    }

    pub fn objective(&self) -> &str {
        &self.objective
    }

    pub const fn budget(&self) -> ContextBudget {
        self.budget
    }

    pub fn consume_input_tokens(&mut self, tokens: u64) -> Result<(), ContextError> {
        self.budget.consume_input_tokens(tokens)
    }

    pub fn versions(&self) -> &ContextVersionSet {
        &self.versions
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyDecisionSet {
    policy_snapshot_digest: Sha256Digest,
    decision_ids: Vec<String>,
}

impl PolicyDecisionSet {
    pub fn new(
        policy_snapshot_digest: Sha256Digest,
        mut decision_ids: Vec<String>,
    ) -> Result<Self, ContextError> {
        if decision_ids.is_empty() || decision_ids.iter().any(|id| !valid_identifier(id)) {
            return Err(ContextError::InvalidPackage);
        }
        decision_ids.sort();
        if decision_ids.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(ContextError::DuplicatePolicyDecision);
        }
        Ok(Self {
            policy_snapshot_digest,
            decision_ids,
        })
    }

    pub fn policy_snapshot_digest(&self) -> &Sha256Digest {
        &self.policy_snapshot_digest
    }

    pub fn decision_ids(&self) -> &[String] {
        &self.decision_ids
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContextPackageArtifact {
    artifact_id: ArtifactId,
    content_digest: Sha256Digest,
}

impl ContextPackageArtifact {
    pub fn new(
        artifact_id: ArtifactId,
        artifact_digest: Sha256Digest,
        content_digest: Sha256Digest,
    ) -> Result<Self, ContextError> {
        if !valid_identifier(artifact_id.as_str()) {
            return Err(ContextError::InvalidPackage);
        }
        if artifact_digest != content_digest {
            return Err(ContextError::ArtifactDigestMismatch);
        }
        Ok(Self {
            artifact_id,
            content_digest,
        })
    }

    pub fn artifact_id(&self) -> &ArtifactId {
        &self.artifact_id
    }

    pub fn content_digest(&self) -> &Sha256Digest {
        &self.content_digest
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContextPackageMember {
    member_id: String,
    task_id: TaskId,
    citation: EvidenceCitation,
    disclosure: Disclosure,
}

impl ContextPackageMember {
    pub fn new(
        member_id: &str,
        task_id: TaskId,
        citation: EvidenceCitation,
        disclosure: Disclosure,
    ) -> Result<Self, ContextError> {
        if !valid_identifier(member_id) || !valid_identifier(task_id.as_str()) {
            return Err(ContextError::InvalidPackage);
        }
        Ok(Self {
            member_id: member_id.to_owned(),
            task_id,
            citation,
            disclosure,
        })
    }

    pub fn member_id(&self) -> &str {
        &self.member_id
    }

    pub fn task_id(&self) -> &TaskId {
        &self.task_id
    }

    pub fn citation(&self) -> &EvidenceCitation {
        &self.citation
    }

    pub fn disclosure(&self) -> &Disclosure {
        &self.disclosure
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContextPackageBinding {
    descriptor: ContextPackageDescriptor,
    policy: PolicyDecisionSet,
    artifact: ContextPackageArtifact,
    members: Vec<ContextPackageMember>,
}

impl ContextPackageBinding {
    pub fn new(
        descriptor: ContextPackageDescriptor,
        policy: PolicyDecisionSet,
        artifact: ContextPackageArtifact,
        mut members: Vec<ContextPackageMember>,
    ) -> Result<Self, ContextError> {
        if artifact.artifact_id() != descriptor.effective_content_artifact_id() {
            return Err(ContextError::InvalidPackage);
        }
        if members
            .iter()
            .any(|member| member.task_id() != descriptor.task_id())
        {
            return Err(ContextError::CrossTaskReference);
        }
        members.sort_by(|left, right| left.member_id.cmp(&right.member_id));
        if members
            .windows(2)
            .any(|pair| pair[0].member_id == pair[1].member_id && pair[0] != pair[1])
        {
            return Err(ContextError::ConflictingMember);
        }
        members.dedup();
        Ok(Self {
            descriptor,
            policy,
            artifact,
            members,
        })
    }

    pub fn descriptor(&self) -> &ContextPackageDescriptor {
        &self.descriptor
    }

    pub fn policy(&self) -> &PolicyDecisionSet {
        &self.policy
    }

    pub fn artifact(&self) -> &ContextPackageArtifact {
        &self.artifact
    }

    pub fn members(&self) -> &[ContextPackageMember] {
        &self.members
    }
}

fn valid_identifier(value: &str) -> bool {
    !value.trim().is_empty() && value.len() <= MAX_IDENTIFIER_LENGTH && !value.contains('\0')
}

fn valid_text(value: &str, maximum_length: usize) -> bool {
    !value.trim().is_empty() && value.len() <= maximum_length && !value.contains('\0')
}

fn valid_version(value: &str) -> bool {
    if !valid_identifier(value) {
        return false;
    }
    let Some(delimiter_index) = value.rfind("-v").into_iter().chain(value.rfind(".v")).max() else {
        return false;
    };
    let name = &value[..delimiter_index];
    let version = &value[delimiter_index + 2..];
    !name.is_empty()
        && version.as_bytes().first().is_some_and(u8::is_ascii_digit)
        && version.bytes().all(|byte| byte.is_ascii_alphanumeric())
}
