use std::{
    fmt::Write,
    sync::{Arc, Mutex, OnceLock},
};

use local_agent_terminal_application::{
    AgentContextQueryCommit, AgentRuntime, ArtifactRef, ArtifactStore, ArtifactWriteReservation,
    BuildInitialContext, BuildInitialContextRequest, CanonicalJsonRequest, Clock,
    ContextArtifactKind, ContextArtifactPublisher, ContextArtifactReader, ContextArtifactRef,
    ContextPackageBinding, ContextPackageDescriptor, ContextRetrievalAuthority,
    ImmutableContextArtifact, InspectRepository, PolicyDecisionId, PolicyDecisionStore, PortError,
    QueryContext, QueryContextRequest, RecordedPolicyDecision, RepositoryContextSource,
    RepositoryGateway, RepositoryLocator, ReservedArtifact, RetrievedContextItem, Retryability,
    SafeErrorClassification, Sha256Digest, SourceSnapshotRequest, TaskId, TaskQuery,
    WorkspaceEvidenceStore,
};
use local_agent_terminal_context_engine::{
    BuiltContextPackage, ContextPackageBuildRequest, ContextPackageBuilder,
};
use local_agent_terminal_policy_engine::{PolicyContextSourceClassifier, VersionedPolicyEngine};
use local_agent_terminal_repository_git::{GitRepositoryContextSource, GitRepositoryGateway};
use local_agent_terminal_storage_files::{
    ContentAddressedArtifactReader, ContentAddressedArtifactStore, JournaledArtifactWriter,
};
use local_agent_terminal_storage_sqlite::SqliteStore;
use sha2::{Digest, Sha256};

use crate::workspace_monitor::publish_canonical_json;

pub(crate) const DEFAULT_POLICY_BUNDLE: &str = r#"{
  "version": 1,
  "rules": [
    {"id":"default-deny-process","effect":"deny","action":"process.exec"},
    {"id":"deny-secret-index-metadata","effect":"deny","action":"context.index_metadata","resourceClass":"secret"},
    {"id":"deny-secret-index-content","effect":"deny","action":"context.index_content","resourceClass":"secret"},
    {"id":"deny-secret-retrieval","effect":"deny","action":"context.retrieve_item","resourceClass":"secret"},
    {"id":"deny-secret-final-package","effect":"deny","action":"context.final_package","resourceClass":"secret"},
    {"id":"index-metadata","effect":"allow_with_redaction","action":"context.index_metadata","redactions":["secret_scanner"]},
    {"id":"index-content","effect":"allow_with_redaction","action":"context.index_content","redactions":["secret_scanner"]},
    {"id":"retrieved-item","effect":"allow_with_redaction","action":"context.retrieve_item","redactions":["secret_scanner"]},
    {"id":"final-context-package","effect":"allow_with_redaction","action":"context.final_package","redactions":["secret_scanner"]},
    {"id":"structured-read","effect":"allow_with_redaction","action":"context.disclose","redactions":["secret_scanner"]},
    {"id":"tool-display","effect":"allow_with_redaction","action":"tool.approval.display","redactions":["secret_scanner"]}
  ]
}"#;

pub(crate) fn compose_context_runtime(
    database: SqliteStore,
    artifacts: Arc<ContentAddressedArtifactStore>,
    repositories: GitRepositoryGateway,
) -> Result<Arc<ContextRuntime>, PortError> {
    let policy = Arc::new(VersionedPolicyEngine::from_json(DEFAULT_POLICY_BUNDLE)?);
    let database = database.with_artifact_reader(Arc::new(ContentAddressedArtifactReader));
    Ok(Arc::new(ContextRuntime::new(
        database,
        artifacts,
        policy,
        repositories,
    )))
}

/// Owns the outer ports needed to construct policy-bound context packages.
///
/// Context selection, budgeting, disclosure, and redaction policy remain in
/// `context-engine`; this type only supplies the concrete application ports.
pub struct ContextRuntime {
    database: SqliteStore,
    artifacts: Arc<ContentAddressedArtifactStore>,
    policy: Arc<VersionedPolicyEngine>,
    repositories: GitRepositoryGateway,
    agents: OnceLock<Arc<dyn AgentRuntime>>,
}

impl ContextRuntime {
    fn new(
        database: SqliteStore,
        artifacts: Arc<ContentAddressedArtifactStore>,
        policy: Arc<VersionedPolicyEngine>,
        repositories: GitRepositoryGateway,
    ) -> Self {
        Self {
            database,
            artifacts,
            policy,
            repositories,
            agents: OnceLock::new(),
        }
    }

    pub(crate) fn attach_agents(&self, agents: Arc<dyn AgentRuntime>) -> Result<(), PortError> {
        self.agents.set(agents).map_err(|_| conflict())
    }

    pub fn build_initial(
        &self,
        locator: RepositoryLocator,
        captured_at: &str,
        request: BuildInitialContextRequest,
    ) -> Result<ContextPackageBinding, PortError> {
        if &request.policy.policy_snapshot_digest != self.policy.snapshot_digest() {
            return Err(integrity_failure());
        }
        let source = GitRepositoryContextSource::new(locator, captured_at)?;
        let classifier = PolicyContextSourceClassifier::new(request.policy.evaluated_at)?;
        let publisher =
            self.publisher_for(&request.package.descriptor, &request.policy.actor.agent_id)?;
        let assembler = ContextPackageBuilder::new(self.policy.as_ref(), &self.database);
        BuildInitialContext::new(
            &source,
            &classifier,
            &self.database,
            &publisher,
            self.policy.as_ref(),
            &self.database,
            &assembler,
        )
        .execute(request)
    }

    pub fn query(&self, request: QueryContextRequest) -> Result<ContextPackageBinding, PortError> {
        let prepared = self.prepare_query(request)?;
        self.commit_query(prepared)
    }

    pub(crate) fn prepare_query(
        &self,
        request: QueryContextRequest,
    ) -> Result<AgentContextQueryCommit, PortError> {
        if &request.policy.policy_snapshot_digest != self.policy.snapshot_digest() {
            return Err(integrity_failure());
        }
        let publisher =
            self.query_artifacts_for(&request.package.descriptor, &request.policy.actor.agent_id)?;
        let decisions = BufferedPolicyDecisionStore::default();
        let assembler = ContextPackageBuilder::new(self.policy.as_ref(), &decisions);
        let package = QueryContext::new(
            &self.database,
            &publisher,
            &publisher,
            self.policy.as_ref(),
            &decisions,
            &assembler,
            self,
        )
        .prepare(request)?;
        let policy_decisions = decisions.records()?;
        if policy_decisions.iter().any(|record| {
            let decision_id = PolicyDecisionId::from_decision(&record.decision);
            !package
                .policy_decision_ids()
                .iter()
                .any(|persisted| persisted == &decision_id)
        }) {
            return Err(integrity_failure());
        }
        Ok(AgentContextQueryCommit {
            package,
            policy_decisions,
        })
    }

    pub(crate) fn commit_query(
        &self,
        prepared: AgentContextQueryCommit,
    ) -> Result<ContextPackageBinding, PortError> {
        for decision in &prepared.policy_decisions {
            let expected = PolicyDecisionId::from_decision(&decision.decision);
            if self.database.record(decision.clone())? != expected {
                return Err(integrity_failure());
            }
        }
        let publisher = self.publisher_for(
            prepared.package.binding().descriptor(),
            prepared.package.binding().descriptor().agent_id(),
        )?;
        let assembler = ContextPackageBuilder::new(self.policy.as_ref(), &self.database);
        QueryContext::new(
            &self.database,
            &publisher,
            &publisher,
            self.policy.as_ref(),
            &self.database,
            &assembler,
            self,
        )
        .commit(prepared.package)
    }

    fn publisher_for(
        &self,
        descriptor: &ContextPackageDescriptor,
        policy_agent_id: &str,
    ) -> Result<ProductionContextArtifacts, PortError> {
        if descriptor.agent_id() != policy_agent_id {
            return Err(invalid_input());
        }
        let agent = self
            .agents
            .get()
            .ok_or_else(unavailable)?
            .list_agents()?
            .into_iter()
            .find(|agent| agent.agent_id == descriptor.agent_id())
            .ok_or_else(unavailable)?;
        let publisher = ProductionContextArtifacts {
            database: self.database.clone(),
            artifacts: Arc::clone(&self.artifacts),
        };
        publisher.publish_manifest(
            descriptor.task_id(),
            descriptor.agent_manifest_artifact_id(),
            &agent.manifest_json,
            &agent.manifest_digest,
        )?;
        Ok(publisher)
    }

    fn query_artifacts_for(
        &self,
        descriptor: &ContextPackageDescriptor,
        policy_agent_id: &str,
    ) -> Result<ProductionContextArtifacts, PortError> {
        if descriptor.agent_id() != policy_agent_id {
            return Err(invalid_input());
        }
        let _agent = self
            .agents
            .get()
            .ok_or_else(unavailable)?
            .list_agents()?
            .into_iter()
            .find(|agent| agent.agent_id == descriptor.agent_id())
            .ok_or_else(unavailable)?;
        Ok(ProductionContextArtifacts {
            database: self.database.clone(),
            artifacts: Arc::clone(&self.artifacts),
        })
    }

    pub fn policy_snapshot_digest(&self) -> &Sha256Digest {
        self.policy.snapshot_digest()
    }

    pub fn build(
        &self,
        request: ContextPackageBuildRequest,
    ) -> Result<BuiltContextPackage, PortError> {
        ContextPackageBuilder::new(self.policy.as_ref(), &self.database).build(request)
    }
}

#[derive(Default)]
struct BufferedPolicyDecisionStore {
    decisions: Mutex<Vec<(PolicyDecisionId, RecordedPolicyDecision)>>,
}

impl BufferedPolicyDecisionStore {
    fn records(&self) -> Result<Vec<RecordedPolicyDecision>, PortError> {
        self.decisions
            .lock()
            .map(|decisions| {
                decisions
                    .iter()
                    .map(|(_, decision)| decision.clone())
                    .collect()
            })
            .map_err(|_| unavailable())
    }
}

impl PolicyDecisionStore for BufferedPolicyDecisionStore {
    fn record(&self, decision: RecordedPolicyDecision) -> Result<PolicyDecisionId, PortError> {
        let decision_id = PolicyDecisionId::from_decision(&decision.decision);
        let mut decisions = self.decisions.lock().map_err(|_| unavailable())?;
        if let Some((_, existing)) = decisions.iter().find(|(id, _)| id == &decision_id) {
            if existing != &decision {
                return Err(integrity_failure());
            }
            return Ok(decision_id);
        }
        decisions.push((decision_id.clone(), decision));
        Ok(decision_id)
    }
}

impl ContextRetrievalAuthority for ContextRuntime {
    fn verify_current(
        &self,
        task_id: &TaskId,
        items: &[RetrievedContextItem],
    ) -> Result<(), PortError> {
        let task = self.database.task(task_id)?;
        let path = self.database.task_repository_path(task_id)?;
        let locator = self.repositories.locate_persisted(&path)?;
        let inspection = self.repositories.inspect(InspectRepository {
            locator: locator.clone(),
        })?;
        let captured_at = self.database.now_utc()?;
        let source = GitRepositoryContextSource::new(locator, &captured_at)?;
        let repository_fingerprint = source.repository_fingerprint()?;
        let snapshot = source.snapshot(SourceSnapshotRequest {
            project_id: task.project_id,
            task_id: task_id.clone(),
            revision: inspection.fingerprint.head().as_str().to_owned(),
            repository_fingerprint,
        })?;
        if items.iter().any(|persisted| {
            !snapshot.items.iter().any(|current| {
                current.member_id == persisted.member_id && current.identity == persisted.identity
            })
        }) {
            return Err(conflict());
        }
        Ok(())
    }
}

struct ProductionContextArtifacts {
    database: SqliteStore,
    artifacts: Arc<ContentAddressedArtifactStore>,
}

impl ProductionContextArtifacts {
    fn publish_manifest(
        &self,
        task_id: &local_agent_terminal_application::TaskId,
        artifact_id: &local_agent_terminal_application::ArtifactId,
        manifest_json: &[u8],
        expected_digest: &Sha256Digest,
    ) -> Result<(), PortError> {
        let value = serde_json::from_slice(manifest_json).map_err(|_| integrity_failure())?;
        let task = self.database.task(task_id)?;
        let request = CanonicalJsonRequest::new(
            artifact_id.clone(),
            task.project_id,
            Some(task_id.clone()),
            "manifest",
            format!("agent-manifests/{}.json", artifact_id.as_str()),
            "core",
            "context-runtime",
            &value,
            format!("agent-manifest:{}", artifact_id.as_str()),
        )?;
        if request.canonical_bytes != manifest_json
            || request.expected_hash != expected_digest.as_str()
        {
            return Err(integrity_failure());
        }
        let published = publish_canonical_json(&self.database, self.artifacts.as_ref(), request)?;
        if published.content_hash != expected_digest.as_str() {
            return Err(integrity_failure());
        }
        Ok(())
    }
}

impl ContextArtifactPublisher for ProductionContextArtifacts {
    fn publish(&self, artifact: ImmutableContextArtifact) -> Result<(), PortError> {
        validate_artifact(&artifact)?;
        let task = self.database.task(&artifact.task_id)?;
        if let Some(existing) = self.database.available_evidence(&artifact.artifact_id)? {
            if existing.project_id != task.project_id
                || existing.task_id.as_ref() != Some(&artifact.task_id)
                || existing.content_hash != artifact.content_digest.as_str()
                || existing.size_bytes
                    != u64::try_from(artifact.bytes.len()).map_err(|_| invalid_input())?
            {
                return Err(integrity_failure());
            }
            return Ok(());
        }
        let created_at = self.database.now_utc()?;
        let artifact_type = artifact_kind(artifact.kind);
        let digest = artifact.content_digest.as_str();
        let written =
            JournaledArtifactWriter::new(self.artifacts.as_ref(), &self.database, &self.database)
                .write(
                ArtifactWriteReservation {
                    operation_id: format!("context-artifact:{}", artifact.artifact_id.as_str()),
                    artifact: ReservedArtifact {
                        artifact_id: artifact.artifact_id.as_str().to_owned(),
                        task_id: Some(artifact.task_id.clone()),
                        project_id: task.project_id.as_str().to_owned(),
                        artifact_type: artifact_type.to_owned(),
                        logical_path: format!(
                            "context/{}/{}",
                            artifact.task_id.as_str(),
                            artifact.artifact_id.as_str()
                        ),
                        content_hash: digest.to_owned(),
                        storage_key: storage_key(digest)?,
                        size_bytes: u64::try_from(artifact.bytes.len())
                            .map_err(|_| invalid_input())?,
                        mime_type: Some("application/octet-stream".to_owned()),
                        created_by_type: "core".to_owned(),
                        created_by_id: "context-runtime".to_owned(),
                        created_at: created_at.clone(),
                        supersedes: None,
                    },
                    temp_name: format!("{}.tmp", artifact.artifact_id.as_str()),
                    created_at,
                },
                &artifact.bytes,
            )?;
        if written.content_hash != digest
            || written.size_bytes
                != u64::try_from(artifact.bytes.len()).map_err(|_| invalid_input())?
        {
            return Err(integrity_failure());
        }
        Ok(())
    }
}

impl ContextArtifactReader for ProductionContextArtifacts {
    fn read(&self, artifact: &ContextArtifactRef) -> Result<Vec<u8>, PortError> {
        let reference = self
            .database
            .available_evidence(artifact.artifact_id())?
            .ok_or_else(unavailable)?;
        if reference.content_hash != artifact.content_digest().as_str()
            || reference.size_bytes != artifact.size_bytes()
        {
            return Err(integrity_failure());
        }
        Ok(self
            .artifacts
            .read(&ArtifactRef {
                content_hash: reference.content_hash,
                storage_key: reference.storage_key,
                size_bytes: reference.size_bytes,
            })?
            .bytes)
    }
}

fn validate_artifact(artifact: &ImmutableContextArtifact) -> Result<(), PortError> {
    if artifact.bytes.is_empty()
        || digest_bytes(&artifact.bytes).as_str() != artifact.content_digest.as_str()
    {
        Err(integrity_failure())
    } else {
        Ok(())
    }
}

const fn artifact_kind(kind: ContextArtifactKind) -> &'static str {
    match kind {
        ContextArtifactKind::ClassificationEvidence => "context_classification",
        ContextArtifactKind::SourceChunk => "context_source_chunk",
        ContextArtifactKind::ContextPackage => "context_package",
    }
}

fn storage_key(digest: &str) -> Result<String, PortError> {
    let encoded = digest
        .strip_prefix("sha256:")
        .filter(|value| value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit()))
        .ok_or_else(integrity_failure)?;
    Ok(format!("objects/{}/{}", &encoded[..2], encoded))
}

fn digest_bytes(bytes: &[u8]) -> Sha256Digest {
    let digest = Sha256::digest(bytes);
    let mut encoded = String::with_capacity(71);
    encoded.push_str("sha256:");
    for byte in digest {
        write!(encoded, "{byte:02x}").expect("writing to String cannot fail");
    }
    Sha256Digest::new(encoded).expect("SHA-256 formatting is valid")
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

fn conflict() -> PortError {
    PortError::failure(
        SafeErrorClassification::Conflict,
        Retryability::NonRetryable,
    )
}

fn unavailable() -> PortError {
    PortError::failure(
        SafeErrorClassification::Unavailable,
        Retryability::Retryable,
    )
}
