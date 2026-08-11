use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use local_agent_terminal_application::{
    BuildInitialContext, BuildInitialContextRequest, ContextArtifactKind, ContextArtifactPublisher,
    ContextArtifactRef, ContextBuildPolicy, ContextClassificationOutcome, ContextLogicalIdentity,
    ContextPackageContract, ContextPackageDraft, ContextQuery, ContextRunReconstructibility,
    ContextSourceClassification, ContextSourceClassifier, ContextSourceRecord, ContextSourceState,
    ContextStore, DisclosureChannel, DisclosurePolicyEvaluator, DisclosureRequest,
    ImmutableContextArtifact, PolicyApprovedDisclosure, PolicyDecision, PortError,
    RepositoryContextSource, Retryability, SafeErrorClassification, SourceClassificationRequest,
    SourceIndexMetadata, SourceSnapshot, SourceSnapshotItem, SourceSnapshotRequest,
    SourceStateTransition,
};
use local_agent_terminal_context_engine::ContextPackageBuilder;
use local_agent_terminal_domain::{
    combine_policy_rules, ActorLocality, ArtifactId, ContextBudget, ContextPackageBinding,
    ContextPackageDescriptor, ContextPackageIdentity, ContextVersionSet, MatchedPolicyRule,
    PolicyActor, PolicyEffect, PolicyRuleId, PolicyVersion, ProjectId, ResourceClass, Sha256Digest,
    SourceIdentity, TaskId, TaskRisk, Timestamp, TrustTier,
};
use local_agent_terminal_storage_files::{
    ContentAddressedArtifactReader, ContentAddressedArtifactStore,
};
use local_agent_terminal_storage_sqlite::SqliteStore;
use rusqlite::{params, Connection};
use sha2::{Digest, Sha256};

static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

struct TestDatabase {
    directory: PathBuf,
    path: PathBuf,
    artifact_root: PathBuf,
}

impl TestDatabase {
    fn new() -> Self {
        Self::new_with_manifest_kind("manifest")
    }

    fn new_with_manifest_kind(manifest_kind: &str) -> Self {
        let directory = std::env::temp_dir().join(format!(
            "local-agent-terminal-context-store-test-{}-{}",
            std::process::id(),
            NEXT_TEMP.fetch_add(1, Ordering::Relaxed),
        ));
        fs::create_dir_all(&directory).unwrap();
        let artifact_root = directory.join("artifacts");
        fs::create_dir(&artifact_root).unwrap();
        let path = directory.join("state.sqlite3");
        SqliteStore::open(&path).unwrap();
        let database = Self {
            directory,
            path,
            artifact_root,
        };
        database.seed(manifest_kind);
        database
    }

    fn store(&self) -> SqliteStore {
        SqliteStore::open(&self.path)
            .unwrap()
            .with_artifact_reader(Arc::new(ContentAddressedArtifactReader))
    }

    fn connection(&self) -> Connection {
        let connection = Connection::open(&self.path).unwrap();
        connection
            .execute_batch("PRAGMA foreign_keys = ON;")
            .unwrap();
        connection
    }

    fn seed(&self, manifest_kind: &str) {
        let connection = self.connection();
        connection
            .execute(
                "INSERT INTO projects (
                    id, name, repository_path, repository_identity, created_at, updated_at,
                    policy_profile_id, artifact_root_mode, artifact_root_path
                 ) VALUES ('project-1', 'Project', 'C:/repo', 'repo-identity',
                    '2026-08-09T00:00:00Z', '2026-08-09T00:00:00Z', 'default',
                    'application_data', ?1)",
                [self.artifact_root.to_string_lossy().as_ref()],
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO tasks (
                    id, project_id, title, objective, phase, condition, operation_state,
                    risk_level, base_branch, base_commit, current_sequence, workspace_version,
                    fencing_epoch, created_at, updated_at
                 ) VALUES ('task-1', 'project-1', 'Task', 'Build context', 'ContextBuild',
                    'Active', 'None', 'medium', 'main', ?1, 0, 0, 1,
                    '2026-08-09T00:00:00Z', '2026-08-09T00:00:00Z')",
                ["a".repeat(40)],
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO agent_descriptors (
                    id, display_name, transport_type, trust_tier, manifest_json,
                    manifest_digest, executable_digest, enabled, containment_verified,
                    last_health_status, updated_at
                 ) VALUES ('agent-1', 'Agent', 'in_process', 'core_adapter', '{}', ?1,
                    NULL, 1, 1, 'healthy', '2026-08-09T00:00:00Z')",
                [digest(b"{}").as_str()],
            )
            .unwrap();
        drop(connection);
        self.publish_artifact(
            &ArtifactId::new("artifact-agent-manifest-1").unwrap(),
            manifest_kind,
            b"{}",
        )
        .unwrap();
    }

    fn publish_artifact(
        &self,
        artifact_id: &ArtifactId,
        artifact_type: &str,
        bytes: &[u8],
    ) -> Result<(), PortError> {
        use local_agent_terminal_application::{ArtifactStore, NewArtifact};

        let content_hash = digest(bytes);
        let physical = ContentAddressedArtifactStore::open(&self.artifact_root)
            .map_err(|_| failure(SafeErrorClassification::Internal))?
            .put(NewArtifact {
                expected_hash: content_hash.as_str().to_owned(),
                expected_size: u64::try_from(bytes.len())
                    .map_err(|_| failure(SafeErrorClassification::InvalidInput))?,
                content: bytes.to_vec(),
            })?;
        let connection = self.connection();
        connection
            .execute(
                "INSERT OR IGNORE INTO artifacts (
                    id, task_id, project_id, artifact_type, logical_path, content_hash,
                    storage_key, size_bytes, mime_type, availability, created_by_type,
                    created_by_id, created_at, supersedes, verification_state
                 ) VALUES (?1, 'task-1', 'project-1', ?2, ?3, ?4, ?5, ?6,
                    'application/json', 'available', 'core', 'context-test',
                    '2026-08-09T00:00:01Z', NULL, 'hash_verified')",
                params![
                    artifact_id.as_str(),
                    artifact_type,
                    format!("context/{}.json", artifact_id.as_str()),
                    content_hash.as_str(),
                    physical.storage_key,
                    i64::try_from(bytes.len())
                        .map_err(|_| failure(SafeErrorClassification::InvalidInput))?,
                ],
            )
            .map_err(|_| failure(SafeErrorClassification::Internal))?;
        let exact: bool = connection
            .query_row(
                "SELECT EXISTS(
                    SELECT 1 FROM artifacts
                    WHERE id = ?1 AND task_id = 'task-1' AND artifact_type = ?2
                      AND content_hash = ?3 AND storage_key = ?4 AND size_bytes = ?5
                 )",
                params![
                    artifact_id.as_str(),
                    artifact_type,
                    content_hash.as_str(),
                    physical.storage_key,
                    i64::try_from(bytes.len())
                        .map_err(|_| failure(SafeErrorClassification::InvalidInput))?,
                ],
                |row| row.get(0),
            )
            .map_err(|_| failure(SafeErrorClassification::Internal))?;
        if exact {
            Ok(())
        } else {
            Err(failure(SafeErrorClassification::Conflict))
        }
    }

    fn execute(&self, item: SourceSnapshotItem) -> Result<ContextPackageBinding, PortError> {
        let store = self.store();
        let source = Source {
            snapshot: source_snapshot(item),
        };
        let publisher = Publisher { database: self };
        let policy = AllowOrDenyPolicy;
        let assembler = ContextPackageBuilder::new(&policy, &store);
        BuildInitialContext::new(
            &source,
            &Classifier,
            &store,
            &publisher,
            &policy,
            &store,
            &assembler,
        )
        .execute(build_request())
    }
}

impl Drop for TestDatabase {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.directory);
    }
}

#[test]
fn sqlite_store_exposes_the_application_context_port() {
    fn accepts(_: &dyn ContextStore) {}

    let database = TestDatabase::new();
    accepts(&database.store());
}

#[test]
fn exact_replay_persists_queryable_context_and_every_policy_link_before_a_run() {
    let database = TestDatabase::new();
    let item = source_item("src/lib.rs", b"allowed source", "2026-08-09T00:00:00Z");

    let first = database.execute(item.clone()).unwrap();
    let second = database.execute(item).unwrap();

    assert_eq!(first, second);
    let connection = database.connection();
    assert_eq!(count(&connection, "source_documents"), 1);
    assert_eq!(count(&connection, "source_chunks"), 1);
    assert_eq!(count(&connection, "context_packages"), 1);
    assert_eq!(count(&connection, "agent_runs"), 0);
    assert_eq!(
        count(&connection, "context_package_policy_decisions"),
        i64::try_from(first.policy().decision_ids().len()).unwrap()
    );
    drop(connection);

    let content_hash = digest(b"allowed source");
    let found = database
        .store()
        .query(ContextQuery {
            task_id: TaskId::new("task-1").unwrap(),
            query_id: "query-revision-hash".to_owned(),
            terms: vec!["commit-1".to_owned(), content_hash.as_str().to_owned()],
            max_items: 10,
            max_tokens: 1_024,
        })
        .unwrap();
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].identity.path_identity(), "src/lib.rs");
    assert_eq!(found[0].identity.content_hash(), &content_hash);
}

#[test]
fn context_package_rejects_a_non_manifest_manifest_artifact() {
    let database = TestDatabase::new_with_manifest_kind("content");

    let error = database
        .execute(source_item(
            "src/lib.rs",
            b"allowed source",
            "2026-08-09T00:00:00Z",
        ))
        .unwrap_err();

    assert_eq!(
        error.safe_classification(),
        SafeErrorClassification::IntegrityFailure
    );
}

#[test]
fn replay_with_changed_source_projection_conflicts_without_partial_writes() {
    let database = TestDatabase::new();
    database
        .execute(source_item(
            "src/lib.rs",
            b"allowed source",
            "2026-08-09T00:00:00Z",
        ))
        .unwrap();

    let error = database
        .execute(source_item(
            "src/lib.rs",
            b"allowed source",
            "2026-08-09T00:00:02Z",
        ))
        .unwrap_err();

    assert_eq!(
        error.safe_classification(),
        SafeErrorClassification::Conflict
    );
    let connection = database.connection();
    assert_eq!(count(&connection, "source_documents"), 1);
    assert_eq!(count(&connection, "source_chunks"), 1);
    assert_eq!(count(&connection, "context_packages"), 1);
}

#[test]
fn denied_source_persists_only_a_redacted_identity_and_classification_evidence() {
    let database = TestDatabase::new();
    database
        .execute(source_item(
            "src/lib.rs",
            b"allowed source",
            "2026-08-09T00:00:00Z",
        ))
        .unwrap();
    let allowed = database
        .store()
        .query(ContextQuery {
            task_id: TaskId::new("task-1").unwrap(),
            query_id: "query-classification".to_owned(),
            terms: Vec::new(),
            max_items: 10,
            max_tokens: 1_024,
        })
        .unwrap()
        .pop()
        .unwrap();
    let artifacts_before = count(&database.connection(), "artifacts");
    database
        .store()
        .persist_source(ContextSourceRecord {
            document_id: "document-denied".to_owned(),
            task_id: TaskId::new("task-1").unwrap(),
            project_id: ProjectId::new("project-1").unwrap(),
            logical_identity: ContextLogicalIdentity::redacted("redacted-secret-1").unwrap(),
            revision: "commit-1".to_owned(),
            content_hash: digest(b"SECRET=value"),
            source_kind: local_agent_terminal_application::ContextSourceKind::RepositoryFile,
            classification: allowed.classification,
            state: ContextSourceState::Denied,
            updated_at: "2026-08-09T00:00:02Z".to_owned(),
            metadata_policy: allowed.provenance.index_metadata().clone(),
        })
        .unwrap();

    let connection = database.connection();
    let source: (String, String) = connection
        .query_row(
            "SELECT logical_path, index_state FROM source_documents
             WHERE id = 'document-denied'",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(source.1, "denied");
    assert_ne!(source.0, "secrets.env");
    assert_eq!(
        connection
            .query_row(
                "SELECT COUNT(*) FROM source_chunks WHERE document_id = 'document-denied'",
                [],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
        0
    );
    assert_eq!(count(&connection, "artifacts"), artifacts_before);
}

#[test]
fn current_to_stale_transition_is_exact_and_removes_chunks_from_queries() {
    let database = TestDatabase::new();
    database
        .execute(source_item(
            "src/lib.rs",
            b"allowed source",
            "2026-08-09T00:00:00Z",
        ))
        .unwrap();
    let transition = SourceStateTransition {
        document_id: "document-1".to_owned(),
        expected_state: local_agent_terminal_application::ContextSourceState::Current,
        next_state: local_agent_terminal_application::ContextSourceState::Stale,
        updated_at: "2026-08-09T00:00:03Z".to_owned(),
    };

    database
        .store()
        .transition_source(transition.clone())
        .unwrap();
    database.store().transition_source(transition).unwrap();

    assert!(database
        .store()
        .query(ContextQuery {
            task_id: TaskId::new("task-1").unwrap(),
            query_id: "query-stale".to_owned(),
            terms: Vec::new(),
            max_items: 10,
            max_tokens: 1_024,
        })
        .unwrap()
        .is_empty());
}

#[test]
fn unavailable_or_tampered_chunk_artifacts_fail_closed_on_recovery_read() {
    let database = TestDatabase::new();
    database
        .execute(source_item(
            "src/lib.rs",
            b"allowed source",
            "2026-08-09T00:00:00Z",
        ))
        .unwrap();
    let connection = database.connection();
    connection
        .execute(
            "UPDATE artifacts SET availability = 'missing'
             WHERE id = 'artifact-source-1'",
            [],
        )
        .unwrap();
    drop(connection);

    let error = database
        .store()
        .query(ContextQuery {
            task_id: TaskId::new("task-1").unwrap(),
            query_id: "query-unavailable".to_owned(),
            terms: Vec::new(),
            max_items: 10,
            max_tokens: 1_024,
        })
        .unwrap_err();
    assert_eq!(
        error.safe_classification(),
        SafeErrorClassification::IntegrityFailure
    );

    let connection = database.connection();
    let storage_key: String = connection
        .query_row(
            "SELECT storage_key FROM artifacts WHERE id = 'artifact-source-1'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    connection
        .execute(
            "UPDATE artifacts SET availability = 'available'
             WHERE id = 'artifact-source-1'",
            [],
        )
        .unwrap();
    drop(connection);
    fs::write(database.artifact_root.join(storage_key), b"tampered").unwrap();

    let tampered = database
        .store()
        .query(ContextQuery {
            task_id: TaskId::new("task-1").unwrap(),
            query_id: "query-tampered".to_owned(),
            terms: Vec::new(),
            max_items: 10,
            max_tokens: 1_024,
        })
        .unwrap_err();
    assert_eq!(
        tampered.safe_classification(),
        SafeErrorClassification::IntegrityFailure
    );
}

struct Source {
    snapshot: SourceSnapshot,
}

impl RepositoryContextSource for Source {
    fn snapshot(&self, request: SourceSnapshotRequest) -> Result<SourceSnapshot, PortError> {
        assert_eq!(request, self.snapshot.request);
        Ok(self.snapshot.clone())
    }
}

struct Classifier;

impl ContextSourceClassifier for Classifier {
    fn classify(
        &self,
        request: SourceClassificationRequest,
    ) -> Result<ContextClassificationOutcome, PortError> {
        let evidence_bytes = format!("classification:{}", request.document_id()).into_bytes();
        Ok(ContextClassificationOutcome {
            classification: ContextSourceClassification::issue(
                &request,
                local_agent_terminal_application::ContextSensitivity::InternalCode,
                ContextArtifactRef::new(
                    ArtifactId::new(format!("classification-{}", request.document_id())).unwrap(),
                    digest(&evidence_bytes),
                    u64::try_from(evidence_bytes.len())
                        .map_err(|_| failure(SafeErrorClassification::InvalidInput))?,
                )?,
                Timestamp::from_unix_seconds(1_786_262_400),
            )?,
            evidence_bytes,
        })
    }
}

struct Publisher<'a> {
    database: &'a TestDatabase,
}

impl ContextArtifactPublisher for Publisher<'_> {
    fn publish(&self, artifact: ImmutableContextArtifact) -> Result<(), PortError> {
        if digest(&artifact.bytes) != artifact.content_digest {
            return Err(failure(SafeErrorClassification::IntegrityFailure));
        }
        let artifact_type = match artifact.kind {
            ContextArtifactKind::ClassificationEvidence => "context-classification",
            ContextArtifactKind::SourceChunk => "context-source",
            ContextArtifactKind::ContextPackage => "content",
        };
        self.database
            .publish_artifact(&artifact.artifact_id, artifact_type, &artifact.bytes)
    }
}

struct AllowOrDenyPolicy;

impl DisclosurePolicyEvaluator for AllowOrDenyPolicy {
    fn disclose(&self, request: DisclosureRequest) -> Result<PolicyApprovedDisclosure, PortError> {
        let denied = request.channel == DisclosureChannel::IndexContent
            && request.bytes.windows(6).any(|bytes| bytes == b"SECRET");
        let effect = if denied {
            PolicyEffect::Deny
        } else {
            PolicyEffect::Allow
        };
        let channel = channel_name(request.channel);
        let original_digest = digest(&request.bytes);
        let draft = combine_policy_rules(
            request.policy_request,
            PolicyVersion::new(1).unwrap(),
            vec![MatchedPolicyRule {
                rule_id: PolicyRuleId::new(format!("rule-{channel}")).unwrap(),
                effect,
                redactions: Vec::new(),
            }],
            None,
        )
        .unwrap();
        let effective_bytes = (!denied).then_some(request.bytes);
        let effective_digest = effective_bytes.as_deref().map(digest);
        Ok(PolicyApprovedDisclosure {
            decision: PolicyDecision {
                draft,
                operation_digest: digest(
                    format!("{channel}:{}", original_digest.as_str()).as_bytes(),
                ),
            },
            channel: request.channel,
            original_digest,
            effective_bytes,
            effective_digest,
            redaction_report_digest: digest(b"no-redaction"),
            approval_binding: None,
        })
    }
}

fn source_snapshot(item: SourceSnapshotItem) -> SourceSnapshot {
    SourceSnapshot {
        request: SourceSnapshotRequest {
            project_id: ProjectId::new("project-1").unwrap(),
            task_id: TaskId::new("task-1").unwrap(),
            revision: "commit-1".to_owned(),
            repository_fingerprint: digest(b"repository"),
        },
        items: vec![item],
    }
}

fn source_item(path: &str, bytes: &[u8], updated_at: &str) -> SourceSnapshotItem {
    SourceSnapshotItem {
        document_id: "document-1".to_owned(),
        updated_at: updated_at.to_owned(),
        member_id: "member-1".to_owned(),
        content_artifact_id: ArtifactId::new("artifact-source-1").unwrap(),
        identity: SourceIdentity::new(
            ProjectId::new("project-1").unwrap(),
            "commit-1",
            path,
            digest(bytes),
        )
        .unwrap(),
        metadata: SourceIndexMetadata::new(Some("rust"), [("logicalId", "source-1")]).unwrap(),
        content: bytes.to_vec(),
        line_range: None,
        symbol: Some("entry".to_owned()),
    }
}

fn build_request() -> BuildInitialContextRequest {
    BuildInitialContextRequest {
        snapshot: SourceSnapshotRequest {
            project_id: ProjectId::new("project-1").unwrap(),
            task_id: TaskId::new("task-1").unwrap(),
            revision: "commit-1".to_owned(),
            repository_fingerprint: digest(b"repository"),
        },
        policy: ContextBuildPolicy {
            task_id: TaskId::new("task-1").unwrap(),
            actor: PolicyActor {
                connection_id: "connection-1".to_owned(),
                agent_id: "agent-1".to_owned(),
                trust_tier: TrustTier::CoreAdapter,
                locality: ActorLocality::Local,
            },
            resource_class: ResourceClass::InternalCode,
            task_risk: TaskRisk::Medium,
            workflow_phase: "ContextBuild".to_owned(),
            purpose: "build initial context".to_owned(),
            policy_snapshot_digest: digest(b"policy"),
            evaluated_at: Timestamp::from_unix_seconds(1_786_262_400),
        },
        package: ContextPackageDraft {
            descriptor: ContextPackageDescriptor::new(
                ContextPackageIdentity::new(
                    "package-1",
                    TaskId::new("task-1").unwrap(),
                    "agent-1",
                    "reviewer",
                    ArtifactId::new("artifact-agent-manifest-1").unwrap(),
                    ArtifactId::new("artifact-package-1").unwrap(),
                    Timestamp::from_unix_seconds(1_786_262_400),
                )
                .unwrap(),
                "analyze repository",
                ContextVersionSet::new("prompt.v1", "retrieval.v1", "byte-token-v1").unwrap(),
                ContextBudget::new(4_096, 1_024).unwrap(),
            )
            .unwrap(),
            contract: context_contract(),
        },
    }
}

fn channel_name(channel: DisclosureChannel) -> &'static str {
    match channel {
        DisclosureChannel::IndexMetadata => "index-metadata",
        DisclosureChannel::IndexContent => "index-content",
        DisclosureChannel::RetrievedItem => "retrieved-item",
        DisclosureChannel::FinalContextPackage => "final-context-package",
        DisclosureChannel::FileRead => "file-read",
        DisclosureChannel::ListMetadata => "list-metadata",
        DisclosureChannel::GitStatus => "git-status",
        DisclosureChannel::GitDiff => "git-diff",
        DisclosureChannel::Diagnostic => "diagnostic",
        DisclosureChannel::Artifact => "artifact",
        DisclosureChannel::Summary => "summary",
        DisclosureChannel::FinalSerializedPayload => "final-serialized-payload",
    }
}

fn count(connection: &Connection, table: &str) -> i64 {
    connection
        .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
            row.get(0)
        })
        .unwrap()
}

fn digest(bytes: &[u8]) -> Sha256Digest {
    Sha256Digest::new(format!("sha256:{:x}", Sha256::digest(bytes))).unwrap()
}

fn context_contract() -> ContextPackageContract {
    ContextPackageContract {
        task_scope: vec!["src/**".to_owned()],
        policy_constraints: vec!["read-only".to_owned()],
        shared_summary: "bounded summary".to_owned(),
        accepted_decisions: Vec::new(),
        unresolved_objections: Vec::new(),
        active_thread_messages: Vec::new(),
        permissions: vec!["context.query".to_owned()],
        protocol_capabilities: vec!["context/query".to_owned()],
        reconstructibility: ContextRunReconstructibility {
            run_config_artifact_id: "run-config-1".to_owned(),
            adapter_version: "adapter-1".to_owned(),
            provider_id: "provider-1".to_owned(),
            model_id: "model-1".to_owned(),
            generation_parameters_digest: digest(b"generation").as_str().to_owned(),
            response_schema_version: "message.v1".to_owned(),
            manifest_digest: digest(b"manifest").as_str().to_owned(),
            executable_digest: digest(b"executable").as_str().to_owned(),
            connection_binding_digest: digest(b"connection").as_str().to_owned(),
            authoritative_receipt_unix_seconds: 1_787_000_000,
        },
    }
}

fn failure(classification: SafeErrorClassification) -> PortError {
    PortError::failure(classification, Retryability::NonRetryable)
}
