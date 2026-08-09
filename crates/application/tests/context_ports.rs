use std::sync::{Arc, Mutex};

use local_agent_terminal_application::{
    BuildInitialContext, BuildInitialContextRequest, ContextArtifactKind, ContextArtifactPublisher,
    ContextBuildPolicy, ContextChunkRecord, ContextPackageDraft, ContextPackagePersistence,
    ContextPackageRecord, ContextQuery, ContextSourceRecord, ContextStore, DisclosureChannel,
    DisclosurePolicyEvaluator, DisclosureRequest, ImmutableContextArtifact,
    PolicyApprovedDisclosure, PolicyDecision, PolicyDecisionId, PolicyDecisionStore, PortError,
    QueryContext, QueryContextRequest, RepositoryContextSource, RetrievedContextItem, Retryability,
    SafeErrorClassification, SourceSnapshot, SourceSnapshotItem, SourceSnapshotRequest,
};
use local_agent_terminal_domain::{
    combine_policy_rules, ActorLocality, ArtifactId, ContextBudget, ContextPackageDescriptor,
    ContextVersionSet, MatchedPolicyRule, PolicyEffect, PolicyRuleId, PolicyVersion, ProjectId,
    ResourceClass, Sha256Digest, SourceIdentity, TaskId, TaskRisk, Timestamp, TrustTier,
};
use sha2::{Digest, Sha256};

#[derive(Default)]
struct RecordingState {
    calls: Vec<String>,
    sources: Vec<ContextSourceRecord>,
    chunks: Vec<ContextChunkRecord>,
    packages: Vec<ContextPackageRecord>,
    links: Vec<(String, String)>,
    decisions: Vec<PolicyDecisionId>,
    artifacts: Vec<ImmutableContextArtifact>,
    retrieved: Vec<RetrievedContextItem>,
    package_transactions: Vec<ContextPackagePersistence>,
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

struct Store {
    state: Arc<Mutex<RecordingState>>,
    fail_package_transaction: bool,
}

impl ContextStore for Store {
    fn persist_source(&self, source: ContextSourceRecord) -> Result<(), PortError> {
        let mut state = self.state.lock().unwrap();
        state.calls.push("persist-source".to_owned());
        state.sources.push(source);
        Ok(())
    }

    fn persist_chunk(&self, chunk: ContextChunkRecord) -> Result<(), PortError> {
        let mut state = self.state.lock().unwrap();
        state.calls.push("persist-chunk".to_owned());
        state.chunks.push(chunk);
        Ok(())
    }

    fn query(&self, _: ContextQuery) -> Result<Vec<RetrievedContextItem>, PortError> {
        Ok(self.state.lock().unwrap().retrieved.clone())
    }

    fn persist_package_with_policy_decisions(
        &self,
        persistence: ContextPackagePersistence,
    ) -> Result<(), PortError> {
        let mut state = self.state.lock().unwrap();
        state.calls.push("persist-package-atomically".to_owned());
        if self.fail_package_transaction {
            return Err(PortError::failure(
                SafeErrorClassification::Conflict,
                Retryability::NonRetryable,
            ));
        }
        state.packages.push(persistence.package.clone());
        state
            .links
            .extend(persistence.policy_decision_ids.iter().map(|decision_id| {
                (
                    persistence
                        .package
                        .binding
                        .descriptor()
                        .package_id()
                        .to_owned(),
                    decision_id.as_str().to_owned(),
                )
            }));
        state.package_transactions.push(persistence);
        Ok(())
    }
}

struct Publisher {
    state: Arc<Mutex<RecordingState>>,
}

impl ContextArtifactPublisher for Publisher {
    fn publish(&self, artifact: ImmutableContextArtifact) -> Result<(), PortError> {
        let mut state = self.state.lock().unwrap();
        state.calls.push(match artifact.kind {
            ContextArtifactKind::SourceChunk => "publish-chunk".to_owned(),
            ContextArtifactKind::ContextPackage => "publish-package".to_owned(),
        });
        state.artifacts.push(artifact);
        Ok(())
    }
}

struct Policy {
    state: Arc<Mutex<RecordingState>>,
    redact_final_package: bool,
}

impl DisclosurePolicyEvaluator for Policy {
    fn disclose(&self, request: DisclosureRequest) -> Result<PolicyApprovedDisclosure, PortError> {
        self.state
            .lock()
            .unwrap()
            .calls
            .push(format!("policy:{:?}", request.channel));
        let denied = request.channel == DisclosureChannel::IndexContent
            && request.bytes.windows(6).any(|bytes| bytes == b"SECRET");
        let redact_final_package =
            self.redact_final_package && request.channel == DisclosureChannel::FinalContextPackage;
        let effect = if denied {
            PolicyEffect::Deny
        } else if redact_final_package {
            PolicyEffect::AllowWithRedaction
        } else {
            PolicyEffect::Allow
        };
        let draft = combine_policy_rules(
            request.policy_request,
            PolicyVersion::new(1).unwrap(),
            vec![MatchedPolicyRule {
                rule_id: PolicyRuleId::new(format!("rule-{:?}", request.channel)).unwrap(),
                effect,
                redactions: redact_final_package
                    .then(|| {
                        local_agent_terminal_domain::RedactionDirective::new("final-mask").unwrap()
                    })
                    .into_iter()
                    .collect(),
            }],
            None,
        )
        .unwrap();
        let original_digest = digest(&request.bytes);
        let operation_digest =
            digest(format!("{:?}:{original_digest:?}", request.channel).as_bytes());
        let effective_bytes = if redact_final_package {
            Some(b"redacted-final-package".to_vec())
        } else {
            (!denied).then_some(request.bytes)
        };
        let effective_digest = effective_bytes.as_deref().map(digest);
        Ok(PolicyApprovedDisclosure {
            decision: PolicyDecision {
                draft,
                operation_digest,
            },
            channel: request.channel,
            original_digest: original_digest.clone(),
            effective_bytes,
            effective_digest,
            redaction_report_digest: digest(b"redaction-report"),
            approval_binding: None,
        })
    }
}

struct Decisions {
    state: Arc<Mutex<RecordingState>>,
}

impl PolicyDecisionStore for Decisions {
    fn record(
        &self,
        decision: local_agent_terminal_application::RecordedPolicyDecision,
    ) -> Result<PolicyDecisionId, PortError> {
        let id = PolicyDecisionId::from_decision(&decision.decision);
        let mut state = self.state.lock().unwrap();
        state.calls.push(format!("record-policy:{}", id.as_str()));
        state.decisions.push(id.clone());
        Ok(id)
    }
}

#[test]
fn context_ports_are_object_safe() {
    fn source(_: &dyn RepositoryContextSource) {}
    fn store(_: &dyn ContextStore) {}
    fn publisher(_: &dyn ContextArtifactPublisher) {}

    let state = Arc::new(Mutex::new(RecordingState::default()));
    let source_port = Source {
        snapshot: snapshot(Vec::new()),
    };
    source(&source_port);
    store(&Store {
        state: Arc::clone(&state),
        fail_package_transaction: false,
    });
    publisher(&Publisher { state });
}

#[test]
fn initial_context_preserves_coherent_identity_and_orders_policy_before_persistence() {
    let identity = source_identity("src/lib.rs", b"allowed source");
    let item = SourceSnapshotItem {
        member_id: "member-1".to_owned(),
        content_artifact_id: ArtifactId::new("artifact-source-1").unwrap(),
        identity: identity.clone(),
        metadata: br#"{"language":"rust","logicalId":"source-1"}"#.to_vec(),
        content: b"allowed source".to_vec(),
        line_range: None,
        symbol: Some("entry".to_owned()),
    };
    let (service, state) = service(snapshot(vec![item]));

    let package = service.execute(build_request()).unwrap();

    assert_eq!(package.members()[0].citation().source(), &identity);
    let state = state.lock().unwrap();
    assert_eq!(state.sources[0].identity, identity);
    assert_eq!(state.chunks[0].identity, state.sources[0].identity);
    let first_persistence = state
        .calls
        .iter()
        .position(|call| call.starts_with("persist-") || call.starts_with("publish-"))
        .unwrap();
    assert!(state.calls[..first_persistence]
        .iter()
        .any(|call| call == "policy:IndexMetadata"));
    assert!(state.calls[..first_persistence]
        .iter()
        .any(|call| call == "policy:IndexContent"));
}

#[test]
fn denied_content_never_reaches_artifact_or_index_ports() {
    let denied = SourceSnapshotItem {
        member_id: "member-denied".to_owned(),
        content_artifact_id: ArtifactId::new("artifact-denied").unwrap(),
        identity: source_identity("src/secret.rs", b"SECRET bytes"),
        metadata: br#"{"logicalId":"secret-source"}"#.to_vec(),
        content: b"SECRET bytes".to_vec(),
        line_range: None,
        symbol: None,
    };
    let (service, state) = service(snapshot(vec![denied]));

    let package = service.execute(build_request()).unwrap();

    let state = state.lock().unwrap();
    assert!(state.chunks.is_empty());
    assert!(state
        .artifacts
        .iter()
        .all(|artifact| !artifact.bytes.windows(6).any(|bytes| bytes == b"SECRET")));
    assert_eq!(package.policy().decision_ids().len(), 3);
    assert_eq!(state.links.len(), 3);
}

#[test]
fn final_manifest_is_core_owned_canonical_complete_and_scanned_before_publish() {
    let item = SourceSnapshotItem {
        member_id: "member-1".to_owned(),
        content_artifact_id: ArtifactId::new("artifact-source-1").unwrap(),
        identity: source_identity("src/lib.rs", b"allowed source"),
        metadata: br#"{"logicalId":"source-1"}"#.to_vec(),
        content: b"allowed source".to_vec(),
        line_range: Some(local_agent_terminal_domain::LineRange::new(2, 7).unwrap()),
        symbol: Some("entry".to_owned()),
    };
    let (service, state) = service(snapshot(vec![item]));

    let package = service.execute(build_request()).unwrap();

    let state = state.lock().unwrap();
    let scan = state
        .calls
        .iter()
        .position(|call| call == "policy:FinalContextPackage")
        .unwrap();
    let publish = state
        .calls
        .iter()
        .position(|call| call == "publish-package")
        .unwrap();
    assert!(scan < publish);
    let artifact = state
        .artifacts
        .iter()
        .find(|artifact| artifact.kind == ContextArtifactKind::ContextPackage)
        .unwrap();
    let manifest: serde_json::Value = serde_json::from_slice(&artifact.bytes).unwrap();
    assert_eq!(
        serde_json_canonicalizer::to_vec(&manifest).unwrap(),
        artifact.bytes
    );
    assert_eq!(manifest["schema"], "context-package-manifest");
    assert_eq!(manifest["version"], 1);
    assert_eq!(manifest["artifactId"], "artifact-package-1");
    assert_eq!(manifest["descriptor"]["packageId"], "package-1");
    assert_eq!(manifest["descriptor"]["taskId"], "task-1");
    assert_eq!(manifest["descriptor"]["objective"], "analyze repository");
    assert_eq!(
        manifest["descriptor"]["versions"]["promptTemplate"],
        "prompt.v1"
    );
    assert_eq!(
        manifest["descriptor"]["versions"]["retrievalPipeline"],
        "retrieval.v1"
    );
    assert_eq!(
        manifest["descriptor"]["versions"]["tokenizer"],
        "tokenizer.v1"
    );
    assert_eq!(manifest["descriptor"]["budget"]["maxTokens"], 4_096);
    assert_eq!(
        manifest["descriptor"]["budget"]["reservedResponseTokens"],
        1_024
    );
    assert_eq!(manifest["descriptor"]["budget"]["usedInputTokens"], 0);
    assert_eq!(manifest["members"][0]["memberId"], "member-1");
    assert_eq!(manifest["members"][0]["taskId"], "task-1");
    assert_eq!(
        manifest["members"][0]["citation"]["source"]["projectId"],
        "project-1"
    );
    assert_eq!(
        manifest["members"][0]["citation"]["source"]["revision"],
        "commit-1"
    );
    assert_eq!(
        manifest["members"][0]["citation"]["source"]["pathIdentity"],
        "src/lib.rs"
    );
    assert_eq!(
        manifest["members"][0]["citation"]["source"]["contentHash"],
        digest(b"allowed source").as_str()
    );
    assert_eq!(manifest["members"][0]["citation"]["range"]["start"], 2);
    assert_eq!(manifest["members"][0]["citation"]["range"]["end"], 7);
    assert_eq!(manifest["members"][0]["citation"]["symbol"], "entry");
    assert_eq!(manifest["members"][0]["citation"]["freshness"], "current");
    assert_eq!(manifest["members"][0]["disclosure"]["kind"], "allowed");
    assert!(manifest["members"][0]["disclosure"]["stableReportId"].is_null());
    assert_eq!(
        manifest["policy"]["policySnapshotDigest"],
        digest(b"policy").as_str()
    );
    let mut expected_item_decisions: Vec<_> = state.decisions[..state.decisions.len() - 1]
        .iter()
        .map(PolicyDecisionId::as_str)
        .collect();
    expected_item_decisions.sort_unstable();
    assert_eq!(
        manifest["policy"]["itemDecisionIds"],
        serde_json::json!(expected_item_decisions)
    );
    assert!(!artifact
        .bytes
        .windows(state.decisions.last().unwrap().as_str().len())
        .any(|bytes| { bytes == state.decisions.last().unwrap().as_str().as_bytes() }));
    assert_eq!(
        &digest(&artifact.bytes),
        package.artifact().content_digest()
    );
    assert_eq!(state.links.len(), package.policy().decision_ids().len());
    assert_eq!(state.packages[0].binding, package);
    assert_eq!(state.package_transactions.len(), 1);
    assert_eq!(
        state.package_transactions[0]
            .policy_decision_ids
            .iter()
            .map(PolicyDecisionId::as_str)
            .collect::<Vec<_>>(),
        package.policy().decision_ids()
    );
}

#[test]
fn final_manifest_redaction_fails_closed_before_publish_or_persistence() {
    let item = SourceSnapshotItem {
        member_id: "member-1".to_owned(),
        content_artifact_id: ArtifactId::new("artifact-source-1").unwrap(),
        identity: source_identity("src/lib.rs", b"allowed source"),
        metadata: br#"{"logicalId":"source-1"}"#.to_vec(),
        content: b"allowed source".to_vec(),
        line_range: None,
        symbol: None,
    };
    let (service, state) = service_with_final_redaction(snapshot(vec![item]));

    assert!(service.execute(build_request()).is_err());

    let state = state.lock().unwrap();
    assert!(state
        .artifacts
        .iter()
        .all(|artifact| artifact.kind != ContextArtifactKind::ContextPackage));
    assert!(state.packages.is_empty());
    assert!(state.links.is_empty());
}

#[test]
fn package_and_all_policy_relations_are_one_atomic_store_call_after_publish() {
    let item = SourceSnapshotItem {
        member_id: "member-1".to_owned(),
        content_artifact_id: ArtifactId::new("artifact-source-1").unwrap(),
        identity: source_identity("src/lib.rs", b"allowed source"),
        metadata: br#"{"logicalId":"source-1"}"#.to_vec(),
        content: b"allowed source".to_vec(),
        line_range: None,
        symbol: None,
    };
    let (service, state) = service_with_failing_package_transaction(snapshot(vec![item]));

    assert!(service.execute(build_request()).is_err());

    let state = state.lock().unwrap();
    assert_eq!(
        state
            .calls
            .iter()
            .filter(|call| call.as_str() == "persist-package-atomically")
            .count(),
        1
    );
    let publish = state
        .calls
        .iter()
        .position(|call| call == "publish-package")
        .unwrap();
    let transaction = state
        .calls
        .iter()
        .position(|call| call == "persist-package-atomically")
        .unwrap();
    assert!(publish < transaction);
    assert!(state
        .artifacts
        .iter()
        .any(|artifact| artifact.kind == ContextArtifactKind::ContextPackage));
    assert!(state.packages.is_empty());
    assert!(state.links.is_empty());
    assert!(state.package_transactions.is_empty());
}

#[test]
fn query_context_scans_each_retrieved_item_and_the_final_package() {
    let state = Arc::new(Mutex::new(RecordingState::default()));
    state.lock().unwrap().retrieved.push(RetrievedContextItem {
        member_id: "retrieved-1".to_owned(),
        artifact_id: ArtifactId::new("artifact-retrieved-1").unwrap(),
        identity: source_identity("src/query.rs", b"retrieved source"),
        bytes: b"retrieved source".to_vec(),
        line_range: None,
        symbol: Some("query".to_owned()),
    });
    let store = Store {
        state: Arc::clone(&state),
        fail_package_transaction: false,
    };
    let publisher = Publisher {
        state: Arc::clone(&state),
    };
    let policy = Policy {
        state: Arc::clone(&state),
        redact_final_package: false,
    };
    let decisions = Decisions {
        state: Arc::clone(&state),
    };
    let build = build_request();

    let package = QueryContext::new(&store, &publisher, &policy, &decisions)
        .execute(QueryContextRequest {
            query: ContextQuery {
                task_id: TaskId::new("task-1").unwrap(),
                query_id: "query-1".to_owned(),
                terms: vec!["query".to_owned()],
                max_items: 4,
                max_tokens: 1_024,
            },
            policy: build.policy,
            package: build.package,
        })
        .unwrap();

    let state = state.lock().unwrap();
    assert_eq!(package.members().len(), 1);
    assert!(state
        .calls
        .iter()
        .any(|call| call == "policy:RetrievedItem"));
    assert!(state
        .calls
        .iter()
        .any(|call| call == "policy:FinalContextPackage"));
}

fn service(
    source_snapshot: SourceSnapshot,
) -> (BuildInitialContext<'static>, Arc<Mutex<RecordingState>>) {
    let state = Arc::new(Mutex::new(RecordingState::default()));
    let source = Box::leak(Box::new(Source {
        snapshot: source_snapshot,
    }));
    let store = Box::leak(Box::new(Store {
        state: Arc::clone(&state),
        fail_package_transaction: false,
    }));
    let publisher = Box::leak(Box::new(Publisher {
        state: Arc::clone(&state),
    }));
    let policy = Box::leak(Box::new(Policy {
        state: Arc::clone(&state),
        redact_final_package: false,
    }));
    let decisions = Box::leak(Box::new(Decisions {
        state: Arc::clone(&state),
    }));
    (
        BuildInitialContext::new(source, store, publisher, policy, decisions),
        state,
    )
}

fn service_with_final_redaction(
    source_snapshot: SourceSnapshot,
) -> (BuildInitialContext<'static>, Arc<Mutex<RecordingState>>) {
    let state = Arc::new(Mutex::new(RecordingState::default()));
    let source = Box::leak(Box::new(Source {
        snapshot: source_snapshot,
    }));
    let store = Box::leak(Box::new(Store {
        state: Arc::clone(&state),
        fail_package_transaction: false,
    }));
    let publisher = Box::leak(Box::new(Publisher {
        state: Arc::clone(&state),
    }));
    let policy = Box::leak(Box::new(Policy {
        state: Arc::clone(&state),
        redact_final_package: true,
    }));
    let decisions = Box::leak(Box::new(Decisions {
        state: Arc::clone(&state),
    }));
    (
        BuildInitialContext::new(source, store, publisher, policy, decisions),
        state,
    )
}

fn service_with_failing_package_transaction(
    source_snapshot: SourceSnapshot,
) -> (BuildInitialContext<'static>, Arc<Mutex<RecordingState>>) {
    let state = Arc::new(Mutex::new(RecordingState::default()));
    let source = Box::leak(Box::new(Source {
        snapshot: source_snapshot,
    }));
    let store = Box::leak(Box::new(Store {
        state: Arc::clone(&state),
        fail_package_transaction: true,
    }));
    let publisher = Box::leak(Box::new(Publisher {
        state: Arc::clone(&state),
    }));
    let policy = Box::leak(Box::new(Policy {
        state: Arc::clone(&state),
        redact_final_package: false,
    }));
    let decisions = Box::leak(Box::new(Decisions {
        state: Arc::clone(&state),
    }));
    (
        BuildInitialContext::new(source, store, publisher, policy, decisions),
        state,
    )
}

fn snapshot(items: Vec<SourceSnapshotItem>) -> SourceSnapshot {
    SourceSnapshot {
        request: SourceSnapshotRequest {
            project_id: ProjectId::new("project-1").unwrap(),
            task_id: TaskId::new("task-1").unwrap(),
            revision: "commit-1".to_owned(),
            repository_fingerprint: digest(b"repository"),
        },
        items,
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
            actor: local_agent_terminal_domain::PolicyActor {
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
            evaluated_at: Timestamp::from_unix_seconds(1_787_000_000),
        },
        package: ContextPackageDraft {
            descriptor: ContextPackageDescriptor::new(
                "package-1",
                TaskId::new("task-1").unwrap(),
                "analyze repository",
                ContextVersionSet::new("prompt.v1", "retrieval.v1", "tokenizer.v1").unwrap(),
                ContextBudget::new(4_096, 1_024).unwrap(),
            )
            .unwrap(),
            artifact_id: ArtifactId::new("artifact-package-1").unwrap(),
        },
    }
}

fn source_identity(path: &str, bytes: &[u8]) -> SourceIdentity {
    SourceIdentity::new(
        ProjectId::new("project-1").unwrap(),
        "commit-1",
        path,
        digest(bytes),
    )
    .unwrap()
}

fn digest(bytes: &[u8]) -> Sha256Digest {
    Sha256Digest::new(format!("sha256:{:x}", Sha256::digest(bytes))).unwrap()
}

fn _safe_error() -> PortError {
    PortError::failure(
        SafeErrorClassification::InvalidInput,
        Retryability::NonRetryable,
    )
}
