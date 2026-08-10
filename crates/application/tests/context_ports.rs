use std::sync::{Arc, Mutex};

use local_agent_terminal_application::{
    BuildInitialContext, BuildInitialContextRequest, ContextArtifactKind, ContextArtifactPublisher,
    ContextArtifactReader, ContextArtifactRef, ContextBuildPolicy, ContextChunkRecord,
    ContextClassificationOutcome, ContextIndexProvenance, ContextIndexProvenanceRehydration,
    ContextPackageDraft, ContextPackagePersistence, ContextPackageRecord, ContextPolicyDecisionRef,
    ContextQuery, ContextSourceClassification, ContextSourceClassifier, ContextSourceRecord,
    ContextStore, DisclosureChannel, DisclosurePolicyEvaluator, DisclosureRequest,
    ImmutableContextArtifact, PolicyApprovedDisclosure, PolicyDecision, PolicyDecisionId,
    PolicyDecisionStore, PortError, QueryContext, QueryContextRequest, RepositoryContextSource,
    RetrievedContextItem, Retryability, SafeErrorClassification, SourceClassificationRequest,
    SourceIndexMetadata, SourceSnapshot, SourceSnapshotItem, SourceSnapshotRequest,
    SourceStateTransition,
};
use local_agent_terminal_domain::{
    combine_policy_rules, ActorLocality, ArtifactId, ContextBudget, ContextPackageDescriptor,
    ContextPackageIdentity, ContextVersionSet, MatchedPolicyRule, PolicyEffect, PolicyRuleId,
    PolicyVersion, ProjectId, ResourceClass, Sha256Digest, SourceIdentity, TaskId, TaskRisk,
    Timestamp, TrustTier,
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

#[derive(Default)]
struct Classifier {
    substitute_previous: bool,
    previous: Mutex<Option<ContextClassificationOutcome>>,
}

impl ContextSourceClassifier for Classifier {
    fn classify(
        &self,
        request: SourceClassificationRequest,
    ) -> Result<ContextClassificationOutcome, PortError> {
        if self.substitute_previous {
            if let Some(previous) = self.previous.lock().unwrap().clone() {
                return Ok(previous);
            }
        }
        let sensitivity = if request.document_id().contains("secret") {
            local_agent_terminal_application::ContextSensitivity::Secret
        } else {
            local_agent_terminal_application::ContextSensitivity::InternalCode
        };
        let evidence_bytes = format!("classification:{}", request.document_id()).into_bytes();
        let classification = ContextSourceClassification::issue(
            &request,
            sensitivity,
            ContextArtifactRef::new(
                ArtifactId::new(format!("classification-{}", request.document_id())).unwrap(),
                digest(&evidence_bytes),
                evidence_bytes.len() as u64,
            )?,
            Timestamp::from_unix_seconds(1_787_000_000),
        )?;
        let outcome = ContextClassificationOutcome {
            classification,
            evidence_bytes,
        };
        *self.previous.lock().unwrap() = Some(outcome.clone());
        Ok(outcome)
    }
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

    fn transition_source(&self, _: SourceStateTransition) -> Result<(), PortError> {
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
            ContextArtifactKind::ClassificationEvidence => "publish-classification".to_owned(),
            ContextArtifactKind::SourceChunk => "publish-chunk".to_owned(),
            ContextArtifactKind::ContextPackage => "publish-package".to_owned(),
        });
        state.artifacts.push(artifact);
        Ok(())
    }
}

impl ContextArtifactReader for Publisher {
    fn read(
        &self,
        reference: &local_agent_terminal_application::ContextArtifactRef,
    ) -> Result<Vec<u8>, PortError> {
        self.state
            .lock()
            .unwrap()
            .artifacts
            .iter()
            .find(|artifact| &artifact.artifact_id == reference.artifact_id())
            .map(|artifact| artifact.bytes.clone())
            .ok_or_else(|| {
                PortError::failure(
                    SafeErrorClassification::NotFound,
                    Retryability::NonRetryable,
                )
            })
    }
}

struct Policy {
    state: Arc<Mutex<RecordingState>>,
    redact_final_package: bool,
    metadata_rewrite: MetadataRewrite,
}

#[derive(Debug, Clone, Copy, Default)]
enum MetadataRewrite {
    #[default]
    None,
    RedactIdentityAndSymbol,
    CrossProject,
    CrossRevision,
    CrossHash,
    CrossArtifact,
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
        let rewrite_metadata = request.channel == DisclosureChannel::IndexMetadata
            && !matches!(self.metadata_rewrite, MetadataRewrite::None);
        let effect = if denied {
            PolicyEffect::Deny
        } else if redact_final_package || rewrite_metadata {
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
                redactions: (redact_final_package || rewrite_metadata)
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
        } else if rewrite_metadata {
            let mut value: serde_json::Value = serde_json::from_slice(&request.bytes).unwrap();
            value["source"]["logicalIdentity"] = serde_json::json!({
                "kind": "redacted",
                "value": "redacted-source-1",
            });
            value["symbol"] = serde_json::Value::Null;
            match self.metadata_rewrite {
                MetadataRewrite::None | MetadataRewrite::RedactIdentityAndSymbol => {}
                MetadataRewrite::CrossProject => {
                    value["source"]["projectId"] = serde_json::json!("project-2")
                }
                MetadataRewrite::CrossRevision => {
                    value["source"]["revision"] = serde_json::json!("commit-2")
                }
                MetadataRewrite::CrossHash => {
                    value["source"]["contentHash"] =
                        serde_json::json!(digest(b"substituted").as_str())
                }
                MetadataRewrite::CrossArtifact => {
                    value["artifact"]["artifactId"] = serde_json::json!("artifact-substituted")
                }
            }
            Some(serde_json_canonicalizer::to_vec(&value).unwrap())
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
    fn classifier(_: &dyn ContextSourceClassifier) {}

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
    classifier(&Classifier::default());
}

#[test]
fn source_metadata_is_typed_and_classification_is_a_separate_trusted_port() {
    fn classifier(_: &dyn ContextSourceClassifier) {}
    let metadata = SourceIndexMetadata::new(Some("rust"), [("logicalId", "source-1")]).unwrap();
    assert_eq!(metadata.language(), Some("rust"));

    struct TrustedClassifier;
    impl ContextSourceClassifier for TrustedClassifier {
        fn classify(
            &self,
            request: SourceClassificationRequest,
        ) -> Result<ContextClassificationOutcome, PortError> {
            let evidence_bytes = b"classification evidence".to_vec();
            let classification = ContextSourceClassification::issue(
                &request,
                local_agent_terminal_application::ContextSensitivity::InternalCode,
                ContextArtifactRef::new(
                    ArtifactId::new("classification-1").unwrap(),
                    digest(b"classification evidence"),
                    23,
                )?,
                Timestamp::from_unix_seconds(1_787_000_000),
            )?;
            Ok(ContextClassificationOutcome {
                classification,
                evidence_bytes,
            })
        }
    }
    classifier(&TrustedClassifier);
}

#[test]
fn initial_context_preserves_coherent_identity_and_orders_policy_before_persistence() {
    let identity = source_identity("src/lib.rs", b"allowed source");
    let item = SourceSnapshotItem {
        document_id: "document-member-1".to_owned(),
        updated_at: "2026-08-09T00:00:00Z".to_owned(),
        member_id: "member-1".to_owned(),
        content_artifact_id: ArtifactId::new("artifact-source-1").unwrap(),
        identity: identity.clone(),
        metadata: source_metadata(Some("rust"), "source-1"),
        content: b"allowed source".to_vec(),
        line_range: None,
        symbol: Some("entry".to_owned()),
    };
    let (service, state) = service(snapshot(vec![item]));

    let package = service.execute(build_request()).unwrap();

    assert_eq!(package.members()[0].citation().source(), &identity);
    let state = state.lock().unwrap();
    assert_eq!(
        state.sources[0].disclosed_source_identity().unwrap(),
        Some(identity.clone())
    );
    assert_eq!(state.chunks[0].identity, identity);
    assert_eq!(state.sources[0].document_id, "document-member-1");
    assert_eq!(state.sources[0].source_kind.as_str(), "repository_file");
    assert_eq!(
        state.sources[0].classification.sensitivity().as_str(),
        "internal-code"
    );
    assert_ne!(
        state.sources[0].classification.result_digest(),
        &digest(b"classification")
    );
    assert_eq!(
        state.sources[0].state,
        local_agent_terminal_application::ContextSourceState::Current
    );
    assert_eq!(state.chunks[0].document_id, "document-member-1");
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&state.chunks[0].metadata).unwrap()["metadata"]
            ["language"],
        "rust"
    );
    assert_eq!(state.chunks[0].symbol.as_deref(), Some("entry"));
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
        document_id: "document-member-denied".to_owned(),
        updated_at: "2026-08-09T00:00:00Z".to_owned(),
        member_id: "member-denied".to_owned(),
        content_artifact_id: ArtifactId::new("artifact-denied").unwrap(),
        identity: source_identity("src/secret.rs", b"SECRET bytes"),
        metadata: source_metadata(None, "secret-source"),
        content: b"SECRET bytes".to_vec(),
        line_range: None,
        symbol: None,
    };
    let (service, state) = service(snapshot(vec![denied]));

    let package = service.execute(build_request()).unwrap();

    let state = state.lock().unwrap();
    assert!(state.chunks.is_empty());
    assert!(state.sources.is_empty());
    assert!(state
        .artifacts
        .iter()
        .all(|artifact| !artifact.bytes.windows(6).any(|bytes| bytes == b"SECRET")));
    assert_eq!(package.policy().decision_ids().len(), 3);
    assert_eq!(state.links.len(), 3);
}

#[test]
fn denied_source_records_accept_only_explicit_stable_redacted_identity() {
    let item = SourceSnapshotItem {
        document_id: "document-member-1".to_owned(),
        updated_at: "2026-08-09T00:00:00Z".to_owned(),
        member_id: "member-1".to_owned(),
        content_artifact_id: ArtifactId::new("artifact-source-1").unwrap(),
        identity: source_identity("src/lib.rs", b"allowed source"),
        metadata: source_metadata(None, "source-1"),
        content: b"allowed source".to_vec(),
        line_range: None,
        symbol: None,
    };
    let (service, state) = service(snapshot(vec![item]));
    service.execute(build_request()).unwrap();
    let mut record = state.lock().unwrap().sources[0].clone();
    record.state = local_agent_terminal_application::ContextSourceState::Denied;
    record.logical_identity =
        local_agent_terminal_application::ContextLogicalIdentity::redacted("redacted-source-1")
            .unwrap();

    assert!(record.validate().is_ok());
    assert_eq!(record.disclosed_source_identity().unwrap(), None);
    record.logical_identity = local_agent_terminal_application::ContextLogicalIdentity::disclosed(
        "C:/secret/physical/path.rs",
    )
    .unwrap();
    assert!(record.validate().is_err());
}

#[test]
fn final_manifest_is_core_owned_canonical_complete_and_scanned_before_publish() {
    let item = SourceSnapshotItem {
        document_id: "document-member-1".to_owned(),
        updated_at: "2026-08-09T00:00:00Z".to_owned(),
        member_id: "member-1".to_owned(),
        content_artifact_id: ArtifactId::new("artifact-source-1").unwrap(),
        identity: source_identity("src/lib.rs", b"allowed source"),
        metadata: source_metadata(None, "source-1"),
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
        document_id: "document-member-1".to_owned(),
        updated_at: "2026-08-09T00:00:00Z".to_owned(),
        member_id: "member-1".to_owned(),
        content_artifact_id: ArtifactId::new("artifact-source-1").unwrap(),
        identity: source_identity("src/lib.rs", b"allowed source"),
        metadata: source_metadata(None, "source-1"),
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
        document_id: "document-member-1".to_owned(),
        updated_at: "2026-08-09T00:00:00Z".to_owned(),
        member_id: "member-1".to_owned(),
        content_artifact_id: ArtifactId::new("artifact-source-1").unwrap(),
        identity: source_identity("src/lib.rs", b"allowed source"),
        metadata: source_metadata(None, "source-1"),
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
    let retrieved_bytes = b"retrieved source".to_vec();
    let item = SourceSnapshotItem {
        document_id: "document-retrieved-1".to_owned(),
        updated_at: "2026-08-09T00:00:00Z".to_owned(),
        member_id: "retrieved-1".to_owned(),
        content_artifact_id: ArtifactId::new("artifact-retrieved-1").unwrap(),
        identity: source_identity("src/query.rs", &retrieved_bytes),
        metadata: source_metadata(Some("rust"), "query-source"),
        content: retrieved_bytes,
        line_range: None,
        symbol: Some("query".to_owned()),
    };
    let (initial, state) = service(snapshot(vec![item]));
    initial.execute(build_request()).unwrap();
    let chunk = state.lock().unwrap().chunks[0].clone();
    let retrieved = RetrievedContextItem {
        document_id: chunk.document_id,
        task_id: chunk.task_id,
        member_id: chunk.member_id,
        artifact: chunk.artifact,
        identity: chunk.identity,
        metadata: chunk.metadata,
        line_range: chunk.line_range,
        symbol: chunk.symbol,
        created_at: chunk.created_at,
        classification: chunk.classification,
        provenance: chunk.provenance,
    };
    let metadata_decision = retrieved.provenance.index_metadata().decision_id().clone();
    let content_decision = retrieved.provenance.index_content().decision_id().clone();
    state
        .lock()
        .unwrap()
        .retrieved
        .extend([retrieved.clone(), retrieved]);
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
        metadata_rewrite: MetadataRewrite::None,
    };
    let decisions = Decisions {
        state: Arc::clone(&state),
    };
    let build = build_request();

    let package = QueryContext::new(&store, &publisher, &publisher, &policy, &decisions)
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
    assert!(package
        .policy()
        .decision_ids()
        .iter()
        .any(|id| id == metadata_decision.as_str()));
    assert!(package
        .policy()
        .decision_ids()
        .iter()
        .any(|id| id == content_decision.as_str()));
    assert!(package
        .policy()
        .decision_ids()
        .windows(2)
        .all(|pair| pair[0] != pair[1]));
    assert!(state
        .calls
        .iter()
        .any(|call| call == "policy:RetrievedItem"));
    assert!(state
        .calls
        .iter()
        .any(|call| call == "policy:FinalContextPackage"));
}

#[test]
fn metadata_redaction_replaces_identity_and_symbol_everywhere_after_policy() {
    let original_path = "src/private-name.rs";
    let original_symbol = "private_symbol";
    let item = SourceSnapshotItem {
        document_id: "document-redacted-1".to_owned(),
        updated_at: "2026-08-09T00:00:00Z".to_owned(),
        member_id: "member-redacted-1".to_owned(),
        content_artifact_id: ArtifactId::new("artifact-redacted-1").unwrap(),
        identity: source_identity(original_path, b"allowed source"),
        metadata: source_metadata(Some("rust"), "source-redacted-1"),
        content: b"allowed source".to_vec(),
        line_range: Some(local_agent_terminal_domain::LineRange::new(1, 2).unwrap()),
        symbol: Some(original_symbol.to_owned()),
    };
    let (service, state) = service_with_metadata_options(
        snapshot(vec![item]),
        MetadataRewrite::RedactIdentityAndSymbol,
        false,
    );

    let package = service.execute(build_request()).unwrap();

    assert_eq!(
        package.members()[0].citation().source().path_identity(),
        "redacted-source-1"
    );
    assert_eq!(package.members()[0].citation().symbol(), None);
    assert_eq!(
        package.members()[0].disclosure().kind(),
        local_agent_terminal_domain::DisclosureKind::Redacted
    );
    let state = state.lock().unwrap();
    assert_eq!(
        state.sources[0].logical_identity.as_str(),
        "redacted-source-1"
    );
    assert_eq!(
        state.chunks[0].identity.path_identity(),
        "redacted-source-1"
    );
    assert_eq!(state.chunks[0].symbol, None);
    let persisted = format!("{:?}{:?}{:?}", state.sources, state.chunks, state.packages);
    assert!(!persisted.contains(original_path));
    assert!(!persisted.contains(original_symbol));
    assert!(state.artifacts.iter().all(|artifact| {
        !artifact
            .bytes
            .windows(original_path.len())
            .any(|bytes| bytes == original_path.as_bytes())
            && !artifact
                .bytes
                .windows(original_symbol.len())
                .any(|bytes| bytes == original_symbol.as_bytes())
    }));
}

#[test]
fn metadata_policy_cannot_substitute_project_revision_hash_or_artifact() {
    for rewrite in [
        MetadataRewrite::CrossProject,
        MetadataRewrite::CrossRevision,
        MetadataRewrite::CrossHash,
        MetadataRewrite::CrossArtifact,
    ] {
        let item = SourceSnapshotItem {
            document_id: "document-member-1".to_owned(),
            updated_at: "2026-08-09T00:00:00Z".to_owned(),
            member_id: "member-1".to_owned(),
            content_artifact_id: ArtifactId::new("artifact-source-1").unwrap(),
            identity: source_identity("src/lib.rs", b"allowed source"),
            metadata: source_metadata(Some("rust"), "source-1"),
            content: b"allowed source".to_vec(),
            line_range: None,
            symbol: Some("entry".to_owned()),
        };
        let (service, state) = service_with_metadata_options(snapshot(vec![item]), rewrite, false);
        assert!(service.execute(build_request()).is_err(), "{rewrite:?}");
        let state = state.lock().unwrap();
        assert!(state.sources.is_empty(), "{rewrite:?}");
        assert!(state.chunks.is_empty(), "{rewrite:?}");
        assert!(state.artifacts.is_empty(), "{rewrite:?}");
        assert!(state.packages.is_empty(), "{rewrite:?}");
    }
}

#[test]
fn per_item_classifications_may_differ_but_cross_item_substitution_is_rejected() {
    let items = vec![
        SourceSnapshotItem {
            document_id: "document-public-1".to_owned(),
            updated_at: "2026-08-09T00:00:00Z".to_owned(),
            member_id: "member-public-1".to_owned(),
            content_artifact_id: ArtifactId::new("artifact-public-1").unwrap(),
            identity: source_identity("src/public.rs", b"public source"),
            metadata: source_metadata(Some("rust"), "public-source"),
            content: b"public source".to_vec(),
            line_range: None,
            symbol: None,
        },
        SourceSnapshotItem {
            document_id: "document-secret-1".to_owned(),
            updated_at: "2026-08-09T00:00:00Z".to_owned(),
            member_id: "member-secret-1".to_owned(),
            content_artifact_id: ArtifactId::new("artifact-secret-1").unwrap(),
            identity: source_identity("src/restricted.rs", b"restricted source"),
            metadata: source_metadata(Some("rust"), "secret-source"),
            content: b"restricted source".to_vec(),
            line_range: None,
            symbol: None,
        },
    ];
    let (service, state) = service(snapshot(items.clone()));
    service.execute(build_request()).unwrap();
    let state = state.lock().unwrap();
    assert_eq!(
        state.sources[0].classification.sensitivity(),
        local_agent_terminal_application::ContextSensitivity::InternalCode
    );
    assert_eq!(
        state.sources[1].classification.sensitivity(),
        local_agent_terminal_application::ContextSensitivity::Secret
    );
    drop(state);

    let (service, state) =
        service_with_metadata_options(snapshot(items), MetadataRewrite::None, true);
    assert!(service.execute(build_request()).is_err());
    assert!(state.lock().unwrap().packages.is_empty());
}

#[test]
fn persisted_classification_and_provenance_rehydrate_without_blessing_substitutions() {
    let item = SourceSnapshotItem {
        document_id: "document-reopen-1".to_owned(),
        updated_at: "2026-08-09T00:00:00Z".to_owned(),
        member_id: "member-reopen-1".to_owned(),
        content_artifact_id: ArtifactId::new("artifact-reopen-1").unwrap(),
        identity: source_identity("src/reopen.rs", b"reopen source"),
        metadata: source_metadata(Some("rust"), "reopen-source"),
        content: b"reopen source".to_vec(),
        line_range: Some(local_agent_terminal_domain::LineRange::new(3, 7).unwrap()),
        symbol: Some("reopen".to_owned()),
    };
    let (service, state) = service(snapshot(vec![item]));
    service.execute(build_request()).unwrap();
    let chunk = state.lock().unwrap().chunks[0].clone();
    let classification = &chunk.classification;

    let reopened = ContextSourceClassification::rehydrate(
        classification.request_digest().clone(),
        classification.sensitivity(),
        classification.evidence().clone(),
        classification.result_digest().clone(),
        classification.classified_at(),
    )
    .unwrap();
    assert_eq!(&reopened, classification);

    assert!(ContextSourceClassification::rehydrate(
        digest(b"wrong-request"),
        classification.sensitivity(),
        classification.evidence().clone(),
        classification.result_digest().clone(),
        classification.classified_at(),
    )
    .is_err());
    assert!(ContextSourceClassification::rehydrate(
        classification.request_digest().clone(),
        classification.sensitivity(),
        ContextArtifactRef::new(
            classification.evidence().artifact_id().clone(),
            digest(b"wrong-evidence"),
            classification.evidence().size_bytes(),
        )
        .unwrap(),
        classification.result_digest().clone(),
        classification.classified_at(),
    )
    .is_err());
    assert!(ContextSourceClassification::rehydrate(
        classification.request_digest().clone(),
        local_agent_terminal_application::ContextSensitivity::Secret,
        classification.evidence().clone(),
        classification.result_digest().clone(),
        classification.classified_at(),
    )
    .is_err());
    assert!(ContextSourceClassification::rehydrate(
        classification.request_digest().clone(),
        classification.sensitivity(),
        classification.evidence().clone(),
        classification.result_digest().clone(),
        Timestamp::from_unix_seconds(classification.classified_at().unix_seconds() + 1),
    )
    .is_err());
    assert!(ContextSourceClassification::rehydrate(
        classification.request_digest().clone(),
        classification.sensitivity(),
        ContextArtifactRef::new(
            ArtifactId::new("classification-substituted").unwrap(),
            classification.evidence().content_digest().clone(),
            classification.evidence().size_bytes(),
        )
        .unwrap(),
        classification.result_digest().clone(),
        classification.classified_at(),
    )
    .is_err());
    assert!(ContextSourceClassification::rehydrate(
        classification.request_digest().clone(),
        classification.sensitivity(),
        classification.evidence().clone(),
        digest(b"wrong-result"),
        classification.classified_at(),
    )
    .is_err());

    let record = ContextIndexProvenanceRehydration {
        task_id: chunk.task_id.clone(),
        document_id: chunk.document_id.clone(),
        member_id: chunk.member_id.clone(),
        identity: chunk.identity.clone(),
        artifact: chunk.artifact.clone(),
        metadata: chunk.metadata.clone(),
        line_range: chunk.line_range,
        symbol: chunk.symbol.clone(),
        created_at: chunk.created_at,
        classification: chunk.classification.clone(),
        index_metadata: chunk.provenance.index_metadata().clone(),
        index_content: chunk.provenance.index_content().clone(),
        binding_digest: chunk.provenance.binding_digest().clone(),
    };
    assert_eq!(
        ContextIndexProvenance::rehydrate(record.clone()).unwrap(),
        chunk.provenance
    );

    let mut wrong_symbol = record.clone();
    wrong_symbol.symbol = Some("substituted".to_owned());
    assert!(ContextIndexProvenance::rehydrate(wrong_symbol).is_err());
    let mut wrong_metadata = record.clone();
    wrong_metadata.metadata = serde_json::to_vec(&serde_json::json!({"wrong": true})).unwrap();
    assert!(ContextIndexProvenance::rehydrate(wrong_metadata).is_err());
    let mut wrong_task = record.clone();
    wrong_task.task_id = TaskId::new("task-2").unwrap();
    assert!(ContextIndexProvenance::rehydrate(wrong_task).is_err());
    let mut wrong_document = record.clone();
    wrong_document.document_id = "document-substituted".to_owned();
    assert!(ContextIndexProvenance::rehydrate(wrong_document).is_err());
    let mut wrong_member = record.clone();
    wrong_member.member_id = "member-substituted".to_owned();
    assert!(ContextIndexProvenance::rehydrate(wrong_member).is_err());
    let mut wrong_identity = record.clone();
    wrong_identity.identity = source_identity("src/substituted.rs", b"reopen source");
    assert!(ContextIndexProvenance::rehydrate(wrong_identity).is_err());
    let mut wrong_range = record.clone();
    wrong_range.line_range = Some(local_agent_terminal_domain::LineRange::new(4, 7).unwrap());
    assert!(ContextIndexProvenance::rehydrate(wrong_range).is_err());
    let mut wrong_created_at = record.clone();
    wrong_created_at.created_at =
        Timestamp::from_unix_seconds(record.created_at.unix_seconds() + 1);
    assert!(ContextIndexProvenance::rehydrate(wrong_created_at).is_err());
    let mut wrong_metadata_policy = record.clone();
    wrong_metadata_policy.index_metadata = ContextPolicyDecisionRef::new(
        record.index_metadata.decision_id().clone(),
        digest(b"wrong-metadata-policy"),
    );
    assert!(ContextIndexProvenance::rehydrate(wrong_metadata_policy).is_err());
    let mut wrong_content_policy = record.clone();
    wrong_content_policy.index_content = ContextPolicyDecisionRef::new(
        record.index_content.decision_id().clone(),
        digest(b"wrong-content-policy"),
    );
    assert!(ContextIndexProvenance::rehydrate(wrong_content_policy).is_err());
    let mut wrong_binding_digest = record.clone();
    wrong_binding_digest.binding_digest = digest(b"wrong-binding");
    assert!(ContextIndexProvenance::rehydrate(wrong_binding_digest).is_err());
    let mut wrong_artifact = record;
    wrong_artifact.artifact = ContextArtifactRef::new(
        ArtifactId::new("artifact-substituted").unwrap(),
        chunk.artifact.content_digest().clone(),
        chunk.artifact.size_bytes(),
    )
    .unwrap();
    assert!(ContextIndexProvenance::rehydrate(wrong_artifact).is_err());
}

#[test]
fn retrieved_item_provenance_rejects_substitution_before_new_disclosure() {
    let item = SourceSnapshotItem {
        document_id: "document-retrieved-1".to_owned(),
        updated_at: "2026-08-09T00:00:00Z".to_owned(),
        member_id: "retrieved-1".to_owned(),
        content_artifact_id: ArtifactId::new("artifact-retrieved-1").unwrap(),
        identity: source_identity("src/query.rs", b"retrieved source"),
        metadata: source_metadata(Some("rust"), "query-source"),
        content: b"retrieved source".to_vec(),
        line_range: None,
        symbol: Some("query".to_owned()),
    };
    let (initial, state) = service(snapshot(vec![item]));
    initial.execute(build_request()).unwrap();
    let chunk = state.lock().unwrap().chunks[0].clone();
    state.lock().unwrap().retrieved.push(RetrievedContextItem {
        document_id: chunk.document_id,
        task_id: chunk.task_id,
        member_id: chunk.member_id,
        artifact: chunk.artifact,
        identity: chunk.identity,
        metadata: chunk.metadata,
        line_range: chunk.line_range,
        symbol: Some("substituted-symbol".to_owned()),
        created_at: chunk.created_at,
        classification: chunk.classification,
        provenance: chunk.provenance,
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
        metadata_rewrite: MetadataRewrite::None,
    };
    let decisions = Decisions {
        state: Arc::clone(&state),
    };
    let request = build_request();
    assert!(
        QueryContext::new(&store, &publisher, &publisher, &policy, &decisions)
            .execute(QueryContextRequest {
                query: ContextQuery {
                    task_id: TaskId::new("task-1").unwrap(),
                    query_id: "query-hostile".to_owned(),
                    terms: vec!["query".to_owned()],
                    max_items: 4,
                    max_tokens: 1_024,
                },
                policy: request.policy,
                package: request.package,
            })
            .is_err()
    );
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
    let classifier = Box::leak(Box::new(Classifier::default()));
    let publisher = Box::leak(Box::new(Publisher {
        state: Arc::clone(&state),
    }));
    let policy = Box::leak(Box::new(Policy {
        state: Arc::clone(&state),
        redact_final_package: false,
        metadata_rewrite: MetadataRewrite::None,
    }));
    let decisions = Box::leak(Box::new(Decisions {
        state: Arc::clone(&state),
    }));
    (
        BuildInitialContext::new(source, classifier, store, publisher, policy, decisions),
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
    let classifier = Box::leak(Box::new(Classifier::default()));
    let publisher = Box::leak(Box::new(Publisher {
        state: Arc::clone(&state),
    }));
    let policy = Box::leak(Box::new(Policy {
        state: Arc::clone(&state),
        redact_final_package: true,
        metadata_rewrite: MetadataRewrite::None,
    }));
    let decisions = Box::leak(Box::new(Decisions {
        state: Arc::clone(&state),
    }));
    (
        BuildInitialContext::new(source, classifier, store, publisher, policy, decisions),
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
    let classifier = Box::leak(Box::new(Classifier::default()));
    let publisher = Box::leak(Box::new(Publisher {
        state: Arc::clone(&state),
    }));
    let policy = Box::leak(Box::new(Policy {
        state: Arc::clone(&state),
        redact_final_package: false,
        metadata_rewrite: MetadataRewrite::None,
    }));
    let decisions = Box::leak(Box::new(Decisions {
        state: Arc::clone(&state),
    }));
    (
        BuildInitialContext::new(source, classifier, store, publisher, policy, decisions),
        state,
    )
}

fn service_with_metadata_options(
    source_snapshot: SourceSnapshot,
    metadata_rewrite: MetadataRewrite,
    substitute_previous_classification: bool,
) -> (BuildInitialContext<'static>, Arc<Mutex<RecordingState>>) {
    let state = Arc::new(Mutex::new(RecordingState::default()));
    let source = Box::leak(Box::new(Source {
        snapshot: source_snapshot,
    }));
    let classifier = Box::leak(Box::new(Classifier {
        substitute_previous: substitute_previous_classification,
        previous: Mutex::new(None),
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
        metadata_rewrite,
    }));
    let decisions = Box::leak(Box::new(Decisions {
        state: Arc::clone(&state),
    }));
    (
        BuildInitialContext::new(source, classifier, store, publisher, policy, decisions),
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
                ContextPackageIdentity::new(
                    "package-1",
                    TaskId::new("task-1").unwrap(),
                    "agent-1",
                    "reviewer",
                    ArtifactId::new("artifact-agent-manifest-1").unwrap(),
                    ArtifactId::new("artifact-package-1").unwrap(),
                    Timestamp::from_unix_seconds(1),
                )
                .unwrap(),
                "analyze repository",
                ContextVersionSet::new("prompt.v1", "retrieval.v1", "tokenizer.v1").unwrap(),
                ContextBudget::new(4_096, 1_024).unwrap(),
            )
            .unwrap(),
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

fn source_metadata(language: Option<&str>, logical_id: &str) -> SourceIndexMetadata {
    SourceIndexMetadata::new(language, [("logicalId", logical_id)]).unwrap()
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
