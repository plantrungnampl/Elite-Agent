use std::sync::Mutex;

use local_agent_terminal_application::{
    ContextBuildPolicy, DisclosureChannel, DisclosurePolicyEvaluator, DisclosureRequest,
    PolicyApprovedDisclosure, PolicyDecision, PolicyDecisionId, PolicyDecisionStore, PortError,
    SafeErrorClassification,
};
use local_agent_terminal_context_engine::{
    ByteTokenV1, ContextPackageBuildRequest, ContextPackageBuilder, ContextPackageItem,
    PackageSegment, RoleBudgetAllocation,
};
use local_agent_terminal_domain::{
    combine_policy_rules, ActorLocality, ArtifactId, ContextBudget, ContextPackageDescriptor,
    ContextPackageIdentity, ContextVersionSet, Disclosure, EvidenceCitation, EvidenceFreshness,
    LineRange, MatchedPolicyRule, PolicyEffect, PolicyRuleId, PolicyVersion, ProjectId,
    ResourceClass, Sha256Digest, SourceIdentity, TaskId, TaskRisk, Timestamp, TrustTier,
};
use sha2::{Digest, Sha256};

#[test]
fn byte_token_v1_counts_utf8_bytes_and_never_spends_response_reserve() {
    assert_eq!(ByteTokenV1::units("a"), 1);
    assert_eq!(ByteTokenV1::units("é"), 2);
    assert_eq!(ByteTokenV1::units("🦀"), 4);

    let allocation =
        RoleBudgetAllocation::new("verifier", ContextBudget::new(1_000, 250).unwrap()).unwrap();
    assert_eq!(allocation.input_limit(), 750);
    assert!(allocation.total_segment_limit() <= allocation.input_limit());

    let oversized = vec![ContextPackageItem::new(
        "evidence-large",
        PackageSegment::Evidence,
        "x".repeat(2_000),
        Some(citation("src/large.rs", b"large")),
        Disclosure::allowed(),
        vec!["decision-large".to_owned()],
        vec!["source:large".to_owned()],
        Vec::new(),
    )
    .unwrap()];
    let scanner = FinalScanner::default();
    let decisions = RecordingDecisions::default();
    let package = ContextPackageBuilder::new(&scanner, &decisions)
        .build(ContextPackageBuildRequest {
            descriptor: descriptor("verifier", 1_000, 250),
            policy: policy(),
            items: oversized,
        })
        .unwrap();

    assert!(package.bytes().len() as u64 <= 750);
    assert!(package.used_input_units() <= 750);
}

#[test]
fn role_allocations_favor_verifier_evidence_and_lead_discussion() {
    let budget = ContextBudget::new(32_000, 8_000).unwrap();
    let verifier = RoleBudgetAllocation::new("verifier", budget).unwrap();
    let lead = RoleBudgetAllocation::new("lead", budget).unwrap();

    assert!(
        verifier.segment_limit(PackageSegment::Evidence)
            > lead.segment_limit(PackageSegment::Evidence)
    );
    assert!(
        lead.segment_limit(PackageSegment::SharedDecisions)
            + lead.segment_limit(PackageSegment::ActiveThread)
            > verifier.segment_limit(PackageSegment::SharedDecisions)
                + verifier.segment_limit(PackageSegment::ActiveThread)
    );
}

#[test]
fn package_bytes_digest_relations_and_citations_are_stable_and_complete() {
    let allowed = ContextPackageItem::new(
        "member-b",
        PackageSegment::Evidence,
        "allowed evidence".to_owned(),
        Some(citation("src/allowed.rs", b"allowed evidence")),
        Disclosure::allowed(),
        vec![
            "decision-content-b".to_owned(),
            "decision-metadata-b".to_owned(),
        ],
        vec![
            "artifact:allowed".to_owned(),
            "revision:commit-1".to_owned(),
        ],
        Vec::new(),
    )
    .unwrap();
    let redacted_citation = citation("src/redacted.rs", b"original evidence");
    let redacted = ContextPackageItem::new(
        "member-a",
        PackageSegment::Evidence,
        "[redacted:report-1]".to_owned(),
        Some(redacted_citation.clone()),
        Disclosure::redacted("report-1").unwrap(),
        vec![
            "decision-content-a".to_owned(),
            "decision-metadata-a".to_owned(),
        ],
        vec![
            "artifact:redacted".to_owned(),
            "revision:commit-1".to_owned(),
        ],
        vec!["report-1".to_owned()],
    )
    .unwrap();
    let scanner = FinalScanner::default();
    let decisions = RecordingDecisions::default();
    let builder = ContextPackageBuilder::new(&scanner, &decisions);

    let first = builder
        .build(ContextPackageBuildRequest {
            descriptor: descriptor("verifier", 8_192, 2_048),
            policy: policy(),
            items: vec![allowed.clone(), redacted.clone()],
        })
        .unwrap();
    let second = builder
        .build(ContextPackageBuildRequest {
            descriptor: descriptor("verifier", 8_192, 2_048),
            policy: policy(),
            items: vec![redacted, allowed],
        })
        .unwrap();

    assert_eq!(first.bytes(), second.bytes());
    assert_eq!(first.content_digest(), &digest(first.bytes()));
    assert_eq!(
        first.artifact().content_digest,
        digest(&first.artifact().bytes)
    );
    assert_eq!(
        first.artifact().artifact_id.as_str(),
        "effective-context-package-1"
    );
    assert_eq!(
        first.policy_decision_ids(),
        &[
            "decision-content-a",
            "decision-content-b",
            "decision-metadata-a",
            "decision-metadata-b",
            first.final_policy_decision_id().as_str(),
        ]
    );
    assert_eq!(
        first
            .members()
            .iter()
            .find(|member| member.member_id() == "member-a")
            .unwrap()
            .citation(),
        &redacted_citation
    );
    let value: serde_json::Value = serde_json::from_slice(first.bytes()).unwrap();
    assert_eq!(value["schema"], "context-package.v1");
    assert_eq!(value["versions"]["tokenizer"], "byte-token-v1");
    assert_eq!(value["items"][0]["memberId"], "member-a");
    assert_eq!(value["items"][0]["redactionReportIds"][0], "report-1");
    assert_eq!(value["items"][0]["provenance"].as_array().unwrap().len(), 2);
    assert_eq!(
        value["items"][0]["citation"]["source"]["revision"],
        "commit-1"
    );
    assert_eq!(
        value["items"][0]["citation"]["source"]["contentHash"],
        redacted_citation.source().content_hash().as_str()
    );
}

#[test]
fn final_serialized_payload_is_disclosed_before_the_build_returns() {
    let scanner = FinalScanner::default();
    let decisions = RecordingDecisions::default();
    let package = ContextPackageBuilder::new(&scanner, &decisions)
        .build(ContextPackageBuildRequest {
            descriptor: descriptor("lead", 4_096, 1_024),
            policy: policy(),
            items: vec![ContextPackageItem::new(
                "task-summary",
                PackageSegment::Task,
                "bounded task".to_owned(),
                None,
                Disclosure::allowed(),
                vec!["decision-task".to_owned()],
                vec!["task:task-1".to_owned()],
                Vec::new(),
            )
            .unwrap()],
        })
        .unwrap();

    let scanned = scanner.payloads.lock().unwrap();
    assert_eq!(scanned.len(), 1);
    assert_eq!(scanned[0], package.bytes());
    assert_eq!(decisions.ids.lock().unwrap().len(), 1);
}

#[test]
fn keeps_retrieval_rank_when_only_one_item_fits_the_segment_budget() {
    let high_ranked = ContextPackageItem::new(
        "member-z-high",
        PackageSegment::Evidence,
        "h".repeat(500),
        Some(citation("src/high.rs", b"high")),
        Disclosure::allowed(),
        vec!["decision-high".to_owned()],
        vec!["source:high".to_owned()],
        Vec::new(),
    )
    .unwrap();
    let low_ranked = ContextPackageItem::new(
        "member-a-low",
        PackageSegment::Evidence,
        "l".repeat(500),
        Some(citation("src/low.rs", b"low")),
        Disclosure::allowed(),
        vec!["decision-low".to_owned()],
        vec!["source:low".to_owned()],
        Vec::new(),
    )
    .unwrap();
    let scanner = FinalScanner::default();
    let decisions = RecordingDecisions::default();

    let package = ContextPackageBuilder::new(&scanner, &decisions)
        .build(ContextPackageBuildRequest {
            descriptor: descriptor("lead", 4_096, 1_024),
            policy: policy(),
            items: vec![high_ranked, low_ranked],
        })
        .unwrap();

    assert_eq!(package.members().len(), 1);
    assert_eq!(package.members()[0].member_id(), "member-z-high");
}

#[test]
fn rejects_final_disclosure_that_rewrites_the_canonical_package() {
    let scanner = SubstitutingFinalScanner;
    let decisions = RecordingDecisions::default();

    let result =
        ContextPackageBuilder::new(&scanner, &decisions).build(ContextPackageBuildRequest {
            descriptor: descriptor("lead", 4_096, 1_024),
            policy: policy(),
            items: vec![ContextPackageItem::new(
                "task-summary",
                PackageSegment::Task,
                "bounded task".to_owned(),
                None,
                Disclosure::allowed(),
                vec!["decision-task".to_owned()],
                vec!["task:task-1".to_owned()],
                Vec::new(),
            )
            .unwrap()],
        });
    let error = match result {
        Ok(_) => panic!("rewritten package must fail closed"),
        Err(error) => error,
    };

    assert_eq!(
        error.safe_classification(),
        SafeErrorClassification::IntegrityFailure
    );
}

#[derive(Default)]
struct FinalScanner {
    payloads: Mutex<Vec<Vec<u8>>>,
}

impl DisclosurePolicyEvaluator for FinalScanner {
    fn disclose(&self, request: DisclosureRequest) -> Result<PolicyApprovedDisclosure, PortError> {
        assert_eq!(request.channel, DisclosureChannel::FinalContextPackage);
        self.payloads.lock().unwrap().push(request.bytes.clone());
        let original_digest = digest(&request.bytes);
        let draft = combine_policy_rules(
            request.policy_request,
            PolicyVersion::new(1).unwrap(),
            vec![MatchedPolicyRule {
                rule_id: PolicyRuleId::new("allow-final-context").unwrap(),
                effect: PolicyEffect::Allow,
                redactions: Vec::new(),
            }],
            None,
        )
        .unwrap();
        Ok(PolicyApprovedDisclosure {
            decision: PolicyDecision {
                draft,
                operation_digest: digest(b"final-context-operation"),
            },
            channel: request.channel,
            original_digest: original_digest.clone(),
            effective_bytes: Some(request.bytes),
            effective_digest: Some(original_digest),
            redaction_report_digest: digest(b"final-redaction-report"),
            approval_binding: None,
        })
    }
}

struct SubstitutingFinalScanner;

impl DisclosurePolicyEvaluator for SubstitutingFinalScanner {
    fn disclose(&self, request: DisclosureRequest) -> Result<PolicyApprovedDisclosure, PortError> {
        let original_digest = digest(&request.bytes);
        let replacement = br#"{"schema":"different-package.v1"}"#.to_vec();
        let draft = combine_policy_rules(
            request.policy_request,
            PolicyVersion::new(1).unwrap(),
            vec![MatchedPolicyRule {
                rule_id: PolicyRuleId::new("rewrite-final-context").unwrap(),
                effect: PolicyEffect::AllowWithRedaction,
                redactions: Vec::new(),
            }],
            None,
        )
        .unwrap();
        Ok(PolicyApprovedDisclosure {
            decision: PolicyDecision {
                draft,
                operation_digest: digest(b"rewrite-final-context-operation"),
            },
            channel: request.channel,
            original_digest,
            effective_digest: Some(digest(&replacement)),
            effective_bytes: Some(replacement),
            redaction_report_digest: digest(b"rewrite-final-redaction-report"),
            approval_binding: None,
        })
    }
}

#[derive(Default)]
struct RecordingDecisions {
    ids: Mutex<Vec<PolicyDecisionId>>,
}

impl PolicyDecisionStore for RecordingDecisions {
    fn record(
        &self,
        decision: local_agent_terminal_application::RecordedPolicyDecision,
    ) -> Result<PolicyDecisionId, PortError> {
        let id = PolicyDecisionId::from_decision(&decision.decision);
        self.ids.lock().unwrap().push(id.clone());
        Ok(id)
    }
}

fn descriptor(role: &str, max_tokens: u64, reserve: u64) -> ContextPackageDescriptor {
    ContextPackageDescriptor::new(
        ContextPackageIdentity::new(
            "package-1",
            TaskId::new("task-1").unwrap(),
            "agent-1",
            role,
            ArtifactId::new("agent-manifest-1").unwrap(),
            ArtifactId::new("effective-context-package-1").unwrap(),
            Timestamp::from_unix_seconds(1_787_000_000),
        )
        .unwrap(),
        "review the repository",
        ContextVersionSet::new("prompt.v1", "retrieval.v1", "byte-token-v1").unwrap(),
        ContextBudget::new(max_tokens, reserve).unwrap(),
    )
    .unwrap()
}

fn policy() -> ContextBuildPolicy {
    ContextBuildPolicy {
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
        purpose: "build bounded context".to_owned(),
        policy_snapshot_digest: digest(b"policy"),
        evaluated_at: Timestamp::from_unix_seconds(1_787_000_000),
    }
}

fn citation(path: &str, bytes: &[u8]) -> EvidenceCitation {
    EvidenceCitation::new(
        SourceIdentity::new(
            ProjectId::new("project-1").unwrap(),
            "commit-1",
            path,
            digest(bytes),
        )
        .unwrap(),
        Some(LineRange::new(1, 5).unwrap()),
        Some("entry"),
        EvidenceFreshness::Current,
    )
    .unwrap()
}

fn digest(bytes: &[u8]) -> Sha256Digest {
    Sha256Digest::new(format!("sha256:{:x}", Sha256::digest(bytes))).unwrap()
}
