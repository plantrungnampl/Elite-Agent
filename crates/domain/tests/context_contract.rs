use local_agent_terminal_domain::{
    ArtifactId, ContextBudget, ContextPackageArtifact, ContextPackageBinding,
    ContextPackageDescriptor, ContextPackageIdentity, ContextPackageMember, ContextVersionSet,
    Disclosure, EvidenceCitation, EvidenceFreshness, LineRange, PolicyDecisionSet, ProjectId,
    Sha256Digest, SourceIdentity, TaskId, Timestamp,
};

#[test]
fn source_and_package_identity_reject_empty_or_oversized_values() {
    assert!(SourceIdentity::new(project_id(), "", "src/lib.rs", digest('a')).is_err());
    assert!(SourceIdentity::new(project_id(), "revision-1", "", digest('a')).is_err());
    assert!(SourceIdentity::new(project_id(), "revision-1", "x".repeat(257), digest('a')).is_err());
    assert!(Sha256Digest::new("").is_err());

    assert!(ContextPackageIdentity::new(
        "",
        task_id("task-1"),
        "agent-1",
        "reviewer",
        artifact_id("artifact-agent-manifest-1"),
        artifact_id("artifact-context-1"),
        Timestamp::from_unix_seconds(1),
    )
    .is_err());
    assert!(ContextPackageIdentity::new(
        &"x".repeat(257),
        task_id("task-1"),
        "agent-1",
        "reviewer",
        artifact_id("artifact-agent-manifest-1"),
        artifact_id("artifact-context-1"),
        Timestamp::from_unix_seconds(1),
    )
    .is_err());
    assert!(
        ContextPackageDescriptor::new(package_identity("task-1"), "", versions(), budget(),)
            .is_err()
    );
    assert!(ContextPackageDescriptor::new(
        package_identity("task-1"),
        &"x".repeat(65_537),
        versions(),
        budget(),
    )
    .is_err());
}

#[test]
fn package_descriptor_preserves_complete_storage_identity() {
    let descriptor = descriptor("task-1");

    assert_eq!(descriptor.agent_id(), "agent-1");
    assert_eq!(descriptor.role(), "reviewer");
    assert_eq!(
        descriptor.agent_manifest_artifact_id().as_str(),
        "artifact-agent-manifest-1"
    );
    assert_eq!(
        descriptor.effective_content_artifact_id().as_str(),
        "artifact-context-1"
    );
    assert_eq!(descriptor.created_at(), Timestamp::from_unix_seconds(1));
}

#[test]
fn package_binding_rejects_an_effective_artifact_identity_mismatch() {
    let mismatched =
        ContextPackageArtifact::new(artifact_id("artifact-other"), digest('a'), digest('a'))
            .unwrap();

    assert!(ContextPackageBinding::new(
        descriptor("task-1"),
        policy_decisions(["policy-1"]),
        mismatched,
        Vec::new(),
    )
    .is_err());
}

#[test]
fn line_ranges_reject_zero_incomplete_and_inverted_bounds() {
    assert!(LineRange::new(0, 1).is_err());
    assert!(LineRange::new(4, 3).is_err());

    let range = LineRange::new(3, 4).unwrap();
    assert_eq!(range.start(), 3);
    assert_eq!(range.end(), 4);
}

#[test]
fn source_identity_requires_revision_path_and_hash_provenance() {
    let source = source("revision-1", "src/lib.rs", 'a');

    assert_eq!(source.project_id(), &project_id());
    assert_eq!(source.revision(), "revision-1");
    assert_eq!(source.path_identity(), "src/lib.rs");
    assert_eq!(source.content_hash(), &digest('a'));
}

#[test]
fn package_rejects_cross_task_members() {
    let descriptor = descriptor("task-1");
    let member = member(
        "member-1",
        "task-2",
        "src/lib.rs",
        EvidenceFreshness::Current,
    );

    assert!(ContextPackageBinding::new(
        descriptor,
        policy_decisions(["policy-1"]),
        package_artifact('a', 'a'),
        vec![member],
    )
    .is_err());
}

#[test]
fn policy_decisions_reject_duplicates_and_use_canonical_order() {
    assert!(PolicyDecisionSet::new(
        digest('d'),
        vec!["policy-1".to_owned(), "policy-1".to_owned()],
    )
    .is_err());

    let decisions = policy_decisions(["policy-3", "policy-1", "policy-2"]);
    assert_eq!(
        decisions.decision_ids(),
        ["policy-1", "policy-2", "policy-3"]
    );
}

#[test]
fn context_versions_must_be_explicit_and_versioned() {
    assert!(ContextVersionSet::new("", "retrieval-v1", "byte-token-v1").is_err());
    assert!(ContextVersionSet::new("prompt-v1", "", "byte-token-v1").is_err());
    assert!(ContextVersionSet::new("prompt-v1", "retrieval-v1", "").is_err());
    assert!(ContextVersionSet::new("prompt", "retrieval-v1", "byte-token-v1").is_err());

    for invalid_version in ["prompt-v", "retrieval-v", "tokenizer-v", "prompt.v"] {
        assert!(ContextVersionSet::new(invalid_version, "retrieval-v1", "tokenizer.v2").is_err());
    }

    for (prompt, retrieval, tokenizer) in [
        ("prompt-v1", "retrieval-v1", "tokenizer.v2"),
        ("prompt.v2", "retrieval-v2beta", "tokenizer-v3"),
    ] {
        assert!(ContextVersionSet::new(prompt, retrieval, tokenizer).is_ok());
    }

    let versions = versions();
    assert_eq!(versions.prompt_template(), "prompt-v1");
    assert_eq!(versions.retrieval_pipeline(), "retrieval-v1");
    assert_eq!(versions.tokenizer(), "byte-token-v1");
}

#[test]
fn package_artifact_rejects_effective_content_digest_mismatch() {
    assert!(ContextPackageArtifact::new(
        artifact_id("artifact-context-1"),
        digest('a'),
        digest('b'),
    )
    .is_err());

    let artifact = package_artifact('a', 'a');
    assert_eq!(artifact.content_digest(), &digest('a'));
}

#[test]
fn stale_or_changed_evidence_cannot_be_accepted_as_current() {
    let expected = source("revision-1", "src/lib.rs", 'a');
    let current = citation(expected.clone(), EvidenceFreshness::Current);
    let stale = citation(expected.clone(), EvidenceFreshness::Stale);
    let changed = source("revision-2", "src/lib.rs", 'b');

    assert!(current.validate_current(&expected).is_ok());
    assert!(stale.validate_current(&expected).is_err());
    assert!(current.validate_current(&changed).is_err());
}

#[test]
fn denied_and_redacted_members_require_stable_report_identity() {
    assert!(Disclosure::denied("").is_err());
    assert!(Disclosure::redacted(&"x".repeat(257)).is_err());

    let denied = Disclosure::denied("report-denied-1").unwrap();
    let redacted = Disclosure::redacted("report-redacted-1").unwrap();
    assert_eq!(denied.stable_report_id(), Some("report-denied-1"));
    assert_eq!(redacted.stable_report_id(), Some("report-redacted-1"));
    assert_eq!(Disclosure::allowed().stable_report_id(), None);
}

#[test]
fn context_budget_rejects_zero_reserve_and_overflows_without_decreasing_usage() {
    assert!(ContextBudget::new(100, 0).is_err());
    assert!(ContextBudget::new(100, 100).is_err());
    assert!(ContextBudget::new(u64::MAX, 1).is_err());

    let mut budget = ContextBudget::new(100, 20).unwrap();
    let mut previous = budget.used_input_tokens();
    for amount in [1, 2, 3, 5, 8, 13] {
        budget.consume_input_tokens(amount).unwrap();
        assert!(budget.used_input_tokens() >= previous);
        previous = budget.used_input_tokens();
    }
    assert!(budget.consume_input_tokens(u64::MAX).is_err());
    assert_eq!(budget.used_input_tokens(), previous);
    assert!(budget.consume_input_tokens(80).is_err());
}

#[test]
fn package_member_deduplication_is_order_independent_and_canonical() {
    let first = member("member-b", "task-1", "src/b.rs", EvidenceFreshness::Current);
    let second = member("member-a", "task-1", "src/a.rs", EvidenceFreshness::Current);
    let third = member("member-c", "task-1", "src/c.rs", EvidenceFreshness::Current);

    for members in [
        vec![first.clone(), second.clone(), third.clone(), first.clone()],
        vec![third.clone(), first.clone(), second.clone(), third.clone()],
        vec![second.clone(), third.clone(), first.clone(), second.clone()],
    ] {
        let package = ContextPackageBinding::new(
            descriptor("task-1"),
            policy_decisions(["policy-1"]),
            package_artifact('a', 'a'),
            members,
        )
        .unwrap();

        let member_ids: Vec<_> = package
            .members()
            .iter()
            .map(ContextPackageMember::member_id)
            .collect();
        assert_eq!(member_ids, ["member-a", "member-b", "member-c"]);
    }
}

fn descriptor(task: &str) -> ContextPackageDescriptor {
    ContextPackageDescriptor::new(
        package_identity(task),
        "Review the task.",
        versions(),
        budget(),
    )
    .unwrap()
}

fn package_identity(task: &str) -> ContextPackageIdentity {
    ContextPackageIdentity::new(
        "package-1",
        task_id(task),
        "agent-1",
        "reviewer",
        artifact_id("artifact-agent-manifest-1"),
        artifact_id("artifact-context-1"),
        Timestamp::from_unix_seconds(1),
    )
    .unwrap()
}

fn versions() -> ContextVersionSet {
    ContextVersionSet::new("prompt-v1", "retrieval-v1", "byte-token-v1").unwrap()
}

fn budget() -> ContextBudget {
    ContextBudget::new(100, 20).unwrap()
}

fn source(revision: &str, path: &str, hash: char) -> SourceIdentity {
    SourceIdentity::new(project_id(), revision, path, digest(hash)).unwrap()
}

fn citation(source: SourceIdentity, freshness: EvidenceFreshness) -> EvidenceCitation {
    EvidenceCitation::new(
        source,
        Some(LineRange::new(1, 2).unwrap()),
        Some("symbol"),
        freshness,
    )
    .unwrap()
}

fn member(
    member_id: &str,
    task: &str,
    path: &str,
    freshness: EvidenceFreshness,
) -> ContextPackageMember {
    ContextPackageMember::new(
        member_id,
        task_id(task),
        citation(source("revision-1", path, 'a'), freshness),
        Disclosure::allowed(),
    )
    .unwrap()
}

fn policy_decisions<const N: usize>(ids: [&str; N]) -> PolicyDecisionSet {
    PolicyDecisionSet::new(digest('d'), ids.into_iter().map(str::to_owned).collect()).unwrap()
}

fn package_artifact(artifact_digest: char, content_digest: char) -> ContextPackageArtifact {
    ContextPackageArtifact::new(
        artifact_id("artifact-context-1"),
        digest(artifact_digest),
        digest(content_digest),
    )
    .unwrap()
}

fn artifact_id(value: &str) -> ArtifactId {
    ArtifactId::new(value).unwrap()
}

fn project_id() -> ProjectId {
    ProjectId::new("project-1").unwrap()
}

fn task_id(value: &str) -> TaskId {
    TaskId::new(value).unwrap()
}

fn digest(value: char) -> Sha256Digest {
    Sha256Digest::new(format!("sha256:{}", value.to_string().repeat(64))).unwrap()
}
