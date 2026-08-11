
#[cfg(test)]
mod manifest_tests {
    use local_agent_terminal_domain::{
        ArtifactId, ContextBudget, ContextPackageDescriptor, ContextPackageIdentity,
        ContextPackageMember, ContextVersionSet, Disclosure, DisclosureKind, EvidenceCitation,
        EvidenceFreshness, LineRange, ProjectId, Sha256Digest, SourceIdentity, TaskId, Timestamp,
    };

    use super::{canonical_context_package_manifest, ContextPackageDraft};
    use crate::{canonical_json::sha256_digest, PolicyDecisionId};

    type Mutation = (&'static str, Box<dyn Fn(&mut ManifestCase)>);

    #[derive(Clone)]
    struct ManifestCase {
        package_id: String,
        task_id: String,
        agent_id: String,
        role: String,
        agent_manifest_artifact_id: String,
        objective: String,
        prompt_version: String,
        retrieval_version: String,
        tokenizer_version: String,
        max_tokens: u64,
        reserved_response_tokens: u64,
        used_input_tokens: u64,
        artifact_id: String,
        created_at: i64,
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
                "agent_id",
                Box::new(|value| value.agent_id = "agent-2".into()),
            ),
            ("role", Box::new(|value| value.role = "planner".into())),
            (
                "agent_manifest_artifact_id",
                Box::new(|value| {
                    value.agent_manifest_artifact_id = "artifact-agent-manifest-2".into()
                }),
            ),
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
            ("created_at", Box::new(|value| value.created_at += 1)),
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
                agent_id: "agent-1".into(),
                role: "reviewer".into(),
                agent_manifest_artifact_id: "artifact-agent-manifest-1".into(),
                objective: "analyze repository".into(),
                prompt_version: "prompt.v1".into(),
                retrieval_version: "retrieval.v1".into(),
                tokenizer_version: "tokenizer.v1".into(),
                max_tokens: 4_096,
                reserved_response_tokens: 1_024,
                used_input_tokens: 17,
                artifact_id: "artifact-package-1".into(),
                created_at: 1,
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
                ContextPackageIdentity::new(
                    &self.package_id,
                    task_id.clone(),
                    &self.agent_id,
                    &self.role,
                    ArtifactId::new(&self.agent_manifest_artifact_id).unwrap(),
                    ArtifactId::new(&self.artifact_id).unwrap(),
                    Timestamp::from_unix_seconds(self.created_at),
                )
                .unwrap(),
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
                ContextPackageDraft { descriptor },
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
