use local_agent_terminal_domain::{
    combine_policy_rules, ActorLocality, CapabilityRef, MatchedPolicyRule, PolicyAction,
    PolicyActor, PolicyEffect, PolicyRequest, PolicyResource, PolicyRuleId, PolicyVersion,
    RedactionDirective, ResourceClass, Sha256Digest, TaskId, TaskRisk, Timestamp, TrustTier,
};

const DIGEST: &str = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

fn request(evaluated_at: i64) -> PolicyRequest {
    PolicyRequest {
        task_id: TaskId::new("task-1").unwrap(),
        actor: PolicyActor {
            connection_id: "connection-1".into(),
            agent_id: "agent-1".into(),
            trust_tier: TrustTier::CoreAdapter,
            locality: ActorLocality::Cloud,
        },
        action: PolicyAction::new("context.disclose").unwrap(),
        resource: PolicyResource {
            capability: CapabilityRef::source("main", "src/lib.rs").unwrap(),
            content_digest: Sha256Digest::new(DIGEST).unwrap(),
            resource_class: ResourceClass::InternalCode,
        },
        task_risk: TaskRisk::Medium,
        workflow_phase: "CrossReview".into(),
        purpose: "review source".into(),
        policy_snapshot_digest: Sha256Digest::new(DIGEST).unwrap(),
        evaluated_at: Timestamp::from_unix_seconds(evaluated_at),
    }
}

fn rule(id: &str, effect: PolicyEffect, redaction: &str) -> MatchedPolicyRule {
    MatchedPolicyRule {
        rule_id: PolicyRuleId::new(id).unwrap(),
        effect,
        redactions: vec![RedactionDirective::new(redaction).unwrap()],
    }
}

#[test]
fn policy_values_reject_empty_oversized_and_malformed_inputs() {
    assert!(PolicyAction::new("").is_err());
    assert!(PolicyRuleId::new(" ").is_err());
    assert!(PolicyRuleId::new("x".repeat(256)).is_ok());
    assert!(PolicyRuleId::new("x".repeat(257)).is_err());
    assert!(Sha256Digest::new("sha256:ABC").is_err());
    assert!(Sha256Digest::new(
        "sha512:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    )
    .is_err());
    assert!(PolicyVersion::new(2).is_err());
}

#[test]
fn policy_combination_denies_no_match_invalid_binding_and_expiry() {
    let version = PolicyVersion::new(1).unwrap();

    let no_match = combine_policy_rules(request(10), version, vec![], None).unwrap();
    assert_eq!(no_match.effect(), PolicyEffect::Deny);
    assert_eq!(no_match.request().task_id.as_str(), "task-1");
    assert_eq!(no_match.policy_version(), version);

    let mut incomplete = request(10);
    incomplete.actor.agent_id.clear();
    let incomplete = combine_policy_rules(
        incomplete,
        version,
        vec![
            rule("z-rule", PolicyEffect::Allow, "secret-pattern"),
            rule("a-rule", PolicyEffect::AllowWithRedaction, "token-mask"),
        ],
        None,
    )
    .unwrap();
    assert_eq!(incomplete.effect(), PolicyEffect::Deny);
    assert_eq!(incomplete.request().actor.agent_id, "");
    assert_eq!(incomplete.policy_version(), version);
    assert_eq!(incomplete.rule_ids(), ["a-rule", "z-rule"]);
    assert_eq!(incomplete.redactions(), ["secret-pattern", "token-mask"]);

    let mut malformed_resource = request(10);
    malformed_resource.resource.capability =
        CapabilityRef::worktree(TaskId::new("other-task").unwrap(), "src/lib.rs").unwrap();
    let malformed_resource = combine_policy_rules(
        malformed_resource,
        version,
        vec![rule("allow", PolicyEffect::Allow, "secret-pattern")],
        None,
    )
    .unwrap();
    assert_eq!(malformed_resource.effect(), PolicyEffect::Deny);
    assert_eq!(malformed_resource.request().task_id.as_str(), "task-1");

    let expired = combine_policy_rules(
        request(10),
        version,
        vec![
            rule("z-rule", PolicyEffect::Allow, "secret-pattern"),
            rule("a-rule", PolicyEffect::AllowWithRedaction, "token-mask"),
        ],
        Some(Timestamp::from_unix_seconds(10)),
    )
    .unwrap();
    assert_eq!(expired.effect(), PolicyEffect::Deny);
    assert_eq!(expired.request().task_id.as_str(), "task-1");
    assert_eq!(expired.policy_version(), version);
    assert_eq!(expired.rule_ids(), ["a-rule", "z-rule"]);
    assert_eq!(expired.redactions(), ["secret-pattern", "token-mask"]);
}

#[test]
fn policy_combination_is_deterministic_and_uses_deny_overrides() {
    let version = PolicyVersion::new(1).unwrap();
    let cases = [
        (vec![PolicyEffect::Allow], PolicyEffect::Allow),
        (
            vec![PolicyEffect::AllowWithRedaction],
            PolicyEffect::AllowWithRedaction,
        ),
        (
            vec![PolicyEffect::RequireApproval],
            PolicyEffect::RequireApproval,
        ),
        (vec![PolicyEffect::Deny], PolicyEffect::Deny),
        (
            vec![PolicyEffect::Allow, PolicyEffect::AllowWithRedaction],
            PolicyEffect::AllowWithRedaction,
        ),
        (
            vec![PolicyEffect::Allow, PolicyEffect::RequireApproval],
            PolicyEffect::RequireApproval,
        ),
        (
            vec![PolicyEffect::Allow, PolicyEffect::Deny],
            PolicyEffect::Deny,
        ),
        (
            vec![
                PolicyEffect::AllowWithRedaction,
                PolicyEffect::RequireApproval,
            ],
            PolicyEffect::RequireApproval,
        ),
        (
            vec![PolicyEffect::AllowWithRedaction, PolicyEffect::Deny],
            PolicyEffect::Deny,
        ),
        (
            vec![PolicyEffect::RequireApproval, PolicyEffect::Deny],
            PolicyEffect::Deny,
        ),
        (
            vec![
                PolicyEffect::Allow,
                PolicyEffect::AllowWithRedaction,
                PolicyEffect::RequireApproval,
            ],
            PolicyEffect::RequireApproval,
        ),
        (
            vec![
                PolicyEffect::Allow,
                PolicyEffect::AllowWithRedaction,
                PolicyEffect::Deny,
            ],
            PolicyEffect::Deny,
        ),
        (
            vec![
                PolicyEffect::Allow,
                PolicyEffect::RequireApproval,
                PolicyEffect::Deny,
            ],
            PolicyEffect::Deny,
        ),
        (
            vec![
                PolicyEffect::AllowWithRedaction,
                PolicyEffect::RequireApproval,
                PolicyEffect::Deny,
            ],
            PolicyEffect::Deny,
        ),
        (
            vec![
                PolicyEffect::Allow,
                PolicyEffect::AllowWithRedaction,
                PolicyEffect::RequireApproval,
                PolicyEffect::Deny,
            ],
            PolicyEffect::Deny,
        ),
    ];

    for (effects, expected) in cases {
        let forward = effects
            .iter()
            .enumerate()
            .map(|(index, effect)| rule(&format!("rule-{index}"), *effect, "secret-pattern"))
            .collect();
        let reverse = effects
            .iter()
            .enumerate()
            .rev()
            .map(|(index, effect)| rule(&format!("rule-{index}"), *effect, "secret-pattern"))
            .collect();

        let forward = combine_policy_rules(request(10), version, forward, None).unwrap();
        let reverse = combine_policy_rules(request(10), version, reverse, None).unwrap();

        assert_eq!(forward.effect(), expected);
        assert_eq!(forward, reverse);
    }

    let effects = [
        PolicyEffect::Allow,
        PolicyEffect::AllowWithRedaction,
        PolicyEffect::RequireApproval,
    ];
    for order in [
        [0, 1, 2],
        [0, 2, 1],
        [1, 0, 2],
        [1, 2, 0],
        [2, 0, 1],
        [2, 1, 0],
    ] {
        let rules = order
            .iter()
            .map(|index| rule(&format!("rule-{index}"), effects[*index], "secret-pattern"))
            .collect();
        assert_eq!(
            combine_policy_rules(request(10), version, rules, None)
                .unwrap()
                .effect(),
            PolicyEffect::RequireApproval,
        );
    }

    let effects = [
        PolicyEffect::Allow,
        PolicyEffect::AllowWithRedaction,
        PolicyEffect::RequireApproval,
        PolicyEffect::Deny,
    ];
    let mut order = [0, 1, 2, 3];
    loop {
        let rules = order
            .iter()
            .map(|index| rule(&format!("rule-{index}"), effects[*index], "secret-pattern"))
            .collect();
        assert_eq!(
            combine_policy_rules(request(10), version, rules, None)
                .unwrap()
                .effect(),
            PolicyEffect::Deny,
        );
        if !next_permutation(&mut order) {
            break;
        }
    }
}

fn next_permutation(values: &mut [usize]) -> bool {
    let Some(pivot) = (0..values.len() - 1).rfind(|&index| values[index] < values[index + 1])
    else {
        return false;
    };
    let successor = (pivot + 1..values.len())
        .rfind(|&index| values[pivot] < values[index])
        .unwrap();
    values.swap(pivot, successor);
    values[pivot + 1..].reverse();
    true
}

#[test]
fn policy_combination_sorts_and_deduplicates_rule_ids_while_retaining_redactions() {
    let decision = combine_policy_rules(
        request(10),
        PolicyVersion::new(1).unwrap(),
        vec![
            rule("z-rule", PolicyEffect::Allow, "secret-pattern"),
            rule("a-rule", PolicyEffect::AllowWithRedaction, "token-mask"),
            rule("z-rule", PolicyEffect::Allow, "secret-pattern"),
        ],
        None,
    )
    .unwrap();

    assert_eq!(decision.rule_ids(), ["a-rule", "z-rule"]);
    assert_eq!(decision.redactions(), ["secret-pattern", "token-mask"]);

    let reordered = combine_policy_rules(
        request(10),
        PolicyVersion::new(1).unwrap(),
        vec![
            rule("z-rule", PolicyEffect::Allow, "secret-pattern"),
            rule("a-rule", PolicyEffect::AllowWithRedaction, "token-mask"),
        ],
        None,
    )
    .unwrap();
    assert_eq!(decision, reordered);
}
