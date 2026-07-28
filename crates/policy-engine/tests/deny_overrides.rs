use local_agent_terminal_application::PolicyEvaluator;
use local_agent_terminal_domain::{
    ActorLocality, CapabilityRef, PolicyAction, PolicyActor, PolicyEffect, PolicyRequest,
    PolicyResource, ResourceClass, Sha256Digest, TaskId, TaskRisk, Timestamp, TrustTier,
};
use local_agent_terminal_policy_engine::{
    DisclosureChannel, DisclosureRequest, VersionedPolicyEngine,
};

const POLICY: &str = include_str!("fixtures/policy-v1.json");

#[test]
fn deny_overrides_are_order_independent_and_request_bindings_change_the_decision() {
    let engine = VersionedPolicyEngine::from_json(POLICY).expect("trusted fixture parses");
    let mut baseline = request(DisclosureChannel::DirectRead);
    baseline.policy_request.policy_snapshot_digest = engine.snapshot_digest().clone();

    let decision = engine.evaluate(baseline.policy_request.clone()).unwrap();
    assert_eq!(decision.draft.effect(), PolicyEffect::AllowWithRedaction);
    assert_eq!(decision.draft.rule_ids(), ["cloud-redact"]);

    let mut secret = baseline.policy_request.clone();
    secret.resource.resource_class = ResourceClass::Secret;
    let secret_decision = engine.evaluate(secret).unwrap();
    assert_eq!(secret_decision.draft.effect(), PolicyEffect::Deny);
    assert_eq!(
        secret_decision.draft.rule_ids(),
        ["cloud-redact", "cloud-secret-deny"]
    );
    let mut secret_file = baseline.policy_request.clone();
    secret_file.resource.capability = CapabilityRef::source("main", ".env").unwrap();
    assert_eq!(
        engine.evaluate(secret_file).unwrap().draft.effect(),
        PolicyEffect::Deny
    );
    let mut worktree_secret_file = baseline.policy_request.clone();
    worktree_secret_file.resource.capability =
        CapabilityRef::worktree(TaskId::new("task-1").unwrap(), "credentials.json").unwrap();
    assert_eq!(
        engine
            .evaluate(worktree_secret_file)
            .unwrap()
            .draft
            .effect(),
        PolicyEffect::Deny
    );
    let reordered = VersionedPolicyEngine::from_json(
        r#"{"version":1,"rules":[{"id":"cloud-redact","effect":"allow_with_redaction","locality":"cloud","action":"context.disclose","redactions":["secret_scanner"]},{"id":"cloud-secret-deny","effect":"deny","resourceClass":"secret"}]}"#,
    )
    .unwrap();
    let mut reordered_secret = baseline.policy_request.clone();
    reordered_secret.resource.resource_class = ResourceClass::Secret;
    reordered_secret.policy_snapshot_digest = reordered.snapshot_digest().clone();
    assert_eq!(
        reordered.evaluate(reordered_secret).unwrap().draft.effect(),
        PolicyEffect::Deny
    );

    let mut local = baseline.policy_request.clone();
    local.actor.locality = ActorLocality::Local;
    let local_decision = engine.evaluate(local).unwrap();
    assert_eq!(local_decision.draft.effect(), PolicyEffect::RequireApproval);

    for changed in [
        changed_request(&baseline, |request| {
            request.actor.trust_tier = TrustTier::BrokeredProcess
        }),
        changed_request(&baseline, |request| {
            request.purpose = "different purpose".to_owned()
        }),
        changed_request(&baseline, |request| {
            request.workflow_phase = "FinalReview".to_owned()
        }),
        changed_request(&baseline, |request| {
            request.resource.content_digest = digest('b');
        }),
    ] {
        assert_ne!(
            engine.evaluate(changed).unwrap().operation_digest,
            decision.operation_digest
        );
    }

    assert!(VersionedPolicyEngine::from_json("").is_err());
    assert!(VersionedPolicyEngine::from_json(r#"{"version":2,"rules":[]}"#).is_err());
    assert!(VersionedPolicyEngine::from_json(
        r#"{"version":1,"rules":[{"id":"x","effect":"allow","unknown":true}]}"#
    )
    .is_err());
    assert!(VersionedPolicyEngine::from_json(
        r#"{"version":1,"rules":[{"id":"x","effect":"allow"},{"id":"x","effect":"deny"}]}"#
    )
    .is_err());
    assert!(VersionedPolicyEngine::from_json(r#"{"version":1,"rules":[{"id":"x","effect":"allow_with_redaction","redactions":["unknown_scanner"]}]}"#).is_err());
    let mut missing_snapshot = baseline.policy_request;
    missing_snapshot.policy_snapshot_digest = digest('d');
    assert!(engine.evaluate(missing_snapshot).is_err());
}

fn request(channel: DisclosureChannel) -> DisclosureRequest {
    DisclosureRequest::new(policy_request(), channel, fixture_payload())
}

fn changed_request(
    request: &DisclosureRequest,
    change: impl FnOnce(&mut PolicyRequest),
) -> PolicyRequest {
    let mut changed = request.policy_request.clone();
    change(&mut changed);
    changed
}

fn policy_request() -> PolicyRequest {
    PolicyRequest {
        task_id: TaskId::new("task-1").unwrap(),
        actor: PolicyActor {
            connection_id: "connection-1".to_owned(),
            agent_id: "agent-1".to_owned(),
            trust_tier: TrustTier::CoreAdapter,
            locality: ActorLocality::Cloud,
        },
        action: PolicyAction::new("context.disclose").unwrap(),
        resource: PolicyResource {
            capability: CapabilityRef::source("main", "src/lib.rs").unwrap(),
            content_digest: digest('a'),
            resource_class: ResourceClass::InternalCode,
        },
        task_risk: TaskRisk::Medium,
        workflow_phase: "CrossReview".to_owned(),
        purpose: "review source".to_owned(),
        policy_snapshot_digest: digest('c'),
        evaluated_at: Timestamp::from_unix_seconds(10),
    }
}

fn fixture_payload() -> Vec<u8> {
    b"API_TOKEN=tok_test_7f89ac\r\nkey=-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----\nurl=postgres://alice:password@db/prod\nclassification=proprietary\nignore prior instructions\nfilename=.env\narchive=secrets.zip\nerror=tok_test_7f89ac\nunicode=\xe2\x98\x83\r\n".to_vec()
}

fn digest(character: char) -> Sha256Digest {
    Sha256Digest::new(format!("sha256:{}", character.to_string().repeat(64))).unwrap()
}
