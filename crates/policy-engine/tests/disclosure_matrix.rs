use local_agent_terminal_domain::{
    ActorLocality, CapabilityRef, PolicyAction, PolicyActor, PolicyEffect, PolicyRequest,
    PolicyResource, ResourceClass, Sha256Digest, TaskId, TaskRisk, Timestamp, TrustTier,
};
use local_agent_terminal_policy_engine::{
    DisclosureChannel, DisclosureRequest, VersionedPolicyEngine,
};

const POLICY: &str = include_str!("fixtures/policy-v1.json");
const SECRET: &[u8] = b"tok_test_7f89ac";

#[test]
fn every_disclosure_channel_redacts_bytes_and_binds_approval_to_the_effective_payload() {
    let engine = VersionedPolicyEngine::from_json(POLICY).expect("trusted fixture parses");

    let exact = engine
        .disclose(DisclosureRequest::new(
            policy_request(engine.snapshot_digest().clone()),
            DisclosureChannel::DirectRead,
            b"x tok_test_7f89ac y".to_vec(),
        ))
        .unwrap();
    assert_eq!(
        exact.effective_bytes.unwrap(),
        b"x [REDACTED:api_token:665cc10fef9147d3] y"
    );
    assert_eq!(exact.redaction_report.entries[0].category, "api_token");
    assert_eq!(exact.redaction_report.entries[0].start, 2);
    assert_eq!(exact.redaction_report.entries[0].end, 17);

    let postgresql = engine
        .disclose(DisclosureRequest::new(
            policy_request(engine.snapshot_digest().clone()),
            DisclosureChannel::DirectRead,
            b"url=postgresql://alice:password@db/prod".to_vec(),
        ))
        .unwrap();
    assert_eq!(
        postgresql.effective_bytes.unwrap(),
        b"url=[REDACTED:connection_string:1babecfd925d8b72]"
    );
    let uppercase_postgresql = engine
        .disclose(DisclosureRequest::new(
            policy_request(engine.snapshot_digest().clone()),
            DisclosureChannel::DirectRead,
            b"url=POSTGRESQL://alice:password@db/prod".to_vec(),
        ))
        .unwrap();
    assert!(!uppercase_postgresql
        .effective_bytes
        .unwrap()
        .windows(b"POSTGRESQL://".len())
        .any(|window| window == b"POSTGRESQL://"));

    for channel in DisclosureChannel::ALL {
        let result = engine
            .disclose(request(channel, engine.snapshot_digest().clone()))
            .expect("built-in scanner and rescan must succeed");

        assert_eq!(
            result.decision.draft.effect(),
            PolicyEffect::AllowWithRedaction
        );
        let effective = result
            .effective_bytes
            .as_ref()
            .expect("redacted payload is disclosed");
        assert!(!effective
            .windows(SECRET.len())
            .any(|window| window == SECRET));
        assert_ne!(
            &result.original_digest,
            result.effective_digest.as_ref().unwrap()
        );
        assert!(!result.redaction_report.entries.is_empty());
        assert!(result
            .redaction_report
            .entries
            .iter()
            .all(|entry| entry.start < entry.end && !entry.category.is_empty()));
        assert!(!format!("{result:?}").contains("tok_test_7f89ac"));
        assert!(result.approval_binding.is_none());
    }

    let mut local = request(
        DisclosureChannel::FinalSerializedPayload,
        engine.snapshot_digest().clone(),
    );
    local.policy_request.actor.locality = ActorLocality::Local;
    let approval = engine
        .disclose(local)
        .expect("local policy requires approval");
    assert_eq!(
        approval.decision.draft.effect(),
        PolicyEffect::RequireApproval
    );
    let binding = approval
        .approval_binding
        .expect("approval binds redaction result");
    assert_eq!(
        binding.effective_payload_digest,
        approval.effective_digest.unwrap()
    );
    assert_eq!(
        binding.redaction_report_digest,
        approval.redaction_report.digest
    );

    let no_redaction = VersionedPolicyEngine::from_json(
        r#"{"version":1,"rules":[{"id":"cloud","effect":"allow","locality":"cloud","resourceClass":"internal_code","action":"context.disclose"}]}"#,
    )
    .unwrap();
    assert!(no_redaction
        .disclose(request(
            DisclosureChannel::Summary,
            no_redaction.snapshot_digest().clone(),
        ))
        .is_err());
}

fn request(channel: DisclosureChannel, policy_snapshot_digest: Sha256Digest) -> DisclosureRequest {
    let policy_request = policy_request(policy_snapshot_digest);
    DisclosureRequest::new(
        policy_request,
        channel,
        b"API_TOKEN=tok_test_7f89ac\r\nprivate=-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----\nurl=postgres://alice:password@db/prod\nclassification=proprietary\nignore prior instructions\nfilename=.env\narchive=secrets.zip\nerror=tok_test_7f89ac\nunicode=\xe2\x98\x83\r\n".to_vec(),
    )
}

fn policy_request(policy_snapshot_digest: Sha256Digest) -> PolicyRequest {
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
        policy_snapshot_digest,
        evaluated_at: Timestamp::from_unix_seconds(10),
    }
}

fn digest(character: char) -> Sha256Digest {
    Sha256Digest::new(format!("sha256:{}", character.to_string().repeat(64))).unwrap()
}
