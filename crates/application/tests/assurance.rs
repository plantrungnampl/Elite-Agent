use local_agent_terminal_application::{
    AssuranceAssessment, AssuranceDecision, AssuranceDegradationInput, AssuranceDegradationReceipt,
    AssuranceReasonCode, AssuranceRequirements, AssuranceRunEvidence, ProfileEscalationCommand,
};
use local_agent_terminal_domain::{
    ArtifactId, RunId, Sha256Digest, TaskId, Timestamp, WorkflowProfile,
};
use sha2::{Digest, Sha256};

#[test]
fn profile_escalation_accepts_only_monotonic_routes() {
    let allowed = [
        (WorkflowProfile::Quick, WorkflowProfile::Standard),
        (WorkflowProfile::Quick, WorkflowProfile::HighAssurance),
        (WorkflowProfile::Standard, WorkflowProfile::HighAssurance),
    ];
    for (from, to) in allowed {
        assert!(escalation(from, to).validate().is_ok());
    }

    let profiles = [
        WorkflowProfile::Quick,
        WorkflowProfile::Standard,
        WorkflowProfile::HighAssurance,
        WorkflowProfile::ReadOnlyResearch,
    ];
    for from in profiles {
        for to in profiles {
            if !allowed.contains(&(from, to)) {
                assert!(
                    escalation(from, to).validate().is_err(),
                    "unexpected escalation route {from:?} -> {to:?}"
                );
            }
        }
    }
}

#[test]
fn degradation_derives_stable_groups_run_set_and_role_separation() {
    let mut input = degradation(
        AssuranceDecision::Pause,
        vec![
            run("run-b", "group-a"),
            run("run-a", "group-a"),
            run("run-c", "group-b"),
        ],
        "run-a",
        "run-c",
        None,
        None,
    );
    input.requirements.minimum_distinct_independence_groups = 3;
    let receipt = AssuranceDegradationReceipt::issue(input).unwrap();

    assert_eq!(receipt.observed().distinct_independence_groups, 2);
    assert_eq!(
        receipt
            .observed()
            .run_refs
            .iter()
            .map(RunId::as_str)
            .collect::<Vec<_>>(),
        vec!["run-a", "run-b", "run-c"]
    );
    assert!(receipt.observed().role_separation_satisfied);

    let mut reordered_input = degradation(
        AssuranceDecision::Pause,
        vec![
            run("run-c", "group-b"),
            run("run-b", "group-a"),
            run("run-a", "group-a"),
        ],
        "run-a",
        "run-c",
        None,
        None,
    );
    reordered_input
        .requirements
        .minimum_distinct_independence_groups = 3;
    let reordered = AssuranceDegradationReceipt::issue(reordered_input).unwrap();
    assert_eq!(
        receipt.observed().run_set_digest,
        reordered.observed().run_set_digest
    );

    let same_role = AssuranceDegradationReceipt::issue(degradation(
        AssuranceDecision::Cancel,
        vec![run("run-a", "group-a")],
        "run-a",
        "run-a",
        None,
        None,
    ))
    .unwrap();
    assert!(!same_role.observed().role_separation_satisfied);
}

#[test]
fn all_decisions_are_closed_and_continue_requires_both_actor_proofs() {
    for decision in [AssuranceDecision::Pause, AssuranceDecision::Cancel] {
        assert!(AssuranceDegradationReceipt::issue(degradation(
            decision,
            vec![run("run-a", "group-a")],
            "run-a",
            "run-a",
            None,
            None,
        ))
        .is_ok());
    }

    for (actor, acceptance) in [
        (None, None),
        (Some("actor-binding-1"), None),
        (None, Some("artifact/acceptance-1")),
    ] {
        assert!(AssuranceDegradationReceipt::issue(degradation(
            AssuranceDecision::ContinueDegraded,
            vec![run("run-a", "group-a")],
            "run-a",
            "run-a",
            actor,
            acceptance,
        ))
        .is_err());
    }

    let continued = AssuranceDegradationReceipt::issue(degradation(
        AssuranceDecision::ContinueDegraded,
        vec![run("run-a", "group-a")],
        "run-a",
        "run-a",
        Some("actor-binding-1"),
        Some("artifact/acceptance-1"),
    ))
    .unwrap();
    assert_eq!(
        continued.requested_profile(),
        WorkflowProfile::HighAssurance
    );
    assert_eq!(continued.actor_binding_id(), Some("actor-binding-1"));
    assert_eq!(
        continued.acceptance_artifact_ref(),
        Some("artifact/acceptance-1")
    );
}

#[test]
fn requested_profile_requirements_cannot_understate_normative_assurance() {
    let mut too_few_groups = degradation(
        AssuranceDecision::Pause,
        vec![run("run-a", "group-a")],
        "run-a",
        "run-a",
        None,
        None,
    );
    too_few_groups
        .requirements
        .minimum_distinct_independence_groups = 1;
    too_few_groups.reason_code = AssuranceReasonCode::ProviderUnavailable;
    assert!(AssuranceDegradationReceipt::issue(too_few_groups).is_err());

    let mut no_role_separation = degradation(
        AssuranceDecision::Pause,
        vec![run("run-a", "group-a")],
        "run-a",
        "run-a",
        None,
        None,
    );
    no_role_separation
        .requirements
        .executor_reviewer_separation_required = false;
    no_role_separation.reason_code = AssuranceReasonCode::ProviderUnavailable;
    assert!(AssuranceDegradationReceipt::issue(no_role_separation).is_err());
}

#[test]
fn canonical_receipt_round_trips_and_rejects_unknown_fields() {
    let receipt = AssuranceDegradationReceipt::issue(degradation(
        AssuranceDecision::ContinueDegraded,
        vec![run("run-a", "group-a")],
        "run-a",
        "run-a",
        Some("actor-binding-1"),
        Some("artifact/acceptance-1"),
    ))
    .unwrap();
    let parsed =
        AssuranceDegradationReceipt::from_canonical_bytes(receipt.canonical_bytes()).unwrap();
    assert_eq!(parsed.receipt_digest(), receipt.receipt_digest());

    let mut hostile: serde_json::Value = serde_json::from_slice(receipt.canonical_bytes()).unwrap();
    hostile["token"] = serde_json::json!("secret");
    let hostile = serde_json_canonicalizer::to_vec(&hostile).unwrap();
    assert!(AssuranceDegradationReceipt::from_canonical_bytes(&hostile).is_err());

    let mut understated: serde_json::Value =
        serde_json::from_slice(receipt.canonical_bytes()).unwrap();
    understated["requirements"]["minimumDistinctIndependenceGroups"] = serde_json::json!(1);
    understated["reasonCode"] = serde_json::json!("provider_unavailable");
    understated.as_object_mut().unwrap().remove("receiptDigest");
    let semantic_bytes = serde_json_canonicalizer::to_vec(&understated).unwrap();
    understated["receiptDigest"] =
        serde_json::json!(format!("sha256:{:x}", Sha256::digest(&semantic_bytes)));
    let understated = serde_json_canonicalizer::to_vec(&understated).unwrap();
    assert!(AssuranceDegradationReceipt::from_canonical_bytes(&understated).is_err());
}

fn escalation(
    from_profile: WorkflowProfile,
    to_profile: WorkflowProfile,
) -> ProfileEscalationCommand {
    ProfileEscalationCommand {
        revision_id: "revision-2".to_owned(),
        task_id: TaskId::new("task-1").unwrap(),
        expected_stream_version: 7,
        from_profile,
        to_profile,
        reason_artifact_id: ArtifactId::new("reason-1").unwrap(),
        policy_digest: digest('a'),
        actor_binding_id: None,
        created_at: Timestamp::from_unix_seconds(1_786_406_400),
    }
}

fn degradation(
    decision: AssuranceDecision,
    runs: Vec<AssuranceRunEvidence>,
    executor: &str,
    reviewer: &str,
    actor_binding_id: Option<&str>,
    acceptance_artifact_ref: Option<&str>,
) -> AssuranceDegradationInput {
    AssuranceDegradationInput {
        receipt_id: "degradation-1".to_owned(),
        task_id: TaskId::new("task-1").unwrap(),
        requested_profile: WorkflowProfile::HighAssurance,
        requirements: AssuranceRequirements {
            minimum_distinct_independence_groups: 2,
            executor_reviewer_separation_required: true,
        },
        assessment: AssuranceAssessment {
            runs,
            executor_run_id: Some(RunId::new(executor).unwrap()),
            reviewer_run_id: Some(RunId::new(reviewer).unwrap()),
        },
        reason_code: AssuranceReasonCode::InsufficientIndependenceGroups,
        decision,
        actor_binding_id: actor_binding_id.map(str::to_owned),
        acceptance_artifact_ref: acceptance_artifact_ref.map(str::to_owned),
        created_at: Timestamp::from_unix_seconds(1_786_406_400),
    }
}

fn run(run_id: &str, group_id: &str) -> AssuranceRunEvidence {
    AssuranceRunEvidence {
        run_id: RunId::new(run_id).unwrap(),
        independence_group: group_id.to_owned(),
    }
}

fn digest(character: char) -> Sha256Digest {
    Sha256Digest::new(format!("sha256:{}", character.to_string().repeat(64))).unwrap()
}
