
#[test]
fn canonical_claim_records_reject_agent_authority_substitution() {
    for record in [
        DeliberationRecord::ClaimSet {
            claims: vec![material_claim(
                "claim-a",
                VerificationMethod::SourceMatch,
                None,
            )],
            artifact: artifact("claim-set-1", '3'),
        },
        DeliberationRecord::VerificationSet {
            claims: vec![material_claim(
                "claim-a",
                VerificationMethod::SourceMatch,
                Some(ClaimVerification::Verified),
            )],
            artifact: artifact("verification-set-1", '4'),
        },
    ] {
        assert!(CanonicalDeliberationFact::issue(
            task_id(),
            EventId::new("event-claim-hostile-1").unwrap(),
            3,
            ActorId::new("agent-1").unwrap(),
            record,
        )
        .is_err());
    }
}

#[test]
fn canonical_claim_parser_rejects_unknown_enums_with_matching_digest() {
    let issued = issued_verification_set();
    for (field, hostile) in [
        ("method", "unknown_method"),
        ("verification", "unknown_verification"),
    ] {
        let mut value: serde_json::Value =
            serde_json::from_slice(issued.canonical_bytes()).unwrap();
        value["fact"]["claims"][0][field] = serde_json::json!(hostile);
        let bytes = serde_json_canonicalizer::to_vec(&value).unwrap();

        assert!(CanonicalDeliberationFact::rehydrate(bytes.clone(), digest_bytes(&bytes)).is_err());
    }
}

#[test]
fn canonical_claim_parser_rejects_tamper_wrong_digest_and_noncanonical_bytes() {
    let issued = issued_verification_set();
    let original_digest = issued.content_digest().clone();
    for (field, hostile) in [("claimId", "claim-tampered"), ("claimant", "agent-9")] {
        let mut value: serde_json::Value =
            serde_json::from_slice(issued.canonical_bytes()).unwrap();
        value["fact"]["claims"][0][field] = serde_json::json!(hostile);
        let bytes = serde_json_canonicalizer::to_vec(&value).unwrap();
        assert!(CanonicalDeliberationFact::rehydrate(bytes, original_digest.clone()).is_err());
    }
    let mut value: serde_json::Value = serde_json::from_slice(issued.canonical_bytes()).unwrap();
    value["taskId"] = serde_json::json!("task-tampered");
    let bytes = serde_json_canonicalizer::to_vec(&value).unwrap();
    assert!(CanonicalDeliberationFact::rehydrate(bytes, original_digest.clone()).is_err());

    assert!(
        CanonicalDeliberationFact::rehydrate(issued.canonical_bytes().to_vec(), digest('0'),)
            .is_err()
    );

    let value: serde_json::Value = serde_json::from_slice(issued.canonical_bytes()).unwrap();
    let noncanonical = serde_json::to_vec_pretty(&value).unwrap();
    assert!(CanonicalDeliberationFact::rehydrate(
        noncanonical.clone(),
        digest_bytes(&noncanonical),
    )
    .is_err());
}

#[test]
fn canonical_decision_draft_round_trips_every_domain_leaf_and_full_ref() {
    let decision = decision_package();
    let reopened = round_trip(
        "event-decision-1",
        ActorId::new("core").unwrap(),
        DeliberationRecord::DecisionDraft {
            decision: decision.clone(),
            artifact: artifact("decision-record-1", '5'),
            plan_artifact: artifact("plan-1", '4'),
            plan_version: 3,
        },
    );

    assert!(matches!(
        reopened.record(),
        DeliberationRecord::DecisionDraft {
            decision: reopened_decision,
            artifact,
            plan_artifact,
            plan_version,
        } if reopened_decision == &decision
            && reopened_decision.selected().approach_id() == "approach-selected"
            && reopened_decision.rejected()[0].reason() == "higher operational risk"
            && reopened_decision.evidence().iter().all(|claim| claim.verification().is_some())
            && reopened_decision.dissent()[0].participant_id() == "agent-2"
            && reopened_decision.plan().as_str() == "plan-1"
            && artifact == &self::artifact("decision-record-1", '5')
            && plan_artifact == &self::artifact("plan-1", '4')
            && *plan_version == 3
    ));
}

#[test]
fn canonical_objection_set_round_trips_strict_severity_and_every_leaf() {
    let objections = objection_set();
    let reopened = round_trip(
        "event-objection-1",
        ActorId::new("core").unwrap(),
        DeliberationRecord::ObjectionSet {
            objections: objections.clone(),
            artifact: artifact("objection-set-1", '6'),
        },
    );

    assert!(matches!(
        reopened.record(),
        DeliberationRecord::ObjectionSet {
            objections: reopened_objections,
            artifact,
        } if reopened_objections == &objections
            && reopened_objections.round() == 2
            && reopened_objections.objections()[0].participant_id() == "agent-1"
            && reopened_objections.objections()[0].severity() == ObjectionSeverity::Severe
            && reopened_objections.objections()[0].impact() == "violates workspace isolation"
            && reopened_objections.objections()[0].violated_requirement()
                == Some("workspace writes stay fenced")
            && artifact == &self::artifact("objection-set-1", '6')
    ));
}

#[test]
fn canonical_severe_objection_acceptance_round_trips_exact_objections_plan_and_refs() {
    let objections = objection_set();
    let review_plan = reopen_review_plan(3);
    let reopened = round_trip(
        "event-severe-objection-accepted-1",
        ActorId::new("core").unwrap(),
        DeliberationRecord::ObjectionSevereAccepted {
            objections: objections.clone(),
            objection_artifact: artifact("objection-set-1", '6'),
            review_plan: review_plan.clone(),
            review_artifact: artifact("review-plan-3", '7'),
        },
    );

    assert!(matches!(
        reopened.record(),
        DeliberationRecord::ObjectionSevereAccepted {
            objections: reopened_objections,
            objection_artifact,
            review_plan: reopened_plan,
            review_artifact,
        } if reopened_objections == &objections
            && objection_artifact == &artifact("objection-set-1", '6')
            && reopened_plan == &review_plan
            && reopened_plan.edges().iter().all(|edge| edge.round() == 3)
            && review_artifact == &artifact("review-plan-3", '7')
    ));
}

#[test]
fn canonical_severe_objection_acceptance_rejects_actor_and_tampering() {
    let record = DeliberationRecord::ObjectionSevereAccepted {
        objections: objection_set(),
        objection_artifact: artifact("objection-set-1", '6'),
        review_plan: reopen_review_plan(3),
        review_artifact: artifact("review-plan-3", '7'),
    };
    assert!(CanonicalDeliberationFact::issue(
        task_id(),
        EventId::new("event-severe-objection-agent").unwrap(),
        3,
        ActorId::new("agent-1").unwrap(),
        record.clone(),
    )
    .is_err());

    let issued = CanonicalDeliberationFact::issue(
        task_id(),
        EventId::new("event-severe-objection-hostile").unwrap(),
        3,
        ActorId::new("core").unwrap(),
        record,
    )
    .unwrap();
    for path in [
        "severity",
        "round",
        "empty_plan",
        "objection_ref",
        "review_ref",
    ] {
        let mut value: serde_json::Value =
            serde_json::from_slice(issued.canonical_bytes()).unwrap();
        match path {
            "severity" => {
                value["fact"]["objections"]["objections"][0]["severity"] = serde_json::json!("low");
            }
            "round" => {
                value["fact"]["review_plan"]["edges"][0]["round"] = serde_json::json!(2);
            }
            "empty_plan" => {
                value["fact"]["review_plan"]["edges"] = serde_json::json!([]);
            }
            "objection_ref" => {
                value["fact"]["objection_artifact"]["sizeBytes"] = serde_json::json!(0);
            }
            "review_ref" => {
                value["fact"]["review_artifact"]["sizeBytes"] = serde_json::json!(0);
            }
            _ => unreachable!(),
        }
        let bytes = serde_json_canonicalizer::to_vec(&value).unwrap();
        assert!(
            CanonicalDeliberationFact::rehydrate(bytes.clone(), digest_bytes(&bytes)).is_err(),
            "{path}"
        );
    }
}

#[test]
fn canonical_supersession_round_trips_both_full_distinct_refs() {
    let reopened = round_trip(
        "event-supersession-1",
        ActorId::new("core").unwrap(),
        DeliberationRecord::Supersession {
            superseded: artifact("decision-old", '7'),
            replacement: artifact("decision-new", '8'),
        },
    );

    assert!(matches!(
        reopened.record(),
        DeliberationRecord::Supersession {
            superseded,
            replacement,
        } if superseded == &self::artifact("decision-old", '7')
            && replacement == &self::artifact("decision-new", '8')
    ));
}

#[test]
fn canonical_a03_records_reject_agent_authority_and_same_id_supersession() {
    for record in [
        DeliberationRecord::DecisionDraft {
            decision: decision_package(),
            artifact: artifact("decision-record-1", '5'),
            plan_artifact: artifact("plan-1", '4'),
            plan_version: 3,
        },
        DeliberationRecord::ObjectionSet {
            objections: objection_set(),
            artifact: artifact("objection-set-1", '6'),
        },
        DeliberationRecord::Supersession {
            superseded: artifact("decision-old", '7'),
            replacement: artifact("decision-new", '8'),
        },
    ] {
        assert!(CanonicalDeliberationFact::issue(
            task_id(),
            EventId::new("event-a03-hostile-1").unwrap(),
            3,
            ActorId::new("agent-1").unwrap(),
            record,
        )
        .is_err());
    }

    assert!(CanonicalDeliberationFact::issue(
        task_id(),
        EventId::new("event-supersession-hostile-1").unwrap(),
        3,
        ActorId::new("core").unwrap(),
        DeliberationRecord::Supersession {
            superseded: artifact("decision-same", '7'),
            replacement: artifact("decision-same", '8'),
        },
    )
    .is_err());
}

#[test]
fn canonical_objection_parser_rejects_unknown_severity_with_matching_digest() {
    let issued = issued_objection_set();
    let mut value: serde_json::Value = serde_json::from_slice(issued.canonical_bytes()).unwrap();
    value["fact"]["objections"]["objections"][0]["severity"] =
        serde_json::json!("unknown_severity");
    let bytes = serde_json_canonicalizer::to_vec(&value).unwrap();

    assert!(CanonicalDeliberationFact::rehydrate(bytes.clone(), digest_bytes(&bytes)).is_err());
}

#[test]
fn canonical_decision_parser_rejects_leaf_and_ref_substitution() {
    let issued = issued_decision_draft();
    for (field, hostile) in [
        ("decision", "approach-tampered".to_owned()),
        ("artifact", digest('9').as_str().to_owned()),
    ] {
        let mut value: serde_json::Value =
            serde_json::from_slice(issued.canonical_bytes()).unwrap();
        if field == "decision" {
            value["fact"]["decision"]["selected"]["approachId"] = serde_json::json!(hostile);
        } else {
            value["fact"]["artifact"]["contentDigest"] = serde_json::json!(hostile);
        }
        let bytes = serde_json_canonicalizer::to_vec(&value).unwrap();
        assert!(
            CanonicalDeliberationFact::rehydrate(bytes, issued.content_digest().clone(),).is_err()
        );
    }
}

#[test]
fn canonical_decision_parser_rejects_plan_ref_and_version_substitution() {
    let issued = issued_decision_draft();
    for field in ["digest", "size"] {
        let mut value: serde_json::Value =
            serde_json::from_slice(issued.canonical_bytes()).unwrap();
        if field == "digest" {
            value["fact"]["planArtifact"]["contentDigest"] =
                serde_json::json!(digest('8').as_str());
        } else {
            value["fact"]["planArtifact"]["sizeBytes"] = serde_json::json!(18);
        }
        let bytes = serde_json_canonicalizer::to_vec(&value).unwrap();
        assert!(
            CanonicalDeliberationFact::rehydrate(bytes, issued.content_digest().clone(),).is_err()
        );
    }

    for (field, hostile) in [
        ("id", serde_json::json!("plan-other")),
        ("size", serde_json::json!(0)),
        ("version", serde_json::json!(0)),
        ("version", serde_json::json!(9_007_199_254_740_992_u64)),
    ] {
        let mut value: serde_json::Value =
            serde_json::from_slice(issued.canonical_bytes()).unwrap();
        match field {
            "id" => value["fact"]["planArtifact"]["artifactId"] = hostile,
            "size" => value["fact"]["planArtifact"]["sizeBytes"] = hostile,
            "version" => value["fact"]["planVersion"] = hostile,
            _ => unreachable!(),
        }
        let bytes = serde_json_canonicalizer::to_vec(&value).unwrap();
        assert!(
            CanonicalDeliberationFact::rehydrate(bytes.clone(), digest_bytes(&bytes)).is_err(),
            "{field}"
        );
    }
}

#[test]
fn canonical_objection_round_closed_round_trips_full_approval_and_record_ref() {
    let plan_approval = plan_approval("task-1");
    let reopened = round_trip(
        "event-objection-closed-1",
        ActorId::new("core").unwrap(),
        DeliberationRecord::ObjectionRoundClosed {
            artifact: artifact("objection-closed-record-1", '9'),
            plan_approval: Box::new(plan_approval.clone()),
        },
    );

    assert_eq!(reopened.actor_type(), "core");
    assert_eq!(reopened.observation_class(), "core_observed");
    assert!(matches!(
        reopened.record(),
        DeliberationRecord::ObjectionRoundClosed {
            artifact: reopened_artifact,
            plan_approval: reopened_approval,
        } if reopened_artifact == &artifact("objection-closed-record-1", '9')
            && reopened_approval.as_ref() == &plan_approval
            && reopened_approval.request_artifact() == plan_approval.request_artifact()
            && reopened_approval.authority_binding().canonical_bytes()
                == plan_approval.authority_binding().canonical_bytes()
    ));
}

#[test]
fn canonical_objection_round_closed_rejects_wrong_actor_and_task() {
    assert!(CanonicalDeliberationFact::issue(
        task_id(),
        EventId::new("event-objection-closed-hostile-actor").unwrap(),
        3,
        ActorId::new("agent-1").unwrap(),
        DeliberationRecord::ObjectionRoundClosed {
            artifact: artifact("objection-closed-record-1", '9'),
            plan_approval: Box::new(plan_approval("task-1")),
        },
    )
    .is_err());

    assert!(CanonicalDeliberationFact::issue(
        task_id(),
        EventId::new("event-objection-closed-hostile-task").unwrap(),
        3,
        ActorId::new("core").unwrap(),
        DeliberationRecord::ObjectionRoundClosed {
            artifact: artifact("objection-closed-record-1", '9'),
            plan_approval: Box::new(plan_approval("task-2")),
        },
    )
    .is_err());
}

#[test]
fn canonical_objection_round_closed_parser_rejects_nested_substitution() {
    let issued = CanonicalDeliberationFact::issue(
        task_id(),
        EventId::new("event-objection-closed-hostile-nested").unwrap(),
        3,
        ActorId::new("core").unwrap(),
        DeliberationRecord::ObjectionRoundClosed {
            artifact: artifact("objection-closed-record-1", '9'),
            plan_approval: Box::new(plan_approval("task-1")),
        },
    )
    .unwrap();

    for path in [
        "operationDigest",
        "requestArtifact.contentDigest",
        "authorityBindingDigest",
        "canonicalBytes",
        "authorityBindingBytes",
    ] {
        let mut value: serde_json::Value =
            serde_json::from_slice(issued.canonical_bytes()).unwrap();
        match path {
            "operationDigest" => {
                value["fact"]["plan_approval"]["operationDigest"] =
                    serde_json::json!(digest('a').as_str());
            }
            "requestArtifact.contentDigest" => {
                value["fact"]["plan_approval"]["requestArtifact"]["contentDigest"] =
                    serde_json::json!(digest('b').as_str());
            }
            "authorityBindingDigest" => {
                value["fact"]["plan_approval"]["authorityBindingDigest"] =
                    serde_json::json!(digest('c').as_str());
            }
            "canonicalBytes" => {
                value["fact"]["plan_approval"]["canonicalBytes"][0] = serde_json::json!(0);
            }
            "authorityBindingBytes" => {
                value["fact"]["plan_approval"]["authorityBindingBytes"][0] = serde_json::json!(0);
            }
            _ => unreachable!(),
        }
        let bytes = serde_json_canonicalizer::to_vec(&value).unwrap();
        assert!(
            CanonicalDeliberationFact::rehydrate(bytes.clone(), digest_bytes(&bytes)).is_err(),
            "{path}"
        );
    }
}

#[test]
fn canonical_objection_round_closed_parser_rejects_noncanonical_nested_request() {
    let issued = CanonicalDeliberationFact::issue(
        task_id(),
        EventId::new("event-objection-closed-hostile-canonical").unwrap(),
        3,
        ActorId::new("core").unwrap(),
        DeliberationRecord::ObjectionRoundClosed {
            artifact: artifact("objection-closed-record-1", '9'),
            plan_approval: Box::new(plan_approval("task-1")),
        },
    )
    .unwrap();
    let mut value: serde_json::Value = serde_json::from_slice(issued.canonical_bytes()).unwrap();
    let request_bytes = value["fact"]["plan_approval"]["canonicalBytes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|byte| byte.as_u64().unwrap() as u8)
        .collect::<Vec<_>>();
    let request_value: serde_json::Value = serde_json::from_slice(&request_bytes).unwrap();
    let noncanonical = serde_json::to_vec_pretty(&request_value).unwrap();
    let noncanonical_digest = digest_bytes(&noncanonical);
    value["fact"]["plan_approval"]["canonicalBytes"] = serde_json::json!(noncanonical);
    value["fact"]["plan_approval"]["operationDigest"] =
        serde_json::json!(noncanonical_digest.as_str());
    value["fact"]["plan_approval"]["requestArtifact"]["contentDigest"] =
        serde_json::json!(noncanonical_digest.as_str());
    value["fact"]["plan_approval"]["requestArtifact"]["sizeBytes"] =
        serde_json::json!(noncanonical.len());
    let bytes = serde_json_canonicalizer::to_vec(&value).unwrap();

    assert!(CanonicalDeliberationFact::rehydrate(bytes.clone(), digest_bytes(&bytes)).is_err());
}

fn task_id() -> TaskId {
    TaskId::new("task-1").unwrap()
}

fn plan_approval(task_id: &str) -> NewPlanApproval {
    plan_approval_at(task_id, 7)
}

fn plan_approval_at(task_id: &str, task_version: u64) -> NewPlanApproval {
    plan_approval_for(task_id, task_version, "plan-1", '1', 2)
}

fn plan_approval_for(
    task_id: &str,
    task_version: u64,
    plan_artifact_id: &str,
    plan_digest_character: char,
    plan_version: u64,
) -> NewPlanApproval {
    let binding = PlanApprovalBindingInput {
        task_id: task_id.to_owned(),
        plan_artifact_id: plan_artifact_id.to_owned(),
        plan_digest: digest(plan_digest_character).as_str().to_owned(),
        plan_version,
        base_commit: "a".repeat(40),
        allowed_paths: vec![PlanApprovalPathScopeV1 {
            root_capability: "workspace-root".to_owned(),
            patterns: vec!["crates/application/**".to_owned()],
        }],
        planned_tool_digests: vec![digest('2').as_str().to_owned()],
        verification_profile_digest: digest('3').as_str().to_owned(),
        risk_class: "high".to_owned(),
        repository_fingerprint: digest('4').as_str().to_owned(),
        policy_snapshot_digest: digest('5').as_str().to_owned(),
        agent_id: "agent-1".to_owned(),
        agent_manifest_digest: digest('6').as_str().to_owned(),
        actor_id: "core".to_owned(),
        task_version,
        workspace_version: 3,
        fencing_epoch: 4,
        requested_at: "2026-07-23T12:00:00Z".to_owned(),
        expires_at: "2026-07-23T12:15:00Z".to_owned(),
    };
    let authority = PlanApprovalAuthorityBinding::issue(binding).unwrap();
    let canonical = canonical_plan_approval_payload(authority.binding()).unwrap();
    NewPlanApproval::rehydrate(NewPlanApprovalRehydration {
        approval_id: ApprovalId::new("approval-plan-recovery-1").unwrap(),
        request_artifact: PlanApprovalRequestArtifact {
            artifact_id: ArtifactId::new("approval-request-1").unwrap(),
            content_digest: canonical.operation_digest.clone(),
            size_bytes: canonical.canonical_bytes.len() as u64,
        },
        canonical_bytes: canonical.canonical_bytes,
        operation_digest: canonical.operation_digest,
        authority_binding_bytes: authority.canonical_bytes().to_vec(),
        authority_binding_digest: authority.content_digest().clone(),
    })
    .unwrap()
}

fn assignment(
    run_id: &str,
    agent_id: &str,
    family: &str,
    actor_id: &str,
) -> DeliberationRunAssignment {
    DeliberationRunAssignment::new(
        RunId::new(run_id).unwrap(),
        agent_id,
        local_agent_terminal_domain::AgentFamilyKey::new(family).unwrap(),
        ActorId::new(actor_id).unwrap(),
    )
    .unwrap()
}

fn private_proposal_fact() -> CanonicalDeliberationFact {
    private_proposal_fact_for(1, "event-1", 3)
}

fn private_proposal_fact_for(
    number: u8,
    event_id: &str,
    event_sequence: u64,
) -> CanonicalDeliberationFact {
    CanonicalDeliberationFact::issue(
        task_id(),
        EventId::new(event_id).unwrap(),
        event_sequence,
        ActorId::new(format!("agent-{number}")).unwrap(),
        DeliberationRecord::PrivateProposal {
            proposal: proposal(number),
            proposal_artifact: artifact(&format!("proposal-{number}"), 'c'),
            receipt: artifact(&format!("receipt-{number}"), 'a'),
        },
    )
    .unwrap()
}

fn retry_private_proposal_fact(event_id: &str, event_sequence: u64) -> CanonicalDeliberationFact {
    let proposal = IndependentProposal::new(
        task_id(),
        RunId::new("run-3").unwrap(),
        "agent-1",
        local_agent_terminal_domain::AgentFamilyKey::new("family-1").unwrap(),
        ArtifactId::new("proposal-3").unwrap(),
        vec![citation()],
    )
    .unwrap();
    CanonicalDeliberationFact::issue(
        task_id(),
        EventId::new(event_id).unwrap(),
        event_sequence,
        ActorId::new("agent-1").unwrap(),
        DeliberationRecord::PrivateProposal {
            proposal,
            proposal_artifact: artifact("proposal-3", 'f'),
            receipt: artifact("receipt-3", 'a'),
        },
    )
    .unwrap()
}

fn quorum_fact(
    proposals: Vec<IndependentProposal>,
    event_id: &str,
    event_sequence: u64,
) -> CanonicalDeliberationFact {
    quorum_fact_with_plan(proposals, review_plan(), event_id, event_sequence)
}

fn quorum_fact_with_plan(
    proposals: Vec<IndependentProposal>,
    review_plan: ReviewPlan,
    event_id: &str,
    event_sequence: u64,
) -> CanonicalDeliberationFact {
    CanonicalDeliberationFact::issue(
        task_id(),
        EventId::new(event_id).unwrap(),
        event_sequence,
        ActorId::new("core").unwrap(),
        DeliberationRecord::QuorumPublication {
            proposals,
            proposal_artifact: artifact("proposal-bundle-1", 'd'),
            review_plan,
            review_artifact: artifact("review-plan-1", 'e'),
        },
    )
    .unwrap()
}

fn specialist_request_fact(
    request: SpecialistRequest,
    event_id: &str,
    event_sequence: u64,
) -> CanonicalDeliberationFact {
    CanonicalDeliberationFact::issue(
        task_id(),
        EventId::new(event_id).unwrap(),
        event_sequence,
        ActorId::new("agent-1").unwrap(),
        DeliberationRecord::SpecialistRequest {
            request,
            artifact: artifact("specialist-request-1", '2'),
        },
    )
    .unwrap()
}

fn review_edges_fact(event_id: &str, event_sequence: u64) -> CanonicalDeliberationFact {
    review_edges_fact_with(
        review_plan(),
        artifact("review-plan-1", 'e'),
        event_id,
        event_sequence,
    )
}

fn review_edges_fact_with(
    plan: ReviewPlan,
    artifact: DeliberationArtifactRef,
    event_id: &str,
    event_sequence: u64,
) -> CanonicalDeliberationFact {
    CanonicalDeliberationFact::issue(
        task_id(),
        EventId::new(event_id).unwrap(),
        event_sequence,
        ActorId::new("core").unwrap(),
        DeliberationRecord::ReviewEdges { plan, artifact },
    )
    .unwrap()
}

fn thread_summary_fact(
    thread_id: &str,
    event_id: &str,
    event_sequence: u64,
) -> CanonicalDeliberationFact {
    CanonicalDeliberationFact::issue(
        task_id(),
        EventId::new(event_id).unwrap(),
        event_sequence,
        ActorId::new("core").unwrap(),
        DeliberationRecord::ThreadSummary {
            thread_id: thread_id.to_owned(),
            artifact: artifact("thread-summary-1", '1'),
        },
    )
    .unwrap()
}

fn lifecycle_facts_to_decision() -> Vec<CanonicalDeliberationFact> {
    vec![
        private_proposal_fact_for(1, "event-private-1", 1),
        private_proposal_fact_for(2, "event-private-2", 2),
        quorum_fact(quorum_proposals(), "event-quorum-1", 3),
        claim_set_fact("event-claims-1", 4),
        verification_set_fact("event-verification-1", 5),
        decision_draft_fact("event-decision-1", 6),
    ]
}

fn claim_set_fact(event_id: &str, event_sequence: u64) -> CanonicalDeliberationFact {
    CanonicalDeliberationFact::issue(
        task_id(),
        EventId::new(event_id).unwrap(),
        event_sequence,
        ActorId::new("core").unwrap(),
        DeliberationRecord::ClaimSet {
            claims: unclassified_claims(),
            artifact: artifact("claim-set-1", '3'),
        },
    )
    .unwrap()
}

fn verification_set_fact(event_id: &str, event_sequence: u64) -> CanonicalDeliberationFact {
    CanonicalDeliberationFact::issue(
        task_id(),
        EventId::new(event_id).unwrap(),
        event_sequence,
        ActorId::new("core").unwrap(),
        DeliberationRecord::VerificationSet {
            claims: classified_claims(),
            artifact: artifact("verification-set-1", '4'),
        },
    )
    .unwrap()
}

fn decision_draft_fact(event_id: &str, event_sequence: u64) -> CanonicalDeliberationFact {
    decision_draft_fact_with(decision_package(), event_id, event_sequence)
}

fn decision_draft_fact_with(
    decision: DecisionPackage,
    event_id: &str,
    event_sequence: u64,
) -> CanonicalDeliberationFact {
    CanonicalDeliberationFact::issue(
        task_id(),
        EventId::new(event_id).unwrap(),
        event_sequence,
        ActorId::new("core").unwrap(),
        DeliberationRecord::DecisionDraft {
            decision,
            artifact: artifact("decision-record-1", '5'),
            plan_artifact: artifact("plan-1", '4'),
            plan_version: 3,
        },
    )
    .unwrap()
}

fn objection_set_fact(
    event_id: &str,
    event_sequence: u64,
    objections: FinalObjectionSet,
    artifact: DeliberationArtifactRef,
) -> CanonicalDeliberationFact {
    CanonicalDeliberationFact::issue(
        task_id(),
        EventId::new(event_id).unwrap(),
        event_sequence,
        ActorId::new("core").unwrap(),
        DeliberationRecord::ObjectionSet {
            objections,
            artifact,
        },
    )
    .unwrap()
}

fn severe_acceptance_fact(
    event_id: &str,
    event_sequence: u64,
    objections: FinalObjectionSet,
    objection_artifact: DeliberationArtifactRef,
    review_plan: ReviewPlan,
    review_artifact: DeliberationArtifactRef,
) -> CanonicalDeliberationFact {
    CanonicalDeliberationFact::issue(
        task_id(),
        EventId::new(event_id).unwrap(),
        event_sequence,
        ActorId::new("core").unwrap(),
        DeliberationRecord::ObjectionSevereAccepted {
            objections,
            objection_artifact,
            review_plan,
            review_artifact,
        },
    )
    .unwrap()
}

fn claim_set_fact_for_round(
    event_id: &str,
    event_sequence: u64,
    round: u32,
) -> CanonicalDeliberationFact {
    CanonicalDeliberationFact::issue(
        task_id(),
        EventId::new(event_id).unwrap(),
        event_sequence,
        ActorId::new("core").unwrap(),
        DeliberationRecord::ClaimSet {
            claims: unclassified_claims(),
            artifact: artifact(&format!("claim-set-{round}"), '3'),
        },
    )
    .unwrap()
}

fn verification_set_fact_for_round(
    event_id: &str,
    event_sequence: u64,
    round: u32,
) -> CanonicalDeliberationFact {
    CanonicalDeliberationFact::issue(
        task_id(),
        EventId::new(event_id).unwrap(),
        event_sequence,
        ActorId::new("core").unwrap(),
        DeliberationRecord::VerificationSet {
            claims: classified_claims(),
            artifact: artifact(&format!("verification-set-{round}"), '4'),
        },
    )
    .unwrap()
}

fn supersession_fact(
    event_id: &str,
    event_sequence: u64,
    superseded: DeliberationArtifactRef,
    replacement: DeliberationArtifactRef,
) -> CanonicalDeliberationFact {
    CanonicalDeliberationFact::issue(
        task_id(),
        EventId::new(event_id).unwrap(),
        event_sequence,
        ActorId::new("core").unwrap(),
        DeliberationRecord::Supersession {
            superseded,
            replacement,
        },
    )
    .unwrap()
}

fn decision_draft_fact_for_round(
    event_id: &str,
    event_sequence: u64,
    round: u32,
) -> CanonicalDeliberationFact {
    let plan_id = format!("plan-{round}");
    CanonicalDeliberationFact::issue(
        task_id(),
        EventId::new(event_id).unwrap(),
        event_sequence,
        ActorId::new("core").unwrap(),
        DeliberationRecord::DecisionDraft {
            decision: decision_package_for(&plan_id),
            artifact: artifact(&format!("decision-record-{round}"), '8'),
            plan_artifact: artifact(&plan_id, '4'),
            plan_version: u64::from(round),
        },
    )
    .unwrap()
}

fn objection_round_closed_fact(
    event_id: &str,
    event_sequence: u64,
    plan_approval: NewPlanApproval,
) -> CanonicalDeliberationFact {
    CanonicalDeliberationFact::issue(
        task_id(),
        EventId::new(event_id).unwrap(),
        event_sequence,
        ActorId::new("core").unwrap(),
        DeliberationRecord::ObjectionRoundClosed {
            artifact: artifact("objection-closed-record-1", 'a'),
            plan_approval: Box::new(plan_approval),
        },
    )
    .unwrap()
}

fn unclassified_claims() -> Vec<MaterialClaim> {
    vec![
        material_claim("claim-a", VerificationMethod::SourceMatch, None),
        material_claim("claim-b", VerificationMethod::PolicyReview, None),
    ]
}

fn classified_claims() -> Vec<MaterialClaim> {
    vec![
        material_claim(
            "claim-a",
            VerificationMethod::SourceMatch,
            Some(ClaimVerification::Verified),
        ),
        material_claim(
            "claim-b",
            VerificationMethod::PolicyReview,
            Some(ClaimVerification::Rejected),
        ),
    ]
}

fn round_trip(
    event_id: &str,
    actor_id: ActorId,
    record: DeliberationRecord,
) -> CanonicalDeliberationFact {
    let issued = CanonicalDeliberationFact::issue(
        task_id(),
        EventId::new(event_id).unwrap(),
        3,
        actor_id,
        record,
    )
    .unwrap();
    let reopened = CanonicalDeliberationFact::rehydrate(
        issued.canonical_bytes().to_vec(),
        issued.content_digest().clone(),
    )
    .unwrap();
    assert_eq!(reopened, issued);
    reopened
}

fn quorum_proposals() -> Vec<IndependentProposal> {
    IndependentQuorum::new(vec![proposal(1), proposal(2)])
        .unwrap()
        .reveal()
}

fn review_plan() -> ReviewPlan {
    ReviewPlan::new(
        DeliberationLimits::new(2, 2, 2, 2).unwrap(),
        vec![
            ReviewEdge::new("agent-2", ArtifactId::new("proposal-1").unwrap(), 1).unwrap(),
            ReviewEdge::new("agent-1", ArtifactId::new("proposal-2").unwrap(), 2).unwrap(),
        ],
    )
    .unwrap()
}

fn multi_reviewer_plan() -> ReviewPlan {
    ReviewPlan::new(
        DeliberationLimits::new(3, 2, 4, 2).unwrap(),
        vec![
            ReviewEdge::new("agent-2", ArtifactId::new("proposal-1").unwrap(), 1).unwrap(),
            ReviewEdge::new("agent-3", ArtifactId::new("proposal-1").unwrap(), 1).unwrap(),
            ReviewEdge::new("agent-1", ArtifactId::new("proposal-2").unwrap(), 1).unwrap(),
        ],
    )
    .unwrap()
}

fn reopen_review_plan(round: u32) -> ReviewPlan {
    ReviewPlan::new(
        DeliberationLimits::new(2, round, 2, 2).unwrap(),
        vec![
            ReviewEdge::new("agent-2", ArtifactId::new("proposal-1").unwrap(), round).unwrap(),
            ReviewEdge::new("agent-1", ArtifactId::new("proposal-2").unwrap(), round).unwrap(),
        ],
    )
    .unwrap()
}

fn reopen_review_plan_with(reviewer: &str, target: &str) -> ReviewPlan {
    ReviewPlan::new(
        DeliberationLimits::new(2, 2, 2, 2).unwrap(),
        vec![
            ReviewEdge::new(reviewer, ArtifactId::new(target).unwrap(), 2).unwrap(),
            ReviewEdge::new("agent-1", ArtifactId::new("proposal-2").unwrap(), 2).unwrap(),
        ],
    )
    .unwrap()
}

fn specialist_request() -> SpecialistRequest {
    SpecialistRequest::new(
        "specialist-1",
        task_id(),
        RunId::new("run-1").unwrap(),
        "repository-analysis",
        "inspect repository invariants",
        vec![
            ArtifactId::new("context-2").unwrap(),
            ArtifactId::new("context-1").unwrap(),
        ],
        SpecialistBudget::new(512, 5_120, Timestamp::from_unix_seconds(1_800_000_000)).unwrap(),
    )
    .unwrap()
}

fn material_claim(
    claim_id: &str,
    method: VerificationMethod,
    verification: Option<ClaimVerification>,
) -> MaterialClaim {
    let claim = MaterialClaim::new(
        claim_id,
        "agent-1",
        ArtifactId::new("proposal-1").unwrap(),
        vec![citation()],
        method,
    )
    .unwrap();
    match verification {
        Some(verification) => claim.classify(verification).unwrap(),
        None => claim,
    }
}

fn issued_verification_set() -> CanonicalDeliberationFact {
    CanonicalDeliberationFact::issue(
        task_id(),
        EventId::new("event-verification-hostile-1").unwrap(),
        3,
        ActorId::new("core").unwrap(),
        DeliberationRecord::VerificationSet {
            claims: vec![material_claim(
                "claim-a",
                VerificationMethod::SourceMatch,
                Some(ClaimVerification::Verified),
            )],
            artifact: artifact("verification-set-1", '4'),
        },
    )
    .unwrap()
}

fn decision_package() -> DecisionPackage {
    decision_package_for("plan-1")
}

fn decision_package_for(plan_id: &str) -> DecisionPackage {
    let selected = DecisionApproach::new(
        "approach-selected",
        ArtifactId::new("approach-selected-artifact").unwrap(),
        vec!["claim-a".to_owned()],
    )
    .unwrap();
    let rejected = RejectedApproach::new(
        DecisionApproach::new(
            "approach-rejected",
            ArtifactId::new("approach-rejected-artifact").unwrap(),
            vec!["claim-b".to_owned()],
        )
        .unwrap(),
        "higher operational risk",
    )
    .unwrap();
    let dissent = vec![
        Dissent::new(
            "dissent-b",
            "agent-3",
            ArtifactId::new("dissent-artifact-b").unwrap(),
            "prefers a smaller change",
        )
        .unwrap(),
        Dissent::new(
            "dissent-a",
            "agent-2",
            ArtifactId::new("dissent-artifact-a").unwrap(),
            "requires stronger verification",
        )
        .unwrap(),
    ];
    DecisionPackage::new(
        selected,
        vec![rejected],
        vec![
            material_claim(
                "claim-b",
                VerificationMethod::PolicyReview,
                Some(ClaimVerification::Rejected),
            ),
            material_claim(
                "claim-a",
                VerificationMethod::SourceMatch,
                Some(ClaimVerification::Verified),
            ),
        ],
        dissent,
        &["dissent-a", "dissent-b"],
        ArtifactId::new(plan_id).unwrap(),
    )
    .unwrap()
}

fn objection_set() -> FinalObjectionSet {
    FinalObjectionSet::new(
        2,
        vec![
            FinalObjection::new(
                "agent-2",
                2,
                ObjectionSeverity::Low,
                "minor documentation ambiguity",
                vec![citation()],
                None,
            )
            .unwrap(),
            FinalObjection::new(
                "agent-1",
                2,
                ObjectionSeverity::Severe,
                "violates workspace isolation",
                vec![citation()],
                Some("workspace writes stay fenced"),
            )
            .unwrap(),
        ],
    )
    .unwrap()
}

fn objection_set_for(round: u32, severity: ObjectionSeverity) -> FinalObjectionSet {
    FinalObjectionSet::new(
        round,
        vec![FinalObjection::new(
            "agent-1",
            round,
            severity,
            "reviewed lifecycle objection",
            vec![citation()],
            Some("decision history remains immutable"),
        )
        .unwrap()],
    )
    .unwrap()
}

fn issued_decision_draft() -> CanonicalDeliberationFact {
    CanonicalDeliberationFact::issue(
        task_id(),
        EventId::new("event-decision-hostile-1").unwrap(),
        3,
        ActorId::new("core").unwrap(),
        DeliberationRecord::DecisionDraft {
            decision: decision_package(),
            artifact: artifact("decision-record-1", '5'),
            plan_artifact: artifact("plan-1", '4'),
            plan_version: 3,
        },
    )
    .unwrap()
}

fn issued_objection_set() -> CanonicalDeliberationFact {
    CanonicalDeliberationFact::issue(
        task_id(),
        EventId::new("event-objection-hostile-1").unwrap(),
        3,
        ActorId::new("core").unwrap(),
        DeliberationRecord::ObjectionSet {
            objections: objection_set(),
            artifact: artifact("objection-set-1", '6'),
        },
    )
    .unwrap()
}

fn digest_bytes(bytes: &[u8]) -> Sha256Digest {
    Sha256Digest::new(format!("sha256:{:x}", Sha256::digest(bytes))).unwrap()
}

fn proposal(number: u8) -> IndependentProposal {
    IndependentProposal::new(
        task_id(),
        RunId::new(format!("run-{number}")).unwrap(),
        &format!("agent-{number}"),
        local_agent_terminal_domain::AgentFamilyKey::new(format!("family-{number}")).unwrap(),
        ArtifactId::new(format!("proposal-{number}")).unwrap(),
        vec![citation()],
    )
    .unwrap()
}

fn state(phase: Phase, sequence: u64) -> WorkflowState {
    WorkflowState::new(
        phase,
        Condition::Active,
        OperationState::None,
        Sequence::new(sequence),
        WorkspaceVersion::new(1),
        FencingToken::new(1).unwrap(),
    )
    .unwrap()
}

fn artifact(id: &str, character: char) -> DeliberationArtifactRef {
    DeliberationArtifactRef::new(ArtifactId::new(id).unwrap(), digest(character), 17).unwrap()
}

fn digest(character: char) -> Sha256Digest {
    Sha256Digest::new(format!("sha256:{}", character.to_string().repeat(64))).unwrap()
}

fn citation() -> local_agent_terminal_domain::EvidenceCitation {
    local_agent_terminal_domain::EvidenceCitation::new(
        local_agent_terminal_domain::SourceIdentity::new(
            local_agent_terminal_domain::ProjectId::new("project-1").unwrap(),
            "a".repeat(40),
            "src/lib.rs",
            digest('b'),
        )
        .unwrap(),
        None,
        Some("entry"),
        local_agent_terminal_domain::EvidenceFreshness::Current,
    )
    .unwrap()
}
