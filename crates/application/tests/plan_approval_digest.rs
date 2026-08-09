use std::sync::Mutex;

use local_agent_terminal_application::{
    canonical_approval_payload, canonical_plan_approval_payload,
    parse_canonical_plan_approval_payload, plan_approval_payload, ApprovalDigestPayload,
    ApprovalId, Clock, CompareAndExpirePlanApproval, CompareAndInvalidatePlanApproval,
    CompareAndResolvePlanApproval, ContextPackageDto, DeliberationWorkspaceDto,
    InvalidatePlanApproval, InvalidatePlanApprovalInput, PlanApprovalAction,
    PlanApprovalAuthorityBinding, PlanApprovalBindingInput, PlanApprovalCurrentState,
    PlanApprovalPathScopeV1, PlanApprovalRequestArtifact, PlanApprovalResolution,
    PlanApprovalState, PlanApprovalStore, PlanApprovalTerminal, PolicyExceptionApprovalOperationV1,
    PolicyExceptionApprovalPayloadV1, PortError, PreparePlanApprovalRequest,
    PreparePlanApprovalRequestInput, ResolvePlanApproval, ResolvePlanApprovalInput,
    ResolvePlanApprovalRequestDto, Retryability, SafeErrorClassification, StoredPlanApproval,
    StoredPlanApprovalRehydration,
};
use local_agent_terminal_domain::{
    ActorId, Condition, FencingToken, OperationState, Phase, Sequence, Sha256Digest, TaskId,
    WorkflowState, WorkspaceVersion,
};

type BindingMutation = (&'static str, Box<dyn Fn(&mut PlanApprovalBindingInput)>);

#[test]
fn every_rich_binding_leaf_changes_the_normative_envelope_digest() {
    let baseline = binding();
    let baseline_digest = canonical_plan_approval_payload(&baseline)
        .unwrap()
        .operation_digest;
    let mutations: Vec<BindingMutation> = vec![
        ("task_id", Box::new(|value| value.task_id = "task-2".into())),
        (
            "plan_artifact_id",
            Box::new(|value| value.plan_artifact_id = "plan-2".into()),
        ),
        (
            "plan_digest",
            Box::new(|value| value.plan_digest = digest('a')),
        ),
        ("plan_version", Box::new(|value| value.plan_version += 1)),
        (
            "base_commit",
            Box::new(|value| value.base_commit = "b".repeat(40)),
        ),
        (
            "allowed_root_0",
            Box::new(|value| value.allowed_paths[0].root_capability = "root-c".into()),
        ),
        (
            "allowed_pattern_0_0",
            Box::new(|value| value.allowed_paths[0].patterns[0] = "src/c.rs".into()),
        ),
        (
            "allowed_pattern_0_1",
            Box::new(|value| value.allowed_paths[0].patterns[1] = "src/d.rs".into()),
        ),
        (
            "allowed_root_1",
            Box::new(|value| value.allowed_paths[1].root_capability = "root-d".into()),
        ),
        (
            "allowed_pattern_1_0",
            Box::new(|value| value.allowed_paths[1].patterns[0] = "tests/c.rs".into()),
        ),
        (
            "allowed_pattern_1_1",
            Box::new(|value| value.allowed_paths[1].patterns[1] = "tests/d.rs".into()),
        ),
        (
            "planned_tool_0",
            Box::new(|value| value.planned_tool_digests[0] = digest('b')),
        ),
        (
            "planned_tool_1",
            Box::new(|value| value.planned_tool_digests[1] = digest('c')),
        ),
        (
            "verification_profile_digest",
            Box::new(|value| value.verification_profile_digest = digest('d')),
        ),
        (
            "risk_class",
            Box::new(|value| value.risk_class = "critical".into()),
        ),
        (
            "repository_fingerprint",
            Box::new(|value| value.repository_fingerprint = digest('e')),
        ),
        (
            "policy_snapshot_digest",
            Box::new(|value| value.policy_snapshot_digest = digest('f')),
        ),
        (
            "actor_id",
            Box::new(|value| value.actor_id = "actor-2".into()),
        ),
        (
            "agent_id",
            Box::new(|value| value.agent_id = "agent-2".into()),
        ),
        (
            "agent_manifest_digest",
            Box::new(|value| value.agent_manifest_digest = digest('8')),
        ),
        ("task_version", Box::new(|value| value.task_version += 1)),
        (
            "workspace_version",
            Box::new(|value| value.workspace_version += 1),
        ),
        ("fencing_epoch", Box::new(|value| value.fencing_epoch += 1)),
        (
            "requested_at",
            Box::new(|value| value.requested_at = "2026-07-23T12:00:01Z".into()),
        ),
        (
            "expires_at",
            Box::new(|value| value.expires_at = "2026-07-23T12:15:01Z".into()),
        ),
    ];

    for (name, mutate) in mutations {
        let mut changed = baseline.clone();
        mutate(&mut changed);
        assert_ne!(
            canonical_plan_approval_payload(&changed)
                .unwrap_or_else(|_| panic!("valid mutation rejected: {name}"))
                .operation_digest,
            baseline_digest,
            "{name}"
        );
    }
}

#[test]
fn binding_nonce_cryptographically_covers_repository_actor_and_fencing() {
    let baseline = binding();
    let baseline_payload = plan_approval_payload(&baseline).unwrap();
    let baseline_digest = canonical_plan_approval_payload(&baseline)
        .unwrap()
        .operation_digest;

    for mutate in [
        |value: &mut PlanApprovalBindingInput| value.repository_fingerprint = digest('a'),
        |value: &mut PlanApprovalBindingInput| value.actor_id = "actor-2".into(),
        |value: &mut PlanApprovalBindingInput| value.fencing_epoch += 1,
    ] {
        let mut changed = baseline.clone();
        mutate(&mut changed);
        assert_ne!(
            plan_approval_payload(&changed).unwrap().nonce,
            baseline_payload.nonce
        );
        assert_ne!(
            canonical_plan_approval_payload(&changed)
                .unwrap()
                .operation_digest,
            baseline_digest
        );
    }
}

#[test]
fn list_order_and_unicode_form_change_exact_authorization_bytes() {
    let baseline = binding();
    let canonical = canonical_plan_approval_payload(&baseline).unwrap();

    let mut reordered_scopes = baseline.clone();
    reordered_scopes.allowed_paths.swap(0, 1);
    let mut reordered_patterns = baseline.clone();
    reordered_patterns.allowed_paths[0].patterns.swap(0, 1);
    let mut reordered_tools = baseline.clone();
    reordered_tools.planned_tool_digests.swap(0, 1);
    for changed in [reordered_scopes, reordered_patterns, reordered_tools] {
        let changed = canonical_plan_approval_payload(&changed).unwrap();
        assert_ne!(changed.canonical_bytes, canonical.canonical_bytes);
        assert_ne!(changed.operation_digest, canonical.operation_digest);
    }

    let mut composed = baseline.clone();
    composed.allowed_paths[0].patterns[0] = "café.rs".into();
    let mut decomposed = baseline;
    decomposed.allowed_paths[0].patterns[0] = "café.rs".into();
    assert_ne!(
        canonical_plan_approval_payload(&composed)
            .unwrap()
            .operation_digest,
        canonical_plan_approval_payload(&decomposed)
            .unwrap()
            .operation_digest
    );
}

#[test]
fn resolver_reloads_shared_plan_and_recomputes_authoritative_binding() {
    let binding = binding();
    let store = plan_store(binding.clone());
    let resolver = ResolvePlanApproval::new(&store, &FixedClock);
    let digest = canonical_plan_approval_payload(&binding)
        .unwrap()
        .operation_digest;

    let resolution = resolver
        .execute(ResolvePlanApprovalInput {
            approval_id: ApprovalId::new("approval-plan-1").unwrap(),
            displayed_digest: digest.clone(),
            expected_task_version: binding.task_version,
            actor_id: ActorId::new(&binding.actor_id).unwrap(),
            action: PlanApprovalAction::Approve,
        })
        .unwrap();

    assert_eq!(resolution.operation_digest, digest);
    assert_eq!(resolution.append.expected_version, Sequence::new(9));
    assert_eq!(
        resolution.append.events[0].event_type.as_str(),
        "plan.approved"
    );
    assert!(
        matches!(resolution.append.projection_changes.as_slice(), [local_agent_terminal_application::ProjectionChange::TaskState { state, .. }] if state.phase() == Phase::Implementation)
    );
    assert_eq!(
        store.loads.lock().unwrap().as_slice(),
        ["approval", "current", "compare-and-resolve"]
    );
    assert_eq!(store.resolutions.lock().unwrap().len(), 1);
    assert!(matches!(
        store.stored.lock().unwrap().terminal,
        Some(PlanApprovalTerminal::Resolved {
            action: PlanApprovalAction::Approve,
            ..
        })
    ));

    assert!(resolver.execute(approval_input(&binding, digest)).is_err());
    assert_eq!(store.resolutions.lock().unwrap().len(), 1);
}

#[test]
fn resolution_emits_only_declared_workflow_transitions() {
    for (action, event, phase) in [
        (
            PlanApprovalAction::Approve,
            "plan.approved",
            Phase::Implementation,
        ),
        (
            PlanApprovalAction::Reject,
            "task.cancelled",
            Phase::Cancelled,
        ),
    ] {
        let binding = binding();
        let store = plan_store(binding.clone());
        let mut input = approval_input(
            &binding,
            canonical_plan_approval_payload(&binding)
                .unwrap()
                .operation_digest,
        );
        input.action = action;

        let resolution = ResolvePlanApproval::new(&store, &FixedClock)
            .execute(input)
            .unwrap();
        assert_eq!(resolution.append.events[0].event_type.as_str(), event);
        assert!(
            matches!(resolution.append.projection_changes.as_slice(), [local_agent_terminal_application::ProjectionChange::TaskState { state, .. }] if state.phase() == phase)
        );
    }

    for action in [
        PlanApprovalAction::Revise,
        PlanApprovalAction::Reopen,
        PlanApprovalAction::AddOrReplaceAgent,
    ] {
        let binding = binding();
        let store = plan_store(binding.clone());
        let mut input = approval_input(
            &binding,
            canonical_plan_approval_payload(&binding)
                .unwrap()
                .operation_digest,
        );
        input.action = action;

        assert!(ResolvePlanApproval::new(&store, &FixedClock)
            .execute(input)
            .is_err());
        assert!(store.resolutions.lock().unwrap().is_empty());
        assert!(!store.loads.lock().unwrap().contains(&"compare-and-resolve"));
    }
}

#[test]
fn compare_and_resolve_rejects_authority_races_without_resolution() {
    for race in [CasRace::ChangeCurrent, CasRace::InvalidateApproval] {
        let binding = binding();
        let store = plan_store_with_race(binding.clone(), race);
        let digest = canonical_plan_approval_payload(&binding)
            .unwrap()
            .operation_digest;

        assert!(ResolvePlanApproval::new(&store, &FixedClock)
            .execute(approval_input(&binding, digest))
            .is_err());
        assert!(store.resolutions.lock().unwrap().is_empty());
        assert_eq!(
            store
                .loads
                .lock()
                .unwrap()
                .iter()
                .filter(|load| **load == "compare-and-resolve")
                .count(),
            1
        );
    }
}

#[test]
fn direct_resolution_command_rejects_malformed_or_out_of_window_time_even_with_exact_append() {
    let binding = binding();
    let store = plan_store(binding.clone());
    ResolvePlanApproval::new(&store, &FixedClock)
        .execute(approval_input(
            &binding,
            canonical_plan_approval_payload(&binding)
                .unwrap()
                .operation_digest,
        ))
        .unwrap();
    let valid = store.resolve_commands.lock().unwrap()[0].clone();

    for forged_time in [
        "not-a-timestamp",
        "2026-07-23T12:15:00Z",
        "2026-07-23T12:15:01Z",
    ] {
        let mut forged = valid.clone();
        forged.resolution.resolved_at = forged_time.to_owned();
        forged.resolution.append.events[0].created_at = forged_time.to_owned();
        let local_agent_terminal_application::ProjectionChange::TaskState { updated_at, .. } =
            &mut forged.resolution.append.projection_changes[0];
        *updated_at = forged_time.to_owned();

        assert!(forged.validate().is_err(), "{forged_time}");
        let hostile_store = plan_store(binding.clone());
        assert!(hostile_store.compare_and_resolve(forged).is_err());
        assert!(hostile_store.resolutions.lock().unwrap().is_empty());
    }
}

#[test]
fn stored_plan_parser_rejects_other_shared_approval_variants() {
    let wrong_variant = ApprovalDigestPayload::PolicyException(PolicyExceptionApprovalPayloadV1 {
        schema: "approval-digest.v1".into(),
        approval_type: "policy_exception".into(),
        task_id: "task-1".into(),
        operation: PolicyExceptionApprovalOperationV1 {
            actor_binding_digest: digest('1'),
            purpose: "review".into(),
            resource_digest: digest('2'),
            destination: "provider".into(),
            effective_payload_digest: digest('3'),
            redaction_report_digest: digest('4'),
        },
        policy_snapshot_digest: digest('5'),
        workspace_version: 9,
        requested_at: "2026-07-23T12:00:00Z".into(),
        expires_at: "2026-07-23T12:15:00Z".into(),
        nonce: "0123456789abcdef0123456789abcdef".into(),
    });
    let canonical = canonical_approval_payload(&wrong_variant).unwrap();

    assert!(parse_canonical_plan_approval_payload(&canonical.canonical_bytes).is_err());
}

#[test]
fn stale_or_substituted_authority_cannot_resolve() {
    let binding = binding();
    let store = plan_store(binding.clone());
    store.current.lock().unwrap().binding.plan_digest = digest('a');
    let resolver = ResolvePlanApproval::new(&store, &FixedClock);

    assert!(resolver
        .execute(ResolvePlanApprovalInput {
            approval_id: ApprovalId::new("approval-plan-1").unwrap(),
            displayed_digest: canonical_plan_approval_payload(&binding)
                .unwrap()
                .operation_digest,
            expected_task_version: binding.task_version,
            actor_id: ActorId::new(&binding.actor_id).unwrap(),
            action: PlanApprovalAction::Approve,
        })
        .is_err());
    assert!(store.resolutions.lock().unwrap().is_empty());

    let store = plan_store(binding.clone());
    store.current.lock().unwrap().binding.agent_id = "agent-2".into();
    assert!(ResolvePlanApproval::new(&store, &FixedClock)
        .execute(approval_input(
            &binding,
            canonical_plan_approval_payload(&binding)
                .unwrap()
                .operation_digest,
        ))
        .is_err());
    assert!(store.resolutions.lock().unwrap().is_empty());
}

#[test]
fn resolver_rejects_digest_version_actor_phase_and_time_substitution() {
    let binding = binding();
    let canonical = canonical_plan_approval_payload(&binding).unwrap();
    let store = plan_store(binding.clone());
    let mut input = approval_input(&binding, canonical.operation_digest.clone());
    input.displayed_digest = _typed_digest(digest('a'));
    assert!(ResolvePlanApproval::new(&store, &FixedClock)
        .execute(input)
        .is_err());
    assert!(store.resolutions.lock().unwrap().is_empty());

    let store = plan_store(binding.clone());
    let mut input = approval_input(&binding, canonical.operation_digest.clone());
    input.expected_task_version += 1;
    assert!(ResolvePlanApproval::new(&store, &FixedClock)
        .execute(input)
        .is_err());
    assert!(store.resolutions.lock().unwrap().is_empty());

    let store = plan_store(binding.clone());
    let mut input = approval_input(&binding, canonical.operation_digest.clone());
    input.actor_id = ActorId::new("actor-2").unwrap();
    assert!(ResolvePlanApproval::new(&store, &FixedClock)
        .execute(input)
        .is_err());
    assert!(store.resolutions.lock().unwrap().is_empty());

    let store = plan_store(binding.clone());
    store.current.lock().unwrap().phase = Phase::Synthesis;
    assert!(ResolvePlanApproval::new(&store, &FixedClock)
        .execute(approval_input(&binding, canonical.operation_digest.clone()))
        .is_err());
    assert!(store.resolutions.lock().unwrap().is_empty());

    let store = plan_store(binding.clone());
    assert!(ResolvePlanApproval::new(&store, &ExpiredClock)
        .execute(approval_input(&binding, canonical.operation_digest))
        .is_err());
    assert!(store.resolutions.lock().unwrap().is_empty());
    let expired = store.stored.lock().unwrap().clone();
    assert_eq!(expired.state, PlanApprovalState::Expired);
    assert!(matches!(
        expired.terminal,
        Some(PlanApprovalTerminal::Expired { ref expired_at })
            if expired_at == "2026-07-23T12:15:00Z"
    ));
    expired.validate().unwrap();
}

#[test]
fn request_builder_owns_canonical_bytes_artifact_and_exact_authority_binding() {
    let binding = binding();
    let authority = PlanApprovalAuthorityBinding::issue(binding.clone()).unwrap();
    let store = plan_store(binding.clone());
    let current = store.current.lock().unwrap().clone();
    let request = PreparePlanApprovalRequest::execute(
        PreparePlanApprovalRequestInput {
            approval_id: ApprovalId::new("approval-plan-2").unwrap(),
            request_artifact_id: local_agent_terminal_domain::ArtifactId::new(
                "artifact-plan-approval-2",
            )
            .unwrap(),
        },
        &authority,
        &current,
    )
    .unwrap();

    request.validate().unwrap();
    assert_eq!(request.task_id().as_str(), "task-1");
    assert_eq!(request.binding().agent_id, "agent-1");
    assert_eq!(request.binding().agent_manifest_digest, digest('7'));
    assert_eq!(request.binding().workspace_version, 3);
    assert_eq!(
        request.request_artifact().content_digest,
        *request.operation_digest()
    );
    assert_eq!(
        request.request_artifact().size_bytes,
        request.canonical_bytes().len() as u64
    );
    assert_eq!(
        request.authority_binding().content_digest(),
        authority.content_digest()
    );

    let mut stale = current;
    stale.binding.workspace_version += 1;
    assert!(PreparePlanApprovalRequest::execute(
        PreparePlanApprovalRequestInput {
            approval_id: ApprovalId::new("approval-plan-3").unwrap(),
            request_artifact_id: local_agent_terminal_domain::ArtifactId::new(
                "artifact-plan-approval-3",
            )
            .unwrap(),
        },
        &authority,
        &stale,
    )
    .is_err());
}

#[test]
fn request_builder_rejects_each_substituted_authority_leaf_against_durable_current_state() {
    let baseline = binding();
    let current = plan_store(baseline.clone()).current.into_inner().unwrap();
    let mutations: Vec<BindingMutation> = vec![
        ("task", Box::new(|value| value.task_id = "task-2".into())),
        (
            "plan",
            Box::new(|value| value.plan_artifact_id = "plan-2".into()),
        ),
        ("base", Box::new(|value| value.base_commit = "b".repeat(40))),
        ("scope", Box::new(|value| value.allowed_paths.clear())),
        (
            "tools",
            Box::new(|value| value.planned_tool_digests.clear()),
        ),
        (
            "verification",
            Box::new(|value| value.verification_profile_digest = digest('a')),
        ),
        (
            "policy",
            Box::new(|value| value.policy_snapshot_digest = digest('b')),
        ),
        (
            "repository",
            Box::new(|value| value.repository_fingerprint = digest('c')),
        ),
        ("agent", Box::new(|value| value.agent_id = "agent-2".into())),
        (
            "manifest",
            Box::new(|value| value.agent_manifest_digest = digest('d')),
        ),
        ("actor", Box::new(|value| value.actor_id = "actor-2".into())),
        ("task-version", Box::new(|value| value.task_version += 1)),
        ("workspace", Box::new(|value| value.workspace_version += 1)),
        ("fencing", Box::new(|value| value.fencing_epoch += 1)),
        (
            "requested",
            Box::new(|value| value.requested_at = "2026-07-23T12:00:01Z".into()),
        ),
        (
            "expires",
            Box::new(|value| value.expires_at = "2026-07-23T12:15:01Z".into()),
        ),
    ];

    for (name, mutate) in mutations {
        let mut changed = baseline.clone();
        mutate(&mut changed);
        let Ok(authority) = PlanApprovalAuthorityBinding::issue(changed) else {
            continue;
        };
        let result = PreparePlanApprovalRequest::execute(
            PreparePlanApprovalRequestInput {
                approval_id: ApprovalId::new("approval-hostile").unwrap(),
                request_artifact_id: local_agent_terminal_domain::ArtifactId::new(
                    "artifact-plan-hostile",
                )
                .unwrap(),
            },
            &authority,
            &current,
        );
        assert!(result.is_err(), "{name}");
    }
}

#[test]
fn authoritative_binding_rehydrates_after_restart_and_rejects_every_leaf_substitution() {
    let authority = PlanApprovalAuthorityBinding::issue(binding()).unwrap();
    let reopened = PlanApprovalAuthorityBinding::rehydrate(
        authority.canonical_bytes().to_vec(),
        authority.content_digest().clone(),
    )
    .unwrap();
    assert_eq!(reopened.binding(), authority.binding());

    let mutations: Vec<(&str, serde_json::Value)> = vec![
        ("taskId", serde_json::json!("task-2")),
        ("planArtifactId", serde_json::json!("plan-2")),
        ("planDigest", serde_json::json!(digest('a'))),
        ("planVersion", serde_json::json!(3)),
        ("baseCommit", serde_json::json!("b".repeat(40))),
        ("allowedPaths", serde_json::json!([])),
        ("plannedToolDigests", serde_json::json!([digest('b')])),
        ("verificationProfileDigest", serde_json::json!(digest('c'))),
        ("riskClass", serde_json::json!("critical")),
        ("repositoryFingerprint", serde_json::json!(digest('d'))),
        ("policySnapshotDigest", serde_json::json!(digest('e'))),
        ("agentId", serde_json::json!("agent-2")),
        ("agentManifestDigest", serde_json::json!(digest('f'))),
        ("actorId", serde_json::json!("actor-2")),
        ("taskVersion", serde_json::json!(10)),
        ("workspaceVersion", serde_json::json!(4)),
        ("fencingEpoch", serde_json::json!(8)),
        ("requestedAt", serde_json::json!("2026-07-23T12:00:01Z")),
        ("expiresAt", serde_json::json!("2026-07-23T12:15:01Z")),
    ];
    for (field, replacement) in mutations {
        let mut value: serde_json::Value =
            serde_json::from_slice(authority.canonical_bytes()).unwrap();
        value["binding"][field] = replacement;
        let tampered = serde_json::to_vec(&value).unwrap();
        assert!(
            PlanApprovalAuthorityBinding::rehydrate(tampered, authority.content_digest().clone(),)
                .is_err(),
            "{field}"
        );
    }
}

#[test]
fn stored_plan_approval_rehydrates_from_both_durable_envelopes_and_rejects_substitution() {
    let authority = PlanApprovalAuthorityBinding::issue(binding()).unwrap();
    let canonical = canonical_plan_approval_payload(authority.binding()).unwrap();
    let artifact = request_artifact(
        canonical.operation_digest.clone(),
        canonical.canonical_bytes.len() as u64,
    );
    let record = || StoredPlanApprovalRehydration {
        approval_id: ApprovalId::new("approval-plan-1").unwrap(),
        state: PlanApprovalState::Requested,
        canonical_bytes: canonical.canonical_bytes.clone(),
        operation_digest: canonical.operation_digest.clone(),
        request_artifact: artifact.clone(),
        authority_binding_bytes: authority.canonical_bytes().to_vec(),
        authority_binding_digest: authority.content_digest().clone(),
        terminal: None,
    };

    let reopened = StoredPlanApproval::rehydrate(record()).unwrap();
    assert_eq!(reopened.binding(), authority.binding());
    reopened.validate().unwrap();

    let mut wrong_binding = record();
    wrong_binding.authority_binding_digest = _typed_digest(digest('a'));
    assert!(StoredPlanApproval::rehydrate(wrong_binding).is_err());

    let mut wrong_approval = record();
    wrong_approval.operation_digest = _typed_digest(digest('b'));
    assert!(StoredPlanApproval::rehydrate(wrong_approval).is_err());
}

#[test]
fn invalidation_is_core_built_compare_and_swap_and_durable_after_reload() {
    let binding = binding();
    let store = plan_store(binding);
    let invalidation = InvalidatePlanApproval::new(&store, &FixedClock)
        .execute(InvalidatePlanApprovalInput {
            approval_id: ApprovalId::new("approval-plan-1").unwrap(),
            actor_id: ActorId::new("actor-1").unwrap(),
            reason_code: "workspace-changed".to_owned(),
        })
        .unwrap();

    assert_eq!(
        invalidation.append().events[0].event_type.as_str(),
        "approval.invalidated"
    );
    assert!(invalidation.append().projection_changes.is_empty());
    let reloaded = store
        .reload(&ApprovalId::new("approval-plan-1").unwrap())
        .unwrap()
        .unwrap();
    assert_eq!(reloaded.state, PlanApprovalState::Invalidated);
    assert!(matches!(
        reloaded.terminal,
        Some(PlanApprovalTerminal::Invalidated {
            ref reason_code,
            ref actor_id,
            ..
        }) if reason_code == "workspace-changed" && actor_id.as_str() == "actor-1"
    ));
    reloaded.validate().unwrap();
    assert!(InvalidatePlanApproval::new(&store, &FixedClock)
        .execute(InvalidatePlanApprovalInput {
            approval_id: ApprovalId::new("approval-plan-1").unwrap(),
            actor_id: ActorId::new("actor-1").unwrap(),
            reason_code: "again".to_owned(),
        })
        .is_err());
}

#[test]
fn stale_workspace_version_is_rejected_before_resolution_cas() {
    let binding = binding();
    let store = plan_store(binding.clone());
    store.current.lock().unwrap().task_state =
        awaiting_approval_state_with_workspace(binding.task_version, binding.workspace_version + 1);

    assert!(ResolvePlanApproval::new(&store, &FixedClock)
        .execute(approval_input(
            &binding,
            canonical_plan_approval_payload(&binding)
                .unwrap()
                .operation_digest,
        ))
        .is_err());
    assert!(!store.loads.lock().unwrap().contains(&"compare-and-resolve"));
}

#[test]
fn plan_approval_store_and_request_handler_are_object_safe_and_narrow() {
    fn accepts(_: &dyn PlanApprovalStore) {}
    let store = plan_store(binding());
    accepts(&store);

    let request = serde_json::json!({
        "approvalId": "approval-plan-1",
        "displayedDigest": digest('4'),
        "expectedTaskVersion": 9,
        "actorId": "actor-1",
        "action": "approve"
    });
    assert!(serde_json::from_value::<ResolvePlanApprovalRequestDto>(request.clone()).is_ok());
    for forbidden in [
        "plan",
        "providerPayload",
        "physicalPath",
        "policy",
        "event",
        "tool",
    ] {
        let mut hostile = request.clone();
        hostile
            .as_object_mut()
            .unwrap()
            .insert(forbidden.to_owned(), serde_json::json!("untrusted"));
        assert!(serde_json::from_value::<ResolvePlanApprovalRequestDto>(hostile).is_err());
    }

    let serialized = format!(
        "{}{}",
        serde_json::to_string(&ContextPackageDto {
            package_id: "package-1".into(),
            task_id: "task-1".into(),
            agent_id: "agent-1".into(),
            role: "critic".into(),
            artifact_id: "artifact-package-1".into(),
            content_digest: digest('5'),
            policy_snapshot_digest: digest('6'),
            policy_decision_ids: vec!["policy-decision:1".into()],
        })
        .unwrap(),
        serde_json::to_string(&DeliberationWorkspaceDto {
            task_id: "task-1".into(),
            phase: "AwaitingPlanApproval".into(),
            task_version: 9,
            private_proposal_count: 2,
            published_proposal_ids: vec!["proposal-1".into()],
            decision_artifact_id: Some("decision-1".into()),
            unresolved_objection_ids: vec!["objection-1".into()],
        })
        .unwrap()
    );
    for forbidden in [
        "sourceBytes",
        "physicalPath",
        "providerPayload",
        "secretMatch",
    ] {
        assert!(!serialized.contains(forbidden));
    }
}

struct Store {
    stored: Mutex<StoredPlanApproval>,
    current: Mutex<PlanApprovalCurrentState>,
    resolutions: Mutex<Vec<PlanApprovalResolution>>,
    resolve_commands: Mutex<Vec<CompareAndResolvePlanApproval>>,
    loads: Mutex<Vec<&'static str>>,
    cas_race: Option<CasRace>,
}

#[derive(Debug, Clone, Copy)]
enum CasRace {
    ChangeCurrent,
    InvalidateApproval,
}

impl PlanApprovalStore for Store {
    fn reload(&self, _: &ApprovalId) -> Result<Option<StoredPlanApproval>, PortError> {
        self.loads.lock().unwrap().push("approval");
        Ok(Some(self.stored.lock().unwrap().clone()))
    }

    fn current_state(&self, _: &TaskId) -> Result<PlanApprovalCurrentState, PortError> {
        self.loads.lock().unwrap().push("current");
        Ok(self.current.lock().unwrap().clone())
    }

    fn compare_and_resolve(&self, command: CompareAndResolvePlanApproval) -> Result<(), PortError> {
        command.validate()?;
        self.resolve_commands.lock().unwrap().push(command.clone());
        self.loads.lock().unwrap().push("compare-and-resolve");
        let mut stored = self.stored.lock().unwrap();
        let mut current = self.current.lock().unwrap();
        match self.cas_race {
            Some(CasRace::ChangeCurrent) => current.binding.plan_digest = digest('a'),
            Some(CasRace::InvalidateApproval) => stored.state = PlanApprovalState::Invalidated,
            None => {}
        }
        if *stored != command.expected_approval
            || *current != command.expected_current
            || stored.state != PlanApprovalState::Requested
        {
            return Err(PortError::failure(
                SafeErrorClassification::Conflict,
                Retryability::NonRetryable,
            ));
        }
        stored.state = PlanApprovalState::Resolved;
        stored.terminal = Some(PlanApprovalTerminal::Resolved {
            action: command.resolution.action,
            actor_id: command.resolution.actor_id.clone(),
            resolved_at: command.resolution.resolved_at.clone(),
        });
        self.resolutions.lock().unwrap().push(command.resolution);
        Ok(())
    }

    fn compare_and_invalidate(
        &self,
        command: CompareAndInvalidatePlanApproval,
    ) -> Result<(), PortError> {
        command.validate()?;
        let mut stored = self.stored.lock().unwrap();
        let current = self.current.lock().unwrap();
        if *stored != command.expected_approval
            || *current != command.expected_current
            || stored.state != PlanApprovalState::Requested
        {
            return Err(conflict_error());
        }
        stored.state = PlanApprovalState::Invalidated;
        stored.terminal = Some(PlanApprovalTerminal::Invalidated {
            reason_code: command.invalidation.reason_code().to_owned(),
            actor_id: command.invalidation.actor_id().clone(),
            invalidated_at: command.invalidation.invalidated_at().to_owned(),
        });
        Ok(())
    }

    fn compare_and_expire(&self, command: CompareAndExpirePlanApproval) -> Result<(), PortError> {
        command.validate()?;
        let mut stored = self.stored.lock().unwrap();
        let current = self.current.lock().unwrap();
        if *stored != command.expected_approval
            || *current != command.expected_current
            || stored.state != PlanApprovalState::Requested
        {
            return Err(conflict_error());
        }
        stored.state = PlanApprovalState::Expired;
        stored.terminal = Some(PlanApprovalTerminal::Expired {
            expired_at: command.expiry.expired_at().to_owned(),
        });
        Ok(())
    }
}

struct FixedClock;

impl Clock for FixedClock {
    fn now_utc(&self) -> Result<String, PortError> {
        Ok("2026-07-23T12:05:00Z".into())
    }
}

struct ExpiredClock;

impl Clock for ExpiredClock {
    fn now_utc(&self) -> Result<String, PortError> {
        Ok("2026-07-23T12:15:00Z".into())
    }
}

fn plan_store(binding: PlanApprovalBindingInput) -> Store {
    plan_store_with_optional_race(binding, None)
}

fn plan_store_with_race(binding: PlanApprovalBindingInput, race: CasRace) -> Store {
    plan_store_with_optional_race(binding, Some(race))
}

fn plan_store_with_optional_race(
    binding: PlanApprovalBindingInput,
    cas_race: Option<CasRace>,
) -> Store {
    let authority = PlanApprovalAuthorityBinding::issue(binding.clone()).unwrap();
    let canonical = canonical_plan_approval_payload(&binding).unwrap();
    let request_artifact = request_artifact(
        canonical.operation_digest.clone(),
        canonical.canonical_bytes.len() as u64,
    );
    Store {
        stored: Mutex::new(
            StoredPlanApproval::rehydrate(StoredPlanApprovalRehydration {
                approval_id: ApprovalId::new("approval-plan-1").unwrap(),
                state: PlanApprovalState::Requested,
                canonical_bytes: canonical.canonical_bytes,
                operation_digest: canonical.operation_digest,
                request_artifact,
                authority_binding_bytes: authority.canonical_bytes().to_vec(),
                authority_binding_digest: authority.content_digest().clone(),
                terminal: None,
            })
            .unwrap(),
        ),
        current: Mutex::new(PlanApprovalCurrentState {
            phase: Phase::AwaitingPlanApproval,
            task_state: awaiting_approval_state(binding.task_version),
            binding,
        }),
        resolutions: Mutex::new(Vec::new()),
        resolve_commands: Mutex::new(Vec::new()),
        loads: Mutex::new(Vec::new()),
        cas_race,
    }
}

fn binding() -> PlanApprovalBindingInput {
    PlanApprovalBindingInput {
        task_id: "task-1".into(),
        plan_artifact_id: "plan-1".into(),
        plan_digest: digest('1'),
        plan_version: 2,
        base_commit: "a".repeat(40),
        allowed_paths: vec![
            PlanApprovalPathScopeV1 {
                root_capability: "root-a".into(),
                patterns: vec!["src/a.rs".into(), "src/b.rs".into()],
            },
            PlanApprovalPathScopeV1 {
                root_capability: "root-b".into(),
                patterns: vec!["tests/a.rs".into(), "tests/b.rs".into()],
            },
        ],
        planned_tool_digests: vec![digest('2'), digest('3')],
        verification_profile_digest: digest('4'),
        risk_class: "high".into(),
        repository_fingerprint: digest('5'),
        policy_snapshot_digest: digest('6'),
        agent_id: "agent-1".into(),
        agent_manifest_digest: digest('7'),
        actor_id: "actor-1".into(),
        task_version: 9,
        workspace_version: 3,
        fencing_epoch: 4,
        requested_at: "2026-07-23T12:00:00Z".into(),
        expires_at: "2026-07-23T12:15:00Z".into(),
    }
}

fn request_artifact(content_digest: Sha256Digest, size_bytes: u64) -> PlanApprovalRequestArtifact {
    PlanApprovalRequestArtifact {
        artifact_id: local_agent_terminal_domain::ArtifactId::new("artifact-plan-approval-1")
            .unwrap(),
        content_digest,
        size_bytes,
    }
}

fn awaiting_approval_state(version: u64) -> WorkflowState {
    awaiting_approval_state_with_workspace(version, 3)
}

fn awaiting_approval_state_with_workspace(version: u64, workspace_version: u64) -> WorkflowState {
    WorkflowState::new(
        Phase::AwaitingPlanApproval,
        Condition::Active,
        OperationState::None,
        Sequence::new(version),
        WorkspaceVersion::new(workspace_version),
        FencingToken::new(3).unwrap(),
    )
    .unwrap()
}

fn approval_input(
    binding: &PlanApprovalBindingInput,
    displayed_digest: Sha256Digest,
) -> ResolvePlanApprovalInput {
    ResolvePlanApprovalInput {
        approval_id: ApprovalId::new("approval-plan-1").unwrap(),
        displayed_digest,
        expected_task_version: binding.task_version,
        actor_id: ActorId::new(&binding.actor_id).unwrap(),
        action: PlanApprovalAction::Approve,
    }
}

fn digest(character: char) -> String {
    format!("sha256:{}", character.to_string().repeat(64))
}

fn _typed_digest(value: String) -> Sha256Digest {
    Sha256Digest::new(value).unwrap()
}

fn conflict_error() -> PortError {
    PortError::failure(
        SafeErrorClassification::Conflict,
        Retryability::NonRetryable,
    )
}
