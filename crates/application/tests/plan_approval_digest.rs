use std::sync::Mutex;

use local_agent_terminal_application::{
    canonical_approval_payload, canonical_plan_approval_payload,
    parse_canonical_plan_approval_payload, plan_approval_payload, ApprovalDigestPayload,
    ApprovalId, Clock, CompareAndResolvePlanApproval, ContextPackageDto, DeliberationWorkspaceDto,
    NewPlanApproval, PlanApprovalAction, PlanApprovalBindingInput, PlanApprovalCurrentState,
    PlanApprovalInvalidation, PlanApprovalPathScopeV1, PlanApprovalResolution, PlanApprovalState,
    PlanApprovalStore, PolicyExceptionApprovalOperationV1, PolicyExceptionApprovalPayloadV1,
    PortError, ResolvePlanApproval, ResolvePlanApprovalInput, ResolvePlanApprovalRequestDto,
    Retryability, SafeErrorClassification, StoredPlanApproval,
};
use local_agent_terminal_domain::{ActorId, Phase, Sha256Digest, TaskId};

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
        ("task_version", Box::new(|value| value.task_version += 1)),
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
    assert_eq!(
        store.loads.lock().unwrap().as_slice(),
        ["approval", "current", "compare-and-resolve"]
    );
    assert_eq!(store.resolutions.lock().unwrap().len(), 1);

    assert!(resolver.execute(approval_input(&binding, digest)).is_err());
    assert_eq!(store.resolutions.lock().unwrap().len(), 1);
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
    loads: Mutex<Vec<&'static str>>,
    cas_race: Option<CasRace>,
}

#[derive(Debug, Clone, Copy)]
enum CasRace {
    ChangeCurrent,
    InvalidateApproval,
}

impl PlanApprovalStore for Store {
    fn request(&self, _: NewPlanApproval) -> Result<StoredPlanApproval, PortError> {
        Ok(self.stored.lock().unwrap().clone())
    }

    fn reload(&self, _: &ApprovalId) -> Result<Option<StoredPlanApproval>, PortError> {
        self.loads.lock().unwrap().push("approval");
        Ok(Some(self.stored.lock().unwrap().clone()))
    }

    fn current_state(&self, _: &TaskId) -> Result<PlanApprovalCurrentState, PortError> {
        self.loads.lock().unwrap().push("current");
        Ok(self.current.lock().unwrap().clone())
    }

    fn compare_and_resolve(&self, command: CompareAndResolvePlanApproval) -> Result<(), PortError> {
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
        self.resolutions.lock().unwrap().push(command.resolution);
        Ok(())
    }

    fn invalidate(&self, _: PlanApprovalInvalidation) -> Result<u64, PortError> {
        Ok(0)
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
    let canonical = canonical_plan_approval_payload(&binding).unwrap();
    Store {
        stored: Mutex::new(StoredPlanApproval {
            approval_id: ApprovalId::new("approval-plan-1").unwrap(),
            state: PlanApprovalState::Requested,
            canonical_bytes: canonical.canonical_bytes,
            operation_digest: canonical.operation_digest,
        }),
        current: Mutex::new(PlanApprovalCurrentState {
            phase: Phase::AwaitingPlanApproval,
            binding,
        }),
        resolutions: Mutex::new(Vec::new()),
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
        actor_id: "actor-1".into(),
        task_version: 9,
        fencing_epoch: 4,
        requested_at: "2026-07-23T12:00:00Z".into(),
        expires_at: "2026-07-23T12:15:00Z".into(),
    }
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
