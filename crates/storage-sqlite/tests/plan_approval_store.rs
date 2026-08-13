use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Barrier, Mutex};

use local_agent_terminal_application::{
    ApprovalId, Clock, InvalidatePlanApproval, InvalidatePlanApprovalInput, PlanApprovalAction,
    PlanApprovalAuthorityBinding, PlanApprovalBindingInput, PlanApprovalCurrentAuthority,
    PlanApprovalCurrentAuthoritySource, PlanApprovalCurrentState, PlanApprovalPathScopeV1,
    PlanApprovalState, PlanApprovalStore, PlanApprovalTerminal, PortError,
    PreparePlanApprovalRequest, PreparePlanApprovalRequestInput, ResolvePlanApproval,
    ResolvePlanApprovalInput, SafeErrorClassification,
};
use local_agent_terminal_domain::{
    ActorId, ArtifactId, Condition, OperationState, Phase, Sha256Digest, TaskId, TaskOutcomeMode,
    WorkflowProfile, WorkflowState, WorkflowStateSnapshot,
};
use local_agent_terminal_storage_files::{
    ContentAddressedArtifactReader, ContentAddressedArtifactStore,
};
use local_agent_terminal_storage_sqlite::SqliteStore;
use rusqlite::{params, Connection};
use sha2::{Digest, Sha256};

static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

struct TestDatabase {
    directory: PathBuf,
    path: PathBuf,
    artifact_root: PathBuf,
    authority: Arc<MutableAuthority>,
    approval: local_agent_terminal_application::NewPlanApproval,
}

struct MutableAuthority {
    current: Mutex<PlanApprovalCurrentAuthority>,
    calls: AtomicU64,
    repository_mutation_on_call: Mutex<Option<(u64, Sha256Digest)>>,
}

impl MutableAuthority {
    fn new(current: PlanApprovalCurrentAuthority) -> Self {
        Self {
            current: Mutex::new(current),
            calls: AtomicU64::new(0),
            repository_mutation_on_call: Mutex::new(None),
        }
    }

    fn set_repository_fingerprint(&self, repository_fingerprint: Sha256Digest) {
        self.current.lock().unwrap().repository_fingerprint = repository_fingerprint;
    }

    fn set_policy_snapshot_digest(&self, policy_snapshot_digest: Sha256Digest) {
        self.current.lock().unwrap().policy_snapshot_digest = policy_snapshot_digest;
    }

    fn mutate_repository_on_call(&self, call: u64, repository_fingerprint: Sha256Digest) {
        *self.repository_mutation_on_call.lock().unwrap() = Some((call, repository_fingerprint));
    }
}

impl PlanApprovalCurrentAuthoritySource for MutableAuthority {
    fn current_authority(
        &self,
        _task_id: &TaskId,
    ) -> Result<PlanApprovalCurrentAuthority, PortError> {
        let call = self.calls.fetch_add(1, Ordering::SeqCst) + 1;
        let mutation = self.repository_mutation_on_call.lock().unwrap().clone();
        if let Some((mutation_call, repository_fingerprint)) = mutation {
            if call == mutation_call {
                self.current.lock().unwrap().repository_fingerprint = repository_fingerprint;
            }
        }
        Ok(self.current.lock().unwrap().clone())
    }
}

impl TestDatabase {
    fn new() -> Self {
        let directory = std::env::temp_dir().join(format!(
            "local-agent-terminal-plan-approval-store-test-{}-{}",
            std::process::id(),
            NEXT_TEMP.fetch_add(1, Ordering::Relaxed),
        ));
        fs::create_dir_all(&directory).unwrap();
        let artifact_root = directory.join("artifacts");
        fs::create_dir(&artifact_root).unwrap();
        let path = directory.join("state.sqlite3");
        SqliteStore::open(&path).unwrap();
        seed_authority(&path, &artifact_root);
        let binding = binding();
        let live_authority = Arc::new(MutableAuthority::new(PlanApprovalCurrentAuthority {
            repository_fingerprint: Sha256Digest::new(&binding.repository_fingerprint).unwrap(),
            policy_snapshot_digest: Sha256Digest::new(&binding.policy_snapshot_digest).unwrap(),
        }));
        let authority = PlanApprovalAuthorityBinding::issue(binding.clone()).unwrap();
        let approval = PreparePlanApprovalRequest::execute(
            PreparePlanApprovalRequestInput {
                approval_id: ApprovalId::new("approval-plan-1").unwrap(),
                request_artifact_id: ArtifactId::new("artifact-plan-approval-1").unwrap(),
            },
            &authority,
            &PlanApprovalCurrentState {
                phase: Phase::AwaitingPlanApproval,
                task_state: awaiting_state(),
                binding,
            },
        )
        .unwrap();
        let database = Self {
            directory,
            path,
            artifact_root,
            authority: live_authority,
            approval,
        };
        database.persist_request();
        database
    }

    fn store(&self) -> SqliteStore {
        SqliteStore::open(&self.path)
            .unwrap()
            .with_artifact_reader(Arc::new(ContentAddressedArtifactReader))
            .with_plan_approval_authority_source(self.authority.clone())
    }

    fn set_repository_fingerprint(&self, repository_fingerprint: Sha256Digest) {
        self.authority
            .set_repository_fingerprint(repository_fingerprint);
    }

    fn set_policy_snapshot_digest(&self, policy_snapshot_digest: Sha256Digest) {
        self.authority
            .set_policy_snapshot_digest(policy_snapshot_digest);
    }

    fn mutate_repository_on_authority_call(&self, call: u64, repository_fingerprint: Sha256Digest) {
        self.authority
            .mutate_repository_on_call(call, repository_fingerprint);
    }

    fn connection(&self) -> Connection {
        let connection = Connection::open(&self.path).unwrap();
        connection
            .execute_batch("PRAGMA foreign_keys = ON;")
            .unwrap();
        connection
    }

    fn persist_request(&self) {
        publish_artifact(
            &self.path,
            &self.artifact_root,
            self.approval.request_artifact().artifact_id.clone(),
            "plan-approval",
            self.approval.canonical_bytes(),
        );
        let connection = self.connection();
        connection
            .execute(
                "INSERT INTO operation_intents (
                    id, task_id, run_id, operation_kind, idempotency_class, idempotency_key,
                    canonical_request_artifact_id, operation_digest, actor_binding_digest,
                    status, current_attempt_no, created_at, updated_at
                 ) VALUES ('plan-intent-1', 'task-1', NULL, 'plan.approve',
                    'non_repeatable', 'plan-approval:task-1', ?1, ?2, ?3, 'pending', 0, ?4, ?4)",
                params![
                    self.approval.request_artifact().artifact_id.as_str(),
                    self.approval.operation_digest().as_str(),
                    digest(b"actor-binding").as_str(),
                    self.approval.binding().requested_at,
                ],
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO approvals (
                    id, task_id, operation_intent_id, approval_type, schema_version,
                    operation_digest, actor_binding_digest, nonce, status, requested_at,
                    resolved_at, expires_at, request_artifact_id, invalidation_reason
                 ) VALUES (?1, 'task-1', 'plan-intent-1', 'plan', 'approval-digest.v1', ?2,
                    ?3, 'plan-approval-nonce-1', 'pending', ?4, NULL, ?5, ?6, NULL)",
                params![
                    self.approval.approval_id().as_str(),
                    self.approval.operation_digest().as_str(),
                    digest(b"actor-binding").as_str(),
                    self.approval.binding().requested_at,
                    self.approval.binding().expires_at,
                    self.approval.request_artifact().artifact_id.as_str(),
                ],
            )
            .unwrap();
        let authority: serde_json::Value =
            serde_json::from_slice(self.approval.authority_binding().canonical_bytes()).unwrap();
        let payload = serde_json::json!({
            "taskId": "task-1",
            "recordType": "objection.round.closed",
            "artifactId": "objection-close-1",
            "artifactDigest": digest(b"objection close").as_str(),
            "artifactSizeBytes": 15,
            "approvalId": self.approval.approval_id().as_str(),
            "approvalArtifactId": self.approval.request_artifact().artifact_id.as_str(),
            "approvalDigest": self.approval.operation_digest().as_str(),
            "approvalAuthorityBinding": authority,
            "approvalAuthorityBindingDigest": self
                .approval
                .authority_binding()
                .content_digest()
                .as_str(),
        });
        for sequence in 1..8 {
            connection
                .execute(
                    "INSERT INTO events (
                        event_id, stream_id, sequence, event_type, schema_version, actor_type,
                        actor_id, observation_class, payload_json, metadata_json, causation_id,
                        correlation_id, created_at
                     ) VALUES (?1, 'task-1', ?2, 'test.seed', 1, 'core', 'core',
                        'core_observed', '{}', '{}', NULL, 'seed',
                        '2026-08-09T00:00:00Z')",
                    params![format!("event-seed-{sequence}"), sequence],
                )
                .unwrap();
        }
        connection
            .execute(
                "INSERT INTO events (
                    event_id, stream_id, sequence, event_type, schema_version, actor_type,
                    actor_id, observation_class, payload_json, metadata_json, causation_id,
                    correlation_id, created_at
                 ) VALUES ('event-objection-close', 'task-1', 8, 'objection.round.closed', 1,
                    'core', 'core', 'core_observed', ?1, '{}', NULL, 'approval-plan-1',
                    '2026-08-09T00:00:00Z')",
                [payload.to_string()],
            )
            .unwrap();
    }
}

impl Drop for TestDatabase {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.directory);
    }
}

#[test]
fn sqlite_store_exposes_the_dedicated_plan_approval_port() {
    fn accepts(_: &dyn PlanApprovalStore) {}

    let database = TestDatabase::new();
    accepts(&database.store());
}

#[test]
fn pending_plan_request_reloads_and_resolution_fails_closed_without_receipt_authority() {
    let database = TestDatabase::new();
    let store = database.store();
    let pending = store
        .reload(database.approval.approval_id())
        .unwrap()
        .unwrap();
    assert_eq!(pending.state, PlanApprovalState::Requested);
    assert_eq!(pending.canonical_bytes, database.approval.canonical_bytes());
    assert_eq!(
        store
            .current_state(&TaskId::new("task-1").unwrap())
            .unwrap()
            .binding,
        binding()
    );

    let error = ResolvePlanApproval::new(&store, &WithinWindow)
        .execute(resolve_input(&database, PlanApprovalAction::Approve))
        .unwrap_err();
    assert_eq!(
        error.safe_classification(),
        SafeErrorClassification::IntegrityFailure
    );

    let reopened = database.store();
    let pending = reopened
        .reload(database.approval.approval_id())
        .unwrap()
        .unwrap();
    assert_eq!(pending.state, PlanApprovalState::Requested);
    assert!(pending.terminal.is_none());
    assert_eq!(
        database
            .connection()
            .query_row("SELECT phase FROM tasks WHERE id = 'task-1'", [], |row| {
                row.get::<_, String>(0)
            })
            .unwrap(),
        "AwaitingPlanApproval"
    );
    assert_pending_without_terminal_event(&database);
}

#[test]
fn concurrent_plan_resolution_attempts_both_fail_closed_without_receipt_authority() {
    let database = TestDatabase::new();
    let store = database.store();
    let barrier = Arc::new(Barrier::new(2));
    let approve = resolve_input(&database, PlanApprovalAction::Approve);
    let reject = resolve_input(&database, PlanApprovalAction::Reject);

    let outcomes = std::thread::scope(|scope| {
        let first_store = store.clone();
        let first_barrier = Arc::clone(&barrier);
        let first = scope.spawn(move || {
            first_barrier.wait();
            ResolvePlanApproval::new(&first_store, &WithinWindow).execute(approve)
        });
        let second_store = store.clone();
        let second_barrier = Arc::clone(&barrier);
        let second = scope.spawn(move || {
            second_barrier.wait();
            ResolvePlanApproval::new(&second_store, &WithinWindow).execute(reject)
        });
        [first.join().unwrap(), second.join().unwrap()]
    });

    assert!(outcomes.iter().all(|outcome| matches!(
        outcome,
        Err(error)
            if error.safe_classification() == SafeErrorClassification::IntegrityFailure
    )));
    let connection = database.connection();
    let (status, current_sequence, terminal_events): (String, i64, i64) = connection
        .query_row(
            "SELECT
                (SELECT status FROM approvals WHERE id = 'approval-plan-1'),
                (SELECT current_sequence FROM tasks WHERE id = 'task-1'),
                (SELECT COUNT(*) FROM events
                 WHERE event_type IN ('plan.approved', 'task.cancelled'))",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap();
    assert_eq!(status, "pending");
    assert_eq!(current_sequence, 8);
    assert_eq!(terminal_events, 0);
}

#[test]
fn change_actions_fail_closed_without_receipt_authority() {
    let database = TestDatabase::new();
    let store = database.store();

    let error = ResolvePlanApproval::new(&store, &WithinWindow)
        .execute(resolve_input(&database, PlanApprovalAction::Revise))
        .unwrap_err();
    assert_eq!(
        error.safe_classification(),
        SafeErrorClassification::IntegrityFailure
    );

    let pending = database
        .store()
        .reload(database.approval.approval_id())
        .unwrap()
        .unwrap();
    assert_eq!(pending.state, PlanApprovalState::Requested);
    assert!(pending.terminal.is_none());
    let connection = database.connection();
    assert_eq!(
        connection
            .query_row("SELECT phase FROM tasks WHERE id = 'task-1'", [], |row| {
                row.get::<_, String>(0)
            })
            .unwrap(),
        "AwaitingPlanApproval"
    );
    assert_eq!(
        connection
            .query_row(
                "SELECT COUNT(*) FROM events WHERE event_type = ?1",
                ["plan.revision.requested"],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
        0
    );

    for action in [
        PlanApprovalAction::Reopen,
        PlanApprovalAction::AddOrReplaceAgent,
    ] {
        let database = TestDatabase::new();
        let store = database.store();
        let mut input = resolve_input(&database, action);
        input.feedback = Some("This action has no normative transition.".to_owned());
        assert!(ResolvePlanApproval::new(&store, &WithinWindow)
            .execute(input)
            .is_err());
        assert_pending_without_terminal_event(&database);
    }
}

#[test]
fn invalidation_is_atomic_terminal_and_durable() {
    let database = TestDatabase::new();
    let store = database.store();

    InvalidatePlanApproval::new(&store, &WithinWindow)
        .execute(InvalidatePlanApprovalInput {
            approval_id: database.approval.approval_id().clone(),
            actor_id: ActorId::new("actor-1").unwrap(),
            reason_code: "repository-changed".to_owned(),
        })
        .unwrap();

    let invalidated = database
        .store()
        .reload(database.approval.approval_id())
        .unwrap()
        .unwrap();
    assert_eq!(invalidated.state, PlanApprovalState::Invalidated);
    assert!(matches!(
        invalidated.terminal,
        Some(PlanApprovalTerminal::Invalidated {
            ref reason_code,
            ref actor_id,
            ..
        }) if reason_code == "repository-changed" && actor_id.as_str() == "actor-1"
    ));
    assert!(InvalidatePlanApproval::new(&store, &WithinWindow)
        .execute(InvalidatePlanApprovalInput {
            approval_id: database.approval.approval_id().clone(),
            actor_id: ActorId::new("actor-1").unwrap(),
            reason_code: "again".to_owned(),
        })
        .is_err());
}

#[test]
fn live_repository_change_rejects_resolution_across_reopen_without_mutation() {
    let database = TestDatabase::new();
    database.set_repository_fingerprint(digest(b"repository changed"));

    let error = ResolvePlanApproval::new(&database.store(), &WithinWindow)
        .execute(resolve_input(&database, PlanApprovalAction::Approve))
        .unwrap_err();
    assert_eq!(
        error.safe_classification(),
        SafeErrorClassification::Conflict
    );
    assert_pending_without_terminal_event(&database);
}

#[test]
fn repository_change_after_transaction_check_rolls_back_resolution() {
    let database = TestDatabase::new();
    database.mutate_repository_on_authority_call(3, digest(b"repository changed during commit"));

    let error = ResolvePlanApproval::new(&database.store(), &WithinWindow)
        .execute(resolve_input(&database, PlanApprovalAction::Approve))
        .unwrap_err();
    assert_eq!(
        error.safe_classification(),
        SafeErrorClassification::IntegrityFailure
    );
    assert_pending_without_terminal_event(&database);
}

#[test]
fn live_policy_change_rejects_resolution_across_reopen_without_mutation() {
    let database = TestDatabase::new();
    database.set_policy_snapshot_digest(digest(b"policy changed"));

    let error = ResolvePlanApproval::new(&database.store(), &WithinWindow)
        .execute(resolve_input(&database, PlanApprovalAction::Approve))
        .unwrap_err();
    assert_eq!(
        error.safe_classification(),
        SafeErrorClassification::Conflict
    );
    assert_pending_without_terminal_event(&database);
}

#[test]
fn missing_live_authority_fails_closed_without_mutation() {
    let database = TestDatabase::new();
    let store = SqliteStore::open(&database.path).unwrap();

    let error = store
        .current_state(&TaskId::new("task-1").unwrap())
        .unwrap_err();
    assert_eq!(
        error.safe_classification(),
        SafeErrorClassification::Unavailable
    );
    assert_pending_without_terminal_event(&database);
}

#[test]
fn expired_request_terminalizes_durably_before_rejecting_resolution() {
    let database = TestDatabase::new();
    let store = database.store();

    assert!(ResolvePlanApproval::new(&store, &AfterExpiry)
        .execute(resolve_input(&database, PlanApprovalAction::Approve))
        .is_err());

    let expired = database
        .store()
        .reload(database.approval.approval_id())
        .unwrap()
        .unwrap();
    assert_eq!(expired.state, PlanApprovalState::Expired);
    assert!(matches!(
        expired.terminal,
        Some(PlanApprovalTerminal::Expired { .. })
    ));
}

#[test]
fn unavailable_request_artifact_fails_closed_without_mutation() {
    let database = TestDatabase::new();
    database
        .connection()
        .execute(
            "UPDATE artifacts SET availability = 'missing'
             WHERE id = 'artifact-plan-approval-1'",
            [],
        )
        .unwrap();

    let error = database
        .store()
        .reload(database.approval.approval_id())
        .unwrap_err();
    assert_eq!(
        error.safe_classification(),
        SafeErrorClassification::IntegrityFailure
    );
    assert_eq!(
        database
            .connection()
            .query_row("SELECT status FROM approvals", [], |row| {
                row.get::<_, String>(0)
            })
            .unwrap(),
        "pending"
    );
}

struct WithinWindow;

impl Clock for WithinWindow {
    fn now_utc(&self) -> Result<String, PortError> {
        Ok("2026-08-09T00:05:00Z".to_owned())
    }
}

struct AfterExpiry;

impl Clock for AfterExpiry {
    fn now_utc(&self) -> Result<String, PortError> {
        Ok("2026-08-09T00:16:00Z".to_owned())
    }
}

fn seed_authority(path: &PathBuf, artifact_root: &PathBuf) {
    let repository_fingerprint = digest(b"repository");
    let manifest_digest = digest(b"{}");
    let policy_digest = digest(b"policy");
    let connection = Connection::open(path).unwrap();
    connection
        .execute_batch("PRAGMA foreign_keys = ON;")
        .unwrap();
    connection
        .execute(
            "INSERT INTO projects (
                id, name, repository_path, repository_identity, created_at, updated_at,
                policy_profile_id, artifact_root_mode, artifact_root_path
             ) VALUES ('project-1', 'Project', 'C:/repo', ?1,
                '2026-08-09T00:00:00Z', '2026-08-09T00:00:00Z', 'default',
                'application_data', ?2)",
            params![
                repository_fingerprint.as_str(),
                artifact_root.to_string_lossy().as_ref()
            ],
        )
        .unwrap();
    connection
        .execute(
            "INSERT INTO tasks (
                id, project_id, title, objective, phase, condition, operation_state,
                risk_level, base_branch, base_commit, current_sequence, workspace_version,
                fencing_epoch, created_at, updated_at
             ) VALUES ('task-1', 'project-1', 'Task', 'Approve plan',
                'AwaitingPlanApproval', 'Active', 'None', 'medium', 'main', ?1,
                8, 1, 1, '2026-08-09T00:00:00Z', '2026-08-09T00:00:00Z')",
            ["a".repeat(40)],
        )
        .unwrap();
    connection
        .execute(
            "INSERT INTO agent_descriptors (
                id, display_name, transport_type, trust_tier, manifest_json,
                manifest_digest, executable_digest, enabled,
                last_health_status, updated_at
             ) VALUES ('agent-1', 'Agent', 'in_process', 'core_adapter', '{}', ?1,
                NULL, 1, 'healthy', '2026-08-09T00:00:00Z')",
            [manifest_digest.as_str()],
        )
        .unwrap();
    drop(connection);
    publish_artifact(
        path,
        artifact_root,
        ArtifactId::new("artifact-agent-manifest-1").unwrap(),
        "manifest",
        b"{}",
    );
    publish_artifact(
        path,
        artifact_root,
        ArtifactId::new("artifact-context-1").unwrap(),
        "content",
        b"context",
    );
    publish_artifact(
        path,
        artifact_root,
        ArtifactId::new("artifact-workflow-transition-command").unwrap(),
        "workflow_transition_command",
        b"workflow transition command",
    );
    publish_artifact(
        path,
        artifact_root,
        ArtifactId::new("artifact-workflow-profile-revision").unwrap(),
        "receipt",
        b"workflow profile revision",
    );
    let connection = Connection::open(path).unwrap();
    connection
        .execute_batch("PRAGMA foreign_keys = ON;")
        .unwrap();
    connection
        .execute(
            "INSERT INTO context_packages (
                id, task_id, agent_id, role, objective, manifest_artifact_id,
                effective_content_artifact_id, content_hash, policy_snapshot_digest,
                prompt_template_version, retrieval_pipeline_version, created_at
             ) VALUES ('context-1', 'task-1', 'agent-1', 'reviewer', 'approve',
                'artifact-agent-manifest-1', 'artifact-context-1', ?1, ?2,
                'prompt.v1', 'retrieval.v1', '2026-08-09T00:00:00Z')",
            params![digest(b"context").as_str(), policy_digest.as_str()],
        )
        .unwrap();
    seed_awaiting_plan_approval_workflow_state(&connection, &policy_digest);
}

struct WorkflowTransitionFixture {
    id: &'static str,
    rule_id: &'static str,
    expected_stream_version: i64,
    from_phase: &'static str,
    event_type: &'static str,
    to_phase: &'static str,
    workflow_profile: &'static str,
}

fn seed_awaiting_plan_approval_workflow_state(
    connection: &Connection,
    policy_digest: &Sha256Digest,
) {
    connection
        .execute(
            "INSERT INTO task_workflow_authority (
                task_id, workflow_profile, outcome_mode, phase, selected_by_kind,
                selected_by_actor_binding_id, selection_policy_digest, created_at,
                updated_at, completed_at, stream_version, last_transition_event_id,
                profile_revision, last_profile_revision_id
             ) VALUES (
                'task-1', 'Standard', 'WorkspaceChange', 'Intake', 'core', NULL, ?1,
                '2026-08-09T00:00:00.000Z', '2026-08-09T00:00:00.000Z', NULL,
                0, NULL, 1, NULL
             )",
            [policy_digest.as_str()],
        )
        .unwrap();

    for (index, transition) in [
        WorkflowTransitionFixture {
            id: "workflow-transition-p001",
            rule_id: "WF-P001",
            expected_stream_version: 0,
            from_phase: "Intake",
            event_type: "task.validated",
            to_phase: "ContextBuild",
            workflow_profile: "Standard",
        },
        WorkflowTransitionFixture {
            id: "workflow-transition-p002",
            rule_id: "WF-P002",
            expected_stream_version: 1,
            from_phase: "ContextBuild",
            event_type: "context.initial.ready",
            to_phase: "ParallelAnalysis",
            workflow_profile: "Standard",
        },
        WorkflowTransitionFixture {
            id: "workflow-transition-p004",
            rule_id: "WF-P004",
            expected_stream_version: 2,
            from_phase: "ParallelAnalysis",
            event_type: "analysis.quorum.reached",
            to_phase: "CrossReview",
            workflow_profile: "Standard",
        },
        WorkflowTransitionFixture {
            id: "workflow-transition-p005",
            rule_id: "WF-P005",
            expected_stream_version: 3,
            from_phase: "CrossReview",
            event_type: "review.complete",
            to_phase: "PrePlanVerification",
            workflow_profile: "Standard",
        },
        WorkflowTransitionFixture {
            id: "workflow-transition-p006",
            rule_id: "WF-P006",
            expected_stream_version: 4,
            from_phase: "PrePlanVerification",
            event_type: "claims.checked",
            to_phase: "Synthesis",
            workflow_profile: "Standard",
        },
        WorkflowTransitionFixture {
            id: "workflow-transition-p007",
            rule_id: "WF-P007",
            expected_stream_version: 5,
            from_phase: "Synthesis",
            event_type: "decision.draft.created",
            to_phase: "FinalObjection",
            workflow_profile: "Standard",
        },
    ]
    .into_iter()
    .enumerate()
    {
        let updated_at = format!("2026-08-09T00:00:{:02}.000Z", index + 1);
        accept_workflow_transition(connection, &transition, &updated_at);
        connection
            .execute(
                "UPDATE task_workflow_authority
                 SET phase = ?1, stream_version = ?2, last_transition_event_id = ?3,
                     updated_at = ?4
                 WHERE task_id = 'task-1'",
                params![
                    transition.to_phase,
                    transition.expected_stream_version + 1,
                    transition.id,
                    updated_at,
                ],
            )
            .unwrap();
    }

    connection
        .execute(
            "INSERT INTO workflow_profile_revisions (
                id, task_id, revision_no, expected_stream_version, from_profile,
                to_profile, reason_artifact_id, policy_digest, decided_by_kind,
                actor_binding_id, created_at, receipt_digest
             ) VALUES (
                'workflow-profile-revision-2', 'task-1', 2, 6, 'Standard',
                'HighAssurance', 'artifact-workflow-profile-revision', ?1, 'core', NULL,
                '2026-08-09T00:00:07.000Z', ?2
             )",
            params![
                policy_digest.as_str(),
                digest(b"workflow-profile-revision-2").as_str(),
            ],
        )
        .unwrap();
    connection
        .execute(
            "UPDATE task_workflow_authority
             SET workflow_profile = 'HighAssurance', stream_version = 7,
                 profile_revision = 2,
                 last_profile_revision_id = 'workflow-profile-revision-2',
                 updated_at = '2026-08-09T00:00:07.000Z'
             WHERE task_id = 'task-1'",
            [],
        )
        .unwrap();

    let transition = WorkflowTransitionFixture {
        id: "workflow-transition-p013",
        rule_id: "WF-P013",
        expected_stream_version: 7,
        from_phase: "FinalObjection",
        event_type: "objection.round.closed",
        to_phase: "AwaitingPlanApproval",
        workflow_profile: "HighAssurance",
    };
    accept_workflow_transition(connection, &transition, "2026-08-09T00:00:08.000Z");
    connection
        .execute(
            "UPDATE task_workflow_authority
             SET phase = 'AwaitingPlanApproval', stream_version = 8,
                 last_transition_event_id = 'workflow-transition-p013',
                 updated_at = '2026-08-09T00:00:08.000Z'
             WHERE task_id = 'task-1'",
            [],
        )
        .unwrap();
}

fn accept_workflow_transition(
    connection: &Connection,
    transition: &WorkflowTransitionFixture,
    accepted_at: &str,
) {
    let binding_digest = digest(transition.id.as_bytes());
    connection
        .execute(
            "INSERT INTO workflow_transition_events (
                id, task_id, rule_id, expected_stream_version, from_phase, event_type,
                to_phase, workflow_profile, outcome_mode, transition_command_artifact_id,
                guard_set_digest, effect_set_digest, core_actor_digest, reducer_version,
                status, prepared_at, accepted_at, rejected_at
             ) VALUES (
                ?1, 'task-1', ?2, ?3, ?4, ?5, ?6, ?7, 'WorkspaceChange',
                'artifact-workflow-transition-command', ?8, ?8, ?8, 'v3',
                'prepared', ?9, NULL, NULL
             )",
            params![
                transition.id,
                transition.rule_id,
                transition.expected_stream_version,
                transition.from_phase,
                transition.event_type,
                transition.to_phase,
                transition.workflow_profile,
                binding_digest.as_str(),
                accepted_at,
            ],
        )
        .unwrap();

    let guard_kinds: Vec<String> = {
        let mut statement = connection
            .prepare(
                "SELECT evidence_kind
                 FROM workflow_transition_rule_guard_requirements
                 WHERE rule_id = ?1
                 ORDER BY evidence_kind",
            )
            .unwrap();
        statement
            .query_map([transition.rule_id], |row| row.get(0))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap()
    };
    for (index, evidence_kind) in guard_kinds.iter().enumerate() {
        connection
            .execute(
                "INSERT INTO workflow_transition_guard_bindings (
                    transition_event_id, evidence_kind, evidence_ref, subject_digest,
                    evidence_digest, artifact_id, approval_receipt_id, acceptance_receipt_id,
                    verification_receipt_id, ref_promotion_receipt_id
                 ) VALUES (?1, ?2, ?3, NULL, ?4, NULL, NULL, NULL, NULL, NULL)",
                params![
                    transition.id,
                    evidence_kind,
                    format!("{}:guard:{index}", transition.id),
                    binding_digest.as_str(),
                ],
            )
            .unwrap();
    }

    let effect_kinds: Vec<String> = {
        let mut statement = connection
            .prepare(
                "SELECT effect_kind
                 FROM workflow_transition_rule_effect_requirements
                 WHERE rule_id = ?1
                 ORDER BY effect_kind",
            )
            .unwrap();
        statement
            .query_map([transition.rule_id], |row| row.get(0))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap()
    };
    for (index, effect_kind) in effect_kinds.iter().enumerate() {
        connection
            .execute(
                "INSERT INTO workflow_transition_effect_bindings (
                    transition_event_id, effect_kind, effect_ref, effect_digest, artifact_id
                 ) VALUES (?1, ?2, ?3, ?4, NULL)",
                params![
                    transition.id,
                    effect_kind,
                    format!("{}:effect:{index}", transition.id),
                    binding_digest.as_str(),
                ],
            )
            .unwrap();
    }
    connection
        .execute(
            "UPDATE workflow_transition_events
             SET status = 'accepted', accepted_at = ?1
             WHERE id = ?2",
            params![accepted_at, transition.id],
        )
        .unwrap();
}

fn publish_artifact(
    path: &PathBuf,
    artifact_root: &PathBuf,
    artifact_id: ArtifactId,
    artifact_type: &str,
    bytes: &[u8],
) {
    use local_agent_terminal_application::{ArtifactStore, NewArtifact};

    let content_digest = digest(bytes);
    let physical = ContentAddressedArtifactStore::open(artifact_root)
        .unwrap()
        .put(NewArtifact {
            expected_hash: content_digest.as_str().to_owned(),
            expected_size: u64::try_from(bytes.len()).unwrap(),
            content: bytes.to_vec(),
        })
        .unwrap();
    let connection = Connection::open(path).unwrap();
    connection
        .execute_batch("PRAGMA foreign_keys = ON;")
        .unwrap();
    connection
        .execute(
            "INSERT INTO artifacts (
                id, task_id, project_id, artifact_type, logical_path, content_hash,
                storage_key, size_bytes, mime_type, availability, created_by_type,
                created_by_id, created_at, supersedes, verification_state
             ) VALUES (?1, 'task-1', 'project-1', ?2, ?3, ?4, ?5, ?6,
                'application/json', 'available', 'core', 'test',
                '2026-08-09T00:00:00Z', NULL, 'hash_verified')",
            params![
                artifact_id.as_str(),
                artifact_type,
                format!("approval/{}.json", artifact_id.as_str()),
                content_digest.as_str(),
                physical.storage_key,
                i64::try_from(bytes.len()).unwrap(),
            ],
        )
        .unwrap();
}

fn binding() -> PlanApprovalBindingInput {
    PlanApprovalBindingInput {
        task_id: "task-1".to_owned(),
        plan_artifact_id: "plan-1".to_owned(),
        plan_digest: digest(b"plan").as_str().to_owned(),
        plan_version: 1,
        base_commit: "a".repeat(40),
        allowed_paths: vec![PlanApprovalPathScopeV1 {
            root_capability: "root-1".to_owned(),
            patterns: vec!["src/**".to_owned()],
        }],
        planned_tool_digests: vec![digest(b"tool").as_str().to_owned()],
        verification_profile_digest: digest(b"verification").as_str().to_owned(),
        risk_class: "medium".to_owned(),
        repository_fingerprint: digest(b"repository").as_str().to_owned(),
        policy_snapshot_digest: digest(b"policy").as_str().to_owned(),
        agent_id: "agent-1".to_owned(),
        agent_manifest_digest: digest(b"{}").as_str().to_owned(),
        actor_id: "actor-1".to_owned(),
        task_version: 8,
        workspace_version: 1,
        fencing_epoch: 2,
        requested_at: "2026-08-09T00:00:00Z".to_owned(),
        expires_at: "2026-08-09T00:15:00Z".to_owned(),
    }
}

fn awaiting_state() -> WorkflowState {
    WorkflowState::rehydrate(WorkflowStateSnapshot {
        phase: Phase::AwaitingPlanApproval,
        condition: Condition::Active,
        operation: OperationState::None,
        workflow_profile: WorkflowProfile::HighAssurance,
        outcome_mode: TaskOutcomeMode::WorkspaceChange,
        stream_version: 8,
        profile_revision: 2,
        workspace_version: 1,
        fencing_epoch: 1,
        last_transition_event_id: Some("workflow-transition-p013".to_owned()),
        last_profile_revision_id: Some("workflow-profile-revision-2".to_owned()),
    })
    .unwrap()
}

fn resolve_input(database: &TestDatabase, action: PlanApprovalAction) -> ResolvePlanApprovalInput {
    ResolvePlanApprovalInput {
        approval_id: database.approval.approval_id().clone(),
        displayed_digest: database.approval.operation_digest().clone(),
        expected_task_version: 8,
        actor_id: ActorId::new("actor-1").unwrap(),
        action,
        feedback: (action == PlanApprovalAction::Revise)
            .then(|| "Revise the plan with the supplied user feedback.".to_owned()),
    }
}

fn assert_pending_without_terminal_event(database: &TestDatabase) {
    let connection = database.connection();
    assert_eq!(
        connection
            .query_row("SELECT status FROM approvals", [], |row| {
                row.get::<_, String>(0)
            })
            .unwrap(),
        "pending"
    );
    assert_eq!(
        connection
            .query_row(
                "SELECT COUNT(*) FROM events WHERE event_type IN (
                    'plan.approved', 'task.cancelled', 'approval.invalidated',
                    'approval.expired'
                 )",
                [],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
        0
    );
}

fn digest(bytes: &[u8]) -> Sha256Digest {
    Sha256Digest::new(format!("sha256:{:x}", Sha256::digest(bytes))).unwrap()
}
