use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::sync::Mutex;

use local_agent_terminal_application::{
    canonical_plan_approval_payload, ApprovalId, CanonicalDeliberationFact,
    DeliberationArtifactRef, DeliberationBoundaryCheck, DeliberationBoundaryStore,
    DeliberationCommandContext, DeliberationCommands, DeliberationDispatchBinding,
    DeliberationDispatchStore, DeliberationPersistenceCommand, DeliberationPhaseDispatchAuthority,
    DeliberationPhaseDispatchSet, DeliberationPlanDto, DeliberationProposalDispatchPlan,
    DeliberationRecord, DeliberationRejectedAlternativeDto, DeliberationRunAssignment,
    DeliberationSnapshot, DeliberationStore, DeliberationSynthesisStore,
    PersistDeliberationSynthesis, PlanApprovalAuthorityBinding, PlanApprovalAuthorityProvider,
    PlanApprovalBindingInput, PlanApprovalPathScopeV1, PlanApprovalState, PlanApprovalStore,
    PortError, PreparePlanApprovalRequestInput, SafeErrorClassification,
};
use local_agent_terminal_domain::{
    ActorId, AgentFamilyKey, AgentRunLimits, ArtifactId, BoundAgentConnection,
    BoundAgentRunRequest, BoundEffectiveContext, BoundGenerationParameters, BoundRunConfig,
    ClaimVerification, DecisionApproach, DecisionPackage, DeliberationLimits,
    DeliberationTaskBudget, Dissent, EventId, EvidenceCitation, EvidenceFreshness, FinalObjection,
    FinalObjectionSet, GitObjectId, IndependentProposal, LineRange, MaterialClaim,
    ObjectionSeverity, Phase, ProjectId, RejectedApproach, ReviewEdge, ReviewPlan, RunId,
    Sha256Digest, SourceIdentity, SpecialistBudget, SpecialistRequest, TaskId, Timestamp,
    TrustTier, VerificationMethod, WorkspaceFingerprint,
};
use local_agent_terminal_storage_files::{
    ContentAddressedArtifactReader, ContentAddressedArtifactStore,
};
use local_agent_terminal_storage_sqlite::{canonical_agent_run_config_artifact, SqliteStore};
use rusqlite::{params, Connection};
use sha2::{Digest, Sha256};

static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

struct TestDatabase {
    directory: PathBuf,
    path: PathBuf,
    artifact_root: PathBuf,
}

impl TestDatabase {
    fn new() -> Self {
        let directory = std::env::temp_dir().join(format!(
            "local-agent-terminal-deliberation-store-test-{}-{}",
            std::process::id(),
            NEXT_TEMP.fetch_add(1, Ordering::Relaxed),
        ));
        fs::create_dir_all(&directory).unwrap();
        let artifact_root = directory.join("artifacts");
        fs::create_dir(&artifact_root).unwrap();
        let path = directory.join("state.sqlite3");
        SqliteStore::open(&path).unwrap();
        let database = Self {
            directory,
            path,
            artifact_root,
        };
        database.seed();
        database
    }

    fn store(&self) -> SqliteStore {
        SqliteStore::open(&self.path)
            .unwrap()
            .with_artifact_reader(Arc::new(ContentAddressedArtifactReader))
    }

    fn connection(&self) -> Connection {
        let connection = Connection::open(&self.path).unwrap();
        connection
            .execute_batch("PRAGMA foreign_keys = ON;")
            .unwrap();
        connection
    }

    fn seed(&self) {
        let digest = digest(b"seed");
        let connection = self.connection();
        connection
            .execute(
                "INSERT INTO projects (
                    id, name, repository_path, repository_identity, created_at, updated_at,
                    policy_profile_id, artifact_root_mode, artifact_root_path
                 ) VALUES ('project-1', 'Project', 'C:/repo', ?1,
                    '2026-08-09T00:00:00Z', '2026-08-09T00:00:00Z', 'default',
                    'application_data', ?2)",
                params![
                    digest.as_str(),
                    self.artifact_root.to_string_lossy().as_ref()
                ],
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO tasks (
                    id, project_id, title, objective, phase, condition, operation_state,
                    risk_level, base_branch, base_commit, current_sequence, workspace_version,
                    fencing_epoch, created_at, updated_at
                 ) VALUES ('task-1', 'project-1', 'Task', 'Deliberate', 'ParallelAnalysis',
                    'Active', 'None', 'medium', 'main', ?1, 0, 1, 1,
                    '2026-08-09T00:00:00Z', '2026-08-09T00:00:00Z')",
                ["a".repeat(40)],
            )
            .unwrap();
        drop(connection);
        for number in 1..=2 {
            self.seed_agent_run(number);
        }
    }

    fn seed_agent_run(&self, number: u8) {
        let agent_id = format!("agent-{number}");
        let manifest_id = ArtifactId::new(format!("manifest-{number}")).unwrap();
        let content_id = ArtifactId::new(format!("context-content-{number}")).unwrap();
        let config_id = ArtifactId::new(format!("run-config-{number}")).unwrap();
        self.publish_raw(&manifest_id, "manifest", b"{}").unwrap();
        self.publish_raw(&content_id, "content", b"context")
            .unwrap();
        let binding_digest = connection_binding_digest(number);
        let executable_digest = digest(format!("executable-{number}").as_bytes());
        self.publish_raw(
            &config_id,
            "run-config",
            &run_config_artifact(number, binding_digest.clone()),
        )
        .unwrap();
        let connection = self.connection();
        connection
            .execute(
                "INSERT INTO agent_descriptors (
                    id, display_name, transport_type, trust_tier, manifest_json,
                    manifest_digest, executable_digest, enabled, containment_verified,
                    last_health_status, updated_at
                 ) VALUES (?1, ?2, 'in_process', 'core_adapter', '{}', ?3,
                    ?4, 1, 1, 'healthy', '2026-08-09T00:00:00Z')",
                params![
                    agent_id,
                    format!("Agent {number}"),
                    digest(b"{}").as_str(),
                    executable_digest.as_str(),
                ],
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO context_packages (
                    id, task_id, agent_id, role, objective, manifest_artifact_id,
                    effective_content_artifact_id, content_hash, policy_snapshot_digest,
                    prompt_template_version, retrieval_pipeline_version, created_at
                 ) VALUES (?1, 'task-1', ?2, ?3, 'analyze', ?4, ?5, ?6, ?7,
                    'prompt.v1', 'retrieval.v1', '2026-08-09T00:00:00Z')",
                params![
                    format!("context-{number}"),
                    agent_id,
                    "reviewer",
                    manifest_id.as_str(),
                    content_id.as_str(),
                    digest(b"context").as_str(),
                    digest(b"policy").as_str(),
                ],
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO agent_runs (
                    id, task_id, agent_id, role, phase, status, context_package_id,
                    idempotency_key, connection_binding_digest, run_config_artifact_id,
                    supersedes_run_id, started_at, completed_at, provider_usage_json,
                    core_usage_json, estimated_cost_microunits, error_json
                 ) VALUES (?1, 'task-1', ?2, ?3, 'ParallelAnalysis', 'running', ?4,
                    ?5, ?6, ?7, NULL, '2026-08-09T00:00:00Z', NULL, NULL, NULL, NULL, NULL)",
                params![
                    format!("run-{number}"),
                    agent_id,
                    "reviewer",
                    format!("context-{number}"),
                    format!("run-key-{number}"),
                    binding_digest.as_str(),
                    config_id.as_str(),
                ],
            )
            .unwrap();
    }

    fn publish(&self, id: &str, bytes: &[u8]) -> DeliberationArtifactRef {
        let artifact_id = ArtifactId::new(id).unwrap();
        self.publish_raw(&artifact_id, "deliberation", bytes)
            .unwrap();
        DeliberationArtifactRef::new(
            artifact_id,
            digest(bytes),
            u64::try_from(bytes.len()).unwrap(),
        )
        .unwrap()
    }

    fn publish_raw(
        &self,
        artifact_id: &ArtifactId,
        artifact_type: &str,
        bytes: &[u8],
    ) -> Result<(), PortError> {
        use local_agent_terminal_application::{ArtifactStore, NewArtifact};

        let content_digest = digest(bytes);
        let physical = ContentAddressedArtifactStore::open(&self.artifact_root)
            .unwrap()
            .put(NewArtifact {
                expected_hash: content_digest.as_str().to_owned(),
                expected_size: u64::try_from(bytes.len()).unwrap(),
                content: bytes.to_vec(),
            })?;
        self.connection()
            .execute(
                "INSERT OR IGNORE INTO artifacts (
                    id, task_id, project_id, artifact_type, logical_path, content_hash,
                    storage_key, size_bytes, mime_type, availability, created_by_type,
                    created_by_id, created_at, supersedes, verification_state
                 ) VALUES (?1, 'task-1', 'project-1', ?2, ?3, ?4, ?5, ?6,
                    'application/json', 'available', 'core', 'test',
                    '2026-08-09T00:00:00Z', NULL, 'hash_verified')",
                params![
                    artifact_id.as_str(),
                    artifact_type,
                    format!("deliberation/{}.json", artifact_id.as_str()),
                    content_digest.as_str(),
                    physical.storage_key,
                    i64::try_from(bytes.len()).unwrap(),
                ],
            )
            .unwrap();
        Ok(())
    }
}

impl Drop for TestDatabase {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.directory);
    }
}

#[test]
fn sqlite_store_exposes_the_application_deliberation_port() {
    fn accepts(_: &dyn DeliberationStore) {}
    fn accepts_dispatch(_: &dyn DeliberationDispatchStore) {}
    fn accepts_boundary(_: &dyn DeliberationBoundaryStore) {}
    fn accepts_synthesis(_: &dyn DeliberationSynthesisStore) {}

    let database = TestDatabase::new();
    accepts(&database.store());
    accepts_dispatch(&database.store());
    accepts_boundary(&database.store());
    accepts_synthesis(&database.store());
}

#[test]
fn repository_boundary_is_idempotent_and_invalidates_task_context_packages() {
    let database = TestDatabase::new();
    let store = database.store();
    let baseline = workspace_fingerprint('a');
    let changed = workspace_fingerprint('b');

    let accepted = store
        .compare_and_persist_boundary(DeliberationBoundaryCheck::new(
            TaskId::new("task-1").unwrap(),
            Phase::ParallelAnalysis,
            baseline,
        ))
        .unwrap();
    assert!(!accepted.blocked);
    let blocked_check =
        DeliberationBoundaryCheck::new(TaskId::new("task-1").unwrap(), Phase::CrossReview, changed);
    let blocked = store
        .compare_and_persist_boundary(blocked_check.clone())
        .unwrap();
    let repeated = store.compare_and_persist_boundary(blocked_check).unwrap();

    assert!(blocked.blocked);
    assert_eq!(repeated, blocked);
    assert!(store.context_package_view("context-1").unwrap().is_none());
    let connection = database.connection();
    assert_eq!(
        count(&connection, "deliberation_repository_boundary_records"),
        2
    );
    assert_eq!(
        count(&connection, "deliberation_context_package_invalidations"),
        2
    );
}

#[test]
fn dispatch_reservations_are_atomic_idempotent_and_task_bounded() {
    let database = TestDatabase::new();
    let store = database.store();
    let budget =
        DeliberationTaskBudget::new(4, 16_000, 200, Timestamp::from_unix_seconds(2_000_000_000))
            .unwrap();
    let plan = dispatch_plan("run-dispatch-a", "run-dispatch-b", budget);

    store
        .compare_and_persist_proposal_binding_set(&plan)
        .unwrap();
    store
        .compare_and_persist_proposal_binding_set(&plan)
        .unwrap();

    let connection = database.connection();
    let reserved: (i64, i64, i64) = connection
        .query_row(
            "SELECT reserved_threads, reserved_tokens, reserved_cost_microunits
             FROM deliberation_task_budgets WHERE task_id = 'task-1'",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap();
    assert_eq!(reserved, (0, 16_000, 200));
    assert_eq!(count(&connection, "deliberation_dispatch_reservations"), 2);

    let exhausted = dispatch_plan("run-dispatch-c", "run-dispatch-d", budget);
    let error = store
        .compare_and_persist_proposal_binding_set(&exhausted)
        .unwrap_err();
    assert_eq!(
        error.safe_classification(),
        SafeErrorClassification::Conflict
    );
    assert_eq!(count(&connection, "deliberation_dispatch_reservations"), 2);

    let raised =
        DeliberationTaskBudget::new(4, 32_000, 400, Timestamp::from_unix_seconds(2_000_000_000))
            .unwrap();
    let error = store
        .compare_and_persist_proposal_binding_set(&dispatch_plan(
            "run-dispatch-a",
            "run-dispatch-b",
            raised,
        ))
        .unwrap_err();
    assert_eq!(
        error.safe_classification(),
        SafeErrorClassification::Conflict
    );
}

#[test]
fn phase_dispatch_rejects_an_all_new_set_for_the_same_task_phase() {
    let database = TestDatabase::new();
    let store = database.store();
    let budget =
        DeliberationTaskBudget::new(4, 32_000, 400, Timestamp::from_unix_seconds(2_000_000_000))
            .unwrap();
    let first = phase_dispatch_set("run-phase-a", 1, budget);
    let replacement = phase_dispatch_set("run-phase-b", 2, budget);

    store.compare_and_persist_phase_binding_set(&first).unwrap();
    let error = store
        .compare_and_persist_phase_binding_set(&replacement)
        .unwrap_err();

    assert_eq!(
        error.safe_classification(),
        SafeErrorClassification::Conflict
    );
    assert_eq!(
        count(&database.connection(), "deliberation_dispatch_reservations"),
        1
    );
}

#[test]
fn explicit_reopened_round_persists_as_a_distinct_bounded_dispatch_set() {
    let database = TestDatabase::new();
    let store = database.store();
    let budget =
        DeliberationTaskBudget::new(4, 32_000, 400, Timestamp::from_unix_seconds(2_000_000_000))
            .unwrap();

    store
        .compare_and_persist_phase_binding_set(&phase_dispatch_set_for_round(
            "run-round-1",
            1,
            1,
            budget,
        ))
        .unwrap();
    store
        .compare_and_persist_phase_binding_set(&phase_dispatch_set_for_round(
            "run-round-2",
            2,
            2,
            budget,
        ))
        .unwrap();

    let connection = database.connection();
    assert_eq!(count(&connection, "deliberation_dispatch_reservations"), 2);
    let rounds: String = connection
        .query_row(
            "SELECT group_concat(dispatch_round, ',') FROM (
                SELECT dispatch_round FROM deliberation_dispatch_reservations
                ORDER BY dispatch_round
             )",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(rounds, "1,2");
}

#[test]
fn specialist_persistence_cannot_reuse_tokens_and_cost_reserved_by_dispatch() {
    let database = TestDatabase::new();
    let store = database.store();
    let budget =
        DeliberationTaskBudget::new(4, 20_000, 250, Timestamp::from_unix_seconds(2_000_000_000))
            .unwrap();
    store
        .compare_and_persist_proposal_binding_set(&dispatch_plan(
            "run-dispatch-a",
            "run-dispatch-b",
            budget,
        ))
        .unwrap();

    let snapshot = store.load(&TaskId::new("task-1").unwrap()).unwrap();
    let request = SpecialistRequest::new(
        "specialist-over-budget",
        TaskId::new("task-1").unwrap(),
        RunId::new("run-1").unwrap(),
        "security-review",
        "Verify a material security claim.",
        vec![ArtifactId::new("context-content-1").unwrap()],
        SpecialistBudget::new(5_000, 100, Timestamp::from_unix_seconds(1_800_000_300)).unwrap(),
    )
    .unwrap();
    let error = DeliberationCommands::new(&store)
        .request_specialist(
            command_context_with_budget(
                &snapshot,
                "agent-1",
                database.publish("specialist-over-budget", b"specialist over budget"),
                "event-specialist-over-budget",
                budget,
            ),
            request,
        )
        .unwrap_err();
    assert_eq!(
        error.safe_classification(),
        SafeErrorClassification::Conflict
    );

    let connection = database.connection();
    assert_eq!(count(&connection, "events"), 0);
    let reserved: (i64, i64) = connection
        .query_row(
            "SELECT reserved_tokens, reserved_cost_microunits
             FROM deliberation_task_budgets WHERE task_id = 'task-1'",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(reserved, (16_000, 200));
}

#[test]
fn budget_authority_seeds_reservations_from_historical_deliberation_records() {
    let database = TestDatabase::new();
    let store = database.store();
    let budget =
        DeliberationTaskBudget::new(4, 21_000, 250, Timestamp::from_unix_seconds(2_000_000_000))
            .unwrap();
    let snapshot = store.load(&TaskId::new("task-1").unwrap()).unwrap();
    let request = SpecialistRequest::new(
        "specialist-before-v8",
        TaskId::new("task-1").unwrap(),
        RunId::new("run-1").unwrap(),
        "security-review",
        "Verify a material security claim.",
        vec![ArtifactId::new("context-content-1").unwrap()],
        SpecialistBudget::new(5_000, 50, Timestamp::from_unix_seconds(1_800_000_300)).unwrap(),
    )
    .unwrap();
    DeliberationCommands::new(&store)
        .request_specialist(
            command_context_with_budget(
                &snapshot,
                "agent-1",
                database.publish("specialist-before-v8", b"specialist before v8"),
                "event-specialist-before-v8",
                budget,
            ),
            request,
        )
        .unwrap();

    let connection = database.connection();
    connection
        .execute_batch(
            "DROP TRIGGER IF EXISTS deliberation_task_budget_delete_forbidden;
             DELETE FROM deliberation_task_budgets WHERE task_id = 'task-1';",
        )
        .unwrap();
    drop(connection);

    assert_eq!(
        store
            .deliberation_task_budget(&TaskId::new("task-1").unwrap())
            .unwrap(),
        Some(budget)
    );

    let recovered_reservation: (i64, i64, i64) = database
        .connection()
        .query_row(
            "SELECT reserved_threads, reserved_tokens, reserved_cost_microunits
             FROM deliberation_task_budgets WHERE task_id = 'task-1'",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap();
    assert_eq!(recovered_reservation, (1, 5_000, 50));

    store
        .compare_and_persist_proposal_binding_set(&dispatch_plan(
            "run-dispatch-after-v7-a",
            "run-dispatch-after-v7-b",
            budget,
        ))
        .unwrap();

    let reserved: (i64, i64, i64) = database
        .connection()
        .query_row(
            "SELECT reserved_threads, reserved_tokens, reserved_cost_microunits
             FROM deliberation_task_budgets WHERE task_id = 'task-1'",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap();
    assert_eq!(reserved, (1, 21_000, 250));
}

#[test]
fn specialist_request_rejects_an_unavailable_required_context_artifact() {
    let database = TestDatabase::new();
    let store = database.store();
    let snapshot = store.load(&TaskId::new("task-1").unwrap()).unwrap();
    let record_artifact = database.publish("specialist-request", b"specialist request");
    let request = SpecialistRequest::new(
        "specialist-1",
        TaskId::new("task-1").unwrap(),
        RunId::new("run-1").unwrap(),
        "security-review",
        "Verify a material security claim.",
        vec![ArtifactId::new("missing-context").unwrap()],
        SpecialistBudget::new(1_000, 10_000, Timestamp::from_unix_seconds(1_800_000_300)).unwrap(),
    )
    .unwrap();

    let error = DeliberationCommands::new(&store)
        .request_specialist(
            command_context(
                &snapshot,
                "agent-1",
                record_artifact,
                "event-specialist-request",
            ),
            request,
        )
        .unwrap_err();

    assert_eq!(
        error.safe_classification(),
        SafeErrorClassification::IntegrityFailure
    );
    assert_eq!(count(&database.connection(), "events"), 0);
}

#[test]
fn recovery_rejects_a_deliberation_event_moved_to_another_task_stream() {
    let database = TestDatabase::new();
    let store = database.store();
    let snapshot = store.load(&TaskId::new("task-1").unwrap()).unwrap();
    DeliberationCommands::new(&store)
        .record_private_proposal(
            command_context(
                &snapshot,
                "agent-1",
                database.publish("receipt-cross-stream", b"receipt cross stream"),
                "event-cross-stream",
            ),
            proposal(1),
            database.publish("proposal-1", b"proposal cross stream"),
        )
        .unwrap();
    let connection = database.connection();
    connection
        .execute_batch(
            "DROP TRIGGER events_update_forbidden;
             UPDATE events SET stream_id = 'task-other'
             WHERE event_id = 'event-cross-stream';",
        )
        .unwrap();

    let error = database
        .store()
        .load(&TaskId::new("task-1").unwrap())
        .unwrap_err();
    assert_eq!(
        error.safe_classification(),
        SafeErrorClassification::IntegrityFailure
    );
}

#[test]
fn recovery_rejects_a_deliberation_event_with_a_substituted_sequence() {
    let database = TestDatabase::new();
    let store = database.store();
    let snapshot = store.load(&TaskId::new("task-1").unwrap()).unwrap();
    DeliberationCommands::new(&store)
        .record_private_proposal(
            command_context(
                &snapshot,
                "agent-1",
                database.publish("receipt-sequence", b"receipt sequence"),
                "event-sequence",
            ),
            proposal(1),
            database.publish("proposal-1", b"proposal sequence"),
        )
        .unwrap();
    let connection = database.connection();
    connection
        .execute_batch(
            "DROP TRIGGER events_update_forbidden;
             UPDATE events SET sequence = 99 WHERE event_id = 'event-sequence';",
        )
        .unwrap();

    let error = database
        .store()
        .load(&TaskId::new("task-1").unwrap())
        .unwrap_err();
    assert_eq!(
        error.safe_classification(),
        SafeErrorClassification::IntegrityFailure
    );
}

#[test]
fn recovery_rejects_a_rewritten_fact_not_bound_to_the_immutable_event() {
    let database = TestDatabase::new();
    let store = database.store();
    let snapshot = store.load(&TaskId::new("task-1").unwrap()).unwrap();
    let proposal_artifact = database.publish("proposal-1", b"proposal fact binding");
    let receipt = database.publish("receipt-fact-binding", b"receipt fact binding");
    DeliberationCommands::new(&store)
        .record_private_proposal(
            command_context(&snapshot, "agent-1", receipt.clone(), "event-fact-binding"),
            proposal(1),
            proposal_artifact.clone(),
        )
        .unwrap();
    let rewritten = CanonicalDeliberationFact::issue(
        TaskId::new("task-1").unwrap(),
        EventId::new("event-fact-binding").unwrap(),
        1,
        ActorId::new("agent-1").unwrap(),
        DeliberationRecord::PrivateProposal {
            proposal: IndependentProposal::new(
                TaskId::new("task-1").unwrap(),
                RunId::new("run-1").unwrap(),
                "agent-1",
                local_agent_terminal_domain::AgentFamilyKey::from_provider_model(
                    "provider-1",
                    "model-1",
                )
                .unwrap(),
                ArtifactId::new("proposal-1").unwrap(),
                vec![citation_with_symbol("rewritten-entry")],
            )
            .unwrap(),
            proposal_artifact,
            receipt,
        },
    )
    .unwrap();
    let connection = database.connection();
    connection
        .execute_batch("DROP TRIGGER deliberation_records_update_forbidden;")
        .unwrap();
    connection
        .execute(
            "UPDATE deliberation_records
             SET canonical_record_json = ?1, canonical_record_digest = ?2
             WHERE event_id = 'event-fact-binding'",
            params![
                std::str::from_utf8(rewritten.canonical_bytes()).unwrap(),
                rewritten.content_digest().as_str(),
            ],
        )
        .unwrap();

    let error = database
        .store()
        .load(&TaskId::new("task-1").unwrap())
        .unwrap_err();
    assert_eq!(
        error.safe_classification(),
        SafeErrorClassification::IntegrityFailure
    );
}

#[test]
fn private_receipts_replay_without_messages_then_quorum_publishes_atomically_and_reopens() {
    let database = TestDatabase::new();
    let store = database.store();
    let initial = store.load(&TaskId::new("task-1").unwrap()).unwrap();
    let proposal_one_artifact = database.publish("proposal-1", b"proposal one");
    let receipt_one = database.publish("receipt-1", b"receipt one");
    let command = capture_private_command(
        initial.clone(),
        command_context(&initial, "agent-1", receipt_one.clone(), "event-private-1"),
        proposal(1),
        proposal_one_artifact.clone(),
    );

    store.persist(command.clone()).unwrap();
    store.persist(command).unwrap();
    assert_eq!(count(&database.connection(), "messages"), 0);

    let changed_receipt = database.publish("receipt-changed", b"changed receipt");
    let changed = capture_private_command(
        initial,
        command_context_for(
            0,
            local_agent_terminal_domain::Phase::ParallelAnalysis,
            "agent-1",
            changed_receipt,
            "event-private-1",
        ),
        proposal(1),
        proposal_one_artifact,
    );
    assert_eq!(
        store.persist(changed).unwrap_err().safe_classification(),
        SafeErrorClassification::Conflict
    );
    assert_eq!(count(&database.connection(), "events"), 1);

    let after_first = store.load(&TaskId::new("task-1").unwrap()).unwrap();
    let proposal_two_artifact = database.publish("proposal-2", b"proposal two");
    let receipt_two = database.publish("receipt-2", b"receipt two");
    DeliberationCommands::new(&store)
        .record_private_proposal(
            command_context(&after_first, "agent-2", receipt_two, "event-private-2"),
            proposal(2),
            proposal_two_artifact,
        )
        .unwrap();
    assert_eq!(count(&database.connection(), "messages"), 0);

    let before_quorum = store.load(&TaskId::new("task-1").unwrap()).unwrap();
    let publication = database.publish("proposal-publication", b"published proposals");
    let review_artifact = database.publish("review-plan", b"review plan");
    DeliberationCommands::new(&store)
        .publish_proposals(
            command_context(&before_quorum, "core", publication, "event-quorum"),
            review_plan(),
            review_artifact.clone(),
        )
        .unwrap();

    let connection = database.connection();
    assert_eq!(count(&connection, "messages"), 2);
    assert_eq!(count(&connection, "deliberation_records"), 3);
    assert_eq!(
        connection
            .query_row(
                "SELECT COUNT(*) FROM messages
                 WHERE content_artifact_id IN ('receipt-1', 'receipt-2')",
                [],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
        0
    );
    drop(connection);

    let reopened = database.store();
    let snapshot = reopened.load(&TaskId::new("task-1").unwrap()).unwrap();
    assert_eq!(snapshot.private_proposals().len(), 2);
    assert!(snapshot.quorum().is_some());
    assert!(snapshot.review_plan().is_some());
    assert_eq!(
        snapshot.task_state.phase(),
        local_agent_terminal_domain::Phase::CrossReview
    );

    DeliberationCommands::new(&reopened)
        .record_review_edges(
            command_context(&snapshot, "core", review_artifact, "event-review-edges-1"),
            review_plan(),
        )
        .unwrap();
    let snapshot = reopened.load(&TaskId::new("task-1").unwrap()).unwrap();
    DeliberationCommands::new(&reopened)
        .record_thread_summary(
            command_context(
                &snapshot,
                "core",
                database.publish("thread-summary-1", b"thread summary one"),
                "event-thread-summary-1",
            ),
            "thread-1",
        )
        .unwrap();
    let snapshot = reopened.load(&TaskId::new("task-1").unwrap()).unwrap();
    DeliberationCommands::new(&reopened)
        .record_claim_set(
            command_context(
                &snapshot,
                "core",
                database.publish("claim-set-1", b"claim set one"),
                "event-claim-set-1",
            ),
            vec![claim(false)],
        )
        .unwrap();
    let snapshot = reopened.load(&TaskId::new("task-1").unwrap()).unwrap();
    DeliberationCommands::new(&reopened)
        .record_verification_set(
            command_context(
                &snapshot,
                "core",
                database.publish("verification-set-1", b"verification set one"),
                "event-verification-set-1",
            ),
            vec![claim(true)],
        )
        .unwrap();
    let snapshot = reopened.load(&TaskId::new("task-1").unwrap()).unwrap();
    let decision_one = database.publish("decision-draft-1", b"decision draft one");
    let mismatched_plan = database.publish("plan-mismatch", b"not the canonical plan DTO");
    let before_synthesis = count(&database.connection(), "deliberation_records");
    let mismatched = PersistDeliberationSynthesis::new(&reopened)
        .prepare(
            command_context(&snapshot, "core", decision_one.clone(), "event-decision-1"),
            decision("plan-mismatch", claim(true)),
            plan_dto(),
            mismatched_plan,
            1,
        )
        .unwrap();
    assert!(reopened.persist_synthesis(mismatched).is_err());
    assert_eq!(
        count(&database.connection(), "deliberation_records"),
        before_synthesis
    );
    assert_eq!(
        count(&database.connection(), "deliberation_synthesis_plans"),
        0
    );
    let plan_one = database.publish("plan-1", &plan_bytes());
    let synthesis = PersistDeliberationSynthesis::new(&reopened)
        .prepare(
            command_context(&snapshot, "core", decision_one.clone(), "event-decision-1"),
            decision("plan-1", claim(true)),
            plan_dto(),
            plan_one,
            1,
        )
        .unwrap();
    reopened.persist_synthesis(synthesis.clone()).unwrap();
    reopened.persist_synthesis(synthesis).unwrap();
    assert_eq!(
        count(&database.connection(), "deliberation_synthesis_plans"),
        1
    );
    let snapshot = reopened.load(&TaskId::new("task-1").unwrap()).unwrap();
    DeliberationCommands::new(&reopened)
        .record_objection_set(
            command_context(
                &snapshot,
                "core",
                database.publish("objection-set-1", b"objection set one"),
                "event-objection-set-1",
            ),
            severe_objection_set(),
        )
        .unwrap();
    let snapshot = reopened.load(&TaskId::new("task-1").unwrap()).unwrap();
    let review_artifact_two = database.publish("review-plan-2", b"review plan two");
    DeliberationCommands::new(&reopened)
        .accept_severe_objection(
            command_context(
                &snapshot,
                "core",
                review_artifact_two.clone(),
                "event-severe-objection-1",
            ),
            review_plan_for_round(2),
        )
        .unwrap();
    let snapshot = reopened.load(&TaskId::new("task-1").unwrap()).unwrap();
    DeliberationCommands::new(&reopened)
        .record_review_edges(
            command_context(
                &snapshot,
                "core",
                review_artifact_two,
                "event-review-edges-2",
            ),
            review_plan_for_round(2),
        )
        .unwrap();
    let snapshot = reopened.load(&TaskId::new("task-1").unwrap()).unwrap();
    DeliberationCommands::new(&reopened)
        .record_claim_set(
            command_context(
                &snapshot,
                "core",
                database.publish("claim-set-2", b"claim set two"),
                "event-claim-set-2",
            ),
            vec![claim(false)],
        )
        .unwrap();
    let snapshot = reopened.load(&TaskId::new("task-1").unwrap()).unwrap();
    DeliberationCommands::new(&reopened)
        .record_verification_set(
            command_context(
                &snapshot,
                "core",
                database.publish("verification-set-2", b"verification set two"),
                "event-verification-set-2",
            ),
            vec![claim(true)],
        )
        .unwrap();
    let snapshot = reopened.load(&TaskId::new("task-1").unwrap()).unwrap();
    let decision_two = database.publish("decision-draft-2", b"decision draft two");
    DeliberationCommands::new(&reopened)
        .record_supersession(
            command_context(
                &snapshot,
                "core",
                decision_two.clone(),
                "event-supersession-1",
            ),
            decision_one,
        )
        .unwrap();
    let snapshot = reopened.load(&TaskId::new("task-1").unwrap()).unwrap();
    let plan_two = database.publish("plan-2", &plan_bytes());
    PersistDeliberationSynthesis::new(&reopened)
        .execute(
            command_context(&snapshot, "core", decision_two, "event-decision-2"),
            decision("plan-2", claim(true)),
            plan_dto(),
            plan_two.clone(),
            2,
        )
        .unwrap();
    let snapshot = reopened.load(&TaskId::new("task-1").unwrap()).unwrap();
    DeliberationCommands::new(&reopened)
        .record_objection_set(
            command_context(
                &snapshot,
                "core",
                database.publish("objection-set-2", b"objection set two"),
                "event-objection-set-2",
            ),
            FinalObjectionSet::new(2, Vec::new()).unwrap(),
        )
        .unwrap();

    let snapshot = reopened.load(&TaskId::new("task-1").unwrap()).unwrap();
    let binding = plan_approval_binding(&snapshot, &plan_two);
    let authority = FixedPlanApprovalAuthority {
        binding: PlanApprovalAuthorityBinding::issue(binding.clone()).unwrap(),
    };
    let request = PreparePlanApprovalRequestInput {
        approval_id: ApprovalId::new("approval-plan-1").unwrap(),
        request_artifact_id: ArtifactId::new("plan-approval-request-1").unwrap(),
    };
    let canonical_request = canonical_plan_approval_payload(&binding).unwrap();
    database
        .publish_raw(
            &request.request_artifact_id,
            "approval-request",
            &canonical_request.canonical_bytes,
        )
        .unwrap();
    DeliberationCommands::with_plan_approval_authority(&reopened, &authority)
        .close_objection_round(
            command_context(
                &snapshot,
                "core",
                database.publish("objection-round-close-1", b"objection round closed"),
                "event-objection-round-close-1",
            ),
            request,
        )
        .unwrap();

    let recovered = database.store();
    let snapshot = recovered.load(&TaskId::new("task-1").unwrap()).unwrap();
    assert_eq!(
        snapshot.task_state.phase(),
        local_agent_terminal_domain::Phase::AwaitingPlanApproval
    );
    assert_eq!(snapshot.review_edges_history().len(), 2);
    assert_eq!(snapshot.thread_summaries().len(), 1);
    assert_eq!(snapshot.claim_sets().len(), 2);
    assert_eq!(snapshot.verification_sets().len(), 2);
    assert_eq!(snapshot.decision_drafts().len(), 2);
    assert_eq!(snapshot.objection_sets().len(), 2);
    assert_eq!(snapshot.severe_objection_acceptances().len(), 1);
    assert_eq!(snapshot.supersessions().len(), 1);
    assert_eq!(snapshot.objection_round_closures().len(), 1);
    assert_eq!(
        database
            .connection()
            .query_row(
                "SELECT schema_version FROM approvals WHERE id = 'approval-plan-1'",
                [],
                |row| row.get::<_, String>(0),
            )
            .unwrap(),
        "approval-digest.v1"
    );
    assert_eq!(
        PlanApprovalStore::reload(&recovered, &ApprovalId::new("approval-plan-1").unwrap())
            .unwrap()
            .unwrap()
            .state,
        PlanApprovalState::Requested
    );
}

struct CaptureStore {
    snapshot: DeliberationSnapshot,
    command: Mutex<Option<DeliberationPersistenceCommand>>,
}

struct FixedPlanApprovalAuthority {
    binding: PlanApprovalAuthorityBinding,
}

impl PlanApprovalAuthorityProvider for FixedPlanApprovalAuthority {
    fn current(&self, _: &TaskId) -> Result<PlanApprovalAuthorityBinding, PortError> {
        Ok(self.binding.clone())
    }
}

impl DeliberationStore for CaptureStore {
    fn load(&self, _: &TaskId) -> Result<DeliberationSnapshot, PortError> {
        Ok(self.snapshot.clone())
    }

    fn persist(&self, command: DeliberationPersistenceCommand) -> Result<(), PortError> {
        command.validate()?;
        *self.command.lock().unwrap() = Some(command);
        Ok(())
    }
}

fn capture_private_command(
    snapshot: DeliberationSnapshot,
    context: DeliberationCommandContext,
    proposal: IndependentProposal,
    artifact: DeliberationArtifactRef,
) -> DeliberationPersistenceCommand {
    let capture = CaptureStore {
        snapshot,
        command: Mutex::new(None),
    };
    DeliberationCommands::new(&capture)
        .record_private_proposal(context, proposal, artifact)
        .unwrap();
    capture.command.into_inner().unwrap().unwrap()
}

fn command_context(
    snapshot: &DeliberationSnapshot,
    actor_id: &str,
    artifact: DeliberationArtifactRef,
    event_id: &str,
) -> DeliberationCommandContext {
    command_context_with_budget(snapshot, actor_id, artifact, event_id, task_budget())
}

fn command_context_with_budget(
    snapshot: &DeliberationSnapshot,
    actor_id: &str,
    artifact: DeliberationArtifactRef,
    event_id: &str,
    budget: DeliberationTaskBudget,
) -> DeliberationCommandContext {
    DeliberationCommandContext::new(
        snapshot.task_id.clone(),
        snapshot.task_version,
        snapshot.task_state,
        budget,
        ActorId::new(actor_id).unwrap(),
        artifact,
        EventId::new(event_id).unwrap(),
        format!("correlation-{event_id}"),
        "2026-08-09T00:00:00Z",
    )
    .unwrap()
}

fn command_context_for(
    version: u64,
    phase: local_agent_terminal_domain::Phase,
    actor_id: &str,
    artifact: DeliberationArtifactRef,
    event_id: &str,
) -> DeliberationCommandContext {
    let state = local_agent_terminal_domain::WorkflowState::new(
        phase,
        local_agent_terminal_domain::Condition::Active,
        local_agent_terminal_domain::OperationState::None,
        local_agent_terminal_domain::Sequence::new(version),
        local_agent_terminal_domain::WorkspaceVersion::new(1),
        local_agent_terminal_domain::FencingToken::new(1).unwrap(),
    )
    .unwrap();
    DeliberationCommandContext::new(
        TaskId::new("task-1").unwrap(),
        version,
        state,
        task_budget(),
        ActorId::new(actor_id).unwrap(),
        artifact,
        EventId::new(event_id).unwrap(),
        format!("correlation-{event_id}"),
        "2026-08-09T00:00:00Z",
    )
    .unwrap()
}

fn task_budget() -> DeliberationTaskBudget {
    DeliberationTaskBudget::new(
        64,
        1_000_000,
        1_000_000_000_000,
        Timestamp::from_unix_seconds(2_000_000_000),
    )
    .unwrap()
}

fn workspace_fingerprint(character: char) -> WorkspaceFingerprint {
    WorkspaceFingerprint::new(
        GitObjectId::new(character.to_string().repeat(40)).unwrap(),
        digest(format!("index-{character}").as_bytes()).as_str(),
        digest(format!("status-{character}").as_bytes()).as_str(),
    )
    .unwrap()
}

fn plan_dto() -> DeliberationPlanDto {
    DeliberationPlanDto {
        selected_approach_id: "selected-approach".to_owned(),
        rejected_alternatives: vec![DeliberationRejectedAlternativeDto {
            approach_id: "rejected-approach".to_owned(),
            reason: "The verified evidence supports proposal 1.".to_owned(),
        }],
        verified_claim_ids: vec!["claim-a".to_owned()],
        inconclusive_claim_ids: Vec::new(),
        dissent_ids: vec!["dissent-agent-2".to_owned()],
        affected_files: vec!["crates/application/src/deliberation/commands.rs".to_owned()],
        implementation_steps: vec!["Persist the complete synthesis atomically".to_owned()],
        planned_tools: vec!["cargo.test".to_owned()],
        verification_profile: "m4-task-10".to_owned(),
        rollback_plan: "Revert the local source commit".to_owned(),
        risk: "medium".to_owned(),
        estimated_cost_microunits: Some(100),
        estimated_duration_seconds: Some(30),
        confidence: 90,
    }
}

fn plan_bytes() -> Vec<u8> {
    serde_json_canonicalizer::to_vec(&plan_dto()).unwrap()
}

fn proposal(number: u8) -> IndependentProposal {
    IndependentProposal::new(
        TaskId::new("task-1").unwrap(),
        RunId::new(format!("run-{number}")).unwrap(),
        &format!("agent-{number}"),
        local_agent_terminal_domain::AgentFamilyKey::from_provider_model(
            &format!("provider-{number}"),
            &format!("model-{number}"),
        )
        .unwrap(),
        ArtifactId::new(format!("proposal-{number}")).unwrap(),
        vec![citation()],
    )
    .unwrap()
}

fn run_config_artifact(number: u8, binding_digest: Sha256Digest) -> Vec<u8> {
    canonical_agent_run_config_artifact(&bound_run_request(number, binding_digest)).unwrap()
}

fn bound_run_request(number: u8, binding_digest: Sha256Digest) -> BoundAgentRunRequest {
    let task_id = TaskId::new("task-1").unwrap();
    let agent_id = format!("agent-{number}");
    let role = "reviewer".to_owned();
    let manifest_digest = digest(b"{}");
    let executable_digest = Some(digest(format!("executable-{number}").as_bytes()));
    let context_digest = digest(b"context");
    let policy_digest = digest(b"policy");
    BoundAgentRunRequest {
        run_id: RunId::new(format!("run-{number}")).unwrap(),
        task_id: task_id.clone(),
        agent_id: agent_id.clone(),
        role: role.clone(),
        phase: "ParallelAnalysis".to_owned(),
        idempotency_key: format!("run-key-{number}"),
        context: BoundEffectiveContext {
            context_package_id: format!("context-{number}"),
            task_id: task_id.clone(),
            agent_id: agent_id.clone(),
            role: role.clone(),
            objective: "analyze".to_owned(),
            manifest_artifact_id: ArtifactId::new(format!("manifest-{number}")).unwrap(),
            effective_context_artifact_id: ArtifactId::new(format!("context-content-{number}"))
                .unwrap(),
            content_digest: context_digest.clone(),
            policy_snapshot_digest: policy_digest.clone(),
            prompt_template_version: "prompt.v1".to_owned(),
            retrieval_pipeline_version: "retrieval.v1".to_owned(),
            created_at: Timestamp::from_unix_seconds(1),
        },
        run_config: BoundRunConfig {
            run_config_artifact_id: ArtifactId::new(format!("run-config-{number}")).unwrap(),
            task_id: task_id.clone(),
            agent_id: agent_id.clone(),
            role,
            context_package_id: format!("context-{number}"),
            effective_context_artifact_id: ArtifactId::new(format!("context-content-{number}"))
                .unwrap(),
            effective_context_digest: context_digest,
            trust_tier: TrustTier::CoreAdapter,
            manifest_digest: manifest_digest.clone(),
            executable_digest: executable_digest.clone(),
            contract_version: "1.0".to_owned(),
            adapter_version: "adapter-1".to_owned(),
            provider_id: format!("provider-{number}"),
            model_id: format!("model-{number}"),
            generation_parameters: BoundGenerationParameters {
                canonical_json: b"{}".to_vec(),
                digest: manifest_digest.clone(),
            },
            prompt_template_version: "prompt.v1".to_owned(),
            response_schema_version: "message.v1".to_owned(),
            policy_snapshot_digest: policy_digest,
            limits: AgentRunLimits {
                deadline: Timestamp::from_unix_seconds(1_800_000_300),
                max_output_tokens: 8_000,
                max_tool_requests: 8,
                max_context_queries: 8,
                max_specialist_requests: 2,
            },
        },
        connection: BoundAgentConnection {
            connection_id: format!("connection-{number}"),
            agent_id,
            trust_tier: TrustTier::CoreAdapter,
            manifest_digest,
            executable_digest,
            contract_version: "1.0".to_owned(),
            adapter_version: "adapter-1".to_owned(),
            binding_digest,
        },
        supersedes_run_id: None,
    }
}

fn dispatch_plan(
    first_run: &str,
    second_run: &str,
    budget: DeliberationTaskBudget,
) -> DeliberationProposalDispatchPlan {
    let mut first = bound_run_request(1, connection_binding_digest(1));
    first.run_id = RunId::new(first_run).unwrap();
    first.idempotency_key = format!("dispatch:{first_run}");
    let mut second = bound_run_request(2, connection_binding_digest(2));
    second.run_id = RunId::new(second_run).unwrap();
    second.idempotency_key = format!("dispatch:{second_run}");
    DeliberationProposalDispatchPlan::new(
        DeliberationDispatchBinding::new(
            first,
            DeliberationRunAssignment::new(
                RunId::new(first_run).unwrap(),
                "agent-1",
                AgentFamilyKey::from_provider_model("provider-1", "model-1").unwrap(),
                ActorId::new("agent-1").unwrap(),
            )
            .unwrap(),
            100,
        )
        .unwrap(),
        DeliberationDispatchBinding::new(
            second,
            DeliberationRunAssignment::new(
                RunId::new(second_run).unwrap(),
                "agent-2",
                AgentFamilyKey::from_provider_model("provider-2", "model-2").unwrap(),
                ActorId::new("agent-2").unwrap(),
            )
            .unwrap(),
            100,
        )
        .unwrap(),
        budget,
    )
    .unwrap()
}

fn phase_dispatch_set(
    run_id: &str,
    number: u8,
    budget: DeliberationTaskBudget,
) -> DeliberationPhaseDispatchSet {
    build_phase_dispatch_set(run_id, number, None, budget)
}

fn phase_dispatch_set_for_round(
    run_id: &str,
    number: u8,
    round: u32,
    budget: DeliberationTaskBudget,
) -> DeliberationPhaseDispatchSet {
    build_phase_dispatch_set(run_id, number, Some(round), budget)
}

fn build_phase_dispatch_set(
    run_id: &str,
    number: u8,
    round: Option<u32>,
    budget: DeliberationTaskBudget,
) -> DeliberationPhaseDispatchSet {
    let mut request = bound_run_request(number, connection_binding_digest(number));
    request.run_id = RunId::new(run_id).unwrap();
    request.idempotency_key = format!("dispatch:{run_id}");
    let assignment = DeliberationRunAssignment::new(
        RunId::new(run_id).unwrap(),
        format!("agent-{number}"),
        AgentFamilyKey::from_provider_model(
            &format!("provider-{number}"),
            &format!("model-{number}"),
        )
        .unwrap(),
        ActorId::new(format!("agent-{number}")).unwrap(),
    )
    .unwrap();
    let binding = DeliberationDispatchBinding::new(request, assignment.clone(), 100).unwrap();
    let task_id = TaskId::new("task-1").unwrap();
    let limits = DeliberationLimits::new(2, 2, 8, 2).unwrap();
    let authority = match round {
        Some(round) => DeliberationPhaseDispatchAuthority::for_round(
            task_id,
            Phase::CrossReview,
            round,
            vec![assignment],
            limits,
            budget,
        ),
        None => DeliberationPhaseDispatchAuthority::new(
            task_id,
            Phase::CrossReview,
            vec![assignment],
            limits,
            budget,
        ),
    }
    .unwrap();
    DeliberationPhaseDispatchSet::new(vec![binding], authority).unwrap()
}

fn connection_binding_digest(number: u8) -> Sha256Digest {
    let value = serde_json::json!({
        "schema": "agent-connection-binding.v1",
        "identity": {
            "connectionId": format!("connection-{number}"),
            "agentId": format!("agent-{number}"),
        },
        "manifestDigest": digest(b"{}").as_str(),
        "executableDigest": digest(format!("executable-{number}").as_bytes()).as_str(),
        "trustTier": "core_adapter",
        "contractVersion": "1.0",
        "adapterVersion": "adapter-1",
    });
    digest(&serde_json_canonicalizer::to_vec(&value).unwrap())
}

fn review_plan() -> ReviewPlan {
    review_plan_for_round(1)
}

fn review_plan_for_round(round: u32) -> ReviewPlan {
    ReviewPlan::new(
        DeliberationLimits::new(4, 2, 8, 2).unwrap(),
        vec![
            ReviewEdge::new("agent-2", ArtifactId::new("proposal-1").unwrap(), round).unwrap(),
            ReviewEdge::new("agent-1", ArtifactId::new("proposal-2").unwrap(), round).unwrap(),
        ],
    )
    .unwrap()
}

fn claim(verified: bool) -> MaterialClaim {
    let claim = MaterialClaim::new(
        "claim-a",
        "agent-1",
        ArtifactId::new("proposal-1").unwrap(),
        vec![citation()],
        VerificationMethod::SourceMatch,
    )
    .unwrap();
    if verified {
        claim.classify(ClaimVerification::Verified).unwrap()
    } else {
        claim
    }
}

fn decision(plan_artifact_id: &str, evidence: MaterialClaim) -> DecisionPackage {
    let rejected = RejectedApproach::new(
        DecisionApproach::new(
            "rejected-approach",
            ArtifactId::new("proposal-2").unwrap(),
            Vec::new(),
        )
        .unwrap(),
        "The verified evidence supports proposal 1.",
    )
    .unwrap();
    let dissent = Dissent::new(
        "dissent-agent-2",
        "agent-2",
        ArtifactId::new("proposal-2").unwrap(),
        "Agent 2 retains proposal 2 as the rejected alternative.",
    )
    .unwrap();
    DecisionPackage::new(
        DecisionApproach::new(
            "selected-approach",
            ArtifactId::new("proposal-1").unwrap(),
            vec![evidence.claim_id().to_owned()],
        )
        .unwrap(),
        vec![rejected],
        vec![evidence],
        vec![dissent],
        ArtifactId::new(plan_artifact_id).unwrap(),
    )
    .unwrap()
}

fn severe_objection_set() -> FinalObjectionSet {
    FinalObjectionSet::new(
        1,
        vec![FinalObjection::new(
            "agent-1",
            1,
            ObjectionSeverity::Severe,
            "The first decision needs another review round.",
            vec![citation()],
            Some("Re-run review and supersede the decision."),
        )
        .unwrap()],
    )
    .unwrap()
}

fn plan_approval_binding(
    snapshot: &DeliberationSnapshot,
    plan_artifact: &DeliberationArtifactRef,
) -> PlanApprovalBindingInput {
    PlanApprovalBindingInput {
        task_id: "task-1".to_owned(),
        plan_artifact_id: plan_artifact.artifact_id().as_str().to_owned(),
        plan_digest: plan_artifact.content_digest().as_str().to_owned(),
        plan_version: 2,
        base_commit: "a".repeat(40),
        allowed_paths: vec![PlanApprovalPathScopeV1 {
            root_capability: "workspace".to_owned(),
            patterns: vec!["crates/**".to_owned()],
        }],
        planned_tool_digests: vec![digest(b"planned-tool").as_str().to_owned()],
        verification_profile_digest: digest(b"verification-profile").as_str().to_owned(),
        risk_class: "medium".to_owned(),
        repository_fingerprint: digest(b"seed").as_str().to_owned(),
        policy_snapshot_digest: digest(b"policy").as_str().to_owned(),
        agent_id: "agent-1".to_owned(),
        agent_manifest_digest: digest(b"{}").as_str().to_owned(),
        actor_id: "core".to_owned(),
        task_version: snapshot.task_version + 1,
        workspace_version: snapshot.task_state.workspace_version().get(),
        fencing_epoch: snapshot.task_state.fencing_token().get() + 1,
        requested_at: "2026-08-09T00:00:00Z".to_owned(),
        expires_at: "2026-08-09T00:15:00Z".to_owned(),
    }
}

fn citation() -> EvidenceCitation {
    citation_with_symbol("entry")
}

fn citation_with_symbol(symbol: &str) -> EvidenceCitation {
    EvidenceCitation::new(
        SourceIdentity::new(
            ProjectId::new("project-1").unwrap(),
            "commit-1",
            "src/lib.rs",
            digest(b"source"),
        )
        .unwrap(),
        Some(LineRange::new(1, 2).unwrap()),
        Some(symbol),
        EvidenceFreshness::Current,
    )
    .unwrap()
}

fn count(connection: &Connection, table: &str) -> i64 {
    connection
        .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
            row.get(0)
        })
        .unwrap()
}

fn digest(bytes: &[u8]) -> Sha256Digest {
    Sha256Digest::new(format!("sha256:{:x}", Sha256::digest(bytes))).unwrap()
}
