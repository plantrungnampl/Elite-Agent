use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Barrier};
use std::thread;

use local_agent_terminal_application::{
    AcquireLease, ArtifactJournal, ArtifactJournalStatus, ArtifactJournalTransition,
    ArtifactRootMode, ArtifactWriteReservation, CanonicalEvidenceRef, ExecutorLeaseStore,
    ExpectedPresence, IdempotencyClass, LeaseState, NewProject, NewTask, OperationIntent,
    OperationIntentStatus, ProjectSettings, RepositoryHealth, RepositoryInspectionRecord,
    RepositorySnapshot, RevokeLease, RiskLevel, SafeErrorClassification, TaskQuery,
    WorkspaceMutationRequest, WorkspaceMutationStore, WorkspaceRecoveryStore, WorkspaceStateStore,
    WorktreeIntent, WorktreeSnapshot, WorktreeState,
};
use local_agent_terminal_domain::{
    ActorId, ArtifactId, FencingToken, GitObjectId, LeaseClaim, ProjectId, RepositoryId, RunId,
    TaskBranch, TaskId, WorkspaceFingerprint, WorktreeId,
};
use local_agent_terminal_storage_sqlite::{CoreSystemRunRequest, SqliteStore};
use rusqlite::{params, Connection};

static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);
const SHA1: &str = "1111111111111111111111111111111111111111";
const DIGEST_A: &str = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const DIGEST_B: &str = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const SHA1_POST: &str = "2222222222222222222222222222222222222222";
const DIGEST_C: &str = "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";

struct TempDatabase {
    directory: PathBuf,
    path: PathBuf,
}

impl TempDatabase {
    fn new() -> Self {
        let directory = std::env::temp_dir().join(format!(
            "local-agent-terminal-workspace-recovery-{}-{}",
            std::process::id(),
            NEXT_TEMP.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&directory).unwrap();
        Self {
            path: directory.join("state.sqlite3"),
            directory,
        }
    }
}

impl Drop for TempDatabase {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.directory);
    }
}

fn fingerprint() -> WorkspaceFingerprint {
    WorkspaceFingerprint::new(GitObjectId::new(SHA1).unwrap(), DIGEST_A, DIGEST_B).unwrap()
}

fn post_fingerprint() -> WorkspaceFingerprint {
    WorkspaceFingerprint::new(GitObjectId::new(SHA1_POST).unwrap(), DIGEST_B, DIGEST_C).unwrap()
}

fn repository_snapshot() -> RepositorySnapshot {
    RepositorySnapshot {
        repository_id: RepositoryId::new("repository-1").unwrap(),
        health: RepositoryHealth::Healthy,
        stable_identity: "repository-identity-1".to_owned(),
        default_branch: Some(TaskBranch::new("main").unwrap()),
        base_commit: Some(GitObjectId::new(SHA1).unwrap()),
        original_checkout: local_agent_terminal_application::OriginalCheckoutState::Clean,
        hazards: Vec::new(),
        fingerprint: fingerprint(),
    }
}

fn new_project() -> NewProject {
    NewProject {
        project_id: ProjectId::new("project-1").unwrap(),
        name: "Local Agent Terminal".to_owned(),
        repository: repository_snapshot(),
        repository_path: "D:/source/project".to_owned(),
        settings: ProjectSettings {
            policy_profile_id: "default".to_owned(),
            artifact_root_mode: ArtifactRootMode::ApplicationData,
            artifact_root_path: "D:/application-data/artifacts".to_owned(),
        },
        created_at: "2026-07-26T00:00:00Z".to_owned(),
    }
}

fn new_task() -> NewTask {
    NewTask {
        task_id: TaskId::new("task-1").unwrap(),
        project_id: ProjectId::new("project-1").unwrap(),
        title: "Repository recovery".to_owned(),
        objective: "Keep the original checkout unchanged".to_owned(),
        risk_level: RiskLevel::High,
        base_branch: TaskBranch::new("main").unwrap(),
        base_commit: GitObjectId::new(SHA1).unwrap(),
        created_at: "2026-07-26T00:00:01Z".to_owned(),
    }
}

fn reservation(
    operation_id: &str,
    artifact_id: &str,
    task_id: Option<TaskId>,
) -> ArtifactWriteReservation {
    ArtifactWriteReservation {
        operation_id: operation_id.to_owned(),
        artifact: local_agent_terminal_application::ReservedArtifact {
            artifact_id: artifact_id.to_owned(),
            task_id,
            project_id: "project-1".to_owned(),
            artifact_type: "canonical_json".to_owned(),
            logical_path: format!("evidence/{artifact_id}.json"),
            content_hash: DIGEST_A.to_owned(),
            storage_key: format!("objects/aa/{artifact_id}"),
            size_bytes: 2,
            mime_type: Some("application/json".to_owned()),
            created_by_type: "core".to_owned(),
            created_by_id: "workspace-coordinator".to_owned(),
            created_at: "2026-07-26T00:00:02Z".to_owned(),
            supersedes: None,
        },
        temp_name: format!(".{artifact_id}.tmp"),
        created_at: "2026-07-26T00:00:02Z".to_owned(),
    }
}

fn publish_artifact(
    store: &SqliteStore,
    operation_id: &str,
    artifact_id: &str,
    task_id: Option<TaskId>,
) -> CanonicalEvidenceRef {
    store
        .reserve(reservation(operation_id, artifact_id, task_id.clone()))
        .unwrap();
    for (expected_status, next_status, completed_at) in [
        (
            ArtifactJournalStatus::Intent,
            ArtifactJournalStatus::Staging,
            None,
        ),
        (
            ArtifactJournalStatus::Staging,
            ArtifactJournalStatus::Renamed,
            None,
        ),
        (
            ArtifactJournalStatus::Renamed,
            ArtifactJournalStatus::Completed,
            Some("2026-07-26T00:00:03Z".to_owned()),
        ),
    ] {
        store
            .transition(ArtifactJournalTransition {
                operation_id: operation_id.to_owned(),
                expected_status,
                next_status,
                updated_at: "2026-07-26T00:00:03Z".to_owned(),
                completed_at,
                error: None,
            })
            .unwrap();
    }
    CanonicalEvidenceRef {
        artifact_id: ArtifactId::new(artifact_id).unwrap(),
        content_hash: DIGEST_A.to_owned(),
        storage_key: format!("objects/aa/{artifact_id}"),
        size_bytes: 2,
        project_id: ProjectId::new("project-1").unwrap(),
        task_id,
    }
}

fn seed_project(store: &SqliteStore) {
    store.create_project(new_project()).unwrap();
    let evidence = publish_artifact(
        store,
        "artifact-operation-repository",
        "artifact-repository",
        None,
    );
    store
        .record_repository_inspection(RepositoryInspectionRecord {
            project_id: ProjectId::new("project-1").unwrap(),
            repository: repository_snapshot(),
            evidence,
            actor_id: ActorId::new("workspace-coordinator").unwrap(),
            correlation_id: "correlation-repository".to_owned(),
            observed_at: "2026-07-26T00:00:04Z".to_owned(),
        })
        .unwrap();
}

fn seed_task(store: &SqliteStore) {
    seed_project(store);
    store.create_task(new_task()).unwrap();
}

fn operation_intent() -> OperationIntent {
    OperationIntent {
        id: "intent-worktree-1".to_owned(),
        task_id: TaskId::new("task-1").unwrap(),
        operation_kind: "worktree.create".to_owned(),
        idempotency_class: IdempotencyClass::Queryable,
        idempotency_key: "worktree:create:task-1".to_owned(),
        canonical_request_artifact_id: ArtifactId::new("artifact-worktree-request").unwrap(),
        operation_digest: DIGEST_A.to_owned(),
        status: OperationIntentStatus::Pending,
        executor_fencing_token: None,
        attempt_count: 0,
        created_at: "2026-07-26T00:00:05Z".to_owned(),
        updated_at: "2026-07-26T00:00:05Z".to_owned(),
    }
}

fn worktree_intent() -> WorktreeIntent {
    WorktreeIntent {
        operation: operation_intent(),
        worktree_id: WorktreeId::new("worktree-1").unwrap(),
        repository_id: RepositoryId::new("repository-1").unwrap(),
        repository_identity: "repository-identity-1".to_owned(),
        branch: TaskBranch::new("codex/task-1").unwrap(),
        base_commit: GitObjectId::new(SHA1).unwrap(),
        target_path_display: "<workspace>/task-1".to_owned(),
        expected_presence: ExpectedPresence::Present,
    }
}

#[test]
fn project_onboarding_persists_identity_health_and_canonical_evidence() {
    let database = TempDatabase::new();
    let store = SqliteStore::open(&database.path).unwrap();

    seed_project(&store);

    let dashboard = store
        .dashboard(&ProjectId::new("project-1").unwrap())
        .unwrap();
    assert_eq!(dashboard.repository, repository_snapshot());
    assert!(dashboard.tasks.is_empty());

    let connection = Connection::open(&database.path).unwrap();
    let project: (String, String, String, String) = connection
        .query_row(
            "SELECT repository_path, repository_identity, policy_profile_id, artifact_root_path
             FROM projects WHERE id = 'project-1'",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .unwrap();
    assert_eq!(
        project,
        (
            "D:/source/project".to_owned(),
            "repository-identity-1".to_owned(),
            "default".to_owned(),
            "D:/application-data/artifacts".to_owned(),
        )
    );
    let event: (String, String) = connection
        .query_row(
            "SELECT event_type, payload_json FROM events
             WHERE stream_id = 'project:project-1' ORDER BY sequence DESC LIMIT 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(event.0, "repository.inspected");
    assert!(event
        .1
        .contains("\"evidenceArtifactId\":\"artifact-repository\""));
}

#[test]
fn pending_onboarding_is_queryable_and_exact_project_retry_is_idempotent() {
    let database = TempDatabase::new();
    let store = SqliteStore::open(&database.path).unwrap();
    let request = new_project();

    let first = store.create_project(request.clone()).unwrap();
    let pending = store.recovery_projects().unwrap();

    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].project_id, request.project_id);
    assert_eq!(pending[0].repository_path, request.repository_path);
    assert_eq!(pending[0].repository, request.repository);
    assert_eq!(store.create_project(request.clone()).unwrap(), first);

    let mut conflicting = request;
    conflicting.name = "A different project".to_owned();
    assert_eq!(
        store
            .create_project(conflicting)
            .unwrap_err()
            .safe_classification(),
        SafeErrorClassification::Conflict
    );

    let connection = Connection::open(&database.path).unwrap();
    let (count, payload): (i64, String) = connection
        .query_row(
            "SELECT COUNT(*), payload_json FROM events
             WHERE stream_id = 'project:project-1' AND event_type = 'project.created'",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    let payload: serde_json::Value = serde_json::from_str(&payload).unwrap();
    assert_eq!(count, 1);
    assert_eq!(payload["onboardingStatus"], "pending");
    assert_eq!(payload["projectId"], "project-1");
    assert_eq!(payload["name"], "Local Agent Terminal");
    assert_eq!(payload["repositoryPath"], "D:/source/project");
    assert_eq!(
        payload["repository"]["stableIdentity"],
        "repository-identity-1"
    );
    assert_eq!(payload["settings"]["policyProfileId"], "default");
}

#[test]
fn exact_repository_inspection_retry_reuses_one_completion_event() {
    let database = TempDatabase::new();
    let store = SqliteStore::open(&database.path).unwrap();
    store.create_project(new_project()).unwrap();
    let evidence = publish_artifact(
        &store,
        "artifact-operation-repository",
        "artifact-repository",
        None,
    );
    let inspection = RepositoryInspectionRecord {
        project_id: ProjectId::new("project-1").unwrap(),
        repository: repository_snapshot(),
        evidence,
        actor_id: ActorId::new("workspace-coordinator").unwrap(),
        correlation_id: "correlation-repository".to_owned(),
        observed_at: "2026-07-26T00:00:04Z".to_owned(),
    };

    let first = store
        .record_repository_inspection(inspection.clone())
        .unwrap();
    assert_eq!(
        store.record_repository_inspection(inspection).unwrap(),
        first
    );

    let connection = Connection::open(&database.path).unwrap();
    let count: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM events
             WHERE stream_id = 'project:project-1'
               AND event_type = 'repository.inspected'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(count, 1);
}

#[test]
fn task_intent_requires_available_evidence_and_is_durable_before_git() {
    let database = TempDatabase::new();
    let store = SqliteStore::open(&database.path).unwrap();
    seed_task(&store);

    store
        .reserve(reservation(
            "artifact-operation-worktree",
            "artifact-worktree-request",
            Some(TaskId::new("task-1").unwrap()),
        ))
        .unwrap();
    assert_eq!(
        store
            .begin_worktree_intent(worktree_intent())
            .unwrap_err()
            .safe_classification(),
        local_agent_terminal_application::SafeErrorClassification::IntegrityFailure
    );
    for (expected_status, next_status, completed_at) in [
        (
            ArtifactJournalStatus::Intent,
            ArtifactJournalStatus::Staging,
            None,
        ),
        (
            ArtifactJournalStatus::Staging,
            ArtifactJournalStatus::Renamed,
            None,
        ),
        (
            ArtifactJournalStatus::Renamed,
            ArtifactJournalStatus::Completed,
            Some("2026-07-26T00:00:06Z".to_owned()),
        ),
    ] {
        store
            .transition(ArtifactJournalTransition {
                operation_id: "artifact-operation-worktree".to_owned(),
                expected_status,
                next_status,
                updated_at: "2026-07-26T00:00:06Z".to_owned(),
                completed_at,
                error: None,
            })
            .unwrap();
    }

    let intent = store.begin_worktree_intent(worktree_intent()).unwrap();
    assert_eq!(intent.status, OperationIntentStatus::Pending);
    assert_eq!(
        store.begin_worktree_intent(worktree_intent()).unwrap(),
        intent
    );

    let connection = Connection::open(&database.path).unwrap();
    let projection: (String, String, i64) = connection
        .query_row(
            "SELECT task_branch, worktree_path, current_sequence
             FROM tasks WHERE id = 'task-1'",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap();
    assert_eq!(
        projection,
        (
            "codex/task-1".to_owned(),
            "<workspace>/task-1".to_owned(),
            2,
        )
    );
    let durable: (String, String, String) = connection
        .query_row(
            "SELECT i.status, i.idempotency_class, e.event_type
             FROM operation_intents i
             JOIN events e ON json_extract(e.payload_json, '$.intentId') = i.id
             WHERE i.id = 'intent-worktree-1'",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap();
    assert_eq!(
        durable,
        (
            "pending".to_owned(),
            "queryable".to_owned(),
            "worktree.intent.recorded".to_owned(),
        )
    );
}

fn core_run_request(run: &str, suffix: &str) -> CoreSystemRunRequest {
    CoreSystemRunRequest {
        run_id: RunId::new(run).unwrap(),
        task_id: TaskId::new("task-1").unwrap(),
        context_package_id: format!("context-{suffix}"),
        manifest_artifact_id: ArtifactId::new(format!("artifact-manifest-{suffix}")).unwrap(),
        effective_content_artifact_id: ArtifactId::new(format!("artifact-content-{suffix}"))
            .unwrap(),
        run_config_artifact_id: ArtifactId::new(format!("artifact-run-config-{suffix}")).unwrap(),
        content_hash: DIGEST_A.to_owned(),
        policy_snapshot_digest: DIGEST_A.to_owned(),
        connection_binding_digest: DIGEST_B.to_owned(),
        idempotency_key: format!("core-system-run:{suffix}"),
        created_at: "2026-07-26T00:00:07Z".to_owned(),
    }
}

fn seed_core_run(store: &SqliteStore, run: &str, suffix: &str) {
    for kind in ["manifest", "content", "run-config"] {
        publish_artifact(
            store,
            &format!("artifact-operation-{kind}-{suffix}"),
            &format!("artifact-{kind}-{suffix}"),
            Some(TaskId::new("task-1").unwrap()),
        );
    }
    store
        .ensure_core_system_run(core_run_request(run, suffix))
        .unwrap();
}

fn mutation_request(store: &SqliteStore) -> WorkspaceMutationRequest {
    let pre = publish_artifact(
        store,
        "artifact-operation-pre",
        "artifact-pre",
        Some(TaskId::new("task-1").unwrap()),
    );
    let post = publish_artifact(
        store,
        "artifact-operation-post",
        "artifact-post",
        Some(TaskId::new("task-1").unwrap()),
    );
    WorkspaceMutationRequest {
        task_id: TaskId::new("task-1").unwrap(),
        expected_sequence: local_agent_terminal_domain::Sequence::new(2),
        claim: LeaseClaim::new(
            TaskId::new("task-1").unwrap(),
            RunId::new("run-1").unwrap(),
            FencingToken::new(1).unwrap(),
        ),
        pre_fingerprint: fingerprint(),
        post_fingerprint: post_fingerprint(),
        pre_evidence: pre,
        post_evidence: post,
        actor_id: ActorId::new("workspace-monitor").unwrap(),
        correlation_id: "correlation-mutation".to_owned(),
    }
}

fn seed_mutation_state(path: &Path, store: &SqliteStore) {
    seed_task(store);
    seed_core_run(store, "run-1", "one");
    store.acquire(acquire("run-1", 0)).unwrap();
    let connection = Connection::open(path).unwrap();
    connection
        .execute(
            "UPDATE tasks SET phase = 'Implementation', active_candidate_tree = ?1
             WHERE id = 'task-1'",
            [SHA1],
        )
        .unwrap();
    for (id, approval_type) in [
        ("approval-plan", "plan"),
        ("approval-tool", "tool"),
        ("approval-commit", "final_commit"),
    ] {
        connection
            .execute(
                "INSERT INTO approvals (
                    id, task_id, approval_type, schema_version, operation_digest, status,
                    requested_at, resolved_at, resolved_by, expires_at, request_artifact_id,
                    invalidation_reason
                 ) VALUES (?1, 'task-1', ?2, 'v1', ?3, 'pending', ?4, NULL, NULL, ?5, ?6, NULL)",
                params![
                    id,
                    approval_type,
                    DIGEST_A,
                    "2026-07-26T00:00:09Z",
                    "2026-07-27T00:00:00Z",
                    "artifact-repository",
                ],
            )
            .unwrap();
    }
}

fn acquire(run: &str, expected_fencing_epoch: u64) -> AcquireLease {
    AcquireLease {
        task_id: TaskId::new("task-1").unwrap(),
        holder_run_id: RunId::new(run).unwrap(),
        expected_fencing_epoch,
        acquired_at: "2026-07-26T00:00:08Z".to_owned(),
        expires_at: "2026-07-26T00:05:08Z".to_owned(),
    }
}

#[test]
fn core_system_run_satisfies_foreign_keys_and_one_lease_contender_wins() {
    let database = TempDatabase::new();
    let store = SqliteStore::open(&database.path).unwrap();
    seed_task(&store);
    seed_core_run(&store, "run-1", "one");
    seed_core_run(&store, "run-2", "two");
    let barrier = Arc::new(Barrier::new(3));

    let contenders: Vec<_> = ["run-1", "run-2"]
        .into_iter()
        .map(|run| {
            let store = store.clone();
            let barrier = Arc::clone(&barrier);
            thread::spawn(move || {
                barrier.wait();
                store.acquire(acquire(run, 0))
            })
        })
        .collect();
    barrier.wait();
    let outcomes: Vec<_> = contenders
        .into_iter()
        .map(|thread| thread.join().unwrap())
        .collect();

    assert_eq!(outcomes.iter().filter(|outcome| outcome.is_ok()).count(), 1);
    let winner = outcomes.into_iter().find_map(Result::ok).unwrap();
    assert_eq!(winner.token.get(), 1);
    assert_eq!(winner.state, LeaseState::Active);

    let connection = Connection::open(&database.path).unwrap();
    assert_eq!(
        connection
            .query_row(
                "SELECT COUNT(*) FROM agent_runs WHERE id IN ('run-1', 'run-2')",
                [],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
        2
    );
    assert_eq!(
        connection
            .query_row(
                "SELECT fencing_epoch FROM tasks WHERE id = 'task-1'",
                [],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
        1
    );
    store
        .ensure_core_system_run(core_run_request("run-1", "one"))
        .unwrap();
    assert_eq!(
        connection
            .query_row(
                "SELECT COUNT(*) FROM agent_runs WHERE id = 'run-1'",
                [],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
        1
    );
}

#[test]
fn lease_replacement_increments_token_and_stale_claim_cannot_write() {
    let database = TempDatabase::new();
    let store = SqliteStore::open(&database.path).unwrap();
    seed_task(&store);
    seed_core_run(&store, "run-1", "one");
    seed_core_run(&store, "run-2", "two");

    let first = store.acquire(acquire("run-1", 0)).unwrap();
    let stale_claim = LeaseClaim::new(
        first.task_id.clone(),
        first.holder_run_id.clone(),
        first.token,
    );
    store
        .revoke(RevokeLease {
            claim: stale_claim.clone(),
            revoked_at: "2026-07-26T00:01:00Z".to_owned(),
        })
        .unwrap();
    let replacement = store.acquire(acquire("run-2", 1)).unwrap();

    assert_eq!(replacement.token, FencingToken::new(2).unwrap());
    assert!(matches!(
        store.assert_current(stale_claim),
        Err(local_agent_terminal_application::PortError::StaleLease {
            current,
            supplied
        }) if current == FencingToken::new(2).unwrap()
            && supplied == FencingToken::new(1).unwrap()
    ));

    let connection = Connection::open(&database.path).unwrap();
    let lease: (String, i64, String) = connection
        .query_row(
            "SELECT holder_run_id, fencing_token, status
             FROM executor_leases WHERE task_id = 'task-1'",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap();
    assert_eq!(lease, ("run-2".to_owned(), 2, "active".to_owned()));

    let replacement_payload: String = connection
        .query_row(
            "SELECT payload_json FROM events
             WHERE stream_id = 'task-1' AND event_type = 'executor.lease.replaced'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert!(replacement_payload.contains("\"previousHolderRunId\":\"run-1\""));
    assert!(replacement_payload.contains("\"previousFencingToken\":1"));
}

#[test]
fn task_query_returns_sequence_order_without_external_rebuild_effects() {
    let database = TempDatabase::new();
    let store = SqliteStore::open(&database.path).unwrap();
    seed_task(&store);
    publish_artifact(
        &store,
        "artifact-operation-worktree",
        "artifact-worktree-request",
        Some(TaskId::new("task-1").unwrap()),
    );
    store.begin_worktree_intent(worktree_intent()).unwrap();

    let timeline = store.timeline(&TaskId::new("task-1").unwrap()).unwrap();
    assert_eq!(
        timeline
            .iter()
            .map(|entry| entry.sequence)
            .collect::<Vec<_>>(),
        [1, 2]
    );
    assert_eq!(timeline[0].event_type, "task.created");
    assert_eq!(timeline[1].event_type, "worktree.intent.recorded");

    let connection = Connection::open(&database.path).unwrap();
    assert_eq!(
        connection
            .query_row("SELECT COUNT(*) FROM operation_intents", [], |row| {
                row.get::<_, i64>(0)
            })
            .unwrap(),
        1
    );
}

#[test]
fn workspace_mutation_is_atomic_and_invalidates_candidate_approvals() {
    let database = TempDatabase::new();
    let store = SqliteStore::open(&database.path).unwrap();
    seed_mutation_state(&database.path, &store);

    let result = store
        .record_workspace_mutation(mutation_request(&store))
        .unwrap();
    assert_eq!(result.new_sequence.get(), 3);
    assert_eq!(
        result.task_state.phase(),
        local_agent_terminal_domain::Phase::WorkspaceDirty
    );
    assert_eq!(result.task_state.workspace_version().get(), 1);
    assert_eq!(result.task_state.fencing_token().get(), 2);
    assert_eq!(
        result.invalidated_approval_ids,
        vec![
            "approval-commit".to_owned(),
            "approval-plan".to_owned(),
            "approval-tool".to_owned()
        ]
    );
    assert_eq!(
        result.resume_target,
        Some(local_agent_terminal_domain::Phase::Implementation)
    );

    let connection = Connection::open(&database.path).unwrap();
    let task: (String, i64, i64, i64, Option<String>, i64) = connection
        .query_row(
            "SELECT phase, workspace_version, fencing_epoch, current_sequence,
                    active_candidate_tree, (SELECT COUNT(*) FROM approvals
                     WHERE task_id = 'task-1' AND status = 'invalidated')
             FROM tasks WHERE id = 'task-1'",
            [],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                ))
            },
        )
        .unwrap();
    assert_eq!(task, ("WorkspaceDirty".to_owned(), 1, 2, 3, None, 3));
    assert_eq!(
        connection
            .query_row(
                "SELECT status FROM executor_leases WHERE task_id = 'task-1'",
                [],
                |row| row.get::<_, String>(0),
            )
            .unwrap(),
        "revoked"
    );
    let payload: String = connection
        .query_row(
            "SELECT payload_json FROM events
             WHERE stream_id = 'task-1' AND event_type = 'workspace.mutated'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert!(payload.contains("\"preEvidenceArtifactId\":\"artifact-pre\""));
    assert!(payload.contains("\"postEvidenceArtifactId\":\"artifact-post\""));
    assert!(payload.contains("\"resumeTarget\":\"Implementation\""));
}

#[test]
fn mutation_rolls_back_event_projection_approvals_candidate_and_lease_together() {
    let database = TempDatabase::new();
    let store = SqliteStore::open(&database.path).unwrap();
    seed_mutation_state(&database.path, &store);
    let connection = Connection::open(&database.path).unwrap();
    connection
        .execute_batch(
            "CREATE TRIGGER fail_workspace_approval_invalidation
             BEFORE UPDATE OF status ON approvals
             WHEN NEW.status = 'invalidated'
             BEGIN
                 SELECT RAISE(ABORT, 'injected approval failure');
             END;",
        )
        .unwrap();
    drop(connection);

    let error = store
        .record_workspace_mutation(mutation_request(&store))
        .unwrap_err();
    assert!(matches!(
        error.safe_classification(),
        SafeErrorClassification::Internal | SafeErrorClassification::InvalidInput
    ));

    let connection = Connection::open(&database.path).unwrap();
    let state: (String, i64, i64, i64, Option<String>, String, i64) = connection
        .query_row(
            "SELECT
                t.phase, t.workspace_version, t.fencing_epoch, t.current_sequence,
                t.active_candidate_tree, l.status,
                (SELECT COUNT(*) FROM events WHERE event_type = 'workspace.mutated')
             FROM tasks t JOIN executor_leases l ON l.task_id = t.id
             WHERE t.id = 'task-1'",
            [],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    row.get(6)?,
                ))
            },
        )
        .unwrap();
    assert_eq!(
        state,
        (
            "Implementation".to_owned(),
            0,
            1,
            2,
            Some(SHA1.to_owned()),
            "active".to_owned(),
            0
        )
    );
    assert_eq!(
        connection
            .query_row(
                "SELECT COUNT(*) FROM approvals WHERE status = 'pending'",
                [],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
        3
    );
}

#[test]
fn stale_mutation_claim_is_rejected_before_projection_changes() {
    let database = TempDatabase::new();
    let store = SqliteStore::open(&database.path).unwrap();
    seed_mutation_state(&database.path, &store);
    let mut request = mutation_request(&store);
    request.claim = LeaseClaim::new(
        TaskId::new("task-1").unwrap(),
        RunId::new("run-1").unwrap(),
        FencingToken::new(99).unwrap(),
    );

    let error = store.record_workspace_mutation(request).unwrap_err();
    assert!(matches!(
        error,
        local_agent_terminal_application::PortError::StaleLease { .. }
    ));
    let connection = Connection::open(&database.path).unwrap();
    assert_eq!(
        connection
            .query_row(
                "SELECT COUNT(*) FROM events WHERE event_type = 'workspace.mutated'",
                [],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
        0
    );
}

#[test]
fn started_unknown_and_non_repeatable_intents_become_indeterminate_without_retry() {
    let database = TempDatabase::new();
    let store = SqliteStore::open(&database.path).unwrap();
    seed_task(&store);
    for (id, kind, class, key, artifact) in [
        (
            "intent-unknown",
            "mystery.operation",
            IdempotencyClass::Queryable,
            "mystery:1",
            "artifact-unknown",
        ),
        (
            "intent-non-repeatable",
            "worktree.create",
            IdempotencyClass::NonRepeatable,
            "non-repeatable:1",
            "artifact-non-repeatable",
        ),
    ] {
        publish_artifact(
            &store,
            &format!("operation-{id}"),
            artifact,
            Some(TaskId::new("task-1").unwrap()),
        );
        let mut intent = worktree_intent();
        intent.operation.id = id.to_owned();
        intent.operation.operation_kind = kind.to_owned();
        intent.operation.idempotency_class = class;
        intent.operation.idempotency_key = key.to_owned();
        intent.operation.canonical_request_artifact_id = ArtifactId::new(artifact).unwrap();
        store.begin_worktree_intent(intent.clone()).unwrap();
        store
            .transition_worktree_intent(local_agent_terminal_application::IntentTransition {
                intent_id: id.to_owned(),
                expected_status: OperationIntentStatus::Pending,
                next_status: OperationIntentStatus::Started,
                executor_fencing_token: Some(FencingToken::new(1).unwrap()),
                attempt_count: 1,
                updated_at: "2026-07-26T00:00:10Z".to_owned(),
                error: None,
                observed_fingerprint: None,
            })
            .unwrap();
    }

    let candidates = store.reconcile_intents().unwrap();
    assert_eq!(candidates.len(), 2);
    for candidate in &candidates {
        assert!(!candidate.actions.contains(
            &local_agent_terminal_application::RecoveryAction::RetryAfterAuthoritativeAbsence
        ));
    }
    assert!(candidates.iter().any(|candidate| {
        candidate.reason == local_agent_terminal_application::RecoveryReason::UnknownOperation
    }));
    assert!(candidates.iter().any(|candidate| {
        candidate.reason
            == local_agent_terminal_application::RecoveryReason::IndeterminateNonRepeatable
    }));
    let connection = Connection::open(&database.path).unwrap();
    assert_eq!(
        connection
            .query_row(
                "SELECT COUNT(*) FROM operation_intents
                 WHERE status = 'indeterminate'",
                [],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
        2
    );
}

#[test]
fn recovery_candidate_keeps_every_exact_worktree_identity_for_adoption() {
    let database = TempDatabase::new();
    let store = SqliteStore::open(&database.path).unwrap();
    seed_task(&store);
    publish_artifact(
        &store,
        "artifact-operation-worktree",
        "artifact-worktree-request",
        Some(TaskId::new("task-1").unwrap()),
    );
    let intent = worktree_intent();
    store.begin_worktree_intent(intent.clone()).unwrap();
    store
        .transition_worktree_intent(local_agent_terminal_application::IntentTransition {
            intent_id: intent.operation.id.clone(),
            expected_status: OperationIntentStatus::Pending,
            next_status: OperationIntentStatus::Started,
            executor_fencing_token: Some(FencingToken::new(1).unwrap()),
            attempt_count: 1,
            updated_at: "2026-07-26T00:00:10Z".to_owned(),
            error: None,
            observed_fingerprint: None,
        })
        .unwrap();

    let candidate = store
        .reconcile_intents()
        .unwrap()
        .into_iter()
        .next()
        .unwrap();
    let expected = candidate.expected_worktree.unwrap();
    let observed = WorktreeSnapshot {
        worktree_id: expected.worktree_id.clone(),
        repository_id: expected.repository_id.clone(),
        repository_identity: expected.repository_identity.clone(),
        task_id: expected.operation.task_id.clone(),
        branch: expected.branch.clone(),
        base_commit: expected.base_commit.clone(),
        target_path_display: expected.target_path_display.clone(),
        state: WorktreeState::Present,
        expected_presence: ExpectedPresence::Present,
        fingerprint: fingerprint(),
    };
    assert_eq!(
        expected.compare_observation(&observed),
        local_agent_terminal_application::WorktreeMatch::Exact
    );
    let mut conflicting = observed;
    conflicting.target_path_display = "<workspace>/other".to_owned();
    assert_eq!(
        expected.compare_observation(&conflicting),
        local_agent_terminal_application::WorktreeMatch::Conflict(
            local_agent_terminal_application::RecoveryReason::PathMismatch
        )
    );
}

#[test]
fn fencing_stale_leases_preserves_row_history_and_advances_epoch() {
    let database = TempDatabase::new();
    let store = SqliteStore::open(&database.path).unwrap();
    seed_task(&store);
    seed_core_run(&store, "run-1", "one");
    let lease = store.acquire(acquire("run-1", 0)).unwrap();

    let fenced = store.fence_stale().unwrap();
    assert_eq!(fenced.len(), 1);
    assert_eq!(fenced[0].token, lease.token);
    assert_eq!(fenced[0].state, LeaseState::Stale);
    assert!(matches!(
        store.assert_current(LeaseClaim::new(
            lease.task_id.clone(),
            lease.holder_run_id.clone(),
            lease.token,
        )),
        Err(local_agent_terminal_application::PortError::StaleLease { current, supplied })
            if current == FencingToken::new(2).unwrap()
                && supplied == FencingToken::new(1).unwrap()
    ));

    let connection = Connection::open(&database.path).unwrap();
    let row: (String, i64, i64) = connection
        .query_row(
            "SELECT status, fencing_token,
                    (SELECT fencing_epoch FROM tasks WHERE id = 'task-1')
             FROM executor_leases WHERE task_id = 'task-1'",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap();
    assert_eq!(row, ("revoked".to_owned(), 1, 2));
}
