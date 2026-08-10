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
    ActorId, ArtifactId, Condition, FencingToken, OperationState, Phase, Sequence, Sha256Digest,
    TaskId, WorkflowState, WorkspaceVersion,
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
}

impl MutableAuthority {
    fn new(current: PlanApprovalCurrentAuthority) -> Self {
        Self {
            current: Mutex::new(current),
        }
    }

    fn set_repository_fingerprint(&self, repository_fingerprint: Sha256Digest) {
        self.current.lock().unwrap().repository_fingerprint = repository_fingerprint;
    }

    fn set_policy_snapshot_digest(&self, policy_snapshot_digest: Sha256Digest) {
        self.current.lock().unwrap().policy_snapshot_digest = policy_snapshot_digest;
    }
}

impl PlanApprovalCurrentAuthoritySource for MutableAuthority {
    fn current_authority(
        &self,
        _task_id: &TaskId,
    ) -> Result<PlanApprovalCurrentAuthority, PortError> {
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
                "INSERT INTO approvals (
                    id, task_id, approval_type, schema_version, operation_digest, status,
                    requested_at, resolved_at, resolved_by, expires_at, request_artifact_id,
                    invalidation_reason
                 ) VALUES (?1, 'task-1', 'plan', 'approval-digest.v1', ?2, 'pending', ?3,
                    NULL, NULL, ?4, ?5, NULL)",
                params![
                    self.approval.approval_id().as_str(),
                    self.approval.operation_digest().as_str(),
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
fn pending_plan_request_reloads_and_resolves_exactly_once_across_reopen() {
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

    ResolvePlanApproval::new(&store, &WithinWindow)
        .execute(resolve_input(&database, PlanApprovalAction::Approve))
        .unwrap();

    let reopened = database.store();
    let resolved = reopened
        .reload(database.approval.approval_id())
        .unwrap()
        .unwrap();
    assert_eq!(resolved.state, PlanApprovalState::Resolved);
    assert!(matches!(
        resolved.terminal,
        Some(PlanApprovalTerminal::Resolved {
            action: PlanApprovalAction::Approve,
            ref actor_id,
            ..
        }) if actor_id.as_str() == "actor-1"
    ));
    assert_eq!(
        database
            .connection()
            .query_row("SELECT phase FROM tasks WHERE id = 'task-1'", [], |row| {
                row.get::<_, String>(0)
            })
            .unwrap(),
        "Implementation"
    );
    assert!(ResolvePlanApproval::new(&reopened, &WithinWindow)
        .execute(resolve_input(&database, PlanApprovalAction::Approve))
        .is_err());
    assert_eq!(
        database
            .connection()
            .query_row(
                "SELECT COUNT(*) FROM events WHERE event_type = 'plan.approved'",
                [],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
        1
    );
}

#[test]
fn concurrent_plan_resolution_has_exactly_one_terminal_winner() {
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

    assert_eq!(outcomes.iter().filter(|outcome| outcome.is_ok()).count(), 1);
    assert_eq!(
        outcomes.iter().filter(|outcome| outcome.is_err()).count(),
        1
    );
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
    assert!(matches!(status.as_str(), "granted" | "denied"));
    assert_eq!(current_sequence, 9);
    assert_eq!(terminal_events, 1);
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
                repository_fingerprint
                    .as_str()
                    .strip_prefix("sha256:")
                    .unwrap(),
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
                manifest_digest, executable_digest, enabled, containment_verified,
                last_health_status, updated_at
             ) VALUES ('agent-1', 'Agent', 'in_process', 'core_adapter', '{}', ?1,
                NULL, 1, 1, 'healthy', '2026-08-09T00:00:00Z')",
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
    WorkflowState::new(
        Phase::AwaitingPlanApproval,
        Condition::Active,
        OperationState::None,
        Sequence::new(8),
        WorkspaceVersion::new(1),
        FencingToken::new(1).unwrap(),
    )
    .unwrap()
}

fn resolve_input(database: &TestDatabase, action: PlanApprovalAction) -> ResolvePlanApprovalInput {
    ResolvePlanApprovalInput {
        approval_id: database.approval.approval_id().clone(),
        displayed_digest: database.approval.operation_digest().clone(),
        expected_task_version: 8,
        actor_id: ActorId::new("actor-1").unwrap(),
        action,
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
