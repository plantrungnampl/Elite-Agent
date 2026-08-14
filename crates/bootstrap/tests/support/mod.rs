use std::fs;
use std::path::{Path, PathBuf};

use git2::{IndexAddOption, Repository, Signature};
use local_agent_terminal_application::{
    select_initial_workflow, ArtifactRootMode, ArtifactWriteReservation, CanonicalEvidenceRef,
    Clock, CreateWorktree, ExpectedPresence, IdempotencyClass, InspectRepository, IntentTransition,
    ManagedWorktreePath, NewProject, NewTask, OperationIntent, OperationIntentStatus, PortError,
    ProjectSettings, RecoveryAction, RecoveryOperationIntent, RepositoryGateway,
    RepositoryInspectionRecord, ReservedArtifact, RiskLevel, TaskQuery, WorkspaceStateStore,
    WorktreeIntent,
};
use local_agent_terminal_bootstrap::{Bootstrap, StartupConfig};
use local_agent_terminal_domain::{
    ActorId, ArtifactId, FencingToken, LeaseClaim, ProjectId, RunId, TaskBranch, TaskId,
    TaskOutcomeMode, WorkspaceVersion, WorktreeId,
};
use local_agent_terminal_repository_git::GitRepositoryGateway;
use local_agent_terminal_storage_files::{ContentAddressedArtifactStore, JournaledArtifactWriter};
use local_agent_terminal_storage_sqlite::{CoreSystemRunRequest, SqliteStore};
use rusqlite::{params, Connection};
use tempfile::TempDir;

pub const PROJECT_ID: &str = "project-1";
pub const TASK_ID: &str = "task-1";
pub const WORKTREE_ID: &str = "worktree-task-1";
pub const WORKTREE_BRANCH: &str = "codex/task-1";
pub const EMPTY_JSON_HASH: &str =
    "sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a";

pub struct WorkspaceFixture {
    pub root: TempDir,
    pub app_data: PathBuf,
    pub database_path: PathBuf,
    pub workspace_root: PathBuf,
    pub source: PathBuf,
    pub locator: local_agent_terminal_application::RepositoryLocator,
    pub repository: local_agent_terminal_application::RepositorySnapshot,
}

impl WorkspaceFixture {
    pub fn new() -> Self {
        let root = TempDir::new().expect("tempdir");
        let app_data = root.path().join("app-data");
        let database_path = app_data.join("state.sqlite3");
        let workspace_root = root.path().join("managed-workspaces");
        let source = root.path().join("source");
        fs::create_dir(&app_data).expect("app data");
        fs::create_dir(&workspace_root).expect("workspace root");
        fs::create_dir(&source).expect("source");
        commit_repository(&source);

        let database = SqliteStore::open(&database_path).expect("database");
        let artifacts = ContentAddressedArtifactStore::open(app_data.join("artifacts"))
            .expect("artifact store");
        let gateway = GitRepositoryGateway::open(&workspace_root, &[app_data.join("artifacts")])
            .expect("gateway");
        let locator = gateway.locate(&source).expect("locator");
        let repository = gateway
            .inspect(InspectRepository {
                locator: locator.clone(),
            })
            .expect("repository inspection");
        let project_id = ProjectId::new(PROJECT_ID).expect("project id");
        database
            .create_project(NewProject {
                project_id: project_id.clone(),
                name: "Workspace recovery fixture".to_owned(),
                repository: repository.clone(),
                repository_path: locator.canonical_workdir.to_string_lossy().into_owned(),
                settings: ProjectSettings {
                    policy_profile_id: "default".to_owned(),
                    artifact_root_mode: ArtifactRootMode::ApplicationData,
                    artifact_root_path: app_data.join("artifacts").to_string_lossy().into_owned(),
                },
                created_at: "2026-07-26T00:00:00Z".to_owned(),
            })
            .expect("project");
        let evidence = publish_artifact(
            &database,
            &artifacts,
            "artifact-repository-inspection",
            None,
        );
        database
            .record_repository_inspection(RepositoryInspectionRecord {
                project_id: project_id.clone(),
                repository: repository.clone(),
                evidence,
                actor_id: ActorId::new("workspace-coordinator").expect("actor"),
                correlation_id: "repository-inspection".to_owned(),
                observed_at: "2026-07-26T00:00:01Z".to_owned(),
            })
            .expect("inspection record");
        database
            .create_task(NewTask {
                task_id: TaskId::new(TASK_ID).expect("task id"),
                project_id,
                title: "Recover worktree".to_owned(),
                objective: "Preserve every ambiguous Git state".to_owned(),
                risk_level: RiskLevel::High,
                base_branch: repository.default_branch.clone().expect("default branch"),
                base_commit: repository.base_commit.clone().expect("base commit"),
                initial_workflow: select_initial_workflow(
                    RiskLevel::High,
                    TaskOutcomeMode::WorkspaceChange,
                    "default",
                )
                .expect("initial workflow"),
                created_at: "2026-07-26T00:00:02Z".to_owned(),
            })
            .expect("task");

        Self {
            root,
            app_data,
            database_path,
            workspace_root,
            source,
            locator,
            repository,
        }
    }

    pub fn start(&self) -> Bootstrap {
        Bootstrap::new(StartupConfig {
            app_data_dir: self.app_data.clone(),
            trusted_workspace_root: self.workspace_root.clone(),
            secret_values: Vec::new(),
            openai: None,
            anthropic: None,
        })
    }

    pub fn seed_present_workspace(&self) {
        let database = SqliteStore::open(&self.database_path).expect("database");
        let artifacts = ContentAddressedArtifactStore::open(self.app_data.join("artifacts"))
            .expect("artifact store");
        let intent = self.worktree_intent(&database, &artifacts);
        database
            .begin_worktree_intent(intent.clone())
            .expect("worktree intent");
        database
            .transition_worktree_intent(IntentTransition {
                intent_id: intent.operation.id.clone(),
                expected_status: OperationIntentStatus::Pending,
                next_status: OperationIntentStatus::Started,
                executor_fencing_token: Some(FencingToken::new(1).expect("token")),
                attempt_count: 1,
                updated_at: "2026-07-26T00:00:04Z".to_owned(),
                error: None,
                observed_fingerprint: None,
            })
            .expect("started intent");
        let gateway =
            GitRepositoryGateway::open(&self.workspace_root, &[self.app_data.join("artifacts")])
                .expect("gateway");
        let created = gateway
            .create_worktree(CreateWorktree {
                repository: self.locator.clone(),
                managed_path: ManagedWorktreePath {
                    trusted_root_id: gateway.trusted_root_id().to_owned(),
                    relative_leaf: PathBuf::from(WORKTREE_ID),
                    redacted_display: intent.target_path_display.clone(),
                },
                task_id: TaskId::new(TASK_ID).expect("task id"),
                lease_claim: LeaseClaim::new(
                    TaskId::new(TASK_ID).expect("task id"),
                    RunId::new("fixture-worktree-run").expect("run"),
                    FencingToken::new(1).expect("token"),
                ),
                expected_workspace_version: WorkspaceVersion::new(0),
                worktree_id: WorktreeId::new(WORKTREE_ID).expect("worktree"),
                branch: TaskBranch::new(WORKTREE_BRANCH).expect("branch"),
                base_commit: self.repository.base_commit.clone().expect("base commit"),
            })
            .expect("worktree");
        database
            .transition_worktree_intent(IntentTransition {
                intent_id: intent.operation.id,
                expected_status: OperationIntentStatus::Started,
                next_status: OperationIntentStatus::Succeeded,
                executor_fencing_token: Some(FencingToken::new(1).expect("token")),
                attempt_count: 1,
                updated_at: "2026-07-26T00:00:05Z".to_owned(),
                error: None,
                observed_fingerprint: Some(created.fingerprint),
            })
            .expect("succeeded intent");
        self.seed_core_run(&database, &artifacts);
        self.seed_implementation_projection();
    }

    #[allow(dead_code)]
    pub fn seed_interrupted_workspace(&self) {
        let database = SqliteStore::open(&self.database_path).expect("database");
        let artifacts = ContentAddressedArtifactStore::open(self.app_data.join("artifacts"))
            .expect("artifact store");
        let intent = self.worktree_intent(&database, &artifacts);
        database
            .begin_worktree_intent(intent.clone())
            .expect("worktree intent");
        database
            .transition_worktree_intent(IntentTransition {
                intent_id: intent.operation.id.clone(),
                expected_status: OperationIntentStatus::Pending,
                next_status: OperationIntentStatus::Started,
                executor_fencing_token: Some(FencingToken::new(1).expect("token")),
                attempt_count: 1,
                updated_at: "2026-07-26T00:00:04Z".to_owned(),
                error: None,
                observed_fingerprint: None,
            })
            .expect("started intent");
        database
            .transition_worktree_intent(IntentTransition {
                intent_id: intent.operation.id,
                expected_status: OperationIntentStatus::Started,
                next_status: OperationIntentStatus::Interrupted,
                executor_fencing_token: Some(FencingToken::new(1).expect("token")),
                attempt_count: 1,
                updated_at: "2026-07-26T00:00:05Z".to_owned(),
                error: None,
                observed_fingerprint: None,
            })
            .expect("interrupted intent");
    }

    #[allow(dead_code)]
    pub fn seed_pending_discard_recovery(&self) {
        let database = SqliteStore::open(&self.database_path).expect("database");
        let artifacts = ContentAddressedArtifactStore::open(self.app_data.join("artifacts"))
            .expect("artifact store");
        let task_id = TaskId::new(TASK_ID).expect("task id");
        let task = database.task(&task_id).expect("task");
        let candidate_id = "intent-worktree-1".to_owned();
        let request_sequence = task.current_sequence.get();
        let artifact_id = format!("recovery-request-discard-{candidate_id}-{request_sequence}");
        let evidence = publish_artifact(&database, &artifacts, &artifact_id, Some(task_id.clone()));
        database
            .begin_recovery_intent(RecoveryOperationIntent {
                operation: OperationIntent {
                    id: format!("recovery-discard-{candidate_id}-{request_sequence}"),
                    task_id,
                    operation_kind: "workspace.recovery.discard".to_owned(),
                    idempotency_class: IdempotencyClass::Queryable,
                    idempotency_key: format!(
                        "workspace-recovery:discard:{candidate_id}:{request_sequence}"
                    ),
                    canonical_request_artifact_id: evidence.artifact_id,
                    operation_digest: evidence.content_hash,
                    status: OperationIntentStatus::Pending,
                    executor_fencing_token: None,
                    attempt_count: 0,
                    created_at: "2026-07-26T00:00:06Z".to_owned(),
                    updated_at: "2026-07-26T00:00:06Z".to_owned(),
                },
                candidate_id,
                action: RecoveryAction::DiscardExactWorktree,
                expected_workspace_version: WorkspaceVersion::new(0),
            })
            .expect("pending discard recovery");
    }

    pub fn managed_worktree(&self) -> PathBuf {
        self.workspace_root.join(WORKTREE_ID)
    }

    pub fn database(&self) -> Connection {
        Connection::open(&self.database_path).expect("database")
    }

    fn worktree_intent(
        &self,
        database: &SqliteStore,
        artifacts: &ContentAddressedArtifactStore,
    ) -> WorktreeIntent {
        publish_artifact(
            database,
            artifacts,
            "artifact-worktree-request",
            Some(TaskId::new(TASK_ID).expect("task id")),
        );
        WorktreeIntent {
            operation: OperationIntent {
                id: "intent-worktree-1".to_owned(),
                task_id: TaskId::new(TASK_ID).expect("task id"),
                operation_kind: "worktree.create".to_owned(),
                idempotency_class: IdempotencyClass::Queryable,
                idempotency_key: "worktree:create:task-1".to_owned(),
                canonical_request_artifact_id: ArtifactId::new("artifact-worktree-request")
                    .expect("artifact id"),
                operation_digest: EMPTY_JSON_HASH.to_owned(),
                status: OperationIntentStatus::Pending,
                executor_fencing_token: None,
                attempt_count: 0,
                created_at: "2026-07-26T00:00:03Z".to_owned(),
                updated_at: "2026-07-26T00:00:03Z".to_owned(),
            },
            worktree_id: WorktreeId::new(WORKTREE_ID).expect("worktree"),
            repository_id: self.repository.repository_id.clone(),
            repository_identity: self.repository.stable_identity.clone(),
            branch: TaskBranch::new(WORKTREE_BRANCH).expect("branch"),
            base_commit: self.repository.base_commit.clone().expect("base commit"),
            target_path_display: format!("<managed-workspace>/{WORKTREE_ID}"),
            expected_presence: ExpectedPresence::Present,
        }
    }

    fn seed_core_run(&self, database: &SqliteStore, artifacts: &ContentAddressedArtifactStore) {
        for suffix in ["lease-1", "lease-2"] {
            let manifest = format!("artifact-run-manifest-{suffix}");
            let content = format!("artifact-run-content-{suffix}");
            let config = format!("artifact-run-config-{suffix}");
            for artifact_id in [&manifest, &content, &config] {
                publish_artifact(
                    database,
                    artifacts,
                    artifact_id,
                    Some(TaskId::new(TASK_ID).expect("task id")),
                );
            }
            database
                .ensure_core_system_run(CoreSystemRunRequest {
                    run_id: RunId::new(format!("run-{suffix}")).expect("run"),
                    task_id: TaskId::new(TASK_ID).expect("task id"),
                    context_package_id: format!("context-{suffix}"),
                    manifest_artifact_id: ArtifactId::new(manifest).expect("artifact id"),
                    effective_content_artifact_id: ArtifactId::new(content).expect("artifact id"),
                    run_config_artifact_id: ArtifactId::new(config).expect("artifact id"),
                    content_hash: EMPTY_JSON_HASH.to_owned(),
                    policy_snapshot_digest: EMPTY_JSON_HASH.to_owned(),
                    connection_binding_digest: EMPTY_JSON_HASH.to_owned(),
                    idempotency_key: format!("core-system-run:{suffix}"),
                    created_at: "2026-07-26T00:00:06Z".to_owned(),
                })
                .expect("core run");
        }
    }

    fn seed_implementation_projection(&self) {
        let connection = self.database();
        connection
            .execute(
                "UPDATE tasks
                 SET phase = 'Implementation', active_candidate_tree = ?1
                 WHERE id = ?2",
                params![
                    self.repository
                        .base_commit
                        .as_ref()
                        .expect("base commit")
                        .as_str(),
                    TASK_ID
                ],
            )
            .expect("implementation projection");
        self.seed_open_approvals("", "2026-07-26T00:00:07Z");
    }

    pub fn seed_open_approvals(&self, suffix: &str, requested_at: &str) {
        let connection = self.database();
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
                     ) VALUES (
                        ?1, ?2, ?3, 'v1', ?4, 'pending', ?5, NULL, NULL, ?6, ?7, NULL
                    )",
                    params![
                        format!("{id}{suffix}"),
                        TASK_ID,
                        approval_type,
                        EMPTY_JSON_HASH,
                        requested_at,
                        "2099-07-26T01:00:07Z",
                        "artifact-worktree-request"
                    ],
                )
                .expect("approval");
        }
    }
}

fn commit_repository(root: &Path) {
    let repository = Repository::init(root).expect("init repository");
    fs::write(root.join("README.md"), b"original\n").expect("write fixture");
    let mut index = repository.index().expect("index");
    index
        .add_all(["README.md"], IndexAddOption::DEFAULT, None)
        .expect("add");
    let tree_id = index.write_tree().expect("tree");
    index.write().expect("write index");
    let signature = Signature::now("fixture", "fixture@example.invalid").expect("signature");
    let tree = repository.find_tree(tree_id).expect("tree");
    repository
        .commit(Some("HEAD"), &signature, &signature, "initial", &tree, &[])
        .expect("commit");
}

fn publish_artifact(
    database: &SqliteStore,
    artifacts: &ContentAddressedArtifactStore,
    artifact_id: &str,
    task_id: Option<TaskId>,
) -> CanonicalEvidenceRef {
    let reference = JournaledArtifactWriter::new(artifacts, database, &FixedClock)
        .write(
            ArtifactWriteReservation {
                operation_id: format!("write-{artifact_id}"),
                artifact: ReservedArtifact {
                    artifact_id: artifact_id.to_owned(),
                    task_id: task_id.clone(),
                    project_id: PROJECT_ID.to_owned(),
                    artifact_type: "canonical_json".to_owned(),
                    logical_path: format!("evidence/{artifact_id}.json"),
                    content_hash: EMPTY_JSON_HASH.to_owned(),
                    storage_key: format!("objects/44/{}", &EMPTY_JSON_HASH[7..]),
                    size_bytes: 2,
                    mime_type: Some("application/json".to_owned()),
                    created_by_type: "core".to_owned(),
                    created_by_id: "workspace-coordinator".to_owned(),
                    created_at: "2026-07-26T00:00:00Z".to_owned(),
                    supersedes: None,
                },
                temp_name: format!("{artifact_id}.tmp"),
                created_at: "2026-07-26T00:00:00Z".to_owned(),
            },
            b"{}",
        )
        .expect("published artifact");
    CanonicalEvidenceRef {
        artifact_id: ArtifactId::new(artifact_id).expect("artifact id"),
        content_hash: reference.content_hash,
        storage_key: reference.storage_key,
        size_bytes: reference.size_bytes,
        project_id: ProjectId::new(PROJECT_ID).expect("project id"),
        task_id,
    }
}

struct FixedClock;

impl Clock for FixedClock {
    fn now_utc(&self) -> Result<String, PortError> {
        Ok("2026-07-26T00:00:00Z".to_owned())
    }
}
