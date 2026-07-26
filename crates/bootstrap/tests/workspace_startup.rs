use std::fs;
use std::path::{Path, PathBuf};

use git2::{IndexAddOption, Repository, Signature};
use local_agent_terminal_application::{
    AcquireLease, ArtifactRootMode, ArtifactWriteReservation, CanonicalEvidenceRef, Clock,
    CreateWorktree, ExecutorLeaseStore, ExpectedPresence, IdempotencyClass, InspectRepository,
    IntentTransition, ManagedWorktreePath, NewProject, NewTask, OperationIntent,
    OperationIntentStatus, PortError, ProjectSettings, RecoveryAction, RecoveryReason,
    RepositoryGateway, RepositoryInspectionRecord, ReservedArtifact, RiskLevel, StartupStateDto,
    TaskQuery, WorkspaceDashboardRequestDto, WorkspaceStateStore, WorktreeIntent, WorktreeState,
};
use local_agent_terminal_bootstrap::{Bootstrap, StartupConfig};
use local_agent_terminal_domain::{
    ActorId, ArtifactId, FencingToken, LeaseClaim, ProjectId, RunId, TaskBranch, TaskId,
    WorkspaceVersion, WorktreeId,
};
use local_agent_terminal_repository_git::GitRepositoryGateway;
use local_agent_terminal_storage_files::{ContentAddressedArtifactStore, JournaledArtifactWriter};
use local_agent_terminal_storage_sqlite::{CoreSystemRunRequest, SqliteStore};
use rusqlite::Connection;
use tempfile::TempDir;

const PROJECT_ID: &str = "project-1";
const TASK_ID: &str = "task-1";
const WORKTREE_ID: &str = "worktree-task-1";
const WORKTREE_BRANCH: &str = "codex/task-1";
const EMPTY_JSON_HASH: &str =
    "sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a";

#[test]
fn startup_exposes_workspace_runtime_only_after_ordered_recovery() {
    let fixture = TempDir::new().expect("tempdir");
    let app_data = fixture.path().join("app-data");
    let trusted_workspace_root = fixture.path().join("workspaces");
    fs::create_dir(&trusted_workspace_root).expect("workspace root");

    let bootstrap = Bootstrap::new(StartupConfig {
        app_data_dir: app_data,
        trusted_workspace_root,
        secret_values: Vec::new(),
    });

    assert_eq!(bootstrap.status().state, StartupStateDto::Ready);
    assert!(bootstrap.workspace_runtime().is_some());
    assert!(bootstrap
        .workspace_runtime()
        .expect("runtime")
        .recovery_candidates()
        .is_empty());
    let codes = bootstrap
        .local_diagnostics()
        .iter()
        .map(|diagnostic| diagnostic.code.as_str())
        .collect::<Vec<_>>();
    assert_eq!(
        codes,
        [
            "startup.recovery_lock.acquired",
            "startup.app_directories.validated",
            "startup.database.validated",
            "startup.artifacts.validated",
            "startup.artifacts.reconciled",
            "startup.leases.fenced",
            "startup.repositories.reconciled",
            "startup.intents.reconciled",
            "startup.ready",
        ]
    );
}

#[test]
fn startup_adopts_only_the_exact_durable_worktree() {
    let fixture = WorkspaceFixture::new();
    let intent = fixture.seed_started_intent("worktree.create", IdempotencyClass::Queryable);
    let original = fs::read(fixture.source.join("README.md")).expect("original checkout");
    let source_head = fixture.source_head();
    fixture.create_git_worktree(&intent);

    let bootstrap = fixture.start();

    assert_eq!(bootstrap.status().state, StartupStateDto::Ready);
    assert!(bootstrap
        .workspace_runtime()
        .expect("runtime")
        .recovery_candidates()
        .is_empty());
    assert_eq!(fixture.intent_status(), "succeeded");
    let database = SqliteStore::open(&fixture.database_path).expect("database");
    let task = database
        .task(&TaskId::new(TASK_ID).expect("task id"))
        .expect("task");
    assert_eq!(
        task.worktree.expect("worktree").state,
        WorktreeState::Present
    );
    assert_eq!(
        fs::read(fixture.source.join("README.md")).expect("original checkout"),
        original
    );
    assert_eq!(fixture.source_head(), source_head);
    assert!(fixture
        .workspace_root
        .join(WORKTREE_ID)
        .join("README.md")
        .is_file());
}

#[test]
fn startup_marks_retryable_only_after_authoritative_worktree_absence() {
    let fixture = WorkspaceFixture::new();
    fixture.seed_started_intent("worktree.create", IdempotencyClass::Queryable);
    let source_head = fixture.source_head();

    let bootstrap = fixture.start();

    assert_eq!(bootstrap.status().state, StartupStateDto::Ready);
    let candidates = bootstrap
        .workspace_runtime()
        .expect("runtime")
        .recovery_candidates();
    assert_eq!(candidates.len(), 1);
    assert_eq!(candidates[0].reason, RecoveryReason::AuthoritativeAbsence);
    assert!(candidates[0]
        .actions
        .contains(&RecoveryAction::RetryAfterAuthoritativeAbsence));
    assert_eq!(fixture.intent_status(), "interrupted");
    assert!(!fixture.workspace_root.join(WORKTREE_ID).exists());
    assert!(!fixture.branch_exists());
    assert_eq!(fixture.source_head(), source_head);
}

#[test]
fn startup_preserves_an_orphan_branch_as_a_specific_conflict() {
    let fixture = WorkspaceFixture::new();
    fixture.seed_started_intent("worktree.create", IdempotencyClass::Queryable);
    let branch_target = fixture.create_orphan_branch();

    let bootstrap = fixture.start();

    assert_eq!(bootstrap.status().state, StartupStateDto::Ready);
    let candidates = bootstrap
        .workspace_runtime()
        .expect("runtime")
        .recovery_candidates();
    assert_eq!(candidates.len(), 1);
    assert_eq!(candidates[0].reason, RecoveryReason::PresenceMismatch);
    assert!(!candidates[0]
        .actions
        .contains(&RecoveryAction::RetryAfterAuthoritativeAbsence));
    let dashboard = bootstrap
        .workspace_runtime()
        .expect("runtime")
        .get_workspace_dashboard(WorkspaceDashboardRequestDto {
            project_id: PROJECT_ID.to_owned(),
        })
        .expect("dashboard");
    assert_eq!(
        dashboard.tasks[0].recovery_candidates[0].reason,
        RecoveryReason::PresenceMismatch
    );
    assert_eq!(fixture.intent_status(), "started");
    assert_eq!(fixture.branch_target(), branch_target);
    assert!(!fixture.workspace_root.join(WORKTREE_ID).exists());
}

#[test]
fn startup_preserves_an_occupied_managed_path_without_creating_a_branch() {
    let fixture = WorkspaceFixture::new();
    fixture.seed_started_intent("worktree.create", IdempotencyClass::Queryable);
    let occupied = fixture.workspace_root.join(WORKTREE_ID);
    fs::create_dir(&occupied).expect("occupied path");
    fs::write(occupied.join("KEEP.txt"), b"preserve me").expect("sentinel");

    let bootstrap = fixture.start();

    assert_eq!(bootstrap.status().state, StartupStateDto::Ready);
    let candidates = bootstrap
        .workspace_runtime()
        .expect("runtime")
        .recovery_candidates();
    assert_eq!(candidates.len(), 1);
    assert_eq!(candidates[0].reason, RecoveryReason::PresenceMismatch);
    assert_eq!(fixture.intent_status(), "started");
    assert_eq!(
        fs::read(occupied.join("KEEP.txt")).expect("sentinel"),
        b"preserve me"
    );
    assert!(!fixture.branch_exists());
}

#[test]
fn startup_marks_unknown_operations_indeterminate_without_touching_git() {
    let fixture = WorkspaceFixture::new();
    fixture.seed_started_intent("future.unknown", IdempotencyClass::Queryable);
    let unavailable_source = fixture.root.path().join("source-unavailable");
    fs::rename(&fixture.source, &unavailable_source).expect("hide source repository");

    let bootstrap = fixture.start();

    assert_eq!(bootstrap.status().state, StartupStateDto::Ready);
    let candidates = bootstrap
        .workspace_runtime()
        .expect("runtime")
        .recovery_candidates();
    assert_eq!(candidates.len(), 1);
    assert_eq!(candidates[0].reason, RecoveryReason::UnknownOperation);
    assert!(!candidates[0]
        .actions
        .contains(&RecoveryAction::RetryAfterAuthoritativeAbsence));
    assert_eq!(fixture.intent_status(), "indeterminate");
    assert!(!fixture.workspace_root.join(WORKTREE_ID).exists());
    assert!(bootstrap.local_diagnostics().iter().any(|diagnostic| {
        diagnostic.code == "startup.repositories.reconciled"
            && diagnostic.detail.contains("scanned=0")
    }));
}

#[test]
fn startup_fences_every_preexisting_executor_lease_before_ready() {
    let fixture = WorkspaceFixture::new();
    fixture.seed_active_lease();

    let bootstrap = fixture.start();

    assert_eq!(bootstrap.status().state, StartupStateDto::Ready);
    let connection = Connection::open(&fixture.database_path).expect("database");
    let lease_status: String = connection
        .query_row(
            "SELECT status FROM executor_leases WHERE task_id = ?1",
            [TASK_ID],
            |row| row.get(0),
        )
        .expect("lease status");
    let fencing_epoch: i64 = connection
        .query_row(
            "SELECT fencing_epoch FROM tasks WHERE id = ?1",
            [TASK_ID],
            |row| row.get(0),
        )
        .expect("fencing epoch");
    assert_eq!(lease_status, "revoked");
    assert_eq!(fencing_epoch, 2);
    assert!(bootstrap.local_diagnostics().iter().any(|diagnostic| {
        diagnostic.code == "startup.leases.fenced" && diagnostic.detail.contains("fenced=1")
    }));
}

struct WorkspaceFixture {
    root: TempDir,
    app_data: PathBuf,
    database_path: PathBuf,
    workspace_root: PathBuf,
    source: PathBuf,
    locator: local_agent_terminal_application::RepositoryLocator,
    repository: local_agent_terminal_application::RepositorySnapshot,
}

impl WorkspaceFixture {
    fn new() -> Self {
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
                created_at: "2026-07-26T00:00:02Z".to_owned(),
            })
            .expect("task");
        drop(artifacts);
        drop(database);
        drop(gateway);

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

    fn start(&self) -> Bootstrap {
        Bootstrap::new(StartupConfig {
            app_data_dir: self.app_data.clone(),
            trusted_workspace_root: self.workspace_root.clone(),
            secret_values: Vec::new(),
        })
    }

    fn seed_started_intent(
        &self,
        operation_kind: &str,
        idempotency_class: IdempotencyClass,
    ) -> WorktreeIntent {
        let database = SqliteStore::open(&self.database_path).expect("database");
        let artifacts = ContentAddressedArtifactStore::open(self.app_data.join("artifacts"))
            .expect("artifact store");
        publish_artifact(
            &database,
            &artifacts,
            "artifact-worktree-request",
            Some(TaskId::new(TASK_ID).expect("task id")),
        );
        let intent = WorktreeIntent {
            operation: OperationIntent {
                id: "intent-worktree-1".to_owned(),
                task_id: TaskId::new(TASK_ID).expect("task id"),
                operation_kind: operation_kind.to_owned(),
                idempotency_class,
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
            worktree_id: WorktreeId::new(WORKTREE_ID).expect("worktree id"),
            repository_id: self.repository.repository_id.clone(),
            repository_identity: self.repository.stable_identity.clone(),
            branch: TaskBranch::new(WORKTREE_BRANCH).expect("branch"),
            base_commit: self.repository.base_commit.clone().expect("base commit"),
            target_path_display: format!("<managed-workspace>/{WORKTREE_ID}"),
            expected_presence: ExpectedPresence::Present,
        };
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
        intent
    }

    fn create_git_worktree(&self, intent: &WorktreeIntent) {
        let gateway =
            GitRepositoryGateway::open(&self.workspace_root, &[self.app_data.join("artifacts")])
                .expect("gateway");
        gateway
            .create_worktree(CreateWorktree {
                repository: self.locator.clone(),
                managed_path: ManagedWorktreePath {
                    trusted_root_id: gateway.trusted_root_id().to_owned(),
                    relative_leaf: PathBuf::from(intent.worktree_id.as_str()),
                    redacted_display: intent.target_path_display.clone(),
                },
                task_id: intent.operation.task_id.clone(),
                lease_claim: LeaseClaim::new(
                    intent.operation.task_id.clone(),
                    RunId::new("run-worktree-1").expect("run id"),
                    FencingToken::new(1).expect("token"),
                ),
                expected_workspace_version: WorkspaceVersion::new(0),
                worktree_id: intent.worktree_id.clone(),
                branch: intent.branch.clone(),
                base_commit: intent.base_commit.clone(),
            })
            .expect("worktree");
    }

    fn create_orphan_branch(&self) -> String {
        let repository = Repository::open(&self.source).expect("repository");
        let commit = repository
            .head()
            .expect("head")
            .peel_to_commit()
            .expect("commit");
        let branch = repository
            .branch(WORKTREE_BRANCH, &commit, false)
            .expect("orphan branch");
        branch.get().target().expect("target").to_string()
    }

    fn seed_active_lease(&self) {
        let database = SqliteStore::open(&self.database_path).expect("database");
        let artifacts = ContentAddressedArtifactStore::open(self.app_data.join("artifacts"))
            .expect("artifact store");
        for artifact_id in [
            "artifact-run-manifest",
            "artifact-run-content",
            "artifact-run-config",
        ] {
            publish_artifact(
                &database,
                &artifacts,
                artifact_id,
                Some(TaskId::new(TASK_ID).expect("task id")),
            );
        }
        database
            .ensure_core_system_run(CoreSystemRunRequest {
                run_id: RunId::new("run-lease-1").expect("run id"),
                task_id: TaskId::new(TASK_ID).expect("task id"),
                context_package_id: "context-lease-1".to_owned(),
                manifest_artifact_id: ArtifactId::new("artifact-run-manifest")
                    .expect("artifact id"),
                effective_content_artifact_id: ArtifactId::new("artifact-run-content")
                    .expect("artifact id"),
                run_config_artifact_id: ArtifactId::new("artifact-run-config")
                    .expect("artifact id"),
                content_hash: EMPTY_JSON_HASH.to_owned(),
                policy_snapshot_digest: EMPTY_JSON_HASH.to_owned(),
                connection_binding_digest: EMPTY_JSON_HASH.to_owned(),
                idempotency_key: "core-system-run:lease-1".to_owned(),
                created_at: "2026-07-26T00:00:05Z".to_owned(),
            })
            .expect("core run");
        let lease = database
            .acquire(AcquireLease {
                task_id: TaskId::new(TASK_ID).expect("task id"),
                holder_run_id: RunId::new("run-lease-1").expect("run id"),
                expected_fencing_epoch: 0,
                acquired_at: "2026-07-26T00:00:06Z".to_owned(),
                expires_at: "2026-07-26T01:00:06Z".to_owned(),
            })
            .expect("lease");
        assert_eq!(lease.token.get(), 1);
    }

    fn intent_status(&self) -> String {
        Connection::open(&self.database_path)
            .expect("database")
            .query_row(
                "SELECT status FROM operation_intents WHERE id = 'intent-worktree-1'",
                [],
                |row| row.get(0),
            )
            .expect("intent status")
    }

    fn source_head(&self) -> String {
        Repository::open(&self.source)
            .expect("repository")
            .head()
            .expect("head")
            .target()
            .expect("target")
            .to_string()
    }

    fn branch_exists(&self) -> bool {
        Repository::open(&self.source)
            .expect("repository")
            .find_reference(&format!("refs/heads/{WORKTREE_BRANCH}"))
            .is_ok()
    }

    fn branch_target(&self) -> String {
        Repository::open(&self.source)
            .expect("repository")
            .find_reference(&format!("refs/heads/{WORKTREE_BRANCH}"))
            .expect("branch")
            .target()
            .expect("target")
            .to_string()
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
