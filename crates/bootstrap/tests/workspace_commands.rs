use std::fs;

use git2::{IndexAddOption, Repository, Signature};
use local_agent_terminal_application::{
    select_initial_workflow, CreateTaskWorkspaceRequestDto, NewTask, OnboardRepositoryRequestDto,
    ProjectId, RecoveryReason, RiskLevel, TaskId, TaskLeaseState, TaskOutcomeMode,
    WorkspaceDashboardRequestDto, WorkspaceStateStore, WorktreeState,
};
use local_agent_terminal_bootstrap::{Bootstrap, StartupConfig};
use local_agent_terminal_storage_sqlite::SqliteStore;
use rusqlite::Connection;
use tempfile::TempDir;

#[test]
fn typed_workspace_commands_create_an_isolated_worktree_without_serializing_paths() {
    let root = TempDir::new().unwrap();
    let source = root.path().join("source");
    fs::create_dir(&source).unwrap();
    commit_repository(&source);
    let bootstrap = Bootstrap::new(StartupConfig {
        app_data_dir: root.path().join("app-data"),
        trusted_workspace_root: root.path().join("managed-workspaces"),
        secret_values: Vec::new(),
        openai: None,
        anthropic: None,
    });
    let runtime = bootstrap.workspace_runtime().unwrap();

    let project = runtime
        .onboard_repository(OnboardRepositoryRequestDto {
            project_id: "project-1".to_owned(),
            name: "Workspace commands".to_owned(),
            repository_path: source.to_string_lossy().into_owned(),
        })
        .unwrap();
    let serialized = serde_json::to_string(&project).unwrap();
    assert!(!serialized.contains(&source.to_string_lossy().into_owned()));
    assert!(!serialized.contains("repositoryPath"));

    let task = runtime
        .create_task_workspace(CreateTaskWorkspaceRequestDto {
            project_id: "project-1".to_owned(),
            task_id: "task-1".to_owned(),
            title: "Create an isolated worktree".to_owned(),
            objective: "Keep the original checkout unchanged".to_owned(),
            risk_level: "low".to_owned(),
        })
        .unwrap();
    assert_eq!(
        task.worktree.as_ref().unwrap().target_path_display,
        "<managed-workspace>/worktree-task-1"
    );
    assert_eq!(fs::read(source.join("README.md")).unwrap(), b"original\n");
    assert!(Repository::open(&source)
        .unwrap()
        .statuses(None)
        .unwrap()
        .is_empty());

    let dashboard = runtime
        .get_workspace_dashboard(WorkspaceDashboardRequestDto {
            project_id: "project-1".to_owned(),
        })
        .unwrap();
    assert_eq!(dashboard.tasks.len(), 1);
    assert!(!dashboard.tasks[0].timeline.is_empty());
}

#[test]
fn task_creation_rechecks_repository_health_before_persisting_a_task() {
    let root = TempDir::new().unwrap();
    let source = root.path().join("source");
    fs::create_dir(&source).unwrap();
    commit_repository(&source);
    let bootstrap = Bootstrap::new(StartupConfig {
        app_data_dir: root.path().join("app-data"),
        trusted_workspace_root: root.path().join("managed-workspaces"),
        secret_values: Vec::new(),
        openai: None,
        anthropic: None,
    });
    let runtime = bootstrap.workspace_runtime().unwrap();
    runtime
        .onboard_repository(OnboardRepositoryRequestDto {
            project_id: "project-1".to_owned(),
            name: "Workspace commands".to_owned(),
            repository_path: source.to_string_lossy().into_owned(),
        })
        .unwrap();
    fs::write(source.join("README.md"), b"dirty\n").unwrap();

    runtime
        .create_task_workspace(CreateTaskWorkspaceRequestDto {
            project_id: "project-1".to_owned(),
            task_id: "task-1".to_owned(),
            title: "Must not use stale repository health".to_owned(),
            objective: "Reject a newly dirty original checkout".to_owned(),
            risk_level: "low".to_owned(),
        })
        .expect_err("dirty repository must block task creation");

    let dashboard = runtime
        .get_workspace_dashboard(WorkspaceDashboardRequestDto {
            project_id: "project-1".to_owned(),
        })
        .unwrap();
    assert!(dashboard.tasks.is_empty());
    assert!(!root
        .path()
        .join("managed-workspaces")
        .join("worktree-task-1")
        .exists());
}

#[test]
fn exact_retry_resumes_after_the_task_record_but_before_the_worktree_intent() {
    let root = TempDir::new().unwrap();
    let source = root.path().join("source");
    let database_path = root.path().join("app-data/state.sqlite3");
    fs::create_dir(&source).unwrap();
    commit_repository(&source);
    let bootstrap = Bootstrap::new(StartupConfig {
        app_data_dir: root.path().join("app-data"),
        trusted_workspace_root: root.path().join("managed-workspaces"),
        secret_values: Vec::new(),
        openai: None,
        anthropic: None,
    });
    let runtime = bootstrap.workspace_runtime().unwrap();
    let project = runtime
        .onboard_repository(OnboardRepositoryRequestDto {
            project_id: "project-1".to_owned(),
            name: "Workspace commands".to_owned(),
            repository_path: source.to_string_lossy().into_owned(),
        })
        .unwrap();
    let request = CreateTaskWorkspaceRequestDto {
        project_id: "project-1".to_owned(),
        task_id: "task-1".to_owned(),
        title: "Resume exact task setup".to_owned(),
        objective: "Finish the durable intent after a process interruption".to_owned(),
        risk_level: "high".to_owned(),
    };
    SqliteStore::open(&database_path)
        .unwrap()
        .create_task(NewTask {
            task_id: TaskId::new("task-1").unwrap(),
            project_id: ProjectId::new("project-1").unwrap(),
            title: request.title.clone(),
            objective: request.objective.clone(),
            risk_level: RiskLevel::High,
            base_branch: project.repository.default_branch.unwrap(),
            base_commit: project.repository.base_commit.unwrap(),
            initial_workflow: select_initial_workflow(
                RiskLevel::High,
                TaskOutcomeMode::WorkspaceChange,
                "default",
            )
            .unwrap(),
            created_at: "2026-07-26T00:00:00Z".to_owned(),
        })
        .unwrap();

    let task = runtime.create_task_workspace(request.clone()).unwrap();
    assert_eq!(
        task.worktree.as_ref().unwrap().state,
        WorktreeState::Present
    );
    let repeated = runtime.create_task_workspace(request).unwrap();
    assert_eq!(
        repeated.worktree.as_ref().unwrap().state,
        WorktreeState::Present
    );
    let operation_count: i64 = Connection::open(database_path)
        .unwrap()
        .query_row(
            "SELECT COUNT(*) FROM operation_intents WHERE operation_kind = 'worktree.create'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(operation_count, 1);
}

#[test]
fn failed_git_creation_is_recoverable_and_revokes_the_executor() {
    let root = TempDir::new().unwrap();
    let source = root.path().join("source");
    let managed = root
        .path()
        .join("managed-workspaces")
        .join("worktree-task-1");
    fs::create_dir(&source).unwrap();
    commit_repository(&source);
    let bootstrap = Bootstrap::new(StartupConfig {
        app_data_dir: root.path().join("app-data"),
        trusted_workspace_root: root.path().join("managed-workspaces"),
        secret_values: Vec::new(),
        openai: None,
        anthropic: None,
    });
    let runtime = bootstrap.workspace_runtime().unwrap();
    runtime
        .onboard_repository(OnboardRepositoryRequestDto {
            project_id: "project-1".to_owned(),
            name: "Workspace commands".to_owned(),
            repository_path: source.to_string_lossy().into_owned(),
        })
        .unwrap();
    fs::create_dir_all(&managed).unwrap();
    fs::write(managed.join("keep.txt"), b"do not overwrite\n").unwrap();

    runtime
        .create_task_workspace(CreateTaskWorkspaceRequestDto {
            project_id: "project-1".to_owned(),
            task_id: "task-1".to_owned(),
            title: "Preserve a failed create".to_owned(),
            objective: "Leave enough durable state for explicit recovery".to_owned(),
            risk_level: "high".to_owned(),
        })
        .expect_err("occupied managed path must fail closed");

    let dashboard = runtime
        .get_workspace_dashboard(WorkspaceDashboardRequestDto {
            project_id: "project-1".to_owned(),
        })
        .unwrap();
    assert_eq!(dashboard.tasks.len(), 1);
    assert_eq!(dashboard.tasks[0].lease_state, TaskLeaseState::Revoked);
    assert_eq!(
        dashboard.tasks[0].recovery_candidates[0].reason,
        RecoveryReason::OutcomeIndeterminate
    );
    assert_eq!(
        fs::read(managed.join("keep.txt")).unwrap(),
        b"do not overwrite\n"
    );
    let status: String = Connection::open(root.path().join("app-data/state.sqlite3"))
        .unwrap()
        .query_row(
            "SELECT status FROM operation_intents WHERE operation_kind = 'worktree.create'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(status, "indeterminate");
}

#[test]
fn dashboard_poll_detects_a_real_out_of_band_workspace_mutation() {
    let root = TempDir::new().unwrap();
    let source = root.path().join("source");
    fs::create_dir(&source).unwrap();
    commit_repository(&source);
    let bootstrap = Bootstrap::new(StartupConfig {
        app_data_dir: root.path().join("app-data"),
        trusted_workspace_root: root.path().join("managed-workspaces"),
        secret_values: Vec::new(),
        openai: None,
        anthropic: None,
    });
    let runtime = bootstrap.workspace_runtime().unwrap();
    runtime
        .onboard_repository(OnboardRepositoryRequestDto {
            project_id: "project-1".to_owned(),
            name: "Workspace commands".to_owned(),
            repository_path: source.to_string_lossy().into_owned(),
        })
        .unwrap();
    runtime
        .create_task_workspace(CreateTaskWorkspaceRequestDto {
            project_id: "project-1".to_owned(),
            task_id: "task-1".to_owned(),
            title: "Detect external edits".to_owned(),
            objective: "Fence the writer before returning dashboard state".to_owned(),
            risk_level: "high".to_owned(),
        })
        .unwrap();
    Connection::open(root.path().join("app-data/state.sqlite3"))
        .unwrap()
        .execute(
            "UPDATE tasks SET phase = 'Implementation' WHERE id = 'task-1'",
            [],
        )
        .unwrap();
    fs::write(
        root.path()
            .join("managed-workspaces")
            .join("worktree-task-1")
            .join("README.md"),
        b"out-of-band\n",
    )
    .unwrap();

    let dashboard = runtime
        .get_workspace_dashboard(WorkspaceDashboardRequestDto {
            project_id: "project-1".to_owned(),
        })
        .unwrap();

    assert_eq!(dashboard.tasks[0].phase.as_str(), "WorkspaceDirty");
    assert_eq!(dashboard.tasks[0].workspace_version.get(), 1);
    assert_eq!(dashboard.tasks[0].lease_state, TaskLeaseState::Revoked);
}

fn commit_repository(root: &std::path::Path) {
    let repository = Repository::init(root).unwrap();
    fs::write(root.join("README.md"), b"original\n").unwrap();
    let mut index = repository.index().unwrap();
    index
        .add_all(["README.md"], IndexAddOption::DEFAULT, None)
        .unwrap();
    let tree_id = index.write_tree().unwrap();
    index.write().unwrap();
    let signature = Signature::now("fixture", "fixture@example.invalid").unwrap();
    let tree = repository.find_tree(tree_id).unwrap();
    repository
        .commit(Some("HEAD"), &signature, &signature, "initial", &tree, &[])
        .unwrap();
}
