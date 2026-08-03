mod support;

use local_agent_terminal_application::{
    ConfirmDiscardWorkspaceRequestDto, RecoveryAction, RecoveryCandidateRequestDto,
    WorkspaceDashboardRequestDto, WorktreeState,
};

use support::{WorkspaceFixture, PROJECT_ID, TASK_ID};

#[test]
fn reconcile_reloads_authorization_and_records_a_durable_recovery_operation() {
    let fixture = WorkspaceFixture::new();
    assert!(fixture.root.path().is_dir());
    fixture.seed_interrupted_workspace();
    let bootstrap = fixture.start();
    let runtime = bootstrap.workspace_runtime().expect("runtime");
    let dashboard = runtime
        .get_workspace_dashboard(dashboard_request())
        .expect("dashboard");
    let candidate = dashboard.tasks[0].recovery_candidates[0].clone();
    assert!(candidate
        .actions
        .contains(&RecoveryAction::RetryAfterAuthoritativeAbsence));

    runtime
        .reconcile_workspace(RecoveryCandidateRequestDto {
            candidate_id: candidate.intent_id.clone().expect("candidate id"),
            project_id: "project-other".to_owned(),
            task_id: TASK_ID.to_owned(),
            expected_workspace_version: dashboard.tasks[0].workspace_version.get(),
        })
        .expect_err("candidate cannot cross projects");
    runtime
        .reconcile_workspace(RecoveryCandidateRequestDto {
            candidate_id: candidate.intent_id.clone().expect("candidate id"),
            project_id: PROJECT_ID.to_owned(),
            task_id: "task-other".to_owned(),
            expected_workspace_version: dashboard.tasks[0].workspace_version.get(),
        })
        .expect_err("candidate cannot cross tasks");
    runtime
        .reconcile_workspace(RecoveryCandidateRequestDto {
            candidate_id: candidate.intent_id.clone().expect("candidate id"),
            project_id: PROJECT_ID.to_owned(),
            task_id: TASK_ID.to_owned(),
            expected_workspace_version: dashboard.tasks[0].workspace_version.get() + 1,
        })
        .expect_err("stale workspace version");
    assert!(!fixture.managed_worktree().exists());
    assert_eq!(recovery_count(&fixture, "workspace.recovery.reconcile"), 0);

    let reconciled = runtime
        .reconcile_workspace(RecoveryCandidateRequestDto {
            candidate_id: candidate.intent_id.expect("candidate id"),
            project_id: PROJECT_ID.to_owned(),
            task_id: TASK_ID.to_owned(),
            expected_workspace_version: dashboard.tasks[0].workspace_version.get(),
        })
        .expect("reconcile");

    assert_eq!(
        reconciled.tasks[0]
            .worktree
            .as_ref()
            .expect("worktree")
            .state,
        WorktreeState::Present
    );
    assert!(fixture.managed_worktree().join("README.md").is_file());
    assert!(reconciled.tasks[0]
        .recovery_candidates
        .iter()
        .any(|candidate| {
            candidate
                .actions
                .contains(&RecoveryAction::DiscardExactWorktree)
        }));
    assert!(reconciled.tasks[0]
        .recovery_candidates
        .iter()
        .all(|candidate| !candidate
            .actions
            .contains(&RecoveryAction::RetryAfterAuthoritativeAbsence)));
    assert_eq!(
        recovery_status(&fixture, "workspace.recovery.reconcile"),
        "succeeded"
    );
}

#[test]
fn preserve_records_the_decision_and_removes_the_original_action() {
    let fixture = WorkspaceFixture::new();
    fixture.seed_interrupted_workspace();
    let bootstrap = fixture.start();
    let runtime = bootstrap.workspace_runtime().expect("runtime");
    let dashboard = runtime
        .get_workspace_dashboard(dashboard_request())
        .expect("dashboard");
    let task = &dashboard.tasks[0];
    let candidate = task.recovery_candidates[0].clone();

    let preserved = runtime
        .preserve_workspace(RecoveryCandidateRequestDto {
            candidate_id: candidate.intent_id.expect("candidate id"),
            project_id: PROJECT_ID.to_owned(),
            task_id: TASK_ID.to_owned(),
            expected_workspace_version: task.workspace_version.get(),
        })
        .expect("preserve");

    assert!(preserved.tasks[0].recovery_candidates.is_empty());
    assert_eq!(
        recovery_status(&fixture, "workspace.recovery.preserve"),
        "succeeded"
    );
    assert!(!fixture.managed_worktree().exists());
}

#[test]
fn discard_requires_confirmation_and_records_intent_before_the_exact_effect() {
    let fixture = WorkspaceFixture::new();
    fixture.seed_present_workspace();
    let original = std::fs::read(fixture.source.join("README.md")).expect("source");
    let bootstrap = fixture.start();
    let runtime = bootstrap.workspace_runtime().expect("runtime");
    let dashboard = runtime
        .get_workspace_dashboard(dashboard_request())
        .expect("dashboard");
    let task = &dashboard.tasks[0];
    let candidate = task.recovery_candidates[0].clone();
    assert!(candidate
        .actions
        .contains(&RecoveryAction::DiscardExactWorktree));
    let candidate_id = candidate.intent_id.expect("candidate id");

    runtime
        .discard_workspace(ConfirmDiscardWorkspaceRequestDto {
            candidate_id: candidate_id.clone(),
            project_id: PROJECT_ID.to_owned(),
            task_id: TASK_ID.to_owned(),
            expected_workspace_version: task.workspace_version.get(),
            confirmed: false,
        })
        .expect_err("confirmation is required");
    assert!(fixture.managed_worktree().exists());
    assert_eq!(recovery_count(&fixture, "workspace.recovery.discard"), 0);
    let refreshed = runtime
        .get_workspace_dashboard(dashboard_request())
        .expect("refreshed dashboard");

    let discarded = runtime
        .discard_workspace(ConfirmDiscardWorkspaceRequestDto {
            candidate_id,
            project_id: PROJECT_ID.to_owned(),
            task_id: TASK_ID.to_owned(),
            expected_workspace_version: refreshed.tasks[0].workspace_version.get(),
            confirmed: true,
        })
        .expect("discard");

    assert!(!fixture.managed_worktree().exists());
    assert_eq!(
        discarded.tasks[0]
            .worktree
            .as_ref()
            .expect("worktree")
            .state,
        WorktreeState::Discarded
    );
    assert!(discarded.tasks[0].recovery_candidates.is_empty());
    assert_eq!(
        recovery_status(&fixture, "workspace.recovery.discard"),
        "succeeded"
    );
    assert_eq!(
        std::fs::read(fixture.source.join("README.md")).expect("source"),
        original
    );
}

#[test]
fn cancelling_an_interrupted_discard_restores_an_actionable_exact_worktree() {
    let fixture = WorkspaceFixture::new();
    fixture.seed_present_workspace();
    fixture.seed_pending_discard_recovery();
    let bootstrap = fixture.start();
    let runtime = bootstrap.workspace_runtime().expect("runtime");
    let dashboard = runtime
        .get_workspace_dashboard(dashboard_request())
        .expect("dashboard");
    let pending = dashboard.tasks[0]
        .recovery_candidates
        .iter()
        .find(|candidate| candidate.actions.contains(&RecoveryAction::PreserveTask))
        .cloned()
        .expect("pending recovery");

    let preserved = runtime
        .preserve_workspace(RecoveryCandidateRequestDto {
            candidate_id: pending.intent_id.expect("candidate id"),
            project_id: PROJECT_ID.to_owned(),
            task_id: TASK_ID.to_owned(),
            expected_workspace_version: dashboard.tasks[0].workspace_version.get(),
        })
        .expect("preserve pending discard");

    assert_eq!(
        preserved.tasks[0]
            .worktree
            .as_ref()
            .expect("worktree")
            .state,
        WorktreeState::Present
    );
    let discard = preserved.tasks[0]
        .recovery_candidates
        .iter()
        .find(|candidate| {
            candidate
                .actions
                .contains(&RecoveryAction::DiscardExactWorktree)
        })
        .cloned()
        .expect("restored discard action");
    let discarded = runtime
        .discard_workspace(ConfirmDiscardWorkspaceRequestDto {
            candidate_id: discard.intent_id.expect("candidate id"),
            project_id: PROJECT_ID.to_owned(),
            task_id: TASK_ID.to_owned(),
            expected_workspace_version: preserved.tasks[0].workspace_version.get(),
            confirmed: true,
        })
        .expect("discard after preserving interrupted recovery");

    assert_eq!(
        discarded.tasks[0]
            .worktree
            .as_ref()
            .expect("worktree")
            .state,
        WorktreeState::Discarded
    );
    assert!(!fixture.managed_worktree().exists());
}

fn dashboard_request() -> WorkspaceDashboardRequestDto {
    WorkspaceDashboardRequestDto {
        project_id: PROJECT_ID.to_owned(),
    }
}

fn recovery_status(fixture: &WorkspaceFixture, operation_kind: &str) -> String {
    fixture
        .database()
        .query_row(
            "SELECT status FROM operation_intents WHERE operation_kind = ?1",
            [operation_kind],
            |row| row.get(0),
        )
        .expect("recovery status")
}

fn recovery_count(fixture: &WorkspaceFixture, operation_kind: &str) -> i64 {
    fixture
        .database()
        .query_row(
            "SELECT COUNT(*) FROM operation_intents WHERE operation_kind = ?1",
            [operation_kind],
            |row| row.get(0),
        )
        .expect("recovery count")
}
