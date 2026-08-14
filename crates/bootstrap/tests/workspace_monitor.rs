#[path = "support/rename.rs"]
mod rename_support;
mod support;

use std::fs;

use local_agent_terminal_application::{
    AcquireLease, PortError, RevokeLease, StartupStateDto, TaskLeaseState,
    WorkspaceDashboardRequestDto,
};
use local_agent_terminal_domain::{LeaseClaim, RunId, TaskId};
use rusqlite::OptionalExtension;
use serde_json::Value;

use rename_support::rename_fixture;
use support::{WorkspaceFixture, TASK_ID};

#[test]
fn startup_reconciles_a_completed_worktree_before_exposing_ready() {
    let fixture = WorkspaceFixture::new();
    fixture.seed_present_workspace();
    let moved = fixture.root.path().join("moved-before-startup");
    rename_fixture(&fixture.managed_worktree(), &moved, "move worktree");

    let bootstrap = fixture.start();
    let runtime = bootstrap.workspace_runtime().expect("runtime");

    assert!(!runtime.recovery_candidates().is_empty());
    let task = runtime.task(&task_id()).expect("task");
    assert_eq!(
        task.worktree.as_ref().expect("worktree").state,
        local_agent_terminal_application::WorktreeState::Conflict
    );
    assert!(!task.recovery_candidates.is_empty());
}

#[test]
fn failed_dashboard_inspection_revokes_new_monitor_authority() {
    let fixture = WorkspaceFixture::new();
    fixture.seed_present_workspace();
    let bootstrap = fixture.start();
    let runtime = bootstrap.workspace_runtime().expect("runtime");
    let moved_source = fixture.root.path().join("source-moved");
    rename_fixture(&fixture.source, &moved_source, "move source");

    runtime
        .get_workspace_dashboard(WorkspaceDashboardRequestDto {
            project_id: "project-1".to_owned(),
        })
        .expect_err("inspection must fail closed");

    let lease_status: String = fixture
        .database()
        .query_row(
            "SELECT status FROM executor_leases WHERE task_id = ?1",
            [TASK_ID],
            |row| row.get(0),
        )
        .expect("lease");
    assert_eq!(lease_status, "revoked");
}

#[test]
fn dashboard_reestablishes_monitor_authority_after_restart() {
    let fixture = WorkspaceFixture::new();
    fixture.seed_present_workspace();
    let bootstrap = fixture.start();
    let runtime = bootstrap.workspace_runtime().expect("runtime");
    fs::write(
        fixture.managed_worktree().join("README.md"),
        b"changed after restart\n",
    )
    .expect("mutation");

    let dashboard = runtime
        .get_workspace_dashboard(WorkspaceDashboardRequestDto {
            project_id: "project-1".to_owned(),
        })
        .expect("dashboard");

    assert_eq!(dashboard.tasks[0].phase.as_str(), "WorkspaceDirty");
    assert_eq!(dashboard.tasks[0].workspace_version.get(), 1);
    assert_eq!(dashboard.tasks[0].lease_state, TaskLeaseState::Revoked);
}

#[test]
fn missing_worktree_enters_durable_recovery_without_stranding_the_monitor_lease() {
    let fixture = WorkspaceFixture::new();
    fixture.seed_present_workspace();
    let bootstrap = fixture.start();
    let runtime = bootstrap.workspace_runtime().expect("runtime");
    let moved = fixture.root.path().join("moved-worktree");
    rename_fixture(&fixture.managed_worktree(), &moved, "move worktree");

    let dashboard = runtime
        .get_workspace_dashboard(WorkspaceDashboardRequestDto {
            project_id: "project-1".to_owned(),
        })
        .expect("recovery dashboard");

    assert_eq!(dashboard.tasks[0].lease_state, TaskLeaseState::Revoked);
    assert!(!dashboard.tasks[0].recovery_candidates.is_empty());
    assert_eq!(
        dashboard.tasks[0]
            .worktree
            .as_ref()
            .expect("worktree")
            .state,
        local_agent_terminal_application::WorktreeState::Conflict
    );
    let repeated = runtime
        .get_workspace_dashboard(WorkspaceDashboardRequestDto {
            project_id: "project-1".to_owned(),
        })
        .expect("dashboard remains available");
    assert_eq!(repeated.tasks[0].lease_state, TaskLeaseState::Revoked);
    assert!(!repeated.tasks[0].recovery_candidates.is_empty());
}

#[test]
fn unchanged_authoritative_fingerprint_is_a_no_op() {
    let fixture = WorkspaceFixture::new();
    fixture.seed_present_workspace();
    let bootstrap = fixture.start();
    let runtime = bootstrap.workspace_runtime().expect("runtime");
    let lease = runtime
        .acquire_lease(acquire("run-lease-1", 0))
        .expect("lease");
    let claim = LeaseClaim::new(task_id(), lease.holder_run_id, lease.token);
    let before = mutation_counts(&fixture);

    let outcome = runtime
        .poll_workspace(&task_id(), claim)
        .expect("workspace poll");

    assert!(outcome.is_none());
    assert_eq!(mutation_counts(&fixture), before);
    let connection = fixture.database();
    let phase: String = connection
        .query_row("SELECT phase FROM tasks WHERE id = ?1", [TASK_ID], |row| {
            row.get(0)
        })
        .expect("phase");
    assert_eq!(phase, "Implementation");
}

#[test]
fn out_of_band_change_enters_workspace_dirty_once_with_atomic_evidence() {
    let fixture = WorkspaceFixture::new();
    fixture.seed_present_workspace();
    let original_source = fs::read(fixture.source.join("README.md")).expect("source");
    let bootstrap = fixture.start();
    let runtime = bootstrap.workspace_runtime().expect("runtime");
    fixture.seed_open_approvals("-revalidated", "2026-07-26T00:00:08Z");
    let lease = runtime
        .acquire_lease(acquire("run-lease-1", 0))
        .expect("lease");
    let claim = LeaseClaim::new(task_id(), lease.holder_run_id, lease.token);
    fs::write(
        fixture.managed_worktree().join("README.md"),
        b"out-of-band\n",
    )
    .expect("mutation");

    let mutation = runtime
        .poll_workspace(&task_id(), claim)
        .expect("workspace poll")
        .expect("detected mutation");

    assert_eq!(
        mutation.task_state.phase(),
        local_agent_terminal_domain::Phase::WorkspaceDirty
    );
    assert_eq!(mutation.task_state.workspace_version().get(), 1);
    assert_eq!(mutation.task_state.fencing_epoch(), 2);
    assert_eq!(
        mutation.resume_target,
        Some(local_agent_terminal_domain::Phase::Implementation)
    );
    assert_eq!(mutation.invalidated_approval_ids.len(), 3);
    assert_eq!(
        fs::read(fixture.source.join("README.md")).unwrap(),
        original_source
    );

    let connection = fixture.database();
    let projection: (String, i64, i64, Option<String>, String) = connection
        .query_row(
            "SELECT t.phase, t.workspace_version, t.fencing_epoch, t.active_candidate_tree,
                    l.status
             FROM tasks t JOIN executor_leases l ON l.task_id = t.id
             WHERE t.id = ?1",
            [TASK_ID],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                ))
            },
        )
        .expect("projection");
    assert_eq!(
        projection,
        (
            "WorkspaceDirty".to_owned(),
            1,
            2,
            None,
            "revoked".to_owned()
        )
    );
    let invalidated: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM approvals
             WHERE task_id = ?1 AND status = 'invalidated'
               AND invalidation_reason = 'workspace_mutated'",
            [TASK_ID],
            |row| row.get(0),
        )
        .expect("invalidated approvals");
    assert_eq!(invalidated, 3);
    let payload: String = connection
        .query_row(
            "SELECT payload_json FROM events
             WHERE stream_id = ?1 AND event_type = 'workspace.mutated'",
            [TASK_ID],
            |row| row.get(0),
        )
        .expect("mutation event");
    let payload: Value = serde_json::from_str(&payload).expect("payload");
    assert_eq!(payload["resumeTarget"], "Implementation");
    assert!(payload["preEvidenceArtifactId"].as_str().is_some());
    assert!(payload["postEvidenceArtifactId"].as_str().is_some());
    assert_eq!(mutation_counts(&fixture).0, 1);
}

#[test]
fn stale_monitor_claim_is_rejected_before_evidence_or_repository_bytes_change() {
    let fixture = WorkspaceFixture::new();
    fixture.seed_present_workspace();
    let bootstrap = fixture.start();
    let runtime = bootstrap.workspace_runtime().expect("runtime");
    let first = runtime
        .acquire_lease(acquire("run-lease-1", 0))
        .expect("lease");
    let stale_claim = LeaseClaim::new(task_id(), first.holder_run_id.clone(), first.token);
    runtime
        .revoke_lease(RevokeLease {
            claim: stale_claim.clone(),
            revoked_at: "2026-07-26T00:01:00Z".to_owned(),
        })
        .expect("revoke");
    let replacement = runtime
        .acquire_lease(acquire("run-lease-2", 1))
        .expect("replacement");
    assert_eq!(replacement.token.get(), 2);
    fs::write(fixture.managed_worktree().join("README.md"), b"external\n").expect("mutation");
    let before = mutation_counts(&fixture);

    let error = runtime
        .poll_workspace(&task_id(), stale_claim)
        .expect_err("stale claim");

    assert!(matches!(
        error,
        PortError::StaleLease {
            current,
            supplied
        } if current.get() == 2 && supplied.get() == 1
    ));
    assert_eq!(mutation_counts(&fixture), before);
    assert_eq!(
        fs::read(fixture.managed_worktree().join("README.md")).expect("worktree"),
        b"external\n"
    );
    let connection = fixture.database();
    let state: (String, String, i64) = connection
        .query_row(
            "SELECT t.phase, l.status, l.fencing_token
             FROM tasks t JOIN executor_leases l ON l.task_id = t.id
             WHERE t.id = ?1",
            [TASK_ID],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .expect("state");
    assert_eq!(state, ("Implementation".to_owned(), "active".to_owned(), 2));
}

#[test]
fn retry_and_drop_leave_no_monitor_thread_holding_workspace_adapters() {
    let fixture = WorkspaceFixture::new();
    fixture.seed_present_workspace();
    let mut bootstrap = fixture.start();
    let runtime = bootstrap.workspace_runtime().expect("runtime");
    let lease = runtime
        .acquire_lease(acquire("run-lease-1", 0))
        .expect("lease");
    let claim = LeaseClaim::new(task_id(), lease.holder_run_id, lease.token);
    assert!(runtime
        .poll_workspace(&task_id(), claim)
        .expect("poll")
        .is_none());

    assert_eq!(
        bootstrap.retry_startup_validation().state,
        StartupStateDto::Ready
    );
    drop(bootstrap);
    let moved = fixture.root.path().join("managed-workspaces-moved");
    rename_fixture(
        &fixture.workspace_root,
        &moved,
        "workspace root is not held",
    );
    rename_fixture(&moved, &fixture.workspace_root, "restore workspace root");
}

fn acquire(run_id: &str, expected_fencing_epoch: u64) -> AcquireLease {
    AcquireLease {
        task_id: task_id(),
        holder_run_id: RunId::new(run_id).expect("run"),
        expected_fencing_epoch,
        acquired_at: "2026-07-26T00:00:10Z".to_owned(),
        expires_at: "2026-07-26T01:00:10Z".to_owned(),
    }
}

fn task_id() -> TaskId {
    TaskId::new(TASK_ID).expect("task")
}

fn mutation_counts(fixture: &WorkspaceFixture) -> (i64, i64) {
    let connection = fixture.database();
    let events = connection
        .query_row(
            "SELECT COUNT(*) FROM events
             WHERE stream_id = ?1 AND event_type = 'workspace.mutated'",
            [TASK_ID],
            |row| row.get(0),
        )
        .expect("events");
    let evidence = connection
        .query_row(
            "SELECT COUNT(*) FROM artifacts
             WHERE task_id = ?1 AND artifact_type = 'workspace_fingerprint'",
            [TASK_ID],
            |row| row.get(0),
        )
        .optional()
        .expect("evidence")
        .unwrap_or_default();
    (events, evidence)
}
