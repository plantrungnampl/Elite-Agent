use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Barrier};

use local_agent_terminal_application::{
    bind_tool_approval_payload, canonical_approval_payload, ApprovalCheck, ApprovalClaim,
    ApprovalDigestPayload, ApprovalExpiryStore, ApprovalId, ApprovalInvalidation,
    ApprovalResolution, ApprovalState, ApprovalStore, ApprovedExecutableIdentity,
    ApprovedProcessRequest, ExecutableFileIdentity, NewApproval, PolicyDecision,
    PolicyDecisionStore, RecordedPolicyDecision, ResolvedExecutable, SafeErrorClassification,
    ToolApprovalOperationV1, ToolApprovalPayloadV1,
};
use local_agent_terminal_domain::{
    combine_policy_rules, ActorLocality, CapabilityRef, EnvironmentProfile, MatchedPolicyRule,
    NetworkProfile, Phase, PlanStepId, PolicyAction, PolicyActor, PolicyEffect, PolicyRequest,
    PolicyResource, PolicyRuleId, PolicyVersion, ProcessBinding, ProcessInvocation,
    ProcessToolRequest, ProcessTrustTier, ResourceClass, RunId, Sha256Digest, TaskId, TaskRisk,
    Timestamp, TrustTier, WorkspaceVersion,
};
use local_agent_terminal_storage_sqlite::SqliteStore;
use rusqlite::{params, Connection};
use sha2::Digest;

static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

struct TestDatabase {
    directory: PathBuf,
    path: PathBuf,
    store: SqliteStore,
}

impl TestDatabase {
    fn new() -> Self {
        let directory = std::env::temp_dir().join(format!(
            "local-agent-terminal-policy-tool-{}-{}",
            std::process::id(),
            NEXT_TEMP.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&directory).unwrap();
        let path = directory.join("state.sqlite3");
        let store = SqliteStore::open(&path).unwrap();
        seed_project_and_task(&path, &directory);
        Self {
            directory,
            path,
            store,
        }
    }
}

impl Drop for TestDatabase {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.directory);
    }
}

#[test]
fn policy_decisions_are_persisted_in_the_normative_table() {
    let database = TestDatabase::new();
    let cases = [
        (PolicyEffect::Allow, "allow", 'c'),
        (PolicyEffect::Deny, "deny", 'd'),
        (PolicyEffect::RequireApproval, "require_approval", 'e'),
        (
            PolicyEffect::AllowWithRedaction,
            "allow_with_redaction",
            'f',
        ),
    ];
    for (effect, expected, character) in cases {
        let operation_digest = digest(character);
        let decision_id = database
            .store
            .record(policy_decision(effect, operation_digest.clone()))
            .unwrap();
        assert_eq!(
            decision_id.as_str(),
            format!(
                "policy-decision:{}",
                operation_digest.as_str().strip_prefix("sha256:").unwrap()
            )
        );
        let actual: String = configured_connection(&database.path)
            .query_row(
                "SELECT effect FROM policy_decisions WHERE operation_digest = ?1",
                [operation_digest.as_str()],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(actual, expected);
    }

    let connection = configured_connection(&database.path);
    let operation_digest = digest('c');
    let row: (String, String, String) = connection
        .query_row(
            "SELECT task_id, effect, operation_digest
             FROM policy_decisions WHERE operation_digest = ?1",
            [operation_digest.as_str()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap();
    assert_eq!(
        row,
        (
            "task-1".to_owned(),
            "allow".to_owned(),
            operation_digest.as_str().to_owned()
        )
    );
    assert!(connection
        .execute(
            "UPDATE policy_decisions SET effect = 'deny' WHERE operation_digest = ?1",
            [operation_digest.as_str()]
        )
        .is_err());
}

#[test]
fn approval_resolution_and_claim_fail_closed_without_decision_receipt_authority() {
    let database = TestDatabase::new();
    let (payload, binding) = approval_payload();
    let canonical =
        canonical_approval_payload(&ApprovalDigestPayload::Tool(payload.clone())).unwrap();
    persist_artifact(
        &database,
        "approval-artifact-1",
        "approvals/approval-1.json",
        &canonical.canonical_bytes,
    );
    let approval_id = ApprovalId::new("approval-1").unwrap();
    let requested = database
        .store
        .request(NewApproval {
            approval_id: approval_id.clone(),
            operation_digest: canonical.operation_digest.clone(),
            task_id: TaskId::new("task-1").unwrap(),
            workspace_version: WorkspaceVersion::new(4),
            policy_snapshot_digest: digest('b'),
            fencing_token: Some(1),
            tool_request_binding_digest: Some(binding.clone()),
            expires_at: payload.expires_at.clone(),
            nonce: payload.nonce.clone(),
        })
        .unwrap();
    assert_eq!(requested.state, ApprovalState::Requested);
    assert_eq!(
        requested.tool_request_binding_digest.as_ref(),
        Some(&binding)
    );
    persist_cross_task_artifact_duplicate(
        &database,
        "000-approval-duplicate",
        "approval-artifact-1",
    );
    let reopened = SqliteStore::open(&database.path).unwrap();
    let resolution_error = reopened
        .resolve(ApprovalResolution {
            approval_id: approval_id.clone(),
            approved: true,
        })
        .unwrap_err();
    assert_eq!(
        resolution_error.safe_classification(),
        SafeErrorClassification::IntegrityFailure
    );
    let check = ApprovalCheck {
        approval_id: approval_id.clone(),
        expected_operation_digest: canonical.operation_digest.clone(),
        task_id: TaskId::new("task-1").unwrap(),
        workspace_version: WorkspaceVersion::new(4),
        policy_snapshot_digest: digest('b'),
        fencing_token: Some(1),
        checked_at: "2026-08-23T12:01:00Z".to_owned(),
    };
    assert!(reopened.valid_for(check.clone()).unwrap().is_none());
    let claim = ApprovalClaim {
        approval_id: approval_id.clone(),
        expected_operation_digest: canonical.operation_digest,
        task_id: TaskId::new("task-1").unwrap(),
        workspace_version: WorkspaceVersion::new(4),
        policy_snapshot_digest: digest('b'),
        fencing_token: Some(1),
        tool_request_binding_digest: binding,
        nonce: payload.nonce,
        claimed_at: "2026-08-23T12:01:00Z".to_owned(),
    };
    let mut replay = claim.clone();
    replay.nonce = "abcdef0123456789abcdef0123456789".to_owned();
    assert!(reopened.claim(replay).unwrap().is_none());
    let mut digest_replay = claim.clone();
    digest_replay.expected_operation_digest = digest('f');
    assert!(reopened.claim(digest_replay).unwrap().is_none());
    let mut binding_replay = claim.clone();
    binding_replay.tool_request_binding_digest =
        local_agent_terminal_application::ToolRequestBindingDigest::from_persisted(digest('f'));
    assert!(reopened.claim(binding_replay).unwrap().is_none());
    assert!(reopened.claim(claim.clone()).unwrap().is_none());
    assert!(reopened.claim(claim).unwrap().is_none());

    let connection = configured_connection(&database.path);
    assert_eq!(
        connection
            .query_row(
                "SELECT status || ':' || COALESCE(invalidation_reason, '')
                 FROM approvals WHERE id = 'approval-1'",
                [],
                |row| row.get::<_, String>(0)
            )
            .unwrap(),
        "pending:"
    );
    assert!(connection
        .execute(
            "UPDATE approvals SET status = 'granted' WHERE id = 'approval-1'",
            []
        )
        .is_err());
}

#[test]
fn approval_requests_reject_valid_but_noncanonical_json_evidence() {
    let database = TestDatabase::new();
    let (payload, binding) = approval_payload();
    let canonical =
        canonical_approval_payload(&ApprovalDigestPayload::Tool(payload.clone())).unwrap();
    let mut noncanonical = vec![b' '];
    noncanonical.extend_from_slice(&canonical.canonical_bytes);
    let noncanonical_digest =
        Sha256Digest::new(format!("sha256:{:x}", sha2::Sha256::digest(&noncanonical))).unwrap();
    persist_artifact(
        &database,
        "approval-noncanonical",
        "approvals/approval-noncanonical.json",
        &noncanonical,
    );

    assert!(database
        .store
        .request(NewApproval {
            approval_id: ApprovalId::new("approval-noncanonical").unwrap(),
            operation_digest: noncanonical_digest,
            task_id: TaskId::new("task-1").unwrap(),
            workspace_version: WorkspaceVersion::new(4),
            policy_snapshot_digest: digest('b'),
            fencing_token: Some(1),
            tool_request_binding_digest: Some(binding),
            expires_at: payload.expires_at,
            nonce: payload.nonce,
        })
        .is_err());
}

#[test]
fn workspace_change_invalidates_pending_approvals() {
    let database = TestDatabase::new();
    let (mut payload, binding) = approval_payload();
    payload.nonce = "abcdef0123456789abcdef0123456789".to_owned();
    let canonical =
        canonical_approval_payload(&ApprovalDigestPayload::Tool(payload.clone())).unwrap();
    persist_artifact(
        &database,
        "approval-artifact-2",
        "approvals/approval-2.json",
        &canonical.canonical_bytes,
    );
    database
        .store
        .request(NewApproval {
            approval_id: ApprovalId::new("approval-2").unwrap(),
            operation_digest: canonical.operation_digest,
            task_id: TaskId::new("task-1").unwrap(),
            workspace_version: WorkspaceVersion::new(4),
            policy_snapshot_digest: digest('b'),
            fencing_token: Some(1),
            tool_request_binding_digest: Some(binding),
            expires_at: payload.expires_at,
            nonce: payload.nonce,
        })
        .unwrap();

    assert_eq!(
        database
            .store
            .invalidate(ApprovalInvalidation {
                task_id: TaskId::new("task-1").unwrap(),
                workspace_version: WorkspaceVersion::new(5),
            })
            .unwrap(),
        1
    );
    assert_eq!(task_operation_state(&database.path), "None");

    let (mut payload, binding) = approval_payload();
    payload.nonce = "fedcba9876543210fedcba9876543210".to_owned();
    let canonical =
        canonical_approval_payload(&ApprovalDigestPayload::Tool(payload.clone())).unwrap();
    persist_artifact(
        &database,
        "approval-artifact-3",
        "approvals/approval-3.json",
        &canonical.canonical_bytes,
    );
    let approval_id = ApprovalId::new("approval-3").unwrap();
    database
        .store
        .request(NewApproval {
            approval_id: approval_id.clone(),
            operation_digest: canonical.operation_digest.clone(),
            task_id: TaskId::new("task-1").unwrap(),
            workspace_version: WorkspaceVersion::new(4),
            policy_snapshot_digest: digest('b'),
            fencing_token: Some(1),
            tool_request_binding_digest: Some(binding),
            expires_at: payload.expires_at,
            nonce: payload.nonce,
        })
        .unwrap();
    assert_eq!(
        database
            .store
            .resolve(ApprovalResolution {
                approval_id: approval_id.clone(),
                approved: true,
            })
            .unwrap_err()
            .safe_classification(),
        SafeErrorClassification::IntegrityFailure
    );
    assert_eq!(
        database
            .store
            .invalidate(ApprovalInvalidation {
                task_id: TaskId::new("task-1").unwrap(),
                workspace_version: WorkspaceVersion::new(4),
            })
            .unwrap(),
        0
    );
    assert_eq!(
        database
            .store
            .invalidate(ApprovalInvalidation {
                task_id: TaskId::new("task-1").unwrap(),
                workspace_version: WorkspaceVersion::new(5),
            })
            .unwrap(),
        1
    );
    assert_eq!(
        configured_connection(&database.path)
            .query_row(
                "SELECT status FROM approvals WHERE id = 'approval-3'",
                [],
                |row| row.get::<_, String>(0)
            )
            .unwrap(),
        "invalidated"
    );
    assert_eq!(task_operation_state(&database.path), "None");
}

#[test]
fn fencing_change_and_expiry_do_not_authorize_unreceipted_grants() {
    for (suffix, checked_at, fencing_token) in [
        ("fence", "2026-08-23T12:01:00Z", Some(2)),
        ("expiry", "2026-08-23T12:16:00Z", Some(1)),
    ] {
        let database = TestDatabase::new();
        let (mut payload, binding) = approval_payload();
        payload.nonce = if suffix == "fence" {
            "11111111111111111111111111111111".to_owned()
        } else {
            "22222222222222222222222222222222".to_owned()
        };
        let canonical =
            canonical_approval_payload(&ApprovalDigestPayload::Tool(payload.clone())).unwrap();
        let approval_id = ApprovalId::new(format!("approval-{suffix}")).unwrap();
        persist_artifact(
            &database,
            &format!("artifact-{suffix}"),
            &format!("approvals/{}.json", approval_id.as_str()),
            &canonical.canonical_bytes,
        );
        database
            .store
            .request(NewApproval {
                approval_id: approval_id.clone(),
                operation_digest: canonical.operation_digest.clone(),
                task_id: TaskId::new("task-1").unwrap(),
                workspace_version: WorkspaceVersion::new(4),
                policy_snapshot_digest: digest('b'),
                fencing_token: Some(1),
                tool_request_binding_digest: Some(binding),
                expires_at: payload.expires_at,
                nonce: payload.nonce,
            })
            .unwrap();
        assert_eq!(
            database
                .store
                .resolve(ApprovalResolution {
                    approval_id: approval_id.clone(),
                    approved: true,
                })
                .unwrap_err()
                .safe_classification(),
            SafeErrorClassification::IntegrityFailure
        );
        assert!(database
            .store
            .valid_for(ApprovalCheck {
                approval_id: approval_id.clone(),
                expected_operation_digest: canonical.operation_digest,
                task_id: TaskId::new("task-1").unwrap(),
                workspace_version: WorkspaceVersion::new(4),
                policy_snapshot_digest: digest('b'),
                fencing_token,
                checked_at: checked_at.to_owned(),
            })
            .unwrap()
            .is_none());
        assert_eq!(
            configured_connection(&database.path)
                .query_row(
                    "SELECT status FROM approvals WHERE id = ?1",
                    [approval_id.as_str()],
                    |row| row.get::<_, String>(0)
                )
                .unwrap(),
            "pending"
        );
    }
}

#[test]
fn startup_expiry_atomically_invalidates_open_approvals_once() {
    let database = TestDatabase::new();
    for (index, expires_at, grant) in [
        (1, "2026-08-23T12:10:00Z", false),
        (2, "2026-08-23T12:15:00Z", true),
        (3, "2026-08-23T12:30:00Z", false),
    ] {
        let (mut payload, binding) = approval_payload();
        payload.expires_at = expires_at.to_owned();
        payload.nonce = format!("{index:032}");
        let canonical =
            canonical_approval_payload(&ApprovalDigestPayload::Tool(payload.clone())).unwrap();
        let approval_id = ApprovalId::new(format!("approval-expiry-{index}")).unwrap();
        persist_artifact(
            &database,
            &format!("approval-expiry-artifact-{index}"),
            &format!("approvals/{}.json", approval_id.as_str()),
            &canonical.canonical_bytes,
        );
        database
            .store
            .request(NewApproval {
                approval_id: approval_id.clone(),
                operation_digest: canonical.operation_digest,
                task_id: TaskId::new("task-1").unwrap(),
                workspace_version: WorkspaceVersion::new(4),
                policy_snapshot_digest: digest('b'),
                fencing_token: Some(1),
                tool_request_binding_digest: Some(binding),
                expires_at: payload.expires_at,
                nonce: payload.nonce,
            })
            .unwrap();
        if grant {
            assert_eq!(
                database
                    .store
                    .resolve(ApprovalResolution {
                        approval_id,
                        approved: true,
                    })
                    .unwrap_err()
                    .safe_classification(),
                SafeErrorClassification::IntegrityFailure
            );
        }
    }

    configured_connection(&database.path)
        .execute_batch(
            "DROP TRIGGER approvals_identity_immutable;
             UPDATE approvals SET expires_at = 'not-a-timestamp'
             WHERE id = 'approval-expiry-3';",
        )
        .unwrap();
    assert_eq!(
        database
            .store
            .expire_before("2026-08-23T12:16:00Z")
            .unwrap_err()
            .safe_classification(),
        SafeErrorClassification::IntegrityFailure
    );
    assert_eq!(
        configured_connection(&database.path)
            .query_row(
                "SELECT COUNT(*) FROM events WHERE event_type = 'approval.expired'",
                [],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
        0
    );
    configured_connection(&database.path)
        .execute(
            "UPDATE approvals SET expires_at = '2026-08-23T12:30:00Z'
             WHERE id = 'approval-expiry-3'",
            [],
        )
        .unwrap();

    assert_eq!(
        database
            .store
            .expire_before("2026-08-23T12:16:00Z")
            .unwrap(),
        2
    );
    assert_eq!(
        database
            .store
            .expire_before("2026-08-23T12:16:00Z")
            .unwrap(),
        0
    );
    let connection = configured_connection(&database.path);
    assert_eq!(
        connection
            .prepare("SELECT status FROM approvals ORDER BY id")
            .unwrap()
            .query_map([], |row| row.get::<_, String>(0))
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap(),
        ["expired", "expired", "pending"]
    );
    assert_eq!(
        connection
            .query_row(
                "SELECT COUNT(*) FROM events WHERE event_type = 'approval.expired'",
                [],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
        2
    );
}

#[test]
fn concurrent_unreceipted_resolution_attempts_both_fail_closed() {
    let database = TestDatabase::new();
    let (mut payload, binding) = approval_payload();
    payload.nonce = "33333333333333333333333333333333".to_owned();
    let canonical =
        canonical_approval_payload(&ApprovalDigestPayload::Tool(payload.clone())).unwrap();
    let approval_id = ApprovalId::new("approval-race").unwrap();
    persist_artifact(
        &database,
        "artifact-race",
        "approvals/approval-race.json",
        &canonical.canonical_bytes,
    );
    database
        .store
        .request(NewApproval {
            approval_id: approval_id.clone(),
            operation_digest: canonical.operation_digest,
            task_id: TaskId::new("task-1").unwrap(),
            workspace_version: WorkspaceVersion::new(4),
            policy_snapshot_digest: digest('b'),
            fencing_token: Some(1),
            tool_request_binding_digest: Some(binding),
            expires_at: payload.expires_at,
            nonce: payload.nonce,
        })
        .unwrap();
    let barrier = Arc::new(Barrier::new(2));
    let outcomes = std::thread::scope(|scope| {
        let first_store = database.store.clone();
        let first_id = approval_id.clone();
        let first_barrier = Arc::clone(&barrier);
        let first = scope.spawn(move || {
            first_barrier.wait();
            first_store.resolve(ApprovalResolution {
                approval_id: first_id,
                approved: true,
            })
        });
        let second_store = database.store.clone();
        let second_barrier = Arc::clone(&barrier);
        let second = scope.spawn(move || {
            second_barrier.wait();
            second_store.resolve(ApprovalResolution {
                approval_id,
                approved: false,
            })
        });
        [first.join().unwrap(), second.join().unwrap()]
    });
    assert!(outcomes.iter().all(|outcome| matches!(
        outcome,
        Err(error)
            if error.safe_classification() == SafeErrorClassification::IntegrityFailure
    )));
}

#[test]
fn operation_intent_trigger_matches_the_authoritative_transition_table() {
    let database = TestDatabase::new();
    persist_artifact(
        &database,
        "operation-intent-artifact",
        "operations/request.json",
        b"{}",
    );
    let connection = configured_connection(&database.path);
    let allowed = [
        ("pending", "claimed"),
        ("pending", "started"),
        ("pending", "cancelled"),
        ("claimed", "pending"),
        ("claimed", "started"),
        ("claimed", "cancelled"),
        ("started", "succeeded"),
        ("started", "failed"),
        ("started", "interrupted"),
        ("started", "indeterminate"),
        ("started", "cancelled"),
        ("interrupted", "pending"),
        ("interrupted", "cancelled"),
        ("indeterminate", "succeeded"),
        ("indeterminate", "failed"),
        ("indeterminate", "cancelled"),
        ("succeeded", "interrupted"),
        ("succeeded", "indeterminate"),
    ];
    for (index, (from, to)) in allowed.into_iter().enumerate() {
        insert_operation_intent(&connection, index, from);
        let outcome = connection.execute(
            "UPDATE operation_intents SET status = ?1 WHERE id = ?2",
            params![to, format!("intent-{index}")],
        );
        let allowed_without_attempt_authority = matches!(
            (from, to),
            ("pending", "claimed")
                | ("pending", "started")
                | ("claimed", "pending")
                | ("claimed", "started")
        );
        if !allowed_without_attempt_authority {
            assert!(
                outcome.is_err(),
                "terminal {from} -> {to} requires exact v7 attempt authority"
            );
        } else {
            assert_eq!(outcome.unwrap(), 1, "expected {from} -> {to} to be allowed");
        }
    }

    let forbidden = [
        ("pending", "failed"),
        ("claimed", "failed"),
        ("succeeded", "failed"),
        ("failed", "started"),
        ("interrupted", "succeeded"),
        ("indeterminate", "pending"),
        ("cancelled", "pending"),
    ];
    for (offset, (from, to)) in forbidden.into_iter().enumerate() {
        let index = allowed.len() + offset;
        insert_operation_intent(&connection, index, from);
        assert!(
            connection
                .execute(
                    "UPDATE operation_intents SET status = ?1 WHERE id = ?2",
                    params![to, format!("intent-{index}")],
                )
                .is_err(),
            "expected {from} -> {to} to be forbidden",
        );
    }
}

#[test]
fn foreign_keys_and_lowercase_digest_constraints_remain_enabled() {
    let database = TestDatabase::new();
    let connection = configured_connection(&database.path);
    assert!(connection
        .query_row("PRAGMA foreign_keys", [], |row| row.get::<_, bool>(0))
        .unwrap());
    assert!(connection
        .execute(
            "INSERT INTO policy_decisions (
                id, task_id, actor_json, actor_binding_digest, action, resource_json,
                resource_digest, purpose, workflow_phase, effect, matched_rules_json,
                policy_snapshot_digest, operation_digest, created_at, expires_at, approval_id
             ) VALUES ('bad-digest', 'task-1', '{}', ?1, 'process.exec', '{}', ?1,
                'test', 'Implementation', 'allow', '[]', ?1, ?2,
                '2026-07-23T12:00:00Z', NULL, NULL)",
            params![digest('a').as_str(), format!("sha256:{}", "A".repeat(64))],
        )
        .is_err());
    assert!(connection
        .execute("DELETE FROM projects WHERE id = 'project-1'", [])
        .is_err());
}

fn seed_project_and_task(path: &Path, artifact_root: &Path) {
    let connection = configured_connection(path);
    connection
        .execute(
            "INSERT INTO projects (
                id, name, repository_path, repository_identity, created_at, updated_at,
                policy_profile_id, artifact_root_mode, artifact_root_path
             ) VALUES ('project-1', 'Project', 'C:/repo',
                'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
                '2026-07-23T00:00:00Z', '2026-07-23T00:00:00Z',
                'policy-1', 'application_data', ?1)",
            [artifact_root.to_string_lossy().as_ref()],
        )
        .unwrap();
    connection
        .execute(
            "INSERT INTO tasks (
                id, project_id, title, objective, phase, condition, operation_state, risk_level,
                base_branch, base_commit, workspace_version, fencing_epoch, created_at, updated_at
             ) VALUES ('task-1', 'project-1', 'Task', 'Objective', 'Implementation', 'Active',
                'None', 'high', 'main', ?1, 4, 1,
                '2026-07-23T00:00:00Z', '2026-07-23T00:00:00Z')",
            ["a".repeat(40)],
        )
        .unwrap();
}

fn configured_connection(path: &Path) -> Connection {
    let connection = Connection::open(path).unwrap();
    connection
        .pragma_update(None, "foreign_keys", "ON")
        .unwrap();
    connection
}

fn task_operation_state(path: &Path) -> String {
    configured_connection(path)
        .query_row(
            "SELECT operation_state FROM tasks WHERE id = 'task-1'",
            [],
            |row| row.get(0),
        )
        .unwrap()
}

fn insert_operation_intent(connection: &Connection, index: usize, status: &str) {
    connection
        .execute(
            "INSERT INTO operation_intents (
                id, task_id, operation_kind, idempotency_class, idempotency_key,
                canonical_request_artifact_id, operation_digest, actor_binding_digest,
                status, current_attempt_no,
                created_at, updated_at
             ) VALUES (?1, 'task-1', 'test.operation', 'idempotent', ?2,
                 'operation-intent-artifact', ?3, ?3, ?4, 0,
                '2026-07-23T12:00:00Z', '2026-07-23T12:00:00Z')",
            params![
                format!("intent-{index}"),
                format!("intent-key-{index}"),
                format!("sha256:{:x}", sha2::Sha256::digest(b"{}")),
                status,
            ],
        )
        .unwrap();
}

fn persist_cross_task_artifact_duplicate(
    database: &TestDatabase,
    duplicate_id: &str,
    source_id: &str,
) {
    let connection = configured_connection(&database.path);
    connection
        .execute(
            "INSERT INTO projects (
                id, name, repository_path, repository_identity, created_at, updated_at,
                policy_profile_id, artifact_root_mode, artifact_root_path
             ) VALUES ('project-2', 'Other', 'C:/other',
                'sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
                '2026-07-23T00:00:00Z', '2026-07-23T00:00:00Z',
                'policy-1', 'application_data', ?1)",
            [database.directory.to_string_lossy().as_ref()],
        )
        .unwrap();
    connection
        .execute(
            "INSERT INTO tasks (
                id, project_id, title, objective, phase, condition, operation_state,
                risk_level, base_branch, base_commit, created_at, updated_at
             ) VALUES ('task-2', 'project-2', 'Other', 'Other', 'Implementation',
                'Active', 'None', 'low', 'main', ?1,
                '2026-07-23T00:00:00Z', '2026-07-23T00:00:00Z')",
            ["b".repeat(40)],
        )
        .unwrap();
    connection
        .execute(
            "INSERT INTO artifacts (
                id, task_id, project_id, artifact_type, logical_path, content_hash, storage_key,
                size_bytes, mime_type, availability, created_by_type, created_by_id, created_at,
                supersedes, verification_state
             )
             SELECT ?1, 'task-2', 'project-2', artifact_type, logical_path, content_hash,
                    storage_key, size_bytes, mime_type, availability, created_by_type,
                    created_by_id, created_at, supersedes, verification_state
             FROM artifacts WHERE id = ?2",
            params![duplicate_id, source_id],
        )
        .unwrap();
}

fn persist_artifact(database: &TestDatabase, id: &str, logical_path: &str, bytes: &[u8]) {
    use sha2::{Digest, Sha256};
    let hash = format!("sha256:{:x}", Sha256::digest(bytes));
    let storage_key = format!("objects/{}", &hash[7..]);
    let object = database.directory.join(&storage_key);
    fs::create_dir_all(object.parent().unwrap()).unwrap();
    fs::write(object, bytes).unwrap();
    let connection = configured_connection(&database.path);
    connection
        .execute(
            "INSERT INTO artifacts (
                id, task_id, project_id, artifact_type, logical_path, content_hash, storage_key,
                size_bytes, mime_type, availability, created_by_type, created_by_id, created_at,
                supersedes, verification_state
             ) VALUES (?1, 'task-1', 'project-1', 'approval-payload', ?2, ?3, ?4, ?5,
                'application/json', 'available', 'core', 'core', '2026-07-23T12:00:00Z',
                NULL, 'hash_verified')",
            params![id, logical_path, hash, storage_key, bytes.len() as i64],
        )
        .unwrap();
    if logical_path.starts_with("approvals/") {
        connection
            .execute(
                "INSERT INTO operation_intents (
                    id, task_id, operation_kind, idempotency_class, idempotency_key,
                    canonical_request_artifact_id, operation_digest, actor_binding_digest,
                    status, current_attempt_no, created_at, updated_at
                 ) VALUES (?1, 'task-1', 'approval.request', 'non_repeatable', ?2,
                    ?3, ?4, ?5, 'pending', 0,
                    '2026-07-23T12:00:00Z', '2026-07-23T12:00:00Z')",
                params![
                    format!("intent-for-{id}"),
                    format!("approval:{id}"),
                    id,
                    hash,
                    digest('d').as_str(),
                ],
            )
            .unwrap();
    }
}

fn approval_payload() -> (
    ToolApprovalPayloadV1,
    local_agent_terminal_application::ToolRequestBindingDigest,
) {
    let binding = ProcessBinding::new(
        TaskId::new("task-1").unwrap(),
        RunId::new("run-1").unwrap(),
        PlanStepId::new("step-1").unwrap(),
        Phase::Implementation,
        WorkspaceVersion::new(4),
        EnvironmentProfile::new("rust", digest('e')).unwrap(),
        1_000,
    )
    .unwrap();
    let request = ApprovedProcessRequest::new(
        ApprovedExecutableIdentity::new(
            ResolvedExecutable {
                canonical_path: std::env::temp_dir()
                    .join("local-agent-terminal-approved-executables")
                    .join("cargo.exe"),
                sha256: digest('d'),
                file_identity: ExecutableFileIdentity::new("storage-test-cargo").unwrap(),
                toolchain_id: "cargo".to_owned(),
            },
            "1.97.1",
        )
        .unwrap(),
        ProcessToolRequest::new(
            binding,
            ProcessInvocation::new(
                CapabilityRef::toolchain("cargo").unwrap(),
                vec!["test".to_owned()],
                CapabilityRef::worktree(TaskId::new("task-1").unwrap(), ".").unwrap(),
                ProcessTrustTier::IsolatedWorker,
                NetworkProfile::Denied,
                Vec::new(),
                Some(local_agent_terminal_domain::FencingToken::new(1).unwrap()),
            )
            .unwrap(),
        )
        .unwrap(),
        Vec::new(),
        None,
        None,
        None,
    )
    .unwrap();
    let bound = bind_tool_approval_payload(
        ToolApprovalPayloadV1 {
            schema: "approval-digest.v1".to_owned(),
            approval_type: "tool".to_owned(),
            task_id: "unbound".to_owned(),
            operation: ToolApprovalOperationV1 {
                run_id: "unbound".to_owned(),
                plan_step_id: "unbound".to_owned(),
                tool: "process.exec".to_owned(),
                executable_digest: None,
                arguments_digest: digest('0').to_string(),
                script_digest: None,
                cwd_capability: "unbound".to_owned(),
                environment_profile_digest: digest('0').to_string(),
                network_profile: "denied".to_owned(),
                expected_writes: Vec::new(),
                executor_fencing_token: None,
            },
            policy_snapshot_digest: digest('b').to_string(),
            workspace_version: 0,
            requested_at: "2026-08-23T12:00:00Z".to_owned(),
            expires_at: "2026-08-23T12:15:00Z".to_owned(),
            nonce: "0123456789abcdef0123456789abcdef".to_owned(),
        },
        &request,
    )
    .unwrap();
    (
        bound.payload().clone(),
        bound.request_binding_digest().clone(),
    )
}

fn policy_decision(effect: PolicyEffect, operation_digest: Sha256Digest) -> RecordedPolicyDecision {
    let request = PolicyRequest {
        task_id: TaskId::new("task-1").unwrap(),
        actor: PolicyActor {
            connection_id: "connection-1".to_owned(),
            agent_id: "agent-1".to_owned(),
            trust_tier: TrustTier::CoreAdapter,
            locality: ActorLocality::Local,
        },
        action: PolicyAction::new("process.exec").unwrap(),
        resource: PolicyResource {
            capability: CapabilityRef::toolchain("cargo").unwrap(),
            content_digest: digest('a'),
            resource_class: ResourceClass::InternalCode,
        },
        task_risk: TaskRisk::High,
        workflow_phase: "Implementation".to_owned(),
        purpose: "run focused tests".to_owned(),
        policy_snapshot_digest: digest('b'),
        evaluated_at: Timestamp::from_unix_seconds(1_790_000_000),
    };
    let draft = combine_policy_rules(
        request,
        PolicyVersion::new(1).unwrap(),
        vec![MatchedPolicyRule {
            rule_id: PolicyRuleId::new(format!("rule-{effect:?}")).unwrap(),
            effect,
            redactions: Vec::new(),
        }],
        None,
    )
    .unwrap();
    RecordedPolicyDecision::exact(
        PolicyDecision {
            draft,
            operation_digest,
        },
        Timestamp::from_unix_seconds(1_790_000_001),
    )
}

fn digest(character: char) -> Sha256Digest {
    Sha256Digest::new(format!("sha256:{}", character.to_string().repeat(64))).unwrap()
}
