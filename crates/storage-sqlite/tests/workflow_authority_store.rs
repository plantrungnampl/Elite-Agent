use std::fs;
use std::path::PathBuf;
use std::sync::Arc;

use local_agent_terminal_application::{
    prepare_workflow_transition, ArtifactStore, ArtifactWriteReservation, NewArtifact,
    ReservedArtifact, SafeErrorClassification, WorkflowAuthorityStore, WorkflowEffectBinding,
    WorkflowGuardEvidence,
};
use local_agent_terminal_domain::{
    ArtifactId, Condition, OperationState, Phase, ProjectId, Sha256Digest, TaskId, TaskOutcomeMode,
    Timestamp, WorkflowEvent, WorkflowProfile, WorkflowState, WorkflowStateSnapshot,
};
use local_agent_terminal_storage_files::{
    ContentAddressedArtifactReader, ContentAddressedArtifactStore, JournaledArtifactWriter,
};
use local_agent_terminal_storage_sqlite::SqliteStore;
use rusqlite::{params, Connection};
use sha2::{Digest, Sha256};

struct Fixture {
    directory: PathBuf,
    path: PathBuf,
    store: SqliteStore,
    artifacts: ContentAddressedArtifactStore,
}

impl Fixture {
    fn new() -> Self {
        let directory = std::env::temp_dir().join(format!(
            "workflow-authority-{}-{}",
            std::process::id(),
            unique_suffix(),
        ));
        fs::create_dir_all(&directory).unwrap();
        let path = directory.join("state.sqlite3");
        let artifacts = ContentAddressedArtifactStore::open(&directory).unwrap();
        let store = SqliteStore::open(&path)
            .unwrap()
            .with_artifact_reader(Arc::new(ContentAddressedArtifactReader))
            .with_workflow_core_actor_digest(digest(b"actor"));
        let fixture = Self {
            directory,
            path,
            store,
            artifacts,
        };
        fixture.seed_project_and_task();
        fixture
    }

    fn connection(&self) -> Connection {
        let connection = Connection::open(&self.path).unwrap();
        connection
            .execute_batch("PRAGMA foreign_keys = ON;")
            .unwrap();
        connection
    }

    fn seed_project_and_task(&self) {
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
                    digest(b"repository").as_str(),
                    self.directory.to_string_lossy()
                ],
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO tasks (
                    id, project_id, title, objective, phase, condition, operation_state,
                    risk_level, base_branch, base_commit, current_sequence, workspace_version,
                    fencing_epoch, row_version, created_at, updated_at
                 ) VALUES ('task-1', 'project-1', 'Task', 'Workflow', 'Intake',
                    'Active', 'None', 'medium', 'main', ?1, 0, 0, 1, 0,
                    '2026-08-09T00:00:00Z', '2026-08-09T00:00:00Z')",
                ["a".repeat(40)],
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO task_workflow_authority (
                    task_id, workflow_profile, outcome_mode, phase, selected_by_kind,
                    selected_by_actor_binding_id, selection_policy_digest, created_at,
                    updated_at, completed_at, stream_version, last_transition_event_id,
                    profile_revision, last_profile_revision_id
                 ) VALUES ('task-1', 'Standard', 'WorkspaceChange', 'Intake', 'core',
                    NULL, ?1, '2026-08-09T00:00:00.000Z',
                    '2026-08-09T00:00:00.000Z', NULL, 0, NULL, 1, NULL)",
                [digest(b"policy").as_str()],
            )
            .unwrap();
    }

    fn seed_artifact(&self, artifact_id: &str, artifact_type: &str, bytes: &[u8]) {
        let connection = self.connection();
        let digest = digest(bytes);
        let artifact = self
            .artifacts
            .put(NewArtifact {
                expected_hash: digest.as_str().to_owned(),
                expected_size: u64::try_from(bytes.len()).unwrap(),
                content: bytes.to_vec(),
            })
            .unwrap();
        let logical_path = if artifact_type == "workflow_transition_command" {
            format!("workflow/commands/{artifact_id}.json")
        } else {
            format!("workflow/{artifact_id}.json")
        };
        let created_by_id = if artifact_type == "workflow_transition_command" {
            "workflow-authority"
        } else {
            "test"
        };
        connection
            .execute(
                "INSERT INTO artifacts (
                    id, task_id, project_id, artifact_type, logical_path, content_hash,
                    storage_key, size_bytes, mime_type, availability, created_by_type,
                    created_by_id, created_at, supersedes, verification_state
                 ) VALUES (?1, 'task-1', 'project-1', ?2,
                    ?3, ?4, ?5, ?6, 'application/json', 'available', 'core',
                    ?7, '2026-08-09T00:00:00Z', NULL, 'hash_verified')",
                params![
                    artifact_id,
                    artifact_type,
                    logical_path,
                    digest.as_str(),
                    artifact.storage_key,
                    i64::try_from(bytes.len()).unwrap(),
                    created_by_id,
                ],
            )
            .unwrap();
        if artifact_type == "workflow_transition_command" {
            connection
                .execute(
                    "INSERT INTO artifact_operations (
                        id, artifact_id, temp_name, expected_hash, expected_size, status,
                        created_at, updated_at, completed_at, error_json
                     ) VALUES (?1, ?2, ?3, ?4, ?5, 'completed',
                        '2026-08-09T00:00:00Z', '2026-08-09T00:00:01Z',
                        '2026-08-09T00:00:01Z', NULL)",
                    params![
                        format!("operation-{artifact_id}"),
                        artifact_id,
                        format!("temp-{artifact_id}"),
                        digest.as_str(),
                        i64::try_from(bytes.len()).unwrap(),
                    ],
                )
                .unwrap();
        }
    }

    fn seed_command_artifact(&self, artifact_id: &str, bytes: &[u8]) {
        let content_hash = digest(bytes);
        JournaledArtifactWriter::new(&self.artifacts, &self.store, &self.store)
            .write(
                ArtifactWriteReservation {
                    operation_id: format!("workflow-transition:{artifact_id}"),
                    artifact: ReservedArtifact {
                        artifact_id: artifact_id.to_owned(),
                        task_id: Some(TaskId::new("task-1").unwrap()),
                        project_id: "project-1".to_owned(),
                        artifact_type: "workflow_transition_command".to_owned(),
                        logical_path: format!("workflow/commands/{artifact_id}.json"),
                        content_hash: content_hash.as_str().to_owned(),
                        storage_key: ContentAddressedArtifactStore::storage_key(
                            content_hash.as_str(),
                        )
                        .unwrap(),
                        size_bytes: u64::try_from(bytes.len()).unwrap(),
                        mime_type: Some("application/json".to_owned()),
                        created_by_type: "core".to_owned(),
                        created_by_id: "workflow-authority".to_owned(),
                        created_at: "2026-08-09T00:00:00Z".to_owned(),
                        supersedes: None,
                    },
                    temp_name: format!("{artifact_id}.tmp"),
                    created_at: "2026-08-09T00:00:00Z".to_owned(),
                },
                bytes,
            )
            .unwrap();
    }

    fn seed_transition_artifact(&self, artifact_id: &str) {
        self.seed_artifact(
            artifact_id,
            "workflow_transition_command",
            artifact_id.as_bytes(),
        );
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.directory);
    }
}

fn unique_suffix() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos()
}

fn digest(bytes: &[u8]) -> Sha256Digest {
    Sha256Digest::new(format!("sha256:{:x}", Sha256::digest(bytes))).unwrap()
}

fn state_at_intake() -> WorkflowState {
    WorkflowState::rehydrate(WorkflowStateSnapshot {
        phase: Phase::Intake,
        condition: Condition::Active,
        operation: OperationState::None,
        workflow_profile: WorkflowProfile::Standard,
        outcome_mode: TaskOutcomeMode::WorkspaceChange,
        stream_version: 0,
        profile_revision: 1,
        workspace_version: 0,
        fencing_epoch: 1,
        last_transition_event_id: None,
        last_profile_revision_id: None,
    })
    .unwrap()
}

fn seed_plan_approval_authority(fixture: &Fixture) {
    let transitions = [
        (
            "seed-p001",
            "WF-P001",
            "task.validated",
            "Intake",
            "ContextBuild",
            "Standard",
            0_i64,
        ),
        (
            "seed-p002",
            "WF-P002",
            "context.initial.ready",
            "ContextBuild",
            "ParallelAnalysis",
            "Standard",
            1,
        ),
        (
            "seed-p004",
            "WF-P004",
            "analysis.quorum.reached",
            "ParallelAnalysis",
            "CrossReview",
            "Standard",
            2,
        ),
        (
            "seed-p005",
            "WF-P005",
            "review.complete",
            "CrossReview",
            "PrePlanVerification",
            "Standard",
            3,
        ),
        (
            "seed-p006",
            "WF-P006",
            "claims.checked",
            "PrePlanVerification",
            "Synthesis",
            "Standard",
            4,
        ),
        (
            "seed-p007",
            "WF-P007",
            "decision.draft.created",
            "Synthesis",
            "FinalObjection",
            "Standard",
            5,
        ),
    ];
    for (index, (id, rule, event, from, to, profile, version)) in
        transitions.into_iter().enumerate()
    {
        fixture.seed_transition_artifact(id);
        seed_accepted_transition(
            fixture,
            id,
            rule,
            event,
            from,
            to,
            profile,
            version,
            &format!("2026-08-09T00:00:{:02}.000Z", index + 1),
        );
    }

    fixture.seed_artifact("seed-profile-reason", "receipt", b"profile reason");
    let connection = fixture.connection();
    connection
        .execute(
            "INSERT INTO workflow_profile_revisions (
                id, task_id, revision_no, expected_stream_version, from_profile,
                to_profile, reason_artifact_id, policy_digest, decided_by_kind,
                actor_binding_id, created_at, receipt_digest
             ) VALUES ('seed-profile-revision', 'task-1', 2, 6, 'Standard',
                'HighAssurance', 'seed-profile-reason', ?1, 'core', NULL,
                '2026-08-09T00:00:07.000Z', ?2)",
            params![
                digest(b"policy").as_str(),
                digest(b"profile-revision").as_str()
            ],
        )
        .unwrap();
    connection
        .execute(
            "UPDATE task_workflow_authority
             SET workflow_profile = 'HighAssurance', stream_version = 7,
                 profile_revision = 2, last_profile_revision_id = 'seed-profile-revision',
                 updated_at = '2026-08-09T00:00:07.000Z'
             WHERE task_id = 'task-1'",
            [],
        )
        .unwrap();

    fixture.seed_transition_artifact("seed-p013");
    seed_accepted_transition(
        fixture,
        "seed-p013",
        "WF-P013",
        "objection.round.closed",
        "FinalObjection",
        "AwaitingPlanApproval",
        "HighAssurance",
        7,
        "2026-08-09T00:00:08.000Z",
    );

    fixture.seed_artifact("plan-request", "plan-approval", b"plan request");
    fixture.seed_artifact("credential-evidence", "credential", b"credential");
    let connection = fixture.connection();
    let operation_digest = digest(b"plan request");
    let actor_digest = digest(b"plan-actor");
    connection
        .execute(
            "INSERT INTO operation_intents (
                id, task_id, run_id, operation_kind, idempotency_class, idempotency_key,
                canonical_request_artifact_id, operation_digest, actor_binding_digest,
                status, current_attempt_no, created_at, updated_at
             ) VALUES ('plan-intent', 'task-1', NULL, 'plan.approve', 'non_repeatable',
                'plan-intent-key', 'plan-request', ?1, ?2, 'pending', 0,
                '2026-08-09T00:00:00Z', '2026-08-09T00:00:00Z')",
            params![operation_digest.as_str(), actor_digest.as_str()],
        )
        .unwrap();
    connection
        .execute(
            "INSERT INTO approvals (
                id, task_id, operation_intent_id, approval_type, schema_version,
                operation_digest, actor_binding_digest, nonce, status, requested_at,
                resolved_at, expires_at, request_artifact_id, invalidation_reason
             ) VALUES ('approval-1', 'task-1', 'plan-intent', 'plan', 'approval-digest.v1',
                ?1, ?2, 'approval-nonce', 'pending', '2026-08-09T00:00:00Z',
                NULL, '2026-08-10T00:00:00Z', 'plan-request', NULL)",
            params![operation_digest.as_str(), actor_digest.as_str()],
        )
        .unwrap();
    connection
        .execute(
            "INSERT INTO approval_decision_receipts (
                id, approval_id, task_id, operation_intent_id, operation_digest,
                actor_binding_digest, nonce, decision, credential_evidence_artifact_id,
                decided_at, receipt_digest
             ) VALUES ('approval-receipt-1', 'approval-1', 'task-1', 'plan-intent',
                ?1, ?2, 'approval-nonce', 'granted', 'credential-evidence',
                '2026-08-09T00:00:09Z', ?3)",
            params![
                operation_digest.as_str(),
                actor_digest.as_str(),
                digest(b"approval-receipt").as_str()
            ],
        )
        .unwrap();
    connection
        .execute(
            "INSERT INTO actor_bindings (
                id, actor_kind, actor_id, session_id, proof_type, binding_digest,
                issued_at, expires_at, revoked_at, session_epoch
             ) VALUES ('actor-1', 'system', 'workflow-authority', 'session-1',
                'local_authenticated_session', ?1, '2026-08-09T00:00:00Z',
                '2026-08-10T00:00:00Z', NULL, 1)",
            [actor_digest.as_str()],
        )
        .unwrap();
    connection
        .execute(
            "INSERT INTO credential_challenges (
                id, actor_binding_id, purpose, operation_digest, nonce,
                challenge_digest, issued_at, expires_at
             ) VALUES ('challenge-1', 'actor-1', 'plan.approval', ?1,
                '012345678901234567890123', ?2, '2026-08-09T00:00:00Z',
                '2026-08-10T00:00:00Z')",
            params![operation_digest.as_str(), digest(b"challenge").as_str()],
        )
        .unwrap();
    connection
        .execute(
            "INSERT INTO credential_challenge_receipts (
                id, challenge_id, actor_binding_id, proof_type, proof_artifact_id,
                verified_at, receipt_digest
             ) VALUES ('challenge-receipt-1', 'challenge-1', 'actor-1',
                'local_authenticated_session', 'credential-evidence',
                '2026-08-09T00:00:09Z', ?1)",
            [digest(b"challenge-receipt").as_str()],
        )
        .unwrap();
    connection
        .execute(
            "INSERT INTO approval_actor_proof_bindings (
                approval_receipt_id, actor_binding_id, challenge_receipt_id, created_at
             ) VALUES ('approval-receipt-1', 'actor-1', 'challenge-receipt-1',
                '2026-08-09T00:00:09Z')",
            [],
        )
        .unwrap();
    connection
        .execute(
            "UPDATE approvals SET status = 'granted', resolved_at = '2026-08-09T00:00:09Z'
             WHERE id = 'approval-1'",
            [],
        )
        .unwrap();
}

fn seed_other_task_plan_approval_receipt(fixture: &Fixture) {
    let connection = fixture.connection();
    let operation_digest = digest(b"task-2-plan-request");
    let actor_digest = digest(b"task-2-plan-actor");
    connection
        .execute(
            "INSERT INTO tasks (
                id, project_id, title, objective, phase, condition, operation_state,
                risk_level, base_branch, base_commit, current_sequence, workspace_version,
                fencing_epoch, row_version, created_at, updated_at
             ) VALUES ('task-2', 'project-1', 'Other task', 'Other approval', 'Intake',
                'Active', 'None', 'medium', 'main', ?1, 0, 0, 1, 0,
                '2026-08-09T00:00:00Z', '2026-08-09T00:00:00Z')",
            ["b".repeat(40)],
        )
        .unwrap();
    for (id, artifact_type, content_hash) in [
        (
            "task-2-plan-request",
            "plan-approval",
            operation_digest.as_str(),
        ),
        (
            "task-2-credential-evidence",
            "credential",
            digest(b"task-2-credential").as_str(),
        ),
    ] {
        connection
            .execute(
                "INSERT INTO artifacts (
                    id, task_id, project_id, artifact_type, logical_path, content_hash,
                    storage_key, size_bytes, mime_type, availability, created_by_type,
                    created_by_id, created_at, supersedes, verification_state
                 ) VALUES (?1, 'task-2', 'project-1', ?2, ?1, ?3, ?1, 1,
                    'application/json', 'available', 'core', 'test',
                    '2026-08-09T00:00:00Z', NULL, 'hash_verified')",
                params![id, artifact_type, content_hash],
            )
            .unwrap();
    }
    connection
        .execute(
            "INSERT INTO operation_intents (
                id, task_id, run_id, operation_kind, idempotency_class, idempotency_key,
                canonical_request_artifact_id, operation_digest, actor_binding_digest,
                status, current_attempt_no, created_at, updated_at
             ) VALUES ('task-2-plan-intent', 'task-2', NULL, 'plan.approve',
                'non_repeatable', 'task-2-plan-intent-key', 'task-2-plan-request',
                ?1, ?2, 'pending', 0, '2026-08-09T00:00:00Z',
                '2026-08-09T00:00:00Z')",
            params![operation_digest.as_str(), actor_digest.as_str()],
        )
        .unwrap();
    connection
        .execute(
            "INSERT INTO approvals (
                id, task_id, operation_intent_id, approval_type, schema_version,
                operation_digest, actor_binding_digest, nonce, status, requested_at,
                resolved_at, expires_at, request_artifact_id, invalidation_reason
             ) VALUES ('task-2-approval', 'task-2', 'task-2-plan-intent', 'plan',
                'approval-digest.v1', ?1, ?2, 'task-2-approval-nonce', 'pending',
                '2026-08-09T00:00:00Z', NULL, '2026-08-10T00:00:00Z',
                'task-2-plan-request', NULL)",
            params![operation_digest.as_str(), actor_digest.as_str()],
        )
        .unwrap();
    connection
        .execute(
            "INSERT INTO approval_decision_receipts (
                id, approval_id, task_id, operation_intent_id, operation_digest,
                actor_binding_digest, nonce, decision, credential_evidence_artifact_id,
                decided_at, receipt_digest
             ) VALUES ('task-2-approval-receipt', 'task-2-approval', 'task-2',
                'task-2-plan-intent', ?1, ?2, 'task-2-approval-nonce', 'granted',
                'task-2-credential-evidence', '2026-08-09T00:00:09Z', ?3)",
            params![
                operation_digest.as_str(),
                actor_digest.as_str(),
                digest(b"task-2-approval-receipt").as_str(),
            ],
        )
        .unwrap();
    connection
        .execute(
            "INSERT INTO actor_bindings (
                id, actor_kind, actor_id, session_id, proof_type, binding_digest,
                issued_at, expires_at, revoked_at, session_epoch
             ) VALUES ('task-2-actor', 'system', 'workflow-authority',
                'task-2-session', 'local_authenticated_session', ?1,
                '2026-08-09T00:00:00Z', '2026-08-10T00:00:00Z', NULL, 1)",
            [actor_digest.as_str()],
        )
        .unwrap();
    connection
        .execute(
            "INSERT INTO credential_challenges (
                id, actor_binding_id, purpose, operation_digest, nonce,
                challenge_digest, issued_at, expires_at
             ) VALUES ('task-2-challenge', 'task-2-actor', 'plan.approval', ?1,
                '123456789012345678901234', ?2, '2026-08-09T00:00:00Z',
                '2026-08-10T00:00:00Z')",
            params![
                operation_digest.as_str(),
                digest(b"task-2-challenge").as_str()
            ],
        )
        .unwrap();
    connection
        .execute(
            "INSERT INTO credential_challenge_receipts (
                id, challenge_id, actor_binding_id, proof_type, proof_artifact_id,
                verified_at, receipt_digest
             ) VALUES ('task-2-challenge-receipt', 'task-2-challenge', 'task-2-actor',
                'local_authenticated_session', 'task-2-credential-evidence',
                '2026-08-09T00:00:09Z', ?1)",
            [digest(b"task-2-challenge-receipt").as_str()],
        )
        .unwrap();
    connection
        .execute(
            "INSERT INTO approval_actor_proof_bindings (
                approval_receipt_id, actor_binding_id, challenge_receipt_id, created_at
             ) VALUES ('task-2-approval-receipt', 'task-2-actor',
                'task-2-challenge-receipt', '2026-08-09T00:00:09Z')",
            [],
        )
        .unwrap();
    connection
        .execute(
            "UPDATE approvals SET status = 'granted', resolved_at = '2026-08-09T00:00:09Z'
             WHERE id = 'task-2-approval'",
            [],
        )
        .unwrap();
}

#[allow(clippy::too_many_arguments)]
fn seed_accepted_transition(
    fixture: &Fixture,
    id: &str,
    rule: &str,
    event: &str,
    from: &str,
    to: &str,
    profile: &str,
    version: i64,
    accepted_at: &str,
) {
    let connection = fixture.connection();
    let binding_digest = digest(id.as_bytes());
    connection
        .execute(
            "INSERT INTO workflow_transition_events (
                id, task_id, rule_id, expected_stream_version, from_phase, event_type,
                to_phase, workflow_profile, outcome_mode, transition_command_artifact_id,
                guard_set_digest, effect_set_digest, core_actor_digest, reducer_version,
                status, prepared_at, accepted_at, rejected_at
             ) VALUES (?1, 'task-1', ?2, ?3, ?4, ?5, ?6, ?7, 'WorkspaceChange',
                ?1, ?8, ?8, ?8, 'v3', 'prepared', ?9, NULL, NULL)",
            params![
                id,
                rule,
                version,
                from,
                event,
                to,
                profile,
                binding_digest.as_str(),
                accepted_at
            ],
        )
        .unwrap();
    let guards: Vec<String> = connection
        .prepare(
            "SELECT evidence_kind FROM workflow_transition_rule_guard_requirements
             WHERE rule_id = ?1 ORDER BY evidence_kind",
        )
        .unwrap()
        .query_map([rule], |row| row.get(0))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    for (index, kind) in guards.iter().enumerate() {
        connection
            .execute(
                "INSERT INTO workflow_transition_guard_bindings (
                    transition_event_id, evidence_kind, evidence_ref, subject_digest,
                    evidence_digest, artifact_id, approval_receipt_id, acceptance_receipt_id,
                    verification_receipt_id, ref_promotion_receipt_id
                 ) VALUES (?1, ?2, ?3, NULL, ?4, NULL, NULL, NULL, NULL, NULL)",
                params![
                    id,
                    kind,
                    format!("{id}:guard:{index}"),
                    binding_digest.as_str()
                ],
            )
            .unwrap();
    }
    let effects: Vec<String> = connection
        .prepare(
            "SELECT effect_kind FROM workflow_transition_rule_effect_requirements
             WHERE rule_id = ?1 ORDER BY effect_kind",
        )
        .unwrap()
        .query_map([rule], |row| row.get(0))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    for (index, kind) in effects.iter().enumerate() {
        connection
            .execute(
                "INSERT INTO workflow_transition_effect_bindings (
                    transition_event_id, effect_kind, effect_ref, effect_digest, artifact_id
                 ) VALUES (?1, ?2, ?3, ?4, NULL)",
                params![
                    id,
                    kind,
                    format!("{id}:effect:{index}"),
                    binding_digest.as_str()
                ],
            )
            .unwrap();
    }
    connection
        .execute(
            "UPDATE workflow_transition_events
             SET status = 'accepted', accepted_at = ?1 WHERE id = ?2",
            params![accepted_at, id],
        )
        .unwrap();
    connection
        .execute(
            "UPDATE task_workflow_authority
             SET phase = ?1, stream_version = ?2, last_transition_event_id = ?3,
                 updated_at = ?4
             WHERE task_id = 'task-1'",
            params![to, version + 1, id, accepted_at],
        )
        .unwrap();
    connection
        .execute(
            "UPDATE tasks SET phase = ?1, updated_at = ?2, row_version = row_version + 1
             WHERE id = 'task-1'",
            params![to, accepted_at],
        )
        .unwrap();
}

fn wf_p015_input() -> local_agent_terminal_application::TransitionWorkflowInput {
    let operation_digest = digest(b"plan request");
    let receipt_digest = digest(b"approval-receipt");
    let effect_digest = digest(b"effect");
    local_agent_terminal_application::TransitionWorkflowInput {
        command_id: "command-p015".to_owned(),
        transition_event_id: "transition-p015".to_owned(),
        task_id: TaskId::new("task-1").unwrap(),
        rule_id: "WF-P015".to_owned(),
        expected_stream_version: 8,
        event: WorkflowEvent::new("plan.approved").unwrap(),
        guards: vec![WorkflowGuardEvidence {
            kind: "plan_approval_receipt".to_owned(),
            reference: "approval-receipt-1".to_owned(),
            subject_digest: Some(operation_digest),
            evidence_digest: receipt_digest,
            artifact_id: Some(ArtifactId::new("plan-request").unwrap()),
            approval_receipt_id: Some("approval-receipt-1".to_owned()),
        }],
        effects: vec![
            WorkflowEffectBinding {
                kind: "allocate_executor_lease".to_owned(),
                reference: "lease-1".to_owned(),
                effect_digest: effect_digest.clone(),
                artifact_id: None,
            },
            WorkflowEffectBinding {
                kind: "persist_approved_plan_version".to_owned(),
                reference: "plan-1".to_owned(),
                effect_digest,
                artifact_id: None,
            },
        ],
        core_actor_digest: digest(b"actor"),
        reducer_version: "v3".to_owned(),
        prepared_at: Timestamp::from_unix_seconds(1_760_000_100),
    }
}

fn state_at_plan_approval() -> WorkflowState {
    WorkflowState::rehydrate(WorkflowStateSnapshot {
        phase: Phase::AwaitingPlanApproval,
        condition: Condition::Active,
        operation: OperationState::None,
        workflow_profile: WorkflowProfile::HighAssurance,
        outcome_mode: TaskOutcomeMode::WorkspaceChange,
        stream_version: 8,
        profile_revision: 2,
        workspace_version: 0,
        fencing_epoch: 1,
        last_transition_event_id: Some("seed-p013".to_owned()),
        last_profile_revision_id: Some("seed-profile-revision".to_owned()),
    })
    .unwrap()
}

fn wf_p001_input() -> local_agent_terminal_application::TransitionWorkflowInput {
    let evidence_digest = digest(b"evidence");
    local_agent_terminal_application::TransitionWorkflowInput {
        command_id: "command-p001".to_owned(),
        transition_event_id: "transition-p001".to_owned(),
        task_id: TaskId::new("task-1").unwrap(),
        rule_id: "WF-P001".to_owned(),
        expected_stream_version: 0,
        event: WorkflowEvent::new("task.validated").unwrap(),
        guards: vec![WorkflowGuardEvidence {
            kind: "profile_outcome_policy_budget_receipt".to_owned(),
            reference: "receipt-p001".to_owned(),
            subject_digest: None,
            evidence_digest: evidence_digest.clone(),
            artifact_id: None,
            approval_receipt_id: None,
        }],
        effects: vec![
            WorkflowEffectBinding {
                kind: "persist_base_identity".to_owned(),
                reference: "base".to_owned(),
                effect_digest: evidence_digest.clone(),
                artifact_id: None,
            },
            WorkflowEffectBinding {
                kind: "persist_outcome_mode".to_owned(),
                reference: "outcome".to_owned(),
                effect_digest: evidence_digest.clone(),
                artifact_id: None,
            },
            WorkflowEffectBinding {
                kind: "persist_risk".to_owned(),
                reference: "risk".to_owned(),
                effect_digest: evidence_digest.clone(),
                artifact_id: None,
            },
            WorkflowEffectBinding {
                kind: "persist_workflow_profile".to_owned(),
                reference: "profile".to_owned(),
                effect_digest: evidence_digest,
                artifact_id: None,
            },
        ],
        core_actor_digest: digest(b"actor"),
        reducer_version: "v3".to_owned(),
        prepared_at: Timestamp::from_unix_seconds(1_760_000_000),
    }
}

#[test]
fn accepted_workflow_transition_is_atomic_and_rehydratable() {
    let fixture = Fixture::new();
    let command = prepare_workflow_transition(
        &state_at_intake(),
        wf_p001_input(),
        ProjectId::new("project-1").unwrap(),
        ArtifactId::new("command-p001").unwrap(),
    )
    .unwrap();
    fixture.seed_command_artifact("command-p001", &command.command_artifact.canonical_bytes);

    let next = fixture.store.persist_transition(&command).unwrap();
    assert_eq!(next.phase(), Phase::ContextBuild);
    assert_eq!(next.stream_version(), 1);
    assert_eq!(
        fixture
            .store
            .load_workflow(&TaskId::new("task-1").unwrap())
            .unwrap()
            .phase(),
        Phase::ContextBuild
    );
    let connection = fixture.connection();
    assert_eq!(
        connection
            .query_row(
                "SELECT status FROM workflow_transition_events WHERE id = 'transition-p001'",
                [],
                |row| row.get::<_, String>(0),
            )
            .unwrap(),
        "accepted"
    );
}

#[test]
fn untrusted_core_actor_is_rejected_without_publication_or_authority_mutation() {
    let fixture = Fixture::new();
    let mut request = wf_p001_input();
    request.core_actor_digest = digest(b"caller-selected-actor");
    let command = prepare_workflow_transition(
        &state_at_intake(),
        request,
        ProjectId::new("project-1").unwrap(),
        ArtifactId::new("command-untrusted-actor").unwrap(),
    )
    .unwrap();
    fixture.seed_command_artifact(
        "command-untrusted-actor",
        &command.command_artifact.canonical_bytes,
    );

    let error = fixture.store.persist_transition(&command).unwrap_err();

    assert_eq!(
        error.safe_classification(),
        SafeErrorClassification::Conflict
    );
    assert_eq!(
        fixture
            .connection()
            .query_row(
                "SELECT count(*) FROM workflow_transition_events",
                [],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
        0
    );
}

#[test]
fn regressed_clock_persists_a_monotonic_rfc3339_authority_timestamp() {
    let fixture = Fixture::new();
    fixture
        .connection()
        .execute(
            "UPDATE task_workflow_authority
             SET updated_at = '2099-01-01T00:00:00.000Z'
             WHERE task_id = 'task-1'",
            [],
        )
        .unwrap();
    assert_eq!(
        fixture
            .connection()
            .query_row(
                "SELECT strftime('%Y-%m-%dT%H:%M:%fZ', updated_at, '+1 second')
                 FROM task_workflow_authority WHERE task_id = 'task-1'",
                [],
                |row| row.get::<_, Option<String>>(0),
            )
            .unwrap()
            .as_deref(),
        Some("2099-01-01T00:00:01.000Z")
    );
    let mut request = wf_p001_input();
    request.command_id = "command-clock-regression".to_owned();
    request.transition_event_id = "transition-clock-regression".to_owned();
    let command = prepare_workflow_transition(
        &state_at_intake(),
        request,
        ProjectId::new("project-1").unwrap(),
        ArtifactId::new("command-clock-regression").unwrap(),
    )
    .unwrap();
    fixture.seed_command_artifact(
        "command-clock-regression",
        &command.command_artifact.canonical_bytes,
    );

    fixture.store.persist_transition(&command).unwrap();

    let accepted_at: String = fixture
        .connection()
        .query_row(
            "SELECT accepted_at FROM workflow_transition_events
             WHERE id = 'transition-clock-regression'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(accepted_at, "2099-01-01T00:00:01.000Z");
    assert!(!accepted_at.ends_with('~'));
}

#[test]
fn wf_p015_accepts_exact_approval_receipt_and_required_effects() {
    let fixture = Fixture::new();
    seed_plan_approval_authority(&fixture);
    let command = prepare_workflow_transition(
        &state_at_plan_approval(),
        wf_p015_input(),
        ProjectId::new("project-1").unwrap(),
        ArtifactId::new("command-p015").unwrap(),
    )
    .unwrap();
    fixture.seed_command_artifact("command-p015", &command.command_artifact.canonical_bytes);

    let next = fixture
        .store
        .persist_transition(&command)
        .unwrap_or_else(|error| panic!("persist WF-P015 failed: {error:?}"));
    assert_eq!(next.phase(), Phase::Implementation);
    assert_eq!(next.stream_version(), 9);
    assert_eq!(next.fencing_token().get(), 2);
    assert_eq!(
        fixture
            .store
            .load_workflow(&TaskId::new("task-1").unwrap())
            .unwrap()
            .phase(),
        Phase::Implementation
    );
    let connection = fixture.connection();
    assert_eq!(
        connection
            .query_row(
                "SELECT count(*) FROM workflow_transition_guard_bindings
                 WHERE transition_event_id = 'transition-p015'
                   AND approval_receipt_id = 'approval-receipt-1'",
                [],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
        1
    );
}

#[test]
fn missing_or_unverified_command_artifact_does_not_mutate_authority() {
    let fixture = Fixture::new();
    let command = prepare_workflow_transition(
        &state_at_intake(),
        wf_p001_input(),
        ProjectId::new("project-1").unwrap(),
        ArtifactId::new("command-missing").unwrap(),
    )
    .unwrap();
    let error = fixture.store.persist_transition(&command).unwrap_err();
    assert_eq!(
        error.safe_classification(),
        SafeErrorClassification::IntegrityFailure
    );
    let connection = fixture.connection();
    assert_eq!(
        connection
            .query_row(
                "SELECT count(*) FROM workflow_transition_events",
                [],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
        0
    );
}

#[test]
fn missing_artifact_reader_does_not_mutate_authority() {
    let fixture = Fixture::new();
    let command = prepare_workflow_transition(
        &state_at_intake(),
        wf_p001_input(),
        ProjectId::new("project-1").unwrap(),
        ArtifactId::new("command-p001").unwrap(),
    )
    .unwrap();
    fixture.seed_command_artifact("command-p001", &command.command_artifact.canonical_bytes);
    let store = SqliteStore::open(&fixture.path)
        .unwrap()
        .with_workflow_core_actor_digest(digest(b"actor"));

    let error = store.persist_transition(&command).unwrap_err();
    assert_eq!(
        error.safe_classification(),
        SafeErrorClassification::Unavailable
    );
    assert_eq!(
        fixture
            .connection()
            .query_row(
                "SELECT count(*) FROM workflow_transition_events",
                [],
                |row| { row.get::<_, i64>(0) }
            )
            .unwrap(),
        0
    );
}

#[test]
fn cross_task_evidence_is_rejected_before_event_insertion() {
    let fixture = Fixture::new();
    let connection = fixture.connection();
    connection
        .execute(
            "INSERT INTO tasks (
                id, project_id, title, objective, phase, condition, operation_state,
                risk_level, base_branch, base_commit, current_sequence, workspace_version,
                fencing_epoch, row_version, created_at, updated_at
             ) VALUES ('task-2', 'project-1', 'Other', 'Other', 'Intake',
                'Active', 'None', 'low', 'main', ?1, 0, 0, 1, 0,
                '2026-08-09T00:00:00Z', '2026-08-09T00:00:00Z')",
            ["b".repeat(40)],
        )
        .unwrap();
    let evidence_bytes = b"cross-task evidence";
    let evidence_digest = digest(evidence_bytes);
    let evidence_artifact = fixture
        .artifacts
        .put(NewArtifact {
            expected_hash: evidence_digest.as_str().to_owned(),
            expected_size: u64::try_from(evidence_bytes.len()).unwrap(),
            content: evidence_bytes.to_vec(),
        })
        .unwrap();
    connection
        .execute(
            "INSERT INTO artifacts (
                id, task_id, project_id, artifact_type, logical_path, content_hash,
                storage_key, size_bytes, mime_type, availability, created_by_type,
                created_by_id, created_at, supersedes, verification_state
             ) VALUES ('cross-task-evidence', 'task-2', 'project-1', 'receipt',
                'receipt/cross-task', ?1, ?2, ?3,
                'application/json', 'available', 'core', 'test',
                '2026-08-09T00:00:00Z', NULL, 'hash_verified')",
            params![
                evidence_digest.as_str(),
                evidence_artifact.storage_key,
                i64::try_from(evidence_bytes.len()).unwrap()
            ],
        )
        .unwrap();

    let mut input = wf_p001_input();
    input.command_id = "command-cross-task".to_owned();
    input.guards[0].artifact_id = Some(ArtifactId::new("cross-task-evidence").unwrap());
    let command = prepare_workflow_transition(
        &state_at_intake(),
        input,
        ProjectId::new("project-1").unwrap(),
        ArtifactId::new("command-cross-task").unwrap(),
    )
    .unwrap();
    fixture.seed_command_artifact(
        "command-cross-task",
        &command.command_artifact.canonical_bytes,
    );
    let error = fixture.store.persist_transition(&command).unwrap_err();
    assert_eq!(
        error.safe_classification(),
        SafeErrorClassification::IntegrityFailure
    );
    assert_eq!(
        fixture
            .connection()
            .query_row(
                "SELECT count(*) FROM workflow_transition_events",
                [],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
        0
    );
}

#[test]
fn stale_replay_is_conflict_without_a_second_event() {
    let fixture = Fixture::new();
    let mut input = wf_p001_input();
    input.command_id = "command-replay".to_owned();
    let command = prepare_workflow_transition(
        &state_at_intake(),
        input,
        ProjectId::new("project-1").unwrap(),
        ArtifactId::new("command-replay").unwrap(),
    )
    .unwrap();
    fixture.seed_command_artifact("command-replay", &command.command_artifact.canonical_bytes);
    fixture.store.persist_transition(&command).unwrap();
    let error = fixture.store.persist_transition(&command).unwrap_err();
    assert_eq!(
        error.safe_classification(),
        SafeErrorClassification::Conflict
    );
    assert_eq!(
        fixture
            .connection()
            .query_row(
                "SELECT count(*) FROM workflow_transition_events",
                [],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
        1
    );
}

#[test]
fn raw_accepted_replay_reaches_terminal_event_immutability_trigger() {
    let fixture = Fixture::new();
    fixture.seed_transition_artifact("raw-replay");
    seed_accepted_transition(
        &fixture,
        "raw-replay",
        "WF-P001",
        "task.validated",
        "Intake",
        "ContextBuild",
        "Standard",
        0,
        "2026-08-09T00:00:01.000Z",
    );

    let error = fixture
        .connection()
        .execute(
            "UPDATE workflow_transition_events
             SET status = 'accepted', accepted_at = '2026-08-09T00:00:02.000Z'
             WHERE id = 'raw-replay'",
            [],
        )
        .unwrap_err();

    assert!(error
        .to_string()
        .contains("terminal workflow transition event is immutable"));
}

#[test]
fn raw_cross_task_plan_receipt_reaches_exact_receipt_trigger() {
    let fixture = Fixture::new();
    seed_plan_approval_authority(&fixture);
    seed_other_task_plan_approval_receipt(&fixture);
    fixture.seed_transition_artifact("raw-cross-task-receipt");
    let connection = fixture.connection();
    let binding_digest = digest(b"raw-cross-task-receipt");
    connection
        .execute(
            "INSERT INTO workflow_transition_events (
                id, task_id, rule_id, expected_stream_version, from_phase, event_type,
                to_phase, workflow_profile, outcome_mode, transition_command_artifact_id,
                guard_set_digest, effect_set_digest, core_actor_digest, reducer_version,
                status, prepared_at, accepted_at, rejected_at
             ) VALUES ('raw-cross-task-receipt', 'task-1', 'WF-P015', 8,
                'AwaitingPlanApproval', 'plan.approved', 'Implementation',
                'HighAssurance', 'WorkspaceChange', 'raw-cross-task-receipt',
                ?1, ?1, ?1, 'v3', 'prepared',
                '2026-08-09T00:00:10.000Z', NULL, NULL)",
            [binding_digest.as_str()],
        )
        .unwrap();

    let error = connection
        .execute(
            "INSERT INTO workflow_transition_guard_bindings (
                transition_event_id, evidence_kind, evidence_ref, subject_digest,
                evidence_digest, artifact_id, approval_receipt_id, acceptance_receipt_id,
                verification_receipt_id, ref_promotion_receipt_id
             ) VALUES ('raw-cross-task-receipt', 'plan_approval_receipt',
                'task-2-approval-receipt', ?1, ?2, NULL,
                'task-2-approval-receipt', NULL, NULL, NULL)",
            params![
                digest(b"task-2-plan-request").as_str(),
                digest(b"task-2-approval-receipt").as_str(),
            ],
        )
        .unwrap_err();

    assert!(error
        .to_string()
        .contains("plan approval receipt must be exact and granted"));
}

#[test]
fn raw_projection_update_and_missing_bindings_are_rejected_by_v7_triggers() {
    let fixture = Fixture::new();
    let connection = fixture.connection();
    let error = connection
        .execute(
            "UPDATE task_workflow_authority SET phase = 'ContextBuild'
             WHERE task_id = 'task-1'",
            [],
        )
        .unwrap_err();
    assert!(error.to_string().contains("workflow"));

    fixture.seed_transition_artifact("raw-event");
    connection
        .execute(
            "INSERT INTO workflow_transition_events (
                id, task_id, rule_id, expected_stream_version, from_phase, event_type,
                to_phase, workflow_profile, outcome_mode, transition_command_artifact_id,
                guard_set_digest, effect_set_digest, core_actor_digest, reducer_version,
                status, prepared_at, accepted_at, rejected_at
             ) VALUES ('raw-event', 'task-1', 'WF-P001', 0, 'Intake', 'task.validated',
                'ContextBuild', 'Standard', 'WorkspaceChange', 'raw-event',
                ?1, ?1, ?1, 'v3', 'prepared', '2026-08-09T00:00:00Z', NULL, NULL)",
            [digest(b"raw").as_str()],
        )
        .unwrap();
    let error = connection
        .execute(
            "UPDATE workflow_transition_events
             SET status = 'accepted', accepted_at = '2026-08-09T00:00:01Z'
             WHERE id = 'raw-event'",
            [],
        )
        .unwrap_err();
    assert!(error.to_string().contains("missing required"));

    let fixture = Fixture::new();
    fixture.seed_transition_artifact("seed-wrong-profile-p001");
    seed_accepted_transition(
        &fixture,
        "seed-wrong-profile-p001",
        "WF-P001",
        "task.validated",
        "Intake",
        "ContextBuild",
        "Standard",
        0,
        "2026-08-09T00:00:01.000Z",
    );
    fixture.seed_transition_artifact("wrong-profile");
    let connection = fixture.connection();
    let error = connection
        .execute(
            "INSERT INTO workflow_transition_events (
                id, task_id, rule_id, expected_stream_version, from_phase, event_type,
                to_phase, workflow_profile, outcome_mode, transition_command_artifact_id,
                guard_set_digest, effect_set_digest, core_actor_digest, reducer_version,
                status, prepared_at, accepted_at, rejected_at
             ) VALUES ('wrong-profile', 'task-1', 'WF-P003', 1, 'ContextBuild',
                'context.initial.ready', 'PrePlanVerification', 'Standard', 'WorkspaceChange',
                'wrong-profile', ?1, ?1, ?1, 'v3', 'prepared',
                '2026-08-09T00:00:00Z', NULL, NULL)",
            [digest(b"wrong-profile").as_str()],
        )
        .unwrap_err();
    assert!(error
        .to_string()
        .contains("workflow transition profile route is not allowed by the rule"));

    let fixture = Fixture::new();
    fixture.seed_transition_artifact("raw-event-missing-effect");
    let connection = fixture.connection();
    let binding_digest = digest(b"raw-missing-effect");
    connection
        .execute(
            "INSERT INTO workflow_transition_events (
                id, task_id, rule_id, expected_stream_version, from_phase, event_type,
                to_phase, workflow_profile, outcome_mode, transition_command_artifact_id,
                guard_set_digest, effect_set_digest, core_actor_digest, reducer_version,
                status, prepared_at, accepted_at, rejected_at
             ) VALUES ('raw-event-missing-effect', 'task-1', 'WF-P001', 0, 'Intake',
                'task.validated', 'ContextBuild', 'Standard', 'WorkspaceChange',
                'raw-event-missing-effect', ?1, ?1, ?1, 'v3', 'prepared',
                '2026-08-09T00:00:00Z', NULL, NULL)",
            [binding_digest.as_str()],
        )
        .unwrap();
    let guard_kinds: Vec<String> = connection
        .prepare(
            "SELECT evidence_kind FROM workflow_transition_rule_guard_requirements
             WHERE rule_id = 'WF-P001'",
        )
        .unwrap()
        .query_map([], |row| row.get(0))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    for (index, kind) in guard_kinds.iter().enumerate() {
        connection
            .execute(
                "INSERT INTO workflow_transition_guard_bindings (
                    transition_event_id, evidence_kind, evidence_ref, subject_digest,
                    evidence_digest, artifact_id, approval_receipt_id, acceptance_receipt_id,
                    verification_receipt_id, ref_promotion_receipt_id
                 ) VALUES (?1, ?2, ?3, NULL, ?4, NULL, NULL, NULL, NULL, NULL)",
                params![
                    "raw-event-missing-effect",
                    kind,
                    format!("raw-missing-effect:guard:{index}"),
                    binding_digest.as_str()
                ],
            )
            .unwrap();
    }
    let error = connection
        .execute(
            "UPDATE workflow_transition_events
             SET status = 'accepted', accepted_at = '2026-08-09T00:00:01Z'
             WHERE id = 'raw-event-missing-effect'",
            [],
        )
        .unwrap_err();
    assert!(error.to_string().contains("missing required effects"));
}
