use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use local_agent_terminal_application::{
    prepare_assurance_acceptance_artifact, ArtifactStore, AssuranceAssessment, AssuranceDecision,
    AssuranceDegradationInput, AssuranceDegradationReceipt, AssuranceReasonCode,
    AssuranceRequirements, AssuranceRunEvidence, AssuranceStore, NewArtifact,
    ProfileEscalationCommand, SafeErrorClassification,
};
use local_agent_terminal_domain::{
    ArtifactId, RunId, Sha256Digest, TaskId, Timestamp, WorkflowProfile,
};
use local_agent_terminal_storage_files::{
    ContentAddressedArtifactReader, ContentAddressedArtifactStore,
};
use local_agent_terminal_storage_sqlite::SqliteStore;
use rusqlite::{params, Connection};
use sha2::{Digest, Sha256};

static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

struct Fixture {
    directory: PathBuf,
    path: PathBuf,
    artifact_root: PathBuf,
}

impl Fixture {
    fn new(profile: WorkflowProfile) -> Self {
        let directory = std::env::temp_dir().join(format!(
            "assurance-store-{}-{}",
            std::process::id(),
            NEXT_TEMP.fetch_add(1, Ordering::Relaxed)
        ));
        let artifact_root = directory.join("artifacts");
        fs::create_dir_all(&artifact_root).unwrap();
        let path = directory.join("state.sqlite3");
        SqliteStore::open(&path).unwrap();
        let fixture = Self {
            directory,
            path,
            artifact_root,
        };
        fixture.seed(profile);
        fixture
    }

    fn store(&self) -> SqliteStore {
        SqliteStore::open(&self.path)
            .unwrap()
            .with_artifact_reader(Arc::new(ContentAddressedArtifactReader))
    }

    fn connection(&self) -> Connection {
        let connection = Connection::open(&self.path).unwrap();
        connection.execute_batch("PRAGMA foreign_keys=ON;").unwrap();
        connection
    }

    fn seed(&self, profile: WorkflowProfile) {
        let connection = self.connection();
        connection.execute("INSERT INTO projects (id,name,repository_path,repository_identity,created_at,updated_at,policy_profile_id,artifact_root_mode,artifact_root_path) VALUES ('project-1','P','C:/repo',?1,'2026-08-11T00:00:00Z','2026-08-11T00:00:00Z','default','application_data',?2)", params![digest(b"repository").as_str(), self.artifact_root.to_string_lossy()]).unwrap();
        connection.execute("INSERT INTO tasks (id,project_id,title,objective,phase,condition,operation_state,risk_level,base_branch,base_commit,current_sequence,workspace_version,fencing_epoch,row_version,created_at,updated_at) VALUES ('task-1','project-1','T','O','Intake','Active','None','high','main',?1,8,0,1,0,'2026-08-11T00:00:00Z','2026-08-11T00:00:00Z')", ["a".repeat(40)]).unwrap();
        connection.execute("INSERT INTO task_workflow_authority (task_id,workflow_profile,outcome_mode,phase,selected_by_kind,selected_by_actor_binding_id,selection_policy_digest,created_at,updated_at,completed_at,stream_version,last_transition_event_id,profile_revision,last_profile_revision_id) VALUES ('task-1',?1,'WorkspaceChange','Intake','core',NULL,?2,'2026-08-11T00:00:00Z','2026-08-11T00:00:00Z',NULL,0,NULL,1,NULL)", params![profile.as_str(), digest(b"policy").as_str()]).unwrap();
        connection.execute("INSERT INTO actor_bindings (id,actor_kind,actor_id,session_id,proof_type,binding_digest,issued_at,expires_at,revoked_at,session_epoch) VALUES ('actor-binding-1','user','user-1','session-1','local_authenticated_session',?1,'2026-08-11T00:00:00Z','2026-08-11T01:00:00Z',NULL,1)", [digest(b"actor").as_str()]).unwrap();
        self.insert_artifact("reason-1", "receipt", b"profile escalation reason");
        self.insert_artifact("manifest-1", "manifest", b"{}");
        self.insert_artifact("context-1", "content", b"{}");
        self.insert_artifact("run-config-1", "run-config", b"{}");
        connection.execute("INSERT INTO agent_descriptors (id,display_name,transport_type,trust_tier,manifest_json,manifest_digest,executable_digest,enabled,last_health_status,updated_at) VALUES ('agent-1','Agent','in_process','core_adapter','{}',?1,?2,1,NULL,'2026-08-11T00:00:00Z')", params![digest(b"{}").as_str(), digest(b"agent").as_str()]).unwrap();
        connection.execute("INSERT INTO context_packages (id,task_id,agent_id,role,objective,manifest_artifact_id,effective_content_artifact_id,content_hash,policy_snapshot_digest,prompt_template_version,retrieval_pipeline_version,created_at) VALUES ('context-package-1','task-1','agent-1','reviewer','Review','manifest-1','context-1',?1,?2,'prompt-1','retrieval-1','2026-08-11T00:00:01Z')", params![digest(b"{}").as_str(), digest(b"context-policy").as_str()]).unwrap();
        connection.execute("INSERT INTO agent_runs (id,task_id,agent_id,role,phase,status,context_package_id,idempotency_key,connection_binding_digest,run_config_artifact_id,supersedes_run_id,started_at,completed_at,provider_usage_json,core_usage_json,estimated_cost_microunits,error_json) VALUES ('run-1','task-1','agent-1','reviewer','analysis','created','context-package-1','run-key',?1,'run-config-1',NULL,NULL,NULL,NULL,NULL,NULL,NULL)", [digest(b"connection").as_str()]).unwrap();
        connection.execute("INSERT INTO run_configuration_bindings (run_id,config_artifact_id,config_digest,provider_connection_ref,adapter_id,resolved_model_id,independence_group,independence_fingerprint,created_at) VALUES ('run-1','run-config-1',?1,'connection-1','openai','gpt-5','group-1',?2,'2026-08-11T00:00:01Z')", params![digest(b"semantic-config").as_str(), digest(b"independence").as_str()]).unwrap();
    }

    fn insert_artifact(
        &self,
        id: &str,
        kind: &str,
        bytes: &[u8],
    ) -> local_agent_terminal_application::ArtifactRef {
        let content_digest = digest(bytes);
        let reference = ContentAddressedArtifactStore::open(&self.artifact_root)
            .unwrap()
            .put(NewArtifact {
                expected_hash: content_digest.as_str().to_owned(),
                expected_size: bytes.len() as u64,
                content: bytes.to_vec(),
            })
            .unwrap();
        self.connection().execute("INSERT INTO artifacts (id,task_id,project_id,artifact_type,logical_path,content_hash,storage_key,size_bytes,mime_type,availability,created_by_type,created_by_id,created_at,supersedes,verification_state) VALUES (?1,'task-1','project-1',?2,?3,?4,?5,?6,'application/json','available','core','assurance','2026-08-11T00:00:01Z',NULL,'hash_verified')", params![id, kind, format!("assurance/{id}.json"), content_digest.as_str(), reference.storage_key, bytes.len() as i64]).unwrap();
        reference
    }

    fn publish_receipt(
        &self,
        receipt: &AssuranceDegradationReceipt,
    ) -> local_agent_terminal_application::ArtifactRef {
        self.insert_artifact(receipt.receipt_id(), "receipt", receipt.canonical_bytes())
    }

    fn publish_acceptance(
        &self,
        receipt: &AssuranceDegradationReceipt,
    ) -> local_agent_terminal_application::ArtifactRef {
        let artifact = prepare_assurance_acceptance_artifact(receipt).unwrap();
        let reference = ContentAddressedArtifactStore::open(&self.artifact_root)
            .unwrap()
            .put(artifact)
            .unwrap();
        self.connection().execute("INSERT INTO artifacts (id,task_id,project_id,artifact_type,logical_path,content_hash,storage_key,size_bytes,mime_type,availability,created_by_type,created_by_id,created_at,supersedes,verification_state) VALUES (?1,'task-1','project-1','assurance-acceptance',?2,?3,?4,?5,'application/json','available','user','actor-binding-1','2026-08-11T00:00:20Z',NULL,'user_approved')", params![receipt.acceptance_artifact_ref().unwrap(), format!("assurance/{}.json", receipt.acceptance_artifact_ref().unwrap()), reference.content_hash, reference.storage_key, reference.size_bytes as i64]).unwrap();
        reference
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.directory);
    }
}

#[test]
fn escalation_is_atomic_monotonic_idempotent_and_keeps_phase() {
    let fixture = Fixture::new(WorkflowProfile::Quick);
    let command = escalation(WorkflowProfile::Quick, WorkflowProfile::Standard);
    let state = fixture
        .store()
        .persist_profile_escalation(&command)
        .unwrap();
    assert_eq!(state.workflow_profile(), WorkflowProfile::Standard);
    assert_eq!(state.phase().as_str(), "Intake");
    assert_eq!(state.stream_version(), 1);
    assert_eq!(state.profile_revision(), 2);
    assert_eq!(state.last_profile_revision_id(), Some("revision-2"));

    let replay = fixture
        .store()
        .persist_profile_escalation(&command)
        .unwrap();
    assert_eq!(replay, state);
    let count: i64 = fixture
        .connection()
        .query_row(
            "SELECT COUNT(*) FROM workflow_profile_revisions",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(count, 1);
}

#[test]
fn stale_or_changed_escalations_conflict_without_mutation() {
    let fixture = Fixture::new(WorkflowProfile::Quick);
    let command = escalation(WorkflowProfile::Quick, WorkflowProfile::HighAssurance);
    fixture
        .store()
        .persist_profile_escalation(&command)
        .unwrap();

    let mut changed = command.clone();
    changed.to_profile = WorkflowProfile::Standard;
    let error = fixture
        .store()
        .persist_profile_escalation(&changed)
        .unwrap_err();
    assert_eq!(
        error.safe_classification(),
        SafeErrorClassification::Conflict
    );

    let mut stale = escalation(WorkflowProfile::Quick, WorkflowProfile::Standard);
    stale.revision_id = "revision-stale".to_owned();
    let error = fixture
        .store()
        .persist_profile_escalation(&stale)
        .unwrap_err();
    assert_eq!(
        error.safe_classification(),
        SafeErrorClassification::Conflict
    );
}

#[test]
fn exact_escalation_replay_remains_safe_after_a_later_escalation() {
    let fixture = Fixture::new(WorkflowProfile::Quick);
    let first = escalation(WorkflowProfile::Quick, WorkflowProfile::Standard);
    fixture.store().persist_profile_escalation(&first).unwrap();
    let mut second = escalation(WorkflowProfile::Standard, WorkflowProfile::HighAssurance);
    second.revision_id = "revision-3".to_owned();
    second.expected_stream_version = 1;
    second.created_at = Timestamp::from_unix_seconds(1_786_406_411);
    let latest = fixture.store().persist_profile_escalation(&second).unwrap();

    let replayed = fixture.store().persist_profile_escalation(&first).unwrap();
    assert_eq!(replayed, latest);
    assert_eq!(replayed.workflow_profile(), WorkflowProfile::HighAssurance);
    assert_eq!(replayed.stream_version(), 2);
    assert_eq!(replayed.profile_revision(), 3);
}

#[test]
fn degradation_persists_exact_physical_and_semantic_receipt_once() {
    let fixture = Fixture::new(WorkflowProfile::HighAssurance);
    let receipt = receipt(AssuranceDecision::ContinueDegraded);
    fixture.publish_acceptance(&receipt);
    let artifact = fixture.publish_receipt(&receipt);
    assert_ne!(artifact.content_hash, receipt.receipt_digest().as_str());

    fixture
        .store()
        .persist_degradation(&receipt, &artifact)
        .unwrap();
    fixture
        .connection()
        .execute(
            "UPDATE actor_bindings SET revoked_at='2026-08-11T00:00:30Z'
             WHERE id='actor-binding-1'",
            [],
        )
        .unwrap();
    fixture
        .store()
        .persist_degradation(&receipt, &artifact)
        .unwrap();
    let stored: (String, String, String, String) = fixture.connection().query_row("SELECT requested_profile,decision,actor_binding_id,receipt_digest FROM assurance_degradation_receipts WHERE id='degradation-1'", [], |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?))).unwrap();
    assert_eq!(stored.0, "HighAssurance");
    assert_eq!(stored.1, "continue_degraded");
    assert_eq!(stored.2, "actor-binding-1");
    assert_eq!(stored.3, receipt.receipt_digest().as_str());
}

#[test]
fn degradation_rejects_missing_actor_acceptance_and_physical_tampering() {
    let fixture = Fixture::new(WorkflowProfile::HighAssurance);
    let receipt = receipt(AssuranceDecision::ContinueDegraded);
    fixture.publish_acceptance(&receipt);
    let artifact = fixture.publish_receipt(&receipt);
    fs::write(
        fixture.artifact_root.join(&artifact.storage_key),
        b"tampered",
    )
    .unwrap();
    let error = fixture
        .store()
        .persist_degradation(&receipt, &artifact)
        .unwrap_err();
    assert_eq!(
        error.safe_classification(),
        SafeErrorClassification::IntegrityFailure
    );
    let count: i64 = fixture
        .connection()
        .query_row(
            "SELECT COUNT(*) FROM assurance_degradation_receipts",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(count, 0);
}

#[test]
fn degradation_rejects_an_arbitrary_verified_task_artifact_as_acceptance() {
    let fixture = Fixture::new(WorkflowProfile::HighAssurance);
    let receipt = receipt(AssuranceDecision::ContinueDegraded);
    fixture.insert_artifact(
        "artifact/acceptance-1",
        "receipt",
        b"not an assurance acceptance",
    );
    let artifact = fixture.publish_receipt(&receipt);

    let error = fixture
        .store()
        .persist_degradation(&receipt, &artifact)
        .unwrap_err();
    assert_eq!(
        error.safe_classification(),
        SafeErrorClassification::Conflict
    );
}

#[test]
fn degradation_rejects_a_run_set_without_normative_bindings() {
    let fixture = Fixture::new(WorkflowProfile::HighAssurance);
    let receipt = AssuranceDegradationReceipt::issue(AssuranceDegradationInput {
        receipt_id: "degradation-unbound".to_owned(),
        task_id: TaskId::new("task-1").unwrap(),
        requested_profile: WorkflowProfile::HighAssurance,
        requirements: AssuranceRequirements {
            minimum_distinct_independence_groups: 3,
            executor_reviewer_separation_required: true,
        },
        assessment: AssuranceAssessment {
            runs: vec![
                AssuranceRunEvidence {
                    run_id: RunId::new("run-1").unwrap(),
                    independence_group: "group-1".to_owned(),
                },
                AssuranceRunEvidence {
                    run_id: RunId::new("run-unbound").unwrap(),
                    independence_group: "group-forged".to_owned(),
                },
            ],
            executor_run_id: Some(RunId::new("run-1").unwrap()),
            reviewer_run_id: Some(RunId::new("run-unbound").unwrap()),
        },
        reason_code: AssuranceReasonCode::InsufficientIndependenceGroups,
        decision: AssuranceDecision::Pause,
        actor_binding_id: None,
        acceptance_artifact_ref: None,
        created_at: Timestamp::from_unix_seconds(1_786_406_420),
    })
    .unwrap();
    let artifact = fixture.publish_receipt(&receipt);

    let error = fixture
        .store()
        .persist_degradation(&receipt, &artifact)
        .unwrap_err();
    assert_eq!(
        error.safe_classification(),
        SafeErrorClassification::Conflict
    );
}

fn escalation(
    from_profile: WorkflowProfile,
    to_profile: WorkflowProfile,
) -> ProfileEscalationCommand {
    ProfileEscalationCommand {
        revision_id: "revision-2".to_owned(),
        task_id: TaskId::new("task-1").unwrap(),
        expected_stream_version: 0,
        from_profile,
        to_profile,
        reason_artifact_id: ArtifactId::new("reason-1").unwrap(),
        policy_digest: digest(b"profile-policy"),
        actor_binding_id: None,
        created_at: Timestamp::from_unix_seconds(1_786_406_410),
    }
}

fn receipt(decision: AssuranceDecision) -> AssuranceDegradationReceipt {
    AssuranceDegradationReceipt::issue(AssuranceDegradationInput {
        receipt_id: "degradation-1".to_owned(),
        task_id: TaskId::new("task-1").unwrap(),
        requested_profile: WorkflowProfile::HighAssurance,
        requirements: AssuranceRequirements {
            minimum_distinct_independence_groups: 2,
            executor_reviewer_separation_required: true,
        },
        assessment: AssuranceAssessment {
            runs: vec![AssuranceRunEvidence {
                run_id: RunId::new("run-1").unwrap(),
                independence_group: "group-1".to_owned(),
            }],
            executor_run_id: Some(RunId::new("run-1").unwrap()),
            reviewer_run_id: Some(RunId::new("run-1").unwrap()),
        },
        reason_code: AssuranceReasonCode::InsufficientIndependenceGroups,
        decision,
        actor_binding_id: matches!(decision, AssuranceDecision::ContinueDegraded)
            .then(|| "actor-binding-1".to_owned()),
        acceptance_artifact_ref: matches!(decision, AssuranceDecision::ContinueDegraded)
            .then(|| "artifact/acceptance-1".to_owned()),
        created_at: Timestamp::from_unix_seconds(1_786_406_420),
    })
    .unwrap()
}

fn digest(bytes: &[u8]) -> Sha256Digest {
    Sha256Digest::new(format!("sha256:{:x}", Sha256::digest(bytes))).unwrap()
}
