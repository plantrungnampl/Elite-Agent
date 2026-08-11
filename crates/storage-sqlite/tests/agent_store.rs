use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU64, Ordering};
use std::sync::Arc;

use local_agent_terminal_agent_protocol::{
    ConnectionBinding, PeerDescriptor, ProtocolCapabilities, ProtocolError, ProtocolPeer,
    ProtocolTrustTier,
};
use local_agent_terminal_agent_runtime::{
    MaliciousScript, ProtocolAgentRuntime, Script, ScriptedPeer, DEFAULT_HEARTBEAT_TIMEOUT_SECS,
};
use local_agent_terminal_application::{
    AgentArtifactStore, AgentMessageArtifact, AgentRunStore, AgentRuntime, ArtifactRef,
    ArtifactStore, Clock, NewArtifact, PortError, Retryability, SafeErrorClassification,
};
use local_agent_terminal_domain::{
    AgentDescriptor, AgentRunLimits, AgentRunMessage, AgentRunStatus, AgentRunTerminal, AgentUsage,
    ArtifactId, BoundAgentConnection, BoundAgentRunRequest, BoundEffectiveContext,
    BoundGenerationParameters, BoundRunConfig, Phase, RunId, Sha256Digest, TaskId, Timestamp,
    TrustTier,
};
use local_agent_terminal_storage_files::{
    ContentAddressedArtifactReader, ContentAddressedArtifactStore,
};
use local_agent_terminal_storage_sqlite::{canonical_agent_run_config_artifact, SqliteStore};
use rusqlite::{params, Connection};
use serde_json::Value;
use sha2::{Digest, Sha256};

const EMPTY_JSON_DIGEST: &str =
    "sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a";
const CONNECTION_BINDING_DIGEST: &str =
    "sha256:6e171d4e7a1d7b7db1c14807e8a2a5cc9093eac495d66a2ca76439264d09b7d5";
const CONTEXT_BYTES: &[u8] = br#"{"context":"bound"}"#;
const RFC8785_GENERATION_DIGEST: &str =
    "sha256:0ac6c8907856746804e71de596b1ddceed49d53b3c52035da285c42271851863";
const RFC8785_RUN_CONFIG_DIGEST: &str =
    "sha256:e730df0d28bc2827af7d559c318357a1e79107661d5f6ace658d8117e4a057f0";

static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

struct TestDatabase {
    directory: PathBuf,
    path: PathBuf,
    artifact_root: PathBuf,
}

impl TestDatabase {
    fn new() -> Self {
        let directory = std::env::temp_dir().join(format!(
            "local-agent-terminal-agent-store-test-{}-{}",
            std::process::id(),
            NEXT_TEMP.fetch_add(1, Ordering::Relaxed),
        ));
        let artifact_root = directory.join("artifacts");
        fs::create_dir_all(&artifact_root).unwrap();
        let path = directory.join("state.sqlite3");
        SqliteStore::open(&path).unwrap();
        let database = Self {
            directory,
            path,
            artifact_root,
        };
        database.seed_task("task-1");
        database.seed_task("task-2");
        database
    }

    fn store(&self) -> SqliteStore {
        SqliteStore::open(&self.path)
            .unwrap()
            .with_artifact_reader(Arc::new(ContentAddressedArtifactReader))
    }

    fn connection(&self) -> Connection {
        let connection = Connection::open(&self.path).unwrap();
        connection
            .execute_batch("PRAGMA foreign_keys = ON;")
            .unwrap();
        connection
    }

    fn seed_task(&self, task_id: &str) {
        let connection = self.connection();
        connection
            .execute(
                "INSERT OR IGNORE INTO projects (
                    id, name, repository_path, repository_identity, created_at, updated_at,
                    policy_profile_id, artifact_root_mode, artifact_root_path
                 ) VALUES ('project-1', 'Project', 'C:/repo', 'repo-identity',
                    '1970-01-01T00:00:00Z', '1970-01-01T00:00:00Z', 'default',
                    'application_data', ?1)",
                [self.artifact_root.to_string_lossy().as_ref()],
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO tasks (
                    id, project_id, title, objective, phase, condition, operation_state,
                    risk_level, base_branch, base_commit, current_sequence, workspace_version,
                    fencing_epoch, created_at, updated_at
                 ) VALUES (?1, 'project-1', 'Task', 'Persist agent run', 'Implementation', 'Active',
                    'None', 'low', 'main', '0123456789abcdef0123456789abcdef01234567',
                    0, 0, 1, '1970-01-01T00:00:00Z', '1970-01-01T00:00:00Z')",
                [task_id],
            )
            .unwrap();
    }

    fn put_artifact(&self, artifact_id: &ArtifactId, task_id: &str, kind: &str, bytes: &[u8]) {
        self.put_artifact_with_storage_key(artifact_id, task_id, kind, bytes, None);
    }

    fn put_artifact_with_storage_key(
        &self,
        artifact_id: &ArtifactId,
        task_id: &str,
        kind: &str,
        bytes: &[u8],
        storage_key_override: Option<&str>,
    ) {
        let content_hash = digest_bytes(bytes);
        let reference = ContentAddressedArtifactStore::open(&self.artifact_root)
            .unwrap()
            .put(NewArtifact {
                expected_hash: content_hash.as_str().to_owned(),
                expected_size: u64::try_from(bytes.len()).unwrap(),
                content: bytes.to_vec(),
            })
            .unwrap();
        let storage_key = storage_key_override.unwrap_or(&reference.storage_key);
        if storage_key_override.is_some() {
            let substituted_path = self.artifact_root.join(storage_key);
            fs::create_dir_all(substituted_path.parent().unwrap()).unwrap();
            fs::copy(
                self.artifact_root.join(&reference.storage_key),
                &substituted_path,
            )
            .unwrap();
        }
        self.connection()
            .execute(
                "INSERT OR REPLACE INTO artifacts (
                    id, task_id, project_id, artifact_type, logical_path, content_hash,
                    storage_key, size_bytes, mime_type, availability, created_by_type,
                    created_by_id, created_at, supersedes, verification_state
                 ) VALUES (?1, ?2, 'project-1', ?3, ?4, ?5, ?6, ?7, 'application/json',
                    'available', 'core', 'core', '1970-01-01T00:00:01Z', NULL, 'hash_verified')",
                params![
                    artifact_id.as_str(),
                    task_id,
                    kind,
                    format!("agent/{}.json", artifact_id.as_str()),
                    content_hash.as_str(),
                    storage_key,
                    i64::try_from(bytes.len()).unwrap(),
                ],
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
fn descriptor_registration_is_idempotent_only_for_exact_canonical_bytes() {
    let database = TestDatabase::new();
    let store = database.store();
    let descriptor = descriptor();

    store.register_descriptor(&descriptor).unwrap();
    store.register_descriptor(&descriptor).unwrap();

    assert_eq!(row_count(&database.path, "agent_descriptors"), 1);

    let mut manifest_drift = descriptor.clone();
    manifest_drift.manifest_json = br#"{"version":1}"#.to_vec();
    manifest_drift.manifest_digest = digest_bytes(&manifest_drift.manifest_json);
    assert_eq!(
        store
            .register_descriptor(&manifest_drift)
            .unwrap_err()
            .safe_classification(),
        SafeErrorClassification::Conflict,
    );

    let mut executable_drift = descriptor.clone();
    executable_drift.executable_digest = Some(digest('c'));
    assert_eq!(
        store
            .register_descriptor(&executable_drift)
            .unwrap_err()
            .safe_classification(),
        SafeErrorClassification::Conflict,
    );

    let mut noncanonical = descriptor;
    noncanonical.agent_id = "agent-2".to_owned();
    noncanonical.manifest_json = br#"{ "id": "agent-2" }"#.to_vec();
    noncanonical.manifest_digest = digest_bytes(&noncanonical.manifest_json);
    assert_eq!(
        store
            .register_descriptor(&noncanonical)
            .unwrap_err()
            .safe_classification(),
        SafeErrorClassification::InvalidInput,
    );
}

#[test]
fn rfc8785_canonical_bytes_and_digests_survive_run_reconstruction() {
    let raw: Value = serde_json::from_str(r#"{"\uE000":1,"\uD83D\uDE00":-0.0}"#).unwrap();
    let canonical = serde_json_canonicalizer::to_vec(&raw).unwrap();
    assert_eq!(
        canonical,
        format!(r#"{{"{}":0,"{}":1}}"#, '\u{1f600}', '\u{e000}').as_bytes(),
    );
    assert_eq!(digest_bytes(&canonical).as_str(), RFC8785_GENERATION_DIGEST);

    let database = TestDatabase::new();
    let store = database.store();
    let mut canonical_descriptor = descriptor();
    canonical_descriptor.agent_id = "agent-rfc8785".to_owned();
    canonical_descriptor.manifest_json = canonical.clone();
    canonical_descriptor.manifest_digest = digest_from_str(RFC8785_GENERATION_DIGEST);
    store.register_descriptor(&canonical_descriptor).unwrap();

    let mut noncanonical_descriptor = canonical_descriptor;
    noncanonical_descriptor.agent_id = "agent-rfc8785-noncanonical".to_owned();
    noncanonical_descriptor.manifest_json =
        r#"{"\uE000":1,"\uD83D\uDE00":-0.0}"#.as_bytes().to_vec();
    noncanonical_descriptor.manifest_digest = digest_bytes(&noncanonical_descriptor.manifest_json);
    assert_eq!(
        store
            .register_descriptor(&noncanonical_descriptor)
            .unwrap_err()
            .safe_classification(),
        SafeErrorClassification::InvalidInput,
    );

    let descriptor = descriptor();
    store.register_descriptor(&descriptor).unwrap();
    let mut request = bound_run("rfc8785", "rfc8785-key");
    request.run_config.generation_parameters = BoundGenerationParameters {
        canonical_json: canonical,
        digest: digest_from_str(RFC8785_GENERATION_DIGEST),
    };
    request.validate().unwrap();
    let run_config = canonical_agent_run_config_artifact(&request).unwrap();
    assert_eq!(
        digest_bytes(&run_config).as_str(),
        RFC8785_RUN_CONFIG_DIGEST,
    );
    seed_default_artifacts(&database, &request, &descriptor);
    store.create_bound_run(&request).unwrap();
    drop(store);

    assert_eq!(
        database
            .store()
            .load_run(&request.run_id)
            .unwrap()
            .unwrap()
            .request,
        request,
    );
}

#[test]
fn canonical_run_config_v2_binds_each_new_limit_to_bytes_and_digest() {
    let baseline = bound_run("canonical-limits", "canonical-limits-key");
    let baseline_bytes = canonical_agent_run_config_artifact(&baseline).unwrap();
    let baseline_digest = digest_bytes(&baseline_bytes);
    let value: Value = serde_json::from_slice(&baseline_bytes).unwrap();
    assert_eq!(value["schema"], "agent-run-config.v2");

    let mut context_queries = baseline.clone();
    context_queries.run_config.limits.max_context_queries = 1;
    let mut specialist_requests = baseline;
    specialist_requests
        .run_config
        .limits
        .max_specialist_requests = 1;

    for changed in [context_queries, specialist_requests] {
        let changed_bytes = canonical_agent_run_config_artifact(&changed).unwrap();
        assert_ne!(changed_bytes, baseline_bytes);
        assert_ne!(digest_bytes(&changed_bytes), baseline_digest);
    }
}

#[test]
fn nonzero_run_limits_survive_persistence_and_reopen() {
    let database = TestDatabase::new();
    let store = database.store();
    let descriptor = descriptor();
    let mut request = bound_run("limits", "limits-key");
    request.run_config.limits.max_context_queries = 7;
    request.run_config.limits.max_specialist_requests = 9;
    request.validate().unwrap();
    store.register_descriptor(&descriptor).unwrap();
    seed_default_artifacts(&database, &request, &descriptor);

    store.create_bound_run(&request).unwrap();
    drop(store);
    let reconstructed = database.store().load_run(&request.run_id).unwrap().unwrap();

    assert_eq!(
        reconstructed.request.run_config.limits,
        request.run_config.limits
    );
}

#[test]
fn legacy_v1_run_config_artifacts_default_new_limits_to_zero() {
    let database = TestDatabase::new();
    let store = database.store();
    let descriptor = descriptor();
    let request = bound_run("legacy-v1", "legacy-v1-key");
    store.register_descriptor(&descriptor).unwrap();
    seed_historical_created_run(
        &database,
        &request,
        &descriptor,
        &legacy_v1_run_config_artifact(&request),
    );
    drop(store);

    let reconstructed = database.store().load_run(&request.run_id).unwrap().unwrap();
    assert_eq!(
        reconstructed.request.run_config.limits.max_context_queries,
        0
    );
    assert_eq!(
        reconstructed
            .request
            .run_config
            .limits
            .max_specialist_requests,
        0,
    );
}

#[test]
fn run_config_parser_rejects_nonexact_or_unknown_versioned_shapes() {
    assert_historical_run_config_rejected("v1-extra", |value| {
        value["schema"] = Value::String("agent-run-config.v1".to_owned());
        let limits = value["runConfig"]["limits"].as_object_mut().unwrap();
        limits.remove("maxContextQueries");
        limits.remove("maxSpecialistRequests");
        limits.insert("maxContextQueries".to_owned(), Value::from(0));
    });
    assert_historical_run_config_rejected("v2-missing", |value| {
        value["schema"] = Value::String("agent-run-config.v2".to_owned());
        let limits = value["runConfig"]["limits"].as_object_mut().unwrap();
        limits.insert("maxContextQueries".to_owned(), Value::from(0));
        limits.remove("maxSpecialistRequests");
    });
    assert_historical_run_config_rejected("unknown", |value| {
        value["schema"] = Value::String("agent-run-config.v3".to_owned());
    });
}

#[test]
fn create_bound_run_rejects_missing_foreign_mismatched_or_wrong_kind_artifacts() {
    let database = TestDatabase::new();
    let store = database.store();
    let descriptor = descriptor();
    store.register_descriptor(&descriptor).unwrap();

    let missing = bound_run("missing", "missing-key");
    assert_integrity_failure(store.create_bound_run(&missing));

    let foreign_context = bound_run("foreign-context", "foreign-context-key");
    seed_bound_artifacts(
        &database,
        &foreign_context,
        &descriptor,
        "task-1",
        "task-2",
        "task-1",
        "run-config",
    );
    assert_integrity_failure(store.create_bound_run(&foreign_context));

    let foreign_config = bound_run("foreign-config", "foreign-config-key");
    seed_bound_artifacts(
        &database,
        &foreign_config,
        &descriptor,
        "task-1",
        "task-1",
        "task-2",
        "run-config",
    );
    assert_integrity_failure(store.create_bound_run(&foreign_config));

    let wrong_kind = bound_run("wrong-kind", "wrong-kind-key");
    seed_bound_artifacts(
        &database,
        &wrong_kind,
        &descriptor,
        "task-1",
        "task-1",
        "task-1",
        "report",
    );
    assert_integrity_failure(store.create_bound_run(&wrong_kind));

    let mismatched_config = bound_run("mismatched-config", "mismatched-config-key");
    seed_bound_artifacts(
        &database,
        &mismatched_config,
        &descriptor,
        "task-1",
        "task-1",
        "task-1",
        "run-config",
    );
    database.put_artifact(
        &mismatched_config.run_config.run_config_artifact_id,
        "task-1",
        "run-config",
        br#"{"schema":"agent-run-config.v1"}"#,
    );
    assert_integrity_failure(store.create_bound_run(&mismatched_config));
}

#[test]
fn available_artifact_with_non_hash_derived_storage_key_is_rejected() {
    let database = TestDatabase::new();
    let store = database.store();
    let descriptor = descriptor();
    let request = bound_run("wrong-storage-key", "wrong-storage-key-idempotency");
    store.register_descriptor(&descriptor).unwrap();
    database.put_artifact(
        &request.context.manifest_artifact_id,
        "task-1",
        "manifest",
        &descriptor.manifest_json,
    );
    database.put_artifact(
        &request.context.effective_context_artifact_id,
        "task-1",
        "content",
        CONTEXT_BYTES,
    );
    database.put_artifact_with_storage_key(
        &request.run_config.run_config_artifact_id,
        "task-1",
        "run-config",
        &canonical_agent_run_config_artifact(&request).unwrap(),
        Some("objects/00/not-the-content-hash"),
    );

    assert_integrity_failure(store.create_bound_run(&request));
}

#[test]
fn pre_persisted_context_is_reused_exactly_and_changed_payload_with_same_identity_conflicts() {
    let database = TestDatabase::new();
    let store = database.store();
    let descriptor = descriptor();
    store.register_descriptor(&descriptor).unwrap();
    let request = bound_run("pre-persisted-context", "pre-persisted-context-key");
    seed_default_artifacts(&database, &request, &descriptor);
    database
        .connection()
        .execute(
            "INSERT INTO context_packages (
                id, task_id, agent_id, role, objective, manifest_artifact_id,
                effective_content_artifact_id, content_hash, policy_snapshot_digest,
                prompt_template_version, retrieval_pipeline_version, created_at
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11,
                strftime('%Y-%m-%dT%H:%M:%SZ', ?12, 'unixepoch'))",
            params![
                request.context.context_package_id,
                request.context.task_id.as_str(),
                request.context.agent_id,
                request.context.role,
                request.context.objective,
                request.context.manifest_artifact_id.as_str(),
                request.context.effective_context_artifact_id.as_str(),
                request.context.content_digest.as_str(),
                request.context.policy_snapshot_digest.as_str(),
                request.context.prompt_template_version,
                request.context.retrieval_pipeline_version,
                request.context.created_at.unix_seconds(),
            ],
        )
        .unwrap();

    store.create_bound_run(&request).unwrap();

    let mut changed = request.clone();
    changed.run_id = RunId::new("run-pre-persisted-context-changed").unwrap();
    changed.idempotency_key = "pre-persisted-context-changed-key".to_owned();
    changed.context.objective = "changed objective".to_owned();
    assert_eq!(
        store
            .create_bound_run(&changed)
            .unwrap_err()
            .safe_classification(),
        SafeErrorClassification::Conflict
    );
    assert_eq!(
        database
            .connection()
            .query_row("SELECT COUNT(*) FROM agent_runs", [], |row| {
                row.get::<_, i64>(0)
            })
            .unwrap(),
        1
    );
}

#[test]
fn duplicate_idempotency_key_conflicts_but_exact_replay_is_idempotent() {
    let database = TestDatabase::new();
    let store = database.store();
    let descriptor = descriptor();
    store.register_descriptor(&descriptor).unwrap();
    let first = bound_run("first", "shared-key");
    seed_default_artifacts(&database, &first, &descriptor);

    let created = store.create_bound_run(&first).unwrap();
    assert_eq!(store.create_bound_run(&first).unwrap(), created);

    let duplicate = bound_run("duplicate", "shared-key");
    seed_default_artifacts(&database, &duplicate, &descriptor);
    assert_eq!(
        store
            .create_bound_run(&duplicate)
            .unwrap_err()
            .safe_classification(),
        SafeErrorClassification::Conflict,
    );
}

#[test]
fn terminal_run_can_be_superseded_by_a_new_bound_run() {
    let database = TestDatabase::new();
    let store = database.store();
    let descriptor = descriptor();
    store.register_descriptor(&descriptor).unwrap();
    let first = bound_run("first", "first-key");
    seed_default_artifacts(&database, &first, &descriptor);
    store.create_bound_run(&first).unwrap();
    assert_eq!(
        store
            .interrupt_connection(first.connection.binding_digest.as_str(), timestamp(5))
            .unwrap(),
        vec![first.run_id.clone()],
    );

    let mut replacement = bound_run("replacement", "replacement-key");
    replacement.supersedes_run_id = Some(first.run_id);
    seed_default_artifacts(&database, &replacement, &descriptor);

    assert_eq!(
        store.create_bound_run(&replacement).unwrap().request,
        replacement,
    );
}

#[test]
fn lifecycle_moves_forward_and_reopens_with_exact_acceptance_and_start_times() {
    let database = TestDatabase::new();
    let store = database.store();
    let descriptor = descriptor();
    store.register_descriptor(&descriptor).unwrap();
    let request = bound_run("lifecycle", "lifecycle-key");
    seed_default_artifacts(&database, &request, &descriptor);
    store.create_bound_run(&request).unwrap();

    assert!(store.mark_running(&request.run_id, timestamp(9)).is_err());
    store.accept_run(&request.run_id, timestamp(10)).unwrap();
    assert!(store.accept_run(&request.run_id, timestamp(10)).is_err());
    store.mark_running(&request.run_id, timestamp(11)).unwrap();
    assert!(store.accept_run(&request.run_id, timestamp(12)).is_err());
    drop(store);

    let reopened = database.store();
    let snapshot = reopened.load_run(&request.run_id).unwrap().unwrap();
    assert_eq!(snapshot.request, request);
    assert_eq!(snapshot.status, AgentRunStatus::Running);
    assert_eq!(snapshot.accepted_at, Some(Timestamp::from_unix_seconds(10)),);
    assert_eq!(snapshot.started_at, Some(Timestamp::from_unix_seconds(11)),);
    assert_eq!(snapshot.completed_at, None);
}

#[test]
fn reopen_rejects_a_context_artifact_that_became_unavailable() {
    let database = TestDatabase::new();
    let store = database.store();
    let descriptor = descriptor();
    store.register_descriptor(&descriptor).unwrap();
    let request = bound_run("stale-context", "stale-context-key");
    seed_default_artifacts(&database, &request, &descriptor);
    store.create_bound_run(&request).unwrap();
    database
        .connection()
        .execute(
            "UPDATE artifacts SET availability = 'missing' WHERE id = ?1",
            [request.context.effective_context_artifact_id.as_str()],
        )
        .unwrap();

    assert_integrity_failure(store.load_run(&request.run_id));
}

#[test]
fn terminal_persists_message_and_separate_usage_atomically_and_only_once() {
    let database = TestDatabase::new();
    let store = prepared_running_store(&database, "terminal");
    let terminal = terminal("terminal", "message-terminal", AgentRunStatus::Succeeded);
    database.put_artifact(
        &terminal.message.content_artifact_id,
        "task-1",
        "agent-message",
        br#"{"message":"complete"}"#,
    );

    let mut wrong_binding = terminal.clone();
    wrong_binding.message.run_id = run_id("other-run");
    assert!(store.persist_terminal(&wrong_binding).is_err());
    store.persist_terminal(&terminal).unwrap();

    let connection = database.connection();
    let stored: (String, String, String, i64) = connection
        .query_row(
            "SELECT status, provider_usage_json, core_usage_json, estimated_cost_microunits
             FROM agent_runs WHERE id = ?1",
            [terminal.run_id.as_str()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .unwrap();
    assert_eq!(stored.0, "succeeded");
    assert_eq!(
        serde_json::from_str::<Value>(&stored.1).unwrap()["inputTokens"],
        10,
    );
    assert_eq!(
        serde_json::from_str::<Value>(&stored.2).unwrap()["inputTokens"],
        13,
    );
    assert_eq!(stored.3, 12);
    assert_eq!(row_count(&database.path, "messages"), 1);

    let mut duplicate = terminal;
    duplicate.message.message_id = "message-duplicate".to_owned();
    duplicate.message.content_artifact_id = artifact_id("artifact-message-duplicate");
    database.put_artifact(
        &duplicate.message.content_artifact_id,
        "task-1",
        "agent-message",
        br#"{"message":"duplicate"}"#,
    );
    assert!(store.persist_terminal(&duplicate).is_err());
    assert_eq!(row_count(&database.path, "messages"), 1);
    assert_eq!(
        connection
            .query_row(
                "SELECT COUNT(*) FROM messages WHERE id = 'message-duplicate'",
                [],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
        0,
    );
}

#[test]
fn parallel_analysis_terminal_stays_private_and_immutable() {
    let database = TestDatabase::new();
    let store = database.store();
    let descriptor = descriptor();
    store.register_descriptor(&descriptor).unwrap();
    let mut request = bound_run("private", "private-key");
    request.phase = Phase::ParallelAnalysis.as_str().to_owned();
    request.validate().unwrap();
    seed_default_artifacts(&database, &request, &descriptor);
    store.create_bound_run(&request).unwrap();
    store.accept_run(&request.run_id, timestamp(10)).unwrap();
    store.mark_running(&request.run_id, timestamp(11)).unwrap();
    let terminal = terminal("private", "message-private", AgentRunStatus::Succeeded);
    database.put_artifact(
        &terminal.message.content_artifact_id,
        "task-1",
        "agent-message",
        br#"{"message":"private proposal"}"#,
    );

    store.persist_terminal(&terminal).unwrap();

    let connection = database.connection();
    assert_eq!(row_count(&database.path, "messages"), 0);
    assert_eq!(row_count(&database.path, "agent_run_outputs"), 1);
    assert_eq!(
        connection
            .query_row(
                "SELECT message_id || ':' || content_artifact_id
                 FROM agent_run_outputs WHERE run_id = ?1",
                [request.run_id.as_str()],
                |row| row.get::<_, String>(0),
            )
            .unwrap(),
        "message-private:artifact-message-private"
    );
    assert!(connection
        .execute(
            "UPDATE agent_run_outputs SET message_id = 'forged' WHERE run_id = ?1",
            [request.run_id.as_str()],
        )
        .is_err());
    assert!(connection
        .execute(
            "DELETE FROM agent_run_outputs WHERE run_id = ?1",
            [request.run_id.as_str()],
        )
        .is_err());
}

#[test]
fn sqlite_failure_rolls_back_terminal_message_before_success_is_returned() {
    let database = TestDatabase::new();
    let store = prepared_running_store(&database, "fault");
    let terminal = terminal("fault", "message-fault", AgentRunStatus::Succeeded);
    database.put_artifact(
        &terminal.message.content_artifact_id,
        "task-1",
        "agent-message",
        br#"{"message":"fault"}"#,
    );
    database
        .connection()
        .execute_batch(
            "CREATE TRIGGER fail_agent_terminal
             BEFORE UPDATE OF status ON agent_runs
             FOR EACH ROW WHEN NEW.status = 'succeeded'
             BEGIN SELECT RAISE(ABORT, 'forced terminal failure'); END;",
        )
        .unwrap();

    assert!(store.persist_terminal(&terminal).is_err());

    let connection = database.connection();
    assert_eq!(row_count(&database.path, "messages"), 0);
    assert_eq!(
        connection
            .query_row(
                "SELECT status FROM agent_runs WHERE id = ?1",
                [terminal.run_id.as_str()],
                |row| row.get::<_, String>(0),
            )
            .unwrap(),
        "running",
    );
    assert_eq!(
        connection
            .query_row(
                "SELECT COUNT(*) FROM events WHERE stream_id = ?1 AND event_type = 'agent.run.completed'",
                [format!("agent-run:{}", terminal.run_id.as_str())],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
        0,
    );
}

#[test]
fn interruption_marks_every_active_run_for_the_connection() {
    let database = TestDatabase::new();
    let store = database.store();
    let descriptor = descriptor();
    store.register_descriptor(&descriptor).unwrap();
    let created = bound_run("created", "created-key");
    let running = bound_run("running", "running-key");
    for request in [&created, &running] {
        seed_default_artifacts(&database, request, &descriptor);
        store.create_bound_run(request).unwrap();
    }
    store.accept_run(&running.run_id, timestamp(10)).unwrap();
    store.mark_running(&running.run_id, timestamp(11)).unwrap();

    assert_eq!(
        store
            .interrupt_connection(CONNECTION_BINDING_DIGEST, timestamp(30))
            .unwrap(),
        vec![created.run_id.clone(), running.run_id.clone()],
    );
    for run_id in [&created.run_id, &running.run_id] {
        let snapshot = store.load_run(run_id).unwrap().unwrap();
        assert_eq!(snapshot.status, AgentRunStatus::Interrupted);
        assert_eq!(
            snapshot.completed_at,
            Some(Timestamp::from_unix_seconds(30)),
        );
    }
}

#[test]
fn interruption_uses_only_lifecycle_state_when_bound_artifacts_are_unavailable() {
    let database = TestDatabase::new();
    let store = database.store();
    let descriptor = descriptor();
    store.register_descriptor(&descriptor).unwrap();
    let created = bound_run("artifact-blind-created", "artifact-blind-created-key");
    let running = bound_run("artifact-blind-running", "artifact-blind-running-key");
    let unaffected = bound_run("artifact-blind-unaffected", "artifact-blind-unaffected-key");
    for request in [&created, &running, &unaffected] {
        seed_default_artifacts(&database, request, &descriptor);
        store.create_bound_run(request).unwrap();
    }
    store.accept_run(&running.run_id, timestamp(10)).unwrap();
    store.mark_running(&running.run_id, timestamp(11)).unwrap();

    let connection = database.connection();
    connection
        .execute(
            "UPDATE agent_runs SET connection_binding_digest = ?1 WHERE id = ?2",
            params![digest('e').as_str(), unaffected.run_id.as_str()],
        )
        .unwrap();
    connection
        .execute(
            "UPDATE artifacts SET availability = 'missing'
             WHERE id IN (?1, ?2, ?3, ?4)",
            params![
                created.context.effective_context_artifact_id.as_str(),
                created.run_config.run_config_artifact_id.as_str(),
                running.context.effective_context_artifact_id.as_str(),
                running.run_config.run_config_artifact_id.as_str(),
            ],
        )
        .unwrap();

    assert!(store
        .interrupt_connection(CONNECTION_BINDING_DIGEST, timestamp(9))
        .is_err());
    for run_id in [&created.run_id, &running.run_id] {
        assert_eq!(
            connection
                .query_row(
                    "SELECT status FROM agent_runs WHERE id = ?1",
                    [run_id.as_str()],
                    |row| row.get::<_, String>(0),
                )
                .unwrap(),
            if run_id == &running.run_id {
                "running"
            } else {
                "created"
            },
        );
    }

    assert_eq!(
        store
            .interrupt_connection(CONNECTION_BINDING_DIGEST, timestamp(30))
            .unwrap(),
        vec![created.run_id.clone(), running.run_id.clone()],
    );
    for run_id in [&created.run_id, &running.run_id] {
        assert_eq!(
            connection
                .query_row(
                    "SELECT status, completed_at FROM agent_runs WHERE id = ?1",
                    [run_id.as_str()],
                    |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
                )
                .unwrap(),
            ("interrupted".to_owned(), timestamp(30).to_owned()),
        );
        assert_eq!(
            connection
                .query_row(
                    "SELECT COUNT(*) FROM events
                     WHERE stream_id = ?1 AND event_type = 'agent.run.completed'",
                    [format!("agent-run:{}", run_id.as_str())],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            1,
        );
    }
    assert_eq!(
        connection
            .query_row(
                "SELECT status, completed_at FROM agent_runs WHERE id = ?1",
                [unaffected.run_id.as_str()],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, Option<String>>(1)?)),
            )
            .unwrap(),
        ("created".to_owned(), None),
    );
}

#[test]
fn provider_outage_terminal_does_not_mutate_task_workflow_projection() {
    let database = TestDatabase::new();
    let store = prepared_running_store(&database, "outage");
    let mut terminal = terminal("outage", "message-outage", AgentRunStatus::Failed);
    terminal.error = Some("provider_unavailable".to_owned());
    database.put_artifact(
        &terminal.message.content_artifact_id,
        "task-1",
        "agent-message",
        br#"{"message":"provider unavailable"}"#,
    );
    let before = task_projection(&database.path);

    store.persist_terminal(&terminal).unwrap();

    assert_eq!(task_projection(&database.path), before);
}

#[test]
fn runtime_terminal_publishes_exact_bytes_through_sqlite_and_content_addressed_storage() {
    let database = TestDatabase::new();
    let request = bound_run("runtime-success", "runtime-success-key");
    let descriptor = descriptor();
    seed_default_artifacts(&database, &request, &descriptor);
    let store = Arc::new(database.store());
    let artifacts = Arc::new(RuntimeArtifacts::new(&database));
    let clock = Arc::new(ManualClock::new(1_800_000_000));
    let peer = Arc::new(ScriptedPeer::new(Script::Proposer, peer_descriptor()));
    let runtime = ProtocolAgentRuntime::new(
        store.clone(),
        artifacts.clone(),
        clock,
        vec![(
            descriptor,
            digest_from_str(CONNECTION_BINDING_DIGEST),
            peer.clone() as Arc<dyn ProtocolPeer>,
        )],
    )
    .unwrap();

    runtime.start_run(request.clone()).unwrap();
    peer.drive().unwrap();

    assert_eq!(
        store.load_run(&request.run_id).unwrap().unwrap().status,
        AgentRunStatus::Succeeded
    );
    let content_artifact_id: String = database
        .connection()
        .query_row(
            "SELECT content_artifact_id FROM messages WHERE run_id = ?1",
            [request.run_id.as_str()],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(
        artifacts.read_artifact(&content_artifact_id).unwrap(),
        peer.outputs()[0].as_bytes()
    );
}

#[test]
fn hostile_crashed_and_timed_out_runtime_runs_do_not_mutate_real_task_workflow_state() {
    let scripts = [
        Script::Malicious(MaliciousScript::MalformedFrame),
        Script::Malicious(MaliciousScript::WrongConnection),
        Script::Malicious(MaliciousScript::WrongRun),
        Script::Malicious(MaliciousScript::SequenceGap),
        Script::Malicious(MaliciousScript::OversizeFrame),
        Script::Malicious(MaliciousScript::OversizeOutput),
        Script::Malicious(MaliciousScript::DuplicateTerminal),
        Script::Malicious(MaliciousScript::ConflictingTerminal),
        Script::Crashing,
        Script::Slow,
    ];
    for (index, script) in scripts.into_iter().enumerate() {
        let database = TestDatabase::new();
        seed_workflow_event(&database);
        let suffix = format!("runtime-hostile-{index}");
        let request = bound_run(&suffix, &format!("{suffix}-key"));
        let descriptor = descriptor();
        seed_default_artifacts(&database, &request, &descriptor);
        let store = Arc::new(database.store());
        let artifacts = Arc::new(RuntimeArtifacts::new(&database));
        let clock = Arc::new(ManualClock::new(1_800_000_000));
        let peer = Arc::new(ScriptedPeer::new(script, peer_descriptor()));
        let runtime = ProtocolAgentRuntime::new(
            store.clone(),
            artifacts,
            clock.clone(),
            vec![(
                descriptor,
                digest_from_str(CONNECTION_BINDING_DIGEST),
                peer.clone() as Arc<dyn ProtocolPeer>,
            )],
        )
        .unwrap();
        let before = task_workflow_state(&database.path);

        runtime.start_run(request.clone()).unwrap();
        if script == Script::Slow {
            clock.advance(DEFAULT_HEARTBEAT_TIMEOUT_SECS);
            runtime.check_timeouts().unwrap();
        } else {
            peer.drive().unwrap();
        }

        assert!(store
            .load_run(&request.run_id)
            .unwrap()
            .unwrap()
            .status
            .is_terminal());
        assert_eq!(task_workflow_state(&database.path), before);
    }
}

#[test]
fn artifact_and_terminal_store_failures_do_not_mutate_real_task_workflow_state() {
    for fail_artifact_publication in [true, false] {
        let database = TestDatabase::new();
        seed_workflow_event(&database);
        let suffix = if fail_artifact_publication {
            "runtime-artifact-failure"
        } else {
            "runtime-terminal-store-failure"
        };
        let request = bound_run(suffix, &format!("{suffix}-key"));
        let descriptor = descriptor();
        seed_default_artifacts(&database, &request, &descriptor);
        if !fail_artifact_publication {
            fail_agent_run_status(&database, "succeeded");
        }
        let store = Arc::new(database.store());
        let artifacts = Arc::new(RuntimeArtifacts::new(&database));
        if fail_artifact_publication {
            artifacts.fail_publication();
        }
        let peer = Arc::new(ScriptedPeer::new(Script::Proposer, peer_descriptor()));
        let runtime = ProtocolAgentRuntime::new(
            store,
            artifacts,
            Arc::new(ManualClock::new(1_800_000_000)),
            vec![(
                descriptor,
                digest_from_str(CONNECTION_BINDING_DIGEST),
                peer.clone() as Arc<dyn ProtocolPeer>,
            )],
        )
        .unwrap();
        let before = task_workflow_state(&database.path);

        runtime.start_run(request).unwrap();
        assert_eq!(peer.drive(), Err(ProtocolError::InternalAgentFailure));

        assert_eq!(task_workflow_state(&database.path), before);
    }
}

#[test]
fn post_start_store_failures_do_not_mutate_real_task_workflow_state() {
    for failed_status in ["accepted", "running"] {
        let database = TestDatabase::new();
        seed_workflow_event(&database);
        let suffix = format!("runtime-{failed_status}-failure");
        let request = bound_run(&suffix, &format!("{suffix}-key"));
        let descriptor = descriptor();
        seed_default_artifacts(&database, &request, &descriptor);
        fail_agent_run_status(&database, failed_status);
        let store = Arc::new(database.store());
        let peer = Arc::new(ScriptedPeer::new(Script::Slow, peer_descriptor()));
        let runtime = ProtocolAgentRuntime::new(
            store,
            Arc::new(RuntimeArtifacts::new(&database)),
            Arc::new(ManualClock::new(1_800_000_000)),
            vec![(
                descriptor,
                digest_from_str(CONNECTION_BINDING_DIGEST),
                peer as Arc<dyn ProtocolPeer>,
            )],
        )
        .unwrap();
        let before = task_workflow_state(&database.path);

        assert!(runtime.start_run(request).is_err());

        assert_eq!(task_workflow_state(&database.path), before);
    }
}

struct RuntimeArtifacts {
    database_path: PathBuf,
    content: ContentAddressedArtifactStore,
    fail_publication: AtomicBool,
}

impl RuntimeArtifacts {
    fn new(database: &TestDatabase) -> Self {
        Self {
            database_path: database.path.clone(),
            content: ContentAddressedArtifactStore::open(&database.artifact_root).unwrap(),
            fail_publication: AtomicBool::new(false),
        }
    }

    fn fail_publication(&self) {
        self.fail_publication.store(true, Ordering::Relaxed);
    }

    fn read_artifact(&self, artifact_id: &str) -> Result<Vec<u8>, PortError> {
        let reference = artifact_reference(&self.database_path, artifact_id)?;
        Ok(self.content.read(&reference)?.bytes)
    }
}

impl AgentArtifactStore for RuntimeArtifacts {
    fn load_effective_context(
        &self,
        context: &BoundEffectiveContext,
    ) -> Result<Vec<u8>, PortError> {
        self.read_artifact(context.effective_context_artifact_id.as_str())
    }

    fn publish_agent_message(
        &self,
        artifact: &AgentMessageArtifact,
    ) -> Result<ArtifactId, PortError> {
        if self.fail_publication.load(Ordering::Relaxed) {
            return Err(internal_failure());
        }
        let content_hash = digest_bytes(&artifact.content);
        let reference = self.content.put(NewArtifact {
            expected_hash: content_hash.as_str().to_owned(),
            expected_size: u64::try_from(artifact.content.len()).map_err(|_| internal_failure())?,
            content: artifact.content.clone(),
        })?;
        let artifact_id = ArtifactId::new(format!("artifact-{}", artifact.message_id))
            .map_err(|_| internal_failure())?;
        Connection::open(&self.database_path)
            .map_err(|_| internal_failure())?
            .execute(
                "INSERT INTO artifacts (
                    id, task_id, project_id, artifact_type, logical_path, content_hash,
                    storage_key, size_bytes, mime_type, availability, created_by_type,
                    created_by_id, created_at, supersedes, verification_state
                 ) VALUES (?1, ?2, 'project-1', 'agent-message', ?3, ?4, ?5, ?6,
                    'text/plain', 'available', 'agent', ?7,
                    '2027-01-15T08:00:00Z', NULL, 'hash_verified')",
                params![
                    artifact_id.as_str(),
                    artifact.task_id.as_str(),
                    format!("agent/{}.txt", artifact.message_id),
                    reference.content_hash,
                    reference.storage_key,
                    i64::try_from(reference.size_bytes).map_err(|_| internal_failure())?,
                    artifact.run_id.as_str(),
                ],
            )
            .map_err(|_| internal_failure())?;
        Ok(artifact_id)
    }
}

struct ManualClock {
    seconds: AtomicI64,
}

impl ManualClock {
    const fn new(seconds: i64) -> Self {
        Self {
            seconds: AtomicI64::new(seconds),
        }
    }

    fn advance(&self, seconds: i64) {
        self.seconds.fetch_add(seconds, Ordering::Relaxed);
    }
}

impl Clock for ManualClock {
    fn now_utc(&self) -> Result<String, PortError> {
        match self.seconds.load(Ordering::Relaxed) {
            1_800_000_000 => Ok("2027-01-15T08:00:00Z".to_owned()),
            1_800_000_030 => Ok("2027-01-15T08:00:30Z".to_owned()),
            _ => Err(internal_failure()),
        }
    }
}

fn prepared_running_store(database: &TestDatabase, suffix: &str) -> SqliteStore {
    let store = database.store();
    let descriptor = descriptor();
    store.register_descriptor(&descriptor).unwrap();
    let request = bound_run(suffix, &format!("{suffix}-key"));
    seed_default_artifacts(database, &request, &descriptor);
    store.create_bound_run(&request).unwrap();
    store.accept_run(&request.run_id, timestamp(10)).unwrap();
    store.mark_running(&request.run_id, timestamp(11)).unwrap();
    store
}

fn seed_default_artifacts(
    database: &TestDatabase,
    request: &BoundAgentRunRequest,
    descriptor: &AgentDescriptor,
) {
    seed_bound_artifacts(
        database,
        request,
        descriptor,
        "task-1",
        "task-1",
        "task-1",
        "run-config",
    );
}

fn legacy_v1_run_config_artifact(request: &BoundAgentRunRequest) -> Vec<u8> {
    let mut value: Value =
        serde_json::from_slice(&canonical_agent_run_config_artifact(request).unwrap()).unwrap();
    value["schema"] = Value::String("agent-run-config.v1".to_owned());
    let limits = value["runConfig"]["limits"].as_object_mut().unwrap();
    limits.remove("maxContextQueries");
    limits.remove("maxSpecialistRequests");
    serde_json_canonicalizer::to_vec(&value).unwrap()
}

fn assert_historical_run_config_rejected(suffix: &str, mutate: impl FnOnce(&mut Value)) {
    let database = TestDatabase::new();
    let store = database.store();
    let descriptor = descriptor();
    let request = bound_run(suffix, &format!("{suffix}-key"));
    store.register_descriptor(&descriptor).unwrap();

    let mut value: Value =
        serde_json::from_slice(&canonical_agent_run_config_artifact(&request).unwrap()).unwrap();
    mutate(&mut value);
    let bytes = serde_json_canonicalizer::to_vec(&value).unwrap();
    seed_historical_created_run(&database, &request, &descriptor, &bytes);
    drop(store);

    assert_integrity_failure(database.store().load_run(&request.run_id));
}

fn seed_historical_created_run(
    database: &TestDatabase,
    request: &BoundAgentRunRequest,
    descriptor: &AgentDescriptor,
    run_config_bytes: &[u8],
) {
    database.put_artifact(
        &request.context.manifest_artifact_id,
        "task-1",
        "manifest",
        &descriptor.manifest_json,
    );
    database.put_artifact(
        &request.context.effective_context_artifact_id,
        "task-1",
        "content",
        CONTEXT_BYTES,
    );
    database.put_artifact(
        &request.run_config.run_config_artifact_id,
        "task-1",
        "run-config",
        run_config_bytes,
    );
    let connection = database.connection();
    connection
        .execute(
            "INSERT INTO context_packages (
                id, task_id, agent_id, role, objective, manifest_artifact_id,
                effective_content_artifact_id, content_hash, policy_snapshot_digest,
                prompt_template_version, retrieval_pipeline_version, created_at
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11,
                '1970-01-01T00:00:01Z')",
            params![
                request.context.context_package_id,
                request.task_id.as_str(),
                request.agent_id,
                request.role,
                request.context.objective,
                request.context.manifest_artifact_id.as_str(),
                request.context.effective_context_artifact_id.as_str(),
                request.context.content_digest.as_str(),
                request.context.policy_snapshot_digest.as_str(),
                request.context.prompt_template_version,
                request.context.retrieval_pipeline_version,
            ],
        )
        .unwrap();
    connection
        .execute(
            "INSERT INTO agent_runs (
                id, task_id, agent_id, role, phase, status, context_package_id,
                idempotency_key, connection_binding_digest, run_config_artifact_id,
                supersedes_run_id, started_at, completed_at, provider_usage_json,
                core_usage_json, estimated_cost_microunits, error_json
             ) VALUES (?1, ?2, ?3, ?4, ?5, 'created', ?6, ?7, ?8, ?9, NULL,
                NULL, NULL, NULL, NULL, NULL, NULL)",
            params![
                request.run_id.as_str(),
                request.task_id.as_str(),
                request.agent_id,
                request.role,
                request.phase,
                request.context.context_package_id,
                request.idempotency_key,
                request.connection.binding_digest.as_str(),
                request.run_config.run_config_artifact_id.as_str(),
            ],
        )
        .unwrap();
}

#[allow(clippy::too_many_arguments)]
fn seed_bound_artifacts(
    database: &TestDatabase,
    request: &BoundAgentRunRequest,
    descriptor: &AgentDescriptor,
    manifest_task: &str,
    context_task: &str,
    config_task: &str,
    config_kind: &str,
) {
    database.put_artifact(
        &request.context.manifest_artifact_id,
        manifest_task,
        "manifest",
        &descriptor.manifest_json,
    );
    database.put_artifact(
        &request.context.effective_context_artifact_id,
        context_task,
        "content",
        CONTEXT_BYTES,
    );
    database.put_artifact(
        &request.run_config.run_config_artifact_id,
        config_task,
        config_kind,
        &canonical_agent_run_config_artifact(request).unwrap(),
    );
}

fn descriptor() -> AgentDescriptor {
    AgentDescriptor {
        agent_id: "agent-1".to_owned(),
        display_name: "Agent One".to_owned(),
        trust_tier: TrustTier::CoreAdapter,
        manifest_json: br#"{}"#.to_vec(),
        manifest_digest: digest_from_str(EMPTY_JSON_DIGEST),
        executable_digest: Some(digest('b')),
        enabled: true,
        containment_verified: true,
    }
}

fn peer_descriptor() -> PeerDescriptor {
    PeerDescriptor {
        binding: ConnectionBinding {
            connection_id: "connection-1".to_owned(),
            agent_id: "agent-1".to_owned(),
            manifest_digest: EMPTY_JSON_DIGEST.to_owned(),
            executable_digest: digest('b').as_str().to_owned(),
            trust_tier: ProtocolTrustTier::CoreAdapter,
        },
        protocol_version: "1.0".to_owned(),
        capabilities: ProtocolCapabilities {
            roles: ["reviewer".to_owned()].into_iter().collect(),
            skills: ["testing".to_owned()].into_iter().collect(),
            streaming: true,
            context_query: false,
            tool_requests: false,
            specialist_requests: false,
            max_concurrent_runs: 1,
            max_context_tokens: 1_024,
        },
    }
}

fn bound_run(suffix: &str, idempotency_key: &str) -> BoundAgentRunRequest {
    let task_id = task_id("task-1");
    let manifest_digest = digest_from_str(EMPTY_JSON_DIGEST);
    let executable_digest = Some(digest('b'));
    let context_digest = digest_bytes(CONTEXT_BYTES);
    let policy_digest = digest('d');

    let request = BoundAgentRunRequest {
        run_id: run_id(&format!("run-{suffix}")),
        task_id: task_id.clone(),
        agent_id: "agent-1".to_owned(),
        role: "reviewer".to_owned(),
        phase: "analysis".to_owned(),
        idempotency_key: idempotency_key.to_owned(),
        context: BoundEffectiveContext {
            context_package_id: format!("context-{suffix}"),
            task_id: task_id.clone(),
            agent_id: "agent-1".to_owned(),
            role: "reviewer".to_owned(),
            objective: "Review the task.".to_owned(),
            manifest_artifact_id: artifact_id(&format!("artifact-manifest-{suffix}")),
            effective_context_artifact_id: artifact_id(&format!("artifact-context-{suffix}")),
            content_digest: context_digest.clone(),
            policy_snapshot_digest: policy_digest.clone(),
            prompt_template_version: "prompt-1".to_owned(),
            retrieval_pipeline_version: "retrieval-1".to_owned(),
            created_at: Timestamp::from_unix_seconds(1),
        },
        run_config: BoundRunConfig {
            run_config_artifact_id: artifact_id(&format!("artifact-run-config-{suffix}")),
            task_id: task_id.clone(),
            agent_id: "agent-1".to_owned(),
            role: "reviewer".to_owned(),
            context_package_id: format!("context-{suffix}"),
            effective_context_artifact_id: artifact_id(&format!("artifact-context-{suffix}")),
            effective_context_digest: context_digest,
            trust_tier: TrustTier::CoreAdapter,
            manifest_digest: manifest_digest.clone(),
            executable_digest: executable_digest.clone(),
            contract_version: "1.0".to_owned(),
            adapter_version: "adapter-1".to_owned(),
            provider_id: "provider-1".to_owned(),
            model_id: "model-1".to_owned(),
            generation_parameters: BoundGenerationParameters {
                canonical_json: br#"{}"#.to_vec(),
                digest: digest_from_str(EMPTY_JSON_DIGEST),
            },
            prompt_template_version: "prompt-1".to_owned(),
            response_schema_version: "message-1".to_owned(),
            policy_snapshot_digest: policy_digest,
            limits: AgentRunLimits {
                deadline: Timestamp::from_unix_seconds(1_800_000_300),
                max_output_tokens: 8_000,
                max_tool_requests: 8,
                max_context_queries: 0,
                max_specialist_requests: 0,
            },
        },
        connection: BoundAgentConnection {
            connection_id: "connection-1".to_owned(),
            agent_id: "agent-1".to_owned(),
            trust_tier: TrustTier::CoreAdapter,
            manifest_digest,
            executable_digest,
            contract_version: "1.0".to_owned(),
            adapter_version: "adapter-1".to_owned(),
            binding_digest: digest_from_str(CONNECTION_BINDING_DIGEST),
        },
        supersedes_run_id: None,
    };
    request.validate().unwrap();
    request
}

fn terminal(suffix: &str, message_id: &str, status: AgentRunStatus) -> AgentRunTerminal {
    AgentRunTerminal {
        run_id: run_id(&format!("run-{suffix}")),
        task_id: task_id("task-1"),
        status,
        message: AgentRunMessage {
            message_id: message_id.to_owned(),
            task_id: task_id("task-1"),
            run_id: run_id(&format!("run-{suffix}")),
            thread_id: "thread-1".to_owned(),
            message_type: "review".to_owned(),
            reply_to: None,
            content_artifact_id: artifact_id(&format!("artifact-message-{suffix}")),
            claims: Vec::new(),
        },
        provider_usage: Some(AgentUsage {
            input_tokens: 10,
            output_tokens: 11,
            cost_microunits: Some(12),
        }),
        core_usage: Some(AgentUsage {
            input_tokens: 13,
            output_tokens: 14,
            cost_microunits: None,
        }),
        estimated_cost_microunits: Some(12),
        error: None,
        core_received_at: Some(Timestamp::from_unix_seconds(20)),
    }
}

fn assert_integrity_failure<T: std::fmt::Debug>(
    result: Result<T, local_agent_terminal_application::PortError>,
) {
    assert_eq!(
        result.unwrap_err().safe_classification(),
        SafeErrorClassification::IntegrityFailure,
    );
}

fn task_projection(path: &Path) -> (String, String, String, i64, i64) {
    Connection::open(path)
        .unwrap()
        .query_row(
            "SELECT phase, condition, operation_state, current_sequence, workspace_version
             FROM tasks WHERE id = 'task-1'",
            [],
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
        .unwrap()
}

fn seed_workflow_event(database: &TestDatabase) {
    let connection = database.connection();
    let transaction = connection.unchecked_transaction().unwrap();
    transaction
        .execute(
            "INSERT INTO events (
                event_id, stream_id, sequence, event_type, schema_version, actor_type,
                actor_id, observation_class, payload_json, metadata_json, causation_id,
                correlation_id, created_at
             ) VALUES ('event-task-1', 'task-1', 1, 'task.created', 1, 'core',
                'core', 'core_observed', '{}', '{}', NULL, 'task-1',
                '1970-01-01T00:00:01Z')",
            [],
        )
        .unwrap();
    transaction
        .execute(
            "UPDATE tasks SET current_sequence = 1 WHERE id = 'task-1'",
            [],
        )
        .unwrap();
    transaction.commit().unwrap();
}

fn fail_agent_run_status(database: &TestDatabase, status: &str) {
    assert!(matches!(status, "accepted" | "running" | "succeeded"));
    database
        .connection()
        .execute_batch(&format!(
            "CREATE TRIGGER fail_runtime_agent_status
             BEFORE UPDATE OF status ON agent_runs
             FOR EACH ROW WHEN NEW.status = '{status}'
             BEGIN SELECT RAISE(ABORT, 'forced runtime status failure'); END;"
        ))
        .unwrap();
}

fn task_workflow_state(path: &Path) -> ((String, String, String, i64, i64), i64) {
    let connection = Connection::open(path).unwrap();
    let event_count = connection
        .query_row(
            "SELECT COUNT(*) FROM events WHERE stream_id = 'task-1'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    (task_projection(path), event_count)
}

fn artifact_reference(path: &Path, artifact_id: &str) -> Result<ArtifactRef, PortError> {
    Connection::open(path)
        .map_err(|_| internal_failure())?
        .query_row(
            "SELECT content_hash, storage_key, size_bytes
             FROM artifacts WHERE id = ?1 AND availability = 'available'",
            [artifact_id],
            |row| {
                Ok(ArtifactRef {
                    content_hash: row.get(0)?,
                    storage_key: row.get(1)?,
                    size_bytes: row.get(2)?,
                })
            },
        )
        .map_err(|_| internal_failure())
}

fn row_count(path: &Path, table: &str) -> i64 {
    Connection::open(path)
        .unwrap()
        .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
            row.get(0)
        })
        .unwrap()
}

const fn internal_failure() -> PortError {
    PortError::failure(
        SafeErrorClassification::Internal,
        Retryability::NonRetryable,
    )
}

fn timestamp(second: u32) -> &'static str {
    match second {
        5 => "1970-01-01T00:00:05Z",
        9 => "1970-01-01T00:00:09Z",
        10 => "1970-01-01T00:00:10Z",
        11 => "1970-01-01T00:00:11Z",
        12 => "1970-01-01T00:00:12Z",
        30 => "1970-01-01T00:00:30Z",
        _ => unreachable!(),
    }
}

fn task_id(value: &str) -> TaskId {
    TaskId::new(value).unwrap()
}

fn run_id(value: &str) -> RunId {
    RunId::new(value).unwrap()
}

fn artifact_id(value: &str) -> ArtifactId {
    ArtifactId::new(value).unwrap()
}

fn digest(value: char) -> Sha256Digest {
    digest_from_str(&format!("sha256:{}", value.to_string().repeat(64)))
}

fn digest_from_str(value: &str) -> Sha256Digest {
    Sha256Digest::new(value).unwrap()
}

fn digest_bytes(bytes: &[u8]) -> Sha256Digest {
    digest_from_str(&format!("sha256:{:x}", Sha256::digest(bytes)))
}
