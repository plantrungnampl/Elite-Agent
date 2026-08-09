#[allow(dead_code)]
mod support;

use std::{fs, path::Path};

use local_agent_terminal_application::{
    AgentRunStore, ArtifactRef, ArtifactStore, ArtifactWriteReservation, Clock, ReservedArtifact,
    TaskQuery, WorkspaceEvidenceStore,
};
use local_agent_terminal_bootstrap::{
    Bootstrap, OpenAiApiKey, OpenAiBootstrapConfig, StartupConfig,
};
use local_agent_terminal_domain::{
    AgentRunLimits, AgentRunStatus, ArtifactId, BoundAgentConnection, BoundAgentRunRequest,
    BoundEffectiveContext, BoundGenerationParameters, BoundRunConfig, RunId, Sha256Digest, TaskId,
    Timestamp, TrustTier,
};
use local_agent_terminal_storage_files::{ContentAddressedArtifactStore, JournaledArtifactWriter};
use local_agent_terminal_storage_sqlite::{canonical_agent_run_config_artifact, SqliteStore};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tempfile::TempDir;

use support::{WorkspaceFixture, PROJECT_ID, TASK_ID};

const API_KEY_CANARY: &str = "sk-bootstrap-canary";
const LOOPBACK_ENDPOINT: &str = "http://127.0.0.1:9/v1/responses";
const CORE_MANIFEST: &[u8] = br#"{"adapter":"openai-responses","agentId":"core_adapter","providerId":"openai","schema":"trusted-openai-core-adapter-manifest.v1"}"#;
const CORE_MANIFEST_DIGEST: &str =
    "sha256:28d00daa6b56f0d8bb9b6ad78dd561a24bb61c668af842446c3a845e5b8ff0e5";
const CORE_RELEASE_DIGEST: &str =
    "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const POLICY_DIGEST: &str =
    "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";

#[test]
fn reopening_without_provider_configuration_keeps_agent_runtime_absent() {
    let fixture = TempDir::new().expect("temporary application directory");
    let first = Bootstrap::new(config(fixture.path()));
    assert_eq!(
        first.status().state,
        local_agent_terminal_application::StartupStateDto::Ready
    );
    drop(first);

    let restarted = Bootstrap::new(config(fixture.path()));

    assert_eq!(
        restarted.status().state,
        local_agent_terminal_application::StartupStateDto::Ready
    );
    assert!(restarted.agent_runtime_handle().is_none());
}

#[test]
fn restart_interrupts_an_incomplete_openai_run_and_reconstructs_its_durable_inputs() {
    let fixture = WorkspaceFixture::new();
    let first = Bootstrap::new(configured_workspace(&fixture));
    assert_eq!(
        first.status().state,
        local_agent_terminal_application::StartupStateDto::Ready
    );

    let context = canonical_context();
    let request = bound_request(
        "run-openai-restart",
        "agent-context-restart",
        digest_bytes(&context),
    );
    publish_artifact(
        &fixture,
        request.context.manifest_artifact_id.as_str(),
        "manifest",
        CORE_MANIFEST,
    );
    publish_artifact(
        &fixture,
        request.context.effective_context_artifact_id.as_str(),
        "content",
        &context,
    );
    publish_artifact(
        &fixture,
        request.run_config.run_config_artifact_id.as_str(),
        "run-config",
        &canonical_agent_run_config_artifact(&request).expect("run config"),
    );
    let before = task_snapshot(&fixture);
    let database = SqliteStore::open(&fixture.database_path).expect("database");
    database.create_bound_run(&request).expect("created run");
    database
        .accept_run(&request.run_id, &database.now_utc().expect("clock"))
        .expect("accepted run");
    database
        .mark_running(&request.run_id, &database.now_utc().expect("clock"))
        .expect("running run");
    assert_eq!(
        database
            .load_run(&request.run_id)
            .expect("run query")
            .expect("run")
            .status,
        AgentRunStatus::Running
    );

    drop(first);
    let restarted = Bootstrap::new(configured_workspace(&fixture));
    assert_eq!(
        restarted.status().state,
        local_agent_terminal_application::StartupStateDto::Ready
    );
    assert!(restarted.agent_runtime_handle().is_some());

    let reopened = SqliteStore::open(&fixture.database_path)
        .expect("database")
        .load_run(&request.run_id)
        .expect("run query")
        .expect("interrupted run");
    assert_eq!(reopened.status, AgentRunStatus::Interrupted);
    assert_eq!(reopened.request, request);
    assert_eq!(task_snapshot(&fixture), before);
    assert_eq!(
        artifact_bytes(
            &fixture,
            reopened
                .request
                .context
                .effective_context_artifact_id
                .as_str(),
        ),
        context
    );
    assert_eq!(
        artifact_bytes(
            &fixture,
            reopened.request.run_config.run_config_artifact_id.as_str(),
        ),
        canonical_agent_run_config_artifact(&reopened.request).expect("reconstructed config")
    );
    let durable = durable_bytes(&fixture.app_data);
    assert_not_present(&durable, API_KEY_CANARY);
    assert_not_present(&durable, LOOPBACK_ENDPOINT);
    let diagnostics = format!("{:?}", restarted.local_diagnostics());
    assert_not_present(diagnostics.as_bytes(), API_KEY_CANARY);
    assert_not_present(diagnostics.as_bytes(), LOOPBACK_ENDPOINT);
}

#[test]
fn adapter_version_rotation_interrupts_incomplete_core_adapter_runs() {
    let fixture = WorkspaceFixture::new();
    let first = Bootstrap::new(configured_workspace_with(
        &fixture,
        CORE_RELEASE_DIGEST,
        "openai-responses-v1",
    ));
    assert_eq!(
        first.status().state,
        local_agent_terminal_application::StartupStateDto::Ready
    );

    let context = canonical_context();
    let request = bound_request(
        "run-adapter-version-rotation",
        "agent-context-adapter-version-rotation",
        digest_bytes(&context),
    );
    persist_running_bound_run(&fixture, &request, &context);
    drop(first);

    let restarted = Bootstrap::new(configured_workspace_with(
        &fixture,
        CORE_RELEASE_DIGEST,
        "openai-responses-v2",
    ));

    assert_eq!(
        restarted.status().state,
        local_agent_terminal_application::StartupStateDto::Ready
    );
    assert_eq!(
        SqliteStore::open(&fixture.database_path)
            .expect("database")
            .load_run(&request.run_id)
            .expect("run query")
            .expect("interrupted run")
            .status,
        AgentRunStatus::Interrupted
    );
}

#[test]
fn core_release_rotation_interrupts_incomplete_runs_and_reconstructs_completed_history() {
    const NEXT_CORE_RELEASE_DIGEST: &str =
        "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";

    let fixture = WorkspaceFixture::new();
    let first = Bootstrap::new(configured_workspace_with(
        &fixture,
        CORE_RELEASE_DIGEST,
        "openai-responses-v1",
    ));
    assert_eq!(
        first.status().state,
        local_agent_terminal_application::StartupStateDto::Ready
    );

    let context = canonical_context();
    let mut completed_request = bound_request(
        "run-core-release-completed",
        "agent-context-core-release-completed",
        digest_bytes(&context),
    );
    set_adapter_version(&mut completed_request, "openai-responses-v0");
    let active_request = bound_request(
        "run-core-release-active",
        "agent-context-core-release-active",
        digest_bytes(&context),
    );
    persist_running_bound_run(&fixture, &completed_request, &context);
    persist_running_bound_run(&fixture, &active_request, &context);
    let database = SqliteStore::open(&fixture.database_path).expect("database");
    database
        .interrupt_connection(
            completed_request.connection.binding_digest.as_str(),
            &database.now_utc().expect("clock"),
        )
        .expect("complete historical run");
    let completed_history = database
        .load_run(&completed_request.run_id)
        .expect("history query")
        .expect("completed history");
    assert_eq!(completed_history.status, AgentRunStatus::Interrupted);
    assert_eq!(completed_history.request, completed_request);

    drop(first);
    let restarted = Bootstrap::new(configured_workspace_with(
        &fixture,
        NEXT_CORE_RELEASE_DIGEST,
        "openai-responses-v2",
    ));

    assert_eq!(
        restarted.status().state,
        local_agent_terminal_application::StartupStateDto::Ready
    );
    let database = SqliteStore::open(&fixture.database_path).expect("database");
    let interrupted_active = database
        .load_run(&active_request.run_id)
        .expect("active query")
        .expect("interrupted active run");
    assert_eq!(interrupted_active.status, AgentRunStatus::Interrupted);
    assert_eq!(
        database
            .load_run(&completed_request.run_id)
            .expect("history query")
            .expect("completed history")
            .request,
        completed_request
    );
}

fn config(root: &Path) -> StartupConfig {
    StartupConfig {
        app_data_dir: root.join("app-data"),
        trusted_workspace_root: root.join("workspaces"),
        secret_values: Vec::new(),
        openai: None,
    }
}

fn configured_workspace(fixture: &WorkspaceFixture) -> StartupConfig {
    configured_workspace_with(fixture, CORE_RELEASE_DIGEST, "openai-responses-v1")
}

fn configured_workspace_with(
    fixture: &WorkspaceFixture,
    core_release_digest: &str,
    adapter_version: &str,
) -> StartupConfig {
    StartupConfig {
        app_data_dir: fixture.app_data.clone(),
        trusted_workspace_root: fixture.workspace_root.clone(),
        secret_values: vec![API_KEY_CANARY.to_owned()],
        openai: Some(OpenAiBootstrapConfig {
            endpoint: LOOPBACK_ENDPOINT.to_owned(),
            api_key: OpenAiApiKey::new(API_KEY_CANARY).expect("API key"),
            manifest_digest: digest(CORE_MANIFEST_DIGEST),
            core_release_digest: digest(core_release_digest),
            adapter_version: adapter_version.to_owned(),
        }),
    }
}

fn bound_request(
    run: &str,
    effective_context_artifact_id: &str,
    effective_context_digest: Sha256Digest,
) -> BoundAgentRunRequest {
    let task_id = TaskId::new(TASK_ID).expect("task id");
    let connection = core_connection();
    let generation_parameters = canonical_json(json!({"temperature": 0}));
    let request = BoundAgentRunRequest {
        run_id: RunId::new(run).expect("run id"),
        task_id: task_id.clone(),
        agent_id: "core_adapter".to_owned(),
        role: "critic".to_owned(),
        phase: "analysis".to_owned(),
        idempotency_key: format!("{TASK_ID}:critic:{run}"),
        context: BoundEffectiveContext {
            context_package_id: format!("context-package-{run}"),
            task_id: task_id.clone(),
            agent_id: "core_adapter".to_owned(),
            role: "critic".to_owned(),
            objective: "Review the current task.".to_owned(),
            manifest_artifact_id: ArtifactId::new(format!("agent-manifest-{run}"))
                .expect("manifest artifact id"),
            effective_context_artifact_id: ArtifactId::new(effective_context_artifact_id)
                .expect("context artifact id"),
            content_digest: effective_context_digest.clone(),
            policy_snapshot_digest: digest(POLICY_DIGEST),
            prompt_template_version: "prompt-v1".to_owned(),
            retrieval_pipeline_version: "retrieval-v1".to_owned(),
            created_at: Timestamp::from_unix_seconds(1_800_000_000),
        },
        run_config: BoundRunConfig {
            run_config_artifact_id: ArtifactId::new(format!("agent-run-config-{run}"))
                .expect("run config artifact id"),
            task_id: task_id.clone(),
            agent_id: "core_adapter".to_owned(),
            role: "critic".to_owned(),
            context_package_id: format!("context-package-{run}"),
            effective_context_artifact_id: ArtifactId::new(effective_context_artifact_id)
                .expect("context artifact id"),
            effective_context_digest,
            trust_tier: TrustTier::CoreAdapter,
            manifest_digest: digest(CORE_MANIFEST_DIGEST),
            executable_digest: Some(digest(CORE_RELEASE_DIGEST)),
            contract_version: "1.0".to_owned(),
            adapter_version: "openai-responses-v1".to_owned(),
            provider_id: "openai".to_owned(),
            model_id: "gpt-task8-model".to_owned(),
            generation_parameters: BoundGenerationParameters {
                digest: digest_bytes(&generation_parameters),
                canonical_json: generation_parameters,
            },
            prompt_template_version: "prompt-v1".to_owned(),
            response_schema_version: "agent-message.v1".to_owned(),
            policy_snapshot_digest: digest(POLICY_DIGEST),
            limits: AgentRunLimits {
                deadline: Timestamp::from_unix_seconds(2_000_000_000),
                max_output_tokens: 256,
                max_tool_requests: 0,
                max_context_queries: 0,
                max_specialist_requests: 0,
            },
        },
        connection,
        supersedes_run_id: None,
    };
    request.validate().expect("bound request");
    request
}

fn core_connection() -> BoundAgentConnection {
    let mut connection = BoundAgentConnection {
        connection_id: "openai_core_adapter".to_owned(),
        agent_id: "core_adapter".to_owned(),
        trust_tier: TrustTier::CoreAdapter,
        manifest_digest: digest(CORE_MANIFEST_DIGEST),
        executable_digest: Some(digest(CORE_RELEASE_DIGEST)),
        contract_version: "1.0".to_owned(),
        adapter_version: "openai-responses-v1".to_owned(),
        binding_digest: digest(
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        ),
    };
    connection.binding_digest = digest_bytes(&canonical_json(json!({
        "schema": "agent-connection-binding.v1",
        "identity": {
            "connectionId": connection.connection_id,
            "agentId": connection.agent_id,
        },
        "manifestDigest": connection.manifest_digest.as_str(),
        "executableDigest": connection.executable_digest.as_ref().map(Sha256Digest::as_str),
        "trustTier": connection.trust_tier.as_str(),
        "contractVersion": connection.contract_version,
        "adapterVersion": connection.adapter_version,
    })));
    connection.validate().expect("canonical connection");
    connection
}

fn set_adapter_version(request: &mut BoundAgentRunRequest, adapter_version: &str) {
    request.connection.adapter_version = adapter_version.to_owned();
    request.run_config.adapter_version = adapter_version.to_owned();
    request.connection.binding_digest = digest_bytes(&canonical_json(json!({
        "schema": "agent-connection-binding.v1",
        "identity": {
            "connectionId": request.connection.connection_id,
            "agentId": request.connection.agent_id,
        },
        "manifestDigest": request.connection.manifest_digest.as_str(),
        "executableDigest": request.connection.executable_digest.as_ref().map(Sha256Digest::as_str),
        "trustTier": request.connection.trust_tier.as_str(),
        "contractVersion": request.connection.contract_version,
        "adapterVersion": request.connection.adapter_version,
    })));
    request.validate().expect("rotated request");
}

fn canonical_context() -> Vec<u8> {
    canonical_json(json!({
        "objective": "Review the current task.",
        "sources": [],
    }))
}

fn canonical_json(value: Value) -> Vec<u8> {
    serde_json_canonicalizer::to_vec(&value).expect("canonical JSON")
}

fn publish_artifact(
    fixture: &WorkspaceFixture,
    artifact_id: &str,
    artifact_type: &str,
    bytes: &[u8],
) {
    let database = SqliteStore::open(&fixture.database_path).expect("database");
    let artifacts = ContentAddressedArtifactStore::open(fixture.app_data.join("artifacts"))
        .expect("artifact store");
    let content_hash = digest_bytes(bytes);
    let created_at = database.now_utc().expect("clock");
    JournaledArtifactWriter::new(&artifacts, &database, &database)
        .write(
            ArtifactWriteReservation {
                operation_id: format!("task8:{artifact_id}"),
                artifact: ReservedArtifact {
                    artifact_id: artifact_id.to_owned(),
                    task_id: Some(TaskId::new(TASK_ID).expect("task id")),
                    project_id: PROJECT_ID.to_owned(),
                    artifact_type: artifact_type.to_owned(),
                    logical_path: format!("task8/{artifact_id}.json"),
                    content_hash: content_hash.as_str().to_owned(),
                    storage_key: ContentAddressedArtifactStore::storage_key(content_hash.as_str())
                        .expect("storage key"),
                    size_bytes: bytes.len() as u64,
                    mime_type: Some("application/json".to_owned()),
                    created_by_type: "core".to_owned(),
                    created_by_id: "bootstrap-agent-runtime-recovery".to_owned(),
                    created_at: created_at.clone(),
                    supersedes: None,
                },
                temp_name: format!("{artifact_id}.tmp"),
                created_at,
            },
            bytes,
        )
        .expect("publish artifact");
}

fn persist_running_bound_run(
    fixture: &WorkspaceFixture,
    request: &BoundAgentRunRequest,
    context: &[u8],
) {
    publish_artifact(
        fixture,
        request.context.manifest_artifact_id.as_str(),
        "manifest",
        CORE_MANIFEST,
    );
    publish_artifact(
        fixture,
        request.context.effective_context_artifact_id.as_str(),
        "content",
        context,
    );
    publish_artifact(
        fixture,
        request.run_config.run_config_artifact_id.as_str(),
        "run-config",
        &canonical_agent_run_config_artifact(request).expect("run config"),
    );
    let database = SqliteStore::open(&fixture.database_path).expect("database");
    database.create_bound_run(request).expect("created run");
    database
        .accept_run(&request.run_id, &database.now_utc().expect("clock"))
        .expect("accepted run");
    database
        .mark_running(&request.run_id, &database.now_utc().expect("clock"))
        .expect("running run");
}

fn task_snapshot(fixture: &WorkspaceFixture) -> local_agent_terminal_application::TaskSnapshot {
    SqliteStore::open(&fixture.database_path)
        .expect("database")
        .task(&TaskId::new(TASK_ID).expect("task id"))
        .expect("task")
}

fn artifact_bytes(fixture: &WorkspaceFixture, artifact_id: &str) -> Vec<u8> {
    let database = SqliteStore::open(&fixture.database_path).expect("database");
    let evidence = database
        .available_evidence(&ArtifactId::new(artifact_id).expect("artifact id"))
        .expect("evidence query")
        .expect("available evidence");
    ContentAddressedArtifactStore::open(fixture.app_data.join("artifacts"))
        .expect("artifact store")
        .read(&ArtifactRef {
            content_hash: evidence.content_hash,
            storage_key: evidence.storage_key,
            size_bytes: evidence.size_bytes,
        })
        .expect("artifact bytes")
        .bytes
}

fn durable_bytes(root: &Path) -> Vec<u8> {
    let mut bytes = Vec::new();
    append_durable_bytes(root, &mut bytes);
    bytes
}

fn append_durable_bytes(path: &Path, bytes: &mut Vec<u8>) {
    for entry in fs::read_dir(path).expect("durable directory") {
        let entry = entry.expect("durable entry");
        let entry_path = entry.path();
        if entry_path.is_dir() {
            append_durable_bytes(&entry_path, bytes);
        } else {
            bytes.extend(fs::read(entry_path).expect("durable bytes"));
        }
    }
}

fn assert_not_present(bytes: &[u8], value: &str) {
    assert!(
        !bytes
            .windows(value.len())
            .any(|candidate| candidate == value.as_bytes()),
        "durable or diagnostic material contained a configured secret or endpoint"
    );
}

fn digest(value: &str) -> Sha256Digest {
    Sha256Digest::new(value).expect("digest")
}

fn digest_bytes(bytes: &[u8]) -> Sha256Digest {
    Sha256Digest::new(format!("sha256:{:x}", Sha256::digest(bytes))).expect("SHA-256 digest")
}
