#[allow(dead_code)]
mod support;

use std::{
    collections::BTreeMap,
    fs,
    io::{BufRead, BufReader, ErrorKind, Read, Write},
    net::{TcpListener, TcpStream},
    path::Path,
    sync::mpsc::{self, Receiver, Sender},
    thread,
    time::{Duration, Instant},
};

use local_agent_terminal_application::{
    AgentRunStore, ArtifactRef, ArtifactStore, ArtifactWriteReservation, Clock, ReservedArtifact,
    SafeErrorClassification, TaskQuery, WorkspaceEvidenceStore,
};
use local_agent_terminal_bootstrap::{
    Bootstrap, OpenAiApiKey, OpenAiBootstrapConfig, StartupConfig,
};
use local_agent_terminal_domain::{
    AgentRunLimits, AgentRunStatus, ArtifactId, BoundAgentConnection, BoundAgentRunRequest,
    BoundEffectiveContext, BoundGenerationParameters, BoundRunConfig, CancelAgentRun, RunId,
    Sha256Digest, TaskId, Timestamp, TrustTier,
};
use local_agent_terminal_storage_files::{ContentAddressedArtifactStore, JournaledArtifactWriter};
use local_agent_terminal_storage_sqlite::{canonical_agent_run_config_artifact, SqliteStore};
use rusqlite::params;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tempfile::TempDir;

use support::{WorkspaceFixture, PROJECT_ID, TASK_ID};

const API_KEY_CANARY: &str = "sk-bootstrap-canary";
const CORE_MANIFEST: &[u8] = br#"{"adapter":"openai-responses","agentId":"core_adapter","providerId":"openai","schema":"trusted-openai-core-adapter-manifest.v1"}"#;
const CORE_MANIFEST_DIGEST: &str =
    "sha256:28d00daa6b56f0d8bb9b6ad78dd561a24bb61c668af842446c3a845e5b8ff0e5";
const CORE_RELEASE_DIGEST: &str =
    "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const POLICY_DIGEST: &str =
    "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";

#[test]
fn startup_without_openai_is_ready_without_an_agent_runtime() {
    let fixture = TempDir::new().expect("temporary application directory");
    let bootstrap = Bootstrap::new(config(fixture.path()));

    assert_eq!(
        bootstrap.status().state,
        local_agent_terminal_application::StartupStateDto::Ready
    );
    assert!(bootstrap.agent_runtime_handle().is_none());
}

#[test]
fn configured_openai_registers_the_exact_trusted_core_adapter_descriptor() {
    let fixture = TempDir::new().expect("temporary application directory");
    let bootstrap = Bootstrap::new(configured(fixture.path()));

    assert_eq!(
        bootstrap.status().state,
        local_agent_terminal_application::StartupStateDto::Ready
    );
    let agents = bootstrap
        .agent_runtime_handle()
        .expect("configured provider runtime")
        .list_agents()
        .expect("registered agents");
    assert_eq!(agents.len(), 1);
    assert_eq!(agents[0].agent_id, "core_adapter");
    assert_eq!(agents[0].manifest_json, CORE_MANIFEST);
    assert_eq!(agents[0].manifest_digest.as_str(), CORE_MANIFEST_DIGEST);
    assert_eq!(
        agents[0]
            .executable_digest
            .as_ref()
            .expect("core release binding")
            .as_str(),
        CORE_RELEASE_DIGEST
    );
    assert!(agents[0].enabled);
    assert!(agents[0].containment_verified);
}

#[test]
fn loopback_sse_persists_a_terminal_run_and_reconstructs_its_bound_inputs_after_reopen() {
    let fixture = WorkspaceFixture::new();
    let context = canonical_context();
    let request = bound_request(
        "run-openai-success",
        "agent-context-success",
        digest_bytes(&context),
    );
    publish_artifact(
        &fixture,
        request.context.effective_context_artifact_id.as_str(),
        "content",
        &context,
    );

    let mut server = GatedSseServer::success();
    let endpoint = server.endpoint().to_owned();
    let bootstrap = Bootstrap::new(configured_workspace(&fixture, endpoint.clone()));
    assert_eq!(
        bootstrap.status().state,
        local_agent_terminal_application::StartupStateDto::Ready
    );
    let runtime = bootstrap
        .agent_runtime_handle()
        .expect("configured provider runtime");
    let before = task_snapshot(&fixture);

    let receipt = runtime.start_run(request.clone()).expect("durable receipt");
    assert_eq!(receipt.run_id, request.run_id);

    let captured = server.await_request();
    assert_eq!(captured.method, "POST");
    assert_eq!(captured.target, "/v1/responses");
    assert_eq!(
        captured.header("authorization"),
        Some(&format!("Bearer {API_KEY_CANARY}"))
    );
    let request_body: Value = serde_json::from_slice(&captured.body).expect("OpenAI request JSON");
    assert_eq!(
        request_body["input"],
        String::from_utf8(context.clone()).expect("context text")
    );
    assert_eq!(request_body["model"], "gpt-task8-model");
    assert_eq!(request_body["temperature"], 0);
    assert_eq!(request_body["stream"], true);
    assert_eq!(request_body["store"], false);

    let running = load_run(&fixture, &request.run_id).expect("accepted run");
    assert_eq!(running.status, AgentRunStatus::Running);
    assert!(running.completed_at.is_none());

    server.release_and_join();
    let completed = wait_for_terminal(&fixture, &request.run_id);
    assert_eq!(completed.status, AgentRunStatus::Succeeded);
    assert_eq!(task_snapshot(&fixture), before);

    let reopened = load_run(&fixture, &request.run_id).expect("reconstructed run");
    assert_eq!(reopened.request, request);
    assert_eq!(
        artifact_bytes(
            &fixture,
            reopened
                .request
                .context
                .effective_context_artifact_id
                .as_str()
        ),
        context
    );
    assert_eq!(
        artifact_bytes(
            &fixture,
            reopened.request.context.manifest_artifact_id.as_str()
        ),
        CORE_MANIFEST
    );
    assert_eq!(
        artifact_bytes(
            &fixture,
            reopened.request.run_config.run_config_artifact_id.as_str(),
        ),
        canonical_agent_run_config_artifact(&reopened.request).expect("canonical run config")
    );
    assert_eq!(
        artifact_bytes(&fixture, &message_artifact_id(&fixture, &request.run_id)),
        b"accepted output"
    );

    let persisted = durable_bytes(&fixture.app_data);
    assert_not_present(&persisted, API_KEY_CANARY);
    assert_not_present(&persisted, &endpoint);
    let diagnostics = format!("{:?}", bootstrap.local_diagnostics());
    assert_not_present(diagnostics.as_bytes(), API_KEY_CANARY);
    assert_not_present(diagnostics.as_bytes(), &endpoint);
}

#[test]
fn accepted_cancellation_terminalizes_cleanly_without_changing_the_task_workflow() {
    let fixture = WorkspaceFixture::new();
    let context = canonical_context();
    let request = bound_request(
        "run-openai-cancel",
        "agent-context-cancel",
        digest_bytes(&context),
    );
    publish_artifact(
        &fixture,
        request.context.effective_context_artifact_id.as_str(),
        "content",
        &context,
    );

    let mut server = GatedSseServer::success();
    let bootstrap = Bootstrap::new(configured_workspace(&fixture, server.endpoint().to_owned()));
    let runtime = bootstrap
        .agent_runtime_handle()
        .expect("configured provider runtime");
    let before = task_snapshot(&fixture);
    runtime.start_run(request.clone()).expect("durable receipt");
    let _captured = server.await_request();

    let cancellation = runtime
        .cancel(CancelAgentRun {
            run_id: request.run_id.clone(),
            reason: "user-requested".to_owned(),
            deadline_ms: 1_000,
        })
        .expect("accepted cancellation");
    assert_eq!(cancellation.run_id, request.run_id);

    server.release_and_join();
    let completed = wait_for_terminal(&fixture, &request.run_id);
    assert_eq!(completed.status, AgentRunStatus::CancelledCleanly);
    assert_eq!(task_snapshot(&fixture), before);
}

#[test]
fn openai_outage_terminalizes_the_agent_run_without_changing_the_task_workflow() {
    let fixture = WorkspaceFixture::new();
    let context = canonical_context();
    let request = bound_request(
        "run-openai-outage",
        "agent-context-outage",
        digest_bytes(&context),
    );
    publish_artifact(
        &fixture,
        request.context.effective_context_artifact_id.as_str(),
        "content",
        &context,
    );

    let server = ImmediateResponseServer::unavailable();
    let bootstrap = Bootstrap::new(configured_workspace(&fixture, server.endpoint().to_owned()));
    let runtime = bootstrap
        .agent_runtime_handle()
        .expect("configured provider runtime");
    let before = task_snapshot(&fixture);
    runtime.start_run(request.clone()).expect("durable receipt");
    let captured = server.capture_and_join();
    assert_eq!(
        captured.header("authorization"),
        Some(&format!("Bearer {API_KEY_CANARY}"))
    );

    let completed = wait_for_terminal(&fixture, &request.run_id);
    assert_eq!(completed.status, AgentRunStatus::Failed);
    assert_eq!(task_snapshot(&fixture), before);
}

#[test]
fn missing_or_mismatched_context_fails_before_openai_loopback_dispatch() {
    for (case, context_bytes, requested_digest, expected_error) in [
        (
            "missing",
            None,
            digest_bytes(&canonical_context()),
            SafeErrorClassification::NotFound,
        ),
        (
            "mismatched",
            Some(canonical_json(json!({"objective": "different"}))),
            digest_bytes(&canonical_context()),
            SafeErrorClassification::IntegrityFailure,
        ),
    ] {
        let fixture = WorkspaceFixture::new();
        let endpoint = UnobservedLoopback::new();
        let bootstrap = Bootstrap::new(configured_workspace(
            &fixture,
            endpoint.endpoint().to_owned(),
        ));
        let runtime = bootstrap
            .agent_runtime_handle()
            .expect("configured provider runtime");
        let request = bound_request(
            &format!("run-context-{case}"),
            &format!("agent-context-{case}"),
            requested_digest,
        );
        if let Some(context_bytes) = context_bytes {
            publish_artifact(
                &fixture,
                request.context.effective_context_artifact_id.as_str(),
                "content",
                &context_bytes,
            );
        }

        let error = runtime
            .start_run(request.clone())
            .expect_err("context rejected");
        assert_eq!(error.safe_classification(), expected_error);
        endpoint.assert_no_connection();
        assert!(load_run(&fixture, &request.run_id).is_none());
        let database = SqliteStore::open(&fixture.database_path).expect("database");
        assert!(database
            .available_evidence(&request.run_config.run_config_artifact_id)
            .expect("run-config query")
            .is_none());
    }
}

#[test]
fn non_openai_provider_is_rejected_before_publication_or_loopback_dispatch() {
    let fixture = WorkspaceFixture::new();
    let context = canonical_context();
    let mut request = bound_request(
        "run-non-openai-provider",
        "agent-context-non-openai-provider",
        digest_bytes(&context),
    );
    request.run_config.provider_id = "different-provider".to_owned();
    request.validate().expect("otherwise valid bound request");
    publish_artifact(
        &fixture,
        request.context.effective_context_artifact_id.as_str(),
        "content",
        &context,
    );

    let endpoint = UnobservedLoopback::new();
    let bootstrap = Bootstrap::new(configured_workspace(
        &fixture,
        endpoint.endpoint().to_owned(),
    ));
    let runtime = bootstrap
        .agent_runtime_handle()
        .expect("configured provider runtime");

    let error = runtime
        .start_run(request.clone())
        .expect_err("provider rejected");

    assert_eq!(
        error.safe_classification(),
        SafeErrorClassification::InvalidInput
    );
    endpoint.assert_no_connection();
    assert!(load_run(&fixture, &request.run_id).is_none());
    let database = SqliteStore::open(&fixture.database_path).expect("database");
    assert!(database
        .available_evidence(&request.context.manifest_artifact_id)
        .expect("manifest query")
        .is_none());
    assert!(database
        .available_evidence(&request.run_config.run_config_artifact_id)
        .expect("run-config query")
        .is_none());
}

#[test]
fn reconfigure_waits_for_active_openai_worker_and_permanently_closes_cloned_handle() {
    let fixture = WorkspaceFixture::new();
    let context = canonical_context();
    let request = bound_request(
        "run-reconfigure-active",
        "agent-context-reconfigure-active",
        digest_bytes(&context),
    );
    publish_artifact(
        &fixture,
        request.context.effective_context_artifact_id.as_str(),
        "content",
        &context,
    );

    let mut server = GatedSseServer::success();
    let bootstrap = Bootstrap::new(configured_workspace(&fixture, server.endpoint().to_owned()));
    let stale_runtime = bootstrap
        .agent_runtime_handle()
        .expect("configured provider runtime");
    stale_runtime
        .start_run(request.clone())
        .expect("active provider run");
    let _request = server.await_request();

    let replacement = StartupConfig {
        app_data_dir: fixture.app_data.clone(),
        trusted_workspace_root: fixture.workspace_root.clone(),
        secret_values: vec![API_KEY_CANARY.to_owned()],
        openai: None,
    };
    let (completed, completed_rx) = mpsc::channel();
    let reconfigure = thread::spawn(move || {
        let mut bootstrap = bootstrap;
        bootstrap.reconfigure(replacement);
        completed.send(()).expect("reconfigure completion");
        bootstrap
    });

    assert!(
        completed_rx
            .recv_timeout(Duration::from_millis(100))
            .is_err(),
        "reconfigure returned before the active provider worker was released"
    );
    server.release_and_join();
    let bootstrap = reconfigure.join().expect("reconfigure thread");

    assert!(bootstrap.agent_runtime_handle().is_none());
    assert!(load_run(&fixture, &request.run_id)
        .expect("terminal run")
        .status
        .is_terminal());
    assert_eq!(
        stale_runtime
            .cancel(CancelAgentRun {
                run_id: request.run_id.clone(),
                reason: "stale-runtime".to_owned(),
                deadline_ms: 1,
            })
            .expect_err("closed runtime cannot cancel")
            .safe_classification(),
        SafeErrorClassification::NotFound
    );
    let stale_request = bound_request(
        "run-reconfigure-stale",
        "agent-context-reconfigure-stale",
        digest_bytes(&context),
    );
    publish_artifact(
        &fixture,
        stale_request.context.effective_context_artifact_id.as_str(),
        "content",
        &context,
    );
    assert_eq!(
        stale_runtime
            .start_run(stale_request.clone())
            .expect_err("closed runtime cannot dispatch")
            .safe_classification(),
        SafeErrorClassification::Conflict
    );
    assert!(load_run(&fixture, &stale_request.run_id).is_none());
}

#[test]
fn retry_waits_for_active_openai_worker_and_permanently_closes_cloned_handle() {
    let fixture = WorkspaceFixture::new();
    let context = canonical_context();
    let request = bound_request(
        "run-retry-active",
        "agent-context-retry-active",
        digest_bytes(&context),
    );
    publish_artifact(
        &fixture,
        request.context.effective_context_artifact_id.as_str(),
        "content",
        &context,
    );

    let mut server = GatedSseServer::success();
    let bootstrap = Bootstrap::new(configured_workspace(&fixture, server.endpoint().to_owned()));
    let stale_runtime = bootstrap
        .agent_runtime_handle()
        .expect("configured provider runtime");
    stale_runtime
        .start_run(request.clone())
        .expect("active provider run");
    let _request = server.await_request();

    let (completed, completed_rx) = mpsc::channel();
    let retry = thread::spawn(move || {
        let mut bootstrap = bootstrap;
        bootstrap.retry_startup_validation();
        completed.send(()).expect("retry completion");
        bootstrap
    });

    assert!(
        completed_rx
            .recv_timeout(Duration::from_millis(100))
            .is_err(),
        "retry returned before the active provider worker was released"
    );
    server.release_and_join();
    let bootstrap = retry.join().expect("retry thread");

    assert!(bootstrap.agent_runtime_handle().is_some());
    assert!(load_run(&fixture, &request.run_id)
        .expect("terminal run")
        .status
        .is_terminal());
    assert_eq!(
        stale_runtime
            .cancel(CancelAgentRun {
                run_id: request.run_id.clone(),
                reason: "stale-runtime".to_owned(),
                deadline_ms: 1,
            })
            .expect_err("closed runtime cannot cancel")
            .safe_classification(),
        SafeErrorClassification::NotFound
    );
    let stale_request = bound_request(
        "run-retry-stale",
        "agent-context-retry-stale",
        digest_bytes(&context),
    );
    publish_artifact(
        &fixture,
        stale_request.context.effective_context_artifact_id.as_str(),
        "content",
        &context,
    );
    assert_eq!(
        stale_runtime
            .start_run(stale_request.clone())
            .expect_err("closed runtime cannot dispatch")
            .safe_classification(),
        SafeErrorClassification::Conflict
    );
    assert!(load_run(&fixture, &stale_request.run_id).is_none());
}

#[test]
fn dropping_bootstrap_waits_for_active_openai_worker_and_permanently_closes_cloned_handle() {
    let fixture = WorkspaceFixture::new();
    let context = canonical_context();
    let request = bound_request(
        "run-drop-active",
        "agent-context-drop-active",
        digest_bytes(&context),
    );
    publish_artifact(
        &fixture,
        request.context.effective_context_artifact_id.as_str(),
        "content",
        &context,
    );

    let mut server = GatedSseServer::success();
    let bootstrap = Bootstrap::new(configured_workspace(&fixture, server.endpoint().to_owned()));
    let stale_runtime = bootstrap
        .agent_runtime_handle()
        .expect("configured provider runtime");
    stale_runtime
        .start_run(request.clone())
        .expect("active provider run");
    let _request = server.await_request();

    let (completed, completed_rx) = mpsc::channel();
    let dropping = thread::spawn(move || {
        drop(bootstrap);
        completed.send(()).expect("drop completion");
    });

    assert!(
        completed_rx
            .recv_timeout(Duration::from_millis(100))
            .is_err(),
        "Bootstrap drop returned before the active provider worker was released"
    );
    server.release_and_join();
    dropping.join().expect("drop thread");

    assert!(load_run(&fixture, &request.run_id)
        .expect("terminal run")
        .status
        .is_terminal());
    assert_eq!(
        stale_runtime
            .cancel(CancelAgentRun {
                run_id: request.run_id.clone(),
                reason: "stale-runtime".to_owned(),
                deadline_ms: 1,
            })
            .expect_err("closed runtime cannot cancel")
            .safe_classification(),
        SafeErrorClassification::NotFound
    );
    let stale_request = bound_request(
        "run-drop-stale",
        "agent-context-drop-stale",
        digest_bytes(&context),
    );
    publish_artifact(
        &fixture,
        stale_request.context.effective_context_artifact_id.as_str(),
        "content",
        &context,
    );
    assert_eq!(
        stale_runtime
            .start_run(stale_request.clone())
            .expect_err("closed runtime cannot dispatch")
            .safe_classification(),
        SafeErrorClassification::Conflict
    );
    assert!(load_run(&fixture, &stale_request.run_id).is_none());
}

#[test]
fn successful_runs_before_and_after_bootstrap_restart_persist_distinct_messages() {
    let fixture = WorkspaceFixture::new();
    let context = canonical_context();
    let first_request = bound_request(
        "run-message-before-restart",
        "agent-context-message-before-restart",
        digest_bytes(&context),
    );
    let second_request = bound_request(
        "run-message-after-restart",
        "agent-context-message-after-restart",
        digest_bytes(&context),
    );
    for request in [&first_request, &second_request] {
        publish_artifact(
            &fixture,
            request.context.effective_context_artifact_id.as_str(),
            "content",
            &context,
        );
    }

    let mut first_server = GatedSseServer::success();
    let first_bootstrap = Bootstrap::new(configured_workspace(
        &fixture,
        first_server.endpoint().to_owned(),
    ));
    first_bootstrap
        .agent_runtime_handle()
        .expect("first runtime")
        .start_run(first_request.clone())
        .expect("first receipt");
    let _first_http = first_server.await_request();
    first_server.release_and_join();
    assert_eq!(
        wait_for_terminal(&fixture, &first_request.run_id).status,
        AgentRunStatus::Succeeded
    );
    drop(first_bootstrap);

    let mut second_server = GatedSseServer::success();
    let second_bootstrap = Bootstrap::new(configured_workspace(
        &fixture,
        second_server.endpoint().to_owned(),
    ));
    second_bootstrap
        .agent_runtime_handle()
        .expect("second runtime")
        .start_run(second_request.clone())
        .expect("second receipt");
    let _second_http = second_server.await_request();
    second_server.release_and_join();
    assert_eq!(
        wait_for_terminal(&fixture, &second_request.run_id).status,
        AgentRunStatus::Succeeded
    );

    let database = fixture.database();
    let first_message_id: String = database
        .query_row(
            "SELECT id FROM messages WHERE run_id = ?1",
            [first_request.run_id.as_str()],
            |row| row.get(0),
        )
        .expect("first persisted message");
    let second_message_id: String = database
        .query_row(
            "SELECT id FROM messages WHERE run_id = ?1",
            [second_request.run_id.as_str()],
            |row| row.get(0),
        )
        .expect("second persisted message");
    assert_ne!(first_message_id, second_message_id);
}

fn config(root: &Path) -> StartupConfig {
    StartupConfig {
        app_data_dir: root.join("app-data"),
        trusted_workspace_root: root.join("workspaces"),
        secret_values: Vec::new(),
        openai: None,
    }
}

fn configured(root: &Path) -> StartupConfig {
    let mut config = config(root);
    config.openai = Some(openai_config(
        "https://api.example.test/v1/responses".to_owned(),
    ));
    config
}

fn configured_workspace(fixture: &WorkspaceFixture, endpoint: String) -> StartupConfig {
    StartupConfig {
        app_data_dir: fixture.app_data.clone(),
        trusted_workspace_root: fixture.workspace_root.clone(),
        secret_values: vec![API_KEY_CANARY.to_owned()],
        openai: Some(openai_config(endpoint)),
    }
}

fn openai_config(endpoint: String) -> OpenAiBootstrapConfig {
    OpenAiBootstrapConfig {
        endpoint,
        api_key: OpenAiApiKey::new(API_KEY_CANARY).expect("API key"),
        manifest_digest: Sha256Digest::new(CORE_MANIFEST_DIGEST).expect("manifest digest"),
        core_release_digest: Sha256Digest::new(CORE_RELEASE_DIGEST).expect("release digest"),
        adapter_version: "openai-responses-v1".to_owned(),
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
                    created_by_id: "bootstrap-agent-runtime-e2e".to_owned(),
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

fn load_run(
    fixture: &WorkspaceFixture,
    run_id: &RunId,
) -> Option<local_agent_terminal_domain::AgentRunSnapshot> {
    SqliteStore::open(&fixture.database_path)
        .expect("database")
        .load_run(run_id)
        .expect("run query")
}

fn wait_for_terminal(
    fixture: &WorkspaceFixture,
    run_id: &RunId,
) -> local_agent_terminal_domain::AgentRunSnapshot {
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        if let Some(run) = load_run(fixture, run_id) {
            if run.status.is_terminal() {
                return run;
            }
        }
        assert!(Instant::now() < deadline, "agent run did not terminalize");
        thread::sleep(Duration::from_millis(10));
    }
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

fn message_artifact_id(fixture: &WorkspaceFixture, run_id: &RunId) -> String {
    fixture
        .database()
        .query_row(
            "SELECT content_artifact_id FROM messages WHERE run_id = ?1",
            params![run_id.as_str()],
            |row| row.get(0),
        )
        .expect("persisted message")
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

struct CapturedRequest {
    method: String,
    target: String,
    headers: BTreeMap<String, String>,
    body: Vec<u8>,
}

impl CapturedRequest {
    fn header(&self, name: &str) -> Option<&String> {
        self.headers.get(&name.to_ascii_lowercase())
    }
}

struct GatedSseServer {
    endpoint: String,
    captured: Receiver<CapturedRequest>,
    release: Option<Sender<()>>,
    worker: Option<thread::JoinHandle<()>>,
}

impl GatedSseServer {
    fn success() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("loopback listener");
        let endpoint = format!(
            "http://{}/v1/responses",
            listener.local_addr().expect("address")
        );
        let (captured_sender, captured) = mpsc::channel();
        let (release, wait_for_release) = mpsc::channel();
        let worker = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("OpenAI request");
            captured_sender
                .send(read_http_request(&stream))
                .expect("captured request");
            let body = b"data: {\"type\":\"response.created\",\"response\":{\"id\":\"resp-task8\"}}\n\ndata: {\"type\":\"response.output_text.delta\",\"delta\":\"accepted output\"}\n\ndata: {\"type\":\"response.completed\",\"response\":{\"id\":\"resp-task8\",\"usage\":{\"input_tokens\":3,\"output_tokens\":2}}}\n\n";
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            )
            .expect("response headers");
            stream.flush().expect("response headers flush");
            wait_for_release.recv().expect("release stream");
            stream.write_all(body).expect("SSE body");
            stream.flush().expect("SSE body flush");
        });
        Self {
            endpoint,
            captured,
            release: Some(release),
            worker: Some(worker),
        }
    }

    fn endpoint(&self) -> &str {
        &self.endpoint
    }

    fn await_request(&self) -> CapturedRequest {
        self.captured
            .recv_timeout(Duration::from_secs(1))
            .expect("OpenAI request")
    }

    fn release_and_join(&mut self) {
        if let Some(release) = self.release.take() {
            release.send(()).expect("release stream");
        }
        if let Some(worker) = self.worker.take() {
            worker.join().expect("loopback worker");
        }
    }
}

impl Drop for GatedSseServer {
    fn drop(&mut self) {
        if let Some(release) = self.release.take() {
            let _ = release.send(());
        }
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

struct ImmediateResponseServer {
    endpoint: String,
    captured: Receiver<CapturedRequest>,
    worker: Option<thread::JoinHandle<()>>,
}

impl ImmediateResponseServer {
    fn unavailable() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("loopback listener");
        let endpoint = format!(
            "http://{}/v1/responses",
            listener.local_addr().expect("address")
        );
        let (captured_sender, captured) = mpsc::channel();
        let worker = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("OpenAI request");
            captured_sender
                .send(read_http_request(&stream))
                .expect("captured request");
            stream
                .write_all(
                    b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                )
                .expect("unavailable response");
            stream.flush().expect("unavailable response flush");
        });
        Self {
            endpoint,
            captured,
            worker: Some(worker),
        }
    }

    fn endpoint(&self) -> &str {
        &self.endpoint
    }

    fn capture_and_join(mut self) -> CapturedRequest {
        let captured = self
            .captured
            .recv_timeout(Duration::from_secs(1))
            .expect("OpenAI request");
        self.worker
            .take()
            .expect("loopback worker")
            .join()
            .expect("loopback worker");
        captured
    }
}

impl Drop for ImmediateResponseServer {
    fn drop(&mut self) {
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

struct UnobservedLoopback {
    listener: TcpListener,
    endpoint: String,
}

impl UnobservedLoopback {
    fn new() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("loopback listener");
        listener
            .set_nonblocking(true)
            .expect("nonblocking listener");
        let endpoint = format!(
            "http://{}/v1/responses",
            listener.local_addr().expect("address")
        );
        Self { listener, endpoint }
    }

    fn endpoint(&self) -> &str {
        &self.endpoint
    }

    fn assert_no_connection(&self) {
        let deadline = Instant::now() + Duration::from_millis(150);
        loop {
            match self.listener.accept() {
                Ok(_) => panic!("OpenAI loopback received a request for an invalid context"),
                Err(error) if error.kind() == ErrorKind::WouldBlock => {
                    if Instant::now() >= deadline {
                        return;
                    }
                    thread::sleep(Duration::from_millis(5));
                }
                Err(error) => panic!("loopback accept failed: {error}"),
            }
        }
    }
}

fn read_http_request(stream: &TcpStream) -> CapturedRequest {
    let mut reader = BufReader::new(stream.try_clone().expect("clone stream"));
    let mut request_line = String::new();
    reader.read_line(&mut request_line).expect("request line");
    let mut parts = request_line.split_whitespace();
    let method = parts.next().expect("request method").to_owned();
    let target = parts.next().expect("request target").to_owned();
    let mut headers = BTreeMap::new();
    loop {
        let mut line = String::new();
        reader.read_line(&mut line).expect("request header");
        if line == "\r\n" || line == "\n" {
            break;
        }
        let (name, value) = line.split_once(':').expect("header delimiter");
        headers.insert(name.trim().to_ascii_lowercase(), value.trim().to_owned());
    }
    let content_length = headers
        .get("content-length")
        .expect("request content length")
        .parse::<usize>()
        .expect("numeric content length");
    let mut body = vec![0; content_length];
    reader.read_exact(&mut body).expect("request body");
    CapturedRequest {
        method,
        target,
        headers,
        body,
    }
}
