#[allow(dead_code)]
mod support;

use std::{
    io::{BufRead, BufReader, Write},
    net::{TcpListener, TcpStream},
    sync::Arc,
    thread,
    time::{Duration, Instant},
};

use local_agent_terminal_application::{
    AgentRunStore, ArtifactWriteReservation, Clock, ReservedArtifact, TaskQuery,
};
use local_agent_terminal_bootstrap::{
    Bootstrap, OpenAiApiKey, OpenAiBootstrapConfig, StartupConfig, StartupStateDto,
};
use local_agent_terminal_domain::{
    AgentRunLimits, AgentRunStatus, ArtifactId, BoundAgentConnection, BoundAgentRunRequest,
    BoundEffectiveContext, BoundGenerationParameters, BoundRunConfig, RunId, Sha256Digest, TaskId,
    Timestamp, TrustTier,
};
use local_agent_terminal_storage_files::{
    ContentAddressedArtifactReader, ContentAddressedArtifactStore, JournaledArtifactWriter,
};
use local_agent_terminal_storage_sqlite::SqliteStore;
use serde_json::json;
use sha2::{Digest, Sha256};

use support::{WorkspaceFixture, PROJECT_ID, TASK_ID};

const API_KEY_CANARY: &str = "sk-m4-recovery-canary";
const CORE_MANIFEST_DIGEST: &str =
    "sha256:28d00daa6b56f0d8bb9b6ad78dd561a24bb61c668af842446c3a845e5b8ff0e5";
const CORE_RELEASE_DIGEST: &str =
    "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

#[test]
fn provider_failure_isolated_and_restart_reconstructs_exact_parallel_run() {
    let fixture = WorkspaceFixture::new();
    let context = canonical_json(&json!({
        "objective": "Prove failure isolation and recovery.",
        "sources": [],
    }));
    let request = bound_request(&context);
    publish_context(&fixture, &request, &context);
    let before = task_snapshot(&fixture);
    let server = OutageServer::new();
    let endpoint = server.endpoint();
    let bootstrap = Bootstrap::new(startup_config(&fixture, endpoint.clone()));
    assert_eq!(bootstrap.status().state, StartupStateDto::Ready);
    let runtime = bootstrap
        .agent_runtime_handle()
        .expect("configured provider runtime");

    runtime
        .start_run(request.clone())
        .expect("durable run receipt");
    server.capture_and_join();
    assert_eq!(
        wait_for_terminal(&fixture, &request.run_id).status,
        AgentRunStatus::Failed
    );
    assert_eq!(task_snapshot(&fixture), before);
    assert_eq!(
        fixture
            .database()
            .query_row("SELECT COUNT(*) FROM messages", [], |row| row
                .get::<_, i64>(0))
            .expect("shared messages"),
        0
    );
    assert_eq!(
        fixture
            .database()
            .query_row(
                "SELECT COUNT(*) FROM agent_run_outputs WHERE run_id = ?1",
                [request.run_id.as_str()],
                |row| row.get::<_, i64>(0),
            )
            .expect("private terminal output"),
        1
    );

    drop(runtime);
    drop(bootstrap);
    let restarted = Bootstrap::new(startup_config(&fixture, endpoint));
    assert_eq!(restarted.status().state, StartupStateDto::Ready);
    let reopened = SqliteStore::open(&fixture.database_path)
        .expect("reopened database")
        .with_artifact_reader(Arc::new(ContentAddressedArtifactReader));
    let recovered = reopened
        .load_run(&request.run_id)
        .expect("recovered run query")
        .expect("recovered run");
    assert_eq!(recovered.request, request);
    assert_eq!(recovered.status, AgentRunStatus::Failed);
    assert!(recovered.completed_at.is_some());
    assert_eq!(task_snapshot(&fixture), before);
}

fn startup_config(fixture: &WorkspaceFixture, endpoint: String) -> StartupConfig {
    StartupConfig {
        app_data_dir: fixture.app_data.clone(),
        trusted_workspace_root: fixture.workspace_root.clone(),
        secret_values: vec![API_KEY_CANARY.to_owned()],
        openai: Some(OpenAiBootstrapConfig {
            endpoint,
            api_key: OpenAiApiKey::new(API_KEY_CANARY).expect("API key"),
            manifest_digest: digest(CORE_MANIFEST_DIGEST),
            core_release_digest: digest(CORE_RELEASE_DIGEST),
            adapter_version: "openai-responses-v1".to_owned(),
        }),
        anthropic: None,
    }
}

fn bound_request(context: &[u8]) -> BoundAgentRunRequest {
    let task_id = TaskId::new(TASK_ID).expect("task id");
    let manifest_digest = digest(CORE_MANIFEST_DIGEST);
    let executable_digest = Some(digest(CORE_RELEASE_DIGEST));
    let context_digest = digest_bytes(context);
    let generation_parameters = canonical_json(&json!({"temperature": 0}));
    let mut connection = BoundAgentConnection {
        connection_id: "openai_core_adapter".to_owned(),
        agent_id: "core_adapter".to_owned(),
        trust_tier: TrustTier::CoreAdapter,
        manifest_digest: manifest_digest.clone(),
        executable_digest: executable_digest.clone(),
        contract_version: "1.0".to_owned(),
        adapter_version: "openai-responses-v1".to_owned(),
        binding_digest: digest(
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        ),
    };
    connection.binding_digest = digest_bytes(&canonical_json(&json!({
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
    let request = BoundAgentRunRequest {
        run_id: RunId::new("run-openai-recovery-outage").expect("run id"),
        task_id: task_id.clone(),
        agent_id: "core_adapter".to_owned(),
        role: "critic".to_owned(),
        phase: "ParallelAnalysis".to_owned(),
        idempotency_key: "task-1:ParallelAnalysis:run-openai-recovery-outage".to_owned(),
        context: BoundEffectiveContext {
            context_package_id: "context-recovery-outage".to_owned(),
            task_id: task_id.clone(),
            agent_id: "core_adapter".to_owned(),
            role: "critic".to_owned(),
            objective: "Prove failure isolation and recovery.".to_owned(),
            manifest_artifact_id: ArtifactId::new("manifest-recovery-outage")
                .expect("manifest artifact"),
            effective_context_artifact_id: ArtifactId::new("context-recovery-outage")
                .expect("context artifact"),
            content_digest: context_digest.clone(),
            policy_snapshot_digest: digest_bytes(b"m4-recovery-policy"),
            prompt_template_version: "prompt-v1".to_owned(),
            retrieval_pipeline_version: "retrieval-v1".to_owned(),
            created_at: Timestamp::from_unix_seconds(1_800_000_000),
        },
        run_config: BoundRunConfig {
            run_config_artifact_id: ArtifactId::new("run-config-recovery-outage")
                .expect("run config artifact"),
            task_id,
            agent_id: "core_adapter".to_owned(),
            role: "critic".to_owned(),
            context_package_id: "context-recovery-outage".to_owned(),
            effective_context_artifact_id: ArtifactId::new("context-recovery-outage")
                .expect("context artifact"),
            effective_context_digest: context_digest,
            trust_tier: TrustTier::CoreAdapter,
            manifest_digest,
            executable_digest,
            contract_version: "1.0".to_owned(),
            adapter_version: "openai-responses-v1".to_owned(),
            provider_id: "openai".to_owned(),
            model_id: "gpt-m4-recovery".to_owned(),
            generation_parameters: BoundGenerationParameters {
                digest: digest_bytes(&generation_parameters),
                canonical_json: generation_parameters,
            },
            prompt_template_version: "prompt-v1".to_owned(),
            response_schema_version: "agent-message.v1".to_owned(),
            policy_snapshot_digest: digest_bytes(b"m4-recovery-policy"),
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

fn publish_context(fixture: &WorkspaceFixture, request: &BoundAgentRunRequest, bytes: &[u8]) {
    let database = SqliteStore::open(&fixture.database_path).expect("database");
    let artifacts = ContentAddressedArtifactStore::open(fixture.app_data.join("artifacts"))
        .expect("artifact store");
    let digest = digest_bytes(bytes);
    let created_at = database.now_utc().expect("clock");
    JournaledArtifactWriter::new(&artifacts, &database, &database)
        .write(
            ArtifactWriteReservation {
                operation_id: "m4-recovery-context".to_owned(),
                artifact: ReservedArtifact {
                    artifact_id: request
                        .context
                        .effective_context_artifact_id
                        .as_str()
                        .to_owned(),
                    task_id: Some(request.task_id.clone()),
                    project_id: PROJECT_ID.to_owned(),
                    artifact_type: "content".to_owned(),
                    logical_path: "m4-recovery/context.json".to_owned(),
                    content_hash: digest.as_str().to_owned(),
                    storage_key: ContentAddressedArtifactStore::storage_key(digest.as_str())
                        .expect("storage key"),
                    size_bytes: bytes.len() as u64,
                    mime_type: Some("application/json".to_owned()),
                    created_by_type: "core".to_owned(),
                    created_by_id: "m4-recovery".to_owned(),
                    created_at: created_at.clone(),
                    supersedes: None,
                },
                temp_name: "m4-recovery-context.tmp".to_owned(),
                created_at,
            },
            bytes,
        )
        .expect("publish context");
}

fn wait_for_terminal(
    fixture: &WorkspaceFixture,
    run_id: &RunId,
) -> local_agent_terminal_domain::AgentRunSnapshot {
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        let store = SqliteStore::open(&fixture.database_path)
            .expect("database")
            .with_artifact_reader(Arc::new(ContentAddressedArtifactReader));
        if let Some(run) = store.load_run(run_id).expect("run query") {
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

fn canonical_json(value: &serde_json::Value) -> Vec<u8> {
    serde_json_canonicalizer::to_vec(value).expect("canonical JSON")
}

fn digest(value: &str) -> Sha256Digest {
    Sha256Digest::new(value).expect("digest")
}

fn digest_bytes(bytes: &[u8]) -> Sha256Digest {
    Sha256Digest::new(format!("sha256:{:x}", Sha256::digest(bytes))).expect("digest")
}

struct OutageServer {
    endpoint: String,
    worker: thread::JoinHandle<()>,
}

impl OutageServer {
    fn new() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("loopback listener");
        let endpoint = format!(
            "http://{}/v1/responses",
            listener.local_addr().expect("loopback address")
        );
        let worker = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("provider request");
            read_request_headers(&stream);
            stream
                .write_all(
                    b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                )
                .expect("outage response");
            stream.flush().expect("outage flush");
        });
        Self { endpoint, worker }
    }

    fn endpoint(&self) -> String {
        self.endpoint.clone()
    }

    fn capture_and_join(self) {
        self.worker.join().expect("outage worker");
    }
}

fn read_request_headers(stream: &TcpStream) {
    let mut reader = BufReader::new(stream.try_clone().expect("clone request stream"));
    loop {
        let mut line = String::new();
        reader.read_line(&mut line).expect("request header");
        if line == "\r\n" {
            return;
        }
    }
}
