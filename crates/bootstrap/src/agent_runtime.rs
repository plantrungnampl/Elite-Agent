use std::{
    collections::BTreeSet,
    sync::{Arc, Condvar, Mutex, MutexGuard},
    time::Duration,
};

use local_agent_terminal_agent_runtime::{
    ConnectionBinding, PeerDescriptor, ProtocolAgentRuntime, ProtocolCapabilities, ProtocolPeer,
    ProtocolTrustTier,
};
use local_agent_terminal_application::{
    AgentArtifactStore, AgentCancellationReceipt, AgentDescriptor, AgentMessageArtifact,
    AgentRunReceipt, AgentRunStore, AgentRuntime, ArtifactId, ArtifactRef, ArtifactStore,
    ArtifactWriteReservation, BoundAgentConnection, BoundAgentRunRequest, BoundEffectiveContext,
    CancelAgentRun, CanonicalJsonRequest, Clock, PortError, ProjectId, ReservedArtifact,
    Retryability, SafeErrorClassification, Sha256Digest, TaskId, TaskQuery, TrustTier,
    WorkspaceEvidenceStore,
};
pub use local_agent_terminal_provider_openai::OpenAiApiKey;
use local_agent_terminal_provider_openai::{OpenAiProviderConfig, OpenAiResponsesAdapter};
use local_agent_terminal_storage_files::{ContentAddressedArtifactStore, JournaledArtifactWriter};
use local_agent_terminal_storage_sqlite::{canonical_agent_run_config_artifact, SqliteStore};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use url::Url;

use crate::workspace_monitor::publish_canonical_json;

const CORE_ADAPTER_ID: &str = "core_adapter";
const CORE_CONNECTION_ID: &str = "openai_core_adapter";
const PROTOCOL_VERSION: &str = "1.0";
const CORE_MANIFEST: &[u8] = br#"{"adapter":"openai-responses","agentId":"core_adapter","providerId":"openai","schema":"trusted-openai-core-adapter-manifest.v1"}"#;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const READ_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Clone)]
pub struct OpenAiBootstrapConfig {
    pub endpoint: String,
    pub api_key: OpenAiApiKey,
    pub manifest_digest: Sha256Digest,
    pub core_release_digest: Sha256Digest,
    pub adapter_version: String,
}

pub(crate) fn compose_openai_runtime(
    database: SqliteStore,
    artifacts: Arc<ContentAddressedArtifactStore>,
    config: &OpenAiBootstrapConfig,
) -> Result<Arc<ComposedAgentRuntime>, PortError> {
    let descriptor = core_adapter_descriptor(config)?;
    let connection = core_adapter_connection(config)?;
    let recovery_at = database.now_utc()?;
    database.reconcile_trusted_core_adapter(&descriptor, &recovery_at)?;
    let peer_descriptor = PeerDescriptor {
        binding: ConnectionBinding {
            connection_id: connection.connection_id.clone(),
            agent_id: connection.agent_id.clone(),
            manifest_digest: connection.manifest_digest.as_str().to_owned(),
            executable_digest: connection
                .executable_digest
                .as_ref()
                .ok_or_else(integrity_failure)?
                .as_str()
                .to_owned(),
            trust_tier: ProtocolTrustTier::CoreAdapter,
        },
        protocol_version: PROTOCOL_VERSION.to_owned(),
        capabilities: ProtocolCapabilities {
            roles: BTreeSet::from([
                "proposer".to_owned(),
                "critic".to_owned(),
                "reviewer".to_owned(),
                "verifier".to_owned(),
            ]),
            skills: BTreeSet::new(),
            streaming: true,
            context_query: false,
            tool_requests: false,
            specialist_requests: false,
            max_concurrent_runs: 1,
            max_context_tokens: 16_384,
        },
    };
    let endpoint = Url::parse(&config.endpoint).map_err(|_| invalid_input())?;
    let provider = match endpoint.scheme() {
        "https" => OpenAiProviderConfig::new(
            endpoint,
            config.api_key.clone(),
            CONNECT_TIMEOUT,
            READ_TIMEOUT,
        ),
        "http" => OpenAiProviderConfig::for_loopback_test(
            endpoint,
            config.api_key.clone(),
            CONNECT_TIMEOUT,
            READ_TIMEOUT,
        ),
        _ => return Err(invalid_input()),
    }
    .map_err(|_| invalid_input())?;
    let peer: Arc<dyn ProtocolPeer> = Arc::new(
        OpenAiResponsesAdapter::new(provider, peer_descriptor).map_err(|_| unavailable())?,
    );
    compose_runtime(database, artifacts, descriptor, connection, peer)
}

fn compose_runtime(
    database: SqliteStore,
    artifacts: Arc<ContentAddressedArtifactStore>,
    descriptor: AgentDescriptor,
    connection: BoundAgentConnection,
    peer: Arc<dyn ProtocolPeer>,
) -> Result<Arc<ComposedAgentRuntime>, PortError> {
    let durable_artifacts = Arc::new(DurableAgentArtifacts {
        database: database.clone(),
        artifacts,
    });
    let runtime = Arc::new(ProtocolAgentRuntime::new(
        Arc::new(database.clone()) as Arc<dyn AgentRunStore>,
        durable_artifacts.clone() as Arc<dyn AgentArtifactStore>,
        Arc::new(database.clone()) as Arc<dyn Clock>,
        vec![(descriptor.clone(), connection.binding_digest.clone(), peer)],
    )?);
    Ok(Arc::new(ComposedAgentRuntime {
        database,
        descriptor,
        connection,
        durable_artifacts,
        runtime,
        lifecycle: RuntimeLifecycle::new(),
    }))
}

pub(crate) struct ComposedAgentRuntime {
    database: SqliteStore,
    descriptor: AgentDescriptor,
    connection: BoundAgentConnection,
    durable_artifacts: Arc<DurableAgentArtifacts>,
    runtime: Arc<ProtocolAgentRuntime>,
    lifecycle: RuntimeLifecycle,
}

enum ComposedRuntimeLifecycle {
    Open,
    Closing,
    Closed(Result<(), PortError>),
}

struct RuntimeLifecycle {
    state: Mutex<ComposedRuntimeLifecycle>,
    shutdown_complete: Condvar,
}

impl RuntimeLifecycle {
    fn new() -> Self {
        Self {
            state: Mutex::new(ComposedRuntimeLifecycle::Open),
            shutdown_complete: Condvar::new(),
        }
    }

    fn lock(&self) -> Result<MutexGuard<'_, ComposedRuntimeLifecycle>, PortError> {
        self.state.lock().map_err(|_| integrity_failure())
    }

    fn shutdown(&self, cleanup: impl FnOnce() -> Result<(), PortError>) -> Result<(), PortError> {
        let mut state = self.lock()?;
        loop {
            match &*state {
                ComposedRuntimeLifecycle::Open => {
                    *state = ComposedRuntimeLifecycle::Closing;
                    break;
                }
                ComposedRuntimeLifecycle::Closing => {
                    state = self
                        .shutdown_complete
                        .wait(state)
                        .map_err(|_| integrity_failure())?;
                }
                ComposedRuntimeLifecycle::Closed(result) => return result.clone(),
            }
        }
        drop(state);

        let result = cleanup();
        let mut state = self.lock()?;
        *state = ComposedRuntimeLifecycle::Closed(result.clone());
        self.shutdown_complete.notify_all();
        result
    }
}

impl ComposedAgentRuntime {
    pub(crate) fn shutdown(&self) -> Result<(), PortError> {
        self.lifecycle.shutdown(|| self.runtime.shutdown())
    }

    fn prepare_run(&self, request: &BoundAgentRunRequest) -> Result<(), PortError> {
        request.validate().map_err(|_| invalid_input())?;
        if request.run_config.provider_id != "openai"
            || request.agent_id != self.descriptor.agent_id
            || request.connection != self.connection
            || request.run_config.trust_tier != self.descriptor.trust_tier
            || request.run_config.manifest_digest != self.descriptor.manifest_digest
            || request.run_config.executable_digest != self.descriptor.executable_digest
        {
            return Err(invalid_input());
        }

        self.publish_manifest(request)?;
        self.durable_artifacts
            .load_effective_context(&request.context)?;
        self.publish_run_config(request)
    }

    fn publish_manifest(&self, request: &BoundAgentRunRequest) -> Result<(), PortError> {
        let value: Value = serde_json::from_slice(&self.descriptor.manifest_json)
            .map_err(|_| integrity_failure())?;
        let published = publish_canonical_json(
            &self.database,
            self.durable_artifacts.artifacts.as_ref(),
            CanonicalJsonRequest::new(
                request.context.manifest_artifact_id.clone(),
                project_id(&self.database, &request.task_id)?,
                Some(request.task_id.clone()),
                "manifest",
                format!(
                    "agent-manifests/{}.json",
                    stable_digest(request.context.manifest_artifact_id.as_str())
                ),
                "core",
                "bootstrap",
                &value,
                format!(
                    "agent-manifest:{}",
                    request.context.manifest_artifact_id.as_str()
                ),
            )?,
        )?;
        if published.content_hash != self.descriptor.manifest_digest.as_str() {
            return Err(integrity_failure());
        }
        Ok(())
    }

    fn publish_run_config(&self, request: &BoundAgentRunRequest) -> Result<(), PortError> {
        let bytes = canonical_agent_run_config_artifact(request)?;
        let value: Value = serde_json::from_slice(&bytes).map_err(|_| integrity_failure())?;
        let published = publish_canonical_json(
            &self.database,
            self.durable_artifacts.artifacts.as_ref(),
            CanonicalJsonRequest::new(
                request.run_config.run_config_artifact_id.clone(),
                project_id(&self.database, &request.task_id)?,
                Some(request.task_id.clone()),
                "run-config",
                format!(
                    "agent-runs/{}.json",
                    stable_digest(request.run_config.run_config_artifact_id.as_str())
                ),
                "core",
                "bootstrap",
                &value,
                format!("agent-run-config:{}", request.run_id.as_str()),
            )?,
        )?;
        if published.content_hash != digest_bytes(&bytes).as_str() {
            return Err(integrity_failure());
        }
        Ok(())
    }
}

impl AgentRuntime for ComposedAgentRuntime {
    fn list_agents(&self) -> Result<Vec<AgentDescriptor>, PortError> {
        self.runtime.list_agents()
    }

    fn start_run(&self, request: BoundAgentRunRequest) -> Result<AgentRunReceipt, PortError> {
        let lifecycle = self.lifecycle.lock()?;
        if !matches!(*lifecycle, ComposedRuntimeLifecycle::Open) {
            return Err(conflict());
        }
        self.prepare_run(&request)?;
        let receipt = self.runtime.start_run(request);
        drop(lifecycle);
        receipt
    }

    fn cancel(&self, request: CancelAgentRun) -> Result<AgentCancellationReceipt, PortError> {
        let lifecycle = self.lifecycle.lock()?;
        if !matches!(*lifecycle, ComposedRuntimeLifecycle::Open) {
            return Err(not_found());
        }
        let receipt = self.runtime.cancel(request);
        drop(lifecycle);
        receipt
    }
}

struct DurableAgentArtifacts {
    database: SqliteStore,
    artifacts: Arc<ContentAddressedArtifactStore>,
}

impl AgentArtifactStore for DurableAgentArtifacts {
    fn load_effective_context(
        &self,
        context: &BoundEffectiveContext,
    ) -> Result<Vec<u8>, PortError> {
        let evidence = self
            .database
            .available_evidence(&context.effective_context_artifact_id)?
            .ok_or_else(not_found)?;
        if evidence.task_id.as_ref() != Some(&context.task_id)
            || evidence.content_hash != context.content_digest.as_str()
        {
            return Err(integrity_failure());
        }
        let bytes = self
            .artifacts
            .read(&ArtifactRef {
                content_hash: evidence.content_hash,
                storage_key: evidence.storage_key,
                size_bytes: evidence.size_bytes,
            })?
            .bytes;
        let value: Value = serde_json::from_slice(&bytes).map_err(|_| integrity_failure())?;
        let canonical =
            serde_json_canonicalizer::to_vec(&value).map_err(|_| integrity_failure())?;
        if canonical != bytes || digest_bytes(&bytes) != context.content_digest {
            return Err(integrity_failure());
        }
        Ok(bytes)
    }

    fn publish_agent_message(
        &self,
        artifact: &AgentMessageArtifact,
    ) -> Result<ArtifactId, PortError> {
        let task = self.database.task(&artifact.task_id)?;
        let artifact_id = ArtifactId::new(format!(
            "agent-message-{}",
            stable_digest(&format!(
                "{}:{}:{}",
                artifact.task_id.as_str(),
                artifact.run_id.as_str(),
                artifact.message_id,
            )),
        ))
        .map_err(|_| integrity_failure())?;
        let content_digest = digest_bytes(&artifact.content);
        if let Some(existing) = self.database.available_evidence(&artifact_id)? {
            if existing.task_id.as_ref() != Some(&artifact.task_id)
                || existing.project_id != task.project_id
                || existing.content_hash != content_digest.as_str()
                || existing.size_bytes != artifact.content.len() as u64
            {
                return Err(integrity_failure());
            }
            return Ok(artifact_id);
        }
        let created_at = self.database.now_utc()?;
        JournaledArtifactWriter::new(self.artifacts.as_ref(), &self.database, &self.database)
            .write(
                ArtifactWriteReservation {
                    operation_id: format!("agent-message:{}", artifact_id.as_str()),
                    artifact: ReservedArtifact {
                        artifact_id: artifact_id.as_str().to_owned(),
                        task_id: Some(artifact.task_id.clone()),
                        project_id: task.project_id.as_str().to_owned(),
                        artifact_type: "agent-message".to_owned(),
                        logical_path: format!(
                            "agent-messages/{}.txt",
                            stable_digest(artifact_id.as_str())
                        ),
                        content_hash: content_digest.as_str().to_owned(),
                        storage_key: ContentAddressedArtifactStore::storage_key(
                            content_digest.as_str(),
                        )?,
                        size_bytes: artifact.content.len() as u64,
                        mime_type: Some("text/plain; charset=utf-8".to_owned()),
                        created_by_type: "core".to_owned(),
                        created_by_id: "agent-runtime".to_owned(),
                        created_at: created_at.clone(),
                        supersedes: None,
                    },
                    temp_name: format!("{}.tmp", artifact_id.as_str()),
                    created_at,
                },
                &artifact.content,
            )?;
        Ok(artifact_id)
    }
}

fn core_adapter_descriptor(config: &OpenAiBootstrapConfig) -> Result<AgentDescriptor, PortError> {
    let manifest_digest = digest_bytes(CORE_MANIFEST);
    if config.manifest_digest != manifest_digest {
        return Err(integrity_failure());
    }
    let descriptor = AgentDescriptor {
        agent_id: CORE_ADAPTER_ID.to_owned(),
        display_name: "OpenAI Responses".to_owned(),
        trust_tier: TrustTier::CoreAdapter,
        manifest_json: CORE_MANIFEST.to_vec(),
        manifest_digest,
        executable_digest: Some(config.core_release_digest.clone()),
        enabled: true,
        containment_verified: true,
    };
    descriptor.validate().map_err(|_| invalid_input())?;
    Ok(descriptor)
}

fn core_adapter_connection(
    config: &OpenAiBootstrapConfig,
) -> Result<BoundAgentConnection, PortError> {
    let mut connection = BoundAgentConnection {
        connection_id: CORE_CONNECTION_ID.to_owned(),
        agent_id: CORE_ADAPTER_ID.to_owned(),
        trust_tier: TrustTier::CoreAdapter,
        manifest_digest: config.manifest_digest.clone(),
        executable_digest: Some(config.core_release_digest.clone()),
        contract_version: PROTOCOL_VERSION.to_owned(),
        adapter_version: config.adapter_version.clone(),
        binding_digest: digest_bytes(b"placeholder"),
    };
    connection.binding_digest = connection_digest(&connection)?;
    connection.validate().map_err(|_| invalid_input())?;
    Ok(connection)
}

fn connection_digest(connection: &BoundAgentConnection) -> Result<Sha256Digest, PortError> {
    let value = json!({
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
    });
    let canonical = serde_json_canonicalizer::to_vec(&value).map_err(|_| integrity_failure())?;
    Ok(digest_bytes(&canonical))
}

fn project_id(database: &SqliteStore, task_id: &TaskId) -> Result<ProjectId, PortError> {
    Ok(database.task(task_id)?.project_id)
}

fn digest_bytes(bytes: &[u8]) -> Sha256Digest {
    Sha256Digest::new(format!("sha256:{:x}", Sha256::digest(bytes)))
        .expect("SHA-256 formatting is valid")
}

fn stable_digest(value: &str) -> String {
    format!("{:x}", Sha256::digest(value.as_bytes()))
}

fn invalid_input() -> PortError {
    PortError::failure(
        SafeErrorClassification::InvalidInput,
        Retryability::NonRetryable,
    )
}

fn not_found() -> PortError {
    PortError::failure(
        SafeErrorClassification::NotFound,
        Retryability::NonRetryable,
    )
}

fn unavailable() -> PortError {
    PortError::failure(
        SafeErrorClassification::Unavailable,
        Retryability::NonRetryable,
    )
}

fn integrity_failure() -> PortError {
    PortError::failure(
        SafeErrorClassification::IntegrityFailure,
        Retryability::NonRetryable,
    )
}

fn conflict() -> PortError {
    PortError::failure(
        SafeErrorClassification::Conflict,
        Retryability::NonRetryable,
    )
}

#[cfg(test)]
mod tests {
    use std::{
        path::Path,
        sync::{
            atomic::{AtomicUsize, Ordering},
            mpsc, Arc, Mutex,
        },
        thread,
        time::Duration,
    };

    use local_agent_terminal_agent_runtime::{ProtocolAgentRuntime, Script, ScriptedPeer};
    use local_agent_terminal_application::StartupStateDto;
    use tempfile::TempDir;

    use crate::{Bootstrap, StartupConfig};

    use super::*;

    #[test]
    fn shutdown_preserves_failed_cleanup_result_for_repeated_calls() {
        let temporary = TempDir::new().expect("temporary state directory");
        let clock = Arc::new(FailingShutdownClock::default());
        let runtime = runtime_with_clock(temporary.path(), Arc::clone(&clock));

        let first = runtime.shutdown();
        let repeated = runtime.shutdown();

        assert_shutdown_failure(first);
        assert_shutdown_failure(repeated);
        assert_eq!(clock.calls.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn shutdown_serializes_concurrent_cleanup_and_shares_the_failure() {
        let temporary = TempDir::new().expect("temporary state directory");
        let (cleanup_entered, wait_for_cleanup) = mpsc::channel();
        let (release_cleanup, release) = mpsc::channel();
        let clock = Arc::new(GatedFailureClock::new(cleanup_entered, release));
        let runtime = Arc::new(runtime_with_clock(temporary.path(), Arc::clone(&clock)));
        let (first_done, wait_for_first) = mpsc::channel();
        let first_runtime = Arc::clone(&runtime);
        let first = thread::spawn(move || {
            let _ = first_done.send(first_runtime.shutdown());
        });

        wait_for_cleanup
            .recv_timeout(Duration::from_secs(1))
            .expect("first shutdown entered cleanup");
        let (second_done, wait_for_second) = mpsc::channel();
        let second_runtime = Arc::clone(&runtime);
        let second = thread::spawn(move || {
            let _ = second_done.send(second_runtime.shutdown());
        });

        assert!(
            wait_for_second
                .recv_timeout(Duration::from_millis(30))
                .is_err(),
            "concurrent shutdown returned before authoritative cleanup completed"
        );
        release_cleanup.send(()).expect("release cleanup");

        assert_shutdown_failure(
            wait_for_first
                .recv_timeout(Duration::from_secs(1))
                .expect("first shutdown result"),
        );
        assert_shutdown_failure(
            wait_for_second
                .recv_timeout(Duration::from_secs(1))
                .expect("second shutdown result"),
        );
        first.join().expect("first shutdown thread");
        second.join().expect("second shutdown thread");
        assert_eq!(clock.cleanup_calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn bootstrap_retry_retains_a_runtime_with_a_failed_shutdown_result() {
        let temporary = TempDir::new().expect("temporary state directory");
        let clock = Arc::new(FailingShutdownClock::default());
        let runtime = Arc::new(runtime_with_clock(temporary.path(), Arc::clone(&clock)));
        let mut bootstrap = Bootstrap::with_agent_runtime_for_test(
            StartupConfig {
                app_data_dir: temporary.path().join("app-data"),
                trusted_workspace_root: temporary.path().join("workspaces"),
                secret_values: Vec::new(),
                openai: None,
            },
            runtime,
        );

        assert_eq!(
            bootstrap.retry_startup_validation().state,
            StartupStateDto::RecoverableFailure
        );
        assert_eq!(
            bootstrap.status().issues[0].code,
            "startup.agent_runtime_shutdown_failed"
        );
        assert!(bootstrap.agent_runtime_handle().is_some());
        assert_eq!(
            bootstrap.retry_startup_validation().state,
            StartupStateDto::RecoverableFailure
        );
        assert_eq!(
            bootstrap.status().issues[0].code,
            "startup.agent_runtime_shutdown_failed"
        );
        assert!(bootstrap.agent_runtime_handle().is_some());
        assert_eq!(clock.calls.load(Ordering::SeqCst), 2);
    }

    fn runtime_with_clock<C>(path: &Path, clock: Arc<C>) -> ComposedAgentRuntime
    where
        C: Clock + 'static,
    {
        let database = SqliteStore::open(path.join("state.sqlite3")).expect("database");
        let artifacts = Arc::new(
            ContentAddressedArtifactStore::open(path.join("artifacts")).expect("artifact store"),
        );
        let config = OpenAiBootstrapConfig {
            endpoint: "http://127.0.0.1:9/v1/responses".to_owned(),
            api_key: OpenAiApiKey::new("sk-test-key").expect("API key"),
            manifest_digest: digest_bytes(CORE_MANIFEST),
            core_release_digest: digest_bytes(b"test-release"),
            adapter_version: "test-adapter-v1".to_owned(),
        };
        let descriptor = core_adapter_descriptor(&config).expect("descriptor");
        let connection = core_adapter_connection(&config).expect("connection");
        let peer: Arc<dyn ProtocolPeer> = Arc::new(ScriptedPeer::new(
            Script::Slow,
            peer_descriptor(&connection),
        ));
        let durable_artifacts = Arc::new(DurableAgentArtifacts {
            database: database.clone(),
            artifacts,
        });
        let runtime = Arc::new(
            ProtocolAgentRuntime::new(
                Arc::new(database.clone()) as Arc<dyn AgentRunStore>,
                durable_artifacts.clone() as Arc<dyn AgentArtifactStore>,
                clock as Arc<dyn Clock>,
                vec![(descriptor.clone(), connection.binding_digest.clone(), peer)],
            )
            .expect("protocol runtime"),
        );

        ComposedAgentRuntime {
            database,
            descriptor,
            connection,
            durable_artifacts,
            runtime,
            lifecycle: RuntimeLifecycle::new(),
        }
    }

    fn peer_descriptor(connection: &BoundAgentConnection) -> PeerDescriptor {
        PeerDescriptor {
            binding: ConnectionBinding {
                connection_id: connection.connection_id.clone(),
                agent_id: connection.agent_id.clone(),
                manifest_digest: connection.manifest_digest.as_str().to_owned(),
                executable_digest: connection
                    .executable_digest
                    .as_ref()
                    .expect("core connection executable digest")
                    .as_str()
                    .to_owned(),
                trust_tier: ProtocolTrustTier::CoreAdapter,
            },
            protocol_version: PROTOCOL_VERSION.to_owned(),
            capabilities: ProtocolCapabilities {
                roles: BTreeSet::from([
                    "proposer".to_owned(),
                    "critic".to_owned(),
                    "reviewer".to_owned(),
                    "verifier".to_owned(),
                ]),
                skills: BTreeSet::new(),
                streaming: true,
                context_query: false,
                tool_requests: false,
                specialist_requests: false,
                max_concurrent_runs: 1,
                max_context_tokens: 16_384,
            },
        }
    }

    fn assert_shutdown_failure(result: Result<(), PortError>) {
        let error = result.expect_err("shutdown must preserve the cleanup failure");
        assert_eq!(
            error.safe_classification(),
            SafeErrorClassification::Internal
        );
        assert_eq!(error.retryability(), Retryability::NonRetryable);
    }

    #[derive(Default)]
    struct FailingShutdownClock {
        calls: AtomicUsize,
    }

    impl Clock for FailingShutdownClock {
        fn now_utc(&self) -> Result<String, PortError> {
            if self.calls.fetch_add(1, Ordering::SeqCst) == 0 {
                return Ok("2026-07-23T13:30:00Z".to_owned());
            }
            Err(PortError::failure(
                SafeErrorClassification::Internal,
                Retryability::NonRetryable,
            ))
        }
    }

    struct GatedFailureClock {
        calls: AtomicUsize,
        cleanup_calls: AtomicUsize,
        cleanup_entered: mpsc::Sender<()>,
        release: Mutex<mpsc::Receiver<()>>,
    }

    impl GatedFailureClock {
        fn new(cleanup_entered: mpsc::Sender<()>, release: mpsc::Receiver<()>) -> Self {
            Self {
                calls: AtomicUsize::new(0),
                cleanup_calls: AtomicUsize::new(0),
                cleanup_entered,
                release: Mutex::new(release),
            }
        }
    }

    impl Clock for GatedFailureClock {
        fn now_utc(&self) -> Result<String, PortError> {
            if self.calls.fetch_add(1, Ordering::SeqCst) == 0 {
                return Ok("2026-07-23T13:30:00Z".to_owned());
            }
            self.cleanup_calls.fetch_add(1, Ordering::SeqCst);
            let _ = self.cleanup_entered.send(());
            let _ = self.release.lock().map_err(|_| integrity_failure())?.recv();
            Err(PortError::failure(
                SafeErrorClassification::Internal,
                Retryability::NonRetryable,
            ))
        }
    }
}
