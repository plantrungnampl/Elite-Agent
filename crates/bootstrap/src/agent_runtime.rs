use std::{
    collections::BTreeSet,
    sync::{Arc, Mutex},
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
        lifecycle: Mutex::new(ComposedRuntimeLifecycle::Open),
    }))
}

pub(crate) struct ComposedAgentRuntime {
    database: SqliteStore,
    descriptor: AgentDescriptor,
    connection: BoundAgentConnection,
    durable_artifacts: Arc<DurableAgentArtifacts>,
    runtime: Arc<ProtocolAgentRuntime>,
    lifecycle: Mutex<ComposedRuntimeLifecycle>,
}

enum ComposedRuntimeLifecycle {
    Open,
    Closed,
}

impl ComposedAgentRuntime {
    pub(crate) fn shutdown(&self) -> Result<(), PortError> {
        let mut lifecycle = self.lifecycle.lock().map_err(|_| integrity_failure())?;
        if matches!(*lifecycle, ComposedRuntimeLifecycle::Closed) {
            return Ok(());
        }
        *lifecycle = ComposedRuntimeLifecycle::Closed;
        drop(lifecycle);
        self.runtime.shutdown()
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
        let lifecycle = self.lifecycle.lock().map_err(|_| integrity_failure())?;
        if matches!(*lifecycle, ComposedRuntimeLifecycle::Closed) {
            return Err(conflict());
        }
        self.prepare_run(&request)?;
        let receipt = self.runtime.start_run(request);
        drop(lifecycle);
        receipt
    }

    fn cancel(&self, request: CancelAgentRun) -> Result<AgentCancellationReceipt, PortError> {
        let lifecycle = self.lifecycle.lock().map_err(|_| integrity_failure())?;
        if matches!(*lifecycle, ComposedRuntimeLifecycle::Closed) {
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
