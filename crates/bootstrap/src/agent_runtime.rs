use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{Arc, Condvar, Mutex, MutexGuard},
    time::Duration,
};

use local_agent_terminal_agent_runtime::{
    ConnectionBinding, PeerDescriptor, ProtocolAgentRuntime, ProtocolCapabilities, ProtocolPeer,
    ProtocolTrustTier,
};
use local_agent_terminal_application::{
    AgentArtifactStore, AgentCancellationReceipt, AgentContextQueryRequest,
    AgentContextQueryResponse, AgentDescriptor, AgentMessageArtifact, AgentRequestAudit,
    AgentRequestAuditDecision, AgentRequestHandler, AgentRequestKind, AgentRunReceipt,
    AgentRunStore, AgentRuntime, AgentSpecialistRequest, AgentSpecialistResponse, ArtifactId,
    ArtifactRef, ArtifactStore, ArtifactWriteReservation, BoundAgentConnection,
    BoundAgentRunRequest, BoundEffectiveContext, CancelAgentRun, CanonicalJsonRequest, Clock,
    PortError, ProjectId, ReservedArtifact, Retryability, SafeErrorClassification, Sha256Digest,
    TaskId, TaskQuery, TrustTier, WorkspaceEvidenceStore,
};
pub use local_agent_terminal_provider_anthropic::AnthropicApiKey;
use local_agent_terminal_provider_anthropic::{AnthropicMessagesAdapter, AnthropicProviderConfig};
pub use local_agent_terminal_provider_openai::OpenAiApiKey;
use local_agent_terminal_provider_openai::{OpenAiProviderConfig, OpenAiResponsesAdapter};
use local_agent_terminal_storage_files::{
    ContentAddressedArtifactReader, ContentAddressedArtifactStore, JournaledArtifactWriter,
};
use local_agent_terminal_storage_sqlite::{canonical_agent_run_config_artifact, SqliteStore};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use url::Url;

use crate::workspace_monitor::publish_canonical_json;

const OPENAI_AGENT_ID: &str = "core_adapter";
const OPENAI_CONNECTION_ID: &str = "openai_core_adapter";
const ANTHROPIC_AGENT_ID: &str = "anthropic_core_adapter";
const ANTHROPIC_CONNECTION_ID: &str = "anthropic_core_adapter";
const PROTOCOL_VERSION: &str = "1.0";
const OPENAI_MANIFEST: &[u8] = br#"{"adapter":"openai-responses","agentId":"core_adapter","providerId":"openai","schema":"trusted-openai-core-adapter-manifest.v1"}"#;
const ANTHROPIC_MANIFEST: &[u8] = br#"{"adapter":"anthropic-messages","agentId":"anthropic_core_adapter","providerId":"anthropic","schema":"trusted-anthropic-core-adapter-manifest.v1"}"#;
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

#[derive(Clone)]
pub struct AnthropicBootstrapConfig {
    pub endpoint: String,
    pub api_key: AnthropicApiKey,
    pub manifest_digest: Sha256Digest,
    pub core_release_digest: Sha256Digest,
    pub adapter_version: String,
}

struct ComposedPeer {
    descriptor: AgentDescriptor,
    connection: BoundAgentConnection,
    provider_id: String,
    peer: Arc<dyn ProtocolPeer>,
}

pub(crate) fn compose_agent_runtime(
    database: SqliteStore,
    artifacts: Arc<ContentAddressedArtifactStore>,
    openai: Option<&OpenAiBootstrapConfig>,
    anthropic: Option<&AnthropicBootstrapConfig>,
) -> Result<Option<Arc<ComposedAgentRuntime>>, PortError> {
    let mut peers = Vec::new();
    if let Some(config) = openai {
        peers.push(compose_openai_peer(config)?);
    }
    if let Some(config) = anthropic {
        peers.push(compose_anthropic_peer(config)?);
    }
    if peers.is_empty() {
        return Ok(None);
    }
    let recovery_at = database.now_utc()?;
    for peer in &peers {
        database.reconcile_trusted_core_adapter(&peer.descriptor, &recovery_at)?;
    }
    compose_runtime(database, artifacts, peers).map(Some)
}

fn compose_openai_peer(config: &OpenAiBootstrapConfig) -> Result<ComposedPeer, PortError> {
    let descriptor = core_adapter_descriptor(
        OPENAI_AGENT_ID,
        "OpenAI Responses",
        OPENAI_MANIFEST,
        &config.manifest_digest,
        &config.core_release_digest,
    )?;
    let connection = core_adapter_connection(
        OPENAI_CONNECTION_ID,
        OPENAI_AGENT_ID,
        &config.manifest_digest,
        &config.core_release_digest,
        &config.adapter_version,
    )?;
    let peer_descriptor = peer_descriptor(&connection)?;
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
    Ok(ComposedPeer {
        descriptor,
        connection,
        provider_id: "openai".to_owned(),
        peer,
    })
}

fn compose_anthropic_peer(config: &AnthropicBootstrapConfig) -> Result<ComposedPeer, PortError> {
    let descriptor = core_adapter_descriptor(
        ANTHROPIC_AGENT_ID,
        "Anthropic Messages",
        ANTHROPIC_MANIFEST,
        &config.manifest_digest,
        &config.core_release_digest,
    )?;
    let connection = core_adapter_connection(
        ANTHROPIC_CONNECTION_ID,
        ANTHROPIC_AGENT_ID,
        &config.manifest_digest,
        &config.core_release_digest,
        &config.adapter_version,
    )?;
    let peer_descriptor = peer_descriptor(&connection)?;
    let endpoint = Url::parse(&config.endpoint).map_err(|_| invalid_input())?;
    let provider = match endpoint.scheme() {
        "https" => AnthropicProviderConfig::new(
            endpoint,
            config.api_key.clone(),
            CONNECT_TIMEOUT,
            READ_TIMEOUT,
        ),
        "http" => AnthropicProviderConfig::for_loopback_test(
            endpoint,
            config.api_key.clone(),
            CONNECT_TIMEOUT,
            READ_TIMEOUT,
        ),
        _ => return Err(invalid_input()),
    }
    .map_err(|_| invalid_input())?;
    let peer: Arc<dyn ProtocolPeer> = Arc::new(
        AnthropicMessagesAdapter::new(provider, peer_descriptor).map_err(|_| unavailable())?,
    );
    Ok(ComposedPeer {
        descriptor,
        connection,
        provider_id: "anthropic".to_owned(),
        peer,
    })
}

fn peer_descriptor(connection: &BoundAgentConnection) -> Result<PeerDescriptor, PortError> {
    Ok(PeerDescriptor {
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
    })
}

fn compose_runtime(
    database: SqliteStore,
    artifacts: Arc<ContentAddressedArtifactStore>,
    peers: Vec<ComposedPeer>,
) -> Result<Arc<ComposedAgentRuntime>, PortError> {
    let database = database.with_artifact_reader(Arc::new(ContentAddressedArtifactReader));
    let request_handler = Arc::new(DurableAgentRequestHandler {
        database: database.clone(),
        artifacts: Arc::clone(&artifacts),
    });
    let durable_artifacts = Arc::new(DurableAgentArtifacts {
        database: database.clone(),
        artifacts,
    });
    let mut descriptors = BTreeMap::new();
    let mut connections = BTreeMap::new();
    let mut provider_ids = BTreeMap::new();
    let mut runtime_peers = Vec::with_capacity(peers.len());
    for peer in peers {
        let agent_id = peer.descriptor.agent_id.clone();
        if descriptors
            .insert(agent_id.clone(), peer.descriptor.clone())
            .is_some()
            || connections
                .insert(agent_id.clone(), peer.connection.clone())
                .is_some()
            || provider_ids
                .insert(agent_id, peer.provider_id.clone())
                .is_some()
        {
            return Err(integrity_failure());
        }
        runtime_peers.push((peer.descriptor, peer.connection.binding_digest, peer.peer));
    }
    let runtime = Arc::new(ProtocolAgentRuntime::new_with_request_handler(
        Arc::new(database.clone()) as Arc<dyn AgentRunStore>,
        durable_artifacts.clone() as Arc<dyn AgentArtifactStore>,
        Arc::new(database.clone()) as Arc<dyn Clock>,
        runtime_peers,
        request_handler as Arc<dyn AgentRequestHandler>,
    )?);
    Ok(Arc::new(ComposedAgentRuntime {
        database,
        descriptors,
        connections,
        provider_ids,
        durable_artifacts,
        runtime,
        lifecycle: RuntimeLifecycle::new(),
    }))
}

pub(crate) struct ComposedAgentRuntime {
    database: SqliteStore,
    descriptors: BTreeMap<String, AgentDescriptor>,
    connections: BTreeMap<String, BoundAgentConnection>,
    provider_ids: BTreeMap<String, String>,
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
        let descriptor = self
            .descriptors
            .get(&request.agent_id)
            .ok_or_else(invalid_input)?;
        let connection = self
            .connections
            .get(&request.agent_id)
            .ok_or_else(invalid_input)?;
        let provider_id = self
            .provider_ids
            .get(&request.agent_id)
            .ok_or_else(invalid_input)?;
        if request.run_config.provider_id != *provider_id
            || request.connection != *connection
            || request.run_config.trust_tier != descriptor.trust_tier
            || request.run_config.manifest_digest != descriptor.manifest_digest
            || request.run_config.executable_digest != descriptor.executable_digest
        {
            return Err(invalid_input());
        }

        self.publish_manifest(request, descriptor)?;
        self.durable_artifacts
            .load_effective_context(&request.context)?;
        self.publish_run_config(request)
    }

    fn publish_manifest(
        &self,
        request: &BoundAgentRunRequest,
        descriptor: &AgentDescriptor,
    ) -> Result<(), PortError> {
        let value: Value =
            serde_json::from_slice(&descriptor.manifest_json).map_err(|_| integrity_failure())?;
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
        if published.content_hash != descriptor.manifest_digest.as_str() {
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

struct DurableAgentRequestHandler {
    database: SqliteStore,
    artifacts: Arc<ContentAddressedArtifactStore>,
}

impl AgentRequestHandler for DurableAgentRequestHandler {
    fn query_context(
        &self,
        _request: AgentContextQueryRequest,
    ) -> Result<AgentContextQueryResponse, PortError> {
        Err(permission_denied())
    }

    fn request_specialist(
        &self,
        _request: AgentSpecialistRequest,
    ) -> Result<AgentSpecialistResponse, PortError> {
        Err(permission_denied())
    }

    fn persist_audit(&self, audit: AgentRequestAudit) -> Result<(), PortError> {
        let fence = audit.fence.clone();
        if fence.is_revoked() {
            return Err(conflict());
        }
        let kind = match audit.kind {
            AgentRequestKind::ContextQuery => "context-query",
            AgentRequestKind::SpecialistRequest => "specialist-request",
        };
        let decision = match audit.decision {
            AgentRequestAuditDecision::Accepted => "accepted",
            AgentRequestAuditDecision::Rejected => "rejected",
        };
        let identity = format!(
            "{}:{}:{}:{}:{}:{}:{}:{}",
            audit.run_id.as_str(),
            audit.request_id,
            audit.request_digest.as_str(),
            audit.connection_binding_digest.as_str(),
            kind,
            decision,
            audit.reason_code.as_deref().unwrap_or("none"),
            audit.deadline.unix_seconds(),
        );
        let artifact_id =
            ArtifactId::new(format!("agent-request-audit-{}", stable_digest(&identity)))
                .map_err(|_| integrity_failure())?;
        let value = json!({
            "schema": "agent-request-audit.v1",
            "runId": audit.run_id.as_str(),
            "taskId": audit.task_id.as_str(),
            "connectionId": audit.connection_id,
            "connectionBindingDigest": audit.connection_binding_digest.as_str(),
            "requestId": audit.request_id,
            "kind": kind,
            "requestDigest": audit.request_digest.as_str(),
            "decision": decision,
            "reasonCode": audit.reason_code,
            "deadline": audit.deadline.unix_seconds(),
        });
        let request = CanonicalJsonRequest::new(
            artifact_id.clone(),
            project_id(&self.database, &audit.task_id)?,
            Some(audit.task_id),
            "agent-request-audit",
            format!(
                "agent-request-audits/{}.json",
                stable_digest(artifact_id.as_str())
            ),
            "core",
            "agent-runtime",
            &value,
            format!("agent-request-audit:{}", artifact_id.as_str()),
        )?;
        if !fence.try_begin_commit() {
            return Err(conflict());
        }
        let result = publish_canonical_json(&self.database, self.artifacts.as_ref(), request);
        fence.finish_commit();
        result.map(|_| ())
    }
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

fn core_adapter_descriptor(
    agent_id: &str,
    display_name: &str,
    manifest: &[u8],
    configured_manifest_digest: &Sha256Digest,
    core_release_digest: &Sha256Digest,
) -> Result<AgentDescriptor, PortError> {
    let manifest_digest = digest_bytes(manifest);
    if configured_manifest_digest != &manifest_digest {
        return Err(integrity_failure());
    }
    let descriptor = AgentDescriptor {
        agent_id: agent_id.to_owned(),
        display_name: display_name.to_owned(),
        trust_tier: TrustTier::CoreAdapter,
        manifest_json: manifest.to_vec(),
        manifest_digest,
        executable_digest: Some(core_release_digest.clone()),
        enabled: true,
        containment_verified: true,
    };
    descriptor.validate().map_err(|_| invalid_input())?;
    Ok(descriptor)
}

fn core_adapter_connection(
    connection_id: &str,
    agent_id: &str,
    manifest_digest: &Sha256Digest,
    core_release_digest: &Sha256Digest,
    adapter_version: &str,
) -> Result<BoundAgentConnection, PortError> {
    let mut connection = BoundAgentConnection {
        connection_id: connection_id.to_owned(),
        agent_id: agent_id.to_owned(),
        trust_tier: TrustTier::CoreAdapter,
        manifest_digest: manifest_digest.clone(),
        executable_digest: Some(core_release_digest.clone()),
        contract_version: PROTOCOL_VERSION.to_owned(),
        adapter_version: adapter_version.to_owned(),
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

fn permission_denied() -> PortError {
    PortError::failure(
        SafeErrorClassification::PermissionDenied,
        Retryability::NonRetryable,
    )
}

#[cfg(test)]
pub(crate) fn failing_runtime_for_test(path: &std::path::Path) -> Arc<ComposedAgentRuntime> {
    tests::failing_runtime_for_test(path)
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
    use local_agent_terminal_application::AgentRequestAuditFence;
    use local_agent_terminal_application::StartupStateDto;
    use local_agent_terminal_domain::{RunId, TaskId, Timestamp};
    use rusqlite::params;
    use tempfile::TempDir;

    use crate::{Bootstrap, StartupConfig};

    use super::*;

    #[test]
    fn durable_request_audits_survive_restart_and_separate_rejection_reasons() {
        let temporary = TempDir::new().expect("temporary state directory");
        let database_path = temporary.path().join("state.sqlite3");
        let artifact_path = temporary.path().join("artifacts");
        let artifact_root = artifact_path.to_string_lossy().into_owned();
        let database = SqliteStore::open(&database_path).expect("database");
        let connection = rusqlite::Connection::open(&database_path).expect("sqlite connection");
        connection
            .execute(
                "INSERT INTO projects (
                    id, name, repository_path, repository_identity, created_at, updated_at,
                    policy_profile_id, artifact_root_mode, artifact_root_path
                 ) VALUES (?1, 'Audit project', 'D:/repo', 'repo-1', ?2, ?2,
                    'default', 'application_data', ?3)",
                params!["project-1", "2026-07-23T13:30:00Z", artifact_root,],
            )
            .expect("project row");
        connection
            .execute(
                "INSERT INTO tasks (
                    id, project_id, title, objective, phase, condition, operation_state,
                    risk_level, base_branch, base_commit, created_at, updated_at
                 ) VALUES (?1, 'project-1', 'Audit task', 'Verify durable audits',
                    'ParallelAnalysis', 'Active', 'None', 'high', 'main', ?2, ?3, ?3)",
                params!["task-1", "a".repeat(40), "2026-07-23T13:30:00Z",],
            )
            .expect("task row");
        let handler = DurableAgentRequestHandler {
            database,
            artifacts: Arc::new(
                ContentAddressedArtifactStore::open(&artifact_path).expect("artifact store"),
            ),
        };
        for reason in ["policy_denied", "conflicting_duplicate"] {
            handler
                .persist_audit(AgentRequestAudit {
                    run_id: RunId::new("run-1").expect("run id"),
                    task_id: TaskId::new("task-1").expect("task id"),
                    connection_id: "connection-1".to_owned(),
                    connection_binding_digest: digest_bytes(b"connection"),
                    request_id: "agent:request-1".to_owned(),
                    kind: AgentRequestKind::ContextQuery,
                    request_digest: digest_bytes(b"same request"),
                    decision: AgentRequestAuditDecision::Rejected,
                    reason_code: Some(reason.to_owned()),
                    deadline: Timestamp::from_unix_seconds(1_800_000_300),
                    fence: AgentRequestAuditFence::new(),
                })
                .expect("durable request audit");
        }
        drop(handler);
        drop(connection);

        SqliteStore::open(&database_path).expect("reopened database");
        let connection = rusqlite::Connection::open(database_path).expect("reopened sqlite");
        let count: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM artifacts
                 WHERE artifact_type = 'agent-request-audit' AND availability = 'available'",
                [],
                |row| row.get(0),
            )
            .expect("audit artifact count");
        assert_eq!(count, 2);
    }

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
                anthropic: None,
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

    pub(super) fn failing_runtime_for_test(path: &Path) -> Arc<ComposedAgentRuntime> {
        let clock = Arc::new(FailingShutdownClock::default());
        Arc::new(runtime_with_clock(path, clock))
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
            manifest_digest: digest_bytes(OPENAI_MANIFEST),
            core_release_digest: digest_bytes(b"test-release"),
            adapter_version: "test-adapter-v1".to_owned(),
        };
        let descriptor = core_adapter_descriptor(
            OPENAI_AGENT_ID,
            "OpenAI Responses",
            OPENAI_MANIFEST,
            &config.manifest_digest,
            &config.core_release_digest,
        )
        .expect("descriptor");
        let connection = core_adapter_connection(
            OPENAI_CONNECTION_ID,
            OPENAI_AGENT_ID,
            &config.manifest_digest,
            &config.core_release_digest,
            &config.adapter_version,
        )
        .expect("connection");
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
            descriptors: BTreeMap::from([(OPENAI_AGENT_ID.to_owned(), descriptor)]),
            connections: BTreeMap::from([(OPENAI_AGENT_ID.to_owned(), connection)]),
            provider_ids: BTreeMap::from([(OPENAI_AGENT_ID.to_owned(), "openai".to_owned())]),
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
