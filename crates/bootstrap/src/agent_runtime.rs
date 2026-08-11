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
    parse_policy_timestamp, ActorId, ActorLocality, AgentArtifactStore, AgentCancellationReceipt,
    AgentContextQueryRequest, AgentContextQueryResponse, AgentDescriptor, AgentFamilyKey,
    AgentMessageArtifact, AgentRequestAudit, AgentRequestAuditDecision, AgentRequestHandler,
    AgentRequestKind, AgentRunReceipt, AgentRunStatus, AgentRunStore, AgentRuntime,
    AgentSpecialistCommit, AgentSpecialistDispatchCommand, AgentSpecialistDispatchStore,
    AgentSpecialistRequest, AgentSpecialistResponse, ArtifactId, ArtifactRef, ArtifactStore,
    ArtifactWriteReservation, BoundAgentConnection, BoundAgentRunRequest, BoundEffectiveContext,
    CancelAgentRun, CanonicalJsonRequest, Clock, ContextBudget, ContextBuildPolicy,
    ContextPackageContract, ContextPackageDescriptor, ContextPackageDraft, ContextPackageIdentity,
    ContextQuery, ContextRunReconstructibility, ContextVersionSet, DeliberationArtifactRef,
    DeliberationBudget, DeliberationCommandContext, DeliberationCommands,
    DeliberationRunAssignment, DeliberationStore, EventId, PolicyActor, PortError, ProjectId,
    ReservedArtifact, ResourceClass, Retryability, RiskLevel, RunId, SafeErrorClassification,
    Sha256Digest, SpecialistBudget, SpecialistRequest, TaskId, TaskQuery, TaskRisk, TrustTier,
    WorkspaceEvidenceStore,
};
use local_agent_terminal_orchestration::{
    authorize_specialist, AgentEligibility, SpecialistDenial,
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

use crate::{context_runtime::ContextRuntime, workspace_monitor::publish_canonical_json};

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
    context: Arc<ContextRuntime>,
    openai: Option<&OpenAiBootstrapConfig>,
    anthropic: Option<&AnthropicBootstrapConfig>,
) -> Result<Option<Arc<ComposedAgentRuntime>>, PortError> {
    let peers = openai
        .iter()
        .map(|config| compose_openai_peer(config))
        .chain(
            anthropic
                .iter()
                .map(|config| compose_anthropic_peer(config)),
        )
        .collect::<Result<Vec<_>, _>>()?;
    if peers.is_empty() {
        return Ok(None);
    }
    let recovery_at = database.now_utc()?;
    for peer in &peers {
        database.reconcile_trusted_core_adapter(&peer.descriptor, &recovery_at)?;
    }
    compose_runtime(database, artifacts, context, peers).map(Some)
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
    let provider = select_provider_config(
        endpoint,
        |endpoint| {
            OpenAiProviderConfig::new(
                endpoint,
                config.api_key.clone(),
                CONNECT_TIMEOUT,
                READ_TIMEOUT,
            )
        },
        |endpoint| {
            OpenAiProviderConfig::for_loopback_test(
                endpoint,
                config.api_key.clone(),
                CONNECT_TIMEOUT,
                READ_TIMEOUT,
            )
        },
    )?;
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
    let provider = select_provider_config(
        endpoint,
        |endpoint| {
            AnthropicProviderConfig::new(
                endpoint,
                config.api_key.clone(),
                CONNECT_TIMEOUT,
                READ_TIMEOUT,
            )
        },
        |endpoint| {
            AnthropicProviderConfig::for_loopback_test(
                endpoint,
                config.api_key.clone(),
                CONNECT_TIMEOUT,
                READ_TIMEOUT,
            )
        },
    )?;
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

fn select_provider_config<T, E>(
    endpoint: Url,
    production: impl FnOnce(Url) -> Result<T, E>,
    loopback: impl FnOnce(Url) -> Result<T, E>,
) -> Result<T, PortError> {
    match endpoint.scheme() {
        "https" => production(endpoint),
        "http" => loopback(endpoint),
        _ => return Err(invalid_input()),
    }
    .map_err(|_| invalid_input())
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
                "lead".to_owned(),
                "proposer".to_owned(),
                "critic".to_owned(),
                "reviewer".to_owned(),
                "verifier".to_owned(),
            ]),
            skills: BTreeSet::new(),
            streaming: true,
            context_query: true,
            tool_requests: false,
            specialist_requests: true,
            max_concurrent_runs: 1,
            max_context_tokens: 16_384,
        },
    })
}

fn compose_runtime(
    database: SqliteStore,
    artifacts: Arc<ContentAddressedArtifactStore>,
    context: Arc<ContextRuntime>,
    peers: Vec<ComposedPeer>,
) -> Result<Arc<ComposedAgentRuntime>, PortError> {
    let database = database.with_artifact_reader(Arc::new(ContentAddressedArtifactReader));
    let durable_artifacts = Arc::new(DurableAgentArtifacts {
        database: database.clone(),
        artifacts: Arc::clone(&artifacts),
    });
    let mut descriptors = BTreeMap::new();
    let mut connections = BTreeMap::new();
    let mut provider_ids = BTreeMap::new();
    let mut runtime_peers = Vec::with_capacity(peers.len());
    let mut specialist_candidates = Vec::with_capacity(peers.len());
    for peer in peers {
        let capabilities = peer
            .peer
            .descriptor()
            .capabilities
            .roles
            .iter()
            .chain(peer.peer.descriptor().capabilities.skills.iter())
            .cloned()
            .collect();
        specialist_candidates.push(SpecialistCandidate {
            agent_id: peer.descriptor.agent_id.clone(),
            family: AgentFamilyKey::new(peer.provider_id.clone())
                .map_err(|_| integrity_failure())?,
            capabilities,
            available: peer.descriptor.enabled,
        });
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
    let request_handler = Arc::new(DurableAgentRequestHandler {
        database: database.clone(),
        artifacts: Arc::clone(&artifacts),
        context,
        specialist_candidates,
    });
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

#[derive(Clone)]
struct SpecialistCandidate {
    agent_id: String,
    family: AgentFamilyKey,
    capabilities: BTreeSet<String>,
    available: bool,
}

struct DurableAgentRequestHandler {
    database: SqliteStore,
    artifacts: Arc<ContentAddressedArtifactStore>,
    context: Arc<ContextRuntime>,
    specialist_candidates: Vec<SpecialistCandidate>,
}

impl AgentRequestHandler for DurableAgentRequestHandler {
    fn query_context(
        &self,
        request: AgentContextQueryRequest,
    ) -> Result<AgentContextQueryResponse, PortError> {
        let snapshot = self.bound_run(
            &request.run_id,
            &request.task_id,
            &request.connection_id,
            &request.connection_binding_digest,
            &request.phase,
        )?;
        if request.cancellation.is_cancelled() {
            return Err(conflict());
        }
        let observed_at = parse_policy_timestamp(&self.database.now_utc()?)?;
        if observed_at >= request.deadline {
            return Err(conflict());
        }
        if request
            .scopes
            .iter()
            .any(|scope| !matches!(scope.as_str(), "repository" | "task"))
        {
            return Err(permission_denied());
        }
        let task = self.database.task(&request.task_id)?;
        if task.phase.as_str() != request.phase {
            return Err(conflict());
        }
        let identity = stable_digest(&format!(
            "{}:{}:{}:{}:{}",
            request.run_id.as_str(),
            request.query_id,
            request.query,
            request.max_items,
            request.max_tokens,
        ));
        let package_id = format!("context-supplement-{identity}");
        let artifact_id = ArtifactId::new(format!("context-supplement-artifact-{identity}"))
            .map_err(|_| invalid_input())?;
        let descriptor = ContextPackageDescriptor::new(
            ContextPackageIdentity::new(
                &package_id,
                request.task_id.clone(),
                &snapshot.request.agent_id,
                &snapshot.request.role,
                snapshot.request.context.manifest_artifact_id.clone(),
                artifact_id,
                observed_at,
            )
            .map_err(|_| invalid_input())?,
            &snapshot.request.context.objective,
            ContextVersionSet::new(
                &snapshot.request.context.prompt_template_version,
                &snapshot.request.context.retrieval_pipeline_version,
                "byte-token-v1",
            )
            .map_err(|_| invalid_input())?,
            ContextBudget::new(
                request
                    .max_tokens
                    .checked_add(1)
                    .ok_or_else(invalid_input)?,
                1,
            )
            .map_err(|_| invalid_input())?,
        )
        .map_err(|_| invalid_input())?;
        let terms = request
            .query
            .split_whitespace()
            .map(|term| term.trim_matches(|character: char| !character.is_alphanumeric()))
            .filter(|term| term.len() >= 3)
            .take(4)
            .map(str::to_owned)
            .collect();
        let prepared =
            self.context
                .prepare_query(local_agent_terminal_application::QueryContextRequest {
                    query: ContextQuery {
                        task_id: request.task_id.clone(),
                        query_id: request.query_id.clone(),
                        terms,
                        max_items: request.max_items,
                        max_tokens: request.max_tokens,
                    },
                    policy: ContextBuildPolicy {
                        task_id: request.task_id.clone(),
                        actor: PolicyActor {
                            connection_id: request.connection_id.clone(),
                            agent_id: snapshot.request.agent_id,
                            trust_tier: snapshot.request.connection.trust_tier,
                            locality: ActorLocality::Cloud,
                        },
                        resource_class: ResourceClass::InternalCode,
                        task_risk: task_risk(task.risk_level),
                        workflow_phase: request.phase.clone(),
                        purpose: format!("authorized context query {}", request.query_id),
                        policy_snapshot_digest: snapshot.request.context.policy_snapshot_digest,
                        evaluated_at: observed_at,
                    },
                    package: ContextPackageDraft {
                        descriptor,
                        contract: ContextPackageContract {
                            task_scope: request.scopes.clone(),
                            policy_constraints: vec!["read-only-preapproval".to_owned()],
                            shared_summary: snapshot.request.context.objective.clone(),
                            accepted_decisions: Vec::new(),
                            unresolved_objections: Vec::new(),
                            active_thread_messages: Vec::new(),
                            permissions: vec!["context.query".to_owned()],
                            protocol_capabilities: vec![
                                "context/query".to_owned(),
                                "specialist/request".to_owned(),
                            ],
                            reconstructibility: ContextRunReconstructibility {
                                run_config_artifact_id: snapshot
                                    .request
                                    .run_config
                                    .run_config_artifact_id
                                    .as_str()
                                    .to_owned(),
                                adapter_version: snapshot
                                    .request
                                    .run_config
                                    .adapter_version
                                    .clone(),
                                provider_id: snapshot.request.run_config.provider_id.clone(),
                                model_id: snapshot.request.run_config.model_id.clone(),
                                generation_parameters_digest: snapshot
                                    .request
                                    .run_config
                                    .generation_parameters
                                    .digest
                                    .as_str()
                                    .to_owned(),
                                response_schema_version: snapshot
                                    .request
                                    .run_config
                                    .response_schema_version
                                    .clone(),
                                manifest_digest: snapshot
                                    .request
                                    .run_config
                                    .manifest_digest
                                    .as_str()
                                    .to_owned(),
                                executable_digest: snapshot
                                    .request
                                    .run_config
                                    .executable_digest
                                    .as_ref()
                                    .ok_or_else(integrity_failure)?
                                    .as_str()
                                    .to_owned(),
                                connection_binding_digest: snapshot
                                    .request
                                    .connection
                                    .binding_digest
                                    .as_str()
                                    .to_owned(),
                                authoritative_receipt_unix_seconds: observed_at.unix_seconds(),
                            },
                        },
                    },
                })?;
        if request.cancellation.is_cancelled() {
            return Err(conflict());
        }
        let binding = prepared.package.binding();
        let artifact = prepared.package.artifact();
        let token_count = u64::try_from(artifact.bytes.len()).map_err(|_| integrity_failure())?;
        if artifact.content_digest != *binding.artifact().content_digest()
            || token_count > request.max_tokens
        {
            return Err(integrity_failure());
        }
        let item_ids = binding
            .members()
            .iter()
            .map(|member| member.member_id().to_owned())
            .collect();
        let provenance = prepared
            .package
            .provenance()
            .iter()
            .map(|value| format!("context-provenance-{}", stable_digest(value)))
            .collect();
        Ok(AgentContextQueryResponse {
            run_id: request.run_id,
            task_id: request.task_id,
            query_id: request.query_id,
            supplement_id: package_id,
            content_digest: binding.artifact().content_digest().clone(),
            item_ids,
            token_count,
            provenance,
            redactions: prepared.package.redaction_report_ids().to_vec(),
            policy_decision_ids: binding.policy().decision_ids().to_vec(),
            prepared_commit: Some(prepared),
        })
    }

    fn request_specialist(
        &self,
        request: AgentSpecialistRequest,
    ) -> Result<AgentSpecialistResponse, PortError> {
        let snapshot = self.bound_run(
            &request.run_id,
            &request.task_id,
            &request.connection_id,
            &request.connection_binding_digest,
            &request.phase,
        )?;
        if request.cancellation.is_cancelled() {
            return Ok(specialist_response(
                request,
                false,
                "request_cancelled",
                None,
            ));
        }
        let observed_at = parse_policy_timestamp(&self.database.now_utc()?)?;
        if observed_at >= request.deadline {
            return Ok(specialist_response(
                request,
                false,
                "request_deadline_exceeded",
                None,
            ));
        }
        for context_id in &request.required_context_ids {
            let artifact_id = ArtifactId::new(context_id).map_err(|_| invalid_input())?;
            let reference = self
                .database
                .available_evidence(&artifact_id)?
                .ok_or_else(permission_denied)?;
            if reference.task_id.as_ref() != Some(&request.task_id) {
                return Ok(specialist_response(
                    request,
                    false,
                    "unrequested_context",
                    None,
                ));
            }
        }
        let specialist = SpecialistRequest::new(
            &request.request_id,
            request.task_id.clone(),
            request.run_id.clone(),
            &request.capability,
            &request.reason,
            request
                .required_context_ids
                .iter()
                .map(ArtifactId::new)
                .collect::<Result<Vec<_>, _>>()
                .map_err(|_| invalid_input())?,
            SpecialistBudget::new(request.max_tokens, request.max_tokens, request.deadline)
                .map_err(|_| invalid_input())?,
        )
        .map_err(|_| invalid_input())?;
        let candidates = self
            .specialist_candidates
            .iter()
            .filter(|candidate| candidate.agent_id != snapshot.request.agent_id)
            .map(|candidate| {
                Ok(AgentEligibility {
                    assignment: DeliberationRunAssignment::new(
                        RunId::new(format!(
                            "specialist-{}",
                            stable_digest(&format!(
                                "{}:{}:{}",
                                request.request_id, candidate.agent_id, request.capability
                            ))
                        ))
                        .map_err(|_| invalid_input())?,
                        candidate.agent_id.clone(),
                        candidate.family.clone(),
                        ActorId::new(&candidate.agent_id).map_err(|_| invalid_input())?,
                    )?,
                    capabilities: candidate.capabilities.clone(),
                    available: candidate.available,
                })
            })
            .collect::<Result<Vec<_>, PortError>>()?;
        let mut budget =
            DeliberationBudget::new(request.max_tokens, 1).map_err(|_| invalid_input())?;
        match authorize_specialist(&specialist, &candidates, &mut budget, observed_at) {
            Ok(assignment) => Ok(specialist_response(
                request,
                true,
                "specialist_approved",
                Some(AgentSpecialistCommit {
                    request: specialist,
                    assignment,
                }),
            )),
            Err(denial) => Ok(specialist_response(
                request,
                false,
                specialist_denial_reason(denial),
                None,
            )),
        }
    }

    fn persist_audit(&self, audit: AgentRequestAudit) -> Result<(), PortError> {
        let fence = audit.fence.clone();
        if fence.is_revoked() {
            return Err(conflict());
        }
        let (context_commit, specialist_commit) = match (
            audit.kind,
            audit.decision,
            audit.context_commit,
            audit.specialist_commit,
        ) {
            (
                AgentRequestKind::ContextQuery,
                AgentRequestAuditDecision::Accepted,
                Some(commit),
                None,
            ) => (Some(commit), None),
            (
                AgentRequestKind::SpecialistRequest,
                AgentRequestAuditDecision::Accepted,
                None,
                Some(commit),
            ) => (None, Some(commit)),
            (AgentRequestKind::ContextQuery, AgentRequestAuditDecision::Rejected, None, None)
            | (
                AgentRequestKind::SpecialistRequest,
                AgentRequestAuditDecision::Rejected,
                None,
                None,
            ) => (None, None),
            _ => return Err(integrity_failure()),
        };
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
        let result = (|| {
            if let Some(prepared) = context_commit {
                self.context.commit_query(prepared)?;
            }
            let artifact =
                publish_canonical_json(&self.database, self.artifacts.as_ref(), request)?;
            if let Some(prepared) = specialist_commit {
                self.commit_specialist_request(prepared, artifact)?;
            }
            Ok(())
        })();
        fence.finish_commit();
        result
    }
}

impl DurableAgentRequestHandler {
    fn commit_specialist_request(
        &self,
        prepared: AgentSpecialistCommit,
        artifact: local_agent_terminal_application::CanonicalEvidenceRef,
    ) -> Result<(), PortError> {
        let AgentSpecialistCommit {
            request,
            assignment,
        } = prepared;
        let snapshot = self.database.load(request.task_id())?;
        let artifact = DeliberationArtifactRef::new(
            artifact.artifact_id,
            Sha256Digest::new(artifact.content_hash).map_err(|_| integrity_failure())?,
            artifact.size_bytes,
        )?;
        if snapshot
            .specialist_requests()
            .iter()
            .any(|existing| existing.request() == &request && existing.artifact() == &artifact)
        {
            return if self
                .database
                .specialist_dispatch_exists(request.task_id(), request.request_id())?
            {
                Ok(())
            } else {
                Err(conflict())
            };
        }
        let requesting_assignment = snapshot
            .run_assignments
            .iter()
            .find(|assignment| assignment.run_id() == request.requesting_run())
            .ok_or_else(conflict)?;
        let budget = self
            .database
            .deliberation_task_budget(request.task_id())?
            .ok_or_else(conflict)?;
        let occurred_at = self.database.now_utc()?;
        let event_id = EventId::new(format!(
            "event-specialist-{}",
            stable_digest(&format!(
                "{}:{}:{}",
                request.task_id().as_str(),
                request.requesting_run().as_str(),
                request.request_id(),
            ))
        ))
        .map_err(|_| integrity_failure())?;
        let context = DeliberationCommandContext::new(
            snapshot.task_id.clone(),
            snapshot.task_version,
            snapshot.task_state,
            budget,
            requesting_assignment.actor_id().clone(),
            artifact.clone(),
            event_id,
            format!("{}:specialist", request.task_id().as_str()),
            occurred_at,
        )?;
        let thread_id = format!(
            "thread-specialist-{}",
            stable_digest(&format!(
                "{}:{}:{}",
                request.task_id().as_str(),
                request.request_id(),
                assignment.run_id().as_str(),
            ))
        );
        let context_package = crate::agent_specialist_context::publish_specialist_context_package(
            &self.database,
            self.artifacts.as_ref(),
            &request,
            &assignment,
            &thread_id,
            &artifact,
        )?;
        let persistence = DeliberationCommands::new(&self.database)
            .prepare_specialist_request(context, request)?;
        self.database
            .persist_specialist_dispatch(AgentSpecialistDispatchCommand::new(
                persistence,
                assignment,
                thread_id,
                context_package,
            )?)
    }

    fn bound_run(
        &self,
        run_id: &RunId,
        task_id: &TaskId,
        connection_id: &str,
        binding_digest: &Sha256Digest,
        phase: &str,
    ) -> Result<local_agent_terminal_application::AgentRunSnapshot, PortError> {
        let snapshot = AgentRunStore::load_run(&self.database, run_id)?.ok_or_else(not_found)?;
        if snapshot.status != AgentRunStatus::Running
            || &snapshot.request.task_id != task_id
            || snapshot.request.connection.connection_id != connection_id
            || &snapshot.request.connection.binding_digest != binding_digest
            || snapshot.request.phase != phase
        {
            return Err(conflict());
        }
        Ok(snapshot)
    }
}

fn specialist_response(
    request: AgentSpecialistRequest,
    accepted: bool,
    reason_code: &str,
    prepared_commit: Option<AgentSpecialistCommit>,
) -> AgentSpecialistResponse {
    AgentSpecialistResponse {
        run_id: request.run_id,
        task_id: request.task_id,
        request_id: request.request_id,
        accepted,
        reason_code: reason_code.to_owned(),
        prepared_commit,
    }
}

const fn specialist_denial_reason(denial: SpecialistDenial) -> &'static str {
    match denial {
        SpecialistDenial::RequestExpired => "request_deadline_exceeded",
        SpecialistDenial::CapabilityUnavailable | SpecialistDenial::DependencyUnavailable => {
            "capability_unavailable"
        }
        SpecialistDenial::BudgetExceeded => "budget_exhausted",
    }
}

const fn task_risk(risk: RiskLevel) -> TaskRisk {
    match risk {
        RiskLevel::Low => TaskRisk::Low,
        RiskLevel::Medium => TaskRisk::Medium,
        RiskLevel::High => TaskRisk::High,
        RiskLevel::Critical => TaskRisk::Critical,
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
        let artifacts =
            Arc::new(ContentAddressedArtifactStore::open(&artifact_path).expect("artifact store"));
        let workspace_root = temporary.path().join("workspaces");
        std::fs::create_dir_all(&workspace_root).expect("workspace root");
        let repositories = local_agent_terminal_repository_git::GitRepositoryGateway::open(
            &workspace_root,
            std::slice::from_ref(&artifact_path),
        )
        .expect("repository gateway");
        let context = crate::context_runtime::compose_context_runtime(
            database.clone(),
            Arc::clone(&artifacts),
            repositories,
        )
        .expect("context runtime");
        let handler = DurableAgentRequestHandler {
            database,
            artifacts,
            context,
            specialist_candidates: Vec::new(),
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
                    context_commit: None,
                    specialist_commit: None,
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
    fn accepted_specialist_audit_commits_deliberation_record_and_task_budget() {
        let temporary = TempDir::new().expect("temporary state directory");
        let database_path = temporary.path().join("state.sqlite3");
        let artifact_path = temporary.path().join("artifacts");
        let artifact_root = artifact_path.to_string_lossy().into_owned();
        let database = SqliteStore::open(&database_path)
            .expect("database")
            .with_artifact_reader(Arc::new(ContentAddressedArtifactReader));
        let connection = rusqlite::Connection::open(&database_path).expect("sqlite connection");
        connection
            .execute(
                "INSERT INTO projects (
                    id, name, repository_path, repository_identity, created_at, updated_at,
                    policy_profile_id, artifact_root_mode, artifact_root_path
                 ) VALUES ('project-1', 'Specialist project', 'D:/repo', 'repo-1', ?1, ?1,
                    'default', 'application_data', ?2)",
                params!["2026-08-11T00:00:00Z", artifact_root],
            )
            .expect("project row");
        connection
            .execute(
                "INSERT INTO tasks (
                    id, project_id, title, objective, phase, condition, operation_state,
                    risk_level, base_branch, base_commit, current_sequence, workspace_version,
                    fencing_epoch, created_at, updated_at
                 ) VALUES ('task-1', 'project-1', 'Specialist task', 'Verify specialist commit',
                    'ParallelAnalysis', 'Active', 'None', 'high', 'main', ?1, 0, 1, 1, ?2, ?2)",
                params!["a".repeat(40), "2026-08-11T00:00:00Z"],
            )
            .expect("task row");
        let artifacts =
            Arc::new(ContentAddressedArtifactStore::open(&artifact_path).expect("artifact store"));
        let manifest_digest = digest_bytes(b"{}");
        let context_digest = digest_bytes(b"bound specialist context");
        let release_digest = digest_bytes(b"specialist-test-release");
        publish_runtime_test_artifact(
            &connection,
            artifacts.as_ref(),
            "artifact-manifest",
            "manifest",
            b"{}",
        );
        publish_runtime_test_artifact(
            &connection,
            artifacts.as_ref(),
            "artifact-context",
            "content",
            b"bound specialist context",
        );
        let descriptor = AgentDescriptor {
            agent_id: "agent-parent".to_owned(),
            display_name: "Parent agent".to_owned(),
            trust_tier: TrustTier::CoreAdapter,
            manifest_json: b"{}".to_vec(),
            manifest_digest: manifest_digest.clone(),
            executable_digest: Some(release_digest.clone()),
            enabled: true,
            containment_verified: true,
        };
        database
            .register_descriptor(&descriptor)
            .expect("descriptor");
        let connection_binding = core_adapter_connection(
            "connection-parent",
            "agent-parent",
            &manifest_digest,
            &release_digest,
            "adapter-test-v1",
        )
        .expect("connection binding");
        let run_request = BoundAgentRunRequest {
            run_id: RunId::new("run-parent").expect("run id"),
            task_id: TaskId::new("task-1").expect("task id"),
            agent_id: "agent-parent".to_owned(),
            role: "reviewer".to_owned(),
            phase: "ParallelAnalysis".to_owned(),
            idempotency_key: "task-1:run-parent".to_owned(),
            context: BoundEffectiveContext {
                context_package_id: "context-parent".to_owned(),
                task_id: TaskId::new("task-1").expect("task id"),
                agent_id: "agent-parent".to_owned(),
                role: "reviewer".to_owned(),
                objective: "review".to_owned(),
                manifest_artifact_id: ArtifactId::new("artifact-manifest").expect("artifact id"),
                effective_context_artifact_id: ArtifactId::new("artifact-context")
                    .expect("artifact id"),
                content_digest: context_digest.clone(),
                policy_snapshot_digest: digest_bytes(b"policy"),
                prompt_template_version: "prompt.v1".to_owned(),
                retrieval_pipeline_version: "retrieval.v1".to_owned(),
                created_at: Timestamp::from_unix_seconds(1_786_406_400),
            },
            run_config: local_agent_terminal_application::BoundRunConfig {
                run_config_artifact_id: ArtifactId::new("artifact-run-config")
                    .expect("artifact id"),
                task_id: TaskId::new("task-1").expect("task id"),
                agent_id: "agent-parent".to_owned(),
                role: "reviewer".to_owned(),
                context_package_id: "context-parent".to_owned(),
                effective_context_artifact_id: ArtifactId::new("artifact-context")
                    .expect("artifact id"),
                effective_context_digest: context_digest,
                trust_tier: TrustTier::CoreAdapter,
                manifest_digest: manifest_digest.clone(),
                executable_digest: Some(release_digest.clone()),
                contract_version: PROTOCOL_VERSION.to_owned(),
                adapter_version: "adapter-test-v1".to_owned(),
                provider_id: "provider-parent".to_owned(),
                model_id: "model-parent".to_owned(),
                generation_parameters:
                    local_agent_terminal_application::BoundGenerationParameters {
                        canonical_json: b"{}".to_vec(),
                        digest: manifest_digest.clone(),
                    },
                prompt_template_version: "prompt.v1".to_owned(),
                response_schema_version: "agent-message.v1".to_owned(),
                policy_snapshot_digest: digest_bytes(b"policy"),
                limits: local_agent_terminal_application::AgentRunLimits {
                    deadline: Timestamp::from_unix_seconds(2_000_000_000),
                    max_output_tokens: 1_000,
                    max_tool_requests: 0,
                    max_context_queries: 1,
                    max_specialist_requests: 1,
                },
            },
            connection: connection_binding.clone(),
            supersedes_run_id: None,
        };
        let run_config = canonical_agent_run_config_artifact(&run_request).expect("run config");
        publish_runtime_test_artifact(
            &connection,
            artifacts.as_ref(),
            "artifact-run-config",
            "run-config",
            &run_config,
        );
        database.create_bound_run(&run_request).expect("bound run");
        database
            .accept_run(&run_request.run_id, "2026-08-11T00:00:01Z")
            .expect("accepted run");
        database
            .mark_running(&run_request.run_id, "2026-08-11T00:00:02Z")
            .expect("running run");
        connection
            .execute(
                "INSERT INTO deliberation_task_budgets (
                    task_id, max_threads, max_tokens, max_cost_microunits,
                    deadline_unix_seconds, reserved_threads, reserved_tokens,
                    reserved_cost_microunits
                 ) VALUES ('task-1', 4, 1000, 1000, 2000000000, 0, 0, 0)",
                [],
            )
            .expect("task budget");
        let workspace_root = temporary.path().join("workspaces");
        std::fs::create_dir_all(&workspace_root).expect("workspace root");
        let repositories = local_agent_terminal_repository_git::GitRepositoryGateway::open(
            &workspace_root,
            std::slice::from_ref(&artifact_path),
        )
        .expect("repository gateway");
        let context = crate::context_runtime::compose_context_runtime(
            database.clone(),
            Arc::clone(&artifacts),
            repositories,
        )
        .expect("context runtime");
        let handler = DurableAgentRequestHandler {
            database: database.clone(),
            artifacts,
            context,
            specialist_candidates: vec![SpecialistCandidate {
                agent_id: "agent-specialist".to_owned(),
                family: AgentFamilyKey::from_provider_model(
                    "provider-specialist",
                    "model-specialist",
                )
                .expect("family"),
                capabilities: BTreeSet::from(["review".to_owned()]),
                available: true,
            }],
        };
        let request = AgentSpecialistRequest {
            run_id: run_request.run_id.clone(),
            task_id: run_request.task_id.clone(),
            connection_id: connection_binding.connection_id.clone(),
            connection_binding_digest: connection_binding.binding_digest.clone(),
            phase: run_request.phase.clone(),
            request_id: "specialist-accepted".to_owned(),
            capability: "review".to_owned(),
            reason: "Need independent review".to_owned(),
            required_context_ids: vec!["artifact-context".to_owned()],
            max_tokens: 100,
            deadline: Timestamp::from_unix_seconds(2_000_000_000),
            cancellation: local_agent_terminal_application::AgentRequestCancellation::new(),
        };
        let mut response = handler
            .request_specialist(request)
            .expect("specialist decision");
        assert!(response.accepted);
        let repeated_commit = response.prepared_commit.clone();
        handler
            .persist_audit(AgentRequestAudit {
                run_id: run_request.run_id,
                task_id: run_request.task_id,
                connection_id: connection_binding.connection_id.clone(),
                connection_binding_digest: connection_binding.binding_digest.clone(),
                request_id: "specialist-accepted".to_owned(),
                kind: AgentRequestKind::SpecialistRequest,
                request_digest: digest_bytes(b"specialist request"),
                decision: AgentRequestAuditDecision::Accepted,
                reason_code: None,
                deadline: Timestamp::from_unix_seconds(2_000_000_000),
                fence: AgentRequestAuditFence::new(),
                context_commit: None,
                specialist_commit: response.prepared_commit.take(),
            })
            .expect("specialist audit commit");
        handler
            .persist_audit(AgentRequestAudit {
                run_id: RunId::new("run-parent").expect("run id"),
                task_id: TaskId::new("task-1").expect("task id"),
                connection_id: "connection-parent".to_owned(),
                connection_binding_digest: connection_digest(&connection_binding)
                    .expect("connection digest"),
                request_id: "specialist-accepted".to_owned(),
                kind: AgentRequestKind::SpecialistRequest,
                request_digest: digest_bytes(b"specialist request"),
                decision: AgentRequestAuditDecision::Accepted,
                reason_code: None,
                deadline: Timestamp::from_unix_seconds(2_000_000_000),
                fence: AgentRequestAuditFence::new(),
                context_commit: None,
                specialist_commit: repeated_commit,
            })
            .expect("idempotent specialist audit commit");

        let snapshot = database
            .load(&TaskId::new("task-1").expect("task id"))
            .expect("deliberation snapshot");
        assert_eq!(snapshot.specialist_requests().len(), 1);
        let reserved: (i64, i64, i64) = connection
            .query_row(
                "SELECT reserved_threads, reserved_tokens, reserved_cost_microunits
                 FROM deliberation_task_budgets WHERE task_id = 'task-1'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .expect("budget reservation");
        assert_eq!(reserved, (1, 100, 100));
        let dispatch: (String, String, String, String, String) = connection
            .query_row(
                "SELECT specialist_run_id, specialist_agent_id, family_key, thread_id,
                        context_package_artifact_id
                 FROM deliberation_specialist_dispatches
                 WHERE request_id = 'specialist-accepted'",
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
            .expect("durable specialist dispatch");
        assert!(dispatch.0.starts_with("specialist-"));
        assert_eq!(dispatch.1, "agent-specialist");
        assert_eq!(
            dispatch.2,
            AgentFamilyKey::from_provider_model("provider-specialist", "model-specialist")
                .expect("family")
                .as_str()
        );
        assert!(dispatch.3.starts_with("thread-specialist-"));
        assert!(dispatch.4.starts_with("specialist-context-"));
        let thread_count: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM deliberation_specialist_threads
                 WHERE thread_id = ?1 AND task_id = 'task-1'
                   AND specialist_run_id = ?2 AND context_package_artifact_id = ?3",
                params![dispatch.3, dispatch.0, dispatch.4],
                |row| row.get(0),
            )
            .expect("durable direct thread");
        assert_eq!(thread_count, 1);
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

    fn publish_runtime_test_artifact(
        connection: &rusqlite::Connection,
        artifacts: &ContentAddressedArtifactStore,
        artifact_id: &str,
        artifact_type: &str,
        bytes: &[u8],
    ) {
        let digest = digest_bytes(bytes);
        let physical = artifacts
            .put(local_agent_terminal_application::NewArtifact {
                expected_hash: digest.as_str().to_owned(),
                expected_size: u64::try_from(bytes.len()).expect("artifact size"),
                content: bytes.to_vec(),
            })
            .expect("physical artifact");
        connection
            .execute(
                "INSERT INTO artifacts (
                    id, task_id, project_id, artifact_type, logical_path, content_hash,
                    storage_key, size_bytes, mime_type, availability, created_by_type,
                    created_by_id, created_at, supersedes, verification_state
                 ) VALUES (?1, 'task-1', 'project-1', ?2, ?3, ?4, ?5, ?6,
                    'application/json', 'available', 'core', 'test', ?7, NULL, 'hash_verified')",
                params![
                    artifact_id,
                    artifact_type,
                    format!("agent-runtime/{artifact_id}.json"),
                    digest.as_str(),
                    physical.storage_key,
                    i64::try_from(bytes.len()).expect("artifact size"),
                    "2026-08-11T00:00:00Z",
                ],
            )
            .expect("artifact row");
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
