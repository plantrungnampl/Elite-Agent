use std::sync::Arc;

use local_agent_terminal_application::{
    AdapterConfiguration, AdapterProtocol, AdapterTransport, AgentProfileConfiguration, AgentRole,
    AllowedDataClass, ArtifactId, ArtifactRef, BoundAgentRunRequest, CanonicalJsonRequest,
    CapabilitySnapshot, DataPolicySnapshot, EndpointClass, FallbackMode, FallbackPolicy,
    GenerationParameters, IndependenceConfiguration, IndependenceDimensions,
    ModelEndpointConfiguration, NetworkScope, PortError, ProviderTrainingUse,
    PublishRunConfiguration, PublishedRunConfigurationArtifact, RetentionClass, Retryability,
    RunBudgetReservation, RunConfiguration, RunConfigurationArtifactPublisher,
    SafeErrorClassification, Sha256Digest, TaskId, Timestamp, UnsignedRunConfiguration,
};
use local_agent_terminal_storage_files::ContentAddressedArtifactStore;
use local_agent_terminal_storage_sqlite::SqliteStore;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::{
    agent_runtime_support::{project_id, stable_digest},
    workspace_monitor::publish_canonical_json,
};

pub(crate) fn publish_for_run(
    database: &SqliteStore,
    artifacts: &Arc<ContentAddressedArtifactStore>,
    request: &BoundAgentRunRequest,
    created_at: Timestamp,
) -> Result<(PublishedRunConfigurationArtifact, RunConfiguration), PortError> {
    let unsigned = build_unsigned(request, created_at)?;
    PublishRunConfiguration::new(&ProductionRunConfigurationPublisher {
        database,
        artifacts: artifacts.as_ref(),
        task_id: &request.task_id,
        run_id: request.run_id.as_str(),
    })
    .execute(request.run_config.run_config_artifact_id.clone(), unsigned)
}

struct ProductionRunConfigurationPublisher<'a> {
    database: &'a SqliteStore,
    artifacts: &'a ContentAddressedArtifactStore,
    task_id: &'a TaskId,
    run_id: &'a str,
}

impl RunConfigurationArtifactPublisher for ProductionRunConfigurationPublisher<'_> {
    fn publish(
        &self,
        artifact_id: &ArtifactId,
        configuration: &RunConfiguration,
    ) -> Result<ArtifactRef, PortError> {
        let value: Value = serde_json::from_slice(configuration.canonical_bytes())
            .map_err(|_| integrity_failure())?;
        let published = publish_canonical_json(
            self.database,
            self.artifacts,
            CanonicalJsonRequest::new(
                artifact_id.clone(),
                project_id(self.database, self.task_id)?,
                Some(self.task_id.clone()),
                "run-config",
                format!("agent-runs/{}.json", stable_digest(artifact_id.as_str())),
                "core",
                "bootstrap",
                &value,
                format!("run-configuration-{}", self.run_id),
            )?,
        )?;
        Ok(ArtifactRef {
            content_hash: published.content_hash,
            storage_key: published.storage_key,
            size_bytes: published.size_bytes,
        })
    }
}

fn build_unsigned(
    request: &BoundAgentRunRequest,
    created_at: Timestamp,
) -> Result<UnsignedRunConfiguration, PortError> {
    request.validate().map_err(|_| invalid_input())?;
    let generation = generation_parameters(request)?;
    let model_family = request
        .run_config
        .model_id
        .split(['-', ':'])
        .next()
        .filter(|value| !value.is_empty())
        .ok_or_else(invalid_input)?
        .to_owned();
    let tool_policy_ref = format!(
        "policy-{}",
        &request.context.policy_snapshot_digest.as_str()[7..23]
    );
    let dimensions = IndependenceDimensions {
        provider: request.run_config.provider_id.clone(),
        model_family: model_family.clone(),
        prompt_family: request.run_config.prompt_template_version.clone(),
        context_corpus: request.context.context_package_id.clone(),
        retrieval_pipeline: request.context.retrieval_pipeline_version.clone(),
        tool_policy: tool_policy_ref.clone(),
        adapter_implementation: request.run_config.adapter_version.clone(),
    };
    let independence_fingerprint = digest_canonical(&json!({
        "provider": dimensions.provider,
        "modelFamily": dimensions.model_family,
        "promptFamily": dimensions.prompt_family,
        "contextCorpus": dimensions.context_corpus,
        "retrievalPipeline": dimensions.retrieval_pipeline,
        "toolPolicy": dimensions.tool_policy,
        "adapterImplementation": dimensions.adapter_implementation,
    }))?;
    let capability_digest = digest_canonical(&json!({
        "toolCalling": request.run_config.limits.max_tool_requests > 0,
        "structuredOutput": true,
        "streaming": true,
        "cancellation": true,
        "contextQuery": request.run_config.limits.max_context_queries > 0,
        "vision": false,
        "maxParallelToolCalls": request.run_config.limits.max_tool_requests,
    }))?;
    let wall_seconds = request
        .run_config
        .limits
        .deadline
        .unix_seconds()
        .checked_sub(created_at.unix_seconds())
        .filter(|seconds| *seconds > 0)
        .ok_or_else(invalid_input)?;
    let wall_time_ms = u64::try_from(wall_seconds)
        .ok()
        .and_then(|seconds| seconds.checked_mul(1_000))
        .ok_or_else(invalid_input)?;
    let tool_calls = request
        .run_config
        .limits
        .max_tool_requests
        .checked_add(request.run_config.limits.max_context_queries)
        .and_then(|value| value.checked_add(request.run_config.limits.max_specialist_requests))
        .ok_or_else(invalid_input)?;

    Ok(UnsignedRunConfiguration {
        run_configuration_id: request
            .run_config
            .run_config_artifact_id
            .as_str()
            .to_owned(),
        task_id: request.task_id.clone(),
        provider_connection_ref: request.connection.connection_id.clone(),
        adapter: AdapterConfiguration {
            adapter_id: request.run_config.provider_id.clone(),
            adapter_version: request.run_config.adapter_version.clone(),
            transport: AdapterTransport::Http,
            protocol: AdapterProtocol::MatAgentControlV2,
            implementation_digest: request.run_config.executable_digest.clone(),
        },
        model_endpoint: ModelEndpointConfiguration {
            provider_id: request.run_config.provider_id.clone(),
            resolved_model_id: request.run_config.model_id.clone(),
            model_family,
            endpoint_class: EndpointClass::HostedApi,
            endpoint_ref: None,
            region: None,
            context_window_tokens: 16_384,
            max_output_tokens: request.run_config.limits.max_output_tokens,
        },
        agent_profile: AgentProfileConfiguration {
            profile_id: request.agent_id.clone(),
            role: agent_role(&request.role)?,
            prompt_template_version: request.run_config.prompt_template_version.clone(),
            tool_policy_ref,
            response_schema_ref: request.run_config.response_schema_version.clone(),
        },
        generation_parameters: generation,
        capability_snapshot: CapabilitySnapshot {
            tool_calling: request.run_config.limits.max_tool_requests > 0,
            structured_output: true,
            streaming: true,
            cancellation: true,
            context_query: request.run_config.limits.max_context_queries > 0,
            vision: false,
            max_parallel_tool_calls: request.run_config.limits.max_tool_requests,
            capability_digest,
        },
        data_policy_snapshot: DataPolicySnapshot {
            policy_digest: request.context.policy_snapshot_digest.clone(),
            retention_class: RetentionClass::Ephemeral,
            provider_training_use: ProviderTrainingUse::Unknown,
            allowed_data_classes: vec![AllowedDataClass::Internal, AllowedDataClass::SourceCode],
            network_scope: NetworkScope::ProviderOnly,
            region_constraint: None,
        },
        budget_reservation: RunBudgetReservation {
            input_tokens: 16_384,
            output_tokens: request.run_config.limits.max_output_tokens,
            tool_calls,
            wall_time_ms,
            cost_microunits: 0,
            currency: "USD".to_owned(),
        },
        fallback_policy: FallbackPolicy {
            mode: FallbackMode::None,
            user_approval_required: false,
            candidates: Vec::new(),
        },
        independence: IndependenceConfiguration {
            group_id: format!(
                "{}-{}",
                request.run_config.provider_id, request.run_config.model_id
            ),
            fingerprint: independence_fingerprint,
            dimensions,
        },
        created_at,
    })
}

fn generation_parameters(
    request: &BoundAgentRunRequest,
) -> Result<GenerationParameters, PortError> {
    let value: Value =
        serde_json::from_slice(&request.run_config.generation_parameters.canonical_json)
            .map_err(|_| invalid_input())?;
    let object = value.as_object().ok_or_else(invalid_input)?;
    let temperature = object
        .get("temperature")
        .and_then(Value::as_f64)
        .unwrap_or(0.0);
    let top_p = object
        .get("topP")
        .or_else(|| object.get("top_p"))
        .and_then(Value::as_f64)
        .unwrap_or(1.0);
    let seed = match object.get("seed") {
        Some(value) => Some(value.as_i64().ok_or_else(invalid_input)?),
        None => None,
    };
    let stop_sequences = object
        .get("stopSequences")
        .or_else(|| object.get("stop_sequences"))
        .map(|value| {
            value
                .as_array()
                .ok_or_else(invalid_input)?
                .iter()
                .map(|item| item.as_str().map(str::to_owned).ok_or_else(invalid_input))
                .collect()
        })
        .transpose()?
        .unwrap_or_default();
    Ok(GenerationParameters {
        temperature,
        top_p,
        max_output_tokens: request.run_config.limits.max_output_tokens,
        seed,
        stop_sequences,
    })
}

fn agent_role(role: &str) -> Result<AgentRole, PortError> {
    match role {
        "lead" => Ok(AgentRole::Lead),
        "analyst" | "proposer" => Ok(AgentRole::Analyst),
        "reviewer" | "critic" => Ok(AgentRole::Reviewer),
        "implementer" => Ok(AgentRole::Implementer),
        "verifier" => Ok(AgentRole::Verifier),
        "specialist" => Ok(AgentRole::Specialist),
        "researcher" => Ok(AgentRole::Researcher),
        _ => Err(invalid_input()),
    }
}

fn digest_canonical(value: &Value) -> Result<Sha256Digest, PortError> {
    let bytes = serde_json_canonicalizer::to_vec(value).map_err(|_| integrity_failure())?;
    Sha256Digest::new(format!("sha256:{:x}", Sha256::digest(bytes)))
        .map_err(|_| integrity_failure())
}

fn invalid_input() -> PortError {
    PortError::failure(
        SafeErrorClassification::InvalidInput,
        Retryability::NonRetryable,
    )
}

fn integrity_failure() -> PortError {
    PortError::failure(
        SafeErrorClassification::IntegrityFailure,
        Retryability::NonRetryable,
    )
}
