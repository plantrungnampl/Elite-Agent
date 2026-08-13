use std::sync::Mutex;

use local_agent_terminal_application::{
    AdapterConfiguration, AdapterProtocol, AdapterTransport, AgentProfileConfiguration, AgentRole,
    AllowedDataClass, BindRunConfiguration, CapabilitySnapshot, DataPolicySnapshot, EndpointClass,
    FallbackCandidate, FallbackMode, FallbackPolicy, GenerationParameters,
    IndependenceConfiguration, IndependenceDimensions, ModelEndpointConfiguration, NetworkScope,
    PortError, ProviderTrainingUse, PublishRunConfiguration, PublishedRunConfigurationArtifact,
    RetentionClass, RunBudgetReservation, RunConfiguration, RunConfigurationArtifactPublisher,
    RunConfigurationStore, UnsignedRunConfiguration,
};
use local_agent_terminal_domain::{ArtifactId, RunId, Sha256Digest, TaskId, Timestamp};
use sha2::{Digest, Sha256};

fn digest(byte: char) -> Sha256Digest {
    Sha256Digest::new(format!("sha256:{}", byte.to_string().repeat(64))).unwrap()
}

fn unsigned() -> UnsignedRunConfiguration {
    UnsignedRunConfiguration {
        run_configuration_id: "run-config-1".to_owned(),
        task_id: TaskId::new("task-1").unwrap(),
        provider_connection_ref: "connection-1".to_owned(),
        adapter: AdapterConfiguration {
            adapter_id: "openai".to_owned(),
            adapter_version: "2.0".to_owned(),
            transport: AdapterTransport::Http,
            protocol: AdapterProtocol::MatAgentControlV2,
            implementation_digest: Some(digest('a')),
        },
        model_endpoint: ModelEndpointConfiguration {
            provider_id: "openai".to_owned(),
            resolved_model_id: "gpt-5".to_owned(),
            model_family: "gpt".to_owned(),
            endpoint_class: EndpointClass::HostedApi,
            endpoint_ref: Some("endpoint-1".to_owned()),
            region: Some("us-east".to_owned()),
            context_window_tokens: 128_000,
            max_output_tokens: 8_000,
        },
        agent_profile: AgentProfileConfiguration {
            profile_id: "reviewer-v1".to_owned(),
            role: AgentRole::Reviewer,
            prompt_template_version: "prompt-1".to_owned(),
            tool_policy_ref: "policy/tool-1".to_owned(),
            response_schema_ref: "schema/response-1".to_owned(),
        },
        generation_parameters: GenerationParameters {
            temperature: 0.2,
            top_p: 0.9,
            max_output_tokens: 4_000,
            seed: Some(7),
            stop_sequences: vec!["STOP".to_owned()],
        },
        capability_snapshot: CapabilitySnapshot {
            tool_calling: true,
            structured_output: true,
            streaming: true,
            cancellation: true,
            context_query: true,
            vision: false,
            max_parallel_tool_calls: 4,
            capability_digest: digest('b'),
        },
        data_policy_snapshot: DataPolicySnapshot {
            policy_digest: digest('c'),
            retention_class: RetentionClass::EnterpriseControlled,
            provider_training_use: ProviderTrainingUse::ContractuallyDisabled,
            allowed_data_classes: vec![AllowedDataClass::Internal, AllowedDataClass::SourceCode],
            network_scope: NetworkScope::ProviderOnly,
            region_constraint: Some("us".to_owned()),
        },
        budget_reservation: RunBudgetReservation {
            input_tokens: 10_000,
            output_tokens: 4_000,
            tool_calls: 8,
            wall_time_ms: 60_000,
            cost_microunits: 2_000_000,
            currency: "USD".to_owned(),
        },
        fallback_policy: FallbackPolicy {
            mode: FallbackMode::ExplicitOnly,
            user_approval_required: true,
            candidates: vec![FallbackCandidate {
                provider_connection_ref: "connection-2".to_owned(),
                resolved_model_id: "gpt-5-mini".to_owned(),
                independence_group: "group-2".to_owned(),
            }],
        },
        independence: IndependenceConfiguration {
            group_id: "group-1".to_owned(),
            fingerprint: digest('d'),
            dimensions: IndependenceDimensions {
                provider: "openai".to_owned(),
                model_family: "gpt".to_owned(),
                prompt_family: "review".to_owned(),
                context_corpus: "context-package-1".to_owned(),
                retrieval_pipeline: "retrieval-1".to_owned(),
                tool_policy: "policy/tool-1".to_owned(),
                adapter_implementation: "openai-adapter-2".to_owned(),
            },
        },
        created_at: Timestamp::from_unix_seconds(1),
    }
}

#[test]
fn issue_produces_closed_canonical_v1_without_credentials() {
    let source = unsigned();
    let configuration = RunConfiguration::issue(source.clone()).unwrap();
    let value: serde_json::Value = serde_json::from_slice(configuration.canonical_bytes()).unwrap();

    assert_eq!(value["schemaVersion"], "1.0");
    assert_eq!(value["credentialsExcluded"], true);
    assert_eq!(value["createdAt"], "1970-01-01T00:00:01Z");
    assert_eq!(
        value["configDigest"],
        configuration.config_digest().as_str()
    );
    assert_eq!(
        serde_json_canonicalizer::to_vec(&value).unwrap(),
        configuration.canonical_bytes()
    );
    let fields: Vec<_> = value
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    assert_eq!(
        fields,
        [
            "adapter",
            "agentProfile",
            "budgetReservation",
            "capabilitySnapshot",
            "configDigest",
            "createdAt",
            "credentialsExcluded",
            "dataPolicySnapshot",
            "fallbackPolicy",
            "generationParameters",
            "independence",
            "modelEndpoint",
            "providerConnectionRef",
            "runConfigurationId",
            "schemaVersion",
            "taskId",
        ]
    );
    assert!(String::from_utf8_lossy(configuration.canonical_bytes())
        .find("apiKey")
        .is_none());

    let parsed = RunConfiguration::from_canonical_bytes(configuration.canonical_bytes()).unwrap();
    assert_eq!(parsed.unsigned(), &source);
}

#[test]
fn validation_enforces_bounds_fallback_and_independence_dimensions() {
    let mut invalid = unsigned();
    invalid.provider_connection_ref = "x".repeat(513);
    assert!(RunConfiguration::issue(invalid).is_err());

    let mut invalid = unsigned();
    invalid.fallback_policy.mode = FallbackMode::None;
    assert!(RunConfiguration::issue(invalid).is_err());

    let mut invalid = unsigned();
    invalid.independence.dimensions.context_corpus.clear();
    assert!(RunConfiguration::issue(invalid).is_err());

    let mut invalid = unsigned();
    invalid.generation_parameters.stop_sequences = vec!["x".to_owned(); 33];
    assert!(RunConfiguration::issue(invalid).is_err());

    let mut invalid = unsigned();
    invalid.model_endpoint.endpoint_ref = Some("x".repeat(513));
    assert!(RunConfiguration::issue(invalid).is_err());

    let mut invalid = unsigned();
    invalid.model_endpoint.region = Some("x".repeat(129));
    assert!(RunConfiguration::issue(invalid).is_err());

    let mut invalid = unsigned();
    invalid.data_policy_snapshot.region_constraint = Some("x".repeat(129));
    assert!(RunConfiguration::issue(invalid).is_err());

    let mut invalid = unsigned();
    invalid.data_policy_snapshot.allowed_data_classes =
        vec![AllowedDataClass::Internal, AllowedDataClass::Internal];
    assert!(RunConfiguration::issue(invalid).is_err());
}

#[test]
fn parser_rejects_unknown_enums_fields_and_hostile_credential_keys() {
    let configuration = RunConfiguration::issue(unsigned()).unwrap();
    let mut value: serde_json::Value =
        serde_json::from_slice(configuration.canonical_bytes()).unwrap();
    value["adapter"]["transport"] = serde_json::json!("carrier_pigeon");
    assert!(RunConfiguration::from_canonical_bytes(
        &serde_json_canonicalizer::to_vec(&value).unwrap()
    )
    .is_err());

    for key in [
        "apiKey",
        "accessToken",
        "refreshToken",
        "password",
        "token",
        "credential",
        "secret",
    ] {
        let mut value: serde_json::Value =
            serde_json::from_slice(configuration.canonical_bytes()).unwrap();
        value[key] = serde_json::json!("hostile");
        assert!(
            RunConfiguration::from_canonical_bytes(
                &serde_json_canonicalizer::to_vec(&value).unwrap()
            )
            .is_err(),
            "accepted forbidden {key}"
        );
        let mut nested: serde_json::Value =
            serde_json::from_slice(configuration.canonical_bytes()).unwrap();
        nested["adapter"][key] = serde_json::json!("hostile");
        assert!(
            RunConfiguration::from_canonical_bytes(
                &serde_json_canonicalizer::to_vec(&nested).unwrap()
            )
            .is_err(),
            "accepted nested forbidden {key}"
        );
    }

    let mut value: serde_json::Value =
        serde_json::from_slice(configuration.canonical_bytes()).unwrap();
    value["credentialsExcluded"] = serde_json::json!(false);
    assert!(RunConfiguration::from_canonical_bytes(
        &serde_json_canonicalizer::to_vec(&value).unwrap()
    )
    .is_err());

    let mut value: serde_json::Value =
        serde_json::from_slice(configuration.canonical_bytes()).unwrap();
    value["configDigest"] = serde_json::json!(digest('f').as_str());
    assert!(RunConfiguration::from_canonical_bytes(
        &serde_json_canonicalizer::to_vec(&value).unwrap()
    )
    .is_err());
}

#[test]
fn changing_each_required_section_changes_the_digest() {
    let baseline = RunConfiguration::issue(unsigned())
        .unwrap()
        .config_digest()
        .clone();
    type Mutation = Box<dyn Fn(&mut UnsignedRunConfiguration)>;
    let mutations: Vec<Mutation> = vec![
        Box::new(|v| v.run_configuration_id.push('x')),
        Box::new(|v| v.task_id = TaskId::new("task-2").unwrap()),
        Box::new(|v| v.provider_connection_ref.push('x')),
        Box::new(|v| v.adapter.adapter_version.push('x')),
        Box::new(|v| v.model_endpoint.resolved_model_id.push('x')),
        Box::new(|v| v.agent_profile.profile_id.push('x')),
        Box::new(|v| v.generation_parameters.seed = Some(8)),
        Box::new(|v| v.capability_snapshot.vision = true),
        Box::new(|v| v.data_policy_snapshot.network_scope = NetworkScope::Allowlisted),
        Box::new(|v| v.budget_reservation.tool_calls += 1),
        Box::new(|v| v.fallback_policy.candidates[0].resolved_model_id.push('x')),
        Box::new(|v| v.independence.group_id.push('x')),
        Box::new(|v| v.created_at = Timestamp::from_unix_seconds(2)),
    ];
    for mutate in mutations {
        let mut value = unsigned();
        mutate(&mut value);
        assert_ne!(
            RunConfiguration::issue(value).unwrap().config_digest(),
            &baseline
        );
    }
}

#[derive(Default)]
struct RecordingBoundary {
    calls: Mutex<Vec<&'static str>>,
}

impl RunConfigurationArtifactPublisher for RecordingBoundary {
    fn publish(
        &self,
        artifact_id: &ArtifactId,
        configuration: &RunConfiguration,
    ) -> Result<local_agent_terminal_application::ArtifactRef, PortError> {
        assert_eq!(artifact_id.as_str(), "artifact-config-1");
        self.calls.lock().unwrap().push("publish");
        Ok(local_agent_terminal_application::ArtifactRef {
            content_hash: format!(
                "sha256:{:x}",
                Sha256::digest(configuration.canonical_bytes())
            ),
            storage_key: "sha256/config".to_owned(),
            size_bytes: configuration.canonical_bytes().len() as u64,
        })
    }
}

impl RunConfigurationStore for RecordingBoundary {
    fn bind_run_configuration(
        &self,
        run_id: &RunId,
        artifact: &PublishedRunConfigurationArtifact,
        configuration: &RunConfiguration,
    ) -> Result<(), PortError> {
        assert_eq!(run_id.as_str(), "run-1");
        assert_eq!(artifact.artifact_id.as_str(), "artifact-config-1");
        assert_eq!(
            artifact.reference.size_bytes,
            configuration.canonical_bytes().len() as u64
        );
        self.calls.lock().unwrap().push("bind");
        Ok(())
    }
}

#[test]
fn application_exposes_run_creation_boundary_between_publish_and_bind() {
    let boundary = RecordingBoundary::default();
    let publisher = PublishRunConfiguration::new(&boundary);
    let (artifact, configuration) = publisher
        .execute(ArtifactId::new("artifact-config-1").unwrap(), unsigned())
        .unwrap();
    assert_eq!(*boundary.calls.lock().unwrap(), ["publish"]);

    boundary.calls.lock().unwrap().push("create_run");
    BindRunConfiguration::new(&boundary)
        .execute(&RunId::new("run-1").unwrap(), &artifact, &configuration)
        .unwrap();
    assert_eq!(configuration.task_id().as_str(), "task-1");
    assert_eq!(
        *boundary.calls.lock().unwrap(),
        ["publish", "create_run", "bind"]
    );
}

struct WrongPhysicalDigestPublisher;

impl RunConfigurationArtifactPublisher for WrongPhysicalDigestPublisher {
    fn publish(
        &self,
        _artifact_id: &ArtifactId,
        configuration: &RunConfiguration,
    ) -> Result<local_agent_terminal_application::ArtifactRef, PortError> {
        Ok(local_agent_terminal_application::ArtifactRef {
            content_hash: digest('e').as_str().to_owned(),
            storage_key: "sha256/wrong".to_owned(),
            size_bytes: configuration.canonical_bytes().len() as u64,
        })
    }
}

#[test]
fn publication_with_wrong_physical_digest_is_rejected_independently() {
    let use_case = PublishRunConfiguration::new(&WrongPhysicalDigestPublisher);

    let error = use_case
        .execute(ArtifactId::new("artifact-config-1").unwrap(), unsigned())
        .unwrap_err();

    assert_eq!(
        error.safe_classification(),
        local_agent_terminal_application::SafeErrorClassification::IntegrityFailure
    );
}

struct WrongPhysicalSizePublisher;

impl RunConfigurationArtifactPublisher for WrongPhysicalSizePublisher {
    fn publish(
        &self,
        _artifact_id: &ArtifactId,
        configuration: &RunConfiguration,
    ) -> Result<local_agent_terminal_application::ArtifactRef, PortError> {
        Ok(local_agent_terminal_application::ArtifactRef {
            content_hash: format!(
                "sha256:{:x}",
                Sha256::digest(configuration.canonical_bytes())
            ),
            storage_key: "sha256/wrong-size".to_owned(),
            size_bytes: configuration.canonical_bytes().len() as u64 + 1,
        })
    }
}

#[test]
fn publication_with_wrong_physical_size_is_rejected_independently() {
    let error = PublishRunConfiguration::new(&WrongPhysicalSizePublisher)
        .execute(ArtifactId::new("artifact-config-1").unwrap(), unsigned())
        .unwrap_err();

    assert_eq!(
        error.safe_classification(),
        local_agent_terminal_application::SafeErrorClassification::IntegrityFailure
    );
}

struct FailingPublisher;

impl RunConfigurationArtifactPublisher for FailingPublisher {
    fn publish(
        &self,
        _artifact_id: &ArtifactId,
        _configuration: &RunConfiguration,
    ) -> Result<local_agent_terminal_application::ArtifactRef, PortError> {
        Err(PortError::failure(
            local_agent_terminal_application::SafeErrorClassification::Unavailable,
            local_agent_terminal_application::Retryability::Retryable,
        ))
    }
}

#[test]
fn publication_failure_never_creates_a_run_binding() {
    let use_case = PublishRunConfiguration::new(&FailingPublisher);
    assert!(use_case
        .execute(ArtifactId::new("artifact-config-1").unwrap(), unsigned(),)
        .is_err());
}
