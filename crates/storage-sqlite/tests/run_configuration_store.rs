use std::fs;
use std::path::Path;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use local_agent_terminal_application::{
    AdapterConfiguration, AdapterProtocol, AdapterTransport, AgentProfileConfiguration, AgentRole,
    AllowedDataClass, ArtifactContent, ArtifactRef, ArtifactRootReader, ArtifactStore,
    CapabilitySnapshot, DataPolicySnapshot, EndpointClass, FallbackCandidate, FallbackMode,
    FallbackPolicy, GenerationParameters, IndependenceConfiguration, IndependenceDimensions,
    ModelEndpointConfiguration, NetworkScope, NewArtifact, PortError, ProviderTrainingUse,
    PublishedRunConfigurationArtifact, RetentionClass, RunBudgetReservation, RunConfiguration,
    RunConfigurationStore, SafeErrorClassification, UnsignedRunConfiguration,
};
use local_agent_terminal_domain::{ArtifactId, RunId, Sha256Digest, TaskId, Timestamp};
use local_agent_terminal_storage_files::{
    ContentAddressedArtifactReader, ContentAddressedArtifactStore,
};
use local_agent_terminal_storage_sqlite::SqliteStore;
use rusqlite::{params, Connection};

static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

struct UnverifiedArtifactReader {
    bytes: Vec<u8>,
}

impl ArtifactRootReader for UnverifiedArtifactReader {
    fn read_from_root(
        &self,
        _root: &Path,
        _reference: &ArtifactRef,
    ) -> Result<ArtifactContent, PortError> {
        Ok(ArtifactContent {
            bytes: self.bytes.clone(),
        })
    }
}

struct Fixture {
    directory: PathBuf,
    path: PathBuf,
    artifact_root: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let directory = std::env::temp_dir().join(format!(
            "run-configuration-store-{}-{}",
            std::process::id(),
            NEXT_TEMP.fetch_add(1, Ordering::Relaxed)
        ));
        let artifact_root = directory.join("artifacts");
        fs::create_dir_all(&artifact_root).unwrap();
        let path = directory.join("state.sqlite3");
        SqliteStore::open(&path).unwrap();
        let fixture = Self {
            directory,
            path,
            artifact_root,
        };
        fixture.seed_authority();
        fixture
    }

    fn store(&self) -> SqliteStore {
        SqliteStore::open(&self.path)
            .unwrap()
            .with_artifact_reader(Arc::new(ContentAddressedArtifactReader))
    }

    fn connection(&self) -> Connection {
        let connection = Connection::open(&self.path).unwrap();
        connection.execute_batch("PRAGMA foreign_keys=ON;").unwrap();
        connection
    }

    fn seed_authority(&self) {
        let connection = self.connection();
        connection.execute("INSERT INTO projects (id,name,repository_path,repository_identity,created_at,updated_at,policy_profile_id,artifact_root_mode,artifact_root_path) VALUES ('project-1','P','C:/repo',?1,'1970-01-01T00:00:00Z','1970-01-01T00:00:00Z','default','application_data',?2)", params![digest('9').as_str(), self.artifact_root.to_string_lossy()]).unwrap();
        for task in ["task-1", "task-2"] {
            connection.execute("INSERT INTO tasks (id,project_id,title,objective,phase,condition,operation_state,risk_level,base_branch,base_commit,current_sequence,workspace_version,fencing_epoch,created_at,updated_at) VALUES (?1,'project-1','T','O','Implementation','Active','None','low','main','0123456789abcdef0123456789abcdef01234567',0,0,1,'1970-01-01T00:00:00Z','1970-01-01T00:00:00Z')", [task]).unwrap();
        }
        connection.execute("INSERT INTO agent_descriptors (id,display_name,transport_type,trust_tier,manifest_json,manifest_digest,executable_digest,enabled,last_health_status,updated_at) VALUES ('agent-1','Agent','in_process','core_adapter','{}',?1,?2,1,NULL,'1970-01-01T00:00:00Z')", params![digest_bytes(b"{}").as_str(), digest('8').as_str()]).unwrap();
        self.insert_metadata("manifest-1", "task-1", "manifest", b"{}", "manifest.json");
        self.insert_metadata("context-1", "task-1", "content", b"{}", "context.json");
        connection.execute("INSERT INTO context_packages (id,task_id,agent_id,role,objective,manifest_artifact_id,effective_content_artifact_id,content_hash,policy_snapshot_digest,prompt_template_version,retrieval_pipeline_version,created_at) VALUES ('context-package-1','task-1','agent-1','reviewer','Review','manifest-1','context-1',?1,?2,'prompt-1','retrieval-1','1970-01-01T00:00:01Z')", params![digest_bytes(b"{}").as_str(), digest('7').as_str()]).unwrap();
    }

    fn insert_metadata(
        &self,
        id: &str,
        task: &str,
        kind: &str,
        bytes: &[u8],
        logical: &str,
    ) -> ArtifactRef {
        let digest = digest_bytes(bytes);
        let reference = ContentAddressedArtifactStore::open(&self.artifact_root)
            .unwrap()
            .put(NewArtifact {
                expected_hash: digest.as_str().to_owned(),
                expected_size: bytes.len() as u64,
                content: bytes.to_vec(),
            })
            .unwrap();
        self.connection().execute("INSERT INTO artifacts (id,task_id,project_id,artifact_type,logical_path,content_hash,storage_key,size_bytes,mime_type,availability,created_by_type,created_by_id,created_at,supersedes,verification_state) VALUES (?1,?2,'project-1',?3,?4,?5,?6,?7,'application/json','available','core','core','1970-01-01T00:00:01Z',NULL,'hash_verified')", params![id, task, kind, logical, digest.as_str(), reference.storage_key, bytes.len() as i64]).unwrap();
        reference
    }

    fn seed_run(
        &self,
        artifact_id: &str,
        configuration: &RunConfiguration,
    ) -> PublishedRunConfigurationArtifact {
        let reference = self.insert_metadata(
            artifact_id,
            "task-1",
            "run-config",
            configuration.canonical_bytes(),
            &format!("run/{artifact_id}.json"),
        );
        self.connection().execute("INSERT INTO agent_runs (id,task_id,agent_id,role,phase,status,context_package_id,idempotency_key,connection_binding_digest,run_config_artifact_id,supersedes_run_id,started_at,completed_at,provider_usage_json,core_usage_json,estimated_cost_microunits,error_json) VALUES ('run-1','task-1','agent-1','reviewer','analysis','created','context-package-1','run-key',?1,?2,NULL,NULL,NULL,NULL,NULL,NULL,NULL)", params![digest('6').as_str(), artifact_id]).unwrap();
        PublishedRunConfigurationArtifact {
            artifact_id: ArtifactId::new(artifact_id).unwrap(),
            reference,
        }
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.directory);
    }
}

#[test]
fn binding_round_trips_exact_provider_model_and_independence() {
    let fixture = Fixture::new();
    let configuration = RunConfiguration::issue(unsigned()).unwrap();
    let artifact = fixture.seed_run("config-1", &configuration);
    assert_ne!(
        artifact.reference.content_hash,
        configuration.config_digest().as_str()
    );
    fixture
        .store()
        .bind_run_configuration(&run_id(), &artifact, &configuration)
        .unwrap();
    fixture
        .store()
        .bind_run_configuration(&run_id(), &artifact, &configuration)
        .unwrap();
    let stored = fixture
        .store()
        .run_configuration_binding(&run_id())
        .unwrap()
        .unwrap();
    assert_eq!(stored.config_artifact_id, "config-1");
    assert_eq!(stored.config_digest, *configuration.config_digest());
    assert_eq!(stored.provider_connection_ref, "connection-1");
    assert_eq!(stored.adapter_id, "openai");
    assert_eq!(stored.resolved_model_id, "gpt-5");
    assert_eq!(stored.independence_group, "group-1");
    assert_eq!(stored.independence_fingerprint, digest('d'));
}

#[test]
fn physical_artifact_hash_and_semantic_config_digest_are_verified_independently() {
    let fixture = Fixture::new();
    let configuration = RunConfiguration::issue(unsigned()).unwrap();
    let artifact = fixture.seed_run("config-1", &configuration);
    assert_ne!(
        artifact.reference.content_hash,
        configuration.config_digest().as_str()
    );
    fs::write(
        fixture.artifact_root.join(&artifact.reference.storage_key),
        b"corrupted",
    )
    .unwrap();

    let error = fixture
        .store()
        .bind_run_configuration(&run_id(), &artifact, &configuration)
        .unwrap_err();
    assert_eq!(
        error.safe_classification(),
        SafeErrorClassification::IntegrityFailure
    );
    assert!(fixture
        .store()
        .run_configuration_binding(&run_id())
        .unwrap()
        .is_none());
}

#[test]
fn binding_recomputes_the_physical_hash_instead_of_trusting_the_reader() {
    let fixture = Fixture::new();
    let configuration = RunConfiguration::issue(unsigned()).unwrap();
    let stored_reference = ContentAddressedArtifactStore::open(&fixture.artifact_root)
        .unwrap()
        .put(NewArtifact {
            expected_hash: digest_bytes(configuration.canonical_bytes())
                .as_str()
                .to_owned(),
            expected_size: configuration.canonical_bytes().len() as u64,
            content: configuration.canonical_bytes().to_vec(),
        })
        .unwrap();
    let artifact = PublishedRunConfigurationArtifact {
        artifact_id: ArtifactId::new("config-1").unwrap(),
        reference: ArtifactRef {
            content_hash: digest('e').as_str().to_owned(),
            storage_key: stored_reference.storage_key,
            size_bytes: stored_reference.size_bytes,
        },
    };
    fixture
        .connection()
        .execute(
            "INSERT INTO artifacts (
                id,task_id,project_id,artifact_type,logical_path,content_hash,storage_key,
                size_bytes,mime_type,availability,created_by_type,created_by_id,created_at,
                supersedes,verification_state
             ) VALUES ('config-1','task-1','project-1','run-config','run/config-1.json',
                ?1,?2,?3,'application/json','available','core','core',
                '1970-01-01T00:00:01Z',NULL,'hash_verified')",
            params![
                artifact.reference.content_hash,
                artifact.reference.storage_key,
                artifact.reference.size_bytes as i64,
            ],
        )
        .unwrap();
    fixture.connection().execute("INSERT INTO agent_runs (id,task_id,agent_id,role,phase,status,context_package_id,idempotency_key,connection_binding_digest,run_config_artifact_id,supersedes_run_id,started_at,completed_at,provider_usage_json,core_usage_json,estimated_cost_microunits,error_json) VALUES ('run-1','task-1','agent-1','reviewer','analysis','created','context-package-1','run-key',?1,'config-1',NULL,NULL,NULL,NULL,NULL,NULL,NULL)", params![digest('6').as_str()]).unwrap();
    let store = SqliteStore::open(&fixture.path)
        .unwrap()
        .with_artifact_reader(Arc::new(UnverifiedArtifactReader {
            bytes: configuration.canonical_bytes().to_vec(),
        }));

    let error = store
        .bind_run_configuration(&run_id(), &artifact, &configuration)
        .unwrap_err();

    assert_eq!(
        error.safe_classification(),
        SafeErrorClassification::IntegrityFailure
    );
    assert!(store
        .run_configuration_binding(&run_id())
        .unwrap()
        .is_none());
}

#[test]
fn binding_fails_closed_without_a_physical_artifact_reader() {
    let fixture = Fixture::new();
    let configuration = RunConfiguration::issue(unsigned()).unwrap();
    let artifact = fixture.seed_run("config-1", &configuration);
    let error = SqliteStore::open(&fixture.path)
        .unwrap()
        .bind_run_configuration(&run_id(), &artifact, &configuration)
        .unwrap_err();
    assert_eq!(
        error.safe_classification(),
        SafeErrorClassification::Unavailable
    );
    assert!(fixture
        .store()
        .run_configuration_binding(&run_id())
        .unwrap()
        .is_none());
}

#[test]
fn cross_task_and_unavailable_artifacts_are_rejected_without_binding() {
    let fixture = Fixture::new();
    let configuration = RunConfiguration::issue(unsigned()).unwrap();
    let artifact = fixture.seed_run("config-1", &configuration);
    let other_ref = fixture.insert_metadata(
        "config-2",
        "task-2",
        "run-config",
        configuration.canonical_bytes(),
        "run/config-2.json",
    );
    let cross_task = PublishedRunConfigurationArtifact {
        artifact_id: ArtifactId::new("config-2").unwrap(),
        reference: other_ref,
    };
    assert_eq!(
        fixture
            .store()
            .bind_run_configuration(&run_id(), &cross_task, &configuration)
            .unwrap_err()
            .safe_classification(),
        SafeErrorClassification::Conflict
    );
    fixture
        .connection()
        .execute(
            "UPDATE artifacts SET availability='missing' WHERE id='config-1'",
            [],
        )
        .unwrap();
    assert!(fixture
        .store()
        .bind_run_configuration(&run_id(), &artifact, &configuration)
        .is_err());
    assert!(fixture
        .store()
        .run_configuration_binding(&run_id())
        .unwrap()
        .is_none());
}

#[test]
fn bindings_are_immutable_one_per_run_and_changed_digest_conflicts() {
    let fixture = Fixture::new();
    let configuration = RunConfiguration::issue(unsigned()).unwrap();
    let artifact = fixture.seed_run("config-1", &configuration);
    let store = fixture.store();
    store
        .bind_run_configuration(&run_id(), &artifact, &configuration)
        .unwrap();
    let mut changed = unsigned();
    changed.model_endpoint.resolved_model_id = "gpt-5-mini".to_owned();
    let changed = RunConfiguration::issue(changed).unwrap();
    assert_eq!(
        store
            .bind_run_configuration(&run_id(), &artifact, &changed)
            .unwrap_err()
            .safe_classification(),
        SafeErrorClassification::Conflict
    );
    assert!(fixture
        .connection()
        .execute(
            "UPDATE run_configuration_bindings SET adapter_id='other' WHERE run_id='run-1'",
            []
        )
        .is_err());
    assert!(fixture
        .connection()
        .execute(
            "DELETE FROM run_configuration_bindings WHERE run_id='run-1'",
            []
        )
        .is_err());
    assert!(fixture.connection().execute("INSERT INTO run_configuration_bindings (run_id,config_artifact_id,config_digest,provider_connection_ref,adapter_id,resolved_model_id,independence_group,independence_fingerprint,created_at) VALUES ('run-1','config-1',?1,'other','other','other','other',?2,'1970-01-01T00:00:01Z')", params![configuration.config_digest().as_str(), digest('d').as_str()]).is_err());
}

#[test]
fn repaired_scope_trigger_rejects_a_different_run_artifact_directly() {
    let fixture = Fixture::new();
    let configuration = RunConfiguration::issue(unsigned()).unwrap();
    fixture.seed_run("config-1", &configuration);
    fixture.insert_metadata(
        "config-2",
        "task-2",
        "run-config",
        configuration.canonical_bytes(),
        "run/config-2.json",
    );

    let error = fixture
        .connection()
        .execute(
            "INSERT INTO run_configuration_bindings (
                run_id, config_artifact_id, config_digest, provider_connection_ref,
                adapter_id, resolved_model_id, independence_group,
                independence_fingerprint, created_at
             ) VALUES ('run-1','config-2',?1,'connection-1','openai','gpt-5',
                'group-1',?2,'1970-01-01T00:00:01Z')",
            params![configuration.config_digest().as_str(), digest('d').as_str()],
        )
        .unwrap_err();

    assert!(error
        .to_string()
        .contains("run configuration binding must match the exact run artifact"));
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
            region: Some("us".to_owned()),
            context_window_tokens: 128_000,
            max_output_tokens: 8_000,
        },
        agent_profile: AgentProfileConfiguration {
            profile_id: "reviewer-v1".to_owned(),
            role: AgentRole::Reviewer,
            prompt_template_version: "prompt-1".to_owned(),
            tool_policy_ref: "policy-1".to_owned(),
            response_schema_ref: "response-1".to_owned(),
        },
        generation_parameters: GenerationParameters {
            temperature: 0.2,
            top_p: 0.9,
            max_output_tokens: 4_000,
            seed: Some(7),
            stop_sequences: vec![],
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
            allowed_data_classes: vec![AllowedDataClass::Internal],
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
                context_corpus: "context-1".to_owned(),
                retrieval_pipeline: "retrieval-1".to_owned(),
                tool_policy: "policy-1".to_owned(),
                adapter_implementation: "adapter-2".to_owned(),
            },
        },
        created_at: Timestamp::from_unix_seconds(1),
    }
}
fn run_id() -> RunId {
    RunId::new("run-1").unwrap()
}
fn digest(byte: char) -> Sha256Digest {
    Sha256Digest::new(format!("sha256:{}", byte.to_string().repeat(64))).unwrap()
}
fn digest_bytes(bytes: &[u8]) -> Sha256Digest {
    use sha2::{Digest, Sha256};
    Sha256Digest::new(format!("sha256:{:x}", Sha256::digest(bytes))).unwrap()
}
