use local_agent_terminal_domain::{
    AgentClaim, AgentDescriptor, AgentEvidenceRef, AgentRunMessage, AgentRunSnapshot,
    AgentRunStatus, AgentRunTerminal, AgentUsage, ArtifactId, BoundAgentConnection,
    BoundAgentRunRequest, BoundEffectiveContext, BoundGenerationParameters, BoundRunConfig, RunId,
    Sha256Digest, TaskId, Timestamp, TrustTier, MAX_GENERATION_PARAMETERS_BYTES,
};

const EMPTY_JSON_DIGEST: &str =
    "sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a";
const CONNECTION_BINDING_DIGEST: &str =
    "sha256:6e171d4e7a1d7b7db1c14807e8a2a5cc9093eac495d66a2ca76439264d09b7d5";
const FULL_ACCESS_LEGACY_CONNECTION_BINDING_DIGEST: &str =
    "sha256:bdcaa025b4f264fee3c7126b6a0d70c1988c2e0d378cd276202701193f857be2";

#[test]
fn agent_run_status_moves_forward_and_never_leaves_a_terminal_status() {
    let mut run = AgentRunSnapshot::created(bound_run()).unwrap();

    assert!(run
        .transition_to(AgentRunStatus::Accepted, Timestamp::from_unix_seconds(10))
        .is_ok());
    assert!(run
        .transition_to(AgentRunStatus::Running, Timestamp::from_unix_seconds(11))
        .is_ok());
    assert!(run
        .transition_to(AgentRunStatus::Succeeded, Timestamp::from_unix_seconds(12))
        .is_ok());
    assert!(run
        .transition_to(AgentRunStatus::Running, Timestamp::from_unix_seconds(13))
        .is_err());

    assert!(!AgentRunStatus::Created.can_transition_to(AgentRunStatus::Running));
    assert!(!AgentRunStatus::Accepted.can_transition_to(AgentRunStatus::Created));
    assert!(AgentRunStatus::Succeeded.is_terminal());
}

#[test]
fn descriptor_rejects_unbounded_identity_missing_core_digest_and_enabled_legacy() {
    let mut empty = descriptor();
    empty.agent_id.clear();
    assert!(empty.validate().is_err());

    let mut oversized = descriptor();
    oversized.display_name = "x".repeat(257);
    assert!(oversized.validate().is_err());

    let mut missing_core_digest = descriptor();
    missing_core_digest.executable_digest = None;
    assert!(missing_core_digest.validate().is_err());

    let mut legacy = descriptor();
    legacy.trust_tier = TrustTier::FullAccessLegacy;
    assert!(legacy.validate().is_err());

    assert!(Sha256Digest::new("sha256:not-a-digest").is_err());
}

#[test]
fn disabled_full_access_legacy_descriptor_is_valid() {
    let mut legacy = descriptor();
    legacy.trust_tier = TrustTier::FullAccessLegacy;
    legacy.enabled = false;

    assert!(legacy.validate().is_ok());
}

#[test]
fn bound_run_rejects_full_access_legacy() {
    let mut legacy_run = bound_run();
    legacy_run.run_config.trust_tier = TrustTier::FullAccessLegacy;
    legacy_run.connection.trust_tier = TrustTier::FullAccessLegacy;
    legacy_run.connection.binding_digest = full_access_legacy_connection_binding_digest();

    assert!(legacy_run.validate().is_err());
}

#[test]
fn generation_parameters_reject_noncanonical_json() {
    let mut noncanonical_parameters = bound_run();
    noncanonical_parameters
        .run_config
        .generation_parameters
        .canonical_json = br#"{"z":1,"a":2}"#.to_vec();
    assert!(noncanonical_parameters
        .run_config
        .generation_parameters
        .validate()
        .is_err());
}

#[test]
fn generation_parameters_reject_digest_mismatch() {
    let mut mismatched_parameters = bound_run();
    mismatched_parameters
        .run_config
        .generation_parameters
        .digest = digest('a');
    assert!(mismatched_parameters
        .run_config
        .generation_parameters
        .validate()
        .is_err());
}

#[test]
fn descriptor_rejects_manifest_digest_mismatch() {
    let mut mismatched_manifest = descriptor();
    mismatched_manifest.manifest_digest = digest('c');
    assert!(mismatched_manifest.validate().is_err());
}

#[test]
fn connection_rejects_binding_digest_mismatch() {
    let mut mismatched_connection = bound_run().connection;
    mismatched_connection.binding_digest = digest('f');
    assert!(mismatched_connection.validate().is_err());
}

#[test]
fn bound_run_rejects_mismatched_bindings_same_run_supersession_and_unbounded_parameters() {
    let mut wrong_task = bound_run();
    wrong_task.run_config.task_id = task_id("task-2");
    assert!(wrong_task.validate().is_err());

    let mut wrong_context_artifact = bound_run();
    wrong_context_artifact
        .run_config
        .effective_context_artifact_id = artifact_id("artifact-2");
    assert!(wrong_context_artifact.validate().is_err());

    let mut same_run_supersession = bound_run();
    same_run_supersession.supersedes_run_id = Some(same_run_supersession.run_id.clone());
    assert!(same_run_supersession.validate().is_err());

    let mut unbounded_parameters = bound_run();
    unbounded_parameters
        .run_config
        .generation_parameters
        .canonical_json = vec![b' '; MAX_GENERATION_PARAMETERS_BYTES + 1];
    assert!(unbounded_parameters.validate().is_err());
}

#[test]
fn terminal_requires_its_own_message_noninverted_evidence_nonnegative_usage_and_core_receipt() {
    let mut message_for_another_run = terminal();
    message_for_another_run.message.run_id = run_id("run-2");
    assert!(message_for_another_run.validate().is_err());

    let mut inverted_evidence = terminal();
    inverted_evidence.message.claims[0].evidence[0].end_line = Some(9);
    assert!(inverted_evidence.validate().is_err());

    let mut negative_usage = terminal();
    negative_usage.provider_usage.as_mut().unwrap().input_tokens = -1;
    assert!(negative_usage.validate().is_err());

    let mut missing_receipt = terminal();
    missing_receipt.core_received_at = None;
    assert!(missing_receipt.validate().is_err());
}

fn descriptor() -> AgentDescriptor {
    AgentDescriptor {
        agent_id: "agent-1".to_owned(),
        display_name: "Agent One".to_owned(),
        trust_tier: TrustTier::CoreAdapter,
        manifest_json: br#"{}"#.to_vec(),
        manifest_digest: empty_json_digest(),
        executable_digest: Some(digest('b')),
        enabled: true,
        containment_verified: true,
    }
}

fn bound_run() -> BoundAgentRunRequest {
    let task_id = task_id("task-1");
    let manifest_digest = empty_json_digest();
    let executable_digest = Some(digest('b'));
    let context_digest = digest('c');
    let policy_digest = digest('d');

    BoundAgentRunRequest {
        run_id: run_id("run-1"),
        task_id: task_id.clone(),
        agent_id: "agent-1".to_owned(),
        role: "reviewer".to_owned(),
        phase: "analysis".to_owned(),
        idempotency_key: "task-1:reviewer:1".to_owned(),
        context: BoundEffectiveContext {
            context_package_id: "context-1".to_owned(),
            task_id: task_id.clone(),
            agent_id: "agent-1".to_owned(),
            role: "reviewer".to_owned(),
            objective: "Review the task.".to_owned(),
            manifest_artifact_id: artifact_id("artifact-context-manifest-1"),
            effective_context_artifact_id: artifact_id("artifact-context-1"),
            content_digest: context_digest.clone(),
            policy_snapshot_digest: policy_digest.clone(),
            prompt_template_version: "prompt-1".to_owned(),
            retrieval_pipeline_version: "retrieval-1".to_owned(),
            created_at: Timestamp::from_unix_seconds(1),
        },
        run_config: BoundRunConfig {
            run_config_artifact_id: artifact_id("artifact-run-config-1"),
            task_id: task_id.clone(),
            agent_id: "agent-1".to_owned(),
            role: "reviewer".to_owned(),
            context_package_id: "context-1".to_owned(),
            effective_context_artifact_id: artifact_id("artifact-context-1"),
            effective_context_digest: context_digest,
            trust_tier: TrustTier::CoreAdapter,
            manifest_digest: manifest_digest.clone(),
            executable_digest: executable_digest.clone(),
            contract_version: "1.0".to_owned(),
            adapter_version: "adapter-1".to_owned(),
            provider_id: "provider-1".to_owned(),
            model_id: "model-1".to_owned(),
            generation_parameters: BoundGenerationParameters {
                canonical_json: br#"{}"#.to_vec(),
                digest: empty_json_digest(),
            },
            prompt_template_version: "prompt-1".to_owned(),
            response_schema_version: "message-1".to_owned(),
            policy_snapshot_digest: policy_digest,
        },
        connection: BoundAgentConnection {
            connection_id: "connection-1".to_owned(),
            agent_id: "agent-1".to_owned(),
            trust_tier: TrustTier::CoreAdapter,
            manifest_digest,
            executable_digest,
            contract_version: "1.0".to_owned(),
            adapter_version: "adapter-1".to_owned(),
            binding_digest: connection_binding_digest(),
        },
        supersedes_run_id: None,
    }
}

fn terminal() -> AgentRunTerminal {
    AgentRunTerminal {
        run_id: run_id("run-1"),
        task_id: task_id("task-1"),
        status: AgentRunStatus::Succeeded,
        message: AgentRunMessage {
            message_id: "message-1".to_owned(),
            task_id: task_id("task-1"),
            run_id: run_id("run-1"),
            thread_id: "thread-1".to_owned(),
            message_type: "review".to_owned(),
            reply_to: None,
            content_artifact_id: artifact_id("artifact-message-1"),
            claims: vec![AgentClaim {
                claim_id: "claim-1".to_owned(),
                text: "The evidence is current.".to_owned(),
                evidence: vec![AgentEvidenceRef {
                    source_type: "repository".to_owned(),
                    source_id: "src/lib.rs".to_owned(),
                    revision: "revision-1".to_owned(),
                    content_digest: digest('f'),
                    start_line: Some(10),
                    end_line: Some(11),
                    symbol: Some("run".to_owned()),
                }],
                confidence: 0.9,
            }],
        },
        provider_usage: Some(AgentUsage {
            input_tokens: 10,
            output_tokens: 11,
            cost_microunits: Some(12),
        }),
        core_usage: Some(AgentUsage {
            input_tokens: 13,
            output_tokens: 14,
            cost_microunits: None,
        }),
        estimated_cost_microunits: Some(12),
        error: None,
        core_received_at: Some(Timestamp::from_unix_seconds(20)),
    }
}

fn artifact_id(value: &str) -> ArtifactId {
    ArtifactId::new(value).unwrap()
}

fn digest(value: char) -> Sha256Digest {
    Sha256Digest::new(format!("sha256:{}", value.to_string().repeat(64))).unwrap()
}

fn empty_json_digest() -> Sha256Digest {
    Sha256Digest::new(EMPTY_JSON_DIGEST).unwrap()
}

fn connection_binding_digest() -> Sha256Digest {
    Sha256Digest::new(CONNECTION_BINDING_DIGEST).unwrap()
}

fn full_access_legacy_connection_binding_digest() -> Sha256Digest {
    Sha256Digest::new(FULL_ACCESS_LEGACY_CONNECTION_BINDING_DIGEST).unwrap()
}

fn run_id(value: &str) -> RunId {
    RunId::new(value).unwrap()
}

fn task_id(value: &str) -> TaskId {
    TaskId::new(value).unwrap()
}
