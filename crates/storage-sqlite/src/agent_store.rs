use std::fs;
use std::path::{Component, Path};

use local_agent_terminal_application::{
    AgentRunStore, PortError, Retryability, SafeErrorClassification,
};
use local_agent_terminal_domain::{
    AgentDescriptor, AgentRunLimits, AgentRunSnapshot, AgentRunStatus, AgentRunTerminal,
    AgentUsage, ArtifactId, BoundAgentConnection, BoundAgentRunRequest, BoundEffectiveContext,
    BoundGenerationParameters, BoundRunConfig, RunId, Sha256Digest, TaskId, Timestamp, TrustTier,
};
use rusqlite::{params, Connection, OptionalExtension, Transaction, TransactionBehavior};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::event_store::{open_error_to_port, sqlite_error_to_port};
use crate::SqliteStore;

const MANIFEST_ARTIFACT_KIND: &str = "manifest";
const CONTEXT_ARTIFACT_KIND: &str = "content";
const RUN_CONFIG_ARTIFACT_KIND: &str = "run-config";
const MESSAGE_ARTIFACT_KIND: &str = "agent-message";
const RUN_CONFIG_SCHEMA_V1: &str = "agent-run-config.v1";
const RUN_CONFIG_SCHEMA_V2: &str = "agent-run-config.v2";
const RUN_CONFIG_ARTIFACT_FIELDS: &[&str] = &["connection", "runConfig", "schema"];
const RUN_CONFIG_CONNECTION_FIELDS: &[&str] = &[
    "adapterVersion",
    "agentId",
    "bindingDigest",
    "connectionId",
    "contractVersion",
    "executableDigest",
    "manifestDigest",
    "trustTier",
];
const RUN_CONFIG_FIELDS: &[&str] = &[
    "adapterVersion",
    "agentId",
    "contextPackageId",
    "contractVersion",
    "effectiveContextArtifactId",
    "effectiveContextDigest",
    "executableDigest",
    "generationParameters",
    "generationParametersDigest",
    "limits",
    "manifestDigest",
    "modelId",
    "policySnapshotDigest",
    "promptTemplateVersion",
    "providerId",
    "responseSchemaVersion",
    "role",
    "runConfigArtifactId",
    "taskId",
    "trustTier",
];
const RUN_CONFIG_LIMIT_FIELDS_V1: &[&str] =
    &["deadlineUnixSeconds", "maxOutputTokens", "maxToolRequests"];
const RUN_CONFIG_LIMIT_FIELDS_V2: &[&str] = &[
    "deadlineUnixSeconds",
    "maxContextQueries",
    "maxOutputTokens",
    "maxSpecialistRequests",
    "maxToolRequests",
];
const TRUSTED_CORE_ADAPTER_ID: &str = "core_adapter";

pub fn canonical_agent_run_config_artifact(
    request: &BoundAgentRunRequest,
) -> Result<Vec<u8>, PortError> {
    request.validate().map_err(|_| invalid_input())?;
    let generation_parameters: Value =
        serde_json::from_slice(&request.run_config.generation_parameters.canonical_json)
            .map_err(|_| invalid_input())?;
    let value = json!({
        "schema": RUN_CONFIG_SCHEMA_V2,
        "connection": {
            "adapterVersion": request.connection.adapter_version,
            "agentId": request.connection.agent_id,
            "bindingDigest": request.connection.binding_digest.as_str(),
            "connectionId": request.connection.connection_id,
            "contractVersion": request.connection.contract_version,
            "executableDigest": request.connection.executable_digest.as_ref().map(Sha256Digest::as_str),
            "manifestDigest": request.connection.manifest_digest.as_str(),
            "trustTier": request.connection.trust_tier.as_str(),
        },
        "runConfig": {
            "adapterVersion": request.run_config.adapter_version,
            "agentId": request.run_config.agent_id,
            "contextPackageId": request.run_config.context_package_id,
            "contractVersion": request.run_config.contract_version,
            "effectiveContextArtifactId": request.run_config.effective_context_artifact_id.as_str(),
            "effectiveContextDigest": request.run_config.effective_context_digest.as_str(),
            "executableDigest": request.run_config.executable_digest.as_ref().map(Sha256Digest::as_str),
            "generationParameters": generation_parameters,
            "generationParametersDigest": request.run_config.generation_parameters.digest.as_str(),
            "limits": {
                "deadlineUnixSeconds": request.run_config.limits.deadline.unix_seconds(),
                "maxContextQueries": request.run_config.limits.max_context_queries,
                "maxOutputTokens": request.run_config.limits.max_output_tokens,
                "maxSpecialistRequests": request.run_config.limits.max_specialist_requests,
                "maxToolRequests": request.run_config.limits.max_tool_requests,
            },
            "manifestDigest": request.run_config.manifest_digest.as_str(),
            "modelId": request.run_config.model_id,
            "policySnapshotDigest": request.run_config.policy_snapshot_digest.as_str(),
            "promptTemplateVersion": request.run_config.prompt_template_version,
            "providerId": request.run_config.provider_id,
            "responseSchemaVersion": request.run_config.response_schema_version,
            "role": request.run_config.role,
            "runConfigArtifactId": request.run_config.run_config_artifact_id.as_str(),
            "taskId": request.run_config.task_id.as_str(),
            "trustTier": request.run_config.trust_tier.as_str(),
        },
    });
    serde_json_canonicalizer::to_vec(&value).map_err(|_| internal_failure())
}

impl SqliteStore {
    pub fn reconcile_trusted_core_adapter(
        &self,
        descriptor: &AgentDescriptor,
        at: &str,
    ) -> Result<Vec<RunId>, PortError> {
        descriptor.validate().map_err(|_| invalid_input())?;
        if descriptor.agent_id != TRUSTED_CORE_ADAPTER_ID
            || descriptor.trust_tier != TrustTier::CoreAdapter
            || !descriptor.enabled
            || !descriptor.containment_verified
        {
            return Err(invalid_input());
        }
        let executable_digest = descriptor
            .executable_digest
            .as_ref()
            .ok_or_else(invalid_input)?;
        let manifest = canonical_manifest(&descriptor.manifest_json)?;
        let completed_at = {
            let connection = self.connection().map_err(open_error_to_port)?;
            validated_timestamp(&connection, at)?
        };
        let mut connection = self.connection().map_err(open_error_to_port)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite_error_to_port)?;
        let registered: Option<RegisteredDescriptor> = transaction
            .query_row(
                "SELECT transport_type, trust_tier, manifest_json, manifest_digest,
                            executable_digest, enabled, containment_verified
                     FROM agent_descriptors WHERE id = ?1",
                [TRUSTED_CORE_ADAPTER_ID],
                |row| {
                    Ok(RegisteredDescriptor {
                        transport: row.get(0)?,
                        trust_tier: row.get(1)?,
                        manifest: row.get(2)?,
                        manifest_digest: row.get(3)?,
                        executable_digest: row.get(4)?,
                        enabled: row.get(5)?,
                        containment_verified: row.get(6)?,
                    })
                },
            )
            .optional()
            .map_err(sqlite_error_to_port)?;
        let Some(registered) = registered else {
            if active_run_count(&transaction, ActiveRunScope::Agent(TRUSTED_CORE_ADAPTER_ID))? != 0
            {
                return Err(conflict());
            }
            transaction.commit().map_err(sqlite_error_to_port)?;
            return Ok(Vec::new());
        };
        if registered.transport != transport_type(TrustTier::CoreAdapter)
            || registered.trust_tier != TrustTier::CoreAdapter.as_str()
            || registered.manifest != manifest
            || registered.manifest_digest != descriptor.manifest_digest.as_str()
            || !registered.enabled
            || !registered.containment_verified
        {
            return Err(conflict());
        }
        let registered_executable_digest = registered.executable_digest.ok_or_else(conflict)?;
        Sha256Digest::new(&registered_executable_digest).map_err(|_| integrity_failure())?;
        let interrupted = interrupt_active_runs(
            &transaction,
            ActiveRunScope::Agent(TRUSTED_CORE_ADAPTER_ID),
            completed_at,
            at,
        )?;
        if registered_executable_digest != executable_digest.as_str() {
            let updated = transaction
                .execute(
                    "UPDATE agent_descriptors
                     SET executable_digest = ?1, updated_at = ?2
                     WHERE id = ?3",
                    params![executable_digest.as_str(), at, TRUSTED_CORE_ADAPTER_ID],
                )
                .map_err(sqlite_error_to_port)?;
            if updated != 1 {
                return Err(conflict());
            }
        }
        transaction.commit().map_err(sqlite_error_to_port)?;
        Ok(interrupted)
    }
}

impl AgentRunStore for SqliteStore {
    fn register_descriptor(&self, descriptor: &AgentDescriptor) -> Result<(), PortError> {
        descriptor.validate().map_err(|_| invalid_input())?;
        let manifest_text = canonical_manifest(&descriptor.manifest_json)?;
        let mut connection = self.connection().map_err(open_error_to_port)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite_error_to_port)?;
        transaction
            .execute(
                "INSERT OR IGNORE INTO agent_descriptors (
                    id, display_name, transport_type, trust_tier, manifest_json,
                    manifest_digest, executable_digest, enabled, containment_verified,
                    last_health_status, updated_at
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, NULL,
                    strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))",
                params![
                    descriptor.agent_id,
                    descriptor.display_name,
                    transport_type(descriptor.trust_tier),
                    descriptor.trust_tier.as_str(),
                    manifest_text,
                    descriptor.manifest_digest.as_str(),
                    descriptor
                        .executable_digest
                        .as_ref()
                        .map(Sha256Digest::as_str),
                    descriptor.enabled,
                    descriptor.containment_verified,
                ],
            )
            .map_err(sqlite_error_to_port)?;
        let matches: bool = transaction
            .query_row(
                "SELECT EXISTS(
                    SELECT 1 FROM agent_descriptors
                    WHERE id = ?1 AND display_name = ?2 AND transport_type = ?3
                      AND trust_tier = ?4 AND manifest_json = ?5 AND manifest_digest = ?6
                      AND executable_digest IS ?7 AND enabled = ?8
                      AND containment_verified = ?9
                 )",
                params![
                    descriptor.agent_id,
                    descriptor.display_name,
                    transport_type(descriptor.trust_tier),
                    descriptor.trust_tier.as_str(),
                    manifest_text,
                    descriptor.manifest_digest.as_str(),
                    descriptor
                        .executable_digest
                        .as_ref()
                        .map(Sha256Digest::as_str),
                    descriptor.enabled,
                    descriptor.containment_verified,
                ],
                |row| row.get(0),
            )
            .map_err(sqlite_error_to_port)?;
        if !matches {
            return Err(conflict());
        }
        transaction.commit().map_err(sqlite_error_to_port)
    }

    fn create_bound_run(
        &self,
        request: &BoundAgentRunRequest,
    ) -> Result<AgentRunSnapshot, PortError> {
        request.validate().map_err(|_| invalid_input())?;
        let expected_run_config = canonical_agent_run_config_artifact(request)?;
        let mut connection = self.connection().map_err(open_error_to_port)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite_error_to_port)?;
        verify_task(&transaction, &request.task_id)?;
        let manifest = verify_descriptor(&transaction, request)?;
        let manifest_artifact = load_available_artifact(
            &transaction,
            &request.context.manifest_artifact_id,
            &request.task_id,
            MANIFEST_ARTIFACT_KIND,
            Some(request.run_config.manifest_digest.as_str()),
        )?;
        if manifest_artifact.bytes != manifest {
            return Err(integrity_failure());
        }
        load_available_artifact(
            &transaction,
            &request.context.effective_context_artifact_id,
            &request.task_id,
            CONTEXT_ARTIFACT_KIND,
            Some(request.context.content_digest.as_str()),
        )?;
        let run_config_artifact = load_available_artifact(
            &transaction,
            &request.run_config.run_config_artifact_id,
            &request.task_id,
            RUN_CONFIG_ARTIFACT_KIND,
            Some(digest_bytes(&expected_run_config).as_str()),
        )?;
        if run_config_artifact.bytes != expected_run_config {
            return Err(integrity_failure());
        }
        verify_supersession(&transaction, request)?;
        insert_or_verify_context(&transaction, &request.context)?;

        let inserted = transaction
            .execute(
                "INSERT OR IGNORE INTO agent_runs (
                    id, task_id, agent_id, role, phase, status, context_package_id,
                    idempotency_key, connection_binding_digest, run_config_artifact_id,
                    supersedes_run_id, started_at, completed_at, provider_usage_json,
                    core_usage_json, estimated_cost_microunits, error_json
                 ) VALUES (?1, ?2, ?3, ?4, ?5, 'created', ?6, ?7, ?8, ?9, ?10,
                    NULL, NULL, NULL, NULL, NULL, NULL)",
                params![
                    request.run_id.as_str(),
                    request.task_id.as_str(),
                    request.agent_id,
                    request.role,
                    request.phase,
                    request.context.context_package_id,
                    request.idempotency_key,
                    request.connection.binding_digest.as_str(),
                    request.run_config.run_config_artifact_id.as_str(),
                    request.supersedes_run_id.as_ref().map(RunId::as_str),
                ],
            )
            .map_err(sqlite_error_to_port)?;
        let snapshot = if inserted == 1 {
            AgentRunSnapshot::created(request.clone()).map_err(|_| invalid_input())?
        } else {
            let bound_run_id: Option<String> = transaction
                .query_row(
                    "SELECT id FROM agent_runs WHERE idempotency_key = ?1",
                    [&request.idempotency_key],
                    |row| row.get(0),
                )
                .optional()
                .map_err(sqlite_error_to_port)?;
            if bound_run_id.as_deref() != Some(request.run_id.as_str()) {
                return Err(conflict());
            }
            let snapshot = load_run_on_connection(&transaction, &request.run_id)?
                .ok_or_else(integrity_failure)?;
            if snapshot.request != *request {
                return Err(conflict());
            }
            snapshot
        };
        transaction.commit().map_err(sqlite_error_to_port)?;
        Ok(snapshot)
    }

    fn accept_run(&self, run_id: &RunId, accepted_at: &str) -> Result<(), PortError> {
        let mut connection = self.connection().map_err(open_error_to_port)?;
        validated_timestamp(&connection, accepted_at)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite_error_to_port)?;
        let updated = transaction
            .execute(
                "UPDATE agent_runs SET status = 'accepted'
                 WHERE id = ?1 AND status = 'created'",
                [run_id.as_str()],
            )
            .map_err(sqlite_error_to_port)?;
        if updated != 1 {
            return Err(conflict());
        }
        append_run_event(
            &transaction,
            run_id,
            "agent.run.accepted",
            accepted_at,
            json!({"runId": run_id.as_str(), "status": "accepted"}),
        )?;
        transaction.commit().map_err(sqlite_error_to_port)
    }

    fn mark_running(&self, run_id: &RunId, started_at: &str) -> Result<(), PortError> {
        let started = {
            let connection = self.connection().map_err(open_error_to_port)?;
            validated_timestamp(&connection, started_at)?
        };
        let mut connection = self.connection().map_err(open_error_to_port)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite_error_to_port)?;
        let accepted = load_run_event_timestamp(&transaction, run_id, "agent.run.accepted")?
            .ok_or_else(integrity_failure)?;
        if started < accepted {
            return Err(invalid_input());
        }
        let updated = transaction
            .execute(
                "UPDATE agent_runs SET status = 'running', started_at = ?1
                 WHERE id = ?2 AND status = 'accepted' AND started_at IS NULL",
                params![started_at, run_id.as_str()],
            )
            .map_err(sqlite_error_to_port)?;
        if updated != 1 {
            return Err(conflict());
        }
        append_run_event(
            &transaction,
            run_id,
            "agent.run.started",
            started_at,
            json!({"runId": run_id.as_str(), "status": "running"}),
        )?;
        transaction.commit().map_err(sqlite_error_to_port)
    }

    fn persist_terminal(&self, terminal: &AgentRunTerminal) -> Result<(), PortError> {
        terminal.validate().map_err(|_| invalid_input())?;
        let completed_at = terminal.core_received_at.ok_or_else(invalid_input)?;
        let mut connection = self.connection().map_err(open_error_to_port)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite_error_to_port)?;
        let mut snapshot =
            load_run_on_connection(&transaction, &terminal.run_id)?.ok_or_else(not_found)?;
        if snapshot.request.task_id != terminal.task_id {
            return Err(invalid_input());
        }
        let previous_status = snapshot.status;
        snapshot
            .transition_to(terminal.status, completed_at)
            .map_err(|_| conflict())?;
        load_available_artifact(
            &transaction,
            &terminal.message.content_artifact_id,
            &terminal.task_id,
            MESSAGE_ARTIFACT_KIND,
            None,
        )?;
        let receipt_time = format_timestamp(&transaction, completed_at)?;
        transaction
            .execute(
                "INSERT INTO messages (
                    id, task_id, run_id, thread_id, message_type, reply_to,
                    content_artifact_id, status, core_received_at, superseded_by
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 'accepted', ?8, NULL)",
                params![
                    terminal.message.message_id,
                    terminal.task_id.as_str(),
                    terminal.run_id.as_str(),
                    terminal.message.thread_id,
                    terminal.message.message_type,
                    terminal.message.reply_to,
                    terminal.message.content_artifact_id.as_str(),
                    receipt_time,
                ],
            )
            .map_err(sqlite_error_to_port)?;
        let provider_usage = terminal.provider_usage.as_ref().map(usage_json);
        let core_usage = terminal.core_usage.as_ref().map(usage_json);
        let error_json = terminal
            .error
            .as_ref()
            .map(|error| serde_json::to_string(error).expect("string serialization cannot fail"));
        let updated = transaction
            .execute(
                "UPDATE agent_runs SET status = ?1, completed_at = ?2,
                    provider_usage_json = ?3, core_usage_json = ?4,
                    estimated_cost_microunits = ?5, error_json = ?6
                 WHERE id = ?7 AND status = ?8 AND completed_at IS NULL",
                params![
                    status_name(terminal.status),
                    receipt_time,
                    provider_usage,
                    core_usage,
                    terminal.estimated_cost_microunits,
                    error_json,
                    terminal.run_id.as_str(),
                    status_name(previous_status),
                ],
            )
            .map_err(sqlite_error_to_port)?;
        if updated != 1 {
            return Err(conflict());
        }
        append_run_event(
            &transaction,
            &terminal.run_id,
            "agent.run.completed",
            &receipt_time,
            json!({
                "messageId": terminal.message.message_id,
                "runId": terminal.run_id.as_str(),
                "status": status_name(terminal.status),
            }),
        )?;
        transaction.commit().map_err(sqlite_error_to_port)
    }

    fn interrupt_connection(
        &self,
        connection_digest: &str,
        at: &str,
    ) -> Result<Vec<RunId>, PortError> {
        Sha256Digest::new(connection_digest).map_err(|_| invalid_input())?;
        let completed_at = {
            let connection = self.connection().map_err(open_error_to_port)?;
            validated_timestamp(&connection, at)?
        };
        let mut connection = self.connection().map_err(open_error_to_port)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite_error_to_port)?;
        let interrupted = interrupt_active_runs(
            &transaction,
            ActiveRunScope::Connection(connection_digest),
            completed_at,
            at,
        )?;
        transaction.commit().map_err(sqlite_error_to_port)?;
        Ok(interrupted)
    }

    fn load_run(&self, run_id: &RunId) -> Result<Option<AgentRunSnapshot>, PortError> {
        let connection = self.connection().map_err(open_error_to_port)?;
        load_run_on_connection(&connection, run_id)
    }
}

enum ActiveRunScope<'a> {
    Connection(&'a str),
    Agent(&'a str),
}

struct RegisteredDescriptor {
    transport: String,
    trust_tier: String,
    manifest: String,
    manifest_digest: String,
    executable_digest: Option<String>,
    enabled: bool,
    containment_verified: bool,
}

struct ActiveRun {
    id: String,
    status: String,
    started_at: Option<String>,
    completed_at: Option<String>,
}

fn active_run_count(
    transaction: &Transaction<'_>,
    scope: ActiveRunScope<'_>,
) -> Result<u64, PortError> {
    let (column, value) = active_run_scope(scope);
    transaction
        .query_row(
            &format!(
                "SELECT COUNT(*) FROM agent_runs
                 WHERE {column} = ?1 AND status IN ('created', 'accepted', 'running')"
            ),
            [value],
            |row| row.get(0),
        )
        .map_err(sqlite_error_to_port)
}

fn interrupt_active_runs(
    transaction: &Transaction<'_>,
    scope: ActiveRunScope<'_>,
    completed_at: Timestamp,
    at: &str,
) -> Result<Vec<RunId>, PortError> {
    let active_runs = load_active_runs(transaction, scope)?;
    let mut interrupted = Vec::with_capacity(active_runs.len());
    for active_run in active_runs {
        let run_id = RunId::new(active_run.id).map_err(|_| integrity_failure())?;
        validate_interruption_lifecycle(
            transaction,
            &run_id,
            &active_run.status,
            active_run.started_at.as_deref(),
            active_run.completed_at.as_deref(),
            completed_at,
        )?;
        let updated = transaction
            .execute(
                "UPDATE agent_runs SET status = 'interrupted', completed_at = ?1
                 WHERE id = ?2 AND status = ?3 AND completed_at IS NULL",
                params![at, run_id.as_str(), active_run.status],
            )
            .map_err(sqlite_error_to_port)?;
        if updated != 1 {
            return Err(conflict());
        }
        append_run_event(
            transaction,
            &run_id,
            "agent.run.completed",
            at,
            json!({"runId": run_id.as_str(), "status": "interrupted"}),
        )?;
        interrupted.push(run_id);
    }
    Ok(interrupted)
}

fn load_active_runs(
    transaction: &Transaction<'_>,
    scope: ActiveRunScope<'_>,
) -> Result<Vec<ActiveRun>, PortError> {
    let (column, value) = active_run_scope(scope);
    let mut statement = transaction
        .prepare(&format!(
            "SELECT id, status, started_at, completed_at FROM agent_runs
             WHERE {column} = ?1 AND status IN ('created', 'accepted', 'running')
             ORDER BY id"
        ))
        .map_err(sqlite_error_to_port)?;
    let runs = statement
        .query_map([value], |row| {
            Ok(ActiveRun {
                id: row.get(0)?,
                status: row.get(1)?,
                started_at: row.get(2)?,
                completed_at: row.get(3)?,
            })
        })
        .map_err(sqlite_error_to_port)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(sqlite_error_to_port)?;
    Ok(runs)
}

fn active_run_scope(scope: ActiveRunScope<'_>) -> (&'static str, &str) {
    match scope {
        ActiveRunScope::Connection(digest) => ("connection_binding_digest", digest),
        ActiveRunScope::Agent(agent_id) => ("agent_id", agent_id),
    }
}

struct ArtifactBytes {
    bytes: Vec<u8>,
}

struct RawRun {
    id: String,
    task_id: String,
    agent_id: String,
    role: String,
    phase: String,
    status: String,
    context_package_id: String,
    idempotency_key: String,
    connection_binding_digest: String,
    run_config_artifact_id: String,
    supersedes_run_id: Option<String>,
    started_at: Option<String>,
    completed_at: Option<String>,
    context_agent_id: String,
    context_role: String,
    objective: String,
    manifest_artifact_id: String,
    effective_context_artifact_id: String,
    content_hash: String,
    policy_snapshot_digest: String,
    prompt_template_version: String,
    retrieval_pipeline_version: String,
    context_created_at: String,
}

fn load_run_on_connection(
    connection: &Connection,
    run_id: &RunId,
) -> Result<Option<AgentRunSnapshot>, PortError> {
    let raw = connection
        .query_row(
            "SELECT r.id, r.task_id, r.agent_id, r.role, r.phase, r.status,
                    r.context_package_id, r.idempotency_key, r.connection_binding_digest,
                    r.run_config_artifact_id, r.supersedes_run_id, r.started_at,
                    r.completed_at, c.agent_id, c.role, c.objective,
                    c.manifest_artifact_id, c.effective_content_artifact_id,
                    c.content_hash, c.policy_snapshot_digest, c.prompt_template_version,
                    c.retrieval_pipeline_version, c.created_at
             FROM agent_runs r
             JOIN context_packages c ON c.id = r.context_package_id
             WHERE r.id = ?1",
            [run_id.as_str()],
            |row| {
                Ok(RawRun {
                    id: row.get(0)?,
                    task_id: row.get(1)?,
                    agent_id: row.get(2)?,
                    role: row.get(3)?,
                    phase: row.get(4)?,
                    status: row.get(5)?,
                    context_package_id: row.get(6)?,
                    idempotency_key: row.get(7)?,
                    connection_binding_digest: row.get(8)?,
                    run_config_artifact_id: row.get(9)?,
                    supersedes_run_id: row.get(10)?,
                    started_at: row.get(11)?,
                    completed_at: row.get(12)?,
                    context_agent_id: row.get(13)?,
                    context_role: row.get(14)?,
                    objective: row.get(15)?,
                    manifest_artifact_id: row.get(16)?,
                    effective_context_artifact_id: row.get(17)?,
                    content_hash: row.get(18)?,
                    policy_snapshot_digest: row.get(19)?,
                    prompt_template_version: row.get(20)?,
                    retrieval_pipeline_version: row.get(21)?,
                    context_created_at: row.get(22)?,
                })
            },
        )
        .optional()
        .map_err(sqlite_error_to_port)?;
    raw.map(|raw| snapshot_from_raw(connection, raw))
        .transpose()
}

fn snapshot_from_raw(connection: &Connection, raw: RawRun) -> Result<AgentRunSnapshot, PortError> {
    let task_id = TaskId::new(raw.task_id).map_err(|_| integrity_failure())?;
    let run_id = RunId::new(raw.id).map_err(|_| integrity_failure())?;
    let run_config_artifact_id =
        ArtifactId::new(raw.run_config_artifact_id).map_err(|_| integrity_failure())?;
    let artifact = load_available_artifact(
        connection,
        &run_config_artifact_id,
        &task_id,
        RUN_CONFIG_ARTIFACT_KIND,
        None,
    )?;
    let (run_config, connection_binding) = parse_run_config_artifact(&artifact.bytes)?;
    if connection_binding.binding_digest.as_str() != raw.connection_binding_digest {
        return Err(integrity_failure());
    }
    let context = BoundEffectiveContext {
        context_package_id: raw.context_package_id,
        task_id: task_id.clone(),
        agent_id: raw.context_agent_id,
        role: raw.context_role,
        objective: raw.objective,
        manifest_artifact_id: ArtifactId::new(raw.manifest_artifact_id)
            .map_err(|_| integrity_failure())?,
        effective_context_artifact_id: ArtifactId::new(raw.effective_context_artifact_id)
            .map_err(|_| integrity_failure())?,
        content_digest: Sha256Digest::new(raw.content_hash).map_err(|_| integrity_failure())?,
        policy_snapshot_digest: Sha256Digest::new(raw.policy_snapshot_digest)
            .map_err(|_| integrity_failure())?,
        prompt_template_version: raw.prompt_template_version,
        retrieval_pipeline_version: raw.retrieval_pipeline_version,
        created_at: validated_timestamp(connection, &raw.context_created_at)?,
    };
    let request = BoundAgentRunRequest {
        run_id: run_id.clone(),
        task_id,
        agent_id: raw.agent_id,
        role: raw.role,
        phase: raw.phase,
        idempotency_key: raw.idempotency_key,
        context,
        run_config,
        connection: connection_binding,
        supersedes_run_id: raw
            .supersedes_run_id
            .map(RunId::new)
            .transpose()
            .map_err(|_| integrity_failure())?,
    };
    let manifest_artifact = load_available_artifact(
        connection,
        &request.context.manifest_artifact_id,
        &request.task_id,
        MANIFEST_ARTIFACT_KIND,
        Some(request.run_config.manifest_digest.as_str()),
    )?;
    verify_historical_run_binding(&request, &manifest_artifact.bytes)?;
    load_available_artifact(
        connection,
        &request.context.effective_context_artifact_id,
        &request.task_id,
        CONTEXT_ARTIFACT_KIND,
        Some(request.context.content_digest.as_str()),
    )?;
    let status = parse_status(&raw.status).ok_or_else(integrity_failure)?;
    let accepted_at = load_run_event_timestamp(connection, &run_id, "agent.run.accepted")?;
    let started_at = raw
        .started_at
        .as_deref()
        .map(|value| validated_timestamp(connection, value))
        .transpose()?;
    let completed_at = raw
        .completed_at
        .as_deref()
        .map(|value| validated_timestamp(connection, value))
        .transpose()?;
    let mut snapshot = AgentRunSnapshot::created(request).map_err(|_| integrity_failure())?;
    if let Some(accepted_at) = accepted_at {
        snapshot
            .transition_to(AgentRunStatus::Accepted, accepted_at)
            .map_err(|_| integrity_failure())?;
    }
    if let Some(started_at) = started_at {
        snapshot
            .transition_to(AgentRunStatus::Running, started_at)
            .map_err(|_| integrity_failure())?;
    }
    if status.is_terminal() {
        snapshot
            .transition_to(status, completed_at.ok_or_else(integrity_failure)?)
            .map_err(|_| integrity_failure())?;
    } else if snapshot.status != status || completed_at.is_some() {
        return Err(integrity_failure());
    }
    Ok(snapshot)
}

fn verify_task(connection: &Connection, task_id: &TaskId) -> Result<(), PortError> {
    let exists: bool = connection
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM tasks WHERE id = ?1)",
            [task_id.as_str()],
            |row| row.get(0),
        )
        .map_err(sqlite_error_to_port)?;
    if exists {
        Ok(())
    } else {
        Err(not_found())
    }
}

fn verify_descriptor(
    connection: &Connection,
    request: &BoundAgentRunRequest,
) -> Result<Vec<u8>, PortError> {
    let descriptor: Option<(String, String, Option<String>, bool)> = connection
        .query_row(
            "SELECT manifest_json, trust_tier, executable_digest, enabled
             FROM agent_descriptors
             WHERE id = ?1 AND manifest_digest = ?2",
            params![
                request.agent_id,
                request.run_config.manifest_digest.as_str()
            ],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .optional()
        .map_err(sqlite_error_to_port)?;
    let Some((manifest, trust_tier, executable_digest, enabled)) = descriptor else {
        return Err(integrity_failure());
    };
    if !enabled
        || trust_tier != request.run_config.trust_tier.as_str()
        || executable_digest.as_deref()
            != request
                .run_config
                .executable_digest
                .as_ref()
                .map(Sha256Digest::as_str)
    {
        return Err(integrity_failure());
    }
    Ok(manifest.into_bytes())
}

fn verify_historical_run_binding(
    request: &BoundAgentRunRequest,
    manifest_bytes: &[u8],
) -> Result<(), PortError> {
    request.validate().map_err(|_| integrity_failure())?;
    let manifest = canonical_manifest(manifest_bytes).map_err(|_| integrity_failure())?;
    if digest_bytes(manifest.as_bytes()) != request.run_config.manifest_digest {
        return Err(integrity_failure());
    }
    Ok(())
}

fn verify_supersession(
    connection: &Connection,
    request: &BoundAgentRunRequest,
) -> Result<(), PortError> {
    let Some(supersedes) = &request.supersedes_run_id else {
        return Ok(());
    };
    let previous: Option<(String, String, String)> = connection
        .query_row(
            "SELECT task_id, agent_id, status FROM agent_runs WHERE id = ?1",
            [supersedes.as_str()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()
        .map_err(sqlite_error_to_port)?;
    let Some((task_id, agent_id, status)) = previous else {
        return Err(integrity_failure());
    };
    if task_id != request.task_id.as_str()
        || agent_id != request.agent_id
        || !parse_status(&status).is_some_and(AgentRunStatus::is_terminal)
    {
        return Err(conflict());
    }
    Ok(())
}

fn insert_or_verify_context(
    transaction: &Transaction<'_>,
    context: &BoundEffectiveContext,
) -> Result<(), PortError> {
    transaction
        .execute(
            "INSERT OR IGNORE INTO context_packages (
                id, task_id, agent_id, role, objective, manifest_artifact_id,
                effective_content_artifact_id, content_hash, policy_snapshot_digest,
                prompt_template_version, retrieval_pipeline_version, created_at
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11,
                strftime('%Y-%m-%dT%H:%M:%SZ', ?12, 'unixepoch'))",
            params![
                context.context_package_id,
                context.task_id.as_str(),
                context.agent_id,
                context.role,
                context.objective,
                context.manifest_artifact_id.as_str(),
                context.effective_context_artifact_id.as_str(),
                context.content_digest.as_str(),
                context.policy_snapshot_digest.as_str(),
                context.prompt_template_version,
                context.retrieval_pipeline_version,
                context.created_at.unix_seconds(),
            ],
        )
        .map_err(sqlite_error_to_port)?;
    let matches: bool = transaction
        .query_row(
            "SELECT EXISTS(
                SELECT 1 FROM context_packages
                WHERE id = ?1 AND task_id = ?2 AND agent_id = ?3 AND role = ?4
                  AND objective = ?5 AND manifest_artifact_id = ?6
                  AND effective_content_artifact_id = ?7 AND content_hash = ?8
                  AND policy_snapshot_digest = ?9 AND prompt_template_version = ?10
                  AND retrieval_pipeline_version = ?11 AND unixepoch(created_at) = ?12
             )",
            params![
                context.context_package_id,
                context.task_id.as_str(),
                context.agent_id,
                context.role,
                context.objective,
                context.manifest_artifact_id.as_str(),
                context.effective_context_artifact_id.as_str(),
                context.content_digest.as_str(),
                context.policy_snapshot_digest.as_str(),
                context.prompt_template_version,
                context.retrieval_pipeline_version,
                context.created_at.unix_seconds(),
            ],
            |row| row.get(0),
        )
        .map_err(sqlite_error_to_port)?;
    if matches {
        Ok(())
    } else {
        Err(conflict())
    }
}

fn load_available_artifact(
    connection: &Connection,
    artifact_id: &ArtifactId,
    task_id: &TaskId,
    expected_kind: &str,
    expected_hash: Option<&str>,
) -> Result<ArtifactBytes, PortError> {
    let artifact: Option<(Option<String>, String, String, String, i64, String)> = connection
        .query_row(
            "SELECT a.task_id, a.artifact_type, a.content_hash, a.storage_key,
                    a.size_bytes, p.artifact_root_path
             FROM artifacts a
             JOIN projects p ON p.id = a.project_id
             WHERE a.id = ?1 AND a.availability = 'available'",
            [artifact_id.as_str()],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                ))
            },
        )
        .optional()
        .map_err(sqlite_error_to_port)?;
    let Some((owner, kind, content_hash, storage_key, size_bytes, artifact_root)) = artifact else {
        return Err(integrity_failure());
    };
    if owner.as_deref() != Some(task_id.as_str())
        || kind != expected_kind
        || expected_hash.is_some_and(|expected| expected != content_hash)
    {
        return Err(integrity_failure());
    }
    let relative = Path::new(&storage_key);
    if relative.is_absolute()
        || relative
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(integrity_failure());
    }
    let bytes =
        fs::read(Path::new(&artifact_root).join(relative)).map_err(|_| integrity_failure())?;
    if i64::try_from(bytes.len()).ok() != Some(size_bytes)
        || digest_bytes(&bytes).as_str() != content_hash
    {
        return Err(integrity_failure());
    }
    Ok(ArtifactBytes { bytes })
}

fn append_run_event(
    transaction: &Transaction<'_>,
    run_id: &RunId,
    event_type: &str,
    created_at: &str,
    payload: Value,
) -> Result<(), PortError> {
    let stream_id = format!("agent-run:{}", run_id.as_str());
    let sequence: i64 = transaction
        .query_row(
            "SELECT COALESCE(MAX(sequence), 0) + 1 FROM events WHERE stream_id = ?1",
            [&stream_id],
            |row| row.get(0),
        )
        .map_err(sqlite_error_to_port)?;
    let event_id = format!("{event_type}:{}", run_id.as_str());
    transaction
        .execute(
            "INSERT INTO events (
                event_id, stream_id, sequence, event_type, schema_version, actor_type,
                actor_id, observation_class, payload_json, metadata_json, causation_id,
                correlation_id, created_at
             ) VALUES (?1, ?2, ?3, ?4, 1, 'core', 'core', 'core_observed',
                ?5, '{}', NULL, ?2, ?6)",
            params![
                event_id,
                stream_id,
                sequence,
                event_type,
                payload.to_string(),
                created_at,
            ],
        )
        .map_err(sqlite_error_to_port)?;
    Ok(())
}

fn load_run_event_timestamp(
    connection: &Connection,
    run_id: &RunId,
    event_type: &str,
) -> Result<Option<Timestamp>, PortError> {
    let created_at: Option<String> = connection
        .query_row(
            "SELECT created_at FROM events
             WHERE stream_id = ?1 AND event_type = ?2
             ORDER BY sequence LIMIT 1",
            params![format!("agent-run:{}", run_id.as_str()), event_type],
            |row| row.get(0),
        )
        .optional()
        .map_err(sqlite_error_to_port)?;
    created_at
        .as_deref()
        .map(|value| validated_timestamp(connection, value))
        .transpose()
}

fn validate_interruption_lifecycle(
    connection: &Connection,
    run_id: &RunId,
    status: &str,
    started_at: Option<&str>,
    completed_at: Option<&str>,
    interruption_at: Timestamp,
) -> Result<(), PortError> {
    let status = parse_status(status).ok_or_else(integrity_failure)?;
    if !status.can_transition_to(AgentRunStatus::Interrupted) {
        return Err(conflict());
    }
    if completed_at.is_some() {
        return Err(integrity_failure());
    }
    let accepted_at = load_run_event_timestamp(connection, run_id, "agent.run.accepted")?;
    let started_at = started_at
        .map(|value| validated_timestamp(connection, value))
        .transpose()?;
    let lifecycle_is_consistent = match status {
        AgentRunStatus::Created => accepted_at.is_none() && started_at.is_none(),
        AgentRunStatus::Accepted => accepted_at.is_some() && started_at.is_none(),
        AgentRunStatus::Running => accepted_at
            .zip(started_at)
            .is_some_and(|(accepted_at, started_at)| started_at >= accepted_at),
        _ => false,
    };
    if !lifecycle_is_consistent {
        return Err(integrity_failure());
    }
    if started_at
        .or(accepted_at)
        .is_some_and(|at| interruption_at < at)
    {
        return Err(conflict());
    }
    Ok(())
}

fn parse_run_config_artifact(
    bytes: &[u8],
) -> Result<(BoundRunConfig, BoundAgentConnection), PortError> {
    let value: Value = serde_json::from_slice(bytes).map_err(|_| integrity_failure())?;
    if serde_json_canonicalizer::to_vec(&value).map_err(|_| integrity_failure())? != bytes {
        return Err(integrity_failure());
    }
    require_exact_fields(&value, RUN_CONFIG_ARTIFACT_FIELDS)?;
    let schema = required_string(&value, "schema")?;
    let config = required_object(&value, "runConfig")?;
    let connection = required_object(&value, "connection")?;
    require_exact_fields(config, RUN_CONFIG_FIELDS)?;
    require_exact_fields(connection, RUN_CONFIG_CONNECTION_FIELDS)?;
    let generation_parameters = config
        .get("generationParameters")
        .ok_or_else(integrity_failure)?;
    let limits = required_object(config, "limits")?;
    let (max_context_queries, max_specialist_requests) = match schema {
        RUN_CONFIG_SCHEMA_V1 => {
            require_exact_fields(limits, RUN_CONFIG_LIMIT_FIELDS_V1)?;
            (0, 0)
        }
        RUN_CONFIG_SCHEMA_V2 => {
            require_exact_fields(limits, RUN_CONFIG_LIMIT_FIELDS_V2)?;
            (
                required_u64(limits, "maxContextQueries")?,
                required_u64(limits, "maxSpecialistRequests")?,
            )
        }
        _ => return Err(integrity_failure()),
    };
    let run_config = BoundRunConfig {
        run_config_artifact_id: artifact_id(config, "runConfigArtifactId")?,
        task_id: task_id(config, "taskId")?,
        agent_id: required_string(config, "agentId")?.to_owned(),
        role: required_string(config, "role")?.to_owned(),
        context_package_id: required_string(config, "contextPackageId")?.to_owned(),
        effective_context_artifact_id: artifact_id(config, "effectiveContextArtifactId")?,
        effective_context_digest: digest(config, "effectiveContextDigest")?,
        trust_tier: trust_tier(config, "trustTier")?,
        manifest_digest: digest(config, "manifestDigest")?,
        executable_digest: optional_digest(config, "executableDigest")?,
        contract_version: required_string(config, "contractVersion")?.to_owned(),
        adapter_version: required_string(config, "adapterVersion")?.to_owned(),
        provider_id: required_string(config, "providerId")?.to_owned(),
        model_id: required_string(config, "modelId")?.to_owned(),
        generation_parameters: BoundGenerationParameters {
            canonical_json: serde_json_canonicalizer::to_vec(generation_parameters)
                .map_err(|_| integrity_failure())?,
            digest: digest(config, "generationParametersDigest")?,
        },
        prompt_template_version: required_string(config, "promptTemplateVersion")?.to_owned(),
        response_schema_version: required_string(config, "responseSchemaVersion")?.to_owned(),
        policy_snapshot_digest: digest(config, "policySnapshotDigest")?,
        limits: AgentRunLimits {
            deadline: Timestamp::from_unix_seconds(required_i64(limits, "deadlineUnixSeconds")?),
            max_output_tokens: required_u64(limits, "maxOutputTokens")?,
            max_tool_requests: required_u64(limits, "maxToolRequests")?,
            max_context_queries,
            max_specialist_requests,
        },
    };
    let connection = BoundAgentConnection {
        connection_id: required_string(connection, "connectionId")?.to_owned(),
        agent_id: required_string(connection, "agentId")?.to_owned(),
        trust_tier: trust_tier(connection, "trustTier")?,
        manifest_digest: digest(connection, "manifestDigest")?,
        executable_digest: optional_digest(connection, "executableDigest")?,
        contract_version: required_string(connection, "contractVersion")?.to_owned(),
        adapter_version: required_string(connection, "adapterVersion")?.to_owned(),
        binding_digest: digest(connection, "bindingDigest")?,
    };
    run_config.validate().map_err(|_| integrity_failure())?;
    connection.validate().map_err(|_| integrity_failure())?;
    Ok((run_config, connection))
}

fn required_object<'a>(value: &'a Value, key: &str) -> Result<&'a Value, PortError> {
    value
        .get(key)
        .filter(|field| field.is_object())
        .ok_or_else(integrity_failure)
}

fn require_exact_fields(value: &Value, expected: &[&str]) -> Result<(), PortError> {
    let fields = value.as_object().ok_or_else(integrity_failure)?;
    if fields.len() != expected.len() || expected.iter().any(|field| !fields.contains_key(*field)) {
        return Err(integrity_failure());
    }
    Ok(())
}

fn required_string<'a>(value: &'a Value, key: &str) -> Result<&'a str, PortError> {
    value
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(integrity_failure)
}

fn required_i64(value: &Value, key: &str) -> Result<i64, PortError> {
    value
        .get(key)
        .and_then(Value::as_i64)
        .ok_or_else(integrity_failure)
}

fn required_u64(value: &Value, key: &str) -> Result<u64, PortError> {
    value
        .get(key)
        .and_then(Value::as_u64)
        .ok_or_else(integrity_failure)
}

fn digest(value: &Value, key: &str) -> Result<Sha256Digest, PortError> {
    Sha256Digest::new(required_string(value, key)?).map_err(|_| integrity_failure())
}

fn optional_digest(value: &Value, key: &str) -> Result<Option<Sha256Digest>, PortError> {
    match value.get(key) {
        Some(Value::Null) => Ok(None),
        Some(Value::String(value)) => Sha256Digest::new(value)
            .map(Some)
            .map_err(|_| integrity_failure()),
        _ => Err(integrity_failure()),
    }
}

fn artifact_id(value: &Value, key: &str) -> Result<ArtifactId, PortError> {
    ArtifactId::new(required_string(value, key)?).map_err(|_| integrity_failure())
}

fn task_id(value: &Value, key: &str) -> Result<TaskId, PortError> {
    TaskId::new(required_string(value, key)?).map_err(|_| integrity_failure())
}

fn trust_tier(value: &Value, key: &str) -> Result<TrustTier, PortError> {
    match required_string(value, key)? {
        "core_adapter" => Ok(TrustTier::CoreAdapter),
        "brokered_process" => Ok(TrustTier::BrokeredProcess),
        "isolated_worker" => Ok(TrustTier::IsolatedWorker),
        "full_access_legacy" => Ok(TrustTier::FullAccessLegacy),
        _ => Err(integrity_failure()),
    }
}

fn validated_timestamp(connection: &Connection, value: &str) -> Result<Timestamp, PortError> {
    let seconds: Option<i64> = connection
        .query_row("SELECT unixepoch(?1)", [value], |row| row.get(0))
        .map_err(sqlite_error_to_port)?;
    seconds
        .map(Timestamp::from_unix_seconds)
        .ok_or_else(invalid_input)
}

fn format_timestamp(connection: &Connection, value: Timestamp) -> Result<String, PortError> {
    let timestamp: Option<String> = connection
        .query_row(
            "SELECT strftime('%Y-%m-%dT%H:%M:%SZ', ?1, 'unixepoch')",
            [value.unix_seconds()],
            |row| row.get(0),
        )
        .map_err(sqlite_error_to_port)?;
    timestamp.ok_or_else(invalid_input)
}

fn usage_json(usage: &AgentUsage) -> String {
    json!({
        "costMicrounits": usage.cost_microunits,
        "inputTokens": usage.input_tokens,
        "outputTokens": usage.output_tokens,
    })
    .to_string()
}

fn canonical_manifest(bytes: &[u8]) -> Result<String, PortError> {
    let value: Value = serde_json::from_slice(bytes).map_err(|_| invalid_input())?;
    let canonical = serde_json_canonicalizer::to_vec(&value).map_err(|_| invalid_input())?;
    if canonical != bytes {
        return Err(invalid_input());
    }
    String::from_utf8(canonical).map_err(|_| invalid_input())
}

fn digest_bytes(bytes: &[u8]) -> Sha256Digest {
    Sha256Digest::new(format!("sha256:{:x}", Sha256::digest(bytes)))
        .expect("SHA-256 formatting is valid")
}

fn transport_type(trust_tier: TrustTier) -> &'static str {
    if matches!(trust_tier, TrustTier::CoreAdapter) {
        "in_process"
    } else {
        "protocol_peer"
    }
}

fn status_name(status: AgentRunStatus) -> &'static str {
    match status {
        AgentRunStatus::Created => "created",
        AgentRunStatus::Accepted => "accepted",
        AgentRunStatus::Running => "running",
        AgentRunStatus::Succeeded => "succeeded",
        AgentRunStatus::Failed => "failed",
        AgentRunStatus::CancelledCleanly => "cancelled_cleanly",
        AgentRunStatus::Terminated => "terminated",
        AgentRunStatus::Interrupted => "interrupted",
        AgentRunStatus::Indeterminate => "indeterminate",
    }
}

fn parse_status(value: &str) -> Option<AgentRunStatus> {
    match value {
        "created" => Some(AgentRunStatus::Created),
        "accepted" => Some(AgentRunStatus::Accepted),
        "running" => Some(AgentRunStatus::Running),
        "succeeded" => Some(AgentRunStatus::Succeeded),
        "failed" => Some(AgentRunStatus::Failed),
        "cancelled_cleanly" => Some(AgentRunStatus::CancelledCleanly),
        "terminated" => Some(AgentRunStatus::Terminated),
        "interrupted" => Some(AgentRunStatus::Interrupted),
        "indeterminate" => Some(AgentRunStatus::Indeterminate),
        _ => None,
    }
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

fn conflict() -> PortError {
    PortError::failure(
        SafeErrorClassification::Conflict,
        Retryability::NonRetryable,
    )
}

fn not_found() -> PortError {
    PortError::failure(
        SafeErrorClassification::NotFound,
        Retryability::NonRetryable,
    )
}

fn internal_failure() -> PortError {
    PortError::failure(
        SafeErrorClassification::Internal,
        Retryability::NonRetryable,
    )
}
