use std::str::FromStr;

use local_agent_terminal_application::{
    plan_approval_payload, recover_deliberation, AgentSpecialistDispatchCommand,
    AgentSpecialistDispatchStore, ArtifactRootReader, CanonicalDeliberationFact,
    DeliberationArtifactRef, DeliberationPersistenceCommand, DeliberationRecord,
    DeliberationRecoveryInput, DeliberationSnapshot, DeliberationStore,
    DeliberationSynthesisCommand, DeliberationSynthesisStore, PortError, Retryability,
    SafeErrorClassification,
};
use local_agent_terminal_domain::{
    ArtifactId, Condition, OperationState, Phase, Sha256Digest, TaskId, TaskOutcomeMode,
    WorkflowProfile, WorkflowState, WorkflowStateSnapshot,
};
use rusqlite::{params, Connection, OptionalExtension, Transaction, TransactionBehavior};
use sha2::{Digest, Sha256};

use crate::agent_store::{
    load_deliberation_run_assignments, read_available_artifact, validate_available_artifact,
};
use crate::event_store::{append_in_transaction, open_error_to_port, sqlite_error_to_port};
use crate::SqliteStore;

type WorkflowAuthorityRow = (
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<i64>,
    Option<i64>,
    Option<i64>,
    Option<i64>,
    Option<String>,
    Option<String>,
);

impl DeliberationStore for SqliteStore {
    fn load(&self, task_id: &TaskId) -> Result<DeliberationSnapshot, PortError> {
        let artifact_reader = configured_artifact_reader(self)?;
        let mut connection = self.connection().map_err(open_error_to_port)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Deferred)
            .map_err(sqlite_error_to_port)?;
        let task_state = load_workflow_state(&transaction, task_id)?;
        let task_version = load_task_version(&transaction, task_id)?;
        let run_assignments =
            load_deliberation_run_assignments(&transaction, artifact_reader, task_id)?;
        let facts = load_facts(&transaction, artifact_reader, task_id)?;
        let snapshot = recover_deliberation(DeliberationRecoveryInput {
            task_id: task_id.clone(),
            task_version,
            task_state,
            run_assignments,
            facts,
        })?;
        transaction.commit().map_err(sqlite_error_to_port)?;
        Ok(snapshot)
    }

    fn persist(&self, command: DeliberationPersistenceCommand) -> Result<(), PortError> {
        command.validate()?;
        let artifact_reader = configured_artifact_reader(self)?;
        let mut connection = self.connection().map_err(open_error_to_port)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite_error_to_port)?;
        persist_command_in_transaction(&transaction, artifact_reader, &command)?;
        transaction.commit().map_err(sqlite_error_to_port)
    }
}

impl DeliberationSynthesisStore for SqliteStore {
    fn persist_synthesis(&self, command: DeliberationSynthesisCommand) -> Result<(), PortError> {
        command.validate()?;
        let artifact_reader = configured_artifact_reader(self)?;
        let mut connection = self.connection().map_err(open_error_to_port)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite_error_to_port)?;
        validate_synthesis_plan_artifact(&transaction, artifact_reader, &command)?;
        persist_command_in_transaction(&transaction, artifact_reader, command.persistence())?;
        persist_synthesis_plan(&transaction, &command)?;
        transaction.commit().map_err(sqlite_error_to_port)
    }
}

fn validate_synthesis_plan_artifact(
    connection: &Connection,
    artifact_reader: &dyn ArtifactRootReader,
    command: &DeliberationSynthesisCommand,
) -> Result<(), PortError> {
    let DeliberationRecord::DecisionDraft { plan_artifact, .. } = command.persistence().record()
    else {
        return Err(invalid_input());
    };
    let persisted = read_available_artifact(
        connection,
        artifact_reader,
        plan_artifact.artifact_id(),
        command.persistence().task_id(),
        Some(plan_artifact.content_digest().as_str()),
        Some(plan_artifact.size_bytes()),
    )?;
    let canonical =
        serde_json_canonicalizer::to_vec(command.plan()).map_err(|_| integrity_failure())?;
    if persisted == canonical {
        Ok(())
    } else {
        Err(integrity_failure())
    }
}

impl AgentSpecialistDispatchStore for SqliteStore {
    fn persist_specialist_dispatch(
        &self,
        command: AgentSpecialistDispatchCommand,
    ) -> Result<(), PortError> {
        command.validate()?;
        let artifact_reader = configured_artifact_reader(self)?;
        let mut connection = self.connection().map_err(open_error_to_port)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite_error_to_port)?;
        validate_available_artifact(
            &transaction,
            artifact_reader,
            command.context_package().artifact_id(),
            command.persistence().task_id(),
            Some(command.context_package().content_digest().as_str()),
            Some(command.context_package().size_bytes()),
        )?;
        persist_command_in_transaction(&transaction, artifact_reader, command.persistence())?;
        persist_specialist_dispatch(&transaction, &command)?;
        transaction.commit().map_err(sqlite_error_to_port)
    }

    fn specialist_dispatch_exists(
        &self,
        task_id: &TaskId,
        request_id: &str,
    ) -> Result<bool, PortError> {
        let connection = self.connection().map_err(open_error_to_port)?;
        connection
            .query_row(
                "SELECT EXISTS(
                    SELECT 1
                    FROM deliberation_specialist_dispatches dispatch
                    JOIN deliberation_specialist_threads thread
                      ON thread.thread_id = dispatch.thread_id
                    JOIN artifacts package
                      ON package.id = dispatch.context_package_artifact_id
                    WHERE dispatch.task_id = ?1 AND dispatch.request_id = ?2
                      AND dispatch.status = 'reserved'
                      AND thread.task_id = dispatch.task_id
                      AND thread.parent_run_id = dispatch.parent_run_id
                      AND thread.specialist_run_id = dispatch.specialist_run_id
                      AND thread.specialist_agent_id = dispatch.specialist_agent_id
                      AND thread.context_package_artifact_id = dispatch.context_package_artifact_id
                      AND package.availability = 'available'
                 )",
                params![task_id.as_str(), request_id],
                |row| row.get(0),
            )
            .map_err(sqlite_error_to_port)
    }
}

fn persist_specialist_dispatch(
    transaction: &Transaction<'_>,
    command: &AgentSpecialistDispatchCommand,
) -> Result<(), PortError> {
    let event = command
        .persistence()
        .append()
        .events
        .first()
        .ok_or_else(invalid_input)?;
    let DeliberationRecord::SpecialistRequest { request, .. } = command.persistence().record()
    else {
        return Err(invalid_input());
    };
    let assignment = command.assignment();
    let context_package_id = command.context_package().artifact_id().as_str();
    transaction
        .execute(
            "INSERT INTO deliberation_specialist_threads (
                thread_id, task_id, parent_run_id, specialist_run_id, specialist_agent_id,
                context_package_artifact_id, created_at
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
             ON CONFLICT DO NOTHING",
            params![
                command.thread_id(),
                command.persistence().task_id().as_str(),
                request.requesting_run().as_str(),
                assignment.run_id().as_str(),
                assignment.agent_id(),
                context_package_id,
                event.created_at,
            ],
        )
        .map_err(sqlite_error_to_port)?;
    let exact_thread: bool = transaction
        .query_row(
            "SELECT EXISTS(
                SELECT 1 FROM deliberation_specialist_threads
                WHERE thread_id = ?1 AND task_id = ?2 AND parent_run_id = ?3
                  AND specialist_run_id = ?4 AND specialist_agent_id = ?5
                  AND context_package_artifact_id = ?6 AND created_at = ?7
             )",
            params![
                command.thread_id(),
                command.persistence().task_id().as_str(),
                request.requesting_run().as_str(),
                assignment.run_id().as_str(),
                assignment.agent_id(),
                context_package_id,
                event.created_at,
            ],
            |row| row.get(0),
        )
        .map_err(sqlite_error_to_port)?;
    if !exact_thread {
        return Err(conflict());
    }
    transaction
        .execute(
            "INSERT INTO deliberation_specialist_dispatches (
                event_id, request_id, task_id, parent_run_id, specialist_run_id,
                specialist_agent_id, specialist_actor_id, family_key, thread_id,
                context_package_artifact_id, status, created_at
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, 'reserved', ?11)
             ON CONFLICT DO NOTHING",
            params![
                event.event_id.as_str(),
                request.request_id(),
                command.persistence().task_id().as_str(),
                request.requesting_run().as_str(),
                assignment.run_id().as_str(),
                assignment.agent_id(),
                assignment.actor_id().as_str(),
                assignment.family().as_str(),
                command.thread_id(),
                context_package_id,
                event.created_at,
            ],
        )
        .map_err(sqlite_error_to_port)?;
    let exact_dispatch: bool = transaction
        .query_row(
            "SELECT EXISTS(
                SELECT 1 FROM deliberation_specialist_dispatches
                WHERE event_id = ?1 AND request_id = ?2 AND task_id = ?3
                  AND parent_run_id = ?4 AND specialist_run_id = ?5
                  AND specialist_agent_id = ?6 AND specialist_actor_id = ?7
                  AND family_key = ?8 AND thread_id = ?9
                  AND context_package_artifact_id = ?10 AND status = 'reserved'
                  AND created_at = ?11
             )",
            params![
                event.event_id.as_str(),
                request.request_id(),
                command.persistence().task_id().as_str(),
                request.requesting_run().as_str(),
                assignment.run_id().as_str(),
                assignment.agent_id(),
                assignment.actor_id().as_str(),
                assignment.family().as_str(),
                command.thread_id(),
                context_package_id,
                event.created_at,
            ],
            |row| row.get(0),
        )
        .map_err(sqlite_error_to_port)?;
    if exact_dispatch {
        Ok(())
    } else {
        Err(conflict())
    }
}

fn persist_command_in_transaction(
    transaction: &Transaction<'_>,
    artifact_reader: &dyn ArtifactRootReader,
    command: &DeliberationPersistenceCommand,
) -> Result<(), PortError> {
    let event = command.append().events.first().ok_or_else(invalid_input)?;
    let sequence = command
        .expected_task_version()
        .checked_add(1)
        .ok_or_else(invalid_input)?;
    let fact = CanonicalDeliberationFact::issue(
        command.task_id().clone(),
        event.event_id.clone(),
        sequence,
        event.actor_id.clone(),
        command.record().clone(),
    )?;
    let canonical_json =
        String::from_utf8(fact.canonical_bytes().to_vec()).map_err(|_| integrity_failure())?;
    let primary_artifact = primary_artifact(command.record());
    validate_record_artifacts(
        transaction,
        artifact_reader,
        command.task_id(),
        command.record(),
    )?;
    if let Some(existing) = load_record_identity(transaction, event.event_id.as_str())? {
        let expected = RecordIdentity {
            task_id: command.task_id().as_str().to_owned(),
            sequence: i64::try_from(sequence).map_err(|_| invalid_input())?,
            record_type: event.event_type.as_str().to_owned(),
            primary_artifact_id: primary_artifact.artifact_id().as_str().to_owned(),
            canonical_json,
            canonical_digest: fact.content_digest().as_str().to_owned(),
            created_at: event.created_at.clone(),
        };
        if existing == expected && event_matches(transaction, command.task_id(), sequence, event)? {
            return Ok(());
        }
        return Err(conflict());
    }
    if event_exists(transaction, event.event_id.as_str())? {
        return Err(conflict());
    }
    append_in_transaction(transaction, command.append())?;
    transaction
        .execute(
            "INSERT INTO deliberation_records (
                event_id, task_id, sequence, record_type, primary_artifact_id,
                canonical_record_json, canonical_record_digest, created_at
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                event.event_id.as_str(),
                command.task_id().as_str(),
                i64::try_from(sequence).map_err(|_| invalid_input())?,
                event.event_type.as_str(),
                primary_artifact.artifact_id().as_str(),
                canonical_json,
                fact.content_digest().as_str(),
                event.created_at,
            ],
        )
        .map_err(sqlite_error_to_port)?;
    persist_record_projections(transaction, command.task_id(), command.record(), event)
}

fn persist_synthesis_plan(
    transaction: &Transaction<'_>,
    command: &DeliberationSynthesisCommand,
) -> Result<(), PortError> {
    let event = command
        .persistence()
        .append()
        .events
        .first()
        .ok_or_else(invalid_input)?;
    let plan_json = String::from_utf8(
        serde_json_canonicalizer::to_vec(command.plan()).map_err(|_| integrity_failure())?,
    )
    .map_err(|_| integrity_failure())?;
    let plan_digest = format!("sha256:{:x}", Sha256::digest(plan_json.as_bytes()));
    let existing: Option<(String, String, String)> = transaction
        .query_row(
            "SELECT task_id, plan_json, plan_digest
             FROM deliberation_synthesis_plans WHERE event_id = ?1",
            [event.event_id.as_str()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()
        .map_err(sqlite_error_to_port)?;
    let expected = (
        command.persistence().task_id().as_str().to_owned(),
        plan_json.clone(),
        plan_digest.clone(),
    );
    if let Some(existing) = existing {
        return if existing == expected {
            Ok(())
        } else {
            Err(conflict())
        };
    }
    transaction
        .execute(
            "INSERT INTO deliberation_synthesis_plans (
                event_id, task_id, plan_json, plan_digest, created_at
             ) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                event.event_id.as_str(),
                command.persistence().task_id().as_str(),
                plan_json,
                plan_digest,
                event.created_at,
            ],
        )
        .map_err(sqlite_error_to_port)?;
    Ok(())
}

#[derive(Debug, PartialEq, Eq)]
struct RecordIdentity {
    task_id: String,
    sequence: i64,
    record_type: String,
    primary_artifact_id: String,
    canonical_json: String,
    canonical_digest: String,
    created_at: String,
}

fn load_record_identity(
    connection: &Connection,
    event_id: &str,
) -> Result<Option<RecordIdentity>, PortError> {
    connection
        .query_row(
            "SELECT task_id, sequence, record_type, primary_artifact_id,
                    canonical_record_json, canonical_record_digest, created_at
             FROM deliberation_records WHERE event_id = ?1",
            [event_id],
            |row| {
                Ok(RecordIdentity {
                    task_id: row.get(0)?,
                    sequence: row.get(1)?,
                    record_type: row.get(2)?,
                    primary_artifact_id: row.get(3)?,
                    canonical_json: row.get(4)?,
                    canonical_digest: row.get(5)?,
                    created_at: row.get(6)?,
                })
            },
        )
        .optional()
        .map_err(sqlite_error_to_port)
}

fn event_exists(connection: &Connection, event_id: &str) -> Result<bool, PortError> {
    connection
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM events WHERE event_id = ?1)",
            [event_id],
            |row| row.get(0),
        )
        .map_err(sqlite_error_to_port)
}

fn event_matches(
    connection: &Connection,
    task_id: &TaskId,
    sequence: u64,
    event: &local_agent_terminal_application::NewEvent,
) -> Result<bool, PortError> {
    connection
        .query_row(
            "SELECT EXISTS(
                SELECT 1 FROM events
                WHERE event_id = ?1 AND stream_id = ?2 AND sequence = ?3 AND event_type = ?4
                  AND schema_version = ?5 AND actor_type = ?6 AND actor_id = ?7
                  AND observation_class = ?8 AND payload_json = ?9 AND metadata_json = ?10
                  AND causation_id IS ?11 AND correlation_id = ?12 AND created_at = ?13
             )",
            params![
                event.event_id.as_str(),
                task_id.as_str(),
                i64::try_from(sequence).map_err(|_| invalid_input())?,
                event.event_type.as_str(),
                event.schema_version,
                event.actor_type,
                event.actor_id.as_str(),
                event.observation_class,
                event.payload.to_string(),
                event.metadata.to_string(),
                event.causation_id,
                event.correlation_id,
                event.created_at,
            ],
            |row| row.get(0),
        )
        .map_err(sqlite_error_to_port)
}

fn persist_record_projections(
    transaction: &Transaction<'_>,
    task_id: &TaskId,
    record: &DeliberationRecord,
    event: &local_agent_terminal_application::NewEvent,
) -> Result<(), PortError> {
    match record {
        DeliberationRecord::QuorumPublication { proposals, .. } => {
            for proposal in proposals {
                let message_id = format!(
                    "deliberation-proposal:{}:{}",
                    task_id.as_str(),
                    proposal.artifact_id().as_str()
                );
                let thread_id = format!("deliberation:{}", task_id.as_str());
                transaction
                    .execute(
                        "INSERT INTO messages (
                            id, task_id, run_id, thread_id, message_type, reply_to,
                            content_artifact_id, status, core_received_at, superseded_by
                         ) VALUES (?1, ?2, ?3, ?4, 'proposal', NULL, ?5,
                            'accepted', ?6, NULL)",
                        params![
                            message_id,
                            task_id.as_str(),
                            proposal.run_id().as_str(),
                            thread_id,
                            proposal.artifact_id().as_str(),
                            event.created_at,
                        ],
                    )
                    .map_err(sqlite_error_to_port)?;
            }
            Ok(())
        }
        DeliberationRecord::ObjectionRoundClosed { plan_approval, .. } => {
            persist_plan_approval_request(transaction, plan_approval)
        }
        _ => Ok(()),
    }
}

fn persist_plan_approval_request(
    transaction: &Transaction<'_>,
    approval: &local_agent_terminal_application::NewPlanApproval,
) -> Result<(), PortError> {
    approval.validate()?;
    let payload = plan_approval_payload(approval.binding())?;
    let operation_intent_id = format!(
        "plan-approval-intent:{}:{}",
        approval.task_id().as_str(),
        approval.operation_digest().as_str(),
    );
    let idempotency_key = format!(
        "plan-approval:{}:{}",
        approval.task_id().as_str(),
        approval.operation_digest().as_str(),
    );
    let actor_binding_digest = approval.authority_binding().content_digest().as_str();
    transaction
        .execute(
            "INSERT OR IGNORE INTO operation_intents (
                id, task_id, run_id, operation_kind, idempotency_class, idempotency_key,
                canonical_request_artifact_id, operation_digest, actor_binding_digest,
                status, current_attempt_no, created_at, updated_at
             ) VALUES (?1, ?2, NULL, 'plan.approve', 'non_repeatable', ?3, ?4, ?5,
                ?6, 'pending', 0, ?7, ?7)",
            params![
                operation_intent_id,
                approval.task_id().as_str(),
                idempotency_key,
                approval.request_artifact().artifact_id.as_str(),
                approval.operation_digest().as_str(),
                actor_binding_digest,
                approval.binding().requested_at,
            ],
        )
        .map_err(sqlite_error_to_port)?;
    let exact_intent: bool = transaction
        .query_row(
            "SELECT EXISTS(
                SELECT 1 FROM operation_intents
                WHERE id = ?1 AND task_id = ?2 AND run_id IS NULL
                  AND operation_kind = 'plan.approve'
                  AND idempotency_class = 'non_repeatable' AND idempotency_key = ?3
                  AND canonical_request_artifact_id = ?4 AND operation_digest = ?5
                  AND actor_binding_digest = ?6 AND status = 'pending'
                  AND current_attempt_no = 0 AND created_at = ?7 AND updated_at = ?7
             )",
            params![
                operation_intent_id,
                approval.task_id().as_str(),
                idempotency_key,
                approval.request_artifact().artifact_id.as_str(),
                approval.operation_digest().as_str(),
                actor_binding_digest,
                approval.binding().requested_at,
            ],
            |row| row.get(0),
        )
        .map_err(sqlite_error_to_port)?;
    if !exact_intent {
        return Err(conflict());
    }
    transaction
        .execute(
            "INSERT OR IGNORE INTO approvals (
                id, task_id, operation_intent_id, approval_type, schema_version,
                operation_digest, actor_binding_digest, nonce, status, requested_at,
                resolved_at, expires_at, request_artifact_id, invalidation_reason
             ) VALUES (?1, ?2, ?3, 'plan', 'approval-digest.v1', ?4, ?5, ?6,
                'pending', ?7, NULL, ?8, ?9, NULL)",
            params![
                approval.approval_id().as_str(),
                approval.task_id().as_str(),
                operation_intent_id,
                approval.operation_digest().as_str(),
                actor_binding_digest,
                payload.nonce,
                approval.binding().requested_at,
                approval.binding().expires_at,
                approval.request_artifact().artifact_id.as_str(),
            ],
        )
        .map_err(sqlite_error_to_port)?;
    let exact: bool = transaction
        .query_row(
            "SELECT EXISTS(
                SELECT 1 FROM approvals
                WHERE id = ?1 AND task_id = ?2 AND approval_type = 'plan'
                  AND operation_intent_id = ?3 AND schema_version = 'approval-digest.v1'
                  AND operation_digest = ?4 AND actor_binding_digest = ?5 AND nonce = ?6
                  AND status = 'pending' AND requested_at = ?7 AND resolved_at IS NULL
                  AND expires_at = ?8 AND request_artifact_id = ?9
                  AND invalidation_reason IS NULL
             )",
            params![
                approval.approval_id().as_str(),
                approval.task_id().as_str(),
                operation_intent_id,
                approval.operation_digest().as_str(),
                actor_binding_digest,
                payload.nonce,
                approval.binding().requested_at,
                approval.binding().expires_at,
                approval.request_artifact().artifact_id.as_str(),
            ],
            |row| row.get(0),
        )
        .map_err(sqlite_error_to_port)?;
    if exact {
        Ok(())
    } else {
        Err(conflict())
    }
}

fn load_facts(
    connection: &Connection,
    artifact_reader: &dyn ArtifactRootReader,
    task_id: &TaskId,
) -> Result<Vec<CanonicalDeliberationFact>, PortError> {
    let mut statement = connection
        .prepare(
            "SELECT r.event_id, r.sequence, r.record_type, r.primary_artifact_id,
                    r.canonical_record_json, r.canonical_record_digest,
                    e.stream_id, e.sequence, e.event_type, e.actor_type, e.actor_id,
                    e.observation_class, e.payload_json
             FROM deliberation_records r
             JOIN events e ON e.event_id = r.event_id
             WHERE r.task_id = ?1 ORDER BY r.sequence",
        )
        .map_err(sqlite_error_to_port)?;
    let rows = statement
        .query_map([task_id.as_str()], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, String>(5)?,
                row.get::<_, String>(6)?,
                row.get::<_, i64>(7)?,
                row.get::<_, String>(8)?,
                row.get::<_, String>(9)?,
                row.get::<_, String>(10)?,
                row.get::<_, String>(11)?,
                row.get::<_, String>(12)?,
            ))
        })
        .map_err(sqlite_error_to_port)?;
    let mut facts = Vec::new();
    for row in rows {
        let (
            event_id,
            sequence,
            record_type,
            primary_artifact_id,
            canonical_json,
            canonical_digest,
            stream_id,
            event_sequence,
            event_type,
            actor_type,
            actor_id,
            observation_class,
            event_payload,
        ) = row.map_err(sqlite_error_to_port)?;
        let fact = CanonicalDeliberationFact::rehydrate(
            canonical_json.into_bytes(),
            Sha256Digest::new(canonical_digest.clone()).map_err(|_| integrity_failure())?,
        )?;
        let envelope: serde_json::Value =
            serde_json::from_slice(fact.canonical_bytes()).map_err(|_| integrity_failure())?;
        let event_payload: serde_json::Value =
            serde_json::from_str(&event_payload).map_err(|_| integrity_failure())?;
        if fact.task_id() != task_id
            || fact.event_id().as_str() != event_id
            || i64::try_from(fact.event_sequence()).ok() != Some(sequence)
            || stream_id != task_id.as_str()
            || event_sequence != sequence
            || envelope
                .get("eventType")
                .and_then(serde_json::Value::as_str)
                != Some(record_type.as_str())
            || record_type != event_type
            || fact.actor_type() != actor_type
            || fact.actor_id().as_str() != actor_id
            || fact.observation_class() != observation_class
            || event_payload
                .get("canonicalRecordDigest")
                .and_then(serde_json::Value::as_str)
                != Some(canonical_digest.as_str())
            || primary_artifact(fact.record()).artifact_id().as_str() != primary_artifact_id
        {
            return Err(integrity_failure());
        }
        validate_record_artifacts(connection, artifact_reader, task_id, fact.record())?;
        facts.push(fact);
    }
    Ok(facts)
}

fn load_task_version(connection: &Connection, task_id: &TaskId) -> Result<u64, PortError> {
    let version: i64 = connection
        .query_row(
            "SELECT current_sequence FROM tasks WHERE id = ?1",
            [task_id.as_str()],
            |row| row.get(0),
        )
        .map_err(sqlite_error_to_port)?;
    u64::try_from(version).map_err(|_| integrity_failure())
}

pub(crate) fn load_workflow_state(
    connection: &Connection,
    task_id: &TaskId,
) -> Result<WorkflowState, PortError> {
    let raw: Option<WorkflowAuthorityRow> = connection
        .query_row(
            "SELECT tasks.phase, tasks.condition, tasks.operation_state,
                    authority.phase, authority.workflow_profile, authority.outcome_mode,
                    authority.stream_version, authority.profile_revision,
                    tasks.workspace_version, tasks.fencing_epoch,
                    authority.last_transition_event_id, authority.last_profile_revision_id
             FROM tasks
             JOIN task_workflow_authority AS authority ON authority.task_id = tasks.id
             WHERE tasks.id = ?1",
            [task_id.as_str()],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    row.get(6)?,
                    row.get(7)?,
                    row.get(8)?,
                    row.get(9)?,
                    row.get(10)?,
                    row.get(11)?,
                ))
            },
        )
        .optional()
        .map_err(sqlite_error_to_port)?;
    let Some((
        task_phase,
        condition,
        operation,
        authority_phase,
        workflow_profile,
        outcome_mode,
        stream_version,
        profile_revision,
        workspace_version,
        fencing_epoch,
        last_transition_event_id,
        last_profile_revision_id,
    )) = raw
    else {
        let task_exists: bool = connection
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM tasks WHERE id = ?1)",
                [task_id.as_str()],
                |row| row.get(0),
            )
            .map_err(sqlite_error_to_port)?;
        return Err(if task_exists {
            integrity_failure()
        } else {
            not_found()
        });
    };
    let (
        Some(task_phase),
        Some(condition),
        Some(operation),
        Some(authority_phase),
        Some(workflow_profile),
        Some(outcome_mode),
        Some(stream_version),
        Some(profile_revision),
        Some(workspace_version),
        Some(fencing_epoch),
    ) = (
        task_phase,
        condition,
        operation,
        authority_phase,
        workflow_profile,
        outcome_mode,
        stream_version,
        profile_revision,
        workspace_version,
        fencing_epoch,
    )
    else {
        return Err(integrity_failure());
    };
    if task_phase != authority_phase
        || last_transition_event_id
            .as_deref()
            .is_some_and(str::is_empty)
        || last_profile_revision_id
            .as_deref()
            .is_some_and(str::is_empty)
    {
        return Err(integrity_failure());
    }
    let profile_revision = u64::try_from(profile_revision).map_err(|_| integrity_failure())?;
    if profile_revision == 0
        || (profile_revision == 1 && last_profile_revision_id.is_some())
        || (profile_revision > 1 && last_profile_revision_id.is_none())
    {
        return Err(integrity_failure());
    }
    let snapshot = WorkflowStateSnapshot {
        phase: Phase::from_str(&authority_phase).map_err(|_| integrity_failure())?,
        condition: Condition::from_str(&condition).map_err(|_| integrity_failure())?,
        operation: OperationState::from_str(&operation).map_err(|_| integrity_failure())?,
        workflow_profile: WorkflowProfile::from_str(&workflow_profile)
            .map_err(|_| integrity_failure())?,
        outcome_mode: TaskOutcomeMode::from_str(&outcome_mode).map_err(|_| integrity_failure())?,
        stream_version: u64::try_from(stream_version).map_err(|_| integrity_failure())?,
        profile_revision,
        workspace_version: u64::try_from(workspace_version).map_err(|_| integrity_failure())?,
        fencing_epoch: u64::try_from(fencing_epoch).map_err(|_| integrity_failure())?,
        last_transition_event_id,
        last_profile_revision_id,
    };
    validate_workflow_authority_references(connection, task_id, &snapshot)?;
    WorkflowState::rehydrate(snapshot).map_err(|_| integrity_failure())
}

fn validate_workflow_authority_references(
    connection: &Connection,
    task_id: &TaskId,
    snapshot: &WorkflowStateSnapshot,
) -> Result<(), PortError> {
    if snapshot.phase != Phase::Intake && snapshot.last_transition_event_id.is_none() {
        return Err(integrity_failure());
    }
    let transition = if let Some(transition_event_id) = &snapshot.last_transition_event_id {
        let transition: Option<(String, i64)> = connection
            .query_row(
                "SELECT workflow_profile, expected_stream_version
                 FROM workflow_transition_events
                 WHERE id = ?1
                   AND task_id = ?2
                   AND status = 'accepted'
                   AND to_phase = ?3
                   AND outcome_mode = ?4",
                params![
                    transition_event_id,
                    task_id.as_str(),
                    snapshot.phase.as_str(),
                    snapshot.outcome_mode.as_str(),
                ],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(sqlite_error_to_port)?;
        let Some((workflow_profile, expected_stream_version)) = transition else {
            return Err(integrity_failure());
        };
        Some((
            WorkflowProfile::from_str(&workflow_profile).map_err(|_| integrity_failure())?,
            u64::try_from(expected_stream_version).map_err(|_| integrity_failure())?,
        ))
    } else {
        None
    };
    let profile_revision = if let Some(profile_revision_id) = &snapshot.last_profile_revision_id {
        let profile_revision =
            i64::try_from(snapshot.profile_revision).map_err(|_| integrity_failure())?;
        let revision: Option<(String, i64)> = connection
            .query_row(
                "SELECT from_profile, expected_stream_version
                 FROM workflow_profile_revisions
                 WHERE id = ?1
                   AND task_id = ?2
                   AND revision_no = ?3
                   AND to_profile = ?4",
                params![
                    profile_revision_id,
                    task_id.as_str(),
                    profile_revision,
                    snapshot.workflow_profile.as_str(),
                ],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(sqlite_error_to_port)?;
        let Some((from_profile, expected_stream_version)) = revision else {
            return Err(integrity_failure());
        };
        Some((
            WorkflowProfile::from_str(&from_profile).map_err(|_| integrity_failure())?,
            u64::try_from(expected_stream_version).map_err(|_| integrity_failure())?,
        ))
    } else {
        None
    };
    validate_causal_authority_bindings(connection, task_id, snapshot, transition, profile_revision)
}

fn validate_causal_authority_bindings(
    connection: &Connection,
    task_id: &TaskId,
    snapshot: &WorkflowStateSnapshot,
    transition: Option<(WorkflowProfile, u64)>,
    profile_revision: Option<(WorkflowProfile, u64)>,
) -> Result<(), PortError> {
    if snapshot.stream_version == 0 && transition.is_none() && profile_revision.is_none() {
        return Ok(());
    }
    let latest_version = snapshot
        .stream_version
        .checked_sub(1)
        .ok_or_else(integrity_failure)?;
    if let Some((_, revision_version)) = &profile_revision {
        validate_causal_authority_stream(connection, task_id, *revision_version, latest_version)?;
    }
    match (transition, profile_revision) {
        (Some((transition_profile, transition_version)), None)
            if transition_version == latest_version
                && transition_profile == snapshot.workflow_profile =>
        {
            Ok(())
        }
        (None, Some((_, revision_version))) if revision_version == latest_version => Ok(()),
        (
            Some((transition_profile, transition_version)),
            Some((_revision_from_profile, revision_version)),
        ) if transition_version == latest_version
            && transition_version > revision_version
            && transition_profile == snapshot.workflow_profile =>
        {
            Ok(())
        }
        (
            Some((transition_profile, transition_version)),
            Some((revision_from_profile, revision_version)),
        ) if revision_version == latest_version
            && revision_version > transition_version
            && transition_profile == revision_from_profile =>
        {
            Ok(())
        }
        _ => Err(integrity_failure()),
    }
}

fn validate_causal_authority_stream(
    connection: &Connection,
    task_id: &TaskId,
    start_version: u64,
    latest_version: u64,
) -> Result<(), PortError> {
    if start_version > latest_version {
        return Err(integrity_failure());
    }
    let start_version = i64::try_from(start_version).map_err(|_| integrity_failure())?;
    let latest_version = i64::try_from(latest_version).map_err(|_| integrity_failure())?;
    let mut statement = connection
        .prepare(
            "SELECT expected_stream_version
             FROM workflow_transition_events
             WHERE task_id = ?1
               AND status = 'accepted'
               AND expected_stream_version BETWEEN ?2 AND ?3
             UNION ALL
             SELECT expected_stream_version
             FROM workflow_profile_revisions
             WHERE task_id = ?1
               AND expected_stream_version BETWEEN ?2 AND ?3
             ORDER BY expected_stream_version",
        )
        .map_err(sqlite_error_to_port)?;
    let versions = statement
        .query_map(
            params![task_id.as_str(), start_version, latest_version],
            |row| row.get::<_, i64>(0),
        )
        .map_err(sqlite_error_to_port)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(sqlite_error_to_port)?;
    let expected_count = latest_version
        .checked_sub(start_version)
        .and_then(|span| span.checked_add(1))
        .ok_or_else(integrity_failure)?;
    if i64::try_from(versions.len()).map_err(|_| integrity_failure())? != expected_count {
        return Err(integrity_failure());
    }
    for (offset, version) in versions.into_iter().enumerate() {
        let offset = i64::try_from(offset).map_err(|_| integrity_failure())?;
        if version
            != start_version
                .checked_add(offset)
                .ok_or_else(integrity_failure)?
        {
            return Err(integrity_failure());
        }
    }
    Ok(())
}

fn validate_record_artifacts(
    connection: &Connection,
    artifact_reader: &dyn ArtifactRootReader,
    task_id: &TaskId,
    record: &DeliberationRecord,
) -> Result<(), PortError> {
    for reference in record_artifacts(record) {
        validate_available_artifact(
            connection,
            artifact_reader,
            reference.artifact_id(),
            task_id,
            Some(reference.content_digest().as_str()),
            Some(reference.size_bytes()),
        )?;
    }
    match record {
        DeliberationRecord::PrivateProposal { proposal, .. } => {
            validate_artifact_id(connection, artifact_reader, task_id, proposal.artifact_id())?;
        }
        DeliberationRecord::QuorumPublication {
            proposals,
            review_plan,
            ..
        } => {
            for proposal in proposals {
                validate_artifact_id(connection, artifact_reader, task_id, proposal.artifact_id())?;
            }
            for edge in review_plan.edges() {
                validate_artifact_id(connection, artifact_reader, task_id, edge.target_proposal())?;
            }
        }
        DeliberationRecord::SpecialistRequest { request, .. } => {
            for artifact_id in request.required_context() {
                validate_artifact_id(connection, artifact_reader, task_id, artifact_id)?;
            }
        }
        DeliberationRecord::ObjectionRoundClosed { plan_approval, .. } => {
            let artifact = plan_approval.request_artifact();
            let bytes = read_available_artifact(
                connection,
                artifact_reader,
                &artifact.artifact_id,
                task_id,
                Some(artifact.content_digest.as_str()),
                Some(artifact.size_bytes),
            )?;
            if bytes != plan_approval.canonical_bytes() {
                return Err(integrity_failure());
            }
        }
        _ => {}
    }
    Ok(())
}

fn validate_artifact_id(
    connection: &Connection,
    artifact_reader: &dyn ArtifactRootReader,
    task_id: &TaskId,
    artifact_id: &ArtifactId,
) -> Result<(), PortError> {
    validate_available_artifact(
        connection,
        artifact_reader,
        artifact_id,
        task_id,
        None,
        None,
    )
}

fn configured_artifact_reader(store: &SqliteStore) -> Result<&dyn ArtifactRootReader, PortError> {
    store.artifact_reader().ok_or_else(unavailable)
}

fn record_artifacts(record: &DeliberationRecord) -> Vec<&DeliberationArtifactRef> {
    match record {
        DeliberationRecord::PrivateProposal {
            proposal_artifact,
            receipt,
            ..
        } => vec![proposal_artifact, receipt],
        DeliberationRecord::QuorumPublication {
            proposal_artifact,
            review_artifact,
            ..
        } => vec![proposal_artifact, review_artifact],
        DeliberationRecord::ReviewEdges { artifact, .. }
        | DeliberationRecord::ThreadSummary { artifact, .. }
        | DeliberationRecord::SpecialistRequest { artifact, .. }
        | DeliberationRecord::ClaimSet { artifact, .. }
        | DeliberationRecord::VerificationSet { artifact, .. }
        | DeliberationRecord::ObjectionSet { artifact, .. }
        | DeliberationRecord::ObjectionRoundClosed { artifact, .. } => vec![artifact],
        DeliberationRecord::DecisionDraft {
            artifact,
            plan_artifact,
            ..
        } => vec![artifact, plan_artifact],
        DeliberationRecord::ObjectionSevereAccepted {
            objection_artifact,
            review_artifact,
            ..
        } => vec![objection_artifact, review_artifact],
        DeliberationRecord::Supersession {
            superseded,
            replacement,
        } => vec![superseded, replacement],
    }
}

fn primary_artifact(record: &DeliberationRecord) -> &DeliberationArtifactRef {
    match record {
        DeliberationRecord::PrivateProposal { receipt, .. } => receipt,
        DeliberationRecord::QuorumPublication {
            proposal_artifact, ..
        } => proposal_artifact,
        DeliberationRecord::ReviewEdges { artifact, .. }
        | DeliberationRecord::ThreadSummary { artifact, .. }
        | DeliberationRecord::SpecialistRequest { artifact, .. }
        | DeliberationRecord::ClaimSet { artifact, .. }
        | DeliberationRecord::VerificationSet { artifact, .. }
        | DeliberationRecord::DecisionDraft { artifact, .. }
        | DeliberationRecord::ObjectionSet { artifact, .. }
        | DeliberationRecord::ObjectionRoundClosed { artifact, .. } => artifact,
        DeliberationRecord::ObjectionSevereAccepted {
            review_artifact, ..
        } => review_artifact,
        DeliberationRecord::Supersession { replacement, .. } => replacement,
    }
}

fn conflict() -> PortError {
    PortError::failure(
        SafeErrorClassification::Conflict,
        Retryability::NonRetryable,
    )
}

fn integrity_failure() -> PortError {
    PortError::failure(
        SafeErrorClassification::IntegrityFailure,
        Retryability::NonRetryable,
    )
}

fn invalid_input() -> PortError {
    PortError::failure(
        SafeErrorClassification::InvalidInput,
        Retryability::NonRetryable,
    )
}

fn unavailable() -> PortError {
    PortError::failure(
        SafeErrorClassification::Unavailable,
        Retryability::Retryable,
    )
}

fn not_found() -> PortError {
    PortError::failure(
        SafeErrorClassification::NotFound,
        Retryability::NonRetryable,
    )
}
