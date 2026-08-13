use std::collections::BTreeSet;
use std::path::Path;

use local_agent_terminal_application::{
    prepare_assurance_acceptance_artifact, ArtifactRef, AssuranceStore, PortError,
    ProfileEscalationCommand, Retryability, SafeErrorClassification,
};
use local_agent_terminal_domain::{
    AssuranceDecision, AssuranceDegradationReceipt, AssuranceReasonCode, TaskId, WorkflowState,
};
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use sha2::{Digest, Sha256};

use crate::deliberation_store::load_workflow_state;
use crate::event_store::{open_error_to_port, sqlite_error_to_port};
use crate::SqliteStore;

struct ProfileRevisionRow {
    task_id: String,
    revision_no: i64,
    expected_stream_version: i64,
    from_profile: String,
    to_profile: String,
    reason_artifact_id: String,
    policy_digest: String,
    decided_by_kind: String,
    actor_binding_id: Option<String>,
    created_at: String,
    receipt_digest: String,
}

struct DegradationReceiptRow {
    task_id: String,
    requested_profile: String,
    reason_code: String,
    run_set_digest: String,
    decision: String,
    actor_binding_id: Option<String>,
    receipt_artifact_id: String,
    created_at: String,
    receipt_digest: String,
}

impl AssuranceStore for SqliteStore {
    fn persist_profile_escalation(
        &self,
        command: &ProfileEscalationCommand,
    ) -> Result<WorkflowState, PortError> {
        command.validate()?;
        let receipt_digest = command.receipt_digest()?;
        let created_at = command.created_at_rfc3339()?;
        let mut connection = self.connection().map_err(open_error_to_port)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite_error_to_port)?;

        if let Some(revision_no) =
            exact_profile_revision(&transaction, command, &created_at, receipt_digest.as_str())?
        {
            let state = load_workflow_state(&transaction, &command.task_id)?;
            if profile_contains(state.workflow_profile(), command.to_profile)
                && state.stream_version()
                    >= command
                        .expected_stream_version
                        .checked_add(1)
                        .ok_or_else(invalid_input)?
                && state.profile_revision() >= revision_no
            {
                transaction.commit().map_err(authority_sql_error)?;
                return Ok(state);
            }
            return Err(integrity_failure());
        }

        let state = load_workflow_state(&transaction, &command.task_id)?;
        if state.workflow_profile() != command.from_profile
            || state.stream_version() != command.expected_stream_version
        {
            return Err(conflict());
        }
        verify_task_artifact(
            &transaction,
            configured_artifact_reader(self)?,
            &command.task_id,
            command.reason_artifact_id.as_str(),
        )?;
        if let Some(actor_binding_id) = command.actor_binding_id.as_deref() {
            verify_current_actor_binding(
                &transaction,
                actor_binding_id,
                command.created_at_rfc3339()?.as_str(),
            )?;
        }
        let revision_no = state
            .profile_revision()
            .checked_add(1)
            .ok_or_else(invalid_input)?;
        transaction
            .execute(
                "INSERT INTO workflow_profile_revisions (
                    id, task_id, revision_no, expected_stream_version, from_profile,
                    to_profile, reason_artifact_id, policy_digest, decided_by_kind,
                    actor_binding_id, created_at, receipt_digest
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
                params![
                    command.revision_id,
                    command.task_id.as_str(),
                    i64::try_from(revision_no).map_err(|_| invalid_input())?,
                    i64::try_from(command.expected_stream_version).map_err(|_| invalid_input())?,
                    command.from_profile.as_str(),
                    command.to_profile.as_str(),
                    command.reason_artifact_id.as_str(),
                    command.policy_digest.as_str(),
                    decided_by_kind(command),
                    command.actor_binding_id,
                    created_at,
                    receipt_digest.as_str(),
                ],
            )
            .map_err(authority_sql_error)?;
        let changed = transaction
            .execute(
                "UPDATE task_workflow_authority
                 SET workflow_profile=?1, stream_version=stream_version+1,
                     profile_revision=profile_revision+1, last_profile_revision_id=?2,
                     updated_at=?3
                 WHERE task_id=?4 AND workflow_profile=?5 AND stream_version=?6
                   AND profile_revision=?7",
                params![
                    command.to_profile.as_str(),
                    command.revision_id,
                    created_at,
                    command.task_id.as_str(),
                    command.from_profile.as_str(),
                    i64::try_from(command.expected_stream_version).map_err(|_| invalid_input())?,
                    i64::try_from(state.profile_revision()).map_err(|_| invalid_input())?,
                ],
            )
            .map_err(authority_sql_error)?;
        if changed != 1 {
            return Err(conflict());
        }
        let updated = load_workflow_state(&transaction, &command.task_id)?;
        transaction.commit().map_err(authority_sql_error)?;
        Ok(updated)
    }

    fn persist_degradation(
        &self,
        receipt: &AssuranceDegradationReceipt,
        artifact: &ArtifactRef,
    ) -> Result<(), PortError> {
        let reader = configured_artifact_reader(self)?;
        let mut connection = self.connection().map_err(open_error_to_port)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite_error_to_port)?;

        let receipt_artifact_id = resolve_receipt_artifact(
            &transaction,
            reader,
            receipt.task_id(),
            artifact,
            receipt.canonical_bytes(),
        )?;
        if let Some(exact) = exact_degradation_receipt(&transaction, receipt, &receipt_artifact_id)?
        {
            return if exact {
                transaction.commit().map_err(degradation_sql_error)
            } else {
                Err(conflict())
            };
        }
        let state = load_workflow_state(&transaction, receipt.task_id())?;
        if state.workflow_profile() != receipt.requested_profile() {
            return Err(conflict());
        }
        verify_assurance_claim(&transaction, receipt)?;
        if let Some(actor_binding_id) = receipt.actor_binding_id() {
            verify_current_actor_binding(
                &transaction,
                actor_binding_id,
                receipt.created_at_rfc3339(),
            )?;
        }
        if matches!(receipt.decision(), AssuranceDecision::ContinueDegraded) {
            let acceptance_artifact = receipt
                .acceptance_artifact_ref()
                .ok_or_else(integrity_failure)?;
            verify_acceptance_artifact(&transaction, reader, receipt, acceptance_artifact)?;
        }

        transaction
            .execute(
                "INSERT INTO assurance_degradation_receipts (
                    id, task_id, requested_profile, reason_code, run_set_digest,
                    decision, actor_binding_id, receipt_artifact_id, created_at,
                    receipt_digest
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
                params![
                    receipt.receipt_id(),
                    receipt.task_id().as_str(),
                    receipt.requested_profile().as_str(),
                    receipt.reason_code().as_str(),
                    receipt.observed().run_set_digest.as_str(),
                    receipt.decision().as_str(),
                    receipt.actor_binding_id(),
                    receipt_artifact_id,
                    receipt.created_at_rfc3339(),
                    receipt.receipt_digest().as_str(),
                ],
            )
            .map_err(degradation_sql_error)?;
        transaction.commit().map_err(degradation_sql_error)
    }
}

fn exact_profile_revision(
    connection: &Connection,
    command: &ProfileEscalationCommand,
    created_at: &str,
    receipt_digest: &str,
) -> Result<Option<u64>, PortError> {
    let raw: Option<ProfileRevisionRow> = connection
        .query_row(
            "SELECT task_id, revision_no, expected_stream_version, from_profile,
                    to_profile, reason_artifact_id, policy_digest, decided_by_kind,
                    actor_binding_id, created_at, receipt_digest
             FROM workflow_profile_revisions WHERE id=?1",
            [command.revision_id.as_str()],
            |row| {
                Ok(ProfileRevisionRow {
                    task_id: row.get(0)?,
                    revision_no: row.get(1)?,
                    expected_stream_version: row.get(2)?,
                    from_profile: row.get(3)?,
                    to_profile: row.get(4)?,
                    reason_artifact_id: row.get(5)?,
                    policy_digest: row.get(6)?,
                    decided_by_kind: row.get(7)?,
                    actor_binding_id: row.get(8)?,
                    created_at: row.get(9)?,
                    receipt_digest: row.get(10)?,
                })
            },
        )
        .optional()
        .map_err(sqlite_error_to_port)?;
    let Some(raw) = raw else {
        return Ok(None);
    };
    let exact = raw.task_id == command.task_id.as_str()
        && u64::try_from(raw.expected_stream_version).ok() == Some(command.expected_stream_version)
        && raw.from_profile == command.from_profile.as_str()
        && raw.to_profile == command.to_profile.as_str()
        && raw.reason_artifact_id == command.reason_artifact_id.as_str()
        && raw.policy_digest == command.policy_digest.as_str()
        && raw.decided_by_kind == decided_by_kind(command)
        && raw.actor_binding_id.as_deref() == command.actor_binding_id.as_deref()
        && raw.created_at == created_at
        && raw.receipt_digest == receipt_digest;
    if !exact {
        return Err(conflict());
    }
    u64::try_from(raw.revision_no)
        .map(Some)
        .map_err(|_| integrity_failure())
}

fn verify_assurance_claim(
    connection: &Connection,
    receipt: &AssuranceDegradationReceipt,
) -> Result<(), PortError> {
    let mut groups = BTreeSet::new();
    let mut executor_runs = BTreeSet::new();
    let mut reviewer_runs = BTreeSet::new();
    for run_id in &receipt.observed().run_refs {
        let run: Option<(String, String)> = connection
            .query_row(
                "SELECT b.independence_group, r.role
                 FROM agent_runs r
                 JOIN run_configuration_bindings b ON b.run_id=r.id
                 WHERE r.id=?1 AND r.task_id=?2",
                params![run_id.as_str(), receipt.task_id().as_str()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(sqlite_error_to_port)?;
        let (group, role) = run.ok_or_else(conflict)?;
        groups.insert(group);
        match role.as_str() {
            "executor" | "implementer" => {
                executor_runs.insert(run_id.as_str());
            }
            "reviewer" => {
                reviewer_runs.insert(run_id.as_str());
            }
            _ => {}
        }
    }
    if u8::try_from(groups.len()).ok() != Some(receipt.observed().distinct_independence_groups) {
        return Err(integrity_failure());
    }
    let role_separation_satisfied = executor_runs
        .iter()
        .any(|executor| reviewer_runs.iter().any(|reviewer| executor != reviewer));
    if role_separation_satisfied != receipt.observed().role_separation_satisfied {
        return Err(integrity_failure());
    }
    let supported = match receipt.reason_code() {
        AssuranceReasonCode::InsufficientIndependenceGroups => {
            receipt.observed().distinct_independence_groups
                < receipt.requirements().minimum_distinct_independence_groups
        }
        AssuranceReasonCode::RoleSeparationUnavailable => {
            receipt.requirements().executor_reviewer_separation_required
                && !receipt.observed().role_separation_satisfied
        }
        AssuranceReasonCode::ProviderUnavailable | AssuranceReasonCode::BudgetInsufficient => true,
    };
    if supported {
        Ok(())
    } else {
        Err(integrity_failure())
    }
}

fn verify_current_actor_binding(
    connection: &Connection,
    actor_binding_id: &str,
    created_at: &str,
) -> Result<(), PortError> {
    let current: bool = connection
        .query_row(
            "SELECT EXISTS(
                SELECT 1 FROM actor_bindings
                WHERE id=?1 AND actor_kind='user' AND issued_at<=?2
                  AND expires_at>?2 AND revoked_at IS NULL
             )",
            params![actor_binding_id, created_at],
            |row| row.get(0),
        )
        .map_err(sqlite_error_to_port)?;
    if current {
        Ok(())
    } else {
        Err(conflict())
    }
}

fn verify_task_artifact(
    connection: &Connection,
    reader: &dyn local_agent_terminal_application::ArtifactRootReader,
    task_id: &TaskId,
    artifact_id: &str,
) -> Result<(), PortError> {
    let metadata: Option<(String, String, i64, String)> = connection
        .query_row(
            "SELECT a.content_hash, a.storage_key, a.size_bytes, p.artifact_root_path
             FROM artifacts a
             JOIN tasks t ON t.id=?2
             JOIN projects p ON p.id=t.project_id
             WHERE a.id=?1 AND a.project_id=t.project_id
               AND (a.task_id IS NULL OR a.task_id=t.id)
               AND a.availability='available'
               AND a.verification_state IN ('hash_verified','tool_verified','user_approved')",
            params![artifact_id, task_id.as_str()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .optional()
        .map_err(sqlite_error_to_port)?;
    let Some((content_hash, storage_key, size_bytes, root)) = metadata else {
        return Err(conflict());
    };
    let reference = ArtifactRef {
        content_hash,
        storage_key,
        size_bytes: u64::try_from(size_bytes).map_err(|_| integrity_failure())?,
    };
    let content = reader
        .read_from_root(Path::new(&root), &reference)
        .map_err(|_| integrity_failure())?;
    if physical_digest(&content.bytes) != reference.content_hash
        || u64::try_from(content.bytes.len()).ok() != Some(reference.size_bytes)
    {
        return Err(integrity_failure());
    }
    Ok(())
}

fn verify_acceptance_artifact(
    connection: &Connection,
    reader: &dyn local_agent_terminal_application::ArtifactRootReader,
    receipt: &AssuranceDegradationReceipt,
    artifact_id: &str,
) -> Result<(), PortError> {
    let expected = prepare_assurance_acceptance_artifact(receipt)?;
    let metadata: Option<(String, String, i64, String)> = connection
        .query_row(
            "SELECT a.content_hash, a.storage_key, a.size_bytes, p.artifact_root_path
             FROM artifacts a
             JOIN tasks t ON t.id=?2
             JOIN projects p ON p.id=t.project_id
             WHERE a.id=?1 AND a.project_id=t.project_id AND a.task_id=t.id
               AND a.artifact_type='assurance-acceptance'
               AND a.availability='available' AND a.verification_state='user_approved'
               AND a.created_by_type='user' AND a.created_by_id=?3
               AND a.content_hash=?4 AND a.size_bytes=?5",
            params![
                artifact_id,
                receipt.task_id().as_str(),
                receipt.actor_binding_id(),
                expected.expected_hash,
                i64::try_from(expected.expected_size).map_err(|_| integrity_failure())?,
            ],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .optional()
        .map_err(sqlite_error_to_port)?;
    let Some((content_hash, storage_key, size_bytes, root)) = metadata else {
        return Err(conflict());
    };
    let reference = ArtifactRef {
        content_hash,
        storage_key,
        size_bytes: u64::try_from(size_bytes).map_err(|_| integrity_failure())?,
    };
    let content = reader
        .read_from_root(Path::new(&root), &reference)
        .map_err(|_| integrity_failure())?;
    if content.bytes != expected.content
        || physical_digest(&content.bytes) != reference.content_hash
    {
        return Err(integrity_failure());
    }
    Ok(())
}

fn resolve_receipt_artifact(
    connection: &Connection,
    reader: &dyn local_agent_terminal_application::ArtifactRootReader,
    task_id: &TaskId,
    reference: &ArtifactRef,
    expected_bytes: &[u8],
) -> Result<String, PortError> {
    let mut statement = connection
        .prepare(
            "SELECT a.id, p.artifact_root_path
             FROM artifacts a
             JOIN tasks t ON t.id=?1
             JOIN projects p ON p.id=t.project_id
             WHERE a.project_id=t.project_id AND a.task_id=t.id
               AND a.artifact_type='receipt' AND a.availability='available'
               AND a.verification_state IN ('hash_verified','tool_verified','user_approved')
               AND a.created_by_type='core'
               AND a.content_hash=?2 AND a.storage_key=?3 AND a.size_bytes=?4",
        )
        .map_err(sqlite_error_to_port)?;
    let rows = statement
        .query_map(
            params![
                task_id.as_str(),
                reference.content_hash,
                reference.storage_key,
                i64::try_from(reference.size_bytes).map_err(|_| integrity_failure())?,
            ],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
        )
        .map_err(sqlite_error_to_port)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(sqlite_error_to_port)?;
    let [(artifact_id, root)] = rows.as_slice() else {
        return Err(integrity_failure());
    };
    let content = reader
        .read_from_root(Path::new(root), reference)
        .map_err(|_| integrity_failure())?;
    if content.bytes != expected_bytes
        || physical_digest(&content.bytes) != reference.content_hash
        || AssuranceDegradationReceipt::from_canonical_bytes(&content.bytes).is_err()
    {
        return Err(integrity_failure());
    }
    Ok(artifact_id.clone())
}

fn exact_degradation_receipt(
    connection: &Connection,
    receipt: &AssuranceDegradationReceipt,
    receipt_artifact_id: &str,
) -> Result<Option<bool>, PortError> {
    let raw: Option<DegradationReceiptRow> = connection
        .query_row(
            "SELECT task_id, requested_profile, reason_code, run_set_digest,
                        decision, actor_binding_id, receipt_artifact_id, created_at,
                        receipt_digest
                 FROM assurance_degradation_receipts WHERE id=?1",
            [receipt.receipt_id()],
            |row| {
                Ok(DegradationReceiptRow {
                    task_id: row.get(0)?,
                    requested_profile: row.get(1)?,
                    reason_code: row.get(2)?,
                    run_set_digest: row.get(3)?,
                    decision: row.get(4)?,
                    actor_binding_id: row.get(5)?,
                    receipt_artifact_id: row.get(6)?,
                    created_at: row.get(7)?,
                    receipt_digest: row.get(8)?,
                })
            },
        )
        .optional()
        .map_err(sqlite_error_to_port)?;
    Ok(raw.map(|raw| {
        raw.task_id == receipt.task_id().as_str()
            && raw.requested_profile == receipt.requested_profile().as_str()
            && raw.reason_code == receipt.reason_code().as_str()
            && raw.run_set_digest == receipt.observed().run_set_digest.as_str()
            && raw.decision == receipt.decision().as_str()
            && raw.actor_binding_id.as_deref() == receipt.actor_binding_id()
            && raw.receipt_artifact_id == receipt_artifact_id
            && raw.created_at == receipt.created_at_rfc3339()
            && raw.receipt_digest == receipt.receipt_digest().as_str()
    }))
}

fn decided_by_kind(command: &ProfileEscalationCommand) -> &'static str {
    if command.actor_binding_id.is_some() {
        "user"
    } else {
        "core"
    }
}

fn profile_contains(
    current: local_agent_terminal_domain::WorkflowProfile,
    applied: local_agent_terminal_domain::WorkflowProfile,
) -> bool {
    matches!(
        (current, applied),
        (
            local_agent_terminal_domain::WorkflowProfile::Standard,
            local_agent_terminal_domain::WorkflowProfile::Standard
        ) | (
            local_agent_terminal_domain::WorkflowProfile::HighAssurance,
            local_agent_terminal_domain::WorkflowProfile::Standard
        ) | (
            local_agent_terminal_domain::WorkflowProfile::HighAssurance,
            local_agent_terminal_domain::WorkflowProfile::HighAssurance
        )
    )
}

fn configured_artifact_reader(
    store: &SqliteStore,
) -> Result<&dyn local_agent_terminal_application::ArtifactRootReader, PortError> {
    store.artifact_reader().ok_or_else(unavailable)
}

fn physical_digest(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}

fn authority_sql_error(error: rusqlite::Error) -> PortError {
    let mapped = sqlite_error_to_port(error);
    match mapped.safe_classification() {
        SafeErrorClassification::InvalidInput | SafeErrorClassification::Internal => conflict(),
        _ => mapped,
    }
}

fn degradation_sql_error(error: rusqlite::Error) -> PortError {
    let mapped = sqlite_error_to_port(error);
    match mapped.safe_classification() {
        SafeErrorClassification::InvalidInput | SafeErrorClassification::Internal => conflict(),
        _ => mapped,
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

fn unavailable() -> PortError {
    PortError::failure(
        SafeErrorClassification::Unavailable,
        Retryability::Retryable,
    )
}
