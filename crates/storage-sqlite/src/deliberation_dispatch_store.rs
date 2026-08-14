use local_agent_terminal_application::{
    DeliberationDispatchBinding, DeliberationDispatchStore, DeliberationPhaseDispatchSet,
    DeliberationProposalDispatchPlan, PortError, Retryability, SafeErrorClassification,
};
use rusqlite::{params, OptionalExtension, Transaction, TransactionBehavior};

use crate::event_store::{open_error_to_port, sqlite_error_to_port};
use crate::SqliteStore;

impl DeliberationDispatchStore for SqliteStore {
    fn compare_and_persist_proposal_binding_set(
        &self,
        plan: &DeliberationProposalDispatchPlan,
    ) -> Result<(), PortError> {
        plan.validate()?;
        self.persist_dispatch_set(plan.task_id(), "ParallelAnalysis", 0, plan.bindings())
    }

    fn compare_and_persist_phase_binding_set(
        &self,
        dispatch_set: &DeliberationPhaseDispatchSet,
    ) -> Result<(), PortError> {
        dispatch_set.validate()?;
        self.persist_dispatch_set(
            dispatch_set.task_id(),
            phase_name(dispatch_set.phase()),
            dispatch_set.authority().round(),
            dispatch_set.bindings(),
        )
    }
}

impl SqliteStore {
    fn persist_dispatch_set(
        &self,
        task_id: &local_agent_terminal_domain::TaskId,
        phase: &str,
        round: u32,
        bindings: &[DeliberationDispatchBinding],
    ) -> Result<(), PortError> {
        let mut connection = self.connection().map_err(open_error_to_port)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite_error_to_port)?;
        for binding in bindings {
            require_exact_run_bindings(&transaction, task_id, binding)?;
        }
        let existing = bindings
            .iter()
            .map(|binding| {
                dispatch_reservation_matches(&transaction, task_id, phase, round, binding)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let existing_count = existing.iter().filter(|matches| **matches).count();
        let persisted_set_count = dispatch_set_count(&transaction, task_id, phase, round)?;
        if existing_count == bindings.len() && persisted_set_count == bindings.len() {
            transaction.commit().map_err(sqlite_error_to_port)?;
            return Ok(());
        }
        if existing_count != 0 || persisted_set_count != 0 {
            return Err(conflict());
        }

        for binding in bindings {
            insert_dispatch_reservation(&transaction, task_id, phase, round, binding)?;
        }
        transaction.commit().map_err(sqlite_error_to_port)
    }
}

fn require_exact_run_bindings(
    transaction: &Transaction<'_>,
    task_id: &local_agent_terminal_domain::TaskId,
    binding: &DeliberationDispatchBinding,
) -> Result<(), PortError> {
    let request = binding.request();
    let exact: bool = transaction
        .query_row(
            "SELECT EXISTS(
                SELECT 1
                FROM agent_runs r
                JOIN context_packages c ON c.id = r.context_package_id
                JOIN run_configuration_bindings rc ON rc.run_id = r.id
                WHERE r.id = ?1 AND r.task_id = ?2 AND r.agent_id = ?3
                  AND r.role = ?4 AND r.context_package_id = ?5
                  AND r.connection_binding_digest = ?6
                  AND r.run_config_artifact_id = ?7
                  AND rc.config_artifact_id = r.run_config_artifact_id
                  AND c.task_id = r.task_id AND c.agent_id = r.agent_id
                  AND c.role = r.role AND c.effective_content_artifact_id = ?8
                  AND c.content_hash = ?9 AND c.policy_snapshot_digest = ?10
            )",
            params![
                request.run_id.as_str(),
                task_id.as_str(),
                request.agent_id,
                request.role,
                request.context.context_package_id,
                request.connection.binding_digest.as_str(),
                request.run_config.run_config_artifact_id.as_str(),
                request.context.effective_context_artifact_id.as_str(),
                request.context.content_digest.as_str(),
                request.context.policy_snapshot_digest.as_str(),
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

fn dispatch_set_count(
    transaction: &Transaction<'_>,
    task_id: &local_agent_terminal_domain::TaskId,
    phase: &str,
    round: u32,
) -> Result<usize, PortError> {
    let count: i64 = transaction
        .query_row(
            "SELECT COUNT(*) FROM deliberation_dispatch_reservations
             WHERE task_id = ?1 AND phase = ?2 AND dispatch_round = ?3",
            params![task_id.as_str(), phase, i64::from(round)],
            |row| row.get(0),
        )
        .map_err(sqlite_error_to_port)?;
    usize::try_from(count).map_err(|_| conflict())
}

fn dispatch_reservation_matches(
    transaction: &Transaction<'_>,
    task_id: &local_agent_terminal_domain::TaskId,
    phase: &str,
    round: u32,
    binding: &DeliberationDispatchBinding,
) -> Result<bool, PortError> {
    let request = binding.request();
    let existing: Option<bool> = transaction
        .query_row(
            "SELECT task_id = ?2 AND phase = ?3 AND dispatch_round = ?4
                    AND agent_id = ?5 AND family_key = ?6
                    AND max_tokens = ?7 AND estimated_cost_microunits = ?8
                    AND deadline_unix_seconds = ?9 AND run_config_artifact_id = ?10
                    AND connection_binding_digest = ?11
             FROM deliberation_dispatch_reservations WHERE run_id = ?1",
            params![
                request.run_id.as_str(),
                task_id.as_str(),
                phase,
                i64::from(round),
                request.agent_id,
                binding.family().as_str(),
                to_i64(request.run_config.limits.max_output_tokens)?,
                to_i64(binding.estimated_cost_microunits())?,
                request.run_config.limits.deadline.unix_seconds(),
                request.run_config.run_config_artifact_id.as_str(),
                request.connection.binding_digest.as_str(),
            ],
            |row| row.get(0),
        )
        .optional()
        .map_err(sqlite_error_to_port)?;
    match existing {
        Some(true) => Ok(true),
        Some(false) => Err(conflict()),
        None => Ok(false),
    }
}

fn insert_dispatch_reservation(
    transaction: &Transaction<'_>,
    task_id: &local_agent_terminal_domain::TaskId,
    phase: &str,
    round: u32,
    binding: &DeliberationDispatchBinding,
) -> Result<(), PortError> {
    let request = binding.request();
    transaction
        .execute(
            "INSERT INTO deliberation_dispatch_reservations (
                run_id, task_id, phase, agent_id, family_key, max_tokens,
                estimated_cost_microunits, deadline_unix_seconds,
                run_config_artifact_id, connection_binding_digest, dispatch_round
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            params![
                request.run_id.as_str(),
                task_id.as_str(),
                phase,
                request.agent_id,
                binding.family().as_str(),
                to_i64(request.run_config.limits.max_output_tokens)?,
                to_i64(binding.estimated_cost_microunits())?,
                request.run_config.limits.deadline.unix_seconds(),
                request.run_config.run_config_artifact_id.as_str(),
                request.connection.binding_digest.as_str(),
                i64::from(round),
            ],
        )
        .map_err(sqlite_error_to_port)?;
    Ok(())
}

fn phase_name(phase: local_agent_terminal_domain::Phase) -> &'static str {
    match phase {
        local_agent_terminal_domain::Phase::CrossReview => "CrossReview",
        local_agent_terminal_domain::Phase::PrePlanVerification => "PrePlanVerification",
        local_agent_terminal_domain::Phase::Synthesis => "Synthesis",
        local_agent_terminal_domain::Phase::FinalObjection => "FinalObjection",
        _ => "invalid",
    }
}

fn to_i64(value: u64) -> Result<i64, PortError> {
    i64::try_from(value).map_err(|_| conflict())
}

fn conflict() -> PortError {
    PortError::failure(
        SafeErrorClassification::Conflict,
        Retryability::NonRetryable,
    )
}
