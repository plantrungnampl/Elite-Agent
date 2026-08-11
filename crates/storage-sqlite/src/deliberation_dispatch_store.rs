use local_agent_terminal_application::{
    DeliberationDispatchBinding, DeliberationDispatchStore, DeliberationPhaseDispatchSet,
    DeliberationProposalDispatchPlan, PortError, Retryability, SafeErrorClassification,
};
use rusqlite::{params, OptionalExtension, Transaction, TransactionBehavior};

use crate::deliberation_budget_store::reserve_task_budget;
use crate::event_store::{open_error_to_port, sqlite_error_to_port};
use crate::SqliteStore;

impl DeliberationDispatchStore for SqliteStore {
    fn compare_and_persist_proposal_binding_set(
        &self,
        plan: &DeliberationProposalDispatchPlan,
    ) -> Result<(), PortError> {
        plan.validate()?;
        self.persist_dispatch_set(
            plan.task_id(),
            "ParallelAnalysis",
            plan.task_budget(),
            plan.budget_reservation()?,
            plan.bindings(),
        )
    }

    fn compare_and_persist_phase_binding_set(
        &self,
        dispatch_set: &DeliberationPhaseDispatchSet,
    ) -> Result<(), PortError> {
        dispatch_set.validate()?;
        self.persist_dispatch_set(
            dispatch_set.task_id(),
            phase_name(dispatch_set.phase()),
            dispatch_set.task_budget(),
            dispatch_set.budget_reservation()?,
            dispatch_set.bindings(),
        )
    }
}

impl SqliteStore {
    fn persist_dispatch_set(
        &self,
        task_id: &local_agent_terminal_domain::TaskId,
        phase: &str,
        budget: local_agent_terminal_domain::DeliberationTaskBudget,
        reservation: local_agent_terminal_application::DeliberationBudgetReservation,
        bindings: &[DeliberationDispatchBinding],
    ) -> Result<(), PortError> {
        let mut connection = self.connection().map_err(open_error_to_port)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite_error_to_port)?;
        reserve_task_budget(
            &transaction,
            task_id,
            budget,
            local_agent_terminal_application::DeliberationBudgetReservation::default(),
        )?;
        let existing = bindings
            .iter()
            .map(|binding| dispatch_reservation_matches(&transaction, task_id, phase, binding))
            .collect::<Result<Vec<_>, _>>()?;
        let existing_count = existing.iter().filter(|matches| **matches).count();
        if existing_count == bindings.len() {
            transaction.commit().map_err(sqlite_error_to_port)?;
            return Ok(());
        }
        if existing_count != 0 {
            return Err(conflict());
        }

        reserve_task_budget(&transaction, task_id, budget, reservation)?;
        for binding in bindings {
            insert_dispatch_reservation(&transaction, task_id, phase, binding)?;
        }
        transaction.commit().map_err(sqlite_error_to_port)
    }
}

fn dispatch_reservation_matches(
    transaction: &Transaction<'_>,
    task_id: &local_agent_terminal_domain::TaskId,
    phase: &str,
    binding: &DeliberationDispatchBinding,
) -> Result<bool, PortError> {
    let request = binding.request();
    let existing: Option<bool> = transaction
        .query_row(
            "SELECT task_id = ?2 AND phase = ?3 AND agent_id = ?4 AND family_key = ?5
                    AND max_tokens = ?6 AND estimated_cost_microunits = ?7
                    AND deadline_unix_seconds = ?8 AND run_config_artifact_id = ?9
                    AND connection_binding_digest = ?10
             FROM deliberation_dispatch_reservations WHERE run_id = ?1",
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
    binding: &DeliberationDispatchBinding,
) -> Result<(), PortError> {
    let request = binding.request();
    transaction
        .execute(
            "INSERT INTO deliberation_dispatch_reservations (
                run_id, task_id, phase, agent_id, family_key, max_tokens,
                estimated_cost_microunits, deadline_unix_seconds,
                run_config_artifact_id, connection_binding_digest
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
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
