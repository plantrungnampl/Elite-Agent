use local_agent_terminal_application::{
    CanonicalDeliberationFact, DeliberationBudgetReservation, PortError, Retryability,
    SafeErrorClassification,
};
use local_agent_terminal_domain::{DeliberationTaskBudget, Sha256Digest, TaskId, Timestamp};
use rusqlite::{params, OptionalExtension, Transaction, TransactionBehavior};

use crate::event_store::open_error_to_port;
use crate::event_store::sqlite_error_to_port;
use crate::SqliteStore;

impl SqliteStore {
    pub fn deliberation_task_budget(
        &self,
        task_id: &TaskId,
    ) -> Result<Option<DeliberationTaskBudget>, PortError> {
        let mut connection = self.connection().map_err(open_error_to_port)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite_error_to_port)?;
        let mut raw = load_budget_row(&transaction, task_id)?;
        if raw.is_none() {
            if let Some(recovered) = historical_budget_authority(&transaction, task_id)? {
                let reservation = historical_reservation(&transaction, task_id)?;
                insert_budget_row(&transaction, task_id, recovered, reservation)?;
                raw = load_budget_row(&transaction, task_id)?;
            }
        }
        let budget = raw.map(budget_from_row).transpose()?;
        transaction.commit().map_err(sqlite_error_to_port)?;
        Ok(budget)
    }
}

fn load_budget_row(
    transaction: &Transaction<'_>,
    task_id: &TaskId,
) -> Result<Option<(i64, i64, i64, i64)>, PortError> {
    transaction
        .query_row(
            "SELECT max_threads, max_tokens, max_cost_microunits, deadline_unix_seconds
                 FROM deliberation_task_budgets WHERE task_id = ?1",
            [task_id.as_str()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .optional()
        .map_err(sqlite_error_to_port)
}

fn budget_from_row(
    (threads, tokens, cost, deadline): (i64, i64, i64, i64),
) -> Result<DeliberationTaskBudget, PortError> {
    DeliberationTaskBudget::new(
        u32::try_from(threads).map_err(|_| integrity_failure())?,
        u64::try_from(tokens).map_err(|_| integrity_failure())?,
        u64::try_from(cost).map_err(|_| integrity_failure())?,
        Timestamp::from_unix_seconds(deadline),
    )
    .map_err(|_| integrity_failure())
}

fn insert_budget_row(
    transaction: &Transaction<'_>,
    task_id: &TaskId,
    budget: DeliberationTaskBudget,
    reservation: DeliberationBudgetReservation,
) -> Result<(), PortError> {
    if reservation.thread_count() > budget.max_threads()
        || reservation.token_count() > budget.max_tokens()
        || reservation.cost_microunits() > budget.max_cost_microunits()
    {
        return Err(conflict());
    }
    transaction
        .execute(
            "INSERT INTO deliberation_task_budgets (
                task_id, max_threads, max_tokens, max_cost_microunits,
                deadline_unix_seconds, reserved_threads, reserved_tokens,
                reserved_cost_microunits
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                task_id.as_str(),
                i64::from(budget.max_threads()),
                to_i64(budget.max_tokens())?,
                to_i64(budget.max_cost_microunits())?,
                budget.deadline().unix_seconds(),
                i64::from(reservation.thread_count()),
                to_i64(reservation.token_count())?,
                to_i64(reservation.cost_microunits())?,
            ],
        )
        .map_err(sqlite_error_to_port)?;
    Ok(())
}

pub(crate) fn reserve_task_budget(
    transaction: &Transaction<'_>,
    task_id: &TaskId,
    budget: DeliberationTaskBudget,
    reservation: DeliberationBudgetReservation,
) -> Result<(), PortError> {
    let max_threads = i64::from(budget.max_threads());
    let max_tokens = to_i64(budget.max_tokens())?;
    let max_cost = to_i64(budget.max_cost_microunits())?;
    let exists: bool = transaction
        .query_row(
            "SELECT EXISTS(
                SELECT 1 FROM deliberation_task_budgets WHERE task_id = ?1
             )",
            [task_id.as_str()],
            |row| row.get(0),
        )
        .map_err(sqlite_error_to_port)?;
    let historical = if exists {
        DeliberationBudgetReservation::default()
    } else {
        historical_reservation(transaction, task_id)?
    };
    if historical.thread_count() > budget.max_threads()
        || historical.token_count() > budget.max_tokens()
        || historical.cost_microunits() > budget.max_cost_microunits()
    {
        return Err(conflict());
    }
    if !exists {
        insert_budget_row(transaction, task_id, budget, historical)?;
    }

    let exact: bool = transaction
        .query_row(
            "SELECT EXISTS(
                SELECT 1 FROM deliberation_task_budgets
                WHERE task_id = ?1 AND max_threads = ?2 AND max_tokens = ?3
                  AND max_cost_microunits = ?4 AND deadline_unix_seconds = ?5
             )",
            params![
                task_id.as_str(),
                max_threads,
                max_tokens,
                max_cost,
                budget.deadline().unix_seconds(),
            ],
            |row| row.get(0),
        )
        .map_err(sqlite_error_to_port)?;
    if !exact {
        return Err(conflict());
    }

    let deadline_active: bool = transaction
        .query_row(
            "SELECT unixepoch() <= ?1",
            [budget.deadline().unix_seconds()],
            |row| row.get(0),
        )
        .map_err(sqlite_error_to_port)?;
    if !deadline_active {
        return Err(conflict());
    }

    if reservation == DeliberationBudgetReservation::default() {
        return Ok(());
    }
    let changed = transaction
        .execute(
            "UPDATE deliberation_task_budgets
             SET reserved_threads = reserved_threads + ?2,
                 reserved_tokens = reserved_tokens + ?3,
                 reserved_cost_microunits = reserved_cost_microunits + ?4
             WHERE task_id = ?1
               AND reserved_threads + ?2 <= max_threads
               AND reserved_tokens + ?3 <= max_tokens
               AND reserved_cost_microunits + ?4 <= max_cost_microunits",
            params![
                task_id.as_str(),
                i64::from(reservation.thread_count()),
                to_i64(reservation.token_count())?,
                to_i64(reservation.cost_microunits())?,
            ],
        )
        .map_err(sqlite_error_to_port)?;
    if changed == 1 {
        Ok(())
    } else {
        Err(conflict())
    }
}

fn historical_reservation(
    transaction: &Transaction<'_>,
    task_id: &TaskId,
) -> Result<DeliberationBudgetReservation, PortError> {
    let mut statement = transaction
        .prepare(
            "SELECT canonical_record_json, canonical_record_digest
             FROM deliberation_records WHERE task_id = ?1 ORDER BY sequence",
        )
        .map_err(sqlite_error_to_port)?;
    let records = statement
        .query_map([task_id.as_str()], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })
        .map_err(sqlite_error_to_port)?;
    let mut reservation = DeliberationBudgetReservation::default();
    for record in records {
        let (canonical_json, canonical_digest) = record.map_err(sqlite_error_to_port)?;
        let digest = Sha256Digest::new(canonical_digest).map_err(|_| integrity_failure())?;
        let fact = CanonicalDeliberationFact::rehydrate(canonical_json.into_bytes(), digest)?;
        if fact.task_id() != task_id {
            return Err(integrity_failure());
        }
        reservation = reservation.checked_add(fact.record().budget_reservation())?;
    }
    Ok(reservation)
}

fn historical_budget_authority(
    transaction: &Transaction<'_>,
    task_id: &TaskId,
) -> Result<Option<DeliberationTaskBudget>, PortError> {
    let mut statement = transaction
        .prepare(
            "SELECT
                json_extract(events.payload_json, '$.taskBudget.maxThreads'),
                json_extract(events.payload_json, '$.taskBudget.maxTokens'),
                json_extract(events.payload_json, '$.taskBudget.maxCostMicrounits'),
                json_extract(events.payload_json, '$.taskBudget.deadlineUnixSeconds')
             FROM deliberation_records
             JOIN events ON events.event_id = deliberation_records.event_id
             WHERE deliberation_records.task_id = ?1
             ORDER BY deliberation_records.sequence",
        )
        .map_err(sqlite_error_to_port)?;
    let rows = statement
        .query_map([task_id.as_str()], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
        })
        .map_err(sqlite_error_to_port)?;
    let mut authority = None;
    for row in rows {
        let budget = budget_from_row(row.map_err(sqlite_error_to_port)?)?;
        if authority.is_some_and(|existing| existing != budget) {
            return Err(integrity_failure());
        }
        authority = Some(budget);
    }
    Ok(authority)
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

fn integrity_failure() -> PortError {
    PortError::failure(
        SafeErrorClassification::IntegrityFailure,
        Retryability::NonRetryable,
    )
}
