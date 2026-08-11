use local_agent_terminal_application::{
    DeliberationBoundaryCheck, DeliberationBoundaryRecord, DeliberationBoundaryStore, PortError,
    Retryability, SafeErrorClassification,
};
use local_agent_terminal_domain::{GitObjectId, WorkspaceFingerprint};
use rusqlite::{params, OptionalExtension, TransactionBehavior};

use crate::event_store::{open_error_to_port, sqlite_error_to_port};
use crate::SqliteStore;

impl DeliberationBoundaryStore for SqliteStore {
    fn compare_and_persist_boundary(
        &self,
        check: DeliberationBoundaryCheck,
    ) -> Result<DeliberationBoundaryRecord, PortError> {
        let mut connection = self.connection().map_err(open_error_to_port)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite_error_to_port)?;
        let observed = check.observed_fingerprint();
        transaction
            .execute(
                "INSERT OR IGNORE INTO deliberation_repository_baselines (
                    task_id, head, index_digest, status_digest, captured_at
                 ) VALUES (?1, ?2, ?3, ?4, strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))",
                params![
                    check.task_id().as_str(),
                    observed.head().as_str(),
                    observed.index_digest(),
                    observed.status_digest(),
                ],
            )
            .map_err(sqlite_error_to_port)?;
        let expected =
            load_baseline(&transaction, check.task_id().as_str())?.ok_or_else(integrity_failure)?;
        let record = check.compare_with(expected)?;
        transaction
            .execute(
                "INSERT OR IGNORE INTO deliberation_repository_boundary_records (
                    task_id, phase, expected_head, expected_index_digest,
                    expected_status_digest, observed_head, observed_index_digest,
                    observed_status_digest, blocked, observed_at
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9,
                    strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))",
                params![
                    record.task_id.as_str(),
                    record.phase.as_str(),
                    record.expected_fingerprint.head().as_str(),
                    record.expected_fingerprint.index_digest(),
                    record.expected_fingerprint.status_digest(),
                    record.observed_fingerprint.head().as_str(),
                    record.observed_fingerprint.index_digest(),
                    record.observed_fingerprint.status_digest(),
                    record.blocked,
                ],
            )
            .map_err(sqlite_error_to_port)?;
        let boundary_record_id: i64 = transaction
            .query_row(
                "SELECT id FROM deliberation_repository_boundary_records
                 WHERE task_id = ?1 AND phase = ?2
                   AND expected_head = ?3 AND expected_index_digest = ?4
                   AND expected_status_digest = ?5 AND observed_head = ?6
                   AND observed_index_digest = ?7 AND observed_status_digest = ?8",
                params![
                    record.task_id.as_str(),
                    record.phase.as_str(),
                    record.expected_fingerprint.head().as_str(),
                    record.expected_fingerprint.index_digest(),
                    record.expected_fingerprint.status_digest(),
                    record.observed_fingerprint.head().as_str(),
                    record.observed_fingerprint.index_digest(),
                    record.observed_fingerprint.status_digest(),
                ],
                |row| row.get(0),
            )
            .map_err(sqlite_error_to_port)?;
        if record.blocked {
            transaction
                .execute(
                    "INSERT OR IGNORE INTO deliberation_context_package_invalidations (
                        context_package_id, boundary_record_id, task_id, reason, invalidated_at
                     )
                     SELECT id, ?2, task_id, 'repository_fingerprint_changed',
                            strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
                     FROM context_packages WHERE task_id = ?1",
                    params![record.task_id.as_str(), boundary_record_id],
                )
                .map_err(sqlite_error_to_port)?;
            transaction
                .execute(
                    "UPDATE approvals
                     SET status = 'invalidated',
                         resolved_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now'),
                         invalidation_reason = 'repository_fingerprint_changed'
                     WHERE task_id = ?1 AND status IN ('pending', 'granted')",
                    [record.task_id.as_str()],
                )
                .map_err(sqlite_error_to_port)?;
        }
        transaction.commit().map_err(sqlite_error_to_port)?;
        Ok(record)
    }
}

fn load_baseline(
    connection: &rusqlite::Connection,
    task_id: &str,
) -> Result<Option<WorkspaceFingerprint>, PortError> {
    let stored: Option<(String, String, String)> = connection
        .query_row(
            "SELECT head, index_digest, status_digest
             FROM deliberation_repository_baselines WHERE task_id = ?1",
            [task_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()
        .map_err(sqlite_error_to_port)?;
    stored
        .map(|(head, index_digest, status_digest)| {
            WorkspaceFingerprint::new(
                GitObjectId::new(head).map_err(|_| integrity_failure())?,
                index_digest,
                status_digest,
            )
            .map_err(|_| integrity_failure())
        })
        .transpose()
}

fn integrity_failure() -> PortError {
    PortError::failure(
        SafeErrorClassification::IntegrityFailure,
        Retryability::NonRetryable,
    )
}
