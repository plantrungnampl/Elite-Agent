use local_agent_terminal_application::{PortError, Retryability, SafeErrorClassification};
use local_agent_terminal_domain::{DeliberationTaskBudget, TaskId};

use crate::SqliteStore;

impl SqliteStore {
    pub fn deliberation_task_budget(
        &self,
        _task_id: &TaskId,
    ) -> Result<Option<DeliberationTaskBudget>, PortError> {
        Err(missing_trusted_budget_authority())
    }
}

// The normative v7 workflow requires a trusted budget receipt, but the receipt and
// run-configuration authority are delivered by a later vertical slice. Until then,
// storage must not derive mutable authority from events or projection rows.
fn missing_trusted_budget_authority() -> PortError {
    PortError::failure(
        SafeErrorClassification::IntegrityFailure,
        Retryability::NonRetryable,
    )
}
