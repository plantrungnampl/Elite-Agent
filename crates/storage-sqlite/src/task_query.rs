use std::str::FromStr;

use local_agent_terminal_application::{
    EvidenceSummaryDto, IdempotencyClass, OperationIntentStatus, PortError, RecoveryAction,
    RecoveryCandidate, RecoveryEvidence, RecoveryReason, Retryability, RiskLevel,
    SafeErrorClassification, TaskLeaseState, TaskQuery, TaskSnapshot, TimelineEntryDto,
    WorkspaceDashboardDto,
};
use local_agent_terminal_domain::{
    Condition, GitObjectId, OperationState, Phase, ProjectId, Sequence, TaskBranch, TaskId,
    WorkspaceVersion,
};
use rusqlite::OptionalExtension;
use serde_json::Value;

use crate::event_store::{open_error_to_port, sqlite_error_to_port};
use crate::project_store::{parse_repository_snapshot, project_stream_id};
use crate::workspace_store::{parse_operation_intent, raw_operation_intent};
use crate::SqliteStore;

impl TaskQuery for SqliteStore {
    fn task(&self, task_id: &TaskId) -> Result<TaskSnapshot, PortError> {
        let connection = self.connection().map_err(open_error_to_port)?;
        let row: Option<RawTask> = connection
            .query_row(
                "SELECT
                    t.id, t.project_id, t.title, t.objective, t.risk_level, t.phase,
                    t.condition, t.operation_state, t.base_branch, t.base_commit,
                    t.task_branch, t.current_sequence, t.workspace_version, t.fencing_epoch,
                    l.status
                 FROM tasks t
                 LEFT JOIN executor_leases l ON l.task_id = t.id
                 WHERE t.id = ?1",
                [task_id.as_str()],
                raw_task,
            )
            .optional()
            .map_err(sqlite_error_to_port)?;
        let mut task = row.ok_or_else(not_found).and_then(parse_task)?;
        task.worktree = self.load_worktree_snapshot(&task.task_id)?;
        task.recovery_candidates = self.recovery_for_task(&task.task_id)?;
        Ok(task)
    }

    fn timeline(&self, task_id: &TaskId) -> Result<Vec<TimelineEntryDto>, PortError> {
        let connection = self.connection().map_err(open_error_to_port)?;
        let mut statement = connection
            .prepare(
                "SELECT sequence, event_type, created_at, payload_json
                 FROM events WHERE stream_id = ?1 ORDER BY sequence",
            )
            .map_err(sqlite_error_to_port)?;
        let rows = statement
            .query_map([task_id.as_str()], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                ))
            })
            .map_err(sqlite_error_to_port)?;
        rows.map(|row| {
            let (sequence, event_type, created_at, payload) = row.map_err(sqlite_error_to_port)?;
            let sequence = u64::try_from(sequence).map_err(|_| integrity_failure())?;
            let payload: Value = serde_json::from_str(&payload).map_err(|_| integrity_failure())?;
            let evidence_id = [
                "evidenceArtifactId",
                "canonicalRequestArtifactId",
                "preEvidenceArtifactId",
                "postEvidenceArtifactId",
            ]
            .into_iter()
            .find_map(|key| payload.get(key).and_then(Value::as_str));
            let evidence = evidence_id
                .map(|artifact_id| evidence_summary(&connection, artifact_id))
                .transpose()?;
            Ok(TimelineEntryDto {
                sequence,
                event_type: event_type.clone(),
                created_at,
                summary: event_type,
                evidence,
            })
        })
        .collect()
    }
}

impl SqliteStore {
    fn load_worktree_snapshot(
        &self,
        task_id: &TaskId,
    ) -> Result<Option<local_agent_terminal_application::WorktreeSnapshot>, PortError> {
        let connection = self.connection().map_err(open_error_to_port)?;
        let raw: Option<crate::workspace_store::RawOperationIntent> = connection
            .query_row(
                "SELECT id, task_id, operation_kind, idempotency_class, idempotency_key,
                        canonical_request_artifact_id, operation_digest, status,
                        executor_fencing_token, attempt_count, created_at, updated_at
                 FROM operation_intents
                 WHERE task_id = ?1 AND operation_kind = 'worktree.create'
                 ORDER BY created_at DESC, id DESC LIMIT 1",
                [task_id.as_str()],
                raw_operation_intent,
            )
            .optional()
            .map_err(sqlite_error_to_port)?;
        let Some(raw) = raw else {
            return Ok(None);
        };
        let operation = parse_operation_intent(raw)?;
        let intent = self.load_worktree_intent(&operation)?;
        let repository_stream = project_stream_id(
            &ProjectId::new(
                connection
                    .query_row(
                        "SELECT project_id FROM tasks WHERE id = ?1",
                        [task_id.as_str()],
                        |row| row.get::<_, String>(0),
                    )
                    .map_err(sqlite_error_to_port)?,
            )
            .map_err(|_| integrity_failure())?,
        );
        let repository_payload: String = connection
            .query_row(
                "SELECT payload_json FROM events
                 WHERE stream_id = ?1 AND event_type = 'repository.inspected'
                 ORDER BY sequence DESC LIMIT 1",
                [&repository_stream],
                |row| row.get(0),
            )
            .map_err(sqlite_error_to_port)?;
        let repository = parse_repository_snapshot(
            &serde_json::from_str(&repository_payload).map_err(|_| integrity_failure())?,
        )?;
        let state = match operation.status {
            OperationIntentStatus::Succeeded => {
                local_agent_terminal_application::WorktreeState::Present
            }
            OperationIntentStatus::Failed
            | OperationIntentStatus::Interrupted
            | OperationIntentStatus::Cancelled => {
                local_agent_terminal_application::WorktreeState::Missing
            }
            _ => local_agent_terminal_application::WorktreeState::Planned,
        };
        Ok(Some(local_agent_terminal_application::WorktreeSnapshot {
            worktree_id: intent.worktree_id,
            repository_id: intent.repository_id,
            repository_identity: intent.repository_identity,
            task_id: intent.operation.task_id,
            branch: intent.branch,
            base_commit: intent.base_commit,
            target_path_display: intent.target_path_display,
            state,
            expected_presence: intent.expected_presence,
            fingerprint: repository.fingerprint,
        }))
    }

    fn recovery_for_task(&self, task_id: &TaskId) -> Result<Vec<RecoveryCandidate>, PortError> {
        let connection = self.connection().map_err(open_error_to_port)?;
        let mut statement = connection
            .prepare(
                "SELECT id, task_id, operation_kind, idempotency_class, idempotency_key,
                        canonical_request_artifact_id, operation_digest, status,
                        executor_fencing_token, attempt_count, created_at, updated_at
                 FROM operation_intents
                 WHERE task_id = ?1 AND status IN ('started', 'interrupted', 'indeterminate')
                 ORDER BY created_at, id",
            )
            .map_err(sqlite_error_to_port)?;
        let rows = statement
            .query_map([task_id.as_str()], raw_operation_intent)
            .map_err(sqlite_error_to_port)?;
        let operations = rows
            .map(|row| {
                row.map_err(sqlite_error_to_port)
                    .and_then(parse_operation_intent)
            })
            .collect::<Result<Vec<_>, PortError>>()?;
        drop(statement);
        drop(connection);

        let mut candidates = Vec::with_capacity(operations.len());
        for operation in operations {
            let evidence = RecoveryEvidence {
                summary: "Persisted operation requires recovery review".to_owned(),
                artifact_id: Some(operation.canonical_request_artifact_id.clone()),
            };
            if operation.status == OperationIntentStatus::Interrupted {
                let expected = self.load_worktree_intent(&operation)?;
                candidates.push(RecoveryCandidate {
                    intent_id: Some(operation.id),
                    worktree_id: Some(expected.worktree_id.clone()),
                    reason: RecoveryReason::AuthoritativeAbsence,
                    evidence,
                    actions: vec![
                        RecoveryAction::InspectEvidence,
                        RecoveryAction::RetryAfterAuthoritativeAbsence,
                        RecoveryAction::PreserveTask,
                        RecoveryAction::CancelTask,
                    ],
                    expected_worktree: Some(expected),
                });
                continue;
            }
            if operation.status == OperationIntentStatus::Indeterminate {
                if operation.operation_kind != "worktree.create" {
                    candidates.push(RecoveryCandidate {
                        intent_id: Some(operation.id),
                        worktree_id: None,
                        reason: RecoveryReason::UnknownOperation,
                        evidence,
                        actions: vec![
                            RecoveryAction::InspectEvidence,
                            RecoveryAction::PreserveTask,
                        ],
                        expected_worktree: None,
                    });
                } else {
                    candidates.push(RecoveryCandidate::indeterminate(&operation, evidence));
                }
                continue;
            }
            if operation.idempotency_class == IdempotencyClass::NonRepeatable
                || operation.operation_kind != "worktree.create"
            {
                candidates.push(RecoveryCandidate {
                    intent_id: Some(operation.id),
                    worktree_id: None,
                    reason: if operation.idempotency_class == IdempotencyClass::NonRepeatable {
                        RecoveryReason::IndeterminateNonRepeatable
                    } else {
                        RecoveryReason::UnknownOperation
                    },
                    evidence,
                    actions: vec![
                        RecoveryAction::InspectEvidence,
                        RecoveryAction::PreserveTask,
                        RecoveryAction::CancelTask,
                    ],
                    expected_worktree: None,
                });
                continue;
            }
            let expected = self.load_worktree_intent(&operation)?;
            candidates.push(RecoveryCandidate {
                intent_id: Some(operation.id),
                worktree_id: Some(expected.worktree_id.clone()),
                reason: RecoveryReason::OutcomeIndeterminate,
                evidence,
                actions: vec![
                    RecoveryAction::InspectEvidence,
                    RecoveryAction::PreserveTask,
                ],
                expected_worktree: Some(expected),
            });
        }
        Ok(candidates)
    }

    pub(crate) fn load_dashboard(
        &self,
        project_id: &ProjectId,
    ) -> Result<WorkspaceDashboardDto, PortError> {
        let connection = self.connection().map_err(open_error_to_port)?;
        let project_exists: bool = connection
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM projects WHERE id = ?1)",
                [project_id.as_str()],
                |row| row.get(0),
            )
            .map_err(sqlite_error_to_port)?;
        if !project_exists {
            return Err(not_found());
        }
        let stream_id = project_stream_id(project_id);
        let payload: Option<String> = connection
            .query_row(
                "SELECT payload_json FROM events
                 WHERE stream_id = ?1 AND event_type = 'repository.inspected'
                 ORDER BY sequence DESC LIMIT 1",
                [&stream_id],
                |row| row.get(0),
            )
            .optional()
            .map_err(sqlite_error_to_port)?;
        let payload = payload.ok_or_else(integrity_failure)?;
        let repository = parse_repository_snapshot(
            &serde_json::from_str(&payload).map_err(|_| integrity_failure())?,
        )?;

        let mut statement = connection
            .prepare("SELECT id FROM tasks WHERE project_id = ?1 ORDER BY created_at, id")
            .map_err(sqlite_error_to_port)?;
        let task_ids = statement
            .query_map([project_id.as_str()], |row| row.get::<_, String>(0))
            .map_err(sqlite_error_to_port)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(sqlite_error_to_port)?;
        drop(statement);
        drop(connection);
        let tasks = task_ids
            .into_iter()
            .map(|id| {
                TaskId::new(id)
                    .map_err(|_| integrity_failure())
                    .and_then(|task_id| self.task(&task_id))
            })
            .collect::<Result<Vec<_>, PortError>>()?;
        let recovery = tasks
            .iter()
            .flat_map(|task| task.recovery_candidates.iter().cloned())
            .collect::<Vec<RecoveryCandidate>>();
        Ok(WorkspaceDashboardDto {
            project_id: project_id.clone(),
            repository,
            tasks,
            recovery,
        })
    }
}

struct RawTask {
    task_id: String,
    project_id: String,
    title: String,
    objective: String,
    risk_level: String,
    phase: String,
    condition: String,
    operation_state: String,
    base_branch: String,
    base_commit: String,
    task_branch: Option<String>,
    current_sequence: i64,
    workspace_version: i64,
    fencing_epoch: i64,
    lease_status: Option<String>,
}

fn raw_task(row: &rusqlite::Row<'_>) -> rusqlite::Result<RawTask> {
    Ok(RawTask {
        task_id: row.get(0)?,
        project_id: row.get(1)?,
        title: row.get(2)?,
        objective: row.get(3)?,
        risk_level: row.get(4)?,
        phase: row.get(5)?,
        condition: row.get(6)?,
        operation_state: row.get(7)?,
        base_branch: row.get(8)?,
        base_commit: row.get(9)?,
        task_branch: row.get(10)?,
        current_sequence: row.get(11)?,
        workspace_version: row.get(12)?,
        fencing_epoch: row.get(13)?,
        lease_status: row.get(14)?,
    })
}

fn parse_task(raw: RawTask) -> Result<TaskSnapshot, PortError> {
    Ok(TaskSnapshot {
        task_id: TaskId::new(raw.task_id).map_err(|_| integrity_failure())?,
        project_id: ProjectId::new(raw.project_id).map_err(|_| integrity_failure())?,
        title: raw.title,
        objective: raw.objective,
        risk_level: RiskLevel::parse(&raw.risk_level).ok_or_else(integrity_failure)?,
        phase: Phase::from_str(&raw.phase).map_err(|_| integrity_failure())?,
        condition: Condition::from_str(&raw.condition).map_err(|_| integrity_failure())?,
        operation_state: OperationState::from_str(&raw.operation_state)
            .map_err(|_| integrity_failure())?,
        base_branch: TaskBranch::new(raw.base_branch).map_err(|_| integrity_failure())?,
        base_commit: GitObjectId::new(raw.base_commit).map_err(|_| integrity_failure())?,
        task_branch: raw
            .task_branch
            .map(TaskBranch::new)
            .transpose()
            .map_err(|_| integrity_failure())?,
        worktree: None,
        current_sequence: Sequence::try_from(raw.current_sequence)
            .map_err(|_| integrity_failure())?,
        workspace_version: WorkspaceVersion::try_from(raw.workspace_version)
            .map_err(|_| integrity_failure())?,
        fencing_epoch: u64::try_from(raw.fencing_epoch).map_err(|_| integrity_failure())?,
        lease_state: match raw.lease_status.as_deref() {
            None => TaskLeaseState::None,
            Some("active") => TaskLeaseState::Active,
            Some("released") => TaskLeaseState::Released,
            Some("expired") => TaskLeaseState::Expired,
            Some("revoked") => TaskLeaseState::Revoked,
            Some(_) => return Err(integrity_failure()),
        },
        recovery_candidates: Vec::new(),
    })
}

fn evidence_summary(
    connection: &rusqlite::Connection,
    artifact_id: &str,
) -> Result<EvidenceSummaryDto, PortError> {
    let evidence: Option<(String, i64)> = connection
        .query_row(
            "SELECT content_hash, size_bytes FROM artifacts
             WHERE id = ?1 AND availability = 'available'",
            [artifact_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()
        .map_err(sqlite_error_to_port)?;
    let (content_hash, size_bytes) = evidence.ok_or_else(integrity_failure)?;
    Ok(EvidenceSummaryDto {
        artifact_id: artifact_id.to_owned(),
        content_hash,
        size_bytes: u64::try_from(size_bytes).map_err(|_| integrity_failure())?,
    })
}

fn not_found() -> PortError {
    PortError::failure(
        SafeErrorClassification::NotFound,
        Retryability::NonRetryable,
    )
}

fn integrity_failure() -> PortError {
    PortError::failure(
        SafeErrorClassification::IntegrityFailure,
        Retryability::NonRetryable,
    )
}
