use std::str::FromStr;

use local_agent_terminal_application::{
    Clock, ExpectedPresence, IdempotencyClass, IntentTransition, NewProject, NewTask,
    OperationIntent, OperationIntentStatus, PortError, ProjectSnapshot, RecoveryAction,
    RecoveryCandidate, RecoveryEvidence, RecoveryOperationIntent, RecoveryReason,
    RepositoryInspectionRecord, Retryability, SafeErrorClassification, StartedRecovery,
    TaskLeaseState, TaskSnapshot, WorkspaceEvidenceStore, WorkspaceMutationRequest,
    WorkspaceMutationResult, WorkspaceMutationStore, WorkspaceObservationLossRequest,
    WorkspaceRecoveryStore, WorkspaceStateStore, WorktreeIntent,
};
use local_agent_terminal_domain::{
    reduce, ArtifactId, Condition, FencingToken, GitObjectId, OperationState, Phase, ProjectId,
    RepositoryId, Sequence, TaskBranch, TaskId, TransitionRequest, WorkflowEvent, WorkflowState,
    WorkspaceVersion, WorktreeId,
};
use rusqlite::{params, OptionalExtension, Transaction, TransactionBehavior};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::event_store::{open_error_to_port, sqlite_error_to_port};
use crate::SqliteStore;

fn core_actor_binding_digest(actor_id: &str) -> String {
    format!("sha256:{:x}", Sha256::digest(actor_id.as_bytes()))
}

impl WorkspaceStateStore for SqliteStore {
    fn create_project(&self, project: NewProject) -> Result<ProjectSnapshot, PortError> {
        self.insert_project(project)
    }

    fn record_repository_inspection(
        &self,
        inspection: RepositoryInspectionRecord,
    ) -> Result<ProjectSnapshot, PortError> {
        self.insert_repository_inspection(inspection)
    }

    fn create_task(&self, task: NewTask) -> Result<TaskSnapshot, PortError> {
        validate_new_task(&task)?;
        let mut connection = self.connection().map_err(open_error_to_port)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite_error_to_port)?;
        let project_exists: bool = transaction
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM projects WHERE id = ?1)",
                [task.project_id.as_str()],
                |row| row.get(0),
            )
            .map_err(sqlite_error_to_port)?;
        if !project_exists {
            return Err(not_found());
        }
        transaction
            .execute(
                "INSERT INTO tasks (
                    id, project_id, title, objective, phase, condition, operation_state,
                    risk_level, base_branch, base_commit, task_branch, worktree_path,
                    current_sequence, workspace_version, fencing_epoch, active_candidate_tree,
                    created_at, updated_at
                 ) VALUES (
                    ?1, ?2, ?3, ?4, 'Intake', 'Active', 'None', ?5, ?6, ?7,
                    NULL, NULL, 1, 0, 0, NULL, ?8, ?8
                 )",
                params![
                    task.task_id.as_str(),
                    task.project_id.as_str(),
                    task.title,
                    task.objective,
                    task.risk_level.as_str(),
                    task.base_branch.as_str(),
                    task.base_commit.as_str(),
                    task.created_at,
                ],
            )
            .map_err(sqlite_error_to_port)?;
        let task_created_event_id = format!("task.created:{}", task.task_id.as_str());
        let task_created_payload = json!({
            "taskId": task.task_id.as_str(),
            "projectId": task.project_id.as_str(),
            "title": task.title,
            "objective": task.objective,
            "riskLevel": task.risk_level.as_str(),
            "baseBranch": task.base_branch.as_str(),
            "baseCommit": task.base_commit.as_str(),
        });
        insert_task_event(
            &transaction,
            TaskEvent {
                task_id: task.task_id.as_str(),
                sequence: 1,
                event_id: &task_created_event_id,
                event_type: "task.created",
                payload: &task_created_payload,
                actor_id: "workspace-coordinator",
                correlation_id: &format!("task:create:{}", task.task_id.as_str()),
                created_at: &task.created_at,
            },
        )?;
        transaction.commit().map_err(sqlite_error_to_port)?;

        Ok(TaskSnapshot {
            task_id: task.task_id,
            project_id: task.project_id,
            title: task.title,
            objective: task.objective,
            risk_level: task.risk_level,
            phase: Phase::Intake,
            condition: Condition::Active,
            operation_state: OperationState::None,
            base_branch: task.base_branch,
            base_commit: task.base_commit,
            task_branch: None,
            worktree: None,
            current_sequence: Sequence::new(1),
            workspace_version: WorkspaceVersion::new(0),
            fencing_epoch: 0,
            lease_state: TaskLeaseState::None,
            recovery_candidates: Vec::new(),
            timeline: Vec::new(),
        })
    }

    fn begin_worktree_intent(&self, intent: WorktreeIntent) -> Result<OperationIntent, PortError> {
        validate_worktree_intent(&intent)?;
        let mut connection = self.connection().map_err(open_error_to_port)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite_error_to_port)?;
        verify_intent_evidence(&transaction, &intent)?;
        let task: Option<(i64, String, String)> = transaction
            .query_row(
                "SELECT t.current_sequence, t.base_commit, p.repository_identity
                 FROM tasks t JOIN projects p ON p.id = t.project_id
                 WHERE t.id = ?1",
                [intent.operation.task_id.as_str()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()
            .map_err(sqlite_error_to_port)?;
        let Some((current_sequence, base_commit, repository_identity)) = task else {
            return Err(not_found());
        };
        if base_commit != intent.base_commit.as_str()
            || repository_identity != intent.repository_identity
        {
            return Err(conflict());
        }
        let existing: Option<RawOperationIntent> = transaction
            .query_row(
                "SELECT oi.id, oi.task_id, oi.operation_kind, oi.idempotency_class,
                        oi.idempotency_key, oi.canonical_request_artifact_id,
                        oi.operation_digest, oi.status, attempt.fencing_token,
                        oi.current_attempt_no, oi.created_at, oi.updated_at
                 FROM operation_intents oi
                 LEFT JOIN operation_attempts attempt
                   ON attempt.operation_intent_id = oi.id
                  AND attempt.attempt_no = oi.current_attempt_no
                 WHERE oi.idempotency_key = ?1",
                [intent.operation.idempotency_key.as_str()],
                raw_operation_intent,
            )
            .optional()
            .map_err(sqlite_error_to_port)?;
        if let Some(existing) = existing {
            let existing = parse_operation_intent(existing)?;
            if existing.task_id == intent.operation.task_id
                && existing.operation_kind == intent.operation.operation_kind
                && existing.idempotency_class == intent.operation.idempotency_class
                && existing.canonical_request_artifact_id
                    == intent.operation.canonical_request_artifact_id
                && existing.operation_digest == intent.operation.operation_digest
            {
                let existing_intent =
                    load_worktree_intent_from_transaction(&transaction, &existing)?;
                if same_worktree_intent(&existing_intent, &intent) {
                    return Ok(existing);
                }
            }
            return Err(conflict());
        }
        let sequence = current_sequence.checked_add(1).ok_or_else(invalid_input)?;
        transaction
            .execute(
                "INSERT INTO operation_intents (
                    id, task_id, run_id, operation_kind, idempotency_class, idempotency_key,
                    canonical_request_artifact_id, operation_digest, actor_binding_digest,
                    status, current_attempt_no, created_at, updated_at
                 ) VALUES (
                    ?1, ?2, NULL, ?3, ?4, ?5, ?6, ?7, ?8, 'pending', 0, ?9, ?9
                 )",
                params![
                    intent.operation.id,
                    intent.operation.task_id.as_str(),
                    intent.operation.operation_kind,
                    intent.operation.idempotency_class.as_str(),
                    intent.operation.idempotency_key,
                    intent.operation.canonical_request_artifact_id.as_str(),
                    intent.operation.operation_digest,
                    core_actor_binding_digest("workspace-coordinator"),
                    intent.operation.created_at,
                ],
            )
            .map_err(sqlite_error_to_port)?;
        let payload = worktree_intent_json(&intent);
        let intent_event_id = format!("worktree.intent:{}", intent.operation.id);
        insert_task_event(
            &transaction,
            TaskEvent {
                task_id: intent.operation.task_id.as_str(),
                sequence,
                event_id: &intent_event_id,
                event_type: "worktree.intent.recorded",
                payload: &payload,
                actor_id: "workspace-coordinator",
                correlation_id: &intent.operation.idempotency_key,
                created_at: &intent.operation.created_at,
            },
        )?;
        let changed = transaction
            .execute(
                "UPDATE tasks SET task_branch = ?1, worktree_path = ?2,
                    current_sequence = ?3, updated_at = ?4, row_version = row_version + 1
                 WHERE id = ?5 AND current_sequence = ?6",
                params![
                    intent.branch.as_str(),
                    intent.target_path_display,
                    sequence,
                    intent.operation.updated_at,
                    intent.operation.task_id.as_str(),
                    current_sequence,
                ],
            )
            .map_err(sqlite_error_to_port)?;
        if changed != 1 {
            return Err(conflict());
        }
        transaction.commit().map_err(sqlite_error_to_port)?;
        Ok(intent.operation)
    }

    fn begin_recovery_intent(
        &self,
        intent: RecoveryOperationIntent,
    ) -> Result<OperationIntent, PortError> {
        validate_recovery_intent(&intent)?;
        let mut connection = self.connection().map_err(open_error_to_port)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite_error_to_port)?;
        verify_operation_evidence(&transaction, &intent.operation)?;
        let task: Option<(i64, i64)> = transaction
            .query_row(
                "SELECT current_sequence, workspace_version FROM tasks WHERE id = ?1",
                [intent.operation.task_id.as_str()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(sqlite_error_to_port)?;
        let Some((current_sequence, workspace_version)) = task else {
            return Err(not_found());
        };
        if u64::try_from(workspace_version).ok() != Some(intent.expected_workspace_version.get()) {
            return Err(conflict());
        }
        let candidate_exists: bool = transaction
            .query_row(
                "SELECT EXISTS(
                    SELECT 1 FROM operation_intents WHERE id = ?1 AND task_id = ?2
                 )",
                params![intent.candidate_id, intent.operation.task_id.as_str()],
                |row| row.get(0),
            )
            .map_err(sqlite_error_to_port)?;
        if !candidate_exists {
            return Err(conflict());
        }
        let existing: Option<RawOperationIntent> = transaction
            .query_row(
                "SELECT oi.id, oi.task_id, oi.operation_kind, oi.idempotency_class,
                        oi.idempotency_key, oi.canonical_request_artifact_id,
                        oi.operation_digest, oi.status, attempt.fencing_token,
                        oi.current_attempt_no, oi.created_at, oi.updated_at
                 FROM operation_intents oi
                 LEFT JOIN operation_attempts attempt
                   ON attempt.operation_intent_id = oi.id
                  AND attempt.attempt_no = oi.current_attempt_no
                 WHERE oi.idempotency_key = ?1",
                [intent.operation.idempotency_key.as_str()],
                raw_operation_intent,
            )
            .optional()
            .map_err(sqlite_error_to_port)?;
        if let Some(existing) = existing {
            let existing = parse_operation_intent(existing)?;
            if same_operation_intent(&existing, &intent.operation) {
                return Ok(existing);
            }
            return Err(conflict());
        }
        let sequence = current_sequence.checked_add(1).ok_or_else(invalid_input)?;
        let action = recovery_action_name(intent.action).ok_or_else(invalid_input)?;
        let receipt = json!({
            "candidateId": intent.candidate_id,
            "action": action,
            "expectedWorkspaceVersion": intent.expected_workspace_version.get(),
        });
        transaction
            .execute(
                "INSERT INTO operation_intents (
                    id, task_id, run_id, operation_kind, idempotency_class, idempotency_key,
                    canonical_request_artifact_id, operation_digest, actor_binding_digest,
                    status, current_attempt_no, created_at, updated_at
                 ) VALUES (
                    ?1, ?2, NULL, ?3, ?4, ?5, ?6, ?7, ?8, 'pending', 0, ?9, ?9
                 )",
                params![
                    intent.operation.id,
                    intent.operation.task_id.as_str(),
                    intent.operation.operation_kind,
                    intent.operation.idempotency_class.as_str(),
                    intent.operation.idempotency_key,
                    intent.operation.canonical_request_artifact_id.as_str(),
                    intent.operation.operation_digest,
                    core_actor_binding_digest("workspace-coordinator"),
                    intent.operation.created_at,
                ],
            )
            .map_err(sqlite_error_to_port)?;
        let event_id = format!("workspace.recovery.requested:{}", intent.operation.id);
        insert_task_event(
            &transaction,
            TaskEvent {
                task_id: intent.operation.task_id.as_str(),
                sequence,
                event_id: &event_id,
                event_type: "workspace.recovery.requested",
                payload: &receipt,
                actor_id: "workspace-coordinator",
                correlation_id: &intent.operation.idempotency_key,
                created_at: &intent.operation.created_at,
            },
        )?;
        let changed = transaction
            .execute(
                "UPDATE tasks SET current_sequence = ?1, updated_at = ?2,
                    row_version = row_version + 1
                 WHERE id = ?3 AND current_sequence = ?4 AND workspace_version = ?5",
                params![
                    sequence,
                    intent.operation.updated_at,
                    intent.operation.task_id.as_str(),
                    current_sequence,
                    workspace_version,
                ],
            )
            .map_err(sqlite_error_to_port)?;
        if changed != 1 {
            return Err(conflict());
        }
        transaction.commit().map_err(sqlite_error_to_port)?;
        Ok(intent.operation)
    }

    fn transition_worktree_intent(&self, transition: IntentTransition) -> Result<(), PortError> {
        if !allowed_intent_transition(transition.expected_status, transition.next_status)
            || transition.updated_at.trim().is_empty()
        {
            return Err(invalid_input());
        }
        if transition.next_status == OperationIntentStatus::Started
            && transition.executor_fencing_token.is_none()
        {
            return Err(invalid_input());
        }
        // Normative v7 requires a policy-authorized `operation_attempt` before an
        // intent can transition. This legacy command carries no decision or approval ID.
        Err(integrity_failure())
    }

    fn reconcile_intents(&self) -> Result<Vec<RecoveryCandidate>, PortError> {
        let operations = self.started_operations()?;
        let mut candidates = Vec::with_capacity(operations.len());
        for operation in operations {
            let evidence = RecoveryEvidence {
                summary: "Started operation requires authoritative reconciliation".to_owned(),
                artifact_id: Some(operation.canonical_request_artifact_id.clone()),
            };
            if operation.idempotency_class == IdempotencyClass::NonRepeatable {
                self.mark_operation_indeterminate(&operation)?;
                candidates.push(RecoveryCandidate::indeterminate(&operation, evidence));
                continue;
            }
            if operation.operation_kind != "worktree.create" {
                self.mark_operation_indeterminate(&operation)?;
                candidates.push(RecoveryCandidate {
                    intent_id: Some(operation.id.clone()),
                    worktree_id: None,
                    reason: RecoveryReason::UnknownOperation,
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
                intent_id: Some(operation.id.clone()),
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

    fn dashboard(
        &self,
        project: &ProjectId,
    ) -> Result<local_agent_terminal_application::WorkspaceDashboardDto, PortError> {
        self.load_dashboard(project)
    }
}

impl WorkspaceRecoveryStore for SqliteStore {
    fn recovery_projects(
        &self,
    ) -> Result<Vec<local_agent_terminal_application::RecoveryProject>, PortError> {
        self.load_recovery_projects()
    }

    fn started_recoveries(&self) -> Result<Vec<StartedRecovery>, PortError> {
        self.started_operations()?
            .into_iter()
            .map(|operation| {
                let evidence = RecoveryEvidence {
                    summary: "Started operation requires authoritative reconciliation".to_owned(),
                    artifact_id: Some(operation.canonical_request_artifact_id.clone()),
                };
                let candidate = if operation.idempotency_class == IdempotencyClass::NonRepeatable {
                    RecoveryCandidate::indeterminate(&operation, evidence)
                } else if operation.operation_kind != "worktree.create" {
                    RecoveryCandidate {
                        intent_id: Some(operation.id.clone()),
                        worktree_id: None,
                        reason: RecoveryReason::UnknownOperation,
                        evidence,
                        actions: vec![
                            RecoveryAction::InspectEvidence,
                            RecoveryAction::PreserveTask,
                            RecoveryAction::CancelTask,
                        ],
                        expected_worktree: None,
                    }
                } else {
                    let expected = self.load_worktree_intent(&operation)?;
                    RecoveryCandidate {
                        intent_id: Some(operation.id.clone()),
                        worktree_id: Some(expected.worktree_id.clone()),
                        reason: RecoveryReason::OutcomeIndeterminate,
                        evidence,
                        actions: vec![
                            RecoveryAction::InspectEvidence,
                            RecoveryAction::PreserveTask,
                        ],
                        expected_worktree: Some(expected),
                    }
                };
                Ok(StartedRecovery {
                    operation,
                    candidate,
                })
            })
            .collect()
    }

    fn persisted_recovery_candidates(&self) -> Result<Vec<RecoveryCandidate>, PortError> {
        let projects = self.load_recovery_projects()?;
        let mut candidates = Vec::new();
        for project in projects {
            candidates.extend(self.load_dashboard(&project.project_id)?.recovery);
        }
        Ok(candidates)
    }
}

impl WorkspaceEvidenceStore for SqliteStore {
    fn available_evidence(
        &self,
        artifact_id: &ArtifactId,
    ) -> Result<Option<local_agent_terminal_application::CanonicalEvidenceRef>, PortError> {
        let connection = self.connection().map_err(open_error_to_port)?;
        let row: Option<(String, String, i64, String, Option<String>, String)> = connection
            .query_row(
                "SELECT content_hash, storage_key, size_bytes, project_id, task_id, availability
                 FROM artifacts WHERE id = ?1",
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
        let Some((content_hash, storage_key, size_bytes, project_id, task_id, availability)) = row
        else {
            return Ok(None);
        };
        if availability != "available" {
            return Err(integrity_failure());
        }
        let size_bytes = u64::try_from(size_bytes).map_err(|_| integrity_failure())?;
        let project_id = ProjectId::new(project_id).map_err(|_| integrity_failure())?;
        let task_id = task_id
            .map(TaskId::new)
            .transpose()
            .map_err(|_| integrity_failure())?;
        Ok(Some(
            local_agent_terminal_application::CanonicalEvidenceRef {
                artifact_id: artifact_id.clone(),
                content_hash,
                storage_key,
                size_bytes,
                project_id,
                task_id,
            },
        ))
    }
}

impl WorkspaceMutationStore for SqliteStore {
    fn record_workspace_mutation(
        &self,
        request: WorkspaceMutationRequest,
    ) -> Result<WorkspaceMutationResult, PortError> {
        let mut connection = self.connection().map_err(open_error_to_port)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite_error_to_port)?;
        let result = record_workspace_mutation_in_transaction(&transaction, request)?;
        transaction.commit().map_err(sqlite_error_to_port)?;
        Ok(result)
    }

    fn record_workspace_observation_loss(
        &self,
        request: WorkspaceObservationLossRequest,
    ) -> Result<(), PortError> {
        if request.task_id != request.operation.task_id
            || request.claim.task_id() != &request.task_id
            || request.operation.operation_kind != "worktree.create"
            || request.operation.status != OperationIntentStatus::Succeeded
            || !matches!(
                request.next_status,
                OperationIntentStatus::Interrupted | OperationIntentStatus::Indeterminate
            )
            || request.observed_at.trim().is_empty()
        {
            return Err(invalid_input());
        }
        // v7 makes succeeded attempts terminal and immutable. A later observation-loss
        // correction needs a new authority-bearing recovery intent, which this command lacks.
        Err(integrity_failure())
    }
}

impl SqliteStore {
    pub fn operation_intent(&self, intent_id: &str) -> Result<OperationIntent, PortError> {
        let connection = self.connection().map_err(open_error_to_port)?;
        connection
            .query_row(
                "SELECT oi.id, oi.task_id, oi.operation_kind, oi.idempotency_class,
                        oi.idempotency_key, oi.canonical_request_artifact_id,
                        oi.operation_digest, oi.status, attempt.fencing_token,
                        oi.current_attempt_no, oi.created_at, oi.updated_at
                 FROM operation_intents oi
                 LEFT JOIN operation_attempts attempt
                   ON attempt.operation_intent_id = oi.id
                  AND attempt.attempt_no = oi.current_attempt_no
                 WHERE oi.id = ?1",
                [intent_id],
                raw_operation_intent,
            )
            .optional()
            .map_err(sqlite_error_to_port)?
            .ok_or_else(not_found)
            .and_then(parse_operation_intent)
    }

    fn started_operations(&self) -> Result<Vec<OperationIntent>, PortError> {
        let connection = self.connection().map_err(open_error_to_port)?;
        let mut statement = connection
            .prepare(
                "SELECT oi.id, oi.task_id, oi.operation_kind, oi.idempotency_class,
                        oi.idempotency_key, oi.canonical_request_artifact_id,
                        oi.operation_digest, oi.status, attempt.fencing_token,
                        oi.current_attempt_no, oi.created_at, oi.updated_at
                 FROM operation_intents oi
                 LEFT JOIN operation_attempts attempt
                   ON attempt.operation_intent_id = oi.id
                  AND attempt.attempt_no = oi.current_attempt_no
                 WHERE oi.status = 'started' AND oi.operation_kind <> 'file.write'
                 ORDER BY oi.created_at, oi.id",
            )
            .map_err(sqlite_error_to_port)?;
        let rows = statement
            .query_map([], raw_operation_intent)
            .map_err(sqlite_error_to_port)?;
        rows.map(|row| {
            row.map_err(sqlite_error_to_port)
                .and_then(parse_operation_intent)
        })
        .collect()
    }

    fn mark_operation_indeterminate(&self, operation: &OperationIntent) -> Result<(), PortError> {
        self.transition_worktree_intent(IntentTransition {
            intent_id: operation.id.clone(),
            expected_status: OperationIntentStatus::Started,
            next_status: OperationIntentStatus::Indeterminate,
            executor_fencing_token: operation.executor_fencing_token,
            attempt_count: operation.attempt_count,
            updated_at: self.now_utc()?,
            error: None,
            observed_fingerprint: None,
        })
    }

    pub(crate) fn load_worktree_intent(
        &self,
        operation: &OperationIntent,
    ) -> Result<WorktreeIntent, PortError> {
        let mut connection = self.connection().map_err(open_error_to_port)?;
        let transaction = connection.transaction().map_err(sqlite_error_to_port)?;
        let intent = load_worktree_intent_from_transaction(&transaction, operation)?;
        transaction.rollback().map_err(sqlite_error_to_port)?;
        Ok(intent)
    }
}

fn load_worktree_intent_from_transaction(
    transaction: &Transaction<'_>,
    operation: &OperationIntent,
) -> Result<WorktreeIntent, PortError> {
    let payload: String = transaction
        .query_row(
            "SELECT payload_json FROM events
             WHERE stream_id = ?1 AND event_type = 'worktree.intent.recorded'
               AND json_extract(payload_json, '$.intentId') = ?2
             ORDER BY sequence DESC LIMIT 1",
            params![operation.task_id.as_str(), operation.id],
            |row| row.get(0),
        )
        .map_err(sqlite_error_to_port)?;
    let value: Value = serde_json::from_str(&payload).map_err(|_| integrity_failure())?;
    parse_worktree_intent(operation.clone(), &value)
}

fn same_worktree_intent(left: &WorktreeIntent, right: &WorktreeIntent) -> bool {
    left.worktree_id == right.worktree_id
        && left.repository_id == right.repository_id
        && left.repository_identity == right.repository_identity
        && left.branch == right.branch
        && left.base_commit == right.base_commit
        && left.target_path_display == right.target_path_display
        && left.expected_presence == right.expected_presence
}

pub(crate) fn worktree_intent_json(intent: &WorktreeIntent) -> Value {
    json!({
        "intentId": intent.operation.id,
        "taskId": intent.operation.task_id.as_str(),
        "worktreeId": intent.worktree_id.as_str(),
        "repositoryId": intent.repository_id.as_str(),
        "repositoryIdentity": intent.repository_identity,
        "branch": intent.branch.as_str(),
        "baseCommit": intent.base_commit.as_str(),
        "targetPathDisplay": intent.target_path_display,
        "expectedPresence": match intent.expected_presence {
            ExpectedPresence::Absent => "absent",
            ExpectedPresence::Present => "present",
        },
        "canonicalRequestArtifactId": intent.operation.canonical_request_artifact_id.as_str(),
        "operationDigest": intent.operation.operation_digest,
    })
}

pub(crate) fn parse_worktree_intent(
    operation: OperationIntent,
    value: &Value,
) -> Result<WorktreeIntent, PortError> {
    let text = |name: &str| {
        value
            .get(name)
            .and_then(Value::as_str)
            .ok_or_else(integrity_failure)
    };
    if text("intentId")? != operation.id || text("taskId")? != operation.task_id.as_str() {
        return Err(integrity_failure());
    }
    Ok(WorktreeIntent {
        operation,
        worktree_id: WorktreeId::new(text("worktreeId")?).map_err(|_| integrity_failure())?,
        repository_id: RepositoryId::new(text("repositoryId")?).map_err(|_| integrity_failure())?,
        repository_identity: text("repositoryIdentity")?.to_owned(),
        branch: TaskBranch::new(text("branch")?).map_err(|_| integrity_failure())?,
        base_commit: GitObjectId::new(text("baseCommit")?).map_err(|_| integrity_failure())?,
        target_path_display: text("targetPathDisplay")?.to_owned(),
        expected_presence: match text("expectedPresence")? {
            "absent" => ExpectedPresence::Absent,
            "present" => ExpectedPresence::Present,
            _ => return Err(integrity_failure()),
        },
    })
}

pub(crate) struct RawOperationIntent {
    id: String,
    task_id: String,
    operation_kind: String,
    idempotency_class: String,
    idempotency_key: String,
    canonical_request_artifact_id: String,
    operation_digest: String,
    status: String,
    executor_fencing_token: Option<i64>,
    attempt_count: i64,
    created_at: String,
    updated_at: String,
}

pub(crate) fn raw_operation_intent(
    row: &rusqlite::Row<'_>,
) -> rusqlite::Result<RawOperationIntent> {
    Ok(RawOperationIntent {
        id: row.get(0)?,
        task_id: row.get(1)?,
        operation_kind: row.get(2)?,
        idempotency_class: row.get(3)?,
        idempotency_key: row.get(4)?,
        canonical_request_artifact_id: row.get(5)?,
        operation_digest: row.get(6)?,
        status: row.get(7)?,
        executor_fencing_token: row.get(8)?,
        attempt_count: row.get(9)?,
        created_at: row.get(10)?,
        updated_at: row.get(11)?,
    })
}

pub(crate) fn parse_operation_intent(
    raw: RawOperationIntent,
) -> Result<OperationIntent, PortError> {
    Ok(OperationIntent {
        id: raw.id,
        task_id: TaskId::new(raw.task_id).map_err(|_| integrity_failure())?,
        operation_kind: raw.operation_kind,
        idempotency_class: IdempotencyClass::parse(&raw.idempotency_class)
            .ok_or_else(integrity_failure)?,
        idempotency_key: raw.idempotency_key,
        canonical_request_artifact_id: ArtifactId::new(raw.canonical_request_artifact_id)
            .map_err(|_| integrity_failure())?,
        operation_digest: raw.operation_digest,
        status: OperationIntentStatus::parse(&raw.status).ok_or_else(integrity_failure)?,
        executor_fencing_token: raw
            .executor_fencing_token
            .map(FencingToken::try_from)
            .transpose()
            .map_err(|_| integrity_failure())?,
        attempt_count: u32::try_from(raw.attempt_count).map_err(|_| integrity_failure())?,
        created_at: raw.created_at,
        updated_at: raw.updated_at,
    })
}

pub(crate) struct TaskEvent<'a> {
    pub(crate) task_id: &'a str,
    pub(crate) sequence: i64,
    pub(crate) event_id: &'a str,
    pub(crate) event_type: &'a str,
    pub(crate) payload: &'a Value,
    pub(crate) actor_id: &'a str,
    pub(crate) correlation_id: &'a str,
    pub(crate) created_at: &'a str,
}

pub(crate) fn insert_task_event(
    transaction: &Transaction<'_>,
    event: TaskEvent<'_>,
) -> Result<(), PortError> {
    transaction
        .execute(
            "INSERT INTO events (
                event_id, stream_id, sequence, event_type, schema_version, actor_type,
                actor_id, observation_class, payload_json, metadata_json, causation_id,
                correlation_id, created_at
             ) VALUES (?1, ?2, ?3, ?4, 1, 'core', ?5, 'core_observed',
                ?6, '{}', NULL, ?7, ?8)",
            params![
                event.event_id,
                event.task_id,
                event.sequence,
                event.event_type,
                event.actor_id,
                event.payload.to_string(),
                event.correlation_id,
                event.created_at,
            ],
        )
        .map_err(sqlite_error_to_port)?;
    Ok(())
}

fn verify_intent_evidence(
    transaction: &Transaction<'_>,
    intent: &WorktreeIntent,
) -> Result<(), PortError> {
    verify_operation_evidence(transaction, &intent.operation)
}

fn verify_operation_evidence(
    transaction: &Transaction<'_>,
    operation: &OperationIntent,
) -> Result<(), PortError> {
    let artifact: Option<(Option<String>, String)> = transaction
        .query_row(
            "SELECT task_id, availability FROM artifacts WHERE id = ?1",
            [operation.canonical_request_artifact_id.as_str()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()
        .map_err(sqlite_error_to_port)?;
    if artifact
        != Some((
            Some(operation.task_id.as_str().to_owned()),
            "available".to_owned(),
        ))
    {
        return Err(integrity_failure());
    }
    Ok(())
}

fn validate_new_task(task: &NewTask) -> Result<(), PortError> {
    if task.title.trim().is_empty()
        || task.objective.trim().is_empty()
        || task.created_at.trim().is_empty()
    {
        return Err(invalid_input());
    }
    Ok(())
}

fn validate_worktree_intent(intent: &WorktreeIntent) -> Result<(), PortError> {
    let operation = &intent.operation;
    if operation.status != OperationIntentStatus::Pending
        || operation.id.trim().is_empty()
        || operation.idempotency_key.trim().is_empty()
        || operation.created_at.trim().is_empty()
        || operation.updated_at.trim().is_empty()
    {
        return Err(invalid_input());
    }
    Ok(())
}

fn validate_recovery_intent(intent: &RecoveryOperationIntent) -> Result<(), PortError> {
    let action = recovery_action_name(intent.action).ok_or_else(invalid_input)?;
    if intent.candidate_id.trim().is_empty()
        || intent.operation.operation_kind != format!("workspace.recovery.{action}")
    {
        return Err(invalid_input());
    }
    validate_operation_intent(&intent.operation)
}

fn validate_operation_intent(operation: &OperationIntent) -> Result<(), PortError> {
    if operation.status != OperationIntentStatus::Pending
        || operation.id.trim().is_empty()
        || operation.idempotency_key.trim().is_empty()
        || operation.created_at.trim().is_empty()
        || operation.updated_at.trim().is_empty()
    {
        return Err(invalid_input());
    }
    Ok(())
}

fn same_operation_intent(left: &OperationIntent, right: &OperationIntent) -> bool {
    left.id == right.id
        && left.task_id == right.task_id
        && left.operation_kind == right.operation_kind
        && left.idempotency_class == right.idempotency_class
        && left.idempotency_key == right.idempotency_key
        && left.canonical_request_artifact_id == right.canonical_request_artifact_id
        && left.operation_digest == right.operation_digest
}

const fn recovery_action_name(action: RecoveryAction) -> Option<&'static str> {
    match action {
        RecoveryAction::AdoptExactMatch | RecoveryAction::RetryAfterAuthoritativeAbsence => {
            Some("reconcile")
        }
        RecoveryAction::PreserveTask => Some("preserve"),
        RecoveryAction::DiscardExactWorktree => Some("discard"),
        RecoveryAction::InspectEvidence | RecoveryAction::CancelTask => None,
    }
}

fn allowed_intent_transition(from: OperationIntentStatus, to: OperationIntentStatus) -> bool {
    matches!(
        (from, to),
        (
            OperationIntentStatus::Pending,
            OperationIntentStatus::Claimed | OperationIntentStatus::Started
        ) | (
            OperationIntentStatus::Claimed,
            OperationIntentStatus::Pending | OperationIntentStatus::Started
        ) | (
            OperationIntentStatus::Started,
            OperationIntentStatus::Succeeded
                | OperationIntentStatus::Failed
                | OperationIntentStatus::Interrupted
                | OperationIntentStatus::Indeterminate
        ) | (
            OperationIntentStatus::Interrupted,
            OperationIntentStatus::Pending
        ) | (
            OperationIntentStatus::Indeterminate,
            OperationIntentStatus::Succeeded
                | OperationIntentStatus::Failed
                | OperationIntentStatus::Cancelled
        ) | (
            OperationIntentStatus::Succeeded,
            OperationIntentStatus::Interrupted | OperationIntentStatus::Indeterminate
        ) | (
            OperationIntentStatus::Pending
                | OperationIntentStatus::Claimed
                | OperationIntentStatus::Started
                | OperationIntentStatus::Interrupted,
            OperationIntentStatus::Cancelled
        )
    )
}

pub(crate) fn invalid_input() -> PortError {
    PortError::failure(
        SafeErrorClassification::InvalidInput,
        Retryability::NonRetryable,
    )
}

pub(crate) fn integrity_failure() -> PortError {
    PortError::failure(
        SafeErrorClassification::IntegrityFailure,
        Retryability::NonRetryable,
    )
}

pub(crate) fn conflict() -> PortError {
    PortError::failure(
        SafeErrorClassification::Conflict,
        Retryability::NonRetryable,
    )
}

pub(crate) fn not_found() -> PortError {
    PortError::failure(
        SafeErrorClassification::NotFound,
        Retryability::NonRetryable,
    )
}

pub(crate) fn record_workspace_mutation_in_transaction(
    transaction: &Transaction<'_>,
    request: WorkspaceMutationRequest,
) -> Result<WorkspaceMutationResult, PortError> {
    record_workspace_mutation_with_authority(transaction, request)
}

fn record_workspace_mutation_with_authority(
    transaction: &Transaction<'_>,
    request: WorkspaceMutationRequest,
) -> Result<WorkspaceMutationResult, PortError> {
    validate_mutation_request(&request)?;
    verify_mutation_evidence(transaction, &request)?;
    let task: Option<(String, String, String, i64, i64, i64)> = transaction
        .query_row(
            "SELECT phase, condition, operation_state, current_sequence,
                    workspace_version, fencing_epoch
             FROM tasks WHERE id = ?1",
            [request.task_id.as_str()],
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
    let Some((
        phase_name,
        condition_name,
        operation_name,
        current_sequence,
        workspace_version,
        fencing_epoch,
    )) = task
    else {
        return Err(not_found());
    };
    let expected_sequence =
        i64::try_from(request.expected_sequence.get()).map_err(|_| invalid_input())?;
    if current_sequence != expected_sequence {
        return Err(PortError::version_conflict(
            request.expected_sequence,
            Sequence::try_from(current_sequence).map_err(|_| integrity_failure())?,
        ));
    }
    let current_token = FencingToken::try_from(fencing_epoch).map_err(|_| integrity_failure())?;
    let lease: Option<(String, i64, String)> = transaction
        .query_row(
            "SELECT holder_run_id, fencing_token, status
             FROM executor_leases WHERE task_id = ?1 AND status = 'active'",
            [request.task_id.as_str()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()
        .map_err(sqlite_error_to_port)?;
    let Some((holder_run_id, lease_token, lease_status)) = lease else {
        return Err(PortError::stale_lease(current_token, request.claim.token()));
    };
    let claimed_token = i64::try_from(request.claim.token().get()).map_err(|_| invalid_input())?;
    if lease_status != "active"
        || holder_run_id != request.claim.holder_run_id().as_str()
        || lease_token != claimed_token
        || request.claim.task_id() != &request.task_id
        || request.claim.token() != current_token
    {
        return Err(PortError::stale_lease(current_token, request.claim.token()));
    }

    let state = WorkflowState::new(
        Phase::from_str(&phase_name).map_err(|_| integrity_failure())?,
        Condition::from_str(&condition_name).map_err(|_| integrity_failure())?,
        OperationState::from_str(&operation_name).map_err(|_| integrity_failure())?,
        Sequence::try_from(current_sequence).map_err(|_| integrity_failure())?,
        WorkspaceVersion::try_from(workspace_version).map_err(|_| integrity_failure())?,
        current_token,
    )
    .map_err(|_| integrity_failure())?;
    let event = WorkflowEvent::new("workspace.mutated").map_err(|_| invalid_input())?;
    let transition = reduce(
        &state,
        &TransitionRequest {
            rule_id: "WF-W001".to_owned(),
            event,
            guard_evidence_kinds: ["workspace_mutation_evidence"]
                .into_iter()
                .map(str::to_owned)
                .collect(),
            effect_kinds: [
                "revoke_executor_lease",
                "increment_fencing_epoch",
                "invalidate_affected_approvals",
                "discard_candidate_tree",
                "discard_candidate_commit",
                "stop_write_capable_tools",
                "capture_workspace_evidence",
            ]
            .into_iter()
            .map(str::to_owned)
            .collect(),
        },
    )
    .map_err(|_| conflict())?;
    let next_state = transition.state().clone();
    let next_sequence = current_sequence.checked_add(1).ok_or_else(invalid_input)?;
    let now: String = transaction
        .query_row("SELECT strftime('%Y-%m-%dT%H:%M:%fZ', 'now')", [], |row| {
            row.get(0)
        })
        .map_err(sqlite_error_to_port)?;
    let invalidated_ids: Vec<String> = {
        let mut statement = transaction
            .prepare(
                "SELECT id FROM approvals
                 WHERE task_id = ?1
                   AND approval_type IN ('plan', 'tool', 'final_commit')
                   AND status IN ('pending', 'granted')
                 ORDER BY id",
            )
            .map_err(sqlite_error_to_port)?;
        let rows = statement
            .query_map([request.task_id.as_str()], |row| row.get(0))
            .map_err(sqlite_error_to_port)?
            .collect::<Result<Vec<String>, _>>()
            .map_err(sqlite_error_to_port)?;
        rows
    };
    let payload = json!({
        "taskId": request.task_id.as_str(),
        "preFingerprint": fingerprint_json(&request.pre_fingerprint),
        "postFingerprint": fingerprint_json(&request.post_fingerprint),
        "preEvidenceArtifactId": request.pre_evidence.artifact_id.as_str(),
        "postEvidenceArtifactId": request.post_evidence.artifact_id.as_str(),
        "resumeTarget": state.phase().as_str(),
        "newFencingToken": next_state.fencing_token().get(),
    });
    let event_id = format!(
        "workspace.mutated:{}:{next_sequence}",
        request.task_id.as_str()
    );
    insert_task_event(
        transaction,
        TaskEvent {
            task_id: request.task_id.as_str(),
            sequence: next_sequence,
            event_id: &event_id,
            event_type: "workspace.mutated",
            payload: &payload,
            actor_id: request.actor_id.as_str(),
            correlation_id: &request.correlation_id,
            created_at: &now,
        },
    )?;
    let updated = transaction
        .execute(
            "UPDATE tasks SET
                phase = ?1, condition = ?2, operation_state = ?3,
                workspace_version = ?4, fencing_epoch = ?5,
                current_sequence = ?6, active_candidate_tree = NULL, updated_at = ?7,
                row_version = row_version + 1
             WHERE id = ?8 AND current_sequence = ?9 AND fencing_epoch = ?10",
            params![
                next_state.phase().as_str(),
                next_state.condition().as_str(),
                next_state.operation().as_str(),
                i64::try_from(next_state.workspace_version().get()).map_err(|_| invalid_input())?,
                i64::try_from(next_state.fencing_token().get()).map_err(|_| invalid_input())?,
                next_sequence,
                now,
                request.task_id.as_str(),
                current_sequence,
                fencing_epoch,
            ],
        )
        .map_err(sqlite_error_to_port)?;
    if updated != 1 {
        return Err(conflict());
    }
    if !invalidated_ids.is_empty() {
        transaction
            .execute(
                "UPDATE approvals SET status = 'invalidated',
                    resolved_at = ?1, invalidation_reason = ?2
                 WHERE task_id = ?3
                   AND approval_type IN ('plan', 'tool', 'final_commit')
                   AND status IN ('pending', 'granted')",
                params![now, "workspace_mutated", request.task_id.as_str(),],
            )
            .map_err(sqlite_error_to_port)?;
    }
    let revoked = transaction
        .execute(
            "UPDATE executor_leases SET status = 'revoked', released_at = ?1
             WHERE task_id = ?2 AND holder_run_id = ?3
               AND fencing_token = ?4 AND status = 'active'",
            params![
                now,
                request.task_id.as_str(),
                request.claim.holder_run_id().as_str(),
                claimed_token,
            ],
        )
        .map_err(sqlite_error_to_port)?;
    if revoked != 1 {
        return Err(conflict());
    }

    Ok(WorkspaceMutationResult {
        event_id: local_agent_terminal_domain::EventId::new(event_id)
            .map_err(|_| integrity_failure())?,
        new_sequence: Sequence::new(u64::try_from(next_sequence).map_err(|_| integrity_failure())?),
        task_state: next_state,
        resume_target: Some(state.phase()),
        invalidated_approval_ids: invalidated_ids,
    })
}

fn validate_mutation_request(request: &WorkspaceMutationRequest) -> Result<(), PortError> {
    if request.claim.task_id() != &request.task_id
        || request.correlation_id.trim().is_empty()
        || request.pre_evidence.project_id != request.post_evidence.project_id
        || request.pre_evidence.task_id.as_ref() != Some(&request.task_id)
        || request.post_evidence.task_id.as_ref() != Some(&request.task_id)
    {
        return Err(invalid_input());
    }
    Ok(())
}

fn verify_mutation_evidence(
    transaction: &Transaction<'_>,
    request: &WorkspaceMutationRequest,
) -> Result<(), PortError> {
    for evidence in [&request.pre_evidence, &request.post_evidence] {
        verify_evidence_ref_in_transaction(transaction, evidence, &request.task_id)?;
    }
    Ok(())
}

pub(crate) fn verify_evidence_ref_in_transaction(
    transaction: &Transaction<'_>,
    evidence: &local_agent_terminal_application::CanonicalEvidenceRef,
    expected_task_id: &TaskId,
) -> Result<(), PortError> {
    let row: Option<(Option<String>, String, String, String, i64, String)> = transaction
        .query_row(
            "SELECT task_id, project_id, content_hash, storage_key, size_bytes, availability
             FROM artifacts WHERE id = ?1",
            [evidence.artifact_id.as_str()],
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
    let Some((task_id, project_id, hash, storage_key, size, availability)) = row else {
        return Err(integrity_failure());
    };
    if task_id.as_deref() != Some(expected_task_id.as_str())
        || evidence.task_id.as_ref() != Some(expected_task_id)
        || project_id != evidence.project_id.as_str()
        || hash != evidence.content_hash
        || storage_key != evidence.storage_key
        || u64::try_from(size).map_err(|_| integrity_failure())? != evidence.size_bytes
        || availability != "available"
    {
        return Err(integrity_failure());
    }
    Ok(())
}

fn fingerprint_json(fingerprint: &local_agent_terminal_domain::WorkspaceFingerprint) -> Value {
    json!({
        "head": fingerprint.head().as_str(),
        "indexDigest": fingerprint.index_digest(),
        "statusDigest": fingerprint.status_digest(),
    })
}
