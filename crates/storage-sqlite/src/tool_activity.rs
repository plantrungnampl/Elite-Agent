use local_agent_terminal_application::{
    tool_request_context, ApprovalId, ApprovalResumeStore, ArtifactId, PortError,
    ToolActivityRecord, ToolActivityStatusDto, ToolExecutionId, ToolExecutionResumeStore,
    ToolRedactionStateDto,
};
use local_agent_terminal_domain::{PolicyRuleId, RedactionDirective, Sha256Digest};
use rusqlite::params;
use serde_json::Value;

use crate::event_store::{open_error_to_port, sqlite_error_to_port};
use crate::SqliteStore;

impl SqliteStore {
    pub fn tool_activity_records(&self) -> Result<Vec<ToolActivityRecord>, PortError> {
        self.load_tool_activity_entries(None)
    }

    pub fn tool_activity_record_for_approval(
        &self,
        approval_id: &ApprovalId,
    ) -> Result<ToolActivityRecord, PortError> {
        self.load_tool_activity_entries(Some(approval_id))?
            .pop()
            .ok_or_else(not_found)
    }

    fn load_tool_activity_entries(
        &self,
        approval_id: Option<&ApprovalId>,
    ) -> Result<Vec<ToolActivityRecord>, PortError> {
        let connection = self.connection().map_err(open_error_to_port)?;
        let mut statement = connection
            .prepare(
                "WITH approval_events AS (
                    SELECT json_extract(payload_json, '$.executionId') AS execution_id,
                           json_extract(payload_json, '$.approvalId') AS approval_id,
                           json_extract(payload_json, '$.approvalPolicyDecisionId')
                               AS approval_policy_decision_id
                    FROM events
                    WHERE event_type = 'approval.requested'
                      AND json_extract(payload_json, '$.approvalType') = 'tool'
                 )
                 SELECT oi.id, oi.canonical_request_artifact_id, oi.status,
                        oi.executor_fencing_token, te.status, te.policy_decision_id,
                        te.approval_id, te.started_at, te.completed_at, ae.approval_id, a.status,
                        a.operation_digest, a.expires_at,
                        COALESCE(te.policy_decision_id, ae.approval_policy_decision_id),
                        pd.operation_digest, pd.policy_snapshot_digest, pd.effect,
                        pd.matched_rules_json, ar.role,
                        EXISTS(
                            SELECT 1 FROM events cancel_event
                            WHERE cancel_event.stream_id = oi.task_id
                              AND cancel_event.event_type = 'operation.cancel.requested'
                              AND json_extract(cancel_event.payload_json, '$.executionId') = oi.id
                        )
                 FROM operation_intents oi
                 LEFT JOIN tool_executions te ON te.operation_intent_id = oi.id
                 LEFT JOIN approval_events ae ON ae.execution_id = oi.id
                 LEFT JOIN approvals a ON a.id = ae.approval_id
                 LEFT JOIN policy_decisions pd
                   ON pd.id = COALESCE(te.policy_decision_id, ae.approval_policy_decision_id)
                 LEFT JOIN agent_runs ar ON ar.id = oi.run_id
                 WHERE oi.operation_kind = 'process.exec'
                   AND (?1 IS NULL OR ae.approval_id = ?1)
                 ORDER BY oi.updated_at DESC, oi.id DESC
                 LIMIT 100",
            )
            .map_err(sqlite_error_to_port)?;
        let rows = statement
            .query_map(params![approval_id.map(ApprovalId::as_str)], |row| {
                Ok(RawToolActivityRow {
                    execution_id: row.get(0)?,
                    request_artifact_id: row.get(1)?,
                    intent_status: row.get(2)?,
                    fencing_token: row.get(3)?,
                    execution_status: row.get(4)?,
                    execution_policy_decision_id: row.get(5)?,
                    execution_approval_id: row.get(6)?,
                    started_at: row.get(7)?,
                    completed_at: row.get(8)?,
                    approval_id: row.get(9)?,
                    approval_status: row.get(10)?,
                    approval_operation_digest: row.get(11)?,
                    approval_expires_at: row.get(12)?,
                    policy_decision_id: row.get(13)?,
                    policy_operation_digest: row.get(14)?,
                    policy_snapshot_digest: row.get(15)?,
                    policy_effect: row.get(16)?,
                    matched_rules_json: row.get(17)?,
                    effective_role: row.get(18)?,
                    cancellation_requested: row.get(19)?,
                })
            })
            .map_err(sqlite_error_to_port)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(sqlite_error_to_port)?;
        drop(statement);
        drop(connection);

        // ponytail: the 100-row cap keeps this authoritative per-artifact verification bounded;
        // batch only if refresh latency becomes measurable.
        rows.into_iter()
            .map(|row| self.activity_entry(row))
            .collect()
    }

    fn activity_entry(&self, row: RawToolActivityRow) -> Result<ToolActivityRecord, PortError> {
        let execution_id =
            ToolExecutionId::new(row.execution_id.clone()).map_err(|_| integrity_failure())?;
        let artifact_id =
            ArtifactId::new(row.request_artifact_id.clone()).map_err(|_| integrity_failure())?;
        let immutable = ToolExecutionResumeStore::load_request_artifact(self, &artifact_id)?;
        if immutable.request().execution_id() != &execution_id {
            return Err(integrity_failure());
        }
        let context = tool_request_context(immutable.request()).map_err(|_| integrity_failure())?;
        let approval_id = row
            .approval_id
            .map(ApprovalId::new)
            .transpose()
            .map_err(|_| integrity_failure())?;
        if row.execution_status.is_some()
            && row.execution_approval_id.as_deref() != approval_id.as_ref().map(ApprovalId::as_str)
        {
            return Err(integrity_failure());
        }
        if let Some(approval_id) = &approval_id {
            let approval = ApprovalResumeStore::load_approval_request(self, approval_id)?;
            if approval.execution_id() != &execution_id
                || approval.tool_request_artifact_id() != &artifact_id
                || row.approval_operation_digest.as_deref()
                    != Some(approval.canonical_payload().operation_digest.as_str())
            {
                return Err(integrity_failure());
            }
        }

        let policy_decision_id = row.policy_decision_id.ok_or_else(integrity_failure)?;
        let operation_digest = if row.execution_policy_decision_id.is_some() {
            row.policy_operation_digest.ok_or_else(integrity_failure)?
        } else {
            row.approval_operation_digest
                .ok_or_else(integrity_failure)?
        };
        Sha256Digest::new(operation_digest.clone()).map_err(|_| integrity_failure())?;
        let persisted_policy_snapshot = row.policy_snapshot_digest.ok_or_else(integrity_failure)?;
        if persisted_policy_snapshot != context.policy_snapshot_digest {
            return Err(integrity_failure());
        }
        let matched = parse_matched_rules(
            row.matched_rules_json
                .as_deref()
                .ok_or_else(integrity_failure)?,
        )?;
        let redacted = row.policy_effect.as_deref() == Some("allow_with_redaction")
            || !matched.redactions.is_empty();
        let status = activity_status(
            row.execution_status.as_deref(),
            row.approval_status.as_deref(),
            &row.intent_status,
            row.cancellation_requested,
        )?;
        let effective_role = row
            .effective_role
            .filter(|role| !role.trim().is_empty())
            .unwrap_or(context.fallback_role);
        let request_fencing_token = context.fencing_token;
        if row.fencing_token != request_fencing_token {
            return Err(integrity_failure());
        }

        Ok(ToolActivityRecord {
            request: immutable.request().clone(),
            approval_id: approval_id.map(|value| value.as_str().to_owned()),
            status,
            effective_role,
            operation_digest,
            policy_decision_id: Some(policy_decision_id),
            expires_at: row.approval_expires_at,
            policy_rules: matched.rule_ids,
            redaction_state: if redacted {
                ToolRedactionStateDto::Redacted
            } else {
                ToolRedactionStateDto::None
            },
            started_at: row.started_at,
            completed_at: row.completed_at,
        })
    }
}

struct RawToolActivityRow {
    execution_id: String,
    request_artifact_id: String,
    intent_status: String,
    fencing_token: Option<u64>,
    execution_status: Option<String>,
    execution_policy_decision_id: Option<String>,
    execution_approval_id: Option<String>,
    started_at: Option<String>,
    completed_at: Option<String>,
    approval_id: Option<String>,
    approval_status: Option<String>,
    approval_operation_digest: Option<String>,
    approval_expires_at: Option<String>,
    policy_decision_id: Option<String>,
    policy_operation_digest: Option<String>,
    policy_snapshot_digest: Option<String>,
    policy_effect: Option<String>,
    matched_rules_json: Option<String>,
    effective_role: Option<String>,
    cancellation_requested: bool,
}

struct MatchedRules {
    rule_ids: Vec<String>,
    redactions: Vec<String>,
}

fn parse_matched_rules(raw: &str) -> Result<MatchedRules, PortError> {
    let value: Value = serde_json::from_str(raw).map_err(|_| integrity_failure())?;
    let object = value.as_object().ok_or_else(integrity_failure)?;
    if object.len() != 3 || object.get("policyVersion").and_then(Value::as_u64) != Some(1) {
        return Err(integrity_failure());
    }
    let rule_ids = string_array(object.get("ruleIds"))?;
    let redactions = string_array(object.get("redactions"))?;
    if rule_ids
        .iter()
        .any(|id| PolicyRuleId::new(id.clone()).is_err())
        || redactions
            .iter()
            .any(|directive| RedactionDirective::new(directive.clone()).is_err())
    {
        return Err(integrity_failure());
    }
    Ok(MatchedRules {
        rule_ids,
        redactions,
    })
}

fn string_array(value: Option<&Value>) -> Result<Vec<String>, PortError> {
    value
        .and_then(Value::as_array)
        .ok_or_else(integrity_failure)?
        .iter()
        .map(|value| {
            value
                .as_str()
                .map(str::to_owned)
                .ok_or_else(integrity_failure)
        })
        .collect()
}

fn activity_status(
    execution_status: Option<&str>,
    approval_status: Option<&str>,
    intent_status: &str,
    cancellation_requested: bool,
) -> Result<ToolActivityStatusDto, PortError> {
    if let Some(status) = execution_status {
        return match status {
            "pending" | "running" if cancellation_requested => {
                Ok(ToolActivityStatusDto::Cancelling)
            }
            "pending" | "running" => Ok(ToolActivityStatusDto::Running),
            "succeeded" => Ok(ToolActivityStatusDto::Succeeded),
            "failed" => Ok(ToolActivityStatusDto::Failed),
            "cancelled" | "terminated" => Ok(ToolActivityStatusDto::Terminated),
            "interrupted" => Ok(ToolActivityStatusDto::Interrupted),
            "indeterminate" => Ok(ToolActivityStatusDto::Indeterminate),
            "denied" => Ok(ToolActivityStatusDto::Denied),
            _ => Err(integrity_failure()),
        };
    }
    if let Some(status) = approval_status {
        return match status {
            "pending" => Ok(ToolActivityStatusDto::ApprovalRequired),
            "denied" => Ok(ToolActivityStatusDto::Denied),
            "expired" | "invalidated" => Ok(ToolActivityStatusDto::Interrupted),
            "granted" => Ok(ToolActivityStatusDto::Running),
            _ => Err(integrity_failure()),
        };
    }
    match intent_status {
        "pending" | "claimed" | "started" if cancellation_requested => {
            Ok(ToolActivityStatusDto::Cancelling)
        }
        "pending" | "claimed" | "started" => Ok(ToolActivityStatusDto::Running),
        "succeeded" => Ok(ToolActivityStatusDto::Succeeded),
        "failed" => Ok(ToolActivityStatusDto::Failed),
        "cancelled" => Ok(ToolActivityStatusDto::Terminated),
        "interrupted" => Ok(ToolActivityStatusDto::Interrupted),
        "indeterminate" => Ok(ToolActivityStatusDto::Indeterminate),
        _ => Err(integrity_failure()),
    }
}

fn not_found() -> PortError {
    PortError::failure(
        local_agent_terminal_application::SafeErrorClassification::NotFound,
        local_agent_terminal_application::Retryability::NonRetryable,
    )
}

fn integrity_failure() -> PortError {
    PortError::failure(
        local_agent_terminal_application::SafeErrorClassification::IntegrityFailure,
        local_agent_terminal_application::Retryability::NonRetryable,
    )
}
