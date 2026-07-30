use local_agent_terminal_application::{
    PolicyDecisionId, PolicyDecisionStore, PortError, RecordedPolicyDecision, Retryability,
    SafeErrorClassification,
};
use local_agent_terminal_domain::{
    ActorLocality, CapabilityRef, PolicyEffect, ResourceClass, TaskRisk, TrustTier,
};
use rusqlite::{params, OptionalExtension, TransactionBehavior};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::event_store::{open_error_to_port, sqlite_error_to_port};
use crate::SqliteStore;

type PersistedPolicyDecision = (
    String,
    String,
    String,
    String,
    String,
    String,
    String,
    String,
    String,
    String,
    String,
    Option<String>,
);

impl PolicyDecisionStore for SqliteStore {
    fn record(&self, recorded: RecordedPolicyDecision) -> Result<PolicyDecisionId, PortError> {
        let request = recorded.decision.draft.request();
        let actor_json = actor_json(request);
        let resource_json = resource_json(request);
        let actor_binding_digest = digest_json(&actor_json)?;
        let matched_rules_json = json!({
            "policyVersion": recorded.decision.draft.policy_version().get(),
            "ruleIds": recorded.decision.draft.rule_ids(),
            "redactions": recorded.decision.draft.redactions(),
        });
        let created_at = timestamp(
            &self.connection().map_err(open_error_to_port)?,
            recorded.recorded_at.unix_seconds(),
        )?;
        let expires_at = recorded
            .decision
            .draft
            .expires_at()
            .map(|value| {
                let connection = self.connection().map_err(open_error_to_port)?;
                timestamp(&connection, value.unix_seconds())
            })
            .transpose()?;
        let decision_id = PolicyDecisionId::from_decision(&recorded.decision);
        let effect = effect_name(recorded.decision.draft.effect());

        let mut connection = self.connection().map_err(open_error_to_port)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite_error_to_port)?;
        transaction
            .execute(
                "INSERT OR IGNORE INTO policy_decisions (
                    id, task_id, actor_json, actor_binding_digest, action, resource_json,
                    resource_digest, purpose, workflow_phase, effect, matched_rules_json,
                    policy_snapshot_digest, operation_digest, created_at, expires_at, approval_id
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, NULL)",
                params![
                    decision_id.as_str(),
                    request.task_id.as_str(),
                    actor_json.to_string(),
                    actor_binding_digest,
                    request.action.as_str(),
                    resource_json.to_string(),
                    request.resource.content_digest.as_str(),
                    request.purpose,
                    request.workflow_phase,
                    effect,
                    matched_rules_json.to_string(),
                    request.policy_snapshot_digest.as_str(),
                    recorded.decision.operation_digest.as_str(),
                    created_at,
                    expires_at,
                ],
            )
            .map_err(sqlite_error_to_port)?;
        let persisted: Option<PersistedPolicyDecision> = transaction
            .query_row(
                "SELECT task_id, actor_json, actor_binding_digest, action, resource_json,
                        resource_digest, purpose, workflow_phase, effect, matched_rules_json,
                        policy_snapshot_digest, expires_at
                 FROM policy_decisions WHERE id = ?1 AND operation_digest = ?2",
                params![
                    decision_id.as_str(),
                    recorded.decision.operation_digest.as_str()
                ],
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
        let expected = (
            request.task_id.as_str().to_owned(),
            actor_json.to_string(),
            actor_binding_digest,
            request.action.as_str().to_owned(),
            resource_json.to_string(),
            request.resource.content_digest.as_str().to_owned(),
            request.purpose.clone(),
            request.workflow_phase.clone(),
            effect.to_owned(),
            matched_rules_json.to_string(),
            request.policy_snapshot_digest.as_str().to_owned(),
            expires_at,
        );
        let created_at_matches: bool = transaction
            .query_row(
                "SELECT EXISTS(
                    SELECT 1 FROM policy_decisions WHERE id = ?1 AND created_at = ?2
                )",
                params![decision_id.as_str(), created_at],
                |row| row.get(0),
            )
            .map_err(sqlite_error_to_port)?;
        if persisted.as_ref() != Some(&expected) || !created_at_matches {
            return Err(conflict());
        }
        transaction.commit().map_err(sqlite_error_to_port)?;
        Ok(decision_id)
    }
}

pub(crate) fn actor_json(request: &local_agent_terminal_domain::PolicyRequest) -> Value {
    json!({
        "connectionId": request.actor.connection_id,
        "agentId": request.actor.agent_id,
        "trustTier": match request.actor.trust_tier {
            TrustTier::CoreAdapter => "core_adapter",
            TrustTier::BrokeredProcess => "brokered_process",
            TrustTier::IsolatedWorker => "isolated_worker",
        },
        "locality": match request.actor.locality {
            ActorLocality::Local => "local",
            ActorLocality::Cloud => "cloud",
        },
    })
}

pub(crate) fn resource_json(request: &local_agent_terminal_domain::PolicyRequest) -> Value {
    json!({
        "capability": capability_json(&request.resource.capability),
        "contentDigest": request.resource.content_digest.as_str(),
        "resourceClass": match request.resource.resource_class {
            ResourceClass::Public => "public",
            ResourceClass::InternalCode => "internal_code",
            ResourceClass::Restricted => "restricted",
            ResourceClass::Secret => "secret",
        },
        "taskRisk": match request.task_risk {
            TaskRisk::Low => "low",
            TaskRisk::Medium => "medium",
            TaskRisk::High => "high",
            TaskRisk::Critical => "critical",
        },
    })
}

fn capability_json(capability: &CapabilityRef) -> Value {
    match capability {
        CapabilityRef::Source(value) => {
            json!({"kind": "source", "revision": value.revision(), "path": value.path()})
        }
        CapabilityRef::Artifact(value) => {
            json!({"kind": "artifact", "artifactId": value.artifact_id().as_str()})
        }
        CapabilityRef::Worktree(value) => {
            json!({"kind": "worktree", "taskId": value.task_id().as_str(), "path": value.path()})
        }
        CapabilityRef::Toolchain(value) => {
            json!({"kind": "toolchain", "name": value.name()})
        }
    }
}

pub(crate) fn digest_json(value: &Value) -> Result<String, PortError> {
    let bytes = serde_json::to_vec(value).map_err(|_| invalid_input())?;
    Ok(format!("sha256:{:x}", Sha256::digest(bytes)))
}

fn timestamp(connection: &rusqlite::Connection, unix_seconds: i64) -> Result<String, PortError> {
    connection
        .query_row(
            "SELECT strftime('%Y-%m-%dT%H:%M:%fZ', ?1, 'unixepoch')",
            [unix_seconds],
            |row| row.get(0),
        )
        .map_err(sqlite_error_to_port)
}

pub(crate) const fn effect_name(effect: PolicyEffect) -> &'static str {
    match effect {
        PolicyEffect::Allow => "allow",
        PolicyEffect::Deny => "deny",
        PolicyEffect::RequireApproval => "require_approval",
        PolicyEffect::AllowWithRedaction => "allow_with_redaction",
    }
}

fn invalid_input() -> PortError {
    PortError::failure(
        SafeErrorClassification::InvalidInput,
        Retryability::NonRetryable,
    )
}

fn conflict() -> PortError {
    PortError::failure(
        SafeErrorClassification::Conflict,
        Retryability::NonRetryable,
    )
}
