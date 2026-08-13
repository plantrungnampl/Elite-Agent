use std::fs;
use std::path::{Component, Path, PathBuf};

use local_agent_terminal_application::{
    canonical_policy_binding_digest, parse_tool_request, policy_request_for_tool,
    validate_tool_approval_request, ApprovalDigestPayload, AuthoritativeProcessBinding,
    AuthoritativeProcessTermination, AuthorizedToolExecutionClaim, CancellationReceipt,
    DeniedToolExecution, DurableToolExecutionArtifact,
    DurableToolExecutionArtifacts, DurableToolExecutionReceipt,
    FileWriteRecoveryCompletion, FileWriteRecoveryFailure, FileWriteRecoveryIntent,
    FileWriteRecoverySnapshot,
    FileWriteRecoveryStore, IdempotencyClass, ImmutableToolRequest, IncompleteToolExecution,
    JobReceipt, NewToolExecution, NewToolIntent, OperationIntentSnapshot, PolicyDecisionId,
    PolicyRequestBindingDigest, PortError, ProcessExecutionBindingStore, ProcessStatus,
    Retryability, SafeErrorClassification, SafeToolExecutionError, ToolExecutionCancellationClaim,
    ToolExecutionClaim, ToolExecutionClaimAuthority, ToolExecutionDenialRequest, ToolExecutionId,
    ToolExecutionOutput, ToolExecutionPostEffectReceipt, ToolExecutionRecoveryEvidence,
    ToolExecutionRecoveryState, ToolExecutionResolution, ToolExecutionStore,
    ToolExecutionStreamMetadata, ToolExecutionTerminal, ToolExecutionTerminalKind,
};
use local_agent_terminal_domain::{ArtifactId, FencingToken, RunId, Sha256Digest, TaskId, Timestamp};
use rusqlite::{params, OptionalExtension, Transaction, TransactionBehavior};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::approval_store::{append_approval_event, parse_canonical_approval_payload};
use crate::event_store::{open_error_to_port, sqlite_error_to_port};
use crate::policy_store::{actor_json, digest_json, resource_json};
use crate::SqliteStore;

#[derive(Debug)]
struct PersistedToolExecution {
    task_id: String,
    run_id: Option<String>,
    request_id: String,
    tool_name: String,
    arguments_artifact_id: String,
    policy_decision_id: String,
    approval_id: Option<String>,
    operation_intent_id: String,
    executor_fencing_token: Option<i64>,
    status: String,
    started_at: Option<String>,
    exit_code: Option<i32>,
    stdout_artifact_id: Option<String>,
    stderr_artifact_id: Option<String>,
    completed_at: Option<String>,
}

#[derive(Debug)]
pub(crate) struct StoredArtifact {
    pub id: String,
    pub task_id: String,
    pub bytes: Vec<u8>,
}

type StoredArtifactRow = (String, Option<String>, String, String, String, i64, String);

#[derive(Debug)]
struct ToolRequestEvidence {
    artifact: StoredArtifact,
    run_id: String,
    tool_name: String,
    actor_binding_digest: String,
}
