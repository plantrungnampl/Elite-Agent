use std::fs;
use std::path::{Component, Path, PathBuf};

use local_agent_terminal_application::{
    canonical_file_write_recovery_request, canonical_policy_binding_digest,
    parse_file_write_recovery_request, parse_tool_request, policy_request_for_tool,
    validate_tool_approval_request, ApprovalDigestPayload, AuthoritativeProcessBinding,
    AuthoritativeProcessTermination, AuthorizedToolExecutionClaim, CancellationReceipt,
    CanonicalEvidenceRef, DeniedToolExecution, DurableToolExecutionArtifact,
    DurableToolExecutionArtifacts, DurableToolExecutionReceipt, FileWritePreImage,
    FileWriteRecoveryCompletion, FileWriteRecoveryFailure, FileWriteRecoveryIntent,
    FileWriteRecoveryRequest, FileWriteRecoverySnapshot, FileWriteRecoveryState,
    FileWriteRecoveryStore, IdempotencyClass, ImmutableToolRequest, IncompleteToolExecution,
    JobReceipt, NewToolExecution, NewToolIntent, OperationIntentSnapshot, PolicyDecisionId,
    PolicyRequestBindingDigest, PortError, ProcessExecutionBindingStore, ProcessStatus,
    Retryability, SafeErrorClassification, SafeToolExecutionError, ToolExecutionCancellationClaim,
    ToolExecutionClaim, ToolExecutionClaimAuthority, ToolExecutionDenialRequest, ToolExecutionId,
    ToolExecutionOutput, ToolExecutionPostEffectReceipt, ToolExecutionRecoveryEvidence,
    ToolExecutionRecoveryState, ToolExecutionResolution, ToolExecutionStore,
    ToolExecutionStreamMetadata, ToolExecutionTerminal, ToolExecutionTerminalKind,
    VerifiedFileWriteCompensation, WorkspaceMutationRequest,
};
use local_agent_terminal_domain::{
    ArtifactId, FencingToken, PolicyEffect, ProjectId, RunId, Sequence, Sha256Digest, TaskId,
    Timestamp,
};
use rusqlite::{params, OptionalExtension, Transaction, TransactionBehavior};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::approval_store::{append_approval_event, parse_canonical_approval_payload};
use crate::event_store::{open_error_to_port, sqlite_error_to_port};
use crate::policy_store::{actor_json, digest_json, effect_name, resource_json};
use crate::workspace_store::{
    record_recovered_workspace_mutation_in_transaction, record_workspace_mutation_in_transaction,
    verify_evidence_ref_in_transaction,
};
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
    pub project_id: String,
    pub content_hash: String,
    pub storage_key: String,
    pub size_bytes: u64,
    pub bytes: Vec<u8>,
}

type StoredArtifactRow = (String, Option<String>, String, String, String, i64, String);

#[derive(Debug)]
struct ToolRequestEvidence {
    artifact: StoredArtifact,
    run_id: String,
    tool_name: String,
    fencing_token: Option<u64>,
}
