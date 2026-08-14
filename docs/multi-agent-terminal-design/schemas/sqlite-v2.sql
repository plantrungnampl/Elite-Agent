-- Local-First Multi-Agent Engineering Terminal
-- Authoritative pre-release clean-install schema v2, hardening revision v3.2.
-- The packaged checksum distinguishes this revision from the earlier v3 draft.
-- Runtime startup MUST independently set and verify foreign_keys=ON,
-- journal_mode=WAL, synchronous=FULL, busy_timeout, and defensive mode.

PRAGMA foreign_keys = ON;
PRAGMA journal_mode = WAL;
PRAGMA synchronous = FULL;
PRAGMA busy_timeout = 5000;
PRAGMA wal_autocheckpoint = 1000;

BEGIN IMMEDIATE;

CREATE TABLE schema_migrations (
    version INTEGER PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    applied_at TEXT NOT NULL,
    application_version TEXT NOT NULL,
    checksum TEXT NOT NULL CHECK (
        length(checksum) = 71
        AND substr(checksum, 1, 7) = 'sha256:'
        AND substr(checksum, 8) NOT GLOB '*[^0-9a-f]*'
    )
) STRICT;

CREATE TABLE projects (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    repository_path TEXT NOT NULL,
    repository_identity TEXT NOT NULL UNIQUE,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    policy_profile_id TEXT NOT NULL,
    artifact_root_mode TEXT NOT NULL
        CHECK (artifact_root_mode IN ('application_data', 'project_local')),
    artifact_root_path TEXT NOT NULL
) STRICT;

CREATE TABLE tasks (
    id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE RESTRICT,
    title TEXT NOT NULL,
    objective TEXT NOT NULL,
    phase TEXT NOT NULL CHECK (
        phase IN (
            'Intake',
            'ContextBuild',
            'ParallelAnalysis',
            'CrossReview',
            'PrePlanVerification',
            'Synthesis',
            'FinalObjection',
            'AwaitingPlanApproval',
            'Implementation',
            'Verification',
            'Repair',
            'FinalReview',
            'AwaitingCommitApproval',
            'LocalCommit',
            'WorkspaceDirty',
            'Completed',
            'Cancelled',
            'Failed'
        )
    ),
    condition TEXT NOT NULL CHECK (
        condition IN ('Active', 'Paused', 'Blocked', 'BudgetExhausted')
    ),
    operation_state TEXT NOT NULL CHECK (
        operation_state IN (
            'None',
            'AwaitingApproval',
            'Running',
            'Cancelling',
            'Indeterminate'
        )
    ),
    risk_level TEXT NOT NULL
        CHECK (risk_level IN ('low', 'medium', 'high', 'critical')),
    base_branch TEXT NOT NULL,
    base_commit TEXT NOT NULL CHECK (
        length(base_commit) IN (40, 64)
        AND base_commit NOT GLOB '*[^0-9a-f]*'
    ),
    task_branch TEXT,
    worktree_path TEXT,
    current_sequence INTEGER NOT NULL DEFAULT 0 CHECK (current_sequence >= 0),
    workspace_version INTEGER NOT NULL DEFAULT 0 CHECK (workspace_version >= 0),
    fencing_epoch INTEGER NOT NULL DEFAULT 0 CHECK (fencing_epoch >= 0),
    row_version INTEGER NOT NULL DEFAULT 0 CHECK (row_version >= 0),
    active_candidate_commit_oid TEXT CHECK (
        active_candidate_commit_oid IS NULL
        OR (
            length(active_candidate_commit_oid) IN (40, 64)
            AND active_candidate_commit_oid NOT GLOB '*[^0-9a-f]*'
        )
    ),
    active_candidate_tree TEXT CHECK (
        active_candidate_tree IS NULL
        OR (
            length(active_candidate_tree) IN (40, 64)
            AND active_candidate_tree NOT GLOB '*[^0-9a-f]*'
        )
    ),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    CHECK (
        (phase IN ('Completed', 'Cancelled', 'Failed')
            AND condition = 'Active'
            AND operation_state = 'None')
        OR phase NOT IN ('Completed', 'Cancelled', 'Failed')
    )
) STRICT;


CREATE TRIGGER tasks_fencing_epoch_monotonic
BEFORE UPDATE OF fencing_epoch ON tasks
FOR EACH ROW
WHEN NEW.fencing_epoch < OLD.fencing_epoch
BEGIN
    SELECT RAISE(ABORT, 'task fencing epoch cannot decrease');
END;

CREATE TRIGGER tasks_workspace_version_monotonic
BEFORE UPDATE OF workspace_version ON tasks
FOR EACH ROW
WHEN NEW.workspace_version < OLD.workspace_version
BEGIN
    SELECT RAISE(ABORT, 'workspace version cannot decrease');
END;

CREATE TRIGGER tasks_row_version_monotonic
BEFORE UPDATE ON tasks
FOR EACH ROW
WHEN NEW.row_version <> OLD.row_version + 1
BEGIN
    SELECT RAISE(ABORT, 'task row version must increase exactly by one for every update');
END;

CREATE TABLE events (
    event_id TEXT PRIMARY KEY,
    stream_id TEXT NOT NULL,
    sequence INTEGER NOT NULL CHECK (sequence >= 1),
    event_type TEXT NOT NULL,
    schema_version INTEGER NOT NULL CHECK (schema_version >= 1),
    actor_type TEXT NOT NULL CHECK (
        actor_type IN ('core', 'user', 'agent', 'tool', 'reconciler', 'system')
    ),
    actor_id TEXT NOT NULL,
    observation_class TEXT NOT NULL CHECK (
        observation_class IN (
            'core_observed',
            'tool_verified',
            'provider_reported',
            'agent_claimed',
            'user_asserted'
        )
    ),
    payload_json TEXT NOT NULL CHECK (json_valid(payload_json)),
    metadata_json TEXT NOT NULL CHECK (json_valid(metadata_json)),
    causation_id TEXT,
    correlation_id TEXT NOT NULL,
    created_at TEXT NOT NULL,
    UNIQUE (stream_id, sequence)
) STRICT;

CREATE TRIGGER events_sequence_contiguous
BEFORE INSERT ON events
FOR EACH ROW
BEGIN
    SELECT CASE
        WHEN NEW.sequence <> COALESCE(
            (
                SELECT MAX(sequence) + 1
                FROM events
                WHERE stream_id = NEW.stream_id
            ),
            1
        )
        THEN RAISE(ABORT, 'event sequence must be contiguous')
    END;
END;

CREATE TRIGGER events_update_forbidden
BEFORE UPDATE ON events
FOR EACH ROW
BEGIN
    SELECT RAISE(ABORT, 'events are append-only');
END;

CREATE TRIGGER events_delete_forbidden
BEFORE DELETE ON events
FOR EACH ROW
BEGIN
    SELECT RAISE(ABORT, 'events are append-only');
END;


CREATE TABLE artifacts (
    id TEXT PRIMARY KEY,
    task_id TEXT REFERENCES tasks(id) ON DELETE RESTRICT,
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE RESTRICT,
    artifact_type TEXT NOT NULL,
    logical_path TEXT NOT NULL,
    content_hash TEXT NOT NULL CHECK (
        length(content_hash) = 71
        AND substr(content_hash, 1, 7) = 'sha256:'
        AND substr(content_hash, 8) NOT GLOB '*[^0-9a-f]*'
    ),
    storage_key TEXT NOT NULL,
    size_bytes INTEGER NOT NULL CHECK (size_bytes >= 0),
    mime_type TEXT,
    availability TEXT NOT NULL CHECK (
        availability IN ('reserved', 'available', 'quarantined', 'missing')
    ),
    created_by_type TEXT NOT NULL CHECK (
        created_by_type IN ('core', 'user', 'agent', 'tool', 'reconciler')
    ),
    created_by_id TEXT NOT NULL,
    created_at TEXT NOT NULL,
    supersedes TEXT REFERENCES artifacts(id) ON DELETE RESTRICT,
    verification_state TEXT NOT NULL CHECK (
        verification_state IN (
            'unverified',
            'hash_verified',
            'tool_verified',
            'user_approved',
            'rejected'
        )
    ),
    UNIQUE (project_id, logical_path, content_hash)
) STRICT;

CREATE TABLE artifact_operations (
    id TEXT PRIMARY KEY,
    artifact_id TEXT NOT NULL REFERENCES artifacts(id) ON DELETE RESTRICT,
    temp_name TEXT NOT NULL,
    expected_hash TEXT NOT NULL CHECK (
        length(expected_hash) = 71
        AND substr(expected_hash, 1, 7) = 'sha256:'
        AND substr(expected_hash, 8) NOT GLOB '*[^0-9a-f]*'
    ),
    expected_size INTEGER NOT NULL CHECK (expected_size >= 0),
    status TEXT NOT NULL CHECK (
        status IN (
            'intent',
            'staging',
            'renamed',
            'completed',
            'aborted',
            'quarantined'
        )
    ),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    completed_at TEXT,
    error_json TEXT CHECK (error_json IS NULL OR json_valid(error_json))
) STRICT;

CREATE TABLE agent_descriptors (
    id TEXT PRIMARY KEY,
    display_name TEXT NOT NULL,
    transport_type TEXT NOT NULL,
    trust_tier TEXT NOT NULL CHECK (
        trust_tier IN (
            'core_adapter',
            'brokered_process',
            'isolated_worker',
            'full_access_legacy'
        )
    ),
    manifest_json TEXT NOT NULL CHECK (json_valid(manifest_json)),
    manifest_digest TEXT NOT NULL CHECK (
        length(manifest_digest) = 71
        AND substr(manifest_digest, 1, 7) = 'sha256:'
        AND substr(manifest_digest, 8) NOT GLOB '*[^0-9a-f]*'
    ),
    executable_digest TEXT CHECK (
        executable_digest IS NULL
        OR (
            length(executable_digest) = 71
            AND substr(executable_digest, 1, 7) = 'sha256:'
            AND substr(executable_digest, 8) NOT GLOB '*[^0-9a-f]*'
        )
    ),
    active_attestation_id TEXT,
    enabled INTEGER NOT NULL CHECK (enabled IN (0, 1)),
    last_health_status TEXT,
    updated_at TEXT NOT NULL,
    CHECK (trust_tier <> 'full_access_legacy' OR enabled = 0),
    CHECK (
        trust_tier = 'core_adapter'
        OR enabled = 0
        OR active_attestation_id IS NOT NULL
    )
) STRICT;

CREATE TABLE containment_attestations (
    id TEXT PRIMARY KEY,
    agent_descriptor_id TEXT NOT NULL
        REFERENCES agent_descriptors(id) ON DELETE RESTRICT,
    executable_digest TEXT NOT NULL CHECK (
        length(executable_digest) = 71
        AND substr(executable_digest, 1, 7) = 'sha256:'
        AND substr(executable_digest, 8) NOT GLOB '*[^0-9a-f]*'
    ),
    manifest_digest TEXT NOT NULL CHECK (
        length(manifest_digest) = 71
        AND substr(manifest_digest, 1, 7) = 'sha256:'
        AND substr(manifest_digest, 8) NOT GLOB '*[^0-9a-f]*'
    ),
    launcher_digest TEXT NOT NULL CHECK (
        length(launcher_digest) = 71
        AND substr(launcher_digest, 1, 7) = 'sha256:'
        AND substr(launcher_digest, 8) NOT GLOB '*[^0-9a-f]*'
    ),
    isolation_profile_digest TEXT NOT NULL CHECK (
        length(isolation_profile_digest) = 71
        AND substr(isolation_profile_digest, 1, 7) = 'sha256:'
        AND substr(isolation_profile_digest, 8) NOT GLOB '*[^0-9a-f]*'
    ),
    os_build TEXT NOT NULL,
    architecture TEXT NOT NULL,
    suite_version TEXT NOT NULL,
    evidence_artifact_id TEXT NOT NULL REFERENCES artifacts(id) ON DELETE RESTRICT,
    verified_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    UNIQUE (
        agent_descriptor_id, executable_digest, manifest_digest,
        launcher_digest, isolation_profile_digest, os_build,
        architecture, suite_version
    )
) STRICT;

CREATE TABLE containment_attestation_revocations (
    id TEXT PRIMARY KEY,
    attestation_id TEXT NOT NULL
        REFERENCES containment_attestations(id) ON DELETE RESTRICT,
    reason TEXT NOT NULL,
    revoked_at TEXT NOT NULL,
    UNIQUE (attestation_id)
) STRICT;

CREATE TRIGGER containment_attestations_update_forbidden
BEFORE UPDATE ON containment_attestations
FOR EACH ROW
BEGIN
    SELECT RAISE(ABORT, 'containment attestations are immutable');
END;

CREATE TRIGGER containment_attestations_delete_forbidden
BEFORE DELETE ON containment_attestations
FOR EACH ROW
BEGIN
    SELECT RAISE(ABORT, 'containment attestations are retained');
END;

CREATE TRIGGER containment_revocations_update_forbidden
BEFORE UPDATE ON containment_attestation_revocations
FOR EACH ROW
BEGIN
    SELECT RAISE(ABORT, 'attestation revocations are immutable');
END;

CREATE TRIGGER containment_revocations_delete_forbidden
BEFORE DELETE ON containment_attestation_revocations
FOR EACH ROW
BEGIN
    SELECT RAISE(ABORT, 'attestation revocations are retained');
END;

CREATE TRIGGER agent_descriptor_attestation_insert
BEFORE INSERT ON agent_descriptors
FOR EACH ROW
WHEN NEW.enabled = 1 AND NEW.trust_tier <> 'core_adapter'
BEGIN
    SELECT CASE WHEN NOT EXISTS (
        SELECT 1
        FROM containment_attestations a
        LEFT JOIN containment_attestation_revocations r
          ON r.attestation_id = a.id
        WHERE a.id = NEW.active_attestation_id
          AND a.agent_descriptor_id = NEW.id
          AND a.executable_digest = NEW.executable_digest
          AND a.manifest_digest = NEW.manifest_digest
          AND a.verified_at <= NEW.updated_at
          AND a.expires_at > NEW.updated_at
          AND r.id IS NULL
    ) THEN RAISE(ABORT, 'external agent requires a current exact-tuple containment attestation') END;
END;

CREATE TRIGGER agent_descriptor_attestation_update
BEFORE UPDATE OF enabled, trust_tier, executable_digest, manifest_digest, active_attestation_id, updated_at
ON agent_descriptors
FOR EACH ROW
WHEN NEW.enabled = 1 AND NEW.trust_tier <> 'core_adapter'
BEGIN
    SELECT CASE WHEN NOT EXISTS (
        SELECT 1
        FROM containment_attestations a
        LEFT JOIN containment_attestation_revocations r
          ON r.attestation_id = a.id
        WHERE a.id = NEW.active_attestation_id
          AND a.agent_descriptor_id = NEW.id
          AND a.executable_digest = NEW.executable_digest
          AND a.manifest_digest = NEW.manifest_digest
          AND a.verified_at <= NEW.updated_at
          AND a.expires_at > NEW.updated_at
          AND r.id IS NULL
    ) THEN RAISE(ABORT, 'external agent requires a current exact-tuple containment attestation') END;
END;

CREATE TABLE context_packages (
    id TEXT PRIMARY KEY,
    task_id TEXT NOT NULL REFERENCES tasks(id) ON DELETE RESTRICT,
    agent_id TEXT NOT NULL REFERENCES agent_descriptors(id) ON DELETE RESTRICT,
    role TEXT NOT NULL,
    objective TEXT NOT NULL,
    manifest_artifact_id TEXT NOT NULL
        REFERENCES artifacts(id) ON DELETE RESTRICT,
    effective_content_artifact_id TEXT NOT NULL
        REFERENCES artifacts(id) ON DELETE RESTRICT,
    content_hash TEXT NOT NULL CHECK (
        length(content_hash) = 71
        AND substr(content_hash, 1, 7) = 'sha256:'
        AND substr(content_hash, 8) NOT GLOB '*[^0-9a-f]*'
    ),
    policy_snapshot_digest TEXT NOT NULL CHECK (
        length(policy_snapshot_digest) = 71
        AND substr(policy_snapshot_digest, 1, 7) = 'sha256:'
        AND substr(policy_snapshot_digest, 8) NOT GLOB '*[^0-9a-f]*'
    ),
    prompt_template_version TEXT NOT NULL,
    retrieval_pipeline_version TEXT NOT NULL,
    created_at TEXT NOT NULL
) STRICT;

CREATE TRIGGER context_package_scope_insert
BEFORE INSERT ON context_packages
FOR EACH ROW
BEGIN
    SELECT CASE WHEN NOT EXISTS (
        SELECT 1 FROM tasks t
        JOIN artifacts m ON m.id = NEW.manifest_artifact_id
        JOIN artifacts e ON e.id = NEW.effective_content_artifact_id
        WHERE t.id = NEW.task_id
          AND m.project_id = t.project_id
          AND e.project_id = t.project_id
          AND (m.task_id IS NULL OR m.task_id = NEW.task_id)
          AND (e.task_id IS NULL OR e.task_id = NEW.task_id)
          AND e.content_hash = NEW.content_hash
    ) THEN RAISE(ABORT, 'context package artifacts must belong to task project and hash') END;
END;

CREATE TABLE agent_runs (
    id TEXT PRIMARY KEY,
    task_id TEXT NOT NULL REFERENCES tasks(id) ON DELETE RESTRICT,
    agent_id TEXT NOT NULL REFERENCES agent_descriptors(id) ON DELETE RESTRICT,
    role TEXT NOT NULL,
    phase TEXT NOT NULL,
    status TEXT NOT NULL CHECK (
        status IN (
            'created',
            'accepted',
            'running',
            'succeeded',
            'failed',
            'cancelled_cleanly',
            'terminated',
            'interrupted',
            'indeterminate'
        )
    ),
    context_package_id TEXT NOT NULL
        REFERENCES context_packages(id) ON DELETE RESTRICT,
    idempotency_key TEXT NOT NULL UNIQUE,
    connection_binding_digest TEXT NOT NULL CHECK (
        length(connection_binding_digest) = 71
        AND substr(connection_binding_digest, 1, 7) = 'sha256:'
        AND substr(connection_binding_digest, 8) NOT GLOB '*[^0-9a-f]*'
    ),
    run_config_artifact_id TEXT NOT NULL
        REFERENCES artifacts(id) ON DELETE RESTRICT,
    supersedes_run_id TEXT REFERENCES agent_runs(id) ON DELETE RESTRICT,
    started_at TEXT,
    completed_at TEXT,
    provider_usage_json TEXT CHECK (
        provider_usage_json IS NULL OR json_valid(provider_usage_json)
    ),
    core_usage_json TEXT CHECK (
        core_usage_json IS NULL OR json_valid(core_usage_json)
    ),
    estimated_cost_microunits INTEGER CHECK (
        estimated_cost_microunits IS NULL OR estimated_cost_microunits >= 0
    ),
    error_json TEXT CHECK (error_json IS NULL OR json_valid(error_json))
) STRICT;

CREATE TRIGGER agent_runs_scope_insert
BEFORE INSERT ON agent_runs
FOR EACH ROW
BEGIN
    SELECT CASE WHEN NOT EXISTS (
        SELECT 1
        FROM context_packages cp
        JOIN tasks t ON t.id = NEW.task_id
        JOIN artifacts cfg ON cfg.id = NEW.run_config_artifact_id
        WHERE cp.id = NEW.context_package_id
          AND cp.task_id = NEW.task_id
          AND cp.agent_id = NEW.agent_id
          AND cp.role = NEW.role
          AND cfg.project_id = t.project_id
          AND (cfg.task_id IS NULL OR cfg.task_id = NEW.task_id)
    ) THEN RAISE(ABORT, 'agent run scope is incoherent') END;
    SELECT CASE WHEN NEW.supersedes_run_id IS NOT NULL AND NOT EXISTS (
        SELECT 1 FROM agent_runs prior
        WHERE prior.id = NEW.supersedes_run_id
          AND prior.task_id = NEW.task_id
          AND prior.agent_id = NEW.agent_id
    ) THEN RAISE(ABORT, 'superseded agent run scope is incoherent') END;
END;

CREATE TRIGGER agent_runs_identity_immutable
BEFORE UPDATE OF task_id, agent_id, role, phase, context_package_id, idempotency_key,
    connection_binding_digest, run_config_artifact_id, supersedes_run_id
ON agent_runs
FOR EACH ROW
BEGIN
    SELECT RAISE(ABORT, 'agent run identity is immutable');
END;

CREATE TRIGGER agent_runs_terminal_irreversible
BEFORE UPDATE OF status ON agent_runs
FOR EACH ROW
WHEN OLD.status IN (
    'succeeded', 'failed', 'cancelled_cleanly', 'terminated', 'indeterminate'
) AND NEW.status <> OLD.status
BEGIN
    SELECT RAISE(ABORT, 'terminal agent run status is irreversible');
END;

CREATE TABLE messages (
    id TEXT PRIMARY KEY,
    task_id TEXT NOT NULL REFERENCES tasks(id) ON DELETE RESTRICT,
    run_id TEXT NOT NULL REFERENCES agent_runs(id) ON DELETE RESTRICT,
    thread_id TEXT NOT NULL,
    message_type TEXT NOT NULL,
    reply_to TEXT REFERENCES messages(id) ON DELETE RESTRICT,
    content_artifact_id TEXT NOT NULL
        REFERENCES artifacts(id) ON DELETE RESTRICT,
    status TEXT NOT NULL CHECK (
        status IN (
            'accepted',
            'superseded',
            'retracted',
            'rejected',
            'malformed'
        )
    ),
    core_received_at TEXT NOT NULL,
    superseded_by TEXT REFERENCES messages(id) ON DELETE RESTRICT
) STRICT;

CREATE TRIGGER messages_scope_insert
BEFORE INSERT ON messages
FOR EACH ROW
BEGIN
    SELECT CASE WHEN NOT EXISTS (
        SELECT 1
        FROM agent_runs r
        JOIN tasks t ON t.id = NEW.task_id
        JOIN artifacts a ON a.id = NEW.content_artifact_id
        WHERE r.id = NEW.run_id
          AND r.task_id = NEW.task_id
          AND a.project_id = t.project_id
          AND (a.task_id IS NULL OR a.task_id = NEW.task_id)
    ) THEN RAISE(ABORT, 'message scope is incoherent') END;
    SELECT CASE WHEN NEW.reply_to IS NOT NULL AND NOT EXISTS (
        SELECT 1 FROM messages parent
        WHERE parent.id = NEW.reply_to
          AND parent.task_id = NEW.task_id
          AND parent.thread_id = NEW.thread_id
    ) THEN RAISE(ABORT, 'message reply scope is incoherent') END;
    SELECT CASE WHEN NEW.superseded_by IS NOT NULL AND NOT EXISTS (
        SELECT 1 FROM messages replacement
        WHERE replacement.id = NEW.superseded_by
          AND replacement.task_id = NEW.task_id
          AND replacement.thread_id = NEW.thread_id
    ) THEN RAISE(ABORT, 'message supersession scope is incoherent') END;
END;

CREATE TRIGGER messages_identity_immutable
BEFORE UPDATE OF task_id, run_id, thread_id, message_type, reply_to,
    content_artifact_id, core_received_at
ON messages
FOR EACH ROW
BEGIN
    SELECT RAISE(ABORT, 'message identity is immutable');
END;

CREATE TRIGGER messages_supersession_scope_update
BEFORE UPDATE OF superseded_by ON messages
FOR EACH ROW
WHEN NEW.superseded_by IS NOT NULL
BEGIN
    SELECT CASE WHEN NOT EXISTS (
        SELECT 1 FROM messages replacement
        WHERE replacement.id = NEW.superseded_by
          AND replacement.id <> OLD.id
          AND replacement.task_id = OLD.task_id
          AND replacement.thread_id = OLD.thread_id
    ) THEN RAISE(ABORT, 'message supersession scope is incoherent') END;
END;

CREATE TABLE approvals (
    id TEXT PRIMARY KEY,
    task_id TEXT NOT NULL REFERENCES tasks(id) ON DELETE RESTRICT,
    operation_intent_id TEXT NOT NULL,
    approval_type TEXT NOT NULL CHECK (
        approval_type IN ('plan', 'tool', 'policy_exception', 'final_commit')
    ),
    schema_version TEXT NOT NULL,
    operation_digest TEXT NOT NULL CHECK (
        length(operation_digest) = 71
        AND substr(operation_digest, 1, 7) = 'sha256:'
        AND substr(operation_digest, 8) NOT GLOB '*[^0-9a-f]*'
    ),
    actor_binding_digest TEXT NOT NULL CHECK (
        length(actor_binding_digest) = 71
        AND substr(actor_binding_digest, 1, 7) = 'sha256:'
        AND substr(actor_binding_digest, 8) NOT GLOB '*[^0-9a-f]*'
    ),
    nonce TEXT NOT NULL UNIQUE,
    status TEXT NOT NULL CHECK (
        status IN ('pending', 'granted', 'denied', 'expired', 'invalidated')
    ),
    requested_at TEXT NOT NULL,
    resolved_at TEXT,
    expires_at TEXT NOT NULL,
    request_artifact_id TEXT NOT NULL
        REFERENCES artifacts(id) ON DELETE RESTRICT,
    invalidation_reason TEXT,
    UNIQUE (task_id, operation_intent_id, operation_digest, approval_type)
) STRICT;

CREATE TABLE approval_decision_receipts (
    id TEXT PRIMARY KEY,
    approval_id TEXT NOT NULL UNIQUE REFERENCES approvals(id) ON DELETE RESTRICT,
    task_id TEXT NOT NULL REFERENCES tasks(id) ON DELETE RESTRICT,
    operation_intent_id TEXT NOT NULL,
    operation_digest TEXT NOT NULL CHECK (
        length(operation_digest) = 71
        AND substr(operation_digest, 1, 7) = 'sha256:'
        AND substr(operation_digest, 8) NOT GLOB '*[^0-9a-f]*'
    ),
    actor_binding_digest TEXT NOT NULL CHECK (
        length(actor_binding_digest) = 71
        AND substr(actor_binding_digest, 1, 7) = 'sha256:'
        AND substr(actor_binding_digest, 8) NOT GLOB '*[^0-9a-f]*'
    ),
    nonce TEXT NOT NULL UNIQUE,
    decision TEXT NOT NULL CHECK (decision IN ('granted', 'denied')),
    credential_evidence_artifact_id TEXT NOT NULL
        REFERENCES artifacts(id) ON DELETE RESTRICT,
    decided_at TEXT NOT NULL,
    receipt_digest TEXT NOT NULL UNIQUE CHECK (
        length(receipt_digest) = 71
        AND substr(receipt_digest, 1, 7) = 'sha256:'
        AND substr(receipt_digest, 8) NOT GLOB '*[^0-9a-f]*'
    )
) STRICT;

CREATE TABLE approval_effect_consumptions (
    id TEXT PRIMARY KEY,
    approval_receipt_id TEXT NOT NULL
        REFERENCES approval_decision_receipts(id) ON DELETE RESTRICT,
    operation_intent_id TEXT NOT NULL,
    repository_identity_digest TEXT,
    expected_ref TEXT,
    expected_old_oid TEXT,
    candidate_commit_oid TEXT,
    consumed_at TEXT NOT NULL,
    UNIQUE (approval_receipt_id, operation_intent_id)
) STRICT;

CREATE TABLE final_commit_candidates (
    id TEXT PRIMARY KEY,
    task_id TEXT NOT NULL REFERENCES tasks(id) ON DELETE RESTRICT,
    operation_intent_id TEXT NOT NULL UNIQUE,
    repository_identity_digest TEXT NOT NULL CHECK (
        length(repository_identity_digest) = 71
        AND substr(repository_identity_digest, 1, 7) = 'sha256:'
        AND substr(repository_identity_digest, 8) NOT GLOB '*[^0-9a-f]*'
    ),
    expected_ref TEXT NOT NULL,
    expected_old_oid TEXT NOT NULL CHECK (
        length(expected_old_oid) IN (40, 64)
        AND expected_old_oid NOT GLOB '*[^0-9a-f]*'
    ),
    candidate_tree_oid TEXT NOT NULL CHECK (
        length(candidate_tree_oid) IN (40, 64)
        AND candidate_tree_oid NOT GLOB '*[^0-9a-f]*'
    ),
    candidate_commit_oid TEXT NOT NULL CHECK (
        length(candidate_commit_oid) IN (40, 64)
        AND candidate_commit_oid NOT GLOB '*[^0-9a-f]*'
    ),
    commit_metadata_digest TEXT NOT NULL CHECK (
        length(commit_metadata_digest) = 71
        AND substr(commit_metadata_digest, 1, 7) = 'sha256:'
        AND substr(commit_metadata_digest, 8) NOT GLOB '*[^0-9a-f]*'
    ),
    verification_set_digest TEXT NOT NULL CHECK (
        length(verification_set_digest) = 71
        AND substr(verification_set_digest, 1, 7) = 'sha256:'
        AND substr(verification_set_digest, 8) NOT GLOB '*[^0-9a-f]*'
    ),
    created_at TEXT NOT NULL
) STRICT;

CREATE TRIGGER approvals_identity_immutable
BEFORE UPDATE OF task_id, operation_intent_id, approval_type, schema_version,
    operation_digest, actor_binding_digest, nonce, requested_at, expires_at, request_artifact_id
ON approvals
FOR EACH ROW
BEGIN
    SELECT RAISE(ABORT, 'approval request identity is immutable');
END;

CREATE TRIGGER approvals_terminal_irreversible
BEFORE UPDATE OF status ON approvals
FOR EACH ROW
WHEN OLD.status <> 'pending' AND NEW.status <> OLD.status
BEGIN
    SELECT RAISE(ABORT, 'resolved approval cannot change status');
END;

CREATE TRIGGER approvals_resolution_requires_receipt
BEFORE UPDATE OF status ON approvals
FOR EACH ROW
WHEN OLD.status = 'pending' AND NEW.status IN ('granted', 'denied')
BEGIN
    SELECT CASE WHEN NOT EXISTS (
        SELECT 1 FROM approval_decision_receipts r
        WHERE r.approval_id = OLD.id
          AND r.task_id = OLD.task_id
          AND r.operation_intent_id = OLD.operation_intent_id
          AND r.operation_digest = OLD.operation_digest
          AND r.actor_binding_digest = OLD.actor_binding_digest
          AND r.nonce = OLD.nonce
          AND r.decision = NEW.status
    ) THEN RAISE(ABORT, 'approval resolution requires matching immutable decision receipt') END;
END;

CREATE TRIGGER approval_receipts_update_forbidden
BEFORE UPDATE ON approval_decision_receipts
FOR EACH ROW
BEGIN
    SELECT RAISE(ABORT, 'approval decision receipts are immutable');
END;

CREATE TRIGGER approval_receipts_delete_forbidden
BEFORE DELETE ON approval_decision_receipts
FOR EACH ROW
BEGIN
    SELECT RAISE(ABORT, 'approval decision receipts are retained');
END;

CREATE TRIGGER approval_consumptions_update_forbidden
BEFORE UPDATE ON approval_effect_consumptions
FOR EACH ROW
BEGIN
    SELECT RAISE(ABORT, 'approval effect consumption is immutable');
END;

CREATE TRIGGER approval_consumptions_delete_forbidden
BEFORE DELETE ON approval_effect_consumptions
FOR EACH ROW
BEGIN
    SELECT RAISE(ABORT, 'approval effect consumption is retained');
END;

CREATE TRIGGER final_commit_candidates_update_forbidden
BEFORE UPDATE ON final_commit_candidates
FOR EACH ROW
BEGIN
    SELECT RAISE(ABORT, 'final commit candidate is immutable');
END;

CREATE TRIGGER final_commit_candidates_delete_forbidden
BEFORE DELETE ON final_commit_candidates
FOR EACH ROW
BEGIN
    SELECT RAISE(ABORT, 'final commit candidate is retained');
END;

CREATE TABLE policy_decisions (
    id TEXT PRIMARY KEY,
    task_id TEXT REFERENCES tasks(id) ON DELETE RESTRICT,
    actor_json TEXT NOT NULL CHECK (json_valid(actor_json)),
    actor_binding_digest TEXT NOT NULL CHECK (
        length(actor_binding_digest) = 71
        AND substr(actor_binding_digest, 1, 7) = 'sha256:'
        AND substr(actor_binding_digest, 8) NOT GLOB '*[^0-9a-f]*'
    ),
    action TEXT NOT NULL,
    resource_json TEXT NOT NULL CHECK (json_valid(resource_json)),
    resource_digest TEXT NOT NULL CHECK (
        length(resource_digest) = 71
        AND substr(resource_digest, 1, 7) = 'sha256:'
        AND substr(resource_digest, 8) NOT GLOB '*[^0-9a-f]*'
    ),
    purpose TEXT NOT NULL,
    workflow_phase TEXT NOT NULL,
    effect TEXT NOT NULL CHECK (
        effect IN ('allow', 'deny', 'require_approval', 'allow_with_redaction')
    ),
    matched_rules_json TEXT NOT NULL CHECK (json_valid(matched_rules_json)),
    policy_snapshot_digest TEXT NOT NULL CHECK (
        length(policy_snapshot_digest) = 71
        AND substr(policy_snapshot_digest, 1, 7) = 'sha256:'
        AND substr(policy_snapshot_digest, 8) NOT GLOB '*[^0-9a-f]*'
    ),
    operation_digest TEXT NOT NULL CHECK (
        length(operation_digest) = 71
        AND substr(operation_digest, 1, 7) = 'sha256:'
        AND substr(operation_digest, 8) NOT GLOB '*[^0-9a-f]*'
    ),
    created_at TEXT NOT NULL,
    expires_at TEXT,
    approval_id TEXT REFERENCES approvals(id) ON DELETE RESTRICT
) STRICT;

CREATE TABLE context_package_policy_decisions (
    package_id TEXT NOT NULL
        REFERENCES context_packages(id) ON DELETE RESTRICT,
    policy_decision_id TEXT NOT NULL
        REFERENCES policy_decisions(id) ON DELETE RESTRICT,
    PRIMARY KEY (package_id, policy_decision_id)
) WITHOUT ROWID, STRICT;

CREATE TABLE operation_intents (
    id TEXT PRIMARY KEY,
    task_id TEXT NOT NULL REFERENCES tasks(id) ON DELETE RESTRICT,
    run_id TEXT REFERENCES agent_runs(id) ON DELETE RESTRICT,
    operation_kind TEXT NOT NULL,
    idempotency_class TEXT NOT NULL CHECK (
        idempotency_class IN ('idempotent', 'queryable', 'non_repeatable')
    ),
    idempotency_key TEXT NOT NULL UNIQUE,
    canonical_request_artifact_id TEXT NOT NULL
        REFERENCES artifacts(id) ON DELETE RESTRICT,
    operation_digest TEXT NOT NULL CHECK (
        length(operation_digest) = 71
        AND substr(operation_digest, 1, 7) = 'sha256:'
        AND substr(operation_digest, 8) NOT GLOB '*[^0-9a-f]*'
    ),
    actor_binding_digest TEXT NOT NULL CHECK (
        length(actor_binding_digest) = 71
        AND substr(actor_binding_digest, 1, 7) = 'sha256:'
        AND substr(actor_binding_digest, 8) NOT GLOB '*[^0-9a-f]*'
    ),
    status TEXT NOT NULL CHECK (
        status IN (
            'pending', 'claimed', 'started', 'succeeded', 'failed',
            'interrupted', 'indeterminate', 'cancelled'
        )
    ),
    current_attempt_no INTEGER NOT NULL DEFAULT 0 CHECK (current_attempt_no >= 0),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE (id, task_id, operation_digest, actor_binding_digest)
) STRICT;

CREATE TABLE operation_attempts (
    id TEXT PRIMARY KEY,
    operation_intent_id TEXT NOT NULL REFERENCES operation_intents(id) ON DELETE RESTRICT,
    task_id TEXT NOT NULL REFERENCES tasks(id) ON DELETE RESTRICT,
    attempt_no INTEGER NOT NULL CHECK (attempt_no >= 1),
    owner_run_id TEXT REFERENCES agent_runs(id) ON DELETE RESTRICT,
    fencing_token INTEGER,
    policy_decision_id TEXT NOT NULL REFERENCES policy_decisions(id) ON DELETE RESTRICT,
    approval_id TEXT REFERENCES approvals(id) ON DELETE RESTRICT,
    status TEXT NOT NULL CHECK (
        status IN ('claimed', 'started', 'succeeded', 'failed', 'interrupted', 'indeterminate', 'cancelled')
    ),
    external_request_id TEXT,
    boundary_crossed_at TEXT,
    started_at TEXT NOT NULL,
    terminal_at TEXT,
    result_artifact_id TEXT REFERENCES artifacts(id) ON DELETE RESTRICT,
    receipt_artifact_id TEXT REFERENCES artifacts(id) ON DELETE RESTRICT,
    error_artifact_id TEXT REFERENCES artifacts(id) ON DELETE RESTRICT,
    UNIQUE (operation_intent_id, attempt_no),
    UNIQUE (id, operation_intent_id, task_id),
    CHECK (fencing_token IS NULL OR fencing_token >= 1),
    CHECK (
        status IN ('claimed', 'started')
        OR terminal_at IS NOT NULL
    )
) STRICT;

CREATE UNIQUE INDEX operation_attempts_one_active
ON operation_attempts(operation_intent_id)
WHERE status IN ('claimed', 'started');

CREATE TABLE tool_executions (
    id TEXT PRIMARY KEY,
    task_id TEXT NOT NULL REFERENCES tasks(id) ON DELETE RESTRICT,
    run_id TEXT REFERENCES agent_runs(id) ON DELETE RESTRICT,
    request_id TEXT NOT NULL,
    tool_name TEXT NOT NULL,
    arguments_artifact_id TEXT NOT NULL REFERENCES artifacts(id) ON DELETE RESTRICT,
    policy_decision_id TEXT NOT NULL REFERENCES policy_decisions(id) ON DELETE RESTRICT,
    approval_id TEXT REFERENCES approvals(id) ON DELETE RESTRICT,
    operation_intent_id TEXT NOT NULL REFERENCES operation_intents(id) ON DELETE RESTRICT,
    operation_attempt_id TEXT NOT NULL UNIQUE REFERENCES operation_attempts(id) ON DELETE RESTRICT,
    executor_fencing_token INTEGER CHECK (
        executor_fencing_token IS NULL OR executor_fencing_token >= 1
    ),
    status TEXT NOT NULL CHECK (
        status IN ('pending', 'running', 'succeeded', 'failed', 'terminated', 'interrupted', 'indeterminate', 'denied')
    ),
    started_at TEXT,
    completed_at TEXT,
    exit_code INTEGER,
    stdout_artifact_id TEXT REFERENCES artifacts(id) ON DELETE RESTRICT,
    stderr_artifact_id TEXT REFERENCES artifacts(id) ON DELETE RESTRICT,
    UNIQUE (run_id, request_id)
) STRICT;

CREATE TABLE executor_leases (
    id TEXT PRIMARY KEY,
    task_id TEXT NOT NULL REFERENCES tasks(id) ON DELETE RESTRICT,
    holder_run_id TEXT NOT NULL REFERENCES agent_runs(id) ON DELETE RESTRICT,
    fencing_token INTEGER NOT NULL CHECK (fencing_token >= 1),
    status TEXT NOT NULL CHECK (status IN ('active', 'released', 'expired', 'revoked')),
    acquired_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    released_at TEXT,
    UNIQUE (task_id, fencing_token)
) STRICT;

CREATE UNIQUE INDEX executor_leases_one_active
ON executor_leases(task_id)
WHERE status = 'active';

CREATE TABLE protocol_requests (
    connection_id TEXT NOT NULL,
    request_id TEXT NOT NULL,
    method TEXT NOT NULL,
    request_digest TEXT NOT NULL CHECK (
        length(request_digest) = 71
        AND substr(request_digest, 1, 7) = 'sha256:'
        AND substr(request_digest, 8) NOT GLOB '*[^0-9a-f]*'
    ),
    task_id TEXT REFERENCES tasks(id) ON DELETE RESTRICT,
    run_id TEXT REFERENCES agent_runs(id) ON DELETE RESTRICT,
    status TEXT NOT NULL CHECK (status IN ('pending', 'completed', 'failed')),
    response_artifact_id TEXT REFERENCES artifacts(id) ON DELETE RESTRICT,
    created_at TEXT NOT NULL,
    completed_at TEXT,
    PRIMARY KEY (connection_id, request_id)
) WITHOUT ROWID, STRICT;

CREATE TABLE protocol_stream_heads (
    connection_id TEXT NOT NULL,
    run_id TEXT NOT NULL REFERENCES agent_runs(id) ON DELETE RESTRICT,
    channel TEXT NOT NULL,
    last_sequence INTEGER NOT NULL CHECK (last_sequence >= 0),
    PRIMARY KEY (connection_id, run_id, channel)
) WITHOUT ROWID, STRICT;

CREATE TRIGGER operation_intents_identity_immutable
BEFORE UPDATE OF task_id, run_id, operation_kind, idempotency_class, idempotency_key,
    canonical_request_artifact_id, operation_digest, actor_binding_digest, created_at
ON operation_intents
FOR EACH ROW
BEGIN
    SELECT RAISE(ABORT, 'operation intent identity is immutable');
END;

CREATE TRIGGER operation_intents_attempt_monotonic
BEFORE UPDATE OF current_attempt_no ON operation_intents
FOR EACH ROW
WHEN NEW.current_attempt_no NOT IN (OLD.current_attempt_no, OLD.current_attempt_no + 1)
BEGIN
    SELECT RAISE(ABORT, 'operation attempt number may only stay or increase by one');
END;

CREATE TRIGGER operation_intents_terminal_irreversible
BEFORE UPDATE OF status ON operation_intents
FOR EACH ROW
WHEN OLD.status IN ('succeeded', 'failed', 'indeterminate', 'cancelled')
  AND NEW.status <> OLD.status
BEGIN
    SELECT RAISE(ABORT, 'terminal operation intent status is irreversible');
END;

CREATE TRIGGER operation_attempt_insert_scope
BEFORE INSERT ON operation_attempts
FOR EACH ROW
BEGIN
    SELECT CASE WHEN NOT EXISTS (
        SELECT 1 FROM operation_intents i
        WHERE i.id = NEW.operation_intent_id
          AND i.task_id = NEW.task_id
          AND NEW.attempt_no = i.current_attempt_no + 1
    ) THEN RAISE(ABORT, 'attempt must belong to intent task and be next attempt') END;
    SELECT CASE WHEN NEW.owner_run_id IS NOT NULL AND NOT EXISTS (
        SELECT 1 FROM agent_runs r
        WHERE r.id = NEW.owner_run_id AND r.task_id = NEW.task_id
    ) THEN RAISE(ABORT, 'attempt owner run must belong to task') END;
    SELECT CASE WHEN NOT EXISTS (
        SELECT 1 FROM policy_decisions p
        JOIN operation_intents i ON i.id = NEW.operation_intent_id
        WHERE p.id = NEW.policy_decision_id
          AND p.task_id = NEW.task_id
          AND p.operation_digest = i.operation_digest
          AND p.actor_binding_digest = i.actor_binding_digest
          AND p.effect IN ('allow', 'allow_with_redaction', 'require_approval')
    ) THEN RAISE(ABORT, 'policy decision does not bind this intent') END;
    SELECT CASE WHEN NEW.approval_id IS NOT NULL AND NOT EXISTS (
        SELECT 1 FROM approvals a
        JOIN operation_intents i ON i.id = NEW.operation_intent_id
        WHERE a.id = NEW.approval_id
          AND a.task_id = NEW.task_id
          AND a.operation_intent_id = NEW.operation_intent_id
          AND a.operation_digest = i.operation_digest
          AND a.actor_binding_digest = i.actor_binding_digest
          AND a.status = 'granted'
    ) THEN RAISE(ABORT, 'approval does not bind this intent') END;
END;

CREATE TRIGGER operation_attempts_identity_immutable
BEFORE UPDATE OF operation_intent_id, task_id, attempt_no, owner_run_id, fencing_token,
    policy_decision_id, approval_id, external_request_id, started_at
ON operation_attempts
FOR EACH ROW
BEGIN
    SELECT RAISE(ABORT, 'operation attempt identity is immutable');
END;

CREATE TRIGGER operation_attempts_terminal_irreversible
BEFORE UPDATE OF status ON operation_attempts
FOR EACH ROW
WHEN OLD.status IN ('succeeded', 'failed', 'interrupted', 'indeterminate', 'cancelled')
  AND NEW.status <> OLD.status
BEGIN
    SELECT RAISE(ABORT, 'terminal operation attempt is irreversible');
END;

CREATE TRIGGER operation_attempts_evidence_set_once
BEFORE UPDATE OF boundary_crossed_at, terminal_at, result_artifact_id, receipt_artifact_id, error_artifact_id
ON operation_attempts
FOR EACH ROW
WHEN (OLD.boundary_crossed_at IS NOT NULL AND NEW.boundary_crossed_at IS NOT OLD.boundary_crossed_at)
  OR (OLD.terminal_at IS NOT NULL AND NEW.terminal_at IS NOT OLD.terminal_at)
  OR (OLD.result_artifact_id IS NOT NULL AND NEW.result_artifact_id IS NOT OLD.result_artifact_id)
  OR (OLD.receipt_artifact_id IS NOT NULL AND NEW.receipt_artifact_id IS NOT OLD.receipt_artifact_id)
  OR (OLD.error_artifact_id IS NOT NULL AND NEW.error_artifact_id IS NOT OLD.error_artifact_id)
BEGIN
    SELECT RAISE(ABORT, 'operation attempt evidence is set-once');
END;

CREATE TRIGGER operation_attempts_delete_forbidden
BEFORE DELETE ON operation_attempts
FOR EACH ROW
BEGIN
    SELECT RAISE(ABORT, 'operation attempts are retained for execution history');
END;

CREATE TRIGGER tool_execution_scope_insert
BEFORE INSERT ON tool_executions
FOR EACH ROW
BEGIN
    SELECT CASE WHEN NEW.run_id IS NOT NULL AND NOT EXISTS (
        SELECT 1 FROM agent_runs r WHERE r.id = NEW.run_id AND r.task_id = NEW.task_id
    ) THEN RAISE(ABORT, 'tool run must belong to task') END;
    SELECT CASE WHEN NOT EXISTS (
        SELECT 1
        FROM operation_attempts oa
        JOIN operation_intents oi ON oi.id = oa.operation_intent_id
        JOIN policy_decisions p ON p.id = NEW.policy_decision_id
        WHERE oa.id = NEW.operation_attempt_id
          AND oa.operation_intent_id = NEW.operation_intent_id
          AND oa.task_id = NEW.task_id
          AND oi.task_id = NEW.task_id
          AND p.task_id = NEW.task_id
          AND p.operation_digest = oi.operation_digest
          AND p.actor_binding_digest = oi.actor_binding_digest
    ) THEN RAISE(ABORT, 'tool execution authority chain is incoherent') END;
    SELECT CASE WHEN NEW.approval_id IS NOT NULL AND NOT EXISTS (
        SELECT 1 FROM approvals a
        JOIN operation_intents oi ON oi.id = NEW.operation_intent_id
        WHERE a.id = NEW.approval_id
          AND a.task_id = NEW.task_id
          AND a.operation_intent_id = NEW.operation_intent_id
          AND a.operation_digest = oi.operation_digest
          AND a.actor_binding_digest = oi.actor_binding_digest
          AND a.status = 'granted'
    ) THEN RAISE(ABORT, 'tool approval does not bind execution') END;
END;

CREATE TRIGGER executor_lease_insert_guard
BEFORE INSERT ON executor_leases
FOR EACH ROW
BEGIN
    SELECT CASE WHEN NOT EXISTS (
        SELECT 1 FROM tasks t
        JOIN agent_runs r ON r.id = NEW.holder_run_id
        WHERE t.id = NEW.task_id
          AND r.task_id = NEW.task_id
          AND NEW.fencing_token = t.fencing_epoch
    ) THEN RAISE(ABORT, 'lease holder and token must match task') END;
END;

CREATE TRIGGER executor_lease_identity_immutable
BEFORE UPDATE OF task_id, holder_run_id, fencing_token, acquired_at ON executor_leases
FOR EACH ROW
BEGIN
    SELECT RAISE(ABORT, 'lease identity is immutable; transfer creates a new row') ;
END;

CREATE TRIGGER executor_lease_terminal_irreversible
BEFORE UPDATE OF status ON executor_leases
FOR EACH ROW
WHEN OLD.status <> 'active' AND NEW.status <> OLD.status
BEGIN
    SELECT RAISE(ABORT, 'terminal lease status is irreversible');
END;

CREATE TRIGGER executor_lease_delete_forbidden
BEFORE DELETE ON executor_leases
FOR EACH ROW
BEGIN
    SELECT RAISE(ABORT, 'executor leases are retained for fencing history');
END;

CREATE TRIGGER protocol_request_scope_insert
BEFORE INSERT ON protocol_requests
FOR EACH ROW
BEGIN
    SELECT CASE WHEN NEW.run_id IS NOT NULL AND (
        NEW.task_id IS NULL OR NOT EXISTS (
            SELECT 1 FROM agent_runs r
            WHERE r.id = NEW.run_id AND r.task_id = NEW.task_id
        )
    ) THEN RAISE(ABORT, 'protocol request scope is incoherent') END;
END;

CREATE TRIGGER protocol_request_identity_immutable
BEFORE UPDATE OF connection_id, request_id, method, request_digest, task_id, run_id, created_at
ON protocol_requests
FOR EACH ROW
BEGIN
    SELECT RAISE(ABORT, 'protocol request identity is immutable');
END;

CREATE TRIGGER protocol_request_response_evidence_set_once
BEFORE UPDATE OF response_artifact_id, completed_at ON protocol_requests
FOR EACH ROW
WHEN (OLD.response_artifact_id IS NOT NULL AND NEW.response_artifact_id IS NOT OLD.response_artifact_id)
  OR (OLD.completed_at IS NOT NULL AND NEW.completed_at IS NOT OLD.completed_at)
BEGIN
    SELECT RAISE(ABORT, 'protocol response evidence is set-once');
END;

CREATE TRIGGER protocol_request_terminal_irreversible
BEFORE UPDATE OF status ON protocol_requests
FOR EACH ROW
WHEN OLD.status IN ('completed', 'failed') AND NEW.status <> OLD.status
BEGIN
    SELECT RAISE(ABORT, 'terminal protocol request is irreversible');
END;

CREATE TRIGGER protocol_stream_sequence_contiguous_insert
BEFORE INSERT ON protocol_stream_heads
FOR EACH ROW
WHEN NEW.last_sequence <> 1
BEGIN
    SELECT RAISE(ABORT, 'first stream sequence must be one');
END;

CREATE TRIGGER protocol_stream_sequence_contiguous_update
BEFORE UPDATE OF last_sequence ON protocol_stream_heads
FOR EACH ROW
WHEN NEW.last_sequence <> OLD.last_sequence + 1
BEGIN
    SELECT RAISE(ABORT, 'stream sequence must increase exactly by one');
END;

CREATE TRIGGER protocol_request_delete_forbidden
BEFORE DELETE ON protocol_requests
FOR EACH ROW
BEGIN
    SELECT RAISE(ABORT, 'protocol requests are retained for replay protection');
END;

CREATE TRIGGER protocol_stream_head_delete_forbidden
BEFORE DELETE ON protocol_stream_heads
FOR EACH ROW
BEGIN
    SELECT RAISE(ABORT, 'protocol stream heads are retained for sequence history');
END;

CREATE TABLE memory_entries (
    id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE RESTRICT,
    memory_type TEXT NOT NULL,
    status TEXT NOT NULL CHECK (
        status IN ('candidate', 'verified', 'approved', 'active', 'rejected', 'superseded', 'retracted')
    ),
    content_artifact_id TEXT NOT NULL
        REFERENCES artifacts(id) ON DELETE RESTRICT,
    source_refs_json TEXT NOT NULL CHECK (json_valid(source_refs_json)),
    verification_method TEXT,
    verification_artifact_id TEXT REFERENCES artifacts(id) ON DELETE RESTRICT,
    confidence_millionths INTEGER NOT NULL CHECK (
        confidence_millionths BETWEEN 0 AND 1000000
    ),
    approved_by TEXT,
    created_at TEXT NOT NULL,
    superseded_by TEXT REFERENCES memory_entries(id) ON DELETE RESTRICT,
    CHECK (
        status NOT IN ('verified', 'approved', 'active')
        OR verification_method IS NOT NULL
    )
) STRICT;

CREATE TABLE source_documents (
    id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE RESTRICT,
    task_id TEXT REFERENCES tasks(id) ON DELETE RESTRICT,
    source_kind TEXT NOT NULL,
    logical_path TEXT NOT NULL,
    revision TEXT NOT NULL,
    content_hash TEXT NOT NULL CHECK (
        length(content_hash) = 71
        AND substr(content_hash, 1, 7) = 'sha256:'
        AND substr(content_hash, 8) NOT GLOB '*[^0-9a-f]*'
    ),
    sensitivity TEXT NOT NULL,
    classification_digest TEXT NOT NULL CHECK (
        length(classification_digest) = 71
        AND substr(classification_digest, 1, 7) = 'sha256:'
        AND substr(classification_digest, 8) NOT GLOB '*[^0-9a-f]*'
    ),
    index_state TEXT NOT NULL CHECK (
        index_state IN ('pending', 'current', 'stale', 'denied', 'failed')
    ),
    updated_at TEXT NOT NULL,
    UNIQUE (project_id, logical_path, revision, content_hash)
) STRICT;

CREATE TABLE source_chunks (
    id TEXT PRIMARY KEY,
    document_id TEXT NOT NULL
        REFERENCES source_documents(id) ON DELETE RESTRICT,
    symbol TEXT,
    start_line INTEGER CHECK (start_line IS NULL OR start_line >= 1),
    end_line INTEGER CHECK (end_line IS NULL OR end_line >= 1),
    content_hash TEXT NOT NULL CHECK (
        length(content_hash) = 71
        AND substr(content_hash, 1, 7) = 'sha256:'
        AND substr(content_hash, 8) NOT GLOB '*[^0-9a-f]*'
    ),
    metadata_json TEXT NOT NULL CHECK (json_valid(metadata_json)),
    vector_key TEXT,
    created_at TEXT NOT NULL,
    CHECK (
        start_line IS NULL
        OR end_line IS NULL
        OR end_line >= start_line
    )
) STRICT;

CREATE TABLE repository_graph_nodes (
    id TEXT PRIMARY KEY,
    document_id TEXT NOT NULL
        REFERENCES source_documents(id) ON DELETE RESTRICT,
    node_kind TEXT NOT NULL,
    stable_name TEXT NOT NULL,
    content_hash TEXT NOT NULL CHECK (
        length(content_hash) = 71
        AND substr(content_hash, 1, 7) = 'sha256:'
        AND substr(content_hash, 8) NOT GLOB '*[^0-9a-f]*'
    ),
    metadata_json TEXT NOT NULL CHECK (json_valid(metadata_json))
) STRICT;

CREATE TABLE repository_graph_edges (
    id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE RESTRICT,
    from_node_id TEXT NOT NULL
        REFERENCES repository_graph_nodes(id) ON DELETE RESTRICT,
    to_node_id TEXT NOT NULL
        REFERENCES repository_graph_nodes(id) ON DELETE RESTRICT,
    edge_kind TEXT NOT NULL,
    source_revision TEXT NOT NULL,
    source_hash TEXT NOT NULL CHECK (
        length(source_hash) = 71
        AND substr(source_hash, 1, 7) = 'sha256:'
        AND substr(source_hash, 8) NOT GLOB '*[^0-9a-f]*'
    ),
    metadata_json TEXT NOT NULL CHECK (json_valid(metadata_json)),
    UNIQUE (from_node_id, to_node_id, edge_kind, source_revision)
) STRICT;

CREATE TABLE projection_checkpoints (
    projection_name TEXT PRIMARY KEY,
    stream_id TEXT NOT NULL,
    sequence INTEGER NOT NULL CHECK (sequence >= 0),
    projection_version INTEGER NOT NULL CHECK (projection_version >= 1),
    updated_at TEXT NOT NULL
) STRICT;

CREATE TABLE signed_checkpoints (
    id TEXT PRIMARY KEY,
    last_event_id TEXT NOT NULL REFERENCES events(event_id) ON DELETE RESTRICT,
    stream_heads_artifact_id TEXT NOT NULL
        REFERENCES artifacts(id) ON DELETE RESTRICT,
    previous_checkpoint_hash TEXT CHECK (
        previous_checkpoint_hash IS NULL
        OR (
            length(previous_checkpoint_hash) = 71
            AND substr(previous_checkpoint_hash, 1, 7) = 'sha256:'
            AND substr(previous_checkpoint_hash, 8) NOT GLOB '*[^0-9a-f]*'
        )
    ),
    checkpoint_hash TEXT NOT NULL CHECK (
        length(checkpoint_hash) = 71
        AND substr(checkpoint_hash, 1, 7) = 'sha256:'
        AND substr(checkpoint_hash, 8) NOT GLOB '*[^0-9a-f]*'
    ),
    signature BLOB,
    created_at TEXT NOT NULL
) STRICT;

CREATE TRIGGER signed_checkpoints_update_forbidden
BEFORE UPDATE ON signed_checkpoints
FOR EACH ROW
BEGIN
    SELECT RAISE(ABORT, 'signed checkpoints are immutable');
END;

CREATE TRIGGER signed_checkpoints_delete_forbidden
BEFORE DELETE ON signed_checkpoints
FOR EACH ROW
BEGIN
    SELECT RAISE(ABORT, 'signed checkpoints are retained');
END;

CREATE TRIGGER projection_checkpoint_monotonic
BEFORE UPDATE OF sequence ON projection_checkpoints
FOR EACH ROW
WHEN NEW.sequence < OLD.sequence
BEGIN
    SELECT RAISE(ABORT, 'projection checkpoint cannot move backwards');
END;

CREATE TABLE update_journal (
    id TEXT PRIMARY KEY,
    from_application_version TEXT NOT NULL,
    to_application_version TEXT NOT NULL,
    from_schema_version INTEGER NOT NULL,
    to_schema_version INTEGER NOT NULL,
    status TEXT NOT NULL CHECK (
        status IN (
            'planned',
            'backup_verified',
            'binary_installed',
            'migrated',
            'health_verified',
            'rolled_back',
            'failed'
        )
    ),
    backup_manifest_artifact_id TEXT
        REFERENCES artifacts(id) ON DELETE RESTRICT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    error_json TEXT CHECK (error_json IS NULL OR json_valid(error_json))
) STRICT;

CREATE TRIGGER context_packages_update_forbidden
BEFORE UPDATE ON context_packages
FOR EACH ROW
BEGIN
    SELECT RAISE(ABORT, 'context packages are immutable disclosure receipts');
END;

CREATE TRIGGER context_packages_delete_forbidden
BEFORE DELETE ON context_packages
FOR EACH ROW
BEGIN
    SELECT RAISE(ABORT, 'context packages are retained');
END;

CREATE TRIGGER approvals_scope_insert
BEFORE INSERT ON approvals
FOR EACH ROW
BEGIN
    SELECT CASE WHEN NOT EXISTS (
        SELECT 1 FROM operation_intents i
        WHERE i.id = NEW.operation_intent_id
          AND i.task_id = NEW.task_id
          AND i.operation_digest = NEW.operation_digest
          AND i.actor_binding_digest = NEW.actor_binding_digest
    ) THEN RAISE(ABORT, 'approval request does not bind an exact operation intent') END;
END;

CREATE TRIGGER approval_receipt_scope_insert
BEFORE INSERT ON approval_decision_receipts
FOR EACH ROW
BEGIN
    SELECT CASE WHEN NOT EXISTS (
        SELECT 1 FROM approvals a
        WHERE a.id = NEW.approval_id
          AND a.task_id = NEW.task_id
          AND a.operation_intent_id = NEW.operation_intent_id
          AND a.operation_digest = NEW.operation_digest
          AND a.actor_binding_digest = NEW.actor_binding_digest
          AND a.nonce = NEW.nonce
          AND a.status = 'pending'
    ) THEN RAISE(ABORT, 'decision receipt does not match pending approval request') END;
END;

CREATE TRIGGER final_commit_candidate_scope_insert
BEFORE INSERT ON final_commit_candidates
FOR EACH ROW
BEGIN
    SELECT CASE WHEN NOT EXISTS (
        SELECT 1 FROM operation_intents i
        WHERE i.id = NEW.operation_intent_id
          AND i.task_id = NEW.task_id
          AND i.operation_kind = 'git.final_commit'
    ) THEN RAISE(ABORT, 'final commit candidate must bind final-commit intent') END;
END;

CREATE TRIGGER approval_consumption_scope_insert
BEFORE INSERT ON approval_effect_consumptions
FOR EACH ROW
BEGIN
    SELECT CASE WHEN NOT EXISTS (
        SELECT 1
        FROM approval_decision_receipts r
        JOIN approvals a ON a.id = r.approval_id
        WHERE r.id = NEW.approval_receipt_id
          AND r.decision = 'granted'
          AND r.operation_intent_id = NEW.operation_intent_id
          AND a.status = 'granted'
    ) THEN RAISE(ABORT, 'only a matching granted receipt may be consumed') END;
END;

CREATE TRIGGER tool_execution_identity_immutable
BEFORE UPDATE OF task_id, run_id, request_id, tool_name, arguments_artifact_id,
    policy_decision_id, approval_id, operation_intent_id, operation_attempt_id,
    executor_fencing_token
ON tool_executions
FOR EACH ROW
BEGIN
    SELECT RAISE(ABORT, 'tool execution authority identity is immutable');
END;

CREATE TRIGGER protocol_request_completion_requires_response
BEFORE UPDATE OF status ON protocol_requests
FOR EACH ROW
WHEN NEW.status = 'completed'
BEGIN
    SELECT CASE WHEN NEW.response_artifact_id IS NULL OR NEW.completed_at IS NULL
        THEN RAISE(ABORT, 'completed protocol request requires persisted response and completion time') END;
    SELECT CASE WHEN NEW.task_id IS NOT NULL AND NOT EXISTS (
        SELECT 1
        FROM tasks t
        JOIN artifacts a ON a.id = NEW.response_artifact_id
        WHERE t.id = NEW.task_id
          AND a.project_id = t.project_id
          AND (a.task_id IS NULL OR a.task_id = NEW.task_id)
    ) THEN RAISE(ABORT, 'protocol response scope is incoherent') END;
END;


-- v3.2 self-review hardening: authority/evidence records and lifecycle guards.

CREATE TRIGGER schema_migrations_update_forbidden
BEFORE UPDATE ON schema_migrations
FOR EACH ROW
BEGIN
    SELECT RAISE(ABORT, 'schema migration records are immutable');
END;

CREATE TRIGGER schema_migrations_delete_forbidden
BEFORE DELETE ON schema_migrations
FOR EACH ROW
BEGIN
    SELECT RAISE(ABORT, 'schema migration records are retained');
END;

CREATE TRIGGER artifacts_replacement_forbidden
BEFORE INSERT ON artifacts
FOR EACH ROW
WHEN EXISTS (
    SELECT 1 FROM artifacts existing
    WHERE existing.id = NEW.id
       OR (
            existing.project_id = NEW.project_id
        AND existing.logical_path = NEW.logical_path
        AND existing.content_hash = NEW.content_hash
       )
)
BEGIN
    SELECT RAISE(ABORT, 'artifact identity replacement is forbidden');
END;

CREATE TRIGGER artifacts_scope_insert
BEFORE INSERT ON artifacts
FOR EACH ROW
BEGIN
    SELECT CASE WHEN NEW.task_id IS NOT NULL AND NOT EXISTS (
        SELECT 1 FROM tasks t
        WHERE t.id = NEW.task_id AND t.project_id = NEW.project_id
    ) THEN RAISE(ABORT, 'artifact task/project scope is incoherent') END;
    SELECT CASE WHEN NEW.supersedes IS NOT NULL AND NOT EXISTS (
        SELECT 1 FROM artifacts prior
        WHERE prior.id = NEW.supersedes
          AND prior.id <> NEW.id
          AND prior.project_id = NEW.project_id
          AND prior.task_id IS NEW.task_id
          AND prior.artifact_type = NEW.artifact_type
          AND prior.logical_path = NEW.logical_path
    ) THEN RAISE(ABORT, 'artifact supersession scope is incoherent') END;
END;

CREATE TRIGGER artifacts_identity_immutable
BEFORE UPDATE OF task_id, project_id, artifact_type, logical_path, content_hash,
    storage_key, size_bytes, mime_type, created_by_type, created_by_id, created_at,
    supersedes
ON artifacts
FOR EACH ROW
BEGIN
    SELECT RAISE(ABORT, 'artifact identity is immutable');
END;

CREATE TRIGGER artifacts_availability_transition
BEFORE UPDATE OF availability ON artifacts
FOR EACH ROW
WHEN NOT (
    OLD.availability = NEW.availability
    OR (OLD.availability = 'reserved' AND NEW.availability IN ('available', 'quarantined', 'missing'))
    OR (OLD.availability = 'available' AND NEW.availability IN ('quarantined', 'missing'))
    OR (OLD.availability = 'missing' AND NEW.availability IN ('available', 'quarantined'))
)
BEGIN
    SELECT RAISE(ABORT, 'invalid artifact availability transition');
END;

CREATE TRIGGER artifacts_verification_transition
BEFORE UPDATE OF verification_state ON artifacts
FOR EACH ROW
WHEN NOT (
    OLD.verification_state = NEW.verification_state
    OR (OLD.verification_state = 'unverified' AND NEW.verification_state IN ('hash_verified', 'tool_verified', 'rejected'))
    OR (OLD.verification_state = 'hash_verified' AND NEW.verification_state IN ('tool_verified', 'user_approved', 'rejected'))
    OR (OLD.verification_state = 'tool_verified' AND NEW.verification_state IN ('user_approved', 'rejected'))
    OR (OLD.verification_state = 'user_approved' AND NEW.verification_state = 'rejected')
)
BEGIN
    SELECT RAISE(ABORT, 'invalid artifact verification transition');
END;

CREATE TRIGGER artifacts_delete_forbidden
BEFORE DELETE ON artifacts
FOR EACH ROW
BEGIN
    SELECT RAISE(ABORT, 'artifact records are retained; garbage collection removes quarantined bytes only');
END;

CREATE TRIGGER artifact_operations_insert_scope
BEFORE INSERT ON artifact_operations
FOR EACH ROW
BEGIN
    SELECT CASE WHEN NOT EXISTS (
        SELECT 1 FROM artifacts a
        WHERE a.id = NEW.artifact_id
          AND a.content_hash = NEW.expected_hash
          AND a.size_bytes = NEW.expected_size
    ) THEN RAISE(ABORT, 'artifact operation expectation does not match artifact identity') END;
END;

CREATE TRIGGER artifact_operations_identity_immutable
BEFORE UPDATE OF artifact_id, temp_name, expected_hash, expected_size, created_at
ON artifact_operations
FOR EACH ROW
BEGIN
    SELECT RAISE(ABORT, 'artifact operation identity is immutable');
END;

CREATE TRIGGER artifact_operations_terminal_irreversible
BEFORE UPDATE OF status ON artifact_operations
FOR EACH ROW
WHEN OLD.status IN ('completed', 'aborted', 'quarantined') AND NEW.status <> OLD.status
BEGIN
    SELECT RAISE(ABORT, 'terminal artifact operation is irreversible');
END;

CREATE TRIGGER artifact_operations_evidence_set_once
BEFORE UPDATE OF completed_at, error_json ON artifact_operations
FOR EACH ROW
WHEN (OLD.completed_at IS NOT NULL AND NEW.completed_at IS NOT OLD.completed_at)
  OR (OLD.error_json IS NOT NULL AND NEW.error_json IS NOT OLD.error_json)
BEGIN
    SELECT RAISE(ABORT, 'artifact operation evidence is set-once');
END;

CREATE TRIGGER artifact_operations_delete_forbidden
BEFORE DELETE ON artifact_operations
FOR EACH ROW
BEGIN
    SELECT RAISE(ABORT, 'artifact operations are retained for recovery history');
END;

CREATE TRIGGER policy_decisions_update_forbidden
BEFORE UPDATE ON policy_decisions
FOR EACH ROW
BEGIN
    SELECT RAISE(ABORT, 'policy decisions are immutable');
END;

CREATE TRIGGER policy_decisions_delete_forbidden
BEFORE DELETE ON policy_decisions
FOR EACH ROW
BEGIN
    SELECT RAISE(ABORT, 'policy decisions are retained');
END;

CREATE TRIGGER context_package_policy_scope_insert
BEFORE INSERT ON context_package_policy_decisions
FOR EACH ROW
BEGIN
    SELECT CASE WHEN NOT EXISTS (
        SELECT 1
        FROM context_packages cp
        JOIN policy_decisions p ON p.id = NEW.policy_decision_id
        WHERE cp.id = NEW.package_id
          AND (p.task_id IS NULL OR p.task_id = cp.task_id)
          AND p.policy_snapshot_digest = cp.policy_snapshot_digest
    ) THEN RAISE(ABORT, 'context package policy scope is incoherent') END;
END;

CREATE TRIGGER context_package_policy_update_forbidden
BEFORE UPDATE ON context_package_policy_decisions
FOR EACH ROW
BEGIN
    SELECT RAISE(ABORT, 'context package policy bindings are immutable');
END;

CREATE TRIGGER context_package_policy_delete_forbidden
BEFORE DELETE ON context_package_policy_decisions
FOR EACH ROW
BEGIN
    SELECT RAISE(ABORT, 'context package policy bindings are retained');
END;

CREATE TRIGGER operation_intents_scope_insert
BEFORE INSERT ON operation_intents
FOR EACH ROW
BEGIN
    SELECT CASE WHEN NOT EXISTS (
        SELECT 1
        FROM tasks t
        JOIN artifacts a ON a.id = NEW.canonical_request_artifact_id
        WHERE t.id = NEW.task_id
          AND a.project_id = t.project_id
          AND (a.task_id IS NULL OR a.task_id = NEW.task_id)
    ) THEN RAISE(ABORT, 'operation intent artifact scope is incoherent') END;
    SELECT CASE WHEN NEW.run_id IS NOT NULL AND NOT EXISTS (
        SELECT 1 FROM agent_runs r
        WHERE r.id = NEW.run_id AND r.task_id = NEW.task_id
    ) THEN RAISE(ABORT, 'operation intent run scope is incoherent') END;
END;

CREATE TRIGGER operation_intents_attempt_requires_row
BEFORE UPDATE OF current_attempt_no ON operation_intents
FOR EACH ROW
WHEN NEW.current_attempt_no = OLD.current_attempt_no + 1
BEGIN
    SELECT CASE WHEN NOT EXISTS (
        SELECT 1 FROM operation_attempts a
        WHERE a.operation_intent_id = OLD.id
          AND a.task_id = OLD.task_id
          AND a.attempt_no = NEW.current_attempt_no
    ) THEN RAISE(ABORT, 'operation attempt counter requires a persisted matching attempt') END;
END;

CREATE TRIGGER operation_intents_delete_forbidden
BEFORE DELETE ON operation_intents
FOR EACH ROW
BEGIN
    SELECT RAISE(ABORT, 'operation intents are retained');
END;

CREATE TRIGGER operation_attempt_authority_insert
BEFORE INSERT ON operation_attempts
FOR EACH ROW
BEGIN
    SELECT CASE WHEN NOT EXISTS (
        SELECT 1
        FROM policy_decisions p
        WHERE p.id = NEW.policy_decision_id
          AND (p.expires_at IS NULL OR julianday(p.expires_at) > julianday(NEW.started_at))
    ) THEN RAISE(ABORT, 'policy decision is expired for this attempt') END;
    SELECT CASE WHEN EXISTS (
        SELECT 1 FROM policy_decisions p
        WHERE p.id = NEW.policy_decision_id AND p.effect = 'require_approval'
    ) AND NEW.approval_id IS NULL
    THEN RAISE(ABORT, 'policy requires a granted approval') END;
    SELECT CASE WHEN NEW.approval_id IS NOT NULL AND NOT EXISTS (
        SELECT 1 FROM approvals a
        WHERE a.id = NEW.approval_id
          AND a.status = 'granted'
          AND julianday(a.expires_at) > julianday(NEW.started_at)
    ) THEN RAISE(ABORT, 'approval is missing, not granted, or expired') END;
    SELECT CASE WHEN NEW.result_artifact_id IS NOT NULL AND NOT EXISTS (
        SELECT 1 FROM tasks t JOIN artifacts a ON a.id = NEW.result_artifact_id
        WHERE t.id = NEW.task_id AND a.project_id = t.project_id
          AND (a.task_id IS NULL OR a.task_id = NEW.task_id)
    ) THEN RAISE(ABORT, 'attempt result evidence scope is incoherent') END;
    SELECT CASE WHEN NEW.receipt_artifact_id IS NOT NULL AND NOT EXISTS (
        SELECT 1 FROM tasks t JOIN artifacts a ON a.id = NEW.receipt_artifact_id
        WHERE t.id = NEW.task_id AND a.project_id = t.project_id
          AND (a.task_id IS NULL OR a.task_id = NEW.task_id)
    ) THEN RAISE(ABORT, 'attempt receipt evidence scope is incoherent') END;
    SELECT CASE WHEN NEW.error_artifact_id IS NOT NULL AND NOT EXISTS (
        SELECT 1 FROM tasks t JOIN artifacts a ON a.id = NEW.error_artifact_id
        WHERE t.id = NEW.task_id AND a.project_id = t.project_id
          AND (a.task_id IS NULL OR a.task_id = NEW.task_id)
    ) THEN RAISE(ABORT, 'attempt error evidence scope is incoherent') END;
END;

CREATE TRIGGER operation_attempt_evidence_scope_update
BEFORE UPDATE OF result_artifact_id, receipt_artifact_id, error_artifact_id
ON operation_attempts
FOR EACH ROW
BEGIN
    SELECT CASE WHEN NEW.result_artifact_id IS NOT NULL AND NOT EXISTS (
        SELECT 1 FROM tasks t JOIN artifacts a ON a.id = NEW.result_artifact_id
        WHERE t.id = NEW.task_id AND a.project_id = t.project_id
          AND (a.task_id IS NULL OR a.task_id = NEW.task_id)
    ) THEN RAISE(ABORT, 'attempt result evidence scope is incoherent') END;
    SELECT CASE WHEN NEW.receipt_artifact_id IS NOT NULL AND NOT EXISTS (
        SELECT 1 FROM tasks t JOIN artifacts a ON a.id = NEW.receipt_artifact_id
        WHERE t.id = NEW.task_id AND a.project_id = t.project_id
          AND (a.task_id IS NULL OR a.task_id = NEW.task_id)
    ) THEN RAISE(ABORT, 'attempt receipt evidence scope is incoherent') END;
    SELECT CASE WHEN NEW.error_artifact_id IS NOT NULL AND NOT EXISTS (
        SELECT 1 FROM tasks t JOIN artifacts a ON a.id = NEW.error_artifact_id
        WHERE t.id = NEW.task_id AND a.project_id = t.project_id
          AND (a.task_id IS NULL OR a.task_id = NEW.task_id)
    ) THEN RAISE(ABORT, 'attempt error evidence scope is incoherent') END;
END;

CREATE TRIGGER tool_execution_hardening_insert
BEFORE INSERT ON tool_executions
FOR EACH ROW
BEGIN
    SELECT CASE WHEN NOT EXISTS (
        SELECT 1 FROM tasks t JOIN artifacts a ON a.id = NEW.arguments_artifact_id
        WHERE t.id = NEW.task_id AND a.project_id = t.project_id
          AND (a.task_id IS NULL OR a.task_id = NEW.task_id)
    ) THEN RAISE(ABORT, 'tool argument artifact scope is incoherent') END;
    SELECT CASE WHEN NOT EXISTS (
        SELECT 1 FROM operation_attempts a
        WHERE a.id = NEW.operation_attempt_id
          AND a.operation_intent_id = NEW.operation_intent_id
          AND a.task_id = NEW.task_id
          AND a.policy_decision_id = NEW.policy_decision_id
          AND a.approval_id IS NEW.approval_id
          AND a.status IN ('claimed', 'started')
    ) THEN RAISE(ABORT, 'tool execution does not match its exact active attempt authority') END;
    SELECT CASE WHEN NEW.stdout_artifact_id IS NOT NULL AND NOT EXISTS (
        SELECT 1 FROM tasks t JOIN artifacts a ON a.id = NEW.stdout_artifact_id
        WHERE t.id = NEW.task_id AND a.project_id = t.project_id
          AND (a.task_id IS NULL OR a.task_id = NEW.task_id)
    ) THEN RAISE(ABORT, 'tool stdout artifact scope is incoherent') END;
    SELECT CASE WHEN NEW.stderr_artifact_id IS NOT NULL AND NOT EXISTS (
        SELECT 1 FROM tasks t JOIN artifacts a ON a.id = NEW.stderr_artifact_id
        WHERE t.id = NEW.task_id AND a.project_id = t.project_id
          AND (a.task_id IS NULL OR a.task_id = NEW.task_id)
    ) THEN RAISE(ABORT, 'tool stderr artifact scope is incoherent') END;
END;

CREATE TRIGGER tool_execution_output_scope_update
BEFORE UPDATE OF stdout_artifact_id, stderr_artifact_id ON tool_executions
FOR EACH ROW
BEGIN
    SELECT CASE WHEN NEW.stdout_artifact_id IS NOT NULL AND NOT EXISTS (
        SELECT 1 FROM tasks t JOIN artifacts a ON a.id = NEW.stdout_artifact_id
        WHERE t.id = NEW.task_id AND a.project_id = t.project_id
          AND (a.task_id IS NULL OR a.task_id = NEW.task_id)
    ) THEN RAISE(ABORT, 'tool stdout artifact scope is incoherent') END;
    SELECT CASE WHEN NEW.stderr_artifact_id IS NOT NULL AND NOT EXISTS (
        SELECT 1 FROM tasks t JOIN artifacts a ON a.id = NEW.stderr_artifact_id
        WHERE t.id = NEW.task_id AND a.project_id = t.project_id
          AND (a.task_id IS NULL OR a.task_id = NEW.task_id)
    ) THEN RAISE(ABORT, 'tool stderr artifact scope is incoherent') END;
END;

CREATE TRIGGER tool_execution_terminal_irreversible
BEFORE UPDATE OF status ON tool_executions
FOR EACH ROW
WHEN OLD.status IN ('succeeded', 'failed', 'terminated', 'interrupted', 'indeterminate', 'denied')
  AND NEW.status <> OLD.status
BEGIN
    SELECT RAISE(ABORT, 'terminal tool execution status is irreversible');
END;

CREATE TRIGGER tool_execution_evidence_set_once
BEFORE UPDATE OF started_at, completed_at, exit_code, stdout_artifact_id, stderr_artifact_id
ON tool_executions
FOR EACH ROW
WHEN (OLD.started_at IS NOT NULL AND NEW.started_at IS NOT OLD.started_at)
  OR (OLD.completed_at IS NOT NULL AND NEW.completed_at IS NOT OLD.completed_at)
  OR (OLD.exit_code IS NOT NULL AND NEW.exit_code IS NOT OLD.exit_code)
  OR (OLD.stdout_artifact_id IS NOT NULL AND NEW.stdout_artifact_id IS NOT OLD.stdout_artifact_id)
  OR (OLD.stderr_artifact_id IS NOT NULL AND NEW.stderr_artifact_id IS NOT OLD.stderr_artifact_id)
BEGIN
    SELECT RAISE(ABORT, 'tool execution evidence is set-once');
END;

CREATE TRIGGER tool_execution_delete_forbidden
BEFORE DELETE ON tool_executions
FOR EACH ROW
BEGIN
    SELECT RAISE(ABORT, 'tool executions are retained');
END;

CREATE TRIGGER approvals_request_artifact_scope_insert
BEFORE INSERT ON approvals
FOR EACH ROW
BEGIN
    SELECT CASE WHEN NOT EXISTS (
        SELECT 1 FROM tasks t JOIN artifacts a ON a.id = NEW.request_artifact_id
        WHERE t.id = NEW.task_id AND a.project_id = t.project_id
          AND (a.task_id IS NULL OR a.task_id = NEW.task_id)
    ) THEN RAISE(ABORT, 'approval request artifact scope is incoherent') END;
END;

CREATE TRIGGER approvals_delete_forbidden
BEFORE DELETE ON approvals
FOR EACH ROW
BEGIN
    SELECT RAISE(ABORT, 'approval requests are retained');
END;

CREATE TRIGGER approval_receipt_credential_scope_insert
BEFORE INSERT ON approval_decision_receipts
FOR EACH ROW
BEGIN
    SELECT CASE WHEN NOT EXISTS (
        SELECT 1 FROM tasks t JOIN artifacts a ON a.id = NEW.credential_evidence_artifact_id
        WHERE t.id = NEW.task_id AND a.project_id = t.project_id
          AND (a.task_id IS NULL OR a.task_id = NEW.task_id)
    ) THEN RAISE(ABORT, 'approval credential evidence scope is incoherent') END;
    SELECT CASE WHEN NEW.decision = 'granted' AND EXISTS (
        SELECT 1 FROM approvals a
        WHERE a.id = NEW.approval_id
          AND julianday(NEW.decided_at) > julianday(a.expires_at)
    ) THEN RAISE(ABORT, 'expired approval cannot receive a grant receipt') END;
END;

CREATE TRIGGER final_commit_candidate_repository_scope_insert
BEFORE INSERT ON final_commit_candidates
FOR EACH ROW
BEGIN
    SELECT CASE WHEN NOT EXISTS (
        SELECT 1 FROM tasks t JOIN projects p ON p.id = t.project_id
        WHERE t.id = NEW.task_id
          AND p.repository_identity = NEW.repository_identity_digest
    ) THEN RAISE(ABORT, 'final commit candidate repository identity is incoherent') END;
END;

CREATE TRIGGER approval_consumption_exact_effect_insert
BEFORE INSERT ON approval_effect_consumptions
FOR EACH ROW
BEGIN
    SELECT CASE WHEN EXISTS (
        SELECT 1 FROM operation_intents i
        WHERE i.id = NEW.operation_intent_id AND i.operation_kind = 'git.final_commit'
    ) AND NOT EXISTS (
        SELECT 1 FROM final_commit_candidates c
        WHERE c.operation_intent_id = NEW.operation_intent_id
          AND c.repository_identity_digest = NEW.repository_identity_digest
          AND c.expected_ref = NEW.expected_ref
          AND c.expected_old_oid = NEW.expected_old_oid
          AND c.candidate_commit_oid = NEW.candidate_commit_oid
    ) THEN RAISE(ABORT, 'final commit approval consumption must match the exact candidate tuple') END;
    SELECT CASE WHEN EXISTS (
        SELECT 1 FROM operation_intents i
        WHERE i.id = NEW.operation_intent_id AND i.operation_kind <> 'git.final_commit'
    ) AND (
        NEW.repository_identity_digest IS NOT NULL OR NEW.expected_ref IS NOT NULL
        OR NEW.expected_old_oid IS NOT NULL OR NEW.candidate_commit_oid IS NOT NULL
    ) THEN RAISE(ABORT, 'non-final approval consumption cannot carry a Git candidate tuple') END;
END;

CREATE TRIGGER protocol_request_insert_consistency
BEFORE INSERT ON protocol_requests
FOR EACH ROW
BEGIN
    SELECT CASE WHEN NEW.status = 'completed'
        AND (NEW.response_artifact_id IS NULL OR NEW.completed_at IS NULL)
        THEN RAISE(ABORT, 'completed protocol request requires persisted response and completion time') END;
    SELECT CASE WHEN NEW.status = 'failed' AND NEW.completed_at IS NULL
        THEN RAISE(ABORT, 'failed protocol request requires completion time') END;
    SELECT CASE WHEN NEW.response_artifact_id IS NOT NULL AND NEW.task_id IS NOT NULL AND NOT EXISTS (
        SELECT 1 FROM tasks t JOIN artifacts a ON a.id = NEW.response_artifact_id
        WHERE t.id = NEW.task_id AND a.project_id = t.project_id
          AND (a.task_id IS NULL OR a.task_id = NEW.task_id)
    ) THEN RAISE(ABORT, 'protocol response artifact scope is incoherent') END;
END;


-- v3.2 self-review hardening, pass two: lifecycle and retrieval scope.

CREATE TRIGGER projects_repository_identity_immutable
BEFORE UPDATE OF repository_identity, created_at ON projects
FOR EACH ROW
BEGIN
    SELECT RAISE(ABORT, 'project repository identity is immutable');
END;

CREATE TRIGGER approvals_initial_state_guard
BEFORE INSERT ON approvals
FOR EACH ROW
WHEN NEW.status <> 'pending' OR NEW.resolved_at IS NOT NULL OR NEW.invalidation_reason IS NOT NULL
BEGIN
    SELECT RAISE(ABORT, 'approval requests must start pending and unresolved');
END;

CREATE TRIGGER approvals_resolution_consistency
BEFORE UPDATE OF status, resolved_at, invalidation_reason ON approvals
FOR EACH ROW
BEGIN
    SELECT CASE WHEN NEW.status = 'pending' AND NEW.resolved_at IS NOT NULL
        THEN RAISE(ABORT, 'pending approval cannot have a resolution time') END;
    SELECT CASE WHEN NEW.status <> 'pending' AND NEW.resolved_at IS NULL
        THEN RAISE(ABORT, 'resolved approval requires a resolution time') END;
    SELECT CASE WHEN NEW.status = 'invalidated' AND NEW.invalidation_reason IS NULL
        THEN RAISE(ABORT, 'invalidated approval requires a reason') END;
END;

CREATE TRIGGER operation_attempt_success_receipt_insert
BEFORE INSERT ON operation_attempts
FOR EACH ROW
WHEN NEW.status = 'succeeded' AND NEW.receipt_artifact_id IS NULL
BEGIN
    SELECT RAISE(ABORT, 'successful operation attempt requires a persisted receipt');
END;

CREATE TRIGGER operation_attempt_success_receipt_update
BEFORE UPDATE OF status, receipt_artifact_id ON operation_attempts
FOR EACH ROW
WHEN NEW.status = 'succeeded' AND NEW.receipt_artifact_id IS NULL
BEGIN
    SELECT RAISE(ABORT, 'successful operation attempt requires a persisted receipt');
END;

CREATE TRIGGER agent_runs_terminal_consistency_insert
BEFORE INSERT ON agent_runs
FOR EACH ROW
WHEN NEW.status IN ('succeeded', 'failed', 'cancelled_cleanly', 'terminated', 'interrupted', 'indeterminate')
  AND NEW.completed_at IS NULL
BEGIN
    SELECT RAISE(ABORT, 'terminal agent run requires a completion time');
END;

CREATE TRIGGER agent_runs_terminal_consistency_update
BEFORE UPDATE OF status, completed_at ON agent_runs
FOR EACH ROW
WHEN NEW.status IN ('succeeded', 'failed', 'cancelled_cleanly', 'terminated', 'interrupted', 'indeterminate')
  AND NEW.completed_at IS NULL
BEGIN
    SELECT RAISE(ABORT, 'terminal agent run requires a completion time');
END;

CREATE TRIGGER agent_runs_interrupted_irreversible
BEFORE UPDATE OF status ON agent_runs
FOR EACH ROW
WHEN OLD.status = 'interrupted' AND NEW.status <> OLD.status
BEGIN
    SELECT RAISE(ABORT, 'terminal agent run status is irreversible');
END;

CREATE TRIGGER agent_runs_descriptor_authorization_insert
BEFORE INSERT ON agent_runs
FOR EACH ROW
BEGIN
    SELECT CASE WHEN NOT EXISTS (
        SELECT 1 FROM agent_descriptors d
        WHERE d.id = NEW.agent_id AND d.enabled = 1
    ) THEN RAISE(ABORT, 'agent descriptor is disabled') END;
    SELECT CASE WHEN EXISTS (
        SELECT 1 FROM agent_descriptors d
        WHERE d.id = NEW.agent_id AND d.trust_tier <> 'core_adapter'
    ) AND NOT EXISTS (
        SELECT 1
        FROM agent_descriptors d
        JOIN containment_attestations a ON a.id = d.active_attestation_id
        LEFT JOIN containment_attestation_revocations r ON r.attestation_id = a.id
        WHERE d.id = NEW.agent_id
          AND d.enabled = 1
          AND a.agent_descriptor_id = d.id
          AND a.executable_digest = d.executable_digest
          AND a.manifest_digest = d.manifest_digest
          AND julianday(a.verified_at) <= julianday('now')
          AND julianday(a.expires_at) > julianday('now')
          AND r.id IS NULL
    ) THEN RAISE(ABORT, 'external agent run requires a current unrevoked exact-tuple attestation') END;
END;

CREATE TRIGGER containment_revocation_effective_disable
AFTER INSERT ON containment_attestation_revocations
FOR EACH ROW
BEGIN
    UPDATE agent_descriptors
    SET enabled = 0,
        active_attestation_id = NULL,
        updated_at = NEW.revoked_at
    WHERE active_attestation_id = NEW.attestation_id;
END;

CREATE TRIGGER messages_terminal_irreversible
BEFORE UPDATE OF status ON messages
FOR EACH ROW
WHEN OLD.status IN ('superseded', 'retracted', 'rejected', 'malformed')
  AND NEW.status <> OLD.status
BEGIN
    SELECT RAISE(ABORT, 'terminal message status is irreversible');
END;

CREATE TRIGGER messages_delete_forbidden
BEFORE DELETE ON messages
FOR EACH ROW
BEGIN
    SELECT RAISE(ABORT, 'messages are retained');
END;

CREATE TRIGGER protocol_request_response_scope_update
BEFORE UPDATE OF response_artifact_id ON protocol_requests
FOR EACH ROW
WHEN NEW.response_artifact_id IS NOT NULL AND NEW.task_id IS NOT NULL
BEGIN
    SELECT CASE WHEN NOT EXISTS (
        SELECT 1 FROM tasks t JOIN artifacts a ON a.id = NEW.response_artifact_id
        WHERE t.id = NEW.task_id AND a.project_id = t.project_id
          AND (a.task_id IS NULL OR a.task_id = NEW.task_id)
    ) THEN RAISE(ABORT, 'protocol response artifact scope is incoherent') END;
END;

CREATE TRIGGER protocol_stream_identity_immutable
BEFORE UPDATE OF connection_id, run_id, channel ON protocol_stream_heads
FOR EACH ROW
BEGIN
    SELECT RAISE(ABORT, 'protocol stream identity is immutable');
END;

CREATE TRIGGER executor_lease_expiry_immutable
BEFORE UPDATE OF expires_at ON executor_leases
FOR EACH ROW
BEGIN
    SELECT RAISE(ABORT, 'lease expiry is immutable; renewal creates a new fenced lease');
END;

CREATE TRIGGER operation_intents_digest_binding_insert
BEFORE INSERT ON operation_intents
FOR EACH ROW
BEGIN
    SELECT CASE WHEN NOT EXISTS (
        SELECT 1 FROM artifacts a
        WHERE a.id = NEW.canonical_request_artifact_id
          AND a.content_hash = NEW.operation_digest
    ) THEN RAISE(ABORT, 'operation digest must match the canonical request artifact') END;
END;

CREATE TRIGGER policy_decision_approval_scope_insert
BEFORE INSERT ON policy_decisions
FOR EACH ROW
WHEN NEW.approval_id IS NOT NULL
BEGIN
    SELECT CASE WHEN NOT EXISTS (
        SELECT 1 FROM approvals a
        WHERE a.id = NEW.approval_id
          AND a.task_id IS NEW.task_id
          AND a.operation_digest = NEW.operation_digest
          AND a.actor_binding_digest = NEW.actor_binding_digest
    ) THEN RAISE(ABORT, 'policy approval scope is incoherent') END;
END;

CREATE TRIGGER tool_execution_terminal_consistency_insert
BEFORE INSERT ON tool_executions
FOR EACH ROW
WHEN NEW.status IN ('succeeded', 'failed', 'terminated', 'interrupted', 'indeterminate', 'denied')
  AND NEW.completed_at IS NULL
BEGIN
    SELECT RAISE(ABORT, 'terminal tool execution requires a completion time');
END;

CREATE TRIGGER tool_execution_terminal_consistency_update
BEFORE UPDATE OF status, completed_at ON tool_executions
FOR EACH ROW
WHEN NEW.status IN ('succeeded', 'failed', 'terminated', 'interrupted', 'indeterminate', 'denied')
  AND NEW.completed_at IS NULL
BEGIN
    SELECT RAISE(ABORT, 'terminal tool execution requires a completion time');
END;

CREATE TRIGGER source_documents_scope_insert
BEFORE INSERT ON source_documents
FOR EACH ROW
WHEN NEW.task_id IS NOT NULL
BEGIN
    SELECT CASE WHEN NOT EXISTS (
        SELECT 1 FROM tasks t
        WHERE t.id = NEW.task_id AND t.project_id = NEW.project_id
    ) THEN RAISE(ABORT, 'source document task/project scope is incoherent') END;
END;

CREATE TRIGGER source_documents_scope_update
BEFORE UPDATE OF project_id, task_id ON source_documents
FOR EACH ROW
WHEN NEW.task_id IS NOT NULL
BEGIN
    SELECT CASE WHEN NOT EXISTS (
        SELECT 1 FROM tasks t
        WHERE t.id = NEW.task_id AND t.project_id = NEW.project_id
    ) THEN RAISE(ABORT, 'source document task/project scope is incoherent') END;
END;

CREATE TRIGGER memory_entries_scope_insert
BEFORE INSERT ON memory_entries
FOR EACH ROW
BEGIN
    SELECT CASE WHEN NOT EXISTS (
        SELECT 1 FROM artifacts a
        WHERE a.id = NEW.content_artifact_id AND a.project_id = NEW.project_id
    ) THEN RAISE(ABORT, 'memory content artifact scope is incoherent') END;
    SELECT CASE WHEN NEW.verification_artifact_id IS NOT NULL AND NOT EXISTS (
        SELECT 1 FROM artifacts a
        WHERE a.id = NEW.verification_artifact_id AND a.project_id = NEW.project_id
    ) THEN RAISE(ABORT, 'memory verification artifact scope is incoherent') END;
    SELECT CASE WHEN NEW.superseded_by IS NOT NULL AND NOT EXISTS (
        SELECT 1 FROM memory_entries m
        WHERE m.id = NEW.superseded_by
          AND m.project_id = NEW.project_id
          AND m.memory_type = NEW.memory_type
          AND m.id <> NEW.id
    ) THEN RAISE(ABORT, 'memory supersession scope is incoherent') END;
END;

CREATE TRIGGER memory_entries_scope_update
BEFORE UPDATE OF project_id, content_artifact_id, verification_artifact_id, superseded_by
ON memory_entries
FOR EACH ROW
BEGIN
    SELECT CASE WHEN NOT EXISTS (
        SELECT 1 FROM artifacts a
        WHERE a.id = NEW.content_artifact_id AND a.project_id = NEW.project_id
    ) THEN RAISE(ABORT, 'memory content artifact scope is incoherent') END;
    SELECT CASE WHEN NEW.verification_artifact_id IS NOT NULL AND NOT EXISTS (
        SELECT 1 FROM artifacts a
        WHERE a.id = NEW.verification_artifact_id AND a.project_id = NEW.project_id
    ) THEN RAISE(ABORT, 'memory verification artifact scope is incoherent') END;
    SELECT CASE WHEN NEW.superseded_by IS NOT NULL AND NOT EXISTS (
        SELECT 1 FROM memory_entries m
        WHERE m.id = NEW.superseded_by
          AND m.project_id = NEW.project_id
          AND m.memory_type = NEW.memory_type
          AND m.id <> OLD.id
    ) THEN RAISE(ABORT, 'memory supersession scope is incoherent') END;
END;

CREATE TRIGGER repository_graph_edges_scope_insert
BEFORE INSERT ON repository_graph_edges
FOR EACH ROW
BEGIN
    SELECT CASE WHEN NOT EXISTS (
        SELECT 1
        FROM repository_graph_nodes fn
        JOIN source_documents fd ON fd.id = fn.document_id
        JOIN repository_graph_nodes tn ON tn.id = NEW.to_node_id
        JOIN source_documents td ON td.id = tn.document_id
        WHERE fn.id = NEW.from_node_id
          AND fd.project_id = NEW.project_id
          AND td.project_id = NEW.project_id
    ) THEN RAISE(ABORT, 'repository graph edge project scope is incoherent') END;
END;

CREATE TRIGGER repository_graph_edges_scope_update
BEFORE UPDATE OF project_id, from_node_id, to_node_id ON repository_graph_edges
FOR EACH ROW
BEGIN
    SELECT CASE WHEN NOT EXISTS (
        SELECT 1
        FROM repository_graph_nodes fn
        JOIN source_documents fd ON fd.id = fn.document_id
        JOIN repository_graph_nodes tn ON tn.id = NEW.to_node_id
        JOIN source_documents td ON td.id = tn.document_id
        WHERE fn.id = NEW.from_node_id
          AND fd.project_id = NEW.project_id
          AND td.project_id = NEW.project_id
    ) THEN RAISE(ABORT, 'repository graph edge project scope is incoherent') END;
END;

CREATE TRIGGER update_journal_identity_immutable
BEFORE UPDATE OF from_application_version, to_application_version,
    from_schema_version, to_schema_version, backup_manifest_artifact_id, created_at
ON update_journal
FOR EACH ROW
BEGIN
    SELECT RAISE(ABORT, 'update journal identity is immutable');
END;

CREATE TRIGGER update_journal_terminal_irreversible
BEFORE UPDATE OF status ON update_journal
FOR EACH ROW
WHEN OLD.status IN ('health_verified', 'rolled_back', 'failed') AND NEW.status <> OLD.status
BEGIN
    SELECT RAISE(ABORT, 'terminal update journal status is irreversible');
END;

CREATE TRIGGER update_journal_delete_forbidden
BEFORE DELETE ON update_journal
FOR EACH ROW
BEGIN
    SELECT RAISE(ABORT, 'update journal records are retained');
END;


-- v3.2 self-review hardening, pass three: terminal consistency and exact approval binding.

CREATE TRIGGER projects_repository_identity_digest_insert
BEFORE INSERT ON projects
FOR EACH ROW
WHEN length(NEW.repository_identity) <> 71
  OR substr(NEW.repository_identity, 1, 7) <> 'sha256:'
  OR substr(NEW.repository_identity, 8) GLOB '*[^0-9a-f]*'
BEGIN
    SELECT RAISE(ABORT, 'project repository identity must be a sha256 digest');
END;

CREATE TRIGGER projects_repository_identity_digest_update
BEFORE UPDATE OF repository_identity ON projects
FOR EACH ROW
WHEN length(NEW.repository_identity) <> 71
  OR substr(NEW.repository_identity, 1, 7) <> 'sha256:'
  OR substr(NEW.repository_identity, 8) GLOB '*[^0-9a-f]*'
BEGIN
    SELECT RAISE(ABORT, 'project repository identity must be a sha256 digest');
END;

CREATE TRIGGER operation_intents_interrupted_irreversible
BEFORE UPDATE OF status ON operation_intents
FOR EACH ROW
WHEN OLD.status = 'interrupted' AND NEW.status <> OLD.status
BEGIN
    SELECT RAISE(ABORT, 'terminal operation intent status is irreversible');
END;

CREATE TRIGGER operation_intents_terminal_requires_attempt
BEFORE UPDATE OF status ON operation_intents
FOR EACH ROW
WHEN NEW.status IN ('succeeded', 'failed', 'interrupted', 'indeterminate', 'cancelled')
  AND OLD.status <> NEW.status
BEGIN
    SELECT CASE WHEN NEW.current_attempt_no < 1 OR NOT EXISTS (
        SELECT 1 FROM operation_attempts a
        WHERE a.operation_intent_id = OLD.id
          AND a.task_id = OLD.task_id
          AND a.attempt_no = NEW.current_attempt_no
          AND a.status = NEW.status
    ) THEN RAISE(ABORT, 'terminal operation intent requires its matching current terminal attempt') END;
END;

CREATE TRIGGER artifact_operations_terminal_consistency_insert
BEFORE INSERT ON artifact_operations
FOR EACH ROW
BEGIN
    SELECT CASE WHEN NEW.status = 'completed' AND NEW.completed_at IS NULL
        THEN RAISE(ABORT, 'completed artifact operation requires a completion time') END;
    SELECT CASE WHEN NEW.status <> 'completed' AND NEW.completed_at IS NOT NULL
        THEN RAISE(ABORT, 'non-completed artifact operation cannot have a completion time') END;
END;

CREATE TRIGGER artifact_operations_terminal_consistency_update
BEFORE UPDATE OF status, completed_at ON artifact_operations
FOR EACH ROW
BEGIN
    SELECT CASE WHEN NEW.status = 'completed' AND NEW.completed_at IS NULL
        THEN RAISE(ABORT, 'completed artifact operation requires a completion time') END;
    SELECT CASE WHEN NEW.status <> 'completed' AND NEW.completed_at IS NOT NULL
        THEN RAISE(ABORT, 'non-completed artifact operation cannot have a completion time') END;
END;

CREATE TRIGGER executor_lease_state_consistency_insert
BEFORE INSERT ON executor_leases
FOR EACH ROW
BEGIN
    SELECT CASE WHEN julianday(NEW.expires_at) <= julianday(NEW.acquired_at)
        THEN RAISE(ABORT, 'lease expiry must be after acquisition') END;
    SELECT CASE WHEN NEW.status = 'active' AND NEW.released_at IS NOT NULL
        THEN RAISE(ABORT, 'active lease cannot have a release time') END;
    SELECT CASE WHEN NEW.status <> 'active' AND NEW.released_at IS NULL
        THEN RAISE(ABORT, 'terminal lease requires a release time') END;
END;

CREATE TRIGGER executor_lease_state_consistency_update
BEFORE UPDATE OF status, released_at ON executor_leases
FOR EACH ROW
BEGIN
    SELECT CASE WHEN NEW.status = 'active' AND NEW.released_at IS NOT NULL
        THEN RAISE(ABORT, 'active lease cannot have a release time') END;
    SELECT CASE WHEN NEW.status <> 'active' AND NEW.released_at IS NULL
        THEN RAISE(ABORT, 'terminal lease requires a release time') END;
END;

CREATE TRIGGER executor_lease_release_time_set_once
BEFORE UPDATE OF released_at ON executor_leases
FOR EACH ROW
WHEN OLD.released_at IS NOT NULL AND NEW.released_at IS NOT OLD.released_at
BEGIN
    SELECT RAISE(ABORT, 'lease release time is set-once');
END;

CREATE TRIGGER protocol_request_state_consistency_update
BEFORE UPDATE OF status, response_artifact_id, completed_at ON protocol_requests
FOR EACH ROW
BEGIN
    SELECT CASE WHEN NEW.status = 'completed'
        AND (NEW.response_artifact_id IS NULL OR NEW.completed_at IS NULL)
        THEN RAISE(ABORT, 'completed protocol request requires persisted response and completion time') END;
    SELECT CASE WHEN NEW.status = 'failed' AND NEW.completed_at IS NULL
        THEN RAISE(ABORT, 'failed protocol request requires a completion time') END;
    SELECT CASE WHEN NEW.status = 'pending' AND NEW.completed_at IS NOT NULL
        THEN RAISE(ABORT, 'pending protocol request cannot have a completion time') END;
END;

CREATE TRIGGER messages_superseded_requires_replacement_insert
BEFORE INSERT ON messages
FOR EACH ROW
WHEN NEW.status = 'superseded' AND NEW.superseded_by IS NULL
BEGIN
    SELECT RAISE(ABORT, 'superseded message requires a replacement');
END;

CREATE TRIGGER messages_superseded_requires_replacement_update
BEFORE UPDATE OF status, superseded_by ON messages
FOR EACH ROW
WHEN NEW.status = 'superseded' AND NEW.superseded_by IS NULL
BEGIN
    SELECT RAISE(ABORT, 'superseded message requires a replacement');
END;

CREATE TRIGGER operation_attempt_policy_named_approval_insert
BEFORE INSERT ON operation_attempts
FOR EACH ROW
BEGIN
    SELECT CASE WHEN EXISTS (
        SELECT 1 FROM policy_decisions p
        WHERE p.id = NEW.policy_decision_id
          AND p.approval_id IS NOT NULL
          AND p.approval_id IS NOT NEW.approval_id
    ) THEN RAISE(ABORT, 'attempt approval does not match the policy-named approval') END;
END;

CREATE TRIGGER approvals_final_commit_type_insert
BEFORE INSERT ON approvals
FOR EACH ROW
BEGIN
    SELECT CASE WHEN EXISTS (
        SELECT 1 FROM operation_intents i
        WHERE i.id = NEW.operation_intent_id
          AND i.operation_kind = 'git.final_commit'
    ) AND NEW.approval_type <> 'final_commit'
    THEN RAISE(ABORT, 'git.final_commit intent requires final_commit approval type') END;
    SELECT CASE WHEN EXISTS (
        SELECT 1 FROM operation_intents i
        WHERE i.id = NEW.operation_intent_id
          AND i.operation_kind <> 'git.final_commit'
    ) AND NEW.approval_type = 'final_commit'
    THEN RAISE(ABORT, 'final_commit approval type requires git.final_commit intent') END;
END;

CREATE TRIGGER approvals_resolution_time_matches_receipt
BEFORE UPDATE OF status, resolved_at ON approvals
FOR EACH ROW
WHEN NEW.status IN ('granted', 'denied')
BEGIN
    SELECT CASE WHEN NOT EXISTS (
        SELECT 1 FROM approval_decision_receipts r
        WHERE r.approval_id = OLD.id
          AND r.decision = NEW.status
          AND r.decided_at = NEW.resolved_at
    ) THEN RAISE(ABORT, 'approval resolution time must match the immutable decision receipt') END;
END;


-- v3.2 self-review hardening, pass four: retained run and resolution evidence.

CREATE TRIGGER agent_runs_evidence_set_once
BEFORE UPDATE OF started_at, completed_at, provider_usage_json, core_usage_json,
    estimated_cost_microunits, error_json
ON agent_runs
FOR EACH ROW
WHEN (OLD.started_at IS NOT NULL AND NEW.started_at IS NOT OLD.started_at)
  OR (OLD.completed_at IS NOT NULL AND NEW.completed_at IS NOT OLD.completed_at)
  OR (OLD.provider_usage_json IS NOT NULL AND NEW.provider_usage_json IS NOT OLD.provider_usage_json)
  OR (OLD.core_usage_json IS NOT NULL AND NEW.core_usage_json IS NOT OLD.core_usage_json)
  OR (OLD.estimated_cost_microunits IS NOT NULL AND NEW.estimated_cost_microunits IS NOT OLD.estimated_cost_microunits)
  OR (OLD.error_json IS NOT NULL AND NEW.error_json IS NOT OLD.error_json)
BEGIN
    SELECT RAISE(ABORT, 'agent run evidence is set-once');
END;

CREATE TRIGGER agent_runs_delete_forbidden
BEFORE DELETE ON agent_runs
FOR EACH ROW
BEGIN
    SELECT RAISE(ABORT, 'agent runs are retained');
END;

CREATE TRIGGER messages_supersession_evidence_set_once
BEFORE UPDATE OF superseded_by ON messages
FOR EACH ROW
WHEN OLD.superseded_by IS NOT NULL AND NEW.superseded_by IS NOT OLD.superseded_by
BEGIN
    SELECT RAISE(ABORT, 'message supersession evidence is set-once');
END;

CREATE TRIGGER approvals_resolution_evidence_set_once
BEFORE UPDATE OF resolved_at, invalidation_reason ON approvals
FOR EACH ROW
WHEN (OLD.resolved_at IS NOT NULL AND NEW.resolved_at IS NOT OLD.resolved_at)
  OR (OLD.invalidation_reason IS NOT NULL AND NEW.invalidation_reason IS NOT OLD.invalidation_reason)
BEGIN
    SELECT RAISE(ABORT, 'approval resolution evidence is set-once');
END;

CREATE INDEX idx_tasks_project_phase
    ON tasks(project_id, phase, updated_at);

CREATE INDEX idx_events_stream_sequence
    ON events(stream_id, sequence);

CREATE INDEX idx_events_correlation
    ON events(correlation_id, created_at);

CREATE INDEX idx_artifacts_task_type
    ON artifacts(task_id, artifact_type, created_at);

CREATE INDEX idx_artifacts_content_hash
    ON artifacts(content_hash, availability);

CREATE INDEX idx_artifact_operations_status
    ON artifact_operations(status, updated_at);

CREATE INDEX idx_agent_runs_task_status
    ON agent_runs(task_id, status, started_at);

CREATE UNIQUE INDEX messages_one_terminal_result_per_run
    ON messages(run_id) WHERE message_type = 'terminal_result';

CREATE INDEX idx_messages_thread_time
    ON messages(task_id, thread_id, core_received_at);

CREATE INDEX idx_approvals_pending
    ON approvals(task_id, status, expires_at);

CREATE INDEX idx_policy_decisions_task_action
    ON policy_decisions(task_id, action, created_at);

CREATE INDEX idx_operation_intents_dispatch
    ON operation_intents(status, current_attempt_no, created_at);

CREATE INDEX idx_operation_intents_task
    ON operation_intents(task_id, status, updated_at);

CREATE INDEX idx_tool_executions_task_status
    ON tool_executions(task_id, status, started_at);

CREATE INDEX idx_memory_entries_project_status
    ON memory_entries(project_id, status, memory_type);

CREATE INDEX idx_source_documents_current
    ON source_documents(project_id, index_state, logical_path);

CREATE INDEX idx_source_chunks_document
    ON source_chunks(document_id, start_line);

CREATE INDEX idx_graph_edges_from
    ON repository_graph_edges(from_node_id, edge_kind);

CREATE INDEX idx_graph_edges_to
    ON repository_graph_edges(to_node_id, edge_kind);

COMMIT;

-- After this transaction succeeds, the migration runner records version 2
-- with the actual file checksum, application version, and authoritative time.
