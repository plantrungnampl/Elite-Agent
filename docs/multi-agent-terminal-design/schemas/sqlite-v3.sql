-- Local-First Multi-Agent Engineering Terminal
-- Authoritative v4.0 clean-install schema v3.
-- Includes the full v3.2 authority baseline plus cognitive memory and agent-quality extensions.
-- The packaged checksum distinguishes this contract from sqlite-v2 and earlier v3 drafts.
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

CREATE TRIGGER memory_entries_insert_forbidden
BEFORE INSERT ON memory_entries
FOR EACH ROW
BEGIN
    SELECT RAISE(ABORT, 'legacy memory entries are read-only after v4 schema installation');
END;

CREATE TRIGGER memory_entries_update_forbidden
BEFORE UPDATE ON memory_entries
FOR EACH ROW
BEGIN
    SELECT RAISE(ABORT, 'legacy memory entries are read-only after v4 schema installation');
END;

CREATE TRIGGER memory_entries_delete_forbidden
BEFORE DELETE ON memory_entries
FOR EACH ROW
BEGIN
    SELECT RAISE(ABORT, 'legacy memory entries are retained after v4 schema installation');
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



-- v4.0 cognitive memory and agent-quality authority extension.

CREATE TABLE memory_records (
    id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE RESTRICT,
    logical_key TEXT NOT NULL,
    origin_task_id TEXT REFERENCES tasks(id) ON DELETE RESTRICT,
    origin_run_id TEXT REFERENCES agent_runs(id) ON DELETE RESTRICT,
    memory_type TEXT NOT NULL CHECK (
        memory_type IN ('episodic','semantic','procedural','negative','preference')
    ),
    version INTEGER NOT NULL CHECK (version >= 1),
    status TEXT NOT NULL CHECK (
        status IN ('candidate','verified','approved','active','rejected','stale','superseded','retracted')
    ),
    content_artifact_id TEXT NOT NULL REFERENCES artifacts(id) ON DELETE RESTRICT,
    applicability_json TEXT NOT NULL CHECK (json_valid(applicability_json)),
    invalidation_conditions_json TEXT NOT NULL CHECK (json_valid(invalidation_conditions_json)),
    confidence_millionths INTEGER NOT NULL CHECK (confidence_millionths BETWEEN 0 AND 1000000),
    sensitivity TEXT NOT NULL,
    expires_at TEXT,
    created_at TEXT NOT NULL,
    status_changed_at TEXT NOT NULL,
    activated_at TEXT,
    UNIQUE(project_id, logical_key, version),
    CHECK (COALESCE(json_type(applicability_json)='object',0)),
    CHECK (COALESCE(json_type(applicability_json,'$.summary')='text' AND length(json_extract(applicability_json,'$.summary'))>0,0)),
    CHECK (COALESCE(json_type(applicability_json,'$.scope')='object',0)),
    CHECK (COALESCE(json_extract(applicability_json,'$.scope.kind') IN ('task','project','user','workspace','communication-surface'),0)),
    CHECK (COALESCE(json_type(applicability_json,'$.scope.id')='text' AND length(json_extract(applicability_json,'$.scope.id'))>0,0)),
    CHECK (COALESCE(json_extract(applicability_json,'$.scope.kind')<>'communication-surface' OR (json_type(applicability_json,'$.scope.surface')='text' AND length(json_extract(applicability_json,'$.scope.surface'))>0),0)),
    CHECK (memory_type<>'preference' OR COALESCE(json_type(applicability_json,'$.subject')='object' AND json_extract(applicability_json,'$.subject.kind') IN ('user','project','workspace') AND json_type(applicability_json,'$.subject.id')='text' AND length(json_extract(applicability_json,'$.subject.id'))>0,0)),
    CHECK (COALESCE(json_type(invalidation_conditions_json)='array' AND json_array_length(invalidation_conditions_json)>=1,0)),
    CHECK (status_changed_at >= created_at),
    CHECK (status <> 'candidate' OR activated_at IS NULL),
    CHECK (status <> 'active' OR activated_at IS NOT NULL)
) STRICT;

CREATE TABLE memory_evidence_links (
    id TEXT PRIMARY KEY,
    memory_id TEXT NOT NULL REFERENCES memory_records(id) ON DELETE RESTRICT,
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE RESTRICT,
    evidence_kind TEXT NOT NULL CHECK (evidence_kind IN ('artifact','source_document','source_chunk','event','tool_receipt','decision','evaluation')),
    artifact_id TEXT REFERENCES artifacts(id) ON DELETE RESTRICT,
    source_document_id TEXT REFERENCES source_documents(id) ON DELETE RESTRICT,
    source_chunk_id TEXT REFERENCES source_chunks(id) ON DELETE RESTRICT,
    evidence_digest TEXT NOT NULL CHECK (length(evidence_digest)=71 AND substr(evidence_digest,1,7)='sha256:' AND substr(evidence_digest,8) NOT GLOB '*[^0-9a-f]*'),
    relationship TEXT NOT NULL CHECK (relationship IN ('supports','verifies','refutes','origin','applicability')),
    created_at TEXT NOT NULL,
    CHECK ((artifact_id IS NOT NULL) + (source_document_id IS NOT NULL) + (source_chunk_id IS NOT NULL) = 1),
    CHECK (
        (evidence_kind IN ('artifact','event','tool_receipt','decision','evaluation') AND artifact_id IS NOT NULL)
        OR (evidence_kind='source_document' AND source_document_id IS NOT NULL)
        OR (evidence_kind='source_chunk' AND source_chunk_id IS NOT NULL)
    )
) STRICT;

CREATE TABLE memory_relations (
    id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE RESTRICT,
    from_memory_id TEXT NOT NULL REFERENCES memory_records(id) ON DELETE RESTRICT,
    to_memory_id TEXT NOT NULL REFERENCES memory_records(id) ON DELETE RESTRICT,
    relation_kind TEXT NOT NULL CHECK (relation_kind IN ('supersedes','contradicts','derived_from','refines','duplicates')),
    evidence_artifact_id TEXT REFERENCES artifacts(id) ON DELETE RESTRICT,
    created_at TEXT NOT NULL,
    CHECK (from_memory_id <> to_memory_id),
    UNIQUE(from_memory_id,to_memory_id,relation_kind)
) STRICT;

CREATE TABLE memory_promotion_reviews (
    id TEXT PRIMARY KEY,
    memory_id TEXT NOT NULL REFERENCES memory_records(id) ON DELETE RESTRICT,
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE RESTRICT,
    reviewer_kind TEXT NOT NULL CHECK (reviewer_kind IN ('user','deterministic','policy')),
    reviewer_id TEXT NOT NULL,
    decision TEXT NOT NULL CHECK (decision IN ('granted','rejected','reverify')),
    evidence_artifact_id TEXT NOT NULL REFERENCES artifacts(id) ON DELETE RESTRICT,
    decision_digest TEXT NOT NULL CHECK (length(decision_digest)=71 AND substr(decision_digest,1,7)='sha256:' AND substr(decision_digest,8) NOT GLOB '*[^0-9a-f]*'),
    decided_at TEXT NOT NULL,
    UNIQUE(memory_id, decision_digest)
) STRICT;

CREATE TABLE working_memory_snapshots (
    id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE RESTRICT,
    task_id TEXT NOT NULL REFERENCES tasks(id) ON DELETE RESTRICT,
    run_id TEXT NOT NULL REFERENCES agent_runs(id) ON DELETE RESTRICT,
    sequence INTEGER NOT NULL CHECK (sequence >= 1),
    snapshot_artifact_id TEXT NOT NULL REFERENCES artifacts(id) ON DELETE RESTRICT,
    snapshot_digest TEXT NOT NULL CHECK (length(snapshot_digest)=71 AND substr(snapshot_digest,1,7)='sha256:' AND substr(snapshot_digest,8) NOT GLOB '*[^0-9a-f]*'),
    created_at TEXT NOT NULL,
    UNIQUE(run_id, sequence)
) STRICT;

CREATE TABLE episodes (
    id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE RESTRICT,
    task_id TEXT NOT NULL REFERENCES tasks(id) ON DELETE RESTRICT,
    run_id TEXT NOT NULL REFERENCES agent_runs(id) ON DELETE RESTRICT,
    outcome TEXT NOT NULL CHECK (outcome IN ('succeeded','failed','blocked','cancelled','indeterminate')),
    summary_artifact_id TEXT NOT NULL REFERENCES artifacts(id) ON DELETE RESTRICT,
    verification_artifact_id TEXT REFERENCES artifacts(id) ON DELETE RESTRICT,
    repository_revision TEXT NOT NULL,
    created_at TEXT NOT NULL,
    UNIQUE(run_id)
) STRICT;

CREATE TABLE episode_steps (
    id TEXT PRIMARY KEY,
    episode_id TEXT NOT NULL REFERENCES episodes(id) ON DELETE RESTRICT,
    sequence INTEGER NOT NULL CHECK (sequence >= 1),
    step_kind TEXT NOT NULL CHECK (step_kind IN ('observation','action','tool_result','decision','failure','verification')),
    artifact_id TEXT NOT NULL REFERENCES artifacts(id) ON DELETE RESTRICT,
    created_at TEXT NOT NULL,
    UNIQUE(episode_id, sequence)
) STRICT;

CREATE TABLE index_generations (
    id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE RESTRICT,
    engine_id TEXT NOT NULL,
    engine_version TEXT NOT NULL,
    configuration_digest TEXT NOT NULL CHECK (length(configuration_digest)=71 AND substr(configuration_digest,1,7)='sha256:' AND substr(configuration_digest,8) NOT GLOB '*[^0-9a-f]*'),
    status TEXT NOT NULL CHECK (status IN ('building','current','stale','failed','retired')),
    source_manifest_artifact_id TEXT NOT NULL REFERENCES artifacts(id) ON DELETE RESTRICT,
    created_at TEXT NOT NULL,
    completed_at TEXT,
    UNIQUE(project_id, engine_id, id),
    CHECK (status IN ('building') OR completed_at IS NOT NULL)
) STRICT;

CREATE TABLE retrieval_sessions (
    id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE RESTRICT,
    task_id TEXT NOT NULL REFERENCES tasks(id) ON DELETE RESTRICT,
    run_id TEXT NOT NULL REFERENCES agent_runs(id) ON DELETE RESTRICT,
    index_generation_id TEXT REFERENCES index_generations(id) ON DELETE RESTRICT,
    query_artifact_id TEXT NOT NULL REFERENCES artifacts(id) ON DELETE RESTRICT,
    plan_artifact_id TEXT NOT NULL REFERENCES artifacts(id) ON DELETE RESTRICT,
    engine_id TEXT NOT NULL,
    engine_version TEXT NOT NULL,
    pipeline_version TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('running','succeeded','degraded','failed','indeterminate')),
    branch_status_json TEXT NOT NULL CHECK (json_valid(branch_status_json)),
    trace_artifact_id TEXT REFERENCES artifacts(id) ON DELETE RESTRICT,
    trace_digest TEXT CHECK (trace_digest IS NULL OR (length(trace_digest)=71 AND substr(trace_digest,1,7)='sha256:' AND substr(trace_digest,8) NOT GLOB '*[^0-9a-f]*')),
    started_at TEXT NOT NULL,
    completed_at TEXT,
    CHECK (status='running' OR (completed_at IS NOT NULL AND trace_artifact_id IS NOT NULL AND trace_digest IS NOT NULL))
) STRICT;

CREATE TABLE retrieval_candidates (
    id TEXT PRIMARY KEY,
    retrieval_session_id TEXT NOT NULL REFERENCES retrieval_sessions(id) ON DELETE RESTRICT,
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE RESTRICT,
    source_kind TEXT NOT NULL CHECK (source_kind IN ('artifact','source_document','source_chunk','memory')),
    artifact_id TEXT REFERENCES artifacts(id) ON DELETE RESTRICT,
    source_document_id TEXT REFERENCES source_documents(id) ON DELETE RESTRICT,
    source_chunk_id TEXT REFERENCES source_chunks(id) ON DELETE RESTRICT,
    memory_id TEXT REFERENCES memory_records(id) ON DELETE RESTRICT,
    source_revision TEXT NOT NULL,
    source_hash TEXT NOT NULL CHECK (length(source_hash)=71 AND substr(source_hash,1,7)='sha256:' AND substr(source_hash,8) NOT GLOB '*[^0-9a-f]*'),
    rank_position INTEGER NOT NULL CHECK (rank_position >= 1),
    score_millionths INTEGER NOT NULL CHECK (score_millionths BETWEEN 0 AND 1000000),
    methods_json TEXT NOT NULL CHECK (json_valid(methods_json)),
    reason_artifact_id TEXT NOT NULL REFERENCES artifacts(id) ON DELETE RESTRICT,
    freshness TEXT NOT NULL CHECK (freshness IN ('current','stale','unknown')),
    selected INTEGER NOT NULL CHECK (selected IN (0,1)),
    UNIQUE(retrieval_session_id, rank_position),
    CHECK ((artifact_id IS NOT NULL) + (source_document_id IS NOT NULL) + (source_chunk_id IS NOT NULL) + (memory_id IS NOT NULL) = 1),
    CHECK (
        (source_kind='artifact' AND artifact_id IS NOT NULL)
        OR (source_kind='source_document' AND source_document_id IS NOT NULL)
        OR (source_kind='source_chunk' AND source_chunk_id IS NOT NULL)
        OR (source_kind='memory' AND memory_id IS NOT NULL)
    )
) STRICT;

CREATE TABLE context_package_items (
    id TEXT PRIMARY KEY,
    context_package_id TEXT NOT NULL REFERENCES context_packages(id) ON DELETE RESTRICT,
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE RESTRICT,
    task_id TEXT NOT NULL REFERENCES tasks(id) ON DELETE RESTRICT,
    retrieval_candidate_id TEXT REFERENCES retrieval_candidates(id) ON DELETE RESTRICT,
    category TEXT NOT NULL,
    source_kind TEXT NOT NULL CHECK (source_kind IN ('artifact','source_document','source_chunk','memory','event','decision','tool_receipt')),
    source_artifact_id TEXT REFERENCES artifacts(id) ON DELETE RESTRICT,
    source_document_id TEXT REFERENCES source_documents(id) ON DELETE RESTRICT,
    source_chunk_id TEXT REFERENCES source_chunks(id) ON DELETE RESTRICT,
    memory_id TEXT REFERENCES memory_records(id) ON DELETE RESTRICT,
    source_revision TEXT NOT NULL,
    source_hash TEXT NOT NULL CHECK (length(source_hash)=71 AND substr(source_hash,1,7)='sha256:' AND substr(source_hash,8) NOT GLOB '*[^0-9a-f]*'),
    inclusion_reason_artifact_id TEXT NOT NULL REFERENCES artifacts(id) ON DELETE RESTRICT,
    authority_state TEXT NOT NULL CHECK (authority_state IN ('authoritative','verified_memory','assertion','unknown')),
    token_count INTEGER NOT NULL CHECK (token_count >= 0),
    redacted INTEGER NOT NULL CHECK (redacted IN (0,1)),
    UNIQUE(context_package_id, id),
    CHECK ((source_artifact_id IS NOT NULL) + (source_document_id IS NOT NULL) + (source_chunk_id IS NOT NULL) + (memory_id IS NOT NULL) = 1),
    CHECK (
        (source_kind IN ('artifact','event','decision','tool_receipt') AND source_artifact_id IS NOT NULL)
        OR (source_kind='source_document' AND source_document_id IS NOT NULL)
        OR (source_kind='source_chunk' AND source_chunk_id IS NOT NULL)
        OR (source_kind='memory' AND memory_id IS NOT NULL)
    )
) STRICT;

CREATE TABLE context_item_feedback (
    id TEXT PRIMARY KEY,
    context_package_item_id TEXT NOT NULL REFERENCES context_package_items(id) ON DELETE RESTRICT,
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE RESTRICT,
    task_id TEXT NOT NULL REFERENCES tasks(id) ON DELETE RESTRICT,
    run_id TEXT NOT NULL REFERENCES agent_runs(id) ON DELETE RESTRICT,
    label TEXT NOT NULL CHECK (label IN ('critical','useful','redundant','irrelevant','stale','contradictory','misleading')),
    used_in_conclusion INTEGER NOT NULL CHECK (used_in_conclusion IN (0,1)),
    feedback_artifact_id TEXT REFERENCES artifacts(id) ON DELETE RESTRICT,
    created_at TEXT NOT NULL,
    UNIQUE(context_package_item_id, run_id)
) STRICT;

CREATE TABLE run_reflections (
    id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE RESTRICT,
    task_id TEXT NOT NULL REFERENCES tasks(id) ON DELETE RESTRICT,
    run_id TEXT NOT NULL REFERENCES agent_runs(id) ON DELETE RESTRICT,
    reflection_artifact_id TEXT NOT NULL REFERENCES artifacts(id) ON DELETE RESTRICT,
    reflection_digest TEXT NOT NULL CHECK (length(reflection_digest)=71 AND substr(reflection_digest,1,7)='sha256:' AND substr(reflection_digest,8) NOT GLOB '*[^0-9a-f]*'),
    created_at TEXT NOT NULL,
    UNIQUE(run_id)
) STRICT;

CREATE TABLE run_evaluations (
    id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE RESTRICT,
    task_id TEXT NOT NULL REFERENCES tasks(id) ON DELETE RESTRICT,
    run_id TEXT NOT NULL REFERENCES agent_runs(id) ON DELETE RESTRICT,
    evaluator_version TEXT NOT NULL,
    configuration_digest TEXT NOT NULL CHECK (length(configuration_digest)=71 AND substr(configuration_digest,1,7)='sha256:' AND substr(configuration_digest,8) NOT GLOB '*[^0-9a-f]*'),
    scores_json TEXT NOT NULL CHECK (json_valid(scores_json)),
    gate_decision TEXT NOT NULL CHECK (gate_decision IN ('pass','repair','blocked','indeterminate')),
    evaluation_artifact_id TEXT NOT NULL REFERENCES artifacts(id) ON DELETE RESTRICT,
    created_at TEXT NOT NULL,
    UNIQUE(run_id, evaluator_version, configuration_digest)
) STRICT;

CREATE TABLE benchmark_suites (
    id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE RESTRICT,
    version INTEGER NOT NULL CHECK (version >= 1),
    manifest_artifact_id TEXT NOT NULL REFERENCES artifacts(id) ON DELETE RESTRICT,
    manifest_digest TEXT NOT NULL CHECK (length(manifest_digest)=71 AND substr(manifest_digest,1,7)='sha256:' AND substr(manifest_digest,8) NOT GLOB '*[^0-9a-f]*'),
    created_at TEXT NOT NULL,
    UNIQUE(project_id, id, version)
) STRICT;

CREATE TABLE benchmark_cases (
    id TEXT PRIMARY KEY,
    suite_id TEXT NOT NULL REFERENCES benchmark_suites(id) ON DELETE RESTRICT,
    case_version INTEGER NOT NULL CHECK (case_version >= 1),
    case_artifact_id TEXT NOT NULL REFERENCES artifacts(id) ON DELETE RESTRICT,
    repository_revision TEXT NOT NULL,
    budget_profile_digest TEXT NOT NULL CHECK (length(budget_profile_digest)=71 AND substr(budget_profile_digest,1,7)='sha256:' AND substr(budget_profile_digest,8) NOT GLOB '*[^0-9a-f]*'),
    created_at TEXT NOT NULL,
    UNIQUE(suite_id, id, case_version)
) STRICT;

CREATE TABLE benchmark_runs (
    id TEXT PRIMARY KEY,
    benchmark_case_id TEXT NOT NULL REFERENCES benchmark_cases(id) ON DELETE RESTRICT,
    task_id TEXT NOT NULL REFERENCES tasks(id) ON DELETE RESTRICT,
    system_configuration_digest TEXT NOT NULL CHECK (length(system_configuration_digest)=71 AND substr(system_configuration_digest,1,7)='sha256:' AND substr(system_configuration_digest,8) NOT GLOB '*[^0-9a-f]*'),
    evaluator_configuration_digest TEXT NOT NULL CHECK (length(evaluator_configuration_digest)=71 AND substr(evaluator_configuration_digest,1,7)='sha256:' AND substr(evaluator_configuration_digest,8) NOT GLOB '*[^0-9a-f]*'),
    result_artifact_id TEXT REFERENCES artifacts(id) ON DELETE RESTRICT,
    status TEXT NOT NULL CHECK (status IN ('planned','running','completed','failed','indeterminate')),
    started_at TEXT,
    completed_at TEXT,
    CHECK (status NOT IN ('completed','failed','indeterminate') OR completed_at IS NOT NULL),
    CHECK (status <> 'completed' OR result_artifact_id IS NOT NULL)
) STRICT;


CREATE TABLE benchmark_comparisons (
    id TEXT PRIMARY KEY,
    baseline_run_id TEXT NOT NULL REFERENCES benchmark_runs(id) ON DELETE RESTRICT,
    candidate_run_id TEXT NOT NULL REFERENCES benchmark_runs(id) ON DELETE RESTRICT,
    comparison_artifact_id TEXT NOT NULL REFERENCES artifacts(id) ON DELETE RESTRICT,
    result TEXT NOT NULL CHECK (result IN ('improved','equivalent','regressed','invalid')),
    created_at TEXT NOT NULL,
    CHECK (baseline_run_id <> candidate_run_id),
    UNIQUE(baseline_run_id,candidate_run_id)
) STRICT;

-- Cross-scope and immutability guards.
CREATE TRIGGER memory_records_scope_insert BEFORE INSERT ON memory_records FOR EACH ROW BEGIN
    SELECT CASE WHEN NEW.origin_task_id IS NOT NULL AND NOT EXISTS (SELECT 1 FROM tasks t WHERE t.id=NEW.origin_task_id AND t.project_id=NEW.project_id) THEN RAISE(ABORT,'memory task/project scope is incoherent') END;
    SELECT CASE WHEN NEW.origin_run_id IS NOT NULL AND NOT EXISTS (SELECT 1 FROM agent_runs r JOIN tasks t ON t.id=r.task_id WHERE r.id=NEW.origin_run_id AND t.project_id=NEW.project_id AND (NEW.origin_task_id IS NULL OR r.task_id=NEW.origin_task_id)) THEN RAISE(ABORT,'memory run scope is incoherent') END;
    SELECT CASE WHEN NOT EXISTS (SELECT 1 FROM artifacts a WHERE a.id=NEW.content_artifact_id AND a.project_id=NEW.project_id AND (NEW.origin_task_id IS NULL OR a.task_id IS NULL OR a.task_id=NEW.origin_task_id)) THEN RAISE(ABORT,'memory content artifact scope is incoherent') END;
    SELECT CASE WHEN json_extract(NEW.applicability_json,'$.scope.kind')='project' AND json_extract(NEW.applicability_json,'$.scope.id')<>NEW.project_id THEN RAISE(ABORT,'memory applicability project scope is incoherent') END;
    SELECT CASE WHEN json_extract(NEW.applicability_json,'$.scope.kind')='task' AND (NEW.origin_task_id IS NULL OR json_extract(NEW.applicability_json,'$.scope.id')<>NEW.origin_task_id) THEN RAISE(ABORT,'memory applicability task scope is incoherent') END;
    SELECT CASE WHEN NEW.memory_type='preference' AND NOT COALESCE(json_type(NEW.applicability_json,'$.subject')='object' AND json_extract(NEW.applicability_json,'$.subject.kind') IN ('user','project','workspace') AND json_type(NEW.applicability_json,'$.subject.id')='text' AND length(json_extract(NEW.applicability_json,'$.subject.id'))>0,0) THEN RAISE(ABORT,'preference memory requires explicit subject') END;
    SELECT CASE WHEN NEW.status<>'candidate' THEN RAISE(ABORT,'new memory must start as candidate') END;
END;

CREATE TRIGGER memory_records_identity_immutable BEFORE UPDATE OF id,project_id,logical_key,origin_task_id,origin_run_id,memory_type,version,content_artifact_id,applicability_json,invalidation_conditions_json,confidence_millionths,sensitivity,expires_at,created_at ON memory_records FOR EACH ROW BEGIN SELECT RAISE(ABORT,'memory identity and content are immutable'); END;

CREATE TRIGGER memory_records_status_transition BEFORE UPDATE OF status,status_changed_at ON memory_records FOR EACH ROW
BEGIN
    SELECT CASE WHEN NOT (
        (OLD.status='candidate' AND NEW.status IN ('verified','rejected','stale','superseded','retracted')) OR
        (OLD.status='verified' AND NEW.status IN ('approved','rejected','stale','superseded','retracted')) OR
        (OLD.status='approved' AND NEW.status IN ('active','rejected','stale','superseded','retracted')) OR
        (OLD.status='active' AND NEW.status IN ('stale','superseded','retracted')) OR
        (OLD.status='stale' AND NEW.status IN ('superseded','retracted')) OR
        OLD.status=NEW.status
    ) THEN RAISE(ABORT,'invalid memory lifecycle transition') END;
    SELECT CASE WHEN NEW.status<>OLD.status AND NEW.status_changed_at<=OLD.status_changed_at THEN RAISE(ABORT,'memory status change requires a newer lifecycle time') END;
    SELECT CASE WHEN NEW.status=OLD.status AND NEW.status_changed_at<>OLD.status_changed_at THEN RAISE(ABORT,'memory lifecycle time changes only with status') END;
END;

CREATE TRIGGER memory_records_verified_update BEFORE UPDATE OF status ON memory_records FOR EACH ROW
WHEN NEW.status='verified' AND OLD.status<>'verified'
BEGIN
    SELECT CASE WHEN NOT EXISTS (SELECT 1 FROM memory_evidence_links e WHERE e.memory_id=NEW.id AND e.project_id=NEW.project_id AND e.relationship IN ('supports','verifies') AND e.created_at>=OLD.status_changed_at) THEN RAISE(ABORT,'verified memory requires current supporting evidence') END;
END;

CREATE TRIGGER memory_records_approved_update BEFORE UPDATE OF status ON memory_records FOR EACH ROW
WHEN NEW.status='approved' AND OLD.status<>'approved'
BEGIN
    SELECT CASE WHEN NOT EXISTS (SELECT 1 FROM memory_promotion_reviews pr WHERE pr.memory_id=NEW.id AND pr.project_id=NEW.project_id AND pr.decision='granted' AND pr.decided_at>=OLD.status_changed_at) THEN RAISE(ABORT,'approved memory requires a current granted promotion review') END;
END;

CREATE TRIGGER memory_records_active_update BEFORE UPDATE OF status,activated_at ON memory_records FOR EACH ROW
WHEN NEW.status='active' AND OLD.status<>'active'
BEGIN
    SELECT CASE WHEN NEW.activated_at IS NULL OR NEW.activated_at<>NEW.status_changed_at THEN RAISE(ABORT,'active memory requires activation time equal to lifecycle transition time') END;
    SELECT CASE WHEN NEW.expires_at IS NOT NULL AND NEW.expires_at<=NEW.status_changed_at THEN RAISE(ABORT,'expired memory cannot become active') END;
    SELECT CASE WHEN NOT EXISTS (SELECT 1 FROM memory_promotion_reviews pr WHERE pr.memory_id=NEW.id AND pr.project_id=NEW.project_id AND pr.decision='granted' AND pr.decided_at>=OLD.status_changed_at) THEN RAISE(ABORT,'active memory requires current granted promotion review') END;
    SELECT CASE WHEN NOT EXISTS (SELECT 1 FROM memory_evidence_links e WHERE e.memory_id=NEW.id AND e.project_id=NEW.project_id AND e.relationship IN ('supports','verifies')) THEN RAISE(ABORT,'active memory requires supporting verification evidence') END;
END;

CREATE TRIGGER memory_records_activation_transition_guard BEFORE UPDATE OF activated_at ON memory_records FOR EACH ROW
WHEN NEW.activated_at IS NOT OLD.activated_at AND NOT (
    OLD.status='approved' AND NEW.status='active' AND OLD.activated_at IS NULL
)
BEGIN SELECT RAISE(ABORT,'memory activation evidence is set-once and only set during approved-to-active transition'); END;

CREATE TRIGGER memory_records_superseded_update BEFORE UPDATE OF status ON memory_records FOR EACH ROW
WHEN NEW.status='superseded' AND OLD.status<>'superseded'
BEGIN
    SELECT CASE WHEN NOT EXISTS (
        SELECT 1 FROM memory_relations rel
        JOIN memory_records newer ON newer.id=rel.from_memory_id
        WHERE rel.to_memory_id=NEW.id AND rel.project_id=NEW.project_id
          AND rel.relation_kind='supersedes'
          AND newer.logical_key=NEW.logical_key
          AND newer.memory_type=NEW.memory_type
          AND newer.version>NEW.version
    ) THEN RAISE(ABORT,'superseded memory requires a newer linked version') END;
END;

CREATE TRIGGER memory_records_delete_forbidden BEFORE DELETE ON memory_records FOR EACH ROW BEGIN SELECT RAISE(ABORT,'memory records are retained'); END;

CREATE TRIGGER memory_evidence_scope_insert BEFORE INSERT ON memory_evidence_links FOR EACH ROW BEGIN
    SELECT CASE WHEN NOT EXISTS (SELECT 1 FROM memory_records m WHERE m.id=NEW.memory_id AND m.project_id=NEW.project_id) THEN RAISE(ABORT,'memory evidence scope is incoherent') END;
    SELECT CASE WHEN NEW.artifact_id IS NOT NULL AND NOT EXISTS (SELECT 1 FROM artifacts a WHERE a.id=NEW.artifact_id AND a.project_id=NEW.project_id) THEN RAISE(ABORT,'memory evidence artifact scope is incoherent') END;
    SELECT CASE WHEN NEW.source_document_id IS NOT NULL AND NOT EXISTS (SELECT 1 FROM source_documents d WHERE d.id=NEW.source_document_id AND d.project_id=NEW.project_id) THEN RAISE(ABORT,'memory evidence document scope is incoherent') END;
    SELECT CASE WHEN NEW.source_chunk_id IS NOT NULL AND NOT EXISTS (SELECT 1 FROM source_chunks c JOIN source_documents d ON d.id=c.document_id WHERE c.id=NEW.source_chunk_id AND d.project_id=NEW.project_id) THEN RAISE(ABORT,'memory evidence chunk scope is incoherent') END;
    SELECT CASE WHEN NEW.artifact_id IS NOT NULL AND NOT EXISTS (SELECT 1 FROM artifacts a WHERE a.id=NEW.artifact_id AND a.content_hash=NEW.evidence_digest) THEN RAISE(ABORT,'memory evidence digest does not match artifact') END;
    SELECT CASE WHEN NEW.source_document_id IS NOT NULL AND NOT EXISTS (SELECT 1 FROM source_documents d WHERE d.id=NEW.source_document_id AND d.content_hash=NEW.evidence_digest) THEN RAISE(ABORT,'memory evidence digest does not match document') END;
    SELECT CASE WHEN NEW.source_chunk_id IS NOT NULL AND NOT EXISTS (SELECT 1 FROM source_chunks c WHERE c.id=NEW.source_chunk_id AND c.content_hash=NEW.evidence_digest) THEN RAISE(ABORT,'memory evidence digest does not match chunk') END;
END;
CREATE TRIGGER memory_evidence_update_forbidden BEFORE UPDATE ON memory_evidence_links FOR EACH ROW BEGIN SELECT RAISE(ABORT,'memory evidence is immutable'); END;
CREATE TRIGGER memory_evidence_delete_forbidden BEFORE DELETE ON memory_evidence_links FOR EACH ROW BEGIN SELECT RAISE(ABORT,'memory evidence is retained'); END;

CREATE TRIGGER memory_relation_scope_insert BEFORE INSERT ON memory_relations FOR EACH ROW BEGIN
    SELECT CASE WHEN NOT EXISTS (SELECT 1 FROM memory_records f JOIN memory_records t ON t.id=NEW.to_memory_id WHERE f.id=NEW.from_memory_id AND f.project_id=NEW.project_id AND t.project_id=NEW.project_id) THEN RAISE(ABORT,'memory relation scope is incoherent') END;
    SELECT CASE WHEN NEW.evidence_artifact_id IS NOT NULL AND NOT EXISTS (SELECT 1 FROM artifacts a WHERE a.id=NEW.evidence_artifact_id AND a.project_id=NEW.project_id) THEN RAISE(ABORT,'memory relation evidence scope is incoherent') END;
    SELECT CASE WHEN NEW.relation_kind='supersedes' AND NOT EXISTS (
        SELECT 1 FROM memory_records f JOIN memory_records old ON old.id=NEW.to_memory_id
        WHERE f.id=NEW.from_memory_id AND f.project_id=NEW.project_id AND old.project_id=NEW.project_id
          AND f.logical_key=old.logical_key AND f.memory_type=old.memory_type AND f.version>old.version
    ) THEN RAISE(ABORT,'memory supersession requires same logical key/type and newer version') END;
END;
CREATE TRIGGER memory_relation_update_forbidden BEFORE UPDATE ON memory_relations FOR EACH ROW BEGIN SELECT RAISE(ABORT,'memory relations are immutable'); END;
CREATE TRIGGER memory_relation_delete_forbidden BEFORE DELETE ON memory_relations FOR EACH ROW BEGIN SELECT RAISE(ABORT,'memory relations are retained'); END;

CREATE TRIGGER memory_review_scope_insert BEFORE INSERT ON memory_promotion_reviews FOR EACH ROW BEGIN
    SELECT CASE WHEN NOT EXISTS (SELECT 1 FROM memory_records m WHERE m.id=NEW.memory_id AND m.project_id=NEW.project_id) THEN RAISE(ABORT,'memory review scope is incoherent') END;
    SELECT CASE WHEN NOT EXISTS (SELECT 1 FROM artifacts a WHERE a.id=NEW.evidence_artifact_id AND a.project_id=NEW.project_id) THEN RAISE(ABORT,'memory review evidence scope is incoherent') END;
    SELECT CASE WHEN NEW.decision='granted' AND NOT EXISTS (SELECT 1 FROM memory_records m WHERE m.id=NEW.memory_id AND m.status IN ('verified','approved') AND NEW.decided_at>=m.status_changed_at) THEN RAISE(ABORT,'promotion grant requires current verified or approved memory') END;
END;
CREATE TRIGGER memory_review_update_forbidden BEFORE UPDATE ON memory_promotion_reviews FOR EACH ROW BEGIN SELECT RAISE(ABORT,'memory promotion reviews are immutable'); END;
CREATE TRIGGER memory_review_delete_forbidden BEFORE DELETE ON memory_promotion_reviews FOR EACH ROW BEGIN SELECT RAISE(ABORT,'memory promotion reviews are retained'); END;

CREATE TRIGGER working_memory_scope_insert BEFORE INSERT ON working_memory_snapshots FOR EACH ROW BEGIN
    SELECT CASE WHEN NOT EXISTS (SELECT 1 FROM agent_runs r JOIN tasks t ON t.id=r.task_id WHERE r.id=NEW.run_id AND r.task_id=NEW.task_id AND t.project_id=NEW.project_id) THEN RAISE(ABORT,'working memory run scope is incoherent') END;
    SELECT CASE WHEN NOT EXISTS (SELECT 1 FROM artifacts a WHERE a.id=NEW.snapshot_artifact_id AND a.project_id=NEW.project_id AND a.task_id=NEW.task_id) THEN RAISE(ABORT,'working memory artifact scope is incoherent') END;
    SELECT CASE WHEN NOT EXISTS (SELECT 1 FROM artifacts a WHERE a.id=NEW.snapshot_artifact_id AND a.content_hash=NEW.snapshot_digest) THEN RAISE(ABORT,'working memory digest does not match artifact') END;
END;
CREATE TRIGGER working_memory_update_forbidden BEFORE UPDATE ON working_memory_snapshots FOR EACH ROW BEGIN SELECT RAISE(ABORT,'working memory snapshots are immutable'); END;
CREATE TRIGGER working_memory_delete_forbidden BEFORE DELETE ON working_memory_snapshots FOR EACH ROW BEGIN SELECT RAISE(ABORT,'working memory snapshots are retained'); END;

CREATE TRIGGER episode_scope_insert BEFORE INSERT ON episodes FOR EACH ROW BEGIN
    SELECT CASE WHEN NOT EXISTS (SELECT 1 FROM agent_runs r JOIN tasks t ON t.id=r.task_id WHERE r.id=NEW.run_id AND r.task_id=NEW.task_id AND t.project_id=NEW.project_id) THEN RAISE(ABORT,'episode run scope is incoherent') END;
    SELECT CASE WHEN NOT EXISTS (SELECT 1 FROM artifacts a WHERE a.id=NEW.summary_artifact_id AND a.project_id=NEW.project_id AND a.task_id=NEW.task_id) THEN RAISE(ABORT,'episode summary scope is incoherent') END;
    SELECT CASE WHEN NEW.verification_artifact_id IS NOT NULL AND NOT EXISTS (SELECT 1 FROM artifacts a WHERE a.id=NEW.verification_artifact_id AND a.project_id=NEW.project_id AND a.task_id=NEW.task_id) THEN RAISE(ABORT,'episode verification scope is incoherent') END;
    SELECT CASE WHEN NOT EXISTS (SELECT 1 FROM agent_runs r WHERE r.id=NEW.run_id AND r.status IN ('succeeded','failed','cancelled','interrupted','indeterminate')) THEN RAISE(ABORT,'episode requires terminal run') END;
    SELECT CASE WHEN NEW.outcome='succeeded' AND NEW.verification_artifact_id IS NULL THEN RAISE(ABORT,'successful episode requires verification evidence') END;
END;
CREATE TRIGGER episode_update_forbidden BEFORE UPDATE ON episodes FOR EACH ROW BEGIN SELECT RAISE(ABORT,'episodes are immutable'); END;
CREATE TRIGGER episode_delete_forbidden BEFORE DELETE ON episodes FOR EACH ROW BEGIN SELECT RAISE(ABORT,'episodes are retained'); END;

CREATE TRIGGER episode_step_scope_insert BEFORE INSERT ON episode_steps FOR EACH ROW BEGIN
    SELECT CASE WHEN NOT EXISTS (SELECT 1 FROM episodes e JOIN artifacts a ON a.id=NEW.artifact_id WHERE e.id=NEW.episode_id AND a.project_id=e.project_id AND a.task_id=e.task_id) THEN RAISE(ABORT,'episode step scope is incoherent') END;
END;
CREATE TRIGGER episode_step_update_forbidden BEFORE UPDATE ON episode_steps FOR EACH ROW BEGIN SELECT RAISE(ABORT,'episode steps are immutable'); END;
CREATE TRIGGER episode_step_delete_forbidden BEFORE DELETE ON episode_steps FOR EACH ROW BEGIN SELECT RAISE(ABORT,'episode steps are retained'); END;

CREATE TRIGGER index_generation_scope_insert BEFORE INSERT ON index_generations FOR EACH ROW BEGIN
    SELECT CASE WHEN NOT EXISTS (SELECT 1 FROM artifacts a WHERE a.id=NEW.source_manifest_artifact_id AND a.project_id=NEW.project_id) THEN RAISE(ABORT,'index generation manifest scope is incoherent') END;
    SELECT CASE WHEN NEW.status<>'building' THEN RAISE(ABORT,'new index generation must start building') END;
END;
CREATE TRIGGER index_generation_identity_immutable BEFORE UPDATE OF id,project_id,engine_id,engine_version,configuration_digest,source_manifest_artifact_id,created_at ON index_generations FOR EACH ROW BEGIN SELECT RAISE(ABORT,'index generation identity is immutable'); END;
CREATE TRIGGER index_generation_status_transition BEFORE UPDATE OF status ON index_generations FOR EACH ROW
WHEN NOT ((OLD.status='building' AND NEW.status IN ('current','failed','stale')) OR (OLD.status='current' AND NEW.status IN ('stale','retired')) OR (OLD.status='stale' AND NEW.status IN ('retired')) OR OLD.status=NEW.status)
BEGIN SELECT RAISE(ABORT,'invalid index generation lifecycle transition'); END;
CREATE TRIGGER index_generation_completion_set_once BEFORE UPDATE OF completed_at ON index_generations FOR EACH ROW
WHEN OLD.completed_at IS NOT NULL AND NEW.completed_at IS NOT OLD.completed_at
BEGIN SELECT RAISE(ABORT,'index generation completion evidence is set-once'); END;
CREATE TRIGGER index_generation_delete_forbidden BEFORE DELETE ON index_generations FOR EACH ROW BEGIN SELECT RAISE(ABORT,'index generation receipts are retained'); END;

CREATE TRIGGER retrieval_session_scope_insert BEFORE INSERT ON retrieval_sessions FOR EACH ROW BEGIN
    SELECT CASE WHEN NOT EXISTS (SELECT 1 FROM agent_runs r JOIN tasks t ON t.id=r.task_id WHERE r.id=NEW.run_id AND r.task_id=NEW.task_id AND t.project_id=NEW.project_id) THEN RAISE(ABORT,'retrieval session run scope is incoherent') END;
    SELECT CASE WHEN NEW.index_generation_id IS NOT NULL AND NOT EXISTS (SELECT 1 FROM index_generations g WHERE g.id=NEW.index_generation_id AND g.project_id=NEW.project_id) THEN RAISE(ABORT,'retrieval generation scope is incoherent') END;
    SELECT CASE WHEN NOT EXISTS (SELECT 1 FROM artifacts a WHERE a.id=NEW.query_artifact_id AND a.project_id=NEW.project_id AND a.task_id=NEW.task_id) THEN RAISE(ABORT,'retrieval query scope is incoherent') END;
    SELECT CASE WHEN NOT EXISTS (SELECT 1 FROM artifacts a WHERE a.id=NEW.plan_artifact_id AND a.project_id=NEW.project_id AND a.task_id=NEW.task_id) THEN RAISE(ABORT,'retrieval plan scope is incoherent') END;
    SELECT CASE WHEN NEW.trace_artifact_id IS NOT NULL OR NEW.trace_digest IS NOT NULL OR NEW.completed_at IS NOT NULL THEN RAISE(ABORT,'running retrieval cannot preload terminal trace evidence') END;
    SELECT CASE WHEN NEW.status<>'running' THEN RAISE(ABORT,'new retrieval session must start running') END;
END;
CREATE TRIGGER retrieval_session_identity_immutable BEFORE UPDATE OF id,project_id,task_id,run_id,index_generation_id,query_artifact_id,plan_artifact_id,engine_id,engine_version,pipeline_version,started_at ON retrieval_sessions FOR EACH ROW BEGIN SELECT RAISE(ABORT,'retrieval session identity is immutable'); END;
CREATE TRIGGER retrieval_session_status_transition BEFORE UPDATE OF status,completed_at,trace_artifact_id,trace_digest ON retrieval_sessions FOR EACH ROW BEGIN
    SELECT CASE WHEN OLD.status<>'running' AND NEW.status<>OLD.status THEN RAISE(ABORT,'retrieval terminal state is irreversible') END;
    SELECT CASE WHEN NEW.status='running' AND (NEW.completed_at IS NOT NULL OR NEW.trace_artifact_id IS NOT NULL OR NEW.trace_digest IS NOT NULL) THEN RAISE(ABORT,'running retrieval cannot contain terminal trace evidence') END;
    SELECT CASE WHEN NEW.status<>'running' AND (NEW.completed_at IS NULL OR NEW.trace_artifact_id IS NULL OR NEW.trace_digest IS NULL) THEN RAISE(ABORT,'terminal retrieval requires completion time and exact trace artifact') END;
    SELECT CASE WHEN NEW.trace_artifact_id IS NOT NULL AND NOT EXISTS (
        SELECT 1 FROM artifacts a WHERE a.id=NEW.trace_artifact_id AND a.project_id=NEW.project_id AND a.task_id=NEW.task_id AND a.content_hash=NEW.trace_digest
    ) THEN RAISE(ABORT,'retrieval trace artifact scope or digest is incoherent') END;
    SELECT CASE WHEN OLD.trace_artifact_id IS NOT NULL AND NEW.trace_artifact_id IS NOT OLD.trace_artifact_id THEN RAISE(ABORT,'retrieval trace artifact is set-once') END;
    SELECT CASE WHEN OLD.trace_digest IS NOT NULL AND NEW.trace_digest IS NOT OLD.trace_digest THEN RAISE(ABORT,'retrieval trace digest is set-once') END;
    SELECT CASE WHEN OLD.completed_at IS NOT NULL AND NEW.completed_at IS NOT OLD.completed_at THEN RAISE(ABORT,'retrieval completion evidence is set-once') END;
END;
CREATE TRIGGER retrieval_session_branch_terminal_immutable BEFORE UPDATE OF branch_status_json ON retrieval_sessions FOR EACH ROW
WHEN OLD.status<>'running' AND NEW.branch_status_json IS NOT OLD.branch_status_json
BEGIN SELECT RAISE(ABORT,'terminal retrieval branch status is immutable'); END;
CREATE TRIGGER retrieval_session_delete_forbidden BEFORE DELETE ON retrieval_sessions FOR EACH ROW BEGIN SELECT RAISE(ABORT,'retrieval sessions are retained'); END;

CREATE TRIGGER retrieval_candidate_scope_insert BEFORE INSERT ON retrieval_candidates FOR EACH ROW BEGIN
    SELECT CASE WHEN NOT EXISTS (SELECT 1 FROM retrieval_sessions s WHERE s.id=NEW.retrieval_session_id AND s.project_id=NEW.project_id) THEN RAISE(ABORT,'retrieval candidate session scope is incoherent') END;
    SELECT CASE WHEN NEW.artifact_id IS NOT NULL AND NOT EXISTS (SELECT 1 FROM artifacts a WHERE a.id=NEW.artifact_id AND a.project_id=NEW.project_id) THEN RAISE(ABORT,'retrieval artifact scope is incoherent') END;
    SELECT CASE WHEN NEW.source_document_id IS NOT NULL AND NOT EXISTS (SELECT 1 FROM source_documents d WHERE d.id=NEW.source_document_id AND d.project_id=NEW.project_id) THEN RAISE(ABORT,'retrieval document scope is incoherent') END;
    SELECT CASE WHEN NEW.source_chunk_id IS NOT NULL AND NOT EXISTS (SELECT 1 FROM source_chunks c JOIN source_documents d ON d.id=c.document_id WHERE c.id=NEW.source_chunk_id AND d.project_id=NEW.project_id) THEN RAISE(ABORT,'retrieval chunk scope is incoherent') END;
    SELECT CASE WHEN NEW.memory_id IS NOT NULL AND NOT EXISTS (
        SELECT 1 FROM memory_records m JOIN retrieval_sessions s ON s.id=NEW.retrieval_session_id
        WHERE m.id=NEW.memory_id AND m.project_id=NEW.project_id AND m.status='active' AND (m.expires_at IS NULL OR m.expires_at>s.started_at)
    ) THEN RAISE(ABORT,'retrieval memory must be active, unexpired, and in scope') END;
    SELECT CASE WHEN NEW.artifact_id IS NOT NULL AND NOT EXISTS (SELECT 1 FROM artifacts a WHERE a.id=NEW.artifact_id AND a.content_hash=NEW.source_hash) THEN RAISE(ABORT,'retrieval source hash does not match artifact') END;
    SELECT CASE WHEN NEW.source_document_id IS NOT NULL AND NOT EXISTS (SELECT 1 FROM source_documents d WHERE d.id=NEW.source_document_id AND d.content_hash=NEW.source_hash AND d.revision=NEW.source_revision) THEN RAISE(ABORT,'retrieval source revision/hash does not match document') END;
    SELECT CASE WHEN NEW.source_chunk_id IS NOT NULL AND NOT EXISTS (SELECT 1 FROM source_chunks c JOIN source_documents d ON d.id=c.document_id WHERE c.id=NEW.source_chunk_id AND c.content_hash=NEW.source_hash AND d.revision=NEW.source_revision) THEN RAISE(ABORT,'retrieval source revision/hash does not match chunk') END;
    SELECT CASE WHEN NEW.memory_id IS NOT NULL AND NOT EXISTS (SELECT 1 FROM memory_records m JOIN artifacts a ON a.id=m.content_artifact_id WHERE m.id=NEW.memory_id AND a.content_hash=NEW.source_hash AND ('memory:' || m.version)=NEW.source_revision) THEN RAISE(ABORT,'retrieval source revision/hash does not match memory') END;
    SELECT CASE WHEN NOT EXISTS (SELECT 1 FROM artifacts a WHERE a.id=NEW.reason_artifact_id AND a.project_id=NEW.project_id) THEN RAISE(ABORT,'retrieval reason scope is incoherent') END;
END;
CREATE TRIGGER retrieval_candidate_update_forbidden BEFORE UPDATE ON retrieval_candidates FOR EACH ROW BEGIN SELECT RAISE(ABORT,'retrieval candidates are immutable'); END;
CREATE TRIGGER retrieval_candidate_delete_forbidden BEFORE DELETE ON retrieval_candidates FOR EACH ROW BEGIN SELECT RAISE(ABORT,'retrieval candidates are retained'); END;

CREATE TRIGGER context_item_scope_insert BEFORE INSERT ON context_package_items FOR EACH ROW BEGIN
    SELECT CASE WHEN NOT EXISTS (SELECT 1 FROM context_packages cp JOIN tasks t ON t.id=cp.task_id WHERE cp.id=NEW.context_package_id AND cp.task_id=NEW.task_id AND t.project_id=NEW.project_id) THEN RAISE(ABORT,'context item package scope is incoherent') END;
    SELECT CASE WHEN NEW.retrieval_candidate_id IS NOT NULL AND NOT EXISTS (SELECT 1 FROM retrieval_candidates rc JOIN retrieval_sessions rs ON rs.id=rc.retrieval_session_id WHERE rc.id=NEW.retrieval_candidate_id AND rc.project_id=NEW.project_id AND rs.task_id=NEW.task_id) THEN RAISE(ABORT,'context item retrieval scope is incoherent') END;
    SELECT CASE WHEN NEW.source_artifact_id IS NOT NULL AND NOT EXISTS (SELECT 1 FROM artifacts a WHERE a.id=NEW.source_artifact_id AND a.project_id=NEW.project_id AND (a.task_id IS NULL OR a.task_id=NEW.task_id)) THEN RAISE(ABORT,'context item artifact source scope is incoherent') END;
    SELECT CASE WHEN NEW.source_document_id IS NOT NULL AND NOT EXISTS (SELECT 1 FROM source_documents d WHERE d.id=NEW.source_document_id AND d.project_id=NEW.project_id AND (d.task_id IS NULL OR d.task_id=NEW.task_id)) THEN RAISE(ABORT,'context item document source scope is incoherent') END;
    SELECT CASE WHEN NEW.source_chunk_id IS NOT NULL AND NOT EXISTS (SELECT 1 FROM source_chunks c JOIN source_documents d ON d.id=c.document_id WHERE c.id=NEW.source_chunk_id AND d.project_id=NEW.project_id AND (d.task_id IS NULL OR d.task_id=NEW.task_id)) THEN RAISE(ABORT,'context item chunk source scope is incoherent') END;
    SELECT CASE WHEN NEW.memory_id IS NOT NULL AND NOT EXISTS (
        SELECT 1 FROM memory_records m JOIN context_packages cp ON cp.id=NEW.context_package_id
        WHERE m.id=NEW.memory_id AND m.project_id=NEW.project_id AND m.status='active' AND (m.expires_at IS NULL OR m.expires_at>cp.created_at)
    ) THEN RAISE(ABORT,'context item memory must be active, unexpired, and in scope') END;
    SELECT CASE WHEN NEW.source_artifact_id IS NOT NULL AND NOT EXISTS (SELECT 1 FROM artifacts a WHERE a.id=NEW.source_artifact_id AND a.content_hash=NEW.source_hash) THEN RAISE(ABORT,'context item source hash does not match artifact') END;
    SELECT CASE WHEN NEW.source_document_id IS NOT NULL AND NOT EXISTS (SELECT 1 FROM source_documents d WHERE d.id=NEW.source_document_id AND d.content_hash=NEW.source_hash AND d.revision=NEW.source_revision) THEN RAISE(ABORT,'context item source revision/hash does not match document') END;
    SELECT CASE WHEN NEW.source_chunk_id IS NOT NULL AND NOT EXISTS (SELECT 1 FROM source_chunks c JOIN source_documents d ON d.id=c.document_id WHERE c.id=NEW.source_chunk_id AND c.content_hash=NEW.source_hash AND d.revision=NEW.source_revision) THEN RAISE(ABORT,'context item source revision/hash does not match chunk') END;
    SELECT CASE WHEN NEW.memory_id IS NOT NULL AND NOT EXISTS (SELECT 1 FROM memory_records m JOIN artifacts a ON a.id=m.content_artifact_id WHERE m.id=NEW.memory_id AND a.content_hash=NEW.source_hash AND ('memory:' || m.version)=NEW.source_revision) THEN RAISE(ABORT,'context item source revision/hash does not match memory') END;
    SELECT CASE WHEN NOT EXISTS (SELECT 1 FROM artifacts a WHERE a.id=NEW.inclusion_reason_artifact_id AND a.project_id=NEW.project_id AND (a.task_id IS NULL OR a.task_id=NEW.task_id)) THEN RAISE(ABORT,'context item reason scope is incoherent') END;
    SELECT CASE WHEN NEW.retrieval_candidate_id IS NOT NULL AND NOT EXISTS (
        SELECT 1 FROM retrieval_candidates rc
        WHERE rc.id=NEW.retrieval_candidate_id AND rc.source_hash=NEW.source_hash AND rc.source_revision=NEW.source_revision
          AND ((NEW.source_artifact_id IS NOT NULL AND rc.artifact_id=NEW.source_artifact_id)
            OR (NEW.source_document_id IS NOT NULL AND rc.source_document_id=NEW.source_document_id)
            OR (NEW.source_chunk_id IS NOT NULL AND rc.source_chunk_id=NEW.source_chunk_id)
            OR (NEW.memory_id IS NOT NULL AND rc.memory_id=NEW.memory_id))
    ) THEN RAISE(ABORT,'context item does not match retrieval candidate') END;
END;

CREATE TRIGGER context_item_update_forbidden BEFORE UPDATE ON context_package_items FOR EACH ROW BEGIN SELECT RAISE(ABORT,'context package items are immutable'); END;
CREATE TRIGGER context_item_delete_forbidden BEFORE DELETE ON context_package_items FOR EACH ROW BEGIN SELECT RAISE(ABORT,'context package items are retained'); END;

CREATE TRIGGER context_feedback_scope_insert BEFORE INSERT ON context_item_feedback FOR EACH ROW BEGIN
    SELECT CASE WHEN NOT EXISTS (
        SELECT 1 FROM context_package_items ci JOIN context_packages cp ON cp.id=ci.context_package_id JOIN agent_runs r ON r.id=NEW.run_id
        WHERE ci.id=NEW.context_package_item_id AND ci.project_id=NEW.project_id AND ci.task_id=NEW.task_id AND cp.task_id=NEW.task_id AND r.task_id=NEW.task_id AND r.context_package_id=ci.context_package_id
    ) THEN RAISE(ABORT,'context feedback scope is incoherent') END;
    SELECT CASE WHEN NEW.feedback_artifact_id IS NOT NULL AND NOT EXISTS (SELECT 1 FROM artifacts a WHERE a.id=NEW.feedback_artifact_id AND a.project_id=NEW.project_id AND (a.task_id IS NULL OR a.task_id=NEW.task_id)) THEN RAISE(ABORT,'context feedback artifact scope is incoherent') END;
END;
CREATE TRIGGER context_feedback_update_forbidden BEFORE UPDATE ON context_item_feedback FOR EACH ROW BEGIN SELECT RAISE(ABORT,'context feedback is immutable'); END;
CREATE TRIGGER context_feedback_delete_forbidden BEFORE DELETE ON context_item_feedback FOR EACH ROW BEGIN SELECT RAISE(ABORT,'context feedback is retained'); END;

CREATE TRIGGER run_reflection_scope_insert BEFORE INSERT ON run_reflections FOR EACH ROW BEGIN
    SELECT CASE WHEN NOT EXISTS (SELECT 1 FROM agent_runs r JOIN tasks t ON t.id=r.task_id WHERE r.id=NEW.run_id AND r.task_id=NEW.task_id AND t.project_id=NEW.project_id) THEN RAISE(ABORT,'reflection run scope is incoherent') END;
    SELECT CASE WHEN NOT EXISTS (SELECT 1 FROM artifacts a WHERE a.id=NEW.reflection_artifact_id AND a.project_id=NEW.project_id AND a.task_id=NEW.task_id) THEN RAISE(ABORT,'reflection artifact scope is incoherent') END;
    SELECT CASE WHEN NOT EXISTS (SELECT 1 FROM artifacts a WHERE a.id=NEW.reflection_artifact_id AND a.content_hash=NEW.reflection_digest) THEN RAISE(ABORT,'reflection digest does not match artifact') END;
    SELECT CASE WHEN NOT EXISTS (SELECT 1 FROM agent_runs r WHERE r.id=NEW.run_id AND r.status IN ('succeeded','failed','cancelled','interrupted','indeterminate')) THEN RAISE(ABORT,'reflection requires terminal run') END;
END;
CREATE TRIGGER run_reflection_update_forbidden BEFORE UPDATE ON run_reflections FOR EACH ROW BEGIN SELECT RAISE(ABORT,'run reflections are immutable'); END;
CREATE TRIGGER run_reflection_delete_forbidden BEFORE DELETE ON run_reflections FOR EACH ROW BEGIN SELECT RAISE(ABORT,'run reflections are retained'); END;

CREATE TRIGGER run_evaluation_scope_insert BEFORE INSERT ON run_evaluations FOR EACH ROW BEGIN
    SELECT CASE WHEN NOT EXISTS (SELECT 1 FROM agent_runs r JOIN tasks t ON t.id=r.task_id WHERE r.id=NEW.run_id AND r.task_id=NEW.task_id AND t.project_id=NEW.project_id) THEN RAISE(ABORT,'evaluation run scope is incoherent') END;
    SELECT CASE WHEN NOT EXISTS (SELECT 1 FROM artifacts a WHERE a.id=NEW.evaluation_artifact_id AND a.project_id=NEW.project_id AND a.task_id=NEW.task_id) THEN RAISE(ABORT,'evaluation artifact scope is incoherent') END;
    SELECT CASE WHEN NOT EXISTS (SELECT 1 FROM agent_runs r WHERE r.id=NEW.run_id AND r.status IN ('succeeded','failed','cancelled','interrupted','indeterminate')) THEN RAISE(ABORT,'evaluation requires terminal run') END;
END;
CREATE TRIGGER run_evaluation_update_forbidden BEFORE UPDATE ON run_evaluations FOR EACH ROW BEGIN SELECT RAISE(ABORT,'run evaluations are immutable'); END;
CREATE TRIGGER run_evaluation_delete_forbidden BEFORE DELETE ON run_evaluations FOR EACH ROW BEGIN SELECT RAISE(ABORT,'run evaluations are retained'); END;

CREATE TRIGGER benchmark_suite_scope_insert BEFORE INSERT ON benchmark_suites FOR EACH ROW BEGIN
    SELECT CASE WHEN NOT EXISTS (SELECT 1 FROM artifacts a WHERE a.id=NEW.manifest_artifact_id AND a.project_id=NEW.project_id) THEN RAISE(ABORT,'benchmark suite manifest scope is incoherent') END;
    SELECT CASE WHEN NOT EXISTS (SELECT 1 FROM artifacts a WHERE a.id=NEW.manifest_artifact_id AND a.content_hash=NEW.manifest_digest) THEN RAISE(ABORT,'benchmark suite manifest digest does not match artifact') END;
END;
CREATE TRIGGER benchmark_suite_update_forbidden BEFORE UPDATE ON benchmark_suites FOR EACH ROW BEGIN SELECT RAISE(ABORT,'benchmark suites are immutable'); END;
CREATE TRIGGER benchmark_suite_delete_forbidden BEFORE DELETE ON benchmark_suites FOR EACH ROW BEGIN SELECT RAISE(ABORT,'benchmark suites are retained'); END;

CREATE TRIGGER benchmark_case_scope_insert BEFORE INSERT ON benchmark_cases FOR EACH ROW BEGIN
    SELECT CASE WHEN NOT EXISTS (SELECT 1 FROM benchmark_suites s JOIN artifacts a ON a.id=NEW.case_artifact_id WHERE s.id=NEW.suite_id AND a.project_id=s.project_id) THEN RAISE(ABORT,'benchmark case artifact scope is incoherent') END;
END;
CREATE TRIGGER benchmark_case_update_forbidden BEFORE UPDATE ON benchmark_cases FOR EACH ROW BEGIN SELECT RAISE(ABORT,'benchmark cases are immutable'); END;
CREATE TRIGGER benchmark_case_delete_forbidden BEFORE DELETE ON benchmark_cases FOR EACH ROW BEGIN SELECT RAISE(ABORT,'benchmark cases are retained'); END;

CREATE TRIGGER benchmark_run_scope_insert BEFORE INSERT ON benchmark_runs FOR EACH ROW BEGIN
    SELECT CASE WHEN NOT EXISTS (SELECT 1 FROM benchmark_cases c JOIN benchmark_suites s ON s.id=c.suite_id JOIN tasks t ON t.id=NEW.task_id WHERE c.id=NEW.benchmark_case_id AND t.project_id=s.project_id) THEN RAISE(ABORT,'benchmark run task scope is incoherent') END;
    SELECT CASE WHEN NEW.result_artifact_id IS NOT NULL AND NOT EXISTS (SELECT 1 FROM artifacts a JOIN tasks t ON t.id=NEW.task_id WHERE a.id=NEW.result_artifact_id AND a.project_id=t.project_id AND (a.task_id IS NULL OR a.task_id=NEW.task_id)) THEN RAISE(ABORT,'benchmark run result scope is incoherent') END;
END;
CREATE TRIGGER benchmark_run_identity_immutable BEFORE UPDATE OF id,benchmark_case_id,task_id,system_configuration_digest,evaluator_configuration_digest ON benchmark_runs FOR EACH ROW BEGIN SELECT RAISE(ABORT,'benchmark run identity is immutable'); END;
CREATE TRIGGER benchmark_run_status_transition BEFORE UPDATE OF status,started_at,completed_at,result_artifact_id ON benchmark_runs FOR EACH ROW BEGIN
    SELECT CASE WHEN NOT (
        (OLD.status='planned' AND NEW.status IN ('running','failed','indeterminate')) OR
        (OLD.status='running' AND NEW.status IN ('completed','failed','indeterminate')) OR
        OLD.status=NEW.status
    ) THEN RAISE(ABORT,'invalid benchmark run lifecycle transition') END;
    SELECT CASE WHEN NEW.status='running' AND NEW.started_at IS NULL THEN RAISE(ABORT,'running benchmark requires start time') END;
    SELECT CASE WHEN NEW.status IN ('completed','failed','indeterminate') AND NEW.completed_at IS NULL THEN RAISE(ABORT,'terminal benchmark requires completion time') END;
    SELECT CASE WHEN NEW.result_artifact_id IS NOT NULL AND NOT EXISTS (
        SELECT 1 FROM artifacts a JOIN tasks t ON t.id=NEW.task_id
        WHERE a.id=NEW.result_artifact_id AND a.project_id=t.project_id AND (a.task_id IS NULL OR a.task_id=NEW.task_id)
    ) THEN RAISE(ABORT,'benchmark run result scope is incoherent') END;
    SELECT CASE WHEN OLD.result_artifact_id IS NOT NULL AND NEW.result_artifact_id IS NOT OLD.result_artifact_id THEN RAISE(ABORT,'benchmark result evidence is set-once') END;
    SELECT CASE WHEN OLD.completed_at IS NOT NULL AND NEW.completed_at IS NOT OLD.completed_at THEN RAISE(ABORT,'benchmark completion evidence is set-once') END;
END;
CREATE TRIGGER benchmark_run_delete_forbidden BEFORE DELETE ON benchmark_runs FOR EACH ROW BEGIN SELECT RAISE(ABORT,'benchmark runs are retained'); END;

CREATE TRIGGER benchmark_comparison_scope_insert BEFORE INSERT ON benchmark_comparisons FOR EACH ROW BEGIN
    SELECT CASE WHEN NOT EXISTS (
        SELECT 1 FROM benchmark_runs b JOIN benchmark_runs c ON c.id=NEW.candidate_run_id JOIN tasks bt ON bt.id=b.task_id JOIN tasks ct ON ct.id=c.task_id JOIN artifacts a ON a.id=NEW.comparison_artifact_id
        WHERE b.id=NEW.baseline_run_id AND b.benchmark_case_id=c.benchmark_case_id
          AND b.status='completed' AND c.status='completed'
          AND b.system_configuration_digest=c.system_configuration_digest
          AND b.evaluator_configuration_digest=c.evaluator_configuration_digest
          AND bt.project_id=ct.project_id AND a.project_id=bt.project_id
    ) THEN RAISE(ABORT,'benchmark comparison inputs are not comparable') END;
END;
CREATE TRIGGER benchmark_comparison_update_forbidden BEFORE UPDATE ON benchmark_comparisons FOR EACH ROW BEGIN SELECT RAISE(ABORT,'benchmark comparisons are immutable'); END;
CREATE TRIGGER benchmark_comparison_delete_forbidden BEFORE DELETE ON benchmark_comparisons FOR EACH ROW BEGIN SELECT RAISE(ABORT,'benchmark comparisons are retained'); END;

CREATE UNIQUE INDEX idx_agent_runs_context_package_once ON agent_runs(context_package_id);
CREATE UNIQUE INDEX idx_memory_records_one_active_version ON memory_records(project_id,logical_key) WHERE status='active';
CREATE UNIQUE INDEX idx_index_generation_one_current ON index_generations(project_id,engine_id) WHERE status='current';
CREATE INDEX idx_context_feedback_run ON context_item_feedback(run_id,label);
CREATE INDEX idx_benchmark_runs_case ON benchmark_runs(benchmark_case_id,status);
CREATE INDEX idx_memory_records_active ON memory_records(project_id,memory_type,status,expires_at);
CREATE INDEX idx_memory_evidence_memory ON memory_evidence_links(memory_id,relationship);
CREATE INDEX idx_memory_relations_from ON memory_relations(from_memory_id,relation_kind);
CREATE INDEX idx_working_memory_run ON working_memory_snapshots(run_id,sequence);
CREATE INDEX idx_episodes_project_outcome ON episodes(project_id,outcome,created_at);
CREATE INDEX idx_retrieval_sessions_task ON retrieval_sessions(task_id,status,started_at);
CREATE INDEX idx_retrieval_candidates_session ON retrieval_candidates(retrieval_session_id,rank_position);
CREATE INDEX idx_context_items_package ON context_package_items(context_package_id,category);
CREATE INDEX idx_run_evaluations_task ON run_evaluations(task_id,gate_decision,created_at);

COMMIT;

-- After this transaction succeeds, the migration runner records version 3
-- with the actual file checksum, application version, and authoritative time.
