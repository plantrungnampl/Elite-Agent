-- Local-First Multi-Agent Engineering Terminal
-- Authoritative v4.2 clean-install schema v6.
-- Includes the retained v4.1.1 authority baseline plus corrected end-to-end workflow, actor proof, canonical memory wire bindings, and controlled benchmark receipts.
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
    'succeeded', 'failed', 'cancelled_cleanly', 'terminated', 'interrupted', 'indeterminate'
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
    SELECT CASE WHEN NOT EXISTS (SELECT 1 FROM agent_runs r WHERE r.id=NEW.run_id AND r.status IN ('succeeded','failed','cancelled_cleanly','terminated','interrupted','indeterminate')) THEN RAISE(ABORT,'episode requires terminal run') END;
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
    SELECT CASE WHEN NOT EXISTS (SELECT 1 FROM agent_runs r WHERE r.id=NEW.run_id AND r.status IN ('succeeded','failed','cancelled_cleanly','terminated','interrupted','indeterminate')) THEN RAISE(ABORT,'reflection requires terminal run') END;
END;
CREATE TRIGGER run_reflection_update_forbidden BEFORE UPDATE ON run_reflections FOR EACH ROW BEGIN SELECT RAISE(ABORT,'run reflections are immutable'); END;
CREATE TRIGGER run_reflection_delete_forbidden BEFORE DELETE ON run_reflections FOR EACH ROW BEGIN SELECT RAISE(ABORT,'run reflections are retained'); END;

CREATE TRIGGER run_evaluation_scope_insert BEFORE INSERT ON run_evaluations FOR EACH ROW BEGIN
    SELECT CASE WHEN NOT EXISTS (SELECT 1 FROM agent_runs r JOIN tasks t ON t.id=r.task_id WHERE r.id=NEW.run_id AND r.task_id=NEW.task_id AND t.project_id=NEW.project_id) THEN RAISE(ABORT,'evaluation run scope is incoherent') END;
    SELECT CASE WHEN NOT EXISTS (SELECT 1 FROM artifacts a WHERE a.id=NEW.evaluation_artifact_id AND a.project_id=NEW.project_id AND a.task_id=NEW.task_id) THEN RAISE(ABORT,'evaluation artifact scope is incoherent') END;
    SELECT CASE WHEN NOT EXISTS (SELECT 1 FROM agent_runs r WHERE r.id=NEW.run_id AND r.status IN ('succeeded','failed','cancelled_cleanly','terminated','interrupted','indeterminate')) THEN RAISE(ABORT,'evaluation requires terminal run') END;
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

-- v4.1 context and memory utility hardening extension.

CREATE TABLE state_records (
    id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE RESTRICT,
    task_id TEXT REFERENCES tasks(id) ON DELETE RESTRICT,
    state_key TEXT NOT NULL,
    scope_kind TEXT NOT NULL CHECK (scope_kind IN ('task','project','user','workspace','communication-surface')),
    scope_id TEXT NOT NULL,
    authority_kind TEXT NOT NULL CHECK (authority_kind IN ('current_instruction','task_override','approved_decision','project_setting','explicit_user_preference','inferred_preference')),
    precedence_rank INTEGER NOT NULL CHECK (precedence_rank IN (600,500,400,300,200,100)),
    value_json TEXT NOT NULL CHECK (json_valid(value_json)),
    source_artifact_id TEXT NOT NULL REFERENCES artifacts(id) ON DELETE RESTRICT,
    source_digest TEXT NOT NULL CHECK (length(source_digest)=71 AND substr(source_digest,1,7)='sha256:' AND substr(source_digest,8) NOT GLOB '*[^0-9a-f]*'),
    status TEXT NOT NULL CHECK (status IN ('active','superseded','retracted','expired')),
    valid_from TEXT NOT NULL,
    valid_until TEXT,
    supersedes_state_id TEXT REFERENCES state_records(id) ON DELETE RESTRICT,
    created_at TEXT NOT NULL,
    status_changed_at TEXT NOT NULL,
    retracted_at TEXT,
    CHECK (valid_until IS NULL OR valid_until > valid_from),
    CHECK (status_changed_at >= created_at),
    CHECK (status <> 'retracted' OR retracted_at IS NOT NULL),
    CHECK (status = 'retracted' OR retracted_at IS NULL)
) STRICT;

CREATE TABLE state_evidence_links (
    id TEXT PRIMARY KEY,
    state_id TEXT NOT NULL REFERENCES state_records(id) ON DELETE RESTRICT,
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE RESTRICT,
    evidence_kind TEXT NOT NULL CHECK (evidence_kind IN ('artifact','event','tool_receipt','decision','user_instruction','policy')),
    artifact_id TEXT NOT NULL REFERENCES artifacts(id) ON DELETE RESTRICT,
    evidence_digest TEXT NOT NULL CHECK (length(evidence_digest)=71 AND substr(evidence_digest,1,7)='sha256:' AND substr(evidence_digest,8) NOT GLOB '*[^0-9a-f]*'),
    relationship TEXT NOT NULL CHECK (relationship IN ('supports','defines','supersedes','retracts')),
    created_at TEXT NOT NULL
) STRICT;

CREATE TABLE state_resolution_receipts (
    id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE RESTRICT,
    task_id TEXT REFERENCES tasks(id) ON DELETE RESTRICT,
    state_key TEXT NOT NULL,
    winning_state_id TEXT NOT NULL REFERENCES state_records(id) ON DELETE RESTRICT,
    candidate_state_ids_json TEXT NOT NULL CHECK (json_valid(candidate_state_ids_json) AND json_type(candidate_state_ids_json)='array' AND json_array_length(candidate_state_ids_json)>=1),
    resolution_rule_version TEXT NOT NULL,
    result_artifact_id TEXT NOT NULL REFERENCES artifacts(id) ON DELETE RESTRICT,
    result_digest TEXT NOT NULL CHECK (length(result_digest)=71 AND substr(result_digest,1,7)='sha256:' AND substr(result_digest,8) NOT GLOB '*[^0-9a-f]*'),
    created_at TEXT NOT NULL,
    policy_snapshot_digest TEXT NOT NULL CHECK (length(policy_snapshot_digest)=71 AND substr(policy_snapshot_digest,1,7)='sha256:' AND substr(policy_snapshot_digest,8) NOT GLOB '*[^0-9a-f]*')
) STRICT;

CREATE TABLE memory_invalidation_evaluations (
    id TEXT PRIMARY KEY,
    memory_id TEXT NOT NULL REFERENCES memory_records(id) ON DELETE RESTRICT,
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE RESTRICT,
    task_id TEXT REFERENCES tasks(id) ON DELETE RESTRICT,
    rule_id TEXT NOT NULL,
    result TEXT NOT NULL CHECK (result IN ('passed','failed','indeterminate')),
    evidence_artifact_id TEXT NOT NULL REFERENCES artifacts(id) ON DELETE RESTRICT,
    evidence_digest TEXT NOT NULL CHECK (length(evidence_digest)=71 AND substr(evidence_digest,1,7)='sha256:' AND substr(evidence_digest,8) NOT GLOB '*[^0-9a-f]*'),
    evaluated_at TEXT NOT NULL,
    valid_until TEXT,
    CHECK (valid_until IS NULL OR valid_until > evaluated_at),
    UNIQUE(memory_id,rule_id,evaluated_at)
) STRICT;

CREATE TABLE memory_shadow_evaluations (
    id TEXT PRIMARY KEY,
    memory_id TEXT NOT NULL REFERENCES memory_records(id) ON DELETE RESTRICT,
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE RESTRICT,
    task_id TEXT NOT NULL REFERENCES tasks(id) ON DELETE RESTRICT,
    control_arm TEXT NOT NULL CHECK (control_arm='control_no_memory'),
    candidate_arm TEXT NOT NULL CHECK (candidate_arm='evidence_plus_experience'),
    control_run_id TEXT NOT NULL REFERENCES benchmark_runs(id) ON DELETE RESTRICT,
    candidate_run_id TEXT NOT NULL REFERENCES benchmark_runs(id) ON DELETE RESTRICT,
    result TEXT NOT NULL CHECK (result IN ('passed','failed','indeterminate')),
    quality_delta_millionths INTEGER NOT NULL CHECK (quality_delta_millionths BETWEEN -1000000 AND 1000000),
    new_forbidden_mistakes INTEGER NOT NULL CHECK (new_forbidden_mistakes>=0),
    new_unsupported_claims INTEGER NOT NULL CHECK (new_unsupported_claims>=0),
    evidence_artifact_id TEXT NOT NULL REFERENCES artifacts(id) ON DELETE RESTRICT,
    evidence_digest TEXT NOT NULL CHECK (length(evidence_digest)=71 AND substr(evidence_digest,1,7)='sha256:' AND substr(evidence_digest,8) NOT GLOB '*[^0-9a-f]*'),
    evaluated_at TEXT NOT NULL,
    UNIQUE(memory_id,control_run_id,candidate_run_id)
) STRICT;

CREATE TABLE memory_usage_events (
    id TEXT PRIMARY KEY,
    memory_id TEXT NOT NULL REFERENCES memory_records(id) ON DELETE RESTRICT,
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE RESTRICT,
    task_id TEXT NOT NULL REFERENCES tasks(id) ON DELETE RESTRICT,
    run_id TEXT NOT NULL REFERENCES agent_runs(id) ON DELETE RESTRICT,
    event_type TEXT NOT NULL CHECK (event_type IN ('retrieved','included','cited','used_in_conclusion','helpful','misleading','redundant')),
    retrieved INTEGER NOT NULL CHECK (retrieved IN (0,1)),
    included INTEGER NOT NULL CHECK (included IN (0,1)),
    cited INTEGER NOT NULL CHECK (cited IN (0,1)),
    used_in_conclusion INTEGER NOT NULL CHECK (used_in_conclusion IN (0,1)),
    helpfulness_millionths INTEGER CHECK (helpfulness_millionths BETWEEN -1000000 AND 1000000),
    token_cost INTEGER NOT NULL CHECK (token_cost>=0),
    evidence_artifact_id TEXT NOT NULL REFERENCES artifacts(id) ON DELETE RESTRICT,
    evidence_digest TEXT NOT NULL CHECK (length(evidence_digest)=71 AND substr(evidence_digest,1,7)='sha256:' AND substr(evidence_digest,8) NOT GLOB '*[^0-9a-f]*'),
    created_at TEXT NOT NULL
) STRICT;

CREATE TABLE memory_utility_snapshots (
    id TEXT PRIMARY KEY,
    memory_id TEXT NOT NULL REFERENCES memory_records(id) ON DELETE RESTRICT,
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE RESTRICT,
    generation INTEGER NOT NULL CHECK (generation>=1),
    retrieved_count INTEGER NOT NULL CHECK (retrieved_count>=0),
    helpful_count INTEGER NOT NULL CHECK (helpful_count>=0),
    harmful_count INTEGER NOT NULL CHECK (harmful_count>=0),
    conclusion_use_count INTEGER NOT NULL CHECK (conclusion_use_count>=0),
    token_cost INTEGER NOT NULL CHECK (token_cost>=0),
    redundancy_count INTEGER NOT NULL CHECK (redundancy_count>=0),
    utility_millionths INTEGER NOT NULL CHECK (utility_millionths BETWEEN -1000000 AND 1000000),
    evidence_artifact_id TEXT NOT NULL REFERENCES artifacts(id) ON DELETE RESTRICT,
    evidence_digest TEXT NOT NULL CHECK (length(evidence_digest)=71 AND substr(evidence_digest,1,7)='sha256:' AND substr(evidence_digest,8) NOT GLOB '*[^0-9a-f]*'),
    created_at TEXT NOT NULL,
    UNIQUE(memory_id,generation)
) STRICT;

CREATE TABLE memory_consolidation_actions (
    id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE RESTRICT,
    action_kind TEXT NOT NULL CHECK (action_kind IN ('merge','split','retain','supersede','mark_stale','retract')),
    input_memory_ids_json TEXT NOT NULL CHECK (json_valid(input_memory_ids_json) AND json_type(input_memory_ids_json)='array' AND json_array_length(input_memory_ids_json)>=1),
    result_memory_id TEXT REFERENCES memory_records(id) ON DELETE RESTRICT,
    status TEXT NOT NULL CHECK (status IN ('proposed','approved','rejected','applied')),
    evidence_artifact_id TEXT NOT NULL REFERENCES artifacts(id) ON DELETE RESTRICT,
    evidence_digest TEXT NOT NULL CHECK (length(evidence_digest)=71 AND substr(evidence_digest,1,7)='sha256:' AND substr(evidence_digest,8) NOT GLOB '*[^0-9a-f]*'),
    reviewer_kind TEXT NOT NULL CHECK (reviewer_kind IN ('user','deterministic','policy')),
    created_at TEXT NOT NULL,
    applied_at TEXT,
    CHECK (status='applied' OR applied_at IS NULL),
    CHECK (status<>'applied' OR applied_at IS NOT NULL)
) STRICT;

CREATE TABLE context_budget_decisions (
    id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE RESTRICT,
    task_id TEXT NOT NULL REFERENCES tasks(id) ON DELETE RESTRICT,
    run_id TEXT NOT NULL REFERENCES agent_runs(id) ON DELETE RESTRICT,
    context_package_id TEXT NOT NULL REFERENCES context_packages(id) ON DELETE RESTRICT,
    task_class TEXT NOT NULL,
    risk_level TEXT NOT NULL CHECK (risk_level IN ('low','medium','high','critical')),
    allocations_json TEXT NOT NULL CHECK (json_valid(allocations_json) AND json_type(allocations_json)='object'),
    total_allocated_tokens INTEGER NOT NULL CHECK (total_allocated_tokens>=1),
    strategy_version TEXT NOT NULL,
    coverage_millionths INTEGER CHECK (coverage_millionths BETWEEN 0 AND 1000000),
    marginal_utility_threshold_millionths INTEGER CHECK (marginal_utility_threshold_millionths BETWEEN 0 AND 1000000),
    stopping_reason TEXT NOT NULL CHECK (stopping_reason IN ('sufficient_coverage','budget_exhausted','marginal_utility_below_threshold','policy_limit','no_more_candidates')),
    evidence_artifact_id TEXT NOT NULL REFERENCES artifacts(id) ON DELETE RESTRICT,
    evidence_digest TEXT NOT NULL CHECK (length(evidence_digest)=71 AND substr(evidence_digest,1,7)='sha256:' AND substr(evidence_digest,8) NOT GLOB '*[^0-9a-f]*'),
    policy_snapshot_digest TEXT NOT NULL CHECK (length(policy_snapshot_digest)=71 AND substr(policy_snapshot_digest,1,7)='sha256:' AND substr(policy_snapshot_digest,8) NOT GLOB '*[^0-9a-f]*'),
    created_at TEXT NOT NULL
) STRICT;

CREATE TRIGGER memory_records_v41_typed_invalidation_insert
BEFORE INSERT ON memory_records
FOR EACH ROW
BEGIN
    SELECT CASE WHEN json_type(NEW.invalidation_conditions_json)<>'array' OR json_array_length(NEW.invalidation_conditions_json)<1
        OR EXISTS (
            SELECT 1 FROM json_each(NEW.invalidation_conditions_json) r
            WHERE r.type<>'object'
               OR json_type(r.value,'$.ruleId')<>'text'
               OR json_type(r.value,'$.kind')<>'text'
               OR json_type(r.value,'$.target')<>'object'
               OR json_type(r.value,'$.expected')<>'object'
               OR json_type(r.value,'$.cadence')<>'text'
               OR json_type(r.value,'$.explanation')<>'text'
        )
    THEN RAISE(ABORT,'memory invalidation rules must be typed and executable') END;
END;

CREATE TRIGGER state_records_precedence_insert
BEFORE INSERT ON state_records
FOR EACH ROW
BEGIN
    SELECT CASE WHEN NOT (
        (NEW.authority_kind='current_instruction' AND NEW.precedence_rank=600) OR
        (NEW.authority_kind='task_override' AND NEW.precedence_rank=500) OR
        (NEW.authority_kind='approved_decision' AND NEW.precedence_rank=400) OR
        (NEW.authority_kind='project_setting' AND NEW.precedence_rank=300) OR
        (NEW.authority_kind='explicit_user_preference' AND NEW.precedence_rank=200) OR
        (NEW.authority_kind='inferred_preference' AND NEW.precedence_rank=100)
    ) THEN RAISE(ABORT,'state precedence rank does not match authority kind') END;
END;

CREATE TRIGGER state_records_scope_insert
BEFORE INSERT ON state_records
FOR EACH ROW
BEGIN
    SELECT CASE WHEN NEW.task_id IS NOT NULL AND NOT EXISTS (SELECT 1 FROM tasks t WHERE t.id=NEW.task_id AND t.project_id=NEW.project_id)
        THEN RAISE(ABORT,'state task scope is incoherent') END;
    SELECT CASE WHEN NEW.scope_kind='task' AND (NEW.task_id IS NULL OR NEW.scope_id<>NEW.task_id)
        THEN RAISE(ABORT,'state task scope is incoherent') END;
    SELECT CASE WHEN NEW.scope_kind='project' AND NEW.scope_id<>NEW.project_id
        THEN RAISE(ABORT,'state project scope is incoherent') END;
    SELECT CASE WHEN NOT EXISTS (
        SELECT 1 FROM artifacts a WHERE a.id=NEW.source_artifact_id AND a.project_id=NEW.project_id
          AND (NEW.task_id IS NULL OR a.task_id IS NULL OR a.task_id=NEW.task_id)
    ) THEN RAISE(ABORT,'state source scope is incoherent') END;
    SELECT CASE WHEN NOT EXISTS (SELECT 1 FROM artifacts a WHERE a.id=NEW.source_artifact_id AND a.content_hash=NEW.source_digest)
        THEN RAISE(ABORT,'state source digest does not match artifact') END;
    SELECT CASE WHEN NEW.supersedes_state_id IS NOT NULL AND NOT EXISTS (
        SELECT 1 FROM state_records s WHERE s.id=NEW.supersedes_state_id AND s.project_id=NEW.project_id AND s.state_key=NEW.state_key
    ) THEN RAISE(ABORT,'state supersession scope is incoherent') END;
END;

CREATE TRIGGER state_records_identity_immutable
BEFORE UPDATE OF id,project_id,task_id,state_key,scope_kind,scope_id,authority_kind,precedence_rank,value_json,source_artifact_id,source_digest,valid_from,supersedes_state_id,created_at ON state_records
FOR EACH ROW BEGIN SELECT RAISE(ABORT,'state identity and value are immutable'); END;

CREATE TRIGGER state_records_status_transition
BEFORE UPDATE OF status,status_changed_at,retracted_at,valid_until ON state_records
FOR EACH ROW
BEGIN
    SELECT CASE WHEN NOT (
        (OLD.status='active' AND NEW.status IN ('active','superseded','retracted','expired')) OR OLD.status=NEW.status
    ) THEN RAISE(ABORT,'invalid state lifecycle transition') END;
    SELECT CASE WHEN NEW.status_changed_at<OLD.status_changed_at THEN RAISE(ABORT,'state lifecycle time cannot decrease') END;
END;
CREATE TRIGGER state_records_delete_forbidden BEFORE DELETE ON state_records FOR EACH ROW BEGIN SELECT RAISE(ABORT,'state records are retained'); END;

CREATE TRIGGER state_evidence_scope_insert BEFORE INSERT ON state_evidence_links FOR EACH ROW BEGIN
    SELECT CASE WHEN NOT EXISTS (SELECT 1 FROM state_records s JOIN artifacts a ON a.id=NEW.artifact_id WHERE s.id=NEW.state_id AND s.project_id=NEW.project_id AND a.project_id=NEW.project_id AND a.content_hash=NEW.evidence_digest) THEN RAISE(ABORT,'state evidence scope or digest is incoherent') END;
END;
CREATE TRIGGER state_evidence_update_forbidden BEFORE UPDATE ON state_evidence_links FOR EACH ROW BEGIN SELECT RAISE(ABORT,'state evidence is immutable'); END;
CREATE TRIGGER state_evidence_delete_forbidden BEFORE DELETE ON state_evidence_links FOR EACH ROW BEGIN SELECT RAISE(ABORT,'state evidence is retained'); END;

CREATE TRIGGER state_resolution_scope_insert BEFORE INSERT ON state_resolution_receipts FOR EACH ROW BEGIN
    SELECT CASE WHEN NEW.task_id IS NOT NULL AND NOT EXISTS (SELECT 1 FROM tasks t WHERE t.id=NEW.task_id AND t.project_id=NEW.project_id) THEN RAISE(ABORT,'state resolution task scope is incoherent') END;
    SELECT CASE WHEN NOT EXISTS (SELECT 1 FROM artifacts a WHERE a.id=NEW.result_artifact_id AND a.project_id=NEW.project_id AND (NEW.task_id IS NULL OR a.task_id IS NULL OR a.task_id=NEW.task_id) AND a.content_hash=NEW.result_digest) THEN RAISE(ABORT,'state resolution evidence scope or digest is incoherent') END;
    SELECT CASE WHEN EXISTS (
        SELECT 1 FROM json_each(NEW.candidate_state_ids_json) j
        LEFT JOIN state_records s ON s.id=j.value
        WHERE j.type<>'text' OR s.id IS NULL OR s.project_id<>NEW.project_id OR s.state_key<>NEW.state_key OR s.status<>'active'
          OR (NEW.task_id IS NOT NULL AND s.task_id IS NOT NULL AND s.task_id<>NEW.task_id)
    ) THEN RAISE(ABORT,'state resolution candidates are incoherent') END;
    SELECT CASE WHEN NOT EXISTS (SELECT 1 FROM json_each(NEW.candidate_state_ids_json) j WHERE j.value=NEW.winning_state_id) THEN RAISE(ABORT,'state resolution winner is not a candidate') END;
    SELECT CASE WHEN EXISTS (
        SELECT 1 FROM state_records w, json_each(NEW.candidate_state_ids_json) j JOIN state_records c ON c.id=j.value
        WHERE w.id=NEW.winning_state_id AND c.precedence_rank>w.precedence_rank
    ) THEN RAISE(ABORT,'state resolution winner is not highest precedence') END;
END;
CREATE TRIGGER state_resolution_update_forbidden BEFORE UPDATE ON state_resolution_receipts FOR EACH ROW BEGIN SELECT RAISE(ABORT,'state resolution receipts are immutable'); END;
CREATE TRIGGER state_resolution_delete_forbidden BEFORE DELETE ON state_resolution_receipts FOR EACH ROW BEGIN SELECT RAISE(ABORT,'state resolution receipts are retained'); END;

CREATE TRIGGER invalidation_evaluation_scope_insert BEFORE INSERT ON memory_invalidation_evaluations FOR EACH ROW BEGIN
    SELECT CASE WHEN NOT EXISTS (SELECT 1 FROM memory_records m WHERE m.id=NEW.memory_id AND m.project_id=NEW.project_id AND (NEW.task_id IS NULL OR m.origin_task_id IS NULL OR m.origin_task_id=NEW.task_id)) THEN RAISE(ABORT,'invalidation evaluation scope is incoherent') END;
    SELECT CASE WHEN NOT EXISTS (SELECT 1 FROM memory_records m, json_each(m.invalidation_conditions_json) r WHERE m.id=NEW.memory_id AND json_extract(r.value,'$.ruleId')=NEW.rule_id) THEN RAISE(ABORT,'invalidation rule is not declared by memory') END;
    SELECT CASE WHEN NOT EXISTS (SELECT 1 FROM artifacts a WHERE a.id=NEW.evidence_artifact_id AND a.project_id=NEW.project_id AND (NEW.task_id IS NULL OR a.task_id IS NULL OR a.task_id=NEW.task_id) AND a.content_hash=NEW.evidence_digest) THEN RAISE(ABORT,'invalidation evaluation evidence scope or digest is incoherent') END;
END;
CREATE TRIGGER invalidation_evaluation_update_forbidden BEFORE UPDATE ON memory_invalidation_evaluations FOR EACH ROW BEGIN SELECT RAISE(ABORT,'invalidation evaluations are immutable'); END;
CREATE TRIGGER invalidation_evaluation_delete_forbidden BEFORE DELETE ON memory_invalidation_evaluations FOR EACH ROW BEGIN SELECT RAISE(ABORT,'invalidation evaluations are retained'); END;

CREATE TRIGGER retrieval_candidate_v41_memory_eligibility BEFORE INSERT ON retrieval_candidates FOR EACH ROW WHEN NEW.memory_id IS NOT NULL BEGIN
    SELECT CASE WHEN EXISTS (SELECT 1 FROM memory_records m, json_each(m.invalidation_conditions_json) r WHERE m.id=NEW.memory_id AND r.type<>'object') THEN RAISE(ABORT,'legacy memory requires typed invalidation revalidation') END;
    SELECT CASE WHEN EXISTS (
        SELECT 1 FROM memory_records m, json_each(m.invalidation_conditions_json) r
        WHERE m.id=NEW.memory_id AND NOT EXISTS (
            SELECT 1 FROM memory_invalidation_evaluations e JOIN retrieval_sessions rs ON rs.id=NEW.retrieval_session_id
            WHERE e.memory_id=m.id AND e.rule_id=json_extract(r.value,'$.ruleId') AND e.result='passed'
              AND e.evaluated_at=(SELECT MAX(e2.evaluated_at) FROM memory_invalidation_evaluations e2 WHERE e2.memory_id=m.id AND e2.rule_id=e.rule_id)
              AND (e.valid_until IS NULL OR e.valid_until>rs.started_at)
        )
    ) THEN RAISE(ABORT,'retrieval memory lacks current passing invalidation evidence') END;
END;

CREATE TRIGGER shadow_evaluation_scope_insert BEFORE INSERT ON memory_shadow_evaluations FOR EACH ROW BEGIN
    SELECT CASE WHEN NOT EXISTS (SELECT 1 FROM memory_records m JOIN tasks t ON t.id=NEW.task_id WHERE m.id=NEW.memory_id AND m.project_id=NEW.project_id AND t.project_id=NEW.project_id) THEN RAISE(ABORT,'shadow evaluation scope is incoherent') END;
    SELECT CASE WHEN NOT EXISTS (
        SELECT 1 FROM benchmark_runs b JOIN benchmark_runs c ON c.id=NEW.candidate_run_id
        WHERE b.id=NEW.control_run_id AND b.benchmark_case_id=c.benchmark_case_id AND b.task_id=NEW.task_id AND c.task_id=NEW.task_id AND b.status='completed' AND c.status='completed'
          AND b.system_configuration_digest=c.system_configuration_digest AND b.evaluator_configuration_digest=c.evaluator_configuration_digest
    ) THEN RAISE(ABORT,'shadow evaluation runs are not comparable') END;
    SELECT CASE WHEN NOT EXISTS (SELECT 1 FROM artifacts a WHERE a.id=NEW.evidence_artifact_id AND a.project_id=NEW.project_id AND (a.task_id IS NULL OR a.task_id=NEW.task_id) AND a.content_hash=NEW.evidence_digest) THEN RAISE(ABORT,'shadow evaluation evidence scope or digest is incoherent') END;
    SELECT CASE WHEN NEW.result='passed' AND (NEW.quality_delta_millionths<0 OR NEW.new_forbidden_mistakes<>0 OR NEW.new_unsupported_claims<>0) THEN RAISE(ABORT,'passing shadow evaluation cannot introduce regressions') END;
END;
CREATE TRIGGER shadow_evaluation_update_forbidden BEFORE UPDATE ON memory_shadow_evaluations FOR EACH ROW BEGIN SELECT RAISE(ABORT,'shadow evaluations are immutable'); END;
CREATE TRIGGER shadow_evaluation_delete_forbidden BEFORE DELETE ON memory_shadow_evaluations FOR EACH ROW BEGIN SELECT RAISE(ABORT,'shadow evaluations are retained'); END;

CREATE TRIGGER memory_promotion_v41_shadow_gate BEFORE INSERT ON memory_promotion_reviews FOR EACH ROW
WHEN NEW.decision='granted' AND NEW.reviewer_kind IN ('deterministic','policy')
BEGIN
    SELECT CASE WHEN EXISTS (SELECT 1 FROM memory_records m WHERE m.id=NEW.memory_id AND m.memory_type IN ('semantic','procedural','negative'))
      AND NOT EXISTS (SELECT 1 FROM memory_shadow_evaluations s WHERE s.memory_id=NEW.memory_id AND s.result='passed' AND s.new_forbidden_mistakes=0 AND s.new_unsupported_claims=0 AND s.quality_delta_millionths>=0)
    THEN RAISE(ABORT,'policy promotion requires passing shadow evaluation') END;
END;

CREATE TRIGGER memory_usage_scope_insert BEFORE INSERT ON memory_usage_events FOR EACH ROW BEGIN
    SELECT CASE WHEN NOT EXISTS (
        SELECT 1 FROM memory_records m JOIN tasks t ON t.id=NEW.task_id JOIN agent_runs r ON r.id=NEW.run_id JOIN artifacts a ON a.id=NEW.evidence_artifact_id
        WHERE m.id=NEW.memory_id AND m.project_id=NEW.project_id AND t.project_id=NEW.project_id AND r.task_id=NEW.task_id
          AND a.project_id=NEW.project_id AND (a.task_id IS NULL OR a.task_id=NEW.task_id) AND a.content_hash=NEW.evidence_digest
    ) THEN RAISE(ABORT,'memory usage scope is incoherent') END;
END;
CREATE TRIGGER memory_usage_update_forbidden BEFORE UPDATE ON memory_usage_events FOR EACH ROW BEGIN SELECT RAISE(ABORT,'memory usage events are immutable'); END;
CREATE TRIGGER memory_usage_delete_forbidden BEFORE DELETE ON memory_usage_events FOR EACH ROW BEGIN SELECT RAISE(ABORT,'memory usage events are retained'); END;

CREATE TRIGGER memory_utility_scope_insert BEFORE INSERT ON memory_utility_snapshots FOR EACH ROW BEGIN
    SELECT CASE WHEN NOT EXISTS (SELECT 1 FROM memory_records m JOIN artifacts a ON a.id=NEW.evidence_artifact_id WHERE m.id=NEW.memory_id AND m.project_id=NEW.project_id AND a.project_id=NEW.project_id AND a.content_hash=NEW.evidence_digest) THEN RAISE(ABORT,'memory utility scope or digest is incoherent') END;
END;
CREATE TRIGGER memory_utility_update_forbidden BEFORE UPDATE ON memory_utility_snapshots FOR EACH ROW BEGIN SELECT RAISE(ABORT,'memory utility snapshots are immutable derived projections'); END;
CREATE TRIGGER memory_utility_delete_forbidden BEFORE DELETE ON memory_utility_snapshots FOR EACH ROW BEGIN SELECT RAISE(ABORT,'memory utility snapshots are retained by generation'); END;

CREATE TRIGGER memory_consolidation_scope_insert BEFORE INSERT ON memory_consolidation_actions FOR EACH ROW BEGIN
    SELECT CASE WHEN EXISTS (
        SELECT 1 FROM json_each(NEW.input_memory_ids_json) j LEFT JOIN memory_records m ON m.id=j.value
        WHERE j.type<>'text' OR m.id IS NULL OR m.project_id<>NEW.project_id
    ) THEN RAISE(ABORT,'memory consolidation inputs are incoherent') END;
    SELECT CASE WHEN NEW.result_memory_id IS NOT NULL AND NOT EXISTS (SELECT 1 FROM memory_records m WHERE m.id=NEW.result_memory_id AND m.project_id=NEW.project_id) THEN RAISE(ABORT,'memory consolidation result scope is incoherent') END;
    SELECT CASE WHEN NOT EXISTS (SELECT 1 FROM artifacts a WHERE a.id=NEW.evidence_artifact_id AND a.project_id=NEW.project_id AND a.content_hash=NEW.evidence_digest) THEN RAISE(ABORT,'memory consolidation evidence scope or digest is incoherent') END;
END;
CREATE TRIGGER memory_consolidation_identity_immutable BEFORE UPDATE OF id,project_id,action_kind,input_memory_ids_json,result_memory_id,evidence_artifact_id,evidence_digest,reviewer_kind,created_at ON memory_consolidation_actions FOR EACH ROW BEGIN SELECT RAISE(ABORT,'memory consolidation identity is immutable'); END;
CREATE TRIGGER memory_consolidation_status_transition BEFORE UPDATE OF status,applied_at ON memory_consolidation_actions FOR EACH ROW BEGIN
    SELECT CASE WHEN NOT ((OLD.status='proposed' AND NEW.status IN ('approved','rejected')) OR (OLD.status='approved' AND NEW.status='applied') OR OLD.status=NEW.status) THEN RAISE(ABORT,'invalid memory consolidation lifecycle') END;
END;
CREATE TRIGGER memory_consolidation_delete_forbidden BEFORE DELETE ON memory_consolidation_actions FOR EACH ROW BEGIN SELECT RAISE(ABORT,'memory consolidation actions are retained'); END;

CREATE TRIGGER context_budget_scope_insert BEFORE INSERT ON context_budget_decisions FOR EACH ROW BEGIN
    SELECT CASE WHEN NOT EXISTS (
        SELECT 1 FROM tasks t JOIN agent_runs r ON r.id=NEW.run_id JOIN context_packages cp ON cp.id=NEW.context_package_id JOIN artifacts a ON a.id=NEW.evidence_artifact_id
        WHERE t.id=NEW.task_id AND t.project_id=NEW.project_id AND r.task_id=NEW.task_id AND r.context_package_id=NEW.context_package_id
          AND cp.task_id=NEW.task_id AND a.project_id=NEW.project_id AND (a.task_id IS NULL OR a.task_id=NEW.task_id) AND a.content_hash=NEW.evidence_digest
    ) THEN RAISE(ABORT,'context budget scope is incoherent') END;
    SELECT CASE WHEN EXISTS (SELECT 1 FROM json_each(NEW.allocations_json) WHERE type NOT IN ('integer','real') OR CAST(value AS INTEGER)<0) THEN RAISE(ABORT,'context budget allocations must be non-negative integers') END;
    SELECT CASE WHEN COALESCE((SELECT SUM(CAST(value AS INTEGER)) FROM json_each(NEW.allocations_json)),0)<>NEW.total_allocated_tokens THEN RAISE(ABORT,'context budget allocations do not sum to total') END;
END;
CREATE TRIGGER context_budget_update_forbidden BEFORE UPDATE ON context_budget_decisions FOR EACH ROW BEGIN SELECT RAISE(ABORT,'context budget decisions are immutable'); END;
CREATE TRIGGER context_budget_delete_forbidden BEFORE DELETE ON context_budget_decisions FOR EACH ROW BEGIN SELECT RAISE(ABORT,'context budget decisions are retained'); END;

CREATE UNIQUE INDEX idx_state_active_precedence ON state_records(project_id,scope_kind,scope_id,state_key,precedence_rank) WHERE status='active';
CREATE INDEX idx_state_resolution_lookup ON state_records(project_id,scope_kind,scope_id,state_key,status,precedence_rank DESC);
CREATE INDEX idx_invalidation_due ON memory_invalidation_evaluations(memory_id,rule_id,evaluated_at DESC,valid_until);
CREATE INDEX idx_shadow_memory ON memory_shadow_evaluations(memory_id,result,evaluated_at DESC);
CREATE INDEX idx_memory_usage_lookup ON memory_usage_events(memory_id,event_type,created_at);
CREATE INDEX idx_memory_utility_lookup ON memory_utility_snapshots(memory_id,generation DESC);
CREATE INDEX idx_consolidation_status ON memory_consolidation_actions(project_id,status,created_at);
CREATE UNIQUE INDEX idx_context_budget_package ON context_budget_decisions(context_package_id);

COMMIT;

-- After this transaction succeeds, the migration runner records version 4
-- with the actual file checksum, application version, and authoritative time.

PRAGMA foreign_keys = ON;
BEGIN IMMEDIATE;

-- v4.1.1 loop-review patch: close authority, invalidation, shadow, usage, and budget bypasses.

ALTER TABLE state_records ADD COLUMN ended_at TEXT;
UPDATE state_records SET ended_at=status_changed_at WHERE status IN ('superseded','retracted','expired') AND ended_at IS NULL;
ALTER TABLE memory_shadow_evaluations ADD COLUMN new_cross_scope_leaks INTEGER NOT NULL DEFAULT 0 CHECK (new_cross_scope_leaks>=0);
ALTER TABLE memory_shadow_evaluations ADD COLUMN new_stale_memory_uses INTEGER NOT NULL DEFAULT 0 CHECK (new_stale_memory_uses>=0);
ALTER TABLE memory_usage_events ADD COLUMN position INTEGER CHECK (position IS NULL OR position>=1);
ALTER TABLE memory_usage_events ADD COLUMN outcome_delta_millionths INTEGER CHECK (outcome_delta_millionths IS NULL OR outcome_delta_millionths BETWEEN -1000000 AND 1000000);
ALTER TABLE memory_usage_events ADD COLUMN retrieval_candidate_id TEXT REFERENCES retrieval_candidates(id) ON DELETE RESTRICT;
ALTER TABLE memory_usage_events ADD COLUMN context_package_item_id TEXT REFERENCES context_package_items(id) ON DELETE RESTRICT;
ALTER TABLE context_budget_decisions ADD COLUMN max_budget_tokens INTEGER;
ALTER TABLE context_budget_decisions ADD COLUMN reserved_output_tokens INTEGER;
ALTER TABLE context_budget_decisions ADD COLUMN reserved_verification_tokens INTEGER;

CREATE TABLE state_resolution_conflicts (
    id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE RESTRICT,
    task_id TEXT REFERENCES tasks(id) ON DELETE RESTRICT,
    state_key TEXT NOT NULL,
    candidate_state_ids_json TEXT NOT NULL CHECK (json_valid(candidate_state_ids_json) AND json_type(candidate_state_ids_json)='array' AND json_array_length(candidate_state_ids_json)>=2),
    precedence_rank INTEGER NOT NULL CHECK (precedence_rank IN (600,500,400,300,200,100)),
    evidence_artifact_id TEXT NOT NULL REFERENCES artifacts(id) ON DELETE RESTRICT,
    evidence_digest TEXT NOT NULL CHECK (length(evidence_digest)=71 AND substr(evidence_digest,1,7)='sha256:' AND substr(evidence_digest,8) NOT GLOB '*[^0-9a-f]*'),
    status TEXT NOT NULL CHECK (status IN ('open','resolved','superseded')),
    resolution_receipt_id TEXT REFERENCES state_resolution_receipts(id) ON DELETE RESTRICT,
    created_at TEXT NOT NULL,
    resolved_at TEXT,
    CHECK (status='resolved' OR (resolution_receipt_id IS NULL AND resolved_at IS NULL)),
    CHECK (status<>'resolved' OR (resolution_receipt_id IS NOT NULL AND resolved_at IS NOT NULL))
) STRICT;

ALTER TABLE state_resolution_receipts ADD COLUMN conflict_id TEXT REFERENCES state_resolution_conflicts(id) ON DELETE RESTRICT;

CREATE TABLE memory_origin_records (
    id TEXT PRIMARY KEY,
    memory_id TEXT NOT NULL UNIQUE REFERENCES memory_records(id) ON DELETE RESTRICT,
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE RESTRICT,
    origin_kind TEXT NOT NULL CHECK (origin_kind IN ('model_generated','user_explicit','approved_decision','imported_verified','legacy_unknown')),
    origin_actor_kind TEXT NOT NULL CHECK (origin_actor_kind IN ('user','agent','system','importer','migration')),
    origin_actor_id TEXT NOT NULL CHECK (length(origin_actor_id)>0),
    origin_actor_binding_digest TEXT NOT NULL CHECK (length(origin_actor_binding_digest)=71 AND substr(origin_actor_binding_digest,1,7)='sha256:' AND substr(origin_actor_binding_digest,8) NOT GLOB '*[^0-9a-f]*'),
    evidence_artifact_id TEXT NOT NULL REFERENCES artifacts(id) ON DELETE RESTRICT,
    evidence_digest TEXT NOT NULL CHECK (length(evidence_digest)=71 AND substr(evidence_digest,1,7)='sha256:' AND substr(evidence_digest,8) NOT GLOB '*[^0-9a-f]*'),
    created_at TEXT NOT NULL
) STRICT;

CREATE TABLE benchmark_run_arms (
    id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL UNIQUE REFERENCES benchmark_runs(id) ON DELETE RESTRICT,
    experiment_arm TEXT NOT NULL CHECK (experiment_arm IN ('control_no_memory','compaction_only','evidence_retrieval','evidence_plus_experience')),
    model_configuration_digest TEXT NOT NULL CHECK (length(model_configuration_digest)=71 AND substr(model_configuration_digest,1,7)='sha256:' AND substr(model_configuration_digest,8) NOT GLOB '*[^0-9a-f]*'),
    budget_profile_digest TEXT NOT NULL CHECK (length(budget_profile_digest)=71 AND substr(budget_profile_digest,1,7)='sha256:' AND substr(budget_profile_digest,8) NOT GLOB '*[^0-9a-f]*'),
    policy_configuration_digest TEXT NOT NULL CHECK (length(policy_configuration_digest)=71 AND substr(policy_configuration_digest,1,7)='sha256:' AND substr(policy_configuration_digest,8) NOT GLOB '*[^0-9a-f]*'),
    created_at TEXT NOT NULL
) STRICT;

CREATE TABLE benchmark_run_memory_bindings (
    id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL REFERENCES benchmark_runs(id) ON DELETE RESTRICT,
    memory_id TEXT NOT NULL REFERENCES memory_records(id) ON DELETE RESTRICT,
    availability TEXT NOT NULL CHECK (availability='available'),
    created_at TEXT NOT NULL,
    UNIQUE(run_id,memory_id)
) STRICT;

-- State lifecycle and resolution hardening.
CREATE TRIGGER state_records_v5_new_active BEFORE INSERT ON state_records FOR EACH ROW BEGIN
    SELECT CASE WHEN NEW.status<>'active' OR NEW.ended_at IS NOT NULL OR NEW.retracted_at IS NOT NULL THEN RAISE(ABORT,'new state must start active') END;
    SELECT CASE WHEN NEW.valid_from>NEW.created_at OR (NEW.valid_until IS NOT NULL AND NEW.valid_until<=NEW.created_at) THEN RAISE(ABORT,'new active state must be valid at creation time') END;
END;

CREATE TRIGGER state_records_v5_valid_until_immutable BEFORE UPDATE OF valid_until ON state_records FOR EACH ROW
WHEN NEW.valid_until IS NOT OLD.valid_until BEGIN SELECT RAISE(ABORT,'state validity window is immutable'); END;

CREATE TRIGGER state_records_v5_lifecycle_guard BEFORE UPDATE OF status,status_changed_at,retracted_at,ended_at ON state_records FOR EACH ROW BEGIN
    SELECT CASE WHEN OLD.status=NEW.status AND (
        NEW.status_changed_at IS NOT OLD.status_changed_at OR NEW.retracted_at IS NOT OLD.retracted_at OR NEW.ended_at IS NOT OLD.ended_at
    ) THEN RAISE(ABORT,'state lifecycle fields change only with status') END;
    SELECT CASE WHEN OLD.status<>NEW.status AND NEW.status_changed_at<=OLD.status_changed_at THEN RAISE(ABORT,'state lifecycle transition requires newer time') END;
    SELECT CASE WHEN OLD.status<>NEW.status AND (NEW.ended_at IS NULL OR NEW.ended_at<>NEW.status_changed_at) THEN RAISE(ABORT,'terminal state requires ended_at equal to lifecycle time') END;
    SELECT CASE WHEN NEW.status='retracted' AND (NEW.retracted_at IS NULL OR NEW.retracted_at<>NEW.status_changed_at) THEN RAISE(ABORT,'retracted state requires exact retraction time') END;
    SELECT CASE WHEN NEW.status<>'retracted' AND NEW.retracted_at IS NOT NULL THEN RAISE(ABORT,'non-retracted state cannot carry retraction time') END;
END;

CREATE TRIGGER state_resolution_v5_guard BEFORE INSERT ON state_resolution_receipts FOR EACH ROW BEGIN
    SELECT CASE WHEN EXISTS (
        SELECT 1 FROM json_each(NEW.candidate_state_ids_json) GROUP BY value HAVING COUNT(*)>1
    ) THEN RAISE(ABORT,'candidate state ids must be unique') END;
    SELECT CASE WHEN EXISTS (
        SELECT 1 FROM json_each(NEW.candidate_state_ids_json) j
        JOIN state_records s ON s.id=j.value
        WHERE s.valid_from>NEW.created_at OR (s.valid_until IS NOT NULL AND s.valid_until<=NEW.created_at) OR s.ended_at IS NOT NULL
    ) THEN RAISE(ABORT,'state resolution candidate is not valid at decision time') END;
    SELECT CASE WHEN NEW.conflict_id IS NOT NULL AND NOT EXISTS (
        WITH candidates AS (
            SELECT s.* FROM json_each(NEW.candidate_state_ids_json) j JOIN state_records s ON s.id=j.value
        ), top_rank AS (SELECT MAX(precedence_rank) AS rank FROM candidates)
        SELECT 1 FROM state_resolution_conflicts sc JOIN top_rank tr
        WHERE sc.id=NEW.conflict_id AND sc.project_id=NEW.project_id AND sc.task_id IS NEW.task_id
          AND sc.state_key=NEW.state_key AND sc.status='open' AND sc.precedence_rank=tr.rank
          AND json_array_length(sc.candidate_state_ids_json)=json_array_length(NEW.candidate_state_ids_json)
          AND NOT EXISTS (
              SELECT 1 FROM json_each(sc.candidate_state_ids_json) x
              WHERE NOT EXISTS (SELECT 1 FROM json_each(NEW.candidate_state_ids_json) y WHERE y.value=x.value)
          )
          AND NOT EXISTS (
              SELECT 1 FROM json_each(NEW.candidate_state_ids_json) y
              WHERE NOT EXISTS (SELECT 1 FROM json_each(sc.candidate_state_ids_json) x WHERE x.value=y.value)
          )
    ) THEN RAISE(ABORT,'state resolution conflict link is incoherent') END;
    SELECT CASE WHEN EXISTS (
        WITH candidates AS (
            SELECT s.* FROM json_each(NEW.candidate_state_ids_json) j JOIN state_records s ON s.id=j.value
        ), top_rank AS (SELECT MAX(precedence_rank) AS rank FROM candidates)
        SELECT 1 FROM candidates a JOIN candidates b ON a.id<b.id JOIN top_rank tr
        WHERE a.precedence_rank=tr.rank AND b.precedence_rank=tr.rank
          AND a.value_json<>b.value_json
          AND COALESCE(a.supersedes_state_id,'')<>b.id
          AND COALESCE(b.supersedes_state_id,'')<>a.id
    ) AND NEW.conflict_id IS NULL THEN RAISE(ABORT,'conflict resolution receipt requires explicit conflict link') END;
END;

CREATE TRIGGER state_conflict_v5_scope BEFORE INSERT ON state_resolution_conflicts FOR EACH ROW BEGIN
    SELECT CASE WHEN NEW.task_id IS NOT NULL AND NOT EXISTS (SELECT 1 FROM tasks t WHERE t.id=NEW.task_id AND t.project_id=NEW.project_id) THEN RAISE(ABORT,'state conflict task scope is incoherent') END;
    SELECT CASE WHEN EXISTS (SELECT 1 FROM json_each(NEW.candidate_state_ids_json) GROUP BY value HAVING COUNT(*)>1) THEN RAISE(ABORT,'conflict candidate state ids must be unique') END;
    SELECT CASE WHEN EXISTS (
        SELECT 1 FROM json_each(NEW.candidate_state_ids_json) j LEFT JOIN state_records s ON s.id=j.value
        WHERE j.type<>'text' OR s.id IS NULL OR s.project_id<>NEW.project_id OR s.state_key<>NEW.state_key OR s.status<>'active' OR s.precedence_rank<>NEW.precedence_rank
          OR (NEW.task_id IS NULL AND s.task_id IS NOT NULL)
          OR (NEW.task_id IS NOT NULL AND s.task_id IS NOT NULL AND s.task_id<>NEW.task_id)
          OR s.valid_from>NEW.created_at OR (s.valid_until IS NOT NULL AND s.valid_until<=NEW.created_at) OR s.ended_at IS NOT NULL
    ) THEN RAISE(ABORT,'state conflict candidates are incoherent') END;
    SELECT CASE WHEN NOT EXISTS (
        SELECT 1 FROM json_each(NEW.candidate_state_ids_json) a
        JOIN json_each(NEW.candidate_state_ids_json) b ON a.value<b.value
        JOIN state_records sa ON sa.id=a.value JOIN state_records sb ON sb.id=b.value
        WHERE sa.value_json<>sb.value_json
    ) THEN RAISE(ABORT,'state conflict requires divergent values') END;
    SELECT CASE WHEN NOT EXISTS (SELECT 1 FROM artifacts a WHERE a.id=NEW.evidence_artifact_id AND a.project_id=NEW.project_id AND (NEW.task_id IS NULL OR a.task_id IS NULL OR a.task_id=NEW.task_id) AND a.content_hash=NEW.evidence_digest) THEN RAISE(ABORT,'state conflict evidence scope or digest is incoherent') END;
    SELECT CASE WHEN NEW.status<>'open' OR NEW.resolution_receipt_id IS NOT NULL OR NEW.resolved_at IS NOT NULL THEN RAISE(ABORT,'new state conflict must start open') END;
END;
CREATE TRIGGER state_conflict_v5_identity_immutable BEFORE UPDATE OF id,project_id,task_id,state_key,candidate_state_ids_json,precedence_rank,evidence_artifact_id,evidence_digest,created_at ON state_resolution_conflicts FOR EACH ROW BEGIN SELECT RAISE(ABORT,'state conflict identity is immutable'); END;
CREATE TRIGGER state_conflict_v5_lifecycle BEFORE UPDATE OF status,resolution_receipt_id,resolved_at ON state_resolution_conflicts FOR EACH ROW BEGIN
    SELECT CASE WHEN NOT ((OLD.status='open' AND NEW.status IN ('resolved','superseded')) OR OLD.status=NEW.status) THEN RAISE(ABORT,'invalid state conflict lifecycle') END;
    SELECT CASE WHEN OLD.status=NEW.status AND (NEW.resolution_receipt_id IS NOT OLD.resolution_receipt_id OR NEW.resolved_at IS NOT OLD.resolved_at) THEN RAISE(ABORT,'state conflict resolution fields change only with status') END;
    SELECT CASE WHEN NEW.status='resolved' AND (NEW.resolved_at<=OLD.created_at OR NOT EXISTS (
        SELECT 1 FROM state_resolution_receipts r
        WHERE r.id=NEW.resolution_receipt_id AND r.conflict_id=OLD.id
          AND r.project_id=NEW.project_id AND r.task_id IS NEW.task_id
          AND r.state_key=NEW.state_key AND r.created_at=NEW.resolved_at
          AND json_array_length(r.candidate_state_ids_json)=json_array_length(OLD.candidate_state_ids_json)
          AND NOT EXISTS (
              SELECT 1 FROM json_each(r.candidate_state_ids_json) x
              WHERE NOT EXISTS (SELECT 1 FROM json_each(OLD.candidate_state_ids_json) y WHERE y.value=x.value)
          )
          AND NOT EXISTS (
              SELECT 1 FROM json_each(OLD.candidate_state_ids_json) y
              WHERE NOT EXISTS (SELECT 1 FROM json_each(r.candidate_state_ids_json) x WHERE x.value=y.value)
          )
    )) THEN RAISE(ABORT,'state conflict resolution receipt is incoherent') END;
END;
CREATE TRIGGER state_conflict_v5_delete_forbidden BEFORE DELETE ON state_resolution_conflicts FOR EACH ROW BEGIN SELECT RAISE(ABORT,'state conflicts are retained'); END;

-- Strong executable invalidation validation.
DROP TRIGGER invalidation_evaluation_scope_insert;
DROP TRIGGER retrieval_candidate_v41_memory_eligibility;
CREATE TRIGGER memory_records_v5_invalidation_shape BEFORE INSERT ON memory_records FOR EACH ROW BEGIN
    SELECT CASE WHEN EXISTS (
        SELECT 1 FROM json_each(NEW.invalidation_conditions_json) r
        WHERE json_extract(r.value,'$.kind') NOT IN ('source_hash_changed','source_revision_outside_range','path_modified','dependency_version_changed','schema_version_changed','test_result_changed','policy_changed','time_expired','manual_revoke')
    ) THEN RAISE(ABORT,'unsupported invalidation rule kind') END;
    SELECT CASE WHEN EXISTS (
        SELECT 1 FROM json_each(NEW.invalidation_conditions_json) r
        WHERE json_extract(r.value,'$.cadence') NOT IN ('before_retrieval','on_source_change','on_startup','scheduled','manual')
           OR length(COALESCE(json_extract(r.value,'$.ruleId'),''))=0
           OR length(COALESCE(json_extract(r.value,'$.explanation'),''))=0
    ) THEN RAISE(ABORT,'invalidation rule metadata is invalid') END;
    SELECT CASE WHEN EXISTS (
        SELECT 1 FROM json_each(NEW.invalidation_conditions_json)
        GROUP BY json_extract(value,'$.ruleId') HAVING COUNT(*)>1
    ) THEN RAISE(ABORT,'invalidation rule ids must be unique') END;
    SELECT CASE WHEN EXISTS (
        SELECT 1 FROM json_each(NEW.invalidation_conditions_json) r
        WHERE
          (json_extract(r.value,'$.kind')='source_hash_changed' AND NOT COALESCE((
             json_type(r.value,'$.target.sourceId')='text' AND length(json_extract(r.value,'$.target.sourceId'))>0
             AND json_type(r.value,'$.expected.contentHash')='text' AND length(json_extract(r.value,'$.expected.contentHash'))=71
             AND substr(json_extract(r.value,'$.expected.contentHash'),1,7)='sha256:'
             AND substr(json_extract(r.value,'$.expected.contentHash'),8) NOT GLOB '*[^0-9a-f]*'),0))
          OR (json_extract(r.value,'$.kind')='source_revision_outside_range' AND NOT COALESCE((
             json_type(r.value,'$.target.sourceId')='text' AND length(json_extract(r.value,'$.target.sourceId'))>0
             AND json_type(r.value,'$.expected.allowedRevisions')='array' AND json_array_length(json_extract(r.value,'$.expected.allowedRevisions'))>=1
             AND NOT EXISTS (SELECT 1 FROM json_each(json_extract(r.value,'$.expected.allowedRevisions')) ar WHERE ar.type<>'text' OR length(ar.value)=0)),0))
          OR (json_extract(r.value,'$.kind')='path_modified' AND NOT COALESCE((
             json_type(r.value,'$.target.path')='text' AND length(json_extract(r.value,'$.target.path'))>0
             AND json_type(r.value,'$.expected.contentHash')='text' AND length(json_extract(r.value,'$.expected.contentHash'))=71
             AND substr(json_extract(r.value,'$.expected.contentHash'),1,7)='sha256:'
             AND substr(json_extract(r.value,'$.expected.contentHash'),8) NOT GLOB '*[^0-9a-f]*'),0))
          OR (json_extract(r.value,'$.kind')='dependency_version_changed' AND NOT COALESCE((
             json_type(r.value,'$.target.dependency')='text' AND length(json_extract(r.value,'$.target.dependency'))>0
             AND json_type(r.value,'$.expected.version')='text' AND length(json_extract(r.value,'$.expected.version'))>0),0))
          OR (json_extract(r.value,'$.kind')='schema_version_changed' AND NOT COALESCE((
             json_type(r.value,'$.target.schemaId')='text' AND length(json_extract(r.value,'$.target.schemaId'))>0
             AND json_type(r.value,'$.expected.version')='text' AND length(json_extract(r.value,'$.expected.version'))>0),0))
          OR (json_extract(r.value,'$.kind')='test_result_changed' AND NOT COALESCE((
             json_type(r.value,'$.target.testId')='text' AND length(json_extract(r.value,'$.target.testId'))>0
             AND json_extract(r.value,'$.expected.result') IN ('pass','fail')),0))
          OR (json_extract(r.value,'$.kind')='policy_changed' AND NOT COALESCE((
             json_type(r.value,'$.target.policyId')='text' AND length(json_extract(r.value,'$.target.policyId'))>0
             AND json_type(r.value,'$.expected.policyDigest')='text' AND length(json_extract(r.value,'$.expected.policyDigest'))=71
             AND substr(json_extract(r.value,'$.expected.policyDigest'),1,7)='sha256:'
             AND substr(json_extract(r.value,'$.expected.policyDigest'),8) NOT GLOB '*[^0-9a-f]*'),0))
          OR (json_extract(r.value,'$.kind')='time_expired' AND NOT COALESCE((
             json_type(r.value,'$.target')='object' AND json_type(r.value,'$.expected.expiresAt')='text' AND length(json_extract(r.value,'$.expected.expiresAt'))>0),0))
          OR (json_extract(r.value,'$.kind')='manual_revoke' AND NOT COALESCE((
             json_type(r.value,'$.target.revokeKey')='text' AND length(json_extract(r.value,'$.target.revokeKey'))>0
             AND json_extract(r.value,'$.expected.requiredState')='not_revoked'),0))
    ) THEN RAISE(ABORT,'invalidation rule payload does not match kind') END;
END;

CREATE TRIGGER invalidation_evaluation_v5_scope BEFORE INSERT ON memory_invalidation_evaluations FOR EACH ROW BEGIN
    SELECT CASE WHEN NOT EXISTS (
        SELECT 1 FROM memory_records m
        WHERE m.id=NEW.memory_id AND m.project_id=NEW.project_id
          AND (
            (json_extract(m.applicability_json,'$.scope.kind')='task' AND NEW.task_id=json_extract(m.applicability_json,'$.scope.id'))
            OR (json_extract(m.applicability_json,'$.scope.kind')<>'task' AND (NEW.task_id IS NULL OR EXISTS (SELECT 1 FROM tasks t WHERE t.id=NEW.task_id AND t.project_id=NEW.project_id)))
          )
    ) THEN RAISE(ABORT,'invalidation evaluation applicability scope is incoherent') END;
    SELECT CASE WHEN NOT EXISTS (
        SELECT 1 FROM memory_records m, json_each(m.invalidation_conditions_json) r
        WHERE m.id=NEW.memory_id AND json_extract(r.value,'$.ruleId')=NEW.rule_id
    ) THEN RAISE(ABORT,'invalidation rule is not declared by memory') END;
    SELECT CASE WHEN NOT EXISTS (
        SELECT 1 FROM artifacts a WHERE a.id=NEW.evidence_artifact_id AND a.project_id=NEW.project_id
          AND (NEW.task_id IS NULL OR a.task_id IS NULL OR a.task_id=NEW.task_id) AND a.content_hash=NEW.evidence_digest
    ) THEN RAISE(ABORT,'invalidation evaluation evidence scope or digest is incoherent') END;
END;

CREATE TRIGGER retrieval_candidate_v5_memory_eligibility BEFORE INSERT ON retrieval_candidates FOR EACH ROW WHEN NEW.memory_id IS NOT NULL BEGIN
    SELECT CASE WHEN NOT EXISTS (
        SELECT 1 FROM memory_records m JOIN retrieval_sessions rs ON rs.id=NEW.retrieval_session_id
        WHERE m.id=NEW.memory_id AND m.project_id=rs.project_id
          AND (json_extract(m.applicability_json,'$.scope.kind')<>'task' OR json_extract(m.applicability_json,'$.scope.id')=rs.task_id)
          AND (json_extract(m.applicability_json,'$.scope.kind')<>'project' OR json_extract(m.applicability_json,'$.scope.id')=rs.project_id)
    ) THEN RAISE(ABORT,'retrieval memory applicability scope is incoherent') END;
    SELECT CASE WHEN EXISTS (
        SELECT 1 FROM memory_records m, json_each(m.invalidation_conditions_json) r
        JOIN retrieval_sessions rs ON rs.id=NEW.retrieval_session_id
        WHERE m.id=NEW.memory_id AND NOT EXISTS (
            SELECT 1 FROM memory_invalidation_evaluations e
            WHERE e.id=(
                SELECT e2.id FROM memory_invalidation_evaluations e2
                WHERE e2.memory_id=m.id AND e2.rule_id=json_extract(r.value,'$.ruleId')
                  AND e2.project_id=rs.project_id AND (e2.task_id IS NULL OR e2.task_id=rs.task_id)
                  AND e2.evaluated_at<=rs.started_at
                ORDER BY e2.evaluated_at DESC,e2.id DESC LIMIT 1
            )
              AND e.result='passed' AND (e.valid_until IS NULL OR e.valid_until>rs.started_at)
        )
    ) THEN RAISE(ABORT,'retrieval memory lacks applicable current passing invalidation evidence') END;
END;

CREATE TRIGGER context_item_v5_memory_candidate BEFORE INSERT ON context_package_items FOR EACH ROW WHEN NEW.memory_id IS NOT NULL BEGIN
    SELECT CASE WHEN NEW.retrieval_candidate_id IS NULL OR NOT EXISTS (
        SELECT 1 FROM retrieval_candidates rc
        JOIN retrieval_sessions rs ON rs.id=rc.retrieval_session_id
        JOIN agent_runs r ON r.id=rs.run_id
        WHERE rc.id=NEW.retrieval_candidate_id AND rc.memory_id=NEW.memory_id AND rc.selected=1
          AND rc.project_id=NEW.project_id AND rs.task_id=NEW.task_id
          AND r.task_id=NEW.task_id AND r.context_package_id=NEW.context_package_id
    ) THEN RAISE(ABORT,'experience memory candidate must belong to package run') END;
END;

-- Memory origin and exact shadow isolation.
CREATE TRIGGER memory_origin_v5_scope BEFORE INSERT ON memory_origin_records FOR EACH ROW BEGIN
    SELECT CASE WHEN NOT EXISTS (
        SELECT 1 FROM memory_records m JOIN artifacts a ON a.id=NEW.evidence_artifact_id
        WHERE m.id=NEW.memory_id AND m.project_id=NEW.project_id AND m.status='candidate'
          AND a.project_id=NEW.project_id
          AND ((m.origin_task_id IS NULL AND a.task_id IS NULL) OR (m.origin_task_id IS NOT NULL AND (a.task_id IS NULL OR a.task_id=m.origin_task_id)))
          AND a.content_hash=NEW.evidence_digest AND a.availability='available' AND a.verification_state<>'rejected'
          AND NEW.created_at>=m.created_at
    ) THEN RAISE(ABORT,'memory origin must be recorded while candidate with coherent scope, evidence, and time') END;
    SELECT CASE WHEN NOT (
        (NEW.origin_kind='model_generated' AND NEW.origin_actor_kind='agent')
        OR (NEW.origin_kind='user_explicit' AND NEW.origin_actor_kind='user')
        OR (NEW.origin_kind='approved_decision' AND NEW.origin_actor_kind IN ('user','system'))
        OR (NEW.origin_kind='imported_verified' AND NEW.origin_actor_kind IN ('user','system','importer'))
        OR (NEW.origin_kind='legacy_unknown' AND NEW.origin_actor_kind='migration')
    ) THEN RAISE(ABORT,'memory origin actor kind is incoherent') END;
END;
CREATE TRIGGER memory_origin_v5_update_forbidden BEFORE UPDATE ON memory_origin_records FOR EACH ROW BEGIN SELECT RAISE(ABORT,'memory origin records are immutable'); END;
CREATE TRIGGER memory_origin_v5_delete_forbidden BEFORE DELETE ON memory_origin_records FOR EACH ROW BEGIN SELECT RAISE(ABORT,'memory origin records are retained'); END;
CREATE TRIGGER memory_records_v5_origin_before_verification BEFORE UPDATE OF status ON memory_records FOR EACH ROW
WHEN OLD.status='candidate' AND NEW.status='verified' AND NOT EXISTS (SELECT 1 FROM memory_origin_records o WHERE o.memory_id=OLD.id AND o.project_id=OLD.project_id)
BEGIN SELECT RAISE(ABORT,'verified memory requires immutable origin record'); END;

CREATE TRIGGER benchmark_run_arm_v5_scope BEFORE INSERT ON benchmark_run_arms FOR EACH ROW BEGIN
    SELECT CASE WHEN NOT EXISTS (
        SELECT 1 FROM benchmark_runs r JOIN benchmark_cases c ON c.id=r.benchmark_case_id
        WHERE r.id=NEW.run_id AND NEW.model_configuration_digest=r.system_configuration_digest
          AND NEW.budget_profile_digest=c.budget_profile_digest
    ) THEN RAISE(ABORT,'benchmark run arm scope or configuration is incoherent') END;
END;
CREATE TRIGGER benchmark_run_arm_v5_update_forbidden BEFORE UPDATE ON benchmark_run_arms FOR EACH ROW BEGIN SELECT RAISE(ABORT,'benchmark run arms are immutable'); END;
CREATE TRIGGER benchmark_run_arm_v5_delete_forbidden BEFORE DELETE ON benchmark_run_arms FOR EACH ROW BEGIN SELECT RAISE(ABORT,'benchmark run arms are retained'); END;

CREATE TRIGGER benchmark_memory_binding_v5_scope BEFORE INSERT ON benchmark_run_memory_bindings FOR EACH ROW BEGIN
    SELECT CASE WHEN NOT EXISTS (
        SELECT 1 FROM benchmark_runs r JOIN benchmark_cases c ON c.id=r.benchmark_case_id JOIN benchmark_suites s ON s.id=c.suite_id
        JOIN memory_records m ON m.id=NEW.memory_id JOIN benchmark_run_arms a ON a.run_id=r.id
        WHERE r.id=NEW.run_id AND m.project_id=s.project_id AND a.experiment_arm='evidence_plus_experience'
    ) THEN RAISE(ABORT,'benchmark memory binding scope or arm is incoherent') END;
END;
CREATE TRIGGER benchmark_memory_binding_v5_update_forbidden BEFORE UPDATE ON benchmark_run_memory_bindings FOR EACH ROW BEGIN SELECT RAISE(ABORT,'benchmark memory bindings are immutable'); END;
CREATE TRIGGER benchmark_memory_binding_v5_delete_forbidden BEFORE DELETE ON benchmark_run_memory_bindings FOR EACH ROW BEGIN SELECT RAISE(ABORT,'benchmark memory bindings are retained'); END;

CREATE TRIGGER shadow_evaluation_v5_exact_isolation BEFORE INSERT ON memory_shadow_evaluations FOR EACH ROW BEGIN
    SELECT CASE WHEN NOT EXISTS (
        SELECT 1 FROM benchmark_run_arms ca JOIN benchmark_run_arms aa ON aa.run_id=NEW.candidate_run_id
        WHERE ca.run_id=NEW.control_run_id AND ca.experiment_arm=NEW.control_arm AND aa.experiment_arm=NEW.candidate_arm
          AND ca.model_configuration_digest=aa.model_configuration_digest
          AND ca.budget_profile_digest=aa.budget_profile_digest
          AND ca.policy_configuration_digest=aa.policy_configuration_digest
          AND NOT EXISTS (SELECT 1 FROM benchmark_run_memory_bindings cb WHERE cb.run_id=NEW.control_run_id)
          AND (SELECT COUNT(*) FROM benchmark_run_memory_bindings ab WHERE ab.run_id=NEW.candidate_run_id)=1
          AND EXISTS (SELECT 1 FROM benchmark_run_memory_bindings ab WHERE ab.run_id=NEW.candidate_run_id AND ab.memory_id=NEW.memory_id AND ab.availability='available')
    ) THEN RAISE(ABORT,'shadow evaluation run arms or memory binding are incoherent') END;
    SELECT CASE WHEN NEW.result='passed' AND (NEW.new_cross_scope_leaks<>0 OR NEW.new_stale_memory_uses<>0) THEN RAISE(ABORT,'passing shadow evaluation cannot introduce regressions') END;
END;
CREATE TRIGGER shadow_evaluation_v5_unique_time BEFORE INSERT ON memory_shadow_evaluations FOR EACH ROW
WHEN EXISTS (SELECT 1 FROM memory_shadow_evaluations s WHERE s.memory_id=NEW.memory_id AND s.evaluated_at=NEW.evaluated_at)
BEGIN SELECT RAISE(ABORT,'shadow evaluation time must be unique per memory'); END;

DROP TRIGGER memory_promotion_v41_shadow_gate;
CREATE TRIGGER memory_promotion_v5_shadow_gate BEFORE INSERT ON memory_promotion_reviews FOR EACH ROW
WHEN NEW.decision='granted' AND NEW.reviewer_kind IN ('deterministic','policy')
BEGIN
    SELECT CASE WHEN EXISTS (
        SELECT 1 FROM memory_records m LEFT JOIN memory_origin_records o ON o.memory_id=m.id
        WHERE m.id=NEW.memory_id AND m.memory_type IN ('semantic','procedural','negative')
          AND COALESCE(o.origin_kind,'legacy_unknown') IN ('model_generated','legacy_unknown')
    ) AND NOT EXISTS (
        SELECT 1 FROM memory_shadow_evaluations s
        WHERE s.memory_id=NEW.memory_id
          AND s.id=(SELECT s2.id FROM memory_shadow_evaluations s2 WHERE s2.memory_id=NEW.memory_id ORDER BY s2.evaluated_at DESC,s2.id DESC LIMIT 1)
          AND s.result='passed' AND s.quality_delta_millionths>=0
          AND s.new_forbidden_mistakes=0 AND s.new_unsupported_claims=0
          AND s.new_cross_scope_leaks=0 AND s.new_stale_memory_uses=0
          AND s.evaluated_at>= (SELECT status_changed_at FROM memory_records WHERE id=NEW.memory_id)
          AND (SELECT COUNT(*) FROM memory_shadow_evaluations sx WHERE sx.memory_id=s.memory_id AND sx.evaluated_at=s.evaluated_at)=1
          AND EXISTS (
              SELECT 1 FROM benchmark_run_arms ca JOIN benchmark_run_arms aa ON aa.run_id=s.candidate_run_id
              WHERE ca.run_id=s.control_run_id AND ca.experiment_arm=s.control_arm AND aa.experiment_arm=s.candidate_arm
                AND ca.model_configuration_digest=aa.model_configuration_digest
                AND ca.budget_profile_digest=aa.budget_profile_digest
                AND ca.policy_configuration_digest=aa.policy_configuration_digest
                AND NOT EXISTS (SELECT 1 FROM benchmark_run_memory_bindings cb WHERE cb.run_id=s.control_run_id)
                AND (SELECT COUNT(*) FROM benchmark_run_memory_bindings ab WHERE ab.run_id=s.candidate_run_id)=1
                AND EXISTS (SELECT 1 FROM benchmark_run_memory_bindings ab WHERE ab.run_id=s.candidate_run_id AND ab.memory_id=s.memory_id AND ab.availability='available')
          )
    ) THEN RAISE(ABORT,'latest shadow evaluation must pass') END;
END;

-- Exact contribution evidence.
CREATE TRIGGER memory_usage_v5_semantics BEFORE INSERT ON memory_usage_events FOR EACH ROW BEGIN
    SELECT CASE WHEN NEW.included>NEW.retrieved OR NEW.cited>NEW.included OR NEW.used_in_conclusion>NEW.included THEN RAISE(ABORT,'memory usage flags are incoherent') END;
    SELECT CASE WHEN
        (NEW.event_type='retrieved' AND NEW.retrieved<>1)
        OR (NEW.event_type='included' AND NEW.included<>1)
        OR (NEW.event_type='cited' AND NEW.cited<>1)
        OR (NEW.event_type='used_in_conclusion' AND NEW.used_in_conclusion<>1)
        OR (NEW.event_type IN ('helpful','misleading','redundant') AND NEW.included<>1)
    THEN RAISE(ABORT,'memory usage event type does not match flags') END;
    SELECT CASE WHEN NEW.event_type='helpful' AND COALESCE(NEW.helpfulness_millionths,0)<=0 THEN RAISE(ABORT,'helpful usage requires positive helpfulness') END;
    SELECT CASE WHEN NEW.event_type='misleading' AND COALESCE(NEW.helpfulness_millionths,0)>=0 THEN RAISE(ABORT,'misleading usage requires negative helpfulness') END;
    SELECT CASE WHEN NEW.event_type='retrieved' AND NOT EXISTS (
        SELECT 1 FROM retrieval_candidates rc JOIN retrieval_sessions rs ON rs.id=rc.retrieval_session_id
        WHERE rc.id=NEW.retrieval_candidate_id AND rc.memory_id=NEW.memory_id AND rs.run_id=NEW.run_id AND rs.task_id=NEW.task_id AND rc.project_id=NEW.project_id
    ) THEN RAISE(ABORT,'retrieved usage requires matching retrieval candidate') END;
    SELECT CASE WHEN NEW.event_type IN ('included','cited','used_in_conclusion','helpful','misleading','redundant') AND NOT EXISTS (
        SELECT 1 FROM context_package_items ci
        JOIN retrieval_candidates rc ON rc.id=ci.retrieval_candidate_id
        JOIN retrieval_sessions rs ON rs.id=rc.retrieval_session_id
        JOIN agent_runs r ON r.context_package_id=ci.context_package_id
        WHERE ci.id=NEW.context_package_item_id AND ci.memory_id=NEW.memory_id
          AND ci.project_id=NEW.project_id AND ci.task_id=NEW.task_id AND r.id=NEW.run_id
          AND rc.id=NEW.retrieval_candidate_id AND rc.memory_id=NEW.memory_id AND rc.selected=1
          AND rs.run_id=NEW.run_id AND rs.task_id=NEW.task_id
    ) THEN RAISE(ABORT,'included usage requires exact retrieval candidate and context item') END;
END;

-- Consolidation semantics and set-once application evidence.
CREATE TRIGGER memory_consolidation_v5_shape BEFORE INSERT ON memory_consolidation_actions FOR EACH ROW BEGIN
    SELECT CASE WHEN NEW.status<>'proposed' OR NEW.applied_at IS NOT NULL THEN RAISE(ABORT,'new consolidation action must start proposed') END;
    SELECT CASE WHEN EXISTS (SELECT 1 FROM json_each(NEW.input_memory_ids_json) GROUP BY value HAVING COUNT(*)>1) THEN RAISE(ABORT,'consolidation input memory ids must be unique') END;
    SELECT CASE WHEN
        NEW.action_kind='split'
        OR (NEW.action_kind='merge' AND (json_array_length(NEW.input_memory_ids_json)<2 OR NEW.result_memory_id IS NULL))
        OR (NEW.action_kind='supersede' AND (json_array_length(NEW.input_memory_ids_json)<>1 OR NEW.result_memory_id IS NULL))
        OR (NEW.action_kind IN ('retain','mark_stale','retract') AND (json_array_length(NEW.input_memory_ids_json)<>1 OR NEW.result_memory_id IS NOT NULL))
        OR (NEW.result_memory_id IS NOT NULL AND EXISTS (SELECT 1 FROM json_each(NEW.input_memory_ids_json) WHERE value=NEW.result_memory_id))
    THEN RAISE(ABORT,'consolidation action shape is incoherent') END;
END;
CREATE TRIGGER memory_consolidation_v5_applied_set_once BEFORE UPDATE OF applied_at ON memory_consolidation_actions FOR EACH ROW
WHEN OLD.applied_at IS NOT NULL AND NEW.applied_at IS NOT OLD.applied_at BEGIN SELECT RAISE(ABORT,'consolidation applied time is set-once'); END;
CREATE TRIGGER memory_consolidation_v5_apply_exact BEFORE UPDATE OF status,applied_at ON memory_consolidation_actions FOR EACH ROW
WHEN OLD.status='approved' AND NEW.status='applied' BEGIN
    SELECT CASE WHEN NEW.applied_at IS NULL OR NEW.applied_at<=OLD.created_at THEN RAISE(ABORT,'applied consolidation requires a newer application time') END;
    SELECT CASE WHEN NEW.action_kind='mark_stale' AND EXISTS (
        SELECT 1 FROM json_each(NEW.input_memory_ids_json) j JOIN memory_records m ON m.id=j.value WHERE m.status<>'stale'
    ) THEN RAISE(ABORT,'mark_stale consolidation effect is not applied') END;
    SELECT CASE WHEN NEW.action_kind='retract' AND EXISTS (
        SELECT 1 FROM json_each(NEW.input_memory_ids_json) j JOIN memory_records m ON m.id=j.value WHERE m.status<>'retracted'
    ) THEN RAISE(ABORT,'retract consolidation effect is not applied') END;
    SELECT CASE WHEN NEW.action_kind='supersede' AND EXISTS (
        SELECT 1 FROM json_each(NEW.input_memory_ids_json) j JOIN memory_records m ON m.id=j.value
        WHERE m.status<>'superseded' OR NOT EXISTS (
            SELECT 1 FROM memory_relations rel WHERE rel.from_memory_id=NEW.result_memory_id AND rel.to_memory_id=m.id AND rel.relation_kind='supersedes'
        )
    ) THEN RAISE(ABORT,'supersede consolidation effect is not applied') END;
    SELECT CASE WHEN NEW.action_kind='merge' AND EXISTS (
        SELECT 1 FROM json_each(NEW.input_memory_ids_json) j WHERE NOT EXISTS (
            SELECT 1 FROM memory_relations rel WHERE rel.from_memory_id=NEW.result_memory_id AND rel.to_memory_id=j.value AND rel.relation_kind='derived_from'
        )
    ) THEN RAISE(ABORT,'merge consolidation effect is not applied') END;
END;

-- Complete and bounded adaptive-budget receipt.
CREATE TRIGGER context_budget_v5_complete BEFORE INSERT ON context_budget_decisions FOR EACH ROW BEGIN
    SELECT CASE WHEN NEW.coverage_millionths IS NULL OR NEW.marginal_utility_threshold_millionths IS NULL OR NEW.max_budget_tokens IS NULL OR NEW.reserved_output_tokens IS NULL OR NEW.reserved_verification_tokens IS NULL THEN RAISE(ABORT,'context budget receipt is incomplete') END;
    SELECT CASE WHEN NEW.max_budget_tokens<1 OR NEW.reserved_output_tokens<0 OR NEW.reserved_verification_tokens<0 THEN RAISE(ABORT,'context budget limits are invalid') END;
    SELECT CASE WHEN EXISTS (SELECT 1 FROM json_each(NEW.allocations_json) WHERE type<>'integer' OR value<0) THEN RAISE(ABORT,'context budget allocations must be non-negative integers') END;
    SELECT CASE WHEN NEW.total_allocated_tokens+NEW.reserved_output_tokens+NEW.reserved_verification_tokens>NEW.max_budget_tokens THEN RAISE(ABORT,'context budget exceeds declared token budget') END;
END;

CREATE INDEX idx_state_conflicts_open ON state_resolution_conflicts(project_id,state_key,status,created_at);
CREATE UNIQUE INDEX idx_state_resolution_conflict_receipt ON state_resolution_receipts(conflict_id) WHERE conflict_id IS NOT NULL;
CREATE INDEX idx_memory_origin_kind ON memory_origin_records(project_id,origin_kind);
CREATE INDEX idx_benchmark_run_arm ON benchmark_run_arms(experiment_arm,run_id);
CREATE INDEX idx_benchmark_memory_binding ON benchmark_run_memory_bindings(memory_id,run_id);
CREATE INDEX idx_memory_usage_candidate ON memory_usage_events(retrieval_candidate_id);
CREATE INDEX idx_memory_usage_context_item ON memory_usage_events(context_package_item_id);


-- v4.2 end-to-end contract correction authority.

CREATE TABLE actor_bindings (
    id TEXT PRIMARY KEY,
    actor_kind TEXT NOT NULL CHECK (actor_kind IN ('user','system')),
    actor_id TEXT NOT NULL CHECK (length(actor_id)>0),
    session_id TEXT NOT NULL CHECK (length(session_id)>0),
    proof_type TEXT NOT NULL CHECK (proof_type IN ('local_authenticated_session','windows_hello','os_biometric')),
    binding_digest TEXT NOT NULL UNIQUE CHECK (length(binding_digest)=71 AND substr(binding_digest,1,7)='sha256:' AND substr(binding_digest,8) NOT GLOB '*[^0-9a-f]*'),
    issued_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    revoked_at TEXT,
    session_epoch INTEGER NOT NULL CHECK (session_epoch>=1),
    CHECK (expires_at>issued_at),
    CHECK (revoked_at IS NULL OR revoked_at>=issued_at)
) STRICT;

CREATE TRIGGER actor_binding_identity_immutable BEFORE UPDATE OF id,actor_kind,actor_id,session_id,proof_type,binding_digest,issued_at,expires_at,session_epoch ON actor_bindings FOR EACH ROW BEGIN
    SELECT RAISE(ABORT,'actor binding identity is immutable');
END;
CREATE TRIGGER actor_binding_revocation_set_once BEFORE UPDATE OF revoked_at ON actor_bindings FOR EACH ROW WHEN OLD.revoked_at IS NOT NULL AND NEW.revoked_at IS NOT OLD.revoked_at BEGIN
    SELECT RAISE(ABORT,'actor binding revocation is set-once');
END;
CREATE TRIGGER actor_binding_delete_forbidden BEFORE DELETE ON actor_bindings FOR EACH ROW BEGIN SELECT RAISE(ABORT,'actor bindings are retained'); END;

CREATE TABLE credential_challenges (
    id TEXT PRIMARY KEY,
    actor_binding_id TEXT NOT NULL REFERENCES actor_bindings(id) ON DELETE RESTRICT,
    purpose TEXT NOT NULL CHECK (purpose IN ('plan.approval','deliverable.approval','workspace.approval','final_commit.approval','policy_exception.approval')),
    operation_digest TEXT NOT NULL CHECK (length(operation_digest)=71 AND substr(operation_digest,1,7)='sha256:' AND substr(operation_digest,8) NOT GLOB '*[^0-9a-f]*'),
    nonce TEXT NOT NULL UNIQUE CHECK (length(nonce)>=24),
    challenge_digest TEXT NOT NULL UNIQUE CHECK (length(challenge_digest)=71 AND substr(challenge_digest,1,7)='sha256:' AND substr(challenge_digest,8) NOT GLOB '*[^0-9a-f]*'),
    issued_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    CHECK (expires_at>issued_at)
) STRICT;

CREATE TABLE credential_challenge_receipts (
    id TEXT PRIMARY KEY,
    challenge_id TEXT NOT NULL UNIQUE REFERENCES credential_challenges(id) ON DELETE RESTRICT,
    actor_binding_id TEXT NOT NULL REFERENCES actor_bindings(id) ON DELETE RESTRICT,
    proof_type TEXT NOT NULL CHECK (proof_type IN ('local_authenticated_session','windows_hello','os_biometric')),
    proof_artifact_id TEXT NOT NULL REFERENCES artifacts(id) ON DELETE RESTRICT,
    verified_at TEXT NOT NULL,
    receipt_digest TEXT NOT NULL UNIQUE CHECK (length(receipt_digest)=71 AND substr(receipt_digest,1,7)='sha256:' AND substr(receipt_digest,8) NOT GLOB '*[^0-9a-f]*')
) STRICT;

CREATE TRIGGER credential_challenge_receipt_scope BEFORE INSERT ON credential_challenge_receipts FOR EACH ROW BEGIN
    SELECT CASE WHEN NOT EXISTS (
        SELECT 1 FROM credential_challenges c JOIN actor_bindings b ON b.id=c.actor_binding_id
        WHERE c.id=NEW.challenge_id AND c.actor_binding_id=NEW.actor_binding_id
          AND b.proof_type=NEW.proof_type AND b.revoked_at IS NULL
          AND b.issued_at<=NEW.verified_at AND b.expires_at>NEW.verified_at
          AND c.issued_at<=NEW.verified_at AND c.expires_at>NEW.verified_at
    ) THEN RAISE(ABORT,'credential challenge requires a current matching actor binding') END;
END;
CREATE TRIGGER credential_challenge_update_forbidden BEFORE UPDATE ON credential_challenges FOR EACH ROW BEGIN SELECT RAISE(ABORT,'credential challenges are immutable'); END;
CREATE TRIGGER credential_challenge_delete_forbidden BEFORE DELETE ON credential_challenges FOR EACH ROW BEGIN SELECT RAISE(ABORT,'credential challenges are retained'); END;
CREATE TRIGGER credential_challenge_receipt_update_forbidden BEFORE UPDATE ON credential_challenge_receipts FOR EACH ROW BEGIN SELECT RAISE(ABORT,'credential challenge receipts are immutable'); END;
CREATE TRIGGER credential_challenge_receipt_delete_forbidden BEFORE DELETE ON credential_challenge_receipts FOR EACH ROW BEGIN SELECT RAISE(ABORT,'credential challenge receipts are retained'); END;

CREATE TABLE approval_actor_proof_bindings (
    approval_receipt_id TEXT PRIMARY KEY REFERENCES approval_decision_receipts(id) ON DELETE RESTRICT,
    actor_binding_id TEXT NOT NULL REFERENCES actor_bindings(id) ON DELETE RESTRICT,
    challenge_receipt_id TEXT NOT NULL UNIQUE REFERENCES credential_challenge_receipts(id) ON DELETE RESTRICT,
    created_at TEXT NOT NULL
) STRICT;

CREATE TRIGGER approval_actor_proof_scope BEFORE INSERT ON approval_actor_proof_bindings FOR EACH ROW BEGIN
    SELECT CASE WHEN NOT EXISTS (
        SELECT 1
        FROM approval_decision_receipts r
        JOIN approvals a ON a.id=r.approval_id
        JOIN actor_bindings b ON b.id=NEW.actor_binding_id
        JOIN credential_challenge_receipts cr ON cr.id=NEW.challenge_receipt_id
        JOIN credential_challenges c ON c.id=cr.challenge_id
        WHERE r.id=NEW.approval_receipt_id
          AND r.actor_binding_digest=b.binding_digest
          AND cr.actor_binding_id=b.id
          AND c.operation_digest=r.operation_digest
          AND c.purpose=CASE a.approval_type
            WHEN 'plan' THEN 'plan.approval'
            WHEN 'final_commit' THEN 'final_commit.approval'
            WHEN 'policy_exception' THEN 'policy_exception.approval'
            ELSE 'policy_exception.approval' END
          AND b.revoked_at IS NULL AND b.expires_at>NEW.created_at
          AND cr.verified_at<=NEW.created_at
    ) THEN RAISE(ABORT,'approval actor proof does not match receipt, challenge, purpose, or current session') END;
END;
CREATE TRIGGER approval_actor_proof_update_forbidden BEFORE UPDATE ON approval_actor_proof_bindings FOR EACH ROW BEGIN SELECT RAISE(ABORT,'approval actor proof bindings are immutable'); END;
CREATE TRIGGER approval_actor_proof_delete_forbidden BEFORE DELETE ON approval_actor_proof_bindings FOR EACH ROW BEGIN SELECT RAISE(ABORT,'approval actor proof bindings are retained'); END;

CREATE TRIGGER approvals_v6_resolution_requires_actor_proof BEFORE UPDATE OF status ON approvals FOR EACH ROW
WHEN OLD.status='pending' AND NEW.status='granted' BEGIN
    SELECT CASE WHEN NOT EXISTS (
        SELECT 1 FROM approval_decision_receipts r JOIN approval_actor_proof_bindings p ON p.approval_receipt_id=r.id
        WHERE r.approval_id=OLD.id
    ) THEN RAISE(ABORT,'granted approval requires current actor and credential challenge proof') END;
END;

CREATE TABLE ref_promotion_receipts (
    id TEXT PRIMARY KEY,
    task_id TEXT NOT NULL UNIQUE REFERENCES tasks(id) ON DELETE RESTRICT,
    candidate_id TEXT NOT NULL UNIQUE REFERENCES final_commit_candidates(id) ON DELETE RESTRICT,
    approval_consumption_id TEXT NOT NULL UNIQUE REFERENCES approval_effect_consumptions(id) ON DELETE RESTRICT,
    repository_identity_digest TEXT NOT NULL CHECK (length(repository_identity_digest)=71 AND substr(repository_identity_digest,1,7)='sha256:' AND substr(repository_identity_digest,8) NOT GLOB '*[^0-9a-f]*'),
    expected_ref TEXT NOT NULL,
    expected_old_oid TEXT NOT NULL CHECK (length(expected_old_oid) IN (40,64) AND expected_old_oid NOT GLOB '*[^0-9a-f]*'),
    promoted_commit_oid TEXT NOT NULL CHECK (length(promoted_commit_oid) IN (40,64) AND promoted_commit_oid NOT GLOB '*[^0-9a-f]*'),
    receipt_artifact_id TEXT NOT NULL UNIQUE REFERENCES artifacts(id) ON DELETE RESTRICT,
    succeeded_at TEXT NOT NULL,
    receipt_digest TEXT NOT NULL UNIQUE CHECK (length(receipt_digest)=71 AND substr(receipt_digest,1,7)='sha256:' AND substr(receipt_digest,8) NOT GLOB '*[^0-9a-f]*')
) STRICT;

CREATE TRIGGER ref_promotion_exact_tuple BEFORE INSERT ON ref_promotion_receipts FOR EACH ROW BEGIN
    SELECT CASE WHEN NOT EXISTS (
        SELECT 1
        FROM final_commit_candidates c
        JOIN approval_effect_consumptions e ON e.id=NEW.approval_consumption_id
        JOIN approval_decision_receipts r ON r.id=e.approval_receipt_id
        JOIN approvals ap ON ap.id=r.approval_id
        JOIN tasks t ON t.id=NEW.task_id
        JOIN artifacts a ON a.id=NEW.receipt_artifact_id
        WHERE c.id=NEW.candidate_id AND c.task_id=NEW.task_id
          AND e.operation_intent_id=c.operation_intent_id
          AND e.repository_identity_digest=NEW.repository_identity_digest
          AND e.expected_ref=NEW.expected_ref
          AND e.expected_old_oid=NEW.expected_old_oid
          AND e.candidate_commit_oid=NEW.promoted_commit_oid
          AND c.repository_identity_digest=NEW.repository_identity_digest
          AND c.expected_ref=NEW.expected_ref
          AND c.expected_old_oid=NEW.expected_old_oid
          AND c.candidate_commit_oid=NEW.promoted_commit_oid
          AND r.decision='granted' AND ap.status='granted'
          AND a.project_id=t.project_id AND (a.task_id IS NULL OR a.task_id=NEW.task_id)
          AND a.artifact_type='ref_promotion_receipt' AND a.content_hash=NEW.receipt_digest
    ) THEN RAISE(ABORT,'ref promotion receipt must bind the exact approved candidate tuple and CAS evidence') END;
END;
CREATE TRIGGER ref_promotion_update_forbidden BEFORE UPDATE ON ref_promotion_receipts FOR EACH ROW BEGIN SELECT RAISE(ABORT,'ref promotion receipts are immutable'); END;
CREATE TRIGGER ref_promotion_delete_forbidden BEFORE DELETE ON ref_promotion_receipts FOR EACH ROW BEGIN SELECT RAISE(ABORT,'ref promotion receipts are retained'); END;

CREATE TABLE task_workflow_authority (
    task_id TEXT PRIMARY KEY REFERENCES tasks(id) ON DELETE RESTRICT,
    workflow_profile TEXT NOT NULL CHECK (workflow_profile IN ('Quick','Standard','HighAssurance','ReadOnlyResearch')),
    outcome_mode TEXT NOT NULL CHECK (outcome_mode IN ('ReadOnlyDeliverable','WorkspaceChange','LocalCommit')),
    phase TEXT NOT NULL CHECK (phase IN ('Intake','ContextBuild','ParallelAnalysis','CrossReview','PrePlanVerification','Synthesis','FinalObjection','AwaitingPlanApproval','Implementation','Verification','Repair','FinalReview','AwaitingDeliverableApproval','AwaitingWorkspaceApproval','AwaitingCommitApproval','RefPromotion','WorkspaceDirty','Completed','Cancelled','Failed')),
    selected_by_kind TEXT NOT NULL CHECK (selected_by_kind IN ('core','system','user')),
    selected_by_actor_binding_id TEXT REFERENCES actor_bindings(id) ON DELETE RESTRICT,
    selection_policy_digest TEXT NOT NULL CHECK (length(selection_policy_digest)=71 AND substr(selection_policy_digest,1,7)='sha256:' AND substr(selection_policy_digest,8) NOT GLOB '*[^0-9a-f]*'),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    completed_at TEXT,
    CHECK (workflow_profile<>'ReadOnlyResearch' OR outcome_mode='ReadOnlyDeliverable'),
    CHECK (phase NOT IN ('Completed','Cancelled','Failed') OR completed_at IS NOT NULL),
    CHECK (selected_by_kind<>'user' OR selected_by_actor_binding_id IS NOT NULL)
) STRICT;

CREATE TRIGGER task_workflow_insert_guard BEFORE INSERT ON task_workflow_authority FOR EACH ROW BEGIN
    SELECT CASE WHEN NEW.phase<>'Intake' OR NEW.completed_at IS NOT NULL THEN RAISE(ABORT,'new workflow authority must start at Intake') END;
    SELECT CASE WHEN NEW.selected_by_actor_binding_id IS NOT NULL AND NOT EXISTS (
      SELECT 1 FROM actor_bindings b WHERE b.id=NEW.selected_by_actor_binding_id AND b.revoked_at IS NULL AND b.expires_at>NEW.created_at
    ) THEN RAISE(ABORT,'workflow selection actor binding is not current') END;
END;
CREATE TRIGGER task_workflow_phase_transition BEFORE UPDATE OF phase,updated_at,completed_at ON task_workflow_authority FOR EACH ROW BEGIN
    SELECT CASE WHEN NEW.updated_at<=OLD.updated_at THEN RAISE(ABORT,'workflow update time must increase') END;
    SELECT CASE WHEN NOT (
      NEW.phase=OLD.phase
      OR (OLD.phase='Intake' AND NEW.phase='ContextBuild')
      OR (OLD.phase='ContextBuild' AND ((OLD.workflow_profile='Quick' AND NEW.phase='PrePlanVerification') OR (OLD.workflow_profile<>'Quick' AND NEW.phase='ParallelAnalysis')))
      OR (OLD.phase='ParallelAnalysis' AND NEW.phase='CrossReview')
      OR (OLD.phase='CrossReview' AND NEW.phase='PrePlanVerification')
      OR (OLD.phase='PrePlanVerification' AND NEW.phase='Synthesis')
      OR (OLD.phase='Synthesis' AND NEW.phase='FinalObjection')
      OR (OLD.phase='FinalObjection' AND NEW.phase IN ('CrossReview','PrePlanVerification'))
      OR (OLD.phase='FinalObjection' AND OLD.outcome_mode='ReadOnlyDeliverable' AND NEW.phase='AwaitingDeliverableApproval')
      OR (OLD.phase='FinalObjection' AND OLD.outcome_mode IN ('WorkspaceChange','LocalCommit') AND NEW.phase='AwaitingPlanApproval')
      OR (OLD.phase='AwaitingDeliverableApproval' AND NEW.phase IN ('Synthesis','Completed'))
      OR (OLD.phase='AwaitingPlanApproval' AND NEW.phase IN ('Synthesis','Implementation'))
      OR (OLD.phase='Implementation' AND NEW.phase IN ('Verification','WorkspaceDirty'))
      OR (OLD.phase='Verification' AND NEW.phase IN ('Repair','FinalReview','WorkspaceDirty'))
      OR (OLD.phase='Repair' AND NEW.phase IN ('Verification','WorkspaceDirty'))
      OR (OLD.phase='FinalReview' AND NEW.phase='Repair')
      OR (OLD.phase='FinalReview' AND OLD.outcome_mode='WorkspaceChange' AND NEW.phase='AwaitingWorkspaceApproval')
      OR (OLD.phase='FinalReview' AND OLD.outcome_mode='LocalCommit' AND NEW.phase='AwaitingCommitApproval')
      OR (OLD.phase='AwaitingWorkspaceApproval' AND NEW.phase IN ('Repair','Completed','WorkspaceDirty'))
      OR (OLD.phase='AwaitingCommitApproval' AND NEW.phase IN ('Repair','RefPromotion','WorkspaceDirty'))
      OR (OLD.phase='RefPromotion' AND NEW.phase IN ('Completed','WorkspaceDirty'))
      OR (OLD.phase='WorkspaceDirty' AND NEW.phase IN ('Repair','FinalReview','Cancelled'))
      OR (OLD.phase NOT IN ('Completed','Cancelled','Failed') AND NEW.phase IN ('Cancelled','Failed'))
    ) THEN RAISE(ABORT,'invalid v4.2 workflow phase transition') END;
    SELECT CASE WHEN OLD.phase='AwaitingDeliverableApproval' AND NEW.phase='Completed' AND NOT EXISTS (
      SELECT 1 FROM task_acceptance_receipts r WHERE r.task_id=OLD.task_id AND r.acceptance_kind='deliverable'
    ) THEN RAISE(ABORT,'read-only completion requires a deliverable acceptance receipt') END;
    SELECT CASE WHEN OLD.phase='AwaitingWorkspaceApproval' AND NEW.phase='Completed' AND NOT EXISTS (
      SELECT 1 FROM task_acceptance_receipts r WHERE r.task_id=OLD.task_id AND r.acceptance_kind='workspace'
    ) THEN RAISE(ABORT,'workspace completion requires a workspace acceptance receipt') END;
    SELECT CASE WHEN OLD.phase='RefPromotion' AND NEW.phase='Completed' AND NOT EXISTS (
      SELECT 1 FROM ref_promotion_receipts r WHERE r.task_id=OLD.task_id
    ) THEN RAISE(ABORT,'local commit completion requires successful ref promotion evidence') END;
    SELECT CASE WHEN NEW.phase IN ('Completed','Cancelled','Failed') AND NEW.completed_at IS NULL THEN RAISE(ABORT,'terminal workflow requires completion time') END;
    SELECT CASE WHEN NEW.phase NOT IN ('Completed','Cancelled','Failed') AND NEW.completed_at IS NOT NULL THEN RAISE(ABORT,'nonterminal workflow cannot contain completion time') END;
    SELECT CASE WHEN OLD.completed_at IS NOT NULL AND NEW.completed_at IS NOT OLD.completed_at THEN RAISE(ABORT,'workflow completion time is set-once') END;
END;
CREATE TRIGGER task_workflow_selection_immutable BEFORE UPDATE OF workflow_profile,outcome_mode,selected_by_kind,selected_by_actor_binding_id,selection_policy_digest,created_at ON task_workflow_authority FOR EACH ROW BEGIN SELECT RAISE(ABORT,'workflow profile and outcome selection are immutable'); END;
CREATE TRIGGER task_workflow_terminal_irreversible BEFORE UPDATE OF phase ON task_workflow_authority FOR EACH ROW WHEN OLD.phase IN ('Completed','Cancelled','Failed') AND NEW.phase<>OLD.phase BEGIN SELECT RAISE(ABORT,'terminal workflow phase is irreversible'); END;
CREATE TRIGGER task_workflow_delete_forbidden BEFORE DELETE ON task_workflow_authority FOR EACH ROW BEGIN SELECT RAISE(ABORT,'task workflow authority is retained'); END;

CREATE TABLE task_acceptance_receipts (
    id TEXT PRIMARY KEY,
    task_id TEXT NOT NULL REFERENCES tasks(id) ON DELETE RESTRICT,
    acceptance_kind TEXT NOT NULL CHECK (acceptance_kind IN ('deliverable','workspace')),
    operation_digest TEXT NOT NULL CHECK (length(operation_digest)=71 AND substr(operation_digest,1,7)='sha256:' AND substr(operation_digest,8) NOT GLOB '*[^0-9a-f]*'),
    accepted_artifact_id TEXT NOT NULL REFERENCES artifacts(id) ON DELETE RESTRICT,
    actor_binding_id TEXT NOT NULL REFERENCES actor_bindings(id) ON DELETE RESTRICT,
    challenge_receipt_id TEXT NOT NULL UNIQUE REFERENCES credential_challenge_receipts(id) ON DELETE RESTRICT,
    decided_at TEXT NOT NULL,
    receipt_digest TEXT NOT NULL UNIQUE CHECK (length(receipt_digest)=71 AND substr(receipt_digest,1,7)='sha256:' AND substr(receipt_digest,8) NOT GLOB '*[^0-9a-f]*')
) STRICT;

CREATE TRIGGER task_acceptance_scope BEFORE INSERT ON task_acceptance_receipts FOR EACH ROW BEGIN
    SELECT CASE WHEN NOT EXISTS (
        SELECT 1 FROM tasks t JOIN artifacts a ON a.id=NEW.accepted_artifact_id
        JOIN actor_bindings b ON b.id=NEW.actor_binding_id
        JOIN credential_challenge_receipts cr ON cr.id=NEW.challenge_receipt_id
        JOIN credential_challenges c ON c.id=cr.challenge_id
        WHERE t.id=NEW.task_id AND a.project_id=t.project_id AND (a.task_id IS NULL OR a.task_id=NEW.task_id)
          AND cr.actor_binding_id=b.id AND b.revoked_at IS NULL AND b.expires_at>NEW.decided_at
          AND c.operation_digest=NEW.operation_digest
          AND c.purpose=CASE NEW.acceptance_kind WHEN 'deliverable' THEN 'deliverable.approval' ELSE 'workspace.approval' END
          AND cr.verified_at<=NEW.decided_at
    ) THEN RAISE(ABORT,'task acceptance requires exact artifact and current actor challenge proof') END;
END;
CREATE TRIGGER task_acceptance_update_forbidden BEFORE UPDATE ON task_acceptance_receipts FOR EACH ROW BEGIN SELECT RAISE(ABORT,'task acceptance receipts are immutable'); END;
CREATE TRIGGER task_acceptance_delete_forbidden BEFORE DELETE ON task_acceptance_receipts FOR EACH ROW BEGIN SELECT RAISE(ABORT,'task acceptance receipts are retained'); END;

CREATE TABLE final_commit_verification_receipts (
    id TEXT PRIMARY KEY,
    candidate_id TEXT NOT NULL UNIQUE REFERENCES final_commit_candidates(id) ON DELETE RESTRICT,
    task_id TEXT NOT NULL REFERENCES tasks(id) ON DELETE RESTRICT,
    candidate_tree_oid TEXT NOT NULL CHECK (length(candidate_tree_oid) IN (40,64) AND candidate_tree_oid NOT GLOB '*[^0-9a-f]*'),
    candidate_commit_oid TEXT NOT NULL CHECK (length(candidate_commit_oid) IN (40,64) AND candidate_commit_oid NOT GLOB '*[^0-9a-f]*'),
    verification_set_digest TEXT NOT NULL CHECK (length(verification_set_digest)=71 AND substr(verification_set_digest,1,7)='sha256:' AND substr(verification_set_digest,8) NOT GLOB '*[^0-9a-f]*'),
    verification_artifact_id TEXT NOT NULL REFERENCES artifacts(id) ON DELETE RESTRICT,
    verified_at TEXT NOT NULL,
    receipt_digest TEXT NOT NULL UNIQUE CHECK (length(receipt_digest)=71 AND substr(receipt_digest,1,7)='sha256:' AND substr(receipt_digest,8) NOT GLOB '*[^0-9a-f]*')
) STRICT;

CREATE TRIGGER final_commit_verification_scope BEFORE INSERT ON final_commit_verification_receipts FOR EACH ROW BEGIN
    SELECT CASE WHEN NOT EXISTS (
        SELECT 1 FROM final_commit_candidates c JOIN tasks t ON t.id=c.task_id JOIN artifacts a ON a.id=NEW.verification_artifact_id
        WHERE c.id=NEW.candidate_id AND c.task_id=NEW.task_id
          AND c.candidate_tree_oid=NEW.candidate_tree_oid AND c.candidate_commit_oid=NEW.candidate_commit_oid
          AND c.verification_set_digest=NEW.verification_set_digest
          AND a.project_id=t.project_id AND (a.task_id IS NULL OR a.task_id=NEW.task_id)
    ) THEN RAISE(ABORT,'final commit verification must bind the exact immutable candidate tuple') END;
END;
CREATE TRIGGER final_commit_verification_update_forbidden BEFORE UPDATE ON final_commit_verification_receipts FOR EACH ROW BEGIN SELECT RAISE(ABORT,'final commit verification receipts are immutable'); END;
CREATE TRIGGER final_commit_verification_delete_forbidden BEFORE DELETE ON final_commit_verification_receipts FOR EACH ROW BEGIN SELECT RAISE(ABORT,'final commit verification receipts are retained'); END;

CREATE TRIGGER final_commit_approval_v6_requires_verification BEFORE INSERT ON approvals FOR EACH ROW WHEN NEW.approval_type='final_commit' BEGIN
    SELECT CASE WHEN NOT EXISTS (
        SELECT 1 FROM final_commit_candidates c JOIN final_commit_verification_receipts v ON v.candidate_id=c.id
        WHERE c.operation_intent_id=NEW.operation_intent_id AND c.task_id=NEW.task_id
    ) THEN RAISE(ABORT,'final commit approval requires a pre-created and verified candidate commit OID') END;
END;

CREATE TABLE task_completion_packages (
    id TEXT PRIMARY KEY,
    task_id TEXT NOT NULL UNIQUE REFERENCES tasks(id) ON DELETE RESTRICT,
    outcome_mode TEXT NOT NULL CHECK (outcome_mode IN ('ReadOnlyDeliverable','WorkspaceChange','LocalCommit')),
    deliverable_artifact_id TEXT REFERENCES artifacts(id) ON DELETE RESTRICT,
    evidence_set_artifact_id TEXT NOT NULL REFERENCES artifacts(id) ON DELETE RESTRICT,
    unresolved_objections_artifact_id TEXT NOT NULL REFERENCES artifacts(id) ON DELETE RESTRICT,
    evaluator_receipt_artifact_id TEXT NOT NULL REFERENCES artifacts(id) ON DELETE RESTRICT,
    acceptance_receipt_id TEXT REFERENCES task_acceptance_receipts(id) ON DELETE RESTRICT,
    final_approval_receipt_id TEXT REFERENCES approval_decision_receipts(id) ON DELETE RESTRICT,
    candidate_tree_oid TEXT CHECK (candidate_tree_oid IS NULL OR (length(candidate_tree_oid) IN (40,64) AND candidate_tree_oid NOT GLOB '*[^0-9a-f]*')),
    candidate_commit_oid TEXT CHECK (candidate_commit_oid IS NULL OR (length(candidate_commit_oid) IN (40,64) AND candidate_commit_oid NOT GLOB '*[^0-9a-f]*')),
    ref_promotion_receipt_artifact_id TEXT REFERENCES artifacts(id) ON DELETE RESTRICT,
    created_at TEXT NOT NULL,
    CHECK (
      (outcome_mode='ReadOnlyDeliverable' AND deliverable_artifact_id IS NOT NULL AND acceptance_receipt_id IS NOT NULL AND final_approval_receipt_id IS NULL AND candidate_tree_oid IS NULL AND candidate_commit_oid IS NULL AND ref_promotion_receipt_artifact_id IS NULL)
      OR (outcome_mode='WorkspaceChange' AND deliverable_artifact_id IS NULL AND acceptance_receipt_id IS NOT NULL AND candidate_tree_oid IS NOT NULL AND candidate_commit_oid IS NOT NULL AND final_approval_receipt_id IS NULL AND ref_promotion_receipt_artifact_id IS NULL)
      OR (outcome_mode='LocalCommit' AND deliverable_artifact_id IS NULL AND acceptance_receipt_id IS NULL AND final_approval_receipt_id IS NOT NULL AND candidate_tree_oid IS NOT NULL AND candidate_commit_oid IS NOT NULL AND ref_promotion_receipt_artifact_id IS NOT NULL)
    )
) STRICT;

CREATE TRIGGER task_completion_scope BEFORE INSERT ON task_completion_packages FOR EACH ROW BEGIN
    SELECT CASE WHEN NOT EXISTS (
        SELECT 1 FROM task_workflow_authority w JOIN tasks t ON t.id=w.task_id
        JOIN artifacts e ON e.id=NEW.evidence_set_artifact_id
        JOIN artifacts o ON o.id=NEW.unresolved_objections_artifact_id
        JOIN artifacts v ON v.id=NEW.evaluator_receipt_artifact_id
        WHERE w.task_id=NEW.task_id AND w.phase='Completed' AND w.outcome_mode=NEW.outcome_mode
          AND e.project_id=t.project_id AND o.project_id=t.project_id AND v.project_id=t.project_id
    ) THEN RAISE(ABORT,'completion package requires completed workflow and exact evidence scope') END;
    SELECT CASE WHEN NEW.outcome_mode='ReadOnlyDeliverable' AND NOT EXISTS (
        SELECT 1 FROM task_acceptance_receipts r
        WHERE r.id=NEW.acceptance_receipt_id AND r.task_id=NEW.task_id
          AND r.acceptance_kind='deliverable' AND r.accepted_artifact_id=NEW.deliverable_artifact_id
    ) THEN RAISE(ABORT,'completion package does not match the exact deliverable acceptance') END;
    SELECT CASE WHEN NEW.outcome_mode='WorkspaceChange' AND NOT EXISTS (
        SELECT 1 FROM task_acceptance_receipts r
        WHERE r.id=NEW.acceptance_receipt_id AND r.task_id=NEW.task_id AND r.acceptance_kind='workspace'
    ) THEN RAISE(ABORT,'completion package does not match a workspace acceptance') END;
    SELECT CASE WHEN NEW.final_approval_receipt_id IS NOT NULL AND NOT EXISTS (
        SELECT 1 FROM approval_decision_receipts r JOIN approvals a ON a.id=r.approval_id JOIN final_commit_candidates c ON c.operation_intent_id=r.operation_intent_id
        WHERE r.id=NEW.final_approval_receipt_id AND r.task_id=NEW.task_id AND r.decision='granted' AND a.approval_type='final_commit' AND c.candidate_commit_oid=NEW.candidate_commit_oid AND c.candidate_tree_oid=NEW.candidate_tree_oid
    ) THEN RAISE(ABORT,'completion final approval does not bind the exact candidate OID') END;
    SELECT CASE WHEN NEW.outcome_mode='LocalCommit' AND NOT EXISTS (
        SELECT 1 FROM ref_promotion_receipts rp
        JOIN final_commit_candidates c ON c.id=rp.candidate_id
        WHERE rp.task_id=NEW.task_id
          AND rp.receipt_artifact_id=NEW.ref_promotion_receipt_artifact_id
          AND c.candidate_tree_oid=NEW.candidate_tree_oid
          AND rp.promoted_commit_oid=NEW.candidate_commit_oid
    ) THEN RAISE(ABORT,'completion package requires exact successful ref promotion evidence') END;
END;
CREATE TRIGGER task_completion_update_forbidden BEFORE UPDATE ON task_completion_packages FOR EACH ROW BEGIN SELECT RAISE(ABORT,'task completion packages are immutable'); END;
CREATE TRIGGER task_completion_delete_forbidden BEFORE DELETE ON task_completion_packages FOR EACH ROW BEGIN SELECT RAISE(ABORT,'task completion packages are retained'); END;

CREATE TABLE memory_wire_contracts_v2 (
    memory_id TEXT PRIMARY KEY REFERENCES memory_records(id) ON DELETE RESTRICT,
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE RESTRICT,
    logical_key TEXT NOT NULL,
    applicability_json TEXT NOT NULL CHECK (json_valid(applicability_json) AND json_type(applicability_json)='object' AND json_type(applicability_json,'$.subject') IS NULL),
    wire_schema_version TEXT NOT NULL CHECK (wire_schema_version='cognitive-memory.v4'),
    created_at TEXT NOT NULL
) STRICT;

CREATE TABLE memory_subject_bindings (
    memory_id TEXT PRIMARY KEY REFERENCES memory_records(id) ON DELETE RESTRICT,
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE RESTRICT,
    subject_kind TEXT NOT NULL CHECK (subject_kind IN ('user','project','workspace')),
    subject_id TEXT NOT NULL CHECK (length(subject_id)>0),
    created_at TEXT NOT NULL
) STRICT;

CREATE TRIGGER memory_wire_contract_scope BEFORE INSERT ON memory_wire_contracts_v2 FOR EACH ROW BEGIN
    SELECT CASE WHEN NOT EXISTS (SELECT 1 FROM memory_records m WHERE m.id=NEW.memory_id AND m.project_id=NEW.project_id AND m.logical_key=NEW.logical_key AND m.status='candidate') THEN RAISE(ABORT,'memory wire contract must match a candidate memory and logical key') END;
END;
CREATE TRIGGER memory_subject_binding_scope BEFORE INSERT ON memory_subject_bindings FOR EACH ROW BEGIN
    SELECT CASE WHEN NOT EXISTS (SELECT 1 FROM memory_records m WHERE m.id=NEW.memory_id AND m.project_id=NEW.project_id AND m.memory_type='preference' AND m.status='candidate') THEN RAISE(ABORT,'memory subject binding requires a candidate preference memory') END;
END;
CREATE TRIGGER memory_v6_verified_requires_wire_contract BEFORE UPDATE OF status ON memory_records FOR EACH ROW WHEN OLD.status='candidate' AND NEW.status='verified' BEGIN
    SELECT CASE WHEN NOT EXISTS (SELECT 1 FROM memory_wire_contracts_v2 w WHERE w.memory_id=OLD.id AND w.project_id=OLD.project_id AND w.logical_key=OLD.logical_key) THEN RAISE(ABORT,'verified memory requires canonical cognitive-memory.v4 wire binding') END;
    SELECT CASE WHEN OLD.memory_type='preference' AND NOT EXISTS (SELECT 1 FROM memory_subject_bindings s WHERE s.memory_id=OLD.id AND s.project_id=OLD.project_id) THEN RAISE(ABORT,'verified preference memory requires explicit subject binding') END;
END;
CREATE TRIGGER memory_wire_contract_update_forbidden BEFORE UPDATE ON memory_wire_contracts_v2 FOR EACH ROW BEGIN SELECT RAISE(ABORT,'memory wire contracts are immutable'); END;
CREATE TRIGGER memory_wire_contract_delete_forbidden BEFORE DELETE ON memory_wire_contracts_v2 FOR EACH ROW BEGIN SELECT RAISE(ABORT,'memory wire contracts are retained'); END;
CREATE TRIGGER memory_subject_binding_update_forbidden BEFORE UPDATE ON memory_subject_bindings FOR EACH ROW BEGIN SELECT RAISE(ABORT,'memory subject bindings are immutable'); END;
CREATE TRIGGER memory_subject_binding_delete_forbidden BEFORE DELETE ON memory_subject_bindings FOR EACH ROW BEGIN SELECT RAISE(ABORT,'memory subject bindings are retained'); END;

CREATE TABLE benchmark_suite_versions (
    row_id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE RESTRICT,
    logical_suite_id TEXT NOT NULL,
    version INTEGER NOT NULL CHECK (version>=1),
    manifest_artifact_id TEXT NOT NULL REFERENCES artifacts(id) ON DELETE RESTRICT,
    manifest_digest TEXT NOT NULL CHECK (length(manifest_digest)=71 AND substr(manifest_digest,1,7)='sha256:' AND substr(manifest_digest,8) NOT GLOB '*[^0-9a-f]*'),
    created_at TEXT NOT NULL,
    UNIQUE(project_id,logical_suite_id,version)
) STRICT;

CREATE TABLE benchmark_case_versions (
    row_id TEXT PRIMARY KEY,
    suite_row_id TEXT NOT NULL REFERENCES benchmark_suite_versions(row_id) ON DELETE RESTRICT,
    logical_case_id TEXT NOT NULL,
    case_version INTEGER NOT NULL CHECK (case_version>=1),
    case_artifact_id TEXT NOT NULL REFERENCES artifacts(id) ON DELETE RESTRICT,
    case_artifact_digest TEXT NOT NULL CHECK (length(case_artifact_digest)=71 AND substr(case_artifact_digest,1,7)='sha256:' AND substr(case_artifact_digest,8) NOT GLOB '*[^0-9a-f]*'),
    repository_revision TEXT NOT NULL,
    fixture_manifest_digest TEXT NOT NULL CHECK (length(fixture_manifest_digest)=71 AND substr(fixture_manifest_digest,1,7)='sha256:' AND substr(fixture_manifest_digest,8) NOT GLOB '*[^0-9a-f]*'),
    objective_digest TEXT NOT NULL CHECK (length(objective_digest)=71 AND substr(objective_digest,1,7)='sha256:' AND substr(objective_digest,8) NOT GLOB '*[^0-9a-f]*'),
    budget_profile_digest TEXT NOT NULL CHECK (length(budget_profile_digest)=71 AND substr(budget_profile_digest,1,7)='sha256:' AND substr(budget_profile_digest,8) NOT GLOB '*[^0-9a-f]*'),
    policy_digest TEXT NOT NULL CHECK (length(policy_digest)=71 AND substr(policy_digest,1,7)='sha256:' AND substr(policy_digest,8) NOT GLOB '*[^0-9a-f]*'),
    tool_permissions_digest TEXT NOT NULL CHECK (length(tool_permissions_digest)=71 AND substr(tool_permissions_digest,1,7)='sha256:' AND substr(tool_permissions_digest,8) NOT GLOB '*[^0-9a-f]*'),
    acceptance_rules_digest TEXT NOT NULL CHECK (length(acceptance_rules_digest)=71 AND substr(acceptance_rules_digest,1,7)='sha256:' AND substr(acceptance_rules_digest,8) NOT GLOB '*[^0-9a-f]*'),
    created_at TEXT NOT NULL,
    UNIQUE(suite_row_id,logical_case_id,case_version)
) STRICT;

CREATE TABLE benchmark_run_receipts_v2 (
    id TEXT PRIMARY KEY,
    case_row_id TEXT NOT NULL REFERENCES benchmark_case_versions(row_id) ON DELETE RESTRICT,
    task_id TEXT NOT NULL REFERENCES tasks(id) ON DELETE RESTRICT,
    arm TEXT NOT NULL CHECK (arm IN ('control_no_memory','compaction_only','evidence_retrieval','evidence_plus_experience')),
    controlled_configuration_digest TEXT NOT NULL CHECK (length(controlled_configuration_digest)=71 AND substr(controlled_configuration_digest,1,7)='sha256:' AND substr(controlled_configuration_digest,8) NOT GLOB '*[^0-9a-f]*'),
    treatment_configuration_json TEXT NOT NULL CHECK (
      json_valid(treatment_configuration_json) AND json_type(treatment_configuration_json)='object'
      AND json_type(treatment_configuration_json,'$.retrievalPipeline')='text'
      AND json_type(treatment_configuration_json,'$.contextCompiler')='text'
      AND json_type(treatment_configuration_json,'$.memoryPolicy')='text'
    ),
    treatment_configuration_digest TEXT NOT NULL CHECK (length(treatment_configuration_digest)=71 AND substr(treatment_configuration_digest,1,7)='sha256:' AND substr(treatment_configuration_digest,8) NOT GLOB '*[^0-9a-f]*'),
    actual_repository_revision TEXT NOT NULL,
    fixture_manifest_digest TEXT NOT NULL CHECK (length(fixture_manifest_digest)=71 AND substr(fixture_manifest_digest,1,7)='sha256:' AND substr(fixture_manifest_digest,8) NOT GLOB '*[^0-9a-f]*'),
    objective_digest TEXT NOT NULL CHECK (length(objective_digest)=71 AND substr(objective_digest,1,7)='sha256:' AND substr(objective_digest,8) NOT GLOB '*[^0-9a-f]*'),
    budget_profile_digest TEXT NOT NULL CHECK (length(budget_profile_digest)=71 AND substr(budget_profile_digest,1,7)='sha256:' AND substr(budget_profile_digest,8) NOT GLOB '*[^0-9a-f]*'),
    actual_usage_digest TEXT NOT NULL CHECK (length(actual_usage_digest)=71 AND substr(actual_usage_digest,1,7)='sha256:' AND substr(actual_usage_digest,8) NOT GLOB '*[^0-9a-f]*'),
    policy_digest TEXT NOT NULL CHECK (length(policy_digest)=71 AND substr(policy_digest,1,7)='sha256:' AND substr(policy_digest,8) NOT GLOB '*[^0-9a-f]*'),
    tool_permissions_digest TEXT NOT NULL CHECK (length(tool_permissions_digest)=71 AND substr(tool_permissions_digest,1,7)='sha256:' AND substr(tool_permissions_digest,8) NOT GLOB '*[^0-9a-f]*'),
    model_digest TEXT NOT NULL CHECK (length(model_digest)=71 AND substr(model_digest,1,7)='sha256:' AND substr(model_digest,8) NOT GLOB '*[^0-9a-f]*'),
    prompt_digest TEXT NOT NULL CHECK (length(prompt_digest)=71 AND substr(prompt_digest,1,7)='sha256:' AND substr(prompt_digest,8) NOT GLOB '*[^0-9a-f]*'),
    evaluator_digest TEXT NOT NULL CHECK (length(evaluator_digest)=71 AND substr(evaluator_digest,1,7)='sha256:' AND substr(evaluator_digest,8) NOT GLOB '*[^0-9a-f]*'),
    acceptance_rules_digest TEXT NOT NULL CHECK (length(acceptance_rules_digest)=71 AND substr(acceptance_rules_digest,1,7)='sha256:' AND substr(acceptance_rules_digest,8) NOT GLOB '*[^0-9a-f]*'),
    result_artifact_id TEXT NOT NULL REFERENCES artifacts(id) ON DELETE RESTRICT,
    status TEXT NOT NULL CHECK (status IN ('completed','failed','indeterminate')),
    started_at TEXT NOT NULL,
    completed_at TEXT NOT NULL,
    UNIQUE(case_row_id,task_id,arm)
) STRICT;

CREATE TABLE benchmark_comparison_receipts_v2 (
    id TEXT PRIMARY KEY,
    baseline_run_id TEXT NOT NULL REFERENCES benchmark_run_receipts_v2(id) ON DELETE RESTRICT,
    candidate_run_id TEXT NOT NULL REFERENCES benchmark_run_receipts_v2(id) ON DELETE RESTRICT,
    comparison_artifact_id TEXT NOT NULL REFERENCES artifacts(id) ON DELETE RESTRICT,
    declared_treatment_dimensions_json TEXT NOT NULL CHECK (json_valid(declared_treatment_dimensions_json) AND json_type(declared_treatment_dimensions_json)='array' AND json_array_length(declared_treatment_dimensions_json)>=1),
    result TEXT NOT NULL CHECK (result IN ('improved','equivalent','regressed','invalid')),
    created_at TEXT NOT NULL,
    CHECK (baseline_run_id<>candidate_run_id),
    UNIQUE(baseline_run_id,candidate_run_id)
) STRICT;

CREATE TABLE quality_release_decisions_v2 (
    id TEXT PRIMARY KEY,
    comparison_id TEXT NOT NULL REFERENCES benchmark_comparison_receipts_v2(id) ON DELETE RESTRICT,
    decision_artifact_id TEXT NOT NULL REFERENCES artifacts(id) ON DELETE RESTRICT,
    decision TEXT NOT NULL CHECK (decision IN ('allow_internal_experiment','allow_feature_enablement','allow_quality_claim','deny')),
    actor_binding_id TEXT NOT NULL REFERENCES actor_bindings(id) ON DELETE RESTRICT,
    decided_at TEXT NOT NULL,
    decision_digest TEXT NOT NULL UNIQUE CHECK (length(decision_digest)=71 AND substr(decision_digest,1,7)='sha256:' AND substr(decision_digest,8) NOT GLOB '*[^0-9a-f]*')
) STRICT;

CREATE TRIGGER benchmark_suite_v6_scope BEFORE INSERT ON benchmark_suite_versions FOR EACH ROW BEGIN
    SELECT CASE WHEN NOT EXISTS (SELECT 1 FROM artifacts a WHERE a.id=NEW.manifest_artifact_id AND a.project_id=NEW.project_id AND a.content_hash=NEW.manifest_digest) THEN RAISE(ABORT,'benchmark suite manifest scope or digest is incoherent') END;
END;
CREATE TRIGGER benchmark_case_v6_scope BEFORE INSERT ON benchmark_case_versions FOR EACH ROW BEGIN
    SELECT CASE WHEN NOT EXISTS (
      SELECT 1 FROM benchmark_suite_versions s JOIN artifacts a ON a.id=NEW.case_artifact_id
      WHERE s.row_id=NEW.suite_row_id AND a.project_id=s.project_id AND a.content_hash=NEW.case_artifact_digest
    ) THEN RAISE(ABORT,'benchmark case artifact scope or digest is incoherent') END;
END;
CREATE TRIGGER benchmark_run_v6_exact_binding BEFORE INSERT ON benchmark_run_receipts_v2 FOR EACH ROW BEGIN
    SELECT CASE WHEN EXISTS (SELECT 1 FROM json_each(NEW.treatment_configuration_json) WHERE key NOT IN ('retrievalPipeline','contextCompiler','memoryPolicy')) THEN RAISE(ABORT,'benchmark treatment configuration contains an undeclared dimension') END;
    SELECT CASE WHEN NOT EXISTS (
      SELECT 1 FROM benchmark_case_versions c JOIN benchmark_suite_versions s ON s.row_id=c.suite_row_id JOIN tasks t ON t.id=NEW.task_id JOIN artifacts a ON a.id=NEW.result_artifact_id
      WHERE c.row_id=NEW.case_row_id AND t.project_id=s.project_id AND a.project_id=s.project_id AND (a.task_id IS NULL OR a.task_id=NEW.task_id)
        AND NEW.actual_repository_revision=c.repository_revision
        AND NEW.fixture_manifest_digest=c.fixture_manifest_digest
        AND NEW.objective_digest=c.objective_digest
        AND NEW.budget_profile_digest=c.budget_profile_digest
        AND NEW.policy_digest=c.policy_digest
        AND NEW.tool_permissions_digest=c.tool_permissions_digest
        AND NEW.acceptance_rules_digest=c.acceptance_rules_digest
    ) THEN RAISE(ABORT,'benchmark run revision, fixture, objective, budget, policy, tool permissions, acceptance rules, task, or artifact binding is incoherent') END;
END;
CREATE TRIGGER benchmark_comparison_v6_exact_controls BEFORE INSERT ON benchmark_comparison_receipts_v2 FOR EACH ROW BEGIN
    SELECT CASE WHEN EXISTS (SELECT 1 FROM json_each(NEW.declared_treatment_dimensions_json) WHERE type<>'text' OR value NOT IN ('retrievalPipeline','contextCompiler','memoryPolicy')) THEN RAISE(ABORT,'benchmark comparison declares an invalid treatment dimension') END;
    SELECT CASE WHEN NOT EXISTS (
      SELECT 1 FROM benchmark_run_receipts_v2 b JOIN benchmark_run_receipts_v2 c ON c.id=NEW.candidate_run_id
      JOIN tasks bt ON bt.id=b.task_id JOIN tasks ct ON ct.id=c.task_id JOIN artifacts a ON a.id=NEW.comparison_artifact_id
      WHERE b.id=NEW.baseline_run_id AND b.case_row_id=c.case_row_id AND b.status='completed' AND c.status='completed'
        AND b.controlled_configuration_digest=c.controlled_configuration_digest
        AND b.actual_repository_revision=c.actual_repository_revision
        AND b.fixture_manifest_digest=c.fixture_manifest_digest
        AND b.objective_digest=c.objective_digest
        AND b.budget_profile_digest=c.budget_profile_digest
        AND b.policy_digest=c.policy_digest
        AND b.tool_permissions_digest=c.tool_permissions_digest
        AND b.model_digest=c.model_digest
        AND b.prompt_digest=c.prompt_digest
        AND b.evaluator_digest=c.evaluator_digest
        AND b.acceptance_rules_digest=c.acceptance_rules_digest
        AND bt.project_id=ct.project_id AND a.project_id=bt.project_id
    ) THEN RAISE(ABORT,'benchmark comparison controlled inputs are not exactly comparable') END;
    SELECT CASE WHEN EXISTS (
      SELECT 1 FROM benchmark_run_receipts_v2 b JOIN benchmark_run_receipts_v2 c ON c.id=NEW.candidate_run_id
      WHERE b.id=NEW.baseline_run_id AND (
        (NOT EXISTS (SELECT 1 FROM json_each(NEW.declared_treatment_dimensions_json) WHERE value='retrievalPipeline') AND json_extract(b.treatment_configuration_json,'$.retrievalPipeline')<>json_extract(c.treatment_configuration_json,'$.retrievalPipeline')) OR
        (NOT EXISTS (SELECT 1 FROM json_each(NEW.declared_treatment_dimensions_json) WHERE value='contextCompiler') AND json_extract(b.treatment_configuration_json,'$.contextCompiler')<>json_extract(c.treatment_configuration_json,'$.contextCompiler')) OR
        (NOT EXISTS (SELECT 1 FROM json_each(NEW.declared_treatment_dimensions_json) WHERE value='memoryPolicy') AND json_extract(b.treatment_configuration_json,'$.memoryPolicy')<>json_extract(c.treatment_configuration_json,'$.memoryPolicy'))
      )
    ) THEN RAISE(ABORT,'benchmark comparison contains an undeclared treatment difference') END;
    SELECT CASE WHEN NOT EXISTS (
      SELECT 1 FROM benchmark_run_receipts_v2 b JOIN benchmark_run_receipts_v2 c ON c.id=NEW.candidate_run_id
      WHERE b.id=NEW.baseline_run_id AND (
        (EXISTS (SELECT 1 FROM json_each(NEW.declared_treatment_dimensions_json) WHERE value='retrievalPipeline') AND json_extract(b.treatment_configuration_json,'$.retrievalPipeline')<>json_extract(c.treatment_configuration_json,'$.retrievalPipeline')) OR
        (EXISTS (SELECT 1 FROM json_each(NEW.declared_treatment_dimensions_json) WHERE value='contextCompiler') AND json_extract(b.treatment_configuration_json,'$.contextCompiler')<>json_extract(c.treatment_configuration_json,'$.contextCompiler')) OR
        (EXISTS (SELECT 1 FROM json_each(NEW.declared_treatment_dimensions_json) WHERE value='memoryPolicy') AND json_extract(b.treatment_configuration_json,'$.memoryPolicy')<>json_extract(c.treatment_configuration_json,'$.memoryPolicy'))
      )
    ) THEN RAISE(ABORT,'benchmark comparison declares no actual treatment difference') END;
END;
CREATE TRIGGER benchmark_suite_v6_update_forbidden BEFORE UPDATE ON benchmark_suite_versions FOR EACH ROW BEGIN SELECT RAISE(ABORT,'benchmark suite versions are immutable'); END;
CREATE TRIGGER benchmark_case_v6_update_forbidden BEFORE UPDATE ON benchmark_case_versions FOR EACH ROW BEGIN SELECT RAISE(ABORT,'benchmark case versions are immutable'); END;
CREATE TRIGGER benchmark_run_v6_update_forbidden BEFORE UPDATE ON benchmark_run_receipts_v2 FOR EACH ROW BEGIN SELECT RAISE(ABORT,'benchmark run receipts are immutable'); END;
CREATE TRIGGER benchmark_comparison_v6_update_forbidden BEFORE UPDATE ON benchmark_comparison_receipts_v2 FOR EACH ROW BEGIN SELECT RAISE(ABORT,'benchmark comparison receipts are immutable'); END;
CREATE TRIGGER quality_release_v6_scope BEFORE INSERT ON quality_release_decisions_v2 FOR EACH ROW BEGIN
    SELECT CASE WHEN NOT EXISTS (
      SELECT 1 FROM benchmark_comparison_receipts_v2 c JOIN benchmark_run_receipts_v2 b ON b.id=c.baseline_run_id JOIN tasks t ON t.id=b.task_id JOIN artifacts a ON a.id=NEW.decision_artifact_id JOIN actor_bindings ab ON ab.id=NEW.actor_binding_id
      WHERE c.id=NEW.comparison_id AND a.project_id=t.project_id AND ab.revoked_at IS NULL AND ab.expires_at>NEW.decided_at
    ) THEN RAISE(ABORT,'quality release decision scope or actor binding is incoherent') END;
END;
CREATE TRIGGER quality_release_v6_claim_gate BEFORE INSERT ON quality_release_decisions_v2 FOR EACH ROW WHEN NEW.decision='allow_quality_claim' BEGIN
    SELECT CASE WHEN NOT EXISTS (SELECT 1 FROM benchmark_comparison_receipts_v2 c WHERE c.id=NEW.comparison_id AND c.result='improved') THEN RAISE(ABORT,'quality claim requires an improved controlled comparison') END;
END;
CREATE TRIGGER quality_release_v6_update_forbidden BEFORE UPDATE ON quality_release_decisions_v2 FOR EACH ROW BEGIN SELECT RAISE(ABORT,'quality release decisions are immutable'); END;

CREATE INDEX idx_task_workflow_profile ON task_workflow_authority(workflow_profile,outcome_mode,phase);
CREATE INDEX idx_actor_binding_current ON actor_bindings(actor_id,session_id,expires_at) WHERE revoked_at IS NULL;
CREATE INDEX idx_benchmark_suite_logical_version ON benchmark_suite_versions(project_id,logical_suite_id,version);
CREATE INDEX idx_benchmark_case_logical_version ON benchmark_case_versions(suite_row_id,logical_case_id,case_version);
CREATE INDEX idx_benchmark_run_v2_case_arm ON benchmark_run_receipts_v2(case_row_id,arm,status);

COMMIT;
