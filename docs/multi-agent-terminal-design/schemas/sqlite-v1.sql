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
    enabled INTEGER NOT NULL CHECK (enabled IN (0, 1)),
    containment_verified INTEGER NOT NULL CHECK (containment_verified IN (0, 1)),
    last_health_status TEXT,
    updated_at TEXT NOT NULL,
    CHECK (trust_tier <> 'full_access_legacy' OR enabled = 0)
) STRICT;

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

CREATE TABLE approvals (
    id TEXT PRIMARY KEY,
    task_id TEXT NOT NULL REFERENCES tasks(id) ON DELETE RESTRICT,
    approval_type TEXT NOT NULL CHECK (
        approval_type IN ('plan', 'tool', 'policy_exception', 'final_commit')
    ),
    schema_version TEXT NOT NULL,
    operation_digest TEXT NOT NULL CHECK (
        length(operation_digest) = 71
        AND substr(operation_digest, 1, 7) = 'sha256:'
        AND substr(operation_digest, 8) NOT GLOB '*[^0-9a-f]*'
    ),
    status TEXT NOT NULL CHECK (
        status IN ('pending', 'granted', 'denied', 'expired', 'invalidated')
    ),
    requested_at TEXT NOT NULL,
    resolved_at TEXT,
    resolved_by TEXT,
    expires_at TEXT NOT NULL,
    request_artifact_id TEXT NOT NULL
        REFERENCES artifacts(id) ON DELETE RESTRICT,
    invalidation_reason TEXT,
    UNIQUE (task_id, operation_digest, approval_type, requested_at)
) STRICT;

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
    status TEXT NOT NULL CHECK (
        status IN (
            'pending',
            'claimed',
            'started',
            'succeeded',
            'failed',
            'interrupted',
            'indeterminate',
            'cancelled'
        )
    ),
    executor_fencing_token INTEGER CHECK (
        executor_fencing_token IS NULL OR executor_fencing_token >= 1
    ),
    lease_owner TEXT,
    lease_expires_at TEXT,
    attempt_count INTEGER NOT NULL DEFAULT 0 CHECK (attempt_count >= 0),
    result_artifact_id TEXT REFERENCES artifacts(id) ON DELETE RESTRICT,
    external_receipt_json TEXT CHECK (
        external_receipt_json IS NULL OR json_valid(external_receipt_json)
    ),
    error_json TEXT CHECK (error_json IS NULL OR json_valid(error_json)),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
) STRICT;

CREATE TABLE tool_executions (
    id TEXT PRIMARY KEY,
    task_id TEXT NOT NULL REFERENCES tasks(id) ON DELETE RESTRICT,
    run_id TEXT REFERENCES agent_runs(id) ON DELETE RESTRICT,
    request_id TEXT NOT NULL,
    tool_name TEXT NOT NULL,
    arguments_artifact_id TEXT NOT NULL
        REFERENCES artifacts(id) ON DELETE RESTRICT,
    policy_decision_id TEXT NOT NULL
        REFERENCES policy_decisions(id) ON DELETE RESTRICT,
    approval_id TEXT REFERENCES approvals(id) ON DELETE RESTRICT,
    operation_intent_id TEXT NOT NULL UNIQUE
        REFERENCES operation_intents(id) ON DELETE RESTRICT,
    executor_fencing_token INTEGER CHECK (
        executor_fencing_token IS NULL OR executor_fencing_token >= 1
    ),
    status TEXT NOT NULL CHECK (
        status IN (
            'pending',
            'running',
            'succeeded',
            'failed',
            'terminated',
            'interrupted',
            'indeterminate',
            'denied'
        )
    ),
    started_at TEXT,
    completed_at TEXT,
    exit_code INTEGER,
    stdout_artifact_id TEXT REFERENCES artifacts(id) ON DELETE RESTRICT,
    stderr_artifact_id TEXT REFERENCES artifacts(id) ON DELETE RESTRICT,
    UNIQUE (run_id, request_id)
) STRICT;

CREATE TABLE executor_leases (
    task_id TEXT PRIMARY KEY REFERENCES tasks(id) ON DELETE RESTRICT,
    holder_run_id TEXT NOT NULL REFERENCES agent_runs(id) ON DELETE RESTRICT,
    fencing_token INTEGER NOT NULL CHECK (fencing_token >= 1),
    status TEXT NOT NULL CHECK (
        status IN ('active', 'released', 'expired', 'revoked')
    ),
    acquired_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    released_at TEXT
) STRICT;

CREATE TRIGGER executor_fencing_token_matches_task_insert
BEFORE INSERT ON executor_leases
FOR EACH ROW
WHEN NEW.fencing_token <> (
    SELECT fencing_epoch FROM tasks WHERE id = NEW.task_id
)
BEGIN
    SELECT RAISE(ABORT, 'executor fencing token must match task fencing epoch');
END;

CREATE TRIGGER executor_fencing_token_monotonic
BEFORE UPDATE OF fencing_token ON executor_leases
FOR EACH ROW
WHEN NEW.fencing_token <= OLD.fencing_token
BEGIN
    SELECT RAISE(ABORT, 'executor fencing token must increase');
END;

CREATE TRIGGER executor_fencing_token_matches_task_update
BEFORE UPDATE OF fencing_token ON executor_leases
FOR EACH ROW
WHEN NEW.fencing_token <> (
    SELECT fencing_epoch FROM tasks WHERE id = NEW.task_id
)
BEGIN
    SELECT RAISE(ABORT, 'executor fencing token must match task fencing epoch');
END;

CREATE TRIGGER executor_lease_delete_forbidden
BEFORE DELETE ON executor_leases
FOR EACH ROW
BEGIN
    SELECT RAISE(ABORT, 'executor lease rows are retained for fencing history');
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

CREATE INDEX idx_messages_thread_time
    ON messages(task_id, thread_id, core_received_at);

CREATE INDEX idx_approvals_pending
    ON approvals(task_id, status, expires_at);

CREATE INDEX idx_policy_decisions_task_action
    ON policy_decisions(task_id, action, created_at);

CREATE INDEX idx_operation_intents_dispatch
    ON operation_intents(status, lease_expires_at, created_at);

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

-- After this transaction succeeds, the migration runner records version 1
-- with the actual file checksum, application version, and authoritative time.
