BEGIN IMMEDIATE;

CREATE TABLE agent_run_outputs (
    run_id TEXT PRIMARY KEY REFERENCES agent_runs(id) ON DELETE RESTRICT,
    task_id TEXT NOT NULL REFERENCES tasks(id) ON DELETE RESTRICT,
    message_id TEXT NOT NULL UNIQUE,
    thread_id TEXT NOT NULL,
    message_type TEXT NOT NULL,
    reply_to TEXT,
    content_artifact_id TEXT NOT NULL REFERENCES artifacts(id) ON DELETE RESTRICT,
    core_received_at TEXT NOT NULL
) STRICT;

CREATE INDEX agent_run_outputs_task_received
ON agent_run_outputs(task_id, core_received_at, run_id);

CREATE TRIGGER agent_run_outputs_update_forbidden
BEFORE UPDATE ON agent_run_outputs
FOR EACH ROW BEGIN
    SELECT RAISE(ABORT, 'private agent run outputs are immutable');
END;

CREATE TRIGGER agent_run_outputs_delete_forbidden
BEFORE DELETE ON agent_run_outputs
FOR EACH ROW BEGIN
    SELECT RAISE(ABORT, 'private agent run outputs are immutable');
END;

CREATE TABLE deliberation_records (
    event_id TEXT PRIMARY KEY REFERENCES events(event_id) ON DELETE RESTRICT,
    task_id TEXT NOT NULL REFERENCES tasks(id) ON DELETE RESTRICT,
    sequence INTEGER NOT NULL CHECK (sequence >= 1),
    record_type TEXT NOT NULL,
    primary_artifact_id TEXT NOT NULL REFERENCES artifacts(id) ON DELETE RESTRICT,
    canonical_record_json TEXT NOT NULL CHECK (json_valid(canonical_record_json)),
    canonical_record_digest TEXT NOT NULL CHECK (
        length(canonical_record_digest) = 71
        AND substr(canonical_record_digest, 1, 7) = 'sha256:'
        AND substr(canonical_record_digest, 8) NOT GLOB '*[^0-9a-f]*'
    ),
    created_at TEXT NOT NULL,
    UNIQUE (task_id, sequence)
) STRICT;

CREATE INDEX deliberation_records_task_sequence
ON deliberation_records(task_id, sequence);

CREATE TRIGGER deliberation_records_update_forbidden
BEFORE UPDATE ON deliberation_records
FOR EACH ROW BEGIN
    SELECT RAISE(ABORT, 'deliberation recovery records are immutable');
END;

CREATE TRIGGER deliberation_records_delete_forbidden
BEFORE DELETE ON deliberation_records
FOR EACH ROW BEGIN
    SELECT RAISE(ABORT, 'deliberation recovery records are immutable');
END;

CREATE TABLE deliberation_dispatch_reservations (
    run_id TEXT PRIMARY KEY,
    task_id TEXT NOT NULL REFERENCES tasks(id) ON DELETE RESTRICT,
    phase TEXT NOT NULL CHECK (phase IN (
        'ParallelAnalysis', 'CrossReview', 'PrePlanVerification', 'Synthesis', 'FinalObjection'
    )),
    agent_id TEXT NOT NULL,
    family_key TEXT NOT NULL,
    max_tokens INTEGER NOT NULL CHECK (max_tokens BETWEEN 1 AND 1000000),
    estimated_cost_microunits INTEGER NOT NULL CHECK (estimated_cost_microunits > 0),
    deadline_unix_seconds INTEGER NOT NULL CHECK (deadline_unix_seconds > 0),
    run_config_artifact_id TEXT NOT NULL,
    connection_binding_digest TEXT NOT NULL,
    dispatch_round INTEGER NOT NULL DEFAULT 0 CHECK (dispatch_round BETWEEN 0 AND 64)
) STRICT;

CREATE INDEX deliberation_dispatch_reservations_task
ON deliberation_dispatch_reservations(task_id, phase, dispatch_round, run_id);

CREATE TRIGGER deliberation_dispatch_reservations_update_forbidden
BEFORE UPDATE ON deliberation_dispatch_reservations
FOR EACH ROW BEGIN
    SELECT RAISE(ABORT, 'deliberation dispatch reservations are immutable');
END;

CREATE TRIGGER deliberation_dispatch_reservations_delete_forbidden
BEFORE DELETE ON deliberation_dispatch_reservations
FOR EACH ROW BEGIN
    SELECT RAISE(ABORT, 'deliberation dispatch reservations are immutable');
END;

CREATE TABLE deliberation_repository_baselines (
    task_id TEXT PRIMARY KEY REFERENCES tasks(id) ON DELETE RESTRICT,
    head TEXT NOT NULL,
    index_digest TEXT NOT NULL,
    status_digest TEXT NOT NULL,
    captured_at TEXT NOT NULL
) STRICT;

CREATE TABLE deliberation_repository_boundary_records (
    id INTEGER PRIMARY KEY,
    task_id TEXT NOT NULL REFERENCES tasks(id) ON DELETE RESTRICT,
    phase TEXT NOT NULL,
    expected_head TEXT NOT NULL,
    expected_index_digest TEXT NOT NULL,
    expected_status_digest TEXT NOT NULL,
    observed_head TEXT NOT NULL,
    observed_index_digest TEXT NOT NULL,
    observed_status_digest TEXT NOT NULL,
    blocked INTEGER NOT NULL CHECK (blocked IN (0, 1)),
    observed_at TEXT NOT NULL,
    UNIQUE (
        task_id, phase, expected_head, expected_index_digest, expected_status_digest,
        observed_head, observed_index_digest, observed_status_digest
    )
) STRICT;

CREATE TABLE deliberation_synthesis_plans (
    event_id TEXT PRIMARY KEY REFERENCES deliberation_records(event_id) ON DELETE RESTRICT,
    task_id TEXT NOT NULL REFERENCES tasks(id) ON DELETE RESTRICT,
    plan_json TEXT NOT NULL CHECK (json_valid(plan_json)),
    plan_digest TEXT NOT NULL,
    created_at TEXT NOT NULL
) STRICT;

CREATE TABLE deliberation_specialist_threads (
    thread_id TEXT PRIMARY KEY,
    task_id TEXT NOT NULL REFERENCES tasks(id) ON DELETE RESTRICT,
    parent_run_id TEXT NOT NULL REFERENCES agent_runs(id) ON DELETE RESTRICT,
    specialist_run_id TEXT NOT NULL UNIQUE,
    specialist_agent_id TEXT NOT NULL,
    context_package_artifact_id TEXT NOT NULL REFERENCES artifacts(id) ON DELETE RESTRICT,
    created_at TEXT NOT NULL
) STRICT;

CREATE TABLE deliberation_specialist_dispatches (
    event_id TEXT PRIMARY KEY REFERENCES deliberation_records(event_id) ON DELETE RESTRICT,
    request_id TEXT NOT NULL,
    task_id TEXT NOT NULL REFERENCES tasks(id) ON DELETE RESTRICT,
    parent_run_id TEXT NOT NULL REFERENCES agent_runs(id) ON DELETE RESTRICT,
    specialist_run_id TEXT NOT NULL UNIQUE,
    specialist_agent_id TEXT NOT NULL,
    specialist_actor_id TEXT NOT NULL,
    family_key TEXT NOT NULL,
    thread_id TEXT NOT NULL UNIQUE
        REFERENCES deliberation_specialist_threads(thread_id) ON DELETE RESTRICT,
    context_package_artifact_id TEXT NOT NULL REFERENCES artifacts(id) ON DELETE RESTRICT,
    status TEXT NOT NULL CHECK (status = 'reserved'),
    created_at TEXT NOT NULL,
    UNIQUE (task_id, parent_run_id, request_id)
) STRICT;

CREATE TABLE deliberation_context_package_invalidations (
    context_package_id TEXT NOT NULL REFERENCES context_packages(id) ON DELETE RESTRICT,
    boundary_record_id INTEGER NOT NULL
        REFERENCES deliberation_repository_boundary_records(id) ON DELETE RESTRICT,
    task_id TEXT NOT NULL REFERENCES tasks(id) ON DELETE RESTRICT,
    reason TEXT NOT NULL CHECK (reason = 'repository_fingerprint_changed'),
    invalidated_at TEXT NOT NULL,
    PRIMARY KEY (context_package_id, boundary_record_id)
) STRICT;

CREATE TRIGGER deliberation_repository_baselines_update_forbidden
BEFORE UPDATE ON deliberation_repository_baselines
FOR EACH ROW BEGIN
    SELECT RAISE(ABORT, 'deliberation repository baselines are immutable');
END;

CREATE TRIGGER deliberation_repository_baselines_delete_forbidden
BEFORE DELETE ON deliberation_repository_baselines
FOR EACH ROW BEGIN
    SELECT RAISE(ABORT, 'deliberation repository baselines are immutable');
END;

CREATE TRIGGER deliberation_repository_boundary_records_update_forbidden
BEFORE UPDATE ON deliberation_repository_boundary_records
FOR EACH ROW BEGIN
    SELECT RAISE(ABORT, 'deliberation repository boundary records are immutable');
END;

CREATE TRIGGER deliberation_repository_boundary_records_delete_forbidden
BEFORE DELETE ON deliberation_repository_boundary_records
FOR EACH ROW BEGIN
    SELECT RAISE(ABORT, 'deliberation repository boundary records are immutable');
END;

CREATE TRIGGER deliberation_synthesis_plans_update_forbidden
BEFORE UPDATE ON deliberation_synthesis_plans
FOR EACH ROW BEGIN
    SELECT RAISE(ABORT, 'deliberation synthesis plans are immutable');
END;

CREATE TRIGGER deliberation_synthesis_plans_delete_forbidden
BEFORE DELETE ON deliberation_synthesis_plans
FOR EACH ROW BEGIN
    SELECT RAISE(ABORT, 'deliberation synthesis plans are immutable');
END;

CREATE TRIGGER deliberation_specialist_threads_update_forbidden
BEFORE UPDATE ON deliberation_specialist_threads
FOR EACH ROW BEGIN
    SELECT RAISE(ABORT, 'deliberation specialist threads are immutable');
END;

CREATE TRIGGER deliberation_specialist_threads_delete_forbidden
BEFORE DELETE ON deliberation_specialist_threads
FOR EACH ROW BEGIN
    SELECT RAISE(ABORT, 'deliberation specialist threads are immutable');
END;

CREATE TRIGGER deliberation_specialist_dispatches_update_forbidden
BEFORE UPDATE ON deliberation_specialist_dispatches
FOR EACH ROW BEGIN
    SELECT RAISE(ABORT, 'deliberation specialist dispatches are immutable');
END;

CREATE TRIGGER deliberation_specialist_dispatches_delete_forbidden
BEFORE DELETE ON deliberation_specialist_dispatches
FOR EACH ROW BEGIN
    SELECT RAISE(ABORT, 'deliberation specialist dispatches are immutable');
END;

CREATE TRIGGER deliberation_context_package_invalidations_update_forbidden
BEFORE UPDATE ON deliberation_context_package_invalidations
FOR EACH ROW BEGIN
    SELECT RAISE(ABORT, 'deliberation context package invalidations are immutable');
END;

CREATE TRIGGER deliberation_context_package_invalidations_delete_forbidden
BEFORE DELETE ON deliberation_context_package_invalidations
FOR EACH ROW BEGIN
    SELECT RAISE(ABORT, 'deliberation context package invalidations are immutable');
END;

COMMIT;
