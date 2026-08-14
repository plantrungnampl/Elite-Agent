-- Local-First Multi-Agent Engineering Terminal
-- Incremental migration from the exact reviewed sqlite-v2 v3.2 baseline to schema v3.
-- The migration runner MUST verify the source sqlite-v2 checksum before execution.
-- Runtime startup independently verifies connection PRAGMAs.

PRAGMA foreign_keys = ON;
BEGIN IMMEDIATE;

-- Reinstall artifact lifecycle guards so both patched and historical v3.2
-- databases converge on the exact v4.0 normalized trigger definitions.
DROP TRIGGER IF EXISTS artifacts_availability_transition;
DROP TRIGGER IF EXISTS artifacts_verification_transition;
DROP TRIGGER IF EXISTS artifacts_replacement_forbidden;
DROP TRIGGER IF EXISTS artifacts_delete_guard;
DROP TRIGGER IF EXISTS artifacts_delete_forbidden;

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

-- v4.0 cognitive memory and agent-quality authority extension.

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
