-- Additive v4.0-to-v4.1 migration. Requires the exact reviewed sqlite-v3 authority baseline.
PRAGMA foreign_keys = ON;
BEGIN IMMEDIATE;

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

-- After this transaction succeeds, the migration runner records version 4 with the actual file checksum.
