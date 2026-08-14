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

COMMIT;
