PRAGMA foreign_keys = ON;
BEGIN IMMEDIATE;

DROP TRIGGER agent_runs_terminal_irreversible;
CREATE TRIGGER agent_runs_terminal_irreversible BEFORE UPDATE OF status ON agent_runs FOR EACH ROW
WHEN OLD.status IN ('succeeded','failed','cancelled_cleanly','terminated','interrupted','indeterminate') AND NEW.status <> OLD.status
BEGIN SELECT RAISE(ABORT,'terminal agent run status is irreversible'); END;

DROP TRIGGER episode_scope_insert;
CREATE TRIGGER episode_scope_insert BEFORE INSERT ON episodes FOR EACH ROW BEGIN
    SELECT CASE WHEN NOT EXISTS (SELECT 1 FROM agent_runs r JOIN tasks t ON t.id=r.task_id WHERE r.id=NEW.run_id AND r.task_id=NEW.task_id AND t.project_id=NEW.project_id) THEN RAISE(ABORT,'episode run scope is incoherent') END;
    SELECT CASE WHEN NOT EXISTS (SELECT 1 FROM artifacts a WHERE a.id=NEW.summary_artifact_id AND a.project_id=NEW.project_id AND a.task_id=NEW.task_id) THEN RAISE(ABORT,'episode summary scope is incoherent') END;
    SELECT CASE WHEN NEW.verification_artifact_id IS NOT NULL AND NOT EXISTS (SELECT 1 FROM artifacts a WHERE a.id=NEW.verification_artifact_id AND a.project_id=NEW.project_id AND a.task_id=NEW.task_id) THEN RAISE(ABORT,'episode verification scope is incoherent') END;
    SELECT CASE WHEN NOT EXISTS (SELECT 1 FROM agent_runs r WHERE r.id=NEW.run_id AND r.status IN ('succeeded','failed','cancelled_cleanly','terminated','interrupted','indeterminate')) THEN RAISE(ABORT,'episode requires terminal run') END;
    SELECT CASE WHEN NEW.outcome='succeeded' AND NEW.verification_artifact_id IS NULL THEN RAISE(ABORT,'successful episode requires verification evidence') END;
END;

DROP TRIGGER run_reflection_scope_insert;
CREATE TRIGGER run_reflection_scope_insert BEFORE INSERT ON run_reflections FOR EACH ROW BEGIN
    SELECT CASE WHEN NOT EXISTS (SELECT 1 FROM agent_runs r JOIN tasks t ON t.id=r.task_id WHERE r.id=NEW.run_id AND r.task_id=NEW.task_id AND t.project_id=NEW.project_id) THEN RAISE(ABORT,'reflection run scope is incoherent') END;
    SELECT CASE WHEN NOT EXISTS (SELECT 1 FROM artifacts a WHERE a.id=NEW.reflection_artifact_id AND a.project_id=NEW.project_id AND a.task_id=NEW.task_id) THEN RAISE(ABORT,'reflection artifact scope is incoherent') END;
    SELECT CASE WHEN NOT EXISTS (SELECT 1 FROM artifacts a WHERE a.id=NEW.reflection_artifact_id AND a.content_hash=NEW.reflection_digest) THEN RAISE(ABORT,'reflection digest does not match artifact') END;
    SELECT CASE WHEN NOT EXISTS (SELECT 1 FROM agent_runs r WHERE r.id=NEW.run_id AND r.status IN ('succeeded','failed','cancelled_cleanly','terminated','interrupted','indeterminate')) THEN RAISE(ABORT,'reflection requires terminal run') END;
END;

DROP TRIGGER run_evaluation_scope_insert;
CREATE TRIGGER run_evaluation_scope_insert BEFORE INSERT ON run_evaluations FOR EACH ROW BEGIN
    SELECT CASE WHEN NOT EXISTS (SELECT 1 FROM agent_runs r JOIN tasks t ON t.id=r.task_id WHERE r.id=NEW.run_id AND r.task_id=NEW.task_id AND t.project_id=NEW.project_id) THEN RAISE(ABORT,'evaluation run scope is incoherent') END;
    SELECT CASE WHEN NOT EXISTS (SELECT 1 FROM artifacts a WHERE a.id=NEW.evaluation_artifact_id AND a.project_id=NEW.project_id AND a.task_id=NEW.task_id) THEN RAISE(ABORT,'evaluation artifact scope is incoherent') END;
    SELECT CASE WHEN NOT EXISTS (SELECT 1 FROM agent_runs r WHERE r.id=NEW.run_id AND r.status IN ('succeeded','failed','cancelled_cleanly','terminated','interrupted','indeterminate')) THEN RAISE(ABORT,'evaluation requires terminal run') END;
END;



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
