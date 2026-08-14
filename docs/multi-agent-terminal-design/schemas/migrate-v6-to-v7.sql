BEGIN IMMEDIATE;

-- v4.3 / SQLite v7: reducer-bound workflow authority, run configuration, and assurance receipts

CREATE TABLE workflow_transition_rules (
    rule_id TEXT PRIMARY KEY,
    event_type TEXT NOT NULL,
    to_phase TEXT NOT NULL,
    guard_expression TEXT NOT NULL,
    rule_version INTEGER NOT NULL DEFAULT 1 CHECK (rule_version >= 1)
) STRICT;
CREATE TABLE workflow_transition_rule_sources (
    rule_id TEXT NOT NULL REFERENCES workflow_transition_rules(rule_id) ON DELETE RESTRICT,
    from_phase TEXT NOT NULL,
    PRIMARY KEY (rule_id, from_phase)
) WITHOUT ROWID, STRICT;
CREATE TABLE workflow_transition_rule_profiles (
    rule_id TEXT NOT NULL REFERENCES workflow_transition_rules(rule_id) ON DELETE RESTRICT,
    workflow_profile TEXT NOT NULL CHECK (workflow_profile IN ('Quick','Standard','HighAssurance','ReadOnlyResearch')), 
    PRIMARY KEY (rule_id, workflow_profile)
) WITHOUT ROWID, STRICT;
CREATE TABLE workflow_transition_rule_outcomes (
    rule_id TEXT NOT NULL REFERENCES workflow_transition_rules(rule_id) ON DELETE RESTRICT,
    outcome_mode TEXT NOT NULL CHECK (outcome_mode IN ('ReadOnlyDeliverable','WorkspaceChange','LocalCommit')), 
    PRIMARY KEY (rule_id, outcome_mode)
) WITHOUT ROWID, STRICT;
CREATE TABLE workflow_transition_rule_guard_requirements (
    rule_id TEXT NOT NULL REFERENCES workflow_transition_rules(rule_id) ON DELETE RESTRICT,
    evidence_kind TEXT NOT NULL,
    minimum_count INTEGER NOT NULL DEFAULT 1 CHECK (minimum_count >= 1),
    PRIMARY KEY (rule_id, evidence_kind)
) WITHOUT ROWID, STRICT;
CREATE TABLE workflow_transition_rule_effect_requirements (
    rule_id TEXT NOT NULL REFERENCES workflow_transition_rules(rule_id) ON DELETE RESTRICT,
    effect_kind TEXT NOT NULL,
    minimum_count INTEGER NOT NULL DEFAULT 1 CHECK (minimum_count >= 1),
    PRIMARY KEY (rule_id, effect_kind)
) WITHOUT ROWID, STRICT;

INSERT INTO workflow_transition_rules(rule_id,event_type,to_phase,guard_expression) VALUES ('WF-P001','task.validated','ContextBuild','trusted_core_selected_profile_outcome_policy_budgets_valid');
INSERT INTO workflow_transition_rule_sources(rule_id,from_phase) VALUES ('WF-P001','Intake');
INSERT INTO workflow_transition_rule_profiles(rule_id,workflow_profile) VALUES ('WF-P001','Quick');
INSERT INTO workflow_transition_rule_profiles(rule_id,workflow_profile) VALUES ('WF-P001','Standard');
INSERT INTO workflow_transition_rule_profiles(rule_id,workflow_profile) VALUES ('WF-P001','HighAssurance');
INSERT INTO workflow_transition_rule_profiles(rule_id,workflow_profile) VALUES ('WF-P001','ReadOnlyResearch');
INSERT INTO workflow_transition_rule_outcomes(rule_id,outcome_mode) VALUES ('WF-P001','ReadOnlyDeliverable');
INSERT INTO workflow_transition_rule_outcomes(rule_id,outcome_mode) VALUES ('WF-P001','WorkspaceChange');
INSERT INTO workflow_transition_rule_outcomes(rule_id,outcome_mode) VALUES ('WF-P001','LocalCommit');
INSERT INTO workflow_transition_rule_guard_requirements(rule_id,evidence_kind) VALUES ('WF-P001','profile_outcome_policy_budget_receipt');
INSERT INTO workflow_transition_rule_effect_requirements(rule_id,effect_kind) VALUES ('WF-P001','persist_risk');
INSERT INTO workflow_transition_rule_effect_requirements(rule_id,effect_kind) VALUES ('WF-P001','persist_base_identity');
INSERT INTO workflow_transition_rule_effect_requirements(rule_id,effect_kind) VALUES ('WF-P001','persist_workflow_profile');
INSERT INTO workflow_transition_rule_effect_requirements(rule_id,effect_kind) VALUES ('WF-P001','persist_outcome_mode');
INSERT INTO workflow_transition_rules(rule_id,event_type,to_phase,guard_expression) VALUES ('WF-P002','context.initial.ready','ParallelAnalysis','workflow_profile_in(Standard,HighAssurance,ReadOnlyResearch) AND required_context_packages_valid');
INSERT INTO workflow_transition_rule_sources(rule_id,from_phase) VALUES ('WF-P002','ContextBuild');
INSERT INTO workflow_transition_rule_profiles(rule_id,workflow_profile) VALUES ('WF-P002','Standard');
INSERT INTO workflow_transition_rule_profiles(rule_id,workflow_profile) VALUES ('WF-P002','HighAssurance');
INSERT INTO workflow_transition_rule_profiles(rule_id,workflow_profile) VALUES ('WF-P002','ReadOnlyResearch');
INSERT INTO workflow_transition_rule_outcomes(rule_id,outcome_mode) VALUES ('WF-P002','ReadOnlyDeliverable');
INSERT INTO workflow_transition_rule_outcomes(rule_id,outcome_mode) VALUES ('WF-P002','WorkspaceChange');
INSERT INTO workflow_transition_rule_outcomes(rule_id,outcome_mode) VALUES ('WF-P002','LocalCommit');
INSERT INTO workflow_transition_rule_guard_requirements(rule_id,evidence_kind) VALUES ('WF-P002','context_package_set');
INSERT INTO workflow_transition_rule_effect_requirements(rule_id,effect_kind) VALUES ('WF-P002','freeze_independent_inputs');
INSERT INTO workflow_transition_rules(rule_id,event_type,to_phase,guard_expression) VALUES ('WF-P003','context.initial.ready','PrePlanVerification','workflow_profile=Quick AND required_context_packages_valid');
INSERT INTO workflow_transition_rule_sources(rule_id,from_phase) VALUES ('WF-P003','ContextBuild');
INSERT INTO workflow_transition_rule_profiles(rule_id,workflow_profile) VALUES ('WF-P003','Quick');
INSERT INTO workflow_transition_rule_outcomes(rule_id,outcome_mode) VALUES ('WF-P003','ReadOnlyDeliverable');
INSERT INTO workflow_transition_rule_outcomes(rule_id,outcome_mode) VALUES ('WF-P003','WorkspaceChange');
INSERT INTO workflow_transition_rule_outcomes(rule_id,outcome_mode) VALUES ('WF-P003','LocalCommit');
INSERT INTO workflow_transition_rule_guard_requirements(rule_id,evidence_kind) VALUES ('WF-P003','context_package_set');
INSERT INTO workflow_transition_rule_effect_requirements(rule_id,effect_kind) VALUES ('WF-P003','freeze_quick_path_input');
INSERT INTO workflow_transition_rules(rule_id,event_type,to_phase,guard_expression) VALUES ('WF-P004','analysis.quorum.reached','CrossReview','profile_specific_independent_result_requirement_met');
INSERT INTO workflow_transition_rule_sources(rule_id,from_phase) VALUES ('WF-P004','ParallelAnalysis');
INSERT INTO workflow_transition_rule_profiles(rule_id,workflow_profile) VALUES ('WF-P004','Standard');
INSERT INTO workflow_transition_rule_profiles(rule_id,workflow_profile) VALUES ('WF-P004','HighAssurance');
INSERT INTO workflow_transition_rule_profiles(rule_id,workflow_profile) VALUES ('WF-P004','ReadOnlyResearch');
INSERT INTO workflow_transition_rule_outcomes(rule_id,outcome_mode) VALUES ('WF-P004','ReadOnlyDeliverable');
INSERT INTO workflow_transition_rule_outcomes(rule_id,outcome_mode) VALUES ('WF-P004','WorkspaceChange');
INSERT INTO workflow_transition_rule_outcomes(rule_id,outcome_mode) VALUES ('WF-P004','LocalCommit');
INSERT INTO workflow_transition_rule_guard_requirements(rule_id,evidence_kind) VALUES ('WF-P004','analysis_quorum_receipt');
INSERT INTO workflow_transition_rule_effect_requirements(rule_id,effect_kind) VALUES ('WF-P004','publish_selected_proposals');
INSERT INTO workflow_transition_rule_effect_requirements(rule_id,effect_kind) VALUES ('WF-P004','assign_review_edges');
INSERT INTO workflow_transition_rules(rule_id,event_type,to_phase,guard_expression) VALUES ('WF-P005','review.complete','PrePlanVerification','review_outputs_or_bounded_stop');
INSERT INTO workflow_transition_rule_sources(rule_id,from_phase) VALUES ('WF-P005','CrossReview');
INSERT INTO workflow_transition_rule_profiles(rule_id,workflow_profile) VALUES ('WF-P005','Standard');
INSERT INTO workflow_transition_rule_profiles(rule_id,workflow_profile) VALUES ('WF-P005','HighAssurance');
INSERT INTO workflow_transition_rule_profiles(rule_id,workflow_profile) VALUES ('WF-P005','ReadOnlyResearch');
INSERT INTO workflow_transition_rule_outcomes(rule_id,outcome_mode) VALUES ('WF-P005','ReadOnlyDeliverable');
INSERT INTO workflow_transition_rule_outcomes(rule_id,outcome_mode) VALUES ('WF-P005','WorkspaceChange');
INSERT INTO workflow_transition_rule_outcomes(rule_id,outcome_mode) VALUES ('WF-P005','LocalCommit');
INSERT INTO workflow_transition_rule_guard_requirements(rule_id,evidence_kind) VALUES ('WF-P005','review_completion_receipt');
INSERT INTO workflow_transition_rule_effect_requirements(rule_id,effect_kind) VALUES ('WF-P005','freeze_material_claims');
INSERT INTO workflow_transition_rules(rule_id,event_type,to_phase,guard_expression) VALUES ('WF-P006','claims.checked','Synthesis','all_material_claims_classified');
INSERT INTO workflow_transition_rule_sources(rule_id,from_phase) VALUES ('WF-P006','PrePlanVerification');
INSERT INTO workflow_transition_rule_profiles(rule_id,workflow_profile) VALUES ('WF-P006','Quick');
INSERT INTO workflow_transition_rule_profiles(rule_id,workflow_profile) VALUES ('WF-P006','Standard');
INSERT INTO workflow_transition_rule_profiles(rule_id,workflow_profile) VALUES ('WF-P006','HighAssurance');
INSERT INTO workflow_transition_rule_profiles(rule_id,workflow_profile) VALUES ('WF-P006','ReadOnlyResearch');
INSERT INTO workflow_transition_rule_outcomes(rule_id,outcome_mode) VALUES ('WF-P006','ReadOnlyDeliverable');
INSERT INTO workflow_transition_rule_outcomes(rule_id,outcome_mode) VALUES ('WF-P006','WorkspaceChange');
INSERT INTO workflow_transition_rule_outcomes(rule_id,outcome_mode) VALUES ('WF-P006','LocalCommit');
INSERT INTO workflow_transition_rule_guard_requirements(rule_id,evidence_kind) VALUES ('WF-P006','claim_verification_set');
INSERT INTO workflow_transition_rule_effect_requirements(rule_id,effect_kind) VALUES ('WF-P006','persist_claim_verification_set');
INSERT INTO workflow_transition_rules(rule_id,event_type,to_phase,guard_expression) VALUES ('WF-P007','decision.draft.created','FinalObjection','decision_schema_and_evidence_valid');
INSERT INTO workflow_transition_rule_sources(rule_id,from_phase) VALUES ('WF-P007','Synthesis');
INSERT INTO workflow_transition_rule_profiles(rule_id,workflow_profile) VALUES ('WF-P007','Quick');
INSERT INTO workflow_transition_rule_profiles(rule_id,workflow_profile) VALUES ('WF-P007','Standard');
INSERT INTO workflow_transition_rule_profiles(rule_id,workflow_profile) VALUES ('WF-P007','HighAssurance');
INSERT INTO workflow_transition_rule_profiles(rule_id,workflow_profile) VALUES ('WF-P007','ReadOnlyResearch');
INSERT INTO workflow_transition_rule_outcomes(rule_id,outcome_mode) VALUES ('WF-P007','ReadOnlyDeliverable');
INSERT INTO workflow_transition_rule_outcomes(rule_id,outcome_mode) VALUES ('WF-P007','WorkspaceChange');
INSERT INTO workflow_transition_rule_outcomes(rule_id,outcome_mode) VALUES ('WF-P007','LocalCommit');
INSERT INTO workflow_transition_rule_guard_requirements(rule_id,evidence_kind) VALUES ('WF-P007','decision_draft_artifact');
INSERT INTO workflow_transition_rule_effect_requirements(rule_id,effect_kind) VALUES ('WF-P007','publish_immutable_decision_draft');
INSERT INTO workflow_transition_rules(rule_id,event_type,to_phase,guard_expression) VALUES ('WF-P008','objection.severe.accepted','CrossReview','reopen_criteria_satisfied AND workflow_profile<>Quick');
INSERT INTO workflow_transition_rule_sources(rule_id,from_phase) VALUES ('WF-P008','FinalObjection');
INSERT INTO workflow_transition_rule_profiles(rule_id,workflow_profile) VALUES ('WF-P008','Standard');
INSERT INTO workflow_transition_rule_profiles(rule_id,workflow_profile) VALUES ('WF-P008','HighAssurance');
INSERT INTO workflow_transition_rule_profiles(rule_id,workflow_profile) VALUES ('WF-P008','ReadOnlyResearch');
INSERT INTO workflow_transition_rule_outcomes(rule_id,outcome_mode) VALUES ('WF-P008','ReadOnlyDeliverable');
INSERT INTO workflow_transition_rule_outcomes(rule_id,outcome_mode) VALUES ('WF-P008','WorkspaceChange');
INSERT INTO workflow_transition_rule_outcomes(rule_id,outcome_mode) VALUES ('WF-P008','LocalCommit');
INSERT INTO workflow_transition_rule_guard_requirements(rule_id,evidence_kind) VALUES ('WF-P008','accepted_severe_objection');
INSERT INTO workflow_transition_rule_effect_requirements(rule_id,effect_kind) VALUES ('WF-P008','increment_review_round');
INSERT INTO workflow_transition_rules(rule_id,event_type,to_phase,guard_expression) VALUES ('WF-P009','objection.severe.accepted','PrePlanVerification','reopen_criteria_satisfied AND workflow_profile=Quick');
INSERT INTO workflow_transition_rule_sources(rule_id,from_phase) VALUES ('WF-P009','FinalObjection');
INSERT INTO workflow_transition_rule_profiles(rule_id,workflow_profile) VALUES ('WF-P009','Quick');
INSERT INTO workflow_transition_rule_outcomes(rule_id,outcome_mode) VALUES ('WF-P009','ReadOnlyDeliverable');
INSERT INTO workflow_transition_rule_outcomes(rule_id,outcome_mode) VALUES ('WF-P009','WorkspaceChange');
INSERT INTO workflow_transition_rule_outcomes(rule_id,outcome_mode) VALUES ('WF-P009','LocalCommit');
INSERT INTO workflow_transition_rule_guard_requirements(rule_id,evidence_kind) VALUES ('WF-P009','accepted_severe_objection');
INSERT INTO workflow_transition_rule_effect_requirements(rule_id,effect_kind) VALUES ('WF-P009','increment_review_round');
INSERT INTO workflow_transition_rules(rule_id,event_type,to_phase,guard_expression) VALUES ('WF-P010','deliverable.review.ready','AwaitingDeliverableApproval','outcome_mode=ReadOnlyDeliverable AND no_accepted_severe_objection');
INSERT INTO workflow_transition_rule_sources(rule_id,from_phase) VALUES ('WF-P010','FinalObjection');
INSERT INTO workflow_transition_rule_profiles(rule_id,workflow_profile) VALUES ('WF-P010','Quick');
INSERT INTO workflow_transition_rule_profiles(rule_id,workflow_profile) VALUES ('WF-P010','Standard');
INSERT INTO workflow_transition_rule_profiles(rule_id,workflow_profile) VALUES ('WF-P010','HighAssurance');
INSERT INTO workflow_transition_rule_profiles(rule_id,workflow_profile) VALUES ('WF-P010','ReadOnlyResearch');
INSERT INTO workflow_transition_rule_outcomes(rule_id,outcome_mode) VALUES ('WF-P010','ReadOnlyDeliverable');
INSERT INTO workflow_transition_rule_guard_requirements(rule_id,evidence_kind) VALUES ('WF-P010','final_objection_clearance');
INSERT INTO workflow_transition_rule_effect_requirements(rule_id,effect_kind) VALUES ('WF-P010','freeze_deliverable_artifact');
INSERT INTO workflow_transition_rule_effect_requirements(rule_id,effect_kind) VALUES ('WF-P010','freeze_evidence_set');
INSERT INTO workflow_transition_rule_effect_requirements(rule_id,effect_kind) VALUES ('WF-P010','create_deliverable_approval_request');
INSERT INTO workflow_transition_rules(rule_id,event_type,to_phase,guard_expression) VALUES ('WF-P011','deliverable.revision.requested','Synthesis','user_feedback_present');
INSERT INTO workflow_transition_rule_sources(rule_id,from_phase) VALUES ('WF-P011','AwaitingDeliverableApproval');
INSERT INTO workflow_transition_rule_profiles(rule_id,workflow_profile) VALUES ('WF-P011','Quick');
INSERT INTO workflow_transition_rule_profiles(rule_id,workflow_profile) VALUES ('WF-P011','Standard');
INSERT INTO workflow_transition_rule_profiles(rule_id,workflow_profile) VALUES ('WF-P011','HighAssurance');
INSERT INTO workflow_transition_rule_profiles(rule_id,workflow_profile) VALUES ('WF-P011','ReadOnlyResearch');
INSERT INTO workflow_transition_rule_outcomes(rule_id,outcome_mode) VALUES ('WF-P011','ReadOnlyDeliverable');
INSERT INTO workflow_transition_rule_guard_requirements(rule_id,evidence_kind) VALUES ('WF-P011','user_feedback');
INSERT INTO workflow_transition_rule_effect_requirements(rule_id,effect_kind) VALUES ('WF-P011','supersede_deliverable');
INSERT INTO workflow_transition_rule_effect_requirements(rule_id,effect_kind) VALUES ('WF-P011','invalidate_deliverable_approval');
INSERT INTO workflow_transition_rules(rule_id,event_type,to_phase,guard_expression) VALUES ('WF-P012','deliverable.approved','Completed','outcome_mode=ReadOnlyDeliverable AND exact_deliverable_evidence_objections_evaluator_and_user_receipt_bound');
INSERT INTO workflow_transition_rule_sources(rule_id,from_phase) VALUES ('WF-P012','AwaitingDeliverableApproval');
INSERT INTO workflow_transition_rule_profiles(rule_id,workflow_profile) VALUES ('WF-P012','Quick');
INSERT INTO workflow_transition_rule_profiles(rule_id,workflow_profile) VALUES ('WF-P012','Standard');
INSERT INTO workflow_transition_rule_profiles(rule_id,workflow_profile) VALUES ('WF-P012','HighAssurance');
INSERT INTO workflow_transition_rule_profiles(rule_id,workflow_profile) VALUES ('WF-P012','ReadOnlyResearch');
INSERT INTO workflow_transition_rule_outcomes(rule_id,outcome_mode) VALUES ('WF-P012','ReadOnlyDeliverable');
INSERT INTO workflow_transition_rule_guard_requirements(rule_id,evidence_kind) VALUES ('WF-P012','deliverable_acceptance_receipt');
INSERT INTO workflow_transition_rule_effect_requirements(rule_id,effect_kind) VALUES ('WF-P012','create_read_only_completion_package');
INSERT INTO workflow_transition_rules(rule_id,event_type,to_phase,guard_expression) VALUES ('WF-P013','objection.round.closed','AwaitingPlanApproval','outcome_mode IN (WorkspaceChange,LocalCommit) AND no_accepted_severe_objection');
INSERT INTO workflow_transition_rule_sources(rule_id,from_phase) VALUES ('WF-P013','FinalObjection');
INSERT INTO workflow_transition_rule_profiles(rule_id,workflow_profile) VALUES ('WF-P013','Quick');
INSERT INTO workflow_transition_rule_profiles(rule_id,workflow_profile) VALUES ('WF-P013','Standard');
INSERT INTO workflow_transition_rule_profiles(rule_id,workflow_profile) VALUES ('WF-P013','HighAssurance');
INSERT INTO workflow_transition_rule_outcomes(rule_id,outcome_mode) VALUES ('WF-P013','WorkspaceChange');
INSERT INTO workflow_transition_rule_outcomes(rule_id,outcome_mode) VALUES ('WF-P013','LocalCommit');
INSERT INTO workflow_transition_rule_guard_requirements(rule_id,evidence_kind) VALUES ('WF-P013','final_objection_clearance');
INSERT INTO workflow_transition_rule_effect_requirements(rule_id,effect_kind) VALUES ('WF-P013','create_plan_approval_request');
INSERT INTO workflow_transition_rules(rule_id,event_type,to_phase,guard_expression) VALUES ('WF-P014','plan.revision.requested','Synthesis','user_feedback_present');
INSERT INTO workflow_transition_rule_sources(rule_id,from_phase) VALUES ('WF-P014','AwaitingPlanApproval');
INSERT INTO workflow_transition_rule_profiles(rule_id,workflow_profile) VALUES ('WF-P014','Quick');
INSERT INTO workflow_transition_rule_profiles(rule_id,workflow_profile) VALUES ('WF-P014','Standard');
INSERT INTO workflow_transition_rule_profiles(rule_id,workflow_profile) VALUES ('WF-P014','HighAssurance');
INSERT INTO workflow_transition_rule_outcomes(rule_id,outcome_mode) VALUES ('WF-P014','WorkspaceChange');
INSERT INTO workflow_transition_rule_outcomes(rule_id,outcome_mode) VALUES ('WF-P014','LocalCommit');
INSERT INTO workflow_transition_rule_guard_requirements(rule_id,evidence_kind) VALUES ('WF-P014','user_feedback');
INSERT INTO workflow_transition_rule_effect_requirements(rule_id,effect_kind) VALUES ('WF-P014','supersede_decision_draft');
INSERT INTO workflow_transition_rules(rule_id,event_type,to_phase,guard_expression) VALUES ('WF-P015','plan.approved','Implementation','plan_approval_digest_valid');
INSERT INTO workflow_transition_rule_sources(rule_id,from_phase) VALUES ('WF-P015','AwaitingPlanApproval');
INSERT INTO workflow_transition_rule_profiles(rule_id,workflow_profile) VALUES ('WF-P015','Quick');
INSERT INTO workflow_transition_rule_profiles(rule_id,workflow_profile) VALUES ('WF-P015','Standard');
INSERT INTO workflow_transition_rule_profiles(rule_id,workflow_profile) VALUES ('WF-P015','HighAssurance');
INSERT INTO workflow_transition_rule_outcomes(rule_id,outcome_mode) VALUES ('WF-P015','WorkspaceChange');
INSERT INTO workflow_transition_rule_outcomes(rule_id,outcome_mode) VALUES ('WF-P015','LocalCommit');
INSERT INTO workflow_transition_rule_guard_requirements(rule_id,evidence_kind) VALUES ('WF-P015','plan_approval_receipt');
INSERT INTO workflow_transition_rule_effect_requirements(rule_id,effect_kind) VALUES ('WF-P015','persist_approved_plan_version');
INSERT INTO workflow_transition_rule_effect_requirements(rule_id,effect_kind) VALUES ('WF-P015','allocate_executor_lease');
INSERT INTO workflow_transition_rules(rule_id,event_type,to_phase,guard_expression) VALUES ('WF-P016','candidate.prepared','Verification','no_in_flight_writes AND outcome_mode IN (WorkspaceChange,LocalCommit)');
INSERT INTO workflow_transition_rule_sources(rule_id,from_phase) VALUES ('WF-P016','Implementation');
INSERT INTO workflow_transition_rule_profiles(rule_id,workflow_profile) VALUES ('WF-P016','Quick');
INSERT INTO workflow_transition_rule_profiles(rule_id,workflow_profile) VALUES ('WF-P016','Standard');
INSERT INTO workflow_transition_rule_profiles(rule_id,workflow_profile) VALUES ('WF-P016','HighAssurance');
INSERT INTO workflow_transition_rule_outcomes(rule_id,outcome_mode) VALUES ('WF-P016','WorkspaceChange');
INSERT INTO workflow_transition_rule_outcomes(rule_id,outcome_mode) VALUES ('WF-P016','LocalCommit');
INSERT INTO workflow_transition_rule_guard_requirements(rule_id,evidence_kind) VALUES ('WF-P016','candidate_commit_receipt');
INSERT INTO workflow_transition_rule_effect_requirements(rule_id,effect_kind) VALUES ('WF-P016','revoke_executor_lease');
INSERT INTO workflow_transition_rule_effect_requirements(rule_id,effect_kind) VALUES ('WF-P016','reconcile_workspace');
INSERT INTO workflow_transition_rule_effect_requirements(rule_id,effect_kind) VALUES ('WF-P016','create_candidate_tree');
INSERT INTO workflow_transition_rule_effect_requirements(rule_id,effect_kind) VALUES ('WF-P016','create_complete_candidate_commit');
INSERT INTO workflow_transition_rule_effect_requirements(rule_id,effect_kind) VALUES ('WF-P016','persist_candidate_tree_oid');
INSERT INTO workflow_transition_rule_effect_requirements(rule_id,effect_kind) VALUES ('WF-P016','persist_candidate_commit_oid');
INSERT INTO workflow_transition_rules(rule_id,event_type,to_phase,guard_expression) VALUES ('WF-P017','verification.failed','Repair','repair_budget_available');
INSERT INTO workflow_transition_rule_sources(rule_id,from_phase) VALUES ('WF-P017','Verification');
INSERT INTO workflow_transition_rule_profiles(rule_id,workflow_profile) VALUES ('WF-P017','Quick');
INSERT INTO workflow_transition_rule_profiles(rule_id,workflow_profile) VALUES ('WF-P017','Standard');
INSERT INTO workflow_transition_rule_profiles(rule_id,workflow_profile) VALUES ('WF-P017','HighAssurance');
INSERT INTO workflow_transition_rule_outcomes(rule_id,outcome_mode) VALUES ('WF-P017','WorkspaceChange');
INSERT INTO workflow_transition_rule_outcomes(rule_id,outcome_mode) VALUES ('WF-P017','LocalCommit');
INSERT INTO workflow_transition_rule_guard_requirements(rule_id,evidence_kind) VALUES ('WF-P017','verification_failure_receipt');
INSERT INTO workflow_transition_rule_effect_requirements(rule_id,effect_kind) VALUES ('WF-P017','discard_candidate_tree');
INSERT INTO workflow_transition_rule_effect_requirements(rule_id,effect_kind) VALUES ('WF-P017','discard_candidate_commit');
INSERT INTO workflow_transition_rule_effect_requirements(rule_id,effect_kind) VALUES ('WF-P017','persist_failure_evidence');
INSERT INTO workflow_transition_rule_effect_requirements(rule_id,effect_kind) VALUES ('WF-P017','allocate_new_executor_token');
INSERT INTO workflow_transition_rules(rule_id,event_type,to_phase,guard_expression) VALUES ('WF-P018','verification.passed','FinalReview','required_suite_complete AND verification_cites_candidate_tree_oid_and_candidate_commit_oid');
INSERT INTO workflow_transition_rule_sources(rule_id,from_phase) VALUES ('WF-P018','Verification');
INSERT INTO workflow_transition_rule_profiles(rule_id,workflow_profile) VALUES ('WF-P018','Quick');
INSERT INTO workflow_transition_rule_profiles(rule_id,workflow_profile) VALUES ('WF-P018','Standard');
INSERT INTO workflow_transition_rule_profiles(rule_id,workflow_profile) VALUES ('WF-P018','HighAssurance');
INSERT INTO workflow_transition_rule_outcomes(rule_id,outcome_mode) VALUES ('WF-P018','WorkspaceChange');
INSERT INTO workflow_transition_rule_outcomes(rule_id,outcome_mode) VALUES ('WF-P018','LocalCommit');
INSERT INTO workflow_transition_rule_guard_requirements(rule_id,evidence_kind) VALUES ('WF-P018','final_commit_verification_receipt');
INSERT INTO workflow_transition_rule_effect_requirements(rule_id,effect_kind) VALUES ('WF-P018','freeze_verified_candidate_evidence');
INSERT INTO workflow_transition_rule_effect_requirements(rule_id,effect_kind) VALUES ('WF-P018','persist_final_commit_verification_receipt');
INSERT INTO workflow_transition_rules(rule_id,event_type,to_phase,guard_expression) VALUES ('WF-P019','candidate.prepared','Verification','current_fenced_executor_and_scoped_writes');
INSERT INTO workflow_transition_rule_sources(rule_id,from_phase) VALUES ('WF-P019','Repair');
INSERT INTO workflow_transition_rule_profiles(rule_id,workflow_profile) VALUES ('WF-P019','Quick');
INSERT INTO workflow_transition_rule_profiles(rule_id,workflow_profile) VALUES ('WF-P019','Standard');
INSERT INTO workflow_transition_rule_profiles(rule_id,workflow_profile) VALUES ('WF-P019','HighAssurance');
INSERT INTO workflow_transition_rule_outcomes(rule_id,outcome_mode) VALUES ('WF-P019','WorkspaceChange');
INSERT INTO workflow_transition_rule_outcomes(rule_id,outcome_mode) VALUES ('WF-P019','LocalCommit');
INSERT INTO workflow_transition_rule_guard_requirements(rule_id,evidence_kind) VALUES ('WF-P019','candidate_commit_receipt');
INSERT INTO workflow_transition_rule_effect_requirements(rule_id,effect_kind) VALUES ('WF-P019','increment_workspace_version');
INSERT INTO workflow_transition_rule_effect_requirements(rule_id,effect_kind) VALUES ('WF-P019','revoke_executor_lease');
INSERT INTO workflow_transition_rule_effect_requirements(rule_id,effect_kind) VALUES ('WF-P019','create_candidate_tree');
INSERT INTO workflow_transition_rule_effect_requirements(rule_id,effect_kind) VALUES ('WF-P019','create_complete_candidate_commit');
INSERT INTO workflow_transition_rule_effect_requirements(rule_id,effect_kind) VALUES ('WF-P019','persist_candidate_tree_oid');
INSERT INTO workflow_transition_rule_effect_requirements(rule_id,effect_kind) VALUES ('WF-P019','persist_candidate_commit_oid');
INSERT INTO workflow_transition_rules(rule_id,event_type,to_phase,guard_expression) VALUES ('WF-P020','review.changes.required','Repair','review_finding_accepted');
INSERT INTO workflow_transition_rule_sources(rule_id,from_phase) VALUES ('WF-P020','FinalReview');
INSERT INTO workflow_transition_rule_profiles(rule_id,workflow_profile) VALUES ('WF-P020','Quick');
INSERT INTO workflow_transition_rule_profiles(rule_id,workflow_profile) VALUES ('WF-P020','Standard');
INSERT INTO workflow_transition_rule_profiles(rule_id,workflow_profile) VALUES ('WF-P020','HighAssurance');
INSERT INTO workflow_transition_rule_outcomes(rule_id,outcome_mode) VALUES ('WF-P020','WorkspaceChange');
INSERT INTO workflow_transition_rule_outcomes(rule_id,outcome_mode) VALUES ('WF-P020','LocalCommit');
INSERT INTO workflow_transition_rule_guard_requirements(rule_id,evidence_kind) VALUES ('WF-P020','accepted_review_finding');
INSERT INTO workflow_transition_rule_effect_requirements(rule_id,effect_kind) VALUES ('WF-P020','discard_candidate_tree');
INSERT INTO workflow_transition_rule_effect_requirements(rule_id,effect_kind) VALUES ('WF-P020','discard_candidate_commit');
INSERT INTO workflow_transition_rule_effect_requirements(rule_id,effect_kind) VALUES ('WF-P020','invalidate_candidate_verification_receipt');
INSERT INTO workflow_transition_rule_effect_requirements(rule_id,effect_kind) VALUES ('WF-P020','allocate_new_executor_token');
INSERT INTO workflow_transition_rules(rule_id,event_type,to_phase,guard_expression) VALUES ('WF-P021','review.accepted','AwaitingWorkspaceApproval','outcome_mode=WorkspaceChange AND review_cites_candidate_tree_oid_and_candidate_commit_oid');
INSERT INTO workflow_transition_rule_sources(rule_id,from_phase) VALUES ('WF-P021','FinalReview');
INSERT INTO workflow_transition_rule_profiles(rule_id,workflow_profile) VALUES ('WF-P021','Quick');
INSERT INTO workflow_transition_rule_profiles(rule_id,workflow_profile) VALUES ('WF-P021','Standard');
INSERT INTO workflow_transition_rule_profiles(rule_id,workflow_profile) VALUES ('WF-P021','HighAssurance');
INSERT INTO workflow_transition_rule_outcomes(rule_id,outcome_mode) VALUES ('WF-P021','WorkspaceChange');
INSERT INTO workflow_transition_rule_guard_requirements(rule_id,evidence_kind) VALUES ('WF-P021','final_review_receipt');
INSERT INTO workflow_transition_rule_effect_requirements(rule_id,effect_kind) VALUES ('WF-P021','create_workspace_approval_request');
INSERT INTO workflow_transition_rules(rule_id,event_type,to_phase,guard_expression) VALUES ('WF-P022','workspace.repair.requested','Repair','user_feedback_present');
INSERT INTO workflow_transition_rule_sources(rule_id,from_phase) VALUES ('WF-P022','AwaitingWorkspaceApproval');
INSERT INTO workflow_transition_rule_profiles(rule_id,workflow_profile) VALUES ('WF-P022','Quick');
INSERT INTO workflow_transition_rule_profiles(rule_id,workflow_profile) VALUES ('WF-P022','Standard');
INSERT INTO workflow_transition_rule_profiles(rule_id,workflow_profile) VALUES ('WF-P022','HighAssurance');
INSERT INTO workflow_transition_rule_outcomes(rule_id,outcome_mode) VALUES ('WF-P022','WorkspaceChange');
INSERT INTO workflow_transition_rule_guard_requirements(rule_id,evidence_kind) VALUES ('WF-P022','user_feedback');
INSERT INTO workflow_transition_rule_effect_requirements(rule_id,effect_kind) VALUES ('WF-P022','discard_candidate_tree');
INSERT INTO workflow_transition_rule_effect_requirements(rule_id,effect_kind) VALUES ('WF-P022','discard_candidate_commit');
INSERT INTO workflow_transition_rule_effect_requirements(rule_id,effect_kind) VALUES ('WF-P022','invalidate_workspace_approval');
INSERT INTO workflow_transition_rule_effect_requirements(rule_id,effect_kind) VALUES ('WF-P022','allocate_new_executor_token');
INSERT INTO workflow_transition_rules(rule_id,event_type,to_phase,guard_expression) VALUES ('WF-P023','workspace.approved','Completed','outcome_mode=WorkspaceChange AND approval_binds_verified_workspace_candidate');
INSERT INTO workflow_transition_rule_sources(rule_id,from_phase) VALUES ('WF-P023','AwaitingWorkspaceApproval');
INSERT INTO workflow_transition_rule_profiles(rule_id,workflow_profile) VALUES ('WF-P023','Quick');
INSERT INTO workflow_transition_rule_profiles(rule_id,workflow_profile) VALUES ('WF-P023','Standard');
INSERT INTO workflow_transition_rule_profiles(rule_id,workflow_profile) VALUES ('WF-P023','HighAssurance');
INSERT INTO workflow_transition_rule_outcomes(rule_id,outcome_mode) VALUES ('WF-P023','WorkspaceChange');
INSERT INTO workflow_transition_rule_guard_requirements(rule_id,evidence_kind) VALUES ('WF-P023','workspace_acceptance_receipt');
INSERT INTO workflow_transition_rule_effect_requirements(rule_id,effect_kind) VALUES ('WF-P023','create_workspace_completion_package');
INSERT INTO workflow_transition_rules(rule_id,event_type,to_phase,guard_expression) VALUES ('WF-P024','review.accepted','AwaitingCommitApproval','outcome_mode=LocalCommit AND review_cites_candidate_tree_oid_and_candidate_commit_oid');
INSERT INTO workflow_transition_rule_sources(rule_id,from_phase) VALUES ('WF-P024','FinalReview');
INSERT INTO workflow_transition_rule_profiles(rule_id,workflow_profile) VALUES ('WF-P024','Quick');
INSERT INTO workflow_transition_rule_profiles(rule_id,workflow_profile) VALUES ('WF-P024','Standard');
INSERT INTO workflow_transition_rule_profiles(rule_id,workflow_profile) VALUES ('WF-P024','HighAssurance');
INSERT INTO workflow_transition_rule_outcomes(rule_id,outcome_mode) VALUES ('WF-P024','LocalCommit');
INSERT INTO workflow_transition_rule_guard_requirements(rule_id,evidence_kind) VALUES ('WF-P024','final_review_receipt');
INSERT INTO workflow_transition_rule_effect_requirements(rule_id,effect_kind) VALUES ('WF-P024','create_final_commit_approval_request');
INSERT INTO workflow_transition_rules(rule_id,event_type,to_phase,guard_expression) VALUES ('WF-P025','commit.repair.requested','Repair','user_feedback_present');
INSERT INTO workflow_transition_rule_sources(rule_id,from_phase) VALUES ('WF-P025','AwaitingCommitApproval');
INSERT INTO workflow_transition_rule_profiles(rule_id,workflow_profile) VALUES ('WF-P025','Quick');
INSERT INTO workflow_transition_rule_profiles(rule_id,workflow_profile) VALUES ('WF-P025','Standard');
INSERT INTO workflow_transition_rule_profiles(rule_id,workflow_profile) VALUES ('WF-P025','HighAssurance');
INSERT INTO workflow_transition_rule_outcomes(rule_id,outcome_mode) VALUES ('WF-P025','LocalCommit');
INSERT INTO workflow_transition_rule_guard_requirements(rule_id,evidence_kind) VALUES ('WF-P025','user_feedback');
INSERT INTO workflow_transition_rule_effect_requirements(rule_id,effect_kind) VALUES ('WF-P025','discard_candidate_tree');
INSERT INTO workflow_transition_rule_effect_requirements(rule_id,effect_kind) VALUES ('WF-P025','discard_candidate_commit');
INSERT INTO workflow_transition_rule_effect_requirements(rule_id,effect_kind) VALUES ('WF-P025','invalidate_candidate_and_approval');
INSERT INTO workflow_transition_rule_effect_requirements(rule_id,effect_kind) VALUES ('WF-P025','allocate_new_executor_token');
INSERT INTO workflow_transition_rules(rule_id,event_type,to_phase,guard_expression) VALUES ('WF-P026','commit.approved','RefPromotion','outcome_mode=LocalCommit AND approval_binds_candidate_commit_oid_and_expected_old_oid');
INSERT INTO workflow_transition_rule_sources(rule_id,from_phase) VALUES ('WF-P026','AwaitingCommitApproval');
INSERT INTO workflow_transition_rule_profiles(rule_id,workflow_profile) VALUES ('WF-P026','Quick');
INSERT INTO workflow_transition_rule_profiles(rule_id,workflow_profile) VALUES ('WF-P026','Standard');
INSERT INTO workflow_transition_rule_profiles(rule_id,workflow_profile) VALUES ('WF-P026','HighAssurance');
INSERT INTO workflow_transition_rule_outcomes(rule_id,outcome_mode) VALUES ('WF-P026','LocalCommit');
INSERT INTO workflow_transition_rule_guard_requirements(rule_id,evidence_kind) VALUES ('WF-P026','final_commit_approval_receipt');
INSERT INTO workflow_transition_rule_effect_requirements(rule_id,effect_kind) VALUES ('WF-P026','persist_final_commit_approval');
INSERT INTO workflow_transition_rules(rule_id,event_type,to_phase,guard_expression) VALUES ('WF-P027','ref.cas.succeeded','Completed','ref_now_equals_candidate_commit_oid AND expected_old_value_cas_succeeded');
INSERT INTO workflow_transition_rule_sources(rule_id,from_phase) VALUES ('WF-P027','RefPromotion');
INSERT INTO workflow_transition_rule_profiles(rule_id,workflow_profile) VALUES ('WF-P027','Quick');
INSERT INTO workflow_transition_rule_profiles(rule_id,workflow_profile) VALUES ('WF-P027','Standard');
INSERT INTO workflow_transition_rule_profiles(rule_id,workflow_profile) VALUES ('WF-P027','HighAssurance');
INSERT INTO workflow_transition_rule_outcomes(rule_id,outcome_mode) VALUES ('WF-P027','LocalCommit');
INSERT INTO workflow_transition_rule_guard_requirements(rule_id,evidence_kind) VALUES ('WF-P027','ref_promotion_receipt');
INSERT INTO workflow_transition_rule_effect_requirements(rule_id,effect_kind) VALUES ('WF-P027','persist_ref_promotion_receipt');
INSERT INTO workflow_transition_rule_effect_requirements(rule_id,effect_kind) VALUES ('WF-P027','create_local_commit_completion_package');
INSERT INTO workflow_transition_rules(rule_id,event_type,to_phase,guard_expression) VALUES ('WF-P028','ref.cas.failed','WorkspaceDirty','ref_or_workspace_diverged');
INSERT INTO workflow_transition_rule_sources(rule_id,from_phase) VALUES ('WF-P028','RefPromotion');
INSERT INTO workflow_transition_rule_profiles(rule_id,workflow_profile) VALUES ('WF-P028','Quick');
INSERT INTO workflow_transition_rule_profiles(rule_id,workflow_profile) VALUES ('WF-P028','Standard');
INSERT INTO workflow_transition_rule_profiles(rule_id,workflow_profile) VALUES ('WF-P028','HighAssurance');
INSERT INTO workflow_transition_rule_outcomes(rule_id,outcome_mode) VALUES ('WF-P028','LocalCommit');
INSERT INTO workflow_transition_rule_guard_requirements(rule_id,evidence_kind) VALUES ('WF-P028','ref_promotion_failure_receipt');
INSERT INTO workflow_transition_rule_effect_requirements(rule_id,effect_kind) VALUES ('WF-P028','preserve_candidate_commit');
INSERT INTO workflow_transition_rule_effect_requirements(rule_id,effect_kind) VALUES ('WF-P028','invalidate_final_commit_approval');
INSERT INTO workflow_transition_rule_effect_requirements(rule_id,effect_kind) VALUES ('WF-P028','capture_workspace_evidence');
INSERT INTO workflow_transition_rules(rule_id,event_type,to_phase,guard_expression) VALUES ('WF-P029','workspace.repair.authorized','Repair','mutation_evidence_preserved');
INSERT INTO workflow_transition_rule_sources(rule_id,from_phase) VALUES ('WF-P029','WorkspaceDirty');
INSERT INTO workflow_transition_rule_profiles(rule_id,workflow_profile) VALUES ('WF-P029','Quick');
INSERT INTO workflow_transition_rule_profiles(rule_id,workflow_profile) VALUES ('WF-P029','Standard');
INSERT INTO workflow_transition_rule_profiles(rule_id,workflow_profile) VALUES ('WF-P029','HighAssurance');
INSERT INTO workflow_transition_rule_outcomes(rule_id,outcome_mode) VALUES ('WF-P029','WorkspaceChange');
INSERT INTO workflow_transition_rule_outcomes(rule_id,outcome_mode) VALUES ('WF-P029','LocalCommit');
INSERT INTO workflow_transition_rule_guard_requirements(rule_id,evidence_kind) VALUES ('WF-P029','workspace_mutation_evidence');
INSERT INTO workflow_transition_rule_effect_requirements(rule_id,effect_kind) VALUES ('WF-P029','discard_candidate_tree');
INSERT INTO workflow_transition_rule_effect_requirements(rule_id,effect_kind) VALUES ('WF-P029','discard_candidate_commit');
INSERT INTO workflow_transition_rule_effect_requirements(rule_id,effect_kind) VALUES ('WF-P029','allocate_new_executor_token');
INSERT INTO workflow_transition_rules(rule_id,event_type,to_phase,guard_expression) VALUES ('WF-P030','workspace.reconciled','FinalReview','candidate_commit_rebuilt_and_verified');
INSERT INTO workflow_transition_rule_sources(rule_id,from_phase) VALUES ('WF-P030','WorkspaceDirty');
INSERT INTO workflow_transition_rule_profiles(rule_id,workflow_profile) VALUES ('WF-P030','Quick');
INSERT INTO workflow_transition_rule_profiles(rule_id,workflow_profile) VALUES ('WF-P030','Standard');
INSERT INTO workflow_transition_rule_profiles(rule_id,workflow_profile) VALUES ('WF-P030','HighAssurance');
INSERT INTO workflow_transition_rule_outcomes(rule_id,outcome_mode) VALUES ('WF-P030','WorkspaceChange');
INSERT INTO workflow_transition_rule_outcomes(rule_id,outcome_mode) VALUES ('WF-P030','LocalCommit');
INSERT INTO workflow_transition_rule_guard_requirements(rule_id,evidence_kind) VALUES ('WF-P030','workspace_reconciliation_receipt');
INSERT INTO workflow_transition_rule_effect_requirements(rule_id,effect_kind) VALUES ('WF-P030','create_candidate_tree');
INSERT INTO workflow_transition_rule_effect_requirements(rule_id,effect_kind) VALUES ('WF-P030','create_complete_candidate_commit');
INSERT INTO workflow_transition_rule_effect_requirements(rule_id,effect_kind) VALUES ('WF-P030','persist_final_commit_verification_receipt');
INSERT INTO workflow_transition_rules(rule_id,event_type,to_phase,guard_expression) VALUES ('WF-W001','workspace.mutated','WorkspaceDirty','workspace_mutation_detected_and_evidence_preserved');
INSERT INTO workflow_transition_rule_sources(rule_id,from_phase) VALUES ('WF-W001','Implementation');
INSERT INTO workflow_transition_rule_sources(rule_id,from_phase) VALUES ('WF-W001','Verification');
INSERT INTO workflow_transition_rule_sources(rule_id,from_phase) VALUES ('WF-W001','Repair');
INSERT INTO workflow_transition_rule_sources(rule_id,from_phase) VALUES ('WF-W001','FinalReview');
INSERT INTO workflow_transition_rule_sources(rule_id,from_phase) VALUES ('WF-W001','AwaitingWorkspaceApproval');
INSERT INTO workflow_transition_rule_sources(rule_id,from_phase) VALUES ('WF-W001','AwaitingCommitApproval');
INSERT INTO workflow_transition_rule_sources(rule_id,from_phase) VALUES ('WF-W001','RefPromotion');
INSERT INTO workflow_transition_rule_profiles(rule_id,workflow_profile) VALUES ('WF-W001','Quick');
INSERT INTO workflow_transition_rule_profiles(rule_id,workflow_profile) VALUES ('WF-W001','Standard');
INSERT INTO workflow_transition_rule_profiles(rule_id,workflow_profile) VALUES ('WF-W001','HighAssurance');
INSERT INTO workflow_transition_rule_outcomes(rule_id,outcome_mode) VALUES ('WF-W001','WorkspaceChange');
INSERT INTO workflow_transition_rule_outcomes(rule_id,outcome_mode) VALUES ('WF-W001','LocalCommit');
INSERT INTO workflow_transition_rule_guard_requirements(rule_id,evidence_kind) VALUES ('WF-W001','workspace_mutation_evidence');
INSERT INTO workflow_transition_rule_effect_requirements(rule_id,effect_kind) VALUES ('WF-W001','revoke_executor_lease');
INSERT INTO workflow_transition_rule_effect_requirements(rule_id,effect_kind) VALUES ('WF-W001','increment_fencing_epoch');
INSERT INTO workflow_transition_rule_effect_requirements(rule_id,effect_kind) VALUES ('WF-W001','invalidate_affected_approvals');
INSERT INTO workflow_transition_rule_effect_requirements(rule_id,effect_kind) VALUES ('WF-W001','discard_candidate_tree');
INSERT INTO workflow_transition_rule_effect_requirements(rule_id,effect_kind) VALUES ('WF-W001','discard_candidate_commit');
INSERT INTO workflow_transition_rule_effect_requirements(rule_id,effect_kind) VALUES ('WF-W001','stop_write_capable_tools');
INSERT INTO workflow_transition_rule_effect_requirements(rule_id,effect_kind) VALUES ('WF-W001','capture_workspace_evidence');
INSERT INTO workflow_transition_rules(rule_id,event_type,to_phase,guard_expression) VALUES ('WF-G001','task.cancelled','Cancelled','cancellation_authority_and_terminal_cleanup_valid');
INSERT INTO workflow_transition_rule_sources(rule_id,from_phase) VALUES ('WF-G001','Intake');
INSERT INTO workflow_transition_rule_sources(rule_id,from_phase) VALUES ('WF-G001','ContextBuild');
INSERT INTO workflow_transition_rule_sources(rule_id,from_phase) VALUES ('WF-G001','ParallelAnalysis');
INSERT INTO workflow_transition_rule_sources(rule_id,from_phase) VALUES ('WF-G001','CrossReview');
INSERT INTO workflow_transition_rule_sources(rule_id,from_phase) VALUES ('WF-G001','PrePlanVerification');
INSERT INTO workflow_transition_rule_sources(rule_id,from_phase) VALUES ('WF-G001','Synthesis');
INSERT INTO workflow_transition_rule_sources(rule_id,from_phase) VALUES ('WF-G001','FinalObjection');
INSERT INTO workflow_transition_rule_sources(rule_id,from_phase) VALUES ('WF-G001','AwaitingPlanApproval');
INSERT INTO workflow_transition_rule_sources(rule_id,from_phase) VALUES ('WF-G001','Implementation');
INSERT INTO workflow_transition_rule_sources(rule_id,from_phase) VALUES ('WF-G001','Verification');
INSERT INTO workflow_transition_rule_sources(rule_id,from_phase) VALUES ('WF-G001','Repair');
INSERT INTO workflow_transition_rule_sources(rule_id,from_phase) VALUES ('WF-G001','FinalReview');
INSERT INTO workflow_transition_rule_sources(rule_id,from_phase) VALUES ('WF-G001','AwaitingDeliverableApproval');
INSERT INTO workflow_transition_rule_sources(rule_id,from_phase) VALUES ('WF-G001','AwaitingWorkspaceApproval');
INSERT INTO workflow_transition_rule_sources(rule_id,from_phase) VALUES ('WF-G001','AwaitingCommitApproval');
INSERT INTO workflow_transition_rule_sources(rule_id,from_phase) VALUES ('WF-G001','RefPromotion');
INSERT INTO workflow_transition_rule_sources(rule_id,from_phase) VALUES ('WF-G001','WorkspaceDirty');
INSERT INTO workflow_transition_rule_profiles(rule_id,workflow_profile) VALUES ('WF-G001','Quick');
INSERT INTO workflow_transition_rule_profiles(rule_id,workflow_profile) VALUES ('WF-G001','Standard');
INSERT INTO workflow_transition_rule_profiles(rule_id,workflow_profile) VALUES ('WF-G001','HighAssurance');
INSERT INTO workflow_transition_rule_profiles(rule_id,workflow_profile) VALUES ('WF-G001','ReadOnlyResearch');
INSERT INTO workflow_transition_rule_outcomes(rule_id,outcome_mode) VALUES ('WF-G001','ReadOnlyDeliverable');
INSERT INTO workflow_transition_rule_outcomes(rule_id,outcome_mode) VALUES ('WF-G001','WorkspaceChange');
INSERT INTO workflow_transition_rule_outcomes(rule_id,outcome_mode) VALUES ('WF-G001','LocalCommit');
INSERT INTO workflow_transition_rule_guard_requirements(rule_id,evidence_kind) VALUES ('WF-G001','cancellation_receipt');
INSERT INTO workflow_transition_rule_effect_requirements(rule_id,effect_kind) VALUES ('WF-G001','revoke_executor_lease');
INSERT INTO workflow_transition_rule_effect_requirements(rule_id,effect_kind) VALUES ('WF-G001','stop_active_runs');
INSERT INTO workflow_transition_rule_effect_requirements(rule_id,effect_kind) VALUES ('WF-G001','persist_terminal_reason');
INSERT INTO workflow_transition_rules(rule_id,event_type,to_phase,guard_expression) VALUES ('WF-G002','task.failed','Failed','failure_classification_and_terminal_cleanup_valid');
INSERT INTO workflow_transition_rule_sources(rule_id,from_phase) VALUES ('WF-G002','Intake');
INSERT INTO workflow_transition_rule_sources(rule_id,from_phase) VALUES ('WF-G002','ContextBuild');
INSERT INTO workflow_transition_rule_sources(rule_id,from_phase) VALUES ('WF-G002','ParallelAnalysis');
INSERT INTO workflow_transition_rule_sources(rule_id,from_phase) VALUES ('WF-G002','CrossReview');
INSERT INTO workflow_transition_rule_sources(rule_id,from_phase) VALUES ('WF-G002','PrePlanVerification');
INSERT INTO workflow_transition_rule_sources(rule_id,from_phase) VALUES ('WF-G002','Synthesis');
INSERT INTO workflow_transition_rule_sources(rule_id,from_phase) VALUES ('WF-G002','FinalObjection');
INSERT INTO workflow_transition_rule_sources(rule_id,from_phase) VALUES ('WF-G002','AwaitingPlanApproval');
INSERT INTO workflow_transition_rule_sources(rule_id,from_phase) VALUES ('WF-G002','Implementation');
INSERT INTO workflow_transition_rule_sources(rule_id,from_phase) VALUES ('WF-G002','Verification');
INSERT INTO workflow_transition_rule_sources(rule_id,from_phase) VALUES ('WF-G002','Repair');
INSERT INTO workflow_transition_rule_sources(rule_id,from_phase) VALUES ('WF-G002','FinalReview');
INSERT INTO workflow_transition_rule_sources(rule_id,from_phase) VALUES ('WF-G002','AwaitingDeliverableApproval');
INSERT INTO workflow_transition_rule_sources(rule_id,from_phase) VALUES ('WF-G002','AwaitingWorkspaceApproval');
INSERT INTO workflow_transition_rule_sources(rule_id,from_phase) VALUES ('WF-G002','AwaitingCommitApproval');
INSERT INTO workflow_transition_rule_sources(rule_id,from_phase) VALUES ('WF-G002','RefPromotion');
INSERT INTO workflow_transition_rule_sources(rule_id,from_phase) VALUES ('WF-G002','WorkspaceDirty');
INSERT INTO workflow_transition_rule_profiles(rule_id,workflow_profile) VALUES ('WF-G002','Quick');
INSERT INTO workflow_transition_rule_profiles(rule_id,workflow_profile) VALUES ('WF-G002','Standard');
INSERT INTO workflow_transition_rule_profiles(rule_id,workflow_profile) VALUES ('WF-G002','HighAssurance');
INSERT INTO workflow_transition_rule_profiles(rule_id,workflow_profile) VALUES ('WF-G002','ReadOnlyResearch');
INSERT INTO workflow_transition_rule_outcomes(rule_id,outcome_mode) VALUES ('WF-G002','ReadOnlyDeliverable');
INSERT INTO workflow_transition_rule_outcomes(rule_id,outcome_mode) VALUES ('WF-G002','WorkspaceChange');
INSERT INTO workflow_transition_rule_outcomes(rule_id,outcome_mode) VALUES ('WF-G002','LocalCommit');
INSERT INTO workflow_transition_rule_guard_requirements(rule_id,evidence_kind) VALUES ('WF-G002','failure_receipt');
INSERT INTO workflow_transition_rule_effect_requirements(rule_id,effect_kind) VALUES ('WF-G002','revoke_executor_lease');
INSERT INTO workflow_transition_rule_effect_requirements(rule_id,effect_kind) VALUES ('WF-G002','stop_active_runs');
INSERT INTO workflow_transition_rule_effect_requirements(rule_id,effect_kind) VALUES ('WF-G002','persist_terminal_reason');

CREATE TABLE workflow_transition_events (
    id TEXT PRIMARY KEY,
    task_id TEXT NOT NULL REFERENCES tasks(id) ON DELETE RESTRICT,
    rule_id TEXT NOT NULL REFERENCES workflow_transition_rules(rule_id) ON DELETE RESTRICT,
    expected_stream_version INTEGER NOT NULL CHECK (expected_stream_version >= 0),
    from_phase TEXT NOT NULL,
    event_type TEXT NOT NULL,
    to_phase TEXT NOT NULL,
    workflow_profile TEXT NOT NULL CHECK (workflow_profile IN ('Quick','Standard','HighAssurance','ReadOnlyResearch')), 
    outcome_mode TEXT NOT NULL CHECK (outcome_mode IN ('ReadOnlyDeliverable','WorkspaceChange','LocalCommit')), 
    transition_command_artifact_id TEXT NOT NULL REFERENCES artifacts(id) ON DELETE RESTRICT,
    guard_set_digest TEXT NOT NULL CHECK (length(guard_set_digest)=71 AND substr(guard_set_digest,1,7)='sha256:' AND substr(guard_set_digest,8) NOT GLOB '*[^0-9a-f]*'),
    effect_set_digest TEXT NOT NULL CHECK (length(effect_set_digest)=71 AND substr(effect_set_digest,1,7)='sha256:' AND substr(effect_set_digest,8) NOT GLOB '*[^0-9a-f]*'),
    core_actor_digest TEXT NOT NULL CHECK (length(core_actor_digest)=71 AND substr(core_actor_digest,1,7)='sha256:' AND substr(core_actor_digest,8) NOT GLOB '*[^0-9a-f]*'),
    reducer_version TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('prepared','accepted','rejected')), 
    prepared_at TEXT NOT NULL,
    accepted_at TEXT,
    rejected_at TEXT,
    CHECK ((status='prepared' AND accepted_at IS NULL AND rejected_at IS NULL) OR (status='accepted' AND accepted_at IS NOT NULL AND rejected_at IS NULL) OR (status='rejected' AND accepted_at IS NULL AND rejected_at IS NOT NULL))
) STRICT;
CREATE UNIQUE INDEX workflow_transition_one_live_per_version
ON workflow_transition_events(task_id, expected_stream_version)
WHERE status IN ('prepared','accepted');

CREATE TABLE workflow_transition_guard_bindings (
    transition_event_id TEXT NOT NULL REFERENCES workflow_transition_events(id) ON DELETE RESTRICT,
    evidence_kind TEXT NOT NULL,
    evidence_ref TEXT NOT NULL,
    subject_digest TEXT CHECK (subject_digest IS NULL OR (length(subject_digest)=71 AND substr(subject_digest,1,7)='sha256:' AND substr(subject_digest,8) NOT GLOB '*[^0-9a-f]*')),
    evidence_digest TEXT NOT NULL CHECK (length(evidence_digest)=71 AND substr(evidence_digest,1,7)='sha256:' AND substr(evidence_digest,8) NOT GLOB '*[^0-9a-f]*'),
    artifact_id TEXT REFERENCES artifacts(id) ON DELETE RESTRICT,
    approval_receipt_id TEXT REFERENCES approval_decision_receipts(id) ON DELETE RESTRICT,
    acceptance_receipt_id TEXT REFERENCES task_acceptance_receipts(id) ON DELETE RESTRICT,
    verification_receipt_id TEXT REFERENCES final_commit_verification_receipts(id) ON DELETE RESTRICT,
    ref_promotion_receipt_id TEXT REFERENCES ref_promotion_receipts(id) ON DELETE RESTRICT,
    PRIMARY KEY (transition_event_id, evidence_kind, evidence_ref)
) WITHOUT ROWID, STRICT;
CREATE TABLE workflow_transition_effect_bindings (
    transition_event_id TEXT NOT NULL REFERENCES workflow_transition_events(id) ON DELETE RESTRICT,
    effect_kind TEXT NOT NULL,
    effect_ref TEXT NOT NULL,
    effect_digest TEXT NOT NULL CHECK (length(effect_digest)=71 AND substr(effect_digest,1,7)='sha256:' AND substr(effect_digest,8) NOT GLOB '*[^0-9a-f]*'),
    artifact_id TEXT REFERENCES artifacts(id) ON DELETE RESTRICT,
    PRIMARY KEY (transition_event_id, effect_kind, effect_ref)
) WITHOUT ROWID, STRICT;

CREATE TABLE workflow_profile_revisions (
    id TEXT PRIMARY KEY,
    task_id TEXT NOT NULL REFERENCES tasks(id) ON DELETE RESTRICT,
    revision_no INTEGER NOT NULL CHECK (revision_no >= 2),
    expected_stream_version INTEGER NOT NULL CHECK (expected_stream_version >= 0),
    from_profile TEXT NOT NULL CHECK (from_profile IN ('Quick','Standard')), 
    to_profile TEXT NOT NULL CHECK (to_profile IN ('Standard','HighAssurance')), 
    reason_artifact_id TEXT NOT NULL REFERENCES artifacts(id) ON DELETE RESTRICT,
    policy_digest TEXT NOT NULL CHECK (length(policy_digest)=71 AND substr(policy_digest,1,7)='sha256:' AND substr(policy_digest,8) NOT GLOB '*[^0-9a-f]*'),
    decided_by_kind TEXT NOT NULL CHECK (decided_by_kind IN ('core','system','user')), 
    actor_binding_id TEXT REFERENCES actor_bindings(id) ON DELETE RESTRICT,
    created_at TEXT NOT NULL,
    receipt_digest TEXT NOT NULL UNIQUE CHECK (length(receipt_digest)=71 AND substr(receipt_digest,1,7)='sha256:' AND substr(receipt_digest,8) NOT GLOB '*[^0-9a-f]*'),
    UNIQUE (task_id, revision_no),
    UNIQUE (task_id, expected_stream_version),
    CHECK ((from_profile='Quick' AND to_profile IN ('Standard','HighAssurance')) OR (from_profile='Standard' AND to_profile='HighAssurance')), 
    CHECK (decided_by_kind<>'user' OR actor_binding_id IS NOT NULL)
) STRICT;

ALTER TABLE task_workflow_authority ADD COLUMN stream_version INTEGER NOT NULL DEFAULT 0 CHECK (stream_version >= 0);
ALTER TABLE task_workflow_authority ADD COLUMN last_transition_event_id TEXT REFERENCES workflow_transition_events(id) ON DELETE RESTRICT;
ALTER TABLE task_workflow_authority ADD COLUMN profile_revision INTEGER NOT NULL DEFAULT 1 CHECK (profile_revision >= 1);
ALTER TABLE task_workflow_authority ADD COLUMN last_profile_revision_id TEXT REFERENCES workflow_profile_revisions(id) ON DELETE RESTRICT;

DROP TRIGGER task_workflow_phase_transition;
DROP TRIGGER task_workflow_selection_immutable;
DROP TRIGGER task_workflow_terminal_irreversible;

CREATE TRIGGER workflow_transition_event_insert_guard BEFORE INSERT ON workflow_transition_events FOR EACH ROW BEGIN
    SELECT CASE WHEN NEW.status<>'prepared' OR NEW.accepted_at IS NOT NULL OR NEW.rejected_at IS NOT NULL
      THEN RAISE(ABORT,'new workflow transition event must be prepared') END;
    SELECT CASE WHEN NOT EXISTS (
      SELECT 1
      FROM task_workflow_authority w
      JOIN tasks t ON t.id=w.task_id
      JOIN artifacts a ON a.id=NEW.transition_command_artifact_id
      WHERE w.task_id=NEW.task_id
        AND w.phase=NEW.from_phase
        AND w.workflow_profile=NEW.workflow_profile
        AND w.outcome_mode=NEW.outcome_mode
        AND w.stream_version=NEW.expected_stream_version
        AND a.project_id=t.project_id
        AND (a.task_id IS NULL OR a.task_id=NEW.task_id)
        AND a.artifact_type IN ('workflow_transition_command','receipt','json')
    ) THEN RAISE(ABORT,'workflow transition event does not bind current authority and scoped command artifact') END;
    SELECT CASE WHEN NOT EXISTS (
      SELECT 1 FROM workflow_transition_rules r
      WHERE r.rule_id=NEW.rule_id AND r.event_type=NEW.event_type AND r.to_phase=NEW.to_phase
    ) THEN RAISE(ABORT,'workflow transition event does not match a declared rule') END;
    SELECT CASE WHEN NOT EXISTS (SELECT 1 FROM workflow_transition_rule_sources s WHERE s.rule_id=NEW.rule_id AND s.from_phase=NEW.from_phase)
      THEN RAISE(ABORT,'workflow transition source phase is not allowed by the rule') END;
    SELECT CASE WHEN NOT EXISTS (SELECT 1 FROM workflow_transition_rule_profiles p WHERE p.rule_id=NEW.rule_id AND p.workflow_profile=NEW.workflow_profile)
      THEN RAISE(ABORT,'workflow transition profile route is not allowed by the rule') END;
    SELECT CASE WHEN NOT EXISTS (SELECT 1 FROM workflow_transition_rule_outcomes o WHERE o.rule_id=NEW.rule_id AND o.outcome_mode=NEW.outcome_mode)
      THEN RAISE(ABORT,'workflow transition outcome route is not allowed by the rule') END;
END;

CREATE TRIGGER workflow_transition_guard_insert_guard BEFORE INSERT ON workflow_transition_guard_bindings FOR EACH ROW BEGIN
    SELECT CASE WHEN NOT EXISTS (SELECT 1 FROM workflow_transition_events e WHERE e.id=NEW.transition_event_id AND e.status='prepared') THEN RAISE(ABORT,'guard evidence may bind only a prepared transition') END;
    SELECT CASE WHEN NEW.evidence_kind='plan_approval_receipt' AND NOT EXISTS (
      SELECT 1 FROM workflow_transition_events e JOIN approval_decision_receipts r ON r.id=NEW.approval_receipt_id JOIN approvals ap ON ap.id=r.approval_id
      WHERE e.id=NEW.transition_event_id AND r.task_id=e.task_id AND r.decision='granted' AND ap.status='granted' AND ap.approval_type='plan'
        AND NEW.evidence_ref=r.id AND NEW.evidence_digest=r.receipt_digest AND NEW.subject_digest=r.operation_digest
    ) THEN RAISE(ABORT,'plan approval receipt must be exact and granted') END;
    SELECT CASE WHEN NEW.evidence_kind='deliverable_acceptance_receipt' AND NOT EXISTS (
      SELECT 1 FROM workflow_transition_events e JOIN task_acceptance_receipts r ON r.id=NEW.acceptance_receipt_id WHERE e.id=NEW.transition_event_id AND r.task_id=e.task_id AND r.acceptance_kind='deliverable' AND NEW.evidence_ref=r.id AND NEW.evidence_digest=r.receipt_digest AND NEW.subject_digest=r.operation_digest
    ) THEN RAISE(ABORT,'deliverable acceptance receipt must be exact') END;
    SELECT CASE WHEN NEW.evidence_kind='workspace_acceptance_receipt' AND NOT EXISTS (
      SELECT 1 FROM workflow_transition_events e JOIN task_acceptance_receipts r ON r.id=NEW.acceptance_receipt_id WHERE e.id=NEW.transition_event_id AND r.task_id=e.task_id AND r.acceptance_kind='workspace' AND NEW.evidence_ref=r.id AND NEW.evidence_digest=r.receipt_digest AND NEW.subject_digest=r.operation_digest
    ) THEN RAISE(ABORT,'workspace acceptance receipt must be exact') END;
    SELECT CASE WHEN NEW.evidence_kind='final_commit_approval_receipt' AND NOT EXISTS (
      SELECT 1 FROM workflow_transition_events e JOIN approval_decision_receipts r ON r.id=NEW.approval_receipt_id JOIN approvals ap ON ap.id=r.approval_id WHERE e.id=NEW.transition_event_id AND r.task_id=e.task_id AND r.decision='granted' AND ap.status='granted' AND ap.approval_type='final_commit' AND NEW.evidence_ref=r.id AND NEW.evidence_digest=r.receipt_digest AND NEW.subject_digest=r.operation_digest
    ) THEN RAISE(ABORT,'final commit approval receipt must be exact and granted') END;
    SELECT CASE WHEN NEW.evidence_kind='final_commit_verification_receipt' AND NOT EXISTS (
      SELECT 1 FROM workflow_transition_events e JOIN final_commit_verification_receipts r ON r.id=NEW.verification_receipt_id WHERE e.id=NEW.transition_event_id AND r.task_id=e.task_id AND NEW.evidence_ref=r.id AND NEW.evidence_digest=r.receipt_digest
    ) THEN RAISE(ABORT,'final commit verification receipt must be exact') END;
    SELECT CASE WHEN NEW.evidence_kind='ref_promotion_receipt' AND NOT EXISTS (
      SELECT 1 FROM workflow_transition_events e JOIN ref_promotion_receipts r ON r.id=NEW.ref_promotion_receipt_id WHERE e.id=NEW.transition_event_id AND r.task_id=e.task_id AND NEW.evidence_ref=r.id AND NEW.evidence_digest=r.receipt_digest
    ) THEN RAISE(ABORT,'ref promotion receipt must be exact') END;
END;
CREATE TRIGGER workflow_transition_effect_insert_guard BEFORE INSERT ON workflow_transition_effect_bindings FOR EACH ROW BEGIN
    SELECT CASE WHEN NOT EXISTS (SELECT 1 FROM workflow_transition_events e WHERE e.id=NEW.transition_event_id AND e.status='prepared') THEN RAISE(ABORT,'effects may bind only a prepared transition') END;
END;

CREATE TRIGGER workflow_transition_accept_guard BEFORE UPDATE OF status,accepted_at,rejected_at ON workflow_transition_events FOR EACH ROW BEGIN
    SELECT CASE WHEN OLD.status<>'prepared' THEN RAISE(ABORT,'terminal workflow transition event is immutable') END;
    SELECT CASE WHEN NEW.status NOT IN ('accepted','rejected') THEN RAISE(ABORT,'prepared workflow transition may only be accepted or rejected') END;
    SELECT CASE WHEN NEW.status='accepted' AND (NEW.accepted_at IS NULL OR NEW.rejected_at IS NOT NULL) THEN RAISE(ABORT,'accepted workflow transition requires accepted_at only') END;
    SELECT CASE WHEN NEW.status='rejected' AND (NEW.rejected_at IS NULL OR NEW.accepted_at IS NOT NULL) THEN RAISE(ABORT,'rejected workflow transition requires rejected_at only') END;
    SELECT CASE WHEN NEW.status='accepted' AND NOT EXISTS (
      SELECT 1 FROM task_workflow_authority w WHERE w.task_id=OLD.task_id AND w.phase=OLD.from_phase AND w.workflow_profile=OLD.workflow_profile AND w.outcome_mode=OLD.outcome_mode AND w.stream_version=OLD.expected_stream_version
    ) THEN RAISE(ABORT,'accepted workflow transition is stale') END;
    SELECT CASE WHEN NEW.status='accepted' AND EXISTS (
      SELECT 1 FROM workflow_transition_rule_guard_requirements r WHERE r.rule_id=OLD.rule_id AND (SELECT count(*) FROM workflow_transition_guard_bindings b WHERE b.transition_event_id=OLD.id AND b.evidence_kind=r.evidence_kind)<r.minimum_count
    ) THEN RAISE(ABORT,'accepted workflow transition is missing required guard evidence') END;
    SELECT CASE WHEN NEW.status='accepted' AND EXISTS (
      SELECT 1 FROM workflow_transition_rule_effect_requirements r WHERE r.rule_id=OLD.rule_id AND (SELECT count(*) FROM workflow_transition_effect_bindings b WHERE b.transition_event_id=OLD.id AND b.effect_kind=r.effect_kind)<r.minimum_count
    ) THEN RAISE(ABORT,'accepted workflow transition is missing required effects') END;
END;
CREATE TRIGGER workflow_transition_event_identity_immutable BEFORE UPDATE OF task_id,rule_id,expected_stream_version,from_phase,event_type,to_phase,workflow_profile,outcome_mode,transition_command_artifact_id,guard_set_digest,effect_set_digest,core_actor_digest,reducer_version,prepared_at ON workflow_transition_events FOR EACH ROW BEGIN SELECT RAISE(ABORT,'workflow transition event identity is immutable'); END;
CREATE TRIGGER workflow_transition_event_delete_forbidden BEFORE DELETE ON workflow_transition_events FOR EACH ROW BEGIN SELECT RAISE(ABORT,'workflow transition events are retained'); END;
CREATE TRIGGER workflow_transition_guard_update_forbidden BEFORE UPDATE ON workflow_transition_guard_bindings FOR EACH ROW BEGIN SELECT RAISE(ABORT,'workflow transition guard bindings are immutable'); END;
CREATE TRIGGER workflow_transition_guard_delete_forbidden BEFORE DELETE ON workflow_transition_guard_bindings FOR EACH ROW BEGIN SELECT RAISE(ABORT,'workflow transition guard bindings are retained'); END;
CREATE TRIGGER workflow_transition_effect_update_forbidden BEFORE UPDATE ON workflow_transition_effect_bindings FOR EACH ROW BEGIN SELECT RAISE(ABORT,'workflow transition effect bindings are immutable'); END;
CREATE TRIGGER workflow_transition_effect_delete_forbidden BEFORE DELETE ON workflow_transition_effect_bindings FOR EACH ROW BEGIN SELECT RAISE(ABORT,'workflow transition effect bindings are retained'); END;

CREATE TRIGGER workflow_profile_revision_insert_guard BEFORE INSERT ON workflow_profile_revisions FOR EACH ROW BEGIN
    SELECT CASE WHEN NOT EXISTS (
      SELECT 1 FROM task_workflow_authority w JOIN tasks t ON t.id=w.task_id JOIN artifacts a ON a.id=NEW.reason_artifact_id
      WHERE w.task_id=NEW.task_id AND w.phase NOT IN ('Completed','Cancelled','Failed') AND w.workflow_profile=NEW.from_profile AND w.stream_version=NEW.expected_stream_version AND NEW.revision_no=w.profile_revision+1
        AND a.project_id=t.project_id AND (a.task_id IS NULL OR a.task_id=NEW.task_id)
    ) THEN RAISE(ABORT,'workflow profile escalation is stale or unscoped') END;
    SELECT CASE WHEN NEW.decided_by_kind='user' AND NOT EXISTS (SELECT 1 FROM actor_bindings b WHERE b.id=NEW.actor_binding_id AND b.revoked_at IS NULL AND b.expires_at>NEW.created_at) THEN RAISE(ABORT,'workflow profile escalation user binding is not current') END;
END;
CREATE TRIGGER workflow_profile_revision_update_forbidden BEFORE UPDATE ON workflow_profile_revisions FOR EACH ROW BEGIN SELECT RAISE(ABORT,'workflow profile revisions are immutable'); END;
CREATE TRIGGER workflow_profile_revision_delete_forbidden BEFORE DELETE ON workflow_profile_revisions FOR EACH ROW BEGIN SELECT RAISE(ABORT,'workflow profile revisions are retained'); END;

CREATE TRIGGER task_workflow_v7_update_guard BEFORE UPDATE ON task_workflow_authority FOR EACH ROW BEGIN
    SELECT CASE WHEN NEW.outcome_mode IS NOT OLD.outcome_mode OR NEW.selected_by_kind IS NOT OLD.selected_by_kind OR NEW.selected_by_actor_binding_id IS NOT OLD.selected_by_actor_binding_id OR NEW.selection_policy_digest IS NOT OLD.selection_policy_digest OR NEW.created_at IS NOT OLD.created_at THEN RAISE(ABORT,'workflow outcome and initial selection are immutable') END;
    SELECT CASE WHEN OLD.phase IN ('Completed','Cancelled','Failed') AND (NEW.phase IS NOT OLD.phase OR NEW.workflow_profile IS NOT OLD.workflow_profile) THEN RAISE(ABORT,'terminal workflow authority is irreversible') END;
    SELECT CASE WHEN NEW.phase IS NOT OLD.phase AND NEW.workflow_profile IS NOT OLD.workflow_profile THEN RAISE(ABORT,'phase transition and profile escalation are separate atomic commands') END;
    SELECT CASE WHEN (NEW.phase IS NOT OLD.phase OR NEW.workflow_profile IS NOT OLD.workflow_profile) AND NEW.updated_at<=OLD.updated_at THEN RAISE(ABORT,'workflow authority time must increase') END;
    SELECT CASE WHEN NEW.phase IS NOT OLD.phase AND NOT (
      NEW.workflow_profile=OLD.workflow_profile AND NEW.profile_revision=OLD.profile_revision AND NEW.last_profile_revision_id IS OLD.last_profile_revision_id
      AND NEW.stream_version=OLD.stream_version+1 AND NEW.last_transition_event_id IS NOT NULL AND NEW.last_transition_event_id IS NOT OLD.last_transition_event_id
      AND EXISTS (SELECT 1 FROM workflow_transition_events e WHERE e.id=NEW.last_transition_event_id AND e.task_id=OLD.task_id AND e.status='accepted' AND e.expected_stream_version=OLD.stream_version AND e.from_phase=OLD.phase AND e.to_phase=NEW.phase AND e.workflow_profile=OLD.workflow_profile AND e.outcome_mode=OLD.outcome_mode)
    ) THEN RAISE(ABORT,'workflow projection phase update requires the matching accepted transition event') END;
    SELECT CASE WHEN NEW.workflow_profile IS NOT OLD.workflow_profile AND NOT (
      NEW.phase=OLD.phase AND NEW.stream_version=OLD.stream_version+1 AND NEW.last_transition_event_id IS OLD.last_transition_event_id
      AND NEW.profile_revision=OLD.profile_revision+1 AND NEW.last_profile_revision_id IS NOT NULL AND NEW.last_profile_revision_id IS NOT OLD.last_profile_revision_id
      AND EXISTS (SELECT 1 FROM workflow_profile_revisions r WHERE r.id=NEW.last_profile_revision_id AND r.task_id=OLD.task_id AND r.expected_stream_version=OLD.stream_version AND r.revision_no=NEW.profile_revision AND r.from_profile=OLD.workflow_profile AND r.to_profile=NEW.workflow_profile)
    ) THEN RAISE(ABORT,'workflow profile update requires a matching monotonic escalation receipt') END;
    SELECT CASE WHEN NEW.phase=OLD.phase AND NEW.workflow_profile=OLD.workflow_profile AND (NEW.stream_version<>OLD.stream_version OR NEW.last_transition_event_id IS NOT OLD.last_transition_event_id OR NEW.profile_revision<>OLD.profile_revision OR NEW.last_profile_revision_id IS NOT OLD.last_profile_revision_id) THEN RAISE(ABORT,'workflow authority versions cannot change without an accepted command') END;
    SELECT CASE WHEN NEW.phase='Completed' AND OLD.phase='AwaitingDeliverableApproval' AND NOT EXISTS (SELECT 1 FROM task_acceptance_receipts r WHERE r.task_id=OLD.task_id AND r.acceptance_kind='deliverable') THEN RAISE(ABORT,'read-only completion requires a deliverable acceptance receipt') END;
    SELECT CASE WHEN NEW.phase='Completed' AND OLD.phase='AwaitingWorkspaceApproval' AND NOT EXISTS (SELECT 1 FROM task_acceptance_receipts r WHERE r.task_id=OLD.task_id AND r.acceptance_kind='workspace') THEN RAISE(ABORT,'workspace completion requires a workspace acceptance receipt') END;
    SELECT CASE WHEN NEW.phase='Completed' AND OLD.phase='RefPromotion' AND NOT EXISTS (SELECT 1 FROM ref_promotion_receipts r WHERE r.task_id=OLD.task_id) THEN RAISE(ABORT,'local commit completion requires successful ref promotion evidence') END;
    SELECT CASE WHEN NEW.phase IN ('Completed','Cancelled','Failed') AND NEW.completed_at IS NULL THEN RAISE(ABORT,'terminal workflow requires completion time') END;
    SELECT CASE WHEN NEW.phase NOT IN ('Completed','Cancelled','Failed') AND NEW.completed_at IS NOT NULL THEN RAISE(ABORT,'nonterminal workflow cannot contain completion time') END;
    SELECT CASE WHEN OLD.completed_at IS NOT NULL AND NEW.completed_at IS NOT OLD.completed_at THEN RAISE(ABORT,'workflow completion time is set-once') END;
END;

CREATE TABLE run_configuration_bindings (
    run_id TEXT PRIMARY KEY REFERENCES agent_runs(id) ON DELETE RESTRICT,
    config_artifact_id TEXT NOT NULL UNIQUE REFERENCES artifacts(id) ON DELETE RESTRICT,
    config_digest TEXT NOT NULL UNIQUE CHECK (length(config_digest)=71 AND substr(config_digest,1,7)='sha256:' AND substr(config_digest,8) NOT GLOB '*[^0-9a-f]*'),
    provider_connection_ref TEXT NOT NULL,
    adapter_id TEXT NOT NULL,
    resolved_model_id TEXT NOT NULL,
    independence_group TEXT NOT NULL,
    independence_fingerprint TEXT NOT NULL CHECK (length(independence_fingerprint)=71 AND substr(independence_fingerprint,1,7)='sha256:' AND substr(independence_fingerprint,8) NOT GLOB '*[^0-9a-f]*'),
    created_at TEXT NOT NULL
) STRICT;
CREATE TRIGGER run_configuration_binding_scope BEFORE INSERT ON run_configuration_bindings FOR EACH ROW BEGIN
    SELECT CASE WHEN NOT EXISTS (SELECT 1 FROM agent_runs r JOIN tasks t ON t.id=r.task_id JOIN artifacts a ON a.id=NEW.config_artifact_id WHERE r.id=NEW.run_id AND r.run_config_artifact_id=NEW.config_artifact_id AND a.project_id=t.project_id AND (a.task_id IS NULL OR a.task_id=r.task_id) AND a.content_hash=NEW.config_digest) THEN RAISE(ABORT,'run configuration binding must match the exact run artifact') END;
END;
CREATE TRIGGER run_configuration_binding_update_forbidden BEFORE UPDATE ON run_configuration_bindings FOR EACH ROW BEGIN SELECT RAISE(ABORT,'run configuration bindings are immutable'); END;
CREATE TRIGGER run_configuration_binding_delete_forbidden BEFORE DELETE ON run_configuration_bindings FOR EACH ROW BEGIN SELECT RAISE(ABORT,'run configuration bindings are retained'); END;

CREATE TABLE assurance_degradation_receipts (
    id TEXT PRIMARY KEY,
    task_id TEXT NOT NULL REFERENCES tasks(id) ON DELETE RESTRICT,
    requested_profile TEXT NOT NULL CHECK (requested_profile IN ('Standard','HighAssurance')), 
    reason_code TEXT NOT NULL CHECK (reason_code IN ('insufficient_independence_groups','role_separation_unavailable','provider_unavailable','budget_insufficient')), 
    run_set_digest TEXT NOT NULL CHECK (length(run_set_digest)=71 AND substr(run_set_digest,1,7)='sha256:' AND substr(run_set_digest,8) NOT GLOB '*[^0-9a-f]*'),
    decision TEXT NOT NULL CHECK (decision IN ('continue_degraded','pause','cancel')), 
    actor_binding_id TEXT REFERENCES actor_bindings(id) ON DELETE RESTRICT,
    receipt_artifact_id TEXT NOT NULL UNIQUE REFERENCES artifacts(id) ON DELETE RESTRICT,
    created_at TEXT NOT NULL,
    receipt_digest TEXT NOT NULL UNIQUE CHECK (length(receipt_digest)=71 AND substr(receipt_digest,1,7)='sha256:' AND substr(receipt_digest,8) NOT GLOB '*[^0-9a-f]*')
) STRICT;
CREATE TRIGGER assurance_degradation_scope BEFORE INSERT ON assurance_degradation_receipts FOR EACH ROW BEGIN
    SELECT CASE WHEN NOT EXISTS (SELECT 1 FROM tasks t JOIN artifacts a ON a.id=NEW.receipt_artifact_id WHERE t.id=NEW.task_id AND a.project_id=t.project_id AND (a.task_id IS NULL OR a.task_id=NEW.task_id) AND a.content_hash=NEW.receipt_digest) THEN RAISE(ABORT,'assurance degradation receipt must be exact and task-scoped') END;
    SELECT CASE WHEN NEW.decision='continue_degraded' AND NEW.actor_binding_id IS NULL THEN RAISE(ABORT,'continuing with degraded assurance requires explicit actor proof') END;
END;
CREATE TRIGGER assurance_degradation_update_forbidden BEFORE UPDATE ON assurance_degradation_receipts FOR EACH ROW BEGIN SELECT RAISE(ABORT,'assurance degradation receipts are immutable'); END;
CREATE TRIGGER assurance_degradation_delete_forbidden BEFORE DELETE ON assurance_degradation_receipts FOR EACH ROW BEGIN SELECT RAISE(ABORT,'assurance degradation receipts are retained'); END;

COMMIT;
