use local_agent_terminal_application::{
    DeliberationAgentRunRecovery, DeliberationDurableBoundary, DeliberationRecoveryStore,
    DeliberationSnapshot, PortError,
};
use local_agent_terminal_domain::{AgentRunStatus, Phase, RunId, TaskId};

pub struct DeliberationRecoveryCoordinator<'a> {
    store: &'a dyn DeliberationRecoveryStore,
    agent_runs: &'a dyn DeliberationAgentRunRecovery,
}

impl<'a> DeliberationRecoveryCoordinator<'a> {
    pub const fn new(
        store: &'a dyn DeliberationRecoveryStore,
        agent_runs: &'a dyn DeliberationAgentRunRecovery,
    ) -> Self {
        Self { store, agent_runs }
    }

    pub fn resume(&self, task_id: &TaskId) -> Result<Vec<DeliberationDurableBoundary>, PortError> {
        let checkpoint = self.store.load_checkpoint(task_id)?;
        checkpoint.validate(task_id)?;
        let mut resumed = Vec::new();
        if !checkpoint.event_persisted {
            self.store.persist_recovered_event(task_id)?;
            resumed.push(DeliberationDurableBoundary::Event);
        }
        if !checkpoint.artifact_persisted {
            self.store.persist_recovered_artifact(task_id)?;
            resumed.push(DeliberationDurableBoundary::Artifact);
        }
        if !checkpoint.dispatch_bindings_persisted {
            self.store.persist_recovered_dispatch_bindings(task_id)?;
            resumed.push(DeliberationDurableBoundary::DispatchBindings);
        }
        if !checkpoint.agent_runs_reconciled {
            let reconciliation = self.agent_runs.reconcile_or_retry(task_id)?;
            reconciliation.validate()?;
            self.store
                .persist_recovered_agent_run_reconciliation(&reconciliation)?;
            resumed.push(DeliberationDurableBoundary::AgentRunsReconciled);
        }
        if !checkpoint.proposal_visibility_persisted {
            self.store.persist_recovered_proposal_visibility(task_id)?;
            resumed.push(DeliberationDurableBoundary::ProposalVisibility);
        }
        if !checkpoint.claim_set_persisted {
            self.store.persist_recovered_claim_set(task_id)?;
            resumed.push(DeliberationDurableBoundary::ClaimSet);
        }
        if !checkpoint.decision_draft_persisted {
            self.store.persist_recovered_decision_draft(task_id)?;
            resumed.push(DeliberationDurableBoundary::DecisionDraft);
        }
        if !checkpoint.plan_approval_persisted {
            self.store.persist_recovered_plan_approval(task_id)?;
            resumed.push(DeliberationDurableBoundary::PlanApproval);
        }
        Ok(resumed)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeliberationRecoveryAction {
    ValidateIntake,
    BuildInitialContext,
    AwaitIndependentProposals,
    PublishQuorum,
    PersistReviewEdges,
    FreezeMaterialClaims,
    ClassifyMaterialClaims,
    SynthesizeDecision,
    CollectFinalObjections,
    CloseObjectionRound,
    AwaitPlanApproval,
    PostApproval,
}

pub fn plan_deliberation_recovery(snapshot: &DeliberationSnapshot) -> DeliberationRecoveryAction {
    match snapshot.task_state.phase() {
        Phase::Intake => DeliberationRecoveryAction::ValidateIntake,
        Phase::ContextBuild => DeliberationRecoveryAction::BuildInitialContext,
        Phase::ParallelAnalysis => {
            if snapshot.private_proposals().len() < 2 {
                DeliberationRecoveryAction::AwaitIndependentProposals
            } else {
                DeliberationRecoveryAction::PublishQuorum
            }
        }
        Phase::CrossReview => {
            let expected_review_records = snapshot.severe_objection_acceptances().len() + 1;
            if snapshot.review_edges_history().len() < expected_review_records {
                DeliberationRecoveryAction::PersistReviewEdges
            } else {
                DeliberationRecoveryAction::FreezeMaterialClaims
            }
        }
        Phase::PrePlanVerification => DeliberationRecoveryAction::ClassifyMaterialClaims,
        Phase::Synthesis => DeliberationRecoveryAction::SynthesizeDecision,
        Phase::FinalObjection => {
            if snapshot.objection_sets().len() < snapshot.decision_drafts().len() {
                DeliberationRecoveryAction::CollectFinalObjections
            } else {
                DeliberationRecoveryAction::CloseObjectionRound
            }
        }
        Phase::AwaitingPlanApproval => DeliberationRecoveryAction::AwaitPlanApproval,
        Phase::Implementation
        | Phase::Verification
        | Phase::Repair
        | Phase::FinalReview
        | Phase::AwaitingCommitApproval
        | Phase::LocalCommit
        | Phase::WorkspaceDirty
        | Phase::Completed
        | Phase::Cancelled
        | Phase::Failed => DeliberationRecoveryAction::PostApproval,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PersistedDispatch {
    pub phase: Phase,
    pub run_id: RunId,
    pub status: AgentRunStatus,
    pub idempotent: bool,
    pub replacement_run_id: Option<RunId>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DispatchRecovery {
    ResumePersisted {
        run_id: RunId,
    },
    StartReplacement {
        previous_run_id: RunId,
        new_run_id: RunId,
    },
    WaitForTerminal,
    AwaitExplicitResolution,
    Complete,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoveryPlanningError {
    SameRunReplacement,
    UnexpectedReplacement,
    UnexpectedPhase,
}

pub fn plan_dispatch_recovery(
    dispatch: &PersistedDispatch,
) -> Result<DispatchRecovery, RecoveryPlanningError> {
    if !matches!(
        dispatch.phase,
        Phase::ParallelAnalysis
            | Phase::CrossReview
            | Phase::PrePlanVerification
            | Phase::Synthesis
            | Phase::FinalObjection
    ) {
        return Err(RecoveryPlanningError::UnexpectedPhase);
    }
    match dispatch.status {
        AgentRunStatus::Created if dispatch.idempotent => {
            if dispatch.replacement_run_id.is_some() {
                return Err(RecoveryPlanningError::UnexpectedReplacement);
            }
            Ok(DispatchRecovery::ResumePersisted {
                run_id: dispatch.run_id.clone(),
            })
        }
        AgentRunStatus::Created | AgentRunStatus::Indeterminate => {
            Ok(DispatchRecovery::AwaitExplicitResolution)
        }
        AgentRunStatus::Accepted | AgentRunStatus::Running => Ok(DispatchRecovery::WaitForTerminal),
        AgentRunStatus::Interrupted | AgentRunStatus::Failed | AgentRunStatus::Terminated => {
            let Some(new_run_id) = &dispatch.replacement_run_id else {
                return Ok(DispatchRecovery::AwaitExplicitResolution);
            };
            if new_run_id == &dispatch.run_id {
                return Err(RecoveryPlanningError::SameRunReplacement);
            }
            Ok(DispatchRecovery::StartReplacement {
                previous_run_id: dispatch.run_id.clone(),
                new_run_id: new_run_id.clone(),
            })
        }
        AgentRunStatus::Succeeded | AgentRunStatus::CancelledCleanly => {
            if dispatch.replacement_run_id.is_some() {
                return Err(RecoveryPlanningError::UnexpectedReplacement);
            }
            Ok(DispatchRecovery::Complete)
        }
    }
}
