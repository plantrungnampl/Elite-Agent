use std::collections::BTreeMap;

use local_agent_terminal_domain::{
    ActorId, DecisionPackage, IndependentProposal, IndependentQuorum, MaterialClaim, Phase, TaskId,
};

use crate::{PortError, Retryability, SafeErrorClassification};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeliberationCommandContext {
    pub task_id: TaskId,
    pub expected_task_version: u64,
    pub actor_id: ActorId,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeliberationSnapshot {
    pub task_id: TaskId,
    pub phase: Phase,
    pub task_version: u64,
    pub authorized_actors: Vec<ActorId>,
    pub quorum: Option<IndependentQuorum>,
    pub claims: Vec<MaterialClaim>,
    pub accepted_severe_objection: bool,
}

pub trait DeliberationStore: Send + Sync {
    fn load(&self, task_id: &TaskId) -> Result<DeliberationSnapshot, PortError>;
    fn record_private_proposal(
        &self,
        context: &DeliberationCommandContext,
        proposal: IndependentProposal,
    ) -> Result<(), PortError>;
    fn publish_proposals(
        &self,
        context: &DeliberationCommandContext,
        proposals: Vec<IndependentProposal>,
    ) -> Result<(), PortError>;
    fn record_decision(
        &self,
        context: &DeliberationCommandContext,
        decision: DecisionPackage,
    ) -> Result<(), PortError>;
    fn close_objection_round(&self, context: &DeliberationCommandContext) -> Result<(), PortError>;
}

pub struct DeliberationCommands<'a> {
    store: &'a dyn DeliberationStore,
}

impl<'a> DeliberationCommands<'a> {
    pub const fn new(store: &'a dyn DeliberationStore) -> Self {
        Self { store }
    }

    pub fn record_private_proposal(
        &self,
        context: DeliberationCommandContext,
        proposal: IndependentProposal,
    ) -> Result<(), PortError> {
        let snapshot = self.authorize(&context, Phase::ParallelAnalysis)?;
        if proposal.task_id() != &snapshot.task_id || proposal.is_revealed() {
            return Err(conflict());
        }
        self.store.record_private_proposal(&context, proposal)
    }

    pub fn publish_proposals(&self, context: DeliberationCommandContext) -> Result<(), PortError> {
        let snapshot = self.authorize(&context, Phase::ParallelAnalysis)?;
        let quorum = snapshot.quorum.ok_or_else(conflict)?;
        let proposals = quorum.reveal();
        if proposals
            .iter()
            .any(|proposal| proposal.task_id() != &snapshot.task_id)
        {
            return Err(conflict());
        }
        self.store.publish_proposals(&context, proposals)
    }

    pub fn synthesize(
        &self,
        context: DeliberationCommandContext,
        decision: DecisionPackage,
    ) -> Result<(), PortError> {
        let snapshot = self.authorize(&context, Phase::Synthesis)?;
        let authoritative_claims: BTreeMap<_, _> = snapshot
            .claims
            .iter()
            .map(|claim| (claim.claim_id(), claim))
            .collect();
        let decision_claims: BTreeMap<_, _> = decision
            .evidence()
            .iter()
            .map(|claim| (claim.claim_id(), claim))
            .collect();
        if snapshot
            .claims
            .iter()
            .any(|claim| claim.verification().is_none())
            || authoritative_claims.len() != snapshot.claims.len()
            || decision_claims.len() != decision.evidence().len()
            || authoritative_claims != decision_claims
        {
            return Err(conflict());
        }
        self.store.record_decision(&context, decision)
    }

    pub fn close_objection_round(
        &self,
        context: DeliberationCommandContext,
    ) -> Result<(), PortError> {
        let snapshot = self.authorize(&context, Phase::FinalObjection)?;
        if snapshot.accepted_severe_objection {
            return Err(conflict());
        }
        self.store.close_objection_round(&context)
    }

    fn authorize(
        &self,
        context: &DeliberationCommandContext,
        expected_phase: Phase,
    ) -> Result<DeliberationSnapshot, PortError> {
        let snapshot = self.store.load(&context.task_id)?;
        if snapshot.task_id != context.task_id
            || snapshot.phase != expected_phase
            || snapshot.task_version != context.expected_task_version
        {
            return Err(conflict());
        }
        if !snapshot.authorized_actors.contains(&context.actor_id) {
            return Err(permission_denied());
        }
        Ok(snapshot)
    }
}

fn conflict() -> PortError {
    PortError::failure(
        SafeErrorClassification::Conflict,
        Retryability::NonRetryable,
    )
}

fn permission_denied() -> PortError {
    PortError::failure(
        SafeErrorClassification::PermissionDenied,
        Retryability::NonRetryable,
    )
}
