
pub struct DeliberationCommands<'a> {
    store: &'a dyn DeliberationStore,
    plan_approval_authority: Option<&'a dyn PlanApprovalAuthorityProvider>,
}

impl<'a> DeliberationCommands<'a> {
    pub const fn new(store: &'a dyn DeliberationStore) -> Self {
        Self {
            store,
            plan_approval_authority: None,
        }
    }

    pub const fn with_plan_approval_authority(
        store: &'a dyn DeliberationStore,
        plan_approval_authority: &'a dyn PlanApprovalAuthorityProvider,
    ) -> Self {
        Self {
            store,
            plan_approval_authority: Some(plan_approval_authority),
        }
    }

    pub fn record_private_proposal(
        &self,
        context: DeliberationCommandContext,
        proposal: IndependentProposal,
        proposal_artifact: DeliberationArtifactRef,
    ) -> Result<(), PortError> {
        let snapshot = self.authorize(&context, Phase::ParallelAnalysis)?;
        if snapshot.quorum.is_some()
            || snapshot.quorum_publication.is_some()
            || snapshot.private_proposals.iter().any(|existing| {
                existing.proposal.run_id() == proposal.run_id()
                    || existing.proposal.artifact_id() == proposal.artifact_id()
            })
        {
            return Err(conflict());
        }
        self.persist_authorized(
            context.clone(),
            snapshot,
            DeliberationRecord::PrivateProposal {
                proposal,
                proposal_artifact,
                receipt: context.record_artifact.clone(),
            },
        )
    }

    pub fn publish_proposals(
        &self,
        context: DeliberationCommandContext,
        review_plan: ReviewPlan,
        review_artifact: DeliberationArtifactRef,
    ) -> Result<(), PortError> {
        let snapshot = self.authorize(&context, Phase::ParallelAnalysis)?;
        if snapshot.quorum.is_some() || snapshot.quorum_publication.is_some() {
            return Err(conflict());
        }
        let review_targets: BTreeSet<_> = review_plan
            .edges()
            .iter()
            .map(|edge| edge.target_proposal())
            .collect();
        let selected = snapshot
            .private_proposals
            .iter()
            .filter(|record| review_targets.contains(record.proposal.artifact_id()))
            .map(|record| record.proposal.clone())
            .collect::<Vec<_>>();
        if selected.len() != review_targets.len()
            || review_plan.edges().iter().any(|edge| {
                !snapshot
                    .run_assignments
                    .iter()
                    .any(|assignment| assignment.agent_id() == edge.reviewer_id())
            })
        {
            return Err(conflict());
        }
        let proposals = IndependentQuorum::new(selected)
            .map_err(|_| conflict())?
            .reveal();
        self.persist_authorized(
            context.clone(),
            snapshot,
            DeliberationRecord::QuorumPublication {
                proposals,
                proposal_artifact: context.record_artifact.clone(),
                review_plan,
                review_artifact,
            },
        )
    }

    pub fn record_review_edges(
        &self,
        context: DeliberationCommandContext,
        plan: ReviewPlan,
    ) -> Result<(), PortError> {
        let snapshot = self.authorize(&context, Phase::CrossReview)?;
        let (active_plan, active_artifact) = snapshot
            .severe_objection_acceptances
            .last()
            .map(|accepted| (&accepted.review_plan, &accepted.review_artifact))
            .or_else(|| {
                snapshot
                    .quorum_publication
                    .as_ref()
                    .map(|publication| (&publication.review_plan, &publication.review_artifact))
            })
            .ok_or_else(conflict)?;
        if snapshot
            .review_edges
            .iter()
            .any(|existing| existing.plan == *active_plan && existing.artifact == *active_artifact)
            || plan != *active_plan
            || context.record_artifact != *active_artifact
        {
            return Err(conflict());
        }
        self.persist_authorized(
            context.clone(),
            snapshot,
            DeliberationRecord::ReviewEdges {
                plan,
                artifact: context.record_artifact.clone(),
            },
        )
    }

    pub fn record_thread_summary(
        &self,
        context: DeliberationCommandContext,
        thread_id: impl Into<String>,
    ) -> Result<(), PortError> {
        let snapshot = self.authorize(&context, Phase::CrossReview)?;
        let thread_id = thread_id.into();
        if snapshot.quorum_publication.is_none()
            || snapshot
                .thread_summaries
                .iter()
                .any(|existing| existing.thread_id == thread_id)
        {
            return Err(conflict());
        }
        self.persist_authorized(
            context.clone(),
            snapshot,
            DeliberationRecord::ThreadSummary {
                thread_id,
                artifact: context.record_artifact.clone(),
            },
        )
    }

    pub fn request_specialist(
        &self,
        context: DeliberationCommandContext,
        request: SpecialistRequest,
    ) -> Result<(), PortError> {
        let snapshot = self.authorize(&context, Phase::ParallelAnalysis)?;
        if snapshot.quorum.is_some()
            || snapshot.quorum_publication.is_some()
            || snapshot
                .specialist_requests
                .iter()
                .any(|existing| existing.request.request_id() == request.request_id())
        {
            return Err(conflict());
        }
        self.persist_authorized(
            context.clone(),
            snapshot,
            DeliberationRecord::SpecialistRequest {
                request,
                artifact: context.record_artifact.clone(),
            },
        )
    }

    pub fn record_claim_set(
        &self,
        context: DeliberationCommandContext,
        claims: Vec<MaterialClaim>,
    ) -> Result<(), PortError> {
        let snapshot = self.authorize(&context, Phase::CrossReview)?;
        if snapshot.quorum_publication.is_none()
            || snapshot.claim_sets.len() != snapshot.decision_drafts.len()
            || snapshot.verification_sets.len() != snapshot.claim_sets.len()
        {
            return Err(conflict());
        }
        self.persist_authorized(
            context.clone(),
            snapshot,
            DeliberationRecord::ClaimSet {
                claims,
                artifact: context.record_artifact.clone(),
            },
        )
    }

    pub fn record_verification_set(
        &self,
        context: DeliberationCommandContext,
        claims: Vec<MaterialClaim>,
    ) -> Result<(), PortError> {
        let snapshot = self.authorize(&context, Phase::PrePlanVerification)?;
        let Some(claim_set) = snapshot.claim_sets.last() else {
            return Err(conflict());
        };
        if snapshot.verification_sets.len() + 1 != snapshot.claim_sets.len()
            || !same_claim_authority(&claim_set.claims, &claims)
        {
            return Err(conflict());
        }
        self.persist_authorized(
            context.clone(),
            snapshot,
            DeliberationRecord::VerificationSet {
                claims,
                artifact: context.record_artifact.clone(),
            },
        )
    }

    pub fn synthesize(
        &self,
        context: DeliberationCommandContext,
        decision: DecisionPackage,
        plan_artifact: DeliberationArtifactRef,
        plan_version: u64,
    ) -> Result<(), PortError> {
        let command = self.prepare_synthesis(context, decision, plan_artifact, plan_version)?;
        self.store.persist(command)
    }

    fn prepare_synthesis(
        &self,
        context: DeliberationCommandContext,
        decision: DecisionPackage,
        plan_artifact: DeliberationArtifactRef,
        plan_version: u64,
    ) -> Result<DeliberationPersistenceCommand, PortError> {
        let snapshot = self.authorize(&context, Phase::Synthesis)?;
        let Some(verification_set) = snapshot.verification_sets.last() else {
            return Err(conflict());
        };
        let authoritative_claims: BTreeMap<_, _> = verification_set
            .claims
            .iter()
            .map(|claim| (claim.claim_id(), claim))
            .collect();
        let decision_claims: BTreeMap<_, _> = decision
            .evidence()
            .iter()
            .map(|claim| (claim.claim_id(), claim))
            .collect();
        let replacement_matches = if snapshot.decision_drafts.is_empty() {
            snapshot.supersessions.is_empty()
        } else {
            snapshot.supersessions.len() == snapshot.decision_drafts.len()
                && snapshot
                    .supersessions
                    .last()
                    .is_some_and(|record| record.replacement == context.record_artifact)
        };
        if snapshot.decision_drafts.len() + 1 != snapshot.verification_sets.len()
            || !replacement_matches
            || verification_set
                .claims
                .iter()
                .any(|claim| claim.verification().is_none())
            || authoritative_claims.len() != verification_set.claims.len()
            || decision_claims.len() != decision.evidence().len()
            || authoritative_claims != decision_claims
        {
            return Err(conflict());
        }
        self.build_authorized(
            context.clone(),
            snapshot,
            DeliberationRecord::DecisionDraft {
                decision,
                artifact: context.record_artifact.clone(),
                plan_artifact,
                plan_version,
            },
        )
    }

    pub fn record_objection_set(
        &self,
        context: DeliberationCommandContext,
        objections: FinalObjectionSet,
    ) -> Result<(), PortError> {
        let snapshot = self.authorize(&context, Phase::FinalObjection)?;
        if snapshot.objection_sets.len() + 1 != snapshot.decision_drafts.len()
            || snapshot.severe_objection_acceptances.len() != snapshot.objection_sets.len()
            || objections.round() != snapshot.objection_sets.len() as u32 + 1
        {
            return Err(conflict());
        }
        self.persist_authorized(
            context.clone(),
            snapshot,
            DeliberationRecord::ObjectionSet {
                objections,
                artifact: context.record_artifact.clone(),
            },
        )
    }

    pub fn accept_severe_objection(
        &self,
        context: DeliberationCommandContext,
        review_plan: ReviewPlan,
    ) -> Result<(), PortError> {
        let snapshot = self.authorize(&context, Phase::FinalObjection)?;
        let current_objections = snapshot.objection_sets.last().ok_or_else(conflict)?;
        let objections = current_objections.objections.clone();
        let objection_artifact = current_objections.artifact.clone();
        let quorum = snapshot.quorum.as_ref().ok_or_else(conflict)?;
        if snapshot.severe_objection_acceptances.len() + 1 != snapshot.objection_sets.len()
            || !snapshot.severe_objection_acceptances.is_empty()
            || !review_plan_is_authorized(quorum, &snapshot.run_assignments, &review_plan)
        {
            return Err(conflict());
        }
        self.persist_authorized(
            context.clone(),
            snapshot,
            DeliberationRecord::ObjectionSevereAccepted {
                objections,
                objection_artifact,
                review_plan,
                review_artifact: context.record_artifact.clone(),
            },
        )
    }

    pub fn close_objection_round(
        &self,
        context: DeliberationCommandContext,
        approval_input: PreparePlanApprovalRequestInput,
    ) -> Result<(), PortError> {
        let snapshot = self.authorize(&context, Phase::FinalObjection)?;
        if !snapshot.objection_round_closures.is_empty()
            || snapshot.objection_sets.len() != snapshot.decision_drafts.len()
            || snapshot.severe_objection_acceptances.len() >= snapshot.objection_sets.len()
        {
            return Err(conflict());
        }
        let transition = WorkflowEvent::new("objection.round.closed").map_err(|_| conflict())?;
        let mut guards = GuardEvaluations::new();
        guards.insert(
            GuardName::new("no_accepted_severe_objection").map_err(|_| conflict())?,
            true,
        );
        let next_state = *reduce(&snapshot.task_state, &transition, &guards)
            .map_err(|_| conflict())?
            .state();
        let approval_authority = self
            .plan_approval_authority
            .ok_or_else(conflict)?
            .current(&snapshot.task_id)?;
        approval_authority.validate()?;
        let current_decision = snapshot.decision_drafts.last().ok_or_else(conflict)?;
        let binding = approval_authority.binding();
        if binding.plan_artifact_id != current_decision.plan_artifact.artifact_id().as_str()
            || binding.plan_digest != current_decision.plan_artifact.content_digest().as_str()
            || binding.plan_version != current_decision.plan_version
        {
            return Err(conflict());
        }
        let approval_state = PlanApprovalCurrentState {
            phase: next_state.phase(),
            task_state: next_state,
            binding: approval_authority.binding().clone(),
        };
        let plan_approval = PreparePlanApprovalRequest::execute(
            approval_input,
            &approval_authority,
            &approval_state,
        )?;
        self.persist_authorized(
            context.clone(),
            snapshot,
            DeliberationRecord::ObjectionRoundClosed {
                artifact: context.record_artifact.clone(),
                plan_approval: Box::new(plan_approval),
            },
        )
    }

    pub fn record_supersession(
        &self,
        context: DeliberationCommandContext,
        superseded: DeliberationArtifactRef,
    ) -> Result<(), PortError> {
        let snapshot = self.authorize(&context, Phase::Synthesis)?;
        let Some(current_decision) = snapshot.decision_drafts.last() else {
            return Err(conflict());
        };
        if superseded != current_decision.artifact
            || snapshot.verification_sets.len() != snapshot.decision_drafts.len() + 1
            || snapshot.severe_objection_acceptances.len() != snapshot.decision_drafts.len()
            || snapshot.supersessions.len() + 1 != snapshot.decision_drafts.len()
        {
            return Err(conflict());
        }
        self.persist_authorized(
            context.clone(),
            snapshot,
            DeliberationRecord::Supersession {
                superseded,
                replacement: context.record_artifact.clone(),
            },
        )
    }

    fn persist_authorized(
        &self,
        context: DeliberationCommandContext,
        snapshot: DeliberationSnapshot,
        record: DeliberationRecord,
    ) -> Result<(), PortError> {
        let command = self.build_authorized(context, snapshot, record)?;
        self.store.persist(command)
    }

    fn build_authorized(
        &self,
        context: DeliberationCommandContext,
        snapshot: DeliberationSnapshot,
        record: DeliberationRecord,
    ) -> Result<DeliberationPersistenceCommand, PortError> {
        record.validate(&snapshot.task_id)?;
        record.validate_authority(&context.actor_id, &snapshot.run_assignments)?;
        let event_authority = context.event_authority();
        let append = build_append(
            &snapshot.task_id,
            snapshot.task_version,
            &snapshot.task_state,
            &event_authority,
            &record,
        )?;
        let command = DeliberationPersistenceCommand {
            task_id: snapshot.task_id,
            expected_task_version: snapshot.task_version,
            expected_task_state: snapshot.task_state,
            actor_id: context.actor_id,
            event_authority,
            record,
            append,
        };
        command.validate()?;
        Ok(command)
    }

    fn authorize(
        &self,
        context: &DeliberationCommandContext,
        expected_phase: Phase,
    ) -> Result<DeliberationSnapshot, PortError> {
        context.validate()?;
        let snapshot = self.store.load(&context.task_id)?;
        snapshot.validate()?;
        if snapshot.task_id != context.task_id
            || snapshot.task_version != context.expected_task_version
            || snapshot.task_state != context.expected_task_state
            || snapshot.task_state.phase() != expected_phase
        {
            return Err(conflict());
        }
        Ok(snapshot)
    }
}

pub struct PersistDeliberationSynthesis<'a> {
    store: &'a dyn DeliberationSynthesisStore,
}

impl<'a> PersistDeliberationSynthesis<'a> {
    pub const fn new(store: &'a dyn DeliberationSynthesisStore) -> Self {
        Self { store }
    }

    pub fn execute(
        &self,
        context: DeliberationCommandContext,
        decision: DecisionPackage,
        plan: DeliberationPlanDto,
        plan_artifact: DeliberationArtifactRef,
        plan_version: u64,
    ) -> Result<(), PortError> {
        let persistence = DeliberationCommands::new(self.store).prepare_synthesis(
            context,
            decision,
            plan_artifact,
            plan_version,
        )?;
        let command = DeliberationSynthesisCommand { persistence, plan };
        command.validate()?;
        self.store.persist_synthesis(command)
    }
}

fn build_append(
    task_id: &TaskId,
    expected_task_version: u64,
    expected_task_state: &WorkflowState,
    authority: &EventAuthority,
    record: &DeliberationRecord,
) -> Result<AppendOperation, PortError> {
    let event_type = WorkflowEvent::new(record.event_type()).map_err(|_| conflict())?;
    let (actor_type, observation_class) = record.authority_labels(&authority.actor_id)?;
    let event_sequence = expected_task_version.checked_add(1).ok_or_else(conflict)?;
    let canonical_record = CanonicalDeliberationFact::issue(
        task_id.clone(),
        authority.event_id.clone(),
        event_sequence,
        authority.actor_id.clone(),
        record.clone(),
    )?;
    let projection_changes = if record.changes_phase() {
        let mut guards = GuardEvaluations::new();
        let guard = record.transition_guard().ok_or_else(conflict)?;
        guards.insert(GuardName::new(guard).map_err(|_| conflict())?, true);
        let state = *reduce(expected_task_state, &event_type, &guards)
            .map_err(|_| conflict())?
            .state();
        vec![ProjectionChange::TaskState {
            task_id: task_id.clone(),
            state,
            updated_at: authority.occurred_at.clone(),
        }]
    } else {
        Vec::new()
    };
    Ok(AppendOperation {
        stream_id: StreamId::new(task_id.as_str()).map_err(|_| conflict())?,
        expected_version: local_agent_terminal_domain::Sequence::new(expected_task_version),
        events: vec![NewEvent {
            event_id: authority.event_id.clone(),
            event_type,
            schema_version: 1,
            actor_type: actor_type.to_owned(),
            actor_id: authority.actor_id.clone(),
            observation_class: observation_class.to_owned(),
            payload: record.event_payload(task_id, canonical_record.content_digest()),
            metadata: serde_json::json!({}),
            causation_id: None,
            correlation_id: authority.correlation_id.clone(),
            created_at: authority.occurred_at.clone(),
        }],
        projection_changes,
    })
}

fn validate_claim_set(claims: &[MaterialClaim], require_terminal: bool) -> Result<(), PortError> {
    if claims.is_empty()
        || claims
            .iter()
            .map(MaterialClaim::claim_id)
            .collect::<BTreeSet<_>>()
            .len()
            != claims.len()
        || (!require_terminal && claims.iter().any(|claim| claim.verification().is_some()))
        || (require_terminal && claims.iter().any(|claim| claim.verification().is_none()))
    {
        Err(conflict())
    } else {
        Ok(())
    }
}

pub(crate) fn review_plan_is_authorized(
    quorum: &IndependentQuorum,
    assignments: &[DeliberationRunAssignment],
    review_plan: &ReviewPlan,
) -> bool {
    let expected_targets = quorum
        .proposals()
        .iter()
        .map(IndependentProposal::artifact_id)
        .collect::<BTreeSet<_>>();
    let actual_targets = review_plan
        .edges()
        .iter()
        .map(|edge| edge.target_proposal())
        .collect::<BTreeSet<_>>();
    let authorized_reviewers = assignments
        .iter()
        .map(DeliberationRunAssignment::agent_id)
        .collect::<BTreeSet<_>>();
    let actual_reviewers = review_plan
        .edges()
        .iter()
        .map(|edge| edge.reviewer_id())
        .collect::<BTreeSet<_>>();
    expected_targets == actual_targets
        && !actual_reviewers.is_empty()
        && actual_reviewers.is_subset(&authorized_reviewers)
}

pub(crate) fn same_claim_authority(expected: &[MaterialClaim], actual: &[MaterialClaim]) -> bool {
    if expected.len() != actual.len() {
        return false;
    }
    let expected: BTreeMap<_, _> = expected
        .iter()
        .map(|claim| (claim.claim_id(), claim))
        .collect();
    let actual: BTreeMap<_, _> = actual
        .iter()
        .map(|claim| (claim.claim_id(), claim))
        .collect();
    expected.len() == actual.len()
        && expected.iter().all(|(id, expected)| {
            actual.get(id).is_some_and(|actual| {
                expected.claimant() == actual.claimant()
                    && expected.artifact_id() == actual.artifact_id()
                    && expected.citations() == actual.citations()
                    && expected.method() == actual.method()
                    && actual.verification().is_some()
            })
        })
}

pub(crate) fn same_claim_records(expected: &[MaterialClaim], actual: &[MaterialClaim]) -> bool {
    if expected.len() != actual.len() {
        return false;
    }
    let expected: BTreeMap<_, _> = expected
        .iter()
        .map(|claim| (claim.claim_id(), claim))
        .collect();
    let actual: BTreeMap<_, _> = actual
        .iter()
        .map(|claim| (claim.claim_id(), claim))
        .collect();
    expected.len() == actual.len() && expected == actual
}

fn validate_synthesis_plan(
    plan: &DeliberationPlanDto,
    decision: &DecisionPackage,
) -> Result<(), PortError> {
    let rejected = decision
        .rejected()
        .iter()
        .map(|entry| (entry.approach_id(), entry.reason()))
        .collect::<BTreeMap<_, _>>();
    let dto_rejected = plan
        .rejected_alternatives
        .iter()
        .map(|entry| (entry.approach_id.as_str(), entry.reason.as_str()))
        .collect::<BTreeMap<_, _>>();
    let verified = decision
        .evidence()
        .iter()
        .filter(|claim| {
            claim.verification() == Some(local_agent_terminal_domain::ClaimVerification::Verified)
        })
        .map(MaterialClaim::claim_id)
        .collect::<BTreeSet<_>>();
    let inconclusive = decision
        .evidence()
        .iter()
        .filter(|claim| {
            claim.verification()
                == Some(local_agent_terminal_domain::ClaimVerification::Inconclusive)
        })
        .map(MaterialClaim::claim_id)
        .collect::<BTreeSet<_>>();
    let dissent = decision
        .dissent()
        .iter()
        .map(local_agent_terminal_domain::Dissent::dissent_id)
        .collect::<BTreeSet<_>>();
    if plan.selected_approach_id != decision.selected().approach_id()
        || rejected.len() != decision.rejected().len()
        || dto_rejected.len() != plan.rejected_alternatives.len()
        || rejected != dto_rejected
        || !same_unique_plan_ids(&plan.verified_claim_ids, &verified)
        || !same_unique_plan_ids(&plan.inconclusive_claim_ids, &inconclusive)
        || !same_unique_plan_ids(&plan.dissent_ids, &dissent)
        || !valid_nonempty_plan_texts(&plan.affected_files)
        || !valid_nonempty_plan_texts(&plan.implementation_steps)
        || !valid_nonempty_plan_texts(&plan.planned_tools)
        || !valid_plan_text(&plan.verification_profile)
        || !valid_plan_text(&plan.rollback_plan)
        || !valid_plan_text(&plan.risk)
        || plan.estimated_cost_microunits == Some(0)
        || plan.estimated_duration_seconds == Some(0)
        || plan.confidence > 100
    {
        return Err(invalid_input());
    }
    Ok(())
}

fn same_unique_plan_ids(values: &[String], expected: &BTreeSet<&str>) -> bool {
    let actual = values.iter().map(String::as_str).collect::<BTreeSet<_>>();
    actual.len() == values.len() && &actual == expected
}

fn valid_nonempty_plan_texts(values: &[String]) -> bool {
    !values.is_empty()
        && values.iter().all(|value| valid_plan_text(value))
        && values.iter().collect::<BTreeSet<_>>().len() == values.len()
}

fn valid_plan_text(value: &str) -> bool {
    !value.trim().is_empty() && value.len() <= 16_384 && !value.contains('\0')
}

fn validate_label(value: &str) -> Result<(), PortError> {
    if value.trim().is_empty() || value.len() > 256 || value.contains('\0') {
        Err(invalid_input())
    } else {
        Ok(())
    }
}

fn invalid_input() -> PortError {
    PortError::failure(
        SafeErrorClassification::InvalidInput,
        Retryability::NonRetryable,
    )
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
