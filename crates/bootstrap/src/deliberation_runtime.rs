use std::sync::Arc;

use local_agent_terminal_application::{
    ActorId, AgentLocalityDto, AgentRosterEntryDto, AgentRunStore, AgentRuntime, ApprovalId,
    ArtifactRef, ArtifactStore, ContextDisclosureDto, ContextDisclosureKindDto,
    ContextFreshnessDto, ContextLineRangeDto, ContextPackageBudgetDto, ContextPackageDto,
    ContextPackageMemberDto, ContextPackageSourceDto, ContextPackageVersionsDto,
    DeliberationAvailabilityDto, DeliberationBoundaryStore, DeliberationCardDto,
    DeliberationCardKindDto, DeliberationDispatchStore, DeliberationEvidenceDto,
    DeliberationRepositoryAuthority, DeliberationResumeActionDto, DeliberationStore,
    DeliberationSynthesisStore, DeliberationThreadDto, DeliberationToolCatalog,
    DeliberationToolSchema, DeliberationWorkspaceDto, EventStore, EvidenceStateDto,
    InspectRepository, PlanAgentAgreementDto, PlanAgreementPositionDto,
    PlanApprovalAuthorityProvider, PlanApprovalCurrentAuthority,
    PlanApprovalCurrentAuthoritySource, PlanApprovalResolutionDto, PlanApprovalResolutionStatusDto,
    PlanApprovalStatusDto, PlanApprovalStore, PlanApprovalViewDto, PlanRejectedAlternativeDto,
    PortError, RepositoryGateway, ResolvePlanApproval, ResolvePlanApprovalInput,
    ResolvePlanApprovalRequestDto, Retryability, SafeErrorClassification, Sha256Digest, TaskId,
    ThreadMessageDto, WorkflowPhaseDto, WorkflowPhaseStateDto, WorkspaceFingerprint,
};
use local_agent_terminal_orchestration::{
    plan_deliberation_recovery, verify_repository_boundary, BoundaryOutcome,
    DeliberationCoordinator, DeliberationRecoveryAction, PreApprovalAdvance,
    PreApprovalCoordinator, PrePlanOperation,
};
use local_agent_terminal_repository_git::GitRepositoryGateway;
use local_agent_terminal_storage_files::{
    ContentAddressedArtifactReader, ContentAddressedArtifactStore,
};
use local_agent_terminal_storage_sqlite::SqliteStore;
use sha2::{Digest, Sha256};

use crate::agent_runtime::ComposedAgentRuntime;

pub(crate) fn compose_deliberation_runtime(
    database: SqliteStore,
    artifacts: Arc<ContentAddressedArtifactStore>,
    repositories: GitRepositoryGateway,
    policy_snapshot_digest: Sha256Digest,
    agent_runtime: Option<Arc<ComposedAgentRuntime>>,
) -> Arc<DeliberationRuntime> {
    let authority = Arc::new(ProductionRepositoryAuthority {
        database: database.clone(),
        repositories,
        policy_snapshot_digest,
    });
    let store = Arc::new(
        database
            .with_artifact_reader(Arc::new(ContentAddressedArtifactReader))
            .with_plan_approval_authority_source(
                Arc::clone(&authority) as Arc<dyn PlanApprovalCurrentAuthoritySource>
            ),
    );
    let preapproval_runtime = agent_runtime.map(|runtime| runtime as Arc<dyn AgentRuntime>);
    Arc::new(DeliberationRuntime {
        authority: Some(authority),
        boundaries: Some(Arc::clone(&store) as Arc<dyn DeliberationBoundaryStore>),
        store: Some(Arc::clone(&store) as Arc<dyn DeliberationSynthesisStore>),
        events: Some(Arc::clone(&store) as Arc<dyn EventStore>),
        dispatches: Some(Arc::clone(&store) as Arc<dyn DeliberationDispatchStore>),
        agent_runtime: preapproval_runtime,
        tools: Arc::new(PreApprovalToolCatalog),
        plan_approval_authority: None,
        query_store: Some(store),
        artifacts: Some(artifacts),
    })
}

/// Owns the outer ports used by the deliberation coordinator.
///
/// Repository-boundary checks and deliberation transition policy remain in
/// `orchestration`; this type only supplies their concrete application ports.
pub struct DeliberationRuntime {
    authority: Option<Arc<dyn DeliberationRepositoryAuthority>>,
    boundaries: Option<Arc<dyn DeliberationBoundaryStore>>,
    store: Option<Arc<dyn DeliberationSynthesisStore>>,
    events: Option<Arc<dyn EventStore>>,
    dispatches: Option<Arc<dyn DeliberationDispatchStore>>,
    agent_runtime: Option<Arc<dyn AgentRuntime>>,
    tools: Arc<dyn DeliberationToolCatalog>,
    plan_approval_authority: Option<Arc<dyn PlanApprovalAuthorityProvider>>,
    query_store: Option<Arc<SqliteStore>>,
    artifacts: Option<Arc<ContentAddressedArtifactStore>>,
}

impl DeliberationRuntime {
    pub fn new(
        authority: Arc<dyn DeliberationRepositoryAuthority>,
        boundaries: Arc<dyn DeliberationBoundaryStore>,
        store: Arc<dyn DeliberationSynthesisStore>,
    ) -> Self {
        Self {
            authority: Some(authority),
            boundaries: Some(boundaries),
            store: Some(store),
            events: None,
            dispatches: None,
            agent_runtime: None,
            tools: Arc::new(PreApprovalToolCatalog),
            plan_approval_authority: None,
            query_store: None,
            artifacts: None,
        }
    }

    pub fn with_plan_approval_authority(
        authority: Arc<dyn DeliberationRepositoryAuthority>,
        boundaries: Arc<dyn DeliberationBoundaryStore>,
        store: Arc<dyn DeliberationSynthesisStore>,
        plan_approval_authority: Arc<dyn PlanApprovalAuthorityProvider>,
    ) -> Self {
        Self {
            authority: Some(authority),
            boundaries: Some(boundaries),
            store: Some(store),
            events: None,
            dispatches: None,
            agent_runtime: None,
            tools: Arc::new(PreApprovalToolCatalog),
            plan_approval_authority: Some(plan_approval_authority),
            query_store: None,
            artifacts: None,
        }
    }

    pub fn coordinator(&self) -> Option<DeliberationCoordinator<'_>> {
        let authority = self.authority.as_deref()?;
        let boundaries = self.boundaries.as_deref()?;
        let store = self.store.as_deref()?;
        Some(match self.plan_approval_authority.as_deref() {
            Some(plan_approval_authority) => DeliberationCoordinator::with_plan_approval_authority(
                authority,
                boundaries,
                store,
                plan_approval_authority,
            ),
            None => DeliberationCoordinator::new(authority, boundaries, store),
        })
    }

    pub fn preapproval_coordinator(&self) -> Option<PreApprovalCoordinator<'_>> {
        Some(PreApprovalCoordinator::new(
            self.authority.as_deref()?,
            self.boundaries.as_deref()?,
            self.events.as_deref()?,
            self.tools.as_ref(),
            self.dispatches.as_deref()?,
            self.agent_runtime.as_deref()?,
        ))
    }

    pub fn coordinate_preapproval(
        &self,
        operation: PrePlanOperation,
    ) -> Result<PreApprovalAdvance, PortError> {
        self.preapproval_coordinator()
            .ok_or_else(unavailable)?
            .coordinate(operation)
    }

    pub fn resume_deliberation(
        &self,
        task_id: &str,
    ) -> Result<DeliberationResumeActionDto, PortError> {
        let task_id = TaskId::new(task_id).map_err(|_| invalid_input())?;
        let store = self.query_store.as_deref().ok_or_else(unavailable)?;
        let runtime = self.agent_runtime.as_deref().ok_or_else(unavailable)?;
        let snapshot = DeliberationStore::load(store, &task_id)?;
        let boundary = verify_repository_boundary(
            self.authority.as_deref().ok_or_else(unavailable)?,
            self.boundaries.as_deref().ok_or_else(unavailable)?,
            &task_id,
            snapshot.task_state.phase(),
        )?;
        if boundary == BoundaryOutcome::Blocked {
            return Err(integrity_failure());
        }
        for assignment in &snapshot.run_assignments {
            let run = AgentRunStore::load_run(store, assignment.run_id())?
                .ok_or_else(integrity_failure)?;
            if run.status == local_agent_terminal_application::AgentRunStatus::Created {
                runtime.start_run(run.request)?;
            }
        }
        Ok(recovery_action_dto(plan_deliberation_recovery(&snapshot)))
    }

    pub fn workspace(&self, task_id: &str) -> Result<DeliberationWorkspaceDto, PortError> {
        let task_id = TaskId::new(task_id).map_err(|_| invalid_input())?;
        let store = self.query_store.as_deref().ok_or_else(unavailable)?;
        let artifacts = self.artifacts.as_deref().ok_or_else(unavailable)?;
        let snapshot = DeliberationStore::load(store, &task_id)?;
        let decision = snapshot.decision_drafts().last();
        let approval = snapshot
            .plan_approval()
            .map(|approval| present_plan_approval(store, artifacts, approval, decision))
            .transpose()?;
        let current_phase = snapshot.task_state.phase();
        let published_proposal_ids = snapshot
            .quorum()
            .map(|quorum| {
                quorum
                    .proposals()
                    .iter()
                    .map(|proposal| proposal.artifact_id().as_str().to_owned())
                    .collect()
            })
            .unwrap_or_default();
        let unresolved_objection_ids = snapshot
            .objections
            .as_ref()
            .map(|set| {
                set.objections()
                    .iter()
                    .map(|objection| {
                        format!("{}-round-{}", objection.participant_id(), objection.round())
                    })
                    .collect()
            })
            .unwrap_or_default();
        Ok(DeliberationWorkspaceDto {
            availability: DeliberationAvailabilityDto::Ready,
            task_id: task_id.as_str().to_owned(),
            phase: current_phase.as_str().to_owned(),
            task_version: snapshot.task_version,
            status_message: "Authoritative deliberation state loaded.".to_owned(),
            workflow: local_agent_terminal_application::Phase::ALL
                .iter()
                .copied()
                .map(|phase| WorkflowPhaseDto {
                    phase_id: phase.as_str().to_owned(),
                    label: phase.as_str().to_owned(),
                    state: if phase == current_phase {
                        WorkflowPhaseStateDto::Current
                    } else if phase < current_phase {
                        WorkflowPhaseStateDto::Completed
                    } else {
                        WorkflowPhaseStateDto::Pending
                    },
                    detail: if phase == current_phase {
                        "Current authoritative phase.".to_owned()
                    } else {
                        String::new()
                    },
                    retry_count: 0,
                    approval_gate: matches!(
                        phase,
                        local_agent_terminal_application::Phase::AwaitingPlanApproval
                            | local_agent_terminal_application::Phase::AwaitingCommitApproval
                    ),
                })
                .collect(),
            agents: present_agents(store, artifacts, &snapshot.run_assignments)?,
            cards: present_cards(artifacts, &snapshot)?,
            thread: present_thread(artifacts, snapshot.thread_summaries())?,
            evidence: present_evidence(&snapshot),
            approval,
            private_proposal_count: snapshot.private_proposals().len(),
            published_proposal_ids,
            decision_artifact_id: snapshot
                .decision_drafts()
                .last()
                .map(|decision| decision.artifact().artifact_id().as_str().to_owned()),
            unresolved_objection_ids,
        })
    }

    pub fn context_package(&self, package_id: &str) -> Result<ContextPackageDto, PortError> {
        let store = self.query_store.as_deref().ok_or_else(unavailable)?;
        let artifacts = self.artifacts.as_deref().ok_or_else(unavailable)?;
        let view = store
            .context_package_view(package_id)?
            .ok_or_else(not_found)?;
        let content = artifacts.read(&view.artifact)?;
        let value: serde_json::Value =
            serde_json::from_slice(&content.bytes).map_err(|_| integrity_failure())?;
        present_context_package(view, &value, content.bytes.len())
    }

    pub fn resolve_plan_approval(
        &self,
        request: ResolvePlanApprovalRequestDto,
    ) -> Result<PlanApprovalResolutionDto, PortError> {
        let store = self.query_store.as_deref().ok_or_else(unavailable)?;
        let input = ResolvePlanApprovalInput {
            approval_id: ApprovalId::new(&request.approval_id).map_err(|_| invalid_input())?,
            displayed_digest: Sha256Digest::new(&request.displayed_digest)
                .map_err(|_| invalid_input())?,
            expected_task_version: request.expected_task_version,
            actor_id: ActorId::new(&request.actor_id).map_err(|_| invalid_input())?,
            action: request.action,
            feedback: request.feedback,
        };
        let resolution = ResolvePlanApproval::new(store, store).execute(input)?;
        let task_id = resolution
            .append
            .projection_changes
            .first()
            .map(|change| match change {
                local_agent_terminal_application::ProjectionChange::TaskState {
                    task_id, ..
                } => task_id.as_str().to_owned(),
            })
            .ok_or_else(integrity_failure)?;
        Ok(PlanApprovalResolutionDto {
            approval_id: resolution.approval_id.as_str().to_owned(),
            task_id,
            task_version: resolution
                .expected_task_version
                .checked_add(1)
                .ok_or_else(integrity_failure)?,
            status: if resolution.action
                == local_agent_terminal_application::PlanApprovalAction::Reject
            {
                PlanApprovalResolutionStatusDto::Rejected
            } else {
                PlanApprovalResolutionStatusDto::Resolved
            },
            action: resolution.action,
        })
    }
}

fn present_agents(
    store: &SqliteStore,
    artifacts: &ContentAddressedArtifactStore,
    assignments: &[local_agent_terminal_application::DeliberationRunAssignment],
) -> Result<Vec<AgentRosterEntryDto>, PortError> {
    assignments
        .iter()
        .map(|assignment| {
            let run = AgentRunStore::load_run(store, assignment.run_id())?
                .ok_or_else(integrity_failure)?;
            let usage = store.agent_run_usage(assignment.run_id())?;
            let permissions =
                package_permissions(store, artifacts, &run.request.context.context_package_id)?;
            Ok(AgentRosterEntryDto {
                agent_id: run.request.agent_id.clone(),
                role: run.request.role.clone(),
                provider_label: format!(
                    "{}/{}",
                    run.request.run_config.provider_id, run.request.run_config.model_id
                ),
                locality: AgentLocalityDto::Cloud,
                status: agent_status_name(run.status).to_owned(),
                context_scope: run.request.context.context_package_id.clone(),
                context_package_id: Some(run.request.context.context_package_id.clone()),
                used_tokens: usage.used_tokens,
                cost_microunits: usage.cost_microunits,
                health: agent_status_name(run.status).to_owned(),
                permissions,
                trust_tier: run.request.connection.trust_tier.as_str().to_owned(),
                sandbox_status: run.request.connection.trust_tier.as_str().to_owned(),
                identity_changed: run.request.supersedes_run_id.is_some(),
            })
        })
        .collect()
}

fn package_permissions(
    store: &SqliteStore,
    artifacts: &ContentAddressedArtifactStore,
    package_id: &str,
) -> Result<Vec<String>, PortError> {
    let view = store
        .context_package_view(package_id)?
        .ok_or_else(integrity_failure)?;
    let value = read_artifact_value(artifacts, &view.artifact)?;
    required_string_array(&value, "permissions")
}

fn present_cards(
    artifacts: &ContentAddressedArtifactStore,
    snapshot: &local_agent_terminal_application::DeliberationSnapshot,
) -> Result<Vec<DeliberationCardDto>, PortError> {
    let mut cards = Vec::new();
    if let Some(quorum) = snapshot.quorum() {
        let published: Vec<_> = quorum
            .proposals()
            .iter()
            .map(|proposal| proposal.artifact_id().as_str())
            .collect();
        for proposal in snapshot.private_proposals().iter().filter(|proposal| {
            is_published_proposal(
                proposal.proposal_artifact().artifact_id().as_str(),
                &published,
            )
        }) {
            cards.push(card_from_artifact(
                artifacts,
                proposal.proposal_artifact(),
                DeliberationCardKindDto::Proposal,
                proposal.proposal().agent_id(),
                EvidenceStateDto::Unverified,
            )?);
        }
    }
    for review in snapshot.review_edges_history() {
        cards.push(card_from_artifact(
            artifacts,
            review.artifact(),
            DeliberationCardKindDto::Review,
            review.actor_id().as_str(),
            EvidenceStateDto::Unverified,
        )?);
    }
    for objection in snapshot.objection_sets() {
        cards.push(card_from_artifact(
            artifacts,
            objection.artifact(),
            DeliberationCardKindDto::Objection,
            objection.actor_id().as_str(),
            EvidenceStateDto::Unverified,
        )?);
    }
    for decision in snapshot.decision_drafts() {
        cards.push(card_from_artifact(
            artifacts,
            decision.artifact(),
            DeliberationCardKindDto::Decision,
            decision.actor_id().as_str(),
            EvidenceStateDto::Verified,
        )?);
    }
    Ok(cards)
}

fn is_published_proposal(proposal_id: &str, published: &[&str]) -> bool {
    published.contains(&proposal_id)
}

fn card_from_artifact(
    artifacts: &ContentAddressedArtifactStore,
    artifact: &local_agent_terminal_application::DeliberationArtifactRef,
    kind: DeliberationCardKindDto,
    actor_id: &str,
    evidence_state: EvidenceStateDto,
) -> Result<DeliberationCardDto, PortError> {
    let summary = read_deliberation_artifact_text(artifacts, artifact)?;
    let title = serde_json::from_str::<serde_json::Value>(&summary)
        .ok()
        .and_then(|value| {
            value
                .get("schema")
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned)
        })
        .unwrap_or_else(|| artifact.artifact_id().as_str().to_owned());
    Ok(DeliberationCardDto {
        card_id: artifact.artifact_id().as_str().to_owned(),
        kind,
        title,
        summary,
        actor_id: actor_id.to_owned(),
        evidence_state,
        stale: false,
        artifact_ids: vec![artifact.artifact_id().as_str().to_owned()],
    })
}

fn present_thread(
    artifacts: &ContentAddressedArtifactStore,
    summaries: &[local_agent_terminal_application::ThreadSummarySnapshot],
) -> Result<Option<DeliberationThreadDto>, PortError> {
    let Some(latest) = summaries.last() else {
        return Ok(None);
    };
    let messages = summaries
        .iter()
        .filter(|summary| summary.thread_id() == latest.thread_id())
        .map(|summary| {
            Ok(ThreadMessageDto {
                message_id: summary.event_id().as_str().to_owned(),
                actor_id: summary.actor_id().as_str().to_owned(),
                body: read_deliberation_artifact_text(artifacts, summary.artifact())?,
            })
        })
        .collect::<Result<Vec<_>, PortError>>()?;
    let summary = messages
        .last()
        .map(|message| message.body.clone())
        .ok_or_else(integrity_failure)?;
    Ok(Some(DeliberationThreadDto {
        thread_id: latest.thread_id().to_owned(),
        summary,
        messages,
        truncated: false,
    }))
}

fn present_evidence(
    snapshot: &local_agent_terminal_application::DeliberationSnapshot,
) -> Vec<DeliberationEvidenceDto> {
    snapshot
        .verification_sets()
        .iter()
        .flat_map(|set| set.claims())
        .flat_map(|claim| {
            claim.citations().iter().map(|citation| {
                let source = citation.source();
                DeliberationEvidenceDto {
                    artifact_id: claim.artifact_id().as_str().to_owned(),
                    label: claim.claim_id().to_owned(),
                    path_identity: source.path_identity().to_owned(),
                    line_range: citation.range().map(|range| ContextLineRangeDto {
                        start: range.start(),
                        end: range.end(),
                    }),
                    state: match claim.verification() {
                        Some(local_agent_terminal_application::ClaimVerification::Verified) => {
                            EvidenceStateDto::Verified
                        }
                        Some(local_agent_terminal_application::ClaimVerification::Inconclusive) => {
                            EvidenceStateDto::Inconclusive
                        }
                        Some(local_agent_terminal_application::ClaimVerification::Rejected)
                        | Some(
                            local_agent_terminal_application::ClaimVerification::NotApplicable,
                        )
                        | None => EvidenceStateDto::Unverified,
                    },
                    freshness: match citation.freshness() {
                        local_agent_terminal_application::EvidenceFreshness::Current => {
                            ContextFreshnessDto::Current
                        }
                        local_agent_terminal_application::EvidenceFreshness::Stale => {
                            ContextFreshnessDto::Stale
                        }
                    },
                }
            })
        })
        .collect()
}

fn read_deliberation_artifact_value(
    artifacts: &ContentAddressedArtifactStore,
    artifact: &local_agent_terminal_application::DeliberationArtifactRef,
) -> Result<serde_json::Value, PortError> {
    let content = read_deliberation_artifact_bytes(artifacts, artifact)?;
    serde_json::from_slice(&content).map_err(|_| integrity_failure())
}

fn read_deliberation_artifact_text(
    artifacts: &ContentAddressedArtifactStore,
    artifact: &local_agent_terminal_application::DeliberationArtifactRef,
) -> Result<String, PortError> {
    String::from_utf8(read_deliberation_artifact_bytes(artifacts, artifact)?)
        .map_err(|_| integrity_failure())
}

fn read_deliberation_artifact_bytes(
    artifacts: &ContentAddressedArtifactStore,
    artifact: &local_agent_terminal_application::DeliberationArtifactRef,
) -> Result<Vec<u8>, PortError> {
    let reference = ArtifactRef {
        content_hash: artifact.content_digest().as_str().to_owned(),
        storage_key: ContentAddressedArtifactStore::storage_key(
            artifact.content_digest().as_str(),
        )?,
        size_bytes: artifact.size_bytes(),
    };
    Ok(artifacts.read(&reference)?.bytes)
}

fn read_artifact_value(
    artifacts: &ContentAddressedArtifactStore,
    reference: &ArtifactRef,
) -> Result<serde_json::Value, PortError> {
    let content = artifacts.read(reference)?;
    serde_json::from_slice(&content.bytes).map_err(|_| integrity_failure())
}

const fn agent_status_name(
    status: local_agent_terminal_application::AgentRunStatus,
) -> &'static str {
    match status {
        local_agent_terminal_application::AgentRunStatus::Created => "created",
        local_agent_terminal_application::AgentRunStatus::Accepted => "accepted",
        local_agent_terminal_application::AgentRunStatus::Running => "running",
        local_agent_terminal_application::AgentRunStatus::Succeeded => "succeeded",
        local_agent_terminal_application::AgentRunStatus::Failed => "failed",
        local_agent_terminal_application::AgentRunStatus::CancelledCleanly => "cancelled_cleanly",
        local_agent_terminal_application::AgentRunStatus::Terminated => "terminated",
        local_agent_terminal_application::AgentRunStatus::Interrupted => "interrupted",
        local_agent_terminal_application::AgentRunStatus::Indeterminate => "indeterminate",
    }
}

fn present_plan_approval(
    store: &SqliteStore,
    artifacts: &ContentAddressedArtifactStore,
    approval: &local_agent_terminal_application::NewPlanApproval,
    decision: Option<&local_agent_terminal_application::DecisionDraftSnapshot>,
) -> Result<PlanApprovalViewDto, PortError> {
    let stored =
        PlanApprovalStore::reload(store, approval.approval_id())?.ok_or_else(integrity_failure)?;
    let status = match stored.state {
        local_agent_terminal_application::PlanApprovalState::Requested => {
            PlanApprovalStatusDto::Requested
        }
        local_agent_terminal_application::PlanApprovalState::Resolved => match stored.terminal {
            Some(local_agent_terminal_application::PlanApprovalTerminal::Resolved {
                action: local_agent_terminal_application::PlanApprovalAction::Reject,
                ..
            }) => PlanApprovalStatusDto::Rejected,
            _ => PlanApprovalStatusDto::Resolved,
        },
        local_agent_terminal_application::PlanApprovalState::Invalidated => {
            PlanApprovalStatusDto::Invalidated
        }
        local_agent_terminal_application::PlanApprovalState::Expired => {
            PlanApprovalStatusDto::Expired
        }
    };
    let binding = approval.binding();
    let decision = decision.ok_or_else(integrity_failure)?;
    if decision.plan_artifact().artifact_id().as_str() != binding.plan_artifact_id
        || decision.plan_artifact().content_digest().as_str() != binding.plan_digest
        || decision.plan_version() != binding.plan_version
    {
        return Err(integrity_failure());
    }
    let plan = read_deliberation_artifact_value(artifacts, decision.plan_artifact())?;
    let decision_package = decision.decision();
    let affected_files = optional_string_array(&plan, "files")
        .or_else(|| optional_string_array(&plan, "affectedFiles"))
        .unwrap_or_default();
    let planned_tools = optional_string_array(&plan, "tools")
        .or_else(|| optional_string_array(&plan, "plannedTools"))
        .unwrap_or_default();
    let verification_profile = plan
        .get("verificationProfile")
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned)
        .or_else(|| optional_string_array(&plan, "tests").map(|tests| tests.join(", ")))
        .unwrap_or_default();
    let rollback_plan = plan
        .get("rollback")
        .or_else(|| plan.get("rollbackPlan"))
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default()
        .to_owned();
    let security_implications = plan
        .get("risk")
        .and_then(serde_json::Value::as_str)
        .map(|risk| vec![risk.to_owned()])
        .unwrap_or_default();
    Ok(PlanApprovalViewDto {
        approval_id: approval.approval_id().as_str().to_owned(),
        task_id: approval.task_id().as_str().to_owned(),
        status,
        selected_approach_id: decision_package.selected().approach_id().to_owned(),
        selected_approach_label: decision_package.selected().approach_id().to_owned(),
        rejected_alternatives: decision_package
            .rejected()
            .iter()
            .map(|rejected| PlanRejectedAlternativeDto {
                approach_id: rejected.approach_id().to_owned(),
                label: rejected.approach_id().to_owned(),
                reason: rejected.reason().to_owned(),
            })
            .collect(),
        agreement: decision_package
            .dissent()
            .iter()
            .map(|dissent| PlanAgentAgreementDto {
                agent_id: dissent.participant_id().to_owned(),
                position: PlanAgreementPositionDto::Dissent,
                summary: dissent.reason().to_owned(),
            })
            .collect(),
        unresolved_objections: decision_package
            .dissent()
            .iter()
            .map(|dissent| dissent.dissent_id().to_owned())
            .collect(),
        affected_files,
        planned_tools,
        verification_profile,
        rollback_plan,
        security_implications,
        estimated_cost_microunits: plan
            .get("estimatedCostMicrounits")
            .and_then(serde_json::Value::as_u64),
        estimated_duration_seconds: plan
            .get("estimatedDurationSeconds")
            .and_then(serde_json::Value::as_u64),
        plan_version: binding.plan_version,
        policy_snapshot_digest: binding.policy_snapshot_digest.clone(),
        writable_scopes: binding
            .allowed_paths
            .iter()
            .map(|scope| scope.root_capability.clone())
            .collect(),
        fencing_epoch: binding.fencing_epoch,
        operation_digest: approval.operation_digest().as_str().to_owned(),
        expires_at: binding.expires_at.clone(),
    })
}

fn present_context_package(
    view: local_agent_terminal_storage_sqlite::StoredContextPackageView,
    value: &serde_json::Value,
    byte_len: usize,
) -> Result<ContextPackageDto, PortError> {
    if required_string(value, "schema")? != "context-package.v1"
        || required_u64(value, "version")? != 1
        || required_string(value, "packageId")? != view.package_id
        || required_string(value, "taskId")? != view.task_id
        || required_string(value, "agentId")? != view.agent_id
        || required_string(value, "role")? != view.role
        || required_string(value, "objective")? != view.objective
        || required_string(value, "effectiveContentArtifactId")? != view.artifact_id
        || required_string(value, "policySnapshotDigest")? != view.policy_snapshot_digest
    {
        return Err(integrity_failure());
    }
    let versions = value.get("versions").ok_or_else(integrity_failure)?;
    let budget = value.get("budget").ok_or_else(integrity_failure)?;
    if required_string(versions, "promptTemplate")? != view.prompt_template_version
        || required_string(versions, "retrievalPipeline")? != view.retrieval_pipeline_version
    {
        return Err(integrity_failure());
    }
    let items = value
        .get("items")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(integrity_failure)?;
    let members = items
        .iter()
        .filter_map(|item| item.get("citation").map(|citation| (item, citation)))
        .map(|(item, citation)| present_context_member(item, citation))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(ContextPackageDto {
        package_id: view.package_id,
        task_id: view.task_id,
        agent_id: view.agent_id,
        role: view.role,
        objective: view.objective,
        artifact_id: view.artifact_id,
        content_digest: view.artifact.content_hash,
        policy_snapshot_digest: view.policy_snapshot_digest,
        policy_decision_ids: view.policy_decision_ids,
        versions: ContextPackageVersionsDto {
            prompt_template: required_string(versions, "promptTemplate")?.to_owned(),
            retrieval_pipeline: required_string(versions, "retrievalPipeline")?.to_owned(),
            tokenizer: required_string(versions, "tokenizer")?.to_owned(),
        },
        budget: ContextPackageBudgetDto {
            max_tokens: required_u64(budget, "maxTokens")?,
            reserved_response_tokens: required_u64(budget, "reservedResponseTokens")?,
            used_input_tokens: u64::try_from(byte_len).map_err(|_| integrity_failure())?,
        },
        members,
    })
}

fn present_context_member(
    item: &serde_json::Value,
    citation: &serde_json::Value,
) -> Result<ContextPackageMemberDto, PortError> {
    let source = citation.get("source").ok_or_else(integrity_failure)?;
    let disclosure = item.get("disclosure").ok_or_else(integrity_failure)?;
    let line_range = citation
        .get("range")
        .filter(|value| !value.is_null())
        .map(|range| {
            Ok(ContextLineRangeDto {
                start: u32::try_from(required_u64(range, "start")?)
                    .map_err(|_| integrity_failure())?,
                end: u32::try_from(required_u64(range, "end")?).map_err(|_| integrity_failure())?,
            })
        })
        .transpose()?;
    let freshness = match required_string(citation, "freshness")? {
        "current" => ContextFreshnessDto::Current,
        "stale" => ContextFreshnessDto::Stale,
        _ => return Err(integrity_failure()),
    };
    let kind = match required_string(disclosure, "kind")? {
        "allowed" => ContextDisclosureKindDto::Allowed,
        "redacted" => ContextDisclosureKindDto::Redacted,
        "denied" => ContextDisclosureKindDto::Denied,
        _ => return Err(integrity_failure()),
    };
    Ok(ContextPackageMemberDto {
        member_id: required_string(item, "memberId")?.to_owned(),
        content: required_string(item, "content")?.to_owned(),
        source: ContextPackageSourceDto {
            project_id: required_string(source, "projectId")?.to_owned(),
            revision: required_string(source, "revision")?.to_owned(),
            path_identity: required_string(source, "pathIdentity")?.to_owned(),
            content_hash: required_string(source, "contentHash")?.to_owned(),
        },
        line_range,
        symbol: citation
            .get("symbol")
            .filter(|value| !value.is_null())
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned),
        freshness,
        disclosure: ContextDisclosureDto {
            kind,
            stable_report_id: disclosure
                .get("stableReportId")
                .filter(|value| !value.is_null())
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned),
        },
        policy_decision_ids: required_string_array(item, "policyDecisionIds")?,
        provenance: required_string_array(item, "provenance")?,
        redaction_report_ids: required_string_array(item, "redactionReportIds")?,
    })
}

fn required_string_array(value: &serde_json::Value, field: &str) -> Result<Vec<String>, PortError> {
    value
        .get(field)
        .and_then(serde_json::Value::as_array)
        .ok_or_else(integrity_failure)?
        .iter()
        .map(|entry| {
            entry
                .as_str()
                .filter(|entry| !entry.is_empty())
                .map(str::to_owned)
                .ok_or_else(integrity_failure)
        })
        .collect()
}

fn optional_string_array(value: &serde_json::Value, field: &str) -> Option<Vec<String>> {
    value.get(field)?.as_array().map(|values| {
        values
            .iter()
            .filter_map(serde_json::Value::as_str)
            .map(str::to_owned)
            .collect()
    })
}

fn required_string<'a>(value: &'a serde_json::Value, field: &str) -> Result<&'a str, PortError> {
    value
        .get(field)
        .and_then(serde_json::Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(integrity_failure)
}

fn required_u64(value: &serde_json::Value, field: &str) -> Result<u64, PortError> {
    value
        .get(field)
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(integrity_failure)
}

struct PreApprovalToolCatalog;

impl DeliberationToolCatalog for PreApprovalToolCatalog {
    fn dispatch_schemas(
        &self,
        _task_id: &TaskId,
    ) -> Result<Vec<DeliberationToolSchema>, PortError> {
        Ok(Vec::new())
    }
}

const fn recovery_action_dto(action: DeliberationRecoveryAction) -> DeliberationResumeActionDto {
    match action {
        DeliberationRecoveryAction::ValidateIntake => DeliberationResumeActionDto::ValidateIntake,
        DeliberationRecoveryAction::BuildInitialContext => {
            DeliberationResumeActionDto::BuildInitialContext
        }
        DeliberationRecoveryAction::AwaitIndependentProposals => {
            DeliberationResumeActionDto::AwaitIndependentProposals
        }
        DeliberationRecoveryAction::PublishQuorum => DeliberationResumeActionDto::PublishQuorum,
        DeliberationRecoveryAction::PersistReviewEdges => {
            DeliberationResumeActionDto::PersistReviewEdges
        }
        DeliberationRecoveryAction::FreezeMaterialClaims => {
            DeliberationResumeActionDto::FreezeMaterialClaims
        }
        DeliberationRecoveryAction::ClassifyMaterialClaims => {
            DeliberationResumeActionDto::ClassifyMaterialClaims
        }
        DeliberationRecoveryAction::SynthesizeDecision => {
            DeliberationResumeActionDto::SynthesizeDecision
        }
        DeliberationRecoveryAction::CollectFinalObjections => {
            DeliberationResumeActionDto::CollectFinalObjections
        }
        DeliberationRecoveryAction::CloseObjectionRound => {
            DeliberationResumeActionDto::CloseObjectionRound
        }
        DeliberationRecoveryAction::AwaitPlanApproval => {
            DeliberationResumeActionDto::AwaitPlanApproval
        }
        DeliberationRecoveryAction::PostApproval => DeliberationResumeActionDto::PostApproval,
    }
}

struct ProductionRepositoryAuthority {
    database: SqliteStore,
    repositories: GitRepositoryGateway,
    policy_snapshot_digest: Sha256Digest,
}

impl ProductionRepositoryAuthority {
    fn current_fingerprint(&self, task_id: &TaskId) -> Result<WorkspaceFingerprint, PortError> {
        let path = self.database.task_repository_path(task_id)?;
        let locator = self.repositories.locate_persisted(&path)?;
        Ok(self
            .repositories
            .inspect(InspectRepository { locator })?
            .fingerprint)
    }
}

impl DeliberationRepositoryAuthority for ProductionRepositoryAuthority {
    fn current_fingerprint(&self, task_id: &TaskId) -> Result<WorkspaceFingerprint, PortError> {
        self.current_fingerprint(task_id)
    }
}

impl PlanApprovalCurrentAuthoritySource for ProductionRepositoryAuthority {
    fn current_authority(
        &self,
        task_id: &TaskId,
    ) -> Result<PlanApprovalCurrentAuthority, PortError> {
        Ok(PlanApprovalCurrentAuthority {
            repository_fingerprint: workspace_fingerprint_digest(
                &self.current_fingerprint(task_id)?,
            )?,
            policy_snapshot_digest: self.policy_snapshot_digest.clone(),
        })
    }
}

fn workspace_fingerprint_digest(
    fingerprint: &WorkspaceFingerprint,
) -> Result<Sha256Digest, PortError> {
    let canonical = serde_json_canonicalizer::to_vec(&serde_json::json!({
        "head": fingerprint.head().as_str(),
        "indexDigest": fingerprint.index_digest(),
        "statusDigest": fingerprint.status_digest(),
    }))
    .map_err(|_| integrity_failure())?;
    let digest = Sha256::digest(canonical);
    Sha256Digest::new(format!("sha256:{digest:x}")).map_err(|_| integrity_failure())
}

fn integrity_failure() -> PortError {
    PortError::failure(
        SafeErrorClassification::IntegrityFailure,
        Retryability::NonRetryable,
    )
}

#[cfg(test)]
mod tests {
    use super::is_published_proposal;

    #[test]
    fn private_proposal_is_not_visible_after_a_different_quorum_is_published() {
        let published = ["proposal-selected-a", "proposal-selected-b"];

        assert!(is_published_proposal("proposal-selected-a", &published));
        assert!(!is_published_proposal("proposal-private", &published));
    }
}

fn invalid_input() -> PortError {
    PortError::failure(
        SafeErrorClassification::InvalidInput,
        Retryability::NonRetryable,
    )
}

fn not_found() -> PortError {
    PortError::failure(
        SafeErrorClassification::NotFound,
        Retryability::NonRetryable,
    )
}

fn unavailable() -> PortError {
    PortError::failure(
        SafeErrorClassification::Unavailable,
        Retryability::Retryable,
    )
}
