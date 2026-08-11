use std::sync::Arc;

use local_agent_terminal_application::{
    ActorId, AgentLocalityDto, AgentRosterEntryDto, ApprovalId, ArtifactStore,
    ContextDisclosureDto, ContextDisclosureKindDto, ContextFreshnessDto, ContextLineRangeDto,
    ContextPackageBudgetDto, ContextPackageDto, ContextPackageMemberDto, ContextPackageSourceDto,
    ContextPackageVersionsDto, DeliberationAvailabilityDto, DeliberationBoundaryStore,
    DeliberationRepositoryAuthority, DeliberationStore, DeliberationSynthesisStore,
    DeliberationWorkspaceDto, InspectRepository, PlanApprovalAuthorityProvider,
    PlanApprovalCurrentAuthority, PlanApprovalCurrentAuthoritySource, PlanApprovalResolutionDto,
    PlanApprovalResolutionStatusDto, PlanApprovalStatusDto, PlanApprovalStore, PlanApprovalViewDto,
    PortError, RepositoryGateway, ResolvePlanApproval, ResolvePlanApprovalInput,
    ResolvePlanApprovalRequestDto, Retryability, SafeErrorClassification, Sha256Digest, TaskId,
    WorkflowPhaseDto, WorkflowPhaseStateDto, WorkspaceFingerprint,
};
use local_agent_terminal_orchestration::DeliberationCoordinator;
use local_agent_terminal_repository_git::GitRepositoryGateway;
use local_agent_terminal_storage_files::{
    ContentAddressedArtifactReader, ContentAddressedArtifactStore,
};
use local_agent_terminal_storage_sqlite::SqliteStore;
use sha2::{Digest, Sha256};

pub(crate) fn compose_deliberation_runtime(
    database: SqliteStore,
    artifacts: Arc<ContentAddressedArtifactStore>,
    repositories: GitRepositoryGateway,
    policy_snapshot_digest: Sha256Digest,
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
    Arc::new(DeliberationRuntime::with_query_store(store, artifacts))
}

/// Owns the outer ports used by the deliberation coordinator.
///
/// Repository-boundary checks and deliberation transition policy remain in
/// `orchestration`; this type only supplies their concrete application ports.
pub struct DeliberationRuntime {
    authority: Option<Arc<dyn DeliberationRepositoryAuthority>>,
    boundaries: Option<Arc<dyn DeliberationBoundaryStore>>,
    store: Option<Arc<dyn DeliberationSynthesisStore>>,
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
            plan_approval_authority: None,
            query_store: None,
            artifacts: None,
        }
    }

    fn with_query_store(
        query_store: Arc<SqliteStore>,
        artifacts: Arc<ContentAddressedArtifactStore>,
    ) -> Self {
        Self {
            authority: None,
            boundaries: None,
            store: None,
            plan_approval_authority: None,
            query_store: Some(query_store),
            artifacts: Some(artifacts),
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

    pub fn workspace(&self, task_id: &str) -> Result<DeliberationWorkspaceDto, PortError> {
        let task_id = TaskId::new(task_id).map_err(|_| invalid_input())?;
        let store = self.query_store.as_deref().ok_or_else(unavailable)?;
        let snapshot = DeliberationStore::load(store, &task_id)?;
        let approval = snapshot
            .plan_approval()
            .map(|approval| present_plan_approval(store, approval))
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
            agents: snapshot
                .run_assignments
                .iter()
                .map(|assignment| AgentRosterEntryDto {
                    agent_id: assignment.agent_id().to_owned(),
                    role: "deliberation".to_owned(),
                    provider_label: assignment.family().as_str().to_owned(),
                    locality: AgentLocalityDto::Cloud,
                    status: "assigned".to_owned(),
                    context_scope: "immutable-package".to_owned(),
                    context_package_id: None,
                    used_tokens: 0,
                    cost_microunits: 0,
                    health: "unknown".to_owned(),
                    permissions: vec!["context.query".to_owned()],
                    trust_tier: "restricted".to_owned(),
                    sandbox_status: "provider-boundary".to_owned(),
                    identity_changed: false,
                })
                .collect(),
            cards: Vec::new(),
            thread: None,
            evidence: Vec::new(),
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

fn present_plan_approval(
    store: &SqliteStore,
    approval: &local_agent_terminal_application::NewPlanApproval,
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
    Ok(PlanApprovalViewDto {
        approval_id: approval.approval_id().as_str().to_owned(),
        task_id: approval.task_id().as_str().to_owned(),
        status,
        selected_approach_id: binding.plan_artifact_id.clone(),
        selected_approach_label: binding.plan_artifact_id.clone(),
        rejected_alternatives: Vec::new(),
        agreement: Vec::new(),
        unresolved_objections: Vec::new(),
        affected_files: binding
            .allowed_paths
            .iter()
            .flat_map(|scope| scope.patterns.iter().cloned())
            .collect(),
        planned_tools: binding.planned_tool_digests.clone(),
        verification_profile: binding.verification_profile_digest.clone(),
        rollback_plan: "Use the immutable pre-implementation repository state.".to_owned(),
        security_implications: Vec::new(),
        estimated_cost_microunits: None,
        estimated_duration_seconds: None,
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
