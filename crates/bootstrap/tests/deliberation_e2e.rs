#[path = "deliberation_e2e/support.rs"]
mod deliberation_support;
#[allow(dead_code)]
mod support;

use std::{
    fs,
    io::{BufRead, BufReader, Read, Write},
    net::{TcpListener, TcpStream},
    sync::{mpsc, Mutex},
    thread,
    time::Duration,
};

use git2::Repository;
use local_agent_terminal_application::{
    canonical_plan_approval_payload, ActorId, AgentRunStore, ApprovalId, ArtifactWriteReservation,
    BuildInitialContextRequest, Clock, ContextBuildPolicy, ContextPackageDraft, ContextQuery,
    DeliberationArtifactRef, DeliberationBoundaryCheck, DeliberationBoundaryRecord,
    DeliberationBoundaryStore, DeliberationCommandContext, DeliberationCommands,
    DeliberationDispatchStore, DeliberationPhaseDispatchSet, DeliberationProposalDispatchPlan,
    DeliberationRepositoryAuthority, DeliberationRunAssignment, DeliberationStore,
    DeliberationToolCatalog, DeliberationToolSchema, InitialDeliberationPhaseRequest,
    InspectRepository, PlanApprovalAction, PlanApprovalAuthorityBinding,
    PlanApprovalAuthorityProvider, PlanApprovalBindingInput, PlanApprovalCurrentAuthority,
    PlanApprovalCurrentAuthoritySource, PlanApprovalPathScopeV1, PreparePlanApprovalRequestInput,
    QueryContextRequest, RepositoryContextSource, RepositoryGateway, ReservedArtifact,
    ResolvePlanApproval, ResolvePlanApprovalInput, SourceSnapshotRequest,
};
use local_agent_terminal_bootstrap::{
    AnthropicApiKey, AnthropicBootstrapConfig, Bootstrap, OpenAiApiKey, OpenAiBootstrapConfig,
    StartupConfig, StartupStateDto,
};
use local_agent_terminal_domain::{
    ActorLocality, AgentFamilyKey, AgentRunLimits, AgentRunStatus, ArtifactId,
    BoundAgentConnection, BoundAgentRunRequest, BoundEffectiveContext, BoundGenerationParameters,
    BoundRunConfig, ClaimVerification, ContextBudget, ContextPackageBinding,
    ContextPackageDescriptor, ContextPackageIdentity, ContextVersionSet, DecisionApproach,
    DecisionPackage, DeliberationLimits, DisclosureKind, Dissent, EventId, EvidenceCitation,
    EvidenceFreshness, FinalObjection, FinalObjectionSet, IndependentProposal, MaterialClaim,
    ObjectionSeverity, Phase, PolicyActor, RejectedApproach, ReviewEdge, ReviewPlan, RunId,
    Sha256Digest, SpecialistBudget, SpecialistRequest, TaskId, TaskRisk, Timestamp, TrustTier,
    VerificationMethod, WorkflowState, WorkspaceFingerprint,
};
use local_agent_terminal_orchestration::{
    normative_preapproval_transitions, PreApprovalCoordinator, PrePlanOperation,
};
use local_agent_terminal_repository_git::{GitRepositoryContextSource, GitRepositoryGateway};
use local_agent_terminal_storage_files::{
    ContentAddressedArtifactReader, ContentAddressedArtifactStore, JournaledArtifactWriter,
};
use local_agent_terminal_storage_sqlite::SqliteStore;
use rusqlite::{params, Connection};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use deliberation_support::{commit_context_sources, durable_workspace_bytes};
use support::{WorkspaceFixture, PROJECT_ID, TASK_ID};

const CAPTURED_AT: &str = "2026-08-11T08:00:00Z";
const SECRET_CANARY: &str = "m4-secret-canary-must-not-persist";
const OPENAI_MANIFEST_DIGEST: &str =
    "sha256:28d00daa6b56f0d8bb9b6ad78dd561a24bb61c668af842446c3a845e5b8ff0e5";
const ANTHROPIC_MANIFEST_DIGEST: &str =
    "sha256:e976f4331c4cbec86f78ac1becd262f1aa26c577092d64e30c8d3d35f8e0cea8";
const CORE_RELEASE_DIGEST: &str =
    "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const POLICY_DIGEST: &str =
    "sha256:307c8dbce9694982020fffc33c685d6f62bb4554f73794f3fd67b812d0ba6ed6";

struct RolePackageSpec {
    package_id: &'static str,
    agent_id: &'static str,
    connection_id: &'static str,
    role: &'static str,
    manifest_artifact_id: &'static str,
    manifest_digest: &'static str,
    context_artifact_id: &'static str,
    objective: &'static str,
}

const LEAD_CONTEXT: RolePackageSpec = RolePackageSpec {
    package_id: "package-lead",
    agent_id: "core_adapter",
    connection_id: "openai_core_adapter",
    role: "lead",
    manifest_artifact_id: "manifest-openai",
    manifest_digest: OPENAI_MANIFEST_DIGEST,
    context_artifact_id: "context-package-lead",
    objective: "select implementation evidence",
};

const VERIFIER_CONTEXT: RolePackageSpec = RolePackageSpec {
    package_id: "package-verifier",
    agent_id: "anthropic_core_adapter",
    connection_id: "anthropic_core_adapter",
    role: "verifier",
    manifest_artifact_id: "manifest-anthropic",
    manifest_digest: ANTHROPIC_MANIFEST_DIGEST,
    context_artifact_id: "context-package-verifier",
    objective: "verify implementation evidence",
};

#[test]
fn startup_composes_context_runtime_from_authoritative_adapters() {
    let fixture = WorkspaceFixture::new();
    let bootstrap = Bootstrap::new(context_startup_config(&fixture));

    assert_eq!(bootstrap.status().state, StartupStateDto::Ready);
    assert!(bootstrap.context_runtime().is_some());
}

#[test]
fn real_source_policy_and_storage_block_secrets_before_index_and_bind_the_package() {
    let fixture = WorkspaceFixture::new();
    commit_context_sources(&fixture, SECRET_CANARY);
    let source = GitRepositoryContextSource::new(fixture.locator.clone(), CAPTURED_AT)
        .expect("context source");
    let revision = Repository::open(&fixture.source)
        .expect("repository")
        .head()
        .expect("head")
        .target()
        .expect("head target")
        .to_string();
    let request = context_request(
        revision,
        source.repository_fingerprint().expect("fingerprint"),
        &LEAD_CONTEXT,
    );
    let captured = source
        .snapshot(request.snapshot.clone())
        .expect("coherent source snapshot");
    assert_eq!(captured.items.len(), 3);
    let bootstrap = Bootstrap::new(context_startup_config(&fixture));
    let runtime = bootstrap.context_runtime().expect("context runtime");

    let package = match runtime.build_initial(fixture.locator.clone(), CAPTURED_AT, request) {
        Ok(package) => package,
        Err(error) => {
            let connection = fixture.database();
            let counts = [
                "policy_decisions",
                "artifacts",
                "source_documents",
                "source_chunks",
                "context_packages",
            ]
            .map(|table| {
                connection
                    .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                        row.get::<_, i64>(0)
                    })
                    .expect("diagnostic count")
            });
            panic!("initial context failed: {error:?}; table counts: {counts:?}");
        }
    };

    assert_eq!(package.members().len(), 2);
    assert!(package
        .members()
        .iter()
        .all(|member| member.citation().source().path_identity() != ".env"));
    assert!(package.policy().decision_ids().len() >= 5);

    let connection = fixture.database();
    let indexed_secret_count: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM source_documents WHERE logical_path = '.env'",
            [],
            |row| row.get(0),
        )
        .expect("secret count");
    let package_policy_count: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM context_package_policy_decisions WHERE package_id = 'package-lead'",
            [],
            |row| row.get(0),
        )
        .expect("package policy count");
    assert_eq!(indexed_secret_count, 0);
    assert_eq!(
        package_policy_count,
        i64::try_from(package.policy().decision_ids().len()).expect("decision count")
    );
    assert!(!durable_workspace_bytes(&fixture)
        .windows(SECRET_CANARY.len())
        .any(|window| { window == SECRET_CANARY.as_bytes() }));
}

#[test]
fn two_role_specific_packages_bind_exact_policy_redaction_and_provenance() {
    let fixture = WorkspaceFixture::new();
    commit_context_sources(&fixture, SECRET_CANARY);
    let source = GitRepositoryContextSource::new(fixture.locator.clone(), CAPTURED_AT)
        .expect("context source");
    let revision = Repository::open(&fixture.source)
        .expect("repository")
        .head()
        .expect("head")
        .target()
        .expect("head target")
        .to_string();
    let repository_fingerprint = source.repository_fingerprint().expect("fingerprint");
    let bootstrap = Bootstrap::new(context_startup_config(&fixture));
    let runtime = bootstrap.context_runtime().expect("context runtime");

    let lead = runtime
        .build_initial(
            fixture.locator.clone(),
            CAPTURED_AT,
            context_request(revision.clone(), repository_fingerprint, &LEAD_CONTEXT),
        )
        .expect("lead package");
    let verifier = runtime
        .query(query_request(&VERIFIER_CONTEXT))
        .expect("verifier package");

    assert_role_package(&lead, &LEAD_CONTEXT, &revision);
    assert_role_package(&verifier, &VERIFIER_CONTEXT, &revision);
    assert_ne!(
        lead.artifact().content_digest(),
        verifier.artifact().content_digest()
    );

    let connection = fixture.database();
    assert_linked_policy(&connection, &LEAD_CONTEXT, [3, 2, 0, 1], 6, 1);
    assert_linked_policy(&connection, &VERIFIER_CONTEXT, [2, 2, 2, 1], 7, 0);
}

#[test]
fn heterogeneous_loopback_proposals_remain_private_until_quorum_publication() {
    let fixture = WorkspaceFixture::new();
    commit_context_sources(&fixture, SECRET_CANARY);
    let repository_before = repository_state(&fixture.source);
    let source = GitRepositoryContextSource::new(fixture.locator.clone(), CAPTURED_AT)
        .expect("context source");
    let revision = Repository::open(&fixture.source)
        .expect("repository")
        .head()
        .expect("head")
        .target()
        .expect("head target")
        .to_string();
    let repository_fingerprint = source.repository_fingerprint().expect("fingerprint");
    let mut openai = GatedProvider::openai("openai independent proposal");
    let mut anthropic = GatedProvider::anthropic("anthropic independent proposal");
    let bootstrap = Bootstrap::new(startup_config_with_endpoints(
        &fixture,
        openai.endpoint(),
        anthropic.endpoint(),
    ));
    let contexts = bootstrap.context_runtime().expect("context runtime");
    let lead = contexts
        .build_initial(
            fixture.locator.clone(),
            CAPTURED_AT,
            context_request(revision.clone(), repository_fingerprint, &LEAD_CONTEXT),
        )
        .expect("lead context");
    let verifier = contexts
        .query(query_request(&VERIFIER_CONTEXT))
        .expect("verifier context");
    let database = SqliteStore::open(&fixture.database_path)
        .expect("database")
        .with_artifact_reader(std::sync::Arc::new(ContentAddressedArtifactReader));
    let fingerprint = current_fingerprint(&fixture);
    let approval_repository_digest = workspace_fingerprint_digest(&fingerprint);
    let authority = FixedRepositoryAuthority {
        fingerprint: fingerprint.clone(),
    };
    let boundaries = ExactBoundaryStore::new(fingerprint);
    let tools = EmptyToolCatalog;
    let dispatches = RecordingDispatchStore::default();
    let agents = bootstrap
        .agent_runtime_handle()
        .expect("two-provider runtime");
    let coordinator = PreApprovalCoordinator::new(
        &authority,
        &boundaries,
        &database,
        &tools,
        &dispatches,
        agents.as_ref(),
    );
    let task_id = TaskId::new(TASK_ID).expect("task id");
    let lead_artifact = package_artifact_ref(&fixture, &lead);
    let intake = database.load(&task_id).expect("intake snapshot");
    coordinator
        .coordinate(PrePlanOperation::AdvanceOnly {
            request: phase_request(
                intake.task_state,
                lead_artifact.clone(),
                "event-context-build",
            ),
            transition: normative_preapproval_transitions()[0],
        })
        .expect("enter context build");

    let openai_request = proposal_run_request(
        "run-openai-proposal",
        &lead,
        &LEAD_CONTEXT,
        ProviderRunBinding::openai(),
    );
    let anthropic_request = proposal_run_request(
        "run-anthropic-proposal",
        &verifier,
        &VERIFIER_CONTEXT,
        ProviderRunBinding::anthropic(),
    );
    let dispatch_plan = DeliberationProposalDispatchPlan::new(
        local_agent_terminal_application::DeliberationDispatchBinding::new(
            openai_request.clone(),
            proposal_assignment(&openai_request),
        )
        .expect("OpenAI dispatch"),
        local_agent_terminal_application::DeliberationDispatchBinding::new(
            anthropic_request.clone(),
            proposal_assignment(&anthropic_request),
        )
        .expect("Anthropic dispatch"),
    )
    .expect("heterogeneous dispatch plan");
    let context_build = database.load(&task_id).expect("context build snapshot");
    let dispatch_result = coordinator.coordinate(PrePlanOperation::AdvanceAndDispatch {
        request: phase_request(
            context_build.task_state,
            package_artifact_ref(&fixture, &verifier),
            "event-parallel-analysis",
        ),
        transition: normative_preapproval_transitions()[1],
        dispatch_plan: Box::new(dispatch_plan),
    });
    if let Err(error) = dispatch_result {
        let run_count: i64 = fixture
            .database()
            .query_row("SELECT COUNT(*) FROM agent_runs", [], |row| row.get(0))
            .expect("agent run count");
        let run_config_count: i64 = fixture
            .database()
            .query_row(
                "SELECT COUNT(*) FROM artifacts WHERE artifact_type = 'run-config'",
                [],
                |row| row.get(0),
            )
            .expect("run config count");
        panic!(
            "dispatch independent proposals failed: {error:?}; runs={run_count}; run_configs={run_config_count}; bindings={}",
            dispatches.proposal_count()
        );
    }

    let openai_http = openai.await_request();
    let anthropic_http = anthropic.await_request();
    assert!(!openai_http
        .windows(b"anthropic independent proposal".len())
        .any(|window| { window == b"anthropic independent proposal" }));
    assert!(!anthropic_http
        .windows(b"openai independent proposal".len())
        .any(|window| { window == b"openai independent proposal" }));
    openai.release_and_join();
    anthropic.release_and_join();
    wait_for_terminal(&database, &openai_request.run_id);
    wait_for_terminal(&database, &anthropic_request.run_id);

    assert_eq!(message_count(&fixture.database(), None), 0);
    let openai_output = private_run_output(&fixture.database(), &openai_request.run_id);
    let anthropic_output = private_run_output(&fixture.database(), &anthropic_request.run_id);
    let commands = DeliberationCommands::new(&database);
    let first_snapshot = database.load(&task_id).expect("parallel snapshot");
    commands
        .record_private_proposal(
            command_context(
                &first_snapshot,
                ActorId::new(LEAD_CONTEXT.agent_id).expect("lead actor"),
                openai_output.clone(),
                "event-private-openai",
            ),
            independent_proposal(&openai_request, &openai_output, &lead),
            openai_output.clone(),
        )
        .expect("private OpenAI proposal");
    let second_snapshot = database.load(&task_id).expect("first private proposal");
    commands
        .record_private_proposal(
            command_context(
                &second_snapshot,
                ActorId::new(VERIFIER_CONTEXT.agent_id).expect("verifier actor"),
                anthropic_output.clone(),
                "event-private-anthropic",
            ),
            independent_proposal(&anthropic_request, &anthropic_output, &verifier),
            anthropic_output.clone(),
        )
        .expect("private Anthropic proposal");
    assert_eq!(message_count(&fixture.database(), None), 0);

    let specialist_artifact = publish_deliberation_artifact(
        &fixture,
        "specialist-request-1",
        br#"{"capability":"repository-analysis","maxTokens":128,"schema":"m4-specialist-request.v1"}"#,
    );
    let specialist_request = SpecialistRequest::new(
        "specialist-request-1",
        task_id.clone(),
        openai_request.run_id.clone(),
        "repository-analysis",
        "verify repository invariants for the selected proposal",
        vec![lead_artifact.artifact_id().clone()],
        SpecialistBudget::new(128, Timestamp::from_unix_seconds(2_000_000_000))
            .expect("specialist budget"),
    )
    .expect("bounded specialist request");
    let specialist_snapshot = database.load(&task_id).expect("specialist snapshot");
    commands
        .request_specialist(
            command_context(
                &specialist_snapshot,
                ActorId::new(LEAD_CONTEXT.agent_id).expect("lead actor"),
                specialist_artifact.clone(),
                "event-specialist-request",
            ),
            specialist_request.clone(),
        )
        .expect("specialist request");
    let duplicate_snapshot = database.load(&task_id).expect("specialist recorded");
    assert!(commands
        .request_specialist(
            command_context(
                &duplicate_snapshot,
                ActorId::new(LEAD_CONTEXT.agent_id).expect("lead actor"),
                specialist_artifact.clone(),
                "event-specialist-duplicate",
            ),
            specialist_request,
        )
        .is_err());
    assert_eq!(
        database
            .load(&task_id)
            .expect("bounded specialist snapshot")
            .specialist_requests()
            .len(),
        1
    );

    let review_artifact = publish_deliberation_artifact(
        &fixture,
        "quorum-review-plan",
        br#"{"round":1,"schema":"m4-review-plan.v1"}"#,
    );
    let review_plan = ReviewPlan::new(
        DeliberationLimits::new(2, 2, 2, 1).expect("deliberation limits"),
        vec![
            ReviewEdge::new(
                VERIFIER_CONTEXT.agent_id,
                openai_output.artifact_id().clone(),
                1,
            )
            .expect("OpenAI review edge"),
            ReviewEdge::new(
                LEAD_CONTEXT.agent_id,
                anthropic_output.artifact_id().clone(),
                1,
            )
            .expect("Anthropic review edge"),
        ],
    )
    .expect("review plan");
    let quorum_snapshot = database.load(&task_id).expect("private quorum snapshot");
    commands
        .publish_proposals(
            command_context(
                &quorum_snapshot,
                ActorId::new("core").expect("core actor"),
                review_artifact.clone(),
                "event-quorum-publication",
            ),
            review_plan.clone(),
            review_artifact.clone(),
        )
        .expect("quorum publication");

    assert_eq!(message_count(&fixture.database(), Some("proposal")), 2);
    let published = database.load(&task_id).expect("published quorum");
    assert_eq!(published.task_state.phase(), Phase::CrossReview);
    assert!(published
        .quorum
        .as_ref()
        .expect("heterogeneous quorum")
        .proposals()
        .iter()
        .all(IndependentProposal::is_revealed));
    commands
        .record_review_edges(
            command_context(
                &published,
                ActorId::new("core").expect("core actor"),
                review_artifact.clone(),
                "event-review-edges",
            ),
            review_plan.clone(),
        )
        .expect("controlled review edges");
    let reviewed = database.load(&task_id).expect("review edges snapshot");
    assert!(commands
        .record_review_edges(
            command_context(
                &reviewed,
                ActorId::new("core").expect("core actor"),
                review_artifact,
                "event-review-edges-duplicate",
            ),
            review_plan,
        )
        .is_err());
    let specialist_summary = publish_deliberation_artifact(
        &fixture,
        "specialist-summary-1",
        br#"{"accepted":true,"schema":"m4-specialist-summary.v1","summary":"repository invariants preserved"}"#,
    );
    commands
        .record_thread_summary(
            command_context(
                &reviewed,
                ActorId::new("core").expect("core actor"),
                specialist_summary,
                "event-specialist-summary",
            ),
            "specialist-thread-1",
        )
        .expect("accepted specialist summary");
    let completed_review = database.load(&task_id).expect("completed cross-review");
    assert_eq!(
        completed_review
            .review_edges()
            .expect("review edges")
            .plan()
            .edges()
            .len(),
        2
    );
    assert_eq!(completed_review.thread_summaries().len(), 1);

    let current_claim = MaterialClaim::new(
        "claim-current-source",
        LEAD_CONTEXT.agent_id,
        openai_output.artifact_id().clone(),
        vec![lead.members()[0].citation().clone()],
        VerificationMethod::SourceMatch,
    )
    .expect("current material claim");
    let stale_citation =
        citation_with_freshness(verifier.members()[0].citation(), EvidenceFreshness::Stale);
    let stale_claim = MaterialClaim::new(
        "claim-stale-source",
        VERIFIER_CONTEXT.agent_id,
        anthropic_output.artifact_id().clone(),
        vec![stale_citation],
        VerificationMethod::SourceMatch,
    )
    .expect("stale material claim");
    assert!(stale_claim
        .clone()
        .classify(ClaimVerification::Verified)
        .is_err());
    let second_round_claims = vec![current_claim.clone(), stale_claim.clone()];
    let claim_artifact = publish_deliberation_artifact(
        &fixture,
        "material-claims-1",
        br#"{"claims":["claim-current-source","claim-stale-source"],"schema":"m4-material-claims.v1"}"#,
    );
    commands
        .record_claim_set(
            command_context(
                &completed_review,
                ActorId::new("core").expect("core actor"),
                claim_artifact,
                "event-material-claims",
            ),
            vec![current_claim.clone(), stale_claim.clone()],
        )
        .expect("material claim set");
    let verification = vec![
        current_claim
            .classify(ClaimVerification::Verified)
            .expect("verified current claim"),
        stale_claim
            .classify(ClaimVerification::Inconclusive)
            .expect("inconclusive stale claim"),
    ];
    let preplan = database.load(&task_id).expect("pre-plan verification");
    assert_eq!(preplan.task_state.phase(), Phase::PrePlanVerification);
    let verification_artifact = publish_deliberation_artifact(
        &fixture,
        "claim-verification-1",
        br#"{"claim-current-source":"verified","claim-stale-source":"inconclusive","schema":"m4-claim-verification.v1"}"#,
    );
    commands
        .record_verification_set(
            command_context(
                &preplan,
                ActorId::new("core").expect("core actor"),
                verification_artifact,
                "event-claim-verification",
            ),
            verification.clone(),
        )
        .expect("terminal claim classifications");
    let synthesis = database.load(&task_id).expect("synthesis snapshot");
    assert_eq!(synthesis.task_state.phase(), Phase::Synthesis);
    assert!(synthesis.claims().iter().all(|claim| claim
        .verification()
        .is_some_and(ClaimVerification::is_terminal)));
    let verification_round_two = verification.clone();

    let plan_artifact = publish_deliberation_artifact(
        &fixture,
        "plan-1",
        br#"{"confidence":"medium","cost":"bounded","dissent":["dissent-anthropic"],"files":["crates/bootstrap/src/context_runtime.rs"],"rejected":["anthropic-alternative"],"risk":"medium","rollback":"revert exact commit","schema":"m4-plan.v1","selected":"openai-approach","steps":["implement"],"tests":["cargo test"],"tools":["cargo"]}"#,
    );
    let decision = evidence_linked_decision(
        &openai_output,
        &anthropic_output,
        verification,
        plan_artifact.artifact_id().clone(),
    );
    let decision_artifact = publish_deliberation_artifact(
        &fixture,
        "decision-draft-1",
        br#"{"decision":"openai-approach","schema":"m4-decision.v1"}"#,
    );
    commands
        .synthesize(
            command_context(
                &synthesis,
                ActorId::new("core").expect("core actor"),
                decision_artifact.clone(),
                "event-decision-draft",
            ),
            decision,
            plan_artifact,
            1,
        )
        .expect("evidence-linked synthesis");
    let final_objection = database.load(&task_id).expect("final objection snapshot");
    assert_eq!(final_objection.task_state.phase(), Phase::FinalObjection);
    let preserved = final_objection
        .decision_drafts()
        .last()
        .expect("decision draft")
        .decision();
    assert_eq!(preserved.selected().approach_id(), "openai-approach");
    assert_eq!(preserved.rejected().len(), 1);
    assert_eq!(preserved.evidence().len(), 2);
    assert_eq!(preserved.dissent().len(), 1);

    let objection_artifact = publish_deliberation_artifact(
        &fixture,
        "objection-set-1",
        br#"{"round":1,"schema":"m4-objection-set.v1","severity":"severe"}"#,
    );
    let severe_objections = FinalObjectionSet::new(
        1,
        vec![FinalObjection::new(
            VERIFIER_CONTEXT.agent_id,
            1,
            ObjectionSeverity::Severe,
            "the stale repository citation must be reviewed in one bounded round",
            vec![verifier.members()[0].citation().clone()],
            Some("fresh evidence is required for the repository invariant"),
        )
        .expect("severe objection")],
    )
    .expect("objection set");
    commands
        .record_objection_set(
            command_context(
                &final_objection,
                ActorId::new("core").expect("core actor"),
                objection_artifact,
                "event-objection-set-1",
            ),
            severe_objections,
        )
        .expect("severe objection record");
    let objection_recorded = database.load(&task_id).expect("recorded objection");
    let reopened_review_artifact = publish_deliberation_artifact(
        &fixture,
        "review-plan-2",
        br#"{"round":2,"schema":"m4-review-plan.v1"}"#,
    );
    let reopened_review_plan = review_plan_for_round(2, &openai_output, &anthropic_output);
    commands
        .accept_severe_objection(
            command_context(
                &objection_recorded,
                ActorId::new("core").expect("core actor"),
                reopened_review_artifact.clone(),
                "event-severe-objection-accepted",
            ),
            reopened_review_plan.clone(),
        )
        .expect("bounded review reopening");
    let reopened_review = database.load(&task_id).expect("reopened cross-review");
    assert_eq!(reopened_review.task_state.phase(), Phase::CrossReview);
    assert_eq!(reopened_review.decision_drafts().len(), 1);
    assert_eq!(reopened_review.severe_objection_acceptances().len(), 1);
    commands
        .record_review_edges(
            command_context(
                &reopened_review,
                ActorId::new("core").expect("core actor"),
                reopened_review_artifact,
                "event-review-edges-2",
            ),
            reopened_review_plan,
        )
        .expect("second-round review edges");
    let second_review = database.load(&task_id).expect("second review snapshot");
    let second_claim_artifact = publish_deliberation_artifact(
        &fixture,
        "material-claims-2",
        br#"{"round":2,"schema":"m4-material-claims.v1"}"#,
    );
    commands
        .record_claim_set(
            command_context(
                &second_review,
                ActorId::new("core").expect("core actor"),
                second_claim_artifact,
                "event-material-claims-2",
            ),
            second_round_claims,
        )
        .expect("second-round claims");
    let second_preplan = database
        .load(&task_id)
        .expect("second pre-plan verification");
    let second_verification_artifact = publish_deliberation_artifact(
        &fixture,
        "claim-verification-2",
        br#"{"round":2,"schema":"m4-claim-verification.v1"}"#,
    );
    commands
        .record_verification_set(
            command_context(
                &second_preplan,
                ActorId::new("core").expect("core actor"),
                second_verification_artifact,
                "event-claim-verification-2",
            ),
            verification_round_two.clone(),
        )
        .expect("second-round verification");
    let second_synthesis = database.load(&task_id).expect("second synthesis");
    let plan_two = publish_deliberation_artifact(
        &fixture,
        "plan-2",
        br#"{"round":2,"schema":"m4-plan.v1","selected":"openai-approach"}"#,
    );
    let decision_two = publish_deliberation_artifact(
        &fixture,
        "decision-draft-2",
        br#"{"round":2,"schema":"m4-decision.v1"}"#,
    );
    commands
        .record_supersession(
            command_context(
                &second_synthesis,
                ActorId::new("core").expect("core actor"),
                decision_two.clone(),
                "event-decision-supersession",
            ),
            decision_artifact,
        )
        .expect("immutable decision supersession");
    let superseded = database.load(&task_id).expect("supersession snapshot");
    commands
        .synthesize(
            command_context(
                &superseded,
                ActorId::new("core").expect("core actor"),
                decision_two,
                "event-decision-draft-2",
            ),
            evidence_linked_decision(
                &openai_output,
                &anthropic_output,
                verification_round_two,
                plan_two.artifact_id().clone(),
            ),
            plan_two.clone(),
            2,
        )
        .expect("superseding synthesis");
    let second_final = database.load(&task_id).expect("second final objection");
    assert_eq!(second_final.task_state.phase(), Phase::FinalObjection);
    assert_eq!(second_final.decision_drafts().len(), 2);
    assert_eq!(second_final.supersessions().len(), 1);
    let no_objection_artifact = publish_deliberation_artifact(
        &fixture,
        "objection-set-2",
        br#"{"objections":[],"round":2,"schema":"m4-objection-set.v1"}"#,
    );
    commands
        .record_objection_set(
            command_context(
                &second_final,
                ActorId::new("core").expect("core actor"),
                no_objection_artifact,
                "event-objection-set-2",
            ),
            FinalObjectionSet::new(2, Vec::new()).expect("closed objection set"),
        )
        .expect("close bounded objection history");

    let approval_snapshot = database
        .load(&task_id)
        .expect("approval preparation snapshot");
    let approval_policy_digest = lead.policy().policy_snapshot_digest().clone();
    let (approval_base_commit, approval_risk): (String, String) = fixture
        .database()
        .query_row(
            "SELECT base_commit, risk_level FROM tasks WHERE id = ?1",
            [TASK_ID],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .expect("approval task authority");
    let approval_binding = PlanApprovalBindingInput {
        task_id: TASK_ID.to_owned(),
        plan_artifact_id: plan_two.artifact_id().as_str().to_owned(),
        plan_digest: plan_two.content_digest().as_str().to_owned(),
        plan_version: 2,
        base_commit: approval_base_commit,
        allowed_paths: vec![PlanApprovalPathScopeV1 {
            root_capability: "workspace".to_owned(),
            patterns: vec!["crates/**".to_owned()],
        }],
        planned_tool_digests: vec![digest_bytes(b"cargo").as_str().to_owned()],
        verification_profile_digest: digest_bytes(b"m4-complete-gate").as_str().to_owned(),
        risk_class: approval_risk,
        repository_fingerprint: approval_repository_digest.as_str().to_owned(),
        policy_snapshot_digest: approval_policy_digest.as_str().to_owned(),
        agent_id: LEAD_CONTEXT.agent_id.to_owned(),
        agent_manifest_digest: OPENAI_MANIFEST_DIGEST.to_owned(),
        actor_id: "approver-1".to_owned(),
        task_version: approval_snapshot.task_version + 1,
        workspace_version: approval_snapshot.task_state.workspace_version().get(),
        fencing_epoch: approval_snapshot.task_state.fencing_token().get() + 1,
        requested_at: "2026-08-11T08:00:00Z".to_owned(),
        expires_at: "2026-08-11T08:15:00Z".to_owned(),
    };
    let approval_authority = FixedPlanApprovalAuthority {
        binding: PlanApprovalAuthorityBinding::issue(approval_binding.clone())
            .expect("approval authority binding"),
    };
    let canonical_approval =
        canonical_plan_approval_payload(&approval_binding).expect("canonical plan approval");
    let approval_request_artifact = publish_deliberation_artifact(
        &fixture,
        "plan-approval-request-1",
        &canonical_approval.canonical_bytes,
    );
    let approval_close_artifact = publish_deliberation_artifact(
        &fixture,
        "objection-round-close-1",
        br#"{"round":2,"schema":"m4-objection-round-close.v1"}"#,
    );
    DeliberationCommands::with_plan_approval_authority(&database, &approval_authority)
        .close_objection_round(
            command_context(
                &approval_snapshot,
                ActorId::new("core").expect("core actor"),
                approval_close_artifact,
                "event-objection-round-close",
            ),
            PreparePlanApprovalRequestInput {
                approval_id: ApprovalId::new("approval-plan-1").expect("approval id"),
                request_artifact_id: approval_request_artifact.artifact_id().clone(),
            },
        )
        .expect("await exact plan approval");
    let awaiting = database.load(&task_id).expect("awaiting approval");
    assert_eq!(awaiting.task_state.phase(), Phase::AwaitingPlanApproval);
    let approval = awaiting.plan_approval().expect("plan approval").clone();
    let approval_store = SqliteStore::open(&fixture.database_path)
        .expect("approval database")
        .with_artifact_reader(std::sync::Arc::new(ContentAddressedArtifactReader))
        .with_plan_approval_authority_source(std::sync::Arc::new(
            FixedPlanApprovalCurrentAuthority {
                repository_fingerprint: approval_repository_digest,
                policy_snapshot_digest: approval_policy_digest,
            },
        ));
    let stale_resolution = ResolvePlanApprovalInput {
        approval_id: approval.approval_id().clone(),
        displayed_digest: digest_bytes(b"stale displayed digest"),
        expected_task_version: awaiting.task_version,
        actor_id: ActorId::new("approver-1").expect("approver actor"),
        action: PlanApprovalAction::Approve,
    };
    assert!(ResolvePlanApproval::new(&approval_store, &ApprovalClock)
        .execute(stale_resolution)
        .is_err());
    assert_eq!(
        database
            .load(&task_id)
            .expect("still awaiting exact approval")
            .task_state
            .phase(),
        Phase::AwaitingPlanApproval
    );
    let exact_resolution = ResolvePlanApprovalInput {
        approval_id: approval.approval_id().clone(),
        displayed_digest: approval.operation_digest().clone(),
        expected_task_version: awaiting.task_version,
        actor_id: ActorId::new("approver-1").expect("approver actor"),
        action: PlanApprovalAction::Approve,
    };
    ResolvePlanApproval::new(&approval_store, &ApprovalClock)
        .execute(exact_resolution.clone())
        .expect("exact plan approval");
    assert!(ResolvePlanApproval::new(&approval_store, &ApprovalClock)
        .execute(exact_resolution)
        .is_err());
    assert_eq!(
        fixture
            .database()
            .query_row("SELECT phase FROM tasks WHERE id = ?1", [TASK_ID], |row| {
                row.get::<_, String>(0)
            })
            .expect("implementation phase"),
        "Implementation"
    );
    assert_eq!(repository_state(&fixture.source), repository_before);
    assert_eq!(boundaries.check_count(), 2);
    assert_eq!(dispatches.proposal_count(), 2);
}

struct FixedPlanApprovalAuthority {
    binding: PlanApprovalAuthorityBinding,
}

impl PlanApprovalAuthorityProvider for FixedPlanApprovalAuthority {
    fn current(
        &self,
        _task_id: &TaskId,
    ) -> Result<PlanApprovalAuthorityBinding, local_agent_terminal_application::PortError> {
        Ok(self.binding.clone())
    }
}

struct FixedPlanApprovalCurrentAuthority {
    repository_fingerprint: Sha256Digest,
    policy_snapshot_digest: Sha256Digest,
}

impl PlanApprovalCurrentAuthoritySource for FixedPlanApprovalCurrentAuthority {
    fn current_authority(
        &self,
        _task_id: &TaskId,
    ) -> Result<PlanApprovalCurrentAuthority, local_agent_terminal_application::PortError> {
        Ok(PlanApprovalCurrentAuthority {
            repository_fingerprint: self.repository_fingerprint.clone(),
            policy_snapshot_digest: self.policy_snapshot_digest.clone(),
        })
    }
}

struct ApprovalClock;

impl Clock for ApprovalClock {
    fn now_utc(&self) -> Result<String, local_agent_terminal_application::PortError> {
        Ok("2026-08-11T08:05:00Z".to_owned())
    }
}

#[derive(Debug, PartialEq, Eq)]
struct RepositoryState {
    head: (Option<String>, Option<String>, Option<String>),
    refs: Vec<(String, Option<String>, Option<String>)>,
    index_bytes: Vec<u8>,
    index_modes: Vec<(String, u32)>,
    files: Vec<(String, Vec<u8>, bool)>,
    worktrees: Vec<String>,
}

fn repository_state(path: &std::path::Path) -> RepositoryState {
    let repository = Repository::open(path).expect("repository state");
    let head = repository.head().expect("repository head");
    let mut refs = repository
        .references()
        .expect("repository refs")
        .map(|reference| {
            let reference = reference.expect("reference");
            (
                reference.name().expect("valid reference name").to_owned(),
                reference.target().map(|target| target.to_string()),
                reference
                    .symbolic_target()
                    .expect("valid symbolic target")
                    .map(str::to_owned),
            )
        })
        .collect::<Vec<_>>();
    refs.sort();
    let index = repository.index().expect("repository index");
    let mut index_modes = index
        .iter()
        .map(|entry| {
            (
                String::from_utf8(entry.path.clone()).expect("UTF-8 index path"),
                entry.mode,
            )
        })
        .collect::<Vec<_>>();
    index_modes.sort();
    let mut files = Vec::new();
    collect_repository_files(path, path, &mut files);
    files.sort_by(|left, right| left.0.cmp(&right.0));
    let mut worktrees = repository
        .worktrees()
        .expect("worktree list")
        .iter()
        .map(|name| {
            name.expect("valid worktree name")
                .expect("worktree name")
                .to_owned()
        })
        .collect::<Vec<_>>();
    worktrees.sort();
    RepositoryState {
        head: (
            Some(head.name().expect("valid head name").to_owned()),
            head.target().map(|target| target.to_string()),
            head.symbolic_target()
                .expect("valid head symbolic target")
                .map(str::to_owned),
        ),
        refs,
        index_bytes: fs::read(repository.path().join("index")).expect("index bytes"),
        index_modes,
        files,
        worktrees,
    }
}

fn collect_repository_files(
    root: &std::path::Path,
    directory: &std::path::Path,
    files: &mut Vec<(String, Vec<u8>, bool)>,
) {
    for entry in fs::read_dir(directory).expect("repository directory") {
        let entry = entry.expect("repository entry");
        let path = entry.path();
        if path == root.join(".git") {
            continue;
        }
        let metadata = entry.metadata().expect("repository metadata");
        if metadata.is_dir() {
            collect_repository_files(root, &path, files);
        } else if metadata.is_file() {
            files.push((
                path.strip_prefix(root)
                    .expect("repository relative path")
                    .to_string_lossy()
                    .replace('\\', "/"),
                fs::read(&path).expect("repository file bytes"),
                metadata.permissions().readonly(),
            ));
        }
    }
}

fn workspace_fingerprint_digest(fingerprint: &WorkspaceFingerprint) -> Sha256Digest {
    digest_bytes(&canonical_json(&json!({
        "head": fingerprint.head().as_str(),
        "indexDigest": fingerprint.index_digest(),
        "statusDigest": fingerprint.status_digest(),
    })))
}

struct FixedRepositoryAuthority {
    fingerprint: WorkspaceFingerprint,
}

impl DeliberationRepositoryAuthority for FixedRepositoryAuthority {
    fn current_fingerprint(
        &self,
        _task_id: &TaskId,
    ) -> Result<WorkspaceFingerprint, local_agent_terminal_application::PortError> {
        Ok(self.fingerprint.clone())
    }
}

struct ExactBoundaryStore {
    expected: WorkspaceFingerprint,
    records: Mutex<Vec<DeliberationBoundaryRecord>>,
}

impl ExactBoundaryStore {
    fn new(expected: WorkspaceFingerprint) -> Self {
        Self {
            expected,
            records: Mutex::new(Vec::new()),
        }
    }

    fn check_count(&self) -> usize {
        self.records.lock().expect("boundary records").len()
    }
}

impl DeliberationBoundaryStore for ExactBoundaryStore {
    fn compare_and_persist_boundary(
        &self,
        check: DeliberationBoundaryCheck,
    ) -> Result<DeliberationBoundaryRecord, local_agent_terminal_application::PortError> {
        let record = check.compare_with(self.expected.clone())?;
        self.records
            .lock()
            .map_err(|_| unavailable())?
            .push(record.clone());
        Ok(record)
    }
}

#[derive(Default)]
struct RecordingDispatchStore {
    proposal_runs: Mutex<Vec<RunId>>,
}

impl RecordingDispatchStore {
    fn proposal_count(&self) -> usize {
        self.proposal_runs
            .lock()
            .expect("proposal dispatches")
            .len()
    }
}

impl DeliberationDispatchStore for RecordingDispatchStore {
    fn compare_and_persist_proposal_binding_set(
        &self,
        plan: &DeliberationProposalDispatchPlan,
    ) -> Result<(), local_agent_terminal_application::PortError> {
        plan.validate()?;
        let mut runs = self.proposal_runs.lock().map_err(|_| unavailable())?;
        runs.extend(
            plan.bindings()
                .iter()
                .map(|binding| binding.request().run_id.clone()),
        );
        Ok(())
    }

    fn compare_and_persist_phase_binding_set(
        &self,
        dispatch_set: &DeliberationPhaseDispatchSet,
    ) -> Result<(), local_agent_terminal_application::PortError> {
        if dispatch_set.bindings().is_empty() {
            Err(unavailable())
        } else {
            Ok(())
        }
    }
}

struct EmptyToolCatalog;

impl DeliberationToolCatalog for EmptyToolCatalog {
    fn dispatch_schemas(
        &self,
        _task_id: &TaskId,
    ) -> Result<Vec<DeliberationToolSchema>, local_agent_terminal_application::PortError> {
        Ok(Vec::new())
    }
}

fn unavailable() -> local_agent_terminal_application::PortError {
    local_agent_terminal_application::PortError::failure(
        local_agent_terminal_application::SafeErrorClassification::Unavailable,
        local_agent_terminal_application::Retryability::Retryable,
    )
}

fn current_fingerprint(fixture: &WorkspaceFixture) -> WorkspaceFingerprint {
    let gateway = GitRepositoryGateway::open(
        &fixture.workspace_root,
        &[fixture.app_data.join("artifacts")],
    )
    .expect("repository gateway");
    gateway
        .inspect(InspectRepository {
            locator: fixture.locator.clone(),
        })
        .expect("repository inspection")
        .fingerprint
}

fn phase_request(
    state: WorkflowState,
    effect: DeliberationArtifactRef,
    event_id: &str,
) -> InitialDeliberationPhaseRequest {
    InitialDeliberationPhaseRequest {
        task_id: TaskId::new(TASK_ID).expect("task id"),
        expected_state: state,
        event_id: EventId::new(event_id).expect("event id"),
        occurred_at: "2026-08-11T08:01:00Z".to_owned(),
        correlation_id: "task-1:m4-e2e".to_owned(),
        effect_artifacts: vec![effect],
    }
}

fn package_artifact_ref(
    fixture: &WorkspaceFixture,
    package: &ContextPackageBinding,
) -> DeliberationArtifactRef {
    artifact_ref(&fixture.database(), package.artifact().artifact_id())
}

fn artifact_ref(connection: &Connection, artifact_id: &ArtifactId) -> DeliberationArtifactRef {
    let (digest, size): (String, i64) = connection
        .query_row(
            "SELECT content_hash, size_bytes FROM artifacts
             WHERE id = ?1 AND availability = 'available'",
            [artifact_id.as_str()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .expect("available artifact");
    DeliberationArtifactRef::new(
        artifact_id.clone(),
        Sha256Digest::new(digest).expect("artifact digest"),
        u64::try_from(size).expect("artifact size"),
    )
    .expect("deliberation artifact")
}

struct ProviderRunBinding {
    agent_id: &'static str,
    connection_id: &'static str,
    manifest_digest: &'static str,
    adapter_version: &'static str,
    provider_id: &'static str,
    model_id: &'static str,
}

impl ProviderRunBinding {
    const fn openai() -> Self {
        Self {
            agent_id: "core_adapter",
            connection_id: "openai_core_adapter",
            manifest_digest: OPENAI_MANIFEST_DIGEST,
            adapter_version: "openai-responses-v1",
            provider_id: "openai",
            model_id: "gpt-m4",
        }
    }

    const fn anthropic() -> Self {
        Self {
            agent_id: "anthropic_core_adapter",
            connection_id: "anthropic_core_adapter",
            manifest_digest: ANTHROPIC_MANIFEST_DIGEST,
            adapter_version: "anthropic-messages-v1",
            provider_id: "anthropic",
            model_id: "claude-m4",
        }
    }
}

fn proposal_run_request(
    run_id: &str,
    package: &ContextPackageBinding,
    role: &RolePackageSpec,
    provider: ProviderRunBinding,
) -> BoundAgentRunRequest {
    assert_eq!(role.agent_id, provider.agent_id);
    let task_id = TaskId::new(TASK_ID).expect("task id");
    let generation_json = canonical_json(&json!({"temperature": 0}));
    let connection = bound_connection(&provider);
    let request = BoundAgentRunRequest {
        run_id: RunId::new(run_id).expect("run id"),
        task_id: task_id.clone(),
        agent_id: role.agent_id.to_owned(),
        role: role.role.to_owned(),
        phase: Phase::ParallelAnalysis.as_str().to_owned(),
        idempotency_key: format!("{TASK_ID}:ParallelAnalysis:{run_id}"),
        context: BoundEffectiveContext {
            context_package_id: role.package_id.to_owned(),
            task_id: task_id.clone(),
            agent_id: role.agent_id.to_owned(),
            role: role.role.to_owned(),
            objective: role.objective.to_owned(),
            manifest_artifact_id: ArtifactId::new(role.manifest_artifact_id)
                .expect("manifest artifact"),
            effective_context_artifact_id: ArtifactId::new(role.context_artifact_id)
                .expect("context artifact"),
            content_digest: package.artifact().content_digest().clone(),
            policy_snapshot_digest: package.policy().policy_snapshot_digest().clone(),
            prompt_template_version: package.descriptor().versions().prompt_template().to_owned(),
            retrieval_pipeline_version: package
                .descriptor()
                .versions()
                .retrieval_pipeline()
                .to_owned(),
            created_at: package.descriptor().created_at(),
        },
        run_config: BoundRunConfig {
            run_config_artifact_id: ArtifactId::new(format!("run-config-{run_id}"))
                .expect("run config artifact"),
            task_id,
            agent_id: role.agent_id.to_owned(),
            role: role.role.to_owned(),
            context_package_id: role.package_id.to_owned(),
            effective_context_artifact_id: ArtifactId::new(role.context_artifact_id)
                .expect("context artifact"),
            effective_context_digest: package.artifact().content_digest().clone(),
            trust_tier: TrustTier::CoreAdapter,
            manifest_digest: Sha256Digest::new(provider.manifest_digest).expect("manifest digest"),
            executable_digest: Some(
                Sha256Digest::new(CORE_RELEASE_DIGEST).expect("release digest"),
            ),
            contract_version: "1.0".to_owned(),
            adapter_version: provider.adapter_version.to_owned(),
            provider_id: provider.provider_id.to_owned(),
            model_id: provider.model_id.to_owned(),
            generation_parameters: BoundGenerationParameters {
                digest: digest_bytes(&generation_json),
                canonical_json: generation_json,
            },
            prompt_template_version: package.descriptor().versions().prompt_template().to_owned(),
            response_schema_version: "agent-message.v1".to_owned(),
            policy_snapshot_digest: package.policy().policy_snapshot_digest().clone(),
            limits: AgentRunLimits {
                deadline: Timestamp::from_unix_seconds(2_000_000_000),
                max_output_tokens: 256,
                max_tool_requests: 0,
                max_context_queries: 0,
                max_specialist_requests: 0,
            },
        },
        connection,
        supersedes_run_id: None,
    };
    request.validate().expect("proposal run request");
    request
}

fn bound_connection(provider: &ProviderRunBinding) -> BoundAgentConnection {
    let mut connection = BoundAgentConnection {
        connection_id: provider.connection_id.to_owned(),
        agent_id: provider.agent_id.to_owned(),
        trust_tier: TrustTier::CoreAdapter,
        manifest_digest: Sha256Digest::new(provider.manifest_digest).expect("manifest digest"),
        executable_digest: Some(Sha256Digest::new(CORE_RELEASE_DIGEST).expect("release digest")),
        contract_version: "1.0".to_owned(),
        adapter_version: provider.adapter_version.to_owned(),
        binding_digest: Sha256Digest::new(
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        )
        .expect("placeholder digest"),
    };
    connection.binding_digest = digest_bytes(&canonical_json(&json!({
        "schema": "agent-connection-binding.v1",
        "identity": {
            "connectionId": connection.connection_id,
            "agentId": connection.agent_id,
        },
        "manifestDigest": connection.manifest_digest.as_str(),
        "executableDigest": connection.executable_digest.as_ref().map(Sha256Digest::as_str),
        "trustTier": connection.trust_tier.as_str(),
        "contractVersion": connection.contract_version,
        "adapterVersion": connection.adapter_version,
    })));
    connection.validate().expect("connection binding");
    connection
}

fn proposal_assignment(request: &BoundAgentRunRequest) -> DeliberationRunAssignment {
    DeliberationRunAssignment::new(
        request.run_id.clone(),
        request.agent_id.clone(),
        AgentFamilyKey::from_provider_model(
            &request.run_config.provider_id,
            &request.run_config.model_id,
        )
        .expect("family key"),
        ActorId::new(&request.agent_id).expect("actor id"),
    )
    .expect("run assignment")
}

fn wait_for_terminal(database: &SqliteStore, run_id: &RunId) {
    for _ in 0..200 {
        let run = database
            .load_run(run_id)
            .expect("run query")
            .expect("persisted run");
        if run.status.is_terminal() {
            assert_eq!(run.status, AgentRunStatus::Succeeded);
            return;
        }
        thread::sleep(Duration::from_millis(5));
    }
    panic!("agent run did not terminalize");
}

fn private_run_output(connection: &Connection, run_id: &RunId) -> DeliberationArtifactRef {
    let artifact_id: String = connection
        .query_row(
            "SELECT content_artifact_id FROM agent_run_outputs WHERE run_id = ?1",
            [run_id.as_str()],
            |row| row.get(0),
        )
        .expect("private run output");
    artifact_ref(
        connection,
        &ArtifactId::new(artifact_id).expect("output artifact"),
    )
}

fn message_count(connection: &Connection, message_type: Option<&str>) -> i64 {
    match message_type {
        Some(message_type) => connection
            .query_row(
                "SELECT COUNT(*) FROM messages WHERE message_type = ?1",
                [message_type],
                |row| row.get(0),
            )
            .expect("message count"),
        None => connection
            .query_row("SELECT COUNT(*) FROM messages", [], |row| row.get(0))
            .expect("message count"),
    }
}

fn command_context(
    snapshot: &local_agent_terminal_application::DeliberationSnapshot,
    actor: ActorId,
    artifact: DeliberationArtifactRef,
    event_id: &str,
) -> DeliberationCommandContext {
    DeliberationCommandContext::new(
        snapshot.task_id.clone(),
        snapshot.task_version,
        snapshot.task_state,
        actor,
        artifact,
        EventId::new(event_id).expect("event id"),
        "task-1:m4-e2e",
        "2026-08-11T08:02:00Z",
    )
    .expect("command context")
}

fn independent_proposal(
    request: &BoundAgentRunRequest,
    artifact: &DeliberationArtifactRef,
    package: &ContextPackageBinding,
) -> IndependentProposal {
    IndependentProposal::new(
        request.task_id.clone(),
        request.run_id.clone(),
        &request.agent_id,
        AgentFamilyKey::from_provider_model(
            &request.run_config.provider_id,
            &request.run_config.model_id,
        )
        .expect("family key"),
        artifact.artifact_id().clone(),
        vec![package.members()[0].citation().clone()],
    )
    .expect("independent proposal")
}

fn citation_with_freshness(
    citation: &EvidenceCitation,
    freshness: EvidenceFreshness,
) -> EvidenceCitation {
    EvidenceCitation::new(
        citation.source().clone(),
        citation.range(),
        citation.symbol(),
        freshness,
    )
    .expect("citation freshness")
}

fn review_plan_for_round(
    round: u32,
    openai: &DeliberationArtifactRef,
    anthropic: &DeliberationArtifactRef,
) -> ReviewPlan {
    ReviewPlan::new(
        DeliberationLimits::new(2, 2, 2, 1).expect("deliberation limits"),
        vec![
            ReviewEdge::new(
                VERIFIER_CONTEXT.agent_id,
                openai.artifact_id().clone(),
                round,
            )
            .expect("OpenAI review edge"),
            ReviewEdge::new(
                LEAD_CONTEXT.agent_id,
                anthropic.artifact_id().clone(),
                round,
            )
            .expect("Anthropic review edge"),
        ],
    )
    .expect("review plan")
}

fn evidence_linked_decision(
    openai: &DeliberationArtifactRef,
    anthropic: &DeliberationArtifactRef,
    evidence: Vec<MaterialClaim>,
    plan: ArtifactId,
) -> DecisionPackage {
    DecisionPackage::new(
        DecisionApproach::new(
            "openai-approach",
            openai.artifact_id().clone(),
            vec!["claim-current-source".to_owned()],
        )
        .expect("selected approach"),
        vec![RejectedApproach::new(
            DecisionApproach::new(
                "anthropic-alternative",
                anthropic.artifact_id().clone(),
                vec!["claim-stale-source".to_owned()],
            )
            .expect("rejected approach"),
            "citation is stale and remains inconclusive",
        )
        .expect("rejected alternative")],
        evidence,
        vec![Dissent::new(
            "dissent-anthropic",
            VERIFIER_CONTEXT.agent_id,
            anthropic.artifact_id().clone(),
            "retain the stale-evidence concern until refreshed",
        )
        .expect("preserved dissent")],
        &["dissent-anthropic"],
        plan,
    )
    .expect("evidence-linked decision")
}

fn publish_deliberation_artifact(
    fixture: &WorkspaceFixture,
    artifact_id: &str,
    bytes: &[u8],
) -> DeliberationArtifactRef {
    let database = SqliteStore::open(&fixture.database_path).expect("database");
    let artifacts = ContentAddressedArtifactStore::open(fixture.app_data.join("artifacts"))
        .expect("artifact store");
    let digest = digest_bytes(bytes);
    let created_at = database.now_utc().expect("clock");
    JournaledArtifactWriter::new(&artifacts, &database, &database)
        .write(
            ArtifactWriteReservation {
                operation_id: format!("m4-e2e:{artifact_id}"),
                artifact: ReservedArtifact {
                    artifact_id: artifact_id.to_owned(),
                    task_id: Some(TaskId::new(TASK_ID).expect("task id")),
                    project_id: PROJECT_ID.to_owned(),
                    artifact_type: "deliberation-record".to_owned(),
                    logical_path: format!("deliberation/{artifact_id}.json"),
                    content_hash: digest.as_str().to_owned(),
                    storage_key: ContentAddressedArtifactStore::storage_key(digest.as_str())
                        .expect("storage key"),
                    size_bytes: bytes.len() as u64,
                    mime_type: Some("application/json".to_owned()),
                    created_by_type: "core".to_owned(),
                    created_by_id: "m4-e2e".to_owned(),
                    created_at: created_at.clone(),
                    supersedes: None,
                },
                temp_name: format!("{artifact_id}.tmp"),
                created_at,
            },
            bytes,
        )
        .expect("publish deliberation artifact");
    artifact_ref(
        &fixture.database(),
        &ArtifactId::new(artifact_id).expect("artifact id"),
    )
}

fn canonical_json(value: &Value) -> Vec<u8> {
    serde_json_canonicalizer::to_vec(value).expect("canonical JSON")
}

fn digest_bytes(bytes: &[u8]) -> Sha256Digest {
    Sha256Digest::new(format!("sha256:{:x}", Sha256::digest(bytes))).expect("SHA-256 digest")
}

struct GatedProvider {
    endpoint: String,
    captured: mpsc::Receiver<Vec<u8>>,
    release: Option<mpsc::Sender<()>>,
    worker: Option<thread::JoinHandle<()>>,
}

impl GatedProvider {
    fn openai(output: &str) -> Self {
        let escaped = serde_json::to_string(output).expect("OpenAI output");
        let body = format!(
            "data: {{\"type\":\"response.created\",\"response\":{{\"id\":\"resp-m4\"}}}}\n\ndata: {{\"type\":\"response.output_text.delta\",\"delta\":{escaped}}}\n\ndata: {{\"type\":\"response.completed\",\"response\":{{\"id\":\"resp-m4\",\"usage\":{{\"input_tokens\":3,\"output_tokens\":2}}}}}}\n\n"
        );
        Self::new("/v1/responses", body.into_bytes())
    }

    fn anthropic(output: &str) -> Self {
        let escaped = serde_json::to_string(output).expect("Anthropic output");
        let body = format!(
            "event: message_start\ndata: {{\"type\":\"message_start\",\"message\":{{\"id\":\"msg-m4\",\"usage\":{{\"input_tokens\":3,\"output_tokens\":0}}}}}}\n\nevent: content_block_start\ndata: {{\"type\":\"content_block_start\",\"index\":0,\"content_block\":{{\"type\":\"text\",\"text\":\"\"}}}}\n\nevent: content_block_delta\ndata: {{\"type\":\"content_block_delta\",\"index\":0,\"delta\":{{\"type\":\"text_delta\",\"text\":{escaped}}}}}\n\nevent: content_block_stop\ndata: {{\"type\":\"content_block_stop\",\"index\":0}}\n\nevent: message_delta\ndata: {{\"type\":\"message_delta\",\"delta\":{{\"stop_reason\":\"end_turn\"}},\"usage\":{{\"output_tokens\":3}}}}\n\nevent: message_stop\ndata: {{\"type\":\"message_stop\"}}\n\n"
        );
        Self::new("/v1/messages", body.into_bytes())
    }

    fn new(path: &str, body: Vec<u8>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("loopback listener");
        let endpoint = format!("http://{}{path}", listener.local_addr().expect("address"));
        let (captured_sender, captured) = mpsc::channel();
        let (release, released) = mpsc::channel();
        let worker = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("provider request");
            captured_sender
                .send(read_http_body(&stream))
                .expect("captured request");
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            )
            .expect("response headers");
            stream.flush().expect("response headers flush");
            released.recv().expect("release provider");
            stream.write_all(&body).expect("SSE body");
            stream.flush().expect("SSE body flush");
        });
        Self {
            endpoint,
            captured,
            release: Some(release),
            worker: Some(worker),
        }
    }

    fn endpoint(&self) -> String {
        self.endpoint.clone()
    }

    fn await_request(&self) -> Vec<u8> {
        self.captured
            .recv_timeout(Duration::from_secs(2))
            .expect("provider request")
    }

    fn release_and_join(&mut self) {
        if let Some(release) = self.release.take() {
            release.send(()).expect("release provider");
        }
        if let Some(worker) = self.worker.take() {
            worker.join().expect("provider worker");
        }
    }
}

impl Drop for GatedProvider {
    fn drop(&mut self) {
        if let Some(release) = self.release.take() {
            let _ = release.send(());
        }
        let _ = self.worker.take();
    }
}

fn read_http_body(stream: &TcpStream) -> Vec<u8> {
    let mut reader = BufReader::new(stream.try_clone().expect("clone stream"));
    let mut request_line = String::new();
    reader.read_line(&mut request_line).expect("request line");
    let mut content_length = 0_usize;
    loop {
        let mut line = String::new();
        reader.read_line(&mut line).expect("request header");
        if line == "\r\n" || line == "\n" {
            break;
        }
        if let Some((name, value)) = line.split_once(':') {
            if name.eq_ignore_ascii_case("content-length") {
                content_length = value.trim().parse().expect("content length");
            }
        }
    }
    let mut body = vec![0; content_length];
    reader.read_exact(&mut body).expect("request body");
    body
}

fn context_startup_config(fixture: &WorkspaceFixture) -> StartupConfig {
    startup_config_with_endpoints(
        fixture,
        "https://api.openai.test/v1/responses".to_owned(),
        "https://api.anthropic.test/v1/messages".to_owned(),
    )
}

fn startup_config_with_endpoints(
    fixture: &WorkspaceFixture,
    openai_endpoint: String,
    anthropic_endpoint: String,
) -> StartupConfig {
    StartupConfig {
        app_data_dir: fixture.app_data.clone(),
        trusted_workspace_root: fixture.workspace_root.clone(),
        secret_values: Vec::new(),
        openai: Some(OpenAiBootstrapConfig {
            endpoint: openai_endpoint,
            api_key: OpenAiApiKey::new("sk-context-runtime-test").expect("API key"),
            manifest_digest: local_agent_terminal_domain::Sha256Digest::new(OPENAI_MANIFEST_DIGEST)
                .expect("manifest digest"),
            core_release_digest: local_agent_terminal_domain::Sha256Digest::new(
                CORE_RELEASE_DIGEST,
            )
            .expect("release digest"),
            adapter_version: "openai-responses-v1".to_owned(),
        }),
        anthropic: Some(AnthropicBootstrapConfig {
            endpoint: anthropic_endpoint,
            api_key: AnthropicApiKey::new("sk-ant-context-runtime-test").expect("API key"),
            manifest_digest: local_agent_terminal_domain::Sha256Digest::new(
                ANTHROPIC_MANIFEST_DIGEST,
            )
            .expect("manifest digest"),
            core_release_digest: local_agent_terminal_domain::Sha256Digest::new(
                CORE_RELEASE_DIGEST,
            )
            .expect("release digest"),
            adapter_version: "anthropic-messages-v1".to_owned(),
        }),
    }
}

fn context_request(
    revision: String,
    repository_fingerprint: local_agent_terminal_domain::Sha256Digest,
    role: &RolePackageSpec,
) -> BuildInitialContextRequest {
    let task_id = TaskId::new(TASK_ID).expect("task id");
    BuildInitialContextRequest {
        snapshot: SourceSnapshotRequest {
            project_id: local_agent_terminal_domain::ProjectId::new(PROJECT_ID)
                .expect("project id"),
            task_id: task_id.clone(),
            revision,
            repository_fingerprint,
        },
        policy: context_policy(task_id.clone(), role),
        package: context_package(task_id, role),
    }
}

fn query_request(role: &RolePackageSpec) -> QueryContextRequest {
    let task_id = TaskId::new(TASK_ID).expect("task id");
    QueryContextRequest {
        query: ContextQuery {
            task_id: task_id.clone(),
            query_id: format!("query-{}", role.role),
            terms: Vec::new(),
            max_items: 8,
            max_tokens: 16_384,
        },
        policy: context_policy(task_id.clone(), role),
        package: context_package(task_id, role),
    }
}

fn context_policy(task_id: TaskId, role: &RolePackageSpec) -> ContextBuildPolicy {
    ContextBuildPolicy {
        task_id,
        actor: PolicyActor {
            connection_id: role.connection_id.to_owned(),
            agent_id: role.agent_id.to_owned(),
            trust_tier: TrustTier::CoreAdapter,
            locality: ActorLocality::Local,
        },
        resource_class: local_agent_terminal_domain::ResourceClass::InternalCode,
        task_risk: TaskRisk::High,
        workflow_phase: "ContextBuild".to_owned(),
        purpose: format!("build {} M4 context", role.role),
        policy_snapshot_digest: local_agent_terminal_domain::Sha256Digest::new(
            "sha256:307c8dbce9694982020fffc33c685d6f62bb4554f73794f3fd67b812d0ba6ed6",
        )
        .expect("policy digest"),
        evaluated_at: Timestamp::from_unix_seconds(1_786_435_200),
    }
}

fn context_package(task_id: TaskId, role: &RolePackageSpec) -> ContextPackageDraft {
    ContextPackageDraft {
        descriptor: ContextPackageDescriptor::new(
            ContextPackageIdentity::new(
                role.package_id,
                task_id,
                role.agent_id,
                role.role,
                ArtifactId::new(role.manifest_artifact_id).expect("manifest"),
                ArtifactId::new(role.context_artifact_id).expect("package artifact"),
                Timestamp::from_unix_seconds(1_786_435_200),
            )
            .expect("package identity"),
            role.objective,
            ContextVersionSet::new("prompt.v1", "keyword.v1", "byte-token-v1").expect("versions"),
            ContextBudget::new(16_384, 4_096).expect("budget"),
        )
        .expect("descriptor"),
    }
}

fn assert_role_package(
    package: &local_agent_terminal_domain::ContextPackageBinding,
    role: &RolePackageSpec,
    revision: &str,
) {
    assert_eq!(package.descriptor().package_id(), role.package_id);
    assert_eq!(package.descriptor().agent_id(), role.agent_id);
    assert_eq!(package.descriptor().role(), role.role);
    assert_eq!(package.descriptor().objective(), role.objective);
    assert_eq!(
        package.descriptor().agent_manifest_artifact_id().as_str(),
        role.manifest_artifact_id
    );
    assert_eq!(
        package
            .descriptor()
            .effective_content_artifact_id()
            .as_str(),
        role.context_artifact_id
    );
    assert_eq!(
        package.policy().policy_snapshot_digest().as_str(),
        POLICY_DIGEST
    );
    assert_eq!(package.members().len(), 2);
    assert!(package.members().iter().all(|member| {
        member.citation().source().revision() == revision
            && member.citation().freshness() == EvidenceFreshness::Current
            && member.disclosure().kind() == DisclosureKind::Allowed
            && member.citation().source().path_identity() != ".env"
    }));
    assert!(package
        .policy()
        .decision_ids()
        .windows(2)
        .all(|pair| pair[0] < pair[1]));
}

fn assert_linked_policy(
    connection: &Connection,
    role: &RolePackageSpec,
    expected_actions: [i64; 4],
    expected_redacted_rules: i64,
    expected_denials: i64,
) {
    let actions = [
        "context.index_metadata",
        "context.index_content",
        "context.retrieve_item",
        "context.final_package",
    ];
    for (action, expected) in actions.into_iter().zip(expected_actions) {
        let count: i64 = connection
            .query_row(
                "SELECT COUNT(*)
                 FROM context_package_policy_decisions links
                 JOIN policy_decisions decisions ON decisions.id = links.policy_decision_id
                 WHERE links.package_id = ?1 AND decisions.action = ?2",
                params![role.package_id, action],
                |row| row.get(0),
            )
            .expect("linked action count");
        assert_eq!(count, expected, "{} action {action}", role.role);
    }
    let redacted_rules: i64 = connection
        .query_row(
            "SELECT COUNT(*)
             FROM context_package_policy_decisions links
             JOIN policy_decisions decisions ON decisions.id = links.policy_decision_id
             WHERE links.package_id = ?1
               AND json_extract(decisions.matched_rules_json, '$.redactions[0]') = 'secret_scanner'",
            [role.package_id],
            |row| row.get(0),
        )
        .expect("linked redaction count");
    let denials: i64 = connection
        .query_row(
            "SELECT COUNT(*)
             FROM context_package_policy_decisions links
             JOIN policy_decisions decisions ON decisions.id = links.policy_decision_id
             WHERE links.package_id = ?1 AND decisions.effect = 'deny'",
            [role.package_id],
            |row| row.get(0),
        )
        .expect("linked denial count");
    let manifest_is_exact: bool = connection
        .query_row(
            "SELECT EXISTS(
                SELECT 1 FROM artifacts
                WHERE id = ?1 AND task_id = ?2 AND artifact_type = 'manifest'
                  AND content_hash = ?3 AND availability = 'available'
             )",
            params![role.manifest_artifact_id, TASK_ID, role.manifest_digest],
            |row| row.get(0),
        )
        .expect("manifest binding");
    let package_is_exact: bool = connection
        .query_row(
            "SELECT EXISTS(
                SELECT 1 FROM context_packages
                WHERE id = ?1 AND task_id = ?2 AND agent_id = ?3 AND role = ?4
                  AND objective = ?5 AND manifest_artifact_id = ?6
                  AND effective_content_artifact_id = ?7 AND policy_snapshot_digest = ?8
             )",
            params![
                role.package_id,
                TASK_ID,
                role.agent_id,
                role.role,
                role.objective,
                role.manifest_artifact_id,
                role.context_artifact_id,
                POLICY_DIGEST,
            ],
            |row| row.get(0),
        )
        .expect("package binding");
    assert_eq!(
        redacted_rules, expected_redacted_rules,
        "{} redactions",
        role.role
    );
    assert_eq!(denials, expected_denials, "{} denials", role.role);
    assert!(manifest_is_exact, "{} manifest", role.role);
    assert!(package_is_exact, "{} package", role.role);
}
