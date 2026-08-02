use std::path::PathBuf;

use local_agent_terminal_application::{
    validate_authoritative_tool_request, ApprovedExecutableIdentity, ApprovedProcessRequest,
    LeaseSnapshot, LeaseState, PortError, ResolvedExecutable, ToolAuthorityResolver,
    ToolAuthoritySnapshot, ToolExecutionId, ToolPolicyContext, ToolRequest,
};
use local_agent_terminal_domain::{
    ActorLocality, CapabilityRef, EnvironmentProfile, ExpectedWrite, FencingToken, NetworkProfile,
    Phase, PlanStepId, PolicyAction, PolicyActor, PolicyResource, ProcessBinding,
    ProcessInvocation, ProcessToolRequest, ProcessTrustTier, ResourceClass, RunId, Sha256Digest,
    TaskId, TaskRisk, TrustTier, WorkspaceVersion,
};
use sha2::{Digest, Sha256};

const MAX_RESOURCE_BYTES: usize = 8 * 1024 * 1024;

#[test]
fn authority_resolver_is_object_safe() {
    struct Resolver;

    impl ToolAuthorityResolver for Resolver {
        fn resolve(&self, request: &ToolRequest) -> Result<ToolAuthoritySnapshot, PortError> {
            let bytes = Fixture::default().resource_bytes;
            ToolAuthoritySnapshot::new(request.clone(), &bytes, coherent_lease(request))
        }
    }

    fn accepts_object_safe_port(_: &dyn ToolAuthorityResolver) {}

    let resolver = Resolver;
    accepts_object_safe_port(&resolver);
    let snapshot = resolver
        .resolve(&tool_request(&Fixture::default()))
        .unwrap();
    assert_eq!(snapshot.effective_role(), TrustTier::IsolatedWorker);
}

#[test]
fn read_only_snapshot_succeeds_without_a_lease() {
    let fixture = Fixture::read_only();
    let request = tool_request(&fixture);

    let snapshot = ToolAuthoritySnapshot::new(request, &fixture.resource_bytes, None).unwrap();

    assert!(snapshot
        .request()
        .process()
        .process()
        .executor_fencing_token()
        .is_none());
}

#[test]
fn write_snapshot_succeeds_with_a_coherent_active_lease() {
    let fixture = Fixture::default();
    let request = tool_request(&fixture);
    let lease = coherent_lease(&request);

    ToolAuthoritySnapshot::new(request, &fixture.resource_bytes, lease).unwrap();
}

#[test]
fn snapshot_rejects_resource_digest_mismatch() {
    let fixture = Fixture::default();
    let request = tool_request(&fixture);
    let lease = coherent_lease(&request);

    assert_integrity_failure(ToolAuthoritySnapshot::new(
        request,
        b"different bytes",
        lease,
    ));
}

#[test]
fn snapshot_rejects_resource_larger_than_platform_read_ceiling() {
    let fixture = Fixture {
        resource_bytes: vec![b'x'; MAX_RESOURCE_BYTES + 1],
        ..Default::default()
    };
    let request = tool_request(&fixture);
    let lease = coherent_lease(&request);

    assert_integrity_failure(ToolAuthoritySnapshot::new(
        request,
        &fixture.resource_bytes,
        lease,
    ));
}

#[test]
fn read_only_snapshot_rejects_an_extra_lease() {
    let fixture = Fixture::read_only();
    let request = tool_request(&fixture);
    let lease = Some(active_lease(&request, FencingToken::new(19).unwrap()));

    assert_integrity_failure(ToolAuthoritySnapshot::new(
        request,
        &fixture.resource_bytes,
        lease,
    ));
}

#[test]
fn write_snapshot_rejects_invalid_lease_bindings() {
    type Mutation = fn(&mut LeaseSnapshot);
    let fixture = Fixture::default();
    let request = tool_request(&fixture);
    let active = coherent_lease(&request).unwrap();
    let invalid: [Option<Mutation>; 6] = [
        None,
        Some(|lease| lease.task_id = TaskId::new("task-2").unwrap()),
        Some(|lease| lease.holder_run_id = RunId::new("run-2").unwrap()),
        Some(|lease| lease.token = FencingToken::new(20).unwrap()),
        Some(|lease| lease.state = LeaseState::Revoked),
        Some(|lease| lease.released_at = Some("2025-07-23T12:30:00Z".to_owned())),
    ];

    for mutation in invalid {
        let lease = mutation.map(|mutate| {
            let mut lease = active.clone();
            mutate(&mut lease);
            lease
        });
        assert_integrity_failure(ToolAuthoritySnapshot::new(
            request.clone(),
            &fixture.resource_bytes,
            lease,
        ));
    }
}

#[test]
fn unchanged_authoritative_request_is_valid() {
    let fixture = Fixture::default();
    let expected = tool_request(&fixture);
    let current = authority_snapshot(&fixture);

    validate_authoritative_tool_request(&expected, &current).unwrap();
}

#[test]
fn policy_resource_class_may_upgrade_but_not_downgrade() {
    let expected = tool_request(&Fixture::default());
    let upgraded = authority_snapshot(&Fixture {
        resource_class: ResourceClass::Secret,
        ..Default::default()
    });
    validate_authoritative_tool_request(&expected, &upgraded).unwrap();

    let downgraded = authority_snapshot(&Fixture {
        resource_class: ResourceClass::Public,
        ..Default::default()
    });
    assert_integrity_failure(validate_authoritative_tool_request(&expected, &downgraded));
}

#[test]
fn representative_request_mutations_fail_closed() {
    type Mutation = fn(&mut Fixture);
    let mutations: [Mutation; 31] = [
        |fixture| fixture.execution_id = "execution-2",
        |fixture| fixture.actor_connection = "connection-2",
        |fixture| fixture.actor_agent = "agent-2",
        |fixture| fixture.actor_trust = TrustTier::CoreAdapter,
        |fixture| fixture.actor_locality = ActorLocality::Cloud,
        |fixture| fixture.task_id = "task-2",
        |fixture| fixture.run_id = "run-2",
        |fixture| fixture.step_id = "step-2",
        |fixture| fixture.phase = Phase::Verification,
        |fixture| fixture.workspace_version = 5,
        |fixture| fixture.timeout_ms = 2,
        |fixture| fixture.task_risk = TaskRisk::Critical,
        |fixture| fixture.purpose = "mutated purpose",
        |fixture| fixture.policy_digest = 'c',
        |fixture| fixture.resource_path = "src",
        |fixture| fixture.resource_bytes = b"changed resource".to_vec(),
        |fixture| fixture.toolchain_id = "rustc",
        |fixture| fixture.executable_version = "2.0",
        |fixture| fixture.executable_path = alternate_executable_path(),
        |fixture| fixture.file_identity = "file-2",
        |fixture| fixture.executable_digest = 'd',
        |fixture| fixture.argv = vec!["build"],
        |fixture| fixture.cwd = "src",
        |fixture| fixture.environment_name = "python",
        |fixture| fixture.environment_digest = 'd',
        |fixture| fixture.network = NetworkProfile::ProviderEndpointOnly,
        |fixture| fixture.expected_reads = vec!["Cargo.toml"],
        |fixture| fixture.expected_writes = vec!["logs"],
        |fixture| fixture.memory_limit = Some(2_048),
        |fixture| fixture.cpu_limit = Some(5_000),
        |fixture| fixture.fencing_token = Some(20),
    ];
    let expected = tool_request(&Fixture::default());

    for mutate in mutations {
        let mut fixture = Fixture::default();
        mutate(&mut fixture);
        let current = authority_snapshot(&fixture);
        assert_integrity_failure(validate_authoritative_tool_request(&expected, &current));
    }
}

fn authority_snapshot(fixture: &Fixture) -> ToolAuthoritySnapshot {
    let request = tool_request(fixture);
    let lease = coherent_lease(&request);
    ToolAuthoritySnapshot::new(request, &fixture.resource_bytes, lease).unwrap()
}

fn coherent_lease(request: &ToolRequest) -> Option<LeaseSnapshot> {
    let token = request.process().process().executor_fencing_token()?;
    Some(active_lease(request, token))
}

fn active_lease(request: &ToolRequest, token: FencingToken) -> LeaseSnapshot {
    let binding = request.process().process().binding();
    LeaseSnapshot {
        task_id: binding.task_id().clone(),
        holder_run_id: binding.run_id().clone(),
        token,
        state: LeaseState::Active,
        acquired_at: "2025-07-23T12:00:00Z".to_owned(),
        expires_at: "2025-07-23T13:00:00Z".to_owned(),
        released_at: None,
    }
}

fn assert_integrity_failure<T>(result: Result<T, PortError>) {
    let error = result
        .err()
        .expect("authority validation unexpectedly passed");
    assert_eq!(
        error.safe_classification(),
        local_agent_terminal_application::SafeErrorClassification::IntegrityFailure
    );
    assert_eq!(
        error.retryability(),
        local_agent_terminal_application::Retryability::NonRetryable
    );
}

#[derive(Clone)]
struct Fixture {
    execution_id: &'static str,
    task_id: &'static str,
    run_id: &'static str,
    step_id: &'static str,
    phase: Phase,
    workspace_version: u64,
    timeout_ms: u64,
    environment_name: &'static str,
    environment_digest: char,
    toolchain_id: &'static str,
    executable_version: &'static str,
    executable_path: &'static str,
    executable_digest: char,
    file_identity: &'static str,
    argv: Vec<&'static str>,
    cwd: &'static str,
    network: NetworkProfile,
    expected_reads: Vec<&'static str>,
    expected_writes: Vec<&'static str>,
    memory_limit: Option<u64>,
    cpu_limit: Option<u64>,
    fencing_token: Option<u64>,
    actor_connection: &'static str,
    actor_agent: &'static str,
    actor_trust: TrustTier,
    actor_locality: ActorLocality,
    task_risk: TaskRisk,
    purpose: &'static str,
    policy_digest: char,
    resource_path: &'static str,
    resource_class: ResourceClass,
    resource_bytes: Vec<u8>,
}

impl Fixture {
    fn read_only() -> Self {
        Self {
            expected_writes: Vec::new(),
            fencing_token: None,
            ..Self::default()
        }
    }
}

impl Default for Fixture {
    fn default() -> Self {
        Self {
            execution_id: "execution-authority",
            task_id: "task-1",
            run_id: "run-1",
            step_id: "step-1",
            phase: Phase::Implementation,
            workspace_version: 4,
            timeout_ms: 1,
            environment_name: "rust",
            environment_digest: 'e',
            toolchain_id: "cargo",
            executable_version: "1.0",
            executable_path: executable_path(),
            executable_digest: 'f',
            file_identity: "file-1",
            argv: vec!["test"],
            cwd: ".",
            network: NetworkProfile::Denied,
            expected_reads: vec!["src"],
            expected_writes: vec!["target"],
            memory_limit: Some(1_024),
            cpu_limit: Some(1_000),
            fencing_token: Some(19),
            actor_connection: "connection-1",
            actor_agent: "agent-1",
            actor_trust: TrustTier::IsolatedWorker,
            actor_locality: ActorLocality::Local,
            task_risk: TaskRisk::High,
            purpose: "run focused tests",
            policy_digest: 'b',
            resource_path: ".",
            resource_class: ResourceClass::InternalCode,
            resource_bytes: b"authoritative source".to_vec(),
        }
    }
}

fn tool_request(fixture: &Fixture) -> ToolRequest {
    let task_id = TaskId::new(fixture.task_id).unwrap();
    let process = ProcessToolRequest::new(
        ProcessBinding::new(
            task_id.clone(),
            RunId::new(fixture.run_id).unwrap(),
            PlanStepId::new(fixture.step_id).unwrap(),
            fixture.phase,
            WorkspaceVersion::new(fixture.workspace_version),
            EnvironmentProfile::new(fixture.environment_name, digest(fixture.environment_digest))
                .unwrap(),
            fixture.timeout_ms,
        )
        .unwrap(),
        ProcessInvocation::new(
            CapabilityRef::toolchain(fixture.toolchain_id).unwrap(),
            fixture
                .argv
                .iter()
                .map(|value| (*value).to_owned())
                .collect(),
            CapabilityRef::worktree(task_id.clone(), fixture.cwd).unwrap(),
            ProcessTrustTier::IsolatedWorker,
            fixture.network,
            fixture
                .expected_writes
                .iter()
                .map(|path| {
                    ExpectedWrite::new(CapabilityRef::worktree(task_id.clone(), *path).unwrap())
                        .unwrap()
                })
                .collect(),
            fixture
                .fencing_token
                .map(|value| FencingToken::new(value).unwrap()),
        )
        .unwrap(),
    )
    .unwrap();
    let approved = ApprovedProcessRequest::new(
        ApprovedExecutableIdentity::new(
            ResolvedExecutable {
                canonical_path: PathBuf::from(fixture.executable_path),
                sha256: digest(fixture.executable_digest),
                file_identity: local_agent_terminal_application::ExecutableFileIdentity::new(
                    fixture.file_identity,
                )
                .unwrap(),
                toolchain_id: fixture.toolchain_id.to_owned(),
            },
            fixture.executable_version,
        )
        .unwrap(),
        process,
        fixture
            .expected_reads
            .iter()
            .map(|path| CapabilityRef::worktree(task_id.clone(), *path).unwrap())
            .collect(),
        fixture.memory_limit,
        fixture.cpu_limit,
        None,
    )
    .unwrap();
    ToolRequest::new(
        ToolExecutionId::new(fixture.execution_id).unwrap(),
        approved,
        ToolPolicyContext::new(
            PolicyActor {
                connection_id: fixture.actor_connection.to_owned(),
                agent_id: fixture.actor_agent.to_owned(),
                trust_tier: fixture.actor_trust,
                locality: fixture.actor_locality,
            },
            PolicyAction::new("process.exec").unwrap(),
            PolicyResource {
                capability: CapabilityRef::worktree(task_id, fixture.resource_path).unwrap(),
                content_digest: resource_digest(&fixture.resource_bytes),
                resource_class: fixture.resource_class,
            },
            fixture.task_risk,
            fixture.purpose,
            digest(fixture.policy_digest),
        )
        .unwrap(),
    )
    .unwrap()
}

fn resource_digest(bytes: &[u8]) -> Sha256Digest {
    Sha256Digest::new(format!("sha256:{:x}", Sha256::digest(bytes))).unwrap()
}

fn digest(character: char) -> Sha256Digest {
    Sha256Digest::new(format!("sha256:{}", character.to_string().repeat(64))).unwrap()
}

#[cfg(windows)]
fn executable_path() -> &'static str {
    r"C:\approved\cargo.exe"
}

#[cfg(not(windows))]
fn executable_path() -> &'static str {
    "/approved/cargo"
}

#[cfg(windows)]
fn alternate_executable_path() -> &'static str {
    r"C:\approved\cargo-v2.exe"
}

#[cfg(not(windows))]
fn alternate_executable_path() -> &'static str {
    "/approved/cargo-v2"
}
