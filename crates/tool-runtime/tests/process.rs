use std::fs;
use std::path::Path;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use local_agent_terminal_application::{
    AcquireLease, ApprovedExecutableIdentity, ApprovedProcessRequest, AuthorizedProcessRequest,
    BoundedOutput, CancellationReceipt, CapabilityRequest, CapabilityResolver,
    CapabilityRootIdentity, ExecutorLeaseStore, JobReceipt, LeaseSnapshot, ObservedProcessWrite,
    PortError, ProcessFenceAuthority, ProcessLauncher, ProcessReceipt, ProcessStatus,
    ProcessWorkingDirectory, RelativePathComponents, ResolvedCapability, ResolvedCapabilityTarget,
    Retryability, RevokeLease, SafeErrorClassification, ToolExecutionId, VerifiedWrite,
    WorkspaceWriteCoordinator,
};
use local_agent_terminal_domain::{
    CapabilityRef, EnvironmentProfile, ExpectedWrite, FencingToken, LeaseClaim, NetworkProfile,
    Phase, PlanStepId, ProcessBinding, ProcessInvocation, ProcessToolRequest, ProcessTrustTier,
    RunId, Sha256Digest, TaskId, WorkspaceVersion,
};
use local_agent_terminal_platform_core::{
    EnvironmentProfileRegistry, ExecutableRegistry, NetworkEnforcementEvidence,
    NetworkPolicyAdapter, TrustedEnvironmentProfile, TrustedExecutableRegistration,
    TrustedNetworkProfile,
};
use local_agent_terminal_platform_windows::{
    IsolatedWorkerBoundaryAdapter, IsolatedWorkerBoundaryBinding, IsolatedWorkerBoundaryClaims,
    PreparedIsolatedWorkerBoundary, WindowsExecutableInspector, WindowsProcessLauncher,
};
use local_agent_terminal_tool_runtime::ProcessRuntime;
use sha2::{Digest, Sha256};
use tempfile::TempDir;

#[test]
fn brokered_process_cannot_receive_a_worktree_cwd() {
    let task_id = TaskId::new("task-1").unwrap();
    let result = ProcessInvocation::new(
        CapabilityRef::toolchain("agent-host").unwrap(),
        vec!["serve".to_owned()],
        CapabilityRef::worktree(task_id, ".").unwrap(),
        ProcessTrustTier::BrokeredProcess,
        NetworkProfile::Denied,
        Vec::new(),
        None,
    );

    assert!(result.is_err());
}

#[test]
fn typed_process_exec_resolves_profiles_and_preserves_argv_boundaries() {
    let argv = vec!["test".to_owned(), ";&|$()".to_owned()];
    let outcome = execute_case(argv.clone(), CaseMutation::None);
    let receipt = outcome.result.unwrap();
    let captured = outcome.request.unwrap();

    assert_eq!(captured.execution_id, outcome.execution_id);
    assert_eq!(receipt.execution_id, outcome.execution_id);
    assert_eq!(captured.argv, argv);
    assert_eq!(captured.executable.toolchain_id, "cargo");
    assert_eq!(captured.environment.values.get("CI").unwrap(), "1");
    assert_eq!(captured.network.profile, NetworkProfile::Denied);
    assert_eq!(captured.executor_claim, outcome.claim);
    assert!(matches!(
        captured.cwd,
        ProcessWorkingDirectory::IsolatedWorktree(_)
    ));
}

#[test]
fn expected_write_scopes_are_resolved_before_launch() {
    let outcome = execute_case(vec!["test".to_owned()], CaseMutation::ExpectedWriteScopes);
    let captured = outcome.request.expect("launcher request");

    assert_eq!(captured.expected_writes.len(), 2);
    for (scope, path) in captured
        .expected_writes
        .iter()
        .zip([".", "target/second.txt"])
    {
        assert_eq!(
            scope.capability(),
            &CapabilityRef::worktree(TaskId::new("task-1").unwrap(), path).unwrap()
        );
        assert_eq!(scope.root_identity().as_str(), "worktree-root");
        let expected_target = if path == "." {
            ResolvedCapabilityTarget::Root
        } else {
            ResolvedCapabilityTarget::Relative(
                RelativePathComponents::new(path.split('/').map(str::to_owned).collect::<Vec<_>>())
                    .unwrap(),
            )
        };
        assert_eq!(scope.target(), &expected_target);
    }
}

#[test]
fn response_file_arguments_are_denied_before_launch() {
    let outcome = execute_case(
        vec!["test".to_owned(), "@attacker.rsp".to_owned()],
        CaseMutation::None,
    );

    assert!(outcome.result.is_err());
    assert!(outcome.request.is_none());
}

#[test]
fn unresolved_profiles_cwd_and_stale_lease_never_reach_the_launcher() {
    for mutation in [
        CaseMutation::UnregisteredExecutable,
        CaseMutation::EnvironmentDigest,
        CaseMutation::NetworkProfile,
        CaseMutation::ResolverEcho,
        CaseMutation::StaleLease,
        CaseMutation::MissingFencingToken,
        CaseMutation::ExpectedReads,
    ] {
        let outcome = execute_case(vec!["test".to_owned()], mutation);

        assert!(outcome.result.is_err(), "{mutation:?}");
        assert!(outcome.request.is_none(), "{mutation:?}");
    }
}

#[test]
fn write_scope_resolution_failures_never_reach_launcher() {
    for mutation in [
        CaseMutation::WriteResolverFailure,
        CaseMutation::WriteTaskEcho,
        CaseMutation::WriteCapabilityEcho,
        CaseMutation::WriteRootIdentity,
        CaseMutation::WriteTarget,
    ] {
        let outcome = execute_case(vec!["test".to_owned()], mutation);

        let error = match outcome.result {
            Ok(receipt) => panic!("{mutation:?} reached launcher: {receipt:?}"),
            Err(error) => error,
        };
        assert_eq!(
            error.safe_classification(),
            SafeErrorClassification::IntegrityFailure,
            "{mutation:?}"
        );
        assert_eq!(outcome.launcher_calls, 0, "{mutation:?}");
        assert!(outcome.request.is_none(), "{mutation:?}");
    }
}

#[test]
fn launcher_write_evidence_is_revalidated_by_runtime() {
    let outcome = execute_case(
        vec!["test".to_owned()],
        CaseMutation::LauncherMissingWriteEvidence,
    );

    let error = outcome.result.expect_err("missing evidence must be denied");
    assert_eq!(
        error.safe_classification(),
        SafeErrorClassification::IntegrityFailure
    );
    assert_eq!(outcome.launcher_calls, 1);
    assert!(outcome.request.is_some());
}

#[test]
fn old_approval_executable_identity_replacement_never_reaches_launcher() {
    for replacement in [
        ExecutableReplacement::Version,
        ExecutableReplacement::Digest,
        ExecutableReplacement::Path,
        ExecutableReplacement::FileIdentity,
        ExecutableReplacement::Registry,
    ] {
        let outcome = execute_replacement_case(replacement);

        let error = outcome.result.expect_err("replacement must be denied");
        assert_eq!(
            error.safe_classification(),
            SafeErrorClassification::IntegrityFailure,
            "{replacement:?}"
        );
        assert_eq!(outcome.launcher_calls, 0, "{replacement:?}");
        assert!(outcome.request.is_none(), "{replacement:?}");
    }
}

#[test]
fn runtime_initial_check_cannot_bypass_final_windows_resume_fence() {
    let root = TempDir::new().unwrap();
    let marker = root.path().join("must-not-run-after-runtime-check.txt");
    let executable_path = std::env::current_exe().unwrap();
    let executables = executable_registry(&executable_path, "test-version");
    let approved_executable = executables.resolve_registered("cargo").unwrap();
    let environment_digest = Sha256Digest::new(
        "sha256:c465e195c2dd90a8fc0317b7ba545d3fa5233faec2b1a216c4d205dc7be61c65",
    )
    .unwrap();
    let environments = EnvironmentProfileRegistry::load(vec![TrustedEnvironmentProfile::new(
        "rust-build",
        vec![
            ("CI".to_owned(), "1".to_owned()),
            ("RUST_BACKTRACE".to_owned(), "0".to_owned()),
        ],
        false,
    )
    .unwrap()])
    .unwrap();
    let networks = NetworkPolicyAdapter::load(vec![TrustedNetworkProfile::new(
        "offline",
        NetworkProfile::Denied,
        Vec::new(),
        "firewall-rule-7",
    )
    .unwrap()])
    .unwrap();
    let enforced_network = networks
        .prepare(
            "offline",
            NetworkProfile::Denied,
            NetworkEnforcementEvidence::new("firewall-rule-7", true, true).unwrap(),
        )
        .unwrap();
    let leases = Arc::new(AuthoritativeReplacingLeaseStore::new());
    let writes = Arc::new(WorkspaceWriteCoordinator::new());
    let authority = ProcessFenceAuthority::new(leases.clone(), writes);
    let boundary = Arc::new(RuntimeLeaseReplacingBoundary {
        cwd: root.path().to_owned(),
        leases: Arc::clone(&leases),
        authority: authority.clone(),
    });
    let launcher = WindowsProcessLauncher::with_isolated_worker_boundary(
        boundary,
        IsolatedWorkerBoundaryBinding::new("runtime-test-identity", "runtime-test-acl").unwrap(),
    );
    let resolver = WorktreeResolver {
        mutation: CaseMutation::None,
    };
    let runtime = ProcessRuntime::new(
        &executables,
        &environments,
        &networks,
        vec![enforced_network],
        &resolver,
        &authority,
        &launcher,
    )
    .unwrap();
    let task_id = TaskId::new("task-1").unwrap();
    let run_id = RunId::new("run-1").unwrap();
    let process = ProcessToolRequest::new(
        ProcessBinding::new(
            task_id.clone(),
            run_id,
            PlanStepId::new("step-1").unwrap(),
            Phase::Implementation,
            WorkspaceVersion::new(4),
            EnvironmentProfile::new("rust-build", environment_digest).unwrap(),
            5_000,
        )
        .unwrap(),
        ProcessInvocation::new(
            CapabilityRef::toolchain("cargo").unwrap(),
            vec![
                "--exact".to_owned(),
                "process_runtime_final_fence_child_helper".to_owned(),
                "--nocapture".to_owned(),
                "--skip".to_owned(),
                marker.to_string_lossy().into_owned(),
            ],
            CapabilityRef::worktree(task_id, ".").unwrap(),
            ProcessTrustTier::IsolatedWorker,
            NetworkProfile::Denied,
            Vec::new(),
            Some(FencingToken::new(7).unwrap()),
        )
        .unwrap(),
    )
    .unwrap();
    let execution_id = ToolExecutionId::new("runtime-final-fence-race").unwrap();

    let error = runtime
        .execute(
            execution_id.clone(),
            ApprovedProcessRequest::new(
                approved_executable,
                process,
                Vec::new(),
                Some(64 * 1024 * 1024),
                Some(2_000),
            )
            .unwrap(),
        )
        .expect_err("replacement after the runtime check must deny resume");

    assert!(matches!(
        error,
        PortError::StaleLease { current, supplied }
            if current.get() == 8 && supplied.get() == 7
    ));
    assert_eq!(leases.assertions.load(Ordering::SeqCst), 2);
    assert_eq!(leases.acquisitions.load(Ordering::SeqCst), 1);
    assert!(!marker.exists());
    assert!(launcher.cancel(&execution_id).is_err());
}

#[test]
fn process_runtime_final_fence_child_helper() {
    let arguments = std::env::args().collect::<Vec<_>>();
    if let Some(marker) = arguments
        .windows(2)
        .find(|pair| pair[0] == "--skip")
        .map(|pair| &pair[1])
    {
        fs::write(marker, b"child-ran").unwrap();
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CaseMutation {
    None,
    UnregisteredExecutable,
    EnvironmentDigest,
    NetworkProfile,
    ResolverEcho,
    StaleLease,
    MissingFencingToken,
    ExpectedReads,
    ExpectedWriteScopes,
    WriteResolverFailure,
    WriteTaskEcho,
    WriteCapabilityEcho,
    WriteRootIdentity,
    WriteTarget,
    LauncherMissingWriteEvidence,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ExecutableReplacement {
    Version,
    Digest,
    Path,
    FileIdentity,
    Registry,
}

struct CaseOutcome {
    result: Result<ProcessReceipt, PortError>,
    request: Option<AuthorizedProcessRequest>,
    execution_id: ToolExecutionId,
    claim: LeaseClaim,
    launcher_calls: usize,
}

fn execute_case(argv: Vec<String>, mutation: CaseMutation) -> CaseOutcome {
    let executable_path = std::env::current_exe().unwrap();
    let executables = executable_registry(&executable_path, "test-version");
    let approved_executable = executables.resolve_registered("cargo").unwrap();
    execute_with_registry(argv, mutation, &executables, approved_executable)
}

fn execute_replacement_case(replacement: ExecutableReplacement) -> CaseOutcome {
    let root = TempDir::new().unwrap();
    let approved_path = root.path().join("approved-tool.exe");
    fs::copy(std::env::current_exe().unwrap(), &approved_path).unwrap();
    let approved_registry = executable_registry(&approved_path, "approved-version");
    let approved_executable = approved_registry.resolve_registered("cargo").unwrap();

    let replacement_path = root.path().join("replacement-tool.exe");
    let (registered_path, registered_version) = match replacement {
        ExecutableReplacement::Version => (approved_path.clone(), "replacement-version"),
        ExecutableReplacement::Digest => {
            fs::write(&approved_path, b"replacement executable digest").unwrap();
            (approved_path.clone(), "approved-version")
        }
        ExecutableReplacement::Path => {
            fs::hard_link(&approved_path, &replacement_path).unwrap();
            (replacement_path, "approved-version")
        }
        ExecutableReplacement::FileIdentity => {
            fs::copy(&approved_path, &replacement_path).unwrap();
            fs::remove_file(&approved_path).unwrap();
            fs::rename(&replacement_path, &approved_path).unwrap();
            (approved_path.clone(), "approved-version")
        }
        ExecutableReplacement::Registry => {
            fs::write(&replacement_path, b"replacement registry executable").unwrap();
            (replacement_path, "replacement-version")
        }
    };
    let current_registry = executable_registry(&registered_path, registered_version);
    let current_executable = current_registry.resolve_registered("cargo").unwrap();
    assert_replacement_fixture(replacement, &approved_executable, &current_executable);

    execute_with_registry(
        vec!["test".to_owned()],
        CaseMutation::None,
        &current_registry,
        approved_executable,
    )
}

fn executable_registry(path: &Path, version: &str) -> ExecutableRegistry {
    let executable_digest = digest(&fs::read(path).unwrap());
    ExecutableRegistry::load(
        vec![
            TrustedExecutableRegistration::new("cargo", version, path, executable_digest).unwrap(),
        ],
        std::sync::Arc::new(WindowsExecutableInspector),
    )
    .unwrap()
}

fn assert_replacement_fixture(
    replacement: ExecutableReplacement,
    approved: &ApprovedExecutableIdentity,
    current: &ApprovedExecutableIdentity,
) {
    match replacement {
        ExecutableReplacement::Version => {
            assert_eq!(approved.executable(), current.executable());
            assert_ne!(approved.version(), current.version());
        }
        ExecutableReplacement::Digest => {
            assert_eq!(approved.version(), current.version());
            assert_eq!(
                approved.executable().canonical_path,
                current.executable().canonical_path
            );
            assert_eq!(
                approved.executable().file_identity,
                current.executable().file_identity
            );
            assert_ne!(approved.executable().sha256, current.executable().sha256);
        }
        ExecutableReplacement::Path => {
            assert_eq!(approved.version(), current.version());
            assert_eq!(approved.executable().sha256, current.executable().sha256);
            assert_eq!(
                approved.executable().file_identity,
                current.executable().file_identity
            );
            assert_ne!(
                approved.executable().canonical_path,
                current.executable().canonical_path
            );
        }
        ExecutableReplacement::FileIdentity => {
            assert_eq!(approved.version(), current.version());
            assert_eq!(approved.executable().sha256, current.executable().sha256);
            assert_eq!(
                approved.executable().canonical_path,
                current.executable().canonical_path
            );
            assert_ne!(
                approved.executable().file_identity,
                current.executable().file_identity
            );
        }
        ExecutableReplacement::Registry => assert_ne!(approved, current),
    }
}

fn execute_with_registry(
    argv: Vec<String>,
    mutation: CaseMutation,
    executables: &ExecutableRegistry,
    approved_executable: ApprovedExecutableIdentity,
) -> CaseOutcome {
    let environment_digest = Sha256Digest::new(
        "sha256:c465e195c2dd90a8fc0317b7ba545d3fa5233faec2b1a216c4d205dc7be61c65",
    )
    .unwrap();
    let environments = EnvironmentProfileRegistry::load(vec![TrustedEnvironmentProfile::new(
        "rust-build",
        vec![
            ("CI".to_owned(), "1".to_owned()),
            ("RUST_BACKTRACE".to_owned(), "0".to_owned()),
        ],
        false,
    )
    .unwrap()])
    .unwrap();
    let networks = NetworkPolicyAdapter::load(vec![TrustedNetworkProfile::new(
        "offline",
        NetworkProfile::Denied,
        Vec::new(),
        "firewall-rule-7",
    )
    .unwrap()])
    .unwrap();
    let enforced_network = networks
        .prepare(
            "offline",
            NetworkProfile::Denied,
            NetworkEnforcementEvidence::new("firewall-rule-7", true, true).unwrap(),
        )
        .unwrap();
    let task_id = TaskId::new("task-1").unwrap();
    let run_id = RunId::new("run-1").unwrap();
    let claim = LeaseClaim::new(
        task_id.clone(),
        run_id.clone(),
        FencingToken::new(7).unwrap(),
    );
    let resolver = WorktreeResolver { mutation };
    let leases = Arc::new(CurrentLease {
        expected: claim.clone(),
        stale: mutation == CaseMutation::StaleLease,
    });
    let executor_fence =
        ProcessFenceAuthority::new(leases, Arc::new(WorkspaceWriteCoordinator::new()));
    let launcher = CapturingLauncher {
        omit_write_evidence: mutation == CaseMutation::LauncherMissingWriteEvidence,
        ..CapturingLauncher::default()
    };
    let runtime = ProcessRuntime::new(
        executables,
        &environments,
        &networks,
        vec![enforced_network],
        &resolver,
        &executor_fence,
        &launcher,
    )
    .unwrap();
    let process = ProcessToolRequest::new(
        ProcessBinding::new(
            task_id.clone(),
            run_id,
            PlanStepId::new("step-1").unwrap(),
            Phase::Implementation,
            WorkspaceVersion::new(4),
            EnvironmentProfile::new(
                "rust-build",
                if mutation == CaseMutation::EnvironmentDigest {
                    digest(b"wrong-environment")
                } else {
                    environment_digest
                },
            )
            .unwrap(),
            5_000,
        )
        .unwrap(),
        ProcessInvocation::new(
            CapabilityRef::toolchain(if mutation == CaseMutation::UnregisteredExecutable {
                "rustc"
            } else {
                "cargo"
            })
            .unwrap(),
            argv.clone(),
            CapabilityRef::worktree(task_id.clone(), ".").unwrap(),
            ProcessTrustTier::IsolatedWorker,
            if mutation == CaseMutation::NetworkProfile {
                NetworkProfile::ApprovedDestinations
            } else {
                NetworkProfile::Denied
            },
            if matches!(
                mutation,
                CaseMutation::ExpectedWriteScopes
                    | CaseMutation::WriteResolverFailure
                    | CaseMutation::WriteTaskEcho
                    | CaseMutation::WriteCapabilityEcho
                    | CaseMutation::WriteRootIdentity
                    | CaseMutation::WriteTarget
                    | CaseMutation::LauncherMissingWriteEvidence
            ) {
                [".", "target/second.txt"]
                    .into_iter()
                    .map(|path| {
                        ExpectedWrite::new(CapabilityRef::worktree(task_id.clone(), path).unwrap())
                            .unwrap()
                    })
                    .collect()
            } else {
                Vec::new()
            },
            (mutation != CaseMutation::MissingFencingToken).then(|| FencingToken::new(7).unwrap()),
        )
        .unwrap(),
    )
    .unwrap();

    let execution_id = ToolExecutionId::new("execution-1").unwrap();
    let approved = ApprovedProcessRequest::new(
        approved_executable,
        process,
        if mutation == CaseMutation::ExpectedReads {
            vec![CapabilityRef::worktree(TaskId::new("task-1").unwrap(), "src").unwrap()]
        } else {
            Vec::new()
        },
        Some(64 * 1024 * 1024),
        Some(2_000),
    );
    let result = approved.and_then(|approved| runtime.execute(execution_id.clone(), approved));
    let request = launcher.request.lock().unwrap().clone();
    let launcher_calls = launcher.calls.load(Ordering::SeqCst);
    CaseOutcome {
        result,
        request,
        execution_id,
        claim,
        launcher_calls,
    }
}

#[derive(Default)]
struct CapturingLauncher {
    request: Mutex<Option<AuthorizedProcessRequest>>,
    calls: AtomicUsize,
    omit_write_evidence: bool,
}

impl ProcessLauncher for CapturingLauncher {
    fn execute(&self, request: AuthorizedProcessRequest) -> Result<ProcessReceipt, PortError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let execution_id = request.execution_id.clone();
        let observed_writes = if self.omit_write_evidence {
            Vec::new()
        } else {
            request
                .expected_writes
                .iter()
                .map(|scope| {
                    ObservedProcessWrite::new(
                        scope.capability().clone(),
                        scope.root_identity().clone(),
                        scope.target().clone(),
                        VerifiedWrite {
                            digest: digest(b"observed process write"),
                            size_bytes: 22,
                        },
                    )
                })
                .collect()
        };
        *self.request.lock().unwrap() = Some(request);
        Ok(ProcessReceipt {
            execution_id,
            status: ProcessStatus::Exited,
            exit_code: Some(0),
            stdout: BoundedOutput {
                bytes: b"ok".to_vec(),
                truncated: false,
            },
            stderr: BoundedOutput {
                bytes: Vec::new(),
                truncated: false,
            },
            duration_ms: 1,
            job_receipt: JobReceipt {
                root_pid: 1,
                job_id: "test-job".to_owned(),
                kill_on_close: true,
                no_breakaway: true,
                job_memory_limit: true,
                job_cpu_time_limit: true,
                memory_limit_bytes: 256 * 1024 * 1024,
                cpu_time_limit_ms: 5_000,
                max_active_processes: 8,
                total_user_time_ms: 0,
                resource_limit_terminated: false,
                tree_terminated: false,
            },
            observed_writes,
            output_digest: digest(b"ok"),
        })
    }

    fn cancel(&self, execution_id: &ToolExecutionId) -> Result<CancellationReceipt, PortError> {
        Ok(CancellationReceipt {
            execution_id: execution_id.clone(),
            status: ProcessStatus::Terminated,
            job_receipt: None,
            cancelled: true,
        })
    }
}

struct WorktreeResolver {
    mutation: CaseMutation,
}

impl CapabilityResolver for WorktreeResolver {
    fn resolve(&self, request: CapabilityRequest) -> Result<ResolvedCapability, PortError> {
        let is_write_scope = matches!(
            &request.capability,
            CapabilityRef::Worktree(worktree) if worktree.path() != "."
        );
        if is_write_scope && self.mutation == CaseMutation::WriteResolverFailure {
            return Err(PortError::failure(
                SafeErrorClassification::IntegrityFailure,
                Retryability::NonRetryable,
            ));
        }
        let target = match &request.capability {
            CapabilityRef::Worktree(_)
                if is_write_scope && self.mutation == CaseMutation::WriteTarget =>
            {
                ResolvedCapabilityTarget::Relative(
                    RelativePathComponents::new(vec!["different.txt".to_owned()]).unwrap(),
                )
            }
            CapabilityRef::Worktree(worktree) if worktree.path() != "." => {
                ResolvedCapabilityTarget::Relative(
                    RelativePathComponents::new(
                        worktree
                            .path()
                            .split('/')
                            .map(str::to_owned)
                            .collect::<Vec<_>>(),
                    )
                    .unwrap(),
                )
            }
            _ => ResolvedCapabilityTarget::Root,
        };
        Ok(ResolvedCapability {
            capability: if is_write_scope && self.mutation == CaseMutation::WriteTaskEcho {
                let CapabilityRef::Worktree(worktree) = &request.capability else {
                    unreachable!();
                };
                CapabilityRef::worktree(TaskId::new("other-task").unwrap(), worktree.path())
                    .unwrap()
            } else if self.mutation == CaseMutation::ResolverEcho
                || (is_write_scope && self.mutation == CaseMutation::WriteCapabilityEcho)
            {
                CapabilityRef::worktree(request.task_id, "src").unwrap()
            } else {
                request.capability
            },
            content_digest: None,
            root_identity: CapabilityRootIdentity::new(
                if is_write_scope && self.mutation == CaseMutation::WriteRootIdentity {
                    "other-root"
                } else {
                    "worktree-root"
                },
            )
            .unwrap(),
            target,
        })
    }
}

struct CurrentLease {
    expected: LeaseClaim,
    stale: bool,
}

struct RuntimeLeaseReplacingBoundary {
    cwd: std::path::PathBuf,
    leases: Arc<AuthoritativeReplacingLeaseStore>,
    authority: ProcessFenceAuthority,
}

impl IsolatedWorkerBoundaryAdapter for RuntimeLeaseReplacingBoundary {
    fn prepare(
        &self,
        request: &AuthorizedProcessRequest,
    ) -> Result<PreparedIsolatedWorkerBoundary, PortError> {
        PreparedIsolatedWorkerBoundary::new(
            &self.cwd,
            "runtime-test-identity",
            "runtime-test-acl",
            None,
            IsolatedWorkerBoundaryClaims::from_request(request),
        )
    }

    fn verify_before_resume(
        &self,
        request: &AuthorizedProcessRequest,
        _prepared: &PreparedIsolatedWorkerBoundary,
    ) -> Result<(), PortError> {
        assert_eq!(self.leases.assertions.load(Ordering::SeqCst), 1);
        self.authority.acquire_lease(AcquireLease {
            task_id: request.executor_claim.task_id().clone(),
            holder_run_id: RunId::new("run-2").unwrap(),
            expected_fencing_epoch: 7,
            acquired_at: "2026-07-29T00:00:00Z".to_owned(),
            expires_at: "2026-07-29T01:00:00Z".to_owned(),
        })?;
        Ok(())
    }
}

struct AuthoritativeReplacingLeaseStore {
    current: AtomicU64,
    assertions: AtomicUsize,
    acquisitions: AtomicUsize,
}

impl AuthoritativeReplacingLeaseStore {
    const fn new() -> Self {
        Self {
            current: AtomicU64::new(7),
            assertions: AtomicUsize::new(0),
            acquisitions: AtomicUsize::new(0),
        }
    }
}

impl ExecutorLeaseStore for AuthoritativeReplacingLeaseStore {
    fn acquire(&self, request: AcquireLease) -> Result<LeaseSnapshot, PortError> {
        self.acquisitions.fetch_add(1, Ordering::SeqCst);
        self.current.store(8, Ordering::SeqCst);
        Ok(LeaseSnapshot {
            task_id: request.task_id,
            holder_run_id: request.holder_run_id,
            token: FencingToken::new(8).unwrap(),
            state: local_agent_terminal_application::LeaseState::Active,
            acquired_at: request.acquired_at,
            expires_at: request.expires_at,
            released_at: None,
        })
    }

    fn revoke(&self, _request: RevokeLease) -> Result<(), PortError> {
        unreachable!()
    }

    fn fence_stale(&self) -> Result<Vec<LeaseSnapshot>, PortError> {
        unreachable!()
    }

    fn assert_current(&self, claim: LeaseClaim) -> Result<(), PortError> {
        self.assertions.fetch_add(1, Ordering::SeqCst);
        assert_eq!(claim.task_id(), &TaskId::new("task-1").unwrap());
        let current = FencingToken::new(self.current.load(Ordering::SeqCst)).unwrap();
        if current == claim.token() {
            Ok(())
        } else {
            Err(PortError::stale_lease(current, claim.token()))
        }
    }
}

impl ExecutorLeaseStore for CurrentLease {
    fn acquire(&self, _request: AcquireLease) -> Result<LeaseSnapshot, PortError> {
        unreachable!()
    }

    fn revoke(&self, _request: RevokeLease) -> Result<(), PortError> {
        unreachable!()
    }

    fn fence_stale(&self) -> Result<Vec<LeaseSnapshot>, PortError> {
        unreachable!()
    }

    fn assert_current(&self, claim: LeaseClaim) -> Result<(), PortError> {
        assert_eq!(claim, self.expected);
        if self.stale {
            Err(PortError::stale_lease(
                FencingToken::new(8).unwrap(),
                claim.token(),
            ))
        } else {
            Ok(())
        }
    }
}

fn digest(bytes: &[u8]) -> Sha256Digest {
    Sha256Digest::new(format!("sha256:{:x}", Sha256::digest(bytes))).unwrap()
}
