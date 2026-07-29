use std::fs;
use std::sync::Mutex;

use local_agent_terminal_application::{
    AcquireLease, ApprovedProcessRequest, AuthorizedProcessRequest, BoundedOutput,
    CancellationReceipt, CapabilityRequest, CapabilityResolver, CapabilityRootIdentity,
    ExecutorLeaseStore, JobReceipt, LeaseSnapshot, PortError, ProcessLauncher, ProcessReceipt,
    ProcessStatus, ProcessWorkingDirectory, ResolvedCapability, ResolvedCapabilityTarget,
    RevokeLease, ToolExecutionId,
};
use local_agent_terminal_domain::{
    CapabilityRef, EnvironmentProfile, FencingToken, LeaseClaim, NetworkProfile, Phase, PlanStepId,
    ProcessBinding, ProcessInvocation, ProcessToolRequest, ProcessTrustTier, RunId, Sha256Digest,
    TaskId, WorkspaceVersion,
};
use local_agent_terminal_platform_core::{
    EnvironmentProfileRegistry, ExecutableRegistry, NetworkEnforcementEvidence,
    NetworkPolicyAdapter, TrustedEnvironmentProfile, TrustedExecutableRegistration,
    TrustedNetworkProfile,
};
use local_agent_terminal_platform_windows::WindowsExecutableInspector;
use local_agent_terminal_tool_runtime::ProcessRuntime;
use sha2::{Digest, Sha256};

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
}

struct CaseOutcome {
    result: Result<ProcessReceipt, PortError>,
    request: Option<AuthorizedProcessRequest>,
    execution_id: ToolExecutionId,
    claim: LeaseClaim,
}

fn execute_case(argv: Vec<String>, mutation: CaseMutation) -> CaseOutcome {
    let executable_path = std::env::current_exe().unwrap();
    let executable_digest = digest(&fs::read(&executable_path).unwrap());
    let executables = ExecutableRegistry::load(
        vec![TrustedExecutableRegistration::new(
            "cargo",
            "test-version",
            &executable_path,
            executable_digest,
        )
        .unwrap()],
        std::sync::Arc::new(WindowsExecutableInspector),
    )
    .unwrap();
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
    let resolver = WorktreeResolver {
        mismatched_echo: mutation == CaseMutation::ResolverEcho,
    };
    let leases = CurrentLease {
        expected: claim.clone(),
        stale: mutation == CaseMutation::StaleLease,
    };
    let launcher = CapturingLauncher::default();
    let runtime = ProcessRuntime::new(
        &executables,
        &environments,
        &networks,
        vec![enforced_network],
        &resolver,
        &leases,
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
            CapabilityRef::worktree(task_id, ".").unwrap(),
            ProcessTrustTier::IsolatedWorker,
            if mutation == CaseMutation::NetworkProfile {
                NetworkProfile::ApprovedDestinations
            } else {
                NetworkProfile::Denied
            },
            Vec::new(),
            (mutation != CaseMutation::MissingFencingToken).then(|| FencingToken::new(7).unwrap()),
        )
        .unwrap(),
    )
    .unwrap();

    let execution_id = ToolExecutionId::new("execution-1").unwrap();
    let result = runtime.execute(
        execution_id.clone(),
        ApprovedProcessRequest {
            process,
            expected_reads: if mutation == CaseMutation::ExpectedReads {
                vec![CapabilityRef::worktree(TaskId::new("task-1").unwrap(), "src").unwrap()]
            } else {
                Vec::new()
            },
            memory_limit_bytes: Some(64 * 1024 * 1024),
            cpu_time_limit_ms: Some(2_000),
        },
    );
    let request = launcher.request.lock().unwrap().clone();
    CaseOutcome {
        result,
        request,
        execution_id,
        claim,
    }
}

#[derive(Default)]
struct CapturingLauncher {
    request: Mutex<Option<AuthorizedProcessRequest>>,
}

impl ProcessLauncher for CapturingLauncher {
    fn execute(&self, request: AuthorizedProcessRequest) -> Result<ProcessReceipt, PortError> {
        let execution_id = request.execution_id.clone();
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
            observed_writes: Vec::new(),
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
    mismatched_echo: bool,
}

impl CapabilityResolver for WorktreeResolver {
    fn resolve(&self, request: CapabilityRequest) -> Result<ResolvedCapability, PortError> {
        Ok(ResolvedCapability {
            capability: if self.mismatched_echo {
                CapabilityRef::worktree(request.task_id, "src").unwrap()
            } else {
                request.capability
            },
            content_digest: None,
            root_identity: CapabilityRootIdentity::new("worktree-root").unwrap(),
            target: ResolvedCapabilityTarget::Root,
        })
    }
}

struct CurrentLease {
    expected: LeaseClaim,
    stale: bool,
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
