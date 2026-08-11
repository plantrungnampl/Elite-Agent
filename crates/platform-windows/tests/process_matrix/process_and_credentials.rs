use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::net::{IpAddr, SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::os::windows::ffi::OsStrExt;
use std::os::windows::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::ptr;
#[cfg(feature = "test-seams")]
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::{AtomicU64, Ordering};
#[cfg(feature = "test-seams")]
use std::sync::mpsc;
#[cfg(feature = "test-seams")]
use std::sync::Mutex;
use std::sync::{Arc, OnceLock};
use std::thread;
use std::time::Duration;
#[cfg(feature = "test-seams")]
use std::time::Instant;

#[cfg(feature = "test-seams")]
use local_agent_terminal_application::ExecutableFileIdentity;
use local_agent_terminal_application::{
    validate_and_order_process_writes, AcquireLease, AuthoritativeProcessBinding,
    AuthorizedExpectedWrite, AuthorizedProcessRequest, CancellationReceipt, CapabilityRootIdentity,
    EnforcedNetworkProfile, ExecutorLeaseStore, LeaseSnapshot, LeaseState,
    NetworkEnforcementReceipt, ObservedProcessWrite, PortError, ProcessExecutionBindingStore,
    ProcessFenceAuthority, ProcessLimits, ProcessReceipt, ProcessStatus, ProcessWorkingDirectory,
    RelativePathComponents, ResolvedCapability, ResolvedCapabilityTarget,
    ResolvedEnvironmentProfile, Retryability, RevokeLease, SafeErrorClassification,
    ToolControlSelfTest, ToolExecutionClaimAuthority, ToolExecutionId, VerifiedWrite,
    WorkspaceWriteCoordinator,
};
use local_agent_terminal_domain::{
    CapabilityRef, ExpectedWrite, FencingToken, LeaseClaim, NetworkProfile, ProcessTrustTier,
    RunId, Sha256Digest, TaskId,
};
use local_agent_terminal_platform_core::{
    ExecutableRegistry, PrivateRuntimeDirectoryRegistry, TrustedExecutableRegistration,
    TrustedPrivateRuntimeDirectory,
};
#[cfg(feature = "test-seams")]
use local_agent_terminal_platform_windows::{
    block_next_job_cleanup_failure_for_test, bypass_aap_attestation_for_test,
    configure_all_packages_canary_for_test, fail_after_resume_for_test,
    fail_lpac_token_verification_for_test, fail_next_output_reader_start_for_test,
    lpac_lifecycle_counts_for_test, observe_stderr_marker_for_test,
    omit_all_application_packages_policy_for_test, output_reader_counts_for_test,
    IsolatedWorkerBoundaryAdapter, IsolatedWorkerBoundaryBinding, IsolatedWorkerBoundaryClaims,
    JobCleanupFailurePointForTest, LpacLifecycleCountsForTest,
    LpacTokenVerificationMismatchForTest, PreparedIsolatedWorkerBoundary,
};
use local_agent_terminal_platform_windows::{
    TrustedLpacWorktreeRegistration, WindowsExecutableInspector,
    WindowsPrivateRuntimeDirectoryInspector, WindowsProcessLauncher,
};
use sha2::{Digest, Sha256};
use tempfile::TempDir;
use windows_sys::core::GUID;
#[cfg(feature = "test-seams")]
use windows_sys::Win32::Foundation::STILL_ACTIVE;
use windows_sys::Win32::Foundation::{
    CloseHandle, GetLastError, LocalFree, ERROR_ACCESS_DENIED, ERROR_ALREADY_EXISTS,
    ERROR_FILE_NOT_FOUND, ERROR_INSUFFICIENT_BUFFER, ERROR_INVALID_FUNCTION,
    ERROR_NOT_ENOUGH_QUOTA, ERROR_NOT_FOUND, ERROR_NOT_SUPPORTED,
    ERROR_NOT_SUPPORTED_IN_APPCONTAINER, ERROR_NO_SUCH_LOGON_SESSION, ERROR_PIPE_CONNECTED,
    ERROR_PIPE_LISTENING, ERROR_SUCCESS, FILETIME, GENERIC_READ, GENERIC_WRITE,
    INVALID_HANDLE_VALUE, WAIT_OBJECT_0,
};
use windows_sys::Win32::Networking::WinSock::{
    closesocket, connect, getsockopt, ioctlsocket, socket, WSACleanup, WSAGetLastError, WSAPoll,
    WSAStartup, AF_INET, FIONBIO, INVALID_SOCKET, IN_ADDR, IN_ADDR_0, IPPROTO_TCP, POLLOUT,
    SOCKADDR, SOCKADDR_IN, SOCKET, SOCKET_ERROR, SOCK_STREAM, SOL_SOCKET, SO_ERROR, WSADATA,
    WSAEACCES, WSAEINPROGRESS, WSAEPROVIDERFAILEDINIT, WSAEWOULDBLOCK, WSAPOLLFD,
    WSASYSCALLFAILURE,
};
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW, GetSecurityInfo,
    SDDL_REVISION_1, SE_KERNEL_OBJECT,
};
use windows_sys::Win32::Security::Credentials::{
    CredDeleteW, CredEnumerateW, CredFree, CredReadW, CredWriteW, CREDENTIALW,
    CRED_PERSIST_SESSION, CRED_TYPE_GENERIC,
};
use windows_sys::Win32::Security::{
    AclSizeInformation, GetAce, GetAclInformation, GetTokenInformation, TokenCapabilities,
    TokenIsAppContainer, TokenUser, ACCESS_ALLOWED_ACE, ACL_SIZE_INFORMATION,
    DACL_SECURITY_INFORMATION, SECURITY_ATTRIBUTES, SID_AND_ATTRIBUTES, TOKEN_GROUPS, TOKEN_QUERY,
    TOKEN_USER,
};
#[cfg(feature = "test-seams")]
use windows_sys::Win32::Storage::FileSystem::SYNCHRONIZE;
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, FILE_ATTRIBUTE_NORMAL, OPEN_EXISTING, PIPE_ACCESS_DUPLEX,
};
use windows_sys::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe, PIPE_NOWAIT, PIPE_READMODE_BYTE,
    PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_BYTE,
};
use windows_sys::Win32::System::Registry::{
    RegCloseKey, RegCreateKeyExW, RegDeleteTreeW, RegGetValueW, RegOpenKeyExW, RegSetValueExW,
    HKEY_CURRENT_USER, KEY_READ, KEY_WRITE, REG_BINARY, REG_CREATED_NEW_KEY, RRF_RT_REG_BINARY,
};
use windows_sys::Win32::System::Rpc::{
    UuidCreate, RPC_S_INVALID_BINDING, RPC_S_OK, RPC_S_UUID_LOCAL_ONLY,
};
use windows_sys::Win32::System::Threading::{
    CreateProcessW, GetCurrentProcess, GetProcessTimes, OpenProcessToken, TerminateProcess,
    WaitForSingleObject, CREATE_BREAKAWAY_FROM_JOB, CREATE_NEW_PROCESS_GROUP,
    CREATE_UNICODE_ENVIRONMENT, DETACHED_PROCESS, PROCESS_INFORMATION, STARTUPINFOW,
};
#[cfg(feature = "test-seams")]
use windows_sys::Win32::System::Threading::{
    GetExitCodeProcess, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
};

#[cfg(feature = "test-seams")]
static JOB_CLEANUP_FAILURE_TEST_LOCK: Mutex<()> = Mutex::new(());
static NEXT_PROCESS_EXECUTION_ID: AtomicU64 = AtomicU64::new(1);

trait TestProcessLauncher {
    fn execute(&self, request: AuthorizedProcessRequest) -> Result<ProcessReceipt, PortError>;
    fn cancel(&self, execution_id: &ToolExecutionId) -> Result<CancellationReceipt, PortError>;
}

impl TestProcessLauncher for WindowsProcessLauncher {
    fn execute(&self, request: AuthorizedProcessRequest) -> Result<ProcessReceipt, PortError> {
        let authority = claimed_authority(&request);
        let bindings = TestProcessBindings::accepting(authority.clone());
        local_agent_terminal_application::ProcessLauncher::execute(
            self, request, &authority, &bindings,
        )
    }

    fn cancel(&self, execution_id: &ToolExecutionId) -> Result<CancellationReceipt, PortError> {
        local_agent_terminal_application::ProcessLauncher::cancel(self, execution_id)
    }
}

struct TestProcessBindings {
    authority: ToolExecutionClaimAuthority,
    reject_record: bool,
}

#[cfg(feature = "test-seams")]
struct CapturingProcessBindings {
    authority: ToolExecutionClaimAuthority,
    captured: Arc<Mutex<Option<AuthoritativeProcessBinding>>>,
}

#[cfg(feature = "test-seams")]
impl ProcessExecutionBindingStore for CapturingProcessBindings {
    fn load_claimed_authority(
        &self,
        execution_id: &ToolExecutionId,
    ) -> Result<ToolExecutionClaimAuthority, PortError> {
        if self.authority.execution_id() != execution_id {
            return Err(test_binding_error());
        }
        Ok(self.authority.clone())
    }

    fn record_process_binding(
        &self,
        binding: AuthoritativeProcessBinding,
    ) -> Result<(), PortError> {
        if binding.authority() != &self.authority {
            return Err(test_binding_error());
        }
        *self.captured.lock().unwrap() = Some(binding);
        Ok(())
    }
}

impl TestProcessBindings {
    fn accepting(authority: ToolExecutionClaimAuthority) -> Self {
        Self {
            authority,
            reject_record: false,
        }
    }

    #[cfg(feature = "test-seams")]
    fn rejecting(authority: ToolExecutionClaimAuthority) -> Self {
        Self {
            authority,
            reject_record: true,
        }
    }
}

impl ProcessExecutionBindingStore for TestProcessBindings {
    fn load_claimed_authority(
        &self,
        execution_id: &ToolExecutionId,
    ) -> Result<ToolExecutionClaimAuthority, PortError> {
        if self.authority.execution_id() != execution_id {
            return Err(test_binding_error());
        }
        Ok(self.authority.clone())
    }

    fn record_process_binding(
        &self,
        binding: AuthoritativeProcessBinding,
    ) -> Result<(), PortError> {
        if binding.authority() != &self.authority || self.reject_record {
            return Err(test_binding_error());
        }
        Ok(())
    }
}

fn claimed_authority(request: &AuthorizedProcessRequest) -> ToolExecutionClaimAuthority {
    ToolExecutionClaimAuthority::from_persisted(
        request.execution_id.clone(),
        digest(b"test process operation"),
        request.executor_claim.holder_run_id().clone(),
        1,
        Some(request.executor_claim.token()),
    )
    .unwrap()
}

#[cfg(feature = "test-seams")]
fn substituted_authorities(
    authority: &ToolExecutionClaimAuthority,
) -> [ToolExecutionClaimAuthority; 5] {
    [
        ToolExecutionClaimAuthority::from_persisted(
            ToolExecutionId::new("execution-retained-recovery-substitute").unwrap(),
            authority.operation_digest().clone(),
            authority.owner_run_id().clone(),
            authority.attempt(),
            authority.executor_fencing_token(),
        )
        .unwrap(),
        ToolExecutionClaimAuthority::from_persisted(
            authority.execution_id().clone(),
            digest(b"substituted process operation"),
            authority.owner_run_id().clone(),
            authority.attempt(),
            authority.executor_fencing_token(),
        )
        .unwrap(),
        ToolExecutionClaimAuthority::from_persisted(
            authority.execution_id().clone(),
            authority.operation_digest().clone(),
            RunId::new("run-2").unwrap(),
            authority.attempt(),
            authority.executor_fencing_token(),
        )
        .unwrap(),
        ToolExecutionClaimAuthority::from_persisted(
            authority.execution_id().clone(),
            authority.operation_digest().clone(),
            authority.owner_run_id().clone(),
            authority.attempt() + 1,
            authority.executor_fencing_token(),
        )
        .unwrap(),
        ToolExecutionClaimAuthority::from_persisted(
            authority.execution_id().clone(),
            authority.operation_digest().clone(),
            authority.owner_run_id().clone(),
            authority.attempt(),
            None,
        )
        .unwrap(),
    ]
}

fn test_binding_error() -> PortError {
    PortError::Failure {
        classification: SafeErrorClassification::Internal,
        retryability: Retryability::NonRetryable,
    }
}

#[test]
fn executable_registry_rejects_path_lookup_version_drift_and_replacement() {
    let root = TempDir::new().unwrap();
    let executable = root.path().join("registered-tool.exe");
    fs::copy(std::env::current_exe().unwrap(), &executable).unwrap();
    let expected_digest = digest(&fs::read(&executable).unwrap());

    assert!(TrustedExecutableRegistration::new(
        "cargo",
        "1.97.1",
        "cargo.exe",
        expected_digest.clone(),
    )
    .is_err());

    let registry = ExecutableRegistry::load(
        vec![TrustedExecutableRegistration::new(
            "cargo",
            "1.97.1",
            &executable,
            expected_digest.clone(),
        )
        .unwrap()],
        Arc::new(WindowsExecutableInspector),
    )
    .unwrap();
    let resolved = registry.resolve("cargo", "1.97.1").unwrap();

    assert_eq!(
        resolved.canonical_path,
        fs::canonicalize(&executable).unwrap()
    );
    assert_eq!(resolved.sha256, expected_digest);
    assert_eq!(resolved.toolchain_id, "cargo");
    assert!(registry.resolve("cargo", "1.98.0").is_err());

    fs::write(&executable, b"attacker replacement").unwrap();
    assert!(registry.verify_and_retain(&resolved).is_err());
}

#[test]
fn private_runtime_cwd_must_be_registered_and_reverified_by_identity() {
    let root = TempDir::new().unwrap();
    let runtime = root.path().join("private-runtime");
    fs::create_dir(&runtime).unwrap();

    assert!(TrustedPrivateRuntimeDirectory::new("agent-runtime", "relative/runtime").is_err());
    let registry = PrivateRuntimeDirectoryRegistry::load(
        vec![TrustedPrivateRuntimeDirectory::new("agent-runtime", &runtime).unwrap()],
        Arc::new(WindowsPrivateRuntimeDirectoryInspector),
    )
    .unwrap();
    assert!(registry.resolve("missing").is_err());
    let resolved = registry.resolve("agent-runtime").unwrap();

    fs::rename(&runtime, root.path().join("original-runtime")).unwrap();
    fs::create_dir(&runtime).unwrap();
    assert!(registry.verify_and_retain(&resolved).is_err());
}

#[test]
fn missing_os_containment_denies_before_child_code_runs() {
    let root = TempDir::new().unwrap();
    let marker = root.path().join("must-not-exist");
    let launcher = WindowsProcessLauncher::fail_closed();
    let request = request(
        vec![],
        BTreeMap::from([
            ("LAT_PROCESS_HELPER".to_owned(), "marker".to_owned()),
            (
                "LAT_PROCESS_MARKER".to_owned(),
                marker.to_string_lossy().into_owned(),
            ),
        ]),
    );

    assert!(launcher.execute(request).is_err());
    assert!(!marker.exists());
}

#[cfg(feature = "test-seams")]
#[test]
fn unrepresentable_cpu_limit_is_rejected_before_boundary_preparation() {
    let root = TempDir::new().unwrap();
    let boundary = Arc::new(TestOnlyBoundary::valid(root.path().to_owned()));
    let prepare_calls = boundary.prepare_calls.clone();
    let launcher =
        WindowsProcessLauncher::with_isolated_worker_boundary(boundary, boundary_binding());
    let mut request = request(Vec::new(), BTreeMap::new());
    request.limits.cpu_time_limit_ms = 9_007_199_254_740_991;

    assert!(launcher.execute(request).is_err());
    assert_eq!(prepare_calls.load(Ordering::Acquire), 0);
}

#[cfg(feature = "test-seams")]
#[test]
fn requested_disk_write_budget_fails_closed_before_child_creation() {
    let root = TempDir::new().unwrap();
    let boundary = Arc::new(TestOnlyBoundary::valid(root.path().to_owned()));
    let prepare_calls = boundary.prepare_calls.clone();
    let launcher =
        WindowsProcessLauncher::with_isolated_worker_boundary(boundary, boundary_binding());
    let mut request = request(Vec::new(), BTreeMap::new());
    request.limits.disk_write_limit_bytes = Some(1);
    let execution_id = request.execution_id.clone();

    let error = launcher.execute(request).unwrap_err();

    assert_eq!(
        error.safe_classification(),
        local_agent_terminal_application::SafeErrorClassification::Unavailable
    );
    assert_eq!(prepare_calls.load(Ordering::Acquire), 0);
    assert_eq!(
        lpac_lifecycle_counts_for_test(&execution_id),
        LpacLifecycleCountsForTest::default()
    );
}

#[cfg(feature = "test-seams")]
#[test]
fn cancellation_during_boundary_preparation_is_retained_without_creating_a_child() {
    let root = TempDir::new().unwrap();
    let marker = root.path().join("pending-cancel-must-not-run");
    let (prepare_block, prepare_entered, release_prepare) = BoundaryBlock::new();
    let mut boundary = TestOnlyBoundary::valid(root.path().to_owned());
    boundary.prepare_block = Some(prepare_block);
    let cleanup_count = boundary.cleanup_count.clone();
    let launcher = Arc::new(WindowsProcessLauncher::with_isolated_worker_boundary(
        Arc::new(boundary),
        boundary_binding(),
    ));
    let request = lpac_marker_request("execution-pending-cancel", &marker);
    let retry_request = request.clone();
    let execution_id = request.execution_id.clone();
    let executing = Arc::clone(&launcher);
    let execution = thread::spawn(move || executing.execute(request));

    prepare_entered
        .recv_timeout(Duration::from_secs(5))
        .expect("boundary preparation must reach the deterministic block");
    let cancellation = launcher.cancel(&execution_id);
    release_prepare.send(()).unwrap();
    let cancellation = cancellation.expect("pending cancellation must be retained");

    assert_eq!(cancellation.execution_id, execution_id);
    assert_eq!(cancellation.status, ProcessStatus::Terminated);
    assert!(cancellation.cancelled);
    assert_eq!(cancellation.job_receipt, None);
    let error = execution
        .join()
        .unwrap()
        .expect_err("the retained cancellation must stop execution");
    assert_eq!(
        error.safe_classification(),
        local_agent_terminal_application::SafeErrorClassification::PermissionDenied
    );
    assert_eq!(
        error.retryability(),
        local_agent_terminal_application::Retryability::NonRetryable
    );
    assert_eq!(
        lpac_lifecycle_counts_for_test(&execution_id),
        LpacLifecycleCountsForTest::default()
    );
    assert_eq!(output_reader_counts_for_test(&execution_id), (0, 0));
    assert_eq!(cleanup_count.load(Ordering::Acquire), 1);
    assert!(!marker.exists());

    let receipt = launcher
        .execute(retry_request)
        .expect("the execution ID must be reusable after cleanup");
    assert_eq!(receipt.status, ProcessStatus::Exited);
    assert!(marker.exists());
    assert_eq!(cleanup_count.load(Ordering::Acquire), 2);
    assert_eq!(output_reader_counts_for_test(&execution_id), (2, 2));
}

#[cfg(feature = "test-seams")]
#[test]
fn cancellation_after_suspended_child_creation_prevents_resume_and_returns_job_receipt() {
    let root = TempDir::new().unwrap();
    let marker = root.path().join("active-pre-resume-cancel-must-not-run");
    let (verification_block, verification_entered, release_verification) = BoundaryBlock::new();
    let mut boundary = TestOnlyBoundary::valid(root.path().to_owned());
    boundary.verification_block = Some(verification_block);
    let cleanup_count = boundary.cleanup_count.clone();
    let launcher = Arc::new(WindowsProcessLauncher::with_isolated_worker_boundary(
        Arc::new(boundary),
        boundary_binding(),
    ));
    let request = lpac_marker_request("execution-active-pre-resume-cancel", &marker);
    let retry_request = request.clone();
    let execution_id = request.execution_id.clone();
    let executing = Arc::clone(&launcher);
    let execution = thread::spawn(move || executing.execute(request));

    verification_entered
        .recv_timeout(Duration::from_secs(5))
        .expect("verification must block after suspended-child creation");
    assert_eq!(
        lpac_lifecycle_counts_for_test(&execution_id).suspended_children_created,
        1
    );
    let cancellation = launcher.cancel(&execution_id);
    release_verification.send(()).unwrap();
    let cancellation = cancellation.expect("active pre-resume cancellation must terminate the Job");

    assert_eq!(cancellation.execution_id, execution_id);
    assert_eq!(cancellation.status, ProcessStatus::Terminated);
    assert!(cancellation.cancelled);
    let job_receipt = cancellation
        .job_receipt
        .expect("active cancellation must return authoritative Job evidence");
    assert!(job_receipt.kill_on_close);
    assert!(job_receipt.no_breakaway);
    assert!(job_receipt.tree_terminated);
    let error = execution
        .join()
        .unwrap()
        .expect_err("cancelled suspended child must not resume");
    assert_eq!(
        error.safe_classification(),
        local_agent_terminal_application::SafeErrorClassification::PermissionDenied
    );
    let lifecycle = lpac_lifecycle_counts_for_test(&execution_id);
    assert_eq!(lifecycle.suspended_children_created, 1);
    assert_eq!(lifecycle.resumes_succeeded, 0);
    assert_eq!(output_reader_counts_for_test(&execution_id), (2, 2));
    assert_eq!(cleanup_count.load(Ordering::Acquire), 1);
    assert!(!marker.exists());
    assert!(launcher.cancel(&execution_id).is_err());

    let receipt = launcher
        .execute(retry_request)
        .expect("the execution ID must be reusable after active cleanup");
    assert_eq!(receipt.status, ProcessStatus::Exited);
    assert!(marker.exists());
    let lifecycle = lpac_lifecycle_counts_for_test(&execution_id);
    assert_eq!(lifecycle.suspended_children_created, 2);
    assert_eq!(lifecycle.resumes_succeeded, 1);
    assert_eq!(cleanup_count.load(Ordering::Acquire), 2);
    assert_eq!(output_reader_counts_for_test(&execution_id), (4, 4));
}

#[cfg(feature = "test-seams")]
#[test]
fn pre_resume_cancellation_cleanup_retries_before_joining_output_readers() {
    let _cleanup_failure_test = JOB_CLEANUP_FAILURE_TEST_LOCK.lock().unwrap();
    for (point, execution_name) in [
        (
            JobCleanupFailurePointForTest::Terminate,
            "execution-pre-resume-terminate-retry",
        ),
        (
            JobCleanupFailurePointForTest::TreeWait,
            "execution-pre-resume-tree-wait-retry",
        ),
    ] {
        let root = TempDir::new().unwrap();
        let marker = root.path().join(format!("{execution_name}-must-not-run"));
        let retry_marker = root.path().join(format!("{execution_name}-retry"));
        let (verification_block, verification_entered, release_verification) = BoundaryBlock::new();
        let mut boundary = TestOnlyBoundary::valid(root.path().to_owned());
        boundary.verification_block = Some(verification_block);
        let cleanup_count = boundary.cleanup_count.clone();
        let leases = Arc::new(ReplaceableLeaseStore::new(7));
        let authority =
            ProcessFenceAuthority::new(leases, Arc::new(WorkspaceWriteCoordinator::new()));
        let launcher = Arc::new(WindowsProcessLauncher::with_isolated_worker_boundary(
            Arc::new(boundary),
            boundary_binding(),
        ));
        let mut request = lpac_marker_request(execution_name, &marker);
        request.executor_fence = authority.binding();
        let execution_id = request.execution_id.clone();
        let retry_request = lpac_marker_request(execution_name, &retry_marker);
        let cleanup_failure = block_next_job_cleanup_failure_for_test(execution_id.clone(), point);
        let executing = Arc::clone(&launcher);
        let execution = thread::spawn(move || executing.execute(request));

        verification_entered
            .recv_timeout(Duration::from_secs(5))
            .expect("verification must block after suspended-child creation");
        let cancelling = Arc::clone(&launcher);
        let cancelled_execution_id = execution_id.clone();
        let cancellation = thread::spawn(move || cancelling.cancel(&cancelled_execution_id));
        let first_attempt_observed = cleanup_failure.wait_for_attempt(1, Duration::from_secs(5));
        cleanup_failure.fail_current_attempt();
        let first_cancellation = cancellation.join().unwrap();
        release_verification.send(()).unwrap();

        let execution_cleanup_retried = cleanup_failure.wait_for_attempt(2, Duration::from_secs(5));
        let boundary_held_until_retry = cleanup_count.load(Ordering::Acquire) == 0;
        let (mutation_started_tx, mutation_started_rx) = mpsc::channel();
        let (mutation_tx, mutation_rx) = mpsc::channel();
        let mutating_authority = authority.clone();
        let mutation = thread::spawn(move || {
            mutation_started_tx.send(()).unwrap();
            let result = mutating_authority.revoke_lease(RevokeLease {
                claim: LeaseClaim::new(
                    TaskId::new("task-1").unwrap(),
                    RunId::new("run-1").unwrap(),
                    FencingToken::new(7).unwrap(),
                ),
                revoked_at: "2026-07-30T00:30:00Z".to_owned(),
            });
            mutation_tx.send(result).unwrap();
        });
        mutation_started_rx
            .recv_timeout(Duration::from_secs(5))
            .unwrap();
        let fence_held_until_retry = matches!(
            mutation_rx.recv_timeout(Duration::from_millis(100)),
            Err(mpsc::RecvTimeoutError::Timeout)
        );

        cleanup_failure.allow_cleanup();
        let rescue_cancellation =
            (!execution_cleanup_retried).then(|| launcher.cancel(&execution_id));
        let execution_result = execution.join().unwrap();
        let mutation_result = mutation_rx.recv_timeout(Duration::from_secs(5));
        mutation.join().unwrap();

        assert!(first_attempt_observed);
        assert!(first_cancellation.is_err());
        assert!(execution_cleanup_retried);
        assert!(boundary_held_until_retry);
        assert!(fence_held_until_retry);
        assert!(rescue_cancellation.is_none());
        assert!(execution_result.is_err());
        assert!(mutation_result.unwrap().is_ok());
        let lifecycle = lpac_lifecycle_counts_for_test(&execution_id);
        assert_eq!(lifecycle.suspended_children_created, 1);
        assert_eq!(lifecycle.resumes_succeeded, 0);
        assert_eq!(output_reader_counts_for_test(&execution_id), (2, 2));
        assert_eq!(cleanup_count.load(Ordering::Acquire), 1);
        assert!(!marker.exists());
        assert!(launcher.cancel(&execution_id).is_err());

        let receipt = launcher
            .execute(retry_request)
            .expect("the execution ID must be reusable after cleanup retry");
        assert_eq!(receipt.status, ProcessStatus::Exited);
        assert!(retry_marker.exists());
        assert_eq!(cleanup_count.load(Ordering::Acquire), 2);
        assert_eq!(output_reader_counts_for_test(&execution_id), (4, 4));
    }
}

#[cfg(feature = "test-seams")]
#[test]
fn concurrent_pre_resume_termination_waits_for_in_flight_attempt() {
    let _cleanup_failure_test = JOB_CLEANUP_FAILURE_TEST_LOCK.lock().unwrap();
    let root = TempDir::new().unwrap();
    let marker = root.path().join("overlapping-termination-must-not-run");
    let retry_marker = root.path().join("overlapping-termination-retry");
    let (verification_block, verification_entered, release_verification) = BoundaryBlock::new();
    let mut boundary = TestOnlyBoundary::valid(root.path().to_owned());
    boundary.verification_block = Some(verification_block);
    let cleanup_count = boundary.cleanup_count.clone();
    let leases = Arc::new(ReplaceableLeaseStore::new(7));
    let authority = ProcessFenceAuthority::new(leases, Arc::new(WorkspaceWriteCoordinator::new()));
    let launcher = Arc::new(WindowsProcessLauncher::with_isolated_worker_boundary(
        Arc::new(boundary),
        boundary_binding(),
    ));
    let mut request = lpac_marker_request("execution-overlapping-termination", &marker);
    request.executor_fence = authority.binding();
    let execution_id = request.execution_id.clone();
    let retry_request = lpac_marker_request("execution-overlapping-termination", &retry_marker);
    let cleanup_failure = block_next_job_cleanup_failure_for_test(
        execution_id.clone(),
        JobCleanupFailurePointForTest::Terminate,
    );
    let executing = Arc::clone(&launcher);
    let execution = thread::spawn(move || executing.execute(request));

    verification_entered
        .recv_timeout(Duration::from_secs(5))
        .expect("verification must block after suspended-child creation");
    let cancelling = Arc::clone(&launcher);
    let cancelled_execution_id = execution_id.clone();
    let (cancellation_tx, cancellation_rx) = mpsc::channel();
    let cancellation = thread::spawn(move || {
        cancellation_tx
            .send(cancelling.cancel(&cancelled_execution_id))
            .unwrap();
    });
    let first_attempt_observed = cleanup_failure.wait_for_attempt(1, Duration::from_secs(5));
    release_verification.send(()).unwrap();
    let second_entry_observed = cleanup_failure.wait_for_entry(2, Duration::from_secs(5));
    let cleanup_attempts_overlapped =
        second_entry_observed && cleanup_failure.wait_for_attempt(2, Duration::from_millis(100));
    cleanup_failure.fail_current_attempt();
    let first_cancellation_before_retry = if cleanup_attempts_overlapped {
        None
    } else {
        cancellation_rx.recv_timeout(Duration::from_secs(5)).ok()
    };
    let execution_cleanup_retried = !cleanup_attempts_overlapped
        && first_cancellation_before_retry.is_some()
        && cleanup_failure.wait_for_attempt(2, Duration::from_secs(5));
    let boundary_held_until_retry = cleanup_count.load(Ordering::Acquire) == 0;
    let (mutation_started_tx, mutation_started_rx) = mpsc::channel();
    let (mutation_tx, mutation_rx) = mpsc::channel();
    let mutating_authority = authority.clone();
    let mutation = thread::spawn(move || {
        mutation_started_tx.send(()).unwrap();
        let result = mutating_authority.revoke_lease(RevokeLease {
            claim: LeaseClaim::new(
                TaskId::new("task-1").unwrap(),
                RunId::new("run-1").unwrap(),
                FencingToken::new(7).unwrap(),
            ),
            revoked_at: "2026-07-30T00:30:00Z".to_owned(),
        });
        mutation_tx.send(result).unwrap();
    });
    mutation_started_rx
        .recv_timeout(Duration::from_secs(5))
        .unwrap();
    let fence_held_until_retry = matches!(
        mutation_rx.recv_timeout(Duration::from_millis(100)),
        Err(mpsc::RecvTimeoutError::Timeout)
    );

    cleanup_failure.allow_cleanup();
    let rescue_cancellation = (cleanup_attempts_overlapped || !execution_cleanup_retried)
        .then(|| launcher.cancel(&execution_id));
    let first_cancellation = first_cancellation_before_retry
        .or_else(|| cancellation_rx.recv_timeout(Duration::from_secs(5)).ok());
    cancellation.join().unwrap();
    let execution_result = execution.join().unwrap();
    let mutation_result = mutation_rx.recv_timeout(Duration::from_secs(5));
    mutation.join().unwrap();

    assert!(first_attempt_observed);
    assert!(second_entry_observed);
    assert!(!cleanup_attempts_overlapped);
    assert!(first_cancellation.is_some_and(|result| result.is_err()));
    assert!(execution_cleanup_retried);
    assert!(boundary_held_until_retry);
    assert!(fence_held_until_retry);
    assert!(rescue_cancellation.is_none());
    assert!(execution_result.is_err());
    assert!(mutation_result.unwrap().is_ok());
    let lifecycle = lpac_lifecycle_counts_for_test(&execution_id);
    assert_eq!(lifecycle.suspended_children_created, 1);
    assert_eq!(lifecycle.resumes_succeeded, 0);
    assert_eq!(output_reader_counts_for_test(&execution_id), (2, 2));
    assert_eq!(cleanup_count.load(Ordering::Acquire), 1);
    assert!(!marker.exists());
    assert!(launcher.cancel(&execution_id).is_err());

    let receipt = launcher
        .execute(retry_request)
        .expect("the execution ID must be reusable after serialized termination");
    assert_eq!(receipt.status, ProcessStatus::Exited);
    assert!(retry_marker.exists());
    assert_eq!(cleanup_count.load(Ordering::Acquire), 2);
    assert_eq!(output_reader_counts_for_test(&execution_id), (4, 4));
}

#[cfg(feature = "test-seams")]
#[test]
fn output_reader_start_failure_never_resumes_or_leaves_an_active_job() {
    let root = TempDir::new().unwrap();
    let marker = root.path().join("must-not-run-after-reader-failure");
    let boundary = Arc::new(TestOnlyBoundary::valid(root.path().to_owned()));
    let launcher =
        WindowsProcessLauncher::with_isolated_worker_boundary(boundary, boundary_binding());
    let mut request = request(
        vec![
            "--exact".to_owned(),
            "process_child_helper".to_owned(),
            "--nocapture".to_owned(),
        ],
        BTreeMap::from([
            ("LAT_PROCESS_HELPER".to_owned(), "marker".to_owned()),
            (
                "LAT_PROCESS_MARKER".to_owned(),
                marker.to_string_lossy().into_owned(),
            ),
        ]),
    );
    request.execution_id = ToolExecutionId::new("execution-reader-failure").unwrap();
    let execution_id = request.execution_id.clone();
    fail_next_output_reader_start_for_test(execution_id.clone());

    assert!(launcher.execute(request).is_err());
    thread::sleep(Duration::from_millis(100));
    assert!(!marker.exists());
    assert!(launcher.cancel(&execution_id).is_err());
}

#[cfg(feature = "test-seams")]
#[test]
fn process_binding_failure_never_resumes_and_releases_the_execution_id() {
    let root = TempDir::new().unwrap();
    let marker = root.path().join("must-not-run-before-binding");
    let retry_marker = root.path().join("binding-failure-retry");
    let boundary = Arc::new(TestOnlyBoundary::valid(root.path().to_owned()));
    let launcher =
        WindowsProcessLauncher::with_isolated_worker_boundary(boundary, boundary_binding());
    let request = lpac_marker_request("execution-binding-failure", &marker);
    let execution_id = request.execution_id.clone();
    let authority = claimed_authority(&request);
    let bindings = TestProcessBindings::rejecting(authority.clone());

    local_agent_terminal_application::ProcessLauncher::execute(
        &launcher, request, &authority, &bindings,
    )
    .expect_err("a durable binding failure must abort the suspended child");

    assert_eq!(
        lpac_lifecycle_counts_for_test(&execution_id).resumes_succeeded,
        0
    );
    assert!(!marker.exists());
    assert!(launcher.cancel(&execution_id).is_err());

    let receipt = launcher
        .execute(lpac_marker_request(
            "execution-binding-failure",
            &retry_marker,
        ))
        .expect("the execution ID must be reusable after binding cleanup");
    assert_eq!(receipt.status, ProcessStatus::Exited);
    assert!(retry_marker.exists());
}

#[cfg(feature = "test-seams")]
#[test]
fn verified_boundary_runs_in_a_real_kill_on_close_job_and_captures_output() {
    let root = TempDir::new().unwrap();
    let boundary = Arc::new(TestOnlyBoundary::valid(root.path().to_owned()));
    let launcher =
        WindowsProcessLauncher::with_isolated_worker_boundary(boundary, boundary_binding());
    let request = request(
        vec![
            "--exact".to_owned(),
            "process_child_helper".to_owned(),
            "--nocapture".to_owned(),
        ],
        BTreeMap::from([("LAT_PROCESS_HELPER".to_owned(), "emit".to_owned())]),
    );
    let receipt = launcher.execute(request).unwrap();

    assert_eq!(receipt.status, ProcessStatus::Exited);
    assert_eq!(receipt.exit_code, Some(0));
    assert!(!receipt.stdout.truncated);
    assert!(String::from_utf8_lossy(&receipt.stdout.bytes).contains("literal ;&|$()"));
    assert!(receipt.job_receipt.kill_on_close);
    assert!(receipt.job_receipt.no_breakaway);
}

#[cfg(feature = "test-seams")]
#[test]
fn job_termination_exit_code_without_termination_is_reported_as_exited() {
    let root = TempDir::new().unwrap();
    let boundary = Arc::new(TestOnlyBoundary::valid(root.path().to_owned()));
    let launcher =
        WindowsProcessLauncher::with_isolated_worker_boundary(boundary, boundary_binding());
    let mut request = request(
        vec![
            "--exact".to_owned(),
            "process_child_helper".to_owned(),
            "--nocapture".to_owned(),
        ],
        BTreeMap::from([(
            "LAT_PROCESS_HELPER".to_owned(),
            "exit-job-termination-code".to_owned(),
        )]),
    );
    request.execution_id = ToolExecutionId::new("execution-nonzero-exit").unwrap();

    let receipt = launcher.execute(request).unwrap();

    assert_eq!(receipt.status, ProcessStatus::Exited);
    assert_eq!(receipt.exit_code, Some(0xC000_013Au32 as i32));
}

#[test]
fn real_lpac_child_reports_less_privileged_appcontainer_identity() {
    let root = TempDir::new().unwrap();
    let launcher = registered_lpac_launcher(root.path());
    let mut request = request(
        vec![
            "--exact".to_owned(),
            "process_child_helper".to_owned(),
            "--nocapture".to_owned(),
        ],
        lpac_identity_environment(),
    );
    request.execution_id = ToolExecutionId::new("execution-lpac-identity").unwrap();
    let execution_id = request.execution_id.clone();

    let receipt = launcher.execute(request).unwrap();
    let stdout = String::from_utf8(receipt.stdout.bytes).unwrap();
    let stderr = String::from_utf8(receipt.stderr.bytes).unwrap();

    assert_eq!(receipt.status, ProcessStatus::Exited);
    assert_eq!(receipt.exit_code, Some(0), "stderr={stderr:?}");
    assert!(receipt.job_receipt.kill_on_close);
    assert!(receipt.job_receipt.no_breakaway);

    assert!(stderr.is_empty(), "stderr={stderr:?}");
    assert!(stdout.lines().any(|line| line == "appcontainer=1"));
    assert!(stdout.lines().any(|line| line == "capabilities=0"));
    assert!(stdout.lines().any(|line| line == "reserved-env=valid"));
    assert!(stdout.lines().any(|line| line == "cwd-root-readable=1"));
    #[cfg(feature = "test-seams")]
    assert_eq!(
        lpac_lifecycle_counts_for_test(&execution_id),
        LpacLifecycleCountsForTest {
            profiles_created: 1,
            profiles_deleted: 1,
            acl_grants: 2,
            acl_revokes: 2,
            suspended_children_created: 1,
            resumes_succeeded: 1,
            last_windows_error: None,
        }
    );
    #[cfg(not(feature = "test-seams"))]
    let _ = execution_id;
}

#[test]
fn real_lpac_denies_registered_descendant_creation_modes() {
    let root = TempDir::new().unwrap();
    let launcher = registered_lpac_launcher(root.path());
    let mut request = request(
        vec![
            "--exact".to_owned(),
            "process_child_helper".to_owned(),
            "--nocapture".to_owned(),
        ],
        BTreeMap::from([(
            "LAT_PROCESS_HELPER".to_owned(),
            "lpac-descendant-denial".to_owned(),
        )]),
    );
    request.execution_id = ToolExecutionId::new("execution-lpac-descendant-denial").unwrap();
    request.timeout_ms = 2_000;
    request.limits.max_active_processes = 1;
    let execution_id = request.execution_id.clone();

    let receipt = launcher.execute(request).unwrap();
    let stderr = String::from_utf8(receipt.stderr.bytes).unwrap();
    let observed = stderr
        .lines()
        .filter_map(|line| line.strip_prefix("d2d-descendant-"))
        .collect::<BTreeSet<_>>();
    assert_eq!(observed.len(), 4);
    assert!(observed.contains("attempts=complete"));
    assert!(observed.contains("breakaway=access-denied"));
    for allowed in [
        ["ordinary=process-limit-denied", "ordinary=access-denied"],
        [
            "detached-new-process-group=process-limit-denied",
            "detached-new-process-group=access-denied",
        ],
    ] {
        assert!(
            allowed.iter().any(|result| observed.contains(result)),
            "unexpected descendant result: {observed:?}",
        );
    }
    assert_eq!(receipt.status, ProcessStatus::Terminated);
    assert_eq!(receipt.exit_code, None);
    assert!(!receipt.stderr.truncated);
    assert_ne!(receipt.job_receipt.root_pid, 0);
    assert!(receipt.job_receipt.kill_on_close);
    assert!(receipt.job_receipt.no_breakaway);
    assert_eq!(receipt.job_receipt.max_active_processes, 1);
    assert!(!receipt.job_receipt.resource_limit_terminated);
    assert!(receipt.job_receipt.tree_terminated);
    assert_real_lpac_lifecycle(&execution_id);
}

#[test]
fn lpac_rejects_registered_root_named_stream_before_any_side_effect() {
    let container = TempDir::new().unwrap();
    let root = container.path().join("registered-root");
    fs::create_dir(&root).unwrap();
    let mut stream = root.as_os_str().to_os_string();
    stream.push(":hidden");
    let stream = PathBuf::from(stream);
    fs::write(&stream, b"hidden root stream").unwrap();
    assert_eq!(fs::read(&stream).unwrap(), b"hidden root stream");
    assert!(fs::read_dir(&root).unwrap().next().is_none());

    let launcher = registered_lpac_launcher(&root);
    let marker = container.path().join("root-stream-child-marker");
    let request = lpac_marker_request("execution-root-named-stream", &marker);
    let execution_id = request.execution_id.clone();

    launcher
        .execute(request)
        .expect_err("a registered root with a named stream must fail before launch");
    assert!(!marker.exists());
    #[cfg(feature = "test-seams")]
    assert_eq!(
        lpac_lifecycle_counts_for_test(&execution_id),
        LpacLifecycleCountsForTest::default()
    );
    #[cfg(not(feature = "test-seams"))]
    let _ = execution_id;
}

#[test]
fn lpac_rejects_registered_executable_named_stream_before_any_side_effect() {
    let container = TempDir::new().unwrap();
    let root = container.path().join("registered-root");
    fs::create_dir(&root).unwrap();
    let executable = container.path().join("registered-helper.exe");
    fs::copy(std::env::current_exe().unwrap(), &executable).unwrap();
    let executable_digest = digest(&fs::read(&executable).unwrap());
    let registry = ExecutableRegistry::load(
        vec![TrustedExecutableRegistration::new(
            "stream-helper",
            "test-version",
            &executable,
            executable_digest,
        )
        .unwrap()],
        Arc::new(WindowsExecutableInspector),
    )
    .unwrap();
    let mut stream = executable.as_os_str().to_os_string();
    stream.push(":hidden");
    let stream = PathBuf::from(stream);
    fs::write(&stream, b"hidden executable stream").unwrap();
    assert_eq!(fs::read(&stream).unwrap(), b"hidden executable stream");

    let launcher = registered_lpac_launcher(&root);
    let mut request = request(
        vec![
            "--exact".to_owned(),
            "process_child_helper".to_owned(),
            "--nocapture".to_owned(),
        ],
        BTreeMap::from([("LAT_PROCESS_HELPER".to_owned(), "emit".to_owned())]),
    );
    request.execution_id = ToolExecutionId::new("execution-executable-named-stream").unwrap();
    request.executable = registry.resolve("stream-helper", "test-version").unwrap();
    let execution_id = request.execution_id.clone();

    launcher
        .execute(request)
        .expect_err("a registered executable with a named stream must fail before launch");
    #[cfg(feature = "test-seams")]
    assert_eq!(
        lpac_lifecycle_counts_for_test(&execution_id),
        LpacLifecycleCountsForTest::default()
    );
    #[cfg(not(feature = "test-seams"))]
    let _ = execution_id;
}

#[test]
fn real_lpac_denies_filesystem_path_environment_and_network_hostile_matrix() {
    let container = TempDir::new().unwrap();
    let root = container.path().join("registered-root");
    let sibling = container.path().join("unregistered-sibling");
    fs::create_dir(&root).unwrap();
    fs::create_dir(&sibling).unwrap();

    let repository_root =
        fs::canonicalize(Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")).unwrap();
    let repository_fixture_root = repository_root.join("target/task7-fixtures");
    fs::create_dir_all(&repository_fixture_root).unwrap();
    let repository_owner = TempDir::new_in(repository_fixture_root).unwrap();
    let original_owner = TempDir::new_in(&repository_root).unwrap();
    let user_profile = PathBuf::from(std::env::var_os("USERPROFILE").unwrap());
    let user_profile_owner = TempDir::new_in(user_profile).unwrap();
    let application_data = PathBuf::from(std::env::var_os("LOCALAPPDATA").unwrap());
    let application_data_owner = TempDir::new_in(application_data).unwrap();
    let capability_adjacent = container.path().join("capability-adjacent");
    fs::create_dir(&capability_adjacent).unwrap();
    let canaries = [
        DeniedCanary::new("repository", repository_owner.path()),
        DeniedCanary::new("original", original_owner.path()),
        DeniedCanary::new("sibling", &sibling),
        DeniedCanary::new("profile", user_profile_owner.path()),
        DeniedCanary::new("appdata", application_data_owner.path()),
        DeniedCanary::new("capability", &capability_adjacent),
    ];
    let original_snapshot = ["Cargo.toml", ".git/HEAD", ".git/index"]
        .map(|path| fs::read(repository_root.join(path)).unwrap());
    let registry = RegistryFixture::new();
    let mut credentials = CredentialFixture::new();
    let pipe = NamedPipeFixture::new();
    pipe.prove_parent_connections();
    let child_pipe_read_server = pipe.server(&pipe.read_name);
    let child_pipe_write_server = pipe.server(&pipe.write_name);

    let junction = container.path().join("junction-escape");
    create_junction(repository_owner.path(), &junction);
    let junction_path = junction.join(canaries[0].read.file_name().unwrap());
    let symlink = container.path().join("symlink-escape");
    let (symlink_label, symlink_path) =
        match std::os::windows::fs::symlink_file(&canaries[0].read, &symlink) {
            Ok(()) => ("symlink", symlink),
            Err(error) if error.raw_os_error() == Some(1_314) => {
                create_junction(repository_owner.path(), &symlink);
                (
                    "symlink-junction-fallback",
                    symlink.join(canaries[0].read.file_name().unwrap()),
                )
            }
            Err(error) => panic!("unable to create symlink control: {error}"),
        };
    let unc_path = localhost_admin_share_path(&canaries[0].read);
    let extended_path = extended_length_path(&canaries[0].read);
    let case_folded_path = canaries[0]
        .read
        .parent()
        .unwrap()
        .join("REPOSITORY-READ.BIN");
    let unicode_path = repository_owner.path().join("canary-測試-🧪.bin");
    fs::hard_link(&canaries[0].read, &unicode_path).unwrap();
    let mut long_directory = repository_owner.path().join("long-path");
    for index in 0..6 {
        long_directory.push(format!("segment-{index}-{}", "x".repeat(48)));
    }
    fs::create_dir_all(&long_directory).unwrap();
    let long_path = long_directory.join("repository-read-hardlink.bin");
    fs::hard_link(&canaries[0].read, &long_path).unwrap();
    assert!(long_path.as_os_str().len() > 260);
    let alternate_stream_path = named_stream_path(&canaries[0].read, "hostile");
    fs::write(&alternate_stream_path, b"alternate stream canary").unwrap();
    let replacement_path = repository_owner.path().join("replacement-escape.bin");
    fs::hard_link(&canaries[0].read, &replacement_path).unwrap();
    let path_variants = [
        ("junction", junction_path),
        (symlink_label, symlink_path),
        ("unc", unc_path),
        ("device", extended_path),
        ("ads", alternate_stream_path),
        ("casefold", case_folded_path),
        ("unicode", unicode_path),
        ("long", long_path),
        ("replacement", replacement_path),
    ];
    for (_, path) in &path_variants {
        assert!(
            fs::read(path).is_ok(),
            "parent path control failed for {}",
            path.display()
        );
    }

    let loopback_listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let lan_ip = host_lan_ip();
    let lan_listener = TcpListener::bind(SocketAddr::new(lan_ip, 0)).unwrap();
    prove_parent_connection(&loopback_listener);
    prove_parent_connection(&lan_listener);

    assert!(std::env::var_os("PATH").is_some());
    assert!(std::env::var_os("USERPROFILE").is_some());
    assert!(std::env::var_os("APPDATA").is_some());
    let _environment_guards = [
        EnvironmentVariableGuard::set("LAT_M2_PARENT_SECRET", "must-not-cross"),
        EnvironmentVariableGuard::set("AWS_ACCESS_KEY_ID", "must-not-cross"),
        EnvironmentVariableGuard::set("AZURE_CLIENT_SECRET", "must-not-cross"),
        EnvironmentVariableGuard::set("GITHUB_TOKEN", "must-not-cross"),
        EnvironmentVariableGuard::set("OPENAI_API_KEY", "must-not-cross"),
    ];
    let mut environment = BTreeMap::from([
        (
            "LAT_M2_LOOPBACK".to_owned(),
            loopback_listener.local_addr().unwrap().to_string(),
        ),
        (
            "LAT_M2_LAN".to_owned(),
            lan_listener.local_addr().unwrap().to_string(),
        ),
        ("LAT_M2_INTERNET".to_owned(), "1.1.1.1:443".to_owned()),
        ("LAT_M2_REGISTRY_KEY".to_owned(), registry.subkey.clone()),
        (
            "LAT_M2_CREDENTIAL_PARENT".to_owned(),
            credentials.parent_target.clone(),
        ),
        (
            "LAT_M2_CREDENTIAL_CHILD".to_owned(),
            credentials.child_target.clone(),
        ),
        (
            "LAT_M2_CREDENTIAL_FILTER".to_owned(),
            credentials.filter.clone(),
        ),
        ("LAT_M2_PIPE_READ".to_owned(), pipe.read_name.clone()),
        ("LAT_M2_PIPE_WRITE".to_owned(), pipe.write_name.clone()),
    ]);
    for (index, canary) in canaries.iter().enumerate() {
        environment.insert(format!("LAT_M2_READ_{index}"), path_text(&canary.read));
        environment.insert(format!("LAT_M2_WRITE_{index}"), path_text(&canary.write));
    }
    for (index, (_, path)) in path_variants.iter().enumerate() {
        environment.insert(format!("LAT_M2_PATH_{index}"), path_text(path));
    }
    environment.insert(
        "LAT_M2_SYMLINK_CONTROL".to_owned(),
        symlink_label.to_owned(),
    );

    let launcher = registered_lpac_launcher(&root);
    let mut request = request(Vec::new(), environment);
    request.executable = registered_executable(
        "m2-containment-probe",
        "m2-v1",
        &containment_probe_executable(),
    );
    request.execution_id = ToolExecutionId::new("execution-lpac-hostile-d2a").unwrap();
    request.timeout_ms = 8_000;
    let execution_id = request.execution_id.clone();

    let receipt = launcher.execute(request).unwrap_or_else(|error| {
        #[cfg(feature = "test-seams")]
        panic!(
            "{error:?}; lifecycle={:?}",
            lpac_lifecycle_counts_for_test(&execution_id)
        );
        #[cfg(not(feature = "test-seams"))]
        panic!("{error:?}");
    });
    credentials.observe_child_ownership();
    let stdout = String::from_utf8(receipt.stdout.bytes).unwrap();
    let stderr = String::from_utf8(receipt.stderr.bytes).unwrap();
    let observed = stdout
        .lines()
        .filter_map(|line| line.strip_prefix("m2-"))
        .map(str::to_owned)
        .collect::<BTreeSet<_>>();
    let mut expected = [
        "root-enumerate=success",
        "root-file-create=denied",
        "root-directory-create=denied",
        "root-stream-create=denied",
        "read-repository=denied",
        "write-repository=denied",
        "read-original=denied",
        "write-original=denied",
        "read-sibling=denied",
        "write-sibling=denied",
        "read-profile=denied",
        "write-profile=denied",
        "read-appdata=denied",
        "write-appdata=denied",
        "read-capability=denied",
        "write-capability=denied",
        "path-junction=denied",
        "path-unc=denied",
        "path-device=denied",
        "path-ads=denied",
        "path-casefold=denied",
        "path-unicode=denied",
        "path-long=denied",
        "path-replacement=denied",
        "environment=clean",
        "registry-read=denied",
        "registry-write=denied",
        "credential-read=rpc-invalid-binding",
        "credential-enumerate=rpc-invalid-binding",
        "credential-write=rpc-invalid-binding",
        "pipe-read=not-found",
        "pipe-write=not-found",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect::<BTreeSet<_>>();
    expected.insert(format!("path-{symlink_label}=denied"));
    let observed_without_network = observed
        .iter()
        .filter(|label| !label.starts_with("network-"))
        .cloned()
        .collect::<BTreeSet<_>>();

    assert_eq!(receipt.status, ProcessStatus::Exited);
    assert_eq!(receipt.exit_code, Some(0), "stderr={stderr:?}");
    assert_eq!(
        observed_without_network, expected,
        "stdout={stdout:?}; stderr={stderr:?}"
    );
    assert_exact_lpac_network_denial(&network_observations(&stdout));
    assert!(stderr.is_empty(), "stderr={stderr:?}");
    assert!(fs::read_dir(&root).unwrap().next().is_none());
    assert!(fs::read(named_stream_path(&root, "d2a-created-stream")).is_err());
    for canary in &canaries {
        canary.assert_unchanged();
        assert!(!stdout.contains(&path_text(&canary.read)));
        assert!(!stdout.contains(&path_text(&canary.write)));
        assert!(!stdout.contains(std::str::from_utf8(&canary.read_contents).unwrap()));
        assert!(!stdout.contains(std::str::from_utf8(&canary.write_contents).unwrap()));
    }
    for (_, path) in &path_variants {
        assert!(!stdout.contains(&path_text(path)));
    }
    for (index, path) in ["Cargo.toml", ".git/HEAD", ".git/index"].iter().enumerate() {
        assert_eq!(
            fs::read(repository_root.join(path)).unwrap(),
            original_snapshot[index]
        );
    }
    registry.assert_unchanged();
    assert!(!stdout.contains(&registry.subkey));
    credentials.assert_unchanged();
    assert!(!stdout.contains(&credentials.parent_target));
    assert!(!stdout.contains(&credentials.child_target));
    assert!(!stdout.contains(std::str::from_utf8(CREDENTIAL_BLOB).unwrap()));
    assert!(!child_pipe_read_server.accepted_connection());
    assert!(!child_pipe_write_server.accepted_connection());
    assert!(!stdout.contains(&pipe.read_name));
    assert!(!stdout.contains(&pipe.write_name));
    assert!(!stdout.contains("alternate stream canary"));
    assert_no_pending_connection(&loopback_listener);
    assert_no_pending_connection(&lan_listener);
    #[cfg(feature = "test-seams")]
    assert_eq!(
        lpac_lifecycle_counts_for_test(&execution_id),
        LpacLifecycleCountsForTest {
            profiles_created: 1,
            profiles_deleted: 1,
            acl_grants: 2,
            acl_revokes: 2,
            suspended_children_created: 1,
            resumes_succeeded: 1,
            last_windows_error: None,
        }
    );
    #[cfg(not(feature = "test-seams"))]
    let _ = execution_id;
    registry.cleanup();
    credentials.cleanup();
    pipe.cleanup(child_pipe_read_server, child_pipe_write_server);
}

#[test]
fn named_pipe_fixture_uses_local_namespace_parent_only_dacl_and_minimal_accesses() {
    let pipe = NamedPipeFixture::new();

    assert!(pipe.read_name.starts_with(r"\\.\pipe\LOCAL\"));
    assert!(pipe.write_name.starts_with(r"\\.\pipe\LOCAL\"));
    assert_ne!(pipe.read_name, pipe.write_name);
    let server = pipe.server(&pipe.read_name);
    assert_eq!(
        server.allowed_sid_strings(),
        vec![current_user_sid_string()]
    );
    drop(server);
    pipe.prove_parent_connections();
}

#[test]
fn credential_fixture_preserves_preexisting_parent_and_child_targets() {
    for suffix in ["parent", "child"] {
        let nonce = credential_nonce();
        let target = format!("LocalAgentTerminal/Task7/{nonce}/{suffix}");
        let stale = OwnedTestCredential::new(target.clone(), b"preexisting inert blob");

        let construction = CredentialFixture::try_new_with_nonce(&nonce);

        assert!(
            matches!(construction, Err(ERROR_ALREADY_EXISTS)),
            "{suffix}"
        );
        assert_eq!(
            read_credential(&target).unwrap(),
            b"preexisting inert blob",
            "{suffix}"
        );
        stale.cleanup();
    }
}
