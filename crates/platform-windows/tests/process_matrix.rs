#![cfg(windows)]

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
use std::sync::Arc;
#[cfg(feature = "test-seams")]
use std::sync::Mutex;
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
    ERROR_FILE_NOT_FOUND, ERROR_INSUFFICIENT_BUFFER, ERROR_INVALID_FUNCTION, ERROR_NOT_FOUND,
    ERROR_NOT_SUPPORTED, ERROR_NOT_SUPPORTED_IN_APPCONTAINER, ERROR_NO_SUCH_LOGON_SESSION,
    ERROR_PIPE_CONNECTED, ERROR_PIPE_LISTENING, ERROR_SUCCESS, FILETIME, GENERIC_READ,
    GENERIC_WRITE, INVALID_HANDLE_VALUE, WAIT_OBJECT_0,
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
    let execution_id = request.execution_id.clone();

    let receipt = launcher.execute(request).unwrap();
    let stderr = String::from_utf8(receipt.stderr.bytes).unwrap();
    let observed = stderr
        .lines()
        .filter_map(|line| line.strip_prefix("d2d-descendant-"))
        .collect::<BTreeSet<_>>();
    let expected = BTreeSet::from([
        "ordinary=access-denied",
        "detached-new-process-group=access-denied",
        "breakaway=access-denied",
        "attempts=complete",
    ]);

    assert_eq!(observed, expected);
    assert_eq!(receipt.status, ProcessStatus::Terminated);
    assert_eq!(receipt.exit_code, None);
    assert!(!receipt.stderr.truncated);
    assert_ne!(receipt.job_receipt.root_pid, 0);
    assert!(receipt.job_receipt.kill_on_close);
    assert!(receipt.job_receipt.no_breakaway);
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
    let user_profile = PathBuf::from(std::env::var_os("USERPROFILE").unwrap());
    let user_profile_owner = TempDir::new_in(user_profile).unwrap();
    let application_data = PathBuf::from(std::env::var_os("LOCALAPPDATA").unwrap());
    let application_data_owner = TempDir::new_in(application_data).unwrap();
    let canaries = [
        DeniedCanary::new("repository", repository_owner.path()),
        DeniedCanary::new("profile", user_profile_owner.path()),
        DeniedCanary::new("appdata", application_data_owner.path()),
        DeniedCanary::new("sibling", &sibling),
    ];
    let registry = RegistryFixture::new();
    let mut credentials = CredentialFixture::new();
    let pipe = NamedPipeFixture::new();
    pipe.prove_parent_connections();
    let child_pipe_read_server = pipe.server(&pipe.read_name);
    let child_pipe_write_server = pipe.server(&pipe.write_name);

    let junction = container.path().join("junction-escape");
    create_junction(repository_owner.path(), &junction);
    let junction_path = junction.join(canaries[0].read.file_name().unwrap());
    let extended_path = extended_length_path(&canaries[0].read);
    let case_folded_path = canaries[0]
        .read
        .parent()
        .unwrap()
        .join("REPOSITORY-READ.BIN");
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
    let path_variants = [
        ("junction", junction_path),
        ("extended", extended_path),
        ("casefold", case_folded_path),
        ("long", long_path),
        ("ads", alternate_stream_path),
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
    let _credential_guard =
        EnvironmentVariableGuard::set("LAT_D2A_PARENT_CREDENTIAL_CANARY", "must-not-cross");
    let mut environment = BTreeMap::from([
        (
            "LAT_PROCESS_HELPER".to_owned(),
            "lpac-hostile-d2a".to_owned(),
        ),
        (
            "LAT_D2A_LOOPBACK".to_owned(),
            loopback_listener.local_addr().unwrap().to_string(),
        ),
        (
            "LAT_D2A_LAN".to_owned(),
            lan_listener.local_addr().unwrap().to_string(),
        ),
        ("LAT_D2A_INTERNET".to_owned(), "1.1.1.1:443".to_owned()),
        ("LAT_D2B_REGISTRY_KEY".to_owned(), registry.subkey.clone()),
        (
            "LAT_D2B_CREDENTIAL_PARENT".to_owned(),
            credentials.parent_target.clone(),
        ),
        (
            "LAT_D2B_CREDENTIAL_CHILD".to_owned(),
            credentials.child_target.clone(),
        ),
        (
            "LAT_D2B_CREDENTIAL_FILTER".to_owned(),
            credentials.filter.clone(),
        ),
        ("LAT_D2B_PIPE_READ".to_owned(), pipe.read_name.clone()),
        ("LAT_D2B_PIPE_WRITE".to_owned(), pipe.write_name.clone()),
    ]);
    for (index, canary) in canaries.iter().enumerate() {
        environment.insert(format!("LAT_D2A_READ_{index}"), path_text(&canary.read));
        environment.insert(format!("LAT_D2A_WRITE_{index}"), path_text(&canary.write));
    }
    for (index, (_, path)) in path_variants.iter().enumerate() {
        environment.insert(format!("LAT_D2A_PATH_{index}"), path_text(path));
    }

    let launcher = registered_lpac_launcher(&root);
    let mut request = request(
        vec![
            "--exact".to_owned(),
            "process_child_helper".to_owned(),
            "--nocapture".to_owned(),
        ],
        environment,
    );
    request.execution_id = ToolExecutionId::new("execution-lpac-hostile-d2a").unwrap();
    request.timeout_ms = 8_000;
    let execution_id = request.execution_id.clone();

    let receipt = launcher.execute(request).unwrap();
    credentials.observe_child_ownership();
    let stdout = String::from_utf8(receipt.stdout.bytes).unwrap();
    let stderr = String::from_utf8(receipt.stderr.bytes).unwrap();
    let observed = stdout
        .lines()
        .filter_map(|line| line.strip_prefix("d2a-"))
        .map(str::to_owned)
        .collect::<BTreeSet<_>>();
    let expected = [
        "root-enumerate=success",
        "root-file-create=denied",
        "root-directory-create=denied",
        "root-stream-create=denied",
        "read-repository=denied",
        "write-repository=denied",
        "read-profile=denied",
        "write-profile=denied",
        "read-appdata=denied",
        "write-appdata=denied",
        "read-sibling=denied",
        "write-sibling=denied",
        "path-junction=denied",
        "path-extended=denied",
        "path-casefold=denied",
        "path-long=denied",
        "path-ads=denied",
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

#[cfg(feature = "test-seams")]
#[test]
fn lpac_network_denial_is_stronger_than_the_paired_ordinary_appcontainer_control() {
    let root = TempDir::new().unwrap();
    let loopback_listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let lan_listener = TcpListener::bind(SocketAddr::new(host_lan_ip(), 0)).unwrap();
    prove_parent_connection(&loopback_listener);
    prove_parent_connection(&lan_listener);
    let environment = BTreeMap::from([
        (
            "LAT_PROCESS_HELPER".to_owned(),
            "lpac-network-d2a".to_owned(),
        ),
        (
            "LAT_D2A_LOOPBACK".to_owned(),
            loopback_listener.local_addr().unwrap().to_string(),
        ),
        (
            "LAT_D2A_LAN".to_owned(),
            lan_listener.local_addr().unwrap().to_string(),
        ),
        ("LAT_D2A_INTERNET".to_owned(), "1.1.1.1:443".to_owned()),
    ]);
    let run_case = |execution_id: &str, ordinary_appcontainer: bool| {
        let launcher = registered_lpac_launcher(root.path());
        let mut request = request(
            vec![
                "--exact".to_owned(),
                "process_child_helper".to_owned(),
                "--nocapture".to_owned(),
            ],
            environment.clone(),
        );
        request.execution_id = ToolExecutionId::new(execution_id).unwrap();
        let execution_id = request.execution_id.clone();
        if ordinary_appcontainer {
            omit_all_application_packages_policy_for_test(execution_id.clone());
            bypass_aap_attestation_for_test(execution_id.clone());
        }
        let receipt = launcher.execute(request).unwrap();
        assert_eq!(receipt.status, ProcessStatus::Exited);
        assert_eq!(receipt.exit_code, Some(0));
        let stdout = String::from_utf8(receipt.stdout.bytes).unwrap();
        let observed = network_observations(&stdout);
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
        observed
    };

    let ordinary = run_case("execution-d2a-network-ordinary", true);
    assert_eq!(ordinary.len(), 4);
    assert!(ordinary.contains("network-subsystem=ready"));
    for label in ["loopback", "lan", "internet"] {
        assert!(
            ["provider-init-failed", "denied-socket", "denied-connect"]
                .into_iter()
                .any(|status| ordinary.contains(&format!("network-{label}={status}"))),
            "ordinary AppContainer network control escaped denial: {ordinary:?}"
        );
    }
    let lpac = run_case("execution-d2a-network-lpac", false);
    assert_exact_lpac_network_denial(&lpac);
    assert_no_pending_connection(&loopback_listener);
    assert_no_pending_connection(&lan_listener);
}

#[test]
fn lpac_network_evidence_accepts_socket_or_connect_access_denial_per_endpoint() {
    let observed = [
        "network-subsystem=ready",
        "network-loopback=denied-socket",
        "network-lan=denied-connect",
        "network-internet=denied-socket",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect::<BTreeSet<_>>();

    assert_exact_lpac_network_denial(&observed);
}

fn assert_exact_lpac_network_denial(observed: &BTreeSet<String>) {
    assert_eq!(
        observed.len(),
        4,
        "unexpected LPAC network result: {observed:?}"
    );
    if observed.contains("network-subsystem=subsystem-denied") {
        for endpoint in ["loopback", "lan", "internet"] {
            assert!(
                observed.contains(&format!("network-{endpoint}=subsystem-denied")),
                "unexpected LPAC network result: {observed:?}"
            );
        }
        return;
    }

    assert!(
        observed.contains("network-subsystem=ready"),
        "unexpected LPAC network result: {observed:?}"
    );
    for endpoint in ["loopback", "lan", "internet"] {
        assert!(
            ["denied-socket", "denied-connect"]
                .into_iter()
                .any(|status| observed.contains(&format!("network-{endpoint}={status}"))),
            "unexpected LPAC network result: {observed:?}"
        );
    }
}

#[test]
fn lpac_rejects_physical_cwd_rebind_before_profile_or_child() {
    let container = TempDir::new().unwrap();
    let registered_parent = container.path().join("registered-parent");
    let registered_root = registered_parent.join("worktree");
    let rebound_parent = container.path().join("rebound-parent");
    let relocated_root = registered_parent.join("relocated-worktree");
    fs::create_dir_all(&registered_root).unwrap();
    let launcher = registered_lpac_launcher(&registered_root);

    fs::rename(&registered_parent, &rebound_parent)
        .expect_err("the retained root handle must deny the physical ancestor rename");

    fs::rename(&registered_root, &relocated_root)
        .expect("the physical leaf rename must exercise the path-rebind case");
    fs::create_dir(&registered_root).unwrap();

    assert!(registered_root.is_dir());
    assert!(relocated_root.is_dir());
    let marker = container.path().join("physical-cwd-rebind-marker");
    let request = lpac_marker_request("execution-physical-cwd-rebind", &marker);

    assert_lpac_rejected_before_resume(&launcher, request, &marker, false);

    drop(launcher);
    fs::rename(&registered_parent, &rebound_parent)
        .expect("the ancestor rename must succeed after releasing the retained root handle");
    assert!(rebound_parent.is_dir());
}

#[test]
fn lpac_control_self_test_rejects_rebound_registered_root() {
    let container = TempDir::new().unwrap();
    let registered_parent = container.path().join("registered-parent");
    let registered_root = registered_parent.join("worktree");
    let rebound_parent = container.path().join("rebound-parent");
    let relocated_root = registered_parent.join("relocated-worktree");
    fs::create_dir_all(&registered_root).unwrap();
    let launcher = registered_lpac_launcher(&registered_root);

    ToolControlSelfTest::verify_controls(&launcher).unwrap();
    fs::rename(&registered_root, &relocated_root).unwrap();
    fs::create_dir(&registered_root).unwrap();

    let error = ToolControlSelfTest::verify_controls(&launcher)
        .expect_err("the retained LPAC root must reject a path rebind");

    assert_eq!(
        error.safe_classification(),
        SafeErrorClassification::IntegrityFailure
    );
    drop(launcher);
    fs::rename(&registered_parent, &rebound_parent).unwrap();
    assert!(rebound_parent.is_dir());
}

#[cfg(feature = "test-seams")]
#[test]
fn lpac_policy_attestation_accepts_lpac_and_rejects_ordinary_appcontainer_before_resume() {
    let worktree = TempDir::new().unwrap();

    let launcher = registered_lpac_launcher(worktree.path());
    let mut intended_request = request(
        vec![
            "--exact".to_owned(),
            "process_child_helper".to_owned(),
            "--nocapture".to_owned(),
        ],
        lpac_identity_environment(),
    );
    intended_request.execution_id = ToolExecutionId::new("execution-policy-lpac").unwrap();
    let intended_execution_id = intended_request.execution_id.clone();
    launcher
        .execute(intended_request)
        .expect("the intended LPAC token must pass policy attestation");
    assert_eq!(
        lpac_lifecycle_counts_for_test(&intended_execution_id),
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

    let launcher = registered_lpac_launcher(worktree.path());
    let mut ordinary_request = request(
        vec![
            "--exact".to_owned(),
            "process_child_helper".to_owned(),
            "--nocapture".to_owned(),
        ],
        lpac_identity_environment(),
    );
    ordinary_request.execution_id = ToolExecutionId::new("execution-policy-control").unwrap();
    let ordinary_execution_id = ordinary_request.execution_id.clone();
    omit_all_application_packages_policy_for_test(ordinary_execution_id.clone());

    launcher
        .execute(ordinary_request)
        .expect_err("ordinary AppContainer control must fail policy attestation before resume");
    assert_eq!(
        lpac_lifecycle_counts_for_test(&ordinary_execution_id),
        LpacLifecycleCountsForTest {
            profiles_created: 1,
            profiles_deleted: 1,
            acl_grants: 2,
            acl_revokes: 2,
            suspended_children_created: 1,
            resumes_succeeded: 0,
            last_windows_error: None,
        }
    );
}

#[cfg(feature = "test-seams")]
#[test]
fn lpac_rejects_reserved_environment_names_before_profile_creation() {
    for (index, reserved_name) in ["LOCALAPPDATA", "temp", "TmP"].into_iter().enumerate() {
        let root = TempDir::new().unwrap();
        let launcher = registered_lpac_launcher(root.path());
        let mut environment = lpac_identity_environment();
        environment.insert(reserved_name.to_owned(), "caller-controlled".to_owned());
        let mut request = request(
            vec![
                "--exact".to_owned(),
                "process_child_helper".to_owned(),
                "--nocapture".to_owned(),
            ],
            environment,
        );
        request.execution_id =
            ToolExecutionId::new(format!("execution-reserved-environment-{index}")).unwrap();
        let execution_id = request.execution_id.clone();

        launcher
            .execute(request)
            .expect_err("reserved AppContainer environment names must be rejected");
        assert_eq!(
            lpac_lifecycle_counts_for_test(&execution_id),
            LpacLifecycleCountsForTest::default(),
            "reserved name {reserved_name:?} reached an LPAC side effect"
        );
    }
}

#[cfg(feature = "test-seams")]
#[test]
fn lpac_denies_all_application_packages_only_filesystem_canary() {
    let worktree = TempDir::new().unwrap();
    let canary_directory = TempDir::new().unwrap();
    let canary = canary_directory.path().join("all-packages-canary.bin");
    fs::write(&canary, b"behavioral canary").unwrap();
    configure_all_packages_canary_for_test(canary_directory.path(), &canary)
        .unwrap_or_else(|error| panic!("canary DACL setup failed with Windows error {error}"));
    assert_eq!(fs::read(&canary).unwrap(), b"behavioral canary");

    let run_case = |execution_name: &str, omit_lpac_policy: bool| {
        let launcher = registered_lpac_launcher(worktree.path());
        let mut environment = lpac_identity_environment();
        environment.insert("LAT_PROCESS_HELPER".to_owned(), "canary-read".to_owned());
        environment.insert(
            "LAT_PROCESS_CANARY".to_owned(),
            canary.to_string_lossy().into_owned(),
        );
        let mut request = request(
            vec![
                "--exact".to_owned(),
                "process_child_helper".to_owned(),
                "--nocapture".to_owned(),
            ],
            environment,
        );
        request.execution_id = ToolExecutionId::new(execution_name).unwrap();
        let execution_id = request.execution_id.clone();
        if omit_lpac_policy {
            omit_all_application_packages_policy_for_test(execution_id.clone());
            bypass_aap_attestation_for_test(execution_id.clone());
        }

        let receipt = launcher
            .execute(request)
            .expect("the configured AppContainer policy must pass");
        let lifecycle = lpac_lifecycle_counts_for_test(&execution_id);
        let stdout = String::from_utf8(receipt.stdout.bytes).unwrap();
        let stderr = String::from_utf8(receipt.stderr.bytes).unwrap();
        assert_eq!(receipt.status, ProcessStatus::Exited);
        assert_eq!(receipt.exit_code, Some(0));
        assert!(stderr.is_empty(), "stderr={stderr:?}");
        assert_eq!(lifecycle.profiles_created, 1);
        assert_eq!(lifecycle.profiles_deleted, 1);
        assert_eq!(lifecycle.acl_grants, 2);
        assert_eq!(lifecycle.acl_revokes, 2);
        assert_eq!(lifecycle.suspended_children_created, 1);
        assert_eq!(lifecycle.resumes_succeeded, 1);
        stdout
    };

    let ordinary_app_container = run_case("execution-aap-canary-control", true);
    assert!(
        ordinary_app_container.contains("canary-read=success;cwd-root-readable=1"),
        "ordinary AppContainer control could not read the AAP-only canary: {ordinary_app_container:?}"
    );
    let intended_lpac = run_case("execution-aap-canary-lpac", false);
    assert!(
        intended_lpac.contains("canary-read=denied;cwd-root-readable=1"),
        "intended LPAC read the AAP-only canary: {intended_lpac:?}"
    );
}

#[test]
fn lpac_rejects_unregistered_root_before_resume() {
    let root = TempDir::new().unwrap();
    let launcher = registered_lpac_launcher(root.path());
    let marker = root.path().join("unregistered-root-must-not-run.txt");
    let mut request = lpac_marker_request("lpac-unregistered-root", &marker);
    let ProcessWorkingDirectory::IsolatedWorktree(cwd) = &mut request.cwd else {
        unreachable!()
    };
    cwd.root_identity = CapabilityRootIdentity::new("unregistered-worktree").unwrap();

    assert_lpac_rejected_before_resume(&launcher, request, &marker, false);
}

#[test]
fn lpac_rejects_relative_cwd_before_resume() {
    let root = TempDir::new().unwrap();
    let launcher = registered_lpac_launcher(root.path());
    let marker = root.path().join("relative-cwd-must-not-run.txt");
    let mut request = lpac_marker_request("lpac-relative-cwd", &marker);
    let task_id = request.executor_claim.task_id().clone();
    let ProcessWorkingDirectory::IsolatedWorktree(cwd) = &mut request.cwd else {
        unreachable!()
    };
    cwd.capability = CapabilityRef::worktree(task_id, "nested").unwrap();
    cwd.target = ResolvedCapabilityTarget::Relative(
        RelativePathComponents::new(vec!["nested".to_owned()]).unwrap(),
    );

    assert_lpac_rejected_before_resume(&launcher, request, &marker, false);
}

#[test]
fn lpac_rejects_expected_writes_before_resume() {
    let root = TempDir::new().unwrap();
    let launcher = registered_lpac_launcher(root.path());
    let marker = root.path().join("expected-write-must-not-run.txt");
    let mut request = lpac_marker_request("lpac-expected-write", &marker);
    request.expected_writes = vec![authorized_write("output.txt", "test-worktree")];

    assert_lpac_rejected_before_resume(&launcher, request, &marker, false);
}

#[test]
fn lpac_rejects_non_denied_network_before_resume() {
    let root = TempDir::new().unwrap();
    let launcher = registered_lpac_launcher(root.path());
    let marker = root.path().join("network-mode-must-not-run.txt");
    let mut request = lpac_marker_request("lpac-network-mode", &marker);
    let network_digest = digest(b"provider-endpoint-only");
    request.network = EnforcedNetworkProfile {
        profile: NetworkProfile::ProviderEndpointOnly,
        profile_digest: network_digest.clone(),
        receipt: NetworkEnforcementReceipt::new("provider-network", network_digest).unwrap(),
    };

    assert_lpac_rejected_before_resume(&launcher, request, &marker, false);
}

#[cfg(feature = "test-seams")]
#[test]
fn lpac_token_verification_mismatch_never_resumes_child() {
    for (mismatch, name) in [
        (
            LpacTokenVerificationMismatchForTest::AppContainer,
            "appcontainer",
        ),
        (
            LpacTokenVerificationMismatchForTest::LessPrivilegedAppContainer,
            "lpac",
        ),
        (LpacTokenVerificationMismatchForTest::PackageSid, "sid"),
        (
            LpacTokenVerificationMismatchForTest::Capabilities,
            "capabilities",
        ),
    ] {
        let root = TempDir::new().unwrap();
        let launcher = registered_lpac_launcher(root.path());
        let marker = root
            .path()
            .join(format!("{name}-mismatch-must-not-run.txt"));
        let request = lpac_marker_request(&format!("lpac-{name}-mismatch"), &marker);
        fail_lpac_token_verification_for_test(request.execution_id.clone(), mismatch);

        assert_lpac_rejected_before_resume(&launcher, request, &marker, true);
    }
}

#[cfg(feature = "test-seams")]
#[test]
fn failed_boundary_reverification_never_resumes_child_code() {
    let root = TempDir::new().unwrap();
    let marker = root.path().join("must-not-exist");
    let mut boundary = TestOnlyBoundary::valid(root.path().to_owned());
    boundary.fail_before_resume = true;
    let launcher = WindowsProcessLauncher::with_isolated_worker_boundary(
        Arc::new(boundary),
        boundary_binding(),
    );
    let request = request(
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

    assert!(launcher.execute(request).is_err());
    assert!(!marker.exists());
}

#[cfg(feature = "test-seams")]
#[test]
fn lease_replacement_after_initial_check_is_denied_before_resume() {
    let root = TempDir::new().unwrap();
    let marker = root.path().join("must-not-run-after-lease-replacement");
    let leases = Arc::new(ReplaceableLeaseStore::new(7));
    let writes = Arc::new(WorkspaceWriteCoordinator::new());
    let authority = ProcessFenceAuthority::new(leases.clone(), writes);
    let boundary = Arc::new(LeaseReplacingBoundary {
        inner: TestOnlyBoundary::valid(root.path().to_owned()),
        authority: authority.clone(),
    });
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
    request.execution_id = ToolExecutionId::new("execution-stale-before-resume").unwrap();
    request.executor_fence = authority.binding();
    let execution_id = request.execution_id.clone();
    leases
        .assert_current(request.executor_claim.clone())
        .expect("initial runtime check");

    let error = launcher
        .execute(request)
        .expect_err("replacement must fence the suspended child");

    assert!(matches!(
        error,
        PortError::StaleLease { current, supplied }
            if current.get() == 8 && supplied.get() == 7
    ));
    #[cfg(feature = "test-seams")]
    assert_eq!(output_reader_counts_for_test(&execution_id), (2, 2));
    assert!(!marker.exists());
    assert!(launcher.cancel(&execution_id).is_err());
}

#[cfg(feature = "test-seams")]
#[test]
fn every_boundary_receipt_mismatch_is_rejected_before_child_creation() {
    for mismatch in [
        BoundaryMismatch::Identity,
        BoundaryMismatch::Acl,
        BoundaryMismatch::Task,
        BoundaryMismatch::ExecutorFence,
        BoundaryMismatch::Tier,
        BoundaryMismatch::CwdRootIdentity,
        BoundaryMismatch::NetworkEnforcement,
        BoundaryMismatch::NetworkDigest,
        BoundaryMismatch::ExecutableIdentity,
        BoundaryMismatch::ExecutableDigest,
        BoundaryMismatch::EnvironmentProfile,
        BoundaryMismatch::EnvironmentValues,
        BoundaryMismatch::Limits,
        BoundaryMismatch::ExpectedWrites,
        BoundaryMismatch::Argv,
        BoundaryMismatch::Timeout,
    ] {
        let root = TempDir::new().unwrap();
        let marker = root.path().join(format!("must-not-exist-{mismatch:?}"));
        let mut boundary = TestOnlyBoundary::valid(root.path().to_owned());
        match mismatch {
            BoundaryMismatch::Identity => boundary.identity_receipt = "wrong-identity".to_owned(),
            BoundaryMismatch::Acl => boundary.acl_receipt = "wrong-acl".to_owned(),
            _ => boundary.claims_mismatch = Some(mismatch),
        }
        let launcher = WindowsProcessLauncher::with_isolated_worker_boundary(
            Arc::new(boundary),
            boundary_binding(),
        );
        let request = request(
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

        assert!(launcher.execute(request).is_err(), "{mismatch:?}");
        assert!(!marker.exists(), "{mismatch:?}");
    }
}

#[cfg(feature = "test-seams")]
#[test]
fn executable_digest_is_revalidated_before_child_creation() {
    let root = TempDir::new().unwrap();
    let marker = root.path().join("must-not-exist-executable");
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
    request.executable.sha256 = digest(b"attacker replacement");

    assert!(launcher.execute(request).is_err());
    assert!(!marker.exists());
}

#[test]
fn output_overflow_terminates_the_job_and_returns_only_the_bound() {
    let root = TempDir::new().unwrap();
    let launcher = registered_lpac_launcher(root.path());
    let mut request = request(
        vec![
            "--exact".to_owned(),
            "process_child_helper".to_owned(),
            "--nocapture".to_owned(),
        ],
        BTreeMap::from([("LAT_PROCESS_HELPER".to_owned(), "flood".to_owned())]),
    );
    request.execution_id = ToolExecutionId::new("execution-lpac-output-overflow").unwrap();
    request.limits.max_stdout_bytes = 32;
    let execution_id = request.execution_id.clone();

    let receipt = launcher.execute(request).unwrap();

    assert_eq!(receipt.status, ProcessStatus::Terminated);
    assert!(receipt.stdout.truncated);
    assert_eq!(receipt.stdout.bytes.len(), 32);
    assert!(receipt.job_receipt.kill_on_close);
    assert!(receipt.job_receipt.no_breakaway);
    assert!(receipt.job_receipt.job_memory_limit);
    assert!(receipt.job_receipt.job_cpu_time_limit);
    assert_eq!(receipt.job_receipt.memory_limit_bytes, 256 * 1024 * 1024);
    assert_eq!(receipt.job_receipt.cpu_time_limit_ms, 5_000);
    assert_eq!(receipt.job_receipt.max_active_processes, 8);
    assert!(!receipt.job_receipt.resource_limit_terminated);
    assert!(receipt.job_receipt.tree_terminated);
    assert_real_lpac_lifecycle(&execution_id);
}

#[test]
fn stderr_overflow_terminates_the_real_lpac_job_and_returns_only_the_bound() {
    let root = TempDir::new().unwrap();
    let launcher = registered_lpac_launcher(root.path());
    let mut request = request(
        vec![
            "--exact".to_owned(),
            "process_child_helper".to_owned(),
            "--nocapture".to_owned(),
        ],
        BTreeMap::from([("LAT_PROCESS_HELPER".to_owned(), "stderr-flood".to_owned())]),
    );
    request.execution_id = ToolExecutionId::new("execution-lpac-stderr-overflow").unwrap();
    request.limits.max_stderr_bytes = 32;
    let execution_id = request.execution_id.clone();
    #[cfg(feature = "test-seams")]
    let oversized_marker = b"stderr-observation-sentinel";
    #[cfg(feature = "test-seams")]
    let observation =
        observe_stderr_marker_for_test(execution_id.clone(), oversized_marker).unwrap();

    let receipt = launcher.execute(request).unwrap();

    assert_eq!(receipt.status, ProcessStatus::Terminated);
    assert!(receipt.stderr.truncated);
    assert_eq!(receipt.stderr.bytes.len(), 32);
    assert!(receipt.job_receipt.kill_on_close);
    assert!(receipt.job_receipt.no_breakaway);
    assert!(receipt.job_receipt.job_memory_limit);
    assert!(receipt.job_receipt.job_cpu_time_limit);
    assert_eq!(receipt.job_receipt.memory_limit_bytes, 256 * 1024 * 1024);
    assert_eq!(receipt.job_receipt.cpu_time_limit_ms, 5_000);
    assert_eq!(receipt.job_receipt.max_active_processes, 8);
    assert!(!receipt.job_receipt.resource_limit_terminated);
    assert!(receipt.job_receipt.tree_terminated);
    #[cfg(feature = "test-seams")]
    {
        assert!(!observation.observed());
        assert!(observation.buffered_len() < oversized_marker.len());
        drop(observation);
        assert!(observe_stderr_marker_for_test(execution_id.clone(), oversized_marker).is_some());
    }
    assert_real_lpac_lifecycle(&execution_id);
}

#[test]
fn bounded_inert_helper_outlives_a_short_real_lpac_timeout() {
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
            "bounded-inert-wait".to_owned(),
        )]),
    );
    request.execution_id = ToolExecutionId::new("execution-lpac-bounded-inert-timeout").unwrap();
    request.timeout_ms = 1_000;

    let receipt = launcher.execute(request).unwrap();

    assert_eq!(receipt.status, ProcessStatus::Terminated);
    assert_eq!(receipt.exit_code, None);
    assert!(receipt
        .stderr
        .bytes
        .windows(b"bounded-inert-started".len())
        .any(|window| window == b"bounded-inert-started"));
    assert!(!receipt.stderr.truncated);
    assert!(receipt.job_receipt.kill_on_close);
    assert!(receipt.job_receipt.no_breakaway);
    assert!(receipt.job_receipt.job_memory_limit);
    assert!(receipt.job_receipt.job_cpu_time_limit);
    assert_eq!(receipt.job_receipt.memory_limit_bytes, 256 * 1024 * 1024);
    assert_eq!(receipt.job_receipt.cpu_time_limit_ms, 5_000);
    assert_eq!(receipt.job_receipt.max_active_processes, 8);
    assert!(!receipt.job_receipt.resource_limit_terminated);
    assert!(receipt.job_receipt.tree_terminated);
}

#[cfg(feature = "test-seams")]
#[test]
fn explicit_cancellation_terminates_a_live_real_lpac_root() {
    let root = TempDir::new().unwrap();
    let launcher = Arc::new(registered_lpac_launcher(root.path()));
    let started_marker = b"bounded-inert-started";
    let mut request = request(
        vec![
            "--exact".to_owned(),
            "process_child_helper".to_owned(),
            "--nocapture".to_owned(),
        ],
        BTreeMap::from([(
            "LAT_PROCESS_HELPER".to_owned(),
            "bounded-inert-wait".to_owned(),
        )]),
    );
    request.execution_id = ToolExecutionId::new("execution-lpac-explicit-cancel").unwrap();
    request.timeout_ms = 30_000;
    let execution_id = request.execution_id.clone();
    let stderr_observation =
        observe_stderr_marker_for_test(execution_id.clone(), started_marker).unwrap();
    let unrelated_execution_id =
        ToolExecutionId::new("execution-lpac-explicit-cancel-unrelated").unwrap();
    let unrelated_observation =
        observe_stderr_marker_for_test(unrelated_execution_id, started_marker).unwrap();
    let executing = Arc::clone(&launcher);
    let execution = thread::spawn(move || executing.execute(request));

    let resume_deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let lifecycle = lpac_lifecycle_counts_for_test(&execution_id);
        if lifecycle.resumes_succeeded == 1 {
            break;
        }
        assert!(
            Instant::now() < resume_deadline,
            "LPAC root did not resume: {lifecycle:?}"
        );
        thread::yield_now();
    }

    let output_deadline = Instant::now() + Duration::from_secs(5);
    while !stderr_observation.observed() {
        assert!(
            Instant::now() < output_deadline,
            "LPAC root stderr marker was not observed"
        );
        thread::yield_now();
    }
    assert!(!unrelated_observation.observed());

    let cancellation = launcher.cancel(&execution_id).unwrap();
    let receipt = execution.join().unwrap().unwrap();

    assert_eq!(cancellation.execution_id, execution_id);
    assert_eq!(cancellation.status, ProcessStatus::Terminated);
    assert!(cancellation.cancelled);
    let cancellation_job = cancellation.job_receipt.unwrap();
    assert!(cancellation_job.kill_on_close);
    assert!(cancellation_job.no_breakaway);
    assert!(cancellation_job.job_memory_limit);
    assert!(cancellation_job.job_cpu_time_limit);
    assert_eq!(cancellation_job.memory_limit_bytes, 256 * 1024 * 1024);
    assert_eq!(cancellation_job.cpu_time_limit_ms, 5_000);
    assert_eq!(cancellation_job.max_active_processes, 8);
    assert!(!cancellation_job.resource_limit_terminated);
    assert!(cancellation_job.tree_terminated);

    assert_eq!(receipt.execution_id, execution_id);
    assert_eq!(receipt.status, ProcessStatus::Terminated);
    assert!(receipt
        .stderr
        .bytes
        .windows(started_marker.len())
        .any(|window| window == started_marker));
    assert!(receipt.job_receipt.kill_on_close);
    assert!(receipt.job_receipt.no_breakaway);
    assert!(receipt.job_receipt.job_memory_limit);
    assert!(receipt.job_receipt.job_cpu_time_limit);
    assert_eq!(receipt.job_receipt.memory_limit_bytes, 256 * 1024 * 1024);
    assert_eq!(receipt.job_receipt.cpu_time_limit_ms, 5_000);
    assert_eq!(receipt.job_receipt.max_active_processes, 8);
    assert!(!receipt.job_receipt.resource_limit_terminated);
    assert!(receipt.job_receipt.tree_terminated);
    assert_real_lpac_lifecycle(&execution_id);
    drop(stderr_observation);
    assert!(observe_stderr_marker_for_test(execution_id, started_marker).is_some());
}

#[cfg(feature = "test-seams")]
#[test]
fn retained_process_recovery_validates_exact_authority_and_job_before_termination() {
    let root = TempDir::new().unwrap();
    let launcher = Arc::new(registered_lpac_launcher(root.path()));
    let mut request = request(
        vec![
            "--exact".to_owned(),
            "process_child_helper".to_owned(),
            "--nocapture".to_owned(),
        ],
        BTreeMap::from([(
            "LAT_PROCESS_HELPER".to_owned(),
            "bounded-inert-wait".to_owned(),
        )]),
    );
    request.execution_id = ToolExecutionId::new("execution-retained-recovery").unwrap();
    request.timeout_ms = 30_000;
    let execution_id = request.execution_id.clone();
    let authority = claimed_authority(&request);
    let captured = Arc::new(Mutex::new(None));
    let bindings = CapturingProcessBindings {
        authority: authority.clone(),
        captured: Arc::clone(&captured),
    };
    let executing = Arc::clone(&launcher);
    let execution_authority = authority.clone();
    let execution = thread::spawn(move || {
        local_agent_terminal_application::ProcessLauncher::execute(
            executing.as_ref(),
            request,
            &execution_authority,
            &bindings,
        )
    });

    let deadline = Instant::now() + Duration::from_secs(5);
    let binding = loop {
        if let Some(binding) = captured.lock().unwrap().clone() {
            break binding;
        }
        assert!(
            Instant::now() < deadline,
            "process binding was not persisted"
        );
        thread::yield_now();
    };
    while lpac_lifecycle_counts_for_test(&execution_id).resumes_succeeded != 1 {
        assert!(Instant::now() < deadline, "retained process did not resume");
        thread::yield_now();
    }

    let wrong_authority = ToolExecutionClaimAuthority::from_persisted(
        authority.execution_id().clone(),
        authority.operation_digest().clone(),
        authority.owner_run_id().clone(),
        authority.attempt() + 1,
        authority.executor_fencing_token(),
    )
    .unwrap();
    let wrong_authority_binding =
        AuthoritativeProcessBinding::new(wrong_authority, binding.root_pid(), binding.job_id())
            .unwrap();
    assert_eq!(
        local_agent_terminal_application::ProcessLauncher::terminate_retained_process(
            launcher.as_ref(),
            &wrong_authority_binding,
        )
        .unwrap_err()
        .safe_classification(),
        SafeErrorClassification::IntegrityFailure
    );
    assert!(process_is_active(binding.root_pid()));

    let wrong_job_binding =
        AuthoritativeProcessBinding::new(authority, binding.root_pid(), "job-not-retained")
            .unwrap();
    assert_eq!(
        local_agent_terminal_application::ProcessLauncher::terminate_retained_process(
            launcher.as_ref(),
            &wrong_job_binding,
        )
        .unwrap_err()
        .safe_classification(),
        SafeErrorClassification::IntegrityFailure
    );
    assert!(process_is_active(binding.root_pid()));

    let termination =
        local_agent_terminal_application::ProcessLauncher::terminate_retained_process(
            launcher.as_ref(),
            &binding,
        )
        .unwrap();
    let receipt = execution.join().unwrap().unwrap();

    assert_eq!(termination.execution_id, execution_id);
    assert_eq!(termination.status, ProcessStatus::Terminated);
    assert!(termination.cancelled);
    let job = termination.job_receipt.unwrap();
    assert_eq!(job.root_pid, binding.root_pid());
    assert_eq!(job.job_id, binding.job_id());
    assert!(job.tree_terminated);
    assert_eq!(receipt.status, ProcessStatus::Terminated);
}

#[cfg(feature = "test-seams")]
#[test]
fn cancellation_terminates_descendants_and_breakaway_is_denied() {
    let root = TempDir::new().unwrap();
    let marker = root.path().join("tree-state.txt");
    let boundary = Arc::new(TestOnlyBoundary::valid(root.path().to_owned()));
    let launcher = Arc::new(WindowsProcessLauncher::with_isolated_worker_boundary(
        boundary,
        boundary_binding(),
    ));
    let mut request = request(
        vec![
            "--exact".to_owned(),
            "process_child_helper".to_owned(),
            "--nocapture".to_owned(),
        ],
        BTreeMap::from([
            ("LAT_PROCESS_HELPER".to_owned(), "tree-root".to_owned()),
            (
                "LAT_PROCESS_MARKER".to_owned(),
                marker.to_string_lossy().into_owned(),
            ),
        ]),
    );
    request.timeout_ms = 30_000;
    let execution_id = request.execution_id.clone();
    let executing = launcher.clone();
    let execution = thread::spawn(move || executing.execute(request));
    let state = wait_for_file(&marker);
    let (breakaway, descendant_pid) = state.trim().split_once(':').unwrap();
    assert_eq!(breakaway, "breakaway-denied");
    let descendant_pid = descendant_pid.parse::<u32>().unwrap();

    let cancellation = launcher.cancel(&execution_id).unwrap();
    let receipt = execution.join().unwrap().unwrap();

    assert_eq!(cancellation.status, ProcessStatus::Terminated);
    assert!(cancellation.job_receipt.unwrap().tree_terminated);
    assert_eq!(receipt.status, ProcessStatus::Terminated);
    assert!(!process_is_active(descendant_pid));
}

#[cfg(feature = "test-seams")]
#[test]
fn write_capable_process_blocks_lease_acquire_and_revoke_until_cancellation_completes() {
    for change in [
        CoordinatedLeaseChange::Acquire,
        CoordinatedLeaseChange::Revoke,
    ] {
        let root = TempDir::new().unwrap();
        let name = change.name();
        let marker = root.path().join(format!("permit-held-{name}.txt"));
        let scope = authorized_write(&format!("permit-held-{name}.txt"), "test-worktree");
        let mut boundary = TestOnlyBoundary::valid(root.path().to_owned());
        boundary.allow_expected_writes = true;
        boundary.observed_writes = vec![observed_write(&scope, b"running")];
        let authority = ProcessFenceAuthority::new(
            Arc::new(ReplaceableLeaseStore::new(7)),
            Arc::new(WorkspaceWriteCoordinator::new()),
        );
        let launcher = Arc::new(WindowsProcessLauncher::with_isolated_worker_boundary(
            Arc::new(boundary),
            boundary_binding(),
        ));
        let mut request = request(
            vec![
                "--exact".to_owned(),
                "process_child_helper".to_owned(),
                "--nocapture".to_owned(),
            ],
            BTreeMap::from([
                ("LAT_PROCESS_HELPER".to_owned(), "marker-wait".to_owned()),
                (
                    "LAT_PROCESS_MARKER".to_owned(),
                    marker.to_string_lossy().into_owned(),
                ),
            ]),
        );
        request.execution_id =
            ToolExecutionId::new(format!("execution-permit-held-{name}")).unwrap();
        request.expected_writes = vec![scope];
        request.executor_fence = authority.binding();
        request.timeout_ms = 30_000;
        let execution_id = request.execution_id.clone();
        let executing = Arc::clone(&launcher);
        let execution = thread::spawn(move || executing.execute(request));
        assert_eq!(wait_for_file(&marker), "running");

        let (change_started_tx, change_started_rx) = mpsc::channel();
        let (change_tx, change_rx) = mpsc::channel();
        let changing_authority = authority.clone();
        let changing = thread::spawn(move || {
            change_started_tx.send(()).unwrap();
            let result = change.execute(&changing_authority);
            change_tx.send(result).unwrap();
        });
        change_started_rx
            .recv_timeout(Duration::from_secs(5))
            .unwrap();
        assert!(matches!(
            change_rx.recv_timeout(Duration::from_millis(100)),
            Err(mpsc::RecvTimeoutError::Timeout)
        ));

        let cancellation = launcher.cancel(&execution_id).unwrap();
        let receipt = execution.join().unwrap().unwrap();
        assert_eq!(
            change_rx
                .recv_timeout(Duration::from_secs(5))
                .expect("lease change must proceed after the Job exits")
                .unwrap(),
            8
        );
        changing.join().unwrap();

        assert_eq!(cancellation.status, ProcessStatus::Terminated);
        assert_eq!(receipt.status, ProcessStatus::Terminated);
    }
}

#[cfg(feature = "test-seams")]
#[test]
fn post_resume_cleanup_fault_keeps_fence_until_job_exit_is_retried() {
    let _cleanup_failure_test = JOB_CLEANUP_FAILURE_TEST_LOCK.lock().unwrap();
    for (point, execution_name) in [
        (
            JobCleanupFailurePointForTest::Terminate,
            "execution-cleanup-terminate-fault",
        ),
        (
            JobCleanupFailurePointForTest::TreeWait,
            "execution-cleanup-tree-wait-fault",
        ),
    ] {
        let root = TempDir::new().unwrap();
        let marker = root.path().join(format!("{execution_name}.txt"));
        let boundary = Arc::new(TestOnlyBoundary::valid(root.path().to_owned()));
        let leases = Arc::new(ReplaceableLeaseStore::new(7));
        let authority =
            ProcessFenceAuthority::new(leases, Arc::new(WorkspaceWriteCoordinator::new()));
        let launcher = Arc::new(WindowsProcessLauncher::with_isolated_worker_boundary(
            boundary,
            boundary_binding(),
        ));
        let mut request = request(
            vec![
                "--exact".to_owned(),
                "process_child_helper".to_owned(),
                "--nocapture".to_owned(),
            ],
            BTreeMap::from([
                ("LAT_PROCESS_HELPER".to_owned(), "marker-wait".to_owned()),
                (
                    "LAT_PROCESS_MARKER".to_owned(),
                    marker.to_string_lossy().into_owned(),
                ),
            ]),
        );
        request.execution_id = ToolExecutionId::new(execution_name).unwrap();
        request.executor_fence = authority.binding();
        let execution_id = request.execution_id.clone();
        fail_after_resume_for_test(execution_id.clone());
        let cleanup_failure = block_next_job_cleanup_failure_for_test(execution_id.clone(), point);
        let executing = Arc::clone(&launcher);
        let execution = thread::spawn(move || executing.execute(request));
        assert!(cleanup_failure.wait_for_attempt(1, Duration::from_secs(5)));

        let (mutation_started_tx, mutation_started_rx) = mpsc::channel();
        let (mutation_tx, mutation_rx) = mpsc::channel();
        let mutating_authority = authority.clone();
        let mutation = thread::spawn(move || {
            mutation_started_tx.send(()).unwrap();
            let result = match point {
                JobCleanupFailurePointForTest::Terminate => mutating_authority
                    .acquire_lease(AcquireLease {
                        task_id: TaskId::new("task-1").unwrap(),
                        holder_run_id: RunId::new("run-2").unwrap(),
                        expected_fencing_epoch: 7,
                        acquired_at: "2026-07-29T00:00:00Z".to_owned(),
                        expires_at: "2026-07-29T01:00:00Z".to_owned(),
                    })
                    .map(|snapshot| snapshot.token.get()),
                JobCleanupFailurePointForTest::TreeWait => mutating_authority
                    .revoke_lease(RevokeLease {
                        claim: LeaseClaim::new(
                            TaskId::new("task-1").unwrap(),
                            RunId::new("run-1").unwrap(),
                            FencingToken::new(7).unwrap(),
                        ),
                        revoked_at: "2026-07-29T00:30:00Z".to_owned(),
                    })
                    .map(|()| 8),
            };
            mutation_tx.send(result).unwrap();
        });
        mutation_started_rx
            .recv_timeout(Duration::from_secs(5))
            .unwrap();
        assert!(matches!(
            mutation_rx.recv_timeout(Duration::from_millis(100)),
            Err(mpsc::RecvTimeoutError::Timeout)
        ));

        cleanup_failure.fail_current_attempt();
        assert!(cleanup_failure.wait_for_attempt(2, Duration::from_secs(5)));
        assert!(matches!(
            mutation_rx.recv_timeout(Duration::from_millis(100)),
            Err(mpsc::RecvTimeoutError::Timeout)
        ));
        cleanup_failure.allow_cleanup();

        assert!(execution.join().unwrap().is_err());
        assert_eq!(
            mutation_rx
                .recv_timeout(Duration::from_secs(5))
                .unwrap()
                .unwrap(),
            8
        );
        mutation.join().unwrap();
        assert!(launcher.cancel(&execution_id).is_err());
    }
}

#[cfg(feature = "test-seams")]
#[test]
fn wall_timeout_waits_for_the_full_process_tree() {
    let root = TempDir::new().unwrap();
    let marker = root.path().join("timeout-tree-state.txt");
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
            ("LAT_PROCESS_HELPER".to_owned(), "tree-root".to_owned()),
            (
                "LAT_PROCESS_MARKER".to_owned(),
                marker.to_string_lossy().into_owned(),
            ),
        ]),
    );
    request.timeout_ms = 250;

    let receipt = launcher.execute(request).unwrap();
    let state = fs::read_to_string(marker).unwrap();
    let (_, descendant_pid) = state.trim().split_once(':').unwrap();
    let descendant_pid = descendant_pid.parse::<u32>().unwrap();

    assert_eq!(receipt.status, ProcessStatus::Terminated);
    assert!(receipt.job_receipt.tree_terminated);
    assert!(!process_is_active(descendant_pid));
}

#[cfg(feature = "test-seams")]
#[test]
fn typed_windows_command_line_preserves_metacharacters_as_one_argument() {
    let root = TempDir::new().unwrap();
    let boundary = Arc::new(TestOnlyBoundary::valid(root.path().to_owned()));
    let launcher =
        WindowsProcessLauncher::with_isolated_worker_boundary(boundary, boundary_binding());
    let request = request(
        vec![
            "--exact".to_owned(),
            "process_child_helper".to_owned(),
            "--nocapture".to_owned(),
            "--skip".to_owned(),
            ";&|$() spaced \"quoted\" \\".to_owned(),
        ],
        BTreeMap::from([("LAT_PROCESS_HELPER".to_owned(), "argv".to_owned())]),
    );

    let receipt = launcher.execute(request).unwrap();

    assert!(
        String::from_utf8_lossy(&receipt.stdout.bytes).contains("argv=;&|$() spaced \"quoted\" \\")
    );
}

#[cfg(feature = "test-seams")]
#[test]
fn child_environment_starts_empty_and_does_not_inherit_parent_canary() {
    const CANARY: &str = "LAT_PARENT_SECRET_CANARY_TASK7";
    let _guard = EnvironmentVariableGuard::set(CANARY, "must-not-cross");
    let root = TempDir::new().unwrap();
    let boundary = Arc::new(TestOnlyBoundary::valid(root.path().to_owned()));
    let launcher =
        WindowsProcessLauncher::with_isolated_worker_boundary(boundary, boundary_binding());
    let request = request(
        vec![
            "--exact".to_owned(),
            "process_child_helper".to_owned(),
            "--nocapture".to_owned(),
            "--skip".to_owned(),
            "environment-probe".to_owned(),
        ],
        BTreeMap::new(),
    );

    let receipt = launcher.execute(request).unwrap();

    assert!(String::from_utf8_lossy(&receipt.stdout.bytes).contains("canary=missing"));
}

#[cfg(feature = "test-seams")]
#[test]
fn brokered_worktree_and_unenforced_expected_writes_never_start_child_code() {
    for mutation in [
        LaunchMutation::BrokeredWorktree,
        LaunchMutation::ExpectedWrite,
    ] {
        let root = TempDir::new().unwrap();
        let marker = root.path().join(format!("must-not-exist-{mutation:?}"));
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
        match mutation {
            LaunchMutation::BrokeredWorktree => {
                request.trust_tier = ProcessTrustTier::BrokeredProcess
            }
            LaunchMutation::ExpectedWrite => {
                request.expected_writes = vec![authorized_write("target", "test-worktree")]
            }
        }

        assert!(launcher.execute(request).is_err(), "{mutation:?}");
        assert!(!marker.exists(), "{mutation:?}");
    }
}

#[cfg(feature = "test-seams")]
#[test]
fn enforced_expected_write_scope_is_bound_and_returns_observed_evidence() {
    let root = TempDir::new().unwrap();
    let scope = authorized_write("generated.txt", "test-worktree");
    let mut boundary = TestOnlyBoundary::valid(root.path().to_owned());
    boundary.allow_expected_writes = true;
    boundary.observed_writes = vec![observed_write(&scope, b"observed write")];
    let boundary = Arc::new(boundary);
    let launcher =
        WindowsProcessLauncher::with_isolated_worker_boundary(boundary, boundary_binding());
    let mut request = request(
        vec![
            "--exact".to_owned(),
            "process_child_helper".to_owned(),
            "--nocapture".to_owned(),
        ],
        BTreeMap::from([("LAT_PROCESS_HELPER".to_owned(), "emit".to_owned())]),
    );
    request.expected_writes = vec![scope];

    let receipt = launcher.execute(request).unwrap();

    assert_eq!(receipt.status, ProcessStatus::Exited);
    assert_eq!(receipt.observed_writes.len(), 1);
    assert_eq!(receipt.observed_writes[0].write().size_bytes, 14);
}

#[cfg(feature = "test-seams")]
#[test]
fn reversed_write_evidence_is_canonicalized_to_approved_scope_order() {
    let root = TempDir::new().unwrap();
    let first = authorized_write("generated/first.txt", "test-worktree");
    let second = authorized_write("generated/second.txt", "test-worktree");
    let mut boundary = TestOnlyBoundary::valid(root.path().to_owned());
    boundary.allow_expected_writes = true;
    boundary.observed_writes = vec![
        observed_write(&second, b"second"),
        observed_write(&first, b"first"),
    ];
    let boundary = Arc::new(boundary);
    let launcher =
        WindowsProcessLauncher::with_isolated_worker_boundary(boundary, boundary_binding());
    let mut request = request(
        vec![
            "--exact".to_owned(),
            "process_child_helper".to_owned(),
            "--nocapture".to_owned(),
        ],
        BTreeMap::from([("LAT_PROCESS_HELPER".to_owned(), "emit".to_owned())]),
    );
    request.expected_writes = vec![first, second];

    let receipt = launcher.execute(request).unwrap();

    assert_eq!(receipt.observed_writes.len(), 2);
    assert_eq!(
        receipt.observed_writes[0].capability(),
        &CapabilityRef::worktree(TaskId::new("task-1").unwrap(), "generated/first.txt").unwrap()
    );
    assert_eq!(receipt.observed_writes[0].write().digest, digest(b"first"));
    assert_eq!(
        receipt.observed_writes[1].capability(),
        &CapabilityRef::worktree(TaskId::new("task-1").unwrap(), "generated/second.txt").unwrap()
    );
    assert_eq!(receipt.observed_writes[1].write().digest, digest(b"second"));
}

#[cfg(feature = "test-seams")]
#[test]
fn logical_aliases_for_one_physical_write_scope_are_ambiguous() {
    let root = TempDir::new().unwrap();
    let slash = authorized_write("generated/alias.txt", "test-worktree");
    let backslash = authorized_write("generated\\alias.txt", "test-worktree");
    assert_ne!(slash.capability(), backslash.capability());
    assert_eq!(slash.root_identity(), backslash.root_identity());
    assert_eq!(slash.target(), backslash.target());
    let mut boundary = TestOnlyBoundary::valid(root.path().to_owned());
    boundary.allow_expected_writes = true;
    boundary.observed_writes = vec![
        observed_write(&slash, b"slash"),
        observed_write(&backslash, b"backslash"),
    ];
    let boundary = Arc::new(boundary);
    let launcher =
        WindowsProcessLauncher::with_isolated_worker_boundary(boundary, boundary_binding());
    let mut request = request(
        vec![
            "--exact".to_owned(),
            "process_child_helper".to_owned(),
            "--nocapture".to_owned(),
        ],
        BTreeMap::from([("LAT_PROCESS_HELPER".to_owned(), "emit".to_owned())]),
    );
    request.expected_writes = vec![slash, backslash];

    let error = launcher
        .execute(request)
        .expect_err("one physical scope must not have two logical labels");

    assert_eq!(
        error.safe_classification(),
        local_agent_terminal_application::SafeErrorClassification::IntegrityFailure
    );
}

#[test]
fn write_scope_matcher_rejects_more_than_the_approval_limit() {
    let approved = (0..=1024)
        .map(|index| authorized_write(&format!("generated/{index}.txt"), "test-worktree"))
        .collect::<Vec<_>>();
    let observed = approved
        .iter()
        .map(|scope| observed_write(scope, b"observed"))
        .collect();

    let error = validate_and_order_process_writes(&approved, observed)
        .expect_err("unbounded scope sets must be denied before matching");

    assert_eq!(
        error.safe_classification(),
        local_agent_terminal_application::SafeErrorClassification::IntegrityFailure
    );
}

#[cfg(feature = "test-seams")]
#[test]
fn write_evidence_must_match_approved_scopes_one_to_one() {
    for mutation in [
        WriteEvidenceMutation::Missing,
        WriteEvidenceMutation::Extra,
        WriteEvidenceMutation::Duplicate,
        WriteEvidenceMutation::AmbiguousApproval,
        WriteEvidenceMutation::Capability,
        WriteEvidenceMutation::Root,
        WriteEvidenceMutation::Path,
    ] {
        let root = TempDir::new().unwrap();
        let first = authorized_write("generated/first.txt", "test-worktree");
        let second = authorized_write("generated/second.txt", "test-worktree");
        let first_observation = observed_write(&first, b"first");
        let second_observation = observed_write(&second, b"second");
        let (approved, observed) = match mutation {
            WriteEvidenceMutation::Missing => (vec![first, second], vec![first_observation]),
            WriteEvidenceMutation::Extra => {
                let extra = authorized_write("generated/extra.txt", "test-worktree");
                (
                    vec![first, second],
                    vec![
                        first_observation,
                        second_observation,
                        observed_write(&extra, b"extra"),
                    ],
                )
            }
            WriteEvidenceMutation::Duplicate => (
                vec![first, second],
                vec![first_observation.clone(), first_observation],
            ),
            WriteEvidenceMutation::AmbiguousApproval => (
                vec![first.clone(), first],
                vec![first_observation, second_observation],
            ),
            WriteEvidenceMutation::Capability => (
                vec![first.clone(), second],
                vec![
                    observed_evidence(
                        CapabilityRef::worktree(
                            TaskId::new("task-1").unwrap(),
                            "generated/other.txt",
                        )
                        .unwrap(),
                        first.root_identity().clone(),
                        first.target().clone(),
                        b"first",
                    ),
                    second_observation,
                ],
            ),
            WriteEvidenceMutation::Root => (
                vec![first.clone(), second],
                vec![
                    observed_evidence(
                        first.capability().clone(),
                        CapabilityRootIdentity::new("other-worktree").unwrap(),
                        first.target().clone(),
                        b"first",
                    ),
                    second_observation,
                ],
            ),
            WriteEvidenceMutation::Path => (
                vec![first.clone(), second],
                vec![
                    observed_evidence(
                        first.capability().clone(),
                        first.root_identity().clone(),
                        ResolvedCapabilityTarget::Relative(
                            RelativePathComponents::new(vec![
                                "generated".to_owned(),
                                "other.txt".to_owned(),
                            ])
                            .unwrap(),
                        ),
                        b"first",
                    ),
                    second_observation,
                ],
            ),
        };
        let mut boundary = TestOnlyBoundary::valid(root.path().to_owned());
        boundary.allow_expected_writes = true;
        boundary.observed_writes = observed;
        let boundary = Arc::new(boundary);
        let launcher =
            WindowsProcessLauncher::with_isolated_worker_boundary(boundary, boundary_binding());
        let mut request = request(
            vec![
                "--exact".to_owned(),
                "process_child_helper".to_owned(),
                "--nocapture".to_owned(),
            ],
            BTreeMap::from([("LAT_PROCESS_HELPER".to_owned(), "emit".to_owned())]),
        );
        request.expected_writes = approved;

        let error = match launcher.execute(request) {
            Ok(receipt) => panic!("{mutation:?} was accepted: {receipt:?}"),
            Err(error) => error,
        };

        assert_eq!(
            error.safe_classification(),
            local_agent_terminal_application::SafeErrorClassification::IntegrityFailure,
            "{mutation:?}"
        );
    }
}

#[test]
fn cpu_job_limit_terminates_busy_process_before_wall_timeout() {
    let root = TempDir::new().unwrap();
    let launcher = registered_lpac_launcher(root.path());
    let mut request = request(
        vec![
            "--exact".to_owned(),
            "process_child_helper".to_owned(),
            "--nocapture".to_owned(),
        ],
        BTreeMap::from([("LAT_PROCESS_HELPER".to_owned(), "cpu".to_owned())]),
    );
    request.execution_id = ToolExecutionId::new("execution-lpac-cpu-limit").unwrap();
    request.timeout_ms = 15_000;
    request.limits.cpu_time_limit_ms = 1;
    let execution_id = request.execution_id.clone();

    let receipt = launcher.execute(request).unwrap();

    assert_eq!(receipt.status, ProcessStatus::Terminated);
    assert!(receipt.duration_ms < 15_000);
    assert!(receipt.job_receipt.kill_on_close);
    assert!(receipt.job_receipt.no_breakaway);
    assert!(receipt.job_receipt.job_memory_limit);
    assert!(receipt.job_receipt.job_cpu_time_limit);
    assert_eq!(receipt.job_receipt.memory_limit_bytes, 256 * 1024 * 1024);
    assert_eq!(receipt.job_receipt.cpu_time_limit_ms, 1);
    assert_eq!(receipt.job_receipt.max_active_processes, 8);
    assert!(receipt.job_receipt.resource_limit_terminated);
    assert!(receipt.job_receipt.tree_terminated);
    assert_real_lpac_lifecycle(&execution_id);
}

#[test]
fn memory_job_limit_denies_additional_committed_memory() {
    let root = TempDir::new().unwrap();
    let launcher = registered_lpac_launcher(root.path());
    let mut request = request(
        vec![
            "--exact".to_owned(),
            "process_child_helper".to_owned(),
            "--nocapture".to_owned(),
        ],
        BTreeMap::from([("LAT_PROCESS_HELPER".to_owned(), "memory".to_owned())]),
    );
    request.execution_id = ToolExecutionId::new("execution-lpac-memory-limit").unwrap();
    request.timeout_ms = 5_000;
    request.limits.memory_limit_bytes = 64 * 1024 * 1024;
    let execution_id = request.execution_id.clone();

    let receipt = launcher.execute(request).unwrap();

    assert_eq!(receipt.status, ProcessStatus::Exited);
    assert_eq!(receipt.exit_code, Some(0));
    assert!(String::from_utf8_lossy(&receipt.stdout.bytes).contains("memory-denied"));
    assert!(receipt.job_receipt.kill_on_close);
    assert!(receipt.job_receipt.no_breakaway);
    assert!(receipt.job_receipt.job_memory_limit);
    assert!(receipt.job_receipt.job_cpu_time_limit);
    assert_eq!(receipt.job_receipt.memory_limit_bytes, 64 * 1024 * 1024);
    assert_eq!(receipt.job_receipt.cpu_time_limit_ms, 5_000);
    assert_eq!(receipt.job_receipt.max_active_processes, 8);
    assert!(!receipt.job_receipt.resource_limit_terminated);
    assert!(!receipt.job_receipt.tree_terminated);
    assert_real_lpac_lifecycle(&execution_id);
}

#[cfg(feature = "test-seams")]
#[test]
fn memory_limit_is_shared_by_the_complete_descendant_tree() {
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
        BTreeMap::from([("LAT_PROCESS_HELPER".to_owned(), "memory-tree".to_owned())]),
    );
    request.timeout_ms = 5_000;
    request.limits.memory_limit_bytes = 96 * 1024 * 1024;
    let receipt = launcher.execute(request).unwrap();

    assert!(String::from_utf8_lossy(&receipt.stdout.bytes).contains("memory-denied"));
}

#[cfg(feature = "test-seams")]
#[test]
fn cpu_limit_is_shared_by_the_complete_descendant_tree() {
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
        BTreeMap::from([("LAT_PROCESS_HELPER".to_owned(), "cpu-tree".to_owned())]),
    );
    request.timeout_ms = 20_000;
    request.limits.cpu_time_limit_ms = 650;
    let receipt = launcher.execute(request).unwrap();

    assert!(receipt.job_receipt.job_cpu_time_limit);
    assert_eq!(receipt.job_receipt.cpu_time_limit_ms, 650);
    assert!(
        receipt.job_receipt.resource_limit_terminated,
        "status={:?}, duration={} ms, user={} ms",
        receipt.status, receipt.duration_ms, receipt.job_receipt.total_user_time_ms,
    );
    assert_eq!(
        receipt.status,
        ProcessStatus::Terminated,
        "observed job user time: {} ms",
        receipt.job_receipt.total_user_time_ms,
    );
    assert!(receipt.duration_ms < 20_000);
}

#[test]
fn process_child_helper() {
    let arguments = std::env::args().collect::<Vec<_>>();
    let skip_value = arguments
        .windows(2)
        .find(|pair| pair[0] == "--skip")
        .map(|pair| pair[1].as_str());
    match std::env::var("LAT_PROCESS_HELPER").ok().as_deref() {
        Some("emit") => println!("literal ;&|$()"),
        Some("argv") => println!("argv={}", skip_value.unwrap()),
        Some("lpac-identity") => {
            let is_app_container = current_process_token_flag(TokenIsAppContainer);
            let capability_count = current_process_token_group_count(TokenCapabilities);
            let local_app_data = PathBuf::from(std::env::var_os("LOCALAPPDATA").unwrap());
            let expected_temp = local_app_data.join("Temp");
            assert_eq!(
                std::env::var_os("TEMP").as_deref(),
                Some(expected_temp.as_os_str())
            );
            assert_eq!(
                std::env::var_os("TMP").as_deref(),
                Some(expected_temp.as_os_str())
            );
            let mut root_entries = fs::read_dir(".").unwrap();
            assert!(root_entries.next().is_none());
            println!("appcontainer={is_app_container}");
            println!("capabilities={capability_count}");
            println!("reserved-env=valid");
            println!("cwd-root-readable=1");
        }
        Some("cpu") => {
            let mut value = 0_u64;
            loop {
                value = std::hint::black_box(value.wrapping_add(1));
            }
        }
        Some("cpu-tree") => {
            for _ in 0..2 {
                let mut child = Command::new(std::env::current_exe().unwrap())
                    .args(["--exact", "process_child_helper", "--nocapture"])
                    .env_clear()
                    .env("LAT_PROCESS_HELPER", "cpu-fixed")
                    .spawn()
                    .unwrap();
                child.wait().unwrap();
            }
            loop {
                thread::sleep(Duration::from_secs(60));
            }
        }
        Some("cpu-fixed") => {
            burn_user_cpu(Duration::from_millis(400));
            println!("cpu-complete");
        }
        Some("memory") => {
            let mut chunks = Vec::new();
            loop {
                let mut chunk = Vec::<u8>::new();
                if chunk.try_reserve_exact(1024 * 1024).is_err() {
                    println!("memory-denied");
                    break;
                }
                chunk.resize(1024 * 1024, 0xA5);
                chunks.push(chunk);
            }
        }
        Some("memory-tree") => {
            let children = (0..2)
                .map(|_| {
                    Command::new(std::env::current_exe().unwrap())
                        .args(["--exact", "process_child_helper", "--nocapture"])
                        .env_clear()
                        .env("LAT_PROCESS_HELPER", "memory-fixed")
                        .spawn()
                        .unwrap()
                })
                .collect::<Vec<_>>();
            for mut child in children {
                child.wait().unwrap();
            }
        }
        Some("memory-fixed") => {
            let mut bytes = Vec::<u8>::new();
            if bytes.try_reserve_exact(48 * 1024 * 1024).is_err() {
                println!("memory-denied");
            } else {
                bytes.resize(48 * 1024 * 1024, 0xA5);
                println!("memory-allocated");
                thread::sleep(Duration::from_millis(200));
                std::hint::black_box(bytes);
            }
        }
        Some("flood") => println!("{}", "x".repeat(128 * 1024)),
        Some("stderr-flood") => eprintln!("{}", "x".repeat(128 * 1024)),
        Some("bounded-inert-wait") => {
            eprintln!("bounded-inert-started");
            thread::sleep(Duration::from_secs(30));
        }
        Some("canary-read") => {
            let read_status = if fs::read(std::env::var_os("LAT_PROCESS_CANARY").unwrap()).is_ok() {
                "success"
            } else {
                "denied"
            };
            let mut root_entries = fs::read_dir(".").unwrap();
            assert!(root_entries.next().is_none());
            println!("canary-read={read_status};cwd-root-readable=1");
        }
        Some("lpac-hostile-d2a") => run_lpac_hostile_d2a_probe(),
        Some("lpac-network-d2a") => run_lpac_d2a_network_probe(),
        Some("lpac-descendant-denial") => run_lpac_descendant_denial_probe(),
        Some("lpac-descendant-child") => {}
        Some("marker") => {
            fs::write(std::env::var_os("LAT_PROCESS_MARKER").unwrap(), b"ran").unwrap();
        }
        Some("marker-wait") => {
            fs::write(std::env::var_os("LAT_PROCESS_MARKER").unwrap(), b"running").unwrap();
            loop {
                thread::sleep(Duration::from_secs(1));
            }
        }
        Some("tree-root") => {
            let marker = std::env::var_os("LAT_PROCESS_MARKER").unwrap();
            let mut breakaway = Command::new(std::env::current_exe().unwrap());
            breakaway
                .args(["--exact", "process_child_helper", "--nocapture"])
                .env_clear()
                .env("LAT_PROCESS_HELPER", "tree-child")
                .creation_flags(CREATE_BREAKAWAY_FROM_JOB);
            assert!(breakaway.spawn().is_err());

            let mut child = Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "process_child_helper", "--nocapture"])
                .env_clear()
                .env("LAT_PROCESS_HELPER", "tree-child")
                .spawn()
                .unwrap();
            fs::write(marker, format!("breakaway-denied:{}", child.id())).unwrap();
            child.wait().unwrap();
        }
        Some("tree-child") => loop {
            thread::sleep(Duration::from_secs(1));
        },
        _ if skip_value == Some("environment-probe") => println!(
            "canary={}",
            std::env::var("LAT_PARENT_SECRET_CANARY_TASK7")
                .map(|_| "inherited")
                .unwrap_or("missing")
        ),
        _ => {}
    }
}

fn run_lpac_descendant_denial_probe() {
    for (mode, creation_flags) in [
        ("ordinary", 0),
        (
            "detached-new-process-group",
            DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP,
        ),
        ("breakaway", CREATE_BREAKAWAY_FROM_JOB),
    ] {
        eprintln!(
            "d2d-descendant-{mode}={}",
            attempt_registered_descendant(creation_flags)
        );
    }
    eprintln!("d2d-descendant-attempts=complete");
    thread::sleep(Duration::from_secs(30));
}

fn attempt_registered_descendant(creation_flags: u32) -> &'static str {
    let executable = std::env::current_exe().unwrap();
    let application = executable
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    let mut command_line = vec![u16::from(b'"')];
    command_line.extend(executable.as_os_str().encode_wide());
    command_line.extend("\" --exact process_child_helper --nocapture\0".encode_utf16());
    let environment = "LAT_PROCESS_HELPER=lpac-descendant-child\0\0"
        .encode_utf16()
        .collect::<Vec<_>>();
    let current_directory = std::env::current_dir()
        .unwrap()
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    let startup = STARTUPINFOW {
        cb: std::mem::size_of::<STARTUPINFOW>() as u32,
        ..STARTUPINFOW::default()
    };
    let mut process_information = PROCESS_INFORMATION::default();

    // SAFETY: all pointers reference live, correctly terminated buffers; startup has
    // its documented size; process_information is writable; handles are not inherited.
    let created = unsafe {
        CreateProcessW(
            application.as_ptr(),
            command_line.as_mut_ptr(),
            ptr::null(),
            ptr::null(),
            0,
            creation_flags | CREATE_UNICODE_ENVIRONMENT,
            environment.as_ptr().cast(),
            current_directory.as_ptr(),
            &startup,
            &mut process_information,
        )
    };
    if created == 0 {
        // SAFETY: CreateProcessW failed on this thread, so GetLastError returns its status.
        let error = unsafe { GetLastError() };
        assert_eq!(process_information.dwProcessId, 0);
        return match error {
            ERROR_ACCESS_DENIED => "access-denied",
            _ => "other-failure",
        };
    }

    assert_ne!(process_information.dwProcessId, 0);
    // SAFETY: CreateProcessW returned both owned handles. Every operation is
    // best-effort so both handles are closed even if termination or waiting fails.
    let cleanup_complete = unsafe {
        let stopped = if WaitForSingleObject(process_information.hProcess, 250) == WAIT_OBJECT_0 {
            true
        } else {
            let termination_requested = TerminateProcess(process_information.hProcess, 1) != 0;
            let stopped = WaitForSingleObject(process_information.hProcess, 5_000) == WAIT_OBJECT_0;
            termination_requested && stopped
        };
        let thread_closed = CloseHandle(process_information.hThread) != 0;
        let process_closed = CloseHandle(process_information.hProcess) != 0;
        stopped && thread_closed && process_closed
    };
    if cleanup_complete {
        "started"
    } else {
        "started-cleanup-failed"
    }
}

fn run_lpac_hostile_d2a_probe() {
    println!("d2a-root-enumerate={}", root_enumeration_status());
    println!(
        "d2a-root-file-create={}",
        create_file_status(Path::new("d2a-created-file"))
    );
    println!(
        "d2a-root-directory-create={}",
        io_status(fs::create_dir("d2a-created-directory"))
    );
    let root_stream = named_stream_path(&std::env::current_dir().unwrap(), "d2a-created-stream");
    println!(
        "d2a-root-stream-create={}",
        create_file_status(&root_stream)
    );
    for (index, label) in ["repository", "profile", "appdata", "sibling"]
        .into_iter()
        .enumerate()
    {
        let read = PathBuf::from(std::env::var_os(format!("LAT_D2A_READ_{index}")).unwrap());
        let write = PathBuf::from(std::env::var_os(format!("LAT_D2A_WRITE_{index}")).unwrap());
        println!("d2a-read-{label}={}", read_status(&read));
        println!("d2a-write-{label}={}", append_status(&write));
    }
    for (index, label) in ["junction", "extended", "casefold", "long", "ads"]
        .into_iter()
        .enumerate()
    {
        let path = PathBuf::from(std::env::var_os(format!("LAT_D2A_PATH_{index}")).unwrap());
        println!("d2a-path-{label}={}", read_status(&path));
    }

    let local_app_data = std::env::var_os("LOCALAPPDATA");
    let reserved_environment_is_valid = local_app_data.as_ref().is_some_and(|local_app_data| {
        let expected_temp = Path::new(local_app_data).join("Temp");
        std::env::var_os("TEMP").as_deref() == Some(expected_temp.as_os_str())
            && std::env::var_os("TMP").as_deref() == Some(expected_temp.as_os_str())
    });
    let inherited_environment_is_absent = [
        "USERPROFILE",
        "HOMEDRIVE",
        "HOMEPATH",
        "APPDATA",
        "PATH",
        "LAT_D2A_PARENT_CREDENTIAL_CANARY",
    ]
    .into_iter()
    .all(|name| std::env::var_os(name).is_none());
    println!(
        "d2a-environment={}",
        if reserved_environment_is_valid && inherited_environment_is_absent {
            "clean"
        } else {
            "inherited"
        }
    );

    run_lpac_d2a_network_probe();
    println!(
        "d2a-registry-read={}",
        registry_read_status(&std::env::var("LAT_D2B_REGISTRY_KEY").unwrap_or_default())
    );
    println!(
        "d2a-registry-write={}",
        registry_write_status(&std::env::var("LAT_D2B_REGISTRY_KEY").unwrap_or_default())
    );
    println!(
        "d2a-credential-read={}",
        credential_read_status(&std::env::var("LAT_D2B_CREDENTIAL_PARENT").unwrap_or_default())
    );
    println!(
        "d2a-credential-enumerate={}",
        credential_enumerate_status(
            &std::env::var("LAT_D2B_CREDENTIAL_FILTER").unwrap_or_default()
        )
    );
    println!(
        "d2a-credential-write={}",
        credential_write_status(&std::env::var("LAT_D2B_CREDENTIAL_CHILD").unwrap_or_default())
    );
    println!(
        "d2a-pipe-read={}",
        pipe_connect_status(
            &std::env::var("LAT_D2B_PIPE_READ").unwrap_or_default(),
            GENERIC_READ,
        )
    );
    println!(
        "d2a-pipe-write={}",
        pipe_connect_status(
            &std::env::var("LAT_D2B_PIPE_WRITE").unwrap_or_default(),
            GENERIC_WRITE,
        )
    );
}

fn registry_read_status(subkey: &str) -> &'static str {
    let subkey = wide_nul(subkey);
    let mut key = ptr::null_mut();
    // SAFETY: subkey is NUL-terminated and key points to writable storage.
    let status =
        unsafe { RegOpenKeyExW(HKEY_CURRENT_USER, subkey.as_ptr(), 0, KEY_READ, &mut key) };
    if status != ERROR_SUCCESS {
        return protected_resource_status(status);
    }
    let key = OwnedRegistryKey(key);
    match read_registry_binary(key.0, REGISTRY_PARENT_VALUE) {
        Ok(_) => "success",
        Err(status) => protected_resource_status(status),
    }
}

fn registry_write_status(subkey: &str) -> &'static str {
    match create_registry_key(HKEY_CURRENT_USER, subkey, KEY_WRITE) {
        Ok((key, _)) => match set_registry_binary(key.0, REGISTRY_CHILD_MARKER, b"child marker") {
            Ok(()) => "success",
            Err(status) => protected_resource_status(status),
        },
        Err(status) => protected_resource_status(status),
    }
}

fn credential_read_status(target: &str) -> &'static str {
    match read_credential(target) {
        Ok(_) => "success",
        Err(status) => protected_resource_status(status),
    }
}

fn credential_enumerate_status(filter: &str) -> &'static str {
    match enumerate_credentials(filter) {
        Ok(_) => "success",
        Err(status) => protected_resource_status(status),
    }
}

fn credential_write_status(target: &str) -> &'static str {
    match write_credential(target, CREDENTIAL_BLOB) {
        Ok(()) => match delete_credential(target) {
            Ok(()) => "isolated-cleaned",
            Err(_) => "cleanup-failed",
        },
        Err(status) => protected_resource_status(status),
    }
}

fn protected_resource_status(status: u32) -> &'static str {
    match status {
        ERROR_ACCESS_DENIED => "denied",
        ERROR_FILE_NOT_FOUND | ERROR_NOT_FOUND => "not-found",
        ERROR_NO_SUCH_LOGON_SESSION => "no-logon-session",
        ERROR_NOT_SUPPORTED => "not-supported",
        ERROR_NOT_SUPPORTED_IN_APPCONTAINER => "not-supported-in-appcontainer",
        ERROR_INVALID_FUNCTION => "invalid-function",
        status if status == RPC_S_INVALID_BINDING as u32 => "rpc-invalid-binding",
        _ => "error",
    }
}

fn pipe_connect_status(name: &str, access: u32) -> &'static str {
    match connect_pipe(name, access) {
        Ok(_) => "success",
        Err(status) => protected_resource_status(status),
    }
}

fn run_lpac_d2a_network_probe() {
    let network_targets = [
        ("loopback", "LAT_D2A_LOOPBACK"),
        ("lan", "LAT_D2A_LAN"),
        ("internet", "LAT_D2A_INTERNET"),
    ];
    let addresses = network_targets.map(|(_, variable)| {
        std::env::var(variable)
            .ok()
            .and_then(|value| value.parse::<SocketAddr>().ok())
    });
    let (subsystem_status, connection_statuses) = probe_network_targets(&addresses);
    println!("d2a-network-subsystem={subsystem_status}");
    for ((label, _), status) in network_targets.into_iter().zip(connection_statuses) {
        println!("d2a-network-{label}={status}");
    }
}

fn root_enumeration_status() -> &'static str {
    match fs::read_dir(".") {
        Ok(mut entries) => {
            if entries.next().is_none() {
                "success"
            } else {
                "unexpected-entry"
            }
        }
        Err(error) if is_permission_denied(&error) => "denied",
        Err(_) => "other",
    }
}

fn read_status(path: &Path) -> &'static str {
    match fs::read(path) {
        Ok(_) => "allowed",
        Err(error) if is_permission_denied(&error) => "denied",
        Err(_) => "other",
    }
}

fn append_status(path: &Path) -> &'static str {
    match OpenOptions::new().append(true).open(path) {
        Ok(mut file) => match file.write_all(b"x") {
            Ok(()) => "allowed",
            Err(error) if is_permission_denied(&error) => "denied",
            Err(_) => "other",
        },
        Err(error) if is_permission_denied(&error) => "denied",
        Err(_) => "other",
    }
}

fn create_file_status(path: &Path) -> &'static str {
    match OpenOptions::new().create_new(true).write(true).open(path) {
        Ok(_) => "allowed",
        Err(error) if is_permission_denied(&error) => "denied",
        Err(_) => "other",
    }
}

fn io_status(result: std::io::Result<()>) -> &'static str {
    match result {
        Ok(()) => "allowed",
        Err(error) if is_permission_denied(&error) => "denied",
        Err(_) => "other",
    }
}

fn probe_network_targets(addresses: &[Option<SocketAddr>; 3]) -> (&'static str, [&'static str; 3]) {
    let mut data = WSADATA::default();
    // SAFETY: data is writable for WSADATA and the requested version is Winsock 2.2.
    let startup = unsafe { WSAStartup(0x0202, &mut data) };
    if startup != 0 {
        let status = if startup == WSASYSCALLFAILURE {
            "subsystem-denied"
        } else {
            "subsystem-error"
        };
        return (status, [status; 3]);
    }
    let _winsock = WinsockSession;
    (
        "ready",
        addresses.map(|address| address.as_ref().map(connect_status).unwrap_or("invalid")),
    )
}

fn connect_status(address: &SocketAddr) -> &'static str {
    let IpAddr::V4(ip) = address.ip() else {
        return "invalid";
    };
    // SAFETY: Winsock was initialized by probe_network_targets and the constants
    // describe an IPv4 TCP stream socket.
    let socket = unsafe { socket(i32::from(AF_INET), SOCK_STREAM, IPPROTO_TCP) };
    if socket == INVALID_SOCKET {
        // SAFETY: this reads the calling thread's last Winsock error immediately
        // after the failed socket call.
        let error = unsafe { WSAGetLastError() };
        return match error {
            WSAEACCES => "denied-socket",
            WSAEPROVIDERFAILEDINIT => "provider-init-failed",
            _ => "socket-error",
        };
    }
    let socket = OwnedSocket(socket);
    let mut nonblocking = 1_u32;
    // SAFETY: socket is live and nonblocking points to writable u32 storage.
    if unsafe { ioctlsocket(socket.0, FIONBIO, &mut nonblocking) } == SOCKET_ERROR {
        return "socket-error";
    }
    let target = SOCKADDR_IN {
        sin_family: AF_INET,
        sin_port: address.port().to_be(),
        sin_addr: IN_ADDR {
            S_un: IN_ADDR_0 {
                S_addr: u32::from_ne_bytes(ip.octets()),
            },
        },
        sin_zero: [0; 8],
    };
    // SAFETY: socket is live and target is a fully initialized IPv4 sockaddr
    // whose byte length matches the value passed to connect.
    let connected = unsafe {
        connect(
            socket.0,
            (&target as *const SOCKADDR_IN).cast::<SOCKADDR>(),
            std::mem::size_of::<SOCKADDR_IN>() as i32,
        )
    };
    if connected == 0 {
        return "allowed";
    }
    // SAFETY: this reads the calling thread's last Winsock error immediately
    // after the failed connect call.
    let error = unsafe { WSAGetLastError() };
    if error == WSAEACCES {
        return "denied-connect";
    }
    if !matches!(error, WSAEWOULDBLOCK | WSAEINPROGRESS) {
        return "other";
    }

    let mut poll = WSAPOLLFD {
        fd: socket.0,
        events: POLLOUT,
        revents: 0,
    };
    // SAFETY: poll is writable for one WSAPOLLFD and the timeout is bounded.
    let poll_result = unsafe { WSAPoll(&mut poll, 1, 500) };
    if poll_result == 0 {
        return "timeout";
    }
    if poll_result == SOCKET_ERROR {
        return "other";
    }
    let mut socket_error = 0_i32;
    let mut socket_error_bytes = std::mem::size_of::<i32>() as i32;
    // SAFETY: socket is live and both output pointers are writable for the
    // declared SO_ERROR integer size.
    if unsafe {
        getsockopt(
            socket.0,
            SOL_SOCKET,
            SO_ERROR,
            (&mut socket_error as *mut i32).cast(),
            &mut socket_error_bytes,
        )
    } == SOCKET_ERROR
        || socket_error_bytes != std::mem::size_of::<i32>() as i32
    {
        return "other";
    }
    match socket_error {
        0 => "allowed",
        WSAEACCES => "denied-connect",
        _ => "other",
    }
}

fn is_permission_denied(error: &std::io::Error) -> bool {
    error.kind() == std::io::ErrorKind::PermissionDenied
        || matches!(error.raw_os_error(), Some(5 | 10_013))
}

struct WinsockSession;

impl Drop for WinsockSession {
    fn drop(&mut self) {
        // SAFETY: WinsockSession is created only after a successful WSAStartup.
        unsafe {
            WSACleanup();
        }
    }
}

struct OwnedSocket(SOCKET);

impl Drop for OwnedSocket {
    fn drop(&mut self) {
        // SAFETY: OwnedSocket is created only from a non-INVALID_SOCKET result.
        unsafe {
            closesocket(self.0);
        }
    }
}

fn current_process_token_flag(information_class: i32) -> u32 {
    let mut token = std::ptr::null_mut();
    // SAFETY: token points to writable handle storage and the pseudo-handle is valid.
    assert_ne!(
        unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) },
        0
    );
    let flag = token_flag(token, information_class);
    // SAFETY: token was returned by OpenProcessToken and remains owned here.
    assert_ne!(unsafe { CloseHandle(token) }, 0);
    flag
}

fn current_process_token_group_count(information_class: i32) -> u32 {
    let mut token = std::ptr::null_mut();
    // SAFETY: token points to writable handle storage and the pseudo-handle is valid.
    assert_ne!(
        unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) },
        0
    );
    let group_count = token_group_count(token, information_class);
    // SAFETY: token was returned by OpenProcessToken and remains owned here.
    assert_ne!(unsafe { CloseHandle(token) }, 0);
    group_count
}

fn token_group_count(token: windows_sys::Win32::Foundation::HANDLE, information_class: i32) -> u32 {
    let mut required = 0_u32;
    // SAFETY: this sizing query intentionally supplies no buffer and writes only required.
    let queried = unsafe {
        GetTokenInformation(
            token,
            information_class,
            std::ptr::null_mut(),
            0,
            &mut required,
        )
    };
    let query_error = unsafe { GetLastError() };
    assert_eq!(queried, 0);
    assert_eq!(query_error, ERROR_INSUFFICIENT_BUFFER);
    assert!(required as usize >= std::mem::size_of::<u32>());

    let words = (required as usize).div_ceil(std::mem::size_of::<usize>());
    let mut buffer = vec![0_usize; words];
    let mut returned = 0_u32;
    // SAFETY: the usize buffer is suitably aligned, writable for required bytes, and token is
    // valid for TOKEN_QUERY.
    let queried = unsafe {
        GetTokenInformation(
            token,
            information_class,
            buffer.as_mut_ptr().cast(),
            required,
            &mut returned,
        )
    };
    assert_ne!(
        queried,
        0,
        "token information class {information_class} failed with Windows error {}",
        unsafe { GetLastError() }
    );
    assert!(returned as usize >= std::mem::size_of::<u32>());
    assert!(returned <= required);

    // SAFETY: the usize buffer is aligned for u32 and the returned-length check covers it.
    let group_count = unsafe { buffer.as_ptr().cast::<u32>().read() };
    if group_count == 0 {
        return 0;
    }
    let groups_bytes = std::mem::offset_of!(TOKEN_GROUPS, Groups)
        .checked_add(
            usize::try_from(group_count)
                .unwrap()
                .checked_mul(std::mem::size_of::<SID_AND_ATTRIBUTES>())
                .unwrap(),
        )
        .unwrap();
    assert!(returned as usize >= groups_bytes);
    group_count
}

fn token_flag(token: windows_sys::Win32::Foundation::HANDLE, information_class: i32) -> u32 {
    let mut flag = 0_u32;
    let mut returned = 0_u32;
    // SAFETY: flag is writable for the declared size and token is a valid query handle.
    let queried = unsafe {
        GetTokenInformation(
            token,
            information_class,
            (&mut flag as *mut u32).cast(),
            std::mem::size_of::<u32>() as u32,
            &mut returned,
        )
    };
    assert_ne!(
        queried,
        0,
        "token information class {information_class} failed with Windows error {}",
        unsafe { GetLastError() }
    );
    assert_eq!(returned, std::mem::size_of::<u32>() as u32);
    flag
}

#[cfg(feature = "test-seams")]
struct TestOnlyBoundary {
    cwd: PathBuf,
    fail_before_resume: bool,
    identity_receipt: String,
    acl_receipt: String,
    claims_mismatch: Option<BoundaryMismatch>,
    prepare_calls: Arc<AtomicUsize>,
    prepare_block: Option<Arc<BoundaryBlock>>,
    verification_block: Option<Arc<BoundaryBlock>>,
    cleanup_count: Arc<AtomicUsize>,
    allow_expected_writes: bool,
    observed_writes: Vec<ObservedProcessWrite>,
}

#[cfg(feature = "test-seams")]
struct BoundaryBlock {
    entered: mpsc::Sender<()>,
    release: Mutex<mpsc::Receiver<()>>,
    blocked: std::sync::atomic::AtomicBool,
}

#[cfg(feature = "test-seams")]
impl BoundaryBlock {
    fn new() -> (Arc<Self>, mpsc::Receiver<()>, mpsc::Sender<()>) {
        let (entered, entered_receiver) = mpsc::channel();
        let (release_sender, release) = mpsc::channel();
        (
            Arc::new(Self {
                entered,
                release: Mutex::new(release),
                blocked: std::sync::atomic::AtomicBool::new(false),
            }),
            entered_receiver,
            release_sender,
        )
    }

    fn wait_once(&self) {
        if self
            .blocked
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return;
        }
        self.entered.send(()).unwrap();
        self.release.lock().unwrap().recv().unwrap();
    }
}

#[cfg(feature = "test-seams")]
struct LeaseReplacingBoundary {
    inner: TestOnlyBoundary,
    authority: ProcessFenceAuthority,
}

#[cfg(feature = "test-seams")]
impl IsolatedWorkerBoundaryAdapter for LeaseReplacingBoundary {
    fn prepare(
        &self,
        request: &AuthorizedProcessRequest,
    ) -> Result<PreparedIsolatedWorkerBoundary, PortError> {
        self.inner.prepare(request)
    }

    fn verify_before_resume(
        &self,
        request: &AuthorizedProcessRequest,
        prepared: &PreparedIsolatedWorkerBoundary,
    ) -> Result<(), PortError> {
        self.inner.verify_before_resume(request, prepared)?;
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

struct ReplaceableLeaseStore {
    current: AtomicU64,
}

impl ReplaceableLeaseStore {
    const fn new(token: u64) -> Self {
        Self {
            current: AtomicU64::new(token),
        }
    }
}

impl ExecutorLeaseStore for ReplaceableLeaseStore {
    fn acquire(&self, request: AcquireLease) -> Result<LeaseSnapshot, PortError> {
        self.current.store(8, Ordering::SeqCst);
        Ok(LeaseSnapshot {
            task_id: request.task_id,
            holder_run_id: request.holder_run_id,
            token: FencingToken::new(8).unwrap(),
            state: LeaseState::Active,
            acquired_at: request.acquired_at,
            expires_at: request.expires_at,
            released_at: None,
        })
    }

    fn revoke(&self, request: RevokeLease) -> Result<(), PortError> {
        let current = FencingToken::new(self.current.load(Ordering::SeqCst)).unwrap();
        if current != request.claim.token() {
            return Err(PortError::stale_lease(current, request.claim.token()));
        }
        self.current.store(8, Ordering::SeqCst);
        Ok(())
    }

    fn fence_stale(&self) -> Result<Vec<LeaseSnapshot>, PortError> {
        unreachable!()
    }

    fn assert_current(&self, claim: LeaseClaim) -> Result<(), PortError> {
        let current = FencingToken::new(self.current.load(Ordering::SeqCst)).unwrap();
        if current == claim.token() {
            Ok(())
        } else {
            Err(PortError::stale_lease(current, claim.token()))
        }
    }
}

#[derive(Debug, Clone, Copy)]
#[cfg(feature = "test-seams")]
enum BoundaryMismatch {
    Identity,
    Acl,
    Task,
    ExecutorFence,
    Tier,
    CwdRootIdentity,
    NetworkEnforcement,
    NetworkDigest,
    ExecutableIdentity,
    ExecutableDigest,
    EnvironmentProfile,
    EnvironmentValues,
    Limits,
    ExpectedWrites,
    Argv,
    Timeout,
}

#[derive(Debug, Clone, Copy)]
#[cfg(feature = "test-seams")]
enum LaunchMutation {
    BrokeredWorktree,
    ExpectedWrite,
}

#[derive(Debug, Clone, Copy)]
#[cfg(feature = "test-seams")]
enum CoordinatedLeaseChange {
    Acquire,
    Revoke,
}

#[cfg(feature = "test-seams")]
impl CoordinatedLeaseChange {
    const fn name(self) -> &'static str {
        match self {
            Self::Acquire => "acquire",
            Self::Revoke => "revoke",
        }
    }

    fn execute(self, authority: &ProcessFenceAuthority) -> Result<u64, PortError> {
        match self {
            Self::Acquire => authority
                .acquire_lease(AcquireLease {
                    task_id: TaskId::new("task-1").unwrap(),
                    holder_run_id: RunId::new("run-2").unwrap(),
                    expected_fencing_epoch: 7,
                    acquired_at: "2026-07-29T00:00:00Z".to_owned(),
                    expires_at: "2026-07-29T01:00:00Z".to_owned(),
                })
                .map(|snapshot| snapshot.token.get()),
            Self::Revoke => authority
                .revoke_lease(RevokeLease {
                    claim: LeaseClaim::new(
                        TaskId::new("task-1").unwrap(),
                        RunId::new("run-1").unwrap(),
                        FencingToken::new(7).unwrap(),
                    ),
                    revoked_at: "2026-07-29T00:30:00Z".to_owned(),
                })
                .map(|()| 8),
        }
    }
}

#[derive(Debug, Clone, Copy)]
#[cfg(feature = "test-seams")]
enum WriteEvidenceMutation {
    Missing,
    Extra,
    Duplicate,
    AmbiguousApproval,
    Capability,
    Root,
    Path,
}

#[cfg(feature = "test-seams")]
impl TestOnlyBoundary {
    fn valid(cwd: PathBuf) -> Self {
        Self {
            cwd,
            fail_before_resume: false,
            identity_receipt: "test-only-identity".to_owned(),
            acl_receipt: "test-only-acl".to_owned(),
            claims_mismatch: None,
            prepare_calls: Arc::new(AtomicUsize::new(0)),
            prepare_block: None,
            verification_block: None,
            cleanup_count: Arc::new(AtomicUsize::new(0)),
            allow_expected_writes: false,
            observed_writes: Vec::new(),
        }
    }
}

#[cfg(feature = "test-seams")]
impl IsolatedWorkerBoundaryAdapter for TestOnlyBoundary {
    fn prepare(
        &self,
        request: &AuthorizedProcessRequest,
    ) -> Result<PreparedIsolatedWorkerBoundary, local_agent_terminal_application::PortError> {
        self.prepare_calls.fetch_add(1, Ordering::AcqRel);
        if let Some(block) = &self.prepare_block {
            block.wait_once();
        }
        if !request.expected_writes.is_empty() && !self.allow_expected_writes {
            return Err(local_agent_terminal_application::PortError::failure(
                local_agent_terminal_application::SafeErrorClassification::PermissionDenied,
                local_agent_terminal_application::Retryability::NonRetryable,
            ));
        }
        let mut claims = IsolatedWorkerBoundaryClaims::from_request(request);
        if let Some(mismatch) = self.claims_mismatch {
            mutate_claims(&mut claims, mismatch);
        }
        PreparedIsolatedWorkerBoundary::new(
            &self.cwd,
            &self.identity_receipt,
            &self.acl_receipt,
            (!request.expected_writes.is_empty()).then(|| "test-only-write-scope".to_owned()),
            claims,
        )
        .map(|prepared| prepared.with_cleanup_counter_for_test(self.cleanup_count.clone()))
    }

    fn verify_before_resume(
        &self,
        _request: &AuthorizedProcessRequest,
        _prepared: &PreparedIsolatedWorkerBoundary,
    ) -> Result<(), local_agent_terminal_application::PortError> {
        if let Some(block) = &self.verification_block {
            block.wait_once();
        }
        if self.fail_before_resume {
            Err(local_agent_terminal_application::PortError::failure(
                local_agent_terminal_application::SafeErrorClassification::PermissionDenied,
                local_agent_terminal_application::Retryability::NonRetryable,
            ))
        } else {
            Ok(())
        }
    }

    fn observed_writes(
        &self,
        request: &AuthorizedProcessRequest,
        _prepared: &PreparedIsolatedWorkerBoundary,
    ) -> Result<Vec<ObservedProcessWrite>, local_agent_terminal_application::PortError> {
        if request.expected_writes.is_empty() {
            Ok(Vec::new())
        } else if self.allow_expected_writes {
            Ok(self.observed_writes.clone())
        } else {
            Err(local_agent_terminal_application::PortError::failure(
                local_agent_terminal_application::SafeErrorClassification::PermissionDenied,
                local_agent_terminal_application::Retryability::NonRetryable,
            ))
        }
    }
}

#[cfg(feature = "test-seams")]
fn mutate_claims(claims: &mut IsolatedWorkerBoundaryClaims, mismatch: BoundaryMismatch) {
    match mismatch {
        BoundaryMismatch::Identity | BoundaryMismatch::Acl => {}
        BoundaryMismatch::Task => {
            claims.executor_claim = LeaseClaim::new(
                TaskId::new("task-2").unwrap(),
                claims.executor_claim.holder_run_id().clone(),
                claims.executor_claim.token(),
            );
        }
        BoundaryMismatch::ExecutorFence => {
            claims.executor_fence = ProcessFenceAuthority::new(
                Arc::new(ReplaceableLeaseStore::new(7)),
                Arc::new(WorkspaceWriteCoordinator::new()),
            )
            .binding();
        }
        BoundaryMismatch::Tier => claims.trust_tier = ProcessTrustTier::BrokeredProcess,
        BoundaryMismatch::CwdRootIdentity => {
            let ProcessWorkingDirectory::IsolatedWorktree(resolved) = &mut claims.cwd else {
                unreachable!()
            };
            resolved.root_identity = CapabilityRootIdentity::new("wrong-worktree").unwrap();
        }
        BoundaryMismatch::NetworkEnforcement => {
            claims.network.receipt = NetworkEnforcementReceipt::new(
                "wrong-network",
                claims.network.profile_digest.clone(),
            )
            .unwrap();
        }
        BoundaryMismatch::NetworkDigest => claims.network.profile_digest = digest(b"wrong-network"),
        BoundaryMismatch::ExecutableIdentity => {
            claims.executable.file_identity =
                ExecutableFileIdentity::new("wrong-executable").unwrap()
        }
        BoundaryMismatch::ExecutableDigest => {
            claims.executable.sha256 = digest(b"wrong-executable")
        }
        BoundaryMismatch::EnvironmentProfile => {
            claims.environment.name = "wrong-environment".to_owned()
        }
        BoundaryMismatch::EnvironmentValues => {
            claims
                .environment
                .values
                .insert("EXTRA".to_owned(), "1".to_owned());
        }
        BoundaryMismatch::Limits => claims.limits.memory_limit_bytes += 1,
        BoundaryMismatch::ExpectedWrites => claims
            .expected_writes
            .push(authorized_write("unexpected.txt", "test-worktree")),
        BoundaryMismatch::Argv => claims.argv.push("extra".to_owned()),
        BoundaryMismatch::Timeout => claims.timeout_ms += 1,
    }
}

fn registered_lpac_launcher(root: &std::path::Path) -> WindowsProcessLauncher {
    WindowsProcessLauncher::with_lpac_boundary(vec![TrustedLpacWorktreeRegistration::new(
        TaskId::new("task-1").unwrap(),
        CapabilityRootIdentity::new("test-worktree").unwrap(),
        root,
    )
    .unwrap()])
    .unwrap()
}

#[cfg(feature = "test-seams")]
fn assert_real_lpac_lifecycle(execution_id: &ToolExecutionId) {
    assert_eq!(
        lpac_lifecycle_counts_for_test(execution_id),
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
}

#[cfg(not(feature = "test-seams"))]
fn assert_real_lpac_lifecycle(_: &ToolExecutionId) {}

struct DeniedCanary {
    read: PathBuf,
    write: PathBuf,
    read_contents: Vec<u8>,
    write_contents: Vec<u8>,
}

const REGISTRY_PARENT_VALUE: &str = "parent-value";
const REGISTRY_CHILD_MARKER: &str = "child-marker";
const REGISTRY_CONTENTS: &[u8] = b"task7 inert registry fixture";
static NEXT_REGISTRY_FIXTURE: AtomicU64 = AtomicU64::new(1);
const CREDENTIAL_BLOB: &[u8] = b"task7 inert credential blob";
static NEXT_PIPE_FIXTURE: AtomicU64 = AtomicU64::new(1);

struct RegistryFixture {
    subkey: String,
    key: Option<OwnedRegistryKey>,
    active: bool,
}

impl RegistryFixture {
    fn new() -> Self {
        let parent = open_registry_key("Software", KEY_READ | KEY_WRITE).unwrap();
        let child_name = format!(
            "LocalAgentTerminal-Task7-{}-{}",
            std::process::id(),
            NEXT_REGISTRY_FIXTURE.fetch_add(1, Ordering::Relaxed)
        );
        let (key, disposition) =
            create_registry_key(parent.0, &child_name, KEY_READ | KEY_WRITE).unwrap();
        let mut fixture = Self {
            subkey: format!(r"Software\{child_name}"),
            key: Some(key),
            active: disposition == REG_CREATED_NEW_KEY,
        };
        assert_eq!(disposition, REG_CREATED_NEW_KEY);
        let key = fixture.key.as_ref().unwrap().0;
        set_registry_binary(key, REGISTRY_PARENT_VALUE, REGISTRY_CONTENTS).unwrap();
        assert_eq!(
            read_registry_binary(key, REGISTRY_PARENT_VALUE).unwrap(),
            REGISTRY_CONTENTS
        );
        set_registry_binary(key, REGISTRY_PARENT_VALUE, b"parent write control").unwrap();
        assert_eq!(
            read_registry_binary(key, REGISTRY_PARENT_VALUE).unwrap(),
            b"parent write control"
        );
        set_registry_binary(key, REGISTRY_PARENT_VALUE, REGISTRY_CONTENTS).unwrap();
        assert_eq!(
            read_registry_binary(key, REGISTRY_CHILD_MARKER),
            Err(windows_sys::Win32::Foundation::ERROR_FILE_NOT_FOUND)
        );
        drop(fixture.key.take());
        fixture
    }

    fn assert_unchanged(&self) {
        let key = open_registry_key(&self.subkey, KEY_READ).unwrap();
        assert_eq!(
            read_registry_binary(key.0, REGISTRY_PARENT_VALUE).unwrap(),
            REGISTRY_CONTENTS
        );
        assert_eq!(
            read_registry_binary(key.0, REGISTRY_CHILD_MARKER),
            Err(windows_sys::Win32::Foundation::ERROR_FILE_NOT_FOUND)
        );
    }

    fn cleanup(mut self) {
        self.remove();
        assert!(matches!(
            open_registry_key(&self.subkey, KEY_READ),
            Err(ERROR_FILE_NOT_FOUND)
        ));
    }

    fn remove(&mut self) {
        if self.active {
            drop(self.key.take());
            let subkey = wide_nul(self.subkey.as_ref());
            // SAFETY: subkey is NUL-terminated and names only this test-owned tree.
            assert_eq!(
                unsafe { RegDeleteTreeW(HKEY_CURRENT_USER, subkey.as_ptr()) },
                ERROR_SUCCESS
            );
            self.active = false;
        }
    }
}

impl Drop for RegistryFixture {
    fn drop(&mut self) {
        if self.active {
            drop(self.key.take());
            let subkey = wide_nul(self.subkey.as_ref());
            // SAFETY: subkey is NUL-terminated and names only this test-owned tree.
            unsafe {
                RegDeleteTreeW(HKEY_CURRENT_USER, subkey.as_ptr());
            }
        }
    }
}

struct CredentialFixture {
    parent_target: String,
    child_target: String,
    filter: String,
    parent_owned: bool,
    child_owned: bool,
    child_target_was_absent: bool,
}

impl CredentialFixture {
    fn new() -> Self {
        let nonce = credential_nonce();
        Self::try_new_with_nonce(&nonce).unwrap()
    }

    fn try_new_with_nonce(nonce: &str) -> Result<Self, u32> {
        let prefix = format!("LocalAgentTerminal/Task7/{nonce}/");
        let mut fixture = Self {
            parent_target: format!("{prefix}parent"),
            child_target: format!("{prefix}child"),
            filter: format!("{prefix}*"),
            parent_owned: false,
            child_owned: false,
            child_target_was_absent: false,
        };
        require_absent_credential(&fixture.parent_target)?;
        require_absent_credential(&fixture.child_target)?;
        fixture.child_target_was_absent = true;
        write_credential(&fixture.parent_target, CREDENTIAL_BLOB)?;
        fixture.parent_owned = true;
        write_credential(&fixture.child_target, CREDENTIAL_BLOB)?;
        fixture.child_owned = true;
        delete_credential(&fixture.child_target)?;
        fixture.child_owned = false;
        fixture.assert_unchanged();
        Ok(fixture)
    }

    fn observe_child_ownership(&mut self) {
        match read_credential(&self.child_target) {
            Ok(_) if self.child_target_was_absent => self.child_owned = true,
            Ok(_) => panic!("credential child target was not reserved by this fixture"),
            Err(ERROR_NOT_FOUND) => {}
            Err(status) => panic!("credential child observation failed with status {status}"),
        }
    }

    fn assert_unchanged(&self) {
        assert_eq!(
            read_credential(&self.parent_target).unwrap(),
            CREDENTIAL_BLOB
        );
        assert_eq!(read_credential(&self.child_target), Err(ERROR_NOT_FOUND));
        let targets = enumerate_credentials(&self.filter).unwrap();
        assert_eq!(targets, vec![self.parent_target.clone()]);
    }

    fn cleanup(mut self) {
        self.observe_child_ownership();
        self.remove_owned();
        assert_eq!(read_credential(&self.parent_target), Err(ERROR_NOT_FOUND));
        assert_eq!(read_credential(&self.child_target), Err(ERROR_NOT_FOUND));
        assert_eq!(enumerate_credentials(&self.filter), Err(ERROR_NOT_FOUND));
    }

    fn remove_owned(&mut self) {
        if self.parent_owned {
            delete_credential(&self.parent_target).unwrap();
            self.parent_owned = false;
        }
        if self.child_owned {
            delete_credential(&self.child_target).unwrap();
            self.child_owned = false;
        }
    }
}

struct OwnedTestCredential {
    target: String,
    active: bool,
}

impl OwnedTestCredential {
    fn new(target: String, blob: &[u8]) -> Self {
        assert_eq!(read_credential(&target), Err(ERROR_NOT_FOUND));
        write_credential(&target, blob).unwrap();
        Self {
            target,
            active: true,
        }
    }

    fn cleanup(mut self) {
        delete_credential(&self.target).unwrap();
        self.active = false;
        assert_eq!(read_credential(&self.target), Err(ERROR_NOT_FOUND));
    }
}

impl Drop for OwnedTestCredential {
    fn drop(&mut self) {
        if self.active {
            let _ = delete_credential(&self.target);
        }
    }
}

impl Drop for CredentialFixture {
    fn drop(&mut self) {
        if self.child_target_was_absent
            && !self.child_owned
            && read_credential(&self.child_target).is_ok()
        {
            self.child_owned = true;
        }
        if self.parent_owned {
            let _ = delete_credential(&self.parent_target);
        }
        if self.child_owned {
            let _ = delete_credential(&self.child_target);
        }
    }
}

fn credential_nonce() -> String {
    let mut nonce = GUID::from_u128(0);
    // SAFETY: nonce points to writable GUID storage.
    let status = unsafe { UuidCreate(&mut nonce) };
    assert!(status == RPC_S_OK || status == RPC_S_UUID_LOCAL_ONLY);
    format!(
        "{:08x}-{:04x}-{:04x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        nonce.data1,
        nonce.data2,
        nonce.data3,
        nonce.data4[0],
        nonce.data4[1],
        nonce.data4[2],
        nonce.data4[3],
        nonce.data4[4],
        nonce.data4[5],
        nonce.data4[6],
        nonce.data4[7],
    )
}

fn require_absent_credential(target: &str) -> Result<(), u32> {
    match read_credential(target) {
        Err(ERROR_NOT_FOUND) => Ok(()),
        Ok(_) => Err(ERROR_ALREADY_EXISTS),
        Err(status) => Err(status),
    }
}

struct PipeSecurityDescriptor(OwnedLocalAllocation);

impl PipeSecurityDescriptor {
    fn for_current_user() -> Self {
        let user_sid = current_user_sid_string();
        let sddl = wide_nul(&format!("D:P(A;;GA;;;{user_sid})"));
        let mut descriptor = ptr::null_mut();
        // SAFETY: sddl is live and NUL-terminated; descriptor points to writable
        // storage that receives a LocalAlloc-owned security descriptor.
        assert_ne!(
            unsafe {
                ConvertStringSecurityDescriptorToSecurityDescriptorW(
                    sddl.as_ptr(),
                    SDDL_REVISION_1,
                    &mut descriptor,
                    ptr::null_mut(),
                )
            },
            0
        );
        Self(OwnedLocalAllocation(descriptor))
    }

    fn attributes(&self) -> SECURITY_ATTRIBUTES {
        SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: self.0.as_ptr(),
            bInheritHandle: 0,
        }
    }
}

struct OwnedLocalAllocation(*mut std::ffi::c_void);

impl OwnedLocalAllocation {
    fn as_ptr(&self) -> *mut std::ffi::c_void {
        self.0
    }
}

impl Drop for OwnedLocalAllocation {
    fn drop(&mut self) {
        // SAFETY: this pointer was allocated by a Windows API documented for LocalFree.
        unsafe {
            LocalFree(self.0);
        }
    }
}

struct OwnedTokenHandle(windows_sys::Win32::Foundation::HANDLE);

impl Drop for OwnedTokenHandle {
    fn drop(&mut self) {
        // SAFETY: this token handle is owned here.
        unsafe {
            CloseHandle(self.0);
        }
    }
}

fn current_user_sid_string() -> String {
    let mut token = ptr::null_mut();
    // SAFETY: the current-process pseudo-handle is valid and token is writable.
    assert_ne!(
        unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) },
        0
    );
    let token = OwnedTokenHandle(token);
    let mut required = 0;
    // SAFETY: this sizing query intentionally supplies no buffer.
    assert_eq!(
        unsafe { GetTokenInformation(token.0, TokenUser, ptr::null_mut(), 0, &mut required) },
        0
    );
    // SAFETY: GetTokenInformation failed on this thread.
    assert_eq!(unsafe { GetLastError() }, ERROR_INSUFFICIENT_BUFFER);
    let words = (required as usize).div_ceil(std::mem::size_of::<usize>());
    let mut buffer = vec![0_usize; words];
    // SAFETY: buffer is aligned and writable for the requested TOKEN_USER bytes.
    assert_ne!(
        unsafe {
            GetTokenInformation(
                token.0,
                TokenUser,
                buffer.as_mut_ptr().cast(),
                required,
                &mut required,
            )
        },
        0
    );
    // SAFETY: the successful query returned an aligned TOKEN_USER structure.
    let user = unsafe { &*buffer.as_ptr().cast::<TOKEN_USER>() };
    sid_string(user.User.Sid)
}

fn sid_string(sid: windows_sys::Win32::Security::PSID) -> String {
    let mut sid_text = ptr::null_mut();
    // SAFETY: sid is live for this call and sid_text is writable.
    assert_ne!(unsafe { ConvertSidToStringSidW(sid, &mut sid_text) }, 0);
    let sid_text = OwnedLocalAllocation(sid_text.cast());
    // SAFETY: successful conversion returned a NUL-terminated UTF-16 string.
    unsafe { wide_ptr_string(sid_text.as_ptr().cast()) }
}

struct NamedPipeFixture {
    read_name: String,
    write_name: String,
    security: PipeSecurityDescriptor,
}

impl NamedPipeFixture {
    fn new() -> Self {
        let id = NEXT_PIPE_FIXTURE.fetch_add(1, Ordering::Relaxed);
        Self {
            read_name: format!(
                r"\\.\pipe\LOCAL\LocalAgentTerminal-Task7-{}-{id}-read",
                std::process::id(),
            ),
            write_name: format!(
                r"\\.\pipe\LOCAL\LocalAgentTerminal-Task7-{}-{id}-write",
                std::process::id(),
            ),
            security: PipeSecurityDescriptor::for_current_user(),
        }
    }

    fn server(&self, name: &str) -> OwnedNamedPipe {
        let name = wide_nul(name);
        let security = self.security.attributes();
        // SAFETY: name is NUL-terminated and security points to the fixture-owned
        // descriptor for the duration of this call.
        let handle = unsafe {
            CreateNamedPipeW(
                name.as_ptr(),
                PIPE_ACCESS_DUPLEX,
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_NOWAIT | PIPE_REJECT_REMOTE_CLIENTS,
                1,
                0,
                0,
                0,
                &security,
            )
        };
        assert_ne!(handle, INVALID_HANDLE_VALUE);
        OwnedNamedPipe(handle)
    }

    fn prove_parent_connections(&self) {
        for (name, access) in [
            (&self.read_name, GENERIC_READ),
            (&self.write_name, GENERIC_WRITE),
        ] {
            let server = self.server(name);
            let client = connect_pipe(name, access).unwrap();
            assert!(server.accepted_connection());
            drop(client);
            server.disconnect();
        }
    }

    fn cleanup(self, read_server: OwnedNamedPipe, write_server: OwnedNamedPipe) {
        drop(read_server);
        drop(write_server);
        assert_eq!(
            connect_pipe(&self.read_name, GENERIC_READ).unwrap_err(),
            ERROR_FILE_NOT_FOUND
        );
        assert_eq!(
            connect_pipe(&self.write_name, GENERIC_WRITE).unwrap_err(),
            ERROR_FILE_NOT_FOUND
        );
    }
}

#[derive(Debug)]
struct OwnedNamedPipe(windows_sys::Win32::Foundation::HANDLE);

impl OwnedNamedPipe {
    fn allowed_sid_strings(&self) -> Vec<String> {
        let mut dacl = ptr::null_mut();
        let mut descriptor = ptr::null_mut();
        // SAFETY: the pipe handle is live and all requested output pointers are writable.
        assert_eq!(
            unsafe {
                GetSecurityInfo(
                    self.0,
                    SE_KERNEL_OBJECT,
                    DACL_SECURITY_INFORMATION,
                    ptr::null_mut(),
                    ptr::null_mut(),
                    &mut dacl,
                    ptr::null_mut(),
                    &mut descriptor,
                )
            },
            ERROR_SUCCESS
        );
        let _descriptor = OwnedLocalAllocation(descriptor);
        let mut information = ACL_SIZE_INFORMATION::default();
        // SAFETY: dacl belongs to the live descriptor and information is writable.
        assert_ne!(
            unsafe {
                GetAclInformation(
                    dacl,
                    (&mut information as *mut ACL_SIZE_INFORMATION).cast(),
                    std::mem::size_of::<ACL_SIZE_INFORMATION>() as u32,
                    AclSizeInformation,
                )
            },
            0
        );
        (0..information.AceCount)
            .map(|index| {
                let mut raw_ace = ptr::null_mut();
                // SAFETY: index is within the queried ACE count and raw_ace is writable.
                assert_ne!(unsafe { GetAce(dacl, index, &mut raw_ace) }, 0);
                // SAFETY: this test-owned DACL is expected to contain access-allowed ACEs.
                let ace = unsafe { &*raw_ace.cast::<ACCESS_ALLOWED_ACE>() };
                assert_eq!(ace.Header.AceType, 0);
                sid_string((&ace.SidStart as *const u32).cast_mut().cast())
            })
            .collect()
    }

    fn accepted_connection(&self) -> bool {
        // SAFETY: the server handle is live; PIPE_NOWAIT makes this observation bounded.
        if unsafe { ConnectNamedPipe(self.0, ptr::null_mut()) } != 0 {
            return true;
        }
        // SAFETY: ConnectNamedPipe failed on this thread, so GetLastError returns its status.
        match unsafe { GetLastError() } {
            ERROR_PIPE_CONNECTED => true,
            ERROR_PIPE_LISTENING => false,
            status => panic!("unexpected named-pipe observation status {status}"),
        }
    }

    fn disconnect(&self) {
        // SAFETY: the server handle is live and has an accepted parent connection.
        assert_ne!(unsafe { DisconnectNamedPipe(self.0) }, 0);
    }
}

impl Drop for OwnedNamedPipe {
    fn drop(&mut self) {
        // SAFETY: this server handle is owned here.
        unsafe {
            CloseHandle(self.0);
        }
    }
}

#[derive(Debug)]
struct OwnedPipeClient(windows_sys::Win32::Foundation::HANDLE);

impl Drop for OwnedPipeClient {
    fn drop(&mut self) {
        // SAFETY: this client handle is owned here.
        unsafe {
            CloseHandle(self.0);
        }
    }
}

fn connect_pipe(name: &str, access: u32) -> Result<OwnedPipeClient, u32> {
    let name = wide_nul(name);
    // SAFETY: name is NUL-terminated; optional security and template handles are null.
    let handle = unsafe {
        CreateFileW(
            name.as_ptr(),
            access,
            0,
            ptr::null(),
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            ptr::null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        // SAFETY: CreateFileW failed on this thread, so GetLastError returns its status.
        Err(unsafe { GetLastError() })
    } else {
        Ok(OwnedPipeClient(handle))
    }
}

struct OwnedRegistryKey(windows_sys::Win32::System::Registry::HKEY);

impl Drop for OwnedRegistryKey {
    fn drop(&mut self) {
        // SAFETY: this handle was returned by RegCreateKeyExW and is owned here.
        unsafe {
            RegCloseKey(self.0);
        }
    }
}

fn create_registry_key(
    root: windows_sys::Win32::System::Registry::HKEY,
    subkey: &str,
    access: u32,
) -> Result<(OwnedRegistryKey, u32), u32> {
    let subkey = wide_nul(subkey);
    let mut key = ptr::null_mut();
    let mut disposition = 0;
    // SAFETY: root is live; subkey is NUL-terminated; output storage is valid;
    // optional pointers are null.
    let status = unsafe {
        RegCreateKeyExW(
            root,
            subkey.as_ptr(),
            0,
            ptr::null(),
            0,
            access,
            ptr::null(),
            &mut key,
            &mut disposition,
        )
    };
    if status == ERROR_SUCCESS {
        Ok((OwnedRegistryKey(key), disposition))
    } else {
        Err(status)
    }
}

fn open_registry_key(subkey: &str, access: u32) -> Result<OwnedRegistryKey, u32> {
    let subkey = wide_nul(subkey);
    let mut key = ptr::null_mut();
    // SAFETY: subkey is NUL-terminated and key points to writable storage.
    let status = unsafe { RegOpenKeyExW(HKEY_CURRENT_USER, subkey.as_ptr(), 0, access, &mut key) };
    if status == ERROR_SUCCESS {
        Ok(OwnedRegistryKey(key))
    } else {
        Err(status)
    }
}

fn set_registry_binary(
    key: windows_sys::Win32::System::Registry::HKEY,
    name: &str,
    value: &[u8],
) -> Result<(), u32> {
    let name = wide_nul(name);
    // SAFETY: key is live; name is NUL-terminated; value points to value.len() bytes.
    let status = unsafe {
        RegSetValueExW(
            key,
            name.as_ptr(),
            0,
            REG_BINARY,
            value.as_ptr(),
            u32::try_from(value.len()).unwrap(),
        )
    };
    (status == ERROR_SUCCESS).then_some(()).ok_or(status)
}

fn read_registry_binary(
    key: windows_sys::Win32::System::Registry::HKEY,
    name: &str,
) -> Result<Vec<u8>, u32> {
    let name = wide_nul(name);
    let mut value = [0_u8; 128];
    let mut size = value.len() as u32;
    // SAFETY: key is live; name is NUL-terminated; value and size are writable.
    let status = unsafe {
        RegGetValueW(
            key,
            ptr::null(),
            name.as_ptr(),
            RRF_RT_REG_BINARY,
            ptr::null_mut(),
            value.as_mut_ptr().cast(),
            &mut size,
        )
    };
    if status == ERROR_SUCCESS {
        Ok(value[..size as usize].to_vec())
    } else {
        Err(status)
    }
}

fn write_credential(target: &str, blob: &[u8]) -> Result<(), u32> {
    let target = wide_nul(target);
    let username = wide_nul("task7");
    let credential = CREDENTIALW {
        Type: CRED_TYPE_GENERIC,
        TargetName: target.as_ptr().cast_mut(),
        CredentialBlobSize: u32::try_from(blob.len()).unwrap(),
        CredentialBlob: blob.as_ptr().cast_mut(),
        Persist: CRED_PERSIST_SESSION,
        UserName: username.as_ptr().cast_mut(),
        ..CREDENTIALW::default()
    };
    // SAFETY: all credential pointers reference live buffers for the duration of the call.
    if unsafe { CredWriteW(&credential, 0) } != 0 {
        Ok(())
    } else {
        // SAFETY: CredWriteW failed on this thread, so GetLastError returns its status.
        Err(unsafe { GetLastError() })
    }
}

fn read_credential(target: &str) -> Result<Vec<u8>, u32> {
    let target = wide_nul(target);
    let mut credential = ptr::null_mut();
    // SAFETY: target is NUL-terminated and credential points to writable storage.
    if unsafe { CredReadW(target.as_ptr(), CRED_TYPE_GENERIC, 0, &mut credential) } == 0 {
        // SAFETY: CredReadW failed on this thread, so GetLastError returns its status.
        return Err(unsafe { GetLastError() });
    }
    let credential = OwnedCredentialBuffer(credential.cast());
    // SAFETY: successful CredReadW returns one valid CREDENTIALW allocation.
    let credential = unsafe { &*credential.0.cast::<CREDENTIALW>() };
    // SAFETY: CredentialBlob points to CredentialBlobSize readable bytes.
    Ok(unsafe {
        std::slice::from_raw_parts(
            credential.CredentialBlob,
            credential.CredentialBlobSize as usize,
        )
        .to_vec()
    })
}

fn enumerate_credentials(filter: &str) -> Result<Vec<String>, u32> {
    let filter = wide_nul(filter);
    let mut count = 0;
    let mut credentials = ptr::null_mut();
    // SAFETY: filter is NUL-terminated and both output pointers are writable.
    if unsafe { CredEnumerateW(filter.as_ptr(), 0, &mut count, &mut credentials) } == 0 {
        // SAFETY: CredEnumerateW failed on this thread, so GetLastError returns its status.
        return Err(unsafe { GetLastError() });
    }
    let credentials = OwnedCredentialBuffer(credentials.cast());
    // SAFETY: successful CredEnumerateW returns count pointers to valid CREDENTIALW values.
    let credentials = unsafe {
        std::slice::from_raw_parts(credentials.0.cast::<*mut CREDENTIALW>(), count as usize)
    };
    let mut targets = credentials
        .iter()
        .map(|credential| {
            // SAFETY: each returned credential and TargetName are valid until CredFree.
            unsafe { wide_ptr_string((**credential).TargetName) }
        })
        .collect::<Vec<_>>();
    targets.sort();
    Ok(targets)
}

fn delete_credential(target: &str) -> Result<(), u32> {
    let target = wide_nul(target);
    // SAFETY: target is NUL-terminated.
    if unsafe { CredDeleteW(target.as_ptr(), CRED_TYPE_GENERIC, 0) } != 0 {
        Ok(())
    } else {
        // SAFETY: CredDeleteW failed on this thread, so GetLastError returns its status.
        Err(unsafe { GetLastError() })
    }
}

struct OwnedCredentialBuffer(*mut std::ffi::c_void);

impl Drop for OwnedCredentialBuffer {
    fn drop(&mut self) {
        // SAFETY: this allocation was returned by CredReadW or CredEnumerateW.
        unsafe {
            CredFree(self.0);
        }
    }
}

unsafe fn wide_ptr_string(value: *const u16) -> String {
    let mut length = 0;
    // SAFETY: caller guarantees value points to a NUL-terminated Windows string.
    while unsafe { *value.add(length) } != 0 {
        length += 1;
    }
    // SAFETY: caller guarantees the first length elements are readable.
    String::from_utf16(unsafe { std::slice::from_raw_parts(value, length) }).unwrap()
}

fn wide_nul(value: &str) -> Vec<u16> {
    std::ffi::OsStr::new(value)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

impl DeniedCanary {
    fn new(label: &str, directory: &Path) -> Self {
        let read = directory.join(format!("{label}-read.bin"));
        let write = directory.join(format!("{label}-write.bin"));
        let read_contents = format!("{label} read canary").into_bytes();
        let write_contents = format!("{label} write canary").into_bytes();
        fs::write(&read, &read_contents).unwrap();
        fs::write(&write, &write_contents).unwrap();
        assert_eq!(fs::read(&read).unwrap(), read_contents);
        fs::write(&write, b"parent write control").unwrap();
        assert_eq!(fs::read(&write).unwrap(), b"parent write control");
        fs::write(&write, &write_contents).unwrap();
        Self {
            read,
            write,
            read_contents,
            write_contents,
        }
    }

    fn assert_unchanged(&self) {
        assert_eq!(fs::read(&self.read).unwrap(), self.read_contents);
        assert_eq!(fs::read(&self.write).unwrap(), self.write_contents);
    }
}

fn named_stream_path(path: &Path, name: &str) -> PathBuf {
    let mut stream = path.as_os_str().to_os_string();
    stream.push(format!(":{name}"));
    PathBuf::from(stream)
}

fn extended_length_path(path: &Path) -> PathBuf {
    let canonical = fs::canonicalize(path).unwrap();
    if path_text(&canonical).starts_with(r"\\?\") {
        canonical
    } else {
        PathBuf::from(format!(r"\\?\{}", canonical.display()))
    }
}

fn path_text(path: &Path) -> String {
    path.to_str()
        .expect("test fixture path must be Unicode")
        .to_owned()
}

fn create_junction(target: &Path, link: &Path) {
    let output = Command::new("cmd.exe")
        .args(["/D", "/C", "mklink", "/J"])
        .arg(link)
        .arg(target)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn host_lan_ip() -> IpAddr {
    let route_probe = UdpSocket::bind(("0.0.0.0", 0)).unwrap();
    route_probe.connect(("192.0.2.1", 9)).unwrap();
    let ip = route_probe.local_addr().unwrap().ip();
    assert!(
        !ip.is_loopback() && !ip.is_unspecified(),
        "no host LAN address"
    );
    ip
}

fn prove_parent_connection(listener: &TcpListener) {
    let address = listener.local_addr().unwrap();
    let connection = TcpStream::connect_timeout(&address, Duration::from_secs(1)).unwrap();
    let (accepted, _) = listener.accept().unwrap();
    drop(connection);
    drop(accepted);
}

fn assert_no_pending_connection(listener: &TcpListener) {
    listener.set_nonblocking(true).unwrap();
    let error = listener
        .accept()
        .expect_err("LPAC child reached a denied listener");
    assert_eq!(error.kind(), std::io::ErrorKind::WouldBlock);
}

fn network_observations(stdout: &str) -> BTreeSet<String> {
    stdout
        .lines()
        .filter_map(|line| line.strip_prefix("d2a-network-"))
        .map(|line| format!("network-{line}"))
        .collect()
}

fn lpac_identity_environment() -> BTreeMap<String, String> {
    BTreeMap::from([("LAT_PROCESS_HELPER".to_owned(), "lpac-identity".to_owned())])
}

fn lpac_marker_request(execution_id: &str, marker: &std::path::Path) -> AuthorizedProcessRequest {
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
    request.execution_id = ToolExecutionId::new(execution_id).unwrap();
    request
}

fn assert_lpac_rejected_before_resume(
    launcher: &WindowsProcessLauncher,
    request: AuthorizedProcessRequest,
    marker: &std::path::Path,
    suspended_child_expected: bool,
) {
    let execution_id = request.execution_id.clone();

    assert!(launcher.execute(request).is_err());
    assert!(!marker.exists());
    assert!(launcher.cancel(&execution_id).is_err());
    #[cfg(feature = "test-seams")]
    {
        let counts = lpac_lifecycle_counts_for_test(&execution_id);
        if suspended_child_expected {
            assert_eq!(counts.profiles_created, 1);
            assert_eq!(counts.profiles_deleted, 1);
            assert_eq!(counts.acl_grants, 2);
            assert_eq!(counts.acl_revokes, 2);
            assert_eq!(counts.suspended_children_created, 1);
            assert_eq!(counts.resumes_succeeded, 0);
        } else {
            assert_eq!(counts, LpacLifecycleCountsForTest::default());
        }
    }
    #[cfg(not(feature = "test-seams"))]
    let _ = suspended_child_expected;
}

fn request(argv: Vec<String>, environment: BTreeMap<String, String>) -> AuthorizedProcessRequest {
    let task_id = TaskId::new("task-1").unwrap();
    let executable_path = std::env::current_exe().unwrap();
    let executable_digest = digest(&fs::read(&executable_path).unwrap());
    let executables = ExecutableRegistry::load(
        vec![TrustedExecutableRegistration::new(
            "test-helper",
            "test-version",
            &executable_path,
            executable_digest,
        )
        .unwrap()],
        Arc::new(WindowsExecutableInspector),
    )
    .unwrap();
    let executable = executables.resolve("test-helper", "test-version").unwrap();
    let network_digest = digest(b"network-profile");
    AuthorizedProcessRequest {
        execution_id: ToolExecutionId::new("execution-1").unwrap(),
        trust_tier: ProcessTrustTier::IsolatedWorker,
        executable,
        argv,
        cwd: ProcessWorkingDirectory::IsolatedWorktree(ResolvedCapability {
            capability: CapabilityRef::worktree(task_id.clone(), ".").unwrap(),
            content_digest: None,
            root_identity: CapabilityRootIdentity::new("test-worktree").unwrap(),
            target: ResolvedCapabilityTarget::Root,
        }),
        environment: ResolvedEnvironmentProfile {
            name: "test-empty-parent".to_owned(),
            values: environment,
            digest: digest(b"environment-profile"),
        },
        network: EnforcedNetworkProfile {
            profile: NetworkProfile::Denied,
            profile_digest: network_digest.clone(),
            receipt: NetworkEnforcementReceipt::new("test-network", network_digest).unwrap(),
        },
        timeout_ms: 5_000,
        limits: ProcessLimits {
            memory_limit_bytes: 256 * 1024 * 1024,
            cpu_time_limit_ms: 5_000,
            max_stdout_bytes: 64 * 1024,
            max_stderr_bytes: 64 * 1024,
            max_active_processes: 8,
        },
        expected_writes: Vec::new(),
        executor_claim: LeaseClaim::new(
            task_id,
            RunId::new("run-1").unwrap(),
            FencingToken::new(7).unwrap(),
        ),
        executor_fence: ProcessFenceAuthority::new(
            Arc::new(ReplaceableLeaseStore::new(7)),
            Arc::new(WorkspaceWriteCoordinator::new()),
        )
        .binding(),
    }
}

fn authorized_write(path: &str, root_identity: &str) -> AuthorizedExpectedWrite {
    let task_id = TaskId::new("task-1").unwrap();
    let capability = CapabilityRef::worktree(task_id.clone(), path).unwrap();
    let expected = ExpectedWrite::new(capability.clone()).unwrap();
    let target = if path == "." {
        ResolvedCapabilityTarget::Root
    } else {
        ResolvedCapabilityTarget::Relative(
            RelativePathComponents::new(path.split(['/', '\\']).map(str::to_owned).collect())
                .unwrap(),
        )
    };
    AuthorizedExpectedWrite::new(
        &task_id,
        &expected,
        ResolvedCapability {
            capability,
            content_digest: None,
            root_identity: CapabilityRootIdentity::new(root_identity).unwrap(),
            target,
        },
    )
    .unwrap()
}

fn observed_write(scope: &AuthorizedExpectedWrite, bytes: &[u8]) -> ObservedProcessWrite {
    observed_evidence(
        scope.capability().clone(),
        scope.root_identity().clone(),
        scope.target().clone(),
        bytes,
    )
}

fn observed_evidence(
    capability: CapabilityRef,
    root_identity: CapabilityRootIdentity,
    target: ResolvedCapabilityTarget,
    bytes: &[u8],
) -> ObservedProcessWrite {
    ObservedProcessWrite::new(
        capability,
        root_identity,
        target,
        VerifiedWrite {
            digest: digest(bytes),
            size_bytes: bytes.len() as u64,
        },
    )
}

fn digest(bytes: &[u8]) -> Sha256Digest {
    Sha256Digest::new(format!("sha256:{:x}", Sha256::digest(bytes))).unwrap()
}

#[cfg(feature = "test-seams")]
fn boundary_binding() -> IsolatedWorkerBoundaryBinding {
    IsolatedWorkerBoundaryBinding::new("test-only-identity", "test-only-acl").unwrap()
}

#[cfg(feature = "test-seams")]
fn wait_for_file(path: &PathBuf) -> String {
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        if let Ok(contents) = fs::read_to_string(path) {
            return contents;
        }
        thread::sleep(Duration::from_millis(10));
    }
    panic!("child did not publish process-tree state");
}

fn burn_user_cpu(duration: Duration) {
    let target_ticks = process_user_time_ticks() + duration.as_nanos() as u64 / 100;
    let mut value = 0_u64;
    while process_user_time_ticks() < target_ticks {
        for _ in 0..1_000_000 {
            value = std::hint::black_box(value.wrapping_add(1));
        }
    }
}

fn process_user_time_ticks() -> u64 {
    let mut creation_time = FILETIME::default();
    let mut exit_time = FILETIME::default();
    let mut kernel_time = FILETIME::default();
    let mut user_time = FILETIME::default();
    // SAFETY: all output pointers refer to initialized writable FILETIME values,
    // and GetCurrentProcess returns a valid pseudo-handle for this process.
    assert_ne!(
        unsafe {
            GetProcessTimes(
                GetCurrentProcess(),
                &mut creation_time,
                &mut exit_time,
                &mut kernel_time,
                &mut user_time,
            )
        },
        0,
    );
    (u64::from(user_time.dwHighDateTime) << 32) | u64::from(user_time.dwLowDateTime)
}

#[cfg(feature = "test-seams")]
fn process_is_active(process_id: u32) -> bool {
    // SAFETY: OpenProcess is called with query-only access and a numeric PID.
    let process = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, process_id) };
    if process.is_null() {
        return false;
    }
    let mut exit_code = 0;
    // SAFETY: process is a valid query handle and exit_code is writable.
    let active = unsafe { GetExitCodeProcess(process, &mut exit_code) } != 0
        && exit_code == STILL_ACTIVE as u32;
    // SAFETY: process was returned by OpenProcess and is owned in this scope.
    unsafe {
        CloseHandle(process);
    }
    active
}

struct EnvironmentVariableGuard {
    name: &'static str,
    previous: Option<std::ffi::OsString>,
}

impl EnvironmentVariableGuard {
    fn set(name: &'static str, value: &str) -> Self {
        let previous = std::env::var_os(name);
        std::env::set_var(name, value);
        Self { name, previous }
    }
}

impl Drop for EnvironmentVariableGuard {
    fn drop(&mut self) {
        if let Some(value) = &self.previous {
            std::env::set_var(self.name, value);
        } else {
            std::env::remove_var(self.name);
        }
    }
}
