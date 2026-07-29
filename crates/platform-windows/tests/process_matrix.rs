#![cfg(windows)]

use std::collections::BTreeMap;
use std::fs;
use std::os::windows::process::CommandExt;
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use local_agent_terminal_application::{
    AuthorizedProcessRequest, CapabilityRootIdentity, EnforcedNetworkProfile,
    ExecutableFileIdentity, NetworkEnforcementReceipt, ProcessLauncher, ProcessLimits,
    ProcessStatus, ProcessWorkingDirectory, ResolvedCapability, ResolvedCapabilityTarget,
    ResolvedEnvironmentProfile, ToolExecutionId, VerifiedWrite,
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
use local_agent_terminal_platform_windows::fail_next_output_reader_start_for_test;
use local_agent_terminal_platform_windows::{
    IsolatedWorkerBoundaryAdapter, IsolatedWorkerBoundaryBinding, IsolatedWorkerBoundaryClaims,
    PreparedIsolatedWorkerBoundary, WindowsExecutableInspector,
    WindowsPrivateRuntimeDirectoryInspector, WindowsProcessLauncher,
};
use sha2::{Digest, Sha256};
use tempfile::TempDir;
use windows_sys::Win32::Foundation::{CloseHandle, FILETIME, STILL_ACTIVE};
use windows_sys::Win32::System::Threading::{
    GetCurrentProcess, GetExitCodeProcess, GetProcessTimes, OpenProcess, CREATE_BREAKAWAY_FROM_JOB,
    PROCESS_QUERY_LIMITED_INFORMATION,
};

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

#[test]
fn every_boundary_receipt_mismatch_is_rejected_before_child_creation() {
    for mismatch in [
        BoundaryMismatch::Identity,
        BoundaryMismatch::Acl,
        BoundaryMismatch::Task,
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
    let boundary = Arc::new(TestOnlyBoundary::valid(root.path().to_owned()));
    let launcher =
        WindowsProcessLauncher::with_isolated_worker_boundary(boundary, boundary_binding());
    let mut request = request(
        vec![
            "--exact".to_owned(),
            "process_child_helper".to_owned(),
            "--nocapture".to_owned(),
        ],
        BTreeMap::from([("LAT_PROCESS_HELPER".to_owned(), "flood".to_owned())]),
    );
    request.limits.max_stdout_bytes = 32;

    let receipt = launcher.execute(request).unwrap();

    assert_eq!(receipt.status, ProcessStatus::Terminated);
    assert!(receipt.stdout.truncated);
    assert_eq!(receipt.stdout.bytes.len(), 32);
    assert!(receipt.job_receipt.tree_terminated);
}

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
                request.expected_writes = vec![ExpectedWrite::new(
                    CapabilityRef::worktree(TaskId::new("task-1").unwrap(), "target").unwrap(),
                )
                .unwrap()]
            }
        }

        assert!(launcher.execute(request).is_err(), "{mutation:?}");
        assert!(!marker.exists(), "{mutation:?}");
    }
}

#[test]
fn enforced_expected_write_scope_is_bound_and_returns_observed_evidence() {
    let root = TempDir::new().unwrap();
    let mut boundary = TestOnlyBoundary::valid(root.path().to_owned());
    boundary.allow_expected_writes = true;
    boundary.observed_writes = vec![VerifiedWrite {
        digest: digest(b"observed write"),
        size_bytes: 14,
    }];
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
    request.expected_writes = vec![ExpectedWrite::new(
        CapabilityRef::worktree(TaskId::new("task-1").unwrap(), "generated.txt").unwrap(),
    )
    .unwrap()];

    let receipt = launcher.execute(request).unwrap();

    assert_eq!(receipt.status, ProcessStatus::Exited);
    assert_eq!(receipt.observed_writes.len(), 1);
    assert_eq!(receipt.observed_writes[0].size_bytes, 14);
}

#[test]
fn cpu_job_limit_terminates_busy_process_before_wall_timeout() {
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
        BTreeMap::from([("LAT_PROCESS_HELPER".to_owned(), "cpu".to_owned())]),
    );
    request.timeout_ms = 15_000;
    request.limits.cpu_time_limit_ms = 1;

    let receipt = launcher.execute(request).unwrap();

    assert_eq!(receipt.status, ProcessStatus::Terminated);
    assert!(receipt.duration_ms < 15_000);
    assert!(receipt.job_receipt.tree_terminated);
}

#[test]
fn memory_job_limit_denies_additional_committed_memory() {
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
        BTreeMap::from([("LAT_PROCESS_HELPER".to_owned(), "memory".to_owned())]),
    );
    request.timeout_ms = 5_000;
    request.limits.memory_limit_bytes = 64 * 1024 * 1024;

    let receipt = launcher.execute(request).unwrap();

    assert_eq!(receipt.status, ProcessStatus::Exited);
    assert_eq!(receipt.exit_code, Some(0));
    assert!(String::from_utf8_lossy(&receipt.stdout.bytes).contains("memory-denied"));
}

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
        Some("marker") => {
            fs::write(std::env::var_os("LAT_PROCESS_MARKER").unwrap(), b"ran").unwrap();
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

struct TestOnlyBoundary {
    cwd: PathBuf,
    fail_before_resume: bool,
    identity_receipt: String,
    acl_receipt: String,
    claims_mismatch: Option<BoundaryMismatch>,
    prepare_calls: Arc<AtomicUsize>,
    allow_expected_writes: bool,
    observed_writes: Vec<VerifiedWrite>,
}

#[derive(Debug, Clone, Copy)]
enum BoundaryMismatch {
    Identity,
    Acl,
    Task,
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
enum LaunchMutation {
    BrokeredWorktree,
    ExpectedWrite,
}

impl TestOnlyBoundary {
    fn valid(cwd: PathBuf) -> Self {
        Self {
            cwd,
            fail_before_resume: false,
            identity_receipt: "test-only-identity".to_owned(),
            acl_receipt: "test-only-acl".to_owned(),
            claims_mismatch: None,
            prepare_calls: Arc::new(AtomicUsize::new(0)),
            allow_expected_writes: false,
            observed_writes: Vec::new(),
        }
    }
}

impl IsolatedWorkerBoundaryAdapter for TestOnlyBoundary {
    fn prepare(
        &self,
        request: &AuthorizedProcessRequest,
    ) -> Result<PreparedIsolatedWorkerBoundary, local_agent_terminal_application::PortError> {
        self.prepare_calls.fetch_add(1, Ordering::AcqRel);
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
    }

    fn verify_before_resume(
        &self,
        _request: &AuthorizedProcessRequest,
        _prepared: &PreparedIsolatedWorkerBoundary,
    ) -> Result<(), local_agent_terminal_application::PortError> {
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
    ) -> Result<Vec<VerifiedWrite>, local_agent_terminal_application::PortError> {
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
        BoundaryMismatch::ExpectedWrites => claims.expected_writes.push(
            ExpectedWrite::new(
                CapabilityRef::worktree(TaskId::new("task-1").unwrap(), "unexpected.txt").unwrap(),
            )
            .unwrap(),
        ),
        BoundaryMismatch::Argv => claims.argv.push("extra".to_owned()),
        BoundaryMismatch::Timeout => claims.timeout_ms += 1,
    }
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
    }
}

fn digest(bytes: &[u8]) -> Sha256Digest {
    Sha256Digest::new(format!("sha256:{:x}", Sha256::digest(bytes))).unwrap()
}

fn boundary_binding() -> IsolatedWorkerBoundaryBinding {
    IsolatedWorkerBoundaryBinding::new("test-only-identity", "test-only-acl").unwrap()
}

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
