
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
fn app_exit_and_crash_kill_a_live_real_lpac_root() {
    for (mode, clean_exit) in [("exit", true), ("crash", false)] {
        let root = TempDir::new().unwrap();
        let worktree = root.path().join("worktree");
        let pid_path = root.path().join("lpac.pid");
        let acknowledged_path = root.path().join("acknowledged");
        fs::create_dir(&worktree).unwrap();
        let mut host = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "lpac_host_exit_helper", "--nocapture"])
            .env("LAT_LPAC_HOST_MODE", mode)
            .env("LAT_LPAC_HOST_WORKTREE", &worktree)
            .env("LAT_LPAC_HOST_PID", &pid_path)
            .env("LAT_LPAC_HOST_ACK", &acknowledged_path)
            .spawn()
            .unwrap();

        let child_pid = wait_for_file(&pid_path).trim().parse::<u32>().unwrap();
        // SAFETY: OpenProcess receives the observed LPAC PID with query/synchronize access only.
        let child_process = unsafe {
            OpenProcess(
                PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE,
                0,
                child_pid,
            )
        };
        assert!(!child_process.is_null());
        let mut child_exit_code = 0;
        // SAFETY: child_process is a live query handle and child_exit_code is writable.
        assert_ne!(
            unsafe { GetExitCodeProcess(child_process, &mut child_exit_code) },
            0
        );
        assert_eq!(child_exit_code, STILL_ACTIVE as u32);
        fs::write(&acknowledged_path, b"acknowledged").unwrap();

        let status = host.wait().unwrap();
        if clean_exit {
            assert_eq!(status.code(), Some(0));
        } else {
            assert_eq!(status.code(), Some(86));
        }
        // SAFETY: child_process remains owned by this test until CloseHandle below.
        assert_eq!(
            unsafe { WaitForSingleObject(child_process, 5_000) },
            WAIT_OBJECT_0,
            "LPAC root survived host {mode}",
        );
        // SAFETY: child_process remains a valid query handle and child_exit_code is writable.
        assert_ne!(
            unsafe { GetExitCodeProcess(child_process, &mut child_exit_code) },
            0
        );
        assert_ne!(child_exit_code, STILL_ACTIVE as u32);
        // SAFETY: child_process is owned by this iteration.
        unsafe {
            CloseHandle(child_process);
        }
    }
}

#[cfg(feature = "test-seams")]
#[test]
fn lpac_host_exit_helper() {
    let Ok(mode) = std::env::var("LAT_LPAC_HOST_MODE") else {
        return;
    };
    let worktree = PathBuf::from(std::env::var_os("LAT_LPAC_HOST_WORKTREE").unwrap());
    let pid_path = PathBuf::from(std::env::var_os("LAT_LPAC_HOST_PID").unwrap());
    let acknowledged_path = PathBuf::from(std::env::var_os("LAT_LPAC_HOST_ACK").unwrap());
    let launcher = Arc::new(registered_lpac_launcher(&worktree));
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
    request.execution_id = ToolExecutionId::new(format!("execution-lpac-host-{mode}")).unwrap();
    request.timeout_ms = 30_000;
    let execution_id = request.execution_id.clone();
    let authority = claimed_authority(&request);
    let captured = Arc::new(Mutex::new(None));
    let bindings = CapturingProcessBindings {
        authority: authority.clone(),
        captured: Arc::clone(&captured),
    };
    let stderr_observation =
        observe_stderr_marker_for_test(execution_id.clone(), b"bounded-inert-started").unwrap();
    let executing = Arc::clone(&launcher);
    let _execution = thread::spawn(move || {
        local_agent_terminal_application::ProcessLauncher::execute(
            executing.as_ref(),
            request,
            &authority,
            &bindings,
        )
    });

    let deadline = Instant::now() + Duration::from_secs(10);
    let binding = loop {
        if let Some(binding) = captured.lock().unwrap().clone() {
            break binding;
        }
        assert!(Instant::now() < deadline, "LPAC root was not bound");
        thread::yield_now();
    };
    while lpac_lifecycle_counts_for_test(&execution_id).resumes_succeeded != 1 {
        assert!(Instant::now() < deadline, "LPAC root did not resume");
        thread::yield_now();
    }
    while !stderr_observation.observed() {
        assert!(
            Instant::now() < deadline,
            "LPAC root did not publish readiness"
        );
        thread::yield_now();
    }
    assert!(process_is_active(binding.root_pid()));
    let staged_pid_path = pid_path.with_extension("tmp");
    fs::write(&staged_pid_path, binding.root_pid().to_string()).unwrap();
    fs::rename(staged_pid_path, &pid_path).unwrap();
    while !acknowledged_path.exists() {
        assert!(
            Instant::now() < deadline,
            "parent did not acknowledge LPAC root"
        );
        thread::sleep(Duration::from_millis(10));
    }
    assert!(process_is_active(binding.root_pid()));

    match mode.as_str() {
        "exit" => std::process::exit(0),
        "crash" => {
            // SAFETY: the pseudo-handle targets this helper process only.
            assert_ne!(unsafe { TerminateProcess(GetCurrentProcess(), 86) }, 0);
            std::process::abort();
        }
        _ => panic!("unsupported host termination mode"),
    }
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
    let duplicate_request = request.clone();
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
    let recovery_launcher = WindowsProcessLauncher::default();

    let duplicate_launcher = WindowsProcessLauncher::with_isolated_worker_boundary(
        Arc::new(TestOnlyBoundary::valid(root.path().to_owned())),
        boundary_binding(),
    );
    let duplicate_bindings = TestProcessBindings::rejecting(authority.clone());
    assert_eq!(
        local_agent_terminal_application::ProcessLauncher::execute(
            &duplicate_launcher,
            duplicate_request,
            &authority,
            &duplicate_bindings,
        )
        .unwrap_err()
        .safe_classification(),
        SafeErrorClassification::IntegrityFailure
    );
    assert!(process_is_active(binding.root_pid()));

    for wrong_authority in substituted_authorities(&authority) {
        let wrong_authority_binding =
            AuthoritativeProcessBinding::new(wrong_authority, binding.root_pid(), binding.job_id())
                .unwrap();
        assert_eq!(
            local_agent_terminal_application::ProcessLauncher::terminate_retained_process(
                &recovery_launcher,
                &wrong_authority_binding,
            )
            .unwrap_err()
            .safe_classification(),
            SafeErrorClassification::IntegrityFailure
        );
        assert!(process_is_active(binding.root_pid()));
    }

    let wrong_job_binding =
        AuthoritativeProcessBinding::new(authority, binding.root_pid(), "job-not-retained")
            .unwrap();
    assert_eq!(
        local_agent_terminal_application::ProcessLauncher::terminate_retained_process(
            &recovery_launcher,
            &wrong_job_binding,
        )
        .unwrap_err()
        .safe_classification(),
        SafeErrorClassification::IntegrityFailure
    );
    assert!(process_is_active(binding.root_pid()));

    let termination =
        local_agent_terminal_application::ProcessLauncher::terminate_retained_process(
            &recovery_launcher,
            &binding,
        )
        .unwrap();
    let _ = execution.join().unwrap().unwrap();

    assert_eq!(termination.execution_id, execution_id);
    assert_eq!(termination.status, ProcessStatus::Terminated);
    assert!(termination.cancelled);
    let job = termination.job_receipt.unwrap();
    assert_eq!(job.root_pid, binding.root_pid());
    assert_eq!(job.job_id, binding.job_id());
    assert!(job.tree_terminated);
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
