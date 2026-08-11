
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
        Some("exit-job-termination-code") => std::process::exit(0xC000_013Au32 as i32),
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
            ERROR_NOT_ENOUGH_QUOTA => "process-limit-denied",
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
