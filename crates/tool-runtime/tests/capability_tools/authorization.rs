use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Mutex;

use local_agent_terminal_application::{
    bind_tool_approval_payload, canonical_file_write_recovery_request, AcquireLease,
    ApprovedExecutableIdentity, ApprovedProcessExecutor, ApprovedProcessRequest,
    AuthorizedFileRead, AuthorizedGitDiff, AuthorizedGitStatus, AuthorizedToolRequest,
    BoundedOutput, CapabilityFileWriteSession, CapabilityFileWriteSessionFactory,
    CapabilityFilesystem, CapabilityRequest, CapabilityResolver, CapabilityRootIdentity,
    CaptureFileWritePostEvidence, CaptureFileWritePreEvidence, Clock, DisclosureContextProvider,
    DisclosureContextRequest, DisclosureOutcome, DisclosurePolicyEvaluator, DisclosureRequest,
    ExecutableFileIdentity, ExecutorLeaseStore, FileReadRequest, FileWriteEvidenceStore,
    FileWritePolicyBinding, FileWritePostExpectation, FileWritePreImage,
    FileWriteRecoveryCompletion, FileWriteRecoveryFailure, FileWriteRecoveryIntent,
    FileWriteRecoverySnapshot, FileWriteRecoveryState, FileWriteRecoveryStore, FileWriteRequest,
    GitDiffRequest, GitStatusRequest, JobReceipt, LeaseSnapshot, ObservedFileImage,
    ObservedProcessWrite, OpenFileWriteSession, PolicyApprovedDisclosure, PolicyDecisionId,
    PolicyDecisionStore, PortError, ProcessReceipt, ProcessStatus, RawGitDiffResult,
    RawGitStatusResult, RecordedPolicyDecision, RelativePathComponents, ResolvedCapability,
    ResolvedCapabilityTarget, ResolvedExecutable, RevokeLease, StructuredGit,
    StructuredToolExecutor, ToolApprovalOperationV1, ToolApprovalPayloadV1, ToolControlSelfTest,
    ToolExecutionArtifactEvidence, ToolExecutionId, TrustedDisclosureContext, VerifiedBytes,
    VerifiedFileWriteCompensation, VerifiedWrite, WorkspaceWriteCoordinator,
};
use local_agent_terminal_domain::{
    ActorId, ActorLocality, ArtifactId, CapabilityRef, EnvironmentProfile, FencingToken,
    GitObjectId, LeaseClaim, NetworkProfile, Phase, PlanStepId, PolicyActor, PolicyEffect,
    ProcessBinding, ProcessInvocation, ProcessToolRequest, ProcessTrustTier, ProjectId,
    ResourceClass, RunId, Sequence, Sha256Digest, TaskId, TaskRisk, TrustTier,
    WorkspaceFingerprint, WorkspaceVersion,
};
use local_agent_terminal_policy_engine::{ScanFailurePoint, VersionedPolicyEngine};
use local_agent_terminal_tool_runtime::ToolRuntime;

#[test]
fn file_read_forces_resolved_digest_records_authoritative_decision_and_returns_only_effective_bytes(
) {
    let original = b"x tok_test_7f89ac y".to_vec();
    let resolver = DisclosureResolver {
        observed_digest: digest(&original),
    };
    let filesystem = DisclosureFilesystem {
        original: original.clone(),
        expected_digest: Mutex::new(None),
    };
    let engine = VersionedPolicyEngine::from_json(
        r#"{"version":1,"rules":[{"id":"cloud-redact","effect":"allow_with_redaction","locality":"cloud","action":"context.disclose","redactions":["secret_scanner"]}]}"#,
    )
    .unwrap();
    let context = FixedDisclosureContext {
        snapshot_digest: engine.snapshot_digest().clone(),
        resource_class: ResourceClass::InternalCode,
        locality: ActorLocality::Cloud,
    };
    let decisions = RecordingDecisionStore::default();
    let harness = Harness::new(Some(b"before".to_vec()));
    let runtime = ToolRuntime::new(
        &resolver,
        &filesystem,
        &harness.sessions,
        &harness.git,
        &harness.leases,
        &harness.process,
        &harness.evidence,
        &harness.recovery,
        &harness.writes,
        &context,
        &engine,
        &decisions,
        &FixedClock,
    );

    let outcome = runtime
        .file_read(FileReadRequest {
            task_id: task(),
            capability: capability("secret.txt"),
            expected_digest: None,
        })
        .unwrap();
    let DisclosureOutcome::Disclosed(disclosure) = outcome else {
        panic!("cloud redaction must disclose only effective bytes");
    };
    let expected = b"x [REDACTED:api_token:665cc10fef9147d3] y";

    assert_eq!(disclosure.bytes, expected);
    assert_eq!(disclosure.digest, digest(expected));
    assert_eq!(disclosure.original_digest, digest(&original));
    assert_eq!(
        filesystem.expected_digest.lock().unwrap().as_ref(),
        Some(&digest(&original))
    );
    let recorded = decisions.recorded.lock().unwrap();
    assert_eq!(recorded.len(), 1);
    assert_eq!(
        disclosure.policy_decision_id,
        PolicyDecisionId::from_decision(recorded[0].decision())
    );
}

#[test]
fn denied_file_read_records_the_decision_without_exposing_an_oracle() {
    let original = b"private contents".to_vec();
    let resolver = DisclosureResolver {
        observed_digest: digest(&original),
    };
    let filesystem = DisclosureFilesystem {
        original,
        expected_digest: Mutex::new(None),
    };
    let engine = VersionedPolicyEngine::from_json(
        r#"{"version":1,"rules":[{"id":"deny-secret","effect":"deny","resourceClass":"secret","action":"context.disclose"}]}"#,
    )
    .unwrap();
    let context = FixedDisclosureContext {
        snapshot_digest: engine.snapshot_digest().clone(),
        resource_class: ResourceClass::Secret,
        locality: ActorLocality::Cloud,
    };
    let decisions = RecordingDecisionStore::default();
    let harness = Harness::new(Some(b"before".to_vec()));
    let runtime = ToolRuntime::new(
        &resolver,
        &filesystem,
        &harness.sessions,
        &harness.git,
        &harness.leases,
        &harness.process,
        &harness.evidence,
        &harness.recovery,
        &harness.writes,
        &context,
        &engine,
        &decisions,
        &FixedClock,
    );

    let outcome = runtime
        .file_read(FileReadRequest {
            task_id: task(),
            capability: capability("secret.txt"),
            expected_digest: None,
        })
        .unwrap();

    assert_eq!(format!("{outcome:?}"), "Denied");
    assert_eq!(decisions.recorded.lock().unwrap().len(), 1);
    for forbidden in [
        "secret.txt",
        "worktree:",
        "sha256:",
        "policy-decision:",
        "private contents",
        "size",
        "exists",
    ] {
        assert!(!format!("{outcome:?}").contains(forbidden));
    }
}

#[test]
fn git_status_is_policy_bound_before_bytes_cross_the_runtime_boundary() {
    let original = b"token=tok_test_7f89ac\n".to_vec();
    let git = StatusDisclosureGit {
        original: original.clone(),
    };
    let engine = VersionedPolicyEngine::from_json(
        r#"{"version":1,"rules":[{"id":"cloud-redact","effect":"allow_with_redaction","locality":"cloud","action":"context.disclose","redactions":["secret_scanner"]}]}"#,
    )
    .unwrap();
    let context = FixedDisclosureContext {
        snapshot_digest: engine.snapshot_digest().clone(),
        resource_class: ResourceClass::InternalCode,
        locality: ActorLocality::Cloud,
    };
    let decisions = RecordingDecisionStore::default();
    let harness = Harness::new(Some(b"before".to_vec()));
    let runtime = ToolRuntime::new(
        &RootResolver,
        &harness.reads,
        &harness.sessions,
        &git,
        &harness.leases,
        &harness.process,
        &harness.evidence,
        &harness.recovery,
        &harness.writes,
        &context,
        &engine,
        &decisions,
        &FixedClock,
    );

    let outcome = runtime
        .git_status(GitStatusRequest {
            task_id: task(),
            worktree: capability("."),
        })
        .unwrap();
    let DisclosureOutcome::Disclosed(status) = outcome else {
        panic!("redacted Git status must be disclosed");
    };
    let expected = b"token=[REDACTED:api_token:665cc10fef9147d3]\n";

    assert_eq!(status.disclosure.bytes, expected);
    assert_eq!(status.disclosure.digest, digest(expected));
    assert_eq!(status.disclosure.original_digest, digest(&original));
    assert_eq!(
        status.repository_id,
        local_agent_terminal_domain::RepositoryId::new("repo-1").unwrap()
    );
    assert_eq!(status.revision, GitObjectId::new("a".repeat(40)).unwrap());
    assert_eq!(status.path_scope, capability("."));
    assert!(!status.truncated);
    assert_eq!(decisions.recorded.lock().unwrap().len(), 1);
}

#[test]
fn git_diff_copies_only_validated_metadata_and_policy_bound_effective_bytes() {
    let original = b"diff tok_test_7f89ac\n".to_vec();
    let git = StatusDisclosureGit {
        original: original.clone(),
    };
    let engine = disclosure_engine("allow_with_redaction", "cloud");
    let context = disclosure_context(&engine, ActorLocality::Cloud);
    let decisions = RecordingDecisionStore::default();
    let harness = Harness::new(None);
    let runtime = ToolRuntime::new(
        &RootResolver,
        &harness.reads,
        &harness.sessions,
        &git,
        &harness.leases,
        &harness.process,
        &harness.evidence,
        &harness.recovery,
        &harness.writes,
        &context,
        &engine,
        &decisions,
        &FixedClock,
    );

    let outcome = runtime
        .git_diff(GitDiffRequest {
            task_id: task(),
            worktree: capability("."),
        })
        .unwrap();
    let DisclosureOutcome::Disclosed(diff) = outcome else {
        panic!("redacted Git diff must be disclosed");
    };
    let expected = b"diff [REDACTED:api_token:665cc10fef9147d3]\n";

    assert_eq!(diff.disclosure.bytes, expected);
    assert_eq!(diff.disclosure.digest, digest(expected));
    assert_eq!(diff.disclosure.original_digest, digest(&original));
    assert_eq!(
        diff.repository_id,
        local_agent_terminal_domain::RepositoryId::new("repo-1").unwrap()
    );
    assert_eq!(diff.revision, GitObjectId::new("b".repeat(40)).unwrap());
    assert_eq!(diff.path_scope, capability("."));
    assert!(diff.truncated);
}

#[test]
fn disclosure_channel_changes_the_recorded_decision_identity() {
    let original = b"clean observation\n".to_vec();
    let git = StatusDisclosureGit { original };
    let engine = disclosure_engine("allow", "cloud");
    let context = disclosure_context(&engine, ActorLocality::Cloud);
    let decisions = RecordingDecisionStore::default();
    let harness = Harness::new(None);
    let runtime = ToolRuntime::new(
        &RootResolver,
        &harness.reads,
        &harness.sessions,
        &git,
        &harness.leases,
        &harness.process,
        &harness.evidence,
        &harness.recovery,
        &harness.writes,
        &context,
        &engine,
        &decisions,
        &FixedClock,
    );

    runtime
        .git_status(GitStatusRequest {
            task_id: task(),
            worktree: capability("."),
        })
        .unwrap();
    runtime
        .git_diff(GitDiffRequest {
            task_id: task(),
            worktree: capability("."),
        })
        .unwrap();

    let recorded = decisions.recorded.lock().unwrap();
    assert_ne!(
        recorded[0].decision().operation_digest,
        recorded[1].decision().operation_digest
    );
    assert_ne!(
        PolicyDecisionId::from_decision(recorded[0].decision()),
        PolicyDecisionId::from_decision(recorded[1].decision())
    );
}

#[test]
fn approval_required_records_the_decision_and_returns_only_the_exact_binding() {
    let original = b"tok_test_7f89ac".to_vec();
    let resolver = DisclosureResolver {
        observed_digest: digest(&original),
    };
    let filesystem = DisclosureFilesystem {
        original,
        expected_digest: Mutex::new(None),
    };
    let engine = disclosure_engine("require_approval", "local");
    let context = disclosure_context(&engine, ActorLocality::Local);
    let decisions = RecordingDecisionStore::default();
    let harness = Harness::new(None);
    let runtime = ToolRuntime::new(
        &resolver,
        &filesystem,
        &harness.sessions,
        &harness.git,
        &harness.leases,
        &harness.process,
        &harness.evidence,
        &harness.recovery,
        &harness.writes,
        &context,
        &engine,
        &decisions,
        &FixedClock,
    );

    let outcome = runtime
        .file_read(FileReadRequest {
            task_id: task(),
            capability: capability("approval.txt"),
            expected_digest: None,
        })
        .unwrap();
    let DisclosureOutcome::ApprovalRequired { ref binding } = outcome else {
        panic!("local restricted disclosure must require approval");
    };

    assert_eq!(
        binding.effective_payload_digest,
        digest(b"[REDACTED:api_token:665cc10fef9147d3]")
    );
    assert_eq!(decisions.recorded.lock().unwrap().len(), 1);
    let rendered = format!("{outcome:?}");
    assert!(!rendered.contains("tok_test_7f89ac"));
    assert!(!rendered.contains("policy-decision:"));
}

#[test]
fn scanner_failures_and_stale_policy_snapshots_disclose_nothing_and_record_nothing() {
    for failure in [ScanFailurePoint::Initial, ScanFailurePoint::FinalRescan] {
        let original = b"tok_test_7f89ac".to_vec();
        let resolver = DisclosureResolver {
            observed_digest: digest(&original),
        };
        let filesystem = DisclosureFilesystem {
            original,
            expected_digest: Mutex::new(None),
        };
        let engine =
            disclosure_engine("allow_with_redaction", "cloud").with_scan_failure_for_test(failure);
        let context = disclosure_context(&engine, ActorLocality::Cloud);
        let decisions = RecordingDecisionStore::default();
        let harness = Harness::new(None);
        let runtime = ToolRuntime::new(
            &resolver,
            &filesystem,
            &harness.sessions,
            &harness.git,
            &harness.leases,
            &harness.process,
            &harness.evidence,
            &harness.recovery,
            &harness.writes,
            &context,
            &engine,
            &decisions,
            &FixedClock,
        );

        let error = runtime
            .file_read(FileReadRequest {
                task_id: task(),
                capability: capability("scan.txt"),
                expected_digest: None,
            })
            .expect_err("scanner failure must fail closed");
        assert_eq!(
            error.safe_classification(),
            local_agent_terminal_application::SafeErrorClassification::PermissionDenied
        );
        assert!(decisions.recorded.lock().unwrap().is_empty());
    }

    let original = b"clean".to_vec();
    let resolver = DisclosureResolver {
        observed_digest: digest(&original),
    };
    let filesystem = DisclosureFilesystem {
        original,
        expected_digest: Mutex::new(None),
    };
    let engine = disclosure_engine("allow", "cloud");
    let context = FixedDisclosureContext {
        snapshot_digest: digest(b"stale-policy"),
        resource_class: ResourceClass::InternalCode,
        locality: ActorLocality::Cloud,
    };
    let decisions = RecordingDecisionStore::default();
    let harness = Harness::new(None);
    let runtime = ToolRuntime::new(
        &resolver,
        &filesystem,
        &harness.sessions,
        &harness.git,
        &harness.leases,
        &harness.process,
        &harness.evidence,
        &harness.recovery,
        &harness.writes,
        &context,
        &engine,
        &decisions,
        &FixedClock,
    );

    assert!(runtime
        .file_read(FileReadRequest {
            task_id: task(),
            capability: capability("stale.txt"),
            expected_digest: None,
        })
        .is_err());
    assert!(decisions.recorded.lock().unwrap().is_empty());
}

#[test]
fn evaluator_echo_mismatches_are_rejected_before_recording_or_disclosure() {
    for tamper in [
        EvaluatorTamper::Request,
        EvaluatorTamper::Channel,
        EvaluatorTamper::OriginalDigest,
    ] {
        let engine = disclosure_engine("allow", "cloud");
        let evaluator = TamperingEvaluator { engine, tamper };
        let context = disclosure_context(&evaluator.engine, ActorLocality::Cloud);
        let decisions = RecordingDecisionStore::default();

        let error = run_file_disclosure(&evaluator, &context, &decisions)
            .expect_err("tampered evaluator echo must fail closed");

        assert_eq!(
            error.safe_classification(),
            local_agent_terminal_application::SafeErrorClassification::IntegrityFailure,
            "{tamper:?}"
        );
        assert!(decisions.recorded.lock().unwrap().is_empty(), "{tamper:?}");
    }
}

#[test]
fn mismatched_store_identity_is_rejected_after_recording_and_before_disclosure() {
    let engine = disclosure_engine("allow", "cloud");
    let context = disclosure_context(&engine, ActorLocality::Cloud);
    let decisions = WrongIdDecisionStore::default();

    let error = run_file_disclosure(&engine, &context, &decisions)
        .expect_err("the persistence identity must echo the authoritative decision");

    assert_eq!(
        error.safe_classification(),
        local_agent_terminal_application::SafeErrorClassification::IntegrityFailure
    );
    assert_eq!(decisions.recorded.lock().unwrap().len(), 1);
}

#[test]
fn git_result_digest_mismatch_is_rejected_before_policy_or_disclosure() {
    let engine = disclosure_engine("allow", "cloud");
    let context = disclosure_context(&engine, ActorLocality::Cloud);
    let decisions = RecordingDecisionStore::default();
    let harness = Harness::new(None);
    let runtime = ToolRuntime::new(
        &RootResolver,
        &harness.reads,
        &harness.sessions,
        &TamperedStatusGit,
        &harness.leases,
        &harness.process,
        &harness.evidence,
        &harness.recovery,
        &harness.writes,
        &context,
        &engine,
        &decisions,
        &FixedClock,
    );

    let error = runtime
        .git_status(GitStatusRequest {
            task_id: task(),
            worktree: capability("."),
        })
        .expect_err("raw Git bytes must match the adapter digest");

    assert_eq!(
        error.safe_classification(),
        local_agent_terminal_application::SafeErrorClassification::IntegrityFailure
    );
    assert!(decisions.recorded.lock().unwrap().is_empty());
}

#[test]
fn git_status_passes_only_the_resolvers_opaque_root_to_the_git_port() {
    let harness = Harness::new(Some(b"before".to_vec()));
    let resolver = RootResolver;
    let git = RootRecordingGit::default();
    let runtime = ToolRuntime::new(
        &resolver,
        &harness.reads,
        &harness.sessions,
        &git,
        &harness.leases,
        &harness.process,
        &harness.evidence,
        &harness.recovery,
        &harness.writes,
        &harness.disclosure_context,
        &harness.disclosure_policy,
        &harness.policy_decisions,
        &harness.clock,
    );

    runtime
        .git_status(GitStatusRequest {
            task_id: task(),
            worktree: CapabilityRef::worktree(task(), ".").unwrap(),
        })
        .unwrap();

    assert_eq!(
        git.root.lock().unwrap().as_ref().unwrap().as_str(),
        "git-root"
    );
}

#[test]
fn resolved_capabilities_expose_only_opaque_roots_and_normalized_components() {
    let root = CapabilityRootIdentity::new("root-1").unwrap();
    let components =
        RelativePathComponents::new(vec!["src".to_owned(), "lib.rs".to_owned()]).unwrap();

    assert_eq!(root.as_str(), "root-1");
    assert_eq!(components.as_slice(), ["src", "lib.rs"]);
    assert!(RelativePathComponents::new(vec!["..".to_owned()]).is_err());
    assert!(RelativePathComponents::new(vec!["CON.txt".to_owned()]).is_err());
    assert!(RelativePathComponents::new(vec!["name. ".to_owned()]).is_err());
}

#[test]
fn read_denial_is_non_disclosing_and_never_reaches_the_filesystem() {
    let harness = Harness::new(Some(b"before".to_vec()));
    harness.resolver.allowed.store(false, Ordering::SeqCst);

    let error = harness
        .runtime()
        .file_read(FileReadRequest {
            task_id: task(),
            capability: capability("secret.txt"),
            expected_digest: None,
        })
        .expect_err("denied reads must fail");

    assert_eq!(
        error.safe_classification(),
        local_agent_terminal_application::SafeErrorClassification::PermissionDenied
    );
    assert!(!harness.reads.read_called.load(Ordering::SeqCst));
    assert_eq!(
        error.to_string(),
        "port failure (PermissionDenied, NonRetryable)"
    );
}

#[test]
fn write_holds_the_exact_durable_call_order() {
    let harness = Harness::new(Some(b"before".to_vec()));

    harness.runtime().file_write(write_request()).unwrap();

    assert_eq!(
        harness.calls(),
        [
            "resolve",
            "assert_current",
            "open_session",
            "pre_image",
            "capture_pre_write",
            "prepare",
            "start",
            "assert_current",
            "apply",
            "verify_post_image",
            "capture_post_write",
            "complete",
        ]
    );
}

#[test]
fn stale_write_has_zero_target_or_durable_effect() {
    let harness = Harness::new(Some(b"before".to_vec()));
    harness.leases.current.store(false, Ordering::SeqCst);

    let error = harness
        .runtime()
        .file_write(write_request())
        .expect_err("stale writes must fail");

    assert_eq!(
        error.safe_classification(),
        local_agent_terminal_application::SafeErrorClassification::Conflict
    );
    assert_eq!(harness.target(), Some(b"before".to_vec()));
    assert_eq!(harness.calls(), ["resolve", "assert_current"]);
    assert!(!harness.recovery.indeterminate.load(Ordering::SeqCst));
}

#[test]
fn atomic_complete_failure_restores_and_verifies_the_pre_image() {
    let harness = Harness::new(Some(b"before".to_vec()));
    harness
        .recovery
        .complete_fails
        .store(true, Ordering::SeqCst);

    assert!(harness.runtime().file_write(write_request()).is_err());

    assert_eq!(harness.target(), Some(b"before".to_vec()));
    assert!(harness
        .calls()
        .ends_with(&["complete", "restore_pre_image_and_verify", "fail"]));
    assert_eq!(
        *harness.recovery.state.lock().unwrap(),
        Some(FileWriteRecoveryState::Compensated)
    );
    assert!(harness.recovery.recover().unwrap().is_empty());
    assert!(!harness.recovery.indeterminate.load(Ordering::SeqCst));
}

#[test]
fn compensated_write_persistence_failure_recovers_exact_pre_image_without_replaying_effect() {
    let harness = Harness::new(Some(b"before".to_vec()));
    harness
        .recovery
        .complete_fails
        .store(true, Ordering::SeqCst);
    harness.recovery.fail_fails.store(true, Ordering::SeqCst);

    let error = harness
        .runtime()
        .file_write(write_request())
        .expect_err("terminal persistence failure must fail closed");

    assert_eq!(
        error.safe_classification(),
        local_agent_terminal_application::SafeErrorClassification::IntegrityFailure
    );
    assert_eq!(harness.target(), Some(b"before".to_vec()));
    assert_eq!(
        *harness.recovery.state.lock().unwrap(),
        Some(FileWriteRecoveryState::Started)
    );
    harness.recovery.fail_fails.store(false, Ordering::SeqCst);

    let recovered = harness.runtime().recover_file_writes().unwrap();

    assert_eq!(recovered.len(), 1);
    assert_eq!(
        recovered[0].state,
        FileWriteRecoveryState::RecoveredNoNetEffect
    );
    assert!(harness.recovery.recover().unwrap().is_empty());
    assert_eq!(
        harness
            .calls()
            .iter()
            .filter(|call| **call == "apply")
            .count(),
        1
    );
}

#[test]
fn started_recovery_resolves_exact_post_and_marks_unproven_outcomes_indeterminate() {
    for (current, expected_state, complete_fails) in [
        (
            b"replacement".to_vec(),
            FileWriteRecoveryState::Completed,
            false,
        ),
        (
            b"replacement".to_vec(),
            FileWriteRecoveryState::Indeterminate,
            true,
        ),
        (
            b"unexpected".to_vec(),
            FileWriteRecoveryState::Indeterminate,
            false,
        ),
    ] {
        let harness = Harness::new(Some(b"before".to_vec()));
        harness
            .recovery
            .complete_fails
            .store(true, Ordering::SeqCst);
        harness.recovery.fail_fails.store(true, Ordering::SeqCst);
        assert!(harness.runtime().file_write(write_request()).is_err());
        *harness.sessions.target.bytes.lock().unwrap() = Some(current);
        harness
            .recovery
            .complete_fails
            .store(complete_fails, Ordering::SeqCst);
        harness.recovery.fail_fails.store(false, Ordering::SeqCst);

        let recovered = harness.runtime().recover_file_writes().unwrap();

        assert_eq!(recovered[0].state, expected_state);
        assert_eq!(
            harness
                .calls()
                .iter()
                .filter(|call| **call == "apply")
                .count(),
            1
        );
    }
}

#[test]
fn prepared_recovery_becomes_terminal_without_opening_a_write_session() {
    let harness = Harness::new(Some(b"before".to_vec()));
    harness
        .recovery
        .complete_fails
        .store(true, Ordering::SeqCst);
    harness.recovery.fail_fails.store(true, Ordering::SeqCst);
    assert!(harness.runtime().file_write(write_request()).is_err());
    *harness.recovery.state.lock().unwrap() = Some(FileWriteRecoveryState::Prepared);
    harness.recovery.fail_fails.store(false, Ordering::SeqCst);
    let opens_before = harness
        .calls()
        .iter()
        .filter(|call| **call == "open_session")
        .count();

    let recovered = harness.runtime().recover_file_writes().unwrap();

    assert_eq!(recovered[0].state, FileWriteRecoveryState::Failed);
    assert_eq!(
        harness
            .calls()
            .iter()
            .filter(|call| **call == "open_session")
            .count(),
        opens_before
    );
}

#[test]
fn compensation_failure_marks_the_durable_write_indeterminate() {
    let harness = Harness::new(Some(b"before".to_vec()));
    harness
        .recovery
        .complete_fails
        .store(true, Ordering::SeqCst);
    harness
        .sessions
        .compensation_fails
        .store(true, Ordering::SeqCst);

    assert!(harness.runtime().file_write(write_request()).is_err());

    assert_eq!(harness.target(), Some(b"replacement".to_vec()));
    assert!(harness.calls().ends_with(&[
        "complete",
        "restore_pre_image_and_verify",
        "mark_indeterminate"
    ]));
    assert!(harness.recovery.indeterminate.load(Ordering::SeqCst));
}

#[test]
fn successful_write_returns_the_exact_verified_digest_and_size() {
    let harness = Harness::new(None);

    let result = harness.runtime().file_write(write_request()).unwrap();

    assert_eq!(result.digest, digest(b"replacement"));
    assert_eq!(result.size_bytes, b"replacement".len() as u64);
    assert_eq!(harness.target(), Some(b"replacement".to_vec()));
}

#[test]
fn pre_write_evidence_must_echo_every_execution_binding_exactly() {
    for tamper in [
        PreEvidenceTamper::Execution,
        PreEvidenceTamper::Task,
        PreEvidenceTamper::Root,
        PreEvidenceTamper::Components,
        PreEvidenceTamper::Lease,
        PreEvidenceTamper::PreImage,
        PreEvidenceTamper::PostDigest,
        PreEvidenceTamper::PostSize,
        PreEvidenceTamper::Policy,
        PreEvidenceTamper::RequestArtifact,
    ] {
        let harness = Harness::new(Some(b"before".to_vec()));
        *harness.evidence.pre_tamper.lock().unwrap() = Some(tamper);

        let error = harness
            .runtime()
            .file_write(write_request())
            .expect_err("tampered pre-write evidence must fail closed");

        assert_eq!(
            error.safe_classification(),
            local_agent_terminal_application::SafeErrorClassification::IntegrityFailure,
            "{tamper:?}"
        );
        assert_eq!(harness.target(), Some(b"before".to_vec()), "{tamper:?}");
        assert_eq!(
            harness.calls().last(),
            Some(&"capture_pre_write"),
            "{tamper:?}"
        );
    }
}

#[test]
fn tampered_post_write_evidence_is_compensated_before_completion() {
    let harness = Harness::new(Some(b"before".to_vec()));
    harness
        .evidence
        .post_digest_tamper
        .store(true, Ordering::SeqCst);

    let error = harness
        .runtime()
        .file_write(write_request())
        .expect_err("tampered post-write evidence must fail closed");

    assert_eq!(
        error.safe_classification(),
        local_agent_terminal_application::SafeErrorClassification::IntegrityFailure
    );
    assert_eq!(harness.target(), Some(b"before".to_vec()));
    assert!(harness.calls().ends_with(&[
        "capture_post_write",
        "restore_pre_image_and_verify",
        "fail"
    ]));
    assert!(!harness.calls().contains(&"complete"));
    assert_eq!(
        *harness.recovery.state.lock().unwrap(),
        Some(FileWriteRecoveryState::Compensated)
    );
}

#[test]
fn recovery_state_echo_is_verified_before_crossing_the_effect_boundary() {
    let harness = Harness::new(Some(b"before".to_vec()));
    harness
        .recovery
        .prepare_state_tamper
        .store(true, Ordering::SeqCst);

    let error = harness
        .runtime()
        .file_write(write_request())
        .expect_err("a mismatched recovery state must fail closed");

    assert_eq!(
        error.safe_classification(),
        local_agent_terminal_application::SafeErrorClassification::IntegrityFailure
    );
    assert_eq!(harness.target(), Some(b"before".to_vec()));
    assert_eq!(harness.calls().last(), Some(&"prepare"));
    assert!(!harness.calls().contains(&"start"));
}

#[test]
fn lease_revocation_after_prepare_blocks_the_write_before_apply() {
    let harness = Harness::new(Some(b"before".to_vec()));
    harness.leases.stale_on_second.store(true, Ordering::SeqCst);

    let error = harness
        .runtime()
        .file_write(write_request())
        .expect_err("lease revocation must win the final pre-effect race");

    assert_eq!(
        error.safe_classification(),
        local_agent_terminal_application::SafeErrorClassification::Conflict
    );
    assert_eq!(harness.target(), Some(b"before".to_vec()));
    assert!(harness.calls().ends_with(&["start", "assert_current"]));
    assert!(!harness.calls().contains(&"apply"));
    assert!(!harness.recovery.indeterminate.load(Ordering::SeqCst));
}

#[test]
fn control_self_test_propagates_process_executor_failure() {
    let harness = Harness::new(None);

    let error = ToolControlSelfTest::verify_controls(&harness.runtime())
        .expect_err("the exact process executor self-test must gate the tool runtime");

    assert_eq!(
        error.safe_classification(),
        local_agent_terminal_application::SafeErrorClassification::Unavailable
    );
}

#[test]
fn process_streams_are_scanned_and_redacted_before_the_executor_result_crosses_the_runtime() {
    let mut harness = Harness::new(None);
    harness.disclosure_policy = disclosure_engine("allow_with_redaction", "local");
    harness.disclosure_context.snapshot_digest =
        harness.disclosure_policy.snapshot_digest().clone();
    let process = OutputProcess;
    let runtime = ToolRuntime::new(
        &harness.resolver,
        &harness.reads,
        &harness.sessions,
        &harness.git,
        &harness.leases,
        &process,
        &harness.evidence,
        &harness.recovery,
        &harness.writes,
        &harness.disclosure_context,
        &harness.disclosure_policy,
        &harness.policy_decisions,
        &harness.clock,
    );

    let result = StructuredToolExecutor::execute(&runtime, authorized_output_request()).unwrap();

    assert!(!String::from_utf8_lossy(&result.receipt.stdout.bytes).contains("tok_test_7f89ac"));
    let ToolExecutionArtifactEvidence::Disclosed(artifacts) = result.artifacts else {
        panic!("tool runtime must return policy-bound output evidence");
    };
    assert_eq!(
        artifacts.stdout().original_digest,
        digest(b"x tok_test_7f89ac y")
    );
    assert_eq!(artifacts.stdout().bytes, result.receipt.stdout.bytes);
    assert_ne!(
        artifacts.stdout().original_digest,
        artifacts.stdout().digest
    );
    assert_eq!(artifacts.observed_writes().len(), 1);
    assert!(
        !String::from_utf8_lossy(&artifacts.observed_writes()[0].bytes).contains("tok_test_7f89ac")
    );
    assert_eq!(harness.policy_decisions.recorded.lock().unwrap().len(), 3);
}

#[test]
fn process_effect_failure_returns_only_quarantined_receipt_metadata() {
    let mut harness = Harness::new(None);
    harness.disclosure_policy =
        disclosure_engine("allow", "local").with_scan_failure_for_test(ScanFailurePoint::Initial);
    harness.disclosure_context.snapshot_digest =
        harness.disclosure_policy.snapshot_digest().clone();
    let process = OutputProcess;
    let runtime = ToolRuntime::new(
        &harness.resolver,
        &harness.reads,
        &harness.sessions,
        &harness.git,
        &harness.leases,
        &process,
        &harness.evidence,
        &harness.recovery,
        &harness.writes,
        &harness.disclosure_context,
        &harness.disclosure_policy,
        &harness.policy_decisions,
        &harness.clock,
    );

    let result = StructuredToolExecutor::execute(&runtime, authorized_output_request())
        .expect("post-effect scanner failure must retain a safe terminal result");
    assert!(result.receipt.stdout.bytes.is_empty());
    assert!(result.receipt.stderr.bytes.is_empty());
    let ToolExecutionArtifactEvidence::Quarantined(quarantined) = result.artifacts else {
        panic!("scanner failure must produce quarantined evidence");
    };
    assert_eq!(
        quarantined.receipt().stdout.digest,
        digest(b"x tok_test_7f89ac y")
    );
    assert_eq!(quarantined.receipt().stdout.size_bytes, 19);
    assert_eq!(quarantined.receipt().observed_writes.len(), 1);
    let rendered = format!("{quarantined:?}");
    assert!(!rendered.contains("tok_test_7f89ac"));
}

struct OutputProcess;

impl ToolControlSelfTest for OutputProcess {
    fn verify_controls(&self) -> Result<(), PortError> {
        Ok(())
    }
}

impl ApprovedProcessExecutor for OutputProcess {
    fn execute(
        &self,
        execution_id: ToolExecutionId,
        _: ApprovedProcessRequest,
        _authority: Option<&local_agent_terminal_application::ToolExecutionClaimAuthority>,
    ) -> Result<ProcessReceipt, PortError> {
        Ok(ProcessReceipt {
            execution_id,
            status: ProcessStatus::Exited,
            exit_code: Some(0),
            stdout: BoundedOutput {
                bytes: b"x tok_test_7f89ac y".to_vec(),
                truncated: false,
            },
            stderr: BoundedOutput {
                bytes: Vec::new(),
                truncated: false,
            },
            duration_ms: 1,
            job_receipt: JobReceipt {
                root_pid: 1,
                job_id: "output-job".to_owned(),
                kill_on_close: true,
                no_breakaway: true,
                job_memory_limit: true,
                job_cpu_time_limit: true,
                memory_limit_bytes: 1,
                cpu_time_limit_ms: 1,
                max_active_processes: 1,
                total_user_time_ms: 1,
                resource_limit_terminated: false,
                tree_terminated: false,
            },
            observed_writes: vec![ObservedProcessWrite::new(
                CapabilityRef::worktree(task(), "tok_test_7f89ac.txt").unwrap(),
                CapabilityRootIdentity::new("output-root").unwrap(),
                ResolvedCapabilityTarget::Relative(
                    RelativePathComponents::new(vec!["tok_test_7f89ac.txt".to_owned()]).unwrap(),
                ),
                VerifiedWrite {
                    digest: digest(b"written bytes"),
                    size_bytes: 13,
                },
            )],
            output_digest: digest(b"raw output"),
        })
    }

    fn cancel(
        &self,
        _: &ToolExecutionId,
    ) -> Result<local_agent_terminal_application::CancellationReceipt, PortError> {
        unreachable!()
    }
}

fn authorized_output_request() -> AuthorizedToolRequest {
    let task_id = task();
    let approved = ApprovedProcessRequest::new(
        ApprovedExecutableIdentity::new(
            ResolvedExecutable {
                canonical_path: output_executable_path(),
                sha256: digest(b"output executable"),
                file_identity: ExecutableFileIdentity::new("output-executable").unwrap(),
                toolchain_id: "output-probe".to_owned(),
            },
            "1",
        )
        .unwrap(),
        ProcessToolRequest::new(
            ProcessBinding::new(
                task_id.clone(),
                RunId::new("run-1").unwrap(),
                PlanStepId::new("step-1").unwrap(),
                Phase::Implementation,
                WorkspaceVersion::new(1),
                EnvironmentProfile::new("empty", digest(b"environment")).unwrap(),
                1_000,
            )
            .unwrap(),
            ProcessInvocation::new(
                CapabilityRef::toolchain("output-probe").unwrap(),
                vec!["run".to_owned()],
                CapabilityRef::worktree(task_id, ".").unwrap(),
                ProcessTrustTier::IsolatedWorker,
                NetworkProfile::Denied,
                Vec::new(),
                None,
            )
            .unwrap(),
        )
        .unwrap(),
        Vec::new(),
        None,
        None,
        None,
    )
    .unwrap();
    let approval = bind_tool_approval_payload(
        ToolApprovalPayloadV1 {
            schema: "approval-digest.v1".to_owned(),
            approval_type: "tool".to_owned(),
            task_id: "bound-by-core".to_owned(),
            operation: ToolApprovalOperationV1 {
                run_id: "bound-by-core".to_owned(),
                plan_step_id: "bound-by-core".to_owned(),
                tool: "process.exec".to_owned(),
                executable_digest: None,
                arguments_digest: digest(b"placeholder").to_string(),
                script_digest: None,
                cwd_capability: "bound-by-core".to_owned(),
                environment_profile_digest: digest(b"placeholder").to_string(),
                network_profile: "denied".to_owned(),
                expected_writes: Vec::new(),
                executor_fencing_token: None,
            },
            policy_snapshot_digest: digest(b"policy").to_string(),
            workspace_version: 1,
            requested_at: "2026-08-02T00:00:00Z".to_owned(),
            expires_at: "2026-08-02T00:15:00Z".to_owned(),
            nonce: "0123456789abcdef0123456789abcdef".to_owned(),
        },
        &approved,
    )
    .unwrap();
    AuthorizedToolRequest::new(
        ToolExecutionId::new("output-1").unwrap(),
        approval,
        approved,
    )
}
