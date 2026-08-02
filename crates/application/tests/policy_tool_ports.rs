use local_agent_terminal_application::{
    bind_tool_approval_payload, canonical_approval_payload, canonical_file_write_recovery_request,
    parse_file_write_recovery_request, ApprovalDigestPayload, ApprovalStore,
    ApprovedExecutableIdentity, ApprovedProcessExecutor, ApprovedProcessRequest, BoundToolApproval,
    CanonicalEvidenceRef, CapabilityFileWriteSession, CapabilityFileWriteSessionFactory,
    CapabilityFilesystem, CapabilityResolver, CapabilityRootIdentity, CaptureFileWritePostEvidence,
    CaptureFileWritePreEvidence, DisclosureChannel, DisclosurePolicyEvaluator, DisclosureRequest,
    ExecutableFileIdentity, FileWriteEvidenceStore, FileWritePolicyBinding,
    FileWritePostExpectation, FileWritePreImage, FileWriteRecoveryRequest, ObservedFileImage,
    OpenFileWriteSession, PolicyDecisionStore, PolicyEvaluator, ProcessLauncher,
    RelativePathComponents, ResolvedExecutable, StructuredGit, StructuredToolExecutor,
    ToolApprovalOperationV1, ToolApprovalPayloadV1, ToolExecutionId, ToolExecutionStore,
    VerifiedWrite,
};
use local_agent_terminal_domain::{
    ActorId, ArtifactId, CapabilityRef, EnvironmentProfile, ExpectedWrite, FencingToken,
    GitObjectId, LeaseClaim, NetworkProfile, Phase, PlanStepId, PolicyEffect, ProcessBinding,
    ProcessInvocation, ProcessToolRequest, ProcessTrustTier, ProjectId, RunId, Sequence,
    Sha256Digest, TaskId, WorkspaceFingerprint, WorkspaceVersion,
};
use sha2::Digest;
use std::path::PathBuf;

fn assert_object_safe<T: ?Sized>() {}

#[test]
fn policy_and_tool_ports_are_object_safe() {
    assert_object_safe::<dyn PolicyEvaluator>();
    assert_object_safe::<dyn DisclosurePolicyEvaluator>();
    assert_object_safe::<dyn local_agent_terminal_application::FileWriteRecoveryStore>();
    assert_object_safe::<dyn CapabilityFileWriteSession>();
    assert_object_safe::<dyn CapabilityFileWriteSessionFactory>();
    assert_object_safe::<dyn FileWriteEvidenceStore>();
    assert_object_safe::<dyn PolicyDecisionStore>();
    assert_object_safe::<dyn ApprovalStore>();
    assert_object_safe::<dyn CapabilityResolver>();
    assert_object_safe::<dyn CapabilityFilesystem>();
    assert_object_safe::<dyn StructuredGit>();
    assert_object_safe::<dyn ProcessLauncher>();
    assert_object_safe::<dyn ApprovedProcessExecutor>();
    assert_object_safe::<dyn ToolExecutionStore>();
    assert_object_safe::<dyn StructuredToolExecutor>();
}

#[test]
fn disclosure_request_binds_policy_input_channel_and_exact_bytes() {
    let request = DisclosureRequest {
        policy_request: policy_request(),
        channel: DisclosureChannel::FileRead,
        bytes: b"API_TOKEN=secret".to_vec(),
    };

    assert_eq!(request.channel, DisclosureChannel::FileRead);
    assert_eq!(request.bytes, b"API_TOKEN=secret");
}

#[test]
fn file_write_session_input_binds_target_lease_and_authoritative_pre_image() {
    let bytes = b"before".to_vec();
    let expected_pre_digest =
        Sha256Digest::new(format!("sha256:{:x}", sha2::Sha256::digest(&bytes))).unwrap();
    let session = OpenFileWriteSession::new(
        ToolExecutionId::new("file-write-session-1").unwrap(),
        task_id(),
        CapabilityRootIdentity::new("worktree-root-1").unwrap(),
        RelativePathComponents::new(vec!["src".into(), "main.rs".into()]).unwrap(),
        Some(expected_pre_digest.clone()),
        LeaseClaim::new(
            task_id(),
            RunId::new("run-1").unwrap(),
            FencingToken::new(19).unwrap(),
        ),
    )
    .unwrap();
    let pre_image = ObservedFileImage::present(bytes);
    let expected_post = FileWritePostExpectation::new(digest('2'), 12).unwrap();

    let capture =
        CaptureFileWritePreEvidence::new(session.clone(), expected_post, pre_image).unwrap();

    assert_eq!(capture.session(), &session);
    assert_eq!(
        capture.pre_image().present_bytes().unwrap().digest,
        expected_pre_digest
    );
    assert_eq!(
        capture.pre_image().present_bytes().unwrap().bytes,
        b"before"
    );

    let cross_task_claim = LeaseClaim::new(
        TaskId::new("task-2").unwrap(),
        RunId::new("run-1").unwrap(),
        FencingToken::new(19).unwrap(),
    );
    assert!(OpenFileWriteSession::new(
        ToolExecutionId::new("file-write-session-2").unwrap(),
        task_id(),
        CapabilityRootIdentity::new("worktree-root-1").unwrap(),
        RelativePathComponents::new(vec!["src".into(), "main.rs".into()]).unwrap(),
        None,
        cross_task_claim,
    )
    .is_err());

    let mismatched_target = OpenFileWriteSession::new(
        ToolExecutionId::new("file-write-session-3").unwrap(),
        task_id(),
        CapabilityRootIdentity::new("worktree-root-1").unwrap(),
        RelativePathComponents::new(vec!["src".into(), "main.rs".into()]).unwrap(),
        Some(digest('9')),
        LeaseClaim::new(
            task_id(),
            RunId::new("run-1").unwrap(),
            FencingToken::new(19).unwrap(),
        ),
    )
    .unwrap();
    assert!(CaptureFileWritePreEvidence::new(
        mismatched_target,
        FileWritePostExpectation::new(digest('2'), 12).unwrap(),
        ObservedFileImage::present(b"before".to_vec()),
    )
    .is_err());
}

#[test]
fn post_write_evidence_accepts_only_the_durable_digest_and_size() {
    let recovery_request = file_write_recovery_request();
    let matching = VerifiedWrite {
        digest: recovery_request.expected_post_digest.clone(),
        size_bytes: recovery_request.expected_post_size,
    };

    let capture =
        CaptureFileWritePostEvidence::new(recovery_request.clone(), matching.clone()).unwrap();

    assert_eq!(capture.recovery_request(), &recovery_request);
    assert_eq!(capture.observed_post(), &matching);
    assert!(CaptureFileWritePostEvidence::new(
        recovery_request.clone(),
        VerifiedWrite {
            digest: digest('9'),
            size_bytes: recovery_request.expected_post_size,
        },
    )
    .is_err());
    assert!(CaptureFileWritePostEvidence::new(
        recovery_request.clone(),
        VerifiedWrite {
            digest: recovery_request.expected_post_digest.clone(),
            size_bytes: recovery_request.expected_post_size + 1,
        },
    )
    .is_err());
}

#[test]
fn file_write_recovery_request_round_trips_canonical_identity() {
    let request = file_write_recovery_request();

    let canonical = canonical_file_write_recovery_request(&request).unwrap();

    assert_eq!(
        parse_file_write_recovery_request(&canonical.canonical_bytes).unwrap(),
        request
    );
    assert_eq!(
        canonical.operation_digest,
        Sha256Digest::new(format!(
            "sha256:{:x}",
            sha2::Sha256::digest(&canonical.canonical_bytes)
        ))
        .unwrap()
    );
    assert!(!String::from_utf8(canonical.canonical_bytes)
        .unwrap()
        .contains("C:\\"));
}

#[test]
fn file_write_recovery_digest_changes_with_every_effect_identity() {
    let baseline = file_write_recovery_request();
    let baseline_digest = canonical_file_write_recovery_request(&baseline)
        .unwrap()
        .operation_digest;
    let mut changed_target = baseline.clone();
    changed_target.relative_components =
        RelativePathComponents::new(vec!["other.txt".to_owned()]).unwrap();
    let mut changed_lease = baseline.clone();
    changed_lease.lease_claim = LeaseClaim::new(
        task_id(),
        RunId::new("run-2").unwrap(),
        FencingToken::new(20).unwrap(),
    );
    let mut changed_pre_image = baseline.clone();
    changed_pre_image.pre_image = FileWritePreImage::Absent;
    let mut changed_post = baseline.clone();
    changed_post.expected_post_digest = digest('9');
    let mut changed_policy = baseline.clone();
    changed_policy.policy.operation_digest = digest('8');

    for changed in [
        changed_target,
        changed_lease,
        changed_pre_image,
        changed_post,
        changed_policy,
    ] {
        assert_ne!(
            canonical_file_write_recovery_request(&changed)
                .unwrap()
                .operation_digest,
            baseline_digest
        );
    }
}

#[test]
fn file_write_recovery_request_rejects_unbound_or_noncanonical_evidence() {
    let mut cross_task = file_write_recovery_request();
    let FileWritePreImage::Artifact(pre_image) = &mut cross_task.pre_image else {
        unreachable!()
    };
    pre_image.task_id = Some(TaskId::new("task-2").unwrap());
    assert!(canonical_file_write_recovery_request(&cross_task).is_err());

    let canonical = canonical_file_write_recovery_request(&file_write_recovery_request()).unwrap();
    let mut noncanonical = vec![b' '];
    noncanonical.extend_from_slice(&canonical.canonical_bytes);
    assert!(parse_file_write_recovery_request(&noncanonical).is_err());
}

#[test]
fn arguments_digest_binds_only_argv() {
    let baseline_request = authorized_process_request_for(RequestMutation::None);
    let baseline_payload = approved_tool_payload(&baseline_request, APPROVAL_NONCE);
    let baseline_arguments_digest = baseline_payload.operation.arguments_digest.clone();
    let baseline_operation_digest =
        canonical_approval_payload(&ApprovalDigestPayload::Tool(baseline_payload))
            .unwrap()
            .operation_digest;

    for mutation in [
        RequestMutation::Task,
        RequestMutation::Run,
        RequestMutation::PlanStep,
        RequestMutation::Phase,
        RequestMutation::Workspace,
        RequestMutation::Fencing,
        RequestMutation::Executable,
        RequestMutation::Cwd,
        RequestMutation::Environment,
        RequestMutation::Network,
        RequestMutation::ExpectedReads,
        RequestMutation::ExpectedWrites,
        RequestMutation::Timeout,
        RequestMutation::MemoryLimit,
        RequestMutation::CpuLimit,
        RequestMutation::DiskWriteLimit,
    ] {
        let request = authorized_process_request_for(mutation);
        let payload = approved_tool_payload(&request, APPROVAL_NONCE);

        assert_eq!(
            payload.operation.arguments_digest, baseline_arguments_digest,
            "{mutation:?}"
        );
    }

    for mutation in [
        RequestMutation::Task,
        RequestMutation::Run,
        RequestMutation::PlanStep,
        RequestMutation::Workspace,
        RequestMutation::Fencing,
        RequestMutation::Cwd,
        RequestMutation::Environment,
        RequestMutation::Network,
        RequestMutation::ExpectedWrites,
    ] {
        let request = authorized_process_request_for(mutation);
        let payload = approved_tool_payload(&request, APPROVAL_NONCE);
        assert_ne!(
            canonical_approval_payload(&ApprovalDigestPayload::Tool(payload))
                .unwrap()
                .operation_digest,
            baseline_operation_digest,
            "{mutation:?}"
        );
    }

    for mutation in [
        RequestMutation::Phase,
        RequestMutation::Executable,
        RequestMutation::ExpectedReads,
        RequestMutation::Timeout,
        RequestMutation::MemoryLimit,
        RequestMutation::CpuLimit,
    ] {
        let request = authorized_process_request_for(mutation);
        let payload = approved_tool_payload(&request, APPROVAL_NONCE);
        assert_eq!(
            canonical_approval_payload(&ApprovalDigestPayload::Tool(payload))
                .unwrap()
                .operation_digest,
            baseline_operation_digest,
            "{mutation:?}"
        );
    }

    let changed_arguments = approved_tool_payload(
        &authorized_process_request_for(RequestMutation::Arguments),
        APPROVAL_NONCE,
    );
    assert_ne!(
        changed_arguments.operation.arguments_digest,
        baseline_arguments_digest
    );
}

#[test]
fn trusted_request_binding_covers_every_execution_detail() {
    let baseline = approved_tool_binding(
        &authorized_process_request_for(RequestMutation::None),
        APPROVAL_NONCE,
    );

    for mutation in [
        RequestMutation::Task,
        RequestMutation::Run,
        RequestMutation::PlanStep,
        RequestMutation::Phase,
        RequestMutation::Workspace,
        RequestMutation::Fencing,
        RequestMutation::Executable,
        RequestMutation::Arguments,
        RequestMutation::Cwd,
        RequestMutation::Environment,
        RequestMutation::Network,
        RequestMutation::ExpectedReads,
        RequestMutation::ExpectedWrites,
        RequestMutation::Timeout,
        RequestMutation::MemoryLimit,
        RequestMutation::CpuLimit,
    ] {
        let changed =
            approved_tool_binding(&authorized_process_request_for(mutation), APPROVAL_NONCE);

        assert_ne!(
            changed.request_binding_digest(),
            baseline.request_binding_digest(),
            "{mutation:?}"
        );
    }
}

#[test]
fn process_approval_freezes_digest_version_path_and_file_identity() {
    let baseline_request = authorized_process_request_for(RequestMutation::None);
    let baseline = approved_tool_binding(&baseline_request, APPROVAL_NONCE);

    assert_eq!(
        baseline.payload().operation.executable_digest.as_deref(),
        Some(digest('d').as_str())
    );

    for approved_executable in [
        approved_executable_identity(
            "cargo",
            "1.98.0",
            "approved-cargo.exe",
            digest('d'),
            "file-cargo",
        ),
        approved_executable_identity(
            "cargo",
            "1.97.1",
            "approved-cargo.exe",
            digest('9'),
            "file-cargo",
        ),
        approved_executable_identity(
            "cargo",
            "1.97.1",
            "replacement-cargo.exe",
            digest('d'),
            "file-cargo",
        ),
        approved_executable_identity(
            "cargo",
            "1.97.1",
            "approved-cargo.exe",
            digest('d'),
            "replacement-file-cargo",
        ),
    ] {
        let changed_request = ApprovedProcessRequest::new(
            approved_executable,
            baseline_request.process().clone(),
            baseline_request.expected_reads().to_vec(),
            baseline_request.memory_limit_bytes(),
            baseline_request.cpu_time_limit_ms(),
            baseline_request.disk_write_limit_bytes(),
        )
        .unwrap();
        let changed = approved_tool_binding(&changed_request, APPROVAL_NONCE);

        assert_ne!(
            changed.request_binding_digest(),
            baseline.request_binding_digest()
        );
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RequestMutation {
    None,
    Task,
    Workspace,
    Fencing,
    Run,
    PlanStep,
    Phase,
    Executable,
    Arguments,
    Cwd,
    Environment,
    Network,
    ExpectedReads,
    ExpectedWrites,
    Timeout,
    MemoryLimit,
    CpuLimit,
    DiskWriteLimit,
}

fn authorized_process_request_for(mutation: RequestMutation) -> ApprovedProcessRequest {
    let task_id = TaskId::new(if mutation == RequestMutation::Task {
        "task-2"
    } else {
        "task-1"
    })
    .unwrap();
    let environment_digest = if mutation == RequestMutation::Environment {
        digest('f')
    } else {
        digest('e')
    };
    let binding = ProcessBinding::new(
        task_id.clone(),
        RunId::new(if mutation == RequestMutation::Run {
            "run-2"
        } else {
            "run-1"
        })
        .unwrap(),
        PlanStepId::new(if mutation == RequestMutation::PlanStep {
            "step-2"
        } else {
            "step-1"
        })
        .unwrap(),
        if mutation == RequestMutation::Phase {
            Phase::Verification
        } else {
            Phase::Implementation
        },
        WorkspaceVersion::new(if mutation == RequestMutation::Workspace {
            5
        } else {
            4
        }),
        EnvironmentProfile::new("rust", environment_digest).unwrap(),
        if mutation == RequestMutation::Timeout {
            2
        } else {
            1
        },
    )
    .unwrap();
    let expected_writes = if mutation == RequestMutation::ExpectedWrites {
        vec![
            ExpectedWrite::new(CapabilityRef::worktree(task_id.clone(), "target").unwrap())
                .unwrap(),
        ]
    } else {
        Vec::new()
    };
    let process = ProcessToolRequest::new(
        binding,
        ProcessInvocation::new(
            CapabilityRef::toolchain(if mutation == RequestMutation::Executable {
                "rustc"
            } else {
                "cargo"
            })
            .unwrap(),
            if mutation == RequestMutation::Arguments {
                vec!["check".to_owned()]
            } else {
                vec!["test".to_owned()]
            },
            CapabilityRef::worktree(
                task_id.clone(),
                if mutation == RequestMutation::Cwd {
                    "src"
                } else {
                    "."
                },
            )
            .unwrap(),
            ProcessTrustTier::IsolatedWorker,
            if mutation == RequestMutation::Network {
                NetworkProfile::ApprovedDestinations
            } else {
                NetworkProfile::Denied
            },
            expected_writes,
            Some(
                FencingToken::new(if mutation == RequestMutation::Fencing {
                    20
                } else {
                    19
                })
                .unwrap(),
            ),
        )
        .unwrap(),
    )
    .unwrap();
    ApprovedProcessRequest::new(
        approved_executable_identity(
            if mutation == RequestMutation::Executable {
                "rustc"
            } else {
                "cargo"
            },
            "1.97.1",
            "approved-cargo.exe",
            digest('d'),
            "file-cargo",
        ),
        process,
        match mutation {
            RequestMutation::ExpectedReads => {
                vec![CapabilityRef::worktree(task_id, "src").unwrap()]
            }
            _ => Vec::new(),
        },
        (mutation == RequestMutation::MemoryLimit).then_some(1024),
        (mutation == RequestMutation::CpuLimit).then_some(500),
        (mutation == RequestMutation::DiskWriteLimit).then_some(2048),
    )
    .unwrap()
}

fn approved_executable_identity(
    toolchain_id: &str,
    version: &str,
    file_name: &str,
    sha256: Sha256Digest,
    file_identity: &str,
) -> ApprovedExecutableIdentity {
    ApprovedExecutableIdentity::new(
        ResolvedExecutable {
            canonical_path: absolute_test_path(file_name),
            sha256,
            file_identity: ExecutableFileIdentity::new(file_identity).unwrap(),
            toolchain_id: toolchain_id.to_owned(),
        },
        version,
    )
    .unwrap()
}

fn absolute_test_path(file_name: &str) -> PathBuf {
    std::env::temp_dir()
        .join("local-agent-terminal-approved-executables")
        .join(file_name)
}

const APPROVAL_NONCE: &str = "0123456789abcdef0123456789abcdef";

fn approved_tool_payload(request: &ApprovedProcessRequest, nonce: &str) -> ToolApprovalPayloadV1 {
    approved_tool_binding(request, nonce).payload().clone()
}

fn approved_tool_binding(request: &ApprovedProcessRequest, nonce: &str) -> BoundToolApproval {
    bind_tool_approval_payload(
        ToolApprovalPayloadV1 {
            schema: "approval-digest.v1".to_owned(),
            approval_type: "tool".to_owned(),
            task_id: "unbound".to_owned(),
            operation: ToolApprovalOperationV1 {
                run_id: "unbound".to_owned(),
                plan_step_id: "unbound".to_owned(),
                tool: "process.exec".to_owned(),
                executable_digest: None,
                arguments_digest: digest('0').as_str().to_owned(),
                script_digest: None,
                cwd_capability: "unbound".to_owned(),
                environment_profile_digest: digest('0').as_str().to_owned(),
                network_profile: "denied".to_owned(),
                expected_writes: Vec::new(),
                executor_fencing_token: None,
            },
            policy_snapshot_digest: digest('b').as_str().to_owned(),
            workspace_version: 0,
            requested_at: "2026-07-23T12:00:00Z".to_owned(),
            expires_at: "2026-07-23T12:15:00Z".to_owned(),
            nonce: nonce.to_owned(),
        },
        request,
    )
    .unwrap()
}

fn task_id() -> TaskId {
    TaskId::new("task-1").unwrap()
}

fn policy_request() -> local_agent_terminal_domain::PolicyRequest {
    use local_agent_terminal_domain::{
        ActorLocality, CapabilityRef, PolicyAction, PolicyActor, PolicyResource, ResourceClass,
        TaskRisk, Timestamp, TrustTier,
    };

    local_agent_terminal_domain::PolicyRequest {
        task_id: task_id(),
        actor: PolicyActor {
            connection_id: "connection-1".to_owned(),
            agent_id: "agent-1".to_owned(),
            trust_tier: TrustTier::CoreAdapter,
            locality: ActorLocality::Local,
        },
        action: PolicyAction::new("tool.read").unwrap(),
        resource: PolicyResource {
            capability: CapabilityRef::worktree(task_id(), "file.txt").unwrap(),
            content_digest: digest('a'),
            resource_class: ResourceClass::InternalCode,
        },
        task_risk: TaskRisk::Low,
        workflow_phase: "Implementation".to_owned(),
        purpose: "test".to_owned(),
        policy_snapshot_digest: digest('b'),
        evaluated_at: Timestamp::from_unix_seconds(1),
    }
}

fn file_write_recovery_request() -> FileWriteRecoveryRequest {
    let task_id = task_id();
    FileWriteRecoveryRequest {
        execution_id: ToolExecutionId::new("file-write-1").unwrap(),
        task_id: task_id.clone(),
        root_identity: CapabilityRootIdentity::new("worktree-root-1").unwrap(),
        relative_components: RelativePathComponents::new(vec!["src".into(), "main.rs".into()])
            .unwrap(),
        lease_claim: LeaseClaim::new(
            task_id.clone(),
            RunId::new("run-1").unwrap(),
            FencingToken::new(19).unwrap(),
        ),
        expected_sequence: Sequence::new(7),
        pre_image: FileWritePreImage::Artifact(evidence("pre-image", "1", "objects/pre-image")),
        expected_post_digest: digest('2'),
        expected_post_size: 12,
        pre_fingerprint: WorkspaceFingerprint::new(
            GitObjectId::new("a".repeat(40)).unwrap(),
            digest('3').as_str(),
            digest('4').as_str(),
        )
        .unwrap(),
        pre_evidence: evidence("pre-evidence", "5", "objects/pre-evidence"),
        actor_id: ActorId::new("tool-runtime").unwrap(),
        correlation_id: "file-write:file-write-1".to_owned(),
        policy: FileWritePolicyBinding {
            decision_id: "policy-file-write-1".to_owned(),
            operation_digest: digest('6'),
            policy_snapshot_digest: digest('b'),
            effect: PolicyEffect::Allow,
            approval_id: None,
        },
    }
}

fn evidence(id: &str, hash: &str, storage_key: &str) -> CanonicalEvidenceRef {
    CanonicalEvidenceRef {
        artifact_id: ArtifactId::new(id).unwrap(),
        content_hash: format!("sha256:{}", hash.repeat(64)),
        storage_key: storage_key.to_owned(),
        size_bytes: 12,
        project_id: ProjectId::new("project-1").unwrap(),
        task_id: Some(task_id()),
    }
}

fn digest(character: char) -> Sha256Digest {
    Sha256Digest::new(format!("sha256:{}", character.to_string().repeat(64))).unwrap()
}
