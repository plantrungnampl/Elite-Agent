use local_agent_terminal_domain::{
    ArtifactId, CapabilityRef, EnvironmentProfile, ExpectedWrite, FencingToken, NetworkProfile,
    Phase, PlanStepId, ProcessBinding, ProcessInvocation, ProcessToolRequest, ProcessTrustTier,
    RawShellRequest, RunId, Sha256Digest, StructuredToolName, TaskId, ToolError, WorkspaceVersion,
};

const DIGEST: &str = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

fn task_id() -> TaskId {
    TaskId::new("task-1").unwrap()
}

fn worktree(task_id: TaskId, path: &str) -> CapabilityRef {
    CapabilityRef::worktree(task_id, path).unwrap()
}

fn binding(task_id: TaskId) -> ProcessBinding {
    ProcessBinding::new(
        task_id,
        RunId::new("run-1").unwrap(),
        PlanStepId::new("step-1").unwrap(),
        Phase::Implementation,
        WorkspaceVersion::new(3),
        EnvironmentProfile::new("rust-build-no-secrets", Sha256Digest::new(DIGEST).unwrap())
            .unwrap(),
        600_000,
    )
    .unwrap()
}

fn process(
    binding: ProcessBinding,
    cwd: CapabilityRef,
    expected_writes: Vec<ExpectedWrite>,
    token: Option<FencingToken>,
) -> ProcessToolRequest {
    let invocation = ProcessInvocation::new(
        CapabilityRef::toolchain("cargo").unwrap(),
        vec!["test".into()],
        cwd,
        ProcessTrustTier::IsolatedWorker,
        NetworkProfile::Denied,
        expected_writes,
        token,
    )
    .unwrap();
    ProcessToolRequest::new(binding, invocation).unwrap()
}

#[test]
fn capability_references_reject_paths_that_can_escape_the_broker() {
    assert!(CapabilityRef::toolchain("").is_err());

    for invalid in [
        "",
        "/absolute",
        "C:\\absolute",
        "../escape",
        "src/../escape",
        "src\0file",
    ] {
        assert!(
            CapabilityRef::worktree(task_id(), invalid).is_err(),
            "{invalid:?}"
        );
        assert!(
            CapabilityRef::source("main", invalid).is_err(),
            "{invalid:?}"
        );
    }

    assert!(CapabilityRef::artifact(ArtifactId::new("x".repeat(257)).unwrap()).is_err());
    assert!(CapabilityRef::artifact(ArtifactId::new("artifact\0id").unwrap()).is_err());
}

#[test]
fn process_bindings_require_valid_complete_domain_fields() {
    assert!(PlanStepId::new("").is_err());
    assert!(PlanStepId::new("x".repeat(257)).is_err());
    assert!(EnvironmentProfile::new("", Sha256Digest::new(DIGEST).unwrap()).is_err());
    assert!(ProcessBinding::new(
        task_id(),
        RunId::new("run-1").unwrap(),
        PlanStepId::new("step-1").unwrap(),
        Phase::Implementation,
        WorkspaceVersion::new(3),
        EnvironmentProfile::new("rust-build", Sha256Digest::new(DIGEST).unwrap()).unwrap(),
        0,
    )
    .is_err());
}

#[test]
fn process_requests_reject_empty_boundaries_and_null_bytes() {
    assert!(ProcessInvocation::new(
        CapabilityRef::toolchain("cargo").unwrap(),
        vec![],
        worktree(task_id(), "."),
        ProcessTrustTier::BrokeredProcess,
        NetworkProfile::Denied,
        vec![],
        None,
    )
    .is_err());

    assert!(ProcessInvocation::new(
        CapabilityRef::toolchain("cargo").unwrap(),
        vec!["test\0--workspace".into()],
        worktree(task_id(), "."),
        ProcessTrustTier::BrokeredProcess,
        NetworkProfile::Denied,
        vec![],
        None,
    )
    .is_err());
}

#[test]
fn process_requests_reject_cross_task_capability_scopes() {
    assert!(matches!(
        ProcessToolRequest::new(
            binding(task_id()),
            ProcessInvocation::new(
                CapabilityRef::toolchain("cargo").unwrap(),
                vec!["test".into()],
                worktree(TaskId::new("other-task").unwrap(), "."),
                ProcessTrustTier::IsolatedWorker,
                NetworkProfile::Denied,
                vec![],
                None,
            )
            .unwrap(),
        ),
        Err(ToolError::MismatchedTaskScope)
    ));

    assert!(matches!(
        ProcessToolRequest::new(
            binding(task_id()),
            ProcessInvocation::new(
                CapabilityRef::toolchain("cargo").unwrap(),
                vec!["test".into()],
                worktree(task_id(), "."),
                ProcessTrustTier::IsolatedWorker,
                NetworkProfile::Denied,
                vec![
                    ExpectedWrite::new(worktree(TaskId::new("other-task").unwrap(), "target/**"))
                        .unwrap()
                ],
                Some(FencingToken::new(1).unwrap()),
            )
            .unwrap(),
        ),
        Err(ToolError::MismatchedTaskScope)
    ));
}

#[test]
fn writes_require_a_current_fencing_token_and_are_unique() {
    let write = ExpectedWrite::new(worktree(task_id(), "target/**")).unwrap();
    assert!(matches!(
        ProcessInvocation::new(
            CapabilityRef::toolchain("cargo").unwrap(),
            vec!["test".into()],
            worktree(task_id(), "."),
            ProcessTrustTier::IsolatedWorker,
            NetworkProfile::Denied,
            vec![write.clone()],
            None,
        ),
        Err(ToolError::MissingFencingToken)
    ));

    assert!(matches!(
        ProcessInvocation::new(
            CapabilityRef::toolchain("cargo").unwrap(),
            vec!["test".into()],
            worktree(task_id(), "."),
            ProcessTrustTier::IsolatedWorker,
            NetworkProfile::Denied,
            vec![write.clone(), write],
            Some(FencingToken::new(1).unwrap()),
        ),
        Err(ToolError::DuplicateExpectedWrite)
    ));

    let request = process(
        binding(task_id()),
        worktree(task_id(), "."),
        vec![ExpectedWrite::new(worktree(task_id(), "target/**")).unwrap()],
        Some(FencingToken::new(1).unwrap()),
    );
    assert_eq!(request.tool(), StructuredToolName::ProcessExec);
    assert_eq!(request.binding().task_id().as_str(), "task-1");
    assert_eq!(request.binding().run_id().as_str(), "run-1");
    assert_eq!(request.binding().plan_step_id().as_str(), "step-1");
    assert_eq!(request.binding().workflow_phase(), Phase::Implementation);
    assert_eq!(
        request.binding().workspace_version(),
        WorkspaceVersion::new(3)
    );
    assert_eq!(
        request.binding().environment_profile().name(),
        "rust-build-no-secrets"
    );
    assert_eq!(
        request.binding().environment_profile().digest().as_str(),
        DIGEST
    );
    assert_eq!(request.binding().timeout_ms(), 600_000);
}

#[test]
fn default_profile_denies_raw_shell_requests() {
    let raw = RawShellRequest::new(
        CapabilityRef::toolchain("powershell").unwrap(),
        Sha256Digest::new(DIGEST).unwrap(),
        worktree(task_id(), "."),
    )
    .unwrap();

    assert!(raw.validate_default_profile().is_err());
}
