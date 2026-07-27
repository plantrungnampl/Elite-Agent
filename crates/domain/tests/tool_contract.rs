use local_agent_terminal_domain::{
    CapabilityRef, ExpectedWrite, FencingToken, NetworkProfile, ProcessToolRequest,
    ProcessTrustTier, RawShellRequest, Sha256Digest, StructuredToolName, TaskId, ToolError,
};

const DIGEST: &str = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

fn worktree(path: &str) -> CapabilityRef {
    CapabilityRef::worktree(TaskId::new("task-1").unwrap(), path).unwrap()
}

fn process(expected_writes: Vec<ExpectedWrite>, token: Option<FencingToken>) -> ProcessToolRequest {
    ProcessToolRequest::new(
        CapabilityRef::toolchain("cargo").unwrap(),
        vec!["test".into()],
        worktree("."),
        ProcessTrustTier::IsolatedWorker,
        NetworkProfile::Denied,
        expected_writes,
        token,
    )
    .unwrap()
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
            CapabilityRef::worktree(TaskId::new("task-1").unwrap(), invalid).is_err(),
            "{invalid:?}"
        );
        assert!(
            CapabilityRef::source("main", invalid).is_err(),
            "{invalid:?}"
        );
    }
}

#[test]
fn process_requests_reject_empty_boundaries_and_null_bytes() {
    assert!(ProcessToolRequest::new(
        CapabilityRef::toolchain("cargo").unwrap(),
        vec![],
        worktree("."),
        ProcessTrustTier::BrokeredProcess,
        NetworkProfile::Denied,
        vec![],
        None,
    )
    .is_err());

    assert!(ProcessToolRequest::new(
        CapabilityRef::toolchain("cargo").unwrap(),
        vec!["test\0--workspace".into()],
        worktree("."),
        ProcessTrustTier::BrokeredProcess,
        NetworkProfile::Denied,
        vec![],
        None,
    )
    .is_err());
}

#[test]
fn writes_require_a_current_fencing_token_and_are_unique() {
    let write = ExpectedWrite::new(worktree("target/**")).unwrap();
    assert!(matches!(
        ProcessToolRequest::new(
            CapabilityRef::toolchain("cargo").unwrap(),
            vec!["test".into()],
            worktree("."),
            ProcessTrustTier::IsolatedWorker,
            NetworkProfile::Denied,
            vec![write.clone()],
            None,
        ),
        Err(ToolError::MissingFencingToken)
    ));

    assert!(matches!(
        ProcessToolRequest::new(
            CapabilityRef::toolchain("cargo").unwrap(),
            vec!["test".into()],
            worktree("."),
            ProcessTrustTier::IsolatedWorker,
            NetworkProfile::Denied,
            vec![write.clone(), write],
            Some(FencingToken::new(1).unwrap()),
        ),
        Err(ToolError::DuplicateExpectedWrite)
    ));

    assert_eq!(
        process(
            vec![ExpectedWrite::new(worktree("target/**")).unwrap()],
            Some(FencingToken::new(1).unwrap()),
        )
        .tool(),
        StructuredToolName::ProcessExec,
    );
}

#[test]
fn default_profile_denies_raw_shell_requests() {
    let raw = RawShellRequest::new(
        CapabilityRef::toolchain("powershell").unwrap(),
        Sha256Digest::new(DIGEST).unwrap(),
        worktree("."),
    )
    .unwrap();

    assert!(raw.validate_default_profile().is_err());
}
