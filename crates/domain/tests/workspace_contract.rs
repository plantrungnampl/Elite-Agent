use local_agent_terminal_domain::{
    authorize_fenced_write, ArtifactId, FencedWriteError, FencingToken, GitObjectId, LeaseClaim,
    ProjectId, RepositoryId, RunId, TaskBranch, TaskId, WorkspaceFingerprint, WorktreeId,
};

const SHA1: &str = "1111111111111111111111111111111111111111";
const SHA256: &str = "2222222222222222222222222222222222222222222222222222222222222222";
const DIGEST_A: &str = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const DIGEST_B: &str = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

#[test]
fn repository_workspace_identifiers_reject_empty_values() {
    assert!(ProjectId::new(" ").is_err());
    assert!(RunId::new("\t").is_err());
    assert!(ArtifactId::new("").is_err());
    assert!(RepositoryId::new("\r\n").is_err());
    assert!(WorktreeId::new(" ").is_err());

    assert_eq!(ProjectId::new("project-1").unwrap().as_str(), "project-1");
}

#[test]
fn git_object_ids_support_exact_sha1_and_sha256_values() {
    assert_eq!(GitObjectId::new(SHA1).unwrap().as_str(), SHA1);
    assert_eq!(GitObjectId::new(SHA256).unwrap().as_str(), SHA256);

    for invalid in [
        "",
        "abc",
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "111111111111111111111111111111111111111g",
        "11111111111111111111111111111111111111111",
    ] {
        assert!(GitObjectId::new(invalid).is_err(), "{invalid}");
    }
}

#[test]
fn task_branches_reject_git_ref_hazards() {
    assert_eq!(
        TaskBranch::new("codex/task-123").unwrap().as_str(),
        "codex/task-123"
    );

    for invalid in [
        "",
        ".hidden",
        "/leading",
        "trailing/",
        "trailing.",
        "has space",
        "two..dots",
        "reflog@{1}",
        "branch.lock",
        "bad~ref",
        "bad^ref",
        "bad:ref",
        "bad?ref",
        "bad*ref",
        "bad[ref",
        "bad\\ref",
        "double//slash",
    ] {
        assert!(TaskBranch::new(invalid).is_err(), "{invalid}");
    }
}

#[test]
fn workspace_fingerprint_validates_each_digest() {
    let fingerprint =
        WorkspaceFingerprint::new(GitObjectId::new(SHA1).unwrap(), DIGEST_A, DIGEST_B).unwrap();

    assert_eq!(fingerprint.head().as_str(), SHA1);
    assert_eq!(fingerprint.index_digest(), DIGEST_A);
    assert_eq!(fingerprint.status_digest(), DIGEST_B);
    assert!(WorkspaceFingerprint::new(
        GitObjectId::new(SHA1).unwrap(),
        "sha256:not-a-digest",
        DIGEST_B,
    )
    .is_err());
}

#[test]
fn only_the_current_active_lease_claim_is_authorized() {
    let task_id = TaskId::new("task-1").unwrap();
    let holder = RunId::new("run-1").unwrap();
    let current = LeaseClaim::new(
        task_id.clone(),
        holder.clone(),
        FencingToken::new(2).unwrap(),
    );
    let same = current.clone();

    assert_eq!(authorize_fenced_write(Some(&current), &same), Ok(()));
    assert_eq!(
        authorize_fenced_write(None, &same),
        Err(FencedWriteError::LeaseNotActive)
    );

    let stale = LeaseClaim::new(task_id.clone(), holder, FencingToken::new(1).unwrap());
    assert_eq!(
        authorize_fenced_write(Some(&current), &stale),
        Err(FencedWriteError::StaleFencingToken {
            current: FencingToken::new(2).unwrap(),
            supplied: FencingToken::new(1).unwrap(),
        })
    );

    let wrong_holder = LeaseClaim::new(
        task_id,
        RunId::new("run-2").unwrap(),
        FencingToken::new(2).unwrap(),
    );
    assert_eq!(
        authorize_fenced_write(Some(&current), &wrong_holder),
        Err(FencedWriteError::LeaseNotActive)
    );
    assert_eq!(current, same);
}
