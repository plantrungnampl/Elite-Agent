use std::fs;

use git2::{Repository, Signature};
use local_agent_terminal_application::{AuthorizedGitDiff, AuthorizedGitStatus, StructuredGit};
use local_agent_terminal_domain::{CapabilityRef, TaskId};
use local_agent_terminal_repository_git::{GitRepositoryGateway, GitStructuredTools};
use tempfile::TempDir;

#[test]
fn status_and_diff_are_in_process_and_fail_closed_for_hostile_configuration() {
    let fixture = TempDir::new().unwrap();
    let repository = Repository::init(fixture.path()).unwrap();
    fs::write(fixture.path().join("README.md"), b"one\n").unwrap();
    let mut index = repository.index().unwrap();
    index.add_path(std::path::Path::new("README.md")).unwrap();
    index.write().unwrap();
    let tree_id = index.write_tree().unwrap();
    let signature = Signature::now("test", "test@example.com").unwrap();
    repository
        .commit(
            Some("HEAD"),
            &signature,
            &signature,
            "initial",
            &repository.find_tree(tree_id).unwrap(),
            &[],
        )
        .unwrap();
    repository
        .config()
        .unwrap()
        .set_str("diff.external", "must-not-run")
        .unwrap();

    let managed = fixture.path().join("managed");
    fs::create_dir(&managed).unwrap();
    let gateway = GitRepositoryGateway::open(&managed, &[]).unwrap();
    let tools = GitStructuredTools::new(gateway.locate(fixture.path()).unwrap(), task());
    for result in [
        tools
            .status(AuthorizedGitStatus {
                task_id: task(),
                worktree: worktree(),
                policy_decision_id: "policy-1".to_owned(),
            })
            .map(|_| ()),
        tools
            .diff(AuthorizedGitDiff {
                task_id: task(),
                worktree: worktree(),
                policy_decision_id: "policy-1".to_owned(),
            })
            .map(|_| ()),
    ] {
        assert!(result.is_err());
    }
    assert_eq!(
        fs::read(fixture.path().join("README.md")).unwrap(),
        b"one\n"
    );
}

#[test]
fn status_binds_the_repository_revision_scope_and_policy_decision() {
    let fixture = TempDir::new().unwrap();
    let repository = Repository::init(fixture.path()).unwrap();
    fs::write(fixture.path().join("README.md"), b"one\n").unwrap();
    let mut index = repository.index().unwrap();
    index.add_path(std::path::Path::new("README.md")).unwrap();
    index.write().unwrap();
    let tree_id = index.write_tree().unwrap();
    let signature = Signature::now("test", "test@example.com").unwrap();
    let commit = repository
        .commit(
            Some("HEAD"),
            &signature,
            &signature,
            "initial",
            &repository.find_tree(tree_id).unwrap(),
            &[],
        )
        .unwrap();
    fs::write(fixture.path().join("README.md"), b"two\n").unwrap();
    let managed = fixture.path().join("managed");
    fs::create_dir(&managed).unwrap();
    let gateway = GitRepositoryGateway::open(&managed, &[]).unwrap();
    let locator = gateway.locate(fixture.path()).unwrap();
    let tools = GitStructuredTools::new(locator.clone(), task());

    let result = tools
        .status(AuthorizedGitStatus {
            task_id: task(),
            worktree: worktree(),
            policy_decision_id: "policy-1".to_owned(),
        })
        .unwrap();

    assert_eq!(result.repository_id, locator.repository_id);
    assert_eq!(result.revision.as_str(), commit.to_string());
    assert_eq!(result.path_scope, worktree());
    assert!(!result.truncated);
    assert_eq!(result.policy_decision_id, "policy-1");
}

fn task() -> TaskId {
    TaskId::new("task-1").unwrap()
}
fn worktree() -> CapabilityRef {
    CapabilityRef::worktree(task(), ".").unwrap()
}
