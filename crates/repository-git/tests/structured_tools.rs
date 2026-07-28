use std::fs;

use git2::{Repository, Signature};
use local_agent_terminal_application::{
    AuthorizedGitDiff, AuthorizedGitStatus, CapabilityRootIdentity, StructuredGit,
};
use local_agent_terminal_domain::{CapabilityRef, GitObjectId, TaskId};
use local_agent_terminal_repository_git::{
    GitRepositoryGateway, GitStructuredTools, GitWorktreeRegistration,
};
use tempfile::TempDir;

#[test]
fn scoped_credential_proxy_ssh_and_protocol_configuration_fail_closed() {
    for (name, value) in [
        ("credential.https://example.invalid.helper", "must-not-run"),
        ("http.proxy", "http://127.0.0.1:9"),
        ("http.extraHeader", "Authorization: secret"),
        ("ssh.variant", "plink"),
        ("protocol.ext.allow", "always"),
    ] {
        let fixture = initialized_repository("one\n");
        Repository::open(fixture.path())
            .unwrap()
            .config()
            .unwrap()
            .set_str(name, value)
            .unwrap();
        let tools = structured_tools(&fixture);

        let error = tools
            .status(AuthorizedGitStatus {
                task_id: task(),
                worktree: worktree(),
                root_identity: root("worktree-root"),
            })
            .unwrap_err();

        assert_eq!(
            error.safe_classification(),
            local_agent_terminal_application::SafeErrorClassification::PermissionDenied,
            "{name}"
        );
        assert!(!error.to_string().contains(value));
    }
}

#[test]
fn gitlink_lfs_response_nested_repository_and_symlink_modes_fail_closed() {
    for hazard in [
        ContentHazard::Gitlink,
        ContentHazard::LfsPointer,
        ContentHazard::ResponseFilename,
        ContentHazard::NestedRepository,
        ContentHazard::SymlinkMode,
    ] {
        let fixture = initialized_repository("one\n");
        let repository = Repository::open(fixture.path()).unwrap();
        match hazard {
            ContentHazard::Gitlink => commit_special_mode(&repository, "vendor", 0o160000),
            ContentHazard::LfsPointer => {
                fs::write(
                    fixture.path().join("asset.bin"),
                    b"version https://git-lfs.github.com/spec/v1\noid sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\nsize 1\n",
                )
                .unwrap();
                commit_all(&repository, "lfs pointer");
            }
            ContentHazard::ResponseFilename => {
                fs::write(fixture.path().join("@arguments"), b"--execute\n").unwrap();
            }
            ContentHazard::NestedRepository => {
                fs::create_dir(fixture.path().join("nested")).unwrap();
                Repository::init(fixture.path().join("nested")).unwrap();
            }
            ContentHazard::SymlinkMode => {
                commit_special_mode(&repository, "link", 0o120000);
            }
        }
        let tools = structured_tools(&fixture);

        let error = tools
            .status(AuthorizedGitStatus {
                task_id: task(),
                worktree: worktree(),
                root_identity: root("worktree-root"),
            })
            .unwrap_err();

        assert_eq!(
            error.safe_classification(),
            local_agent_terminal_application::SafeErrorClassification::PermissionDenied,
            "{hazard:?}"
        );
    }
}

#[cfg(feature = "test-seams")]
#[test]
fn mutation_after_initial_capture_is_stopped_at_the_work_bound_before_generation() {
    let fixture = initialized_repository("one\n");
    let repository_path = fixture.path().to_owned();
    let tools = structured_tools(&fixture).with_before_generation_hook_for_test(move || {
        for index in 0..4_097 {
            fs::write(repository_path.join(format!("flood-{index:04}.txt")), b"x").unwrap();
        }
    });

    let error = tools
        .status(AuthorizedGitStatus {
            task_id: task(),
            worktree: worktree(),
            root_identity: root("worktree-root"),
        })
        .unwrap_err();

    assert_eq!(
        error.safe_classification(),
        local_agent_terminal_application::SafeErrorClassification::PermissionDenied
    );
}

#[test]
fn configuration_enumeration_allows_the_boundary_and_denies_one_over() {
    // Repository::init creates six local core entries on Windows.
    for (entry_count, should_allow) in [(250usize, true), (251, false)] {
        let fixture = initialized_repository("one\n");
        let repository = Repository::open(fixture.path()).unwrap();
        let mut config = repository.config().unwrap();
        for index in 0..entry_count {
            config
                .set_str(&format!("safe.bound{index:03}"), "inert")
                .unwrap();
        }
        let tools = structured_tools(&fixture);
        let result = tools.status(AuthorizedGitStatus {
            task_id: task(),
            worktree: worktree(),
            root_identity: root("worktree-root"),
        });

        if should_allow {
            assert!(result.is_ok(), "boundary must remain usable");
        } else {
            let error = result.unwrap_err();
            assert_eq!(
                error.safe_classification(),
                local_agent_terminal_application::SafeErrorClassification::PermissionDenied
            );
        }
    }
}

#[test]
fn attributes_at_nested_info_and_committed_scopes_fail_closed() {
    for scope in [
        AttributeScope::NestedWorktree,
        AttributeScope::Info,
        AttributeScope::Committed,
    ] {
        let fixture = initialized_repository("one\n");
        let repository = Repository::open(fixture.path()).unwrap();
        match scope {
            AttributeScope::NestedWorktree => {
                fs::create_dir(fixture.path().join("nested")).unwrap();
                fs::write(
                    fixture.path().join("nested/.gitattributes"),
                    b"*.txt diff=hostile\n",
                )
                .unwrap();
            }
            AttributeScope::Info => {
                fs::write(
                    repository.path().join("info/attributes"),
                    b"*.txt diff=hostile\n",
                )
                .unwrap();
            }
            AttributeScope::Committed => {
                fs::create_dir(fixture.path().join("nested")).unwrap();
                fs::write(
                    fixture.path().join("nested/.gitattributes"),
                    b"*.txt -diff\n",
                )
                .unwrap();
                commit_all(&repository, "attributes");
            }
        }
        let tools = structured_tools(&fixture);

        let error = tools
            .status(AuthorizedGitStatus {
                task_id: task(),
                worktree: worktree(),
                root_identity: root("worktree-root"),
            })
            .unwrap_err();

        assert_eq!(
            error.safe_classification(),
            local_agent_terminal_application::SafeErrorClassification::PermissionDenied,
            "{scope:?}"
        );
    }
}

#[test]
fn repository_hook_is_rejected_without_executing_the_canary() {
    let fixture = initialized_repository("one\n");
    let marker = fixture.path().join("hook.executed");
    let repository = Repository::open(fixture.path()).unwrap();
    fs::write(
        repository.path().join("hooks/post-checkout"),
        format!("#!/bin/sh\nprintf executed > \"{}\"\n", marker.display()),
    )
    .unwrap();
    let tools = structured_tools(&fixture);

    let error = tools
        .status(AuthorizedGitStatus {
            task_id: task(),
            worktree: worktree(),
            root_identity: root("worktree-root"),
        })
        .unwrap_err();

    assert_eq!(
        error.safe_classification(),
        local_agent_terminal_application::SafeErrorClassification::PermissionDenied
    );
    assert!(!marker.exists());
    assert!(!error.to_string().contains("post-checkout"));
}

#[test]
fn textconv_is_rejected_without_executing_the_canary() {
    let fixture = initialized_repository("one\n");
    let marker = fixture.path().join("textconv.executed");
    let command = fixture.path().join("textconv.cmd");
    fs::write(
        &command,
        format!("@echo off\r\n> \"{}\" echo executed\r\n", marker.display()),
    )
    .unwrap();
    let repository = Repository::open(fixture.path()).unwrap();
    repository
        .config()
        .unwrap()
        .set_str("diff.hostile.textconv", &command.to_string_lossy())
        .unwrap();
    let tools = structured_tools(&fixture);

    let error = tools
        .diff(AuthorizedGitDiff {
            task_id: task(),
            worktree: worktree(),
            root_identity: root("worktree-root"),
        })
        .unwrap_err();

    assert_eq!(
        error.safe_classification(),
        local_agent_terminal_application::SafeErrorClassification::PermissionDenied
    );
    assert!(!marker.exists());
    assert!(!error.to_string().contains("textconv"));
}

#[cfg(feature = "test-seams")]
#[test]
fn coherent_snapshot_fails_closed_for_head_index_or_worktree_mutation() {
    for mutation in [
        SnapshotMutation::Head,
        SnapshotMutation::Index,
        SnapshotMutation::Worktree,
    ] {
        let fixture = initialized_repository("one\n");
        let managed = TempDir::new().unwrap();
        let gateway = GitRepositoryGateway::open(managed.path(), &[]).unwrap();
        let locator = gateway.locate(fixture.path()).unwrap();
        let head = GitObjectId::new(first_locator_head(fixture.path()).to_string()).unwrap();
        let repository_path = fixture.path().to_owned();
        let tools = GitStructuredTools::new(vec![GitWorktreeRegistration::new(
            root("worktree-root"),
            task(),
            locator,
            head,
        )
        .unwrap()])
        .unwrap()
        .with_snapshot_hook_for_test(move || mutate_repository(&repository_path, mutation));

        let error = tools
            .status(AuthorizedGitStatus {
                task_id: task(),
                worktree: worktree(),
                root_identity: root("worktree-root"),
            })
            .unwrap_err();

        assert_eq!(
            error.safe_classification(),
            local_agent_terminal_application::SafeErrorClassification::PermissionDenied,
            "{mutation:?}"
        );
    }
}

#[test]
fn registered_root_task_and_locator_binding_cannot_be_cross_paired() {
    let first = initialized_repository("first");
    let second = initialized_repository("second");
    let managed = TempDir::new().unwrap();
    let gateway = GitRepositoryGateway::open(managed.path(), &[]).unwrap();
    let first_locator = gateway.locate(first.path()).unwrap();
    let second_locator = gateway.locate(second.path()).unwrap();
    let first_head = GitObjectId::new(first_locator_head(first.path()).to_string()).unwrap();
    let second_head = GitObjectId::new(first_locator_head(second.path()).to_string()).unwrap();
    let tools = GitStructuredTools::new(vec![
        GitWorktreeRegistration::new(root("first-root"), task(), first_locator, first_head)
            .unwrap(),
        GitWorktreeRegistration::new(
            root("second-root"),
            TaskId::new("task-2").unwrap(),
            second_locator,
            second_head,
        )
        .unwrap(),
    ])
    .unwrap();

    let error = tools
        .status(AuthorizedGitStatus {
            task_id: task(),
            worktree: worktree(),
            root_identity: root("second-root"),
        })
        .unwrap_err();

    assert_eq!(
        error.safe_classification(),
        local_agent_terminal_application::SafeErrorClassification::PermissionDenied
    );
}

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
    repository
        .config()
        .unwrap()
        .set_str("diff.external", "must-not-run")
        .unwrap();

    let managed = fixture.path().join("managed");
    fs::create_dir(&managed).unwrap();
    let gateway = GitRepositoryGateway::open(&managed, &[]).unwrap();
    let tools = GitStructuredTools::new(vec![GitWorktreeRegistration::new(
        root("worktree-root"),
        task(),
        gateway.locate(fixture.path()).unwrap(),
        GitObjectId::new(commit.to_string()).unwrap(),
    )
    .unwrap()])
    .unwrap();
    for result in [
        tools
            .status(AuthorizedGitStatus {
                task_id: task(),
                worktree: worktree(),
                root_identity: root("worktree-root"),
            })
            .map(|_| ()),
        tools
            .diff(AuthorizedGitDiff {
                task_id: task(),
                worktree: worktree(),
                root_identity: root("worktree-root"),
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
fn status_binds_the_repository_revision_and_scope() {
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
    let tools = GitStructuredTools::new(vec![GitWorktreeRegistration::new(
        root("worktree-root"),
        task(),
        locator.clone(),
        GitObjectId::new(commit.to_string()).unwrap(),
    )
    .unwrap()])
    .unwrap();

    let result = tools
        .status(AuthorizedGitStatus {
            task_id: task(),
            worktree: worktree(),
            root_identity: root("worktree-root"),
        })
        .unwrap();

    assert_eq!(result.repository_id, locator.repository_id);
    assert_eq!(result.revision.as_str(), commit.to_string());
    assert_eq!(result.path_scope, worktree());
    assert!(!result.truncated);
    assert_eq!(result.bytes, b"README.md\t00000100\n");
    assert_eq!(
        result.digest.as_str(),
        "sha256:e2f9ec8c06901a9da28ff78fb6f4b5f5160e0f9addb8e92d5d337b4f9e65e23e"
    );
}

fn task() -> TaskId {
    TaskId::new("task-1").unwrap()
}
fn worktree() -> CapabilityRef {
    CapabilityRef::worktree(task(), ".").unwrap()
}

fn root(value: &str) -> CapabilityRootIdentity {
    CapabilityRootIdentity::new(value).unwrap()
}

fn initialized_repository(contents: &str) -> TempDir {
    let fixture = TempDir::new().unwrap();
    let repository = Repository::init(fixture.path()).unwrap();
    fs::write(fixture.path().join("README.md"), contents).unwrap();
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
    drop(repository);
    fixture
}

fn commit_all(repository: &Repository, message: &str) -> git2::Oid {
    let mut index = repository.index().unwrap();
    index
        .add_all(["*"].iter(), git2::IndexAddOption::DEFAULT, None)
        .unwrap();
    index.write().unwrap();
    let tree_id = index.write_tree().unwrap();
    let tree = repository.find_tree(tree_id).unwrap();
    let parent = repository.head().unwrap().peel_to_commit().unwrap();
    let signature = Signature::now("test", "test@example.com").unwrap();
    repository
        .commit(
            Some("HEAD"),
            &signature,
            &signature,
            message,
            &tree,
            &[&parent],
        )
        .unwrap()
}

fn commit_special_mode(repository: &Repository, path: &str, mode: i32) {
    let parent = repository.head().unwrap().peel_to_commit().unwrap();
    let parent_tree = parent.tree().unwrap();
    let mut builder = repository.treebuilder(Some(&parent_tree)).unwrap();
    let oid = if mode == 0o160000 {
        parent.id()
    } else {
        repository.blob(b"target").unwrap()
    };
    builder.insert(path, oid, mode).unwrap();
    let tree_id = builder.write().unwrap();
    let tree = repository.find_tree(tree_id).unwrap();
    let signature = Signature::now("test", "test@example.com").unwrap();
    repository
        .commit(
            Some("HEAD"),
            &signature,
            &signature,
            "special mode",
            &tree,
            &[&parent],
        )
        .unwrap();
}

fn first_locator_head(path: &std::path::Path) -> git2::Oid {
    Repository::open(path)
        .unwrap()
        .head()
        .unwrap()
        .target()
        .unwrap()
}

fn structured_tools(fixture: &TempDir) -> GitStructuredTools {
    let managed = TempDir::new().unwrap();
    let gateway = GitRepositoryGateway::open(managed.path(), &[]).unwrap();
    let locator = gateway.locate(fixture.path()).unwrap();
    let head = GitObjectId::new(first_locator_head(fixture.path()).to_string()).unwrap();
    GitStructuredTools::new(vec![GitWorktreeRegistration::new(
        root("worktree-root"),
        task(),
        locator,
        head,
    )
    .unwrap()])
    .unwrap()
}

#[cfg(feature = "test-seams")]
#[derive(Clone, Copy, Debug)]
enum SnapshotMutation {
    Head,
    Index,
    Worktree,
}

#[derive(Clone, Copy, Debug)]
enum AttributeScope {
    NestedWorktree,
    Info,
    Committed,
}

#[derive(Clone, Copy, Debug)]
enum ContentHazard {
    Gitlink,
    LfsPointer,
    ResponseFilename,
    NestedRepository,
    SymlinkMode,
}

#[cfg(feature = "test-seams")]
fn mutate_repository(path: &std::path::Path, mutation: SnapshotMutation) {
    let repository = Repository::open(path).unwrap();
    match mutation {
        SnapshotMutation::Head => {
            let head = repository.head().unwrap().peel_to_commit().unwrap();
            let tree = head.tree().unwrap();
            let signature = Signature::now("test", "test@example.com").unwrap();
            repository
                .commit(
                    Some("HEAD"),
                    &signature,
                    &signature,
                    "concurrent",
                    &tree,
                    &[&head],
                )
                .unwrap();
        }
        SnapshotMutation::Index => {
            fs::write(path.join("INDEXED.md"), b"indexed\n").unwrap();
            let mut index = repository.index().unwrap();
            index.add_path(std::path::Path::new("INDEXED.md")).unwrap();
            index.write().unwrap();
        }
        SnapshotMutation::Worktree => fs::write(path.join("README.md"), b"concurrent\n").unwrap(),
    }
}
