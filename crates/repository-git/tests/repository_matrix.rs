use std::fs;
use std::path::{Path, PathBuf};

use git2::{
    IndexAddOption, ObjectFormat as GitObjectFormat, Repository, RepositoryInitOptions, Signature,
};
use local_agent_terminal_application::{
    CreateWorktree, ExpectedPresence, InspectRepository, ManagedWorktreePath, ObjectFormat,
    RepositoryGateway, RepositoryHealth, WorktreeState,
};
use local_agent_terminal_domain::{
    FencingToken, GitObjectId, LeaseClaim, RunId, TaskBranch, TaskId, WorkspaceVersion, WorktreeId,
};
use local_agent_terminal_repository_git::GitRepositoryGateway;
use tempfile::TempDir;

fn commit_repository(root: &Path) -> (Repository, String) {
    commit_repository_with_format(root, GitObjectFormat::Sha1)
}

fn commit_repository_with_format(
    root: &Path,
    object_format: GitObjectFormat,
) -> (Repository, String) {
    let mut options = RepositoryInitOptions::new();
    options.object_format(object_format);
    let repository = Repository::init_opts(root, &options).expect("init");
    let file = root.join("README.md");
    fs::write(&file, b"original\n").expect("write");
    let mut index = repository.index().expect("index");
    index
        .add_all(["README.md"], IndexAddOption::DEFAULT, None)
        .expect("add");
    let tree_id = index.write_tree().expect("tree");
    index.write().expect("write index");
    let signature = Signature::now("fixture", "fixture@example.invalid").expect("signature");
    let tree = repository.find_tree(tree_id).expect("find tree");
    let commit = repository
        .commit(Some("HEAD"), &signature, &signature, "initial", &tree, &[])
        .expect("commit");
    drop(tree);
    (repository, commit.to_string())
}

fn locator(
    gateway: &GitRepositoryGateway,
    path: &Path,
) -> local_agent_terminal_application::RepositoryLocator {
    gateway.locate(path).expect("locator")
}

fn request(
    gateway: &GitRepositoryGateway,
    repository: &local_agent_terminal_application::RepositoryLocator,
    root: &Path,
) -> CreateWorktree {
    let worktree_id = WorktreeId::new("wt-task-1").expect("worktree id");
    CreateWorktree {
        repository: repository.clone(),
        managed_path: ManagedWorktreePath {
            trusted_root_id: gateway.trusted_root_id().to_owned(),
            relative_leaf: PathBuf::from("task-1"),
            redacted_display: "task-1".to_owned(),
        },
        task_id: TaskId::new("task-1").expect("task"),
        lease_claim: LeaseClaim::new(
            TaskId::new("task-1").expect("task"),
            RunId::new("run-1").expect("run"),
            FencingToken::new(1).expect("token"),
        ),
        expected_workspace_version: WorkspaceVersion::new(0),
        worktree_id,
        branch: TaskBranch::new("agent/task-1").expect("branch"),
        base_commit: GitObjectId::new(repository_base(repository, root)).expect("base"),
    }
}

fn repository_base(
    _repository: &local_agent_terminal_application::RepositoryLocator,
    root: &Path,
) -> String {
    let opened = Repository::open(root).expect("open");
    let oid = opened.head().expect("head").target().expect("target");
    oid.to_string()
}

#[test]
fn inspect_reports_clean_repository_without_exposing_handles() {
    let fixture = TempDir::new().expect("tempdir");
    let source = fixture.path().join("source");
    fs::create_dir(&source).expect("source");
    let (_repository, _commit) = commit_repository(&source);
    let managed_root = fixture.path().join("managed");
    fs::create_dir(&managed_root).expect("managed");
    let gateway = GitRepositoryGateway::open(&managed_root, &[]).expect("gateway");
    let repository = locator(&gateway, &source);

    let snapshot = gateway
        .inspect(InspectRepository {
            locator: repository,
        })
        .expect("inspect");

    assert_eq!(snapshot.health, RepositoryHealth::Healthy);
    assert_eq!(
        snapshot.original_checkout,
        local_agent_terminal_application::OriginalCheckoutState::Clean
    );
}

#[test]
fn persisted_canonical_repository_path_can_be_reopened() {
    let fixture = TempDir::new().expect("tempdir");
    let source = fixture.path().join("source");
    fs::create_dir(&source).expect("source");
    let (_repository, _commit) = commit_repository(&source);
    let managed_root = fixture.path().join("managed");
    fs::create_dir(&managed_root).expect("managed");
    let gateway = GitRepositoryGateway::open(&managed_root, &[]).expect("gateway");
    let located = locator(&gateway, &source);

    let reopened = gateway
        .locate_persisted(&located.canonical_workdir)
        .expect("persisted locator");

    assert_eq!(reopened, located);
    #[cfg(windows)]
    assert!(gateway.locate(&located.canonical_workdir).is_err());
}

#[test]
fn worktree_creation_preserves_original_and_disables_checkout_filters() {
    let fixture = TempDir::new().expect("tempdir");
    let source = fixture.path().join("source");
    fs::create_dir(&source).expect("source");
    let (_repository, _commit) = commit_repository(&source);
    let managed_root = fixture.path().join("managed");
    fs::create_dir(&managed_root).expect("managed");
    let gateway = GitRepositoryGateway::open(&managed_root, &[]).expect("gateway");
    let repository = locator(&gateway, &source);
    let source_before = fs::read(source.join("README.md")).expect("before");

    let created = gateway
        .create_worktree(request(&gateway, &repository, &source))
        .expect("create");

    assert_eq!(created.state, WorktreeState::Present);
    assert_eq!(created.expected_presence, ExpectedPresence::Present);
    assert_eq!(
        fs::read(source.join("README.md")).expect("after"),
        source_before
    );
    assert!(managed_root.join("task-1").join("README.md").is_file());
}

#[test]
fn worktree_creation_rejects_a_dirty_original_checkout() {
    let fixture = TempDir::new().expect("tempdir");
    let source = fixture.path().join("source");
    fs::create_dir(&source).expect("source");
    let (repository, _commit) = commit_repository(&source);
    let managed_root = fixture.path().join("managed");
    fs::create_dir(&managed_root).expect("managed");
    let gateway = GitRepositoryGateway::open(&managed_root, &[]).expect("gateway");
    let locator = locator(&gateway, &source);
    fs::write(source.join("README.md"), b"dirty\n").expect("dirty source");

    gateway
        .create_worktree(request(&gateway, &locator, &source))
        .expect_err("dirty original checkout must not create a worktree");

    assert!(!managed_root.join("task-1").exists());
    assert!(repository
        .find_reference("refs/heads/agent/task-1")
        .is_err());
}

#[test]
fn unsafe_filter_configuration_is_rejected_before_checkout() {
    let fixture = TempDir::new().expect("tempdir");
    let source = fixture.path().join("source");
    fs::create_dir(&source).expect("source");
    let (repository, _commit) = commit_repository(&source);
    let sentinel = fixture.path().join("SHOULD_NOT_RUN");
    let mut config = repository.config().expect("config");
    config
        .set_str(
            "filter.sentinel.process",
            &format!("cmd /C echo touched > {}", sentinel.to_string_lossy()),
        )
        .expect("config");
    let managed_root = fixture.path().join("managed");
    fs::create_dir(&managed_root).expect("managed");
    let gateway = GitRepositoryGateway::open(&managed_root, &[]).expect("gateway");
    let repository = locator(&gateway, &source);

    let result = gateway.inspect(InspectRepository {
        locator: repository,
    });

    let snapshot = result.expect("inspection");
    assert_eq!(snapshot.health, RepositoryHealth::Unsafe);
    assert!(snapshot.hazards.iter().any(|hazard| hazard.reason
        == local_agent_terminal_application::RepositoryHazardReason::FiltersConfigured));
    let locator = locator(&gateway, &source);
    assert!(gateway
        .create_worktree(request(&gateway, &locator, &source))
        .is_err());
    assert!(!sentinel.exists());
}

#[test]
fn sha256_repository_keeps_exact_object_ids() {
    let fixture = TempDir::new().expect("tempdir");
    let source = fixture.path().join("source");
    fs::create_dir(&source).expect("source");
    let (_repository, commit) = commit_repository_with_format(&source, GitObjectFormat::Sha256);
    assert_eq!(commit.len(), 64);
    let managed_root = fixture.path().join("managed");
    fs::create_dir(&managed_root).expect("managed");
    let gateway = GitRepositoryGateway::open(&managed_root, &[]).expect("gateway");
    let locator = locator(&gateway, &source);
    assert_eq!(locator.object_format, ObjectFormat::Sha256);
    let snapshot = gateway
        .inspect(InspectRepository {
            locator: locator.clone(),
        })
        .expect("inspect");
    assert_eq!(snapshot.base_commit.expect("base").as_str().len(), 64);
    let created = gateway
        .create_worktree(request(&gateway, &locator, &source))
        .expect("create");
    assert_eq!(created.base_commit.as_str().len(), 64);
}

#[test]
fn branch_conflict_is_preserved_without_creating_target() {
    let fixture = TempDir::new().expect("tempdir");
    let source = fixture.path().join("source");
    fs::create_dir(&source).expect("source");
    let (repository, commit) = commit_repository(&source);
    let branch = repository
        .branch(
            "agent/task-1",
            &repository
                .head()
                .expect("head")
                .peel_to_commit()
                .expect("commit"),
            false,
        )
        .expect("branch");
    let branch_target = branch.get().target().expect("target").to_string();
    let managed_root = fixture.path().join("managed");
    fs::create_dir(&managed_root).expect("managed");
    let gateway = GitRepositoryGateway::open(&managed_root, &[]).expect("gateway");
    let locator = locator(&gateway, &source);
    let result = gateway.create_worktree(request(&gateway, &locator, &source));
    assert!(matches!(
        result,
        Err(local_agent_terminal_application::PortError::Failure {
            classification: local_agent_terminal_application::SafeErrorClassification::Conflict,
            ..
        })
    ));
    assert_eq!(
        repository
            .find_reference("refs/heads/agent/task-1")
            .expect("branch")
            .target()
            .expect("target")
            .to_string(),
        branch_target
    );
    assert!(!managed_root.join("task-1").exists());
    assert_eq!(commit.len(), 40);
}

#[test]
fn exact_worktree_can_be_listed_and_discarded() {
    let fixture = TempDir::new().expect("tempdir");
    let source = fixture.path().join("source");
    fs::create_dir(&source).expect("source");
    let (_repository, _commit) = commit_repository(&source);
    let managed_root = fixture.path().join("managed");
    fs::create_dir(&managed_root).expect("managed");
    let gateway = GitRepositoryGateway::open(&managed_root, &[]).expect("gateway");
    let locator = locator(&gateway, &source);
    let create = request(&gateway, &locator, &source);
    let created = gateway.create_worktree(create.clone()).expect("create");
    let listed = gateway.list_worktrees(&locator).expect("list");
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].worktree_id, created.worktree_id);
    let discard = local_agent_terminal_application::DiscardWorktree {
        repository: locator,
        managed_path: create.managed_path,
        task_id: create.task_id,
        lease_claim: create.lease_claim,
        expected_workspace_version: create.expected_workspace_version,
        worktree_id: create.worktree_id,
        branch: create.branch,
        base_commit: create.base_commit,
    };
    gateway.discard_worktree(discard).expect("discard");
    assert!(!managed_root.join("task-1").exists());
}

#[test]
fn checkout_disables_crlf_filters_and_preserves_blob_bytes() {
    let fixture = TempDir::new().expect("tempdir");
    let source = fixture.path().join("source");
    fs::create_dir(&source).expect("source");
    let (repository, _commit) = commit_repository(&source);
    fs::write(source.join(".gitattributes"), b"*.txt text eol=crlf\n").expect("attributes");
    fs::write(source.join("line.txt"), b"one\ntwo\n").expect("line");
    let mut index = repository.index().expect("index");
    index
        .add_all(
            [".gitattributes", "line.txt"],
            IndexAddOption::DEFAULT,
            None,
        )
        .expect("add");
    let tree_id = index.write_tree().expect("tree");
    index.write().expect("write index");
    let tree = repository.find_tree(tree_id).expect("tree");
    let signature = Signature::now("fixture", "fixture@example.invalid").expect("signature");
    repository
        .commit(
            Some("HEAD"),
            &signature,
            &signature,
            "attributes",
            &tree,
            &[&repository
                .head()
                .expect("head")
                .peel_to_commit()
                .expect("parent")],
        )
        .expect("commit");
    drop(tree);
    let managed_root = fixture.path().join("managed");
    fs::create_dir(&managed_root).expect("managed");
    let gateway = GitRepositoryGateway::open(&managed_root, &[]).expect("gateway");
    let locator = locator(&gateway, &source);
    let created = gateway
        .create_worktree(request(&gateway, &locator, &source))
        .expect("create");
    assert_eq!(
        fs::read(managed_root.join("task-1").join("line.txt")).expect("target"),
        b"one\ntwo\n"
    );
    assert!(Repository::open(managed_root.join("task-1"))
        .expect("target repository")
        .statuses(None)
        .expect("target status")
        .is_empty());
    assert_eq!(created.state, WorktreeState::Present);
}

#[test]
fn dirty_detached_and_unborn_states_are_explicit() {
    let fixture = TempDir::new().expect("tempdir");
    let managed_root = fixture.path().join("managed");
    fs::create_dir(&managed_root).expect("managed");
    let gateway = GitRepositoryGateway::open(&managed_root, &[]).expect("gateway");

    let dirty_source = fixture.path().join("dirty");
    fs::create_dir(&dirty_source).expect("dirty");
    let (_dirty_repository, _commit) = commit_repository(&dirty_source);
    fs::write(dirty_source.join("README.md"), b"changed\n").expect("dirty write");
    let dirty = gateway
        .inspect(InspectRepository {
            locator: locator(&gateway, &dirty_source),
        })
        .expect("dirty inspect");
    assert_eq!(dirty.health, RepositoryHealth::Dirty);
    assert_eq!(
        dirty.original_checkout,
        local_agent_terminal_application::OriginalCheckoutState::Dirty
    );

    let detached_source = fixture.path().join("detached");
    fs::create_dir(&detached_source).expect("detached");
    let (detached_repository, commit) = commit_repository(&detached_source);
    detached_repository
        .set_head_detached(git2::Oid::from_str(&commit).expect("oid"))
        .expect("detach");
    let detached = gateway
        .inspect(InspectRepository {
            locator: locator(&gateway, &detached_source),
        })
        .expect("detached inspect");
    assert_eq!(
        detached.original_checkout,
        local_agent_terminal_application::OriginalCheckoutState::Detached
    );

    let unborn_source = fixture.path().join("unborn");
    fs::create_dir(&unborn_source).expect("unborn");
    let _unborn_repository = Repository::init(&unborn_source).expect("init unborn");
    let unborn = gateway
        .inspect(InspectRepository {
            locator: locator(&gateway, &unborn_source),
        })
        .expect("unborn inspect");
    assert_eq!(
        unborn.original_checkout,
        local_agent_terminal_application::OriginalCheckoutState::Unborn
    );
}

#[test]
fn repository_hazards_are_classified_before_worktree_side_effects() {
    let fixture = TempDir::new().expect("tempdir");
    let source = fixture.path().join("source");
    fs::create_dir(&source).expect("source");
    let (repository, _commit) = commit_repository(&source);
    let mut config = repository.config().expect("config");
    config
        .set_str("core.hooksPath", "untrusted-hooks")
        .expect("hooks");
    config
        .set_str("credential.helper", "sentinel-helper")
        .expect("credential");
    config
        .set_str("remote.origin.url", "ext::sentinel")
        .expect("remote");
    fs::write(source.join(".gitmodules"), b"[submodule \"child\"]\n").expect("modules");
    fs::write(source.join(".lfsconfig"), b"[lfs]\nurl = https://invalid\n").expect("lfs");
    let managed_root = fixture.path().join("managed");
    fs::create_dir(&managed_root).expect("managed");
    let gateway = GitRepositoryGateway::open(&managed_root, &[]).expect("gateway");
    let locator = locator(&gateway, &source);
    let snapshot = gateway
        .inspect(InspectRepository {
            locator: locator.clone(),
        })
        .expect("inspect");
    assert_eq!(snapshot.health, RepositoryHealth::Unsafe);
    assert!(snapshot.hazards.iter().any(|hazard| {
        hazard.reason == local_agent_terminal_application::RepositoryHazardReason::HooksConfigured
    }));
    assert!(snapshot.hazards.iter().any(|hazard| {
        hazard.reason == local_agent_terminal_application::RepositoryHazardReason::SubmodulesPresent
    }));
    assert!(snapshot.hazards.iter().any(|hazard| {
        hazard.reason == local_agent_terminal_application::RepositoryHazardReason::LfsConfigured
    }));
    let result = gateway.create_worktree(request(&gateway, &locator, &source));
    assert!(result.is_err());
    assert!(!managed_root.join("task-1").exists());
}

#[test]
fn target_inside_original_checkout_and_case_collisions_fail_closed() {
    let fixture = TempDir::new().expect("tempdir");
    let source = fixture.path().join("source");
    fs::create_dir(&source).expect("source");
    let (_repository, _commit) = commit_repository(&source);
    let nested_root = source.join("managed");
    fs::create_dir(&nested_root).expect("nested root");
    let nested_gateway = GitRepositoryGateway::open(&nested_root, &[]).expect("nested gateway");
    let nested_locator = locator(&nested_gateway, &source);
    assert!(nested_gateway
        .create_worktree(request(&nested_gateway, &nested_locator, &source,))
        .is_err());

    let managed_root = fixture.path().join("outside");
    fs::create_dir(&managed_root).expect("outside");
    fs::create_dir(managed_root.join("Task-1")).expect("case sibling");
    let gateway = GitRepositoryGateway::open(&managed_root, &[]).expect("gateway");
    let locator = locator(&gateway, &source);
    assert!(gateway
        .create_worktree(request(&gateway, &locator, &source))
        .is_err());
    assert!(!source
        .join(".git")
        .join("refs")
        .join("heads")
        .join("agent")
        .join("task-1")
        .exists());
}
