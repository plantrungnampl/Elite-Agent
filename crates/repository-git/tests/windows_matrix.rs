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

fn commit_all(repository: &Repository, message: &str) -> String {
    let mut index = repository.index().expect("index");
    index
        .add_all(["*"], IndexAddOption::DEFAULT, None)
        .expect("add all");
    let tree_id = index.write_tree().expect("tree");
    index.write().expect("write index");
    let tree = repository.find_tree(tree_id).expect("find tree");
    let parent = repository
        .head()
        .expect("head")
        .peel_to_commit()
        .expect("parent");
    let signature = Signature::now("fixture", "fixture@example.invalid").expect("signature");
    repository
        .commit(
            Some("HEAD"),
            &signature,
            &signature,
            message,
            &tree,
            &[&parent],
        )
        .expect("commit")
        .to_string()
}

#[cfg(feature = "test-seams")]
fn dangling_commit(repository: &Repository, message: &str) -> git2::Oid {
    let tree = repository
        .head()
        .expect("head")
        .peel_to_tree()
        .expect("tree");
    let parent = repository
        .head()
        .expect("head")
        .peel_to_commit()
        .expect("parent");
    let signature = Signature::now("fixture", "fixture@example.invalid").expect("signature");
    repository
        .commit(None, &signature, &signature, message, &tree, &[&parent])
        .expect("dangling commit")
}

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
    request_at(gateway, repository, root, PathBuf::from("task-1"))
}

fn request_at(
    gateway: &GitRepositoryGateway,
    repository: &local_agent_terminal_application::RepositoryLocator,
    root: &Path,
    relative_leaf: PathBuf,
) -> CreateWorktree {
    let worktree_id = WorktreeId::new("wt-task-1").expect("worktree id");
    CreateWorktree {
        repository: repository.clone(),
        managed_path: ManagedWorktreePath {
            trusted_root_id: gateway.trusted_root_id().to_owned(),
            redacted_display: relative_leaf.to_string_lossy().into_owned(),
            relative_leaf,
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

fn libgit2_directory(path: &Path) -> String {
    let mut path = fs::canonicalize(path)
        .expect("canonical path")
        .to_string_lossy()
        .replace('\\', "/");
    if let Some(without_prefix) = path.strip_prefix("//?/") {
        path = without_prefix.to_owned();
    }
    if !path.ends_with('/') {
        path.push('/');
    }
    path
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
    let target = managed_root.join("task-1");
    assert!(target.join("README.md").is_file());
    let metadata = source.join(".git").join("worktrees").join("wt-task-1");
    assert_eq!(
        fs::read_to_string(target.join(".git")).expect("worktree gitfile"),
        format!("gitdir: {}\n", libgit2_directory(&metadata))
    );
    assert_eq!(
        fs::read_to_string(metadata.join("commondir")).expect("commondir"),
        format!("{}\n", libgit2_directory(&source.join(".git")))
    );
    assert_eq!(
        fs::read_to_string(metadata.join("gitdir")).expect("gitdir"),
        format!("{}.git\n", libgit2_directory(&target))
    );
    assert_eq!(
        fs::read_to_string(metadata.join("HEAD")).expect("worktree HEAD"),
        "ref: refs/heads/agent/task-1\n"
    );
    assert_eq!(
        fs::read(metadata.join("locked")).expect("worktree lock"),
        b""
    );
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
    let (repository, commit) = commit_repository_with_format(&source, GitObjectFormat::Sha256);
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
    assert_eq!(snapshot.base_commit.expect("base").as_str(), commit);
    let create = request(&gateway, &locator, &source);
    assert_eq!(create.base_commit.as_str(), commit);
    let created = gateway.create_worktree(create).expect("create");
    assert_eq!(created.base_commit.as_str(), commit);
    assert_eq!(
        repository
            .find_reference("refs/heads/agent/task-1")
            .expect("branch")
            .target()
            .expect("branch target")
            .to_string(),
        commit
    );
    assert_eq!(
        Repository::open(managed_root.join("task-1"))
            .expect("worktree repository")
            .head()
            .expect("worktree head")
            .target()
            .expect("worktree target")
            .to_string(),
        commit
    );
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

#[cfg(all(windows, feature = "test-seams"))]
#[test]
fn discard_preserves_a_target_replaced_after_validation() {
    use std::sync::{Arc, Barrier};

    use local_agent_terminal_application::{DiscardWorktree, PortError, SafeErrorClassification};
    use local_agent_terminal_repository_git::TestHooks;

    let fixture = TempDir::new().expect("tempdir");
    let source = fixture.path().join("source");
    fs::create_dir(&source).expect("source");
    let (repository, commit) = commit_repository(&source);
    let managed_root = fixture.path().join("managed");
    fs::create_dir(&managed_root).expect("managed");
    let mut gateway = GitRepositoryGateway::open(&managed_root, &[]).expect("gateway");
    let locator = locator(&gateway, &source);
    let create = request(&gateway, &locator, &source);
    gateway
        .create_worktree(create.clone())
        .expect("create worktree");

    let barrier = Arc::new(Barrier::new(2));
    gateway.set_test_hooks(TestHooks {
        after_discard_validation: Some(barrier.clone()),
        ..TestHooks::default()
    });
    let discard = DiscardWorktree {
        repository: locator,
        managed_path: create.managed_path,
        task_id: create.task_id,
        lease_claim: create.lease_claim,
        expected_workspace_version: create.expected_workspace_version,
        worktree_id: create.worktree_id,
        branch: create.branch,
        base_commit: create.base_commit,
    };
    let worker = std::thread::spawn(move || gateway.discard_worktree(discard));

    barrier.wait();
    let target = managed_root.join("task-1");
    let displaced = managed_root.join("owned-target-displaced");
    fs::rename(&target, &displaced).expect("displace validated target");
    fs::create_dir(&target).expect("replacement target");
    fs::write(target.join("KEEP.txt"), b"keep").expect("replacement sentinel");
    barrier.wait();

    let result = worker.join().expect("worker");
    assert!(matches!(
        result,
        Err(PortError::Failure {
            classification: SafeErrorClassification::Conflict,
            ..
        })
    ));
    assert_eq!(
        fs::read(target.join("KEEP.txt")).expect("replacement survives"),
        b"keep"
    );
    assert!(displaced.join("README.md").is_file());
    assert_eq!(
        repository
            .find_reference("refs/heads/agent/task-1")
            .expect("branch preserved")
            .target()
            .expect("branch target")
            .to_string(),
        commit
    );
    assert!(repository.find_worktree("wt-task-1").is_ok());
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
    fs::write(source.join(".gitattributes"), b"*.bin filter=lfs\n").expect("attributes");
    commit_all(&repository, "committed hazards");
    fs::remove_file(source.join(".gitmodules")).expect("remove working modules");
    fs::remove_file(source.join(".lfsconfig")).expect("remove working lfs");
    fs::write(source.join(".gitattributes"), b"*.bin -filter\n")
        .expect("replace working attributes");
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
fn hazard_scan_fails_closed_when_head_object_is_missing() {
    let fixture = TempDir::new().expect("tempdir");
    let source = fixture.path().join("source");
    fs::create_dir(&source).expect("source");
    let (repository, _commit) = commit_repository(&source);
    let managed_root = fixture.path().join("managed");
    fs::create_dir(&managed_root).expect("managed");
    let gateway = GitRepositoryGateway::open(&managed_root, &[]).expect("gateway");
    let locator = locator(&gateway, &source);
    let head_name = repository
        .head()
        .expect("head")
        .name()
        .expect("head name")
        .to_owned();
    let head_path = repository.path().join(&head_name);
    fs::create_dir_all(head_path.parent().expect("head parent")).expect("head parent");
    fs::write(head_path, format!("{}\n", "1".repeat(40))).expect("replace head");

    gateway
        .inspect(InspectRepository { locator })
        .expect_err("missing HEAD object must fail closed");
}

#[test]
fn hazard_scan_fails_closed_when_attributes_path_is_not_a_blob() {
    let fixture = TempDir::new().expect("tempdir");
    let source = fixture.path().join("source");
    fs::create_dir(&source).expect("source");
    let (repository, _commit) = commit_repository(&source);
    fs::create_dir(source.join(".gitattributes")).expect("attributes directory");
    fs::write(source.join(".gitattributes").join("nested"), b"inert\n").expect("nested");
    commit_all(&repository, "non-blob attributes");
    let managed_root = fixture.path().join("managed");
    fs::create_dir(&managed_root).expect("managed");
    let gateway = GitRepositoryGateway::open(&managed_root, &[]).expect("gateway");

    gateway
        .inspect(InspectRepository {
            locator: locator(&gateway, &source),
        })
        .expect_err("non-blob attributes must fail closed");
}

#[test]
fn hazard_scan_fails_closed_when_attributes_blob_is_missing() {
    let fixture = TempDir::new().expect("tempdir");
    let source = fixture.path().join("source");
    fs::create_dir(&source).expect("source");
    let (repository, _commit) = commit_repository(&source);
    fs::write(source.join(".gitattributes"), b"*.bin -filter\n").expect("attributes");
    commit_all(&repository, "missing attributes blob");
    let tree = repository
        .head()
        .expect("head")
        .peel_to_tree()
        .expect("tree");
    let blob = tree
        .get_path(Path::new(".gitattributes"))
        .expect("attributes entry")
        .id()
        .to_string();
    fs::remove_file(
        repository
            .path()
            .join("objects")
            .join(&blob[..2])
            .join(&blob[2..]),
    )
    .expect("remove attributes blob");
    let managed_root = fixture.path().join("managed");
    fs::create_dir(&managed_root).expect("managed");
    let gateway = GitRepositoryGateway::open(&managed_root, &[]).expect("gateway");

    gateway
        .inspect(InspectRepository {
            locator: locator(&gateway, &source),
        })
        .expect_err("missing attributes blob must fail closed");
}

#[test]
fn hazard_scan_fails_closed_for_non_utf8_attributes() {
    let fixture = TempDir::new().expect("tempdir");
    let source = fixture.path().join("source");
    fs::create_dir(&source).expect("source");
    let (repository, _commit) = commit_repository(&source);
    fs::write(source.join(".gitattributes"), [0xff, b'\n']).expect("attributes");
    commit_all(&repository, "non-UTF-8 attributes");
    let managed_root = fixture.path().join("managed");
    fs::create_dir(&managed_root).expect("managed");
    let gateway = GitRepositoryGateway::open(&managed_root, &[]).expect("gateway");

    gateway
        .inspect(InspectRepository {
            locator: locator(&gateway, &source),
        })
        .expect_err("non-UTF-8 attributes must fail closed");
}

#[test]
fn hazard_scan_fails_closed_for_malformed_attributes() {
    let fixture = TempDir::new().expect("tempdir");
    let source = fixture.path().join("source");
    fs::create_dir(&source).expect("source");
    let (repository, _commit) = commit_repository(&source);
    fs::write(source.join(".gitattributes"), b"*.bin\n").expect("attributes");
    commit_all(&repository, "malformed attributes");
    let managed_root = fixture.path().join("managed");
    fs::create_dir(&managed_root).expect("managed");
    let gateway = GitRepositoryGateway::open(&managed_root, &[]).expect("gateway");

    gateway
        .inspect(InspectRepository {
            locator: locator(&gateway, &source),
        })
        .expect_err("malformed attributes must fail closed");
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

#[test]
fn successful_unicode_worktree_preserves_original_head_index_and_checkout_bytes() {
    let fixture = TempDir::new().expect("tempdir");
    let source = fixture.path().join("source with spaces-資料");
    fs::create_dir(&source).expect("source");
    let (repository, commit) = commit_repository(&source);
    let index_path = repository.path().join("index");
    let index_before = fs::read(&index_path).expect("index before");
    let checkout_before = fs::read(source.join("README.md")).expect("checkout before");
    let managed_root = fixture.path().join("managed workspaces-資料");
    fs::create_dir(&managed_root).expect("managed");
    let gateway = GitRepositoryGateway::open(&managed_root, &[]).expect("gateway");
    let locator = locator(&gateway, &source);
    let leaf = PathBuf::from("task space-資料");

    let created = gateway
        .create_worktree(request_at(&gateway, &locator, &source, leaf.clone()))
        .expect("create");

    assert_eq!(created.base_commit.as_str(), commit);
    assert_eq!(fs::read(index_path).expect("index after"), index_before);
    assert_eq!(
        fs::read(source.join("README.md")).expect("checkout after"),
        checkout_before
    );
    assert_eq!(
        repository
            .head()
            .expect("head")
            .target()
            .expect("target")
            .to_string(),
        commit
    );
    assert!(repository.statuses(None).expect("status").is_empty());
    assert!(managed_root.join(leaf).join("README.md").is_file());
}

#[test]
fn long_path_checkout_fails_closed_without_mutating_original_state() {
    use local_agent_terminal_application::{PortError, SafeErrorClassification};

    let fixture = TempDir::new().expect("tempdir");
    let source = fixture.path().join("source");
    fs::create_dir(&source).expect("source");
    let (repository, commit) = commit_repository(&source);
    let index_before = fs::read(repository.path().join("index")).expect("index before");
    let managed_root = fixture.path().join("managed");
    fs::create_dir(&managed_root).expect("managed");
    let gateway = GitRepositoryGateway::open(&managed_root, &[]).expect("gateway");
    let locator = locator(&gateway, &source);
    let long_leaf = PathBuf::from(format!("task-{}", "x".repeat(230)));

    let result =
        gateway.create_worktree(request_at(&gateway, &locator, &source, long_leaf.clone()));
    assert!(matches!(
        result,
        Err(PortError::Failure {
            classification: SafeErrorClassification::Conflict,
            ..
        })
    ));

    assert_eq!(
        repository
            .head()
            .expect("head")
            .target()
            .expect("target")
            .to_string(),
        commit
    );
    assert_eq!(
        fs::read(repository.path().join("index")).expect("index after"),
        index_before
    );
    assert_eq!(
        repository
            .find_reference("refs/heads/agent/task-1")
            .expect("preserved attempt branch")
            .target()
            .expect("attempt target")
            .to_string(),
        commit
    );
    if managed_root.join(long_leaf).exists() {
        assert!(
            repository.find_worktree("wt-task-1").is_ok(),
            "partial target is preserved only with its worktree metadata"
        );
    }
}

#[test]
fn invalid_windows_target_forms_are_rejected_without_git_side_effects() {
    let fixture = TempDir::new().expect("tempdir");
    let source = fixture.path().join("source");
    fs::create_dir(&source).expect("source");
    let (repository, _commit) = commit_repository(&source);
    let managed_root = fixture.path().join("managed");
    fs::create_dir(&managed_root).expect("managed");
    let gateway = GitRepositoryGateway::open(&managed_root, &[]).expect("gateway");
    let locator = locator(&gateway, &source);

    for leaf in [
        r"..\escape",
        r"\\server\share",
        r"\\?\C:\device",
        r"\\.\PIPE\device",
        "task:ads",
        "CON",
        "trailing.",
        "trailing ",
        "meta*name",
    ] {
        let result =
            gateway.create_worktree(request_at(&gateway, &locator, &source, PathBuf::from(leaf)));
        assert!(result.is_err(), "{leaf}");
    }
    assert!(repository
        .find_reference("refs/heads/agent/task-1")
        .is_err());
}

#[test]
fn valid_windows_shell_metacharacters_are_supported_in_managed_paths() {
    let fixture = TempDir::new().expect("tempdir");
    let source = fixture.path().join("source");
    fs::create_dir(&source).expect("source");
    let (_repository, _commit) = commit_repository(&source);
    let managed_root = fixture.path().join("managed");
    fs::create_dir(&managed_root).expect("managed");
    let gateway = GitRepositoryGateway::open(&managed_root, &[]).expect("gateway");
    let locator = locator(&gateway, &source);
    let leaf = PathBuf::from("task &()^%;");

    gateway
        .create_worktree(request_at(&gateway, &locator, &source, leaf.clone()))
        .expect("metacharacter path");

    assert!(managed_root.join(leaf).join("README.md").is_file());
}

#[test]
fn excluded_artifact_root_and_git_common_dir_targets_are_rejected() {
    let fixture = TempDir::new().expect("tempdir");
    let source = fixture.path().join("source");
    fs::create_dir(&source).expect("source");
    let (repository, _commit) = commit_repository(&source);

    let managed_root = fixture.path().join("managed");
    let artifact_root = managed_root.join("artifacts");
    fs::create_dir_all(&artifact_root).expect("artifact root");
    let gateway = GitRepositoryGateway::open(&managed_root, std::slice::from_ref(&artifact_root))
        .expect("gateway");
    let artifact_locator = locator(&gateway, &source);
    assert!(gateway
        .create_worktree(request_at(
            &gateway,
            &artifact_locator,
            &source,
            PathBuf::from("artifacts/task-1"),
        ))
        .is_err());

    let common_managed = repository.path().join("managed");
    fs::create_dir(&common_managed).expect("common managed");
    let common_gateway = GitRepositoryGateway::open(&common_managed, &[]).expect("gateway");
    let common_locator = locator(&common_gateway, &source);
    assert!(common_gateway
        .create_worktree(request(&common_gateway, &common_locator, &source))
        .is_err());
    assert!(repository
        .find_reference("refs/heads/agent/task-1")
        .is_err());
}

#[test]
fn ref_lock_and_base_cas_conflicts_leave_branch_target_and_index_absent() {
    let fixture = TempDir::new().expect("tempdir");
    let source = fixture.path().join("source");
    fs::create_dir(&source).expect("source");
    let (repository, _commit) = commit_repository(&source);
    let index_before = fs::read(repository.path().join("index")).expect("index");
    let managed_root = fixture.path().join("managed");
    fs::create_dir(&managed_root).expect("managed");
    let gateway = GitRepositoryGateway::open(&managed_root, &[]).expect("gateway");
    let locator = locator(&gateway, &source);

    let mut stale = request(&gateway, &locator, &source);
    stale.base_commit = GitObjectId::new("0".repeat(40)).expect("zero oid");
    assert!(gateway.create_worktree(stale).is_err());

    let lock = repository.path().join("refs/heads/agent/task-1.lock");
    fs::create_dir_all(lock.parent().expect("lock parent")).expect("lock parent");
    fs::write(&lock, b"inert lock").expect("lock");
    assert!(gateway
        .create_worktree(request(&gateway, &locator, &source))
        .is_err());

    assert_eq!(
        fs::read(repository.path().join("index")).expect("index after"),
        index_before
    );
    assert!(!managed_root.join("task-1").exists());
    assert!(repository
        .find_reference("refs/heads/agent/task-1")
        .is_err());
}

#[test]
fn every_execution_capable_git_configuration_fails_closed_and_stays_inert() {
    let fixture = TempDir::new().expect("tempdir");
    let source = fixture.path().join("source");
    fs::create_dir(&source).expect("source");
    let (repository, _commit) = commit_repository(&source);
    let commands = fixture.path().join("commands");
    fs::create_dir(&commands).expect("commands");
    let mut sentinels = Vec::new();
    let mut command = |name: &str| {
        let marker = fixture.path().join(format!("{name}.executed"));
        let executable = commands.join(format!("{name}.cmd"));
        fs::write(
            &executable,
            format!("@echo off\r\n> \"{}\" echo executed\r\n", marker.display()),
        )
        .expect("sentinel command");
        sentinels.push(marker);
        format!("\"{}\"", executable.display())
    };
    let filter = command("filter");
    let fsmonitor = command("fsmonitor");
    let credential = command("credential");
    let ssh = command("ssh");
    let remote = command("remote");
    let diff = command("diff");
    let merge = command("merge");
    let hooks = fixture.path().join("hooks");
    fs::create_dir(&hooks).expect("hooks");
    let hook_marker = fixture.path().join("hook.executed");
    fs::write(
        hooks.join("post-checkout"),
        format!(
            "#!/bin/sh\nprintf executed > \"{}\"\n",
            hook_marker.display()
        ),
    )
    .expect("hook sentinel");
    sentinels.push(hook_marker);
    let included = fixture.path().join("included.cfg");
    fs::write(&included, b"[safe]\n\tvalue = inert\n").expect("include");
    let mut config = repository.config().expect("config");
    let hooks_value = hooks.to_string_lossy().into_owned();
    let included_value = included.to_string_lossy().into_owned();
    let remote_value = format!("ext::{remote}");
    for (name, value) in [
        ("filter.hostile.process", filter.as_str()),
        ("core.hooksPath", hooks_value.as_str()),
        ("core.fsmonitor", fsmonitor.as_str()),
        ("include.path", included_value.as_str()),
        ("credential.helper", credential.as_str()),
        ("core.sshCommand", ssh.as_str()),
        ("remote.origin.url", remote_value.as_str()),
        ("diff.hostile.command", diff.as_str()),
        ("merge.hostile.driver", merge.as_str()),
    ] {
        config.set_str(name, value).expect(name);
    }
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
    assert!(gateway
        .create_worktree(request(&gateway, &locator, &source))
        .is_err());
    for sentinel in sentinels {
        assert!(
            !sentinel.exists(),
            "{} must remain inert",
            sentinel.display()
        );
    }
    assert!(!managed_root.join("task-1").exists());
}

#[test]
fn shallow_and_sparse_repositories_fail_closed() {
    let fixture = TempDir::new().expect("tempdir");
    let managed_root = fixture.path().join("managed");
    fs::create_dir(&managed_root).expect("managed");
    let gateway = GitRepositoryGateway::open(&managed_root, &[]).expect("gateway");

    let shallow_source = fixture.path().join("shallow");
    fs::create_dir(&shallow_source).expect("shallow");
    let (shallow_repository, commit) = commit_repository(&shallow_source);
    fs::write(
        shallow_repository.path().join("shallow"),
        format!("{commit}\n"),
    )
    .expect("shallow marker");
    let shallow_locator = locator(&gateway, &shallow_source);
    assert_eq!(
        gateway
            .inspect(InspectRepository {
                locator: shallow_locator.clone(),
            })
            .expect("shallow inspect")
            .health,
        RepositoryHealth::Unsafe
    );
    assert!(gateway
        .create_worktree(request(&gateway, &shallow_locator, &shallow_source,))
        .is_err());

    let sparse_source = fixture.path().join("sparse");
    fs::create_dir(&sparse_source).expect("sparse");
    let (sparse_repository, _commit) = commit_repository(&sparse_source);
    sparse_repository
        .config()
        .expect("config")
        .set_bool("core.sparseCheckout", true)
        .expect("sparse config");
    let sparse_locator = locator(&gateway, &sparse_source);
    assert_eq!(
        gateway
            .inspect(InspectRepository {
                locator: sparse_locator.clone(),
            })
            .expect("sparse inspect")
            .health,
        RepositoryHealth::Unsafe
    );
    assert!(gateway
        .create_worktree(request(&gateway, &sparse_locator, &sparse_source))
        .is_err());
}

#[test]
fn static_symlink_target_is_rejected_without_touching_its_destination() {
    let fixture = TempDir::new().expect("tempdir");
    let source = fixture.path().join("source");
    fs::create_dir(&source).expect("source");
    let (repository, _commit) = commit_repository(&source);
    let managed_root = fixture.path().join("managed");
    let outside = fixture.path().join("outside");
    fs::create_dir(&managed_root).expect("managed");
    fs::create_dir(&outside).expect("outside");
    fs::write(outside.join("KEEP.txt"), b"keep").expect("sentinel");
    create_directory_symlink(&outside, &managed_root.join("task-1"));
    let gateway = GitRepositoryGateway::open(&managed_root, &[]).expect("gateway");
    let locator = locator(&gateway, &source);

    assert!(gateway
        .create_worktree(request(&gateway, &locator, &source))
        .is_err());
    assert_eq!(
        fs::read(outside.join("KEEP.txt")).expect("sentinel after"),
        b"keep"
    );
    assert!(repository
        .find_reference("refs/heads/agent/task-1")
        .is_err());
}

#[cfg(windows)]
fn create_directory_symlink(target: &Path, link: &Path) {
    if std::os::windows::fs::symlink_dir(target, link).is_ok() {
        return;
    }
    let status = std::process::Command::new("cmd")
        .args(["/D", "/C", "mklink", "/J"])
        .arg(link)
        .arg(target)
        .status()
        .expect("junction setup");
    assert!(status.success(), "junction setup");
}

#[cfg(unix)]
fn create_directory_symlink(target: &Path, link: &Path) {
    std::os::unix::fs::symlink(target, link).expect("directory symlink");
}

#[cfg(feature = "test-seams")]
#[test]
fn every_post_add_failure_preserves_owned_state_as_a_conflict() {
    use local_agent_terminal_application::{PortError, SafeErrorClassification};
    use local_agent_terminal_repository_git::{PostAddStage, TestHooks};

    for stage in [
        PostAddStage::AfterAdd,
        PostAddStage::AfterParentVerify,
        PostAddStage::AfterTargetValidate,
        PostAddStage::AfterTargetOpen,
        PostAddStage::AfterConfigAttach,
        PostAddStage::AfterSnapshot,
        PostAddStage::AfterRefVerify,
        PostAddStage::AfterOriginalVerify,
    ] {
        let fixture = TempDir::new().expect("tempdir");
        let source = fixture.path().join("source");
        fs::create_dir(&source).expect("source");
        let (repository, commit) = commit_repository(&source);
        let index_before = fs::read(repository.path().join("index")).expect("index");
        let managed_root = fixture.path().join("managed");
        fs::create_dir(&managed_root).expect("managed");
        let mut gateway = GitRepositoryGateway::open(&managed_root, &[]).expect("gateway");
        gateway.set_test_hooks(TestHooks {
            fail_at: Some(stage),
            ..TestHooks::default()
        });
        let locator = locator(&gateway, &source);

        let result = gateway.create_worktree(request(&gateway, &locator, &source));

        assert!(
            matches!(
                result,
                Err(PortError::Failure {
                    classification: SafeErrorClassification::Conflict,
                    ..
                })
            ),
            "{stage:?}"
        );
        assert!(
            managed_root.join("task-1").join("README.md").is_file(),
            "{stage:?}"
        );
        assert_eq!(
            repository
                .find_reference("refs/heads/agent/task-1")
                .expect("preserved branch")
                .target()
                .expect("branch target")
                .to_string(),
            commit,
            "{stage:?}"
        );
        assert!(repository.find_worktree("wt-task-1").is_ok(), "{stage:?}");
        assert_eq!(
            repository
                .head()
                .expect("head")
                .target()
                .expect("target")
                .to_string(),
            commit,
            "{stage:?}"
        );
        assert_eq!(
            fs::read(repository.path().join("index")).expect("index after"),
            index_before,
            "{stage:?}"
        );
    }
}

#[cfg(feature = "test-seams")]
#[test]
fn failed_create_preserves_replacements_after_ownership_observation() {
    use std::sync::{Arc, Barrier};

    use local_agent_terminal_application::{PortError, SafeErrorClassification};
    use local_agent_terminal_repository_git::{PostAddStage, TestHooks};

    let fixture = TempDir::new().expect("tempdir");
    let source = fixture.path().join("source");
    fs::create_dir(&source).expect("source");
    let (repository, commit) = commit_repository(&source);
    let replacement = dangling_commit(&repository, "replacement");
    let managed_root = fixture.path().join("managed");
    fs::create_dir(&managed_root).expect("managed");
    let mut gateway = GitRepositoryGateway::open(&managed_root, &[]).expect("gateway");
    let barrier = Arc::new(Barrier::new(2));
    gateway.set_test_hooks(TestHooks {
        after_cleanup_ownership_check: Some(barrier.clone()),
        fail_at: Some(PostAddStage::AfterAdd),
        ..TestHooks::default()
    });
    let locator = locator(&gateway, &source);
    let create = request(&gateway, &locator, &source);
    let worker = std::thread::spawn(move || gateway.create_worktree(create));
    barrier.wait();
    repository
        .reference(
            "refs/heads/agent/task-1",
            replacement,
            true,
            "concurrent replacement",
        )
        .expect("replace branch");
    let target = managed_root.join("task-1");
    let displaced_target = managed_root.join("owned-target-displaced");
    fs::rename(&target, &displaced_target).expect("displace owned target");
    fs::create_dir(&target).expect("replacement target");
    fs::write(target.join("FOREIGN.txt"), b"preserve").expect("foreign marker");
    let worktree_admin = repository.path().join("worktrees").join("wt-task-1");
    let displaced_admin = repository
        .path()
        .join("worktrees")
        .join("owned-admin-displaced");
    fs::rename(&worktree_admin, &displaced_admin).expect("displace owned worktree metadata");
    fs::create_dir(&worktree_admin).expect("replacement worktree metadata");
    fs::write(worktree_admin.join("FOREIGN.txt"), b"preserve").expect("admin marker");
    barrier.wait();

    let result = worker.join().expect("worker");

    assert!(matches!(
        result,
        Err(PortError::Failure {
            classification: SafeErrorClassification::Conflict,
            ..
        })
    ));
    assert_eq!(
        fs::read(target.join("FOREIGN.txt")).expect("foreign marker after"),
        b"preserve"
    );
    assert_eq!(
        fs::read(worktree_admin.join("FOREIGN.txt")).expect("admin marker after"),
        b"preserve"
    );
    assert!(displaced_target.join("README.md").is_file());
    assert!(displaced_admin.is_dir());
    assert_eq!(
        repository
            .find_reference("refs/heads/agent/task-1")
            .expect("replacement branch preserved")
            .target()
            .expect("replacement target"),
        replacement
    );
    assert_ne!(replacement.to_string(), commit);
}

#[cfg(all(windows, feature = "test-seams"))]
#[test]
fn parent_swap_race_is_blocked_while_checkout_is_in_progress() {
    use std::sync::{Arc, Barrier};

    use local_agent_terminal_repository_git::TestHooks;

    let fixture = TempDir::new().expect("tempdir");
    let source = fixture.path().join("source");
    fs::create_dir(&source).expect("source");
    let (_repository, _commit) = commit_repository(&source);

    let managed_root = fixture.path().join("managed");
    fs::create_dir(&managed_root).expect("managed");
    let moved_root = fixture.path().join("managed-swapped");
    let mut gateway = GitRepositoryGateway::open(&managed_root, &[]).expect("gateway");
    let barrier = Arc::new(Barrier::new(2));
    gateway.set_test_hooks(TestHooks {
        before_checkout: Some(barrier.clone()),
        ..TestHooks::default()
    });
    let locator = locator(&gateway, &source);
    let create = request(&gateway, &locator, &source);
    let worker = std::thread::spawn(move || gateway.create_worktree(create));
    barrier.wait();
    let swap = fs::rename(&managed_root, &moved_root);
    barrier.wait();
    let created = worker.join().expect("worker").expect("create");

    assert!(swap.is_err(), "parent directory swap must be denied");
    assert_eq!(created.state, WorktreeState::Present);
    assert!(managed_root.join("task-1").join("README.md").is_file());
    assert!(!moved_root.exists());
}

#[cfg(all(windows, feature = "test-seams"))]
#[test]
fn target_swap_race_is_blocked_during_checkout_without_touching_outside_bytes() {
    use std::sync::{Arc, Barrier};

    use local_agent_terminal_repository_git::TestHooks;

    let fixture = TempDir::new().expect("tempdir");
    let source = fixture.path().join("source");
    fs::create_dir(&source).expect("source");
    let (_repository, _commit) = commit_repository(&source);

    let managed_root = fixture.path().join("managed");
    let outside = fixture.path().join("outside");
    fs::create_dir(&managed_root).expect("managed");
    fs::create_dir(&outside).expect("outside");
    fs::write(outside.join("KEEP.txt"), b"keep").expect("sentinel");
    let replacement = fixture.path().join("replacement");
    create_directory_symlink(&outside, &replacement);

    let mut gateway = GitRepositoryGateway::open(&managed_root, &[]).expect("gateway");
    let barrier = Arc::new(Barrier::new(2));
    gateway.set_test_hooks(TestHooks {
        during_checkout: Some(barrier.clone()),
        ..TestHooks::default()
    });
    let locator = locator(&gateway, &source);
    let create = request(&gateway, &locator, &source);
    let worker = std::thread::spawn(move || gateway.create_worktree(create));

    barrier.wait();
    let target = managed_root.join("task-1");
    let displaced = managed_root.join("task-1-displaced");
    let swap = fs::rename(&target, &displaced);
    if swap.is_ok() {
        fs::rename(&replacement, &target).expect("install replacement");
    }
    barrier.wait();

    let created = worker.join().expect("worker").expect("create");

    assert!(swap.is_err(), "target directory swap must be denied");
    assert_eq!(created.state, WorktreeState::Present);
    assert!(target.join("README.md").is_file());
    assert!(fs::symlink_metadata(&replacement).is_ok());
    assert_eq!(
        fs::read(outside.join("KEEP.txt")).expect("sentinel after"),
        b"keep"
    );
    assert!(!outside.join("README.md").exists());
    assert!(!displaced.exists());
}
