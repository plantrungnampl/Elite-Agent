use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;

use git2::{Repository, Signature};
use local_agent_terminal_application::{
    AuthorizedGitDiff, AuthorizedGitStatus, ExpectedPresence, PortError, Retryability, RiskLevel,
    SafeErrorClassification, StructuredGit, TaskLeaseState, TaskQuery, TaskSnapshot,
    WorktreeSnapshot, WorktreeState,
};
use local_agent_terminal_domain::{
    CapabilityRef, Condition, GitObjectId, OperationState, Phase, ProjectId, Sequence, TaskBranch,
    TaskId, WorkspaceFingerprint, WorkspaceVersion, WorktreeId,
};
use local_agent_terminal_repository_git::{GitRepositoryGateway, GitStructuredTools};
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
                root_identity: tools.root_identity(&task()).unwrap().clone(),
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
                root_identity: tools.root_identity(&task()).unwrap().clone(),
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
            root_identity: tools.root_identity(&task()).unwrap().clone(),
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
            root_identity: tools.root_identity(&task()).unwrap().clone(),
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
                root_identity: tools.root_identity(&task()).unwrap().clone(),
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
            root_identity: tools.root_identity(&task()).unwrap().clone(),
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
            root_identity: tools.root_identity(&task()).unwrap().clone(),
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
        let repository_path = fixture.path().to_owned();
        let tools = structured_tools(&fixture)
            .with_snapshot_hook_for_test(move || mutate_repository(&repository_path, mutation));

        let error = tools
            .status(AuthorizedGitStatus {
                task_id: task(),
                worktree: worktree(),
                root_identity: tools.root_identity(&task()).unwrap().clone(),
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
    let fixture = OwnedGitFixture::with_tasks(&[
        ("task-1", "worktree-1", "first"),
        ("task-2", "worktree-2", "second"),
    ]);
    let second_task = TaskId::new("task-2").unwrap();
    let tools = GitStructuredTools::from_owned_tasks(
        &fixture.gateway,
        &fixture.tasks,
        &[task(), second_task.clone()],
    )
    .unwrap();
    let second_root = tools.root_identity(&second_task).unwrap().clone();

    let error = tools
        .status(AuthorizedGitStatus {
            task_id: task(),
            worktree: worktree(),
            root_identity: second_root,
        })
        .unwrap_err();

    assert_eq!(
        error.safe_classification(),
        local_agent_terminal_application::SafeErrorClassification::PermissionDenied
    );
}

#[test]
fn validated_registration_derives_root_from_task_repository_and_revision() {
    let fixture = OwnedGitFixture::with_tasks(&[
        ("task-1", "worktree-1", "first"),
        ("task-2", "worktree-2", "second"),
    ]);
    let second_task = TaskId::new("task-2").unwrap();
    let tools = GitStructuredTools::from_owned_tasks(
        &fixture.gateway,
        &fixture.tasks,
        &[task(), second_task.clone()],
    )
    .unwrap();

    assert_ne!(
        tools.root_identity(&task()),
        tools.root_identity(&second_task)
    );
    let first_root = tools.root_identity(&task()).unwrap().clone();
    let result = tools
        .status(AuthorizedGitStatus {
            task_id: task(),
            worktree: worktree(),
            root_identity: first_root,
        })
        .unwrap();
    assert_eq!(result.path_scope, worktree());
}

#[cfg(feature = "test-seams")]
#[test]
fn canonical_worktree_rebind_is_rejected_before_git_bytes_are_generated() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    let fixture = OwnedGitFixture::new("first");
    let first_path = fixture.workdir.clone();
    let second_path = fixture._root.path().join("second");
    fs::create_dir(&second_path).unwrap();
    initialize_repository_at(&second_path, "second");
    let generation_count = Arc::new(AtomicUsize::new(0));
    let observed_generation_count = generation_count.clone();
    let tools = structured_tools(&fixture).with_before_generation_hook_for_test(move || {
        observed_generation_count.fetch_add(1, Ordering::SeqCst);
    });
    let root_identity = tools.root_identity(&task()).unwrap().clone();
    let displaced = fixture._root.path().join("displaced");
    fs::rename(&first_path, &displaced).unwrap();
    fs::rename(&second_path, &first_path).unwrap();

    let error = tools
        .status(AuthorizedGitStatus {
            task_id: task(),
            worktree: worktree(),
            root_identity,
        })
        .unwrap_err();

    assert_eq!(
        error.safe_classification(),
        local_agent_terminal_application::SafeErrorClassification::PermissionDenied
    );
    assert_eq!(generation_count.load(Ordering::SeqCst), 0);
}

#[test]
fn production_ownership_seam_rejects_an_unowned_or_cross_paired_task_record() {
    let fixture = OwnedGitFixture::new("first\n");

    let legitimate = GitStructuredTools::from_owned_tasks(
        &fixture.gateway,
        &fixture.tasks,
        std::slice::from_ref(&task()),
    );
    assert!(legitimate.is_ok());

    let unowned = GitStructuredTools::from_owned_tasks(
        &fixture.gateway,
        &fixture.tasks,
        &[TaskId::new("task-2").unwrap()],
    )
    .err()
    .unwrap();
    assert_eq!(
        unowned.safe_classification(),
        SafeErrorClassification::PermissionDenied
    );

    let mut cross_paired_tasks = fixture.tasks.clone();
    cross_paired_tasks
        .tasks
        .get_mut(task().as_str())
        .unwrap()
        .worktree
        .as_mut()
        .unwrap()
        .task_id = TaskId::new("task-2").unwrap();
    let cross_paired = GitStructuredTools::from_owned_tasks(
        &fixture.gateway,
        &cross_paired_tasks,
        std::slice::from_ref(&task()),
    )
    .err()
    .unwrap();
    assert_eq!(
        cross_paired.safe_classification(),
        SafeErrorClassification::PermissionDenied
    );
}

#[cfg(feature = "test-seams")]
#[test]
fn rebind_after_initial_binding_check_denies_before_first_capture() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    for operation in [StructuredOperation::Status, StructuredOperation::Diff] {
        let fixture = OwnedGitFixture::new("first\n");
        let replacement = fixture._root.path().join("replacement");
        fs::create_dir(&replacement).unwrap();
        initialize_repository_at(&replacement, "attacker\n");
        let displaced = fixture._root.path().join("displaced");
        let workdir = fixture.workdir.clone();
        let generation_count = Arc::new(AtomicUsize::new(0));
        let observed_generation_count = generation_count.clone();
        let tools = GitStructuredTools::from_owned_tasks(
            &fixture.gateway,
            &fixture.tasks,
            std::slice::from_ref(&task()),
        )
        .unwrap()
        .with_after_initial_binding_hook_for_test(move || {
            fs::rename(&workdir, &displaced).is_ok() && fs::rename(&replacement, &workdir).is_ok()
        })
        .with_before_generation_hook_for_test(move || {
            observed_generation_count.fetch_add(1, Ordering::SeqCst);
        });

        let error = run_structured_operation(&tools, operation).unwrap_err();

        assert_eq!(
            error.safe_classification(),
            SafeErrorClassification::PermissionDenied,
            "{operation:?}"
        );
        assert_eq!(generation_count.load(Ordering::SeqCst), 0, "{operation:?}");
    }
}

#[cfg(feature = "test-seams")]
#[test]
fn rebind_after_output_before_return_denies_without_git_bytes() {
    for operation in [StructuredOperation::Status, StructuredOperation::Diff] {
        let fixture = OwnedGitFixture::new("first\n");
        let replacement = fixture._root.path().join("replacement");
        fs::create_dir(&replacement).unwrap();
        initialize_repository_at(&replacement, "attacker\n");
        let displaced = fixture._root.path().join("displaced");
        let workdir = fixture.workdir.clone();
        let tools = GitStructuredTools::from_owned_tasks(
            &fixture.gateway,
            &fixture.tasks,
            std::slice::from_ref(&task()),
        )
        .unwrap()
        .with_before_return_hook_for_test(move || {
            fs::rename(&workdir, &displaced).is_ok() && fs::rename(&replacement, &workdir).is_ok()
        });

        let error = run_structured_operation(&tools, operation).unwrap_err();

        assert_eq!(
            error.safe_classification(),
            SafeErrorClassification::PermissionDenied,
            "{operation:?}"
        );
    }
}

#[test]
fn status_and_diff_are_in_process_and_fail_closed_for_hostile_configuration() {
    let fixture = initialized_repository("one\n");
    let repository = Repository::open(fixture.path()).unwrap();
    repository
        .config()
        .unwrap()
        .set_str("diff.external", "must-not-run")
        .unwrap();
    let tools = structured_tools(&fixture);
    for result in [
        tools
            .status(AuthorizedGitStatus {
                task_id: task(),
                worktree: worktree(),
                root_identity: tools.root_identity(&task()).unwrap().clone(),
            })
            .map(|_| ()),
        tools
            .diff(AuthorizedGitDiff {
                task_id: task(),
                worktree: worktree(),
                root_identity: tools.root_identity(&task()).unwrap().clone(),
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
    let fixture = initialized_repository("one\n");
    let commit = first_locator_head(fixture.path());
    fs::write(fixture.path().join("README.md"), b"two\n").unwrap();
    let locator = fixture.gateway.locate(fixture.path()).unwrap();
    let tools = structured_tools(&fixture);

    let result = tools
        .status(AuthorizedGitStatus {
            task_id: task(),
            worktree: worktree(),
            root_identity: tools.root_identity(&task()).unwrap().clone(),
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

fn initialized_repository(contents: &str) -> OwnedGitFixture {
    OwnedGitFixture::new(contents)
}

fn initialize_repository_at(path: &std::path::Path, contents: &str) {
    let repository = Repository::init(path).unwrap();
    fs::write(path.join("README.md"), contents).unwrap();
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

fn structured_tools(fixture: &OwnedGitFixture) -> GitStructuredTools {
    let revision = GitObjectId::new(first_locator_head(fixture.path()).to_string()).unwrap();
    let mut tasks = fixture.tasks.clone();
    let task_snapshot = tasks.tasks.get_mut(task().as_str()).unwrap();
    task_snapshot.base_commit = revision.clone();
    task_snapshot.worktree.as_mut().unwrap().base_commit = revision;
    GitStructuredTools::from_owned_tasks(&fixture.gateway, &tasks, std::slice::from_ref(&task()))
        .unwrap()
}

struct OwnedGitFixture {
    _root: TempDir,
    workdir: PathBuf,
    gateway: GitRepositoryGateway,
    tasks: FakeTaskQuery,
}

impl OwnedGitFixture {
    fn new(contents: &str) -> Self {
        Self::with_tasks(&[("task-1", "worktree-1", contents)])
    }

    fn with_tasks(specifications: &[(&str, &str, &str)]) -> Self {
        let root = TempDir::new().unwrap();
        let gateway = GitRepositoryGateway::open(root.path(), &[]).unwrap();
        let mut tasks = BTreeMap::new();
        let mut first_workdir = None;
        for (task_id, worktree_id, contents) in specifications {
            let task_id = TaskId::new(*task_id).unwrap();
            let worktree_id = WorktreeId::new(*worktree_id).unwrap();
            let workdir = root.path().join(worktree_id.as_str());
            fs::create_dir(&workdir).unwrap();
            initialize_repository_at(&workdir, contents);
            let locator = gateway.locate(&workdir).unwrap();
            let revision = GitObjectId::new(first_locator_head(&workdir).to_string()).unwrap();
            let snapshot = owned_task_snapshot(task_id, worktree_id, &locator, revision);
            tasks.insert(snapshot.task_id.as_str().to_owned(), snapshot);
            first_workdir.get_or_insert(workdir);
        }
        Self {
            _root: root,
            workdir: first_workdir.unwrap(),
            gateway,
            tasks: FakeTaskQuery { tasks },
        }
    }

    fn path(&self) -> &std::path::Path {
        &self.workdir
    }
}

#[derive(Clone)]
struct FakeTaskQuery {
    tasks: BTreeMap<String, TaskSnapshot>,
}

impl TaskQuery for FakeTaskQuery {
    fn task(&self, task_id: &TaskId) -> Result<TaskSnapshot, PortError> {
        self.tasks.get(task_id.as_str()).cloned().ok_or_else(|| {
            PortError::failure(
                SafeErrorClassification::NotFound,
                Retryability::NonRetryable,
            )
        })
    }

    fn timeline(
        &self,
        _task_id: &TaskId,
    ) -> Result<Vec<local_agent_terminal_application::TimelineEntryDto>, PortError> {
        Ok(Vec::new())
    }
}

fn owned_task_snapshot(
    task_id: TaskId,
    worktree_id: WorktreeId,
    locator: &local_agent_terminal_application::RepositoryLocator,
    revision: GitObjectId,
) -> TaskSnapshot {
    let fingerprint = WorkspaceFingerprint::new(
        revision.clone(),
        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    )
    .unwrap();
    let branch = TaskBranch::new(format!("codex/{}", task_id.as_str())).unwrap();
    let worktree = WorktreeSnapshot {
        worktree_id: worktree_id.clone(),
        repository_id: locator.repository_id.clone(),
        repository_identity: locator.stable_identity.clone(),
        task_id: task_id.clone(),
        branch: branch.clone(),
        base_commit: revision.clone(),
        target_path_display: format!("<managed-workspace>/{}", worktree_id.as_str()),
        state: WorktreeState::Present,
        expected_presence: ExpectedPresence::Present,
        fingerprint,
    };
    TaskSnapshot {
        task_id,
        project_id: ProjectId::new("project-1").unwrap(),
        title: "Structured Git".to_owned(),
        objective: "Keep Git output task-owned".to_owned(),
        risk_level: RiskLevel::High,
        phase: Phase::Intake,
        condition: Condition::Active,
        operation_state: OperationState::None,
        base_branch: TaskBranch::new("main").unwrap(),
        base_commit: revision,
        task_branch: Some(branch),
        worktree: Some(worktree),
        current_sequence: Sequence::new(0),
        workspace_version: WorkspaceVersion::new(0),
        fencing_epoch: 1,
        lease_state: TaskLeaseState::Active,
        recovery_candidates: Vec::new(),
        timeline: Vec::new(),
    }
}

#[cfg(feature = "test-seams")]
#[derive(Clone, Copy, Debug)]
enum StructuredOperation {
    Status,
    Diff,
}

#[cfg(feature = "test-seams")]
fn run_structured_operation(
    tools: &GitStructuredTools,
    operation: StructuredOperation,
) -> Result<(), PortError> {
    match operation {
        StructuredOperation::Status => tools
            .status(AuthorizedGitStatus {
                task_id: task(),
                worktree: worktree(),
                root_identity: tools.root_identity(&task()).unwrap().clone(),
            })
            .map(|_| ()),
        StructuredOperation::Diff => tools
            .diff(AuthorizedGitDiff {
                task_id: task(),
                worktree: worktree(),
                root_identity: tools.root_identity(&task()).unwrap().clone(),
            })
            .map(|_| ()),
    }
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
