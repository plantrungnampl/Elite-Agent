use std::fs;
use std::path::Path;

use git2::{Repository, Signature};
use local_agent_terminal_application::{
    InspectRepository, ProjectId, RepositoryContextSource, RepositoryGateway,
    SourceSnapshotRequest, TaskId,
};
use local_agent_terminal_repository_git::{GitRepositoryContextSource, GitRepositoryGateway};
use sha2::{Digest, Sha256};
use tempfile::TempDir;

const CAPTURED_AT: &str = "2026-08-10T00:00:00Z";

#[test]
fn reads_one_coherent_committed_tree_with_fingerprint_bound_tracked_overlays() {
    let fixture = Fixture::new(&[
        ("src/committed.rs", b"pub fn committed() {}\n"),
        ("src/overlay.rs", b"pub fn original() {}\n"),
    ]);
    fs::write(
        fixture.workdir.join("src/overlay.rs"),
        b"pub fn overlay() {}\n",
    )
    .unwrap();

    let observation = fixture.observation();
    let revision = observation.base_commit.unwrap().to_string();
    let source = GitRepositoryContextSource::new(fixture.locator.clone(), CAPTURED_AT).unwrap();
    let fingerprint = source.repository_fingerprint().unwrap();
    let before_head = fixture.head();
    let before_index = fs::read(fixture.repository.path().join("index")).unwrap();
    let before_committed = fs::read(fixture.workdir.join("src/committed.rs")).unwrap();
    let before_overlay = fs::read(fixture.workdir.join("src/overlay.rs")).unwrap();

    let snapshot = source
        .snapshot(SourceSnapshotRequest {
            project_id: ProjectId::new("project-1").unwrap(),
            task_id: TaskId::new("task-1").unwrap(),
            revision: revision.clone(),
            repository_fingerprint: fingerprint.clone(),
        })
        .unwrap();

    assert_eq!(snapshot.items.len(), 2);
    let committed = snapshot
        .items
        .iter()
        .find(|item| item.identity.path_identity() == "src/committed.rs")
        .unwrap();
    assert_eq!(committed.identity.revision(), revision);
    assert_eq!(committed.content, before_committed);
    assert_eq!(
        committed.identity.content_hash(),
        &digest(&committed.content)
    );
    assert_eq!(committed.metadata.language(), Some("rust"));
    assert_eq!(
        committed
            .metadata
            .attributes()
            .get("sourceLayer")
            .map(String::as_str),
        Some("committed")
    );

    let overlay = snapshot
        .items
        .iter()
        .find(|item| item.identity.path_identity() == "src/overlay.rs")
        .unwrap();
    assert_eq!(
        overlay.identity.revision(),
        format!("worktree:{revision}:{}", fingerprint.as_str())
    );
    assert_eq!(overlay.content, before_overlay);
    assert_eq!(overlay.identity.content_hash(), &digest(&overlay.content));
    assert_eq!(
        overlay
            .metadata
            .attributes()
            .get("sourceLayer")
            .map(String::as_str),
        Some("tracked-worktree")
    );
    assert_eq!(
        overlay
            .metadata
            .attributes()
            .get("workspaceFingerprint")
            .map(String::as_str),
        Some(fingerprint.as_str())
    );

    assert_eq!(fixture.head(), before_head);
    assert_eq!(
        fs::read(fixture.repository.path().join("index")).unwrap(),
        before_index
    );
    assert_eq!(
        fs::read(fixture.workdir.join("src/committed.rs")).unwrap(),
        committed.content
    );
    assert_eq!(
        fs::read(fixture.workdir.join("src/overlay.rs")).unwrap(),
        overlay.content
    );
}

#[test]
fn rejects_stale_fingerprint_and_repository_identity_substitution() {
    let fixture = Fixture::new(&[("src/lib.rs", b"pub fn initial() {}\n")]);
    let observation = fixture.observation();
    let revision = observation.base_commit.unwrap().to_string();
    let source = GitRepositoryContextSource::new(fixture.locator.clone(), CAPTURED_AT).unwrap();
    let fingerprint = source.repository_fingerprint().unwrap();
    fs::write(fixture.workdir.join("src/lib.rs"), b"pub fn changed() {}\n").unwrap();

    let error = source
        .snapshot(request(&revision, fingerprint))
        .unwrap_err();
    assert_eq!(
        error.safe_classification(),
        local_agent_terminal_application::SafeErrorClassification::Conflict
    );

    let mut substituted = fixture.locator.clone();
    substituted.stable_identity.push_str("-substituted");
    let error = GitRepositoryContextSource::new(substituted, CAPTURED_AT).unwrap_err();
    assert_eq!(
        error.safe_classification(),
        local_agent_terminal_application::SafeErrorClassification::Conflict
    );
}

#[test]
fn rejects_same_status_worktree_mutation_after_fingerprint_acceptance() {
    let fixture = Fixture::new(&[("src/lib.rs", b"pub fn committed() {}\n")]);
    let revision = fixture.observation().base_commit.unwrap().to_string();
    fs::write(fixture.workdir.join("src/lib.rs"), b"pub fn dirty_a() {}\n").unwrap();
    let source = GitRepositoryContextSource::new(fixture.locator.clone(), CAPTURED_AT).unwrap();
    let fingerprint = source.repository_fingerprint().unwrap();

    fs::write(fixture.workdir.join("src/lib.rs"), b"pub fn dirty_b() {}\n").unwrap();

    let error = source
        .snapshot(request(&revision, fingerprint))
        .unwrap_err();
    assert_eq!(
        error.safe_classification(),
        local_agent_terminal_application::SafeErrorClassification::Conflict
    );
}

#[test]
fn ignores_untracked_ignored_oversized_files_during_context_capture() {
    let fixture = Fixture::new(&[("src/lib.rs", b"pub fn tracked() {}\n")]);
    fs::write(
        fixture.repository.path().join("info/exclude"),
        "node_modules/\n",
    )
    .unwrap();
    let untracked = fixture.workdir.join("node_modules/cache.bin");
    fs::create_dir_all(untracked.parent().unwrap()).unwrap();
    fs::write(&untracked, vec![b'x'; 1024 * 1024 + 1]).unwrap();
    let revision = fixture.observation().base_commit.unwrap().to_string();
    let source = GitRepositoryContextSource::new(fixture.locator.clone(), CAPTURED_AT).unwrap();
    let fingerprint = source.repository_fingerprint().unwrap();

    let snapshot = source.snapshot(request(&revision, fingerprint)).unwrap();

    assert_eq!(snapshot.items.len(), 1);
    assert_eq!(snapshot.items[0].identity.path_identity(), "src/lib.rs");
}

#[test]
fn rejects_symlink_submodule_device_binary_and_oversized_sources() {
    for hostile in [
        HostileSource::Symlink,
        HostileSource::Submodule,
        HostileSource::Device,
    ] {
        let fixture = Fixture::with_hostile_tree(hostile);
        assert_snapshot_denied(&fixture);
    }

    let binary = Fixture::new(&[("src/binary.bin", b"text\0binary")]);
    assert_snapshot_denied(&binary);

    let oversized_bytes = vec![b'a'; 1024 * 1024 + 1];
    let oversized = Fixture::new(&[("src/oversized.rs", &oversized_bytes)]);
    assert_snapshot_denied(&oversized);
}

#[cfg(feature = "test-seams")]
#[test]
fn rejects_mutation_during_capture_without_returning_mixed_bytes() {
    let fixture = Fixture::new(&[("src/lib.rs", b"pub fn before() {}\n")]);
    let observation = fixture.observation();
    let revision = observation.base_commit.unwrap().to_string();
    let fingerprint = GitRepositoryContextSource::new(fixture.locator.clone(), CAPTURED_AT)
        .unwrap()
        .repository_fingerprint()
        .unwrap();
    let path = fixture.workdir.join("src/lib.rs");
    let source = GitRepositoryContextSource::new(fixture.locator.clone(), CAPTURED_AT)
        .unwrap()
        .with_capture_hook_for_test(move || {
            fs::write(&path, b"pub fn during() {}\n").unwrap();
        });

    let error = source
        .snapshot(request(&revision, fingerprint))
        .unwrap_err();
    assert_eq!(
        error.safe_classification(),
        local_agent_terminal_application::SafeErrorClassification::Conflict
    );
}

fn assert_snapshot_denied(fixture: &Fixture) {
    let observation = fixture.observation();
    let revision = observation.base_commit.unwrap().to_string();
    let source = GitRepositoryContextSource::new(fixture.locator.clone(), CAPTURED_AT).unwrap();
    let error = source
        .snapshot(request(&revision, digest(b"untrusted fingerprint")))
        .unwrap_err();
    assert_eq!(
        error.safe_classification(),
        local_agent_terminal_application::SafeErrorClassification::PermissionDenied
    );
}

fn request(
    revision: &str,
    repository_fingerprint: local_agent_terminal_application::Sha256Digest,
) -> SourceSnapshotRequest {
    SourceSnapshotRequest {
        project_id: ProjectId::new("project-1").unwrap(),
        task_id: TaskId::new("task-1").unwrap(),
        revision: revision.to_owned(),
        repository_fingerprint,
    }
}

fn digest(bytes: &[u8]) -> local_agent_terminal_application::Sha256Digest {
    local_agent_terminal_application::Sha256Digest::new(format!(
        "sha256:{:x}",
        Sha256::digest(bytes)
    ))
    .unwrap()
}

#[derive(Clone, Copy)]
enum HostileSource {
    Symlink,
    Submodule,
    Device,
}

struct Fixture {
    _root: TempDir,
    workdir: std::path::PathBuf,
    repository: Repository,
    gateway: GitRepositoryGateway,
    locator: local_agent_terminal_application::RepositoryLocator,
}

impl Fixture {
    fn new(files: &[(&str, &[u8])]) -> Self {
        Self::build(files, None)
    }

    fn with_hostile_tree(hostile: HostileSource) -> Self {
        Self::build(&[("src/lib.rs", b"pub fn safe() {}\n")], Some(hostile))
    }

    fn build(files: &[(&str, &[u8])], hostile: Option<HostileSource>) -> Self {
        let root = TempDir::new().unwrap();
        let workdir = root.path().join("repo");
        let repository = Repository::init(&workdir).unwrap();
        for (path, contents) in files {
            let absolute = workdir.join(path);
            fs::create_dir_all(absolute.parent().unwrap()).unwrap();
            fs::write(absolute, contents).unwrap();
        }
        let mut index = repository.index().unwrap();
        for (path, _) in files {
            index.add_path(Path::new(path)).unwrap();
        }
        index.write().unwrap();
        let tree_id = index.write_tree().unwrap();
        let mut tree_id = tree_id;
        if let Some(hostile) = hostile {
            let base_tree = repository.find_tree(tree_id).unwrap();
            let mut builder = repository.treebuilder(Some(&base_tree)).unwrap();
            match hostile {
                HostileSource::Symlink => {
                    let oid = repository.blob(b"target").unwrap();
                    builder.insert("link", oid, 0o120000).unwrap();
                }
                HostileSource::Submodule => {
                    let oid = repository.blob(b"placeholder").unwrap();
                    builder.insert("module", oid, 0o160000).unwrap();
                }
                HostileSource::Device => {
                    let oid = repository.blob(b"device").unwrap();
                    builder.insert("NUL", oid, 0o100644).unwrap();
                }
            }
            tree_id = builder.write().unwrap();
        }
        let signature = Signature::now("test", "test@example.invalid").unwrap();
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

        let gateway = GitRepositoryGateway::open(root.path(), &[]).unwrap();
        let locator = gateway.locate(&workdir).unwrap();
        Self {
            _root: root,
            workdir,
            repository,
            gateway,
            locator,
        }
    }

    fn observation(&self) -> local_agent_terminal_application::RepositorySnapshot {
        self.gateway
            .inspect(InspectRepository {
                locator: self.locator.clone(),
            })
            .unwrap()
    }

    fn head(&self) -> git2::Oid {
        self.repository.head().unwrap().target().unwrap()
    }
}
