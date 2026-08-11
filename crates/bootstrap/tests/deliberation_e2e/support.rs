use std::{
    fs,
    path::{Path, PathBuf},
};

use git2::{IndexAddOption, Repository, Signature};

use crate::support::WorkspaceFixture;

pub fn commit_context_sources(fixture: &WorkspaceFixture, secret_canary: &str) {
    fs::create_dir_all(fixture.source.join("src")).expect("source directory");
    fs::write(
        fixture.source.join("src/allowed.rs"),
        b"pub fn bounded_context() -> bool { true }\n",
    )
    .expect("allowed source");
    fs::write(fixture.source.join(".env"), secret_canary).expect("secret source");
    let repository = Repository::open(&fixture.source).expect("repository");
    let mut index = repository.index().expect("index");
    index
        .add_all(["src/allowed.rs", ".env"], IndexAddOption::DEFAULT, None)
        .expect("add sources");
    index.write().expect("write index");
    let tree_id = index.write_tree().expect("tree id");
    let tree = repository.find_tree(tree_id).expect("tree");
    let parent_id = repository
        .head()
        .expect("head")
        .target()
        .expect("head target");
    let parent = repository.find_commit(parent_id).expect("parent");
    let signature = Signature::now("fixture", "fixture@example.invalid").expect("signature");
    repository
        .commit(
            Some("HEAD"),
            &signature,
            &signature,
            "context sources",
            &tree,
            &[&parent],
        )
        .expect("commit sources");
}

pub fn durable_workspace_bytes(fixture: &WorkspaceFixture) -> Vec<u8> {
    let mut bytes = fs::read(&fixture.database_path).expect("database bytes");
    let artifacts = fixture.app_data.join("artifacts");
    if artifacts.exists() {
        for entry in walk_files(&artifacts) {
            if entry.is_file() {
                bytes.extend(fs::read(entry).expect("artifact bytes"));
            }
        }
    }
    bytes
}

fn walk_files(root: &Path) -> Vec<PathBuf> {
    let mut pending = vec![root.to_path_buf()];
    let mut files = Vec::new();
    while let Some(path) = pending.pop() {
        for entry in fs::read_dir(path).expect("read durable directory") {
            let entry = entry.expect("durable entry").path();
            if entry.is_dir() {
                pending.push(entry);
            } else {
                files.push(entry);
            }
        }
    }
    files
}
