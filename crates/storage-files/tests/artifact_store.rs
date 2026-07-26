use std::fs;

use local_agent_terminal_application::{ArtifactRef, ArtifactStore, NewArtifact};
use local_agent_terminal_storage_files::ContentAddressedArtifactStore;
use tempfile::TempDir;

const HELLO_HASH: &str = "sha256:2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824";

#[test]
fn identical_bytes_deduplicate_to_one_sha256_object() {
    let root = TempDir::new().unwrap();
    let store = ContentAddressedArtifactStore::open(root.path()).unwrap();
    let artifact = NewArtifact {
        expected_hash: HELLO_HASH.to_owned(),
        expected_size: 5,
        content: b"hello".to_vec(),
    };

    let first = store.put(artifact.clone()).unwrap();
    let second = store.put(artifact).unwrap();

    assert_eq!(first, second);
    assert_eq!(
        first.storage_key,
        format!("objects/2c/{}", &HELLO_HASH[7..])
    );
    assert_eq!(
        fs::read_dir(root.path().join("objects/2c"))
            .unwrap()
            .count(),
        1
    );
    assert_eq!(store.read(&first).unwrap().bytes, b"hello");
}

#[test]
fn traversal_absolute_and_cross_root_storage_keys_are_rejected() {
    let root = TempDir::new().unwrap();
    let outside = TempDir::new().unwrap();
    let store = ContentAddressedArtifactStore::open(root.path()).unwrap();

    for storage_key in [
        "../outside".to_owned(),
        outside.path().join("object").display().to_string(),
        format!("objects/../{}", &HELLO_HASH[7..]),
    ] {
        assert!(store
            .read(&ArtifactRef {
                content_hash: HELLO_HASH.to_owned(),
                storage_key,
                size_bytes: 5,
            })
            .is_err());
    }
    assert_eq!(fs::read_dir(outside.path()).unwrap().count(), 0);
}

#[test]
fn a_mismatched_deduplication_target_is_preserved_in_quarantine() {
    let root = TempDir::new().unwrap();
    let store = ContentAddressedArtifactStore::open(root.path()).unwrap();
    let artifact = NewArtifact {
        expected_hash: HELLO_HASH.to_owned(),
        expected_size: 5,
        content: b"hello".to_vec(),
    };
    let reference = store.put(artifact.clone()).unwrap();
    fs::write(root.path().join(&reference.storage_key), b"jello").unwrap();

    store.put(artifact).unwrap();

    assert_eq!(store.read(&reference).unwrap().bytes, b"hello");
    let quarantined: Vec<_> = fs::read_dir(root.path().join("quarantine"))
        .unwrap()
        .map(|entry| fs::read(entry.unwrap().path()).unwrap())
        .collect();
    assert_eq!(quarantined, [b"jello".to_vec()]);
}

#[test]
fn symlink_or_junction_object_prefix_escape_is_rejected() {
    let root = TempDir::new().unwrap();
    let outside = TempDir::new().unwrap();
    let store = ContentAddressedArtifactStore::open(root.path()).unwrap();
    let prefix = root.path().join("objects").join("2c");
    create_directory_link(outside.path(), &prefix);

    assert!(store
        .put(NewArtifact {
            expected_hash: HELLO_HASH.to_owned(),
            expected_size: 5,
            content: b"hello".to_vec(),
        })
        .is_err());
    assert_eq!(fs::read_dir(outside.path()).unwrap().count(), 0);
}

#[test]
fn artifact_root_creation_does_not_follow_a_symlink_or_junction_parent() {
    let holder = TempDir::new().unwrap();
    let outside = TempDir::new().unwrap();
    let link = holder.path().join("linked-root");
    create_directory_link(outside.path(), &link);

    assert!(ContentAddressedArtifactStore::open(link.join("nested")).is_err());
    assert!(!outside.path().join("nested").exists());
}

#[cfg(unix)]
fn create_directory_link(target: &std::path::Path, link: &std::path::Path) {
    std::os::unix::fs::symlink(target, link).unwrap();
}

#[cfg(windows)]
fn create_directory_link(target: &std::path::Path, link: &std::path::Path) {
    let output = std::process::Command::new("cmd.exe")
        .args(["/C", "mklink", "/J"])
        .arg(link)
        .arg(target)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "mklink failed for {} -> {}: {}{}",
        link.display(),
        target.display(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}
