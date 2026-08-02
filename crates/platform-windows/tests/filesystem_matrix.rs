#![cfg(windows)]

use std::fs;
use std::io::{Read, Seek, SeekFrom};
#[cfg(feature = "test-seams")]
use std::os::windows::io::AsRawHandle;
use std::path::Path;
use std::process::Command;

use cap_fs_ext::DirExt;
use cap_std::{ambient_authority, fs::Dir};
use local_agent_terminal_application::{
    AuthorizedFileRead, AuthorizedFileWrite, CapabilityFileWriteSessionFactory,
    CapabilityFilesystem, CapabilityRequest, CapabilityResolver, CapabilityRootIdentity,
    FileWritePostExpectation, OpenFileWriteSession, PortError, RelativePathComponents,
    ResolvedCapabilityTarget, Retryability, SafeErrorClassification, ToolExecutionId,
    VerifiedFileWriteCompensation, VerifiedWrite,
};
use local_agent_terminal_domain::{
    ArtifactId, CapabilityRef, FencingToken, LeaseClaim, RunId, Sha256Digest, TaskId,
};
use local_agent_terminal_platform_windows::{CapabilityRegistration, WindowsCapabilityAdapter};
use sha2::{Digest, Sha256};
use tempfile::TempDir;
#[cfg(feature = "test-seams")]
use windows_sys::Win32::Foundation::HANDLE;
#[cfg(feature = "test-seams")]
use windows_sys::Win32::Storage::FileSystem::{
    FileIdInfo, GetFileInformationByHandleEx, FILE_ID_INFO,
};

const MAX_READ_BYTES: usize = 8 * 1024 * 1024;
const MAX_DIRECTORY_ENTRIES: usize = 4_096;

#[test]
fn registered_capability_kinds_resolve_and_read_only_for_their_owner() {
    let source = TempDir::new().unwrap();
    fs::create_dir(source.path().join("src")).unwrap();
    fs::write(source.path().join("src/lib.rs"), b"source").unwrap();
    let artifact = TempDir::new().unwrap();
    fs::write(artifact.path().join("artifact.bin"), b"artifact").unwrap();
    let worktree = TempDir::new().unwrap();
    fs::write(worktree.path().join("task.txt"), b"worktree").unwrap();
    let toolchain = TempDir::new().unwrap();
    fs::write(toolchain.path().join("cargo.exe"), b"toolchain").unwrap();
    let task = task("task-1");
    let artifact_id = ArtifactId::new("artifact-1").unwrap();
    let adapter = WindowsCapabilityAdapter::new(vec![
        CapabilityRegistration::source(
            root("source-root"),
            task.clone(),
            "revision-1",
            source.path(),
        )
        .unwrap(),
        CapabilityRegistration::artifact(
            root("artifact-root"),
            task.clone(),
            artifact_id.clone(),
            artifact.path().join("artifact.bin"),
        )
        .unwrap(),
        CapabilityRegistration::worktree(root("worktree-root"), task.clone(), worktree.path())
            .unwrap(),
        CapabilityRegistration::toolchain(
            root("toolchain-root"),
            task.clone(),
            "cargo",
            toolchain.path().join("cargo.exe"),
        )
        .unwrap(),
    ])
    .unwrap();

    let cases = [
        (
            CapabilityRef::source("revision-1", "src/lib.rs").unwrap(),
            b"source".as_slice(),
        ),
        (
            CapabilityRef::artifact(artifact_id).unwrap(),
            b"artifact".as_slice(),
        ),
        (
            CapabilityRef::worktree(task.clone(), "task.txt").unwrap(),
            b"worktree".as_slice(),
        ),
        (
            CapabilityRef::toolchain("cargo").unwrap(),
            b"toolchain".as_slice(),
        ),
    ];

    for (capability, expected) in cases {
        assert_eq!(resolve_and_read(&adapter, &task, capability), expected);
    }
}

#[test]
fn resolver_denies_wrong_owner_binding_and_root_kind_without_detail() {
    let source = TempDir::new().unwrap();
    fs::write(source.path().join("source.txt"), b"secret").unwrap();
    let artifact = TempDir::new().unwrap();
    fs::write(artifact.path().join("artifact.bin"), b"artifact").unwrap();
    let task_1 = task("task-1");
    let task_2 = task("task-2");
    let adapter = WindowsCapabilityAdapter::new(vec![
        CapabilityRegistration::source(
            root("source-root"),
            task_1.clone(),
            "revision-1",
            source.path(),
        )
        .unwrap(),
        CapabilityRegistration::artifact(
            root("artifact-root"),
            task_1.clone(),
            ArtifactId::new("artifact-1").unwrap(),
            artifact.path().join("artifact.bin"),
        )
        .unwrap(),
    ])
    .unwrap();

    let denied_requests = [
        CapabilityRequest {
            task_id: task_2.clone(),
            capability: CapabilityRef::source("revision-1", "source.txt").unwrap(),
        },
        CapabilityRequest {
            task_id: task_1.clone(),
            capability: CapabilityRef::source("revision-2", "source.txt").unwrap(),
        },
        CapabilityRequest {
            task_id: task_1.clone(),
            capability: CapabilityRef::artifact(ArtifactId::new("artifact-2").unwrap()).unwrap(),
        },
        CapabilityRequest {
            task_id: task_1.clone(),
            capability: CapabilityRef::toolchain("revision-1").unwrap(),
        },
        CapabilityRequest {
            task_id: task_1.clone(),
            capability: CapabilityRef::worktree(task_2, "source.txt").unwrap(),
        },
    ];

    for request in denied_requests {
        assert_non_disclosing(adapter.resolve(request).unwrap_err());
    }
}

#[test]
fn unsupported_windows_path_forms_fail_closed() {
    let task = task("task-1");
    for path in [
        "",
        "/absolute",
        r"\absolute",
        r"C:\absolute",
        r"C:drive-relative",
        r"\\server\share\file",
        r"\\?\C:\device",
        r"..\escape",
        r"nested\..\escape",
        r"nested\\empty",
        r"nested\.\dot",
        "file:stream",
    ] {
        assert!(
            CapabilityRef::worktree(task.clone(), path).is_err(),
            "{path}"
        );
    }

    let root_dir = TempDir::new().unwrap();
    let adapter = WindowsCapabilityAdapter::new(vec![CapabilityRegistration::worktree(
        root("worktree-root"),
        task.clone(),
        root_dir.path(),
    )
    .unwrap()])
    .unwrap();
    for path in ["NUL", "COM1.txt", "trailing.", "trailing ", "bad*.txt"] {
        let capability = CapabilityRef::worktree(task.clone(), path).unwrap();
        assert_non_disclosing(
            adapter
                .resolve(CapabilityRequest {
                    task_id: task.clone(),
                    capability,
                })
                .unwrap_err(),
        );
    }
    assert!(RelativePathComponents::new(Vec::new()).is_err());
    assert!(RelativePathComponents::new(vec![".".to_owned()]).is_err());
}

#[test]
fn worktree_root_capability_resolves_explicitly_without_weakening_file_components() {
    let root_dir = TempDir::new().unwrap();
    let task = task("task-1");
    let adapter = WindowsCapabilityAdapter::new(vec![CapabilityRegistration::worktree(
        root("worktree-root"),
        task.clone(),
        root_dir.path(),
    )
    .unwrap()])
    .unwrap();

    let resolved = adapter
        .resolve(CapabilityRequest {
            task_id: task.clone(),
            capability: CapabilityRef::worktree(task, ".").unwrap(),
        })
        .unwrap();

    assert_eq!(resolved.target, ResolvedCapabilityTarget::Root);
    assert!(RelativePathComponents::new(Vec::new()).is_err());
    assert!(RelativePathComponents::new(vec![".".to_owned()]).is_err());
}

#[test]
fn exact_case_and_missing_reads_have_one_non_disclosing_error() {
    let root_dir = TempDir::new().unwrap();
    fs::write(root_dir.path().join("VisibleName.txt"), b"seven!!").unwrap();
    let task = task("task-1");
    let root_identity = root("worktree-root");
    let adapter = WindowsCapabilityAdapter::new(vec![CapabilityRegistration::worktree(
        root_identity.clone(),
        task.clone(),
        root_dir.path(),
    )
    .unwrap()])
    .unwrap();

    let errors = ["visiblename.txt", "missing-secret-name.txt"].map(|path| {
        adapter
            .read(AuthorizedFileRead {
                task_id: task.clone(),
                root_identity: root_identity.clone(),
                relative_components: components(path),
                expected_digest: None,
            })
            .unwrap_err()
    });

    assert_eq!(errors[0], errors[1]);
    for error in errors {
        assert_non_disclosing(error);
    }
}

#[test]
fn unicode_normalization_is_exact_and_non_disclosing() {
    let root_dir = TempDir::new().unwrap();
    fs::write(root_dir.path().join("café.txt"), b"unicode").unwrap();
    let task = task("task-1");
    let root_identity = root("worktree-root");
    let adapter = WindowsCapabilityAdapter::new(vec![CapabilityRegistration::worktree(
        root_identity.clone(),
        task.clone(),
        root_dir.path(),
    )
    .unwrap()])
    .unwrap();

    assert_eq!(
        adapter
            .read(AuthorizedFileRead {
                task_id: task.clone(),
                root_identity: root_identity.clone(),
                relative_components: components("café.txt"),
                expected_digest: None,
            })
            .unwrap()
            .bytes,
        b"unicode"
    );
    let normalized_error = adapter
        .read(AuthorizedFileRead {
            task_id: task.clone(),
            root_identity: root_identity.clone(),
            relative_components: components("cafe\u{301}.txt"),
            expected_digest: None,
        })
        .unwrap_err();
    let missing_error = adapter
        .read(AuthorizedFileRead {
            task_id: task,
            root_identity,
            relative_components: components("missing.txt"),
            expected_digest: None,
        })
        .unwrap_err();

    assert_eq!(normalized_error, missing_error);
    assert_non_disclosing(normalized_error);
}

#[test]
fn long_paths_are_opened_relative_to_retained_directory_handles() {
    let root_dir = TempDir::new().unwrap();
    let path_components = (0..18)
        .map(|index| format!("component-{index:02}-abcdefgh"))
        .collect::<Vec<_>>();
    let mut directory = Dir::open_ambient_dir(root_dir.path(), ambient_authority()).unwrap();
    for component in &path_components {
        directory.create_dir(component).unwrap();
        directory = directory.open_dir_nofollow(component).unwrap();
    }
    directory.write("leaf.txt", b"long-path").unwrap();
    let relative = format!("{}/leaf.txt", path_components.join("/"));
    assert!(
        root_dir
            .path()
            .join(relative.replace('/', "\\"))
            .as_os_str()
            .len()
            > 260
    );
    let task = task("task-1");
    let adapter = WindowsCapabilityAdapter::new(vec![CapabilityRegistration::source(
        root("source-root"),
        task.clone(),
        "revision-1",
        root_dir.path(),
    )
    .unwrap()])
    .unwrap();

    assert_eq!(
        resolve_and_read(
            &adapter,
            &task,
            CapabilityRef::source("revision-1", relative).unwrap(),
        ),
        b"long-path"
    );
}

#[test]
fn reads_and_directory_enumeration_are_bounded() {
    let bytes_root = TempDir::new().unwrap();
    fs::write(
        bytes_root.path().join("too-large.bin"),
        vec![b'x'; MAX_READ_BYTES + 1],
    )
    .unwrap();
    let entries_root = TempDir::new().unwrap();
    for index in 0..=MAX_DIRECTORY_ENTRIES {
        fs::write(entries_root.path().join(format!("{index:04}.txt")), b"x").unwrap();
    }
    fs::write(entries_root.path().join("target.txt"), b"target").unwrap();
    let task = task("task-1");
    let adapter = WindowsCapabilityAdapter::new(vec![
        CapabilityRegistration::source(
            root("bytes-root"),
            task.clone(),
            "bytes-revision",
            bytes_root.path(),
        )
        .unwrap(),
        CapabilityRegistration::source(
            root("entries-root"),
            task.clone(),
            "entries-revision",
            entries_root.path(),
        )
        .unwrap(),
    ])
    .unwrap();

    for (root_identity, path) in [
        (root("bytes-root"), "too-large.bin"),
        (root("entries-root"), "target.txt"),
    ] {
        assert_non_disclosing(
            adapter
                .read(AuthorizedFileRead {
                    task_id: task.clone(),
                    root_identity,
                    relative_components: components(path),
                    expected_digest: None,
                })
                .unwrap_err(),
        );
    }
}

#[test]
fn static_root_and_nested_junctions_fail_closed() {
    let outside = TempDir::new().unwrap();
    fs::write(outside.path().join("sentinel.txt"), b"outside").unwrap();
    let holder = TempDir::new().unwrap();
    let root_link = holder.path().join("root-link");
    create_junction(outside.path(), &root_link);
    assert!(
        WindowsCapabilityAdapter::new(vec![CapabilityRegistration::source(
            root("linked-root"),
            task("task-1"),
            "revision-1",
            &root_link,
        )
        .unwrap(),])
        .is_err()
    );

    let safe_root = TempDir::new().unwrap();
    create_junction(outside.path(), &safe_root.path().join("nested"));
    let task = task("task-1");
    let root_identity = root("safe-root");
    let adapter = WindowsCapabilityAdapter::new(vec![CapabilityRegistration::source(
        root_identity.clone(),
        task.clone(),
        "revision-1",
        safe_root.path(),
    )
    .unwrap()])
    .unwrap();
    assert_non_disclosing(
        adapter
            .read(AuthorizedFileRead {
                task_id: task,
                root_identity,
                relative_components: components("nested/sentinel.txt"),
                expected_digest: None,
            })
            .unwrap_err(),
    );
    assert_eq!(
        fs::read(outside.path().join("sentinel.txt")).unwrap(),
        b"outside"
    );
}

#[test]
#[cfg(feature = "test-seams")]
fn replacement_races_are_contained_by_retained_and_exact_file_handles() {
    let root_dir = TempDir::new().unwrap();
    fs::create_dir(root_dir.path().join("nested")).unwrap();
    let leaf = root_dir.path().join("nested/leaf.txt");
    fs::write(&leaf, b"original").unwrap();
    let task = task("task-1");
    let root_identity = root("source-root");
    let adapter = WindowsCapabilityAdapter::new(vec![CapabilityRegistration::source(
        root_identity.clone(),
        task.clone(),
        "revision-1",
        root_dir.path(),
    )
    .unwrap()])
    .unwrap();
    let resolved = adapter
        .resolve(CapabilityRequest {
            task_id: task.clone(),
            capability: CapabilityRef::source("revision-1", "nested/leaf.txt").unwrap(),
        })
        .unwrap();
    let backup_root = root_dir.path().with_extension("replaced");
    let backup_ancestor = root_dir.path().join("old-nested");
    let old_leaf = root_dir.path().join("nested/old-leaf.txt");

    let result = adapter
        .read_with_post_open_hook(
            AuthorizedFileRead {
                task_id: task,
                root_identity,
                relative_components: resolved_relative(resolved.target),
                expected_digest: None,
            },
            || {
                assert!(fs::rename(root_dir.path(), &backup_root).is_err());
                assert!(fs::rename(root_dir.path().join("nested"), &backup_ancestor).is_err());
                fs::rename(&leaf, &old_leaf)?;
                fs::write(&leaf, b"replacement")
            },
        )
        .unwrap();

    assert_eq!(result.bytes, b"original");
    assert_eq!(fs::read(&leaf).unwrap(), b"replacement");
}

#[test]
fn ancestor_and_leaf_reparse_replacement_after_resolution_cannot_escape() {
    let outside = TempDir::new().unwrap();
    fs::write(outside.path().join("sentinel.txt"), b"outside").unwrap();
    let root_dir = TempDir::new().unwrap();
    fs::create_dir(root_dir.path().join("ancestor")).unwrap();
    fs::write(root_dir.path().join("ancestor/sentinel.txt"), b"inside").unwrap();
    fs::write(root_dir.path().join("leaf"), b"inside-leaf").unwrap();
    let task = task("task-1");
    let root_identity = root("source-root");
    let adapter = WindowsCapabilityAdapter::new(vec![CapabilityRegistration::source(
        root_identity.clone(),
        task.clone(),
        "revision-1",
        root_dir.path(),
    )
    .unwrap()])
    .unwrap();
    let ancestor = adapter
        .resolve(CapabilityRequest {
            task_id: task.clone(),
            capability: CapabilityRef::source("revision-1", "ancestor/sentinel.txt").unwrap(),
        })
        .unwrap();
    let leaf = adapter
        .resolve(CapabilityRequest {
            task_id: task.clone(),
            capability: CapabilityRef::source("revision-1", "leaf").unwrap(),
        })
        .unwrap();

    fs::rename(
        root_dir.path().join("ancestor"),
        root_dir.path().join("old-ancestor"),
    )
    .unwrap();
    create_junction(outside.path(), &root_dir.path().join("ancestor"));
    fs::remove_file(root_dir.path().join("leaf")).unwrap();
    create_junction(outside.path(), &root_dir.path().join("leaf"));

    for resolved in [ancestor, leaf] {
        assert_non_disclosing(
            adapter
                .read(AuthorizedFileRead {
                    task_id: task.clone(),
                    root_identity: root_identity.clone(),
                    relative_components: resolved_relative(resolved.target),
                    expected_digest: None,
                })
                .unwrap_err(),
        );
    }
    assert_eq!(
        fs::read(outside.path().join("sentinel.txt")).unwrap(),
        b"outside"
    );
}

#[test]
fn worktree_write_session_applies_verifies_and_restores_preimage() {
    let root_dir = TempDir::new().unwrap();
    let target = root_dir.path().join("target.txt");
    fs::write(&target, b"before").unwrap();
    let task = task("task-1");
    let root_identity = root("worktree-root");
    let adapter = WindowsCapabilityAdapter::new(vec![CapabilityRegistration::worktree(
        root_identity.clone(),
        task.clone(),
        root_dir.path(),
    )
    .unwrap()])
    .unwrap();
    let before_digest =
        Sha256Digest::new(format!("sha256:{:x}", Sha256::digest(b"before"))).unwrap();
    let after_digest = Sha256Digest::new(format!("sha256:{:x}", Sha256::digest(b"after"))).unwrap();
    let request = OpenFileWriteSession::new(
        ToolExecutionId::new("write-1").unwrap(),
        task.clone(),
        root_identity,
        components("target.txt"),
        Some(before_digest.clone()),
        LeaseClaim::new(
            task,
            RunId::new("run-1").unwrap(),
            FencingToken::new(7).unwrap(),
        ),
    )
    .unwrap();

    let mut session = CapabilityFileWriteSessionFactory::open(&adapter, request).unwrap();
    assert_eq!(
        session.pre_image().present_bytes().unwrap().bytes,
        b"before"
    );
    session.apply(b"after").unwrap();
    let verified = session
        .verify_post_image(&FileWritePostExpectation::new(after_digest.clone(), 5).unwrap())
        .unwrap();

    assert_eq!(
        verified,
        VerifiedWrite {
            digest: after_digest,
            size_bytes: 5,
        }
    );
    assert_eq!(fs::read(&target).unwrap(), b"after");
    assert_eq!(
        session.restore_pre_image_and_verify().unwrap(),
        VerifiedFileWriteCompensation::Restored(VerifiedWrite {
            digest: before_digest,
            size_bytes: 6,
        })
    );
    assert_eq!(fs::read(target).unwrap(), b"before");
}

#[test]
fn apply_atomically_replaces_instead_of_mutating_the_open_preimage() {
    let root_dir = TempDir::new().unwrap();
    let target = root_dir.path().join("target.txt");
    fs::write(&target, b"before").unwrap();
    let mut open_preimage = fs::File::open(&target).unwrap();
    let task = task("task-1");
    let root_identity = root("worktree-root");
    let adapter = WindowsCapabilityAdapter::new(vec![CapabilityRegistration::worktree(
        root_identity.clone(),
        task.clone(),
        root_dir.path(),
    )
    .unwrap()])
    .unwrap();
    let request = OpenFileWriteSession::new(
        ToolExecutionId::new("write-atomic-replace").unwrap(),
        task.clone(),
        root_identity,
        components("target.txt"),
        None,
        LeaseClaim::new(
            task,
            RunId::new("run-1").unwrap(),
            FencingToken::new(7).unwrap(),
        ),
    )
    .unwrap();
    let mut session = CapabilityFileWriteSessionFactory::open(&adapter, request).unwrap();

    session.apply(b"after").unwrap();
    open_preimage.seek(SeekFrom::Start(0)).unwrap();
    let mut retained_bytes = Vec::new();
    open_preimage.read_to_end(&mut retained_bytes).unwrap();

    assert_eq!(retained_bytes, b"before");
    assert_eq!(fs::read(target).unwrap(), b"after");
    assert_eq!(directory_names(root_dir.path()), ["target.txt"]);
}

#[test]
fn source_artifact_and_toolchain_capabilities_cannot_open_write_sessions() {
    let source = TempDir::new().unwrap();
    fs::write(source.path().join("source.txt"), b"source").unwrap();
    let artifact = TempDir::new().unwrap();
    fs::write(artifact.path().join("artifact.bin"), b"artifact").unwrap();
    let toolchain = TempDir::new().unwrap();
    fs::write(toolchain.path().join("tool.exe"), b"toolchain").unwrap();
    let task = task("task-1");
    let adapter = WindowsCapabilityAdapter::new(vec![
        CapabilityRegistration::source(
            root("source-root"),
            task.clone(),
            "revision-1",
            source.path(),
        )
        .unwrap(),
        CapabilityRegistration::artifact(
            root("artifact-root"),
            task.clone(),
            ArtifactId::new("artifact-1").unwrap(),
            artifact.path().join("artifact.bin"),
        )
        .unwrap(),
        CapabilityRegistration::toolchain(
            root("toolchain-root"),
            task.clone(),
            "tool",
            toolchain.path().join("tool.exe"),
        )
        .unwrap(),
    ])
    .unwrap();

    let errors = [
        ("write-source", root("source-root"), "source.txt"),
        ("write-artifact", root("artifact-root"), "artifact.bin"),
        ("write-toolchain", root("toolchain-root"), "tool.exe"),
    ]
    .map(|(execution_id, root_identity, path)| {
        let request = OpenFileWriteSession::new(
            ToolExecutionId::new(execution_id).unwrap(),
            task.clone(),
            root_identity,
            components(path),
            None,
            LeaseClaim::new(
                task.clone(),
                RunId::new("run-1").unwrap(),
                FencingToken::new(7).unwrap(),
            ),
        )
        .unwrap();
        match CapabilityFileWriteSessionFactory::open(&adapter, request) {
            Ok(_) => panic!("non-worktree capabilities must remain read-only"),
            Err(error) => error,
        }
    });

    assert_eq!(errors[0], errors[1]);
    assert_eq!(errors[1], errors[2]);
    for error in errors {
        assert_non_disclosing(error);
    }
    assert_eq!(
        fs::read(source.path().join("source.txt")).unwrap(),
        b"source"
    );
    assert_eq!(
        fs::read(artifact.path().join("artifact.bin")).unwrap(),
        b"artifact"
    );
    assert_eq!(
        fs::read(toolchain.path().join("tool.exe")).unwrap(),
        b"toolchain"
    );
}

#[test]
fn expected_preimage_digest_mismatch_has_zero_filesystem_effect() {
    let root_dir = TempDir::new().unwrap();
    let target = root_dir.path().join("secret-name.txt");
    fs::write(&target, b"secret-before").unwrap();
    let task = task("task-1");
    let root_identity = root("worktree-root");
    let adapter = WindowsCapabilityAdapter::new(vec![CapabilityRegistration::worktree(
        root_identity.clone(),
        task.clone(),
        root_dir.path(),
    )
    .unwrap()])
    .unwrap();
    let request = OpenFileWriteSession::new(
        ToolExecutionId::new("write-digest-mismatch").unwrap(),
        task.clone(),
        root_identity,
        components("secret-name.txt"),
        Some(
            Sha256Digest::new(format!("sha256:{:x}", Sha256::digest(b"not-the-preimage"))).unwrap(),
        ),
        LeaseClaim::new(
            task,
            RunId::new("run-1").unwrap(),
            FencingToken::new(7).unwrap(),
        ),
    )
    .unwrap();

    let error = match CapabilityFileWriteSessionFactory::open(&adapter, request) {
        Ok(_) => panic!("a mismatched pre-image digest must not open a session"),
        Err(error) => error,
    };

    assert_non_disclosing(error);
    assert_eq!(fs::read(target).unwrap(), b"secret-before");
    assert_eq!(directory_names(root_dir.path()), ["secret-name.txt"]);
}

#[test]
fn absent_target_compensation_removes_exactly_the_applied_file() {
    let root_dir = TempDir::new().unwrap();
    let task = task("task-1");
    let root_identity = root("worktree-root");
    let adapter = WindowsCapabilityAdapter::new(vec![CapabilityRegistration::worktree(
        root_identity.clone(),
        task.clone(),
        root_dir.path(),
    )
    .unwrap()])
    .unwrap();
    let request = OpenFileWriteSession::new(
        ToolExecutionId::new("write-new-file").unwrap(),
        task.clone(),
        root_identity,
        components("created.txt"),
        None,
        LeaseClaim::new(
            task,
            RunId::new("run-1").unwrap(),
            FencingToken::new(7).unwrap(),
        ),
    )
    .unwrap();
    let mut session = CapabilityFileWriteSessionFactory::open(&adapter, request).unwrap();

    assert!(session.pre_image().present_bytes().is_none());
    session.apply(b"created").unwrap();
    let expected_digest =
        Sha256Digest::new(format!("sha256:{:x}", Sha256::digest(b"created"))).unwrap();
    assert_eq!(
        session
            .verify_post_image(&FileWritePostExpectation::new(expected_digest.clone(), 7).unwrap())
            .unwrap(),
        VerifiedWrite {
            digest: expected_digest,
            size_bytes: 7,
        }
    );
    assert_eq!(
        session.restore_pre_image_and_verify().unwrap(),
        VerifiedFileWriteCompensation::Absent
    );
    assert!(!root_dir.path().join("created.txt").exists());
    assert!(directory_names(root_dir.path()).is_empty());
}

#[test]
fn absent_worktree_target_resolves_without_a_fabricated_content_digest() {
    let root_dir = TempDir::new().unwrap();
    let task = task("task-1");
    let adapter = WindowsCapabilityAdapter::new(vec![CapabilityRegistration::worktree(
        root("worktree-root"),
        task.clone(),
        root_dir.path(),
    )
    .unwrap()])
    .unwrap();

    let resolved = adapter
        .resolve(CapabilityRequest {
            task_id: task.clone(),
            capability: CapabilityRef::worktree(task, "created.txt").unwrap(),
        })
        .unwrap();

    assert_eq!(resolved.content_digest, None);
    assert_eq!(
        resolved_relative(resolved.target).as_slice(),
        ["created.txt"]
    );
    assert!(directory_names(root_dir.path()).is_empty());
}

#[test]
fn oversized_write_is_denied_before_target_or_temp_mutation() {
    let root_dir = TempDir::new().unwrap();
    let target = root_dir.path().join("secret-large.txt");
    fs::write(&target, b"before").unwrap();
    let task = task("task-1");
    let root_identity = root("worktree-root");
    let adapter = WindowsCapabilityAdapter::new(vec![CapabilityRegistration::worktree(
        root_identity.clone(),
        task.clone(),
        root_dir.path(),
    )
    .unwrap()])
    .unwrap();
    let request = OpenFileWriteSession::new(
        ToolExecutionId::new("write-too-large").unwrap(),
        task.clone(),
        root_identity,
        components("secret-large.txt"),
        None,
        LeaseClaim::new(
            task,
            RunId::new("run-1").unwrap(),
            FencingToken::new(7).unwrap(),
        ),
    )
    .unwrap();
    let mut session = CapabilityFileWriteSessionFactory::open(&adapter, request).unwrap();

    let error = session.apply(&vec![b'x'; MAX_READ_BYTES + 1]).unwrap_err();

    assert_non_disclosing(error);
    assert_eq!(fs::read(target).unwrap(), b"before");
    assert_eq!(directory_names(root_dir.path()), ["secret-large.txt"]);
}

#[test]
fn write_session_requires_the_exact_task_and_root_owner_binding() {
    let root_dir = TempDir::new().unwrap();
    fs::write(root_dir.path().join("owner-only.txt"), b"owner").unwrap();
    let owner = task("task-1");
    let other = task("task-2");
    let root_identity = root("worktree-root");
    let adapter = WindowsCapabilityAdapter::new(vec![CapabilityRegistration::worktree(
        root_identity.clone(),
        owner.clone(),
        root_dir.path(),
    )
    .unwrap()])
    .unwrap();
    let wrong_task = OpenFileWriteSession::new(
        ToolExecutionId::new("write-wrong-task").unwrap(),
        other.clone(),
        root_identity,
        components("owner-only.txt"),
        None,
        LeaseClaim::new(
            other,
            RunId::new("run-2").unwrap(),
            FencingToken::new(8).unwrap(),
        ),
    )
    .unwrap();
    let wrong_root = OpenFileWriteSession::new(
        ToolExecutionId::new("write-wrong-root").unwrap(),
        owner.clone(),
        root("other-root"),
        components("owner-only.txt"),
        None,
        LeaseClaim::new(
            owner,
            RunId::new("run-1").unwrap(),
            FencingToken::new(7).unwrap(),
        ),
    )
    .unwrap();

    let errors = [wrong_task, wrong_root].map(|request| {
        match CapabilityFileWriteSessionFactory::open(&adapter, request) {
            Ok(_) => panic!("unowned task/root binding must not open a session"),
            Err(error) => error,
        }
    });

    assert_eq!(errors[0], errors[1]);
    for error in errors {
        assert_non_disclosing(error);
    }
    assert_eq!(
        fs::read(root_dir.path().join("owner-only.txt")).unwrap(),
        b"owner"
    );
    assert_eq!(directory_names(root_dir.path()), ["owner-only.txt"]);
}

#[test]
fn legacy_filesystem_write_is_non_disclosing_and_has_zero_effect() {
    let root_dir = TempDir::new().unwrap();
    let target = root_dir.path().join("secret-legacy.txt");
    fs::write(&target, b"before").unwrap();
    let task = task("task-1");
    let root_identity = root("worktree-root");
    let adapter = WindowsCapabilityAdapter::new(vec![CapabilityRegistration::worktree(
        root_identity.clone(),
        task.clone(),
        root_dir.path(),
    )
    .unwrap()])
    .unwrap();

    let error = adapter
        .write(AuthorizedFileWrite {
            task_id: task.clone(),
            root_identity,
            relative_components: components("secret-legacy.txt"),
            expected_digest: None,
            bytes: b"attacker-bytes".to_vec(),
            fencing_token: FencingToken::new(7).unwrap(),
            lease_claim: LeaseClaim::new(
                task,
                RunId::new("run-1").unwrap(),
                FencingToken::new(7).unwrap(),
            ),
        })
        .unwrap_err();

    assert_non_disclosing(error);
    assert_eq!(fs::read(target).unwrap(), b"before");
    assert_eq!(directory_names(root_dir.path()), ["secret-legacy.txt"]);
}

#[test]
fn blocked_root_and_ancestor_swaps_and_detected_leaf_swap_cannot_redirect_the_write() {
    let outside = TempDir::new().unwrap();
    fs::write(outside.path().join("sentinel.txt"), b"outside").unwrap();
    fs::write(
        outside.path().join("replacement-canary.txt"),
        b"replacement-tree",
    )
    .unwrap();
    let root_dir = TempDir::new().unwrap();
    fs::create_dir(root_dir.path().join("ancestor")).unwrap();
    fs::write(root_dir.path().join("root-canary.txt"), b"root-original").unwrap();
    fs::write(
        root_dir.path().join("ancestor").join("ancestor-canary.txt"),
        b"ancestor-original",
    )
    .unwrap();
    let leaf = root_dir.path().join("ancestor").join("leaf.txt");
    fs::write(&leaf, b"original").unwrap();
    let task = task("task-1");
    let root_identity = root("worktree-root");
    let adapter = WindowsCapabilityAdapter::new(vec![CapabilityRegistration::worktree(
        root_identity.clone(),
        task.clone(),
        root_dir.path(),
    )
    .unwrap()])
    .unwrap();
    let request = OpenFileWriteSession::new(
        ToolExecutionId::new("write-replacement-race").unwrap(),
        task.clone(),
        root_identity,
        components("ancestor/leaf.txt"),
        None,
        LeaseClaim::new(
            task,
            RunId::new("run-1").unwrap(),
            FencingToken::new(7).unwrap(),
        ),
    )
    .unwrap();
    let mut session = CapabilityFileWriteSessionFactory::open(&adapter, request).unwrap();
    let detached_root = root_dir.path().with_extension("detached");
    let detached_ancestor = root_dir.path().join("detached-ancestor");
    let detached_leaf = root_dir.path().join("ancestor").join("detached-leaf.txt");

    let root_swap = fs::rename(root_dir.path(), &detached_root);
    assert!(
        root_swap.is_err(),
        "the retained root handle must block its swap"
    );
    assert!(!detached_root.exists());
    assert_eq!(
        fs::read(root_dir.path().join("root-canary.txt")).unwrap(),
        b"root-original"
    );

    let ancestor_swap = fs::rename(root_dir.path().join("ancestor"), &detached_ancestor);
    assert!(
        ancestor_swap.is_err(),
        "the retained ancestor handle must block its swap"
    );
    assert!(!detached_ancestor.exists());
    assert_eq!(
        fs::read(root_dir.path().join("ancestor").join("ancestor-canary.txt")).unwrap(),
        b"ancestor-original"
    );

    fs::rename(&leaf, &detached_leaf).unwrap();
    create_junction(outside.path(), &leaf);
    assert!(detached_leaf.exists());
    assert!(leaf.is_dir());

    let error = session.apply(b"replacement").unwrap_err();

    assert_non_disclosing(error);
    assert_eq!(fs::read(detached_leaf).unwrap(), b"original");
    assert_eq!(
        fs::read(outside.path().join("sentinel.txt")).unwrap(),
        b"outside"
    );
    assert_eq!(
        fs::read(outside.path().join("replacement-canary.txt")).unwrap(),
        b"replacement-tree"
    );
    assert_eq!(fs::read(leaf.join("sentinel.txt")).unwrap(), b"outside");
    assert_eq!(
        directory_names(&root_dir.path().join("ancestor")),
        ["ancestor-canary.txt", "detached-leaf.txt", "leaf.txt"]
    );
}

#[test]
fn applied_target_replacement_before_compensation_is_never_clobbered() {
    let root_dir = TempDir::new().unwrap();
    let target = root_dir.path().join("target.txt");
    let detached_applied = root_dir.path().join("detached-applied.txt");
    fs::write(&target, b"preimage").unwrap();
    let task = task("task-1");
    let root_identity = root("worktree-root");
    let adapter = WindowsCapabilityAdapter::new(vec![CapabilityRegistration::worktree(
        root_identity.clone(),
        task.clone(),
        root_dir.path(),
    )
    .unwrap()])
    .unwrap();
    let request = OpenFileWriteSession::new(
        ToolExecutionId::new("write-compensation-race").unwrap(),
        task.clone(),
        root_identity,
        components("target.txt"),
        None,
        LeaseClaim::new(
            task,
            RunId::new("run-1").unwrap(),
            FencingToken::new(7).unwrap(),
        ),
    )
    .unwrap();
    let mut session = CapabilityFileWriteSessionFactory::open(&adapter, request).unwrap();
    session.apply(b"applied").unwrap();
    fs::rename(&target, &detached_applied).unwrap();
    fs::write(&target, b"attacker").unwrap();

    let error = session.restore_pre_image_and_verify().unwrap_err();

    assert_non_disclosing(error);
    assert_eq!(fs::read(target).unwrap(), b"attacker");
    assert_eq!(fs::read(detached_applied).unwrap(), b"applied");
    assert_eq!(
        directory_names(root_dir.path()),
        ["detached-applied.txt", "target.txt"]
    );
}

#[test]
#[cfg(feature = "test-seams")]
fn post_stage_target_replacement_cleans_temp_without_deleting_attacker_file() {
    let root_dir = TempDir::new().unwrap();
    let target = root_dir.path().join("target.txt");
    let task = task("task-1");
    let root_identity = root("worktree-root");
    let adapter = WindowsCapabilityAdapter::new(vec![CapabilityRegistration::worktree(
        root_identity.clone(),
        task.clone(),
        root_dir.path(),
    )
    .unwrap()])
    .unwrap();
    let request = OpenFileWriteSession::new(
        ToolExecutionId::new("write-post-stage-race").unwrap(),
        task.clone(),
        root_identity,
        components("target.txt"),
        None,
        LeaseClaim::new(
            task,
            RunId::new("run-1").unwrap(),
            FencingToken::new(7).unwrap(),
        ),
    )
    .unwrap();
    let mut session = adapter
        .open_write_session_with_post_stage_hook(
            request,
            Box::new({
                let target = target.clone();
                move || fs::write(target, b"attacker")
            }),
        )
        .unwrap();

    let error = session.apply(b"applied").unwrap_err();

    assert_non_disclosing(error);
    assert_eq!(fs::read(target).unwrap(), b"attacker");
    assert_eq!(directory_names(root_dir.path()), ["target.txt"]);
}

#[test]
#[cfg(feature = "test-seams")]
fn compensation_stage_failure_cleans_temp_without_clobbering_attacker_file() {
    let root_dir = TempDir::new().unwrap();
    let target = root_dir.path().join("target.txt");
    let detached_applied = root_dir.path().join("detached-applied.txt");
    fs::write(&target, b"preimage").unwrap();
    let task = task("task-1");
    let root_identity = root("worktree-root");
    let adapter = WindowsCapabilityAdapter::new(vec![CapabilityRegistration::worktree(
        root_identity.clone(),
        task.clone(),
        root_dir.path(),
    )
    .unwrap()])
    .unwrap();
    let request = OpenFileWriteSession::new(
        ToolExecutionId::new("write-compensation-stage-failure").unwrap(),
        task.clone(),
        root_identity,
        components("target.txt"),
        None,
        LeaseClaim::new(
            task,
            RunId::new("run-1").unwrap(),
            FencingToken::new(7).unwrap(),
        ),
    )
    .unwrap();
    let mut session = adapter
        .open_write_session_with_compensation_post_stage_hook(
            request,
            Box::new({
                let target = target.clone();
                let detached_applied = detached_applied.clone();
                move || {
                    fs::rename(&target, detached_applied)?;
                    fs::write(target, b"attacker")
                }
            }),
        )
        .unwrap();
    session.apply(b"applied").unwrap();

    let error = session.restore_pre_image_and_verify().unwrap_err();

    assert_non_disclosing(error);
    assert_eq!(fs::read(target).unwrap(), b"attacker");
    assert_eq!(fs::read(detached_applied).unwrap(), b"applied");
    assert_eq!(
        directory_names(root_dir.path()),
        ["detached-applied.txt", "target.txt"]
    );
}

#[test]
#[cfg(feature = "test-seams")]
fn temp_identity_mismatch_never_deletes_attacker_owned_replacement() {
    let root_dir = TempDir::new().unwrap();
    let task = task("task-1");
    let root_identity = root("worktree-root");
    let adapter = WindowsCapabilityAdapter::new(vec![CapabilityRegistration::worktree(
        root_identity.clone(),
        task.clone(),
        root_dir.path(),
    )
    .unwrap()])
    .unwrap();
    let request = OpenFileWriteSession::new(
        ToolExecutionId::new("write-temp-identity-race").unwrap(),
        task.clone(),
        root_identity,
        components("target.txt"),
        None,
        LeaseClaim::new(
            task,
            RunId::new("run-1").unwrap(),
            FencingToken::new(7).unwrap(),
        ),
    )
    .unwrap();
    let root_path = root_dir.path().to_owned();
    let mut session = adapter
        .open_write_session_with_post_stage_hook(
            request,
            Box::new(move || {
                let temp_name = directory_names(&root_path)
                    .into_iter()
                    .find(|name| name.starts_with(".lat-write-"))
                    .expect("the staged file exists before the hook");
                fs::rename(
                    root_path.join(&temp_name),
                    root_path.join("detached-staged.bin"),
                )?;
                fs::write(root_path.join(temp_name), b"attacker-temp")
            }),
        )
        .unwrap();

    let error = session.apply(b"applied").unwrap_err();

    assert_non_disclosing(error);
    assert!(!root_dir.path().join("target.txt").exists());
    assert_eq!(
        fs::read(root_dir.path().join("detached-staged.bin")).unwrap(),
        b"applied"
    );
    let attacker_temp = directory_names(root_dir.path())
        .into_iter()
        .find(|name| name.starts_with(".lat-write-"))
        .unwrap();
    assert_eq!(
        fs::read(root_dir.path().join(attacker_temp)).unwrap(),
        b"attacker-temp"
    );
}

#[test]
#[cfg(feature = "test-seams")]
fn post_rename_target_replacement_fails_exact_post_image_verification() {
    let root_dir = TempDir::new().unwrap();
    let target = root_dir.path().join("target.txt");
    let detached_applied = root_dir.path().join("detached-applied.txt");
    let task = task("task-1");
    let root_identity = root("worktree-root");
    let adapter = WindowsCapabilityAdapter::new(vec![CapabilityRegistration::worktree(
        root_identity.clone(),
        task.clone(),
        root_dir.path(),
    )
    .unwrap()])
    .unwrap();
    let request = OpenFileWriteSession::new(
        ToolExecutionId::new("write-post-rename-race").unwrap(),
        task.clone(),
        root_identity,
        components("target.txt"),
        None,
        LeaseClaim::new(
            task,
            RunId::new("run-1").unwrap(),
            FencingToken::new(7).unwrap(),
        ),
    )
    .unwrap();
    let mut session = adapter
        .open_write_session_with_post_rename_hook(
            request,
            Box::new({
                let target = target.clone();
                let detached_applied = detached_applied.clone();
                move || {
                    fs::rename(&target, detached_applied)?;
                    fs::write(target, b"attacker")
                }
            }),
        )
        .unwrap();

    let error = session.apply(b"applied").unwrap_err();

    assert_non_disclosing(error);
    assert_eq!(fs::read(target).unwrap(), b"attacker");
    assert_eq!(fs::read(detached_applied).unwrap(), b"applied");
    assert_eq!(
        directory_names(root_dir.path()),
        ["detached-applied.txt", "target.txt"]
    );
}

#[test]
#[cfg(feature = "test-seams")]
fn last_moment_present_apply_race_preserves_attacker_and_preimage() {
    let outside = TempDir::new().unwrap();
    fs::write(outside.path().join("sentinel.txt"), b"outside").unwrap();
    let root_dir = TempDir::new().unwrap();
    let target = root_dir.path().join("target.txt");
    let displaced = root_dir.path().join("displaced-preimage.txt");
    let attacker_path = root_dir.path().join("attacker.bin");
    fs::write(&target, b"preimage").unwrap();
    fs::write(&attacker_path, b"attacker").unwrap();
    let mut preimage_handle = fs::File::open(&target).unwrap();
    let attacker_handle = fs::File::open(&attacker_path).unwrap();
    let (adapter, request) = write_adapter_and_request(&root_dir, "present-apply-race");
    let mut session = adapter
        .open_write_session_with_pre_operation_hook(
            request,
            Box::new({
                let target = target.clone();
                move || {
                    fs::rename(&target, displaced)?;
                    fs::rename(attacker_path, target)
                }
            }),
        )
        .unwrap();

    let error = session.apply(b"applied").unwrap_err();

    assert_non_disclosing(error);
    assert_eq!(
        file_identity(&fs::File::open(&target).unwrap()),
        file_identity(&attacker_handle)
    );
    assert_eq!(fs::read(&target).unwrap(), b"attacker");
    assert_handle_bytes(&mut preimage_handle, b"preimage");
    assert_eq!(
        fs::read(outside.path().join("sentinel.txt")).unwrap(),
        b"outside"
    );
    assert_preserved_backup(root_dir.path(), &preimage_handle, b"preimage");
    assert_no_staged_file(root_dir.path());
}

#[test]
#[cfg(feature = "test-seams")]
fn last_moment_absent_apply_race_preserves_attacker() {
    let outside = TempDir::new().unwrap();
    fs::write(outside.path().join("sentinel.txt"), b"outside").unwrap();
    let root_dir = TempDir::new().unwrap();
    let target = root_dir.path().join("target.txt");
    let attacker_path = root_dir.path().join("attacker.bin");
    fs::write(&attacker_path, b"attacker").unwrap();
    let attacker_handle = fs::File::open(&attacker_path).unwrap();
    let (adapter, request) = write_adapter_and_request(&root_dir, "absent-apply-race");
    let mut session = adapter
        .open_write_session_with_pre_operation_hook(
            request,
            Box::new({
                let target = target.clone();
                move || fs::rename(attacker_path, target)
            }),
        )
        .unwrap();

    let error = session.apply(b"applied").unwrap_err();

    assert_non_disclosing(error);
    assert_eq!(
        file_identity(&fs::File::open(&target).unwrap()),
        file_identity(&attacker_handle)
    );
    assert_eq!(fs::read(&target).unwrap(), b"attacker");
    assert_eq!(
        fs::read(outside.path().join("sentinel.txt")).unwrap(),
        b"outside"
    );
    assert_no_staged_file(root_dir.path());
}

#[test]
#[cfg(feature = "test-seams")]
fn last_moment_present_compensation_race_preserves_attacker_and_both_images() {
    let outside = TempDir::new().unwrap();
    fs::write(outside.path().join("sentinel.txt"), b"outside").unwrap();
    let root_dir = TempDir::new().unwrap();
    let target = root_dir.path().join("target.txt");
    let displaced = root_dir.path().join("displaced-applied.txt");
    fs::write(&target, b"preimage").unwrap();
    let mut preimage_handle = fs::File::open(&target).unwrap();
    let (adapter, request) = write_adapter_and_request(&root_dir, "present-compensation-race");
    let attacker_path = root_dir.path().join("attacker.bin");
    let hook_attacker_path = attacker_path.clone();
    let mut session = adapter
        .open_write_session_with_compensation_pre_operation_hook(
            request,
            Box::new({
                let target = target.clone();
                move || {
                    fs::rename(&target, displaced)?;
                    fs::rename(hook_attacker_path, target)
                }
            }),
        )
        .unwrap();
    session.apply(b"applied").unwrap();
    let mut applied_handle = fs::File::open(&target).unwrap();
    fs::write(&attacker_path, b"attacker").unwrap();
    let attacker_handle = fs::File::open(&attacker_path).unwrap();

    let error = session.restore_pre_image_and_verify().unwrap_err();

    assert_non_disclosing(error);
    assert_eq!(
        file_identity(&fs::File::open(&target).unwrap()),
        file_identity(&attacker_handle)
    );
    assert_eq!(fs::read(&target).unwrap(), b"attacker");
    assert_handle_bytes(&mut preimage_handle, b"preimage");
    assert_handle_bytes(&mut applied_handle, b"applied");
    assert_eq!(
        fs::read(outside.path().join("sentinel.txt")).unwrap(),
        b"outside"
    );
    assert_preserved_backup(root_dir.path(), &applied_handle, b"applied");
    assert_no_staged_file(root_dir.path());
}

#[test]
#[cfg(feature = "test-seams")]
fn last_moment_absent_compensation_race_preserves_attacker() {
    let outside = TempDir::new().unwrap();
    fs::write(outside.path().join("sentinel.txt"), b"outside").unwrap();
    let root_dir = TempDir::new().unwrap();
    let target = root_dir.path().join("target.txt");
    let displaced = root_dir.path().join("displaced-applied.txt");
    let (adapter, request) = write_adapter_and_request(&root_dir, "absent-compensation-race");
    let attacker_path = root_dir.path().join("attacker.bin");
    let hook_attacker_path = attacker_path.clone();
    let mut session = adapter
        .open_write_session_with_compensation_pre_operation_hook(
            request,
            Box::new({
                let target = target.clone();
                move || {
                    fs::rename(&target, displaced)?;
                    fs::rename(hook_attacker_path, target)
                }
            }),
        )
        .unwrap();
    session.apply(b"applied").unwrap();
    let mut applied_handle = fs::File::open(&target).unwrap();
    fs::write(&attacker_path, b"attacker").unwrap();
    let attacker_handle = fs::File::open(&attacker_path).unwrap();

    let error = session.restore_pre_image_and_verify().unwrap_err();

    assert_non_disclosing(error);
    assert_eq!(
        file_identity(&fs::File::open(&target).unwrap()),
        file_identity(&attacker_handle)
    );
    assert_eq!(fs::read(&target).unwrap(), b"attacker");
    assert_handle_bytes(&mut applied_handle, b"applied");
    assert_eq!(
        fs::read(outside.path().join("sentinel.txt")).unwrap(),
        b"outside"
    );
    assert_no_staged_file(root_dir.path());
}

fn resolve_and_read(
    adapter: &WindowsCapabilityAdapter,
    task_id: &TaskId,
    capability: CapabilityRef,
) -> Vec<u8> {
    let resolved = adapter
        .resolve(CapabilityRequest {
            task_id: task_id.clone(),
            capability,
        })
        .unwrap();
    adapter
        .read(AuthorizedFileRead {
            task_id: task_id.clone(),
            root_identity: resolved.root_identity,
            relative_components: resolved_relative(resolved.target),
            expected_digest: resolved.content_digest,
        })
        .unwrap()
        .bytes
}

fn task(value: &str) -> TaskId {
    TaskId::new(value).unwrap()
}

fn resolved_relative(target: ResolvedCapabilityTarget) -> RelativePathComponents {
    match target {
        ResolvedCapabilityTarget::Relative(components) => components,
        ResolvedCapabilityTarget::Root => panic!("test requires a relative capability target"),
    }
}

fn root(value: &str) -> CapabilityRootIdentity {
    CapabilityRootIdentity::new(value).unwrap()
}

fn components(path: &str) -> RelativePathComponents {
    RelativePathComponents::new(path.split('/').map(str::to_owned).collect()).unwrap()
}

fn directory_names(path: &Path) -> Vec<String> {
    let mut names = fs::read_dir(path)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .collect::<Vec<_>>();
    names.sort();
    names
}

#[cfg(feature = "test-seams")]
fn write_adapter_and_request(
    root_dir: &TempDir,
    execution_id: &str,
) -> (WindowsCapabilityAdapter, OpenFileWriteSession) {
    let owner = task("task-1");
    let root_identity = root("worktree-root");
    let adapter = WindowsCapabilityAdapter::new(vec![CapabilityRegistration::worktree(
        root_identity.clone(),
        owner.clone(),
        root_dir.path(),
    )
    .unwrap()])
    .unwrap();
    let request = OpenFileWriteSession::new(
        ToolExecutionId::new(execution_id).unwrap(),
        owner.clone(),
        root_identity,
        components("target.txt"),
        None,
        LeaseClaim::new(
            owner,
            RunId::new("run-1").unwrap(),
            FencingToken::new(7).unwrap(),
        ),
    )
    .unwrap();
    (adapter, request)
}

#[cfg(feature = "test-seams")]
fn file_identity(file: &fs::File) -> (u64, [u8; 16]) {
    let mut info = FILE_ID_INFO::default();
    // SAFETY: `info` is a correctly sized writable output buffer.
    let success = unsafe {
        GetFileInformationByHandleEx(
            file.as_raw_handle() as HANDLE,
            FileIdInfo,
            std::ptr::from_mut(&mut info).cast(),
            std::mem::size_of::<FILE_ID_INFO>() as u32,
        )
    };
    assert_ne!(success, 0);
    (info.VolumeSerialNumber, info.FileId.Identifier)
}

#[cfg(feature = "test-seams")]
fn assert_handle_bytes(file: &mut fs::File, expected: &[u8]) {
    file.seek(SeekFrom::Start(0)).unwrap();
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes).unwrap();
    assert_eq!(bytes, expected);
}

#[cfg(feature = "test-seams")]
fn assert_no_staged_file(path: &Path) {
    assert!(
        directory_names(path)
            .iter()
            .all(|name| !name.starts_with(".lat-write-") || name.ends_with(".bak")),
        "only a preserved exact backup may remain after a failed operation"
    );
}

#[cfg(feature = "test-seams")]
fn assert_preserved_backup(path: &Path, expected: &fs::File, bytes: &[u8]) {
    let backup = directory_names(path)
        .into_iter()
        .find(|name| name.starts_with(".lat-write-") && name.ends_with(".bak"))
        .expect("the exact displaced target remains preserved after restore fails");
    let backup_path = path.join(backup);
    let backup = fs::File::open(&backup_path).unwrap();
    assert_eq!(file_identity(&backup), file_identity(expected));
    assert_eq!(fs::read(backup_path).unwrap(), bytes);
}

fn assert_non_disclosing(error: PortError) {
    assert_eq!(
        error.safe_classification(),
        SafeErrorClassification::PermissionDenied
    );
    assert_eq!(error.retryability(), Retryability::NonRetryable);
    let outward = error.to_string();
    assert_eq!(outward, "port failure (PermissionDenied, NonRetryable)");
    assert!(!outward.contains("sentinel"));
    assert!(!outward.contains("secret"));
    assert!(!outward.contains("seven"));
}

fn create_junction(target: &Path, link: &Path) {
    let output = Command::new("cmd.exe")
        .args(["/C", "mklink", "/J"])
        .arg(link)
        .arg(target)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}
