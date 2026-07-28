use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::Read;
use std::path::{Path, PathBuf};

use git2::{DiffLineType, DiffOptions, ObjectType, Oid, Patch};
use local_agent_terminal_application::{
    AuthorizedGitDiff, AuthorizedGitStatus, GitDiffResult, GitStatusResult, PortError,
    Retryability, SafeErrorClassification, StructuredGit,
};
use local_agent_terminal_domain::{CapabilityRef, GitObjectId, Sha256Digest};
use sha2::{Digest, Sha256};

use crate::{hazards, paths, GitStructuredTools};

const MAX_OUTPUT_BYTES: usize = 64 * 1024;
const MAX_INDEX_BYTES: u64 = 8 * 1024 * 1024;
const MAX_CONFIG_BYTES: u64 = 64 * 1024;
const MAX_CAPTURE_ENTRIES: usize = 4_096;
const MAX_CAPTURE_PATH_BYTES: usize = 256 * 1024;
const MAX_FILE_BYTES: u64 = 1024 * 1024;
const MAX_CAPTURE_BYTES: u64 = 16 * 1024 * 1024;
const MAX_DIFF_HUNKS: usize = 8_192;
const MAX_DIFF_LINES: usize = 65_536;

impl StructuredGit for GitStructuredTools {
    fn status(&self, request: AuthorizedGitStatus) -> Result<GitStatusResult, PortError> {
        let registration =
            self.authorize(&request.task_id, &request.worktree, &request.root_identity)?;
        let (repository, config) =
            paths::open_for_locator(&registration.locator).map_err(|_| denied())?;
        verify_revision(&repository, &registration.revision)?;
        self.reject_hazards(&repository, &config)?;
        let before = capture_repository(&repository)?;
        self.run_before_generation_hook();
        self.reject_hazards(&repository, &config)?;
        let captured = capture_repository(&repository)?;
        if captured != before {
            return Err(denied());
        }
        let output = bounded_status(&captured)?;
        self.run_snapshot_hook();
        self.reject_hazards(&repository, &config)?;
        if capture_repository(&repository)? != captured {
            return Err(denied());
        }
        self.status_result(request, registration, output)
    }

    fn diff(&self, request: AuthorizedGitDiff) -> Result<GitDiffResult, PortError> {
        let registration =
            self.authorize(&request.task_id, &request.worktree, &request.root_identity)?;
        let (repository, config) =
            paths::open_for_locator(&registration.locator).map_err(|_| denied())?;
        verify_revision(&repository, &registration.revision)?;
        self.reject_hazards(&repository, &config)?;
        let before = capture_repository(&repository)?;
        self.run_before_generation_hook();
        self.reject_hazards(&repository, &config)?;
        let captured = capture_repository(&repository)?;
        if captured != before {
            return Err(denied());
        }
        let output = bounded_diff(&captured)?;
        self.run_snapshot_hook();
        self.reject_hazards(&repository, &config)?;
        if capture_repository(&repository)? != captured {
            return Err(denied());
        }
        self.diff_result(request, registration, output)
    }
}

impl GitStructuredTools {
    fn authorize<'a>(
        &'a self,
        task_id: &local_agent_terminal_domain::TaskId,
        capability: &CapabilityRef,
        root_identity: &local_agent_terminal_application::CapabilityRootIdentity,
    ) -> Result<&'a crate::GitWorktreeRegistration, PortError> {
        if !matches!(capability, CapabilityRef::Worktree(worktree) if worktree.task_id() == task_id && worktree.path() == ".")
        {
            return Err(denied());
        }
        self.registrations
            .iter()
            .find(|registration| {
                &registration.task_id == task_id && &registration.root_identity == root_identity
            })
            .ok_or_else(denied)
    }

    fn run_snapshot_hook(&self) {
        #[cfg(feature = "test-seams")]
        if let Some(hook) = &self.snapshot_hook {
            hook();
        }
    }

    fn run_before_generation_hook(&self) {
        #[cfg(feature = "test-seams")]
        if let Some(hook) = &self.before_generation_hook {
            hook();
        }
    }

    fn reject_hazards(
        &self,
        repository: &git2::Repository,
        config: &git2::Config,
    ) -> Result<(), PortError> {
        if !hazards::scan(repository, config)?.is_empty()
            || hazards::structured_attributes_present(repository)?
            || hostile_attributes(repository)
        {
            return Err(denied());
        }
        Ok(())
    }

    fn status_result(
        &self,
        request: AuthorizedGitStatus,
        registration: &crate::GitWorktreeRegistration,
        output: BoundedOutput,
    ) -> Result<GitStatusResult, PortError> {
        let digest = digest(&output.bytes);
        Ok(GitStatusResult {
            digest,
            bytes: output.bytes,
            repository_id: registration.locator.repository_id.clone(),
            revision: registration.revision.clone(),
            path_scope: request.worktree,
            truncated: output.truncated,
        })
    }

    fn diff_result(
        &self,
        request: AuthorizedGitDiff,
        registration: &crate::GitWorktreeRegistration,
        output: BoundedOutput,
    ) -> Result<GitDiffResult, PortError> {
        let digest = digest(&output.bytes);
        Ok(GitDiffResult {
            digest,
            bytes: output.bytes,
            repository_id: registration.locator.repository_id.clone(),
            revision: registration.revision.clone(),
            path_scope: request.worktree,
            truncated: output.truncated,
        })
    }
}

struct BoundedOutput {
    bytes: Vec<u8>,
    truncated: bool,
}

#[derive(PartialEq, Eq)]
struct CapturedRepository {
    head: GitObjectId,
    index_digest: Sha256Digest,
    config_digest: Sha256Digest,
    state: git2::RepositoryState,
    head_entries: BTreeMap<Vec<u8>, CapturedTreeEntry>,
    index_entries: BTreeMap<Vec<u8>, CapturedFile>,
    worktree_entries: BTreeMap<Vec<u8>, CapturedFile>,
}

#[derive(PartialEq, Eq)]
struct CapturedTreeEntry {
    oid: Oid,
    mode: u32,
    bytes: Vec<u8>,
}

#[derive(PartialEq, Eq)]
struct CapturedFile {
    oid: Option<Oid>,
    mode: u32,
    bytes: Vec<u8>,
}

fn capture_repository(repository: &git2::Repository) -> Result<CapturedRepository, PortError> {
    let head = revision(repository)?;
    let index_path = repository
        .index()
        .map_err(|_| denied())?
        .path()
        .ok_or_else(denied)?
        .to_owned();
    let (_index_lock, index_bytes) = open_and_read_bounded(&index_path, MAX_INDEX_BYTES)?;
    let (_config_lock, config_bytes) =
        open_and_read_bounded(&repository.path().join("config"), MAX_CONFIG_BYTES)?;
    let head_entries = capture_head(repository)?;
    let index_entries = capture_index(repository)?;
    let worktree_entries = capture_worktree(repository)?;
    Ok(CapturedRepository {
        head,
        index_digest: digest(&index_bytes),
        config_digest: digest(&config_bytes),
        state: repository.state(),
        head_entries,
        index_entries,
        worktree_entries,
    })
}

fn open_and_read_bounded(path: &Path, max_bytes: u64) -> Result<(File, Vec<u8>), PortError> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        const FILE_SHARE_READ: u32 = 0x0000_0001;
        const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
        options
            .share_mode(FILE_SHARE_READ)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }
    let mut file = options.open(path).map_err(|_| denied())?;
    let metadata = file.metadata().map_err(|_| denied())?;
    if !metadata.is_file() || metadata.len() > max_bytes {
        return Err(denied());
    }
    let capacity = usize::try_from(metadata.len()).map_err(|_| denied())?;
    let mut bytes = Vec::with_capacity(capacity);
    file.by_ref()
        .take(max_bytes.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|_| denied())?;
    if u64::try_from(bytes.len()).map_err(|_| denied())? != metadata.len()
        || file.metadata().map_err(|_| denied())?.len() != metadata.len()
    {
        return Err(denied());
    }
    Ok((file, bytes))
}

fn capture_head(
    repository: &git2::Repository,
) -> Result<BTreeMap<Vec<u8>, CapturedTreeEntry>, PortError> {
    let tree = repository
        .head()
        .map_err(|_| denied())?
        .peel_to_tree()
        .map_err(|_| denied())?;
    let mut entries = BTreeMap::new();
    let mut count = 0usize;
    let mut path_bytes = 0usize;
    let mut total_bytes = 0u64;
    let mut invalid = false;
    let odb = repository.odb().map_err(|_| denied())?;
    let walked = tree.walk(git2::TreeWalkMode::PreOrder, |root, entry| {
        count = count.saturating_add(1);
        path_bytes = path_bytes
            .saturating_add(root.len())
            .saturating_add(entry.name_bytes().len());
        if count > MAX_CAPTURE_ENTRIES || path_bytes > MAX_CAPTURE_PATH_BYTES {
            invalid = true;
            return git2::TreeWalkResult::Abort;
        }
        if entry.kind() == Some(ObjectType::Commit) {
            invalid = true;
            return git2::TreeWalkResult::Abort;
        }
        if entry.kind() == Some(ObjectType::Blob) {
            let mut path = root.as_bytes().to_vec();
            path.extend_from_slice(entry.name_bytes());
            let mode = u32::try_from(entry.filemode()).unwrap_or_default();
            let header = odb.read_header(entry.id());
            let Ok((size, kind)) = header else {
                invalid = true;
                return git2::TreeWalkResult::Abort;
            };
            let size = u64::try_from(size).unwrap_or(u64::MAX);
            total_bytes = total_bytes.saturating_add(size);
            if hazardous_path(&path)
                || !valid_blob_mode(mode)
                || kind != ObjectType::Blob
                || size > MAX_FILE_BYTES
                || total_bytes > MAX_CAPTURE_BYTES
            {
                invalid = true;
                return git2::TreeWalkResult::Abort;
            }
            let Ok(blob) = repository.find_blob(entry.id()) else {
                invalid = true;
                return git2::TreeWalkResult::Abort;
            };
            let bytes = blob.content().to_vec();
            if u64::try_from(bytes.len()).ok() != Some(size) || lfs_pointer(&bytes) {
                invalid = true;
                return git2::TreeWalkResult::Abort;
            }
            entries.insert(
                path,
                CapturedTreeEntry {
                    oid: entry.id(),
                    mode,
                    bytes,
                },
            );
        }
        git2::TreeWalkResult::Ok
    });
    if invalid {
        return Err(denied());
    }
    walked.map_err(|_| denied())?;
    Ok(entries)
}

fn capture_index(
    repository: &git2::Repository,
) -> Result<BTreeMap<Vec<u8>, CapturedFile>, PortError> {
    let index = repository.index().map_err(|_| denied())?;
    if index.has_conflicts() || index.len() > MAX_CAPTURE_ENTRIES {
        return Err(denied());
    }
    let odb = repository.odb().map_err(|_| denied())?;
    let mut entries = BTreeMap::new();
    let mut path_bytes = 0usize;
    let mut total_bytes = 0u64;
    for entry in index.iter() {
        path_bytes = path_bytes.saturating_add(entry.path.len());
        if path_bytes > MAX_CAPTURE_PATH_BYTES
            || entry.flags & 0x3000 != 0
            || hazardous_path(&entry.path)
            || !valid_blob_mode(entry.mode)
        {
            return Err(denied());
        }
        let (size, kind) = odb.read_header(entry.id).map_err(|_| denied())?;
        let size = u64::try_from(size).map_err(|_| denied())?;
        total_bytes = total_bytes.saturating_add(size);
        if kind != ObjectType::Blob || size > MAX_FILE_BYTES || total_bytes > MAX_CAPTURE_BYTES {
            return Err(denied());
        }
        let blob = repository.find_blob(entry.id).map_err(|_| denied())?;
        let bytes = blob.content().to_vec();
        if lfs_pointer(&bytes) {
            return Err(denied());
        }
        entries.insert(
            entry.path.clone(),
            CapturedFile {
                oid: Some(entry.id),
                mode: entry.mode,
                bytes,
            },
        );
    }
    Ok(entries)
}

fn capture_worktree(
    repository: &git2::Repository,
) -> Result<BTreeMap<Vec<u8>, CapturedFile>, PortError> {
    let workdir = repository.workdir().ok_or_else(denied)?;
    let mut pending = vec![(workdir.to_owned(), PathBuf::new())];
    let mut entries = BTreeMap::new();
    let mut count = 0usize;
    let mut path_bytes = 0usize;
    let mut total_bytes = 0u64;
    while let Some((directory, relative)) = pending.pop() {
        for entry in fs::read_dir(&directory).map_err(|_| denied())? {
            let entry = entry.map_err(|_| denied())?;
            let name = entry.file_name();
            if relative.as_os_str().is_empty() && name == ".git" {
                continue;
            }
            count = count.saturating_add(1);
            let child_relative = relative.join(&name);
            let path = portable_path(&child_relative)?;
            path_bytes = path_bytes.saturating_add(path.len());
            if count > MAX_CAPTURE_ENTRIES
                || path_bytes > MAX_CAPTURE_PATH_BYTES
                || hazardous_path(&path)
            {
                return Err(denied());
            }
            let metadata = fs::symlink_metadata(entry.path()).map_err(|_| denied())?;
            if metadata.file_type().is_symlink() || is_reparse_point(&metadata) {
                return Err(denied());
            }
            if metadata.is_dir() {
                pending.push((entry.path(), child_relative));
            } else if metadata.is_file() {
                let (_lock, bytes) = open_and_read_bounded(&entry.path(), MAX_FILE_BYTES)?;
                total_bytes =
                    total_bytes.saturating_add(u64::try_from(bytes.len()).map_err(|_| denied())?);
                if total_bytes > MAX_CAPTURE_BYTES || lfs_pointer(&bytes) {
                    return Err(denied());
                }
                entries.insert(
                    path,
                    CapturedFile {
                        oid: None,
                        mode: 0o100644,
                        bytes,
                    },
                );
            } else {
                return Err(denied());
            }
        }
    }
    Ok(entries)
}

fn bounded_status(captured: &CapturedRepository) -> Result<BoundedOutput, PortError> {
    let mut output = BoundedOutput {
        bytes: Vec::new(),
        truncated: false,
    };
    for (path, flags) in status_records(captured) {
        append_bounded(&mut output, path);
        append_bounded(&mut output, b"\t");
        append_bounded(&mut output, format!("{flags:08x}\n").as_bytes());
        if output.truncated {
            break;
        }
    }
    Ok(output)
}

fn status_records(captured: &CapturedRepository) -> Vec<(&[u8], u32)> {
    let paths = captured
        .head_entries
        .keys()
        .chain(captured.index_entries.keys())
        .chain(captured.worktree_entries.keys())
        .collect::<BTreeSet<_>>();
    paths
        .into_iter()
        .filter_map(|path| {
            let mut flags = 0u32;
            match (
                captured.head_entries.get(path),
                captured.index_entries.get(path),
            ) {
                (None, Some(_)) => flags |= git2::Status::INDEX_NEW.bits(),
                (Some(_), None) => flags |= git2::Status::INDEX_DELETED.bits(),
                (Some(head), Some(index))
                    if index.oid.as_ref() != Some(&head.oid) || head.mode != index.mode =>
                {
                    flags |= git2::Status::INDEX_MODIFIED.bits();
                }
                _ => {}
            }
            match (
                captured.index_entries.get(path),
                captured.worktree_entries.get(path),
            ) {
                (None, Some(_)) => flags |= git2::Status::WT_NEW.bits(),
                (Some(_), None) => flags |= git2::Status::WT_DELETED.bits(),
                (Some(index), Some(worktree))
                    if index.bytes != worktree.bytes || index.mode != worktree.mode =>
                {
                    flags |= git2::Status::WT_MODIFIED.bits();
                }
                _ => {}
            }
            (flags != 0).then_some((path.as_slice(), flags))
        })
        .collect()
}

fn bounded_diff(captured: &CapturedRepository) -> Result<BoundedOutput, PortError> {
    let mut options = DiffOptions::new();
    options.context_lines(3);
    let mut output = BoundedOutput {
        bytes: Vec::new(),
        truncated: false,
    };
    let mut hunks = 0usize;
    let mut lines = 0usize;
    for (path, index) in &captured.index_entries {
        let Some(worktree) = captured.worktree_entries.get(path) else {
            append_patch(
                &mut output,
                &mut hunks,
                &mut lines,
                path,
                &index.bytes,
                &[],
                &mut options,
            )?;
            continue;
        };
        if index.bytes != worktree.bytes {
            append_patch(
                &mut output,
                &mut hunks,
                &mut lines,
                path,
                &index.bytes,
                &worktree.bytes,
                &mut options,
            )?;
        }
        if output.truncated {
            break;
        }
    }
    Ok(output)
}

fn append_patch(
    output: &mut BoundedOutput,
    hunks: &mut usize,
    lines: &mut usize,
    path: &[u8],
    old_bytes: &[u8],
    new_bytes: &[u8],
    options: &mut DiffOptions,
) -> Result<(), PortError> {
    let path = std::str::from_utf8(path).map_err(|_| denied())?;
    let path = Path::new(path);
    let mut patch =
        Patch::from_buffers(old_bytes, Some(path), new_bytes, Some(path), Some(options))
            .map_err(|_| denied())?;
    let printed = patch.print(&mut |_delta, _hunk, line| {
        if line.origin_value() == DiffLineType::HunkHeader {
            *hunks = hunks.saturating_add(1);
        } else if !matches!(line.origin_value(), DiffLineType::FileHeader) {
            *lines = lines.saturating_add(1);
        }
        if *hunks > MAX_DIFF_HUNKS || *lines > MAX_DIFF_LINES {
            return false;
        }
        if output.bytes.len().saturating_add(line.content().len()) > MAX_OUTPUT_BYTES {
            output.truncated = true;
            return false;
        }
        output.bytes.extend_from_slice(line.content());
        true
    });
    if printed.is_err() && !output.truncated {
        return Err(denied());
    }
    if *hunks > MAX_DIFF_HUNKS || *lines > MAX_DIFF_LINES {
        return Err(denied());
    }
    Ok(())
}

fn portable_path(path: &Path) -> Result<Vec<u8>, PortError> {
    let value = path.to_str().ok_or_else(denied)?.replace('\\', "/");
    if value.is_empty() || value.contains('\0') {
        return Err(denied());
    }
    Ok(value.into_bytes())
}

fn hazardous_path(path: &[u8]) -> bool {
    let leaf = path.rsplit(|byte| *byte == b'/').next().unwrap_or(path);
    leaf.eq_ignore_ascii_case(b".gitattributes")
        || leaf.eq_ignore_ascii_case(b".gitmodules")
        || leaf.eq_ignore_ascii_case(b".lfsconfig")
        || leaf.eq_ignore_ascii_case(b".git")
        || leaf.first() == Some(&b'@')
        || leaf.ends_with(b".rsp")
}

fn lfs_pointer(bytes: &[u8]) -> bool {
    bytes.starts_with(b"version https://git-lfs.github.com/spec/v1")
}

fn valid_blob_mode(mode: u32) -> bool {
    matches!(mode, 0o100644 | 0o100755)
}

#[cfg(windows)]
fn is_reparse_point(metadata: &fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
    metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

#[cfg(not(windows))]
fn is_reparse_point(_metadata: &fs::Metadata) -> bool {
    false
}

fn hostile_attributes(repository: &git2::Repository) -> bool {
    let Some(workdir) = repository.workdir() else {
        return true;
    };
    [".gitattributes", ".gitmodules", ".lfsconfig"]
        .into_iter()
        .any(|name| fs::symlink_metadata(workdir.join(name)).is_ok())
}

fn append_bounded(output: &mut BoundedOutput, bytes: &[u8]) {
    if output.bytes.len().saturating_add(bytes.len()) > MAX_OUTPUT_BYTES {
        output.truncated = true;
        return;
    }
    output.bytes.extend_from_slice(bytes);
}

fn revision(repository: &git2::Repository) -> Result<GitObjectId, PortError> {
    let oid = repository
        .head()
        .map_err(|_| denied())?
        .target()
        .ok_or_else(denied)?;
    GitObjectId::new(oid.to_string()).map_err(|_| denied())
}

fn verify_revision(repository: &git2::Repository, expected: &GitObjectId) -> Result<(), PortError> {
    if revision(repository).as_ref() != Ok(expected) {
        return Err(denied());
    }
    Ok(())
}

fn digest(bytes: &[u8]) -> Sha256Digest {
    Sha256Digest::new(format!("sha256:{:x}", Sha256::digest(bytes)))
        .expect("SHA-256 formatting is valid")
}

fn denied() -> PortError {
    PortError::failure(
        SafeErrorClassification::PermissionDenied,
        Retryability::NonRetryable,
    )
}
