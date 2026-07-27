use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

#[cfg(test)]
use git2::WorktreeAddOptions;
use git2::{Reference, Repository, Tree, Worktree};
use local_agent_terminal_application::PortError;

use crate::paths;
#[cfg(feature = "test-seams")]
use crate::GitRepositoryGateway;

pub(crate) struct AddedWorktree {
    pub(crate) worktree: Worktree,
    pub(crate) target_guard: paths::DirectoryGuard,
}

pub(crate) fn add(
    repository: &Repository,
    name: &str,
    path: &Path,
    reference: &Reference<'_>,
    parent_guard: &paths::DirectoryGuard,
    #[cfg(feature = "test-seams")] gateway: &GitRepositoryGateway,
) -> Result<AddedWorktree, PortError> {
    if !reference.is_branch() || branch_is_checked_out(reference) {
        return Err(paths::conflict());
    }
    let reference_name = reference.name().map_err(|_| paths::integrity())?;
    let metadata_parent = repository.commondir().join("worktrees");
    create_metadata_parent(&metadata_parent)?;
    let metadata = metadata_parent.join(name);
    fs::create_dir(&metadata).map_err(map_create_error)?;
    let metadata = pretty_directory(&metadata)?;
    let target_guard = paths::DirectoryGuard::create_child(parent_guard, path)?;
    let target = pretty_directory(path)?;
    let common = pretty_directory(repository.commondir())?;

    write_new(&metadata.join("locked"), b"")?;
    target_guard.write_child(
        &path.join(".git"),
        format!("gitdir: {}\n", display_directory(&metadata)?).as_bytes(),
    )?;
    write_new(
        &metadata.join("commondir"),
        format!("{}\n", display_directory(&common)?).as_bytes(),
    )?;
    write_new(
        &metadata.join("gitdir"),
        format!("{}.git\n", display_directory(&target)?).as_bytes(),
    )?;
    write_new(
        &metadata.join("HEAD"),
        format!("ref: {reference_name}\n").as_bytes(),
    )?;

    let tree = reference.peel_to_tree().map_err(paths::map_git_error)?;
    let mut index = git2::Index::open_ext(&metadata.join("index"), repository.object_format())
        .map_err(paths::map_git_error)?;
    index.read_tree(&tree).map_err(paths::map_git_error)?;
    index.write().map_err(paths::map_git_error)?;
    #[cfg(feature = "test-seams")]
    pause_during_checkout(gateway);
    materialize_tree(repository, &tree, &target_guard, path)?;
    target_guard.verify()?;
    let worktree = repository
        .find_worktree(name)
        .map_err(paths::map_git_error)?;
    Ok(AddedWorktree {
        worktree,
        target_guard,
    })
}

#[cfg(feature = "test-seams")]
fn pause_during_checkout(gateway: &GitRepositoryGateway) {
    if let Some(barrier) = &gateway.test_hooks.during_checkout {
        barrier.wait();
        barrier.wait();
    }
}

fn materialize_tree(
    repository: &Repository,
    tree: &Tree<'_>,
    parent_guard: &paths::DirectoryGuard,
    parent_path: &Path,
) -> Result<(), PortError> {
    for entry in tree {
        let name = entry.name().map_err(|_| paths::unavailable())?;
        if !paths::valid_component(name) || name.eq_ignore_ascii_case(".git") {
            return Err(paths::unavailable());
        }
        let path = parent_path.join(name);
        match entry.filemode() {
            0o040000 => {
                let child_tree = repository
                    .find_tree(entry.id())
                    .map_err(paths::map_git_error)?;
                let child_guard = paths::DirectoryGuard::create_child(parent_guard, &path)?;
                materialize_tree(repository, &child_tree, &child_guard, &path)?;
                child_guard.verify()?;
            }
            0o100644 | 0o100755 => {
                let blob = repository
                    .find_blob(entry.id())
                    .map_err(paths::map_git_error)?;
                parent_guard.write_child(&path, blob.content())?;
            }
            _ => return Err(paths::unavailable()),
        }
    }
    Ok(())
}

fn create_metadata_parent(path: &Path) -> Result<(), PortError> {
    match fs::create_dir(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            paths::canonical_directory(path).map(|_| ())
        }
        Err(error) => Err(map_create_error(error)),
    }
}

fn write_new(path: &Path, bytes: &[u8]) -> Result<(), PortError> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(map_create_error)?;
    file.write_all(bytes).map_err(|_| paths::permission())
}

fn pretty_directory(path: &Path) -> Result<PathBuf, PortError> {
    paths::canonical_directory(path)
}

fn display_directory(path: &Path) -> Result<String, PortError> {
    let mut path = path.to_str().ok_or_else(paths::invalid)?.replace('\\', "/");
    if let Some(without_prefix) = path.strip_prefix("//?/") {
        path = without_prefix.to_owned();
    }
    if !path.ends_with('/') {
        path.push('/');
    }
    Ok(path)
}

fn map_create_error(error: std::io::Error) -> PortError {
    match error.kind() {
        std::io::ErrorKind::AlreadyExists => paths::conflict(),
        std::io::ErrorKind::PermissionDenied => paths::permission(),
        _ => paths::unavailable(),
    }
}

fn branch_is_checked_out(reference: &Reference<'_>) -> bool {
    unsafe extern "C" {
        fn git_branch_is_checked_out(branch: *const libgit2_sys::git_reference) -> i32;
    }
    // SAFETY: the reviewed libgit2 1.9.3 symbol only reads the live reference.
    unsafe { git_branch_is_checked_out(reference.raw()) != 0 }
}

#[cfg(windows)]
pub(crate) mod windows_directory {
    use std::ffi::{OsStr, OsString};
    use std::fs::File;
    use std::mem::size_of;
    use std::os::windows::ffi::{OsStrExt, OsStringExt};
    use std::os::windows::io::{AsRawHandle, FromRawHandle};
    use std::path::{Path, PathBuf};
    use std::ptr;

    use local_agent_terminal_application::PortError;
    use windows_sys::Wdk::Foundation::OBJECT_ATTRIBUTES;
    use windows_sys::Wdk::Storage::FileSystem::{
        FileDirectoryInformation, NtCreateFile, NtQueryDirectoryFile, FILE_CREATE,
        FILE_DIRECTORY_FILE, FILE_DIRECTORY_INFORMATION, FILE_NON_DIRECTORY_FILE, FILE_OPEN,
        FILE_OPEN_REPARSE_POINT, FILE_SYNCHRONOUS_IO_NONALERT,
    };
    use windows_sys::Win32::Foundation::{
        HANDLE, OBJ_CASE_INSENSITIVE, STATUS_BUFFER_OVERFLOW, STATUS_NO_MORE_FILES, STATUS_SUCCESS,
        UNICODE_STRING,
    };
    use windows_sys::Win32::Storage::FileSystem::{
        FileAttributeTagInfo, FileDispositionInfo, FileIdInfo, FileRenameInfo,
        GetFileInformationByHandleEx, GetFinalPathNameByHandleW, SetFileInformationByHandle,
        DELETE, FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_NORMAL, FILE_ATTRIBUTE_REPARSE_POINT,
        FILE_ATTRIBUTE_TAG_INFO, FILE_DISPOSITION_INFO, FILE_GENERIC_READ, FILE_GENERIC_WRITE,
        FILE_ID_INFO, FILE_READ_ATTRIBUTES, FILE_RENAME_INFO, FILE_SHARE_READ, FILE_SHARE_WRITE,
        SYNCHRONIZE,
    };
    use windows_sys::Win32::System::IO::IO_STATUS_BLOCK;

    use crate::paths;

    #[derive(Clone, Copy, PartialEq, Eq)]
    pub(crate) struct DirectoryIdentity {
        volume: u64,
        file_id: [u8; 16],
    }

    pub(crate) fn create(parent: &File, leaf: &OsStr) -> Result<File, PortError> {
        open_relative(parent, leaf, FILE_CREATE, false, FILE_DIRECTORY_FILE)
    }

    pub(crate) fn create_file(parent: &File, leaf: &OsStr) -> Result<File, PortError> {
        open_relative(parent, leaf, FILE_CREATE, false, FILE_NON_DIRECTORY_FILE)
    }

    pub(crate) fn open_for_rename(parent: &File, leaf: &OsStr) -> Result<File, PortError> {
        open_relative(parent, leaf, FILE_OPEN, true, FILE_DIRECTORY_FILE)
    }

    pub(crate) fn remove_tree(root: &File) -> Result<(), PortError> {
        if has_reparse_tag(root)? {
            return Err(paths::conflict());
        }
        // ponytail: restart-scans after each deletion (O(n²)); retain a native
        // enumeration cursor if managed worktrees become large enough to matter.
        while let Some(entry) = next_directory_entry(root)? {
            remove_child(root, entry)?;
        }
        mark_for_deletion(root)
    }

    fn open_relative(
        parent: &File,
        leaf: &OsStr,
        disposition: u32,
        delete_access: bool,
        kind: u32,
    ) -> Result<File, PortError> {
        let mut name = leaf.encode_wide().collect::<Vec<_>>();
        let byte_length = name
            .len()
            .checked_mul(size_of::<u16>())
            .and_then(|length| u16::try_from(length).ok())
            .ok_or_else(paths::invalid)?;
        let unicode_name = UNICODE_STRING {
            Length: byte_length,
            MaximumLength: byte_length,
            Buffer: name.as_mut_ptr(),
        };
        let attributes = OBJECT_ATTRIBUTES {
            Length: size_of::<OBJECT_ATTRIBUTES>() as u32,
            RootDirectory: parent.as_raw_handle() as HANDLE,
            ObjectName: &unicode_name,
            Attributes: OBJ_CASE_INSENSITIVE,
            SecurityDescriptor: ptr::null(),
            SecurityQualityOfService: ptr::null(),
        };
        let mut handle: HANDLE = ptr::null_mut();
        let mut io_status = IO_STATUS_BLOCK::default();
        let desired_access = FILE_GENERIC_READ
            | FILE_READ_ATTRIBUTES
            | SYNCHRONIZE
            | if delete_access {
                DELETE
            } else {
                FILE_GENERIC_WRITE
            };
        // SAFETY: all pointers reference initialized values for the duration of
        // the call. The returned owned handle is converted to `File` once.
        let status = unsafe {
            NtCreateFile(
                &mut handle,
                desired_access,
                &attributes,
                &mut io_status,
                ptr::null(),
                FILE_ATTRIBUTE_NORMAL,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                disposition,
                kind | FILE_OPEN_REPARSE_POINT | FILE_SYNCHRONOUS_IO_NONALERT,
                ptr::null(),
                0,
            )
        };
        if status != STATUS_SUCCESS || handle.is_null() {
            return Err(paths::conflict());
        }
        // SAFETY: successful `NtCreateFile` returned one uniquely owned handle.
        Ok(unsafe { File::from_raw_handle(handle) })
    }

    pub(crate) fn identity(handle: &File) -> Result<DirectoryIdentity, PortError> {
        let mut info = FILE_ID_INFO::default();
        // SAFETY: `info` is a correctly sized writable output buffer.
        let success = unsafe {
            GetFileInformationByHandleEx(
                handle.as_raw_handle() as HANDLE,
                FileIdInfo,
                ptr::from_mut(&mut info).cast(),
                size_of::<FILE_ID_INFO>() as u32,
            )
        };
        if success == 0 {
            return Err(paths::permission());
        }
        Ok(DirectoryIdentity {
            volume: info.VolumeSerialNumber,
            file_id: info.FileId.Identifier,
        })
    }

    pub(crate) fn verify(
        handle: &File,
        path: &Path,
        expected: DirectoryIdentity,
    ) -> Result<(), PortError> {
        if identity(handle)? != expected
            || has_reparse_tag(handle)?
            || comparable(&final_path(handle)?) != comparable(path)
        {
            return Err(paths::conflict());
        }
        Ok(())
    }

    fn has_reparse_tag(handle: &File) -> Result<bool, PortError> {
        let mut info = FILE_ATTRIBUTE_TAG_INFO::default();
        // SAFETY: `info` is a correctly sized writable output buffer.
        let success = unsafe {
            GetFileInformationByHandleEx(
                handle.as_raw_handle() as HANDLE,
                FileAttributeTagInfo,
                ptr::from_mut(&mut info).cast(),
                size_of::<FILE_ATTRIBUTE_TAG_INFO>() as u32,
            )
        };
        if success == 0 {
            return Err(paths::permission());
        }
        Ok(info.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0)
    }

    struct DirectoryEntry {
        leaf: OsString,
        is_directory: bool,
    }

    fn next_directory_entry(root: &File) -> Result<Option<DirectoryEntry>, PortError> {
        let mut buffer = vec![0_u8; 64 * 1024];
        let mut io_status = IO_STATUS_BLOCK::default();
        // SAFETY: `root` is an open directory handle, `io_status` and `buffer`
        // are initialized writable storage for this synchronous call, and null
        // callback/filter pointers request the documented default enumeration.
        let status = unsafe {
            NtQueryDirectoryFile(
                root.as_raw_handle() as HANDLE,
                ptr::null_mut(),
                None,
                ptr::null(),
                &mut io_status,
                buffer.as_mut_ptr().cast(),
                buffer.len() as u32,
                FileDirectoryInformation,
                false,
                ptr::null(),
                true,
            )
        };
        if status == STATUS_NO_MORE_FILES {
            return Ok(None);
        }
        if status != STATUS_SUCCESS && status != STATUS_BUFFER_OVERFLOW {
            return Err(paths::conflict());
        }
        let name_offset = std::mem::offset_of!(FILE_DIRECTORY_INFORMATION, FileName);
        if io_status.Information < name_offset {
            return Err(paths::conflict());
        }
        let returned = io_status.Information.min(buffer.len());
        let mut offset = 0;
        while offset < returned {
            if returned - offset < name_offset {
                return Err(paths::conflict());
            }
            // SAFETY: `offset` was bounded by the byte count returned for this
            // buffer and the fixed header length was checked immediately above.
            let entry = unsafe {
                buffer
                    .as_ptr()
                    .add(offset)
                    .cast::<FILE_DIRECTORY_INFORMATION>()
                    .as_ref()
            }
            .ok_or_else(paths::conflict)?;
            let name_bytes =
                usize::try_from(entry.FileNameLength).map_err(|_| paths::conflict())?;
            if name_bytes == 0
                || name_bytes % size_of::<u16>() != 0
                || name_bytes > returned - offset - name_offset
            {
                return Err(paths::conflict());
            }
            let name_length = name_bytes / size_of::<u16>();
            // SAFETY: `FileNameLength` was checked against the returned byte
            // count, so this slice stays within the directory-query buffer.
            let name = unsafe {
                std::slice::from_raw_parts(ptr::addr_of!(entry.FileName).cast::<u16>(), name_length)
            };
            let leaf = OsString::from_wide(name);
            let leaf_text = leaf.to_str().ok_or_else(paths::conflict)?;
            if leaf_text != "." && leaf_text != ".." {
                if !paths::valid_component(leaf_text) {
                    return Err(paths::conflict());
                }
                return Ok(Some(DirectoryEntry {
                    leaf,
                    is_directory: entry.FileAttributes & FILE_ATTRIBUTE_DIRECTORY != 0,
                }));
            }
            let next = usize::try_from(entry.NextEntryOffset).map_err(|_| paths::conflict())?;
            if next == 0 {
                return Ok(None);
            }
            if next < name_offset || next > returned - offset {
                return Err(paths::conflict());
            }
            offset += next;
        }
        Ok(None)
    }

    fn remove_child(parent: &File, entry: DirectoryEntry) -> Result<(), PortError> {
        let kind = if entry.is_directory {
            FILE_DIRECTORY_FILE
        } else {
            FILE_NON_DIRECTORY_FILE
        };
        let child = open_relative(parent, &entry.leaf, FILE_OPEN, true, kind)?;
        if has_reparse_tag(&child)? {
            return Err(paths::conflict());
        }
        if entry.is_directory {
            remove_tree(&child)
        } else {
            mark_for_deletion(&child)
        }
    }

    fn mark_for_deletion(handle: &File) -> Result<(), PortError> {
        let mut disposition = FILE_DISPOSITION_INFO { DeleteFile: true };
        // SAFETY: `disposition` is the exact buffer required by the API and the
        // handle was opened with DELETE access.
        let success = unsafe {
            SetFileInformationByHandle(
                handle.as_raw_handle() as HANDLE,
                FileDispositionInfo,
                ptr::from_mut(&mut disposition).cast(),
                size_of::<FILE_DISPOSITION_INFO>() as u32,
            )
        };
        if success == 0 {
            return Err(paths::conflict());
        }
        Ok(())
    }

    fn final_path(handle: &File) -> Result<PathBuf, PortError> {
        let mut buffer = vec![0_u16; 32_768];
        // SAFETY: `buffer` is writable for the advertised capacity.
        let length = unsafe {
            GetFinalPathNameByHandleW(
                handle.as_raw_handle() as HANDLE,
                buffer.as_mut_ptr(),
                buffer.len() as u32,
                0,
            )
        } as usize;
        if length == 0 || length >= buffer.len() {
            return Err(paths::permission());
        }
        buffer.truncate(length);
        Ok(PathBuf::from(OsString::from_wide(&buffer)))
    }

    fn comparable(path: &Path) -> String {
        let normalized = path.to_string_lossy().replace('/', "\\");
        normalized
            .strip_prefix(r"\\?\")
            .unwrap_or(&normalized)
            .to_lowercase()
    }

    pub(crate) fn rename(handle: &File, destination: &Path) -> Result<(), PortError> {
        let name = destination.as_os_str().encode_wide().collect::<Vec<_>>();
        let name_bytes = name
            .len()
            .checked_mul(size_of::<u16>())
            .and_then(|length| u32::try_from(length).ok())
            .ok_or_else(paths::invalid)?;
        let buffer_bytes = size_of::<FILE_RENAME_INFO>()
            .checked_add(name_bytes as usize)
            .ok_or_else(paths::invalid)?;
        let words = buffer_bytes
            .checked_add(size_of::<usize>() - 1)
            .ok_or_else(paths::invalid)?
            / size_of::<usize>();
        let mut buffer = vec![0_usize; words];
        let info = buffer.as_mut_ptr().cast::<FILE_RENAME_INFO>();
        // SAFETY: the word-aligned buffer has room for the fixed fields and the
        // exact UTF-16 destination. The API reads it only during this call.
        let success = unsafe {
            (*info).Anonymous.ReplaceIfExists = false;
            (*info).RootDirectory = ptr::null_mut();
            (*info).FileNameLength = name_bytes;
            ptr::copy_nonoverlapping(
                name.as_ptr(),
                ptr::addr_of_mut!((*info).FileName).cast::<u16>(),
                name.len(),
            );
            SetFileInformationByHandle(
                handle.as_raw_handle() as HANDLE,
                FileRenameInfo,
                info.cast(),
                buffer_bytes as u32,
            )
        };
        if success == 0 {
            return Err(paths::conflict());
        }
        Ok(())
    }
}

#[cfg(test)]
fn disable_filters(options: &mut WorktreeAddOptions<'_>) -> bool {
    // The git2 0.21 wrapper exposes the worktree options as an opaque pointer.
    // libgit2-sys 0.18.4 is pinned to the exact layout used here.
    let raw = options.raw() as *mut libgit2_sys::git_worktree_add_options;
    // SAFETY: `WorktreeAddOptions::raw` points to its initialized in-place
    // libgit2-sys representation and the dependency version is pinned.
    unsafe {
        if (*raw).version != libgit2_sys::GIT_WORKTREE_ADD_OPTIONS_VERSION
            || (*raw).checkout_options.version != libgit2_sys::GIT_CHECKOUT_OPTIONS_VERSION
        {
            return false;
        }
        (*raw).checkout_options.disable_filters = 1;
    }
    true
}

#[cfg(test)]
mod tests {
    use git2::WorktreeAddOptions;

    #[test]
    fn checkout_option_layout_sentinel_is_supported() {
        let mut options = WorktreeAddOptions::new();
        assert!(super::disable_filters(&mut options));
    }
}
