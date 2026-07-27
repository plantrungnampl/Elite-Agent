use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use git2::build::CheckoutBuilder;
#[cfg(test)]
use git2::WorktreeAddOptions;
use git2::{Reference, Repository, Worktree};
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
    write_new(
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

    let target_repository = paths::open_repository(path)?;
    let config =
        git2::Config::open(&repository.path().join("config")).map_err(|_| paths::unavailable())?;
    target_repository
        .set_config(&config)
        .map_err(|_| paths::unavailable())?;
    let mut checkout = CheckoutBuilder::new();
    checkout.disable_filters(true);
    #[cfg(feature = "test-seams")]
    install_checkout_barrier(&mut checkout, gateway);
    target_repository
        .checkout_head(Some(&mut checkout))
        .map_err(paths::map_git_error)?;
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
fn install_checkout_barrier(checkout: &mut CheckoutBuilder<'_>, gateway: &GitRepositoryGateway) {
    let Some(barrier) = &gateway.test_hooks.during_checkout else {
        return;
    };
    let barrier = barrier.clone();
    let mut waiting = true;
    checkout.progress(move |path, completed, _total| {
        if waiting && path.is_none() && completed == 0 {
            waiting = false;
            barrier.wait();
            barrier.wait();
        }
    });
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
        NtCreateFile, FILE_CREATE, FILE_DIRECTORY_FILE, FILE_OPEN, FILE_OPEN_REPARSE_POINT,
        FILE_SYNCHRONOUS_IO_NONALERT,
    };
    use windows_sys::Win32::Foundation::{
        HANDLE, OBJ_CASE_INSENSITIVE, STATUS_SUCCESS, UNICODE_STRING,
    };
    use windows_sys::Win32::Storage::FileSystem::{
        FileAttributeTagInfo, FileIdInfo, FileRenameInfo, GetFileInformationByHandleEx,
        GetFinalPathNameByHandleW, SetFileInformationByHandle, DELETE, FILE_ATTRIBUTE_NORMAL,
        FILE_ATTRIBUTE_REPARSE_POINT, FILE_ATTRIBUTE_TAG_INFO, FILE_GENERIC_READ,
        FILE_GENERIC_WRITE, FILE_ID_INFO, FILE_READ_ATTRIBUTES, FILE_RENAME_INFO, FILE_SHARE_READ,
        FILE_SHARE_WRITE, SYNCHRONIZE,
    };
    use windows_sys::Win32::System::IO::IO_STATUS_BLOCK;

    use crate::paths;

    #[derive(Clone, Copy, PartialEq, Eq)]
    pub(crate) struct DirectoryIdentity {
        volume: u64,
        file_id: [u8; 16],
    }

    pub(crate) fn create(parent: &File, leaf: &OsStr) -> Result<File, PortError> {
        open_relative(parent, leaf, FILE_CREATE, false)
    }

    pub(crate) fn open_for_rename(parent: &File, leaf: &OsStr) -> Result<File, PortError> {
        open_relative(parent, leaf, FILE_OPEN, true)
    }

    fn open_relative(
        parent: &File,
        leaf: &OsStr,
        disposition: u32,
        delete_access: bool,
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
                FILE_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT | FILE_SYNCHRONOUS_IO_NONALERT,
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
