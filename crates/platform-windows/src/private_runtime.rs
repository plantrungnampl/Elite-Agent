use std::fs::OpenOptions;
use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use local_agent_terminal_application::{
    DirectoryFileIdentity, PortError, PrivateRuntimeDirectoryInspector,
    PrivateRuntimeDirectoryVerificationGuard, ResolvedPrivateRuntimeDirectory, Retryability,
    SafeErrorClassification,
};
use windows_sys::Win32::Storage::FileSystem::{
    FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
};

const WINDOWS_FILE_SHARE_READ: u32 = 0x0000_0001;

#[derive(Debug, Default)]
pub struct WindowsPrivateRuntimeDirectoryInspector;

#[derive(Debug)]
pub struct RetainedPrivateRuntimeDirectory {
    _handle: winapi_util::Handle,
}

impl PrivateRuntimeDirectoryVerificationGuard for RetainedPrivateRuntimeDirectory {}

impl PrivateRuntimeDirectoryInspector for WindowsPrivateRuntimeDirectoryInspector {
    fn inspect_and_retain(
        &self,
        configured_absolute_path: &str,
        registration_id: &str,
    ) -> Result<
        (
            ResolvedPrivateRuntimeDirectory,
            Box<dyn PrivateRuntimeDirectoryVerificationGuard>,
        ),
        PortError,
    > {
        inspect_directory(Path::new(configured_absolute_path), registration_id)
            .map(|(resolved, retained)| (resolved, Box::new(retained) as _))
    }
}

fn inspect_directory(
    path: &Path,
    registration_id: &str,
) -> Result<
    (
        ResolvedPrivateRuntimeDirectory,
        RetainedPrivateRuntimeDirectory,
    ),
    PortError,
> {
    reject_reparse_components(path)?;
    let canonical_path = std::fs::canonicalize(path).map_err(|_| denied())?;
    let metadata = std::fs::symlink_metadata(&canonical_path).map_err(|_| denied())?;
    if !metadata.is_dir()
        || metadata.file_type().is_symlink()
        || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
    {
        return Err(denied());
    }
    let file = OpenOptions::new()
        .read(true)
        .share_mode(WINDOWS_FILE_SHARE_READ)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .open(&canonical_path)
        .map_err(|_| denied())?;
    let handle = winapi_util::Handle::from_file(file);
    let information = winapi_util::file::information(&handle).map_err(|_| denied())?;
    let file_identity = DirectoryFileIdentity::new(format!(
        "windows:{:016x}:{:016x}",
        information.volume_serial_number(),
        information.file_index(),
    ))?;
    if std::fs::canonicalize(path).ok().as_ref() != Some(&canonical_path) {
        return Err(integrity_failure());
    }
    Ok((
        ResolvedPrivateRuntimeDirectory {
            canonical_path,
            file_identity,
            registration_id: registration_id.to_owned(),
        },
        RetainedPrivateRuntimeDirectory { _handle: handle },
    ))
}

fn reject_reparse_components(path: &Path) -> Result<(), PortError> {
    let mut current = PathBuf::new();
    for component in path.components() {
        current.push(component.as_os_str());
        let Ok(metadata) = std::fs::symlink_metadata(&current) else {
            continue;
        };
        if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(denied());
        }
    }
    Ok(())
}

fn denied() -> PortError {
    PortError::failure(
        SafeErrorClassification::PermissionDenied,
        Retryability::NonRetryable,
    )
}

fn integrity_failure() -> PortError {
    PortError::failure(
        SafeErrorClassification::IntegrityFailure,
        Retryability::NonRetryable,
    )
}
