use std::fs::OpenOptions;
use std::io::Read;
use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;

use local_agent_terminal_application::{
    ExecutableArtifactInspector, ExecutableFileIdentity, ExecutableVerificationGuard, PortError,
    ResolvedExecutable, Retryability, SafeErrorClassification,
};
use local_agent_terminal_domain::Sha256Digest;
use sha2::{Digest, Sha256};
use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;

const WINDOWS_FILE_SHARE_READ: u32 = 0x0000_0001;

#[derive(Debug, Default)]
pub struct WindowsExecutableInspector;

#[derive(Debug)]
pub struct RetainedExecutable {
    handle: winapi_util::Handle,
}

impl ExecutableVerificationGuard for RetainedExecutable {}

impl ExecutableArtifactInspector for WindowsExecutableInspector {
    fn inspect_and_retain(
        &self,
        configured_absolute_path: &str,
        toolchain_id: &str,
        expected_sha256: &Sha256Digest,
    ) -> Result<(ResolvedExecutable, Box<dyn ExecutableVerificationGuard>), PortError> {
        inspect_executable(
            Path::new(configured_absolute_path),
            toolchain_id,
            expected_sha256,
        )
        .map(|(resolved, retained)| (resolved, Box::new(retained) as _))
    }
}

fn inspect_executable(
    path: &Path,
    toolchain_id: &str,
    expected_sha256: &Sha256Digest,
) -> Result<(ResolvedExecutable, RetainedExecutable), PortError> {
    let metadata = std::fs::symlink_metadata(path).map_err(|_| denied())?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
    {
        return Err(denied());
    }
    let canonical_path = std::fs::canonicalize(path).map_err(|_| denied())?;
    let file = OpenOptions::new()
        .read(true)
        .share_mode(WINDOWS_FILE_SHARE_READ)
        .open(&canonical_path)
        .map_err(|_| denied())?;
    let handle = winapi_util::Handle::from_file(file);
    let information = winapi_util::file::information(&handle).map_err(|_| denied())?;
    let file_identity = ExecutableFileIdentity::new(format!(
        "windows:{:016x}:{:016x}",
        information.volume_serial_number(),
        information.file_index(),
    ))?;
    let mut retained = RetainedExecutable { handle };
    let mut bytes = Vec::new();
    retained
        .handle
        .as_file_mut()
        .read_to_end(&mut bytes)
        .map_err(|_| denied())?;
    let sha256 = Sha256Digest::new(format!("sha256:{:x}", Sha256::digest(&bytes)))
        .map_err(|_| integrity_failure())?;
    if &sha256 != expected_sha256
        || std::fs::canonicalize(path).ok().as_ref() != Some(&canonical_path)
    {
        return Err(integrity_failure());
    }
    Ok((
        ResolvedExecutable {
            canonical_path,
            sha256,
            file_identity,
            toolchain_id: toolchain_id.to_owned(),
        },
        retained,
    ))
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
