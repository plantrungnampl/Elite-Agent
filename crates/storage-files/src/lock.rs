use std::fs::{File, TryLockError};
use std::path::Path;

use cap_fs_ext::{FollowSymlinks, OpenOptionsFollowExt};
use cap_std::fs::OpenOptions;
use local_agent_terminal_application::{PortError, Retryability, SafeErrorClassification};

use crate::content_address::{io_error, open_root_directory};

pub struct RecoveryLock {
    _file: File,
}

impl RecoveryLock {
    pub fn acquire(app_root: &Path) -> Result<Self, PortError> {
        let (_, directory) = open_root_directory(app_root, || Ok(()))?;
        let mut options = OpenOptions::new();
        options
            .read(true)
            .write(true)
            .create(true)
            .follow(FollowSymlinks::No);
        let file = directory
            .open_with(".recovery.lock", &options)
            .map_err(io_error)?
            .into_std();
        file.try_lock().map_err(lock_error)?;
        Ok(Self { _file: file })
    }
}

fn lock_error(error: TryLockError) -> PortError {
    match error {
        TryLockError::WouldBlock => PortError::failure(
            SafeErrorClassification::Unavailable,
            Retryability::Retryable,
        ),
        TryLockError::Error(error) => io_error(error),
    }
}
