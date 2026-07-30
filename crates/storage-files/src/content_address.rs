use std::ffi::OsString;
use std::fs;
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use cap_fs_ext::{DirExt, FollowSymlinks, OpenOptionsFollowExt, OpenOptionsMaybeDirExt};
use cap_std::ambient_authority;
use cap_std::fs::{Dir, File, OpenOptions};
use local_agent_terminal_application::{
    ArtifactContent, ArtifactRef, ArtifactStore, ArtifactWriteReservation, NewArtifact, PortError,
    Retryability, SafeErrorClassification,
};
use sha2::{Digest, Sha256};

static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

#[derive(Debug)]
pub struct ContentAddressedArtifactStore {
    root: PathBuf,
    directory: Dir,
}

enum InspectedFile {
    Missing,
    Invalid,
    Valid(Vec<u8>),
}

pub(crate) enum PublishError {
    Quarantined,
    Other(PortError),
}

impl PublishError {
    pub(crate) fn into_port_error(self) -> PortError {
        match self {
            Self::Quarantined => integrity_failure(),
            Self::Other(error) => error,
        }
    }
}

impl From<PortError> for PublishError {
    fn from(error: PortError) -> Self {
        Self::Other(error)
    }
}

impl ContentAddressedArtifactStore {
    pub fn open(root: impl AsRef<Path>) -> Result<Self, PortError> {
        Self::open_internal(root.as_ref(), || Ok(()))
    }

    fn open_internal(
        root: &Path,
        before_first_create: impl FnMut() -> std::io::Result<()>,
    ) -> Result<Self, PortError> {
        let (root, directory) = open_root_directory(root, before_first_create)?;
        let store = Self { root, directory };
        for relative in [
            Path::new("objects"),
            Path::new("staging"),
            Path::new("quarantine"),
        ] {
            store.ensure_directory(relative)?;
        }
        store.sync_relative_directory(Path::new("."))?;
        Ok(store)
    }

    #[cfg(test)]
    fn open_with_creation_hook(
        root: &Path,
        hook: impl FnMut() -> std::io::Result<()>,
    ) -> Result<Self, PortError> {
        Self::open_internal(root, hook)
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn validate_health(&self) -> Result<(), PortError> {
        let temp_name = format!(
            "health-{}-{}",
            std::process::id(),
            NEXT_TEMP.fetch_add(1, Ordering::Relaxed)
        );
        let staging = self.staging_path(&temp_name)?;
        let expected_hash = format!("sha256:{:x}", Sha256::digest(b"health"));
        let result = (|| {
            let mut file = self.create_staging(&temp_name)?;
            file.write_all(b"health").map_err(io_error)?;
            file.flush().map_err(io_error)?;
            file.sync_all().map_err(io_error)?;
            drop(file);
            if !self.verify(&staging, &expected_hash, 6)? {
                return Err(integrity_failure());
            }
            self.discard_staging(&staging)
        })();
        if result.is_err() && self.entry_exists(&staging).unwrap_or(false) {
            let _ = self.discard_staging(&staging);
        }
        result
    }

    pub(crate) fn staging_path(&self, temp_name: &str) -> Result<PathBuf, PortError> {
        Ok(self.root.join(staging_relative(temp_name)?))
    }

    pub(crate) fn object_path(&self, hash: &str) -> Result<PathBuf, PortError> {
        Ok(self.root.join(object_relative(hash)?))
    }

    pub fn storage_key(hash: &str) -> Result<String, PortError> {
        let hex = validate_hash(hash)?;
        Ok(format!("objects/{}/{}", &hex[..2], hex))
    }

    pub(crate) fn verify(
        &self,
        path: &Path,
        expected_hash: &str,
        expected_size: u64,
    ) -> Result<bool, PortError> {
        self.verify_relative(self.relative(path)?, expected_hash, expected_size)
    }

    pub(crate) fn create_staging(&self, temp_name: &str) -> Result<File, PortError> {
        let relative = staging_relative(temp_name)?;
        let mut options = OpenOptions::new();
        options
            .write(true)
            .create_new(true)
            .follow(FollowSymlinks::No);
        let file = self
            .directory
            .open_with(&relative, &options)
            .map_err(io_error)?;
        self.sync_relative_directory(Path::new("staging"))?;
        Ok(file)
    }

    pub(crate) fn publish(
        &self,
        staging: &Path,
        expected_hash: &str,
        expected_size: u64,
    ) -> Result<PathBuf, PublishError> {
        self.publish_internal(staging, expected_hash, expected_size, || Ok(()))
    }

    fn publish_internal(
        &self,
        staging: &Path,
        expected_hash: &str,
        expected_size: u64,
        after_rename: impl FnOnce() -> Result<(), PortError>,
    ) -> Result<PathBuf, PublishError> {
        let staging_relative = self.relative(staging)?.to_owned();
        let target_relative = object_relative(expected_hash)?;
        let target_parent = target_relative.parent().ok_or_else(invalid_input)?;
        self.ensure_directory(target_parent)?;
        if self.entry_exists_relative(&target_relative)? {
            if self.verify_relative(&target_relative, expected_hash, expected_size)? {
                if self.entry_exists_relative(&staging_relative)? {
                    self.discard_staging(staging)?;
                }
                return Ok(self.root.join(target_relative));
            }
            self.quarantine(&self.root.join(&target_relative))?;
        }
        self.directory
            .rename(&staging_relative, &self.directory, &target_relative)
            .map_err(io_error)?;
        self.sync_relative_directory(target_parent)?;
        self.sync_relative_directory(Path::new("staging"))?;
        after_rename()?;
        if !self.verify_relative(&target_relative, expected_hash, expected_size)? {
            if self.entry_exists_relative(&target_relative)? {
                self.quarantine(&self.root.join(&target_relative))?;
                return Err(PublishError::Quarantined);
            }
            return Err(PublishError::Other(integrity_failure()));
        }
        Ok(self.root.join(target_relative))
    }

    pub(crate) fn publish_with_post_rename_hook(
        &self,
        staging: &Path,
        expected_hash: &str,
        expected_size: u64,
        hook: impl FnOnce() -> Result<(), PortError>,
    ) -> Result<PathBuf, PublishError> {
        self.publish_internal(staging, expected_hash, expected_size, hook)
    }

    pub(crate) fn quarantine(&self, source: &Path) -> Result<PathBuf, PortError> {
        let source_relative = self.relative(source)?.to_owned();
        let metadata = self
            .directory
            .symlink_metadata(&source_relative)
            .map_err(io_error)?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(permission_denied());
        }
        loop {
            let name = format!(
                "{}-{}-{}",
                source_relative
                    .file_name()
                    .and_then(|name| name.to_str())
                    .unwrap_or("artifact"),
                std::process::id(),
                NEXT_TEMP.fetch_add(1, Ordering::Relaxed)
            );
            let target_relative = Path::new("quarantine").join(name);
            if self.entry_exists_relative(&target_relative)? {
                continue;
            }
            self.directory
                .rename(&source_relative, &self.directory, &target_relative)
                .map_err(io_error)?;
            self.sync_relative_directory(Path::new("quarantine"))?;
            if let Some(parent) = source_relative.parent() {
                self.sync_relative_directory(parent)?;
            }
            return Ok(self.root.join(target_relative));
        }
    }

    pub(crate) fn discard_staging(&self, path: &Path) -> Result<(), PortError> {
        let relative = self.relative(path)?;
        let metadata = self
            .directory
            .symlink_metadata(relative)
            .map_err(io_error)?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(permission_denied());
        }
        self.directory.remove_file(relative).map_err(io_error)?;
        self.sync_relative_directory(Path::new("staging"))
    }

    pub(crate) fn entry_exists(&self, path: &Path) -> Result<bool, PortError> {
        self.entry_exists_relative(self.relative(path)?)
    }

    pub(crate) fn staging_entries(&self) -> Result<Vec<PathBuf>, PortError> {
        self.directory
            .read_dir("staging")
            .map_err(io_error)?
            .map(|entry| {
                let name = entry.map_err(io_error)?.file_name();
                validate_filename_os(&name)?;
                Ok(self.root.join("staging").join(name))
            })
            .collect()
    }

    pub(crate) fn reference_for(
        &self,
        hash: &str,
        size_bytes: u64,
    ) -> Result<ArtifactRef, PortError> {
        Ok(ArtifactRef {
            content_hash: hash.to_owned(),
            storage_key: Self::storage_key(hash)?,
            size_bytes,
        })
    }

    pub(crate) fn validate_reservation(
        &self,
        reservation: &ArtifactWriteReservation,
        content: &[u8],
    ) -> Result<(), PortError> {
        self.validate_reservation_metadata(reservation)?;
        validate_declared_content_parts(
            &reservation.artifact.content_hash,
            reservation.artifact.size_bytes,
            content,
        )
    }

    pub(crate) fn validate_reservation_metadata(
        &self,
        reservation: &ArtifactWriteReservation,
    ) -> Result<(), PortError> {
        if reservation.artifact.storage_key
            != Self::storage_key(&reservation.artifact.content_hash)?
        {
            return Err(invalid_input());
        }
        staging_relative(&reservation.temp_name)?;
        object_relative(&reservation.artifact.content_hash)?;
        Ok(())
    }

    fn put_content(&self, artifact: NewArtifact) -> Result<ArtifactRef, PortError> {
        validate_declared_content(&artifact)?;
        let storage_key = Self::storage_key(&artifact.expected_hash)?;
        let target = self.object_path(&artifact.expected_hash)?;
        if self.entry_exists(&target)?
            && self.verify(&target, &artifact.expected_hash, artifact.expected_size)?
        {
            return Ok(ArtifactRef {
                content_hash: artifact.expected_hash,
                storage_key,
                size_bytes: artifact.expected_size,
            });
        }
        let temp_name = format!(
            "put-{}-{}-{}",
            std::process::id(),
            NEXT_TEMP.fetch_add(1, Ordering::Relaxed),
            &artifact.expected_hash[7..15]
        );
        let staging = self.staging_path(&temp_name)?;
        let mut file = self.create_staging(&temp_name)?;
        file.write_all(&artifact.content).map_err(io_error)?;
        file.flush().map_err(io_error)?;
        file.sync_all().map_err(io_error)?;
        drop(file);
        if !self.verify(&staging, &artifact.expected_hash, artifact.expected_size)? {
            self.quarantine(&staging)?;
            return Err(integrity_failure());
        }
        self.publish(&staging, &artifact.expected_hash, artifact.expected_size)
            .map_err(PublishError::into_port_error)?;
        Ok(ArtifactRef {
            content_hash: artifact.expected_hash,
            storage_key,
            size_bytes: artifact.expected_size,
        })
    }

    fn read_internal(
        &self,
        reference: &ArtifactRef,
        after_open: impl FnOnce() -> std::io::Result<()>,
    ) -> Result<ArtifactContent, PortError> {
        let expected_key = Self::storage_key(&reference.content_hash)?;
        if reference.storage_key != expected_key {
            return Err(invalid_input());
        }
        let path = self.object_path(&reference.content_hash)?;
        let bytes = match self.inspect_relative_with_post_open_hook(
            self.relative(&path)?,
            &reference.content_hash,
            reference.size_bytes,
            after_open,
        )? {
            InspectedFile::Missing => return Err(not_found()),
            InspectedFile::Invalid => return Err(integrity_failure()),
            InspectedFile::Valid(bytes) => bytes,
        };
        Ok(ArtifactContent { bytes })
    }

    #[cfg(test)]
    fn read_with_post_open_hook(
        &self,
        reference: &ArtifactRef,
        hook: impl FnOnce() -> std::io::Result<()>,
    ) -> Result<ArtifactContent, PortError> {
        self.read_internal(reference, hook)
    }

    fn verify_relative(
        &self,
        relative: &Path,
        expected_hash: &str,
        expected_size: u64,
    ) -> Result<bool, PortError> {
        let mut options = OpenOptions::new();
        options.read(true).follow(FollowSymlinks::No);
        let mut file = match self.directory.open_with(relative, &options) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
            Err(error) => return Err(io_error(error)),
        };
        let metadata = file.metadata().map_err(io_error)?;
        if !metadata.is_file() || metadata.len() != expected_size {
            return Ok(false);
        }
        verify_stream(&mut file, expected_hash, expected_size)
    }

    fn inspect_relative_with_post_open_hook(
        &self,
        relative: &Path,
        expected_hash: &str,
        expected_size: u64,
        after_open: impl FnOnce() -> std::io::Result<()>,
    ) -> Result<InspectedFile, PortError> {
        let mut options = OpenOptions::new();
        options.read(true).follow(FollowSymlinks::No);
        let mut file = match self.directory.open_with(relative, &options) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(InspectedFile::Missing)
            }
            Err(error) => return Err(io_error(error)),
        };
        after_open().map_err(io_error)?;
        let metadata = file.metadata().map_err(io_error)?;
        if !metadata.is_file() || metadata.len() != expected_size {
            return Ok(InspectedFile::Invalid);
        }
        let mut bytes = Vec::with_capacity(expected_size.min(usize::MAX as u64) as usize);
        file.read_to_end(&mut bytes).map_err(io_error)?;
        if bytes.len() as u64 != expected_size
            || format!("sha256:{:x}", Sha256::digest(&bytes)) != expected_hash
        {
            return Ok(InspectedFile::Invalid);
        }
        Ok(InspectedFile::Valid(bytes))
    }

    fn relative<'a>(&self, path: &'a Path) -> Result<&'a Path, PortError> {
        let relative = path.strip_prefix(&self.root).map_err(|_| invalid_input())?;
        validate_relative(relative)?;
        Ok(relative)
    }

    fn entry_exists_relative(&self, relative: &Path) -> Result<bool, PortError> {
        match self.directory.symlink_metadata(relative) {
            Ok(_) => Ok(true),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(error) => Err(io_error(error)),
        }
    }

    fn ensure_directory(&self, relative: &Path) -> Result<Dir, PortError> {
        validate_relative(relative)?;
        let mut directory = self.directory.try_clone().map_err(io_error)?;
        for component in relative.components() {
            if component == Component::CurDir {
                continue;
            }
            let Component::Normal(name) = component else {
                return Err(invalid_input());
            };
            directory = match directory.open_dir_nofollow(name) {
                Ok(child) => child,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    let created = match directory.create_dir(name) {
                        Ok(()) => true,
                        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => false,
                        Err(error) => return Err(io_error(error)),
                    };
                    if created {
                        sync_directory_handle(&directory)?;
                    }
                    directory.open_dir_nofollow(name).map_err(io_error)?
                }
                Err(error) => return Err(io_error(error)),
            };
        }
        Ok(directory)
    }

    fn sync_relative_directory(&self, relative: &Path) -> Result<(), PortError> {
        let directory = self
            .directory
            .open_dir_nofollow(relative)
            .map_err(io_error)?;
        sync_directory_handle(&directory)
    }
}

pub(crate) fn open_root_directory(
    root: &Path,
    mut before_first_create: impl FnMut() -> std::io::Result<()>,
) -> Result<(PathBuf, Dir), PortError> {
    let absolute = validated_absolute(root)?;
    reject_existing_link_components(&absolute)?;
    let (anchor, components) = anchored_components(&absolute)?;
    let mut directory = Dir::open_ambient_dir(anchor, ambient_authority()).map_err(io_error)?;
    let mut called = false;
    for component in components {
        directory = match directory.open_dir_nofollow(&component) {
            Ok(child) => child,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                if !called {
                    before_first_create().map_err(io_error)?;
                    called = true;
                }
                let created = match directory.create_dir(&component) {
                    Ok(()) => true,
                    Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => false,
                    Err(error) => return Err(io_error(error)),
                };
                if created {
                    sync_directory_handle(&directory)?;
                }
                directory.open_dir_nofollow(&component).map_err(io_error)?
            }
            Err(error) => return Err(io_error(error)),
        };
    }
    reject_existing_link_components(&absolute)?;
    Ok((fs::canonicalize(&absolute).map_err(io_error)?, directory))
}

impl ArtifactStore for ContentAddressedArtifactStore {
    fn put(&self, artifact: NewArtifact) -> Result<ArtifactRef, PortError> {
        self.put_content(artifact)
    }

    fn read(&self, reference: &ArtifactRef) -> Result<ArtifactContent, PortError> {
        self.read_internal(reference, || Ok(()))
    }
}

fn staging_relative(temp_name: &str) -> Result<PathBuf, PortError> {
    validate_filename(temp_name)?;
    Ok(Path::new("staging").join(temp_name))
}

fn object_relative(hash: &str) -> Result<PathBuf, PortError> {
    let hex = validate_hash(hash)?;
    Ok(Path::new("objects").join(&hex[..2]).join(hex))
}

fn validate_declared_content(artifact: &NewArtifact) -> Result<(), PortError> {
    validate_declared_content_parts(
        &artifact.expected_hash,
        artifact.expected_size,
        &artifact.content,
    )
}

fn validate_declared_content_parts(
    expected_hash: &str,
    expected_size: u64,
    content: &[u8],
) -> Result<(), PortError> {
    validate_hash(expected_hash)?;
    if content.len() as u64 != expected_size {
        return Err(invalid_input());
    }
    if format!("sha256:{:x}", Sha256::digest(content)) != expected_hash {
        return Err(integrity_failure());
    }
    Ok(())
}

fn verify_stream(
    reader: &mut impl Read,
    expected_hash: &str,
    expected_size: u64,
) -> Result<bool, PortError> {
    let mut hash = Sha256::new();
    let mut size = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = reader.read(&mut buffer).map_err(io_error)?;
        if read == 0 {
            break;
        }
        size = size
            .checked_add(read as u64)
            .ok_or_else(integrity_failure)?;
        if size > expected_size {
            return Ok(false);
        }
        hash.update(&buffer[..read]);
    }
    Ok(size == expected_size && format!("sha256:{:x}", hash.finalize()) == expected_hash)
}

fn validate_hash(hash: &str) -> Result<&str, PortError> {
    let hex = hash.strip_prefix("sha256:").ok_or_else(invalid_input)?;
    if hex.len() != 64
        || !hex
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(invalid_input());
    }
    Ok(hex)
}

fn validate_filename(name: &str) -> Result<(), PortError> {
    validate_filename_os(name.as_ref())
}

fn validate_filename_os(name: &std::ffi::OsStr) -> Result<(), PortError> {
    if name.to_string_lossy().contains(':') {
        return Err(invalid_input());
    }
    let mut components = Path::new(name).components();
    if !matches!(components.next(), Some(Component::Normal(_))) || components.next().is_some() {
        return Err(invalid_input());
    }
    Ok(())
}

fn validate_relative(path: &Path) -> Result<(), PortError> {
    if path.is_absolute()
        || path
            .components()
            .any(|component| !matches!(component, Component::Normal(_) | Component::CurDir))
    {
        return Err(invalid_input());
    }
    Ok(())
}

fn validated_absolute(path: &Path) -> Result<PathBuf, PortError> {
    if path
        .components()
        .any(|component| matches!(component, Component::ParentDir))
    {
        return Err(invalid_input());
    }
    std::path::absolute(path).map_err(io_error)
}

fn anchored_components(path: &Path) -> Result<(PathBuf, Vec<OsString>), PortError> {
    let mut anchor = PathBuf::new();
    let mut relative = Vec::new();
    let mut saw_normal = false;
    for component in path.components() {
        match component {
            Component::Prefix(prefix) if !saw_normal => {
                validate_root_prefix(prefix.kind())?;
                anchor.push(component);
            }
            Component::RootDir if !saw_normal => anchor.push(component),
            Component::Normal(name) => {
                saw_normal = true;
                relative.push(name.to_owned());
            }
            Component::CurDir => {}
            Component::Prefix(_) | Component::RootDir | Component::ParentDir => {
                return Err(invalid_input())
            }
        }
    }
    if anchor.as_os_str().is_empty() {
        return Err(invalid_input());
    }
    Ok((anchor, relative))
}

#[cfg(windows)]
fn validate_root_prefix(prefix: std::path::Prefix<'_>) -> Result<(), PortError> {
    match prefix {
        std::path::Prefix::Disk(_) => Ok(()),
        _ => Err(invalid_input()),
    }
}

#[cfg(not(windows))]
fn validate_root_prefix(_prefix: std::path::Prefix<'_>) -> Result<(), PortError> {
    Err(invalid_input())
}

fn reject_existing_link_components(path: &Path) -> Result<(), PortError> {
    let mut current = PathBuf::new();
    for component in path.components() {
        current.push(component);
        match fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.file_type().is_symlink() || is_reparse_point(&metadata) => {
                return Err(permission_denied())
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(io_error(error)),
        }
    }
    Ok(())
}

#[cfg(windows)]
fn is_reparse_point(metadata: &fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    metadata.file_attributes() & 0x400 != 0
}

#[cfg(not(windows))]
fn is_reparse_point(_metadata: &fs::Metadata) -> bool {
    false
}

fn sync_directory_handle(directory: &Dir) -> Result<(), PortError> {
    sync_directory_handle_platform(directory)
}

#[cfg(windows)]
fn sync_directory_handle_platform(directory: &Dir) -> Result<(), PortError> {
    let mut options = OpenOptions::new();
    options
        .write(true)
        .maybe_dir(true)
        .follow(FollowSymlinks::No);
    directory
        .open_with(".", &options)
        .map_err(io_error)?
        .sync_all()
        .map_err(io_error)
}

#[cfg(not(windows))]
fn sync_directory_handle_platform(directory: &Dir) -> Result<(), PortError> {
    directory
        .try_clone()
        .map_err(io_error)?
        .into_std_file()
        .sync_all()
        .map_err(io_error)
}

#[cfg(test)]
fn sync_directory(path: &Path) -> Result<(), PortError> {
    let directory = Dir::open_ambient_dir(path, ambient_authority()).map_err(io_error)?;
    sync_directory_handle(&directory)
}

pub(crate) fn io_error(error: std::io::Error) -> PortError {
    let classification = match error.raw_os_error() {
        Some(28 | 112) => SafeErrorClassification::StorageFull,
        Some(5 | 13) => SafeErrorClassification::PermissionDenied,
        _ if error.kind() == std::io::ErrorKind::NotFound => SafeErrorClassification::NotFound,
        _ if error.kind() == std::io::ErrorKind::PermissionDenied => {
            SafeErrorClassification::PermissionDenied
        }
        _ => SafeErrorClassification::Internal,
    };
    let retryability = if matches!(
        error.kind(),
        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
    ) || matches!(error.raw_os_error(), Some(11 | 16 | 26 | 32 | 33))
    {
        Retryability::Retryable
    } else {
        Retryability::NonRetryable
    };
    PortError::failure(classification, retryability)
}

fn invalid_input() -> PortError {
    PortError::failure(
        SafeErrorClassification::InvalidInput,
        Retryability::NonRetryable,
    )
}

fn permission_denied() -> PortError {
    PortError::failure(
        SafeErrorClassification::PermissionDenied,
        Retryability::NonRetryable,
    )
}

pub(crate) fn integrity_failure() -> PortError {
    PortError::failure(
        SafeErrorClassification::IntegrityFailure,
        Retryability::NonRetryable,
    )
}

fn not_found() -> PortError {
    PortError::failure(
        SafeErrorClassification::NotFound,
        Retryability::NonRetryable,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use local_agent_terminal_application::ArtifactStore;
    use tempfile::TempDir;

    const HELLO_HASH: &str =
        "sha256:2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824";

    #[test]
    fn read_returns_the_exact_bytes_verified_from_one_open_handle() {
        let root = TempDir::new().unwrap();
        let store = ContentAddressedArtifactStore::open(root.path()).unwrap();
        let reference = store
            .put(NewArtifact {
                expected_hash: HELLO_HASH.to_owned(),
                expected_size: 5,
                content: b"hello".to_vec(),
            })
            .unwrap();
        let object = root.path().join(&reference.storage_key);
        let replacement = root.path().join("replacement");
        fs::write(&replacement, b"jello").unwrap();

        let content = store
            .read_with_post_open_hook(&reference, || {
                #[cfg(windows)]
                {
                    let backup = root.path().join("original");
                    fs::rename(&object, backup)?;
                    fs::rename(&replacement, &object)
                }
                #[cfg(not(windows))]
                {
                    fs::rename(&replacement, &object)
                }
            })
            .unwrap();

        assert_eq!(content.bytes, b"hello");
    }

    #[test]
    fn capability_relative_creation_cannot_escape_after_parent_replacement() {
        let holder = TempDir::new().unwrap();
        let outside = TempDir::new().unwrap();
        let parent = holder.path().join("parent");
        fs::create_dir(&parent).unwrap();
        let requested = parent.join("nested");

        let result = ContentAddressedArtifactStore::open_with_creation_hook(&requested, || {
            fs::remove_dir(&parent)?;
            create_directory_link(outside.path(), &parent)
        });

        assert!(result.is_err());
        assert!(!outside.path().join("nested").exists());
    }

    #[test]
    fn invalid_post_rename_object_is_quarantined_before_error() {
        let root = TempDir::new().unwrap();
        let store = ContentAddressedArtifactStore::open(root.path()).unwrap();
        let staging = store.staging_path("post-rename.tmp").unwrap();
        let mut file = store.create_staging("post-rename.tmp").unwrap();
        file.write_all(b"hello").unwrap();
        file.flush().unwrap();
        file.sync_all().unwrap();
        drop(file);
        let target = store.object_path(HELLO_HASH).unwrap();

        assert!(store
            .publish_with_post_rename_hook(&staging, HELLO_HASH, 5, || {
                fs::write(&target, b"jello").map_err(io_error)
            })
            .is_err());

        assert!(!target.exists());
        let evidence: Vec<_> = fs::read_dir(root.path().join("quarantine"))
            .unwrap()
            .map(|entry| fs::read(entry.unwrap().path()).unwrap())
            .collect();
        assert_eq!(evidence, [b"jello".to_vec()]);
    }

    #[test]
    fn internal_verification_reads_in_bounded_chunks() {
        struct BoundedReader {
            bytes: std::io::Cursor<Vec<u8>>,
        }

        impl Read for BoundedReader {
            fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
                if buffer.len() > 64 * 1024 {
                    return Err(std::io::Error::other("unbounded read"));
                }
                self.bytes.read(buffer)
            }
        }

        let bytes = vec![b'x'; 128 * 1024 + 1];
        let expected_hash = format!("sha256:{:x}", Sha256::digest(&bytes));
        let mut reader = BoundedReader {
            bytes: std::io::Cursor::new(bytes),
        };

        assert!(verify_stream(&mut reader, &expected_hash, 128 * 1024 + 1).unwrap());
    }

    #[test]
    fn transient_lock_errors_are_retryable() {
        let error = io_error(std::io::Error::new(
            std::io::ErrorKind::WouldBlock,
            "locked",
        ));
        assert_eq!(error.retryability(), Retryability::Retryable);
    }

    #[cfg(windows)]
    #[test]
    fn windows_directory_sync_is_not_a_silent_noop() {
        let root = TempDir::new().unwrap();
        assert!(sync_directory(&root.path().join("missing")).is_err());
        sync_directory(root.path()).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn windows_verbatim_device_roots_are_rejected() {
        assert!(validate_root_prefix(std::path::Prefix::VerbatimDisk(b'C')).is_err());
    }

    #[cfg(unix)]
    fn create_directory_link(target: &Path, link: &Path) -> std::io::Result<()> {
        std::os::unix::fs::symlink(target, link)
    }

    #[cfg(windows)]
    fn create_directory_link(target: &Path, link: &Path) -> std::io::Result<()> {
        let output = std::process::Command::new("cmd.exe")
            .args(["/C", "mklink", "/J"])
            .arg(link)
            .arg(target)
            .output()?;
        if output.status.success() {
            Ok(())
        } else {
            Err(std::io::Error::other(
                String::from_utf8_lossy(&output.stderr).into_owned(),
            ))
        }
    }
}
