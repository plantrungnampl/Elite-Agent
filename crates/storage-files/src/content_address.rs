use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use local_agent_terminal_application::{
    ArtifactContent, ArtifactRef, ArtifactStore, ArtifactWriteReservation, NewArtifact, PortError,
    Retryability, SafeErrorClassification,
};
use sha2::{Digest, Sha256};

static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone)]
pub struct ContentAddressedArtifactStore {
    root: PathBuf,
}

impl ContentAddressedArtifactStore {
    pub fn open(root: impl AsRef<Path>) -> Result<Self, PortError> {
        reject_existing_link_components(root.as_ref())?;
        fs::create_dir_all(root.as_ref()).map_err(io_error)?;
        reject_link(root.as_ref())?;
        let root = fs::canonicalize(root.as_ref()).map_err(io_error)?;
        let store = Self { root };
        for directory in [
            store.objects_dir(),
            store.staging_dir(),
            store.quarantine_dir(),
        ] {
            fs::create_dir_all(&directory).map_err(io_error)?;
            store.ensure_contained(&directory)?;
        }
        Ok(store)
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub(crate) fn staging_path(&self, temp_name: &str) -> Result<PathBuf, PortError> {
        validate_filename(temp_name)?;
        let path = self.staging_dir().join(temp_name);
        self.ensure_parent_contained(&path)?;
        Ok(path)
    }

    pub(crate) fn object_path(&self, hash: &str) -> Result<PathBuf, PortError> {
        let hex = validate_hash(hash)?;
        let path = self.objects_dir().join(&hex[..2]).join(hex);
        self.ensure_parent_contained(&path)?;
        Ok(path)
    }

    pub(crate) fn storage_key(hash: &str) -> Result<String, PortError> {
        let hex = validate_hash(hash)?;
        Ok(format!("objects/{}/{}", &hex[..2], hex))
    }

    pub(crate) fn verify(
        &self,
        path: &Path,
        expected_hash: &str,
        expected_size: u64,
    ) -> Result<bool, PortError> {
        if !entry_exists(path)? {
            return Ok(false);
        }
        self.ensure_contained(path)?;
        reject_link(path)?;
        let metadata = fs::metadata(path).map_err(io_error)?;
        if !metadata.is_file() || metadata.len() != expected_size {
            return Ok(false);
        }
        let mut file = File::open(path).map_err(io_error)?;
        let mut digest = Sha256::new();
        let mut buffer = [0_u8; 64 * 1024];
        loop {
            let read = file.read(&mut buffer).map_err(io_error)?;
            if read == 0 {
                break;
            }
            digest.update(&buffer[..read]);
        }
        Ok(format!("sha256:{:x}", digest.finalize()) == expected_hash)
    }

    pub(crate) fn create_staging(&self, temp_name: &str) -> Result<File, PortError> {
        let path = self.staging_path(temp_name)?;
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .map_err(io_error)?;
        sync_directory(&self.staging_dir())?;
        Ok(file)
    }

    pub(crate) fn publish(
        &self,
        staging: &Path,
        expected_hash: &str,
        expected_size: u64,
    ) -> Result<PathBuf, PortError> {
        self.ensure_contained(staging)?;
        let target = self.object_path(expected_hash)?;
        let parent = target.parent().ok_or_else(invalid_input)?;
        fs::create_dir_all(parent).map_err(io_error)?;
        self.ensure_contained(parent)?;
        if entry_exists(&target)? {
            if self.verify(&target, expected_hash, expected_size)? {
                if entry_exists(staging)? {
                    self.discard_staging(staging)?;
                }
                return Ok(target);
            }
            self.quarantine(&target)?;
        }
        fs::rename(staging, &target).map_err(io_error)?;
        sync_directory(parent)?;
        sync_directory(&self.staging_dir())?;
        if !self.verify(&target, expected_hash, expected_size)? {
            return Err(integrity_failure());
        }
        Ok(target)
    }

    pub(crate) fn quarantine(&self, source: &Path) -> Result<PathBuf, PortError> {
        self.ensure_contained(source)?;
        reject_link(source)?;
        if !fs::metadata(source).map_err(io_error)?.is_file() {
            return Err(invalid_input());
        }
        loop {
            let name = format!(
                "{}-{}-{}",
                source
                    .file_name()
                    .and_then(|name| name.to_str())
                    .unwrap_or("artifact"),
                std::process::id(),
                NEXT_TEMP.fetch_add(1, Ordering::Relaxed)
            );
            let target = self.quarantine_dir().join(name);
            if entry_exists(&target)? {
                continue;
            }
            fs::rename(source, &target).map_err(io_error)?;
            sync_directory(&self.quarantine_dir())?;
            if let Some(parent) = source.parent() {
                sync_directory(parent)?;
            }
            return Ok(target);
        }
    }

    pub(crate) fn discard_staging(&self, path: &Path) -> Result<(), PortError> {
        self.ensure_contained(path)?;
        reject_link(path)?;
        fs::remove_file(path).map_err(io_error)?;
        sync_directory(&self.staging_dir())
    }

    pub(crate) fn entry_exists(&self, path: &Path) -> Result<bool, PortError> {
        entry_exists(path)
    }

    pub(crate) fn staging_entries(&self) -> Result<Vec<PathBuf>, PortError> {
        self.ensure_contained(&self.staging_dir())?;
        fs::read_dir(self.staging_dir())
            .map_err(io_error)?
            .map(|entry| {
                let path = entry.map_err(io_error)?.path();
                self.ensure_contained(&path)?;
                Ok(path)
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
        self.staging_path(&reservation.temp_name)?;
        self.object_path(&reservation.artifact.content_hash)?;
        Ok(())
    }

    fn put_content(&self, artifact: NewArtifact) -> Result<ArtifactRef, PortError> {
        validate_declared_content(&artifact)?;
        let storage_key = Self::storage_key(&artifact.expected_hash)?;
        let target = self.object_path(&artifact.expected_hash)?;
        if entry_exists(&target)?
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
        self.publish(&staging, &artifact.expected_hash, artifact.expected_size)?;
        Ok(ArtifactRef {
            content_hash: artifact.expected_hash,
            storage_key,
            size_bytes: artifact.expected_size,
        })
    }

    fn ensure_parent_contained(&self, path: &Path) -> Result<(), PortError> {
        let parent = path.parent().ok_or_else(invalid_input)?;
        if entry_exists(parent)? {
            self.ensure_contained(parent)
        } else {
            for ancestor in parent.ancestors() {
                if entry_exists(ancestor)? {
                    return self.ensure_contained(ancestor);
                }
            }
            Err(invalid_input())
        }
    }

    fn ensure_contained(&self, path: &Path) -> Result<(), PortError> {
        let relative = path.strip_prefix(&self.root).map_err(|_| invalid_input())?;
        let mut current = self.root.clone();
        for component in relative.components() {
            if !matches!(component, Component::Normal(_)) {
                return Err(invalid_input());
            }
            current.push(component);
            match fs::symlink_metadata(&current) {
                Ok(metadata) => {
                    if metadata.file_type().is_symlink() || is_reparse_point(&metadata) {
                        return Err(permission_denied());
                    }
                    let canonical = fs::canonicalize(&current).map_err(io_error)?;
                    if !canonical.starts_with(&self.root) {
                        return Err(permission_denied());
                    }
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(io_error(error)),
            }
        }
        Ok(())
    }

    fn objects_dir(&self) -> PathBuf {
        self.root.join("objects")
    }

    fn staging_dir(&self) -> PathBuf {
        self.root.join("staging")
    }

    fn quarantine_dir(&self) -> PathBuf {
        self.root.join("quarantine")
    }
}

impl ArtifactStore for ContentAddressedArtifactStore {
    fn put(&self, artifact: NewArtifact) -> Result<ArtifactRef, PortError> {
        self.put_content(artifact)
    }

    fn read(&self, reference: &ArtifactRef) -> Result<ArtifactContent, PortError> {
        let expected_key = Self::storage_key(&reference.content_hash)?;
        if reference.storage_key != expected_key {
            return Err(invalid_input());
        }
        let path = self.object_path(&reference.content_hash)?;
        if !path.exists() {
            return Err(not_found());
        }
        if !self.verify(&path, &reference.content_hash, reference.size_bytes)? {
            return Err(integrity_failure());
        }
        Ok(ArtifactContent {
            bytes: fs::read(path).map_err(io_error)?,
        })
    }
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
    if u64::try_from(content.len()).map_err(|_| invalid_input())? != expected_size {
        return Err(invalid_input());
    }
    let digest = Sha256::digest(content);
    if format!("sha256:{digest:x}") != expected_hash {
        return Err(integrity_failure());
    }
    Ok(())
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
    if name.contains(':') {
        return Err(invalid_input());
    }
    let mut components = Path::new(name).components();
    if !matches!(components.next(), Some(Component::Normal(_))) || components.next().is_some() {
        return Err(invalid_input());
    }
    Ok(())
}

fn entry_exists(path: &Path) -> Result<bool, PortError> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(io_error(error)),
    }
}

fn reject_link(path: &Path) -> Result<(), PortError> {
    let metadata = fs::symlink_metadata(path).map_err(io_error)?;
    if metadata.file_type().is_symlink() || is_reparse_point(&metadata) {
        return Err(permission_denied());
    }
    Ok(())
}

fn reject_existing_link_components(path: &Path) -> Result<(), PortError> {
    let absolute = if path.is_absolute() {
        path.to_owned()
    } else {
        std::env::current_dir().map_err(io_error)?.join(path)
    };
    let mut current = PathBuf::new();
    for component in absolute.components() {
        match component {
            Component::Prefix(_) | Component::RootDir | Component::Normal(_) => {
                current.push(component)
            }
            Component::CurDir | Component::ParentDir => return Err(invalid_input()),
        }
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

#[cfg(unix)]
fn sync_directory(path: &Path) -> Result<(), PortError> {
    File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(io_error)
}

#[cfg(windows)]
fn sync_directory(_path: &Path) -> Result<(), PortError> {
    Ok(())
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
    PortError::failure(classification, Retryability::NonRetryable)
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
