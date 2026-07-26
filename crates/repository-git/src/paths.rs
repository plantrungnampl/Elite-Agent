#[cfg(windows)]
use std::fs::OpenOptions;
use std::fs::{self, File};
use std::path::{Component, Path, PathBuf};

use git2::{Config, ErrorCode, Repository, RepositoryOpenFlags};
use local_agent_terminal_application::{
    ManagedWorktreePath, ObjectFormat, PortError, RepositoryLocator, Retryability,
    SafeErrorClassification,
};
use local_agent_terminal_domain::RepositoryId;
use sha2::{Digest, Sha256};

use crate::GitRepositoryGateway;

pub(crate) fn new_gateway(
    trusted_workspace_root: &Path,
    excluded_roots: &[PathBuf],
) -> Result<GitRepositoryGateway, PortError> {
    validate_external_path(trusted_workspace_root)?;
    for root in excluded_roots {
        validate_external_path(root)?;
    }
    let trusted_workspace_root = canonical_directory(trusted_workspace_root)?;
    let excluded_roots = excluded_roots
        .iter()
        .map(|root| canonical_directory(root))
        .collect::<Result<Vec<_>, _>>()?;
    let trusted_root_id = digest_id(&trusted_workspace_root.to_string_lossy());
    Ok(GitRepositoryGateway {
        trusted_workspace_root,
        excluded_roots,
        trusted_root_id,
        calls: std::sync::Mutex::new(()),
    })
}

pub(crate) fn locate(
    gateway: &GitRepositoryGateway,
    workdir: &Path,
) -> Result<RepositoryLocator, PortError> {
    validate_external_path(workdir)?;
    let workdir = canonical_directory(workdir)?;
    let repository = open_repository(&workdir)?;
    let common_dir = canonical_directory(repository.commondir())?;
    let actual_workdir = repository.workdir().ok_or_else(|| {
        failure(
            SafeErrorClassification::Conflict,
            Retryability::NonRetryable,
        )
    })?;
    let actual_workdir = canonical_directory(actual_workdir)?;
    if actual_workdir != workdir {
        return Err(conflict());
    }
    let object_format = object_format(repository.object_format())?;
    let stable_identity = identity(&common_dir, object_format);
    let repository_id =
        RepositoryId::new(format!("repo-{stable_identity}")).map_err(|_| integrity())?;
    if is_excluded(gateway, &workdir) {
        return Err(conflict());
    }
    Ok(RepositoryLocator {
        repository_id,
        stable_identity,
        canonical_workdir: workdir,
        canonical_common_dir: common_dir,
        object_format,
    })
}

pub(crate) fn open_for_locator(
    locator: &RepositoryLocator,
) -> Result<(Repository, Config), PortError> {
    let workdir = canonical_directory(&locator.canonical_workdir)?;
    let repository = open_repository(&workdir)?;
    let actual_workdir = repository.workdir().ok_or_else(|| {
        failure(
            SafeErrorClassification::Conflict,
            Retryability::NonRetryable,
        )
    })?;
    if canonical_directory(actual_workdir)? != workdir {
        return Err(conflict());
    }
    let common_dir = canonical_directory(repository.commondir())?;
    if common_dir != locator.canonical_common_dir {
        return Err(conflict());
    }
    let format = object_format(repository.object_format())?;
    if format != locator.object_format || identity(&common_dir, format) != locator.stable_identity {
        return Err(conflict());
    }
    let expected_id = format!("repo-{}", locator.stable_identity);
    if locator.repository_id.as_str() != expected_id {
        return Err(conflict());
    }
    let config_path = repository.path().join("config");
    let config_metadata = fs::symlink_metadata(&config_path).map_err(|_| not_found())?;
    if !config_metadata.is_file() || config_metadata.file_type().is_symlink() {
        return Err(conflict());
    }
    let config_parent = canonical_directory(config_path.parent().ok_or_else(|| {
        failure(
            SafeErrorClassification::IntegrityFailure,
            Retryability::NonRetryable,
        )
    })?)?;
    if !is_within(&common_dir, &config_parent) {
        return Err(conflict());
    }
    let config = Config::open(&config_path).map_err(|_| unavailable())?;
    repository.set_config(&config).map_err(|_| unavailable())?;
    Ok((repository, config))
}

pub(crate) fn managed_path(
    gateway: &GitRepositoryGateway,
    path: &ManagedWorktreePath,
) -> Result<PathBuf, PortError> {
    let target = recovery_path(gateway, path)?;
    match fs::symlink_metadata(&target) {
        Ok(_) => return Err(conflict()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(_) => return Err(unavailable()),
    }
    Ok(target)
}

pub(crate) fn recovery_path(
    gateway: &GitRepositoryGateway,
    path: &ManagedWorktreePath,
) -> Result<PathBuf, PortError> {
    if path.trusted_root_id != gateway.trusted_root_id
        || path.relative_leaf.is_absolute()
        || path.relative_leaf.as_os_str().is_empty()
        || !safe_relative(&path.relative_leaf)
    {
        return Err(invalid());
    }
    let target = gateway.trusted_workspace_root.join(&path.relative_leaf);
    let parent = target.parent().ok_or_else(invalid)?;
    let parent = canonical_directory(parent)?;
    if !is_within(&gateway.trusted_workspace_root, &parent) {
        return Err(conflict());
    }
    for component in path.relative_leaf.components() {
        if let Component::Normal(value) = component {
            if !valid_component(&value.to_string_lossy()) {
                return Err(invalid());
            }
        }
    }
    if is_excluded(gateway, &target) {
        return Err(conflict());
    }
    let leaf = target.file_name().ok_or_else(invalid)?;
    let entries = fs::read_dir(&parent).map_err(|_| permission())?;
    for entry in entries {
        let entry = entry.map_err(|_| unavailable())?;
        let existing = entry.file_name();
        if existing != leaf
            && existing
                .to_string_lossy()
                .eq_ignore_ascii_case(&leaf.to_string_lossy())
        {
            return Err(conflict());
        }
    }
    Ok(target)
}

pub(crate) struct DirectoryGuard {
    path: PathBuf,
    _handle: File,
}

impl DirectoryGuard {
    pub(crate) fn open(path: &Path) -> Result<Self, PortError> {
        let handle = open_directory_without_delete_sharing(path)?;
        let canonical = canonical_directory(path)?;
        Ok(Self {
            path: canonical,
            _handle: handle,
        })
    }

    pub(crate) fn verify(&self) -> Result<(), PortError> {
        if canonical_directory(&self.path)? != self.path {
            return Err(conflict());
        }
        Ok(())
    }
}

#[cfg(windows)]
fn open_directory_without_delete_sharing(path: &Path) -> Result<File, PortError> {
    use std::os::windows::fs::OpenOptionsExt;

    const FILE_SHARE_READ: u32 = 0x0000_0001;
    const FILE_SHARE_WRITE: u32 = 0x0000_0002;
    const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
    const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;

    let mut options = OpenOptions::new();
    options
        .read(true)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT);
    options.open(path).map_err(|_| permission())
}

#[cfg(not(windows))]
fn open_directory_without_delete_sharing(path: &Path) -> Result<File, PortError> {
    File::open(path).map_err(|_| permission())
}

pub(crate) fn validate_existing_target(
    gateway: &GitRepositoryGateway,
    path: &Path,
) -> Result<PathBuf, PortError> {
    let canonical = canonical_directory(path)?;
    if !is_within(&gateway.trusted_workspace_root, &canonical) || is_excluded(gateway, &canonical) {
        return Err(conflict());
    }
    Ok(canonical)
}

pub(crate) fn canonical_directory(path: &Path) -> Result<PathBuf, PortError> {
    if !path.is_absolute() || !safe_absolute(path) {
        return Err(invalid());
    }
    let metadata = fs::symlink_metadata(path).map_err(|_| not_found())?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(conflict());
    }
    reject_reparse_components(path)?;
    fs::canonicalize(path).map_err(|_| unavailable())
}

pub(crate) fn open_repository(path: &Path) -> Result<Repository, PortError> {
    reject_git_environment()?;
    Repository::open_ext(
        path,
        RepositoryOpenFlags::NO_SEARCH,
        std::iter::empty::<&std::ffi::OsStr>(),
    )
    .map_err(map_git_error)
}

pub(crate) fn is_within(root: &Path, candidate: &Path) -> bool {
    candidate.strip_prefix(root).is_ok()
}

pub(crate) fn is_excluded(gateway: &GitRepositoryGateway, candidate: &Path) -> bool {
    gateway
        .excluded_roots
        .iter()
        .any(|root| is_within(root, candidate))
}

pub(crate) fn object_format(format: git2::ObjectFormat) -> Result<ObjectFormat, PortError> {
    match format {
        git2::ObjectFormat::Sha1 => Ok(ObjectFormat::Sha1),
        git2::ObjectFormat::Sha256 => Ok(ObjectFormat::Sha256),
    }
}

pub(crate) fn identity(common_dir: &Path, format: ObjectFormat) -> String {
    let mut hasher = Sha256::new();
    hasher.update(common_dir.as_os_str().to_string_lossy().as_bytes());
    hasher.update([0]);
    hasher.update(format.as_str().as_bytes());
    hex_digest(hasher.finalize().as_slice())
}

pub(crate) fn digest_id(value: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(value.as_bytes());
    hex_digest(hasher.finalize().as_slice())
}

pub(crate) fn hex_digest(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

pub(crate) fn safe_relative(path: &Path) -> bool {
    path.components().all(|component| {
        matches!(component, Component::Normal(_))
            && !component.as_os_str().to_string_lossy().is_empty()
    })
}

fn safe_absolute(path: &Path) -> bool {
    path.components().all(|component| match component {
        Component::Prefix(prefix) => {
            #[cfg(windows)]
            {
                !matches!(
                    prefix.kind(),
                    std::path::Prefix::Verbatim(_)
                        | std::path::Prefix::VerbatimUNC(_, _)
                        | std::path::Prefix::UNC(_, _)
                        | std::path::Prefix::DeviceNS(_)
                )
            }
            #[cfg(not(windows))]
            {
                let _ = prefix;
                true
            }
        }
        Component::RootDir | Component::Normal(_) => true,
        Component::CurDir | Component::ParentDir => false,
    })
}

fn validate_external_path(path: &Path) -> Result<(), PortError> {
    if !path.is_absolute() {
        return Err(invalid());
    }
    #[cfg(windows)]
    {
        let Some(Component::Prefix(prefix)) = path.components().next() else {
            return Err(invalid());
        };
        if !matches!(prefix.kind(), std::path::Prefix::Disk(_)) {
            return Err(invalid());
        }
    }
    Ok(())
}

fn valid_component(value: &str) -> bool {
    if value.is_empty()
        || value.ends_with(['.', ' '])
        || value
            .chars()
            .any(|character| character.is_control() || r#"<>:"/\|?*"#.contains(character))
    {
        return false;
    }
    let stem = value
        .split('.')
        .next()
        .unwrap_or_default()
        .to_ascii_uppercase();
    !matches!(stem.as_str(), "CON" | "PRN" | "AUX" | "NUL")
        && !(stem.len() == 4
            && (stem.starts_with("COM") || stem.starts_with("LPT"))
            && matches!(stem.as_bytes()[3], b'1'..=b'9'))
}

fn reject_git_environment() -> Result<(), PortError> {
    for (name, _) in std::env::vars_os() {
        if name
            .to_string_lossy()
            .to_ascii_uppercase()
            .starts_with("GIT_")
        {
            return Err(conflict());
        }
    }
    Ok(())
}

fn reject_reparse_components(path: &Path) -> Result<(), PortError> {
    let mut ancestors = path.ancestors().collect::<Vec<_>>();
    ancestors.reverse();
    for current in ancestors {
        let metadata = fs::symlink_metadata(current).map_err(|_| not_found())?;
        if metadata.file_type().is_symlink() {
            return Err(conflict());
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::MetadataExt;
            const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
            if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
                return Err(conflict());
            }
        }
    }
    Ok(())
}

pub(crate) fn map_git_error(error: git2::Error) -> PortError {
    match error.code() {
        ErrorCode::NotFound => not_found(),
        ErrorCode::Exists | ErrorCode::Modified | ErrorCode::Locked => conflict(),
        ErrorCode::UnbornBranch => conflict(),
        ErrorCode::Auth | ErrorCode::Certificate => permission(),
        ErrorCode::InvalidSpec | ErrorCode::Invalid => invalid(),
        _ => unavailable(),
    }
}

pub(crate) fn invalid() -> PortError {
    failure(
        SafeErrorClassification::InvalidInput,
        Retryability::NonRetryable,
    )
}

pub(crate) fn conflict() -> PortError {
    failure(
        SafeErrorClassification::Conflict,
        Retryability::NonRetryable,
    )
}

pub(crate) fn unavailable() -> PortError {
    failure(
        SafeErrorClassification::Unavailable,
        Retryability::Retryable,
    )
}

pub(crate) fn not_found() -> PortError {
    failure(
        SafeErrorClassification::NotFound,
        Retryability::NonRetryable,
    )
}

pub(crate) fn permission() -> PortError {
    failure(
        SafeErrorClassification::PermissionDenied,
        Retryability::NonRetryable,
    )
}

pub(crate) fn integrity() -> PortError {
    failure(
        SafeErrorClassification::IntegrityFailure,
        Retryability::NonRetryable,
    )
}

pub(crate) fn internal() -> PortError {
    failure(
        SafeErrorClassification::Internal,
        Retryability::NonRetryable,
    )
}

pub(crate) fn failure(
    classification: SafeErrorClassification,
    retryability: Retryability,
) -> PortError {
    PortError::failure(classification, retryability)
}
