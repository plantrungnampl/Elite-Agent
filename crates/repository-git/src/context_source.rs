use std::collections::BTreeMap;
use std::fmt;

#[cfg(feature = "test-seams")]
use std::sync::Arc;

use local_agent_terminal_application::{
    parse_policy_timestamp, PortError, RepositoryContextSource, RepositoryLocator, Retryability,
    SafeErrorClassification, SourceIndexMetadata, SourceSnapshot, SourceSnapshotItem,
    SourceSnapshotRequest,
};
use local_agent_terminal_domain::{ArtifactId, LineRange, Sha256Digest, SourceIdentity};
use sha2::{Digest, Sha256};

use crate::{hazards, paths, tools};

const MAX_CONTEXT_SOURCE_BYTES: usize = 1024 * 1024;

pub struct GitRepositoryContextSource {
    locator: RepositoryLocator,
    captured_at: String,
    #[cfg(feature = "test-seams")]
    capture_hook: Option<Arc<dyn Fn() + Send + Sync>>,
}

impl fmt::Debug for GitRepositoryContextSource {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GitRepositoryContextSource")
            .field("repository_id", &self.locator.repository_id)
            .field("captured_at", &self.captured_at)
            .finish_non_exhaustive()
    }
}

impl GitRepositoryContextSource {
    pub fn new(locator: RepositoryLocator, captured_at: &str) -> Result<Self, PortError> {
        parse_policy_timestamp(captured_at)?;
        paths::open_for_locator(&locator)?;
        Ok(Self {
            locator,
            captured_at: captured_at.to_owned(),
            #[cfg(feature = "test-seams")]
            capture_hook: None,
        })
    }

    #[cfg(feature = "test-seams")]
    pub fn with_capture_hook_for_test(mut self, hook: impl Fn() + Send + Sync + 'static) -> Self {
        self.capture_hook = Some(Arc::new(hook));
        self
    }

    fn run_capture_hook(&self) {
        #[cfg(feature = "test-seams")]
        if let Some(hook) = &self.capture_hook {
            hook();
        }
    }

    pub fn repository_fingerprint(&self) -> Result<Sha256Digest, PortError> {
        let captured = self.capture_coherent()?;
        context_fingerprint(&captured)
    }

    fn capture_coherent(&self) -> Result<tools::CapturedRepository, PortError> {
        let (repository, config) = paths::open_for_locator(&self.locator)?;
        reject_repository_hazards(&repository, &config)?;
        let before =
            tools::capture_context_repository(&repository).map_err(normalize_capture_error)?;
        self.run_capture_hook();
        let after =
            tools::capture_context_repository(&repository).map_err(normalize_capture_error)?;
        if before != after {
            return Err(conflict());
        }
        reject_repository_hazards(&repository, &config)?;
        paths::open_for_locator(&self.locator)?;
        validate_source_capture(&after)?;
        Ok(after)
    }
}

impl RepositoryContextSource for GitRepositoryContextSource {
    fn snapshot(&self, request: SourceSnapshotRequest) -> Result<SourceSnapshot, PortError> {
        let captured = self.capture_coherent()?;

        if request.revision != captured.head.as_str() {
            return Err(conflict());
        }
        let fingerprint_digest = context_fingerprint(&captured)?;
        if request.repository_fingerprint != fingerprint_digest {
            return Err(conflict());
        }

        let items = source_items(&request, &captured, &fingerprint_digest, &self.captured_at)?;
        Ok(SourceSnapshot { request, items })
    }
}

fn context_fingerprint(captured: &tools::CapturedRepository) -> Result<Sha256Digest, PortError> {
    let mut hasher = Sha256::new();
    update_hash_part(&mut hasher, b"context-source-fingerprint-v1")?;
    update_hash_part(&mut hasher, captured.head.as_str().as_bytes())?;
    update_hash_part(&mut hasher, captured.index_digest.as_str().as_bytes())?;
    for (path, flags) in tools::status_records(captured) {
        update_hash_part(&mut hasher, path)?;
        hasher.update(flags.to_be_bytes());
    }
    for (path, committed) in &captured.head_entries {
        update_hash_part(&mut hasher, path)?;
        let (layer, mode, bytes) = captured.worktree_entries.get(path).map_or_else(
            || {
                (
                    b"committed".as_slice(),
                    committed.mode,
                    committed.bytes.as_slice(),
                )
            },
            |worktree| {
                (
                    b"tracked-worktree".as_slice(),
                    worktree.mode,
                    worktree.bytes.as_slice(),
                )
            },
        );
        update_hash_part(&mut hasher, layer)?;
        hasher.update(mode.to_be_bytes());
        update_hash_part(&mut hasher, digest(bytes).as_str().as_bytes())?;
    }
    Sha256Digest::new(format!("sha256:{:x}", hasher.finalize())).map_err(|_| integrity())
}

fn update_hash_part(hasher: &mut Sha256, bytes: &[u8]) -> Result<(), PortError> {
    hasher.update(
        u64::try_from(bytes.len())
            .map_err(|_| integrity())?
            .to_be_bytes(),
    );
    hasher.update(bytes);
    Ok(())
}

fn source_items(
    request: &SourceSnapshotRequest,
    captured: &tools::CapturedRepository,
    fingerprint: &Sha256Digest,
    captured_at: &str,
) -> Result<Vec<SourceSnapshotItem>, PortError> {
    validate_logical_paths(captured)?;
    captured
        .head_entries
        .iter()
        .map(|(path_bytes, committed)| {
            let path = std::str::from_utf8(path_bytes).map_err(|_| permission())?;
            let overlay = captured
                .worktree_entries
                .get(path_bytes)
                .filter(|worktree| worktree.bytes != committed.bytes);
            let (bytes, revision, source_layer) = if let Some(overlay) = overlay {
                (
                    overlay.bytes.as_slice(),
                    format!("worktree:{}:{}", request.revision, fingerprint.as_str()),
                    "tracked-worktree",
                )
            } else {
                (
                    committed.bytes.as_slice(),
                    request.revision.clone(),
                    "committed",
                )
            };
            validate_text(bytes)?;
            let content_hash = digest(bytes);
            let stable_id = stable_item_id(
                request.task_id.as_str(),
                &revision,
                path,
                content_hash.as_str(),
            );
            let identity =
                SourceIdentity::new(request.project_id.clone(), &revision, path, content_hash)
                    .map_err(|_| integrity())?;
            let mut attributes = BTreeMap::from([
                ("baseRevision", request.revision.as_str()),
                ("sourceLayer", source_layer),
            ]);
            if overlay.is_some() {
                attributes.insert("workspaceFingerprint", fingerprint.as_str());
            }
            Ok(SourceSnapshotItem {
                document_id: format!("context-document-{stable_id}"),
                updated_at: captured_at.to_owned(),
                member_id: format!("context-member-{stable_id}"),
                content_artifact_id: ArtifactId::new(format!("context-source-{stable_id}"))
                    .map_err(|_| integrity())?,
                identity,
                metadata: SourceIndexMetadata::new(language(path), attributes)?,
                content: bytes.to_vec(),
                line_range: line_range(bytes)?,
                symbol: None,
            })
        })
        .collect()
}

fn validate_logical_paths(captured: &tools::CapturedRepository) -> Result<(), PortError> {
    let mut folded_paths = std::collections::BTreeSet::new();
    for path_bytes in captured.head_entries.keys() {
        let path = std::str::from_utf8(path_bytes).map_err(|_| permission())?;
        if path.is_empty()
            || path.contains(['\\', '\0'])
            || path
                .split('/')
                .any(|component| !paths::valid_component(component))
            || !folded_paths.insert(path.to_lowercase())
        {
            return Err(permission());
        }
    }
    Ok(())
}

fn validate_source_capture(captured: &tools::CapturedRepository) -> Result<(), PortError> {
    validate_logical_paths(captured)?;
    for (path, committed) in &captured.head_entries {
        let bytes = captured
            .worktree_entries
            .get(path)
            .map(|worktree| worktree.bytes.as_slice())
            .unwrap_or(committed.bytes.as_slice());
        validate_text(bytes)?;
    }
    Ok(())
}

fn reject_repository_hazards(
    repository: &git2::Repository,
    config: &git2::Config,
) -> Result<(), PortError> {
    if !hazards::scan(repository, config)?.is_empty()
        || hazards::structured_attributes_present(repository)?
    {
        Err(permission())
    } else {
        Ok(())
    }
}

fn validate_text(bytes: &[u8]) -> Result<(), PortError> {
    if bytes.is_empty()
        || bytes.len() > MAX_CONTEXT_SOURCE_BYTES
        || bytes.contains(&0)
        || std::str::from_utf8(bytes).is_err()
    {
        Err(permission())
    } else {
        Ok(())
    }
}

fn line_range(bytes: &[u8]) -> Result<Option<LineRange>, PortError> {
    let text = std::str::from_utf8(bytes).map_err(|_| permission())?;
    let end = u32::try_from(text.lines().count().max(1)).map_err(|_| permission())?;
    LineRange::new(1, end).map(Some).map_err(|_| integrity())
}

fn language(path: &str) -> Option<&'static str> {
    match path.rsplit_once('.').map(|(_, extension)| extension) {
        Some("rs") => Some("rust"),
        Some("ts" | "tsx") => Some("typescript"),
        Some("js" | "jsx") => Some("javascript"),
        Some("md") => Some("markdown"),
        Some("json") => Some("json"),
        Some("toml") => Some("toml"),
        Some("yml" | "yaml") => Some("yaml"),
        Some("py") => Some("python"),
        _ => None,
    }
}

fn stable_item_id(task_id: &str, revision: &str, path: &str, content_hash: &str) -> String {
    let mut hasher = Sha256::new();
    for part in [task_id, revision, path, content_hash] {
        hasher.update((part.len() as u64).to_be_bytes());
        hasher.update(part.as_bytes());
    }
    format!("{:x}", hasher.finalize())
}

fn digest(bytes: &[u8]) -> Sha256Digest {
    Sha256Digest::new(format!("sha256:{:x}", Sha256::digest(bytes)))
        .expect("SHA-256 formatting is valid")
}

fn normalize_capture_error(error: PortError) -> PortError {
    match error.safe_classification() {
        SafeErrorClassification::Conflict => conflict(),
        _ => permission(),
    }
}

fn conflict() -> PortError {
    PortError::failure(
        SafeErrorClassification::Conflict,
        Retryability::NonRetryable,
    )
}

fn permission() -> PortError {
    PortError::failure(
        SafeErrorClassification::PermissionDenied,
        Retryability::NonRetryable,
    )
}

fn integrity() -> PortError {
    PortError::failure(
        SafeErrorClassification::IntegrityFailure,
        Retryability::NonRetryable,
    )
}
