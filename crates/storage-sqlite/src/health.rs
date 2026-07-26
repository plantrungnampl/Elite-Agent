use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::SqliteStore;

static NEXT_PROBE: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DatabaseHealth {
    Healthy,
    Unhealthy(DatabaseIssue),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DatabaseIssue {
    Unreadable,
    IntegrityCheckFailed(String),
    ForeignKeyViolation,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArtifactRootIssue {
    Missing,
    NotDirectory,
    NotWritable,
}

impl SqliteStore {
    pub fn database_health(&self) -> DatabaseHealth {
        let Ok(connection) = self.connection() else {
            return DatabaseHealth::Unhealthy(DatabaseIssue::Unreadable);
        };
        let integrity: rusqlite::Result<String> =
            connection.query_row("PRAGMA integrity_check", [], |row| row.get(0));
        match integrity {
            Ok(result) if result == "ok" => {}
            Ok(result) => {
                return DatabaseHealth::Unhealthy(DatabaseIssue::IntegrityCheckFailed(result));
            }
            Err(_) => return DatabaseHealth::Unhealthy(DatabaseIssue::Unreadable),
        }
        let foreign_key_violation: rusqlite::Result<bool> = connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM pragma_foreign_key_check)",
            [],
            |row| row.get(0),
        );
        match foreign_key_violation {
            Ok(false) => DatabaseHealth::Healthy,
            Ok(true) => DatabaseHealth::Unhealthy(DatabaseIssue::ForeignKeyViolation),
            Err(_) => DatabaseHealth::Unhealthy(DatabaseIssue::Unreadable),
        }
    }
}

pub fn artifact_root_health(root: &Path) -> Result<(), ArtifactRootIssue> {
    let metadata = fs::symlink_metadata(root).map_err(|error| {
        if error.kind() == std::io::ErrorKind::NotFound {
            ArtifactRootIssue::Missing
        } else {
            ArtifactRootIssue::NotWritable
        }
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(ArtifactRootIssue::NotDirectory);
    }

    let probe = root.join(format!(
        ".write-probe-{}-{}",
        std::process::id(),
        NEXT_PROBE.fetch_add(1, Ordering::Relaxed)
    ));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&probe)
        .map_err(|_| ArtifactRootIssue::NotWritable)?;
    let write_result = file.write_all(b"probe").and_then(|()| file.sync_all());
    drop(file);
    let remove_result = fs::remove_file(&probe);
    if write_result.is_err() || remove_result.is_err() {
        let _ = fs::remove_file(probe);
        return Err(ArtifactRootIssue::NotWritable);
    }
    Ok(())
}
