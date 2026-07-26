#![forbid(unsafe_code)]

mod artifact_journal;
mod event_store;
mod health;
mod migrations;

use std::path::{Path, PathBuf};

use rusqlite::Connection;

pub use health::{artifact_root_health, ArtifactRootIssue, DatabaseHealth, DatabaseIssue};
pub use migrations::{migration_checksum, OpenError};

#[derive(Debug, Clone)]
pub struct SqliteStore {
    path: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PragmaSettings {
    pub foreign_keys: bool,
    pub journal_mode: String,
    pub synchronous: i64,
    pub busy_timeout_ms: i64,
    pub wal_autocheckpoint: i64,
}

impl SqliteStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, OpenError> {
        let store = Self {
            path: path.as_ref().to_owned(),
        };
        let mut connection = store.connection()?;
        migrations::validate_or_migrate(&mut connection)?;
        Ok(store)
    }

    pub fn pragma_settings(&self) -> Result<PragmaSettings, OpenError> {
        let connection = self.connection()?;
        Ok(PragmaSettings {
            foreign_keys: connection.query_row("PRAGMA foreign_keys", [], |row| row.get(0))?,
            journal_mode: connection.query_row("PRAGMA journal_mode", [], |row| row.get(0))?,
            synchronous: connection.query_row("PRAGMA synchronous", [], |row| row.get(0))?,
            busy_timeout_ms: connection.query_row("PRAGMA busy_timeout", [], |row| row.get(0))?,
            wal_autocheckpoint: connection
                .query_row("PRAGMA wal_autocheckpoint", [], |row| row.get(0))?,
        })
    }

    pub(crate) fn connection(&self) -> Result<Connection, OpenError> {
        let connection = Connection::open(&self.path)?;
        initialize_connection(&connection)?;
        Ok(connection)
    }
}

fn initialize_connection(connection: &Connection) -> Result<(), OpenError> {
    connection.pragma_update(None, "foreign_keys", "ON")?;
    connection.query_row("PRAGMA journal_mode = WAL", [], |_| Ok(()))?;
    connection.pragma_update(None, "synchronous", "FULL")?;
    connection.pragma_update(None, "busy_timeout", 5000)?;
    connection.pragma_update(None, "wal_autocheckpoint", 1000)?;
    Ok(())
}
