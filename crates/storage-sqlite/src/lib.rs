#![forbid(unsafe_code)]

mod agent_store;
mod approval_store;
mod artifact_journal;
mod context_store;
mod deliberation_boundary_store;
mod deliberation_budget_store;
mod deliberation_dispatch_store;
mod deliberation_store;
mod event_store;
mod health;
mod lease_store;
mod migrations;
mod plan_approval_store;
mod policy_store;
mod project_store;
mod task_query;
mod tool_activity;
mod tool_execution_store;
mod workspace_store;

use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use local_agent_terminal_application::{
    ArtifactRootReader, Clock, PlanApprovalCurrentAuthoritySource, PortError,
};
use rusqlite::Connection;

pub use agent_store::{canonical_agent_run_config_artifact, StoredAgentRunUsage};
pub use context_store::StoredContextPackageView;
pub use health::{artifact_root_health, ArtifactRootIssue, DatabaseHealth, DatabaseIssue};
pub use lease_store::CoreSystemRunRequest;
pub use migrations::{migration_checksum, OpenError};

#[derive(Clone)]
pub struct SqliteStore {
    path: PathBuf,
    artifact_reader: Option<Arc<dyn ArtifactRootReader>>,
    plan_approval_authority_source: Option<Arc<dyn PlanApprovalCurrentAuthoritySource>>,
}

impl fmt::Debug for SqliteStore {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SqliteStore")
            .field("path", &self.path)
            .field(
                "artifact_reader_configured",
                &self.artifact_reader.is_some(),
            )
            .field(
                "plan_approval_authority_source_configured",
                &self.plan_approval_authority_source.is_some(),
            )
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PragmaSettings {
    pub foreign_keys: bool,
    pub journal_mode: String,
    pub synchronous: i64,
    pub busy_timeout_ms: i64,
    pub wal_autocheckpoint: i64,
    pub recursive_triggers: bool,
}

impl SqliteStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, OpenError> {
        let store = Self {
            path: path.as_ref().to_owned(),
            artifact_reader: None,
            plan_approval_authority_source: None,
        };
        let mut connection = Connection::open(&store.path)?;
        migrations::validate_or_migrate(&mut connection)?;
        initialize_connection(&connection)?;
        Ok(store)
    }

    #[must_use]
    pub fn with_artifact_reader(mut self, reader: Arc<dyn ArtifactRootReader>) -> Self {
        self.artifact_reader = Some(reader);
        self
    }

    #[must_use]
    pub fn with_plan_approval_authority_source(
        mut self,
        source: Arc<dyn PlanApprovalCurrentAuthoritySource>,
    ) -> Self {
        self.plan_approval_authority_source = Some(source);
        self
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
            recursive_triggers: connection
                .query_row("PRAGMA recursive_triggers", [], |row| row.get(0))?,
        })
    }

    pub(crate) fn connection(&self) -> Result<Connection, OpenError> {
        let connection = Connection::open(&self.path)?;
        initialize_connection(&connection)?;
        Ok(connection)
    }

    pub(crate) fn plan_approval_authority_source(
        &self,
    ) -> Option<&dyn PlanApprovalCurrentAuthoritySource> {
        self.plan_approval_authority_source.as_deref()
    }

    pub(crate) fn artifact_reader(&self) -> Option<&dyn ArtifactRootReader> {
        self.artifact_reader.as_deref()
    }
}

impl Clock for SqliteStore {
    fn now_utc(&self) -> Result<String, PortError> {
        let connection = self.connection().map_err(event_store::open_error_to_port)?;
        connection
            .query_row("SELECT strftime('%Y-%m-%dT%H:%M:%fZ', 'now')", [], |row| {
                row.get(0)
            })
            .map_err(event_store::sqlite_error_to_port)
    }
}

fn initialize_connection(connection: &Connection) -> Result<(), OpenError> {
    connection.pragma_update(None, "foreign_keys", "ON")?;
    connection.query_row("PRAGMA journal_mode = WAL", [], |_| Ok(()))?;
    connection.pragma_update(None, "synchronous", "FULL")?;
    connection.pragma_update(None, "busy_timeout", 5000)?;
    connection.pragma_update(None, "wal_autocheckpoint", 1000)?;
    connection.pragma_update(None, "recursive_triggers", "ON")?;
    Ok(())
}
