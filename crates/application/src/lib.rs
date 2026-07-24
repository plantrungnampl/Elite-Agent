#![forbid(unsafe_code)]

mod append_events;
mod dto;
mod error;
mod ports;

pub use append_events::AppendEvents;
pub use dto::{
    LocalDiagnosticDto, RecoveryActionDto, StartupIssueDto, StartupStateDto, StartupStatusDto,
};
pub use error::{AppendEventsError, PortError, Retryability, SafeErrorClassification};
pub use ports::{
    AppendOperation, AppendResult, ArtifactContent, ArtifactJournal, ArtifactJournalEntry,
    ArtifactJournalStatus, ArtifactJournalTransition, ArtifactRef, ArtifactStore, Clock,
    EventStore, IdGenerator, NewArtifact, NewEvent, ProjectionChange,
};
