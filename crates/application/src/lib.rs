#![forbid(unsafe_code)]

mod append_events;
mod dto;
mod error;
mod ports;

pub use append_events::AppendEvents;
pub use dto::{
    DiagnosticSeverityDto, LocalDiagnosticDto, ObservationClassDto, RecoveryActionDto,
    StartupIssueDto, StartupStateDto, StartupStatusDto, TrustLabelDto,
};
pub use error::{PortError, Retryability, SafeErrorClassification};
pub use ports::{
    AppendOperation, AppendResult, ArtifactContent, ArtifactJournal, ArtifactJournalEntry,
    ArtifactJournalInvalidation, ArtifactJournalStatus, ArtifactJournalTransition, ArtifactRef,
    ArtifactStore, ArtifactUnavailableState, ArtifactWriteReservation, Clock, EventStore,
    IdGenerator, NewArtifact, NewEvent, ProjectionChange, ReservedArtifact,
};
