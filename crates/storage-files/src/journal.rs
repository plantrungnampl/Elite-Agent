use std::io::Write;

use local_agent_terminal_application::{
    ArtifactJournal, ArtifactJournalStatus, ArtifactJournalTransition, ArtifactRef,
    ArtifactWriteReservation, Clock, PortError,
};

use crate::content_address::ContentAddressedArtifactStore;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FaultPoint {
    BeforeWrite,
    AfterWrite,
    AfterFlush,
    AfterJournalTransition,
    AfterRename,
    BeforeCompletionRecord,
}

pub struct JournaledArtifactWriter<'a> {
    store: &'a ContentAddressedArtifactStore,
    journal: &'a dyn ArtifactJournal,
    clock: &'a dyn Clock,
}

impl<'a> JournaledArtifactWriter<'a> {
    pub fn new(
        store: &'a ContentAddressedArtifactStore,
        journal: &'a dyn ArtifactJournal,
        clock: &'a dyn Clock,
    ) -> Self {
        Self {
            store,
            journal,
            clock,
        }
    }

    pub fn write(
        &self,
        reservation: ArtifactWriteReservation,
        content: &[u8],
    ) -> Result<ArtifactRef, PortError> {
        self.write_with_fault(reservation, content, |_| Ok(()))
    }

    pub fn write_with_fault(
        &self,
        reservation: ArtifactWriteReservation,
        content: &[u8],
        mut fault: impl FnMut(FaultPoint) -> Result<(), PortError>,
    ) -> Result<ArtifactRef, PortError> {
        self.store.validate_reservation(&reservation, content)?;
        self.journal.reserve(reservation.clone())?;
        fault(FaultPoint::BeforeWrite)?;

        let staging = self.store.staging_path(&reservation.temp_name)?;
        let mut file = self.store.create_staging(&reservation.temp_name)?;
        file.write_all(content)
            .map_err(super::content_address::io_error)?;
        fault(FaultPoint::AfterWrite)?;
        file.flush().map_err(super::content_address::io_error)?;
        file.sync_all().map_err(super::content_address::io_error)?;
        fault(FaultPoint::AfterFlush)?;
        drop(file);

        if !self.store.verify(
            &staging,
            &reservation.artifact.content_hash,
            reservation.artifact.size_bytes,
        )? {
            self.store.quarantine(&staging)?;
            self.transition(
                &reservation.operation_id,
                ArtifactJournalStatus::Intent,
                ArtifactJournalStatus::Quarantined,
            )?;
            return Err(super::content_address::integrity_failure());
        }
        self.transition(
            &reservation.operation_id,
            ArtifactJournalStatus::Intent,
            ArtifactJournalStatus::Staging,
        )?;
        fault(FaultPoint::AfterJournalTransition)?;

        self.store.publish(
            &staging,
            &reservation.artifact.content_hash,
            reservation.artifact.size_bytes,
        )?;
        fault(FaultPoint::AfterRename)?;
        self.transition(
            &reservation.operation_id,
            ArtifactJournalStatus::Staging,
            ArtifactJournalStatus::Renamed,
        )?;
        fault(FaultPoint::BeforeCompletionRecord)?;
        self.transition(
            &reservation.operation_id,
            ArtifactJournalStatus::Renamed,
            ArtifactJournalStatus::Completed,
        )?;
        self.store.reference_for(
            &reservation.artifact.content_hash,
            reservation.artifact.size_bytes,
        )
    }

    fn transition(
        &self,
        operation_id: &str,
        expected_status: ArtifactJournalStatus,
        next_status: ArtifactJournalStatus,
    ) -> Result<(), PortError> {
        let updated_at = self.clock.now_utc()?;
        self.journal.transition(ArtifactJournalTransition {
            operation_id: operation_id.to_owned(),
            expected_status,
            next_status,
            completed_at: (next_status == ArtifactJournalStatus::Completed)
                .then(|| updated_at.clone()),
            updated_at,
            error: None,
        })
    }
}
