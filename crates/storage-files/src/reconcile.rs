use std::collections::HashSet;
use std::ffi::OsString;

use local_agent_terminal_application::{
    ArtifactJournal, ArtifactJournalEntry, ArtifactJournalInvalidation, ArtifactJournalStatus,
    ArtifactJournalTransition, ArtifactUnavailableState, Clock, PortError,
};
use serde_json::json;

use crate::content_address::ContentAddressedArtifactStore;
use crate::content_address::PublishError;

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct ReconcileReport {
    pub completed: usize,
    pub aborted: usize,
    pub quarantined: usize,
    pub invalidated: usize,
}

pub fn reconcile_artifacts(
    store: &ContentAddressedArtifactStore,
    journal: &dyn ArtifactJournal,
    clock: &dyn Clock,
) -> Result<ReconcileReport, PortError> {
    let mut report = ReconcileReport::default();
    let incomplete = journal.incomplete()?;
    let completed = journal.completed()?;
    let recognized: HashSet<OsString> = incomplete
        .iter()
        .chain(&completed)
        .filter(|entry| {
            store
                .validate_reservation_metadata(&entry.reservation)
                .is_ok()
        })
        .map(|entry| OsString::from(&entry.reservation.temp_name))
        .collect();
    for entry in &incomplete {
        reconcile_incomplete(store, journal, clock, entry, &mut report)?;
    }
    for entry in &completed {
        reconcile_completed(store, journal, clock, entry, &mut report)?;
    }
    for staging in store.staging_entries()? {
        if !recognized.contains(staging.file_name().expect("staging entry has a file name")) {
            store.quarantine(&staging)?;
            report.quarantined += 1;
        }
    }
    Ok(report)
}

fn reconcile_incomplete(
    store: &ContentAddressedArtifactStore,
    journal: &dyn ArtifactJournal,
    clock: &dyn Clock,
    entry: &ArtifactJournalEntry,
    report: &mut ReconcileReport,
) -> Result<(), PortError> {
    if intent_disagrees_with_metadata(entry) {
        quarantine_staging(store, entry)?;
        raw_transition_with_error(
            journal,
            clock,
            &entry.reservation.operation_id,
            entry.status,
            ArtifactJournalStatus::Quarantined,
            Some(json!({"kind": "intent_metadata_mismatch"})),
        )?;
        report.quarantined += 1;
        return Ok(());
    }
    if store
        .validate_reservation_metadata(&entry.reservation)
        .is_err()
    {
        transition(journal, clock, entry, ArtifactJournalStatus::Quarantined)?;
        report.quarantined += 1;
        return Ok(());
    }
    let artifact = &entry.reservation.artifact;
    let staging = store.staging_path(&entry.reservation.temp_name)?;
    let target = store.object_path(&artifact.content_hash)?;

    if store.entry_exists(&target)? {
        if !store.verify(&target, &artifact.content_hash, artifact.size_bytes)? {
            store.quarantine(&target)?;
            if store.entry_exists(&staging)? {
                store.quarantine(&staging)?;
            }
            transition(journal, clock, entry, ArtifactJournalStatus::Quarantined)?;
            report.quarantined += 1;
            return Ok(());
        }
        if store.entry_exists(&staging)? {
            if store.verify(&staging, &artifact.content_hash, artifact.size_bytes)? {
                store.discard_staging(&staging)?;
            } else {
                store.quarantine(&staging)?;
            }
        }
        complete(journal, clock, entry)?;
        report.completed += 1;
        return Ok(());
    }

    if !store.entry_exists(&staging)? {
        let terminal = if entry.status == ArtifactJournalStatus::Renamed {
            ArtifactJournalStatus::Quarantined
        } else {
            ArtifactJournalStatus::Aborted
        };
        transition(journal, clock, entry, terminal)?;
        if terminal == ArtifactJournalStatus::Aborted {
            report.aborted += 1;
        } else {
            report.quarantined += 1;
        }
        return Ok(());
    }
    if !store.verify(&staging, &artifact.content_hash, artifact.size_bytes)? {
        store.quarantine(&staging)?;
        transition(journal, clock, entry, ArtifactJournalStatus::Quarantined)?;
        report.quarantined += 1;
        return Ok(());
    }

    if entry.status == ArtifactJournalStatus::Intent {
        raw_transition(
            journal,
            clock,
            &entry.reservation.operation_id,
            ArtifactJournalStatus::Intent,
            ArtifactJournalStatus::Staging,
        )?;
    }
    let publish_status = if entry.status == ArtifactJournalStatus::Renamed {
        ArtifactJournalStatus::Renamed
    } else {
        ArtifactJournalStatus::Staging
    };
    match store.publish(&staging, &artifact.content_hash, artifact.size_bytes) {
        Ok(_) => {}
        Err(PublishError::Quarantined) => {
            raw_transition_with_error(
                journal,
                clock,
                &entry.reservation.operation_id,
                publish_status,
                ArtifactJournalStatus::Quarantined,
                Some(json!({"kind": "object_invalid_after_rename"})),
            )?;
            report.quarantined += 1;
            return Ok(());
        }
        Err(error) => return Err(error.into_port_error()),
    }
    if entry.status != ArtifactJournalStatus::Renamed {
        raw_transition(
            journal,
            clock,
            &entry.reservation.operation_id,
            ArtifactJournalStatus::Staging,
            ArtifactJournalStatus::Renamed,
        )?;
    }
    raw_transition(
        journal,
        clock,
        &entry.reservation.operation_id,
        ArtifactJournalStatus::Renamed,
        ArtifactJournalStatus::Completed,
    )?;
    report.completed += 1;
    Ok(())
}

fn reconcile_completed(
    store: &ContentAddressedArtifactStore,
    journal: &dyn ArtifactJournal,
    clock: &dyn Clock,
    entry: &ArtifactJournalEntry,
    report: &mut ReconcileReport,
) -> Result<(), PortError> {
    if intent_disagrees_with_metadata(entry) {
        quarantine_staging(store, entry)?;
        invalidate(
            journal,
            clock,
            entry,
            ArtifactUnavailableState::Quarantined,
            "intent_metadata_mismatch",
        )?;
        report.invalidated += 1;
        return Ok(());
    }
    if store
        .validate_reservation_metadata(&entry.reservation)
        .is_err()
    {
        invalidate(
            journal,
            clock,
            entry,
            ArtifactUnavailableState::Quarantined,
            "invalid_metadata",
        )?;
        report.invalidated += 1;
        return Ok(());
    }
    let artifact = &entry.reservation.artifact;
    let target = store.object_path(&artifact.content_hash)?;
    let staging = store.staging_path(&entry.reservation.temp_name)?;
    if store.entry_exists(&staging)? {
        store.quarantine(&staging)?;
    }
    if !store.entry_exists(&target)? {
        invalidate(
            journal,
            clock,
            entry,
            ArtifactUnavailableState::Missing,
            "object_missing",
        )?;
        report.invalidated += 1;
    } else if !store.verify(&target, &artifact.content_hash, artifact.size_bytes)? {
        store.quarantine(&target)?;
        invalidate(
            journal,
            clock,
            entry,
            ArtifactUnavailableState::Quarantined,
            "object_invalid",
        )?;
        report.invalidated += 1;
    }
    Ok(())
}

fn intent_disagrees_with_metadata(entry: &ArtifactJournalEntry) -> bool {
    entry.expected_hash != entry.reservation.artifact.content_hash
        || entry.expected_size != entry.reservation.artifact.size_bytes
}

fn quarantine_staging(
    store: &ContentAddressedArtifactStore,
    entry: &ArtifactJournalEntry,
) -> Result<(), PortError> {
    let staging = store.staging_path(&entry.reservation.temp_name)?;
    if store.entry_exists(&staging)? {
        store.quarantine(&staging)?;
    }
    Ok(())
}

fn complete(
    journal: &dyn ArtifactJournal,
    clock: &dyn Clock,
    entry: &ArtifactJournalEntry,
) -> Result<(), PortError> {
    let operation_id = &entry.reservation.operation_id;
    match entry.status {
        ArtifactJournalStatus::Intent => {
            raw_transition(
                journal,
                clock,
                operation_id,
                ArtifactJournalStatus::Intent,
                ArtifactJournalStatus::Staging,
            )?;
            raw_transition(
                journal,
                clock,
                operation_id,
                ArtifactJournalStatus::Staging,
                ArtifactJournalStatus::Renamed,
            )?;
        }
        ArtifactJournalStatus::Staging => {
            raw_transition(
                journal,
                clock,
                operation_id,
                ArtifactJournalStatus::Staging,
                ArtifactJournalStatus::Renamed,
            )?;
        }
        ArtifactJournalStatus::Renamed => {}
        _ => return Err(super::content_address::integrity_failure()),
    }
    raw_transition(
        journal,
        clock,
        operation_id,
        ArtifactJournalStatus::Renamed,
        ArtifactJournalStatus::Completed,
    )
}

fn transition(
    journal: &dyn ArtifactJournal,
    clock: &dyn Clock,
    entry: &ArtifactJournalEntry,
    next_status: ArtifactJournalStatus,
) -> Result<(), PortError> {
    raw_transition(
        journal,
        clock,
        &entry.reservation.operation_id,
        entry.status,
        next_status,
    )
}

fn raw_transition(
    journal: &dyn ArtifactJournal,
    clock: &dyn Clock,
    operation_id: &str,
    expected_status: ArtifactJournalStatus,
    next_status: ArtifactJournalStatus,
) -> Result<(), PortError> {
    let error = (matches!(
        next_status,
        ArtifactJournalStatus::Aborted | ArtifactJournalStatus::Quarantined
    ))
    .then(|| json!({"kind": format!("artifact_{next_status:?}").to_lowercase()}));
    raw_transition_with_error(
        journal,
        clock,
        operation_id,
        expected_status,
        next_status,
        error,
    )
}

fn raw_transition_with_error(
    journal: &dyn ArtifactJournal,
    clock: &dyn Clock,
    operation_id: &str,
    expected_status: ArtifactJournalStatus,
    next_status: ArtifactJournalStatus,
    error: Option<serde_json::Value>,
) -> Result<(), PortError> {
    let updated_at = clock.now_utc()?;
    journal.transition(ArtifactJournalTransition {
        operation_id: operation_id.to_owned(),
        expected_status,
        next_status,
        completed_at: (next_status == ArtifactJournalStatus::Completed).then(|| updated_at.clone()),
        updated_at,
        error,
    })
}

fn invalidate(
    journal: &dyn ArtifactJournal,
    clock: &dyn Clock,
    entry: &ArtifactJournalEntry,
    unavailable_state: ArtifactUnavailableState,
    kind: &str,
) -> Result<(), PortError> {
    journal.invalidate_completed(ArtifactJournalInvalidation {
        operation_id: entry.reservation.operation_id.clone(),
        unavailable_state,
        updated_at: clock.now_utc()?,
        error: json!({"kind": kind}),
    })
}
