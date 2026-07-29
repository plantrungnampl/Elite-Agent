use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;

use local_agent_terminal_application::{
    PortError, PrivateRuntimeDirectoryInspector, PrivateRuntimeDirectoryVerificationGuard,
    ResolvedPrivateRuntimeDirectory, Retryability, SafeErrorClassification,
};

#[derive(Debug)]
pub struct TrustedPrivateRuntimeDirectory {
    registration_id: String,
    path: PathBuf,
}

impl TrustedPrivateRuntimeDirectory {
    pub fn new(
        registration_id: impl Into<String>,
        path: impl Into<PathBuf>,
    ) -> Result<Self, PortError> {
        let registration_id = registration_id.into();
        let path = path.into();
        if !valid_name(&registration_id) || !path.is_absolute() || path.to_str().is_none() {
            return Err(invalid_input());
        }
        Ok(Self {
            registration_id,
            path,
        })
    }
}

pub struct PrivateRuntimeDirectoryRegistry {
    directories: BTreeMap<String, ResolvedPrivateRuntimeDirectory>,
    inspector: Arc<dyn PrivateRuntimeDirectoryInspector>,
}

impl PrivateRuntimeDirectoryRegistry {
    pub fn load(
        registrations: Vec<TrustedPrivateRuntimeDirectory>,
        inspector: Arc<dyn PrivateRuntimeDirectoryInspector>,
    ) -> Result<Self, PortError> {
        let mut directories = BTreeMap::new();
        for registration in registrations {
            if directories.contains_key(&registration.registration_id) {
                return Err(invalid_input());
            }
            let (resolved, retained) = inspector.inspect_and_retain(
                registration.path.to_str().ok_or_else(invalid_input)?,
                &registration.registration_id,
            )?;
            validate_inspection(&registration, &resolved)?;
            drop(retained);
            directories.insert(registration.registration_id, resolved);
        }
        Ok(Self {
            directories,
            inspector,
        })
    }

    pub fn resolve(
        &self,
        registration_id: &str,
    ) -> Result<ResolvedPrivateRuntimeDirectory, PortError> {
        self.directories
            .get(registration_id)
            .cloned()
            .ok_or_else(denied)
    }

    pub fn verify_and_retain(
        &self,
        directory: &ResolvedPrivateRuntimeDirectory,
    ) -> Result<Box<dyn PrivateRuntimeDirectoryVerificationGuard>, PortError> {
        let registered = self
            .directories
            .get(&directory.registration_id)
            .filter(|registered| *registered == directory)
            .ok_or_else(denied)?;
        let (observed, retained) = self.inspector.inspect_and_retain(
            registered
                .canonical_path
                .to_str()
                .ok_or_else(invalid_input)?,
            &registered.registration_id,
        )?;
        if observed != *registered {
            return Err(integrity_failure());
        }
        Ok(retained)
    }
}

fn validate_inspection(
    registration: &TrustedPrivateRuntimeDirectory,
    resolved: &ResolvedPrivateRuntimeDirectory,
) -> Result<(), PortError> {
    let canonical_path = std::fs::canonicalize(&registration.path).map_err(|_| denied())?;
    if resolved.canonical_path != canonical_path
        || !resolved.canonical_path.is_absolute()
        || resolved.registration_id != registration.registration_id
    {
        return Err(integrity_failure());
    }
    Ok(())
}

fn valid_name(value: &str) -> bool {
    !value.trim().is_empty()
        && value.len() <= 256
        && !value.contains(['\0', '\r', '\n', '/', '\\', ':', '='])
}

fn invalid_input() -> PortError {
    PortError::failure(
        SafeErrorClassification::InvalidInput,
        Retryability::NonRetryable,
    )
}

fn denied() -> PortError {
    PortError::failure(
        SafeErrorClassification::PermissionDenied,
        Retryability::NonRetryable,
    )
}

fn integrity_failure() -> PortError {
    PortError::failure(
        SafeErrorClassification::IntegrityFailure,
        Retryability::NonRetryable,
    )
}
