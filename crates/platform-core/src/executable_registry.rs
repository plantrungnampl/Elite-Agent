use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;

use local_agent_terminal_application::{
    ApprovedExecutableIdentity, ExecutableArtifactInspector, ExecutableProfileResolver,
    ExecutableVerificationGuard, PortError, ResolvedExecutable, Retryability,
    SafeErrorClassification, ToolControlSelfTest,
};
use local_agent_terminal_domain::Sha256Digest;

#[derive(Debug)]
pub struct TrustedExecutableRegistration {
    toolchain_id: String,
    version: String,
    path: PathBuf,
    expected_sha256: Sha256Digest,
}

impl TrustedExecutableRegistration {
    pub fn new(
        toolchain_id: impl Into<String>,
        version: impl Into<String>,
        path: impl Into<PathBuf>,
        expected_sha256: Sha256Digest,
    ) -> Result<Self, PortError> {
        let toolchain_id = toolchain_id.into();
        let version = version.into();
        let path = path.into();
        if !valid_name(&toolchain_id)
            || !valid_name(&version)
            || !path.is_absolute()
            || path.to_str().is_none()
        {
            return Err(invalid_input());
        }
        Ok(Self {
            toolchain_id,
            version,
            path,
            expected_sha256,
        })
    }
}

pub struct ExecutableRegistry {
    registrations: BTreeMap<String, RegisteredExecutable>,
    inspector: Arc<dyn ExecutableArtifactInspector>,
}

#[derive(Debug)]
struct RegisteredExecutable {
    approved: ApprovedExecutableIdentity,
}

impl ExecutableRegistry {
    pub fn load(
        registrations: Vec<TrustedExecutableRegistration>,
        inspector: Arc<dyn ExecutableArtifactInspector>,
    ) -> Result<Self, PortError> {
        let mut loaded = BTreeMap::new();
        for registration in registrations {
            if loaded.contains_key(&registration.toolchain_id) {
                return Err(invalid_input());
            }
            let (resolved, retained) = inspector.inspect_and_retain(
                registration.path.to_str().ok_or_else(invalid_input)?,
                &registration.toolchain_id,
                &registration.expected_sha256,
            )?;
            validate_inspection(&registration, &resolved)?;
            drop(retained);
            let approved = ApprovedExecutableIdentity::new(resolved, registration.version)?;
            loaded.insert(registration.toolchain_id, RegisteredExecutable { approved });
        }
        Ok(Self {
            registrations: loaded,
            inspector,
        })
    }

    pub fn resolve(
        &self,
        toolchain_id: &str,
        version: &str,
    ) -> Result<ResolvedExecutable, PortError> {
        self.registrations
            .get(toolchain_id)
            .filter(|registered| registered.approved.version() == version)
            .map(|registered| registered.approved.executable().clone())
            .ok_or_else(denied)
    }

    pub fn resolve_registered(
        &self,
        toolchain_id: &str,
    ) -> Result<ApprovedExecutableIdentity, PortError> {
        self.registrations
            .get(toolchain_id)
            .map(|registered| registered.approved.clone())
            .ok_or_else(denied)
    }

    pub fn verify_and_retain(
        &self,
        executable: &ResolvedExecutable,
    ) -> Result<Box<dyn ExecutableVerificationGuard>, PortError> {
        let registered = self
            .registrations
            .get(&executable.toolchain_id)
            .filter(|registered| registered.approved.executable() == executable)
            .ok_or_else(denied)?;
        let (observed, retained) = self.inspector.inspect_and_retain(
            registered
                .approved
                .executable()
                .canonical_path
                .to_str()
                .ok_or_else(invalid_input)?,
            &registered.approved.executable().toolchain_id,
            &registered.approved.executable().sha256,
        )?;
        if &observed != registered.approved.executable() {
            return Err(integrity_failure());
        }
        Ok(retained)
    }
}

impl ExecutableProfileResolver for ExecutableRegistry {
    fn resolve_registered(
        &self,
        toolchain_id: &str,
    ) -> Result<ApprovedExecutableIdentity, PortError> {
        Self::resolve_registered(self, toolchain_id)
    }

    fn verify_and_retain(
        &self,
        executable: &ResolvedExecutable,
    ) -> Result<Box<dyn ExecutableVerificationGuard>, PortError> {
        Self::verify_and_retain(self, executable)
    }
}

impl ToolControlSelfTest for ExecutableRegistry {
    fn verify_controls(&self) -> Result<(), PortError> {
        for registered in self.registrations.values() {
            drop(self.verify_and_retain(registered.approved.executable())?);
        }
        Ok(())
    }
}

fn validate_inspection(
    registration: &TrustedExecutableRegistration,
    resolved: &ResolvedExecutable,
) -> Result<(), PortError> {
    let canonical_path = std::fs::canonicalize(&registration.path).map_err(|_| denied())?;
    if resolved.canonical_path != canonical_path
        || !resolved.canonical_path.is_absolute()
        || resolved.sha256 != registration.expected_sha256
        || resolved.toolchain_id != registration.toolchain_id
    {
        return Err(integrity_failure());
    }
    Ok(())
}

fn valid_name(value: &str) -> bool {
    !value.trim().is_empty() && value.len() <= 256 && !value.contains(['\0', '/', '\\', ':'])
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
