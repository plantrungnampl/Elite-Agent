use local_agent_terminal_domain::{ArtifactId, RunConfiguration, RunId, UnsignedRunConfiguration};
use sha2::{Digest, Sha256};

use crate::{ArtifactRef, PortError};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublishedRunConfigurationArtifact {
    pub artifact_id: ArtifactId,
    pub reference: ArtifactRef,
}

pub trait RunConfigurationArtifactPublisher: Send + Sync {
    fn publish(
        &self,
        artifact_id: &ArtifactId,
        configuration: &RunConfiguration,
    ) -> Result<ArtifactRef, PortError>;
}

pub trait RunConfigurationStore: Send + Sync {
    fn bind_run_configuration(
        &self,
        run_id: &RunId,
        artifact: &PublishedRunConfigurationArtifact,
        configuration: &RunConfiguration,
    ) -> Result<(), PortError>;
}

pub struct PublishRunConfiguration<'a> {
    publisher: &'a dyn RunConfigurationArtifactPublisher,
}

impl<'a> PublishRunConfiguration<'a> {
    #[must_use]
    pub const fn new(publisher: &'a dyn RunConfigurationArtifactPublisher) -> Self {
        Self { publisher }
    }

    pub fn execute(
        &self,
        artifact_id: ArtifactId,
        unsigned: UnsignedRunConfiguration,
    ) -> Result<(PublishedRunConfigurationArtifact, RunConfiguration), PortError> {
        let configuration = RunConfiguration::issue(unsigned).map_err(|_| invalid_input())?;
        let reference = self.publisher.publish(&artifact_id, &configuration)?;
        validate_physical_reference(&reference, &configuration)?;
        Ok((
            PublishedRunConfigurationArtifact {
                artifact_id,
                reference,
            },
            configuration,
        ))
    }
}

pub struct BindRunConfiguration<'a> {
    store: &'a dyn RunConfigurationStore,
}

impl<'a> BindRunConfiguration<'a> {
    #[must_use]
    pub const fn new(store: &'a dyn RunConfigurationStore) -> Self {
        Self { store }
    }

    pub fn execute(
        &self,
        run_id: &RunId,
        artifact: &PublishedRunConfigurationArtifact,
        configuration: &RunConfiguration,
    ) -> Result<(), PortError> {
        validate_physical_reference(&artifact.reference, configuration)?;
        self.store
            .bind_run_configuration(run_id, artifact, configuration)
    }
}

fn validate_physical_reference(
    reference: &ArtifactRef,
    configuration: &RunConfiguration,
) -> Result<(), PortError> {
    if reference.content_hash != physical_digest(configuration.canonical_bytes())
        || reference.size_bytes != configuration.canonical_bytes().len() as u64
    {
        return Err(integrity_failure());
    }
    Ok(())
}

fn physical_digest(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}

fn invalid_input() -> PortError {
    PortError::failure(
        crate::SafeErrorClassification::InvalidInput,
        crate::Retryability::NonRetryable,
    )
}

fn integrity_failure() -> PortError {
    PortError::failure(
        crate::SafeErrorClassification::IntegrityFailure,
        crate::Retryability::NonRetryable,
    )
}
