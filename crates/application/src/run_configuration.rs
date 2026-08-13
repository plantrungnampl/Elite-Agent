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

pub struct BindRunConfiguration<'a> {
    publisher: &'a dyn RunConfigurationArtifactPublisher,
    store: &'a dyn RunConfigurationStore,
}

impl<'a> BindRunConfiguration<'a> {
    #[must_use]
    pub const fn new(
        publisher: &'a dyn RunConfigurationArtifactPublisher,
        store: &'a dyn RunConfigurationStore,
    ) -> Self {
        Self { publisher, store }
    }

    pub fn execute(
        &self,
        run_id: &RunId,
        artifact_id: ArtifactId,
        unsigned: UnsignedRunConfiguration,
    ) -> Result<RunConfiguration, PortError> {
        let configuration = RunConfiguration::issue(unsigned).map_err(|_| invalid_input())?;
        let reference = self.publisher.publish(&artifact_id, &configuration)?;
        if reference.content_hash != physical_digest(configuration.canonical_bytes())
            || reference.size_bytes != configuration.canonical_bytes().len() as u64
        {
            return Err(integrity_failure());
        }
        let artifact = PublishedRunConfigurationArtifact {
            artifact_id,
            reference,
        };
        self.store
            .bind_run_configuration(run_id, &artifact, &configuration)?;
        Ok(configuration)
    }
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
