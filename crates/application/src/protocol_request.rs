use local_agent_terminal_domain::{ArtifactId, RunId, Sequence, Sha256Digest, TaskId};
use serde_json::Value;
use sha2::{Digest, Sha256};
use time::{format_description::well_known::Rfc3339, OffsetDateTime};

use crate::{PortError, Retryability, SafeErrorClassification};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtocolRequestIdentity {
    connection_id: String,
    request_id: String,
    method: String,
    request_digest: Sha256Digest,
}

impl ProtocolRequestIdentity {
    pub fn new(
        connection_id: impl Into<String>,
        request_id: impl Into<String>,
        method: impl Into<String>,
        request_digest: Sha256Digest,
    ) -> Result<Self, PortError> {
        let identity = Self {
            connection_id: connection_id.into(),
            request_id: request_id.into(),
            method: method.into(),
            request_digest,
        };
        identity.validate()?;
        Ok(identity)
    }

    #[must_use]
    pub fn connection_id(&self) -> &str {
        &self.connection_id
    }

    #[must_use]
    pub fn request_id(&self) -> &str {
        &self.request_id
    }

    #[must_use]
    pub fn method(&self) -> &str {
        &self.method
    }

    #[must_use]
    pub fn request_digest(&self) -> &Sha256Digest {
        &self.request_digest
    }

    pub fn validate(&self) -> Result<(), PortError> {
        validate_identifier(&self.connection_id)?;
        validate_identifier(&self.request_id)?;
        validate_identifier(&self.method)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtocolRequestBegin {
    identity: ProtocolRequestIdentity,
    task_id: Option<TaskId>,
    run_id: Option<RunId>,
    created_at: String,
}

impl ProtocolRequestBegin {
    pub fn new(
        identity: ProtocolRequestIdentity,
        task_id: Option<TaskId>,
        run_id: Option<RunId>,
        created_at: impl Into<String>,
    ) -> Result<Self, PortError> {
        let begin = Self {
            identity,
            task_id,
            run_id,
            created_at: created_at.into(),
        };
        begin.validate()?;
        Ok(begin)
    }

    #[must_use]
    pub fn identity(&self) -> &ProtocolRequestIdentity {
        &self.identity
    }

    #[must_use]
    pub fn task_id(&self) -> Option<&TaskId> {
        self.task_id.as_ref()
    }

    #[must_use]
    pub fn run_id(&self) -> Option<&RunId> {
        self.run_id.as_ref()
    }

    #[must_use]
    pub fn created_at(&self) -> &str {
        &self.created_at
    }

    pub fn validate(&self) -> Result<(), PortError> {
        self.identity.validate()?;
        if self.run_id.is_some() && self.task_id.is_none() {
            return Err(invalid_input());
        }
        validate_timestamp(&self.created_at)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtocolRequestTerminalStatus {
    Completed,
    Failed,
}

impl ProtocolRequestTerminalStatus {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Completed => "completed",
            Self::Failed => "failed",
        }
    }

    pub fn parse(value: &str) -> Result<Self, PortError> {
        match value {
            "completed" => Ok(Self::Completed),
            "failed" => Ok(Self::Failed),
            _ => Err(invalid_input()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtocolResponseArtifact {
    artifact_id: ArtifactId,
    bytes: Vec<u8>,
    content_digest: Sha256Digest,
}

impl ProtocolResponseArtifact {
    pub fn new(artifact_id: ArtifactId, bytes: Vec<u8>) -> Result<Self, PortError> {
        if bytes.is_empty() || serde_json::from_slice::<Value>(&bytes).is_err() {
            return Err(invalid_input());
        }
        let content_digest = Sha256Digest::new(format!("sha256:{:x}", Sha256::digest(&bytes)))
            .expect("SHA-256 formatting is valid");
        Ok(Self {
            artifact_id,
            bytes,
            content_digest,
        })
    }

    #[must_use]
    pub fn artifact_id(&self) -> &ArtifactId {
        &self.artifact_id
    }

    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    #[must_use]
    pub fn content_digest(&self) -> &Sha256Digest {
        &self.content_digest
    }

    #[must_use]
    pub fn size_bytes(&self) -> u64 {
        u64::try_from(self.bytes.len()).expect("usize fits into u64")
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtocolRequestTerminal {
    identity: ProtocolRequestIdentity,
    status: ProtocolRequestTerminalStatus,
    response: ProtocolResponseArtifact,
    completed_at: String,
}

impl ProtocolRequestTerminal {
    pub fn new(
        identity: ProtocolRequestIdentity,
        status: ProtocolRequestTerminalStatus,
        response: ProtocolResponseArtifact,
        completed_at: impl Into<String>,
    ) -> Result<Self, PortError> {
        let terminal = Self {
            identity,
            status,
            response,
            completed_at: completed_at.into(),
        };
        terminal.validate()?;
        Ok(terminal)
    }

    #[must_use]
    pub fn identity(&self) -> &ProtocolRequestIdentity {
        &self.identity
    }

    #[must_use]
    pub const fn status(&self) -> ProtocolRequestTerminalStatus {
        self.status
    }

    #[must_use]
    pub fn response(&self) -> &ProtocolResponseArtifact {
        &self.response
    }

    #[must_use]
    pub fn completed_at(&self) -> &str {
        &self.completed_at
    }

    pub fn validate(&self) -> Result<(), PortError> {
        self.identity.validate()?;
        validate_timestamp(&self.completed_at)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProtocolRequestState {
    Pending,
    Terminal(ProtocolRequestTerminal),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtocolRequestRecord {
    begin: ProtocolRequestBegin,
    state: ProtocolRequestState,
}

impl ProtocolRequestRecord {
    pub fn pending(begin: ProtocolRequestBegin) -> Self {
        Self {
            begin,
            state: ProtocolRequestState::Pending,
        }
    }

    pub fn terminal(
        begin: ProtocolRequestBegin,
        terminal: ProtocolRequestTerminal,
    ) -> Result<Self, PortError> {
        if begin.identity != terminal.identity {
            return Err(invalid_input());
        }
        Ok(Self {
            begin,
            state: ProtocolRequestState::Terminal(terminal),
        })
    }

    #[must_use]
    pub fn begin(&self) -> &ProtocolRequestBegin {
        &self.begin
    }

    #[must_use]
    pub fn state(&self) -> &ProtocolRequestState {
        &self.state
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProtocolRequestBeginResult {
    Begun,
    Pending,
    Replayed(ProtocolRequestTerminal),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtocolStreamIdentity {
    connection_id: String,
    run_id: RunId,
    channel: String,
}

impl ProtocolStreamIdentity {
    pub fn new(
        connection_id: impl Into<String>,
        run_id: RunId,
        channel: impl Into<String>,
    ) -> Result<Self, PortError> {
        let identity = Self {
            connection_id: connection_id.into(),
            run_id,
            channel: channel.into(),
        };
        identity.validate()?;
        Ok(identity)
    }

    #[must_use]
    pub fn connection_id(&self) -> &str {
        &self.connection_id
    }

    #[must_use]
    pub fn run_id(&self) -> &RunId {
        &self.run_id
    }

    #[must_use]
    pub fn channel(&self) -> &str {
        &self.channel
    }

    pub fn validate(&self) -> Result<(), PortError> {
        validate_identifier(&self.connection_id)?;
        if !matches!(self.channel.as_str(), "content" | "status" | "telemetry") {
            return Err(invalid_input());
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtocolStreamAdvance {
    stream: ProtocolStreamIdentity,
    sequence: Sequence,
}

impl ProtocolStreamAdvance {
    pub fn new(
        connection_id: impl Into<String>,
        run_id: RunId,
        channel: impl Into<String>,
        sequence: Sequence,
    ) -> Result<Self, PortError> {
        let advance = Self {
            stream: ProtocolStreamIdentity::new(connection_id, run_id, channel)?,
            sequence,
        };
        advance.validate()?;
        Ok(advance)
    }

    #[must_use]
    pub fn connection_id(&self) -> &str {
        self.stream.connection_id()
    }

    #[must_use]
    pub fn run_id(&self) -> &RunId {
        self.stream.run_id()
    }

    #[must_use]
    pub fn channel(&self) -> &str {
        self.stream.channel()
    }

    #[must_use]
    pub const fn sequence(&self) -> Sequence {
        self.sequence
    }

    #[must_use]
    pub fn stream(&self) -> &ProtocolStreamIdentity {
        &self.stream
    }

    pub fn validate(&self) -> Result<(), PortError> {
        self.stream.validate()?;
        if self.sequence.get() == 0 {
            return Err(invalid_input());
        }
        Ok(())
    }
}

pub trait ProtocolRequestStore: Send + Sync {
    fn begin(
        &self,
        request: &ProtocolRequestBegin,
    ) -> Result<ProtocolRequestBeginResult, PortError>;
    fn load(
        &self,
        identity: &ProtocolRequestIdentity,
    ) -> Result<Option<ProtocolRequestRecord>, PortError>;
    fn complete(
        &self,
        terminal: &ProtocolRequestTerminal,
    ) -> Result<ProtocolRequestTerminal, PortError>;
    fn load_stream_head(
        &self,
        stream: &ProtocolStreamIdentity,
    ) -> Result<Option<Sequence>, PortError>;
    fn advance_stream(&self, advance: &ProtocolStreamAdvance) -> Result<(), PortError>;
}

pub trait ProtocolResponseArtifactPublisher: Send + Sync {
    fn publish_protocol_response(
        &self,
        begin: &ProtocolRequestBegin,
        response: &ProtocolResponseArtifact,
    ) -> Result<ProtocolResponseArtifact, PortError>;
}

fn validate_identifier(value: &str) -> Result<(), PortError> {
    if value.trim().is_empty() || value.contains('\0') {
        Err(invalid_input())
    } else {
        Ok(())
    }
}

fn validate_timestamp(value: &str) -> Result<(), PortError> {
    OffsetDateTime::parse(value, &Rfc3339)
        .map(|_| ())
        .map_err(|_| invalid_input())
}

fn invalid_input() -> PortError {
    PortError::failure(
        SafeErrorClassification::InvalidInput,
        Retryability::NonRetryable,
    )
}
