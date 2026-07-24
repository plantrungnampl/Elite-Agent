use std::fmt;

use local_agent_terminal_domain::Sequence;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Retryability {
    Retryable,
    NonRetryable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SafeErrorClassification {
    Conflict,
    Unavailable,
    PermissionDenied,
    NotFound,
    InvalidInput,
    IntegrityFailure,
    StorageFull,
    Internal,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PortError {
    VersionConflict {
        expected: Sequence,
        actual: Sequence,
    },
    Failure {
        classification: SafeErrorClassification,
        retryability: Retryability,
    },
}

impl PortError {
    pub const fn version_conflict(expected: Sequence, actual: Sequence) -> Self {
        Self::VersionConflict { expected, actual }
    }

    pub const fn failure(
        classification: SafeErrorClassification,
        retryability: Retryability,
    ) -> Self {
        Self::Failure {
            classification,
            retryability,
        }
    }

    pub const fn retryability(&self) -> Retryability {
        match self {
            Self::VersionConflict { .. } => Retryability::NonRetryable,
            Self::Failure { retryability, .. } => *retryability,
        }
    }

    pub const fn safe_classification(&self) -> SafeErrorClassification {
        match self {
            Self::VersionConflict { .. } => SafeErrorClassification::Conflict,
            Self::Failure { classification, .. } => *classification,
        }
    }
}

impl fmt::Display for PortError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::VersionConflict { expected, actual } => write!(
                formatter,
                "event stream version conflict: expected {}, actual {}",
                expected.get(),
                actual.get()
            ),
            Self::Failure {
                classification,
                retryability,
            } => write!(
                formatter,
                "port failure ({classification:?}, {retryability:?})"
            ),
        }
    }
}

impl std::error::Error for PortError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AppendEventsError {
    VersionConflict {
        expected: Sequence,
        actual: Sequence,
    },
    PortFailure {
        classification: SafeErrorClassification,
        retryability: Retryability,
    },
}

impl AppendEventsError {
    pub const fn retryability(&self) -> Retryability {
        match self {
            Self::VersionConflict { .. } => Retryability::NonRetryable,
            Self::PortFailure { retryability, .. } => *retryability,
        }
    }

    pub const fn safe_classification(&self) -> SafeErrorClassification {
        match self {
            Self::VersionConflict { .. } => SafeErrorClassification::Conflict,
            Self::PortFailure { classification, .. } => *classification,
        }
    }
}

impl From<PortError> for AppendEventsError {
    fn from(error: PortError) -> Self {
        match error {
            PortError::VersionConflict { expected, actual } => {
                Self::VersionConflict { expected, actual }
            }
            PortError::Failure {
                classification,
                retryability,
            } => Self::PortFailure {
                classification,
                retryability,
            },
        }
    }
}

impl fmt::Display for AppendEventsError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::VersionConflict { expected, actual } => write!(
                formatter,
                "event stream version conflict: expected {}, actual {}",
                expected.get(),
                actual.get()
            ),
            Self::PortFailure {
                classification,
                retryability,
            } => write!(
                formatter,
                "append failed ({classification:?}, {retryability:?})"
            ),
        }
    }
}

impl std::error::Error for AppendEventsError {}
