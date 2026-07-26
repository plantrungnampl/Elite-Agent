use std::fmt;

use local_agent_terminal_domain::{FencingToken, Sequence};

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
    StaleLease {
        current: FencingToken,
        supplied: FencingToken,
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

    pub const fn stale_lease(current: FencingToken, supplied: FencingToken) -> Self {
        Self::StaleLease { current, supplied }
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
            Self::VersionConflict { .. } | Self::StaleLease { .. } => Retryability::NonRetryable,
            Self::Failure { retryability, .. } => *retryability,
        }
    }

    pub const fn safe_classification(&self) -> SafeErrorClassification {
        match self {
            Self::VersionConflict { .. } | Self::StaleLease { .. } => {
                SafeErrorClassification::Conflict
            }
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
            Self::StaleLease { current, supplied } => write!(
                formatter,
                "stale executor lease: current token {}, supplied token {}",
                current.get(),
                supplied.get()
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
