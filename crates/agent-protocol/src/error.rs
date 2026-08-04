use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtocolError {
    EmptyFrame,
    FrameTooLarge { max_frame_bytes: usize },
    MultipleFrames,
    InvalidUtf8,
    InvalidJson,
    InvalidFrame,
    Encode,
    ProtocolIncompatible,
    InvalidRequest,
    IdentityBindingFailed,
    ProviderUnavailable,
    RateLimited,
    ContextTooLarge,
    OutputLimitExceeded,
    Cancelled,
    Timeout,
    PolicyDenied,
    ApprovalRequired,
    StaleFencingToken,
    MalformedStructuredOutput,
    InternalAgentFailure,
}

impl fmt::Display for ProtocolError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyFrame => formatter.write_str("NDJSON frame is empty"),
            Self::FrameTooLarge { max_frame_bytes } => write!(
                formatter,
                "NDJSON frame exceeds configured byte limit of {max_frame_bytes}"
            ),
            Self::MultipleFrames => formatter.write_str("NDJSON input contains multiple frames"),
            Self::InvalidUtf8 => formatter.write_str("NDJSON frame is not valid UTF-8"),
            Self::InvalidJson => formatter.write_str("NDJSON frame is not valid JSON"),
            Self::InvalidFrame => formatter.write_str("NDJSON frame does not match protocol v1"),
            Self::Encode => formatter.write_str("protocol v1 frame could not be encoded"),
            Self::ProtocolIncompatible => {
                formatter.write_str("protocol negotiation is incompatible")
            }
            Self::InvalidRequest => formatter.write_str("protocol request violates session state"),
            Self::IdentityBindingFailed => {
                formatter.write_str("protocol connection binding does not match")
            }
            Self::ProviderUnavailable => formatter.write_str("protocol provider is unavailable"),
            Self::RateLimited => formatter.write_str("protocol provider rate limit was reached"),
            Self::ContextTooLarge => formatter.write_str("protocol context limit was exceeded"),
            Self::OutputLimitExceeded => {
                formatter.write_str("protocol run exceeded its output limit")
            }
            Self::Cancelled => formatter.write_str("protocol run was cancelled"),
            Self::Timeout => formatter.write_str("protocol session timed out"),
            Self::PolicyDenied => formatter.write_str("protocol request was denied by policy"),
            Self::ApprovalRequired => formatter.write_str("protocol request requires approval"),
            Self::StaleFencingToken => formatter.write_str("protocol fencing token is stale"),
            Self::MalformedStructuredOutput => {
                formatter.write_str("protocol structured output is malformed")
            }
            Self::InternalAgentFailure => formatter.write_str("protocol peer connection was lost"),
        }
    }
}

impl std::error::Error for ProtocolError {}
