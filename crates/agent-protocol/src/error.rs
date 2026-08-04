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
        }
    }
}

impl std::error::Error for ProtocolError {}
