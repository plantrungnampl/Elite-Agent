use serde_json::error::Category;

use crate::{ProtocolError, ProtocolFrame};

pub const DEFAULT_MAX_FRAME_BYTES: usize = 8 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NdjsonCodec {
    max_frame_bytes: usize,
}

impl Default for NdjsonCodec {
    fn default() -> Self {
        Self::new(DEFAULT_MAX_FRAME_BYTES)
    }
}

impl NdjsonCodec {
    pub const fn new(max_frame_bytes: usize) -> Self {
        Self { max_frame_bytes }
    }

    pub fn decode(&self, line: &[u8]) -> Result<ProtocolFrame, ProtocolError> {
        let frame = line.strip_suffix(b"\n").unwrap_or(line);
        if frame.len() > self.max_frame_bytes {
            return Err(ProtocolError::FrameTooLarge {
                max_frame_bytes: self.max_frame_bytes,
            });
        }
        if frame.is_empty() {
            return Err(ProtocolError::EmptyFrame);
        }
        if frame.contains(&b'\n') || frame.contains(&b'\r') {
            return Err(ProtocolError::MultipleFrames);
        }

        let frame = std::str::from_utf8(frame).map_err(|_| ProtocolError::InvalidUtf8)?;
        serde_json::from_str(frame).map_err(|error| match error.classify() {
            Category::Data => ProtocolError::InvalidFrame,
            Category::Io | Category::Eof | Category::Syntax => ProtocolError::InvalidJson,
        })
    }

    pub fn encode(&self, frame: &ProtocolFrame) -> Result<Vec<u8>, ProtocolError> {
        let mut encoded = serde_json::to_vec(frame).map_err(|_| ProtocolError::Encode)?;
        if encoded.len() > self.max_frame_bytes {
            return Err(ProtocolError::FrameTooLarge {
                max_frame_bytes: self.max_frame_bytes,
            });
        }
        encoded.push(b'\n');
        Ok(encoded)
    }
}
