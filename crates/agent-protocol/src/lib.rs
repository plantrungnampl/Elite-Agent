//! Open Agent Protocol v1 types and codecs.

mod codec;
mod error;
mod generated;

pub use codec::{NdjsonCodec, DEFAULT_MAX_FRAME_BYTES};
pub use error::ProtocolError;
pub use generated::OpenAgentProtocolV1Frame as ProtocolFrame;
