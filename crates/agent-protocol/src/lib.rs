//! MAT Agent Control Protocol v2 types and codecs.

mod codec;
mod error;
mod generated;
mod peer;
mod session;

pub use codec::{NdjsonCodec, DEFAULT_MAX_FRAME_BYTES};
pub use error::ProtocolError;
pub use generated::MatAgentControlProtocolV2Frames as ProtocolFrame;
pub use peer::{
    conformance_cases, run_conformance, CancelAcceptance, ConformanceCase, ConformancePeerFactory,
    ConformanceScenario, PeerDescriptor, PeerEventSink, ProtocolPeer, RunAcceptance, RunCancel,
    RunExecutionBinding, RunStart,
};
pub use session::{
    ConnectionBinding, InboundDisposition, ProtocolCapabilities, ProtocolOffer, ProtocolSession,
    ProtocolTrustTier, SessionLimits,
};
