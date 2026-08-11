//! Durable runtime for Open Agent Protocol peers.

mod fakes;
mod runtime;

pub use fakes::{
    MaliciousScript, RequestScript, Script, ScriptLog, ScriptedPeer, ScriptedPeerFactory,
};
pub use local_agent_terminal_agent_protocol::{
    ConnectionBinding, PeerDescriptor, ProtocolCapabilities, ProtocolPeer, ProtocolTrustTier,
};
pub use runtime::{
    ProtocolAgentRuntime, DEFAULT_HEARTBEAT_TIMEOUT_SECS, DEFAULT_RUN_DEADLINE_SECS,
};
