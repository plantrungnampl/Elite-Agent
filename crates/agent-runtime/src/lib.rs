//! Durable runtime for Open Agent Protocol peers.

mod fakes;
mod runtime;

pub use fakes::{MaliciousScript, Script, ScriptLog, ScriptedPeer, ScriptedPeerFactory};
pub use runtime::{
    ProtocolAgentRuntime, DEFAULT_HEARTBEAT_TIMEOUT_SECS, DEFAULT_RUN_DEADLINE_SECS,
};
