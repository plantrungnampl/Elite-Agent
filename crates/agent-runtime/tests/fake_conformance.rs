use std::collections::BTreeSet;

use local_agent_terminal_agent_protocol::{
    run_conformance, ConnectionBinding, PeerDescriptor, ProtocolCapabilities, ProtocolTrustTier,
};
use local_agent_terminal_agent_runtime::ScriptedPeerFactory;

#[test]
fn every_script_passes_the_shared_protocol_conformance_matrix() {
    run_conformance(&ScriptedPeerFactory::new(descriptor()))
        .expect("the single scripted peer model must pass every shared case");
}

fn descriptor() -> PeerDescriptor {
    PeerDescriptor {
        binding: ConnectionBinding {
            connection_id: "connection-1".to_owned(),
            agent_id: "agent-1".to_owned(),
            manifest_digest:
                "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_owned(),
            executable_digest:
                "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_owned(),
            trust_tier: ProtocolTrustTier::CoreAdapter,
        },
        protocol_version: "1.0".to_owned(),
        capabilities: ProtocolCapabilities {
            roles: BTreeSet::from(["critic".to_owned()]),
            skills: BTreeSet::from(["testing".to_owned()]),
            streaming: true,
            context_query: true,
            tool_requests: true,
            specialist_requests: true,
            max_concurrent_runs: 1,
            max_context_tokens: 1_024,
        },
    }
}
