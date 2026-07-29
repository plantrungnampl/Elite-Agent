use std::collections::{BTreeMap, BTreeSet};

use local_agent_terminal_application::{
    EnforcedNetworkProfile, NetworkEnforcementReceipt, NetworkProfileVerifier, PortError,
    Retryability, SafeErrorClassification,
};
use local_agent_terminal_domain::{NetworkProfile, Sha256Digest};
use sha2::{Digest, Sha256};

#[derive(Debug)]
pub struct TrustedNetworkProfile {
    name: String,
    mode: NetworkProfile,
    destinations: BTreeSet<String>,
    enforcement_id: String,
}

impl TrustedNetworkProfile {
    pub fn new(
        name: impl Into<String>,
        mode: NetworkProfile,
        destinations: Vec<String>,
        enforcement_id: impl Into<String>,
    ) -> Result<Self, PortError> {
        let name = name.into();
        let enforcement_id = enforcement_id.into();
        if !valid_name(&name) || !valid_name(&enforcement_id) {
            return Err(invalid_input());
        }
        let mut normalized = BTreeSet::new();
        for destination in destinations {
            let destination = normalize_destination(&destination)?;
            if !normalized.insert(destination) {
                return Err(invalid_input());
            }
        }
        match mode {
            NetworkProfile::Denied if !normalized.is_empty() => return Err(invalid_input()),
            NetworkProfile::ProviderEndpointOnly | NetworkProfile::ApprovedDestinations
                if normalized.is_empty() =>
            {
                return Err(invalid_input());
            }
            _ => {}
        }
        Ok(Self {
            name,
            mode,
            destinations: normalized,
            enforcement_id,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkEnforcementEvidence {
    enforcement_id: String,
    redirect_chain_verified: bool,
    resolution_stable: bool,
}

impl NetworkEnforcementEvidence {
    pub fn new(
        enforcement_id: impl Into<String>,
        redirect_chain_verified: bool,
        resolution_stable: bool,
    ) -> Result<Self, PortError> {
        let enforcement_id = enforcement_id.into();
        if !valid_name(&enforcement_id) {
            return Err(invalid_input());
        }
        Ok(Self {
            enforcement_id,
            redirect_chain_verified,
            resolution_stable,
        })
    }
}

#[derive(Debug)]
pub struct NetworkPolicyAdapter {
    profiles: BTreeMap<String, RegisteredNetworkProfile>,
}

#[derive(Debug)]
struct RegisteredNetworkProfile {
    mode: NetworkProfile,
    enforcement_id: String,
    digest: Sha256Digest,
}

impl NetworkPolicyAdapter {
    pub fn load(profiles: Vec<TrustedNetworkProfile>) -> Result<Self, PortError> {
        let mut loaded = BTreeMap::new();
        for profile in profiles {
            let digest = network_digest(&profile)?;
            let name = profile.name;
            let registered = RegisteredNetworkProfile {
                mode: profile.mode,
                enforcement_id: profile.enforcement_id,
                digest,
            };
            if loaded.insert(name, registered).is_some() {
                return Err(invalid_input());
            }
        }
        Ok(Self { profiles: loaded })
    }

    pub fn prepare(
        &self,
        name: &str,
        requested_mode: NetworkProfile,
        evidence: NetworkEnforcementEvidence,
    ) -> Result<EnforcedNetworkProfile, PortError> {
        let profile = self
            .profiles
            .get(name)
            .filter(|profile| {
                profile.mode == requested_mode
                    && profile.enforcement_id == evidence.enforcement_id
                    && evidence.redirect_chain_verified
                    && evidence.resolution_stable
            })
            .ok_or_else(denied)?;
        Ok(EnforcedNetworkProfile {
            profile: profile.mode,
            profile_digest: profile.digest.clone(),
            receipt: NetworkEnforcementReceipt::new(
                profile.enforcement_id.clone(),
                profile.digest.clone(),
            )?,
        })
    }

    pub fn verify(&self, profile: &EnforcedNetworkProfile) -> Result<(), PortError> {
        self.profiles
            .values()
            .any(|registered| {
                registered.mode == profile.profile
                    && registered.digest == profile.profile_digest
                    && registered.enforcement_id == profile.receipt.enforcement_id()
                    && registered.digest == *profile.receipt.profile_digest()
            })
            .then_some(())
            .ok_or_else(denied)
    }
}

impl NetworkProfileVerifier for NetworkPolicyAdapter {
    fn verify(&self, profile: &EnforcedNetworkProfile) -> Result<(), PortError> {
        Self::verify(self, profile)
    }
}

fn network_digest(profile: &TrustedNetworkProfile) -> Result<Sha256Digest, PortError> {
    let mut canonical = format!(
        "network-profile.v1\nname={}\nmode={}\nenforcement={}\n",
        profile.name,
        mode_name(profile.mode),
        profile.enforcement_id,
    );
    for destination in &profile.destinations {
        canonical.push_str("destination=");
        canonical.push_str(destination);
        canonical.push('\n');
    }
    Sha256Digest::new(format!("sha256:{:x}", Sha256::digest(canonical.as_bytes())))
        .map_err(|_| invalid_input())
}

fn normalize_destination(value: &str) -> Result<String, PortError> {
    let value = value.trim().to_ascii_lowercase();
    let (host, port) = value.rsplit_once(':').ok_or_else(invalid_input)?;
    if host.is_empty()
        || host.contains(['/', '\\', '@', '\0', '\r', '\n', ' '])
        || !port.parse::<u16>().is_ok_and(|port| port != 0)
    {
        return Err(invalid_input());
    }
    Ok(value)
}

fn valid_name(value: &str) -> bool {
    !value.trim().is_empty()
        && value.len() <= 256
        && !value.contains(['\0', '\r', '\n', '/', '\\', ':', '='])
}

const fn mode_name(mode: NetworkProfile) -> &'static str {
    match mode {
        NetworkProfile::Denied => "denied",
        NetworkProfile::ProviderEndpointOnly => "provider_endpoint_only",
        NetworkProfile::ApprovedDestinations => "approved_destinations",
    }
}

fn invalid_input() -> PortError {
    PortError::failure(
        SafeErrorClassification::InvalidInput,
        Retryability::NonRetryable,
    )
}

fn denied() -> PortError {
    PortError::failure(
        SafeErrorClassification::PermissionDenied,
        Retryability::NonRetryable,
    )
}
