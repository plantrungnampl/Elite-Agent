use std::collections::{BTreeMap, BTreeSet};

use local_agent_terminal_application::{
    EnvironmentProfileResolver, PortError, ResolvedEnvironmentProfile, Retryability,
    SafeErrorClassification, ToolControlSelfTest,
};
use local_agent_terminal_domain::Sha256Digest;
use sha2::{Digest, Sha256};

#[derive(Debug)]
pub struct TrustedEnvironmentProfile {
    name: String,
    values: BTreeMap<String, String>,
}

impl TrustedEnvironmentProfile {
    pub fn new(
        name: impl Into<String>,
        values: Vec<(String, String)>,
        inherit_parent: bool,
    ) -> Result<Self, PortError> {
        let name = name.into();
        if inherit_parent || !valid_profile_name(&name) {
            return Err(invalid_input());
        }
        let mut normalized = BTreeMap::new();
        let mut seen = BTreeSet::new();
        for (raw_name, value) in values {
            let variable_name = raw_name.to_ascii_uppercase();
            if !valid_variable_name(&variable_name)
                || !seen.insert(variable_name.clone())
                || secret_name(&variable_name)
                || secret_value(&value)
            {
                return Err(invalid_input());
            }
            normalized.insert(variable_name, value);
        }
        Ok(Self {
            name,
            values: normalized,
        })
    }

    fn resolve(self) -> Result<ResolvedEnvironmentProfile, PortError> {
        let digest = environment_digest(&self.name, &self.values)?;
        Ok(ResolvedEnvironmentProfile {
            name: self.name,
            values: self.values,
            digest,
        })
    }
}

#[derive(Debug)]
pub struct EnvironmentProfileRegistry {
    profiles: BTreeMap<String, ResolvedEnvironmentProfile>,
}

impl EnvironmentProfileRegistry {
    pub fn load(profiles: Vec<TrustedEnvironmentProfile>) -> Result<Self, PortError> {
        let mut loaded = BTreeMap::new();
        for profile in profiles {
            let resolved = profile.resolve()?;
            if loaded.insert(resolved.name.clone(), resolved).is_some() {
                return Err(invalid_input());
            }
        }
        Ok(Self { profiles: loaded })
    }

    pub fn resolve(
        &self,
        name: &str,
        expected_digest: &Sha256Digest,
    ) -> Result<ResolvedEnvironmentProfile, PortError> {
        self.profiles
            .get(name)
            .filter(|profile| &profile.digest == expected_digest)
            .cloned()
            .ok_or_else(denied)
    }
}

impl EnvironmentProfileResolver for EnvironmentProfileRegistry {
    fn resolve(
        &self,
        name: &str,
        expected_digest: &Sha256Digest,
    ) -> Result<ResolvedEnvironmentProfile, PortError> {
        Self::resolve(self, name, expected_digest)
    }
}

impl ToolControlSelfTest for EnvironmentProfileRegistry {
    fn verify_controls(&self) -> Result<(), PortError> {
        for profile in self.profiles.values() {
            if environment_digest(&profile.name, &profile.values)? != profile.digest {
                return Err(integrity_failure());
            }
        }
        Ok(())
    }
}

fn environment_digest(
    name: &str,
    values: &BTreeMap<String, String>,
) -> Result<Sha256Digest, PortError> {
    let mut canonical = format!("environment-profile.v1\nname={name}\n");
    for (variable_name, value) in values {
        canonical.push_str(variable_name);
        canonical.push('=');
        canonical.push_str(value);
        canonical.push('\n');
    }
    Sha256Digest::new(format!("sha256:{:x}", Sha256::digest(canonical.as_bytes())))
        .map_err(|_| invalid_input())
}

fn valid_profile_name(value: &str) -> bool {
    !value.trim().is_empty()
        && value.len() <= 256
        && !value.contains(['\0', '\r', '\n', '/', '\\', ':', '='])
}

fn valid_variable_name(value: &str) -> bool {
    let mut bytes = value.bytes();
    bytes
        .next()
        .is_some_and(|byte| byte == b'_' || byte.is_ascii_uppercase())
        && bytes.all(|byte| byte == b'_' || byte.is_ascii_uppercase() || byte.is_ascii_digit())
        && value.len() <= 256
}

fn secret_name(value: &str) -> bool {
    value.contains("TOKEN")
        || value.contains("SECRET")
        || value.contains("PASSWORD")
        || value.contains("CREDENTIAL")
        || value.contains("COOKIE")
        || value.contains("PRIVATE_KEY")
        || value == "KEY"
        || value.starts_with("KEY_")
        || value.ends_with("_KEY")
}

fn secret_value(value: &str) -> bool {
    let trimmed = value.trim();
    let uppercase = trimmed.to_ascii_uppercase();
    trimmed.contains(['\0', '\r', '\n'])
        || trimmed.starts_with("ghp_")
        || trimmed.starts_with("github_pat_")
        || trimmed.starts_with("sk-")
        || (uppercase.starts_with("AKIA") && trimmed.len() >= 20)
        || uppercase.contains("PRIVATE KEY-----")
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

fn integrity_failure() -> PortError {
    PortError::failure(
        SafeErrorClassification::IntegrityFailure,
        Retryability::NonRetryable,
    )
}
