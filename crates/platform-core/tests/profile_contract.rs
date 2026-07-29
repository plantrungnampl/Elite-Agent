use std::fs;
use std::path::Path;
use std::sync::Arc;

use local_agent_terminal_application::{
    DirectoryFileIdentity, ExecutableArtifactInspector, ExecutableFileIdentity,
    ExecutableVerificationGuard, PortError, PrivateRuntimeDirectoryInspector,
    PrivateRuntimeDirectoryVerificationGuard, ResolvedExecutable, ResolvedPrivateRuntimeDirectory,
    Retryability, SafeErrorClassification,
};
use local_agent_terminal_domain::NetworkProfile;
use local_agent_terminal_domain::Sha256Digest;
use local_agent_terminal_platform_core::{
    EnvironmentProfileRegistry, ExecutableRegistry, NetworkEnforcementEvidence,
    NetworkPolicyAdapter, PrivateRuntimeDirectoryRegistry, TrustedEnvironmentProfile,
    TrustedExecutableRegistration, TrustedNetworkProfile, TrustedPrivateRuntimeDirectory,
};
use sha2::{Digest, Sha256};
use tempfile::TempDir;

#[test]
fn executable_registry_rejects_path_lookup_version_drift_and_replacement() {
    let root = TempDir::new().unwrap();
    let executable = root.path().join("registered-tool.exe");
    fs::copy(std::env::current_exe().unwrap(), &executable).unwrap();
    let expected_digest = digest(&fs::read(&executable).unwrap());

    assert!(TrustedExecutableRegistration::new(
        "cargo",
        "1.97.1",
        "cargo.exe",
        expected_digest.clone(),
    )
    .is_err());
    assert!(ExecutableRegistry::load(
        vec![
            TrustedExecutableRegistration::new("cargo", "1.97.1", &executable, digest(b"wrong"),)
                .unwrap()
        ],
        Arc::new(TestExecutableInspector),
    )
    .is_err());

    let registry = ExecutableRegistry::load(
        vec![TrustedExecutableRegistration::new(
            "cargo",
            "1.97.1",
            &executable,
            expected_digest.clone(),
        )
        .unwrap()],
        Arc::new(TestExecutableInspector),
    )
    .unwrap();
    let resolved = registry.resolve("cargo", "1.97.1").unwrap();

    assert_eq!(
        resolved.canonical_path,
        fs::canonicalize(&executable).unwrap()
    );
    assert_eq!(resolved.sha256, expected_digest);
    assert_eq!(resolved.toolchain_id, "cargo");
    assert!(registry.resolve("cargo", "1.98.0").is_err());

    fs::write(&executable, b"attacker replacement").unwrap();
    assert!(registry.verify_and_retain(&resolved).is_err());
}

#[test]
fn environment_profiles_start_empty_reject_secrets_and_hash_canonically() {
    assert!(TrustedEnvironmentProfile::new(
        "inherited",
        vec![("CI".to_owned(), "1".to_owned())],
        true,
    )
    .is_err());
    assert!(TrustedEnvironmentProfile::new(
        "duplicates",
        vec![
            ("Path".to_owned(), "one".to_owned()),
            ("PATH".to_owned(), "two".to_owned()),
        ],
        false,
    )
    .is_err());
    assert!(TrustedEnvironmentProfile::new(
        "secret-name",
        vec![("AWS_SECRET_ACCESS_KEY".to_owned(), "value".to_owned())],
        false,
    )
    .is_err());
    assert!(TrustedEnvironmentProfile::new(
        "secret-value",
        vec![(
            "SAFE_NAME".to_owned(),
            "ghp_012345678901234567890123456789".to_owned()
        )],
        false,
    )
    .is_err());

    let expected_digest = Sha256Digest::new(
        "sha256:c465e195c2dd90a8fc0317b7ba545d3fa5233faec2b1a216c4d205dc7be61c65",
    )
    .unwrap();
    let registry = EnvironmentProfileRegistry::load(vec![TrustedEnvironmentProfile::new(
        "rust-build",
        vec![
            ("RUST_BACKTRACE".to_owned(), "0".to_owned()),
            ("ci".to_owned(), "1".to_owned()),
        ],
        false,
    )
    .unwrap()])
    .unwrap();
    let resolved = registry.resolve("rust-build", &expected_digest).unwrap();

    assert_eq!(resolved.digest, expected_digest);
    assert_eq!(
        resolved.values.into_iter().collect::<Vec<_>>(),
        vec![
            ("CI".to_owned(), "1".to_owned()),
            ("RUST_BACKTRACE".to_owned(), "0".to_owned()),
        ]
    );
    assert!(registry.resolve("rust-build", &digest(b"wrong")).is_err());
}

#[test]
fn network_profiles_fail_closed_on_unsupported_redirect_or_rebinding_state() {
    let expected_digest = Sha256Digest::new(
        "sha256:baf1943f40995492be93b9ff7bc4e873623b2bfd04b4cf707ea2918b29451d31",
    )
    .unwrap();
    let adapter = NetworkPolicyAdapter::load(vec![TrustedNetworkProfile::new(
        "offline",
        NetworkProfile::Denied,
        Vec::new(),
        "firewall-rule-7",
    )
    .unwrap()])
    .unwrap();

    assert!(adapter
        .prepare(
            "missing",
            NetworkProfile::Denied,
            NetworkEnforcementEvidence::new("firewall-rule-7", true, true).unwrap(),
        )
        .is_err());
    assert!(adapter
        .prepare(
            "offline",
            NetworkProfile::ProviderEndpointOnly,
            NetworkEnforcementEvidence::new("firewall-rule-7", true, true).unwrap(),
        )
        .is_err());
    assert!(adapter
        .prepare(
            "offline",
            NetworkProfile::Denied,
            NetworkEnforcementEvidence::new("firewall-rule-7", false, true).unwrap(),
        )
        .is_err());
    assert!(adapter
        .prepare(
            "offline",
            NetworkProfile::Denied,
            NetworkEnforcementEvidence::new("firewall-rule-7", true, false).unwrap(),
        )
        .is_err());

    let prepared = adapter
        .prepare(
            "offline",
            NetworkProfile::Denied,
            NetworkEnforcementEvidence::new("firewall-rule-7", true, true).unwrap(),
        )
        .unwrap();
    assert_eq!(prepared.profile, NetworkProfile::Denied);
    assert_eq!(prepared.profile_digest, expected_digest);
    assert_eq!(prepared.receipt.enforcement_id(), "firewall-rule-7");
}

#[test]
fn private_runtime_cwd_must_be_registered_and_reverified_by_identity() {
    let root = TempDir::new().unwrap();
    let runtime = root.path().join("private-runtime");
    fs::create_dir(&runtime).unwrap();
    fs::write(runtime.join(".identity"), b"original").unwrap();

    assert!(TrustedPrivateRuntimeDirectory::new("agent-runtime", "relative/runtime").is_err());
    let registry = PrivateRuntimeDirectoryRegistry::load(
        vec![TrustedPrivateRuntimeDirectory::new("agent-runtime", &runtime).unwrap()],
        Arc::new(TestPrivateRuntimeInspector),
    )
    .unwrap();
    assert!(registry.resolve("missing").is_err());
    let resolved = registry.resolve("agent-runtime").unwrap();

    fs::rename(&runtime, root.path().join("original-runtime")).unwrap();
    fs::create_dir(&runtime).unwrap();
    fs::write(runtime.join(".identity"), b"replacement").unwrap();
    assert!(registry.verify_and_retain(&resolved).is_err());
}

struct TestExecutableInspector;

struct TestExecutableGuard;

impl ExecutableVerificationGuard for TestExecutableGuard {}

impl ExecutableArtifactInspector for TestExecutableInspector {
    fn inspect_and_retain(
        &self,
        configured_absolute_path: &str,
        toolchain_id: &str,
        expected_sha256: &Sha256Digest,
    ) -> Result<(ResolvedExecutable, Box<dyn ExecutableVerificationGuard>), PortError> {
        let path = Path::new(configured_absolute_path);
        let canonical_path = fs::canonicalize(path).map_err(|_| denied())?;
        let observed_digest = digest(&fs::read(path).map_err(|_| denied())?);
        if &observed_digest != expected_sha256 {
            return Err(integrity_failure());
        }
        Ok((
            ResolvedExecutable {
                canonical_path,
                sha256: observed_digest.clone(),
                file_identity: ExecutableFileIdentity::new(format!(
                    "test:{}",
                    observed_digest.as_str()
                ))?,
                toolchain_id: toolchain_id.to_owned(),
            },
            Box::new(TestExecutableGuard),
        ))
    }
}

struct TestPrivateRuntimeInspector;

struct TestPrivateRuntimeGuard;

impl PrivateRuntimeDirectoryVerificationGuard for TestPrivateRuntimeGuard {}

impl PrivateRuntimeDirectoryInspector for TestPrivateRuntimeInspector {
    fn inspect_and_retain(
        &self,
        configured_absolute_path: &str,
        registration_id: &str,
    ) -> Result<
        (
            ResolvedPrivateRuntimeDirectory,
            Box<dyn PrivateRuntimeDirectoryVerificationGuard>,
        ),
        PortError,
    > {
        let path = Path::new(configured_absolute_path);
        let identity_bytes = fs::read(path.join(".identity")).map_err(|_| denied())?;
        Ok((
            ResolvedPrivateRuntimeDirectory {
                canonical_path: fs::canonicalize(path).map_err(|_| denied())?,
                file_identity: DirectoryFileIdentity::new(format!(
                    "test:{}",
                    digest(&identity_bytes).as_str()
                ))?,
                registration_id: registration_id.to_owned(),
            },
            Box::new(TestPrivateRuntimeGuard),
        ))
    }
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

fn digest(bytes: &[u8]) -> Sha256Digest {
    Sha256Digest::new(format!("sha256:{:x}", Sha256::digest(bytes))).unwrap()
}
