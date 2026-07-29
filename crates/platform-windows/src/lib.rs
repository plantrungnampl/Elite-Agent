#![cfg(windows)]

mod executable_inspector;
mod filesystem;
mod job;
mod lpac;
mod private_runtime;
mod process;

pub use executable_inspector::{RetainedExecutable, WindowsExecutableInspector};
pub use filesystem::{CapabilityRegistration, WindowsCapabilityAdapter};
#[cfg(feature = "test-seams")]
pub use job::{
    block_next_job_cleanup_failure_for_test, JobCleanupFailureControlForTest,
    JobCleanupFailurePointForTest,
};
pub use lpac::TrustedLpacWorktreeRegistration;
#[cfg(feature = "test-seams")]
pub use lpac::{
    bypass_aap_attestation_for_test, configure_all_packages_canary_for_test,
    fail_lpac_token_verification_for_test, lpac_lifecycle_counts_for_test,
    LpacLifecycleCountsForTest, LpacTokenVerificationMismatchForTest,
};
pub use private_runtime::{
    RetainedPrivateRuntimeDirectory, WindowsPrivateRuntimeDirectoryInspector,
};
pub use process::WindowsProcessLauncher;
#[cfg(feature = "test-seams")]
pub use process::{
    fail_after_resume_for_test, fail_next_output_reader_start_for_test,
    omit_all_application_packages_policy_for_test, output_reader_counts_for_test,
};
#[cfg(feature = "test-seams")]
pub use process::{
    IsolatedWorkerBoundaryAdapter, IsolatedWorkerBoundaryBinding, IsolatedWorkerBoundaryClaims,
    PreparedIsolatedWorkerBoundary,
};
