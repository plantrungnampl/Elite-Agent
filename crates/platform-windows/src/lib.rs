#![cfg(windows)]

mod executable_inspector;
mod filesystem;
mod job;
mod private_runtime;
mod process;

pub use executable_inspector::{RetainedExecutable, WindowsExecutableInspector};
pub use filesystem::{CapabilityRegistration, WindowsCapabilityAdapter};
#[cfg(feature = "test-seams")]
pub use job::{
    block_next_job_cleanup_failure_for_test, JobCleanupFailureControlForTest,
    JobCleanupFailurePointForTest,
};
pub use private_runtime::{
    RetainedPrivateRuntimeDirectory, WindowsPrivateRuntimeDirectoryInspector,
};
#[cfg(feature = "test-seams")]
pub use process::{
    fail_after_resume_for_test, fail_next_output_reader_start_for_test,
    output_reader_counts_for_test,
};
pub use process::{
    IsolatedWorkerBoundaryAdapter, IsolatedWorkerBoundaryBinding, IsolatedWorkerBoundaryClaims,
    PreparedIsolatedWorkerBoundary, WindowsProcessLauncher,
};
