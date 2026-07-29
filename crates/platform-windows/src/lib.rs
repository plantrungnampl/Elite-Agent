#![cfg(windows)]

mod executable_inspector;
mod filesystem;
mod job;
mod private_runtime;
mod process;

pub use executable_inspector::{RetainedExecutable, WindowsExecutableInspector};
pub use filesystem::{CapabilityRegistration, WindowsCapabilityAdapter};
pub use private_runtime::{
    RetainedPrivateRuntimeDirectory, WindowsPrivateRuntimeDirectoryInspector,
};
#[cfg(feature = "test-seams")]
pub use process::fail_next_output_reader_start_for_test;
pub use process::{
    IsolatedWorkerBoundaryAdapter, IsolatedWorkerBoundaryBinding, IsolatedWorkerBoundaryClaims,
    PreparedIsolatedWorkerBoundary, WindowsProcessLauncher,
};
