use std::collections::BTreeMap;
use std::ffi::{c_void, OsStr, OsString};
use std::fs::{File, OpenOptions};
use std::io::Read;
use std::mem::size_of;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::fs::OpenOptionsExt;
use std::os::windows::io::AsRawHandle;
use std::path::Path;
#[cfg(feature = "test-seams")]
use std::path::PathBuf;
use std::ptr;
use std::sync::{Arc, Mutex, Weak};
use std::time::Instant;

use local_agent_terminal_application::{
    validate_and_order_process_writes, AuthorizedProcessRequest, BoundedOutput,
    CancellationReceipt, ObservedProcessWrite, PortError, ProcessLauncher, ProcessReceipt,
    ProcessStatus, Retryability, SafeErrorClassification, ToolExecutionId, WorkspaceWritePermit,
};
#[cfg(feature = "test-seams")]
use local_agent_terminal_application::{
    AuthorizedExpectedWrite, EnforcedNetworkProfile, ProcessFenceBinding, ProcessLimits,
    ProcessWorkingDirectory, ResolvedEnvironmentProfile, ResolvedExecutable,
};
#[cfg(feature = "test-seams")]
use local_agent_terminal_domain::LeaseClaim;
use local_agent_terminal_domain::{ProcessTrustTier, Sha256Digest};
use sha2::{Digest, Sha256};
use windows_sys::Win32::Foundation::{
    SetHandleInformation, HANDLE, HANDLE_FLAG_INHERIT, WAIT_OBJECT_0, WAIT_TIMEOUT,
};
use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;
use windows_sys::Win32::Security::SECURITY_CAPABILITIES;
use windows_sys::Win32::Storage::FileSystem::{
    GetFileInformationByHandle, BY_HANDLE_FILE_INFORMATION, FILE_SHARE_READ,
};
use windows_sys::Win32::System::Pipes::CreatePipe;
use windows_sys::Win32::System::Threading::{
    CreateProcessW, DeleteProcThreadAttributeList, InitializeProcThreadAttributeList, ResumeThread,
    UpdateProcThreadAttribute, CREATE_NO_WINDOW, CREATE_SUSPENDED, CREATE_UNICODE_ENVIRONMENT,
    EXTENDED_STARTUPINFO_PRESENT, INFINITE, PROCESS_INFORMATION,
    PROC_THREAD_ATTRIBUTE_ALL_APPLICATION_PACKAGES_POLICY, PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
    PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES, STARTF_USESTDHANDLES, STARTUPINFOEXW,
};
use windows_sys::Win32::System::WindowsProgramming::PROCESS_CREATION_ALL_APPLICATION_PACKAGES_OPT_OUT;

use crate::job::{create_job, terminate_process, validate_job_limits, ActiveJob, OwnedHandle};
use crate::lpac::{
    record_current_windows_error, record_resume_succeeded, record_suspended_child_created,
    LpacBoundary, PreparedLpacBoundary, TrustedLpacWorktreeRegistration,
};

const FAILED_THREAD_RESUME: u32 = u32::MAX;

#[cfg(feature = "test-seams")]
static FAIL_OUTPUT_READER_START: Mutex<Option<ToolExecutionId>> = Mutex::new(None);

#[cfg(feature = "test-seams")]
static FAIL_AFTER_RESUME: Mutex<Option<ToolExecutionId>> = Mutex::new(None);

#[cfg(feature = "test-seams")]
static OMIT_ALL_APPLICATION_PACKAGES_POLICY: Mutex<Option<ToolExecutionId>> = Mutex::new(None);

#[cfg(feature = "test-seams")]
static OUTPUT_READER_COUNTS: Mutex<BTreeMap<ToolExecutionId, (usize, usize)>> =
    Mutex::new(BTreeMap::new());

#[cfg(feature = "test-seams")]
#[doc(hidden)]
pub fn fail_next_output_reader_start_for_test(execution_id: ToolExecutionId) {
    if let Ok(mut failure) = FAIL_OUTPUT_READER_START.lock() {
        *failure = Some(execution_id);
    }
}

#[cfg(feature = "test-seams")]
#[doc(hidden)]
pub fn fail_after_resume_for_test(execution_id: ToolExecutionId) {
    if let Ok(mut failure) = FAIL_AFTER_RESUME.lock() {
        *failure = Some(execution_id);
    }
}

#[cfg(feature = "test-seams")]
#[doc(hidden)]
pub fn omit_all_application_packages_policy_for_test(execution_id: ToolExecutionId) {
    if let Ok(mut configured) = OMIT_ALL_APPLICATION_PACKAGES_POLICY.lock() {
        *configured = Some(execution_id);
    }
}

#[cfg(feature = "test-seams")]
fn take_omit_all_application_packages_policy(execution_id: &ToolExecutionId) -> bool {
    OMIT_ALL_APPLICATION_PACKAGES_POLICY
        .lock()
        .is_ok_and(|mut configured| {
            if configured.as_ref() == Some(execution_id) {
                configured.take();
                true
            } else {
                false
            }
        })
}

#[cfg(feature = "test-seams")]
#[doc(hidden)]
pub fn output_reader_counts_for_test(execution_id: &ToolExecutionId) -> (usize, usize) {
    OUTPUT_READER_COUNTS
        .lock()
        .ok()
        .and_then(|counts| counts.get(execution_id).copied())
        .unwrap_or_default()
}

#[cfg(feature = "test-seams")]
fn take_after_resume_failure(execution_id: &ToolExecutionId) -> bool {
    FAIL_AFTER_RESUME.lock().is_ok_and(|mut failure| {
        if failure.as_ref() == Some(execution_id) {
            failure.take();
            true
        } else {
            false
        }
    })
}

/// Evidence supplied by a trusted OS-containment adapter and retained through launch.
///
/// This value does not create containment. The adapter that constructs it is part of
/// the trusted computing base and must keep its identity, ACL, and network controls
/// active until the process tree has exited.
#[derive(Debug)]
#[cfg(feature = "test-seams")]
pub struct PreparedIsolatedWorkerBoundary {
    launch_cwd: PathBuf,
    identity_receipt: String,
    acl_receipt: String,
    write_scope_receipt: Option<String>,
    claims: IsolatedWorkerBoundaryClaims,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg(feature = "test-seams")]
pub struct IsolatedWorkerBoundaryClaims {
    pub execution_id: ToolExecutionId,
    pub trust_tier: ProcessTrustTier,
    pub executable: ResolvedExecutable,
    pub argv: Vec<String>,
    pub cwd: ProcessWorkingDirectory,
    pub environment: ResolvedEnvironmentProfile,
    pub network: EnforcedNetworkProfile,
    pub timeout_ms: u64,
    pub limits: ProcessLimits,
    pub expected_writes: Vec<AuthorizedExpectedWrite>,
    pub executor_claim: LeaseClaim,
    pub executor_fence: ProcessFenceBinding,
}

#[cfg(feature = "test-seams")]
impl IsolatedWorkerBoundaryClaims {
    pub fn from_request(request: &AuthorizedProcessRequest) -> Self {
        Self {
            execution_id: request.execution_id.clone(),
            trust_tier: request.trust_tier,
            executable: request.executable.clone(),
            argv: request.argv.clone(),
            cwd: request.cwd.clone(),
            environment: request.environment.clone(),
            network: request.network.clone(),
            timeout_ms: request.timeout_ms,
            limits: request.limits.clone(),
            expected_writes: request.expected_writes.clone(),
            executor_claim: request.executor_claim.clone(),
            executor_fence: request.executor_fence.clone(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg(feature = "test-seams")]
pub struct IsolatedWorkerBoundaryBinding {
    identity_receipt: String,
    acl_receipt: String,
}

#[cfg(feature = "test-seams")]
impl IsolatedWorkerBoundaryBinding {
    pub fn new(
        identity_receipt: impl Into<String>,
        acl_receipt: impl Into<String>,
    ) -> Result<Self, PortError> {
        let identity_receipt = identity_receipt.into();
        let acl_receipt = acl_receipt.into();
        if !valid_receipt(&identity_receipt) || !valid_receipt(&acl_receipt) {
            return Err(invalid_input());
        }
        Ok(Self {
            identity_receipt,
            acl_receipt,
        })
    }
}

#[cfg(feature = "test-seams")]
impl PreparedIsolatedWorkerBoundary {
    pub fn new(
        launch_cwd: impl Into<PathBuf>,
        identity_receipt: impl Into<String>,
        acl_receipt: impl Into<String>,
        write_scope_receipt: Option<String>,
        claims: IsolatedWorkerBoundaryClaims,
    ) -> Result<Self, PortError> {
        let launch_cwd = launch_cwd.into();
        let identity_receipt = identity_receipt.into();
        let acl_receipt = acl_receipt.into();
        if !launch_cwd.is_absolute()
            || !valid_receipt(&identity_receipt)
            || !valid_receipt(&acl_receipt)
            || write_scope_receipt
                .as_deref()
                .is_some_and(|receipt| !valid_receipt(receipt))
            || claims.expected_writes.is_empty() != write_scope_receipt.is_none()
        {
            return Err(invalid_input());
        }
        Ok(Self {
            launch_cwd,
            identity_receipt,
            acl_receipt,
            write_scope_receipt,
            claims,
        })
    }

    pub fn launch_cwd(&self) -> &Path {
        &self.launch_cwd
    }

    pub fn identity_receipt(&self) -> &str {
        &self.identity_receipt
    }

    pub fn acl_receipt(&self) -> &str {
        &self.acl_receipt
    }

    pub fn write_scope_receipt(&self) -> Option<&str> {
        self.write_scope_receipt.as_deref()
    }
}

/// Trusted port for controls a Job Object cannot provide.
///
/// Implementations must enforce a dedicated identity, filesystem/registry ACLs,
/// network policy, and write observation. Tests may inject a fake implementation
/// to exercise Job Object lifecycle only; that is not containment evidence.
#[cfg(feature = "test-seams")]
pub trait IsolatedWorkerBoundaryAdapter: Send + Sync {
    fn prepare(
        &self,
        request: &AuthorizedProcessRequest,
    ) -> Result<PreparedIsolatedWorkerBoundary, PortError>;

    fn verify_before_resume(
        &self,
        request: &AuthorizedProcessRequest,
        prepared: &PreparedIsolatedWorkerBoundary,
    ) -> Result<(), PortError>;

    fn observed_writes(
        &self,
        request: &AuthorizedProcessRequest,
        prepared: &PreparedIsolatedWorkerBoundary,
    ) -> Result<Vec<ObservedProcessWrite>, PortError> {
        if request.expected_writes.is_empty() {
            Ok(Vec::new())
        } else {
            let _ = prepared;
            Err(permission_denied())
        }
    }
}

pub struct WindowsProcessLauncher {
    boundary: Option<ConfiguredProcessBoundary>,
    active: Mutex<BTreeMap<ToolExecutionId, Arc<ActiveJob>>>,
}

#[cfg(feature = "test-seams")]
struct ConfiguredIsolatedWorkerBoundary {
    adapter: Arc<dyn IsolatedWorkerBoundaryAdapter>,
    binding: IsolatedWorkerBoundaryBinding,
}

enum ConfiguredProcessBoundary {
    Lpac(LpacBoundary),
    #[cfg(feature = "test-seams")]
    ClaimOnly(ConfiguredIsolatedWorkerBoundary),
}

enum PreparedProcessBoundary {
    Lpac(PreparedLpacBoundary),
    #[cfg(feature = "test-seams")]
    ClaimOnly(Box<PreparedIsolatedWorkerBoundary>),
}

impl ConfiguredProcessBoundary {
    fn prepare(
        &self,
        request: &AuthorizedProcessRequest,
    ) -> Result<PreparedProcessBoundary, PortError> {
        match self {
            Self::Lpac(boundary) => boundary.prepare(request).map(PreparedProcessBoundary::Lpac),
            #[cfg(feature = "test-seams")]
            Self::ClaimOnly(configured) => {
                let prepared = configured.adapter.prepare(request)?;
                verify_prepared_boundary(request, &prepared, &configured.binding)?;
                Ok(PreparedProcessBoundary::ClaimOnly(Box::new(prepared)))
            }
        }
    }

    fn verify_before_resume(
        &self,
        _request: &AuthorizedProcessRequest,
        prepared: &PreparedProcessBoundary,
        process: HANDLE,
    ) -> Result<(), PortError> {
        match (self, prepared) {
            (Self::Lpac(_), PreparedProcessBoundary::Lpac(prepared)) => {
                prepared.verify_child_token(process)
            }
            #[cfg(feature = "test-seams")]
            (Self::ClaimOnly(configured), PreparedProcessBoundary::ClaimOnly(prepared)) => {
                configured.adapter.verify_before_resume(_request, prepared)
            }
            #[cfg(feature = "test-seams")]
            _ => Err(integrity_failure()),
        }
    }

    fn observed_writes(
        &self,
        _request: &AuthorizedProcessRequest,
        prepared: &PreparedProcessBoundary,
    ) -> Result<Vec<ObservedProcessWrite>, PortError> {
        match (self, prepared) {
            (Self::Lpac(_), PreparedProcessBoundary::Lpac(_)) => Ok(Vec::new()),
            #[cfg(feature = "test-seams")]
            (Self::ClaimOnly(configured), PreparedProcessBoundary::ClaimOnly(prepared)) => {
                configured.adapter.observed_writes(_request, prepared)
            }
            #[cfg(feature = "test-seams")]
            _ => Err(integrity_failure()),
        }
    }
}

impl PreparedProcessBoundary {
    fn launch_cwd(&self) -> &Path {
        match self {
            Self::Lpac(prepared) => prepared.launch_cwd(),
            #[cfg(feature = "test-seams")]
            Self::ClaimOnly(prepared) => prepared.launch_cwd(),
        }
    }

    fn security_capabilities(&self) -> Option<SECURITY_CAPABILITIES> {
        match self {
            Self::Lpac(prepared) => Some(prepared.security_capabilities()),
            #[cfg(feature = "test-seams")]
            Self::ClaimOnly(_) => None,
        }
    }

    fn environment_block(
        &self,
        _request: &AuthorizedProcessRequest,
    ) -> Result<Vec<u16>, PortError> {
        match self {
            Self::Lpac(prepared) => os_environment_block(prepared.environment()),
            #[cfg(feature = "test-seams")]
            Self::ClaimOnly(_) => environment_block(&_request.environment.values),
        }
    }

    fn requires_proven_tree_exit(&self) -> bool {
        matches!(self, Self::Lpac(_))
    }

    fn cleanup(&mut self) -> Result<(), PortError> {
        match self {
            Self::Lpac(prepared) => prepared.cleanup(),
            #[cfg(feature = "test-seams")]
            Self::ClaimOnly(_) => Ok(()),
        }
    }
}

impl WindowsProcessLauncher {
    /// Creates the production-safe unavailable state. No child is created.
    pub fn fail_closed() -> Self {
        Self {
            boundary: None,
            active: Mutex::new(BTreeMap::new()),
        }
    }

    /// Installs a trusted OS-containment adapter.
    ///
    /// The caller is responsible for admitting only an adapter that has passed the
    /// complete containment acceptance suite.
    #[cfg(feature = "test-seams")]
    pub fn with_isolated_worker_boundary(
        boundary: Arc<dyn IsolatedWorkerBoundaryAdapter>,
        binding: IsolatedWorkerBoundaryBinding,
    ) -> Self {
        Self {
            boundary: Some(ConfiguredProcessBoundary::ClaimOnly(
                ConfiguredIsolatedWorkerBoundary {
                    adapter: boundary,
                    binding,
                },
            )),
            active: Mutex::new(BTreeMap::new()),
        }
    }

    pub fn with_lpac_boundary(
        registrations: Vec<TrustedLpacWorktreeRegistration>,
    ) -> Result<Self, PortError> {
        Ok(Self {
            boundary: Some(ConfiguredProcessBoundary::Lpac(LpacBoundary::new(
                registrations,
            )?)),
            active: Mutex::new(BTreeMap::new()),
        })
    }
}

impl Default for WindowsProcessLauncher {
    fn default() -> Self {
        Self::fail_closed()
    }
}

impl ProcessLauncher for WindowsProcessLauncher {
    fn execute(&self, request: AuthorizedProcessRequest) -> Result<ProcessReceipt, PortError> {
        let configured = self.boundary.as_ref().ok_or_else(permission_denied)?;
        validate_request(&request)?;
        let _executable_guard = verify_executable_and_retain(&request.executable)?;
        let prepared = configured.prepare(&request)?;

        let started_at = Instant::now();
        let child = create_suspended_process(&request, &prepared)?;
        let mut cleanup = ExecutionCleanupGuard::new(
            self,
            request.execution_id.clone(),
            child.active.clone(),
            prepared,
        );
        child.active.configure_and_assign(&request)?;
        configured.verify_before_resume(
            &request,
            cleanup.prepared(),
            child.active.process_handle(),
        )?;

        drop(child.stdout_write);
        drop(child.stderr_write);
        drop(child.stdin_read);
        let stdout_reader = output_reader(
            child.stdout_read,
            request.limits.max_stdout_bytes,
            Arc::downgrade(&child.active),
            &request.execution_id,
        )?;
        let stderr_reader = output_reader(
            child.stderr_read,
            request.limits.max_stderr_bytes,
            Arc::downgrade(&child.active),
            &request.execution_id,
        )?;
        cleanup.register()?;

        let workspace_permit = match request
            .executor_fence
            .monitor_permit(request.executor_claim.clone())
        {
            Ok(permit) => permit,
            Err(error) => {
                child.active.terminate()?;
                child.active.wait_process(INFINITE);
                child.active.wait_tree_exit()?;
                join_output(stdout_reader)?;
                join_output(stderr_reader)?;
                cleanup.finish()?;
                return Err(error);
            }
        };
        cleanup.hold_permit(workspace_permit);

        // SAFETY: the primary thread handle is owned and remains valid here. The
        // process is already assigned to the configured kill-on-close Job Object.
        let resume_result = unsafe { ResumeThread(child.primary_thread.as_raw()) };
        if resume_result == FAILED_THREAD_RESUME {
            child.active.terminate()?;
            child.active.wait_process(INFINITE);
            child.active.wait_tree_exit()?;
            return Err(platform_error());
        }
        record_resume_succeeded(&request.execution_id);
        #[cfg(feature = "test-seams")]
        if take_after_resume_failure(&request.execution_id) {
            return Err(platform_error());
        }
        drop(child.primary_thread);

        let timeout_ms = wait_timeout(request.timeout_ms);
        let wait_result = child.active.wait_process(timeout_ms);
        if wait_result == WAIT_TIMEOUT {
            child.active.terminate()?;
            child.active.wait_process(INFINITE);
        } else if wait_result != WAIT_OBJECT_0 {
            child.active.terminate()?;
            child.active.wait_process(INFINITE);
            child.active.wait_tree_exit()?;
            return Err(platform_error());
        }
        let resource_limit_terminated = child.active.resource_limit_terminated_process()?;
        child.active.stop_remaining_tree()?;

        let stdout = join_output(stdout_reader)?;
        let stderr = join_output(stderr_reader)?;
        let terminated = child.active.was_terminated() || resource_limit_terminated;
        let exit_code = if terminated {
            None
        } else {
            Some(child.active.exit_code()?)
        };
        let observed_writes = configured.observed_writes(&request, cleanup.prepared());
        let observed_writes =
            validate_and_order_process_writes(&request.expected_writes, observed_writes?)?;

        let status = if terminated {
            ProcessStatus::Terminated
        } else {
            ProcessStatus::Exited
        };
        let job_receipt = child.active.receipt(terminated)?;
        let receipt = ProcessReceipt {
            execution_id: request.execution_id.clone(),
            status,
            exit_code,
            output_digest: output_digest(&stdout.bytes, &stderr.bytes),
            stdout,
            stderr,
            duration_ms: elapsed_millis(started_at),
            job_receipt,
            observed_writes,
        };
        cleanup.finish()?;
        Ok(receipt)
    }

    fn cancel(&self, execution_id: &ToolExecutionId) -> Result<CancellationReceipt, PortError> {
        let active = self
            .active
            .lock()
            .map_err(|_| internal_error())?
            .get(execution_id)
            .cloned()
            .ok_or_else(permission_denied)?;
        active.terminate()?;
        if active.wait_process(INFINITE) != WAIT_OBJECT_0 {
            return Err(platform_error());
        }
        active.wait_tree_exit()?;
        Ok(CancellationReceipt {
            execution_id: execution_id.clone(),
            status: ProcessStatus::Terminated,
            job_receipt: Some(active.receipt(true)?),
            cancelled: true,
        })
    }
}

impl WindowsProcessLauncher {
    fn remove_active(&self, execution_id: &ToolExecutionId, completed: &Arc<ActiveJob>) {
        if let Ok(mut active) = self.active.lock() {
            let should_remove = active
                .get(execution_id)
                .is_some_and(|registered| Arc::ptr_eq(registered, completed));
            if should_remove {
                active.remove(execution_id);
            }
        }
    }
}

struct ExecutionCleanupGuard<'launcher, 'permit> {
    launcher: &'launcher WindowsProcessLauncher,
    execution_id: ToolExecutionId,
    active: Arc<ActiveJob>,
    boundary: Option<PreparedProcessBoundary>,
    permit: Option<WorkspaceWritePermit<'permit>>,
    registered: bool,
    armed: bool,
}

impl<'launcher, 'permit> ExecutionCleanupGuard<'launcher, 'permit> {
    fn new(
        launcher: &'launcher WindowsProcessLauncher,
        execution_id: ToolExecutionId,
        active: Arc<ActiveJob>,
        boundary: PreparedProcessBoundary,
    ) -> Self {
        Self {
            launcher,
            execution_id,
            active,
            boundary: Some(boundary),
            permit: None,
            registered: false,
            armed: true,
        }
    }

    fn hold_permit(&mut self, permit: WorkspaceWritePermit<'permit>) {
        self.permit = Some(permit);
    }

    fn prepared(&self) -> &PreparedProcessBoundary {
        self.boundary
            .as_ref()
            .expect("prepared boundary remains owned until cleanup completes")
    }

    fn register(&mut self) -> Result<(), PortError> {
        let mut active = self.launcher.active.lock().map_err(|_| internal_error())?;
        if active.contains_key(&self.execution_id) {
            return Err(integrity_failure());
        }
        active.insert(self.execution_id.clone(), self.active.clone());
        self.registered = true;
        Ok(())
    }

    fn finish(mut self) -> Result<(), PortError> {
        if let Some(boundary) = self.boundary.as_mut() {
            boundary.cleanup()?;
        }
        self.boundary.take();
        if self.registered {
            self.launcher
                .remove_active(&self.execution_id, &self.active);
            self.registered = false;
        }
        self.armed = false;
        Ok(())
    }
}

impl Drop for ExecutionCleanupGuard<'_, '_> {
    fn drop(&mut self) {
        let boundary_requires_tree_exit = self
            .boundary
            .as_ref()
            .is_some_and(PreparedProcessBoundary::requires_proven_tree_exit);
        if self.armed && (self.permit.is_some() || boundary_requires_tree_exit) {
            loop {
                let tree_exited = self.active.terminate().is_ok()
                    && self.active.wait_process(INFINITE) == WAIT_OBJECT_0
                    && self.active.wait_tree_exit().is_ok();
                if tree_exited {
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(1));
            }
        } else if self.armed && self.active.terminate().is_ok() {
            self.active.wait_process(INFINITE);
            let _ = self.active.wait_tree_exit();
        }
        if self.armed {
            if let Some(boundary) = self.boundary.as_mut() {
                while boundary.cleanup().is_err() {
                    std::thread::sleep(std::time::Duration::from_millis(1));
                }
            }
            self.boundary.take();
        }
        if self.registered {
            self.launcher
                .remove_active(&self.execution_id, &self.active);
        }
    }
}

impl Drop for WindowsProcessLauncher {
    fn drop(&mut self) {
        if let Ok(mut active) = self.active.lock() {
            for job in active.values() {
                let _ = job.terminate();
                job.wait_process(INFINITE);
                let _ = job.wait_tree_exit();
            }
            active.clear();
        }
    }
}

struct SuspendedChild {
    active: Arc<ActiveJob>,
    primary_thread: OwnedHandle,
    stdin_read: OwnedHandle,
    stdout_read: OwnedHandle,
    stdout_write: OwnedHandle,
    stderr_read: OwnedHandle,
    stderr_write: OwnedHandle,
}

fn create_suspended_process(
    request: &AuthorizedProcessRequest,
    boundary: &PreparedProcessBoundary,
) -> Result<SuspendedChild, PortError> {
    let job = create_job()?;
    let (stdin_read, stdin_write) = create_pipe_pair(PipeInheritance::Read)?;
    drop(stdin_write);
    let (stdout_read, stdout_write) = create_pipe_pair(PipeInheritance::Write)?;
    let (stderr_read, stderr_write) = create_pipe_pair(PipeInheritance::Write)?;
    let inherited = [
        stdin_read.as_raw(),
        stdout_write.as_raw(),
        stderr_write.as_raw(),
    ];
    let attributes = ThreadAttributeList::new(
        &inherited,
        boundary.security_capabilities(),
        &request.execution_id,
    )?;
    let mut startup = STARTUPINFOEXW::default();
    startup.StartupInfo.cb = size_of::<STARTUPINFOEXW>() as u32;
    startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
    startup.StartupInfo.hStdInput = stdin_read.as_raw();
    startup.StartupInfo.hStdOutput = stdout_write.as_raw();
    startup.StartupInfo.hStdError = stderr_write.as_raw();
    startup.lpAttributeList = attributes.as_raw();

    let application = wide_nul(request.executable.canonical_path.as_os_str())?;
    let mut command_line = command_line(&request.executable.canonical_path, &request.argv)?;
    let environment = boundary.environment_block(request)?;
    let current_directory = wide_nul(boundary.launch_cwd().as_os_str())?;
    let mut process_information = PROCESS_INFORMATION::default();
    // SAFETY: all pointers reference live, correctly terminated buffers; startup and
    // process_information use their documented layouts; the handle list limits
    // inheritance to the three standard-stream handles.
    let created = unsafe {
        CreateProcessW(
            application.as_ptr(),
            command_line.as_mut_ptr(),
            ptr::null(),
            ptr::null(),
            1,
            CREATE_SUSPENDED
                | CREATE_NO_WINDOW
                | CREATE_UNICODE_ENVIRONMENT
                | EXTENDED_STARTUPINFO_PRESENT,
            environment.as_ptr().cast::<c_void>(),
            current_directory.as_ptr(),
            &startup.StartupInfo,
            &mut process_information,
        )
    };
    if created == 0 {
        record_current_windows_error(&request.execution_id);
        return Err(platform_error());
    }
    record_suspended_child_created(&request.execution_id);

    let process = OwnedHandle::new(process_information.hProcess)?;
    let primary_thread = OwnedHandle::new(process_information.hThread).inspect_err(|_| {
        terminate_process(&process);
    })?;
    Ok(SuspendedChild {
        active: Arc::new(ActiveJob::new(
            job,
            process,
            process_information.dwProcessId,
            request.execution_id.as_str().to_owned(),
        )),
        primary_thread,
        stdin_read,
        stdout_read,
        stdout_write,
        stderr_read,
        stderr_write,
    })
}

enum PipeInheritance {
    Read,
    Write,
}

fn create_pipe_pair(
    inherited_end: PipeInheritance,
) -> Result<(OwnedHandle, OwnedHandle), PortError> {
    let mut read = ptr::null_mut();
    let mut write = ptr::null_mut();
    let security = SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: ptr::null_mut(),
        bInheritHandle: 1,
    };
    // SAFETY: output pointers and SECURITY_ATTRIBUTES are valid for this call.
    if unsafe { CreatePipe(&mut read, &mut write, &security, 0) } == 0 {
        return Err(platform_error());
    }
    let read = OwnedHandle::new(read)?;
    let write = OwnedHandle::new(write)?;
    let parent_end = match inherited_end {
        PipeInheritance::Read => write.as_raw(),
        PipeInheritance::Write => read.as_raw(),
    };
    // SAFETY: parent_end is a valid pipe handle; clearing inherit does not transfer it.
    if unsafe { SetHandleInformation(parent_end, HANDLE_FLAG_INHERIT, 0) } == 0 {
        return Err(platform_error());
    }
    Ok((read, write))
}

struct ThreadAttributeList {
    words: Vec<usize>,
    initialized: bool,
    security_capabilities: Option<Box<SECURITY_CAPABILITIES>>,
    all_application_packages_policy: Option<Box<u32>>,
}

impl ThreadAttributeList {
    fn new(
        handles: &[HANDLE],
        security_capabilities: Option<SECURITY_CAPABILITIES>,
        execution_id: &ToolExecutionId,
    ) -> Result<Self, PortError> {
        #[cfg(feature = "test-seams")]
        let omit_policy = take_omit_all_application_packages_policy(execution_id);
        #[cfg(not(feature = "test-seams"))]
        let omit_policy = false;
        let has_security_capabilities = security_capabilities.is_some();
        let include_policy = has_security_capabilities && !omit_policy;
        let attribute_count = 1 + u32::from(has_security_capabilities) + u32::from(include_policy);
        let mut bytes_required = 0;
        // SAFETY: the first call intentionally supplies null to query required size.
        unsafe {
            InitializeProcThreadAttributeList(
                ptr::null_mut(),
                attribute_count,
                0,
                &mut bytes_required,
            );
        }
        if bytes_required == 0 {
            record_current_windows_error(execution_id);
            return Err(platform_error());
        }
        let word_count = bytes_required.div_ceil(size_of::<usize>());
        let mut list = Self {
            words: vec![0; word_count],
            initialized: false,
            security_capabilities: security_capabilities.map(Box::new),
            all_application_packages_policy: include_policy
                .then(|| Box::new(PROCESS_CREATION_ALL_APPLICATION_PACKAGES_OPT_OUT)),
        };
        // SAFETY: words provides an aligned writable allocation of at least the
        // queried size for one attribute.
        if unsafe {
            InitializeProcThreadAttributeList(
                list.as_raw(),
                attribute_count,
                0,
                &mut bytes_required,
            )
        } == 0
        {
            record_current_windows_error(execution_id);
            return Err(platform_error());
        }
        list.initialized = true;
        // SAFETY: handles remains live through CreateProcessW and has the exact byte size.
        if unsafe {
            UpdateProcThreadAttribute(
                list.as_raw(),
                0,
                PROC_THREAD_ATTRIBUTE_HANDLE_LIST as usize,
                handles.as_ptr().cast::<c_void>(),
                size_of_val(handles),
                ptr::null_mut(),
                ptr::null(),
            )
        } == 0
        {
            record_current_windows_error(execution_id);
            return Err(platform_error());
        }
        if let Some(capabilities) = list.security_capabilities.as_deref() {
            if unsafe {
                UpdateProcThreadAttribute(
                    list.as_raw(),
                    0,
                    PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES as usize,
                    (capabilities as *const SECURITY_CAPABILITIES)
                        .cast_mut()
                        .cast::<c_void>(),
                    size_of::<SECURITY_CAPABILITIES>(),
                    ptr::null_mut(),
                    ptr::null(),
                )
            } == 0
            {
                record_current_windows_error(execution_id);
                return Err(platform_error());
            }
            if let Some(policy) = list.all_application_packages_policy.as_deref() {
                if unsafe {
                    UpdateProcThreadAttribute(
                        list.as_raw(),
                        0,
                        PROC_THREAD_ATTRIBUTE_ALL_APPLICATION_PACKAGES_POLICY as usize,
                        (policy as *const u32).cast_mut().cast::<c_void>(),
                        size_of::<u32>(),
                        ptr::null_mut(),
                        ptr::null(),
                    )
                } == 0
                {
                    record_current_windows_error(execution_id);
                    return Err(platform_error());
                }
            }
        }
        Ok(list)
    }

    fn as_raw(&self) -> *mut c_void {
        self.words.as_ptr().cast_mut().cast::<c_void>()
    }
}

impl Drop for ThreadAttributeList {
    fn drop(&mut self) {
        if self.initialized {
            // SAFETY: words contains a successfully initialized attribute list.
            unsafe {
                DeleteProcThreadAttributeList(self.as_raw());
            }
        }
    }
}

struct OutputReader {
    handle: std::thread::JoinHandle<Result<BoundedOutput, PortError>>,
    #[cfg(feature = "test-seams")]
    execution_id: ToolExecutionId,
}

fn output_reader(
    handle: OwnedHandle,
    max_bytes: u64,
    active: Weak<ActiveJob>,
    execution_id: &ToolExecutionId,
) -> Result<OutputReader, PortError> {
    #[cfg(not(feature = "test-seams"))]
    let _ = execution_id;
    #[cfg(feature = "test-seams")]
    {
        let mut failure = FAIL_OUTPUT_READER_START
            .lock()
            .map_err(|_| internal_error())?;
        if failure.as_ref() == Some(execution_id) {
            failure.take();
            return Err(internal_error());
        }
    }
    let max_bytes = usize::try_from(max_bytes).map_err(|_| invalid_input())?;
    let handle = std::thread::Builder::new()
        .name("bounded-process-output".to_owned())
        .spawn(move || read_bounded(handle.into_file(), max_bytes, &active))
        .map_err(|_| internal_error())?;
    #[cfg(feature = "test-seams")]
    if let Ok(mut counts) = OUTPUT_READER_COUNTS.lock() {
        counts.entry(execution_id.clone()).or_default().0 += 1;
    }
    Ok(OutputReader {
        handle,
        #[cfg(feature = "test-seams")]
        execution_id: execution_id.clone(),
    })
}

fn read_bounded(
    mut file: File,
    max_bytes: usize,
    active: &Weak<ActiveJob>,
) -> Result<BoundedOutput, PortError> {
    let mut bytes = Vec::with_capacity(max_bytes.min(64 * 1024));
    let mut buffer = [0_u8; 8 * 1024];
    let mut truncated = false;
    loop {
        let count = file.read(&mut buffer).map_err(|_| platform_error())?;
        if count == 0 {
            break;
        }
        let remaining = max_bytes.saturating_sub(bytes.len());
        bytes.extend_from_slice(&buffer[..count.min(remaining)]);
        if count > remaining {
            truncated = true;
            if let Some(active) = active.upgrade() {
                let _ = active.terminate();
            }
        }
    }
    Ok(BoundedOutput { bytes, truncated })
}

fn join_output(reader: OutputReader) -> Result<BoundedOutput, PortError> {
    #[cfg(feature = "test-seams")]
    let execution_id = reader.execution_id.clone();
    let result = reader.handle.join().map_err(|_| internal_error())?;
    #[cfg(feature = "test-seams")]
    if let Ok(mut counts) = OUTPUT_READER_COUNTS.lock() {
        counts.entry(execution_id).or_default().1 += 1;
    }
    result
}

fn validate_request(request: &AuthorizedProcessRequest) -> Result<(), PortError> {
    if request.trust_tier != ProcessTrustTier::IsolatedWorker
        || !request.executable.canonical_path.is_absolute()
        || request.argv.iter().any(|argument| argument.contains('\0'))
        || request.environment.values.iter().any(|(name, value)| {
            name.is_empty()
                || name.contains(['=', '\0', '\r', '\n'])
                || value.contains(['\0', '\r', '\n'])
        })
        || request.timeout_ms == 0
        || request.limits.memory_limit_bytes == 0
        || request.limits.cpu_time_limit_ms == 0
        || request.limits.max_stdout_bytes == 0
        || request.limits.max_stderr_bytes == 0
        || request.limits.max_active_processes == 0
        || is_shell(&request.executable)
    {
        return Err(permission_denied());
    }
    validate_job_limits(request)
}

fn verify_executable_and_retain(
    executable: &local_agent_terminal_application::ResolvedExecutable,
) -> Result<File, PortError> {
    let metadata =
        std::fs::symlink_metadata(&executable.canonical_path).map_err(|_| permission_denied())?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(permission_denied());
    }
    let canonical =
        std::fs::canonicalize(&executable.canonical_path).map_err(|_| permission_denied())?;
    if canonical != executable.canonical_path {
        return Err(integrity_failure());
    }
    let mut options = OpenOptions::new();
    options.read(true).share_mode(FILE_SHARE_READ);
    let mut retained = options.open(&canonical).map_err(|_| permission_denied())?;
    let identity = executable_identity(&retained)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let count = retained
            .read(&mut buffer)
            .map_err(|_| integrity_failure())?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
    }
    let digest = Sha256Digest::new(format!("sha256:{:x}", hasher.finalize()))
        .map_err(|_| integrity_failure())?;
    if digest != executable.sha256
        || identity != executable.file_identity.as_str()
        || std::fs::canonicalize(&executable.canonical_path)
            .ok()
            .as_ref()
            != Some(&canonical)
    {
        return Err(integrity_failure());
    }
    Ok(retained)
}

fn executable_identity(file: &File) -> Result<String, PortError> {
    let mut information = BY_HANDLE_FILE_INFORMATION::default();
    // SAFETY: the file handle is valid and information is writable for the API call.
    if unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut information) } == 0 {
        return Err(platform_error());
    }
    let file_index =
        (u64::from(information.nFileIndexHigh) << 32) | u64::from(information.nFileIndexLow);
    Ok(format!(
        "windows:{:016x}:{file_index:016x}",
        information.dwVolumeSerialNumber,
    ))
}

#[cfg(feature = "test-seams")]
fn verify_prepared_boundary(
    request: &AuthorizedProcessRequest,
    prepared: &PreparedIsolatedWorkerBoundary,
    binding: &IsolatedWorkerBoundaryBinding,
) -> Result<(), PortError> {
    let claims = &prepared.claims;
    if prepared.identity_receipt != binding.identity_receipt
        || prepared.acl_receipt != binding.acl_receipt
        || claims.execution_id != request.execution_id
        || claims.executor_claim.task_id() != request.executor_claim.task_id()
        || claims.executor_claim.holder_run_id() != request.executor_claim.holder_run_id()
        || claims.executor_claim.token() != request.executor_claim.token()
        || claims.executor_fence != request.executor_fence
        || claims.trust_tier != request.trust_tier
        || claims.executable.canonical_path != request.executable.canonical_path
        || claims.executable.toolchain_id != request.executable.toolchain_id
        || claims.executable.file_identity != request.executable.file_identity
        || claims.executable.sha256 != request.executable.sha256
        || claims.argv != request.argv
        || claims.cwd != request.cwd
        || cwd_root_identity(&claims.cwd) != cwd_root_identity(&request.cwd)
        || claims.environment.name != request.environment.name
        || claims.environment.digest != request.environment.digest
        || claims.environment.values != request.environment.values
        || claims.network.profile != request.network.profile
        || claims.network.profile_digest != request.network.profile_digest
        || claims.network.receipt.enforcement_id() != request.network.receipt.enforcement_id()
        || claims.network.receipt.profile_digest() != request.network.receipt.profile_digest()
        || claims.timeout_ms != request.timeout_ms
        || claims.limits != request.limits
        || claims.expected_writes != request.expected_writes
        || request.expected_writes.is_empty() != prepared.write_scope_receipt.is_none()
        || !prepared.launch_cwd.is_dir()
    {
        return Err(integrity_failure());
    }
    Ok(())
}

#[cfg(feature = "test-seams")]
fn cwd_root_identity(cwd: &ProcessWorkingDirectory) -> Option<&str> {
    match cwd {
        ProcessWorkingDirectory::IsolatedWorktree(resolved) => {
            Some(resolved.root_identity.as_str())
        }
        ProcessWorkingDirectory::PrivateRuntime(_) => None,
    }
}

fn is_shell(executable: &local_agent_terminal_application::ResolvedExecutable) -> bool {
    let registered = executable.toolchain_id.to_ascii_lowercase();
    let file = executable
        .canonical_path
        .file_name()
        .and_then(OsStr::to_str)
        .unwrap_or_default()
        .to_ascii_lowercase();
    [
        "cmd",
        "cmd.exe",
        "powershell",
        "powershell.exe",
        "pwsh",
        "pwsh.exe",
    ]
    .iter()
    .any(|shell| registered == *shell || file == *shell)
}

fn command_line(executable: &Path, argv: &[String]) -> Result<Vec<u16>, PortError> {
    let mut command = quote_argument(&executable.as_os_str().to_string_lossy());
    for argument in argv {
        command.push(' ');
        command.push_str(&quote_argument(argument));
    }
    let mut wide = OsStr::new(&command).encode_wide().collect::<Vec<_>>();
    if wide.len() >= 32_767 {
        return Err(invalid_input());
    }
    wide.push(0);
    Ok(wide)
}

fn quote_argument(argument: &str) -> String {
    if !argument.is_empty()
        && !argument
            .chars()
            .any(|character| character == ' ' || character == '\t' || character == '"')
    {
        return argument.to_owned();
    }
    let mut quoted = String::from("\"");
    let mut backslashes = 0;
    for character in argument.chars() {
        if character == '\\' {
            backslashes += 1;
        } else {
            if character == '"' {
                quoted.extend(std::iter::repeat_n('\\', backslashes + 1));
            }
            quoted.extend(std::iter::repeat_n('\\', backslashes));
            backslashes = 0;
            quoted.push(character);
        }
    }
    quoted.extend(std::iter::repeat_n('\\', backslashes * 2));
    quoted.push('"');
    quoted
}

#[cfg(feature = "test-seams")]
fn environment_block(values: &BTreeMap<String, String>) -> Result<Vec<u16>, PortError> {
    let mut block = Vec::new();
    for (name, value) in values {
        block.extend(OsStr::new(name).encode_wide());
        block.push('=' as u16);
        block.extend(OsStr::new(value).encode_wide());
        block.push(0);
    }
    block.push(0);
    if values.is_empty() {
        block.push(0);
    }
    Ok(block)
}

fn os_environment_block(values: &BTreeMap<OsString, OsString>) -> Result<Vec<u16>, PortError> {
    let mut block = Vec::new();
    for (name, value) in values {
        block.extend(name.encode_wide());
        block.push('=' as u16);
        block.extend(value.encode_wide());
        block.push(0);
    }
    block.push(0);
    if values.is_empty() {
        block.push(0);
    }
    Ok(block)
}

fn wide_nul(value: &OsStr) -> Result<Vec<u16>, PortError> {
    let mut wide = value.encode_wide().collect::<Vec<_>>();
    if wide.contains(&0) {
        return Err(invalid_input());
    }
    wide.push(0);
    Ok(wide)
}

fn wait_timeout(timeout_ms: u64) -> u32 {
    u32::try_from(timeout_ms)
        .unwrap_or(u32::MAX - 1)
        .min(u32::MAX - 1)
}

fn elapsed_millis(started_at: Instant) -> u64 {
    u64::try_from(started_at.elapsed().as_millis()).unwrap_or(u64::MAX)
}

fn output_digest(stdout: &[u8], stderr: &[u8]) -> Sha256Digest {
    let mut hasher = Sha256::new();
    hasher.update((stdout.len() as u64).to_le_bytes());
    hasher.update(stdout);
    hasher.update((stderr.len() as u64).to_le_bytes());
    hasher.update(stderr);
    Sha256Digest::new(format!("sha256:{:x}", hasher.finalize()))
        .expect("SHA-256 formatting always satisfies the domain invariant")
}

#[cfg(feature = "test-seams")]
fn valid_receipt(value: &str) -> bool {
    !value.trim().is_empty() && value.len() <= 256 && !value.contains(['\0', '\r', '\n'])
}

fn invalid_input() -> PortError {
    PortError::failure(
        SafeErrorClassification::InvalidInput,
        Retryability::NonRetryable,
    )
}

fn permission_denied() -> PortError {
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

fn platform_error() -> PortError {
    PortError::failure(
        SafeErrorClassification::Unavailable,
        Retryability::NonRetryable,
    )
}

fn internal_error() -> PortError {
    PortError::failure(
        SafeErrorClassification::Internal,
        Retryability::NonRetryable,
    )
}
