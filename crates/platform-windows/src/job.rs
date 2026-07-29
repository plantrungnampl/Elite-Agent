use std::ffi::c_void;
use std::fs::File;
use std::mem::size_of;
use std::os::windows::io::FromRawHandle;
use std::ptr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::OnceLock;
#[cfg(feature = "test-seams")]
use std::sync::{Arc, Condvar, Mutex};
use std::thread;
use std::time::{Duration, Instant};

#[cfg(feature = "test-seams")]
use local_agent_terminal_application::ToolExecutionId;
use local_agent_terminal_application::{
    AuthorizedProcessRequest, JobReceipt, PortError, Retryability, SafeErrorClassification,
};
use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, JobObjectBasicAccountingInformation,
    JobObjectEndOfJobTimeInformation, JobObjectExtendedLimitInformation, QueryInformationJobObject,
    SetInformationJobObject, TerminateJobObject, JOBOBJECT_BASIC_ACCOUNTING_INFORMATION,
    JOBOBJECT_END_OF_JOB_TIME_INFORMATION, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
    JOB_OBJECT_LIMIT_ACTIVE_PROCESS, JOB_OBJECT_LIMIT_JOB_MEMORY, JOB_OBJECT_LIMIT_JOB_TIME,
    JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE, JOB_OBJECT_TERMINATE_AT_END_OF_JOB,
};
use windows_sys::Win32::System::Threading::{
    GetExitCodeProcess, TerminateProcess, WaitForSingleObject, INFINITE,
};

pub(super) const TERMINATED_EXIT_CODE: u32 = 0xC000_013A;
const TREE_EXIT_DEADLINE: Duration = Duration::from_secs(5);
const NATURAL_TREE_EXIT_GRACE: Duration = Duration::from_millis(50);

#[cfg(feature = "test-seams")]
static JOB_CLEANUP_FAILURE: Mutex<Option<ConfiguredJobCleanupFailure>> = Mutex::new(None);

#[cfg(feature = "test-seams")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JobCleanupFailurePointForTest {
    Terminate,
    TreeWait,
}

#[cfg(feature = "test-seams")]
struct ConfiguredJobCleanupFailure {
    execution_id: String,
    point: JobCleanupFailurePointForTest,
    state: Arc<(Mutex<JobCleanupFailureState>, Condvar)>,
}

#[cfg(feature = "test-seams")]
#[derive(Default)]
struct JobCleanupFailureState {
    attempts: usize,
    fail_current_attempt: bool,
    allow_cleanup: bool,
}

#[cfg(feature = "test-seams")]
pub struct JobCleanupFailureControlForTest {
    state: Arc<(Mutex<JobCleanupFailureState>, Condvar)>,
}

#[cfg(feature = "test-seams")]
pub fn block_next_job_cleanup_failure_for_test(
    execution_id: ToolExecutionId,
    point: JobCleanupFailurePointForTest,
) -> JobCleanupFailureControlForTest {
    let state = Arc::new((
        Mutex::new(JobCleanupFailureState::default()),
        Condvar::new(),
    ));
    if let Ok(mut configured) = JOB_CLEANUP_FAILURE.lock() {
        *configured = Some(ConfiguredJobCleanupFailure {
            execution_id: execution_id.as_str().to_owned(),
            point,
            state: Arc::clone(&state),
        });
    }
    JobCleanupFailureControlForTest { state }
}

#[cfg(feature = "test-seams")]
impl JobCleanupFailureControlForTest {
    pub fn wait_for_attempt(&self, expected: usize, timeout: Duration) -> bool {
        let (state, changed) = &*self.state;
        let Ok(state) = state.lock() else {
            return false;
        };
        changed
            .wait_timeout_while(state, timeout, |state| state.attempts < expected)
            .is_ok_and(|(state, _)| state.attempts >= expected)
    }

    pub fn fail_current_attempt(&self) {
        let (state, changed) = &*self.state;
        if let Ok(mut state) = state.lock() {
            state.fail_current_attempt = true;
            changed.notify_all();
        }
    }

    pub fn allow_cleanup(&self) {
        let (state, changed) = &*self.state;
        if let Ok(mut state) = state.lock() {
            state.allow_cleanup = true;
            changed.notify_all();
        }
    }
}

pub(super) struct ActiveJob {
    job: OwnedHandle,
    process: OwnedHandle,
    root_pid: u32,
    job_id: String,
    terminated: AtomicBool,
    assigned: AtomicBool,
    configured_limits: OnceLock<ConfiguredJobLimits>,
}

struct ConfiguredJobLimits {
    memory_limit_bytes: u64,
    cpu_time_limit_ms: u64,
    max_active_processes: u32,
}

impl ActiveJob {
    pub(super) fn new(
        job: OwnedHandle,
        process: OwnedHandle,
        root_pid: u32,
        job_id: String,
    ) -> Self {
        Self {
            job,
            process,
            root_pid,
            job_id,
            terminated: AtomicBool::new(false),
            assigned: AtomicBool::new(false),
            configured_limits: OnceLock::new(),
        }
    }

    pub(super) fn configure_and_assign(
        &self,
        request: &AuthorizedProcessRequest,
    ) -> Result<(), PortError> {
        self.configure_end_of_job_time_action()?;
        let mut limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
        limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
            | JOB_OBJECT_LIMIT_ACTIVE_PROCESS
            | JOB_OBJECT_LIMIT_JOB_MEMORY
            | JOB_OBJECT_LIMIT_JOB_TIME;
        limits.BasicLimitInformation.ActiveProcessLimit = request.limits.max_active_processes;
        limits.BasicLimitInformation.PerJobUserTimeLimit =
            millis_to_windows_ticks(request.limits.cpu_time_limit_ms)?;
        limits.JobMemoryLimit =
            usize::try_from(request.limits.memory_limit_bytes).map_err(|_| invalid_input())?;
        // SAFETY: limits points to a fully initialized structure of the declared size.
        if unsafe {
            SetInformationJobObject(
                self.job.as_raw(),
                JobObjectExtendedLimitInformation,
                (&limits as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast::<c_void>(),
                size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            )
        } == 0
        {
            self.terminate_unassigned();
            return Err(platform_error());
        }
        let configured_limits = self.verify_configured_limits(request)?;
        self.configured_limits
            .set(configured_limits)
            .map_err(|_| platform_error())?;
        // SAFETY: both handles are valid and the process remains suspended.
        if unsafe { AssignProcessToJobObject(self.job.as_raw(), self.process.as_raw()) } == 0 {
            self.terminate_unassigned();
            return Err(platform_error());
        }
        self.assigned.store(true, Ordering::Release);
        Ok(())
    }

    pub(super) fn terminate(&self) -> Result<(), PortError> {
        #[cfg(feature = "test-seams")]
        if controlled_cleanup_failure(&self.job_id, JobCleanupFailurePointForTest::Terminate) {
            return Err(platform_error());
        }
        if self
            .terminated
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return Ok(());
        }
        if !self.assigned.load(Ordering::Acquire) {
            terminate_process(&self.process);
            return Ok(());
        }
        // SAFETY: the Job Object handle remains owned by self for this call.
        if unsafe { TerminateJobObject(self.job.as_raw(), TERMINATED_EXIT_CODE) } == 0 {
            self.terminated.store(false, Ordering::Release);
            return Err(platform_error());
        }
        Ok(())
    }

    pub(super) fn wait_process(&self, timeout_ms: u32) -> u32 {
        // SAFETY: the process handle remains owned by self for this call.
        unsafe { WaitForSingleObject(self.process.as_raw(), timeout_ms) }
    }

    pub(super) fn process_handle(&self) -> HANDLE {
        self.process.as_raw()
    }

    pub(super) fn stop_remaining_tree(&self) -> Result<(), PortError> {
        let grace_deadline = Instant::now() + NATURAL_TREE_EXIT_GRACE;
        while self.active_process_count()? != 0 && Instant::now() < grace_deadline {
            thread::sleep(Duration::from_millis(1));
        }
        if self.active_process_count()? == 0 {
            return Ok(());
        }
        self.terminate()?;
        self.wait_tree_exit()
    }

    pub(super) fn wait_tree_exit(&self) -> Result<(), PortError> {
        #[cfg(feature = "test-seams")]
        if controlled_cleanup_failure(&self.job_id, JobCleanupFailurePointForTest::TreeWait) {
            return Err(platform_error());
        }
        let deadline = Instant::now() + TREE_EXIT_DEADLINE;
        loop {
            if self.active_process_count()? == 0 {
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(platform_error());
            }
            thread::sleep(Duration::from_millis(1));
        }
    }

    pub(super) fn exit_code(&self) -> Result<i32, PortError> {
        let mut code = 0;
        // SAFETY: code points to writable storage and the process handle is valid.
        if unsafe { GetExitCodeProcess(self.process.as_raw(), &mut code) } == 0 {
            return Err(platform_error());
        }
        Ok(code as i32)
    }

    pub(super) fn was_terminated(&self) -> bool {
        self.terminated.load(Ordering::Acquire)
    }

    pub(super) fn resource_limit_terminated_process(&self) -> Result<bool, PortError> {
        Ok(self.accounting()?.TotalTerminatedProcesses != 0)
    }

    pub(super) fn receipt(&self, tree_terminated: bool) -> Result<JobReceipt, PortError> {
        let configured = self.configured_limits.get().ok_or_else(platform_error)?;
        let accounting = self.accounting()?;
        let total_user_time_ms =
            u64::try_from(accounting.TotalUserTime).map_err(|_| platform_error())? / 10_000;
        Ok(JobReceipt {
            root_pid: self.root_pid,
            job_id: self.job_id.clone(),
            kill_on_close: true,
            no_breakaway: true,
            job_memory_limit: true,
            job_cpu_time_limit: true,
            memory_limit_bytes: configured.memory_limit_bytes,
            cpu_time_limit_ms: configured.cpu_time_limit_ms,
            max_active_processes: configured.max_active_processes,
            total_user_time_ms,
            resource_limit_terminated: accounting.TotalTerminatedProcesses != 0,
            tree_terminated,
        })
    }

    fn active_process_count(&self) -> Result<u32, PortError> {
        Ok(self.accounting()?.ActiveProcesses)
    }

    fn accounting(&self) -> Result<JOBOBJECT_BASIC_ACCOUNTING_INFORMATION, PortError> {
        let mut accounting = JOBOBJECT_BASIC_ACCOUNTING_INFORMATION::default();
        // SAFETY: accounting is writable for the declared structure size and job is valid.
        if unsafe {
            QueryInformationJobObject(
                self.job.as_raw(),
                JobObjectBasicAccountingInformation,
                (&mut accounting as *mut JOBOBJECT_BASIC_ACCOUNTING_INFORMATION).cast::<c_void>(),
                size_of::<JOBOBJECT_BASIC_ACCOUNTING_INFORMATION>() as u32,
                ptr::null_mut(),
            )
        } == 0
        {
            return Err(platform_error());
        }
        Ok(accounting)
    }

    fn verify_configured_limits(
        &self,
        request: &AuthorizedProcessRequest,
    ) -> Result<ConfiguredJobLimits, PortError> {
        let mut observed = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
        // SAFETY: observed is writable for the declared structure size and job is valid.
        if unsafe {
            QueryInformationJobObject(
                self.job.as_raw(),
                JobObjectExtendedLimitInformation,
                (&mut observed as *mut JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast::<c_void>(),
                size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
                ptr::null_mut(),
            )
        } == 0
        {
            self.terminate_unassigned();
            return Err(platform_error());
        }
        let required_flags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
            | JOB_OBJECT_LIMIT_ACTIVE_PROCESS
            | JOB_OBJECT_LIMIT_JOB_MEMORY
            | JOB_OBJECT_LIMIT_JOB_TIME;
        let expected_ticks = millis_to_windows_ticks(request.limits.cpu_time_limit_ms)?;
        let expected_memory =
            usize::try_from(request.limits.memory_limit_bytes).map_err(|_| invalid_input())?;
        if observed.BasicLimitInformation.LimitFlags & required_flags != required_flags
            || observed.BasicLimitInformation.ActiveProcessLimit
                != request.limits.max_active_processes
            || observed.BasicLimitInformation.PerJobUserTimeLimit != expected_ticks
            || observed.JobMemoryLimit != expected_memory
        {
            self.terminate_unassigned();
            return Err(platform_error());
        }
        Ok(ConfiguredJobLimits {
            memory_limit_bytes: u64::try_from(observed.JobMemoryLimit)
                .map_err(|_| platform_error())?,
            cpu_time_limit_ms: u64::try_from(observed.BasicLimitInformation.PerJobUserTimeLimit)
                .map_err(|_| platform_error())?
                / 10_000,
            max_active_processes: observed.BasicLimitInformation.ActiveProcessLimit,
        })
    }

    fn configure_end_of_job_time_action(&self) -> Result<(), PortError> {
        let action = JOBOBJECT_END_OF_JOB_TIME_INFORMATION {
            EndOfJobTimeAction: JOB_OBJECT_TERMINATE_AT_END_OF_JOB,
        };
        // SAFETY: action points to a fully initialized structure of the declared size.
        if unsafe {
            SetInformationJobObject(
                self.job.as_raw(),
                JobObjectEndOfJobTimeInformation,
                (&action as *const JOBOBJECT_END_OF_JOB_TIME_INFORMATION).cast::<c_void>(),
                size_of::<JOBOBJECT_END_OF_JOB_TIME_INFORMATION>() as u32,
            )
        } == 0
        {
            self.terminate_unassigned();
            return Err(platform_error());
        }
        let mut observed = JOBOBJECT_END_OF_JOB_TIME_INFORMATION::default();
        // SAFETY: observed is writable for the declared structure size and job is valid.
        if unsafe {
            QueryInformationJobObject(
                self.job.as_raw(),
                JobObjectEndOfJobTimeInformation,
                (&mut observed as *mut JOBOBJECT_END_OF_JOB_TIME_INFORMATION).cast::<c_void>(),
                size_of::<JOBOBJECT_END_OF_JOB_TIME_INFORMATION>() as u32,
                ptr::null_mut(),
            )
        } == 0
            || observed.EndOfJobTimeAction != JOB_OBJECT_TERMINATE_AT_END_OF_JOB
        {
            self.terminate_unassigned();
            return Err(platform_error());
        }
        Ok(())
    }

    fn terminate_unassigned(&self) {
        terminate_process(&self.process);
        self.terminated.store(true, Ordering::Release);
    }
}

#[cfg(feature = "test-seams")]
fn controlled_cleanup_failure(job_id: &str, point: JobCleanupFailurePointForTest) -> bool {
    let state = JOB_CLEANUP_FAILURE.lock().ok().and_then(|configured| {
        configured
            .as_ref()
            .filter(|failure| failure.execution_id == job_id && failure.point == point)
            .map(|failure| Arc::clone(&failure.state))
    });
    let Some(state) = state else {
        return false;
    };
    let (state, changed) = &*state;
    let Ok(mut state) = state.lock() else {
        return false;
    };
    if state.allow_cleanup {
        return false;
    }
    state.attempts += 1;
    changed.notify_all();
    while !state.fail_current_attempt && !state.allow_cleanup {
        let Ok(next) = changed.wait(state) else {
            return false;
        };
        state = next;
    }
    if state.allow_cleanup {
        false
    } else {
        state.fail_current_attempt = false;
        true
    }
}

impl Drop for ActiveJob {
    fn drop(&mut self) {
        if !self.assigned.load(Ordering::Acquire) && !self.terminated.load(Ordering::Acquire) {
            terminate_process(&self.process);
            self.terminated.store(true, Ordering::Release);
        }
    }
}

pub(super) struct OwnedHandle {
    raw: usize,
}

impl OwnedHandle {
    pub(super) fn new(raw: HANDLE) -> Result<Self, PortError> {
        if raw.is_null() || raw == INVALID_HANDLE_VALUE {
            return Err(platform_error());
        }
        Ok(Self { raw: raw as usize })
    }

    pub(super) fn as_raw(&self) -> HANDLE {
        self.raw as HANDLE
    }

    pub(super) fn into_file(mut self) -> File {
        let raw = self.as_raw();
        self.raw = 0;
        // SAFETY: ownership of this valid handle is transferred from OwnedHandle to
        // File exactly once; setting raw to zero prevents the original Drop close.
        unsafe { File::from_raw_handle(raw) }
    }
}

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        if self.raw != 0 {
            // SAFETY: raw is a uniquely owned, non-null Windows kernel handle.
            unsafe {
                CloseHandle(self.as_raw());
            }
        }
    }
}

pub(super) fn create_job() -> Result<OwnedHandle, PortError> {
    // SAFETY: null security attributes and name request a private unnamed Job Object.
    OwnedHandle::new(unsafe { CreateJobObjectW(ptr::null(), ptr::null()) })
}

pub(super) fn terminate_process(process: &OwnedHandle) {
    // SAFETY: the process handle is valid. Callers use this only before user code resumes.
    unsafe {
        TerminateProcess(process.as_raw(), TERMINATED_EXIT_CODE);
        WaitForSingleObject(process.as_raw(), INFINITE);
    }
}

fn millis_to_windows_ticks(milliseconds: u64) -> Result<i64, PortError> {
    milliseconds
        .checked_mul(10_000)
        .and_then(|ticks| i64::try_from(ticks).ok())
        .ok_or_else(invalid_input)
}

pub(super) fn validate_job_limits(request: &AuthorizedProcessRequest) -> Result<(), PortError> {
    millis_to_windows_ticks(request.limits.cpu_time_limit_ms)?;
    usize::try_from(request.limits.memory_limit_bytes).map_err(|_| invalid_input())?;
    Ok(())
}

fn invalid_input() -> PortError {
    PortError::failure(
        SafeErrorClassification::InvalidInput,
        Retryability::NonRetryable,
    )
}

fn platform_error() -> PortError {
    PortError::failure(
        SafeErrorClassification::Unavailable,
        Retryability::NonRetryable,
    )
}
