use std::ffi::c_void;
use std::fs::File;
use std::mem::size_of;
use std::os::windows::io::FromRawHandle;
use std::ptr;
use std::sync::atomic::{AtomicBool, Ordering};
#[cfg(feature = "test-seams")]
use std::sync::{Arc, Condvar};
use std::sync::{Mutex, OnceLock};
use std::thread;
use std::time::{Duration, Instant};

#[cfg(feature = "test-seams")]
use local_agent_terminal_application::ToolExecutionId;
use local_agent_terminal_application::{
    AuthorizedProcessRequest, JobReceipt, PortError, Retryability, SafeErrorClassification,
};
use windows_sys::Win32::Foundation::{
    CloseHandle, GetLastError, SetLastError, ERROR_ALREADY_EXISTS, ERROR_SUCCESS, HANDLE,
    INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, JobObjectBasicAccountingInformation,
    JobObjectEndOfJobTimeInformation, JobObjectExtendedLimitInformation, OpenJobObjectW,
    QueryInformationJobObject, SetInformationJobObject, TerminateJobObject,
    JOBOBJECT_BASIC_ACCOUNTING_INFORMATION, JOBOBJECT_END_OF_JOB_TIME_INFORMATION,
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JOB_OBJECT_LIMIT_ACTIVE_PROCESS,
    JOB_OBJECT_LIMIT_BREAKAWAY_OK, JOB_OBJECT_LIMIT_JOB_MEMORY, JOB_OBJECT_LIMIT_JOB_TIME,
    JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE, JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK,
    JOB_OBJECT_TERMINATE_AT_END_OF_JOB,
};
use windows_sys::Win32::System::SystemServices::{JOB_OBJECT_QUERY, JOB_OBJECT_TERMINATE};
use windows_sys::Win32::System::Threading::{
    GetExitCodeProcess, TerminateProcess, WaitForSingleObject, INFINITE,
};

pub(super) const TERMINATED_EXIT_CODE: u32 = 0xC000_013A;
const TREE_EXIT_DEADLINE: Duration = Duration::from_secs(5);
const NATURAL_TREE_EXIT_GRACE: Duration = Duration::from_millis(50);
const REQUIRED_LIMIT_FLAGS: u32 = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
    | JOB_OBJECT_LIMIT_ACTIVE_PROCESS
    | JOB_OBJECT_LIMIT_JOB_MEMORY
    | JOB_OBJECT_LIMIT_JOB_TIME;
const BREAKAWAY_LIMIT_FLAGS: u32 =
    JOB_OBJECT_LIMIT_BREAKAWAY_OK | JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK;

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
    entries: usize,
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
    pub fn wait_for_entry(&self, expected: usize, timeout: Duration) -> bool {
        let (state, changed) = &*self.state;
        let Ok(state) = state.lock() else {
            return false;
        };
        changed
            .wait_timeout_while(state, timeout, |state| state.entries < expected)
            .is_ok_and(|(state, _)| state.entries >= expected)
    }

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
    #[cfg(feature = "test-seams")]
    execution_id: String,
    termination: Mutex<()>,
    terminated: AtomicBool,
    assigned: AtomicBool,
    configured_limits: OnceLock<ConfiguredJobLimits>,
}

struct ConfiguredJobLimits {
    memory_limit_bytes: u64,
    cpu_time_limit_ms: u64,
    max_active_processes: u32,
}

pub(super) struct RetainedJob {
    job: OwnedHandle,
    root_pid: u32,
    job_id: String,
    configured_limits: ConfiguredJobLimits,
}

impl ActiveJob {
    pub(super) fn new(
        job: OwnedHandle,
        process: OwnedHandle,
        root_pid: u32,
        job_id: String,
        execution_id: String,
    ) -> Self {
        #[cfg(not(feature = "test-seams"))]
        let _ = execution_id;
        Self {
            job,
            process,
            root_pid,
            job_id,
            #[cfg(feature = "test-seams")]
            execution_id,
            termination: Mutex::new(()),
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
        limits.BasicLimitInformation.LimitFlags = REQUIRED_LIMIT_FLAGS;
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
        if !self.assigned.load(Ordering::Acquire) {
            // Unassigned jobs are never published, so this pre-configuration
            // fallback has no concurrent termination caller to serialize with.
            if !self.terminated.load(Ordering::Acquire) {
                terminate_process(&self.process);
                self.terminated.store(true, Ordering::Release);
            }
            return Ok(());
        }
        #[cfg(feature = "test-seams")]
        record_termination_entry(&self.execution_id);
        let _termination = self.termination.lock().map_err(|_| platform_error())?;
        if self.terminated.load(Ordering::Acquire) {
            return Ok(());
        }
        #[cfg(feature = "test-seams")]
        if controlled_cleanup_failure(&self.execution_id, JobCleanupFailurePointForTest::Terminate)
        {
            return Err(platform_error());
        }
        terminate_job(&self.job)?;
        self.terminated.store(true, Ordering::Release);
        Ok(())
    }

    pub(super) fn wait_process(&self, timeout_ms: u32) -> u32 {
        // SAFETY: the process handle remains owned by self for this call.
        unsafe { WaitForSingleObject(self.process.as_raw(), timeout_ms) }
    }

    pub(super) fn process_handle(&self) -> HANDLE {
        self.process.as_raw()
    }

    pub(super) const fn root_pid(&self) -> u32 {
        self.root_pid
    }

    pub(super) fn job_id(&self) -> &str {
        &self.job_id
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
        if controlled_cleanup_failure(&self.execution_id, JobCleanupFailurePointForTest::TreeWait) {
            return Err(platform_error());
        }
        wait_for_tree_exit(&self.job)
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
        job_receipt(
            &self.job,
            self.root_pid,
            &self.job_id,
            configured,
            tree_terminated,
        )
    }

    fn active_process_count(&self) -> Result<u32, PortError> {
        Ok(self.accounting()?.ActiveProcesses)
    }

    fn accounting(&self) -> Result<JOBOBJECT_BASIC_ACCOUNTING_INFORMATION, PortError> {
        query_job_accounting(&self.job)
    }

    fn verify_configured_limits(
        &self,
        request: &AuthorizedProcessRequest,
    ) -> Result<ConfiguredJobLimits, PortError> {
        let observed = query_extended_limits(&self.job).inspect_err(|_| {
            self.terminate_unassigned();
        })?;
        let expected_ticks = millis_to_windows_ticks(request.limits.cpu_time_limit_ms)?;
        let expected_memory =
            usize::try_from(request.limits.memory_limit_bytes).map_err(|_| invalid_input())?;
        if observed.BasicLimitInformation.LimitFlags & REQUIRED_LIMIT_FLAGS != REQUIRED_LIMIT_FLAGS
            || observed.BasicLimitInformation.LimitFlags & BREAKAWAY_LIMIT_FLAGS != 0
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

impl RetainedJob {
    pub(super) fn open(job_id: &str, root_pid: u32) -> Result<Self, PortError> {
        let name = wide_job_name(job_id)?;
        // SAFETY: name is a live NUL-terminated string; the returned handle is owned.
        let job = OwnedHandle::new(unsafe {
            OpenJobObjectW(JOB_OBJECT_QUERY | JOB_OBJECT_TERMINATE, 0, name.as_ptr())
        })?;
        let configured_limits = verify_retained_controls(&job)?;
        Ok(Self {
            job,
            root_pid,
            job_id: job_id.to_owned(),
            configured_limits,
        })
    }

    pub(super) fn terminate(&self) -> Result<(), PortError> {
        terminate_job(&self.job)
    }

    pub(super) fn wait_tree_exit(&self) -> Result<(), PortError> {
        wait_for_tree_exit(&self.job)
    }

    pub(super) fn receipt(&self) -> Result<JobReceipt, PortError> {
        job_receipt(
            &self.job,
            self.root_pid,
            &self.job_id,
            &self.configured_limits,
            true,
        )
    }
}

fn verify_retained_controls(job: &OwnedHandle) -> Result<ConfiguredJobLimits, PortError> {
    let observed = query_extended_limits(job)?;
    let flags = observed.BasicLimitInformation.LimitFlags;
    if flags & REQUIRED_LIMIT_FLAGS != REQUIRED_LIMIT_FLAGS
        || flags & BREAKAWAY_LIMIT_FLAGS != 0
        || observed.BasicLimitInformation.ActiveProcessLimit == 0
        || observed.BasicLimitInformation.PerJobUserTimeLimit <= 0
        || observed.BasicLimitInformation.PerJobUserTimeLimit % 10_000 != 0
        || observed.JobMemoryLimit == 0
        || query_end_of_job_time_action(job)? != JOB_OBJECT_TERMINATE_AT_END_OF_JOB
    {
        return Err(platform_error());
    }
    Ok(ConfiguredJobLimits {
        memory_limit_bytes: u64::try_from(observed.JobMemoryLimit).map_err(|_| platform_error())?,
        cpu_time_limit_ms: u64::try_from(observed.BasicLimitInformation.PerJobUserTimeLimit)
            .map_err(|_| platform_error())?
            / 10_000,
        max_active_processes: observed.BasicLimitInformation.ActiveProcessLimit,
    })
}

fn terminate_job(job: &OwnedHandle) -> Result<(), PortError> {
    // SAFETY: the Job Object handle remains valid for this call.
    if unsafe { TerminateJobObject(job.as_raw(), TERMINATED_EXIT_CODE) } == 0 {
        return Err(platform_error());
    }
    Ok(())
}

fn wait_for_tree_exit(job: &OwnedHandle) -> Result<(), PortError> {
    let deadline = Instant::now() + TREE_EXIT_DEADLINE;
    loop {
        if query_job_accounting(job)?.ActiveProcesses == 0 {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(platform_error());
        }
        thread::sleep(Duration::from_millis(1));
    }
}

fn query_job_accounting(
    job: &OwnedHandle,
) -> Result<JOBOBJECT_BASIC_ACCOUNTING_INFORMATION, PortError> {
    let mut accounting = JOBOBJECT_BASIC_ACCOUNTING_INFORMATION::default();
    // SAFETY: accounting is writable for the declared structure size and job is valid.
    if unsafe {
        QueryInformationJobObject(
            job.as_raw(),
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

fn query_extended_limits(
    job: &OwnedHandle,
) -> Result<JOBOBJECT_EXTENDED_LIMIT_INFORMATION, PortError> {
    let mut limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
    // SAFETY: limits is writable for the declared structure size and job is valid.
    if unsafe {
        QueryInformationJobObject(
            job.as_raw(),
            JobObjectExtendedLimitInformation,
            (&mut limits as *mut JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast::<c_void>(),
            size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            ptr::null_mut(),
        )
    } == 0
    {
        return Err(platform_error());
    }
    Ok(limits)
}

fn query_end_of_job_time_action(job: &OwnedHandle) -> Result<u32, PortError> {
    let mut action = JOBOBJECT_END_OF_JOB_TIME_INFORMATION::default();
    // SAFETY: action is writable for the declared structure size and job is valid.
    if unsafe {
        QueryInformationJobObject(
            job.as_raw(),
            JobObjectEndOfJobTimeInformation,
            (&mut action as *mut JOBOBJECT_END_OF_JOB_TIME_INFORMATION).cast::<c_void>(),
            size_of::<JOBOBJECT_END_OF_JOB_TIME_INFORMATION>() as u32,
            ptr::null_mut(),
        )
    } == 0
    {
        return Err(platform_error());
    }
    Ok(action.EndOfJobTimeAction)
}

fn job_receipt(
    job: &OwnedHandle,
    root_pid: u32,
    job_id: &str,
    configured: &ConfiguredJobLimits,
    tree_terminated: bool,
) -> Result<JobReceipt, PortError> {
    let accounting = query_job_accounting(job)?;
    let total_user_time_ms =
        u64::try_from(accounting.TotalUserTime).map_err(|_| platform_error())? / 10_000;
    Ok(JobReceipt {
        root_pid,
        job_id: job_id.to_owned(),
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

#[cfg(feature = "test-seams")]
fn record_termination_entry(job_id: &str) {
    let state = cleanup_failure_state(job_id, JobCleanupFailurePointForTest::Terminate);
    let Some(state) = state else {
        return;
    };
    let (state, changed) = &*state;
    if let Ok(mut state) = state.lock() {
        state.entries += 1;
        changed.notify_all();
    };
}

#[cfg(feature = "test-seams")]
fn controlled_cleanup_failure(job_id: &str, point: JobCleanupFailurePointForTest) -> bool {
    let state = cleanup_failure_state(job_id, point);
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

#[cfg(feature = "test-seams")]
fn cleanup_failure_state(
    job_id: &str,
    point: JobCleanupFailurePointForTest,
) -> Option<Arc<(Mutex<JobCleanupFailureState>, Condvar)>> {
    JOB_CLEANUP_FAILURE.lock().ok().and_then(|configured| {
        configured
            .as_ref()
            .filter(|failure| failure.execution_id == job_id && failure.point == point)
            .map(|failure| Arc::clone(&failure.state))
    })
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

pub(super) fn create_job(job_id: &str) -> Result<OwnedHandle, PortError> {
    let name = wide_job_name(job_id)?;
    // SAFETY: name is a live NUL-terminated string and null security attributes use
    // the caller's default DACL.
    let job = unsafe {
        SetLastError(ERROR_SUCCESS);
        OwnedHandle::new(CreateJobObjectW(ptr::null(), name.as_ptr()))?
    };
    // SAFETY: CreateJobObjectW documents last-error as ERROR_ALREADY_EXISTS on reuse.
    if unsafe { GetLastError() } == ERROR_ALREADY_EXISTS {
        return Err(integrity_failure());
    }
    Ok(job)
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

fn wide_job_name(job_id: &str) -> Result<Vec<u16>, PortError> {
    if job_id.is_empty() || job_id.contains('\0') {
        return Err(invalid_input());
    }
    Ok(job_id.encode_utf16().chain(std::iter::once(0)).collect())
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
