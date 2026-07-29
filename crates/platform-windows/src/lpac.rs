use std::collections::{BTreeMap, BTreeSet};
use std::ffi::{c_void, OsString};
use std::fs::{File, OpenOptions};
use std::os::windows::ffi::OsStringExt;
use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
use std::os::windows::io::AsRawHandle;
use std::path::{Component, Path, PathBuf};
use std::ptr;
use std::sync::Arc;
#[cfg(feature = "test-seams")]
use std::sync::Mutex;
use std::time::Duration;

use local_agent_terminal_application::{
    AuthorizedProcessRequest, CapabilityRootIdentity, PortError, ProcessWorkingDirectory,
    ResolvedExecutable, Retryability, SafeErrorClassification, ToolExecutionId,
};
use local_agent_terminal_domain::{CapabilityRef, NetworkProfile, ProcessTrustTier, TaskId};
use windows_sys::Win32::Foundation::{
    GetLastError, LocalFree, ERROR_ALREADY_EXISTS, ERROR_HANDLE_EOF, ERROR_INSUFFICIENT_BUFFER,
    ERROR_SUCCESS, HANDLE,
};
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidW, GetSecurityInfo, SetEntriesInAclW, SetSecurityInfo, EXPLICIT_ACCESS_W,
    GRANT_ACCESS, REVOKE_ACCESS, SE_FILE_OBJECT, TRUSTEE_IS_SID, TRUSTEE_IS_USER,
    TRUSTEE_IS_WELL_KNOWN_GROUP, TRUSTEE_W,
};
use windows_sys::Win32::Security::Cryptography::{
    BCryptGenRandom, BCRYPT_USE_SYSTEM_PREFERRED_RNG,
};
use windows_sys::Win32::Security::Isolation::{
    CreateAppContainerProfile, DeleteAppContainerProfile, GetAppContainerFolderPath,
};
#[cfg(feature = "test-seams")]
use windows_sys::Win32::Security::PROTECTED_DACL_SECURITY_INFORMATION;
use windows_sys::Win32::Security::{
    AccessCheck, DuplicateTokenEx, EqualSid, FreeSid, GetTokenInformation,
    InitializeSecurityDescriptor, SecurityImpersonation, SetSecurityDescriptorDacl,
    SetSecurityDescriptorGroup, SetSecurityDescriptorOwner, TokenAppContainerSid,
    TokenCapabilities, TokenImpersonation, TokenIsAppContainer, TokenUser, ACL,
    DACL_SECURITY_INFORMATION, GENERIC_MAPPING, NO_INHERITANCE, PRIVILEGE_SET,
    PSECURITY_DESCRIPTOR, PSID, SECURITY_CAPABILITIES, SECURITY_DESCRIPTOR,
    TOKEN_APPCONTAINER_INFORMATION, TOKEN_DUPLICATE, TOKEN_GROUPS, TOKEN_QUERY, TOKEN_USER,
};
#[cfg(feature = "test-seams")]
use windows_sys::Win32::Storage::FileSystem::FILE_ALL_ACCESS;
use windows_sys::Win32::Storage::FileSystem::{
    FileStreamInfo, GetFileInformationByHandle, GetFileInformationByHandleEx,
    BY_HANDLE_FILE_INFORMATION, FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_REPARSE_POINT,
    FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_GENERIC_EXECUTE,
    FILE_GENERIC_READ, FILE_READ_ATTRIBUTES, FILE_SHARE_READ, FILE_STREAM_INFO, READ_CONTROL,
    WRITE_DAC,
};
use windows_sys::Win32::System::Com::CoTaskMemFree;
#[cfg(feature = "test-seams")]
use windows_sys::Win32::System::Threading::GetCurrentProcess;
use windows_sys::Win32::System::Threading::OpenProcessToken;

use crate::job::OwnedHandle;

const HRESULT_ALREADY_EXISTS: i32 = 0x8007_00B7_u32 as i32;
const STREAM_INFORMATION_BUFFER_BYTES: usize = 64 * 1024;

#[derive(Debug)]
pub struct TrustedLpacWorktreeRegistration {
    task_id: TaskId,
    root_identity: CapabilityRootIdentity,
    configured_root: PathBuf,
}

impl TrustedLpacWorktreeRegistration {
    pub fn new(
        task_id: TaskId,
        root_identity: CapabilityRootIdentity,
        configured_root: impl Into<PathBuf>,
    ) -> Result<Self, PortError> {
        let configured_root = configured_root.into();
        if !configured_root.is_absolute() || configured_root.to_str().is_none() {
            return Err(invalid_input());
        }
        Ok(Self {
            task_id,
            root_identity,
            configured_root,
        })
    }
}

#[cfg(feature = "test-seams")]
pub fn configure_all_packages_canary_for_test(directory: &Path, file: &Path) -> Result<(), u32> {
    let directory_handle = open_canary_acl_handle(directory, true)?;
    let file_handle = open_canary_acl_handle(file, false)?;
    let user_buffer = current_token_user_buffer()?;
    let token_user = unsafe { user_buffer.as_ptr().cast::<TOKEN_USER>().read() };
    if token_user.User.Sid.is_null() {
        return Err(13);
    }
    let all_application_packages = FixedAppPackageSid::new(1);
    set_canary_dacl(
        directory_handle.as_raw_handle() as HANDLE,
        token_user.User.Sid,
        all_application_packages.as_psid(),
    )?;
    set_canary_dacl(
        file_handle.as_raw_handle() as HANDLE,
        token_user.User.Sid,
        all_application_packages.as_psid(),
    )
}

#[cfg(feature = "test-seams")]
fn open_canary_acl_handle(path: &Path, directory: bool) -> Result<File, u32> {
    let metadata = std::fs::symlink_metadata(path).map_err(os_error_code)?;
    if metadata.file_type().is_symlink()
        || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
        || metadata.is_dir() != directory
    {
        return Err(5);
    }
    let mut flags = FILE_FLAG_OPEN_REPARSE_POINT;
    if directory {
        flags |= FILE_FLAG_BACKUP_SEMANTICS;
    }
    OpenOptions::new()
        .access_mode(READ_CONTROL | WRITE_DAC)
        .share_mode(FILE_SHARE_READ)
        .custom_flags(flags)
        .open(path)
        .map_err(os_error_code)
}

#[cfg(feature = "test-seams")]
fn current_token_user_buffer() -> Result<Vec<usize>, u32> {
    let mut token = ptr::null_mut();
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
        return Err(unsafe { GetLastError() });
    }
    let token = OwnedHandle::new(token).map_err(|_| 6_u32)?;
    let mut bytes = 0_u32;
    let first =
        unsafe { GetTokenInformation(token.as_raw(), TokenUser, ptr::null_mut(), 0, &mut bytes) };
    let first_error = unsafe { GetLastError() };
    if first != 0 || bytes == 0 || first_error != ERROR_INSUFFICIENT_BUFFER {
        return Err(first_error);
    }
    let capacity = bytes;
    let mut buffer = vec![0_usize; (capacity as usize).div_ceil(std::mem::size_of::<usize>())];
    let mut returned = capacity;
    if unsafe {
        GetTokenInformation(
            token.as_raw(),
            TokenUser,
            buffer.as_mut_ptr().cast::<c_void>(),
            capacity,
            &mut returned,
        )
    } == 0
    {
        return Err(unsafe { GetLastError() });
    }
    if returned < std::mem::size_of::<TOKEN_USER>() as u32 || returned > capacity {
        return Err(13);
    }
    Ok(buffer)
}

#[cfg(feature = "test-seams")]
fn set_canary_dacl(handle: HANDLE, user_sid: PSID, all_packages_sid: PSID) -> Result<(), u32> {
    let entries = [
        explicit_sid_access(user_sid, TRUSTEE_IS_USER, FILE_ALL_ACCESS),
        explicit_sid_access(
            all_packages_sid,
            TRUSTEE_IS_WELL_KNOWN_GROUP,
            FILE_GENERIC_READ | FILE_GENERIC_EXECUTE,
        ),
    ];
    let mut dacl: *mut ACL = ptr::null_mut();
    let acl_result = unsafe {
        SetEntriesInAclW(
            entries.len() as u32,
            entries.as_ptr(),
            ptr::null(),
            &mut dacl,
        )
    };
    if acl_result != ERROR_SUCCESS || dacl.is_null() {
        if !dacl.is_null() {
            unsafe {
                LocalFree(dacl.cast());
            }
        }
        return Err(acl_result);
    }
    let set_result = unsafe {
        SetSecurityInfo(
            handle,
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            ptr::null_mut(),
            ptr::null_mut(),
            dacl,
            ptr::null_mut(),
        )
    };
    unsafe {
        LocalFree(dacl.cast());
    }
    if set_result == ERROR_SUCCESS {
        Ok(())
    } else {
        Err(set_result)
    }
}

fn explicit_sid_access(sid: PSID, trustee_type: i32, permissions: u32) -> EXPLICIT_ACCESS_W {
    EXPLICIT_ACCESS_W {
        grfAccessPermissions: permissions,
        grfAccessMode: GRANT_ACCESS,
        grfInheritance: NO_INHERITANCE,
        Trustee: TRUSTEE_W {
            pMultipleTrustee: ptr::null_mut(),
            MultipleTrusteeOperation: 0,
            TrusteeForm: TRUSTEE_IS_SID,
            TrusteeType: trustee_type,
            ptstrName: sid.cast::<u16>(),
        },
    }
}

#[cfg(feature = "test-seams")]
fn os_error_code(error: std::io::Error) -> u32 {
    error
        .raw_os_error()
        .and_then(|code| u32::try_from(code).ok())
        .unwrap_or(5)
}

fn aap_only_access_check(
    token: HANDLE,
    user_sid: PSID,
    execution_id: &ToolExecutionId,
) -> Result<(u32, bool), PortError> {
    const SYNTHETIC_ACCESS: u32 = 0x0000_0001;

    let mut impersonation_token = ptr::null_mut();
    let duplicate_result = unsafe {
        DuplicateTokenEx(
            token,
            TOKEN_QUERY,
            ptr::null(),
            SecurityImpersonation,
            TokenImpersonation,
            &mut impersonation_token,
        )
    };
    if duplicate_result == 0 {
        record_last_error(execution_id);
        return Err(platform_error());
    }
    let impersonation_token = OwnedHandle::new(impersonation_token)?;

    let world = FixedWorldSid::new();
    let all_application_packages = FixedAppPackageSid::new(1);
    let entries = [
        explicit_sid_access(user_sid, TRUSTEE_IS_USER, SYNTHETIC_ACCESS),
        explicit_sid_access(
            all_application_packages.as_psid(),
            TRUSTEE_IS_WELL_KNOWN_GROUP,
            SYNTHETIC_ACCESS,
        ),
    ];
    let mut dacl: *mut ACL = ptr::null_mut();
    let acl_result = unsafe {
        SetEntriesInAclW(
            entries.len() as u32,
            entries.as_ptr(),
            ptr::null(),
            &mut dacl,
        )
    };
    if acl_result != ERROR_SUCCESS || dacl.is_null() {
        record_windows_error(execution_id, acl_result);
        if !dacl.is_null() {
            unsafe {
                LocalFree(dacl.cast());
            }
        }
        return Err(platform_error());
    }

    let result = (|| {
        let mut descriptor = SECURITY_DESCRIPTOR::default();
        require_windows_success(
            unsafe {
                InitializeSecurityDescriptor(
                    (&mut descriptor as *mut SECURITY_DESCRIPTOR).cast(),
                    1,
                )
            },
            execution_id,
        )?;
        require_windows_success(
            unsafe {
                SetSecurityDescriptorOwner(
                    (&mut descriptor as *mut SECURITY_DESCRIPTOR).cast(),
                    world.as_psid(),
                    0,
                )
            },
            execution_id,
        )?;
        require_windows_success(
            unsafe {
                SetSecurityDescriptorGroup(
                    (&mut descriptor as *mut SECURITY_DESCRIPTOR).cast(),
                    world.as_psid(),
                    0,
                )
            },
            execution_id,
        )?;
        require_windows_success(
            unsafe {
                SetSecurityDescriptorDacl(
                    (&mut descriptor as *mut SECURITY_DESCRIPTOR).cast(),
                    1,
                    dacl,
                    0,
                )
            },
            execution_id,
        )?;

        let generic_mapping = GENERIC_MAPPING {
            GenericRead: SYNTHETIC_ACCESS,
            GenericWrite: SYNTHETIC_ACCESS,
            GenericExecute: SYNTHETIC_ACCESS,
            GenericAll: SYNTHETIC_ACCESS,
        };
        let mut privilege_set = vec![
            0_usize;
            std::mem::size_of::<PRIVILEGE_SET>()
                .div_ceil(std::mem::size_of::<usize>())
        ];
        let mut privilege_set_length = std::mem::size_of::<PRIVILEGE_SET>() as u32;
        let mut granted_access = 0_u32;
        let mut access_status = 0;
        require_windows_success(
            unsafe {
                AccessCheck(
                    (&mut descriptor as *mut SECURITY_DESCRIPTOR).cast(),
                    impersonation_token.as_raw(),
                    SYNTHETIC_ACCESS,
                    &generic_mapping,
                    privilege_set.as_mut_ptr().cast::<PRIVILEGE_SET>(),
                    &mut privilege_set_length,
                    &mut granted_access,
                    &mut access_status,
                )
            },
            execution_id,
        )?;
        Ok((granted_access, access_status != 0))
    })();
    unsafe {
        LocalFree(dacl.cast());
    }
    result
}

fn require_windows_success(result: i32, execution_id: &ToolExecutionId) -> Result<(), PortError> {
    if result == 0 {
        record_last_error(execution_id);
        Err(platform_error())
    } else {
        Ok(())
    }
}

pub(super) struct LpacBoundary {
    worktrees: Vec<RetainedLpacWorktree>,
}

struct RetainedLpacWorktree {
    task_id: TaskId,
    root_identity: CapabilityRootIdentity,
    canonical_root: PathBuf,
    retained_root: File,
    volume_serial_number: u32,
    file_index: u64,
}

pub(super) struct PreparedLpacBoundary {
    execution_id: ToolExecutionId,
    launch_cwd: PathBuf,
    environment: BTreeMap<OsString, OsString>,
    profile: AppContainerProfile,
    acl_grants: Vec<RetainedAclGrant>,
}

struct AppContainerProfile {
    execution_id: ToolExecutionId,
    moniker: Vec<u16>,
    package_sid: Arc<OwnedAppContainerSid>,
    local_app_data: PathBuf,
    active: bool,
}

struct OwnedAppContainerSid(usize);

struct RetainedAclGrant {
    execution_id: ToolExecutionId,
    handle: File,
    package_sid: Arc<OwnedAppContainerSid>,
    active: bool,
}

impl LpacBoundary {
    pub(super) fn new(
        registrations: Vec<TrustedLpacWorktreeRegistration>,
    ) -> Result<Self, PortError> {
        if registrations.is_empty() {
            return Err(invalid_input());
        }
        let mut identities = BTreeSet::new();
        let mut worktrees = Vec::with_capacity(registrations.len());
        for registration in registrations {
            let key = (
                registration.task_id.as_str().to_owned(),
                registration.root_identity.as_str().to_owned(),
            );
            if !identities.insert(key) {
                return Err(invalid_input());
            }
            worktrees.push(RetainedLpacWorktree::open(registration)?);
        }
        Ok(Self { worktrees })
    }

    pub(super) fn prepare(
        &self,
        request: &AuthorizedProcessRequest,
    ) -> Result<PreparedLpacBoundary, PortError> {
        validate_lpac_request(request)?;
        let ProcessWorkingDirectory::IsolatedWorktree(cwd) = &request.cwd else {
            return Err(permission_denied());
        };
        let task_id = cwd
            .capability
            .worktree_task_id()
            .ok_or_else(permission_denied)?;
        let worktree = self
            .worktrees
            .iter()
            .find(|registered| {
                &registered.task_id == task_id && registered.root_identity == cwd.root_identity
            })
            .ok_or_else(permission_denied)?;
        worktree.reverify()?;
        ensure_empty_worktree(worktree, &request.execution_id)?;
        let executable = open_retained_executable(&request.executable, &request.execution_id)?;

        let profile = AppContainerProfile::create(request.execution_id.clone())?;
        let environment = lpac_environment(request, profile.local_app_data());
        let mut acl_grants = Vec::new();
        let root_handle = worktree.retained_root.try_clone().map_err(|_| denied())?;
        acl_grants.push(RetainedAclGrant::grant(
            request.execution_id.clone(),
            root_handle,
            Arc::clone(&profile.package_sid),
        )?);
        acl_grants.push(RetainedAclGrant::grant(
            request.execution_id.clone(),
            executable,
            Arc::clone(&profile.package_sid),
        )?);

        Ok(PreparedLpacBoundary {
            execution_id: request.execution_id.clone(),
            launch_cwd: worktree.canonical_root.clone(),
            environment,
            profile,
            acl_grants,
        })
    }
}

impl RetainedLpacWorktree {
    fn open(registration: TrustedLpacWorktreeRegistration) -> Result<Self, PortError> {
        reject_reparse_components(&registration.configured_root)?;
        let canonical_root = std::fs::canonicalize(&registration.configured_root)
            .map_err(|_| permission_denied())?;
        let metadata = std::fs::symlink_metadata(&canonical_root).map_err(|_| denied())?;
        if !metadata.is_dir()
            || metadata.file_type().is_symlink()
            || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
        {
            return Err(permission_denied());
        }
        let retained_root = open_acl_handle(&canonical_root, true)?;
        let information = file_information(&retained_root)?;
        Ok(Self {
            task_id: registration.task_id,
            root_identity: registration.root_identity,
            canonical_root,
            retained_root,
            volume_serial_number: information.dwVolumeSerialNumber,
            file_index: file_index(&information),
        })
    }

    fn reverify(&self) -> Result<(), PortError> {
        let information = file_information(&self.retained_root)?;
        let reopened_root = open_acl_handle(&self.canonical_root, true)?;
        let reopened_information = file_information(&reopened_root)?;
        if information.dwVolumeSerialNumber != self.volume_serial_number
            || file_index(&information) != self.file_index
            || information.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY == 0
            || information.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
            || reopened_information.dwVolumeSerialNumber != self.volume_serial_number
            || file_index(&reopened_information) != self.file_index
            || std::fs::canonicalize(&self.canonical_root).ok().as_ref()
                != Some(&self.canonical_root)
        {
            return Err(integrity_failure());
        }
        Ok(())
    }
}

impl PreparedLpacBoundary {
    pub(super) fn launch_cwd(&self) -> &Path {
        &self.launch_cwd
    }

    pub(super) fn environment(&self) -> &BTreeMap<OsString, OsString> {
        &self.environment
    }

    pub(super) fn security_capabilities(&self) -> SECURITY_CAPABILITIES {
        SECURITY_CAPABILITIES {
            AppContainerSid: self.profile.package_sid(),
            Capabilities: ptr::null_mut(),
            CapabilityCount: 0,
            Reserved: 0,
        }
    }

    pub(super) fn verify_child_token(&self, process: HANDLE) -> Result<(), PortError> {
        let token = open_process_token(process, &self.execution_id)?;
        let is_app_container =
            query_token_flag(token.as_raw(), TokenIsAppContainer, &self.execution_id)?;
        let observed_sid =
            query_token_buffer(token.as_raw(), TokenAppContainerSid, &self.execution_id)?;
        let app_container = observed_sid.read::<TOKEN_APPCONTAINER_INFORMATION>()?;
        let sid_matches = !app_container.TokenAppContainer.is_null()
            && unsafe { EqualSid(app_container.TokenAppContainer, self.profile.package_sid()) }
                != 0;
        let capabilities =
            query_token_buffer(token.as_raw(), TokenCapabilities, &self.execution_id)?;
        let capability_count = capabilities.token_group_count()?;
        let user = query_token_buffer(token.as_raw(), TokenUser, &self.execution_id)?;
        let token_user = user.read::<TOKEN_USER>()?;
        if token_user.User.Sid.is_null() {
            return Err(integrity_failure());
        }
        let (aap_granted_access, aap_access_allowed) =
            aap_only_access_check(token.as_raw(), token_user.User.Sid, &self.execution_id)?;

        #[cfg(feature = "test-seams")]
        let observations =
            if let Some(mismatch) = take_token_verification_mismatch(&self.execution_id) {
                match mismatch {
                    LpacTokenVerificationMismatchForTest::AppContainer => (
                        0,
                        sid_matches,
                        capability_count,
                        aap_granted_access,
                        aap_access_allowed,
                    ),
                    LpacTokenVerificationMismatchForTest::LessPrivilegedAppContainer => {
                        (is_app_container, sid_matches, capability_count, 1, true)
                    }
                    LpacTokenVerificationMismatchForTest::PackageSid => (
                        is_app_container,
                        false,
                        capability_count,
                        aap_granted_access,
                        aap_access_allowed,
                    ),
                    LpacTokenVerificationMismatchForTest::Capabilities => (
                        is_app_container,
                        sid_matches,
                        1,
                        aap_granted_access,
                        aap_access_allowed,
                    ),
                }
            } else {
                (
                    is_app_container,
                    sid_matches,
                    capability_count,
                    aap_granted_access,
                    aap_access_allowed,
                )
            };
        #[cfg(not(feature = "test-seams"))]
        let observations = (
            is_app_container,
            sid_matches,
            capability_count,
            aap_granted_access,
            aap_access_allowed,
        );
        let (
            is_app_container,
            sid_matches,
            capability_count,
            aap_granted_access,
            aap_access_allowed,
        ) = observations;
        #[cfg(feature = "test-seams")]
        let bypass_aap_attestation = take_aap_attestation_bypass(&self.execution_id);
        #[cfg(not(feature = "test-seams"))]
        let bypass_aap_attestation = false;

        if is_app_container != 1
            || !sid_matches
            || capability_count != 0
            || (!bypass_aap_attestation && (aap_granted_access != 0 || aap_access_allowed))
        {
            return Err(integrity_failure());
        }
        Ok(())
    }

    pub(super) fn cleanup(&mut self) -> Result<(), PortError> {
        let mut failed = false;
        for grant in self.acl_grants.iter_mut().rev() {
            if grant.revoke().is_err() {
                failed = true;
            }
        }
        if failed {
            return Err(platform_error());
        }
        self.profile.delete()
    }
}

impl Drop for PreparedLpacBoundary {
    fn drop(&mut self) {
        while self.cleanup().is_err() {
            std::thread::sleep(Duration::from_millis(1));
        }
    }
}

impl AppContainerProfile {
    fn create(execution_id: ToolExecutionId) -> Result<Self, PortError> {
        let moniker = unique_profile_moniker(&execution_id)?;
        let mut package_sid = ptr::null_mut();
        let result = unsafe {
            CreateAppContainerProfile(
                moniker.as_ptr(),
                moniker.as_ptr(),
                moniker.as_ptr(),
                ptr::null(),
                0,
                &mut package_sid,
            )
        };
        if result < 0 || package_sid.is_null() {
            record_windows_error(&execution_id, result as u32);
            if result == HRESULT_ALREADY_EXISTS || result as u32 == ERROR_ALREADY_EXISTS {
                return Err(integrity_failure());
            }
            return Err(platform_error());
        }
        record_profile_created(&execution_id);
        let mut profile = Self {
            execution_id,
            moniker,
            package_sid: Arc::new(OwnedAppContainerSid(package_sid as usize)),
            local_app_data: PathBuf::new(),
            active: true,
        };
        profile.local_app_data =
            app_container_folder_path(profile.package_sid(), &profile.execution_id)?;
        Ok(profile)
    }

    fn package_sid(&self) -> PSID {
        self.package_sid.as_psid()
    }

    fn local_app_data(&self) -> &Path {
        &self.local_app_data
    }

    fn delete(&mut self) -> Result<(), PortError> {
        if !self.active {
            return Ok(());
        }
        let result = unsafe { DeleteAppContainerProfile(self.moniker.as_ptr()) };
        if result < 0 {
            record_windows_error(&self.execution_id, result as u32);
            return Err(platform_error());
        }
        self.active = false;
        record_profile_deleted(&self.execution_id);
        Ok(())
    }
}

impl Drop for AppContainerProfile {
    fn drop(&mut self) {
        while self.active && self.delete().is_err() {
            std::thread::sleep(Duration::from_millis(1));
        }
    }
}

impl OwnedAppContainerSid {
    fn as_psid(&self) -> PSID {
        self.0 as PSID
    }
}

impl Drop for OwnedAppContainerSid {
    fn drop(&mut self) {
        if self.0 != 0 {
            unsafe {
                FreeSid(self.as_psid());
            }
            self.0 = 0;
        }
    }
}

impl RetainedAclGrant {
    fn grant(
        execution_id: ToolExecutionId,
        handle: File,
        package_sid: Arc<OwnedAppContainerSid>,
    ) -> Result<Self, PortError> {
        update_acl(
            handle.as_raw_handle() as HANDLE,
            package_sid.as_psid(),
            GRANT_ACCESS,
            FILE_GENERIC_READ | FILE_GENERIC_EXECUTE,
            &execution_id,
        )?;
        record_acl_granted(&execution_id);
        Ok(Self {
            execution_id,
            handle,
            package_sid,
            active: true,
        })
    }

    fn revoke(&mut self) -> Result<(), PortError> {
        if !self.active {
            return Ok(());
        }
        update_acl(
            self.handle.as_raw_handle() as HANDLE,
            self.package_sid.as_psid(),
            REVOKE_ACCESS,
            0,
            &self.execution_id,
        )?;
        self.active = false;
        record_acl_revoked(&self.execution_id);
        Ok(())
    }
}

impl Drop for RetainedAclGrant {
    fn drop(&mut self) {
        while self.active && self.revoke().is_err() {
            std::thread::sleep(Duration::from_millis(1));
        }
    }
}

fn app_container_folder_path(
    package_sid: PSID,
    execution_id: &ToolExecutionId,
) -> Result<PathBuf, PortError> {
    let mut sid_string = ptr::null_mut();
    // SAFETY: package_sid is owned by the live profile and sid_string points to
    // writable storage for the LocalAlloc-owned result.
    if unsafe { ConvertSidToStringSidW(package_sid, &mut sid_string) } == 0 {
        record_last_error(execution_id);
        return Err(platform_error());
    }
    let sid_string = LocalWideString(sid_string);
    let mut folder = ptr::null_mut();
    // SAFETY: sid_string is a live NUL-terminated SID string and folder points to
    // writable storage for the CoTaskMem-owned result.
    let result = unsafe { GetAppContainerFolderPath(sid_string.0, &mut folder) };
    if result < 0 || folder.is_null() {
        record_windows_error(execution_id, result as u32);
        return Err(platform_error());
    }
    let folder = CoTaskWideString(folder);
    wide_os_string(folder.0).map(PathBuf::from)
}

fn wide_os_string(value: *const u16) -> Result<OsString, PortError> {
    if value.is_null() {
        return Err(integrity_failure());
    }
    let mut length = 0_usize;
    while length < 32_767 {
        // SAFETY: Windows documents the returned string as NUL-terminated; the
        // allocation remains owned by the caller while this helper runs.
        if unsafe { *value.add(length) } == 0 {
            // SAFETY: length was determined within the live NUL-terminated buffer.
            let wide = unsafe { std::slice::from_raw_parts(value, length) };
            return Ok(OsString::from_wide(wide));
        }
        length += 1;
    }
    Err(integrity_failure())
}

struct LocalWideString(*mut u16);

impl Drop for LocalWideString {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: ConvertSidToStringSidW allocated this pointer with LocalAlloc.
            unsafe {
                LocalFree(self.0.cast());
            }
        }
    }
}

struct CoTaskWideString(*mut u16);

impl Drop for CoTaskWideString {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: GetAppContainerFolderPath allocated this pointer with CoTaskMemAlloc.
            unsafe {
                CoTaskMemFree(self.0.cast());
            }
        }
    }
}

fn lpac_environment(
    request: &AuthorizedProcessRequest,
    local_app_data: &Path,
) -> BTreeMap<OsString, OsString> {
    let mut environment = request
        .environment
        .values
        .iter()
        .map(|(name, value)| (OsString::from(name), OsString::from(value)))
        .collect::<BTreeMap<_, _>>();
    let temp = local_app_data.join("Temp").into_os_string();
    environment.insert(
        OsString::from("LOCALAPPDATA"),
        local_app_data.as_os_str().to_os_string(),
    );
    environment.insert(OsString::from("TEMP"), temp.clone());
    environment.insert(OsString::from("TMP"), temp);
    environment
}

fn validate_lpac_request(request: &AuthorizedProcessRequest) -> Result<(), PortError> {
    if request.environment.values.keys().any(|name| {
        ["LOCALAPPDATA", "TEMP", "TMP"]
            .iter()
            .any(|reserved| name.eq_ignore_ascii_case(reserved))
    }) {
        return Err(invalid_input());
    }
    if request.trust_tier != ProcessTrustTier::IsolatedWorker
        || !request.expected_writes.is_empty()
        || request.network.profile != NetworkProfile::Denied
    {
        return Err(permission_denied());
    }
    let ProcessWorkingDirectory::IsolatedWorktree(cwd) = &request.cwd else {
        return Err(permission_denied());
    };
    let CapabilityRef::Worktree(worktree) = &cwd.capability else {
        return Err(permission_denied());
    };
    if worktree.path() != "."
        || !matches!(
            cwd.target,
            local_agent_terminal_application::ResolvedCapabilityTarget::Root
        )
        || worktree.task_id() != request.executor_claim.task_id()
    {
        return Err(permission_denied());
    }
    Ok(())
}

fn ensure_empty_worktree(
    worktree: &RetainedLpacWorktree,
    execution_id: &ToolExecutionId,
) -> Result<(), PortError> {
    let mut entries = std::fs::read_dir(&worktree.canonical_root).map_err(|_| denied())?;
    match entries.next() {
        None => {
            worktree.reverify()?;
            ensure_directory_has_no_named_streams(&worktree.retained_root, execution_id)
        }
        Some(Ok(_)) => Err(permission_denied()),
        Some(Err(_)) => Err(permission_denied()),
    }
}

fn open_retained_executable(
    executable: &ResolvedExecutable,
    execution_id: &ToolExecutionId,
) -> Result<File, PortError> {
    let metadata = std::fs::symlink_metadata(&executable.canonical_path).map_err(|_| denied())?;
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
    {
        return Err(permission_denied());
    }
    let handle = open_acl_handle(&executable.canonical_path, false)?;
    let information = file_information(&handle)?;
    let identity = format!(
        "windows:{:016x}:{:016x}",
        information.dwVolumeSerialNumber,
        file_index(&information),
    );
    if identity != executable.file_identity.as_str()
        || information.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY != 0
        || information.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
        || information.nNumberOfLinks > 1
    {
        return Err(integrity_failure());
    }
    ensure_file_has_only_unnamed_data_stream(&handle, execution_id)?;
    Ok(handle)
}

fn ensure_directory_has_no_named_streams(
    file: &File,
    execution_id: &ToolExecutionId,
) -> Result<(), PortError> {
    inspect_stream_information(file, execution_id, true)
}

fn ensure_file_has_only_unnamed_data_stream(
    file: &File,
    execution_id: &ToolExecutionId,
) -> Result<(), PortError> {
    inspect_stream_information(file, execution_id, false)
}

fn inspect_stream_information(
    file: &File,
    execution_id: &ToolExecutionId,
    empty_stream_list_allowed: bool,
) -> Result<(), PortError> {
    let buffer_element_count = STREAM_INFORMATION_BUFFER_BYTES.div_ceil(std::mem::size_of::<u64>());
    let mut aligned_buffer = vec![0_u64; buffer_element_count];
    // SAFETY: file is a retained live handle and aligned_buffer is writable,
    // 8-byte aligned, and covers the fixed byte count passed to the API.
    let queried = unsafe {
        GetFileInformationByHandleEx(
            file.as_raw_handle() as HANDLE,
            FileStreamInfo,
            aligned_buffer.as_mut_ptr().cast(),
            STREAM_INFORMATION_BUFFER_BYTES as u32,
        )
    };
    if queried == 0 {
        // SAFETY: this reads the calling thread's last error immediately after
        // the failed file-information query.
        let error = unsafe { GetLastError() };
        if empty_stream_list_allowed && error == ERROR_HANDLE_EOF {
            return Ok(());
        }
        record_windows_error(execution_id, error);
        return Err(platform_error());
    }
    // SAFETY: aligned_buffer remains live and its allocation covers the fixed byte count.
    let bytes = unsafe {
        std::slice::from_raw_parts(
            aligned_buffer.as_ptr().cast::<u8>(),
            STREAM_INFORMATION_BUFFER_BYTES,
        )
    };
    let stream_name_offset = std::mem::offset_of!(FILE_STREAM_INFO, StreamName);
    let unnamed_data_stream = "::$DATA".encode_utf16().collect::<Vec<_>>();
    let mut entry_offset = 0_usize;
    let mut entry_count = 0_usize;
    loop {
        let next_entry_offset = read_u32(bytes, entry_offset).ok_or_else(integrity_failure)?;
        let stream_name_length = read_u32(bytes, entry_offset + std::mem::size_of::<u32>())
            .ok_or_else(integrity_failure)? as usize;
        if stream_name_length == 0 || !stream_name_length.is_multiple_of(std::mem::size_of::<u16>())
        {
            return Err(integrity_failure());
        }
        let stream_name_start = entry_offset
            .checked_add(stream_name_offset)
            .ok_or_else(integrity_failure)?;
        let stream_name_end = stream_name_start
            .checked_add(stream_name_length)
            .ok_or_else(integrity_failure)?;
        let stream_name_bytes = bytes
            .get(stream_name_start..stream_name_end)
            .ok_or_else(integrity_failure)?;
        let stream_name = stream_name_bytes
            .chunks_exact(std::mem::size_of::<u16>())
            .map(|unit| u16::from_ne_bytes([unit[0], unit[1]]))
            .collect::<Vec<_>>();
        if stream_name != unnamed_data_stream {
            return Err(permission_denied());
        }
        entry_count += 1;
        if next_entry_offset == 0 {
            return if entry_count == 1 {
                Ok(())
            } else {
                Err(integrity_failure())
            };
        }
        let next_entry_offset = next_entry_offset as usize;
        if next_entry_offset < stream_name_offset + stream_name_length
            || !next_entry_offset.is_multiple_of(std::mem::align_of::<u64>())
        {
            return Err(integrity_failure());
        }
        entry_offset = entry_offset
            .checked_add(next_entry_offset)
            .filter(|offset| *offset < bytes.len())
            .ok_or_else(integrity_failure)?;
    }
}

fn read_u32(bytes: &[u8], offset: usize) -> Option<u32> {
    let end = offset.checked_add(std::mem::size_of::<u32>())?;
    let value = bytes.get(offset..end)?;
    Some(u32::from_ne_bytes(value.try_into().ok()?))
}

fn open_acl_handle(path: &Path, directory: bool) -> Result<File, PortError> {
    let mut flags = FILE_FLAG_OPEN_REPARSE_POINT;
    if directory {
        flags |= FILE_FLAG_BACKUP_SEMANTICS;
    }
    OpenOptions::new()
        .access_mode(FILE_READ_ATTRIBUTES | READ_CONTROL | WRITE_DAC)
        .share_mode(FILE_SHARE_READ)
        .custom_flags(flags)
        .open(path)
        .map_err(|_| denied())
}

fn file_information(file: &File) -> Result<BY_HANDLE_FILE_INFORMATION, PortError> {
    let mut information = BY_HANDLE_FILE_INFORMATION::default();
    let result =
        unsafe { GetFileInformationByHandle(file.as_raw_handle() as HANDLE, &mut information) };
    if result == 0 {
        Err(platform_error())
    } else {
        Ok(information)
    }
}

fn file_index(information: &BY_HANDLE_FILE_INFORMATION) -> u64 {
    (u64::from(information.nFileIndexHigh) << 32) | u64::from(information.nFileIndexLow)
}

fn reject_reparse_components(path: &Path) -> Result<(), PortError> {
    let mut current = PathBuf::new();
    for component in path.components() {
        current.push(component.as_os_str());
        if matches!(component, Component::Prefix(_)) {
            continue;
        }
        let metadata = std::fs::symlink_metadata(&current).map_err(|_| permission_denied())?;
        if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(permission_denied());
        }
    }
    Ok(())
}

fn update_acl(
    handle: HANDLE,
    package_sid: PSID,
    access_mode: i32,
    access_permissions: u32,
    execution_id: &ToolExecutionId,
) -> Result<(), PortError> {
    let mut dacl: *mut ACL = ptr::null_mut();
    let mut security_descriptor: PSECURITY_DESCRIPTOR = ptr::null_mut();
    let security_result = unsafe {
        GetSecurityInfo(
            handle,
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            ptr::null_mut(),
            ptr::null_mut(),
            &mut dacl,
            ptr::null_mut(),
            &mut security_descriptor,
        )
    };
    if security_result != ERROR_SUCCESS || dacl.is_null() || security_descriptor.is_null() {
        record_windows_error(execution_id, security_result);
        if !security_descriptor.is_null() {
            unsafe {
                LocalFree(security_descriptor);
            }
        }
        return Err(platform_error());
    }

    let entry = EXPLICIT_ACCESS_W {
        grfAccessPermissions: access_permissions,
        grfAccessMode: access_mode,
        grfInheritance: NO_INHERITANCE,
        Trustee: TRUSTEE_W {
            pMultipleTrustee: ptr::null_mut(),
            MultipleTrusteeOperation: 0,
            TrusteeForm: TRUSTEE_IS_SID,
            TrusteeType: TRUSTEE_IS_USER,
            ptstrName: package_sid.cast::<u16>(),
        },
    };
    let mut updated_dacl: *mut ACL = ptr::null_mut();
    let acl_result = unsafe { SetEntriesInAclW(1, &entry, dacl, &mut updated_dacl) };
    unsafe {
        LocalFree(security_descriptor);
    }
    if acl_result != ERROR_SUCCESS || updated_dacl.is_null() {
        record_windows_error(execution_id, acl_result);
        if !updated_dacl.is_null() {
            unsafe {
                LocalFree(updated_dacl.cast());
            }
        }
        return Err(platform_error());
    }
    let set_result = unsafe {
        SetSecurityInfo(
            handle,
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            ptr::null_mut(),
            ptr::null_mut(),
            updated_dacl,
            ptr::null_mut(),
        )
    };
    unsafe {
        LocalFree(updated_dacl.cast());
    }
    if set_result != ERROR_SUCCESS {
        record_windows_error(execution_id, set_result);
        return Err(platform_error());
    }
    Ok(())
}

fn unique_profile_moniker(execution_id: &ToolExecutionId) -> Result<Vec<u16>, PortError> {
    let mut random = [0_u8; 16];
    let status = unsafe {
        BCryptGenRandom(
            ptr::null_mut(),
            random.as_mut_ptr(),
            random.len() as u32,
            BCRYPT_USE_SYSTEM_PREFERRED_RNG,
        )
    };
    if status != 0 {
        record_windows_error(execution_id, status as u32);
        return Err(platform_error());
    }
    let suffix = random
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let moniker = format!("LatLpac.{suffix}");
    let mut wide = moniker.encode_utf16().collect::<Vec<_>>();
    wide.push(0);
    Ok(wide)
}

fn open_process_token(
    process: HANDLE,
    execution_id: &ToolExecutionId,
) -> Result<OwnedHandle, PortError> {
    let mut token = ptr::null_mut();
    let result = unsafe { OpenProcessToken(process, TOKEN_QUERY | TOKEN_DUPLICATE, &mut token) };
    if result == 0 {
        record_last_error(execution_id);
        return Err(platform_error());
    }
    OwnedHandle::new(token)
}

fn query_token_flag(
    token: HANDLE,
    information_class: i32,
    execution_id: &ToolExecutionId,
) -> Result<u32, PortError> {
    let mut flag = 0_u32;
    let mut returned = 0_u32;
    let result = unsafe {
        GetTokenInformation(
            token,
            information_class,
            (&mut flag as *mut u32).cast::<c_void>(),
            std::mem::size_of::<u32>() as u32,
            &mut returned,
        )
    };
    if result == 0 || returned != std::mem::size_of::<u32>() as u32 {
        record_last_error(execution_id);
        return Err(platform_error());
    }
    Ok(flag)
}

fn query_token_buffer(
    token: HANDLE,
    information_class: i32,
    execution_id: &ToolExecutionId,
) -> Result<TokenInformationBuffer, PortError> {
    let mut bytes = 0_u32;
    let initial_result =
        unsafe { GetTokenInformation(token, information_class, ptr::null_mut(), 0, &mut bytes) };
    let initial_error = unsafe { GetLastError() };
    if initial_result != 0 || bytes == 0 || initial_error != ERROR_INSUFFICIENT_BUFFER {
        record_windows_error(execution_id, initial_error);
        return Err(platform_error());
    }
    let capacity = bytes;
    let words = (capacity as usize).div_ceil(std::mem::size_of::<usize>());
    let mut buffer = vec![0_usize; words];
    let mut returned = capacity;
    let result = unsafe {
        GetTokenInformation(
            token,
            information_class,
            buffer.as_mut_ptr().cast::<c_void>(),
            capacity,
            &mut returned,
        )
    };
    if result == 0 || returned == 0 || returned > capacity {
        record_last_error(execution_id);
        return Err(platform_error());
    }
    Ok(TokenInformationBuffer {
        words: buffer,
        returned: returned as usize,
    })
}

struct TokenInformationBuffer {
    words: Vec<usize>,
    returned: usize,
}

impl TokenInformationBuffer {
    fn read<T: Copy>(&self) -> Result<T, PortError> {
        if self.returned < std::mem::size_of::<T>() {
            return Err(integrity_failure());
        }
        Ok(unsafe { self.words.as_ptr().cast::<T>().read() })
    }

    fn token_group_count(&self) -> Result<u32, PortError> {
        let group_count = self.read::<u32>()?;
        if group_count == 0 {
            return Ok(0);
        }
        let groups_offset = std::mem::offset_of!(TOKEN_GROUPS, Groups);
        let groups_bytes = usize::try_from(group_count)
            .ok()
            .and_then(|count| {
                count.checked_mul(std::mem::size_of::<
                    windows_sys::Win32::Security::SID_AND_ATTRIBUTES,
                >())
            })
            .and_then(|bytes| groups_offset.checked_add(bytes))
            .ok_or_else(integrity_failure)?;
        if self.returned < groups_bytes {
            return Err(integrity_failure());
        }
        Ok(group_count)
    }
}

#[repr(C)]
struct FixedAppPackageSid {
    revision: u8,
    sub_authority_count: u8,
    identifier_authority: [u8; 6],
    app_package_authority: u32,
    package_kind: u32,
}

#[repr(C)]
struct FixedWorldSid {
    revision: u8,
    sub_authority_count: u8,
    identifier_authority: [u8; 6],
    sub_authority: u32,
}

impl FixedWorldSid {
    const fn new() -> Self {
        Self {
            revision: 1,
            sub_authority_count: 1,
            identifier_authority: [0, 0, 0, 0, 0, 1],
            sub_authority: 0,
        }
    }

    fn as_psid(&self) -> PSID {
        (self as *const Self).cast_mut().cast::<c_void>()
    }
}

impl FixedAppPackageSid {
    const fn new(package_kind: u32) -> Self {
        Self {
            revision: 1,
            sub_authority_count: 2,
            identifier_authority: [0, 0, 0, 0, 0, 15],
            app_package_authority: 2,
            package_kind,
        }
    }

    fn as_psid(&self) -> PSID {
        (self as *const Self).cast_mut().cast::<c_void>()
    }
}

fn record_last_error(execution_id: &ToolExecutionId) {
    record_windows_error(execution_id, unsafe { GetLastError() });
}

pub(super) fn record_current_windows_error(execution_id: &ToolExecutionId) {
    record_last_error(execution_id);
}

#[cfg(feature = "test-seams")]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct LpacLifecycleCountsForTest {
    pub profiles_created: usize,
    pub profiles_deleted: usize,
    pub acl_grants: usize,
    pub acl_revokes: usize,
    pub suspended_children_created: usize,
    pub resumes_succeeded: usize,
    pub last_windows_error: Option<u32>,
}

#[cfg(feature = "test-seams")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LpacTokenVerificationMismatchForTest {
    AppContainer,
    LessPrivilegedAppContainer,
    PackageSid,
    Capabilities,
}

#[cfg(feature = "test-seams")]
static LPAC_LIFECYCLE: Mutex<BTreeMap<String, LpacLifecycleCountsForTest>> =
    Mutex::new(BTreeMap::new());

#[cfg(feature = "test-seams")]
static TOKEN_VERIFICATION_MISMATCH: Mutex<Option<(String, LpacTokenVerificationMismatchForTest)>> =
    Mutex::new(None);

#[cfg(feature = "test-seams")]
static BYPASS_AAP_ATTESTATION: Mutex<BTreeSet<String>> = Mutex::new(BTreeSet::new());

#[cfg(feature = "test-seams")]
pub fn lpac_lifecycle_counts_for_test(
    execution_id: &ToolExecutionId,
) -> LpacLifecycleCountsForTest {
    LPAC_LIFECYCLE
        .lock()
        .ok()
        .and_then(|counts| counts.get(execution_id.as_str()).copied())
        .unwrap_or_default()
}

#[cfg(feature = "test-seams")]
pub fn fail_lpac_token_verification_for_test(
    execution_id: ToolExecutionId,
    mismatch: LpacTokenVerificationMismatchForTest,
) {
    if let Ok(mut configured) = TOKEN_VERIFICATION_MISMATCH.lock() {
        *configured = Some((execution_id.as_str().to_owned(), mismatch));
    }
}

#[cfg(feature = "test-seams")]
pub fn bypass_aap_attestation_for_test(execution_id: ToolExecutionId) {
    if let Ok(mut configured) = BYPASS_AAP_ATTESTATION.lock() {
        configured.insert(execution_id.as_str().to_owned());
    }
}

#[cfg(feature = "test-seams")]
fn take_aap_attestation_bypass(execution_id: &ToolExecutionId) -> bool {
    BYPASS_AAP_ATTESTATION
        .lock()
        .is_ok_and(|mut configured| configured.remove(execution_id.as_str()))
}

#[cfg(feature = "test-seams")]
fn take_token_verification_mismatch(
    execution_id: &ToolExecutionId,
) -> Option<LpacTokenVerificationMismatchForTest> {
    TOKEN_VERIFICATION_MISMATCH
        .lock()
        .ok()
        .and_then(|mut mismatch| {
            if mismatch
                .as_ref()
                .is_some_and(|(configured, _)| configured == execution_id.as_str())
            {
                mismatch.take().map(|(_, mismatch)| mismatch)
            } else {
                None
            }
        })
}

#[cfg(feature = "test-seams")]
fn update_lifecycle(
    execution_id: &ToolExecutionId,
    update: impl FnOnce(&mut LpacLifecycleCountsForTest),
) {
    if let Ok(mut counts) = LPAC_LIFECYCLE.lock() {
        update(counts.entry(execution_id.as_str().to_owned()).or_default());
    }
}

#[cfg(not(feature = "test-seams"))]
fn record_profile_created(_: &ToolExecutionId) {}
#[cfg(feature = "test-seams")]
fn record_profile_created(execution_id: &ToolExecutionId) {
    update_lifecycle(execution_id, |counts| counts.profiles_created += 1);
}

#[cfg(not(feature = "test-seams"))]
fn record_profile_deleted(_: &ToolExecutionId) {}
#[cfg(feature = "test-seams")]
fn record_profile_deleted(execution_id: &ToolExecutionId) {
    update_lifecycle(execution_id, |counts| counts.profiles_deleted += 1);
}

#[cfg(not(feature = "test-seams"))]
fn record_acl_granted(_: &ToolExecutionId) {}
#[cfg(feature = "test-seams")]
fn record_acl_granted(execution_id: &ToolExecutionId) {
    update_lifecycle(execution_id, |counts| counts.acl_grants += 1);
}

#[cfg(not(feature = "test-seams"))]
fn record_acl_revoked(_: &ToolExecutionId) {}
#[cfg(feature = "test-seams")]
fn record_acl_revoked(execution_id: &ToolExecutionId) {
    update_lifecycle(execution_id, |counts| counts.acl_revokes += 1);
}

#[cfg(not(feature = "test-seams"))]
fn record_windows_error(_: &ToolExecutionId, _: u32) {}
#[cfg(feature = "test-seams")]
fn record_windows_error(execution_id: &ToolExecutionId, error: u32) {
    update_lifecycle(execution_id, |counts| {
        counts.last_windows_error = Some(error)
    });
}

pub(super) fn record_suspended_child_created(execution_id: &ToolExecutionId) {
    #[cfg(feature = "test-seams")]
    update_lifecycle(execution_id, |counts| {
        counts.suspended_children_created += 1
    });
    #[cfg(not(feature = "test-seams"))]
    let _ = execution_id;
}

pub(super) fn record_resume_succeeded(execution_id: &ToolExecutionId) {
    #[cfg(feature = "test-seams")]
    update_lifecycle(execution_id, |counts| counts.resumes_succeeded += 1);
    #[cfg(not(feature = "test-seams"))]
    let _ = execution_id;
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

fn denied() -> PortError {
    permission_denied()
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
