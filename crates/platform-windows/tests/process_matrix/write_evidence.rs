
#[derive(Debug, Clone, Copy)]
#[cfg(feature = "test-seams")]
enum WriteEvidenceMutation {
    Missing,
    Extra,
    Duplicate,
    AmbiguousApproval,
    Capability,
    Root,
    Path,
}

#[cfg(feature = "test-seams")]
impl TestOnlyBoundary {
    fn valid(cwd: PathBuf) -> Self {
        Self {
            cwd,
            fail_before_resume: false,
            identity_receipt: "test-only-identity".to_owned(),
            acl_receipt: "test-only-acl".to_owned(),
            claims_mismatch: None,
            prepare_calls: Arc::new(AtomicUsize::new(0)),
            prepare_block: None,
            verification_block: None,
            cleanup_count: Arc::new(AtomicUsize::new(0)),
            allow_expected_writes: false,
            observed_writes: Vec::new(),
        }
    }
}

#[cfg(feature = "test-seams")]
impl IsolatedWorkerBoundaryAdapter for TestOnlyBoundary {
    fn prepare(
        &self,
        request: &AuthorizedProcessRequest,
    ) -> Result<PreparedIsolatedWorkerBoundary, local_agent_terminal_application::PortError> {
        self.prepare_calls.fetch_add(1, Ordering::AcqRel);
        if let Some(block) = &self.prepare_block {
            block.wait_once();
        }
        if !request.expected_writes.is_empty() && !self.allow_expected_writes {
            return Err(local_agent_terminal_application::PortError::failure(
                local_agent_terminal_application::SafeErrorClassification::PermissionDenied,
                local_agent_terminal_application::Retryability::NonRetryable,
            ));
        }
        let mut claims = IsolatedWorkerBoundaryClaims::from_request(request);
        if let Some(mismatch) = self.claims_mismatch {
            mutate_claims(&mut claims, mismatch);
        }
        PreparedIsolatedWorkerBoundary::new(
            &self.cwd,
            &self.identity_receipt,
            &self.acl_receipt,
            (!request.expected_writes.is_empty()).then(|| "test-only-write-scope".to_owned()),
            claims,
        )
        .map(|prepared| prepared.with_cleanup_counter_for_test(self.cleanup_count.clone()))
    }

    fn verify_before_resume(
        &self,
        _request: &AuthorizedProcessRequest,
        _prepared: &PreparedIsolatedWorkerBoundary,
    ) -> Result<(), local_agent_terminal_application::PortError> {
        if let Some(block) = &self.verification_block {
            block.wait_once();
        }
        if self.fail_before_resume {
            Err(local_agent_terminal_application::PortError::failure(
                local_agent_terminal_application::SafeErrorClassification::PermissionDenied,
                local_agent_terminal_application::Retryability::NonRetryable,
            ))
        } else {
            Ok(())
        }
    }

    fn observed_writes(
        &self,
        request: &AuthorizedProcessRequest,
        _prepared: &PreparedIsolatedWorkerBoundary,
    ) -> Result<Vec<ObservedProcessWrite>, local_agent_terminal_application::PortError> {
        if request.expected_writes.is_empty() {
            Ok(Vec::new())
        } else if self.allow_expected_writes {
            Ok(self.observed_writes.clone())
        } else {
            Err(local_agent_terminal_application::PortError::failure(
                local_agent_terminal_application::SafeErrorClassification::PermissionDenied,
                local_agent_terminal_application::Retryability::NonRetryable,
            ))
        }
    }
}

#[cfg(feature = "test-seams")]
fn mutate_claims(claims: &mut IsolatedWorkerBoundaryClaims, mismatch: BoundaryMismatch) {
    match mismatch {
        BoundaryMismatch::Identity | BoundaryMismatch::Acl => {}
        BoundaryMismatch::Task => {
            claims.executor_claim = LeaseClaim::new(
                TaskId::new("task-2").unwrap(),
                claims.executor_claim.holder_run_id().clone(),
                claims.executor_claim.token(),
            );
        }
        BoundaryMismatch::ExecutorFence => {
            claims.executor_fence = ProcessFenceAuthority::new(
                Arc::new(ReplaceableLeaseStore::new(7)),
                Arc::new(WorkspaceWriteCoordinator::new()),
            )
            .binding();
        }
        BoundaryMismatch::Tier => claims.trust_tier = ProcessTrustTier::BrokeredProcess,
        BoundaryMismatch::CwdRootIdentity => {
            let ProcessWorkingDirectory::IsolatedWorktree(resolved) = &mut claims.cwd else {
                unreachable!()
            };
            resolved.root_identity = CapabilityRootIdentity::new("wrong-worktree").unwrap();
        }
        BoundaryMismatch::NetworkEnforcement => {
            claims.network.receipt = NetworkEnforcementReceipt::new(
                "wrong-network",
                claims.network.profile_digest.clone(),
            )
            .unwrap();
        }
        BoundaryMismatch::NetworkDigest => claims.network.profile_digest = digest(b"wrong-network"),
        BoundaryMismatch::ExecutableIdentity => {
            claims.executable.file_identity =
                ExecutableFileIdentity::new("wrong-executable").unwrap()
        }
        BoundaryMismatch::ExecutableDigest => {
            claims.executable.sha256 = digest(b"wrong-executable")
        }
        BoundaryMismatch::EnvironmentProfile => {
            claims.environment.name = "wrong-environment".to_owned()
        }
        BoundaryMismatch::EnvironmentValues => {
            claims
                .environment
                .values
                .insert("EXTRA".to_owned(), "1".to_owned());
        }
        BoundaryMismatch::Limits => claims.limits.memory_limit_bytes += 1,
        BoundaryMismatch::ExpectedWrites => claims
            .expected_writes
            .push(authorized_write("unexpected.txt", "test-worktree")),
        BoundaryMismatch::Argv => claims.argv.push("extra".to_owned()),
        BoundaryMismatch::Timeout => claims.timeout_ms += 1,
    }
}

fn registered_lpac_launcher(root: &std::path::Path) -> WindowsProcessLauncher {
    WindowsProcessLauncher::with_lpac_boundary(vec![TrustedLpacWorktreeRegistration::new(
        TaskId::new("task-1").unwrap(),
        CapabilityRootIdentity::new("test-worktree").unwrap(),
        root,
    )
    .unwrap()])
    .unwrap()
}

fn containment_probe_executable() -> PathBuf {
    static EXECUTABLE: OnceLock<PathBuf> = OnceLock::new();
    EXECUTABLE
        .get_or_init(|| {
            let repository_root =
                fs::canonicalize(Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")).unwrap();
            let fixture = repository_root.join("tests/fixtures/m2-containment-probe");
            let target = repository_root.join("target/m2-containment-probe");
            let status = Command::new(env!("CARGO"))
                .args(["build", "--manifest-path"])
                .arg(fixture.join("Cargo.toml"))
                .arg("--target-dir")
                .arg(&target)
                .args(["--locked", "--quiet"])
                .status()
                .unwrap();
            assert!(status.success());
            let built = target.join("debug/m2-containment-probe.exe");
            let standalone = target.join("standalone/m2-containment-probe.exe");
            fs::create_dir_all(standalone.parent().unwrap()).unwrap();
            fs::copy(built, &standalone).unwrap();
            standalone
        })
        .clone()
}

#[cfg(feature = "test-seams")]
fn assert_real_lpac_lifecycle(execution_id: &ToolExecutionId) {
    assert_eq!(
        lpac_lifecycle_counts_for_test(execution_id),
        LpacLifecycleCountsForTest {
            profiles_created: 1,
            profiles_deleted: 1,
            acl_grants: 2,
            acl_revokes: 2,
            suspended_children_created: 1,
            resumes_succeeded: 1,
            last_windows_error: None,
        }
    );
}

#[cfg(not(feature = "test-seams"))]
fn assert_real_lpac_lifecycle(_: &ToolExecutionId) {}

struct DeniedCanary {
    read: PathBuf,
    write: PathBuf,
    read_contents: Vec<u8>,
    write_contents: Vec<u8>,
}

const REGISTRY_PARENT_VALUE: &str = "parent-value";
const REGISTRY_CHILD_MARKER: &str = "child-marker";
const REGISTRY_CONTENTS: &[u8] = b"task7 inert registry fixture";
static NEXT_REGISTRY_FIXTURE: AtomicU64 = AtomicU64::new(1);
const CREDENTIAL_BLOB: &[u8] = b"task7 inert credential blob";
static NEXT_PIPE_FIXTURE: AtomicU64 = AtomicU64::new(1);

struct RegistryFixture {
    subkey: String,
    key: Option<OwnedRegistryKey>,
    active: bool,
}

impl RegistryFixture {
    fn new() -> Self {
        let parent = open_registry_key("Software", KEY_READ | KEY_WRITE).unwrap();
        let child_name = format!(
            "LocalAgentTerminal-Task7-{}-{}",
            std::process::id(),
            NEXT_REGISTRY_FIXTURE.fetch_add(1, Ordering::Relaxed)
        );
        let (key, disposition) =
            create_registry_key(parent.0, &child_name, KEY_READ | KEY_WRITE).unwrap();
        let mut fixture = Self {
            subkey: format!(r"Software\{child_name}"),
            key: Some(key),
            active: disposition == REG_CREATED_NEW_KEY,
        };
        assert_eq!(disposition, REG_CREATED_NEW_KEY);
        let key = fixture.key.as_ref().unwrap().0;
        set_registry_binary(key, REGISTRY_PARENT_VALUE, REGISTRY_CONTENTS).unwrap();
        assert_eq!(
            read_registry_binary(key, REGISTRY_PARENT_VALUE).unwrap(),
            REGISTRY_CONTENTS
        );
        set_registry_binary(key, REGISTRY_PARENT_VALUE, b"parent write control").unwrap();
        assert_eq!(
            read_registry_binary(key, REGISTRY_PARENT_VALUE).unwrap(),
            b"parent write control"
        );
        set_registry_binary(key, REGISTRY_PARENT_VALUE, REGISTRY_CONTENTS).unwrap();
        assert_eq!(
            read_registry_binary(key, REGISTRY_CHILD_MARKER),
            Err(windows_sys::Win32::Foundation::ERROR_FILE_NOT_FOUND)
        );
        drop(fixture.key.take());
        fixture
    }

    fn assert_unchanged(&self) {
        let key = open_registry_key(&self.subkey, KEY_READ).unwrap();
        assert_eq!(
            read_registry_binary(key.0, REGISTRY_PARENT_VALUE).unwrap(),
            REGISTRY_CONTENTS
        );
        assert_eq!(
            read_registry_binary(key.0, REGISTRY_CHILD_MARKER),
            Err(windows_sys::Win32::Foundation::ERROR_FILE_NOT_FOUND)
        );
    }

    fn cleanup(mut self) {
        self.remove();
        assert!(matches!(
            open_registry_key(&self.subkey, KEY_READ),
            Err(ERROR_FILE_NOT_FOUND)
        ));
    }

    fn remove(&mut self) {
        if self.active {
            drop(self.key.take());
            let subkey = wide_nul(self.subkey.as_ref());
            // SAFETY: subkey is NUL-terminated and names only this test-owned tree.
            assert_eq!(
                unsafe { RegDeleteTreeW(HKEY_CURRENT_USER, subkey.as_ptr()) },
                ERROR_SUCCESS
            );
            self.active = false;
        }
    }
}

impl Drop for RegistryFixture {
    fn drop(&mut self) {
        if self.active {
            drop(self.key.take());
            let subkey = wide_nul(self.subkey.as_ref());
            // SAFETY: subkey is NUL-terminated and names only this test-owned tree.
            unsafe {
                RegDeleteTreeW(HKEY_CURRENT_USER, subkey.as_ptr());
            }
        }
    }
}

struct CredentialFixture {
    parent_target: String,
    child_target: String,
    filter: String,
    parent_owned: bool,
    child_owned: bool,
    child_target_was_absent: bool,
}

impl CredentialFixture {
    fn new() -> Self {
        let nonce = credential_nonce();
        Self::try_new_with_nonce(&nonce).unwrap()
    }

    fn try_new_with_nonce(nonce: &str) -> Result<Self, u32> {
        let prefix = format!("LocalAgentTerminal/Task7/{nonce}/");
        let mut fixture = Self {
            parent_target: format!("{prefix}parent"),
            child_target: format!("{prefix}child"),
            filter: format!("{prefix}*"),
            parent_owned: false,
            child_owned: false,
            child_target_was_absent: false,
        };
        require_absent_credential(&fixture.parent_target)?;
        require_absent_credential(&fixture.child_target)?;
        fixture.child_target_was_absent = true;
        write_credential(&fixture.parent_target, CREDENTIAL_BLOB)?;
        fixture.parent_owned = true;
        write_credential(&fixture.child_target, CREDENTIAL_BLOB)?;
        fixture.child_owned = true;
        delete_credential(&fixture.child_target)?;
        fixture.child_owned = false;
        fixture.assert_unchanged();
        Ok(fixture)
    }

    fn observe_child_ownership(&mut self) {
        match read_credential(&self.child_target) {
            Ok(_) if self.child_target_was_absent => self.child_owned = true,
            Ok(_) => panic!("credential child target was not reserved by this fixture"),
            Err(ERROR_NOT_FOUND) => {}
            Err(status) => panic!("credential child observation failed with status {status}"),
        }
    }

    fn assert_unchanged(&self) {
        assert_eq!(
            read_credential(&self.parent_target).unwrap(),
            CREDENTIAL_BLOB
        );
        assert_eq!(read_credential(&self.child_target), Err(ERROR_NOT_FOUND));
        let targets = enumerate_credentials(&self.filter).unwrap();
        assert_eq!(targets, vec![self.parent_target.clone()]);
    }

    fn cleanup(mut self) {
        self.observe_child_ownership();
        self.remove_owned();
        assert_eq!(read_credential(&self.parent_target), Err(ERROR_NOT_FOUND));
        assert_eq!(read_credential(&self.child_target), Err(ERROR_NOT_FOUND));
        assert_eq!(enumerate_credentials(&self.filter), Err(ERROR_NOT_FOUND));
    }

    fn remove_owned(&mut self) {
        if self.parent_owned {
            delete_credential(&self.parent_target).unwrap();
            self.parent_owned = false;
        }
        if self.child_owned {
            delete_credential(&self.child_target).unwrap();
            self.child_owned = false;
        }
    }
}

struct OwnedTestCredential {
    target: String,
    active: bool,
}

impl OwnedTestCredential {
    fn new(target: String, blob: &[u8]) -> Self {
        assert_eq!(read_credential(&target), Err(ERROR_NOT_FOUND));
        write_credential(&target, blob).unwrap();
        Self {
            target,
            active: true,
        }
    }

    fn cleanup(mut self) {
        delete_credential(&self.target).unwrap();
        self.active = false;
        assert_eq!(read_credential(&self.target), Err(ERROR_NOT_FOUND));
    }
}

impl Drop for OwnedTestCredential {
    fn drop(&mut self) {
        if self.active {
            let _ = delete_credential(&self.target);
        }
    }
}

impl Drop for CredentialFixture {
    fn drop(&mut self) {
        if self.child_target_was_absent
            && !self.child_owned
            && read_credential(&self.child_target).is_ok()
        {
            self.child_owned = true;
        }
        if self.parent_owned {
            let _ = delete_credential(&self.parent_target);
        }
        if self.child_owned {
            let _ = delete_credential(&self.child_target);
        }
    }
}

fn credential_nonce() -> String {
    let mut nonce = GUID::from_u128(0);
    // SAFETY: nonce points to writable GUID storage.
    let status = unsafe { UuidCreate(&mut nonce) };
    assert!(status == RPC_S_OK || status == RPC_S_UUID_LOCAL_ONLY);
    format!(
        "{:08x}-{:04x}-{:04x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        nonce.data1,
        nonce.data2,
        nonce.data3,
        nonce.data4[0],
        nonce.data4[1],
        nonce.data4[2],
        nonce.data4[3],
        nonce.data4[4],
        nonce.data4[5],
        nonce.data4[6],
        nonce.data4[7],
    )
}

fn require_absent_credential(target: &str) -> Result<(), u32> {
    match read_credential(target) {
        Err(ERROR_NOT_FOUND) => Ok(()),
        Ok(_) => Err(ERROR_ALREADY_EXISTS),
        Err(status) => Err(status),
    }
}

struct PipeSecurityDescriptor(OwnedLocalAllocation);

impl PipeSecurityDescriptor {
    fn for_current_user() -> Self {
        let user_sid = current_user_sid_string();
        let sddl = wide_nul(&format!("D:P(A;;GA;;;{user_sid})"));
        let mut descriptor = ptr::null_mut();
        // SAFETY: sddl is live and NUL-terminated; descriptor points to writable
        // storage that receives a LocalAlloc-owned security descriptor.
        assert_ne!(
            unsafe {
                ConvertStringSecurityDescriptorToSecurityDescriptorW(
                    sddl.as_ptr(),
                    SDDL_REVISION_1,
                    &mut descriptor,
                    ptr::null_mut(),
                )
            },
            0
        );
        Self(OwnedLocalAllocation(descriptor))
    }

    fn attributes(&self) -> SECURITY_ATTRIBUTES {
        SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: self.0.as_ptr(),
            bInheritHandle: 0,
        }
    }
}

struct OwnedLocalAllocation(*mut std::ffi::c_void);

impl OwnedLocalAllocation {
    fn as_ptr(&self) -> *mut std::ffi::c_void {
        self.0
    }
}

impl Drop for OwnedLocalAllocation {
    fn drop(&mut self) {
        // SAFETY: this pointer was allocated by a Windows API documented for LocalFree.
        unsafe {
            LocalFree(self.0);
        }
    }
}

struct OwnedTokenHandle(windows_sys::Win32::Foundation::HANDLE);

impl Drop for OwnedTokenHandle {
    fn drop(&mut self) {
        // SAFETY: this token handle is owned here.
        unsafe {
            CloseHandle(self.0);
        }
    }
}

fn current_user_sid_string() -> String {
    let mut token = ptr::null_mut();
    // SAFETY: the current-process pseudo-handle is valid and token is writable.
    assert_ne!(
        unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) },
        0
    );
    let token = OwnedTokenHandle(token);
    let mut required = 0;
    // SAFETY: this sizing query intentionally supplies no buffer.
    assert_eq!(
        unsafe { GetTokenInformation(token.0, TokenUser, ptr::null_mut(), 0, &mut required) },
        0
    );
    // SAFETY: GetTokenInformation failed on this thread.
    assert_eq!(unsafe { GetLastError() }, ERROR_INSUFFICIENT_BUFFER);
    let words = (required as usize).div_ceil(std::mem::size_of::<usize>());
    let mut buffer = vec![0_usize; words];
    // SAFETY: buffer is aligned and writable for the requested TOKEN_USER bytes.
    assert_ne!(
        unsafe {
            GetTokenInformation(
                token.0,
                TokenUser,
                buffer.as_mut_ptr().cast(),
                required,
                &mut required,
            )
        },
        0
    );
    // SAFETY: the successful query returned an aligned TOKEN_USER structure.
    let user = unsafe { &*buffer.as_ptr().cast::<TOKEN_USER>() };
    sid_string(user.User.Sid)
}

fn sid_string(sid: windows_sys::Win32::Security::PSID) -> String {
    let mut sid_text = ptr::null_mut();
    // SAFETY: sid is live for this call and sid_text is writable.
    assert_ne!(unsafe { ConvertSidToStringSidW(sid, &mut sid_text) }, 0);
    let sid_text = OwnedLocalAllocation(sid_text.cast());
    // SAFETY: successful conversion returned a NUL-terminated UTF-16 string.
    unsafe { wide_ptr_string(sid_text.as_ptr().cast()) }
}

struct NamedPipeFixture {
    read_name: String,
    write_name: String,
    security: PipeSecurityDescriptor,
}

impl NamedPipeFixture {
    fn new() -> Self {
        let id = NEXT_PIPE_FIXTURE.fetch_add(1, Ordering::Relaxed);
        Self {
            read_name: format!(
                r"\\.\pipe\LOCAL\LocalAgentTerminal-Task7-{}-{id}-read",
                std::process::id(),
            ),
            write_name: format!(
                r"\\.\pipe\LOCAL\LocalAgentTerminal-Task7-{}-{id}-write",
                std::process::id(),
            ),
            security: PipeSecurityDescriptor::for_current_user(),
        }
    }

    fn server(&self, name: &str) -> OwnedNamedPipe {
        let name = wide_nul(name);
        let security = self.security.attributes();
        // SAFETY: name is NUL-terminated and security points to the fixture-owned
        // descriptor for the duration of this call.
        let handle = unsafe {
            CreateNamedPipeW(
                name.as_ptr(),
                PIPE_ACCESS_DUPLEX,
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_NOWAIT | PIPE_REJECT_REMOTE_CLIENTS,
                1,
                0,
                0,
                0,
                &security,
            )
        };
        assert_ne!(handle, INVALID_HANDLE_VALUE);
        OwnedNamedPipe(handle)
    }

    fn prove_parent_connections(&self) {
        for (name, access) in [
            (&self.read_name, GENERIC_READ),
            (&self.write_name, GENERIC_WRITE),
        ] {
            let server = self.server(name);
            let client = connect_pipe(name, access).unwrap();
            assert!(server.accepted_connection());
            drop(client);
            server.disconnect();
        }
    }

    fn cleanup(self, read_server: OwnedNamedPipe, write_server: OwnedNamedPipe) {
        drop(read_server);
        drop(write_server);
        assert_eq!(
            connect_pipe(&self.read_name, GENERIC_READ).unwrap_err(),
            ERROR_FILE_NOT_FOUND
        );
        assert_eq!(
            connect_pipe(&self.write_name, GENERIC_WRITE).unwrap_err(),
            ERROR_FILE_NOT_FOUND
        );
    }
}

#[derive(Debug)]
struct OwnedNamedPipe(windows_sys::Win32::Foundation::HANDLE);

impl OwnedNamedPipe {
    fn allowed_sid_strings(&self) -> Vec<String> {
        let mut dacl = ptr::null_mut();
        let mut descriptor = ptr::null_mut();
        // SAFETY: the pipe handle is live and all requested output pointers are writable.
        assert_eq!(
            unsafe {
                GetSecurityInfo(
                    self.0,
                    SE_KERNEL_OBJECT,
                    DACL_SECURITY_INFORMATION,
                    ptr::null_mut(),
                    ptr::null_mut(),
                    &mut dacl,
                    ptr::null_mut(),
                    &mut descriptor,
                )
            },
            ERROR_SUCCESS
        );
        let _descriptor = OwnedLocalAllocation(descriptor);
        let mut information = ACL_SIZE_INFORMATION::default();
        // SAFETY: dacl belongs to the live descriptor and information is writable.
        assert_ne!(
            unsafe {
                GetAclInformation(
                    dacl,
                    (&mut information as *mut ACL_SIZE_INFORMATION).cast(),
                    std::mem::size_of::<ACL_SIZE_INFORMATION>() as u32,
                    AclSizeInformation,
                )
            },
            0
        );
        (0..information.AceCount)
            .map(|index| {
                let mut raw_ace = ptr::null_mut();
                // SAFETY: index is within the queried ACE count and raw_ace is writable.
                assert_ne!(unsafe { GetAce(dacl, index, &mut raw_ace) }, 0);
                // SAFETY: this test-owned DACL is expected to contain access-allowed ACEs.
                let ace = unsafe { &*raw_ace.cast::<ACCESS_ALLOWED_ACE>() };
                assert_eq!(ace.Header.AceType, 0);
                sid_string((&ace.SidStart as *const u32).cast_mut().cast())
            })
            .collect()
    }

    fn accepted_connection(&self) -> bool {
        // SAFETY: the server handle is live; PIPE_NOWAIT makes this observation bounded.
        if unsafe { ConnectNamedPipe(self.0, ptr::null_mut()) } != 0 {
            return true;
        }
        // SAFETY: ConnectNamedPipe failed on this thread, so GetLastError returns its status.
        match unsafe { GetLastError() } {
            ERROR_PIPE_CONNECTED => true,
            ERROR_PIPE_LISTENING => false,
            status => panic!("unexpected named-pipe observation status {status}"),
        }
    }

    fn disconnect(&self) {
        // SAFETY: the server handle is live and has an accepted parent connection.
        assert_ne!(unsafe { DisconnectNamedPipe(self.0) }, 0);
    }
}

impl Drop for OwnedNamedPipe {
    fn drop(&mut self) {
        // SAFETY: this server handle is owned here.
        unsafe {
            CloseHandle(self.0);
        }
    }
}

#[derive(Debug)]
struct OwnedPipeClient(windows_sys::Win32::Foundation::HANDLE);

impl Drop for OwnedPipeClient {
    fn drop(&mut self) {
        // SAFETY: this client handle is owned here.
        unsafe {
            CloseHandle(self.0);
        }
    }
}

fn connect_pipe(name: &str, access: u32) -> Result<OwnedPipeClient, u32> {
    let name = wide_nul(name);
    // SAFETY: name is NUL-terminated; optional security and template handles are null.
    let handle = unsafe {
        CreateFileW(
            name.as_ptr(),
            access,
            0,
            ptr::null(),
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            ptr::null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        // SAFETY: CreateFileW failed on this thread, so GetLastError returns its status.
        Err(unsafe { GetLastError() })
    } else {
        Ok(OwnedPipeClient(handle))
    }
}

struct OwnedRegistryKey(windows_sys::Win32::System::Registry::HKEY);

impl Drop for OwnedRegistryKey {
    fn drop(&mut self) {
        // SAFETY: this handle was returned by RegCreateKeyExW and is owned here.
        unsafe {
            RegCloseKey(self.0);
        }
    }
}

fn create_registry_key(
    root: windows_sys::Win32::System::Registry::HKEY,
    subkey: &str,
    access: u32,
) -> Result<(OwnedRegistryKey, u32), u32> {
    let subkey = wide_nul(subkey);
    let mut key = ptr::null_mut();
    let mut disposition = 0;
    // SAFETY: root is live; subkey is NUL-terminated; output storage is valid;
    // optional pointers are null.
    let status = unsafe {
        RegCreateKeyExW(
            root,
            subkey.as_ptr(),
            0,
            ptr::null(),
            0,
            access,
            ptr::null(),
            &mut key,
            &mut disposition,
        )
    };
    if status == ERROR_SUCCESS {
        Ok((OwnedRegistryKey(key), disposition))
    } else {
        Err(status)
    }
}

fn open_registry_key(subkey: &str, access: u32) -> Result<OwnedRegistryKey, u32> {
    let subkey = wide_nul(subkey);
    let mut key = ptr::null_mut();
    // SAFETY: subkey is NUL-terminated and key points to writable storage.
    let status = unsafe { RegOpenKeyExW(HKEY_CURRENT_USER, subkey.as_ptr(), 0, access, &mut key) };
    if status == ERROR_SUCCESS {
        Ok(OwnedRegistryKey(key))
    } else {
        Err(status)
    }
}

fn set_registry_binary(
    key: windows_sys::Win32::System::Registry::HKEY,
    name: &str,
    value: &[u8],
) -> Result<(), u32> {
    let name = wide_nul(name);
    // SAFETY: key is live; name is NUL-terminated; value points to value.len() bytes.
    let status = unsafe {
        RegSetValueExW(
            key,
            name.as_ptr(),
            0,
            REG_BINARY,
            value.as_ptr(),
            u32::try_from(value.len()).unwrap(),
        )
    };
    (status == ERROR_SUCCESS).then_some(()).ok_or(status)
}

fn read_registry_binary(
    key: windows_sys::Win32::System::Registry::HKEY,
    name: &str,
) -> Result<Vec<u8>, u32> {
    let name = wide_nul(name);
    let mut value = [0_u8; 128];
    let mut size = value.len() as u32;
    // SAFETY: key is live; name is NUL-terminated; value and size are writable.
    let status = unsafe {
        RegGetValueW(
            key,
            ptr::null(),
            name.as_ptr(),
            RRF_RT_REG_BINARY,
            ptr::null_mut(),
            value.as_mut_ptr().cast(),
            &mut size,
        )
    };
    if status == ERROR_SUCCESS {
        Ok(value[..size as usize].to_vec())
    } else {
        Err(status)
    }
}

fn write_credential(target: &str, blob: &[u8]) -> Result<(), u32> {
    let target = wide_nul(target);
    let username = wide_nul("task7");
    let credential = CREDENTIALW {
        Type: CRED_TYPE_GENERIC,
        TargetName: target.as_ptr().cast_mut(),
        CredentialBlobSize: u32::try_from(blob.len()).unwrap(),
        CredentialBlob: blob.as_ptr().cast_mut(),
        Persist: CRED_PERSIST_SESSION,
        UserName: username.as_ptr().cast_mut(),
        ..CREDENTIALW::default()
    };
    // SAFETY: all credential pointers reference live buffers for the duration of the call.
    if unsafe { CredWriteW(&credential, 0) } != 0 {
        Ok(())
    } else {
        // SAFETY: CredWriteW failed on this thread, so GetLastError returns its status.
        Err(unsafe { GetLastError() })
    }
}

fn read_credential(target: &str) -> Result<Vec<u8>, u32> {
    let target = wide_nul(target);
    let mut credential = ptr::null_mut();
    // SAFETY: target is NUL-terminated and credential points to writable storage.
    if unsafe { CredReadW(target.as_ptr(), CRED_TYPE_GENERIC, 0, &mut credential) } == 0 {
        // SAFETY: CredReadW failed on this thread, so GetLastError returns its status.
        return Err(unsafe { GetLastError() });
    }
    let credential = OwnedCredentialBuffer(credential.cast());
    // SAFETY: successful CredReadW returns one valid CREDENTIALW allocation.
    let credential = unsafe { &*credential.0.cast::<CREDENTIALW>() };
    // SAFETY: CredentialBlob points to CredentialBlobSize readable bytes.
    Ok(unsafe {
        std::slice::from_raw_parts(
            credential.CredentialBlob,
            credential.CredentialBlobSize as usize,
        )
        .to_vec()
    })
}

fn enumerate_credentials(filter: &str) -> Result<Vec<String>, u32> {
    let filter = wide_nul(filter);
    let mut count = 0;
    let mut credentials = ptr::null_mut();
    // SAFETY: filter is NUL-terminated and both output pointers are writable.
    if unsafe { CredEnumerateW(filter.as_ptr(), 0, &mut count, &mut credentials) } == 0 {
        // SAFETY: CredEnumerateW failed on this thread, so GetLastError returns its status.
        return Err(unsafe { GetLastError() });
    }
    let credentials = OwnedCredentialBuffer(credentials.cast());
    // SAFETY: successful CredEnumerateW returns count pointers to valid CREDENTIALW values.
    let credentials = unsafe {
        std::slice::from_raw_parts(credentials.0.cast::<*mut CREDENTIALW>(), count as usize)
    };
    let mut targets = credentials
        .iter()
        .map(|credential| {
            // SAFETY: each returned credential and TargetName are valid until CredFree.
            unsafe { wide_ptr_string((**credential).TargetName) }
        })
        .collect::<Vec<_>>();
    targets.sort();
    Ok(targets)
}

fn delete_credential(target: &str) -> Result<(), u32> {
    let target = wide_nul(target);
    // SAFETY: target is NUL-terminated.
    if unsafe { CredDeleteW(target.as_ptr(), CRED_TYPE_GENERIC, 0) } != 0 {
        Ok(())
    } else {
        // SAFETY: CredDeleteW failed on this thread, so GetLastError returns its status.
        Err(unsafe { GetLastError() })
    }
}

struct OwnedCredentialBuffer(*mut std::ffi::c_void);

impl Drop for OwnedCredentialBuffer {
    fn drop(&mut self) {
        // SAFETY: this allocation was returned by CredReadW or CredEnumerateW.
        unsafe {
            CredFree(self.0);
        }
    }
}

unsafe fn wide_ptr_string(value: *const u16) -> String {
    let mut length = 0;
    // SAFETY: caller guarantees value points to a NUL-terminated Windows string.
    while unsafe { *value.add(length) } != 0 {
        length += 1;
    }
    // SAFETY: caller guarantees the first length elements are readable.
    String::from_utf16(unsafe { std::slice::from_raw_parts(value, length) }).unwrap()
}

fn wide_nul(value: &str) -> Vec<u16> {
    std::ffi::OsStr::new(value)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

impl DeniedCanary {
    fn new(label: &str, directory: &Path) -> Self {
        let read = directory.join(format!("{label}-read.bin"));
        let write = directory.join(format!("{label}-write.bin"));
        let read_contents = format!("{label} read canary").into_bytes();
        let write_contents = format!("{label} write canary").into_bytes();
        fs::write(&read, &read_contents).unwrap();
        fs::write(&write, &write_contents).unwrap();
        assert_eq!(fs::read(&read).unwrap(), read_contents);
        fs::write(&write, b"parent write control").unwrap();
        assert_eq!(fs::read(&write).unwrap(), b"parent write control");
        fs::write(&write, &write_contents).unwrap();
        Self {
            read,
            write,
            read_contents,
            write_contents,
        }
    }

    fn assert_unchanged(&self) {
        assert_eq!(fs::read(&self.read).unwrap(), self.read_contents);
        assert_eq!(fs::read(&self.write).unwrap(), self.write_contents);
    }
}

fn named_stream_path(path: &Path, name: &str) -> PathBuf {
    let mut stream = path.as_os_str().to_os_string();
    stream.push(format!(":{name}"));
    PathBuf::from(stream)
}

fn extended_length_path(path: &Path) -> PathBuf {
    let canonical = fs::canonicalize(path).unwrap();
    if path_text(&canonical).starts_with(r"\\?\") {
        canonical
    } else {
        PathBuf::from(format!(r"\\?\{}", canonical.display()))
    }
}

fn path_text(path: &Path) -> String {
    path.to_str()
        .expect("test fixture path must be Unicode")
        .to_owned()
}

fn localhost_admin_share_path(path: &Path) -> PathBuf {
    let canonical = fs::canonicalize(path).unwrap();
    let value = canonical.to_string_lossy();
    let value = value.strip_prefix(r"\\?\").unwrap_or(&value);
    let drive = value.chars().next().unwrap();
    let relative = value.get(3..).unwrap();
    PathBuf::from(format!(r"\\localhost\{drive}$\{relative}"))
}

fn create_junction(target: &Path, link: &Path) {
    let output = Command::new("cmd.exe")
        .args(["/D", "/C", "mklink", "/J"])
        .arg(link)
        .arg(target)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn host_lan_ip() -> IpAddr {
    let route_probe = UdpSocket::bind(("0.0.0.0", 0)).unwrap();
    route_probe.connect(("192.0.2.1", 9)).unwrap();
    let ip = route_probe.local_addr().unwrap().ip();
    assert!(
        !ip.is_loopback() && !ip.is_unspecified(),
        "no host LAN address"
    );
    ip
}

fn prove_parent_connection(listener: &TcpListener) {
    let address = listener.local_addr().unwrap();
    let connection = TcpStream::connect_timeout(&address, Duration::from_secs(1)).unwrap();
    let (accepted, _) = listener.accept().unwrap();
    drop(connection);
    drop(accepted);
}

fn assert_no_pending_connection(listener: &TcpListener) {
    listener.set_nonblocking(true).unwrap();
    let error = listener
        .accept()
        .expect_err("LPAC child reached a denied listener");
    assert_eq!(error.kind(), std::io::ErrorKind::WouldBlock);
}

fn network_observations(stdout: &str) -> BTreeSet<String> {
    stdout
        .lines()
        .filter_map(|line| {
            line.strip_prefix("d2a-network-")
                .or_else(|| line.strip_prefix("m2-network-"))
        })
        .map(|line| format!("network-{line}"))
        .collect()
}

fn lpac_identity_environment() -> BTreeMap<String, String> {
    BTreeMap::from([("LAT_PROCESS_HELPER".to_owned(), "lpac-identity".to_owned())])
}

fn lpac_marker_request(execution_id: &str, marker: &std::path::Path) -> AuthorizedProcessRequest {
    let mut request = request(
        vec![
            "--exact".to_owned(),
            "process_child_helper".to_owned(),
            "--nocapture".to_owned(),
        ],
        BTreeMap::from([
            ("LAT_PROCESS_HELPER".to_owned(), "marker".to_owned()),
            (
                "LAT_PROCESS_MARKER".to_owned(),
                marker.to_string_lossy().into_owned(),
            ),
        ]),
    );
    request.execution_id = ToolExecutionId::new(execution_id).unwrap();
    request
}

fn assert_lpac_rejected_before_resume(
    launcher: &WindowsProcessLauncher,
    request: AuthorizedProcessRequest,
    marker: &std::path::Path,
    suspended_child_expected: bool,
) {
    let execution_id = request.execution_id.clone();

    assert!(launcher.execute(request).is_err());
    assert!(!marker.exists());
    assert!(launcher.cancel(&execution_id).is_err());
    #[cfg(feature = "test-seams")]
    {
        let counts = lpac_lifecycle_counts_for_test(&execution_id);
        if suspended_child_expected {
            assert_eq!(counts.profiles_created, 1);
            assert_eq!(counts.profiles_deleted, 1);
            assert_eq!(counts.acl_grants, 2);
            assert_eq!(counts.acl_revokes, 2);
            assert_eq!(counts.suspended_children_created, 1);
            assert_eq!(counts.resumes_succeeded, 0);
        } else {
            assert_eq!(counts, LpacLifecycleCountsForTest::default());
        }
    }
    #[cfg(not(feature = "test-seams"))]
    let _ = suspended_child_expected;
}

fn request(argv: Vec<String>, environment: BTreeMap<String, String>) -> AuthorizedProcessRequest {
    let task_id = TaskId::new("task-1").unwrap();
    let executable_path = std::env::current_exe().unwrap();
    let executable = registered_executable("test-helper", "test-version", &executable_path);
    let network_digest = digest(b"network-profile");
    AuthorizedProcessRequest {
        execution_id: ToolExecutionId::new(format!(
            "execution-test-{}-{}",
            std::process::id(),
            NEXT_PROCESS_EXECUTION_ID.fetch_add(1, Ordering::Relaxed),
        ))
        .unwrap(),
        trust_tier: ProcessTrustTier::IsolatedWorker,
        executable,
        argv,
        cwd: ProcessWorkingDirectory::IsolatedWorktree(ResolvedCapability {
            capability: CapabilityRef::worktree(task_id.clone(), ".").unwrap(),
            content_digest: None,
            root_identity: CapabilityRootIdentity::new("test-worktree").unwrap(),
            target: ResolvedCapabilityTarget::Root,
        }),
        environment: ResolvedEnvironmentProfile {
            name: "test-empty-parent".to_owned(),
            values: environment,
            digest: digest(b"environment-profile"),
        },
        network: EnforcedNetworkProfile {
            profile: NetworkProfile::Denied,
            profile_digest: network_digest.clone(),
            receipt: NetworkEnforcementReceipt::new("test-network", network_digest).unwrap(),
        },
        timeout_ms: 5_000,
        limits: ProcessLimits {
            memory_limit_bytes: 256 * 1024 * 1024,
            cpu_time_limit_ms: 5_000,
            max_stdout_bytes: 64 * 1024,
            max_stderr_bytes: 64 * 1024,
            max_active_processes: 8,
            disk_write_limit_bytes: None,
        },
        expected_writes: Vec::new(),
        executor_claim: LeaseClaim::new(
            task_id,
            RunId::new("run-1").unwrap(),
            FencingToken::new(7).unwrap(),
        ),
        executor_fence: ProcessFenceAuthority::new(
            Arc::new(ReplaceableLeaseStore::new(7)),
            Arc::new(WorkspaceWriteCoordinator::new()),
        )
        .binding(),
    }
}

fn registered_executable(
    name: &str,
    version: &str,
    path: &Path,
) -> local_agent_terminal_application::ResolvedExecutable {
    let executable_digest = digest(&fs::read(path).unwrap());
    let executables = ExecutableRegistry::load(
        vec![TrustedExecutableRegistration::new(name, version, path, executable_digest).unwrap()],
        Arc::new(WindowsExecutableInspector),
    )
    .unwrap();
    executables.resolve(name, version).unwrap()
}

fn authorized_write(path: &str, root_identity: &str) -> AuthorizedExpectedWrite {
    let task_id = TaskId::new("task-1").unwrap();
    let capability = CapabilityRef::worktree(task_id.clone(), path).unwrap();
    let expected = ExpectedWrite::new(capability.clone()).unwrap();
    let target = if path == "." {
        ResolvedCapabilityTarget::Root
    } else {
        ResolvedCapabilityTarget::Relative(
            RelativePathComponents::new(path.split(['/', '\\']).map(str::to_owned).collect())
                .unwrap(),
        )
    };
    AuthorizedExpectedWrite::new(
        &task_id,
        &expected,
        ResolvedCapability {
            capability,
            content_digest: None,
            root_identity: CapabilityRootIdentity::new(root_identity).unwrap(),
            target,
        },
    )
    .unwrap()
}

fn observed_write(scope: &AuthorizedExpectedWrite, bytes: &[u8]) -> ObservedProcessWrite {
    observed_evidence(
        scope.capability().clone(),
        scope.root_identity().clone(),
        scope.target().clone(),
        bytes,
    )
}

fn observed_evidence(
    capability: CapabilityRef,
    root_identity: CapabilityRootIdentity,
    target: ResolvedCapabilityTarget,
    bytes: &[u8],
) -> ObservedProcessWrite {
    ObservedProcessWrite::new(
        capability,
        root_identity,
        target,
        VerifiedWrite {
            digest: digest(bytes),
            size_bytes: bytes.len() as u64,
        },
    )
}

fn digest(bytes: &[u8]) -> Sha256Digest {
    Sha256Digest::new(format!("sha256:{:x}", Sha256::digest(bytes))).unwrap()
}

#[cfg(feature = "test-seams")]
fn boundary_binding() -> IsolatedWorkerBoundaryBinding {
    IsolatedWorkerBoundaryBinding::new("test-only-identity", "test-only-acl").unwrap()
}

#[cfg(feature = "test-seams")]
fn wait_for_file(path: &PathBuf) -> String {
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        if let Ok(contents) = fs::read_to_string(path) {
            return contents;
        }
        thread::sleep(Duration::from_millis(10));
    }
    panic!("child did not publish process-tree state");
}

fn burn_user_cpu(duration: Duration) {
    let target_ticks = process_user_time_ticks() + duration.as_nanos() as u64 / 100;
    let mut value = 0_u64;
    while process_user_time_ticks() < target_ticks {
        for _ in 0..1_000_000 {
            value = std::hint::black_box(value.wrapping_add(1));
        }
    }
}

fn process_user_time_ticks() -> u64 {
    let mut creation_time = FILETIME::default();
    let mut exit_time = FILETIME::default();
    let mut kernel_time = FILETIME::default();
    let mut user_time = FILETIME::default();
    // SAFETY: all output pointers refer to initialized writable FILETIME values,
    // and GetCurrentProcess returns a valid pseudo-handle for this process.
    assert_ne!(
        unsafe {
            GetProcessTimes(
                GetCurrentProcess(),
                &mut creation_time,
                &mut exit_time,
                &mut kernel_time,
                &mut user_time,
            )
        },
        0,
    );
    (u64::from(user_time.dwHighDateTime) << 32) | u64::from(user_time.dwLowDateTime)
}

#[cfg(feature = "test-seams")]
fn process_is_active(process_id: u32) -> bool {
    // SAFETY: OpenProcess is called with query-only access and a numeric PID.
    let process = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, process_id) };
    if process.is_null() {
        return false;
    }
    let mut exit_code = 0;
    // SAFETY: process is a valid query handle and exit_code is writable.
    let active = unsafe { GetExitCodeProcess(process, &mut exit_code) } != 0
        && exit_code == STILL_ACTIVE as u32;
    // SAFETY: process was returned by OpenProcess and is owned in this scope.
    unsafe {
        CloseHandle(process);
    }
    active
}

struct EnvironmentVariableGuard {
    name: &'static str,
    previous: Option<std::ffi::OsString>,
}

impl EnvironmentVariableGuard {
    fn set(name: &'static str, value: &str) -> Self {
        let previous = std::env::var_os(name);
        std::env::set_var(name, value);
        Self { name, previous }
    }
}

impl Drop for EnvironmentVariableGuard {
    fn drop(&mut self) {
        if let Some(value) = &self.previous {
            std::env::set_var(self.name, value);
        } else {
            std::env::remove_var(self.name);
        }
    }
}
