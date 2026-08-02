#![cfg(windows)]

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::net::{IpAddr, SocketAddr};
use std::os::windows::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::ptr;

use windows_sys::Win32::Foundation::{
    CloseHandle, GetLastError, ERROR_ACCESS_DENIED, ERROR_FILE_NOT_FOUND, ERROR_INVALID_FUNCTION,
    ERROR_NOT_FOUND, ERROR_NOT_SUPPORTED, ERROR_NOT_SUPPORTED_IN_APPCONTAINER,
    ERROR_NO_SUCH_LOGON_SESSION, ERROR_SUCCESS, GENERIC_READ, GENERIC_WRITE, INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::Networking::WinSock::{
    closesocket, connect, getsockopt, ioctlsocket, socket, WSACleanup, WSAGetLastError, WSAPoll,
    WSAStartup, AF_INET, FIONBIO, INVALID_SOCKET, IN_ADDR, IN_ADDR_0, IPPROTO_TCP, POLLOUT,
    SOCKADDR, SOCKADDR_IN, SOCKET, SOCKET_ERROR, SOCK_STREAM, SOL_SOCKET, SO_ERROR, WSADATA,
    WSAEACCES, WSAEINPROGRESS, WSAEPROVIDERFAILEDINIT, WSAEWOULDBLOCK, WSAPOLLFD,
    WSASYSCALLFAILURE,
};
use windows_sys::Win32::Security::Credentials::{
    CredDeleteW, CredEnumerateW, CredFree, CredReadW, CredWriteW, CREDENTIALW,
    CRED_PERSIST_SESSION, CRED_TYPE_GENERIC,
};
use windows_sys::Win32::Storage::FileSystem::{CreateFileW, FILE_ATTRIBUTE_NORMAL, OPEN_EXISTING};
use windows_sys::Win32::System::Registry::{
    RegCloseKey, RegCreateKeyExW, RegGetValueW, RegOpenKeyExW, RegSetValueExW, HKEY_CURRENT_USER,
    KEY_READ, KEY_WRITE, REG_BINARY, RRF_RT_REG_BINARY,
};
use windows_sys::Win32::System::Rpc::RPC_S_INVALID_BINDING;

const REGISTRY_PARENT_VALUE: &str = "parent-value";
const REGISTRY_CHILD_MARKER: &str = "child-marker";
const CREDENTIAL_BLOB: &[u8] = b"m2 inert credential blob";

fn main() {
    println!("m2-root-enumerate={}", root_enumeration_status());
    println!(
        "m2-root-file-create={}",
        create_file_status(Path::new("m2-created-file"))
    );
    println!(
        "m2-root-directory-create={}",
        io_status(fs::create_dir("m2-created-directory"))
    );
    let root_stream = named_stream_path(&std::env::current_dir().unwrap(), "m2-created-stream");
    println!("m2-root-stream-create={}", create_file_status(&root_stream));

    for (index, label) in [
        "repository",
        "original",
        "sibling",
        "profile",
        "appdata",
        "capability",
    ]
    .into_iter()
    .enumerate()
    {
        let read = environment_path("LAT_M2_READ", index);
        let write = environment_path("LAT_M2_WRITE", index);
        println!("m2-read-{label}={}", read_status(&read));
        println!("m2-write-{label}={}", append_status(&write));
    }
    for (index, label) in [
        "junction",
        "symlink",
        "unc",
        "device",
        "ads",
        "casefold",
        "unicode",
        "long",
        "replacement",
    ]
    .into_iter()
    .enumerate()
    {
        println!(
            "m2-path-{label}={}",
            read_status(&environment_path("LAT_M2_PATH", index))
        );
    }

    let reserved_environment_is_valid = std::env::var_os("LOCALAPPDATA").is_some_and(|value| {
        let expected = Path::new(&value).join("Temp");
        std::env::var_os("TEMP").as_deref() == Some(expected.as_os_str())
            && std::env::var_os("TMP").as_deref() == Some(expected.as_os_str())
    });
    let ambient_environment_is_absent = [
        "USERPROFILE",
        "HOMEDRIVE",
        "HOMEPATH",
        "APPDATA",
        "PATH",
        "AWS_ACCESS_KEY_ID",
        "AZURE_CLIENT_SECRET",
        "GITHUB_TOKEN",
        "OPENAI_API_KEY",
        "LAT_M2_PARENT_SECRET",
    ]
    .into_iter()
    .all(|name| std::env::var_os(name).is_none());
    println!(
        "m2-environment={}",
        if reserved_environment_is_valid && ambient_environment_is_absent {
            "clean"
        } else {
            "inherited"
        }
    );

    run_network_probe();
    println!(
        "m2-registry-read={}",
        registry_read_status(&std::env::var("LAT_M2_REGISTRY_KEY").unwrap_or_default())
    );
    println!(
        "m2-registry-write={}",
        registry_write_status(&std::env::var("LAT_M2_REGISTRY_KEY").unwrap_or_default())
    );
    println!(
        "m2-credential-read={}",
        credential_read_status(&std::env::var("LAT_M2_CREDENTIAL_PARENT").unwrap_or_default())
    );
    println!(
        "m2-credential-enumerate={}",
        credential_enumerate_status(&std::env::var("LAT_M2_CREDENTIAL_FILTER").unwrap_or_default())
    );
    println!(
        "m2-credential-write={}",
        credential_write_status(&std::env::var("LAT_M2_CREDENTIAL_CHILD").unwrap_or_default())
    );
    println!(
        "m2-pipe-read={}",
        pipe_connect_status(
            &std::env::var("LAT_M2_PIPE_READ").unwrap_or_default(),
            GENERIC_READ
        )
    );
    println!(
        "m2-pipe-write={}",
        pipe_connect_status(
            &std::env::var("LAT_M2_PIPE_WRITE").unwrap_or_default(),
            GENERIC_WRITE
        )
    );
}

fn environment_path(prefix: &str, index: usize) -> PathBuf {
    PathBuf::from(std::env::var_os(format!("{prefix}_{index}")).unwrap())
}

fn root_enumeration_status() -> &'static str {
    match fs::read_dir(".") {
        Ok(mut entries) => {
            if entries.next().is_none() {
                "success"
            } else {
                "unexpected-entry"
            }
        }
        Err(error) if is_permission_denied(&error) => "denied",
        Err(_) => "other",
    }
}

fn read_status(path: &Path) -> &'static str {
    match fs::read(path) {
        Ok(_) => "allowed",
        Err(error) if is_permission_denied(&error) => "denied",
        Err(_) if path.as_os_str().to_string_lossy().starts_with(r"\\") => "denied",
        Err(_) => "other",
    }
}

fn append_status(path: &Path) -> &'static str {
    match OpenOptions::new().append(true).open(path) {
        Ok(mut file) => match file.write_all(b"x") {
            Ok(()) => "allowed",
            Err(error) if is_permission_denied(&error) => "denied",
            Err(_) => "other",
        },
        Err(error) if is_permission_denied(&error) => "denied",
        Err(_) => "other",
    }
}

fn create_file_status(path: &Path) -> &'static str {
    match OpenOptions::new().create_new(true).write(true).open(path) {
        Ok(_) => "allowed",
        Err(error) if is_permission_denied(&error) => "denied",
        Err(_) => "other",
    }
}

fn io_status(result: std::io::Result<()>) -> &'static str {
    match result {
        Ok(()) => "allowed",
        Err(error) if is_permission_denied(&error) => "denied",
        Err(_) => "other",
    }
}

fn run_network_probe() {
    let targets = [
        ("loopback", "LAT_M2_LOOPBACK"),
        ("lan", "LAT_M2_LAN"),
        ("internet", "LAT_M2_INTERNET"),
    ];
    let addresses = targets.map(|(_, variable)| {
        std::env::var(variable)
            .ok()
            .and_then(|value| value.parse::<SocketAddr>().ok())
    });
    let (subsystem, statuses) = probe_network_targets(&addresses);
    println!("m2-network-subsystem={subsystem}");
    for ((label, _), status) in targets.into_iter().zip(statuses) {
        println!("m2-network-{label}={status}");
    }
}

fn probe_network_targets(addresses: &[Option<SocketAddr>; 3]) -> (&'static str, [&'static str; 3]) {
    let mut data = WSADATA::default();
    // SAFETY: data is writable for WSADATA and the requested version is Winsock 2.2.
    let startup = unsafe { WSAStartup(0x0202, &mut data) };
    if startup != 0 {
        let status = if startup == WSASYSCALLFAILURE {
            "subsystem-denied"
        } else {
            "subsystem-error"
        };
        return (status, [status; 3]);
    }
    let _winsock = WinsockSession;
    (
        "ready",
        addresses.map(|address| address.as_ref().map(connect_status).unwrap_or("invalid")),
    )
}

fn connect_status(address: &SocketAddr) -> &'static str {
    let IpAddr::V4(ip) = address.ip() else {
        return "invalid";
    };
    // SAFETY: Winsock was initialized and the constants describe an IPv4 TCP stream socket.
    let socket = unsafe { socket(i32::from(AF_INET), SOCK_STREAM, IPPROTO_TCP) };
    if socket == INVALID_SOCKET {
        // SAFETY: socket failed on this thread, so WSAGetLastError returns its status.
        return match unsafe { WSAGetLastError() } {
            WSAEACCES => "denied-socket",
            WSAEPROVIDERFAILEDINIT => "provider-init-failed",
            _ => "socket-error",
        };
    }
    let socket = OwnedSocket(socket);
    let mut nonblocking = 1_u32;
    // SAFETY: socket is live and nonblocking points to writable storage.
    if unsafe { ioctlsocket(socket.0, FIONBIO, &mut nonblocking) } == SOCKET_ERROR {
        return "socket-error";
    }
    let target = SOCKADDR_IN {
        sin_family: AF_INET,
        sin_port: address.port().to_be(),
        sin_addr: IN_ADDR {
            S_un: IN_ADDR_0 {
                S_addr: u32::from_ne_bytes(ip.octets()),
            },
        },
        sin_zero: [0; 8],
    };
    // SAFETY: target is a fully initialized IPv4 sockaddr of the declared length.
    if unsafe {
        connect(
            socket.0,
            (&target as *const SOCKADDR_IN).cast::<SOCKADDR>(),
            std::mem::size_of::<SOCKADDR_IN>() as i32,
        )
    } == 0
    {
        return "allowed";
    }
    // SAFETY: connect failed on this thread, so WSAGetLastError returns its status.
    let error = unsafe { WSAGetLastError() };
    if error == WSAEACCES {
        return "denied-connect";
    }
    if !matches!(error, WSAEWOULDBLOCK | WSAEINPROGRESS) {
        return "other";
    }
    let mut poll = WSAPOLLFD {
        fd: socket.0,
        events: POLLOUT,
        revents: 0,
    };
    // SAFETY: poll is writable for one bounded WSAPoll call.
    let poll_result = unsafe { WSAPoll(&mut poll, 1, 500) };
    if poll_result == 0 {
        return "timeout";
    }
    if poll_result == SOCKET_ERROR {
        return "other";
    }
    let mut socket_error = 0_i32;
    let mut socket_error_bytes = std::mem::size_of::<i32>() as i32;
    // SAFETY: output pointers are writable for the declared SO_ERROR integer size.
    if unsafe {
        getsockopt(
            socket.0,
            SOL_SOCKET,
            SO_ERROR,
            (&mut socket_error as *mut i32).cast(),
            &mut socket_error_bytes,
        )
    } == SOCKET_ERROR
        || socket_error_bytes != std::mem::size_of::<i32>() as i32
    {
        return "other";
    }
    match socket_error {
        0 => "allowed",
        WSAEACCES => "denied-connect",
        _ => "other",
    }
}

fn registry_read_status(subkey: &str) -> &'static str {
    let subkey = wide_nul(subkey);
    let mut key = ptr::null_mut();
    // SAFETY: subkey is NUL-terminated and key points to writable storage.
    let status =
        unsafe { RegOpenKeyExW(HKEY_CURRENT_USER, subkey.as_ptr(), 0, KEY_READ, &mut key) };
    if status != ERROR_SUCCESS {
        return protected_resource_status(status);
    }
    let key = OwnedRegistryKey(key);
    match read_registry_binary(key.0, REGISTRY_PARENT_VALUE) {
        Ok(_) => "success",
        Err(status) => protected_resource_status(status),
    }
}

fn registry_write_status(subkey: &str) -> &'static str {
    match create_registry_key(subkey, KEY_WRITE) {
        Ok(key) => match set_registry_binary(key.0, REGISTRY_CHILD_MARKER, b"child marker") {
            Ok(()) => "success",
            Err(status) => protected_resource_status(status),
        },
        Err(status) => protected_resource_status(status),
    }
}

fn credential_read_status(target: &str) -> &'static str {
    match read_credential(target) {
        Ok(_) => "success",
        Err(status) => protected_resource_status(status),
    }
}

fn credential_enumerate_status(filter: &str) -> &'static str {
    match enumerate_credentials(filter) {
        Ok(_) => "success",
        Err(status) => protected_resource_status(status),
    }
}

fn credential_write_status(target: &str) -> &'static str {
    match write_credential(target, CREDENTIAL_BLOB) {
        Ok(()) => match delete_credential(target) {
            Ok(()) => "isolated-cleaned",
            Err(_) => "cleanup-failed",
        },
        Err(status) => protected_resource_status(status),
    }
}

fn pipe_connect_status(name: &str, access: u32) -> &'static str {
    let name = wide_nul(name);
    // SAFETY: name is NUL-terminated and optional pointers are null.
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
        protected_resource_status(unsafe { GetLastError() })
    } else {
        // SAFETY: this handle was returned by CreateFileW and is owned here.
        unsafe { CloseHandle(handle) };
        "success"
    }
}

fn protected_resource_status(status: u32) -> &'static str {
    match status {
        ERROR_ACCESS_DENIED => "denied",
        ERROR_FILE_NOT_FOUND | ERROR_NOT_FOUND => "not-found",
        ERROR_NO_SUCH_LOGON_SESSION => "no-logon-session",
        ERROR_NOT_SUPPORTED => "not-supported",
        ERROR_NOT_SUPPORTED_IN_APPCONTAINER => "not-supported-in-appcontainer",
        ERROR_INVALID_FUNCTION => "invalid-function",
        status if status == RPC_S_INVALID_BINDING as u32 => "rpc-invalid-binding",
        _ => "error",
    }
}

fn create_registry_key(subkey: &str, access: u32) -> Result<OwnedRegistryKey, u32> {
    let subkey = wide_nul(subkey);
    let mut key = ptr::null_mut();
    let mut disposition = 0;
    // SAFETY: root is live, subkey is NUL-terminated, and output storage is valid.
    let status = unsafe {
        RegCreateKeyExW(
            HKEY_CURRENT_USER,
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
        Ok(OwnedRegistryKey(key))
    } else {
        Err(status)
    }
}

fn set_registry_binary(key: *mut std::ffi::c_void, name: &str, value: &[u8]) -> Result<(), u32> {
    let name = wide_nul(name);
    // SAFETY: key is live and the name/value buffers stay live for the call.
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

fn read_registry_binary(key: *mut std::ffi::c_void, name: &str) -> Result<Vec<u8>, u32> {
    let name = wide_nul(name);
    let mut value = [0_u8; 128];
    let mut size = value.len() as u32;
    // SAFETY: key is live and output buffers are writable.
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
    let username = wide_nul("m2");
    let credential = CREDENTIALW {
        Type: CRED_TYPE_GENERIC,
        TargetName: target.as_ptr().cast_mut(),
        CredentialBlobSize: u32::try_from(blob.len()).unwrap(),
        CredentialBlob: blob.as_ptr().cast_mut(),
        Persist: CRED_PERSIST_SESSION,
        UserName: username.as_ptr().cast_mut(),
        ..CREDENTIALW::default()
    };
    // SAFETY: all credential pointers remain live for the call.
    if unsafe { CredWriteW(&credential, 0) } != 0 {
        Ok(())
    } else {
        // SAFETY: CredWriteW failed on this thread.
        Err(unsafe { GetLastError() })
    }
}

fn read_credential(target: &str) -> Result<(), u32> {
    let target = wide_nul(target);
    let mut credential = ptr::null_mut();
    // SAFETY: target is NUL-terminated and output storage is writable.
    if unsafe { CredReadW(target.as_ptr(), CRED_TYPE_GENERIC, 0, &mut credential) } == 0 {
        // SAFETY: CredReadW failed on this thread.
        return Err(unsafe { GetLastError() });
    }
    // SAFETY: successful CredReadW returns an allocation owned by CredFree.
    unsafe { CredFree(credential.cast()) };
    Ok(())
}

fn enumerate_credentials(filter: &str) -> Result<(), u32> {
    let filter = wide_nul(filter);
    let mut count = 0;
    let mut credentials = ptr::null_mut();
    // SAFETY: filter is NUL-terminated and output storage is writable.
    if unsafe { CredEnumerateW(filter.as_ptr(), 0, &mut count, &mut credentials) } == 0 {
        // SAFETY: CredEnumerateW failed on this thread.
        return Err(unsafe { GetLastError() });
    }
    // SAFETY: successful CredEnumerateW returns an allocation owned by CredFree.
    unsafe { CredFree(credentials.cast()) };
    Ok(())
}

fn delete_credential(target: &str) -> Result<(), u32> {
    let target = wide_nul(target);
    // SAFETY: target is NUL-terminated.
    if unsafe { CredDeleteW(target.as_ptr(), CRED_TYPE_GENERIC, 0) } != 0 {
        Ok(())
    } else {
        // SAFETY: CredDeleteW failed on this thread.
        Err(unsafe { GetLastError() })
    }
}

fn named_stream_path(path: &Path, name: &str) -> PathBuf {
    let mut stream = path.as_os_str().to_os_string();
    stream.push(format!(":{name}"));
    PathBuf::from(stream)
}

fn wide_nul(value: &str) -> Vec<u16> {
    std::ffi::OsStr::new(value)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

fn is_permission_denied(error: &std::io::Error) -> bool {
    error.kind() == std::io::ErrorKind::PermissionDenied
        || matches!(
            error.raw_os_error(),
            Some(5 | 53 | 67 | 1_231 | 1_260 | 10_013)
        )
}

struct OwnedRegistryKey(*mut std::ffi::c_void);

impl Drop for OwnedRegistryKey {
    fn drop(&mut self) {
        // SAFETY: the handle was returned by a successful registry call and is owned here.
        unsafe { RegCloseKey(self.0) };
    }
}

struct WinsockSession;

impl Drop for WinsockSession {
    fn drop(&mut self) {
        // SAFETY: WinsockSession is created only after WSAStartup succeeds.
        unsafe { WSACleanup() };
    }
}

struct OwnedSocket(SOCKET);

impl Drop for OwnedSocket {
    fn drop(&mut self) {
        // SAFETY: OwnedSocket is created only from a non-INVALID_SOCKET result.
        unsafe { closesocket(self.0) };
    }
}
