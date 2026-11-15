//! Windows plumbing: pipe security, client access checks, Ctrl+C delivery, process handles.

use anyhow::{anyhow, bail, Context, Result};
use std::ffi::c_void;
use std::os::windows::process::CommandExt;
use std::time::Duration;
use std::os::windows::fs::OpenOptionsExt;
use std::os::windows::io::IntoRawHandle;
use tokio::net::windows::named_pipe::NamedPipeClient;

const FILE_FLAG_OVERLAPPED: u32 = 0x4000_0000;

use windows_sys::Win32::Foundation::{
    CloseHandle, GetLastError, LocalFree, ERROR_ACCESS_DENIED, ERROR_BAD_IMPERSONATION_LEVEL,
    ERROR_INVALID_PARAMETER, ERROR_PIPE_BUSY, HANDLE, WAIT_TIMEOUT,
};
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};
use windows_sys::Win32::Security::{
    GetTokenInformation, LookupAccountNameW, RevertToSelf, TokenElevation, TokenUser,
    SECURITY_ATTRIBUTES, SID_NAME_USE, TOKEN_ELEVATION, TOKEN_QUERY, TOKEN_USER,
};
use windows_sys::Win32::System::Console::{
    AttachConsole, FreeConsole, GenerateConsoleCtrlEvent, SetConsoleCtrlHandler, CTRL_C_EVENT,
};
use windows_sys::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress};
use windows_sys::Win32::System::Pipes::{GetNamedPipeClientProcessId, ImpersonateNamedPipeClient};
use windows_sys::Win32::System::Threading::{
    GetCurrentProcess, OpenProcess, OpenProcessToken, WaitForSingleObject,
    PROCESS_QUERY_INFORMATION, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SYNCHRONIZE,
    PROCESS_VM_READ,
};

pub const CREATE_SUSPENDED: u32 = 0x0000_0004;
pub const DETACHED_PROCESS: u32 = 0x0000_0008;
pub const CREATE_NO_WINDOW: u32 = 0x0800_0000;
/// SECURITY_SQOS_PRESENT is added by tokio; this is SecurityImpersonation << 16.
const SECURITY_IMPERSONATION: u32 = 0x0002_0000;

/// Pipe rights handed to allowed clients: read/write data + attributes + sync.
/// Deliberately excludes FILE_CREATE_PIPE_INSTANCE (0x4) so clients can't squat server instances.
const PIPE_CLIENT_RIGHTS: &str = "0x120183";

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

unsafe fn from_wide_ptr(p: *const u16) -> String {
    unsafe {
        let mut len = 0;
        while *p.add(len) != 0 {
            len += 1;
        }
        String::from_utf16_lossy(std::slice::from_raw_parts(p, len))
    }
}

fn last_error() -> u32 {
    unsafe { GetLastError() }
}

// ---------------------------------------------------------------------------------------------
// Client connection

pub async fn connect_pipe(name: &str) -> Result<NamedPipeClient> {
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    loop {
        // Ask for exactly the rights the pipe ACL grants clients. tokio's ClientOptions asks for
        // GENERIC_WRITE, which maps to FILE_GENERIC_WRITE and so includes FILE_APPEND_DATA ==
        // FILE_CREATE_PIPE_INSTANCE, the one right the ACL withholds: that open is denied.
        // Impersonation level is required for the daemon's "can you open this pid yourself" check.
        let opened = std::fs::OpenOptions::new()
            .access_mode(u32::from_str_radix(&PIPE_CLIENT_RIGHTS[2..], 16).unwrap())
            .custom_flags(FILE_FLAG_OVERLAPPED)
            .security_qos_flags(SECURITY_IMPERSONATION)
            .open(name);
        match opened {
            // SAFETY: a freshly opened, owned, overlapped pipe handle; we're inside a tokio runtime.
            Ok(f) => return Ok(unsafe { NamedPipeClient::from_raw_handle(f.into_raw_handle())? }),
            Err(e) if e.raw_os_error() == Some(ERROR_PIPE_BUSY as i32) => {
                if std::time::Instant::now() > deadline {
                    bail!("samplyd pipe {name} stayed busy for 10s");
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            Err(e) => {
                return Err(e).with_context(|| {
                    format!("could not connect to samplyd at {name} (is it running? are you in its --allow list?)")
                })
            }
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Token helpers

struct OwnedHandle(HANDLE);
impl Drop for OwnedHandle {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe { CloseHandle(self.0) };
        }
    }
}
unsafe impl Send for OwnedHandle {}
unsafe impl Sync for OwnedHandle {}

fn own_token() -> Result<OwnedHandle> {
    let mut tok: HANDLE = std::ptr::null_mut();
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut tok) } == 0 {
        bail!("OpenProcessToken failed: {}", last_error());
    }
    Ok(OwnedHandle(tok))
}

pub fn is_elevated() -> bool {
    let Ok(tok) = own_token() else { return false };
    let mut elev = TOKEN_ELEVATION { TokenIsElevated: 0 };
    let mut ret = 0u32;
    let ok = unsafe {
        GetTokenInformation(
            tok.0,
            TokenElevation,
            &mut elev as *mut _ as *mut c_void,
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut ret,
        )
    };
    ok != 0 && elev.TokenIsElevated != 0
}

unsafe fn sid_to_string(sid: *mut c_void) -> Result<String> {
    unsafe {
        let mut s: *mut u16 = std::ptr::null_mut();
        if ConvertSidToStringSidW(sid, &mut s) == 0 {
            bail!("ConvertSidToStringSidW failed: {}", last_error());
        }
        let out = from_wide_ptr(s);
        LocalFree(s as *mut c_void);
        Ok(out)
    }
}

/// String SID of the user this process runs as (same SID whether elevated or not).
pub fn current_user_sid() -> Result<String> {
    let tok = own_token()?;
    let mut needed = 0u32;
    unsafe { GetTokenInformation(tok.0, TokenUser, std::ptr::null_mut(), 0, &mut needed) };
    let mut buf = vec![0u8; needed as usize];
    if unsafe {
        GetTokenInformation(
            tok.0,
            TokenUser,
            buf.as_mut_ptr() as *mut c_void,
            needed,
            &mut needed,
        )
    } == 0
    {
        bail!("GetTokenInformation(TokenUser) failed: {}", last_error());
    }
    let tu = unsafe { &*(buf.as_ptr() as *const TOKEN_USER) };
    unsafe { sid_to_string(tu.User.Sid) }
}

/// Accepts a string SID ("S-1-5-21-..."), an SDDL alias ("IU", "BU"...), or an account/group
/// name ("DOMAIN\\user", "Users") and returns something usable inside an SDDL ACE.
pub fn resolve_principal(p: &str) -> Result<String> {
    if p.starts_with("S-1-") || (p.len() == 2 && p.chars().all(|c| c.is_ascii_uppercase())) {
        return Ok(p.to_string());
    }
    let name = wide(p);
    let mut sid_len = 0u32;
    let mut dom_len = 0u32;
    let mut use_: SID_NAME_USE = 0;
    unsafe {
        LookupAccountNameW(
            std::ptr::null(),
            name.as_ptr(),
            std::ptr::null_mut(),
            &mut sid_len,
            std::ptr::null_mut(),
            &mut dom_len,
            &mut use_,
        )
    };
    if sid_len == 0 {
        bail!("unknown account {p:?} (error {})", last_error());
    }
    let mut sid = vec![0u8; sid_len as usize];
    let mut dom = vec![0u16; dom_len as usize];
    if unsafe {
        LookupAccountNameW(
            std::ptr::null(),
            name.as_ptr(),
            sid.as_mut_ptr() as *mut c_void,
            &mut sid_len,
            dom.as_mut_ptr(),
            &mut dom_len,
            &mut use_,
        )
    } == 0
    {
        bail!("LookupAccountNameW({p:?}) failed: {}", last_error());
    }
    unsafe { sid_to_string(sid.as_mut_ptr() as *mut c_void) }
}

// ---------------------------------------------------------------------------------------------
// Pipe security descriptor

pub struct PipeSecurity {
    sa: Box<SECURITY_ATTRIBUTES>,
    pub sddl: String,
}
unsafe impl Send for PipeSecurity {}
unsafe impl Sync for PipeSecurity {}

impl PipeSecurity {
    /// SYSTEM + Administrators get full control; each allowed principal gets read/write only.
    /// Mandatory label = Medium, so normal user processes can write but Low-IL sandboxes can't.
    pub fn new(allowed: &[String]) -> Result<Self> {
        // FA, not GA: generic bits in an explicit ACE are never mapped for a pipe, so GA grants
        // nothing, and the daemon itself could not create the next instance
        // (FILE_CREATE_PIPE_INSTANCE) after the first client connected. OW (owner rights) covers
        // a daemon that runs unelevated and so is neither SYSTEM nor Administrators.
        let mut sddl = String::from("D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;OW)");
        for a in allowed {
            sddl.push_str(&format!("(A;;{PIPE_CLIENT_RIGHTS};;;{a})"));
        }
        sddl.push_str("S:(ML;;NW;;;ME)");
        let w = wide(&sddl);
        let mut psd: *mut c_void = std::ptr::null_mut();
        if unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                w.as_ptr(),
                SDDL_REVISION_1,
                &mut psd,
                std::ptr::null_mut(),
            )
        } == 0
        {
            bail!("invalid pipe SDDL {sddl:?}: error {}", last_error());
        }
        let sa = Box::new(SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: psd, // intentionally leaked; lives for the daemon's lifetime
            bInheritHandle: 0,
        });
        Ok(PipeSecurity { sa, sddl })
    }

    pub fn as_ptr(&self) -> *mut c_void {
        &*self.sa as *const SECURITY_ATTRIBUTES as *mut c_void
    }
}

// ---------------------------------------------------------------------------------------------
// Per-request client checks

pub fn pipe_client_pid(pipe: isize) -> Option<u32> {
    let mut pid = 0u32;
    (unsafe { GetNamedPipeClientProcessId(pipe as HANDLE, &mut pid) } != 0).then_some(pid)
}

/// Impersonate the pipe client and check that *it* could open `pid` for profiling-type access
/// (PROCESS_QUERY_INFORMATION | PROCESS_VM_READ). This stops a normal-integrity caller from
/// using the elevated daemon to profile elevated or other users' processes.
pub fn client_can_open_process(pipe: isize, pid: u32) -> Result<()> {
    unsafe {
        if ImpersonateNamedPipeClient(pipe as HANDLE) == 0 {
            bail!("ImpersonateNamedPipeClient failed: {}", last_error());
        }
        let h = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, 0, pid);
        let err = last_error();
        if RevertToSelf() == 0 {
            // Continuing to run as the client would be a security bug; bail out hard.
            eprintln!("samplyd: RevertToSelf failed ({}); aborting", last_error());
            std::process::abort();
        }
        if h.is_null() {
            return Err(match err {
                ERROR_ACCESS_DENIED => anyhow!(
                    "access denied: the calling process may not open pid {pid} itself \
                     (elevated or another user's process?). Start samplyd with --allow-any-pid to permit this."
                ),
                ERROR_INVALID_PARAMETER => anyhow!("no process with pid {pid}"),
                ERROR_BAD_IMPERSONATION_LEVEL => anyhow!(
                    "client connected with Identification-level impersonation; open the pipe with \
                     SECURITY_IMPERSONATION (the default for CreateFile without SECURITY_SQOS_PRESENT)"
                ),
                e => anyhow!("OpenProcess({pid}) as client failed: error {e}"),
            });
        }
        CloseHandle(h);
    }
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// Target process liveness (held handle => immune to pid reuse)

pub struct TargetHandle(OwnedHandle);

impl TargetHandle {
    pub fn open(pid: u32) -> Result<Self> {
        let h = unsafe {
            OpenProcess(
                PROCESS_SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION,
                0,
                pid,
            )
        };
        if h.is_null() {
            match last_error() {
                ERROR_INVALID_PARAMETER => bail!("no process with pid {pid}"),
                e => bail!("OpenProcess({pid}) failed: error {e}"),
            }
        }
        Ok(TargetHandle(OwnedHandle(h)))
    }
    pub fn is_alive(&self) -> bool {
        unsafe { WaitForSingleObject(self.0 .0, 0) == WAIT_TIMEOUT }
    }
}

// ---------------------------------------------------------------------------------------------
// Ctrl+C delivery
//
// samply only stops attach/system-wide recordings on Ctrl+C. We start samply with
// CREATE_NO_WINDOW (its own hidden console). To signal it, we run a tiny helper (this same exe
// with `__ctrl-c <pid>`) that detaches from any console, attaches to samply's console, ignores
// Ctrl+C itself and broadcasts CTRL_C_EVENT to that console.

pub fn samply_creation_flags() -> u32 {
    CREATE_NO_WINDOW
}

pub async fn send_ctrl_c(pid: u32) -> Result<()> {
    let exe = std::env::current_exe()?;
    let status = tokio::process::Command::new(exe)
        .arg("__ctrl-c")
        .arg(pid.to_string())
        .creation_flags(DETACHED_PROCESS)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .await
        .context("failed to spawn ctrl-c helper")?;
    if !status.success() {
        bail!("ctrl-c helper failed with {status} (2=AttachConsole, 3=GenerateConsoleCtrlEvent)");
    }
    Ok(())
}

/// Entry point for the `__ctrl-c <pid>` helper mode. Returns the process exit code.
pub fn ctrl_c_helper_main(pid: u32) -> i32 {
    unsafe {
        FreeConsole();
        if AttachConsole(pid) == 0 {
            return 2;
        }
        SetConsoleCtrlHandler(None, 1); // ignore it ourselves
        if GenerateConsoleCtrlEvent(CTRL_C_EVENT, 0) == 0 {
            return 3;
        }
        // Give the console a moment to dispatch before we detach and exit.
        std::thread::sleep(Duration::from_millis(200));
        FreeConsole();
    }
    0
}

pub fn detach_console() {
    unsafe { FreeConsole() };
}

// ---------------------------------------------------------------------------------------------
// Client-side launch helpers (record mode)

pub fn configure_suspended(cmd: &mut std::process::Command) {
    cmd.creation_flags(CREATE_SUSPENDED);
}

/// Resume a process created with CREATE_SUSPENDED (std doesn't expose the main thread handle,
/// so use ntdll!NtResumeProcess on the process handle).
pub fn resume_child(child: &std::process::Child) -> Result<()> {
    use std::os::windows::io::AsRawHandle;
    type NtResumeProcess = unsafe extern "system" fn(HANDLE) -> i32;
    unsafe {
        let ntdll = GetModuleHandleA(b"ntdll.dll\0".as_ptr());
        if ntdll.is_null() {
            bail!("ntdll not loaded?");
        }
        let f = GetProcAddress(ntdll, b"NtResumeProcess\0".as_ptr())
            .ok_or_else(|| anyhow!("NtResumeProcess not found"))?;
        let f: NtResumeProcess = std::mem::transmute(f);
        let st = f(child.as_raw_handle() as HANDLE);
        if st < 0 {
            bail!("NtResumeProcess failed: NTSTATUS {st:#x}");
        }
    }
    Ok(())
}

/// Locate xperf.exe the same way samply does.
pub fn find_xperf() -> Option<std::path::PathBuf> {
    crate::which("xperf").or_else(|| {
        let pf = std::env::var("ProgramFiles(x86)").ok()?;
        let p = std::path::PathBuf::from(pf)
            .join("Windows Kits/10/Windows Performance Toolkit/xperf.exe");
        p.exists().then_some(p)
    })
}
