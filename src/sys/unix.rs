//! Unix plumbing (Linux/macOS). On Linux you usually don't need samplyd at all if
//! `kernel.perf_event_paranoid <= 1`; it's here so the same client works everywhere and for
//! setups where samply must run as root (e.g. macOS attach without `samply setup`).

use anyhow::{bail, Result};

pub fn is_elevated() -> bool {
    unsafe { libc::geteuid() == 0 }
}

pub fn samply_creation_flags() -> u32 {
    0
}

pub async fn send_ctrl_c(pid: u32) -> Result<()> {
    if unsafe { libc::kill(pid as libc::pid_t, libc::SIGINT) } != 0 {
        bail!("kill(SIGINT) failed: {}", std::io::Error::last_os_error());
    }
    Ok(())
}

pub fn detach_console() {}

pub struct TargetHandle(u32);

impl TargetHandle {
    pub fn open(pid: u32) -> Result<Self> {
        let h = TargetHandle(pid);
        if !h.is_alive() {
            bail!("no process with pid {pid}");
        }
        Ok(h)
    }
    pub fn is_alive(&self) -> bool {
        let r = unsafe { libc::kill(self.0 as libc::pid_t, 0) };
        r == 0 || std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
    }
}

/// Owner uid of a process, used to check that a client only profiles its own processes.
#[cfg(target_os = "linux")]
pub fn pid_owner_uid(pid: u32) -> Option<u32> {
    use std::os::unix::fs::MetadataExt;
    std::fs::metadata(format!("/proc/{pid}"))
        .ok()
        .map(|m| m.uid())
}

#[cfg(target_os = "macos")]
pub fn pid_owner_uid(pid: u32) -> Option<u32> {
    let mut info: libc::proc_bsdinfo = unsafe { std::mem::zeroed() };
    let size = std::mem::size_of::<libc::proc_bsdinfo>() as libc::c_int;
    let n = unsafe {
        libc::proc_pidinfo(
            pid as libc::c_int,
            libc::PROC_PIDTBSDINFO,
            0,
            &mut info as *mut _ as *mut libc::c_void,
            size,
        )
    };
    (n == size).then_some(info.pbi_uid)
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub fn pid_owner_uid(_pid: u32) -> Option<u32> {
    None
}

/// Default allowed client uid: whoever invoked sudo, else ourselves.
pub fn default_allowed_uid() -> u32 {
    std::env::var("SUDO_UID")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or_else(|| unsafe { libc::getuid() })
}

pub fn chown(path: &std::path::Path, uid: u32) {
    use std::os::unix::ffi::OsStrExt;
    if let Ok(c) = std::ffi::CString::new(path.as_os_str().as_bytes()) {
        unsafe { libc::chown(c.as_ptr(), uid, u32::MAX) };
    }
}

// ---------------------------------------------------------------------------------------------
// Client-side launch helpers (record mode)
//
// std's spawn() blocks until exec, so we can't stop the child before exec. Instead wrap it in
// `sh -c 'kill -STOP $$; exec "$@"'`: the shell stops itself, we attach to its pid, then SIGCONT
// and it execs the real program under the same pid.

pub fn wrap_suspended(program: &str, args: &[String]) -> std::process::Command {
    let mut cmd = std::process::Command::new("/bin/sh");
    cmd.arg("-c")
        .arg("kill -STOP $$; exec \"$@\"")
        .arg("sh")
        .arg(program)
        .args(args);
    cmd
}

/// Block until the child has actually stopped itself.
pub fn wait_until_stopped(child: &std::process::Child) -> Result<()> {
    let mut status = 0;
    let r = unsafe { libc::waitpid(child.id() as libc::pid_t, &mut status, libc::WUNTRACED) };
    if r < 0 {
        bail!("waitpid failed: {}", std::io::Error::last_os_error());
    }
    if !libc::WIFSTOPPED(status) {
        bail!("child exited before it could be attached to");
    }
    Ok(())
}

pub fn resume_child(child: &std::process::Child) -> Result<()> {
    if unsafe { libc::kill(child.id() as libc::pid_t, libc::SIGCONT) } != 0 {
        bail!("SIGCONT failed: {}", std::io::Error::last_os_error());
    }
    Ok(())
}
