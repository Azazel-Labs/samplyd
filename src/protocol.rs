//! Wire protocol: newline-delimited JSON. One request line in, one response line out.
//! A connection may send several requests in sequence.
//!
//! Examples (what you'd write to the pipe/socket):
//!   {"cmd":"ping"}
//!   {"cmd":"start","target":{"pid":1234},"rate_hz":4000,"presymbolicate":true}
//!   {"cmd":"start","target":"all","duration_secs":10}
//!   {"cmd":"stop"}
//!   {"cmd":"wait","timeout_secs":60}
//!   {"cmd":"status"}
//!   {"cmd":"clean","keep":20}

use serde::{Deserialize, Serialize};

pub const PROTOCOL_VERSION: u32 = 1;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "cmd", rename_all = "snake_case")]
pub enum Request {
    /// Health check; returns daemon info.
    Ping,
    /// Start a recording. Fails if one is already running (ETW's kernel logger is a singleton).
    Start(StartParams),
    /// Ask samply to stop (Ctrl+C) and wait until the profile is written.
    /// `id` is optional; defaults to the active session.
    Stop { id: Option<u64> },
    /// Wait for a session to finish on its own (duration elapsed / target exited).
    Wait {
        id: Option<u64>,
        timeout_secs: Option<f64>,
    },
    /// Active session + recent history.
    Status,
    /// Recovery: when nothing is recording, force-stop any leftover ETW sessions
    /// (`xperf -stop`, `xperf -stop SamplySession`) left behind by a crashed samply.
    /// No-op on non-Windows.
    Reset,
    /// When idle, delete raw ETW traces (`*.etl`) that samply left in the output directory
    /// (it removes them itself only after a successful conversion) and, with `keep`, every
    /// profile but the newest `keep`.
    Clean {
        #[serde(default)]
        keep: Option<usize>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Target {
    /// Attach to an existing process. On Windows the caller must itself be able to open the
    /// process with PROCESS_QUERY_INFORMATION | PROCESS_VM_READ (unless the daemon was started
    /// with --allow-any-pid).
    Pid(u32),
    /// System-wide recording. Only allowed if the daemon was started with --allow-system-wide.
    All,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StartParams {
    pub target: Target,
    /// Profile name shown in the Firefox Profiler.
    #[serde(default)]
    pub name: Option<String>,
    /// Sampling rate in Hz (samply default 1000).
    #[serde(default)]
    pub rate_hz: Option<f64>,
    /// Stop automatically after this many seconds. Enforced by the daemon, because samply
    /// ignores --duration in attach mode on Windows.
    #[serde(default)]
    pub duration_secs: Option<f64>,
    /// Pass --presymbolicate so a `.syms.json` sidecar is written (handy for tools/AI that
    /// read the profile without the Firefox Profiler UI).
    #[serde(default)]
    pub presymbolicate: bool,
    /// Write `.json.gz` instead of `.json`.
    #[serde(default)]
    pub compress: bool,
    /// Stop automatically when the target pid exits (default true).
    #[serde(default = "default_true")]
    pub stop_on_exit: bool,
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionState {
    Starting,
    Recording,
    Stopping,
    Finished,
    Failed,
}

impl SessionState {
    pub fn is_done(self) -> bool {
        matches!(self, SessionState::Finished | SessionState::Failed)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StopReason {
    Requested,
    Duration,
    TargetExited,
    SamplyExited,
    DaemonShutdown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionInfo {
    pub id: u64,
    pub state: SessionState,
    pub target: Target,
    /// Absolute path of the profile samply writes.
    pub output: String,
    /// Sidecar symbol file, if presymbolicate was requested and it exists.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub syms_output: Option<String>,
    pub started_at_unix: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ended_at_unix: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stop_reason: Option<StopReason>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exit_code: Option<i32>,
    /// Last lines of samply's stdout/stderr, for diagnosing failures.
    pub log_tail: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DaemonInfo {
    pub protocol_version: u32,
    pub daemon_version: String,
    pub samply_path: String,
    pub output_dir: String,
    pub elevated: bool,
    pub allow_system_wide: bool,
    pub allow_any_pid: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Response {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// Non-fatal note (e.g. samply didn't confirm it was recording before the ready timeout).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub warning: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub daemon: Option<DaemonInfo>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session: Option<SessionInfo>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub history: Vec<SessionInfo>,
    /// Files deleted by `clean`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub removed: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub freed_bytes: Option<u64>,
}

impl Response {
    pub fn err(msg: impl Into<String>) -> Self {
        Response {
            ok: false,
            error: Some(msg.into()),
            ..Default::default()
        }
    }
    pub fn session(s: SessionInfo) -> Self {
        Response {
            ok: true,
            session: Some(s),
            ..Default::default()
        }
    }
}
