//! samplyd: runs elevated once, keeps samply ready, and takes structured commands from
//! unprivileged clients over a named pipe (Windows) or Unix socket.
//!
//! Security model (see README): clients never pass raw samply arguments or output paths.
//! They can only attach to a pid they could open themselves (or system-wide if the operator
//! allowed it). samply never launches programs on a client's behalf, so the daemon can't be
//! used to run arbitrary code elevated.

use anyhow::{bail, Context, Result};
use clap::{Args, Parser, Subcommand};
use samplyd::protocol::*;
use samplyd::{now_unix, sys};
use std::collections::VecDeque;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, SystemTime};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::process::{Child, Command};
use tokio::sync::{oneshot, watch, Notify};
use tokio::time::{interval, sleep_until, timeout, Instant};

const LOG_TAIL_LINES: usize = 80;

#[derive(Parser)]
#[command(
    name = "samplyd",
    version,
    about = "Elevated samply broker for unprivileged clients"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Run the daemon in the foreground (run this elevated).
    Serve(ServeArgs),
    /// Register a logon-time Scheduled Task that runs `samplyd serve` with highest privileges,
    /// then start it. Run once from an elevated terminal; no UAC prompts after that.
    #[cfg(windows)]
    InstallTask(ServeArgs),
    /// Remove the Scheduled Task.
    #[cfg(windows)]
    UninstallTask,
    #[command(name = "__ctrl-c", hide = true)]
    CtrlC { pid: u32 },
}

#[derive(Args, Clone, Debug)]
struct ServeArgs {
    /// Pipe name / socket path. Default: \\.\pipe\samplyd or /tmp/samplyd.sock
    #[arg(long)]
    endpoint: Option<String>,
    /// Path to samply. Default: `samply` on PATH.
    #[arg(long)]
    samply: Option<PathBuf>,
    /// Where profiles are written. Default: %LOCALAPPDATA%\samplyd\profiles or /tmp/samplyd-profiles
    #[arg(long)]
    output_dir: Option<PathBuf>,
    /// Who may connect. Windows: SID, SDDL alias (IU, BU, AU…) or account/group name; default is
    /// the user running the daemon. Unix: numeric uid; default is $SUDO_UID or the current uid.
    /// Repeatable.
    #[arg(long)]
    allow: Vec<String>,
    /// Allow clients to request system-wide (`-a`) recordings.
    #[arg(long)]
    allow_system_wide: bool,
    /// Skip the "client must be able to open the target pid itself" check.
    #[arg(long)]
    allow_any_pid: bool,
    /// Extra argument passed to every `samply record` (operator-controlled, e.g.
    /// --samply-arg=--windows-symbol-server=https://msdl.microsoft.com/download/symbols). Repeatable.
    #[arg(long, allow_hyphen_values = true)]
    samply_arg: Vec<String>,
    /// How long to wait for samply to finish writing after Ctrl+C before killing it.
    #[arg(long, default_value_t = 600)]
    stop_timeout_secs: u64,
    /// How long to wait for samply to report it is recording.
    #[arg(long, default_value_t = 30)]
    ready_timeout_secs: u64,
    /// Number of finished sessions kept in `status`.
    #[arg(long, default_value_t = 20)]
    history: usize,
    /// Detach from the console and log to --log-file (used by install-task).
    #[arg(long)]
    background: bool,
    /// Log file (default: stderr; with --background: <data dir>/samplyd.log).
    #[arg(long)]
    log_file: Option<PathBuf>,
}

impl ServeArgs {
    /// Re-serialize for the scheduled task command line.
    #[allow(dead_code)]
    fn to_args(&self) -> Vec<String> {
        let mut v = vec!["serve".to_string(), "--background".to_string()];
        let mut kv = |k: &str, val: String| {
            v.push(format!("--{k}={val}"));
        };
        if let Some(e) = &self.endpoint {
            kv("endpoint", e.clone());
        }
        if let Some(s) = &self.samply {
            kv("samply", s.display().to_string());
        }
        if let Some(o) = &self.output_dir {
            kv("output-dir", o.display().to_string());
        }
        for a in &self.allow {
            kv("allow", a.clone());
        }
        for a in &self.samply_arg {
            kv("samply-arg", a.clone());
        }
        kv("stop-timeout-secs", self.stop_timeout_secs.to_string());
        kv("ready-timeout-secs", self.ready_timeout_secs.to_string());
        kv("history", self.history.to_string());
        if let Some(l) = &self.log_file {
            kv("log-file", l.display().to_string());
        }
        if self.allow_system_wide {
            v.push("--allow-system-wide".into());
        }
        if self.allow_any_pid {
            v.push("--allow-any-pid".into());
        }
        v
    }
}

// ---------------------------------------------------------------------------------------------
// Logging

static LOG: OnceLock<Mutex<Box<dyn Write + Send>>> = OnceLock::new();

macro_rules! log {
    ($($t:tt)*) => {{
        let msg = format!($($t)*);
        if let Some(l) = LOG.get() {
            let mut l = l.lock().unwrap();
            let _ = writeln!(l, "[{:.3}] {}", now_unix(), msg);
            let _ = l.flush();
        } else {
            eprintln!("{msg}");
        }
    }};
}

fn data_dir() -> PathBuf {
    #[cfg(windows)]
    {
        std::env::var_os("LOCALAPPDATA")
            .map(PathBuf::from)
            .unwrap_or_else(std::env::temp_dir)
            .join("samplyd")
    }
    #[cfg(unix)]
    {
        PathBuf::from("/tmp/samplyd")
    }
}

// ---------------------------------------------------------------------------------------------
// Config & shared state

struct Config {
    endpoint: String,
    samply: PathBuf,
    output_dir: PathBuf,
    allow: Vec<String>,
    allow_system_wide: bool,
    allow_any_pid: bool,
    samply_args: Vec<String>,
    stop_timeout: Duration,
    ready_timeout: Duration,
    history: usize,
    /// `--presymbolicate`, or `--unstable-presymbolicate` on samply <= 0.13.
    presym_flag: &'static str,
}

/// samply 0.13 only has `--unstable-presymbolicate`; later releases renamed it.
fn presym_flag(samply: &Path) -> &'static str {
    let help = std::process::Command::new(samply)
        .args(["record", "--help"])
        .stdin(Stdio::null())
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
        .unwrap_or_default();
    if help.contains("--unstable-presymbolicate") && !help.contains(" --presymbolicate") {
        "--unstable-presymbolicate"
    } else {
        "--presymbolicate"
    }
}

impl Config {
    fn resolve(a: &ServeArgs) -> Result<Self> {
        let samply = match &a.samply {
            Some(p) => p.clone(),
            None => samplyd::which("samply")
                .context("samply not found on PATH; pass --samply <path>")?,
        };
        if !samply.exists() {
            bail!("samply not found at {}", samply.display());
        }
        let output_dir = a.output_dir.clone().unwrap_or_else(|| {
            if cfg!(windows) {
                data_dir().join("profiles")
            } else {
                PathBuf::from("/tmp/samplyd-profiles")
            }
        });
        std::fs::create_dir_all(&output_dir)
            .with_context(|| format!("creating {}", output_dir.display()))?;
        let output_dir = std::fs::canonicalize(&output_dir)?;
        let samply = std::fs::canonicalize(&samply).unwrap_or(samply);
        Ok(Config {
            presym_flag: presym_flag(&samply),
            endpoint: a.endpoint.clone().unwrap_or_else(samplyd::default_endpoint),
            samply,
            output_dir,
            allow: a.allow.clone(),
            allow_system_wide: a.allow_system_wide,
            allow_any_pid: a.allow_any_pid,
            samply_args: a.samply_arg.clone(),
            stop_timeout: Duration::from_secs(a.stop_timeout_secs),
            ready_timeout: Duration::from_secs(a.ready_timeout_secs),
            history: a.history.max(1),
        })
    }
}

struct ActiveSession {
    id: u64,
    rx: watch::Receiver<SessionInfo>,
    stop: Arc<Notify>,
}

#[derive(Default)]
struct Inner {
    active: Option<ActiveSession>,
    history: VecDeque<SessionInfo>,
    /// `clean` is deleting files and may stop ETW sessions; no recording may start meanwhile.
    cleaning: bool,
}

struct Shared {
    cfg: Config,
    next_id: AtomicU64,
    inner: Mutex<Inner>,
}

enum Lookup {
    Active(watch::Receiver<SessionInfo>, Arc<Notify>),
    Done(SessionInfo),
    NotFound,
}

impl Shared {
    fn info(&self) -> DaemonInfo {
        DaemonInfo {
            protocol_version: PROTOCOL_VERSION,
            daemon_version: env!("CARGO_PKG_VERSION").to_string(),
            samply_path: self.cfg.samply.display().to_string(),
            output_dir: self.cfg.output_dir.display().to_string(),
            elevated: sys::is_elevated(),
            allow_system_wide: self.cfg.allow_system_wide,
            allow_any_pid: self.cfg.allow_any_pid,
        }
    }

    fn find(&self, id: Option<u64>) -> Lookup {
        let inner = self.inner.lock().unwrap();
        if let Some(a) = &inner.active {
            if id.is_none() || id == Some(a.id) {
                return Lookup::Active(a.rx.clone(), a.stop.clone());
            }
        }
        let found = match id {
            Some(id) => inner.history.iter().find(|s| s.id == id),
            None => inner.history.back(),
        };
        found.cloned().map(Lookup::Done).unwrap_or(Lookup::NotFound)
    }
}

// ---------------------------------------------------------------------------------------------
// Peer identity

struct Peer {
    desc: String,
    #[cfg(windows)]
    pipe: isize,
    #[cfg(unix)]
    uid: u32,
}

impl Peer {
    fn check_pid(&self, pid: u32) -> Result<()> {
        #[cfg(windows)]
        {
            sys::client_can_open_process(self.pipe, pid)
        }
        #[cfg(unix)]
        {
            if self.uid == 0 {
                return Ok(());
            }
            match sys::pid_owner_uid(pid) {
                Some(owner) if owner == self.uid => Ok(()),
                Some(owner) => bail!(
                    "pid {pid} belongs to uid {owner}, you are uid {}; start samplyd with --allow-any-pid to permit this",
                    self.uid
                ),
                None => bail!("no process with pid {pid} (or its owner could not be determined)"),
            }
        }
    }

    fn owner_uid(&self) -> Option<u32> {
        #[cfg(unix)]
        {
            Some(self.uid)
        }
        #[cfg(windows)]
        {
            None
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Request handling

async fn handle_conn<S: AsyncRead + AsyncWrite + Unpin>(
    shared: Arc<Shared>,
    stream: S,
    peer: Peer,
) {
    let (r, mut w) = tokio::io::split(stream);
    let mut r = BufReader::new(r);
    let mut buf = Vec::new();
    loop {
        buf.clear();
        match r.read_until(b'\n', &mut buf).await {
            Ok(0) | Err(_) => break,
            Ok(_) => {}
        }
        let line = String::from_utf8_lossy(&buf);
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let resp = match serde_json::from_str::<Request>(line) {
            Ok(req) => {
                log!("{}: {}", peer.desc, line);
                dispatch(&shared, req, &peer).await
            }
            Err(e) => Response::err(format!("bad request: {e}")),
        };
        let mut out = serde_json::to_string(&resp).unwrap_or_else(|_| "{\"ok\":false}".into());
        out.push('\n');
        if w.write_all(out.as_bytes()).await.is_err() || w.flush().await.is_err() {
            break;
        }
    }
}

async fn dispatch(shared: &Arc<Shared>, req: Request, peer: &Peer) -> Response {
    let res = match req {
        Request::Ping => Ok(Response {
            ok: true,
            daemon: Some(shared.info()),
            ..Default::default()
        }),
        Request::Status => {
            let inner = shared.inner.lock().unwrap();
            Ok(Response {
                ok: true,
                session: inner.active.as_ref().map(|a| a.rx.borrow().clone()),
                history: inner.history.iter().cloned().collect(),
                ..Default::default()
            })
        }
        Request::Start(p) => start(shared, p, peer).await,
        Request::Stop { id } => stop_or_wait(shared, id, true, None).await,
        Request::Wait { id, timeout_secs } => {
            stop_or_wait(shared, id, false, timeout_secs.map(Duration::from_secs_f64)).await
        }
        Request::Reset => reset(shared).await,
        Request::Clean { keep } => clean(shared, keep).await,
    };
    res.unwrap_or_else(|e| Response::err(format!("{e:#}")))
}

async fn start(shared: &Arc<Shared>, p: StartParams, peer: &Peer) -> Result<Response> {
    let cfg = &shared.cfg;
    if let Some(r) = p.rate_hz {
        if !(r > 0.0 && r.is_finite()) {
            bail!("rate_hz must be > 0");
        }
    }
    if let Some(d) = p.duration_secs {
        if !(d > 0.0 && d.is_finite()) {
            bail!("duration_secs must be > 0");
        }
    }
    let target_handle = match p.target {
        Target::Pid(pid) => {
            if !cfg.allow_any_pid {
                peer.check_pid(pid)?;
            }
            Some(sys::TargetHandle::open(pid)?)
        }
        Target::All => {
            if !cfg.allow_system_wide {
                bail!("system-wide recording is disabled; start samplyd with --allow-system-wide");
            }
            None
        }
    };

    let (child, tx, mut rx, stop) = {
        let mut inner = shared.inner.lock().unwrap();
        if inner.cleaning {
            bail!("busy: cleaning the output directory; try again shortly");
        }
        if let Some(a) = &inner.active {
            let st = a.rx.borrow().state;
            bail!(
                "busy: session {} is {:?}; stop it first (only one ETW kernel session can run)",
                a.id,
                st
            );
        }
        let id = shared.next_id.fetch_add(1, Ordering::SeqCst) + 1;
        let tag = match p.target {
            Target::Pid(pid) => format!("pid{pid}"),
            Target::All => "all".into(),
        };
        let ext = if p.compress { "json.gz" } else { "json" };
        let output = cfg
            .output_dir
            .join(format!("samply-{}-{id}-{tag}.{ext}", now_unix() as u64));

        let mut cmd = Command::new(&cfg.samply);
        cmd.arg("record")
            .arg("--save-only")
            .arg(format!("--output={}", output.display()));
        if let Some(r) = p.rate_hz {
            cmd.arg(format!("--rate={r}"));
        }
        if let Some(n) = &p.name {
            cmd.arg(format!("--profile-name={n}"));
        }
        if p.presymbolicate {
            cmd.arg(cfg.presym_flag);
        }
        cmd.args(&cfg.samply_args);
        match p.target {
            Target::Pid(pid) => {
                cmd.arg(format!("--pid={pid}"));
            }
            Target::All => {
                cmd.arg("--all");
            }
        }
        cmd.stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        #[cfg(windows)]
        cmd.creation_flags(sys::samply_creation_flags());
        #[cfg(unix)]
        let _ = sys::samply_creation_flags();

        let child = cmd
            .spawn()
            .with_context(|| format!("failed to launch {}", cfg.samply.display()))?;
        log!(
            "session {id}: launched samply pid {:?} -> {}",
            child.id(),
            output.display()
        );

        let info = SessionInfo {
            id,
            state: SessionState::Starting,
            target: p.target.clone(),
            output: output.display().to_string(),
            syms_output: None,
            started_at_unix: now_unix(),
            ended_at_unix: None,
            stop_reason: None,
            exit_code: None,
            log_tail: Vec::new(),
        };
        let (tx, rx) = watch::channel(info);
        let stop = Arc::new(Notify::new());
        inner.active = Some(ActiveSession {
            id,
            rx: rx.clone(),
            stop: stop.clone(),
        });
        (child, tx, rx, stop)
    };

    tokio::spawn(run_session(
        shared.clone(),
        child,
        tx,
        stop,
        p,
        target_handle,
        peer.owner_uid(),
    ));

    let ready = timeout(
        cfg.ready_timeout,
        rx.wait_for(|s| s.state != SessionState::Starting),
    )
    .await
    .is_ok();
    let snap = rx.borrow().clone();
    Ok(match snap.state {
        s if s.is_done() => finished_response(snap),
        SessionState::Starting => Response {
            ok: true,
            warning: Some(format!(
                "samply did not report it was recording within {:?} (ready={})",
                cfg.ready_timeout, ready
            )),
            session: Some(snap),
            ..Default::default()
        },
        _ => Response::session(snap),
    })
}

type Log = Arc<Mutex<VecDeque<String>>>;

fn spawn_reader<R: AsyncRead + Unpin + Send + 'static>(
    r: R,
    log: Log,
    ready: Arc<Mutex<Option<oneshot::Sender<()>>>>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut r = BufReader::new(r);
        let mut buf = Vec::new();
        loop {
            buf.clear();
            match r.read_until(b'\n', &mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(_) => {}
            }
            let line = String::from_utf8_lossy(&buf).trim_end().to_string();
            let low = line.to_ascii_lowercase();
            // samply prints "Press Ctrl+C to stop." (Windows), "... until Ctrl+C..." (Linux),
            // "press Ctrl-C to stop" (macOS) once the recorder is live.
            if low.contains("ctrl+c") || low.contains("ctrl-c") {
                if let Some(s) = ready.lock().unwrap().take() {
                    let _ = s.send(());
                }
            }
            let mut l = log.lock().unwrap();
            if l.len() >= LOG_TAIL_LINES {
                l.pop_front();
            }
            l.push_back(line);
        }
    })
}

enum Outcome {
    Exited(std::io::Result<std::process::ExitStatus>),
    Stop,
}

async fn run_session(
    shared: Arc<Shared>,
    mut child: Child,
    tx: watch::Sender<SessionInfo>,
    stop: Arc<Notify>,
    p: StartParams,
    target: Option<sys::TargetHandle>,
    owner_uid: Option<u32>,
) {
    let cfg = &shared.cfg;
    let id = tx.borrow().id;
    let log: Log = Arc::new(Mutex::new(VecDeque::new()));
    let (ready_tx, ready_rx) = oneshot::channel();
    let ready_tx = Arc::new(Mutex::new(Some(ready_tx)));
    let mut readers = Vec::new();
    if let Some(o) = child.stdout.take() {
        readers.push(spawn_reader(o, log.clone(), ready_tx.clone()));
    }
    if let Some(e) = child.stderr.take() {
        readers.push(spawn_reader(e, log.clone(), ready_tx.clone()));
    }
    drop(ready_tx);

    let sync_log = |tx: &watch::Sender<SessionInfo>| {
        let tail: Vec<String> = log.lock().unwrap().iter().cloned().collect();
        tx.send_if_modified(|s| {
            if s.log_tail != tail {
                s.log_tail = tail;
                true
            } else {
                false
            }
        });
    };

    let spawned = Instant::now();
    let mut ready = false;
    let mut ready_rx = Some(ready_rx);
    let mut deadline: Option<Instant> = None;
    let mut pending: Option<StopReason> = None;
    let mut tick = interval(Duration::from_millis(250));

    let outcome = loop {
        tokio::select! {
            st = child.wait() => break Outcome::Exited(st),
            r = async { ready_rx.as_mut().unwrap().await }, if ready_rx.is_some() => {
                ready_rx = None;
                if r.is_ok() {
                    ready = true;
                    deadline = p.duration_secs.map(|d| Instant::now() + Duration::from_secs_f64(d));
                    tx.send_modify(|s| s.state = SessionState::Recording);
                    log!("session {id}: recording");
                    if pending.is_some() { break Outcome::Stop; }
                }
            }
            _ = stop.notified() => {
                pending.get_or_insert(StopReason::Requested);
                if ready { break Outcome::Stop; }
            }
            _ = async { sleep_until(deadline.unwrap()).await }, if deadline.is_some() => {
                pending = Some(StopReason::Duration);
                break Outcome::Stop;
            }
            _ = tick.tick() => {
                sync_log(&tx);
                if p.stop_on_exit {
                    if let Some(t) = &target {
                        if !t.is_alive() {
                            pending.get_or_insert(StopReason::TargetExited);
                            if ready { break Outcome::Stop; }
                        }
                    }
                }
                // Stop requested but samply never confirmed it was live: don't wait forever.
                if pending.is_some() && !ready && spawned.elapsed() > cfg.ready_timeout {
                    break Outcome::Stop;
                }
            }
        }
    };

    let (status, reason) = match outcome {
        Outcome::Exited(st) => (st, pending.unwrap_or(StopReason::SamplyExited)),
        Outcome::Stop => {
            let reason = pending.unwrap_or(StopReason::Requested);
            tx.send_modify(|s| s.state = SessionState::Stopping);
            log!("session {id}: stopping ({reason:?})");
            if let Some(pid) = child.id() {
                if let Err(e) = sys::send_ctrl_c(pid).await {
                    log!("session {id}: ctrl-c failed: {e:#}");
                }
            }
            match timeout(cfg.stop_timeout, child.wait()).await {
                Ok(st) => (st, reason),
                Err(_) => {
                    log!(
                        "session {id}: samply didn't exit within {:?}; killing",
                        cfg.stop_timeout
                    );
                    let _ = child.kill().await;
                    (child.wait().await, reason)
                }
            }
        }
    };

    for r in readers {
        let _ = timeout(Duration::from_secs(2), r).await;
    }
    sync_log(&tx);

    let exit_code = status.as_ref().ok().and_then(|s| s.code());
    let success = status.as_ref().map(|s| s.success()).unwrap_or(false);
    let output = PathBuf::from(&tx.borrow().output);
    let exists = output.exists();
    let syms = companion(&output, "syms.json");
    let syms_exists = syms.exists();
    if let Some(uid) = owner_uid {
        #[cfg(unix)]
        {
            for f in [&output, &syms] {
                if f.exists() {
                    sys::chown(f, uid);
                }
            }
        }
        let _ = uid;
    }

    tx.send_modify(|s| {
        s.state = if success && exists {
            SessionState::Finished
        } else {
            SessionState::Failed
        };
        s.ended_at_unix = Some(now_unix());
        s.stop_reason = Some(reason);
        s.exit_code = exit_code;
        s.syms_output = syms_exists.then(|| syms.display().to_string());
    });
    let fin = tx.borrow().clone();
    log!(
        "session {id}: {:?} exit={:?} output_exists={exists}",
        fin.state,
        exit_code
    );
    // A samply that was killed or failed leaves its raw trace behind, and a leaked ETW session
    // may still be writing to it. Clean up while this session still blocks new recordings.
    let leftovers = output
        .file_name()
        .and_then(|n| n.to_str())
        .and_then(|n| n.split('.').next())
        .map(|stem| leftover_traces(&cfg.output_dir, Some(stem)))
        .unwrap_or_default();
    if !leftovers.is_empty() {
        let (removed, freed) = remove_traces(leftovers, true).await;
        log!("session {id}: removed {} leftover trace(s), {freed} bytes", removed.len());
    }
    {
        let mut inner = shared.inner.lock().unwrap();
        if inner.active.as_ref().map(|a| a.id) == Some(id) {
            inner.active = None;
        }
        inner.history.push_back(fin);
        while inner.history.len() > cfg.history {
            inner.history.pop_front();
        }
    }
}

fn companion(profile: &Path, ext: &str) -> PathBuf {
    // samply 0.13 writes `x.json.gz` -> `x.json.syms.json` (appends to the name without `.gz`);
    // also accept `x.syms.json` in case another version replaces the extension instead.
    let mut p = profile.to_owned();
    if p.extension() == Some(std::ffi::OsStr::new("gz")) {
        p.set_extension("");
    }
    let mut appended = p.clone().into_os_string();
    appended.push(format!(".{ext}"));
    let appended = PathBuf::from(appended);
    p.set_extension(ext);
    if appended.exists() || !p.exists() {
        appended
    } else {
        p
    }
}

async fn stop_or_wait(
    shared: &Arc<Shared>,
    id: Option<u64>,
    stop: bool,
    wait_timeout: Option<Duration>,
) -> Result<Response> {
    let (mut rx, notify) = match shared.find(id) {
        Lookup::NotFound => bail!(match id {
            Some(id) => format!("no session {id}"),
            None => "no sessions yet".into(),
        }),
        Lookup::Done(info) => return Ok(finished_response(info)),
        Lookup::Active(rx, n) => (rx, n),
    };
    let limit = if stop {
        notify.notify_one();
        Some(shared.cfg.stop_timeout + shared.cfg.ready_timeout + Duration::from_secs(30))
    } else {
        wait_timeout
    };
    let waited = match limit {
        Some(l) => timeout(l, rx.wait_for(|s| s.state.is_done())).await.is_ok(),
        None => rx.wait_for(|s| s.state.is_done()).await.is_ok(),
    };
    let snap = rx.borrow().clone();
    if !waited || !snap.state.is_done() {
        return Ok(Response {
            ok: false,
            error: Some("timed out waiting for the session to finish".into()),
            session: Some(snap),
            ..Default::default()
        });
    }
    Ok(finished_response(snap))
}

fn finished_response(info: SessionInfo) -> Response {
    if info.state == SessionState::Failed {
        Response {
            ok: false,
            error: Some("samply did not produce a profile; see session.log_tail".into()),
            session: Some(info),
            ..Default::default()
        }
    } else {
        Response::session(info)
    }
}

async fn reset(shared: &Arc<Shared>) -> Result<Response> {
    if shared.inner.lock().unwrap().active.is_some() {
        bail!("a session is active; stop it first");
    }
    let notes = stop_etw_sessions().await?;
    Ok(Response {
        ok: true,
        warning: (!notes.is_empty()).then(|| notes.join(" | ")),
        ..Default::default()
    })
}

/// `xperf -stop` and `xperf -stop SamplySession`: end ETW sessions a crashed samply leaked.
async fn stop_etw_sessions() -> Result<Vec<String>> {
    #[cfg(windows)]
    {
        let xperf = sys::find_xperf().context("xperf.exe not found")?;
        let mut notes = Vec::new();
        for args in [vec!["-stop"], vec!["-stop", "SamplySession"]] {
            let out = Command::new(&xperf).args(&args).output().await?;
            notes.push(format!(
                "xperf {}: {} {}",
                args.join(" "),
                String::from_utf8_lossy(&out.stdout).trim(),
                String::from_utf8_lossy(&out.stderr).trim()
            ));
        }
        Ok(notes)
    }
    #[cfg(unix)]
    Ok(Vec::new())
}

/// Files samply wrote in `dir`, with their session stem: `samply-<time>-<id>-<target>.<ext>`.
fn samply_files(dir: &Path) -> Vec<(PathBuf, String)> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    entries
        .flatten()
        .filter(|e| e.file_type().is_ok_and(|t| t.is_file()))
        .filter_map(|e| {
            let name = e.file_name().into_string().ok()?;
            let stem = name.split('.').next()?.to_string();
            (name.starts_with("samply-") && stem.len() < name.len()).then(|| (e.path(), stem))
        })
        .collect()
}

fn is_trace(path: &Path) -> bool {
    path.extension().is_some_and(|e| e.eq_ignore_ascii_case("etl"))
}

/// Raw ETW traces (`*.etl`) in `dir`: all of them, or only those of the session `stem`.
fn leftover_traces(dir: &Path, stem: Option<&str>) -> Vec<PathBuf> {
    samply_files(dir)
        .into_iter()
        .filter(|(path, s)| is_trace(path) && stem.map_or(true, |stem| stem == s))
        .map(|(path, _)| path)
        .collect()
}

/// Delete `files`, returning what was removed and the bytes freed. A trace that is still open
/// is usually held by an ETW session a killed samply leaked; with `stop_etw`, stop leftover ETW
/// sessions and try once more.
async fn remove_traces(files: Vec<PathBuf>, stop_etw: bool) -> (Vec<String>, u64) {
    let mut removed = Vec::new();
    let mut freed = 0;
    let mut failed = remove_files(files, &mut removed, &mut freed);
    if stop_etw && failed.iter().any(|f| is_trace(f)) {
        match stop_etw_sessions().await {
            Ok(notes) => log!("stopped leftover ETW sessions: {}", notes.join(" | ")),
            Err(e) => log!("could not stop leftover ETW sessions: {e:#}"),
        }
        failed = remove_files(failed, &mut removed, &mut freed);
    }
    for f in failed {
        log!("could not remove {}", f.display());
    }
    (removed, freed)
}

/// Delete `files`, returning those that could not be deleted.
fn remove_files(files: Vec<PathBuf>, removed: &mut Vec<String>, freed: &mut u64) -> Vec<PathBuf> {
    let mut failed = Vec::new();
    for f in files {
        let len = std::fs::metadata(&f).map(|m| m.len()).unwrap_or(0);
        match std::fs::remove_file(&f) {
            Ok(()) => {
                *freed += len;
                removed.push(f.display().to_string());
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => failed.push(f),
        }
    }
    failed
}

async fn clean(shared: &Arc<Shared>, keep: Option<usize>) -> Result<Response> {
    {
        let mut inner = shared.inner.lock().unwrap();
        if inner.active.is_some() {
            bail!("a session is active; stop it first");
        }
        if inner.cleaning {
            bail!("already cleaning");
        }
        inner.cleaning = true;
    }
    struct Cleaning<'a>(&'a Shared);
    impl Drop for Cleaning<'_> {
        fn drop(&mut self) {
            self.0.inner.lock().unwrap().cleaning = false;
        }
    }
    let _cleaning = Cleaning(shared.as_ref());

    let dir = &shared.cfg.output_dir;
    let mut files = leftover_traces(dir, None);
    if let Some(keep) = keep {
        // Sessions newest first, by the latest write among each session's files.
        let mut sessions: Vec<(String, SystemTime, Vec<PathBuf>)> = Vec::new();
        for (path, stem) in samply_files(dir) {
            if is_trace(&path) {
                continue;
            }
            let time = std::fs::metadata(&path)
                .and_then(|m| m.modified())
                .unwrap_or(SystemTime::UNIX_EPOCH);
            match sessions.iter_mut().find(|(s, ..)| *s == stem) {
                Some((_, t, paths)) => {
                    *t = (*t).max(time);
                    paths.push(path);
                }
                None => sessions.push((stem, time, vec![path])),
            }
        }
        sessions.sort_by(|a, b| b.1.cmp(&a.1));
        files.extend(sessions.into_iter().skip(keep).flat_map(|(.., paths)| paths));
    }
    let (removed, freed) = remove_traces(files, true).await;
    log!("clean: removed {} file(s), {freed} bytes", removed.len());
    Ok(Response {
        ok: true,
        removed,
        freed_bytes: Some(freed),
        ..Default::default()
    })
}

// ---------------------------------------------------------------------------------------------
// Listeners

#[cfg(windows)]
async fn listen(shared: Arc<Shared>) -> Result<()> {
    use std::os::windows::io::AsRawHandle;
    use tokio::net::windows::named_pipe::ServerOptions;

    let mut allowed = Vec::new();
    if shared.cfg.allow.is_empty() {
        allowed.push(sys::current_user_sid()?);
    } else {
        for a in &shared.cfg.allow {
            allowed.push(sys::resolve_principal(a)?);
        }
    }
    let sec: &'static sys::PipeSecurity = Box::leak(Box::new(sys::PipeSecurity::new(&allowed)?));
    log!("pipe security: {}", sec.sddl);
    let ep = shared.cfg.endpoint.clone();
    let mut server = unsafe {
        ServerOptions::new()
            .first_pipe_instance(true)
            .reject_remote_clients(true)
            .create_with_security_attributes_raw(&ep, sec.as_ptr())
    }
    .with_context(|| format!("creating pipe {ep} (is another samplyd already running?)"))?;
    log!("listening on {ep}");
    loop {
        // A client that connects and drops before ConnectNamedPipe completes errors here; that
        // must not take the daemon down.
        if let Err(e) = server.connect().await {
            log!("pipe connect failed: {e}");
            let _ = server.disconnect();
            continue;
        }
        let conn = server;
        server = loop {
            match unsafe {
                ServerOptions::new()
                    .reject_remote_clients(true)
                    .create_with_security_attributes_raw(&ep, sec.as_ptr())
            } {
                Ok(s) => break s,
                Err(e) => {
                    log!("creating next pipe instance failed: {e}; retrying");
                    tokio::time::sleep(Duration::from_secs(1)).await;
                }
            }
        };
        let h = conn.as_raw_handle() as isize;
        let desc = match sys::pipe_client_pid(h) {
            Some(pid) => format!("client pid {pid}"),
            None => "client".into(),
        };
        let peer = Peer { desc, pipe: h };
        tokio::spawn(handle_conn(shared.clone(), conn, peer));
    }
}

#[cfg(unix)]
async fn listen(shared: Arc<Shared>) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    use tokio::net::{UnixListener, UnixStream};

    let ep = shared.cfg.endpoint.clone();
    if Path::new(&ep).exists() {
        if UnixStream::connect(&ep).await.is_ok() {
            bail!("another samplyd is already listening on {ep}");
        }
        std::fs::remove_file(&ep)?;
    }
    let listener = UnixListener::bind(&ep).with_context(|| format!("binding {ep}"))?;
    // Access is enforced by peer credentials below, so the socket itself is world-connectable.
    std::fs::set_permissions(&ep, std::fs::Permissions::from_mode(0o666))?;
    let allowed: Vec<u32> = if shared.cfg.allow.is_empty() {
        vec![sys::default_allowed_uid()]
    } else {
        shared
            .cfg
            .allow
            .iter()
            .map(|s| {
                s.parse::<u32>()
                    .with_context(|| format!("--allow expects a uid on unix, got {s:?}"))
            })
            .collect::<Result<_>>()?
    };
    log!("listening on {ep} (allowed uids: {allowed:?})");
    loop {
        let (mut s, _) = listener.accept().await?;
        let cred = match s.peer_cred() {
            Ok(c) => c,
            Err(_) => continue,
        };
        let uid = cred.uid();
        if uid != 0 && !allowed.contains(&uid) {
            let mut msg =
                serde_json::to_string(&Response::err(format!("uid {uid} is not allowed")))?;
            msg.push('\n');
            let _ = s.write_all(msg.as_bytes()).await;
            continue;
        }
        let desc = format!("uid {uid} pid {:?}", cred.pid());
        tokio::spawn(handle_conn(shared.clone(), s, Peer { desc, uid }));
    }
}

async fn serve(args: ServeArgs) -> Result<()> {
    if args.background || args.log_file.is_some() {
        let path = args
            .log_file
            .clone()
            .unwrap_or_else(|| data_dir().join("samplyd.log"));
        if let Some(d) = path.parent() {
            std::fs::create_dir_all(d)?;
        }
        let f = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)?;
        let _ = LOG.set(Mutex::new(Box::new(f)));
        if args.background {
            sys::detach_console();
        }
    }
    let cfg = Config::resolve(&args)?;
    if !sys::is_elevated() {
        log!("warning: samplyd is not elevated; samply will still prompt/fail where it needs privileges");
    }
    log!(
        "samplyd {} samply={} output_dir={}",
        env!("CARGO_PKG_VERSION"),
        cfg.samply.display(),
        cfg.output_dir.display()
    );
    let shared = Arc::new(Shared {
        cfg,
        next_id: AtomicU64::new(0),
        inner: Mutex::new(Inner::default()),
    });
    // Traces a samply killed before this daemon last stopped left behind. Don't stop ETW sessions
    // here: if another samplyd is already running, they may be its live recording.
    let leftovers = leftover_traces(&shared.cfg.output_dir, None);
    if !leftovers.is_empty() {
        let (removed, freed) = remove_traces(leftovers, false).await;
        log!("removed {} leftover trace(s), {freed} bytes", removed.len());
    }

    tokio::select! {
        r = listen(shared.clone()) => r,
        _ = tokio::signal::ctrl_c() => {
            log!("shutting down");
            let active = shared.inner.lock().unwrap().active.as_ref().map(|a| (a.rx.clone(), a.stop.clone()));
            if let Some((mut rx, stop)) = active {
                stop.notify_one();
                let _ = timeout(shared.cfg.stop_timeout, rx.wait_for(|s| s.state.is_done())).await;
            }
            Ok(())
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Scheduled task install (Windows)

#[cfg(windows)]
fn install_task(mut args: ServeArgs) -> Result<()> {
    if !sys::is_elevated() {
        bail!("install-task must be run once from an elevated (Administrator) terminal");
    }
    // Bake the absolute samply path so the task doesn't depend on PATH at logon.
    let samply = match &args.samply {
        Some(p) => p.clone(),
        None => {
            samplyd::which("samply").context("samply not found on PATH; pass --samply <path>")?
        }
    };
    args.samply = Some(std::fs::canonicalize(&samply).unwrap_or(samply));
    let exe = std::env::current_exe()?;
    let cmdline: Vec<String> = args.to_args().iter().map(|a| quote_arg(a)).collect();
    let user = format!(
        "{}\\{}",
        std::env::var("USERDOMAIN").unwrap_or_default(),
        std::env::var("USERNAME").context("USERNAME not set")?
    );
    let xml = format!(
        r#"<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo><Description>samplyd: elevated samply broker</Description></RegistrationInfo>
  <Triggers><LogonTrigger><Enabled>true</Enabled><UserId>{user}</UserId></LogonTrigger></Triggers>
  <Principals><Principal id="Author"><UserId>{user}</UserId><LogonType>InteractiveToken</LogonType><RunLevel>HighestAvailable</RunLevel></Principal></Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <AllowHardTerminate>true</AllowHardTerminate>
    <StartWhenAvailable>true</StartWhenAvailable>
    <Enabled>true</Enabled>
    <Hidden>false</Hidden>
    <RestartOnFailure><Interval>PT1M</Interval><Count>3</Count></RestartOnFailure>
  </Settings>
  <Actions Context="Author"><Exec><Command>{cmd}</Command><Arguments>{argstr}</Arguments></Exec></Actions>
</Task>"#,
        user = xml_escape(&user),
        cmd = xml_escape(&exe.display().to_string()),
        argstr = xml_escape(&cmdline.join(" ")),
    );
    let path = std::env::temp_dir().join("samplyd-task.xml");
    let mut bytes = vec![0xFF, 0xFE];
    for u in xml.encode_utf16() {
        bytes.extend_from_slice(&u.to_le_bytes());
    }
    std::fs::write(&path, bytes)?;
    run(
        "schtasks",
        &[
            "/Create",
            "/TN",
            "samplyd",
            "/XML",
            &path.display().to_string(),
            "/F",
        ],
    )?;
    let _ = std::fs::remove_file(&path);
    // Stop a running instance (if any) so the new settings take effect.
    let _ = std::process::Command::new("schtasks")
        .args(["/End", "/TN", "samplyd"])
        .output();
    run("schtasks", &["/Run", "/TN", "samplyd"])?;
    println!("Installed and started scheduled task 'samplyd'.");
    println!("  command: {} {}", exe.display(), cmdline.join(" "));
    println!("  log:     {}", data_dir().join("samplyd.log").display());
    println!("Check it with: samplyctl ping");
    Ok(())
}

#[cfg(windows)]
fn uninstall_task() -> Result<()> {
    let _ = std::process::Command::new("schtasks")
        .args(["/End", "/TN", "samplyd"])
        .output();
    run("schtasks", &["/Delete", "/TN", "samplyd", "/F"])?;
    println!("Removed scheduled task 'samplyd'.");
    Ok(())
}

#[cfg(windows)]
fn run(prog: &str, args: &[&str]) -> Result<()> {
    let out = std::process::Command::new(prog).args(args).output()?;
    if !out.status.success() {
        bail!(
            "{prog} {} failed: {}{}",
            args.join(" "),
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
    }
    Ok(())
}

#[cfg(windows)]
fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

/// Quote one argument for a Windows command line (CommandLineToArgvW rules).
#[cfg(windows)]
fn quote_arg(a: &str) -> String {
    if !a.is_empty() && !a.contains([' ', '\t', '"']) {
        return a.to_string();
    }
    let mut out = String::from("\"");
    let mut backslashes = 0;
    for c in a.chars() {
        match c {
            '\\' => backslashes += 1,
            '"' => {
                out.push_str(&"\\".repeat(backslashes * 2 + 1));
                out.push('"');
                backslashes = 0;
            }
            _ => {
                out.push_str(&"\\".repeat(backslashes));
                out.push(c);
                backslashes = 0;
            }
        }
    }
    out.push_str(&"\\".repeat(backslashes * 2));
    out.push('"');
    out
}

// ---------------------------------------------------------------------------------------------

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.cmd {
        #[cfg(windows)]
        Cmd::CtrlC { pid } => std::process::exit(sys::ctrl_c_helper_main(pid)),
        #[cfg(unix)]
        Cmd::CtrlC { pid } => {
            let rt = tokio::runtime::Runtime::new()?;
            rt.block_on(sys::send_ctrl_c(pid))
        }
        #[cfg(windows)]
        Cmd::InstallTask(a) => install_task(a),
        #[cfg(windows)]
        Cmd::UninstallTask => uninstall_task(),
        Cmd::Serve(a) => tokio::runtime::Runtime::new()?.block_on(serve(a)),
    }
}
