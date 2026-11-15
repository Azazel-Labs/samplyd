//! samplyctl: unprivileged client for samplyd. Every command prints one JSON response on stdout
//! and exits 0 on success, 1 on failure, so scripts and AI agents can drive it directly.

use anyhow::{bail, Context, Result};
use clap::{Args, Parser, Subcommand};
use samplyd::protocol::*;
use samplyd::{default_endpoint, request, sys};

#[derive(Parser)]
#[command(
    name = "samplyctl",
    version,
    about = "Drive an elevated samplyd from an unprivileged process"
)]
struct Cli {
    /// Pipe name / socket path (default: $SAMPLYD_ENDPOINT, \\.\pipe\samplyd, /tmp/samplyd.sock)
    #[arg(long, global = true)]
    endpoint: Option<String>,
    /// Print single-line JSON instead of pretty JSON.
    #[arg(long, global = true)]
    compact: bool,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Args, Clone)]
struct RecOpts {
    /// Sampling rate in Hz.
    #[arg(short, long)]
    rate: Option<f64>,
    /// Stop automatically after N seconds.
    #[arg(short, long)]
    duration: Option<f64>,
    /// Profile name.
    #[arg(long)]
    name: Option<String>,
    /// Write a .syms.json sidecar with resolved symbols.
    #[arg(long)]
    presymbolicate: bool,
    /// Write .json.gz instead of .json.
    #[arg(long)]
    compress: bool,
}

#[derive(Subcommand)]
enum Cmd {
    /// Check the daemon is up and show its config.
    Ping,
    /// Show the active session and recent history.
    Status,
    /// Start recording an existing process (or the whole system).
    Start {
        #[arg(short, long, required_unless_present = "all", conflicts_with = "all")]
        pid: Option<u32>,
        #[arg(short, long)]
        all: bool,
        /// Keep recording after the target exits.
        #[arg(long)]
        no_stop_on_exit: bool,
        #[command(flatten)]
        opts: RecOpts,
    },
    /// Stop a recording and wait for the profile to be written.
    Stop {
        #[arg(long)]
        id: Option<u64>,
    },
    /// Wait for a recording to end on its own (duration / target exit).
    Wait {
        #[arg(long)]
        id: Option<u64>,
        /// Give up after N seconds.
        #[arg(long)]
        timeout: Option<f64>,
    },
    /// Launch a command as *you* (unprivileged), suspended; attach samply; resume; stop when it
    /// exits. The final JSON line on stdout is the result (the command's own stdout comes first).
    Record {
        #[command(flatten)]
        opts: RecOpts,
        /// Command to run.
        #[arg(trailing_var_arg = true, required = true, allow_hyphen_values = true)]
        command: Vec<String>,
    },
    /// Stop leftover ETW/xperf sessions after a crash (only when idle).
    Reset,
    /// Delete raw ETW traces (*.etl) that failed or killed recordings left behind (when idle).
    Clean {
        /// Also delete every profile but the newest N.
        #[arg(long)]
        keep: Option<usize>,
    },
    /// Send a raw JSON request line, e.g. '{"cmd":"status"}'.
    Raw { json: String },
}

fn print(resp: &serde_json::Value, compact: bool) {
    let s = if compact {
        serde_json::to_string(resp)
    } else {
        serde_json::to_string_pretty(resp)
    };
    println!("{}", s.unwrap_or_default());
}

fn start_params(target: Target, o: &RecOpts, stop_on_exit: bool) -> StartParams {
    StartParams {
        target,
        name: o.name.clone(),
        rate_hz: o.rate,
        duration_secs: o.duration,
        presymbolicate: o.presymbolicate,
        compress: o.compress,
        stop_on_exit,
    }
}

async fn record(ep: &str, opts: &RecOpts, command: &[String]) -> Result<serde_json::Value> {
    let (prog, args) = command.split_first().context("no command given")?;

    #[cfg(windows)]
    let mut child = {
        let mut cmd = std::process::Command::new(prog);
        cmd.args(args);
        sys::configure_suspended(&mut cmd);
        cmd.spawn()
            .with_context(|| format!("failed to launch {prog}"))?
    };
    #[cfg(unix)]
    let mut child = {
        let mut cmd = sys::wrap_suspended(prog, args);
        let child = cmd
            .spawn()
            .with_context(|| format!("failed to launch {prog}"))?;
        sys::wait_until_stopped(&child)?;
        child
    };

    let pid = child.id();
    let name = opts.name.clone().or_else(|| Some(command.join(" ")));
    let mut params = start_params(Target::Pid(pid), opts, true);
    params.name = name;
    let started = match request(ep, &Request::Start(params)).await {
        Ok(r) if r.ok => r,
        Ok(r) => {
            let _ = child.kill();
            let _ = child.wait();
            return Ok(serde_json::to_value(r)?);
        }
        Err(e) => {
            let _ = child.kill();
            let _ = child.wait();
            return Err(e);
        }
    };
    if let Some(w) = &started.warning {
        eprintln!("samplyctl: warning: {w}");
    }
    let id = started.session.as_ref().map(|s| s.id);
    sys::resume_child(&child)?;

    let status = tokio::task::spawn_blocking(move || child.wait()).await??;
    let resp = request(ep, &Request::Stop { id }).await?;
    let mut v = serde_json::to_value(&resp)?;
    if let Some(obj) = v.as_object_mut() {
        obj.insert("child_exit_code".into(), status.code().into());
    }
    Ok(v)
}

async fn run(cli: Cli) -> Result<bool> {
    let ep = cli.endpoint.clone().unwrap_or_else(default_endpoint);
    let v: serde_json::Value = match cli.cmd {
        Cmd::Ping => serde_json::to_value(request(&ep, &Request::Ping).await?)?,
        Cmd::Status => serde_json::to_value(request(&ep, &Request::Status).await?)?,
        Cmd::Reset => serde_json::to_value(request(&ep, &Request::Reset).await?)?,
        Cmd::Clean { keep } => {
            serde_json::to_value(request(&ep, &Request::Clean { keep }).await?)?
        }
        Cmd::Stop { id } => serde_json::to_value(request(&ep, &Request::Stop { id }).await?)?,
        Cmd::Wait { id, timeout } => serde_json::to_value(
            request(
                &ep,
                &Request::Wait {
                    id,
                    timeout_secs: timeout,
                },
            )
            .await?,
        )?,
        Cmd::Start {
            pid,
            all,
            no_stop_on_exit,
            opts,
        } => {
            let target = match (pid, all) {
                (Some(p), false) => Target::Pid(p),
                (None, true) => Target::All,
                _ => bail!("pass exactly one of --pid or --all"),
            };
            let req = Request::Start(start_params(target, &opts, !no_stop_on_exit));
            serde_json::to_value(request(&ep, &req).await?)?
        }
        Cmd::Record { opts, command } => record(&ep, &opts, &command).await?,
        Cmd::Raw { json } => {
            let req: Request = serde_json::from_str(&json).context("invalid request JSON")?;
            serde_json::to_value(request(&ep, &req).await?)?
        }
    };
    let ok = v.get("ok").and_then(|b| b.as_bool()).unwrap_or(false);
    print(&v, cli.compact);
    Ok(ok)
}

fn main() {
    let cli = Cli::parse();
    let compact = cli.compact;
    let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
    match rt.block_on(run(cli)) {
        Ok(true) => std::process::exit(0),
        Ok(false) => std::process::exit(1),
        Err(e) => {
            let v = serde_json::json!({ "ok": false, "error": format!("{e:#}") });
            print(&v, compact);
            std::process::exit(1);
        }
    }
}
