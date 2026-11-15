# samplyd

Keep an elevated [samply](https://github.com/mstange/samply) ready as a background service, and
drive it from **any unprivileged process** (scripts, CI steps, AI agents) without UAC prompts.

- `samplyd`: the broker. Runs elevated once (via a logon Scheduled Task) and launches
  `samply record` on request.
- `samplyctl`: the client. Unprivileged. Every command prints one JSON object and exits 0/1.
- The protocol is newline-delimited JSON over `\\.\pipe\samplyd` (Windows) or
  `/tmp/samplyd.sock` (Linux/macOS), so you can skip `samplyctl` and talk to the pipe directly.

## Why this works

On Windows samply only needs admin for its ETW/xperf helper, which it starts with a `runas`
(UAC) prompt each time. If samply's parent is already elevated, there's no prompt. samplyd is
that elevated parent: it stays running and takes commands.

Two samply behaviours samplyd works around:

1. **In attach (`--pid`) and system-wide (`--all`) mode, samply only stops on Ctrl+C.** It
   ignores `--duration` there on Windows. samplyd starts samply on its own hidden console
   (`CREATE_NO_WINDOW`). To stop it, samplyd spawns a tiny helper (`samplyd __ctrl-c <pid>`)
   that attaches to that console and sends a real `CTRL_C_EVENT`. samply then stops xperf,
   processes the ETL, and writes the profile. The daemon enforces durations itself.
2. **A Ctrl+C before samply finishes starting can leave a kernel ETW session running.**
   samplyd waits for samply's "Press Ctrl+C to stop" line before it reports `recording` or
   sends Ctrl+C. If something does leak, `samplyctl reset` runs `xperf -stop`.
3. **A failed or killed samply leaves its raw kernel trace (`samply-*.kernel.etl`) behind.**
   samply deletes it only after converting it, and a leaked ETW session keeps it growing (tens
   of GB). samplyd deletes a session's leftover `.etl` when the session ends, stopping leaked
   ETW sessions first if the file is still open, and sweeps stray ones when it starts.

## Install (Windows)

Prereqs: `samply` on PATH (e.g. `cargo install --locked samply`) and xperf (Windows Performance
Toolkit, which samply already needs).

```powershell
cargo install --path .          # installs samplyd.exe and samplyctl.exe into ~/.cargo/bin

# One time, from an *elevated* terminal:
samplyd install-task            # registers + starts a logon task with "Run with highest privileges"

# From then on, from any normal terminal:
samplyctl ping
```

`install-task` accepts every `serve` option and bakes it into the task, for example:

```powershell
samplyd install-task --samply-arg=--windows-symbol-server=https://msdl.microsoft.com/download/symbols
```

- Logs go to `%LOCALAPPDATA%\samplyd\samplyd.log`.
- Profiles go to `%LOCALAPPDATA%\samplyd\profiles`.
- Remove it with `samplyd uninstall-task`.
- To test without a task, run `samplyd serve` in an elevated terminal.

Why a Scheduled Task and not a Windows Service? A service runs as SYSTEM in session 0, with
SYSTEM's profile, symbol cache and environment. A logon task runs as *you*, elevated, in your
session. That's how samply expects to run.

## Usage

```sh
# Launch a program as yourself, profile it from the first instruction, stop when it exits.
# (The child is created suspended, samply attaches, then the child is resumed.)
samplyctl record --rate 4000 --presymbolicate -- cargo bench --bench parse

# Attach to something already running
samplyctl start --pid 12345 --duration 10
samplyctl wait

# Or stop by hand
samplyctl start --pid 12345
samplyctl stop

samplyctl status        # active session + history
samplyctl reset         # clean up leftover ETW sessions after a crash
samplyctl clean         # delete leftover raw traces (*.etl) from the output directory
samplyctl clean --keep 20   # ...and every profile but the newest 20
```

Example result:

```json
{
  "ok": true,
  "session": {
    "id": 3,
    "state": "finished",
    "target": { "pid": 12345 },
    "output": "C:\\Users\\nick\\AppData\\Local\\samplyd\\profiles\\samply-1794363767-3-pid12345.json",
    "syms_output": "C:\\Users\\nick\\AppData\\Local\\samplyd\\profiles\\samply-1794363767-3-pid12345.syms.json",
    "stop_reason": "duration",
    "exit_code": 0,
    "log_tail": ["Profiling process with pid 12345...", "Press Ctrl+C to stop.", "..."]
  }
}
```

Open the result with `samply load <output>`. That needs no elevation.

## Protocol

Send one JSON object per line and read one JSON line back. A connection can carry several requests.

| request | effect |
|---|---|
| `{"cmd":"ping"}` | daemon info |
| `{"cmd":"start","target":{"pid":N},"rate_hz":4000,"duration_secs":10,"presymbolicate":true,"compress":false,"stop_on_exit":true,"name":"x"}` | start recording; returns once samply is live. Only `target` is required. |
| `{"cmd":"start","target":"all"}` | system-wide; requires `--allow-system-wide` |
| `{"cmd":"stop","id":N}` | Ctrl+C samply and wait until the profile is written (`id` optional) |
| `{"cmd":"wait","id":N,"timeout_secs":60}` | wait for duration or target exit |
| `{"cmd":"status"}` | active session + history |
| `{"cmd":"reset"}` | `xperf -stop` / `xperf -stop SamplySession` when idle |
| `{"cmd":"clean","keep":20}` | when idle, delete leftover `*.etl` traces and, with `keep` (optional), all but the newest `keep` profiles; returns `removed` and `freed_bytes` |

Session `state` goes `starting → recording → stopping → finished | failed`. `stop_reason` is
`requested | duration | target_exited | samply_exited | daemon_shutdown`.

Talking to the pipe directly from PowerShell. Note the **Impersonation** level (the daemon needs
it to check pid access) and the explicit access rights: `InOut` asks for GENERIC_WRITE, which
includes FILE_CREATE_PIPE_INSTANCE, the one right the pipe ACL withholds, so that open is denied.

```powershell
$rights = [System.IO.Pipes.PipeAccessRights]'ReadData, WriteData, ReadAttributes, WriteAttributes, Synchronize, ReadPermissions'
$p = [System.IO.Pipes.NamedPipeClientStream]::new('.', 'samplyd', $rights, 'None', 'Impersonation', 'None')
$p.Connect(5000)
$w = [System.IO.StreamWriter]::new($p); $w.AutoFlush = $true
$r = [System.IO.StreamReader]::new($p)
$w.WriteLine('{"cmd":"status"}'); $r.ReadLine()
```

## Security model

An always-on elevated process that takes orders from unprivileged code is a UAC bypass if it's
careless. samplyd limits what a client can make it do:

- **No program launches.** samply is only ever run with `--pid` or `--all`, never with a
  command. `samplyctl record` launches the program itself, unprivileged, and asks the daemon to
  attach. So a client can't run code elevated through samplyd.
- **No raw arguments, no output paths.** Clients send structured fields. The daemon picks the
  output file inside its own directory, so a client can't make an elevated process write
  anywhere. Extra samply flags (symbol servers etc.) come only from the operator via
  `--samply-arg`.
- **Pid check under the client's identity.** Before attaching, the daemon impersonates the pipe
  client and tries `OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ)` on the target. If
  the caller couldn't open it itself (elevated processes, services, other users), the request
  is refused. Override with `--allow-any-pid`. On Unix the target must be owned by the peer's
  uid (from `SO_PEERCRED`).
- **System-wide recording is off** unless the daemon was started with `--allow-system-wide`
  (it shows every process on the box).
- **Pipe ACL.** Full control for SYSTEM and Administrators. Read/write only (no
  `FILE_CREATE_PIPE_INSTANCE`, so no pipe squatting) for the allowed principals: by default just
  the user running the daemon, or whatever `--allow` lists (SID, alias like `IU`, or account
  name). Mandatory label is Medium, so Low-integrity sandboxes can't connect. Remote clients are
  rejected and the first pipe instance is exclusive.
- What's left: any process running as you can profile *your own* medium-integrity processes
  without a prompt. That's the point of the tool, but it's worth knowing.

## Linux / macOS

The same daemon and client work over a Unix socket (`--allow <uid>`; profiles are `chown`ed to the
requesting user). On Linux you usually don't need any of this: `sudo sysctl
kernel.perf_event_paranoid=1` lets samply run unprivileged. On macOS, `samply setup` covers
attaching for most cases.

## Troubleshooting

- `samplyctl ping` fails to connect: is the task running (`schtasks /Query /TN samplyd`)? Check
  `%LOCALAPPDATA%\samplyd\samplyd.log`.
- `start` returns a warning that samply didn't report readiness: samply's output format may
  have changed. The session still runs, but `record` may miss the first moments.
- Start fails with an xperf error about a session already running: run `samplyctl reset`.
- `failed` sessions include `log_tail` with samply's last output.
- The output directory is filling the disk: `samplyctl clean` (add `--keep N` to prune old
  profiles too). The directory is writable only by Administrators, so this is the way to clean
  it from a normal shell.

## Status

Tested end to end on Windows 11 with samply 0.13.1: install-task, the pipe ACL, impersonation,
`record` (suspended launch, attach, resume, stop on exit), Ctrl+C delivery and the `.syms.json`
sidecar. The Linux build is tested against a stand-in samply.

Install the binaries somewhere only admins can write (e.g. `C:\Program Files\samplyd`, samply.exe
included) and pass `--output-dir`/`--log-file` under an admin-write-only directory: the task runs
`samplyd.exe` and samply elevated at every logon, and the daemon writes profiles and its log as
admin, so a user-writable location (`~/.cargo/bin`, `%LOCALAPPDATA%`) lets any process you run
swap the binary or plant a junction there.
