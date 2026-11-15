//! Project tasks. `cargo xtask install` builds the release binaries and installs them into
//! `%ProgramFiles%\samplyd`, restarting the scheduled task.
//!
//! The build runs as you, so `target/` never gets admin-owned files. Only the copy and
//! restart run elevated, in a second copy of this program started through UAC, which
//! writes its output to a log that this side prints.

use std::env;
use std::error::Error;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};
use std::thread;
use std::time::{Duration, Instant};

type Result<T = ()> = std::result::Result<T, Box<dyn Error>>;

const TASK: &str = "samplyd";
const BINARIES: [&str; 2] = ["samplyd.exe", "samplyctl.exe"];
const USAGE: &str = "usage: cargo xtask install";

fn main() -> ExitCode {
    let args: Vec<String> = env::args().skip(1).collect();
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    let result = match args.as_slice() {
        ["install"] => install(),
        // Internal: the elevated half of `install`.
        ["apply", source, log] => apply_logged(Path::new(source), Path::new(log)),
        _ => {
            eprintln!("{USAGE}");
            return ExitCode::from(2);
        }
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("error: {error}");
            ExitCode::FAILURE
        }
    }
}

fn install_dir() -> PathBuf {
    PathBuf::from(env::var_os("ProgramFiles").unwrap_or_else(|| r"C:\Program Files".into()))
        .join("samplyd")
}

fn data_dir() -> PathBuf {
    PathBuf::from(env::var_os("ProgramData").unwrap_or_else(|| r"C:\ProgramData".into()))
        .join("samplyd")
}

fn install() -> Result {
    if !cfg!(windows) {
        return Err("install is Windows only; elsewhere use `cargo install --path .`".into());
    }
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .ok_or("xtask has no parent directory")?;
    let cargo = env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    println!("Building release binaries...");
    let status = Command::new(cargo)
        .current_dir(root)
        .args(["build", "--release", "--locked", "--package", "samplyd"])
        .status()?;
    if !status.success() {
        return Err("release build failed".into());
    }
    let source = root.join("target").join("release");
    for name in BINARIES {
        if !source.join(name).is_file() {
            return Err(format!("{} was not built", source.join(name).display()).into());
        }
    }

    let log = env::temp_dir().join(format!("samplyd-install-{}.log", std::process::id()));
    let _ = fs::remove_file(&log);
    println!(
        "Installing into {} (approve the UAC prompt)...",
        install_dir().display()
    );
    let elevated = elevate(
        &env::current_exe()?,
        &[
            "apply",
            &source.display().to_string(),
            &log.display().to_string(),
        ],
    );
    let output = fs::read_to_string(&log).unwrap_or_default();
    let _ = fs::remove_file(&log);
    print!("{output}");
    match elevated {
        Ok(true) => {}
        Ok(false) if output.is_empty() => {
            return Err("the elevated install did not start (UAC declined?)".into())
        }
        Ok(false) => return Err("the elevated install failed".into()),
        Err(error) => return Err(format!("could not start the elevated install: {error}").into()),
    }
    verify()
}

/// Runs `exe args` elevated through UAC and waits; true if it exited with 0.
fn elevate(exe: &Path, args: &[&str]) -> Result<bool> {
    // Start-Process joins -ArgumentList without quoting, so pass one pre-quoted string.
    let quoted: Vec<String> = args.iter().map(|a| format!("\"{a}\"")).collect();
    let literal = |s: &str| format!("'{}'", s.replace('\'', "''"));
    let script = format!(
        "$p = Start-Process -FilePath {} -ArgumentList {} -Verb RunAs -WindowStyle Hidden -Wait -PassThru; exit $p.ExitCode",
        literal(&exe.display().to_string()),
        literal(&quoted.join(" ")),
    );
    let status = Command::new("powershell")
        .args(["-NoProfile", "-NonInteractive", "-Command", &script])
        .status()?;
    Ok(status.success())
}

/// Waits for the restarted daemon to answer.
fn verify() -> Result {
    let ctl = install_dir().join("samplyctl.exe");
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        let output = Command::new(&ctl).arg("ping").output()?;
        if output.status.success() {
            println!("samplyd is running from {}.", install_dir().display());
            return Ok(());
        }
        if Instant::now() > deadline {
            return Err(format!(
                "installed, but `samplyctl ping` still fails: {}{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            )
            .into());
        }
        thread::sleep(Duration::from_millis(500));
    }
}

fn apply_logged(source: &Path, log: &Path) -> Result {
    let mut out = fs::File::create(log)?;
    let result = apply(source, &mut out);
    if let Err(error) = &result {
        let _ = writeln!(out, "error: {error}");
    }
    result
}

/// Elevated: stop the task, copy the binaries, and start it again. A task that is missing,
/// or runs samplyd from somewhere else, is registered with the default settings.
fn apply(source: &Path, out: &mut impl Write) -> Result {
    let dest = install_dir();
    let exe = dest.join("samplyd.exe");
    let registered = task_command()
        .is_some_and(|command| command.eq_ignore_ascii_case(&exe.display().to_string()));
    let _ = Command::new("schtasks")
        .args(["/End", "/TN", TASK])
        .output();
    fs::create_dir_all(&dest)?;
    for name in BINARIES {
        copy_retrying(&source.join(name), &dest.join(name))?;
        writeln!(out, "Copied {name}")?;
    }
    if registered {
        run(Command::new("schtasks").args(["/Run", "/TN", TASK]), out)?;
        writeln!(
            out,
            "Restarted scheduled task '{TASK}' with its existing settings."
        )?;
    } else {
        writeln!(
            out,
            "Registering scheduled task '{TASK}' with default settings."
        )?;
        let data = data_dir();
        let mut command = Command::new(&exe);
        command.arg("install-task");
        let samply = dest.join("samply.exe");
        if samply.is_file() {
            command.arg(format!("--samply={}", samply.display()));
        }
        command
            .arg(format!("--output-dir={}", data.join("profiles").display()))
            .arg(format!("--log-file={}", data.join("samplyd.log").display()));
        run(&mut command, out)?;
    }
    Ok(())
}

/// The program the scheduled task runs, if it exists.
fn task_command() -> Option<String> {
    let output = Command::new("schtasks")
        .args(["/Query", "/TN", TASK, "/XML"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let xml = decode(&output.stdout);
    let start = xml.find("<Command>")? + "<Command>".len();
    let end = start + xml[start..].find("</Command>")?;
    Some(xml[start..end].trim().replace("&amp;", "&"))
}

/// schtasks writes either the console code page or UTF-16, depending on how it is run.
fn decode(bytes: &[u8]) -> String {
    if bytes.len() >= 2 && bytes.iter().skip(1).step_by(2).take(64).all(|&b| b == 0) {
        let units: Vec<u16> = bytes
            .as_chunks::<2>()
            .0
            .iter()
            .map(|&pair| u16::from_le_bytes(pair))
            .collect();
        String::from_utf16_lossy(&units)
    } else {
        String::from_utf8_lossy(bytes).into_owned()
    }
}

/// The old daemon may hold the file for a moment after `schtasks /End`.
fn copy_retrying(from: &Path, to: &Path) -> Result {
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        match fs::copy(from, to) {
            Ok(_) => return Ok(()),
            Err(error) if Instant::now() > deadline => {
                return Err(
                    format!("copying {} to {}: {error}", from.display(), to.display()).into(),
                )
            }
            Err(_) => thread::sleep(Duration::from_millis(250)),
        }
    }
}

fn run(command: &mut Command, out: &mut impl Write) -> Result {
    let output = command.output()?;
    out.write_all(&output.stdout)?;
    out.write_all(&output.stderr)?;
    if !output.status.success() {
        return Err(format!("{:?} failed", command.get_program()).into());
    }
    Ok(())
}
