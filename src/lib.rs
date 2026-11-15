pub mod protocol;
pub mod sys;

use anyhow::{bail, Context, Result};
use protocol::{Request, Response};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};

/// Default endpoint: a named pipe on Windows, a Unix socket elsewhere.
/// Override with `--endpoint` or the `SAMPLYD_ENDPOINT` env var.
pub fn default_endpoint() -> String {
    if let Ok(e) = std::env::var("SAMPLYD_ENDPOINT") {
        if !e.is_empty() {
            return e;
        }
    }
    if cfg!(windows) {
        r"\\.\pipe\samplyd".to_string()
    } else {
        "/tmp/samplyd.sock".to_string()
    }
}

/// Send one request over an already-connected stream and read one response line.
pub async fn roundtrip<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut BufReader<S>,
    req: &Request,
) -> Result<Response> {
    let mut line = serde_json::to_string(req)?;
    line.push('\n');
    stream.get_mut().write_all(line.as_bytes()).await?;
    stream.get_mut().flush().await?;
    let mut resp = String::new();
    let n = stream.read_line(&mut resp).await?;
    if n == 0 {
        bail!("daemon closed the connection without replying");
    }
    serde_json::from_str(resp.trim()).context("malformed response from daemon")
}

/// Connect to the daemon and perform a single request.
pub async fn request(endpoint: &str, req: &Request) -> Result<Response> {
    #[cfg(windows)]
    {
        let client = sys::connect_pipe(endpoint).await?;
        let mut s = BufReader::new(client);
        roundtrip(&mut s, req).await
    }
    #[cfg(unix)]
    {
        let client = tokio::net::UnixStream::connect(endpoint)
            .await
            .with_context(|| {
                format!("could not connect to samplyd at {endpoint} (is it running?)")
            })?;
        let mut s = BufReader::new(client);
        roundtrip(&mut s, req).await
    }
}

pub fn now_unix() -> f64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}

/// Minimal `which`: resolve a program name against PATH (and PATHEXT on Windows).
pub fn which(name: &str) -> Option<std::path::PathBuf> {
    let p = std::path::Path::new(name);
    if p.components().count() > 1 {
        return p.exists().then(|| p.to_path_buf());
    }
    let exts: Vec<String> = if cfg!(windows) {
        std::env::var("PATHEXT")
            .unwrap_or_else(|_| ".EXE;.CMD;.BAT;.COM".into())
            .split(';')
            .map(|s| s.to_ascii_lowercase())
            .chain(std::iter::once(String::new()))
            .collect()
    } else {
        vec![String::new()]
    };
    let path = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path) {
        for ext in &exts {
            let cand = dir.join(format!("{name}{ext}"));
            if cand.is_file() {
                return Some(cand);
            }
        }
    }
    None
}
