//! keys: a single-binary secrets vault for a Tailscale network, with a web
//! interface, a REST API, a credential-injecting proxy and an MCP endpoint.

mod app;
mod auth;
mod config;
mod crypto;
mod dashboard;
mod db;
mod describe;
mod identity;
mod import;
mod import_api;
mod keychain;
mod material;
mod mcp;
mod providers;
mod proxy;
mod rotate;
mod server;
mod stations;
mod timeutil;
mod vault;
mod web;

#[cfg(test)]
mod tests;

use axum_server::tls_rustls::RustlsConfig;
use clap::{Parser, Subcommand};
use std::{
    net::SocketAddr,
    os::unix::fs::{DirBuilderExt, PermissionsExt},
    path::PathBuf,
    process::ExitCode,
    sync::Arc,
    time::Duration,
};
use tokio::sync::Semaphore;
use zeroize::Zeroizing;

use crate::app::{App, AutoUnlock};
use crate::auth::{LoginLimiter, Sessions};
use crate::config::Config;
use crate::crypto::KdfParams;
use crate::db::Db;
use crate::identity::Resolver;
use crate::vault::Vault;

#[derive(Parser)]
#[command(version, about = "AgentVault: a secrets vault for your tailnet")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Run the server.
    Serve {
        #[arg(short, long)]
        config: PathBuf,
    },
    /// Check the usage log's hash chain for tampering.
    AuditVerify {
        #[arg(short, long)]
        config: PathBuf,
    },
    /// Validate a config file and exit.
    CheckConfig {
        #[arg(short, long)]
        config: PathBuf,
    },
    /// Ask Tailscale which device and user an address belongs to, the way the
    /// vault identifies callers. Checks the vault can see Tailscale.
    Whois {
        /// A tailnet address, e.g. 100.101.102.103
        addr: std::net::IpAddr,
        /// Tailscale's socket (Linux, open-source tailscaled); the Mac apps are found without it.
        #[arg(long)]
        socket: Option<PathBuf>,
    },
    /// macOS: store the passphrase in your login Keychain so the vault unlocks
    /// itself after a restart (`--off` removes it). On Linux use
    /// `sudo /usr/local/lib/agentvault/auto-unlock`.
    AutoUnlock {
        #[arg(short, long)]
        config: PathBuf,
        /// Remove the stored passphrase.
        #[arg(long, conflicts_with = "at_next_sign_in")]
        off: bool,
        /// Store it the next time you sign in on the web page, instead of asking here.
        #[arg(long)]
        at_next_sign_in: bool,
    },
    /// Show what importing a key file would create, with every value masked.
    /// Reads the file locally; nothing is stored or sent anywhere.
    ImportPreview { file: PathBuf },
}

fn import_preview(file: &std::path::Path) -> Result<(), String> {
    let text = std::fs::read_to_string(file).map_err(|e| format!("reading {}: {e}", file.display()))?;
    let text = Zeroizing::new(text);
    if text.len() > import::MAX_TEXT {
        return Err("file is larger than 1 MiB".into());
    }
    let parsed = import::parse(&text);
    let props = import::propose(&parsed, &[], |_| None);
    for p in &props {
        let mut flags = vec![];
        if !p.include {
            flags.push(format!("SKIP: same value as {}", p.duplicate_of.as_deref().unwrap_or("?")));
        }
        if p.owner_only {
            flags.push("owner-only".into());
        }
        if !p.needs.is_empty() {
            flags.push(format!("needs: {}", p.needs.iter().map(|n| n.label).collect::<Vec<_>>().join(", ")));
        }
        if let Some(parent) = &p.parent {
            flags.push(format!("managed by {parent}"));
        }
        if !p.fields.is_empty() {
            flags.push(format!("with {}", p.fields.keys().cloned().collect::<Vec<_>>().join(", ")));
        }
        println!(
            "line {:>3}  {:<40} {:<28} {:<7} {:<22} {}",
            p.line,
            p.name,
            p.provider_name.unwrap_or("Unknown"),
            p.rotation,
            p.preview,
            flags.join("; ")
        );
    }
    for u in &parsed.unmatched {
        println!("line {:>3}  (no value found) {}", u.line, u.text);
    }
    Ok(())
}

/// Keeps key material out of core dumps and blocks debuggers (ptrace, and on
/// Linux /proc/<pid>/mem reads) from other processes of the same user. This
/// doesn't protect the config, passphrase file or TLS key on disk, so run the
/// service as its own system user (deploy/install.sh does).
fn harden_process() {
    // SAFETY: plain libc calls with valid arguments; no memory is shared.
    unsafe {
        #[cfg(target_os = "linux")]
        libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0);
        // macOS: refuse debugger attachment for the life of the process.
        #[cfg(target_os = "macos")]
        libc::ptrace(libc::PT_DENY_ATTACH, 0, std::ptr::null_mut(), 0);
        let none = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
        libc::setrlimit(libc::RLIMIT_CORE, &none);
        libc::umask(0o077);
    }
}

/// Reads a line from the terminal with echo off.
fn read_secret(prompt: &str) -> Result<Zeroizing<String>, String> {
    use std::io::{BufRead, Write};
    use std::os::fd::AsRawFd;
    let tty = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/tty")
        .map_err(|_| "this needs a terminal to ask for your passphrase".to_string())?;
    let fd = tty.as_raw_fd();
    // SAFETY: termios is plain data; fd is an open terminal for the whole call.
    let saved = unsafe {
        let mut t: libc::termios = std::mem::zeroed();
        if libc::tcgetattr(fd, &mut t) != 0 {
            return Err("couldn't turn off echo on the terminal".into());
        }
        let saved = t;
        t.c_lflag &= !libc::ECHO;
        libc::tcsetattr(fd, libc::TCSANOW, &t);
        saved
    };
    let _ = write!(&tty, "{prompt}");
    let mut line = Zeroizing::new(String::new());
    let read = std::io::BufReader::new(&tty).read_line(&mut line);
    // SAFETY: as above.
    unsafe { libc::tcsetattr(fd, libc::TCSANOW, &saved) };
    let _ = writeln!(&tty);
    read.map_err(|e| e.to_string())?;
    Ok(Zeroizing::new(line.trim_end_matches(['\n', '\r']).to_string()))
}

fn auto_unlock(cfg: &Config, off: bool, at_next_sign_in: bool) -> Result<(), String> {
    if !cfg!(target_os = "macos") {
        return Err("on Linux, run: sudo /usr/local/lib/agentvault/auto-unlock".into());
    }
    let marker = cfg.auto_unlock_marker();
    if at_next_sign_in {
        std::fs::write(&marker, b"").map_err(|e| format!("writing {}: {e}", marker.display()))?;
        println!(
            "The next time you sign in at {}, the vault stores your passphrase for automatic unlock.",
            cfg.origin()
        );
        return Ok(());
    }
    if off {
        let _ = std::fs::remove_file(&marker);
        let had = keychain::delete()?;
        println!(
            "{} Restart the vault; after that, sign in at {} to unlock it.",
            if had {
                "Removed the stored passphrase."
            } else {
                "No passphrase was stored."
            },
            cfg.origin()
        );
        return Ok(());
    }
    let db = Db::open(&cfg.db_path()).map_err(|e| format!("opening the vault's database: {e}"))?;
    if !Vault::is_initialized(&db).map_err(|e| e.to_string())? {
        return Err(format!("set your passphrase first: open {} in a browser", cfg.origin()));
    }
    let pass = read_secret("Your vault passphrase (not shown): ")?;
    Vault::default()
        .unlock(&db, &pass)
        .map_err(|_| "that passphrase doesn't unlock this vault. Nothing was stored.".to_string())?;
    keychain::set(&pass)?;
    println!("Stored in your login Keychain. Only the agentvault program can read it without macOS asking you first.");
    Ok(())
}

async fn tailscale_cert(cfg: &Config) {
    let out = tokio::process::Command::new("tailscale")
        .arg("cert")
        .arg("--cert-file")
        .arg(&cfg.tls.cert_file)
        .arg("--key-file")
        .arg(&cfg.tls.key_file)
        .arg(&cfg.hostname)
        .output()
        .await;
    match out {
        Ok(o) if o.status.success() => tracing::info!("TLS certificate refreshed with tailscale cert"),
        Ok(o) => tracing::warn!("tailscale cert failed: {}", String::from_utf8_lossy(&o.stderr).trim()),
        Err(e) => tracing::warn!("couldn't run tailscale cert: {e}"),
    }
}

async fn serve(cfg: Config) -> Result<(), String> {
    harden_process();
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(&cfg.data_dir)
        .map_err(|e| format!("creating {}: {e}", cfg.data_dir.display()))?;
    let db = Db::open(&cfg.db_path()).map_err(|e| format!("opening database: {e}"))?;
    let _ = std::fs::set_permissions(cfg.db_path(), std::fs::Permissions::from_mode(0o600));

    // No read timeout here: proxied event streams stay open between events.
    // Every use sets its own limit (the proxy in proxy::send and redact_stream,
    // rotation and descriptions per request).
    let http = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(10))
        .user_agent(concat!("agentvault/", env!("CARGO_PKG_VERSION")))
        .build()
        .map_err(|e| format!("building HTTP client: {e}"))?;

    let app = Arc::new(App {
        origin: cfg.origin(),
        resolver: Resolver::tailscale(cfg.tailscale_socket.clone()),
        db: Arc::new(db),
        vault: Vault::default(),
        sessions: Sessions::default(),
        limiter: LoginLimiter::default(),
        http,
        kdf: KdfParams::DEFAULT,
        kdf_gate: Semaphore::new(2),
        cfg: cfg.clone(),
        denied_budget: Default::default(),
        imports: Default::default(),
        describe_gate: Semaphore::new(4),
        minted: Default::default(),
        endpoints: Default::default(),
        auto_unlock: Default::default(),
        stations: Default::default(),
    });
    match app.db.rotations_fail_stale() {
        Ok(n) if n > 0 => tracing::warn!("{n} rotation(s) were interrupted by a restart; the old keys are still in use"),
        _ => {}
    }

    // A passphrase file or systemd credential first, then (macOS) the Keychain.
    let stored = match cfg.unlock_passphrase() {
        Some(p) => Ok(Some(p)),
        None => keychain::get(),
    };
    if let Err(e) = &stored {
        app.auto_unlock.set(AutoUnlock::FAILED);
        tracing::warn!("automatic unlock failed: {e}. Sign in to unlock in the meantime");
    }
    if let Ok(Some(pass)) = stored {
        let a = app.clone();
        let res = tokio::task::spawn_blocking(move || {
            if Vault::is_initialized(&a.db)? {
                a.vault.unlock(&a.db, &pass).map(|_| true)
            } else {
                Ok(false)
            }
        })
        .await
        .map_err(|e| e.to_string())?;
        match res {
            Ok(true) => {
                app.auto_unlock.set(AutoUnlock::ON);
                tracing::info!("vault unlocked from the stored passphrase");
            }
            Ok(false) => {
                app.auto_unlock.set(AutoUnlock::ON);
                tracing::info!("vault not set up yet; ignoring the stored passphrase");
            }
            Err(e) => {
                app.auto_unlock.set(AutoUnlock::FAILED);
                let fix = if cfg!(target_os = "macos") {
                    "agentvault auto-unlock -c <config>"
                } else {
                    "sudo /usr/local/lib/agentvault/auto-unlock"
                };
                tracing::warn!("automatic unlock failed: {e}. Sign in to unlock, then run `{fix}` to store the current passphrase");
            }
        }
    }

    if cfg.tls.renew_with_tailscale {
        tailscale_cert(&cfg).await;
    }
    let tls = RustlsConfig::from_pem_file(&cfg.tls.cert_file, &cfg.tls.key_file)
        .await
        .map_err(|e| format!("loading TLS certificate {}: {e}", cfg.tls.cert_file.display()))?;

    // Maintenance: refresh the certificate and prune old events.
    {
        let (app, tls) = (app.clone(), tls.clone());
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_secs(6 * 3600));
            loop {
                tick.tick().await;
                if app.cfg.tls.renew_with_tailscale {
                    tailscale_cert(&app.cfg).await;
                }
                if let Err(e) = tls.reload_from_pem_file(&app.cfg.tls.cert_file, &app.cfg.tls.key_file).await {
                    tracing::warn!("reloading TLS certificate: {e}");
                }
                let cutoff = db::now_ms() - i64::from(app.cfg.event_retention_days) * 86_400_000;
                match app.db.events_prune(cutoff) {
                    Ok(n) if n > 0 => tracing::info!("pruned {n} old events"),
                    Ok(_) => {}
                    Err(e) => tracing::warn!("pruning events: {e}"),
                }
            }
        });
    }

    // Rotation: revoke old keys after their grace period, rotate keys whose
    // schedule is due.
    {
        let app = app.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_secs(60));
            loop {
                tick.tick().await;
                rotate::tick(&app).await;
            }
        });
    }

    let router = server::router(app.clone());
    tracing::info!("agentvault listening on {} ({})", cfg.listen, app.origin);
    axum_server::bind_rustls(cfg.listen, tls)
        .serve(router.into_make_service_with_connect_info::<SocketAddr>())
        .await
        .map_err(|e| format!("server error: {e}"))
}

#[tokio::main]
async fn main() -> ExitCode {
    tracing_subscriber::fmt().with_target(false).init();
    let cli = Cli::parse();
    let result = match cli.cmd {
        Cmd::Serve { config } => match Config::load(&config) {
            Ok(cfg) => serve(cfg).await,
            Err(e) => Err(e),
        },
        Cmd::AuditVerify { config } => Config::load(&config).and_then(|cfg| {
            let db = Db::open(&cfg.db_path()).map_err(|e| e.to_string())?;
            let r = db.audit_verify().map_err(|e| e.to_string())?;
            println!("{}", serde_json::to_string_pretty(&r).expect("json"));
            if r.ok { Ok(()) } else { Err("audit chain is broken".into()) }
        }),
        Cmd::CheckConfig { config } => Config::load(&config).map(|cfg| println!("ok: {} on {}", cfg.origin(), cfg.listen)),
        Cmd::ImportPreview { file } => import_preview(&file),
        Cmd::AutoUnlock {
            config,
            off,
            at_next_sign_in,
        } => Config::load(&config).and_then(|cfg| auto_unlock(&cfg, off, at_next_sign_in)),
        Cmd::Whois { addr, socket } => {
            let socket = socket.unwrap_or_else(config::default_socket);
            identity::whois(&socket, SocketAddr::new(addr, 0)).await.map(|c| {
                println!("{}", serde_json::to_string_pretty(&c).expect("json"));
            })
        }
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}
