use serde::Deserialize;
use std::{net::SocketAddr, path::PathBuf};

/// Server configuration, loaded from a TOML file (see `config.example.toml`).
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Address to listen on. Use this machine's Tailscale IP so the service is
    /// only reachable over the tailnet.
    pub listen: SocketAddr,
    /// MagicDNS name clients use, e.g. `vault.your-tailnet.ts.net`. Requests
    /// carrying any other Host header are rejected (DNS-rebinding defence).
    pub hostname: String,
    /// Tailscale login (e.g. `you@example.com`) allowed to set up the vault and
    /// sign in to the web interface. Nobody else can, even with the passphrase.
    pub owner: String,
    /// Where the database lives. Created with 0700 permissions.
    pub data_dir: PathBuf,
    #[serde(default = "default_socket")]
    pub tailscale_socket: PathBuf,
    pub tls: Tls,
    #[serde(default)]
    pub describe: Describe,
    #[serde(default)]
    pub unlock: Unlock,
    /// Usage events older than this are deleted.
    #[serde(default = "default_retention")]
    pub event_retention_days: u32,
    #[serde(default)]
    pub rotation: RotationCfg,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RotationCfg {
    /// Rotate keys automatically when their schedule says so (only keys whose
    /// provider supports it and that have a manager set).
    #[serde(default = "yes")]
    pub scheduled: bool,
    /// After a rotation, how long the old key keeps working before the vault
    /// revokes it, so apps that copied the raw value can pick up the new one.
    #[serde(default = "default_grace")]
    pub grace_hours: u32,
}

impl Default for RotationCfg {
    fn default() -> Self {
        Self { scheduled: true, grace_hours: default_grace() }
    }
}

fn default_grace() -> u32 {
    24
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Tls {
    pub cert_file: PathBuf,
    pub key_file: PathBuf,
    /// Run `tailscale cert` at startup and daily to (re)issue the certificate.
    /// Needs `sudo tailscale set --operator=<user>` once, or leave this off and
    /// refresh the files with the bundled systemd timer instead.
    #[serde(default)]
    pub renew_with_tailscale: bool,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Describe {
    /// Ask the provider's "who am I" endpoint what a new key can do.
    #[serde(default = "yes")]
    pub verify_with_provider: bool,
    /// Name of a secret in this vault holding an Anthropic API key. When it
    /// exists, Claude writes descriptions from the key's metadata (never its
    /// value). When it doesn't, built-in templates are used.
    #[serde(default = "default_claude_secret")]
    pub claude_secret: Option<String>,
    #[serde(default = "default_model")]
    pub model: String,
}

impl Default for Describe {
    fn default() -> Self {
        Self {
            verify_with_provider: true,
            claude_secret: default_claude_secret(),
            model: default_model(),
        }
    }
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Unlock {
    /// Optional file holding the passphrase, for unattended unlock at boot.
    /// Anyone who can read this file can unlock the vault. If unset, the
    /// systemd credential `$CREDENTIALS_DIRECTORY/passphrase` is tried, and
    /// otherwise the vault stays sealed until you sign in.
    pub passphrase_file: Option<PathBuf>,
}

impl Config {
    /// The stored passphrase for unattended unlock: the configured file, or
    /// the systemd credential `passphrase`. None when neither exists.
    pub fn unlock_passphrase(&self) -> Option<zeroize::Zeroizing<String>> {
        let path = self
            .unlock
            .passphrase_file
            .clone()
            .or_else(|| std::env::var_os("CREDENTIALS_DIRECTORY").map(|d| PathBuf::from(d).join("passphrase")))?;
        let text = zeroize::Zeroizing::new(std::fs::read_to_string(&path).ok()?);
        let p = zeroize::Zeroizing::new(text.trim_end_matches(['\n', '\r']).to_string());
        (!p.is_empty()).then_some(p)
    }

    pub fn load(path: &std::path::Path) -> Result<Self, String> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| format!("reading {}: {e}", path.display()))?;
        let mut cfg: Config = toml::from_str(&text).map_err(|e| format!("parsing {}: {e}", path.display()))?;
        if cfg.describe.claude_secret.as_deref().is_some_and(str::is_empty) {
            cfg.describe.claude_secret = None;
        }
        if cfg.hostname.is_empty() || cfg.owner.is_empty() {
            return Err("hostname and owner must be set".into());
        }
        Ok(cfg)
    }

    /// The exact Origin a browser sends for pages served by this instance.
    pub fn origin(&self) -> String {
        if self.listen.port() == 443 {
            format!("https://{}", self.hostname)
        } else {
            format!("https://{}:{}", self.hostname, self.listen.port())
        }
    }

    pub fn db_path(&self) -> PathBuf {
        self.data_dir.join("keys.db")
    }
}

fn default_socket() -> PathBuf {
    PathBuf::from("/var/run/tailscale/tailscaled.sock")
}
fn default_retention() -> u32 {
    365
}
fn default_claude_secret() -> Option<String> {
    Some("ANTHROPIC_API_KEY".into())
}
fn default_model() -> String {
    "claude-opus-5-5".into()
}
fn yes() -> bool {
    true
}
