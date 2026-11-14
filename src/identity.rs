//! Who is calling? Asks the local tailscaled which tailnet device and user own
//! the connection's source address. WireGuard has already authenticated the
//! peer cryptographically, so this can't be spoofed by a remote caller.

use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    path::{Path, PathBuf},
    sync::Mutex,
    time::{Duration, Instant},
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct Caller {
    pub ip: IpAddr,
    /// Tailscale's stable node ID; survives renames, unlike the name.
    pub node_id: String,
    /// Short machine name, e.g. `laptop`.
    pub node: String,
    pub node_fqdn: String,
    /// Tailscale login of the device owner; `tagged-devices` for tagged nodes.
    pub user: String,
    pub tags: Vec<String>,
}

impl Caller {
    pub fn is_tagged(&self) -> bool {
        !self.tags.is_empty()
    }
}

const CACHE_TTL: Duration = Duration::from_secs(30);

pub enum Resolver {
    Tailscale {
        socket: PathBuf,
        cache: Mutex<HashMap<IpAddr, (Instant, Caller)>>,
    },
    #[cfg(test)]
    Fixed(HashMap<IpAddr, Caller>),
}

#[derive(Deserialize)]
struct WhoIs {
    #[serde(rename = "Node")]
    node: WhoIsNode,
    #[serde(rename = "UserProfile")]
    user: WhoIsUser,
}
#[derive(Deserialize)]
struct WhoIsNode {
    #[serde(rename = "StableID", default)]
    stable_id: String,
    #[serde(rename = "Name")]
    name: String,
    #[serde(rename = "ComputedName", default)]
    computed_name: Option<String>,
    #[serde(rename = "Tags", default)]
    tags: Option<Vec<String>>,
}
#[derive(Deserialize)]
struct WhoIsUser {
    #[serde(rename = "LoginName")]
    login_name: String,
}

impl Resolver {
    pub fn tailscale(socket: PathBuf) -> Self {
        Self::Tailscale {
            socket,
            cache: Mutex::new(HashMap::new()),
        }
    }

    pub async fn resolve(&self, addr: SocketAddr) -> Result<Caller, String> {
        match self {
            Self::Tailscale { socket, cache } => {
                if let Some((at, c)) = cache.lock().unwrap_or_else(|p| p.into_inner()).get(&addr.ip())
                    && at.elapsed() < CACHE_TTL
                {
                    return Ok(c.clone());
                }
                let caller = tokio::time::timeout(Duration::from_secs(3), whois(socket, addr))
                    .await
                    .map_err(|_| "tailscaled whois timed out".to_string())??;
                let mut cache = cache.lock().unwrap_or_else(|p| p.into_inner());
                if cache.len() > 4096 {
                    cache.clear();
                }
                cache.insert(addr.ip(), (Instant::now(), caller.clone()));
                Ok(caller)
            }
            #[cfg(test)]
            Self::Fixed(map) => map.get(&addr.ip()).cloned().ok_or_else(|| "not a tailnet peer".into()),
        }
    }
}

/// Where Tailscale's local API is. Linux and the open-source tailscaled use a
/// Unix socket. The Mac apps listen on a localhost port instead, guarded by a
/// password in a "same user proof" file that only root and admin accounts
/// (standalone edition) or the logged-in user (App Store edition) can read.
#[derive(Debug, PartialEq, Eq)]
enum LocalApi {
    Unix(PathBuf),
    Tcp { port: u16, token: String },
}

/// Looked up on every call: the Mac apps pick a new port and password when
/// Tailscale restarts.
fn local_api(socket: &Path) -> Result<LocalApi, String> {
    if cfg!(not(target_os = "macos")) || socket.exists() {
        return Ok(LocalApi::Unix(socket.to_path_buf()));
    }
    mac_local_api().ok_or_else(|| {
        format!(
            "can't find Tailscale's local API: no socket at {}, and no Tailscale app port \
             (/Library/Tailscale/ipnport, or the App Store app's group container) this account can read",
            socket.display()
        )
    })
}

fn mac_local_api() -> Option<LocalApi> {
    // Standalone edition (from tailscale.com): the port is a symlink's target,
    // the password is in sameuserproof-PORT next to it.
    let dir = Path::new("/Library/Tailscale");
    if let Ok(target) = std::fs::read_link(dir.join("ipnport"))
        && let Ok(port) = target.to_string_lossy().parse::<u16>()
        && let Ok(token) = std::fs::read_to_string(dir.join(format!("sameuserproof-{port}")))
        && !token.trim().is_empty()
    {
        return Some(LocalApi::Tcp {
            port,
            token: token.trim().to_string(),
        });
    }
    // App Store edition: both are in a file name in the app's group container,
    // sameuserproof-PORT-PASSWORD.
    let groups = Path::new(&std::env::var_os("HOME")?).join("Library/Group Containers");
    for entry in std::fs::read_dir(groups).ok()?.flatten() {
        if !entry.file_name().to_string_lossy().ends_with("io.tailscale.ipn.macos") {
            continue;
        }
        for f in std::fs::read_dir(entry.path()).into_iter().flatten().flatten() {
            if let Some(api) = parse_proof_name(&f.file_name().to_string_lossy()) {
                return Some(api);
            }
        }
    }
    None
}

fn parse_proof_name(name: &str) -> Option<LocalApi> {
    let (port, token) = name.strip_prefix("sameuserproof-")?.split_once('-')?;
    let port = port.parse().ok()?;
    (!token.is_empty() && token.chars().all(|c| c.is_ascii_alphanumeric())).then(|| LocalApi::Tcp {
        port,
        token: token.to_string(),
    })
}

async fn local_api_get<S: AsyncReadExt + AsyncWriteExt + Unpin>(mut stream: S, path: &str, auth: &str) -> Result<Vec<u8>, String> {
    // HTTP/1.0 so the reply is never chunked and ends at EOF.
    let req = format!("GET {path} HTTP/1.0\r\nHost: local-tailscaled.sock\r\nSec-Tailscale: localapi\r\n{auth}\r\n");
    stream.write_all(req.as_bytes()).await.map_err(|e| e.to_string())?;
    let mut buf = Vec::new();
    stream.take(1 << 20).read_to_end(&mut buf).await.map_err(|e| e.to_string())?;
    Ok(buf)
}

pub async fn whois(socket: &Path, addr: SocketAddr) -> Result<Caller, String> {
    let path = format!("/localapi/v0/whois?addr={addr}");
    let buf = match local_api(socket)? {
        LocalApi::Unix(p) => {
            let s = tokio::net::UnixStream::connect(&p)
                .await
                .map_err(|e| format!("connecting to tailscaled: {e}"))?;
            local_api_get(s, &path, "").await?
        }
        LocalApi::Tcp { port, token } => {
            use base64::Engine;
            let s = tokio::net::TcpStream::connect(("127.0.0.1", port))
                .await
                .map_err(|e| format!("connecting to the Tailscale app: {e}"))?;
            let basic = base64::engine::general_purpose::STANDARD.encode(format!(":{token}"));
            local_api_get(s, &path, &format!("Authorization: Basic {basic}\r\n")).await?
        }
    };
    let text = String::from_utf8_lossy(&buf);
    let (head, body) = text.split_once("\r\n\r\n").ok_or("malformed tailscaled reply")?;
    let status = head.lines().next().unwrap_or("");
    if !status.contains(" 200 ") {
        return Err(format!("not a tailnet peer ({})", status.trim()));
    }
    let w: WhoIs = serde_json::from_str(body).map_err(|e| format!("parsing whois: {e}"))?;
    let fqdn = w.node.name.trim_end_matches('.').to_string();
    let node = w
        .node
        .computed_name
        .filter(|n| !n.is_empty())
        .unwrap_or_else(|| fqdn.split('.').next().unwrap_or("").to_string());
    if w.node.stable_id.is_empty() {
        return Err("tailscaled whois reply has no node ID".into());
    }
    Ok(Caller {
        ip: addr.ip(),
        node_id: w.node.stable_id,
        node,
        node_fqdn: fqdn,
        user: w.user.login_name,
        tags: w.node.tags.unwrap_or_default(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_the_mac_apps_local_api_from_the_proof_file_name() {
        assert_eq!(
            parse_proof_name("sameuserproof-49480-AbC123xyz"),
            Some(LocalApi::Tcp {
                port: 49480,
                token: "AbC123xyz".into()
            })
        );
        for bad in [
            "sameuserproof-49480",
            "sameuserproof-x-abc",
            "sameuserproof-1-a/b",
            "other-1-abc",
            "sameuserproof-70000-abc",
        ] {
            assert_eq!(parse_proof_name(bad), None, "{bad}");
        }
    }

    #[test]
    fn linux_always_uses_the_socket() {
        if cfg!(not(target_os = "macos")) {
            let p = Path::new("/nonexistent/tailscaled.sock");
            assert_eq!(local_api(p), Ok(LocalApi::Unix(p.to_path_buf())));
        }
    }
}
