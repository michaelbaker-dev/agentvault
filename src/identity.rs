//! Who is calling? Asks the local tailscaled which tailnet device and user own
//! the connection's source address. WireGuard has already authenticated the
//! peer cryptographically, so this can't be spoofed by a remote caller.

use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    path::PathBuf,
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

async fn whois(socket: &PathBuf, addr: SocketAddr) -> Result<Caller, String> {
    let mut stream = tokio::net::UnixStream::connect(socket)
        .await
        .map_err(|e| format!("connecting to tailscaled: {e}"))?;
    // HTTP/1.0 so the reply is never chunked and ends at EOF.
    let req = format!("GET /localapi/v0/whois?addr={addr} HTTP/1.0\r\nHost: local-tailscaled.sock\r\nSec-Tailscale: localapi\r\n\r\n");
    stream.write_all(req.as_bytes()).await.map_err(|e| e.to_string())?;
    let mut buf = Vec::new();
    stream.take(1 << 20).read_to_end(&mut buf).await.map_err(|e| e.to_string())?;
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
