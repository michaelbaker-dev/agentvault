//! Two factors on every request: the Tailscale identity of the device (checked
//! in the HTTP guard), plus either an API token or an owner web session.
//!
//! Network identity alone is not enough, because Claude Code may run on the
//! same machine as your browser and would inherit your device identity.

use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    net::IpAddr,
    sync::Mutex,
    time::{Duration, Instant},
};
use subtle::ConstantTimeEq;

use crate::crypto::{random_bytes, sha256};
use crate::db::{SecretMeta, TokenRow};
use crate::identity::Caller;

pub const TOKEN_PREFIX: &str = "kt_";
pub const SESSION_COOKIE: &str = "__Host-keys_session";
pub const CSRF_HEADER: &str = "x-keys-csrf";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Scope {
    /// See names and descriptions (never values).
    List,
    /// Fetch raw values.
    Read,
    /// Create secrets and change values, notes and tags.
    Write,
    Delete,
    /// Call a provider through the proxy without seeing the key.
    Proxy,
}

impl Scope {
    pub const ALL: [Scope; 5] = [Scope::List, Scope::Read, Scope::Write, Scope::Delete, Scope::Proxy];

    pub fn as_str(self) -> &'static str {
        match self {
            Scope::List => "list",
            Scope::Read => "read",
            Scope::Write => "write",
            Scope::Delete => "delete",
            Scope::Proxy => "proxy",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|x| x.as_str() == s)
    }
}

#[derive(Debug, Clone)]
pub struct TokenGrant {
    pub name: String,
    pub scopes: Vec<Scope>,
    pub secrets: Vec<String>,
    /// Proxy only GET requests, so the token can't mint new credentials or
    /// change anything at the provider.
    pub proxy_get_only: bool,
}

#[derive(Debug, Clone)]
pub enum Principal {
    /// The vault owner signed in through the web interface. Can do everything,
    /// but revealing values, creating tokens, redirecting the proxy and deleting
    /// need a recent passphrase confirmation (`fresh`), so a stolen cookie alone
    /// can't extract keys.
    Owner { session: [u8; 32], fresh: bool },
    Token(TokenGrant),
}

impl Principal {
    pub fn label(&self) -> String {
        match self {
            Principal::Owner { .. } => "owner (web)".into(),
            Principal::Token(t) => format!("token:{}", t.name),
        }
    }

    pub fn is_owner(&self) -> bool {
        matches!(self, Principal::Owner { .. })
    }

    pub fn has(&self, scope: Scope) -> bool {
        match self {
            Principal::Owner { .. } => true,
            Principal::Token(t) => t.scopes.contains(&scope),
        }
    }

    pub fn may_touch(&self, secret: &str) -> bool {
        match self {
            Principal::Owner { .. } => true,
            Principal::Token(t) => t.secrets.iter().any(|g| glob_match(g, secret)),
        }
    }

    pub fn allows(&self, scope: Scope, secret: &str) -> bool {
        self.has(scope) && self.may_touch(secret)
    }

    /// Like [`Self::may_touch`], but also honours the owner-only flag: no
    /// token reaches an owner-only secret, even with `*`.
    pub fn may_use(&self, m: &SecretMeta) -> bool {
        match self {
            Principal::Owner { .. } => true,
            Principal::Token(_) => !m.owner_only && self.may_touch(&m.name),
        }
    }
}

/// `*` matches any run of characters; everything else is literal.
pub fn glob_match(pattern: &str, name: &str) -> bool {
    let parts: Vec<&str> = pattern.split('*').collect();
    if parts.len() == 1 {
        return pattern == name;
    }
    let mut rest = name;
    for (i, part) in parts.iter().enumerate() {
        if i == 0 {
            match rest.strip_prefix(part) {
                Some(r) => rest = r,
                None => return false,
            }
        } else if i == parts.len() - 1 {
            return rest.ends_with(part);
        } else if let Some(pos) = rest.find(part) {
            rest = &rest[pos + part.len()..];
        } else {
            return false;
        }
    }
    true
}

/// Returns (plaintext token shown once, sha256 stored in the database).
pub fn new_token() -> (String, [u8; 32]) {
    let raw: [u8; 32] = random_bytes();
    let token = format!("{TOKEN_PREFIX}{}", hex::encode(raw));
    let hash = sha256(token.as_bytes());
    (token, hash)
}

pub fn token_hash(token: &str) -> [u8; 32] {
    sha256(token.as_bytes())
}

/// Checks a token row against the calling device. Returns None if the token
/// is pinned to other machines.
pub fn grant_for(row: &TokenRow, caller: &Caller) -> Option<TokenGrant> {
    if !row.nodes.is_empty() && !row.nodes.iter().any(|n| n == &caller.node || n == &caller.node_fqdn) {
        return None;
    }
    Some(TokenGrant {
        name: row.name.clone(),
        scopes: row.scopes.iter().filter_map(|s| Scope::parse(s)).collect(),
        secrets: row.secrets.clone(),
        proxy_get_only: row.proxy_get_only,
    })
}

pub fn ct_eq(a: &str, b: &str) -> bool {
    a.len() == b.len() && bool::from(a.as_bytes().ct_eq(b.as_bytes()))
}

// ---- owner web sessions (memory only; a restart signs everyone out) ----

const SESSION_IDLE: Duration = Duration::from_secs(15 * 60);
const SESSION_MAX: Duration = Duration::from_secs(12 * 60 * 60);
/// How long a passphrase confirmation unlocks sensitive actions.
pub const FRESH_FOR: Duration = Duration::from_secs(5 * 60);

struct Session {
    csrf: String,
    /// Tailscale stable node ID of the device that signed in.
    node: String,
    created: Instant,
    last_seen: Instant,
    verified: Instant,
}

#[derive(Default)]
pub struct Sessions {
    inner: Mutex<HashMap<[u8; 32], Session>>,
}

pub struct SessionInfo {
    pub id: [u8; 32],
    pub csrf: String,
    pub fresh: bool,
}

impl Sessions {
    /// Returns (cookie value, csrf token).
    pub fn create(&self, node: &str) -> (String, String) {
        let cookie = hex::encode(random_bytes::<32>());
        let csrf = hex::encode(random_bytes::<24>());
        let now = Instant::now();
        let mut map = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        map.retain(|_, s| s.last_seen.elapsed() < SESSION_IDLE && s.created.elapsed() < SESSION_MAX);
        map.insert(
            sha256(cookie.as_bytes()),
            Session { csrf: csrf.clone(), node: node.to_string(), created: now, last_seen: now, verified: now },
        );
        (cookie, csrf)
    }

    /// Validates a cookie for this device and refreshes its idle timer.
    pub fn check(&self, cookie: &str, node: &str) -> Option<SessionInfo> {
        let id = sha256(cookie.as_bytes());
        let mut map = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        let s = map.get_mut(&id)?;
        if s.last_seen.elapsed() >= SESSION_IDLE || s.created.elapsed() >= SESSION_MAX || s.node != node {
            map.remove(&id);
            return None;
        }
        s.last_seen = Instant::now();
        Some(SessionInfo { id, csrf: s.csrf.clone(), fresh: s.verified.elapsed() < FRESH_FOR })
    }

    /// Records a fresh passphrase confirmation for this session.
    pub fn reverify(&self, id: &[u8; 32]) {
        if let Some(s) = self.inner.lock().unwrap_or_else(|p| p.into_inner()).get_mut(id) {
            s.verified = Instant::now();
        }
    }

    /// Signs out every session except `keep` (after a passphrase change).
    pub fn clear_except(&self, keep: &[u8; 32]) {
        self.inner.lock().unwrap_or_else(|p| p.into_inner()).retain(|id, _| id == keep);
    }

    pub fn remove(&self, id: &[u8; 32]) {
        self.inner.lock().unwrap_or_else(|p| p.into_inner()).remove(id);
    }

    #[cfg(test)]
    pub fn make_stale(&self) {
        let past = Instant::now().checked_sub(FRESH_FOR + Duration::from_secs(1)).expect("uptime");
        for s in self.inner.lock().unwrap_or_else(|p| p.into_inner()).values_mut() {
            s.verified = past;
        }
    }

    pub fn clear(&self) {
        self.inner.lock().unwrap_or_else(|p| p.into_inner()).clear();
    }
}

// ---- passphrase attempt limiting ----

const MAX_FAILURES: u32 = 5;
const LOCKOUT: Duration = Duration::from_secs(15 * 60);

#[derive(Default)]
pub struct LoginLimiter {
    inner: Mutex<HashMap<IpAddr, (u32, Instant)>>,
}

impl LoginLimiter {
    /// Counts an attempt *before* the slow passphrase check runs, so parallel
    /// requests can't all slip past the limit. Returns the seconds to wait if
    /// the caller is locked out. Call [`Self::success`] when the passphrase
    /// turns out to be right.
    pub fn begin(&self, ip: IpAddr) -> Result<(), u64> {
        let mut map = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        let e = map.entry(ip).or_insert((0, Instant::now()));
        if e.1.elapsed() >= LOCKOUT {
            *e = (0, Instant::now());
        }
        if e.0 >= MAX_FAILURES {
            return Err((LOCKOUT.saturating_sub(e.1.elapsed())).as_secs().max(1));
        }
        e.0 += 1;
        e.1 = Instant::now();
        Ok(())
    }

    pub fn success(&self, ip: IpAddr) {
        self.inner.lock().unwrap_or_else(|p| p.into_inner()).remove(&ip);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn globs() {
        assert!(glob_match("*", "ANYTHING"));
        assert!(glob_match("OPENAI_*", "OPENAI_API_KEY"));
        assert!(!glob_match("OPENAI_*", "XOPENAI_API_KEY"));
        assert!(glob_match("*_KEY", "STRIPE_KEY"));
        assert!(glob_match("A*B*C", "AxxBxxC"));
        assert!(!glob_match("A*B*C", "AxxCxxB"));
        assert!(glob_match("EXACT", "EXACT"));
        assert!(!glob_match("EXACT", "EXACT2"));
    }

    #[test]
    fn token_scopes_and_globs() {
        let p = Principal::Token(TokenGrant {
            name: "claude".into(),
            scopes: vec![Scope::List, Scope::Proxy],
            secrets: vec!["OPENAI_*".into()],
            proxy_get_only: true,
        });
        assert!(p.allows(Scope::Proxy, "OPENAI_API_KEY"));
        assert!(!p.allows(Scope::Read, "OPENAI_API_KEY"));
        assert!(!p.allows(Scope::Proxy, "STRIPE_KEY"));
    }

    #[test]
    fn node_pinning() {
        let row = TokenRow {
            id: 1,
            name: "t".into(),
            scopes: vec!["list".into()],
            secrets: vec!["*".into()],
            nodes: vec!["mac".into()],
            proxy_get_only: false,
            created_at: 0,
            last_used_at: None,
            revoked_at: None,
        };
        let mut c = Caller {
            ip: "100.64.0.2".parse().unwrap(),
            node_id: "nmac".into(),
            node: "mac".into(),
            node_fqdn: "mac.ts.net".into(),
            user: "u".into(),
            tags: vec![],
        };
        assert!(grant_for(&row, &c).is_some());
        c.node = "other".into();
        c.node_fqdn = "other.ts.net".into();
        assert!(grant_for(&row, &c).is_none());
    }

    #[test]
    fn sessions_bound_to_device() {
        let s = Sessions::default();
        let (cookie, csrf) = s.create("laptop");
        assert_eq!(s.check(&cookie, "laptop").unwrap().csrf, csrf);
        assert!(s.check(&cookie, "server").is_none(), "a cookie stolen to another device is useless");
        assert!(s.check(&cookie, "laptop").is_none(), "and gets revoked when misused");
    }

    #[test]
    fn limiter_counts_attempts_before_checking() {
        let l = LoginLimiter::default();
        let ip: IpAddr = "100.64.0.9".parse().unwrap();
        // Five attempts in flight at once are allowed; the sixth is refused
        // even though none of them has finished yet.
        for _ in 0..MAX_FAILURES {
            assert!(l.begin(ip).is_ok());
        }
        assert!(l.begin(ip).is_err());
        l.success(ip);
        assert!(l.begin(ip).is_ok());
    }
}
