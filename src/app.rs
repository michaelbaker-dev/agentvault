//! Shared state, error type, authentication and usage-event recording.

use axum::{
    Json,
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
};
use serde_json::json;
use std::{
    collections::HashMap,
    net::IpAddr,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use tokio::sync::Semaphore;

use crate::auth::{self, LoginLimiter, Principal, Sessions};
use crate::config::Config;
use crate::crypto::KdfParams;
use crate::db::{Db, NewEvent, NewValue, SecretMeta, now_ms};
use crate::identity::{Caller, Resolver};
use crate::material::Material;
use crate::vault::{Vault, VaultError};

pub struct App {
    pub cfg: Config,
    pub db: Arc<Db>,
    pub vault: Vault,
    pub sessions: Sessions,
    pub limiter: LoginLimiter,
    pub resolver: Resolver,
    pub http: reqwest::Client,
    pub kdf: KdfParams,
    /// Argon2id uses 64 MiB per attempt; cap concurrent attempts.
    pub kdf_gate: Semaphore,
    pub origin: String,
    /// Per-device budget for logging refused requests, so a misbehaving
    /// device can't fill the disk with "denied" rows.
    pub denied_budget: Mutex<HashMap<IpAddr, (Instant, u32)>>,
    /// Parsed key files waiting for the owner to review, by import id.
    pub imports: Mutex<HashMap<String, crate::import_api::Session>>,
    /// Caps concurrent describer runs, so a big import doesn't flood providers.
    pub describe_gate: Semaphore,
    /// Short-lived credentials minted from stored ones, and rotation locks.
    pub minted: crate::rotate::MintCache,
    /// Overrides for provider API addresses (tests point them at fakes).
    pub endpoints: crate::rotate::Endpoints,
    /// Whether the vault unlocks itself at boot, and whether that still works.
    pub auto_unlock: AutoUnlock,
}

/// State of unattended unlock at boot (a systemd credential or passphrase file).
#[derive(Default)]
pub struct AutoUnlock(std::sync::atomic::AtomicU8);

impl AutoUnlock {
    pub const OFF: u8 = 0;
    /// Configured, and it unlocked the vault (or the vault wasn't set up yet).
    pub const ON: u8 = 1;
    /// Configured, but the stored passphrase was wrong at the last start.
    pub const FAILED: u8 = 2;
    /// The passphrase was changed since: the next restart will stay locked.
    pub const STALE: u8 = 3;

    pub fn set(&self, v: u8) {
        self.0.store(v, std::sync::atomic::Ordering::Relaxed);
    }
    pub fn get(&self) -> u8 {
        self.0.load(std::sync::atomic::Ordering::Relaxed)
    }
    pub fn label(&self) -> &'static str {
        match self.get() {
            Self::ON => "on",
            Self::FAILED => "failed",
            Self::STALE => "stale",
            _ => "off",
        }
    }
}

const DENIED_PER_MINUTE: u32 = 60;

pub type AppRef = Arc<App>;

/// Attached to a response so the HTTP guard records it with timing.
#[derive(Debug, Clone)]
pub struct EventInfo {
    pub action: &'static str,
    pub secret: Option<String>,
    pub actor: String,
    pub upstream_us: Option<i64>,
    pub detail: Option<String>,
}

impl EventInfo {
    pub fn new(action: &'static str, actor: impl Into<String>) -> Self {
        Self {
            action,
            secret: None,
            actor: actor.into(),
            upstream_us: None,
            detail: None,
        }
    }
    pub fn secret(mut self, s: impl Into<String>) -> Self {
        self.secret = Some(s.into());
        self
    }
    pub fn upstream(mut self, d: Duration) -> Self {
        self.upstream_us = Some(d.as_micros() as i64);
        self
    }
    pub fn detail(mut self, d: impl Into<String>) -> Self {
        self.detail = Some(d.into());
        self
    }
}

pub fn with_event(resp: impl IntoResponse, ev: EventInfo) -> Response {
    let mut r = resp.into_response();
    r.extensions_mut().insert(ev);
    r
}

#[derive(Debug)]
pub struct ApiError {
    pub status: StatusCode,
    pub msg: String,
    pub event: Option<Box<EventInfo>>,
}

impl ApiError {
    pub fn new(status: StatusCode, msg: impl Into<String>) -> Self {
        Self {
            status,
            msg: msg.into(),
            event: None,
        }
    }
    pub fn bad_request(msg: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, msg)
    }
    pub fn unauthorized(msg: impl Into<String>) -> Self {
        Self::new(StatusCode::UNAUTHORIZED, msg)
    }
    pub fn forbidden(msg: impl Into<String>) -> Self {
        Self::new(StatusCode::FORBIDDEN, msg)
    }
    pub fn not_found() -> Self {
        Self::new(StatusCode::NOT_FOUND, "no such secret")
    }
    pub fn internal(e: impl std::fmt::Display) -> Self {
        tracing::error!("internal error: {e}");
        Self::new(StatusCode::INTERNAL_SERVER_ERROR, "internal error")
    }
    pub fn event(mut self, ev: EventInfo) -> Self {
        self.event = Some(Box::new(ev));
        self
    }
}

impl From<rusqlite::Error> for ApiError {
    fn from(e: rusqlite::Error) -> Self {
        Self::internal(e)
    }
}

impl From<VaultError> for ApiError {
    fn from(e: VaultError) -> Self {
        match e {
            VaultError::Sealed => Self::new(StatusCode::SERVICE_UNAVAILABLE, e.to_string()),
            VaultError::BadPassphrase => Self::unauthorized(e.to_string()),
            VaultError::NotInitialized | VaultError::AlreadyInitialized => Self::new(StatusCode::CONFLICT, e.to_string()),
            VaultError::Corrupt(_) | VaultError::Db(_) => Self::internal(e),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let mut r = (self.status, Json(json!({ "error": self.msg }))).into_response();
        if self.status == StatusCode::UNAUTHORIZED {
            r.headers_mut()
                .insert(header::WWW_AUTHENTICATE, "Bearer realm=\"agentvault\"".parse().expect("static"));
        }
        if let Some(ev) = self.event {
            r.extensions_mut().insert(*ev);
        }
        r
    }
}

pub type ApiResult<T = Response> = Result<T, ApiError>;

fn bearer(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(header::AUTHORIZATION)?
        .to_str()
        .ok()?
        .strip_prefix("Bearer ")
        .map(str::trim)
}

pub fn cookie<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .filter_map(|kv| kv.trim().split_once('='))
        .find(|(k, _)| *k == name)
        .map(|(_, v)| v)
}

impl App {
    pub fn is_owner_device(&self, caller: &Caller) -> bool {
        caller.user == self.cfg.owner && !caller.is_tagged()
    }

    /// Resolves the credential on a request. Owner sessions must also present
    /// the CSRF header; tokens can't be sent by a browser automatically, so
    /// they don't need one.
    pub fn authenticate(&self, headers: &HeaderMap, caller: &Caller) -> ApiResult<Principal> {
        if let Some(tok) = bearer(headers) {
            if !tok.starts_with(auth::TOKEN_PREFIX) {
                return Err(ApiError::unauthorized("not a keys token"));
            }
            let row = self
                .db
                .token_by_hash(&auth::token_hash(tok))?
                .ok_or_else(|| ApiError::unauthorized("invalid or revoked token"))?;
            let (grant, pin) = auth::grant_for(&row, caller)
                .ok_or_else(|| ApiError::forbidden(format!("token '{}' is not allowed from {}", row.name, caller.node)))?;
            if let Some(name) = pin {
                self.db.token_pin(row.id, &name, &caller.node_id)?;
            }
            self.db.token_touch(row.id)?;
            return Ok(Principal::Token(grant));
        }
        if let Some(c) = cookie(headers, auth::SESSION_COOKIE) {
            if !self.is_owner_device(caller) {
                return Err(ApiError::forbidden("web sessions are for the owner's devices only"));
            }
            let s = self
                .sessions
                .check(c, &caller.node_id)
                .ok_or_else(|| ApiError::unauthorized("session expired: sign in again"))?;
            let sent = headers.get(auth::CSRF_HEADER).and_then(|v| v.to_str().ok()).unwrap_or("");
            if !auth::ct_eq(sent, &s.csrf) {
                return Err(ApiError::forbidden("missing or wrong CSRF header"));
            }
            return Ok(Principal::Owner {
                session: s.id,
                fresh: s.fresh,
            });
        }
        Err(ApiError::unauthorized("sign in, or send Authorization: Bearer <token>"))
    }

    /// Sensitive owner actions need the passphrase confirmed within the last
    /// few minutes. Tokens are governed by their scopes instead.
    pub fn require_fresh(&self, p: &Principal) -> ApiResult<()> {
        match p {
            Principal::Owner { fresh: false, .. } => Err(ApiError::new(
                StatusCode::PRECONDITION_REQUIRED,
                "confirm your passphrase to do this",
            )),
            _ => Ok(()),
        }
    }

    /// True if another refused request from this device may be logged.
    pub fn may_log_denied(&self, ip: IpAddr) -> bool {
        let mut map = self.denied_budget.lock().unwrap_or_else(|p| p.into_inner());
        if map.len() > 4096 {
            map.clear();
        }
        let e = map.entry(ip).or_insert((Instant::now(), 0));
        if e.0.elapsed() >= Duration::from_secs(60) {
            *e = (Instant::now(), 0);
        }
        e.1 += 1;
        e.1 <= DENIED_PER_MINUTE
    }

    pub fn record(&self, caller: &Caller, ev: EventInfo, status: u16, latency: Duration) {
        let e = NewEvent {
            ts: now_ms(),
            node: caller.node.clone(),
            user: caller.user.clone(),
            ip: caller.ip.to_string(),
            actor: ev.actor,
            action: ev.action.to_string(),
            secret: ev.secret,
            status: status as i64,
            latency_us: latency.as_micros() as i64,
            upstream_us: ev.upstream_us,
            detail: ev.detail,
        };
        if let Err(err) = self.db.event_insert(e) {
            tracing::error!("recording event: {err}");
        }
    }

    /// Records work the server does on its own (verification, describing).
    pub fn record_internal(&self, ev: EventInfo, status: u16, latency: Duration) {
        let me = Caller {
            ip: self.cfg.listen.ip(),
            node_id: "server".into(),
            node: format!("{} (server)", self.cfg.hostname.split('.').next().unwrap_or("agentvault")),
            node_fqdn: self.cfg.hostname.clone(),
            user: "agentvault".into(),
            tags: vec![],
        };
        self.record(&me, ev, status, latency);
    }

    /// Decrypts the current version of a secret.
    pub fn reveal(&self, meta: &SecretMeta) -> ApiResult<Material> {
        let v = self.db.secret_ciphertext(meta.id)?.ok_or_else(ApiError::not_found)?;
        self.open_version(meta.id, &v)
    }

    /// Decrypts a specific (possibly old) version.
    pub fn reveal_version(&self, meta: &SecretMeta, version: i64) -> ApiResult<Material> {
        let v = self.db.version_ciphertext(meta.id, version)?.ok_or_else(ApiError::not_found)?;
        self.open_version(meta.id, &v)
    }

    fn open_version(&self, id: i64, v: &crate::db::VersionCt) -> ApiResult<Material> {
        let bytes = self.vault.decrypt(id, v.version, v.format, &v.value_ct, &v.dek_ct)?;
        Material::decode(v.format, &bytes).map_err(ApiError::internal)
    }

    /// Encrypts and stores `m` as the secret's new current version.
    pub fn save_version(&self, id: i64, m: &Material, provider_ref: Option<&str>) -> ApiResult<i64> {
        let mac = self.vault.fingerprint(m.value.as_bytes())?;
        let (format, bytes) = m.encode();
        let parts = m.extra_names();
        let nv = NewValue {
            format,
            parts: &parts,
            mac: &mac,
            provider_ref,
        };
        Ok(self
            .db
            .secret_add_version(id, &nv, |id, ver| self.vault.encrypt(id, ver, format, &bytes))?)
    }

    /// Another secret already holding this value, if any.
    pub fn duplicate_of(&self, value: &str, except: Option<i64>) -> ApiResult<Option<String>> {
        let mac = self.vault.fingerprint(value.as_bytes())?;
        Ok(self.db.secret_by_mac(&mac, except)?)
    }
}
