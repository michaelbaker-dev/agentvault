//! Key rotation and short-lived credentials.
//!
//! - **Auto**: the vault creates the replacement through the provider's API
//!   (usually with a managing "parent" credential), checks it works, makes it
//!   the current version, and revokes the old key after a grace period so
//!   apps that copied the raw value can catch up.
//! - **Guided**: the owner creates the key on the provider's site and pastes
//!   it in; the vault checks it, switches over, and revokes the old key
//!   through the API where it can, or reminds the owner to.
//! - **Minted**: GitHub App keys, Tailscale OAuth clients and Slack refresh
//!   tokens are turned into short-lived tokens on demand for the proxy.

use aws_lc_rs::{rand::SystemRandom, signature};
use axum::http::StatusCode;
use base64::Engine;
use serde_json::{Map, Value, json};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use zeroize::Zeroizing;

use crate::app::{ApiError, ApiResult, AppRef, EventInfo};
use crate::db::{RotationRow, SecretMeta, now_ms};
use crate::describe;
use crate::material::Material;
use crate::providers::{self, Provider, Rotation};
use crate::proxy::{Creds, Redactor};
use crate::timeutil;

const DAY_MS: i64 = 86_400_000;
const HOUR_MS: i64 = 3_600_000;
const HTTP_TIMEOUT: Duration = Duration::from_secs(20);
pub const ACTOR_SCHEDULER: &str = "agentvault (scheduler)";

/// Provider API addresses. Tests point them at a local fake.
#[derive(Clone)]
pub struct Endpoints {
    pub openrouter: String,
    pub cloudflare: String,
    pub tailscale: String,
    pub ms_login: String,
    pub graph: String,
    pub google_token: String,
    pub google_apikeys: String,
    pub github: String,
    pub slack: String,
    pub anthropic: String,
}

impl Default for Endpoints {
    fn default() -> Self {
        Self {
            openrouter: "https://openrouter.ai/api/v1".into(),
            cloudflare: "https://api.cloudflare.com/client/v4".into(),
            tailscale: "https://api.tailscale.com/api/v2".into(),
            ms_login: "https://login.microsoftonline.com".into(),
            graph: "https://graph.microsoft.com/v1.0".into(),
            google_token: "https://oauth2.googleapis.com/token".into(),
            google_apikeys: "https://apikeys.googleapis.com/v2".into(),
            github: "https://api.github.com".into(),
            slack: "https://slack.com/api".into(),
            anthropic: "https://api.anthropic.com/v1".into(),
        }
    }
}

impl Endpoints {
    /// Points a provider URL at the configured address (only tests change these).
    pub fn rewrite(&self, url: url::Url) -> url::Url {
        let d = Self::default();
        let pairs = [
            (&d.openrouter, &self.openrouter),
            (&d.cloudflare, &self.cloudflare),
            (&d.tailscale, &self.tailscale),
            (&d.github, &self.github),
            (&d.slack, &self.slack),
            (&d.anthropic, &self.anthropic),
        ];
        for (real, mine) in pairs {
            if real != mine
                && let Some(rest) = url.as_str().strip_prefix(real.as_str())
                && let Ok(u) = url::Url::parse(&format!("{mine}{rest}"))
            {
                return u;
            }
        }
        url
    }
}

type MintedToken = (Zeroizing<String>, Instant);

/// Minted tokens by (secret id, version), and one lock per secret so a
/// rotation, a revocation and a mint never run at the same time.
#[derive(Default)]
pub struct MintCache {
    /// (secret id, version) → (token, use until)
    tokens: Mutex<HashMap<(i64, i64), MintedToken>>,
    locks: Mutex<HashMap<i64, Arc<tokio::sync::Mutex<()>>>>,
}

impl MintCache {
    fn lock_for(&self, id: i64) -> Arc<tokio::sync::Mutex<()>> {
        self.locks.lock().unwrap_or_else(|p| p.into_inner()).entry(id).or_default().clone()
    }

    fn get(&self, id: i64, version: i64) -> Option<Zeroizing<String>> {
        let map = self.tokens.lock().unwrap_or_else(|p| p.into_inner());
        map.get(&(id, version))
            .filter(|(_, until)| *until > Instant::now())
            .map(|(t, _)| t.clone())
    }

    fn put(&self, id: i64, version: i64, token: Zeroizing<String>, valid_for: Duration) {
        let mut map = self.tokens.lock().unwrap_or_else(|p| p.into_inner());
        map.retain(|_, (_, until)| *until > Instant::now());
        // Stop using a token five minutes before it expires.
        let ttl = valid_for.saturating_sub(Duration::from_secs(300)).max(Duration::from_secs(30));
        map.insert((id, version), (token, Instant::now() + ttl));
    }

    pub fn forget(&self, id: i64) {
        self.tokens
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .retain(|(sid, _), _| *sid != id);
    }

    /// Drops every minted token (when the vault is locked).
    pub fn clear(&self) {
        self.tokens.lock().unwrap_or_else(|p| p.into_inner()).clear();
    }
}

// ---------------------------------------------------------------- info

fn provider_of(m: &SecretMeta) -> Option<&'static Provider> {
    m.provider.as_deref().and_then(providers::by_id)
}

/// Labels of the plaintext details the provider needs that the secret
/// doesn't have (secret parts can't be checked without decrypting).
fn missing_details(p: Option<&Provider>, m: &SecretMeta) -> Vec<&'static str> {
    p.map(|p| p.needs)
        .unwrap_or(&[])
        .iter()
        .filter(|n| !n.secret)
        .filter(|n| match n.name {
            "base_url" => m.proxy_base_url.is_none(),
            name => m.fields.get(name).and_then(Value::as_str).is_none_or(str::is_empty),
        })
        .map(|n| n.label)
        .collect()
}

/// Whether the vault can rotate this secret on its own right now.
fn auto_ready(p: Option<&Provider>, m: &SecretMeta) -> bool {
    if !missing_details(p, m).is_empty() {
        return false;
    }
    match p.map(|p| (p.rotation, p.parent_provider)) {
        // Cloudflare tokens may roll themselves if they have the permission.
        Some((Rotation::Auto(_), Some(pp))) => m.parent.is_some() || p.is_some_and(|p| p.id == pp),
        Some((Rotation::Auto(_), None)) => true,
        _ => false,
    }
}

/// Why the secret's manager can't be used, if it can't: it must exist, be
/// owner-only and be the kind of credential the rotation needs. `all` is
/// every secret the caller may see.
pub fn manager_problem(p: Option<&Provider>, m: &SecretMeta, all: &[SecretMeta]) -> Option<String> {
    let pp = p.and_then(|p| p.parent_provider)?;
    let name = m.parent.as_ref()?;
    let want = providers::by_id(pp).map(|x| x.name).unwrap_or(pp);
    match all.iter().find(|o| &o.name == name) {
        None => Some(format!("the manager {name} doesn't exist")),
        Some(o) if o.provider.as_deref() != Some(pp) => Some(format!(
            "{name} isn't an {want} (it was checked as {})",
            o.provider_name.as_deref().unwrap_or("something else")
        )),
        Some(o) if !o.owner_only => Some(format!("{name} must be owner-only")),
        Some(_) => None,
    }
}

pub fn next_due(m: &SecretMeta) -> Option<i64> {
    m.rotate_every_days.map(|d| m.rotated_at.unwrap_or(m.created_at) + d * DAY_MS)
}

/// How this secret is rotated, for the UI and API. `all` is every secret the
/// caller may see (to check the manager).
pub fn info(m: &SecretMeta, all: &[SecretMeta]) -> Value {
    let p = provider_of(m);
    let rotation = p.map(|p| p.rotation).unwrap_or(Rotation::Guided);
    let manager_problem = manager_problem(p, m, all);
    json!({
        "mode": rotation.mode(),
        "ready": auto_ready(p, m) && manager_problem.is_none(),
        "manager_problem": manager_problem,
        "never_reason": match rotation { Rotation::Never(r) => Some(r), _ => None },
        "steps": p.map(|p| p.steps).unwrap_or(&[]),
        "rotate_url": p.and_then(|p| p.rotate_url),
        "parent_hint": p.and_then(|p| p.parent_hint),
        "parent_provider": p.and_then(|p| p.parent_provider),
        "revokes_old": p.is_some_and(|p| revoker(p).is_some()),
        "missing": missing_details(p, m),
        "every_days": m.rotate_every_days,
        "next_due": next_due(m),
        "needs": p.map(|p| p.needs.iter().map(|n| json!({"name": n.name, "label": n.label, "secret": n.secret, "hint": n.hint})).collect::<Vec<_>>()).unwrap_or_default(),
    })
}

/// Which API can revoke this provider's old keys.
fn revoker(p: &Provider) -> Option<&'static str> {
    match p.rotation {
        Rotation::Auto("cloudflare") => None, // rolling already invalidates the old value
        Rotation::Auto(r) => Some(r),
        _ if p.id == "anthropic" => Some("anthropic"),
        _ => None,
    }
}

// ---------------------------------------------------------------- HTTP helpers

fn safe_seg(s: &str) -> Result<&str, String> {
    let ok = (1..=128).contains(&s.len()) && s.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | '~'));
    if ok {
        Ok(s)
    } else {
        Err("an ID returned or stored for this key has unexpected characters".into())
    }
}

fn field<'a>(m: &'a SecretMeta, name: &str) -> Result<&'a str, String> {
    m.fields
        .get(name)
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| format!("add the '{name}' field to this secret first"))
}

fn form(pairs: &[(&str, &str)]) -> String {
    let mut s = url::form_urlencoded::Serializer::new(String::new());
    for (k, v) in pairs {
        s.append_pair(k, v);
    }
    s.finish()
}

fn error_text(v: &Value) -> String {
    [
        "/error/message",
        "/error_description",
        "/error",
        "/errors/0/message",
        "/message",
        "/detail",
    ]
    .iter()
    .find_map(|p| v.pointer(p).and_then(Value::as_str))
    .unwrap_or("")
    .to_string()
}

/// Sends a request and returns the JSON body, or an error that names the
/// step and never contains any of `secrets`.
async fn send_json(rb: reqwest::RequestBuilder, what: &str, secrets: &[&str]) -> Result<Value, String> {
    let r = Redactor::new(secrets);
    // Redact the whole text first, then shorten it, so a secret cut at the
    // edge can't slip through.
    let clean = |s: String| {
        String::from_utf8_lossy(&r.redact(s.as_bytes()))
            .chars()
            .take(300)
            .collect::<String>()
    };
    let resp = rb
        .timeout(HTTP_TIMEOUT)
        .send()
        .await
        .map_err(|_| format!("{what}: couldn't reach the provider"))?;
    let status = resp.status();
    let body: Value = resp.json().await.unwrap_or(Value::Null);
    if !status.is_success() {
        return Err(clean(
            format!("{what}: HTTP {} {}", status.as_u16(), error_text(&body)).trim().to_string(),
        ));
    }
    if body.get("ok") == Some(&Value::Bool(false)) || body.get("success") == Some(&Value::Bool(false)) {
        return Err(clean(format!("{what}: {}", error_text(&body))));
    }
    Ok(body)
}

fn str_at<'a>(v: &'a Value, ptr: &str, what: &str) -> Result<&'a str, String> {
    v.pointer(ptr)
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| format!("{what}: the reply had no {ptr}"))
}

// ---------------------------------------------------------------- RS256 JWTs

fn pem_der(pem: &str) -> Result<(bool, Zeroizing<Vec<u8>>), String> {
    let pkcs8 = pem.contains("-----BEGIN PRIVATE KEY-----");
    let rsa = pem.contains("-----BEGIN RSA PRIVATE KEY-----");
    if !pkcs8 && !rsa {
        return Err("expected an RSA private key in PEM format".into());
    }
    let body: Zeroizing<String> = Zeroizing::new(
        pem.lines()
            .map(str::trim)
            .filter(|l| !l.starts_with("-----") && !l.is_empty())
            .collect(),
    );
    // Service account JSON stores the key with literal "\n" sequences.
    let body = Zeroizing::new(body.replace("\\n", ""));
    let der = base64::engine::general_purpose::STANDARD
        .decode(body.as_bytes())
        .map_err(|_| "the private key isn't valid PEM")?;
    Ok((pkcs8, Zeroizing::new(der)))
}

fn b64url(b: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b)
}

pub fn sign_rs256(pem: &str, claims: &Value, kid: Option<&str>) -> Result<Zeroizing<String>, String> {
    let (pkcs8, der) = pem_der(pem)?;
    let key = if pkcs8 {
        signature::RsaKeyPair::from_pkcs8(&der)
    } else {
        signature::RsaKeyPair::from_der(&der)
    }
    .map_err(|_| "the private key was rejected (needs RSA, 2048 bits or more)".to_string())?;
    let mut header = json!({ "alg": "RS256", "typ": "JWT" });
    if let Some(k) = kid {
        header["kid"] = json!(k);
    }
    let input = format!(
        "{}.{}",
        b64url(header.to_string().as_bytes()),
        b64url(claims.to_string().as_bytes())
    );
    let mut sig = vec![0u8; key.public_modulus_len()];
    key.sign(&signature::RSA_PKCS1_SHA256, &SystemRandom::new(), input.as_bytes(), &mut sig)
        .map_err(|_| "signing failed")?;
    Ok(Zeroizing::new(format!("{input}.{}", b64url(&sig))))
}

// ---------------------------------------------------------------- minting

/// What the proxy authenticates with: the stored value, or for "minted"
/// providers a short-lived token made from it.
pub async fn proxy_material(app: &AppRef, meta: &SecretMeta, stored: &Material) -> ApiResult<Material> {
    let Some(Rotation::Minted(kind)) = provider_of(meta).map(|p| p.rotation) else {
        return Ok(stored.clone());
    };
    if let Some(t) = app.minted.get(meta.id, meta.version) {
        return Ok(Material::single(t.as_str()));
    }
    let lock = app.minted.lock_for(meta.id);
    let _guard = lock.lock().await;
    // Someone else may have minted (or, for Slack, saved a new version) meanwhile.
    let meta = app.db.secret_by_id(meta.id)?.ok_or_else(ApiError::not_found)?;
    if let Some(t) = app.minted.get(meta.id, meta.version) {
        return Ok(Material::single(t.as_str()));
    }
    let stored = app.reveal(&meta)?;
    let start = Instant::now();
    let r = match kind {
        "github-app" => mint_github(app, &meta, &stored).await,
        "tailscale" => tailscale_token(app, &meta, &stored).await,
        "slack" => mint_slack(app, &meta, &stored).await,
        other => Err(format!("unknown minter {other}")),
    };
    let ev = EventInfo::new("mint", "agentvault (proxy)")
        .secret(&meta.name)
        .upstream(start.elapsed());
    match r {
        Ok((token, version, ttl)) => {
            app.record_internal(ev.detail(kind), 200, start.elapsed());
            let out = Material::single(token.as_str());
            app.minted.put(meta.id, version, token, ttl);
            Ok(out)
        }
        Err(e) => {
            app.record_internal(ev.detail(format!("{kind}: failed")), 502, start.elapsed());
            Err(ApiError::new(StatusCode::BAD_GATEWAY, e))
        }
    }
}

type Minted = (Zeroizing<String>, i64, Duration);

async fn mint_github(app: &AppRef, meta: &SecretMeta, m: &Material) -> Result<Minted, String> {
    let installation = field(meta, "installation_id")?;
    if !installation.chars().all(|c| c.is_ascii_digit()) {
        return Err("installation_id must be a number".into());
    }
    let iss = meta
        .fields
        .get("client_id")
        .and_then(Value::as_str)
        .map_or_else(|| field(meta, "app_id"), Ok)?;
    let now = now_ms() / 1000;
    let jwt = sign_rs256(&m.value, &json!({ "iat": now - 60, "exp": now + 540, "iss": iss }), None)?;
    let rb = app
        .http
        .post(format!("{}/app/installations/{installation}/access_tokens", app.endpoints.github))
        .bearer_auth(jwt.as_str())
        .header("accept", "application/vnd.github+json")
        .header("x-github-api-version", "2022-11-28")
        .header("user-agent", "agentvault");
    let v = send_json(rb, "GitHub installation token", &[jwt.as_str()]).await?;
    let token = Zeroizing::new(str_at(&v, "/token", "GitHub")?.to_string());
    let ttl = v
        .get("expires_at")
        .and_then(Value::as_str)
        .and_then(timeutil::parse_time)
        .map(|e| Duration::from_millis((e - now_ms()).max(0) as u64))
        .unwrap_or(Duration::from_secs(3600));
    Ok((token, meta.version, ttl))
}

async fn tailscale_token(app: &AppRef, meta: &SecretMeta, m: &Material) -> Result<Minted, String> {
    let client_id = field(meta, "client_id")?;
    let rb = app
        .http
        .post(format!("{}/oauth/token", app.endpoints.tailscale))
        .header("content-type", "application/x-www-form-urlencoded")
        .body(form(&[
            ("client_id", client_id),
            ("client_secret", &m.value),
            ("grant_type", "client_credentials"),
        ]));
    let v = send_json(rb, "Tailscale OAuth", &[&m.value]).await?;
    let token = Zeroizing::new(str_at(&v, "/access_token", "Tailscale OAuth")?.to_string());
    let ttl = Duration::from_secs(v.get("expires_in").and_then(Value::as_u64).unwrap_or(3600));
    Ok((token, meta.version, ttl))
}

/// Slack refresh tokens are single-use: each refresh returns a new one,
/// which is saved as a new version before the access token is used.
async fn mint_slack(app: &AppRef, meta: &SecretMeta, m: &Material) -> Result<Minted, String> {
    let client_id = field(meta, "client_id")?;
    let client_secret = m
        .get("client_secret")
        .filter(|s| !s.is_empty())
        .ok_or("add the client_secret part to this secret first")?;
    let basic = base64::engine::general_purpose::STANDARD.encode(format!("{client_id}:{client_secret}"));
    let rb = app
        .http
        .post(format!("{}/oauth.v2.access", app.endpoints.slack))
        .header("authorization", format!("Basic {basic}"))
        .header("content-type", "application/x-www-form-urlencoded")
        .body(form(&[("grant_type", "refresh_token"), ("refresh_token", &m.value)]));
    let v = send_json(rb, "Slack token refresh", &[&m.value, client_secret, &basic]).await?;
    let token = Zeroizing::new(str_at(&v, "/access_token", "Slack")?.to_string());
    let ttl = Duration::from_secs(v.get("expires_in").and_then(Value::as_u64).unwrap_or(43_200));
    let mut version = meta.version;
    if let Some(next) = v.get("refresh_token").and_then(Value::as_str).filter(|r| *r != m.value) {
        let mut nm = m.clone();
        nm.value = next.to_string();
        let mut saved = Err(String::new());
        for attempt in 0..3 {
            match app.save_version(meta.id, &nm, None) {
                Ok(v) => {
                    saved = Ok(v);
                    break;
                }
                Err(e) => {
                    tracing::error!(
                        "saving Slack's new refresh token for {} (attempt {}): {}",
                        meta.name,
                        attempt + 1,
                        e.msg
                    );
                    saved = Err(e.msg);
                    tokio::time::sleep(Duration::from_millis(200)).await;
                }
            }
        }
        version = saved.map_err(|e| {
            format!("Slack issued a new refresh token but it couldn't be saved ({e}); reinstall the Slack app to get a new one")
        })?;
        // Old versions of a single-use token are useless; don't keep them.
        let _ = app.db.version_delete(meta.id, meta.version);
        let _ = app.db.secret_mark_rotated(meta.id);
        let _ = app.db.secret_set_describe_status(meta.id, "refreshed by the vault");
    }
    Ok((token, version, ttl))
}

// ---------------------------------------------------------------- rotators

struct Ctx<'a> {
    app: &'a AppRef,
    meta: &'a SecretMeta,
    old: &'a Material,
    parent: Option<(SecretMeta, Material)>,
}

impl Ctx<'_> {
    fn parent(&self) -> Result<&(SecretMeta, Material), String> {
        self.parent.as_ref().ok_or_else(|| "set this secret's manager first".into())
    }
    fn ep(&self) -> &crate::rotate::Endpoints {
        &self.app.endpoints
    }
}

struct Created {
    material: Material,
    provider_ref: Option<String>,
    old_ref: Option<String>,
    /// The provider already invalidated the old value (a roll).
    old_gone: bool,
    fields: Option<Map<String, Value>>,
}

async fn create_new(rotator: &str, c: &Ctx<'_>) -> Result<Created, String> {
    match rotator {
        "openrouter" => openrouter_create(c).await,
        "cloudflare" => cloudflare_roll(c).await,
        "tailscale-authkey" => tailscale_create(c).await,
        "azure-app-secret" => azure_create(c).await,
        "google-apikey" => google_create(c).await,
        other => Err(format!("no automatic rotation for {other}")),
    }
}

/// Finds the provider's ID for the current (old) key, for revoking it later.
async fn find_old_ref(rotator: &str, c: &Ctx<'_>) -> Result<Option<String>, String> {
    match rotator {
        "openrouter" => openrouter_find(c).await,
        "tailscale-authkey" => Ok(tailscale_key_id(&c.old.value)),
        "azure-app-secret" => azure_find(c).await,
        "google-apikey" => google_find(c).await.map(|(name, _)| Some(name)),
        "anthropic" => anthropic_find(c).await,
        _ => Ok(None),
    }
}

/// Revokes an old key by its provider ID. `c.old` is the *current* value here.
async fn revoke(rotator: &str, c: &Ctx<'_>, old_ref: &str) -> Result<(), String> {
    let id = safe_seg(old_ref.rsplit('/').next().unwrap_or(""))?;
    let app = c.app;
    match rotator {
        "openrouter" => {
            let (_, pm) = c.parent()?;
            let rb = app.http.delete(format!("{}/keys/{id}", c.ep().openrouter)).bearer_auth(&pm.value);
            send_json(rb, "OpenRouter delete key", &[&pm.value]).await.map(|_| ())
        }
        "tailscale-authkey" => {
            let token = tailscale_parent_token(c).await?;
            let rb = app
                .http
                .delete(format!("{}/tailnet/-/keys/{id}", c.ep().tailscale))
                .bearer_auth(token.as_str());
            send_json(rb, "Tailscale delete key", &[token.as_str()]).await.map(|_| ())
        }
        "azure-app-secret" => {
            let token = azure_token(c, &c.old.value).await?;
            let app_id = safe_seg(field(c.meta, "client_id")?)?;
            let rb = app
                .http
                .post(format!("{}/applications(appId='{app_id}')/removePassword", c.ep().graph))
                .bearer_auth(token.as_str())
                .json(&json!({ "keyId": id }));
            send_json(rb, "Microsoft Graph removePassword", &[token.as_str()]).await.map(|_| ())
        }
        "google-apikey" => {
            if !valid_google_key_name(old_ref) {
                return Err("unexpected Google key name".into());
            }
            let token = google_token(c).await?;
            let rb = app
                .http
                .delete(format!("{}/{old_ref}", c.ep().google_apikeys))
                .bearer_auth(token.as_str());
            send_json(rb, "Google delete key", &[token.as_str()]).await.map(|_| ())
        }
        "anthropic" => {
            let (_, pm) = c.parent()?;
            let rb = app
                .http
                .post(format!("{}/organizations/api_keys/{id}", c.ep().anthropic))
                .header("x-api-key", &pm.value)
                .header("anthropic-version", "2023-06-01")
                .json(&json!({ "status": "inactive" }));
            send_json(rb, "Anthropic disable key", &[&pm.value]).await.map(|_| ())
        }
        _ => Ok(()),
    }
}

// OpenRouter: a management key creates and deletes keys.

async fn openrouter_find(c: &Ctx<'_>) -> Result<Option<String>, String> {
    let (_, pm) = c.parent()?;
    let app = c.app;
    // The key's own masked label, then the management list to find its hash.
    let me = send_json(
        app.http.get(format!("{}/key", c.ep().openrouter)).bearer_auth(&c.old.value),
        "OpenRouter key info",
        &[&c.old.value],
    )
    .await?;
    let label = me.pointer("/data/label").and_then(Value::as_str).unwrap_or("").to_string();
    if label.is_empty() {
        return Ok(None);
    }
    let mut hits = vec![];
    for page in 0..20 {
        let url = format!("{}/keys?include_disabled=true&offset={}", c.ep().openrouter, page * 100);
        let v = send_json(app.http.get(url).bearer_auth(&pm.value), "OpenRouter list keys", &[&pm.value]).await?;
        let rows = v.get("data").and_then(Value::as_array).cloned().unwrap_or_default();
        hits.extend(
            rows.iter()
                .filter(|r| r.get("label").and_then(Value::as_str) == Some(label.as_str()))
                .filter_map(|r| r.get("hash").and_then(Value::as_str).map(String::from)),
        );
        if rows.len() < 100 {
            break;
        }
    }
    Ok(if hits.len() == 1 { hits.pop() } else { None })
}

async fn openrouter_create(c: &Ctx<'_>) -> Result<Created, String> {
    let (_, pm) = c.parent()?;
    let app = c.app;
    // The old key must be in this management key's account: otherwise the new
    // key would be made in the wrong account and the old one never revoked.
    let old_ref = openrouter_find(c).await?.ok_or(
        "couldn't find this key in the management key's account, so nothing was created. Is the manager from the same OpenRouter account?",
    )?;
    let old_ref = Some(old_ref);
    // Keep the old key's spending limit, if it had one.
    let mut limit = Value::Null;
    let mut reset = Value::Null;
    if let Some(h) = &old_ref {
        let v = send_json(
            app.http
                .get(format!("{}/keys/{}", c.ep().openrouter, safe_seg(h)?))
                .bearer_auth(&pm.value),
            "OpenRouter key",
            &[&pm.value],
        )
        .await?;
        limit = v.pointer("/data/limit").cloned().unwrap_or(Value::Null);
        reset = v.pointer("/data/limit_reset").cloned().unwrap_or(Value::Null);
    }
    let name = format!("{} (rotated {})", c.meta.name, timeutil::format_date(now_ms()));
    let body = json!({ "name": name, "limit": limit, "limit_reset": reset });
    let v = send_json(
        app.http
            .post(format!("{}/keys", c.ep().openrouter))
            .bearer_auth(&pm.value)
            .json(&body),
        "OpenRouter create key",
        &[&pm.value],
    )
    .await?;
    let key = str_at(&v, "/key", "OpenRouter create key")?;
    Ok(Created {
        material: Material::single(key),
        provider_ref: v.pointer("/data/hash").and_then(Value::as_str).map(String::from),
        old_ref,
        old_gone: false,
        fields: None,
    })
}

// Cloudflare: roll the token's value (the old value stops working).

async fn cloudflare_roll(c: &Ctx<'_>) -> Result<Created, String> {
    let app = c.app;
    let v = send_json(
        app.http
            .get(format!("{}/user/tokens/verify", c.ep().cloudflare))
            .bearer_auth(&c.old.value),
        "Cloudflare verify",
        &[&c.old.value],
    )
    .await?;
    let token_id = safe_seg(str_at(&v, "/result/id", "Cloudflare verify")?)?.to_string();
    // A manager token with "API Tokens: Edit", or the token itself.
    let manager = c.parent.as_ref().map(|(_, m)| m.value.as_str()).unwrap_or(&c.old.value);
    let url = match c.meta.fields.get("account_id").and_then(Value::as_str) {
        Some(acct) => format!("{}/accounts/{}/tokens/{token_id}/value", c.ep().cloudflare, safe_seg(acct)?),
        None => format!("{}/user/tokens/{token_id}/value", c.ep().cloudflare),
    };
    let v = send_json(
        app.http.put(url).bearer_auth(manager).json(&json!({})),
        "Cloudflare roll token",
        &[manager, &c.old.value],
    )
    .await
    .map_err(|e| {
        if e.contains("HTTP 403") || e.contains("HTTP 401") {
            format!("{e}. Set a manager token that has the \"API Tokens: Edit\" permission.")
        } else {
            e
        }
    })?;
    let value = v
        .get("result")
        .and_then(Value::as_str)
        .filter(|s| s.len() >= 20)
        .ok_or("Cloudflare roll: no new value in the reply")?;
    Ok(Created {
        material: Material::single(value),
        provider_ref: Some(token_id),
        old_ref: None,
        old_gone: true,
        fields: None,
    })
}

// Tailscale: an OAuth client creates a new auth key with the old one's settings.

fn tailscale_key_id(key: &str) -> Option<String> {
    key.strip_prefix("tskey-auth-")?
        .split('-')
        .next()
        .filter(|s| !s.is_empty())
        .map(String::from)
}

async fn tailscale_parent_token(c: &Ctx<'_>) -> Result<Zeroizing<String>, String> {
    let (pmeta, pm) = c.parent()?;
    tailscale_token(c.app, pmeta, pm).await.map(|t| t.0)
}

async fn tailscale_create(c: &Ctx<'_>) -> Result<Created, String> {
    let app = c.app;
    let token = tailscale_parent_token(c).await?;
    let old_id = tailscale_key_id(&c.old.value).ok_or("this doesn't look like a Tailscale auth key")?;
    // The old key must exist in this tailnet and be an auth key; its settings are copied.
    let url = format!("{}/tailnet/-/keys/{}", c.ep().tailscale, safe_seg(&old_id)?);
    let v = send_json(app.http.get(url).bearer_auth(token.as_str()), "Tailscale key", &[token.as_str()])
        .await
        .map_err(|e| format!("{e}. If the device already joined, revoke the old key and delete it here instead"))?;
    if v.get("keyType").and_then(Value::as_str).is_some_and(|t| t != "auth") {
        return Err("Tailscale says this isn't an auth key, so nothing was created".into());
    }
    let mut caps = v
        .pointer("/capabilities/devices/create")
        .cloned()
        .ok_or("Tailscale didn't return the old key's settings")?;
    let old_id = Some(old_id);
    if let Some(tags) = c.meta.fields.get("tags").and_then(Value::as_str) {
        let t: Vec<&str> = tags.split([',', ' ']).filter(|t| !t.is_empty()).collect();
        caps["tags"] = json!(t);
    }
    if caps.get("tags").and_then(Value::as_array).is_none_or(Vec::is_empty) {
        return Err("Tailscale requires tags on keys made by an OAuth client: add a 'tags' field such as tag:server".into());
    }
    let body = json!({
        "capabilities": { "devices": { "create": caps } },
        "expirySeconds": 90 * 86_400,
        "description": "rotated by keys vault",
    });
    let v = send_json(
        app.http
            .post(format!("{}/tailnet/-/keys", c.ep().tailscale))
            .bearer_auth(token.as_str())
            .json(&body),
        "Tailscale create key",
        &[token.as_str()],
    )
    .await?;
    let key = str_at(&v, "/key", "Tailscale create key")?;
    Ok(Created {
        material: Material::single(key),
        provider_ref: v.get("id").and_then(Value::as_str).map(String::from),
        old_ref: old_id,
        old_gone: false,
        fields: None,
    })
}

// Microsoft Entra: the app adds a new client secret to itself.

async fn azure_token(c: &Ctx<'_>, secret: &str) -> Result<Zeroizing<String>, String> {
    let tenant = safe_seg(field(c.meta, "tenant_id")?)?;
    let client_id = field(c.meta, "client_id")?;
    let rb = c
        .app
        .http
        .post(format!("{}/{tenant}/oauth2/v2.0/token", c.ep().ms_login))
        .header("content-type", "application/x-www-form-urlencoded")
        .body(form(&[
            ("client_id", client_id),
            ("client_secret", secret),
            ("scope", "https://graph.microsoft.com/.default"),
            ("grant_type", "client_credentials"),
        ]));
    let v = send_json(rb, "Microsoft sign-in", &[secret]).await?;
    Ok(Zeroizing::new(str_at(&v, "/access_token", "Microsoft sign-in")?.to_string()))
}

async fn azure_find(c: &Ctx<'_>) -> Result<Option<String>, String> {
    let token = azure_token(c, &c.old.value).await?;
    let app_id = safe_seg(field(c.meta, "client_id")?)?;
    let url = format!("{}/applications(appId='{app_id}')?$select=id,passwordCredentials", c.ep().graph);
    let v = send_json(
        c.app.http.get(url).bearer_auth(token.as_str()),
        "Microsoft Graph application",
        &[token.as_str()],
    )
    .await?;
    let hint: String = c.old.value.chars().take(3).collect();
    let hits: Vec<String> = v
        .get("passwordCredentials")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter(|p| p.get("hint").and_then(Value::as_str) == Some(hint.as_str()))
        .filter_map(|p| p.get("keyId").and_then(Value::as_str).map(String::from))
        .collect();
    Ok(if hits.len() == 1 { hits.into_iter().next() } else { None })
}

async fn azure_create(c: &Ctx<'_>) -> Result<Created, String> {
    let old_ref = azure_find(c).await?;
    let token = azure_token(c, &c.old.value).await?;
    let app_id = safe_seg(field(c.meta, "client_id")?)?;
    let days = c.meta.rotate_every_days.unwrap_or(180).clamp(30, 365) * 2;
    let body = json!({ "passwordCredential": {
        "displayName": format!("agentvault {}", timeutil::format_date(now_ms())),
        "endDateTime": timeutil::format_rfc3339(now_ms() + days * DAY_MS),
    }});
    let rb = c
        .app
        .http
        .post(format!("{}/applications(appId='{app_id}')/addPassword", c.ep().graph))
        .bearer_auth(token.as_str())
        .json(&body);
    let v = send_json(rb, "Microsoft Graph addPassword", &[token.as_str()]).await.map_err(|e| {
        if e.contains("HTTP 403") {
            format!("{e}. The app needs the Application.ReadWrite.OwnedBy permission and must be an owner of itself.")
        } else {
            e
        }
    })?;
    let secret = str_at(&v, "/secretText", "Microsoft Graph addPassword")?;
    Ok(Created {
        material: Material::single(secret),
        provider_ref: v.get("keyId").and_then(Value::as_str).map(String::from),
        old_ref,
        old_gone: false,
        fields: None,
    })
}

// Google: a service account creates a copy of the key with the same restrictions.

fn valid_google_key_name(n: &str) -> bool {
    let p: Vec<&str> = n.split('/').collect();
    p.len() == 6
        && p[0] == "projects"
        && p[2] == "locations"
        && p[3] == "global"
        && p[4] == "keys"
        && safe_seg(p[1]).is_ok()
        && safe_seg(p[5]).is_ok()
}

async fn google_token(c: &Ctx<'_>) -> Result<Zeroizing<String>, String> {
    let (_, pm) = c.parent()?;
    let sa: Value = serde_json::from_str(&pm.value).map_err(|_| "the manager isn't a service account JSON key")?;
    let email = sa
        .get("client_email")
        .and_then(Value::as_str)
        .ok_or("service account JSON has no client_email")?;
    let pem = Zeroizing::new(
        sa.get("private_key")
            .and_then(Value::as_str)
            .ok_or("service account JSON has no private_key")?
            .to_string(),
    );
    let now = now_ms() / 1000;
    // Always Google's token endpoint, never one named inside the JSON.
    let claims = json!({
        "iss": email, "scope": "https://www.googleapis.com/auth/cloud-platform",
        "aud": "https://oauth2.googleapis.com/token", "iat": now, "exp": now + 3600,
    });
    let jwt = sign_rs256(&pem, &claims, sa.get("private_key_id").and_then(Value::as_str))?;
    let rb = c
        .app
        .http
        .post(&c.ep().google_token)
        .header("content-type", "application/x-www-form-urlencoded")
        .body(form(&[
            ("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer"),
            ("assertion", jwt.as_str()),
        ]));
    let v = send_json(rb, "Google sign-in", &[jwt.as_str()]).await?;
    Ok(Zeroizing::new(str_at(&v, "/access_token", "Google sign-in")?.to_string()))
}

/// (key resource name, project) of the current key.
async fn google_find(c: &Ctx<'_>) -> Result<(String, String), String> {
    let token = google_token(c).await?;
    let mut url = url::Url::parse(&format!("{}/keys:lookupKey", c.ep().google_apikeys)).map_err(|e| e.to_string())?;
    url.query_pairs_mut().append_pair("keyString", &c.old.value);
    let v = send_json(
        c.app.http.get(url).bearer_auth(token.as_str()),
        "Google lookupKey",
        &[token.as_str(), &c.old.value],
    )
    .await?;
    let name = str_at(&v, "/name", "Google lookupKey")?.to_string();
    let parent = str_at(&v, "/parent", "Google lookupKey")?.to_string();
    if !valid_google_key_name(&name) || !parent.starts_with("projects/") || safe_seg(&parent["projects/".len()..]).is_err() {
        return Err("Google returned an unexpected key name".into());
    }
    Ok((name, parent))
}

async fn google_create(c: &Ctx<'_>) -> Result<Created, String> {
    let app = c.app;
    let (old_name, parent) = google_find(c).await?;
    let token = google_token(c).await?;
    let base = &c.ep().google_apikeys;
    let old = send_json(
        app.http.get(format!("{base}/{old_name}")).bearer_auth(token.as_str()),
        "Google get key",
        &[token.as_str()],
    )
    .await?;
    let mut body = json!({ "displayName": format!("{} (rotated {})", old.get("displayName").and_then(Value::as_str).unwrap_or(&c.meta.name), timeutil::format_date(now_ms())) });
    if let Some(r) = old.get("restrictions") {
        body["restrictions"] = r.clone();
    }
    let op = send_json(
        app.http
            .post(format!("{base}/{parent}/locations/global/keys"))
            .bearer_auth(token.as_str())
            .json(&body),
        "Google create key",
        &[token.as_str()],
    )
    .await?;
    let mut op = op;
    for _ in 0..30 {
        if op.get("done") == Some(&Value::Bool(true)) {
            break;
        }
        let name = str_at(&op, "/name", "Google operation")?;
        if !name.starts_with("operations/") || safe_seg(&name["operations/".len()..]).is_err() {
            return Err("unexpected Google operation name".into());
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
        op = send_json(
            app.http.get(format!("{base}/{name}")).bearer_auth(token.as_str()),
            "Google operation",
            &[token.as_str()],
        )
        .await?;
    }
    if let Some(e) = op.get("error") {
        return Err(format!("Google create key: {}", error_text(&json!({ "error": e }))));
    }
    let key = str_at(&op, "/response/keyString", "Google create key")?;
    Ok(Created {
        material: Material::single(key),
        provider_ref: op.pointer("/response/name").and_then(Value::as_str).map(String::from),
        old_ref: Some(old_name),
        old_gone: false,
        fields: None,
    })
}

// Anthropic: keys can't be created through the API, but an Admin key can
// disable the old one once the owner has pasted a new one.

async fn anthropic_find(c: &Ctx<'_>) -> Result<Option<String>, String> {
    let (_, pm) = c.parent()?;
    let mut hits = vec![];
    let mut after: Option<String> = None;
    for _ in 0..20 {
        let mut url = format!("{}/organizations/api_keys?limit=1000&status=active", c.ep().anthropic);
        if let Some(a) = &after {
            url.push_str(&format!("&after_id={}", safe_seg(a)?));
        }
        let rb = c
            .app
            .http
            .get(url)
            .header("x-api-key", &pm.value)
            .header("anthropic-version", "2023-06-01");
        let v = send_json(rb, "Anthropic list keys", &[&pm.value]).await?;
        for k in v.get("data").and_then(Value::as_array).into_iter().flatten() {
            let hint = k.get("partial_key_hint").and_then(Value::as_str).unwrap_or("");
            if let Some((head, tail)) = hint.split_once("...")
                && !head.is_empty()
                && !tail.is_empty()
                && c.old.value.starts_with(head)
                && c.old.value.ends_with(tail)
                && let Some(id) = k.get("id").and_then(Value::as_str)
            {
                hits.push(id.to_string());
            }
        }
        if v.get("has_more") != Some(&Value::Bool(true)) {
            break;
        }
        after = v.get("last_id").and_then(Value::as_str).map(String::from);
    }
    Ok(if hits.len() == 1 { hits.pop() } else { None })
}

// ---------------------------------------------------------------- the engine

/// The provider a rotator's managing credential must be.
fn parent_provider_for(rotator: &str) -> Option<&'static str> {
    match rotator {
        "openrouter" => Some("openrouter-management"),
        "tailscale-authkey" => Some("tailscale-oauth"),
        "google-apikey" => Some("google-service-account"),
        "anthropic" => Some("anthropic-admin"),
        "cloudflare" => Some("cloudflare"),
        _ => None,
    }
}

/// Loads a secret's manager, refusing one that isn't owner-only or isn't
/// the kind of credential this rotator expects: a manager that a token could
/// have written, or one for another service, must never be used.
fn load_parent(app: &AppRef, meta: &SecretMeta, rotator: &str) -> ApiResult<Option<(SecretMeta, Material)>> {
    let Some(name) = &meta.parent else { return Ok(None) };
    let pm = app
        .db
        .secret_get(name)?
        .ok_or_else(|| ApiError::bad_request(format!("the manager '{name}' no longer exists")))?;
    let want = parent_provider_for(rotator);
    if !pm.owner_only || want.is_none() || pm.provider.as_deref() != want {
        return Err(ApiError::bad_request(format!(
            "the manager '{name}' must be an owner-only {} key; check it on its page",
            want.and_then(providers::by_id).map(|p| p.name).unwrap_or("managing")
        )));
    }
    let pv = app.reveal(&pm)?;
    let _ = app.db.secret_touch(pm.id);
    Ok(Some((pm, pv)))
}
/// Checks that a new value works: the provider's "who am I" call where
/// there is one, or a sign-in for Azure. Retries a little, because some
/// providers take a few seconds to accept a new key.
async fn check_new(app: &AppRef, p: &Provider, meta: &SecretMeta, m: &Material, retries: bool) -> Result<(), String> {
    let delays: &[u64] = if !retries {
        &[0]
    } else if p.id == "azure-app-secret" {
        &[0, 3, 10, 20]
    } else {
        &[0, 2, 5]
    };
    let mut last = String::new();
    for d in delays {
        tokio::time::sleep(Duration::from_secs(*d)).await;
        if p.id == "azure-app-secret" {
            let c = Ctx {
                app,
                meta,
                old: m,
                parent: None,
            };
            match azure_token(&c, &m.value).await {
                Ok(_) => return Ok(()),
                Err(e) => last = e,
            }
            continue;
        }
        let Some(v) = &p.verify else { return Ok(()) };
        let Some(url) = describe::verify_url(p, v, meta) else {
            return Ok(());
        };
        let url = app.endpoints.rewrite(url);
        let out = describe::verify_with_provider(
            &app.http,
            v,
            url,
            &Creds {
                material: m,
                fields: &meta.fields,
            },
        )
        .await;
        if out.valid() {
            return Ok(());
        }
        last = match out.result.get("status").and_then(Value::as_str) {
            Some("rejected") => "the provider rejected the new key".into(),
            Some("incomplete") => out
                .result
                .get("error")
                .and_then(Value::as_str)
                .unwrap_or("missing parts")
                .to_string(),
            _ => format!("the provider didn't confirm the new key (HTTP {})", out.status),
        };
    }
    Err(last)
}

fn row(app: &AppRef, id: i64) -> ApiResult<RotationRow> {
    app.db.rotation_get(id)?.ok_or_else(|| ApiError::internal("rotation vanished"))
}

/// Makes `new` the current version and decides what happens to the old key.
#[allow(clippy::too_many_arguments)]
fn swap_in(
    app: &AppRef,
    meta: &SecretMeta,
    rot: i64,
    new: &Material,
    provider_ref: Option<&str>,
    fields: Option<Map<String, Value>>,
    old_ref: Option<String>,
    revocable: bool,
    old_gone: bool,
    rotator: Option<&str>,
) -> ApiResult<RotationRow> {
    app.db.rotation_set_rotator(rot, rotator)?;
    if let Some(f) = fields {
        let mut merged = meta.fields.as_object().cloned().unwrap_or_default();
        merged.extend(f);
        app.db.secret_set_settings(
            meta.id,
            &crate::db::Settings {
                fields: Some(Value::Object(merged)),
                ..Default::default()
            },
        )?;
    }
    let version = app.save_version(meta.id, new, provider_ref)?;
    app.db.secret_mark_rotated(meta.id)?;
    app.minted.forget(meta.id);
    let grace = i64::from(app.cfg.rotation.grace_hours) * HOUR_MS;
    if old_gone {
        let _ = app.db.version_delete(meta.id, meta.version);
        app.db.rotation_update(
            rot,
            "done",
            Some(version),
            None,
            None,
            Some("the provider replaced the old value, so it stopped working at once"),
            true,
        )?;
    } else if revocable && old_ref.is_some() {
        let msg = format!("the old key is revoked automatically after {} hours", app.cfg.rotation.grace_hours);
        app.db.rotation_update(
            rot,
            "grace",
            Some(version),
            old_ref.as_deref(),
            Some(now_ms() + grace),
            Some(&msg),
            false,
        )?;
    } else {
        let msg = "delete the old key on the provider's site, then mark this done";
        app.db
            .rotation_update(rot, "manual_revoke", Some(version), None, None, Some(msg), false)?;
    }
    tokio::spawn(describe::run(app.clone(), meta.id, version, true, false));
    row(app, rot)
}

/// Rotates through the provider's API.
pub async fn rotate_auto(app: &AppRef, meta: &SecretMeta, actor: &str) -> ApiResult<RotationRow> {
    let p = provider_of(meta).ok_or_else(|| ApiError::bad_request("the vault doesn't know this key's provider"))?;
    let Rotation::Auto(rotator) = p.rotation else {
        return Err(ApiError::bad_request(
            "this key can't be rotated automatically: paste a new value instead",
        ));
    };
    if !auto_ready(Some(p), meta) {
        let missing = missing_details(Some(p), meta);
        return Err(ApiError::bad_request(if missing.is_empty() {
            format!("set a manager first: {}", p.parent_hint.unwrap_or("a managing credential"))
        } else {
            format!("add these details first: {}", missing.join(", "))
        }));
    }
    let lock = app.minted.lock_for(meta.id);
    let _guard = lock.lock().await;
    let meta = app.db.secret_by_id(meta.id)?.ok_or_else(ApiError::not_found)?;
    if app.db.rotation_active(meta.id)?.is_some() {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            "finish or undo this key's previous rotation first",
        ));
    }
    let start = Instant::now();
    let rot = app.db.rotation_insert(meta.id, "auto", actor, Some(meta.version))?;
    let ev = EventInfo::new("rotate", actor.to_string()).secret(&meta.name);
    match rotate_inner(app, p, rotator, &meta, rot).await {
        Ok(r) => {
            app.record_internal(ev.detail(format!("{rotator}: {}", r.state)), 200, start.elapsed());
            Ok(r)
        }
        Err(e) => {
            app.record_internal(ev.detail(format!("{rotator}: failed")), 502, start.elapsed());
            // Still "running" means nothing was switched: the old key is in use.
            if app.db.rotation_transition(rot, "running", "failed", &e.msg, true)? {
                return Err(ApiError::new(
                    e.status,
                    format!("rotation failed: {}. The old key is still in use.", e.msg),
                ));
            }
            Err(e)
        }
    }
}

async fn rotate_inner(app: &AppRef, p: &Provider, rotator: &str, meta: &SecretMeta, rot: i64) -> ApiResult<RotationRow> {
    let gw = |e: String| ApiError::new(StatusCode::BAD_GATEWAY, e);
    let old = app.reveal(meta)?;
    let parent = load_parent(app, meta, rotator)?;
    if parent.is_none() && p.parent_provider.is_some_and(|pp| pp != p.id) {
        return Err(ApiError::bad_request("set a manager first"));
    }
    let ctx = Ctx {
        app,
        meta,
        old: &old,
        parent,
    };
    let created = create_new(rotator, &ctx).await.map_err(gw)?;
    let mut check_meta = meta.clone();
    if let Some(f) = &created.fields
        && let Some(m) = check_meta.fields.as_object_mut()
    {
        m.extend(f.clone());
    }
    if created.old_gone {
        // The provider already replaced the value: keep the new one whatever
        // happens next, since the old one no longer works.
        let r = swap_in(
            app,
            meta,
            rot,
            &created.material,
            created.provider_ref.as_deref(),
            created.fields.clone(),
            None,
            false,
            true,
            Some(rotator),
        )?;
        if let Err(e) = check_new(app, p, &check_meta, &created.material, true).await {
            let msg = format!("the provider replaced the key and the new value is saved, but it didn't pass the check yet: {e}");
            app.db.rotation_transition(rot, "done", "failed", &msg, true)?;
            return Err(gw(msg));
        }
        return Ok(r);
    }
    if let Err(e) = check_new(app, p, &check_meta, &created.material, true).await {
        // Don't leave an unused key behind.
        if let Some(r) = &created.provider_ref {
            let new_ctx = Ctx {
                app,
                meta,
                old: &created.material,
                parent: load_parent(app, meta, rotator)?,
            };
            let _ = revoke(rotator, &new_ctx, r).await;
        }
        return Err(gw(format!("the new key didn't work: {e}")));
    }
    swap_in(
        app,
        meta,
        rot,
        &created.material,
        created.provider_ref.as_deref(),
        created.fields,
        created.old_ref,
        true,
        false,
        Some(rotator),
    )
}
/// Finishes a rotation the owner did by hand: checks the pasted value,
/// switches over, and arranges for the old key to be revoked.
pub async fn complete_guided(
    app: &AppRef,
    meta: &SecretMeta,
    new: Material,
    fields: Option<Map<String, Value>>,
    skip_check: bool,
    actor: &str,
) -> ApiResult<RotationRow> {
    let lock = app.minted.lock_for(meta.id);
    let _guard = lock.lock().await;
    let meta = app.db.secret_by_id(meta.id)?.ok_or_else(ApiError::not_found)?;
    if app.db.rotation_active(meta.id)?.is_some() {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            "finish or undo this key's previous rotation first (Rotation page)",
        ));
    }
    let old = app.reveal(&meta)?;
    if old.value == new.value {
        return Err(ApiError::bad_request("that's the same value as now: paste the new key"));
    }
    // The provider stays the one the key already has; a pasted value of
    // another kind can't send the manager to a different service.
    let p = meta
        .provider_hint
        .as_deref()
        .or(meta.provider.as_deref())
        .and_then(providers::by_id)
        .or_else(|| providers::resolve(&meta, &new.value));
    let mut check_meta = meta.clone();
    if let Some(f) = &fields
        && let Some(m) = check_meta.fields.as_object_mut()
    {
        m.extend(f.clone());
    }
    if !skip_check
        && let Some(p) = p
        && let Err(e) = check_new(app, p, &check_meta, &new, false).await
    {
        return Err(ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            format!("{e}. Nothing was changed."),
        ));
    }
    let rot = app.db.rotation_insert(meta.id, "guided", actor, Some(meta.version))?;
    // Find the old key's provider ID while we still have the old value.
    let mut old_ref = None;
    let rev = p.and_then(revoker);
    if let Some(r) = rev {
        let parent = load_parent(app, &meta, r).ok().flatten();
        let ctx = Ctx {
            app,
            meta: &check_meta,
            old: &old,
            parent,
        };
        if ctx.parent.is_some() || r == "azure-app-secret" {
            old_ref = find_old_ref(r, &ctx).await.ok().flatten();
        }
    }
    let old_gone = p.is_some_and(|p| matches!(p.rotation, Rotation::Auto("cloudflare")));
    swap_in(
        app,
        &meta,
        rot,
        &new,
        None,
        fields,
        old_ref.clone(),
        rev.is_some() && old_ref.is_some(),
        old_gone,
        rev,
    )
}

/// Revokes the old key of a rotation whose grace period is over.
pub async fn finish(app: &AppRef, due: &RotationRow) {
    let Ok(Some(meta)) = app.db.secret_by_id(due.secret_id) else {
        return;
    };
    let lock = app.minted.lock_for(meta.id);
    let _guard = lock.lock().await;
    // Re-read under the lock: an undo may have just happened.
    let Ok(Some(r)) = app.db.rotation_get(due.id) else { return };
    let Ok(Some(meta)) = app.db.secret_by_id(meta.id) else { return };
    if r.state != "grace" {
        return;
    }
    let manual = |msg: &str| {
        let _ = app.db.rotation_transition(r.id, "grace", "manual_revoke", msg, false);
    };
    let (Some(old_ref), Some(rotator)) = (r.old_ref.as_deref(), r.rotator.as_deref()) else {
        return manual("delete the old key on the provider's site, then mark this done");
    };
    if Some(meta.version) != r.new_version {
        return manual(
            "the key changed after this rotation, so the vault won't revoke anything; delete the old key by hand if it still exists",
        );
    }
    let start = Instant::now();
    let ev = EventInfo::new("revoke", ACTOR_SCHEDULER).secret(&meta.name);
    let Ok(current) = app.reveal(&meta) else { return }; // sealed; try again later
    let parent = match load_parent(app, &meta, rotator) {
        Ok(p) => p,
        Err(e) => {
            return manual(&format!(
                "couldn't revoke the old key: {}; delete it on the provider's site, then mark this done",
                e.msg
            ));
        }
    };
    let ctx = Ctx {
        app,
        meta: &meta,
        old: &current,
        parent,
    };
    match revoke(rotator, &ctx, old_ref).await {
        Ok(()) => {
            if app
                .db
                .rotation_transition(r.id, "grace", "done", "the old key was revoked", true)
                .unwrap_or(false)
                && let Some(v) = r.old_version
            {
                let _ = app.db.version_delete(meta.id, v);
            }
            app.record_internal(ev.detail(rotator), 200, start.elapsed());
        }
        Err(e) => {
            if now_ms() - r.revoke_after.unwrap_or(0) > DAY_MS {
                manual(&format!(
                    "couldn't revoke the old key ({e}); delete it on the provider's site, then mark this done"
                ));
            } else {
                let _ = app.db.rotation_retry(r.id, now_ms() + HOUR_MS, &format!("retrying: {e}"));
            }
            app.record_internal(ev.detail(format!("{rotator}: failed")), 502, start.elapsed());
        }
    }
}

/// Undoes a rotation that hasn't finished: the old value becomes current again.
pub async fn rollback(app: &AppRef, id: i64) -> ApiResult<RotationRow> {
    let first = app.db.rotation_get(id)?.ok_or_else(ApiError::not_found)?;
    let lock = app.minted.lock_for(first.secret_id);
    let _guard = lock.lock().await;
    let r = app.db.rotation_get(id)?.ok_or_else(ApiError::not_found)?;
    if !matches!(r.state.as_str(), "grace" | "manual_revoke") {
        return Err(ApiError::bad_request("only a rotation still in its overlap period can be undone"));
    }
    let (Some(old_v), Some(new_v)) = (r.old_version, r.new_version) else {
        return Err(ApiError::bad_request("nothing to roll back to"));
    };
    let meta = app.db.secret_by_id(r.secret_id)?.ok_or_else(ApiError::not_found)?;
    if meta.version != new_v {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            "the key has changed since this rotation, so it can't be undone",
        ));
    }
    let old = app.reveal_version(&meta, old_v)?;
    if !app.db.rotation_transition(id, &r.state, "rolled_back", "rolling back", true)? {
        return Err(ApiError::new(StatusCode::CONFLICT, "this rotation changed meanwhile; reload"));
    }
    if !app.db.version_restore(meta.id, old_v)? {
        return Err(ApiError::bad_request("the old value is no longer stored"));
    }
    let mac = app.vault.fingerprint(old.value.as_bytes())?;
    app.db.secret_set_value_meta(meta.id, &old.extra_names(), &mac)?;
    app.minted.forget(meta.id);
    // Revoke the key we created, if the provider lets us.
    let mut msg = "rolled back: the old key is current again".to_string();
    let new_ref = app.db.version_ciphertext(meta.id, new_v)?.and_then(|v| v.provider_ref);
    if r.mode == "auto"
        && let (Some(rot), Some(nr)) = (r.rotator.as_deref(), new_ref)
    {
        match load_parent(app, &meta, rot) {
            Ok(parent) => {
                let ctx = Ctx {
                    app,
                    meta: &meta,
                    old: &old,
                    parent,
                };
                match revoke(rot, &ctx, &nr).await {
                    Ok(()) => msg.push_str("; the new key was revoked"),
                    Err(e) => msg.push_str(&format!("; couldn't revoke the new key ({e}), delete it on the provider's site")),
                }
            }
            Err(e) => msg.push_str(&format!(
                "; couldn't revoke the new key ({}), delete it on the provider's site",
                e.msg
            )),
        }
    }
    let _ = app.db.version_delete(meta.id, new_v);
    app.db.rotation_update(r.id, "rolled_back", None, None, None, Some(&msg), true)?;
    tokio::spawn(describe::run(app.clone(), meta.id, old_v, true, false));
    row(app, id)
}

/// The owner deleted the old key by hand.
pub fn mark_done(app: &AppRef, id: i64) -> ApiResult<RotationRow> {
    let r = app.db.rotation_get(id)?.ok_or_else(ApiError::not_found)?;
    if !matches!(r.state.as_str(), "manual_revoke" | "grace") {
        return Err(ApiError::bad_request("this rotation isn't waiting for the old key to be deleted"));
    }
    if app
        .db
        .rotation_transition(id, &r.state, "done", "the old key was deleted by hand", true)?
        && let Some(v) = r.old_version
    {
        let _ = app.db.version_delete(r.secret_id, v);
    }
    row(app, id)
}
/// Runs every minute: revokes old keys whose grace period is over, and
/// rotates keys whose schedule is due.
pub async fn tick(app: &AppRef) {
    crate::stations::prune(app);
    crate::import_api::prune(app);
    if app.vault.is_sealed() {
        return;
    }
    for r in app.db.rotations_due(now_ms()).unwrap_or_default() {
        finish(app, &r).await;
    }
    if !app.cfg.rotation.scheduled {
        return;
    }
    let latest: HashMap<i64, RotationRow> = app
        .db
        .rotations_latest()
        .unwrap_or_default()
        .into_iter()
        .map(|r| (r.secret_id, r))
        .collect();
    let all = app.db.secret_list().unwrap_or_default();
    for meta in all.iter().cloned() {
        let p = provider_of(&meta);
        if !matches!(p.map(|p| p.rotation), Some(Rotation::Auto(_))) || !auto_ready(p, &meta) || manager_problem(p, &meta, &all).is_some() {
            continue;
        }
        if next_due(&meta).is_none_or(|d| d > now_ms()) {
            continue;
        }
        // After a failure, wait a day before trying again.
        if let Some(l) = latest.get(&meta.id)
            && (matches!(l.state.as_str(), "running" | "grace" | "manual_revoke")
                || l.state == "failed" && now_ms() - l.finished_at.unwrap_or(0) < DAY_MS)
        {
            continue;
        }
        if let Err(e) = rotate_auto(app, &meta, ACTOR_SCHEDULER).await {
            tracing::warn!("scheduled rotation of {} failed: {}", meta.name, e.msg);
        }
    }
}

// ---------------------------------------------------------------- attention

/// Things the owner should look at, most urgent first.
/// Everything that needs the owner's attention, before acknowledgements.
/// Each item carries `kind` and a fingerprint `fp` of the situation, so an OK
/// covers exactly that situation and the item returns when it changes.
fn attention_items(app: &AppRef) -> ApiResult<Vec<(i64, Value)>> {
    let now = now_ms();
    let all = app.db.secret_list()?;
    let latest: HashMap<i64, RotationRow> = app.db.rotations_latest()?.into_iter().map(|r| (r.secret_id, r)).collect();
    // Values reported as seen in a prompt or transcript (spandeck), for the version still in use.
    let reports: HashMap<i64, _> = app.db.exposure_reports_latest()?.into_iter().map(|r| (r.secret_id, r)).collect();
    let mut out = vec![];
    let mut add = |m: &SecretMeta, kind: &str, fp: String, level: &str, reason: String, action: &str| {
        out.push((
            m.id,
            json!({ "secret": m.name, "kind": kind, "fp": fp, "level": level, "reason": reason, "action": action }),
        ));
    };
    for m in &all {
        let p = provider_of(m);
        let ver = format!("v{}", m.version);
        if let Some(e) = m.expires_at {
            if e <= now {
                add(m, "expired", e.to_string(), "critical", "expired".into(), "rotate");
            } else if e - now < 30 * DAY_MS {
                add(
                    m,
                    "expiring",
                    e.to_string(),
                    "warning",
                    format!("expires in {} days", (e - now) / DAY_MS + 1),
                    "rotate",
                );
            }
        }
        let status = m.facts.pointer("/verification/status").and_then(Value::as_str);
        if status == Some("rejected") {
            add(
                m,
                "rejected",
                ver.clone(),
                "critical",
                "the provider rejected it the last time it was checked".into(),
                "rotate",
            );
        }
        if let Some(x) = &m.exposed {
            add(m, "exposed", ver.clone(), "critical", x.clone(), "rotate");
        }
        if let Some(r) = latest.get(&m.id) {
            match r.state.as_str() {
                "failed" => add(
                    m,
                    "rotation_failed",
                    r.id.to_string(),
                    "critical",
                    format!("the last rotation failed: {}", r.message.as_deref().unwrap_or("")),
                    "rotate",
                ),
                "manual_revoke" => add(
                    m,
                    "delete_old",
                    r.id.to_string(),
                    "warning",
                    "rotated; delete the old key on the provider's site".into(),
                    "done",
                ),
                _ => {}
            }
        }
        if let Some(due) = next_due(m).filter(|d| *d <= now)
            && !matches!(p.map(|p| p.rotation), Some(Rotation::Never(_) | Rotation::Minted(_)))
        {
            add(m, "due", due.to_string(), "warning", "due for rotation".into(), "rotate");
        }
        if let Some(miss) = m.facts.get("missing").and_then(Value::as_array).filter(|a| !a.is_empty()) {
            let labels: Vec<&str> = miss.iter().filter_map(Value::as_str).collect();
            add(
                m,
                "missing",
                format!("{ver}:{}", labels.join(",")),
                "warning",
                format!("missing: {}", labels.join(", ")),
                "edit",
            );
        }
        if let Some(mac) = &m.value_mac
            && let Some(o) = all.iter().find(|o| o.id < m.id && o.value_mac.as_ref() == Some(mac))
        {
            add(
                m,
                "duplicate",
                format!("{ver}:{}", o.id),
                "info",
                format!("same value as {}", o.name),
                "delete",
            );
        }
        if let Some(r) = reports.get(&m.id)
            && r.version == m.version
        {
            let reason = format!(
                "seen in {} on {} ({}, reported by {}); replace it",
                r.place,
                r.node,
                crate::timeutil::format_date(r.reported_at),
                r.reporter
            );
            add(m, "reported", r.id.to_string(), "critical", reason, "rotate");
        }
        if let Some(problem) = manager_problem(p, m, &all) {
            add(
                m,
                "manager",
                problem.clone(),
                "warning",
                format!("can't rotate automatically: {problem}"),
                "edit",
            );
        } else if matches!(p.map(|p| p.rotation), Some(Rotation::Auto(_))) && !auto_ready(p, m) && missing_details(p, m).is_empty() {
            add(
                m,
                "no_manager",
                p.map(|p| p.id).unwrap_or("").to_string(),
                "info",
                format!(
                    "set a manager to rotate it automatically: {}",
                    p.and_then(|p| p.parent_hint).unwrap_or("")
                ),
                "edit",
            );
        }
    }
    let rank = |v: &Value| match v["level"].as_str() {
        Some("critical") => 0,
        Some("warning") => 1,
        _ => 2,
    };
    out.sort_by_key(|(_, v)| rank(v));
    Ok(out)
}

/// (still needing attention, OK'd by the owner). Dismissed items carry `dismissed_at`.
pub fn attention_split(app: &AppRef) -> ApiResult<(Vec<Value>, Vec<Value>)> {
    let acks = app.db.acks_all()?;
    let (mut active, mut dismissed) = (vec![], vec![]);
    for (id, mut v) in attention_items(app)? {
        let kind = v["kind"].as_str().unwrap_or("").to_string();
        match acks.get(&(id, kind)) {
            Some((fp, at)) if v["fp"].as_str() == Some(fp.as_str()) => {
                v["dismissed_at"] = json!(at);
                dismissed.push(v);
            }
            _ => active.push(v),
        }
    }
    Ok((active, dismissed))
}

/// What still needs attention (OK'd items left out).
pub fn attention(app: &AppRef) -> ApiResult<Vec<Value>> {
    Ok(attention_split(app)?.0)
}

/// OKs every current item for one secret. Returns the kinds acknowledged.
pub fn dismiss(app: &AppRef, secret_id: i64, name: &str) -> ApiResult<Vec<String>> {
    let mut kinds = vec![];
    for (id, v) in attention_items(app)? {
        if id == secret_id && v["secret"] == name {
            let (kind, fp) = (v["kind"].as_str().unwrap_or(""), v["fp"].as_str().unwrap_or(""));
            app.db.ack_set(id, kind, fp)?;
            kinds.push(kind.to_string());
        }
    }
    Ok(kinds)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rs256_signatures_verify() {
        use aws_lc_rs::encoding::AsDer;
        let kp = signature::RsaKeyPair::generate(aws_lc_rs::rsa::KeySize::Rsa2048).unwrap();
        let der = kp.as_der().unwrap();
        let body = base64::engine::general_purpose::STANDARD.encode(der.as_ref());
        let pem = format!("-----BEGIN PRIVATE KEY-----\n{body}\n-----END PRIVATE KEY-----\n");
        let jwt = sign_rs256(&pem, &json!({ "iss": "123" }), Some("kid1")).unwrap();
        let parts: Vec<&str> = jwt.split('.').collect();
        assert_eq!(parts.len(), 3);
        let header: Value = serde_json::from_slice(&base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(parts[0]).unwrap()).unwrap();
        assert_eq!(header, json!({ "alg": "RS256", "typ": "JWT", "kid": "kid1" }));
        let sig = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(parts[2]).unwrap();
        let pk = signature::UnparsedPublicKey::new(
            &signature::RSA_PKCS1_2048_8192_SHA256,
            aws_lc_rs::signature::KeyPair::public_key(&kp).as_ref(),
        );
        pk.verify(format!("{}.{}", parts[0], parts[1]).as_bytes(), &sig)
            .expect("signature verifies");
        assert!(sign_rs256("not a key", &json!({}), None).is_err());
    }

    #[test]
    fn helpers() {
        assert_eq!(tailscale_key_id("tskey-auth-kAbC123CNTRL-secretpart"), Some("kAbC123CNTRL".into()));
        assert_eq!(tailscale_key_id("tskey-client-x-y"), None);
        assert!(safe_seg("apikey_01ABC").is_ok());
        assert!(safe_seg("../x").is_err());
        assert!(safe_seg("a/b").is_err());
        assert!(valid_google_key_name("projects/123/locations/global/keys/abc-1"));
        assert!(!valid_google_key_name("projects/123/locations/global/keys/../../x"));
        assert_eq!(form(&[("a", "b c"), ("d", "&=")]), "a=b+c&d=%26%3D");
    }
}
