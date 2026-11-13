//! HTTP routes, the request guard and the REST handlers.

use axum::{
    Extension, Json, Router,
    body::{Body, Bytes},
    extract::{ConnectInfo, DefaultBodyLimit, Path, Query, RawQuery, Request, State},
    http::{HeaderMap, HeaderValue, Method, StatusCode, header},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{any, delete, get, post},
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::{net::SocketAddr, time::Instant};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::app::{ApiError, ApiResult, AppRef, AutoUnlock, EventInfo, cookie, with_event};
use crate::auth::{self, Principal, Scope};
use crate::dashboard;
use crate::db::{NewValue, SecretMeta, Settings};
use crate::describe;
use crate::identity::Caller;
use crate::material::{self, Extra, Material};
use crate::mcp;
use crate::providers;
use crate::proxy;
use crate::vault::{Vault, VaultError};
use crate::web;

const MAX_VALUE_BYTES: usize = 64 * 1024;
const MAX_BODY_BYTES: usize = 10 * 1024 * 1024;
const MIN_PASSPHRASE: usize = 12;

pub fn router(app: AppRef) -> Router {
    Router::new()
        .route("/", get(web::index))
        .route("/app.js", get(web::script))
        .route("/app.css", get(web::style))
        .route("/favicon.svg", get(web::favicon))
        .route("/v1/status", get(status))
        .route("/v1/setup", post(setup))
        .route("/v1/session", get(session_get).post(login).delete(logout))
        .route("/v1/session/confirm", post(confirm_passphrase))
        .route("/v1/seal", post(seal))
        .route("/v1/passphrase", post(change_passphrase))
        .route("/v1/secrets", get(list_secrets).post(create_secret))
        .route("/v1/secrets/{name}", get(get_secret).patch(update_secret).delete(delete_secret))
        .route("/v1/secrets/{name}/value", get(read_value))
        .route("/v1/secrets/{name}/describe", post(redescribe))
        .route("/v1/proxy/{name}/{*path}", any(proxy_request))
        .route("/v1/secrets/{name}/rotate", post(rotate_secret))
        .route("/v1/rotations", get(list_rotations))
        .route("/v1/rotations/{id}/rollback", post(rollback_rotation))
        .route("/v1/rotations/{id}/done", post(rotation_done))
        .route("/v1/attention", get(attention))
        .route("/v1/attention/dismiss", post(attention_dismiss))
        .route("/v1/attention/restore", post(attention_restore))
        .route("/v1/providers", get(list_providers))
        .route("/v1/import/preview", post(crate::import_api::preview))
        .route("/v1/import/commit", post(crate::import_api::commit))
        .route("/v1/tokens", get(list_tokens).post(create_token))
        .route("/v1/tokens/{id}", delete(revoke_token).patch(update_token))
        .route("/v1/tokens/self", get(crate::stations::token_self))
        .route("/v1/tokens/self/rotate", post(crate::stations::rotate_self))
        .route("/v1/tokens/self/rotation", axum::routing::put(crate::stations::set_rotation))
        .route("/v1/token-requests", get(crate::stations::list).post(crate::stations::open))
        .route("/v1/token-requests/{id}", get(crate::stations::collect))
        .route("/v1/token-requests/{id}/approve", post(crate::stations::approve))
        .route("/v1/token-requests/{id}/deny", post(crate::stations::deny))
        .route("/v1/attention/report", post(crate::stations::report))
        .route("/v1/dashboard", get(dashboard_handler))
        .route("/v1/events", get(events))
        .route("/v1/audit/verify", get(audit_verify))
        .route("/mcp", post(mcp::handle).get(mcp_get).delete(mcp_get))
        .fallback(|| async { ApiError::new(StatusCode::NOT_FOUND, "not found") })
        .layer(middleware::from_fn_with_state(app.clone(), guard))
        .layer(DefaultBodyLimit::max(MAX_BODY_BYTES))
        .with_state(app)
}

// ---------------------------------------------------------------- guard

const CSP: &str = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; \
    connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'";

fn host_allowed(app: &AppRef, host: &str) -> bool {
    let host = host.to_ascii_lowercase();
    let name = app.cfg.hostname.to_ascii_lowercase();
    host == name || host == format!("{name}:{}", app.cfg.listen.port())
}

/// Runs on every request: Host and Origin checks, Tailscale identity, event
/// recording with timing, and security headers.
async fn guard(State(app): State<AppRef>, ConnectInfo(addr): ConnectInfo<SocketAddr>, mut req: Request, next: Next) -> Response {
    let start = Instant::now();
    let host = req
        .headers()
        .get(header::HOST)
        .and_then(|v| v.to_str().ok())
        .map(String::from)
        .or_else(|| req.uri().authority().map(|a| a.to_string()))
        .unwrap_or_default();
    if !host_allowed(&app, &host) {
        return secure(ApiError::new(StatusCode::MISDIRECTED_REQUEST, "unknown host").into_response(), true);
    }
    if let Some(origin) = req.headers().get(header::ORIGIN)
        && origin.as_bytes() != app.origin.as_bytes()
    {
        return secure(ApiError::forbidden("cross-origin requests are not allowed").into_response(), true);
    }
    let caller = match app.resolver.resolve(addr).await {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!("rejecting {addr}: {e}");
            return secure(ApiError::forbidden("only devices on the tailnet may connect").into_response(), true);
        }
    };
    let path = req.uri().path().to_string();
    let is_api = path.starts_with("/v1/") || path == "/mcp";
    req.extensions_mut().insert(caller.clone());

    let mut resp = next.run(req).await;
    let status = resp.status().as_u16();
    let latency = start.elapsed();
    if let Some(ev) = resp.extensions_mut().remove::<EventInfo>() {
        app.record(&caller, ev, status, latency);
    } else if is_api && matches!(status, 401 | 403 | 429) && app.may_log_denied(caller.ip) {
        app.record(
            &caller,
            EventInfo::new("denied", "unknown").detail(truncate(&path, 200)),
            status,
            latency,
        );
    }
    secure(resp, is_api)
}

fn secure(mut resp: Response, no_store: bool) -> Response {
    let h = resp.headers_mut();
    let set = |h: &mut HeaderMap, k: &'static str, v: &'static str| {
        h.insert(k, HeaderValue::from_static(v));
    };
    set(h, "content-security-policy", CSP);
    set(h, "x-content-type-options", "nosniff");
    set(h, "x-frame-options", "DENY");
    set(h, "referrer-policy", "no-referrer");
    set(h, "strict-transport-security", "max-age=31536000");
    set(h, "cross-origin-opener-policy", "same-origin");
    set(h, "cross-origin-resource-policy", "same-origin");
    set(h, "permissions-policy", "camera=(), microphone=(), geolocation=(), usb=()");
    if no_store {
        set(h, "cache-control", "no-store");
    }
    resp
}

pub(crate) fn truncate(s: &str, n: usize) -> String {
    s.chars().take(n).collect()
}

// ---------------------------------------------------------------- validation

pub fn valid_name(n: &str) -> bool {
    (1..=128).contains(&n.len()) && n.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'))
}

pub(crate) fn valid_glob(g: &str) -> bool {
    (1..=128).contains(&g.len()) && g.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.' | '*'))
}

fn valid_node(n: &str) -> bool {
    (1..=253).contains(&n.len()) && n.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '.' | '_'))
}

pub(crate) fn clean_tags(tags: Option<Vec<String>>) -> ApiResult<Option<Vec<String>>> {
    let Some(tags) = tags else { return Ok(None) };
    if tags.len() > 20 {
        return Err(ApiError::bad_request("at most 20 tags"));
    }
    let mut out = Vec::new();
    for t in tags {
        let t = t.trim().to_string();
        if t.is_empty() {
            continue;
        }
        if t.len() > 40
            || !t
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.' | ':' | ' '))
        {
            return Err(ApiError::bad_request(format!("invalid tag '{}'", truncate(&t, 40))));
        }
        if !out.contains(&t) {
            out.push(t);
        }
    }
    Ok(Some(out))
}

pub(crate) fn check_notes(n: &Option<String>) -> ApiResult<()> {
    if n.as_ref().is_some_and(|n| n.chars().count() > 4000) {
        return Err(ApiError::bad_request("notes are limited to 4000 characters"));
    }
    Ok(())
}

fn check_value(v: &str) -> ApiResult<()> {
    if v.trim().is_empty() {
        return Err(ApiError::bad_request("value is empty"));
    }
    if v.len() > MAX_VALUE_BYTES {
        return Err(ApiError::bad_request("value is larger than 64 KiB"));
    }
    Ok(())
}

pub(crate) fn owner(app: &AppRef, headers: &HeaderMap, caller: &Caller) -> ApiResult<Principal> {
    let p = app.authenticate(headers, caller)?;
    if !p.is_owner() {
        return Err(ApiError::forbidden("this needs the owner's web session"));
    }
    Ok(p)
}

/// The secret the describer sends to Anthropic: only the owner may create,
/// rename into or overwrite it, so a token can't redirect another key there.
fn protect_describer_key(app: &AppRef, p: &Principal, name: &str, ev: &EventInfo) -> ApiResult<()> {
    if !p.is_owner() && app.cfg.describe.claude_secret.as_deref() == Some(name) {
        return Err(ApiError::forbidden(format!("only the owner can set {name}")).event(ev.clone().detail("describer key denied")));
    }
    Ok(())
}

/// Whether rotation depends on this key's value: it rotates or renews itself,
/// has a manager, or manages another key.
fn managed(app: &AppRef, m: &SecretMeta) -> ApiResult<bool> {
    let rotates = m
        .provider
        .as_deref()
        .and_then(providers::by_id)
        .is_some_and(|p| matches!(p.rotation, providers::Rotation::Auto(_) | providers::Rotation::Minted(_)));
    Ok(rotates || m.parent.is_some() || app.db.secret_is_parent(&m.name)?)
}

/// Tokens never learn that an owner-only secret exists.
fn require_use(p: &Principal, meta: &SecretMeta, ev: &EventInfo) -> ApiResult<()> {
    if p.may_use(meta) {
        Ok(())
    } else {
        Err(ApiError::not_found().event(ev.clone().detail("owner-only")))
    }
}

const KINDS: &[&str] = &["api_key", "password", "private_key", "other"];
const MAX_FIELD_LEN: usize = 500;

pub(crate) fn clean_fields(f: &serde_json::Map<String, serde_json::Value>) -> ApiResult<serde_json::Value> {
    if f.len() > 12 {
        return Err(ApiError::bad_request("at most 12 fields"));
    }
    let mut out = serde_json::Map::new();
    for (k, v) in f {
        if !material::valid_part_name(k) {
            return Err(ApiError::bad_request(format!("invalid field name '{}'", truncate(k, 40))));
        }
        let v = v.as_str().ok_or_else(|| ApiError::bad_request("field values must be text"))?.trim();
        if v.len() > MAX_FIELD_LEN || v.chars().any(char::is_control) {
            return Err(ApiError::bad_request(format!("field '{k}' is too long or has control characters")));
        }
        if !v.is_empty() {
            out.insert(k.clone(), json!(v));
        }
    }
    Ok(serde_json::Value::Object(out))
}

pub(crate) fn check_extras(extras: &[Extra]) -> ApiResult<()> {
    if extras.len() > material::MAX_EXTRAS {
        return Err(ApiError::bad_request(format!("at most {} extra parts", material::MAX_EXTRAS)));
    }
    let mut total = 0;
    for e in extras {
        if !material::valid_part_name(&e.name) {
            return Err(ApiError::bad_request(format!("invalid part name '{}'", truncate(&e.name, 40))));
        }
        total += e.value.len();
    }
    if total > MAX_VALUE_BYTES {
        return Err(ApiError::bad_request("extra parts are larger than 64 KiB"));
    }
    Ok(())
}

fn require(p: &Principal, scope: Scope, secret: &str, ev: &EventInfo) -> ApiResult<()> {
    if p.allows(scope, secret) {
        Ok(())
    } else {
        Err(ApiError::forbidden(format!("{} may not {} '{}'", p.label(), scope.as_str(), secret)).event(ev.clone().detail("scope denied")))
    }
}

// ---------------------------------------------------------------- session & vault

#[derive(Deserialize, Zeroize, ZeroizeOnDrop)]
struct PassBody {
    passphrase: String,
}

#[derive(Deserialize, Zeroize, ZeroizeOnDrop)]
struct ChangePassBody {
    current: String,
    new: String,
}

async fn status(State(app): State<AppRef>, Extension(caller): Extension<Caller>) -> ApiResult {
    // Anyone on the tailnet can ask: tell them only that this is AgentVault,
    // its version and whether it is set up and unlocked (spandeck's discovery
    // and vault state need no more). The owner's devices get the full picture.
    if !app.is_owner_device(&caller) {
        return Ok(Json(json!({
            "service": "agentvault",
            "version": env!("CARGO_PKG_VERSION"),
            "initialized": Vault::is_initialized(&app.db)?,
            "sealed": app.vault.is_sealed(),
            "owner_device": false,
            "caller": { "node": caller.node, "user": caller.user, "tags": caller.tags },
        }))
        .into_response());
    }
    let claude_ready = match &app.cfg.describe.claude_secret {
        Some(n) => app.db.secret_get(n)?.is_some(),
        None => false,
    };
    Ok(Json(json!({
        "service": "agentvault",
        "initialized": Vault::is_initialized(&app.db)?,
        "sealed": app.vault.is_sealed(),
        "caller": { "node": caller.node, "user": caller.user, "tags": caller.tags },
        "owner_device": app.is_owner_device(&caller),
        "hostname": app.cfg.hostname,
        "origin": app.origin,
        "describer": {
            "claude_secret": app.cfg.describe.claude_secret,
            "claude_ready": claude_ready,
            "model": app.cfg.describe.model,
            "verify_with_provider": app.cfg.describe.verify_with_provider,
        },
        "rotation": { "scheduled": app.cfg.rotation.scheduled, "grace_hours": app.cfg.rotation.grace_hours },
        "auto_unlock": app.auto_unlock.label(),
        "version": env!("CARGO_PKG_VERSION"),
    }))
    .into_response())
}

fn session_response(app: &AppRef, caller: &Caller, ev: EventInfo) -> Response {
    let (cookie_value, csrf) = app.sessions.create(&caller.node_id);
    let mut resp = with_event(Json(json!({ "signed_in": true, "csrf": csrf })), ev);
    let c = format!(
        "{}={cookie_value}; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=43200",
        auth::SESSION_COOKIE
    );
    resp.headers_mut()
        .insert(header::SET_COOKIE, HeaderValue::from_str(&c).expect("ascii cookie"));
    resp
}

async fn setup(State(app): State<AppRef>, Extension(caller): Extension<Caller>, Json(body): Json<PassBody>) -> ApiResult {
    let ev = EventInfo::new("vault.setup", caller.user.clone());
    if !app.is_owner_device(&caller) {
        return Err(ApiError::forbidden("only the owner's devices can set up the vault").event(ev));
    }
    if body.passphrase.chars().count() < MIN_PASSPHRASE {
        return Err(ApiError::bad_request(format!(
            "use a passphrase of at least {MIN_PASSPHRASE} characters"
        )));
    }
    let _permit = app.kdf_gate.acquire().await.map_err(ApiError::internal)?;
    let a = app.clone();
    let pass = Zeroizing::new(body.passphrase.clone());
    tokio::task::spawn_blocking(move || a.vault.initialize(&a.db, &pass, a.kdf))
        .await
        .map_err(ApiError::internal)??;
    Ok(session_response(&app, &caller, ev))
}

async fn session_get(State(app): State<AppRef>, Extension(caller): Extension<Caller>, headers: HeaderMap) -> ApiResult {
    let info = cookie(&headers, auth::SESSION_COOKIE)
        .filter(|_| app.is_owner_device(&caller))
        .and_then(|c| app.sessions.check(c, &caller.node_id));
    Ok(match info {
        Some(s) => Json(json!({ "signed_in": true, "csrf": s.csrf })).into_response(),
        None => Json(json!({ "signed_in": false })).into_response(),
    })
}

async fn login(State(app): State<AppRef>, Extension(caller): Extension<Caller>, Json(body): Json<PassBody>) -> ApiResult {
    let ev = EventInfo::new("login", caller.user.clone());
    if !app.is_owner_device(&caller) {
        return Err(ApiError::forbidden("only the owner's devices can sign in").event(ev.detail("not an owner device")));
    }
    check_passphrase(&app, &caller, &body.passphrase, &ev).await?;
    Ok(session_response(&app, &caller, ev))
}

/// Verifies the passphrase (unsealing if needed) under the attempt limiter.
async fn check_passphrase(app: &AppRef, caller: &Caller, passphrase: &str, ev: &EventInfo) -> ApiResult<()> {
    if let Err(secs) = app.limiter.begin(caller.ip) {
        return Err(ApiError::new(
            StatusCode::TOO_MANY_REQUESTS,
            format!("too many wrong passphrases; try again in {secs}s"),
        )
        .event(ev.clone().detail("locked out")));
    }
    let _permit = app.kdf_gate.acquire().await.map_err(ApiError::internal)?;
    let a = app.clone();
    let pass = Zeroizing::new(passphrase.to_string());
    match tokio::task::spawn_blocking(move || a.vault.unlock(&a.db, &pass))
        .await
        .map_err(ApiError::internal)?
    {
        Ok(()) => {
            app.limiter.success(caller.ip);
            Ok(())
        }
        Err(VaultError::BadPassphrase) => Err(ApiError::unauthorized("wrong passphrase").event(ev.clone().detail("wrong passphrase"))),
        Err(e) => Err(e.into()),
    }
}

/// Re-enters the passphrase to unlock sensitive actions for a few minutes.
async fn confirm_passphrase(
    State(app): State<AppRef>,
    Extension(caller): Extension<Caller>,
    headers: HeaderMap,
    Json(body): Json<PassBody>,
) -> ApiResult {
    let Principal::Owner { session, .. } = owner(&app, &headers, &caller)? else {
        return Err(ApiError::forbidden("owner session required"));
    };
    let ev = EventInfo::new("confirm", "owner (web)");
    // A wrong passphrase here must not look like an expired session to the UI.
    check_passphrase(&app, &caller, &body.passphrase, &ev).await.map_err(|e| {
        if e.status == StatusCode::UNAUTHORIZED {
            ApiError {
                status: StatusCode::FORBIDDEN,
                ..e
            }
        } else {
            e
        }
    })?;
    app.sessions.reverify(&session);
    Ok(with_event(
        Json(json!({ "confirmed": true, "valid_for_secs": auth::FRESH_FOR.as_secs() })),
        ev,
    ))
}

async fn logout(State(app): State<AppRef>, Extension(caller): Extension<Caller>, headers: HeaderMap) -> ApiResult {
    if let Principal::Owner { session, .. } = owner(&app, &headers, &caller)? {
        app.sessions.remove(&session);
    }
    let mut resp = with_event(Json(json!({ "signed_in": false })), EventInfo::new("logout", "owner (web)"));
    let c = format!("{}=; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=0", auth::SESSION_COOKIE);
    resp.headers_mut()
        .insert(header::SET_COOKIE, HeaderValue::from_str(&c).expect("ascii"));
    Ok(resp)
}

async fn seal(State(app): State<AppRef>, Extension(caller): Extension<Caller>, headers: HeaderMap) -> ApiResult {
    owner(&app, &headers, &caller)?;
    app.vault.seal();
    app.minted.clear();
    app.imports.lock().unwrap_or_else(|p| p.into_inner()).clear();
    app.sessions.clear();
    Ok(with_event(
        Json(json!({ "sealed": true })),
        EventInfo::new("vault.seal", "owner (web)"),
    ))
}

async fn change_passphrase(
    State(app): State<AppRef>,
    Extension(caller): Extension<Caller>,
    headers: HeaderMap,
    Json(body): Json<ChangePassBody>,
) -> ApiResult {
    let Principal::Owner { session, .. } = owner(&app, &headers, &caller)? else {
        return Err(ApiError::forbidden("owner session required"));
    };
    let ev = EventInfo::new("vault.passphrase", "owner (web)");
    if body.new.chars().count() < MIN_PASSPHRASE {
        return Err(ApiError::bad_request(format!(
            "use a passphrase of at least {MIN_PASSPHRASE} characters"
        )));
    }
    if let Err(secs) = app.limiter.begin(caller.ip) {
        return Err(ApiError::new(
            StatusCode::TOO_MANY_REQUESTS,
            format!("too many wrong passphrases; try again in {secs}s"),
        ));
    }
    let _permit = app.kdf_gate.acquire().await.map_err(ApiError::internal)?;
    let a = app.clone();
    let ip = caller.ip;
    let (cur, new) = (Zeroizing::new(body.current.clone()), Zeroizing::new(body.new.clone()));
    // Everything after the change happens in the blocking task too: it runs to
    // completion even if the browser goes away mid-request, so other sessions
    // are always signed out and the automatic-unlock state stays accurate.
    let stale = tokio::task::spawn_blocking(move || {
        a.vault.change_passphrase(&a.db, &cur, &new, a.kdf)?;
        a.limiter.success(ip);
        a.sessions.clear_except(&session);
        // Does the stored boot passphrase still match?
        let mut stale = false;
        if a.auto_unlock.get() != AutoUnlock::OFF {
            stale = a
                .cfg
                .unlock_passphrase()
                .is_none_or(|stored| crate::crypto::sha256(stored.as_bytes()) != crate::crypto::sha256(new.as_bytes()));
            a.auto_unlock.set(if stale { AutoUnlock::STALE } else { AutoUnlock::ON });
        }
        Ok::<_, crate::vault::VaultError>(stale)
    })
    .await
    .map_err(ApiError::internal)?
    .map_err(|e| {
        let e = ApiError::from(e);
        // Wrong current passphrase: a 403, so the UI doesn't treat it as signed out.
        let e = if e.status == StatusCode::UNAUTHORIZED {
            ApiError {
                status: StatusCode::FORBIDDEN,
                ..e
            }
        } else {
            e
        };
        e.event(ev.clone().detail("failed"))
    })?;
    Ok(with_event(Json(json!({ "changed": true, "auto_unlock_stale": stale })), ev))
}

// ---------------------------------------------------------------- secrets

#[derive(Serialize)]
struct SecretView<'a> {
    #[serde(flatten)]
    meta: &'a SecretMeta,
    proxy_ready: bool,
    /// Other secrets holding the same value.
    duplicates: Vec<&'a str>,
}

fn view_with(m: &SecretMeta, all: &[SecretMeta]) -> serde_json::Value {
    let duplicates = match &m.value_mac {
        Some(mac) => all
            .iter()
            .filter(|o| o.id != m.id && o.value_mac.as_ref() == Some(mac))
            .map(|o| o.name.as_str())
            .collect(),
        None => vec![],
    };
    let target = proxy::target_for(m);
    let mut v = serde_json::to_value(SecretView {
        meta: m,
        proxy_ready: target.is_some(),
        duplicates,
    })
    .expect("json");
    // Where proxy paths go: the owner's base URL or the provider's default.
    v["proxy_target"] = target.map(|t| serde_json::Value::from(t.base.as_str())).unwrap_or_default();
    // `all` is what the caller may see; don't name a manager outside it,
    // either directly or inside the rotation status text.
    let hidden_parent = m.parent.as_ref().is_some_and(|p| !all.iter().any(|o| &o.name == p));
    if hidden_parent {
        v["parent"] = serde_json::Value::Null;
    }
    v["rotation"] = crate::rotate::info(m, all);
    if hidden_parent && !v["rotation"]["manager_problem"].is_null() {
        v["rotation"]["manager_problem"] = serde_json::Value::from("its manager is a key you can't see");
    }
    v
}

/// `duplicates` only names secrets the caller may see, so a token can't learn
/// of an owner-only secret through it.
fn view_for(app: &AppRef, p: &Principal, m: &SecretMeta) -> ApiResult<serde_json::Value> {
    let all: Vec<SecretMeta> = app.db.secret_list()?.into_iter().filter(|o| p.may_use(o)).collect();
    Ok(view_with(m, &all))
}

fn view(app: &AppRef, m: &SecretMeta) -> ApiResult<serde_json::Value> {
    Ok(view_with(m, &app.db.secret_list()?))
}

fn load(app: &AppRef, name: &str, ev: &EventInfo) -> ApiResult<SecretMeta> {
    app.db
        .secret_get(name)?
        .ok_or_else(|| ApiError::not_found().event(ev.clone().detail("not found")))
}

#[derive(Deserialize)]
struct ListQuery {
    q: Option<String>,
}

async fn list_secrets(
    State(app): State<AppRef>,
    Extension(caller): Extension<Caller>,
    headers: HeaderMap,
    Query(lq): Query<ListQuery>,
) -> ApiResult {
    let p = app.authenticate(&headers, &caller)?;
    let ev = EventInfo::new("secret.list", p.label());
    if !p.has(Scope::List) {
        return Err(ApiError::forbidden("token lacks the list scope").event(ev));
    }
    let q = lq.q.unwrap_or_default().to_lowercase();
    let all: Vec<SecretMeta> = app.db.secret_list()?.into_iter().filter(|m| p.may_use(m)).collect();
    let items: Vec<_> = all
        .iter()
        .filter(|m| q.is_empty() || m.name.to_lowercase().contains(&q) || m.description.to_lowercase().contains(&q))
        .map(|m| view_with(m, &all))
        .collect();
    Ok(with_event(Json(json!({ "secrets": items })), ev))
}

/// Owner-only settings, shared by create and update.
#[derive(Deserialize, Default)]
pub(crate) struct SettingsBody {
    #[serde(default)]
    pub(crate) kind: Option<String>,
    #[serde(default)]
    pub(crate) owner_only: Option<bool>,
    #[serde(default)]
    pub(crate) fields: Option<serde_json::Map<String, serde_json::Value>>,
    /// Provider id, overriding detection; "" clears.
    #[serde(default)]
    pub(crate) provider: Option<String>,
    /// Name of the managing secret; "" clears.
    #[serde(default)]
    pub(crate) parent: Option<String>,
    /// 0 clears.
    #[serde(default)]
    pub(crate) rotate_every_days: Option<i64>,
    /// Unix ms; 0 clears.
    #[serde(default)]
    pub(crate) expires_at: Option<i64>,
    /// "" clears.
    #[serde(default)]
    pub(crate) exposed: Option<String>,
    #[serde(default)]
    pub(crate) proxy: Option<ProxyBody>,
}

impl SettingsBody {
    fn any(&self) -> bool {
        self.kind.is_some()
            || self.owner_only.is_some()
            || self.fields.is_some()
            || self.provider.is_some()
            || self.parent.is_some()
            || self.rotate_every_days.is_some()
            || self.expires_at.is_some()
            || self.exposed.is_some()
            || self.proxy.is_some()
    }

    /// Validates and converts. `own_name` stops a secret managing itself
    /// through a rename race; providers whose rotation uses the key itself
    /// set no parent.
    pub(crate) fn to_settings(&self, app: &AppRef, own_name: &str) -> ApiResult<Settings> {
        let mut st = Settings::default();
        if let Some(k) = &self.kind {
            if !KINDS.contains(&k.as_str()) {
                return Err(ApiError::bad_request("kind must be api_key, password, private_key or other"));
            }
            st.kind = Some(k.clone());
        }
        st.owner_only = self.owner_only;
        if let Some(f) = &self.fields {
            st.fields = Some(clean_fields(f)?);
        }
        if let Some(p) = &self.provider {
            let p = p.trim();
            if !p.is_empty() && providers::by_id(p).is_none() {
                return Err(ApiError::bad_request(format!("unknown provider '{}'", truncate(p, 40))));
            }
            st.provider_hint = Some((!p.is_empty()).then(|| p.to_string()));
        }
        if let Some(p) = &self.parent {
            let p = p.trim();
            if !p.is_empty() {
                if p == own_name {
                    return Err(ApiError::bad_request("a secret can't manage itself"));
                }
                if app.db.secret_get(p)?.is_none() {
                    return Err(ApiError::bad_request(format!("no secret named '{}'", truncate(p, 128))));
                }
            }
            st.parent = Some((!p.is_empty()).then(|| p.to_string()));
        }
        if let Some(d) = self.rotate_every_days {
            if !(0..=3650).contains(&d) {
                return Err(ApiError::bad_request(
                    "rotate_every_days must be between 1 and 3650 (0 turns it off)",
                ));
            }
            st.rotate_every_days = Some((d > 0).then_some(d));
        }
        if let Some(e) = self.expires_at {
            st.expires_at = Some((e > 0).then_some(e));
        }
        if let Some(x) = &self.exposed {
            let x = x.trim();
            if x.chars().count() > 500 {
                return Err(ApiError::bad_request("exposure note is limited to 500 characters"));
            }
            st.exposed = Some((!x.is_empty()).then(|| x.to_string()));
        }
        Ok(st)
    }
}

/// Checks a proxy settings change. Returns (base URL, auth spec).
pub(crate) fn proxy_change(pb: &ProxyBody) -> ApiResult<(Option<String>, Option<String>)> {
    let base = pb.base_url.as_deref().map(str::trim).filter(|s| !s.is_empty());
    let auth = pb.auth.as_deref().map(str::trim).filter(|s| !s.is_empty());
    if let Some(b) = base {
        proxy::validate_base_url(b).map_err(ApiError::bad_request)?;
    }
    if let Some(a) = auth
        && proxy::Auth::parse(a).is_none()
    {
        return Err(ApiError::bad_request(
            "auth must be bearer, basic, basic:<part>, header:<name>, query:<param> or headers:<Name>={part};...",
        ));
    }
    Ok((base.map(String::from), auth.map(String::from)))
}

#[derive(Deserialize, Zeroize, ZeroizeOnDrop)]
struct CreateBody {
    name: String,
    value: String,
    #[serde(default)]
    extras: Vec<Extra>,
    #[serde(default)]
    notes: Option<String>,
    #[serde(default)]
    #[zeroize(skip)]
    tags: Option<Vec<String>>,
    #[serde(default)]
    #[zeroize(skip)]
    verify: Option<bool>,
    #[serde(flatten)]
    #[zeroize(skip)]
    settings: SettingsBody,
}

/// Fills in what the provider implies (kind, owner-only, schedule) where the
/// caller didn't say.
fn provider_defaults(st: &mut Settings, p: Option<&providers::Provider>) {
    let kind = st
        .kind
        .clone()
        .or_else(|| p.map(|p| p.kind.to_string()))
        .unwrap_or_else(|| "api_key".into());
    if st.owner_only.is_none() {
        st.owner_only = Some(p.map(|p| p.owner_only).unwrap_or(false) || kind == "password");
    }
    if st.rotate_every_days.is_none() {
        st.rotate_every_days = Some(p.and_then(|p| p.rotate_days).map(i64::from));
    }
    st.kind = Some(kind);
}

/// Everything needed to store a new secret.
pub struct NewSecret {
    pub name: String,
    pub material: Material,
    pub notes: String,
    pub tags: Vec<String>,
    pub settings: Settings,
    pub proxy: Option<(Option<String>, Option<String>)>,
    pub verify: bool,
}

/// Stores a new secret (the caller has checked permissions and input).
/// Returns its metadata and the name of another secret with the same value.
pub fn create_internal(app: &AppRef, mut ns: NewSecret) -> ApiResult<(SecretMeta, Option<String>)> {
    app.vault.ensure_unsealed()?;
    if app.db.secret_get(&ns.name)?.is_some() {
        return Err(ApiError::new(StatusCode::CONFLICT, format!("'{}' already exists", ns.name)));
    }
    let fields = ns.settings.fields.clone().unwrap_or_else(|| json!({}));
    let provider = ns
        .settings
        .provider_hint
        .clone()
        .flatten()
        .and_then(|h| providers::by_id(&h))
        .or_else(|| providers::detect(&ns.material.value, &format!("{} {}", ns.name, ns.notes)))
        .map(|p| providers::refine(p, &fields));
    provider_defaults(&mut ns.settings, provider);
    let m = &ns.material;
    let duplicate_of = app.duplicate_of(&m.value, None)?;
    let mac = app.vault.fingerprint(m.value.as_bytes())?;
    let (format, bytes) = m.encode();
    let parts = m.extra_names();
    let nv = NewValue {
        format,
        parts: &parts,
        mac: &mac,
        provider_ref: None,
    };
    let id = app.db.secret_create(&ns.name, &ns.notes, &ns.tags, &ns.settings, &nv, |id, ver| {
        app.vault.encrypt(id, ver, format, &bytes)
    })?;
    drop(bytes);
    if let Some((base, auth)) = &ns.proxy {
        app.db
            .secret_update_fields(id, None, None, None, Some((base.as_deref(), auth.as_deref())))?;
    }
    if let Some(p) = provider {
        app.db.secret_set_provider(id, p.id, p.name, p.risk)?;
    }
    if let Some(Some(parent)) = &ns.settings.parent {
        app.db.secret_force_owner_only(parent)?;
    }
    tokio::spawn(describe::run(app.clone(), id, 1, ns.verify, true));
    let meta = app.db.secret_by_id(id)?.ok_or_else(ApiError::not_found)?;
    Ok((meta, duplicate_of))
}

async fn create_secret(
    State(app): State<AppRef>,
    Extension(caller): Extension<Caller>,
    headers: HeaderMap,
    Json(body): Json<CreateBody>,
) -> ApiResult {
    let p = app.authenticate(&headers, &caller)?;
    let name = body.name.trim().to_string();
    let ev = EventInfo::new("secret.create", p.label()).secret(&name);
    if !valid_name(&name) {
        return Err(ApiError::bad_request(
            "names may use letters, digits, '_', '-' and '.', up to 128 characters",
        ));
    }
    require(&p, Scope::Write, &name, &ev)?;
    // An owner creating a key needs the passphrase: a new value is compared
    // with every stored one (a duplicate is a confirmed guess), and the
    // settings can name a manager, provider or linked fields.
    app.require_fresh(&p)?;
    protect_describer_key(&app, &p, &name, &ev)?;
    if body.settings.any() && !p.is_owner() {
        return Err(
            ApiError::forbidden("only the owner can set kind, owner-only, fields, provider, manager, schedule or proxy")
                .event(ev.detail("settings denied")),
        );
    }
    check_value(&body.value)?;
    check_extras(&body.extras)?;
    check_notes(&body.notes)?;
    let tags = clean_tags(body.tags.clone())?.unwrap_or_default();
    let settings = body.settings.to_settings(&app, &name)?;
    let proxy = match &body.settings.proxy {
        Some(pb) => {
            app.require_fresh(&p)?;
            Some(proxy_change(pb)?)
        }
        None => None,
    };
    let mut material = Material::single(body.value.trim());
    for e in body.extras.iter().filter(|e| !e.value.trim().is_empty()) {
        material.set_extra(&e.name, e.value.trim().to_string());
    }
    let ns = NewSecret {
        name: name.clone(),
        material,
        notes: body.notes.clone().unwrap_or_default(),
        tags,
        settings,
        proxy,
        verify: body.verify.unwrap_or(true),
    };
    let (meta, duplicate_of) = create_internal(&app, ns)?;
    let mut v = view_for(&app, &p, &meta)?;
    // A token only learns of a duplicate it could see anyway.
    let visible = |n: &String| app.db.secret_get(n).ok().flatten().is_some_and(|o| p.may_use(&o));
    v["duplicate_of"] = json!(duplicate_of.filter(visible));
    Ok(with_event((StatusCode::CREATED, Json(v)), ev))
}

async fn get_secret(
    State(app): State<AppRef>,
    Extension(caller): Extension<Caller>,
    headers: HeaderMap,
    Path(name): Path<String>,
) -> ApiResult {
    let p = app.authenticate(&headers, &caller)?;
    let ev = EventInfo::new("secret.info", p.label()).secret(&name);
    require(&p, Scope::List, &name, &ev)?;
    let meta = load(&app, &name, &ev)?;
    require_use(&p, &meta, &ev)?;
    let mut v = view_for(&app, &p, &meta)?;
    if p.is_owner() {
        v["rotations"] = json!(app.db.rotations_recent(Some(meta.id), 10)?);
    }
    Ok(with_event(Json(v), ev))
}

#[derive(Deserialize, Default)]
pub(crate) struct ProxyBody {
    pub(crate) base_url: Option<String>,
    pub(crate) auth: Option<String>,
}

#[derive(Deserialize, Zeroize, ZeroizeOnDrop)]
struct UpdateBody {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    value: Option<String>,
    /// Extra secret parts to set; an empty value removes that part.
    #[serde(default)]
    extras: Option<Vec<Extra>>,
    #[serde(default)]
    notes: Option<String>,
    #[serde(default)]
    #[zeroize(skip)]
    tags: Option<Vec<String>>,
    #[serde(default)]
    #[zeroize(skip)]
    verify: Option<bool>,
    #[serde(flatten)]
    #[zeroize(skip)]
    settings: SettingsBody,
}

async fn update_secret(
    State(app): State<AppRef>,
    Extension(caller): Extension<Caller>,
    headers: HeaderMap,
    Path(name): Path<String>,
    Json(body): Json<UpdateBody>,
) -> ApiResult {
    let p = app.authenticate(&headers, &caller)?;
    let ev = EventInfo::new("secret.update", p.label()).secret(&name);
    require(&p, Scope::Write, &name, &ev)?;
    let meta = load(&app, &name, &ev)?;
    require_use(&p, &meta, &ev)?;
    check_notes(&body.notes)?;
    let tags = clean_tags(body.tags.clone())?;
    if let Some(x) = &body.extras {
        check_extras(x)?;
    }

    let new_name = body.name.as_deref().map(str::trim).filter(|n| *n != name).map(String::from);
    // A rename can move a key into a token's name pattern, and a new value is
    // checked against every stored value for duplicates (a guessing oracle):
    // both need the passphrase when the owner does them.
    let value_given = body.value.as_deref().is_some_and(|v| !v.trim().is_empty()) || body.extras.is_some();
    if new_name.is_some() || value_given {
        app.require_fresh(&p)?;
    }
    if let Some(n) = &new_name {
        if !valid_name(n) {
            return Err(ApiError::bad_request("invalid new name"));
        }
        require(&p, Scope::Write, n, &ev)?;
        protect_describer_key(&app, &p, n, &ev)?;
        protect_describer_key(&app, &p, &name, &ev)?;
        if app.db.secret_get(n)?.is_some() {
            return Err(ApiError::new(StatusCode::CONFLICT, format!("'{n}' already exists")));
        }
    }

    // Changing who can see a key, where the proxy sends it or what manages
    // it could expose it, so only the owner may, with a fresh passphrase.
    let sb = &body.settings;
    if sb.any() && !p.is_owner() {
        return Err(ApiError::forbidden("only the owner can change these settings").event(ev.clone().detail("settings denied")));
    }
    if sb.proxy.is_some() || sb.parent.is_some() || sb.owner_only == Some(false) || sb.provider.is_some() || sb.fields.is_some() {
        app.require_fresh(&p)?;
    }
    // Tokens minted from the old provider or fields mustn't outlive them.
    if sb.provider.is_some() || sb.fields.is_some() {
        app.minted.forget(meta.id);
    }
    let settings = sb.to_settings(&app, new_name.as_deref().unwrap_or(&name))?;
    let proxy = sb.proxy.as_ref().map(proxy_change).transpose()?;

    let value_change = body.value.as_deref().is_some_and(|v| !v.trim().is_empty()) || body.extras.is_some();
    // A key that rotates, renews itself or manages others decides which key
    // the vault creates or revokes; a token writing it could steer that.
    if value_change && !p.is_owner() && managed(&app, &meta)? {
        return Err(
            ApiError::forbidden("this key is managed by rotation; only the owner can change its value")
                .event(ev.clone().detail("managed value denied")),
        );
    }
    let mut new_material = None;
    if value_change {
        if let Some(v) = &body.value {
            check_value(v)?;
        }
        protect_describer_key(&app, &p, &name, &ev)?;
        app.vault.ensure_unsealed()?;
        let mut m = app.reveal(&meta)?;
        if let Some(v) = body.value.as_deref().filter(|v| !v.trim().is_empty()) {
            m.value = v.trim().to_string();
        }
        for e in body.extras.iter().flatten() {
            if e.value.trim().is_empty() {
                m.extras.retain(|x| x.name != e.name);
            } else {
                m.set_extra(&e.name, e.value.trim().to_string());
            }
        }
        new_material = Some(m);
    }
    app.db.secret_update_fields(
        meta.id,
        new_name.as_deref(),
        body.notes.as_deref(),
        tags.as_deref(),
        proxy.as_ref().map(|(b, a)| (b.as_deref(), a.as_deref())),
    )?;
    app.db.secret_set_settings(meta.id, &settings)?;
    if let Some(Some(parent)) = &settings.parent {
        app.db.secret_force_owner_only(parent)?;
    }
    let final_name = new_name.clone().unwrap_or_else(|| name.clone());
    let mut duplicate_of = None;
    let mut redescribe = sb.provider.is_some() || sb.fields.is_some() || sb.proxy.is_some();
    if let Some(m) = &new_material {
        duplicate_of = app.duplicate_of(&m.value, Some(meta.id))?;
        let version = app.save_version(meta.id, m, None)?;
        tokio::spawn(describe::run(app.clone(), meta.id, version, body.verify.unwrap_or(true), true));
        redescribe = false;
    }
    if redescribe {
        let cur = load(&app, &final_name, &ev)?;
        app.db.secret_set_describe_status(meta.id, "pending")?;
        tokio::spawn(describe::run(app.clone(), meta.id, cur.version, body.verify.unwrap_or(true), false));
    }
    drop(new_material);
    let updated = load(&app, &final_name, &ev)?;
    let mut detail = vec![];
    if new_name.is_some() {
        detail.push(format!("renamed from {name}"));
    }
    if value_change {
        detail.push(format!("new value (v{})", updated.version));
    }
    if proxy.is_some() {
        detail.push("proxy settings".into());
    }
    if sb.any() && sb.proxy.is_none() {
        detail.push("settings".into());
    }
    let ev = EventInfo {
        secret: Some(final_name),
        ..ev
    };
    let ev = if detail.is_empty() { ev } else { ev.detail(detail.join(", ")) };
    let mut v = view_for(&app, &p, &updated)?;
    let visible = |n: &String| app.db.secret_get(n).ok().flatten().is_some_and(|o| p.may_use(&o));
    v["duplicate_of"] = json!(duplicate_of.filter(visible));
    Ok(with_event(Json(v), ev))
}

async fn delete_secret(
    State(app): State<AppRef>,
    Extension(caller): Extension<Caller>,
    headers: HeaderMap,
    Path(name): Path<String>,
) -> ApiResult {
    let p = app.authenticate(&headers, &caller)?;
    let ev = EventInfo::new("secret.delete", p.label()).secret(&name);
    require(&p, Scope::Delete, &name, &ev)?;
    app.require_fresh(&p)?;
    let meta = load(&app, &name, &ev)?;
    require_use(&p, &meta, &ev)?;
    app.db.secret_delete(meta.id)?;
    app.minted.forget(meta.id);
    Ok(with_event(Json(json!({ "deleted": name })), ev))
}

async fn read_value(
    State(app): State<AppRef>,
    Extension(caller): Extension<Caller>,
    headers: HeaderMap,
    Path(name): Path<String>,
) -> ApiResult {
    let p = app.authenticate(&headers, &caller)?;
    let ev = EventInfo::new("secret.read", p.label()).secret(&name);
    require(&p, Scope::Read, &name, &ev)?;
    app.require_fresh(&p)?;
    let meta = load(&app, &name, &ev)?;
    require_use(&p, &meta, &ev)?;
    let m = app.reveal(&meta).map_err(|e| e.event(ev.clone()))?;
    app.db.secret_touch(meta.id)?;
    let parts: serde_json::Map<String, serde_json::Value> = m.extras.iter().map(|e| (e.name.clone(), json!(e.value))).collect();
    Ok(with_event(
        Json(json!({ "name": name, "version": meta.version, "value": m.value, "parts": parts, "fields": meta.fields })),
        ev,
    ))
}

async fn redescribe(
    State(app): State<AppRef>,
    Extension(caller): Extension<Caller>,
    headers: HeaderMap,
    Path(name): Path<String>,
) -> ApiResult {
    let p = app.authenticate(&headers, &caller)?;
    let ev = EventInfo::new("secret.redescribe", p.label()).secret(&name);
    require(&p, Scope::Write, &name, &ev)?;
    let meta = load(&app, &name, &ev)?;
    require_use(&p, &meta, &ev)?;
    app.vault.ensure_unsealed()?;
    app.db.secret_set_describe_status(meta.id, "pending")?;
    tokio::spawn(describe::run(app.clone(), meta.id, meta.version, true, false));
    Ok(with_event((StatusCode::ACCEPTED, Json(json!({ "describing": name }))), ev))
}

// ---------------------------------------------------------------- rotation

#[derive(Deserialize, Zeroize, ZeroizeOnDrop, Default)]
struct RotateBody {
    /// The new key, for a rotation done by hand. Omit to rotate through the API.
    #[serde(default)]
    value: Option<String>,
    #[serde(default)]
    extras: Vec<Extra>,
    /// Plaintext parts that changed too (e.g. Alpaca's new key ID).
    #[serde(default)]
    #[zeroize(skip)]
    fields: Option<serde_json::Map<String, serde_json::Value>>,
    /// Store it even if the provider can't confirm it works.
    #[serde(default)]
    #[zeroize(skip)]
    skip_check: bool,
}

async fn rotate_secret(
    State(app): State<AppRef>,
    Extension(caller): Extension<Caller>,
    headers: HeaderMap,
    Path(name): Path<String>,
    body: Option<Json<RotateBody>>,
) -> ApiResult {
    let p = owner(&app, &headers, &caller)?;
    app.require_fresh(&p)?;
    let ev = EventInfo::new("secret.rotate", "owner (web)").secret(&name);
    let meta = load(&app, &name, &ev)?;
    let body = body.map(|b| b.0).unwrap_or_default();
    check_extras(&body.extras)?;
    let fields = match &body.fields {
        Some(f) => clean_fields(f)?.as_object().cloned(),
        None => None,
    };
    let result = match body.value.as_deref().map(str::trim).filter(|v| !v.is_empty()) {
        Some(v) => {
            check_value(v)?;
            let mut m = app.reveal(&meta)?;
            m.value = v.to_string();
            for e in body.extras.iter().filter(|e| !e.value.trim().is_empty()) {
                m.set_extra(&e.name, e.value.trim().to_string());
            }
            crate::rotate::complete_guided(&app, &meta, m, fields, body.skip_check, "owner (web)").await
        }
        None => crate::rotate::rotate_auto(&app, &meta, "owner (web)").await,
    };
    match result {
        Ok(r) => {
            let ev = ev.detail(format!("{} rotation: {}", r.mode, r.state));
            Ok(with_event(
                Json(json!({ "rotation": r, "secret": view(&app, &load(&app, &name, &EventInfo::new("x", "x"))?)? })),
                ev,
            ))
        }
        Err(e) => {
            let msg = truncate(&e.msg, 200);
            Err(e.event(ev.detail(msg)))
        }
    }
}

async fn list_rotations(State(app): State<AppRef>, Extension(caller): Extension<Caller>, headers: HeaderMap) -> ApiResult {
    owner(&app, &headers, &caller)?;
    Ok(Json(json!({ "rotations": app.db.rotations_recent(None, 100)? })).into_response())
}

async fn rollback_rotation(
    State(app): State<AppRef>,
    Extension(caller): Extension<Caller>,
    headers: HeaderMap,
    Path(id): Path<i64>,
) -> ApiResult {
    let p = owner(&app, &headers, &caller)?;
    app.require_fresh(&p)?;
    let r = crate::rotate::rollback(&app, id).await?;
    let ev = EventInfo::new("rotation.rollback", "owner (web)").secret(&r.secret);
    Ok(with_event(Json(json!({ "rotation": r })), ev))
}

async fn rotation_done(
    State(app): State<AppRef>,
    Extension(caller): Extension<Caller>,
    headers: HeaderMap,
    Path(id): Path<i64>,
) -> ApiResult {
    let p = owner(&app, &headers, &caller)?;
    app.require_fresh(&p)?;
    let r = crate::rotate::mark_done(&app, id)?;
    let ev = EventInfo::new("rotation.done", "owner (web)").secret(&r.secret);
    Ok(with_event(Json(json!({ "rotation": r })), ev))
}

async fn attention(State(app): State<AppRef>, Extension(caller): Extension<Caller>, headers: HeaderMap) -> ApiResult {
    owner(&app, &headers, &caller)?;
    let (items, dismissed) = crate::rotate::attention_split(&app)?;
    Ok(Json(json!({ "items": items, "dismissed": dismissed })).into_response())
}

#[derive(Deserialize)]
struct AttentionBody {
    secret: String,
}

/// OK: hides a secret's current "needs attention" items until its situation
/// changes (new value, new expiry, another failed check or rotation...).
async fn attention_dismiss(
    State(app): State<AppRef>,
    Extension(caller): Extension<Caller>,
    headers: HeaderMap,
    Json(body): Json<AttentionBody>,
) -> ApiResult {
    owner(&app, &headers, &caller)?;
    let ev = EventInfo::new("attention.dismiss", "owner (web)").secret(&body.secret);
    let meta = load(&app, &body.secret, &ev)?;
    let kinds = crate::rotate::dismiss(&app, meta.id, &meta.name)?;
    if kinds.is_empty() {
        return Err(ApiError::new(StatusCode::NOT_FOUND, "nothing needs attention for this secret").event(ev));
    }
    Ok(with_event(Json(json!({ "dismissed": kinds })), ev.detail(kinds.join(","))))
}

/// Undo: shows a secret's OK'd items again.
async fn attention_restore(
    State(app): State<AppRef>,
    Extension(caller): Extension<Caller>,
    headers: HeaderMap,
    Json(body): Json<AttentionBody>,
) -> ApiResult {
    owner(&app, &headers, &caller)?;
    let ev = EventInfo::new("attention.restore", "owner (web)").secret(&body.secret);
    let meta = load(&app, &body.secret, &ev)?;
    let n = app.db.acks_clear(meta.id)?;
    Ok(with_event(Json(json!({ "restored": n })), ev))
}

/// The provider table, for choosing a provider in the UI.
async fn list_providers(State(app): State<AppRef>, Extension(caller): Extension<Caller>, headers: HeaderMap) -> ApiResult {
    owner(&app, &headers, &caller)?;
    let list: Vec<_> = providers::PROVIDERS
        .iter()
        .map(|p| {
            json!({
                "id": p.id, "name": p.name, "kind": p.kind, "risk": p.risk, "rotation": p.rotation.mode(),
                "rotate_url": p.rotate_url, "parent_provider": p.parent_provider, "parent_hint": p.parent_hint,
                "needs": p.needs.iter().map(|n| json!({"name": n.name, "label": n.label, "secret": n.secret, "hint": n.hint})).collect::<Vec<_>>(),
            })
        })
        .collect();
    Ok(Json(json!({ "providers": list })).into_response())
}

// ---------------------------------------------------------------- proxy

#[allow(clippy::too_many_arguments)]
async fn proxy_request(
    State(app): State<AppRef>,
    Extension(caller): Extension<Caller>,
    Path((name, path)): Path<(String, String)>,
    method: Method,
    headers: HeaderMap,
    RawQuery(query): RawQuery,
    body: Bytes,
) -> ApiResult {
    let p = app.authenticate(&headers, &caller)?;
    // spandeck names the pane that asked. It is recorded as a label the
    // caller reported, never used for a permission decision, and stripped
    // before the request goes to the provider.
    let actor = match headers.get("x-agentvault-actor").and_then(|v| v.to_str().ok()).map(str::trim) {
        Some(l) if !l.is_empty() && !l.chars().any(char::is_control) => format!("{} · {} (reported)", p.label(), truncate(l, 120)),
        _ => p.label(),
    };
    let ev = EventInfo::new("proxy", actor)
        .secret(&name)
        .detail(truncate(&format!("{method} /{path}"), 200));
    require(&p, Scope::Proxy, &name, &ev)?;
    // The owner can use every key, owner-only ones included: a cookie taken by
    // an agent running as the owner must not be enough to drive them.
    app.require_fresh(&p).map_err(|e| e.event(ev.clone().detail("needs passphrase")))?;
    let get_only = matches!(&p, Principal::Token(t) if t.proxy_get_only);
    if !proxy::allowed_method(&method, get_only) {
        let msg = if get_only {
            "this token may only send GET requests through the proxy"
        } else {
            "method not allowed"
        };
        return Err(ApiError::new(StatusCode::METHOD_NOT_ALLOWED, msg).event(ev.detail("method denied")));
    }
    let meta = load(&app, &name, &ev)?;
    require_use(&p, &meta, &ev)?;
    let target = proxy::target_for(&meta)
        .ok_or_else(|| ApiError::bad_request("no proxy target for this secret: set a base URL in its settings").event(ev.clone()))?;
    let url = proxy::build_url(&target.base, &path, query.as_deref()).map_err(|e| ApiError::bad_request(e).event(ev.clone()))?;
    let stored = app.reveal(&meta).map_err(|e| e.event(ev.clone()))?;
    let material = crate::rotate::proxy_material(&app, &meta, &stored)
        .await
        .map_err(|e| e.event(ev.clone()))?;
    let creds = proxy::Creds {
        material: &material,
        fields: &meta.fields,
    };
    let fwd = proxy::forward_request_headers(&headers, &target.auth);
    let (resp, upstream) = proxy::send(&app.http, &target, &creds, method, url, fwd, body)
        .await
        .map_err(|e| ApiError::new(StatusCode::BAD_GATEWAY, e).event(ev.clone()))?;
    let mut redactor = proxy::Redactor::for_creds(&creds, &target.auth);
    redactor.extend(&stored.secrets());
    let redactor = std::sync::Arc::new(redactor);
    drop((material, stored));
    app.db.secret_touch(meta.id)?;
    let status = StatusCode::from_u16(resp.status().as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);
    let resp_headers = proxy::response_headers(resp.headers(), &redactor);
    let mut out = Response::new(Body::from_stream(proxy::redact_stream(resp.bytes_stream(), redactor)));
    *out.status_mut() = status;
    *out.headers_mut() = resp_headers;
    Ok(with_event(out, ev.upstream(upstream)))
}

// ---------------------------------------------------------------- tokens

#[derive(Deserialize)]
struct TokenBody {
    name: String,
    scopes: Vec<String>,
    #[serde(default)]
    secrets: Option<Vec<String>>,
    #[serde(default)]
    nodes: Option<Vec<String>>,
    #[serde(default)]
    proxy_get_only: bool,
}

async fn list_tokens(State(app): State<AppRef>, Extension(caller): Extension<Caller>, headers: HeaderMap) -> ApiResult {
    owner(&app, &headers, &caller)?;
    Ok(Json(json!({ "tokens": app.db.token_list()? })).into_response())
}

/// Validated token settings, shared by create and edit.
struct TokenSettings {
    name: String,
    scopes: Vec<String>,
    secrets: Vec<String>,
    nodes: Vec<String>,
}

fn token_settings(body: &TokenBody) -> ApiResult<TokenSettings> {
    let name = body.name.trim().to_string();
    if name.is_empty() || name.len() > 64 || name.chars().any(|c| c.is_control()) {
        return Err(ApiError::bad_request("token name must be 1-64 characters"));
    }
    let mut scopes = vec![];
    for s in &body.scopes {
        let sc = Scope::parse(s).ok_or_else(|| ApiError::bad_request(format!("unknown scope '{}'", truncate(s, 20))))?;
        if !scopes.contains(&sc.as_str().to_string()) {
            scopes.push(sc.as_str().to_string());
        }
    }
    if scopes.is_empty() {
        return Err(ApiError::bad_request("pick at least one scope"));
    }
    let secrets: Vec<String> = body
        .secrets
        .clone()
        .unwrap_or_else(|| vec!["*".into()])
        .into_iter()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    if secrets.is_empty() || !secrets.iter().all(|g| valid_glob(g)) {
        return Err(ApiError::bad_request(
            "secret patterns may use letters, digits, '_', '-', '.' and '*'",
        ));
    }
    let nodes: Vec<String> = body
        .nodes
        .clone()
        .unwrap_or_default()
        .into_iter()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    if !nodes.iter().all(|n| valid_node(n)) {
        return Err(ApiError::bad_request("invalid machine name"));
    }
    Ok(TokenSettings {
        name,
        scopes,
        secrets,
        nodes,
    })
}

/// Changes what an existing token may do. It takes effect on the token's next
/// request; the token itself stays the same, so nothing needs reconfiguring.
async fn update_token(
    State(app): State<AppRef>,
    Extension(caller): Extension<Caller>,
    headers: HeaderMap,
    Path(id): Path<i64>,
    Json(body): Json<TokenBody>,
) -> ApiResult {
    let p = owner(&app, &headers, &caller)?;
    app.require_fresh(&p)?;
    let TokenSettings {
        name,
        scopes,
        secrets,
        nodes,
    } = token_settings(&body)?;
    let Some(old) = app.db.token_get(id)?.filter(|t| t.revoked_at.is_none()) else {
        return Err(ApiError::new(StatusCode::NOT_FOUND, "no such active token"));
    };
    if !app.db.token_update(id, &name, &scopes, &secrets, &nodes, body.proxy_get_only)? {
        return Err(ApiError::new(StatusCode::NOT_FOUND, "no such active token"));
    }
    let describe = |s: &[String], g: &[String], n: &[String], get_only: bool| {
        format!(
            "[{}] keys {} machines {}{}",
            s.join(","),
            g.join(","),
            if n.is_empty() { "any".to_string() } else { n.join(",") },
            if get_only && s.iter().any(|x| x == "proxy") {
                " GET-only"
            } else {
                ""
            }
        )
    };
    let detail = format!(
        "{name}: {} -> {}",
        describe(&old.scopes, &old.secrets, &old.nodes, old.proxy_get_only),
        describe(&scopes, &secrets, &nodes, body.proxy_get_only)
    );
    let ev = EventInfo::new("token.update", "owner (web)").detail(truncate(&detail, 400));
    let row = app.db.token_get(id)?;
    Ok(with_event(Json(json!({ "token": row })), ev))
}

async fn create_token(
    State(app): State<AppRef>,
    Extension(caller): Extension<Caller>,
    headers: HeaderMap,
    Json(body): Json<TokenBody>,
) -> ApiResult {
    let p = owner(&app, &headers, &caller)?;
    app.require_fresh(&p)?;
    let TokenSettings {
        name,
        scopes,
        secrets,
        nodes,
    } = token_settings(&body)?;
    let (token, hash) = auth::new_token();
    let id = app.db.token_create(&name, &hash, &scopes, &secrets, &nodes, body.proxy_get_only)?;
    let ev = EventInfo::new("token.create", "owner (web)").detail(format!("{name} [{}]", scopes.join(",")));
    Ok(with_event(
        (
            StatusCode::CREATED,
            Json(json!({
                "id": id, "name": name, "token": token, "scopes": scopes, "secrets": secrets,
                "nodes": nodes, "proxy_get_only": body.proxy_get_only,
            })),
        ),
        ev,
    ))
}

async fn revoke_token(
    State(app): State<AppRef>,
    Extension(caller): Extension<Caller>,
    headers: HeaderMap,
    Path(id): Path<i64>,
) -> ApiResult {
    owner(&app, &headers, &caller)?;
    if !app.db.token_revoke(id)? {
        return Err(ApiError::new(StatusCode::NOT_FOUND, "no such active token"));
    }
    Ok(with_event(
        Json(json!({ "revoked": id })),
        EventInfo::new("token.revoke", "owner (web)").detail(format!("token #{id}")),
    ))
}

// ---------------------------------------------------------------- dashboard & audit

#[derive(Deserialize)]
struct RangeQuery {
    range: Option<String>,
}

async fn dashboard_handler(
    State(app): State<AppRef>,
    Extension(caller): Extension<Caller>,
    headers: HeaderMap,
    Query(rq): Query<RangeQuery>,
) -> ApiResult {
    owner(&app, &headers, &caller)?;
    let range = dashboard::Range::parse(rq.range.as_deref().unwrap_or("24h"));
    let db = app.db.clone();
    let d = tokio::task::spawn_blocking(move || -> Result<_, rusqlite::Error> {
        let since = crate::db::now_ms() - range.span_ms;
        Ok(dashboard::build(range, db.events_since(since, dashboard::EVENT_LIMIT)?))
    })
    .await
    .map_err(ApiError::internal)??;
    let mut d = serde_json::to_value(d).map_err(ApiError::internal)?;
    let att = crate::rotate::attention(&app)?;
    d["attention"] = json!({
        "total": att.len(),
        "critical": att.iter().filter(|a| a["level"] == "critical").count(),
    });
    Ok(Json(d).into_response())
}

#[derive(Deserialize)]
struct EventsQuery {
    before: Option<i64>,
    limit: Option<i64>,
}

async fn events(
    State(app): State<AppRef>,
    Extension(caller): Extension<Caller>,
    headers: HeaderMap,
    Query(q): Query<EventsQuery>,
) -> ApiResult {
    owner(&app, &headers, &caller)?;
    let rows = app.db.events_page(q.before, q.limit.unwrap_or(100).clamp(1, 500))?;
    Ok(Json(json!({ "events": rows })).into_response())
}

async fn audit_verify(State(app): State<AppRef>, Extension(caller): Extension<Caller>, headers: HeaderMap) -> ApiResult {
    owner(&app, &headers, &caller)?;
    let db = app.db.clone();
    let r = tokio::task::spawn_blocking(move || db.audit_verify())
        .await
        .map_err(ApiError::internal)??;
    Ok(Json(r).into_response())
}

async fn mcp_get() -> Response {
    // No server-initiated stream; clients fall back to plain POST.
    (StatusCode::METHOD_NOT_ALLOWED, [(header::ALLOW, "POST")]).into_response()
}
