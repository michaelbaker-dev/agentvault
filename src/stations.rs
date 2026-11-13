//! Connecting spandeck stations, rotating their tokens, and reports of keys
//! seen where they shouldn't be. Agreed with the spandeck project; see the
//! README's "With spandeck" section.
//!
//! A station asks for a token without any credential (`open`); nothing is
//! issued until the owner approves it on the vault's own page with a fresh
//! passphrase (`approve`). The station then collects the token once, from the
//! same machine, with the one-time code it was given (`collect`).

use axum::{
    Json,
    extract::{Extension, Path, RawQuery, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
};
use serde::Deserialize;
use serde_json::{Value, json};
use std::{
    collections::HashMap,
    time::{Duration, Instant},
};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::app::{ApiError, ApiResult, AppRef, EventInfo, with_event};
use crate::auth::{self, Principal};
use crate::crypto;
use crate::db::now_ms;
use crate::identity::Caller;
use crate::server::{self, truncate};

/// How long a request waits for approval, and an approved token for collection.
pub const REQUEST_TTL_MS: i64 = 10 * 60 * 1000;
/// After a swap, the old token keeps working until the new one is first used,
/// for at most this long.
pub const OLD_TOKEN_GRACE_MS: i64 = 24 * 3_600_000;
const MAX_REQUESTS: usize = 200;
pub const MIN_ROTATION_HOURS: i64 = 1;
const MAX_ROTATION_HOURS: i64 = 24 * 366;
/// Exposure reports accepted per caller per minute; extra ones are dropped
/// (with the same reply, so the limit reveals nothing).
const REPORTS_PER_MINUTE: u32 = 120;
const MAX_REPORT_BYTES: usize = 64 * 1024;
pub const TOKEN_PREFIX: &str = "spandeck:";

#[derive(Debug)]
pub enum RequestState {
    Pending,
    Denied,
    Approved {
        token: Zeroizing<String>,
        token_id: i64,
        secrets: Vec<String>,
        proxy_get_only: bool,
    },
    Expired,
}

#[derive(Debug)]
pub struct TokenRequest {
    pub node: String,
    pub node_fqdn: String,
    pub node_id: String,
    pub user: String,
    pub tags: Vec<String>,
    /// What the station calls itself; shown as reported, never trusted.
    pub label: String,
    pub created_at: i64,
    pub expires_at: i64,
    code_hash: [u8; 32],
    pub state: RequestState,
}

/// Requests and per-caller report budgets, kept in memory: a restart drops
/// pending requests, and the station simply asks again.
#[derive(Default)]
pub struct Stations {
    requests: std::sync::Mutex<HashMap<String, TokenRequest>>,
    report_budget: std::sync::Mutex<HashMap<String, (Instant, u32)>>,
}

#[cfg(test)]
impl Stations {
    /// Makes every request look expired, as if ten minutes had passed.
    pub fn expire_all(&self) {
        for r in self.requests.lock().unwrap().values_mut() {
            r.expires_at = now_ms() - 1;
        }
    }
}

fn station_actor(c: &Caller) -> String {
    format!("station {}", c.node)
}

/// Expires old requests, revoking tokens that were approved but never
/// collected. Called on every request-related call and by the scheduler.
pub fn prune(app: &AppRef) {
    let now = now_ms();
    let mut expired = vec![];
    {
        let mut map = app.stations.requests.lock().unwrap_or_else(|p| p.into_inner());
        for (id, r) in map.iter_mut() {
            if now <= r.expires_at {
                continue;
            }
            match std::mem::replace(&mut r.state, RequestState::Expired) {
                RequestState::Pending => expired.push((id.clone(), r.node.clone(), None)),
                RequestState::Approved { token_id, .. } => expired.push((id.clone(), r.node.clone(), Some(token_id))),
                other => r.state = other,
            }
        }
        // Keep finished requests a while so a late poll gets a clear answer.
        map.retain(|_, r| now - r.expires_at < REQUEST_TTL_MS);
    }
    for (id, node, token_id) in expired {
        let mut detail = format!("request {} from {node}", &id[..8]);
        if let Some(t) = token_id {
            let _ = app.db.token_revoke(t);
            detail.push_str(": approved but never collected, token revoked");
        }
        app.record_internal(
            EventInfo::new("token_request.expired", "agentvault").detail(detail),
            200,
            Duration::ZERO,
        );
    }
}

#[derive(Deserialize)]
pub struct OpenBody {
    station: Option<String>,
}

/// `POST /v1/token-requests` — no credential: any process on a station could
/// do this, which is safe only because nothing is issued without approval.
pub async fn open(State(app): State<AppRef>, Extension(caller): Extension<Caller>, Json(body): Json<OpenBody>) -> ApiResult {
    let ev = EventInfo::new("token_request.open", station_actor(&caller));
    if !(caller.user == app.cfg.owner || caller.is_tagged()) {
        return Err(ApiError::forbidden("only the owner's own devices and tagged machines can ask for a token").event(ev));
    }
    if caller.node_id.is_empty() {
        return Err(ApiError::forbidden("this machine has no stable Tailscale ID").event(ev));
    }
    let label = body.station.unwrap_or_default().trim().to_string();
    if label.chars().count() > 64 || label.chars().any(char::is_control) {
        return Err(ApiError::bad_request("station must be at most 64 characters with no control characters").event(ev));
    }
    let label = if label.is_empty() { caller.node.clone() } else { label };
    prune(&app);
    let id = hex::encode(crypto::random_bytes::<16>());
    let code = hex::encode(crypto::random_bytes::<32>());
    let now = now_ms();
    let expires_at = now + REQUEST_TTL_MS;
    {
        let mut map = app.stations.requests.lock().unwrap_or_else(|p| p.into_inner());
        // One pending request per machine: a new one replaces it.
        map.retain(|_, r| !(r.node_id == caller.node_id && matches!(r.state, RequestState::Pending)));
        if map.len() >= MAX_REQUESTS {
            return Err(ApiError::new(StatusCode::TOO_MANY_REQUESTS, "too many open token requests; try again shortly").event(ev));
        }
        map.insert(
            id.clone(),
            TokenRequest {
                node: caller.node.clone(),
                node_fqdn: caller.node_fqdn.clone(),
                node_id: caller.node_id.clone(),
                user: caller.user.clone(),
                tags: caller.tags.clone(),
                label: label.clone(),
                created_at: now,
                expires_at,
                code_hash: crypto::sha256(code.as_bytes()),
                state: RequestState::Pending,
            },
        );
    }
    let approve_url = format!("{}/#/approve/{id}", app.origin);
    Ok(with_event(
        (
            StatusCode::CREATED,
            Json(json!({ "request_id": id, "approve_url": approve_url, "collect_code": code, "expires_at": expires_at })),
        ),
        ev.detail(format!("request {} labelled {}", &id[..8], truncate(&label, 64))),
    ))
}

/// `GET /v1/token-requests` — the owner's view of what is waiting.
pub async fn list(State(app): State<AppRef>, Extension(caller): Extension<Caller>, headers: HeaderMap) -> ApiResult {
    server::owner(&app, &headers, &caller)?;
    prune(&app);
    let map = app.stations.requests.lock().unwrap_or_else(|p| p.into_inner());
    let mut items: Vec<Value> = map
        .iter()
        .filter(|(_, r)| matches!(r.state, RequestState::Pending))
        .map(|(id, r)| {
            json!({
                "id": id, "node": r.node, "node_fqdn": r.node_fqdn, "user": r.user, "tags": r.tags,
                "label": r.label, "created_at": r.created_at, "expires_at": r.expires_at,
                "token_name": format!("{TOKEN_PREFIX}{}", r.node),
            })
        })
        .collect();
    items.sort_by_key(|v| v["created_at"].as_i64());
    Ok(Json(json!({ "requests": items, "allows": "list and proxy only; never raw values or owner-only keys" })).into_response())
}

#[derive(Deserialize)]
pub struct ApproveBody {
    #[serde(default)]
    secrets: Option<Vec<String>>,
    #[serde(default)]
    proxy_get_only: Option<bool>,
}

/// `POST /v1/token-requests/{id}/approve` — owner session and a fresh passphrase.
pub async fn approve(
    State(app): State<AppRef>,
    Extension(caller): Extension<Caller>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(body): Json<ApproveBody>,
) -> ApiResult {
    let p = server::owner(&app, &headers, &caller)?;
    app.require_fresh(&p)?;
    prune(&app);
    let secrets: Vec<String> = body
        .secrets
        .unwrap_or_else(|| vec!["*".into()])
        .into_iter()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    if secrets.is_empty() || !secrets.iter().all(|g| server::valid_glob(g)) {
        return Err(ApiError::bad_request("key patterns may use letters, digits, '_', '-', '.' and '*'"));
    }
    let get_only = body.proxy_get_only.unwrap_or(true);
    let (node, node_id) = {
        let map = app.stations.requests.lock().unwrap_or_else(|p| p.into_inner());
        match map.get(&id) {
            Some(r) if matches!(r.state, RequestState::Pending) => (r.node.clone(), r.node_id.clone()),
            Some(_) => {
                return Err(ApiError::new(
                    StatusCode::CONFLICT,
                    "this request was already handled or has expired",
                ));
            }
            None => return Err(ApiError::new(StatusCode::NOT_FOUND, "no such request; it may have expired")),
        }
    };
    // Approving replaces any earlier spandeck token for this machine.
    for t in app.db.token_list()? {
        if t.revoked_at.is_none() && t.name.starts_with(TOKEN_PREFIX) && t.node_pins.values().any(|v| *v == node_id) {
            app.db.token_revoke(t.id)?;
        }
    }
    let (token, hash) = auth::new_token();
    let name = format!("{TOKEN_PREFIX}{node}");
    let scopes = vec!["list".to_string(), "proxy".to_string()];
    let token_id = app
        .db
        .token_create_pinned(&name, &hash, &scopes, &secrets, &node, &node_id, get_only)?;
    {
        let mut map = app.stations.requests.lock().unwrap_or_else(|p| p.into_inner());
        let Some(r) = map.get_mut(&id).filter(|r| matches!(r.state, RequestState::Pending)) else {
            // Handled concurrently: don't leave a token nobody can collect.
            app.db.token_revoke(token_id)?;
            return Err(ApiError::new(StatusCode::CONFLICT, "this request was already handled"));
        };
        r.state = RequestState::Approved {
            token: Zeroizing::new(token),
            token_id,
            secrets: secrets.clone(),
            proxy_get_only: get_only,
        };
        r.expires_at = now_ms() + REQUEST_TTL_MS;
    }
    let detail = format!("{name}: keys {}{}", secrets.join(","), if get_only { ", GET only" } else { "" });
    Ok(with_event(
        Json(json!({ "approved": id, "token_name": name })),
        EventInfo::new("token_request.approve", "owner (web)").detail(detail),
    ))
}

/// `POST /v1/token-requests/{id}/deny` — owner session.
pub async fn deny(
    State(app): State<AppRef>,
    Extension(caller): Extension<Caller>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> ApiResult {
    server::owner(&app, &headers, &caller)?;
    prune(&app);
    let mut map = app.stations.requests.lock().unwrap_or_else(|p| p.into_inner());
    let Some(r) = map.get_mut(&id).filter(|r| matches!(r.state, RequestState::Pending)) else {
        return Err(ApiError::new(StatusCode::NOT_FOUND, "no pending request with that id"));
    };
    r.state = RequestState::Denied;
    let detail = format!("request {} from {}", &id[..8.min(id.len())], r.node);
    Ok(with_event(
        Json(json!({ "denied": id })),
        EventInfo::new("token_request.deny", "owner (web)").detail(detail),
    ))
}

/// `GET /v1/token-requests/{id}` with the collect code — the station that
/// asked polls this until the token is approved, then collects it once.
pub async fn collect(
    State(app): State<AppRef>,
    Extension(caller): Extension<Caller>,
    headers: HeaderMap,
    Path(id): Path<String>,
    RawQuery(query): RawQuery,
) -> ApiResult {
    let ev = EventInfo::new("token_request.collect", station_actor(&caller));
    prune(&app);
    let code = headers
        .get("x-collect-code")
        .and_then(|v| v.to_str().ok())
        .map(str::to_string)
        .or_else(|| {
            query
                .as_deref()
                .unwrap_or("")
                .split('&')
                .find_map(|kv| kv.strip_prefix("code=").map(str::to_string))
        })
        .unwrap_or_default();
    let mut map = app.stations.requests.lock().unwrap_or_else(|p| p.into_inner());
    let Some(r) = map.get_mut(&id) else {
        return Err(ApiError::new(StatusCode::NOT_FOUND, "no such request; it may have expired, so ask again").event(ev));
    };
    // Only the machine that asked, and only with its code.
    if r.node_id != caller.node_id || !crypto::ct_eq_bytes(&crypto::sha256(code.as_bytes()), &r.code_hash) {
        return Err(ApiError::forbidden("not the station that asked, or the wrong collect code").event(ev.detail("refused")));
    }
    match std::mem::replace(&mut r.state, RequestState::Expired) {
        RequestState::Pending => {
            r.state = RequestState::Pending;
            Ok(Json(json!({ "status": "pending", "expires_at": r.expires_at })).into_response())
        }
        RequestState::Denied => {
            r.state = RequestState::Denied;
            Ok(Json(json!({ "status": "denied" })).into_response())
        }
        RequestState::Expired => {
            map.remove(&id);
            Err(ApiError::new(StatusCode::GONE, "already collected or expired; ask again").event(ev.detail("gone")))
        }
        RequestState::Approved {
            token,
            secrets,
            proxy_get_only,
            ..
        } => {
            // Handed over once: the request is forgotten and the token is
            // nowhere in memory after this reply.
            let node = r.node.clone();
            map.remove(&id);
            let body = json!({
                "status": "approved", "token": token.as_str(), "scopes": ["list", "proxy"],
                "secrets": secrets, "proxy_get_only": proxy_get_only,
            });
            Ok(with_event(Json(body), ev.detail(format!("collected by {node}"))))
        }
    }
}

fn token_principal(p: &Principal) -> ApiResult<&auth::TokenGrant> {
    match p {
        Principal::Token(t) => Ok(t),
        Principal::Owner { .. } => Err(ApiError::bad_request("this call is for tokens; the owner session has no token")),
    }
}

/// `GET /v1/tokens/self` — what the calling token is and may do.
pub async fn token_self(State(app): State<AppRef>, Extension(caller): Extension<Caller>, headers: HeaderMap) -> ApiResult {
    let p = app.authenticate(&headers, &caller)?;
    let t = token_principal(&p)?;
    let row = app.db.token_get(t.id)?.ok_or_else(|| ApiError::unauthorized("token not found"))?;
    Ok(Json(json!({
        "name": row.name, "scopes": row.scopes, "secrets": row.secrets, "nodes": row.nodes,
        "proxy_get_only": row.proxy_get_only, "created_at": row.created_at,
        "rotation": {
            "every_hours": row.rotate_every_hours, "changed_at": row.rotation_changed_at,
            "last_rotated_at": row.last_rotated_at, "due_at": row.due_at(),
        },
    }))
    .into_response())
}

/// `POST /v1/tokens/self/rotate` — swap for a fresh token. Allowed even when
/// overdue. The old token works until the new one is first used (a day at
/// most); swapping again with the old token discards the unused new one.
pub async fn rotate_self(State(app): State<AppRef>, Extension(caller): Extension<Caller>, headers: HeaderMap) -> ApiResult {
    let p = app.authenticate_with(&headers, &caller, true)?;
    let t = token_principal(&p)?;
    let ev = EventInfo::new("token.rotate", p.label());
    let (token, hash) = auth::new_token();
    if !app.db.token_set_next(t.id, &hash)? {
        return Err(ApiError::unauthorized("token not found").event(ev));
    }
    let body = json!({ "token": token, "old_token_valid_until": "the new token's first use, or 24 hours from now at most" });
    Ok(with_event(Json(body), ev))
}

#[derive(Deserialize)]
pub struct RotationBody {
    every_hours: Option<i64>,
}

/// `PUT /v1/tokens/self/rotation` — the interval set in spandeck's Control
/// Deck, or null for never. No passphrase: it only affects hygiene (the token
/// is pinned to its machine), and every change is logged for the owner.
pub async fn set_rotation(
    State(app): State<AppRef>,
    Extension(caller): Extension<Caller>,
    headers: HeaderMap,
    Json(body): Json<RotationBody>,
) -> ApiResult {
    let p = app.authenticate(&headers, &caller)?;
    let t = token_principal(&p)?;
    let ev = EventInfo::new("token.rotation_setting", p.label());
    if let Some(h) = body.every_hours
        && !(MIN_ROTATION_HOURS..=MAX_ROTATION_HOURS).contains(&h)
    {
        return Err(ApiError::bad_request(format!(
            "every_hours must be between {MIN_ROTATION_HOURS} and {MAX_ROTATION_HOURS}, or null for never"
        ))
        .event(ev));
    }
    let before = app.db.token_get(t.id)?.and_then(|r| r.rotate_every_hours);
    app.db.token_set_rotation(t.id, body.every_hours)?;
    let show = |h: Option<i64>| h.map_or("never".to_string(), |h| format!("every {h} h"));
    let detail = format!("{} -> {}", show(before), show(body.every_hours));
    Ok(with_event(Json(json!({ "every_hours": body.every_hours })), ev.detail(detail)))
}

#[derive(Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct ReportBody {
    value: String,
    #[zeroize(skip)]
    #[serde(default)]
    place: Option<String>,
}

/// `POST /v1/attention/report` — a value seen in a prompt, command or
/// transcript. The reply is identical whether or not it matches a stored key,
/// and the matching happens after the reply is sent, so neither the answer
/// nor its timing can be used to test guesses. A match appears in the
/// owner's Needs attention list.
pub async fn report(
    State(app): State<AppRef>,
    Extension(caller): Extension<Caller>,
    headers: HeaderMap,
    Json(mut body): Json<ReportBody>,
) -> ApiResult {
    let p = app.authenticate(&headers, &caller)?;
    let ev = EventInfo::new("attention.report", p.label());
    let reply = || with_event((StatusCode::ACCEPTED, Json(json!({ "received": true }))), ev.clone());
    if body.value.len() > MAX_REPORT_BYTES || body.value.trim().len() < 8 {
        return Ok(reply());
    }
    let who = match &p {
        Principal::Token(t) => format!("token:{}", t.id),
        Principal::Owner { .. } => "owner".into(),
    };
    {
        let mut b = app.stations.report_budget.lock().unwrap_or_else(|p| p.into_inner());
        let e = b.entry(who).or_insert((Instant::now(), 0));
        if e.0.elapsed() > Duration::from_secs(60) {
            *e = (Instant::now(), 0);
        }
        e.1 += 1;
        if e.1 > REPORTS_PER_MINUTE {
            return Ok(reply());
        }
    }
    let value = Zeroizing::new(std::mem::take(&mut body.value));
    let place = truncate(body.place.as_deref().unwrap_or("a transcript"), 40);
    let (reporter, node) = (p.label(), caller.node.clone());
    let a = app.clone();
    tokio::task::spawn_blocking(move || {
        let Ok(mac) = a.vault.fingerprint(value.trim().as_bytes()) else {
            return;
        };
        if let Ok(Some((id, version))) = a.db.secret_id_by_mac(&mac) {
            let _ = a.db.exposure_report(id, version, &reporter, &node, &place);
        }
    });
    Ok(reply())
}
