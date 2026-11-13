//! Import endpoints: the owner pastes a key file, reviews what the vault
//! proposes (values masked), adjusts names and missing parts, then commits.
//! Parsed values stay in server memory between the two steps; they are never
//! sent back to the browser.

use axum::{
    Extension, Json,
    extract::State,
    http::{HeaderMap, StatusCode},
};
use serde::Deserialize;
use serde_json::json;
use std::time::{Duration, Instant};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::app::{ApiError, ApiResult, AppRef, EventInfo, with_event};
use crate::identity::Caller;
use crate::import::{self, Candidate};
use crate::material::{Extra, Material};
use crate::server::{self, NewSecret, ProxyBody, SettingsBody};

const SESSION_TTL: Duration = Duration::from_secs(30 * 60);
const MAX_SESSIONS: usize = 4;

pub struct Session {
    created: Instant,
    node_id: String,
    candidates: Vec<Candidate>,
}

/// Drops expired import sessions (run every minute), so pasted values don't
/// sit in memory longer than needed.
pub fn prune(app: &AppRef) {
    app.imports
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .retain(|_, s| s.created.elapsed() < SESSION_TTL);
}

#[derive(Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct PreviewBody {
    text: String,
}

pub async fn preview(
    State(app): State<AppRef>,
    Extension(caller): Extension<Caller>,
    headers: HeaderMap,
    Json(mut body): Json<PreviewBody>,
) -> ApiResult {
    let p = server::owner(&app, &headers, &caller)?;
    // Each pasted value is checked against every stored one, so a preview is a
    // way to test guesses: it needs the passphrase, like the commit.
    app.require_fresh(&p)?;
    app.vault.ensure_unsealed()?;
    if body.text.len() > import::MAX_TEXT {
        return Err(ApiError::bad_request("that's more than 1 MiB of text"));
    }
    // Parsing and duplicate checks are CPU work: keep them off the async workers.
    let text = zeroize::Zeroizing::new(std::mem::take(&mut body.text));
    let a = app.clone();
    let (parsed, items) = tokio::task::spawn_blocking(move || -> ApiResult<_> {
        let parsed = import::parse(&text);
        if parsed.candidates.len() > import::MAX_CANDIDATES {
            return Err(ApiError::bad_request(format!(
                "that file has {} keys; import at most {} at a time",
                parsed.candidates.len(),
                import::MAX_CANDIDATES
            )));
        }
        let existing: Vec<(String, Option<String>)> = a.db.secret_list()?.into_iter().map(|m| (m.name, m.provider)).collect();
        let items = import::propose(&parsed, &existing, |v| a.duplicate_of(v, None).ok().flatten());
        Ok((parsed, items))
    })
    .await
    .map_err(ApiError::internal)??;
    let id = hex::encode(crate::crypto::random_bytes::<16>());
    {
        let mut map = app.imports.lock().unwrap_or_else(|p| p.into_inner());
        map.retain(|_, s| s.created.elapsed() < SESSION_TTL);
        while map.len() >= MAX_SESSIONS {
            let oldest = map.iter().min_by_key(|(_, s)| s.created).map(|(k, _)| k.clone());
            match oldest {
                Some(k) => map.remove(&k),
                None => break,
            };
        }
        map.insert(
            id.clone(),
            Session {
                created: Instant::now(),
                node_id: caller.node_id.clone(),
                candidates: parsed.candidates,
            },
        );
    }
    let ev = EventInfo::new("import.preview", "owner (web)").detail(format!("{} candidates", items.len()));
    Ok(with_event(
        Json(json!({ "import_id": id, "items": items, "unmatched": parsed.unmatched, "expires_in": SESSION_TTL.as_secs() })),
        ev,
    ))
}

#[derive(Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct CommitItem {
    #[zeroize(skip)]
    id: usize,
    #[zeroize(skip)]
    #[serde(default = "yes")]
    include: bool,
    #[zeroize(skip)]
    name: String,
    #[serde(default)]
    #[zeroize(skip)]
    notes: Option<String>,
    #[serde(default)]
    #[zeroize(skip)]
    kind: Option<String>,
    #[serde(default)]
    #[zeroize(skip)]
    owner_only: Option<bool>,
    #[serde(default)]
    #[zeroize(skip)]
    provider: Option<String>,
    #[serde(default)]
    #[zeroize(skip)]
    parent: Option<String>,
    #[serde(default)]
    #[zeroize(skip)]
    fields: Option<serde_json::Map<String, serde_json::Value>>,
    #[serde(default)]
    #[zeroize(skip)]
    base_url: Option<String>,
    /// Secret parts the file didn't have (e.g. a client secret).
    #[serde(default)]
    extras: Vec<Extra>,
}

fn yes() -> bool {
    true
}

#[derive(Deserialize)]
pub struct CommitBody {
    import_id: String,
    items: Vec<CommitItem>,
    /// Record that these values sat in a plaintext file, so they're flagged
    /// for rotation until replaced.
    #[serde(default = "yes")]
    mark_exposed: bool,
}

pub async fn commit(
    State(app): State<AppRef>,
    Extension(caller): Extension<Caller>,
    headers: HeaderMap,
    Json(body): Json<CommitBody>,
) -> ApiResult {
    let p = server::owner(&app, &headers, &caller)?;
    app.require_fresh(&p)?;
    app.vault.ensure_unsealed()?;
    let session = {
        let mut map = app.imports.lock().unwrap_or_else(|p| p.into_inner());
        match map.remove(&body.import_id) {
            Some(s) if s.created.elapsed() < SESSION_TTL && s.node_id == caller.node_id => s,
            Some(_) | None => return Err(ApiError::new(StatusCode::GONE, "this import expired: paste the file again")),
        }
    };
    let today = crate::timeutil::format_date(crate::db::now_ms());
    // Create managers before the secrets that name them as parent.
    let parents: Vec<String> = body.items.iter().filter_map(|i| i.parent.clone()).collect();
    let mut order: Vec<&CommitItem> = body.items.iter().filter(|i| i.include).collect();
    order.sort_by_key(|i| !parents.contains(&i.name));

    let mut results = vec![];
    for item in order {
        let name = item.name.trim().to_string();
        let r = commit_one(&app, &session, item, &name, body.mark_exposed, &today);
        results.push(match r {
            Ok(dup) => json!({ "id": item.id, "name": name, "status": "created", "duplicate_of": dup }),
            Err(e) => json!({ "id": item.id, "name": name, "status": "error", "error": e.msg }),
        });
    }
    for item in body.items.iter().filter(|i| !i.include) {
        results.push(json!({ "id": item.id, "name": item.name, "status": "skipped" }));
    }
    let created = results.iter().filter(|r| r["status"] == "created").count();
    let failed = results.iter().filter(|r| r["status"] == "error").count();
    let ev = EventInfo::new("import.commit", "owner (web)").detail(format!("{created} created, {failed} failed"));
    Ok(with_event(
        Json(json!({ "created": created, "failed": failed, "results": results })),
        ev,
    ))
}

fn commit_one(
    app: &AppRef,
    session: &Session,
    item: &CommitItem,
    name: &str,
    mark_exposed: bool,
    today: &str,
) -> ApiResult<Option<String>> {
    let c = session
        .candidates
        .get(item.id)
        .ok_or_else(|| ApiError::bad_request("unknown item"))?;
    if !server::valid_name(name) {
        return Err(ApiError::bad_request("names may use letters, digits, '_', '-' and '.'"));
    }
    if let Some(n) = &item.notes {
        server::check_notes(&Some(n.clone()))?;
    }
    server::check_extras(&item.extras)?;
    // Fields found in the file, overridden by what the owner typed.
    let mut fields = c.fields.clone();
    for (k, v) in item.fields.iter().flatten() {
        fields.insert(k.clone(), v.clone());
    }
    let sb = SettingsBody {
        kind: item.kind.clone(),
        owner_only: item.owner_only,
        fields: Some(fields),
        provider: item.provider.clone(),
        parent: item.parent.clone(),
        exposed: mark_exposed.then(|| format!("Was stored in a plaintext file (imported {today}). Replace it.")),
        proxy: item.base_url.as_ref().filter(|b| !b.trim().is_empty()).map(|b| ProxyBody {
            base_url: Some(b.clone()),
            auth: None,
        }),
        ..Default::default()
    };
    let settings = sb.to_settings(app, name)?;
    let proxy = sb.proxy.as_ref().map(server::proxy_change).transpose()?;
    let mut material = Material::single(c.material.value.clone());
    for e in &c.material.extras {
        material.set_extra(&e.name, e.value.clone());
    }
    for e in item.extras.iter().filter(|e| !e.value.trim().is_empty()) {
        material.set_extra(&e.name, e.value.trim().to_string());
    }
    let mut notes = vec![];
    if !c.label.is_empty() {
        notes.push(format!("From the import: \"{}\"", import::mask_line(&c.label)));
    }
    notes.extend(c.notes.iter().cloned());
    if let Some(n) = item.notes.as_deref().filter(|n| !n.trim().is_empty()) {
        notes.push(n.trim().to_string());
    }
    let ns = NewSecret {
        name: name.to_string(),
        material,
        notes: server::truncate(&notes.join("\n"), 4000),
        tags: vec!["imported".into()],
        settings,
        proxy,
        verify: true,
    };
    server::create_internal(app, ns).map(|(_, dup)| dup)
}
