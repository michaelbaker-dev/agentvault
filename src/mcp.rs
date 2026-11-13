//! A minimal MCP server (Streamable HTTP transport, JSON responses only) so
//! Claude Code can use stored keys without seeing them:
//!
//! ```text
//! claude mcp add --transport http keys https://<host>:<port>/mcp --header "Authorization: Bearer kt_..."
//! ```
//!
//! There is deliberately no tool that returns a raw value.

use axum::{
    Extension, Json,
    body::Bytes,
    extract::State,
    http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode, header},
    response::{IntoResponse, Response},
};
use serde_json::{Value, json};

use crate::app::{AppRef, EventInfo, with_event};
use crate::auth::{Principal, Scope};
use crate::identity::Caller;
use crate::proxy;

const PROTOCOL_VERSIONS: &[&str] = &["2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05"];
const MAX_TOOL_BODY: usize = 100_000;

const INSTRUCTIONS: &str = "This server gives you use of API keys stored in the owner's vault without revealing \
them. Call list_secrets to find a key, describe_secret to learn what it is for and how risky it is, and \
proxy_request to call that provider's API: the server attaches the key on its side. Raw key values are never \
available through this server, so don't ask the user to paste keys; use proxy_request instead. Prefer read-only \
requests unless the user asked for a change, and treat high-risk keys (those that spend money or change \
production systems) with extra care.";

fn rpc_result(id: &Value, result: Value) -> Response {
    Json(json!({ "jsonrpc": "2.0", "id": id, "result": result })).into_response()
}

fn rpc_error(id: &Value, code: i64, message: &str) -> Response {
    Json(json!({ "jsonrpc": "2.0", "id": id, "error": { "code": code, "message": message } })).into_response()
}

fn tool_text(v: Value, is_error: bool) -> Value {
    json!({ "content": [{ "type": "text", "text": v.to_string() }], "isError": is_error })
}

fn tools_for(p: &Principal) -> Vec<Value> {
    let mut tools = vec![];
    if p.has(Scope::List) {
        tools.push(json!({
            "name": "list_secrets",
            "title": "List stored API keys",
            "description": "List the API keys and credentials in the vault that you may use: name, provider, plain-English description, risk level, and whether proxy_request works with it. Values are never included.",
            "inputSchema": {
                "type": "object",
                "properties": { "query": { "type": "string", "description": "Optional filter on name or description" } },
                "additionalProperties": false
            },
            "annotations": { "readOnlyHint": true }
        }));
        tools.push(json!({
            "name": "describe_secret",
            "title": "Describe one API key",
            "description": "Full metadata for one stored key: what it is for, which account it belongs to, its scopes, risk level, docs link and how the proxy reaches it. Never includes the value.",
            "inputSchema": {
                "type": "object",
                "properties": { "name": { "type": "string" } },
                "required": ["name"],
                "additionalProperties": false
            },
            "annotations": { "readOnlyHint": true }
        }));
    }
    if p.has(Scope::Proxy) {
        tools.push(json!({
            "name": "proxy_request",
            "title": "Call an API with a stored key",
            "description": "Send an HTTP request to the provider a stored key belongs to (for example api.openai.com for an OpenAI key). The vault adds the key's authentication itself; do not include any credentials. `path` is relative to the provider's API base (see describe_secret), e.g. '/v1/models'. Returns status, content type and up to 100 KB of response body.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "secret": { "type": "string", "description": "Name of the stored key" },
                    "method": { "type": "string", "enum": ["GET", "POST", "PUT", "PATCH", "DELETE"], "default": "GET" },
                    "path": { "type": "string" },
                    "query": { "type": "string", "description": "Query string without the leading '?'" },
                    "headers": { "type": "object", "additionalProperties": { "type": "string" } },
                    "body": { "description": "Request body: a JSON value (sent as application/json) or a string" }
                },
                "required": ["secret", "path"],
                "additionalProperties": false
            },
            "annotations": { "readOnlyHint": false, "openWorldHint": true }
        }));
    }
    tools
}

pub async fn handle(State(app): State<AppRef>, Extension(caller): Extension<Caller>, headers: HeaderMap, body: Bytes) -> Response {
    let principal = match app.authenticate(&headers, &caller) {
        Ok(p) => p,
        Err(e) => return e.into_response(),
    };
    let is_json = headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.starts_with("application/json"));
    if !is_json {
        return (StatusCode::UNSUPPORTED_MEDIA_TYPE, "MCP messages must be application/json").into_response();
    }
    let Ok(msg) = serde_json::from_slice::<Value>(&body) else {
        return (StatusCode::BAD_REQUEST, rpc_error(&Value::Null, -32700, "parse error")).into_response();
    };
    let Some(method) = msg.get("method").and_then(Value::as_str) else {
        // A response or batch from the client: nothing to do.
        return StatusCode::ACCEPTED.into_response();
    };
    let Some(id) = msg.get("id").cloned() else {
        return StatusCode::ACCEPTED.into_response(); // notification
    };
    let params = msg.get("params").cloned().unwrap_or(Value::Null);

    match method {
        "initialize" => {
            let asked = params.get("protocolVersion").and_then(Value::as_str).unwrap_or("");
            let version = PROTOCOL_VERSIONS.iter().find(|v| **v == asked).unwrap_or(&PROTOCOL_VERSIONS[0]);
            rpc_result(
                &id,
                json!({
                    "protocolVersion": version,
                    "capabilities": { "tools": { "listChanged": false } },
                    "serverInfo": { "name": "agentvault", "title": "AgentVault", "version": env!("CARGO_PKG_VERSION") },
                    "instructions": INSTRUCTIONS,
                }),
            )
        }
        "ping" => rpc_result(&id, json!({})),
        "tools/list" => rpc_result(&id, json!({ "tools": tools_for(&principal) })),
        "tools/call" => {
            let name = params.get("name").and_then(Value::as_str).unwrap_or("");
            let args = params.get("arguments").cloned().unwrap_or(json!({}));
            let (result, ev) = call_tool(&app, &principal, name, &args).await;
            let resp = rpc_result(&id, result);
            match ev {
                Some(ev) => with_event(resp, ev),
                None => resp,
            }
        }
        _ => rpc_error(&id, -32601, "method not found"),
    }
}

async fn call_tool(app: &AppRef, p: &Principal, tool: &str, args: &Value) -> (Value, Option<EventInfo>) {
    let s = |k: &str| args.get(k).and_then(Value::as_str).map(str::to_string);
    match tool {
        "list_secrets" => {
            let ev = EventInfo::new("mcp.list", p.label());
            if !p.has(Scope::List) {
                return (
                    tool_text(json!({"error": "this token can't list secrets"}), true),
                    Some(ev.detail("scope denied")),
                );
            }
            let q = s("query").unwrap_or_default().to_lowercase();
            let list = match app.db.secret_list() {
                Ok(l) => l,
                Err(e) => return (tool_text(json!({"error": e.to_string()}), true), Some(ev)),
            };
            let items: Vec<Value> = list
                .iter()
                .filter(|m| p.may_use(m))
                .filter(|m| q.is_empty() || m.name.to_lowercase().contains(&q) || m.description.to_lowercase().contains(&q))
                .map(|m| {
                    json!({
                        "name": m.name,
                        "provider": m.provider_name,
                        "description": m.description,
                        "risk": m.risk,
                        "tags": m.tags,
                        "proxy_ready": proxy::target_for(m).is_some(),
                        "last_used_at": m.last_used_at,
                    })
                })
                .collect();
            (tool_text(json!({ "secrets": items }), false), Some(ev))
        }
        "describe_secret" => {
            let name = s("name").unwrap_or_default();
            let ev = EventInfo::new("mcp.describe", p.label()).secret(&name);
            if !p.allows(Scope::List, &name) {
                return (
                    tool_text(json!({"error": "not allowed for this token"}), true),
                    Some(ev.detail("scope denied")),
                );
            }
            match app.db.secret_get(&name) {
                Ok(Some(m)) if p.may_use(&m) => {
                    let target = proxy::target_for(&m);
                    let v = json!({
                        "name": m.name,
                        "provider": m.provider_name,
                        "description": m.description,
                        "notes": m.notes,
                        "risk": m.risk,
                        "risk_reason": m.risk_reason,
                        "facts": m.facts,
                        "docs_url": m.docs_url,
                        "tags": m.tags,
                        "version": m.version,
                        "proxy": target.map(|t| json!({ "base_url": t.base.as_str() })),
                        "updated_at": m.updated_at,
                        "last_used_at": m.last_used_at,
                    });
                    (tool_text(v, false), Some(ev))
                }
                Ok(_) => (tool_text(json!({"error": "no such secret"}), true), Some(ev.detail("not found"))),
                Err(e) => (tool_text(json!({"error": e.to_string()}), true), Some(ev)),
            }
        }
        "proxy_request" => proxy_tool(app, p, args).await,
        _ => (tool_text(json!({"error": format!("unknown tool '{tool}'")}), true), None),
    }
}

async fn proxy_tool(app: &AppRef, p: &Principal, args: &Value) -> (Value, Option<EventInfo>) {
    let name = args.get("secret").and_then(Value::as_str).unwrap_or("").to_string();
    let method_s = args.get("method").and_then(Value::as_str).unwrap_or("GET").to_ascii_uppercase();
    let path = args.get("path").and_then(Value::as_str).unwrap_or("").to_string();
    let query = args
        .get("query")
        .and_then(Value::as_str)
        .map(|q| q.trim_start_matches('?').to_string());
    let ev = EventInfo::new("mcp.proxy", p.label())
        .secret(&name)
        .detail(format!("{method_s} {}", path.chars().take(200).collect::<String>()));
    let fail = |msg: String, ev: EventInfo| (tool_text(json!({ "error": msg }), true), Some(ev));

    if !p.allows(Scope::Proxy, &name) {
        return fail(
            "this token may not use that key through the proxy".into(),
            ev.detail("scope denied"),
        );
    }
    let Ok(method) = Method::from_bytes(method_s.as_bytes()) else {
        return fail("unsupported method".into(), ev);
    };
    let get_only = matches!(p, Principal::Token(t) if t.proxy_get_only);
    if !proxy::allowed_method(&method, get_only) {
        let msg = if get_only {
            "this token may only send GET requests through the proxy"
        } else {
            "unsupported method"
        };
        return fail(msg.into(), ev.detail("method denied"));
    }
    let meta = match app.db.secret_get(&name) {
        Ok(Some(m)) if p.may_use(&m) => m,
        Ok(_) => return fail("no such secret".into(), ev),
        Err(e) => return fail(e.to_string(), ev),
    };
    let Some(target) = proxy::target_for(&meta) else {
        return fail(
            "no proxy target for this secret; the owner can set one in the web interface".into(),
            ev,
        );
    };
    let url = match proxy::build_url(&target.base, &path, query.as_deref()) {
        Ok(u) => u,
        Err(e) => return fail(e, ev),
    };

    let mut headers = HeaderMap::new();
    if let Some(obj) = args.get("headers").and_then(Value::as_object) {
        for (k, v) in obj {
            if let (Ok(n), Some(Ok(val))) = (
                HeaderName::from_bytes(k.to_ascii_lowercase().as_bytes()),
                v.as_str().map(HeaderValue::from_str),
            ) {
                headers.insert(n, val);
            }
        }
    }
    headers.remove(header::ACCEPT_ENCODING); // we need to read the body as text
    let body = match args.get("body") {
        None | Some(Value::Null) => Bytes::new(),
        Some(Value::String(s)) => Bytes::from(s.clone()),
        Some(v) => {
            headers
                .entry(header::CONTENT_TYPE)
                .or_insert(HeaderValue::from_static("application/json"));
            Bytes::from(v.to_string())
        }
    };
    let headers = proxy::forward_request_headers(&headers, &target.auth);

    let stored = match app.reveal(&meta) {
        Ok(s) => s,
        Err(e) => return fail(e.msg, ev),
    };
    let material = match crate::rotate::proxy_material(app, &meta, &stored).await {
        Ok(m) => m,
        Err(e) => return fail(e.msg, ev),
    };
    let creds = proxy::Creds {
        material: &material,
        fields: &meta.fields,
    };
    let mut redactor = proxy::Redactor::for_creds(&creds, &target.auth);
    redactor.extend(&stored.secrets());
    let (mut resp, upstream) = match proxy::send(&app.http, &target, &creds, method, url, headers, body).await {
        Ok(r) => r,
        Err(e) => return fail(e, ev),
    };
    drop((material, stored));
    let _ = app.db.secret_touch(meta.id);
    let status = resp.status().as_u16();
    let content_type = resp
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    // Read at most a little past the limit, so a huge body can't exhaust memory.
    let mut bytes = Vec::new();
    let mut truncated = false;
    while let Ok(Some(chunk)) = resp.chunk().await {
        bytes.extend_from_slice(&chunk);
        if bytes.len() > MAX_TOOL_BODY + 1024 {
            truncated = true;
            break;
        }
    }
    // Redact before truncating so a key straddling the cut is still caught.
    let mut redacted = redactor.redact(&bytes);
    if redacted.len() > MAX_TOOL_BODY {
        truncated = true;
        redacted.truncate(MAX_TOOL_BODY);
    }
    let text = match std::str::from_utf8(&redacted) {
        Ok(t) => t.to_string(),
        Err(e) if e.error_len().is_none() || content_type.starts_with("text") || content_type.contains("json") => {
            String::from_utf8_lossy(&redacted).into_owned()
        }
        Err(_) => format!("[binary body, {} bytes]", bytes.len()),
    };
    let out = json!({ "status": status, "content_type": content_type, "truncated": truncated, "body": text });
    (tool_text(out, status >= 400), Some(ev.upstream(upstream)))
}
